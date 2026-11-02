//! The agent's MQTT task (spec §6.2): one long-lived connection to the push broker that turns
//! doorbells into wake-ups for the main loop.
//!
//! The task trades the device credential for a broker grant ([`Fetcher::push_token`]), connects
//! with the grant's `broker`, `client_id` and token (MQTT 5, clean start, no session expiry,
//! keepalive 60 s, TLS checked against the system roots with the broker's host name, rustls with
//! ring as reqwest), and subscribes to the grant's `topics` (the school's settings topic and the
//! machine's inbox topic) with QoS 1. Once the broker acknowledged the subscriptions it sends
//! [`PushEvent::Connected`] (the main loop then syncs settings and inbox over HTTPS: the only way
//! a doorbell missed while offline is made up) and a [`PushEvent::Status`] with `ok = true`.
//! Every doorbell becomes [`PushEvent::Bell`]; a payload [`Doorbell::parse`] does not understand
//! becomes [`PushEvent::Connected`] ("sync both").
//!
//! The grant is reused across reconnects until its renewal time ([`renew_schedule`]: 10–60
//! minutes, drawn at random, before `expires_at`), when the connection is closed and a new grant
//! fetched. The renewal time is also kept as elapsed time since the grant arrived, so a local clock
//! that is far ahead (or behind) of the server's still renews about once per token lifetime.
//! An authentication failure (CONNACK refused, a subscription refused, the broker disconnecting
//! with "not authorized") also drops the grant.
//!
//! Every failure is reported as a [`PushEvent::Status`] with `ok = false` and a detail starting
//! with `dns:`, `tcp:`, `tls:`, `auth:` or `token:` ([`classify`]), then retried after the
//! ruling 59 backoff ([`crate::backoff`]). A 403 on `/v1/push-token` (the server does not accept
//! the device credential) waits `backoff_max` instead. The broker token and the device secret
//! never reach a log line, an error or a status detail.
//!
//! Events are queued inside the task and handed to the main loop as it takes them, so a main loop
//! busy applying settings never stalls the MQTT connection (and its keepalive). If the queue grows
//! past [`OUTBOX_CAP`] it collapses into one `Connected` (plus the latest status): syncing both
//! covers every doorbell it replaces.
//!
//! The task never gives up on its own (ruling R9): there is no fallback polling, so a dead push
//! channel would leave the machine deaf to doorbells. Failures that a quick retry will not fix
//! (no usable system root certificates, a 403 on the token) are retried after `backoff_max`. It
//! stops only on `shutdown` or when the main loop dropped the receiving end of `events`, which
//! means the main loop is gone and counts as shutdown.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use chrono::{DateTime, SecondsFormat, Utc};
use mastersos_bundle::push::{Doorbell, PushTokenResponse, PUSH_TOKEN_TTL_SECS};
use mastersos_bundle::ItemResult;
use rumqttc::v5::mqttbytes::v5::{DisconnectReasonCode, Filter, Packet, SubscribeReasonCode};
use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::{AsyncClient, ConnectionError, Event, MqttOptions};
use rumqttc::{Outgoing, TlsConfiguration, Transport};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::backoff::{backoff, jittered, Jitter};
use crate::fetch::{CredRejected, DeviceCred, Fetcher, Unauthorized};

/// The status report item this task fills.
pub const ITEM: &str = "push";
/// MQTT keepalive (spec: 60 s).
pub const KEEPALIVE: Duration = Duration::from_secs(60);
/// The MQTT username: the app name, the token's `iss` (the server's `push::jwt::ISSUER`).
pub const USERNAME: &str = "mastersos";
/// A connection that stayed up at least this long after its subscriptions were acknowledged
/// resets the backoff; one dropped sooner counts as another failure, so a broker that accepts and
/// drops at once is not redialled (and every machine does not resync over HTTPS) every 5 s.
pub const RESET_BACKOFF_AFTER: Duration = KEEPALIVE;
/// A connection is kept at least this long before renewing its token, whatever the schedule
/// says. A clock far ahead does not reach this floor: [`renew_schedule`] then renews by elapsed
/// time since the grant arrived. If the broker drops an expired token first, that is an
/// authentication failure and backs off.
pub const MIN_RENEW_DELAY: Duration = Duration::from_secs(60);
/// Events waiting for the main loop, at most, before they collapse into one `Connected`.
pub const OUTBOX_CAP: usize = 64;
/// The `push` status detail for a 401 on `/v1/push-token`: the fetch token was refused. The main
/// loop answers it as it answers a 401 on `/v1/bundle` (spec §6.2): it syncs settings, whose 401
/// switches to another saved token; the switched token is shared with this task's `Fetcher`.
pub const TOKEN_UNAUTHORIZED: &str = "token: the server rejected the fetch token (401)";
/// Resolving the broker's name gives up after this long.
const DNS_TIMEOUT: Duration = Duration::from_secs(30);

/// What the MQTT task tells the main loop.
#[derive(Debug, Clone, PartialEq)]
pub enum PushEvent {
    /// Connected and subscribed (first time or again), or a doorbell nobody understood: sync
    /// settings and inbox once.
    Connected,
    /// A doorbell: one counter moved.
    Bell(Doorbell),
    /// The `push` status report item ([`ITEM`]).
    Status(ItemResult),
}

/// Timing and environment of the MQTT task.
#[derive(Debug, Clone)]
pub struct PushTiming {
    /// The first wait after a failure (ruling 59: 5 s)…
    pub backoff_start: Duration,
    /// …doubling up to this (15 min), then ×0.8–1.2. Also the wait after a 403 on the token.
    pub backoff_max: Duration,
    /// Random source of the backoff factor and of the renewal time.
    pub jitter: Jitter,
    /// The token is renewed at least this long before it expires (10 min)…
    pub renew_early_min: Duration,
    /// …and at most this long (60 min), uniformly in between.
    pub renew_early_max: Duration,
    /// The image is a lab image: `/v1/push-token` may then go over plain http (the device secret
    /// otherwise only travels over https; [`crate::fetch::escrow_transport_ok`]). The broker
    /// connection is TLS either way.
    pub lab: bool,
}

impl PushTiming {
    /// The spec's values: backoff 5 s to 15 min with the system jitter, renewal 10–60 min early.
    pub fn standard(lab: bool) -> PushTiming {
        PushTiming {
            backoff_start: Duration::from_secs(5),
            backoff_max: Duration::from_secs(15 * 60),
            jitter: Jitter::system(),
            renew_early_min: Duration::from_secs(10 * 60),
            renew_early_max: Duration::from_secs(60 * 60),
            lab,
        }
    }
}

/// Start the MQTT task on the current runtime. It never exits on its own: every failure,
/// including a TLS setup that cannot load the system root certificates, is reported as a
/// `Status` and retried. It stops only when `shutdown` is cancelled or the receiving end of
/// `events` is dropped (the main loop is gone, which counts as shutdown).
pub fn spawn(
    fetcher: Fetcher,
    cred: DeviceCred,
    cfg: PushTiming,
    events: mpsc::Sender<PushEvent>,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(run(fetcher, cred, cfg, events, shutdown, tls_config))
}

/// Builds the broker TLS configuration ([`tls_config`]; tests inject a failing one).
type TlsLoader = fn() -> anyhow::Result<Arc<rustls::ClientConfig>>;

/// When to renew a token expiring at `expires_at`, received at `now` (local clock): `early`
/// before it. Returns the delay from now, to be measured on the monotonic clock, and the same
/// moment on the local clock (which, unlike the monotonic clock, also runs while suspended).
///
/// The delay never exceeds the token lifetime ([`PUSH_TOKEN_TTL_SECS`]) minus `early`, so a clock
/// behind the server's still renews in time. When `expires_at` is no more than `early` away by the
/// local clock, that clock is taken to be ahead of the server's (the server issues every token for
/// the full lifetime): the delay is the lifetime minus `early` and there is no local-clock time,
/// so the connection is not renewed at once, again and again.
fn renew_schedule(
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
    early: Duration,
) -> (Duration, Option<DateTime<Utc>>) {
    let lifetime = Duration::from_secs(PUSH_TOKEN_TTL_SECS).saturating_sub(early);
    let left = (expires_at - now).to_std().ok();
    match (left, chrono::Duration::from_std(early)) {
        (Some(left), Ok(e)) if left > early => {
            (lifetime.min(left - early), expires_at.checked_sub_signed(e))
        }
        _ => (lifetime, None),
    }
}

/// How early to renew for a random `unit` in [0, 1]: `renew_early_min` at 0, `renew_early_max`
/// at 1, linearly in between. Out-of-range units are clamped; NaN counts as 0.
fn renew_early(cfg: &PushTiming, unit: f64) -> Duration {
    let u = if unit.is_nan() {
        0.0
    } else {
        unit.clamp(0.0, 1.0)
    };
    let span = cfg.renew_early_max.saturating_sub(cfg.renew_early_min);
    cfg.renew_early_min + span.mul_f64(u)
}

/// The failure class of a broker connection error, the prefix of the status detail:
/// - `tls`: the TLS handshake failed (certificate, name, protocol).
/// - `auth`: the broker refused the CONNECT (CONNACK with a failure reason code).
/// - `tcp`: everything else on the way — refused or reset connections, timeouts (rumqttc's
///   connection timeout covers TCP, TLS and CONNACK together), protocol errors.
///
/// rumqttc resolves the broker's name inside the same I/O error as a refused connection, so
/// [`run`] resolves the name itself first and reports `dns` from there; a resolution failure that
/// still reaches rumqttc (the name stopped resolving in between) is folded into `tcp`.
fn classify(err: &ConnectionError) -> &'static str {
    match err {
        ConnectionError::Tls(_) => "tls",
        ConnectionError::ConnectionRefused(_) => "auth",
        _ => "tcp",
    }
}

/// A short reason for `err`, without anything the broker could echo back: I/O and TLS errors as
/// the OS / rustls word them, CONNACK as its reason code.
fn reason(err: &ConnectionError) -> String {
    match err {
        ConnectionError::Io(e) => e.to_string(),
        ConnectionError::Tls(e) => e.to_string(),
        ConnectionError::ConnectionRefused(code) => {
            format!("the broker refused the connection ({code:?})")
        }
        ConnectionError::Timeout(_) => "connection timed out".into(),
        ConnectionError::MqttState(e) => format!("protocol: {e}"),
        ConnectionError::NotConnAck(_) => "protocol: expected CONNACK".into(),
        ConnectionError::RequestsDone => "client stopped".into(),
        #[allow(unreachable_patterns)]
        _ => "connection failed".into(),
    }
}

fn passed(detail: String) -> ItemResult {
    ItemResult {
        item: ITEM.into(),
        ok: true,
        detail: Some(detail),
    }
}

fn failed(detail: String) -> ItemResult {
    ItemResult {
        item: ITEM.into(),
        ok: false,
        detail: Some(detail),
    }
}

/// `ok = true`, "connected since <RFC 3339>".
fn connected_status(since: DateTime<Utc>) -> ItemResult {
    passed(format!(
        "connected since {}",
        since.to_rfc3339_opts(SecondsFormat::Secs, true)
    ))
}

/// "<class>: <reason>" for a broker connection error: the detail of an `ok = false` status.
fn failure_detail(err: &ConnectionError) -> String {
    format!("{}: {}", classify(err), reason(err))
}

/// "token: <reason>" for a failed `/v1/push-token`. `push_token`'s errors never carry the URL,
/// the request body or the secret.
fn token_detail(e: &anyhow::Error) -> String {
    if e.downcast_ref::<CredRejected>().is_some() {
        "token: the server rejected the device credential (403)".into()
    } else if e.downcast_ref::<Unauthorized>().is_some() {
        TOKEN_UNAUTHORIZED.into()
    } else {
        format!("token: {e:#}")
    }
}

/// What a PUBLISH payload means to the main loop: the doorbell, or — when it is not one this agent
/// understands — `Connected`, which the main loop treats as "sync both".
fn event_for_payload(payload: &[u8]) -> PushEvent {
    match Doorbell::parse(payload) {
        Some(bell) => PushEvent::Bell(bell),
        None => PushEvent::Connected,
    }
}

/// `host:port`, optionally written `mqtts://host:port`; the port is required.
fn split_broker(broker: &str) -> anyhow::Result<(String, u16)> {
    let hp = broker.strip_prefix("mqtts://").unwrap_or(broker);
    let (host, port) = hp
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("expected host:port"))?;
    let port: u16 = port
        .parse()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| anyhow!("invalid port"))?;
    if host.is_empty() || host.contains('/') {
        return Err(anyhow!("invalid host"));
    }
    Ok((host.to_owned(), port))
}

/// rustls with ring and the system's root certificates (as reqwest's `rustls-tls-native-roots`
/// and the server's publisher).
fn tls_config() -> anyhow::Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    let found = rustls_native_certs::load_native_certs();
    for e in &found.errors {
        log::warn!("loading a system root certificate failed: {e}");
    }
    let (added, _) = roots.add_parsable_certificates(found.certs);
    if added == 0 {
        return Err(anyhow!("no system root certificates"));
    }
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("TLS protocol versions")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// A broker grant ready to connect with.
struct Grant {
    resp: PushTokenResponse,
    host: String,
    port: u16,
    /// Renew from this moment on (monotonic clock, from when the grant arrived)…
    renew_deadline: tokio::time::Instant,
    /// …or from this one on the local clock, whichever comes first ([`renew_schedule`]).
    renew_at: Option<DateTime<Utc>>,
}

impl Grant {
    /// How long until the grant is due for renewal (zero: due now).
    fn renew_in(&self) -> Duration {
        let mono = self
            .renew_deadline
            .saturating_duration_since(tokio::time::Instant::now());
        match self.renew_at {
            Some(at) => mono.min((at - Utc::now()).to_std().unwrap_or(Duration::ZERO)),
            None => mono,
        }
    }
}

/// Connection options for `g`.
///
/// Multiple broker IPs (spec §6.2 asks to try all of them in random order, with SNI and the
/// certificate check on the broker's name): rumqttc takes one `host` for both the TCP connect and
/// the TLS server name and cannot separate them. So the task connects **by name**; rumqttc tries
/// every address the resolver returns, in the resolver's order, until one accepts TCP. An address
/// that accepts TCP but fails later (TLS, CONNACK) is not skipped within that attempt: the task
/// relies on the backoff and on the broker DNS health check, which drops a bad host within 1–2
/// minutes.
fn options(g: &Grant, tls: &Arc<rustls::ClientConfig>) -> MqttOptions {
    let mut o = MqttOptions::new(g.resp.client_id.clone(), g.host.clone(), g.port);
    o.set_keep_alive(KEEPALIVE)
        .set_clean_start(true)
        .set_session_expiry_interval(None)
        .set_credentials(USERNAME, g.resp.token.clone())
        .set_transport(Transport::tls_with_config(TlsConfiguration::Rustls(
            tls.clone(),
        )));
    o
}

/// Events waiting for the main loop.
#[derive(Default)]
struct Outbox(VecDeque<PushEvent>);

impl Outbox {
    fn push(&mut self, ev: PushEvent) {
        if self.0.len() >= OUTBOX_CAP {
            let status = self
                .0
                .iter()
                .rev()
                .find(|e| matches!(e, PushEvent::Status(_)))
                .cloned();
            self.0.clear();
            self.0.push_back(PushEvent::Connected);
            self.0.extend(status);
        }
        self.0.push_back(ev);
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn pop(&mut self) -> Option<PushEvent> {
        self.0.pop_front()
    }
}

/// Wait `d` while handing queued events to the main loop. `false`: stop the task (`shutdown` was
/// cancelled or the main loop dropped its receiver).
async fn idle(
    d: Duration,
    events: &mpsc::Sender<PushEvent>,
    out: &mut Outbox,
    shutdown: &CancellationToken,
) -> bool {
    let sleep = tokio::time::sleep(d);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return false,
            _ = &mut sleep => return true,
            p = events.reserve(), if !out.is_empty() => match p {
                Ok(p) => {
                    if let Some(ev) = out.pop() {
                        p.send(ev);
                    }
                }
                Err(_) => return false,
            },
        }
    }
}

/// How one connection ended.
enum Ended {
    /// The token is due for renewal; the connection was closed cleanly.
    Renew,
    /// `shutdown` was cancelled or the main loop dropped its receiver.
    Stop,
    /// The connection failed. `up_for`: how long it had been subscribed (`None`: never got
    /// there); `auth`: the broker refused the credentials, so the grant is dropped.
    Failed {
        up_for: Option<Duration>,
        detail: String,
        auth: bool,
    },
}

async fn run(
    fetcher: Fetcher,
    cred: DeviceCred,
    cfg: PushTiming,
    events: mpsc::Sender<PushEvent>,
    shutdown: CancellationToken,
    load_tls: TlsLoader,
) {
    let mut out = Outbox::default();
    let mut tls: Option<Arc<rustls::ClientConfig>> = None;
    let mut failures: u32 = 0;
    let mut grant: Option<Grant> = None;
    loop {
        // Built once and cached. Without system roots a quick retry will not help, but the roots
        // may still be installed or repaired, so retry after `backoff_max` rather than give up.
        let tls = match &tls {
            Some(t) => t.clone(),
            None => match load_tls() {
                Ok(t) => {
                    tls = Some(t.clone());
                    t
                }
                Err(e) => {
                    let wait = jittered(cfg.backoff_max, cfg.jitter.unit());
                    log::error!(
                        "push: TLS setup failed: {e:#}; retrying in {} s",
                        wait.as_secs()
                    );
                    out.push(PushEvent::Status(failed(format!("tls: {e:#}"))));
                    if !idle(wait, &events, &mut out, &shutdown).await {
                        return;
                    }
                    continue;
                }
            },
        };
        let g = match grant.take() {
            Some(g) if !g.renew_in().is_zero() => g,
            _ => {
                let r = tokio::select! {
                    _ = shutdown.cancelled() => return,
                    r = fetcher.push_token(&cred, cfg.lab) => r,
                };
                match r.and_then(|resp| {
                    let (host, port) = split_broker(&resp.broker)
                        .map_err(|e| anyhow!("invalid broker address in the grant: {e}"))?;
                    let early = renew_early(&cfg, cfg.jitter.unit());
                    let (delay, renew_at) = renew_schedule(resp.expires_at, Utc::now(), early);
                    if renew_at.is_none() {
                        log::warn!(
                            "push: the token expires within {} min by the local clock (clock \
                             ahead of the server's?); renewing it in {} min of elapsed time",
                            early.as_secs() / 60,
                            delay.as_secs() / 60
                        );
                    }
                    Ok(Grant {
                        resp,
                        host,
                        port,
                        renew_deadline: tokio::time::Instant::now() + delay,
                        renew_at,
                    })
                }) {
                    Ok(g) => g,
                    Err(e) => {
                        let detail = token_detail(&e);
                        let wait = if e.downcast_ref::<CredRejected>().is_some() {
                            jittered(cfg.backoff_max, cfg.jitter.unit())
                        } else {
                            backoff(
                                failures,
                                cfg.backoff_start,
                                cfg.backoff_max,
                                cfg.jitter.unit(),
                            )
                        };
                        failures = failures.saturating_add(1);
                        log::warn!("push: {detail}; retrying in {} s", wait.as_secs());
                        out.push(PushEvent::Status(failed(detail)));
                        if !idle(wait, &events, &mut out, &shutdown).await {
                            return;
                        }
                        continue;
                    }
                }
            }
        };

        // Resolve the name first, so that a DNS failure is reported as one (rumqttc's own lookup
        // is indistinguishable from a refused connection); the connection then goes by name.
        let ended = match resolve(&g.host, g.port).await {
            Err(why) => Ended::Failed {
                up_for: None,
                detail: format!("dns: {why}"),
                auth: false,
            },
            Ok(()) => session(&g, &tls, &events, &mut out, &shutdown).await,
        };
        let wait = match ended {
            Ended::Stop => return,
            Ended::Renew => {
                log::info!("push: renewing the broker token");
                failures = 0;
                continue;
            }
            Ended::Failed {
                up_for,
                detail,
                auth,
            } => {
                if up_for.is_some_and(|d| d >= RESET_BACKOFF_AFTER) {
                    failures = 0;
                }
                if !auth {
                    grant = Some(g);
                }
                let wait = backoff(
                    failures,
                    cfg.backoff_start,
                    cfg.backoff_max,
                    cfg.jitter.unit(),
                );
                failures = failures.saturating_add(1);
                log::warn!("push: {detail}; retrying in {} s", wait.as_secs());
                out.push(PushEvent::Status(failed(detail)));
                wait
            }
        };
        if !idle(wait, &events, &mut out, &shutdown).await {
            return;
        }
    }
}

/// Resolve `host:port`; `Err` is a short reason.
async fn resolve(host: &str, port: u16) -> Result<(), String> {
    match tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host((host, port))).await {
        Err(_) => Err("lookup timed out".into()),
        Ok(Err(e)) => Err(e.to_string()),
        Ok(Ok(mut addrs)) => {
            let first: Option<SocketAddr> = addrs.next();
            first.map(|_| ()).ok_or_else(|| "no addresses".into())
        }
    }
}

/// Drive one connection: connect, subscribe, forward doorbells, until it fails, the token is due
/// for renewal, or the task stops.
async fn session(
    g: &Grant,
    tls: &Arc<rustls::ClientConfig>,
    events: &mpsc::Sender<PushEvent>,
    out: &mut Outbox,
    shutdown: &CancellationToken,
) -> Ended {
    let (client, mut el) = AsyncClient::new(options(g, tls), 16);
    let filters: Vec<Filter> = g
        .resp
        .topics
        .iter()
        .map(|t| Filter::new(t.clone(), QoS::AtLeastOnce))
        .collect();
    if filters.is_empty() {
        return Ended::Failed {
            up_for: None,
            detail: "auth: the grant has no topics".into(),
            auth: true,
        };
    }
    // Queued now, sent by the event loop right after the CONNACK.
    if let Err(e) = client.try_subscribe_many(filters) {
        return Ended::Failed {
            up_for: None,
            detail: format!("tcp: subscribe: {e}"),
            auth: false,
        };
    }
    let delay = g.renew_in().max(MIN_RENEW_DELAY);
    let renew = tokio::time::sleep(delay);
    tokio::pin!(renew);
    let mut subscribed_at: Option<tokio::time::Instant> = None;
    let up_for = |at: Option<tokio::time::Instant>| at.map(|t| t.elapsed());
    loop {
        tokio::select! {
            // The process is stopping: no DISCONNECT, the broker drops the session at keepalive.
            _ = shutdown.cancelled() => return Ended::Stop,
            _ = &mut renew => {
                // Say goodbye so the broker does not wait out the keepalive.
                let _ = client.try_disconnect();
                let _ = tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        match el.poll().await {
                            Ok(Event::Outgoing(Outgoing::Disconnect)) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                })
                .await;
                return Ended::Renew;
            }
            p = events.reserve(), if !out.is_empty() => match p {
                Ok(p) => {
                    if let Some(ev) = out.pop() {
                        p.send(ev);
                    }
                }
                Err(_) => return Ended::Stop,
            },
            ev = el.poll() => match ev {
                Ok(Event::Incoming(Packet::SubAck(ack))) => {
                    if let Some(code) = ack
                        .return_codes
                        .iter()
                        .find(|c| !matches!(c, SubscribeReasonCode::Success(_)))
                    {
                        return Ended::Failed {
                            up_for: None,
                            detail: format!("auth: the broker refused a subscription ({code:?})"),
                            auth: true,
                        };
                    }
                    let now = Utc::now();
                    subscribed_at = Some(tokio::time::Instant::now());
                    log::info!("push: connected to {} and subscribed", g.host);
                    out.push(PushEvent::Connected);
                    out.push(PushEvent::Status(connected_status(now)));
                }
                Ok(Event::Incoming(Packet::Publish(p))) => {
                    let ev = event_for_payload(&p.payload);
                    if ev == PushEvent::Connected {
                        log::warn!(
                            "push: unrecognised doorbell ({} bytes); syncing settings and inbox",
                            p.payload.len()
                        );
                    }
                    out.push(ev);
                }
                Ok(Event::Incoming(Packet::Disconnect(d))) => {
                    let auth = d.reason_code == DisconnectReasonCode::NotAuthorized;
                    return Ended::Failed {
                        up_for: up_for(subscribed_at),
                        detail: format!(
                            "{}: disconnected by the broker ({:?})",
                            if auth { "auth" } else { "tcp" },
                            d.reason_code
                        ),
                        auth,
                    };
                }
                Ok(_) => {}
                Err(e) => {
                    return Ended::Failed {
                        up_for: up_for(subscribed_at),
                        detail: failure_detail(&e),
                        auth: classify(&e) == "auth",
                    };
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use chrono::{TimeZone, Utc};
    use rumqttc::v5::mqttbytes::v5::ConnectReturnCode;
    use rumqttc::v5::{ConnectionError, TlsError};

    use crate::backoff::Jitter;

    fn timing(unit: f64) -> PushTiming {
        PushTiming {
            backoff_start: Duration::from_secs(5),
            backoff_max: Duration::from_secs(900),
            jitter: Jitter::fixed(unit),
            renew_early_min: Duration::from_secs(600),
            renew_early_max: Duration::from_secs(3600),
            lab: false,
        }
    }

    #[test]
    fn renew_is_10_to_60_min_early() {
        let now = Utc.with_ymd_and_hms(2026, 10, 27, 0, 0, 0).unwrap();
        let exp = now + chrono::Duration::hours(24);
        for (unit, min) in [(0.0, 10), (1.0, 60), (0.5, 35)] {
            let t = timing(unit);
            let (delay, at) = renew_schedule(exp, now, renew_early(&t, t.jitter.unit()));
            assert_eq!(delay, Duration::from_secs((24 * 60 - min) * 60), "{unit}");
            assert_eq!(
                at,
                Some(exp - chrono::Duration::minutes(min as i64)),
                "{unit}"
            );
        }
        // Units outside [0, 1] stay within the window.
        let lo = timing(0.0);
        assert_eq!(renew_early(&lo, -1.0), Duration::from_secs(600));
        assert_eq!(renew_early(&lo, 9.0), Duration::from_secs(3600));
        assert_eq!(renew_early(&lo, f64::NAN), Duration::from_secs(600));
    }

    #[test]
    fn renew_follows_elapsed_time_when_the_clock_is_off() {
        let now = Utc.with_ymd_and_hms(2026, 10, 27, 12, 0, 0).unwrap();
        let early = Duration::from_secs(600);
        let lifetime = Duration::from_secs(PUSH_TOKEN_TTL_SECS) - early;
        // Clock about 23 h 55 min ahead: by the local clock the token expires in 5 minutes.
        let exp = now + chrono::Duration::minutes(5);
        assert_eq!(renew_schedule(exp, now, early), (lifetime, None));
        // Already expired by the local clock.
        let exp = now - chrono::Duration::hours(3);
        assert_eq!(renew_schedule(exp, now, Duration::from_secs(3600)).1, None);
        // Clock 5 h behind: the local clock would renew 5 h too late, elapsed time does not.
        let exp = now + chrono::Duration::hours(29);
        let (delay, at) = renew_schedule(exp, now, early);
        assert_eq!(delay, lifetime);
        assert_eq!(at, Some(exp - chrono::Duration::minutes(10)));
        // Clock 1 h ahead: renewed by the local clock, 1 h earlier than needed (harmless).
        let exp = now + chrono::Duration::hours(23);
        assert_eq!(
            renew_schedule(exp, now, early).0,
            Duration::from_secs(23 * 3600) - early
        );
    }

    #[test]
    fn push_status_reports_failure_reason() {
        let refused =
            ConnectionError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        assert_eq!(classify(&refused), "tcp");
        let tls = ConnectionError::Tls(TlsError::TLS(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        )));
        assert_eq!(classify(&tls), "tls");
        let auth = ConnectionError::ConnectionRefused(ConnectReturnCode::NotAuthorized);
        assert_eq!(classify(&auth), "auth");
        let bad_pw = ConnectionError::ConnectionRefused(ConnectReturnCode::BadUserNamePassword);
        assert_eq!(classify(&bad_pw), "auth");

        // The status item carries the prefix and a reason, never more.
        let s = failed(failure_detail(&auth));
        assert_eq!(s.item, ITEM);
        assert!(!s.ok);
        let d = s.detail.unwrap();
        assert!(d.starts_with("auth: "), "{d}");
        assert!(d.contains("NotAuthorized"), "{d}");
        let d = failed(failure_detail(&refused)).detail.unwrap();
        assert!(d.starts_with("tcp: "), "{d}");
        let d = failed(failure_detail(&tls)).detail.unwrap();
        assert!(d.starts_with("tls: "), "{d}");

        let ok = connected_status(Utc.with_ymd_and_hms(2026, 10, 27, 8, 30, 0).unwrap());
        assert_eq!(ok.item, "push");
        assert!(ok.ok);
        assert_eq!(
            ok.detail.as_deref(),
            Some("connected since 2026-10-27T08:30:00Z")
        );
    }

    #[test]
    fn unknown_bell_becomes_connected() {
        assert!(matches!(
            event_for_payload(br#"{"settings":42}"#),
            PushEvent::Bell(Doorbell::Settings(42))
        ));
        assert!(matches!(
            event_for_payload(br#"{"inbox":7}"#),
            PushEvent::Bell(Doorbell::Inbox(7))
        ));
        for junk in [&b"garbage"[..], b"", br#"{"reboot":1}"#, br#"{"inbox":-1}"#] {
            assert!(
                matches!(event_for_payload(junk), PushEvent::Connected),
                "{junk:?}"
            );
        }
    }

    fn seed(url: &str) -> mastersos_bundle::Seed {
        mastersos_bundle::Seed {
            server_url: url.into(),
            trust: vec![],
            fetch_token: Some("tok".into()),
            group: None,
            oidc: None,
            min_version: None,
            school_id: None,
            wifi: vec![],
            school_name: None,
            it_account: None,
        }
    }

    fn cred() -> DeviceCred {
        DeviceCred {
            device_id: "dev-1".into(),
            secret: "DEVICE-SECRET-xyz".into(),
        }
    }

    /// The first `Status` the task sends, within 10 s.
    async fn first_status(rx: &mut mpsc::Receiver<PushEvent>) -> ItemResult {
        loop {
            let ev = tokio::time::timeout(Duration::from_secs(10), rx.recv())
                .await
                .expect("a status within 10 s")
                .expect("the task is running");
            if let PushEvent::Status(s) = ev {
                return s;
            }
        }
    }

    #[tokio::test]
    async fn token_refusal_is_reported_as_token() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let srv = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/push-token"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&srv)
            .await;
        let (tx, mut rx) = mpsc::channel(8);
        let stop = CancellationToken::new();
        let mut cfg = timing(0.5);
        cfg.lab = true; // wiremock is plain http
        let h = spawn(
            Fetcher::from_seed(&seed(&srv.uri())),
            cred(),
            cfg,
            tx,
            stop.clone(),
        );
        let s = first_status(&mut rx).await;
        assert!(!s.ok);
        let d = s.detail.unwrap();
        assert!(d.starts_with("token: "), "{d}");
        assert!(!d.contains("DEVICE-SECRET"), "{d}");
        stop.cancel();
        h.await.unwrap();
    }

    #[tokio::test]
    async fn refused_broker_is_reported_as_tcp_without_secrets() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let srv = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/push-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                // Nothing listens on port 1: the TCP connect is refused.
                "token": "BROKER-JWT-abc", "broker": "127.0.0.1:1", "client_id": "mastersos/s.dev-1",
                "topics": ["mastersos/s/settings", "mastersos/s/d/dev-1"],
                "expires_at": (Utc::now() + chrono::Duration::hours(24)).to_rfc3339()
            })))
            .mount(&srv)
            .await;
        let (tx, mut rx) = mpsc::channel(8);
        let stop = CancellationToken::new();
        let mut cfg = timing(0.5);
        cfg.lab = true;
        let h = spawn(
            Fetcher::from_seed(&seed(&srv.uri())),
            cred(),
            cfg,
            tx,
            stop.clone(),
        );
        let s = first_status(&mut rx).await;
        assert_eq!(s.item, ITEM);
        assert!(!s.ok);
        let d = s.detail.unwrap();
        assert!(d.starts_with("tcp: "), "{d}");
        assert!(
            !d.contains("BROKER-JWT") && !d.contains("DEVICE-SECRET"),
            "{d}"
        );
        stop.cancel();
        h.await.unwrap();
    }

    #[test]
    fn outbox_collapses_into_connected() {
        let mut o = Outbox::default();
        for i in 0..OUTBOX_CAP as u64 - 1 {
            o.push(PushEvent::Bell(Doorbell::Inbox(i)));
        }
        o.push(PushEvent::Status(failed("tcp: x".into())));
        assert_eq!(o.0.len(), OUTBOX_CAP);
        o.push(PushEvent::Bell(Doorbell::Settings(9)));
        let all: Vec<_> = std::iter::from_fn(|| o.pop()).collect();
        assert_eq!(
            all,
            [
                PushEvent::Connected,
                PushEvent::Status(failed("tcp: x".into())),
                PushEvent::Bell(Doorbell::Settings(9)),
            ]
        );
    }

    #[test]
    fn broker_address_needs_host_and_port() {
        assert_eq!(
            split_broker("mqtt.52j.me:443").unwrap(),
            ("mqtt.52j.me".to_owned(), 443)
        );
        assert_eq!(
            split_broker("mqtts://b:8883").unwrap(),
            ("b".to_owned(), 8883)
        );
        for bad in [
            "mqtt.52j.me",
            ":443",
            "mqtt.52j.me:0",
            "x:y",
            "https://a/b:1",
        ] {
            assert!(split_broker(bad).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn tls_setup_failure_is_retried_not_fatal() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        fn no_roots() -> anyhow::Result<Arc<rustls::ClientConfig>> {
            CALLS.fetch_add(1, Ordering::SeqCst);
            Err(anyhow!("no system root certificates"))
        }
        let (tx, mut rx) = mpsc::channel(8);
        let stop = CancellationToken::new();
        let mut cfg = timing(0.5);
        cfg.backoff_max = Duration::from_millis(20);
        cfg.lab = true;
        // Never reached: the task fails before asking for a token.
        let fetcher = Fetcher::from_seed(&seed("http://127.0.0.1:1"));
        let h = tokio::spawn(run(fetcher, cred(), cfg, tx, stop.clone(), no_roots));
        for _ in 0..3 {
            let s = first_status(&mut rx).await;
            assert!(!s.ok);
            let d = s.detail.unwrap();
            assert!(d.starts_with("tls: "), "{d}");
        }
        assert!(CALLS.load(Ordering::SeqCst) >= 3, "TLS setup retried");
        assert!(!h.is_finished(), "the task keeps running");
        stop.cancel();
        h.await.unwrap();
    }

    #[tokio::test]
    async fn dropped_receiver_stops_the_task() {
        fn no_roots() -> anyhow::Result<Arc<rustls::ClientConfig>> {
            Err(anyhow!("no system root certificates"))
        }
        let (tx, rx) = mpsc::channel(8);
        drop(rx);
        let mut cfg = timing(0.5);
        cfg.backoff_max = Duration::from_millis(20);
        let fetcher = Fetcher::from_seed(&seed("http://127.0.0.1:1"));
        let h = tokio::spawn(run(
            fetcher,
            cred(),
            cfg,
            tx,
            CancellationToken::new(),
            no_roots,
        ));
        tokio::time::timeout(Duration::from_secs(10), h)
            .await
            .expect("the task stops once the main loop is gone")
            .unwrap();
    }

    /// Fails the test binary if the test is still running after `secs` of real time: on a held
    /// clock no tokio timeout can fire, so a hang would otherwise never end. Dropping it disarms.
    struct Watchdog(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for Watchdog {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn watchdog(name: &'static str, secs: u64) -> Watchdog {
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let d = done.clone();
        std::thread::spawn(move || {
            let end = std::time::Instant::now() + Duration::from_secs(secs);
            while std::time::Instant::now() < end {
                if d.load(std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            eprintln!("{name} still running after {secs} s: aborting");
            std::process::abort();
        });
        Watchdog(done)
    }

    /// Lets `ms` of real time pass, the clock held (the busy task keeps tokio from auto-advancing
    /// it while wiremock and the refused TCP connect do real I/O).
    async fn settle(ms: u64) {
        let end = std::time::Instant::now() + Duration::from_millis(ms);
        while std::time::Instant::now() < end {
            tokio::task::yield_now().await;
        }
    }

    /// A local clock about 23 h 50 min ahead of the server's: every grant is already within the
    /// renewal margin when it arrives. Over 2 h of (paused) time with a broker that refuses
    /// connections, the task keeps the one grant and retries the broker with the backoff; it
    /// does not fetch a new token on every retry.
    #[tokio::test(start_paused = true)]
    async fn skewed_clock_does_not_renew_on_every_connect() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let _watchdog = watchdog("skewed_clock_does_not_renew_on_every_connect", 120);
        let _hold = tokio::spawn(async {
            loop {
                tokio::task::yield_now().await;
            }
        });
        let srv = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/push-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "BROKER-JWT-abc", "broker": "127.0.0.1:1", "client_id": "mastersos/s.dev-1",
                "topics": ["mastersos/s/settings", "mastersos/s/d/dev-1"],
                "expires_at": (Utc::now() + chrono::Duration::minutes(10)).to_rfc3339()
            })))
            .mount(&srv)
            .await;
        fn no_check() -> anyhow::Result<Arc<rustls::ClientConfig>> {
            // The TCP connect is refused before TLS starts: any configuration will do.
            let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
            Ok(Arc::new(cfg))
        }
        let (tx, mut rx) = mpsc::channel(1024);
        let stop = CancellationToken::new();
        let mut cfg = timing(0.0);
        cfg.lab = true; // wiremock is plain http
        let h = tokio::spawn(run(
            Fetcher::from_seed(&seed(&srv.uri())),
            cred(),
            cfg,
            tx,
            stop.clone(),
            no_check,
        ));
        let srv = &srv;
        let tokens = || async move {
            srv.received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.url.path() == "/v1/push-token")
                .count()
        };
        // The first grant, in real time with the clock held.
        for _ in 0..500 {
            if tokens().await == 1 {
                break;
            }
            settle(10).await;
        }
        assert_eq!(tokens().await, 1, "the first grant");
        let mut failures = 0;
        let step = Duration::from_secs(5);
        let mut t = Duration::ZERO;
        while t < Duration::from_secs(2 * 3600) {
            tokio::time::advance(step).await;
            settle(5).await;
            while let Ok(ev) = rx.try_recv() {
                if matches!(ev, PushEvent::Status(ref s) if !s.ok) {
                    failures += 1;
                }
            }
            t += step;
        }
        assert!(failures >= 5, "the broker was retried: {failures} failures");
        assert_eq!(tokens().await, 1, "one token for 2 h of retries");
        stop.cancel();
        h.await.unwrap();
    }
}
