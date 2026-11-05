//! `mastersos-agent support host`: the root service behind `/run/mastersos-support/support.sock` (socket activation,
//! `Accept=no`; the listening socket arrives as stdin, `StandardInput=socket`). The login screen, the desktop and the
//! kiosk native host talk to it, one connection per request:
//!
//! - in: one JSON line of at most [`MAX_REQUEST_BYTES`]; out: one JSON line.
//! - `{"op":"submit","category":…,"text":…,"session":…,"screenshot_png_b64":null|"…"}` →
//!   `{"ok":true,"client_id":"…","state":"queued"}` or `{"ok":false,"error":"rate_limited|invalid|disabled"}`
//!   (`failed` when the queue cannot be written: the dialog shows its generic error).
//! - `{"op":"status","client_id":"…"}` → `{"ok":true,"state":"queued|sent|failed|disabled","ticket":"1042"?}`, only
//!   for the uid that submitted it; any other client id is `invalid`.
//! - `{"op":"enabled"}` → `{"ok":true,"enabled":bool}`.
//!
//! Each op takes exactly its fields (`deny_unknown_fields`): a request naming a user is refused, who sent it comes from
//! the peer credentials only ([`super::identity`]). The session the dialog sends must look like one but is replaced by
//! the derived one. Only a submit may be longer than [`SMALL_REQUEST_BYTES`].
//!
//! Limits (any local user can connect): at most [`ServeOpts::max_open`] connections at once (more are closed at once,
//! without a reply), at most [`ServeOpts::max_large`] of them reading or handling a request longer than
//! [`SMALL_REQUEST_BYTES`] (the others wait for a place while their read time runs), so memory stays within the unit's
//! `MemoryMax`. The budget (rate limit, queue room) is checked before anything costly, and again, under the queue's
//! lock, when the item is written; nothing else is serialized. An `accept` error (out of file descriptors, a
//! connection aborted) is logged and the service goes on.
//!
//! The service exits after [`IDLE`] without a connection; the socket stays and starts it again.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;
use chrono::{DateTime, Utc};
use mastersos_bundle::diag::{
    SupportCategory, SupportRequest, SupportSnapshot, SUPPORT_TEXT_MAX_CHARS,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::identity::{identify, Peer, Who};
use super::store::{Item, ItemState, Store};
use super::{kick_sender, MAX_REQUEST_BYTES, MAX_SCREENSHOT_BYTES, SUPPORT_JSON};
use crate::runner::Runner;

/// The service exits after this long without a connection.
pub const IDLE: Duration = Duration::from_secs(120);
/// A client has this long to send its line.
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// The longest request other than a submit, and the size from which a request needs one of the
/// [`ServeOpts::max_large`] places.
pub const SMALL_REQUEST_BYTES: usize = 4096;
/// After an `accept` error, wait this long before the next one.
const ACCEPT_PAUSE: Duration = Duration::from_millis(200);
const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

const ERR_INVALID: &str = "invalid";
const ERR_DISABLED: &str = "disabled";
const ERR_RATE_LIMITED: &str = "rate_limited";
const ERR_FAILED: &str = "failed";

/// One reply line.
#[derive(Serialize, Debug, Default, Clone, PartialEq, Eq)]
pub struct Reply {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ItemState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

impl Reply {
    fn err(e: &'static str) -> Reply {
        Reply {
            ok: false,
            error: Some(e),
            ..Reply::default()
        }
    }

    fn ok() -> Reply {
        Reply {
            ok: true,
            ..Reply::default()
        }
    }

    pub fn line(&self) -> Vec<u8> {
        let mut v = serde_json::to_vec(self).unwrap_or_else(|_| br#"{"ok":false}"#.to_vec());
        v.push(b'\n');
        v
    }
}

// `op` is read here too so that `deny_unknown_fields` sees every key of the request.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct SubmitReq {
    op: String,
    category: String,
    text: String,
    session: String,
    #[serde(default)]
    screenshot_png_b64: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct StatusReq {
    op: String,
    client_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct EnabledReq {
    op: String,
}

enum Request {
    Submit(SubmitReq),
    Status(StatusReq),
    Enabled,
}

/// Just the op (other fields are skipped, not kept).
#[derive(Deserialize)]
struct Op {
    op: String,
}

/// Straight into the op's own struct (no intermediate JSON value). A JSON object only: serde would read a struct from
/// an array too. Only a submit may be longer than [`SMALL_REQUEST_BYTES`].
fn parse(line: &[u8]) -> Option<Request> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    if line.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return None;
    }
    let op: Op = serde_json::from_slice(line).ok()?;
    if op.op != "submit" && line.len() > SMALL_REQUEST_BYTES {
        return None;
    }
    match op.op.as_str() {
        "submit" => serde_json::from_slice(line).ok().map(Request::Submit),
        "status" => serde_json::from_slice(line).ok().map(Request::Status),
        "enabled" => serde_json::from_slice::<EnabledReq>(line)
            .ok()
            .map(|_| Request::Enabled),
        _ => None,
    }
}

/// The dialogs' category ids: [`SupportCategory`]'s wire names. Unknown ones are refused here (the cloud would read
/// them as `other`; the dialogs only offer these).
fn category(s: &str) -> Option<SupportCategory> {
    Some(match s {
        "wifi" => SupportCategory::Wifi,
        "sign_in" => SupportCategory::SignIn,
        "app" => SupportCategory::App,
        "hardware" => SupportCategory::Hardware,
        "battery" => SupportCategory::Battery,
        "other" => SupportCategory::Other,
        _ => return None,
    })
}

/// What a dialog may claim: `login`, `desktop`, `kiosk` (the kiosk extension's placeholder) or `kiosk:<id>`.
fn session_shape_ok(s: &str) -> bool {
    matches!(s, "login" | "desktop" | "kiosk")
        || s.strip_prefix("kiosk:")
            .is_some_and(|id| mastersos_bundle::kiosk::check_id(id).is_ok())
}

/// The longest base64 a [`MAX_SCREENSHOT_BYTES`] PNG takes.
const MAX_SCREENSHOT_B64: usize = MAX_SCREENSHOT_BYTES.div_ceil(3) * 4;

/// A PNG of at most [`MAX_SCREENSHOT_BYTES`], or `None`.
fn decode_png(b64: &str) -> Option<Vec<u8>> {
    if b64.len() > MAX_SCREENSHOT_B64 {
        return None;
    }
    let png = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    (png.len() <= MAX_SCREENSHOT_BYTES && png.starts_with(PNG_MAGIC)).then_some(png)
}

/// The request handler; the parts the tests replace are fields.
pub struct Host {
    pub store: Store,
    /// Where the agent writes `support.json` (`/var/lib/mastersos-public`).
    pub public_dir: PathBuf,
    /// System root for the snapshot (`/sys`, the queue's file system); `/` in production.
    pub root: PathBuf,
    pub os_release: PathBuf,
    pub who: Box<dyn Who>,
    pub runner: Arc<dyn Runner>,
}

impl Host {
    /// `support.json` says `{"enabled": true}`. Missing, unreadable or anything else: off (the dialogs read it the
    /// same way).
    pub fn enabled(&self) -> bool {
        #[derive(Deserialize)]
        struct Support {
            enabled: bool,
        }
        std::fs::read(self.public_dir.join(SUPPORT_JSON))
            .ok()
            .and_then(|b| serde_json::from_slice::<Support>(&b).ok())
            .is_some_and(|s| s.enabled)
    }

    /// One request line from `peer` at `now` → the reply.
    pub fn handle(&self, line: &[u8], peer: Peer, now: DateTime<Utc>) -> Reply {
        self.dispatch(parse(line), peer, now)
    }

    /// Like [`Host::handle`], but the line is freed as soon as it is parsed (a submit's line can be 8 MiB).
    pub fn handle_owned(&self, line: Vec<u8>, peer: Peer, now: DateTime<Utc>) -> Reply {
        let req = parse(&line);
        drop(line);
        self.dispatch(req, peer, now)
    }

    fn dispatch(&self, req: Option<Request>, peer: Peer, now: DateTime<Utc>) -> Reply {
        match req {
            None => Reply::err(ERR_INVALID),
            Some(Request::Enabled) => Reply {
                enabled: Some(self.enabled()),
                ..Reply::ok()
            },
            Some(Request::Status(r)) => self.status(&r.client_id, peer),
            Some(Request::Submit(r)) => match self.submit(r, peer, now) {
                Ok(reply) => reply,
                Err(e) => {
                    log::error!("support: saving a help request failed: {e:#}");
                    Reply::err(ERR_FAILED)
                }
            },
        }
    }

    /// Under the queue's lock: `peer` is within the rate limits and the queue has room. Refused for either reason
    /// alike: the student is asked to try later.
    fn budget_allows(&self, peer: Peer, now: DateTime<Utc>) -> Result<bool> {
        let rate = self.store.rate_allows(now, peer.uid)?;
        let room = self.store.has_room()?;
        if rate && !room {
            log::warn!(
                "support: the help request queue is full; refusing new requests until it is sent"
            );
        }
        Ok(rate && room)
    }

    fn status(&self, client_id: &str, peer: Peer) -> Reply {
        match self.store.get(client_id) {
            Ok(Some(item)) if item.uid == peer.uid => Reply {
                state: Some(item.state),
                ticket: item.ticket,
                ..Reply::ok()
            },
            Ok(_) => Reply::err(ERR_INVALID),
            Err(e) => {
                log::error!("support: reading the queue failed: {e:#}");
                Reply::err(ERR_INVALID)
            }
        }
    }

    fn submit(&self, mut r: SubmitReq, peer: Peer, now: DateTime<Utc>) -> Result<Reply> {
        if !self.enabled() {
            return Ok(Reply::err(ERR_DISABLED));
        }
        let Some(category) = category(&r.category) else {
            return Ok(Reply::err(ERR_INVALID));
        };
        let text = r.text.trim().to_string();
        if text.chars().count() > SUPPORT_TEXT_MAX_CHARS
            || !session_shape_ok(&r.session)
            || r.screenshot_png_b64
                .as_ref()
                .is_some_and(|b| b.len() > MAX_SCREENSHOT_B64)
        {
            return Ok(Reply::err(ERR_INVALID));
        }
        // The budget first: a refused submit costs no decoding, no lookups and no snapshot.
        {
            let _lock = self.store.lock()?;
            if !self.budget_allows(peer, now)? {
                return Ok(Reply::err(ERR_RATE_LIMITED));
            }
        }
        let png = match r.screenshot_png_b64.take() {
            None => None,
            Some(b) => match decode_png(&b) {
                Some(p) => Some(p),
                None => return Ok(Reply::err(ERR_INVALID)),
            },
        };
        let id = identify(&peer, self.who.as_ref());
        if id.session != r.session {
            log::debug!(
                "support: the dialog said session {:?}; using {:?}",
                r.session,
                id.session
            );
        }
        let request = SupportRequest {
            client_id: uuid::Uuid::new_v4().to_string(),
            category,
            text,
            user: id.user,
            session: id.session,
            created_at: now,
            snapshot: self.snapshot(),
            screenshot: png.is_some(),
        };
        if let Err(e) = request.validate() {
            log::warn!("support: refusing a help request: {e}");
            return Ok(Reply::err(ERR_INVALID));
        }
        {
            // Again under the lock: another request may have taken the last place meanwhile.
            let _lock = self.store.lock()?;
            if !self.budget_allows(peer, now)? {
                return Ok(Reply::err(ERR_RATE_LIMITED));
            }
            self.store
                .put_new(&Item::new(request.clone(), peer.uid, now), png.as_deref())?;
            self.store.record_submit(now, peer.uid)?;
        }
        log::info!(
            "support: queued help request {} ({:?}, {})",
            request.client_id,
            request.user.kind,
            request.session
        );
        kick_sender(self.runner.as_ref());
        Ok(Reply {
            client_id: Some(request.client_id),
            state: Some(ItemState::Queued),
            ..Reply::ok()
        })
    }

    /// The machine when the student pressed Send: system version, battery, free disk. The network and the latest
    /// status report are left to the sender (Task 5b), which knows them.
    fn snapshot(&self) -> SupportSnapshot {
        let cfg = crate::AgentConfig {
            os_release: self.os_release.clone(),
            ..crate::AgentConfig::default()
        };
        let (battery_percent, on_ac) = power(&self.root.join("sys/class/power_supply"));
        let disk_free_bytes = rustix::fs::statvfs(self.store.dir().parent().unwrap_or(&self.root))
            .ok()
            .map(|s| s.f_bavail.saturating_mul(s.f_frsize));
        SupportSnapshot {
            os_version: crate::ident::os_version(&cfg).unwrap_or_else(|| "unknown".into()),
            network: None,
            battery_percent,
            on_ac,
            disk_free_bytes,
            status: None,
        }
    }
}

/// The first battery's `capacity`, and whether any `Mains` supply is `online`.
fn power(dir: &std::path::Path) -> (Option<u8>, Option<bool>) {
    let read = |p: PathBuf| {
        std::fs::read_to_string(p)
            .ok()
            .map(|s| s.trim().to_string())
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (None, None);
    };
    let mut names: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    names.sort();
    let mut battery = None;
    let mut ac = None;
    for p in names {
        match read(p.join("type")).as_deref() {
            Some("Battery") if battery.is_none() => {
                battery = read(p.join("capacity")).and_then(|c| c.parse::<u8>().ok());
            }
            Some("Mains") => {
                if let Some(o) = read(p.join("online")) {
                    ac = Some(ac.unwrap_or(false) || o == "1");
                }
            }
            _ => {}
        }
    }
    (battery, ac)
}

/// How [`serve`] limits its clients.
#[derive(Debug, Clone, Copy)]
pub struct ServeOpts {
    /// Exit after this long without a connection.
    pub idle: Duration,
    /// A client has this long to send its line (and to take the reply).
    pub read_timeout: Duration,
    /// Connections open at once; one more is closed at once.
    pub max_open: usize,
    /// Requests longer than [`SMALL_REQUEST_BYTES`] read or handled at once. Each costs up to about 16 MiB (the line,
    /// then the base64 and the decoded PNG); `MemoryMax=64M` in the unit is sized for two.
    pub max_large: usize,
}

impl Default for ServeOpts {
    fn default() -> Self {
        ServeOpts {
            idle: IDLE,
            read_timeout: READ_TIMEOUT,
            max_open: 16,
            max_large: 2,
        }
    }
}

/// Reads one line of at most [`MAX_REQUEST_BYTES`] (the newline not counted) within `timeout`. Past
/// [`SMALL_REQUEST_BYTES`] it first takes a place from `large`, which the caller keeps until the request is handled.
/// `None` when the line is longer, or the client closes or stalls first.
async fn read_line(
    stream: &mut UnixStream,
    timeout: Duration,
    large: &Arc<Semaphore>,
) -> Option<(Vec<u8>, Option<OwnedSemaphorePermit>)> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut r = BufReader::new(stream);
    let mut line = Vec::new();
    let mut permit = None;
    loop {
        let chunk = tokio::time::timeout_at(deadline, r.fill_buf())
            .await
            .ok()?
            .ok()?;
        if chunk.is_empty() {
            return None;
        }
        let (take, done) = match chunk.iter().position(|b| *b == b'\n') {
            Some(i) => (i + 1, true),
            None => (chunk.len(), false),
        };
        let len = line.len() + take;
        if len > MAX_REQUEST_BYTES + 1 {
            return None;
        }
        if permit.is_none() && len > SMALL_REQUEST_BYTES {
            permit = Some(
                tokio::time::timeout_at(deadline, large.clone().acquire_owned())
                    .await
                    .ok()?
                    .ok()?,
            );
            // One allocation for the rest, not a doubling past the limit.
            line.reserve_exact(MAX_REQUEST_BYTES + 1 - line.len());
        }
        let chunk = r.buffer();
        line.extend_from_slice(&chunk[..take]);
        r.consume(take);
        if done {
            return Some((line, permit));
        }
    }
}

async fn connection(
    mut stream: UnixStream,
    host: Arc<Host>,
    opts: ServeOpts,
    large: Arc<Semaphore>,
) {
    let cred = match stream.peer_cred() {
        Ok(c) => c,
        Err(e) => {
            log::error!("support: reading the peer credentials failed: {e}");
            return;
        }
    };
    let peer = Peer {
        uid: cred.uid(),
        pid: cred.pid().and_then(|p| u32::try_from(p).ok()),
    };
    let reply = match read_line(&mut stream, opts.read_timeout, &large).await {
        None => Reply::err(ERR_INVALID),
        Some((line, permit)) => tokio::task::spawn_blocking(move || {
            let _place = permit;
            host.handle_owned(line, peer, Utc::now())
        })
        .await
        .unwrap_or_else(|_| Reply::err(ERR_FAILED)),
    };
    let _ = tokio::time::timeout(opts.read_timeout, async {
        stream.write_all(&reply.line()).await?;
        stream.shutdown().await
    })
    .await;
}

/// Accepts connections until none came for `opts.idle` (and none is still open).
pub async fn serve(listener: UnixListener, host: Arc<Host>, opts: ServeOpts) -> Result<()> {
    let large = Arc::new(Semaphore::new(opts.max_large));
    let open = Arc::new(AtomicUsize::new(0));
    loop {
        let stream = match tokio::time::timeout(opts.idle, listener.accept()).await {
            Err(_) if open.load(Ordering::SeqCst) == 0 => return Ok(()),
            Err(_) => continue,
            Ok(Ok((s, _))) => s,
            Ok(Err(e)) => {
                // EMFILE, ECONNABORTED, …: never the end of the service (the start limit would then leave it failed)
                log::warn!("support: accepting a connection failed: {e}");
                tokio::time::sleep(ACCEPT_PAUSE).await;
                continue;
            }
        };
        if open.load(Ordering::SeqCst) >= opts.max_open {
            log::warn!(
                "support: {} connections open; closing a new one",
                opts.max_open
            );
            drop(stream);
            continue;
        }
        let (h, l, o) = (host.clone(), large.clone(), open.clone());
        o.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            connection(stream, h, opts, l).await;
            o.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

/// `support host`: the listening socket is stdin (`StandardInput=socket` in `mastersos-support.service`).
pub fn main() -> Result<()> {
    use std::os::fd::AsFd;
    let fd = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .context("duplicating stdin")?;
    let std_listener = std::os::unix::net::UnixListener::from(fd);
    std_listener
        .local_addr()
        .context("stdin is not a listening socket: start this through mastersos-support.socket")?;
    std_listener.set_nonblocking(true)?;
    let runner: Arc<dyn Runner> = Arc::new(crate::runner::RealRunner);
    let host = Host {
        store: Store::new(super::QUEUE_DIR),
        public_dir: crate::system::SysPaths::default().public_dir,
        root: "/".into(),
        os_release: crate::AgentConfig::default().os_release,
        who: Box::new(super::identity::SystemWho::new(runner.clone(), "/".into())),
        runner,
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building the tokio runtime")?;
    rt.block_on(async {
        let listener = UnixListener::from_std(std_listener)?;
        serve(listener, Arc::new(host), ServeOpts::default()).await
    })
}
