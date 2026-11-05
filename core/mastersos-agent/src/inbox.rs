//! The machine's inbox (MQTT push spec §5.1a, §6.3): commands from the server, fetched over
//! HTTPS with the device credential; MQTT only rings the doorbell.
//!
//! [`sync`] takes `GET /v1/inbox?after=inbox_after` and handles the messages in ascending `seq`,
//! skipping any at or below `after` (the server hands a message out again until it is acked).
//! Each message is acked first; only a successful ack advances `inbox_after` (and saves it). A
//! failed ack ends the sync: the main loop retries it with the backoff.
//!
//! Per message, by the machine's clock read at that moment: a clock before [`clock_floor`] or a
//! passed `expires_at` is acked `failed` and nothing runs (a factory reset checks again right
//! before its `running` ack: the precheck can take over 30 s); an unknown `kind` is acked `failed` ([`DETAIL_UNSUPPORTED`],
//! not skipped, not retried).
//!
//! `factory-reset`:
//! 1. [`reset::precheck`] (seed partition mounted and writable, TPM usable); not met → `failed`
//!    with the reason.
//! 2. Ack `running` and make sure the server recorded it: after `running` the server stops handing
//!    the message out, which is what keeps the reset from running twice. Not acked (network error,
//!    5xx, anything) → stop this sync, run nothing, do not advance. Refused (409: the message is
//!    already final there, e.g. expired by the server's clock) → run nothing, send nothing more,
//!    pass the seq.
//! 3. Write [`RESET_SEQ`] on the seed partition (the reset wipes `state.json`, the seed partition
//!    stays): the new system reports `done` for it ([`ack_reset_done`]).
//! 4. `systemd-factory-reset request` → `systemctl reboot`; either failing is acked `failed`
//!    naming the step. Once the reset started, later messages wait (the sync stops).
//!
//! `collect-diagnostics` (remote diagnostics design 4, Ruling P6): a payload that does not
//! validate is acked `failed` `bad payload: …`. Otherwise ack `running` (recorded, as for the
//! factory reset: a refused `running` runs nothing), queue a `collect` item
//! ([`crate::upload::queue`]) and start `mastersos-upload.service`; the sync goes straight on
//! to the next message. The upload service collects, uploads and acks `done` `diag:<id>` or
//! `failed`. The item is on disk, so a restart or a reboot mid-way resumes it. A queue that
//! cannot be written is acked `failed` `queue: …`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use mastersos_bundle::diag::{CollectDiagnostics, KIND_COLLECT_DIAGNOSTICS};
use mastersos_bundle::push::{
    InboxMessage, InboxResult, InboxResultState, INBOX_DETAIL_MAX_CHARS, KIND_FACTORY_RESET,
};
use mastersos_bundle::{ItemResult, StatusReport};

use crate::fetch::{DeviceCred, Fetcher, InboxSeqUnknown, ResultAck};
use crate::reset::{self, ResetCtx};
use crate::runner::Runner;
use crate::safefs;

/// Seed partition file: the `seq` of the factory reset under way, one decimal line, 0600.
pub const RESET_SEQ: &str = "inbox-reset-seq";
/// `2026-01-01T00:00:00Z`: a machine clock earlier than this is wrong.
pub const CLOCK_FLOOR_SECS: i64 = 1_767_225_600;
pub const DETAIL_EXPIRED: &str = "expired on the machine";
pub const DETAIL_CLOCK: &str = "the machine clock is wrong";
pub const DETAIL_UNSUPPORTED: &str = "unsupported: needs a newer system";
pub const DETAIL_RUNNING: &str = "factory resetting";
pub const DETAIL_DONE: &str = "factory reset finished";
pub const DETAIL_COLLECTING: &str = "collecting diagnostics";
/// The status report sent before the reboot waits at most this long (best effort).
const REPORT_WAIT: Duration = Duration::from_secs(10);

/// The earliest plausible machine time ([`CLOCK_FLOOR_SECS`]).
pub fn clock_floor() -> DateTime<Utc> {
    DateTime::from_timestamp(CLOCK_FLOOR_SECS, 0).expect("a valid timestamp")
}

pub struct InboxCtx<'a> {
    pub fetcher: &'a Fetcher,
    pub cred: &'a DeviceCred,
    /// Runs the factory reset's commands.
    pub runner: Arc<dyn Runner>,
    /// The seed partition's mount point.
    pub seed_dir: &'a Path,
    pub seed_requires_mount: bool,
    /// `/sys` and `/dev` for the TPM probe.
    pub sysfs: PathBuf,
    pub dev: PathBuf,
    /// The machine's clock, read whenever a check needs the time (production: `Utc::now`).
    pub clock: &'a (dyn Fn() -> DateTime<Utc> + Send + Sync),
    /// The status report of this moment; the factory reset sends it with a `reset` item first.
    pub status: StatusReport,
    /// The lab image: the device secret may go over http ([`Fetcher::inbox`]).
    pub lab: bool,
    /// Saves a new `inbox_after` (called after every successful ack that advances it).
    pub persist: &'a (dyn Fn(u64) + Send + Sync),
    /// The upload queue `collect-diagnostics` goes into.
    pub upload_queue: crate::upload::queue::Queue,
}

#[derive(Debug)]
pub struct SyncOutcome {
    /// The highest `seq` handled (acked).
    pub inbox_after: u64,
    /// A factory reset has started: the reboot is under way.
    pub resetting: bool,
    /// The sync stopped early (fetch or ack failed): retry with the backoff. `None`: complete.
    pub error: Option<anyhow::Error>,
}

/// What became of one message.
enum Step {
    /// Acked: advance past it.
    Acked,
    /// Acked `running` and the reset started: advance, stop.
    Resetting,
    /// Not acked (`past`: an earlier ack of it succeeded, advance anyway): stop.
    Stopped { past: bool, error: anyhow::Error },
}

/// See the module docs.
pub async fn sync(cx: &InboxCtx<'_>, after: u64) -> SyncOutcome {
    let mut out = SyncOutcome {
        inbox_after: after,
        resetting: false,
        error: None,
    };
    let page = match cx.fetcher.inbox(cx.cred, after, cx.lab).await {
        Ok(p) => p,
        Err(e) => {
            out.error = Some(e);
            return out;
        }
    };
    let mut messages = page.messages;
    messages.sort_by_key(|m| m.seq);
    for m in messages {
        if m.seq <= out.inbox_after {
            continue;
        }
        let (advance, stop) = match handle(cx, &m).await {
            Step::Acked => (true, false),
            Step::Resetting => {
                out.resetting = true;
                (true, true)
            }
            Step::Stopped { past, error } => {
                out.error = Some(error);
                (past, true)
            }
        };
        if advance {
            out.inbox_after = m.seq;
            (cx.persist)(m.seq);
        }
        if stop {
            break;
        }
    }
    out
}

/// Why `m` must not run at `now` (the `failed` detail), if so.
fn not_runnable(m: &InboxMessage, now: DateTime<Utc>) -> Option<&'static str> {
    if now < clock_floor() {
        log::warn!("inbox: seq {} not run, the machine clock is wrong", m.seq);
        return Some(DETAIL_CLOCK);
    }
    if m.expires_at.is_some_and(|t| t <= now) {
        log::warn!("inbox: seq {} expired on the machine, not run", m.seq);
        return Some(DETAIL_EXPIRED);
    }
    None
}

async fn handle(cx: &InboxCtx<'_>, m: &InboxMessage) -> Step {
    if let Some(why) = not_runnable(m, (cx.clock)()) {
        return ack(cx, m.seq, InboxResultState::Failed, why).await;
    }
    match m.kind.as_str() {
        KIND_FACTORY_RESET => factory_reset(cx, m).await,
        KIND_COLLECT_DIAGNOSTICS => collect_diagnostics(cx, m).await,
        other => {
            log::warn!("inbox: seq {} has an unsupported kind {other:?}", m.seq);
            ack(cx, m.seq, InboxResultState::Failed, DETAIL_UNSUPPORTED).await
        }
    }
}

async fn ack(cx: &InboxCtx<'_>, seq: u64, state: InboxResultState, detail: &str) -> Step {
    // 409 is fine here: a `failed` (or `done`) the server already has as final.
    match send(cx, seq, state, detail).await {
        Ok(_) => Step::Acked,
        Err(error) => Step::Stopped { past: false, error },
    }
}

async fn send(
    cx: &InboxCtx<'_>,
    seq: u64,
    state: InboxResultState,
    detail: &str,
) -> Result<ResultAck> {
    let r = InboxResult {
        state,
        detail: Some(detail.chars().take(INBOX_DETAIL_MAX_CHARS).collect()),
    };
    cx.fetcher
        .inbox_result(cx.cred, seq, &r, cx.lab)
        .await
        .map_err(|e| e.context(format!("acking inbox seq {seq} failed")))
}

async fn factory_reset(cx: &InboxCtx<'_>, m: &InboxMessage) -> Step {
    let seq = m.seq;
    let rcx = ResetCtx {
        seed_dir: cx.seed_dir,
        seed_requires_mount: cx.seed_requires_mount,
        runner: cx.runner.clone(),
        sysfs: cx.sysfs.clone(),
        dev: cx.dev.clone(),
    };
    let dir = match reset::precheck(&rcx).await {
        Ok(d) => d,
        Err(why) => {
            log::warn!("inbox: factory reset (seq {seq}) not run: {why}");
            return ack(
                cx,
                seq,
                InboxResultState::Failed,
                &format!("not run: {why}"),
            )
            .await;
        }
    };
    // The precheck (TPM probe) may have taken a while: check the clock again before starting.
    if let Some(why) = not_runnable(m, (cx.clock)()) {
        return ack(cx, seq, InboxResultState::Failed, why).await;
    }
    match send(cx, seq, InboxResultState::Running, DETAIL_RUNNING).await {
        Ok(ResultAck::Recorded) => {}
        Ok(ResultAck::Refused) => {
            // Final on the server (expired by its clock, cancelled, finished): a stale factory
            // reset never starts. Nothing more to report; pass it.
            log::warn!("inbox: factory reset (seq {seq}) refused by the server (409), not run");
            return Step::Acked;
        }
        Err(error) => {
            // The server may not know it started: it hands the message out again; run nothing now.
            return Step::Stopped { past: false, error };
        }
    }
    // The server no longer hands it out: never handle it again here either.
    (cx.persist)(seq);
    // After `running`, a failure is acked `failed`; if even that ack fails the server marks the
    // message `failed` after a day without news.
    let failed = |why: String| async move {
        log::warn!("inbox: factory reset (seq {seq}): {why}");
        match send(cx, seq, InboxResultState::Failed, &why).await {
            Ok(_) => Step::Acked,
            Err(error) => Step::Stopped { past: true, error },
        }
    };
    report_starting(cx, seq).await;
    // write_at: temporary file → fchmod 0600 → write → fsync → renameat → fsync the directory.
    if let Err(e) = safefs::write_at(&dir, RESET_SEQ, format!("{seq}\n").as_bytes(), 0o600) {
        return failed(format!(
            "not run: could not record the command on the seed partition ({RESET_SEQ}): {e:#}"
        ))
        .await;
    }
    log::warn!("inbox: factory reset (seq {seq}): requesting the reset and rebooting");
    if let Err(why) = reset::request(&rcx).await {
        // No reset follows: no `done` to report after it.
        if let Err(e) = safefs::remove_at(&dir, RESET_SEQ) {
            log::warn!("removing {RESET_SEQ} failed: {e:#}");
        }
        return failed(why).await;
    }
    if let Err(why) = reset::reboot(&rcx).await {
        // The EFI variable is set: the reset happens at the next reboot, and reports `done` then
        // (the server keeps the `failed`, a 409 the new system takes as acked).
        return failed(format!(
            "the factory reset is requested, but {why}; it resets at the next reboot"
        ))
        .await;
    }
    Step::Resetting
}

async fn collect_diagnostics(cx: &InboxCtx<'_>, m: &InboxMessage) -> Step {
    let seq = m.seq;
    let request = serde_json::from_value::<CollectDiagnostics>(m.payload.clone())
        .map_err(|e| e.to_string())
        .and_then(|r| r.validate().map(|()| r));
    let request = match request {
        Ok(r) => r,
        Err(why) => {
            log::warn!("inbox: collect-diagnostics (seq {seq}) not run: bad payload: {why}");
            return ack(
                cx,
                seq,
                InboxResultState::Failed,
                &format!("bad payload: {why}"),
            )
            .await;
        }
    };
    match send(cx, seq, InboxResultState::Running, DETAIL_COLLECTING).await {
        Ok(ResultAck::Recorded) => {}
        Ok(ResultAck::Refused) => {
            log::warn!(
                "inbox: collect-diagnostics (seq {seq}) refused by the server (409), not run"
            );
            return Step::Acked;
        }
        Err(error) => return Step::Stopped { past: false, error },
    }
    if let Err(e) = cx
        .upload_queue
        .enqueue_collect(seq, request, m.expires_at, (cx.clock)())
    {
        let why = format!("queue: {e:#}");
        log::warn!("inbox: collect-diagnostics (seq {seq}): {why}");
        return match send(cx, seq, InboxResultState::Failed, &why).await {
            Ok(_) => Step::Acked,
            Err(error) => Step::Stopped { past: true, error },
        };
    }
    log::info!("inbox: collect-diagnostics (seq {seq}) queued");
    crate::upload::kick(cx.runner.as_ref());
    Step::Acked
}

/// Sends the status report with a `reset` item first (best effort: the `running` ack is what
/// counts), so the device list shows the reset before the machine goes quiet.
async fn report_starting(cx: &InboxCtx<'_>, seq: u64) {
    let mut status = cx.status.clone();
    status.results.retain(|r| r.item != reset::ITEM);
    status.results.insert(
        0,
        ItemResult {
            item: reset::ITEM.into(),
            ok: true,
            detail: Some(format!("{} (inbox seq {seq})", reset::RESETTING)),
        },
    );
    match tokio::time::timeout(
        REPORT_WAIT,
        cx.fetcher.report(&status, Some(cx.cred), cx.lab),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => log::warn!("the report before the factory reset failed, going on: {e:#}"),
        Err(_) => log::warn!(
            "the report before the factory reset took over {} s, going on",
            REPORT_WAIT.as_secs()
        ),
    }
}

/// The `seq` in the seed partition's [`RESET_SEQ`], if any. Not mounted (when required): None.
pub fn read_reset_seq(seed_dir: &Path, requires_mount: bool) -> Result<Option<u64>> {
    if requires_mount && !crate::seedpart::is_mount_point(seed_dir)? {
        return Ok(None);
    }
    let dir = reset::open_seed(seed_dir, false).map_err(|e| anyhow!(e))?;
    let Some(b) = safefs::read_at(&dir, RESET_SEQ)? else {
        return Ok(None);
    };
    String::from_utf8_lossy(&b)
        .trim()
        .parse::<u64>()
        .map(Some)
        .map_err(|_| anyhow!("{RESET_SEQ} on the seed partition is not a number"))
}

/// The first boot after an inbox factory reset: ack `seq` `done`, then delete [`RESET_SEQ`]
/// (only when it still names `seq`). 409 (already final there) and 404 (the server no longer has
/// it, e.g. purged after 90 days) are final too. On any other error the file stays for the next
/// try.
pub async fn ack_reset_done(cx: &InboxCtx<'_>, seq: u64) -> Result<()> {
    match send(cx, seq, InboxResultState::Done, DETAIL_DONE).await {
        Ok(_) => log::info!("inbox: factory reset (seq {seq}) reported done"),
        Err(e) if e.downcast_ref::<InboxSeqUnknown>().is_some() => {
            log::warn!("inbox: the server no longer has seq {seq} (404), not reporting it done")
        }
        Err(e) => return Err(e),
    }
    match read_reset_seq(cx.seed_dir, cx.seed_requires_mount) {
        Ok(Some(s)) if s == seq => {
            let r = reset::open_seed(cx.seed_dir, false)
                .map_err(|e| anyhow!(e))
                .and_then(|d| safefs::remove_at(&d, RESET_SEQ));
            if let Err(e) = r {
                log::warn!("removing {RESET_SEQ} failed: {e:#}");
            }
        }
        Ok(_) => {}
        Err(e) => log::warn!("reading {RESET_SEQ} failed: {e:#}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reset::FACTORY_RESET;
    use crate::runner::{FakeRunner, Output};
    use mastersos_bundle::push::{InboxClass, InboxMessage, InboxPage, KIND_FACTORY_RESET};
    use mastersos_bundle::{GroupSource, Seed};
    use std::fs;
    use std::sync::Mutex;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    const REQUEST: &str = "/usr/lib/systemd/systemd-factory-reset request";
    const REBOOT: &str = "systemctl reboot";

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().to_utc()
    }

    fn now() -> DateTime<Utc> {
        t("2026-10-27T08:00:00Z")
    }

    fn msg(seq: u64, kind: &str, expires_at: Option<&str>) -> InboxMessage {
        InboxMessage {
            seq,
            class: InboxClass::Command,
            kind: kind.into(),
            payload: serde_json::json!({}),
            created_at: t("2026-10-27T07:00:00Z"),
            expires_at: expires_at.map(t),
        }
    }

    fn reset_msg(seq: u64) -> InboxMessage {
        msg(seq, KIND_FACTORY_RESET, Some("2026-10-28T07:00:00Z"))
    }

    /// A fake machine: seed partition, `/sys` and `/dev` with a SHA-256 TPM (none when `tpm` is
    /// false).
    struct Box_ {
        _tmp: tempfile::TempDir,
        seed: PathBuf,
        sysfs: PathBuf,
        dev: PathBuf,
    }

    impl Box_ {
        /// The upload queue of this machine (its state directory is the temporary root).
        fn queue(&self) -> crate::upload::queue::Queue {
            crate::upload::queue::Queue::new(self._tmp.path())
        }
    }

    fn machine(tpm: bool) -> Box_ {
        let tmp = tempfile::tempdir().unwrap();
        let seed = tmp.path().join("seed");
        let sysfs = tmp.path().join("sys");
        let dev = tmp.path().join("dev");
        for d in [&seed, &sysfs, &dev] {
            fs::create_dir_all(d).unwrap();
        }
        if tpm {
            fs::create_dir_all(sysfs.join("class/tpm/tpm0/pcr-sha256")).unwrap();
            fs::write(dev.join("tpmrm0"), "").unwrap();
        }
        Box_ {
            _tmp: tmp,
            seed,
            sysfs,
            dev,
        }
    }

    /// Everything that happened, in order: acks (`ack:<seq>:<state>`) and commands (`cmd:<line>`).
    type Events = Arc<Mutex<Vec<String>>>;

    /// A FakeRunner that logs its commands into `events`, and records `RESET_SEQ` at the request.
    struct Spy {
        inner: FakeRunner,
        seed: PathBuf,
        events: Events,
        seq_at_request: Mutex<Option<String>>,
    }

    impl Runner for Spy {
        fn run(&self, cmd: &crate::runner::Cmd) -> anyhow::Result<Output> {
            let line = cmd.line();
            if line.starts_with(REQUEST) {
                *self.seq_at_request.lock().unwrap() =
                    fs::read_to_string(self.seed.join(RESET_SEQ)).ok();
            }
            self.events.lock().unwrap().push(format!("cmd:{line}"));
            self.inner.run(cmd)
        }
    }

    fn spy(m: &Box_, tpm: bool, events: &Events) -> Arc<Spy> {
        let f = FakeRunner::new();
        let has = if tpm {
            "yes\n+firmware\n+driver\n+system\n+subsystem\n+libraries\n"
        } else {
            "no\n-firmware\n-driver\n+system\n+subsystem\n+libraries\n"
        };
        f.respond("systemd-analyze has-tpm2", Output::fail(1, has));
        Arc::new(Spy {
            inner: f,
            seed: m.seed.clone(),
            events: events.clone(),
            seq_at_request: Mutex::new(None),
        })
    }

    /// Answers every result POST with `code` (`running` with `running_code`), logging it.
    struct Acks {
        events: Events,
        bodies: Arc<Mutex<Vec<(u64, InboxResult)>>>,
        code: u16,
        running_code: u16,
    }

    impl Respond for Acks {
        fn respond(&self, r: &Request) -> ResponseTemplate {
            let seq: u64 = r.url.path().split('/').nth(3).unwrap().parse().unwrap();
            let body: InboxResult = serde_json::from_slice(&r.body).unwrap();
            let state = serde_json::to_string(&body.state).unwrap();
            self.events
                .lock()
                .unwrap()
                .push(format!("ack:{seq}:{}", state.trim_matches('"')));
            let code = if body.state == InboxResultState::Running {
                self.running_code
            } else {
                self.code
            };
            self.bodies.lock().unwrap().push((seq, body));
            ResponseTemplate::new(code)
        }
    }

    struct Srv {
        srv: MockServer,
        events: Events,
        bodies: Arc<Mutex<Vec<(u64, InboxResult)>>>,
    }

    async fn server(messages: Vec<InboxMessage>, running_code: u16) -> Srv {
        let srv = MockServer::start().await;
        let events: Events = Default::default();
        let bodies: Arc<Mutex<Vec<(u64, InboxResult)>>> = Default::default();
        let last_seq = messages.iter().map(|m| m.seq).max().unwrap_or(0);
        Mock::given(method("GET"))
            .and(path("/v1/inbox"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(InboxPage { messages, last_seq }),
            )
            .mount(&srv)
            .await;
        Mock::given(method("POST"))
            .and(wiremock::matchers::path_regex(r"^/v1/inbox/\d+/result$"))
            .respond_with(Acks {
                events: events.clone(),
                bodies: bodies.clone(),
                code: 204,
                running_code,
            })
            .mount(&srv)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/status"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&srv)
            .await;
        Srv {
            srv,
            events,
            bodies,
        }
    }

    fn fetcher(base: &str) -> Fetcher {
        Fetcher::from_seed(&Seed {
            server_url: base.into(),
            trust: vec![],
            fetch_token: Some("ft".into()),
            group: None,
            oidc: None,
            min_version: None,
            school_id: None,
            wifi: vec![],
            school_name: None,
            it_account: None,
        })
    }

    fn cred() -> DeviceCred {
        DeviceCred {
            device_id: "dev-1".into(),
            secret: "s3cret-device".into(),
        }
    }

    fn status() -> StatusReport {
        StatusReport {
            device_id: "dev-1".into(),
            serial: Some("SN-1".into()),
            model: None,
            os_version: None,
            agent_version: "0".into(),
            bundle_version: Some(3),
            group: "default".into(),
            group_source: GroupSource::Bundle,
            locked: false,
            stale: false,
            last_fetch_ok: None,
            results: vec![],
            fresh_until: None,
            newer_withheld: None,
            seed_trust_fingerprints: vec![],
            imported_from_seed_at: None,
            manifest_features: vec![],
            os_pending_version: None,
        }
    }

    /// Runs one sync on machine `m` against `s` at `now`; returns the outcome and what `persist`
    /// was called with.
    async fn run(
        m: &Box_,
        runner: Arc<dyn Runner>,
        s: &Srv,
        now: DateTime<Utc>,
        after: u64,
    ) -> (SyncOutcome, Vec<u64>) {
        let clock = move || now;
        run_clock(m, runner, s, &clock, after).await
    }

    /// Like `run`, the machine's clock read through `clock` each time.
    async fn run_clock(
        m: &Box_,
        runner: Arc<dyn Runner>,
        s: &Srv,
        clock: &(dyn Fn() -> DateTime<Utc> + Send + Sync),
        after: u64,
    ) -> (SyncOutcome, Vec<u64>) {
        let saved = Mutex::new(vec![]);
        let persist = |n: u64| saved.lock().unwrap().push(n);
        let f = fetcher(&s.srv.uri());
        let c = cred();
        let out = sync(
            &InboxCtx {
                fetcher: &f,
                cred: &c,
                runner,
                seed_dir: &m.seed,
                seed_requires_mount: false,
                sysfs: m.sysfs.clone(),
                dev: m.dev.clone(),
                clock,
                status: status(),
                lab: true,
                persist: &persist,
                upload_queue: m.queue(),
            },
            after,
        )
        .await;
        let saved = saved.into_inner().unwrap();
        (out, saved)
    }

    fn acks(s: &Srv) -> Vec<(u64, InboxResultState, String)> {
        s.bodies
            .lock()
            .unwrap()
            .iter()
            .map(|(q, b)| (*q, b.state, b.detail.clone().unwrap_or_default()))
            .collect()
    }

    fn cmds(events: &Events) -> Vec<String> {
        events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.starts_with("cmd:"))
            .cloned()
            .collect()
    }

    #[tokio::test]
    async fn inbox_dedups_by_seq() {
        let m = machine(true);
        // Out of order, with two at or below `after`.
        let s = server(
            vec![
                msg(5, "x-new", None),
                msg(2, "x-new", None),
                msg(3, "x-new", None),
                msg(1, "x-new", None),
            ],
            204,
        )
        .await;
        let r = spy(&m, true, &s.events);
        let (out, saved) = run(&m, r, &s, now(), 2).await;
        assert!(out.error.is_none(), "{:?}", out.error);
        assert_eq!(out.inbox_after, 5);
        assert!(!out.resetting);
        let seqs: Vec<u64> = acks(&s).iter().map(|a| a.0).collect();
        assert_eq!(seqs, [3, 5], "ascending, nothing at or below after");
        assert_eq!(saved, [3, 5], "saved after each ack");
        let q = s.srv.received_requests().await.unwrap();
        assert!(q
            .iter()
            .any(|r| r.url.path() == "/v1/inbox" && r.url.query() == Some("after=2")));
    }

    #[tokio::test]
    async fn reset_not_run_without_running_ack() {
        let m = machine(true);
        let s = server(vec![reset_msg(4)], 500).await;
        let r = spy(&m, true, &s.events);
        let (out, saved) = run(&m, r.clone(), &s, now(), 3).await;
        assert!(out.error.is_some(), "the sync stops");
        assert!(!out.resetting);
        assert_eq!(out.inbox_after, 3, "not advanced");
        assert!(saved.is_empty());
        let c = cmds(&s.events);
        assert!(
            !c.iter()
                .any(|l| l.contains(FACTORY_RESET) || l.contains(REBOOT)),
            "{c:?}"
        );
        assert!(!m.seed.join(RESET_SEQ).exists());
        assert_eq!(
            acks(&s).iter().map(|a| a.1).collect::<Vec<_>>(),
            [InboxResultState::Running],
            "no other ack after the failed running ack"
        );
    }

    #[tokio::test]
    async fn reset_runs_after_running_ack() {
        use std::os::unix::fs::PermissionsExt;
        let m = machine(true);
        // A later message is not touched once the reset started.
        let s = server(vec![reset_msg(7), msg(8, "x-new", None)], 204).await;
        let r = spy(&m, true, &s.events);
        let (out, saved) = run(&m, r.clone(), &s, now(), 6).await;
        assert!(out.error.is_none(), "{:?}", out.error);
        assert!(out.resetting);
        assert_eq!(out.inbox_after, 7);
        assert!(saved.contains(&7));
        let ev: Vec<String> = s
            .events
            .lock()
            .unwrap()
            .iter()
            // The TPM probe's own commands (precheck) are not part of the order.
            .filter(|e| e.starts_with("ack:") || e.contains(FACTORY_RESET) || e.contains(REBOOT))
            .cloned()
            .collect();
        assert_eq!(
            ev,
            [
                "ack:7:running".to_string(),
                format!("cmd:{REQUEST}"),
                format!("cmd:{REBOOT}"),
            ],
            "running ack, then request, then reboot; nothing for seq 8"
        );
        assert_eq!(
            r.seq_at_request.lock().unwrap().as_deref(),
            Some("7\n"),
            "RESET_SEQ written before the request"
        );
        let mode = fs::metadata(m.seed.join(RESET_SEQ))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(acks(&s)[0].2, DETAIL_RUNNING);
    }

    #[tokio::test]
    async fn reset_precheck_failure_reports_failed() {
        let m = machine(false);
        let s = server(vec![reset_msg(2)], 204).await;
        let r = spy(&m, false, &s.events);
        let (out, saved) = run(&m, r, &s, now(), 1).await;
        assert!(out.error.is_none());
        assert!(!out.resetting);
        assert_eq!(out.inbox_after, 2);
        assert_eq!(saved, [2]);
        let a = acks(&s);
        assert_eq!(a.len(), 1, "{a:?}");
        assert_eq!(a[0].1, InboxResultState::Failed);
        assert!(a[0].2.contains("TPM"), "{a:?}");
        let c = cmds(&s.events);
        assert!(
            !c.iter()
                .any(|l| l.contains(FACTORY_RESET) || l.contains(REBOOT)),
            "{c:?}"
        );
        assert!(!m.seed.join(RESET_SEQ).exists());
    }

    #[tokio::test]
    async fn request_failure_reports_failed_and_forgets_seq() {
        let m = machine(true);
        let s = server(vec![reset_msg(2)], 204).await;
        let r = spy(&m, true, &s.events);
        r.inner
            .respond(REQUEST, Output::fail(1, "Failed to set EFI variable"));
        let (out, _) = run(&m, r, &s, now(), 1).await;
        assert!(!out.resetting);
        assert_eq!(out.inbox_after, 2);
        let a = acks(&s);
        assert_eq!(
            a.iter().map(|a| a.1).collect::<Vec<_>>(),
            [InboxResultState::Running, InboxResultState::Failed]
        );
        assert!(a[1].2.contains("systemd-factory-reset request"), "{a:?}");
        assert!(a[1].2.contains("Failed to set EFI variable"), "{a:?}");
        assert!(!cmds(&s.events).iter().any(|l| l.contains(REBOOT)));
        assert!(
            !m.seed.join(RESET_SEQ).exists(),
            "no reset follows: nothing to report done after"
        );
    }

    #[tokio::test]
    async fn expired_locally_not_run() {
        let m = machine(true);
        let s = server(
            vec![msg(3, KIND_FACTORY_RESET, Some("2026-10-27T07:59:59Z"))],
            204,
        )
        .await;
        let r = spy(&m, true, &s.events);
        let (out, _) = run(&m, r, &s, now(), 0).await;
        assert_eq!(out.inbox_after, 3);
        assert_eq!(
            acks(&s),
            [(3, InboxResultState::Failed, DETAIL_EXPIRED.to_string())]
        );
        assert!(cmds(&s.events).is_empty());
    }

    #[tokio::test]
    async fn clock_before_2026_not_run() {
        let m = machine(true);
        let s = server(
            vec![msg(3, KIND_FACTORY_RESET, Some("2025-06-02T00:00:00Z"))],
            204,
        )
        .await;
        let r = spy(&m, true, &s.events);
        let (out, _) = run(&m, r, &s, t("2025-12-31T23:59:59Z"), 0).await;
        assert_eq!(out.inbox_after, 3);
        assert_eq!(
            acks(&s),
            [(3, InboxResultState::Failed, DETAIL_CLOCK.to_string())]
        );
        assert!(cmds(&s.events).is_empty());
    }

    #[tokio::test]
    async fn unknown_kind_fails() {
        let m = machine(true);
        let s = server(vec![msg(9, "reboot", Some("2026-10-28T00:00:00Z"))], 204).await;
        let r = spy(&m, true, &s.events);
        let (out, _) = run(&m, r, &s, now(), 0).await;
        assert_eq!(out.inbox_after, 9);
        assert_eq!(
            acks(&s),
            [(9, InboxResultState::Failed, DETAIL_UNSUPPORTED.to_string())]
        );
        assert!(cmds(&s.events).is_empty());
    }

    #[tokio::test]
    async fn failed_ack_stops_the_sync() {
        let m = machine(true);
        let srv = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/inbox"))
            .respond_with(ResponseTemplate::new(200).set_body_json(InboxPage {
                messages: vec![msg(1, "x-new", None), msg(2, "x-new", None)],
                last_seq: 2,
            }))
            .mount(&srv)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&srv)
            .await;
        let s = Srv {
            srv,
            events: Default::default(),
            bodies: Default::default(),
        };
        let r = spy(&m, true, &s.events);
        let (out, saved) = run(&m, r, &s, now(), 0).await;
        assert!(out.error.is_some());
        assert_eq!(out.inbox_after, 0);
        assert!(saved.is_empty());
        let posts = s
            .srv
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.method == wiremock::http::Method::POST)
            .count();
        assert_eq!(posts, 1, "stops at the first failed ack");
    }

    #[test]
    fn reset_seq_round_trip() {
        let m = machine(true);
        assert_eq!(read_reset_seq(&m.seed, false).unwrap(), None);
        fs::write(m.seed.join(RESET_SEQ), "42\n").unwrap();
        assert_eq!(read_reset_seq(&m.seed, false).unwrap(), Some(42));
        fs::write(m.seed.join(RESET_SEQ), "junk").unwrap();
        assert!(read_reset_seq(&m.seed, false).is_err());
        // Required to be a mount point: a temporary directory is not one, so nothing is read.
        fs::write(m.seed.join(RESET_SEQ), "42\n").unwrap();
        assert_eq!(read_reset_seq(&m.seed, true).unwrap(), None);
    }

    #[tokio::test]
    async fn done_ack_removes_reset_seq_only_on_success() {
        let m = machine(true);
        fs::write(m.seed.join(RESET_SEQ), "7\n").unwrap();
        let f = fetcher("http://127.0.0.1:9");
        let c = cred();
        let persist = |_: u64| {};
        fn cx<'a>(
            m: &'a Box_,
            f: &'a Fetcher,
            c: &'a DeviceCred,
            persist: &'a (dyn Fn(u64) + Send + Sync),
        ) -> InboxCtx<'a> {
            InboxCtx {
                fetcher: f,
                cred: c,
                runner: Arc::new(FakeRunner::new()),
                seed_dir: &m.seed,
                seed_requires_mount: false,
                sysfs: m.sysfs.clone(),
                dev: m.dev.clone(),
                clock: &now,
                status: status(),
                lab: true,
                persist,
                upload_queue: m.queue(),
            }
        }
        assert!(ack_reset_done(&cx(&m, &f, &c, &persist), 7).await.is_err());
        assert!(m.seed.join(RESET_SEQ).exists(), "kept for the next try");
        let s = server(vec![], 204).await;
        let f = fetcher(&s.srv.uri());
        ack_reset_done(&cx(&m, &f, &c, &persist), 7).await.unwrap();
        assert_eq!(
            acks(&s),
            [(7, InboxResultState::Done, DETAIL_DONE.to_string())]
        );
        assert!(!m.seed.join(RESET_SEQ).exists());
    }

    /// The server refuses `running` with 409 (the message expired or was otherwise finished
    /// there): nothing runs, no `failed` ack follows, and the seq is passed (it is final there).
    #[tokio::test]
    async fn reset_not_run_when_running_ack_conflicts() {
        let m = machine(true);
        let s = server(vec![reset_msg(4), msg(5, "x-new", None)], 409).await;
        let r = spy(&m, true, &s.events);
        let (out, saved) = run(&m, r, &s, now(), 3).await;
        assert!(out.error.is_none(), "{:?}", out.error);
        assert!(!out.resetting);
        assert_eq!(out.inbox_after, 5, "past the refused one, on to the next");
        assert!(saved.contains(&4));
        let c = cmds(&s.events);
        assert!(
            !c.iter()
                .any(|l| l.contains(FACTORY_RESET) || l.contains(REBOOT)),
            "{c:?}"
        );
        assert!(!m.seed.join(RESET_SEQ).exists());
        assert_eq!(
            acks(&s).iter().map(|a| (a.0, a.1)).collect::<Vec<_>>(),
            [
                (4, InboxResultState::Running),
                (5, InboxResultState::Failed)
            ],
            "no failed ack for the refused reset"
        );
    }

    /// The clock is read when each check is made: a command that expires while the precheck runs
    /// (the TPM probe can take over 30 s) is not started.
    #[tokio::test]
    async fn reset_expiring_during_precheck_not_run() {
        let m = machine(true);
        let s = server(
            vec![msg(4, KIND_FACTORY_RESET, Some("2026-10-27T08:00:30Z"))],
            204,
        )
        .await;
        let r = spy(&m, true, &s.events);
        let reads = std::sync::atomic::AtomicUsize::new(0);
        // First read: 08:00:00 (not yet expired); every later read: 08:01:00.
        let clock = || {
            if reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                now()
            } else {
                t("2026-10-27T08:01:00Z")
            }
        };
        let (out, _) = run_clock(&m, r, &s, &clock, 3).await;
        assert_eq!(out.inbox_after, 4);
        assert_eq!(
            acks(&s),
            [(4, InboxResultState::Failed, DETAIL_EXPIRED.to_string())]
        );
        let c = cmds(&s.events);
        assert!(
            !c.iter()
                .any(|l| l.contains(FACTORY_RESET) || l.contains(REBOOT)),
            "{c:?}"
        );
    }

    fn collect_msg(seq: u64, payload: serde_json::Value) -> InboxMessage {
        let mut m = msg(seq, KIND_COLLECT_DIAGNOSTICS, Some("2026-10-28T07:00:00Z"));
        m.payload = payload;
        m
    }

    const START_UPLOAD: &str =
        "cmd:systemctl --no-ask-password start --no-block mastersos-upload.service";

    /// The collection is only queued: the next message is handled in the same sync, nothing is
    /// collected in the agent, the upload service is started.
    #[tokio::test]
    async fn collect_does_not_block_next_inbox_message() {
        let m = machine(true);
        let s = server(
            vec![
                collect_msg(5, serde_json::json!({"boots": 2})),
                msg(6, "x-new", None),
            ],
            204,
        )
        .await;
        let r = spy(&m, true, &s.events);
        let (out, saved) = run(&m, r, &s, now(), 4).await;
        assert!(out.error.is_none(), "{:?}", out.error);
        assert_eq!(out.inbox_after, 6);
        assert_eq!(saved, [5, 6]);
        assert_eq!(
            acks(&s),
            [
                (5, InboxResultState::Running, DETAIL_COLLECTING.to_string()),
                (6, InboxResultState::Failed, DETAIL_UNSUPPORTED.to_string()),
            ]
        );
        let c = cmds(&s.events);
        assert_eq!(
            c,
            [START_UPLOAD],
            "only the service start, no collecting here"
        );
        let items = m.queue().list().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].job,
            crate::upload::queue::Job::Collect {
                seq: 5,
                request: CollectDiagnostics {
                    boots: Some(2),
                    since_hours: None
                },
                expires_at: Some(t("2026-10-28T07:00:00Z")),
                tries: 0,
            }
        );
    }

    #[tokio::test]
    async fn invalid_payload_is_failed_not_run() {
        let m = machine(true);
        let s = server(
            vec![
                collect_msg(1, serde_json::json!({"boots": 1, "since_hours": 2})),
                collect_msg(2, serde_json::json!({"boots": 9})),
                collect_msg(3, serde_json::json!({"boots": "many"})),
            ],
            204,
        )
        .await;
        let r = spy(&m, true, &s.events);
        let (out, _) = run(&m, r, &s, now(), 0).await;
        assert_eq!(out.inbox_after, 3);
        let a = acks(&s);
        assert_eq!(a.len(), 3, "{a:?}");
        for (_, state, detail) in &a {
            assert_eq!(*state, InboxResultState::Failed);
            assert!(detail.starts_with("bad payload: "), "{detail}");
        }
        assert!(cmds(&s.events).is_empty());
        assert!(m.queue().list().unwrap().is_empty());
    }

    /// `running` refused (409): nothing is queued, nothing started.
    #[tokio::test]
    async fn collect_not_queued_when_running_is_refused() {
        let m = machine(true);
        let s = server(vec![collect_msg(4, serde_json::json!({}))], 409).await;
        let r = spy(&m, true, &s.events);
        let (out, _) = run(&m, r, &s, now(), 3).await;
        assert!(out.error.is_none());
        assert_eq!(out.inbox_after, 4);
        assert!(cmds(&s.events).is_empty());
        assert!(m.queue().list().unwrap().is_empty());
    }

    /// 404 on the `done` ack: the server has no such message (purged after 90 days): final, the
    /// file goes.
    #[tokio::test]
    async fn done_ack_404_is_final() {
        let m = machine(true);
        fs::write(m.seed.join(RESET_SEQ), "7\n").unwrap();
        let srv = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/inbox/7/result"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&srv)
            .await;
        let f = fetcher(&srv.uri());
        let c = cred();
        let persist = |_: u64| {};
        let clock = now;
        let cx = InboxCtx {
            fetcher: &f,
            cred: &c,
            runner: Arc::new(FakeRunner::new()),
            seed_dir: &m.seed,
            seed_requires_mount: false,
            sysfs: m.sysfs.clone(),
            dev: m.dev.clone(),
            clock: &clock,
            status: status(),
            lab: true,
            persist: &persist,
            upload_queue: m.queue(),
        };
        ack_reset_done(&cx, 7).await.unwrap();
        assert!(!m.seed.join(RESET_SEQ).exists());
    }
}
