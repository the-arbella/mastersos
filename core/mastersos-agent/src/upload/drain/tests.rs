use std::sync::Mutex;

use mastersos_bundle::push::InboxResult;
use mastersos_bundle::Seed;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use super::*;
use crate::runner::{Cmd, FakeRunner, Output};
use crate::upload::queue::{archive_name, collect_name};

fn t(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).unwrap().to_utc()
}

const T0: &str = "2026-11-05T08:00:00Z";
const EXPIRES: &str = "2026-11-05T09:00:00Z";
const USERS: &str = r#"[{"uid":1001,"user":"ana@school.example"},{"uid":60578,"user":"gdm-greeter"},{"uid":0,"user":"root"}]"#;

/// A machine: the state directory is the temporary root; `root/` is what the collector reads.
struct Machine {
    tmp: tempfile::TempDir,
    queue: Queue,
}

impl Machine {
    fn new() -> Machine {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("root")).unwrap();
        std::fs::create_dir_all(tmp.path().join("public")).unwrap();
        let queue = Queue::new(tmp.path());
        Machine { tmp, queue }
    }

    fn paths(&self) -> SysPaths {
        SysPaths {
            root: self.tmp.path().join("root"),
            var_dir: self.tmp.path().join("var"),
            public_dir: self.tmp.path().join("public"),
            state_dir: self.tmp.path().to_path_buf(),
        }
    }

    fn collect(&self, seq: u64) {
        self.queue
            .enqueue_collect(seq, CollectDiagnostics::default(), Some(t(EXPIRES)), t(T0))
            .unwrap();
    }

    fn battery(&self, capacity: u32, status: &str, ac_online: bool) {
        let ps = self.tmp.path().join("root/sys/class/power_supply");
        let bat = ps.join("BAT0");
        std::fs::create_dir_all(&bat).unwrap();
        std::fs::write(bat.join("type"), "Battery\n").unwrap();
        std::fs::write(bat.join("capacity"), format!("{capacity}\n")).unwrap();
        std::fs::write(bat.join("status"), format!("{status}\n")).unwrap();
        let ac = ps.join("AC");
        std::fs::create_dir_all(&ac).unwrap();
        std::fs::write(ac.join("type"), "Mains\n").unwrap();
        std::fs::write(ac.join("online"), if ac_online { "1\n" } else { "0\n" }).unwrap();
    }
}

/// A runner that answers `loginctl list-users` and records, at the first `journalctl`, what
/// the login screen's marker said.
struct Spy {
    inner: FakeRunner,
    marker_at_journal: Mutex<Option<Option<DateTime<Utc>>>>,
    paths: SysPaths,
}

impl Runner for Spy {
    fn run(&self, cmd: &Cmd) -> anyhow::Result<Output> {
        if cmd.line().starts_with("journalctl") {
            let mut m = self.marker_at_journal.lock().unwrap();
            if m.is_none() {
                *m = Some(crate::status::collecting_until(&self.paths));
            }
        }
        self.inner.run(cmd)
    }
}

fn spy(m: &Machine) -> Arc<Spy> {
    let inner = FakeRunner::new();
    for _ in 0..10 {
        inner.respond("loginctl list-users", Output::ok(USERS));
    }
    Arc::new(Spy {
        inner,
        marker_at_journal: Mutex::new(None),
        paths: m.paths(),
    })
}

type Acks = Arc<Mutex<Vec<(u64, InboxResultState, String)>>>;

struct AckRec {
    acks: Acks,
    code: u16,
}

impl Respond for AckRec {
    fn respond(&self, r: &Request) -> ResponseTemplate {
        let seq: u64 = r.url.path().split('/').nth(3).unwrap().parse().unwrap();
        let b: InboxResult = serde_json::from_slice(&r.body).unwrap();
        self.acks
            .lock()
            .unwrap()
            .push((seq, b.state, b.detail.unwrap_or_default()));
        ResponseTemplate::new(self.code)
    }
}

/// `POST /v1/diagnostics`: a presigned URL on the same server, signed for the size asked.
struct Presign {
    base: String,
    asked: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl Respond for Presign {
    fn respond(&self, r: &Request) -> ResponseTemplate {
        let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        let bytes = body["bytes"].as_u64().unwrap();
        self.asked.lock().unwrap().push(body);
        ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "abc123",
            "upload": {
                "method": "PUT",
                "url": format!("{}/s3/obj?X-Amz-Signature=sig", self.base),
                "headers": {
                    "Content-Length": bytes.to_string(),
                    "x-amz-checksum-sha256": "q83vEjRWeJA=",
                    "x-amz-sdk-checksum-algorithm": "SHA256",
                    "x-amz-tagging": "state=pending",
                },
                "expires_at": "2026-11-05T08:15:00Z",
                "expires_in": 900,
            }
        }))
    }
}

struct Cloud {
    srv: MockServer,
    acks: Acks,
    asked: Arc<Mutex<Vec<serde_json::Value>>>,
}

/// The cloud and S3: step 1 answers `step1` (None: a presigned URL), the PUT `put`.
async fn cloud(step1: Option<ResponseTemplate>, put: u16, ack_code: u16) -> Cloud {
    let srv = MockServer::start().await;
    let acks: Acks = Default::default();
    let asked: Arc<Mutex<Vec<serde_json::Value>>> = Default::default();
    Mock::given(method("POST"))
        .and(path_regex(r"^/v1/inbox/\d+/result$"))
        .respond_with(AckRec {
            acks: acks.clone(),
            code: ack_code,
        })
        .mount(&srv)
        .await;
    let m = Mock::given(method("POST")).and(path("/v1/diagnostics"));
    match step1 {
        Some(r) => m.respond_with(r).mount(&srv).await,
        None => {
            m.respond_with(Presign {
                base: srv.uri(),
                asked: asked.clone(),
            })
            .mount(&srv)
            .await
        }
    }
    Mock::given(method("PUT"))
        .and(path("/s3/obj"))
        .respond_with(ResponseTemplate::new(put))
        .mount(&srv)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/diagnostics/abc123/complete"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&srv)
        .await;
    Cloud { srv, acks, asked }
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

/// One drain pass on `m` against `c` at `now` (a fresh context each time: a new process).
async fn pass(m: &Machine, c: &Cloud, runner: Arc<dyn Runner>, now: &str) -> Pass {
    let f = fetcher(&c.srv.uri());
    let cr = cred();
    let now = t(now);
    let clock = move || now;
    let cx = DrainCtx {
        queue: &m.queue,
        fetcher: &f,
        cred: &cr,
        runner,
        paths: m.paths(),
        device_id: "dev-1",
        lab: true,
        clock: &clock,
        jitter: Jitter::fixed(0.5),
        max_queue_bytes: MAX_QUEUE_BYTES,
    };
    drain_once(&cx).await
}

fn acks(c: &Cloud) -> Vec<(u64, InboxResultState, String)> {
    c.acks.lock().unwrap().clone()
}

fn journal_calls(r: &FakeRunner) -> usize {
    r.calls()
        .iter()
        .filter(|l| l.starts_with("journalctl"))
        .count()
}

/// The inbox acked `running` and queued the command (inbox tests); the drain collects,
/// uploads in three steps and acks `done` with the upload id.
#[tokio::test]
async fn collect_acks_running_then_done_with_id() {
    let m = Machine::new();
    m.collect(7);
    let c = cloud(None, 200, 204).await;
    let r = spy(&m);
    let p = pass(&m, &c, r.clone(), T0).await;
    assert_eq!(p, Pass::default(), "nothing left");
    assert_eq!(
        acks(&c),
        [(7, InboxResultState::Done, "diag:abc123".to_string())]
    );
    let asked = c.asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0]["kind"], "inbox");
    assert_eq!(asked[0]["inbox_seq"], 7);
    assert_eq!(journal_calls(&r.inner), 1, "one boot by default");
    assert!(m.queue.is_empty(), "items and archive gone");
}

#[tokio::test]
async fn notice_shown_when_collect_starts() {
    let m = Machine::new();
    // A status.json the agent wrote: the notice goes into it while collecting.
    let st = crate::status::Status::new(
        crate::status::Net::Ok,
        None,
        crate::status::Settings::Ok,
        None,
        crate::status::Browser::Ok,
        None,
    );
    crate::status::write_status(&m.paths(), &st).unwrap();
    m.collect(7);
    let c = cloud(None, 200, 204).await;
    let r = spy(&m);
    pass(&m, &c, r.clone(), T0).await;
    let calls = r.inner.calls();
    let notify: Vec<&String> = calls.iter().filter(|l| l.contains("notify-send")).collect();
    assert_eq!(
        notify.len(),
        1,
        "only the person, not root or the greeter: {calls:?}"
    );
    assert!(
        notify[0].starts_with("systemd-run --machine=1001@.host --user"),
        "{}",
        notify[0]
    );
    assert!(
        notify[0].ends_with(" MastersOS IT is collecting diagnostic info from this computer."),
        "{}",
        notify[0]
    );
    let first_journal = calls
        .iter()
        .position(|l| l.starts_with("journalctl"))
        .unwrap();
    let notified = calls
        .iter()
        .position(|l| l.contains("notify-send"))
        .unwrap();
    assert!(
        notified < first_journal,
        "the notice comes before collecting"
    );
    assert_eq!(
        *r.marker_at_journal.lock().unwrap(),
        Some(Some(t(T0) + NOTICE_FOR)),
        "the login screen's line is up while collecting"
    );
    assert_eq!(
        crate::status::collecting_until(&m.paths()),
        None,
        "and gone after"
    );
    let after = crate::status::read_status(&m.paths()).unwrap();
    assert_eq!(after.diag_collecting_until, None);
}

/// S3 keeps failing: kept and retried with the backoff; past the command's deadline it is
/// acked `failed` with the last upload error.
#[tokio::test]
async fn upload_failure_retries_until_expiry_then_failed_with_upload_prefix() {
    let m = Machine::new();
    m.collect(7);
    let c = cloud(None, 503, 204).await;
    let r = spy(&m);
    let p = pass(&m, &c, r.clone(), T0).await;
    assert!(acks(&c).is_empty(), "nothing final yet");
    assert_eq!(p.remaining, 1);
    assert_eq!(p.next_due, Some(t("2026-11-05T08:01:00Z")), "1 min backoff");
    // Not due yet: nothing is sent.
    pass(&m, &c, r.clone(), "2026-11-05T08:00:30Z").await;
    assert_eq!(c.asked.lock().unwrap().len(), 1);
    let p = pass(&m, &c, r.clone(), "2026-11-05T08:01:00Z").await;
    assert_eq!(c.asked.lock().unwrap().len(), 2);
    assert_eq!(p.next_due, Some(t("2026-11-05T08:03:00Z")), "doubled");
    // A kick (full connectivity) makes it due at once.
    m.queue.mark_kicked(t("2026-11-05T08:01:30Z")).unwrap();
    pass(&m, &c, r.clone(), "2026-11-05T08:01:40Z").await;
    assert_eq!(c.asked.lock().unwrap().len(), 3);
    assert!(acks(&c).is_empty());
    let p = pass(&m, &c, r.clone(), "2026-11-05T09:00:00Z").await;
    assert_eq!(
        c.asked.lock().unwrap().len(),
        3,
        "not tried after the deadline"
    );
    let a = acks(&c);
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].0, 7);
    assert_eq!(a[0].1, InboxResultState::Failed);
    assert!(a[0].2.starts_with("upload: "), "{}", a[0].2);
    assert!(a[0].2.contains("503"), "{}", a[0].2);
    assert!(!a[0].2.contains("X-Amz-Signature"), "{}", a[0].2);
    assert_eq!(p.remaining, 0);
    assert_eq!(journal_calls(&r.inner), 1, "collected once");
}

/// Review Focus 2: the upload stops half-way (the service, the agent or the machine
/// restarts): the next run sends the same archive without collecting again.
#[tokio::test]
async fn resumes_pending_collect_after_restart() {
    let m = Machine::new();
    m.collect(7);
    let failing = cloud(None, 500, 204).await;
    let r1 = spy(&m);
    pass(&m, &failing, r1.clone(), T0).await;
    assert!(acks(&failing).is_empty());
    let target = Target::Inbox { seq: 7 };
    assert!(m.queue.has(&archive_name(&target)), "the archive is kept");
    assert!(!m.queue.has(&collect_name(7)));
    let sha = c_sha(&m.queue, &target);
    // A new process later (after the backoff): the archive goes, the command is done.
    let ok = cloud(None, 200, 204).await;
    let r2 = spy(&m);
    pass(&m, &ok, r2.clone(), "2026-11-05T08:05:00Z").await;
    assert_eq!(
        acks(&ok),
        [(7, InboxResultState::Done, "diag:abc123".to_string())]
    );
    assert_eq!(journal_calls(&r2.inner), 0, "not collected again");
    assert_eq!(ok.asked.lock().unwrap()[0]["sha256"], sha);
    assert!(m.queue.is_empty());

    // Killed after the archive item was written but before the collect item went.
    m.collect(8);
    let r3 = spy(&m);
    pass(&m, &failing, r3.clone(), T0).await;
    m.collect(8); // a no-op: the archive is queued
    assert!(!m.queue.has(&collect_name(8)));
    std::fs::write(
        m.queue.path(&collect_name(8)),
        serde_json::to_vec(&Item::new(
            Job::Collect {
                seq: 8,
                request: CollectDiagnostics::default(),
                expires_at: Some(t(EXPIRES)),
                tries: 1,
            },
            t(T0),
        ))
        .unwrap(),
    )
    .unwrap();
    let r4 = spy(&m);
    pass(&m, &ok, r4.clone(), "2026-11-05T08:05:00Z").await;
    assert_eq!(journal_calls(&r4.inner), 0);
    assert_eq!(acks(&ok).len(), 2);
    assert!(m.queue.is_empty());
}

fn c_sha(q: &Queue, t: &Target) -> String {
    let item = q
        .list()
        .unwrap()
        .into_iter()
        .find(|i| i.name() == archive_name(t))
        .unwrap();
    match item.job {
        Job::Archive { sha256, .. } => sha256,
        _ => unreachable!(),
    }
}

/// A collection killed every time (out of memory, say) is given up after a few starts.
#[tokio::test]
async fn collect_gives_up_after_tries() {
    let m = Machine::new();
    let mut item = Item::new(
        Job::Collect {
            seq: 3,
            request: CollectDiagnostics::default(),
            expires_at: Some(t(EXPIRES)),
            tries: MAX_COLLECT_TRIES,
        },
        t(T0),
    );
    item.retry = Default::default();
    m.queue.put(&item).unwrap();
    let c = cloud(None, 200, 204).await;
    let r = spy(&m);
    pass(&m, &c, r.clone(), T0).await;
    let a = acks(&c);
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].1, InboxResultState::Failed);
    assert!(a[0].2.starts_with("collect: "), "{}", a[0].2);
    assert_eq!(journal_calls(&r.inner), 0);
}

#[tokio::test]
async fn expired_collect_is_failed_not_run() {
    let m = Machine::new();
    m.collect(3);
    let c = cloud(None, 200, 204).await;
    let r = spy(&m);
    pass(&m, &c, r.clone(), EXPIRES).await;
    assert_eq!(
        acks(&c),
        [(
            3,
            InboxResultState::Failed,
            crate::inbox::DETAIL_EXPIRED.to_string()
        )]
    );
    assert_eq!(journal_calls(&r.inner), 0);
}

/// `not_yours` / `expired` (and any drop): final at once.
#[tokio::test]
async fn give_up_actions_fail_the_command() {
    let m = Machine::new();
    m.collect(5);
    let c = cloud(
        Some(ResponseTemplate::new(410).set_body_json(
            serde_json::json!({"error": {"code": "expired", "message": "too late"}}),
        )),
        200,
        204,
    )
    .await;
    pass(&m, &c, spy(&m), T0).await;
    let a = acks(&c);
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].1, InboxResultState::Failed);
    assert!(a[0].2.starts_with("upload: "), "{}", a[0].2);
    assert!(m.queue.is_empty());
}

/// 429 with Retry-After: waits that long, and a kick does not cut it short.
#[tokio::test]
async fn retry_after_is_honoured_over_kicks() {
    let m = Machine::new();
    m.collect(5);
    let c = cloud(
        Some(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "600")
                .set_body_json(serde_json::json!({"error": {"code": "too_many"}})),
        ),
        200,
        204,
    )
    .await;
    let r = spy(&m);
    let p = pass(&m, &c, r.clone(), T0).await;
    assert_eq!(p.next_due, Some(t("2026-11-05T08:10:00Z")));
    m.queue.mark_kicked(t("2026-11-05T08:01:00Z")).unwrap();
    pass(&m, &c, r.clone(), "2026-11-05T08:02:00Z").await;
    let tries = c
        .srv
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|q| q.url.path() == "/v1/diagnostics")
        .count();
    assert_eq!(tries, 1);
}

/// A final ack that cannot be sent is kept as an `ack` item and sent later; the archive is
/// never uploaded twice.
#[tokio::test]
async fn failed_final_ack_is_kept_and_retried() {
    let m = Machine::new();
    m.collect(7);
    let c = cloud(None, 200, 503).await;
    let r = spy(&m);
    pass(&m, &c, r.clone(), T0).await;
    let items = m.queue.list().unwrap();
    assert_eq!(items.len(), 1);
    assert!(matches!(
        items[0].job,
        Job::Ack {
            seq: 7,
            state: InboxResultState::Done,
            ..
        }
    ));
    let ok = cloud(None, 200, 204).await;
    pass(&m, &ok, r.clone(), "2026-11-05T08:02:00Z").await;
    assert_eq!(
        acks(&ok),
        [(7, InboxResultState::Done, "diag:abc123".to_string())]
    );
    assert!(ok.asked.lock().unwrap().is_empty(), "not uploaded again");
    assert!(m.queue.is_empty());
}

#[tokio::test]
async fn low_battery_holds_collections_and_archives() {
    let m = Machine::new();
    m.battery(10, "Discharging", false);
    assert!(low_battery(&m.paths().root));
    m.collect(7);
    let c = cloud(None, 200, 204).await;
    let r = spy(&m);
    let p = pass(&m, &c, r.clone(), T0).await;
    assert_eq!(p.remaining, 1);
    assert_eq!(
        p.next_due, None,
        "nothing to wait for: the timer looks again"
    );
    assert_eq!(journal_calls(&r.inner), 0);
    assert!(acks(&c).is_empty());
    // Plugged in: it goes.
    m.battery(10, "Charging", true);
    assert!(!low_battery(&m.paths().root));
    pass(&m, &c, r.clone(), T0).await;
    assert_eq!(acks(&c).len(), 1);
    m.battery(40, "Discharging", false);
    assert!(!low_battery(&m.paths().root));
}

#[test]
fn no_battery_is_not_low() {
    let d = tempfile::tempdir().unwrap();
    assert!(!low_battery(d.path()));
}

/// Over the queue's size the oldest archives go and their commands are acked `failed`.
#[tokio::test]
async fn queue_over_cap_drops_oldest_archive() {
    let m = Machine::new();
    m.queue.ensure().unwrap();
    for (seq, at) in [(1u64, "2026-11-05T07:00:00Z"), (2, "2026-11-05T07:30:00Z")] {
        let target = Target::Inbox { seq };
        let file = archive_file(&target);
        std::fs::write(m.queue.path(&file), vec![1u8; 4096]).unwrap();
        let mut item = Item::new(
            Job::Archive {
                target,
                file,
                bytes: 4096,
                sha256: "a".repeat(64),
                expires_at: Some(t(EXPIRES)),
                last_error: None,
            },
            t(at),
        );
        item.retry.failed(t(T0), None, 0.5);
        m.queue.put(&item).unwrap();
    }
    let c = cloud(None, 200, 204).await;
    let f = fetcher(&c.srv.uri());
    let cr = cred();
    let clock = || t(T0);
    let cx = DrainCtx {
        queue: &m.queue,
        fetcher: &f,
        cred: &cr,
        runner: spy(&m),
        paths: m.paths(),
        device_id: "dev-1",
        lab: true,
        clock: &clock,
        jitter: Jitter::fixed(0.5),
        max_queue_bytes: 6000,
    };
    drain_once(&cx).await;
    assert_eq!(
        acks(&c),
        [(1, InboxResultState::Failed, DETAIL_QUEUE_FULL.to_string())]
    );
    assert!(m.queue.has(&archive_name(&Target::Inbox { seq: 2 })));
}
