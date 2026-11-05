//! The sender against a fake cloud: the support host queues the request (as on a machine), one
//! drain pass sends it.

use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use chrono::TimeDelta;
use mastersos_bundle::{DeviceIdent, GroupSource, Seed};
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use super::*;
use crate::backoff::Jitter;
use crate::fetch::{DeviceCred, Fetcher};
use crate::runner::{FakeRunner, Output, Runner};
use crate::support::host::Host;
use crate::support::identity::{Account, Peer, Who};
use crate::support::store::ItemState;
use crate::upload::drain::{drain_once, Pass};
use crate::upload::queue::{archive_name, support_name, Queue, Target, MAX_QUEUE_BYTES};

const T0: &str = "2026-11-05T08:00:00Z";
const ME: u32 = 1000;
const OTHER: u32 = 1001;
const PNG: &[u8] = b"\x89PNG\r\n\x1a\n-not-really-an-image";

fn t(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).unwrap().to_utc()
}

fn at(min: i64) -> DateTime<Utc> {
    t(T0) + TimeDelta::minutes(min)
}

struct Everyone;

impl Who for Everyone {
    fn account(&self, uid: u32) -> Option<Account> {
        Some(Account {
            name: format!("user{uid}"),
            authd: false,
        })
    }
    fn is_greeter(&self, _: &Peer) -> bool {
        false
    }
    fn kiosk_record(&self, _: &str) -> Option<(u32, String)> {
        None
    }
}

/// A machine: `root/` is the system root the collector reads, the agent's state directory
/// is inside it (so the screenshot is read through the root, as in production).
struct Machine {
    tmp: tempfile::TempDir,
    queue: Queue,
}

impl Machine {
    fn new() -> Machine {
        let tmp = tempfile::tempdir().unwrap();
        let m = Machine {
            queue: Queue::new(&tmp.path().join("root/var/lib/mastersos")),
            tmp,
        };
        std::fs::create_dir_all(m.paths().state_dir).unwrap();
        std::fs::create_dir_all(m.paths().public_dir).unwrap();
        std::fs::write(
            m.paths().public_dir.join(crate::support::SUPPORT_JSON),
            r#"{"enabled": true}"#,
        )
        .unwrap();
        m
    }

    fn paths(&self) -> SysPaths {
        let root = self.tmp.path().join("root");
        SysPaths {
            state_dir: root.join("var/lib/mastersos"),
            public_dir: root.join("var/lib/mastersos-public"),
            var_dir: root.join("var/lib/mastersos-system"),
            root,
        }
    }

    fn store(&self) -> Store {
        store(&self.paths())
    }

    fn host(&self) -> Host {
        let p = self.paths();
        Host {
            store: self.store(),
            upload: Queue::new(&p.state_dir),
            public_dir: p.public_dir.clone(),
            root: p.root.clone(),
            os_release: p.root.join("os-release"),
            who: Box::new(Everyone),
            runner: Arc::new(FakeRunner::new()),
        }
    }

    fn ask(&self, req: Value, uid: u32, now: DateTime<Utc>) -> Value {
        let line = format!("{req}\n");
        let peer = Peer {
            uid,
            pid: Some(4242),
        };
        serde_json::to_value(self.host().handle(line.as_bytes(), peer, now)).unwrap()
    }

    /// A student presses Send; the client id.
    fn submit(&self, uid: u32, screenshot: bool, now: DateTime<Utc>) -> String {
        let mut req = json!({"op": "submit", "category": "wifi", "text": "no internet", "session": "desktop"});
        if screenshot {
            req["screenshot_png_b64"] = json!(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                PNG
            ));
        }
        let r = self.ask(req, uid, now);
        assert_eq!(r["ok"], json!(true), "{r}");
        r["client_id"].as_str().unwrap().to_string()
    }

    fn status(&self, id: &str, uid: u32) -> Value {
        self.ask(json!({"op": "status", "client_id": id}), uid, t(T0))
    }

    fn item(&self, id: &str) -> super::super::store::Item {
        self.store().get(id).unwrap().expect("in the store")
    }

    fn has_screenshot(&self, id: &str) -> bool {
        self.store().dir().join(format!("{id}.png")).exists()
    }

    fn battery(&self, capacity: u32) {
        let bat = self.paths().root.join("sys/class/power_supply/BAT0");
        std::fs::create_dir_all(&bat).unwrap();
        std::fs::write(bat.join("type"), "Battery\n").unwrap();
        std::fs::write(bat.join("capacity"), format!("{capacity}\n")).unwrap();
        std::fs::write(bat.join("status"), "Discharging\n").unwrap();
    }
}

type Bodies = Arc<Mutex<Vec<Value>>>;

struct Record {
    bodies: Bodies,
    answer: ResponseTemplate,
}

impl Respond for Record {
    fn respond(&self, r: &Request) -> ResponseTemplate {
        self.bodies
            .lock()
            .unwrap()
            .push(serde_json::from_slice(&r.body).unwrap());
        self.answer.clone()
    }
}

/// `POST /v1/diagnostics`: a presigned URL on the same server.
struct Presign {
    base: String,
    asked: Bodies,
}

impl Respond for Presign {
    fn respond(&self, r: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&r.body).unwrap();
        let bytes = body["bytes"].as_u64().unwrap();
        self.asked.lock().unwrap().push(body);
        ResponseTemplate::new(201).set_body_json(json!({
            "id": "att1",
            "upload": {
                "method": "PUT",
                "url": format!("{}/s3/obj?X-Amz-Signature=sig", self.base),
                "headers": {"Content-Length": bytes.to_string()},
                "expires_at": "2026-11-05T08:15:00Z",
                "expires_in": 900,
            }
        }))
    }
}

struct PutRec {
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    code: u16,
}

impl Respond for PutRec {
    fn respond(&self, r: &Request) -> ResponseTemplate {
        self.bodies.lock().unwrap().push(r.body.clone());
        ResponseTemplate::new(self.code)
    }
}

struct Cloud {
    srv: MockServer,
    support: Bodies,
    asked: Bodies,
    puts: Arc<Mutex<Vec<Vec<u8>>>>,
}

fn ticket(n: &str) -> ResponseTemplate {
    ResponseTemplate::new(201).set_body_json(json!({ "ticket": n }))
}

fn error(status: u16, code: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(json!({"error": {"code": code, "message": "no"}}))
}

/// The cloud: `POST /v1/support` answers `support`, `POST /v1/diagnostics` answers `step1`
/// (None: a presigned URL), the PUT `put`.
async fn cloud(support: ResponseTemplate, step1: Option<ResponseTemplate>, put: u16) -> Cloud {
    let srv = MockServer::start().await;
    let c = Cloud {
        support: Bodies::default(),
        asked: Bodies::default(),
        puts: Arc::default(),
        srv,
    };
    Mock::given(method("POST"))
        .and(path("/v1/support"))
        .respond_with(Record {
            bodies: c.support.clone(),
            answer: support,
        })
        .mount(&c.srv)
        .await;
    let m = Mock::given(method("POST")).and(path("/v1/diagnostics"));
    match step1 {
        Some(r) => {
            m.respond_with(Record {
                bodies: c.asked.clone(),
                answer: r,
            })
            .mount(&c.srv)
            .await
        }
        None => {
            m.respond_with(Presign {
                base: c.srv.uri(),
                asked: c.asked.clone(),
            })
            .mount(&c.srv)
            .await
        }
    }
    Mock::given(method("PUT"))
        .and(path("/s3/obj"))
        .respond_with(PutRec {
            bodies: c.puts.clone(),
            code: put,
        })
        .mount(&c.srv)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/diagnostics/att1/complete"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&c.srv)
        .await;
    c
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

/// NetworkManager as the sender sees it.
fn runner() -> Arc<FakeRunner> {
    let r = FakeRunner::new();
    for _ in 0..5 {
        r.respond(
            "nmcli -t -f STATE,CONNECTIVITY general",
            Output::ok("connected:full\n"),
        );
        r.respond(
            "nmcli -t -f TYPE,STATE,CONNECTION device",
            Output::ok("wifi:connected:School\\: Staff\nethernet:unavailable:\nloopback:connected (externally):lo\n"),
        );
    }
    Arc::new(r)
}

/// One drain pass (a fresh process each time).
async fn pass(m: &Machine, c: &Cloud, runner: Arc<dyn Runner>, now: DateTime<Utc>) -> Pass {
    let f = fetcher(&c.srv.uri());
    let cred = DeviceCred {
        device_id: "dev-1".into(),
        secret: "s3cret-device".into(),
    };
    let clock = move || now;
    let cx = DrainCtx {
        queue: &m.queue,
        fetcher: &f,
        cred: &cred,
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

/// The journal window of a request made at [`T0`]: 30 minutes before to 2 after.
const WINDOW_T0: &str = "--since 2026-11-05 07:30:00 UTC --until 2026-11-05 08:02:00 UTC";

/// The `--since … --until …` of the attachment's journal call.
fn journal_window(r: &FakeRunner) -> Option<String> {
    r.calls().iter().find_map(|l| {
        let rest = l.strip_prefix("journalctl --since ")?;
        let end = rest.find(" -o ")?;
        Some(format!("--since {}", &rest[..end]))
    })
}

fn count<T>(b: &Mutex<Vec<T>>) -> usize {
    b.lock().unwrap().len()
}

fn job(m: &Machine, id: &str) -> Option<QueueItem> {
    m.queue
        .list()
        .unwrap()
        .into_iter()
        .find(|i| i.name() == support_name(id))
}

fn last_report() -> mastersos_bundle::StatusReport {
    crate::report::build(
        &crate::report::Machine {
            ident: DeviceIdent {
                serial: Some("PF1".into()),
                device_id: "dev-1".into(),
            },
            model: None,
            os_version: Some("1".into()),
        },
        &crate::report::Placement {
            bundle_version: Some(3),
            group: "g".into(),
            source: GroupSource::Bundle,
            locked: false,
        },
        &crate::report::Freshness::default(),
        vec![],
        t(T0),
    )
}

/// The files in the attachment archive the cloud received.
fn archive_names(tar_zst: &[u8]) -> Vec<String> {
    let mut tar = vec![];
    zstd::Decoder::new(tar_zst)
        .unwrap()
        .read_to_end(&mut tar)
        .unwrap();
    let mut a = tar::Archive::new(&tar[..]);
    a.entries()
        .unwrap()
        .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
        .collect()
}

#[tokio::test]
async fn drain_posts_then_uploads_ticket_attachment() {
    let m = Machine::new();
    crate::report::save_last(&m.paths().state_dir, &last_report());
    let id = m.submit(ME, true, t(T0));
    assert!(job(&m, &id).is_some(), "the host queued it for the sender");
    let c = cloud(ticket("1042"), None, 200).await;
    let r = runner();
    let p = pass(&m, &c, r.clone(), at(1)).await;
    assert_eq!(p, Pass::default(), "nothing left");

    let sent = c.support.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["client_id"], json!(id));
    assert_eq!(sent[0]["screenshot"], json!(true));
    assert_eq!(
        sent[0]["snapshot"]["network"],
        json!("connected (full); wifi: School: Staff")
    );
    assert_eq!(sent[0]["snapshot"]["status"]["device_id"], json!("dev-1"));

    let asked = c.asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0]["kind"], json!("ticket"));
    assert_eq!(asked[0]["client_id"], json!(id));
    let puts = c.puts.lock().unwrap().clone();
    assert_eq!(puts.len(), 1);
    assert_eq!(puts[0].len() as u64, asked[0]["bytes"].as_u64().unwrap());
    let names = archive_names(&puts[0]);
    assert!(names.contains(&"screenshot.png".to_string()), "{names:?}");
    assert!(
        names.contains(&"journal/recent.txt".to_string()),
        "{names:?}"
    );
    assert_eq!(journal_window(&r), Some(WINDOW_T0.to_string()));

    let item = m.item(&id);
    assert_eq!(item.state, ItemState::Sent);
    assert_eq!(item.ticket.as_deref(), Some("1042"));
    assert!(item.attach_done);
    assert!(!m.has_screenshot(&id), "space freed once attached");
    assert!(m.queue.list().unwrap().is_empty());
}

#[tokio::test]
async fn status_shows_sent_with_ticket_after_drain() {
    let m = Machine::new();
    let id = m.submit(ME, false, t(T0));
    assert_eq!(m.status(&id, ME), json!({"ok": true, "state": "queued"}));
    let c = cloud(ticket("1042"), None, 200).await;
    pass(&m, &c, runner(), at(1)).await;
    assert_eq!(
        m.status(&id, ME),
        json!({"ok": true, "state": "sent", "ticket": "1042"})
    );
    assert_eq!(
        m.status(&id, OTHER),
        json!({"ok": false, "error": "invalid"}),
        "still only for its sender"
    );
}

#[tokio::test]
async fn too_many_retries_after() {
    let m = Machine::new();
    let id = m.submit(ME, false, t(T0));
    let srv = MockServer::start().await;
    let support = Bodies::default();
    Mock::given(method("POST"))
        .and(path("/v1/support"))
        .respond_with(Record {
            bodies: support.clone(),
            answer: error(429, "too_many").insert_header("Retry-After", "600"),
        })
        .up_to_n_times(1)
        .mount(&srv)
        .await;
    let c = cloud(ticket("7"), None, 200).await;
    // The first answer comes from `srv`, the later ones from `c`.
    let first = Cloud {
        srv,
        support: support.clone(),
        asked: Bodies::default(),
        puts: Arc::default(),
    };
    let p = pass(&m, &first, runner(), at(0)).await;
    assert_eq!(count(&support), 1);
    assert_eq!(m.item(&id).state, ItemState::Queued);
    let j = job(&m, &id).unwrap();
    assert_eq!(j.retry.not_before, Some(at(10)), "the server's Retry-After");
    assert!(j.retry.server_said);
    assert_eq!(p.next_due, Some(at(10)));

    // A kick (the network came back) does not override the server.
    m.queue.mark_kicked(at(2)).unwrap();
    pass(&m, &c, runner(), at(5)).await;
    assert_eq!(count(&c.support), 0, "held until Retry-After");
    pass(&m, &c, runner(), at(10)).await;
    assert_eq!(count(&c.support), 1);
    assert_eq!(m.item(&id).ticket.as_deref(), Some("7"));
}

#[tokio::test]
async fn support_disabled_drops_queue() {
    let m = Machine::new();
    let a = m.submit(ME, true, t(T0));
    let b = m.submit(OTHER, true, at(1));
    let c = cloud(error(403, "support_disabled"), None, 200).await;
    let p = pass(&m, &c, runner(), at(2)).await;
    assert_eq!(count(&c.support), 1, "the second is dropped unsent");
    assert_eq!(count(&c.asked), 0, "no attachment");
    for (id, uid) in [(&a, ME), (&b, OTHER)] {
        assert_eq!(m.item(id).state, ItemState::Disabled);
        assert!(!m.has_screenshot(id));
        assert_eq!(m.status(id, uid), json!({"ok": true, "state": "disabled"}));
    }
    assert!(m.queue.list().unwrap().is_empty());
    assert_eq!(p, Pass::default());
}

#[tokio::test]
async fn invalid_is_dropped_as_failed() {
    let m = Machine::new();
    let id = m.submit(ME, true, t(T0));
    let c = cloud(error(422, "invalid"), None, 200).await;
    pass(&m, &c, runner(), at(1)).await;
    assert_eq!(m.item(&id).state, ItemState::Failed);
    assert!(!m.has_screenshot(&id));
    assert!(m.queue.list().unwrap().is_empty());
    assert_eq!(count(&c.asked), 0);
}

#[tokio::test]
async fn attachment_dropped_after_48h_ticket_kept() {
    let m = Machine::new();
    let id = m.submit(ME, true, t(T0));
    // Ticket in; the diagnostics storage is down.
    let c = cloud(
        ticket("1042"),
        Some(error(503, "diagnostics_unavailable")),
        200,
    )
    .await;
    pass(&m, &c, runner(), at(1)).await;
    assert_eq!(m.item(&id).state, ItemState::Sent);
    assert!(!m.item(&id).attach_done);
    let target = Target::Ticket {
        client_id: id.clone(),
    };
    assert!(m.queue.has(&archive_name(&target)), "kept for later");
    assert!(job(&m, &id).is_none(), "the archive carries on");

    // Two days later the cloud says the window has passed.
    let later = cloud(ticket("1042"), Some(error(410, "expired")), 200).await;
    pass(&m, &later, runner(), at(49 * 60)).await;
    assert_eq!(count(&later.support), 0, "the ticket is not sent again");
    assert_eq!(count(&later.asked), 1);
    let item = m.item(&id);
    assert_eq!(item.state, ItemState::Sent);
    assert_eq!(item.ticket.as_deref(), Some("1042"));
    assert!(item.attach_done, "given up");
    assert!(!m.has_screenshot(&id));
    assert!(m.queue.list().unwrap().is_empty(), "attachment deleted");
    assert!(m.queue.is_empty());
}

/// Killed mid-way, twice: after the ticket was recorded (before collecting), and during the
/// upload. Each next run goes on from there and never asks for the ticket again.
#[tokio::test]
async fn restart_midway_resumes_without_resending() {
    let m = Machine::new();
    let id = m.submit(ME, true, t(T0));
    // A run recorded the ticket and died before collecting: its item is still queued.
    {
        let s = m.store();
        let _l = s.lock().unwrap();
        let mut i = s.get(&id).unwrap().unwrap();
        i.state = ItemState::Sent;
        i.ticket = Some("1042".into());
        s.update(&i).unwrap();
    }
    // This run collects; the PUT fails.
    let c = cloud(ticket("9999"), None, 500).await;
    pass(&m, &c, runner(), at(1)).await;
    assert_eq!(count(&c.support), 0);
    assert_eq!(count(&c.puts), 1);
    assert!(!m.item(&id).attach_done);
    assert!(!m.has_screenshot(&id), "in the archive now");

    // The next run (after the backoff) uploads the same archive.
    let c2 = cloud(ticket("9999"), None, 200).await;
    pass(&m, &c2, runner(), at(3)).await;
    assert_eq!(count(&c2.support), 0);
    let puts = c2.puts.lock().unwrap().clone();
    assert_eq!(puts.len(), 1);
    assert!(archive_names(&puts[0]).contains(&"screenshot.png".to_string()));
    let item = m.item(&id);
    assert_eq!(item.ticket.as_deref(), Some("1042"));
    assert!(item.attach_done);
    assert!(m.queue.list().unwrap().is_empty());
}

#[tokio::test]
async fn low_battery_sends_the_request_and_holds_the_attachment() {
    let m = Machine::new();
    m.battery(9);
    let id = m.submit(ME, false, t(T0));
    let c = cloud(ticket("1042"), None, 200).await;
    let r = runner();
    pass(&m, &c, r.clone(), at(1)).await;
    assert_eq!(m.item(&id).ticket.as_deref(), Some("1042"));
    assert!(!r.calls().iter().any(|l| l.starts_with("journalctl")));
    assert!(job(&m, &id).is_some(), "the attachment waits for power");
    assert_eq!(count(&c.asked), 0);
}

#[tokio::test]
async fn finished_requests_go_after_a_week_and_do_not_fill_the_queue() {
    let m = Machine::new();
    let old = m.submit(ME, false, t(T0));
    let c = cloud(ticket("1"), None, 200).await;
    pass(&m, &c, runner(), at(1)).await;
    assert!(m.item(&old).finished());
    // A finished one does not take a place.
    assert!(m.store().with_limits(1, u64::MAX).has_room().unwrap());
    let new = m.submit(ME, false, at(60 * 24 * 6));
    pass(&m, &c, runner(), at(60 * 24 * 7 + 1)).await;
    assert!(m.store().get(&old).unwrap().is_none(), "a week old: gone");
    assert_eq!(m.item(&new).state, ItemState::Sent, "kept");
}

/// A store item whose sender item was lost (an old crash, a hand edit) is queued again.
#[tokio::test]
async fn lost_sender_item_is_queued_again() {
    let m = Machine::new();
    let id = m.submit(ME, false, t(T0));
    m.queue.remove(&job(&m, &id).unwrap()).unwrap();
    // Something else wakes the sender.
    m.queue
        .enqueue_collect(3, Default::default(), Some(at(600)), t(T0))
        .unwrap();
    let c = cloud(ticket("5"), None, 200).await;
    pass(&m, &c, runner(), at(1)).await;
    assert_eq!(m.item(&id).ticket.as_deref(), Some("5"));
}

/// Made offline at T0, sent five hours later: the logs are still the ones around T0, never the
/// later ones (another student, the login screen).
#[tokio::test]
async fn late_send_attaches_the_journal_around_the_request() {
    let m = Machine::new();
    let id = m.submit(ME, false, t(T0));
    let c = cloud(ticket("1042"), None, 200).await;
    let r = runner();
    pass(&m, &c, r.clone(), at(5 * 60)).await;
    assert!(m.item(&id).attach_done);
    assert_eq!(journal_window(&r), Some(WINDOW_T0.to_string()));
    assert!(
        !r.calls().iter().any(|l| l.contains("-30min")),
        "{:?}",
        r.calls()
    );
}

#[tokio::test]
async fn prompt_send_attaches_the_same_window() {
    let m = Machine::new();
    m.submit(ME, false, t(T0));
    let c = cloud(ticket("1042"), None, 200).await;
    let r = runner();
    pass(&m, &c, r.clone(), t(T0)).await;
    assert_eq!(journal_window(&r), Some(WINDOW_T0.to_string()));
}

/// The record of a finished attachment could not be written (the store's lock failed): the
/// archive stays, nothing is collected again, and the next pass records it without a second
/// upload (the cloud says the ticket's attachment is complete).
#[tokio::test]
async fn attachment_record_is_retried_without_a_second_upload() {
    let m = Machine::new();
    let id = m.submit(ME, true, t(T0));
    let c = cloud(ticket("1042"), None, 500).await;
    pass(&m, &c, runner(), at(1)).await;
    let target = Target::Ticket {
        client_id: id.clone(),
    };
    assert!(m.queue.has(&archive_name(&target)));

    // The lock cannot be taken.
    let lock = m.store().dir().join(".lock");
    std::fs::remove_file(&lock).unwrap();
    std::fs::create_dir(&lock).unwrap();
    let c2 = cloud(ticket("1042"), None, 200).await;
    let r = runner();
    pass(&m, &c2, r.clone(), at(3)).await;
    assert_eq!(count(&c2.puts), 1, "uploaded");
    assert!(m.queue.has(&archive_name(&target)), "kept until recorded");
    assert!(job(&m, &id).is_none(), "not queued to collect again");
    assert!(!r.calls().iter().any(|l| l.starts_with("journalctl")));
    std::fs::remove_dir(&lock).unwrap();
    assert!(!m.item(&id).attach_done);

    // The lock works again; the cloud has the attachment already.
    let c3 = cloud(
        ticket("1042"),
        Some(ResponseTemplate::new(200).set_body_json(json!({"id": "att1", "complete": true}))),
        200,
    )
    .await;
    let r = runner();
    pass(&m, &c3, r.clone(), at(10)).await;
    assert_eq!(count(&c3.puts), 0, "no second upload");
    assert!(!r.calls().iter().any(|l| l.starts_with("journalctl")));
    assert!(m.item(&id).attach_done);
    assert!(m.queue.list().unwrap().is_empty());
}

/// A screenshot without its request (a crash between the two writes) goes after 10 minutes; one
/// being written now stays.
#[tokio::test]
async fn orphan_screenshot_is_swept() {
    let m = Machine::new();
    let s = m.store();
    s.lock().unwrap();
    let old = s.dir().join("0192f3a4-5b6c-7d8e-9f00-112233445566.png");
    let fresh = s.dir().join("0192f3a4-5b6c-7d8e-9f00-112233445577.png");
    std::fs::write(&old, PNG).unwrap();
    std::fs::write(&fresh, PNG).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&old)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(11 * 60))
        .unwrap();
    let c = cloud(ticket("1"), None, 200).await;
    pass(&m, &c, runner(), at(1)).await;
    assert!(!old.exists());
    assert!(fresh.exists());
}

/// A request that cannot be written leaves no screenshot behind.
#[test]
fn failed_item_write_leaves_no_screenshot() {
    let m = Machine::new();
    let s = m.store();
    let _l = s.lock().unwrap();
    let id = "0192f3a4-5b6c-7d8e-9f00-112233445566";
    std::fs::create_dir(s.dir().join(format!("{id}.json"))).unwrap();
    let req: mastersos_bundle::diag::SupportRequest = serde_json::from_value(json!({
        "client_id": id, "category": "wifi", "text": "", "user": {"kind": "none"},
        "session": "login", "created_at": T0, "snapshot": {"os_version": "1"}, "screenshot": true,
    }))
    .unwrap();
    let item = super::super::store::Item::new(req, ME, t(T0));
    assert!(s.put_new(&item, Some(PNG)).is_err());
    assert!(!m.has_screenshot(id));
}

#[test]
fn store_dir_is_the_hosts() {
    assert_eq!(
        PathBuf::from(crate::support::QUEUE_DIR),
        SysPaths::default().state_dir.join(STORE_DIR)
    );
}
