use std::collections::BTreeMap;
use std::io::Cursor;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use mastersos_bundle::diag::{SupportCategory, SupportUserKind};
use serde_json::{json, Value};

use super::host::{Host, Reply};
use super::identity::{identify, Account, Peer, SystemWho, Who};
use super::native_host;
use super::store::{ItemState, Store};
use super::*;
use crate::runner::{FakeRunner, Output};

const ME: u32 = 1000;
const OTHER: u32 = 1001;
const GREETER: u32 = 60578;
const KIOSK: u32 = 1900;
const SSO: u32 = 10_042;
const LOGIN1: &str =
    "org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager";

/// Accounts and greeter sessions by uid.
#[derive(Default)]
struct FakeWho {
    accounts: BTreeMap<u32, Account>,
    greeters: Vec<u32>,
    /// The kiosk step's records: id → (uid, name).
    kiosk: BTreeMap<String, (u32, String)>,
    /// How many times anyone asked for an account (identify ran).
    lookups: Arc<std::sync::atomic::AtomicUsize>,
}

impl Who for FakeWho {
    fn account(&self, uid: u32) -> Option<Account> {
        self.lookups
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.accounts.get(&uid).cloned()
    }
    fn is_greeter(&self, peer: &Peer) -> bool {
        self.greeters.contains(&peer.uid)
    }
    fn kiosk_record(&self, id: &str) -> Option<(u32, String)> {
        self.kiosk.get(id).cloned()
    }
}

fn who() -> FakeWho {
    let acct = |name: &str, authd| Account {
        name: name.into(),
        authd,
    };
    FakeWho {
        accounts: BTreeMap::from([
            (ME, acct("student", false)),
            (OTHER, acct("other", false)),
            (GREETER, acct("gdm-greeter", false)),
            (crate::system::guest::GUEST_UID, acct("guest", false)),
            (KIOSK, acct("kiosk-nwea", false)),
            (SSO, acct("ana@school.example", true)),
        ]),
        greeters: vec![GREETER],
        kiosk: BTreeMap::from([("nwea".to_string(), (KIOSK, "kiosk-nwea".to_string()))]),
        lookups: Arc::default(),
    }
}

fn now() -> DateTime<Utc> {
    "2026-11-05T08:30:00Z".parse().unwrap()
}

fn peer(uid: u32) -> Peer {
    Peer {
        uid,
        pid: Some(4242),
    }
}

struct Rig {
    dir: tempfile::TempDir,
    runner: Arc<FakeRunner>,
}

impl Rig {
    fn new() -> Rig {
        let r = Rig {
            dir: tempfile::tempdir().unwrap(),
            runner: Arc::new(FakeRunner::new()),
        };
        std::fs::create_dir_all(r.dir.path().join("state")).unwrap();
        r.set_enabled(Some(true));
        r
    }

    fn public(&self) -> std::path::PathBuf {
        self.dir.path().join("public")
    }

    fn queue(&self) -> std::path::PathBuf {
        self.dir.path().join("state/support-queue")
    }

    fn set_enabled(&self, enabled: Option<bool>) {
        std::fs::create_dir_all(self.public()).unwrap();
        let p = self.public().join(SUPPORT_JSON);
        match enabled {
            Some(e) => std::fs::write(&p, json!({ "enabled": e }).to_string()).unwrap(),
            None => {
                let _ = std::fs::remove_file(&p);
            }
        }
    }

    /// A fresh host over the same directories: what a restarted service sees.
    fn host(&self) -> Host {
        Host {
            store: Store::new(self.queue()),
            upload: crate::upload::queue::Queue::new(&self.dir.path().join("state")),
            public_dir: self.public(),
            root: self.dir.path().to_path_buf(),
            os_release: self.dir.path().join("os-release"),
            who: Box::new(who()),
            runner: self.runner.clone(),
        }
    }

    fn ask(&self, req: Value, uid: u32, at: DateTime<Utc>) -> Value {
        let line = format!("{req}\n");
        reply_value(&self.host().handle(line.as_bytes(), peer(uid), at))
    }
}

fn reply_value(r: &Reply) -> Value {
    serde_json::to_value(r).unwrap()
}

fn submit(category: &str, text: &str, session: &str) -> Value {
    json!({
        "op": "submit",
        "category": category,
        "text": text,
        "session": session,
        "screenshot_png_b64": null,
    })
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
}

/// Review focus 4: who sent it comes from the peer credentials only. A request naming a user (or carrying anything
/// else the protocol does not have) is refused as invalid and nothing is queued; the session the dialog claims loses
/// to the one the system derives.
#[test]
fn rejects_client_supplied_identity() {
    let rig = Rig::new();
    for extra in [
        (
            "user",
            json!({"kind": "sso", "name": "teacher@school.example"}),
        ),
        ("name", json!("teacher")),
        ("kind", json!("sso")),
        ("uid", json!(0)),
    ] {
        let mut req = submit("wifi", "no internet", "desktop");
        req[extra.0] = extra.1;
        assert_eq!(
            rig.ask(req, ME, now()),
            json!({"ok": false, "error": "invalid"}),
            "{}",
            extra.0
        );
    }
    assert_eq!(
        rig.ask(json!({"op": "enabled", "user": "x"}), ME, now()),
        json!({"ok": false, "error": "invalid"})
    );
    assert_eq!(
        rig.ask(
            json!({"op": "status", "client_id": "x", "uid": 1}),
            ME,
            now()
        ),
        json!({"ok": false, "error": "invalid"})
    );
    assert!(Store::new(rig.queue()).list().unwrap().is_empty());

    // A local user claiming the login screen is still a local user on the desktop.
    let r = rig.ask(submit("wifi", "no internet", "login"), ME, now());
    assert_eq!(r["ok"], json!(true), "{r}");
    let item = Store::new(rig.queue())
        .get(r["client_id"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(item.request.user.kind, SupportUserKind::Local);
    assert_eq!(item.request.user.name.as_deref(), Some("student"));
    assert_eq!(item.request.session, "desktop");
    assert_eq!(item.uid, ME);
    // A kiosk account claiming the desktop is its kiosk app.
    let r = rig.ask(submit("app", "", "desktop"), KIOSK, now());
    let item = Store::new(rig.queue())
        .get(r["client_id"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(item.request.session, "kiosk:nwea");
    assert_eq!(item.request.user.kind, SupportUserKind::None);
    assert_eq!(item.request.user.name, None);
}

#[test]
fn greeter_peer_is_none_guest_uid_is_guest() {
    let w = who();
    let id = identify(&peer(GREETER), &w);
    assert_eq!(id.user.kind, SupportUserKind::None);
    assert_eq!(id.user.name, None);
    assert_eq!(id.session, "login");

    let id = identify(&peer(crate::system::guest::GUEST_UID), &w);
    assert_eq!(id.user.kind, SupportUserKind::Guest);
    assert_eq!(id.user.name.as_deref(), Some("guest"));
    assert_eq!(id.session, "desktop");

    let id = identify(&peer(KIOSK), &w);
    assert_eq!(
        (id.user.kind, id.user.name, id.session.as_str()),
        (SupportUserKind::None, None, "kiosk:nwea")
    );
    let id = identify(&peer(SSO), &w);
    assert_eq!(id.user.kind, SupportUserKind::Sso);
    assert_eq!(id.user.name.as_deref(), Some("ana@school.example"));
    assert_eq!(id.session, "desktop");
    let id = identify(&peer(ME), &w);
    assert_eq!(id.user.kind, SupportUserKind::Local);

    // GDM's own accounts are the login screen even without a greeter session in logind.
    let mut w = who();
    w.greeters.clear();
    assert_eq!(identify(&peer(GREETER), &w).session, "login");
    // A uid in the kiosk range whose name is not kiosk-<id> is not a kiosk app.
    w.accounts.insert(
        KIOSK + 1,
        Account {
            name: "mallory".into(),
            authd: false,
        },
    );
    let id = identify(&peer(KIOSK + 1), &w);
    assert_eq!(
        (id.user.kind, id.session.as_str()),
        (SupportUserKind::Local, "desktop")
    );
    // An account outside the kiosk range named like one is not a kiosk app either.
    w.accounts.insert(
        ME + 5,
        Account {
            name: "kiosk-nwea".into(),
            authd: false,
        },
    );
    assert_eq!(identify(&peer(ME + 5), &w).session, "desktop");
    // A kiosk-<id> account in the range that the kiosk step has no record of, or whose record has another uid, is
    // not a locked app either.
    w.accounts.insert(
        KIOSK + 2,
        Account {
            name: "kiosk-other".into(),
            authd: false,
        },
    );
    assert_eq!(identify(&peer(KIOSK + 2), &w).session, "desktop");
    w.kiosk
        .insert("other".into(), (KIOSK + 3, "kiosk-other".into()));
    assert_eq!(identify(&peer(KIOSK + 2), &w).session, "desktop");
    w.kiosk
        .insert("other".into(), (KIOSK + 2, "kiosk-other".into()));
    assert_eq!(identify(&peer(KIOSK + 2), &w).session, "kiosk:other");
    // No passwd entry: local, no name.
    let id = identify(&peer(4321), &w);
    assert_eq!((id.user.kind, id.user.name), (SupportUserKind::Local, None));
}

/// The real lookups: logind's session class (the pid's own session first, then every session of the uid) and authd's
/// NSS module for SSO accounts.
#[test]
fn system_who_reads_logind_and_authd() {
    let root = tempfile::tempdir().unwrap();
    let r = Arc::new(FakeRunner::new());
    let w = SystemWho::new(r.clone(), root.path().to_path_buf());
    let by_pid = |pid: u32| format!("busctl call {LOGIN1} GetSessionByPID u {pid}");
    let session = |id: &str| format!("loginctl show-session {id} -p Class -p User");

    // logind says which session the pid is in; that session is the greeter's and belongs to the peer's uid.
    r.respond(
        &by_pid(77),
        Output::ok("o \"/org/freedesktop/login1/session/c1\"\n"),
    );
    r.respond(&session("c1"), Output::ok("Class=greeter\nUser=60578\n"));
    assert!(w.is_greeter(&Peer {
        uid: GREETER,
        pid: Some(77)
    }));
    // Escaped object path (`_33` is "3").
    r.respond(
        &by_pid(79),
        Output::ok("o \"/org/freedesktop/login1/session/_33\"\n"),
    );
    r.respond(&session("3"), Output::ok("Class=user\nUser=1000\n"));
    assert!(!w.is_greeter(&Peer {
        uid: ME,
        pid: Some(79)
    }));
    assert!(
        !r.calls().iter().any(|c| c.contains("show-user 1000")),
        "the pid's own session decides"
    );

    // Review: a student runs `systemd-run --user --scope -u session-c1.scope …`. Its cgroup path names
    // session-c1.scope (under user@1000.service), but nothing reads the cgroup any more: logind has no session for
    // that pid, and the uid's own sessions are not the greeter's.
    let proc_dir = root.path().join("proc/90");
    std::fs::create_dir_all(&proc_dir).unwrap();
    std::fs::write(
        proc_dir.join("cgroup"),
        "0::/user.slice/user-1000.slice/user@1000.service/app.slice/session-c1.scope\n",
    )
    .unwrap();
    r.respond(
        &by_pid(90),
        Output::fail(
            1,
            "Call failed: PID 90 does not belong to any known session",
        ),
    );
    r.respond(
        "loginctl show-user 1000 -p Sessions --value",
        Output::ok("3\n"),
    );
    r.respond(&session("3"), Output::ok("Class=user\nUser=1000\n"));
    assert!(!w.is_greeter(&Peer {
        uid: ME,
        pid: Some(90)
    }));
    // Even when logind names a greeter session for the pid, it counts only if that session is the peer's own uid's.
    r.respond(
        &by_pid(91),
        Output::ok("o \"/org/freedesktop/login1/session/c1\"\n"),
    );
    r.respond(&session("c1"), Output::ok("Class=greeter\nUser=60578\n"));
    r.respond(
        "loginctl show-user 1000 -p Sessions --value",
        Output::ok("c1 3\n"),
    );
    r.respond(&session("c1"), Output::ok("Class=greeter\nUser=60578\n"));
    r.respond(&session("3"), Output::ok("Class=user\nUser=1000\n"));
    assert!(!w.is_greeter(&Peer {
        uid: ME,
        pid: Some(91)
    }));

    // No pid session (the greeter's shell under its user manager): the uid's sessions decide, each checked for the uid.
    r.respond(&by_pid(78), Output::fail(1, "no session"));
    r.respond(
        "loginctl show-user 60579 -p Sessions --value",
        Output::ok("c2 c3\n"),
    );
    r.respond(&session("c2"), Output::ok("Class=user\nUser=60579\n"));
    r.respond(&session("c3"), Output::ok("Class=greeter\nUser=60579\n"));
    assert!(w.is_greeter(&Peer {
        uid: 60579,
        pid: Some(78)
    }));
    // Nothing logind answers is a session id we pass on.
    r.respond(
        &by_pid(4242),
        Output::ok("o \"/org/freedesktop/login1/session/-h\"\n"),
    );
    r.respond(
        "loginctl show-user 1001 -p Sessions --value",
        Output::ok("--help\n"),
    );
    assert!(!w.is_greeter(&peer(OTHER)));
    assert!(!r
        .calls()
        .iter()
        .any(|c| c.contains("--help") || c.contains(" -h")));

    r.respond(
        "getent -s authd passwd 10042",
        Output::ok("ana@school.example:x:10042:10042::/home/ana@school.example:/bin/bash\n"),
    );
    assert_eq!(
        w.account(SSO),
        Some(Account {
            name: "ana@school.example".into(),
            authd: true
        })
    );
    r.respond("getent -s authd passwd 1000", Output::fail(2, ""));
    r.respond(
        "getent passwd 1000",
        Output::ok("student:x:1000:1000::/home/student:/bin/bash\n"),
    );
    assert_eq!(
        w.account(ME),
        Some(Account {
            name: "student".into(),
            authd: false
        })
    );
    // An entry for another uid is not this one.
    r.respond("getent -s authd passwd 1001", Output::fail(2, ""));
    r.respond(
        "getent passwd 1001",
        Output::ok("root:x:0:0::/root:/bin/bash\n"),
    );
    assert_eq!(w.account(OTHER), None);

    // The kiosk step's record in system-state.json; none (no file) is no record.
    assert_eq!(w.kiosk_record("nwea"), None);
    let var = root.path().join("var/lib/mastersos-system");
    std::fs::create_dir_all(&var).unwrap();
    std::fs::write(
        var.join("system-state.json"),
        json!({"kiosk_accounts": {"nwea": {"uid": KIOSK, "name": "kiosk-nwea"}}}).to_string(),
    )
    .unwrap();
    assert_eq!(w.kiosk_record("nwea"), Some((KIOSK, "kiosk-nwea".into())));
    assert_eq!(w.kiosk_record("other"), None);
}

/// Review focus 5: three per hour per machine, counted on disk, so a restarted service still refuses the fourth.
#[test]
fn rate_limit_survives_restart() {
    let rig = Rig::new();
    for (i, uid) in [ME, OTHER, ME].into_iter().enumerate() {
        let t = now() + Duration::minutes(i as i64);
        let r = rig.ask(submit("wifi", "", "desktop"), uid, t);
        assert_eq!(r["ok"], json!(true), "{i}: {r}");
    }
    let t = now() + Duration::minutes(10);
    // rig.ask builds a new Host each time: nothing is kept in memory.
    assert_eq!(
        rig.ask(submit("wifi", "", "desktop"), OTHER, t),
        json!({"ok": false, "error": "rate_limited"})
    );
    assert_eq!(Store::new(rig.queue()).list().unwrap().len(), 3);
    assert_eq!(mode(&rig.queue().join(store::RATE_FILE)), 0o600);
    // An hour after the first one, one slot is free again.
    let t = now() + Duration::minutes(60) + Duration::seconds(1);
    assert_eq!(
        rig.ask(submit("wifi", "", "desktop"), OTHER, t)["ok"],
        json!(true)
    );
    assert_eq!(
        rig.ask(submit("wifi", "", "desktop"), OTHER, t)["error"],
        json!("rate_limited")
    );
    // A clock set back does not lock the machine out for good: times in the future are dropped.
    let earlier = now() - Duration::days(1);
    assert_eq!(
        rig.ask(submit("wifi", "", "desktop"), ME, earlier)["ok"],
        json!(true)
    );
}

/// Review focus 1: the request is on disk (0600 in a 0700 directory) before the reply, with its client id, and a
/// restarted service (and later the sender) finds the same item under the same id.
/// One account (the guest, a kiosk app) cannot use the machine's whole budget: two per uid per hour, three per machine.
/// The budget is checked before anything costly: a refused submit never looks anyone up.
#[test]
fn rate_limit_per_uid_inside_machine_budget() {
    let rig = Rig::new();
    let at = |m: i64| now() + Duration::minutes(m);
    let ask = |host: &Host, uid: u32, t| {
        let line = format!("{}\n", submit("wifi", "", "desktop"));
        reply_value(&host.handle(line.as_bytes(), peer(uid), t))
    };
    let w = who();
    let lookups = w.lookups.clone();
    let mut host = rig.host();
    host.who = Box::new(w);
    let guest = crate::system::guest::GUEST_UID;
    assert_eq!(ask(&host, guest, at(0))["ok"], json!(true));
    assert_eq!(ask(&host, guest, at(1))["ok"], json!(true));
    let n = lookups.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        ask(&host, guest, at(2)),
        json!({"ok": false, "error": "rate_limited"})
    );
    assert_eq!(
        lookups.load(std::sync::atomic::Ordering::SeqCst),
        n,
        "a refused submit must not run identify"
    );
    // Someone else still gets the machine's third.
    assert_eq!(ask(&host, ME, at(3))["ok"], json!(true));
    assert_eq!(ask(&host, OTHER, at(4))["error"], json!("rate_limited"));
    assert_eq!(store::MAX_PER_UID_PER_HOUR, 2);
}

/// The queue holds at most 20 items or 50 MB; a full queue refuses new submits (rate_limited) and keeps every queued
/// one: tickets already made matter more.
#[test]
fn queue_full_refuses_new_and_keeps_old() {
    assert_eq!(store::MAX_QUEUE_ITEMS, 20);
    assert_eq!(store::MAX_QUEUE_BYTES, 50 * 1024 * 1024);
    let rig = Rig::new();
    let line = format!("{}\n", submit("wifi", "", "desktop"));
    // Hours apart, so only the queue's size is in the way.
    let at = |h: i64| now() + Duration::hours(h);
    let mut host = rig.host();
    host.store = Store::new(rig.queue()).with_limits(2, u64::MAX);
    for h in 0..2 {
        assert_eq!(
            reply_value(&host.handle(line.as_bytes(), peer(ME), at(h)))["ok"],
            json!(true)
        );
    }
    let before = host.store.list().unwrap();
    assert_eq!(
        reply_value(&host.handle(line.as_bytes(), peer(ME), at(5))),
        json!({"ok": false, "error": "rate_limited"})
    );
    assert_eq!(host.store.list().unwrap(), before);
    // Bytes count too (items and screenshots).
    host.store = Store::new(rig.queue()).with_limits(100, 100);
    assert_eq!(
        reply_value(&host.handle(line.as_bytes(), peer(ME), at(6))),
        json!({"ok": false, "error": "rate_limited"})
    );
    // Once the sender is done with one, there is room again.
    host.store = Store::new(rig.queue()).with_limits(2, u64::MAX);
    host.store.remove(&before[0].request.client_id).unwrap();
    assert_eq!(
        reply_value(&host.handle(line.as_bytes(), peer(ME), at(7)))["ok"],
        json!(true)
    );
}

/// Only a submit may be large (its screenshot); every other op is refused past a few KiB.
#[test]
fn non_submit_ops_are_small() {
    let rig = Rig::new();
    let host = rig.host();
    let padded = |n: usize| format!("{{\"op\":\"enabled\"{}}}\n", " ".repeat(n));
    assert_eq!(
        reply_value(&host.handle(padded(10).as_bytes(), peer(ME), now())),
        json!({"ok": true, "enabled": true})
    );
    assert_eq!(
        reply_value(&host.handle(
            padded(host::SMALL_REQUEST_BYTES).as_bytes(),
            peer(ME),
            now()
        )),
        json!({"ok": false, "error": "invalid"})
    );
    // JSON that is not an object is not a request, even when a struct could be read from it.
    assert_eq!(
        reply_value(&host.handle(b"[\"enabled\"]\n", peer(ME), now())),
        json!({"ok": false, "error": "invalid"})
    );
}

#[test]
fn queue_survives_restart_and_reuses_client_id() {
    let rig = Rig::new();
    let png = {
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        v.extend_from_slice(&[0u8; 32]);
        v
    };
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &png);
    let mut req = submit("hardware", "  no sound  ", "desktop");
    req["screenshot_png_b64"] = json!(b64);
    let r = rig.ask(req, ME, now());
    assert_eq!(r["ok"], json!(true), "{r}");
    assert_eq!(r["state"], json!("queued"));
    let id = r["client_id"].as_str().unwrap().to_string();
    assert!(mastersos_bundle::valid_school_id(&id), "{id}");
    // The sender has its item and was asked to run.
    let upload = crate::upload::queue::Queue::new(&rig.dir.path().join("state"));
    assert!(upload.has(&crate::upload::queue::support_name(&id)));
    assert_eq!(UPLOAD_UNIT, crate::upload::SERVICE);
    assert!(rig.runner.calls().contains(
        &"systemctl --no-ask-password start --no-block mastersos-upload.service".to_string()
    ));

    assert_eq!(mode(&rig.queue()), 0o700);
    assert_eq!(mode(&rig.queue().join(format!("{id}.json"))), 0o600);
    assert_eq!(mode(&rig.queue().join(format!("{id}.png"))), 0o600);

    let store = Store::new(rig.queue());
    let items = store.list().unwrap();
    assert_eq!(items.len(), 1);
    let item = &items[0];
    assert_eq!(item.request.client_id, id);
    assert_eq!(item.request.category, SupportCategory::Hardware);
    assert_eq!(item.request.text, "no sound");
    assert!(item.request.screenshot);
    assert_eq!(item.request.created_at, now());
    assert_eq!(item.created_at, now());
    assert_eq!(item.state, ItemState::Queued);
    assert_eq!(item.ticket, None);
    assert!(!item.attach_done);
    item.request.validate().unwrap();
    assert_eq!(store.screenshot(&id).unwrap().as_deref(), Some(&png[..]));

    // The sender records the ticket; a restarted service answers from disk with the same id.
    let mut sent = item.clone();
    sent.state = ItemState::Sent;
    sent.ticket = Some("1042".into());
    store.update(&sent).unwrap();
    assert_eq!(
        rig.ask(json!({"op": "status", "client_id": id}), ME, now()),
        json!({"ok": true, "state": "sent", "ticket": "1042"})
    );
    let again = Store::new(rig.queue()).get(&id).unwrap().unwrap();
    assert_eq!(again.request.client_id, id);
    assert_eq!(again.request, item.request);
    // Removing an item takes its screenshot too.
    store.remove(&id).unwrap();
    assert!(store.list().unwrap().is_empty());
    assert!(!rig.queue().join(format!("{id}.png")).exists());
}

#[test]
fn text_over_1000_chars_invalid() {
    let rig = Rig::new();
    // Characters, not bytes: 1000 two-byte characters are fine, 1001 are not.
    let ok = "é".repeat(1000);
    assert_eq!(
        rig.ask(submit("other", &ok, "desktop"), ME, now())["ok"],
        json!(true)
    );
    let long = "é".repeat(1001);
    assert_eq!(
        rig.ask(submit("other", &long, "desktop"), ME, now()),
        json!({"ok": false, "error": "invalid"})
    );
    // Other malformed submits are invalid too.
    for bad in [
        submit("printer", "", "desktop"),
        submit("wifi", "", "office"),
        submit("wifi", "", "kiosk:"),
        json!({"op": "submit", "category": "wifi", "session": "desktop"}),
        json!({"op": "submit", "category": "wifi", "text": 3, "session": "desktop"}),
        json!({"op": "submit", "category": "wifi", "text": "", "session": "desktop", "screenshot_png_b64": "bm90IGEgcG5n"}),
        json!({"op": "submit", "category": "wifi", "text": "", "session": "desktop", "screenshot_png_b64": "%%%"}),
        json!({"op": "nope"}),
        json!(["submit"]),
    ] {
        assert_eq!(
            rig.ask(bad.clone(), ME, now()),
            json!({"ok": false, "error": "invalid"}),
            "{bad}"
        );
    }
    let host = rig.host();
    for line in [&b"not json\n"[..], b"", b"{\"op\":\"enabled\"}{}\n"] {
        assert_eq!(
            reply_value(&host.handle(line, peer(ME), now())),
            json!({"ok": false, "error": "invalid"})
        );
    }
    assert_eq!(Store::new(rig.queue()).list().unwrap().len(), 1);
}

#[test]
fn disabled_config_refuses_submit() {
    let rig = Rig::new();
    for enabled in [None, Some(false)] {
        rig.set_enabled(enabled);
        assert_eq!(
            rig.ask(submit("wifi", "", "desktop"), ME, now()),
            json!({"ok": false, "error": "disabled"})
        );
        assert_eq!(
            rig.ask(json!({"op": "enabled"}), ME, now()),
            json!({"ok": true, "enabled": false})
        );
    }
    std::fs::write(rig.public().join(SUPPORT_JSON), b"{garbage").unwrap();
    assert_eq!(
        rig.ask(json!({"op": "enabled"}), ME, now()),
        json!({"ok": true, "enabled": false})
    );
    assert!(Store::new(rig.queue()).list().unwrap().is_empty());
    assert!(rig.runner.calls().is_empty());
    rig.set_enabled(Some(true));
    assert_eq!(
        rig.ask(json!({"op": "enabled"}), ME, now()),
        json!({"ok": true, "enabled": true})
    );
    assert_eq!(
        rig.ask(submit("wifi", "", "desktop"), ME, now())["ok"],
        json!(true)
    );
}

#[test]
fn status_only_for_own_uid() {
    let rig = Rig::new();
    let r = rig.ask(submit("battery", "", "desktop"), ME, now());
    let id = r["client_id"].as_str().unwrap();
    assert_eq!(
        rig.ask(json!({"op": "status", "client_id": id}), ME, now()),
        json!({"ok": true, "state": "queued"})
    );
    for uid in [OTHER, KIOSK, 0] {
        assert_eq!(
            rig.ask(json!({"op": "status", "client_id": id}), uid, now()),
            json!({"ok": false, "error": "invalid"}),
            "{uid}"
        );
    }
    // Unknown and malformed ids (never a path) are the same answer.
    for bad in [
        "0192f3a4-5b6c-7d8e-9f00-112233445566",
        "../rate",
        "rate",
        "",
    ] {
        assert_eq!(
            rig.ask(json!({"op": "status", "client_id": bad}), ME, now()),
            json!({"ok": false, "error": "invalid"}),
            "{bad}"
        );
    }
}

#[test]
fn native_host_frames_roundtrip() {
    let frame = |v: &Value| {
        let body = v.to_string().into_bytes();
        let mut f = (body.len() as u32).to_le_bytes().to_vec();
        f.extend_from_slice(&body);
        f
    };
    let unframe = |out: &[u8]| -> Value {
        let n = u32::from_le_bytes(out[..4].try_into().unwrap()) as usize;
        assert_eq!(out.len(), 4 + n);
        serde_json::from_slice(&out[4..]).unwrap()
    };
    // Exactly what kiosk-extension/background.js sends for a submit.
    let msg = json!({"op": "submit", "category": "hardware", "text": "no sound", "session": "kiosk", "screenshot_png_b64": null});
    let mut sent = Vec::new();
    let mut out = Vec::new();
    let ok = native_host::run(
        &mut Cursor::new(frame(&msg)),
        &mut out,
        Some("kiosk:nwea"),
        &mut |line: &[u8]| {
            sent.push(line.to_vec());
            Ok(b"{\"ok\":true,\"client_id\":\"c1\",\"state\":\"queued\"}\n".to_vec())
        },
    );
    assert!(ok);
    assert_eq!(sent.len(), 1);
    assert!(sent[0].ends_with(b"\n"));
    assert_eq!(sent[0].iter().filter(|b| **b == b'\n').count(), 1);
    let line: Value = serde_json::from_slice(&sent[0]).unwrap();
    let mut want = msg.clone();
    want["session"] = json!("kiosk:nwea");
    assert_eq!(line, want);
    assert_eq!(
        unframe(&out),
        json!({"ok": true, "client_id": "c1", "state": "queued"})
    );

    // enabled and status pass through unchanged.
    for msg in [
        json!({"op": "enabled"}),
        json!({"op": "status", "client_id": "c1"}),
    ] {
        let mut sent = Vec::new();
        let mut out = Vec::new();
        native_host::run(
            &mut Cursor::new(frame(&msg)),
            &mut out,
            Some("kiosk:nwea"),
            &mut |line: &[u8]| {
                sent.push(line.to_vec());
                Ok(b"{\"ok\":true,\"enabled\":true}\n".to_vec())
            },
        );
        assert_eq!(serde_json::from_slice::<Value>(&sent[0]).unwrap(), msg);
        assert_eq!(unframe(&out), json!({"ok": true, "enabled": true}));
    }

    // No socket, a broken reply, a truncated or oversized frame, a frame that is not an object: one
    // {"ok":false,"error":"unreachable"} or "invalid" frame back, and nothing broken reaches the socket.
    let mut out = Vec::new();
    assert!(!native_host::run(
        &mut Cursor::new(frame(&json!({"op": "enabled"}))),
        &mut out,
        None,
        &mut |_: &[u8]| Err(anyhow::anyhow!("no socket")),
    ));
    assert_eq!(unframe(&out), json!({"ok": false, "error": "unreachable"}));
    let mut out = Vec::new();
    native_host::run(
        &mut Cursor::new(frame(&json!({"op": "enabled"}))),
        &mut out,
        None,
        &mut |_: &[u8]| Ok(b"<html>\n".to_vec()),
    );
    assert_eq!(unframe(&out), json!({"ok": false, "error": "unreachable"}));
    let mut huge = ((native_host::MAX_MESSAGE + 1) as u32)
        .to_le_bytes()
        .to_vec();
    huge.extend_from_slice(&[b' '; 16]);
    for input in [
        huge,
        vec![5, 0, 0, 0, b'{'],
        vec![1, 0],
        frame(&json!(["op"])),
        frame(&json!("enabled")),
    ] {
        let mut out = Vec::new();
        let mut called = false;
        native_host::run(
            &mut Cursor::new(input),
            &mut out,
            Some("kiosk:nwea"),
            &mut |_: &[u8]| {
                called = true;
                Ok(Vec::new())
            },
        );
        assert!(!called);
        assert_eq!(unframe(&out), json!({"ok": false, "error": "invalid"}));
    }
}

/// The socket server: one line in, one line out, the peer's uid from the socket.
#[tokio::test]
async fn host_serves_one_line_per_connection() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let rig = Rig::new();
    let mut w = who();
    let me = rustix::process::getuid().as_raw();
    w.accounts.insert(
        me,
        Account {
            name: "tester".into(),
            authd: false,
        },
    );
    let mut host = rig.host();
    host.who = Box::new(w);
    let sock = rig.dir.path().join("support.sock");
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();
    let server = tokio::spawn(host::serve(
        listener,
        Arc::new(host),
        host::ServeOpts {
            idle: std::time::Duration::from_millis(500),
            ..host::ServeOpts::default()
        },
    ));
    let ask = |line: String| {
        let sock = sock.clone();
        async move {
            let mut s = tokio::net::UnixStream::connect(&sock).await.unwrap();
            s.write_all(line.as_bytes()).await.unwrap();
            let mut r = BufReader::new(s);
            let mut out = String::new();
            r.read_line(&mut out).await.unwrap();
            out
        }
    };
    let out = ask(format!("{}\n", submit("wifi", "", "desktop"))).await;
    assert!(out.ends_with('\n'));
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["ok"], json!(true), "{v}");
    let item = Store::new(rig.queue())
        .get(v["client_id"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(item.uid, me);
    assert_eq!(item.request.user.name.as_deref(), Some("tester"));
    let out = ask("{\"op\":\"enabled\"}\n".into()).await;
    assert_eq!(out, "{\"ok\":true,\"enabled\":true}\n");
    // Idle for longer than the limit: the server returns (socket activation starts it again).
    tokio::time::timeout(std::time::Duration::from_secs(10), server)
        .await
        .expect("the server should exit when idle")
        .unwrap()
        .unwrap();
}

/// At most `max_open` connections at once: one more is closed at once, without a reply, and the service keeps going.
#[tokio::test]
async fn host_drops_connections_over_the_cap() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rig = Rig::new();
    let mut w = who();
    w.accounts.insert(
        rustix::process::getuid().as_raw(),
        Account {
            name: "tester".into(),
            authd: false,
        },
    );
    let mut host = rig.host();
    host.who = Box::new(w);
    let sock = rig.dir.path().join("support.sock");
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();
    let opts = host::ServeOpts {
        idle: std::time::Duration::from_millis(300),
        read_timeout: std::time::Duration::from_secs(2),
        max_open: 2,
        max_large: 1,
    };
    let server = tokio::spawn(host::serve(listener, Arc::new(host), opts));
    // Two clients that never send anything hold both places.
    let mut quiet = Vec::new();
    for _ in 0..2 {
        quiet.push(tokio::net::UnixStream::connect(&sock).await.unwrap());
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let mut extra = tokio::net::UnixStream::connect(&sock).await.unwrap();
    let _ = extra.write_all(b"{\"op\":\"enabled\"}\n").await;
    let mut got = Vec::new();
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        extra.read_to_end(&mut got),
    )
    .await
    .expect("the extra connection should be closed at once");
    assert!(
        n.is_err() || got.is_empty(),
        "no reply over the cap: {got:?}"
    );
    // The quiet ones run out of time and are told so; then there is room again.
    for mut q in quiet {
        let mut out = String::new();
        q.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "{\"ok\":false,\"error\":\"invalid\"}\n");
    }
    let mut s = tokio::net::UnixStream::connect(&sock).await.unwrap();
    s.write_all(b"{\"op\":\"enabled\"}\n").await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    assert_eq!(out, "{\"ok\":true,\"enabled\":true}\n");
    tokio::time::timeout(std::time::Duration::from_secs(10), server)
        .await
        .expect("the server should exit when idle")
        .unwrap()
        .unwrap();
}

#[test]
fn step_writes_support_json() {
    use crate::apply::Phase;
    use crate::system::tests::{paths, tmp_root, with_ctx};
    use mastersos_bundle::School;
    use std::sync::atomic::AtomicBool;
    let root = tmp_root();
    let p = paths(root.path());
    let r = FakeRunner::new();
    let flag = AtomicBool::new(false);
    for enabled in [true, false] {
        let mut sys = crate::system::SysState::default();
        let out = with_ctx(&School::default(), Phase::Full, &flag, |ctx| {
            let mut c = ctx.config.clone();
            c.support_enabled = enabled;
            let ctx = crate::apply::ApplyContext { config: &c, ..*ctx };
            let mut env = crate::system::Env {
                paths: &p,
                runner: &r,
                sys: &mut sys,
            };
            (step().run)(&ctx, &mut env)
        });
        assert_eq!(out, vec![crate::system::ok(ITEM)]);
        let f = p.public_dir.join(SUPPORT_JSON);
        assert_eq!(mode(&f), 0o644);
        let v: Value = serde_json::from_slice(&std::fs::read(&f).unwrap()).unwrap();
        assert_eq!(v, json!({ "enabled": enabled }));
    }
    assert!(step().fast);
}
