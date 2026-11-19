use super::*;
use crate::runner::Output;
use crate::system::exec_block::tests::MountSim;
use crate::system::exec_block::{self, read_lifted};
use crate::user_layer::render::{Index, STATE_SUB};
use crate::user_layer::switch::tests::{assert_switched_to, rendered, session_uid};
use crate::user_layer::switch::{switch_to, write_active};
use crate::user_layer::{config_dir_name, read_active, ACTIVE_FILE, RUN_DIR};
use mastersos_bundle::Capability;
use std::fs;
use std::time::{Duration, UNIX_EPOCH};

const UID: u32 = 2001;
const LIST: &str = "loginctl --json=short list-sessions";
const T0: u64 = 1_800_000_000;

/// A rendered root (nobody signed in: neutral, everything blocked) and a runner that simulates the bind mounts.
fn setup() -> (tempfile::TempDir, SysPaths, Index, MountSim) {
    let (root, p, index) = rendered();
    let r = MountSim::new(root.path());
    (root, p, index, r)
}

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// What `pam-session` leaves after switching `UID` to the teacher config at `T0`: the switched files and the marker.
fn signed_in(p: &SysPaths, index: &Index, state: ActiveState, seen: bool) -> Active {
    let r = &index.configs["teacher"];
    switch_to(&p.root, &p.public_dir, &p.var_dir, r, Some(UID)).unwrap();
    let a = Active {
        uid: UID,
        user: "t1@school.ac.th".into(),
        user_config: "teacher".into(),
        dir: config_dir_name("teacher"),
        caps: r.caps.clone(),
        state,
        reason: None,
        opened_at: T0,
        seen,
        held: false,
    };
    write_active(&p.root, &a).unwrap();
    a
}

/// One `loginctl --json=short list-sessions` row; `state: None` is the systemd 259 shape.
fn row(id: &str, uid: u32, seat: Option<&str>, class: &str, state: Option<&str>) -> String {
    let mut s = format!(
        r#"{{"session":"{id}","uid":{uid},"user":"u{uid}","seat":{},"leader":1234,"class":"{class}","tty":null"#,
        seat.map_or("null".to_string(), |s| format!("\"{s}\""))
    );
    if let Some(st) = state {
        s.push_str(&format!(r#","state":"{st}""#));
    }
    s.push('}');
    s
}

fn list(r: &MountSim, rows: &[String]) {
    r.fake
        .respond(LIST, Output::ok(&format!("[{}]\n", rows.join(","))));
}

fn greeter() -> String {
    row("c1", 60578, Some("seat0"), "greeter", Some("active"))
}

fn lifted(p: &SysPaths) -> Caps {
    read_lifted(p).unwrap().expect("exec-block state")
}

fn revert_cmds(calls: &[String]) -> Vec<String> {
    calls
        .iter()
        .filter(|c| c.starts_with("loginctl disable-linger") || c.starts_with("systemctl"))
        .cloned()
        .collect()
}

fn expected_revert_cmds() -> Vec<String> {
    vec![
        format!("loginctl disable-linger {UID}"),
        format!("systemctl stop user@{UID}.service"),
    ]
}

/// The session is back to neutral: neutral's files, nobody's uid, everything blocked.
fn assert_neutral(p: &SysPaths) {
    assert_switched_to(p, NEUTRAL_DIR);
    assert_eq!(session_uid(p), None);
    assert_eq!(lifted(p), Caps::new());
}

#[test]
fn lift_follows_active_caps() {
    let (_root, p, index, r) = setup();
    // No marker: nothing is lifted or run
    after_login(&p, &r).unwrap();
    assert!(r.calls().is_empty(), "{:?}", r.calls());
    assert_eq!(read_lifted(&p).unwrap(), Some(Caps::new()));
    // An open teacher session gets the teacher's capabilities
    let a = signed_in(&p, &index, ActiveState::Open, false);
    assert!(a.caps.contains(&Capability::Terminal), "{:?}", a.caps);
    after_login(&p, &r).unwrap();
    assert_eq!(lifted(&p), a.caps);
    // A closing one is not lifted again
    exec_block::apply_lifted(&p, &r, &Caps::new()).unwrap();
    let mut closing = a.clone();
    closing.state = ActiveState::Closing;
    write_active(&p.root, &closing).unwrap();
    after_login(&p, &r).unwrap();
    assert_eq!(lifted(&p), Caps::new());
}

/// A held session (its user config was removed mid-session) gets nothing lifted until its next login.
#[test]
fn held_session_lifts_nothing() {
    let (_root, p, index, r) = setup();
    let mut a = signed_in(&p, &index, ActiveState::Open, true);
    a.held = true;
    write_active(&p.root, &a).unwrap();
    assert!(!a.caps.is_empty());
    after_login(&p, &r).unwrap();
    assert_eq!(lifted(&p), Caps::new());
}

#[test]
fn no_marker_is_idle_and_runs_nothing() {
    let (_root, p, _index, r) = setup();
    assert_eq!(watch_at(&p, &r, at(T0)).unwrap(), WatchOutcome::Idle);
    assert!(r.calls().is_empty(), "{:?}", r.calls());
    assert!(!p.root.join(RUN_DIR).join(ACTIVE_FILE).exists());
}

#[test]
fn revert_on_closing() {
    let (_root, p, index, r) = setup();
    let a = signed_in(&p, &index, ActiveState::Closing, false);
    after_login(&p, &r).unwrap();
    exec_block::apply_lifted(&p, &r, &a.caps).unwrap();
    // The closed session is gone from logind (or still closing)
    list(
        &r,
        &[
            greeter(),
            row("3", UID, Some("seat0"), "user", Some("closing")),
        ],
    );
    assert_eq!(
        watch_at(&p, &r, at(T0 + 1)).unwrap(),
        WatchOutcome::Reverted {
            user_config: "teacher".into()
        }
    );
    assert_neutral(&p);
    assert!(read_active(&p.root).is_none());
    assert!(!p.root.join(RUN_DIR).join(ACTIVE_FILE).exists());
    assert_eq!(revert_cmds(&r.calls()), expected_revert_cmds());
    // Nothing left to do
    assert_eq!(watch_at(&p, &r, at(T0 + 6)).unwrap(), WatchOutcome::Idle);
}

#[test]
fn revert_when_logind_has_no_session() {
    let (_root, p, index, r) = setup();
    let a = signed_in(&p, &index, ActiveState::Open, true);
    exec_block::apply_lifted(&p, &r, &a.caps).unwrap();
    // Only the greeter, another person's session and this uid's closing session and user manager
    list(
        &r,
        &[
            greeter(),
            row("3", UID, Some("seat0"), "user", Some("closing")),
            row("4", UID, None, "manager", Some("active")),
            row("9", 3003, None, "user", Some("active")),
        ],
    );
    assert_eq!(
        watch_at(&p, &r, at(T0 + 5)).unwrap(),
        WatchOutcome::Reverted {
            user_config: "teacher".into()
        }
    );
    assert_neutral(&p);
    assert!(read_active(&p.root).is_none());
    assert_eq!(revert_cmds(&r.calls()), expected_revert_cmds());
}

/// R9: pam-session runs before pam_systemd, so a just-opened session is not in logind yet.
#[test]
fn just_opened_marker_is_not_reverted() {
    let (_root, p, index, r) = setup();
    let a = signed_in(&p, &index, ActiveState::Open, false);
    exec_block::apply_lifted(&p, &r, &a.caps).unwrap();
    for secs in [0, 1, 59] {
        list(&r, &[greeter()]);
        assert_eq!(
            watch_at(&p, &r, at(T0 + secs)).unwrap(),
            WatchOutcome::StillOpen,
            "{secs}"
        );
    }
    assert_eq!(read_active(&p.root), Some(a.clone()));
    assert_switched_to(&p, &config_dir_name("teacher"));
    assert_eq!(lifted(&p), a.caps);
    assert!(revert_cmds(&r.calls()).is_empty(), "{:?}", r.calls());
}

/// R9: a login whose logind session never appeared is reverted once the grace is over.
#[test]
fn unseen_marker_reverted_after_grace() {
    let (_root, p, index, r) = setup();
    signed_in(&p, &index, ActiveState::Open, false);
    list(&r, &[greeter()]);
    assert_eq!(
        watch_at(&p, &r, at(T0 + OPEN_GRACE.as_secs())).unwrap(),
        WatchOutcome::Reverted {
            user_config: "teacher".into()
        }
    );
    assert_neutral(&p);
    assert!(read_active(&p.root).is_none());
}

#[test]
fn still_open_does_nothing() {
    let (_root, p, index, r) = setup();
    let a = signed_in(&p, &index, ActiveState::Open, false);
    exec_block::apply_lifted(&p, &r, &a.caps).unwrap();
    // systemd 259: no state in the list, asked per session
    list(&r, &[greeter(), row("5", UID, Some("seat0"), "user", None)]);
    r.fake.respond(
        "loginctl show-session 5 -p State --value",
        Output::ok("active\n"),
    );
    // Long after the grace: the session is there, so it stays
    assert_eq!(
        watch_at(&p, &r, at(T0 + 3600)).unwrap(),
        WatchOutcome::StillOpen
    );
    // Seen from now on
    let mut want = a.clone();
    want.seen = true;
    assert_eq!(read_active(&p.root), Some(want.clone()));
    assert_switched_to(&p, &config_dir_name("teacher"));
    assert_eq!(lifted(&p), a.caps);
    assert!(revert_cmds(&r.calls()).is_empty(), "{:?}", r.calls());
    // A session with a state in the list (systemd 256)
    list(
        &r,
        &[row("5", UID, Some("seat0"), "user-early", Some("online"))],
    );
    assert_eq!(
        watch_at(&p, &r, at(T0 + 3605)).unwrap(),
        WatchOutcome::StillOpen
    );
    assert_eq!(read_active(&p.root), Some(want));
}

/// Any step of the revert failing keeps the marker (logins stay refused); the tightening already done stays.
#[test]
fn revert_clears_marker_last() {
    let (_root, p, index, r) = setup();
    let a = signed_in(&p, &index, ActiveState::Closing, true);
    exec_block::apply_lifted(&p, &r, &a.caps).unwrap();
    list(&r, &[greeter()]);
    r.fail_on("systemctl stop");
    let e = watch_at(&p, &r, at(T0 + 1)).unwrap_err();
    assert!(format!("{e:#}").contains("user@"), "{e:#}");
    assert_eq!(read_active(&p.root), Some(a.clone()));
    assert_neutral(&p);
    assert_eq!(revert_cmds(&r.calls()), expected_revert_cmds());
    // Next round it works and the marker goes
    let r2 = MountSim::new(&p.root);
    list(&r2, &[greeter()]);
    assert_eq!(
        watch_at(&p, &r2, at(T0 + 6)).unwrap(),
        WatchOutcome::Reverted {
            user_config: "teacher".into()
        }
    );
    assert!(read_active(&p.root).is_none());
    // A failing disable-linger keeps it too; the user manager is still stopped
    signed_in(&p, &index, ActiveState::Closing, true);
    let r3 = MountSim::new(&p.root);
    list(&r3, &[greeter()]);
    r3.fail_on("loginctl disable-linger");
    assert!(watch_at(&p, &r3, at(T0 + 11)).is_err());
    assert!(read_active(&p.root).is_some());
    assert_eq!(revert_cmds(&r3.calls()), expected_revert_cmds());
    assert_neutral(&p);
}

/// A marker that cannot be read is never taken for "no session": reported, kept, nothing run.
#[test]
fn unreadable_marker_is_kept() {
    let (_root, p, _index, r) = setup();
    let f = p.root.join(RUN_DIR).join(ACTIVE_FILE);
    fs::create_dir_all(f.parent().unwrap()).unwrap();
    fs::write(&f, b"{not json").unwrap();
    assert!(watch_at(&p, &r, at(T0)).is_err());
    assert!(after_login(&p, &r).is_err());
    assert_eq!(fs::read(&f).unwrap(), b"{not json");
    assert!(r.calls().is_empty(), "{:?}", r.calls());
}

/// A failing or unreadable logind list is an error, not "no session".
#[test]
fn loginctl_failure_does_not_revert() {
    let (_root, p, index, r) = setup();
    let a = signed_in(&p, &index, ActiveState::Open, true);
    for out in [
        Output::fail(1, "Failed to connect to bus"),
        Output::ok("not json"),
        Output::ok(&format!(
            r#"[{{"session":"5","uid":{UID},"seat":"seat0"}}]"#
        )),
        // A user session without a uid
        Output::ok(r#"[{"session":"5","class":"user","seat":"seat0","state":"active"}]"#),
    ] {
        r.fake.respond(LIST, out.clone());
        assert!(watch_at(&p, &r, at(T0 + 3600)).is_err(), "{out:?}");
        assert_eq!(read_active(&p.root), Some(a.clone()), "{out:?}");
    }
    assert!(revert_cmds(&r.calls()).is_empty(), "{:?}", r.calls());
    assert_switched_to(&p, &config_dir_name("teacher"));
}

/// R26: a marker left behind when the settings went back to format 1/2 (whose apply removed the user layer's files and
/// owns the exec-block mode again) is still cleared: the user manager is stopped and the marker removed, and the
/// format 1/2 exec-block mode is left alone.
#[test]
fn stale_marker_after_format_change_is_cleared() {
    let (_root, p, index, r) = setup();
    signed_in(&p, &index, ActiveState::Closing, true);
    fs::remove_dir_all(p.var_dir.join(STATE_SUB)).unwrap();
    // The format 1/2 `desktop` step of a `full` Group
    exec_block::apply(&p, &r, false).unwrap();
    list(&r, &[greeter()]);
    let mode_before = read_lifted(&p).unwrap();
    assert_eq!(
        watch_at(&p, &r, at(T0 + 1)).unwrap(),
        WatchOutcome::Reverted {
            user_config: "teacher".into()
        }
    );
    assert!(read_active(&p.root).is_none());
    assert_eq!(revert_cmds(&r.calls()), expected_revert_cmds());
    assert_eq!(read_lifted(&p).unwrap(), mode_before);
}

/// Boot (spec §4.8): files switched in by the last session survive a reboot; without a marker the agent goes neutral.
#[test]
fn boot_without_marker_switches_to_neutral() {
    let (_root, p, index, r) = setup();
    let a = signed_in(&p, &index, ActiveState::Open, true);
    exec_block::apply_lifted(&p, &r, &a.caps).unwrap();
    // `/run` is gone after the reboot
    fs::remove_file(p.root.join(RUN_DIR).join(ACTIVE_FILE)).unwrap();
    assert!(boot_neutral(&p, &r).unwrap());
    assert_neutral(&p);
}

/// The agent restarting during a session (an update) does not touch it.
#[test]
fn boot_with_marker_keeps_the_session() {
    let (_root, p, index, r) = setup();
    let a = signed_in(&p, &index, ActiveState::Open, true);
    exec_block::apply_lifted(&p, &r, &a.caps).unwrap();
    assert!(!boot_neutral(&p, &r).unwrap());
    assert_switched_to(&p, &config_dir_name("teacher"));
    assert_eq!(lifted(&p), a.caps);
    assert_eq!(read_active(&p.root), Some(a));
}

/// R27: the same person still has a live session elsewhere (a tty login: pam-check lets the same uid in while the marker
/// is open, and pam-session is only in the GDM stacks) when their GDM session closes. That session keeps its config and
/// the marker becomes open (seen) again, so nobody else can sign in; it is reverted once logind shows none.
#[test]
fn closing_with_another_live_session_keeps_it() {
    let (_root, p, index, r) = setup();
    let a = signed_in(&p, &index, ActiveState::Closing, false);
    exec_block::apply_lifted(&p, &r, &a.caps).unwrap();
    list(
        &r,
        &[
            greeter(),
            row("3", UID, Some("seat0"), "user", Some("closing")),
            row("7", UID, None, "user", Some("active")),
        ],
    );
    assert_eq!(
        watch_at(&p, &r, at(T0 + 1)).unwrap(),
        WatchOutcome::StillOpen
    );
    let mut want = a.clone();
    want.state = ActiveState::Open;
    want.seen = true;
    assert_eq!(read_active(&p.root), Some(want));
    assert_switched_to(&p, &config_dir_name("teacher"));
    assert_eq!(lifted(&p), a.caps);
    assert!(revert_cmds(&r.calls()).is_empty(), "{:?}", r.calls());
    // A failing list keeps the closing marker as it is (fail closed); retried next round
    write_active(&p.root, &a).unwrap();
    r.fake
        .respond(LIST, Output::fail(1, "Failed to connect to bus"));
    assert!(watch_at(&p, &r, at(T0 + 6)).is_err());
    assert_eq!(read_active(&p.root), Some(a.clone()));
    assert!(revert_cmds(&r.calls()).is_empty(), "{:?}", r.calls());
    // Once the other session is gone too: reverted
    list(&r, &[greeter()]);
    assert_eq!(
        watch_at(&p, &r, at(T0 + 11)).unwrap(),
        WatchOutcome::Reverted {
            user_config: "teacher".into()
        }
    );
    assert_neutral(&p);
    assert!(read_active(&p.root).is_none());
}

/// After a login whose session logind already lists, the marker is seen at once (no 60 s window of refused logins
/// should a close miss the lock); a failing list does not stop the lift.
#[test]
fn after_login_marks_a_listed_session_seen() {
    let (_root, p, index, r) = setup();
    let a = signed_in(&p, &index, ActiveState::Open, false);
    r.fake
        .respond(LIST, Output::fail(1, "Failed to connect to bus"));
    after_login(&p, &r).unwrap();
    assert_eq!(lifted(&p), a.caps);
    assert_eq!(read_active(&p.root), Some(a.clone()));
    list(
        &r,
        &[
            greeter(),
            row("5", UID, Some("seat0"), "user", Some("active")),
        ],
    );
    after_login(&p, &r).unwrap();
    let mut want = a.clone();
    want.seen = true;
    assert_eq!(read_active(&p.root), Some(want));
}

/// A busy marker lock (a sign-in or sign-out changing the marker) is not a failure: nothing is done, next round retries.
#[test]
fn busy_lock_is_retried_not_failed() {
    let (_root, p, index, r) = setup();
    let a = signed_in(&p, &index, ActiveState::Closing, true);
    let held = switch::lock_active(&p.root, Duration::ZERO).unwrap();
    list(&r, &[greeter()]);
    assert_eq!(watch_at(&p, &r, at(T0 + 1)).unwrap(), WatchOutcome::Busy);
    assert_eq!(read_active(&p.root), Some(a.clone()));
    assert!(revert_cmds(&r.calls()).is_empty(), "{:?}", r.calls());
    let mut open = a.clone();
    open.state = ActiveState::Open;
    write_active(&p.root, &open).unwrap();
    let e = after_login(&p, &r).unwrap_err();
    assert!(switch::is_lock_busy(&e), "{e:#}");
    drop(held);
    write_active(&p.root, &a).unwrap();
    list(&r, &[greeter()]);
    assert_eq!(
        watch_at(&p, &r, at(T0 + 6)).unwrap(),
        WatchOutcome::Reverted {
            user_config: "teacher".into()
        }
    );
}

/// A runner for the monitor: the logind list is whatever `sessions` holds (every call), bind mounts are simulated and
/// fail while `fail_mounts` is set.
struct Sim {
    mounts: MountSim,
    sessions: std::sync::Mutex<String>,
    fail_mounts: std::sync::atomic::AtomicBool,
}

impl Sim {
    fn set_sessions(&self, rows: &[String]) {
        *self.sessions.lock().unwrap() = format!("[{}]\n", rows.join(","));
    }
}

impl Runner for Sim {
    fn run(&self, cmd: &crate::runner::Cmd) -> Result<Output> {
        let line = cmd.line();
        if line.starts_with(LIST) {
            return Ok(Output::ok(&self.sessions.lock().unwrap()));
        }
        if self.fail_mounts.load(std::sync::atomic::Ordering::SeqCst)
            && line.contains("mount --bind")
        {
            return Ok(Output::fail(32, "mount: permission denied"));
        }
        self.mounts.run(cmd)
    }
}

fn item_of(side: &SideResults, name: &str) -> Option<ItemResult> {
    side.lock().unwrap().get(name).cloned()
}

/// Waits (wall clock, letting the monitor run) until `cond` holds.
async fn eventually(what: &str, cond: impl Fn() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while !cond() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Whether `changed` was notified since the last time it was taken.
async fn notified(changed: &Notify) -> bool {
    tokio::time::timeout(Duration::from_millis(1), changed.notified())
        .await
        .is_ok()
}

/// The monitor: a failed lift is reported and retried every round; the fallback reason is reported once lifted; a
/// failed watch is reported and cleared once it works; both items go with the revert; `changed` only on a difference.
#[tokio::test(start_paused = true)]
async fn monitor_lifts_reports_and_reverts() {
    let (_root, p, index, _) = setup();
    let mut a = signed_in(&p, &index, ActiveState::Open, true);
    a.reason = Some("the issuer handed over no facts".into());
    // Only the terminal: the lift mounts the stub over the rest, which can fail
    a.caps = [Capability::Terminal].into_iter().collect();
    write_active(&p.root, &a).unwrap();
    let sim = Arc::new(Sim {
        mounts: MountSim::new(&p.root),
        sessions: Default::default(),
        fail_mounts: true.into(),
    });
    sim.set_sessions(&[
        greeter(),
        row("5", UID, Some("seat0"), "user", Some("active")),
    ]);
    let side: SideResults = Default::default();
    let (changed, kick) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(monitor(
        p.clone(),
        sim.clone(),
        side.clone(),
        changed.clone(),
        kick.clone(),
        shutdown.clone(),
    ));
    // The lift fails: reported
    eventually("the failed lift", || {
        item_of(&side, SESSION_ITEM).is_some_and(|i| !i.ok)
    })
    .await;
    assert!(notified(&changed).await);
    assert_eq!(item_of(&side, REVERT_ITEM), None);
    // Retried on the next round: lifted, the reason reported
    sim.fail_mounts
        .store(false, std::sync::atomic::Ordering::SeqCst);
    tokio::time::sleep(crate::quiet::POLL + Duration::from_secs(1)).await;
    eventually("the lift", || {
        item_of(&side, SESSION_ITEM).is_some_and(|i| i.ok)
    })
    .await;
    let it = item_of(&side, SESSION_ITEM).unwrap();
    assert!(
        it.detail
            .as_deref()
            .is_some_and(|d| d.contains("the issuer handed over no facts")),
        "{it:?}"
    );
    assert_eq!(lifted(&p), a.caps);
    assert!(notified(&changed).await);
    // Rounds and kicks that change nothing do not notify
    kick.notify_one();
    tokio::time::sleep(crate::quiet::POLL * 3).await;
    assert!(!notified(&changed).await);
    assert_eq!(item_of(&side, SESSION_ITEM), Some(it));
    // A watch that fails is reported ...
    *sim.sessions.lock().unwrap() = "not json".into();
    tokio::time::sleep(crate::quiet::POLL + Duration::from_secs(1)).await;
    eventually("the failed watch", || {
        item_of(&side, REVERT_ITEM).is_some_and(|i| !i.ok)
    })
    .await;
    assert!(notified(&changed).await);
    // ... and cleared with the revert once logind shows no session, together with the session's item
    sim.set_sessions(&[greeter()]);
    tokio::time::sleep(crate::quiet::POLL + Duration::from_secs(1)).await;
    eventually("the revert", || read_active(&p.root).is_none()).await;
    eventually("the items cleared", || {
        item_of(&side, REVERT_ITEM).is_none() && item_of(&side, SESSION_ITEM).is_none()
    })
    .await;
    assert!(notified(&changed).await);
    assert_neutral(&p);
    shutdown.cancel();
    task.await.unwrap();
}

/// The format 1/2 cleanup was deferred for this session (R3): the revert removes this layer's files instead of switching
/// to neutral, so the format 1/2 steps' Chrome policy is left as it is, and removes the marker.
#[test]
fn revert_with_deferred_cleanup_removes_the_layer() {
    let (_root, p, index, r) = setup();
    signed_in(&p, &index, ActiveState::Closing, true);
    let var = p.var_dir.join(STATE_SUB);
    fs::write(
        var.join(crate::user_layer::render::CLEANUP_DEFERRED_FILE),
        "",
    )
    .unwrap();
    let managed = p
        .root
        .join("etc/opt/chrome/policies/managed/mastersos.json");
    let policy_before = fs::read(&managed).unwrap();
    list(&r, &[greeter()]);
    assert_eq!(
        watch_at(&p, &r, at(T0 + 1)).unwrap(),
        WatchOutcome::Reverted {
            user_config: "teacher".into()
        }
    );
    assert!(read_active(&p.root).is_none());
    assert_eq!(revert_cmds(&r.calls()), expected_revert_cmds());
    assert_eq!(fs::read(&managed).unwrap(), policy_before);
    // the lifts are dropped (see deferred_revert_drops_the_lifts_and_follows_the_mode_word)
    assert!(!lifted_file(&p).exists());
    assert!(!var.exists());
    assert!(!p.public_dir.join(STATE_SUB).exists());
    assert!(fs::symlink_metadata(p.public_dir.join("session")).is_err());
}

/// Writes the format 1/2 cleanup's deferral (R3).
fn defer_cleanup(p: &SysPaths) {
    fs::write(
        p.var_dir
            .join(STATE_SUB)
            .join(crate::user_layer::render::CLEANUP_DEFERRED_FILE),
        "",
    )
    .unwrap();
}

fn lifted_file(p: &SysPaths) -> std::path::PathBuf {
    p.root
        .join(exec_block::LOCK_DIR)
        .join(exec_block::LIFTED_FILE)
}

/// The revert of a deferred cleanup forgets the session's lifts and converges to the mode word on disk: blocked
/// (`browser`) mounts every stub again, open (`desktop`, a format 1/2 `full` Group) lifts everything.
#[test]
fn deferred_revert_drops_the_lifts_and_follows_the_mode_word() {
    use crate::system::exec_block::tests::is_stub;
    for open in [false, true] {
        let (_root, p, index, r) = setup();
        let a = signed_in(&p, &index, ActiveState::Closing, true);
        exec_block::apply_lifted(&p, &r, &a.caps).unwrap();
        assert!(a.caps.contains(&Capability::Terminal));
        assert!(!is_stub(&p.root, "/usr/libexec/gnome-terminal-server"));
        if open {
            exec_block::write_mode(&p, false).unwrap();
        }
        defer_cleanup(&p);
        list(&r, &[greeter()]);
        assert!(matches!(
            watch_at(&p, &r, at(T0 + 1)).unwrap(),
            WatchOutcome::Reverted { .. }
        ));
        assert!(!lifted_file(&p).exists(), "open {open}");
        assert_eq!(
            is_stub(&p.root, "/usr/libexec/gnome-terminal-server"),
            !open,
            "open {open}"
        );
        assert_eq!(is_stub(&p.root, "/usr/bin/nautilus"), !open, "open {open}");
    }
}

/// While the format 1/2 cleanup is deferred, a login's lift lifts nothing.
#[test]
fn after_login_with_deferred_cleanup_lifts_nothing() {
    let (_root, p, index, r) = setup();
    let a = signed_in(&p, &index, ActiveState::Open, false);
    assert!(!a.caps.is_empty());
    defer_cleanup(&p);
    list(&r, &[greeter()]);
    after_login(&p, &r).unwrap();
    assert_eq!(lifted(&p), Caps::new());
}

/// The deferred removal fails while the session link and the dconf profile are still there: the marker is kept (logins
/// stay refused) and the failure is returned.
#[test]
fn deferred_revert_keeps_the_marker_when_the_removal_fails() {
    let (_root, p, index, r) = setup();
    let a = signed_in(&p, &index, ActiveState::Closing, true);
    defer_cleanup(&p);
    // the profile cannot be removed (a directory where the file is)
    let profile = p.root.join("etc/dconf/profile/user");
    fs::remove_file(&profile).unwrap();
    fs::create_dir_all(profile.join("x")).unwrap();
    list(&r, &[greeter()]);
    let e = watch_at(&p, &r, at(T0 + 1)).unwrap_err();
    assert!(
        format!("{e:#}").contains("removing the user configs"),
        "{e:#}"
    );
    assert_eq!(read_active(&p.root).unwrap(), a);
    assert!(fs::symlink_metadata(p.public_dir.join("session")).is_ok());
}
