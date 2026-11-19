use super::*;
use crate::runner::Output;
use crate::system::exec_block::tests::{put_image, MountSim};
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

/// A rendered root with the exec-block stub and targets in it, and a runner that simulates the bind mounts.
fn setup() -> (tempfile::TempDir, SysPaths, Index, MountSim) {
    let (root, p, index) = rendered();
    put_image(root.path());
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
    assert_eq!(read_lifted(&p).unwrap(), None);
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

#[test]
fn no_marker_is_idle_and_runs_nothing() {
    let (_root, p, _index, r) = setup();
    assert_eq!(watch_at(&p, &r, at(T0)).unwrap(), WatchOutcome::Idle);
    assert!(r.calls().is_empty(), "{:?}", r.calls());
    assert!(!p.root.join(RUN_DIR).exists());
}

#[test]
fn revert_on_closing() {
    let (_root, p, index, r) = setup();
    let a = signed_in(&p, &index, ActiveState::Closing, false);
    after_login(&p, &r).unwrap();
    exec_block::apply_lifted(&p, &r, &a.caps).unwrap();
    assert_eq!(
        watch_at(&p, &r, at(T0 + 1)).unwrap(),
        WatchOutcome::Reverted {
            user_config: "teacher".into()
        }
    );
    assert_neutral(&p);
    assert!(read_active(&p.root).is_none());
    assert!(!p.root.join(RUN_DIR).join(ACTIVE_FILE).exists());
    let calls = r.calls();
    // Closing reverts at once: logind is not asked
    assert!(!calls.iter().any(|c| c.starts_with(LIST)), "{calls:?}");
    assert_eq!(revert_cmds(&calls), expected_revert_cmds());
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
    r.fail_on("systemctl stop");
    let e = watch_at(&p, &r, at(T0 + 1)).unwrap_err();
    assert!(format!("{e:#}").contains("user@"), "{e:#}");
    assert_eq!(read_active(&p.root), Some(a.clone()));
    assert_neutral(&p);
    assert_eq!(revert_cmds(&r.calls()), expected_revert_cmds());
    // Next round it works and the marker goes
    let r2 = MountSim::new(&p.root);
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
