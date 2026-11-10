use super::*;
use crate::runner::{FakeRunner, Output};
use chrono::TimeZone;

fn row(uid: u32, state: Option<&str>) -> String {
    let st = state
        .map(|s| format!(r#","state":"{s}""#))
        .unwrap_or_default();
    format!(r#"[{{"session":"3","uid":{uid},"user":"u","seat":"seat0","class":"user"{st}}}]"#)
}

fn wall(s: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_000 + s, 0).unwrap()
}

#[test]
fn present_for_kiosk_uid() {
    assert!(kiosk_session_present(&row(1900, Some("active"))).unwrap());
}

#[test]
fn guest_and_normal_users_do_not_count() {
    assert!(!kiosk_session_present(&row(1999, Some("active"))).unwrap());
    assert!(!kiosk_session_present(&row(1000, Some("active"))).unwrap());
}

#[test]
fn closing_does_not_count() {
    assert!(!kiosk_session_present(&row(1950, Some("closing"))).unwrap());
}

#[test]
fn missing_state_counts() {
    assert!(kiosk_session_present(&row(1989, None)).unwrap());
}

#[test]
fn bad_json_is_error() {
    assert!(kiosk_session_present("not json").is_err());
}

#[test]
fn enter_when_present() {
    let t0 = Instant::now();
    let mut t = Tracker::new(false, t0, wall(0));
    assert_eq!(t.step(true, false, t0, wall(0)), Action::Enter);
    assert_eq!(t.since(), Some(wall(0)));
}

#[test]
fn stays_quiet_until_delay() {
    let t0 = Instant::now();
    let mut t = Tracker::new(false, t0, wall(0));
    assert_eq!(t.step(true, false, t0, wall(0)), Action::Enter);
    let a = t.step(false, true, t0 + Duration::from_secs(59), wall(59));
    assert_eq!(a, Action::Nothing);
    assert_eq!(t.since(), Some(wall(0)));
    let a = t.step(false, true, t0 + Duration::from_secs(60), wall(60));
    assert_eq!(a, Action::Exit);
    assert_eq!(t.since(), None);
}

#[test]
fn reenter_target_if_someone_stopped_it() {
    let t0 = Instant::now();
    let mut t = Tracker::new(false, t0, wall(0));
    assert_eq!(t.step(true, false, t0, wall(0)), Action::Enter);
    let t1 = t0 + Duration::from_secs(5);
    assert_eq!(t.step(true, false, t1, wall(5)), Action::Enter);
    assert_eq!(t.since(), Some(wall(0)));
}

#[test]
fn stale_target_after_restart_exits() {
    let t0 = Instant::now();
    let mut t = Tracker::new(true, t0, wall(0));
    let a = t.step(false, true, t0 + Duration::from_secs(5), wall(5));
    assert_eq!(a, Action::Nothing);
    let a = t.step(false, true, t0 + Duration::from_secs(60), wall(60));
    assert_eq!(a, Action::Exit);
}

#[test]
fn enter_issues_start_then_stop() {
    let r = FakeRunner::new();
    enter(&r).unwrap();
    assert_eq!(
        r.calls(),
        vec![
            "systemctl start --no-block mastersos-quiet.target",
            "systemctl stop --no-block mastersos-update.service mastersos-chrome.service mastersos-golden-fetch.service mastersos-flatpak.service",
        ]
    );
}

#[test]
fn exit_and_target_active() {
    let r = FakeRunner::new();
    exit(&r).unwrap();
    assert_eq!(
        r.calls(),
        vec!["systemctl stop --no-block mastersos-quiet.target"]
    );
    let r = FakeRunner::new();
    r.respond(
        "systemctl is-active",
        Output {
            code: 3,
            ..Default::default()
        },
    );
    assert!(!target_active(&r));
    let r = FakeRunner::new();
    assert!(target_active(&r));
}
