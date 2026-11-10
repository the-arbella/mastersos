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
fn manager_class_does_not_count() {
    let j =
        r#"[{"session":"4","uid":1900,"user":"u","seat":null,"class":"manager","state":"active"}]"#;
    assert!(!kiosk_session_present(j).unwrap());
}

#[test]
fn seatless_user_session_does_not_count() {
    let j =
        r#"[{"session":"4","uid":1900,"user":"u","seat":null,"class":"user","state":"active"}]"#;
    assert!(!kiosk_session_present(j).unwrap());
    let j = r#"[{"session":"4","uid":1900,"user":"u","seat":"-","class":"user","state":"active"}]"#;
    assert!(!kiosk_session_present(j).unwrap());
    let j = r#"[{"session":"4","uid":1900,"user":"u","seat":"","class":"user-early"}]"#;
    assert!(!kiosk_session_present(j).unwrap());
    let j = r#"[{"session":"4","uid":1900,"user":"u"}]"#;
    assert!(!kiosk_session_present(j).unwrap());
    let j = r#"[{"session":"4","uid":1900,"user":"u","seat":"seat0","class":"user-early"}]"#;
    assert!(kiosk_session_present(j).unwrap());
}

#[test]
fn bad_json_is_error() {
    assert!(kiosk_session_present("not json").is_err());
}

#[test]
fn enter_when_present() {
    let t0 = Instant::now();
    let mut t = Tracker::new(false, t0, wall(0));
    assert_eq!(t.step(Ok(true), false, t0, wall(0)), Action::Enter);
    assert_eq!(t.since(), Some(wall(0)));
}

#[test]
fn stays_quiet_until_delay() {
    let t0 = Instant::now();
    let mut t = Tracker::new(false, t0, wall(0));
    assert_eq!(t.step(Ok(true), false, t0, wall(0)), Action::Enter);
    t.entered(true);
    let a = t.step(Ok(false), true, t0 + Duration::from_secs(59), wall(59));
    assert_eq!(a, Action::Nothing);
    assert_eq!(t.since(), Some(wall(0)));
    let a = t.step(Ok(false), true, t0 + Duration::from_secs(60), wall(60));
    assert_eq!(a, Action::Exit);
    assert_eq!(t.since(), None);
}

#[test]
fn reenter_target_if_someone_stopped_it() {
    let t0 = Instant::now();
    let mut t = Tracker::new(false, t0, wall(0));
    assert_eq!(t.step(Ok(true), false, t0, wall(0)), Action::Enter);
    let t1 = t0 + Duration::from_secs(5);
    assert_eq!(t.step(Ok(true), false, t1, wall(5)), Action::Enter);
    assert_eq!(t.since(), Some(wall(0)));
}

#[test]
fn stale_target_after_restart_exits() {
    let t0 = Instant::now();
    let mut t = Tracker::new(true, t0, wall(0));
    // The first round issues the enter again (the stop may not have happened before the restart).
    let a = t.step(Ok(false), true, t0 + Duration::from_secs(5), wall(5));
    assert_eq!(a, Action::Enter);
    t.entered(true);
    let a = t.step(Ok(false), true, t0 + Duration::from_secs(10), wall(10));
    assert_eq!(a, Action::Nothing);
    assert_eq!(t.since(), Some(wall(0)));
    let a = t.step(Ok(false), true, t0 + Duration::from_secs(60), wall(60));
    assert_eq!(a, Action::Exit);
}

/// The PAM hook starts the target before logind lists the session: that is a fresh entry, not a stale target.
#[test]
fn target_active_with_no_session_yet_does_not_exit_within_exit_delay() {
    let t0 = Instant::now();
    let mut t = Tracker::new(false, t0, wall(0));
    let a = t.step(Ok(false), true, t0, wall(0));
    assert_eq!(
        a,
        Action::Enter,
        "the stop must be issued and the quiet published"
    );
    assert_eq!(t.since(), Some(wall(0)));
    t.entered(true);
    let a = t.step(Ok(false), true, t0 + Duration::from_secs(59), wall(59));
    assert_eq!(a, Action::Nothing);
    assert_eq!(t.since(), Some(wall(0)));
    let a = t.step(Ok(false), true, t0 + Duration::from_secs(60), wall(60));
    assert_eq!(a, Action::Exit);
    assert_eq!(t.since(), None);
}

/// A session seen while the hook's target is already active still enters (publish + stop the units).
#[test]
fn entering_quiet_issues_the_stop_even_when_the_target_is_already_active() {
    let t0 = Instant::now();
    let mut t = Tracker::new(false, t0, wall(0));
    assert_eq!(t.step(Ok(true), true, t0, wall(0)), Action::Enter);
    t.entered(true);
    let t1 = t0 + Duration::from_secs(5);
    assert_eq!(t.step(Ok(true), true, t1, wall(5)), Action::Nothing);
}

/// An enter that failed (start ok, stop failed) is issued again next round, until it succeeds.
#[test]
fn failed_enter_is_retried() {
    let t0 = Instant::now();
    let mut t = Tracker::new(false, t0, wall(0));
    assert_eq!(t.step(Ok(true), false, t0, wall(0)), Action::Enter);
    t.entered(false);
    let t1 = t0 + Duration::from_secs(5);
    assert_eq!(t.step(Ok(true), true, t1, wall(5)), Action::Enter);
    t.entered(true);
    let t2 = t0 + Duration::from_secs(10);
    assert_eq!(t.step(Ok(true), true, t2, wall(10)), Action::Nothing);
}

/// A target that did not stop on exit is stopped again, not taken for a fresh entry.
#[test]
fn target_that_did_not_stop_is_stopped_again() {
    let t0 = Instant::now();
    let mut t = Tracker::new(false, t0, wall(0));
    assert_eq!(t.step(Ok(true), false, t0, wall(0)), Action::Enter);
    t.entered(true);
    let t1 = t0 + Duration::from_secs(60);
    assert_eq!(t.step(Ok(false), true, t1, wall(60)), Action::Exit);
    let t2 = t0 + Duration::from_secs(65);
    assert_eq!(t.step(Ok(false), true, t2, wall(65)), Action::Exit);
    assert_eq!(t.since(), None);
    let t3 = t0 + Duration::from_secs(70);
    assert_eq!(t.step(Ok(false), false, t3, wall(70)), Action::Nothing);
    // Once it is down, a target started again (the PAM hook) is a fresh entry.
    let t4 = t0 + Duration::from_secs(75);
    assert_eq!(t.step(Ok(false), true, t4, wall(75)), Action::Enter);
}

fn fail() -> std::result::Result<bool, String> {
    Err("loginctl exited with 1".into())
}

/// Failing listings keep the previous decision for up to LIST_FAIL_LIMIT, then count as absent (EXIT_DELAY still
/// applies). The error is reported while it lasts and cleared by the next good listing.
#[test]
fn listing_failures_hold_quiet_for_ten_minutes_then_exit() {
    let t0 = Instant::now();
    let s = |n: u64| t0 + Duration::from_secs(n);
    let mut t = Tracker::new(false, t0, wall(0));
    assert_eq!(t.step(Ok(true), false, s(0), wall(0)), Action::Enter);
    t.entered(true);
    assert_eq!(t.error(), None);
    // Failures from second 5 on: still quiet just before the limit and EXIT_DELAY after it.
    let mut n = 5;
    while n < 5 + 600 + 55 {
        assert_eq!(
            t.step(fail(), true, s(n), wall(n as i64)),
            Action::Nothing,
            "at {n}"
        );
        assert_eq!(t.error(), Some("loginctl exited with 1"));
        n += 5;
    }
    // Limit reached at 605 (absent from then), last seen at 600: exits at 660.
    assert_eq!(t.step(fail(), true, s(660), wall(660)), Action::Exit);
    assert_eq!(t.since(), None);
    assert!(t.error().is_some());
    // A good listing clears the error.
    assert_eq!(t.step(Ok(false), false, s(665), wall(665)), Action::Nothing);
    assert_eq!(t.error(), None);
}

/// A good listing with a kiosk session in between restarts the count; a session that keeps being listed holds the
/// quiet with no limit.
#[test]
fn good_listing_resets_the_failure_count() {
    let t0 = Instant::now();
    let s = |n: u64| t0 + Duration::from_secs(n);
    let mut t = Tracker::new(false, t0, wall(0));
    assert_eq!(t.step(Ok(true), false, s(0), wall(0)), Action::Enter);
    t.entered(true);
    assert_eq!(t.step(fail(), true, s(500), wall(500)), Action::Nothing);
    assert_eq!(t.step(Ok(true), true, s(505), wall(505)), Action::Nothing);
    assert_eq!(t.step(fail(), true, s(510), wall(510)), Action::Nothing);
    // 10 minutes after 510, not after 500.
    assert_eq!(t.step(fail(), true, s(1105), wall(1105)), Action::Nothing);
    assert_eq!(
        t.step(Ok(true), true, s(100_000), wall(100_000)),
        Action::Nothing
    );
    assert_eq!(t.since(), Some(wall(0)));
}

/// Failures from the start keep the start's decision: an active target holds, an inactive one stays loud.
#[test]
fn listing_failures_at_start_keep_the_target_state() {
    let t0 = Instant::now();
    let s = |n: u64| t0 + Duration::from_secs(n);
    let mut t = Tracker::new(false, t0, wall(0));
    assert_eq!(t.step(fail(), false, s(0), wall(0)), Action::Nothing);
    assert_eq!(t.since(), None);
    let mut t = Tracker::new(true, t0, wall(0));
    assert_eq!(t.step(fail(), true, s(0), wall(0)), Action::Enter);
    t.entered(true);
    assert_eq!(t.step(fail(), true, s(595), wall(595)), Action::Nothing);
    // Absent from 600 on (limit reached), last seen at 595: exits at 655.
    assert_eq!(t.step(fail(), true, s(600), wall(600)), Action::Nothing);
    assert_eq!(t.step(fail(), true, s(650), wall(650)), Action::Nothing);
    assert_eq!(t.step(fail(), true, s(655), wall(655)), Action::Exit);
}

#[test]
fn initial_is_set_only_when_the_target_is_active() {
    let r = FakeRunner::new();
    assert!(initial(&r).is_some());
    let r = FakeRunner::new();
    r.respond(
        "systemctl is-active",
        Output {
            code: 3,
            ..Default::default()
        },
    );
    assert!(initial(&r).is_none());
}

#[test]
fn enter_issues_start_then_stop() {
    let r = FakeRunner::new();
    enter(&r).unwrap();
    assert_eq!(
        r.calls(),
        vec![
            "systemctl start --no-block mastersos-quiet.target",
            "systemctl stop --no-block mastersos-update.service mastersos-chrome.service mastersos-deb-apps.service mastersos-golden-fetch.service mastersos-flatpak.service",
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

#[test]
fn enter_tolerates_unit_not_loaded() {
    let r = FakeRunner::new();
    r.respond(
        "systemctl stop",
        Output {
            code: 5,
            ..Default::default()
        },
    );
    enter(&r).unwrap();
    let r = FakeRunner::new();
    r.respond(
        "systemctl stop",
        Output {
            code: 1,
            ..Default::default()
        },
    );
    assert!(enter(&r).is_err());
}

/// Waits (yielding to the monitor) until `cond` holds; fails after 10 s of real time.
async fn eventually(what: &str, cond: impl Fn() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(1));
    }
}

const START: &str = "systemctl start --no-block mastersos-quiet.target";
const STOP_UNITS_LINE: &str = "systemctl stop --no-block mastersos-update.service mastersos-chrome.service mastersos-deb-apps.service mastersos-golden-fetch.service mastersos-flatpak.service";
const STOP_TARGET: &str = "systemctl stop --no-block mastersos-quiet.target";

fn inactive() -> Output {
    Output {
        code: 3,
        ..Default::default()
    }
}

fn spawn_monitor(
    r: Arc<dyn Runner>,
) -> (
    QuietRx,
    SideResults,
    Arc<Notify>,
    CancellationToken,
    tokio::task::JoinHandle<()>,
) {
    let (tx, rx) = watch::channel(None);
    let side: SideResults = Default::default();
    let changed = Arc::new(Notify::new());
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(monitor(
        r,
        tx,
        side.clone(),
        changed.clone(),
        shutdown.clone(),
    ));
    (rx, side, changed, shutdown, task)
}

#[tokio::test(start_paused = true)]
async fn monitor_publishes_since() {
    let r = Arc::new(FakeRunner::new());
    // Inactive at start; afterwards the fake answers "active".
    r.respond("systemctl is-active", inactive());
    r.respond("loginctl", Output::ok(&row(1900, Some("active"))));
    for _ in 0..40 {
        r.respond("loginctl", Output::ok("[]"));
    }
    let (mut rx, _side, _changed, shutdown, task) = spawn_monitor(r.clone());
    tokio::time::timeout(Duration::from_secs(1), rx.wait_for(|v| v.is_some()))
        .await
        .expect("quiet not published")
        .unwrap();
    eventually("the enter commands", || {
        let c = r.calls();
        c.contains(&START.to_string()) && c.contains(&STOP_UNITS_LINE.to_string())
    })
    .await;
    // The paused clock moves only while the monitor sleeps between rounds.
    tokio::time::timeout(Duration::from_secs(120), rx.wait_for(|v| v.is_none()))
        .await
        .expect("quiet did not end")
        .unwrap();
    eventually("the target stop", || {
        r.calls().contains(&STOP_TARGET.to_string())
    })
    .await;
    shutdown.cancel();
    task.await.unwrap();
}

/// Records whether the quiet was already published when the units were stopped.
struct PublishedBeforeStop {
    inner: FakeRunner,
    rx: std::sync::Mutex<Option<QuietRx>>,
    seen: std::sync::Mutex<Vec<bool>>,
}

impl Runner for PublishedBeforeStop {
    fn run(&self, cmd: &Cmd) -> Result<crate::runner::Output> {
        if cmd.line() == STOP_UNITS_LINE {
            let published = self
                .rx
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|rx| rx.borrow().is_some());
            self.seen.lock().unwrap().push(published);
        }
        self.inner.run(cmd)
    }
}

/// The hook started the target before logind lists the session: the monitor publishes the quiet, then stops the
/// units, and does not stop the target within EXIT_DELAY.
#[tokio::test(start_paused = true)]
async fn monitor_publishes_then_stops_for_a_hook_started_target() {
    let r = Arc::new(PublishedBeforeStop {
        inner: FakeRunner::new(),
        rx: Default::default(),
        seen: Default::default(),
    });
    // Inactive at start, then active (the hook); no session listed yet.
    r.inner.respond("systemctl is-active", inactive());
    for _ in 0..40 {
        r.inner.respond("loginctl", Output::ok("[]"));
    }
    let (tx, rx) = watch::channel(None);
    *r.rx.lock().unwrap() = Some(rx.clone());
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(monitor(
        r.clone(),
        tx,
        Default::default(),
        Arc::new(Notify::new()),
        shutdown.clone(),
    ));
    let mut rx2 = rx.clone();
    tokio::time::timeout(Duration::from_secs(1), rx2.wait_for(|v| v.is_some()))
        .await
        .expect("quiet not published")
        .unwrap();
    eventually("the units stop", || !r.seen.lock().unwrap().is_empty()).await;
    assert_eq!(*r.seen.lock().unwrap(), vec![true], "stop before publish");
    tokio::time::sleep(Duration::from_secs(50)).await;
    assert!(rx.borrow().is_some());
    assert!(!r.inner.calls().contains(&STOP_TARGET.to_string()));
    shutdown.cancel();
    task.await.unwrap();
}

/// A failing loginctl is reported as the `quiet` item and cleared once it works again.
#[tokio::test(start_paused = true)]
async fn monitor_reports_listing_failure() {
    let r = Arc::new(FakeRunner::new());
    r.respond("systemctl is-active", inactive());
    r.respond("loginctl", Output::fail(1, "no bus"));
    for _ in 0..40 {
        r.respond("loginctl", Output::ok("[]"));
        r.respond("systemctl is-active", inactive());
    }
    let (_rx, side, changed, shutdown, task) = spawn_monitor(r.clone());
    tokio::time::timeout(Duration::from_secs(1), changed.notified())
        .await
        .expect("no change notified");
    let it = crate::jobs::snapshot(&side);
    assert_eq!(it.len(), 1, "{it:?}");
    assert_eq!(it[0].item, ITEM);
    assert!(!it[0].ok);
    assert!(
        it[0].detail.as_deref().unwrap_or("").contains("loginctl"),
        "{it:?}"
    );
    tokio::time::timeout(Duration::from_secs(10), changed.notified())
        .await
        .expect("no change notified");
    assert!(crate::jobs::snapshot(&side).is_empty());
    shutdown.cancel();
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn wait_until_loud_returns_after_exit() {
    let (tx, rx) = watch::channel(Some(wall(0)));
    let mut rx2 = rx.clone();
    let h = tokio::spawn(async move { wait_until_loud(&mut rx2).await });
    tokio::task::yield_now().await;
    assert!(!h.is_finished());
    tx.send(None).unwrap();
    tokio::time::timeout(Duration::from_secs(1), h)
        .await
        .unwrap()
        .unwrap();
    let mut rx3 = rx;
    wait_until_loud(&mut rx3).await;
}
