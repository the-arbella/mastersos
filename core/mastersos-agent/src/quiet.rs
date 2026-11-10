//! Exam quiet: while a kiosk (locked-app) session is on the seat, background jobs that could disturb it are stopped.
//! This module holds the pure decision logic and the systemctl calls; the agent wires it into its main loop.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use mastersos_bundle::ItemResult;
use tokio::sync::{watch, Notify};
use tokio_util::sync::CancellationToken;

use crate::jobs::SideResults;
use crate::runner::{run_ok, Cmd, Runner};
use crate::system::ephemeral::KIOSK_UIDS;

/// The target that is active while the system is quiet.
pub const TARGET: &str = "mastersos-quiet.target";
/// Units stopped when quiet starts, in this order.
pub const STOP_UNITS: &[&str] = &[
    "mastersos-update.service",
    "mastersos-chrome.service",
    "mastersos-golden-fetch.service",
    "mastersos-flatpak.service",
];
/// How often the sessions are polled.
pub const POLL: Duration = Duration::from_secs(5);
/// How long after the last kiosk session is gone the quiet ends.
pub const EXIT_DELAY: Duration = Duration::from_secs(60);
/// How long `loginctl` may keep failing before its failures stop holding the quiet (counted from the first failure).
pub const LIST_FAIL_LIMIT: Duration = Duration::from_secs(10 * 60);
/// The report item that shows a failing `loginctl`.
pub const ITEM: &str = "quiet";

/// Is there a kiosk session in `loginctl --json=short list-sessions` output? A row counts when `uid` is a number in
/// [`KIOSK_UIDS`], `state` is missing (systemd 259 dropped it) or not `"closing"`, `class` starts with `user`
/// (`manager`, `background`, `greeter` and `lock-screen` rows do not count) and `seat` is a real seat (null, `""` and
/// `"-"` mean none). A row without `class` or `seat` is skipped.
pub fn kiosk_session_present(loginctl_json: &str) -> Result<bool> {
    let v: serde_json::Value =
        serde_json::from_str(loginctl_json.trim()).context("loginctl output is not JSON")?;
    let rows = v.as_array().context("loginctl output is not an array")?;
    Ok(rows.iter().any(|row| {
        let uid = row
            .get("uid")
            .and_then(|u| u.as_u64())
            .and_then(|u| u32::try_from(u).ok());
        let closing = row.get("state").and_then(|s| s.as_str()) == Some("closing");
        let user_class = row
            .get("class")
            .and_then(|c| c.as_str())
            .is_some_and(|c| c.starts_with("user"));
        let has_seat = row
            .get("seat")
            .and_then(|s| s.as_str())
            .is_some_and(|s| !s.is_empty() && s != "-");
        uid.is_some_and(|u| KIOSK_UIDS.contains(&u)) && !closing && user_class && has_seat
    }))
}

/// What the caller has to do after a [`Tracker::step`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Enter,
    Exit,
    Nothing,
}

/// Remembers since when the system is quiet, when a kiosk session was last seen, how `loginctl` is doing and whether
/// the last enter or exit still has to be done again.
#[derive(Debug)]
pub struct Tracker {
    since: Option<DateTime<Utc>>,
    last_seen: Option<Instant>,
    /// The previous round's answer; a failed listing repeats it.
    present: bool,
    /// Since when `loginctl` has been failing without a good listing in between.
    failing_since: Option<Instant>,
    /// The latest listing error while listings fail.
    error: Option<String>,
    /// The last enter did not complete (or never ran after a restart): issue it again.
    enter_pending: bool,
    /// We stopped the target and have not seen it inactive yet: while it is still active it is ours to stop again,
    /// not a fresh entry.
    exiting: bool,
}

impl Tracker {
    /// `target_active` true at start (agent restarted while quiet) is treated as "someone was just here": it exits
    /// after [`EXIT_DELAY`] unless a session shows up, and the first round enters again (stops the units).
    pub fn new(target_active: bool, now: Instant, wall: DateTime<Utc>) -> Self {
        Tracker {
            since: target_active.then_some(wall),
            last_seen: target_active.then_some(now),
            present: target_active,
            failing_since: None,
            error: None,
            enter_pending: target_active,
            exiting: false,
        }
    }

    /// One round. `listed` is the `loginctl` answer (is a kiosk session there?) or its error. A failed listing keeps
    /// the previous answer until listings have failed for [`LIST_FAIL_LIMIT`], then counts as "no session".
    /// The target active while not quiet (the PAM hook started it before logind lists the session) is a fresh entry.
    /// [`Action::Enter`] comes when the quiet starts, when the target is down while quiet, and until
    /// [`Tracker::entered`] reports success; the caller publishes [`Tracker::since`] before acting on it.
    pub fn step(
        &mut self,
        listed: std::result::Result<bool, String>,
        target_active: bool,
        now: Instant,
        wall: DateTime<Utc>,
    ) -> Action {
        let present = match listed {
            Ok(p) => {
                self.failing_since = None;
                self.error = None;
                p
            }
            Err(e) => {
                let first = *self.failing_since.get_or_insert(now);
                self.error = Some(e);
                self.present && now.saturating_duration_since(first) < LIST_FAIL_LIMIT
            }
        };
        self.present = present;
        if !target_active {
            self.exiting = false;
        }
        if present || (target_active && self.since.is_none() && !self.exiting) {
            self.last_seen = Some(now);
        }
        let quiet = self
            .last_seen
            .is_some_and(|t| now.saturating_duration_since(t) < EXIT_DELAY);
        if quiet {
            self.exiting = false;
            if self.since.is_none() {
                self.since = Some(wall);
                self.enter_pending = true;
            }
            if self.enter_pending || !target_active {
                Action::Enter
            } else {
                Action::Nothing
            }
        } else if self.since.is_some() || target_active {
            self.since = None;
            self.enter_pending = false;
            self.exiting = true;
            Action::Exit
        } else {
            Action::Nothing
        }
    }

    pub fn since(&self) -> Option<DateTime<Utc>> {
        self.since
    }

    /// The outcome of the enter an [`Action::Enter`] asked for; a failed one is issued again next round.
    pub fn entered(&mut self, ok: bool) {
        self.enter_pending = !ok;
    }

    /// The `loginctl` error while listings fail; `None` after a good listing.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

/// Timeout of every `systemctl` call: `enter` runs in the PAM login path, where a hung systemd must not stall a login.
pub const CMD_TIMEOUT: Duration = Duration::from_secs(5);

fn start_cmd() -> Cmd {
    Cmd::new("systemctl", &["start", "--no-block", TARGET]).timeout(CMD_TIMEOUT)
}

fn stop_units_cmd() -> Cmd {
    let mut args = vec!["stop", "--no-block"];
    args.extend_from_slice(STOP_UNITS);
    Cmd::new("systemctl", &args).timeout(CMD_TIMEOUT)
}

fn stop_target_cmd() -> Cmd {
    Cmd::new("systemctl", &["stop", "--no-block", TARGET]).timeout(CMD_TIMEOUT)
}

fn is_active_cmd() -> Cmd {
    Cmd::new("systemctl", &["is-active", "--quiet", TARGET]).timeout(CMD_TIMEOUT)
}

/// Starts the quiet target, then stops the units that must not run during it (one command).
pub fn enter(runner: &dyn Runner) -> Result<()> {
    run_ok(runner, start_cmd())?;
    // Exit status 5 means "unit not loaded": the transient mastersos-flatpak.service is usually not there. That is fine.
    let out = runner.run(&stop_units_cmd())?;
    if out.code != 0 && out.code != 5 {
        anyhow::bail!("systemctl exited with {}", out.code);
    }
    Ok(())
}

pub fn exit(runner: &dyn Runner) -> Result<()> {
    run_ok(runner, stop_target_cmd())?;
    Ok(())
}

pub fn target_active(runner: &dyn Runner) -> bool {
    runner.run(&is_active_cmd()).is_ok_and(|o| o.code == 0)
}

/// The quiet value to start with: "since now" when the target is already active (the agent restarted during a
/// kiosk session), so nothing held is applied before the monitor's first round.
pub fn initial(runner: &dyn Runner) -> Option<DateTime<Utc>> {
    target_active(runner).then(Utc::now)
}

#[cfg(test)]
mod cmd_timeout_tests {
    use super::*;

    #[test]
    fn every_systemctl_command_has_a_short_timeout() {
        for c in [
            start_cmd(),
            stop_units_cmd(),
            stop_target_cmd(),
            is_active_cmd(),
        ] {
            assert!(c.timeout <= Duration::from_secs(5), "{c:?}");
        }
    }
}

/// Since when the system is quiet; `None` when it is not.
pub type QuietRx = watch::Receiver<Option<DateTime<Utc>>>;

/// Timeout of the `loginctl` call.
const LOGINCTL_TIMEOUT: Duration = Duration::from_secs(5);

/// Runs a blocking closure with the runner off the async threads. A panic or cancelled task counts as a failure.
async fn blocking<T: Send + 'static>(
    runner: &Arc<dyn Runner>,
    f: impl FnOnce(&dyn Runner) -> T + Send + 'static,
) -> Option<T> {
    let r = runner.clone();
    tokio::task::spawn_blocking(move || f(r.as_ref()))
        .await
        .ok()
}

fn publish(tx: &watch::Sender<Option<DateTime<Utc>>>, since: Option<DateTime<Utc>>) {
    tx.send_if_modified(|cur| {
        if *cur == since {
            false
        } else {
            *cur = since;
            true
        }
    });
}

/// Puts the `loginctl` error into the report as the [`ITEM`] item (removed once it works again); `changed` is notified
/// when that changes the results.
fn report_error(side: &SideResults, changed: &Notify, error: Option<&str>) {
    let mut g = side.lock().unwrap_or_else(|e| e.into_inner());
    let differs = match error {
        Some(e) => {
            let it = ItemResult {
                item: ITEM.into(),
                ok: false,
                detail: Some(format!("cannot list the sessions: {e}")),
            };
            g.insert(ITEM.into(), it.clone()) != Some(it)
        }
        None => g.remove(ITEM).is_some(),
    };
    drop(g);
    if differs {
        changed.notify_one();
    }
}

/// Reconciles the quiet target with the sessions every [`POLL`] and publishes since when the system is quiet (before
/// stopping the units, so the agent's own work is held first). A failing `loginctl` keeps the previous answer for up
/// to [`LIST_FAIL_LIMIT`] and is reported as the [`ITEM`] item in `side`. Failed enters and exits are logged and
/// retried next round; the loop only ends on `shutdown`.
pub async fn monitor(
    runner: Arc<dyn Runner>,
    tx: watch::Sender<Option<DateTime<Utc>>>,
    side: SideResults,
    changed: Arc<Notify>,
    shutdown: CancellationToken,
) {
    // `tokio::time::Instant` follows the paused test clock; `Tracker` wants a std one.
    let now = || tokio::time::Instant::now().into_std();
    let active = blocking(&runner, target_active).await.unwrap_or(false);
    let mut tracker = Tracker::new(active, now(), Utc::now());
    loop {
        let listed = blocking(&runner, |r| {
            run_ok(
                r,
                Cmd::new("loginctl", &["--json=short", "list-sessions"]).timeout(LOGINCTL_TIMEOUT),
            )
            .and_then(|out| kiosk_session_present(&out))
        })
        .await
        .unwrap_or_else(|| Err(anyhow::anyhow!("loginctl task failed")))
        .map_err(|e| format!("{e:#}"));
        if let Err(e) = &listed {
            log::warn!("quiet: cannot list sessions: {e}");
        }
        let active = blocking(&runner, target_active).await.unwrap_or(false);
        let action = tracker.step(listed, active, now(), Utc::now());
        report_error(&side, &changed, tracker.error());
        if action == Action::Enter {
            // Hold the agent's own work first, then stop the units.
            publish(&tx, tracker.since());
        }
        let result = match action {
            Action::Enter => blocking(&runner, enter).await,
            Action::Exit => blocking(&runner, exit).await,
            Action::Nothing => Some(Ok(())),
        };
        if action == Action::Enter {
            tracker.entered(matches!(result, Some(Ok(()))));
        }
        match result {
            Some(Ok(())) => {}
            Some(Err(e)) => log::warn!("quiet: {e:#}"),
            None => log::warn!("quiet: systemctl task failed"),
        }
        publish(&tx, tracker.since());
        tokio::select! {
            _ = tokio::time::sleep(POLL) => {}
            _ = shutdown.cancelled() => return,
        }
    }
}

/// Returns at once when the system is not quiet, else waits until it is not.
pub async fn wait_until_loud(rx: &mut QuietRx) {
    // An error means the sender is gone (the agent is shutting down): nothing will make it quiet again.
    let _ = rx.wait_for(|v| v.is_none()).await;
}

#[cfg(test)]
mod tests;
