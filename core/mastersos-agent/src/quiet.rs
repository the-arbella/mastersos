//! Exam quiet: while a kiosk (locked-app) session is on the seat, background jobs that could disturb it are stopped.
//! This module holds the pure decision logic and the systemctl calls; the agent wires it into its main loop.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

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

/// Remembers since when the system is quiet and when a kiosk session was last seen.
#[derive(Debug)]
pub struct Tracker {
    since: Option<DateTime<Utc>>,
    last_seen: Option<Instant>,
}

impl Tracker {
    /// `target_active` true at start (agent restarted while quiet) is treated as "someone was just here": it exits
    /// after [`EXIT_DELAY`] unless a session shows up.
    pub fn new(target_active: bool, now: Instant, wall: DateTime<Utc>) -> Self {
        if target_active {
            Tracker {
                since: Some(wall),
                last_seen: Some(now),
            }
        } else {
            Tracker {
                since: None,
                last_seen: None,
            }
        }
    }

    pub fn step(
        &mut self,
        present: bool,
        target_active: bool,
        now: Instant,
        wall: DateTime<Utc>,
    ) -> Action {
        if present {
            self.last_seen = Some(now);
            self.since.get_or_insert(wall);
        }
        let quiet = present
            || self
                .last_seen
                .is_some_and(|t| now.saturating_duration_since(t) < EXIT_DELAY);
        if quiet {
            if target_active {
                Action::Nothing
            } else {
                Action::Enter
            }
        } else if self.since.is_some() || target_active {
            self.since = None;
            Action::Exit
        } else {
            Action::Nothing
        }
    }

    pub fn since(&self) -> Option<DateTime<Utc>> {
        self.since
    }
}

/// Starts the quiet target, then stops the units that must not run during it (one command).
pub fn enter(runner: &dyn Runner) -> Result<()> {
    run_ok(
        runner,
        Cmd::new("systemctl", &["start", "--no-block", TARGET]),
    )?;
    let mut args = vec!["stop", "--no-block"];
    args.extend_from_slice(STOP_UNITS);
    // Exit status 5 means "unit not loaded": the transient mastersos-flatpak.service is usually not there. That is fine.
    let out = runner.run(&Cmd::new("systemctl", &args))?;
    if out.code != 0 && out.code != 5 {
        anyhow::bail!("systemctl exited with {}", out.code);
    }
    Ok(())
}

pub fn exit(runner: &dyn Runner) -> Result<()> {
    run_ok(
        runner,
        Cmd::new("systemctl", &["stop", "--no-block", TARGET]),
    )?;
    Ok(())
}

pub fn target_active(runner: &dyn Runner) -> bool {
    runner
        .run(&Cmd::new("systemctl", &["is-active", "--quiet", TARGET]))
        .is_ok_and(|o| o.code == 0)
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

/// Reconciles the quiet target with the sessions every [`POLL`] and publishes since when the system is quiet. A failing
/// `loginctl` counts as "a kiosk session is present" for that round (better too quiet than disturbing an exam). Errors
/// of `enter` / `exit` are logged and retried next round; the loop only ends on `shutdown`.
pub async fn monitor(
    runner: Arc<dyn Runner>,
    tx: watch::Sender<Option<DateTime<Utc>>>,
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
        .unwrap_or_else(|| Err(anyhow::anyhow!("loginctl task failed")));
        let present = match listed {
            Ok(p) => p,
            Err(e) => {
                log::warn!(
                    "quiet: cannot list sessions, assuming a kiosk session is present: {e:#}"
                );
                true
            }
        };
        let active = blocking(&runner, target_active).await.unwrap_or(false);
        let result = match tracker.step(present, active, now(), Utc::now()) {
            Action::Enter => blocking(&runner, enter).await,
            Action::Exit => blocking(&runner, exit).await,
            Action::Nothing => Some(Ok(())),
        };
        match result {
            Some(Ok(())) => {}
            Some(Err(e)) => log::warn!("quiet: {e:#}"),
            None => log::warn!("quiet: systemctl task failed"),
        }
        let since = tracker.since();
        tx.send_if_modified(|cur| {
            if *cur == since {
                false
            } else {
                *cur = since;
                true
            }
        });
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
