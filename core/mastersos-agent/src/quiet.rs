//! Exam quiet: while a kiosk (locked-app) session is on the seat, background jobs that could disturb it are stopped.
//! This module holds the pure decision logic and the systemctl calls; the agent wires it into its main loop.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

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
/// [`KIOSK_UIDS`] and `state` is missing (systemd 259 dropped it) or not `"closing"`.
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
        uid.is_some_and(|u| KIOSK_UIDS.contains(&u)) && !closing
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
    run_ok(runner, Cmd::new("systemctl", &args))?;
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

#[cfg(test)]
mod tests;
