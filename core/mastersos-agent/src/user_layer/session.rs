//! The agent's side of a session of the user layer (design `docs/specs/2026-11-19-user-layer-design.md` §4.4, §4.5,
//! §4.8). `pam-session` switches the person's pre-rendered config in and writes the [`Active`] marker
//! ([`super::switch`]); the agent then:
//!
//! - after login ([`after_login`]) lifts the exec-block capabilities of that config (neutral blocks everything, so this
//!   only loosens; a late or failed lift leaves the session stricter);
//! - watches the session ([`watch`], every [`crate::quiet::POLL`] and after every wake-up) and, once it is closing or
//!   gone from logind, reverts to neutral: the neutral config switched in, everything blocked, linger off and the
//!   person's user manager stopped, and only then the marker removed. Until then `pam-check` refuses the next login;
//! - at boot ([`boot_neutral`]) switches to neutral when no session is open: the switched files outlive a reboot.
//!
//! The revert holds [`switch::lock_active`] for its whole sequence, as `pam-session` does while it changes the marker. A
//! busy lock is not an error: the work is retried on the next round.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use mastersos_bundle::{Caps, HomeMode, ItemResult};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use super::render::{Rendered, STATE_SUB};
use super::switch::{self, lock_active, switch_to, write_active, LOCK_WAIT};
use super::{active_marker, Active, ActiveState, ACTIVE_FILE, NEUTRAL_DIR, RUN_DIR};
use crate::jobs::SideResults;
use crate::login_queue::SYSTEMCTL_TIMEOUT;
use crate::runner::{run_ok, Cmd, Runner};
use crate::safefs;
use crate::system::guest::{logind_session_state, logind_sessions};
use crate::system::{exec_block, SysPaths};

/// How long an open session that logind has never listed is left alone (R9): `pam-session` runs before `pam_systemd`,
/// so a session just opened is not in logind yet. After this the login counts as one that never happened (a later PAM
/// module failed) and is reverted.
pub const OPEN_GRACE: Duration = Duration::from_secs(60);
/// The report item of a failed revert (the marker is kept and logins stay refused).
pub const REVERT_ITEM: &str = "user-layer:revert";
/// The report item of the open session: why it got the fallback config, or why its capabilities were not lifted.
pub const SESSION_ITEM: &str = "user-layer:session";

/// What [`watch`] found or did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchOutcome {
    /// No session of the user layer.
    Idle,
    /// The session is open (or just opened and not yet in logind).
    StillOpen,
    /// The session was closed and the Device is back to neutral.
    Reverted { user_config: String },
    /// The marker's lock is held by a sign-in, sign-out or revert: nothing was done; retried next round.
    Busy,
}

/// After a login: when the marker says a session is open (and not [`Active::held`]), lift its config's capabilities
/// ([`exec_block::apply_lifted`]), under the marker's lock so that a lift never lands after a revert. When logind already
/// lists a live session of the uid, the marker records it as seen (as [`watch`] does). A fallback reason in the marker
/// is logged. Nothing to do without a marker; an unreadable marker is an error, a busy lock a
/// [`switch::LockBusy`] error.
pub fn after_login(paths: &SysPaths, runner: &dyn Runner) -> Result<()> {
    let root = paths.root.as_path();
    let Some(before) = active_marker(root)? else {
        return Ok(());
    };
    // Asked outside the lock; only a help for `seen`, so a failure is only logged
    let live = match uid_has_live_session(runner, before.uid) {
        Ok(live) => live,
        Err(e) => {
            log::warn!("user layer: listing the sessions after a login: {e:#}");
            false
        }
    };
    let _lock = lock_active(root, LOCK_WAIT)?;
    let Some(mut a) = active_marker(root)? else {
        return Ok(());
    };
    if a.state != ActiveState::Open {
        return Ok(());
    }
    if live && a.uid == before.uid && !a.seen {
        a.seen = true;
        if let Err(e) = write_active(root, &a) {
            log::warn!("user layer: recording that the session was seen: {e:#}");
        }
    }
    if let Some(why) = &a.reason {
        log::warn!(
            "user layer: the session got the fallback {:?}: {why}",
            a.user_config
        );
    }
    // Held until the next login (its user config was removed mid-session): nothing is lifted
    if a.held {
        return Ok(());
    }
    exec_block::apply_lifted(paths, runner, &a.caps).context("lifting the session's capabilities")
}

/// Checks the session of the marker and reverts to neutral when it is over, that is when logind lists no live `user*`
/// session of its uid (state not `closing`) and the marker is [`ActiveState::Closing`], or [`ActiveState::Open`] with
/// a session the agent saw before (`seen`) or a login at least [`OPEN_GRACE`] old. A live session sets `seen`; a
/// closing marker whose uid still has a live session (R27: the same person signed in elsewhere, say on a tty) becomes
/// open again, so logins stay refused until that session is gone too. The revert, in this order: neutral switched
/// in, everything blocked (both skipped when the format 1/2 apply already removed this layer's files, R26),
/// `loginctl disable-linger`, `systemctl stop user@<uid>.service`, and only when all of them worked the marker removed.
/// Any failure keeps the marker (logins stay refused) and is returned. An unreadable marker or logind list is an error,
/// never "no session". A busy lock is [`WatchOutcome::Busy`].
pub fn watch(paths: &SysPaths, runner: &dyn Runner) -> Result<WatchOutcome> {
    watch_at(paths, runner, SystemTime::now())
}

pub(crate) fn watch_at(
    paths: &SysPaths,
    runner: &dyn Runner,
    now: SystemTime,
) -> Result<WatchOutcome> {
    let root = paths.root.as_path();
    // Most rounds: no session, nothing locked or run
    let Some(before) = active_marker(root).context("reading the session marker")? else {
        return Ok(WatchOutcome::Idle);
    };
    // logind is asked outside the lock, so that a sign-in waiting for it is not held up by `loginctl`; a failure keeps
    // the marker (fail closed) and is retried next round
    let live = uid_has_live_session(runner, before.uid)?;
    let _lock = match lock_active(root, LOCK_WAIT) {
        Ok(l) => l,
        Err(e) if switch::is_lock_busy(&e) => return Ok(WatchOutcome::Busy),
        Err(e) => return Err(e),
    };
    let Some(mut a) = active_marker(root).context("reading the session marker")? else {
        return Ok(WatchOutcome::Idle);
    };
    // What logind said is about `before`'s uid; a marker that changed meanwhile waits for the next round
    if a.uid != before.uid {
        return Ok(WatchOutcome::StillOpen);
    }
    if live {
        if a.state == ActiveState::Closing {
            log::warn!(
                "user layer: a session of uid {} was closed but another one is still signed in; keeping it",
                a.uid
            );
        }
        if a.state != ActiveState::Open || !a.seen {
            a.state = ActiveState::Open;
            a.seen = true;
            write_active(root, &a).context("recording that the session was seen")?;
        }
        return Ok(WatchOutcome::StillOpen);
    }
    if a.state == ActiveState::Open {
        let opened = UNIX_EPOCH + Duration::from_secs(a.opened_at);
        let age = now.duration_since(opened).unwrap_or(Duration::ZERO);
        if !a.seen && age < OPEN_GRACE {
            return Ok(WatchOutcome::StillOpen);
        }
        log::info!(
            "user layer: logind has no session of uid {} any more; reverting",
            a.uid
        );
    }
    revert(paths, runner, &a)?;
    log::info!(
        "user layer: the session of {:?} is back to neutral",
        a.user_config
    );
    Ok(WatchOutcome::Reverted {
        user_config: a.user_config,
    })
}

/// The revert of [`watch`], with the marker's lock held by the caller.
fn revert(paths: &SysPaths, runner: &dyn Runner, a: &Active) -> Result<()> {
    let mut errs: Vec<String> = Vec::new();
    if layer_state_present(paths) {
        if let Err(e) = to_neutral(paths, runner) {
            errs.push(format!("{e:#}"));
        }
    } else {
        log::info!(
            "user layer: its files are gone (settings format 1/2); not switching to neutral"
        );
    }
    let uid = a.uid.to_string();
    let unit = format!("user@{uid}.service");
    for cmd in [
        Cmd::new("loginctl", &["disable-linger", &uid]),
        Cmd::new("systemctl", &["stop", &unit]),
    ] {
        let line = cmd.line();
        if let Err(e) = run_ok(runner, cmd.timeout(SYSTEMCTL_TIMEOUT)) {
            errs.push(format!("{line}: {e:#}"));
        }
    }
    if !errs.is_empty() {
        return Err(anyhow!(
            "reverting the session to neutral: {}",
            errs.join("; ")
        ));
    }
    let dir = safefs::open_dir(&paths.root, Path::new(RUN_DIR), false)?;
    safefs::remove_at(&dir, ACTIVE_FILE).context("removing the session marker")
}

/// Neutral switched in, then every capability blocked. Both are tried; the errors are joined.
pub(crate) fn to_neutral(paths: &SysPaths, runner: &dyn Runner) -> Result<()> {
    let neutral = Rendered {
        dir: NEUTRAL_DIR.into(),
        caps: Caps::new(),
        home: HomeMode::Tidy,
    };
    let switched = switch_to(
        &paths.root,
        &paths.public_dir,
        &paths.var_dir,
        &neutral,
        None,
    )
    .context("switching to neutral");
    let blocked =
        exec_block::apply_lifted(paths, runner, &Caps::new()).context("blocking everything");
    match (switched, blocked) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), Ok(())) | (Ok(()), Err(e)) => Err(e),
        (Err(a), Err(b)) => Err(anyhow!("{a:#}; {b:#}")),
    }
}

/// Whether this layer's pre-rendered state exists (`<var_dir>/user-layer`); only a missing one counts as gone.
fn layer_state_present(paths: &SysPaths) -> bool {
    match std::fs::symlink_metadata(paths.var_dir.join(STATE_SUB)) {
        Ok(_) => true,
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    }
}

/// Whether logind lists a session of `uid` of a `user*` class that is not `closing`. A failing or unreadable list, or
/// a `user*` row without a uid, is an error.
fn uid_has_live_session(runner: &dyn Runner, uid: u32) -> Result<bool> {
    for s in logind_sessions(runner, SYSTEMCTL_TIMEOUT)? {
        if !s.class.starts_with("user") {
            continue;
        }
        let Some(row_uid) = s.uid else {
            anyhow::bail!("loginctl lists a user session without a uid");
        };
        if row_uid != uid {
            continue;
        }
        let id = s.id.as_deref().context("loginctl row has no session")?;
        if logind_session_state(runner, id, s.state.as_deref(), SYSTEMCTL_TIMEOUT)? != "closing" {
            return Ok(true);
        }
    }
    Ok(false)
}

/// At boot (agent start, and `apply-local` before GDM) under a format 3 bundle: no session is open (no marker), so the
/// Device goes neutral, whatever the last session left switched in. Returns whether it did; a marker (or an unreadable
/// one) leaves everything alone: a session is open while the agent restarts.
pub fn boot_neutral(paths: &SysPaths, runner: &dyn Runner) -> Result<bool> {
    let root = paths.root.as_path();
    let _lock = lock_active(root, LOCK_WAIT)?;
    if switch::marker_present(root) {
        return Ok(false);
    }
    to_neutral(paths, runner)?;
    Ok(true)
}

/// The resident agent's loop: [`watch`] every [`crate::quiet::POLL`] and, on `kick` (the login queue was taken after a
/// wake-up: a login or a logout), [`after_login`] then [`watch`]. Failures go into `side` as [`SESSION_ITEM`] and
/// [`REVERT_ITEM`] (removed once they work again; `changed` is notified only when that changes the results). A failed
/// lift is retried every round until it works. A busy lock changes nothing and is retried next round. Ends on
/// `shutdown`.
pub async fn monitor(
    paths: SysPaths,
    runner: Arc<dyn Runner>,
    side: SideResults,
    changed: Arc<Notify>,
    kick: Arc<Notify>,
    shutdown: CancellationToken,
) {
    let paths = Arc::new(paths);
    // A session opened while the agent was not running is lifted on the first round
    let mut lift = true;
    loop {
        if lift {
            let (p, r) = (paths.clone(), runner.clone());
            let done = tokio::task::spawn_blocking(move || {
                after_login(&p, r.as_ref())?;
                Ok::<_, anyhow::Error>(super::read_active(&p.root))
            })
            .await
            .unwrap_or_else(|e| Err(anyhow!("the lift task failed: {e}")));
            match done {
                Err(e) if switch::is_lock_busy(&e) => {}
                Err(e) => {
                    log::warn!("user layer: {e:#}");
                    let item = ItemResult {
                        item: SESSION_ITEM.into(),
                        ok: false,
                        detail: Some(format!("{e:#}")),
                    };
                    set_item(&side, &changed, SESSION_ITEM, Some(item));
                }
                Ok(active) => {
                    lift = false;
                    let item = active
                        .filter(|a| a.state == ActiveState::Open)
                        .and_then(|a| a.reason)
                        .map(|why| ItemResult {
                            item: SESSION_ITEM.into(),
                            ok: true,
                            detail: Some(format!("got the fallback: {why}")),
                        });
                    set_item(&side, &changed, SESSION_ITEM, item);
                }
            }
        }
        let (p, r) = (paths.clone(), runner.clone());
        let watched = tokio::task::spawn_blocking(move || watch(&p, r.as_ref()))
            .await
            .unwrap_or_else(|e| Err(anyhow!("the watch task failed: {e}")));
        match watched {
            Ok(WatchOutcome::Busy) => {}
            Ok(outcome) => {
                if matches!(outcome, WatchOutcome::Reverted { .. }) {
                    set_item(&side, &changed, SESSION_ITEM, None);
                }
                set_item(&side, &changed, REVERT_ITEM, None);
            }
            Err(e) => {
                log::warn!("user layer: {e:#}");
                let item = ItemResult {
                    item: REVERT_ITEM.into(),
                    ok: false,
                    detail: Some(format!("{e:#}")),
                };
                set_item(&side, &changed, REVERT_ITEM, Some(item));
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(crate::quiet::POLL) => {}
            _ = kick.notified() => lift = true,
            _ = shutdown.cancelled() => return,
        }
    }
}

/// Puts `item` into `side` under `name` (`None` removes it); notifies `changed` when that changes the results.
fn set_item(side: &SideResults, changed: &Notify, name: &str, item: Option<ItemResult>) {
    let mut g = side.lock().unwrap_or_else(|e| e.into_inner());
    let differs = match item {
        Some(it) => g.insert(name.into(), it.clone()) != Some(it),
        None => g.remove(name).is_some(),
    };
    drop(g);
    if differs {
        changed.notify_one();
    }
}

#[cfg(test)]
mod tests;
