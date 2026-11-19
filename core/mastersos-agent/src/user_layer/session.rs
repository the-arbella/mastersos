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

use super::render::{self, read_index, Rendered, STATE_SUB};
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
/// (those of the marker that the rules file's rendering of its config still grants)
/// ([`exec_block::apply_lifted`]), under the marker's lock so that a lift never lands after a revert. When logind already
/// lists a live session of the uid, the marker records it as seen (as [`watch`] does). A fallback reason in the marker
/// is logged. Nothing to do without a marker, or while a format 1/2 apply has deferred its cleanup for the session
/// ([`render::cleanup_deferred`]); an unreadable marker is an error, a busy lock a [`switch::LockBusy`] error.
pub fn after_login(paths: &SysPaths, runner: &dyn Runner) -> Result<()> {
    let root = paths.root.as_path();
    let Some(before) = active_marker(root)? else {
        return Ok(());
    };
    // Settings format 1/2 waiting for this session to end: nothing of format 3 is lifted any more
    if render::cleanup_deferred(paths) {
        return Ok(());
    }
    // Asked outside the lock; only a help for `seen`, so a failure is only logged
    let live = match uid_has_live_session(runner, before.uid) {
        Ok(live) => live,
        Err(e) => {
            log::warn!("user layer: listing the sessions after a login: {e:#}");
            false
        }
    };
    let _lock = lock_active(root, LOCK_WAIT)?;
    // Again under the lock: a format 1/2 apply may have deferred its cleanup meanwhile
    if render::cleanup_deferred(paths) {
        return Ok(());
    }
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
    // Only what the rendered config still grants: a marker a failed reapply could not narrow (or that still names a
    // removed config) never lifts a capability the settings took away. No rules file: nothing.
    let granted = read_index(&paths.var_dir)
        .and_then(|i| i.configs.get(&a.user_config).map(|r| r.caps.clone()))
        .unwrap_or_default();
    let caps: Caps = a.caps.intersection(&granted).copied().collect();
    exec_block::apply_lifted(paths, runner, &caps).context("lifting the session's capabilities")
}

/// Checks the session of the marker and reverts to neutral when it is over, that is when logind lists no live `user*`
/// session of its uid (state not `closing`) and the marker is [`ActiveState::Closing`], or [`ActiveState::Open`] with
/// a session the agent saw before (`seen`) or a login at least [`OPEN_GRACE`] old. A live session sets `seen`; a
/// closing marker whose uid still has a live session (R27: the same person signed in elsewhere, say on a tty) becomes
/// open again, so logins stay refused until that session is gone too. The revert, in this order: neutral switched
/// in, everything blocked (both skipped when the format 1/2 apply already removed this layer's files, R26; when a format
/// 1/2 apply deferred that removal for this session, the lifts dropped and the removal instead, whose failure keeps the
/// marker only while the session link or the dconf profile is still there),
/// `loginctl disable-linger`, `systemctl stop user@<uid>.service`, and only when all of them worked the marker removed.
/// Any failure keeps the marker (logins stay refused) and is returned. An unreadable marker or logind list is an error,
/// never "no session". A busy lock is [`WatchOutcome::Busy`]. Without a marker, a deferred format 1/2 cleanup is
/// finished (its failure returned and retried every round). With a marker and a deferral, a stray lift is dropped first;
/// its failure is returned after the session was looked at (an ended one is still torn down). A deferral whose login
/// policy cannot be read is returned as an error, drops the lifts, and keeps an ended session's files and marker.
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
        return idle(paths, runner);
    };
    // logind is asked outside the lock, so that a sign-in waiting for it is not held up by `loginctl`; a failure keeps
    // the marker (fail closed) and is retried next round
    let live = uid_has_live_session(runner, before.uid)?;
    let _lock = match lock_active(root, LOCK_WAIT) {
        Ok(l) => l,
        Err(e) if switch::is_lock_busy(&e) => return Ok(WatchOutcome::Busy),
        Err(e) => return Err(e),
    };
    let Some(a) = active_marker(root).context("reading the session marker")? else {
        // Gone meanwhile: the next round looks at a deferred cleanup
        return Ok(WatchOutcome::Idle);
    };
    // A format 1/2 apply deferred its cleanup for this session: nothing may stay lifted (a lift that slipped in before
    // the deferral is dropped within one round). A login policy that cannot be read counts as deferred (fail closed).
    let due = deferred_cleanup_due(paths);
    let due_known = due.as_ref().ok().copied();
    let mut errs: Vec<anyhow::Error> = Vec::new();
    if let Err(e) = due {
        errs.push(e);
    }
    if exec_block::lifts_recorded(paths) && due_known != Some(false) {
        if let Err(e) = exec_block::drop_lifts(paths, runner) {
            // The session is still looked at below (an ended one is torn down; its revert keeps the marker while the
            // lifts stay); the failure is returned after that
            errs.push(e.context("dropping a lift while the settings format 1/2 cleanup waits"));
        }
    }
    let outcome = session_round(paths, runner, now, a, before.uid, live, due_known);
    match outcome {
        Ok(o @ WatchOutcome::Reverted { .. }) => {
            for e in &errs {
                log::warn!("user layer: {e:#}");
            }
            Ok(o)
        }
        Ok(o) if errs.is_empty() => Ok(o),
        Ok(_) => Err(join_errors(errs)),
        Err(e) => {
            errs.push(e);
            Err(join_errors(errs))
        }
    }
}

/// One error from several, in order.
fn join_errors(mut errs: Vec<anyhow::Error>) -> anyhow::Error {
    if errs.len() == 1 {
        return errs.remove(0);
    }
    let text: Vec<String> = errs.iter().map(|e| format!("{e:#}")).collect();
    anyhow!("{}", text.join("; "))
}

/// The part of [`watch_at`] after the lifts: whether the session of `a` (under the marker's lock) goes on or is
/// reverted. `due` is [`deferred_cleanup_due`], `None` when the login policy cannot be read.
fn session_round(
    paths: &SysPaths,
    runner: &dyn Runner,
    now: SystemTime,
    mut a: Active,
    uid: u32,
    live: bool,
    due: Option<bool>,
) -> Result<WatchOutcome> {
    let root = paths.root.as_path();
    // What logind said is about `before`'s uid; a marker that changed meanwhile waits for the next round
    if a.uid != uid {
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
    revert(paths, runner, &a, due)?;
    log::info!(
        "user layer: the session of {:?} is back to neutral",
        a.user_config
    );
    Ok(WatchOutcome::Reverted {
        user_config: a.user_config,
    })
}

/// The revert of [`watch`], with the marker's lock held by the caller.
/// `due` is [`deferred_cleanup_due`], `None` when the login policy cannot be read.
fn revert(paths: &SysPaths, runner: &dyn Runner, a: &Active, due: Option<bool>) -> Result<()> {
    let mut errs: Vec<String> = Vec::new();
    // Reported after the marker is removed: a failure that leaves nothing a next session would read
    let mut after: Option<anyhow::Error> = None;
    if due.is_none() {
        // A deferral whose login policy cannot be read (reported by the watch): neither neutral (it would overwrite a
        // format 1/2 Chrome policy and mode) nor the removal; the user is torn down, the marker stays, retried
        errs.push(
            "the deferred settings format 1/2 cleanup waits; the session's files are kept".into(),
        );
    } else if due == Some(true) {
        // A format 1/2 apply waited for this session: its lifts are forgotten and its files go now, instead of neutral
        // being switched in (which would overwrite the format 1/2 steps' Chrome policy and exec-block mode).
        if let Err(e) = finish_cleanup(paths, runner) {
            // While the session link or the dconf profile is still there (or the lifts could not be dropped), the next
            // login would get this layer's files or lifts: the marker stays (logins refused). Otherwise the marker goes
            // and the watch finishes the removal on its next rounds (reported until then).
            if e.is::<LiftsKept>() || session_files_present(paths) {
                errs.push(format!("{e:#}"));
            } else {
                after = Some(e);
            }
        }
    } else if layer_state_present(paths) {
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
    safefs::remove_at(&dir, ACTIVE_FILE).context("removing the session marker")?;
    match after {
        Some(e) => Err(e.context(
            "the session is back, but the settings format 1/2 cleanup is not done; retried",
        )),
        None => Ok(()),
    }
}

/// [`watch`] without a marker: a format 1/2 cleanup that was deferred (and no session waits for it any more) is finished
/// under the marker's lock; its failure is returned (reported) and retried next round. Only a stat otherwise.
fn idle(paths: &SysPaths, runner: &dyn Runner) -> Result<WatchOutcome> {
    if !render::cleanup_deferred(paths) {
        return Ok(WatchOutcome::Idle);
    }
    let _lock = match lock_active(&paths.root, LOCK_WAIT) {
        Ok(l) => l,
        Err(e) if switch::is_lock_busy(&e) => return Ok(WatchOutcome::Busy),
        Err(e) => return Err(e),
    };
    if !matches!(active_marker(&paths.root), Ok(None)) {
        // A session (or an unreadable marker): its revert does it
        return Ok(WatchOutcome::Idle);
    }
    if deferred_cleanup_due(paths)? {
        finish_cleanup(paths, runner)?;
        log::info!("user layer: settings format 1/2: removed the user configs of format 3");
    }
    Ok(WatchOutcome::Idle)
}

/// Whether a deferred format 1/2 cleanup ([`render::cleanup_deferred`]) is to be done now, with the marker's lock held:
/// only while the installed login policy is not format 3. Under format 3 the deferral is stale (a format 3 render that
/// could not delete it): it is deleted and the session reverts as usual. A login policy that cannot be read is an error:
/// nothing is removed or switched, and with a marker the lifts are dropped and the marker kept (fail closed).
fn deferred_cleanup_due(paths: &SysPaths) -> Result<bool> {
    if !render::cleanup_deferred(paths) {
        return Ok(false);
    }
    match crate::system::login::policy_at(paths) {
        Some(p) if !p.user_layer => Ok(true),
        Some(_) => {
            if let Err(e) = render::drop_deferral(paths) {
                log::warn!(
                    "user layer: deleting a stale deferral of the format 1/2 cleanup: {e:#}"
                );
            }
            Ok(false)
        }
        None => {
            let e = anyhow!(
                "the login policy cannot be read; the deferred settings format 1/2 cleanup waits"
            );
            log::warn!("user layer: {e}");
            Err(e)
        }
    }
}

/// The lifts could not be dropped: nothing was removed, so the deferral and its retry stay.
#[derive(Debug)]
struct LiftsKept(anyhow::Error);

impl std::fmt::Display for LiftsKept {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "dropping the session's lifts: {:#}", self.0)
    }
}

impl std::error::Error for LiftsKept {}

/// The deferred format 1/2 cleanup, with the marker's lock held: the lifts dropped (the exec-block back to the mode word
/// on disk), then, only when that worked, this layer's files removed (with the deferral).
fn finish_cleanup(paths: &SysPaths, runner: &dyn Runner) -> Result<()> {
    exec_block::drop_lifts(paths, runner).map_err(|e| anyhow::Error::new(LiftsKept(e)))?;
    render::remove_state(paths)
        .context("removing the user configs of an earlier settings format 3")?;
    Ok(())
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

/// Whether a session still reads this layer's files: the session link or the dconf profile exists (or cannot be
/// checked).
fn session_files_present(paths: &SysPaths) -> bool {
    let present = |p: std::path::PathBuf| match std::fs::symlink_metadata(p) {
        Ok(_) => true,
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    };
    present(paths.public_dir.join(render::SESSION_LINK))
        || present(
            paths
                .root
                .join(render::PROFILE_DIR)
                .join(render::PROFILE_FILE),
        )
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
                // No session any more (a revert that removed the marker and then failed, or a deferred cleanup): the
                // session's item goes with it, as on a revert
                if matches!(active_marker(&paths.root), Ok(None)) {
                    set_item(&side, &changed, SESSION_ITEM, None);
                }
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
