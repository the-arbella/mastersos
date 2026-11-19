//! The switch (design `docs/specs/2026-11-19-user-layer-design.md` §4.3, §4.9): at login `pam-session` resolves the
//! person's user config from the pre-rendered rules ([`render::Index`]) and the issuer facts, and switches the session to
//! that config's pre-rendered files. At logout it marks the session closing and wakes the agent, which reverts to neutral.
//!
//! [`switch_to`] only renames files and re-points a symlink, in this order (each step tightens or keeps the strength
//! of the one before, since every config is at least as strict as neutral in the parts switched later):
//!
//! 1. the managed Chrome policy: the staging copy `.mastersos-staging/<d>.json` is made again from `<var_dir>/user-layer/
//!    <d>/chrome.json` and renamed over `managed/mastersos.json`;
//! 2. the dconf database: the config's compiled database ([`render::compiled_db`]) is copied to `mastersos-session.tmp`
//!    (0644) and renamed to `mastersos-session`, the first system database of the dconf profile
//!    `/etc/dconf/profile/user` ([`render::SESSION_PROFILE`], written here once the database exists; it takes
//!    precedence over the image's `/usr/share/dconf/profile/user`, which format 1/2 Devices keep);
//! 3. the session directory: `/var/lib/mastersos-public/session` (first in `XDG_DATA_DIRS`) is re-pointed at
//!    `user-layer/<d>` (`session.tmp`, renamed over `session`); the session mode for the image's readers is
//!    `session/session-mode` behind it, and whose session it is in `session/uid` ([`UID_FILE`], written before the swap;
//!    none for neutral). The target directory is opened (0755) before, and the previous one, unless neutral, is closed
//!    again (0700) after.
//!
//! No command is spawned, nothing is rendered and the bundle is not read: this runs inside PAM (root, synchronous, within
//! `pam-session`'s 5 s budget) and must never panic.

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use mastersos_bundle::{Caps, DeviceFacts, HomeMode, IssuerFacts, Kind, IT_ACCOUNT_USER};

use super::facts::{take_facts, FactsOutcome};
use super::render::{
    self, read_index, Rendered, CHROME_FILE, POLICIES_DIR, SESSION_DB, SESSION_LINK, STAGING_SUB,
    STATE_SUB,
};
use super::{active_marker, is_config_dir, Active, ActiveState, ACTIVE_FILE, NEUTRAL_DIR, RUN_DIR};
use crate::runner::Runner;
use crate::safefs;
use crate::system::chrome_policy;
use crate::system::login::{self, LoginPolicy, UserClass};
use crate::system::SysPaths;

/// The signed-in person's uid (`<uid>\n`, 0644) in the public dir of the config their session uses: the image's readers of
/// `session/session-mode` trust it only in a user manager of this uid, and treat every other one as locked.
pub const UID_FILE: &str = "uid";

/// The lock of the session marker in [`RUN_DIR`] (root 0600): `on_open` holds it from the marker check through the marker
/// write, `on_close` and the agent's revert (Task 6) while they change the marker, so two of them never interleave.
pub const LOCK_FILE: &str = "active.lock";
/// How long `pam-session` waits for [`LOCK_FILE`] before it refuses the login: well inside its 5 s budget.
pub const LOCK_WAIT: Duration = Duration::from_secs(2);

/// The temporary names of the switch, next to their targets.
const SESSION_DB_TMP: &str = "mastersos-session.tmp";
const SESSION_LINK_TMP: &str = "session.tmp";

/// What the Device knows about `user` (uid `uid`) on a Device of Group `group`, for the rules (design §2.1). `kind`
/// is the login classification; a kiosk account never reaches the user layer and counts as a local account. `admin`:
/// a school account in `admin_users`, the agent's `itadmin` (by uid), or a local account where local accounts are
/// administrators.
pub fn device_facts<'a>(
    policy: &LoginPolicy,
    user: &'a str,
    uid: u32,
    group: &'a str,
) -> DeviceFacts<'a> {
    let kind = match login::classify(user, Some(policy)) {
        UserClass::Sso => Kind::Sso,
        UserClass::Guest => Kind::Guest,
        UserClass::Local | UserClass::Kiosk => Kind::Local,
    };
    let it_admin =
        user == IT_ACCOUNT_USER && policy.it_account && policy.it_account_uid == Some(uid);
    let admin = match kind {
        Kind::Sso => login::is_admin(policy, user),
        Kind::Local => it_admin || policy.local_users_admin,
        Kind::Guest => false,
    };
    DeviceFacts {
        kind,
        admin,
        user,
        device_group: group,
    }
}

/// Switches the session to the pre-rendered config `r` (see the module documentation for the three moves and their
/// order). `root` is the system root, `public` the public directory and `var` the agent's system state directory. `uid`
/// is the signed-in person the config is for (`None` for neutral): it is published as [`UID_FILE`] in the config's
/// public dir, so that the image's readers use the session's mode only in that person's own user manager. Stops at the
/// first move that fails: the moves already made stay (each is complete on its own).
pub fn switch_to(
    root: &Path,
    public: &Path,
    var: &Path,
    r: &Rendered,
    uid: Option<u32>,
) -> Result<()> {
    let d = r.dir.as_str();
    if !is_config_dir(d) {
        bail!("{d:?} is not a config directory name");
    }
    switch_chrome(root, var, d).context("Chrome policy")?;
    switch_dconf(root, var, d).context("dconf database")?;
    switch_session_link(public, d, uid).context("session directory")?;
    Ok(())
}

fn switch_chrome(root: &Path, var: &Path, d: &str) -> Result<()> {
    let cdir = safefs::open_abs_dir(var, false)
        .and_then(|v| safefs::open_dir_at(&v, &Path::new(STATE_SUB).join(d), false))?;
    let Some(text) = safefs::read_at(&cdir, CHROME_FILE)? else {
        bail!("{d} has no {CHROME_FILE}");
    };
    let policies = safefs::open_dir(root, Path::new(POLICIES_DIR), false)?;
    let staging = safefs::open_dir_at(&policies, Path::new(STAGING_SUB), true)?;
    safefs::set_mode(&staging, 0o700)?;
    let staged = format!("{d}.json");
    safefs::write_at(&staging, &staged, &text, 0o644)?;
    // Created here only on a Device without it; the mode is explicit since PAM hands down any umask
    let managed = safefs::open_dir(root, Path::new(chrome_policy::POLICY_DIR), true)?;
    safefs::set_mode(&managed, 0o755)?;
    rustix::fs::renameat(
        &staging,
        staged.as_str(),
        &managed,
        chrome_policy::POLICY_FILE,
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("renaming {staged} to {}", chrome_policy::POLICY_FILE))?;
    fsync(&managed)
}

fn switch_dconf(root: &Path, var: &Path, d: &str) -> Result<()> {
    let src = render::compiled_db(root, var, d);
    let (Some(parent), Some(name)) = (src.parent(), src.file_name().and_then(|n| n.to_str()))
    else {
        bail!("{} has no directory", src.display());
    };
    let from = safefs::open_abs_dir(parent, false)?;
    let Some(bytes) = safefs::read_at(&from, name)? else {
        bail!("{name} is missing (not compiled)");
    };
    let db = safefs::open_dir(root, Path::new(render::DCONF_DB_DIR), true)?;
    safefs::write_at(&db, SESSION_DB_TMP, &bytes, 0o644)?;
    safefs::rename_at(&db, SESSION_DB_TMP, SESSION_DB)?;
    // Only now that the database exists may the profile name it (unchanged after the first switch).
    let profile = safefs::open_dir(root, Path::new(render::PROFILE_DIR), true)?;
    safefs::set_mode(&profile, 0o755)?;
    safefs::write_at(
        &profile,
        render::PROFILE_FILE,
        render::SESSION_PROFILE.as_bytes(),
        0o644,
    )?;
    Ok(())
}

fn switch_session_link(public: &Path, d: &str, uid: Option<u32>) -> Result<()> {
    let pub_fd = safefs::open_abs_dir(public, false)?;
    let parent = safefs::open_dir_at(&pub_fd, Path::new(STATE_SUB), false)?;
    let target = safefs::open_dir_at(&parent, Path::new(d), false)?;
    // Whose session this is, before the link makes the dir the session's (neutral is nobody's)
    match uid.filter(|_| d != NEUTRAL_DIR) {
        Some(uid) => {
            safefs::write_at(&target, UID_FILE, format!("{uid}\n").as_bytes(), 0o644)?;
        }
        None => safefs::remove_at(&target, UID_FILE)?,
    }
    safefs::set_mode(&target, 0o755)?;
    let previous = safefs::read_link_at(&pub_fd, SESSION_LINK);
    let link = format!("{STATE_SUB}/{d}");
    match rustix::fs::unlinkat(&pub_fd, SESSION_LINK_TMP, rustix::fs::AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {}
        Err(e) => {
            return Err(std::io::Error::from(e))
                .with_context(|| format!("removing {SESSION_LINK_TMP}"))
        }
    }
    rustix::fs::symlinkat(link.as_str(), &pub_fd, SESSION_LINK_TMP)
        .map_err(std::io::Error::from)
        .with_context(|| format!("creating {SESSION_LINK_TMP}"))?;
    safefs::rename_at(&pub_fd, SESSION_LINK_TMP, SESSION_LINK)?;
    // The previous config's files are root-only again; a failure leaves them readable, never the session looser.
    let prev = previous
        .as_deref()
        .and_then(|p| p.strip_prefix(&format!("{STATE_SUB}/")))
        .filter(|p| is_config_dir(p) && *p != NEUTRAL_DIR && *p != d);
    if let Some(p) = prev {
        let closed = safefs::open_dir_at(&parent, Path::new(p), false)
            .and_then(|fd| safefs::set_mode(&fd, 0o700));
        if let Err(e) = closed {
            eprintln!(
                "mastersos-agent: user layer: closing the previous config directory {p}: {e:#}"
            );
        }
    }
    Ok(())
}

fn fsync(dir: &OwnedFd) -> Result<()> {
    rustix::fs::fsync(dir)
        .map_err(std::io::Error::from)
        .context("fsync of the directory")
}

/// What [`on_open`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenOutcome {
    /// The installed login policy is not format 3: nothing was read or touched.
    NotUserLayer,
    /// The session was switched to `user_config`; `fallback_reason` says why it is the fallback, when it is for a
    /// reason other than the rules.
    Switched {
        user_config: String,
        fallback_reason: Option<String>,
        home: HomeMode,
    },
    /// The login must be refused: another person's session is still signed in (or the marker cannot be read), or
    /// neither the chosen config nor the fallback could be switched in.
    Refused,
}

/// `pam-session`'s open_session of a human account (`user`, uid `uid`): resolves the user config and switches to it,
/// then writes the [`Active`] marker. Reads only the rules file and (for a school account, when the issuer sends facts)
/// the facts file; never the bundle. Facts that are missing, an error or stale only disable the rules with fact
/// conditions (design §5); a config that cannot be switched in gives the fallback, and a fallback that cannot be switched
/// in refuses the login after a best-effort switch to neutral. Reasons go to stderr (the journal) and the marker.
pub fn on_open(
    root: &Path,
    paths: &SysPaths,
    policy: &LoginPolicy,
    user: &str,
    uid: u32,
) -> OpenOutcome {
    on_open_at(root, paths, policy, user, uid, SystemTime::now())
}

pub(crate) fn on_open_at(
    root: &Path,
    paths: &SysPaths,
    policy: &LoginPolicy,
    user: &str,
    uid: u32,
    now: SystemTime,
) -> OpenOutcome {
    if !policy.user_layer {
        return OpenOutcome::NotUserLayer;
    }
    // `root` holds the marker and the facts (`/` in PAM), `paths` the switched files (their root is the same `/`); tests
    // give both the same temporary root.
    debug_assert_eq!(root, paths.root.as_path());
    let log = |msg: &str| eprintln!("mastersos-agent pam-session: {user}: user layer: {msg}");
    // One open at a time, from the marker check through the marker write; a busy lock refuses (fail closed).
    let _lock = match lock_active(root, LOCK_WAIT) {
        Ok(l) => l,
        Err(e) => {
            log(&format!("{e:#}; denied"));
            return OpenOutcome::Refused;
        }
    };
    // Backstop of pam-check's one-session rule: another person's session, or any session being closed, is not touched.
    match active_marker(root) {
        Ok(None) => {}
        Ok(Some(mut a)) if a.uid == uid && a.state == ActiveState::Open => {
            // A second session of the same person keeps the first one's config: nothing is resolved or switched again.
            // The grace of the agent's watch starts again (R9): this login is not in logind yet either, and the first
            // session may be gone already.
            a.opened_at = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
            a.seen = false;
            if let Err(e) = write_active(root, &a) {
                log(&format!("restarting the session's grace failed: {e:#}"));
            }
            let home = read_index(&paths.var_dir)
                .and_then(|i| i.configs.get(&a.user_config).map(|r| r.home))
                .unwrap_or(HomeMode::Keep);
            return OpenOutcome::Switched {
                user_config: a.user_config,
                fallback_reason: a.reason,
                home,
            };
        }
        Ok(Some(a)) => {
            log(&format!(
                "a session is still signed in or closing (uid {}); denied",
                a.uid
            ));
            return OpenOutcome::Refused;
        }
        Err(e) => {
            log(&format!(
                "the session marker cannot be read ({e:#}); denied"
            ));
            return OpenOutcome::Refused;
        }
    }
    let switch =
        |r: &Rendered| switch_to(&paths.root, &paths.public_dir, &paths.var_dir, r, Some(uid));
    let refuse = |why: String| {
        log(&format!("{why}; denied"));
        let neutral = Rendered {
            dir: NEUTRAL_DIR.into(),
            caps: Caps::new(),
            home: HomeMode::Tidy,
        };
        if let Err(e) = switch_to(
            &paths.root,
            &paths.public_dir,
            &paths.var_dir,
            &neutral,
            None,
        ) {
            log(&format!("switching back to neutral: {e:#}"));
        }
        OpenOutcome::Refused
    };
    let Some(index) = read_index(&paths.var_dir) else {
        return refuse("the user config rules are missing or unreadable".into());
    };
    let device = device_facts(policy, user, uid, &index.rules.group);
    let mut reasons: Vec<String> = Vec::new();
    let facts: Option<IssuerFacts> = if device.kind == Kind::Sso && policy.mastersos_claims {
        match take_facts(root, user, now) {
            FactsOutcome::Facts(f) => Some(f),
            FactsOutcome::Missing => {
                reasons.push("the issuer handed over no facts".to_string());
                None
            }
            FactsOutcome::Error(e) => {
                reasons.push(format!("the issuer facts are unusable: {e}"));
                None
            }
            FactsOutcome::Stale => {
                reasons.push("the issuer facts are stale".to_string());
                None
            }
        }
    } else {
        None
    };
    let chosen = index.rules.resolve(&device, facts.as_ref()).user_config;
    let fallback = index.rules.fallback.clone();
    let mut picked = None;
    match index.configs.get(&chosen) {
        Some(r) => match switch(r) {
            Ok(()) => picked = Some((chosen.clone(), r)),
            Err(e) => reasons.push(format!("switching to {chosen:?} failed: {e:#}")),
        },
        None => reasons.push(format!("the user config {chosen:?} was not rendered")),
    }
    if picked.is_none() {
        if !reasons.is_empty() {
            log(&reasons.join("; "));
        }
        if chosen == fallback {
            return refuse(format!("the fallback {fallback:?} cannot be switched in"));
        }
        let Some(r) = index.configs.get(&fallback) else {
            return refuse(format!("the fallback {fallback:?} was not rendered"));
        };
        if let Err(e) = switch(r) {
            return refuse(format!(
                "switching to the fallback {fallback:?} failed: {e:#}"
            ));
        }
        picked = Some((fallback.clone(), r));
    }
    let Some((user_config, r)) = picked else {
        return refuse("no user config was switched in".into());
    };
    // Only a fallback that is not the rules' choice has a reason worth reporting; every reason is kept.
    let reason = (user_config == fallback && !reasons.is_empty()).then(|| reasons.join("; "));
    if let Some(why) = &reason {
        log(&format!("got the fallback {fallback:?}: {why}"));
    }
    let active = Active {
        uid,
        user: user.to_string(),
        user_config: user_config.clone(),
        dir: r.dir.clone(),
        caps: r.caps.clone(),
        state: ActiveState::Open,
        reason: reason.clone(),
        opened_at: now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()),
        seen: false,
    };
    if let Err(e) = write_active(root, &active) {
        return refuse(format!("writing the session marker failed: {e:#}"));
    }
    OpenOutcome::Switched {
        user_config,
        fallback_reason: reason,
        home: r.home,
    }
}

/// `pam-session`'s close_session of a human account (uid `uid`): marks its session [`ActiveState::Closing`] (under
/// [`LOCK_FILE`]) and wakes the agent, which reverts to neutral. Never fails the logout: problems only go to stderr. A
/// marker of another uid is left alone.
pub fn on_close(root: &Path, uid: u32, runner: &dyn Runner) {
    let log = |msg: String| eprintln!("mastersos-agent pam-session: user layer: {msg}");
    match lock_active(root, LOCK_WAIT) {
        Err(e) => log(format!("{e:#}; the session is not marked closing")),
        Ok(_lock) => match active_marker(root) {
            Ok(Some(mut a)) if a.uid == uid => {
                if a.state != ActiveState::Closing {
                    a.state = ActiveState::Closing;
                    if let Err(e) = write_active(root, &a) {
                        log(format!("marking the session closing failed: {e:#}"));
                    }
                }
            }
            Ok(Some(a)) => log(format!(
                "the session marker is for uid {}, not {uid}; left alone",
                a.uid
            )),
            Ok(None) => {}
            Err(e) => log(format!("the session marker cannot be read: {e:#}")),
        },
    }
    crate::login_queue::wake_agent(runner);
}

/// Takes the exclusive `flock` on [`LOCK_FILE`] in [`RUN_DIR`] under `root` (created root 0700 / 0600 when missing),
/// polling up to `wait`; released when the returned fd is dropped. For `pam-session` and the agent's revert (Task 6).
pub fn lock_active(root: &Path, wait: Duration) -> Result<OwnedFd> {
    use rustix::fs::{flock, openat, FlockOperation, Mode, OFlags};
    let dir = safefs::open_dir(root, Path::new(RUN_DIR), true)?;
    safefs::set_mode(&dir, 0o700)?;
    let fd = openat(
        &dir,
        LOCK_FILE,
        OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("opening {LOCK_FILE}"))?;
    let start = Instant::now();
    loop {
        match flock(&fd, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(fd),
            Err(e) if e == rustix::io::Errno::WOULDBLOCK => {}
            Err(e) => {
                return Err(std::io::Error::from(e)).with_context(|| format!("locking {LOCK_FILE}"))
            }
        }
        let waited = start.elapsed();
        if waited >= wait {
            return Err(LockBusy { wait }.into());
        }
        std::thread::sleep(Duration::from_millis(50).min(wait - waited));
    }
}

/// [`lock_active`] waited its whole time: another sign-in, sign-out or revert holds [`LOCK_FILE`].
#[derive(Debug)]
pub struct LockBusy {
    pub wait: Duration,
}

impl std::fmt::Display for LockBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{LOCK_FILE} is still held after {} ms (another sign-in or sign-out is changing the session)",
            self.wait.as_millis()
        )
    }
}

impl std::error::Error for LockBusy {}

/// Whether `e` is (or wraps) a [`LockBusy`].
pub fn is_lock_busy(e: &anyhow::Error) -> bool {
    e.downcast_ref::<LockBusy>().is_some()
}

/// Whether a marker exists under `root` (or cannot be read): some session is open or still being closed.
pub fn marker_present(root: &Path) -> bool {
    !matches!(active_marker(root), Ok(None))
}

/// Writes the marker (`<root>/`[`RUN_DIR`]`/`[`ACTIVE_FILE`], directory root 0700, file 0600).
pub fn write_active(root: &Path, a: &Active) -> Result<()> {
    let dir = safefs::open_dir(root, Path::new(RUN_DIR), true)?;
    safefs::set_mode(&dir, 0o700)?;
    safefs::write_at(&dir, ACTIVE_FILE, &serde_json::to_vec(a)?, 0o600)?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
