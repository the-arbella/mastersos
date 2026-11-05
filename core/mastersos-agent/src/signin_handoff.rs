//! The sign-in handoff (docs/specs/2026-11-05-browser-signin-handoff-design.md): the identity provider's cookies from the
//! login screen's sign-in card go to the desktop Chrome of the school account that just signed in with that card, so the
//! school's websites open already signed in.
//!
//! Three root steps meet in [`HANDOFF_DIR`] (root 0711; [`PRIVATE`] in it root 0700, with a lock file every step holds):
//! - [`begin`] (`signin-handoff begin <greeter>`, the card unit's `ExecStartPre=+`): every card start first removes whatever
//!   an earlier card left, then notes the card ([`CARD`]: instance, `INVOCATION_ID` and the `login_hint` email of the URL the
//!   login screen left in the greeter's runtime directory). Fails only when it could not remove the old state; the card does
//!   not start then.
//! - [`stash`] (`signin-handoff stash <greeter>`, `ExecStopPost=+`, after every process of the unit has exited, so nothing
//!   can change the card's private /tmp any more): when the note is this very invocation's, copies the card's cookie
//!   database ([`MAX_DB_BYTES`] at most) to [`PENDING`] and notes when the card stopped.
//! - [`claim`] (`pam-session`, open_session of an SSO account on `gdm-authd`, through [`claim_from_pam`]): when the note's
//!   email is this user, notes the claim ([`CLAIM`]) and leaves an empty root-owned placeholder `<uid>` that the user unit
//!   waits on.
//!
//! Whichever of stash and claim comes second hands over ([`try_deliver`]): both within [`TTL_SECS`], same email; the
//! database becomes `<uid>` in [`HANDOFF_DIR`] (owned by that uid, 0600, put in place by rename) and the notes are removed.
//! The user's own `signin-import` ([`import`]) reads it, empties it and writes the user's Chrome profile: root never writes
//! where the user (or the greeter) can.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod cookies;
pub mod import;

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use rustix::fs::{FlockOperation, Mode, OFlags};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::safefs;
use crate::system::login;

/// Where the three steps meet and the delivered database waits for its user.
pub const HANDOFF_DIR: &str = "/run/mastersos-signin";
const HANDOFF_REL: &str = "run/mastersos-signin";
/// Root-only notes and the stashed database.
pub const PRIVATE: &str = "private";
const LOCK: &str = "lock";
/// The card that was started last.
pub const CARD: &str = "card.json";
/// Its cookie database, after it stopped.
pub const PENDING: &str = "pending.db";
/// The session that was opened for the card's email.
pub const CLAIM: &str = "claim.json";
/// A stashed database and a claim are each good for this long (the session opens a second or two after the card stops).
pub const TTL_SECS: u64 = 120;
/// The URL the login screen leaves (`card.js` writes one line).
pub const MAX_URL_BYTES: u64 = 4096;
const MAX_RECORD_BYTES: u64 = 4096;
/// The card's cookie database (a sign-in writes some tens of KiB).
pub const MAX_DB_BYTES: u64 = 4 << 20;
/// The card's Chrome profile in the unit's private /tmp: `login-browser`'s `--user-data-dir=/tmp/profile`.
pub const CARD_PROFILE: &str = "profile";
/// The card's unit, a template whose instance is the greeter's user.
pub const CARD_UNIT: &str = "mastersos-login-browser";
/// The file `card.js` leaves in the greeter's runtime directory.
pub const URL_FILE: &str = "mastersos-login-url";
/// The PAM service of a sign-in through the card (authd).
pub const CLAIM_SERVICE: &str = "gdm-authd";
/// How long a step waits for another one to let go of the lock.
const LOCK_WAIT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CardRecord {
    instance: String,
    invocation: String,
    email: String,
    /// Seconds on [`now`]'s clock when the card stopped and its database was stashed.
    #[serde(default)]
    stopped: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Claim {
    user: String,
    uid: u32,
    at: u64,
}

/// Seconds since boot, counting suspend: a laptop closed between the card and the session lets the stash expire.
pub fn now() -> u64 {
    #[cfg(target_os = "linux")]
    let t = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    #[cfg(not(target_os = "linux"))]
    let t = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    u64::try_from(t.tv_sec).unwrap_or(0)
}

/// The greeter's users: `gdm-greeter`, `gdm-greeter-2` and on (the polkit rule of the card unit says the same).
pub fn valid_instance(s: &str) -> bool {
    match s.strip_prefix("gdm-greeter") {
        Some("") => true,
        Some(rest) => rest.strip_prefix('-').is_some_and(|n| {
            !n.is_empty() && n.len() <= 6 && n.bytes().all(|b| b.is_ascii_digit())
        }),
        None => false,
    }
}

/// systemd's `INVOCATION_ID`: 32 lowercase hex digits.
pub fn valid_invocation(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The `login_hint` of the card's URL (the broker puts the user name there, patch 0003), ASCII lowercase. `None` unless the
/// URL is https and the hint looks like an email address.
pub fn email_from_url(url: &str) -> Option<String> {
    let url = reqwest::Url::parse(url.trim()).ok()?;
    if url.scheme() != "https" {
        return None;
    }
    let hint = url
        .query_pairs()
        .find(|(k, _)| k == "login_hint")
        .map(|(_, v)| v.into_owned())?;
    let ok = !hint.is_empty()
        && hint.len() <= 256
        && hint.contains('@')
        && !hint.starts_with('-')
        && !hint.chars().any(|c| c.is_control() || c.is_whitespace());
    ok.then(|| hint.to_ascii_lowercase())
}

fn io(e: rustix::io::Errno) -> anyhow::Error {
    anyhow::Error::from(std::io::Error::from(e))
}

/// Owner, permission bits (setuid, setgid and sticky included) and size.
fn owner_of(fd: impl AsFd) -> Result<(u32, Mode, u64)> {
    let st = rustix::fs::fstat(fd).map_err(io)?;
    Ok((
        st.st_uid,
        Mode::from_raw_mode(st.st_mode),
        u64::try_from(st.st_size).unwrap_or(u64::MAX),
    ))
}

fn ensure_owner(fd: impl AsFd, uid: u32, what: &str) -> Result<()> {
    let (owner, _, _) = owner_of(fd)?;
    ensure!(owner == uid, "{what} belongs to uid {owner}, not {uid}");
    Ok(())
}

/// The handoff directories, open, with the lock held for as long as this lives.
struct Dirs {
    handoff: OwnedFd,
    private: OwnedFd,
    _lock: OwnedFd,
}

/// Opens (creating) [`HANDOFF_DIR`] under `root` and [`PRIVATE`] in it, both owned by `owner` (root; the test's own uid),
/// sets their modes and takes the lock.
fn open_dirs(root: &Path, owner: u32) -> Result<Dirs> {
    let handoff = safefs::open_dir(root, Path::new(HANDOFF_REL), true)?;
    ensure_owner(&handoff, owner, HANDOFF_DIR)?;
    safefs::set_mode(&handoff, 0o711)?;
    let private = safefs::open_dir_at(&handoff, Path::new(PRIVATE), true)?;
    ensure_owner(&private, owner, PRIVATE)?;
    safefs::set_mode(&private, 0o700)?;
    let lock = rustix::fs::openat(
        &private,
        LOCK,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(io)
    .context("opening the lock")?;
    let deadline = Instant::now() + LOCK_WAIT;
    loop {
        match rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => break,
            Err(rustix::io::Errno::WOULDBLOCK) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20))
            }
            Err(e) => return Err(io(e).context("taking the lock")),
        }
    }
    Ok(Dirs {
        handoff,
        private,
        _lock: lock,
    })
}

/// At most `max` bytes of `dir/name`; `None` when it is not there. Larger is an error.
fn read_bounded(dir: &OwnedFd, name: &str, max: u64) -> Result<Option<Vec<u8>>> {
    let Some(f) = safefs::open_file_at(dir, name)? else {
        return Ok(None);
    };
    let mut buf = Vec::new();
    f.take(max + 1)
        .read_to_end(&mut buf)
        .with_context(|| format!("reading {name}"))?;
    ensure!(buf.len() as u64 <= max, "{name} is larger than {max} bytes");
    Ok(Some(buf))
}

/// A note in [`PRIVATE`]; one that does not parse counts as not there.
fn read_note<T: DeserializeOwned>(d: &Dirs, name: &str) -> Result<Option<T>> {
    Ok(read_bounded(&d.private, name, MAX_RECORD_BYTES)?
        .and_then(|b| serde_json::from_slice(&b).ok()))
}

fn write_note<T: Serialize>(d: &Dirs, name: &str, v: &T) -> Result<()> {
    safefs::write_at(&d.private, name, &serde_json::to_vec(v)?, 0o600)?;
    Ok(())
}

/// Removes everything but [`PRIVATE`] from the handoff directory and everything but the lock from [`PRIVATE`].
fn wipe(d: &Dirs) -> Result<()> {
    for name in safefs::list_at(&d.handoff)? {
        if name != PRIVATE {
            safefs::remove_at(&d.handoff, &name)?;
        }
    }
    for name in safefs::list_at(&d.private)? {
        if name != LOCK {
            safefs::remove_at(&d.private, &name)?;
        }
    }
    Ok(())
}

/// Copies `from` (at most [`MAX_DB_BYTES`]) into `to` in `dir`, owned by `uid` when given, mode `mode`.
fn copy_into(
    mut from: std::fs::File,
    dir: &OwnedFd,
    to: &str,
    mode: u32,
    uid: Option<u32>,
) -> Result<()> {
    let (_, _, size) = owner_of(&from)?;
    ensure!(size <= MAX_DB_BYTES, "the cookie database is {size} bytes");
    let mut t = safefs::TmpFile::create(dir, to, mode)?;
    let n = std::io::copy(&mut (&mut from).take(MAX_DB_BYTES + 1), &mut t)?;
    ensure!(
        n <= MAX_DB_BYTES,
        "the cookie database grew past {MAX_DB_BYTES} bytes"
    );
    if let Some(uid) = uid {
        t.chown(uid)?;
    }
    t.commit()
}

/// The first step of every card start: forget everything earlier cards left, then note this one when its URL names an
/// email and systemd gave an invocation id. Returns the email noted.
pub fn begin(
    root: &Path,
    owner: u32,
    instance: &str,
    invocation: &str,
    url: Option<&[u8]>,
) -> Result<Option<String>> {
    let d = open_dirs(root, owner)?;
    wipe(&d)?;
    let email = url
        .and_then(|b| std::str::from_utf8(b).ok())
        .and_then(|s| s.lines().next())
        .and_then(email_from_url);
    let Some(email) = email.filter(|_| valid_instance(instance) && valid_invocation(invocation))
    else {
        return Ok(None);
    };
    write_note(
        &d,
        CARD,
        &CardRecord {
            instance: instance.into(),
            invocation: invocation.into(),
            email: email.clone(),
            stopped: None,
        },
    )?;
    Ok(Some(email))
}

/// The URL `card.js` left for the greeter `greeter_uid` (`run/user/<uid>/`[`URL_FILE`] under `root`): the directory and the
/// file must belong to that uid; at most [`MAX_URL_BYTES`]. Read only, nothing followed. `None` when it is not there.
pub fn read_greeter_url(root: &Path, greeter_uid: u32) -> Result<Option<Vec<u8>>> {
    let users = safefs::open_dir(root, Path::new("run/user"), false)?;
    let Some(dir) = safefs::open_child_dir(&users, &greeter_uid.to_string())? else {
        return Ok(None);
    };
    ensure_owner(&dir, greeter_uid, "the greeter's runtime directory")?;
    let Some(f) = safefs::open_file_at(&dir, URL_FILE)? else {
        return Ok(None);
    };
    ensure_owner(&f, greeter_uid, URL_FILE)?;
    let mut buf = Vec::new();
    f.take(MAX_URL_BYTES + 1).read_to_end(&mut buf)?;
    ensure!(buf.len() as u64 <= MAX_URL_BYTES, "{URL_FILE} is too long");
    Ok(Some(buf))
}

/// Who owns what at the card's stop.
#[derive(Debug, Clone, Copy)]
pub struct Owners {
    /// root (the test's own uid).
    pub root: u32,
    /// The greeter user the card ran as.
    pub greeter: u32,
}

/// What [`stash`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stashed {
    /// No card noted (no email in its URL, or [`begin`] did not run).
    NoCard,
    /// The note is another card's (another greeter, an earlier invocation) or this one was stashed already.
    Stale,
    /// The card left no cookie database: everything is removed (a waiting placeholder too).
    NoCookies,
    /// Stashed; no claim yet.
    Stored,
    /// Stashed and handed to this uid.
    Delivered(u32),
}

/// Names in `dir` that start with `prefix`, skipping names that are not UTF-8 (anyone can make those in /tmp).
fn names_with_prefix(dir: &OwnedFd, prefix: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for e in rustix::fs::Dir::read_from(dir).map_err(io)? {
        let e = e.map_err(io)?;
        if let Ok(name) = std::str::from_utf8(e.file_name().to_bytes()) {
            if let Some(rest) = name.strip_prefix(prefix) {
                if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric()) {
                    out.push(name.to_string());
                }
            }
        }
    }
    Ok(out)
}

fn child_owned(dir: &OwnedFd, name: &str, uid: u32) -> Result<Option<OwnedFd>> {
    let Some(fd) = safefs::open_child_dir(dir, name)? else {
        return Ok(None);
    };
    ensure_owner(&fd, uid, name)?;
    Ok(Some(fd))
}

/// The card's cookie database in its unit's private /tmp (`tmp/systemd-private-<boot id>-<unit>-<random>/tmp/`
/// [`CARD_PROFILE`]`/Default/Cookies` under `root`): exactly one such directory, root's and 0700, then the greeter's profile.
pub fn card_cookies(
    root: &Path,
    owners: Owners,
    boot_id: &str,
    instance: &str,
) -> Result<Option<std::fs::File>> {
    let tmp = safefs::open_dir(root, Path::new("tmp"), false)?;
    let prefix = format!("systemd-private-{boot_id}-{CARD_UNIT}@{instance}.service-");
    let names = names_with_prefix(&tmp, &prefix)?;
    let name = match names.as_slice() {
        [] => return Ok(None),
        [one] => one,
        _ => bail!(
            "{} private /tmp directories for {CARD_UNIT}@{instance}",
            names.len()
        ),
    };
    let Some(outer) = child_owned(&tmp, name, owners.root)? else {
        return Ok(None);
    };
    let (_, mode, _) = owner_of(&outer)?;
    ensure!(
        mode == Mode::from_raw_mode(0o700),
        "{name} has mode {mode:?}, not 0700"
    );
    let Some(inner) = child_owned(&outer, "tmp", owners.root)? else {
        return Ok(None);
    };
    let Some(profile) = child_owned(&inner, CARD_PROFILE, owners.greeter)? else {
        return Ok(None);
    };
    let Some(default) = child_owned(&profile, "Default", owners.greeter)? else {
        return Ok(None);
    };
    let Some(f) = safefs::open_file_at(&default, "Cookies")? else {
        return Ok(None);
    };
    ensure_owner(&f, owners.greeter, "the card's Cookies")?;
    Ok(Some(f))
}

/// The card's last step: when the note is this invocation's, stash its cookie database and hand it over if the session
/// already claimed it.
pub fn stash(
    root: &Path,
    owners: Owners,
    boot_id: &str,
    instance: &str,
    invocation: &str,
    now: u64,
) -> Result<Stashed> {
    let d = open_dirs(root, owners.root)?;
    let Some(mut card) = read_note::<CardRecord>(&d, CARD)? else {
        return Ok(Stashed::NoCard);
    };
    if card.instance != instance || card.invocation != invocation || card.stopped.is_some() {
        return Ok(Stashed::Stale);
    }
    let Some(f) = card_cookies(root, owners, boot_id, instance)? else {
        wipe(&d)?;
        return Ok(Stashed::NoCookies);
    };
    copy_into(f, &d.private, PENDING, 0o600, None)?;
    card.stopped = Some(now);
    write_note(&d, CARD, &card)?;
    Ok(match try_deliver(&d, now)? {
        Some(uid) => Stashed::Delivered(uid),
        None => Stashed::Stored,
    })
}

/// What [`claim`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claimed {
    /// No card noted.
    NoCard,
    /// The card was opened for someone else.
    Mismatch,
    /// Claimed; the card has not stopped yet.
    Waiting,
    /// Claimed and handed over.
    Delivered,
}

/// A session of `user` (uid `uid`) is opening after a sign-in: claim the card's cookies when the card was opened for this
/// user (ASCII case-insensitive).
pub fn claim(root: &Path, owner: u32, user: &str, uid: u32, now: u64) -> Result<Claimed> {
    let d = open_dirs(root, owner)?;
    let Some(card) = read_note::<CardRecord>(&d, CARD)? else {
        return Ok(Claimed::NoCard);
    };
    if !card.email.eq_ignore_ascii_case(user) {
        return Ok(Claimed::Mismatch);
    }
    write_note(
        &d,
        CLAIM,
        &Claim {
            user: user.to_ascii_lowercase(),
            uid,
            at: now,
        },
    )?;
    let name = uid.to_string();
    if safefs::open_file_at(&d.handoff, &name)?.is_none() {
        safefs::write_at(&d.handoff, &name, b"", 0o644)?;
    }
    Ok(match try_deliver(&d, now)? {
        Some(_) => Claimed::Delivered,
        None => Claimed::Waiting,
    })
}

/// Hands the stashed database over when the card stopped and the session claimed it, both within [`TTL_SECS`] and for the
/// same email. Anything expired is removed.
fn try_deliver(d: &Dirs, now: u64) -> Result<Option<u32>> {
    let card = read_note::<CardRecord>(d, CARD)?;
    let claim = read_note::<Claim>(d, CLAIM)?;
    let (Some(card), Some(claim)) = (card, claim) else {
        return Ok(None);
    };
    let fresh = |t: u64| now.saturating_sub(t) <= TTL_SECS;
    if !fresh(claim.at)
        || card.stopped.is_some_and(|t| !fresh(t))
        || !card.email.eq_ignore_ascii_case(&claim.user)
    {
        wipe(d)?;
        return Ok(None);
    }
    if card.stopped.is_none() {
        return Ok(None);
    }
    let Some(pending) = safefs::open_file_at(&d.private, PENDING)? else {
        wipe(d)?;
        return Ok(None);
    };
    copy_into(
        pending,
        &d.handoff,
        &claim.uid.to_string(),
        0o600,
        Some(claim.uid),
    )?;
    for name in [PENDING, CLAIM, CARD] {
        safefs::remove_at(&d.private, name)?;
    }
    Ok(Some(claim.uid))
}

/// `pam-session`, open_session: an SSO account (a name with `@`) signing in on [`CLAIM_SERVICE`] claims the card. Never
/// fails the session; problems go to stderr.
pub fn claim_from_pam(service: &str, user: &str, uid: u32) {
    if service != CLAIM_SERVICE
        || login::classify(user, None) != login::UserClass::Sso
        || login::is_system_uid(uid)
    {
        return;
    }
    match claim(Path::new("/"), 0, user, uid, now()) {
        Ok(Claimed::Delivered) => {
            eprintln!("mastersos-agent pam-session: browser sign-in handed to uid {uid}")
        }
        Ok(_) => {}
        Err(e) => eprintln!("mastersos-agent pam-session: browser sign-in: {e:#}"),
    }
}

fn boot_id() -> Result<String> {
    let s = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .context("reading the boot id")?;
    let id: String = s.trim().chars().filter(|c| *c != '-').collect();
    ensure!(
        valid_invocation(&id),
        "the boot id {s:?} is not 128 bits of hex"
    );
    Ok(id)
}

fn log(msg: impl std::fmt::Display) {
    let _ = writeln!(std::io::stderr(), "mastersos-agent signin-handoff: {msg}");
}

/// `mastersos-agent signin-handoff begin|stash <greeter user>` (the card unit, as root). `begin` exits 1 when it could not
/// clear what an earlier card left (the card must not start then); `stash` always exits 0.
pub fn handoff_main(mut args: impl Iterator<Item = OsString>) -> ExitCode {
    if !rustix::process::geteuid().is_root() {
        log("must run as root");
        return ExitCode::FAILURE;
    }
    let verb = args
        .next()
        .and_then(|v| v.into_string().ok())
        .unwrap_or_default();
    let instance = args
        .next()
        .and_then(|v| v.into_string().ok())
        .unwrap_or_default();
    let invocation = std::env::var("INVOCATION_ID").unwrap_or_default();
    let root = Path::new("/");
    let greeter = if valid_instance(&instance) {
        login::lookup_uid_checked(&instance)
    } else {
        None
    };
    match verb.as_str() {
        "begin" => {
            let url = match greeter.map(|uid| read_greeter_url(root, uid)) {
                Some(Ok(u)) => u,
                Some(Err(e)) => {
                    log(format!("not reading the card's URL: {e:#}"));
                    None
                }
                None => None,
            };
            match begin(root, 0, &instance, &invocation, url.as_deref()) {
                Ok(Some(_)) => ExitCode::SUCCESS,
                Ok(None) => {
                    log("this card has no email; nothing will be handed over");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    log(format!("cannot clear the last card's state: {e:#}"));
                    ExitCode::FAILURE
                }
            }
        }
        "stash" => {
            let Some(greeter) = greeter else {
                log(format!("unknown greeter user {instance:?}"));
                return ExitCode::SUCCESS;
            };
            let r = boot_id().and_then(|b| {
                stash(
                    root,
                    Owners { root: 0, greeter },
                    &b,
                    &instance,
                    &invocation,
                    now(),
                )
            });
            match r {
                Ok(Stashed::Delivered(uid)) => log(format!("handed to uid {uid}")),
                Ok(Stashed::NoCookies) => log("the card left no cookies"),
                Ok(_) => {}
                Err(e) => log(format!("{e:#}")),
            }
            ExitCode::SUCCESS
        }
        _ => {
            log("usage: signin-handoff begin|stash <greeter user>");
            ExitCode::FAILURE
        }
    }
}

/// `mastersos-agent signin-import` (the user unit): see [`import`].
pub fn import_main() -> ExitCode {
    import::main()
}

#[cfg(test)]
mod tests;
