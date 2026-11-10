//! Tidying a learning-mode home directory before login (spec invariant 2): keep only what is on the keep list,
//! move everything else into the trash directory under `/home` (see [`crate::homes::trash`]), which the existing
//! cleanup job deletes later. Nothing is deleted recursively here.
//!
//! - Containers ([`CONTAINERS`]): a fresh temporary directory `.mastersos-tidy<container>` is created, the keep
//!   items are renamed into it, it gets the container's owner and permissions, and it is swapped with the container
//!   (`RENAME_EXCHANGE`, atomic). The old container, now under the temporary name, goes to the trash. The cost depends
//!   only on the length of the keep list, not on how much the student put into the container.
//! - Interruption: whatever state a temporary directory was left in, [`restore`] puts its keep items back into the
//!   container and trashes the rest; it runs before every swap, after a failed swap and after a successful one (where
//!   the temporary name holds the old container, which has no keep items left).
//! - Top level: every other entry whose name starts with `.` goes to the trash, at most [`MAX_TOP_ENTRIES`] per run
//!   out of at most [`MAX_SCAN_ENTRIES`] entries read. Names that shells, PAM or the X session read at login
//!   ([`LOGIN_READ_TOP`]) are moved by name first, so junk entries beyond the caps cannot keep them alive.
//!   Entries not starting with `.` are the student's own files and are never touched.
//! - Every step goes through `*at` calls on directory fds with `O_NOFOLLOW`; links are moved as entries, never
//!   followed. Errors become a [`SkipReason`] and the next item is tried; they never carry names, paths or uids.

use std::ffi::{OsStr, OsString};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;

use rustix::fs::{AtFlags, FileType, Mode, Stat};
use rustix::io::Errno;

use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::homes::trash::to_trash_entry_os;
use crate::runner::{Cmd, Runner};
use crate::safefs::bounded::dir_flags;
use crate::system::ephemeral::PAM_CMD_TIMEOUT;
use crate::system::lock::{self, LOGIN_CMD_TIMEOUT};
use crate::system::{exec_block, SysPaths};

/// Top-level dot entries that are kept as they are (none: `.pki` is a container, see [`CONTAINERS`]).
pub const KEEP_TOP: &[&str] = &[];

/// Containers that are swapped for a fresh directory holding only these items (paths relative to the container).
pub const CONTAINERS: &[(&str, &[&str])] = &[
    (
        ".config",
        &[
            // Chrome profile: bookmarks, sign-in, extensions (Chrome itself is governed by enterprise policy).
            "google-chrome",
            // The user's dconf database (wallpaper, language, input methods); keys that must be fixed are locked by the system.
            "dconf",
            // External monitor layout and scaling.
            "monitors.xml",
            // Bookmarks in the file chooser sidebar.
            "gtk-3.0/bookmarks",
        ],
    ),
    (
        ".cache",
        &[
            // Chrome's cache only, so it is not downloaded again on every login.
            "google-chrome",
        ],
    ),
    (
        ".local",
        &[
            // Keyrings (saved passwords).
            "share/keyrings",
            // Volume and default output device.
            "state/wireplumber",
        ],
    ),
    (
        ".var",
        &[
            // Data of the Flatpak apps the school installed.
            "app",
        ],
    ),
    (
        ".pki",
        &[
            // Chrome's certificate store (NSS database); pkcs11.txt is not kept: it loads modules into Chrome.
            "nssdb/cert9.db",
            // Chrome's private keys for client certificates (NSS database).
            "nssdb/key4.db",
        ],
    ),
];

/// At most this many top-level dot entries are moved per run.
pub const MAX_TOP_ENTRIES: usize = 10_000;

/// At most this many top-level entries are read per run, every entry counting (dot or not), so a home with very
/// many files is not read in full on every login. A normal home has a few dozen.
pub const MAX_SCAN_ENTRIES: usize = 100_000;

/// Top-level names that shells, PAM or the X session read at login (they run code or set the environment). They are
/// moved by name before the scan, so the caps cannot be gamed to keep them.
const LOGIN_READ_TOP: &[&str] = &[
    ".profile",
    ".bash_profile",
    ".bash_login",
    ".bashrc",
    ".bash_logout",
    ".pam_environment",
    ".xprofile",
    ".xsession",
    ".xsessionrc",
    ".xinitrc",
    ".xinputrc",
    ".Xresources",
    ".Xdefaults",
    ".gnomerc",
    ".zshenv",
    ".zprofile",
    ".zshrc",
    ".zlogin",
    ".zlogout",
    ".login",
    ".logout",
    ".cshrc",
    ".tcshrc",
    ".kshrc",
    ".mkshrc",
    ".inputrc",
];

/// Prefix of a container's temporary directory (`.mastersos-tidy.config` for `.config`).
const TEMP_PREFIX: &str = ".mastersos-tidy";

/// What one run did. `moved` counts top-level entries moved to the trash (dot entries, and containers that were
/// links or not directories); the routine swap of a container is not counted, so a clean home gives 0.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tidy {
    pub moved: usize,
    pub skipped: Vec<SkipReason>,
}

/// Why an item was skipped (reason categories only: reports must not carry names).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The home directory or a container is not owned by the user.
    ForeignContainer,
    /// The container is a mount point (or on another file system).
    ContainerBusy,
    /// More than [`MAX_TOP_ENTRIES`] top-level dot entries, or more than [`MAX_SCAN_ENTRIES`] entries in all; the
    /// rest wait for the next login.
    TooManyEntries,
    /// Any other error.
    Io,
}

use SkipReason::*;

impl SkipReason {
    /// The kebab-case name used in the reported result (a category only, never a name or path).
    pub fn name(self) -> &'static str {
        match self {
            ForeignContainer => "foreign-container",
            ContainerBusy => "container-busy",
            TooManyEntries => "too-many-entries",
            Io => "io",
        }
    }
}

/// Tidy the home directory `home` of `uid`, moving what is not kept into `trash`. Never fails as a whole: every
/// error is recorded as a [`SkipReason`] and the next item is tried.
pub fn tidy_home(home: &OwnedFd, trash: &OwnedFd, uid: u32) -> Tidy {
    tidy_home_limited(
        home,
        trash,
        uid,
        Limits {
            max_top: MAX_TOP_ENTRIES,
            max_scan: MAX_SCAN_ENTRIES,
        },
    )
}

/// The bounds of the top-level step (tests use small ones).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub max_top: usize,
    pub max_scan: usize,
}

pub(crate) fn tidy_home_limited(home: &OwnedFd, trash: &OwnedFd, uid: u32, limits: Limits) -> Tidy {
    let mut out = Tidy::default();
    let st = match rustix::fs::fstat(home) {
        Ok(st) => st,
        Err(_) => {
            out.skipped.push(Io);
            return out;
        }
    };
    if !is_dir(&st) || st.st_uid != uid {
        out.skipped.push(ForeignContainer);
        return out;
    }
    for (c, keep) in CONTAINERS {
        if let Err(r) = tidy_container(home, &st, trash, uid, c, keep, &mut out.moved) {
            out.skipped.push(r);
        }
    }
    tidy_top(home, trash, limits, &mut out);
    out
}

fn temp_name(c: &str) -> String {
    format!("{TEMP_PREFIX}{c}")
}

fn is_dir(st: &Stat) -> bool {
    FileType::from_raw_mode(st.st_mode) == FileType::Directory
}

fn lstat(dir: &OwnedFd, name: &OsStr) -> Result<Option<Stat>, SkipReason> {
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => Ok(Some(st)),
        Err(Errno::NOENT) => Ok(None),
        Err(_) => Err(Io),
    }
}

/// Open the real directory `name` (`O_NOFOLLOW`) and check it is the one `st` describes.
fn open_seen(dir: &OwnedFd, name: &OsStr, st: &Stat) -> Result<OwnedFd, SkipReason> {
    let fd = rustix::fs::openat(dir, name, dir_flags(), Mode::empty()).map_err(|_| Io)?;
    let now = rustix::fs::fstat(&fd).map_err(|_| Io)?;
    if now.st_ino != st.st_ino || now.st_dev != st.st_dev {
        return Err(Io);
    }
    Ok(fd)
}

/// Create the new directory `name` (it must not exist), owned by `uid:gid` with `mode`. Ownership and mode are set
/// through the fd of the directory we created (checked to be ours, so a link or a planted directory is refused).
fn make_dir(
    dir: &OwnedFd,
    name: &OsStr,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(OwnedFd, Stat), SkipReason> {
    rustix::fs::mkdirat(dir, name, Mode::from_raw_mode(0o700)).map_err(|_| Io)?;
    let fd = rustix::fs::openat(dir, name, dir_flags(), Mode::empty()).map_err(|_| Io)?;
    let st = rustix::fs::fstat(&fd).map_err(|_| Io)?;
    if st.st_uid != rustix::process::geteuid().as_raw() {
        return Err(Io);
    }
    rustix::fs::fchown(
        &fd,
        Some(rustix::fs::Uid::from_raw(uid)),
        Some(rustix::fs::Gid::from_raw(gid)),
    )
    .map_err(|_| Io)?;
    rustix::fs::fchmod(&fd, Mode::from_raw_mode(mode)).map_err(|_| Io)?;
    let st = rustix::fs::fstat(&fd).map_err(|_| Io)?;
    Ok((fd, st))
}

fn trash_entry(dir: &OwnedFd, trash: &OwnedFd, name: &OsStr) -> Result<(), SkipReason> {
    to_trash_entry_os(dir, trash, name)
        .map(|_| ())
        .map_err(|_| Io)
}

/// `renameat` that never replaces an existing entry.
fn rename_new(from_dir: &OwnedFd, from: &OsStr, to_dir: &OwnedFd, to: &OsStr) -> Result<(), Errno> {
    #[cfg(target_os = "linux")]
    {
        rustix::fs::renameat_with(
            from_dir,
            from,
            to_dir,
            to,
            rustix::fs::RenameFlags::NOREPLACE,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        match rustix::fs::statat(to_dir, to, AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => rustix::fs::renameat(from_dir, from, to_dir, to),
            Ok(_) => Err(Errno::EXIST),
            Err(e) => Err(e),
        }
    }
}

/// Split a keep path into its intermediate directories and its leaf.
fn split(path: &str) -> (Vec<&OsStr>, &OsStr) {
    let mut parts: Vec<&OsStr> = path.split('/').map(OsStr::new).collect();
    let leaf = parts.pop().unwrap_or_default();
    (parts, leaf)
}

/// Walk down existing real directories (no links followed). `None` when one is missing, a link or not a directory.
fn descend(root: &OwnedFd, parents: &[&OsStr]) -> Result<Option<OwnedFd>, SkipReason> {
    let mut fd = root.try_clone().map_err(|_| Io)?;
    for p in parents {
        match lstat(&fd, p)? {
            Some(st) if is_dir(&st) => fd = open_seen(&fd, p, &st)?,
            _ => return Ok(None),
        }
    }
    Ok(Some(fd))
}

/// Walk down, creating missing intermediate directories (owned by `uid:gid`, 0700). An intermediate that is a link
/// or not a directory is moved to the trash first.
fn descend_make(
    root: &OwnedFd,
    parents: &[&OsStr],
    trash: &OwnedFd,
    uid: u32,
    gid: u32,
) -> Result<OwnedFd, SkipReason> {
    let mut fd = root.try_clone().map_err(|_| Io)?;
    for p in parents {
        fd = match lstat(&fd, p)? {
            Some(st) if is_dir(&st) => open_seen(&fd, p, &st)?,
            Some(_) => {
                trash_entry(&fd, trash, p)?;
                make_dir(&fd, p, uid, gid, 0o700)?.0
            }
            None => make_dir(&fd, p, uid, gid, 0o700)?.0,
        };
    }
    Ok(fd)
}

/// Put the keep items found under the temporary directory back into the container `c` (an item of the same name in
/// the container is moved to the trash first), then move the temporary directory to the trash. Correct whether or
/// not the swap happened. On error the temporary directory is left for the next login (it may hold keep items).
fn restore(
    home: &OwnedFd,
    trash: &OwnedFd,
    uid: u32,
    c: &str,
    keep: &[&str],
) -> Result<(), SkipReason> {
    let temp = temp_name(c);
    let temp = OsStr::new(&temp);
    let c = OsStr::new(c);
    let Some(tst) = lstat(home, temp)? else {
        return Ok(());
    };
    if !is_dir(&tst) {
        return trash_entry(home, trash, temp);
    }
    let cfd = match lstat(home, c)? {
        Some(st) if is_dir(&st) => {
            if st.st_uid != uid {
                return Err(ForeignContainer);
            }
            open_seen(home, c, &st)?
        }
        Some(_) => {
            trash_entry(home, trash, c)?;
            make_dir(home, c, uid, tst.st_gid, 0o700)?.0
        }
        None => make_dir(home, c, uid, tst.st_gid, 0o700)?.0,
    };
    let gid = rustix::fs::fstat(&cfd).map_err(|_| Io)?.st_gid;
    let tfd = open_seen(home, temp, &tst)?;
    for path in keep {
        let (parents, leaf) = split(path);
        let Some(from) = descend(&tfd, &parents)? else {
            continue;
        };
        if lstat(&from, leaf)?.is_none() {
            continue;
        }
        let to = descend_make(&cfd, &parents, trash, uid, gid)?;
        if lstat(&to, leaf)?.is_some() {
            trash_entry(&to, trash, leaf)?;
        }
        match rename_new(&from, leaf, &to, leaf) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(_) => return Err(Io),
        }
    }
    trash_entry(home, trash, temp)
}

fn is_busy(e: &anyhow::Error) -> bool {
    e.chain()
        .filter_map(|c| c.downcast_ref::<std::io::Error>())
        .any(|io| io.raw_os_error() == Some(Errno::BUSY.raw_os_error()))
}

fn tidy_container(
    home: &OwnedFd,
    home_st: &Stat,
    trash: &OwnedFd,
    uid: u32,
    c: &str,
    keep: &[&str],
    moved: &mut usize,
) -> Result<(), SkipReason> {
    // Left over from an interrupted run (or planted): only keep items come out of it.
    restore(home, trash, uid, c, keep)?;
    let name = OsStr::new(c);
    let Some(st) = lstat(home, name)? else {
        return Ok(());
    };
    if !is_dir(&st) {
        trash_entry(home, trash, name)?;
        *moved += 1;
        return Ok(());
    }
    if st.st_uid != uid {
        return Err(ForeignContainer);
    }
    if st.st_dev != home_st.st_dev {
        return Err(ContainerBusy);
    }
    let cfd = open_seen(home, name, &st)?;
    let temp = temp_name(c);
    // Root-owned 0700 while it is being filled; it gets the container's owner and mode just before the swap.
    let me = rustix::process::geteuid().as_raw();
    let (tfd, _) = make_dir(home, OsStr::new(&temp), me, st.st_gid, 0o700)?;
    let mut result = fill(&cfd, &tfd, keep, trash, uid, st.st_gid);
    if result.is_ok() {
        result = rustix::fs::fchown(
            &tfd,
            Some(rustix::fs::Uid::from_raw(uid)),
            Some(rustix::fs::Gid::from_raw(st.st_gid)),
        )
        .and_then(|()| rustix::fs::fchmod(&tfd, Mode::from_raw_mode(st.st_mode & 0o777)))
        .map_err(|_| Io);
    }
    drop((cfd, tfd));
    if result.is_ok() {
        result = match crate::safefs::exchange_at(home, c, &temp) {
            Ok(()) => Ok(()),
            Err(e) if is_busy(&e) => Err(ContainerBusy),
            Err(_) => Err(Io),
        };
    }
    // After a swap the temporary name holds the old container: this trashes it. Before one, this puts the keep
    // items back. If the exchange reported an error after swapping (its fsync), this is still right.
    let restored = restore(home, trash, uid, c, keep);
    result.and(restored)
}

/// Move the keep items of the container `cfd` into the temporary directory `tfd`. Any failure (other than an item
/// being absent) stops: the caller then restores, so a keep item is never left behind in the old container.
fn fill(
    cfd: &OwnedFd,
    tfd: &OwnedFd,
    keep: &[&str],
    trash: &OwnedFd,
    uid: u32,
    gid: u32,
) -> Result<(), SkipReason> {
    for path in keep {
        let (parents, leaf) = split(path);
        let Some(from) = descend(cfd, &parents)? else {
            continue;
        };
        if lstat(&from, leaf)?.is_none() {
            continue;
        }
        let to = descend_make(tfd, &parents, trash, uid, gid)?;
        match rename_new(&from, leaf, &to, leaf) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(_) => return Err(Io),
        }
    }
    Ok(())
}

/// Whether a top-level name is moved by the scan: it starts with `.`, and is not kept, already tried by name
/// ([`LOGIN_READ_TOP`]), a container or a temporary directory (those are handled, and on failure deliberately left,
/// by the container step).
fn is_candidate(name: &[u8]) -> bool {
    if !name.starts_with(b".") || name == b"." || name == b".." {
        return false;
    }
    if KEEP_TOP
        .iter()
        .chain(LOGIN_READ_TOP)
        .any(|k| k.as_bytes() == name)
    {
        return false;
    }
    !CONTAINERS
        .iter()
        .any(|(c, _)| c.as_bytes() == name || temp_name(c).as_bytes() == name)
}

/// Read the candidates (raw bytes: a non-UTF-8 name must not stop the step): at most `max_top` of them out of at
/// most `max_scan` entries read.
fn top_candidates(home: &OwnedFd, limits: Limits, out: &mut Tidy) -> Vec<OsString> {
    let mut names = Vec::new();
    let dir = match rustix::fs::Dir::read_from(home) {
        Ok(d) => d,
        Err(_) => {
            out.skipped.push(Io);
            return names;
        }
    };
    for (read, e) in dir.enumerate() {
        if read == limits.max_scan {
            out.skipped.push(TooManyEntries);
            break;
        }
        let Ok(e) = e else {
            out.skipped.push(Io);
            break;
        };
        let name = e.file_name().to_bytes();
        if !is_candidate(name) {
            continue;
        }
        if names.len() == limits.max_top {
            out.skipped.push(TooManyEntries);
            break;
        }
        names.push(OsStr::from_bytes(name).to_os_string());
    }
    names
}

fn tidy_top(home: &OwnedFd, trash: &OwnedFd, limits: Limits, out: &mut Tidy) {
    for name in LOGIN_READ_TOP {
        match lstat(home, OsStr::new(name)) {
            Ok(None) => {}
            Ok(Some(_)) => match to_trash_entry_os(home, trash, OsStr::new(name)) {
                Ok(_) => out.moved += 1,
                Err(_) => out.skipped.push(Io),
            },
            Err(r) => out.skipped.push(r),
        }
    }
    // Names are collected first and moved afterwards, so renaming does not disturb the directory read.
    for name in top_candidates(home, limits, out) {
        match to_trash_entry_os(home, trash, &name) {
            Ok(_) => out.moved += 1,
            Err(_) => out.skipped.push(Io),
        }
    }
}

/// What [`prepare_user_manager`] found. Only `Proceed` lets the home be tidied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prep {
    /// No live session and no user manager left: tidy now.
    Proceed,
    /// The same person is logged in elsewhere (or a session is opening): moving files under it would break it.
    SkipActive,
    /// A leftover could not be ended, or the state could not be read.
    Failed,
}

fn pam_cmd(program: &str, args: &[&str]) -> Cmd {
    Cmd::new(program, args).timeout(PAM_CMD_TIMEOUT)
}

/// Before the home is tidied at login: end what a previous session left behind (a `closing` session with stray
/// processes, or a lingering `user@<uid>.service`). Every command is limited to [`PAM_CMD_TIMEOUT`]. Live sessions
/// (`active`, `online`, `opening`) are left alone. Never reports names or uids.
pub fn prepare_user_manager(runner: &dyn Runner, uid: u32) -> Prep {
    let id = uid.to_string();
    let out = match runner.run(&pam_cmd(
        "loginctl",
        &["show-user", &id, "-p", "State", "--value"],
    )) {
        Ok(o) => o,
        Err(_) => return Prep::Failed,
    };
    if out.code != 0 {
        let gone = out.stderr.contains("not logged in") || out.stderr.contains("No such");
        return if gone { Prep::Proceed } else { Prep::Failed };
    }
    match out.stdout.trim() {
        "active" | "online" | "opening" => Prep::SkipActive,
        "offline" => Prep::Proceed,
        "closing" | "lingering" => {
            let unit = format!("user@{id}.service");
            let steps: [(&str, Vec<&str>); 3] = [
                ("loginctl", vec!["disable-linger", &id]),
                ("loginctl", vec!["terminate-user", &id]),
                ("systemctl", vec!["stop", &unit]),
            ];
            for (program, args) in &steps {
                match runner.run(&pam_cmd(program, args)) {
                    Ok(o) if o.code == 0 => {}
                    _ => return Prep::Failed,
                }
            }
            Prep::Proceed
        }
        _ => Prep::Failed,
    }
}

/// Learning mode: switch off linger for every person account that is not an administrator (case-insensitive), so no
/// user manager starts at boot before anyone logs in. All of them are tried; failures are reported as a count only.
pub fn linger_off_for_students(runner: &dyn Runner, admins: &[String]) -> Result<()> {
    let users = lock::parse_users(&lock::list_users(runner)?)?;
    let mut failed = 0usize;
    for u in users
        .iter()
        .filter(|u| u.linger && lock::is_person(u))
        .filter(|u| !admins.iter().any(|a| a.eq_ignore_ascii_case(&u.user)))
    {
        let id = u.uid.to_string();
        let cmd = Cmd::new("loginctl", &["disable-linger", &id]).timeout(LOGIN_CMD_TIMEOUT);
        match runner.run(&cmd) {
            Ok(o) if o.code == 0 => {}
            _ => failed += 1,
        }
    }
    if failed > 0 {
        anyhow::bail!("disable linger failed for {failed} account(s)");
    }
    Ok(())
}

/// The latest login's result, in `var_dir` (0600, overwritten each time); the `desktop` step reports it.
pub const RESULT_FILE: &str = "home-tidy.json";

/// What the latest login hook did. `outcome` is `tidied`, `skipped-active`, `prepare-failed` or `not-a-home`;
/// `skipped` holds [`SkipReason::name`]s. Nothing here identifies a person or a path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastTidy {
    pub at: u64,
    pub moved: usize,
    pub skipped: Vec<String>,
    pub outcome: String,
}

/// Whether logins are tidied: the session is locked (learning), see [`exec_block::session_mode_locked`].
pub fn tidy_decision(public_dir: &Path) -> bool {
    exec_block::session_mode_locked(public_dir)
}

fn outcome(name: &str) -> LastTidy {
    LastTidy {
        at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        moved: 0,
        skipped: Vec::new(),
        outcome: name.to_string(),
    }
}

/// True when the passwd record of `user` (with uid `uid`) says its home is exactly `/home/<user>`.
fn home_is_standard(runner: &dyn Runner, user: &str, uid: u32) -> bool {
    let id = uid.to_string();
    let Ok(out) = runner.run(&pam_cmd("getent", &["passwd", "--", user])) else {
        return false;
    };
    if out.code != 0 {
        return false;
    }
    let Some(line) = out.stdout.lines().next() else {
        return false;
    };
    let f: Vec<&str> = line.split(':').collect();
    f.len() >= 6 && f[0] == user && f[2] == id && f[5] == format!("/home/{user}")
}

fn tidy_for_login(paths: &SysPaths, runner: &dyn Runner, user: &str, uid: u32) -> LastTidy {
    if !home_is_standard(runner, user, uid) {
        return outcome("not-a-home");
    }
    match prepare_user_manager(runner, uid) {
        Prep::SkipActive => return outcome("skipped-active"),
        Prep::Failed => return outcome("prepare-failed"),
        Prep::Proceed => {}
    }
    let inner = || -> Result<Option<Tidy>> {
        let root = crate::safefs::open_abs_dir(&paths.root.join("home"), false)?;
        let Some(home) = crate::safefs::open_child_dir(&root, user)? else {
            return Ok(None);
        };
        let Some(trash) = crate::homes::trash::open_trash(&root, true)? else {
            return Ok(None);
        };
        Ok(Some(tidy_home(&home, &trash, uid)))
    };
    match inner() {
        // No home yet (it is created later in the login): nothing to tidy.
        Ok(None) => outcome("tidied"),
        Ok(Some(t)) => LastTidy {
            moved: t.moved,
            skipped: t.skipped.iter().map(|r| r.name().to_string()).collect(),
            ..outcome("tidied")
        },
        Err(_) => LastTidy {
            skipped: vec![Io.name().to_string()],
            ..outcome("tidied")
        },
    }
}

fn write_result(paths: &SysPaths, t: &LastTidy) -> Result<()> {
    let dir = crate::system::var_dir(paths)?;
    crate::safefs::write_at(&dir, RESULT_FILE, &serde_json::to_vec(t)?, 0o600)?;
    Ok(())
}

/// The root PAM login hook for `user`: in learning mode tidy the home before the session starts. Never fails and
/// never panics: any problem only shows in the result file (or not at all), and the login goes on. In full mode
/// (or without a session mode) nothing is read from the home, written or run.
pub fn on_login(paths: &SysPaths, runner: &dyn Runner, user: &str, uid: u32) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if !tidy_decision(&paths.public_dir) {
            return;
        }
        let t = tidy_for_login(paths, runner, user, uid);
        let _ = write_result(paths, &t);
    }));
}

#[cfg(test)]
mod tests;
