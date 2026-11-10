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
//! - A keep item with a mount in its way (a mount point on another file system, or the errors such a mount gives:
//!   `EACCES` from a FUSE mount that refuses root, `ENOTCONN` from a dead one, `EBUSY`, `EXDEV`) is not kept: it
//!   stays in the old container and goes to the trash with it, the swap still happens and `container-busy` is
//!   recorded. Mounts are never followed or entered. Every other error stops that container without a swap.
//! - Top level: every other entry whose name starts with `.` goes to the trash, at most [`MAX_TOP_ENTRIES`] per run
//!   out of at most [`MAX_SCAN_ENTRIES`] dot entries read (and at most [`MAX_READ_ENTRIES`] entries read in all).
//!   Names that shells, PAM or the X session read at login ([`LOGIN_READ_TOP`]) are moved by name first, so junk
//!   entries beyond the caps cannot keep them alive. Entries not starting with `.` are the student's own files and
//!   are never touched.
//! - Every step goes through `*at` calls on directory fds with `O_NOFOLLOW`; links are moved as entries, never
//!   followed. Errors become a [`SkipReason`] and the next item is tried; they never carry names, paths or uids.

use std::ffi::{OsStr, OsString};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;

use rustix::fs::{AtFlags, Dev, FileType, Mode, Stat};
use rustix::io::Errno;

use std::path::Path;
use std::time::{Duration, Instant};

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

/// At most this many top-level dot entries are read per run. Entries not starting with `.` do not count, so many
/// ordinary files cannot hide the dot entries behind them. A normal home has a few dozen.
pub const MAX_SCAN_ENTRIES: usize = 100_000;

/// At most this many top-level entries (dot or not) are read per run, so a home with a huge number of files is not
/// read in full on every login.
pub const MAX_READ_ENTRIES: usize = 1_000_000;

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
    ".bash_aliases",
    ".asoundrc",
    ".gtkrc-2.0",
    ".gtkrc",
    ".mailcap",
    ".dmrc",
    ".Xmodmap",
    // gpg-agent.conf can name a program to run (pinentry-program).
    ".gnupg",
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
    /// The container is a mount point (or on another file system), or a mount is in the way of a keep item (that
    /// item is not kept).
    ContainerBusy,
    /// More than [`MAX_TOP_ENTRIES`] top-level dot entries to move, more than [`MAX_SCAN_ENTRIES`] dot entries or
    /// more than [`MAX_READ_ENTRIES`] entries in all; the rest wait for a later login.
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
            max_read: MAX_READ_ENTRIES,
        },
    )
}

/// The bounds of the top-level step (tests use small ones).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub max_top: usize,
    pub max_scan: usize,
    pub max_read: usize,
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
        if let Err(r) = tidy_container(home, &st, trash, uid, c, keep, &mut out) {
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

/// The errors a mount in the way gives: `EACCES` (a FUSE mount that refuses root), `ENOTCONN` (a FUSE mount whose
/// daemon is gone), `EBUSY` (a mount point cannot be renamed) and `EXDEV` (a rename across file systems).
fn mount_in_way(e: Errno) -> bool {
    matches!(
        e,
        Errno::ACCESS | Errno::NOTCONN | Errno::BUSY | Errno::XDEV
    )
}

/// Why one keep item could not be moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ItemErr {
    /// A mount is in the way: the item is not kept and the run goes on.
    Mount,
    /// Anything else: the container is left as it is (fail closed).
    Fatal,
}

fn item_err(e: Errno) -> ItemErr {
    if mount_in_way(e) {
        ItemErr::Mount
    } else {
        ItemErr::Fatal
    }
}

/// The OS error code inside an error from [`to_trash_entry_os`] or [`crate::safefs::exchange_at`].
fn errno_of(e: &anyhow::Error) -> Option<Errno> {
    e.chain()
        .filter_map(|c| c.downcast_ref::<std::io::Error>())
        .find_map(|io| io.raw_os_error())
        .map(Errno::from_raw_os_error)
}

/// `lstat` for the steps of one keep item: `None` when absent. An entry on another file system than `dev` is a
/// mount point (`lstat` reports the root of what is mounted there), so it is in the way.
fn item_stat(dir: &OwnedFd, name: &OsStr, dev: Dev) -> Result<Option<Stat>, ItemErr> {
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) if st.st_dev != dev => Err(ItemErr::Mount),
        Ok(st) => Ok(Some(st)),
        Err(Errno::NOENT) => Ok(None),
        Err(e) => Err(item_err(e)),
    }
}

/// [`open_seen`] for the steps of one keep item.
fn item_open(dir: &OwnedFd, name: &OsStr, st: &Stat) -> Result<OwnedFd, ItemErr> {
    let fd = rustix::fs::openat(dir, name, dir_flags(), Mode::empty()).map_err(item_err)?;
    let now = rustix::fs::fstat(&fd).map_err(item_err)?;
    if now.st_ino != st.st_ino || now.st_dev != st.st_dev {
        return Err(ItemErr::Fatal);
    }
    Ok(fd)
}

fn item_trash(dir: &OwnedFd, trash: &OwnedFd, name: &OsStr) -> Result<(), ItemErr> {
    match to_trash_entry_os(dir, trash, name) {
        Ok(_) => Ok(()),
        Err(e) => Err(errno_of(&e).map_or(ItemErr::Fatal, item_err)),
    }
}

/// Walk down existing real directories of the file system `dev` (no links followed). `None` when one is missing, a
/// link or not a directory.
fn item_descend(root: &OwnedFd, parents: &[&OsStr], dev: Dev) -> Result<Option<OwnedFd>, ItemErr> {
    let mut fd = root.try_clone().map_err(|_| ItemErr::Fatal)?;
    for p in parents {
        match item_stat(&fd, p, dev)? {
            Some(st) if is_dir(&st) => fd = item_open(&fd, p, &st)?,
            _ => return Ok(None),
        }
    }
    Ok(Some(fd))
}

/// Walk down, creating missing intermediate directories (owned by `uid:gid`, 0700). An intermediate that is a link
/// or not a directory is moved to the trash first.
fn item_descend_make(
    root: &OwnedFd,
    parents: &[&OsStr],
    trash: &OwnedFd,
    owner: (u32, u32),
    dev: Dev,
) -> Result<OwnedFd, ItemErr> {
    let (uid, gid) = owner;
    let mut fd = root.try_clone().map_err(|_| ItemErr::Fatal)?;
    for p in parents {
        fd = match item_stat(&fd, p, dev)? {
            Some(st) if is_dir(&st) => item_open(&fd, p, &st)?,
            Some(_) => {
                item_trash(&fd, trash, p)?;
                make_dir(&fd, p, uid, gid, 0o700)
                    .map_err(|_| ItemErr::Fatal)?
                    .0
            }
            None => {
                make_dir(&fd, p, uid, gid, 0o700)
                    .map_err(|_| ItemErr::Fatal)?
                    .0
            }
        };
    }
    Ok(fd)
}

#[cfg(test)]
thread_local! {
    /// Tests: every rename of a keep item whose leaf has this name fails with this error.
    static FAIL_LEAF: std::cell::RefCell<Option<(OsString, Errno)>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn fail_leaf(leaf: Option<(&str, Errno)>) {
    FAIL_LEAF.with(|f| *f.borrow_mut() = leaf.map(|(n, e)| (OsString::from(n), e)));
}

fn item_rename(from: &OwnedFd, leaf: &OsStr, to: &OwnedFd) -> Result<(), Errno> {
    #[cfg(test)]
    {
        let injected = FAIL_LEAF.with(|f| {
            f.borrow()
                .as_ref()
                .and_then(|(n, e)| (n.as_os_str() == leaf).then_some(*e))
        });
        if let Some(e) = injected {
            return Err(e);
        }
    }
    rename_new(from, leaf, to, leaf)
}

/// Move the keep item `path` from under `from_root` (on the file system `from_dev`) to the same place under
/// `to_root` (on `to_dev`); an entry already in its place is moved to the trash first. An absent item is not an
/// error. The one place that decides which errors are a mount in the way, for both [`fill`] and [`restore`].
fn move_item(
    from_root: &OwnedFd,
    to_root: &OwnedFd,
    path: &str,
    trash: &OwnedFd,
    owner: (u32, u32),
    devs: (Dev, Dev),
) -> Result<(), ItemErr> {
    let (from_dev, to_dev) = devs;
    let (parents, leaf) = split(path);
    let Some(from) = item_descend(from_root, &parents, from_dev)? else {
        return Ok(());
    };
    if item_stat(&from, leaf, from_dev)?.is_none() {
        return Ok(());
    }
    let to = item_descend_make(to_root, &parents, trash, owner, to_dev)?;
    if item_stat(&to, leaf, to_dev)?.is_some() {
        item_trash(&to, trash, leaf)?;
    }
    match item_rename(&from, leaf, &to) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(e) => Err(item_err(e)),
    }
}

/// Like [`lstat`], but the errors of a mount in the way (and an entry on another file system than `dev`) are
/// [`ContainerBusy`].
fn lstat_on(dir: &OwnedFd, name: &OsStr, dev: Dev) -> Result<Option<Stat>, SkipReason> {
    match item_stat(dir, name, dev) {
        Ok(st) => Ok(st),
        Err(ItemErr::Mount) => Err(ContainerBusy),
        Err(ItemErr::Fatal) => Err(Io),
    }
}

fn trash_top(home: &OwnedFd, trash: &OwnedFd, name: &OsStr) -> Result<(), SkipReason> {
    match item_trash(home, trash, name) {
        Ok(()) => Ok(()),
        Err(ItemErr::Mount) => Err(ContainerBusy),
        Err(ItemErr::Fatal) => Err(Io),
    }
}

/// Put the keep items found under the temporary directory back into the container `c` (an item of the same name in
/// the container is moved to the trash first), then move the temporary directory to the trash. Correct whether or
/// not the swap happened. A keep item with a mount in its way is left in the temporary directory (so it goes to the
/// trash with it) and `busy` is set. On any other error the temporary directory is left for the next login (it may
/// hold keep items).
fn restore(
    home: &OwnedFd,
    home_dev: Dev,
    trash: &OwnedFd,
    uid: u32,
    c: &str,
    keep: &[&str],
    busy: &mut bool,
) -> Result<(), SkipReason> {
    let temp = temp_name(c);
    let temp = OsStr::new(&temp);
    let c = OsStr::new(c);
    let Some(tst) = lstat_on(home, temp, home_dev)? else {
        return Ok(());
    };
    if !is_dir(&tst) {
        return trash_top(home, trash, temp);
    }
    let cfd = match lstat_on(home, c, home_dev)? {
        Some(st) if is_dir(&st) => {
            if st.st_uid != uid {
                return Err(ForeignContainer);
            }
            open_seen(home, c, &st)?
        }
        Some(_) => {
            trash_top(home, trash, c)?;
            make_dir(home, c, uid, tst.st_gid, 0o700)?.0
        }
        None => make_dir(home, c, uid, tst.st_gid, 0o700)?.0,
    };
    let gid = rustix::fs::fstat(&cfd).map_err(|_| Io)?.st_gid;
    let tfd = open_seen(home, temp, &tst)?;
    for path in keep {
        match move_item(&tfd, &cfd, path, trash, (uid, gid), (home_dev, home_dev)) {
            Ok(()) => {}
            Err(ItemErr::Mount) => *busy = true,
            Err(ItemErr::Fatal) => return Err(Io),
        }
    }
    trash_top(home, trash, temp)
}

fn tidy_container(
    home: &OwnedFd,
    home_st: &Stat,
    trash: &OwnedFd,
    uid: u32,
    c: &str,
    keep: &[&str],
    out: &mut Tidy,
) -> Result<(), SkipReason> {
    let home_dev = home_st.st_dev;
    let mut busy = false;
    let r = tidy_container_inner(
        home,
        home_dev,
        trash,
        uid,
        c,
        keep,
        &mut out.moved,
        &mut busy,
    );
    if busy {
        out.skipped.push(ContainerBusy);
    }
    r
}

#[allow(clippy::too_many_arguments)]
fn tidy_container_inner(
    home: &OwnedFd,
    home_dev: Dev,
    trash: &OwnedFd,
    uid: u32,
    c: &str,
    keep: &[&str],
    moved: &mut usize,
    busy: &mut bool,
) -> Result<(), SkipReason> {
    // Left over from an interrupted run (or planted): only keep items come out of it.
    restore(home, home_dev, trash, uid, c, keep, busy)?;
    let name = OsStr::new(c);
    let Some(st) = lstat_on(home, name, home_dev)? else {
        return Ok(());
    };
    if !is_dir(&st) {
        trash_top(home, trash, name)?;
        *moved += 1;
        return Ok(());
    }
    if st.st_uid != uid {
        return Err(ForeignContainer);
    }
    let cfd = open_seen(home, name, &st)?;
    let temp = temp_name(c);
    // Root-owned 0700 while it is being filled; it gets the container's owner and mode just before the swap.
    let me = rustix::process::geteuid().as_raw();
    let (tfd, _) = make_dir(home, OsStr::new(&temp), me, st.st_gid, 0o700)?;
    let mut result = fill(&cfd, &tfd, keep, trash, (uid, st.st_gid), home_dev, busy);
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
            Err(e) if errno_of(&e) == Some(Errno::BUSY) => Err(ContainerBusy),
            Err(_) => Err(Io),
        };
    }
    // After a swap the temporary name holds the old container: this trashes it (with any item a mount kept from
    // moving). Before one, this puts the keep items back. If the exchange reported an error after swapping (its
    // fsync), this is still right.
    let restored = restore(home, home_dev, trash, uid, c, keep, busy);
    result.and(restored)
}

/// Move the keep items of the container `cfd` into the temporary directory `tfd`. An item with a mount in its way is
/// left behind (not kept) and `busy` is set. Any other failure (other than an item being absent) stops: the caller
/// then restores without swapping, so a keep item is never lost to an unexpected error.
fn fill(
    cfd: &OwnedFd,
    tfd: &OwnedFd,
    keep: &[&str],
    trash: &OwnedFd,
    owner: (u32, u32),
    dev: Dev,
    busy: &mut bool,
) -> Result<(), SkipReason> {
    for path in keep {
        match move_item(cfd, tfd, path, trash, owner, (dev, dev)) {
            Ok(()) => {}
            Err(ItemErr::Mount) => *busy = true,
            Err(ItemErr::Fatal) => return Err(Io),
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
/// most `max_scan` dot entries and at most `max_read` entries read in all.
fn top_candidates(home: &OwnedFd, limits: Limits, out: &mut Tidy) -> Vec<OsString> {
    let mut names = Vec::new();
    let dir = match rustix::fs::Dir::read_from(home) {
        Ok(d) => d,
        Err(_) => {
            out.skipped.push(Io);
            return names;
        }
    };
    let mut dots = 0usize;
    for (read, e) in dir.enumerate() {
        if read == limits.max_read {
            out.skipped.push(TooManyEntries);
            break;
        }
        let Ok(e) = e else {
            out.skipped.push(Io);
            break;
        };
        let name = e.file_name().to_bytes();
        if !name.starts_with(b".") {
            continue;
        }
        if dots == limits.max_scan {
            out.skipped.push(TooManyEntries);
            break;
        }
        dots = dots.saturating_add(1);
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

/// The whole login hook runs no command and does not start the tidy after this long from its start.
pub const LOGIN_DEADLINE: Duration = Duration::from_secs(10);

/// How long [`prepare_user_manager`] waits for stopped leftovers to be gone, and how often it looks.
const GONE_WAIT: Duration = Duration::from_secs(3);
const GONE_POLL: Duration = Duration::from_millis(200);

/// The time source of the login hook (tests use a fake one, so nothing really sleeps).
pub(crate) trait Clock {
    fn now(&self) -> Instant;
    fn sleep(&self, d: Duration);
}

pub(crate) struct RealClock;

impl Clock for RealClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// The point after which the login hook starts nothing more. Every command gets the smaller of
/// [`PAM_CMD_TIMEOUT`] and the time left, so the last one also ends by then (plus the runner's grace for a process
/// that ignores SIGTERM).
pub(crate) struct Deadline<'a> {
    clock: &'a dyn Clock,
    end: Option<Instant>,
}

impl<'a> Deadline<'a> {
    pub(crate) fn new(clock: &'a dyn Clock, within: Duration) -> Self {
        Deadline {
            clock,
            end: clock.now().checked_add(within),
        }
    }

    /// The time left; `None` once it has passed.
    fn left(&self) -> Option<Duration> {
        let d = self.end?.saturating_duration_since(self.clock.now());
        (!d.is_zero()).then_some(d)
    }

    /// The command with its time limit; `None` once the deadline has passed.
    fn cmd(&self, program: &str, args: &[&str]) -> Option<Cmd> {
        let left = self.left()?;
        Some(Cmd::new(program, args).timeout(left.min(PAM_CMD_TIMEOUT)))
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
    /// The login hook's deadline passed.
    OutOfTime,
}

/// `loginctl` failing because the user is not known (not logged in and not lingering).
fn not_logged_in(stderr: &str) -> bool {
    stderr.contains("not logged in") || stderr.contains("No such")
}

/// Before the home is tidied at login: end what a previous session left behind (a `closing` session with stray
/// processes, or a lingering `user@<uid>.service`). Live sessions (`active`, `online`, `opening`) are left alone.
/// Leftovers are ended with `disable-linger`, `kill-user --signal=SIGKILL` (stop jobs of the user's units and
/// processes that ignore SIGTERM would otherwise hold things up for minutes), `terminate-user` and
/// `systemctl stop user@<uid>.service`; their exit codes decide nothing. `Proceed` comes only from seeing the
/// user gone afterwards (polled for [`GONE_WAIT`]). Never reports names or uids.
pub(crate) fn prepare_user_manager(runner: &dyn Runner, uid: u32, dl: &Deadline) -> Prep {
    let id = uid.to_string();
    let Some(cmd) = dl.cmd("loginctl", &["show-user", &id, "-p", "State", "--value"]) else {
        return Prep::OutOfTime;
    };
    let out = match runner.run(&cmd) {
        Ok(o) => o,
        Err(_) => return Prep::Failed,
    };
    if out.code != 0 {
        return if not_logged_in(&out.stderr) {
            Prep::Proceed
        } else {
            Prep::Failed
        };
    }
    match out.stdout.trim() {
        "active" | "online" | "opening" => Prep::SkipActive,
        "offline" => Prep::Proceed,
        "closing" | "lingering" => end_leftovers(runner, uid, &id, dl),
        _ => Prep::Failed,
    }
}

fn end_leftovers(runner: &dyn Runner, uid: u32, id: &str, dl: &Deadline) -> Prep {
    let unit = format!("user@{id}.service");
    let steps: [(&str, Vec<&str>); 4] = [
        ("loginctl", vec!["disable-linger", id]),
        ("loginctl", vec!["kill-user", "--signal=SIGKILL", id]),
        ("loginctl", vec!["terminate-user", id]),
        ("systemctl", vec!["stop", &unit]),
    ];
    for (program, args) in &steps {
        let Some(cmd) = dl.cmd(program, args) else {
            return Prep::OutOfTime;
        };
        // kill-user fails when nothing is left to kill, stop can time out on a dying unit: only the check below counts.
        let _ = runner.run(&cmd);
    }
    let until = dl.clock.now().checked_add(GONE_WAIT);
    loop {
        match user_gone(runner, uid, id, dl) {
            None => return Prep::OutOfTime,
            Some(true) => return Prep::Proceed,
            Some(false) => {}
        }
        match (until, dl.left()) {
            (Some(u), Some(left)) if dl.clock.now() < u => dl.clock.sleep(GONE_POLL.min(left)),
            (_, None) => return Prep::OutOfTime,
            _ => return Prep::Failed,
        }
    }
}

/// Whether logind no longer knows the user: primarily the user is absent from `loginctl list-users` (output that
/// does not parse, or a failure, does not count); otherwise `show-user` failing with "not logged in" or reading
/// `offline`. `None` once the deadline has passed.
fn user_gone(runner: &dyn Runner, uid: u32, id: &str, dl: &Deadline) -> Option<bool> {
    let cmd = dl.cmd("loginctl", &["list-users", "--no-legend", "--json=short"])?;
    if let Ok(o) = runner.run(&cmd) {
        if o.code == 0 && !crate::runner::was_cut(&o.stdout) {
            if let Ok(users) = lock::parse_users(&o.stdout) {
                return Some(!users.iter().any(|u| u.uid == uid));
            }
        }
    }
    let cmd = dl.cmd("loginctl", &["show-user", id, "-p", "State", "--value"])?;
    Some(match runner.run(&cmd) {
        Ok(o) if o.code != 0 => not_logged_in(&o.stderr),
        Ok(o) => o.stdout.trim() == "offline",
        Err(_) => false,
    })
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

/// What the latest login hook did. `outcome` is `tidied`, `skipped-active`, `prepare-failed`, `deadline` (the hook
/// ran out of time, see [`LOGIN_DEADLINE`]) or `not-a-home`; `skipped` holds [`SkipReason::name`]s. Nothing here
/// identifies a person or a path.
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

/// Whether the passwd record of `user` (with uid `uid`) says its home is exactly `/home/<user>`; `None` once the
/// deadline has passed.
fn home_is_standard(runner: &dyn Runner, user: &str, uid: u32, dl: &Deadline) -> Option<bool> {
    if user.is_empty() || user.contains('/') || user.starts_with('.') {
        return Some(false);
    }
    let id = uid.to_string();
    let cmd = dl.cmd("getent", &["passwd", "--", user])?;
    let Ok(out) = runner.run(&cmd) else {
        return Some(false);
    };
    if out.code != 0 {
        return Some(false);
    }
    let Some(line) = out.stdout.lines().next() else {
        return Some(false);
    };
    let f: Vec<&str> = line.split(':').collect();
    let home = format!("/home/{user}");
    Some(
        f.first() == Some(&user)
            && f.get(2) == Some(&id.as_str())
            && f.get(5) == Some(&home.as_str()),
    )
}

fn tidy_for_login(
    paths: &SysPaths,
    runner: &dyn Runner,
    user: &str,
    uid: u32,
    dl: &Deadline,
) -> LastTidy {
    match home_is_standard(runner, user, uid, dl) {
        None => return outcome("deadline"),
        Some(false) => return outcome("not-a-home"),
        Some(true) => {}
    }
    match prepare_user_manager(runner, uid, dl) {
        Prep::SkipActive => return outcome("skipped-active"),
        Prep::Failed => return outcome("prepare-failed"),
        Prep::OutOfTime => return outcome("deadline"),
        Prep::Proceed => {}
    }
    if dl.left().is_none() {
        return outcome("deadline");
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

/// The root PAM login hook for `user`: in learning mode tidy the home before the session starts. Must not panic by
/// construction (release builds are `panic = "abort"` and the hook is `session requisite`, see `system/mod.rs`): it
/// has no `unwrap`, indexing or unchecked arithmetic, and every error only shows in the result file (or not at
/// all) while the login goes on. In full mode (or without a session mode) nothing is read from the home, written
/// or run. It starts nothing after [`LOGIN_DEADLINE`]: the worst case is that deadline, plus the runner's
/// SIGTERM grace (5 s) for a last command that ignores SIGTERM, plus the tidy itself (bounded by entry counts).
pub fn on_login(paths: &SysPaths, runner: &dyn Runner, user: &str, uid: u32) {
    on_login_with(paths, runner, &RealClock, user, uid);
}

pub(crate) fn on_login_with(
    paths: &SysPaths,
    runner: &dyn Runner,
    clock: &dyn Clock,
    user: &str,
    uid: u32,
) {
    if !tidy_decision(&paths.public_dir) {
        return;
    }
    let dl = Deadline::new(clock, LOGIN_DEADLINE);
    let t = tidy_for_login(paths, runner, user, uid, &dl);
    let _ = write_result(paths, &t);
}

#[cfg(test)]
mod tests;
