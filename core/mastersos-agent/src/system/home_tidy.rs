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
//! - Top level: every other entry whose name starts with `.` goes to the trash, at most [`MAX_TOP_ENTRIES`] per run.
//!   Entries not starting with `.` are the student's own files and are never touched.
//! - Every step goes through `*at` calls on directory fds with `O_NOFOLLOW`; links are moved as entries, never
//!   followed. Errors become a [`SkipReason`] and the next item is tried; they never carry names, paths or uids.

use std::ffi::{OsStr, OsString};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;

use rustix::fs::{AtFlags, FileType, Mode, Stat};
use rustix::io::Errno;

use crate::homes::trash::to_trash_entry_os;
use crate::safefs::bounded::dir_flags;

/// Top-level dot entries that are kept as they are.
pub const KEEP_TOP: &[&str] = &[
    // Chrome's certificate store (NSS database).
    ".pki",
];

/// Containers that are swapped for a fresh directory holding only these items (paths relative to the container).
pub const CONTAINERS: &[(&str, &[&str])] = &[
    (
        ".config",
        &[
            // Chrome profile: bookmarks, sign-in, extensions (Chrome itself is governed by enterprise policy).
            "google-chrome",
            // The user's dconf database (wallpaper, language, input methods); keys that must be fixed are locked by the system.
            "dconf",
            // Folder names, so the user is not asked to rename folders on every login.
            "user-dirs.dirs",
            // Locale the folder names were created for (same reason as user-dirs.dirs).
            "user-dirs.locale",
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
];

/// At most this many top-level dot entries are moved per run.
pub const MAX_TOP_ENTRIES: usize = 10_000;

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
    /// More than [`MAX_TOP_ENTRIES`] top-level dot entries; the rest wait for the next login.
    TooManyEntries,
    /// Any other error.
    Io,
}

use SkipReason::*;

/// Tidy the home directory `home` of `uid`, moving what is not kept into `trash`. Never fails as a whole: every
/// error is recorded as a [`SkipReason`] and the next item is tried.
pub fn tidy_home(home: &OwnedFd, trash: &OwnedFd, uid: u32) -> Tidy {
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
    tidy_top(home, trash, &mut out);
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

/// Whether a top-level name is moved: it starts with `.`, and is not kept, a container or a temporary directory
/// (those are handled, and on failure deliberately left, by the container step).
fn is_candidate(name: &[u8]) -> bool {
    if !name.starts_with(b".") || name == b"." || name == b".." {
        return false;
    }
    if KEEP_TOP.iter().any(|k| k.as_bytes() == name) {
        return false;
    }
    !CONTAINERS
        .iter()
        .any(|(c, _)| c.as_bytes() == name || temp_name(c).as_bytes() == name)
}

/// Read the candidates (raw bytes: a non-UTF-8 name must not stop the step), at most [`MAX_TOP_ENTRIES`].
fn top_candidates(home: &OwnedFd, out: &mut Tidy) -> Vec<OsString> {
    let mut names = Vec::new();
    let dir = match rustix::fs::Dir::read_from(home) {
        Ok(d) => d,
        Err(_) => {
            out.skipped.push(Io);
            return names;
        }
    };
    for e in dir {
        let Ok(e) = e else {
            out.skipped.push(Io);
            break;
        };
        let name = e.file_name().to_bytes();
        if !is_candidate(name) {
            continue;
        }
        if names.len() == MAX_TOP_ENTRIES {
            out.skipped.push(TooManyEntries);
            break;
        }
        names.push(OsStr::from_bytes(name).to_os_string());
    }
    names
}

fn tidy_top(home: &OwnedFd, trash: &OwnedFd, out: &mut Tidy) {
    // Names are collected first and moved afterwards, so renaming does not disturb the directory read.
    for name in top_candidates(home, out) {
        match to_trash_entry_os(home, trash, &name) {
            Ok(_) => out.moved += 1,
            Err(_) => out.skipped.push(Io),
        }
    }
}

#[cfg(test)]
mod tests;
