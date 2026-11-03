//! 家目录的删除（复审 T19 I1、I2、M1）：先挪进回收目录，再用 [`crate::safefs::bounded`] 有界地删。
//!
//! - 回收目录 [`TRASH`]（`/home/.mastersos-trash`）：root:root 0700，经 `/home` 的 fd `mkdirat` 建出；已经存在而不是 root
//!   自己的真实目录（或组、其他人有权限）就拒绝，这一轮什么都不动。
//! - [`to_trash`]：核对 `/home/<名字>` 是属主为该 uid 的真实目录，`renameat` 到回收目录里一个随机名字（同一文件系统，
//!   原子：之后登录的人看不到它，`pam_mkhomedir` 给他新建一个），再经 `O_NOFOLLOW|O_DIRECTORY` 打开挪过去的那个目录，
//!   `fstat` 核对还是它，改成 root:root 0700（学生的进程再也进不去）。挪走之前不删任何东西。
//! - [`empty_trash`]：把回收目录里的一切删掉（每轮开头先做一次：上一轮中途崩溃留下的在这里删完）。
//! - 错误与日志里不出现学生家目录里的任何名字，只有计数（复审 M6）。

use std::os::fd::OwnedFd;

use anyhow::{bail, Result};
use rustix::fs::{AtFlags, FileType, Mode};
use rustix::io::Errno;

use crate::safefs::bounded::{check_private_dir, dir_flags, fresh_name, io, FLAT_PREFIX};
pub use crate::safefs::bounded::{Boundary, Removal, MAX_DEPTH};

/// 回收目录在 `/home` 里的名字（不含 `@`，属主 root：永远不会被当成谁的家目录）。
pub const TRASH: &str = ".mastersos-trash";

/// 删掉回收目录里的一切（[`crate::safefs::bounded::empty_dir`]）。
pub fn empty_trash(trash: &OwnedFd, b: &Boundary) -> Removal {
    crate::safefs::bounded::empty_dir(trash, b)
}

/// 打开回收目录；不存在时 `create` 才建（0700，root 时 root:root）。是链接、不是目录、不可信都报错。
pub fn open_trash(home: &OwnedFd, create: bool) -> Result<Option<OwnedFd>> {
    match rustix::fs::statat(home, TRASH, AtFlags::SYMLINK_NOFOLLOW) {
        Err(Errno::NOENT) if !create => return Ok(None),
        Err(Errno::NOENT) => match rustix::fs::mkdirat(home, TRASH, Mode::from_raw_mode(0o700)) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(e) => return Err(io(e).context("creating the trash directory")),
        },
        Err(e) => return Err(io(e).context("checking the trash directory")),
        Ok(st) if FileType::from_raw_mode(st.st_mode) != FileType::Directory => {
            bail!("the trash directory is not a real directory; not removing this round")
        }
        Ok(_) => {}
    }
    let fd = rustix::fs::openat(home, TRASH, dir_flags(), Mode::empty())
        .map_err(|e| io(e).context("opening the trash directory"))?;
    check_private_dir(&fd)?;
    Ok(Some(fd))
}

/// 把 `home` 里的 `name`（属主须是 `uid` 的真实目录）原子地挪进回收目录，改成 root 0700。挪走之前不删任何东西。
/// `Err`：没有挪走；`Ok(true)`：挪走并收好；`Ok(false)`：挪走了，但之后打开、核对或改属主权限失败（家目录已不在原处，
/// 仍由 [`empty_trash`] 删；复审 T19 N3）。
pub fn to_trash(home: &OwnedFd, trash: &OwnedFd, name: &str, uid: u32) -> Result<bool> {
    if name.is_empty() || name.contains('/') || name.starts_with('.') {
        bail!("malformed home directory name");
    }
    let st = rustix::fs::statat(home, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|e| io(e).context("checking the home directory"))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::Directory || st.st_uid != uid {
        bail!("the home directory is not this user's real directory; not removing it");
    }
    let to = fresh_name(FLAT_PREFIX);
    rustix::fs::renameat(home, name, trash, to.as_str())
        .map_err(|e| io(e).context("moving into the trash directory"))?;
    match seal(trash, &to, &st) {
        Ok(()) => Ok(true),
        Err(e) => {
            log::warn!("homes: the moved home directory could not be set to root 0700: {e:#}");
            Ok(false)
        }
    }
}

/// 打开挪过去的目录，核对还是原来那个（ino 与 dev），改成 root:root 0700。
fn seal(trash: &OwnedFd, to: &str, before: &rustix::fs::Stat) -> Result<()> {
    let fd = rustix::fs::openat(trash, to, dir_flags(), Mode::empty())
        .map_err(|e| io(e).context("opening the moved home directory"))?;
    let moved = rustix::fs::fstat(&fd).map_err(io)?;
    if moved.st_ino != before.st_ino || moved.st_dev != before.st_dev {
        bail!("what was moved is not the original directory");
    }
    if rustix::process::geteuid().is_root() {
        rustix::fs::fchown(
            &fd,
            Some(rustix::fs::Uid::ROOT),
            Some(rustix::fs::Gid::ROOT),
        )
        .map_err(|e| io(e).context("changing the owner"))?;
    }
    rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o700))
        .map_err(|e| io(e).context("changing permissions"))?;
    Ok(())
}
