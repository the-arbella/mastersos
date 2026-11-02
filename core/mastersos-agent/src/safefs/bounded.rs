//! 有界的、不跟随链接、不跨挂载的整棵删除（Task 19 复审 I2；F1 起 Task 11 的访客临时目录清理也用它）。
//!
//! - 逐级 `openat(O_NOFOLLOW|O_DIRECTORY)` 进去、相对于父目录的 fd `unlinkat`，用显式的栈而不是递归；栈深到
//!   [`MAX_DEPTH`] 时把更深的子目录 `renameat` 到一个由调用方给的「暂存目录」顶层（换一个随机名字），之后再删它——
//!   同时打开的 fd 不超过 `2 × MAX_DEPTH + 2` 个，与树多深无关。目录项边读边删（不把整个目录的名字读进内存）。
//! - 不跨文件系统：每个打开的目录都 `fstat` 比 `st_dev`，Linux 上再比 `/proc/self/fdinfo` 的 `mnt_id`（Task 11 的
//!   `ProcMounts`，同一文件系统的 bind mount 也认得出）。挂载点整棵留着、不卸载，记一处「没删掉」。
//! - 单个目录项出错（读不了、删不掉、死掉的 FUSE 回 `ENOTCONN`）跳过、计数、接着删别的。
//! - 错误里不出现被删目录里的任何名字，只有计数。

use std::ffi::{OsStr, OsString};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use anyhow::{anyhow, bail, Result};
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::system::ephemeral::{MountOps, ProcMounts};

/// 挪上来的太深的子目录的名字前缀。
pub const FLAT_PREFIX: &str = "t-";
/// 显式栈的最大深度（再深的子目录挪到回收目录顶层再删）。
pub const MAX_DEPTH: usize = 32;

/// 一次删除的计数（不带名字）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Removal {
    /// 删掉的目录项（文件、链接与目录）。
    pub removed: usize,
    /// 出错跳过的目录项。
    pub errors: usize,
    /// 遇到的另一个挂载（整棵留着）。
    pub mounts: usize,
    /// 太深而挪到回收目录顶层的子目录。
    pub flattened: usize,
    /// 显式栈到过的最大深度。
    pub max_depth: usize,
}

impl Removal {
    /// 留下了东西没删。
    pub fn left(&self) -> usize {
        self.errors + self.mounts
    }

    fn add(&mut self, o: &Removal) {
        self.removed += o.removed;
        self.errors += o.errors;
        self.mounts += o.mounts;
        self.flattened += o.flattened;
        self.max_depth = self.max_depth.max(o.max_depth);
    }
}

pub(crate) fn io(e: Errno) -> anyhow::Error {
    anyhow::Error::from(std::io::Error::from(e))
}

pub(crate) fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK
}

/// 同一个文件系统、同一个挂载的判断（见模块文档）。
pub struct Boundary {
    pub(crate) dev: u64,
    mnt: Option<u64>,
    mounts: Box<dyn MountOps + Send + Sync>,
}

impl Boundary {
    /// 以 `root`（`/home` 的 fd）为准。`mnt_id` 取不到（不是 Linux）时只比 `st_dev`。
    pub fn of(root: &OwnedFd) -> Result<Boundary> {
        Self::with(root, Box::new(ProcMounts))
    }

    pub fn with(root: &OwnedFd, mounts: Box<dyn MountOps + Send + Sync>) -> Result<Boundary> {
        let st = rustix::fs::fstat(root).map_err(io)?;
        let mnt = mounts.mount_id(root).ok();
        Ok(Boundary {
            dev: st.st_dev as u64,
            mnt,
            mounts,
        })
    }

    /// 测试用：假装根目录在别的设备上（于是里面每个目录都「跨了挂载」）。
    #[cfg(test)]
    pub(crate) fn foreign_for_test(root: &OwnedFd) -> Boundary {
        let mut b = Self::of(root).unwrap();
        b.dev = b.dev.wrapping_add(1);
        b
    }

    fn same(&self, fd: &OwnedFd) -> bool {
        let Ok(st) = rustix::fs::fstat(fd) else {
            return false;
        };
        // st_dev 在 Linux 是 u64、在 macOS 是 i32：这里的 as 只在 Linux 上多余
        #[allow(clippy::unnecessary_cast)]
        let dev = st.st_dev as u64;
        if dev != self.dev {
            return false;
        }
        match self.mnt {
            Some(m) => self.mounts.mount_id(fd).ok() == Some(m),
            None => true,
        }
    }
}

/// 新名字：`prefix` 加 16 个十六进制字符（随机）。
pub fn fresh_name(prefix: &str) -> String {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 8];
    if ring::rand::SystemRandom::new().fill(&mut b).is_err() {
        // 随机数取不到时退回时刻（只要不与已有的重名；重名时 renameat 会因 EEXIST/ENOTEMPTY 失败、计一处错误）
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        b = n.to_le_bytes();
    }
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{prefix}{hex}")
}

/// 暂存目录可信：属主是本进程（root），是目录，组与其他人没有任何权限。
pub fn check_private_dir(fd: &OwnedFd) -> Result<()> {
    let st = rustix::fs::fstat(fd).map_err(io)?;
    let me = rustix::process::geteuid().as_raw();
    if FileType::from_raw_mode(st.st_mode) != FileType::Directory
        || st.st_uid != me
        || st.st_mode as u32 & 0o077 != 0
    {
        bail!(
            "暂存目录不可信（不是 root 自己的、或权限 {:o} 不是 0700），这一轮不删",
            st.st_mode as u32 & 0o7777
        );
    }
    Ok(())
}

/// 删不掉而跳过的顶层项最多记这么多个（超过就结束这一次，下一轮再来；复审 T19 N4：不为它们无限占内存）。
/// 读目录的次序里排在这 4096 个之后的项，在它们一直删不掉时永远轮不到（复审 X3）；实际上碰不到：删不掉的几乎只有
/// 挂载点，FUSE 的 `mount_max` 默认 1000。
const MAX_STUCK: usize = 4096;

/// 删掉暂存目录 `trash` 里的一切（太深的子目录也挪到它的顶层）。顶层也边读边删（复审 T19 N4），删的过程中挪上来的
/// 在下一遍。删不掉的项留着（下一轮再试），计在 `errors` / `mounts` 里。
pub fn empty_dir(trash: &OwnedFd, b: &Boundary) -> Removal {
    let mut out = Removal::default();
    let mut stuck: std::collections::BTreeSet<OsString> = Default::default();
    loop {
        let mut progressed = false;
        let mut d = match Dir::read_from(trash) {
            Ok(d) => d,
            Err(_) => {
                out.errors += 1;
                return out;
            }
        };
        while let Some(e) = d.read() {
            let n = match e {
                Ok(e) => OsStr::from_bytes(e.file_name().to_bytes()).to_owned(),
                Err(_) => {
                    out.errors += 1;
                    break;
                }
            };
            if n.as_bytes() == b"." || n.as_bytes() == b".." || stuck.contains(&n) {
                continue;
            }
            let r = remove_entry(trash, &n, Some(trash), b);
            out.add(&r);
            if r.left() > 0 {
                if stuck.len() >= MAX_STUCK {
                    return out;
                }
                stuck.insert(n);
            } else {
                progressed = true;
            }
        }
        if !progressed {
            return out;
        }
    }
}

/// 删掉 `parent` 里的 `name`（文件或整棵目录）。太深的子目录挪到 `trash` 顶层（由 [`empty_dir`] 删）；没有暂存目录时
/// 太深的那一处记为错误、留着。
pub fn remove_entry(
    parent: &OwnedFd,
    name: &OsStr,
    trash: Option<&OwnedFd>,
    b: &Boundary,
) -> Removal {
    let mut out = Removal::default();
    let st = match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => st,
        Err(Errno::NOENT) => return out,
        Err(_) => {
            out.errors += 1;
            return out;
        }
    };
    if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
        match rustix::fs::unlinkat(parent, name, AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => out.removed += 1,
            Err(_) => out.errors += 1,
        }
        return out;
    }
    remove_dir(parent, name, trash, b, &mut out);
    out
}

/// 打开 `parent` 里的子目录 `name`：不跟随链接；跨了挂载为 `Ok(None)`（fd 立即关掉）。
fn open_sub(parent: &OwnedFd, name: &OsStr, b: &Boundary) -> Result<Option<OwnedFd>> {
    let fd = rustix::fs::openat(parent, name, dir_flags(), Mode::empty()).map_err(io)?;
    Ok(b.same(&fd).then_some(fd))
}

/// 栈上的一层：目录的 fd、读它的流、它在父目录里的名字、里面有没有留下东西。
struct Level {
    fd: OwnedFd,
    dir: Dir,
    name: OsString,
    kept: bool,
}

fn level(fd: OwnedFd, name: &OsStr) -> Result<Level> {
    let dir = Dir::read_from(&fd).map_err(|e| anyhow!("读目录：{e}"))?;
    Ok(Level {
        fd,
        dir,
        name: name.to_owned(),
        kept: false,
    })
}

/// 删掉 `parent` 里的目录 `name` 整棵（显式栈，见模块文档）。
fn remove_dir(
    parent: &OwnedFd,
    name: &OsStr,
    trash: Option<&OwnedFd>,
    b: &Boundary,
    out: &mut Removal,
) {
    let top = match open_sub(parent, name, b) {
        Ok(Some(fd)) => fd,
        Ok(None) => {
            out.mounts += 1;
            return;
        }
        Err(_) => {
            out.errors += 1;
            return;
        }
    };
    let mut stack = match level(top, name) {
        Ok(l) => vec![l],
        Err(_) => {
            out.errors += 1;
            return;
        }
    };
    loop {
        let depth = stack.len();
        out.max_depth = out.max_depth.max(depth);
        let Some(cur) = stack.last_mut() else {
            return;
        };
        match cur.dir.read() {
            Some(Ok(e)) => {
                let n = e.file_name().to_bytes();
                if n == b"." || n == b".." {
                    continue;
                }
                let n = OsStr::from_bytes(n).to_owned();
                let st = match rustix::fs::statat(&cur.fd, n.as_os_str(), AtFlags::SYMLINK_NOFOLLOW)
                {
                    Ok(st) => st,
                    Err(Errno::NOENT) => continue,
                    Err(_) => {
                        out.errors += 1;
                        cur.kept = true;
                        continue;
                    }
                };
                if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
                    match rustix::fs::unlinkat(&cur.fd, n.as_os_str(), AtFlags::empty()) {
                        Ok(()) | Err(Errno::NOENT) => out.removed += 1,
                        Err(_) => {
                            out.errors += 1;
                            cur.kept = true;
                        }
                    }
                    continue;
                }
                if depth >= MAX_DEPTH {
                    // 挂载点不挪（复审 T19 N5）：设备号不同、或 renameat 回 EBUSY，都记为挂载
                    if st.st_dev as u64 != b.dev {
                        out.mounts += 1;
                        cur.kept = true;
                        continue;
                    }
                    // 太深：挪到暂存目录顶层，由 empty_dir 的下一遍从头删；没有暂存目录就留着
                    let Some(trash) = trash else {
                        out.errors += 1;
                        cur.kept = true;
                        continue;
                    };
                    match rustix::fs::renameat(
                        &cur.fd,
                        n.as_os_str(),
                        trash,
                        fresh_name(FLAT_PREFIX).as_str(),
                    ) {
                        Ok(()) => out.flattened += 1,
                        Err(Errno::BUSY) => {
                            out.mounts += 1;
                            cur.kept = true;
                        }
                        Err(_) => {
                            out.errors += 1;
                            cur.kept = true;
                        }
                    }
                    continue;
                }
                match open_sub(&cur.fd, &n, b) {
                    Ok(Some(fd)) => match level(fd, &n) {
                        Ok(l) => stack.push(l),
                        Err(_) => {
                            out.errors += 1;
                            cur.kept = true;
                        }
                    },
                    Ok(None) => {
                        out.mounts += 1;
                        cur.kept = true;
                    }
                    Err(_) => {
                        out.errors += 1;
                        cur.kept = true;
                    }
                }
            }
            Some(Err(_)) => {
                // 读不下去了：这一层留着，回到上一层
                out.errors += 1;
                cur.kept = true;
                finish(&mut stack, parent, out);
            }
            None => finish(&mut stack, parent, out),
        }
    }
}

/// 栈顶这一层读完了：里面没留东西就从它的父目录里 `rmdir` 它；留了东西就让父目录也记上「留了东西」。
fn finish(stack: &mut Vec<Level>, top_parent: &OwnedFd, out: &mut Removal) {
    let Some(done) = stack.pop() else {
        return;
    };
    let Level {
        fd,
        dir,
        name,
        kept,
    } = done;
    drop(dir);
    drop(fd);
    let parent_kept = if kept {
        true
    } else {
        let pfd = stack.last().map(|l| &l.fd).unwrap_or(top_parent);
        match rustix::fs::unlinkat(pfd, name.as_os_str(), AtFlags::REMOVEDIR) {
            Ok(()) | Err(Errno::NOENT) => {
                out.removed += 1;
                false
            }
            Err(_) => {
                out.errors += 1;
                true
            }
        }
    };
    if parent_kept {
        if let Some(p) = stack.last_mut() {
            p.kept = true;
        }
    }
}

// ---------------------------------------------------------------------------
// 属主是某个 uid 的顶层项（Task 11 的访客临时目录清理；复审 T19 F1）
// ---------------------------------------------------------------------------

/// 访客临时目录里的暂存目录的名字前缀（每次随机，谁都猜不到、抢不了）。
pub const HOLD_PREFIX: &str = ".mastersos-rm-";
/// 建暂存目录时撞名最多重试这么多次。
const HOLD_TRIES: usize = 16;

/// 在 `dir` 里建一个新的暂存目录：随机名字、`mkdirat` 0700（已存在就换个名字，O_EXCL 语义：绝不接受别人先建好的），
/// 再 `O_NOFOLLOW|O_DIRECTORY` 打开、核对是自己的 0700 目录。建不出来（例如 `/dev/mqueue` 不让建目录）为 `None`：
/// 那样太深的子目录记为错误。
fn make_hold(dir: &OwnedFd) -> Option<(String, OwnedFd)> {
    for _ in 0..HOLD_TRIES {
        let name = fresh_name(HOLD_PREFIX);
        match rustix::fs::mkdirat(dir, name.as_str(), Mode::from_raw_mode(0o700)) {
            Ok(()) => {}
            Err(Errno::EXIST) => continue,
            Err(_) => return None,
        }
        let fd = rustix::fs::openat(dir, name.as_str(), dir_flags(), Mode::empty()).ok()?;
        if check_private_dir(&fd).is_err() {
            return None;
        }
        return Some((name, fd));
    }
    None
}

/// 上一次中途崩溃留下的暂存目录（[`HOLD_PREFIX`] 开头、是本进程自己的 0700 真实目录）：删空、删掉。
fn clean_old_holds(dir: &OwnedFd, b: &Boundary, out: &mut Removal) -> Result<()> {
    let mut d = Dir::read_from(dir).map_err(|e| io(e).context("读目录"))?;
    while let Some(e) = d.read() {
        let e = e.map_err(|e| io(e).context("读目录"))?;
        let n = OsStr::from_bytes(e.file_name().to_bytes()).to_owned();
        if !n.as_bytes().starts_with(HOLD_PREFIX.as_bytes()) {
            continue;
        }
        let Ok(fd) = rustix::fs::openat(dir, n.as_os_str(), dir_flags(), Mode::empty()) else {
            continue;
        };
        if check_private_dir(&fd).is_err() {
            continue;
        }
        out.add(&empty_dir(&fd, b));
        drop(fd);
        match rustix::fs::unlinkat(dir, n.as_os_str(), AtFlags::REMOVEDIR) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(_) => out.errors += 1,
        }
    }
    Ok(())
}

/// 已打开的目录 `d` 里属主是 `uid` 的直接子项整个删掉（边读边删；`skip` 是暂存目录的名字）。返回删的顶层项数。
fn remove_owned_level(
    d: &OwnedFd,
    uid: u32,
    skip: Option<&str>,
    hold: Option<&OwnedFd>,
    b: &Boundary,
    out: &mut Removal,
) -> Result<usize> {
    let mut n = 0;
    let mut stream = Dir::read_from(d).map_err(|e| io(e).context("读目录"))?;
    while let Some(e) = stream.read() {
        let e = e.map_err(|e| io(e).context("读目录"))?;
        let name = OsStr::from_bytes(e.file_name().to_bytes()).to_owned();
        if name.as_bytes() == b"." || name.as_bytes() == b".." {
            continue;
        }
        if skip.is_some_and(|s| name.as_bytes() == s.as_bytes()) {
            continue;
        }
        let st = match rustix::fs::statat(d, name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => st,
            Err(Errno::NOENT) => continue,
            Err(_) => {
                out.errors += 1;
                continue;
            }
        };
        if st.st_uid != uid {
            continue;
        }
        out.add(&remove_entry(d, &name, hold, b));
        n += 1;
    }
    Ok(n)
}

/// `dir` 的直接子项里属主是 `uid` 的整个删掉；`sticky` 时对属主不是 `uid`、带 sticky 位的子目录再往下做一层
/// （`/tmp/.X11-unix` 这类）。有界、不跟随链接、不跨挂载（见模块文档）；太深的子目录挪进 `dir` 里新建的随机名字的
/// 暂存目录，最后删空它。有删不掉的（挂载点、出错）就报错（调用方据此不写「已清理」的标记、稍后重试）。
/// 返回删掉的顶层项数。`dir` 本身是链接报错。
pub fn remove_owned_bounded(dir: &Path, uid: u32, sticky: bool) -> Result<usize> {
    let d = super::open_abs_dir(dir, false)?;
    let b = Boundary::of(&d)?;
    let mut out = Removal::default();
    clean_old_holds(&d, &b, &mut out)?;
    let hold = make_hold(&d);
    let (skip, hold_fd) = match &hold {
        Some((n, fd)) => (Some(n.as_str()), Some(fd)),
        None => (None, None),
    };
    let mut n = remove_owned_level(&d, uid, skip, hold_fd, &b, &mut out)?;
    if sticky {
        let mut stream = Dir::read_from(&d).map_err(|e| io(e).context("读目录"))?;
        while let Some(e) = stream.read() {
            let e = e.map_err(|e| io(e).context("读目录"))?;
            let name = OsStr::from_bytes(e.file_name().to_bytes()).to_owned();
            if name.as_bytes() == b"." || name.as_bytes() == b".." {
                continue;
            }
            if skip.is_some_and(|s| name.as_bytes() == s.as_bytes()) {
                continue;
            }
            let st = match rustix::fs::statat(&d, name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW) {
                Ok(st) => st,
                Err(Errno::NOENT) => continue,
                Err(_) => {
                    out.errors += 1;
                    continue;
                }
            };
            let is_dir = FileType::from_raw_mode(st.st_mode) == FileType::Directory;
            if !super::sticky_foreign(is_dir, st.st_uid, st.st_mode as u32, uid) {
                continue;
            }
            let Ok(sub) = rustix::fs::openat(&d, name.as_os_str(), dir_flags(), Mode::empty())
            else {
                out.errors += 1;
                continue;
            };
            let Ok(st) = rustix::fs::fstat(&sub) else {
                out.errors += 1;
                continue;
            };
            // st_mode 在 Linux 是 u32、在 macOS 是 u16：这里的 as 只在 Linux 上多余
            #[allow(clippy::unnecessary_cast)]
            let mode = st.st_mode as u32;
            if !super::sticky_foreign(true, st.st_uid, mode, uid) {
                continue;
            }
            // 别的挂载（不是访客的，访客的已经卸掉了）：跳过、不算留下（复审 T19 R3：否则访客从此登录不了）
            if !b.same(&sub) {
                log::info!("访客清理：一个带 sticky 位的子目录是另一个挂载，不进去");
                continue;
            }
            n += remove_owned_level(&sub, uid, None, hold_fd, &b, &mut out)?;
        }
    }
    if let Some((name, fd)) = hold {
        out.add(&empty_dir(&fd, &b));
        drop(fd);
        match rustix::fs::unlinkat(&d, name.as_str(), AtFlags::REMOVEDIR) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(_) => out.errors += 1,
        }
    }
    if out.left() > 0 {
        bail!(
            "{} 处删不掉（{} 处挂载点、{} 处出错）",
            out.left(),
            out.mounts,
            out.errors
        );
    }
    Ok(n)
}
