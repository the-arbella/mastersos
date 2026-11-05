//! agent 以 root 写系统文件的唯一通道。
//!
//! 从调用方给的根目录开始，路径的每一级都用 `openat(O_DIRECTORY|O_NOFOLLOW)` 相对于上一级的
//! fd 打开，最后一级的文件同样 `O_NOFOLLOW`；之后的读、写、改名、删除都经已打开的目录 fd 做。
//! 这样「检查」和「写入」之间把某一级目录换成符号链接也没有用：我们手里的 fd 仍指向原来的
//! 目录，写不到链接指向的别处。路径上任何一级是符号链接都报错（错误信息含 `symlink`）。

pub mod bounded;

use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, RawMode};
use rustix::io::Errno;

fn mode_of(mode: u32) -> Mode {
    Mode::from_raw_mode(mode as RawMode)
}

/// 单个目录项的名字：非空、不是 `.` / `..`、不含 `/` 与 NUL。
fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        bail!("malformed name: {name:?}");
    }
    Ok(())
}

fn symlink_error(name: &OsStr) -> anyhow::Error {
    anyhow!(
        "{} is a symlink; refusing to follow it",
        Path::new(name).display()
    )
}

/// `openat(O_NOFOLLOW)` 失败后判断是不是因为它是符号链接：Linux 对
/// `O_DIRECTORY|O_NOFOLLOW` 遇到链接回 `ENOTDIR`，对普通的 `O_NOFOLLOW` 回 `ELOOP`；
/// 以 `lstat` 为准，不靠错误码猜。
fn classify(dir: impl AsFd, name: &OsStr, e: Errno, what: &str) -> anyhow::Error {
    if matches!(e, Errno::LOOP | Errno::NOTDIR) {
        if let Ok(st) = rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            if FileType::from_raw_mode(st.st_mode) == FileType::Symlink {
                return symlink_error(name);
            }
        }
    }
    anyhow::Error::from(std::io::Error::from(e))
        .context(format!("{what} {}", Path::new(name).display()))
}

fn open_subdir(dir: impl AsFd, name: &OsStr, create: bool) -> Result<OwnedFd> {
    let dir = dir.as_fd();
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    match rustix::fs::openat(dir, name, flags, Mode::empty()) {
        Ok(fd) => Ok(fd),
        Err(Errno::NOENT) if create => {
            match rustix::fs::mkdirat(dir, name, mode_of(0o755)) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(e) => {
                    return Err(anyhow::Error::from(std::io::Error::from(e))
                        .context(format!("creating directory {}", Path::new(name).display())))
                }
            }
            rustix::fs::openat(dir, name, flags, Mode::empty())
                .map_err(|e| classify(dir, name, e, "opening directory"))
        }
        Err(e) => Err(classify(dir, name, e, "opening directory")),
    }
}

/// 打开 `root/rel`。`root` 自己用普通的 `open`（由调用方保证可信）；`rel` 的每一级都
/// `openat(O_DIRECTORY|O_NOFOLLOW)`，`create` 时不存在的目录以 0755 建出来。
/// `rel` 只能是相对路径，不得含 `.`、`..`；空的 `rel` 打开 `root` 本身。
pub fn open_dir(root: &Path, rel: &Path, create: bool) -> Result<OwnedFd> {
    let parts = rel_parts(rel)?;
    let mut fd = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("opening root directory {}", root.display()))?;
    for p in parts {
        fd = open_subdir(&fd, OsStr::from_bytes(p), create)?;
    }
    Ok(fd)
}

/// 规范的相对路径拆成各级名字（不以 `/` 开头，不含 `.`、`..`）。
fn rel_parts(rel: &Path) -> Result<Vec<&[u8]>> {
    let bytes = rel.as_os_str().as_bytes();
    if bytes.first() == Some(&b'/') {
        bail!("a relative path must not start with /: {}", rel.display());
    }
    let parts: Vec<&[u8]> = bytes
        .split(|b| *b == b'/')
        .filter(|p| !p.is_empty())
        .collect();
    if parts.iter().any(|p| *p == b"." || *p == b"..") {
        bail!(
            "malformed relative path (contains . or ..): {}",
            rel.display()
        );
    }
    Ok(parts)
}

/// 同 [`open_dir`]，但从已打开的目录 `dir` 开始逐级 `openat(O_DIRECTORY|O_NOFOLLOW)`；
/// 空的 `rel` 得到 `dir` 的一个新 fd。
pub fn open_dir_at(dir: &OwnedFd, rel: &Path, create: bool) -> Result<OwnedFd> {
    let parts = rel_parts(rel)?;
    let mut fd = rustix::fs::openat(
        dir,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .context("opening directory")?;
    for p in parts {
        fd = open_subdir(&fd, OsStr::from_bytes(p), create)?;
    }
    Ok(fd)
}

/// `dir` 里的子目录 `name`：不存在为 `None`；是符号链接或不是目录都报错。
pub fn open_child_dir(dir: &OwnedFd, name: &str) -> Result<Option<OwnedFd>> {
    check_name(name)?;
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(Errno::NOENT) => Ok(None),
        Err(e) => {
            Err(anyhow::Error::from(std::io::Error::from(e)).context(format!("checking {name}")))
        }
        Ok(_) => open_subdir(dir, OsStr::new(name), false).map(Some),
    }
}

/// 删掉 `dir` 里的 `name` 连同它下面的一切（目录逐级 `openat(O_NOFOLLOW)` 进去删，
/// 里面的符号链接只删链接本身、不跟随）。不存在算成功；`name` 本身是符号链接报错。
pub fn remove_tree_at(dir: &OwnedFd, name: &str) -> Result<()> {
    check_name(name)?;
    remove_tree_os(dir, OsStr::new(name))
}

/// [`remove_tree_at`] 的本体：名字是任意字节（目录里读出来的名字，不含 `/`，不是 `.`、`..`）。
fn remove_tree_os(dir: &OwnedFd, name: &OsStr) -> Result<()> {
    let shown = Path::new(name).display();
    let st = match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => st,
        Err(Errno::NOENT) => return Ok(()),
        Err(e) => {
            return Err(
                anyhow::Error::from(std::io::Error::from(e)).context(format!("checking {shown}"))
            )
        }
    };
    let flags = match FileType::from_raw_mode(st.st_mode) {
        FileType::Symlink => return Err(symlink_error(name)),
        FileType::Directory => {
            remove_children(dir, name)?;
            AtFlags::REMOVEDIR
        }
        _ => AtFlags::empty(),
    };
    match rustix::fs::unlinkat(dir, name, flags) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(e) => {
            Err(anyhow::Error::from(std::io::Error::from(e)).context(format!("removing {shown}")))
        }
    }
}

/// 删掉目录 `dir/name` 里的全部内容（不删它本身）。
fn remove_children(dir: &OwnedFd, name: &OsStr) -> Result<()> {
    let sub = open_subdir(dir, name, false)?;
    for e in rustix::fs::Dir::read_from(&sub).map_err(std::io::Error::from)? {
        let e = e.map_err(std::io::Error::from)?;
        let child = e.file_name();
        if child.to_bytes() == b"." || child.to_bytes() == b".." {
            continue;
        }
        let child = OsStr::from_bytes(child.to_bytes()).to_owned();
        let st = rustix::fs::statat(&sub, child.as_os_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(std::io::Error::from)?;
        let flags = if FileType::from_raw_mode(st.st_mode) == FileType::Directory {
            remove_children(&sub, &child)?;
            AtFlags::REMOVEDIR
        } else {
            AtFlags::empty()
        };
        match rustix::fs::unlinkat(&sub, child.as_os_str(), flags) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(e) => {
                return Err(anyhow::Error::from(std::io::Error::from(e))
                    .context(format!("removing {}", Path::new(&child).display())))
            }
        }
    }
    Ok(())
}

/// 同一目录里改名 `from` → `to`（`renameat`，再 fsync 目录）。`to` 已存在时按 `rename(2)` 的规则替换。
pub fn rename_at(dir: &OwnedFd, from: &str, to: &str) -> Result<()> {
    check_name(from)?;
    check_name(to)?;
    rustix::fs::renameat(dir, from, dir, to)
        .map_err(std::io::Error::from)
        .with_context(|| format!("renaming {from} to {to}"))?;
    rustix::fs::fsync(dir)
        .map_err(std::io::Error::from)
        .context("fsync of the directory")
}

/// 打开绝对路径 `path` 这个目录本身：父目录用普通的 `open`（由调用方保证可信，例如
/// `/var/lib`），最后一级 `O_DIRECTORY|O_NOFOLLOW`，是符号链接就报错；`create` 时不存在就以
/// 0755 建出来（权限由调用方随后 [`set_mode`]）。
pub fn open_abs_dir(path: &Path, create: bool) -> Result<OwnedFd> {
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => open_dir(parent, Path::new(name), create),
        _ => open_dir(path, Path::new(""), false),
    }
}

/// Opens the directory `path` for lookups only (`O_PATH|O_DIRECTORY|O_NOFOLLOW`): enough for `openat` of a known name in
/// a search-only directory such as 0711 `/run/mastersos-signin`, where `O_RDONLY` gets `EACCES` for anyone but root.
/// The parent is opened as in [`open_abs_dir`]; a symbolic link as the last part is refused.
pub fn open_abs_dir_search(path: &Path) -> Result<OwnedFd> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        bail!("not a directory below another: {}", path.display());
    };
    let parent = open_abs_dir(parent, false)?;
    let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    rustix::fs::openat(&parent, name, flags, Mode::empty())
        .map_err(|e| classify(&parent, name, e, "opening directory"))
}

/// 打开 `dir` 里的普通文件读。不存在为 `None`；是符号链接或不是普通文件都报错。
/// `O_NONBLOCK` 免得碰上 FIFO 时卡住。
pub fn open_file_at(dir: &OwnedFd, name: &str) -> Result<Option<File>> {
    check_name(name)?;
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let fd = match rustix::fs::openat(dir, name, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(e) => return Err(classify(dir, OsStr::new(name), e, "opening")),
    };
    let st = rustix::fs::fstat(&fd).map_err(std::io::Error::from)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        bail!("{name} is not a regular file");
    }
    Ok(Some(File::from(fd)))
}

/// 读 `dir` 里的文件（`O_NOFOLLOW`）。不存在为 `None`；是符号链接报错。
pub fn read_at(dir: &OwnedFd, name: &str) -> Result<Option<Vec<u8>>> {
    let Some(mut f) = open_file_at(dir, name)? else {
        return Ok(None);
    };
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .with_context(|| format!("reading {name}"))?;
    Ok(Some(buf))
}

/// 同目录的临时文件 `.<name>.mastersos-tmp`。`commit` 之前被丢弃（出错返回）就删掉自己。
///
/// 假定**每个目录项只有一个写者**（agent 的应用任务是唯一写者，Ruling 17）：临时文件名是
/// 固定的，`create` 会无条件删掉同名的旧文件，所以 `.<name>.mastersos-tmp` 这个名字归我们保留，
/// 别处不得用它，也不得有两个写者同时写同一个 `name`。
pub struct TmpFile<'a> {
    dir: &'a OwnedFd,
    tmp: String,
    name: String,
    file: Option<File>,
}

impl<'a> TmpFile<'a> {
    /// 先删掉上次残留的同名临时文件，再 `O_CREAT|O_EXCL|O_NOFOLLOW` 新建，`fchmod(mode)`
    /// （不受 umask 影响）。
    pub fn create(dir: &'a OwnedFd, name: &str, mode: u32) -> Result<Self> {
        check_name(name)?;
        let tmp = format!(".{name}.mastersos-tmp");
        match rustix::fs::unlinkat(dir, tmp.as_str(), AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(e) => {
                return Err(anyhow::Error::from(std::io::Error::from(e))
                    .context(format!("removing leftover {tmp}")))
            }
        }
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let fd = rustix::fs::openat(dir, tmp.as_str(), flags, mode_of(0o600))
            .map_err(std::io::Error::from)
            .with_context(|| format!("creating {tmp}"))?;
        let mut t = TmpFile {
            dir,
            tmp,
            name: name.to_owned(),
            file: Some(File::from(fd)),
        };
        rustix::fs::fchmod(t.file()?, mode_of(mode))
            .map_err(std::io::Error::from)
            .with_context(|| format!("setting permissions of {}", t.tmp))?;
        Ok(t)
    }

    fn file(&mut self) -> Result<&mut File> {
        self.file
            .as_mut()
            .ok_or_else(|| anyhow!("temporary file already committed"))
    }

    /// Gives the temporary file to `uid` (`fchown`, group unchanged) before [`TmpFile::commit`].
    pub fn chown(&mut self, uid: u32) -> Result<()> {
        rustix::fs::fchown(self.file()?, Some(rustix::fs::Uid::from_raw(uid)), None)
            .map_err(std::io::Error::from)
            .with_context(|| format!("setting the owner of {}", self.tmp))
    }

    /// `fsync` → `renameat` 到目标名 → `fsync` 目录。
    pub fn commit(mut self) -> Result<()> {
        let f = self
            .file
            .take()
            .ok_or_else(|| anyhow!("temporary file already committed"))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", self.tmp))?;
        drop(f);
        rustix::fs::renameat(self.dir, self.tmp.as_str(), self.dir, self.name.as_str())
            .map_err(std::io::Error::from)
            .with_context(|| format!("renaming to {}", self.name))?;
        // 改名已生效：之后的失败不能再删「临时文件」（那个名字已经不存在）。
        self.tmp.clear();
        rustix::fs::fsync(self.dir)
            .map_err(std::io::Error::from)
            .context("fsync of the directory")?;
        Ok(())
    }
}

impl Write for TmpFile<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.file.as_mut() {
            Some(f) => f.write(buf),
            None => Err(std::io::Error::other("temporary file already committed")),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.file.as_mut() {
            Some(f) => f.flush(),
            None => Ok(()),
        }
    }
}

impl Drop for TmpFile<'_> {
    fn drop(&mut self) {
        if !self.tmp.is_empty() {
            self.file = None;
            let _ = rustix::fs::unlinkat(self.dir, self.tmp.as_str(), AtFlags::empty());
        }
    }
}

/// 内容、权限与属主（本进程的有效 uid/gid）都已一致返回 `false`，不动盘（比较全程经 fd，不按路径 stat）。否则写同目录的
/// 临时文件 → `fchmod(mode)` → 写 → `fsync` → `renameat` → `fsync(dir)`，返回 `true`。
/// 目标是符号链接时报错，不碰链接指向的文件。
pub fn write_at(dir: &OwnedFd, name: &str, bytes: &[u8], mode: u32) -> Result<bool> {
    if let Some(mut f) = open_file_at(dir, name)? {
        let st = rustix::fs::fstat(&f).map_err(std::io::Error::from)?;
        // 属主也要对：agent 以 root 运行时就是 root:root（测试里是当前用户）；新写的文件
        // 属于本进程的有效 uid/gid，所以属主不对时重写一遍就纠正了。
        let owned = st.st_uid == rustix::process::geteuid().as_raw()
            && st.st_gid == rustix::process::getegid().as_raw();
        let same_size = u64::try_from(st.st_size).ok() == u64::try_from(bytes.len()).ok();
        if owned && same_size && Mode::from_raw_mode(st.st_mode) == mode_of(mode) {
            let mut cur = Vec::new();
            f.read_to_end(&mut cur)
                .with_context(|| format!("reading {name}"))?;
            if cur == bytes {
                return Ok(false);
            }
        }
    }
    let mut t = TmpFile::create(dir, name, mode)?;
    t.write_all(bytes)
        .with_context(|| format!("writing the temporary file for {name}"))?;
    t.commit()?;
    Ok(true)
}

/// 删除 `dir` 里的 `name`。不存在算成功；是符号链接报错（`unlinkat` 本身不跟随链接，
/// 拒绝只是为了不悄悄删掉一个不是我们放的链接）。
pub fn remove_at(dir: &OwnedFd, name: &str) -> Result<()> {
    check_name(name)?;
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) if FileType::from_raw_mode(st.st_mode) == FileType::Symlink => {
            return Err(symlink_error(OsStr::new(name)))
        }
        Ok(_) => {}
        Err(Errno::NOENT) => return Ok(()),
        Err(e) => {
            return Err(
                anyhow::Error::from(std::io::Error::from(e)).context(format!("checking {name}"))
            )
        }
    }
    match rustix::fs::unlinkat(dir, name, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(e) => {
            Err(anyhow::Error::from(std::io::Error::from(e)).context(format!("removing {name}")))
        }
    }
}

/// 原子地「拿走」`dir` 里的 `name`：改名为 `to`（`renameat`，同目录；`to` 已存在就被替换）。成功返回 `true`，
/// `name` 本来就不存在（别人先拿走了）返回 `false`。不先 stat：两个调用者同时拿，只有一个得到 `true`。
pub fn take_at(dir: &OwnedFd, name: &str, to: &str) -> Result<bool> {
    check_name(name)?;
    check_name(to)?;
    match rustix::fs::renameat(dir, name, dir, to) {
        Ok(()) => Ok(true),
        Err(Errno::NOENT) => Ok(false),
        Err(e) => Err(anyhow::Error::from(std::io::Error::from(e))
            .context(format!("renaming {name} to {to}"))),
    }
}

/// 把 `dir` 里 `name` 的修改时间设成现在（`utimensat(UTIME_NOW)`，不跟随链接）。
pub fn touch_at(dir: &OwnedFd, name: &str) -> Result<()> {
    check_name(name)?;
    let now = rustix::fs::Timespec {
        tv_sec: 0,
        tv_nsec: rustix::fs::UTIME_NOW,
    };
    rustix::fs::utimensat(
        dir,
        name,
        &rustix::fs::Timestamps {
            last_access: now,
            last_modification: now,
        },
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("updating the timestamps of {name}"))
}

/// 打开挂载点 `root/rel`（`rel` 是相对路径），**路径上任何一级都不许是符号链接**：从 `root` 的 fd 起逐级
/// `openat(O_PATH|O_DIRECTORY|O_NOFOLLOW)`，最后一级 `O_PATH|O_NOFOLLOW` 并经 `fstat` 确认不是链接。之后按 fd 卸载
/// （`/proc/self/fd/N`），内核不再重新解析这条路径——别人在这期间把某一级换成链接也改不了卸的是哪个挂载
/// （复审 T11 N1）。不存在、是链接都报错。
pub fn open_mount_target(root: &Path, rel: &Path) -> Result<OwnedFd> {
    #[cfg(target_os = "linux")]
    let base = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let base = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let parts = rel_parts(rel)?;
    let mut fd = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("opening root directory {}", root.display()))?;
    let n = parts.len();
    for (i, p) in parts.into_iter().enumerate() {
        let name = OsStr::from_bytes(p);
        let flags = if i + 1 < n {
            base | OFlags::DIRECTORY
        } else {
            base
        };
        fd = rustix::fs::openat(&fd, name, flags, Mode::empty())
            .map_err(|e| classify(&fd, name, e, "opening the mount point path"))?;
    }
    // 死掉的 FUSE 上 fstat 会报 ENOTCONN：那时不在这里拦（调用方还要核对挂载 id，链接所在的挂载对不上）
    if let Ok(st) = rustix::fs::fstat(&fd) {
        if FileType::from_raw_mode(st.st_mode) == FileType::Symlink {
            return Err(symlink_error(rel.as_os_str()));
        }
    }
    Ok(fd)
}

/// `dir` 里 `name` 的修改时间（不跟随链接）；不存在为 `None`。
pub fn mtime_at(dir: &OwnedFd, name: &str) -> Result<Option<std::time::SystemTime>> {
    check_name(name)?;
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => {
            let secs = u64::try_from(st.st_mtime).unwrap_or(0);
            Ok(Some(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs),
            ))
        }
        Err(Errno::NOENT) => Ok(None),
        Err(e) => {
            Err(anyhow::Error::from(std::io::Error::from(e)).context(format!("checking {name}")))
        }
    }
}

/// 目录里的名字，不含 `.`、`..`，按名字排序。不是 UTF-8 的名字报错。
pub fn list_at(dir: &OwnedFd) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for e in rustix::fs::Dir::read_from(dir).map_err(std::io::Error::from)? {
        let e = e.map_err(std::io::Error::from)?;
        let name = e.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let name =
            std::str::from_utf8(name).map_err(|_| anyhow!("the directory has a non-UTF-8 name"))?;
        out.push(name.to_owned());
    }
    out.sort();
    Ok(out)
}

/// 清单里的绝对路径 → (父目录相对于根的路径, 文件名)。只接受规范的绝对路径
/// （不含 `..`、`.`，不是根目录本身）。
pub fn split_abs(dest: &str) -> Result<(PathBuf, String)> {
    let p = Path::new(dest);
    if !p.is_absolute() {
        bail!("the target path must be absolute");
    }
    let mut parts = Vec::new();
    for c in p.components() {
        match c {
            Component::RootDir => {}
            Component::Normal(n) => parts.push(n),
            _ => bail!("malformed target path"),
        }
    }
    let Some(name) = parts.pop() else {
        bail!("the target path must not be the root directory");
    };
    let name = name
        .to_str()
        .ok_or_else(|| anyhow!("the target path is not UTF-8"))?
        .to_owned();
    Ok((parts.iter().collect(), name))
}

/// 对已打开的目录（或文件）`fchown`。
pub fn set_owner(fd: &OwnedFd, uid: u32, gid: u32) -> Result<()> {
    rustix::fs::fchown(
        fd,
        Some(rustix::fs::Uid::from_raw(uid)),
        Some(rustix::fs::Gid::from_raw(gid)),
    )
    .map_err(std::io::Error::from)
    .context("setting the owner")
}

/// 对已打开的目录 `fchmod`。
pub fn set_mode(dir: &OwnedFd, mode: u32) -> Result<()> {
    rustix::fs::fchmod(dir, mode_of(mode))
        .map_err(std::io::Error::from)
        .context("setting directory permissions")
}

/// 让 `dir` 里的 `name` 成为指向 `target` 的符号链接，原子地替换已有的链接或文件
/// （同目录的临时链接 + `renameat` + fsync 目录）。`name` 是真实目录时报错（由调用方先处理）。
pub fn replace_symlink_at(dir: &OwnedFd, name: &str, target: &str) -> Result<()> {
    check_name(name)?;
    let tmp = format!(".{name}.mastersos-tmp");
    match rustix::fs::unlinkat(dir, tmp.as_str(), AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(e) => return Err(std::io::Error::from(e)).with_context(|| format!("removing {tmp}")),
    }
    rustix::fs::symlinkat(target, dir, tmp.as_str())
        .map_err(std::io::Error::from)
        .with_context(|| format!("creating link {tmp}"))?;
    if let Err(e) = rustix::fs::renameat(dir, tmp.as_str(), dir, name) {
        let _ = rustix::fs::unlinkat(dir, tmp.as_str(), AtFlags::empty());
        return Err(std::io::Error::from(e)).with_context(|| format!("replacing {name}"));
    }
    rustix::fs::fsync(dir)
        .map_err(std::io::Error::from)
        .context("fsync of the directory")
}

/// 读 `dir` 里的符号链接 `name` 指向哪里；不存在或不是链接为 None。
pub fn read_link_at(dir: &OwnedFd, name: &str) -> Option<String> {
    check_name(name).ok()?;
    let t = rustix::fs::readlinkat(dir, name, Vec::new()).ok()?;
    t.into_string().ok()
}

/// 原子地互换 `dir` 里的两个目录项（`renameat2(RENAME_EXCHANGE)`）。
#[cfg(target_os = "linux")]
pub fn exchange_at(dir: &OwnedFd, a: &str, b: &str) -> Result<()> {
    check_name(a)?;
    check_name(b)?;
    rustix::fs::renameat_with(dir, a, dir, b, rustix::fs::RenameFlags::EXCHANGE)
        .map_err(std::io::Error::from)
        .with_context(|| format!("swapping {a} and {b}"))?;
    rustix::fs::fsync(dir)
        .map_err(std::io::Error::from)
        .context("fsync of the directory")
}

/// 开发机（macOS）没有 `RENAME_EXCHANGE`：一律报错。
#[cfg(not(target_os = "linux"))]
pub fn exchange_at(_dir: &OwnedFd, a: &str, b: &str) -> Result<()> {
    bail!("swapping {a} and {b}: atomic swap is only supported on Linux")
}

/// `dir` 的直接子项里属主是 `uid` 的（`fstatat(AT_SYMLINK_NOFOLLOW)` 取属主）整个删掉：目录用
/// [`bounded`] 的有界、不跟随链接、不跨挂载的删除，链接与其他文件只删目录项本身。返回删掉的顶层项数；有删不掉的报错。
/// 名字不必是 UTF-8（访客能在 `/tmp` 里建任意字节的名字）。Task 11 清访客的临时目录用它（复审 T19 F1：原来的递归版
/// 遇到很深的链会耗尽 fd、在第一个错误处停下，访客从此登录不了）。
pub fn remove_owned_tree(dir: &Path, uid: u32) -> Result<usize> {
    bounded::remove_owned_bounded(dir, uid, false)
}

/// 同 [`remove_owned_tree`]，另外对属主不是 `uid`、带 sticky 位的子目录（`/tmp/.X11-unix` 这类：谁都能往里放东西）
/// 再往下做一层。子目录经已打开的 `dir` 的 fd `openat(O_NOFOLLOW|O_DIRECTORY)`，打开之后再 `fstat` 核对属主与 sticky 位，
/// 判断与使用的是同一个目录（复审 T11 M1 与提交安全审查）。返回删掉的项数（两层合计）。
pub fn remove_owned_tree_and_sticky(dir: &Path, uid: u32) -> Result<usize> {
    bounded::remove_owned_bounded(dir, uid, true)
}

/// 往下看一层的条件：真实目录、属主不是 `uid`（`uid` 自己的整棵已经删了）、带 sticky 位。
pub fn sticky_foreign(is_dir: bool, owner: u32, mode: u32, uid: u32) -> bool {
    is_dir && owner != uid && mode & 0o1000 != 0
}

/// 把 `src`（镜像里 root 拥有的目录，例如 `/etc/skel`；它本身可以是链接）下的内容复制进已打开的空目录 `dst`：
/// 目录、普通文件与符号链接（链接本身），权限照搬，属主改为 `uid:gid`。目标一侧逐项
/// `O_CREAT|O_EXCL|O_NOFOLLOW` / `mkdirat`，已存在就报错；源里的其他类型（设备、FIFO）跳过。
pub fn copy_tree_into(src: &Path, dst: &OwnedFd, uid: u32, gid: u32) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    let (owner, group) = (
        Some(rustix::fs::Uid::from_raw(uid)),
        Some(rustix::fs::Gid::from_raw(gid)),
    );
    for e in std::fs::read_dir(src).with_context(|| format!("reading {}", src.display()))? {
        let e = e.with_context(|| format!("reading {}", src.display()))?;
        let name = e.file_name();
        let from = e.path();
        let meta = std::fs::symlink_metadata(&from)
            .with_context(|| format!("checking {}", from.display()))?;
        let mode = mode_of(meta.permissions().mode() & 0o7777);
        let ft = meta.file_type();
        let what = |verb: &str| format!("{verb} {}", Path::new(&name).display());
        if ft.is_dir() {
            rustix::fs::mkdirat(dst, name.as_os_str(), mode_of(0o700))
                .map_err(std::io::Error::from)
                .with_context(|| what("creating directory"))?;
            let sub = open_subdir(dst, name.as_os_str(), false)?;
            rustix::fs::fchown(&sub, owner, group)
                .map_err(std::io::Error::from)
                .with_context(|| what("setting the owner"))?;
            copy_tree_into(&from, &sub, uid, gid)?;
            rustix::fs::fchmod(&sub, mode)
                .map_err(std::io::Error::from)
                .with_context(|| what("setting permissions"))?;
        } else if ft.is_file() {
            let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
            let mut input = File::from(
                rustix::fs::open(&from, flags, Mode::empty())
                    .map_err(std::io::Error::from)
                    .with_context(|| format!("opening {}", from.display()))?,
            );
            let flags =
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let mut out = File::from(
                rustix::fs::openat(dst, name.as_os_str(), flags, mode_of(0o600))
                    .map_err(std::io::Error::from)
                    .with_context(|| what("creating"))?,
            );
            std::io::copy(&mut input, &mut out).with_context(|| what("writing"))?;
            rustix::fs::fchown(&out, owner, group)
                .map_err(std::io::Error::from)
                .with_context(|| what("setting the owner"))?;
            rustix::fs::fchmod(&out, mode)
                .map_err(std::io::Error::from)
                .with_context(|| what("setting permissions"))?;
        } else if ft.is_symlink() {
            let target = std::fs::read_link(&from)
                .with_context(|| format!("reading link {}", from.display()))?;
            rustix::fs::symlinkat(&target, dst, name.as_os_str())
                .map_err(std::io::Error::from)
                .with_context(|| what("creating link"))?;
            rustix::fs::chownat(
                dst,
                name.as_os_str(),
                owner,
                group,
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(std::io::Error::from)
            .with_context(|| what("setting the owner"))?;
        } else if ft.is_fifo() || ft.is_socket() || ft.is_block_device() || ft.is_char_device() {
            continue;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    fn perm(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn open_dir_creates_missing_levels() {
        let root = tempfile::tempdir().unwrap();
        let fd = open_dir(root.path(), Path::new("a/b/c"), true).unwrap();
        assert!(root.path().join("a/b/c").is_dir());
        assert!(write_at(&fd, "f", b"x", 0o644).unwrap());
        assert_eq!(fs::read(root.path().join("a/b/c/f")).unwrap(), b"x");
        // 不创建时，缺的一级是 NotFound。
        assert!(open_dir(root.path(), Path::new("a/zz"), false).is_err());
        assert!(!root.path().join("a/zz").exists());
        // 空的 rel 是根本身。
        let fd = open_dir(root.path(), Path::new(""), false).unwrap();
        assert_eq!(list_at(&fd).unwrap(), vec!["a"]);
    }

    #[test]
    fn open_dir_rejects_non_canonical_rel() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("a/b")).unwrap();
        let e = open_dir(root.path(), Path::new("/a"), true).unwrap_err();
        assert!(format!("{e:#}").contains("must not start with /"), "{e:#}");
        for bad in ["a/../a", "..", "a/./b", "./a"] {
            let e = open_dir(root.path(), Path::new(bad), true).unwrap_err();
            assert!(format!("{e:#}").contains("malformed"), "{bad}: {e:#}");
        }
    }

    #[test]
    fn open_dir_refuses_symlink_in_middle() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), root.path().join("opt")).unwrap();
        for create in [true, false] {
            let e = open_dir(root.path(), Path::new("opt/x"), create).unwrap_err();
            assert!(format!("{e:#}").contains("symlink"), "{e:#}");
        }
        // 链接在最后一级也一样。
        let e = open_dir(root.path(), Path::new("opt"), false).unwrap_err();
        assert!(format!("{e:#}").contains("symlink"), "{e:#}");
        assert!(!outside.path().join("x").exists());
    }

    #[test]
    fn write_at_refuses_symlink_leaf() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim");
        fs::write(&victim, b"keep").unwrap();
        symlink(&victim, root.path().join("a")).unwrap();
        let dir = open_dir(root.path(), Path::new(""), false).unwrap();
        let e = write_at(&dir, "a", b"new", 0o644).unwrap_err();
        assert!(format!("{e:#}").contains("symlink"), "{e:#}");
        let e = read_at(&dir, "a").unwrap_err();
        assert!(format!("{e:#}").contains("symlink"), "{e:#}");
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        assert!(fs::symlink_metadata(root.path().join("a"))
            .unwrap()
            .file_type()
            .is_symlink());
        // 指向不存在目标的悬空链接也不行。
        symlink(outside.path().join("nope"), root.path().join("b")).unwrap();
        let e = write_at(&dir, "b", b"new", 0o644).unwrap_err();
        assert!(format!("{e:#}").contains("symlink"), "{e:#}");
        assert!(!outside.path().join("nope").exists());
    }

    #[test]
    fn write_at_reports_unchanged() {
        let root = tempfile::tempdir().unwrap();
        let dir = open_dir(root.path(), Path::new(""), false).unwrap();
        assert!(write_at(&dir, "a", b"hello", 0o644).unwrap());
        let p = root.path().join("a");
        assert_eq!(perm(&p), 0o644);
        let ino = fs::metadata(&p).unwrap().ino();
        assert!(!write_at(&dir, "a", b"hello", 0o644).unwrap());
        assert_eq!(fs::metadata(&p).unwrap().ino(), ino);
        assert_eq!(read_at(&dir, "a").unwrap().as_deref(), Some(&b"hello"[..]));
        assert_eq!(read_at(&dir, "missing").unwrap(), None);
        // 内容不同则替换。
        assert!(write_at(&dir, "a", b"other", 0o644).unwrap());
        assert_eq!(fs::read(&p).unwrap(), b"other");
        assert_eq!(
            list_at(&dir).unwrap(),
            vec!["a"],
            "no temporary file left behind"
        );
    }

    #[test]
    fn write_at_fixes_mode_only_change() {
        let root = tempfile::tempdir().unwrap();
        let dir = open_dir(root.path(), Path::new(""), false).unwrap();
        assert!(write_at(&dir, "a", b"psk", 0o644).unwrap());
        assert!(write_at(&dir, "a", b"psk", 0o600).unwrap());
        assert_eq!(perm(&root.path().join("a")), 0o600);
        assert!(!write_at(&dir, "a", b"psk", 0o600).unwrap());
    }

    #[test]
    fn write_at_leaves_no_tmp_on_error() {
        let root = tempfile::tempdir().unwrap();
        let ro = root.path().join("ro");
        fs::create_dir(&ro).unwrap();
        fs::write(ro.join("a"), b"old").unwrap();
        fs::set_permissions(&ro, fs::Permissions::from_mode(0o555)).unwrap();
        // 断言失败也要把权限改回来，免得 tempdir 清理时删不掉。
        struct Restore<'a>(&'a Path);
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                let _ = fs::set_permissions(self.0, fs::Permissions::from_mode(0o755));
            }
        }
        let _restore = Restore(&ro);
        // root 不受目录权限限制，这个场景测不出来。
        if fs::write(ro.join("probe"), b"").is_ok() {
            eprintln!("running as root, skipping");
            return;
        }
        let dir = open_dir(root.path(), Path::new("ro"), false).unwrap();
        assert!(write_at(&dir, "a", b"new", 0o644).is_err());
        assert_eq!(list_at(&dir).unwrap(), vec!["a"]);
        assert_eq!(fs::read(ro.join("a")).unwrap(), b"old");
    }

    #[test]
    fn write_at_rewrites_on_size_change_with_same_mode() {
        let root = tempfile::tempdir().unwrap();
        let dir = open_dir(root.path(), Path::new(""), false).unwrap();
        assert!(write_at(&dir, "a", b"short", 0o644).unwrap());
        assert!(write_at(&dir, "a", b"longer content", 0o644).unwrap());
        assert_eq!(fs::read(root.path().join("a")).unwrap(), b"longer content");
    }

    #[test]
    fn tmp_file_dropped_before_commit_is_removed() {
        let root = tempfile::tempdir().unwrap();
        let dir = open_dir(root.path(), Path::new(""), false).unwrap();
        // 上次残留的临时文件被替换掉。
        fs::write(root.path().join(".a.mastersos-tmp"), b"stale").unwrap();
        let mut t = TmpFile::create(&dir, "a", 0o640).unwrap();
        t.write_all(b"half").unwrap();
        assert_eq!(perm(&root.path().join(".a.mastersos-tmp")), 0o640);
        drop(t);
        assert!(list_at(&dir).unwrap().is_empty());
    }

    #[test]
    fn swapped_parent_after_open_is_not_followed() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let fd = open_dir(root.path(), Path::new("opt/x"), true).unwrap();
        fs::rename(root.path().join("opt/x"), root.path().join("opt/x.moved")).unwrap();
        symlink(outside.path(), root.path().join("opt/x")).unwrap();
        assert!(write_at(&fd, "a", b"data", 0o644).unwrap());
        assert_eq!(
            fs::read(root.path().join("opt/x.moved/a")).unwrap(),
            b"data"
        );
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
        remove_at(&fd, "a").unwrap();
        assert!(!root.path().join("opt/x.moved/a").exists());
    }

    #[test]
    fn remove_at_handles_missing_and_symlink() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("v"), b"keep").unwrap();
        symlink(outside.path().join("v"), root.path().join("l")).unwrap();
        fs::write(root.path().join("f"), b"x").unwrap();
        let dir = open_dir(root.path(), Path::new(""), false).unwrap();
        remove_at(&dir, "missing").unwrap();
        let e = remove_at(&dir, "l").unwrap_err();
        assert!(format!("{e:#}").contains("symlink"), "{e:#}");
        assert!(outside.path().join("v").exists());
        remove_at(&dir, "f").unwrap();
        assert_eq!(list_at(&dir).unwrap(), vec!["l"]);
        for bad in ["", ".", "..", "a/b"] {
            assert!(remove_at(&dir, bad).is_err(), "{bad:?}");
            assert!(write_at(&dir, bad, b"", 0o644).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn list_at_is_sorted_without_dots() {
        let root = tempfile::tempdir().unwrap();
        for n in ["c", "a", "b"] {
            fs::write(root.path().join(n), b"").unwrap();
        }
        fs::create_dir(root.path().join("d")).unwrap();
        let dir = open_dir(root.path(), Path::new(""), false).unwrap();
        assert_eq!(list_at(&dir).unwrap(), vec!["a", "b", "c", "d"]);
    }

    #[test]
    fn split_abs_rejects_non_canonical() {
        assert_eq!(
            split_abs("/etc/x").unwrap(),
            (PathBuf::from("etc"), "x".to_owned())
        );
        assert_eq!(split_abs("/x").unwrap(), (PathBuf::new(), "x".to_owned()));
        for bad in ["etc/x", "/etc/../x", "/", "/.."] {
            assert!(split_abs(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn set_mode_tightens_dir() {
        let root = tempfile::tempdir().unwrap();
        let p = root.path().join("state");
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        let dir = open_dir(root.path(), Path::new("state"), false).unwrap();
        set_mode(&dir, 0o700).unwrap();
        assert_eq!(perm(&p), 0o700);
    }

    #[test]
    fn remove_tree_at_removes_nested_without_following_links() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("keep"), b"x").unwrap();
        let t = root.path().join("t");
        fs::create_dir_all(t.join("a/b/c")).unwrap();
        fs::write(t.join("a/b/c/f"), b"x").unwrap();
        fs::write(t.join("top"), b"x").unwrap();
        symlink(outside.path(), t.join("a/link-dir")).unwrap();
        symlink(outside.path().join("keep"), t.join("link-file")).unwrap();
        let dir = open_dir(root.path(), Path::new(""), false).unwrap();
        remove_tree_at(&dir, "t").unwrap();
        assert!(!t.exists());
        assert!(
            outside.path().join("keep").exists(),
            "does not follow links inside"
        );
        // 不存在算成功；普通文件也删
        remove_tree_at(&dir, "t").unwrap();
        fs::write(root.path().join("f"), b"x").unwrap();
        remove_tree_at(&dir, "f").unwrap();
        assert!(!root.path().join("f").exists());
        // 本身是链接：报错、不碰链接指向的目录
        symlink(outside.path(), root.path().join("l")).unwrap();
        let e = remove_tree_at(&dir, "l").unwrap_err();
        assert!(format!("{e:#}").contains("symlink"), "{e:#}");
        assert!(outside.path().join("keep").exists());
    }

    #[test]
    fn open_child_dir_and_open_dir_at() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("d")).unwrap();
        symlink(outside.path(), root.path().join("l")).unwrap();
        let dir = open_dir(root.path(), Path::new(""), false).unwrap();
        assert!(open_child_dir(&dir, "missing").unwrap().is_none());
        let d = open_child_dir(&dir, "d").unwrap().unwrap();
        let e = open_child_dir(&dir, "l").unwrap_err();
        assert!(format!("{e:#}").contains("symlink"), "{e:#}");
        let deep = open_dir_at(&d, Path::new("x/y"), true).unwrap();
        assert!(write_at(&deep, "f", b"1", 0o644).unwrap());
        assert!(root.path().join("d/x/y/f").exists());
        let e = open_dir_at(&dir, Path::new("l/x"), true).unwrap_err();
        assert!(format!("{e:#}").contains("symlink"), "{e:#}");
        assert!(open_dir_at(&dir, Path::new("../x"), true).is_err());
        rename_at(&dir, "d", "e").unwrap();
        assert!(root.path().join("e/x/y/f").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exchange_at_swaps_atomically() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("a")).unwrap();
        fs::create_dir(root.path().join("b")).unwrap();
        fs::write(root.path().join("a/mark-a"), b"").unwrap();
        fs::write(root.path().join("b/mark-b"), b"").unwrap();
        let dir = open_dir(root.path(), Path::new(""), false).unwrap();
        exchange_at(&dir, "a", "b").unwrap();
        assert!(root.path().join("a/mark-b").exists());
        assert!(root.path().join("b/mark-a").exists());
        assert!(!root.path().join("a/mark-a").exists());
    }

    #[test]
    fn remove_owned_tree_does_not_follow_links() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("keep"), b"x").unwrap();
        fs::create_dir(outside.path().join("keepdir")).unwrap();
        fs::write(outside.path().join("keepdir/inner"), b"x").unwrap();
        let tmp = root.path().join("tmp");
        fs::create_dir_all(tmp.join("d/sub")).unwrap();
        fs::write(tmp.join("d/sub/f"), b"x").unwrap();
        symlink(outside.path().join("keep"), tmp.join("d/sub/link")).unwrap();
        symlink(outside.path().join("keepdir"), tmp.join("d/linkdir")).unwrap();
        // 顶层的链接：删链接本身，不碰它指向的东西
        symlink(outside.path().join("keepdir"), tmp.join("toplink")).unwrap();
        fs::write(tmp.join("f"), b"x").unwrap();
        let me = rustix::process::geteuid().as_raw();
        assert_eq!(remove_owned_tree(&tmp, me).unwrap(), 3);
        assert!(tmp.exists(), "the directory itself stays");
        assert_eq!(fs::read_dir(&tmp).unwrap().count(), 0);
        assert!(outside.path().join("keep").exists());
        assert!(outside.path().join("keepdir/inner").exists());
        // 不存在的目录报错（调用方决定要不要跳过）；目录本身是链接也报错
        assert!(remove_owned_tree(&root.path().join("missing"), me).is_err());
        symlink(outside.path(), root.path().join("ltmp")).unwrap();
        let e = remove_owned_tree(&root.path().join("ltmp"), me).unwrap_err();
        assert!(format!("{e:#}").contains("symlink"), "{e:#}");
        assert!(outside.path().join("keep").exists());
    }

    /// 复审 T19 F1：访客在 /var/tmp 里建的 2000 层深的链（超过 1024 的 fd 软上限）也删得干净，暂存目录不留下。
    #[test]
    fn remove_owned_tree_handles_deep_chains() {
        use rustix::fs::{mkdirat, openat, Mode, OFlags};
        let root = tempfile::tempdir().unwrap();
        let tmp = root.path().join("tmp");
        fs::create_dir_all(tmp.join("chain")).unwrap();
        let mut cur = openat(
            rustix::fs::CWD,
            tmp.join("chain"),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        for _ in 0..2000 {
            mkdirat(&cur, "d", Mode::from_raw_mode(0o755)).unwrap();
            cur = openat(&cur, "d", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap();
        }
        drop(cur);
        let me = rustix::process::geteuid().as_raw();
        assert_eq!(remove_owned_tree_and_sticky(&tmp, me).unwrap(), 1);
        assert_eq!(
            fs::read_dir(&tmp).unwrap().count(),
            0,
            "the staging directory is removed too"
        );
    }

    /// 复审 T19 F1：别人抢先放的同前缀的东西（链接、不是 0700 的目录）不当作暂存目录；链接不跟随。
    #[test]
    fn planted_hold_names_are_not_trusted() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("keep"), b"x").unwrap();
        let tmp = root.path().join("tmp");
        fs::create_dir_all(&tmp).unwrap();
        symlink(outside.path(), tmp.join(".mastersos-rm-0000000000000000")).unwrap();
        let open = tmp.join(".mastersos-rm-1111111111111111");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
        fs::write(open.join("x"), b"x").unwrap();
        let me = rustix::process::geteuid().as_raw();
        let other = if me == 54_321 { 54_322 } else { 54_321 };
        // 不是「本进程的 0700 目录」：不去删空它们
        remove_owned_tree(&tmp, other).unwrap();
        assert!(open.join("x").exists());
        assert!(outside.path().join("keep").exists());
        // 属主是这个 uid 时作为普通的顶层项删：链接只删链接本身
        remove_owned_tree(&tmp, me).unwrap();
        assert!(outside.path().join("keep").exists());
        assert_eq!(fs::read_dir(&tmp).unwrap().count(), 0);
    }

    #[test]
    fn remove_owned_tree_skips_other_owners() {
        use std::os::unix::ffi::OsStrExt;
        let root = tempfile::tempdir().unwrap();
        let tmp = root.path().join("tmp");
        fs::create_dir_all(tmp.join("d")).unwrap();
        fs::write(tmp.join("d/f"), b"x").unwrap();
        fs::write(tmp.join("f"), b"x").unwrap();
        // 不是 UTF-8 的名字也照删（macOS 的 APFS 不收这种名字，只在 Linux 上造）
        let n = if cfg!(target_os = "linux") {
            fs::write(tmp.join(OsStr::from_bytes(b"bad-\xff")), b"x").unwrap();
            3
        } else {
            2
        };
        let me = rustix::process::geteuid().as_raw();
        // 测试里 chown 不了：用一个不存在的 uid 对照——属主不是它的一个都不动
        let other = if me == 54_321 { 54_322 } else { 54_321 };
        assert_eq!(remove_owned_tree(&tmp, other).unwrap(), 0);
        assert_eq!(fs::read_dir(&tmp).unwrap().count(), n);
        assert!(tmp.join("d/f").exists());
        assert_eq!(remove_owned_tree(&tmp, me).unwrap(), n);
        assert_eq!(fs::read_dir(&tmp).unwrap().count(), 0);
    }

    #[test]
    fn copy_tree_into_copies_modes_and_links() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        fs::create_dir(src.path().join(".config")).unwrap();
        fs::write(src.path().join(".config/x.conf"), b"conf").unwrap();
        fs::write(src.path().join(".bashrc"), b"rc").unwrap();
        fs::set_permissions(
            src.path().join(".bashrc"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        fs::set_permissions(
            src.path().join(".config"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        symlink("/nonexistent/target", src.path().join("link")).unwrap();
        // 源本身是链接（真机的 /etc/skel 指向 factory）
        let via = tempfile::tempdir().unwrap();
        symlink(src.path(), via.path().join("skel")).unwrap();
        let me = rustix::process::geteuid().as_raw();
        let mg = rustix::process::getegid().as_raw();
        let d = open_dir(dst.path(), Path::new(""), false).unwrap();
        copy_tree_into(&via.path().join("skel"), &d, me, mg).unwrap();
        assert_eq!(
            fs::read(dst.path().join(".config/x.conf")).unwrap(),
            b"conf"
        );
        assert_eq!(fs::read(dst.path().join(".bashrc")).unwrap(), b"rc");
        assert_eq!(perm(&dst.path().join(".bashrc")), 0o640);
        assert_eq!(perm(&dst.path().join(".config")), 0o700);
        assert_eq!(
            fs::read_link(dst.path().join("link")).unwrap(),
            Path::new("/nonexistent/target")
        );
        assert_eq!(fs::metadata(dst.path().join(".bashrc")).unwrap().uid(), me);
        // 目标里已有同名项：报错，不覆盖（哪一项先撞上取决于目录顺序）
        let e = copy_tree_into(src.path(), &d, me, mg).unwrap_err();
        assert!(format!("{e:#}").contains("exists"), "{e:#}");
        assert_eq!(fs::read(dst.path().join(".bashrc")).unwrap(), b"rc");
    }

    #[test]
    fn take_at_is_one_shot() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("m"), b"").unwrap();
        let d = open_dir(root.path(), Path::new(""), false).unwrap();
        assert!(take_at(&d, "m", "taken").unwrap());
        assert!(
            !take_at(&d, "m", "taken").unwrap(),
            "second take: already gone"
        );
        assert!(!root.path().join("m").exists());
        assert!(root.path().join("taken").exists());
        assert!(mtime_at(&d, "taken").unwrap().is_some());
        assert!(mtime_at(&d, "m").unwrap().is_none());
    }

    #[test]
    fn sticky_foreign_rule() {
        assert!(sticky_foreign(true, 0, 0o41777, 1999));
        assert!(
            !sticky_foreign(true, 0, 0o40755, 1999),
            "no sticky bit: the guest cannot put anything there"
        );
        assert!(
            !sticky_foreign(true, 1999, 0o41777, 1999),
            "owned by the guest: the whole tree is already removed"
        );
        assert!(!sticky_foreign(false, 0, 0o101777, 1999), "not a directory");
    }

    /// 带 sticky 位的子目录：属主是 `uid` 自己的整棵删（第一层就删了）；链接不跟随。
    #[test]
    fn remove_owned_tree_and_sticky_does_not_follow_links() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("keep"), b"x").unwrap();
        let tmp = root.path().join("tmp");
        fs::create_dir_all(tmp.join("s")).unwrap();
        fs::set_permissions(tmp.join("s"), fs::Permissions::from_mode(0o1777)).unwrap();
        fs::write(tmp.join("s/f"), b"x").unwrap();
        symlink(outside.path(), tmp.join("l")).unwrap();
        let me = rustix::process::geteuid().as_raw();
        let other = if me == 54_321 { 54_322 } else { 54_321 };
        assert_eq!(remove_owned_tree_and_sticky(&tmp, other).unwrap(), 0);
        assert!(tmp.join("s/f").exists());
        assert_eq!(remove_owned_tree_and_sticky(&tmp, me).unwrap(), 2);
        assert!(outside.path().join("keep").exists());
    }

    #[test]
    fn open_mount_target_refuses_symlinks_anywhere() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("tmp/g/x/usr")).unwrap();
        fs::create_dir_all(outside.path().join("usr")).unwrap();
        assert!(open_mount_target(root.path(), Path::new("tmp/g/x/usr")).is_ok());
        // 中间一级换成指向外面的链接：不跟随
        fs::rename(
            root.path().join("tmp/g/x"),
            root.path().join("tmp/g/x.real"),
        )
        .unwrap();
        symlink(outside.path(), root.path().join("tmp/g/x")).unwrap();
        let e = open_mount_target(root.path(), Path::new("tmp/g/x/usr")).unwrap_err();
        assert!(format!("{e:#}").contains("symlink"), "{e:#}");
        // 最后一级是链接：同样拒绝
        symlink(outside.path(), root.path().join("tmp/last")).unwrap();
        let e = open_mount_target(root.path(), Path::new("tmp/last")).unwrap_err();
        assert!(format!("{e:#}").contains("symlink"), "{e:#}");
        assert!(open_mount_target(root.path(), Path::new("tmp/missing")).is_err());
    }

    #[test]
    fn touch_at_sets_mtime_now() {
        let root = tempfile::tempdir().unwrap();
        let f = root.path().join("m");
        fs::write(&f, b"").unwrap();
        let old = rustix::fs::Timespec {
            tv_sec: 1_000_000,
            tv_nsec: 0,
        };
        rustix::fs::utimensat(
            rustix::fs::CWD,
            &f,
            &rustix::fs::Timestamps {
                last_access: old,
                last_modification: old,
            },
            AtFlags::empty(),
        )
        .unwrap();
        let d = open_dir(root.path(), Path::new(""), false).unwrap();
        touch_at(&d, "m").unwrap();
        let age = std::time::SystemTime::now()
            .duration_since(mtime_at(&d, "m").unwrap().unwrap())
            .unwrap_or_default();
        assert!(age < std::time::Duration::from_secs(60), "{age:?}");
    }
}
