//! 锁住的会话（`learning`、旧的浏览器模式）的执行层堵法（Ruling T13 carry XDG）：`Hidden=true` 的覆盖只管搜索与
//! Dock——`~/.local/share`（`XDG_DATA_HOME`）永远排在 `XDG_DATA_DIRS` 前面，学生自己写一个 `.desktop` 就能把被藏的程序
//! 再叫出来。所以锁住的会话里把一个只弹提示「This app is not available on this device」、以非 0 退出的桩
//! （[`STUB`]）bind-mount 到镜像里终端、文件管理器、设置的可执行文件上（[`TARGETS`]，只挂镜像里实际有的）；
//! `full` 卸掉。`/usr` 是只读的 erofs（合并了 sysext 时是它上面的 overlay），bind 不改镜像。管理员在锁住的
//! 机器上同样用不了这几个程序（推车机，可接受）。
//!
//! - **挂在 PID 1 的挂载命名空间里**：agent 的单元有 `PrivateTmp=yes`，自己的命名空间里挂的东西系统看不见
//!   （`chrome_sysext::refresh_cmd` 同一个坑），所以经 `nsenter --mount=/proc/1/ns/mnt` 跑 `mount`、`umount`。
//!   agent 的命名空间是 PID 1 那边的 slave，那边挂上的会传过来，所以下面的「挂上了没有」在 agent 里看就对。
//! - **按内容判断挂上了没有**，不看挂载表、也不看 inode：目标路径读出来与桩的内容逐字节相同才算堵住（真程序不会与
//!   一个 shell 脚本相同）。挂载表不行：sysext 合并时 overlay 盖在 `/usr` 上，原来挂在 erofs 的文件上的 bind 被盖住、
//!   表里却还在。(设备, inode) 也不行（VM 165 实测）：合并了 sysext 的 `/usr` 是 overlay，桩自己的路径报 overlay 的
//!   `st_dev`，挂着桩的路径（bind 的是下层的文件）`st_ino` 相同、`st_dev` 却是下层的。卸载同理：读出来还是桩就 `umount -l` 一层，最多 [`MAX_LAYERS`] 层。
//! - **按路径操作是可以的**：这些路径都在 root 所有、只读的 `/usr` 下，普通用户换不了其中任何一级（与 `safefs`
//!   防的「用户可写目录里换链接」不是一回事）。目标本身是符号链接的不挂（`mount --bind` 会跟随链接，挂到链接指向的
//!   文件上；那个文件若也在 [`TARGETS`] 里，会被单独挂上）。
//! - **sysext 刷新后再挂**：`systemd-sysext refresh`（Chrome 更新后）换掉 `/usr` 上的 overlay，挂在旧 overlay 上的 bind
//!   随之消失。镜像给 `systemd-sysext.service` 加了 drop-in，合并与刷新之后跑 `mastersos-agent exec-block`（[`sync_main`]），
//!   按盘上的模式（[`MODE_FILE`]）重新挂上，不必等下一轮应用（最长 6 小时）。`gdm.service` 的 `ExecStartPre=` 与
//!   `apply-local` 一开始也跑它：`apply-local` 失败或超时、sysext 没跑，GDM 之前照样挂着（复审 T13 发现 4）。
//! - **与应用之间持同一把锁**（[`LOCK_FILE`]，复审 T13 发现 1）：应用持锁先写模式、再挂；`exec-block` 持锁之后才读模式。
//!   sysext 刷新与应用同时发生时，后跑的那一方总按最新的模式收敛。

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};

use super::SysPaths;
use crate::runner::{run_ok, Cmd, RealRunner, Runner};

/// 桩（镜像里的 shell 脚本，`mkosi.extra/usr/lib/mastersos/interface-denied`）。
pub const STUB: &str = "/usr/lib/mastersos/interface-denied";

/// 锁住的会话里堵住的可执行文件：终端、文件管理器、设置。镜像里没有的跳过（换了终端的发行版也不出错）。
pub const TARGETS: &[&str] = &[
    // gnome-terminal：客户端（Debian 把真身叫 .real，/usr/bin/gnome-terminal 是包装脚本）与真正开窗口的服务端
    "/usr/bin/gnome-terminal",
    "/usr/bin/gnome-terminal.real",
    "/usr/bin/gnome-terminal.wrapper",
    "/usr/libexec/gnome-terminal-server",
    // 新的 GNOME 终端
    "/usr/bin/ptyxis",
    "/usr/libexec/ptyxis-agent",
    "/usr/bin/kgx",
    "/usr/bin/xterm",
    // 文件管理器
    "/usr/bin/nautilus",
    // 设置
    "/usr/bin/gnome-control-center",
];

/// 同一路径上最多卸几层（并发的两次应用可能叠挂两层）。
pub const MAX_LAYERS: usize = 4;

/// 每条 mount / umount 的超时（复审 T13 R1）：持锁的一方即使碰上卡住的命令，也远在 GDM 的启动时限之内放锁。
pub const CMD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// `exec-block` 等锁最多这么久（复审 T13 R1）：GDM 的 `ExecStartPre` 与 sysext 的钩子都走它，不能无限等。
pub const SYNC_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// `nsenter` 进 PID 1 的挂载命名空间跑 `args`。
fn host_cmd(args: &[&str]) -> Cmd {
    let mut all = vec!["--mount=/proc/1/ns/mnt", "--"];
    all.extend_from_slice(args);
    Cmd::new("nsenter", &all).timeout(CMD_TIMEOUT)
}

/// `root` 下的绝对路径 `abs`（测试里 `root` 是临时目录；命令里永远用 `abs` 本身）。
fn under(root: &Path, abs: &str) -> PathBuf {
    root.join(abs.trim_start_matches('/'))
}

/// 这条路径（跟随链接：要的是它实际打开的文件）读出来就是桩的内容。读不了算不是。
fn is_stub(p: &Path, stub: &[u8]) -> bool {
    if std::fs::metadata(p).map(|m| m.len()).ok() != u64::try_from(stub.len()).ok() {
        return false;
    }
    let mut buf = Vec::with_capacity(stub.len());
    std::fs::File::open(p)
        .and_then(|f| f.take(stub.len() as u64 + 1).read_to_end(&mut buf))
        .is_ok()
        && buf == stub
}

/// 目标是镜像里实际有的普通文件（不是符号链接）。
fn present(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_file())
}

/// 收敛到期望的状态：`block` 时 [`TARGETS`] 里镜像有的每一个都解析到桩，否则没有一个解析到桩。已经是期望的状态时
/// 什么命令都不跑。逐个目标做，某一个失败不挡其余的；失败的汇总成一个错误（只有路径与退出码）。
pub fn ensure(root: &Path, runner: &dyn Runner, block: bool) -> Result<()> {
    let path = under(root, STUB);
    let stub = if present(&path) {
        Some(std::fs::read(&path).with_context(|| format!("读取 {STUB}"))?)
    } else {
        None
    };
    if block && stub.is_none() {
        bail!("镜像里没有 {STUB}，堵不了终端、文件管理器与设置");
    }
    let mut errs = Vec::new();
    for t in TARGETS {
        let p = under(root, t);
        let r = match (&stub, block) {
            (Some(s), true) => bind(runner, &p, t, s),
            (Some(s), false) => unbind(runner, &p, t, s),
            // 没有桩就不可能读出桩（旧镜像、或桩被换掉了）；没有可卸的。
            (None, _) => Ok(()),
        };
        if let Err(e) = r {
            errs.push(format!("{e:#}"));
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        bail!("{}", errs.join("；"))
    }
}

fn bind(runner: &dyn Runner, p: &Path, abs: &str, stub: &[u8]) -> Result<()> {
    if !present(p) || is_stub(p, stub) {
        return Ok(());
    }
    run_ok(runner, host_cmd(&["mount", "--bind", STUB, abs]))
        .with_context(|| format!("把桩挂到 {abs} 上"))?;
    Ok(())
}

fn unbind(runner: &dyn Runner, p: &Path, abs: &str, stub: &[u8]) -> Result<()> {
    if !present(p) {
        // 符号链接本身从来不挂（见 `bind`）：它读出桩是因为它指向的文件挂着，那个文件单独卸
        // （经链接 umount 会卸掉链接指向的那个）。
        return Ok(());
    }
    for _ in 0..MAX_LAYERS {
        if !is_stub(p, stub) {
            return Ok(());
        }
        run_ok(runner, host_cmd(&["umount", "-l", abs]))
            .with_context(|| format!("从 {abs} 上卸掉桩"))?;
    }
    if is_stub(p, stub) {
        bail!("{abs} 卸了 {MAX_LAYERS} 层还是桩");
    }
    Ok(())
}

/// The wanted mode, in this file under `var_dir` (0700). It still holds the old words: `browser\n`
/// (blocked: `learning` and the old browser mode) or `desktop\n` (open: `full`); `learning\n` and
/// `full\n` are also accepted when read.
///
/// Why the old words are still written: an A/B rollback to an image from before configs boots
/// an agent (and `exec-block`) that only knows `browser`/`desktop`. It would read `learning` as
/// unreadable and mount no stubs, failing open, and keep doing so for as long as it cannot
/// parse the cached new-shape bundle to rewrite the file.
///
/// Why it is not in `system-state.json`: that file is saved only after a whole apply run
/// (review T13 finding 1), while this one is written under the lock before any mount changes.
pub const MODE_FILE: &str = "exec-block-mode";
/// The same mode for the user session, in this file under `public_dir` (0644): `learning\n` or
/// `full\n`. `/usr/lib/mastersos/browser-wait` reads it (`MODE_FILE` is in the 0700 var dir);
/// a missing file means no bundle yet, which the session treats as `full`.
pub const SESSION_MODE_FILE: &str = "session-mode";
/// agent 与 `exec-block` 之间的锁（`/run` 在 agent 的 PrivateTmp 之外，两边看到的是同一个文件）。
pub const LOCK_DIR: &str = "run/mastersos";
pub const LOCK_FILE: &str = "exec-block.lock";

fn lock_file(root: &Path) -> Result<std::os::fd::OwnedFd> {
    use rustix::fs::{Mode, OFlags};
    let dir = crate::safefs::open_dir(root, Path::new(LOCK_DIR), true)?;
    let fd = rustix::fs::openat(
        &dir,
        LOCK_FILE,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("打开 /{LOCK_DIR}/{LOCK_FILE}"))?;
    Ok(fd)
}

/// 拿锁（阻塞；`apply` 用：它在应用任务的线程里，没有人在前台等它）。返回的 fd 关掉就放锁。
pub(crate) fn lock(root: &Path) -> Result<std::os::fd::OwnedFd> {
    let fd = lock_file(root)?;
    rustix::fs::flock(&fd, rustix::fs::FlockOperation::LockExclusive)
        .map_err(std::io::Error::from)
        .context("锁 exec-block")?;
    Ok(fd)
}

/// 最多等 `wait` 拿锁；等不到返回 `None`。
fn lock_bounded(root: &Path, wait: std::time::Duration) -> Result<Option<std::os::fd::OwnedFd>> {
    let fd = lock_file(root)?;
    let end = std::time::Instant::now() + wait;
    loop {
        match rustix::fs::flock(&fd, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(Some(fd)),
            Err(rustix::io::Errno::WOULDBLOCK) if std::time::Instant::now() < end => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(rustix::io::Errno::WOULDBLOCK) => return Ok(None),
            Err(e) => return Err(std::io::Error::from(e)).context("锁 exec-block"),
        }
    }
}

pub(crate) fn write_mode(paths: &SysPaths, block: bool) -> Result<()> {
    let dir = super::var_dir(paths)?;
    // The old vocabulary on purpose: see MODE_FILE.
    let text: &[u8] = if block { b"browser\n" } else { b"desktop\n" };
    crate::safefs::write_at(&dir, MODE_FILE, text, 0o600)
        .with_context(|| format!("写入 {MODE_FILE}"))?;
    // The session's copy, in the new words: see SESSION_MODE_FILE.
    let public = super::public_dir(paths)?;
    let text: &[u8] = if block { b"learning\n" } else { b"full\n" };
    crate::safefs::write_at(&public, SESSION_MODE_FILE, text, 0o644)
        .with_context(|| format!("write {SESSION_MODE_FILE}"))?;
    Ok(())
}

/// 盘上的模式：`Some(true)` 挡住（`learning`，或旧的 `browser`）、`Some(false)` 放开（`full`，或旧的 `desktop`）；
/// `var_dir` 或文件不存在、内容读不懂都是 `None`。不建目录。
pub fn read_mode(paths: &SysPaths) -> Result<Option<bool>> {
    let dir = match crate::safefs::open_abs_dir(&paths.var_dir, false) {
        Ok(d) => d,
        Err(e) if crate::apply::is_not_found(&e) => return Ok(None),
        Err(e) => return Err(e),
    };
    Ok(match crate::safefs::read_at(&dir, MODE_FILE)?.as_deref() {
        Some(b"learning\n" | b"browser\n") => Some(true),
        Some(b"full\n" | b"desktop\n") => Some(false),
        Some(_) => {
            log::warn!("{MODE_FILE} 的内容读不懂，什么都不做");
            None
        }
        None => None,
    })
}

/// `desktop` 步骤用：持锁，先把模式落盘、再收敛挂载。之后不论谁（sysext 刷新后的 `exec-block`）在什么时候跑，
/// 读到的都不比挂载旧。
///
/// 模式写不进去时（复审 T13 R2）这一轮照样按要的模式收敛，再把写失败报出来：锁住的会话不因磁盘满之类放开。
/// 之后的 `exec-block` 读到的还是旧模式，直到某一轮写成功——错误在回报里看得见。
pub fn apply(paths: &SysPaths, runner: &dyn Runner, block: bool) -> Result<()> {
    let _lock = lock(&paths.root)?;
    let written = write_mode(paths, block);
    let ensured = ensure(&paths.root, runner, block);
    written.context("record the exec-block mode")?;
    ensured
}

/// `exec-block`（sysext 合并、刷新之后；GDM 之前；`apply-local` 一开始）：持锁之后才读盘上的模式（应用正持锁改模式时
/// 等它做完），按它收敛。没有状态（未受管的机器、还没应用过）或读不懂，什么都不做、什么都不建，返回 `None`。
///
/// 等锁最多 [`SYNC_LOCK_WAIT`]（复审 T13 R1）；等不到就记日志、不持锁照样收敛：模式文件总在挂载之前写好、不比挂载旧，
/// `ensure` 按内容判断、幂等，没锁的重叠最多多叠一层（[`MAX_LAYERS`] 兜住），锁住的会话不会因此放开。
pub fn sync(paths: &SysPaths, runner: &dyn Runner) -> Result<Option<bool>> {
    sync_with(paths, runner, SYNC_LOCK_WAIT)
}

pub(crate) fn sync_with(
    paths: &SysPaths,
    runner: &dyn Runner,
    wait: std::time::Duration,
) -> Result<Option<bool>> {
    if !paths.var_dir.is_dir() {
        return Ok(None);
    }
    let _lock = lock_bounded(&paths.root, wait)?;
    if _lock.is_none() {
        log::warn!(
            "exec-block：{} 秒内没等到锁，不持锁照样按盘上的模式收敛",
            wait.as_secs_f32()
        );
        eprintln!("exec-block：没等到锁，不持锁照样收敛");
    }
    let Some(block) = read_mode(paths)? else {
        return Ok(None);
    };
    // 不持锁时只往「挡住」的方向收敛：持锁的一方可能正在切换模式，这时读到的「放开」可能已经过时，
    // 照它卸掉桩就是在锁住的会话里放开（fail open）。挂上多余的桩只是暂时挡住，持锁的一方做完会收敛回来。
    if _lock.is_none() && !block {
        log::warn!(
            "exec-block: no lock and the mode on disk is full; leaving the stubs to the holder"
        );
        return Ok(Some(block));
    }
    ensure(&paths.root, runner, block)?;
    Ok(Some(block))
}

/// `mastersos-agent exec-block`：见 [`sync`]。失败只打到 stderr、退出码 1（单元里都是 `-` 前缀，不挡 sysext 与 GDM）。
pub fn sync_main() -> ExitCode {
    match sync(&SysPaths::default(), &RealRunner) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("exec-block：{e:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::tests::{paths, tmp_root};
    use super::*;
    use crate::runner::{FakeRunner, Output};
    use std::fs;
    use std::sync::Mutex;

    /// 在临时根里模拟 bind mount：`mount --bind S T` 把 T 换成 S 的硬链接（同一 inode，原文件存成 `T.sim-orig`），
    /// `umount -l T` 换回来。命令都记进内层的 FakeRunner；预设的失败（`respond`）优先。
    pub(crate) struct MountSim {
        pub root: PathBuf,
        pub fake: FakeRunner,
        fail: Mutex<Vec<String>>,
    }

    impl MountSim {
        pub(crate) fn new(root: &Path) -> MountSim {
            MountSim {
                root: root.to_path_buf(),
                fake: FakeRunner::new(),
                fail: Mutex::new(Vec::new()),
            }
        }

        /// 以后 `line()` 以此开头的命令失败（退出码 32）。
        pub(crate) fn fail_on(&self, prefix: &str) {
            self.fail.lock().unwrap().push(prefix.into());
        }

        pub(crate) fn calls(&self) -> Vec<String> {
            self.fake.calls()
        }
    }

    impl Runner for MountSim {
        fn run(&self, cmd: &Cmd) -> Result<Output> {
            let line = cmd.line();
            let out = self.fake.run(cmd)?;
            if self
                .fail
                .lock()
                .unwrap()
                .iter()
                .any(|p| line.starts_with(p))
            {
                return Ok(Output::fail(32, "mount: permission denied"));
            }
            let a: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
            match a.as_slice() {
                ["--mount=/proc/1/ns/mnt", "--", "mount", "--bind", s, t] => {
                    let (s, t) = (under(&self.root, s), under(&self.root, t));
                    let orig = t.with_extension("sim-orig");
                    if !orig.exists() {
                        fs::rename(&t, &orig).unwrap();
                    } else {
                        fs::remove_file(&t).unwrap();
                    }
                    fs::hard_link(&s, &t).unwrap();
                }
                ["--mount=/proc/1/ns/mnt", "--", "umount", "-l", t] => {
                    let t = under(&self.root, t);
                    let orig = t.with_extension("sim-orig");
                    if !orig.exists() {
                        return Ok(Output::fail(32, "umount: not mounted"));
                    }
                    fs::remove_file(&t).unwrap();
                    fs::rename(&orig, &t).unwrap();
                }
                _ => {}
            }
            Ok(out)
        }
    }

    /// 临时根里放好桩与几个目标：gnome-terminal-server、nautilus、gnome-control-center 是普通文件，
    /// /usr/bin/gnome-terminal 是指向 .real 的链接（不挂它本身），ptyxis 不存在。
    pub(crate) fn image_root() -> tempfile::TempDir {
        let root = tmp_root();
        let put = |abs: &str, body: &str| {
            let p = under(root.path(), abs);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, body).unwrap();
        };
        put(STUB, "#!/bin/sh\nexit 126\n");
        put("/usr/libexec/gnome-terminal-server", "server");
        put("/usr/bin/gnome-terminal.real", "client");
        put("/usr/bin/nautilus", "nautilus");
        put("/usr/bin/gnome-control-center", "gcc");
        std::os::unix::fs::symlink(
            "gnome-terminal.real",
            under(root.path(), "/usr/bin/gnome-terminal"),
        )
        .unwrap();
        root
    }

    pub(crate) const PRESENT: [&str; 4] = [
        "/usr/bin/gnome-terminal.real",
        "/usr/libexec/gnome-terminal-server",
        "/usr/bin/nautilus",
        "/usr/bin/gnome-control-center",
    ];

    pub(crate) fn is_stub(root: &Path, abs: &str) -> bool {
        let stub = fs::read(under(root, STUB)).unwrap();
        super::is_stub(&under(root, abs), &stub)
    }

    #[test]
    fn browser_mode_binds_stub_over_present_targets_once() {
        let root = image_root();
        let r = MountSim::new(root.path());
        ensure(root.path(), &r, true).unwrap();
        let mut calls = r.calls();
        calls.sort();
        let mut want: Vec<String> = PRESENT
            .iter()
            .map(|t| format!("nsenter --mount=/proc/1/ns/mnt -- mount --bind {STUB} {t}"))
            .collect();
        want.sort();
        assert_eq!(calls, want, "只挂镜像里有的普通文件，不挂链接本身");
        for t in PRESENT {
            assert!(is_stub(root.path(), t), "{t}");
        }
        // 链接解析到 .real，也就解析到桩了。
        assert!(is_stub(root.path(), "/usr/bin/gnome-terminal"));
        // 幂等：再来一次什么命令都不跑。
        ensure(root.path(), &r, true).unwrap();
        assert_eq!(r.calls().len(), PRESENT.len());
    }

    #[test]
    fn desktop_mode_unbinds_and_is_idempotent() {
        let root = image_root();
        let r = MountSim::new(root.path());
        // 本来就没挂：什么都不跑。
        ensure(root.path(), &r, false).unwrap();
        assert!(r.calls().is_empty());
        ensure(root.path(), &r, true).unwrap();
        let n = r.calls().len();
        ensure(root.path(), &r, false).unwrap();
        let calls = r.calls()[n..].to_vec();
        assert_eq!(calls.len(), PRESENT.len(), "{calls:?}");
        assert!(calls
            .iter()
            .all(|c| c.starts_with("nsenter --mount=/proc/1/ns/mnt -- umount -l /usr/")));
        for t in PRESENT {
            assert!(!is_stub(root.path(), t), "{t}");
        }
        assert_eq!(
            fs::read_to_string(under(root.path(), "/usr/bin/nautilus")).unwrap(),
            "nautilus"
        );
        ensure(root.path(), &r, false).unwrap();
        assert_eq!(r.calls().len(), n + PRESENT.len());
    }

    /// sysext 合并后旧的 bind 被盖住：路径解析到的不再是桩，就再挂一次（不看挂载表）。
    #[test]
    fn rebinds_when_target_no_longer_resolves_to_stub() {
        let root = image_root();
        let r = MountSim::new(root.path());
        ensure(root.path(), &r, true).unwrap();
        // 模拟 overlay 盖上来：nautilus 又是原来的文件。
        let p = under(root.path(), "/usr/bin/nautilus");
        fs::remove_file(&p).unwrap();
        fs::rename(p.with_extension("sim-orig"), &p).unwrap();
        let n = r.calls().len();
        ensure(root.path(), &r, true).unwrap();
        assert_eq!(
            r.calls()[n..].to_vec(),
            vec![format!(
                "nsenter --mount=/proc/1/ns/mnt -- mount --bind {STUB} /usr/bin/nautilus"
            )]
        );
    }

    /// VM 165 实测：合并了 sysext 的 /usr（overlay 盖在 erofs 上）里，挂着桩的路径与桩自己的路径 st_ino 相同、st_dev
    /// 不同（overlay 的与下层的）——按 (设备, inode) 认不出桩，浏览器模式每应用一次就多叠一层、桌面模式一层都不卸。
    /// 所以按内容认：路径读出来与桩的内容一样就是桩（真程序不会与一个 shell 脚本字节相同）。
    #[test]
    fn stub_is_recognised_by_content_not_inode() {
        let root = image_root();
        let r = MountSim::new(root.path());
        // 一份字节相同的拷贝（不同 inode）：算已经堵住，不再挂。
        let p = under(root.path(), "/usr/bin/nautilus");
        fs::copy(under(root.path(), STUB), &p).unwrap();
        ensure(root.path(), &r, true).unwrap();
        assert!(
            !r.calls().iter().any(|c| c.ends_with(" /usr/bin/nautilus")),
            "{:?}",
            r.calls()
        );
        // 长度相同、内容不同：不是桩。gnome-control-center 已被上面那轮挂上了（硬链接）：先拆掉再写别的内容。
        let stub = fs::read(under(root.path(), STUB)).unwrap();
        let p = under(root.path(), "/usr/bin/gnome-control-center");
        fs::remove_file(p.with_extension("sim-orig")).unwrap();
        fs::remove_file(&p).unwrap();
        fs::write(&p, vec![b'x'; stub.len()]).unwrap();
        let r = MountSim::new(root.path());
        ensure(root.path(), &r, true).unwrap();
        assert!(r
            .calls()
            .iter()
            .any(|c| c.ends_with(" /usr/bin/gnome-control-center")));
    }

    #[test]
    fn missing_stub_or_failed_mount_is_an_error() {
        let root = image_root();
        fs::remove_file(under(root.path(), STUB)).unwrap();
        let r = MountSim::new(root.path());
        let e = ensure(root.path(), &r, true).unwrap_err();
        assert!(format!("{e:#}").contains(STUB), "{e:#}");
        assert!(r.calls().is_empty());
        // 没有桩时放开：没有可卸的，成功。
        ensure(root.path(), &r, false).unwrap();

        let root = image_root();
        let r = MountSim::new(root.path());
        r.fail_on("nsenter --mount=/proc/1/ns/mnt -- mount --bind /usr/lib/mastersos/interface-denied /usr/bin/nautilus");
        let e = format!("{:#}", ensure(root.path(), &r, true).unwrap_err());
        assert!(
            e.contains("/usr/bin/nautilus") && e.contains("exited with 32"),
            "{e}"
        );
        // 其余的照样挂上。
        assert!(is_stub(root.path(), "/usr/bin/gnome-control-center"));
        assert!(!is_stub(root.path(), "/usr/bin/nautilus"));
    }

    /// 模拟 sysext 刷新把 overlay 换掉：挂在上面的桩全没了（文件换回原来的）。
    pub(crate) fn drop_binds(root: &Path) {
        for t in PRESENT {
            let p = under(root, t);
            let orig = p.with_extension("sim-orig");
            if orig.exists() {
                fs::remove_file(&p).unwrap();
                fs::rename(&orig, &p).unwrap();
            }
        }
    }

    /// 复审 T13 发现 1：模式先落盘、再动挂载；exec-block 从盘上读到的永远不比挂载旧。
    #[test]
    fn apply_persists_mode_and_sync_reapplies_it_after_refresh() {
        let root = image_root();
        let p = paths(root.path());
        let r = MountSim::new(root.path());
        apply(&p, &r, true).unwrap();
        assert_eq!(read_mode(&p).unwrap(), Some(true));
        assert!(is_stub(root.path(), "/usr/bin/nautilus"));
        let n = r.calls().len();
        // 收敛着的时候 sync 什么都不跑
        assert_eq!(sync(&p, &r).unwrap(), Some(true));
        assert_eq!(r.calls().len(), n);
        // sysext 刷新换掉 overlay → exec-block 按盘上的模式重挂
        drop_binds(root.path());
        assert_eq!(sync(&p, &r).unwrap(), Some(true));
        assert!(is_stub(root.path(), "/usr/bin/nautilus"));
        apply(&p, &r, false).unwrap();
        assert_eq!(read_mode(&p).unwrap(), Some(false));
        assert_eq!(sync(&p, &r).unwrap(), Some(false));
        assert!(!is_stub(root.path(), "/usr/bin/nautilus"));
    }

    /// Writes `text` as the mode file, drops whatever is mounted, then lets `sync` converge.
    fn sync_from_mode_file(text: &[u8], start_blocked: bool) -> (tempfile::TempDir, Option<bool>) {
        let root = image_root();
        let p = paths(root.path());
        let r = MountSim::new(root.path());
        ensure(root.path(), &r, start_blocked).unwrap();
        fs::create_dir_all(&p.var_dir).unwrap();
        fs::write(p.var_dir.join(MODE_FILE), text).unwrap();
        let got = sync(&p, &r).unwrap();
        (root, got)
    }

    /// The mode file is written in the old words (`browser`/`desktop`) so that a rollback to a
    /// pre-config image still blocks; `learning`/`full` are read as well.
    #[test]
    fn mode_file_learning_blocks() {
        let root = image_root();
        let p = paths(root.path());
        let r = MountSim::new(root.path());
        apply(&p, &r, true).unwrap();
        assert_eq!(fs::read(p.var_dir.join(MODE_FILE)).unwrap(), b"browser\n");
        let (root, got) = sync_from_mode_file(b"learning\n", false);
        assert_eq!(got, Some(true));
        for t in PRESENT {
            assert!(is_stub(root.path(), t), "{t}");
        }
    }

    #[test]
    fn mode_file_full_unblocks() {
        let root = image_root();
        let p = paths(root.path());
        let r = MountSim::new(root.path());
        apply(&p, &r, false).unwrap();
        assert_eq!(fs::read(p.var_dir.join(MODE_FILE)).unwrap(), b"desktop\n");
        let (root, got) = sync_from_mode_file(b"full\n", true);
        assert_eq!(got, Some(false));
        for t in PRESENT {
            assert!(!is_stub(root.path(), t), "{t}");
        }
    }

    /// The session (browser-wait) cannot read the 0700 var dir: `write_mode` also writes a public
    /// `session-mode` (0644) under `public_dir`, in the new words `learning` / `full`.
    #[test]
    fn write_mode_also_writes_public_session_mode() {
        use std::os::unix::fs::PermissionsExt;
        let root = tmp_root();
        let p = paths(root.path());
        let f = p.public_dir.join(SESSION_MODE_FILE);
        for (block, want) in [(true, &b"learning\n"[..]), (false, b"full\n")] {
            write_mode(&p, block).unwrap();
            assert_eq!(fs::read(&f).unwrap(), want);
            assert_eq!(
                fs::metadata(&f).unwrap().permissions().mode() & 0o777,
                0o644
            );
            // the private file keeps the old words
            let old: &[u8] = if block { b"browser\n" } else { b"desktop\n" };
            assert_eq!(fs::read(p.var_dir.join(MODE_FILE)).unwrap(), old);
        }
        assert_eq!(SESSION_MODE_FILE, "session-mode");
    }

    /// A mode file an older agent wrote is still understood (the image update replaces the agent,
    /// not `/var`).
    #[test]
    fn old_mode_file_browser_still_blocks() {
        let (root, got) = sync_from_mode_file(b"browser\n", false);
        assert_eq!(got, Some(true));
        for t in PRESENT {
            assert!(is_stub(root.path(), t), "{t}");
        }
    }

    #[test]
    fn old_mode_file_desktop_still_unblocks() {
        let (root, got) = sync_from_mode_file(b"desktop\n", true);
        assert_eq!(got, Some(false));
        for t in PRESENT {
            assert!(!is_stub(root.path(), t), "{t}");
        }
    }

    /// 复审 T13 发现 7：没有状态、或状态读不懂，就什么都不做（不建 var_dir，不卸已挂的桩）。
    #[test]
    fn sync_does_nothing_without_or_with_corrupt_mode() {
        let root = image_root();
        let p = paths(root.path());
        let r = MountSim::new(root.path());
        assert_eq!(sync(&p, &r).unwrap(), None);
        assert!(
            !p.var_dir.exists(),
            "未受管的机器上不建 /var/lib/mastersos-system"
        );
        assert!(r.calls().is_empty());
        apply(&p, &r, true).unwrap();
        let n = r.calls().len();
        for bad in [
            &b"garbage"[..],
            b"",
            b"desktop\nbrowser\n",
            b"learning\nfull\n",
        ] {
            fs::write(p.var_dir.join(MODE_FILE), bad).unwrap();
            drop_binds(root.path());
            ensure(root.path(), &r, true).unwrap();
            let m = r.calls().len();
            assert_eq!(sync(&p, &r).unwrap(), None, "{bad:?}");
            assert_eq!(r.calls().len(), m, "读不懂就不动挂载");
            assert!(is_stub(root.path(), "/usr/bin/nautilus"));
        }
        assert!(n > 0);
        fs::remove_file(p.var_dir.join(MODE_FILE)).unwrap();
        assert_eq!(sync(&p, &r).unwrap(), None);
    }

    /// 复审 T13 发现 1：exec-block 拿到锁之后才读模式——应用正持锁改模式时，它等应用做完再按新模式收敛。
    #[test]
    fn sync_rereads_mode_under_the_lock() {
        let root = image_root();
        let p = paths(root.path());
        let r = std::sync::Arc::new(MountSim::new(root.path()));
        apply(&p, r.as_ref(), false).unwrap();
        let held = lock(&p.root).unwrap();
        let (p2, r2) = (p.clone(), r.clone());
        let t = std::thread::spawn(move || sync(&p2, r2.as_ref()).unwrap());
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(!t.is_finished(), "锁被占着，sync 应在等");
        write_mode(&p, true).unwrap();
        drop(held);
        assert_eq!(t.join().unwrap(), Some(true));
        assert!(is_stub(root.path(), "/usr/bin/nautilus"));
    }

    /// 复审 T13 R1：exec-block 等锁有上限；等不到就不持锁照样按盘上的模式收敛（浏览器模式不放开），不让 GDM 卡住。
    #[test]
    fn sync_proceeds_without_lock_after_bounded_wait() {
        let root = image_root();
        let p = paths(root.path());
        let r = MountSim::new(root.path());
        apply(&p, &r, true).unwrap();
        drop_binds(root.path());
        let _held = lock(&p.root).unwrap();
        let t0 = std::time::Instant::now();
        assert_eq!(
            sync_with(&p, &r, std::time::Duration::from_millis(300)).unwrap(),
            Some(true)
        );
        assert!(t0.elapsed() < std::time::Duration::from_secs(3));
        assert!(
            is_stub(root.path(), "/usr/bin/nautilus"),
            "等不到锁也照样挂上"
        );
    }

    /// 不持锁时读到桌面模式也不卸桩（安全扫描 race-condition / fail-open）：持锁的一方可能正把模式改成浏览器。
    #[test]
    fn lockless_sync_never_unbinds() {
        let root = image_root();
        let p = paths(root.path());
        let r = MountSim::new(root.path());
        apply(&p, &r, true).unwrap();
        write_mode(&p, false).unwrap();
        let _held = lock(&p.root).unwrap();
        assert_eq!(
            sync_with(&p, &r, std::time::Duration::from_millis(300)).unwrap(),
            Some(false)
        );
        assert!(is_stub(root.path(), "/usr/bin/nautilus"), "没持锁时不卸桩");
        drop(_held);
        assert_eq!(sync(&p, &r).unwrap(), Some(false));
        assert!(!is_stub(root.path(), "/usr/bin/nautilus"), "持锁时照常卸");
    }

    /// 复审 T13 R2：模式文件写不进去时，这一轮照样按要的模式挂，再把写失败报出来（浏览器模式不放开）。
    #[test]
    fn failed_mode_write_still_converges_and_reports() {
        let root = image_root();
        let p = paths(root.path());
        // var_dir 的位置是个普通文件：写模式必然失败
        fs::write(&p.var_dir, b"x").unwrap();
        let r = MountSim::new(root.path());
        let e = apply(&p, &r, true).unwrap_err();
        assert!(
            format!("{e:#}").contains("record the exec-block mode"),
            "{e:#}"
        );
        assert!(is_stub(root.path(), "/usr/bin/nautilus"));
        let e = apply(&p, &r, false).unwrap_err();
        assert!(!format!("{e:#}").is_empty());
        assert!(!is_stub(root.path(), "/usr/bin/nautilus"));
    }

    /// 复审 T13 R1：mount/umount 各自有短超时，不按默认的 120 秒。
    #[test]
    fn mount_commands_have_short_timeout() {
        assert!(host_cmd(&["mount"]).timeout <= std::time::Duration::from_secs(10));
    }
}
