//! 临时账号：家目录每次会话前是一份新挂的 tmpfs，会话结束后清掉一切的账号。访客（[`guest`]，uid 1999）是第一个；
//! 锁定应用的 `kiosk-<id>`（[`kiosk`]，uid 1900–1989）用同一套机制。下面以「这个账号」称 [`Ephemeral`] 描述的那一个，
//! 与 uid 有关的名字（slice、标记、家目录）都取自它；与 uid 无关的（`TMP_DIRS`、`ACCOUNTS_DIRS`、`JOURNAL_DIRS`
//! 等）是这里的常量。
//!
//! PAM 钩子跑在 `gdm-session-worker` 里，`pam_systemd` 会把这个进程移进这个账号的 `session-N.scope`
//! （`user-<uid>.slice` 下）——所以「等这个账号的进程都退出」的逻辑**不能放在 PAM 里**（它会等自己、或者把自己杀掉）。
//! 分工：
//! - [`cleanup`]（`mastersos-agent ephemeral-cleanup <user>`，访客另有别名 `guest-cleanup`，root，在 `system.slice`）：
//!   这个账号的 user manager 停下时（`user@<uid>.service` 的 `OnSuccess=`/`OnFailure=`）、开机时、失败后 30 秒
//!   （`Restart=on-failure`）与点登录被拒时跑。认得 `guest` 与登录策略名单里的 `kiosk-<id>`（名字取自名单、uid 现查
//!   `getent`、不在 [`KIOSK_UIDS`] 里不清理，[`cleanup_target`]），别的名字退出 0、记一行。它的 uid 已经是别人就什么都不做。先删 linger 文件、等
//!   它的 slice 不再 active（最多 30 秒，再 SIGKILL 等 5 秒，仍不行就放弃、不留标记），**之后**才由深到浅卸掉
//!   家目录上的挂载、删以前留下的 `user-<uid>*.journal`、懒卸载它在 /tmp 等处挂的东西并清掉属于这个 uid 的东西
//!   （`TMP_DIRS`，sticky 子目录再看一层）、删 AccountsService 按名字存的数据、挂一份空的 tmpfs、把账号的口令、
//!   名字与 shell 恢复原样，账号还在才写就绪标记（`/run/mastersos/<ready_mark>`）。root 绝不在这个账号的进程还活着时
//!   遍历它能写的目录。一位用户留给下一位的其余途径由镜像挡：journald 的 `SplitMode=none`、polkit 拒绝 linger 与改自己的
//!   名字、头像、口令、logind 的 `RemoveIPC=yes`、`cron.deny`/`at.deny`（复审 I1–I3、M1、M2）。
//! - [`session_open`]（`mastersos-agent pam-session`，open_session，排在 `pam_systemd` 之前）：只检查（标记在、家目录是
//!   tmpfs、slice 不 active）、用 `unlinkat` 拿走标记（同一时刻只有一个会话）、复制 `/etc/skel`；不清理、
//!   不等任何进程（被拒而 slice 已不在时只是 `--no-block` 拉起清理）。
//!
//! 账号的建与删（步骤）、谁能从哪个 PAM 服务登录不在这里：访客的见 [`super::guest`] 与 [`super::login`]。

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::ffi::OsStr;
use std::io::Write;
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

use super::guest::{
    CLEANUP_UNIT, GUEST_COMMENT, GUEST_HOME, GUEST_UID, GUEST_USER, OPENING_MARK, READY_MARK, SLICE,
};
use super::login::{self, LoginPolicy, KIOSK_PREFIX};
use crate::runner::{run_ok, Cmd, RealRunner, Runner};
use crate::safefs;

/// 一个临时账号。名字、家目录、slice、标记都由它定，清理与开会话的逻辑对所有临时账号一样。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ephemeral {
    /// 账号名（`guest`、`kiosk-<id>`）。
    pub user: String,
    pub uid: u32,
    /// 家目录（绝对路径）：root 0755 的真实目录，tmpfs 挂在它上面。
    pub home: PathBuf,
    /// `user-<uid>.slice`：会话、user manager 都在它下面；它不再 active 就说明这个账号的进程都没了。
    pub slice: String,
    /// 就绪标记在 [`RUN_DIR`] 里的名字：清理做完才写，开会话时拿走。
    pub ready_mark: String,
    /// `session_open` 拿走标记时把它改名成这个（同在 [`RUN_DIR`]）：会话正在打开、还没进 slice 的那几秒，
    /// 别的会话登录被拒时不拉起清理（清理会把正在打开的会话的家目录卸掉）。清理开头删掉它（提交安全审查：授权）。
    pub opening_mark: String,
    /// 账号的名字（GECOS）：每次清理后恢复成它（复审 I3）。
    pub comment: String,
    /// AccountsService 记录的模板（绝对路径）：清理删掉按名字存的记录之后照它恢复（锁定应用的 `Session=mastersos-kiosk`
    /// 等，见 [`super::kiosk::ACCOUNTS_TEMPLATE`]）。访客没有。
    pub accounts_template: Option<PathBuf>,
}

impl Ephemeral {
    /// 清理服务。访客沿用自己的 `mastersos-guest-cleanup.service`（`user@1999.service` 的 drop-in 与开机启用都指着它），
    /// 其余临时账号用模板 `mastersos-ephemeral-cleanup@<user>.service`。
    pub fn cleanup_unit(&self) -> String {
        if self.user == GUEST_USER {
            CLEANUP_UNIT.to_string()
        } else {
            format!("mastersos-ephemeral-cleanup@{}.service", self.user)
        }
    }
}

/// 访客：`guest`、uid 1999（Ruling 5）。名字都取自 [`super::guest`] 的常量，盘上与单元里的名字不变。
pub fn guest() -> Ephemeral {
    Ephemeral {
        user: GUEST_USER.to_string(),
        uid: GUEST_UID,
        home: PathBuf::from(GUEST_HOME),
        slice: SLICE.to_string(),
        ready_mark: READY_MARK
            .rsplit('/')
            .next()
            .unwrap_or(READY_MARK)
            .to_string(),
        opening_mark: OPENING_MARK.to_string(),
        comment: GUEST_COMMENT.to_string(),
        accounts_template: None,
    }
}

/// 锁定应用 `id` 的临时账号 `kiosk-<id>`。`id` 由清单的校验保证是 `^[a-z][a-z0-9-]{0,23}$`，`uid` 在 1900–1989。
pub fn kiosk(id: &str, uid: u32, name: &str) -> Ephemeral {
    let user = format!("kiosk-{id}");
    Ephemeral {
        home: PathBuf::from(format!("/home/{user}")),
        slice: format!("user-{uid}.slice"),
        ready_mark: format!("{user}-ready"),
        opening_mark: format!("{user}-opening"),
        comment: name.to_string(),
        accounts_template: Some(PathBuf::from(format!(
            "/{}/{id}/{}",
            super::kiosk::PUBLIC_DIR,
            super::kiosk::ACCOUNTS_TEMPLATE
        ))),
        uid,
        user,
    }
}

/// 标记所在的目录（initrd 建的，0700 root）。
pub const RUN_DIR: &str = "/run/mastersos";

/// `OPENING_MARK` 比这更旧：那次打开早已结束（成功的会话这时 slice 早已 active；失败的会话留下了它），可以拉起清理。
const OPENING_GRACE: Duration = Duration::from_secs(60);

/// 等 slice 停下：每 200 ms 看一次，30 秒（150 次）；SIGKILL 之后再看 5 秒（25 次）。
const POLL: Duration = Duration::from_millis(200);
const WAIT_POLLS: u32 = 150;
const KILL_POLLS: u32 = 25;
/// PAM 里调的命令最多等这么久（登录不能被一个卡住的命令拖死）。
pub const PAM_CMD_TIMEOUT: Duration = Duration::from_secs(5);
/// 清理服务里调的命令。
pub const CMD_TIMEOUT: Duration = Duration::from_secs(20);
/// 临时账号写得到、要清掉它的 uid 的东西的目录（相对系统根）。根下直接的项看属主；属主不是它的带 sticky 位的
/// 子目录（`/tmp/.X11-unix` 这类）再往下看一层（复审 M1）。
pub(crate) const TMP_DIRS: [&str; 5] = ["tmp", "var/tmp", "dev/shm", "run/lock", "dev/mqueue"];
/// logind 的 linger 文件所在的目录（复审 I2）：打开 linger，它的 user manager 就永远不停、清理永远不来。
pub(crate) const LINGER_DIR: &str = "var/lib/systemd/linger";
/// AccountsService 按用户名存的名字、头像、语言（复审 I3）：GDM 的用户列表给所有人看。
const ACCOUNTS_DIRS: [&str; 2] = [
    "var/lib/AccountsService/users",
    "var/lib/AccountsService/icons",
];
/// journald 的两个存放处（复审 I1）：旧镜像在 `SplitMode=uid` 下给 1999 写过 `user-1999*.journal`，
/// 1999 读得到、换了访客还在。现在镜像设 `SplitMode=none`，清理时删掉以前留下的。
const JOURNAL_DIRS: [&str; 2] = ["var/log/journal", "run/log/journal"];
/// 临时账号在每次清理后恢复的 shell（复审 I3）。
const SHELL: &str = "/bin/bash";

/// 这个账号的进程还在不在。真实实现 [`SystemdProcs`]；`sleep` 让测试不用真的等。
///
/// 看哪个 slice 由调用方从 [`EphemeralEnv::acct`] 传进来（[`Ephemeral::slice`]），实现里不另存：轮询与 SIGKILL
/// 只有这一个来源，对不上的组合写不出来。
pub trait Procs {
    fn slice_active(&self, slice: &str) -> Result<bool>;
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// `systemctl is-active <slice>`：`active`、`activating`、`deactivating`、`reloading`、`refreshing`
/// 都算 active，`inactive`、`failed` 不算；认不出的输出是错误（调用方按「还在」处理）。
pub struct SystemdProcs<'a> {
    pub runner: &'a dyn Runner,
    pub timeout: Duration,
}

impl Procs for SystemdProcs<'_> {
    fn slice_active(&self, slice: &str) -> Result<bool> {
        let out = self
            .runner
            .run(&Cmd::new("systemctl", &["is-active", slice]).timeout(self.timeout))?;
        match out.stdout.trim() {
            "active" | "activating" | "deactivating" | "reloading" | "refreshing" => Ok(true),
            "inactive" | "failed" => Ok(false),
            other => bail!("unrecognized output from systemctl is-active {slice}: {other:?}"),
        }
    }
}

pub struct EphemeralEnv<'a> {
    pub runner: &'a dyn Runner,
    pub procs: &'a dyn Procs,
    /// 系统根；测试里指向临时目录。
    pub root: &'a Path,
    /// 这个账号的 uid。测试以外一律等于 `acct.uid`（生产的调用方都从 `acct.uid` 取，不另写常量）；只有测试换成
    /// 当前 uid（chown 不了别人）。
    pub uid: u32,
    /// 按 fd 卸载：真机是 [`ProcMounts`]。
    pub mounts: &'a dyn MountOps,
    /// 哪个临时账号。
    pub acct: &'a Ephemeral,
}

impl EphemeralEnv<'_> {
    fn home(&self) -> PathBuf {
        self.root.join(rel(&self.acct.home))
    }
}

/// 绝对路径去掉开头的 `/`，好接在系统根后面。
pub(crate) fn rel(abs: &Path) -> &Path {
    abs.strip_prefix("/").unwrap_or(abs)
}

/// `/run/mastersos`（initrd 建的，0700 root）。
pub(crate) fn run_dir(env: &EphemeralEnv, create: bool) -> Result<std::os::fd::OwnedFd> {
    let dir = safefs::open_dir(env.root, rel(Path::new(RUN_DIR)), create)?;
    if create {
        safefs::set_mode(&dir, 0o700)?;
    }
    Ok(dir)
}

/// 等 slice 不再 active：30 秒，然后 `systemctl kill --signal=KILL`，再 5 秒。
pub fn wait_slice_gone(env: &EphemeralEnv) -> Result<()> {
    let slice = env.acct.slice.as_str();
    for _ in 0..WAIT_POLLS {
        if !env.procs.slice_active(slice)? {
            return Ok(());
        }
        env.procs.sleep(POLL);
    }
    // kill 本身失败（slice 恰好刚停下）不算错：下面再看一次
    let _ = env
        .runner
        .run(&Cmd::new("systemctl", &["kill", "--signal=KILL", slice]).timeout(CMD_TIMEOUT));
    for _ in 0..KILL_POLLS {
        if !env.procs.slice_active(slice)? {
            return Ok(());
        }
        env.procs.sleep(POLL);
    }
    bail!("{slice} is still active after 35 seconds (with one SIGKILL in between)")
}

/// `getent passwd <key>` 的一行：`(name, uid, gid)`；查不到（退出码 2）为 `None`。
fn getent(runner: &dyn Runner, key: &str) -> Result<Option<(String, u32, u32)>> {
    getent_with(runner, key, CMD_TIMEOUT)
}

fn getent_with(
    runner: &dyn Runner,
    key: &str,
    timeout: Duration,
) -> Result<Option<(String, u32, u32)>> {
    let out = runner.run(&Cmd::new("getent", &["passwd", key]).timeout(timeout))?;
    match out.code {
        0 => {}
        2 => return Ok(None),
        c => bail!("getent passwd {key} exited with code {c}"),
    }
    let line = out.stdout.lines().next().unwrap_or_default();
    let f: Vec<&str> = line.split(':').collect();
    if f.len() < 4 || f[0].is_empty() {
        bail!("unrecognized output from getent passwd {key}");
    }
    let uid = f[2].parse().with_context(|| format!("uid of {key}"))?;
    let gid = f[3].parse().with_context(|| format!("gid of {key}"))?;
    Ok(Some((f[0].to_string(), uid, gid)))
}

/// `getent passwd <user>` → `(uid, gid)`；没有这个账号为 `None`。
pub(crate) fn account(runner: &dyn Runner, user: &str) -> Result<Option<(u32, u32)>> {
    account_with(runner, user, CMD_TIMEOUT)
}

fn account_with(runner: &dyn Runner, user: &str, timeout: Duration) -> Result<Option<(u32, u32)>> {
    match getent_with(runner, user, timeout)? {
        None => Ok(None),
        Some((name, _, _)) if name != user => {
            bail!("getent passwd {user} returned {name}")
        }
        Some((_, uid, gid)) => Ok(Some((uid, gid))),
    }
}

/// 家目录上挂着的文件系统类型；不是挂载点为 `None`。
fn home_fstype(env: &EphemeralEnv, timeout: Duration) -> Result<Option<String>> {
    let home = env.home();
    let home = home.to_string_lossy();
    let out = env.runner.run(
        &Cmd::new(
            "findmnt",
            &["-n", "-o", "FSTYPE", "--mountpoint", home.as_ref()],
        )
        .timeout(timeout),
    )?;
    let t = out.stdout.lines().last().unwrap_or_default().trim();
    Ok((out.code == 0 && !t.is_empty()).then(|| t.to_string()))
}

/// `findmnt -r` 把空格等写成 `\xHH`：还原。
pub(crate) fn unescape_findmnt(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1] == b'x' {
            if let Some(v) = s
                .get(i + 2..i + 4)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(v);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 挂载表的一条（`findmnt -rn -o ID,FSTYPE,OPTIONS,TARGET`）。
#[derive(Debug, Clone)]
pub struct MountEntry {
    /// mountinfo 的第一列：同一路径上叠着的、换过的挂载都分得开。
    pub id: u64,
    pub fstype: String,
    pub options: String,
    pub target: PathBuf,
}

/// 当前所有挂载。`-r` 把空格等写成 `\xHH`，所以按空格切前三列、其余是挂载点。
fn mount_table(env: &EphemeralEnv) -> Result<Vec<MountEntry>> {
    let out = run_ok(
        env.runner,
        Cmd::new("findmnt", &["-rn", "-o", "ID,FSTYPE,OPTIONS,TARGET"]).timeout(CMD_TIMEOUT),
    )?;
    let mut v = Vec::new();
    for l in out.lines().filter(|l| !l.is_empty()) {
        let f: Vec<&str> = l.splitn(4, ' ').collect();
        let (Some(id), Some(fstype), Some(options), Some(target)) =
            (f.first(), f.get(1), f.get(2), f.get(3))
        else {
            bail!("unrecognized findmnt output: {l:?}");
        };
        v.push(MountEntry {
            id: id
                .parse()
                .with_context(|| format!("findmnt mount id: {l:?}"))?,
            fstype: fstype.to_string(),
            options: options.to_string(),
            target: PathBuf::from(unescape_findmnt(target)),
        });
    }
    Ok(v)
}

/// 按 fd 卸载（复审 T11 N1）。真实实现 [`ProcMounts`]；测试换成假的。
pub trait MountOps {
    /// `fd` 所在挂载的 id（与挂载表的 `ID` 同一套编号）。
    fn mount_id(&self, fd: &std::os::fd::OwnedFd) -> Result<u64>;
    /// 懒卸载 `fd` 所在的挂载：`umount2("/proc/self/fd/N", MNT_DETACH)`，内核顺着这个魔术链接找到的就是 fd 那个挂载，
    /// 不再按路径解析。手里拿着 fd，非懒卸载一定 EBUSY，所以只做懒卸载（这时这个账号的进程都已没了）。
    fn detach(&self, fd: &std::os::fd::OwnedFd) -> Result<()>;
}

/// `/proc/self/fdinfo/N` 的 `mnt_id:` 与 `umount2("/proc/self/fd/N", MNT_DETACH)`。不经文件系统（死掉的 FUSE 也取得到）。
pub struct ProcMounts;

impl MountOps for ProcMounts {
    fn mount_id(&self, fd: &std::os::fd::OwnedFd) -> Result<u64> {
        use std::os::fd::AsRawFd;
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))
            .context("read /proc/self/fdinfo")?;
        info.lines()
            .find_map(|l| l.strip_prefix("mnt_id:"))
            .and_then(|v| v.trim().parse().ok())
            .ok_or_else(|| anyhow!("no mnt_id in fdinfo"))
    }

    #[cfg(target_os = "linux")]
    fn detach(&self, fd: &std::os::fd::OwnedFd) -> Result<()> {
        use std::os::fd::AsRawFd;
        rustix::mount::unmount(
            format!("/proc/self/fd/{}", fd.as_raw_fd()).as_str(),
            rustix::mount::UnmountFlags::DETACH,
        )
        .map_err(std::io::Error::from)
        .context("umount2(MNT_DETACH)")
    }

    #[cfg(not(target_os = "linux"))]
    fn detach(&self, _fd: &std::os::fd::OwnedFd) -> Result<()> {
        bail!("unmounting by fd is only supported on Linux")
    }
}

/// 卸掉挂载表里的这一条：从系统根的 fd 起逐级不跟随链接地打开挂载点（[`safefs::open_mount_target`]），核对打开的 fd
/// 所在挂载的 id 就是这一条，再按 fd 懒卸载。路径上有链接、打不开、id 对不上都报错、不卸任何东西：别的本机用户在清理
/// 期间改 /tmp 下的路径（把某一级换成指向 / 的链接）也只能让清理失败（不写标记，30 秒后再来），卸不到别处
/// （复审 T11 N1）。
fn unmount_verified(env: &EphemeralEnv, m: &MountEntry) -> Result<()> {
    let rel = m
        .target
        .strip_prefix(env.root)
        .with_context(|| format!("{} is not under the system root", m.target.display()))?;
    let fd = safefs::open_mount_target(env.root, rel)
        .with_context(|| format!("open {} (not unmounting)", m.target.display()))?;
    let id = env.mounts.mount_id(&fd)?;
    if id != m.id {
        bail!(
            "{}: opened mount {id} but the mount table has {}; the path changed, not unmounting",
            m.target.display(),
            m.id
        );
    }
    env.mounts
        .detach(&fd)
        .with_context(|| format!("unmount {}", m.target.display()))
}

/// 由深到浅；同一处叠着的几层后挂的先卸（挂载表按挂载的先后列出）。
fn deepest_first(v: Vec<MountEntry>) -> Vec<MountEntry> {
    let mut v: Vec<(usize, MountEntry)> = v.into_iter().enumerate().collect();
    v.sort_by_key(|(i, m)| {
        (
            std::cmp::Reverse(m.target.components().count()),
            std::cmp::Reverse(*i),
        )
    });
    v.into_iter().map(|(_, m)| m).collect()
}

/// 家目录及其下面的全部挂载，由深到浅按 fd 卸掉；之后它不能还是挂载点。
fn unmount_home_tree(env: &EphemeralEnv) -> Result<()> {
    let home = env.home();
    for m in deepest_first(
        mount_table(env)?
            .into_iter()
            .filter(|m| m.target.starts_with(&home))
            .collect(),
    ) {
        unmount_verified(env, &m)?;
    }
    if home_fstype(env, CMD_TIMEOUT)?.is_some() {
        bail!("{} is still a mount point after unmounting", home.display());
    }
    Ok(())
}

/// `base` 之下、要在删之前卸掉的挂载：这个账号的 FUSE（选项里有 `user_id=<uid>`；复审 T11 N2：别的用户的 FUSE，例如
/// AppImage 的 /tmp/.mount_*，不碰），以及路径上有它的东西或 lstat 失败（死掉的 FUSE）的。
fn account_mounts_under(base: &Path, table: &[MountEntry], uid: u32) -> Vec<MountEntry> {
    let uid_opt = format!("user_id={uid}");
    table
        .iter()
        .filter(|m| m.target.starts_with(base) && m.target != base)
        .filter(|m| {
            (m.fstype.starts_with("fuse") && m.options.split(',').any(|o| o == uid_opt))
                || account_mount_under(base, &m.target, uid)
        })
        .cloned()
        .collect()
}

/// 只用来决定要不要卸（按路径 lstat，不写不删）；调用时这个账号的进程都已没了，路径取自内核的挂载表，自上而下逐级 lstat：
/// 中间哪一级是它的（包括它的链接）都在那一级就判定，不会顺着它的链接走到更下面（提交安全审查）。
/// `target` 在 `base` 之下（不含 `base` 本身）：从第一级到 `target` 本身，任一级 lstat 失败（死掉的 FUSE 是 ENOTCONN）
/// 或属主是 `uid` → 这是它挂的，要卸。全是别人的就留着（root 自己挂在 /tmp 下的东西）。
pub(crate) fn account_mount_under(base: &Path, target: &Path, uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(rest) = target.strip_prefix(base) else {
        return false;
    };
    if rest.as_os_str().is_empty() {
        return false;
    }
    let mut p = base.to_path_buf();
    for c in rest.components() {
        p.push(c);
        match std::fs::symlink_metadata(&p) {
            Err(_) => return true,
            Ok(m) if m.uid() == uid => return true,
            Ok(_) => {}
        }
    }
    false
}

/// `dir`（相对系统根）里的 `name`：在就删，目录不在也算成功。
pub(crate) fn remove_named(env: &EphemeralEnv, dir: &str, name: &str) -> Result<()> {
    let d = match safefs::open_dir(env.root, Path::new(dir), false) {
        Ok(d) => d,
        Err(e) if crate::apply::is_not_found(&e) => return Ok(()),
        Err(e) => return Err(e),
    };
    safefs::remove_at(&d, name).with_context(|| format!("delete /{dir}/{name}"))
}

/// 删掉 `user-<uid>.journal`、`user-<uid>@….journal(~)`（复审 I1）。
fn remove_user_journals(env: &EphemeralEnv) -> Result<()> {
    let prefixes = [format!("user-{}.", env.uid), format!("user-{}@", env.uid)];
    for base in JOURNAL_DIRS {
        let b = match safefs::open_dir(env.root, Path::new(base), false) {
            Ok(d) => d,
            Err(e) if crate::apply::is_not_found(&e) => continue,
            Err(e) => return Err(e),
        };
        for machine in safefs::list_at(&b)? {
            let Some(m) = safefs::open_child_dir(&b, &machine).ok().flatten() else {
                continue;
            };
            for f in safefs::list_at(&m)? {
                if prefixes.iter().any(|p| f.starts_with(p.as_str())) {
                    safefs::remove_at(&m, &f)
                        .with_context(|| format!("delete /{base}/{machine}/{f}"))?;
                }
            }
        }
    }
    Ok(())
}

/// 会话结束后（以及开机时）的清理。见模块文档；任何一步失败都返回错误、**不留标记**。失败时清理服务
/// `Restart=on-failure` 30 秒后再来，点登录被拒时 `session_open` 也会拉起它（复审 I4）。
/// 账号不存在时只卸载、清 `/tmp` 等与删掉按名字留下的东西，不挂、不写标记。
pub fn cleanup(env: &EphemeralEnv) -> Result<()> {
    let user = env.acct.user.as_str();
    // 它的 uid 现在是别人（账号删掉之后 useradd 又发了这个 uid）：一样都不碰（复审 M6）
    if let Some((name, _, _)) = getent(env.runner, &env.uid.to_string())? {
        if name != user {
            let _ = writeln!(
                std::io::stderr(),
                "mastersos-agent ephemeral-cleanup: uid {} is now {name}, not {user}; doing nothing",
                env.uid
            );
            return Ok(());
        }
    }
    let run = run_dir(env, true)?;
    safefs::remove_at(&run, &env.acct.ready_mark)?;
    safefs::remove_at(&run, &env.acct.opening_mark)?;
    // linger 在的话 user manager 不会停：先删掉它，下面的 SIGKILL 才停得下来（复审 I2）
    remove_named(env, LINGER_DIR, user)?;
    wait_slice_gone(env)?;
    // 这个账号的进程都没了：下面才碰它能写的东西
    let home = env.home();
    unmount_home_tree(env)?;
    ensure_home_dir(env)?;
    remove_user_journals(env)?;
    // 挂载表读一次（家目录下的已经卸掉了）；每一条卸之前仍按 fd 核对挂载 id
    let table = mount_table(env)?;
    for d in TMP_DIRS {
        let p = env.root.join(d);
        match std::fs::symlink_metadata(&p) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            _ => {}
        }
        // 它挂的东西先懒卸载，删的时候才不会碰到 ENOTCONN（复审 I4）；按 fd、核对挂载 id（N1、N2）
        for m in deepest_first(account_mounts_under(&p, &table, env.uid)) {
            unmount_verified(env, &m)?;
        }
        safefs::remove_owned_tree_and_sticky(&p, env.uid)
            .with_context(|| format!("clean up /{d}"))?;
    }
    for d in ACCOUNTS_DIRS {
        remove_named(env, d, user)?;
    }
    let Some((uid, gid)) = account(env.runner, user)? else {
        return Ok(());
    };
    if uid != env.uid {
        bail!("the {user} account has uid {uid}, not {}", env.uid);
    }
    // 锁定应用的 AccountsService 记录（会话、是否进用户列表、头像）上面跟着按名字存的一切删了：下面照 kiosk 步骤写下的
    // 模板恢复。模板读不到就不挂、不写标记——没有记录的无口令账号，GDM 会用默认的会话起它
    let template = accounts_template(env)?;
    let home_s = home.to_string_lossy().into_owned();
    let opts = format!("size=30%,mode=0700,uid={uid},gid={gid},nosuid,nodev");
    run_ok(
        env.runner,
        Cmd::new(
            "mount",
            &[
                "-c",
                "-t",
                "tmpfs",
                "-o",
                opts.as_str(),
                "tmpfs",
                home_s.as_str(),
            ],
        )
        .timeout(CMD_TIMEOUT),
    )?;
    // 账号恢复原样：口令清空、名字与 shell（改过的话；复审 I3）
    reset_password(env.runner, env.acct)?;
    run_ok(
        env.runner,
        Cmd::new(
            "usermod",
            &["-c", env.acct.comment.as_str(), "-s", SHELL, user],
        )
        .timeout(CMD_TIMEOUT),
    )?;
    // accounts-daemon 把头像留在内存里（删了它的文件也照样给 GDM 看，VM 上见过）：经它自己的接口清掉——锁定应用的
    // 设回模板里的那个。它没在跑、或调用失败都不算错（polkit 已不许改头像，这是第二道）
    let icon = template
        .as_deref()
        .and_then(template_icon)
        .unwrap_or_default();
    let _ = env.runner.run(
        &Cmd::new(
            "busctl",
            &[
                "call",
                "org.freedesktop.Accounts",
                &format!("/org/freedesktop/Accounts/User{uid}"),
                "org.freedesktop.Accounts.User",
                "SetIconFile",
                "s",
                icon.as_str(),
            ],
        )
        .timeout(CMD_TIMEOUT),
    );
    // 会话同理：上一位在登录界面选过的会话留在 accounts-daemon 的内存里，GDM 经 D-Bus 读它、不读文件——改回模板里的
    // （mastersos-kiosk）。同样不算错：Task 6 的会话守卫才是那道门，这里是第二道
    if let Some(session) = template
        .as_deref()
        .and_then(|t| template_value(t, "Session"))
    {
        for method in ["SetSession", "SetXSession"] {
            let _ = env.runner.run(
                &Cmd::new(
                    "busctl",
                    &[
                        "call",
                        "org.freedesktop.Accounts",
                        &format!("/org/freedesktop/Accounts/User{uid}"),
                        "org.freedesktop.Accounts.User",
                        method,
                        "s",
                        session.as_str(),
                    ],
                )
                .timeout(CMD_TIMEOUT),
            );
        }
    }
    // accounts-daemon 改头像、会话时会把它内存里的记录写回文件：模板在那之后才写
    if let Some(t) = &template {
        let users = safefs::open_dir(env.root, Path::new(ACCOUNTS_DIRS[0]), true)?;
        safefs::write_at(&users, user, t.as_bytes(), 0o600)
            .with_context(|| format!("restore /{}/{user}", ACCOUNTS_DIRS[0]))?;
    }
    // 这期间 agent 删了账号（复审 M3）：卸掉刚挂的，不写标记
    if account(env.runner, user)?.is_none() {
        unmount_home_tree(env)?;
        return Ok(());
    }
    safefs::write_at(&run, &env.acct.ready_mark, b"", 0o600)?;
    Ok(())
}

/// 这个账号的 AccountsService 记录的模板（[`Ephemeral::accounts_template`]）：访客没有，为 `None`；有却读不到是错误。
fn accounts_template(env: &EphemeralEnv) -> Result<Option<String>> {
    let Some(t) = &env.acct.accounts_template else {
        return Ok(None);
    };
    let r = rel(t);
    let (Some(dir), Some(name)) = (r.parent(), r.file_name().and_then(|n| n.to_str())) else {
        bail!("{} is not a normalized path", t.display());
    };
    let bytes = safefs::open_dir(env.root, dir, false)
        .and_then(|d| safefs::read_at(&d, name))
        .with_context(|| format!("read {}", t.display()))?
        .ok_or_else(|| {
            anyhow!(
                "{} is missing (the kiosk step has not written it yet)",
                t.display()
            )
        })?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| anyhow!("{} is not UTF-8", t.display()))
}

/// 模板里的 `Icon=`（kiosk 步骤写的是不用转义的绝对路径）。
fn template_icon(t: &str) -> Option<String> {
    template_value(t, "Icon")
}

/// 模板里 `key=` 的值（kiosk 步骤写的 `Icon`、`Session` 都是不用转义的）。
fn template_value(t: &str, key: &str) -> Option<String> {
    t.lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
        .map(str::to_string)
}

/// 口令清空，并把「最短使用天数」设成 99999、上次修改设成今天：口令是空的，`passwd` 不问旧口令就让人设新的
/// （VM 上访客自己设成功过），pam_unix 对非 root 的用户在最短天数没到时拒绝修改。上次修改不能是 0（那表示
/// 「下次登录必须改口令」）。
pub fn reset_password(r: &dyn Runner, acct: &Ephemeral) -> Result<()> {
    let user = acct.user.as_str();
    run_ok(r, Cmd::new("passwd", &["-d", user]).timeout(CMD_TIMEOUT))?;
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    run_ok(
        r,
        Cmd::new("chage", &["-m", "99999", "-d", today.as_str(), user]).timeout(CMD_TIMEOUT),
    )?;
    Ok(())
}

/// 家目录（`/home/guest` 等）：root 0755 的真实目录（tmpfs 挂在它上面）。不存在就建；是链接或不是目录报错。
///
/// 下面按路径 `mount` 到它上面，所以经 fd 核对：`/home` 逐级 `O_NOFOLLOW` 打开、属主是本进程（root）且组与其他人
/// 不可写（别人改不了它里面的名字）；家目录同样 `O_NOFOLLOW` 打开、属主改回 root、0755。核对时这个账号的进程都已没了
/// （提交安全审查）。
pub fn ensure_home_dir(env: &EphemeralEnv) -> Result<()> {
    let home = env.acct.home.as_path();
    let home_rel = rel(home);
    let parent = home_rel
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", home.display()))?;
    let name = home_rel
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("{} has no file name", home.display()))?;
    let p = safefs::open_dir(env.root, parent, true)?;
    let (euid, egid) = (
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    );
    let st = rustix::fs::fstat(&p).map_err(std::io::Error::from)?;
    if st.st_uid != euid || st.st_mode as u32 & 0o022 != 0 {
        bail!(
            "/{} is owned by {} with mode {:o}: it must be owned by root and not writable by group or others",
            parent.display(),
            st.st_uid,
            st.st_mode as u32 & 0o7777
        );
    }
    let d = match safefs::open_child_dir(&p, name)? {
        Some(d) => d,
        None => safefs::open_dir_at(&p, Path::new(name), true)?,
    };
    safefs::set_owner(&d, euid, egid)?;
    safefs::set_mode(&d, 0o755)
}

/// 在 GDM 上开这个账号的会话（`pam_systemd` 之前，root）。家目录不是 tmpfs、slice 还 active、或拿不到标记 → 错误
/// （PAM 拒绝）；否则把 `/etc/skel` 复制进去（属主是这个账号）。标记用 `unlinkat` 拿：两个同时开的会话只有一个拿得到
/// （复审 M4）。没有标记而 slice 已经不在：清理没做完或失败过，拉起清理服务再来一次（复审 I4）。
/// 复制失败不拒绝登录：标记已经用掉了，家目录照样是空的 tmpfs。
pub fn session_open(env: &EphemeralEnv) -> Result<()> {
    let acct = env.acct;
    let user = acct.user.as_str();
    let opening = acct.opening_mark.as_str();
    let run = run_dir(env, false).with_context(|| format!("{RUN_DIR} is missing"))?;
    let active = env.procs.slice_active(&acct.slice)?;
    if active {
        bail!(
            "{} is still active (processes of the previous {user} are still running)",
            acct.slice
        );
    }
    match home_fstype(env, PAM_CMD_TIMEOUT)? {
        Some(t) if t == "tmpfs" => {}
        other => {
            // 家目录不是 tmpfs：不可能有这个账号的会话正在用它，拉起清理
            kick_cleanup(env);
            bail!("{} is not a tmpfs ({other:?})", acct.home.display());
        }
    }
    // 名字对还不够：它得解析成这个账号的 uid（同名的别的账号不给它的 tmpfs 与标记。提交安全审查：授权逻辑）
    match account_with(env.runner, user, PAM_CMD_TIMEOUT)? {
        Some((uid, _)) if uid == env.uid => {}
        Some((uid, _)) => bail!("{user} has uid {uid}, not {}", env.uid),
        None => bail!("no {user} account"),
    }
    if !safefs::take_at(&run, &acct.ready_mark, opening)? {
        // 另一个会话可能刚拿走标记、还没进 slice：那时不拉起清理（多座席时会撞上）
        let recent = safefs::mtime_at(&run, opening)?.is_some_and(|t| {
            std::time::SystemTime::now()
                .duration_since(t)
                .map_or(true, |age| age < OPENING_GRACE)
        });
        if !recent {
            kick_cleanup(env);
        }
        bail!(
            "{RUN_DIR}/{} is missing (cleanup has not finished)",
            acct.ready_mark
        );
    }
    // 改名不改修改时间：opening 标记会带着清理写标记时的时间，看着早就「过期」了（复审 T11 N3）
    if let Err(e) = safefs::touch_at(&run, opening) {
        let _ = writeln!(
            std::io::stderr(),
            "mastersos-agent pam-session: failed to update the timestamp of {opening}: {e:#}"
        );
    }
    if let Err(e) = copy_skel(env) {
        let _ = writeln!(
            std::io::stderr(),
            "mastersos-agent pam-session: failed to copy /etc/skel: {e:#}"
        );
    }
    Ok(())
}

/// 拒绝时（slice 已不在）拉起清理：不等它（PAM 里不能等），失败也不管。
fn kick_cleanup(env: &EphemeralEnv) {
    let unit = env.acct.cleanup_unit();
    let _ = env.runner.run(
        &Cmd::new("systemctl", &["start", "--no-block", unit.as_str()]).timeout(PAM_CMD_TIMEOUT),
    );
}

/// 目标经 fd 打开（逐级 `O_NOFOLLOW`），再经同一个 fd 核对它就是这个账号的 tmpfs（属主、Linux 上 `fstatfs` 的类型），
/// 之后的写入都相对这个 fd：findmnt 按路径看到的与这里写的是同一个目录（提交安全审查）。
pub fn copy_skel(env: &EphemeralEnv) -> Result<()> {
    let shown = env.acct.home.display();
    let home = safefs::open_dir(env.root, rel(&env.acct.home), false)?;
    // 只对真的系统根核对类型：测试的根是临时目录，不在 tmpfs 上
    #[cfg(target_os = "linux")]
    if env.root == Path::new("/") {
        const TMPFS_MAGIC: i64 = 0x0102_1994;
        let fs = rustix::fs::fstatfs(&home).map_err(std::io::Error::from)?;
        #[allow(clippy::unnecessary_cast)]
        if fs.f_type as i64 != TMPFS_MAGIC {
            bail!("{shown} did not open a tmpfs");
        }
    }
    let st = rustix::fs::fstat(&home).map_err(std::io::Error::from)?;
    if st.st_uid != env.uid {
        bail!("{shown} is owned by {}, not {}", st.st_uid, env.uid);
    }
    safefs::copy_tree_into(&env.root.join("etc/skel"), &home, env.uid, st.st_gid)
}

// ---------------------------------------------------------------------------
// `mastersos-agent ephemeral-cleanup <user>`
// ---------------------------------------------------------------------------

/// 锁定应用的账号的 uid 区间（访客是 1999）。
pub const KIOSK_UIDS: RangeInclusive<u32> = 1900..=1989;

/// 策略里名单上的 `user` → 它的临时账号：名字（GECOS）取自名单，uid 由 `uid` 现查（`getent`），不在 [`KIOSK_UIDS`]
/// 里就不认。认不出时是原因（写日志用）。
pub fn kiosk_account(
    policy: Option<&LoginPolicy>,
    user: &str,
    uid: impl FnOnce() -> Option<u32>,
) -> Result<Ephemeral, String> {
    let Some(p) = policy else {
        return Err("cannot read the login policy".into());
    };
    let Some(id) = user.strip_prefix(KIOSK_PREFIX) else {
        return Err("not a locked app account".into());
    };
    let Some(entry) = p.kiosk_users.iter().find(|k| k.user == user) else {
        return Err("not in the locked app list of the login policy".into());
    };
    // 名单来自 policy_from_bundle（id 已校验）；文件被改过时这里再挡一次：id 进路径、标记与单元名
    if mastersos_bundle::kiosk::check_id(id).is_err() {
        return Err("invalid id in the account name".into());
    }
    match uid() {
        Some(u) if KIOSK_UIDS.contains(&u) => Ok(kiosk(id, u, &entry.name)),
        Some(u) => Err(format!(
            "uid {u} is not in {}-{}",
            KIOSK_UIDS.start(),
            KIOSK_UIDS.end()
        )),
        None => Err("getent cannot find this account".into()),
    }
}

/// `ephemeral-cleanup` 认得的账号：`guest`，以及策略名单里的 `kiosk-<id>`（[`kiosk_account`]）。别的名字是原因
/// （退出 0、记一行、什么都不做）。
pub fn cleanup_target(
    user: &str,
    policy: Option<&LoginPolicy>,
    uid: impl FnOnce() -> Option<u32>,
) -> Result<Ephemeral, String> {
    if user == GUEST_USER {
        return Ok(guest());
    }
    if !user.starts_with(KIOSK_PREFIX) {
        return Err("not an ephemeral account".into());
    }
    kiosk_account(policy, user, uid)
}

/// `mastersos-agent ephemeral-cleanup <user>`（`mastersos-ephemeral-cleanup@<user>.service`；访客的
/// `mastersos-guest-cleanup.service` 经别名 `guest-cleanup` 走到这里）。不 panic、不建 tokio 运行时。
pub fn cleanup_main(user: Option<&OsStr>) -> ExitCode {
    // 清理服务以 root 跑；别人跑它一样都不做（提交安全审查：授权）
    if !rustix::process::geteuid().is_root() {
        let _ = writeln!(
            std::io::stderr(),
            "mastersos-agent ephemeral-cleanup: must run as root"
        );
        return ExitCode::FAILURE;
    }
    let Some(user) = user.and_then(OsStr::to_str) else {
        let _ = writeln!(
            std::io::stderr(),
            "mastersos-agent ephemeral-cleanup: an account name is required"
        );
        return ExitCode::from(2);
    };
    // 与 pam-check、pam-session 读同一份策略；kiosk 账号的 uid 现查，不猜
    let (_, policy) = login::installed_policy();
    let acct = match cleanup_target(user, policy.as_ref(), || login::lookup_uid_checked(user)) {
        Ok(a) => a,
        Err(why) => {
            let _ = writeln!(
                std::io::stderr(),
                "mastersos-agent ephemeral-cleanup: {user:?}: {why}; doing nothing"
            );
            return ExitCode::SUCCESS;
        }
    };
    let runner = RealRunner;
    let procs = SystemdProcs {
        runner: &runner,
        timeout: CMD_TIMEOUT,
    };
    let env = EphemeralEnv {
        runner: &runner,
        procs: &procs,
        root: Path::new("/"),
        uid: acct.uid,
        mounts: &ProcMounts,
        acct: &acct,
    };
    match cleanup(&env) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "mastersos-agent ephemeral-cleanup {user}: {e:#}"
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn kiosk_paths() {
        let k = kiosk("nwea", 1900, "NWEA MAP");
        assert_eq!(k.slice, "user-1900.slice");
        assert_eq!(k.home, Path::new("/home/kiosk-nwea"));
        assert_eq!(k.ready_mark, "kiosk-nwea-ready");
        assert_eq!(k.opening_mark, "kiosk-nwea-opening");
        assert_eq!(k.user, "kiosk-nwea");
        assert_eq!(k.uid, 1900);
        assert_eq!(k.comment, "NWEA MAP");
        assert_eq!(
            k.accounts_template.as_deref(),
            Some(Path::new(
                "/var/lib/mastersos-public/kiosk/nwea/accountsservice"
            ))
        );
        assert_eq!(
            k.cleanup_unit(),
            "mastersos-ephemeral-cleanup@kiosk-nwea.service"
        );
    }

    /// 访客在盘上、单元里的名字一个都不变：与 `guest` 模块的常量一致。
    #[test]
    fn fixed_names_of_the_first_account() {
        let g = guest();
        assert_eq!(
            g,
            Ephemeral {
                user: "guest".into(),
                uid: 1999,
                home: PathBuf::from("/home/guest"),
                slice: "user-1999.slice".into(),
                ready_mark: "guest-ready".into(),
                opening_mark: "guest-opening".into(),
                comment: "访客 Guest".into(),
                accounts_template: None,
            }
        );
        assert_eq!(
            Path::new(RUN_DIR).join(&g.ready_mark),
            Path::new(READY_MARK)
        );
        assert_eq!(g.cleanup_unit(), "mastersos-guest-cleanup.service");
    }

    /// 轮询与 SIGKILL 看的是同一个 slice：都来自 `acct`（kiosk 账号的 `user-1900.slice`），不会轮询一个、杀另一个。
    #[test]
    fn poll_and_kill_use_the_account_slice() {
        struct Rec(std::sync::Mutex<Vec<String>>);
        impl Procs for Rec {
            fn slice_active(&self, slice: &str) -> Result<bool> {
                let mut v = self.0.lock().unwrap();
                v.push(slice.to_string());
                // 前 150 次（30 秒）一直 active，逼出 SIGKILL；之后停下
                Ok(v.len() <= WAIT_POLLS as usize)
            }
            fn sleep(&self, _: Duration) {}
        }
        let acct = kiosk("nwea", 1900, "NWEA MAP");
        let r = crate::runner::FakeRunner::new();
        let procs = Rec(std::sync::Mutex::new(Vec::new()));
        let env = EphemeralEnv {
            runner: &r,
            procs: &procs,
            root: Path::new("/"),
            uid: acct.uid,
            mounts: &ProcMounts,
            acct: &acct,
        };
        wait_slice_gone(&env).unwrap();
        let polled = procs.0.lock().unwrap().clone();
        assert_eq!(polled.len(), WAIT_POLLS as usize + 1);
        assert!(polled.iter().all(|s| s == "user-1900.slice"), "{polled:?}");
        assert_eq!(
            r.calls(),
            vec!["systemctl kill --signal=KILL user-1900.slice".to_string()]
        );
    }

    fn kpol() -> LoginPolicy {
        LoginPolicy {
            methods: vec![],
            allowed_domains: vec![],
            admin_users: vec![],
            locked: false,
            lock_message: None,
            from_bundle: true,
            kiosk_users: vec![super::super::login::KioskUser {
                user: "kiosk-nwea".into(),
                name: "NWEA MAP".into(),
            }],
            it_account: false,
            it_account_uid: None,
        }
    }

    /// `ephemeral-cleanup` 认 `guest`（不查 uid）与策略名单里的 kiosk 账号（名字取自名单、uid 取自 getent）；
    /// uid 不在 1900–1989、名单外、没有策略、别的名字都不清理。
    #[test]
    fn cleanup_target_knows_guest_and_listed_kiosk_accounts() {
        let p = kpol();
        assert_eq!(
            cleanup_target("guest", None, || panic!("访客不查 uid")),
            Ok(guest())
        );
        assert_eq!(
            cleanup_target("kiosk-nwea", Some(&p), || Some(1900)),
            Ok(kiosk("nwea", 1900, "NWEA MAP"))
        );
        assert_eq!(
            cleanup_target("kiosk-nwea", Some(&p), || Some(1989)),
            Ok(kiosk("nwea", 1989, "NWEA MAP"))
        );
        for uid in [
            Some(1999),
            Some(1899),
            Some(1990),
            Some(0),
            Some(60000),
            None,
        ] {
            assert!(
                cleanup_target("kiosk-nwea", Some(&p), || uid).is_err(),
                "{uid:?}"
            );
        }
        assert!(cleanup_target("kiosk-nwea", None, || Some(1900)).is_err());
        assert!(cleanup_target("kiosk-old", Some(&p), || Some(1900)).is_err());
        for u in [
            "Guest",
            "guest ",
            "",
            "Kiosk-nwea",
            "kiosk-nwea ",
            "root",
            "alice",
        ] {
            assert!(cleanup_target(u, Some(&p), || Some(1900)).is_err(), "{u:?}");
        }
        // 名单里混进不带前缀的名字：也不认
        let mut odd = kpol();
        odd.kiosk_users[0].user = "alice".into();
        assert!(cleanup_target("alice", Some(&odd), || Some(1900)).is_err());
        assert_eq!(KIOSK_UIDS, 1900..=1989);
    }
}
