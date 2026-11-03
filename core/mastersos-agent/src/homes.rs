//! 共用机上 SSO 用户的家目录（spec §6.4，Ruling 14；计划 4b Task 19）：家目录留在本机，磁盘紧张时按最久未登录的
//! 顺序删。
//!
//! - 每次登录（Task 18 的 [`crate::login_queue::drain`] 取到的每个 uid）[`record_login`] 记下时刻，存在 [`LAST_LOGIN`]
//!   （0600，只在本机，不进回报）。文件坏了（解析不了、超过 [`MAX_LAST_LOGIN_BYTES`]）就改名为 `last-login.json.bad`、
//!   回报一次，所有人按「现在第一次见到」重新开始（保守：不会因为记录丢了而先删谁）。
//! - 记录在取走登录队列的同一步同步写（[`drain_and_record`]），在叫醒任何后台任务之前；登录记录在 [`RECENT_LOGIN`]
//!   之内的、记号还在登录队列里的人都当作正在用（复审 N1：登录者自己的 PAM 会话阶段里，`pam_systemd` 之前
//!   loginctl 与 slice 都还看不到他）。
//! - [`HomeCleanupJob`]（每小时一轮、换了新包时一轮；登录叫醒不跑）：
//!   1. 先删回收目录（[`trash::TRASH`]）里上一轮没删完的（中途崩溃、断电留下的）。
//!   2. 每轮都给没有记录的 uid 补记「第一次见到」的时刻（不只在空间不够时）。
//!   3. `/home` 的可用空间低于 [`needs_cleanup`] 的线才往下走。
//!   4. 管理员名单读 Task 10 写的登录策略（`login::POLICY_PATH`）；读不到、或它还不是由设置包写的（`from_bundle`
//!      为假：种子的默认值里没有管理员），这一轮一个都不删。
//!   5. 枚举 `/home` 的直接子目录（不跟随链接），名字经 `getent passwd <uid>`（authd 的用户不在 `/etc/passwd` 里）；
//!      只认目录名与属主的用户名相同的那一个（复审 M3）。[`candidates`] 只留 SSO 账号（名字含 `@`，与 Task 17 一致），
//!      去掉管理员、访客与正在用的人（`loginctl list-users` 里的，加上 `user-<uid>.slice` 还 active 的），按最近一次
//!      登录从旧到新。
//!   6. 逐个：再列一次 `loginctl`、再看一次 slice，然后 [`trash::to_trash`] 原子地挪进回收目录（之后登录的人由
//!      `pam_mkhomedir` 拿到新的家目录），再 [`trash::empty_trash`] 有界地删（不跟随链接、不跨挂载、出错跳过计数）。
//!      每删一个看一次 [`enough`]，够了就停。
//! - 回报项 [`ITEM`] 的 `detail` 只有个数与大小，**不写名字与 uid**；日志里也只记计数，不记学生家目录里的名字。
//! - 查不清的一律当作「不能删」：`loginctl` 失败这一轮不删；`systemctl is-active` 失败或状态不是明确的
//!   inactive/failed 当作 active；`getent` 查不到名字的不删。

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod trash;

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use mastersos_bundle::ItemResult;
use rustix::fs::{AtFlags, FileType};

use crate::jobs::{Job, JobCtx};
use crate::runner::{Cmd, Runner};
use crate::safefs;
use crate::system::lock::{self, LOGIN_CMD_TIMEOUT};
use crate::system::login::{LoginPolicy, MAX_POLICY_BYTES};
use crate::system::SysPaths;
pub use trash::Removal;

/// `uid → 最近一次登录的 UTC 时间`（0600，只在本机）。
pub const LAST_LOGIN: &str = "/var/lib/mastersos-system/homes/last-login.json";
/// [`LAST_LOGIN`] 在 `SysPaths::var_dir` 下的子目录与文件名。
const LAST_LOGIN_SUBDIR: &str = "homes";
const LAST_LOGIN_FILE: &str = "last-login.json";
/// 坏掉的登录记录改名为这个（同一目录）。
pub const LAST_LOGIN_BAD: &str = "last-login.json.bad";
/// 登录记录最多这么大（更大的当作坏了）。
pub const MAX_LAST_LOGIN_BYTES: u64 = 1024 * 1024;
/// 登录策略在 `var_dir` 下的位置（`login::POLICY_PATH`）。
const POLICY_SUBDIR: &str = "login";
const POLICY_FILE: &str = "policy.json";
/// 回报项。
pub const ITEM: &str = "homes";
/// 家目录所在。
pub const HOME_DIR: &str = "/home";
/// 访客账号的名字（Task 11）。
const GUEST: &str = "guest";
const GIB: u64 = 1 << 30;
const EVERY: Duration = Duration::from_secs(3600);

/// [`LAST_LOGIN`] 的读改写在本进程里串行（登录时的记录与清理任务的补记各在自己的阻塞线程里）。
static LAST_LOGIN_LOCK: Mutex<()> = Mutex::new(());

// ---------------------------------------------------------------------------
// 登录记录
// ---------------------------------------------------------------------------

/// 读 `path`。不存在是空的；坏了（解析不了、太大）改名为 [`LAST_LOGIN_BAD`] 并当作空的（下一次写入从头开始）。
fn load(path: &Path) -> BTreeMap<u32, DateTime<Utc>> {
    let Ok((parent, name)) = split(path) else {
        return BTreeMap::new();
    };
    let dir = match safefs::open_abs_dir(parent, false) {
        Ok(d) => d,
        Err(e) => {
            if !is_missing(&e) {
                log::warn!("homes: cannot open the login record directory: {e:#}");
            }
            return BTreeMap::new();
        }
    };
    let bytes = match safefs::open_file_at(&dir, name) {
        Ok(None) => return BTreeMap::new(),
        Ok(Some(f)) => {
            let mut buf = Vec::new();
            match f.take(MAX_LAST_LOGIN_BYTES + 1).read_to_end(&mut buf) {
                Ok(_) => buf,
                Err(e) => {
                    log::warn!("homes: reading the login record failed: {e}");
                    return BTreeMap::new();
                }
            }
        }
        Err(e) => {
            log::warn!("homes: reading the login record failed: {e:#}");
            return BTreeMap::new();
        }
    };
    let parsed = if bytes.len() as u64 > MAX_LAST_LOGIN_BYTES {
        None
    } else {
        serde_json::from_slice(&bytes).ok()
    };
    match parsed {
        Some(m) => m,
        None => {
            log::warn!("homes: the login record is corrupt; renamed to {LAST_LOGIN_BAD}, everyone counts as first seen now");
            if let Err(e) = safefs::rename_at(&dir, name, LAST_LOGIN_BAD) {
                log::warn!("homes: renaming the corrupt login record failed: {e:#}");
            }
            BTreeMap::new()
        }
    }
}

/// 写 `path`（0600）。上两级（`var_dir` 与 `homes/`）不存在就建出来、都收紧到 0700；再往上（`/var/lib`）要已经存在。
fn save(path: &Path, map: &BTreeMap<u32, DateTime<Utc>>) -> Result<()> {
    let (parent, name) = split(path)?;
    let (var, sub) = split(parent)?;
    let var = safefs::open_abs_dir(var, true)?;
    safefs::set_mode(&var, 0o700)?;
    let dir = safefs::open_dir_at(&var, Path::new(sub), true)?;
    safefs::set_mode(&dir, 0o700)?;
    safefs::write_at(&dir, name, &serde_json::to_vec_pretty(map)?, 0o600)?;
    Ok(())
}

fn split(path: &Path) -> Result<(&Path, &str)> {
    let parent = path.parent().context("the path has no parent directory")?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .context("the last path component is malformed")?;
    Ok((parent, name))
}

fn is_missing(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
    })
}

/// 记下 `uid` 在 `now` 登录了（Task 18 的 `drain` 每拿到一个 uid 调一次）。
pub fn record_login(path: &Path, uid: u32, now: DateTime<Utc>) -> Result<()> {
    // 不往回拨：开机时 RTC 偏早、NTP 还没对上时登录，不会让这个人看起来最久没登录（复审 N1 附注）
    record_logins(path, &[uid], now)
}

/// 取走登录队列（[`crate::login_queue::drain`]）并把每个 uid 记为在 `now` 登录（同步；失败只记日志）。主循环在叫醒
/// 后台任务之前调它（复审 T19 N1）。
///
/// 先写记录、写成了才删队列里的记号（复审 R1）：清理那一轮先看队列、再看记录，「记号没了」就一定「记录已在盘上」。
/// 写失败时记号留着（这个人仍算正在用），只记日志；下次叫醒再取、再写。
pub fn drain_and_record(queue: &Path, last_login: &Path, now: DateTime<Utc>) -> Vec<u32> {
    crate::login_queue::drain_with(queue, |uids| match record_logins(last_login, uids, now) {
        Ok(()) => true,
        Err(e) => {
            log::warn!("recording the last login failed; the login queue marker is kept: {e:#}");
            false
        }
    })
}

/// 一次读改写记下多个 uid 的登录（不往回拨）。
fn record_logins(path: &Path, uids: &[u32], now: DateTime<Utc>) -> Result<()> {
    let _g = LAST_LOGIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut map = load(path);
    for uid in uids {
        let t = map.get(uid).map_or(now, |old| (*old).max(now));
        map.insert(*uid, t);
    }
    save(path, &map)
}

/// 没有家目录的 uid 的记录留这么久（登录叫醒的那一轮可能在 `pam_mkhomedir` 建出家目录之前跑，VM 实测）。
const KEEP_HOMELESS: chrono::TimeDelta = chrono::TimeDelta::days(7);

/// 没有记录的 uid 补记 `now`（第一次见到它的时刻）；去掉家目录已经没了、且超过 [`KEEP_HOMELESS`] 没登录的记录。
/// 返回是否变了。
pub fn fill_unseen(
    map: &mut BTreeMap<u32, DateTime<Utc>>,
    uids: &BTreeSet<u32>,
    now: DateTime<Utc>,
) -> bool {
    let before = map.len();
    map.retain(|u, t| uids.contains(u) || *t > now - KEEP_HOMELESS);
    let mut changed = map.len() != before;
    for u in uids {
        if !map.contains_key(u) {
            map.insert(*u, now);
            changed = true;
        }
    }
    changed
}

// ---------------------------------------------------------------------------
// 纯判断
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeEntry {
    pub name: String,
    pub uid: u32,
    pub last_login: Option<DateTime<Utc>>,
}

/// 可以删的家目录，最久未登录的在前（见模块文档）。没有记录的排在最后（调用方先 [`fill_unseen`]，正常不会出现）。
pub fn candidates(
    entries: &[HomeEntry],
    admins: &[String],
    active_uids: &BTreeSet<u32>,
) -> Vec<HomeEntry> {
    let mut out: Vec<HomeEntry> = entries
        .iter()
        .filter(|e| e.name.contains('@'))
        .filter(|e| !e.name.eq_ignore_ascii_case(GUEST))
        .filter(|e| !admins.iter().any(|a| a.eq_ignore_ascii_case(&e.name)))
        .filter(|e| !active_uids.contains(&e.uid))
        .cloned()
        .collect();
    out.sort_by_key(|e| (e.last_login.is_none(), e.last_login, e.uid));
    out
}

/// 要清理：可用空间低于总量的 15% 与 10 GiB 中较大的那个。
pub fn needs_cleanup(free: u64, total: u64) -> bool {
    let pct = (u128::from(total) * 15 / 100) as u64;
    free < pct.max(10 * GIB)
}

/// 清理够了：可用空间不少于总量的 25% 与 15 GiB 中较大的那个（比 [`needs_cleanup`] 的线高，小盘也不会每小时再删一个）。
pub fn enough(free: u64, total: u64) -> bool {
    u128::from(free) * 100 >= u128::from(total) * 25 && free >= 15 * GIB
}

// ---------------------------------------------------------------------------
// 系统
// ---------------------------------------------------------------------------

/// 文件系统一侧（测试换成假的）。
pub trait HomeFs: Send + Sync {
    /// `(可用, 总量)`，字节。
    fn space(&self) -> Result<(u64, u64)>;
    /// 家目录所在目录里的真实子目录（不跟随链接）：`(名字, 属主)`。不含回收目录，不是 UTF-8 的名字跳过。
    fn homes(&self) -> Result<Vec<(String, u32)>>;
    /// 把 `name`（属主须是 `uid`）原子地挪进回收目录（[`trash::to_trash`]）。`Err`：没挪走；`Ok(false)`：挪走了、
    /// 没能收成 root 0700。
    fn to_trash(&self, name: &str, uid: u32) -> Result<bool>;
    /// 删空回收目录（没有回收目录时什么都不做）；回收目录不可信是错误。
    fn empty_trash(&self) -> Result<Removal>;
}

/// 真的 `/home`。
pub struct RealHomeFs {
    pub dir: PathBuf,
}

impl RealHomeFs {
    fn open(&self) -> Result<std::os::fd::OwnedFd> {
        safefs::open_abs_dir(&self.dir, false)
    }
}

impl HomeFs for RealHomeFs {
    fn space(&self) -> Result<(u64, u64)> {
        let s = rustix::fs::statvfs(&self.dir)
            .map_err(std::io::Error::from)
            .context("statvfs /home")?;
        Ok((
            s.f_bavail.saturating_mul(s.f_frsize),
            s.f_blocks.saturating_mul(s.f_frsize),
        ))
    }

    fn homes(&self) -> Result<Vec<(String, u32)>> {
        let d = self.open()?;
        let mut out = Vec::new();
        for e in rustix::fs::Dir::read_from(&d).map_err(std::io::Error::from)? {
            let e = e.map_err(std::io::Error::from)?;
            let Ok(name) = std::str::from_utf8(e.file_name().to_bytes()) else {
                continue;
            };
            if name == "." || name == ".." || name == trash::TRASH {
                continue;
            }
            match rustix::fs::statat(&d, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(st) if FileType::from_raw_mode(st.st_mode) == FileType::Directory => {
                    out.push((name.to_string(), st.st_uid));
                }
                Ok(_) | Err(rustix::io::Errno::NOENT) => {}
                Err(e) => return Err(std::io::Error::from(e).into()),
            }
        }
        out.sort();
        Ok(out)
    }

    fn to_trash(&self, name: &str, uid: u32) -> Result<bool> {
        let home = self.open()?;
        let t =
            trash::open_trash(&home, true)?.context("the trash directory could not be created")?;
        trash::to_trash(&home, &t, name, uid)
    }

    fn empty_trash(&self) -> Result<Removal> {
        let home = self.open()?;
        let Some(t) = trash::open_trash(&home, false)? else {
            return Ok(Removal::default());
        };
        let b = trash::Boundary::of(&home)?;
        Ok(trash::empty_trash(&t, &b))
    }
}

/// `getent passwd <uid>` 的第 1 列；查不到、输出对不上（第 3 列不是这个 uid）为 `None`。
fn name_of(uid: u32, runner: &dyn Runner) -> Option<String> {
    let id = uid.to_string();
    let out = runner
        .run(&Cmd::new("getent", &["passwd", "--", &id]).timeout(LOGIN_CMD_TIMEOUT))
        .ok()?;
    if out.code != 0 {
        return None;
    }
    let line = out.stdout.lines().next()?;
    let f: Vec<&str> = line.split(':').collect();
    (f.len() >= 3 && f[2] == id && !f[0].is_empty()).then(|| f[0].to_string())
}

/// `user-<uid>.slice` 是不是还在用：只有 `systemctl is-active` 明确回答 inactive / failed 才算不在用。
fn slice_active(uid: u32, runner: &dyn Runner) -> bool {
    let unit = format!("user-{uid}.slice");
    match runner.run(&Cmd::new("systemctl", &["is-active", &unit]).timeout(LOGIN_CMD_TIMEOUT)) {
        Ok(o) if o.code != 0 => !matches!(o.stdout.trim(), "inactive" | "failed"),
        _ => true,
    }
}

/// 登录着的 uid（`loginctl list-users`）；列不出、解析不了是错误。
fn logged_in(runner: &dyn Runner) -> Result<BTreeSet<u32>> {
    lock::list_users(runner).and_then(|j| lock::logged_in_uids(&j))
}

/// 登录记录在这么久之内的人当作正在用（复审 T19 N1）。
pub const RECENT_LOGIN: chrono::TimeDelta = chrono::TimeDelta::minutes(15);

/// 登录记录在 [`RECENT_LOGIN`] 之内的 uid。
fn recent(map: &BTreeMap<u32, DateTime<Utc>>, now: DateTime<Utc>) -> BTreeSet<u32> {
    map.iter()
        .filter(|(_, t)| **t > now - RECENT_LOGIN)
        .map(|(u, _)| *u)
        .collect()
}

/// 登录队列（Task 18 的 `pam-session` 放的记号，agent 还没取走）里的 uid。只读、不取；目录不存在为空。
fn queued(paths: &SysPaths) -> Result<BTreeSet<u32>> {
    let p = paths
        .root
        .join(crate::login_queue::QUEUE_DIR.trim_start_matches('/'));
    let dir = match safefs::open_abs_dir(&p, false) {
        Ok(d) => d,
        Err(e) if is_missing(&e) => return Ok(BTreeSet::new()),
        Err(e) => return Err(e),
    };
    Ok(safefs::list_at(&dir)?
        .iter()
        .filter_map(|n| n.parse().ok())
        .collect())
}

/// 挪走之前的最后一次核对：loginctl 里有、slice 不是明确的 inactive、登录队列里有、刚登录过，都算正在用。
/// 查不清的（loginctl 或队列读不了）也算。
fn in_use_now(uid: u32, runner: &dyn Runner, paths: &SysPaths) -> bool {
    if logged_in(runner).map_or(true, |a| a.contains(&uid)) || slice_active(uid, runner) {
        return true;
    }
    // 先看队列、再看记录（复审 R1）：drain_and_record 写好记录才删记号，两处之一一定看得到刚登录的人
    if queued(paths).map_or(true, |q| q.contains(&uid)) {
        return true;
    }
    let map = {
        let _g = LAST_LOGIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        load(&last_login_path(paths))
    };
    recent(&map, Utc::now()).contains(&uid)
}

/// 管理员名单读不到、或还不是包给的。
enum AdminsUnknown {
    Unreadable,
    NotFromBundle,
}

/// 管理员名单（登录策略里的 `admin_users`）：文件缺失、超过 `MAX_POLICY_BYTES`、解析不了，或不是由设置包写的，都不行。
fn read_admins(paths: &SysPaths) -> std::result::Result<Vec<String>, AdminsUnknown> {
    let read = || -> Result<LoginPolicy> {
        let dir = safefs::open_abs_dir(&paths.var_dir.join(POLICY_SUBDIR), false)?;
        let f = safefs::open_file_at(&dir, POLICY_FILE)?.context("no login policy file")?;
        let mut buf = Vec::new();
        f.take(MAX_POLICY_BYTES as u64 + 1).read_to_end(&mut buf)?;
        anyhow::ensure!(
            buf.len() <= MAX_POLICY_BYTES,
            "the login policy is too large"
        );
        serde_json::from_slice(&buf).context("parsing the login policy")
    };
    match read() {
        Ok(p) if p.from_bundle => Ok(p.admin_users),
        Ok(_) => Err(AdminsUnknown::NotFromBundle),
        Err(e) => {
            log::warn!("homes: cannot read the administrator list: {e:#}");
            Err(AdminsUnknown::Unreadable)
        }
    }
}

fn last_login_path(paths: &SysPaths) -> PathBuf {
    paths.var_dir.join(LAST_LOGIN_SUBDIR).join(LAST_LOGIN_FILE)
}

/// 坏掉的登录记录（`.bad`）的修改时间；没有为 `None`。
fn bad_mtime(paths: &SysPaths) -> Option<SystemTime> {
    let dir = safefs::open_abs_dir(&paths.var_dir.join(LAST_LOGIN_SUBDIR), false).ok()?;
    safefs::mtime_at(&dir, LAST_LOGIN_BAD).ok().flatten()
}

fn result(ok: bool, detail: String) -> ItemResult {
    ItemResult {
        item: ITEM.into(),
        ok,
        detail: Some(detail),
    }
}

fn failed(detail: String) -> ItemResult {
    result(false, detail)
}

/// 字节数写成人看的（MiB / GiB）。
fn human(b: u64) -> String {
    if b >= GIB {
        format!("{:.1} GiB", b as f64 / GIB as f64)
    } else {
        format!("{} MiB", b >> 20)
    }
}

/// 这一轮要附在回报里的提示（`ok` 为假的那些），与正文用「；」连起来。
fn with_notes(ok: bool, body: String, notes: &[String]) -> ItemResult {
    let mut d = body;
    for n in notes {
        d.push('；');
        d.push_str(n);
    }
    result(ok && notes.is_empty(), d)
}

/// 一轮清理（阻塞），见模块文档。`bad_seen`：上次回报过的坏记录（`.bad`）的修改时间，同一份只回报一次。
pub fn cleanup(
    fs: &dyn HomeFs,
    runner: &dyn Runner,
    paths: &SysPaths,
    now: DateTime<Utc>,
    bad_seen: &Mutex<Option<SystemTime>>,
) -> ItemResult {
    let mut notes = vec![];
    // 1. 上一轮没删完的
    // 删不掉的旧项每次 empty_trash 都会再数一遍：之后每个家目录只算比它多出来的（复审 N2）
    let mut stale_left = match fs.empty_trash() {
        Ok(r) => {
            if r.left() > 0 {
                notes.push(format!(
                    "entries in the trash directory that still cannot be removed: {} (mount points or errors); retrying next round",
                    r.left()
                ));
            } else if r.removed > 0 {
                log::info!(
                    "homes: removed {} entries left in the trash directory",
                    r.removed
                );
            }
            r.left()
        }
        Err(e) => return failed(format!("{e:#}")),
    };
    let homes = match fs.homes() {
        Ok(h) => h,
        Err(e) => return failed(format!("cannot list home directories: {e:#}")),
    };
    // 2. 每轮都补记第一次见到的
    let owners: BTreeSet<u32> = homes.iter().map(|(_, u)| *u).collect();
    let logins = {
        let _g = LAST_LOGIN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = last_login_path(paths);
        let mut map = load(&path);
        if fill_unseen(&mut map, &owners, now) {
            if let Err(e) = save(&path, &map) {
                log::warn!("homes: writing the login record failed: {e:#}");
            }
        }
        map
    };
    if let Some(m) = bad_mtime(paths) {
        let mut g = bad_seen.lock().unwrap_or_else(|e| e.into_inner());
        if *g != Some(m) {
            *g = Some(m);
            notes.push(format!(
                "the login record was corrupt and was renamed to {LAST_LOGIN_BAD}; everyone counts as first seen now"
            ));
        }
    }
    // 3. 空间
    let (free0, total) = match fs.space() {
        Ok(s) => s,
        Err(e) => {
            return failed(format!(
                "cannot read the free space of the home partition: {e:#}"
            ))
        }
    };
    if !needs_cleanup(free0, total) {
        return with_notes(true, "enough free space; no cleanup needed".into(), &notes);
    }
    // 4. 管理员名单
    let admins = match read_admins(paths) {
        Ok(a) => a,
        Err(AdminsUnknown::Unreadable) => {
            return with_notes(false, "cannot read the administrator list; not cleaning up this round".into(), &notes)
        }
        Err(AdminsUnknown::NotFromBundle) => {
            return with_notes(
                false,
                "no login policy has been written from a bundle yet (administrator list unknown); not cleaning up this round".into(),
                &notes,
            )
        }
    };
    // 5. 候选：目录名与属主的用户名相同的那一个
    let entries: Vec<HomeEntry> = homes
        .iter()
        .filter(|(_, u)| *u != 0)
        .filter_map(|(dir, uid)| {
            let name = name_of(*uid, runner)?;
            (name == *dir).then(|| HomeEntry {
                last_login: logins.get(uid).copied(),
                name,
                uid: *uid,
            })
        })
        .collect();
    let mut active = match logged_in(runner) {
        Ok(a) => a,
        Err(e) => {
            log::warn!("homes: cannot list signed-in users: {e:#}");
            return with_notes(
                false,
                "cannot list signed-in users; not cleaning up this round".into(),
                &notes,
            );
        }
    };
    // 刚登录的（登录记录在 RECENT_LOGIN 之内）与登录队列里还没取走的，都当作正在用（复审 N1：PAM 会话阶段里
    // pam_systemd 之前，loginctl 与 slice 都还看不到这个人）
    active.extend(recent(&logins, now));
    match queued(paths) {
        Ok(q) => active.extend(q),
        Err(e) => {
            log::warn!("homes: cannot read the login queue: {e:#}");
            return with_notes(
                false,
                "cannot read the login queue; not cleaning up this round".into(),
                &notes,
            );
        }
    }
    for e in &entries {
        if e.name.contains('@') && !active.contains(&e.uid) && slice_active(e.uid, runner) {
            active.insert(e.uid);
        }
    }
    // 6. 逐个挪走、删
    let (mut removed, mut errors, mut partial, mut left) = (0usize, 0usize, 0usize, 0usize);
    let mut free = free0;
    for c in candidates(&entries, &admins, &active) {
        if in_use_now(c.uid, runner, paths) {
            log::info!("homes: a candidate started a session before removal; skipping it");
            continue;
        }
        match fs.to_trash(&c.name, c.uid) {
            Ok(true) => {}
            // 挪走了、但没能收成 root 0700：家目录已经不在原处，照样删、照样算空间，记一个错误（复审 N3）
            Ok(false) => errors += 1,
            Err(e) => {
                errors += 1;
                log::warn!("homes: moving a home directory away failed: {e:#}");
                continue;
            }
        }
        removed += 1;
        match fs.empty_trash() {
            Ok(r) => {
                let new_left = r.left().saturating_sub(stale_left);
                stale_left = r.left();
                log::info!(
                    "homes: removed a home directory ({} entries, {} left)",
                    r.removed,
                    new_left
                );
                if new_left > 0 {
                    partial += 1;
                    left += new_left;
                }
            }
            Err(e) => {
                errors += 1;
                log::warn!("homes: removing the trash directory failed: {e:#}");
            }
        }
        match fs.space() {
            Ok((f, _)) => free = f,
            Err(e) => {
                log::warn!("homes: cannot read free space after removal; stopping: {e:#}");
                errors += 1;
                break;
            }
        }
        if enough(free, total) {
            break;
        }
    }
    let mut body = format!(
        "home directories removed: {removed}, freed {}",
        human(free.saturating_sub(free0))
    );
    if partial > 0 {
        body.push_str(&format!(
            "; partly removed: {partial} ({left} mount points or unremovable entries left in the trash directory)"
        ));
    }
    if errors > 0 {
        body.push_str(&format!("; failed removals: {errors}"));
    }
    let low = needs_cleanup(free, total);
    if low {
        body.push_str("; still low on space");
    }
    with_notes(errors == 0 && partial == 0 && !low, body, &notes)
}

/// 后台任务 `homes`：每小时一轮 [`cleanup`]。
pub struct HomeCleanupJob {
    runner: Arc<dyn Runner>,
    fs: Arc<dyn HomeFs>,
    bad_seen: Arc<Mutex<Option<SystemTime>>>,
}

impl HomeCleanupJob {
    pub fn new(runner: Arc<dyn Runner>) -> Self {
        Self::with_fs(
            runner,
            Arc::new(RealHomeFs {
                dir: HOME_DIR.into(),
            }),
        )
    }

    pub fn with_fs(runner: Arc<dyn Runner>, fs: Arc<dyn HomeFs>) -> Self {
        HomeCleanupJob {
            runner,
            fs,
            bad_seen: Default::default(),
        }
    }
}

impl Job for HomeCleanupJob {
    fn name(&self) -> &'static str {
        "homes"
    }

    fn every(&self) -> Duration {
        EVERY
    }

    /// 登录叫醒不跑（复审 T19 N1：那一刻正是登录者自己的 PAM 会话阶段）；只按钟点与新包跑。登录带来的拉取若接受了
    /// 新包，一轮仍可能在登录途中开始——那时的安全靠「先写记录再删队列记号」与 15 分钟的保护（复审 R1、X2），不靠这里。
    fn wake_on_signal(&self) -> bool {
        false
    }

    fn wake_on_new_bundle(&self) -> bool {
        true
    }

    fn run<'a>(
        &'a self,
        cx: &'a JobCtx,
    ) -> Pin<Box<dyn Future<Output = Vec<ItemResult>> + Send + 'a>> {
        Box::pin(async move {
            let (runner, fs, paths, bad) = (
                self.runner.clone(),
                self.fs.clone(),
                cx.paths.clone(),
                self.bad_seen.clone(),
            );
            match tokio::task::spawn_blocking(move || {
                cleanup(fs.as_ref(), runner.as_ref(), &paths, Utc::now(), &bad)
            })
            .await
            {
                Ok(r) => vec![r],
                Err(e) => vec![failed(format!("exited abnormally: {e}"))],
            }
        })
    }
}

#[cfg(test)]
mod tests;
