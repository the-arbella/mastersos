//! 登录钩子（Ruling 9、10；计划 4b Task 18）：每次登录都叫醒 agent 立即拉取，`login` 脚本以本人身份跑，
//! 设置可能过期时提示。
//!
//! - [`enqueue`]（`pam-session` 的 open_session，root，在 PAM 里）：往 [`QUEUE_DIR`] 放一个空文件 `<uid>`
//!   （目录 0700 root），再 `systemctl kill -s USR1 --kill-whom=main mastersos-agent.service`。任何一步失败只往 stderr
//!   记一行，**永远不让登录失败**；agent 没在跑时记号留在队列里，agent 下次启动时取走。
//! - 主循环被叫醒（以及启动）时 [`drain`] 取走队列（读完即删），照常拉取；拉取与这一轮应用都结束之后，在阻塞线程里
//!   对取到的每个 uid 跑 [`run_login_scripts`]，不挡主循环（见 `run.rs`）。
//! - 步骤 `login-scripts-export`（[`step`]，fast）把当前分组 `when = "login"` 的脚本导出到 [`EXPORT_DIR`]
//!   （经 `system::public_dir()`；目录 0755、脚本 0755、[`INDEX`] 0644），删掉不再需要的。不放 `/var/lib/mastersos-system`
//!   或 agent 的状态目录：那里 0700，用户的 `systemd-run --user` 读不到。导出的脚本本机所有用户都读得到（以用户身份
//!   运行，本来就得读得到）——**别在 `login` 脚本里放秘密**。
//! - 脚本在该用户的 user manager 里跑：先等 `user@<uid>.service` active（最多 30 秒），再
//!   `systemd-run --machine=<uid>@.host --user --wait --pipe --collect -p RuntimeMaxSec=<超时> <导出的脚本>`，超时由
//!   systemd 终止。`--machine=` 用**数字 uid**：SSO 用户名里有 `@`，写名字有歧义（VM 实测 systemd 259 接受数字 uid）。
//!   按 `"<uid>:<路径>"` 记执行前读出的内容哈希（`State::login_script_hashes`，只在本机），退出码 0 才记，同一内容每人只
//!   成功跑一次；访客（uid 1999）的家目录每次会话都是新的，每次都跑、不记。
//! - 超时的判断：`systemd-run --wait` 在单元被 `RuntimeMaxSec` 终止时退出码是 [`SYSTEMD_RUN_TIMEOUT_CODE`]，与脚本自己
//!   `exit 1` 相同（systemd 255 与 259 实测），所以不加 `--quiet`，再认它结尾的状态行 `Finished with result: timeout`。
//! - 回报项 `login-script:<路径>`，同一脚本多个用户时只留最近一次真的跑了的结果（跳过的不出结果）；`detail` 只有
//!   退出码或「超时」，**不带脚本的输出**（里面可能有用户名、家目录路径），也不带 uid。
//! - `login` 脚本是方便用的机制，不是强制点（复审 N3）：它在用户自己的 user manager 里跑，用户能用自己的
//!   `~/.config/systemd/user` 改它的单元、让它不做事或回报成功/失败。必须做到的事放 `apply` 脚本与设置项。
//! - 已知限制（复审 M7）：队列取出即删、等着的 uid 与跑完未合并的哈希只在内存里；agent 恰在这之间重启，这次登录的脚本
//!   要到下次登录才跑，或已跑过的会再跑一次。
//! - Stale-settings notice ([`notify_if_stale`]): when `report::is_stale` holds (plan 2 Rulings 10, 11: a signed heartbeat
//!   extends freshness), the same `systemd-run` sends one `notify-send` with the number of days; with `newer_withheld` it
//!   says that newer settings could not be fetched instead. The text is in the system language through the
//!   `mastersos-system` catalogue ([`crate::i18n`], [`StaleNotice`]).

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use mastersos_bundle::{Config, ItemResult, Script, Seed, When, MAX_SCRIPT_TIMEOUT_SECS};
use serde::Serialize;

use crate::apply::{sha256_hex, ApplyContext};
use crate::config::DEFAULT_SCRIPT_TIMEOUT_SECS;
use crate::i18n::{self, Locale};
use crate::runner::{Cmd, RealRunner, Runner};
use crate::safefs;
use crate::state::State;
use crate::system::guest::GUEST_UID;
use crate::system::text::slug;
use crate::system::{public_dir, Env, Step, SysPaths};

pub const QUEUE_DIR: &str = "/run/mastersos/login-queue";
const RUN_DIR: &str = "run/mastersos";
const QUEUE_NAME: &str = "login-queue";
/// 导出的 `login` 脚本（`public_dir` 下的 [`EXPORT_SUB`]）。
pub const EXPORT_DIR: &str = "/var/lib/mastersos-public/login-scripts";
const EXPORT_SUB: &str = "login-scripts";
/// 导出目录里的索引：脚本路径 → 文件名与超时。
pub const INDEX: &str = "index.json";
/// 回报项的前缀（后面是脚本路径）。
pub const ITEM_PREFIX: &str = "login-script:";
const AGENT_UNIT: &str = "mastersos-agent.service";
/// PAM 里叫醒 agent 最多等这么久（之后 RealRunner 再给 5 秒 TERM 宽限；叫醒只是尽力而为，记号留在队列里）。
const SIGNAL_TIMEOUT: Duration = Duration::from_secs(1);
/// 等 `user@<uid>.service` active 最多这么久、每隔这么久看一次。
const USER_WAIT: Duration = Duration::from_secs(30);
const USER_POLL: Duration = Duration::from_secs(1);
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(10);
/// `systemd-run` 本身比脚本的超时多给这么久（单元由 systemd 按 RuntimeMaxSec 终止，这只是兜底）。
const RUN_SLACK: Duration = Duration::from_secs(60);
/// `systemd-run --wait` 在单元因 RuntimeMaxSec 被终止时的退出码（VM 实测；与脚本自己退出 1 相同，见模块文档）。
pub const SYSTEMD_RUN_TIMEOUT_CODE: i32 = 1;
/// `systemd-run --wait`（不带 `--quiet`）在单元结束后打在 stderr 结尾的状态行。
const TIMEOUT_RESULT: &str = "Finished with result: timeout";
/// 状态行在 stderr 的最后这么多行里找（systemd 255 打 6 行）。
const RESULT_TAIL_LINES: usize = 12;
/// 发提示：GNOME Shell 可能比 user manager 晚几秒起来，`notify-send` 失败就隔一会儿再试。
const NOTIFY_TRIES: u32 = 6;
const NOTIFY_PAUSE: Duration = Duration::from_secs(5);
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(20);

// ---------------------------------------------------------------------------
// 队列
// ---------------------------------------------------------------------------

/// 记下 `uid` 开了一个会话并叫醒 agent（`pam-session`）。永远返回 Ok：失败只往 stderr 记一行。
pub fn enqueue(uid: u32) -> Result<()> {
    enqueue_at(Path::new("/"), uid, &RealRunner)
}

/// 同 [`enqueue`]，队列在 `root` 下（测试用临时目录）、命令经 `runner`。
pub fn enqueue_at(root: &Path, uid: u32, runner: &dyn Runner) -> Result<()> {
    if let Err(e) = put(root, uid) {
        warn(&format!(
            "cannot write to the login queue (login scripts are skipped this time; sign-in goes ahead): {e:#}"
        ));
    }
    // 记号写没写进去都叫醒：每次登录都立即拉取一次（spec §6.6）。
    let cmd = Cmd::new(
        "systemctl",
        &[
            "--no-ask-password",
            "kill",
            "-s",
            "USR1",
            "--kill-whom=main",
            AGENT_UNIT,
        ],
    )
    .timeout(SIGNAL_TIMEOUT);
    match runner.run(&cmd) {
        Ok(o) if o.code == 0 => {}
        Ok(o) => warn(&format!(
            "waking the agent failed (systemctl exit code {}; if the agent is not running it takes the queue when it next starts)",
            o.code
        )),
        Err(e) => warn(&format!("waking the agent failed: {e:#}")),
    }
    Ok(())
}

fn put(root: &Path, uid: u32) -> Result<()> {
    // `/run/mastersos` 与队列目录都由 tmpfiles 建成 root:root 0700；PAM 里自己建出来时进程的 egid 可能是登录用户的组
    // （VM 实测：root:student）、umask 也是继承来的，所以两级都收回 root:root 0700（复审 M5）
    let parent = safefs::open_dir(root, Path::new(RUN_DIR), true)?;
    own_root_0700(&parent)?;
    let dir = safefs::open_dir_at(&parent, Path::new(QUEUE_NAME), true)?;
    own_root_0700(&dir)?;
    safefs::write_at(&dir, &uid.to_string(), b"", 0o600)?;
    Ok(())
}

/// 是 root 时 chown root:root；都 chmod 0700（测试里不是 root，只改权限）。
fn own_root_0700(dir: &std::os::fd::OwnedFd) -> Result<()> {
    if rustix::process::geteuid().is_root() {
        safefs::set_owner(dir, 0, 0)?;
    }
    safefs::set_mode(dir, 0o700)
}

/// 队列目录可信：属主是本进程（agent 是 root），组与其他人没有任何权限。
fn trusted_dir(dir: &std::os::fd::OwnedFd) -> Result<()> {
    let st = rustix::fs::fstat(dir).map_err(std::io::Error::from)?;
    let me = rustix::process::geteuid().as_raw();
    if st.st_uid != me || st.st_mode as u32 & 0o077 != 0 {
        anyhow::bail!(
            "owner {}, mode {:o} (expected owner {me}, 0700)",
            st.st_uid,
            st.st_mode as u32 & 0o7777
        );
    }
    Ok(())
}

/// PAM 里没有日志：写一行 stderr（pam_exec 交给 journal）。
fn warn(msg: &str) {
    let _ = writeln!(std::io::stderr(), "mastersos-agent pam-session: {msg}");
}

/// 取走队列里的 uid（读完即删；认不出的名字也删）。目录不存在为空。按 uid 排序、去重。
/// 目录不是 agent 自己的、或组与其他人有权限时一个都不取（记日志）：那样的目录里的记号不可信（复审 M5）。
pub fn drain(dir: &Path) -> Vec<u32> {
    drain_with(dir, |_| true)
}

/// 同 [`drain`]，但先读出 uid、交给 `before_ack`，它返回真才删掉这些 uid 的记号（Task 19 复审 R1：先把登录记录写进去
/// 再删记号，「记号没了」就意味着「记录已在盘上」；写失败时记号留着，这个人仍算正在用，下次叫醒再来）。
/// 认不出的名字照样删。返回读出的 uid（不论删没删记号）。
pub fn drain_with(dir: &Path, before_ack: impl FnOnce(&[u32]) -> bool) -> Vec<u32> {
    let fd = match safefs::open_abs_dir(dir, false) {
        Ok(d) => d,
        Err(e) => {
            log::debug!("cannot open the login queue (nobody has signed in): {e:#}");
            return vec![];
        }
    };
    if let Err(e) = trusted_dir(&fd) {
        log::warn!("the login queue directory is not trusted; not taking from it: {e:#}");
        return vec![];
    }
    let names = match safefs::list_at(&fd) {
        Ok(n) => n,
        Err(e) => {
            log::warn!("reading the login queue failed: {e:#}");
            return vec![];
        }
    };
    let mut out = BTreeSet::new();
    let mut marks = vec![];
    for n in names {
        match n.parse::<u32>() {
            Ok(uid) => {
                out.insert(uid);
                marks.push(n);
            }
            Err(_) => {
                log::warn!("unrecognized name {n:?} in the login queue; removing it");
                if let Err(e) = safefs::remove_at(&fd, &n) {
                    log::warn!("removing a marker from the login queue failed: {e:#}");
                }
            }
        }
    }
    let uids: Vec<u32> = out.into_iter().collect();
    if uids.is_empty() || !before_ack(&uids) {
        return uids;
    }
    for n in marks {
        if let Err(e) = safefs::remove_at(&fd, &n) {
            log::warn!("removing a marker from the login queue failed: {e:#}");
        }
    }
    uids
}

// ---------------------------------------------------------------------------
// 导出（步骤 `login-scripts-export`）
// ---------------------------------------------------------------------------

/// 导出目录里这个脚本的文件名：`sha256(路径)` 的前 12 位（与脚本路径里有什么字符无关）。
pub fn exported_name(path: &str) -> String {
    slug(path)
}

fn item(path: &str) -> String {
    format!("{ITEM_PREFIX}{path}")
}

fn failed(path: &str, detail: String) -> ItemResult {
    ItemResult {
        item: item(path),
        ok: false,
        detail: Some(detail),
    }
}

/// The Config's `when = "login"` scripts.
pub fn login_scripts(config: &Config) -> impl Iterator<Item = &Script> {
    config.scripts.iter().filter(|s| s.when == When::Login)
}

/// 脚本的超时（秒）：没写取默认值，夹到上限（validate 已拒收超过上限的；没经过 validate 的也不溢出）。
fn timeout_of(s: &Script) -> u64 {
    s.timeout_secs
        .unwrap_or(DEFAULT_SCRIPT_TIMEOUT_SECS)
        .min(MAX_SCRIPT_TIMEOUT_SECS)
}

#[derive(Serialize)]
struct IndexEntry {
    file: String,
    timeout_secs: u64,
}

/// 步骤 `login-scripts-export`（fast：开机在 GDM 之前也导出，第一个登录的人就有脚本）。
pub fn step() -> Step {
    Step {
        name: "login-scripts-export",
        fast: true,
        run: run_export,
        without_bundle: Some(run_export_without_bundle),
    }
}

fn run_export(ctx: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
    export(ctx.config, ctx.bundle_dir, env.paths)
}

/// 还没有包：没有 login 脚本，导出目录清空（只留空的索引）。
fn run_export_without_bundle(_: &Seed, env: &mut Env) -> Vec<ItemResult> {
    export_list(&[], Path::new(""), env.paths)
}

/// 把分组的 `login` 脚本复制到导出目录（0755）、写 [`INDEX`]（0644），删掉不再需要的。只回报失败的那几项
/// （`login-script:<路径>`）；导出不了的脚本连旧的导出也删掉，不会以旧内容去跑。
pub fn export(config: &Config, bundle_dir: &Path, paths: &SysPaths) -> Vec<ItemResult> {
    export_list(
        &login_scripts(config).collect::<Vec<_>>(),
        bundle_dir,
        paths,
    )
}

fn export_list(scripts: &[&Script], bundle_dir: &Path, paths: &SysPaths) -> Vec<ItemResult> {
    let dir = match public_dir(paths).and_then(|p| {
        let d = safefs::open_dir_at(&p, Path::new(EXPORT_SUB), true)?;
        safefs::set_mode(&d, 0o755)?;
        Ok(d)
    }) {
        Ok(d) => d,
        Err(e) => {
            return scripts
                .iter()
                .map(|s| failed(&s.path, format!("export failed: {e:#}")))
                .collect()
        }
    };
    let mut out = vec![];
    let mut index = BTreeMap::new();
    let mut keep = BTreeSet::from([INDEX.to_string()]);
    for s in scripts {
        let name = exported_name(&s.path);
        let written = std::fs::read(bundle_dir.join(&s.path))
            .context("the bundle has no such script")
            .and_then(|b| safefs::write_at(&dir, &name, &b, 0o755));
        match written {
            Ok(_) => {
                index.insert(
                    s.path.clone(),
                    IndexEntry {
                        file: name.clone(),
                        timeout_secs: timeout_of(s),
                    },
                );
                keep.insert(name);
            }
            Err(e) => out.push(failed(&s.path, format!("export failed: {e:#}"))),
        }
    }
    let idx = serde_json::to_vec_pretty(&index)
        .map_err(anyhow::Error::from)
        .and_then(|b| safefs::write_at(&dir, INDEX, &b, 0o644));
    if let Err(e) = idx {
        log::warn!("writing {INDEX} failed: {e:#}");
    }
    match safefs::list_at(&dir) {
        Ok(names) => {
            for n in names.iter().filter(|n| !keep.contains(*n)) {
                if let Err(e) = safefs::remove_at(&dir, n) {
                    log::warn!("removing the unneeded login script {n} failed: {e:#}");
                }
            }
        }
        Err(e) => log::warn!("reading the login script export directory failed: {e:#}"),
    }
    out
}

// ---------------------------------------------------------------------------
// 以用户身份运行
// ---------------------------------------------------------------------------

/// `systemd-run --machine=<uid>@.host --user`：连到这个 uid 的 user manager（数字 uid，不用名字）。
fn user_run(uid: u32, rest: &[&str]) -> Cmd {
    let machine = format!("--machine={uid}@.host");
    let mut args = vec![machine.as_str(), "--user"];
    args.extend_from_slice(rest);
    Cmd::new("systemd-run", &args)
}

/// 等 `user@<uid>.service` active，最多 `wait`。
fn wait_user(uid: u32, runner: &dyn Runner, wait: Duration) -> bool {
    let unit = format!("user@{uid}.service");
    let deadline = Instant::now() + wait;
    loop {
        let cmd =
            Cmd::new("systemctl", &["is-active", "--quiet", &unit]).timeout(SYSTEMCTL_TIMEOUT);
        if runner.run(&cmd).is_ok_and(|o| o.code == 0) {
            return true;
        }
        if Instant::now() + USER_POLL > deadline {
            return false;
        }
        std::thread::sleep(USER_POLL);
    }
}

fn timed_out(o: &crate::runner::Output) -> bool {
    o.code == SYSTEMD_RUN_TIMEOUT_CODE
        && o.stderr
            .lines()
            .rev()
            .take(RESULT_TAIL_LINES)
            .any(|l| l.trim() == TIMEOUT_RESULT)
}

/// 以 `uid` 的身份跑分组里的 `login` 脚本（读 `export_dir` 里导出的那一份），见模块文档。返回真的跑了的与出错的
/// 那几项；内容没变、这个人已经成功跑过的跳过、不出结果。
pub fn run_login_scripts(
    uid: u32,
    config: &Config,
    export_dir: &Path,
    state: &mut State,
    runner: &dyn Runner,
) -> Vec<ItemResult> {
    run_login_scripts_with(uid, config, export_dir, state, runner, USER_WAIT)
}

fn run_login_scripts_with(
    uid: u32,
    config: &Config,
    export_dir: &Path,
    state: &mut State,
    runner: &dyn Runner,
    wait: Duration,
) -> Vec<ItemResult> {
    let guest = uid == GUEST_UID;
    let mut out = vec![];
    // 先读出导出的内容：没导出的直接失败，这个人已经成功跑过同一内容的跳过（不出结果，也就不会因为会话没就绪而回报失败，复审 N1）
    let mut todo = vec![];
    for s in login_scripts(config) {
        let file = export_dir.join(exported_name(&s.path));
        let Ok(bytes) = std::fs::read(&file) else {
            out.push(failed(&s.path, "this script was not exported".into()));
            continue;
        };
        let hash = sha256_hex(&bytes);
        let key = format!("{uid}:{}", s.path);
        if !guest && state.login_script_hashes.get(&key) == Some(&hash) {
            continue;
        }
        todo.push((s, file, key, hash));
    }
    if todo.is_empty() {
        return out;
    }
    if !wait_user(uid, runner, wait) {
        out.extend(todo.iter().map(|(s, ..)| {
            failed(
                &s.path,
                format!(
                    "the user session was not ready (the user manager did not start within {} s); not run this time",
                    wait.as_secs()
                ),
            )
        }));
        return out;
    }
    for (s, file, key, hash) in todo {
        let secs = timeout_of(s);
        let max = format!("RuntimeMaxSec={secs}");
        let file_s = file.to_string_lossy();
        let cmd = user_run(uid, &["--wait", "--pipe", "--collect", "-p", &max, &file_s])
            .timeout(Duration::from_secs(secs) + RUN_SLACK);
        // detail 不带输出：脚本的输出里可能有用户名、家目录路径。
        let (ok, detail) = match runner.run(&cmd) {
            Ok(o) if o.code == 0 => (true, None),
            Ok(o) if timed_out(&o) => (
                false,
                Some(format!(
                    "timed out: did not finish within {secs} s; stopped by systemd"
                )),
            ),
            Ok(o) => (false, Some(format!("exit code {}", o.code))),
            // RealRunner 的错误只带程序名（「systemd-run 无法运行」「systemd-run 超时……」）
            Err(e) => (false, Some(format!("{e:#}"))),
        };
        // 跑的过程中下一轮应用可能换掉了导出的文件（复审 M1）：跑完再读一次，内容没变才记，变了就不记、下次登录照新内容再跑
        let unchanged = || std::fs::read(&file).is_ok_and(|b| sha256_hex(&b) == hash);
        if ok && !guest && unchanged() {
            state.login_script_hashes.insert(key, hash);
        }
        out.push(ItemResult {
            item: item(&s.path),
            ok,
            detail,
        });
    }
    out
}

/// 一个人这一次登录（主循环交给阻塞线程的）跑完的结果：这个 uid 的哈希（只有 `"<uid>:…"` 的键）与各项结果。
pub struct Batch {
    pub uid: u32,
    pub hashes: BTreeMap<String, String>,
    pub results: Vec<ItemResult>,
}

/// `hashes` 里属于 `uid` 的那些键。
pub fn hashes_of(hashes: &BTreeMap<String, String>, uid: u32) -> BTreeMap<String, String> {
    let prefix = format!("{uid}:");
    hashes
        .iter()
        .filter(|(k, _)| k.starts_with(&prefix))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// 把一个人跑完的哈希并进总表：先去掉这个 uid 的旧键，再放进新的（各人的键互不相交，几个人的批次可以同时跑）。
pub fn merge_hashes(all: &mut BTreeMap<String, String>, b: &Batch) {
    let prefix = format!("{}:", b.uid);
    all.retain(|k, _| !k.starts_with(&prefix));
    all.extend(b.hashes.iter().map(|(k, v)| (k.clone(), v.clone())));
}

/// 只留路径仍是当前分组 `login` 脚本的哈希（复审 M2：清单里删掉的脚本不再一直占着 state.json）。
pub fn prune_hashes(all: &mut BTreeMap<String, String>, config: &Config) {
    let paths: BTreeSet<&str> = login_scripts(config).map(|s| s.path.as_str()).collect();
    all.retain(|k, _| k.split_once(':').is_some_and(|(_, p)| paths.contains(p)));
}

/// 只留当前分组里还有的脚本的结果。
pub fn current_results<'a>(
    results: impl Iterator<Item = &'a ItemResult>,
    config: &Config,
) -> Vec<ItemResult> {
    let keep: BTreeSet<String> = login_scripts(config).map(|s| item(&s.path)).collect();
    results
        .filter(|r| keep.contains(&r.item))
        .cloned()
        .collect()
}

/// 以 `uid` 的身份跑一次 [`run_login_scripts`]（`hashes` 只需这个 uid 的键）。
pub fn run_batch(
    uid: u32,
    config: &Config,
    export_dir: &Path,
    hashes: BTreeMap<String, String>,
    runner: &dyn Runner,
) -> Batch {
    let mut st = State {
        login_script_hashes: hashes,
        ..State::default()
    };
    let results = run_login_scripts(uid, config, export_dir, &mut st, runner);
    Batch {
        uid,
        hashes: hashes_of(&st.login_script_hashes, uid),
        results,
    }
}

// ---------------------------------------------------------------------------
// 过期提示
// ---------------------------------------------------------------------------

/// The stale-settings notice when a newer bundle was withheld. A msgid of `mastersos-system` ([`crate::i18n`]).
pub const MSG_WITHHELD: &str = "Newer settings could not be fetched. Please contact IT.";
/// The stale-settings notice; `%s` is the number of days. A msgid of `mastersos-system` ([`crate::i18n`]).
pub const MSG_STALE_DAYS: &str = "Settings have not been confirmed up to date for %s days. Please connect to the network; if this persists, contact IT.";

/// Which stale-settings notice is due.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleNotice {
    /// A newer bundle was withheld ([`MSG_WITHHELD`]).
    Withheld,
    /// Not confirmed up to date for this many days ([`MSG_STALE_DAYS`]).
    Days(i64),
}

impl StaleNotice {
    /// The notice's text in `locale` (English for `None`), see [`crate::i18n::text`].
    pub fn text(self, runner: &dyn Runner, locale: Option<&Locale>) -> String {
        match self {
            StaleNotice::Withheld => i18n::text(runner, locale, MSG_WITHHELD),
            StaleNotice::Days(d) => i18n::text1(runner, locale, MSG_STALE_DAYS, &d.to_string()),
        }
    }
}

/// The notice to show when the settings may be stale; `None` when they are not. Decided by `report::is_stale` (plan 2
/// Rulings 10, 11). The days run from the last confirmation that the settings were current (review M3, not the brief's
/// `max(accepted_at, fresh_until)`: `fresh_until` is the end of the validity a heartbeat gave, not the moment of a
/// confirmation, and would undercount): with heartbeat evidence (`fresh_until`) `max(accepted_at, last_fetch_ok)`, else
/// `accepted_at` (the server saying "no newer version" is no confirmation), else `last_fetch_ok`.
pub fn stale_notice(state: &State, now: DateTime<Utc>) -> Option<StaleNotice> {
    if !crate::report::is_stale(
        state.last_fetch_ok,
        state.accepted_at,
        state.fresh_until,
        now,
    ) {
        return None;
    }
    if state.newer_withheld.is_some() {
        return Some(StaleNotice::Withheld);
    }
    let confirmed = if state.fresh_until.is_some() {
        state.accepted_at.max(state.last_fetch_ok)
    } else {
        state.accepted_at.or(state.last_fetch_ok)
    };
    let since = confirmed.filter(|t| *t < now).unwrap_or(now);
    Some(StaleNotice::Days((now - since).num_days().max(1)))
}

/// When the settings may be stale, shows `uid` a desktop notice in `locale` (waits for the user manager; a failed
/// `notify-send` is retried a few times, seconds apart).
pub fn notify_if_stale(
    uid: u32,
    state: &State,
    now: DateTime<Utc>,
    locale: Option<&Locale>,
    runner: &dyn Runner,
) {
    if let Some(n) = stale_notice(state, now) {
        let text = n.text(runner, locale);
        notify_with(uid, &text, runner, USER_WAIT, NOTIFY_PAUSE, NOTIFY_TRIES);
    }
}

/// Shows `text` as a notification in every signed-in person's session (`loginctl list-users`:
/// SSO accounts, local people and the guest; never root, GDM's greeter or other system
/// accounts). One try each, no waiting for a session that is still starting: the login screen
/// shows its own line from `status.json` ([`crate::status::set_collecting`]). Best effort.
pub fn notify_sessions(text: &str, runner: &dyn Runner) {
    let uids = crate::system::lock::list_users(runner)
        .and_then(|out| crate::system::lock::sessions_to_end(&out, &[]));
    match uids {
        Ok(uids) => {
            for uid in uids {
                notify_with(uid, text, runner, Duration::ZERO, Duration::ZERO, 1);
            }
        }
        Err(e) => log::warn!("listing the sessions for a notice failed: {e:#}"),
    }
}

fn notify_with(
    uid: u32,
    text: &str,
    runner: &dyn Runner,
    wait: Duration,
    pause: Duration,
    tries: u32,
) {
    if !wait_user(uid, runner, wait) {
        log::warn!("the user session of {uid} was not ready; no notice sent");
        return;
    }
    for i in 0..tries {
        let cmd = user_run(
            uid,
            &[
                "--wait",
                "--quiet",
                "--collect",
                "/usr/bin/notify-send",
                "--app-name=MastersOS",
                "MastersOS",
                text,
            ],
        )
        .timeout(NOTIFY_TIMEOUT);
        match runner.run(&cmd) {
            Ok(o) if o.code == 0 => return,
            Ok(o) => log::info!(
                "the notice was not sent (exit code {}); retrying later",
                o.code
            ),
            Err(e) => log::info!("the notice was not sent: {e:#}"),
        }
        if i + 1 < tries {
            std::thread::sleep(pause);
        }
    }
    log::warn!("the notice to {uid} was not sent after {tries} tries");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::sha256_hex;
    use crate::runner::{FakeRunner, Output};
    use crate::system::guest::GUEST_UID;
    use mastersos_bundle::Manifest;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    /// 每个 (path, timeout) 生成一条 `when = "login"` 的脚本。
    fn config(scripts: &[(&str, Option<u64>)]) -> Config {
        let mut s = String::from("version = 1\n[[group]]\nid = \"default\"\nname = \"d\"\n");
        for (p, t) in scripts {
            s += &format!("[[group.scripts]]\npath = \"{p}\"\nwhen = \"login\"\n");
            if let Some(t) = t {
                s += &format!("timeout_secs = {t}\n");
            }
        }
        s += "[[group.scripts]]\npath = \"scripts/root.sh\"\nwhen = \"apply\"\n";
        let m = Manifest::parse(&s).unwrap();
        mastersos_bundle::effective_config(&m, &m.configs[0])
    }

    /// 已导出的脚本目录：每个 (path, 内容)。
    fn exported(files: &[(&str, &str)]) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for (p, body) in files {
            fs::write(d.path().join(exported_name(p)), body).unwrap();
        }
        d
    }

    fn runs(r: &FakeRunner) -> Vec<String> {
        r.calls()
            .into_iter()
            .filter(|c| c.starts_with("systemd-run"))
            .collect()
    }

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    /// 队列目录建不出来（路径上有个普通文件）：返回 Ok、照样去叫醒 agent，登录不受影响。
    #[test]
    fn enqueue_never_fails_login() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("run"), b"not a dir").unwrap();
        let r = FakeRunner::new();
        assert!(enqueue_at(d.path(), 1001, &r).is_ok());
        assert_eq!(
            r.calls(),
            vec![
                "systemctl --no-ask-password kill -s USR1 --kill-whom=main mastersos-agent.service"
            ]
        );
        // agent 没在跑：systemctl 失败也是 Ok。
        let d = tempfile::tempdir().unwrap();
        let r = FakeRunner::new();
        r.respond(
            "systemctl",
            Output::fail(5, "Unit mastersos-agent.service not loaded."),
        );
        assert!(enqueue_at(d.path(), 1001, &r).is_ok());
        let q = d.path().join(QUEUE_DIR.trim_start_matches('/'));
        assert!(
            q.join("1001").exists(),
            "the marker is written; the agent takes it when it next starts"
        );
        assert_eq!(mode(&q), 0o700);
    }

    #[test]
    fn drain_reads_and_removes() {
        let d = tempfile::tempdir().unwrap();
        let r = FakeRunner::new();
        for uid in [1001, 1002, 1001] {
            enqueue_at(d.path(), uid, &r).unwrap();
        }
        let q = d.path().join(QUEUE_DIR.trim_start_matches('/'));
        fs::write(q.join("junk"), b"").unwrap();
        assert_eq!(drain(&q), vec![1001, 1002]);
        assert!(
            fs::read_dir(&q).unwrap().next().is_none(),
            "removed after reading, unrecognized ones too"
        );
        assert!(drain(&q).is_empty());
        assert!(drain(&d.path().join("missing")).is_empty());
    }

    /// 同一 uid 第二次不跑；另一个 uid 会跑；改脚本内容后两人都再跑。
    #[test]
    fn login_script_runs_once_per_user_and_hash() {
        let g = config(&[("scripts/hello.sh", None)]);
        let ex = exported(&[("scripts/hello.sh", "#!/bin/sh\necho 1\n")]);
        let r = FakeRunner::new();
        let mut st = State::default();
        let first = run_login_scripts(1001, &g, ex.path(), &mut st, &r);
        assert_eq!(first.len(), 1);
        assert!(first[0].ok, "{first:?}");
        assert_eq!(first[0].item, "login-script:scripts/hello.sh");
        assert_eq!(runs(&r).len(), 1);
        assert_eq!(
            st.login_script_hashes.get("1001:scripts/hello.sh"),
            Some(&sha256_hex(b"#!/bin/sh\necho 1\n"))
        );
        // 同一个人再登录：不跑、不出结果（不盖掉别人的最近一次）
        assert!(run_login_scripts(1001, &g, ex.path(), &mut st, &r).is_empty());
        assert_eq!(runs(&r).len(), 1);
        // 另一个人：跑
        run_login_scripts(1002, &g, ex.path(), &mut st, &r);
        assert_eq!(runs(&r).len(), 2);
        // 改了内容：两个人都再跑
        fs::write(
            ex.path().join(exported_name("scripts/hello.sh")),
            "#!/bin/sh\necho 2\n",
        )
        .unwrap();
        run_login_scripts(1001, &g, ex.path(), &mut st, &r);
        run_login_scripts(1002, &g, ex.path(), &mut st, &r);
        assert_eq!(runs(&r).len(), 4);
        // 失败的不记，下次再跑
        r.respond("systemd-run", Output::fail(3, ""));
        let mut st2 = State::default();
        let res = run_login_scripts(1003, &g, ex.path(), &mut st2, &r);
        assert!(!res[0].ok);
        assert_eq!(res[0].detail.as_deref(), Some("exit code 3"));
        assert!(st2.login_script_hashes.is_empty());
        run_login_scripts(1003, &g, ex.path(), &mut st2, &r);
        assert_eq!(runs(&r).len(), 6);
    }

    /// 访客的家目录每次会话都是新的：每次都跑、不记哈希。
    #[test]
    fn guest_runs_every_session() {
        let g = config(&[("scripts/hello.sh", None)]);
        let ex = exported(&[("scripts/hello.sh", "#!/bin/sh\n")]);
        let r = FakeRunner::new();
        let mut st = State::default();
        run_login_scripts(GUEST_UID, &g, ex.path(), &mut st, &r);
        run_login_scripts(GUEST_UID, &g, ex.path(), &mut st, &r);
        assert_eq!(runs(&r).len(), 2);
        assert!(st.login_script_hashes.is_empty());
    }

    /// systemd 以 RuntimeMaxSec 终止：systemd-run 退出码是 [`SYSTEMD_RUN_TIMEOUT_CODE`]，结尾的状态行是
    /// `Finished with result: timeout`（VM 实测，见模块文档）。脚本自己退出 1 不算超时。
    #[test]
    fn login_script_timeout_is_reported() {
        let g = config(&[("scripts/slow.sh", Some(5))]);
        let ex = exported(&[("scripts/slow.sh", "#!/bin/sh\nsleep 600\n")]);
        let r = FakeRunner::new();
        r.respond(
            "systemd-run",
            Output::fail(
                SYSTEMD_RUN_TIMEOUT_CODE,
                // systemd 259（VM 165 实测）的原样：状态行右对齐、前面有空格
                "Running as unit: run-p1662-i12657.service; invocation ID: 013c5856a75c4617ae939c4b8a14211d\n          Finished with result: timeout\nMain processes terminated with: code=killed, status=15/TERM\n               Service runtime: 5.178s\n             CPU time consumed: 8ms\n                   Memory peak: 1.7M (swap: 0B)\n",
            ),
        );
        let mut st = State::default();
        let res = run_login_scripts(1001, &g, ex.path(), &mut st, &r);
        assert!(!res[0].ok);
        let d = res[0].detail.as_deref().unwrap();
        assert!(d.contains("timed out"), "{d}");
        assert!(d.contains('5'), "{d}");
        assert!(st.login_script_hashes.is_empty());
        assert!(
            runs(&r)[0].contains("-p RuntimeMaxSec=5 "),
            "{:?}",
            runs(&r)
        );
        // 同样的退出码、没有那一行：脚本自己失败
        r.respond(
            "systemd-run",
            Output::fail(SYSTEMD_RUN_TIMEOUT_CODE, "boom\n"),
        );
        let res = run_login_scripts(1001, &g, ex.path(), &mut st, &r);
        assert_eq!(
            res[0].detail.as_deref(),
            Some(format!("exit code {SYSTEMD_RUN_TIMEOUT_CODE}").as_str())
        );
    }

    /// 回报项的 item 与 detail 都不含 uid（也就不含用户名：这里根本不知道名字）；脚本的输出不进回报。
    #[test]
    fn login_results_have_no_uid() {
        let g = config(&[
            ("scripts/ok.sh", None),
            ("scripts/fail.sh", None),
            ("scripts/slow.sh", Some(5)),
            ("scripts/missing.sh", None),
        ]);
        let ex = exported(&[
            ("scripts/ok.sh", "#!/bin/sh\n"),
            ("scripts/fail.sh", "#!/bin/sh\nexit 2\n"),
            ("scripts/slow.sh", "#!/bin/sh\nsleep 600\n"),
        ]);
        let r = FakeRunner::new();
        r.respond(
            "systemd-run --machine=4242@.host --user --wait --pipe --collect -p RuntimeMaxSec=300 ",
            Output {
                code: 0,
                stdout: "hello 4242 /home/alice@school.ac.th\n".into(),
                stderr: String::new(),
            },
        );
        r.respond(
            "systemd-run",
            Output::fail(2, "uid=4242 alice@school.ac.th\n"),
        );
        r.respond(
            "systemd-run",
            Output::fail(
                SYSTEMD_RUN_TIMEOUT_CODE,
                "4242\nFinished with result: timeout\n",
            ),
        );
        let mut st = State::default();
        let mut res = run_login_scripts(4242, &g, ex.path(), &mut st, &r);
        // 用户会话没有就绪
        let r2 = FakeRunner::new();
        r2.respond("systemctl is-active", Output::fail(3, "inactive"));
        res.extend(run_login_scripts_with(
            4242,
            &g,
            ex.path(),
            &mut State::default(),
            &r2,
            std::time::Duration::ZERO,
        ));
        assert_eq!(res.len(), 8, "{res:?}");
        for i in &res {
            let text = format!("{} {}", i.item, i.detail.as_deref().unwrap_or(""));
            assert!(!text.contains("4242"), "{text}");
            assert!(!text.contains("alice"), "{text}");
            assert!(i.item.starts_with(ITEM_PREFIX), "{text}");
        }
        assert_eq!(res.iter().filter(|i| i.ok).count(), 1, "{res:?}");
    }

    /// 导出到 public_dir 下（目录 0755、脚本 0755、index.json 0644），不在 0700 的 var_dir 下；不再需要的删掉。
    #[test]
    fn export_is_0755_and_hides_bundle_dir() {
        let root = crate::system::tests::tmp_root();
        let p = crate::system::tests::paths(root.path());
        let bundle = tempfile::tempdir().unwrap();
        fs::create_dir_all(bundle.path().join("scripts")).unwrap();
        fs::write(bundle.path().join("scripts/a.sh"), "#!/bin/sh\necho a\n").unwrap();
        fs::write(bundle.path().join("scripts/b.sh"), "#!/bin/sh\necho b\n").unwrap();
        fs::write(bundle.path().join("scripts/root.sh"), "#!/bin/sh\n").unwrap();
        let g = config(&[("scripts/a.sh", Some(9)), ("scripts/b.sh", None)]);
        assert!(export(&g, bundle.path(), &p).is_empty());
        let dir = p.public_dir.join("login-scripts");
        assert!(dir.starts_with(&p.public_dir) && !dir.starts_with(&p.var_dir));
        assert_eq!(
            Path::new(EXPORT_DIR),
            crate::system::SysPaths::default()
                .public_dir
                .join("login-scripts")
        );
        assert_eq!(mode(&dir), 0o755);
        let a = dir.join(exported_name("scripts/a.sh"));
        assert_eq!(fs::read_to_string(&a).unwrap(), "#!/bin/sh\necho a\n");
        assert_eq!(mode(&a), 0o755);
        assert_eq!(mode(&dir.join(INDEX)), 0o644);
        let idx: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join(INDEX)).unwrap()).unwrap();
        assert_eq!(idx["scripts/a.sh"]["file"], exported_name("scripts/a.sh"));
        assert_eq!(idx["scripts/a.sh"]["timeout_secs"], 9);
        assert_eq!(idx["scripts/b.sh"]["timeout_secs"], 300);
        // apply 脚本不导出
        let names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names.len(), 3, "{names:?}");
        // 清单里去掉 b、包里缺了 a：b 删掉；a 回报失败，旧的导出也删掉（不会跑旧内容）
        fs::remove_file(bundle.path().join("scripts/a.sh")).unwrap();
        let res = export(&config(&[("scripts/a.sh", None)]), bundle.path(), &p);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].item, "login-script:scripts/a.sh");
        assert!(!res[0].ok);
        assert!(!a.exists());
        assert!(!dir.join(exported_name("scripts/b.sh")).exists());
        assert!(dir.join(INDEX).exists());
        // var_dir 没被碰
        assert!(!p.var_dir.join("login-scripts").exists());
    }

    #[test]
    fn systemd_run_uses_numeric_uid() {
        let g = config(&[("scripts/hello.sh", Some(7))]);
        let ex = exported(&[("scripts/hello.sh", "#!/bin/sh\n")]);
        let r = FakeRunner::new();
        run_login_scripts(1001, &g, ex.path(), &mut State::default(), &r);
        let file = ex.path().join(exported_name("scripts/hello.sh"));
        assert_eq!(
            r.calls(),
            vec![
                "systemctl is-active --quiet user@1001.service".to_string(),
                format!(
                    "systemd-run --machine=1001@.host --user --wait --pipe --collect -p RuntimeMaxSec=7 {}",
                    file.display()
                ),
            ]
        );
        let r = FakeRunner::new();
        notify_if_stale(1001, &stale_state(), Utc::now(), None, &r);
        let n = r.calls().pop().unwrap();
        assert!(
            n.starts_with("systemd-run --machine=1001@.host --user "),
            "{n}"
        );
    }

    fn stale_state() -> State {
        State {
            accepted_at: Some(Utc::now() - chrono::TimeDelta::days(8)),
            last_fetch_ok: Some(Utc::now()),
            ..State::default()
        }
    }

    fn notices(r: &FakeRunner) -> Vec<String> {
        r.calls()
            .into_iter()
            .filter(|c| c.contains("notify-send"))
            .collect()
    }

    /// accepted_at 8 days ago, fresh_until None → one notify-send with the days; English without a locale, and no gettext.
    #[test]
    fn stale_state_sends_notification() {
        let r = FakeRunner::new();
        notify_if_stale(1001, &stale_state(), Utc::now(), None, &r);
        let n = notices(&r);
        assert_eq!(n.len(), 1, "{:?}", r.calls());
        assert!(n[0].contains("/usr/bin/notify-send"), "{}", n[0]);
        assert!(
            n[0].ends_with(
                " MastersOS Settings have not been confirmed up to date for 8 days. Please connect to the \
                 network; if this persists, contact IT."
            ),
            "{}",
            n[0]
        );
        assert!(!r.calls().iter().any(|c| c.contains("gettext")));
        // 不过期：什么都不发
        let r = FakeRunner::new();
        let fresh = State {
            accepted_at: Some(Utc::now() - chrono::TimeDelta::days(1)),
            last_fetch_ok: Some(Utc::now()),
            ..State::default()
        };
        notify_if_stale(1001, &fresh, Utc::now(), None, &r);
        assert!(r.calls().is_empty());
    }

    /// accepted_at 8 天前、fresh_until 明天、last_fetch_ok 刚才 → 不发（计划 2 Ruling 11：心跳延长了新鲜期）。
    #[test]
    fn heartbeat_freshness_suppresses_notification() {
        let st = State {
            fresh_until: Some(Utc::now() + chrono::TimeDelta::days(1)),
            ..stale_state()
        };
        let r = FakeRunner::new();
        notify_if_stale(1001, &st, Utc::now(), None, &r);
        assert!(notices(&r).is_empty(), "{:?}", r.calls());
        assert_eq!(stale_notice(&st, Utc::now()), None);
    }

    #[test]
    fn withheld_update_notifies_differently() {
        let st = State {
            newer_withheld: Some(5),
            ..stale_state()
        };
        assert_eq!(stale_notice(&st, Utc::now()), Some(StaleNotice::Withheld));
        let r = FakeRunner::new();
        notify_if_stale(1001, &st, Utc::now(), None, &r);
        assert!(notices(&r)[0].ends_with(&format!(" MastersOS {MSG_WITHHELD}")));
    }

    /// With a locale the notice is gettext's translation, the number in place of %s, run before notify-send.
    #[test]
    fn stale_notice_is_translated() {
        let th = Locale::from_name("th_TH.UTF-8").unwrap();
        let r = FakeRunner::new();
        r.respond(
            &format!(
                "/usr/bin/env LC_ALL=th_TH.UTF-8 LANGUAGE=th_TH TEXTDOMAIN=mastersos-system \
                 TEXTDOMAINDIR=/usr/share/locale /usr/bin/gettext -- {MSG_STALE_DAYS}"
            ),
            Output::ok("ยังไม่ได้ยืนยันการตั้งค่า %s วัน"),
        );
        notify_if_stale(1001, &stale_state(), Utc::now(), Some(&th), &r);
        let calls = r.calls();
        assert!(
            calls[0].contains("/usr/bin/gettext -- Settings"),
            "{calls:?}"
        );
        let n = notices(&r);
        assert_eq!(n.len(), 1, "{calls:?}");
        assert!(
            n[0].ends_with(" MastersOS ยังไม่ได้ยืนยันการตั้งค่า 8 วัน"),
            "{}",
            n[0]
        );
        // gettext missing or failing: English
        let r = FakeRunner::new();
        r.respond("/usr/bin/env", Output::fail(127, "no gettext"));
        notify_if_stale(1001, &stale_state(), Utc::now(), Some(&th), &r);
        assert!(notices(&r)[0].ends_with(" contact IT."), "{:?}", r.calls());
    }

    /// 队列目录不是 agent 自己的、或组与其他人有权限：一个都不取、记号原样留着（复审 M5）。
    #[test]
    fn drain_refuses_untrusted_dir() {
        let d = tempfile::tempdir().unwrap();
        enqueue_at(d.path(), 1001, &FakeRunner::new()).unwrap();
        let q = d.path().join(QUEUE_DIR.trim_start_matches('/'));
        assert_eq!(mode(&q), 0o700);
        assert_eq!(
            mode(q.parent().unwrap()),
            0o700,
            "/run/mastersos is tightened too"
        );
        for m in [0o750, 0o705, 0o777] {
            fs::set_permissions(&q, fs::Permissions::from_mode(m)).unwrap();
            assert!(drain(&q).is_empty(), "{m:o}");
            assert!(q.join("1001").exists());
        }
        fs::set_permissions(&q, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(drain(&q), vec![1001]);
        // 链接不跟随
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&q, &link).unwrap();
        enqueue_at(d.path(), 1002, &FakeRunner::new()).unwrap();
        assert!(drain(&link).is_empty());
        assert!(q.join("1002").exists());
    }

    /// root 跑时两级目录都收回 root:root（只在 Linux 上以 root 跑测试时验，例如 CI 的容器）。
    #[cfg(target_os = "linux")]
    #[test]
    fn enqueue_as_root_owns_dirs() {
        use std::os::unix::fs::MetadataExt;
        if !rustix::process::geteuid().is_root() {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let q = d.path().join(QUEUE_DIR.trim_start_matches('/'));
        fs::create_dir_all(&q).unwrap();
        std::os::unix::fs::chown(&q, Some(1000), Some(1000)).unwrap();
        std::os::unix::fs::chown(q.parent().unwrap(), Some(1000), Some(1000)).unwrap();
        enqueue_at(d.path(), 1001, &FakeRunner::new()).unwrap();
        for p in [&q, &q.parent().unwrap().to_path_buf()] {
            let m = fs::metadata(p).unwrap();
            assert_eq!((m.uid(), m.gid(), mode(p)), (0, 0, 0o700), "{p:?}");
        }
    }

    /// 会话没就绪时，这个人已经跑过同一内容的脚本不回报失败（复审 N1）。
    #[test]
    fn not_ready_skips_scripts_already_done() {
        let g = config(&[("scripts/a.sh", None), ("scripts/b.sh", None)]);
        let ex = exported(&[
            ("scripts/a.sh", "#!/bin/sh\n"),
            ("scripts/b.sh", "#!/bin/sh\nb\n"),
        ]);
        let mut st = State::default();
        st.login_script_hashes
            .insert("1001:scripts/a.sh".into(), sha256_hex(b"#!/bin/sh\n"));
        let r = FakeRunner::new();
        r.respond("systemctl is-active", Output::fail(3, ""));
        let res = run_login_scripts_with(1001, &g, ex.path(), &mut st, &r, Duration::ZERO);
        assert_eq!(res.len(), 1, "{res:?}");
        assert_eq!(res[0].item, "login-script:scripts/b.sh");
        // 都跑过：连 is-active 都不问
        st.login_script_hashes
            .insert("1001:scripts/b.sh".into(), sha256_hex(b"#!/bin/sh\nb\n"));
        let r = FakeRunner::new();
        assert!(run_login_scripts(1001, &g, ex.path(), &mut st, &r).is_empty());
        assert!(r.calls().is_empty());
    }

    /// 跑的过程中导出的文件被下一轮应用换了内容：不记哈希，下次登录照新内容再跑（复审 M1）。
    #[test]
    fn export_replaced_during_run_is_not_recorded() {
        struct Swap(std::path::PathBuf);
        impl Runner for Swap {
            fn run(&self, cmd: &Cmd) -> Result<crate::runner::Output> {
                if cmd.program == "systemd-run" {
                    fs::write(&self.0, "#!/bin/sh\necho new\n").unwrap();
                }
                Ok(Output::ok(""))
            }
        }
        let g = config(&[("scripts/a.sh", None)]);
        let ex = exported(&[("scripts/a.sh", "#!/bin/sh\necho old\n")]);
        let file = ex.path().join(exported_name("scripts/a.sh"));
        let mut st = State::default();
        let res = run_login_scripts(1001, &g, ex.path(), &mut st, &Swap(file));
        assert!(res[0].ok);
        assert!(st.login_script_hashes.is_empty());
    }

    /// 按 uid 合并（几个人的批次可同时跑）；清单里删掉的脚本的哈希与结果都去掉（复审 M2、M9）。
    #[test]
    fn hashes_merge_per_uid_and_prune() {
        let g = config(&[("scripts/a.sh", None)]);
        let ex = exported(&[("scripts/a.sh", "#!/bin/sh\n")]);
        let mut all = BTreeMap::from([
            ("1002:scripts/a.sh".to_string(), "x".to_string()),
            ("1001:scripts/gone.sh".to_string(), "y".to_string()),
        ]);
        let b = run_batch(
            1001,
            &g,
            ex.path(),
            hashes_of(&all, 1001),
            &FakeRunner::new(),
        );
        assert_eq!(b.uid, 1001);
        assert!(b.hashes.keys().all(|k| k.starts_with("1001:")));
        merge_hashes(&mut all, &b);
        assert_eq!(
            all.keys().collect::<Vec<_>>(),
            vec![
                "1001:scripts/a.sh",
                "1001:scripts/gone.sh",
                "1002:scripts/a.sh"
            ],
            "1001's key is replaced with this round's, 1002 is untouched; dropping removed scripts is prune's job"
        );
        all.insert("1003:scripts/gone.sh".into(), "z".into());
        prune_hashes(&mut all, &g);
        assert_eq!(
            all.keys().collect::<Vec<_>>(),
            vec!["1001:scripts/a.sh", "1002:scripts/a.sh"]
        );
        let results = [
            failed("scripts/a.sh", "x".into()),
            failed("scripts/gone.sh", "y".into()),
        ];
        let kept = current_results(results.iter(), &g);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].item, "login-script:scripts/a.sh");
    }

    /// 天数是上次确认到现在：心跳第 0 天给到第 7 天的有效期，第 8 天登录是 8 天，不是 1 天（复审 M3）。
    #[test]
    fn stale_days_count_from_last_confirmation() {
        let now = Utc::now();
        let st = State {
            accepted_at: Some(now - chrono::TimeDelta::days(20)),
            fresh_until: Some(now - chrono::TimeDelta::days(1)),
            last_fetch_ok: Some(now - chrono::TimeDelta::days(8)),
            ..State::default()
        };
        assert_eq!(stale_notice(&st, now), Some(StaleNotice::Days(8)));
        // 没有心跳证据：服务端一直说「没有新版本」不算确认，从接受这一版算
        let st = State {
            accepted_at: Some(now - chrono::TimeDelta::days(9)),
            last_fetch_ok: Some(now),
            ..State::default()
        };
        assert_eq!(stale_notice(&st, now), Some(StaleNotice::Days(9)));
    }
}
