//! Flatpak 软件清单（Ruling 13）：后台任务，不进应用——装一个大应用要十几分钟，不能挡住锁定与登录时的拉取。
//!
//! - [`FlatpakJob`]：按本机配置的 `apps.flatpak` 对账。装清单里有、系统里没有的（`flathub`，每个限时
//!   [`INSTALL_TIMEOUT`]）；卸「我们装过（[`FlatpakState::managed`]）、清单里已没有、仍装着」的。IT 在本机另装的
//!   （不在 `managed` 里）永远不动，哪怕它也在清单里、之后又从清单里删掉。`learning` 与 `full` 都装；旧形状的
//!   浏览器模式不装（不显示 Flatpak），但照清单卸。每天的 `flatpak update` 是 [`FlatpakUpdateJob`]。
//! - 新包被接受（`JobCtx::current` 变了）时立即对账一次；`managed` 变了就叫主循环再应用一次，`desktop` 步骤
//!   把清单里已装好的受管应用加进 Dock（[`dock_apps`]）。
//! - 状态存 `<var_dir>/flatpak-state.json`（0600），由两个任务在 [`FLATPAK_LOCK`] 下读改写；`desktop` 步骤只读，
//!   读不出当作空。**先记意图再装**（复审 I1）：`flatpak install` 之前把 id 记进 `pending` 并落盘，装完再移进
//!   `managed`；装到一半超时、装好了却没记上、agent 被杀在中间，下一轮看到它已装就收进 `managed`——不会变成
//!   「本机另装的」孤儿。`pending` 只收系统里还没有的 id，所以永远不会把 IT 装的认成我们的。
//! - 状态文件内容坏了（解析失败）：改名成 `flatpak-state.json.bad`，回报一次 `flatpak:state`，当作空接着装；
//!   之前我们装的就此变成「不是我们装的」，只会少卸、不会误卸。读都读不了（I/O 错误）时这一轮什么都不做。
//! - 一轮里卸过应用就跑一次 `flatpak uninstall --unused`，清掉没人用的运行时（`flatpak:runtimes`，失败只记在这一项）。
//! - 回报项 `flatpak:<id>`（每一轮替换掉旧的，清单里删掉的那一项不会一直挂着）、`flatpak:state`、`flatpak:runtimes`
//!   与 `flatpak-update`。
//!
//! 已知缺口（Ruling，T13）：旧的浏览器模式下学生自写一个 `flatpak run` 的 `.desktop` 仍能打开已装的 Flatpak
//! （`learning` 本来就放行配置里的 Flatpak）。

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use mastersos_bundle::{checks, ItemResult};
use serde::{Deserialize, Serialize};

use super::{failed, ok, var_dir, SysPaths};
use crate::jobs::{CurrentGroup, Job, JobCtx};
use crate::runner::{run_ok, Cmd, Runner};
use crate::safefs;

/// `<var_dir>` 里本任务的状态文件；内容坏了时改名成它加 `.bad`。
pub const STATE_FILE: &str = "flatpak-state.json";
pub const BAD_STATE_FILE: &str = "flatpak-state.json.bad";
/// 镜像里的 Flathub 仓库描述（含签名公钥；到期与更新见 `image/docs/keys.md`）。
pub const REPO_FILE: &str = "/usr/share/mastersos/flathub.flatpakrepo";
pub const REMOTE: &str = "flathub";
/// 每个应用的安装限时。
pub const INSTALL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// `flatpak update` 的限时（可能一次更新好几个运行时）。
pub const UPDATE_TIMEOUT: Duration = Duration::from_secs(60 * 60);
pub const EVERY: Duration = Duration::from_secs(3600);
/// 每日更新任务多久看一次是否到期（到期 = 距上次成功满 [`UPDATE_INTERVAL`]）。
pub const UPDATE_CHECK_EVERY: Duration = Duration::from_secs(3600);
pub const UPDATE_INTERVAL: chrono::TimeDelta = chrono::TimeDelta::hours(24);
/// agent 启动后第一次看更新之前随机等 0 到这么久：一个教室的机器 8 点同时开机，不一起去 Flathub 下载。
pub const UPDATE_JITTER_SECS: u64 = 30 * 60;
/// 回报项前缀。
pub const ITEM_PREFIX: &str = "flatpak:";
pub const STATE_ITEM: &str = "flatpak:state";
pub const RUNTIMES_ITEM: &str = "flatpak:runtimes";
pub const UPDATE_ITEM: &str = "flatpak-update";

/// 对账与每日更新不同时动系统安装、不同时改状态文件。
static FLATPAK_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlatpakState {
    /// 按清单装上的应用 id（我们装的才会被卸）。
    #[serde(default)]
    pub managed: BTreeSet<String>,
    /// 已决定安装、`flatpak install` 之前先记下的 id（装完移进 `managed`；没装成、仍在清单里的下一轮再装）。
    #[serde(default)]
    pub pending: BTreeSet<String>,
    /// 上一次 `flatpak update` 成功的时刻（[`FlatpakUpdateJob`] 写）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_update: Option<chrono::DateTime<chrono::Utc>>,
}

/// (要装, 要卸)。要装 = `wanted` 里有、`installed` 里没有的（按清单顺序、去重）；要卸 = `managed` 里有、`wanted`
/// 里没有、仍在 `installed` 里的。不是我们装的不动。
pub fn plan(
    wanted: &[String],
    installed: &BTreeSet<String>,
    managed: &BTreeSet<String>,
) -> (Vec<String>, Vec<String>) {
    let mut install: Vec<String> = Vec::new();
    for id in wanted {
        if !installed.contains(id) && !install.contains(id) {
            install.push(id.clone());
        }
    }
    let uninstall = managed
        .iter()
        .filter(|id| !wanted.contains(id) && installed.contains(*id))
        .cloned()
        .collect();
    (install, uninstall)
}

fn item(id: &str) -> String {
    format!("{ITEM_PREFIX}{id}")
}

/// 读状态文件的结果。
enum Loaded {
    Ok(FlatpakState),
    /// 内容解析不了：已改名成 `.bad`（或改名失败），当作空；说明交给回报。
    Corrupt(String),
}

/// 不存在为默认值；读不了（I/O）报错；内容坏了改名成 `.bad`、当作空（[`Loaded::Corrupt`]）。
fn load_or_quarantine(paths: &SysPaths) -> Result<Loaded> {
    let dir = var_dir(paths)?;
    let Some(b) =
        safefs::read_at(&dir, STATE_FILE).with_context(|| format!("read {STATE_FILE}"))?
    else {
        return Ok(Loaded::Ok(FlatpakState::default()));
    };
    match serde_json::from_slice(&b) {
        Ok(s) => Ok(Loaded::Ok(s)),
        Err(e) => {
            let moved = safefs::rename_at(&dir, STATE_FILE, BAD_STATE_FILE);
            let why = match moved {
                Ok(()) => format!(
                    "failed to parse {STATE_FILE} ({e}); renamed it to {BAD_STATE_FILE} and treating it as empty: apps installed from the list before no longer count as ours and will not be removed"
                ),
                Err(m) => format!("failed to parse {STATE_FILE} ({e}); renaming failed ({m:#}); treating it as empty"),
            };
            log::warn!("{why}");
            Ok(Loaded::Corrupt(why))
        }
    }
}

/// 不存在为默认值；读不了、解析不了报错。
pub fn load_state(paths: &SysPaths) -> Result<FlatpakState> {
    match safefs::read_at(&var_dir(paths)?, STATE_FILE)
        .with_context(|| format!("read {STATE_FILE}"))?
    {
        None => Ok(FlatpakState::default()),
        Some(b) => {
            serde_json::from_slice(&b).with_context(|| format!("failed to parse {STATE_FILE}"))
        }
    }
}

// 测试用：Some(n) 时只让接下来 n 次写状态成功、之后都失败；按线程设。
#[cfg(test)]
thread_local! {
    pub(crate) static TEST_SAVE_BUDGET: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

fn save_state(paths: &SysPaths, s: &FlatpakState) -> Result<()> {
    #[cfg(test)]
    {
        if let Some(n) = TEST_SAVE_BUDGET.with(|c| c.get()) {
            if n == 0 {
                anyhow::bail!("write {STATE_FILE}: failure injected by a test");
            }
            TEST_SAVE_BUDGET.with(|c| c.set(Some(n - 1)));
        }
    }
    safefs::write_at(
        &var_dir(paths)?,
        STATE_FILE,
        &serde_json::to_vec_pretty(s)?,
        0o600,
    )
    .with_context(|| format!("write {STATE_FILE}"))?;
    Ok(())
}

/// `desktop` 步骤用：清单里的、已按清单装好的应用 id（按清单顺序）。状态文件不存在、读不出都当作空，不报错，
/// 也不建目录。
pub fn dock_apps(paths: &SysPaths, list: &[String]) -> Vec<String> {
    let managed = safefs::open_abs_dir(&paths.var_dir, false)
        .and_then(|d| safefs::read_at(&d, STATE_FILE))
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice::<FlatpakState>(&b).ok())
        .map(|s| s.managed)
        .unwrap_or_default();
    let mut out: Vec<String> = Vec::new();
    for id in list {
        if managed.contains(id) && !out.contains(id) {
            out.push(id.clone());
        }
    }
    out
}

/// `flatpak list --columns=application` 的输出：每行一个 id（不合格的行——比如表头——跳过）。
fn parse_installed(stdout: &str) -> BTreeSet<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| checks::flatpak_id(l).is_ok())
        .map(String::from)
        .collect()
}

/// 对账一次。返回逐项回报与 `managed` 是否变了（变了要再应用一次，Dock 跟着变）。`still_current()` 在每次安装之前看：
/// 返回 false（这一轮开始之后来了新包）就提前结束这一轮，由唤醒立即按新清单再跑（复审 M5）。
pub fn reconcile(
    runner: &dyn Runner,
    paths: &SysPaths,
    cur: Option<&CurrentGroup>,
    still_current: &dyn Fn() -> bool,
) -> (Vec<ItemResult>, bool) {
    let Some(cur) = cur else {
        // 还没有包：不知道清单，什么都不做
        return (vec![], false);
    };
    let _g = FLATPAK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Whether this mode installs the Config's Flatpaks (config profiles design §4.4)
    let install_mode = super::desktop::profile(&cur.config).flatpaks;
    let mut out = Vec::new();
    let mut wanted: Vec<String> = Vec::new();
    for id in &cur.config.apps.flatpak {
        match checks::flatpak_id(id) {
            Err(e) => out.push(failed(&item(id), e)),
            Ok(()) if !wanted.contains(id) => wanted.push(id.clone()),
            Ok(()) => {}
        }
    }
    let mut st = match load_or_quarantine(paths) {
        Ok(Loaded::Ok(s)) => s,
        Ok(Loaded::Corrupt(why)) => {
            out.push(failed(STATE_ITEM, why));
            FlatpakState::default()
        }
        Err(e) => {
            // 读都读不了：不知道哪些是我们装的，这一轮什么都不做
            let why = format!("{e:#}");
            out.extend(wanted.iter().map(|id| failed(&item(id), why.clone())));
            return (out, false);
        }
    };
    let before = st.clone();
    // 远程源只为安装要（旧的浏览器模式不装）
    let remote = if install_mode && !wanted.is_empty() {
        run_ok(
            runner,
            Cmd::new(
                "flatpak",
                &[
                    "remote-add",
                    "--system",
                    "--if-not-exists",
                    REMOTE,
                    REPO_FILE,
                ],
            ),
        )
        .map(|_| ())
        .map_err(|e| format!("failed to add the Flathub remote: {e:#}"))
    } else {
        Ok(())
    };
    let installed = match run_ok(
        runner,
        Cmd::new(
            "flatpak",
            &["list", "--system", "--app", "--columns=application"],
        ),
    ) {
        Ok(s) => parse_installed(&s),
        Err(e) => {
            let why = format!("failed to list installed Flatpaks: {e:#}");
            let all: BTreeSet<&String> = wanted.iter().chain(st.managed.iter()).collect();
            out.extend(all.into_iter().map(|id| failed(&item(id), why.clone())));
            // 坏状态改了名：这里把空状态写下（之后不再报 flatpak:state）
            if st != before || out.iter().any(|r| r.item == STATE_ITEM) {
                let _ = save_state(paths, &st);
            }
            return (out, false);
        }
    };
    // 上一轮记下了要装、已经装上的：收进 managed（装到一半超时、装完没记上、被杀在中间，复审 I1）
    let landed: Vec<String> = st
        .pending
        .iter()
        .filter(|id| installed.contains(*id))
        .cloned()
        .collect();
    for id in landed {
        st.pending.remove(&id);
        st.managed.insert(id);
    }
    // 没装上的：还在清单里留着（下面再装），清单里没了就丢掉
    st.pending.retain(|id| wanted.contains(id));
    // 被人手动卸掉、清单里也没了的不再算我们的；清单里还有的留着（下面会重装）。一次 list 是空的（读到一半的仓库）
    // 不当真：那样会把 managed 一下清光（复审 M2）
    if !installed.is_empty() {
        st.managed
            .retain(|id| installed.contains(id) || wanted.contains(id));
    }
    let (install, uninstall) = plan(&wanted, &installed, &st.managed);
    let mut superseded = false;
    for id in &wanted {
        let it = item(id);
        if !install_mode {
            out.push(ItemResult {
                item: it,
                ok: true,
                detail: Some("browser mode: not installing".into()),
            });
            continue;
        }
        if !install.contains(id) {
            out.push(if st.managed.contains(id) {
                ok(&it)
            } else {
                ItemResult {
                    item: it,
                    ok: true,
                    detail: Some("already installed on this computer (not from the list; not removed when dropped from the list, not added to the Dock)".into()),
                }
            });
            continue;
        }
        if let Err(why) = &remote {
            out.push(failed(&it, why.clone()));
            continue;
        }
        if superseded || !still_current() {
            // 来了新包：剩下的不装、这一轮的卸载也留给下一轮（马上就跑）
            superseded = true;
            continue;
        }
        // 先记意图：落不了盘就不装（装上了却记不下来，就成了分不清是谁装的孤儿）
        st.pending.insert(id.clone());
        if let Err(e) = save_state(paths, &st) {
            st.pending.remove(id);
            out.push(failed(
                &it,
                format!("not installed: failed to record the app to install: {e:#}"),
            ));
            continue;
        }
        let cmd = Cmd::new(
            "flatpak",
            &["install", "--system", "--noninteractive", "-y", REMOTE, id],
        )
        .timeout(INSTALL_TIMEOUT);
        match run_ok(runner, cmd) {
            Ok(_) => {
                st.pending.remove(id);
                st.managed.insert(id.clone());
                out.push(match save_state(paths, &st) {
                    Ok(()) => ok(&it),
                    // 盘上 pending 里还有它：下一轮看到已装就收进 managed
                    Err(e) => failed(
                        &it,
                        format!("installed, but recording failed (will record next round): {e:#}"),
                    ),
                });
            }
            // pending 里留着：其实装上了（超时在最后一步）下一轮收下；没装上下一轮再装
            Err(e) => out.push(failed(&it, format!("install failed: {e:#}"))),
        }
    }
    let mut removed_any = false;
    if !superseded {
        for id in &uninstall {
            let it = item(id);
            let cmd = Cmd::new(
                "flatpak",
                &["uninstall", "--system", "--noninteractive", "-y", id],
            )
            .timeout(INSTALL_TIMEOUT);
            match run_ok(runner, cmd) {
                Ok(_) => {
                    removed_any = true;
                    st.managed.remove(id);
                    out.push(match save_state(paths, &st) {
                        Ok(()) => ItemResult {
                            item: it,
                            ok: true,
                            detail: Some("removed from the list; uninstalled".into()),
                        },
                        // 盘上还记着它：下一轮看到没装了、清单里也没有，就丢掉
                        Err(e) => failed(&it, format!("uninstalled, but recording failed: {e:#}")),
                    });
                }
                Err(e) => out.push(failed(&it, format!("uninstall failed: {e:#}"))),
            }
        }
    }
    if removed_any {
        let cmd = Cmd::new(
            "flatpak",
            &[
                "uninstall",
                "--system",
                "--noninteractive",
                "-y",
                "--unused",
            ],
        )
        .timeout(INSTALL_TIMEOUT);
        out.push(match run_ok(runner, cmd) {
            Ok(_) => ItemResult {
                item: RUNTIMES_ITEM.into(),
                ok: true,
                detail: Some("removed runtimes no app uses any more".into()),
            },
            Err(e) => failed(
                RUNTIMES_ITEM,
                format!("failed to remove unused runtimes: {e:#}"),
            ),
        });
    }
    let changed = st.managed != before.managed;
    if st != before || out.iter().any(|r| r.item == STATE_ITEM) {
        if let Err(e) = save_state(paths, &st) {
            log::warn!("{e:#}");
        }
    }
    (out, changed)
}

/// 每日更新这一轮要不要跑：距上次成功满 [`UPDATE_INTERVAL`]（从没成功过也算到期）。
pub fn update_due(
    last: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    last.is_none_or(|t| now - t >= UPDATE_INTERVAL || t > now)
}

/// 到期就 `flatpak update` 一次，成功后记下时刻。对账正在跑（拿着锁）时这一轮跳过、不等它。没到期、跳过时返回 None
/// （回报里保留上一次的结果）。
pub fn update(
    runner: &dyn Runner,
    paths: &SysPaths,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<ItemResult> {
    let _g = match FLATPAK_LOCK.try_lock() {
        Ok(g) => g,
        Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => return None,
    };
    let mut st = match load_state(paths) {
        Ok(s) => s,
        // 坏了的状态由对账处理（改名、当作空），这里不写它
        Err(e) => return Some(failed(UPDATE_ITEM, format!("{e:#}"))),
    };
    if !update_due(st.last_update, now) {
        return None;
    }
    let cmd = Cmd::new("flatpak", &["update", "--system", "--noninteractive", "-y"])
        .timeout(UPDATE_TIMEOUT);
    Some(match run_ok(runner, cmd) {
        Ok(_) => {
            st.last_update = Some(now);
            match save_state(paths, &st) {
                Ok(()) => ok(UPDATE_ITEM),
                Err(e) => ItemResult {
                    item: UPDATE_ITEM.into(),
                    ok: true,
                    detail: Some(format!(
                        "updated, but recording the time failed (will update again next hour): {e:#}"
                    )),
                },
            }
        }
        Err(e) => failed(UPDATE_ITEM, format!("{e:#}")),
    })
}

pub struct FlatpakJob {
    runner: Arc<dyn Runner>,
}

impl FlatpakJob {
    pub fn new(runner: Arc<dyn Runner>) -> Self {
        FlatpakJob { runner }
    }
}

impl Job for FlatpakJob {
    fn name(&self) -> &'static str {
        "flatpak"
    }

    fn every(&self) -> Duration {
        EVERY
    }

    fn run<'a>(
        &'a self,
        cx: &'a JobCtx,
    ) -> Pin<Box<dyn Future<Output = Vec<ItemResult>> + Send + 'a>> {
        Box::pin(async move {
            let cur = cx.current.borrow().clone();
            let rx = cx.current.clone();
            let (runner, paths) = (self.runner.clone(), cx.paths.clone());
            // 命令是同步的、可能跑十几分钟：放到阻塞线程上，不占运行时
            match tokio::task::spawn_blocking(move || {
                let still = || *rx.borrow() == cur;
                reconcile(runner.as_ref(), &paths, cur.as_deref(), &still)
            })
            .await
            {
                Ok((out, changed)) => {
                    if changed {
                        cx.reapply.notify_one();
                    }
                    out
                }
                Err(e) => {
                    log::error!("Flatpak reconcile crashed: {e}");
                    vec![]
                }
            }
        })
    }

    fn wake_on_new_bundle(&self) -> bool {
        true
    }

    fn replaces_items(&self) -> Option<&'static str> {
        Some(ITEM_PREFIX)
    }
}

/// 每日更新：每小时看一次是否到期（上次成功记在状态文件里，重启不会让它每次开机都跑，复审 M3）；agent 启动后的
/// 第一次先随机等 0–30 分钟。
pub struct FlatpakUpdateJob {
    runner: Arc<dyn Runner>,
    jitter: Duration,
    first: AtomicBool,
}

impl FlatpakUpdateJob {
    pub fn new(runner: Arc<dyn Runner>) -> Self {
        Self::with_jitter(runner, random_jitter())
    }

    pub fn with_jitter(runner: Arc<dyn Runner>, jitter: Duration) -> Self {
        FlatpakUpdateJob {
            runner,
            jitter,
            first: AtomicBool::new(true),
        }
    }
}

fn random_jitter() -> Duration {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 8];
    let n = match ring::rand::SystemRandom::new().fill(&mut b) {
        Ok(()) => u64::from_le_bytes(b),
        Err(_) => 0,
    };
    Duration::from_secs(n % (UPDATE_JITTER_SECS + 1))
}

impl Job for FlatpakUpdateJob {
    fn name(&self) -> &'static str {
        "flatpak-update"
    }

    fn every(&self) -> Duration {
        UPDATE_CHECK_EVERY
    }

    fn run<'a>(
        &'a self,
        cx: &'a JobCtx,
    ) -> Pin<Box<dyn Future<Output = Vec<ItemResult>> + Send + 'a>> {
        Box::pin(async move {
            if self.first.swap(false, Ordering::SeqCst) {
                tokio::time::sleep(self.jitter).await;
            }
            let (runner, paths) = (self.runner.clone(), cx.paths.clone());
            match tokio::task::spawn_blocking(move || {
                update(runner.as_ref(), &paths, chrono::Utc::now())
            })
            .await
            {
                Ok(r) => r.into_iter().collect(),
                Err(e) => vec![failed(UPDATE_ITEM, format!("crashed: {e}"))],
            }
        })
    }
}

#[cfg(test)]
mod tests;
