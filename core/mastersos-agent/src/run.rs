//! The main loop: sync settings (`GET /v1/bundle?after=N&wait=0`) → verify → store → hand to the
//! apply task → report; failures back off, a bad bundle is remembered and not taken again.
//!
//! No long poll and no fallback polling (MQTT push plan, spec §6.1–6.2). Settings are synced at
//! startup (retried with the backoff until one sync succeeds), on a doorbell for a version above
//! `after` or a (re)connect of the MQTT task ([`crate::push`], started behind the same gate as the
//! first report), on a wake (SIGUSR1) and when someone logs in. Otherwise the loop waits: for
//! doorbells, wakes, the login queue, the status report timer, the heartbeat timer and shutdown.
//!
//! 应用在自己的任务里跑（[`crate::apply_worker`]，Ruling 17）：接受新包、启动、被叫醒时上一轮有
//! 失败项，都只是交一份应用请求；结果回来时合并进 `state.json`（它只有主循环一个写者）并回报。
//! 重试与定期重应用由应用任务自己安排。
//!
//! 启动时 `state_dir` 里没有状态（新装、恢复出厂）就先从种子分区导入种子与缓存的包
//! （[`crate::seedpart`]，Ruling 10、16）：缓存包与刚拉到的包一样走 `take_new`，用种子的
//! `trust` 与 `min_version` 验，验不过就丢掉、照常拉取。接受新包后把它写回种子分区的缓存。
//!
//! Signed heartbeat (spec §4.2): its own timer checks one every `heartbeat_every` (one hour);
//! a settings sync ("nothing new" or a new bundle accepted) also checks one when the last check
//! is at least `heartbeat_every` old by the wall clock. It is verified with the keys the machine
//! trusts now:
//! - 说的就是本机这一版（版本与摘要都对）→ `fresh_until` 往后推到它的 `not_after`；
//! - 说有更高的版本 → 立即再拉一次（`wait=0`）：拉到就照常接受，仍是「没有新版本」才记 `newer_withheld`；
//! - 其余（更旧、摘要不符、验签失败、`issued_at` 晚于本机时间超过 1 天）一律不采信，也不回报
//!   错误项。本机时钟偏慢时宁可误报过期。
//!
//! `fresh_until` 只替本机当前这一版说话：接受了别的版本就清掉。`once` 也取一次心跳（不看间隔）。
//!
//! 拉取令牌（计划 4b Task 2，Ruling 20）：启动时用 [`token::effective`]（state 里的 > 种子分区里的 >
//! 种子的）。机器侧响应说令牌已退役（`X-Mastersos-Fetch-Token: stale`）时，每轮拉取或回报之后按
//! [`token::renew_due`]（最多每小时一次）凭托管凭据换领；换到就写进 state 与种子分区再换上，回报
//! `fetch-token`。当前令牌被 401 而别的来源有不同的令牌（例如服务端回退了轮换）时换用它。
//!
//! Inbox (spec §6.3, [`crate::inbox`]): synced at startup, on an inbox doorbell above
//! `inbox_after`, and on a (re)connect of the MQTT task; a failed sync is retried with the backoff
//! until it succeeds. `inbox_after` lives in `state.json`. Remote factory reset comes only from the
//! inbox now: the bundle's `[[device]].reset` is ignored. Once a reset has started (`resetting`)
//! no more apply requests and no more inbox syncs. The first start on a fresh state after an
//! inbox reset (the seed partition names its `seq`) reports that command `done`.
//!
//! 登录（计划 4b Task 18，Ruling 9、10，[`crate::login_queue`]）：被叫醒（以及启动）时先取走登录队列，同步一次设置。
//! 拉取回来（超过 [`LOGIN_FETCH_WAIT`] 还没回来就当「没有新版本」）就给每个人发过期提示（设置可能过期时），并在
//! 阻塞线程里对每个 uid 跑 `login` 脚本——只有这次拉取接受了新包时才先等它的应用跑完（新脚本要先导出）；上一轮有失败项
//! 而被叫醒触发的重应用不等（复审 I1：打印机关着之类的失败在学校是常态，登录不能排在整轮重应用之后）。每个 uid 一个
//! 阻塞任务，同一个人同一时刻只有一个，不同的人互不等。脚本的哈希按 uid 合并回主循环（state.json 仍只有主循环一个写者）。
//! 已知：拉取满 [`LOGIN_FETCH_WAIT`] 后才下载完的新包，这次登录跑的是旧脚本，新脚本下次登录再跑。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, TimeDelta, Utc};
use mastersos_bundle::push::Doorbell;
use mastersos_bundle::{
    content_digest, select, trust_fingerprint, verify_heartbeat, Bundle, BundleError, DeviceIdent,
    GroupSource, ItemResult, Manifest, Seed, DEFAULT_GROUP,
};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, Notify};
use tokio::time::{sleep_until, Instant};
use tokio_util::sync::CancellationToken;

use crate::apply::{hex, sha256_hex};
use crate::apply::{Applier, ApplyContext, Phase};
use crate::apply_worker::{self, ApplyHandle, ApplyOutcome, ApplyRequest};
use crate::config::{AgentConfig, FALLBACK_SECS};
use crate::fetch::{DeviceCred, FetchOutcome, Fetcher};
use crate::inbox;
use crate::jobs::{self, CurrentGroup, Job, JobCtx, SideResults};
use crate::login_queue::{self, Batch};
use crate::push::{self, PushEvent, PushTiming};
use crate::report::{self, Freshness, Machine, Placement};
use crate::runner::{Cmd, RealRunner, Runner};
use crate::safefs;
use crate::seedpart::{self, Imported};
use crate::state::{self, State};
use crate::system::SysPaths;
use crate::token;

/// 只为更新 `last_fetch_ok` 而写 state.json 的最短间隔（过期按天算，不必每分钟写盘）。
const FETCH_OK_SAVE_EVERY: chrono::TimeDelta = chrono::TimeDelta::hours(1);
/// 心跳的 `issued_at` 最多比本机时间晚这么多（再晚就不采信）。
const HEARTBEAT_FUTURE_SLACK: TimeDelta = TimeDelta::days(1);
/// `apply-local` 等网络加拉取最多这么久（Ruling 15；单元的 TimeoutStartSec=60 是硬上限）。
const LOCAL_NET_BUDGET: Duration = Duration::from_secs(45);
/// `apply-local` 等网络：`nm-online -t` 的秒数。
const LOCAL_NM_ONLINE_SECS: &str = "30";
/// `apply-local` 单次拉取的上限。
const LOCAL_FETCH_TIMEOUT: Duration = Duration::from_secs(15);
/// `apply-local` 连不上服务端（路由还没到）时两次试拉之间停多久。
const LOCAL_RETRY_PAUSE: Duration = Duration::from_secs(2);

/// 错误链里有连接阶段的 reqwest 错误（连接被拒、网络不可达、连接超时）：值得过一会儿再试。
fn is_connect_error(e: &anyhow::Error) -> bool {
    e.chain()
        .filter_map(|c| c.downcast_ref::<reqwest::Error>())
        .any(|r| r.is_connect())
}
/// 第一份回报最多等 `gates_first_report()` 的后台任务（恢复密钥托管）这么久：托管通常几秒内
/// 完成；服务端连不上时托管请求自己 30 秒超时。等不到也照常回报，不让回报一直缺席。
const FIRST_REPORT_GATE: Duration = Duration::from_secs(90);
/// 退出时等正在跑的应用交回结果最多这么久（systemd 默认 TimeoutStopSec=90s）。
const SHUTDOWN_APPLY_GRACE: Duration = Duration::from_secs(60);
/// The settings sync after a login wake-up: not back after this long counts as "nothing new", and
/// the login scripts run without waiting for it.
const LOGIN_FETCH_WAIT: Duration = Duration::from_secs(3);

/// Runs until `shutdown`. SIGUSR1 syncs settings once (and re-applies at once when the last round
/// had failures).
pub async fn run(
    cfg: AgentConfig,
    applier: Arc<dyn Applier>,
    jobs: Vec<Arc<dyn Job>>,
    shutdown: CancellationToken,
) -> Result<()> {
    let wake = Arc::new(Notify::new());
    let mut usr1 = signal(SignalKind::user_defined1()).context("注册 SIGUSR1")?;
    let w = wake.clone();
    let forward = tokio::spawn(async move {
        while usr1.recv().await.is_some() {
            w.notify_one();
        }
    });
    let r = run_with_wake(cfg, applier, jobs, shutdown, wake).await;
    forward.abort();
    r
}

/// Like `run`, but the sync is triggered by `wake`: tests need not send a real signal.
pub async fn run_with_wake(
    cfg: AgentConfig,
    applier: Arc<dyn Applier>,
    jobs: Vec<Arc<dyn Job>>,
    shutdown: CancellationToken,
    wake: Arc<Notify>,
) -> Result<()> {
    run_with_login_runner(cfg, applier, jobs, shutdown, wake, Arc::new(RealRunner)).await
}

/// Like `run_with_wake`; the login hooks' commands (`systemctl is-active`, `systemd-run`) and the
/// factory reset's go through `login_runner` (tests: a `FakeRunner`). The login queue and the
/// export directory are under `cfg.root`.
pub async fn run_with_login_runner(
    cfg: AgentConfig,
    applier: Arc<dyn Applier>,
    jobs: Vec<Arc<dyn Job>>,
    shutdown: CancellationToken,
    wake: Arc<Notify>,
    login_runner: Arc<dyn Runner>,
) -> Result<()> {
    run_resident(
        cfg,
        applier,
        jobs,
        shutdown,
        wake,
        login_runner,
        PushSource::Spawn,
    )
    .await
}

/// Like `run_with_wake`, but no MQTT task is started: the main loop takes its push events from
/// `events` (tests ring the doorbells). The login hooks' and the factory reset's commands go
/// through `runner`.
pub async fn run_with_push_events(
    cfg: AgentConfig,
    applier: Arc<dyn Applier>,
    jobs: Vec<Arc<dyn Job>>,
    shutdown: CancellationToken,
    wake: Arc<Notify>,
    events: mpsc::Receiver<PushEvent>,
    runner: Arc<dyn Runner>,
) -> Result<()> {
    run_resident(
        cfg,
        applier,
        jobs,
        shutdown,
        wake,
        runner,
        PushSource::Events(events),
    )
    .await
}

/// Where the main loop's push events come from.
enum PushSource {
    /// The MQTT task ([`push::spawn`]), started behind the first-report gate.
    Spawn,
    /// A channel the caller feeds.
    Events(mpsc::Receiver<PushEvent>),
}

async fn run_resident(
    cfg: AgentConfig,
    applier: Arc<dyn Applier>,
    jobs: Vec<Arc<dyn Job>>,
    shutdown: CancellationToken,
    wake: Arc<Notify>,
    login_runner: Arc<dyn Runner>,
    push_source: PushSource,
) -> Result<()> {
    // 第一份回报压到托管任务的第一轮之后（包括 start 里接受缓存包时的那一份）。
    let mut agent = Agent::start(cfg, applier, Mode::Resident, true).await?;
    agent.login.runner = login_runner.clone();
    agent.runner = login_runner;
    // Startup syncs both, whether or not the MQTT task ever connects (spec §6.2).
    agent.sync_settings = true;
    agent.sync_inbox = true;
    match push_source {
        PushSource::Events(rx) => agent.push_rx = Some(rx),
        PushSource::Spawn => agent.plan_push(&shutdown),
    }
    // agent 没在跑时登录的人（记号留在队列里）：照样拉取之后跑
    agent.take_logins();
    // 后台任务的第一轮就看得到本地包选中的分组（Flatpak 对账）
    agent.publish_current();
    let cx = Arc::new(JobCtx {
        fetcher: agent.fetcher.clone(),
        ident: agent.machine.ident.clone(),
        paths: sys_paths(&agent.cfg),
        runner: Arc::new(RealRunner),
        identity: agent.identity.clone(),
        current: agent.current.subscribe(),
        reapply: agent.reapply.clone(),
        fetch_error: agent.fetch_error.subscribe(),
    });
    let spawned = jobs::spawn_all(
        jobs,
        cx,
        agent.side.clone(),
        shutdown.clone(),
        agent.job_wake.clone(),
    );
    agent.side_changed = Some(spawned.changed.clone());
    // 导入的缓存包被接受时已经交过请求了。应用与拉取都不等托管，只有回报等。
    if !agent.apply_pending() {
        agent.request_apply();
    }
    agent.save();
    if spawned.first_rounds.is_empty() {
        agent.reports_held = false;
        agent.start_push();
    } else {
        let open = Arc::new(Notify::new());
        let (o, rounds) = (open.clone(), spawned.first_rounds);
        tokio::spawn(async move {
            let all = async {
                for rx in rounds {
                    let _ = rx.await;
                }
            };
            if tokio::time::timeout(FIRST_REPORT_GATE, all).await.is_err() {
                log::warn!(
                    "后台任务 {} 秒内没跑完第一轮，先回报",
                    FIRST_REPORT_GATE.as_secs()
                );
            }
            o.notify_one();
        });
        agent.report_gate = Some(open);
    }
    let _ = agent.report().await;
    while agent.cycle(&shutdown, &wake).await {}
    agent.finish().await;
    for t in spawned.handles {
        let _ = t.await;
    }
    if let Some(t) = agent.push_task.take() {
        // The task ends on `shutdown` (or now that its receiver is gone).
        drop(agent.push_rx.take());
        let _ = t.await;
    }
    Ok(())
}

/// The system paths under `cfg.root` (production: `/`, so the defaults), as the login queue is: the jobs' and the
/// status files land in a test's temporary root.
fn sys_paths(cfg: &AgentConfig) -> SysPaths {
    let d = SysPaths::default();
    SysPaths {
        var_dir: cfg_root_join(&cfg.root, &d.var_dir.to_string_lossy()),
        public_dir: cfg_root_join(&cfg.root, &d.public_dir.to_string_lossy()),
        root: cfg.root.clone(),
        state_dir: cfg.state_dir.clone(),
    }
}

/// 拉取并应用一次后返回；拉取或回报失败时返回错误（本地已有的包照样应用）。
pub async fn once(cfg: AgentConfig, applier: Arc<dyn Applier>) -> Result<()> {
    let mut agent = Agent::start(cfg, applier, Mode::Resident, false).await?;
    let after = agent.after().unwrap_or(0);
    let fetched = match agent.fetcher.fetch_now(after).await {
        Ok(FetchOutcome::New { archive, version }) if Some(version) > agent.after() => {
            agent.take_new(&archive, version, false).await
        }
        Ok(_) => {
            agent.fetch_ok();
            Ok(false)
        }
        Err(e) => Err(e),
    };
    if !agent.apply_pending() {
        agent.request_apply();
    }
    agent.settle().await;
    // 一次性运行也取一次心跳（不看间隔）：手动验证时 fresh_until 与常驻时一样前进。
    if fetched.is_ok() {
        agent
            .heartbeat_unless(&CancellationToken::new(), true)
            .await;
        // 心跳说有更新的版本、重拉接受了：等这一份也应用完。
        agent.settle().await;
    }
    agent.save();
    let reported = agent.report().await;
    agent.finish().await;
    fetched.map(|_| ()).and(reported)
}

/// 开机在 GDM 之前跑（`mastersos-agent apply-local`，Ruling 15）：导入种子分区；本机还没有任何
/// 验过的包时先等网络（`nm-online -q -t 30`）并试拉一次（单次 15 秒，合计不超过 45 秒），拉到
/// 并接受了再应用；然后只调用 applier（`Phase::Boot`，`SystemApplier` 只跑快速步骤），保存
/// state。不放文件、不跑脚本、不回报——完整的应用由常驻的 `run` 做。
pub async fn apply_local(cfg: AgentConfig, applier: Arc<dyn Applier>) -> Result<()> {
    apply_local_with(cfg, applier, Arc::new(RealRunner)).await
}

/// 同 `apply_local`，等网络的命令经 `runner` 跑（测试用 `FakeRunner`）。
pub async fn apply_local_with(
    cfg: AgentConfig,
    applier: Arc<dyn Applier>,
    runner: Arc<dyn Runner>,
) -> Result<()> {
    let deadline = Instant::now() + LOCAL_NET_BUDGET;
    let mut agent = Agent::start(cfg, applier, Mode::Local, false).await?;
    if agent.bundle.is_none() {
        let wait = Cmd::new("nm-online", &["-q", "-t", LOCAL_NM_ONLINE_SECS])
            .timeout(LOCAL_NET_BUDGET - LOCAL_FETCH_TIMEOUT);
        let r = runner.clone();
        let online = match tokio::task::spawn_blocking(move || r.run(&wait)).await {
            Ok(Ok(o)) if o.code == 0 => true,
            Ok(Ok(o)) => {
                log::warn!(
                    "网络没有就绪（nm-online 退出码 {}），按种子的默认值开机",
                    o.code
                );
                false
            }
            Ok(Err(e)) => {
                log::warn!("等网络失败：{e:#}");
                false
            }
            Err(e) => {
                log::warn!("等网络失败：{e}");
                false
            }
        };
        // nm-online 说联网了，路由或地址却可能还没到（VM 实测：IPv6 先就绪、IPv4 的 DHCP 还没回来，
        // 连服务端是 Network is unreachable）：连接错误在预算之内隔一会儿再试，别的错误不重试。reqwest 把 DNS 解析
        // 失败与 TLS 握手失败也算作连接错误：证书配错的服务端会把剩下的预算（最多约 45 秒）都试完再进 GDM——有界、无害
        if online {
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    log::warn!("开机拉取超时");
                    break;
                }
                let after = agent.after().unwrap_or(0);
                match tokio::time::timeout(
                    left.min(LOCAL_FETCH_TIMEOUT),
                    agent.fetcher.fetch_now(after),
                )
                .await
                {
                    Ok(Ok(FetchOutcome::New { archive, version }))
                        if Some(version) > agent.after() =>
                    {
                        agent.fetch_result(None);
                        if let Err(e) = agent.take_new(&archive, version, false).await {
                            log::warn!("{e:#}");
                        }
                        break;
                    }
                    Ok(Ok(_)) => {
                        agent.fetch_result(None);
                        agent.fetch_ok();
                        break;
                    }
                    Ok(Err(e))
                        if is_connect_error(&e)
                            && deadline.saturating_duration_since(Instant::now())
                                > LOCAL_RETRY_PAUSE =>
                    {
                        log::info!(
                            "开机拉取连不上服务端，{} 秒后再试：{e:#}",
                            LOCAL_RETRY_PAUSE.as_secs()
                        );
                        agent.fetch_result(Some(&e));
                        tokio::time::sleep(LOCAL_RETRY_PAUSE).await;
                    }
                    Ok(Err(e)) => {
                        log::warn!("开机拉取失败：{e:#}");
                        agent.fetch_result(Some(&e));
                        break;
                    }
                    Err(_) => {
                        log::warn!("开机拉取超时");
                        agent.fetch_error.send_replace(Some(format!(
                            "fetching settings timed out after {} s",
                            LOCAL_FETCH_TIMEOUT.as_secs()
                        )));
                        break;
                    }
                }
            }
        }
    }
    let results = agent.apply_direct(Phase::Boot).await;
    for r in results.iter().filter(|r| !r.ok) {
        log::warn!(
            "开机应用 {} 失败：{}",
            r.item,
            r.detail.as_deref().unwrap_or("")
        );
    }
    agent.save();
    // Before GDM starts: the login screen says why there is no network, no settings or no browser yet.
    let (paths, has_bundle, fetch_error) = (
        sys_paths(&agent.cfg),
        agent.bundle.is_some(),
        agent.fetch_error.borrow().clone(),
    );
    if let Err(e) = tokio::task::spawn_blocking(move || {
        crate::status::refresh_once(&paths, runner.as_ref(), has_bundle, fetch_error.as_deref())
    })
    .await
    {
        log::warn!("device status: {e}");
    }
    Ok(())
}

/// 常驻（`run`、`once`）有应用任务并回报；`apply-local` 两样都没有。
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Resident,
    Local,
}

enum Wake {
    Shutdown,
    Woken,
    Elapsed,
    Report,
    Applied(ApplyOutcome),
    /// 托管任务的第一轮跑完了：放开回报。
    GateOpen,
    /// 后台任务改了应用步骤要读的状态（Flatpak 装好或卸掉了）：再应用一次。
    Reapply,
    /// 后台任务的结果变了：回报一次。
    SideChanged,
    /// 登录叫醒之后的那次拉取被挂住够久了：不等它，当作没有新版本。
    LoginDue,
    /// 一个人的 login 脚本跑完了（阻塞线程出错时为 None）。
    LoginDone(Option<Batch>),
    /// An event of the MQTT task; None: its channel closed.
    Push(Option<PushEvent>),
    /// The heartbeat timer is due.
    Heartbeat,
    /// A failed inbox sync may be retried.
    InboxRetry,
}

/// 登录钩子在主循环里的状态（见模块文档）。
struct Login {
    /// 登录队列（`<root>/run/mastersos/login-queue`）。
    queue: PathBuf,
    /// 导出的 login 脚本（`<root>/var/lib/mastersos-public/login-scripts`）。
    export: PathBuf,
    /// 最近登录记录（`<root>/var/lib/mastersos-system/homes/last-login.json`，Task 19）。
    last_login: PathBuf,
    runner: Arc<dyn Runner>,
    /// 取到了、还没跑的 uid。
    pending: BTreeSet<u32>,
    /// 取到了、还没发过期提示的 uid（拉取回来就发，不等应用、不等别人的脚本）。
    notify: BTreeSet<u32>,
    /// 叫醒之后的那次拉取还没回来：等到这个时刻为止。
    fetch_wait: Option<Instant>,
    /// 开始等那次拉取时本机的版本：拉取回来时变了，说明接受了新包，脚本要等它的应用（导出）。
    version_at_wake: Option<u64>,
    /// 要等应用任务闲下来再跑（这次拉取接受了新包）。
    wait_apply: bool,
    /// 正在跑的：每个 uid 一个阻塞任务。
    tasks: tokio::task::JoinSet<Batch>,
    /// 任务 id → uid（任务异常退出时也知道是谁的）。
    running: std::collections::HashMap<tokio::task::Id, u32>,
    /// 各脚本最近一次跑的结果（`login-script:<路径>` → 结果），不分用户。
    results: BTreeMap<String, ItemResult>,
}

struct Agent {
    cfg: AgentConfig,
    applier: Arc<dyn Applier>,
    seed: Seed,
    state: State,
    machine: Machine,
    fetcher: Fetcher,
    /// 当前应用着的包；本地没有（或没通过复验）时为 None。
    bundle: Option<Arc<Bundle>>,
    placement: Placement,
    /// 上一次应用的逐项结果。
    results: Vec<ItemResult>,
    /// 应用任务；`apply-local` 没有。
    worker: Option<ApplyHandle>,
    /// 上一轮应用有失败项（被 SIGUSR1 叫醒时立即重应用）。
    last_had_failures: bool,
    /// 后台任务的结果，回报时追加在应用结果之后。
    side: SideResults,
    /// 叫醒后台任务（主循环被叫醒时 `notify_waiters`）。
    job_wake: Arc<Notify>,
    /// 种子分区的 `identity.json`（托管凭据，交给后台任务）。
    identity: Option<seedpart::Identity>,
    /// 为真时 `report()` 什么都不发（第一份回报等托管任务，见 `run_with_wake`）。
    reports_held: bool,
    /// 托管任务的第一轮跑完（或等够了）时被通知：放开回报、立即回报一次。
    report_gate: Option<Arc<Notify>>,
    /// 后台任务的结果变了（例如托管从失败变成功）：立即回报，不等定时回报。
    side_changed: Option<Arc<Notify>>,
    /// 写种子分区缓存失败（`system:seed-cache`）；下一次写成功时清掉。
    seed_cache: Option<ItemResult>,
    mode: Mode,
    /// 最近一次拒收的原因；下一个包被接受时清掉。
    rejected: Option<ItemResult>,
    /// Consecutive failed fetches since the last good one: the next wait is
    /// [`crate::backoff::backoff`] of this (ruling 59).
    backoff_attempt: u32,
    /// 拒收后下一次拉取前等多久：从 reject_wait 起翻倍，上限 FALLBACK_SECS；接受新包后复位。
    reject_backoff: Duration,
    last_report: Instant,
    last_fetch_ok_saved: Option<chrono::DateTime<Utc>>,
    /// 上一次试着换领拉取令牌的时刻（不论结果）。
    last_renew: Option<std::time::Instant>,
    /// `fetch-token` 回报项：换领或换用令牌的最近结果。
    fetch_token: Option<ItemResult>,
    /// 上次拉取成功以来被 401 过的令牌（sha256）：401 时只换用没被拒过的，不来回切换。
    rejected_tokens: std::collections::BTreeSet<String>,
    /// 已经开始恢复出厂（请求已设、重启已发出）：不再交应用请求。
    resetting: bool,
    /// Settings must be synced (`fetch_now`): set at startup, by a doorbell, a (re)connect, a wake
    /// or a failed sync; cleared when a sync starts.
    sync_settings: bool,
    /// The inbox must be synced: set at startup, by an inbox doorbell above `inbox_after`, a
    /// (re)connect or a failed sync; cleared when a sync starts.
    sync_inbox: bool,
    /// A failed inbox sync is retried no earlier than this ([`crate::backoff`]).
    inbox_retry: Option<Instant>,
    /// Consecutive failed inbox syncs.
    inbox_attempt: u32,
    /// "No device credential, no inbox" was logged.
    inbox_no_cred_logged: bool,
    /// The device credential for push and the inbox (`device_id` from the state, the secret from
    /// `identity.json`); None without one.
    cred: Option<DeviceCred>,
    /// Runs the factory reset's commands.
    runner: Arc<dyn Runner>,
    /// Events of the MQTT task (or of a test).
    push_rx: Option<mpsc::Receiver<PushEvent>>,
    /// The MQTT task waiting to start behind the first-report gate.
    push_pending: Option<(DeviceCred, CancellationToken)>,
    push_task: Option<tokio::task::JoinHandle<()>>,
    /// The `push` report item: the MQTT task's latest status.
    push: Option<ItemResult>,
    /// When the heartbeat timer checks next.
    heartbeat_due: Instant,
    /// 这台机器眼下选中的分组，交应用请求时发布（后台任务的 `JobCtx::current`）。
    current: tokio::sync::watch::Sender<Option<Arc<CurrentGroup>>>,
    /// 后台任务要求再应用一次（`JobCtx::reapply`）。
    reapply: Arc<Notify>,
    /// The latest settings fetch's error, `None` after a good one (`JobCtx::fetch_error`, the status job).
    fetch_error: tokio::sync::watch::Sender<Option<String>>,
    login: Login,
}

/// A fixed phrase per refusal for the login-screen status: the error's own text can carry strings from the unverified
/// bundle (parse errors, key ids, paths), which must not reach a pre-login screen. The full error goes to the log and
/// the report only.
pub(crate) fn rejected_reason(e: &mastersos_bundle::BundleError) -> &'static str {
    use mastersos_bundle::BundleError as E;
    match e {
        E::Parse(_) | E::Invalid(_) | E::UnsafePath(_) => "invalid bundle",
        E::TooLarge => "bundle too large",
        E::BadSignature => "bad signature",
        E::UnknownKey(_) => "unknown signing key",
        E::NotNewer { .. } => "not newer than the current settings",
        E::Io(_) => "could not read or store the bundle",
        E::OtherSchool => "bundle is for another school",
        E::KitRequired(_) => "trust change not signed by a recovery kit",
        E::FormatTooNew { .. } => "settings need a newer system version",
    }
}

impl Agent {
    async fn start(
        cfg: AgentConfig,
        applier: Arc<dyn Applier>,
        mode: Mode,
        hold_reports: bool,
    ) -> Result<Agent> {
        let imported = seedpart::import_if_fresh(&cfg.state_dir, &cfg.seed_dir)
            .context("从种子分区导入失败")?;
        let (seed, mut state) = state::load(&cfg.state_dir)?;
        // 每次启动都收紧：里面有种子（fetch_token）、可能带 Wi‑Fi 口令的包。
        if let Err(e) = state::ensure_state_dir(&cfg.state_dir) {
            log::error!("收紧 {} 的权限失败：{e:#}", cfg.state_dir.display());
        }
        // identity.json：还没有 device_id（新装、恢复出厂）时以它为准，恢复出厂后在面板上仍是同一台；
        // 已有 device_id 时只用它的托管凭据（恢复密钥托管，Task 8），device_id 仍以 state 为准——
        // 计划 1 时代装的机器第一次建 identity.json 时也沿用 state 的 device_id。种子分区上的东西
        // 不是任何权威：被改过的托管凭据只会让托管被拒（403，回报里看得见）。
        let identity = match seed_writable(&cfg).and_then(|()| {
            seedpart::load_or_create_identity(&cfg.seed_dir, state.device_id.as_deref())
        }) {
            Ok(id) => Some(id),
            Err(e) => {
                log::warn!("读取种子分区的 identity.json 失败（没有托管凭据；没有 device_id 时改用本机生成的）：{e:#}");
                None
            }
        };
        if state.device_id.is_none() {
            state.device_id = identity.as_ref().map(|id| id.device_id.clone());
        } else if let Some(id) = identity
            .as_ref()
            .filter(|id| Some(&id.device_id) != state.device_id.as_ref())
        {
            log::warn!(
                "identity.json 的 device_id（{}）与 state.json 的不同，以 state.json 为准",
                id.device_id
            );
        }
        if matches!(imported, Imported::Fresh { .. }) {
            // 检测离线改过的种子分区：记下导入时种子里的 trust 指纹，随回报交给服务端对照。
            state.seed_import = Some(state::SeedImport {
                at: Utc::now(),
                trust_fingerprints: seed.trust.iter().map(trust_fingerprint).collect(),
            });
            // The first start after an inbox factory reset: the seed partition names the command.
            match inbox::read_reset_seq(&cfg.seed_dir, cfg.seed_requires_mount) {
                Ok(Some(seq)) => {
                    log::info!("inbox: this state follows the factory reset of seq {seq}");
                    state.inbox_after = state.inbox_after.max(seq);
                    state.reset_done_seq = Some(seq);
                }
                Ok(None) => {}
                Err(e) => log::warn!("reading {} failed: {e:#}", inbox::RESET_SEQ),
            }
            // 立即落盘：apply-local 要到最后才 save，中途断电下次就是 Existing，指纹再也记不上。
            if let Err(e) = state::save(&cfg.state_dir, &state) {
                log::error!("保存导入记录失败：{e:#}");
            }
        }
        let machine = Machine::read(&cfg, &mut state);
        // 先用验过它的那组钥匙复验（轮换后 `trust` 已是新钥匙，包仍是旧钥匙签的）；
        // 再用 `trust`：接受新包后、写 state.json 前断电，验过它的就是那时的 `trust`。
        let loaded = state::load_current_with(
            &cfg.state_dir,
            &[state.bundle_trust.as_slice(), state.trust.as_slice()],
            seed.school_id.as_deref(),
            state.school_id.as_deref(),
        );
        // 本地验过的包本身就是「至少到过这一版」的证据：state.json 损坏重建、或在
        // store_bundle 与 save 之间断电后，版本下限和信任都从包里找回来——
        // 与 take_new 接受它时写下的一样。
        let bundle = loaded.map(|(b, verified_by)| {
            if state.version <= Some(b.manifest.version) {
                state.version = Some(b.manifest.version);
                state.trust = b.manifest.trust.clone();
                state.bundle_trust = verified_by;
                state.accepted_recipients = Some(b.manifest.school.escrow_recipients.clone());
            }
            if let Some(id) = &b.manifest.school.id {
                state.school_id = Some(id.clone());
            }
            Arc::new(b)
        });
        // 应用任务还没起：除了 current 指向的，别的包目录都没人用。
        state::gc_keep_current(&cfg.state_dir, None);
        // 计划 1 的 state 没有 accepted_at：用最后一次拉取成功的时刻补上（不早于它接受过）。
        if state.accepted_at.is_none() && state.version.is_some() {
            state.accepted_at = state.last_fetch_ok;
        }
        let placement = seed_placement(&seed);
        // 下载用：不设总超时（大文件），只限连接与两次读之间的间隔。
        let http = crate::fetch::http_client(crate::fetch::HttpOpts {
            connect: Duration::from_secs(30),
            read: Some(Duration::from_secs(120)),
            total: None,
        });
        let cfg_root = cfg.root.clone();
        let heartbeat_due = later(cfg.heartbeat_every);
        let worker = (mode == Mode::Resident).then(|| {
            apply_worker::spawn(
                applier.clone(),
                cfg.clone(),
                seed.clone(),
                machine.ident.clone(),
                http.clone(),
            )
        });
        let mut agent = Agent {
            fetcher: Fetcher::new(
                &seed,
                token::effective(&cfg.state_dir, &cfg.seed_dir, &seed),
            ),
            backoff_attempt: 0,
            reject_backoff: cfg.reject_wait,
            last_fetch_ok_saved: state.last_fetch_ok,
            cfg,
            applier,
            seed,
            state,
            machine,
            bundle,
            placement,
            results: vec![],
            worker,
            last_had_failures: false,
            side: Arc::new(Mutex::new(Default::default())),
            job_wake: Arc::new(Notify::new()),
            identity,
            reports_held: hold_reports,
            report_gate: None,
            side_changed: None,
            seed_cache: None,
            mode,
            rejected: None,
            last_report: Instant::now(),
            last_renew: None,
            fetch_token: None,
            rejected_tokens: Default::default(),
            resetting: false,
            sync_settings: false,
            sync_inbox: false,
            inbox_retry: None,
            inbox_attempt: 0,
            inbox_no_cred_logged: false,
            cred: None,
            runner: Arc::new(RealRunner),
            push_rx: None,
            push_pending: None,
            push_task: None,
            push: None,
            heartbeat_due,
            current: tokio::sync::watch::channel(None).0,
            reapply: Arc::new(Notify::new()),
            fetch_error: tokio::sync::watch::channel(None).0,
            login: Login {
                queue: cfg_root_join(&cfg_root, login_queue::QUEUE_DIR),
                export: cfg_root_join(&cfg_root, login_queue::EXPORT_DIR),
                last_login: cfg_root_join(&cfg_root, crate::homes::LAST_LOGIN),
                runner: Arc::new(RealRunner),
                pending: BTreeSet::new(),
                notify: BTreeSet::new(),
                fetch_wait: None,
                version_at_wake: None,
                wait_apply: false,
                tasks: tokio::task::JoinSet::new(),
                running: Default::default(),
                results: BTreeMap::new(),
            },
        };
        agent.cred = agent.device_cred();
        agent.save();
        if imported
            == (Imported::Fresh {
                cached_bundle: true,
            })
        {
            agent.take_incoming().await;
        }
        agent.remove_incoming();
        Ok(agent)
    }

    /// 种子分区缓存的包（已复制为 `incoming.bundle`）当作刚拉到的包处理：种子的 `trust`、
    /// `min_version` 的下限，验不过就丢掉。
    async fn take_incoming(&mut self) {
        let path = self.cfg.state_dir.join(seedpart::INCOMING);
        let archive = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                log::warn!("读取 {} 失败：{e}", path.display());
                return;
            }
        };
        let claimed = claimed_version(&archive);
        match self.take_new(&archive, claimed, true).await {
            Ok(true) => log::info!("接受了种子分区缓存的设置包 v{claimed}"),
            Ok(false) => log::warn!("种子分区缓存的设置包没通过验证，丢掉、照常拉取"),
            Err(e) => log::warn!("{e:#}"),
        }
    }

    /// 删掉 `incoming.bundle`（不论验过与否；已有状态时它不会再被读）。
    fn remove_incoming(&self) {
        let r = safefs::open_dir(&self.cfg.state_dir, Path::new(""), false)
            .and_then(|d| safefs::remove_at(&d, seedpart::INCOMING));
        if let Err(e) = r {
            log::warn!("删除 {} 失败：{e:#}", seedpart::INCOMING);
        }
    }

    fn apply_pending(&self) -> bool {
        self.worker.as_ref().is_some_and(|w| w.pending())
    }

    /// 交一份应用请求（`Phase::Full`）；`apply-local` 没有应用任务、或已经开始恢复出厂时什么都不做。
    fn request_apply(&mut self) {
        let Some(w) = &self.worker else {
            return;
        };
        if self.resetting {
            return;
        }
        self.placement = placement_for(self.bundle.as_deref(), &self.machine.ident, &self.seed);
        self.publish_current();
        w.request(ApplyRequest {
            bundle: self.bundle.clone(),
            phase: Phase::Full,
            managed_paths: self.state.managed_paths.clone(),
            script_hashes: self.state.script_hashes.clone(),
        });
    }

    /// 发布这台机器眼下选中的分组（没变就不通知，后台任务不会白跑）。已经开始恢复出厂时发布 None（复审 M4：
    /// 后台任务不该在恢复出厂期间按清单装软件）。
    fn publish_current(&self) {
        let bundle = if self.resetting {
            None
        } else {
            self.bundle.as_deref()
        };
        let now = bundle.map(|b| {
            let m = &b.manifest;
            let sel = select(m, &self.machine.ident, self.seed.group.as_deref());
            Arc::new(CurrentGroup {
                version: m.version,
                group: sel.group.clone(),
                config: sel.config,
                escrow_recipients: m.school.escrow_recipients.clone(),
            })
        });
        self.current.send_if_modified(|cur| {
            if *cur == now {
                return false;
            }
            *cur = now;
            true
        });
    }

    /// 合并应用任务交回的结果并保存。
    fn merge(&mut self, o: ApplyOutcome) {
        self.state.managed_paths = o.managed_paths;
        self.state.script_hashes = o.script_hashes;
        self.results = o.results;
        self.last_had_failures = o.had_failures;
        self.save();
        if let Some(w) = &self.worker {
            w.gc(&self.cfg.state_dir);
        }
    }

    fn seed_writable(&self) -> Result<()> {
        seed_writable(&self.cfg)
    }

    /// 等到最近一次请求的结果回来（`once` 用）。
    async fn settle(&mut self) {
        while self.apply_pending() {
            let Some(o) = self.worker.as_mut().map(|w| w.next_outcome()) else {
                return;
            };
            match o.await {
                Some(o) => self.merge(o),
                None => return,
            }
        }
    }

    /// 退出前：让应用任务停在下一个步骤之前，合并它交回的结果并保存。
    async fn finish(&mut self) {
        let Some(w) = self.worker.take() else {
            return;
        };
        match tokio::time::timeout(SHUTDOWN_APPLY_GRACE, w.finish()).await {
            Ok(outcomes) => {
                for o in outcomes {
                    self.merge(o);
                }
            }
            Err(_) => log::warn!(
                "退出时应用任务 {} 秒内没有停下",
                SHUTDOWN_APPLY_GRACE.as_secs()
            ),
        }
    }

    /// 被 SIGUSR1（或测试的 wake）叫醒：同步一次设置；上一轮有失败项就立即再请求一次应用；取走登录队列。
    fn woken(&mut self) {
        self.sync_settings = true;
        if self.last_had_failures && !self.apply_pending() {
            self.request_apply();
        }
        self.take_logins();
        self.job_wake.notify_waiters();
    }

    /// 取走登录队列：有人登录就记下，等接下来的那次拉取（最多 [`LOGIN_FETCH_WAIT`]）。
    fn take_logins(&mut self) {
        if self.mode != Mode::Resident {
            return;
        }
        // 取走队列并当场记下登录时刻（Task 19 复审 N1）：在叫醒任何后台任务之前写进去，家目录清理的任何一轮都看得到
        // 这个人刚登录过。一个小 JSON 文件，同步写；失败只记日志，不影响登录
        let uids =
            crate::homes::drain_and_record(&self.login.queue, &self.login.last_login, Utc::now());
        if uids.is_empty() {
            return;
        }
        log::info!("有 {} 个会话登录，拉取之后跑 login 脚本", uids.len());
        self.login.pending.extend(uids.iter().copied());
        self.login.notify.extend(uids);
        if self.login.fetch_wait.is_none() {
            self.login.version_at_wake = self.state.version;
        }
        self.login.fetch_wait = Some(Instant::now() + LOGIN_FETCH_WAIT);
    }

    /// 拉取回来了（或不再等它）：这次拉取接受了新包就让脚本等它的应用；发过期提示；条件都满足就开始跑。
    fn login_fetched(&mut self) {
        if self.login.fetch_wait.take().is_some()
            && self.state.version != self.login.version_at_wake
        {
            self.login.wait_apply = true;
        }
        if self.login.fetch_wait.is_none() {
            self.send_notices();
        }
        self.maybe_start_login();
    }

    /// 设置可能过期就给拉取回来之前登录的每个人发提示，每人一个阻塞任务（不挡脚本、不挡主循环）。
    fn send_notices(&mut self) {
        let uids = std::mem::take(&mut self.login.notify);
        let now = Utc::now();
        if self.resetting || login_queue::stale_notice(&self.state, now).is_none() {
            return;
        }
        for uid in uids {
            let (st, r) = (self.state.clone(), self.login.runner.clone());
            tokio::task::spawn_blocking(move || {
                login_queue::notify_if_stale(uid, &st, now, r.as_ref())
            });
        }
    }

    /// 叫醒后的拉取已回来、（接受了新包时）它的应用也跑完了：给每个等着、手上没有正在跑的任务的 uid 起一个阻塞任务。
    fn maybe_start_login(&mut self) {
        if self.login.pending.is_empty() || self.login.fetch_wait.is_some() || self.resetting {
            return;
        }
        if self.login.wait_apply {
            if self.apply_pending() {
                return;
            }
            self.login.wait_apply = false;
        }
        let Some(config) = self.login_config() else {
            self.login.pending.clear();
            return;
        };
        let busy: BTreeSet<u32> = self.login.running.values().copied().collect();
        let ready: Vec<u32> = self
            .login
            .pending
            .iter()
            .copied()
            .filter(|u| !busy.contains(u))
            .collect();
        for uid in ready {
            self.login.pending.remove(&uid);
            let (export, runner, config) = (
                self.login.export.clone(),
                self.login.runner.clone(),
                config.clone(),
            );
            let hashes = login_queue::hashes_of(&self.state.login_script_hashes, uid);
            let h = self.login.tasks.spawn_blocking(move || {
                login_queue::run_batch(uid, &config, &export, hashes, runner.as_ref())
            });
            self.login.running.insert(h.id(), uid);
        }
    }

    /// The Config the current bundle picks for this machine (None without a bundle).
    fn login_config(&self) -> Option<mastersos_bundle::Config> {
        let b = self.bundle.as_deref()?;
        Some(
            select(&b.manifest, &self.machine.ident, self.seed.group.as_deref())
                .config
                .clone(),
        )
    }

    /// 一个人的 login 脚本跑完：按 uid 合并哈希、记结果、去掉清单里已没有的脚本的哈希、保存；再看还有没有等着的人。
    fn login_done(&mut self, b: Option<Batch>) {
        if let Some(b) = b {
            login_queue::merge_hashes(&mut self.state.login_script_hashes, &b);
            for r in b.results {
                self.login.results.insert(r.item.clone(), r);
            }
            if let Some(g) = self.login_config() {
                login_queue::prune_hashes(&mut self.state.login_script_hashes, &g);
            }
            self.save();
        }
        self.maybe_start_login();
    }

    /// 回报里的 login 脚本结果：只留当前配置里还有的脚本。
    fn login_results(&self) -> Vec<ItemResult> {
        match self.login_config() {
            Some(g) => login_queue::current_results(self.login.results.values(), &g),
            None => vec![],
        }
    }

    /// 直接在本任务里调 applier（`apply-local`）。没有包时调 `apply_without_bundle`。
    async fn apply_direct(&mut self, phase: Phase) -> Vec<ItemResult> {
        let applier = self.applier.clone();
        let bundle = self.bundle.clone();
        let ident = self.machine.ident.clone();
        let seed = self.seed.clone();
        let dir = bundle
            .as_deref()
            .map(|b| state::version_dir(&self.cfg.state_dir, b))
            .unwrap_or_default();
        self.placement = placement_for(bundle.as_deref(), &ident, &seed);
        tokio::task::spawn_blocking(move || {
            let Some(b) = bundle else {
                return applier.apply_without_bundle(&seed, phase);
            };
            let m = &b.manifest;
            let sel = select(m, &ident, seed.group.as_deref());
            let superseded = AtomicBool::new(false);
            applier.apply(&ApplyContext {
                seed: &seed,
                school: &m.school,
                group: sel.group,
                config: &sel.config,
                lock: sel.lock,
                bundle_dir: &dir,
                phase,
                superseded: &superseded,
            })
        })
        .await
        .unwrap_or_else(|e| vec![failed("applier", format!("异常退出：{e}"))])
    }

    /// 验新包时的「当前版本」。本地的包丢了或没通过复验时退一格，好把同一版重新拿回来；
    /// 比它旧的仍然拒收。
    ///
    /// 还没接受过任何包时，下限来自种子的 `min_version = m`：版本号小于 m 的包被拒收，
    /// m 本身可以接受。接受过之后，下限照旧来自 `state.version`。
    fn floor(&self) -> Option<u64> {
        let Some(v) = self.state.version else {
            return self.seed.min_version.map(|m| m.saturating_sub(1));
        };
        match self.bundle {
            Some(_) => Some(v),
            None => Some(v.saturating_sub(1)),
        }
    }

    /// 长轮询的 `after`：只看已接受的版本。被拒收的包自称的版本号没有经过验证，
    /// 不能拿来定 `after`——否则一个声称 u64::MAX 的伪造包就能让机器再也不要更新。
    fn after(&self) -> Option<u64> {
        self.floor()
    }

    fn save(&self) {
        if let Err(e) = state::save(&self.cfg.state_dir, &self.state) {
            log::error!("保存 state.json 失败：{e:#}");
        }
    }

    /// Publishes the outcome of a settings fetch for the status job: the error, or `None` when the server answered.
    fn fetch_result(&self, err: Option<&anyhow::Error>) {
        self.fetch_error.send_replace(err.map(|e| format!("{e:#}")));
    }

    fn fetch_ok(&mut self) {
        self.rejected_tokens.clear();
        let now = Utc::now();
        self.state.last_fetch_ok = Some(now);
        self.backoff_attempt = 0;
        let due = self
            .last_fetch_ok_saved
            .is_none_or(|t| now - t >= FETCH_OK_SAVE_EVERY);
        if due {
            self.save();
            self.last_fetch_ok_saved = Some(now);
        }
    }

    /// 托管任务的第一轮跑完了：放开回报，把之前压着的立即发一份。
    async fn open_reports(&mut self) {
        self.report_gate = None;
        self.reports_held = false;
        self.start_push();
        let _ = self.report().await;
    }

    /// The MQTT task needs the device credential: `device_id` from the state, the secret from
    /// `identity.json` (as the escrow job has them). Without one there is no task, and the `push`
    /// item says so.
    fn plan_push(&mut self, shutdown: &CancellationToken) {
        let Some(cred) = self.cred.clone() else {
            log::warn!("push: no device credential, not connecting");
            self.push = Some(failed(push::ITEM, "no device credential".into()));
            return;
        };
        self.push_pending = Some((cred, shutdown.clone()));
    }

    /// The device credential for push and the inbox: `device_id` from the state, the secret
    /// from `identity.json` (as the escrow job has them).
    fn device_cred(&self) -> Option<DeviceCred> {
        match (&self.state.device_id, &self.identity) {
            (Some(device_id), Some(id)) => Some(DeviceCred {
                device_id: device_id.clone(),
                secret: id.escrow_secret.clone(),
            }),
            _ => None,
        }
    }

    /// Whether an inbox sync is due now (asked for, no reset under way, past any retry backoff).
    fn inbox_due(&self) -> bool {
        self.sync_inbox && !self.resetting && self.inbox_retry.is_none_or(|t| Instant::now() >= t)
    }

    /// When a pending inbox retry is due (none without one).
    fn inbox_retry_due(&self) -> Option<Instant> {
        self.inbox_retry
            .filter(|_| self.sync_inbox && !self.resetting)
    }

    /// Syncs the inbox when due ([`inbox::sync`]); first reports a finished factory reset `done`.
    /// A failure keeps `sync_inbox` set and retries after the backoff (ruling 59) until one sync
    /// succeeds; a 401 on the fetch token also syncs settings, which switches tokens.
    async fn maybe_sync_inbox(&mut self) {
        if !self.inbox_due() {
            return;
        }
        self.sync_inbox = false;
        let Some(cred) = self.cred.clone() else {
            if !self.inbox_no_cred_logged {
                log::warn!("inbox: no device credential, not syncing");
                self.inbox_no_cred_logged = true;
            }
            return;
        };
        log::debug!(
            "push: inbox sync requested (after {})",
            self.state.inbox_after
        );
        // The `done` ack of a finished reset is retried on its own: its failure never holds up
        // the inbox (a new command, a new reset, must still get through).
        let mut done_error = None;
        if let Some(seq) = self.state.reset_done_seq {
            let r = {
                let noop = |_: u64| {};
                inbox::ack_reset_done(&self.inbox_ctx(&cred, &noop), seq).await
            };
            match r {
                Ok(()) => {
                    self.state.reset_done_seq = None;
                    self.save();
                }
                Err(e) => done_error = Some(e.context("reporting the factory reset done failed")),
            }
        }
        let mut error = {
            let base = self.state.clone();
            let dir = self.cfg.state_dir.clone();
            let persist = move |n: u64| {
                let mut s = base.clone();
                s.inbox_after = n;
                if let Err(e) = state::save(&dir, &s) {
                    log::error!("saving state.json failed: {e:#}");
                }
            };
            let out = inbox::sync(&self.inbox_ctx(&cred, &persist), self.state.inbox_after).await;
            if out.inbox_after != self.state.inbox_after {
                self.state.inbox_after = out.inbox_after;
                self.save();
            }
            if out.resetting {
                self.resetting = true;
                // The jobs see None and install nothing more during the reset.
                self.publish_current();
            }
            out.error
        };
        if error.is_none() {
            error = done_error;
        } else if let Some(e) = done_error {
            log::warn!("{e:#}");
        }
        match error {
            None => {
                self.inbox_attempt = 0;
                self.inbox_retry = None;
            }
            Some(e) => {
                log::warn!("inbox sync failed: {e:#}");
                if e.downcast_ref::<crate::fetch::Unauthorized>().is_some() {
                    self.sync_settings = true;
                }
                let d = crate::backoff::backoff(
                    self.inbox_attempt,
                    self.cfg.backoff_start,
                    self.cfg.backoff_max,
                    self.cfg.jitter.unit(),
                );
                self.inbox_attempt = self.inbox_attempt.saturating_add(1);
                self.inbox_retry = Some(later(d));
                self.sync_inbox = true;
            }
        }
    }

    fn inbox_ctx<'a>(
        &'a self,
        cred: &'a DeviceCred,
        persist: &'a (dyn Fn(u64) + Send + Sync),
    ) -> inbox::InboxCtx<'a> {
        inbox::InboxCtx {
            fetcher: &self.fetcher,
            cred,
            runner: self.runner.clone(),
            seed_dir: &self.cfg.seed_dir,
            seed_requires_mount: self.cfg.seed_requires_mount,
            sysfs: self.cfg.root.join("sys"),
            dev: self.cfg.root.join("dev"),
            clock: &Utc::now,
            status: self.status_report(),
            lab: crate::luks::image_is_lab(&self.cfg.root),
            persist,
        }
    }

    /// Starts the planned MQTT task (once the first report may go out).
    fn start_push(&mut self) {
        let Some((cred, shutdown)) = self.push_pending.take() else {
            return;
        };
        let (tx, rx) = mpsc::channel(16);
        let lab = crate::luks::image_is_lab(&self.cfg.root);
        self.push_task = Some(push::spawn(
            self.fetcher.clone(),
            cred,
            PushTiming::standard(lab),
            tx,
            shutdown,
        ));
        self.push_rx = Some(rx);
    }

    /// One event of the MQTT task (spec §6.1): sets what to sync; a changed status is reported.
    async fn on_push(&mut self, e: PushEvent) {
        match e {
            PushEvent::Connected => {
                self.sync_settings = true;
                self.sync_inbox = true;
            }
            PushEvent::Bell(Doorbell::Settings(n)) => {
                if n > self.after().unwrap_or(0) {
                    self.sync_settings = true;
                }
            }
            PushEvent::Bell(Doorbell::Inbox(m)) => {
                if m > self.state.inbox_after {
                    self.sync_inbox = true;
                }
            }
            PushEvent::Status(i) => {
                // A 401 on the grant is the fetch's 401 (spec §6.2): the sync that follows meets
                // it on `/v1/bundle` and switches tokens there (`on_unauthorized`); the MQTT task
                // shares the fetcher's token.
                if i.detail.as_deref() == Some(push::TOKEN_UNAUTHORIZED) {
                    self.sync_settings = true;
                }
                if self.push.as_ref() != Some(&i) {
                    self.push = Some(i);
                    let _ = self.report().await;
                }
            }
        }
    }

    /// 回报失败只记日志：下一次事件或定时回报会再发。
    async fn report(&mut self) -> Result<()> {
        if self.mode == Mode::Local || self.reports_held {
            return Ok(());
        }
        self.last_report = Instant::now();
        let r = self.status_report();
        let sent = self.fetcher.report(&r).await;
        if let Err(e) = &sent {
            log::warn!("回报状态失败：{e:#}");
        }
        sent
    }

    /// 这一刻要回报的内容。
    fn status_report(&self) -> mastersos_bundle::StatusReport {
        // 拒收放在最前面：条数上限与 detail 预算都截不掉它。
        let mut results: Vec<ItemResult> = self.rejected.iter().cloned().collect();
        results.extend(self.results.iter().cloned());
        results.extend(self.seed_cache.iter().cloned());
        results.extend(self.fetch_token.iter().cloned());
        results.extend(self.push.iter().cloned());
        results.extend(self.login_results());
        results.extend(jobs::snapshot(&self.side));
        let mut r = report::build(
            &self.machine,
            &self.placement,
            &Freshness {
                last_fetch_ok: self.state.last_fetch_ok,
                accepted_at: self.state.accepted_at,
                fresh_until: self.state.fresh_until,
                newer_withheld: self.state.newer_withheld,
            },
            results,
            Utc::now(),
        );
        if let Some(si) = &self.state.seed_import {
            r.seed_trust_fingerprints = si.trust_fingerprints.clone();
            r.imported_from_seed_at =
                Some(si.at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
        }
        r
    }

    /// 处理一个新包。接受了（并交了应用请求）返回 Ok(true)，拒收返回 Ok(false)；
    /// 落盘失败是本机的问题，返回错误、走退避，不当作拒收。
    /// 拒收时记下包的 sha256：同一个包再送来，直接拒收，不再解包验签，也不再回报一遍。
    /// Only a refusal by this same agent build counts ([`state::State::refused_before`]): one
    /// recorded by an older agent (say, one that could not read `format = 2`) is checked again.
    ///
    /// `from_cache`：包来自种子分区的缓存（离线导入），不是刚从服务端拉到的——不记
    /// `last_fetch_ok`（那是「联系上了服务端」的证据，计划 2 的过期判断靠它）。
    ///
    /// A refusal or a failure to store is also published as the fetch error (`settings bundle rejected: …`), so the
    /// device status says why the machine is still waiting for settings instead of a bare "Waiting".
    async fn take_new(&mut self, archive: &[u8], version: u64, from_cache: bool) -> Result<bool> {
        let sha = sha256_hex(archive);
        if self.state.refused_before(&sha) {
            self.fetch_error.send_replace(Some(format!(
                "settings bundle rejected: v{version} is the bundle refused before"
            )));
            if self.rejected.is_none() {
                // 重启后第一次再见到它：回报里补上这条失败。
                self.rejected = Some(failed("bundle", format!("v{version}：与先前拒收的包相同")));
                let _ = self.report().await;
            }
            return Ok(false);
        }
        // The school binding (plan 6 Task 10b) is part of accepting: a bundle for another school
        // is refused like a bad signature, reported, and the current bundle is kept.
        // Once a school is remembered (state.json, encrypted root), a seed without a school id
        // (or with another) cannot move the machine (review M1 of Task 10b).
        // R7/R8 (plan 6 Task 24c): once a bundle was accepted, a change of trust or escrow
        // recipients must be signed by a recovery kit in the current trust, whatever the server
        // accepted. The first bundle after the seed is checked against the seed's trust alone.
        let prior = if self.state.version.is_some() {
            state::Prior::Accepted(
                self.bundle
                    .as_deref()
                    .map(|b| b.manifest.school.escrow_recipients.as_slice())
                    .or(self.state.accepted_recipients.as_deref()),
            )
        } else {
            state::Prior::Nothing
        };
        match state::accept_bundle(
            archive,
            &self.state.trust,
            self.floor(),
            self.seed.school_id.as_deref(),
            self.state.school_id.as_deref(),
            prior,
        ) {
            Ok(bundle) => {
                if let Err(e) = state::store_bundle(&self.cfg.state_dir, archive, &bundle) {
                    self.fetch_error
                        .send_replace(Some(format!("settings bundle could not be saved: {e:#}")));
                    return Err(e.context("保存设置包失败"));
                }
                // 验过它的钥匙留给开机复验；之后的新包按它列出的 trust 验。
                self.state.bundle_trust =
                    std::mem::replace(&mut self.state.trust, bundle.manifest.trust.clone());
                // fresh_until 说的是旧的那一版：换了版本就作废，新版要靠自己的心跳。
                if self.state.version != Some(bundle.manifest.version) {
                    self.state.fresh_until = None;
                }
                self.state.version = Some(bundle.manifest.version);
                self.state.accepted_recipients =
                    Some(bundle.manifest.school.escrow_recipients.clone());
                self.state.accepted_at = Some(Utc::now());
                if let Some(id) = &bundle.manifest.school.id {
                    self.state.school_id = Some(id.clone());
                }
                if self
                    .state
                    .newer_withheld
                    .is_some_and(|w| w <= bundle.manifest.version)
                {
                    self.state.newer_withheld = None;
                }
                self.state.clear_refusal();
                self.rejected = None;
                self.reject_backoff = self.cfg.reject_wait;
                log::info!("已接受设置包 v{}", bundle.manifest.version);
                self.bundle = Some(Arc::new(bundle));
                if !from_cache {
                    self.fetch_ok();
                }
                self.save();
                // 种子分区的缓存只为恢复出厂后离线也有设置；写不进去只回报，不影响别的。
                self.seed_cache = self
                    .seed_writable()
                    .and_then(|()| seedpart::store_cache(&self.cfg.seed_dir, archive))
                    .err()
                    .map(|e| failed("system:seed-cache", format!("{e:#}")));
                self.request_apply();
                let _ = self.report().await;
                Ok(true)
            }
            // A newer `format` is not a bad bundle: this OS cannot read it yet, but a later OS
            // can. Keep the current bundle, report why, and do not blacklist the sha256, so the
            // same version is taken once the OS is updated; sync again after the reject backoff.
            Err(e @ BundleError::FormatTooNew { .. }) => {
                log::warn!("settings bundle v{version} not applied: {e}");
                self.fetch_error.send_replace(Some(format!(
                    "settings not applied: {}",
                    rejected_reason(&e)
                )));
                self.rejected = Some(failed("bundle", e.to_string()));
                self.sync_settings = true;
                let _ = self.report().await;
                Ok(false)
            }
            Err(e) => {
                log::warn!("拒收设置包（自称 v{version}）：{e}");
                self.fetch_error.send_replace(Some(format!(
                    "settings bundle rejected: {}",
                    rejected_reason(&e)
                )));
                self.state.record_refusal(sha);
                self.backoff_attempt = 0;
                self.save();
                self.rejected = Some(failed("bundle", format!("v{version}：{e}")));
                let _ = self.report().await;
                Ok(false)
            }
        }
    }

    /// Waits until `until` (a backoff), or, without one, until there is something to sync. Meanwhile
    /// reports, apply results, logins, push events and the heartbeat timer are handled; push events
    /// only set what to sync. Returns early on a wake (Woken) or shutdown (Shutdown), else Elapsed.
    async fn wait(
        &mut self,
        until: Option<Instant>,
        shutdown: &CancellationToken,
        wake: &Notify,
    ) -> Wake {
        loop {
            self.maybe_sync_inbox().await;
            if until.is_none() && self.sync_settings {
                return Wake::Elapsed;
            }
            let next_report = self.last_report + self.cfg.report_every;
            let inbox_retry = self.inbox_retry_due();
            let w = tokio::select! {
                biased;
                _ = shutdown.cancelled() => Wake::Shutdown,
                _ = gate_opened(&self.report_gate) => Wake::GateOpen,
                _ = gate_opened(&self.side_changed) => Wake::SideChanged,
                _ = wake.notified() => Wake::Woken,
                _ = self.reapply.notified() => Wake::Reapply,
                o = next_outcome(&mut self.worker) => Wake::Applied(o),
                b = login_finished(&mut self.login.tasks, &mut self.login.running) => Wake::LoginDone(b),
                _ = login_due(self.login.fetch_wait) => Wake::LoginDue,
                e = next_push(&mut self.push_rx) => Wake::Push(e),
                _ = sleep_until(self.heartbeat_due) => Wake::Heartbeat,
                _ = until_due(inbox_retry) => Wake::InboxRetry,
                _ = until_due(until) => Wake::Elapsed,
                _ = sleep_until(next_report) => Wake::Report,
            };
            match w {
                Wake::Report => self.report_then_renew().await,
                Wake::GateOpen => self.open_reports().await,
                Wake::SideChanged => self.report_then_renew().await,
                Wake::Reapply => self.request_apply(),
                Wake::LoginDue => self.login_fetched(),
                Wake::LoginDone(b) => {
                    self.login_done(b);
                    self.report_then_renew().await;
                }
                Wake::Applied(o) => {
                    self.merge(o);
                    self.maybe_start_login();
                    self.report_then_renew().await;
                }
                Wake::Push(Some(e)) => self.on_push(e).await,
                // The loop's top syncs it.
                Wake::InboxRetry => {}
                // The MQTT task is gone (it only stops on shutdown).
                Wake::Push(None) => self.push_rx = None,
                Wake::Heartbeat => {
                    // The timer is the interval: check regardless of the wall clock.
                    if !self.heartbeat_unless(shutdown, true).await {
                        return Wake::Shutdown;
                    }
                }
                Wake::Woken => {
                    self.woken();
                    return Wake::Woken;
                }
                other => return other,
            }
        }
    }

    /// One round: sync what is due, or wait until something is. Returns false when it is time to
    /// exit.
    async fn cycle(&mut self, shutdown: &CancellationToken, wake: &Notify) -> bool {
        // 上一轮的拉取、回报里见到了旧令牌标记：先换领（最多每小时一次）。
        self.maybe_renew().await;
        self.maybe_sync_inbox().await;
        if !self.sync_settings {
            return !matches!(self.wait(None, shutdown, wake).await, Wake::Shutdown);
        }
        self.sync_settings = false;
        let after = self.after().unwrap_or(0);
        // While the fetch is out, apply results, logins and reports are handled as usual.
        let fetcher = self.fetcher.clone();
        let fetch = fetcher.fetch_now(after);
        tokio::pin!(fetch);
        let outcome = loop {
            let next_report = self.last_report + self.cfg.report_every;
            let ev = tokio::select! {
                biased;
                _ = shutdown.cancelled() => return false,
                _ = gate_opened(&self.report_gate) => Wake::GateOpen,
                _ = gate_opened(&self.side_changed) => Wake::SideChanged,
                _ = wake.notified() => Wake::Woken,
                _ = self.reapply.notified() => Wake::Reapply,
                o = next_outcome(&mut self.worker) => Wake::Applied(o),
                b = login_finished(&mut self.login.tasks, &mut self.login.running) => Wake::LoginDone(b),
                _ = login_due(self.login.fetch_wait) => Wake::LoginDue,
                _ = sleep_until(next_report) => Wake::Report,
                r = &mut fetch => break r,
            };
            match ev {
                Wake::Woken => {
                    // Woken: drop this fetch, sync again from the top.
                    self.woken();
                    return true;
                }
                Wake::Applied(o) => {
                    self.merge(o);
                    self.maybe_start_login();
                    let _ = self.report().await;
                }
                Wake::LoginDue => self.login_fetched(),
                Wake::LoginDone(b) => {
                    self.login_done(b);
                    let _ = self.report().await;
                }
                Wake::GateOpen => self.open_reports().await,
                Wake::SideChanged | Wake::Report => {
                    let _ = self.report().await;
                }
                Wake::Reapply => self.request_apply(),
                _ => {}
            }
        };
        self.fetch_result(outcome.as_ref().err());
        let wait = match outcome {
            Ok(FetchOutcome::New { archive, version }) if version > after => {
                match self.take_new(&archive, version, false).await {
                    Ok(true) => {
                        // The server may hold more than this one step (a trust rotation is handed
                        // out version by version): sync again until it says nothing is new.
                        self.sync_settings = true;
                        if !self.heartbeat_unless(shutdown, false).await {
                            return false;
                        }
                        None
                    }
                    // The server answered; the same bundle is not fetched again until a doorbell
                    // or the heartbeat names a newer version, and not before the reject backoff.
                    Ok(false) => Some(self.next_reject_backoff()),
                    Err(e) => {
                        log::warn!("{e:#}");
                        self.sync_settings = true;
                        Some(self.next_backoff())
                    }
                }
            }
            Ok(_) => {
                self.fetch_ok();
                if !self.heartbeat_unless(shutdown, false).await {
                    return false;
                }
                None
            }
            Err(e) => {
                log::warn!("拉取设置包失败：{e:#}");
                if e.downcast_ref::<crate::fetch::Unauthorized>().is_some() {
                    self.on_unauthorized().await;
                }
                // Retried after the backoff until one sync succeeds (spec §6.2).
                self.sync_settings = true;
                Some(self.next_backoff())
            }
        };
        // 拉取回来了（不论结果）：等着的登录可以跑了（新包的应用还在跑时等它跑完）。
        self.login_fetched();
        self.maybe_renew().await;
        match wait {
            Some(d) => !matches!(
                self.wait(Some(later(d)), shutdown, wake).await,
                Wake::Shutdown
            ),
            None => true,
        }
    }

    /// 距上次取心跳超过 `heartbeat_every`（`force` 时不看间隔）就取一次并处理（见模块文档）；
    /// `fresh_until` 或 `newer_withheld` 变了就回报。返回 false 表示收到 shutdown、该退出了。
    /// Every check restarts the heartbeat timer.
    ///
    /// 只有两次网络请求（取心跳、按心跳重拉）与 shutdown 赛跑；接受新包（落盘、应用、跑脚本）
    /// 与主循环里一样，不会被 shutdown 打断在半路。
    async fn heartbeat_unless(&mut self, shutdown: &CancellationToken, force: bool) -> bool {
        let now = Utc::now();
        let every = TimeDelta::from_std(self.cfg.heartbeat_every).unwrap_or(TimeDelta::MAX);
        // 上次的时刻在将来（本机时钟被往回拨过）也算到了时候。
        if !force
            && self
                .state
                .heartbeat_checked_at
                .is_some_and(|t| t <= now && now - t < every)
        {
            return true;
        }
        self.state.heartbeat_checked_at = Some(now);
        self.heartbeat_due = later(self.cfg.heartbeat_every);
        let before = (self.state.fresh_until, self.state.newer_withheld);
        let fetched = tokio::select! {
            biased;
            _ = shutdown.cancelled() => return false,
            r = self.fetcher.heartbeat() => r,
        };
        let higher = match fetched {
            Ok(Some(text)) => self.take_heartbeat(&text, now),
            Ok(None) => None,
            Err(e) => {
                log::warn!("取心跳失败：{e:#}");
                None
            }
        };
        if let Some(v) = higher {
            // 心跳说有更新的版本：立即再拉一次，拉到就照常接受（可能先是一步 trust 轮换）。
            let after = self.after().unwrap_or(0);
            let refetched = tokio::select! {
                biased;
                _ = shutdown.cancelled() => return false,
                r = self.fetcher.fetch_now(after) => r,
            };
            match refetched {
                Ok(FetchOutcome::New { archive, version }) if version > after => {
                    match self.take_new(&archive, version, false).await {
                        // Possibly one step of several: sync again until nothing is new.
                        Ok(true) => self.sync_settings = true,
                        Ok(false) => {}
                        Err(e) => log::warn!("{e:#}"),
                    }
                }
                Ok(_) => {
                    self.fetch_ok();
                    log::warn!("签过名的心跳说有第 {v} 版，服务端却说没有新版本");
                    self.state.newer_withheld = Some(v);
                }
                Err(e) => log::warn!("按心跳重拉失败：{e:#}"),
            }
        }
        self.save();
        if (self.state.fresh_until, self.state.newer_withheld) != before {
            let _ = self.report().await;
        }
        true
    }

    /// 验一份心跳并采信说本机这一版的那种；说有更高版本时返回那个版本号（由调用方立即重拉）。
    fn take_heartbeat(&mut self, text: &str, now: DateTime<Utc>) -> Option<u64> {
        let s = match verify_heartbeat(text, &self.state.trust) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("心跳不采信：{e}");
                return None;
            }
        };
        if s.issued_at > (now + HEARTBEAT_FUTURE_SLACK).timestamp() {
            log::warn!("心跳不采信：签发时刻晚于本机时间超过 1 天");
            return None;
        }
        let current = self.state.version.unwrap_or(0);
        if Some(s.version) == self.state.version {
            let local = self
                .bundle
                .as_ref()
                .filter(|b| b.manifest.version == s.version)
                .map(|b| hex(&content_digest(&b.contents)));
            if local.as_deref() != Some(s.digest_hex.as_str()) {
                log::warn!("心跳不采信：第 {} 版的摘要与本机的包不同", s.version);
                return None;
            }
            if let Some(t) = DateTime::from_timestamp(s.not_after, 0) {
                self.state.fresh_until = Some(self.state.fresh_until.map_or(t, |f| f.max(t)));
            }
            self.state.newer_withheld = None;
            None
        } else {
            (s.version > current).then_some(s.version)
        }
    }

    async fn report_then_renew(&mut self) {
        let _ = self.report().await;
        self.maybe_renew().await;
    }

    /// 见到了旧令牌标记、有托管凭据、距上次换领满一小时：换领一次并回报 `fetch-token`。
    /// 新令牌先写进 state 与种子分区（[`token::save_with`]）再换上；令牌本身不进日志与回报。
    async fn maybe_renew(&mut self) {
        let now = std::time::Instant::now();
        if self.mode != Mode::Resident
            || !token::renew_due(
                self.fetcher.token_is_stale(),
                self.identity.is_some(),
                self.last_renew,
                now,
            )
        {
            return;
        }
        let Some(id) = self.identity.clone() else {
            return;
        };
        self.last_renew = Some(now);
        let lab = crate::luks::image_is_lab(&self.cfg.root);
        let result = match self.fetcher.renew_token(&id, lab).await {
            Ok(crate::fetch::RenewOutcome::New(t)) => {
                let saved = token::save_with(
                    &self.cfg.state_dir,
                    &self.cfg.seed_dir,
                    &t,
                    self.cfg.seed_requires_mount,
                );
                self.fetcher.set_token(t);
                match saved {
                    Ok(()) => passed("fetch-token", "已换成新的拉取令牌".into()),
                    Err(e) if e.downcast_ref::<token::SeedNotWritten>().is_some() => {
                        passed("fetch-token", format!("已换成新的拉取令牌；{e}"))
                    }
                    Err(e) => failed(
                        "fetch-token",
                        format!(
                            "已换成新的拉取令牌，但没存下来（重启后退回旧令牌、再换一次）：{e:#}"
                        ),
                    ),
                }
            }
            Ok(crate::fetch::RenewOutcome::Refused(m)) => failed("fetch-token", m),
            Err(e) => failed("fetch-token", format!("{e:#}")),
        };
        log::info!(
            "换领拉取令牌：{}",
            result.detail.as_deref().unwrap_or_default()
        );
        self.fetch_token = Some(result);
        let _ = self.report().await;
    }

    /// 当前令牌被 401：别的来源（state、种子分区、种子）有一把上次拉取成功以来没被拒过的令牌就换用它，
    /// 回报 `fetch-token` 失败。每把只试一次：都被拒过就停在当前这把，不来回切换（拉取成功后重新算）。
    async fn on_unauthorized(&mut self) {
        let current = self.fetcher.current_token();
        if let Some(c) = &current {
            self.rejected_tokens.insert(sha256_hex(c.as_bytes()));
        }
        let alt = token::sources(&self.cfg.state_dir, &self.cfg.seed_dir, &self.seed)
            .into_iter()
            .find(|t| !self.rejected_tokens.contains(&sha256_hex(t.as_bytes())));
        let Some(alt) = alt else {
            return;
        };
        log::warn!("拉取令牌被拒（401），换用另一处保存的令牌");
        self.fetcher.set_token(alt);
        self.fetch_token = Some(failed("fetch-token", "令牌被拒（401）".into()));
        let _ = self.report().await;
    }

    /// 拒收后这一次要等多久，并把下一次的翻倍（上限 FALLBACK_SECS）。
    fn next_reject_backoff(&mut self) -> Duration {
        let d = self.reject_backoff;
        let cap = Duration::from_secs(FALLBACK_SECS).max(self.cfg.reject_wait);
        self.reject_backoff = (d * 2).min(cap);
        d
    }

    /// How long to wait after this failed fetch (ruling 59, [`crate::backoff`]): `backoff_start`
    /// doubled per consecutive failure, capped at `backoff_max`, times a random factor in
    /// [0.8, 1.2]. Every failed fetch round takes this path — a 503, a failed connection, a timeout,
    /// and also a 401, another unexpected answer or a bundle that could not be stored (as before
    /// the jitter); a rejected bundle waits per [`Self::next_reject_backoff`] instead.
    fn next_backoff(&mut self) -> Duration {
        let d = crate::backoff::backoff(
            self.backoff_attempt,
            self.cfg.backoff_start,
            self.cfg.backoff_max,
            self.cfg.jitter.unit(),
        );
        self.backoff_attempt = self.backoff_attempt.saturating_add(1);
        d
    }
}

fn passed(item: &str, detail: String) -> ItemResult {
    ItemResult {
        item: item.into(),
        ok: true,
        detail: Some(detail),
    }
}

fn failed(item: &str, detail: String) -> ItemResult {
    ItemResult {
        item: item.into(),
        ok: false,
        detail: Some(detail),
    }
}

/// 种子分区真的挂上了才往里写（identity.json、缓存包）：挂载带 `nofail`，挂不上时挂载点只是
/// 根分区上的空目录，写进去的东西恢复出厂就丢了。
fn seed_writable(cfg: &AgentConfig) -> Result<()> {
    if cfg.seed_requires_mount && !seedpart::is_mount_point(&cfg.seed_dir)? {
        anyhow::bail!(
            "种子分区没有挂上（{} 不是挂载点），不写",
            cfg.seed_dir.display()
        );
    }
    Ok(())
}

/// 这个通知到了（没有时永远等着）。
async fn gate_opened(g: &Option<Arc<Notify>>) {
    match g {
        Some(n) => n.notified().await,
        None => std::future::pending().await,
    }
}

/// 某个人的 login 脚本跑完（阻塞线程出错时为 None）；没有在跑的时永远等着。取消安全：`join_next` 被别的分支
/// 抢先时不丢结果。
async fn login_finished(
    tasks: &mut tokio::task::JoinSet<Batch>,
    running: &mut std::collections::HashMap<tokio::task::Id, u32>,
) -> Option<Batch> {
    let Some(r) = tasks.join_next_with_id().await else {
        return std::future::pending().await;
    };
    match r {
        Ok((id, b)) => {
            running.remove(&id);
            Some(b)
        }
        Err(e) => {
            running.remove(&e.id());
            log::warn!("跑 login 脚本的线程异常退出：{e}");
            None
        }
    }
}

/// `now + d`, or far in the future when that does not fit.
fn later(d: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(d)
        .unwrap_or_else(|| now + Duration::from_secs(100 * 365 * 24 * 3600))
}

/// Reached `t` (never, without one).
async fn until_due(t: Option<Instant>) {
    match t {
        Some(t) => sleep_until(t).await,
        None => std::future::pending().await,
    }
}

/// The next event of the MQTT task; None once its channel closed. Without one, never.
/// Cancel-safe (`mpsc::Receiver::recv`).
async fn next_push(rx: &mut Option<mpsc::Receiver<PushEvent>>) -> Option<PushEvent> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// 到了 `t`（没有时永远等着）。
async fn login_due(t: Option<Instant>) {
    match t {
        Some(t) => sleep_until(t).await,
        None => std::future::pending().await,
    }
}

/// `root` 下的绝对路径 `abs`（生产 root 是 `/`）。
fn cfg_root_join(root: &Path, abs: &str) -> PathBuf {
    root.join(abs.trim_start_matches('/'))
}

/// 应用任务的下一份结果；没有应用任务（或它已退出）时永远等着。
async fn next_outcome(w: &mut Option<ApplyHandle>) -> ApplyOutcome {
    if let Some(h) = w {
        if let Some(o) = h.next_outcome().await {
            return o;
        }
    }
    std::future::pending().await
}

/// 包自称的版本号（只用于日志与拒收信息；没验过，不拿来定任何事）。
fn claimed_version(archive: &[u8]) -> u64 {
    mastersos_bundle::read_archive(archive)
        .ok()
        .and_then(|u| Manifest::parse(&u.contents.manifest_text).ok())
        .map_or(0, |m| m.version)
}

/// 这台机器眼下用的是哪一版、哪个分组。没有包时只按种子定。
fn placement_for(bundle: Option<&Bundle>, ident: &DeviceIdent, seed: &Seed) -> Placement {
    let Some(b) = bundle else {
        return seed_placement(seed);
    };
    let m = &b.manifest;
    let sel = select(m, ident, seed.group.as_deref());
    Placement {
        bundle_version: Some(m.version),
        group: sel.group.id.clone(),
        source: sel.source,
        locked: sel.lock.is_some(),
    }
}

/// 还没有包时：种子里写了分组就用它，否则 default。
fn seed_placement(seed: &Seed) -> Placement {
    match &seed.group {
        Some(g) => Placement {
            bundle_version: None,
            group: g.clone(),
            source: GroupSource::Seed,
            locked: false,
        },
        None => Placement {
            bundle_version: None,
            group: DEFAULT_GROUP.into(),
            source: GroupSource::Default,
            locked: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::rejected_reason;
    use mastersos_bundle::BundleError as E;

    /// Strings from an unverified bundle never reach the login-screen status.
    #[test]
    fn rejected_reason_drops_the_payload() {
        let evil = "Call +1 555 0100 for help";
        for e in [
            E::Parse(evil.into()),
            E::Invalid(evil.into()),
            E::UnsafePath(evil.into()),
            E::UnknownKey(evil.into()),
            E::Io(evil.into()),
        ] {
            assert!(!rejected_reason(&e).contains("555"), "{e:?}");
        }
        assert_eq!(rejected_reason(&E::BadSignature), "bad signature");
    }
}
