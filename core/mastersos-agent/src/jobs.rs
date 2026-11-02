//! 后台任务（Task 8 的恢复密钥托管、Task 9 的 Chrome sysext 等）：每个任务一个循环，启动后
//! 立即跑一次，之后每 `every()` 跑一次；主循环被叫醒（SIGUSR1，网络连上）时也提前跑一次
//! （距上一轮开始不到 [`MIN_WAKE_GAP`] 的叫醒推迟到满 [`MIN_WAKE_GAP`] 时，不丢）。结果按 `item` 写进 [`SideResults`]，主循环
//! 回报时追加在应用结果之后。任务各自管自己的状态文件，不碰 `state.json`（它只有一个写者）。
//!
//! `wake_on_new_bundle()` 的任务（Flatpak 对账，Task 16）：主循环发布了新的「本机分组」（[`JobCtx::current`]）时
//! 也立即跑一次，不受 [`MIN_WAKE_GAP`] 限制（换一份包是少见的事）。`replaces_items()` 给出前缀的任务：每一轮的结果
//! 替换掉 `SideResults` 里以这个前缀开头的旧项（清单里删掉的那一项不再一直挂在回报里）。
//!
//! `gates_first_report()` 的任务：主循环的第一份回报等它的第一轮跑完再发（有上限，见
//! `run.rs`）。恢复密钥托管要排在第一份回报之前（progress.md Carry → T8）：`device_id` 在第一次
//! 托管登记凭据之前不出现在服务端，抢注托管凭据（Task 7 的「首次信任」）的窗口就更小。

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mastersos_bundle::{Config, DeviceIdent, Group, ItemResult};
use tokio::sync::{oneshot, watch, Notify};
use tokio::task::JoinHandle;
use tokio::time::{sleep_until, Instant};
use tokio_util::sync::CancellationToken;

use crate::fetch::Fetcher;
use crate::runner::Runner;
use crate::seedpart::Identity;
use crate::system::SysPaths;

/// 叫醒离上一轮开始不到这么久就等到满这么久再跑（网络抖动时不反复托管、反复跑 cryptenroll）。
pub const MIN_WAKE_GAP: Duration = Duration::from_secs(60);

pub type SideResults = Arc<Mutex<BTreeMap<String, ItemResult>>>;

/// 这台机器眼下选中的分组（当前包的版本与它给这台机器选的分组）。
#[derive(Debug, Clone, PartialEq)]
pub struct CurrentGroup {
    pub version: u64,
    pub group: Group,
    /// The Config `group` names; the jobs read their settings from it.
    pub config: Config,
    /// The bundle's `[school].escrow_recipients` (plan 6 Task 13): the LUKS job seals the
    /// recovery key to them. Empty when the bundle names none.
    pub escrow_recipients: Vec<String>,
}

pub struct JobCtx {
    pub fetcher: Fetcher,
    pub ident: DeviceIdent,
    pub paths: SysPaths,
    pub runner: Arc<dyn Runner>,
    /// 种子分区的 `identity.json`（托管凭据）；种子分区没挂上、读不出时为 None。
    pub identity: Option<Identity>,
    /// 主循环每次接受新包（或启动时载入本地包）后发布这台机器选中的分组；还没有包时为 None。
    pub current: watch::Receiver<Option<Arc<CurrentGroup>>>,
    /// 后台任务改了应用步骤要读的状态（例如 Flatpak 装好了、Dock 要加上它）时 `notify_one`：主循环交一份应用请求。
    pub reapply: Arc<Notify>,
    /// The latest settings fetch: `Some(error)` when it failed, `None` when it succeeded (new bundle or nothing new)
    /// or none has finished yet. The status job shows it.
    pub fetch_error: watch::Receiver<Option<String>>,
}

pub trait Job: Send + Sync {
    fn name(&self) -> &'static str;
    fn every(&self) -> Duration;
    fn run<'a>(
        &'a self,
        cx: &'a JobCtx,
    ) -> Pin<Box<dyn Future<Output = Vec<ItemResult>> + Send + 'a>>;
    /// 主循环的第一份回报要等这个任务的第一轮跑完。
    fn gates_first_report(&self) -> bool {
        false
    }
    /// 为真时 `current` 变了（新包、换了分组）也立即跑一次。
    fn wake_on_new_bundle(&self) -> bool {
        false
    }
    /// 为假时主循环被叫醒（SIGUSR1：登录、网络连上）不提前跑，只按 `every()` 与（`wake_on_new_bundle` 时）新包跑。
    /// 家目录清理（Task 19）不该在登录者自己的 PAM 会话阶段里跑（复审 T19 N1）。
    fn wake_on_signal(&self) -> bool {
        true
    }
    /// 给出前缀时：每一轮的结果替换掉 `SideResults` 里以它开头的全部旧项。
    fn replaces_items(&self) -> Option<&'static str> {
        None
    }
}

/// 当前所有后台任务的结果（按 item 排序）。
pub fn snapshot(side: &SideResults) -> Vec<ItemResult> {
    side.lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .cloned()
        .collect()
}

pub struct Spawned {
    pub handles: Vec<JoinHandle<()>>,
    /// 某个任务的结果与上一轮不同时被通知（主循环据此立即回报，不等定时回报）。
    pub changed: Arc<Notify>,
    /// `gates_first_report()` 的任务各一个：第一轮跑完（结果已写进 `SideResults`）时完成。
    pub first_rounds: Vec<oneshot::Receiver<()>>,
}

/// 每个任务起一个循环，直到 `shutdown`。`wake.notify_waiters()` 让正在等下一轮的任务提前跑。
pub fn spawn_all(
    jobs: Vec<Arc<dyn Job>>,
    cx: Arc<JobCtx>,
    side: SideResults,
    shutdown: CancellationToken,
    wake: Arc<Notify>,
) -> Spawned {
    let mut first_rounds = vec![];
    let changed = Arc::new(Notify::new());
    let handles = jobs
        .into_iter()
        .map(|job| {
            let (cx, side, shutdown, wake, changed) = (
                cx.clone(),
                side.clone(),
                shutdown.clone(),
                wake.clone(),
                changed.clone(),
            );
            let mut first = job.gates_first_report().then(|| {
                let (tx, rx) = oneshot::channel();
                first_rounds.push(rx);
                tx
            });
            // 每个任务自己的接收端（`changed()` 要 &mut）；不关心新包的任务不看它。
            let mut current = job.wake_on_new_bundle().then(|| cx.current.clone());
            let signal = job.wake_on_signal();
            tokio::spawn(async move {
                loop {
                    let started = Instant::now();
                    // 这一轮之前发布的都算看过了；跑的过程中再发布的，跑完立即再跑。
                    if let Some(rx) = current.as_mut() {
                        rx.borrow_and_update();
                    }
                    let results = tokio::select! {
                        biased;
                        _ = shutdown.cancelled() => return,
                        r = job.run(&cx) => r,
                    };
                    let mut differs = false;
                    {
                        let mut g = side.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(p) = job.replaces_items() {
                            let stale: Vec<String> = g
                                .keys()
                                .filter(|k| {
                                    k.starts_with(p) && !results.iter().any(|r| &r.item == *k)
                                })
                                .cloned()
                                .collect();
                            differs |= !stale.is_empty();
                            for k in stale {
                                g.remove(&k);
                            }
                        }
                        for r in results {
                            differs |= g.get(&r.item) != Some(&r);
                            g.insert(r.item.clone(), r);
                        }
                    }
                    if differs {
                        changed.notify_one();
                    }
                    if let Some(tx) = first.take() {
                        let _ = tx.send(());
                    }
                    log::debug!("后台任务 {} 跑完一轮", job.name());
                    let mut next = started + job.every();
                    loop {
                        tokio::select! {
                            _ = shutdown.cancelled() => return,
                            _ = sleep_until(next) => break,
                            // 太早的叫醒不丢：推迟到上一轮开始后满 MIN_WAKE_GAP 再跑。
                            _ = wake.notified(), if signal => next = next.min(started + MIN_WAKE_GAP),
                            r = bundle_changed(&mut current) => match r {
                                Ok(()) => break,
                                // 主循环没了（退出中）：不再看它
                                Err(_) => current = None,
                            },
                        }
                    }
                }
            })
        })
        .collect();
    Spawned {
        handles,
        changed,
        first_rounds,
    }
}

/// 等 `current` 变化；不看它的任务永远等不到。
async fn bundle_changed(
    rx: &mut Option<watch::Receiver<Option<Arc<CurrentGroup>>>>,
) -> Result<(), watch::error::RecvError> {
    match rx {
        Some(rx) => rx.changed().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::SysPaths;
    use mastersos_bundle::Seed;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counting {
        runs: Arc<AtomicUsize>,
        gates: bool,
        delay: Duration,
    }

    impl Job for Counting {
        fn name(&self) -> &'static str {
            "counting"
        }
        fn every(&self) -> Duration {
            Duration::from_secs(3600)
        }
        fn run<'a>(
            &'a self,
            _cx: &'a JobCtx,
        ) -> Pin<Box<dyn Future<Output = Vec<ItemResult>> + Send + 'a>> {
            Box::pin(async move {
                tokio::time::sleep(self.delay).await;
                let n = self.runs.fetch_add(1, Ordering::SeqCst) + 1;
                vec![ItemResult {
                    item: "counting".into(),
                    ok: true,
                    detail: Some(n.to_string()),
                }]
            })
        }
        fn gates_first_report(&self) -> bool {
            self.gates
        }
    }

    fn cx() -> Arc<JobCtx> {
        Arc::new(JobCtx {
            fetcher: Fetcher::from_seed(&Seed {
                server_url: "http://127.0.0.1:9".into(),
                trust: vec![],
                fetch_token: None,
                group: None,
                oidc: None,
                min_version: None,
                school_id: None,
                wifi: vec![],
                school_name: None,
                it_account: None,
            }),
            ident: DeviceIdent {
                serial: None,
                device_id: "d".into(),
            },
            paths: SysPaths::default(),
            runner: Arc::new(crate::runner::FakeRunner::new()),
            identity: None,
            current: watch::channel(None).1,
            reapply: Default::default(),
            fetch_error: watch::channel(None).1,
        })
    }

    /// 第一轮跑完（结果已写进 SideResults）才放行第一份回报；不 gate 的任务不出 receiver。
    #[tokio::test(start_paused = true)]
    async fn first_round_signal_fires_after_results_are_stored() {
        let runs = Arc::new(AtomicUsize::new(0));
        let side: SideResults = Default::default();
        let shutdown = CancellationToken::new();
        let jobs: Vec<Arc<dyn Job>> = vec![
            Arc::new(Counting {
                runs: runs.clone(),
                gates: true,
                delay: Duration::from_secs(5),
            }),
            Arc::new(Counting {
                runs: Arc::new(AtomicUsize::new(0)),
                gates: false,
                delay: Duration::ZERO,
            }),
        ];
        let mut s = spawn_all(
            jobs,
            cx(),
            side.clone(),
            shutdown.clone(),
            Default::default(),
        );
        assert_eq!(s.first_rounds.len(), 1);
        let rx = s.first_rounds.pop().unwrap();
        rx.await.unwrap();
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert!(!snapshot(&side).is_empty());
        // 结果变了（第一轮）：通知主循环回报
        tokio::time::timeout(Duration::from_secs(1), s.changed.notified())
            .await
            .unwrap();
        shutdown.cancel();
        for h in s.handles {
            h.await.unwrap();
        }
    }

    /// 叫醒：离上一轮开始满 MIN_WAKE_GAP 才提前跑；太近的叫醒不算。
    #[tokio::test(start_paused = true)]
    async fn wake_runs_again_but_not_too_often() {
        let runs = Arc::new(AtomicUsize::new(0));
        let wake = Arc::new(Notify::new());
        let shutdown = CancellationToken::new();
        let job: Arc<dyn Job> = Arc::new(Counting {
            runs: runs.clone(),
            gates: false,
            delay: Duration::ZERO,
        });
        let s = spawn_all(
            vec![job],
            cx(),
            Default::default(),
            shutdown.clone(),
            wake.clone(),
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        wake.notify_waiters();
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(runs.load(Ordering::SeqCst), 1, "离上一轮不到 60 秒：先不跑");
        // 推迟到上一轮开始后满 60 秒时跑，不丢
        tokio::time::sleep(MIN_WAKE_GAP).await;
        assert_eq!(runs.load(Ordering::SeqCst), 2, "太早的叫醒推迟、不丢");
        // 满 60 秒之后的叫醒立即跑
        tokio::time::sleep(MIN_WAKE_GAP).await;
        wake.notify_waiters();
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(runs.load(Ordering::SeqCst), 3);
        // 不叫醒：一小时后照常再跑
        tokio::time::sleep(Duration::from_secs(3600)).await;
        assert_eq!(runs.load(Ordering::SeqCst), 4);
        shutdown.cancel();
        for h in s.handles {
            h.await.unwrap();
        }
    }

    /// 不听叫醒的任务（复审 T19 N1）：叫醒不提前跑，一小时后照常跑。
    struct Deaf(Arc<AtomicUsize>);

    impl Job for Deaf {
        fn name(&self) -> &'static str {
            "deaf"
        }
        fn every(&self) -> Duration {
            Duration::from_secs(3600)
        }
        fn wake_on_signal(&self) -> bool {
            false
        }
        fn run<'a>(
            &'a self,
            _cx: &'a JobCtx,
        ) -> Pin<Box<dyn Future<Output = Vec<ItemResult>> + Send + 'a>> {
            Box::pin(async move {
                self.0.fetch_add(1, Ordering::SeqCst);
                vec![]
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn deaf_job_ignores_wake() {
        let runs = Arc::new(AtomicUsize::new(0));
        let wake = Arc::new(Notify::new());
        let shutdown = CancellationToken::new();
        let s = spawn_all(
            vec![Arc::new(Deaf(runs.clone()))],
            cx(),
            Default::default(),
            shutdown.clone(),
            wake.clone(),
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        tokio::time::sleep(MIN_WAKE_GAP * 2).await;
        wake.notify_waiters();
        tokio::time::sleep(MIN_WAKE_GAP * 2).await;
        assert_eq!(runs.load(Ordering::SeqCst), 1, "叫醒不跑");
        tokio::time::sleep(Duration::from_secs(3600)).await;
        assert_eq!(runs.load(Ordering::SeqCst), 2, "到点照常跑");
        shutdown.cancel();
        for h in s.handles {
            h.await.unwrap();
        }
    }

    /// 只关心新包、每轮回报 `item` 前缀的项：第 n 轮回报 `p:<n>`，第一轮慢（等 `gate`）。
    struct Watching {
        runs: Arc<AtomicUsize>,
        gate: Arc<Notify>,
    }

    impl Job for Watching {
        fn name(&self) -> &'static str {
            "watching"
        }
        fn every(&self) -> Duration {
            Duration::from_secs(3600)
        }
        fn wake_on_new_bundle(&self) -> bool {
            true
        }
        fn replaces_items(&self) -> Option<&'static str> {
            Some("p:")
        }
        fn run<'a>(
            &'a self,
            _cx: &'a JobCtx,
        ) -> Pin<Box<dyn Future<Output = Vec<ItemResult>> + Send + 'a>> {
            Box::pin(async move {
                let n = self.runs.fetch_add(1, Ordering::SeqCst) + 1;
                if n == 1 {
                    self.gate.notified().await;
                }
                vec![ItemResult {
                    item: format!("p:{n}"),
                    ok: true,
                    detail: None,
                }]
            })
        }
    }

    /// 跑的过程中发布的新包：这一轮跑完立即再跑（不等 every）；每轮的结果替换掉同前缀的旧项，别的项不动。
    #[tokio::test(start_paused = true)]
    async fn publish_during_run_reruns_and_items_are_replaced() {
        let runs = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Notify::new());
        let (tx, rx) = watch::channel(None);
        let mut c = Arc::into_inner(cx()).unwrap();
        c.current = rx;
        let side: SideResults = Default::default();
        side.lock().unwrap().insert(
            "other".into(),
            ItemResult {
                item: "other".into(),
                ok: true,
                detail: None,
            },
        );
        let shutdown = CancellationToken::new();
        let s = spawn_all(
            vec![Arc::new(Watching {
                runs: runs.clone(),
                gate: gate.clone(),
            })],
            Arc::new(c),
            side.clone(),
            shutdown.clone(),
            Default::default(),
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(runs.load(Ordering::SeqCst), 1, "第一轮还卡着");
        let mut m =
            mastersos_bundle::Manifest::parse("version = 1\n[[group]]\nid = \"a\"\nname = \"a\"\n")
                .unwrap();
        m.groups[0].name = "x".into();
        tx.send_replace(Some(Arc::new(CurrentGroup {
            version: 2,
            group: m.groups.remove(0),
            config: mastersos_bundle::effective_config(&m, &m.configs[0]),
            escrow_recipients: vec![],
        })));
        gate.notify_one();
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(
            runs.load(Ordering::SeqCst),
            2,
            "跑的过程中来的新包：跑完立即再跑"
        );
        let items: Vec<String> = snapshot(&side).into_iter().map(|i| i.item).collect();
        assert_eq!(items, vec!["other", "p:2"], "p:1 被替换掉，other 不动");
        shutdown.cancel();
        for h in s.handles {
            h.await.unwrap();
        }
    }
}
