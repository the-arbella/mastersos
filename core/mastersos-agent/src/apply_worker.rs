//! 应用任务（Ruling 17）：应用在自己的 tokio 任务里跑，不挡拉取循环。
//!
//! - 主循环把「应用请求」交给它（`watch`，只保留最新一份）；`request` 同时把正在跑的那一轮的
//!   `superseded` 置位，`SystemApplier` 在步骤之间看到就停下，这一轮作废、从第一步重来。
//! - 每一轮：applier（`spawn_blocking`）→ 放文件与下载 → apply 脚本，即原来 `Agent::apply`
//!   的三段；`Phase::Boot` 与没有包时只有 applier 一段。applier 这段被作废时后两段不跑。
//! - 结果经 `mpsc` 交回主循环，由它合并进 `state.json`（仍只有一个写者）。脚本记录与托管
//!   路径以应用任务自己上一轮的结果为准，请求里带的只作第一轮的初值——免得主循环还没合并上
//!   一轮的结果时发来的新请求让脚本重跑。
//! - Exam quiet (`quiet`): a round does not start while quiet; requests that arrive meanwhile only replace the held one,
//!   and the newest is applied once the quiet ends. Quiet starting mid-round stops the applier between steps (and
//!   keeps the files and the apply scripts from starting); the same request then runs again after the quiet.
//! - 有失败项时 `RETRY_MIN_SECS` 后重跑同一份请求，之后翻倍、上限 `FALLBACK_SECS`；没有失败项时
//!   每 `REAPPLY_SECS` 也整体重应用一次（spec §4.4：下一次同步时覆盖本机改动）。

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mastersos_bundle::{select, Bundle, DeviceIdent, ItemResult, Seed};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::apply::{place, Applier, ApplyContext, Phase};
use crate::config::{AgentConfig, FALLBACK_SECS};
use crate::quiet::{wait_until_loud, QuietRx};
use crate::scripts::run_apply;
use crate::state::{self, State};

/// 有失败项时第一次重试的间隔；之后翻倍，上限 `FALLBACK_SECS`。
pub const RETRY_MIN_SECS: u64 = 60;
/// 没有失败项时也这么久整体重应用一次。
pub const REAPPLY_SECS: u64 = 6 * 3600;

#[derive(Clone)]
pub struct ApplyRequest {
    pub bundle: Option<Arc<Bundle>>,
    pub phase: Phase,
    pub managed_paths: BTreeMap<String, String>,
    pub script_hashes: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ApplyOutcome {
    pub results: Vec<ItemResult>,
    pub managed_paths: BTreeMap<String, String>,
    pub script_hashes: BTreeMap<String, String>,
    pub had_failures: bool,
}

type Tagged<T> = (u64, T);

pub struct ApplyHandle {
    tx: watch::Sender<Option<Tagged<ApplyRequest>>>,
    /// 正在跑（或刚跑完）的那一轮的作废标志。
    current: Arc<Mutex<Arc<AtomicBool>>>,
    rx: mpsc::Receiver<Tagged<ApplyOutcome>>,
    sent: AtomicU64,
    done: u64,
    /// 应用任务这一轮正在用的包目录名（`versions/<名字>`）；清理旧目录时留着它。
    pinned: Arc<Mutex<Option<String>>>,
    task: JoinHandle<()>,
}

impl ApplyHandle {
    /// 交一份新的请求（替换还没开始的那份），并让正在跑的一轮在下一个步骤之前停下。
    ///
    /// 置位与发送在同一把锁里，应用任务取请求、换新标志也在这把锁里：两者不会交错，
    /// 新请求要么被这一轮取到，要么打断这一轮。
    pub fn request(&self, r: ApplyRequest) {
        let gen = self.sent.fetch_add(1, Ordering::SeqCst) + 1;
        let g = self.current.lock().unwrap_or_else(|e| e.into_inner());
        g.store(true, Ordering::SeqCst);
        self.tx.send_replace(Some((gen, r)));
    }

    /// 删掉 `versions/` 里没人用的包目录：留下 `current` 指向的与应用任务这一轮正在用的。
    /// 只由主循环调用（包目录也只由它建），与应用任务登记「正在用」共用一把锁。
    pub fn gc(&self, state_dir: &std::path::Path) {
        let pinned = self.pinned.lock().unwrap_or_else(|e| e.into_inner());
        state::gc_keep_current(state_dir, pinned.clone());
    }

    /// 下一份结果；应用任务已退出时为 None。
    pub async fn next_outcome(&mut self) -> Option<ApplyOutcome> {
        let (gen, o) = self.rx.recv().await?;
        self.done = self.done.max(gen);
        Some(o)
    }

    /// 最近一次请求还没有结果。
    pub fn pending(&self) -> bool {
        self.done < self.sent.load(Ordering::SeqCst)
    }

    /// 退出：正在跑的一轮在下一个步骤之前停下（已经在放文件、跑脚本的照常跑完），
    /// 返回之后交回的结果，供调用方合并保存。
    pub async fn finish(mut self) -> Vec<ApplyOutcome> {
        self.current
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .store(true, Ordering::SeqCst);
        drop(self.tx);
        let mut out = Vec::new();
        while let Some((_, o)) = self.rx.recv().await {
            out.push(o);
        }
        let _ = self.task.await;
        out
    }
}

/// 起应用任务。
pub fn spawn(
    applier: Arc<dyn Applier>,
    cfg: AgentConfig,
    seed: Seed,
    ident: DeviceIdent,
    http: reqwest::Client,
    quiet: QuietRx,
) -> ApplyHandle {
    let (tx, rx) = watch::channel(None);
    let (out_tx, out_rx) = mpsc::channel(4);
    let current = Arc::new(Mutex::new(Arc::new(AtomicBool::new(false))));
    let pinned = Arc::new(Mutex::new(None));
    let w = Worker {
        applier,
        cfg,
        seed,
        ident,
        http,
        pinned: pinned.clone(),
        quiet,
    };
    let task = tokio::spawn(w.run(rx, current.clone(), out_tx));
    ApplyHandle {
        tx,
        current,
        rx: out_rx,
        sent: AtomicU64::new(0),
        done: 0,
        pinned,
        task,
    }
}

struct Worker {
    applier: Arc<dyn Applier>,
    cfg: AgentConfig,
    seed: Seed,
    ident: DeviceIdent,
    http: reqwest::Client,
    pinned: Arc<Mutex<Option<String>>>,
    /// Since when the exam quiet is on; while it is, requests are taken but not applied.
    quiet: QuietRx,
}

/// Aborts the task when dropped (the per-round quiet watcher).
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// 这一轮结束（含提前返回）时撤下「正在用」的登记。
struct Pin<'a>(&'a Mutex<Option<String>>);

impl Drop for Pin<'_> {
    fn drop(&mut self) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

type Maps = (BTreeMap<String, String>, BTreeMap<String, String>);

impl Worker {
    async fn run(
        self,
        mut rx: watch::Receiver<Option<Tagged<ApplyRequest>>>,
        current: Arc<Mutex<Arc<AtomicBool>>>,
        out: mpsc::Sender<Tagged<ApplyOutcome>>,
    ) {
        let min = Duration::from_secs(RETRY_MIN_SECS);
        let cap = Duration::from_secs(FALLBACK_SECS).max(min);
        let mut retry = min;
        // 下一次自己重跑（重试或定期重应用）之前等多久；None 表示只等新请求。
        let mut rerun: Option<Duration> = None;
        let mut last: Option<Tagged<ApplyRequest>> = None;
        let mut maps: Option<Maps> = None;
        loop {
            let fresh = match rerun {
                None => rx.changed().await.is_ok().then_some(true),
                Some(d) => tokio::select! {
                    // 新请求优先于到点的重跑：重跑的是旧请求。
                    biased;
                    r = rx.changed() => r.is_ok().then_some(true),
                    _ = tokio::time::sleep(d) => Some(false),
                },
            };
            let Some(mut fresh) = fresh else {
                return; // 主循环退出了
            };
            // Hold while quiet: newer requests replace the held one (taken below), nothing is applied.
            let mut quiet = self.quiet.clone();
            while quiet.borrow().is_some() && quiet.has_changed().is_ok() {
                tokio::select! {
                    _ = wait_until_loud(&mut quiet) => {}
                    r = rx.changed() => {
                        if r.is_err() {
                            return; // 主循环退出了
                        }
                        fresh = true;
                    }
                }
            }
            let flag = Arc::new(AtomicBool::new(false));
            {
                // 与 `request` 同一把锁：取请求与换上新标志之间不会插进一个请求。
                let mut g = current.lock().unwrap_or_else(|e| e.into_inner());
                if fresh || rx.has_changed().unwrap_or(false) {
                    last = rx.borrow_and_update().clone();
                    retry = min;
                }
                *g = flag.clone();
            }
            let Some((gen, req)) = last.clone() else {
                rerun = None;
                continue;
            };
            let init = maps
                .clone()
                .unwrap_or_else(|| (req.managed_paths.clone(), req.script_hashes.clone()));
            // Set when the quiet starts during this round; the watcher ends with the round.
            let quiet_flag = Arc::new(AtomicBool::new(false));
            let watcher = {
                let (mut q, f) = (self.quiet.clone(), quiet_flag.clone());
                AbortOnDrop(tokio::spawn(async move {
                    // A closed sender (the monitor is gone) counts as loud, as in the hold above.
                    if q.wait_for(|v| v.is_some()).await.is_ok() && q.has_changed().is_ok() {
                        f.store(true, Ordering::SeqCst);
                    }
                }))
            };
            let o = self
                .apply_once(&req, init, flag.clone(), quiet_flag.clone())
                .await;
            drop(watcher);
            let Some(o) = o else {
                if !flag.load(Ordering::SeqCst) && quiet_flag.load(Ordering::SeqCst) {
                    // Stopped by the quiet: come straight back, wait for it to end and run the same request again.
                    rerun = Some(Duration::ZERO);
                } else {
                    // 作废：新请求已在 watch 里（或主循环在退出），下一圈立即拿到。
                    rerun = None;
                }
                continue;
            };
            maps = Some((o.managed_paths.clone(), o.script_hashes.clone()));
            if o.had_failures {
                rerun = Some(retry);
                retry = (retry * 2).min(cap);
            } else {
                rerun = Some(Duration::from_secs(REAPPLY_SECS));
                retry = min;
            }
            if out.send((gen, o)).await.is_err() {
                return;
            }
        }
    }

    /// 跑一轮。applier 这段被作废时返回 None（后两段不跑）。Also None when the quiet started (`quiet`) before the files
    /// or before the apply scripts.
    async fn apply_once(
        &self,
        req: &ApplyRequest,
        (managed, hashes): Maps,
        flag: Arc<AtomicBool>,
        quiet: Arc<AtomicBool>,
    ) -> Option<ApplyOutcome> {
        let applier = self.applier.clone();
        let phase = req.phase;
        let Some(bundle) = req.bundle.clone() else {
            let seed = self.seed.clone();
            let results =
                tokio::task::spawn_blocking(move || applier.apply_without_bundle(&seed, phase))
                    .await
                    .unwrap_or_else(|e| vec![failed("applier", format!("crashed: {e}"))]);
            return Some(outcome(results, managed, hashes));
        };
        // 这一轮从头到尾只用这个包自己的目录（解好之后不再改动）；登记为正在用，主循环不会删它。
        *self.pinned.lock().unwrap_or_else(|e| e.into_inner()) = Some(state::version_name(&bundle));
        let _pin = Pin(&self.pinned);
        let bundle_dir = state::version_dir(&self.cfg.state_dir, &bundle);
        let (ident, seed) = (self.ident.clone(), self.seed.clone());
        let (b, dir, f, q) = (
            bundle.clone(),
            bundle_dir.clone(),
            flag.clone(),
            quiet.clone(),
        );
        let mut results = tokio::task::spawn_blocking(move || {
            let m = &b.manifest;
            let sel = select(m, &ident, seed.group.as_deref());
            applier.apply(&ApplyContext {
                seed: &seed,
                school: &m.school,
                group: sel.group,
                config: &sel.config,
                lock: sel.lock,
                bundle_dir: &dir,
                phase,
                superseded: &f,
                quiet: &q,
            })
        })
        .await
        .unwrap_or_else(|e| vec![failed("applier", format!("crashed: {e}"))]);
        if flag.load(Ordering::SeqCst) || quiet.load(Ordering::SeqCst) {
            return None;
        }
        if phase == Phase::Boot {
            return Some(outcome(results, managed, hashes));
        }

        let config = select(&bundle.manifest, &self.ident, self.seed.group.as_deref())
            .config
            .clone();
        let mut st = State {
            managed_paths: managed,
            script_hashes: hashes,
            ..State::default()
        };
        results.extend(place(&config, &bundle_dir, &self.cfg.root, &mut st, &self.http).await);
        // 脚本那段异常退出时（panic = "abort" 下实际不会发生）沿用放文件之后的记录。
        let (managed, hashes) = (st.managed_paths.clone(), st.script_hashes.clone());
        if quiet.load(Ordering::SeqCst) {
            return None;
        }
        let work = match state::run_dir(&self.cfg.state_dir) {
            Ok(w) => w,
            Err(e) => {
                results.push(failed(
                    "scripts",
                    format!("failed to prepare the execution directory: {e:#}"),
                ));
                return Some(outcome(results, managed, hashes));
            }
        };
        match tokio::task::spawn_blocking(move || {
            let r = run_apply(&config, &bundle_dir, &work, &mut st);
            (st, r)
        })
        .await
        {
            Ok((st, r)) => {
                results.extend(r);
                Some(outcome(results, st.managed_paths, st.script_hashes))
            }
            Err(e) => {
                results.push(failed("scripts", format!("crashed: {e}")));
                Some(outcome(results, managed, hashes))
            }
        }
    }
}

fn outcome(
    results: Vec<ItemResult>,
    managed_paths: BTreeMap<String, String>,
    script_hashes: BTreeMap<String, String>,
) -> ApplyOutcome {
    ApplyOutcome {
        had_failures: results.iter().any(|r| !r.ok),
        results,
        managed_paths,
        script_hashes,
    }
}

fn failed(item: &str, detail: String) -> ItemResult {
    ItemResult {
        item: item.into(),
        ok: false,
        detail: Some(detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::{Cmd, FakeRunner, Output};
    use crate::system::{Env, Step, SysPaths, SystemApplier};
    use mastersos_bundle::{accept, pack, Contents, Ed25519Signer};
    use tokio::time::{timeout, Instant};

    fn bundle() -> Arc<Bundle> {
        bundle_with("")
    }

    /// 同 [`bundle`]，清单末尾再接上 `extra`（例如一条 `[[device]]`）。
    fn bundle_with(extra: &str) -> Arc<Bundle> {
        let s = Ed25519Signer::from_pkcs8("k1", &Ed25519Signer::generate_pkcs8()).unwrap();
        let k = s.trust_key();
        let manifest_text = format!(
            "version = 1\n\n[[trust]]\nid = \"{}\"\nalg = \"ed25519\"\npublic_key = \"{}\"\n\n[[group]]\nid = \"default\"\nname = \"x\"\n{extra}",
            k.id, k.public_key
        );
        let c = Contents {
            manifest_text,
            files: Default::default(),
        };
        Arc::new(accept(&pack(&c, &s).unwrap(), &[k], None).unwrap())
    }

    fn seed() -> Seed {
        Seed {
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
        }
    }

    fn req() -> ApplyRequest {
        ApplyRequest {
            bundle: Some(bundle()),
            phase: Phase::Full,
            managed_paths: BTreeMap::new(),
            script_hashes: BTreeMap::new(),
        }
    }

    fn call(env: &mut Env, what: &str) {
        env.runner.run(&Cmd::new(what, &[])).unwrap();
    }

    fn slow_first(_: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
        call(env, "first");
        std::thread::sleep(Duration::from_millis(200));
        vec![]
    }

    fn second(_: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
        call(env, "second");
        vec![]
    }

    fn fails(_: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
        call(env, "try");
        vec![failed("system:x", "坏了".into())]
    }

    fn step(name: &'static str, run: crate::system::StepFn) -> Step {
        Step {
            name,
            fast: true,
            run,
            without_bundle: None,
        }
    }

    fn worker(steps: Vec<Step>) -> (ApplyHandle, Arc<FakeRunner>, tempfile::TempDir) {
        worker_quiet(steps, watch::channel(None).1)
    }

    /// Same as [`worker`], with the given quiet receiver.
    fn worker_quiet(
        steps: Vec<Step>,
        quiet: QuietRx,
    ) -> (ApplyHandle, Arc<FakeRunner>, tempfile::TempDir) {
        let d = tempfile::tempdir().unwrap();
        let runner = Arc::new(FakeRunner::new());
        let paths = SysPaths {
            root: d.path().join("root"),
            var_dir: d.path().join("var"),
            public_dir: d.path().join("public"),
            state_dir: d.path().join("state"),
        };
        let cfg = AgentConfig {
            state_dir: d.path().join("state"),
            root: d.path().join("root"),
            ..AgentConfig::default()
        };
        let applier = Arc::new(SystemApplier::with_steps(paths, runner.clone(), steps));
        let ident = DeviceIdent {
            serial: None,
            device_id: "dev".into(),
        };
        let h = spawn(applier, cfg, seed(), ident, reqwest::Client::new(), quiet);
        (h, runner, d)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn newer_request_preempts_running_apply() {
        let (mut h, r, _d) = worker(vec![step("first", slow_first), step("second", second)]);
        h.request(req());
        // 等第一轮进了第一步（它要睡 200 ms），再交一份新的。
        let t0 = Instant::now();
        while r.calls().is_empty() {
            assert!(t0.elapsed() < Duration::from_secs(5), "第一轮没开始");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        h.request(req());
        assert!(h.pending());
        let o = timeout(Duration::from_secs(5), h.next_outcome())
            .await
            .unwrap()
            .unwrap();
        assert!(!o.had_failures, "{:?}", o.results);
        assert_eq!(
            r.calls(),
            vec!["first", "first", "second"],
            "第一轮停在第一步之后，第二轮从头跑完"
        );
        assert!(!h.pending());
        // 作废的那一轮不交结果。
        assert!(timeout(Duration::from_millis(300), h.next_outcome())
            .await
            .is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn failures_are_retried_with_backoff() {
        let (mut h, r, _d) = worker(vec![step("fails", fails)]);
        h.request(req());
        let o = h.next_outcome().await.unwrap();
        assert!(o.had_failures);
        let mut t = Instant::now();
        for want in [RETRY_MIN_SECS, RETRY_MIN_SECS * 2, RETRY_MIN_SECS * 4] {
            let o = h.next_outcome().await.unwrap();
            assert!(o.had_failures);
            let gap = t.elapsed();
            assert!(
                gap >= Duration::from_secs(want) && gap < Duration::from_secs(want + 1),
                "期望约 {want} 秒后重试，实际 {gap:?}"
            );
            t = Instant::now();
        }
        assert_eq!(r.calls().len(), 4);
        // 新请求把退避复位，并立即跑。
        h.request(req());
        h.next_outcome().await.unwrap();
        assert!(t.elapsed() < Duration::from_secs(1));
        let o = h.next_outcome().await.unwrap();
        assert!(o.had_failures);
        let gap = t.elapsed();
        assert!(
            gap >= Duration::from_secs(RETRY_MIN_SECS)
                && gap < Duration::from_secs(RETRY_MIN_SECS + 1),
            "{gap:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn success_is_reapplied_periodically() {
        let (mut h, r, _d) = worker(vec![step("second", second)]);
        h.request(req());
        assert!(!h.next_outcome().await.unwrap().had_failures);
        let t = Instant::now();
        h.next_outcome().await.unwrap();
        let gap = t.elapsed();
        assert!(
            gap >= Duration::from_secs(REAPPLY_SECS) && gap < Duration::from_secs(REAPPLY_SECS + 1),
            "{gap:?}"
        );
        assert_eq!(r.calls(), vec!["second", "second"]);
        assert!(h.finish().await.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn maps_from_previous_round_win_over_stale_request() {
        // 主循环还没合并上一轮的结果就发来新请求（带旧的空记录）：用应用任务自己的。
        let (mut h, _r, _d) = worker(vec![]);
        let mut first = req();
        first
            .script_hashes
            .insert("scripts/a.sh".into(), "h1".into());
        h.request(first);
        let o = h.next_outcome().await.unwrap();
        assert_eq!(
            o.script_hashes.get("scripts/a.sh").map(String::as_str),
            Some("h1")
        );
        h.request(req());
        let o = h.next_outcome().await.unwrap();
        assert_eq!(
            o.script_hashes.get("scripts/a.sh").map(String::as_str),
            Some("h1")
        );
    }

    /// Task 16（Ruling 13）：Flatpak 装一个大应用（这里睡 15 秒）期间，应用任务收到把这台机器挂失的新包 → 真正的 `lock`
    /// 步骤（Task 17）在 5 秒内写好锁定的策略、结束学生的会话。只有一个工作线程：Flatpak 任务若在它上面同步等命令，
    /// 应用任务根本排不上（测试本身跑在 block_on 的线程上）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn slow_install_does_not_block_apply() {
        use crate::jobs::{spawn_all, CurrentGroup, JobCtx};
        use crate::system::flatpak::FlatpakJob;
        let fp = Arc::new(FakeRunner::new());
        // The install must clearly outlast the apply even on a loaded machine; the bounds below are a third of it.
        fp.delay("systemd-run", Duration::from_secs(15));
        let d = tempfile::tempdir().unwrap();
        let b = bundle();
        let m = &b.manifest;
        let mut config = m.effective_of_group(&m.groups[0].id).unwrap();
        config.interface = mastersos_bundle::Interface::Full;
        config.apps.flatpak = vec!["org.libreoffice.LibreOffice".into()];
        let (_tx, rx) = watch::channel(Some(Arc::new(CurrentGroup {
            version: 1,
            group: m.groups[0].clone(),
            config,
            escrow_recipients: vec![],
        })));
        let cx = Arc::new(JobCtx {
            fetcher: crate::fetch::Fetcher::from_seed(&seed()),
            ident: DeviceIdent {
                serial: None,
                device_id: "dev".into(),
            },
            paths: SysPaths {
                root: d.path().join("root"),
                var_dir: d.path().join("var"),
                public_dir: d.path().join("public"),
                state_dir: d.path().join("state"),
            },
            runner: fp.clone(),
            identity: None,
            current: rx,
            reapply: Default::default(),
            fetch_error: watch::channel(None).1,
            quiet: watch::channel(None).1,
        });
        let shutdown = tokio_util::sync::CancellationToken::new();
        let jobs = spawn_all(
            vec![Arc::new(FlatpakJob::new(fp.clone()))],
            cx,
            Default::default(),
            shutdown.clone(),
            Default::default(),
        );
        // 等到正在装：在本线程上同步地看（不靠运行时的计时器——工作线程被占住时计时器也不走）
        let t0 = std::time::Instant::now();
        while !fp.calls().iter().any(|c| c.contains("flatpak install")) {
            assert!(t0.elapsed() < Duration::from_secs(10), "没开始装");
            std::thread::sleep(Duration::from_millis(5));
        }
        let (mut h, r, d2) = worker(vec![crate::system::lock::step()]);
        // 真正的步骤要往系统根（横幅）与 var_dir（策略）里写
        std::fs::create_dir_all(d2.path().join("root")).unwrap();
        r.respond(
            "loginctl list-users --no-legend --json=short",
            Output::ok(
                r#"[{"uid":10001,"user":"student@school.ac.th","linger":false,"state":"active"}]"#,
            ),
        );
        let t1 = std::time::Instant::now();
        h.request(ApplyRequest {
            bundle: Some(bundle_with(
                "\n[[device]]\ndevice_id = \"dev\"\ngroup = \"default\"\nlocked = { message = \"lost\" }\n",
            )),
            ..req()
        });
        let o = timeout(Duration::from_secs(5), h.next_outcome())
            .await
            .expect("装 Flatpak 挡住了应用")
            .unwrap();
        assert!(t1.elapsed() < Duration::from_secs(5), "{:?}", t1.elapsed());
        assert!(
            t0.elapsed() < Duration::from_secs(15),
            "装完了才应用：{:?}",
            t0.elapsed()
        );
        assert!(!o.had_failures, "{:?}", o.results);
        assert!(
            o.results.contains(&crate::system::ok("lock")),
            "{:?}",
            o.results
        );
        assert!(
            r.calls()
                .contains(&"loginctl terminate-user 10001".to_string()),
            "{:?}",
            r.calls()
        );
        let pol: crate::system::login::LoginPolicy = serde_json::from_slice(
            &std::fs::read(d2.path().join("var/login/policy.json")).unwrap(),
        )
        .unwrap();
        assert!(pol.locked);
        shutdown.cancel();
        for h in jobs.handles {
            h.await.unwrap();
        }
    }

    fn quiet_now() -> Option<chrono::DateTime<chrono::Utc>> {
        Some(chrono::Utc::now())
    }

    /// A request taken while quiet is held (nothing runs), then applied once the quiet ends.
    #[tokio::test(start_paused = true)]
    async fn held_while_quiet_then_applied() {
        let (qtx, qrx) = watch::channel(quiet_now());
        let (mut h, r, _d) = worker_quiet(vec![step("second", second)], qrx);
        h.request(req());
        assert!(
            timeout(Duration::from_secs(10), h.next_outcome())
                .await
                .is_err(),
            "applied while quiet"
        );
        assert!(r.calls().is_empty(), "{:?}", r.calls());
        assert!(h.pending());
        qtx.send_replace(None);
        let o = h.next_outcome().await.unwrap();
        assert!(!o.had_failures, "{:?}", o.results);
        assert_eq!(r.calls(), vec!["second"]);
        assert!(!h.pending());
    }

    /// Two requests while quiet: only the newest is applied after the quiet ends.
    #[tokio::test(start_paused = true)]
    async fn newest_request_wins_after_quiet() {
        let (qtx, qrx) = watch::channel(quiet_now());
        let (mut h, r, _d) = worker_quiet(vec![step("second", second)], qrx);
        for v in ["5", "6"] {
            let mut x = req();
            x.script_hashes.insert("version".into(), v.into());
            h.request(x);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        assert!(r.calls().is_empty(), "{:?}", r.calls());
        qtx.send_replace(None);
        let o = h.next_outcome().await.unwrap();
        assert_eq!(
            o.script_hashes.get("version").map(String::as_str),
            Some("6")
        );
        assert!(!h.pending());
        // No outcome for version 5 (the next one would be the periodic reapply).
        assert!(timeout(Duration::from_secs(60), h.next_outcome())
            .await
            .is_err());
        assert_eq!(r.calls(), vec!["second"]);
    }

    /// The quiet sender for [`quiet_on_once`] (only `quiet_mid_round_stops_and_reruns` uses it).
    static MID_QUIET: Mutex<Option<watch::Sender<Option<chrono::DateTime<chrono::Utc>>>>> =
        Mutex::new(None);
    static MID_QUIET_DONE: AtomicBool = AtomicBool::new(false);

    fn one(_: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
        call(env, "one");
        vec![]
    }

    /// Turns the quiet on the first time it runs, and gives the worker time to notice.
    fn quiet_on_once(_: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
        call(env, "two");
        if !MID_QUIET_DONE.swap(true, Ordering::SeqCst) {
            if let Some(tx) = MID_QUIET.lock().unwrap().as_ref() {
                tx.send_replace(quiet_now());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        vec![]
    }

    fn three(_: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
        call(env, "three");
        vec![]
    }

    /// Quiet starting in the middle of a round stops it before the next step; after the quiet the same request is
    /// applied again from the first step.
    #[tokio::test(flavor = "multi_thread")]
    async fn quiet_mid_round_stops_and_reruns() {
        let (qtx, qrx) = watch::channel(None);
        *MID_QUIET.lock().unwrap() = Some(qtx.clone());
        let (mut h, r, _d) = worker_quiet(
            vec![
                step("one", one),
                step("two", quiet_on_once),
                step("three", three),
            ],
            qrx,
        );
        h.request(req());
        let t0 = Instant::now();
        while qtx.borrow().is_none() {
            assert!(
                t0.elapsed() < Duration::from_secs(5),
                "step two did not run"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            timeout(Duration::from_secs(2), h.next_outcome())
                .await
                .is_err(),
            "a round finished while quiet"
        );
        assert_eq!(r.calls(), vec!["one", "two"], "step three ran while quiet");
        qtx.send_replace(None);
        let o = timeout(Duration::from_secs(5), h.next_outcome())
            .await
            .unwrap()
            .unwrap();
        assert!(!o.had_failures, "{:?}", o.results);
        assert_eq!(r.calls(), vec!["one", "two", "one", "two", "three"]);
        *MID_QUIET.lock().unwrap() = None;
    }
}
