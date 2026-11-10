//! `SystemApplier`：真正改系统的那一层。由一串步骤（[`Step`]）组成，按顺序跑：
//!
//! - 每一步返回自己的结果；失败只是一条失败的结果，其余步骤照跑。不靠 `catch_unwind`
//!   （`panic = "abort"`）：步骤自己不得 panic，进程因 bug 退出由 `Restart=on-failure` 拉起。
//! - `Phase::Boot`（`apply-local`，在 GDM 之前）只跑 `fast` 的步骤。
//! - 每一步之前看 `superseded`：应用任务收到了更新的请求就停下，由应用任务从第一步重来
//!   （Ruling 17；4b 的 `lock` 永远排第一，挂失锁定最多等一个步骤）。`quiet` (the exam quiet started) stops it the same way.
//! - 步骤之间共享的持久状态是 [`SysState`]，每次应用读写各一次；后台任务的状态各存各的文件。
//!
//! 写系统文件一律经 [`crate::safefs`]；每个写入的目录都列在 [`WRITE_ROOTS`] 里，
//! 其中 `/etc` 下的由测试与镜像的 `/etc` 策略表交叉核对。

pub mod admins;
pub mod banner;
pub mod branding;
pub mod chrome_policy;
pub mod desktop;
pub mod ephemeral;
pub mod exec_block;
pub mod flatpak;
pub mod guest;
pub mod home_tidy;
pub mod it_account;
pub mod kiosk;
pub mod locale;
pub mod lock;
pub mod login;
pub mod printing;
pub mod text;
pub mod update_channel;
pub mod wifi;

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::Result;
use mastersos_bundle::{ItemResult, Seed};
use serde::{Deserialize, Serialize};

use crate::apply::{Applier, ApplyContext, Phase};
use crate::runner::Runner;
use crate::safefs;

/// `SystemApplier` 会写入的每个目录。4b 各任务往这里追加。
pub const WRITE_ROOTS: &[&str] = &[
    "/etc/sysupdate.d",
    "/etc/authd/oidc/broker.conf.d",
    // the broker's domain file (login.rs DOMAINS_FILE)
    "/etc/authd/oidc",
    "/etc/authd/brokers.d",
    "/etc/sudoers.d",
    "/etc/polkit-1/rules.d",
    "/var/lib/mastersos-system",
    "/var/lib/mastersos-public",
    "/etc/dconf/db/mastersos.d",
    "/etc/dconf/db/mastersos.d/locks",
    "/etc/opt/chrome/policies/managed",
    "/var/lib/mastersos-public/xdg",
    "/etc/NetworkManager/system-connections",
    "/etc/netplan",
    // Wi-Fi `tls` private keys: one root 0700 directory per connection, outside NetworkManager's
    // settings so no user can read them over D-Bus.
    "/etc/mastersos/wifi",
    "/etc/sane.d/airscan.d",
    "/etc/dconf/db/gdm.d",
    "/var/lib/mastersos-public/login-scripts",
    // School name, logo and domains for the login screen and quick settings (branding.json, logo.png, logo-icon.png).
    "/var/lib/mastersos-public/branding",
    // 锁定应用（计划 9 Task 5）：启动描述与策略源、AccountsService 的记录、pam_namespace 的配置、user@<uid> 的 drop-in
    "/var/lib/mastersos-public/kiosk",
    "/var/lib/AccountsService/users",
    "/etc/security/namespace.d",
    "/etc/systemd/system",
];

const SYS_STATE: &str = "system-state.json";

#[derive(Debug, Clone)]
pub struct SysPaths {
    /// 系统根；测试里指向临时目录。
    pub root: PathBuf,
    /// `SystemApplier` 自己的状态（0700）。
    pub var_dir: PathBuf,
    /// 用户会话要读到的东西（xdg 覆盖、导出的 login 脚本），root 0755；不放秘密。
    pub public_dir: PathBuf,
    /// agent 的状态目录。
    pub state_dir: PathBuf,
}

impl Default for SysPaths {
    fn default() -> Self {
        SysPaths {
            root: "/".into(),
            var_dir: "/var/lib/mastersos-system".into(),
            public_dir: "/var/lib/mastersos-public".into(),
            state_dir: "/var/lib/mastersos".into(),
        }
    }
}

/// 存在 `<var_dir>/system-state.json`（0600），只由 `SystemApplier` 读写。后续任务各自加
/// `#[serde(default)]` 字段。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysState {
    /// `/etc/sysupdate.d/` 里有我们写的通道覆盖。
    #[serde(default)]
    pub channel_override: bool,
    /// broker 配置变了而 authd 还没重启成功（`login` 步骤下一轮内容没变也再重启）。
    #[serde(default)]
    pub broker_restart_pending: bool,
    /// dconf 的 keyfile 变了而 `dconf update` 还没成功（`desktop` 步骤下一轮内容没变也再编译）。
    #[serde(default)]
    pub dconf_update_pending: bool,
    /// 下载失败过的网页应用图标地址（`desktop` 步骤）；网页应用清单变了（`key` 对不上）就清掉重试。
    #[serde(default)]
    pub icon_failures: IconFailures,
    /// `wifi` 步骤写下的连接文件名（`mastersos-*.nmconnection`，只记文件名，不记 SSID 或 PSK）。
    #[serde(default)]
    pub wifi: std::collections::BTreeSet<String>,
    /// `wifi` 步骤写过的连接的 UUID（累积）：清单里去掉的网络被 NM 搬进 netplan 时，凭它找到 `90-NM-<uuid>.yaml` 删掉。
    /// 一个不在清单里的 UUID 只在确认 netplan 里已没有它的 yaml 之后才去掉；删不掉或目录读不了就一直记着、每轮再试。
    #[serde(default)]
    pub wifi_uuids: std::collections::BTreeSet<String>,
    /// 连接文件变了而 `nmcli connection reload` 还没成功（`wifi` 步骤下一轮内容没变也再 reload）。
    #[serde(default)]
    pub wifi_reload_pending: bool,
    /// `printers` 步骤的队列：队列名（打印机名称整理后，见 `checks::printer_queue`）→ 设备 URI。**归属只看这里**：只删、只改这里
    /// 记着的队列，本机已有的同名队列不动。每台在跑 `lpadmin -p` 之前先记下（`lpadmin` 带 `-E` 时队列在取打印机能力之前就建了，
    /// 失败或超时会留下半个队列）；失败也留着，下一轮重试，清单里去掉了就删。
    #[serde(default)]
    pub printers: std::collections::BTreeMap<String, String>,
    /// `scanners` 步骤上次写进 `airscan.d/mastersos.conf` 的扫描仪：名称 → URI。清单里某一项改坏了，照这里保留它原来那一行。
    #[serde(default)]
    pub scanners: std::collections::BTreeMap<String, String>,
    /// 生效中的 Chrome 更新时段（`HH:MM-HH:MM`）与暂停日期（`YYYY-MM-DD`）：`chrome_update` 步骤写，
    /// `mastersos-agent chrome` 用 [`SysState::peek`] 读（它可能在 agent 之前跑，不读设置包）。
    #[serde(default)]
    pub chrome_window: Option<String>,
    #[serde(default)]
    pub chrome_pause_until: Option<String>,
    /// `kiosk` 步骤建过的锁定应用账号：id → uid 与名字（[`kiosk::KioskAccountState`]）。应用从清单里删掉时凭它结束会话、
    /// 清理、删账号；在 `useradd` 之前就记下，删完才去掉。
    #[serde(default)]
    pub kiosk_accounts: std::collections::BTreeMap<String, kiosk::KioskAccountState>,
    /// kiosk 账号的 drop-in 变了而 `systemctl daemon-reload` 还没成功（`kiosk` 步骤下一轮内容没变也再 reload）。
    #[serde(default)]
    pub kiosk_reload_pending: bool,
    /// The GDM branding snippet changed and `dconf update` has not succeeded yet (the `branding` step
    /// runs it again next time even when the content is unchanged).
    #[serde(default)]
    pub branding_dconf_pending: bool,
    /// 下载失败过、换一轮也不会好的锁定应用图标地址；清单里不再用的地址去掉。
    #[serde(default)]
    pub kiosk_icon_failures: std::collections::BTreeSet<String>,
    /// The uid of the `itadmin` the `it_account` step created (recorded right after `useradd`). Only an `itadmin` with this
    /// uid is managed (and made an administrator); one with another uid was made by somebody else and is left alone.
    #[serde(default)]
    pub it_account_uid: Option<u32>,
    /// A bundle has been applied on this device (set by the `it_account` step on the bundle path, saved at once). From then
    /// on the seed path leaves the IT account, its admin entries and its login exception alone: the agent falls back to the
    /// seed when the current bundle cannot be loaded, and the install-time hash must not undo what the school changed since.
    #[serde(default)]
    pub bundle_applied: bool,
    /// 这一轮 `system-state.json` 读失败、用的是默认值（不存盘）：上面的记录可能丢了，
    /// 步骤按「可能有未完成的事」处理（例如 `login` 在 broker 配置存在时再重启一次）。
    #[serde(skip)]
    pub load_failed: bool,
}

/// 见 [`SysState::icon_failures`]。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IconFailures {
    /// 网页应用清单（序列化后）的 `slug`。
    pub key: String,
    pub urls: std::collections::BTreeSet<String>,
}

impl SysState {
    /// 不存在为默认值；解析不了也退回默认值（记日志），不挡应用。
    pub fn load(paths: &SysPaths) -> Result<SysState> {
        let dir = var_dir(paths)?;
        Ok(match safefs::read_at(&dir, SYS_STATE)? {
            None => SysState::default(),
            Some(b) => serde_json::from_slice(&b).unwrap_or_else(|e| {
                log::error!("failed to parse {SYS_STATE} ({e}); rebuilding from defaults");
                SysState::default()
            }),
        })
    }

    /// 给别的进程只读地看一眼：目录或文件不存在为 `None`（没有种子的机器），不建目录、不改权限。
    pub fn peek(paths: &SysPaths) -> Result<Option<SysState>> {
        let dir = match safefs::open_abs_dir(&paths.var_dir, false) {
            Ok(d) => d,
            Err(e) if crate::apply::is_not_found(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        match safefs::read_at(&dir, SYS_STATE)? {
            None => Ok(None),
            Some(b) => Ok(Some(serde_json::from_slice(&b)?)),
        }
    }

    pub fn save(&self, paths: &SysPaths) -> Result<()> {
        let dir = var_dir(paths)?;
        safefs::write_at(&dir, SYS_STATE, &serde_json::to_vec_pretty(self)?, 0o600)?;
        Ok(())
    }
}

/// 打开（必要时建出）`var_dir`，并收紧到 0700。
pub(crate) fn var_dir(paths: &SysPaths) -> Result<std::os::fd::OwnedFd> {
    let dir = safefs::open_abs_dir(&paths.var_dir, true)?;
    safefs::set_mode(&dir, 0o700)?;
    Ok(dir)
}

/// 打开（必要时建出）`public_dir`，并强制 0755：用户会话要读得到（Ruling 7、9），与收紧到 0700 的
/// [`var_dir`] 分开。里面只放所有用户本来就该读到的东西。
pub fn public_dir(paths: &SysPaths) -> Result<std::os::fd::OwnedFd> {
    let dir = safefs::open_abs_dir(&paths.public_dir, true)?;
    safefs::set_mode(&dir, 0o755)?;
    Ok(dir)
}

pub struct Env<'a> {
    pub paths: &'a SysPaths,
    pub runner: &'a dyn Runner,
    pub sys: &'a mut SysState,
}

pub type StepFn = fn(&ApplyContext, &mut Env) -> Vec<ItemResult>;
pub type WithoutBundleFn = fn(&Seed, &mut Env) -> Vec<ItemResult>;

/// 一个系统步骤。**每一步都必须是声明式、可重复执行的（幂等）**：被更新的请求打断的一轮
/// 会从第一步重来，定期重应用与失败重试也会把同一份设置再跑一遍；步骤要按「期望的状态」
/// 收敛，而不是「再做一次某个动作」。
pub struct Step {
    pub name: &'static str,
    /// 开机在 GDM 之前（`Phase::Boot`）也跑。
    pub fast: bool,
    pub run: StepFn,
    /// 还没有包时跑什么；`None` 表示什么都不做。
    pub without_bundle: Option<WithoutBundleFn>,
}

/// 全部步骤，按顺序。4b 往这里追加，`lock` 永远排第一。
pub fn steps() -> Vec<Step> {
    vec![
        // 第一步（Ruling 11）：先写锁定的策略、再结束会话。
        lock::step(),
        login::step(),
        // After lock and login: the school name, logo and domains for the login screen (fast: no network at boot).
        branding::step(),
        locale::timezone_step(),
        locale::locale_step(),
        guest::step(),
        // The IT maintenance account: before `admins`, which grants it sudo and polkit only once it exists and is ours.
        it_account::step(),
        // 锁定应用的账号：排在 guest 之后（设计 §4.1），在 login 之后（登录策略的名单先写好，清理单元才认得新账号）
        kiosk::step(),
        admins::step(),
        desktop::step(),
        chrome_policy::step(),
        chrome_policy::update_step(),
        update_channel::step(),
        // login 脚本导出到用户读得到的地方（Task 18）；快，开机在 GDM 之前也跑
        crate::login_queue::step(),
        // support.json for the Get help entries and the support host (fast: the login screen reads it at boot)
        crate::support::step(),
        wifi::step(),
        printing::scanners_step(),
        // 最后：每台打印机要连上它取能力，最慢。
        printing::printers_step(),
    ]
}

pub struct SystemApplier {
    paths: SysPaths,
    runner: Arc<dyn Runner>,
    steps: Vec<Step>,
}

impl SystemApplier {
    pub fn new(paths: SysPaths, runner: Arc<dyn Runner>) -> Self {
        Self::with_steps(paths, runner, steps())
    }

    /// 测试用：换一串步骤。
    pub fn with_steps(paths: SysPaths, runner: Arc<dyn Runner>, steps: Vec<Step>) -> Self {
        SystemApplier {
            paths,
            runner,
            steps,
        }
    }

    /// 读一次 `SysState`、按顺序跑 `run`（返回 `None` 的步骤跳过）、写一次。
    /// `stop` 在每一步之前看，成立就停下。
    fn run_steps(
        &self,
        phase: Phase,
        stop: &dyn Fn() -> bool,
        mut run: impl FnMut(&Step, &mut Env) -> Option<Vec<ItemResult>>,
    ) -> Vec<ItemResult> {
        let mut out = Vec::new();
        let (mut sys, loaded) = match SysState::load(&self.paths) {
            Ok(s) => (s, true),
            Err(e) => {
                out.push(failed(
                    "system:state",
                    format!("failed to read {SYS_STATE}: {e:#}"),
                ));
                (
                    SysState {
                        load_failed: true,
                        ..SysState::default()
                    },
                    false,
                )
            }
        };
        let before = sys.clone();
        for step in &self.steps {
            if phase == Phase::Boot && !step.fast {
                continue;
            }
            if stop() {
                log::info!(
                    "a newer apply request is pending; stopping before {}",
                    step.name
                );
                break;
            }
            let mut env = Env {
                paths: &self.paths,
                runner: self.runner.as_ref(),
                sys: &mut sys,
            };
            if let Some(r) = run(step, &mut env) {
                out.extend(r);
            }
        }
        // 读失败时不写：免得用默认值盖掉一份只是暂时读不到的状态。
        if loaded && sys != before {
            if let Err(e) = sys.save(&self.paths) {
                out.push(failed(
                    "system:state",
                    format!("failed to save {SYS_STATE}: {e:#}"),
                ));
            }
        }
        out
    }
}

impl Applier for SystemApplier {
    fn apply(&self, ctx: &ApplyContext) -> Vec<ItemResult> {
        // Checked between steps only. Known limit: a step already running when the quiet starts (printers, desktop
        // downloads, kiosk) checks only `superseded` inside and finishes.
        self.run_steps(
            ctx.phase,
            &|| ctx.superseded.load(Ordering::SeqCst) || ctx.quiet.load(Ordering::SeqCst),
            |step, env| Some((step.run)(ctx, env)),
        )
    }

    fn apply_without_bundle(&self, seed: &Seed, phase: Phase) -> Vec<ItemResult> {
        self.run_steps(phase, &|| false, |step, env| {
            step.without_bundle.map(|f| f(seed, env))
        })
    }
}

pub(crate) fn failed(item: &str, detail: String) -> ItemResult {
    ItemResult {
        item: item.into(),
        ok: false,
        detail: Some(detail),
    }
}

pub(crate) fn ok(item: &str) -> ItemResult {
    ItemResult {
        item: item.into(),
        ok: true,
        detail: None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::runner::{Cmd, FakeRunner};
    use mastersos_bundle::{Config, Group, Interface, Manifest, School};
    use std::collections::BTreeSet;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::atomic::AtomicBool;

    pub(crate) fn paths(root: &Path) -> SysPaths {
        SysPaths {
            root: root.to_path_buf(),
            var_dir: root.join("var/lib/mastersos-system"),
            public_dir: root.join("var/lib/mastersos-public"),
            state_dir: root.join("var/lib/mastersos"),
        }
    }

    /// A seed with nothing but a server address (no school name, no Wi-Fi).
    pub(crate) fn test_seed() -> Seed {
        Seed {
            server_url: "http://x".into(),
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

    pub(crate) fn tmp_root() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("var/lib")).unwrap();
        d
    }

    const DEFAULT_ONLY: &str = "version = 1\n[[group]]\nid = \"default\"\nname = \"d\"\n";

    /// The `default` Group of a legacy-shape text with nothing else in it.
    pub(crate) fn group() -> Group {
        Manifest::parse(DEFAULT_ONLY).unwrap().groups.remove(0)
    }

    /// That Group's implied Config: no settings, `learning` with the `legacy_browser` mark (the old
    /// default browser mode).
    pub(crate) fn config() -> Config {
        let m = Manifest::parse(DEFAULT_ONLY).unwrap();
        mastersos_bundle::effective_config(&m, &m.configs[0])
    }

    /// The kinds of session a Config can ask for: a legacy browser-mode Group, `learning`, `full`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Kind {
        LegacyBrowser,
        Learning,
        Full,
    }

    /// [`config`] set to `kind`.
    pub(crate) fn config_of(kind: Kind) -> Config {
        let mut c = config();
        c.legacy_browser = kind == Kind::LegacyBrowser;
        c.interface = match kind {
            Kind::Full => Interface::Full,
            Kind::LegacyBrowser | Kind::Learning => Interface::Learning,
        };
        c
    }

    /// 用给定的 school 与阶段造一个 ApplyContext 交给 `f`。
    pub(crate) fn with_ctx<R>(
        school: &School,
        phase: Phase,
        superseded: &AtomicBool,
        f: impl FnOnce(&ApplyContext) -> R,
    ) -> R {
        let (g, c) = (group(), config());
        let dir = tempfile::tempdir().unwrap();
        f(&ApplyContext {
            seed: &crate::system::tests::test_seed(),
            school,
            group: &g,
            config: &c,
            lock: None,
            bundle_dir: dir.path(),
            phase,
            superseded,
            quiet: &std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn call(env: &mut Env, what: &str) {
        env.runner.run(&Cmd::new(what, &[])).unwrap();
    }

    fn fast_step(_: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
        call(env, "fast");
        vec![ok("system:fast")]
    }

    fn slow_step(_: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
        call(env, "slow");
        vec![ok("system:slow")]
    }

    fn failing_step(_: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
        call(env, "failing");
        vec![failed("system:failing", "坏了".into())]
    }

    fn superseding_step(ctx: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
        call(env, "first");
        ctx.superseded.store(true, Ordering::SeqCst);
        vec![ok("system:first")]
    }

    fn step(name: &'static str, fast: bool, run: StepFn) -> Step {
        Step {
            name,
            fast,
            run,
            without_bundle: None,
        }
    }

    fn applier(root: &Path, steps: Vec<Step>) -> (SystemApplier, Arc<FakeRunner>) {
        let r = Arc::new(FakeRunner::new());
        (SystemApplier::with_steps(paths(root), r.clone(), steps), r)
    }

    #[test]
    fn boot_phase_runs_only_fast_steps() {
        let root = tmp_root();
        let (a, r) = applier(
            root.path(),
            vec![
                step("slow", false, slow_step),
                step("fast", true, fast_step),
            ],
        );
        let flag = AtomicBool::new(false);
        let out = with_ctx(&School::default(), Phase::Boot, &flag, |c| a.apply(c));
        assert_eq!(r.calls(), vec!["fast"]);
        assert_eq!(out, vec![ok("system:fast")]);
        let out = with_ctx(&School::default(), Phase::Full, &flag, |c| a.apply(c));
        assert_eq!(r.calls(), vec!["fast", "slow", "fast"]);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn failing_step_is_reported_and_others_run() {
        let root = tmp_root();
        let (a, r) = applier(
            root.path(),
            vec![
                step("failing", true, failing_step),
                step("slow", false, slow_step),
            ],
        );
        let flag = AtomicBool::new(false);
        let out = with_ctx(&School::default(), Phase::Full, &flag, |c| a.apply(c));
        assert_eq!(r.calls(), vec!["failing", "slow"]);
        assert_eq!(
            out,
            vec![failed("system:failing", "坏了".into()), ok("system:slow")]
        );
    }

    #[test]
    fn superseded_stops_between_steps() {
        let root = tmp_root();
        let (a, r) = applier(
            root.path(),
            vec![
                step("first", true, superseding_step),
                step("slow", false, slow_step),
            ],
        );
        let flag = AtomicBool::new(false);
        let out = with_ctx(&School::default(), Phase::Full, &flag, |c| a.apply(c));
        assert_eq!(r.calls(), vec!["first"], "第二步不该跑");
        assert_eq!(out, vec![ok("system:first")]);
    }

    #[test]
    fn without_bundle_runs_only_steps_that_have_it() {
        fn nb(_: &Seed, env: &mut Env) -> Vec<ItemResult> {
            call(env, "nb");
            vec![]
        }
        let root = tmp_root();
        let (a, r) = applier(
            root.path(),
            vec![
                step("slow", false, slow_step),
                Step {
                    name: "nb",
                    fast: true,
                    run: fast_step,
                    without_bundle: Some(nb),
                },
            ],
        );
        let seed = Seed {
            server_url: "http://x".into(),
            trust: vec![],
            fetch_token: None,
            group: None,
            oidc: None,
            min_version: None,
            school_id: None,
            wifi: vec![],
            school_name: None,
            it_account: None,
        };
        a.apply_without_bundle(&seed, Phase::Boot);
        assert_eq!(r.calls(), vec!["nb"]);
    }

    /// 用户会话要读的东西（xdg 覆盖、login 脚本）放 `public_dir`：它是 0755，`var_dir` 仍是 0700。
    #[test]
    fn public_dir_is_0755_and_var_dir_stays_0700() {
        let root = tmp_root();
        let p = paths(root.path());
        let mode = |q: &Path| std::fs::metadata(q).unwrap().permissions().mode() & 0o7777;
        // 不存在时建出来；已有但被收紧成 0700（或被放宽）的，强制回 0755。
        let _ = public_dir(&p).unwrap();
        assert_eq!(mode(&p.public_dir), 0o755);
        std::fs::set_permissions(&p.public_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = public_dir(&p).unwrap();
        assert_eq!(mode(&p.public_dir), 0o755);
        std::fs::set_permissions(&p.public_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let _ = public_dir(&p).unwrap();
        assert_eq!(mode(&p.public_dir), 0o755);
        // 两个目录互不影响：先后打开都不改对方的模式。
        let _ = var_dir(&p).unwrap();
        let _ = public_dir(&p).unwrap();
        assert_eq!(mode(&p.var_dir), 0o700);
        assert_eq!(mode(&p.public_dir), 0o755);
        assert_ne!(p.public_dir, p.var_dir);
        assert_eq!(
            SysPaths::default().public_dir,
            PathBuf::from("/var/lib/mastersos-public")
        );
    }

    #[test]
    fn sys_state_roundtrips_and_is_0600() {
        let root = tmp_root();
        let p = paths(root.path());
        assert_eq!(SysState::load(&p).unwrap(), SysState::default());
        let s = SysState {
            channel_override: true,
            broker_restart_pending: true,
            ..SysState::default()
        };
        s.save(&p).unwrap();
        assert_eq!(SysState::load(&p).unwrap(), s);
        let mode = |q: &Path| std::fs::metadata(q).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&p.var_dir.join(SYS_STATE)), 0o600);
        assert_eq!(mode(&p.var_dir), 0o700);
        // 损坏的文件：退回默认值，不挡应用。
        std::fs::write(p.var_dir.join(SYS_STATE), b"{garbage").unwrap();
        assert_eq!(SysState::load(&p).unwrap(), SysState::default());
    }

    /// Ruling 3：`SystemApplier` 写入的每个 /etc 目录，它自己或某个祖先在策略表里是 dir 或 copy，
    /// 而且从 /etc 到它的每一级都不是默认的 L（每一级都在表里，或在某个 copy 之下）。
    #[test]
    fn write_roots_are_covered_by_etc_policy() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../image/etc-policy.conf"
        ))
        .unwrap();
        let mut dirs = BTreeSet::new();
        let mut copies = BTreeSet::new();
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (kind, path) = line.split_once(char::is_whitespace).unwrap();
            match kind {
                "dir" => dirs.insert(path.trim().to_string()),
                "copy" => copies.insert(path.trim().to_string()),
                other => panic!("策略表里有未知的类别 {other}"),
            };
        }
        let under_copy = |p: &Path| p.ancestors().any(|a| copies.contains(a.to_str().unwrap()));
        let mut checked = 0;
        for root in WRITE_ROOTS.iter().filter(|r| r.starts_with("/etc/")) {
            let p = Path::new(root);
            let levels: Vec<&Path> = p
                .ancestors()
                .take_while(|a| *a != Path::new("/etc"))
                .collect();
            for level in levels {
                let s = level.to_str().unwrap();
                assert!(
                    dirs.contains(s) || copies.contains(s) || under_copy(level),
                    "{root}：{s} 在策略表里不是 dir 或 copy，会是指向 factory 的链接（L），写不进去"
                );
            }
            checked += 1;
        }
        assert!(checked > 0);
    }
}
