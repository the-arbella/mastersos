//! 步骤 `kiosk`（计划 9 设计 §4.1、§4.3）：按分组的 `apps.kiosk` 收敛这台机器上的锁定应用。
//!
//! `kiosk = true` 的 .deb 应用（deb-apps design §4.7, §4.8）合成锁定应用一起处理（[`deb_kiosk_apps`]）：账号、
//! AccountsService、删除都走同一条路；只有公开状态里 `ready` 的才上登录界面，启动的程序只取公开状态的 `exec`。
//!
//! 每个应用 `<id>` 对应：
//! - 账号 `kiosk-<id>`（uid 取自 [`KIOSK_UIDS`]，1900–1989；无口令、shell `/bin/bash`、GECOS = `name`）。家目录、
//!   清理与开会话的机制与访客共用（[`super::ephemeral`]）；
//! - [`PUBLIC_DIR`]`/<id>/`（root 0755，kiosk 账号读得到、写不了）：`launch.json`（[`Launch`]，`mastersos-kiosk run`
//!   读它）、`policies/mastersos-kiosk.json`（只有这个应用的 Chrome 策略，`pam_namespace` 把它整个换进会话里的
//!   `/etc/opt/chrome/policies/managed`；本地程序也有一份禁止一切的，终审 I1）、`icon`（图标的本机缓存）与 `accountsservice`（AccountsService
//!   记录的模板，清理每次照它恢复，见 [`ACCOUNTS_TEMPLATE`]）；
//! - [`ACCOUNTS_DIR`]`/kiosk-<id>`：`Session=mastersos-kiosk`、`SystemAccount`（`login_screen = false` 时 true，不进
//!   GDM 的用户列表）、`Icon`；
//! - `/etc/systemd/system/user@<uid>.service.d/`[`DROPIN_FILE`]：它的 user manager 停下就拉起
//!   `mastersos-ephemeral-cleanup@kiosk-<id>.service`；
//! - [`NAMESPACE_CONF`] 里的名单（全部 kiosk 账号一行）。
//!
//! 顺序：建的时候先写策略源与启动描述、再建账号与 AccountsService、最后写 `namespace.conf`；删的时候反过来——先从
//! `namespace.conf` 拿掉，再结束会话、等它的 slice 停下、`userdel`，**在本进程里**跑一次清理（[`ephemeral::cleanup`]：
//! `login` 步骤排在前面、已经把它从登录策略的名单里拿掉了，`ephemeral-cleanup` 单元不再认它），最后删 AccountsService
//! 的记录、`PUBLIC_DIR/<id>` 与 drop-in。账号的 uid 与名字记在 [`super::SysState::kiosk_accounts`]，删的时候靠它。
//!
//! 网页 / PWA 应用的策略要考试扩展的 id 与更新地址：镜像的 [`EXAM_EXT_FILE`]（裁定 R1），读不到或不合规时这些应用
//! 跳过、回报失败，本地程序不受影响。校验不过的应用（[`kiosk::check`]）同样跳过、回报失败；它已有的账号与文件原样
//! 留着（上一次的配置），不删。
//!
//! 开机快速应用（`Phase::Boot`）对每个 kiosk 账号拉起一次清理：断电时有人在锁定会话里，第一位进来的人拿到的也是新的
//! tmpfs。回报项 `kiosk:<id>`；`namespace.conf`、`daemon-reload` 等整体的错误回报在 `kiosk`。

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use mastersos_bundle::kiosk::{self, ExamExtension, KioskError, KioskLaunch};
use mastersos_bundle::{Config, ItemResult, KioskApp};
use serde::{Deserialize, Serialize};

use super::desktop::{self, Definitive};
use super::ephemeral::{
    self, account, cleanup, remove_named, reset_password, wait_slice_gone, EphemeralEnv,
    ProcMounts, SystemdProcs, CMD_TIMEOUT, KIOSK_UIDS, LINGER_DIR,
};
use super::text::keyfile_escape;
use super::{failed, public_dir, Env, Step};
use crate::apply::{is_not_found, ApplyContext, Phase};
use crate::deb_apps;
use crate::deb_apps::status::{AppState, PublicApp};
use crate::runner::{run_ok, Cmd, Runner};
use crate::safefs;

pub mod platform_ext;

/// 整体的回报项（单个应用是 `kiosk:<id>`）。
pub const ITEM: &str = "kiosk";
/// 每个应用一个目录（相对系统根）：`launch.json`、`policies/`、`icon`、`accountsservice`。
pub const PUBLIC_DIR: &str = "var/lib/mastersos-public/kiosk";
pub const LAUNCH_FILE: &str = "launch.json";
pub const POLICIES_DIR: &str = "policies";
pub const POLICY_FILE: &str = "mastersos-kiosk.json";
pub const ICON_FILE: &str = "icon";
/// `icon` 是从哪个 https 地址下载的（换了地址就重下）。
pub const ICON_URL_FILE: &str = "icon.url";
/// AccountsService 记录的模板：清理删掉 AccountsService 里按名字存的一切（上一位留下的会话选择、头像等）之后照它恢复。
pub const ACCOUNTS_TEMPLATE: &str = "accountsservice";
/// `pam_namespace` 的配置（相对系统根）。
pub const NAMESPACE_CONF: &str = "etc/security/namespace.d/mastersos-kiosk.conf";
/// 被多实例化的目录与实例目录的前缀（`namespace.conf` 的前两列）。
pub const NS_POLYDIR: &str = "/etc/opt/chrome/policies/managed";
pub const NS_INSTANCE_PREFIX: &str = "/var/lib/mastersos-kiosk-ns/";
/// AccountsService 按用户名存的记录（相对系统根）。
pub const ACCOUNTS_DIR: &str = "var/lib/AccountsService/users";
/// 会话（`/usr/share/wayland-sessions/mastersos-kiosk.desktop`，镜像里）。
pub const SESSION: &str = "mastersos-kiosk";
/// 考试扩展的 id 与更新地址（相对系统根；镜像按 lab / 正式写）。
pub const EXAM_EXT_FILE: &str = "usr/lib/mastersos/kiosk-ext.json";
/// user manager 的 drop-in 所在（相对系统根）与文件名。
pub const UNIT_DIR: &str = "etc/systemd/system";
pub const DROPIN_FILE: &str = "50-mastersos-kiosk.conf";

/// `launch.json`：`mastersos-kiosk run <id>` 怎么起这个应用（Task 6 读它）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Launch {
    pub id: String,
    pub name: String,
    pub kind: LaunchKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// The app's platform extension's start page (`chrome-extension://<platform extension id>/start.html`) that Chrome
    /// opens instead of the `url` of a web app with `platform` or `inject` (design
    /// docs/specs/2026-11-06-kiosk-platform-inject-design.md §3.3); absent for every other app.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum LaunchKind {
    Web {
        url: String,
    },
    /// `--app=<url>`，策略里另有 `WebAppInstallForceList`（裁定 R3）。
    Pwa {
        url: String,
    },
    /// Flatpak id，或 `/usr/`、`/opt/` 下的绝对路径（`/opt/` 的是 .deb 应用的扩展提供的程序）。
    Exec {
        target: String,
    },
}

/// [`super::SysState::kiosk_accounts`] 的一项：删账号时要的 uid 与名字（清理把 GECOS 恢复成它）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KioskAccountState {
    pub uid: u32,
    pub name: String,
    /// 建好之后的口令恢复（`passwd -d`、`chage`）与第一次清理都成功了。`useradd` 之后两样里有一样失败，账号的口令是
    /// 锁着的、也没有 tmpfs：false 时每轮重做，两样都成功才记 true。旧的状态文件里没有它，按 false 读（再做一次无害）。
    #[serde(default)]
    pub initialized: bool,
}

/// The program in `launch.json` of a `kiosk = true` .deb app that is not ready (deb-apps design §4.7): such an app is
/// off the login screen, and should anyone still reach its session, the program exits at once and the session ends
/// (a local program that exits ends the session). The settings' `exec` is never used: only the program the deb-apps
/// round verified as provided by the app's extension.
pub const DEB_NOT_READY_EXEC: &str = "/usr/bin/false";

/// The `kiosk = true` .deb apps of `config` as locked apps (deb-apps design §4.7), so that their accounts go through the
/// same lifecycle as `apps.kiosk`: a local program (`exec`) that is the `exec` of the public status `public` when the
/// app is `ready` there, listed on the login screen only then (otherwise [`DEB_NOT_READY_EXEC`], off the login screen,
/// the account kept). `name` and `icon` come from the settings; without an `icon` the account has the generic avatar
/// (the package's own icon is a theme name or a path inside the extension, not resolved here). Ids already in
/// `apps.kiosk` are left out (the lint refuses the clash; the locked app wins). None in a mode without the Config's
/// apps ([`desktop::Profile::flatpaks`]: the legacy browser mode, §4.1), so existing accounts are removed.
pub fn deb_kiosk_apps(
    config: &Config,
    public: &BTreeMap<String, PublicApp>,
) -> BTreeMap<String, KioskApp> {
    if !desktop::profile(config).flatpaks {
        return BTreeMap::new();
    }
    config
        .apps
        .deb
        .iter()
        .filter(|(id, app)| app.kiosk && !config.apps.kiosk.contains_key(*id))
        .map(|(id, app)| {
            let ready = public
                .get(id)
                .filter(|p| p.state == AppState::Ready)
                .and_then(|p| p.exec.clone());
            let k = KioskApp {
                name: app.name.clone(),
                icon: app.icon.clone(),
                url: None,
                pwa: false,
                allow: vec![],
                user_agent: None,
                platform: None,
                inject: None,
                device_attributes: false,
                managed_config: None,
                extensions: vec![],
                chrome_policy: toml::Table::new(),
                login_screen: ready.is_some(),
                exec: Some(ready.unwrap_or_else(|| DEB_NOT_READY_EXEC.into())),
                android: None,
                in_session: false,
            };
            (id.clone(), k)
        })
        .collect()
}

/// `apps.kiosk` and the `kiosk = true` .deb apps ([`deb_kiosk_apps`]) of `config`, with the public status the deb-apps
/// round left under `paths.public_dir` (unreadable: no .deb app is ready). A `ready` app whose program is not there
/// counts as not ready: after an image upgrade the old extension is no longer merged (`SYSEXT_LEVEL`) while the status
/// still says ready until the next round, and the login screen must not offer a session that ends at once. So does one
/// whose program is not a regular file owned by the owner of the system root (root on a device) or is writable by its
/// group or others: the session would run whatever someone put there.
fn wanted_apps(config: &Config, paths: &super::SysPaths) -> BTreeMap<String, KioskApp> {
    let mut public =
        deb_apps::status::read_public(&paths.public_dir.join(deb_apps::status::PUBLIC_NAME));
    for p in public.values_mut() {
        let present = p.exec.as_deref().is_some_and(|e| {
            e.starts_with('/')
                && trusted_program(&paths.root, &paths.root.join(e.trim_start_matches('/')))
        });
        if !present {
            p.exec = None;
        }
    }
    let mut apps = config.apps.kiosk.clone();
    apps.extend(deb_kiosk_apps(config, &public));
    apps
}

/// `path` (links followed) is a regular file owned by `root`'s owner and not writable by group or others.
fn trusted_program(root: &Path, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let (Ok(owner), Ok(m)) = (std::fs::metadata(root), std::fs::metadata(path)) else {
        return false;
    };
    m.is_file() && m.uid() == owner.uid() && m.mode() & 0o022 == 0
}

pub fn step() -> Step {
    Step {
        name: "kiosk",
        fast: true,
        run,
        without_bundle: None,
    }
}

/// 应用的启动描述（`launch.json`）。
pub fn launch_of(id: &str, app: &KioskApp) -> Result<Launch, KioskError> {
    let kind = match kiosk::launch(app)? {
        KioskLaunch::Web { url, pwa: false } => LaunchKind::Web { url: url.into() },
        KioskLaunch::Web { url, pwa: true } => LaunchKind::Pwa { url: url.into() },
        KioskLaunch::Exec(target) => LaunchKind::Exec {
            target: target.into(),
        },
    };
    Ok(Launch {
        id: id.into(),
        name: app.name.clone(),
        kind,
        user_agent: app.user_agent.clone(),
        start: None,
    })
}

/// `id` 的 uid：记着的就沿用；没有就取 [`KIOSK_UIDS`] 里最小的、没记在别的应用名下、`getent passwd` 也查不到的。
/// 全占满了是 `None`。
pub fn uid_for(
    runner: &dyn Runner,
    state: &BTreeMap<String, KioskAccountState>,
    id: &str,
) -> Result<Option<u32>> {
    if let Some(s) = state.get(id) {
        return Ok(Some(s.uid));
    }
    let taken: BTreeSet<u32> = state.values().map(|s| s.uid).collect();
    for uid in KIOSK_UIDS {
        if !taken.contains(&uid) && !uid_in_use(runner, uid)? {
            return Ok(Some(uid));
        }
    }
    Ok(None)
}

/// `getent passwd <uid>`：退出 0 是有人用着，2 是没有；别的退出码是错误（不猜）。
fn uid_in_use(runner: &dyn Runner, uid: u32) -> Result<bool> {
    let out =
        runner.run(&Cmd::new("getent", &["passwd", &uid.to_string()]).timeout(CMD_TIMEOUT))?;
    match out.code {
        0 => Ok(true),
        2 => Ok(false),
        c => bail!("getent passwd {uid} exited with code {c}"),
    }
}

/// AccountsService 的记录（GKeyFile）。GDM 显示的名字取自 GECOS，`RealName` 照设计 §4.1 一并写上；`Icon` 是图标缓存的
/// 绝对路径，没有图标就不写（GDM 用默认头像）。
pub fn render_accounts(app: &KioskApp, icon: Option<&str>) -> String {
    let mut s = format!(
        "[User]\nRealName={}\nSession={SESSION}\n",
        keyfile_escape(&app.name)
    );
    if let Some(i) = icon {
        s.push_str(&format!("Icon={}\n", keyfile_escape(i)));
    }
    s.push_str(&format!("SystemAccount={}\n", !app.login_screen));
    s
}

/// `user@<uid>.service` 的 drop-in：user manager 停下（会话都结束了）就清理。
pub fn render_dropin(user: &str) -> String {
    let unit = format!("mastersos-ephemeral-cleanup@{user}.service");
    format!(
        "# Generated by mastersos-agent (kiosk app {user}); do not edit.\n\
         [Unit]\nOnSuccess={unit}\nOnFailure={unit}\n"
    )
}

/// `pam_namespace` 的配置：`users`（按名字排好）的会话里，`/etc/opt/chrome/policies/managed` 整个换成它自己的实例
/// （镜像的 `namespace.init` 往里拷 `PUBLIC_DIR/<id>/policies/`）。
pub fn render_namespace(users: &[String]) -> String {
    format!(
        "# Generated by mastersos-agent (kiosk apps); do not edit.\n\
         {NS_POLYDIR}  {NS_INSTANCE_PREFIX}  user  ~{}\n",
        users.join(",")
    )
}

/// 读镜像里的考试扩展（裁定 R1）并校验；不行就是给回报用的原因。
fn load_exam(root: &Path) -> Result<ExamExtension, String> {
    let why = |w: String| {
        format!("/{EXAM_EXT_FILE} in the image {w}: web and PWA locked apps need the exam extension force-installed; skipping this item")
    };
    let p = Path::new(EXAM_EXT_FILE);
    let (Some(dir), Some(name)) = (p.parent(), p.file_name().and_then(|n| n.to_str())) else {
        return Err(why("is not a normalized path".into()));
    };
    let bytes = safefs::open_dir(root, dir, false)
        .and_then(|d| safefs::read_at(&d, name))
        .map_err(|e| why(format!("cannot be read ({e:#})")))?
        .ok_or_else(|| why("does not exist".into()))?;
    let ext: ExamExtension =
        serde_json::from_slice(&bytes).map_err(|e| why(format!("cannot be parsed ({e})")))?;
    ext.check().map_err(why)?;
    Ok(ext)
}

/// 校验过的一个应用：启动描述与 Chrome 策略（本地程序没有），以及 `platform` / `inject` 的平台扩展。
struct Planned {
    launch: Launch,
    policy: serde_json::Map<String, serde_json::Value>,
    platform: Option<platform_ext::Prepared>,
}

/// 应用的全部规则（[`kiosk::check`]）与考试扩展；不行就是原因。考试扩展只在有网页 / PWA 应用时读一次。
fn plan(
    ctx: &ApplyContext,
    paths: &super::SysPaths,
    id: &str,
    app: &KioskApp,
    exam: &mut Option<Result<ExamExtension, String>>,
) -> Result<Planned, String> {
    let root = paths.root.as_path();
    kiosk::check(id, app).map_err(|e| e.message)?;
    let mut launch = launch_of(id, app).map_err(|e| e.message)?;
    let mut platform = None;
    // 本地程序也有一份禁止一切的策略（终审 I1：程序里的链接会起 Chrome），但用不到考试扩展：不读 kiosk-ext.json，
    // 镜像里没有它时本地程序照样建（传进去的占位 id 不合规，不会与 extensions 里的撞上）
    let policy = match launch.kind {
        LaunchKind::Exec { .. } => {
            let none = ExamExtension {
                id: String::new(),
                update_url: String::new(),
            };
            kiosk::chrome_policy(app, &none, None).map_err(|e| e.message)?
        }
        LaunchKind::Web { .. } | LaunchKind::Pwa { .. } => {
            let ext = exam
                .get_or_insert_with(|| load_exam(root))
                .as_ref()
                .map_err(Clone::clone)?;
            // platform / inject: the start page, the disguise and the script go into the app's platform extension,
            // built here (design §3.4); a bad or missing script skips the app like any other failed check
            if kiosk::uses_start_page(app) {
                let p = platform_ext::prepare(ctx.bundle_dir, &paths.var_dir, id, app, &ext.id)
                    .map_err(|e| format!("{e:#}"))?;
                launch.start = Some(platform_ext::start_url(&p.ext.id));
                platform = Some(p);
            }
            let p = platform.as_ref().map(|p: &platform_ext::Prepared| &p.ext);
            kiosk::chrome_policy(app, ext, p).map_err(|e| e.message)?
        }
    };
    Ok(Planned {
        launch,
        policy,
        platform,
    })
}

/// 一轮里图标下载的共享状态（同 `desktop`）：截止时刻与换一轮也不会好的失败。
struct Icons<'a> {
    deadline: Instant,
    failed: &'a mut BTreeSet<String>,
}

/// 一轮里各个应用共用的东西。
struct Round<'a> {
    base: OwnedFd,
    icons: Icons<'a>,
    exam: Option<Result<ExamExtension, String>>,
    units_changed: bool,
    /// 要拉起的清理单元（去重；daemon-reload 之后才拉起）。
    kicks: BTreeSet<String>,
    /// 其中拉起成功就算建好了的：单元 → 应用 id（[`KioskAccountState::initialized`]）。
    init: BTreeMap<String, String>,
}

fn run(ctx: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
    let mut out = Vec::new();
    let mut errs: Vec<String> = Vec::new();
    let base = match kiosk_base(env) {
        Ok(b) => b,
        Err(e) => return vec![failed(ITEM, format!("open /{PUBLIC_DIR}: {e:#}"))],
    };
    let apps = &wanted_apps(ctx.config, env.paths);
    let mut icon_failed = std::mem::take(&mut env.sys.kiosk_icon_failures);
    let mut round = Round {
        base,
        icons: Icons {
            deadline: Instant::now() + desktop::icon_budget(),
            failed: &mut icon_failed,
        },
        exam: None,
        units_changed: false,
        kicks: BTreeSet::new(),
        init: BTreeMap::new(),
    };

    // 1. 清单里的应用：策略源与启动描述 → AccountsService 与账号
    for (id, app) in apps {
        let item = format!("kiosk:{id}");
        let planned = match plan(ctx, env.paths, id, app, &mut round.exam) {
            Ok(p) => p,
            Err(why) => {
                let why = if env.sys.kiosk_accounts.contains_key(id) {
                    format!("{why}; the previous account and configuration are left as they were")
                } else {
                    why
                };
                out.push(failed(&item, why));
                continue;
            }
        };
        match ensure(ctx, env, &mut round, id, app, &planned) {
            Ok(detail) => out.push(ItemResult {
                item,
                ok: true,
                detail,
            }),
            Err(e) => out.push(failed(&item, format!("{e:#}"))),
        }
    }

    // 2. namespace.conf：建的时候最后写、删的时候最先写（下面的删除之前）
    let users: Vec<String> = env
        .sys
        .kiosk_accounts
        .keys()
        .filter(|id| apps.contains_key(*id))
        .map(|id| kiosk::account_name(id))
        .collect();
    if let Err(e) = write_namespace(&env.paths.root, &users) {
        errs.push(format!("/{NAMESPACE_CONF}: {e:#}"));
    }

    // 3. 清单里没有了的：结束会话、userdel、清理，再删文件；删完才从状态里去掉
    let gone: Vec<(String, KioskAccountState)> = env
        .sys
        .kiosk_accounts
        .iter()
        .filter(|(id, _)| !apps.contains_key(*id))
        .map(|(id, s)| (id.clone(), s.clone()))
        .collect();
    for (id, st) in gone {
        match remove(env, &mut round, &id, &st) {
            Ok(()) => {
                env.sys.kiosk_accounts.remove(&id);
            }
            Err(e) => out.push(failed(
                &format!("kiosk:{id}"),
                format!(
                    "delete locked app account {}: {e:#}",
                    kiosk::account_name(&id)
                ),
            )),
        }
    }
    // 状态这一轮没读出来时不扫：不在状态里的不等于不是我们的
    if env.sys.load_failed {
        log::warn!("system-state.json could not be read this round; not cleaning up kiosk directories and drop-ins missing from the state");
    } else if let Err(e) = sweep(env, &mut round) {
        errs.push(format!("clean up unused directories and drop-ins: {e:#}"));
    }

    // 4. drop-in 变了（或上次没 reload 成功）才 daemon-reload；之后才拉起清理
    if round.units_changed {
        env.sys.kiosk_reload_pending = true;
    }
    if env.sys.kiosk_reload_pending {
        match run_ok(
            env.runner,
            Cmd::new("systemctl", &["daemon-reload"]).timeout(CMD_TIMEOUT),
        ) {
            Ok(_) => env.sys.kiosk_reload_pending = false,
            Err(e) => errs.push(format!("systemctl daemon-reload: {e:#}")),
        }
    }
    // 开机：断电时可能有人在锁定会话里，每个账号都清理一次（第一位进来的人拿到新的 tmpfs）
    if ctx.phase == Phase::Boot {
        for id in env
            .sys
            .kiosk_accounts
            .keys()
            .filter(|id| apps.contains_key(*id))
        {
            round.kicks.insert(format!(
                "mastersos-ephemeral-cleanup@{}.service",
                kiosk::account_name(id)
            ));
        }
    }
    for unit in &round.kicks {
        // --no-block：开机快速应用（mastersos-agent-local）里也跑这一步，清理单元排在它之后
        match run_ok(
            env.runner,
            Cmd::new("systemctl", &["start", "--no-block", unit]).timeout(CMD_TIMEOUT),
        ) {
            Ok(_) => {
                if let Some(k) = round
                    .init
                    .get(unit)
                    .and_then(|id| env.sys.kiosk_accounts.get_mut(id))
                {
                    k.initialized = true;
                }
            }
            Err(e) => errs.push(format!("start {unit}: {e:#}")),
        }
    }

    // 图标下载失败的记录只留清单里还用着的地址
    let used: BTreeSet<&str> = apps.values().filter_map(|a| a.icon.as_deref()).collect();
    icon_failed.retain(|u| used.contains(u.as_str()));
    env.sys.kiosk_icon_failures = icon_failed;

    if !errs.is_empty() {
        out.push(failed(ITEM, errs.join("; ")));
    }
    out
}

/// `PUBLIC_DIR`（root 0755；`public_dir` 也强制 0755）。
fn kiosk_base(env: &Env) -> Result<OwnedFd> {
    let pubd = public_dir(env.paths)?;
    sub_dir(&pubd, "kiosk")
}

/// `dir` 里的子目录 `name`（必要时建出，不跟随链接），强制 0755。
fn sub_dir(dir: &OwnedFd, name: &str) -> Result<OwnedFd> {
    let d = safefs::open_dir_at(dir, Path::new(name), true)?;
    safefs::set_mode(&d, 0o755)?;
    Ok(d)
}

/// 建或更新一个应用。返回回报的 `detail`（图标用不上时写明）。
fn ensure(
    ctx: &ApplyContext,
    env: &mut Env,
    round: &mut Round,
    id: &str,
    app: &KioskApp,
    planned: &Planned,
) -> Result<Option<String>> {
    let r = env.runner;
    let user = kiosk::account_name(id);
    let existing = account(r, &user)?;
    let uid = match existing {
        Some((u, _)) if !KIOSK_UIDS.contains(&u) => bail!(
            "the existing {user} account has uid {u}, not in {}-{}; leaving it alone",
            KIOSK_UIDS.start(),
            KIOSK_UIDS.end()
        ),
        Some((u, _)) => u,
        None => uid_for(r, &env.sys.kiosk_accounts, id)?.ok_or_else(|| {
            anyhow!(
                "all uids in {}-{} are taken",
                KIOSK_UIDS.start(),
                KIOSK_UIDS.end()
            )
        })?,
    };

    // 策略源与启动描述；平台扩展在它们之前（策略与起始页都指着它）
    let dir = sub_dir(&round.base, id)?;
    match &planned.platform {
        Some(p) => platform_ext::place(&dir, p).context("write the platform extension")?,
        None => platform_ext::unplace(&dir).context("remove the platform extension")?,
    }
    safefs::write_at(
        &dir,
        LAUNCH_FILE,
        &serde_json::to_vec_pretty(&planned.launch)?,
        0o644,
    )
    .context("write launch.json")?;
    // 每种应用都有（终审 I1）：namespace.init 把它拷进会话的托管策略目录
    let pd = sub_dir(&dir, POLICIES_DIR)?;
    safefs::write_at(
        &pd,
        POLICY_FILE,
        &serde_json::to_vec_pretty(&planned.policy)?,
        0o644,
    )
    .context("write the Chrome policy")?;
    let (has_icon, detail) = place_icon(ctx, &dir, app, &mut round.icons);

    // AccountsService 的记录与模板（先于 useradd：accounts-daemon 看到新账号时就读得到）、drop-in
    let icon = has_icon.then(|| format!("/{PUBLIC_DIR}/{id}/{ICON_FILE}"));
    let keyfile = render_accounts(app, icon.as_deref());
    safefs::write_at(&dir, ACCOUNTS_TEMPLATE, keyfile.as_bytes(), 0o644)
        .context("write the AccountsService record template")?;
    let users = safefs::open_dir(&env.paths.root, Path::new(ACCOUNTS_DIR), true)?;
    safefs::write_at(&users, &user, keyfile.as_bytes(), 0o600)
        .with_context(|| format!("write /{ACCOUNTS_DIR}/{user}"))?;
    round.units_changed |= write_dropin(&env.paths.root, uid, &user)?;

    // 账号
    let acct = ephemeral::kiosk(id, uid, &app.name);
    let known = env.sys.kiosk_accounts.get(id).cloned();
    match existing {
        None => {
            // 先记下：useradd 失败或之后的步骤失败，下一轮仍知道这个 uid 归它、删的时候也找得到
            env.sys.kiosk_accounts.insert(
                id.to_string(),
                KioskAccountState {
                    uid,
                    name: app.name.clone(),
                    initialized: false,
                },
            );
            let uid_s = uid.to_string();
            run_ok(
                r,
                Cmd::new(
                    "useradd",
                    &[
                        "--uid",
                        &uid_s,
                        "--user-group",
                        "--no-create-home",
                        "--home-dir",
                        &acct.home.to_string_lossy(),
                        "--shell",
                        "/bin/bash",
                        "--comment",
                        &app.name,
                        &user,
                    ],
                )
                .timeout(CMD_TIMEOUT),
            )?;
        }
        Some(_)
            if known
                .as_ref()
                .is_none_or(|k| k.uid != uid || k.name != app.name) =>
        {
            // 改了名字，或状态里没有它（状态丢过）：GECOS 改成现在的名字，清理每次照它恢复。状态丢过的账号不知道建好
            // 没有，按没建好再做一次
            run_ok(
                r,
                Cmd::new("usermod", &["-c", &app.name, &user]).timeout(CMD_TIMEOUT),
            )?;
            env.sys.kiosk_accounts.insert(
                id.to_string(),
                KioskAccountState {
                    uid,
                    name: app.name.clone(),
                    initialized: known.is_some_and(|k| k.uid == uid && k.initialized),
                },
            );
        }
        Some(_) => {}
    }
    let initialized = env
        .sys
        .kiosk_accounts
        .get(id)
        .is_some_and(|k| k.initialized);
    if !initialized {
        // 口令清空（useradd 建的是锁着的 `!`）、第一份 tmpfs 由清理备好（登录策略的名单在 login 步骤里已写上它，单元
        // 认得）。拉起成功才在 run() 里记 initialized
        reset_password(r, &acct)?;
        let unit = acct.cleanup_unit();
        round.kicks.insert(unit.clone());
        round.init.insert(unit, id.to_string());
    }
    Ok(detail)
}

/// 放好图标缓存 `icon`：返回有没有图标，以及用不上时给回报的话。用不上时删掉旧的缓存（用通用的头像）。
fn place_icon(
    ctx: &ApplyContext,
    dir: &OwnedFd,
    app: &KioskApp,
    icons: &mut Icons,
) -> (bool, Option<String>) {
    match try_icon(ctx, dir, app, icons) {
        Ok(has) => (has, None),
        Err(why) => {
            let _ = safefs::remove_at(dir, ICON_FILE);
            let _ = safefs::remove_at(dir, ICON_URL_FILE);
            (false, Some(format!("{why}; using the generic avatar")))
        }
    }
}

fn try_icon(
    ctx: &ApplyContext,
    dir: &OwnedFd,
    app: &KioskApp,
    icons: &mut Icons,
) -> Result<bool, String> {
    let fs_err = |e: anyhow::Error| format!("write icon: {e:#}");
    let Some(src) = app.icon.as_deref() else {
        safefs::remove_at(dir, ICON_FILE).map_err(fs_err)?;
        safefs::remove_at(dir, ICON_URL_FILE).map_err(fs_err)?;
        return Ok(false);
    };
    if src.starts_with("files/") {
        let bytes = desktop::read_bundle_file(ctx.bundle_dir, src)
            .map_err(|e| format!("cannot read icon {src} from the bundle: {e:#}"))?;
        if let Some(p) = desktop::icon_problem(&bytes) {
            return Err(p);
        }
        safefs::write_at(dir, ICON_FILE, &bytes, 0o644).map_err(fs_err)?;
        safefs::remove_at(dir, ICON_URL_FILE).map_err(fs_err)?;
        return Ok(true);
    }
    if !src.starts_with("https://") {
        return Err(format!(
            "icon {src} is neither in the bundle nor an https link"
        ));
    }
    let cached = safefs::read_at(dir, ICON_URL_FILE).ok().flatten();
    if cached.as_deref() == Some(src.as_bytes())
        && matches!(safefs::open_file_at(dir, ICON_FILE), Ok(Some(_)))
    {
        return Ok(true);
    }
    if ctx.phase != Phase::Full {
        return Err("icon not downloaded yet (the quick apply at boot does not download)".into());
    }
    if icons.failed.contains(src) {
        return Err(
            "icon download failed last time; will retry when the icon address changes".into(),
        );
    }
    if ctx.superseded.load(std::sync::atomic::Ordering::SeqCst) {
        return Err("a newer apply request is pending; not downloading icons this round".into());
    }
    let left = icons.deadline.saturating_duration_since(Instant::now());
    if left < Duration::from_secs(1) {
        return Err(
            "icon download time for this round is used up; will download next round".into(),
        );
    }
    match desktop::download_icon(src, left) {
        Err(e) => {
            if e.downcast_ref::<Definitive>().is_some() {
                icons.failed.insert(src.to_string());
            }
            Err(format!("icon download failed: {e:#}"))
        }
        Ok(bytes) => {
            if let Some(p) = desktop::icon_problem(&bytes) {
                icons.failed.insert(src.to_string());
                return Err(p);
            }
            safefs::write_at(dir, ICON_FILE, &bytes, 0o644).map_err(fs_err)?;
            safefs::write_at(dir, ICON_URL_FILE, src.as_bytes(), 0o644).map_err(fs_err)?;
            Ok(true)
        }
    }
}

/// `user@<uid>.service.d/50-mastersos-kiosk.conf`；内容变了返回 `true`。
fn write_dropin(root: &Path, uid: u32, user: &str) -> Result<bool> {
    let units = safefs::open_dir(root, Path::new(UNIT_DIR), true)?;
    let d = sub_dir(&units, &format!("user@{uid}.service.d"))?;
    safefs::write_at(&d, DROPIN_FILE, render_dropin(user).as_bytes(), 0o644)
        .with_context(|| format!("write user@{uid}.service.d/{DROPIN_FILE}"))
}

/// 删掉 `user@<uid>.service.d` 里我们的 drop-in（目录空了一并删）；原来有它返回 `true`。
fn remove_dropin(root: &Path, uid: u32) -> Result<bool> {
    let units = match safefs::open_dir(root, Path::new(UNIT_DIR), false) {
        Ok(d) => d,
        Err(e) if is_not_found(&e) => return Ok(false),
        Err(e) => return Err(e),
    };
    let name = format!("user@{uid}.service.d");
    let Some(d) = safefs::open_child_dir(&units, &name)? else {
        return Ok(false);
    };
    let had = safefs::open_file_at(&d, DROPIN_FILE)?.is_some();
    safefs::remove_at(&d, DROPIN_FILE)?;
    if safefs::list_at(&d)?.is_empty() {
        safefs::remove_tree_at(&units, &name)?;
    }
    Ok(had)
}

/// 写 [`NAMESPACE_CONF`]；名单为空时删掉。
fn write_namespace(root: &Path, users: &[String]) -> Result<()> {
    let p = Path::new(NAMESPACE_CONF);
    let (Some(dir), Some(name)) = (p.parent(), p.file_name().and_then(|n| n.to_str())) else {
        bail!("not a normalized path");
    };
    if users.is_empty() {
        return match safefs::open_dir(root, dir, false) {
            Ok(d) => safefs::remove_at(&d, name),
            Err(e) if is_not_found(&e) => Ok(()),
            Err(e) => Err(e),
        };
    }
    let d = safefs::open_dir(root, dir, true)?;
    safefs::write_at(&d, name, render_namespace(users).as_bytes(), 0o644)?;
    Ok(())
}

/// 删掉清单里没有了的应用 `id`（账号 `kiosk-<id>`、uid 与名字取自状态）。顺序见模块文档：会话结束、slice 停下之后才
/// userdel 与清理，清理在本进程里跑（登录策略已经没有它，`ephemeral-cleanup` 单元不认）。
fn remove(env: &mut Env, round: &mut Round, id: &str, st: &KioskAccountState) -> Result<()> {
    let r = env.runner;
    let user = kiosk::account_name(id);
    let acct = ephemeral::kiosk(id, st.uid, &st.name);
    let procs = SystemdProcs {
        runner: r,
        timeout: CMD_TIMEOUT,
    };
    let eenv = EphemeralEnv {
        runner: r,
        procs: &procs,
        root: &env.paths.root,
        uid: acct.uid,
        mounts: &ProcMounts,
        acct: &acct,
    };
    // linger 文件 userdel 不删，留着 user manager 就停不下（同访客，复审 I2）
    remove_named(&eenv, LINGER_DIR, &user)?;
    // 没登录时 terminate-user 退出码非 0：不算错，下面等 slice 停下才是判据
    let _ = r.run(&Cmd::new("loginctl", &["terminate-user", &user]).timeout(CMD_TIMEOUT));
    wait_slice_gone(&eenv)?;
    match account(r, &user)? {
        Some((u, _)) if u != st.uid => {
            bail!(
                "the {user} account has uid {u}, not the recorded {}; not deleting it",
                st.uid
            )
        }
        Some(_) => {
            run_ok(r, Cmd::new("userdel", &[&user]).timeout(CMD_TIMEOUT))?;
        }
        None => {}
    }
    // 账号已不在：清理只卸掉家目录、清 /tmp 等处属于这个 uid 的东西、删按名字留下的与标记，不挂、不写标记
    cleanup(&eenv).context("cleanup")?;
    remove_named(&eenv, ACCOUNTS_DIR, &user)?;
    safefs::remove_tree_at(&round.base, id)?;
    round.units_changed |= remove_dropin(&env.paths.root, st.uid)?;
    platform_ext::remove_keys_except(&env.paths.var_dir, &|k| k != id)?;
    Ok(())
}

/// 不在状态里的 `PUBLIC_DIR/<id>` 与 1900–1989 的 drop-in（状态丢过、或写到一半失败）：删掉。
fn sweep(env: &mut Env, round: &mut Round) -> Result<()> {
    let keep: &BTreeMap<String, KioskAccountState> = &env.sys.kiosk_accounts;
    for name in safefs::list_at(&round.base)? {
        if !keep.contains_key(&name) {
            safefs::remove_tree_at(&round.base, &name)?;
        }
    }
    platform_ext::remove_keys_except(&env.paths.var_dir, &|k| keep.contains_key(k))?;
    let uids: BTreeSet<u32> = keep.values().map(|s| s.uid).collect();
    let units = match safefs::open_dir(&env.paths.root, Path::new(UNIT_DIR), false) {
        Ok(d) => d,
        Err(e) if is_not_found(&e) => return Ok(()),
        Err(e) => return Err(e),
    };
    for name in safefs::list_at(&units)? {
        let Some(uid) = name
            .strip_prefix("user@")
            .and_then(|s| s.strip_suffix(".service.d"))
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if KIOSK_UIDS.contains(&uid) && !uids.contains(&uid) {
            round.units_changed |= remove_dropin(&env.paths.root, uid)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
