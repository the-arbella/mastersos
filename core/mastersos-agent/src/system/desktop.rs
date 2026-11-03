//! The desktop: the session of each mode and the web app launchers (Ruling 7, 8; spec §6.5;
//! config profiles design §4). What each mode does is one row of [`Profile`]: a locked session
//! (`learning`, and a legacy `mode = "browser"` Group) or the full desktop (`full`).
//!
//! - **dconf**：`/etc/dconf/db/mastersos.d/50-mastersos` 与 `locks/50-mastersos`（profile `user` 是
//!   `user-db:user` + `system-db:mastersos`，镜像里）。内容变了（或上次 `dconf update` 没成功）才跑 `dconf update`。
//! - **网页应用**：`google-chrome-stable --app=<url>` 的 `.desktop`（Ruling 8），写在 [`XDG_DIR`]`/applications/`
//!   （`/var/lib/mastersos-public` 下、root 0755，用户会话读得到；镜像的 `40-mastersos.conf` 把它排在 `XDG_DATA_DIRS`
//!   最前面）。每一项先过 [`checks::web_app`]，不合格的跳过、回报 `webapp:<name>` 失败。图标见 [`icon_source`]：
//!   https 的只在 `Phase::Full` 下载（开机快速应用只用已缓存的），下载失败或格式不对用通用的 `web-browser`，
//!   回报成功但 `detail` 写明。清单里没有了的启动器与图标删掉。
//! - **锁住的会话**：`/usr/share/applications` 与系统 Flatpak 导出目录里看得见的 `.desktop`（不是 `NoDisplay`/
//!   `Hidden` 的），除了 Chrome、网页应用与（`learning` 下）配置里装好的 Flatpak 导出的，都在
//!   [`XDG_DIR`]`/applications/` 写一个同名的 `Hidden=true` 覆盖；
//!   文件管理器与设置的 D-Bus 激活覆盖成 `/bin/false`（[`DBUS_OVERRIDES`]）。这些只管搜索、Dock 与被别的程序拉起：
//!   `~/.local/share`（`XDG_DATA_HOME`）永远排在 `XDG_DATA_DIRS` 前面，学生自己写的 `.desktop` 能盖过它们，所以
//!   终端、文件管理器、设置另由 [`super::exec_block`] 在执行层堵住。`full` 删掉全部覆盖、卸掉桩。
//! - **锁住的会话的 dconf** 除了 Dock、运行对话框、终端快捷键、用户管理，还关掉 Ubuntu 的桌面图标扩展（DING）、
//!   藏起 Dock 的回收站与外接盘（都是通往文件管理器的路，VM 上实测）。文件选择框（上传、另存为）不能跟着
//!   Nautilus 一起没了：GNOME 50 的 xdg-desktop-portal-gnome 把它交给 Nautilus，镜像里的
//!   `/usr/share/xdg-desktop-portal/ubuntu-portals.conf` 把 FileChooser 改走 xdg-desktop-portal-gtk。
//! - **锁定应用**（计划 9 Task 6）：`in_session = true` 的，在 [`XDG_DIR`]`/applications/` 写
//!   `mastersos-kiosk-<id>.desktop`（执行 `mastersos-kiosk enter <id>`：确认后结束当前会话，回到登录界面点这个应用）并
//!   排进 Dock（每种模式都是，在网页应用之后）。只给 kiosk 步骤（排在前面）建好了的应用写——有它的 `launch.json`；
//!   图标用 kiosk 步骤缓存的那份。锁住的会话的 `Hidden=true` 覆盖不盖它、切模式删覆盖时也不碰它。
//! - **Flatpak**（`learning` 与 `full`；旧的浏览器模式没有）：Dock 里加上配置里已由
//!   [`super::flatpak::FlatpakJob`] 装好的应用；装卸由那个后台任务做，它改了状态会叫主循环再应用一次。
//! - 回报项 `desktop`（dconf、覆盖、执行层堵法的错误汇总在这一项）与每个网页应用的 `webapp:<name>`。

use std::collections::BTreeSet;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use mastersos_bundle::{checks, kiosk, Config, Interface, ItemResult, WebApp};

use super::text::{desktop_exec_arg, keyfile_escape, slug};
use super::{exec_block, failed, ok, public_dir, Env, IconFailures, Step, SysPaths, SysState};
use crate::apply::{is_not_found, ApplyContext, Phase};
use crate::runner::{run_ok, Cmd, Runner};
use crate::safefs;

/// 回报项的名字。
pub const ITEM: &str = "desktop";
/// 用户会话读的覆盖目录（root 0755；`public_dir` 下的 `xdg`）。
pub const XDG_DIR: &str = "/var/lib/mastersos-public/xdg";
const XDG_SUB: &str = "xdg";
/// kiosk 步骤的目录（`public_dir` 下的 `kiosk`，即 [`super::kiosk::PUBLIC_DIR`]）。
const KIOSK_SUB: &str = "kiosk";
/// Chrome 的 desktop id（Chrome 的 sysext 带的）与 Chrome 本体。
pub const CHROME_DESKTOP: &str = "google-chrome.desktop";
pub const CHROME_BIN: &str = "/usr/bin/google-chrome-stable";
/// `full` 的 Dock 里另有文件管理器。
pub const NAUTILUS_DESKTOP: &str = "org.gnome.Nautilus.desktop";
/// 网页应用的启动器与图标的文件名前缀（后面是 `slug`）。
pub const WEB_PREFIX: &str = "mastersos-web-";
/// 通用图标（图标主题里的名字）。
pub const GENERIC_ICON: &str = "web-browser";
/// 锁定应用的启动器的文件名前缀（后面是 id）、执行的程序、没有图标缓存时的图标。
pub const KIOSK_PREFIX: &str = "mastersos-kiosk-";
pub const KIOSK_BIN: &str = "/usr/bin/mastersos-kiosk";
pub const KIOSK_GENERIC_ICON: &str = "application-x-executable";
/// https 图标的大小上限。
pub const MAX_ICON_BYTES: usize = 512 * 1024;
/// 下载图标时的 User-Agent。
const ICON_USER_AGENT: &str = concat!("mastersos-agent/", env!("CARGO_PKG_VERSION"));
/// 一轮应用里所有图标下载合计的时限（复审 T13 发现 6）：超了的下一轮再下，不让一串慢的图标站点把应用任务拖住。
const ICON_BUDGET: Duration = Duration::from_secs(60);

// 测试用：非 0 时代替 [`ICON_BUDGET`]（毫秒）；按线程设，并行的测试互不影响。
#[cfg(test)]
thread_local! {
    pub(crate) static TEST_ICON_BUDGET_MS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

pub(crate) fn icon_budget() -> Duration {
    #[cfg(test)]
    {
        let ms = TEST_ICON_BUDGET_MS.with(|c| c.get());
        if ms > 0 {
            return Duration::from_millis(ms);
        }
    }
    ICON_BUDGET
}

/// 一轮里图标下载的共享状态：截止时刻与下载失败过的地址（存在 `SysState::icon_failures`）。
struct Downloads<'a> {
    deadline: std::time::Instant,
    failed: &'a mut BTreeSet<String>,
}

/// dconf 的 keyfile 目录与 locks 目录（相对系统根）、我们的文件名。
pub const DCONF_DIR: &str = "etc/dconf/db/mastersos.d";
pub const DCONF_LOCKS_DIR: &str = "etc/dconf/db/mastersos.d/locks";
pub const DCONF_FILE: &str = "50-mastersos";

/// 锁住的会话要藏的 `.desktop` 从这些目录里找（相对系统根）：镜像自带的与系统 Flatpak 导出的。
pub const SYSTEM_APPS_DIR: &str = "usr/share/applications";
pub const FLATPAK_APPS_DIR: &str = "var/lib/flatpak/exports/share/applications";
pub const APP_DIRS: &[&str] = &[SYSTEM_APPS_DIR, FLATPAK_APPS_DIR];

/// The visible `.desktop` ids of [`APP_DIRS`], by where they were found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VisibleApps {
    /// In [`SYSTEM_APPS_DIR`] (the image's own).
    pub system: BTreeSet<String>,
    /// In [`FLATPAK_APPS_DIR`] (exported by system Flatpaks).
    pub flatpak: BTreeSet<String>,
}

/// 锁住的会话里覆盖成 `/bin/false` 的 D-Bus 激活（文件名；总线名是去掉 `.service` 的部分）。Chrome 的「在文件夹中
/// 显示」走 `org.freedesktop.FileManager1`，快捷设置里的齿轮走 `org.gnome.Settings`（Ruling 7）。
pub const DBUS_OVERRIDES: &[&str] = &[
    "org.gnome.Nautilus.service",
    "org.freedesktop.FileManager1.service",
    "org.gnome.Settings.service",
];

/// Ubuntu 会话自带的桌面图标扩展（DING）。它自己就是个小文件管理器（在 `~/Desktop` 上建、删、改名文件，
/// 「在终端中打开」），还不停地经 D-Bus 拉 Nautilus（VM 上实测）：锁住的会话里关掉。
pub const DING_EXTENSION: &str = "ding@rastersoft.com";

/// Ubuntu 会话（`/usr/share/gnome-shell/modes/ubuntu.json`）自带的扩展里锁住的会话照开的那些（去掉 DING）。锁住的会话
/// 把 `enabled-extensions` 锁成它、`disable-user-extensions` 锁成 true：学生放进 `~/.local/share/gnome-shell/extensions`
/// 的扩展不加载（复审 T13 发现 5）。
pub const LOCKED_EXTENSIONS: &[&str] = &[
    "ubuntu-dock@ubuntu.com",
    "ubuntu-appindicators@ubuntu.com",
    "tiling-assistant@ubuntu.com",
    "snapd-prompting@canonical.com",
    "snapd-search-provider@canonical.com",
    "web-search-provider@ubuntu.com",
    // The image's own quick-settings "managed by" line. Under the lock it is loaded through the session mode
    // (image/mkosi.postinst.chroot adds it to ubuntu.json); listed here so the locked list stays the full set.
    MANAGED_EXTENSION,
];

/// The image's quick-settings extension showing "This device is managed by <school>".
pub const MANAGED_EXTENSION: &str = "mastersos-managed@mastersos.org";

/// 锁住的会话（学习模式、旧的浏览器模式）锁住的键。
const LOCKED_KEYS: &[&str] = &[
    "/org/gnome/shell/favorite-apps",
    "/org/gnome/desktop/lockdown/disable-command-line",
    "/org/gnome/desktop/lockdown/user-administration-disabled",
    "/org/gnome/settings-daemon/plugins/media-keys/terminal",
    "/org/gnome/shell/disabled-extensions",
    "/org/gnome/shell/extensions/dash-to-dock/show-trash",
    "/org/gnome/shell/extensions/dash-to-dock/show-mounts",
    "/org/gnome/shell/disable-user-extensions",
    "/org/gnome/shell/enabled-extensions",
    "/org/gnome/shell/allow-extension-installation",
    "/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings",
];

/// What a session looks like in one mode (config profiles design §4.4). Each mode is one row
/// ([`LEGACY_BROWSER`], [`LEARNING`], [`FULL`]), so the later `create` mode is another row rather
/// than more branches through the steps.
#[derive(Debug, PartialEq, Eq)]
pub struct Profile {
    /// The dconf keys locked. Non-empty means a locked-down session: the lockdown settings in
    /// dconf, `Hidden=true` over every app not in the Dock, the D-Bus overrides ([`DBUS_OVERRIDES`])
    /// and the stub over the terminal, file manager and settings ([`exec_block::TARGETS`]).
    pub locks: &'static [&'static str],
    /// The file manager has a place in the Dock.
    pub dock_files: bool,
    /// The Config's Flatpaks are installed ([`super::flatpak`]), and once installed sit in the
    /// Dock and stay visible.
    pub flatpaks: bool,
}

impl Profile {
    pub fn locked(&self) -> bool {
        !self.locks.is_empty()
    }
}

/// A legacy `mode = "browser"` Group: today's browser mode, byte for byte (§3.1).
pub const LEGACY_BROWSER: Profile = Profile {
    locks: LOCKED_KEYS,
    dock_files: false,
    flatpaks: false,
};
/// `learning`: the browser mode plus the Config's Flatpaks (§4.2).
pub const LEARNING: Profile = Profile {
    locks: LOCKED_KEYS,
    dock_files: false,
    flatpaks: true,
};
/// `full`: the whole desktop (the old desktop mode).
pub const FULL: Profile = Profile {
    locks: &[],
    dock_files: true,
    flatpaks: true,
};

/// The row for `config`'s mode.
pub fn profile(config: &Config) -> &'static Profile {
    match config.interface {
        Interface::Full => &FULL,
        Interface::Learning if config.legacy_browser => &LEGACY_BROWSER,
        Interface::Learning => &LEARNING,
    }
}

/// `Hidden=true` 覆盖的内容（注释里的 browser mode 是旧名字，留着：旧形状的浏览器模式要逐字节不变）。
const HIDDEN_ENTRY: &str = "[Desktop Entry]\n\
    # Generated by mastersos-agent (browser mode); do not edit.\n\
    Type=Application\n\
    Name=Hidden by MastersOS\n\
    Hidden=true\n";

const HEADER: &str = "# Generated by mastersos-agent from the settings bundle; do not edit.\n";

pub fn step() -> Step {
    Step {
        name: "desktop",
        fast: true,
        run,
        without_bundle: None,
    }
}

/// GVariant 文本里的字符串（单引号，`\` 与 `'` 前加 `\`）。
fn gv_str(s: &str) -> String {
    let mut o = String::from("'");
    for c in s.chars() {
        if c == '\\' || c == '\'' {
            o.push('\\');
        }
        o.push(c);
    }
    o.push('\'');
    o
}

/// Every mode: a full-width shelf along the bottom with the icons centred, ChromeOS style. Full
/// width so a maximized window meets the shelf rather than leaving strips of wallpaper beside it.
const DOCK_LAYOUT: &str = "\n[org/gnome/shell/extensions/dash-to-dock]\n\
    dock-position='BOTTOM'\n\
    extend-height=true\n\
    always-center-icons=true\n\
    dock-fixed=true\n\
    dash-max-icon-size=44\n";

/// dconf 的 keyfile 与 locks。`webapps` 是网页应用的 desktop 文件名（按清单顺序），`kiosk` 是锁定应用的启动器
/// （每种模式都进 Dock），`flatpaks` 是已装好的受管 Flatpak id（[`Profile::flatpaks`] 的模式才进 Dock）。
pub fn render_dconf(
    config: &Config,
    webapps: &[String],
    kiosk: &[String],
    flatpaks: &[String],
) -> (String, String) {
    let p = profile(config);
    let mut fav = vec![CHROME_DESKTOP.to_string()];
    fav.extend(webapps.iter().cloned());
    fav.extend(kiosk.iter().cloned());
    if p.dock_files {
        fav.push(NAUTILUS_DESKTOP.to_string());
    }
    if p.flatpaks {
        fav.extend(flatpaks.iter().map(|id| format!("{id}.desktop")));
    }
    let fav: Vec<String> = fav.iter().map(|f| gv_str(f)).collect();
    let mut k = String::from(HEADER);
    k.push_str(&format!(
        "\n[org/gnome/shell]\nfavorite-apps=[{}]\n",
        fav.join(", ")
    ));
    if p.locked() {
        let enabled: Vec<String> = LOCKED_EXTENSIONS.iter().map(|e| gv_str(e)).collect();
        k.push_str(&format!(
            "disabled-extensions=[{}]\n\
             disable-user-extensions=true\n\
             allow-extension-installation=false\n\
             enabled-extensions=[{}]\n",
            gv_str(DING_EXTENSION),
            enabled.join(", ")
        ));
    }
    k.push_str("\n[org/gnome/desktop/screensaver]\nlock-enabled=true\n");
    let mut locks = String::new();
    if p.locked() {
        k.push_str(
            "\n[org/gnome/desktop/lockdown]\n\
             disable-command-line=true\n\
             user-administration-disabled=true\n",
        );
        k.push_str(
            "\n[org/gnome/settings-daemon/plugins/media-keys]\nterminal=['']\ncustom-keybindings=@as []\n",
        );
        locks.push_str(HEADER);
        for l in p.locks {
            locks.push_str(l);
            locks.push('\n');
        }
    }
    k.push_str(DOCK_LAYOUT);
    if p.locked() {
        // Ubuntu Dock 里的回收站与外接盘点开就是文件管理器
        k.push_str("show-trash=false\nshow-mounts=false\n");
    }
    (k, locks)
}

/// 网页应用图标的来源（Ruling 8）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IconSource {
    /// 包里的 `files/…`。
    Bundle(String),
    /// `https://` 链接。
    Https(String),
    /// 没有图标，或不在包里、不是 https：用 [`GENERIC_ICON`]。
    Generic,
}

/// `files/…` 且在包里（`present`）→ `Bundle`；`https://` → `Https`；其余 → `Generic`。
pub fn icon_source(icon: Option<&str>, present: &BTreeSet<String>) -> IconSource {
    match icon {
        Some(i) if i.starts_with("files/") && present.contains(i) => IconSource::Bundle(i.into()),
        Some(i) if i.starts_with("https://") => IconSource::Https(i.into()),
        _ => IconSource::Generic,
    }
}

/// 网页应用的启动器文件名：`mastersos-web-<slug(url)>.desktop`。
pub fn webapp_file(url: &str) -> String {
    format!("{WEB_PREFIX}{}.desktop", slug(url))
}

/// (文件名, 内容)。`icon` 是图标的绝对路径，`None` 用 [`GENERIC_ICON`]。`--app=<url>` 整个是一个加引号的参数
/// （[`desktop_exec_arg`]）。不写 `StartupWMClass`（留空）。
pub fn render_webapp(app: &WebApp, icon: Option<&str>) -> (String, String) {
    let text = format!(
        "[Desktop Entry]\n\
         # Generated by mastersos-agent from the settings bundle; do not edit.\n\
         Type=Application\n\
         Name={name}\n\
         Exec={CHROME_BIN} {arg}\n\
         Icon={icon}\n\
         Terminal=false\n\
         Categories=Network;\n",
        name = keyfile_escape(&app.name),
        arg = desktop_exec_arg(&format!("--app={}", app.url)),
        icon = keyfile_escape(icon.unwrap_or(GENERIC_ICON)),
    );
    (webapp_file(&app.url), text)
}

/// 锁定应用的启动器 (文件名, 内容)。`id` 已过 [`kiosk::check_id`]（只有小写字母、数字与 `-`），在 `Exec` 里不必
/// 加引号；名字照 GKeyFile 转义。`icon` 是图标缓存的绝对路径，`None` 用 [`KIOSK_GENERIC_ICON`]。
pub fn render_kiosk_launcher(id: &str, name: &str, icon: Option<&str>) -> (String, String) {
    let text = format!(
        "[Desktop Entry]\n\
         # Generated by mastersos-agent from the settings bundle (kiosk app); do not edit.\n\
         Type=Application\n\
         Name={name}\n\
         Exec={KIOSK_BIN} enter {id}\n\
         Icon={icon}\n\
         Terminal=false\n\
         Categories=Education;\n",
        name = keyfile_escape(name),
        icon = keyfile_escape(icon.unwrap_or(KIOSK_GENERIC_ICON)),
    );
    (format!("{KIOSK_PREFIX}{id}.desktop"), text)
}

/// 锁住的会话里要写 `Hidden=true` 覆盖的 desktop id：`visible` 里不在 `keep`、也不以 `mastersos-web-`、
/// `mastersos-kiosk-` 开头的，去重排序。`keep_apps` 里的 Flatpak 导出的（[`exported_by`]）也不藏，但只认
/// Flatpak 导出目录里的 id：镜像自带的同名前缀启动器照藏（一个 id 两处都有时也照藏——覆盖按 id 生效，放行它就把
/// 镜像那份一起放出来了）。
pub fn hidden_overrides(
    visible: &VisibleApps,
    keep: &[String],
    keep_apps: &[String],
) -> Vec<String> {
    let kept_export = |id: &String| {
        visible.flatpak.contains(id)
            && !visible.system.contains(id)
            && keep_apps.iter().any(|app| exported_by(app, id))
    };
    let set: BTreeSet<&String> = visible
        .system
        .iter()
        .chain(&visible.flatpak)
        .filter(|id| {
            !keep.contains(id)
                && !kept_export(id)
                && !id.starts_with(WEB_PREFIX)
                && !id.starts_with(KIOSK_PREFIX)
        })
        .collect();
    set.into_iter().cloned().collect()
}

/// Whether the Flatpak `app` exports the launcher `desktop_id`: Flatpak only exports files named
/// after the app id, `<app>.desktop` or `<app>.<more>.desktop` (LibreOffice exports one per
/// component).
pub fn exported_by(app: &str, desktop_id: &str) -> bool {
    desktop_id
        .strip_prefix(app)
        .and_then(|rest| rest.strip_suffix(".desktop"))
        .is_some_and(|mid| mid.is_empty() || mid.starts_with('.'))
}

fn dbus_override(file: &str) -> String {
    let name = file.strip_suffix(".service").unwrap_or(file);
    format!("[D-BUS Service]\nName={name}\nExec=/bin/false\n")
}

fn run(ctx: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
    let p = profile(ctx.config);
    let mut errs: Vec<String> = Vec::new();
    let (ids, mut out) = match webapps(ctx, env.paths, env.sys) {
        Ok(r) => r,
        Err(e) => {
            errs.push(format!("web apps: {e:#}"));
            (Vec::new(), Vec::new())
        }
    };
    // 清单里已按清单装好的 Flatpak（后台任务的状态，读不出当作空；Task 16）
    let flatpaks = super::flatpak::dock_apps(env.paths, &ctx.config.apps.flatpak);
    let kiosk = match kiosk_launchers(env.paths, ctx.config) {
        Ok(k) => k,
        Err(e) => {
            errs.push(format!("locked app launchers: {e:#}"));
            Vec::new()
        }
    };
    let (keyfile, locks) = render_dconf(ctx.config, &ids, &kiosk, &flatpaks);
    if let Err(e) = apply_dconf(&env.paths.root, env.runner, env.sys, &keyfile, &locks) {
        errs.push(format!("dconf: {e:#}"));
    }
    let r = if p.locked() {
        let mut keep = vec![CHROME_DESKTOP.to_string()];
        keep.extend(ids.iter().cloned());
        let apps: &[String] = if p.flatpaks { &flatpaks } else { &[] };
        write_overrides(env.paths, &keep, apps)
    } else {
        remove_overrides(env.paths)
    };
    if let Err(e) = r {
        errs.push(format!("overrides: {e:#}"));
    }
    if let Err(e) = exec_block::apply(env.paths, env.runner, p.locked()) {
        errs.push(format!("terminal, file manager and settings: {e:#}"));
    }
    out.push(if errs.is_empty() {
        ok(ITEM)
    } else {
        failed(ITEM, errs.join("; "))
    });
    out
}

/// 打开（必要时建出）`dir` 里的子目录 `rel`，强制 0755。
fn sub_dir(dir: &OwnedFd, rel: &str) -> Result<OwnedFd> {
    let d = safefs::open_dir_at(dir, Path::new(rel), true)?;
    safefs::set_mode(&d, 0o755)?;
    Ok(d)
}

fn xdg_dir(paths: &SysPaths) -> Result<OwnedFd> {
    sub_dir(&public_dir(paths)?, XDG_SUB)
}

/// 写网页应用的启动器与图标，删掉清单里没有了的。返回写好的启动器文件名（按清单顺序）与每一项的回报。
fn webapps(
    ctx: &ApplyContext,
    paths: &SysPaths,
    sys: &mut SysState,
) -> Result<(Vec<String>, Vec<ItemResult>)> {
    // 下载失败过的图标地址，网页应用清单变了才清掉（复审 T13 发现 6）
    let key = slug(&serde_json::to_string(&ctx.config.apps.web).unwrap_or_default());
    if sys.icon_failures.key != key {
        sys.icon_failures = IconFailures {
            key,
            urls: BTreeSet::new(),
        };
    }
    let mut dl = Downloads {
        deadline: std::time::Instant::now() + icon_budget(),
        failed: &mut sys.icon_failures.urls,
    };
    let xdg = xdg_dir(paths)?;
    let apps_dir = sub_dir(&xdg, "applications")?;
    let icons_dir = sub_dir(&xdg, "icons")?;
    let apps = &ctx.config.apps.web;
    let present = bundle_icons(ctx.bundle_dir, apps);
    let mut ids = Vec::new();
    let mut seen = BTreeSet::new();
    let mut keep_icons = BTreeSet::new();
    let mut out = Vec::new();
    for app in apps {
        let item = format!("webapp:{}", app.name);
        if let Err(e) = checks::web_app(app) {
            out.push(failed(&item, e));
            continue;
        }
        let file = webapp_file(&app.url);
        if !seen.insert(file.clone()) {
            out.push(failed(
                &item,
                "same address as an earlier web app; skipped".into(),
            ));
            continue;
        }
        let icon = place_icon(ctx, &icons_dir, app, &present, &mut dl);
        let (detail, path) = match icon {
            Ok(Some(name)) => {
                let abs = paths.public_dir.join(XDG_SUB).join("icons").join(&name);
                keep_icons.insert(name);
                (None, Some(abs.to_string_lossy().into_owned()))
            }
            Ok(None) => (None, None),
            Err(why) => (Some(format!("{why}; using the generic icon")), None),
        };
        let (_, text) = render_webapp(app, path.as_deref());
        match safefs::write_at(&apps_dir, &file, text.as_bytes(), 0o644) {
            Ok(_) => {
                ids.push(file);
                out.push(ItemResult {
                    item,
                    ok: true,
                    detail,
                });
            }
            Err(e) => out.push(failed(&item, format!("write launcher: {e:#}"))),
        }
    }
    let written: BTreeSet<&String> = ids.iter().collect();
    for name in safefs::list_at(&apps_dir)? {
        if name.starts_with(WEB_PREFIX) && !written.contains(&name) {
            safefs::remove_at(&apps_dir, &name)?;
        }
    }
    for name in safefs::list_at(&icons_dir)? {
        if name.starts_with(WEB_PREFIX) && !keep_icons.contains(&name) {
            safefs::remove_at(&icons_dir, &name)?;
        }
    }
    Ok((ids, out))
}

/// 写 `in_session = true`、校验过、kiosk 步骤也建好了（有 `launch.json`）的锁定应用的启动器，删掉其余的
/// `mastersos-kiosk-*.desktop`。返回写好的文件名（按 id 排序）。
fn kiosk_launchers(paths: &SysPaths, config: &Config) -> Result<Vec<String>> {
    let pubd = public_dir(paths)?;
    let apps_dir = sub_dir(&xdg_dir(paths)?, "applications")?;
    let base = safefs::open_child_dir(&pubd, KIOSK_SUB)?;
    let mut written = Vec::new();
    for (id, app) in &config.apps.kiosk {
        if !app.in_session || kiosk::check(id, app).is_err() {
            continue;
        }
        let Some(dir) = base
            .as_ref()
            .map(|b| safefs::open_child_dir(b, id))
            .transpose()?
            .flatten()
        else {
            continue;
        };
        if safefs::open_file_at(&dir, super::kiosk::LAUNCH_FILE)?.is_none() {
            continue;
        }
        let icon = safefs::open_file_at(&dir, super::kiosk::ICON_FILE)?.map(|_| {
            paths
                .public_dir
                .join(KIOSK_SUB)
                .join(id)
                .join(super::kiosk::ICON_FILE)
                .to_string_lossy()
                .into_owned()
        });
        let (file, text) = render_kiosk_launcher(id, &app.name, icon.as_deref());
        safefs::write_at(&apps_dir, &file, text.as_bytes(), 0o644)
            .with_context(|| format!("write {file}"))?;
        written.push(file);
    }
    for name in safefs::list_at(&apps_dir)? {
        if name.starts_with(KIOSK_PREFIX) && !written.contains(&name) {
            safefs::remove_at(&apps_dir, &name)?;
        }
    }
    Ok(written)
}

/// 清单里引用的、包里确实有的 `files/…` 图标（普通文件）。
fn bundle_icons(bundle_dir: &Path, apps: &[WebApp]) -> BTreeSet<String> {
    apps.iter()
        .filter_map(|a| a.icon.as_deref())
        .filter(|i| i.starts_with("files/") && read_bundle_file(bundle_dir, i).is_ok())
        .map(String::from)
        .collect()
}

pub(crate) fn read_bundle_file(bundle_dir: &Path, rel: &str) -> Result<Vec<u8>> {
    let p = Path::new(rel);
    let (Some(parent), Some(name)) = (p.parent(), p.file_name().and_then(|n| n.to_str())) else {
        bail!("not a normalized path");
    };
    let dir = safefs::open_dir(bundle_dir, parent, false)?;
    let Some(f) = safefs::open_file_at(&dir, name)? else {
        bail!("this file is not in the bundle");
    };
    let mut buf = Vec::new();
    f.take(MAX_ICON_BYTES as u64 + 1).read_to_end(&mut buf)?;
    Ok(buf)
}

/// 按文件头认 PNG 或 SVG，返回扩展名。SVG 要求跳过 XML 声明、注释、DOCTYPE 与空白之后的第一个元素就是 `<svg`
/// （复审 T13 发现 8：只是「里面有 `<svg`」的 HTML 会被存成 .svg、Dock 里画不出来）。
pub fn sniff_icon(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some("png");
    }
    let b = b.strip_prefix(b"\xef\xbb\xbf").unwrap_or(b);
    let head = String::from_utf8_lossy(&b[..b.len().min(4096)]).to_ascii_lowercase();
    let mut t = head.as_str();
    loop {
        t = t.trim_start();
        let end = if t.starts_with("<?") {
            t.find("?>").map(|i| i + 2)
        } else if t.starts_with("<!--") {
            t.find("-->").map(|i| i + 3)
        } else if t.starts_with("<!doctype svg") {
            t.find('>').map(|i| i + 1)
        } else {
            break;
        };
        t = &t[end?..];
    }
    let rest = t.strip_prefix("<svg")?;
    rest.starts_with(|c: char| c.is_ascii_whitespace() || c == '>' || c == '/')
        .then_some("svg")
}

/// 检查大小与格式，写进 `icons/<base>.<ext>`，返回文件名。
/// 内容本身的问题（太大、不是 PNG 或 SVG）：换哪一轮下都一样。
pub(crate) fn icon_problem(bytes: &[u8]) -> Option<String> {
    if bytes.len() > MAX_ICON_BYTES {
        return Some(format!("icon is over {} KiB", MAX_ICON_BYTES / 1024));
    }
    sniff_icon(bytes)
        .is_none()
        .then(|| "icon is not PNG or SVG".into())
}

fn store_icon(icons_dir: &OwnedFd, base: &str, bytes: &[u8]) -> Result<String, String> {
    if let Some(p) = icon_problem(bytes) {
        return Err(p);
    }
    let Some(ext) = sniff_icon(bytes) else {
        return Err("icon is not PNG or SVG".into());
    };
    let name = format!("{base}.{ext}");
    safefs::write_at(icons_dir, &name, bytes, 0o644).map_err(|e| format!("write icon: {e:#}"))?;
    Ok(name)
}

/// 放好这个网页应用的图标，返回 `icons/` 里的文件名；`Ok(None)` 是清单没给图标；`Err` 是给了但用不上的原因。
fn place_icon(
    ctx: &ApplyContext,
    icons_dir: &OwnedFd,
    app: &WebApp,
    present: &BTreeSet<String>,
    dl: &mut Downloads,
) -> Result<Option<String>, String> {
    match icon_source(app.icon.as_deref(), present) {
        IconSource::Generic => match &app.icon {
            None => Ok(None),
            Some(i) => Err(format!(
                "icon {i} is neither in the bundle nor an https link"
            )),
        },
        IconSource::Bundle(src) => {
            let bytes = read_bundle_file(ctx.bundle_dir, &src)
                .map_err(|e| format!("cannot read icon {src} from the bundle: {e:#}"))?;
            let base = format!("{WEB_PREFIX}{}", slug(&app.url));
            store_icon(icons_dir, &base, &bytes).map(Some)
        }
        IconSource::Https(url) => {
            let base = format!("{WEB_PREFIX}{}", slug(&url));
            for ext in ["png", "svg"] {
                let name = format!("{base}.{ext}");
                if matches!(safefs::open_file_at(icons_dir, &name), Ok(Some(_))) {
                    return Ok(Some(name));
                }
            }
            if ctx.phase != Phase::Full {
                return Err(
                    "icon not downloaded yet (the quick apply at boot does not download)".into(),
                );
            }
            if dl.failed.contains(&url) {
                return Err(
                    "icon download failed last time; will retry when the web app manifest changes"
                        .into(),
                );
            }
            if ctx.superseded.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(
                    "a newer apply request is pending; not downloading icons this round".into(),
                );
            }
            let left = dl
                .deadline
                .saturating_duration_since(std::time::Instant::now());
            if left < Duration::from_secs(1) {
                return Err(
                    "icon download time for this round is used up; will download next round".into(),
                );
            }
            // 只记下换一轮也不会好的失败（复审 T13 R3）：4xx、太大、不是图片。超时、连不上、5xx、被这一轮的时间截断、
            // 写盘失败都下一轮完整应用再试
            let r = match download_icon(&url, left) {
                Err(e) => Err((
                    format!("icon download failed: {e:#}"),
                    e.downcast_ref::<Definitive>().is_some(),
                )),
                Ok(bytes) => match icon_problem(&bytes) {
                    Some(p) => Err((p, true)),
                    None => store_icon(icons_dir, &base, &bytes).map_err(|m| (m, false)),
                },
            };
            if let Err((_, true)) = &r {
                dl.failed.insert(url.clone());
            }
            r.map(Some).map_err(|(m, _)| m)
        }
    }
}

/// 测试用：把 `https://<前缀>` 改写到 wiremock 的地址（只在测试里编译）。
#[cfg(test)]
pub(crate) static TEST_URL_MAP: std::sync::Mutex<Vec<(String, String)>> =
    std::sync::Mutex::new(Vec::new());

fn effective_url(url: &str) -> String {
    #[cfg(test)]
    {
        let map = TEST_URL_MAP.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((from, to)) = map.iter().find(|(f, _)| url.starts_with(f.as_str())) {
            return format!("{to}{}", &url[from.len()..]);
        }
    }
    url.to_string()
}

/// 下载图标（最多 [`MAX_ICON_BYTES`] + 1 字节就停）。应用在 `spawn_blocking` 的线程里跑：有运行时就借它的
/// `block_on`，没有（同步的测试）就临时建一个。
/// 换一轮下也不会好的下载失败（4xx、太大）。
#[derive(Debug)]
pub(crate) struct Definitive(String);

impl std::fmt::Display for Definitive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Definitive {}

pub(crate) fn download_icon(url: &str, total: Duration) -> Result<Vec<u8>> {
    let url = effective_url(url);
    let fut = async move {
        let client = crate::fetch::http_client(crate::fetch::HttpOpts {
            connect: Duration::from_secs(15),
            read: Some(Duration::from_secs(30)),
            total: Some(total),
        });
        // 不带 User-Agent 的请求有的站点回 403（Wikimedia，VM 上实测），reqwest 默认不带
        let resp = client
            .get(&url)
            .header(reqwest::header::USER_AGENT, ICON_USER_AGENT)
            .send()
            .await?;
        if resp.status().is_client_error() {
            return Err(Definitive(format!("icon address returned {}", resp.status())).into());
        }
        let mut resp = resp.error_for_status()?;
        let too_big = || Definitive(format!("icon is over {} KiB", MAX_ICON_BYTES / 1024));
        if resp
            .content_length()
            .is_some_and(|n| n > MAX_ICON_BYTES as u64)
        {
            return Err(too_big().into());
        }
        let mut buf = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            buf.extend_from_slice(&chunk);
            if buf.len() > MAX_ICON_BYTES {
                return Err(too_big().into());
            }
        }
        Ok(buf)
    };
    match tokio::runtime::Handle::try_current() {
        Ok(h) => h.block_on(fut),
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build the tokio runtime")?
            .block_on(fut),
    }
}

/// 写 dconf 的 keyfile 与 locks；有变化（或上次没编译成功、或状态读失败）就 `dconf update`。
fn apply_dconf(
    root: &Path,
    runner: &dyn Runner,
    sys: &mut SysState,
    keyfile: &str,
    locks: &str,
) -> Result<()> {
    let dir = safefs::open_dir(root, Path::new(DCONF_DIR), true)?;
    let mut changed = safefs::write_at(&dir, DCONF_FILE, keyfile.as_bytes(), 0o644)
        .with_context(|| format!("write /{DCONF_DIR}/{DCONF_FILE}"))?;
    let ld = safefs::open_dir(root, Path::new(DCONF_LOCKS_DIR), true)?;
    if locks.is_empty() {
        if safefs::read_at(&ld, DCONF_FILE)?.is_some() {
            safefs::remove_at(&ld, DCONF_FILE)?;
            changed = true;
        }
    } else {
        changed |= safefs::write_at(&ld, DCONF_FILE, locks.as_bytes(), 0o644)
            .with_context(|| format!("write /{DCONF_LOCKS_DIR}/{DCONF_FILE}"))?;
    }
    if changed {
        sys.dconf_update_pending = true;
    }
    if sys.dconf_update_pending || sys.load_failed {
        run_ok(runner, Cmd::new("dconf", &["update"]))?;
        sys.dconf_update_pending = false;
    }
    Ok(())
}

/// `[Desktop Entry]` 组里 `NoDisplay=true` 或 `Hidden=true` 的不算看得见。
fn visible(text: &str) -> bool {
    let mut in_entry = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if matches!(k.trim(), "NoDisplay" | "Hidden") && v.trim() == "true" {
                return false;
            }
        }
    }
    true
}

/// [`APP_DIRS`] 里看得见的 `.desktop`（只看顶层）。按路径读：这些目录 root 所有（Flatpak 的导出是指向
/// `/var/lib/flatpak/app/…` 的链接，要跟随）；只读不写。不存在的目录跳过。
fn visible_desktop_ids(root: &Path) -> Result<VisibleApps> {
    Ok(VisibleApps {
        system: visible_in(root, SYSTEM_APPS_DIR)?,
        flatpak: visible_in(root, FLATPAK_APPS_DIR)?,
    })
}

fn visible_in(root: &Path, d: &str) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    let dir = root.join(d);
    let rd = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e).with_context(|| format!("list /{d}")),
    };
    for e in rd {
        let e = e?;
        let Some(name) = e.file_name().to_str().map(String::from) else {
            continue;
        };
        if !name.ends_with(".desktop") || name.starts_with('.') {
            continue;
        }
        let mut text = String::new();
        let Ok(f) = std::fs::File::open(e.path()) else {
            continue;
        };
        if f.take(1 << 20).read_to_string(&mut text).is_err() {
            continue;
        }
        if visible(&text) {
            out.insert(name);
        }
    }
    Ok(out)
}

/// 我们放在 `applications/` 里的 `Hidden=true` 覆盖（网页应用与锁定应用的启动器以外的 `.desktop`）。
fn is_override(name: &str) -> bool {
    name.ends_with(".desktop")
        && !name.starts_with(WEB_PREFIX)
        && !name.starts_with(KIOSK_PREFIX)
        && !name.starts_with('.')
}

fn write_overrides(paths: &SysPaths, keep: &[String], keep_apps: &[String]) -> Result<()> {
    let xdg = xdg_dir(paths)?;
    let apps_dir = sub_dir(&xdg, "applications")?;
    let hide = hidden_overrides(&visible_desktop_ids(&paths.root)?, keep, keep_apps);
    for id in &hide {
        safefs::write_at(&apps_dir, id, HIDDEN_ENTRY.as_bytes(), 0o644)
            .with_context(|| format!("write the override for {id}"))?;
    }
    for name in safefs::list_at(&apps_dir)? {
        if is_override(&name) && !hide.contains(&name) {
            safefs::remove_at(&apps_dir, &name)?;
        }
    }
    let services = sub_dir(&sub_dir(&xdg, "dbus-1")?, "services")?;
    for s in DBUS_OVERRIDES {
        safefs::write_at(&services, s, dbus_override(s).as_bytes(), 0o644)
            .with_context(|| format!("write D-Bus override {s}"))?;
    }
    Ok(())
}

fn remove_overrides(paths: &SysPaths) -> Result<()> {
    let xdg = xdg_dir(paths)?;
    if let Some(apps_dir) = safefs::open_child_dir(&xdg, "applications")? {
        for name in safefs::list_at(&apps_dir)? {
            if is_override(&name) {
                safefs::remove_at(&apps_dir, &name)?;
            }
        }
    }
    match safefs::open_dir_at(&xdg, Path::new("dbus-1/services"), false) {
        Ok(services) => {
            for s in DBUS_OVERRIDES {
                safefs::remove_at(&services, s)?;
            }
        }
        Err(e) if is_not_found(&e) => {}
        Err(e) => return Err(e),
    }
    Ok(())
}

#[cfg(test)]
mod tests;
