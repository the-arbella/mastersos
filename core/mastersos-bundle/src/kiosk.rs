//! 锁定应用（`[config.apps.kiosk]`，计划 9）：类型在 `manifest.rs`，这里是校验、规范化、常量，
//! 以及锁定会话里 Chrome 读的那份托管策略（[`chrome_policy`]，设计 §4.3、§4.5）。
//!
//! [`check`] 由发布前 lint 与 agent 共用：lint 把错误变成 `config.<cid>.apps.kiosk.<id>.<field>`，
//! agent 对不合格的应用不建账号。不收任意 Chrome 命令行参数、不收 shell 命令（设计 §3、§7）。

use std::collections::BTreeSet;

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::checks::{self, has_control};
use crate::KioskApp;

/// 一个分组最多这么多个锁定应用（uid 1900–1989 的区间放得下，lint 报 `kiosk_too_many`）。
pub const MAX_KIOSK_APPS: usize = 32;
/// id 最多这么多个字符：`kiosk-<id>` 在账号名的 32 字节以内。
pub const MAX_ID_LEN: usize = 24;
/// `name` 最多这么多个字符（按字符数：泰文一个字三个字节）。
pub const MAX_NAME_CHARS: usize = 64;
/// `user_agent` 最多这么多字节（裁定 K9）。
pub const MAX_USER_AGENT_LEN: usize = 512;
/// `url` 与扩展 `update_url` 最多这么多字节。
pub const MAX_URL_LEN: usize = 2048;
/// The one value of `platform` (design docs/specs/2026-11-06-kiosk-platform-inject-design.md §1).
pub const PLATFORM_CHROMEOS: &str = "chromeos";
/// An `inject` script is at most this many bytes (64 KiB).
pub const MAX_INJECT_BYTES: usize = 64 * 1024;

/// 应用自己的 `chrome_policy` 不能写的键（`kiosk_policy_locked`）：设计 §4.5 表里的每一条（`PrintingEnabled`
/// 除外：表里写明应用可以打开打印），加上扩展与 PWA 的四个，再加 `3rdparty`——扩展的托管配置只从
/// `extensions[].config` 来，否则应用能借它改写考试扩展的配置——以及另外三条放开扩展安装的策略。
pub const LOCKED_KEYS: &[&str] = &[
    "URLBlocklist",
    "URLAllowlist",
    "DeveloperToolsAvailability",
    "IncognitoModeAvailability",
    "BrowserGuestModeEnabled",
    "BrowserAddPersonEnabled",
    "BrowserSignin",
    "SyncDisabled",
    "DownloadRestrictions",
    "AllowFileSelectionDialogs",
    "PasswordManagerEnabled",
    "AutofillAddressEnabled",
    "AutofillCreditCardEnabled",
    "TaskManagerEndProcessEnabled",
    "ScreenCaptureAllowed",
    "ExtensionInstallBlocklist",
    "DefaultBrowserSettingEnabled",
    "PromotionalTabsEnabled",
    // 关窗口就要真的退出：`mastersos-kiosk run` 等 Chrome 退出才重开（计划 9 Task 6 复审 M3）
    "BackgroundModeEnabled",
    "ExtensionSettings",
    "ExtensionInstallForcelist",
    "WebAppInstallForceList",
    "3rdparty",
    // 锁定应用带扩展只有 `extensions` 一条路：不许另开允许名单、安装来源或扩展类型。
    "ExtensionInstallAllowlist",
    "ExtensionInstallSources",
    "ExtensionAllowedTypes",
    // 已弃用的旧名：新名没设时 Chrome 退回读旧名（我们不设 ExtensionInstallAllowlist，按 id 写的
    // ExtensionInstallWhitelist 会盖过 "*" 的阻止），一并锁上。
    "ExtensionInstallWhitelist",
    "ExtensionInstallBlacklist",
    "URLWhitelist",
    "URLBlacklist",
    // 考试扩展的「退出」按钮靠原生消息宿主：只许本机的那一个，不许用户级宿主。
    "NativeMessagingBlocklist",
    "NativeMessagingAllowlist",
    "NativeMessagingUserLevelHosts",
];

/// 默认锁里应用可以在自己的 `chrome_policy` 里改的几条（不是 [`LOCKED_KEYS`]）：打印（设计 §4.5 原有），以及
/// 终审 I3 加的翻译、拼写检查、Lens、生成式 AI 与用户反馈——考试里默认都不该有，但某个应用确实要用时可以打开。
pub static OPTIONAL_DEFAULTS: std::sync::LazyLock<Vec<(&'static str, Value)>> =
    std::sync::LazyLock::new(|| {
        vec![
            ("PrintingEnabled", json!(false)),
            ("TranslateEnabled", json!(false)),
            ("SpellcheckEnabled", json!(false)),
            // 1 = 不显示 Lens 的「用 Google 搜索屏幕」
            ("LensOverlaySettings", json!(1)),
            // 2 = 关掉全部生成式 AI 功能
            ("GenAiDefaultSettings", json!(2)),
            ("UserFeedbackAllowed", json!(false)),
        ]
    });

/// 本机的错误页（镜像里）：Chrome 60 秒内退出 5 次，`mastersos-kiosk run` 改开它（设计 §4.4）。`URLBlocklist` 是
/// `["*"]`，`file://` 也在里面，所以放行名单的最后一项是它——只是这一个文件，不是整个 `file://`。Chrome 按路径
/// 前缀匹配（`…/kiosk-error.html` 后面再接什么也算），`/usr` 是只读的镜像、那里没有同前缀的文件，实际上就是这一页。
pub const ERROR_PAGE: &str = "file:///usr/share/mastersos/kiosk-error.html";

/// 考试扩展「退出」按钮用的原生消息宿主（镜像里的宿主清单同名）。
pub const EXIT_HOST: &str = "org.mastersos.kiosk_exit";

/// 考试扩展「Get help」用的原生消息宿主（镜像里的宿主清单同名，→ `mastersos-agent support native-host`）。
pub const SUPPORT_HOST: &str = "org.mastersos.support";

/// Where the image carries the exam extension's update manifest. A fresh Chrome profile installs from disk, so the Exit
/// button needs no network. Only the exam extension may use it, and only as this exact string; school `extensions` stay https.
pub const EXAM_LOCAL_UPDATE_URL: &str = "file:///usr/lib/mastersos/kiosk-ext/updates.xml";

/// MastersOS 考试扩展：每个网页 / PWA 锁定会话都强制安装它。id 由签名钥匙的公钥算出，lab 与正式不同，
/// 所以不写死在这里：镜像里的 `/usr/lib/mastersos/kiosk-ext.json` 给出（裁定 R1），agent 读了传进 [`chrome_policy`]。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ExamExtension {
    /// 32 个 a–p。
    pub id: String,
    /// 更新清单（`updates.xml`）的 https 地址，或镜像里的 [`EXAM_LOCAL_UPDATE_URL`]。
    pub update_url: String,
}

impl ExamExtension {
    /// 镜像里的 `kiosk-ext.json` 读出来之后先过这一关（裁定 R1）：id 与 `extensions` 同一条规则（32 个 a–p），
    /// `update_url` 与扩展的 `update_url` 同一条 https 与主机规则。不过就是原因。
    pub fn check(&self) -> Result<(), String> {
        if !extension_id_ok(&self.id) {
            return Err(format!(
                "Exam extension id {:?} must be 32 lowercase letters a-p",
                self.id
            ));
        }
        if self.update_url == EXAM_LOCAL_UPDATE_URL {
            return Ok(());
        }
        https_host(&self.update_url)
            .map(|_| ())
            .map_err(|why| format!("Exam extension update_url {:?} {why}", self.update_url))
    }
}

/// The platform extension the agent builds on the Device for an app with `platform` or `inject`
/// (design §3.4): its id (from the Device's key for this app) and its local update manifest. It
/// has the start page, the ChromeOS disguise and the inject script, and the permissions they need;
/// the exam extension has none of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformExtension {
    pub id: String,
    pub update_url: String,
}

/// The key of the exam extension's managed storage (`3rdparty`) that names the app's platform
/// extension: the only other extension it takes `{cmd:"exit"}` from.
pub const EXAM_PLATFORM_KEY: &str = "platform_extension";

/// Whether `app` has a platform extension and starts at its start page (`platform` or `inject`
/// written; design §3.3). Those apps get `chrome-extension://<platform extension id>` in the
/// allowlist.
pub fn uses_start_page(app: &KioskApp) -> bool {
    app.platform.is_some() || app.inject.is_some()
}

/// The rules for the contents of an `inject` script, where the contents are at hand (the agent,
/// `mastersos check`): at most [`MAX_INJECT_BYTES`], UTF-8, no NUL. The reason otherwise.
pub fn check_inject_source(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_INJECT_BYTES {
        return Err(format!(
            "is {} bytes, more than the {} KiB an inject script may have",
            bytes.len(),
            MAX_INJECT_BYTES / 1024
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "is not UTF-8 text".to_string())?;
    if text.contains('\0') {
        return Err("contains a NUL character".into());
    }
    Ok(())
}

/// The platform extension's configuration (design §3.4, its `config.js`): the app's `url`, the
/// hosts the disguise and the script apply to (the same as the allowlist's), `platform`, whether
/// there is an inject script, and the exam extension's id (where `{cmd:"exit"}` goes).
pub fn platform_config(app: &KioskApp, exam_id: &str) -> Result<Value, KioskError> {
    let (url, hosts) = start_hosts(app)?;
    Ok(json!({
        "v": 1,
        "url": url,
        "hosts": hosts,
        "platform": app.platform,
        "inject": app.inject.is_some(),
        "exam": exam_id,
    }))
}

/// A web app's `url` and the hosts its disguise and inject script apply to: the allowlist's hosts
/// (`allow`, then the host of `url`, each once). Only for web apps without pwa.
pub fn start_hosts(app: &KioskApp) -> Result<(&str, Vec<String>), KioskError> {
    let url = match launch(app)? {
        KioskLaunch::Web { url, pwa: false } => url,
        _ => {
            return fail(
                "kiosk_platform_invalid",
                "platform",
                "platform and inject are only for web apps without pwa".into(),
            )
        }
    };
    let mut hosts = allow_hosts(app)?;
    hosts.push(url_host(url)?);
    let mut seen = BTreeSet::new();
    hosts.retain(|h| seen.insert(h.clone()));
    Ok((url, hosts))
}

/// Chrome 扩展的 id：32 个 a–p。
pub fn extension_id_ok(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

/// 校验不过的一处：`code` 是 lint 的代码，`field` 是应用下的字段名（id 本身是 `"id"`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KioskError {
    pub code: &'static str,
    pub message: String,
    pub field: &'static str,
}

fn fail<T>(code: &'static str, field: &'static str, message: String) -> Result<T, KioskError> {
    Err(KioskError {
        code,
        message,
        field,
    })
}

/// 应用怎么启动：网页 / PWA 进 Chrome，或者一个本地程序。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KioskLaunch<'a> {
    Web {
        url: &'a str,
        pwa: bool,
    },
    /// Flatpak id，或 `/usr/` 下的绝对路径。
    Exec(&'a str),
}

/// 应用的系统账号名。
pub fn account_name(id: &str) -> String {
    format!("kiosk-{id}")
}

/// 启动方式：`url` 与 `exec` 恰好写一个，`pwa` 只配 `url`，`android` 不许写；
/// 写了的那个也要合规（`url` 是 https、`exec` 是 Flatpak id 或 `/usr/` 下的路径）。
pub fn launch(app: &KioskApp) -> Result<KioskLaunch<'_>, KioskError> {
    const CODE: &str = "kiosk_launch_invalid";
    if app.android.is_some() {
        return fail(
            CODE,
            "android",
            "android is a reserved field and Android apps are not supported yet: remove it".into(),
        );
    }
    match (&app.url, &app.exec) {
        (Some(_), Some(_)) => fail(
            CODE,
            "exec",
            "Write only one of url and exec: url for a web page or PWA, exec for a local program".into(),
        ),
        (None, _) if app.pwa => fail(CODE, "pwa", "pwa = true is only valid together with url".into()),
        (None, None) => fail(
            CODE,
            "url",
            "Neither url nor exec is set: write url for a web page or PWA, exec for a local program".into(),
        ),
        (Some(u), None) => {
            url_host(u)?;
            Ok(KioskLaunch::Web {
                url: u,
                pwa: app.pwa,
            })
        }
        (None, Some(x)) => {
            exec(x)?;
            Ok(KioskLaunch::Exec(x))
        }
    }
}

/// 规范化后的放行主机（小写、去掉结尾的点，保留原顺序）。没写 `allow`（或写成空数组）就是 `url`
/// 的主机名；本地程序没有 `url`，那时是空的。
pub fn allow_hosts(app: &KioskApp) -> Result<Vec<String>, KioskError> {
    if app.allow.is_empty() {
        return match &app.url {
            Some(u) => Ok(vec![url_host(u)?]),
            None => Ok(Vec::new()),
        };
    }
    app.allow
        .iter()
        .map(|d| {
            host(d).map_err(|why| KioskError {
                code: "kiosk_allow_invalid",
                message: format!("allow entry {d:?} {why}; write a host name such as \"nwea.org\" (subdomains included)"),
                field: "allow",
            })
        })
        .collect()
}

/// 一个锁定应用的全部规则（设计 §7 里除 `kiosk_policy_locked` 与几条警告以外的错误），报第一处。
/// 图标要看包里有哪些文件，由 lint 判断。
pub fn check(id: &str, app: &KioskApp) -> Result<(), KioskError> {
    check_id(id)?;
    if let Err(why) = name_problem(&app.name) {
        return fail("kiosk_name_invalid", "name", why);
    }
    let how = launch(app)?;
    if let Some(ua) = &app.user_agent {
        if matches!(how, KioskLaunch::Exec(_)) {
            return fail(
                "kiosk_user_agent_invalid",
                "user_agent",
                "user_agent is only for web / PWA apps and cannot be set on a local program (exec)"
                    .into(),
            );
        }
        if ua.len() > MAX_USER_AGENT_LEN || has_control(ua) {
            return fail(
                "kiosk_user_agent_invalid",
                "user_agent",
                format!("user_agent must be at most {MAX_USER_AGENT_LEN} bytes with no control characters"),
            );
        }
    }
    let web_only = matches!(how, KioskLaunch::Web { pwa: false, .. });
    if let Some(p) = &app.platform {
        let why = if !web_only {
            Some("platform is only for web apps (url) without pwa = true".to_string())
        } else if p != PLATFORM_CHROMEOS {
            Some(format!(
                "platform {p:?} is not known: the only value is \"{PLATFORM_CHROMEOS}\""
            ))
        } else if app.user_agent.is_some() {
            Some(
                "platform and user_agent cannot both be set: platform = \"chromeos\" already sets the user agent (remove user_agent)"
                    .into(),
            )
        } else {
            None
        };
        if let Some(why) = why {
            return fail("kiosk_platform_invalid", "platform", why);
        }
    }
    if let Some(f) = &app.inject {
        if !web_only {
            return fail(
                "kiosk_inject_invalid",
                "inject",
                "inject is only for web apps (url) without pwa = true".into(),
            );
        }
        if !inject_path_ok(f) {
            return fail(
                "kiosk_inject_invalid",
                "inject",
                format!("inject {f:?} must be a files/….js file in the bundle, such as \"files/testnav.js\""),
            );
        }
    }
    // 放行主机、扩展与 chrome_policy 的规则都在合成策略的路上：lint 不知道考试扩展的真 id，传一个占位的
    // （它不是合法的扩展 id，不会与 extensions 里的撞上；撞真 id 由 agent 调 chrome_policy 时报）。
    let placeholder = ExamExtension {
        id: "(exam)".into(),
        update_url: "https://exam.invalid/updates.xml".into(),
    };
    let platform = PlatformExtension {
        id: "(platform)".into(),
        update_url: "file:///platform.invalid/updates.xml".into(),
    };
    chrome_policy(app, &placeholder, uses_start_page(app).then_some(&platform))?;
    Ok(())
}

/// `inject`: a bundle member under `files/` ending in `.js`.
pub fn inject_path_ok(f: &str) -> bool {
    f.starts_with("files/")
        && f.len() > "files/.js".len()
        && f.ends_with(".js")
        && crate::check_member_path(f).is_ok()
}

/// 锁定会话里 Chrome 的托管策略（agent 写进 `/var/lib/mastersos/kiosk/<id>/policies/mastersos-kiosk.json`）：
/// 设计 §4.5 的默认锁，叠上应用自己的 `chrome_policy`（锁定键写了就报 `kiosk_policy_locked`），再加
/// `ExtensionSettings` / `ExtensionInstallForcelist`（考试扩展与 `extensions` 强制安装，其余一律阻止）、
/// `3rdparty.extensions.<id>`（各扩展的 `config`）与 PWA 的 `WebAppInstallForceList`。
///
/// 不继承分组的 `chrome_policy`：签名里只有应用。
///
/// 本地程序（`exec`）也有一份（终审 I1）：会话本身不起 Chrome，但程序里的链接（帮助、「关于」、OpenURI 门户、
/// `xdg-open`）会在同一个命名空间里起 Chrome——托管目录是空的就是一个什么都没锁的浏览器。所以它拿同一套默认锁，
/// 放行名单只有错误页（什么网站都打不开）、不强制安装任何扩展（考试扩展也不装：没有要退出的网页会话，
/// 原生消息宿主也一个都不放行），
/// 不叠应用自己的 `chrome_policy`（它只对网页 / PWA 有效，网页表单保存时就去掉）；扩展与 `chrome_policy`
/// 照样校验，lint 报的与 agent 拒的是同一套。
/// `platform` is the app's platform extension (design §3.4), for a web app with `platform` or
/// `inject`: force-installed beside the exam extension, its start page
/// (`chrome-extension://<platform extension id>`) in the allowlist, and its id in the exam
/// extension's managed storage ([`EXAM_PLATFORM_KEY`]).
pub fn chrome_policy(
    app: &KioskApp,
    exam: &ExamExtension,
    platform: Option<&PlatformExtension>,
) -> Result<Map<String, Value>, KioskError> {
    let how = launch(app)?;
    let mut allow = allow_hosts(app)?;
    let mut configs = extensions(app, exam)?;
    if let Some(p) = platform {
        if app.extensions.iter().any(|e| e.id == p.id) {
            return fail(
                "kiosk_extension_invalid",
                "extensions",
                format!(
                    "Extension {} is this app's MastersOS platform extension and need not be listed in extensions",
                    p.id
                ),
            );
        }
    }
    let own = toml_table_to_json(&app.chrome_policy).map_err(|why| KioskError {
        code: "kiosk_policy_invalid",
        message: format!("chrome_policy cannot be converted to a Chrome JSON policy: {why}"),
        field: "chrome_policy",
    })?;
    let locked: Vec<&str> = own
        .keys()
        .map(String::as_str)
        .filter(|k| LOCKED_KEYS.contains(k))
        .collect();
    if !locked.is_empty() {
        return fail(
            "kiosk_policy_locked",
            "chrome_policy",
            format!(
                "chrome_policy must not set {}: the default locks of a kiosk session cannot be overridden by an app",
                locked.join(", ")
            ),
        );
    }
    let web = match how {
        KioskLaunch::Web { url, pwa } => Some((url, pwa)),
        KioskLaunch::Exec(_) => None,
    };

    // 放行：allow 的主机在前，再加 url 的主机，重复的只留第一次；本地程序没有（allow 只对网页有效）。
    match web {
        Some((url, _)) => allow.push(url_host(url)?),
        None => allow.clear(),
    }
    let mut seen = BTreeSet::new();
    allow.retain(|h| seen.insert(h.clone()));
    let platform = platform.filter(|_| web.is_some());
    if let Some(p) = platform {
        allow.push(format!("chrome-extension://{}", p.id));
        configs.insert(exam.id.clone(), json!({ EXAM_PLATFORM_KEY: p.id }));
    }
    allow.push(ERROR_PAGE.to_string());

    let forced: Vec<(&str, &str)> = match web {
        Some(_) => std::iter::once((exam.id.as_str(), exam.update_url.as_str()))
            .chain(platform.map(|p| (p.id.as_str(), p.update_url.as_str())))
            .chain(
                app.extensions
                    .iter()
                    .map(|e| (e.id.as_str(), e.update_url.as_str())),
            )
            .collect(),
        None => Vec::new(),
    };
    let mut settings = Map::new();
    settings.insert("*".into(), json!({"installation_mode": "blocked"}));
    for (id, update_url) in &forced {
        settings.insert(
            (*id).into(),
            json!({"installation_mode": "force_installed", "update_url": update_url}),
        );
    }
    let forcelist: Vec<String> = forced.iter().map(|(id, u)| format!("{id};{u}")).collect();

    let mut m: Map<String, Value> = [
        ("URLBlocklist", json!(["*"])),
        ("URLAllowlist", json!(allow)),
        ("DeveloperToolsAvailability", json!(2)),
        ("IncognitoModeAvailability", json!(1)),
        ("BrowserGuestModeEnabled", json!(false)),
        ("BrowserAddPersonEnabled", json!(false)),
        ("BrowserSignin", json!(0)),
        ("SyncDisabled", json!(true)),
        ("DownloadRestrictions", json!(3)),
        ("AllowFileSelectionDialogs", json!(false)),
        ("PasswordManagerEnabled", json!(false)),
        ("AutofillAddressEnabled", json!(false)),
        ("AutofillCreditCardEnabled", json!(false)),
        ("TaskManagerEndProcessEnabled", json!(false)),
        ("ScreenCaptureAllowed", json!(false)),
        ("ExtensionInstallBlocklist", json!(["*"])),
        ("ExtensionInstallForcelist", json!(forcelist)),
        ("ExtensionSettings", json!(settings)),
        ("DefaultBrowserSettingEnabled", json!(false)),
        ("PromotionalTabsEnabled", json!(false)),
        ("BackgroundModeEnabled", json!(false)),
        // 允许名单只是阻止名单的例外：不配 "*" 的阻止，任何系统级宿主都能连。
        ("NativeMessagingBlocklist", json!(["*"])),
        // 本地程序的会话没有考试扩展，退出与求助的宿主都不放行
        (
            "NativeMessagingAllowlist",
            match web {
                Some(_) => json!([EXIT_HOST, SUPPORT_HOST]),
                None => json!([]),
            },
        ),
        ("NativeMessagingUserLevelHosts", json!(false)),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    // 默认关、应用可以打开的（与 PrintingEnabled 同一类，不进 LOCKED_KEYS；终审 I3）：右键翻译与翻译气泡不是导航，
    // URLBlocklist 挡不住——英文阅读考试一键就翻成泰文；拼写检查、Lens、生成式 AI 与反馈（Alt+Shift+I）同理。
    m.extend(
        OPTIONAL_DEFAULTS
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone())),
    );
    let Some((url, pwa)) = web else {
        return Ok(m);
    };
    if !configs.is_empty() {
        m.insert("3rdparty".into(), json!({ "extensions": configs }));
    }
    if pwa {
        m.insert(
            "WebAppInstallForceList".into(),
            json!([{"url": url, "default_launch_container": "window"}]),
        );
    }
    // 应用的非锁定键（例如 PrintingEnabled = true）盖在默认值上。
    m.extend(own);
    Ok(m)
}

/// `extensions` 的规则：id 是 32 个 a–p、不重复、不是考试扩展的 id（`ExtensionSettings` 以 id 为键，
/// 重复的会悄悄盖掉前一条）；`update_url` 与 `url` 同样的 https 与主机规则；`config` 转得成 JSON。
/// 返回有 `config` 的扩展的 id → 配置。
fn extensions(app: &KioskApp, exam: &ExamExtension) -> Result<Map<String, Value>, KioskError> {
    let bad = |message: String| fail("kiosk_extension_invalid", "extensions", message);
    let mut seen = BTreeSet::new();
    let mut configs = Map::new();
    for e in &app.extensions {
        if !extension_id_ok(&e.id) {
            return bad(format!(
                "Extension id {:?} must be 32 lowercase letters a-p",
                e.id
            ));
        }
        if e.id == exam.id {
            return bad(format!(
                "Extension {} is the MastersOS exam extension: it is always force-installed and need not be listed in extensions",
                e.id
            ));
        }
        if !seen.insert(e.id.as_str()) {
            return bad(format!("Extension {} is listed more than once", e.id));
        }
        if let Err(why) = https_host(&e.update_url) {
            return bad(format!(
                "Extension {} has update_url {:?} that {why}",
                e.id, e.update_url
            ));
        }
        if !e.config.is_empty() {
            let c = toml_table_to_json(&e.config).map_err(|why| KioskError {
                code: "kiosk_extension_invalid",
                message: format!(
                    "The config of extension {} cannot be converted to JSON: {why}",
                    e.id
                ),
                field: "extensions",
            })?;
            configs.insert(e.id.clone(), Value::Object(c));
        }
    }
    Ok(configs)
}

/// TOML 表 → JSON 对象（Chrome 策略用；分组的 `chrome_policy` 也走这里）。日期时间报错「Chrome 策略里不支持
/// 日期时间」；非有限的浮点数（`nan`、`inf`）JSON 表示不了，同样报错。错误前面带上键的路径（`键 A: 键 b: …`）。
pub fn toml_table_to_json(t: &toml::Table) -> Result<Map<String, Value>, String> {
    let mut m = Map::new();
    for (k, v) in t {
        m.insert(
            k.clone(),
            toml_to_json(v).map_err(|e| format!("key {k}: {e}"))?,
        );
    }
    Ok(m)
}

fn toml_to_json(v: &toml::Value) -> Result<Value, String> {
    Ok(match v {
        toml::Value::String(s) => Value::String(s.clone()),
        toml::Value::Integer(i) => Value::from(*i),
        toml::Value::Float(f) => match serde_json::Number::from_f64(*f) {
            Some(n) => Value::Number(n),
            None => {
                return Err(format!(
                    "non-finite number {f} is not supported in a Chrome policy"
                ))
            }
        },
        toml::Value::Boolean(b) => Value::Bool(*b),
        toml::Value::Datetime(_) => {
            return Err("datetime is not supported in a Chrome policy".into())
        }
        toml::Value::Array(a) => {
            Value::Array(a.iter().map(toml_to_json).collect::<Result<_, _>>()?)
        }
        toml::Value::Table(t) => Value::Object(toml_table_to_json(t)?),
    })
}

/// What is wrong with an app `name`, if anything. Shared by kiosk apps and `[config.apps.deb.<id>]`.
///
/// 名字写进账号的 GECOS（`usermod -c`）：`:` 是 passwd 的字段分隔符，写进去 usermod 拒绝、清理永远做不完；
/// `,` 分隔 GECOS 的子字段，accountsservice 只取第一个 `,` 之前的当名字，登录界面显示被截断。
pub fn name_problem(name: &str) -> Result<(), String> {
    if name.trim().is_empty()
        || has_control(name)
        || name.contains([':', ','])
        || name.chars().count() > MAX_NAME_CHARS
    {
        return Err(format!(
            "Name {name:?} must be non-empty, at most {MAX_NAME_CHARS} characters, and contain no colon :, comma , or control characters (newline, tab, etc.)"
        ));
    }
    Ok(())
}

/// Whether `id` is a valid app id: `^[a-z][a-z0-9-]{0,23}$`.
pub fn id_ok(id: &str) -> bool {
    id.len() <= MAX_ID_LEN
        && id.starts_with(|c: char| c.is_ascii_lowercase())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// id：`^[a-z][a-z0-9-]{0,23}$`。
pub fn check_id(id: &str) -> Result<(), KioskError> {
    if id_ok(id) {
        Ok(())
    } else {
        fail(
            "kiosk_id_invalid",
            "id",
            format!(
                "Kiosk app id {id:?} must start with a lowercase letter, contain only lowercase letters, digits and -, and be at most {MAX_ID_LEN} characters"
            ),
        )
    }
}

/// `https://` 开头、有内容，不含空白、控制字符、引号与反斜杠（这些会进 `.desktop` 与 JSON）。
pub(crate) fn https_url(u: &str) -> Result<&str, &'static str> {
    let Some(rest) = u.strip_prefix("https://") else {
        return Err("is not an https:// address");
    };
    if u.len() > MAX_URL_LEN {
        return Err("is too long");
    }
    if u.chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '\\'))
    {
        return Err("contains whitespace, control characters, quotes or a backslash");
    }
    if rest.is_empty() {
        return Err("has no host name");
    }
    Ok(rest)
}

/// `url` 的主机名（规范化后）；`url` 不合规报 `kiosk_url_not_https`。
fn url_host(u: &str) -> Result<String, KioskError> {
    https_host(u).or_else(|why| {
        fail(
            "kiosk_url_not_https",
            "url",
            format!("url {u:?} {why}; expected something like https://test.mapnwea.org/"),
        )
    })
}

/// https 地址（[`https_url`]）的主机名，规范化后；不带用户名或密码，端口可以有（放行名单按主机名）。
/// `url` 与扩展的 `update_url` 共用。
fn https_host(u: &str) -> Result<String, String> {
    let rest = https_url(u)?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return Err("must not carry a user name or password (@)".into());
    }
    let h = match authority.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => authority,
    };
    host(h).map_err(|why| format!("has host name {h:?} that {why}"))
}

/// 主机名：小写、去掉结尾的点之后，字符集同 [`checks::allowed_domain`]（小写字母、数字、. 与 -），
/// 至少两段、每段 1–63 字节，顶级域不是纯数字（挡住 IP 地址）。不许 `*`、路径、端口；
/// 非 ASCII 的国际化域名要写成 punycode。
fn host(d: &str) -> Result<String, String> {
    if !d.is_ascii() {
        return Err("contains non-ASCII characters (write internationalized domain names as punycode, xn--...)".into());
    }
    if d.contains('*') {
        return Err(
            "must not use the wildcard * (a host name already includes its subdomains)".into(),
        );
    }
    if d.contains(['/', ':']) {
        return Err("must not include a scheme, path or port".into());
    }
    let h = d.to_ascii_lowercase();
    let h = h.strip_suffix('.').unwrap_or(&h).to_string();
    checks::allowed_domain(&h)
        .map_err(|_| "may contain only letters, digits, . and -".to_string())?;
    let labels: Vec<&str> = h.split('.').collect();
    if labels.iter().any(|l| l.is_empty() || l.len() > 63) {
        return Err("has an empty label or one longer than 63 bytes".into());
    }
    if labels
        .iter()
        .any(|l| l.starts_with('-') || l.ends_with('-'))
    {
        return Err("has a label starting or ending with -".into());
    }
    if labels.len() < 2 {
        return Err("has a single label (a whole top-level domain cannot be allowed)".into());
    }
    if labels
        .last()
        .is_some_and(|t| t.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(
            "is not a host name (the top-level label is all digits, like an IP address)".into(),
        );
    }
    Ok(h)
}

/// An absolute path under one of `prefixes` (each ends in `/`): every segment non-empty, not `.` or `..`,
/// only letters, digits, `.`, `_`, `-`, `+`. No arguments, so no shell commands either.
pub(crate) fn abs_path_under(x: &str, prefixes: &[&str]) -> bool {
    x.len() <= 4096
        && prefixes.iter().any(|p| {
            x.strip_prefix(p).is_some_and(|rest| {
                rest.split('/').all(|seg| {
                    !seg.is_empty()
                        && seg != "."
                        && seg != ".."
                        && seg.bytes().all(|b| {
                            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+')
                        })
                })
            })
        })
}

/// `exec`：Flatpak id（[`checks::flatpak_id`]），或 `/usr/`、`/opt/` 下的绝对路径（见 [`abs_path_under`]）。
/// `/opt/` 是 .deb 应用（`[config.apps.deb]`）装的位置；lint 只查形状，这个路径是否由某个 .deb 应用提供由 agent 装好之后查。
fn exec(x: &str) -> Result<(), KioskError> {
    let ok = if x.starts_with('/') {
        abs_path_under(x, &["/usr/", "/opt/"])
    } else {
        checks::flatpak_id(x).is_ok()
    };
    if ok {
        Ok(())
    } else {
        fail(
            "kiosk_exec_invalid",
            "exec",
            format!(
                "exec {x:?} is neither a Flatpak id (for example org.example.App) nor an absolute path under /usr/ or /opt/ without ..; arguments are not allowed"
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{features_used, Manifest, FEATURE_KIOSK};

    fn parse(kiosk: &str) -> Manifest {
        Manifest::parse(&format!(
            "version = 1\n[[group]]\nid = \"default\"\nname = \"d\"\n{kiosk}"
        ))
        .unwrap()
    }

    /// 只有一个 kiosk 应用的清单，取出那个应用。
    fn app(fields: &str) -> KioskApp {
        let m = parse(&format!("[group.apps.kiosk.x]\n{fields}"));
        m.configs[0].apps.kiosk["x"].clone()
    }

    fn web(extra: &str) -> KioskApp {
        app(&format!(
            "name = \"NWEA MAP\"\nurl = \"https://test.mapnwea.org/\"\n{extra}"
        ))
    }

    /// TOML 的字符串字面量（Rust 的 `{:?}` 转义 TOML 不认）。
    fn q(s: &str) -> String {
        toml::Value::String(s.into()).to_string()
    }

    fn code(r: Result<(), KioskError>) -> &'static str {
        r.err().map(|e| e.code).unwrap_or("ok")
    }

    #[test]
    fn inline_and_full_table_forms_parse_equal() {
        let inline = parse(
            r#"[group.apps.kiosk]
nwea = { name = "NWEA MAP", url = "https://test.mapnwea.org/", allow = ["nwea.org", "mapnwea.org"], icon = "files/nwea.png", pwa = true, extensions = [{ id = "abcdefghijklmnopabcdefghijklmnop", update_url = "https://v.example/u.xml", config = { partner_code = "p" } }], chrome_policy = { PrintingEnabled = true } }
"#,
        );
        let full = parse(
            r#"[group.apps.kiosk.nwea]
name = "NWEA MAP"
url = "https://test.mapnwea.org/"
allow = ["nwea.org", "mapnwea.org"]
icon = "files/nwea.png"
pwa = true

[[group.apps.kiosk.nwea.extensions]]
id = "abcdefghijklmnopabcdefghijklmnop"
update_url = "https://v.example/u.xml"
config = { partner_code = "p" }

[group.apps.kiosk.nwea.chrome_policy]
PrintingEnabled = true
"#,
        );
        let a = &inline.configs[0].apps.kiosk["nwea"];
        assert_eq!(a, &full.configs[0].apps.kiosk["nwea"]);
        assert_eq!(a.extensions[0].config["partner_code"].as_str(), Some("p"));
        assert_eq!(a.chrome_policy["PrintingEnabled"].as_bool(), Some(true));
        // 内联写法后面还能接完整的表（设计 §3 的例子就是这样混写的）。
        let mixed = parse(
            r#"[group.apps.kiosk]
calc = { name = "计算器", exec = "org.example.Calculator" }

[group.apps.kiosk.map-pwa]
name = "NWEA MAP（PWA）"
url = "https://test.mapnwea.org/"
"#,
        );
        assert_eq!(mixed.configs[0].apps.kiosk.len(), 2);
    }

    #[test]
    fn defaults() {
        let a = web("");
        assert!(a.login_screen);
        assert!(!a.in_session);
        assert!(!a.pwa);
        assert!(a.allow.is_empty() && a.extensions.is_empty() && a.chrome_policy.is_empty());
        assert_eq!(a.icon, None);
        assert_eq!(a.user_agent, None);
        assert_eq!(a.android, None);
        assert_eq!(allow_hosts(&a).unwrap(), ["test.mapnwea.org"]);
        check("nwea", &a).unwrap();
        assert_eq!(
            launch(&a).unwrap(),
            KioskLaunch::Web {
                url: "https://test.mapnwea.org/",
                pwa: false
            }
        );
        assert_eq!(account_name("nwea"), "kiosk-nwea");
        assert_eq!(MAX_KIOSK_APPS, 32);
        // 写了 allow 就只用写的（规范化后），不再自动加 url 的主机。
        let a = web("allow = [\"nwea.org\", \"mapnwea.org\"]");
        assert_eq!(allow_hosts(&a).unwrap(), ["nwea.org", "mapnwea.org"]);
        // 没有分组里的 apps.kiosk：空表。
        assert!(parse("").configs[0].apps.kiosk.is_empty());
    }

    #[test]
    fn unknown_field_rejected() {
        let r = Manifest::parse(
            "version = 1\n[[group]]\nid = \"default\"\nname = \"d\"\n\
             [group.apps.kiosk.x]\nname = \"n\"\nurl = \"https://a.org/\"\ncolour = \"x\"",
        );
        assert!(r.is_err(), "{r:?}");
        let r = Manifest::parse(
            "version = 1\n[[group]]\nid = \"default\"\nname = \"d\"\n\
             [group.apps.kiosk.x]\nname = \"n\"\nurl = \"https://a.org/\"\n\
             extensions = [{ id = \"abcdefghijklmnopabcdefghijklmnop\", update_url = \"https://a.org/u\", x = 1 }]",
        );
        assert!(r.is_err(), "{r:?}");
        // name 必填。
        let r = Manifest::parse(
            "version = 1\n[[group]]\nid = \"default\"\nname = \"d\"\n\
             [group.apps.kiosk.x]\nurl = \"https://a.org/\"",
        );
        assert!(r.is_err(), "{r:?}");
    }

    #[test]
    fn launch_requires_exactly_one_of_url_exec() {
        let both = app("name = \"n\"\nurl = \"https://a.org/\"\nexec = \"org.example.Calc\"");
        let neither = app("name = \"n\"");
        let pwa_exec = app("name = \"n\"\nexec = \"org.example.Calc\"\npwa = true");
        let pwa_none = app("name = \"n\"\npwa = true");
        for (a, field) in [
            (&both, "exec"),
            (&neither, "url"),
            (&pwa_exec, "pwa"),
            (&pwa_none, "pwa"),
        ] {
            let e = launch(a).unwrap_err();
            assert_eq!(e.code, "kiosk_launch_invalid", "{a:?}");
            assert_eq!(e.field, field, "{a:?}");
            assert_eq!(code(check("x", a)), "kiosk_launch_invalid");
        }
        let calc = app("name = \"n\"\nexec = \"org.example.Calc\"");
        assert_eq!(
            launch(&calc).unwrap(),
            KioskLaunch::Exec("org.example.Calc")
        );
        let pwa = web("pwa = true");
        assert_eq!(
            launch(&pwa).unwrap(),
            KioskLaunch::Web {
                url: "https://test.mapnwea.org/",
                pwa: true
            }
        );
    }

    #[test]
    fn android_reserved() {
        for v in ["{}", "\"com.example\"", "true"] {
            let a = web(&format!("android = {v}"));
            let e = check("x", &a).unwrap_err();
            assert_eq!((e.code, e.field), ("kiosk_launch_invalid", "android"));
            assert_eq!(launch(&a).unwrap_err().code, "kiosk_launch_invalid");
        }
    }

    #[test]
    fn id_rules() {
        let a = web("");
        for ok in ["nwea", "a", "map-pwa", "a1-2", &"a".repeat(24)] {
            check(ok, &a).unwrap_or_else(|e| panic!("{ok}: {e:?}"));
        }
        for bad in [
            "NWEA",
            "1abc",
            &"a".repeat(25),
            "a_b",
            "",
            "-a",
            "a.b",
            "นว",
        ] {
            let e = check(bad, &a).unwrap_err();
            assert_eq!((e.code, e.field), ("kiosk_id_invalid", "id"), "{bad}");
        }
        // 账号名 kiosk-<id> 在 32 字节以内。
        assert!(account_name(&"a".repeat(24)).len() <= 32);
    }

    #[test]
    fn url_must_be_https() {
        let with = |u: &str| app(&format!("name = \"n\"\nurl = {}", q(u)));
        for ok in [
            "https://test.mapnwea.org/",
            "https://docs.google.com/forms/d/e/x/viewform?usp=1#a",
            "https://a.org:8443/x",
        ] {
            check("x", &with(ok)).unwrap_or_else(|e| panic!("{ok}: {e:?}"));
        }
        for bad in [
            "http://x.org/",
            "HTTPS://a.org/",
            "https://a.org/x y",
            "https://a.org/\tx",
            "https://a.org/\"x",
            "https://a.org/'x",
            "https://a.org/\\x",
            "https://",
            "https:///x",
            "https://u@a.org/",
            "https://localhost/",
            "file:///etc/passwd",
        ] {
            let e = check("x", &with(bad)).unwrap_err();
            assert_eq!((e.code, e.field), ("kiosk_url_not_https", "url"), "{bad}");
        }
        // 主机名同样规范化：大写、结尾的点。
        let a = with("https://Test.MapNWEA.org./x");
        assert_eq!(allow_hosts(&a).unwrap(), ["test.mapnwea.org"]);
    }

    #[test]
    fn allow_normalizes_and_rejects_non_ascii() {
        let a = web("allow = [\"NWEA.org.\", \"mapnwea.org\", \"xn--12c1fe0br.xn--o3cw4h\"]");
        assert_eq!(
            allow_hosts(&a).unwrap(),
            ["nwea.org", "mapnwea.org", "xn--12c1fe0br.xn--o3cw4h"]
        );
        check("x", &a).unwrap();
        for bad in [
            "*",
            "*.org",
            "org",
            "a.org/x",
            "a.org:443",
            "โรงเรียน.th",
            "",
            ".",
            "a..org",
            "10.0.0.5",
            "https://a.org",
            "a b.org",
        ] {
            let a = web(&format!("allow = [{}]", q(bad)));
            let e = check("x", &a).unwrap_err();
            assert_eq!((e.code, e.field), ("kiosk_allow_invalid", "allow"), "{bad}");
            assert_eq!(allow_hosts(&a).unwrap_err().code, "kiosk_allow_invalid");
        }
        // 非 ASCII 的提示要说写 punycode。
        let e = check("x", &web("allow = [\"โรงเรียน.th\"]")).unwrap_err();
        assert!(e.message.contains("xn--"), "{}", e.message);
    }

    #[test]
    fn exec_under_opt_ok() {
        let a = app("name = \"n\"\nexec = \"/opt/testnav/bin/testnav\"");
        check("x", &a).unwrap();
    }

    #[test]
    fn exec_rules() {
        let with = |x: &str| app(&format!("name = \"n\"\nexec = {}", q(x)));
        for ok in [
            "org.example.Calc",
            "/usr/bin/foo",
            "/usr/lib/x/run-me_2",
            "/opt/testnav/bin/testnav",
        ] {
            check("x", &with(ok)).unwrap_or_else(|e| panic!("{ok}: {e:?}"));
        }
        for bad in [
            "/etc/x",
            "/opt/",
            "/opt/../bin/sh",
            "/optx/y",
            "/usr/../bin/sh",
            "/usr/bin/../../bin/sh",
            "foo bar",
            "/usr/bin/foo bar",
            "/usr/",
            "/usr/bin/",
            "usr/bin/foo",
            "/usr/bin/foo;rm",
            "org.example",
            "sh -c x",
            "",
        ] {
            let e = check("x", &with(bad)).unwrap_err();
            assert_eq!((e.code, e.field), ("kiosk_exec_invalid", "exec"), "{bad}");
        }
    }

    #[test]
    fn extension_rules() {
        let ext = |id: &str, url: &str| {
            web(&format!(
                "[[group.apps.kiosk.x.extensions]]\nid = {}\nupdate_url = {}",
                q(id),
                q(url)
            ))
        };
        let good = "abcdefghijklmnopabcdefghijklmnop";
        check("x", &ext(good, "https://vendor.example/updates.xml")).unwrap();
        for (id, url) in [
            (
                "abcdefghijklmnopabcdefghijklmnoq",
                "https://v.example/u.xml",
            ),
            ("abcdefghijklmnopabcdefghijklmno", "https://v.example/u.xml"),
            (
                "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP",
                "https://v.example/u.xml",
            ),
            (good, "http://v.example/u.xml"),
            (good, "https://v.example/u xml"),
            (good, "https://v.example/\"u"),
            (good, ""),
        ] {
            let e = check("x", &ext(id, url)).unwrap_err();
            assert_eq!(
                (e.code, e.field),
                ("kiosk_extension_invalid", "extensions"),
                "{id} {url}"
            );
        }
    }

    #[test]
    fn user_agent_rules() {
        let ua = |s: &str| web(&format!("user_agent = {}", q(s)));
        check("x", &ua("Mozilla/5.0 (X11; Linux x86_64)")).unwrap();
        check("x", &ua(&"a".repeat(512))).unwrap();
        for bad in [ua(&"a".repeat(513)), ua("a\nb"), ua("a\u{7f}b")] {
            let e = check("x", &bad).unwrap_err();
            assert_eq!(
                (e.code, e.field),
                ("kiosk_user_agent_invalid", "user_agent")
            );
        }
        let exec = app("name = \"n\"\nexec = \"org.example.Calc\"\nuser_agent = \"x\"");
        let e = check("x", &exec).unwrap_err();
        assert_eq!(
            (e.code, e.field),
            ("kiosk_user_agent_invalid", "user_agent")
        );
    }

    #[test]
    fn name_rules() {
        let named = |n: &str| app(&format!("name = {}\nurl = \"https://a.org/\"", q(n)));
        for ok in ["NWEA MAP", "สอบกลางภาค", "期中考试 \"A\" \\ 1"] {
            check("x", &named(ok)).unwrap_or_else(|e| panic!("{ok}: {e:?}"));
        }
        for bad in ["", "  ", "a\nb", "a\tb", "a\u{1b}b"] {
            let e = check("x", &named(bad)).unwrap_err();
            assert_eq!((e.code, e.field), ("kiosk_name_invalid", "name"), "{bad:?}");
        }
        // 名字进账号的 GECOS（`usermod -c`）：`:` 是字段分隔符，不许；最多 MAX_NAME_CHARS 个字符（按字符数，不按字节）
        let thai64 = "ก".repeat(MAX_NAME_CHARS);
        assert_eq!(MAX_NAME_CHARS, 64);
        assert!(thai64.len() > MAX_NAME_CHARS, "泰文一个字三个字节");
        check("x", &named(&thai64)).unwrap();
        check("x", &named(&"a".repeat(64))).unwrap();
        for bad in [
            "NWEA: MAP".to_string(),
            ":".into(),
            // `,` 之后在 GECOS 里是别的子字段：accountsservice 只取第一个 `,` 之前的当名字，登录界面显示被截断
            "Math, Grade 5".into(),
            ",".into(),
            "a".repeat(65),
            "ก".repeat(65),
        ] {
            let e = check("x", &named(&bad)).unwrap_err();
            assert_eq!((e.code, e.field), ("kiosk_name_invalid", "name"), "{bad:?}");
        }
    }

    /// 写回（TOML 与 JSON）再读进来不变；缺省值不写出来，login_screen = false 要写出来。
    #[test]
    fn serialize_round_trips() {
        let a = web("login_screen = false\nin_session = true\npwa = true\nchrome_policy = { PrintingEnabled = true }");
        let text = toml::to_string(&a).unwrap();
        assert!(text.contains("login_screen = false"), "{text}");
        assert_eq!(toml::from_str::<KioskApp>(&text).unwrap(), a);
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(serde_json::from_str::<KioskApp>(&json).unwrap(), a);
        let plain = toml::to_string(&web("")).unwrap();
        assert_eq!(
            plain,
            "name = \"NWEA MAP\"\nurl = \"https://test.mapnwea.org/\"\n"
        );
    }

    #[test]
    fn features_used_includes_kiosk_when_any_group_has_one() {
        let m = parse("");
        assert!(!features_used(&m).contains(&FEATURE_KIOSK));
        let m = Manifest::parse(
            "version = 1\n[[group]]\nid = \"default\"\nname = \"d\"\n\
             [[group]]\nid = \"g\"\nname = \"g\"\n\
             [group.apps.kiosk]\ncalc = { name = \"c\", exec = \"org.example.Calc\" }",
        )
        .unwrap();
        assert_eq!(features_used(&m), [FEATURE_KIOSK]);
        assert_eq!(FEATURE_KIOSK, "kiosk");
    }

    // ---- 计划 9 Task 2：锁定会话的 Chrome 策略 ----

    const EXAM_ID: &str = "ponmlkjihgfedcbaponmlkjihgfedcba";
    const EXT_ID: &str = "abcdefghijklmnopabcdefghijklmnop";
    const HELPER_ID: &str = "aaaabbbbccccddddaaaabbbbccccdddd";

    fn exam() -> ExamExtension {
        ExamExtension {
            id: EXAM_ID.into(),
            update_url: "https://os.example/chrome/updates.xml".into(),
        }
    }

    /// 设计 §3 的 NWEA 样例。
    fn nwea(extra: &str) -> KioskApp {
        web(&format!(
            "allow = [\"nwea.org\", \"mapnwea.org\"]\n{extra}\n\
             [[group.apps.kiosk.x.extensions]]\nid = \"{EXT_ID}\"\n\
             update_url = \"https://vendor.example/updates.xml\"\n\
             config = {{ partner_code = \"p\", n = 3 }}"
        ))
    }

    fn policy(app: &KioskApp) -> serde_json::Value {
        serde_json::Value::Object(chrome_policy(app, &exam(), None).unwrap())
    }

    #[test]
    fn default_locks_present() {
        let p = policy(&nwea(""));
        let want = serde_json::json!({
            "URLBlocklist": ["*"],
            // 最后一项是本机的错误页（`mastersos-kiosk run` 在 Chrome 反复退出后打开它，计划 9 Task 6）
            "URLAllowlist": ["nwea.org", "mapnwea.org", "test.mapnwea.org", ERROR_PAGE],
            "DeveloperToolsAvailability": 2,
            "IncognitoModeAvailability": 1,
            "BrowserGuestModeEnabled": false,
            "BrowserAddPersonEnabled": false,
            "BrowserSignin": 0,
            "SyncDisabled": true,
            "DownloadRestrictions": 3,
            "AllowFileSelectionDialogs": false,
            "PrintingEnabled": false,
            // 终审 I3：翻译、拼写检查、Lens、生成式 AI、反馈默认关（应用可以打开）
            "TranslateEnabled": false,
            "SpellcheckEnabled": false,
            "LensOverlaySettings": 1,
            "GenAiDefaultSettings": 2,
            "UserFeedbackAllowed": false,
            "PasswordManagerEnabled": false,
            "AutofillAddressEnabled": false,
            "AutofillCreditCardEnabled": false,
            "TaskManagerEndProcessEnabled": false,
            "ScreenCaptureAllowed": false,
            "ExtensionInstallBlocklist": ["*"],
            "DefaultBrowserSettingEnabled": false,
            "PromotionalTabsEnabled": false,
            // 关窗口就是退出：后台模式下有 background 权限的扩展会让 Chrome 不退，run 等不到它（复审 M3）
            "BackgroundModeEnabled": false,
            "NativeMessagingBlocklist": ["*"],
            "NativeMessagingAllowlist": ["org.mastersos.kiosk_exit", "org.mastersos.support"],
            "NativeMessagingUserLevelHosts": false,
        });
        for (k, v) in want.as_object().unwrap() {
            assert_eq!(&p[k], v, "{k}");
        }
        // 没写 allow：只放行 url 的主机；allow 里重复的、与 url 主机相同的只留第一次。
        assert_eq!(
            policy(&web(""))["URLAllowlist"],
            serde_json::json!(["test.mapnwea.org", ERROR_PAGE])
        );
        let a = web("allow = [\"test.mapnwea.org\", \"nwea.org\", \"NWEA.org.\"]");
        assert_eq!(
            policy(&a)["URLAllowlist"],
            serde_json::json!(["test.mapnwea.org", "nwea.org", ERROR_PAGE])
        );
        // 表里每一条（除了可以打开的 OPTIONAL_DEFAULTS）都是锁定键，另加扩展与 PWA 的四个。
        let optional: Vec<&str> = OPTIONAL_DEFAULTS.iter().map(|(k, _)| *k).collect();
        assert_eq!(
            optional,
            [
                "PrintingEnabled",
                "TranslateEnabled",
                "SpellcheckEnabled",
                "LensOverlaySettings",
                "GenAiDefaultSettings",
                "UserFeedbackAllowed"
            ]
        );
        for k in want.as_object().unwrap().keys() {
            assert_eq!(
                LOCKED_KEYS.contains(&k.as_str()),
                !optional.contains(&k.as_str()),
                "{k}"
            );
        }
        for k in [
            "ExtensionSettings",
            "ExtensionInstallForcelist",
            "WebAppInstallForceList",
            "ExtensionInstallBlocklist",
        ] {
            assert!(LOCKED_KEYS.contains(&k), "{k}");
        }
        // 不是 PWA：不写 WebAppInstallForceList。
        assert!(p.get("WebAppInstallForceList").is_none());
    }

    #[test]
    fn extension_settings_force_exam_and_listed_only() {
        let p = policy(&nwea(""));
        let s = &p["ExtensionSettings"];
        assert_eq!(s["*"], serde_json::json!({"installation_mode": "blocked"}));
        assert_eq!(
            s[EXAM_ID],
            serde_json::json!({
                "installation_mode": "force_installed",
                "update_url": "https://os.example/chrome/updates.xml",
            })
        );
        assert_eq!(
            s[EXT_ID],
            serde_json::json!({
                "installation_mode": "force_installed",
                "update_url": "https://vendor.example/updates.xml",
            })
        );
        assert_eq!(s.as_object().unwrap().len(), 3, "{s}");
        assert_eq!(
            p["ExtensionInstallForcelist"],
            serde_json::json!([
                format!("{EXAM_ID};https://os.example/chrome/updates.xml"),
                format!("{EXT_ID};https://vendor.example/updates.xml"),
            ])
        );
        assert_eq!(
            p["3rdparty"],
            serde_json::json!({"extensions": {EXT_ID: {"partner_code": "p", "n": 3}}})
        );
        // 没有扩展、也没有 config：只强制安装考试扩展，不写 3rdparty。
        let p = policy(&web(""));
        assert_eq!(p["ExtensionSettings"].as_object().unwrap().len(), 2);
        assert!(p.get("3rdparty").is_none());
    }

    #[test]
    fn app_policy_overlays_non_locked_keys() {
        let p = policy(&nwea(
            "chrome_policy = { PrintingEnabled = true, HomepageLocation = \"https://a.org/\" }",
        ));
        assert_eq!(p["PrintingEnabled"], serde_json::json!(true));
        assert_eq!(p["HomepageLocation"], serde_json::json!("https://a.org/"));
        assert_eq!(p["URLBlocklist"], serde_json::json!(["*"]));
    }

    #[test]
    fn locked_key_override_is_error() {
        for k in LOCKED_KEYS {
            let a = nwea(&format!("chrome_policy = {{ {} = 1 }}", q(k)));
            let e = chrome_policy(&a, &exam(), None).unwrap_err();
            assert_eq!(
                (e.code, e.field),
                ("kiosk_policy_locked", "chrome_policy"),
                "{k}"
            );
            assert!(e.message.contains(k), "{}", e.message);
            // check（lint 与 agent 用的）也报它。
            assert_eq!(code(check("x", &a)), "kiosk_policy_locked", "{k}");
        }
        // 日期时间 JSON 表示不了。
        let a = nwea("chrome_policy = { When = 2026-10-16 }");
        let e = chrome_policy(&a, &exam(), None).unwrap_err();
        assert_eq!((e.code, e.field), ("kiosk_policy_invalid", "chrome_policy"));
        assert!(e.message.contains("datetime"), "{}", e.message);
        assert_eq!(code(check("x", &a)), "kiosk_policy_invalid");
    }

    /// 复审 fix 1：已弃用的旧名也锁上（新名没设时 Chrome 读旧名）。
    #[test]
    fn deprecated_aliases_locked() {
        for k in [
            "ExtensionInstallWhitelist",
            "ExtensionInstallBlacklist",
            "URLWhitelist",
            "URLBlacklist",
        ] {
            let a = nwea(&format!("chrome_policy = {{ {k} = [\"*\"] }}"));
            let e = chrome_policy(&a, &exam(), None).unwrap_err();
            assert_eq!(
                (e.code, e.field),
                ("kiosk_policy_locked", "chrome_policy"),
                "{k}"
            );
            assert_eq!(code(check("x", &a)), "kiosk_policy_locked", "{k}");
        }
    }

    /// 复审 fix 2：「退出」与「Get help」靠原生消息——只放行 MastersOS 的两个宿主、不许用户级宿主，应用改不了。
    #[test]
    fn native_messaging_pinned_to_exit_host() {
        for app in [nwea(""), nwea("pwa = true"), web("")] {
            let p = policy(&app);
            assert_eq!(
                p["NativeMessagingAllowlist"],
                serde_json::json!([EXIT_HOST, SUPPORT_HOST])
            );
            assert_eq!(p["NativeMessagingUserLevelHosts"], serde_json::json!(false));
            assert_eq!(p["NativeMessagingBlocklist"], serde_json::json!(["*"]));
        }
        assert_eq!(EXIT_HOST, "org.mastersos.kiosk_exit");
        assert_eq!(SUPPORT_HOST, "org.mastersos.support");
        for (k, v) in [
            ("NativeMessagingBlocklist", "[\"*\"]"),
            ("NativeMessagingAllowlist", "[\"com.evil\"]"),
            ("NativeMessagingUserLevelHosts", "true"),
        ] {
            let a = nwea(&format!("chrome_policy = {{ {k} = {v} }}"));
            let e = chrome_policy(&a, &exam(), None).unwrap_err();
            assert_eq!(
                (e.code, e.field),
                ("kiosk_policy_locked", "chrome_policy"),
                "{k}"
            );
        }
        // 本地程序的会话没有考试扩展：一个宿主都不放行（终审 I1）。
        let calc = app("name = \"n\"\nexec = \"org.example.Calc\"");
        let p = chrome_policy(&calc, &exam(), None).unwrap();
        assert_eq!(p["NativeMessagingAllowlist"], serde_json::json!([]));
        assert_eq!(p["NativeMessagingBlocklist"], serde_json::json!(["*"]));
        assert_eq!(p["NativeMessagingUserLevelHosts"], serde_json::json!(false));
    }

    /// 复审 fix 5：报错只点名写了的锁定键，不把整张锁定表抄进来。
    #[test]
    fn locked_message_names_only_offending_keys() {
        let a = nwea("chrome_policy = { SyncDisabled = false, PrintingEnabled = true }");
        let e = chrome_policy(&a, &exam(), None).unwrap_err();
        assert!(e.message.contains("SyncDisabled"), "{}", e.message);
        assert!(!e.message.contains("URLBlocklist"), "{}", e.message);
        assert!(!e.message.contains("PrintingEnabled"), "{}", e.message);
        let a = nwea("chrome_policy = { SyncDisabled = false, BrowserSignin = 1 }");
        let e = chrome_policy(&a, &exam(), None).unwrap_err();
        assert!(
            e.message.contains("SyncDisabled") && e.message.contains("BrowserSignin"),
            "{}",
            e.message
        );
        assert!(!e.message.contains("URLAllowlist"), "{}", e.message);
    }

    /// 控制者裁定：应用带扩展只能写 `extensions`，放开安装的三条策略也是锁定键。
    #[test]
    fn extension_install_policies_locked() {
        for k in [
            "ExtensionInstallAllowlist",
            "ExtensionInstallSources",
            "ExtensionAllowedTypes",
        ] {
            let a = nwea(&format!("chrome_policy = {{ {k} = [\"*\"] }}"));
            let e = chrome_policy(&a, &exam(), None).unwrap_err();
            assert_eq!(
                (e.code, e.field),
                ("kiosk_policy_locked", "chrome_policy"),
                "{k}"
            );
            assert_eq!(code(check("x", &a)), "kiosk_policy_locked", "{k}");
        }
    }

    #[test]
    fn pwa_adds_web_app_install_force_list() {
        let p = policy(&nwea("pwa = true"));
        assert_eq!(
            p["WebAppInstallForceList"],
            serde_json::json!([{
                "url": "https://test.mapnwea.org/",
                "default_launch_container": "window",
            }])
        );
    }

    /// 只看应用自己的 `chrome_policy`：分组的那份不继承（签名里就没有分组）。
    #[test]
    fn group_policy_not_inherited() {
        let m = Manifest::parse(
            "version = 1\n[[group]]\nid = \"default\"\nname = \"d\"\n\
             [group.chrome_policy]\nHomepageLocation = \"https://school.th/\"\nBookmarkBarEnabled = true\n\
             [group.apps.kiosk.x]\nname = \"n\"\nurl = \"https://a.org/\"\n",
        )
        .unwrap();
        assert!(!m.configs[0].chrome_policy.is_empty());
        let p = chrome_policy(&m.configs[0].apps.kiosk["x"], &exam(), None).unwrap();
        assert!(!p.contains_key("HomepageLocation") && !p.contains_key("BookmarkBarEnabled"));
    }

    #[test]
    fn exec_app_gets_deny_all_policy() {
        // 终审 I1：程序里的链接在同一个命名空间里起 Chrome——它拿同一套默认锁，什么网站都不放行（只有错误页），
        // 不强制安装任何扩展（考试扩展也不装），不叠应用自己的 chrome_policy。
        let a = app(&format!(
            "name = \"n\"\nexec = \"org.example.Calc\"\nallow = [\"example.org\"]\n\
             chrome_policy = {{ PrintingEnabled = true, HomepageLocation = \"https://a.org/\" }}\n\
             [[group.apps.kiosk.x.extensions]]\nid = \"{EXT_ID}\"\n\
             update_url = \"https://vendor.example/updates.xml\"\nconfig = {{ k = 1 }}"
        ));
        let p = chrome_policy(&a, &exam(), None).unwrap();
        let w = serde_json::Value::Object(chrome_policy(&nwea(""), &exam(), None).unwrap());
        assert_eq!(p["URLBlocklist"], serde_json::json!(["*"]));
        assert_eq!(p["URLAllowlist"], serde_json::json!([ERROR_PAGE]));
        assert_eq!(p["ExtensionInstallForcelist"], serde_json::json!([]));
        assert_eq!(
            p["ExtensionSettings"],
            serde_json::json!({"*": {"installation_mode": "blocked"}})
        );
        assert!(!p.contains_key("3rdparty"));
        assert!(!p.contains_key("WebAppInstallForceList"));
        assert!(!p.contains_key("HomepageLocation"));
        assert_eq!(p["NativeMessagingAllowlist"], serde_json::json!([]));
        assert_eq!(p["PrintingEnabled"], serde_json::json!(false));
        // 其余每一个锁定键与默认值都与网页应用的相同
        for k in LOCKED_KEYS
            .iter()
            .copied()
            .chain(OPTIONAL_DEFAULTS.iter().map(|(k, _)| *k))
        {
            if [
                "URLAllowlist",
                "NativeMessagingAllowlist",
                "ExtensionInstallForcelist",
                "ExtensionSettings",
                "WebAppInstallForceList",
                "3rdparty",
            ]
            .contains(&k)
                || w.get(k).is_none()
            {
                continue;
            }
            assert_eq!(p.get(k), w.get(k), "{k}");
        }
        // 应用的 chrome_policy 照样校验：锁定键照样是错误
        let locked =
            app("name = \"n\"\nexec = \"org.example.Calc\"\nchrome_policy = { URLBlocklist = [] }");
        assert_eq!(
            chrome_policy(&locked, &exam(), None).unwrap_err().code,
            "kiosk_policy_locked"
        );
        // 不合规的应用照样报错，不是策略。
        let bad = app("name = \"n\"\nexec = \"/etc/x\"");
        assert_eq!(
            chrome_policy(&bad, &exam(), None).unwrap_err().code,
            "kiosk_exec_invalid"
        );
    }

    /// 终审 I3：翻译等默认关，应用可以在自己的 chrome_policy 里打开（不是锁定键）。
    #[test]
    fn optional_defaults_overridable() {
        let p = policy(&web(
            "chrome_policy = { TranslateEnabled = true, SpellcheckEnabled = true, LensOverlaySettings = 0, \
             GenAiDefaultSettings = 0, UserFeedbackAllowed = true }",
        ));
        assert_eq!(p["TranslateEnabled"], serde_json::json!(true));
        assert_eq!(p["SpellcheckEnabled"], serde_json::json!(true));
        assert_eq!(p["LensOverlaySettings"], serde_json::json!(0));
        assert_eq!(p["GenAiDefaultSettings"], serde_json::json!(0));
        assert_eq!(p["UserFeedbackAllowed"], serde_json::json!(true));
        let d = policy(&web(""));
        for (k, v) in OPTIONAL_DEFAULTS.iter() {
            assert_eq!(&d[*k], v, "{k}");
            assert!(!LOCKED_KEYS.contains(k), "{k}");
        }
    }

    /// Task 1 复审：update_url 与 url 一样要有主机名、不带用户名。
    #[test]
    fn extension_update_url_host_checked() {
        for url in [
            "https:///x",
            "https://u@x.org/",
            "https://localhost/u.xml",
            "https://-a.org/u",
        ] {
            let a = web(&format!(
                "[[group.apps.kiosk.x.extensions]]\nid = \"{EXT_ID}\"\nupdate_url = {}",
                q(url)
            ));
            let e = check("x", &a).unwrap_err();
            assert_eq!(
                (e.code, e.field),
                ("kiosk_extension_invalid", "extensions"),
                "{url}"
            );
        }
    }

    /// The image's local manifest is for the exam extension only: a school's extension cannot point at disk.
    #[test]
    fn school_extension_cannot_use_local_update_url() {
        let a = web(&format!(
            "[[group.apps.kiosk.x.extensions]]\nid = \"{EXT_ID}\"\nupdate_url = {}",
            q(EXAM_LOCAL_UPDATE_URL)
        ));
        let e = check("x", &a).unwrap_err();
        assert_eq!((e.code, e.field), ("kiosk_extension_invalid", "extensions"));
    }

    /// Task 1 复审：主机名的段不能以 - 开头或结尾。
    #[test]
    fn host_labels_no_leading_or_trailing_hyphen() {
        for bad in ["-a.org", "a-.org", "a.-b.org", "a.org-"] {
            let e = check("x", &web(&format!("allow = [{}]", q(bad)))).unwrap_err();
            assert_eq!(e.code, "kiosk_allow_invalid", "{bad}");
            let u = app(&format!(
                "name = \"n\"\nurl = {}",
                q(&format!("https://{bad}/"))
            ));
            assert_eq!(
                check("x", &u).unwrap_err().code,
                "kiosk_url_not_https",
                "{bad}"
            );
        }
        check("x", &web("allow = [\"a-b.org\", \"xn--o3cw4h.th\"]")).unwrap();
    }

    /// Task 1 复审：ExtensionSettings 以 id 为键，重复的 id 会悄悄盖掉前一条；考试扩展的 id 也不能写。
    #[test]
    fn duplicate_extension_ids_rejected() {
        let two = |a: &str, b: &str| {
            web(&format!(
                "[[group.apps.kiosk.x.extensions]]\nid = \"{a}\"\nupdate_url = \"https://v.example/1\"\n\
                 [[group.apps.kiosk.x.extensions]]\nid = \"{b}\"\nupdate_url = \"https://v.example/2\""
            ))
        };
        check("x", &two(EXT_ID, EXAM_ID)).unwrap();
        let e = check("x", &two(EXT_ID, EXT_ID)).unwrap_err();
        assert_eq!((e.code, e.field), ("kiosk_extension_invalid", "extensions"));
        assert_eq!(
            chrome_policy(&two(EXT_ID, EXT_ID), &exam(), None)
                .unwrap_err()
                .code,
            "kiosk_extension_invalid"
        );
        // 写了考试扩展自己的 id：check 不知道真 id（占位），chrome_policy 知道。
        let e = chrome_policy(&two(EXT_ID, EXAM_ID), &exam(), None).unwrap_err();
        assert_eq!((e.code, e.field), ("kiosk_extension_invalid", "extensions"));
    }

    /// 从 agent 挪过来的转换：整数不变浮点、日期时间与非有限数报错（带键路径）。
    #[test]
    fn toml_table_to_json_converts() {
        let t: toml::Table = "A = 1\nB = 1.5\nC = [\"x\", true]\n[D]\nE = { F = 2 }\n"
            .parse()
            .unwrap();
        let j = toml_table_to_json(&t).unwrap();
        assert_eq!(
            serde_json::Value::Object(j.clone()),
            serde_json::json!({"A": 1, "B": 1.5, "C": ["x", true], "D": {"E": {"F": 2}}})
        );
        assert!(j["A"].is_i64());
        let t: toml::Table = "A = [{ b = 1979-05-27 }]\n".parse().unwrap();
        assert_eq!(
            toml_table_to_json(&t).unwrap_err(),
            "key A: key b: datetime is not supported in a Chrome policy"
        );
        let t: toml::Table = "A = nan\n".parse().unwrap();
        assert!(toml_table_to_json(&t).unwrap_err().contains("non-finite"));
    }

    /// The local manifest is accepted as one exact string: no prefix match, no path normalisation.
    #[test]
    fn exam_extension_local_url_is_exact() {
        let with = |url: &str| ExamExtension {
            id: "abcdefghijklmnopabcdefghijklmnop".into(),
            update_url: url.into(),
        };
        assert_eq!(with(EXAM_LOCAL_UPDATE_URL).check(), Ok(()));
        for url in [
            "file:///usr/lib/mastersos/kiosk-ext/other.xml",
            "file:///usr/lib/mastersos/kiosk-ext/updates.xml.bak",
            "file:///usr/lib/mastersos/kiosk-ext/",
            "file:///var/lib/mastersos-public/kext/updates.xml",
            "file:///home/kiosk-nwea/updates.xml",
            "file:///usr/lib/mastersos/kiosk-ext/../kiosk-ext/updates.xml",
            "file:///usr/lib/mastersos/../mastersos/kiosk-ext/updates.xml",
            "file:///usr/lib/mastersos/kiosk-ext//updates.xml",
            "file:///usr/lib/mastersos/kiosk-ext/updates.xml?v=1",
            "file:///usr/lib/mastersos/kiosk-ext/updates.xml#a",
            "file://localhost/usr/lib/mastersos/kiosk-ext/updates.xml",
            "FILE:///usr/lib/mastersos/kiosk-ext/updates.xml",
            " file:///usr/lib/mastersos/kiosk-ext/updates.xml",
            "file:///usr/lib/mastersos/kiosk-ext/updates.xml ",
            "http:///usr/lib/mastersos/kiosk-ext/updates.xml",
            "http://os.khundavid.com/usr/lib/mastersos/kiosk-ext/updates.xml",
        ] {
            assert!(with(url).check().is_err(), "{url}");
        }
    }

    /// 镜像里的 `kiosk-ext.json` 读出来之后 agent 先校验（裁定 R1）：id 与 `extensions` 同一条规则，
    /// `update_url` 与扩展的 `update_url` 同一条 https 与主机规则。
    #[test]
    fn exam_extension_check() {
        let ok = ExamExtension {
            id: "abcdefghijklmnopabcdefghijklmnop".into(),
            update_url: "https://os.khundavid.com/chrome/updates.xml".into(),
        };
        assert_eq!(ok.check(), Ok(()));
        for (id, url) in [
            (
                "abcdefghijklmnopabcdefghijklmnoq",
                "https://os.khundavid.com/u.xml",
            ),
            ("abcdefghijklmnop", "https://os.khundavid.com/u.xml"),
            (
                "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP",
                "https://os.khundavid.com/u.xml",
            ),
            ("", "https://os.khundavid.com/u.xml"),
            (ok.id.as_str(), "http://os.khundavid.com/u.xml"),
            (ok.id.as_str(), "https://user@os.khundavid.com/u.xml"),
            (ok.id.as_str(), "https://localhost/u.xml"),
            (ok.id.as_str(), "https://10.0.0.1/u.xml"),
            (ok.id.as_str(), "https://os.khundavid.com/u \"x\".xml"),
            (ok.id.as_str(), ""),
        ] {
            let e = ExamExtension {
                id: id.into(),
                update_url: url.into(),
            };
            assert!(e.check().is_err(), "{id} {url}");
        }
    }

    /// Design 2026-11-06-kiosk-platform-inject §1: `platform` is only "chromeos", only on web apps
    /// without pwa, never with user_agent.
    #[test]
    fn platform_rules() {
        assert_eq!(code(check("x", &web("platform = \"chromeos\""))), "ok");
        for extra in [
            "platform = \"ChromeOS\"",
            "platform = \"windows\"",
            "platform = \"chromeos\"\npwa = true",
            "platform = \"chromeos\"\nuser_agent = \"X\"",
        ] {
            let e = check("x", &web(extra)).unwrap_err();
            assert_eq!(
                (e.code, e.field),
                ("kiosk_platform_invalid", "platform"),
                "{extra}"
            );
        }
        let calc =
            app("name = \"Calc\"\nexec = \"/usr/bin/gnome-calculator\"\nplatform = \"chromeos\"");
        assert_eq!(code(check("x", &calc)), "kiosk_platform_invalid");
    }

    #[test]
    fn inject_rules() {
        for ok in ["files/testnav.js", "files/a/b.js"] {
            assert_eq!(
                code(check("x", &web(&format!("inject = {}", q(ok))))),
                "ok",
                "{ok}"
            );
        }
        for bad in [
            "testnav.js",
            "files/testnav.mjs",
            "files/.js",
            "files/../x.js",
            "files//x.js",
            "scripts/x.js",
            "https://x.example/a.js",
        ] {
            let e = check("x", &web(&format!("inject = {}", q(bad)))).unwrap_err();
            assert_eq!(
                (e.code, e.field),
                ("kiosk_inject_invalid", "inject"),
                "{bad}"
            );
        }
        let e = check("x", &web("inject = \"files/a.js\"\npwa = true")).unwrap_err();
        assert_eq!(e.code, "kiosk_inject_invalid");
        let calc =
            app("name = \"Calc\"\nexec = \"/usr/bin/gnome-calculator\"\ninject = \"files/a.js\"");
        assert_eq!(code(check("x", &calc)), "kiosk_inject_invalid");
    }

    #[test]
    fn inject_source_rules() {
        assert_eq!(check_inject_source(b"console.log(1);\n"), Ok(()));
        assert_eq!(check_inject_source(&vec![b' '; MAX_INJECT_BYTES]), Ok(()));
        assert!(check_inject_source(&vec![b' '; MAX_INJECT_BYTES + 1]).is_err());
        assert!(check_inject_source(b"\xff\xfe").is_err());
        assert!(check_inject_source(b"a\0b").is_err());
    }

    #[test]
    fn start_page_allowlist_and_platform_extension() {
        let platform = PlatformExtension {
            id: HELPER_ID.into(),
            update_url: "file:///var/lib/mastersos-public/kiosk/x/platform/updates.xml".into(),
        };
        let plain = chrome_policy(&nwea(""), &exam(), None).unwrap();
        assert!(!plain["URLAllowlist"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str().unwrap().starts_with("chrome-extension://")));
        assert!(plain["3rdparty"]["extensions"].get(EXAM_ID).is_none());
        let a = nwea("platform = \"chromeos\"\ninject = \"files/nwea.js\"");
        let p = chrome_policy(&a, &exam(), Some(&platform)).unwrap();
        let allow: Vec<&str> = p["URLAllowlist"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        // the platform extension's start page, not the exam extension's (it has none)
        assert_eq!(
            allow,
            [
                "nwea.org",
                "mapnwea.org",
                "test.mapnwea.org",
                &format!("chrome-extension://{HELPER_ID}"),
                ERROR_PAGE
            ]
        );
        let forced = p["ExtensionInstallForcelist"].as_array().unwrap();
        assert_eq!(forced[1], format!("{HELPER_ID};{}", platform.update_url));
        assert_eq!(
            p["ExtensionSettings"][HELPER_ID],
            json!({"installation_mode": "force_installed", "update_url": platform.update_url})
        );
        // the exam extension takes {cmd:"exit"} from that id only, next to the vendors' own configs
        assert_eq!(
            p["3rdparty"],
            json!({"extensions": {
                EXAM_ID: {EXAM_PLATFORM_KEY: HELPER_ID},
                EXT_ID: {"partner_code": "p", "n": 3},
            }})
        );
        // the platform extension cannot be listed by the app
        let b = web(&format!(
            "platform = \"chromeos\"\n[[group.apps.kiosk.x.extensions]]\nid = \"{HELPER_ID}\"\n\
             update_url = \"https://vendor.example/updates.xml\""
        ));
        assert_eq!(
            chrome_policy(&b, &exam(), Some(&platform))
                .unwrap_err()
                .code,
            "kiosk_extension_invalid"
        );
        let cfg = platform_config(&a, EXAM_ID).unwrap();
        assert_eq!(
            cfg,
            json!({
                "v": 1,
                "url": "https://test.mapnwea.org/",
                "hosts": ["nwea.org", "mapnwea.org", "test.mapnwea.org"],
                "platform": "chromeos",
                "inject": true,
                "exam": EXAM_ID,
            })
        );
        let only = platform_config(&web("platform = \"chromeos\""), EXAM_ID).unwrap();
        assert_eq!(only["hosts"], json!(["test.mapnwea.org"]));
        assert_eq!(only["inject"], json!(false));
    }

    #[test]
    fn platform_and_inject_are_features() {
        use crate::{FEATURE_KIOSK_INJECT, FEATURE_KIOSK_PLATFORM};
        let m = parse("[group.apps.kiosk.x]\nname = \"X\"\nurl = \"https://x.example/\"\nplatform = \"chromeos\"\ninject = \"files/x.js\"\n");
        let used = features_used(&m);
        assert!(used.contains(&FEATURE_KIOSK_PLATFORM), "{used:?}");
        assert!(used.contains(&FEATURE_KIOSK_INJECT), "{used:?}");
        let m = parse("[group.apps.kiosk.x]\nname = \"X\"\nurl = \"https://x.example/\"\n");
        assert_eq!(features_used(&m), [FEATURE_KIOSK]);
        assert_eq!(FEATURE_KIOSK_PLATFORM, "kiosk_platform");
        assert_eq!(FEATURE_KIOSK_INJECT, "kiosk_inject");
    }
}
