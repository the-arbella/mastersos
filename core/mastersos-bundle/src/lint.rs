//! 发布前 lint：内容规则，只在服务端发布 / 起草时检查。
//!
//! 刻意不放进 `Manifest::validate`：agent 开机时会对本地的包重跑 `validate`，
//! 收紧它会让现场一台已经接受了这种包的机器开机就丢掉当前设置。

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

#[cfg(test)]
use crate::ResetRequest;
use crate::{
    checks, effective_config, kiosk, Apps, ChromeUpdate, Config, ConfigLayer, Defaults, ItAccount,
    LoginMethod, Manifest, NetDevice, Shape, Wifi,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum LintLevel {
    /// Blocks publishing.
    Error,
    /// Shown only. One exception outside the bundle: `mastersos publish` refuses while a
    /// `secret_rerouted` warning exists until IT approves that secret by name.
    Warning,
    /// Reports the current state (for example which configs pause Chrome updates); not a problem.
    Info,
}

/// A range in the source text; line and column are 1-based, and `end_*` is the position just past the last character.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Span {
    pub line: u32,
    pub column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Lint {
    pub level: LintLevel,
    /// Stable identifier; never changes once published (the web UI translates by it).
    pub code: &'static str,
    /// English, one sentence: where, why, how to fix.
    pub message: String,
    /// Like `config.student.apps.web[0].icon`.
    pub path: Option<String>,
    /// Values the message was built from, for translation; always serialized (`{}` when empty).
    /// Never holds secrets.
    pub params: BTreeMap<&'static str, String>,
    /// Where in the source text; `null` when unknown.
    pub span: Option<Span>,
}

impl Lint {
    pub fn new(level: LintLevel, code: &'static str, message: impl Into<String>) -> Lint {
        Lint {
            level,
            code,
            message: message.into(),
            path: None,
            params: BTreeMap::new(),
            span: None,
        }
    }

    pub fn at(mut self, path: impl Into<String>) -> Lint {
        self.path = Some(path.into());
        self
    }

    pub fn param(mut self, key: &'static str, value: impl ToString) -> Lint {
        self.params.insert(key, value.to_string());
        self
    }
}

/// Whether any lint is error level.
pub fn has_errors(lints: &[Lint]) -> bool {
    lints.iter().any(|l| l.level == LintLevel::Error)
}

/// 镜像发布的更新通道（Ruling 5）。
pub const UPDATE_CHANNELS: &[&str] = &["stable", "beta"];

/// 按今天（UTC）的日期 lint，见 [`lint_at`]。
pub fn lint(m: &Manifest, present: &BTreeSet<String>) -> Vec<Lint> {
    lint_at(m, present, chrono::Utc::now().date_naive())
}

/// A lint about Config `c`: its id in the `config` param, and in `group` as well, the param the
/// web UI translated these lints with before configs existed.
fn about(l: Lint, c: &ConfigLayer) -> Lint {
    l.param("config", &c.id).param("group", &c.id)
}

/// `today` 是发布日：只有 Chrome 暂停更新的规则（距发布日不超过 14 天、哪些配置在暂停）看它。
///
/// Two kinds of rule (phase B design §4.2). Format rules look at each layer as written
/// (`[defaults]`, then every `[[config]]`), so a bad entry in the Defaults is reported once, at
/// `defaults.…`, not once per Config that inherits it. Semantic rules look at each Config's
/// [`effective_config`]: the path names the key the Config wrote, or `defaults.<key>` when the
/// value is inherited, and one `(code, path)` is reported once, naming every Config it concerns.
pub fn lint_at(m: &Manifest, present: &BTreeSet<String>, today: chrono::NaiveDate) -> Vec<Lint> {
    let mut out = Vec::new();
    lint_shape(m, &mut out);
    let configs: Vec<(&ConfigLayer, Config)> = m
        .configs
        .iter()
        .map(|g| (g, effective_config(m, g)))
        .collect();
    if m.school.oidc.is_none() {
        let hits = configs
            .iter()
            .filter(|(_, e)| e.login_methods.contains(&LoginMethod::Sso))
            .map(|(g, _)| (pick(m, g.login_methods.is_some(), g, "login_methods"), *g))
            .collect();
        for (path, cs) in group_hits(hits) {
            out.push(many(
                Lint::new(
                    LintLevel::Error,
                    "sso_without_oidc",
                    format!(
                        "{} allows sso login but [school].oidc is not configured: there is nowhere to sign in on its Devices; add [school].oidc or remove sso from login_methods.",
                        subject(&path, &cs)
                    ),
                )
                .at(path.clone()),
                &path,
                &cs,
            ));
        }
    }
    let views = views(m);
    for v in &views {
        lint_web_apps(v, present, &mut out);
        lint_kiosk(v, present, &mut out);
    }
    lint_kiosk_semantics(m, &configs, &mut out);
    let channels = std::iter::once((
        "school.update_channel".to_owned(),
        Some(&m.school.update_channel),
    ))
    .chain(m.defaults.iter().map(|d| {
        (
            "defaults.update_channel".to_owned(),
            d.update_channel.as_ref(),
        )
    }))
    .chain(m.configs.iter().map(|c| {
        (
            format!("config.{}.update_channel", c.id),
            c.update_channel.as_ref(),
        )
    }));
    for (at, channel) in channels {
        let Some(channel) = channel else { continue };
        if !UPDATE_CHANNELS.contains(&channel.as_str()) {
            out.push(
                Lint::new(
                    LintLevel::Error,
                    "update_channel_unknown",
                    format!(
                        "Update channel {channel:?} is not stable or beta: machines treat it as stable and report a failure; use stable or beta."
                    ),
                )
                .at(at)
                .param("channel", channel),
            );
        }
    }
    if let Some(o) = &m.school.oidc {
        if let Err(e) = checks::oidc(o) {
            out.push(err("oidc_invalid", e, "school.oidc".into()));
        }
    }
    lint_formats(m, &views, &configs, &mut out);
    lint_chrome(m, &views, &configs, today, &mut out);
    for (i, d) in m.devices.iter().enumerate() {
        let who = d
            .serial
            .as_deref()
            .or(d.device_id.as_deref())
            .unwrap_or("?");
        if let Some(Err(e)) = d.reset.as_ref().map(|r| r.check_id()) {
            out.push(
                Lint::new(LintLevel::Error, "device_reset_id_invalid", e)
                    .at(format!("device[{i}].reset.id"))
                    .param("device", who),
            );
        }
        if let Some(Err(e)) = d.locked.as_ref().map(|k| checks::lock_message(&k.message)) {
            out.push(err(
                "lock_message_too_long",
                e,
                format!("device[{i}].locked.message"),
            ));
        }
        if d.reset.is_some() {
            out.push(
                Lint::new(
                    LintLevel::Warning,
                    "device_reset_requested",
                    format!(
                        "Device {who} has a legacy `reset` request: Devices ignore it. Factory reset is done from the Devices page (the Device inbox); remove `reset` from the settings."
                    ),
                )
                .at(format!("device[{i}]"))
                .param("device", who),
            );
        }
    }
    out
}

/// One layer of written settings, for the format rules: `[defaults]` (`config` is `None`) or a
/// `[[config]]`. Both hold the same keys, so the rules take this instead of either type.
struct View<'a> {
    /// The lint path prefix: `defaults` or `config.<id>`.
    base: String,
    config: Option<&'a ConfigLayer>,
    wifi: &'a [Wifi],
    apps: &'a Apps,
    printers: &'a [NetDevice],
    scanners: &'a [NetDevice],
    it_account: Option<&'a ItAccount>,
    chrome: &'a ChromeUpdate,
}

impl View<'_> {
    /// A lint about this layer: a Config's own carry [`about`]'s params, the Defaults' say
    /// `layer = defaults` (no Config is to blame).
    fn tag(&self, l: Lint) -> Lint {
        match self.config {
            Some(c) => about(l, c),
            None => l.param("layer", "defaults"),
        }
    }

    /// How messages name the layer: `config teacher` or `[defaults]`.
    fn who(&self) -> String {
        match self.config {
            Some(c) => format!("config {}", c.id),
            None => "[defaults]".into(),
        }
    }

    /// The `layer` param of `it_account_invalid`: `defaults` or the Config's id.
    fn layer_id(&self) -> &str {
        self.config.map_or("defaults", |c| c.id.as_str())
    }
}

/// `[defaults]` (when written) and then every `[[config]]`, as written.
fn views(m: &Manifest) -> Vec<View<'_>> {
    let d = m.defaults.as_ref().map(|d| View {
        base: "defaults".into(),
        config: None,
        wifi: &d.wifi,
        apps: &d.apps,
        printers: &d.printers,
        scanners: &d.scanners,
        it_account: d.it_account.as_ref(),
        chrome: &d.chrome,
    });
    d.into_iter()
        .chain(m.configs.iter().map(|c| View {
            base: format!("config.{}", c.id),
            config: Some(c),
            wifi: &c.wifi,
            apps: &c.apps,
            printers: &c.printers,
            scanners: &c.scanners,
            it_account: c.it_account.as_ref(),
            chrome: &c.chrome,
        }))
        .collect()
}

/// The path of `key` for a semantic rule: in the Config when it wrote the key (or the text has
/// no `[defaults]` to point at), else in the Defaults it inherited it from.
fn pick(m: &Manifest, written: bool, c: &ConfigLayer, key: &str) -> String {
    if written || m.defaults.is_none() {
        format!("config.{}.{key}", c.id)
    } else {
        format!("defaults.{key}")
    }
}

/// Groups `(path, config)` hits by path, in the order paths are first met: one `(code, path)` is
/// reported once, whatever number of Configs inherit the value.
fn group_hits(hits: Vec<(String, &ConfigLayer)>) -> Vec<(String, Vec<&ConfigLayer>)> {
    let mut out: Vec<(String, Vec<&ConfigLayer>)> = Vec::new();
    for (path, c) in hits {
        match out.iter_mut().find(|(p, _)| *p == path) {
            Some((_, cs)) => cs.push(c),
            None => out.push((path, vec![c])),
        }
    }
    out
}

fn config_ids(cs: &[&ConfigLayer]) -> String {
    cs.iter()
        .map(|c| c.id.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Who a semantic lint is about, lowercase for the middle of a message: `config teacher`, or
/// for an inherited value `[defaults] (inherited by config a, b)`.
fn used_by(path: &str, cs: &[&ConfigLayer]) -> String {
    if path.starts_with("defaults.") {
        format!("[defaults] (inherited by config {})", config_ids(cs))
    } else {
        format!("config {}", config_ids(cs))
    }
}

/// [`used_by`] to start a sentence.
fn subject(path: &str, cs: &[&ConfigLayer]) -> String {
    cap(&used_by(path, cs))
}

/// The Configs a semantic lint concerns in the `config` and `group` params (comma-separated
/// when a Defaults value is inherited by several); `layer = defaults` when inherited.
fn many(l: Lint, path: &str, cs: &[&ConfigLayer]) -> Lint {
    let ids = config_ids(cs);
    let l = l.param("config", &ids).param("group", &ids);
    if path.starts_with("defaults.") {
        l.param("layer", "defaults")
    } else {
        l
    }
}

/// Capitalizes the first letter of a message subject.
fn cap(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

/// How far back a machine counts for [`feature_unsupported`] (ruling 14): one that has not been
/// seen for longer rejects the new version when it comes back, until its OS is updated.
pub const FEATURE_WINDOW_DAYS: i64 = 30;

/// At most this many machines are named in a [`FleetGap`] lint; the rest are counted.
pub const FLEET_GAP_NAMED: usize = 10;

/// A machine that blocks a key or format ([`FleetGap`]): how people know it, and what it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapDevice {
    /// The serial number, else the first 8 characters of the device id.
    pub name: String,
    /// The OS image version it last reported.
    pub os_version: Option<String>,
}

/// The machines seen in the last [`FEATURE_WINDOW_DAYS`] days that do not understand a key or a
/// format, as the server found them; the lints only word it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetGap {
    /// The machines, most recently seen first (all of them; the lint names the first
    /// [`FLEET_GAP_NAMED`]).
    pub devices: Vec<GapDevice>,
    /// The day the last of them stops counting if none reports again: its last report plus
    /// [`FEATURE_WINDOW_DAYS`].
    pub until: chrono::NaiveDate,
    /// The oldest OS image version among this school's machines that did report understanding
    /// it, when any did.
    pub supported_in: Option<String>,
}

impl FleetGap {
    /// `NAME (VERSION), ...` for the first [`FLEET_GAP_NAMED`] machines.
    fn list(&self) -> String {
        self.devices
            .iter()
            .take(FLEET_GAP_NAMED)
            .map(|d| match &d.os_version {
                Some(v) => format!("{} ({v})", d.name),
                None => format!("{} (unknown OS)", d.name),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn more(&self) -> usize {
        self.devices.len().saturating_sub(FLEET_GAP_NAMED)
    }

    /// The English sentences after "... do not understand X": who, and what to do.
    fn sentence(&self) -> String {
        let more = match self.more() {
            0 => String::new(),
            n => format!(" and {n} more"),
        };
        let update = match &self.supported_in {
            Some(v) => format!("update them to OS {v} or newer"),
            None => "update them to an OS image that supports it (no device of this school runs one yet; it may not be released)"
                .to_owned(),
        };
        format!(
            "{}{more}. To publish, {update}, take them out of use, or wait until they have been silent for {FEATURE_WINDOW_DAYS} days (on {} if none reports again).",
            self.list(),
            self.until
        )
    }

    fn params(&self, l: Lint) -> Lint {
        l.param("devices", self.devices.len())
            .param("device_list", self.list())
            .param("more", self.more())
            .param("until", self.until)
            .param("supported_in", self.supported_in.as_deref().unwrap_or(""))
    }
}

/// Where in the settings a later-added key is used, for the lints about machines that do not
/// understand it: the first place that writes it (`config` for the `[[config]]` shape).
pub fn feature_path(m: &Manifest, feature: &str) -> String {
    use crate::manifest::*;
    // (path base, kiosk apps written, Wi-Fi entries) of `[defaults]` then each `[[config]]`.
    let layers = || {
        m.defaults
            .iter()
            .map(|d| ("defaults".to_owned(), d.apps.kiosk.is_empty(), &d.wifi))
            .chain(
                m.configs
                    .iter()
                    .map(|c| (format!("config.{}", c.id), c.apps.kiosk.is_empty(), &c.wifi)),
            )
    };
    let found = match feature {
        FEATURE_UPDATE_MIRROR => Some("school.update_mirror".to_owned()),
        FEATURE_ESCROW_RECIPIENTS => Some("school.escrow_recipients".to_owned()),
        FEATURE_SCHOOL_ID => Some("school.id".to_owned()),
        FEATURE_OIDC_CARD => Some("school.oidc".to_owned()),
        FEATURE_CONFIG => Some("config".to_owned()),
        FEATURE_KIOSK => layers()
            .find(|(_, empty, _)| !empty)
            .map(|(base, _, _)| format!("{base}.apps.kiosk")),
        FEATURE_SUPPORT => m
            .defaults
            .iter()
            .filter(|d| !d.support.is_empty())
            .map(|_| "defaults.support".to_owned())
            .chain(
                m.configs
                    .iter()
                    .filter(|c| !c.support.is_empty())
                    .map(|c| format!("config.{}.support", c.id)),
            )
            .next(),
        FEATURE_CONFIG_CHANNEL => m
            .defaults
            .iter()
            .filter(|d| d.update_channel.is_some())
            .map(|_| "defaults.update_channel".to_owned())
            .chain(
                m.configs
                    .iter()
                    .filter(|c| c.update_channel.is_some())
                    .map(|c| format!("config.{}.update_channel", c.id)),
            )
            .next(),
        FEATURE_WIFI_EXT if !m.school.wifi.is_empty() => Some("school.wifi".to_owned()),
        FEATURE_WIFI_EXT => layers().find_map(|(base, _, wifi)| {
            wifi.iter()
                .position(Wifi::uses_ext_keys)
                .map(|i| format!("{base}.wifi[{i}]"))
        }),
        _ => None,
    };
    found.unwrap_or_else(|| "school".to_owned())
}

/// Ruling 14, error: the machines of `gap` (seen in the last [`FEATURE_WINDOW_DAYS`] days) have
/// not reported that they understand `feature` (a key of [`crate::features_used`]); their agents
/// would reject the whole version. `path` is where the settings use it ([`feature_path`]). For a
/// key the latest published version already uses see [`feature_unsupported_in_use`].
pub fn feature_unsupported(feature: &str, path: &str, gap: &FleetGap) -> Lint {
    let n = gap.devices.len();
    gap.params(
        Lint::new(
            LintLevel::Error,
            "feature_unsupported",
            format!(
                "{n} device(s) seen in the last {FEATURE_WINDOW_DAYS} days do not understand '{feature}' and would reject this version: {}",
                gap.sentence()
            ),
        )
        .at(path)
        .param("feature", feature),
    )
}

/// Ruling 14 as amended (Task 10 fix round 1), warning: like [`feature_unsupported`], but the
/// latest published version already uses `feature`, so those machines already reject the current
/// version; publishing another one that uses it changes nothing for them and is not blocked.
pub fn feature_unsupported_in_use(feature: &str, path: &str, gap: &FleetGap) -> Lint {
    let n = gap.devices.len();
    gap.params(
        Lint::new(
            LintLevel::Warning,
            "feature_unsupported_in_use",
            format!(
                "{n} device(s) seen in the last {FEATURE_WINDOW_DAYS} days do not understand '{feature}', which the current version already uses; they already reject the current version and keep rejecting new ones: {}",
                gap.sentence()
            ),
        )
        .at(path)
        .param("feature", feature),
    )
}

/// Phase B §15, error: the machines of `gap` have not reported that they read `format = found`;
/// their agents would reject the whole version. The server finds them (it knows the lowest
/// `format` the text needs); this only words it. For a format the latest published version
/// already uses see [`format_unsupported_in_use`].
pub fn format_unsupported(found: u32, gap: &FleetGap) -> Lint {
    let n = gap.devices.len();
    gap.params(
        Lint::new(
            LintLevel::Error,
            "format_unsupported",
            format!(
                "{n} device(s) seen in the last {FEATURE_WINDOW_DAYS} days cannot read settings format {found} and would reject this version: {}",
                gap.sentence()
            ),
        )
        .at("format")
        .param("found", found),
    )
}

/// Warning: like [`format_unsupported`], but the latest published version already uses that
/// format, so those machines already reject the current version and publishing another one
/// changes nothing for them.
pub fn format_unsupported_in_use(found: u32, gap: &FleetGap) -> Lint {
    let n = gap.devices.len();
    gap.params(
        Lint::new(
            LintLevel::Warning,
            "format_unsupported_in_use",
            format!(
                "{n} device(s) seen in the last {FEATURE_WINDOW_DAYS} days cannot read settings format {found}, which the current version already uses; they keep rejecting new versions: {}",
                gap.sentence()
            ),
        )
        .at("format")
        .param("found", found),
    )
}

/// Plan 6 Task 10b, error: the manifest's `[school] id` is missing or is not `expected`, the id
/// of the school publishing it. Machines of that school refuse such a version ("bundle is for
/// another school"). The server knows its school id; this only compares and words it.
pub fn school_id_mismatch(m: &Manifest, expected: &str) -> Option<Lint> {
    let message = match m.school.id.as_deref() {
        Some(id) if id == expected => return None,
        Some(id) => format!(
            "[school] id is \"{id}\", but this school's id is \"{expected}\": this school's \
             machines would reject the version. Write id = \"{expected}\" under [school]."
        ),
        None => format!(
            "[school] id is missing: this school's machines only accept a version that names \
             their school. Write id = \"{expected}\" under [school]."
        ),
    };
    Some(
        Lint::new(LintLevel::Error, "school_id_mismatch", message)
            .at("school.id")
            .param("expected", expected),
    )
}

/// An icon is a `files/...` entry present in the bundle or an `https://` link (same rule for web apps and kiosk apps).
fn icon_ok(icon: &str, present: &BTreeSet<String>) -> bool {
    icon.starts_with("https://") || (icon.starts_with("files/") && present.contains(icon))
}

/// Web apps of one layer: icon and https rules (their format rule, `web_app_invalid`, is in
/// [`lint_formats`]).
fn lint_web_apps(v: &View, present: &BTreeSet<String>, out: &mut Vec<Lint>) {
    for (i, w) in v.apps.web.iter().enumerate() {
        let base = format!("{}.apps.web[{i}]", v.base);
        if let Some(icon) = &w.icon {
            if !icon_ok(icon, present) {
                out.push(v.tag(
                    Lint::new(
                        LintLevel::Error,
                        "icon_invalid",
                        format!(
                            "Web app {:?} has icon {icon:?}, which is neither a files/... file present in the bundle nor an https:// link: use one of those.",
                            w.name
                        ),
                    )
                    .at(format!("{base}.icon"))
                    .param("app_name", &w.name)
                    .param("icon", icon),
                ));
            }
        }
        if !w.url.starts_with("https://") {
            out.push(v.tag(
                Lint::new(
                    LintLevel::Warning,
                    "web_app_not_https",
                    format!(
                        "Web app {:?} uses address {:?}, which is not https://: prefer an https:// address.",
                        w.name, w.url
                    ),
                )
                .at(format!("{base}.url"))
                .param("app_name", &w.name)
                .param("url", &w.url),
            ));
        }
    }
}

/// `[config.apps.kiosk]` (plan 9), one layer: [`kiosk::check`] errors, icons, and a few warnings
/// and notes about each app as written. The rules that need the Config's whole app list (the
/// count cap, a Flatpak the app launches) are in [`lint_kiosk_semantics`].
fn lint_kiosk(v: &View, present: &BTreeSet<String>, out: &mut Vec<Lint>) {
    let base = format!("{}.apps.kiosk", v.base);
    for (id, app) in &v.apps.kiosk {
        let at = format!("{base}.{id}");
        if let Err(e) = kiosk::check(id, app) {
            out.push(
                v.tag(
                    err(e.code, e.message, format!("{at}.{}", e.field))
                        .param("app_id", id)
                        .param("field", e.field),
                ),
            );
        }
        if let Some(icon) = app.icon.as_deref().filter(|i| !icon_ok(i, present)) {
            out.push(v.tag(
                err(
                    "icon_invalid",
                    format!(
                        "Kiosk app {:?} has icon {icon:?}, which is neither a files/... file present in the bundle nor an https:// link: use one of those.",
                        app.name
                    ),
                    format!("{at}.icon"),
                )
                .param("app_name", &app.name)
                .param("icon", icon),
            ));
        }
        // Final review I2: "entering" from the desktop only ends the current session and returns to the login screen
        // (one-time auto-login is not built yet, design 9.4), and an app with login_screen = false is not listed
        // there, so the student cannot find it. Relax this once auto-login exists.
        if app.in_session && !app.login_screen {
            out.push(v.tag(
                err(
                    "kiosk_in_session_only",
                    format!(
                        "Kiosk app {:?} is shown only on the desktop (in_session = true, login_screen = false) and cannot be entered: entering from the desktop returns to the login screen, where the app must be clicked again, so set login_screen = true as well.",
                        app.name
                    ),
                    format!("{at}.login_screen"),
                )
                .param("app_name", &app.name),
            ));
        }
        if !app.login_screen && !app.in_session {
            out.push(v.tag(
                Lint::new(
                    LintLevel::Warning,
                    "kiosk_no_entry",
                    format!(
                        "Kiosk app {:?} has login_screen and in_session both false: it appears neither on the login screen nor in the session, so nobody can open it.",
                        app.name
                    ),
                )
                .at(at.clone())
                .param("app_name", &app.name),
            ));
        }
        // A local program with user_agent is already kiosk_user_agent_invalid; no extra note.
        if app.user_agent.is_some() && app.url.is_some() {
            out.push(v.tag(
                Lint::new(
                    LintLevel::Info,
                    "kiosk_user_agent",
                    format!(
                        "Kiosk app {:?} overrides user_agent: it is only for browser detection by compatible sites; exam vendors' secure-client detection is handled by the exam extension and needs no change.",
                        app.name
                    ),
                )
                .at(format!("{at}.user_agent"))
                .param("app_name", &app.name),
            ));
        }
    }
}

/// Kiosk rules about what a Config ends up with: more apps than the cap, and an app that
/// launches a Flatpak the Config does not install. Both look at the effective Config, so a
/// Flatpak the Defaults install counts.
fn lint_kiosk_semantics(m: &Manifest, configs: &[(&ConfigLayer, Config)], out: &mut Vec<Lint>) {
    let too_many = configs
        .iter()
        .filter(|(_, e)| e.apps.kiosk.len() > kiosk::MAX_KIOSK_APPS)
        .map(|(g, _)| (pick(m, !g.apps.kiosk.is_empty(), g, "apps.kiosk"), *g))
        .collect();
    for (path, cs) in group_hits(too_many) {
        let n = configs
            .iter()
            .find(|(g, _)| g.id == cs[0].id)
            .map_or(0, |(_, e)| e.apps.kiosk.len());
        out.push(many(
            err(
                "kiosk_too_many",
                format!(
                    "{} has {n} kiosk apps, at most {} are allowed: remove some.",
                    subject(&path, &cs),
                    kiosk::MAX_KIOSK_APPS
                ),
                path.clone(),
            )
            .param("count", n)
            .param("max", kiosk::MAX_KIOSK_APPS),
            &path,
            &cs,
        ));
    }
    let mut missing = Vec::new();
    let mut names = BTreeMap::new();
    for (g, e) in configs {
        for (id, app) in &e.apps.kiosk {
            let Some(x) = app.exec.as_deref().filter(|x| {
                !x.starts_with('/')
                    && checks::flatpak_id(x).is_ok()
                    && !e.apps.flatpak.iter().any(|f| f == x)
            }) else {
                continue;
            };
            let path = pick(
                m,
                g.apps.kiosk.contains_key(id),
                g,
                &format!("apps.kiosk.{id}.exec"),
            );
            names.insert(path.clone(), (app.name.clone(), x.to_string()));
            missing.push((path, *g));
        }
    }
    for (path, cs) in group_hits(missing) {
        let (name, x) = &names[&path];
        out.push(many(
            Lint::new(
                LintLevel::Warning,
                "kiosk_flatpak_missing",
                format!(
                    "Kiosk app {name:?} launches Flatpak {x}, which is not in apps.flatpak of {}: machines will not install it, so the app cannot open.",
                    used_by(&path, &cs)
                ),
            )
            .at(path.clone())
            .param("app_name", name),
            &path,
            &cs,
        ));
    }
}

fn err(code: &'static str, message: String, path: String) -> Lint {
    Lint::new(LintLevel::Error, code, message).at(path)
}

/// The shape checks (config profiles design §3, §5): a legacy text is an error in a Draft; a
/// Config no Group uses is reported as info.
fn lint_shape(m: &Manifest, out: &mut Vec<Lint>) {
    if m.shape == Shape::Legacy {
        out.push(
            Lint::new(
                LintLevel::Error,
                "legacy_shape",
                "This settings file uses the old shape, where each [[group]] carries its own settings: move each Group's settings into a [[config]] with the same id and name, write interface = \"full\" where it had mode = \"desktop\" (otherwise interface = \"learning\"), and keep only id, name and config = \"<that id>\" in the [[group]].",
            )
            .at("group"),
        );
        return;
    }
    lint_group_names(m, out);
    for c in &m.configs {
        if !m.groups.iter().any(|g| g.config == c.id) {
            out.push(
                Lint::new(
                    LintLevel::Info,
                    "config_unused",
                    format!(
                        "No group uses config {}: it applies to no Device until a group names it in config.",
                        c.id
                    ),
                )
                .at(format!("config.{}", c.id))
                .param("config", &c.id),
            );
        }
    }
}

/// Console trial M4: two Groups with the same name (trimmed, ignoring case) cannot be told apart
/// wherever a Group is picked; the second and later ones are an error naming the first.
fn lint_group_names(m: &Manifest, out: &mut Vec<Lint>) {
    let mut seen: BTreeMap<String, &str> = BTreeMap::new();
    for g in &m.groups {
        let key = g.name.trim().to_lowercase();
        if key.is_empty() {
            continue;
        }
        match seen.get(&key) {
            Some(first) => out.push(
                Lint::new(
                    LintLevel::Error,
                    "group_name_duplicate",
                    format!(
                        "Groups {first} and {} are both named {:?}: give each group its own name so they can be told apart.",
                        g.id,
                        g.name.trim()
                    ),
                )
                .at(format!("group.{}.name", g.id))
                .param("group", &g.id)
                .param("other", *first)
                .param("name", g.name.trim()),
            ),
            None => {
                seen.insert(key, &g.id);
            }
        }
    }
}

/// Warnings for Groups whose Devices start installing Flatpak apps when `next` is published
/// (config profiles design §5.1): `prev`, the latest published Version, is in the legacy shape
/// and the Group was in browser mode there (so no Flatpak app was installed), while in `next` the
/// Group uses a Config, of any id, that is not marked legacy browser and lists Flatpak apps. One
/// warning per such Config, naming its Groups. The server calls this; only it knows the latest
/// published Version.
pub fn flatpak_now_installed(prev: &Manifest, next: &Manifest) -> Vec<Lint> {
    if prev.shape != Shape::Legacy {
        return Vec::new();
    }
    // Path -> (configs, groups, apps), in the order the paths are first met: the path names the
    // key the Config wrote, or `defaults.apps.flatpak` when its Flatpaks are inherited, so a
    // Defaults list inherited by several Configs is one warning.
    let mut hits: Vec<FlatpakHit> = Vec::new();
    for g in &next.groups {
        let was_browser = prev
            .config_of_group(&g.id)
            .is_some_and(|p| p.legacy_browser);
        let Some(layer) = next.config_of_group(&g.id) else {
            continue;
        };
        let c = effective_config(next, layer);
        if !was_browser || c.legacy_browser || c.apps.flatpak.is_empty() {
            continue;
        }
        let path = pick(next, !layer.apps.flatpak.is_empty(), layer, "apps.flatpak");
        match hits.iter_mut().find(|h| h.0 == path) {
            Some((_, configs, groups, _)) => {
                if !configs.iter().any(|x| x.id == layer.id) {
                    configs.push(layer);
                }
                groups.push(&g.id);
            }
            None => hits.push((path, vec![layer], vec![&g.id], c.apps.flatpak)),
        }
    }
    hits.into_iter()
        .map(|(path, configs, groups, flatpak)| {
            let apps = flatpak.join(", ");
            many(
                Lint::new(
                    LintLevel::Warning,
                    "flatpak_now_installed",
                    format!(
                        "Group(s) {} were in browser mode in the published version, so no Flatpak app was installed on their Devices; with this version they use {}, which installs {apps} and shows them in the Dock. Remove them from that config's apps.flatpak if that is not wanted.",
                        groups.join(", "),
                        used_by(&path, &configs)
                    ),
                )
                .at(path.clone())
                .param("groups", groups.join(","))
                .param("apps", apps),
                &path,
                &configs,
            )
        })
        .collect()
}

/// Indexes of names that occur a second (or later) time in `items`.
fn duplicates<'a>(items: impl Iterator<Item = &'a str>) -> Vec<usize> {
    let mut seen = BTreeSet::new();
    items
        .enumerate()
        .filter(|(_, n)| !seen.insert(*n))
        .map(|(i, _)| i)
        .collect()
}

/// `[config.chrome]` (task 23): window format and pause format, at most 14 days past the publish
/// day, checked per layer as written; paused configs are listed as info (about each Config's
/// effective pause), with the groups that use them.
fn lint_chrome(
    m: &Manifest,
    views: &[View],
    configs: &[(&ConfigLayer, Config)],
    today: chrono::NaiveDate,
    out: &mut Vec<Lint>,
) {
    for v in views {
        let base = format!("{}.chrome", v.base);
        if let Some(Err(e)) = v.chrome.update_window.as_deref().map(checks::chrome_window) {
            out.push(err(
                "chrome_window_invalid",
                e,
                format!("{base}.update_window"),
            ));
        }
        let Some(p) = v.chrome.pause_until.as_deref() else {
            continue;
        };
        let path = format!("{base}.pause_until");
        match checks::chrome_date(p) {
            Err(e) => out.push(err("chrome_pause_invalid", e, path)),
            Ok(_) => {
                if let Err(e) = checks::chrome_pause(p, today) {
                    out.push(err("chrome_pause_too_long", e, path));
                }
            }
        }
    }
    let mut hits = Vec::new();
    let mut until = BTreeMap::new();
    for (g, e) in configs {
        let Some(p) = e.chrome.pause_until.as_deref() else {
            continue;
        };
        let Ok(d) = checks::chrome_date(p) else {
            continue;
        };
        if checks::chrome_pause(p, today).is_ok() && d >= today {
            let path = pick(m, g.chrome.pause_until.is_some(), g, "chrome.pause_until");
            until.insert(path.clone(), p.to_string());
            hits.push((path, *g));
        }
    }
    for (path, cs) in group_hits(hits) {
        let p = &until[&path];
        let groups: Vec<&str> = m
            .groups
            .iter()
            .filter(|x| cs.iter().any(|c| c.id == x.config))
            .map(|x| x.id.as_str())
            .collect();
        let groups = groups.join(",");
        let groups_note = if groups.is_empty() {
            "no group uses it yet".to_string()
        } else {
            format!("groups: {}", groups.replace(',', ", "))
        };
        out.push(many(
            Lint::new(
                LintLevel::Info,
                "chrome_paused",
                format!(
                    "Chrome updates are paused until {p} (inclusive) for {} ({groups_note}): no new version is installed before then (machines without Chrome still install it).",
                    used_by(&path, &cs)
                ),
            )
            .at(path.clone())
            .param("until", p)
            .param("groups", groups),
            &path,
            &cs,
        ));
    }
}

/// One Wi-Fi list (`[[school.wifi]]`, or a layer's): format errors from [`checks::wifi`], and for
/// valid entries the warnings for an entry with no credentials and for an enterprise network that
/// does not check its server. `tag` adds the layer's params. Messages never carry secrets.
fn lint_wifi(list: &[Wifi], base: &str, tag: &dyn Fn(Lint) -> Lint, out: &mut Vec<Lint>) {
    for (i, w) in list.iter().enumerate() {
        let path = format!("{base}.wifi[{i}]");
        if let Err(e) = checks::wifi(w) {
            out.push(err("wifi_invalid", e, path));
            continue;
        }
        if w.open.is_none() && w.psk.is_none() && w.eap.is_none() {
            out.push(tag(Lint::new(
                LintLevel::Warning,
                "wifi_open_implicit",
                format!(
                    "Wi-Fi {:?} has no psk, eap or open: Devices join it as an open network; if it is open, write open = true (before publishing, every Device must support the newer Wi-Fi settings, feature wifi_ext), otherwise add its password (psk) in the admin web page.",
                    w.ssid
                ),
            )
            .at(path)
            .param("ssid", &w.ssid)));
        } else if w.eap.is_some() && w.check_server == Some(false) {
            out.push(tag(Lint::new(
                LintLevel::Warning,
                "wifi_server_unchecked",
                format!(
                    "Wi-Fi {:?} does not check its RADIUS server (check_server = false): a nearby hotspot with the same name can pose as it and capture the account and password; add server_domain or ca_cert instead.",
                    w.ssid
                ),
            )
            .at(path)
            .param("ssid", &w.ssid)));
        }
    }
}

/// One `drop` list: its collection name, the names dropped, the inherited names, the Config's own.
type DropSet<'a> = (&'a str, &'a [String], Vec<String>, Vec<String>);

/// A path of `flatpak_now_installed`: its Configs, their Groups and the Flatpak ids they install.
type FlatpakHit<'a> = (String, Vec<&'a ConfigLayer>, Vec<&'a str>, Vec<String>);

/// `drop` entries of one Config that do nothing: a name the Defaults (or the school's legacy
/// Wi-Fi) do not have is a warning, since the Defaults may have been renamed since (the Config
/// still publishes); a name the Config also writes itself is an error, because the Config
/// both removes and adds it.
fn lint_drop(m: &Manifest, g: &ConfigLayer, out: &mut Vec<Lint>) {
    let none = Defaults::default();
    let d = m.defaults.as_ref().unwrap_or(&none);
    let strs = |v: Vec<&str>| v.into_iter().map(str::to_owned).collect::<Vec<_>>();
    let dr = &g.drop;
    let sets: Vec<DropSet> = vec![
        (
            "wifi",
            &dr.wifi,
            strs(
                m.school
                    .wifi
                    .iter()
                    .chain(&d.wifi)
                    .map(|w| w.ssid.as_str())
                    .collect(),
            ),
            strs(g.wifi.iter().map(|w| w.ssid.as_str()).collect()),
        ),
        (
            "apps.web",
            &dr.apps.web,
            strs(d.apps.web.iter().map(|a| a.name.as_str()).collect()),
            strs(g.apps.web.iter().map(|a| a.name.as_str()).collect()),
        ),
        (
            "apps.flatpak",
            &dr.apps.flatpak,
            d.apps.flatpak.clone(),
            g.apps.flatpak.clone(),
        ),
        (
            "apps.kiosk",
            &dr.apps.kiosk,
            d.apps.kiosk.keys().cloned().collect(),
            g.apps.kiosk.keys().cloned().collect(),
        ),
        (
            "printers",
            &dr.printers,
            strs(d.printers.iter().map(|p| p.name.as_str()).collect()),
            strs(g.printers.iter().map(|p| p.name.as_str()).collect()),
        ),
        (
            "scanners",
            &dr.scanners,
            strs(d.scanners.iter().map(|p| p.name.as_str()).collect()),
            strs(g.scanners.iter().map(|p| p.name.as_str()).collect()),
        ),
        (
            "files",
            &dr.files,
            strs(d.files.iter().map(|f| f.dest.as_str()).collect()),
            strs(g.files.iter().map(|f| f.dest.as_str()).collect()),
        ),
        (
            "downloads",
            &dr.downloads,
            strs(d.downloads.iter().map(|f| f.dest.as_str()).collect()),
            strs(g.downloads.iter().map(|f| f.dest.as_str()).collect()),
        ),
        (
            "scripts",
            &dr.scripts,
            strs(d.scripts.iter().map(|f| f.path.as_str()).collect()),
            strs(g.scripts.iter().map(|f| f.path.as_str()).collect()),
        ),
        (
            "chrome_policy",
            &dr.chrome_policy,
            d.chrome_policy.keys().cloned().collect(),
            g.chrome_policy.keys().cloned().collect(),
        ),
    ];
    for (collection, dropped, inherited, own) in &sets {
        for (i, name) in dropped.iter().enumerate() {
            let path = format!("config.{}.drop.{collection}[{i}]", g.id);
            let (level, code, message) = if own.contains(name) {
                (
                    LintLevel::Error,
                    "drop_conflict",
                    format!(
                        "Config {} both drops {name:?} and writes it in {collection}: remove it from drop, or from its own {collection} if the inherited one is wanted.",
                        g.id
                    ),
                )
            } else if !inherited.contains(name) {
                (
                    LintLevel::Warning,
                    "drop_unknown",
                    format!(
                        "Config {} drops {name:?} from {collection}, but [defaults] has no such entry: the drop does nothing (the Defaults may have been renamed); remove it or fix the name.",
                        g.id
                    ),
                )
            } else {
                continue;
            };
            out.push(about(
                Lint::new(level, code, message)
                    .at(path)
                    .param("collection", collection)
                    .param("name", name),
                g,
            ));
        }
    }
}

/// Format rules for settings items (the same `checks` functions the agent re-runs per item in its
/// steps): the school's, then each layer's as written.
fn lint_formats(
    m: &Manifest,
    views: &[View],
    configs: &[(&ConfigLayer, Config)],
    out: &mut Vec<Lint>,
) {
    let s = &m.school;
    // Count caps: the login policy file on the machine must fit within what pam-check reads, otherwise the machine can only treat it as locked.
    if s.admin_users.len() > checks::MAX_ADMIN_USERS {
        out.push(
            err(
                "admin_users_too_many",
                format!(
                    "There are {} admin_users, at most {} are allowed: remove some.",
                    s.admin_users.len(),
                    checks::MAX_ADMIN_USERS
                ),
                "school.admin_users".into(),
            )
            .param("count", s.admin_users.len())
            .param("max", checks::MAX_ADMIN_USERS),
        );
    }
    if s.allowed_domains.len() > checks::MAX_ALLOWED_DOMAINS {
        out.push(
            err(
                "allowed_domains_too_many",
                format!(
                    "There are {} allowed_domains, at most {} are allowed: remove some.",
                    s.allowed_domains.len(),
                    checks::MAX_ALLOWED_DOMAINS
                ),
                "school.allowed_domains".into(),
            )
            .param("count", s.allowed_domains.len())
            .param("max", checks::MAX_ALLOWED_DOMAINS),
        );
    }
    if !s.admin_users.is_empty() {
        let hits = configs
            .iter()
            .filter(|(_, e)| !e.login_methods.contains(&LoginMethod::Sso))
            .map(|(g, _)| (pick(m, g.login_methods.is_some(), g, "login_methods"), *g))
            .collect();
        for (path, cs) in group_hits(hits) {
            out.push(many(
                Lint::new(
                    LintLevel::Warning,
                    "admins_without_sso",
                    format!(
                        "{} has no sso login method: admins sign in with school accounts and cannot sign in on the Devices that use it; add sso to login_methods.",
                        subject(&path, &cs)
                    ),
                )
                .at(path.clone()),
                &path,
                &cs,
            ));
        }
    }
    // No valid admin, no IT account and the config does not let local users administer: nobody on these machines can
    // sudo or unlock system settings (by design, since managed machines have no hidden admin, 4a ruling 18, but a
    // school whose first bundle forgot its administrators should know). Warning only. The IT account (`itadmin`) is a
    // local administrator, so a Config that has one is not left without (console trial minor 1).
    if !s.admin_users.iter().any(|u| checks::admin_user(u).is_ok()) {
        let hits = configs
            .iter()
            .filter(|(_, e)| !e.local_users_admin && e.it_account.is_none())
            .map(|(g, _)| {
                (
                    pick(m, g.local_users_admin.is_some(), g, "local_users_admin"),
                    *g,
                )
            })
            .collect();
        for (path, cs) in group_hits(hits) {
            out.push(many(
                Lint::new(
                    LintLevel::Warning,
                    "no_admins",
                    format!(
                        "Devices using {} will have no administrator: there is no IT account, admin_users has no valid entry and local_users_admin is off, so nobody can sudo or unlock system settings.",
                        used_by(&path, &cs)
                    ),
                )
                .at(path.clone()),
                &path,
                &cs,
            ));
        }
    }
    for (i, u) in s.admin_users.iter().enumerate() {
        if let Err(e) = checks::admin_user(u) {
            out.push(
                err("admin_user_invalid", e, format!("school.admin_users[{i}]"))
                    .param("user", u.clone()),
            );
        }
    }
    for (i, d) in s.allowed_domains.iter().enumerate() {
        if let Err(e) = checks::allowed_domain(d) {
            // The value is a param: two bad entries are two different issues, not one said twice
            // (console trial minor 6).
            out.push(
                err(
                    "allowed_domain_invalid",
                    e,
                    format!("school.allowed_domains[{i}]"),
                )
                .param("domain", d.clone()),
            );
        }
    }
    if let Some(Err(e)) = s.update_mirror.as_deref().map(checks::update_mirror) {
        out.push(err(
            "update_mirror_invalid",
            e,
            "school.update_mirror".into(),
        ));
    } else if s
        .update_mirror
        .as_deref()
        .is_some_and(|m| m.starts_with("http://"))
    {
        out.push(
            Lint::new(
                LintLevel::Warning,
                "update_mirror_not_https",
                "update_mirror uses http://: allowed (updates are signed, so content cannot be altered), but https:// is preferable where the cache supports it.",
            )
            .at("school.update_mirror")
            .param("url", s.update_mirror.as_deref().unwrap_or_default()),
        );
    }
    if let Err(e) = checks::escrow_recipients(&s.escrow_recipients) {
        out.push(err(
            "escrow_recipients_invalid",
            e,
            "school.escrow_recipients".into(),
        ));
    }
    if let Some(Err(e)) = s.timezone.as_deref().map(checks::timezone) {
        out.push(err("timezone_invalid", e, "school.timezone".into()));
    }
    if let Some(Err(e)) = s.locale.as_deref().map(checks::locale) {
        out.push(err("locale_invalid", e, "school.locale".into()));
    }
    if let Some(Err(e)) = s.name.as_deref().map(checks::school_name) {
        out.push(err("school_name_invalid", e, "school.name".into()));
    }
    for (key, value) in [
        ("logo_sha256", &s.logo_sha256),
        ("logo_icon_sha256", &s.logo_icon_sha256),
    ] {
        if let Some(Err(e)) = value.as_deref().map(checks::logo_sha256) {
            out.push(err("logo_sha256_invalid", e, format!("school.{key}")));
        }
    }
    // The sign-in logo and the quick menu icon are uploaded together; one alone is a hand edit.
    match (&s.logo_sha256, &s.logo_icon_sha256) {
        (Some(_), None) => out.push(err(
            "logo_incomplete",
            "[school] has logo_sha256 but no logo_icon_sha256: upload the logo again on the \
             console (it writes both), or remove logo_sha256"
                .into(),
            "school.logo_icon_sha256".into(),
        )),
        (None, Some(_)) => out.push(err(
            "logo_incomplete",
            "[school] has logo_icon_sha256 but no logo_sha256: upload the logo again on the \
             console (it writes both), or remove logo_icon_sha256"
                .into(),
            "school.logo_sha256".into(),
        )),
        _ => {}
    }
    // Only in a `format = 2` text: while Wi-Fi is all that would need format 2, the server keeps
    // it in `[school] wifi` (format 1), so a format-1 text could never follow this advice.
    if m.format >= 2 && !s.wifi.is_empty() {
        out.push(
            Lint::new(
                LintLevel::Warning,
                "school_wifi_moved",
                "[[school.wifi]] has moved to [[defaults.wifi]]: networks still written under [school] keep working (they come before the Defaults' ones), but new ones belong in [defaults]; move them there.",
            )
            .at("school.wifi"),
        );
    }
    lint_wifi(&s.wifi, "school", &|l| l, out);
    for i in duplicates(s.wifi.iter().map(|w| w.ssid.as_str())) {
        out.push(
            err(
                "wifi_ssid_duplicate",
                format!(
                    "Wi-Fi name {:?} appears more than once in [school] wifi: keep one entry per name.",
                    s.wifi[i].ssid
                ),
                format!("school.wifi[{i}]"),
            )
            .param("ssid", &s.wifi[i].ssid)
            .param("layer", "school"),
        );
    }
    for v in views {
        let base = &v.base;
        let who = v.who();
        lint_wifi(v.wifi, base, &|l| v.tag(l), out);
        for i in duplicates(v.wifi.iter().map(|w| w.ssid.as_str())) {
            out.push(
                v.tag(
                    err(
                        "wifi_ssid_duplicate",
                        format!(
                        "Wi-Fi name {:?} appears more than once in {who}: keep one entry per name.",
                        v.wifi[i].ssid
                    ),
                        format!("{base}.wifi[{i}]"),
                    )
                    .param("ssid", &v.wifi[i].ssid),
                ),
            );
        }
        for (kind, code, list, uri_check) in [
            (
                "printers",
                "printer_invalid",
                v.printers,
                checks::printer_uri as fn(&str) -> Result<(), String>,
            ),
            (
                "scanners",
                "scanner_invalid",
                v.scanners,
                checks::scanner_uri,
            ),
        ] {
            for (i, d) in list.iter().enumerate() {
                for r in [uri_check(&d.uri), checks::device_name(&d.name)] {
                    if let Err(e) = r {
                        out.push(err(code, e, format!("{base}.{kind}[{i}]")));
                    }
                }
            }
            // Printers compare by CUPS queue name (after sanitizing, case-insensitive); scanners by the name as written.
            let keys: Vec<String> = list
                .iter()
                .map(|d| {
                    if kind == "printers" {
                        checks::printer_queue(&d.name).to_ascii_lowercase()
                    } else {
                        d.name.clone()
                    }
                })
                .collect();
            for i in duplicates(keys.iter().map(String::as_str)) {
                let message = if kind == "printers"
                    && list[..i].iter().all(|d| d.name != list[i].name)
                {
                    format!(
                        "Printer {:?} in {who} has the same queue name {:?} as an earlier printer (after replacing / # spaces etc. with _ and ignoring case): rename it.",
                        list[i].name,
                        checks::printer_queue(&list[i].name)
                    )
                } else {
                    format!(
                        "The name {:?} appears more than once in {kind} of {who}: keep one entry per name.",
                        list[i].name
                    )
                };
                out.push(
                    v.tag(
                        err(
                            "device_name_duplicate",
                            message,
                            format!("{base}.{kind}[{i}]"),
                        )
                        .param("name", &list[i].name),
                    ),
                );
            }
        }
        for (i, a) in v.apps.web.iter().enumerate() {
            if let Err(e) = checks::web_app(a) {
                out.push(err("web_app_invalid", e, format!("{base}.apps.web[{i}]")));
            }
        }
        for (i, id) in v.apps.flatpak.iter().enumerate() {
            if let Err(e) = checks::flatpak_id(id) {
                out.push(err(
                    "flatpak_id_invalid",
                    e,
                    format!("{base}.apps.flatpak[{i}]"),
                ));
            }
        }
        if let Some(Err(e)) = v
            .it_account
            .map(|a| checks::it_password_hash(&a.password_hash))
        {
            out.push(
                v.tag(err("it_account_invalid", e, format!("{base}.it_account")))
                    .param("layer", v.layer_id()),
            );
        }
    }
    for g in &m.configs {
        lint_drop(m, g, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One config `teacher` used by one group `teacher`; `config_extra` goes into the config
    /// (its `[group.…]` tables are read as `[config.…]`, so fixtures read like the settings).
    fn manifest(school_extra: &str, config_extra: &str, login: &str) -> Manifest {
        let config_extra = config_extra.replace("[group.", "[config.");
        Manifest::parse(&format!(
            r#"
version = 1
[[trust]]
id = "k"
alg = "ed25519"
public_key = "AAAA"
[school]
{school_extra}
[[config]]
id = "teacher"
name = "t"
login_methods = [{login}]
{config_extra}
[[group]]
id = "teacher"
name = "t"
config = "teacher"
"#
        ))
        .unwrap()
    }

    const OIDC: &str = r#"oidc = { issuer = "https://sso.school.ac.th", client_id = "c" }"#;

    /// The other cases do not care about the "no administrator" warning (their manifests mostly
    /// have no admin_users) nor about the open-network one (their fixtures write `{ ssid = "x" }`):
    /// both are filtered out; the dedicated cases call `super::lint` directly.
    fn lint(m: &Manifest, present: &BTreeSet<String>) -> Vec<Lint> {
        super::lint(m, present)
            .into_iter()
            .filter(|l| {
                !matches!(
                    l.code,
                    "no_admins" | "wifi_open_implicit" | "school_wifi_moved"
                )
            })
            .collect()
    }

    #[test]
    fn lint_school_wifi_and_warnings() {
        let only = |l: Vec<Lint>| -> Vec<Lint> {
            l.into_iter()
                .filter(|x| x.code != "no_admins" && x.code != "school_wifi_moved")
                .collect()
        };
        // Two school entries with one SSID.
        let school = r#"wifi = [{ ssid = "S", psk = "password1" }, { ssid = "S", open = true }]"#;
        let l = only(super::lint(&manifest(school, "", "\"local\""), &present()));
        assert_eq!(codes(&l), ["wifi_ssid_duplicate"], "{l:?}");
        assert_eq!(l[0].path.as_deref(), Some("school.wifi[1]"));
        assert_eq!(l[0].params["ssid"], "S");
        assert_eq!(l[0].params["layer"], "school");
        assert!(!l[0].params.contains_key("config"), "{l:?}");
        // Invalid school entry.
        let school = r#"wifi = [{ ssid = "S", psk = "PSK-X" }]"#;
        let l = only(super::lint(&manifest(school, "", "\"local\""), &present()));
        assert_eq!(codes(&l), ["wifi_invalid"], "{l:?}");
        assert_eq!(l[0].path.as_deref(), Some("school.wifi[0]"));
        assert!(!l[0].message.contains("PSK-X"));
        // No credentials, in either layer: a warning.
        let l = only(super::lint(
            &manifest(
                "wifi = [{ ssid = \"x\" }]",
                "wifi = [{ ssid = \"y\" }]",
                "\"local\"",
            ),
            &present(),
        ));
        assert_eq!(
            codes(&l),
            ["wifi_open_implicit", "wifi_open_implicit"],
            "{l:?}"
        );
        assert!(l.iter().all(|x| x.level == LintLevel::Warning));
        assert_eq!(l[0].path.as_deref(), Some("school.wifi[0]"));
        assert_eq!(l[1].path.as_deref(), Some("config.teacher.wifi[0]"));
        assert_eq!(l[1].params["config"], "teacher");
        assert!(l[0].message.contains("open = true"), "{l:?}");
        // open = true says so: no warning.
        let l = only(super::lint(
            &manifest("wifi = [{ ssid = \"x\", open = true }]", "", "\"local\""),
            &present(),
        ));
        assert!(l.is_empty(), "{l:?}");
        // Enterprise without the server check.
        let g = r#"wifi = [{ ssid = "E", eap = "peap", identity = "i", password = "PW-SECRET", check_server = false }]"#;
        let l = only(super::lint(&manifest("", g, "\"local\""), &present()));
        assert_eq!(codes(&l), ["wifi_server_unchecked"], "{l:?}");
        assert_eq!(l[0].level, LintLevel::Warning);
        assert_eq!(l[0].path.as_deref(), Some("config.teacher.wifi[0]"));
        assert!(
            l[0].message.contains("nearby hotspot with the same name")
                && l[0].message.contains("password"),
            "{l:?}"
        );
        assert!(!l[0].message.contains("PW-SECRET"));
        // The same with server_domain: clean.
        let g = r#"wifi = [{ ssid = "E", eap = "peap", identity = "i", password = "PW-SECRET", server_domain = "r.x" }]"#;
        assert!(only(super::lint(&manifest("", g, "\"local\""), &present())).is_empty());
    }

    /// Task 12 复审 F5：没有一个合格的管理员、分组又不让本机用户当管理员 → 每个这样的分组一条警告。
    #[test]
    fn lint_no_admins_is_warning() {
        let l = super::lint(&manifest("", "", "\"local\""), &present());
        assert_eq!(codes(&l), ["no_admins"], "{l:?}");
        assert_eq!(l[0].level, LintLevel::Warning);
        assert_eq!(
            l[0].path.as_deref(),
            Some("config.teacher.local_users_admin")
        );
        // 本机用户是管理员：不报。
        let l = super::lint(
            &manifest("", "local_users_admin = true", "\"local\""),
            &present(),
        );
        assert!(l.is_empty(), "{l:?}");
        // 有一个合格的管理员：不报。
        let school = format!("{OIDC}\nadmin_users = [\"it@x.th\"]");
        assert!(super::lint(&manifest(&school, "", "\"sso\""), &present()).is_empty());
        // 名单里只有不合格的名字（会被机器跳过）：照样报，另有 admin_user_invalid。
        let school = format!("{OIDC}\nadmin_users = [\"%x@x.th\"]");
        let l = super::lint(&manifest(&school, "", "\"sso\""), &present());
        assert_eq!(codes(&l), ["no_admins", "admin_user_invalid"], "{l:?}");
        // An IT account (itadmin) is a local administrator: not reported, in the Defaults or the Config.
        let m = Manifest::parse(
            "format = 2\nversion = 1\n[[trust]]\nid = \"k\"\nalg = \"ed25519\"\npublic_key = \"AAAA\"\n\
             [school]\n[[config]]\nid = \"teacher\"\nname = \"t\"\nlogin_methods = [\"local\"]\n\
             it_account = { password_hash = \"$6$rounds=500000$salt$hash\" }\n\
             [[group]]\nid = \"teacher\"\nname = \"t\"\nconfig = \"teacher\"\n",
        )
        .unwrap();
        let l = super::lint(&m, &present());
        assert!(!codes(&l).contains(&"no_admins"), "{l:?}");
    }

    fn present() -> BTreeSet<String> {
        ["files/c.png".to_string()].into()
    }

    fn web(icon_or_url: &str) -> String {
        format!("[group.apps]\nweb = [{{ name = \"w\", {icon_or_url} }}]")
    }

    #[test]
    fn sso_group_without_oidc_is_error() {
        let l = lint(&manifest("", "", "\"sso\""), &present());
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].code, "sso_without_oidc");
        assert_eq!(l[0].level, LintLevel::Error);
        assert_eq!(l[0].path.as_deref(), Some("config.teacher.login_methods"));
    }

    #[test]
    fn sso_group_with_oidc_is_clean() {
        assert!(lint(&manifest(OIDC, "", "\"sso\", \"local\""), &present()).is_empty());
    }

    #[test]
    fn icon_must_be_present_file_or_https() {
        let check = |icon: &str| {
            let g = web(&format!("url = \"https://a\", icon = \"{icon}\""));
            lint(&manifest("", &g, "\"local\""), &present())
        };
        assert!(check("files/c.png").is_empty());
        assert!(check("https://x/a.png").is_empty());
        for bad in ["files/missing.png", "http://x/a.png", "../a.png"] {
            let l = check(bad);
            assert_eq!(l.len(), 1, "{bad}");
            assert_eq!(l[0].code, "icon_invalid");
            assert_eq!(l[0].level, LintLevel::Error);
            assert_eq!(
                l[0].path.as_deref(),
                Some("config.teacher.apps.web[0].icon")
            );
        }
    }

    #[test]
    fn http_web_app_is_warning() {
        let g = web("url = \"http://intranet\"");
        let l = lint(&manifest("", &g, "\"local\""), &present());
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].code, "web_app_not_https");
        assert_eq!(l[0].level, LintLevel::Warning);
        assert!(!has_errors(&l));
    }

    #[test]
    fn google_issuer_passes_lint() {
        // Since 2026-11-05 Devices may sign in with Google accounts: an accounts.google.com issuer
        // is an ordinary OIDC issuer, not an error.
        for issuer in [
            "https://accounts.google.com",
            "https://Accounts.Google.com:443/",
        ] {
            let google = format!("oidc = {{ issuer = \"{issuer}\", client_id = \"c\" }}");
            let m = manifest(&google, "", "\"local\"");
            let l = lint(&m, &present());
            assert!(l.is_empty(), "{issuer}: {l:?}");
            let o = m.school.oidc.as_ref().expect("oidc");
            assert!(checks::oidc(o).is_ok(), "{issuer}");
        }
        let with = r#"oidc = { issuer = "https://accounts.google.com", client_id = "c", client_secret = "s" }
allowed_domains = ["school.ac.th"]"#;
        let l = lint(&manifest(with, "", "\"sso\""), &present());
        assert!(!has_errors(&l), "{l:?}");
    }

    #[test]
    fn same_ssid_in_different_configs_is_fine() {
        let m = Manifest::parse(
            r#"
version = 1
[[trust]]
id = "k"
alg = "ed25519"
public_key = "AAAA"
[school]
[[config]]
id = "a"
name = "a"
wifi = [{ ssid = "x" }]
printers = [{ name = "p", uri = "ipp://h" }]
scanners = [{ name = "p", uri = "http://h" }]
[[config]]
id = "b"
name = "b"
wifi = [{ ssid = "x" }]
[[group]]
id = "a"
name = "a"
config = "a"
[[group]]
id = "b"
name = "b"
config = "b"
"#,
        )
        .unwrap();
        // 不同配置同名 SSID、同配置里打印机与扫描仪同名，都不报。
        assert!(lint(&m, &present()).is_empty());
    }

    fn codes(l: &[Lint]) -> Vec<&'static str> {
        l.iter().map(|x| x.code).collect()
    }

    #[test]
    fn lint_admin_and_domain_caps() {
        let admins: Vec<String> = (0..=checks::MAX_ADMIN_USERS)
            .map(|i| format!("\"a{i}@x.th\""))
            .collect();
        let domains: Vec<String> = (0..=checks::MAX_ALLOWED_DOMAINS)
            .map(|i| format!("\"d{i}.th\""))
            .collect();
        let school = format!(
            "{OIDC}\nadmin_users = [{}]\nallowed_domains = [{}]",
            admins.join(","),
            domains.join(",")
        );
        let l = lint(&manifest(&school, "", "\"sso\""), &present());
        assert_eq!(
            codes(&l),
            ["admin_users_too_many", "allowed_domains_too_many"],
            "{l:?}"
        );
        assert!(l.iter().all(|x| x.level == LintLevel::Error));
        // 正好在上限：不报。
        let school = format!(
            "{OIDC}\nadmin_users = [{}]\nallowed_domains = [{}]",
            admins[..checks::MAX_ADMIN_USERS].join(","),
            domains[..checks::MAX_ALLOWED_DOMAINS].join(",")
        );
        assert!(lint(&manifest(&school, "", "\"sso\""), &present()).is_empty());
    }

    /// 管理员都是学校账号：分组的登录方式里没有 sso，管理员在这些机器上登录不了（broker 配置被删掉）。
    #[test]
    fn lint_admins_without_sso_is_warning() {
        let school = format!("{OIDC}\nadmin_users = [\"boss@x.th\"]");
        let l = lint(&manifest(&school, "", "\"local\""), &present());
        assert_eq!(codes(&l), ["admins_without_sso"], "{l:?}");
        assert_eq!(l[0].level, LintLevel::Warning);
        assert!(l[0].message.contains("cannot sign in"), "{}", l[0].message);
        assert_eq!(l[0].params["group"], "teacher");
        assert_eq!(l[0].path.as_deref(), Some("config.teacher.login_methods"));
        assert!(lint(&manifest(&school, "", "\"local\", \"sso\""), &present()).is_empty());
        // 没有管理员：不报。
        assert!(lint(&manifest("", "", "\"local\""), &present()).is_empty());
    }

    #[test]
    fn lint_oidc_with_newline() {
        let bad =
            r#"oidc = { issuer = "https://sso.x.th\nallowed_users = OWNER", client_id = "c" }"#;
        let l = lint(&manifest(bad, "", "\"sso\""), &present());
        assert_eq!(codes(&l), ["oidc_invalid"], "{l:?}");
        assert_eq!(l[0].path.as_deref(), Some("school.oidc"));
        assert_eq!(l[0].level, LintLevel::Error);
    }

    #[test]
    fn lint_oidc_card_keys() {
        let with = |extra: &str| {
            format!(r#"oidc = {{ issuer = "https://sso.x.th", client_id = "c", {extra} }}"#)
        };
        let ok = with(r#"client_secret = "s-1", card_hosts = ["cdn.x.th"]"#);
        assert!(lint(&manifest(&ok, "", "\"sso\""), &present()).is_empty());
        for bad in [
            r#"card_hosts = ["*.x.th"]"#,
            r#"card_hosts = ["https://cdn.x.th"]"#,
            r#"client_secret = "a b""#,
            r#"client_secret = """#,
        ] {
            let l = lint(&manifest(&with(bad), "", "\"sso\""), &present());
            assert_eq!(codes(&l), ["oidc_invalid"], "{bad}: {l:?}");
            assert_eq!(l[0].path.as_deref(), Some("school.oidc"));
        }
    }

    #[test]
    fn lint_admin_user_with_quote() {
        let l = lint(
            &manifest(
                &format!("{OIDC}\nadmin_users = [\"ok@x.th\", \"a\\\"b@x.th\"]"),
                "",
                "\"local\", \"sso\"",
            ),
            &present(),
        );
        assert_eq!(codes(&l), ["admin_user_invalid"], "{l:?}");
        assert_eq!(l[0].path.as_deref(), Some("school.admin_users[1]"));
        assert_eq!(l[0].level, LintLevel::Error);
    }

    #[test]
    fn lint_school_formats() {
        let l = lint(
            &manifest(
                "allowed_domains = [\"Bad.th\"]\ntimezone = \"../x\"\nlocale = \"th_TH\"",
                "",
                "\"local\"",
            ),
            &present(),
        );
        assert_eq!(
            codes(&l),
            [
                "allowed_domain_invalid",
                "timezone_invalid",
                "locale_invalid"
            ],
            "{l:?}"
        );
        assert_eq!(l[0].path.as_deref(), Some("school.allowed_domains[0]"));
        assert_eq!(l[0].params["domain"], "Bad.th");
    }

    #[test]
    fn lint_group_item_formats() {
        let g = r#"wifi = [{ ssid = "a", psk = "x" }]
printers = [{ name = "p", uri = "file:///dev/null" }]
scanners = [{ name = "s", uri = "ipp://x" }]
[group.apps]
web = [{ name = "w", url = "https://a\"b" }]
flatpak = ["libreoffice"]"#;
        let l = lint(&manifest("", g, "\"local\""), &present());
        assert_eq!(
            codes(&l),
            [
                "wifi_invalid",
                "printer_invalid",
                "scanner_invalid",
                "web_app_invalid",
                "flatpak_id_invalid"
            ],
            "{l:?}"
        );
        assert_eq!(l[0].path.as_deref(), Some("config.teacher.wifi[0]"));
        assert_eq!(l[1].path.as_deref(), Some("config.teacher.printers[0]"));
        assert_eq!(l[4].path.as_deref(), Some("config.teacher.apps.flatpak[0]"));
    }

    #[test]
    fn lint_duplicate_ssid_in_group() {
        let g = r#"wifi = [{ ssid = "a" }, { ssid = "b" }, { ssid = "a" }]"#;
        let l = lint(&manifest("", g, "\"local\""), &present());
        assert_eq!(codes(&l), ["wifi_ssid_duplicate"], "{l:?}");
        assert_eq!(l[0].path.as_deref(), Some("config.teacher.wifi[2]"));
    }

    #[test]
    fn lint_duplicate_device_names() {
        let g = r#"printers = [{ name = "p", uri = "ipp://x" }, { name = "p", uri = "ipp://y" }]
scanners = [{ name = "s", uri = "http://x" }, { name = "s", uri = "http://y" }]"#;
        let l = lint(&manifest("", g, "\"local\""), &present());
        assert_eq!(
            codes(&l),
            ["device_name_duplicate", "device_name_duplicate"],
            "{l:?}"
        );
        assert_eq!(l[1].path.as_deref(), Some("config.teacher.scanners[1]"));
    }

    /// 打印机按 CUPS 的队列名比：整理（/ # 等换成 _）之后相同、或只差大小写（CUPS 的队列名不分大小写），后一项报错。
    #[test]
    fn lint_printer_queue_collisions() {
        let g = r#"printers = [{ name = "A/B", uri = "ipp://x" }, { name = "A#B", uri = "ipp://y" }, { name = "office", uri = "ipp://z" }, { name = "Office", uri = "ipp://w" }]"#;
        let l = lint(&manifest("", g, "\"local\""), &present());
        assert_eq!(
            codes(&l),
            ["device_name_duplicate", "device_name_duplicate"],
            "{l:?}"
        );
        assert_eq!(l[0].path.as_deref(), Some("config.teacher.printers[1]"));
        assert!(l[0].message.contains("A_B"), "{l:?}");
        assert_eq!(l[1].path.as_deref(), Some("config.teacher.printers[3]"));
    }

    #[test]
    fn lint_lock_message_too_long() {
        let mut m = manifest("", "", "\"local\"");
        m.devices = Manifest::parse(&format!(
            "version = 1\n[[device]]\nserial = \"SN-1\"\ngroup = \"teacher\"\nlocked = {{ message = \"{}\" }}\n",
            "字".repeat(501)
        ))
        .unwrap()
        .devices;
        let l = lint(&m, &present());
        assert_eq!(codes(&l), ["lock_message_too_long"], "{l:?}");
        assert_eq!(l[0].path.as_deref(), Some("device[0].locked.message"));
    }

    #[test]
    fn lint_serializes_params_and_null_span() {
        let l = Lint::new(LintLevel::Error, "icon_invalid", "x")
            .at("group.a.apps.web[0].icon")
            .param("app_name", "Khan");
        let v = serde_json::to_value(&l).unwrap();
        assert_eq!(v["params"]["app_name"], "Khan");
        assert!(v["span"].is_null());
        assert_eq!(v["path"], "group.a.apps.web[0].icon");
        // No params: still an empty object, never absent.
        let v = serde_json::to_value(Lint::new(LintLevel::Info, "x", "y")).unwrap();
        assert_eq!(v["params"], serde_json::json!({}));
        assert!(v["path"].is_null());
    }

    fn is_cjk(c: char) -> bool {
        matches!(c, '\u{3000}'..='\u{303f}' | '\u{4e00}'..='\u{9fff}' | '\u{ff00}'..='\u{ffef}')
    }

    /// Every code the manifest-only rules and the server wording helpers produce: English message, and
    /// the params the web UI translates with.
    #[test]
    fn every_lint_message_is_english_and_has_params() {
        const WANT: &[(&str, &[&str])] = &[
            ("sso_without_oidc", &["config", "group"]),
            ("icon_invalid", &["config", "group", "app_name", "icon"]),
            ("web_app_not_https", &["config", "group", "app_name", "url"]),
            ("update_channel_unknown", &["channel"]),
            ("device_reset_id_invalid", &["device"]),
            ("device_reset_requested", &["device"]),
            ("feature_unsupported", &["feature", "devices"]),
            ("feature_unsupported_in_use", &["feature", "devices"]),
            ("school_id_mismatch", &["expected"]),
            ("kiosk_no_entry", &["config", "group", "app_name"]),
            ("kiosk_flatpak_missing", &["config", "group", "app_name"]),
            ("kiosk_user_agent", &["config", "group", "app_name"]),
            ("kiosk_in_session_only", &["config", "group", "app_name"]),
            ("kiosk_too_many", &["config", "group", "count", "max"]),
            ("chrome_paused", &["config", "group", "until", "groups"]),
            ("admins_without_sso", &["config", "group"]),
            ("no_admins", &["config", "group"]),
            ("update_mirror_not_https", &["url"]),
            ("admin_users_too_many", &["count", "max"]),
            ("allowed_domains_too_many", &["count", "max"]),
            ("wifi_ssid_duplicate", &["ssid"]),
            ("wifi_open_implicit", &["ssid"]),
            ("wifi_server_unchecked", &["config", "group", "ssid"]),
            ("device_name_duplicate", &["config", "group", "name"]),
            // Wording from `checks`, shared with the agent.
            ("wifi_invalid", &[]),
            ("printer_invalid", &[]),
            ("scanner_invalid", &[]),
            ("web_app_invalid", &[]),
            ("flatpak_id_invalid", &[]),
            ("admin_user_invalid", &["user"]),
            ("allowed_domain_invalid", &["domain"]),
            ("timezone_invalid", &[]),
            ("locale_invalid", &[]),
            ("oidc_invalid", &[]),
            ("update_mirror_invalid", &[]),
            ("escrow_recipients_invalid", &[]),
            ("lock_message_too_long", &[]),
            ("chrome_window_invalid", &[]),
            ("chrome_pause_invalid", &[]),
            ("chrome_pause_too_long", &[]),
            // Wording from `kiosk`.
            ("kiosk_id_invalid", &["config", "group", "app_id", "field"]),
            (
                "kiosk_launch_invalid",
                &["config", "group", "app_id", "field"],
            ),
            ("config_unused", &["config"]),
            ("group_name_duplicate", &["group", "other", "name"]),
            ("flatpak_now_installed", &["config", "groups", "apps"]),
            ("kiosk_url_not_https", &["field"]),
            ("kiosk_allow_invalid", &["field"]),
            ("kiosk_exec_invalid", &["field"]),
            ("kiosk_extension_invalid", &["field"]),
            ("kiosk_user_agent_invalid", &["field"]),
            ("kiosk_name_invalid", &["field"]),
            ("kiosk_policy_locked", &["field"]),
            ("drop_unknown", &["config", "group", "collection", "name"]),
            ("drop_conflict", &["config", "group", "collection", "name"]),
            ("it_account_invalid", &["layer"]),
            ("logo_sha256_invalid", &[]),
            ("logo_incomplete", &[]),
            ("school_name_invalid", &[]),
            ("school_wifi_moved", &[]),
            ("format_unsupported", &["found", "devices"]),
            ("format_unsupported_in_use", &["found", "devices"]),
        ];
        let today = on("2026-11-06");
        let mut all: Vec<Lint> = Vec::new();
        let mut run = |school: &str, group: &str, login: &str| {
            all.extend(super::lint_at(
                &manifest(school, group, login),
                &present(),
                today,
            ));
        };
        run(
            "update_channel = \"nightly\"\nupdate_mirror = \"http://10.0.0.5\"\nadmin_users = [\"%x@x.th\"]",
            "[group.chrome]\nupdate_window = \"16:00-16:00\"\npause_until = \"2026-11-20\"",
            "\"sso\"",
        );
        run(
            "wifi = [{ ssid = \"s\" }, { ssid = \"s\", open = true }]",
            "",
            "\"local\"",
        );
        run(
            "timezone = \"../x\"\nlocale = \"th_TH\"\nallowed_domains = [\"Bad.th\"]\nescrow_recipients = [\"age1nope\"]\nupdate_mirror = \"file:///x\"",
            "[group.chrome]\npause_until = \"2026-11-21\"",
            "\"local\"",
        );
        run(
            "oidc = { issuer = \"https://accounts.google.com\", client_id = \"c\" }",
            "[group.chrome]\npause_until = \"2026-13-01\"",
            "\"local\"",
        );
        run(
            "oidc = { issuer = \"ftp://x\", client_id = \"c\" }\nadmin_users = [\"a@x.th\"]",
            "",
            "\"local\"",
        );
        run(
            "",
            r#"wifi = [{ ssid = "a", psk = "x" }, { ssid = "a" }, { ssid = "e", eap = "peap", identity = "i", password = "p", check_server = false }]
printers = [{ name = "A/B", uri = "file:///x" }, { name = "A#B", uri = "ipp://y" }]
scanners = [{ name = "s", uri = "ipp://x" }, { name = "s", uri = "http://y" }]
[group.apps]
web = [{ name = "w", url = "http://a\"b", icon = "files/missing.png" }]
flatpak = ["libreoffice"]"#,
            "\"local\"",
        );
        let many: String = (0..=MAX).map(|i| kiosk(&format!("a{i}"), NWEA)).collect();
        run("", &many, "\"local\"");
        let ext =
            "[[group.apps.kiosk.x.extensions]]\nid = \"abc\"\nupdate_url = \"https://v.example/u\"";
        for (id, fields) in [
            ("NWEA", NWEA.to_string()),
            ("x", "name = \"n\"".to_string()),
            ("x", format!("{NWEA}\nandroid = {{}}")),
            ("x", "name = \"n\"\nurl = \"http://a.org/\"".to_string()),
            ("x", format!("{NWEA}\nallow = [\"org\"]")),
            ("x", format!("{NWEA}\nallow = [\"*.org\"]")),
            ("x", "name = \"n\"\nexec = \"/opt/x\"".to_string()),
            ("x", format!("{NWEA}\n{ext}")),
            ("x", format!("{NWEA}\nuser_agent = \"a\\nb\"")),
            ("x", "name = \"\"\nurl = \"https://a.org/\"".to_string()),
            (
                "x",
                format!("{NWEA}\nchrome_policy = {{ URLBlocklist = [] }}"),
            ),
            ("x", format!("{NWEA}\nicon = \"files/missing.png\"")),
            ("x", format!("{NWEA}\nlogin_screen = false")),
            (
                "x",
                format!("{NWEA}\nlogin_screen = false\nin_session = true"),
            ),
            ("x", format!("{NWEA}\nuser_agent = \"Mozilla/5.0\"")),
            ("x", "name = \"c\"\nexec = \"org.example.Calc\"".to_string()),
        ] {
            run("", &kiosk(id, &fields), "\"local\"");
        }
        let admins: Vec<String> = (0..=checks::MAX_ADMIN_USERS)
            .map(|i| format!("\"a{i}@x.th\""))
            .collect();
        let domains: Vec<String> = (0..=checks::MAX_ALLOWED_DOMAINS)
            .map(|i| format!("\"d{i}.th\""))
            .collect();
        run(
            &format!(
                "{OIDC}\nadmin_users = [{}]\nallowed_domains = [{}]",
                admins.join(","),
                domains.join(",")
            ),
            "",
            "\"sso\"",
        );
        // Device lints need `m.devices`, which the `manifest` helper leaves empty.
        let mut m = manifest("", "", "\"local\"");
        m.devices = Manifest::parse(&format!(
            "version = 1\n[[device]]\nserial = \"SN-1\"\ngroup = \"teacher\"\nlocked = {{ message = \"{}\" }}\nreset = {{ id = \"a b\", requested_at = \"2026-10-15T00:00:00Z\" }}\n",
            "x".repeat(501)
        ))
        .unwrap()
        .devices;
        all.extend(super::lint_at(&m, &present(), today));
        // A config no group uses.
        let mut unused = manifest("", "", "\"local\"");
        unused.groups.clear();
        all.extend(super::lint_at(&unused, &present(), today));
        // Lints worded here but computed by the server.
        let mut prev =
            Manifest::parse("version = 1\n[[group]]\nid = \"teacher\"\nname = \"t\"\n").unwrap();
        prev.configs[0].legacy_browser = true;
        all.extend(flatpak_now_installed(
            &prev,
            &manifest("", "[group.apps]\nflatpak = [\"org.x.Y\"]", "\"local\""),
        ));
        let legacy =
            Manifest::parse("version = 1\n[[group]]\nid = \"default\"\nname = \"d\"\n").unwrap();
        all.extend(super::lint_at(&legacy, &present(), today));
        // Phase B rules (format 2 text).
        all.extend(super::lint_at(
            &manifest2(
                r#"
[school]
name = ""
logo_sha256 = "ABC"
wifi = [{ ssid = "s", open = true }]
[[config]]
id = "a"
name = "a"
drop.printers = ["Nope"]
it_account = { password_hash = "$1$x" }
apps.flatpak = ["org.gimp.GIMP"]
drop.apps.flatpak = ["org.gimp.GIMP"]
"#,
            ),
            &present(),
            today,
        ));
        all.extend(lint_at(
            &manifest2(
                r#"
[[config]]
id = "a"
name = "a"

[[group]]
id = "default"
name = "Same"
config = "a"

[[group]]
id = "other"
name = "same"
config = "a"
"#,
            ),
            &present(),
            today,
        ));
        all.push(format_unsupported(2, &gap(3)));
        all.push(format_unsupported_in_use(2, &gap(3)));
        all.push(feature_unsupported(
            "escrow_recipients",
            "school.escrow_recipients",
            &gap(3),
        ));
        all.push(feature_unsupported_in_use(
            "update_mirror",
            "school.update_mirror",
            &gap(2),
        ));
        all.push(
            school_id_mismatch(
                &manifest("", "", ""),
                "0192f3a4-5b6c-7d8e-9f00-00000000000a",
            )
            .unwrap(),
        );

        for (code, keys) in WANT {
            let mut seen = all.iter().filter(|l| l.code == *code).peekable();
            assert!(seen.peek().is_some(), "no fixture produced {code}");
            for l in seen {
                for k in *keys {
                    assert!(l.params.contains_key(k), "{code} lacks param {k}: {l:?}");
                }
            }
        }
        // wifi_ssid_duplicate per layer: config lints keep config and group, school lints say so.
        let dups: Vec<_> = all
            .iter()
            .filter(|l| l.code == "wifi_ssid_duplicate")
            .collect();
        let (school, config): (Vec<&&Lint>, Vec<&&Lint>) = dups
            .iter()
            .partition(|l| l.path.as_deref().is_some_and(|p| p.starts_with("school.")));
        assert!(!school.is_empty() && !config.is_empty(), "{dups:?}");
        for l in school {
            assert_eq!(
                l.params.get("layer").map(String::as_str),
                Some("school"),
                "{l:?}"
            );
        }
        for l in config {
            for k in ["config", "group", "ssid"] {
                assert!(l.params.contains_key(k), "{l:?}");
            }
            assert!(!l.params.contains_key("layer"), "{l:?}");
        }
        for l in &all {
            assert!(!l.message.chars().any(is_cjk), "{l:?}");
        }
    }

    const BAD_PSK: &str = "hunter2";

    #[test]
    fn lint_messages_never_contain_psk() {
        let g = format!(
            "wifi = [{{ ssid = \"a\", psk = \"{BAD_PSK}\" }}, {{ ssid = \"a\", psk = \"{BAD_PSK}\" }}]"
        );
        let l = lint(&manifest("", &g, "\"local\""), &present());
        assert!(l.iter().any(|x| x.code == "wifi_invalid"));
        for x in &l {
            assert!(!x.message.contains(BAD_PSK), "{x:?}");
            assert!(!x.path.as_deref().unwrap_or("").contains(BAD_PSK));
        }
    }

    fn on(date: &str) -> chrono::NaiveDate {
        chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").unwrap()
    }

    /// Task 23：Chrome 的更新时段与暂停。时段格式不对、暂停超过发布日 14 天都是 error；在暂停的分组列成 info。
    #[test]
    fn lint_chrome_update_window_and_pause() {
        let today = on("2026-11-06");
        let at = |g: &str| {
            super::lint_at(&manifest("", g, "\"local\""), &present(), today)
                .into_iter()
                .filter(|l| l.code != "no_admins")
                .collect::<Vec<_>>()
        };
        assert!(at("[group.chrome]\nupdate_window = \"16:00-07:00\"").is_empty());
        let l = at("[group.chrome]\nupdate_window = \"16:00-16:00\"");
        assert_eq!(codes(&l), ["chrome_window_invalid"], "{l:?}");
        assert_eq!(l[0].level, LintLevel::Error);
        assert_eq!(
            l[0].path.as_deref(),
            Some("config.teacher.chrome.update_window")
        );

        let l = at("[group.chrome]\npause_until = \"2026-11-21\"");
        assert_eq!(codes(&l), ["chrome_pause_too_long"], "{l:?}");
        assert_eq!(l[0].level, LintLevel::Error);
        assert_eq!(
            l[0].path.as_deref(),
            Some("config.teacher.chrome.pause_until")
        );
        let l = at("[group.chrome]\npause_until = \"2026-13-01\"");
        assert_eq!(codes(&l), ["chrome_pause_invalid"], "{l:?}");
        assert_eq!(l[0].level, LintLevel::Error);

        // 14 天以内：只是 info，写出分组与日期
        let l = at("[group.chrome]\npause_until = \"2026-11-20\"");
        assert_eq!(codes(&l), ["chrome_paused"], "{l:?}");
        assert_eq!(l[0].level, LintLevel::Info);
        assert_eq!(l[0].params["groups"], "teacher");
        assert_eq!(l[0].params["config"], "teacher");
        assert_eq!(l[0].params["group"], "teacher");
        assert!(!has_errors(&l));
        assert!(
            l[0].message.contains("teacher") && l[0].message.contains("2026-11-20"),
            "{}",
            l[0].message
        );
        assert!(!l[0].message.contains("  "), "{}", l[0].message);
        // TOML 的裸日期也认
        let l = at("[group.chrome]\npause_until = 2026-11-20");
        assert_eq!(codes(&l), ["chrome_paused"], "{l:?}");
        // 已经过去的暂停：没有效果，不报
        assert!(at("[group.chrome]\npause_until = \"2026-11-05\"").is_empty());
        // 暂停到今天（含）仍在暂停
        assert_eq!(
            codes(&at("[group.chrome]\npause_until = \"2026-11-06\"")),
            ["chrome_paused"]
        );
    }

    /// Config profiles design §3: `chrome_paused` names every group that uses the paused config.
    #[test]
    fn chrome_paused_lists_the_groups_of_the_config() {
        let mut m = manifest("", "[group.chrome]\npause_until = 2026-11-10", "\"local\"");
        for id in ["cart-g4", "default"] {
            m.groups.push(crate::Group {
                id: id.into(),
                name: id.into(),
                config: "teacher".into(),
            });
        }
        let l: Vec<_> = super::lint_at(&m, &present(), on("2026-11-06"))
            .into_iter()
            .filter(|l| l.code == "chrome_paused")
            .collect();
        assert_eq!(l.len(), 1, "{l:?}");
        assert_eq!(l[0].params["groups"], "teacher,cart-g4,default");
        assert_eq!(
            l[0].path.as_deref(),
            Some("config.teacher.chrome.pause_until")
        );
        assert!(
            l[0].message.contains("groups: teacher, cart-g4, default"),
            "{}",
            l[0].message
        );
        m.groups.clear();
        let l: Vec<_> = super::lint_at(&m, &present(), on("2026-11-06"))
            .into_iter()
            .filter(|l| l.code == "chrome_paused")
            .collect();
        assert_eq!(l[0].params["groups"], "");
        assert!(
            l[0].message.contains("no group uses it yet"),
            "{}",
            l[0].message
        );
    }

    #[test]
    fn spec_example_has_no_error_lints() {
        let m = Manifest::parse(&crate::testutil::spec_example()).unwrap();
        let l = lint(&m, &crate::testutil::spec_example_present());
        assert!(!has_errors(&l), "{l:?}");
    }

    #[test]
    fn validate_still_accepts_bad_items() {
        let g = r#"wifi = [{ ssid = "a", psk = "x" }]"#;
        let mut m = manifest(
            "admin_users = [\"a\\\"b@x.th\"]\ntimezone = \"../x\"",
            g,
            "\"local\"",
        );
        let l = lint(&m, &present());
        assert!(has_errors(&l), "{l:?}");
        assert!(l.len() >= 3);
        m.groups[0].id = "default".into();
        m.trust[0].public_key = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode([7u8; 32])
        };
        m.validate(&present()).unwrap();
    }

    #[test]
    fn lint_escrow_recipients_invalid() {
        let l = lint(
            &manifest("escrow_recipients = [\"age1nope\"]", "", "\"local\""),
            &present(),
        );
        assert_eq!(codes(&l), ["escrow_recipients_invalid"], "{l:?}");
        assert_eq!(l[0].path.as_deref(), Some("school.escrow_recipients"));
    }

    /// `n` machines; the first runs no known OS, none run an image known to support the key.
    fn gap(n: usize) -> FleetGap {
        FleetGap {
            devices: (0..n)
                .map(|i| GapDevice {
                    name: format!("SN{i}"),
                    os_version: (i > 0).then(|| format!("2026102{i}.1")),
                })
                .collect(),
            until: chrono::NaiveDate::from_ymd_opt(2026, 11, 4).unwrap(),
            supported_in: None,
        }
    }

    #[test]
    fn fleet_lint_wording() {
        let l = feature_unsupported("escrow_recipients", "school.escrow_recipients", &gap(3));
        assert_eq!(l.level, LintLevel::Error);
        assert_eq!(l.code, "feature_unsupported");
        assert_eq!(
            l.message,
            "3 device(s) seen in the last 30 days do not understand 'escrow_recipients' and \
             would reject this version: SN0 (unknown OS), SN1 (20261021.1), SN2 (20261022.1). \
             To publish, update them to an OS image that supports it (no device of this school \
             runs one yet; it may not be released), take them out of use, or wait until they \
             have been silent for 30 days (on 2026-11-04 if none reports again)."
        );
        assert_eq!(l.path.as_deref(), Some("school.escrow_recipients"));
        assert_eq!(l.params["devices"], "3");
        assert_eq!(
            l.params["device_list"],
            "SN0 (unknown OS), SN1 (20261021.1), SN2 (20261022.1)"
        );
        assert_eq!(l.params["more"], "0");
        assert_eq!(l.params["until"], "2026-11-04");
        assert_eq!(l.params["supported_in"], "");
        let mut g = gap(2);
        g.supported_in = Some("20261030.1".into());
        let l = feature_unsupported_in_use("update_mirror", "school.update_mirror", &g);
        assert_eq!(l.level, LintLevel::Warning);
        assert_eq!(l.code, "feature_unsupported_in_use");
        assert!(
            l.message.contains("update them to OS 20261030.1 or newer"),
            "{}",
            l.message
        );
        assert_eq!(l.params["supported_in"], "20261030.1");
        assert_eq!(l.path.as_deref(), Some("school.update_mirror"));
    }

    #[test]
    fn fleet_lint_names_at_most_ten() {
        let l = format_unsupported(2, &gap(13));
        assert_eq!(l.params["devices"], "13");
        assert_eq!(l.params["more"], "3");
        assert_eq!(l.params["device_list"].matches(", ").count(), 9);
        assert!(l.message.contains(" and 3 more."), "{}", l.message);
    }

    #[test]
    fn group_names_must_differ_ignoring_case() {
        let m = manifest2(
            r#"
[[config]]
id = "a"
name = "a"

[[group]]
id = "default"
name = "Teachers"
config = "a"

[[group]]
id = "teachers2"
name = " teachers "
config = "a"

[[group]]
id = "lab"
name = "Lab"
config = "a"
"#,
        );
        let l = super::lint(&m, &present());
        let d = of_code(&l, "group_name_duplicate");
        assert_eq!(d.len(), 1, "{l:?}");
        assert_eq!(d[0].level, LintLevel::Error);
        assert_eq!(d[0].path.as_deref(), Some("group.teachers2.name"));
        assert_eq!(d[0].params["other"], "default");
        assert_eq!(d[0].params["name"], "teachers");
    }

    #[test]
    fn feature_path_points_at_the_use() {
        let m = manifest2(
            r#"
[[config]]
id = "a"
name = "a"

[[config]]
id = "b"
name = "b"
wifi = [{ ssid = "x", psk = "12345678", wpa3_only = true }]
apps.kiosk.k = { name = "K", url = "https://k.example/" }

[[group]]
id = "default"
name = "D"
config = "a"
"#,
        );
        assert_eq!(feature_path(&m, crate::FEATURE_CONFIG), "config");
        assert_eq!(
            feature_path(&m, crate::FEATURE_KIOSK),
            "config.b.apps.kiosk"
        );
        assert_eq!(
            feature_path(&m, crate::FEATURE_WIFI_EXT),
            "config.b.wifi[0]"
        );
        assert_eq!(feature_path(&m, crate::FEATURE_SCHOOL_ID), "school.id");
        assert_eq!(feature_path(&m, crate::FEATURE_OIDC_CARD), "school.oidc");
        assert_eq!(feature_path(&m, "nope"), "school");
    }

    #[test]
    fn feature_path_points_at_support() {
        let body = |defaults: &str| {
            manifest2(&format!(
                "{defaults}\n[[config]]\nid = \"a\"\nname = \"a\"\n\n[[config]]\nid = \"b\"\nname = \"b\"\n\
                 [config.support]\nenabled = false\n\n[[group]]\nid = \"default\"\nname = \"D\"\nconfig = \"a\"\n"
            ))
        };
        assert_eq!(
            feature_path(&body(""), crate::FEATURE_SUPPORT),
            "config.b.support"
        );
        assert_eq!(
            feature_path(
                &body("[defaults]\nsupport.enabled = true"),
                crate::FEATURE_SUPPORT
            ),
            "defaults.support"
        );
    }

    #[test]
    fn lint_update_mirror() {
        let extra = "update_mirror = \"https://cache.school.ac.th/mastersos\"";
        assert!(lint(&manifest(extra, "", "\"local\""), &present()).is_empty());
        // http:// is allowed (school caches are often plain HTTP by IP) but draws a warning, not an error.
        let l = lint(
            &manifest("update_mirror = \"http://10.0.0.5:8080\"", "", "\"local\""),
            &present(),
        );
        assert_eq!(l.len(), 1, "{l:?}");
        assert_eq!(l[0].code, "update_mirror_not_https");
        assert_eq!(l[0].level, LintLevel::Warning);
        for bad in [
            "file:///srv/os",
            "https://cache.lan/os?x=1",
            "https://user:pw@cache.lan/os",
        ] {
            let extra = format!("update_mirror = \"{bad}\"");
            let l = lint(&manifest(&extra, "", "\"local\""), &present());
            assert_eq!(l.len(), 1, "{bad}: {l:?}");
            assert_eq!(l[0].code, "update_mirror_invalid");
            assert_eq!(l[0].level, LintLevel::Error);
            assert_eq!(l[0].path.as_deref(), Some("school.update_mirror"));
        }
    }

    #[test]
    fn feature_path_points_at_config_update_channel() {
        let body = |defaults: &str| {
            manifest2(&format!(
                "{defaults}\n[[config]]\nid = \"a\"\nname = \"a\"\n\n[[config]]\nid = \"b\"\nname = \"b\"\n\
                 update_channel = \"beta\"\n\n[[group]]\nid = \"default\"\nname = \"D\"\nconfig = \"a\"\n"
            ))
        };
        assert_eq!(
            feature_path(&body(""), crate::FEATURE_CONFIG_CHANNEL),
            "config.b.update_channel"
        );
        assert_eq!(
            feature_path(
                &body("[defaults]\nupdate_channel = \"stable\""),
                crate::FEATURE_CONFIG_CHANNEL
            ),
            "defaults.update_channel"
        );
        // an unknown value in a Config is an error at that Config
        let m = manifest2(
            "[[config]]\nid = \"t\"\nname = \"T\"\nupdate_channel = \"nightly\"\n\n\
             [[group]]\nid = \"default\"\nname = \"D\"\nconfig = \"t\"\n",
        );
        let l: Vec<_> = lint(&m, &present())
            .into_iter()
            .filter(|l| l.code == "update_channel_unknown")
            .collect();
        assert_eq!(l.len(), 1, "{l:?}");
        assert_eq!(l[0].path.as_deref(), Some("config.t.update_channel"));
    }

    #[test]
    fn lint_unknown_update_channel() {
        let l = lint(
            &manifest("update_channel = \"nightly\"", "", "\"local\""),
            &present(),
        );
        assert_eq!(l.len(), 1, "{l:?}");
        assert_eq!(l[0].code, "update_channel_unknown");
        assert_eq!(l[0].level, LintLevel::Error);
        assert_eq!(l[0].path.as_deref(), Some("school.update_channel"));
        for ok in ["stable", "beta"] {
            let extra = format!("update_channel = \"{ok}\"");
            assert!(lint(&manifest(&extra, "", "\"local\""), &present()).is_empty());
        }
        // validate 仍放行（Ruling 5/6：agent 遇到未知值按 stable 处理并回报）。
        let mut m = manifest("update_channel = \"nightly\"", "", "\"local\"");
        m.groups[0].id = "default".into();
        m.trust[0].public_key = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode([7u8; 32])
        };
        m.validate(&present()).unwrap();
    }

    #[test]
    fn lint_lists_pending_resets() {
        let mut m = manifest("", "", "\"local\"");
        m.devices = Manifest::parse(
            r#"
version = 1
[[device]]
serial = "SN-1"
group = "teacher"
[[device]]
device_id = "dev-9"
group = "teacher"
reset = { id = "r-1", requested_at = "2026-10-15T00:00:00Z" }
[[device]]
serial = "SN-3"
group = "teacher"
reset = { id = "r-2", requested_at = "2026-10-15T00:00:00Z" }
"#,
        )
        .unwrap()
        .devices;
        let l = lint(&m, &present());
        assert_eq!(l.len(), 2, "{l:?}");
        for x in &l {
            assert_eq!(x.code, "device_reset_requested");
            assert_eq!(x.level, LintLevel::Warning);
        }
        assert_eq!(l[0].path.as_deref(), Some("device[1]"));
        assert!(l[0].message.contains("dev-9"), "{}", l[0].message);
        assert!(l[0].message.contains("ignore"), "{}", l[0].message);
        assert!(
            !l[0].message.contains("will be factory-reset"),
            "{}",
            l[0].message
        );
        assert_eq!(l[1].path.as_deref(), Some("device[2]"));
        assert!(l[1].message.contains("SN-3"), "{}", l[1].message);
        assert!(!has_errors(&l));
    }

    #[test]
    fn lint_reset_id_invalid() {
        let mut m = manifest("", "", "\"local\"");
        m.devices = Manifest::parse(
            "version = 1\n[[device]]\nserial = \"SN-1\"\ngroup = \"teacher\"\nreset = { id = \"a\\nb\", requested_at = \"2026-10-15T00:00:00Z\" }\n",
        )
        .unwrap()
        .devices;
        let l = lint(&m, &present());
        assert!(
            l.iter().any(|x| x.code == "device_reset_id_invalid"
                && x.level == LintLevel::Error
                && x.path.as_deref() == Some("device[0].reset.id")),
            "{l:?}"
        );
        for (id, ok) in [
            ("3f1c2a9e-0b7d-4e2a-9c51-6a2f8d0e4b17", true),
            ("r-1", true),
            ("", false),
            ("a b", false),
            ("a\nb", false),
            (&"x".repeat(65), false),
        ] {
            let r = ResetRequest {
                id: id.into(),
                requested_at: chrono::DateTime::UNIX_EPOCH,
            };
            assert_eq!(r.check_id().is_ok(), ok, "{id:?}");
        }
    }

    #[test]
    fn manifest_validate_unchanged() {
        // Ruling 6：validate 不收紧，机器端重跑不会因为这些内容规则丢设置。
        let g = web("url = \"https://a\", icon = \"files/missing.png\"");
        let m = manifest("", &g, "\"sso\"");
        assert!(!lint(&m, &present()).is_empty());
        let mut m = m;
        m.groups.push(crate::Group {
            id: "default".into(),
            name: "d".into(),
            config: "teacher".into(),
        });
        m.trust[0].public_key = {
            // 用一个真实长度的公钥，免得 validate 因钥匙格式失败而掩盖本测试的意图。
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode([7u8; 32])
        };
        m.validate(&present()).unwrap();
    }

    /// Plan 6 Task 10b: `school_id_mismatch` when `[school] id` is missing or another school's.
    #[test]
    fn lint_school_id_mismatch() {
        const A: &str = "0192f3a4-5b6c-7d8e-9f00-00000000000a";
        const B: &str = "0192f3a4-5b6c-7d8e-9f00-00000000000b";
        assert_eq!(
            school_id_mismatch(&manifest(&format!("id = \"{A}\""), "", ""), A),
            None
        );
        let other = school_id_mismatch(&manifest(&format!("id = \"{B}\""), "", ""), A).unwrap();
        let missing = school_id_mismatch(&manifest("", "", ""), A).unwrap();
        for l in [&other, &missing] {
            assert_eq!(l.level, LintLevel::Error);
            assert_eq!(l.code, "school_id_mismatch");
            assert_eq!(l.path.as_deref(), Some("school.id"));
            assert!(
                l.message.contains(&format!("id = \"{A}\"")),
                "{}",
                l.message
            );
        }
        assert!(other.message.contains(B), "{}", other.message);
        assert!(missing.message.contains("missing"), "{}", missing.message);
        // The manifest-only lint never reports it: only the server knows its school.
        assert!(super::lint(&manifest("", "", ""), &BTreeSet::new())
            .iter()
            .all(|l| l.code != "school_id_mismatch"));
    }

    /// `[group.apps.kiosk.<id>]` 一段（接在 `manifest` 的分组后面）。
    fn kiosk(id: &str, fields: &str) -> String {
        format!("[group.apps.kiosk.{id}]\n{fields}\n")
    }

    const NWEA: &str = "name = \"NWEA MAP\"\nurl = \"https://test.mapnwea.org/\"";

    /// 计划 9 Task 1：`kiosk::check` 的每个错误都变成 error 级 lint，路径落在出错的字段上。
    #[test]
    fn lint_kiosk_check_errors() {
        let ext =
            "[[group.apps.kiosk.x.extensions]]\nid = \"abc\"\nupdate_url = \"https://v.example/u\"";
        for (id, fields, code, field) in [
            ("NWEA", NWEA.to_string(), "kiosk_id_invalid", "id"),
            ("x", "name = \"n\"".into(), "kiosk_launch_invalid", "url"),
            (
                "x",
                format!("{NWEA}\nandroid = {{}}"),
                "kiosk_launch_invalid",
                "android",
            ),
            (
                "x",
                "name = \"n\"\nurl = \"http://a.org/\"".into(),
                "kiosk_url_not_https",
                "url",
            ),
            (
                "x",
                format!("{NWEA}\nallow = [\"org\"]"),
                "kiosk_allow_invalid",
                "allow",
            ),
            (
                "x",
                "name = \"n\"\nexec = \"/opt/x\"".into(),
                "kiosk_exec_invalid",
                "exec",
            ),
            (
                "x",
                format!("{NWEA}\n{ext}"),
                "kiosk_extension_invalid",
                "extensions",
            ),
            (
                "x",
                format!("{NWEA}\nuser_agent = \"a\\nb\""),
                "kiosk_user_agent_invalid",
                "user_agent",
            ),
            (
                "x",
                "name = \"\"\nurl = \"https://a.org/\"".into(),
                "kiosk_name_invalid",
                "name",
            ),
            (
                "x",
                "name = \"Math, Grade 5\"\nurl = \"https://a.org/\"".into(),
                "kiosk_name_invalid",
                "name",
            ),
            (
                "x",
                format!("{NWEA}\nchrome_policy = {{ URLBlocklist = [] }}"),
                "kiosk_policy_locked",
                "chrome_policy",
            ),
        ] {
            let l = lint(&manifest("", &kiosk(id, &fields), "\"local\""), &present());
            let e: Vec<&Lint> = l.iter().filter(|l| l.level == LintLevel::Error).collect();
            assert_eq!(e.len(), 1, "{code}: {l:?}");
            assert_eq!(e[0].code, code, "{l:?}");
            assert_eq!(
                e[0].path.as_deref(),
                Some(format!("config.teacher.apps.kiosk.{id}.{field}").as_str())
            );
        }
        // 合规的不报任何东西。
        let l = lint(&manifest("", &kiosk("nwea", NWEA), "\"local\""), &present());
        assert!(l.is_empty(), "{l:?}");
    }

    #[test]
    fn lint_kiosk_too_many() {
        let many = |n: usize| -> String {
            (0..n)
                .map(|i| kiosk(&format!("a{i}"), NWEA))
                .collect::<String>()
        };
        let l = lint(&manifest("", &many(MAX), "\"local\""), &present());
        assert!(l.is_empty(), "{l:?}");
        let l = lint(&manifest("", &many(MAX + 1), "\"local\""), &present());
        assert_eq!(codes(&l), ["kiosk_too_many"], "{l:?}");
        assert_eq!(l[0].level, LintLevel::Error);
        assert_eq!(l[0].path.as_deref(), Some("config.teacher.apps.kiosk"));
    }
    const MAX: usize = crate::kiosk::MAX_KIOSK_APPS;

    #[test]
    fn lint_kiosk_no_entry() {
        let g = kiosk("nwea", &format!("{NWEA}\nlogin_screen = false"));
        let l = lint(&manifest("", &g, "\"local\""), &present());
        assert_eq!(codes(&l), ["kiosk_no_entry"], "{l:?}");
        assert_eq!(l[0].level, LintLevel::Warning);
        assert_eq!(l[0].path.as_deref(), Some("config.teacher.apps.kiosk.nwea"));
        // 两处都显示：没有提示。
        let g = kiosk("nwea", &format!("{NWEA}\nin_session = true"));
        assert!(lint(&manifest("", &g, "\"local\""), &present()).is_empty());
    }

    /// 终审 I2：只在桌面显示的应用没人进得去——从桌面进入回到登录界面，而那里没有它（自动登录还没做，设计 §9.4）。
    #[test]
    fn lint_kiosk_in_session_only() {
        let g = kiosk(
            "nwea",
            &format!("{NWEA}\nlogin_screen = false\nin_session = true"),
        );
        let l = lint(&manifest("", &g, "\"local\""), &present());
        assert_eq!(codes(&l), ["kiosk_in_session_only"], "{l:?}");
        assert_eq!(l[0].level, LintLevel::Error);
        assert_eq!(
            l[0].path.as_deref(),
            Some("config.teacher.apps.kiosk.nwea.login_screen")
        );
        assert!(l[0].message.contains("login_screen"), "{}", l[0].message);
    }

    #[test]
    fn lint_kiosk_flatpak_missing() {
        let g = kiosk("calc", "name = \"计算器\"\nexec = \"org.example.Calc\"");
        let l = lint(&manifest("", &g, "\"local\""), &present());
        assert_eq!(codes(&l), ["kiosk_flatpak_missing"], "{l:?}");
        assert_eq!(l[0].level, LintLevel::Warning);
        assert_eq!(
            l[0].path.as_deref(),
            Some("config.teacher.apps.kiosk.calc.exec")
        );
        // 列在本分组的 apps.flatpak 里：不报。
        let listed = format!("[group.apps]\nflatpak = [\"org.example.Calc\"]\n{g}");
        assert!(lint(&manifest("", &listed, "\"local\""), &present()).is_empty());
        // /usr 下的程序不是 Flatpak：不报。
        let g = kiosk(
            "calc",
            "name = \"计算器\"\nexec = \"/usr/bin/gnome-calculator\"",
        );
        assert!(lint(&manifest("", &g, "\"local\""), &present()).is_empty());
    }

    #[test]
    fn lint_kiosk_user_agent_is_info() {
        let g = kiosk(
            "nwea",
            &format!("{NWEA}\nuser_agent = \"Mozilla/5.0 (X11)\""),
        );
        let l = lint(&manifest("", &g, "\"local\""), &present());
        assert_eq!(codes(&l), ["kiosk_user_agent"], "{l:?}");
        assert_eq!(l[0].level, LintLevel::Info);
        assert_eq!(
            l[0].path.as_deref(),
            Some("config.teacher.apps.kiosk.nwea.user_agent")
        );
        assert!(l[0]
            .message
            .contains("secure-client detection is handled by the exam extension"));
        assert!(!has_errors(&l));
        // 本地程序写了 user_agent 已经是错误，不再另给提示（Task 1 复审）。
        let g = kiosk(
            "calc",
            "name = \"计算器\"\nexec = \"/usr/bin/gnome-calculator\"\nuser_agent = \"x\"",
        );
        let l = lint(&manifest("", &g, "\"local\""), &present());
        assert_eq!(codes(&l), ["kiosk_user_agent_invalid"], "{l:?}");
    }

    #[test]
    fn lint_kiosk_icon() {
        let with = |icon: &str| {
            let g = kiosk("nwea", &format!("{NWEA}\nicon = \"{icon}\""));
            lint(&manifest("", &g, "\"local\""), &present())
        };
        assert!(with("files/c.png").is_empty());
        assert!(with("https://x/a.png").is_empty());
        for bad in ["files/missing.png", "http://x/a.png", "../a.png"] {
            let l = with(bad);
            assert_eq!(codes(&l), ["icon_invalid"], "{bad}: {l:?}");
            assert_eq!(l[0].level, LintLevel::Error);
            assert_eq!(
                l[0].path.as_deref(),
                Some("config.teacher.apps.kiosk.nwea.icon")
            );
        }
    }

    /// A format 2 text: `body` follows the trust (`[defaults]`, `[school]`, configs, groups).
    fn manifest2(body: &str) -> Manifest {
        Manifest::parse(&format!(
            "format = 2\nversion = 1\n[[trust]]\nid = \"k\"\nalg = \"ed25519\"\npublic_key = \"AAAA\"\n{body}"
        ))
        .unwrap()
    }

    fn of_code<'a>(l: &'a [Lint], code: &str) -> Vec<&'a Lint> {
        l.iter().filter(|l| l.code == code).collect()
    }

    #[test]
    fn drop_unknown_is_warning_drop_conflict_is_error() {
        let m = manifest2(
            r#"
[defaults]
printers = [{ name = "Library", uri = "ipp://lib.school.ac.th/ipp/print" }]
[[config]]
id = "a"
name = "a"
drop.printers = ["Nope"]
apps.flatpak = ["org.gimp.GIMP"]
drop.apps.flatpak = ["org.gimp.GIMP"]
[[config]]
id = "b"
name = "b"
drop.printers = ["Library"]
"#,
        );
        let l = super::lint(&m, &present());
        let unknown = of_code(&l, "drop_unknown");
        assert_eq!(unknown.len(), 1, "{l:?}");
        assert_eq!(unknown[0].level, LintLevel::Warning);
        assert_eq!(unknown[0].params["name"], "Nope");
        assert_eq!(unknown[0].params["collection"], "printers");
        assert_eq!(unknown[0].params["config"], "a");
        assert_eq!(
            unknown[0].path.as_deref(),
            Some("config.a.drop.printers[0]")
        );
        let conflict = of_code(&l, "drop_conflict");
        assert_eq!(conflict.len(), 1, "{l:?}");
        assert_eq!(conflict[0].level, LintLevel::Error);
        assert_eq!(conflict[0].params["name"], "org.gimp.GIMP");
        assert_eq!(conflict[0].params["collection"], "apps.flatpak");
        // Config b drops a real inherited printer: nothing to say.
        assert!(
            l.iter()
                .all(|x| !x.code.starts_with("drop_") || x.params["config"] == "a"),
            "{l:?}"
        );
    }

    #[test]
    fn inherited_problem_reported_once_at_defaults() {
        let m = manifest2(
            r#"
[defaults]
apps.web = [{ name = "Intranet", url = "http://intranet" }]
wifi = [{ ssid = "x" }]
[[config]]
id = "a"
name = "a"
[[config]]
id = "b"
name = "b"
[[config]]
id = "c"
name = "c"
"#,
        );
        let l = super::lint(&m, &present());
        let http = of_code(&l, "web_app_not_https");
        assert_eq!(http.len(), 1, "{l:?}");
        assert!(http[0]
            .path
            .as_deref()
            .unwrap()
            .starts_with("defaults.apps.web[0]"));
        assert_eq!(http[0].params["layer"], "defaults");
        assert_eq!(of_code(&l, "wifi_open_implicit").len(), 1, "{l:?}");
        // A config's own bad entry is reported at the config.
        let m = manifest2(
            r#"
[[config]]
id = "a"
name = "a"
apps.web = [{ name = "Intranet", url = "http://intranet" }]
"#,
        );
        let l = super::lint(&m, &present());
        assert_eq!(
            of_code(&l, "web_app_not_https")[0].path.as_deref(),
            Some("config.a.apps.web[0].url")
        );
    }

    #[test]
    fn sso_semantics_use_effective_config() {
        let two = |second: &str| {
            manifest2(&format!(
                r#"
[defaults]
login_methods = ["sso"]
[[config]]
id = "a"
name = "a"
[[config]]
id = "b"
name = "b"
{second}
"#
            ))
        };
        let l = super::lint(&two(""), &present());
        let sso = of_code(&l, "sso_without_oidc");
        assert_eq!(sso.len(), 1, "{l:?}");
        assert_eq!(sso[0].path.as_deref(), Some("defaults.login_methods"));
        assert_eq!(sso[0].params["config"], "a, b");
        let l = super::lint(&two("login_methods = [\"guest\"]"), &present());
        let sso = of_code(&l, "sso_without_oidc");
        assert_eq!(sso.len(), 1, "{l:?}");
        assert_eq!(sso[0].params["config"], "a");
        // A config writing its own sso is reported at its own key.
        let m = manifest2(
            r#"
[[config]]
id = "a"
name = "a"
login_methods = ["sso"]
"#,
        );
        let l = super::lint(&m, &present());
        assert_eq!(
            of_code(&l, "sso_without_oidc")[0].path.as_deref(),
            Some("config.a.login_methods")
        );
    }

    #[test]
    fn kiosk_lints_see_defaults_flatpaks() {
        let m = manifest2(
            r#"
[defaults]
apps.flatpak = ["org.example.Calc"]
[[config]]
id = "a"
name = "a"
[config.apps.kiosk.calc]
name = "Calc"
exec = "org.example.Calc"
[[config]]
id = "b"
name = "b"
drop.apps.flatpak = ["org.example.Calc"]
[config.apps.kiosk.calc]
name = "Calc"
exec = "org.example.Calc"
"#,
        );
        let l = super::lint(&m, &present());
        let missing = of_code(&l, "kiosk_flatpak_missing");
        assert_eq!(missing.len(), 1, "{l:?}");
        assert_eq!(missing[0].params["config"], "b");
    }

    #[test]
    fn defaults_files_must_be_in_bundle() {
        let m = manifest2(
            r#"
[defaults]
files = [{ src = "files/x.png", dest = "/opt/x.png" }]
[[config]]
id = "a"
name = "a"
[[config]]
id = "b"
name = "b"
"#,
        );
        let l = m.validate_all(&present());
        let missing: Vec<_> = l.iter().filter(|l| l.code == "file_missing").collect();
        assert_eq!(missing.len(), 1, "{l:?}");
        assert_eq!(missing[0].path.as_deref(), Some("defaults.files[0].src"));
    }

    #[test]
    fn it_account_hash_format() {
        let one = |hash: &str, layer: &str| {
            let (d, c) = if layer == "defaults" {
                (
                    format!("[defaults]\nit_account = {{ password_hash = \"{hash}\" }}"),
                    String::new(),
                )
            } else {
                (
                    String::new(),
                    format!("it_account = {{ password_hash = \"{hash}\" }}"),
                )
            };
            super::lint(
                &manifest2(&format!("{d}\n[[config]]\nid = \"a\"\nname = \"a\"\n{c}\n")),
                &present(),
            )
        };
        for layer in ["defaults", "config"] {
            let l = one("$1$abc", layer);
            let bad = of_code(&l, "it_account_invalid");
            assert_eq!(bad.len(), 1, "{l:?}");
            assert_eq!(bad[0].level, LintLevel::Error);
            assert!(!bad[0].message.contains("$1$abc"));
            assert!(bad[0].params.values().all(|v| !v.contains("$1$abc")));
            let want = if layer == "defaults" {
                "defaults.it_account"
            } else {
                "config.a.it_account"
            };
            assert_eq!(bad[0].path.as_deref(), Some(want));
            assert_eq!(
                bad[0].params["layer"],
                if layer == "defaults" { "defaults" } else { "a" }
            );
            for ok in [
                "$y$j9T$abc.def/ghi$XYZ0123",
                "$6$rounds=500000$salt$HASH.x/1",
            ] {
                assert!(
                    of_code(&one(ok, layer), "it_account_invalid").is_empty(),
                    "{ok}"
                );
            }
        }
    }

    #[test]
    fn school_wifi_moved_warns() {
        let m = manifest2(
            r#"
[school]
wifi = [{ ssid = "S", open = true }]
[[config]]
id = "a"
name = "a"
"#,
        );
        let l = super::lint(&m, &present());
        let moved = of_code(&l, "school_wifi_moved");
        assert_eq!(moved.len(), 1, "{l:?}");
        assert_eq!(moved[0].level, LintLevel::Warning);
        assert_eq!(moved[0].path.as_deref(), Some("school.wifi"));
    }

    /// Review I2: in a format-1 text the server keeps Wi-Fi under `[school]` (moving it to
    /// `[defaults]` would need format 2, and it moves it back), so there is nothing to warn about.
    #[test]
    fn school_wifi_moved_silent_in_format_1() {
        let m = Manifest::parse(
            r#"
version = 1
[[trust]]
id = "k"
alg = "ed25519"
public_key = "AAAA"
[school]
wifi = [{ ssid = "S", open = true }]
[[config]]
id = "a"
name = "a"
"#,
        )
        .unwrap();
        assert_eq!(m.format, 1);
        let l = super::lint(&m, &present());
        assert!(of_code(&l, "school_wifi_moved").is_empty(), "{l:?}");
    }

    #[test]
    fn school_name_and_logo_format() {
        let m = manifest2(
            r#"
[school]
name = ""
logo_sha256 = "ABC"
[[config]]
id = "a"
name = "a"
"#,
        );
        let l = super::lint(&m, &present());
        assert_eq!(of_code(&l, "school_name_invalid").len(), 1, "{l:?}");
        assert_eq!(of_code(&l, "logo_sha256_invalid").len(), 1, "{l:?}");
        let m = manifest2(
            r#"
[school]
name = "Masters"
logo_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
logo_icon_sha256 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
[[config]]
id = "a"
name = "a"
"#,
        );
        let l = super::lint(&m, &present());
        assert!(of_code(&l, "school_name_invalid").is_empty());
        assert!(of_code(&l, "logo_sha256_invalid").is_empty());
        assert!(of_code(&l, "logo_incomplete").is_empty(), "{l:?}");
        // A malformed icon digest is reported at its own key.
        let m = manifest2(
            r#"
[school]
logo_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
logo_icon_sha256 = "XYZ"
[[config]]
id = "a"
name = "a"
"#,
        );
        let l = super::lint(&m, &present());
        let bad = of_code(&l, "logo_sha256_invalid");
        assert_eq!(bad.len(), 1, "{l:?}");
        assert_eq!(bad[0].path.as_deref(), Some("school.logo_icon_sha256"));
    }

    /// The two logo digests come together: one without the other is `logo_incomplete` (error),
    /// pointing at the missing key.
    #[test]
    fn logo_without_icon_is_incomplete() {
        let sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        for (have, missing) in [
            ("logo_sha256", "logo_icon_sha256"),
            ("logo_icon_sha256", "logo_sha256"),
        ] {
            let m = manifest2(&format!(
                "[school]\n{have} = \"{sha}\"\n[[config]]\nid = \"a\"\nname = \"a\"\n"
            ));
            let l = super::lint(&m, &present());
            let inc = of_code(&l, "logo_incomplete");
            assert_eq!(inc.len(), 1, "{l:?}");
            assert_eq!(inc[0].level, LintLevel::Error);
            assert_eq!(
                inc[0].path.as_deref(),
                Some(format!("school.{missing}").as_str())
            );
        }
    }

    #[test]
    fn format_unsupported_wording() {
        let l = format_unsupported(2, &gap(3));
        assert_eq!((l.level, l.code), (LintLevel::Error, "format_unsupported"));
        assert_eq!(l.params["found"], "2");
        assert_eq!(l.params["devices"], "3");
        assert!(l.message.contains("3 device(s)"));
        assert_eq!(l.path.as_deref(), Some("format"));
        let l = format_unsupported_in_use(2, &gap(1));
        assert_eq!(
            (l.level, l.code),
            (LintLevel::Warning, "format_unsupported_in_use")
        );
    }

    #[test]
    fn chrome_pause_inherited_is_reported_once() {
        let m = manifest2(
            r#"
[defaults]
chrome.pause_until = 2026-11-10
[[config]]
id = "a"
name = "a"
[[config]]
id = "b"
name = "b"
"#,
        );
        let l = super::lint_at(&m, &present(), on("2026-11-06"));
        let paused = of_code(&l, "chrome_paused");
        assert_eq!(paused.len(), 1, "{l:?}");
        assert_eq!(
            paused[0].path.as_deref(),
            Some("defaults.chrome.pause_until")
        );
    }
}
