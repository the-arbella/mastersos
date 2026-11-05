//! 设置包里的 `manifest.toml`：类型、解析与发布前的一致性检查（spec §5.3、§5.4）。
//!
//! Two shapes parse (config profiles design §3.1): the new one (`[[config]]` plus thin
//! `[[group]]`s naming a config) and the legacy one (`[[group]]`s carrying the settings), which
//! is expanded into one implied config per group. Downstream code only sees the new structure.

use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::{Lint, LintLevel};

/// 默认分组的 id：新机器、找不到自己分组的机器用它；清单里必须有且只有一个。
pub const DEFAULT_GROUP: &str = "default";
/// `apply` 脚本 `timeout_secs` 的上限：开机时先按本地的包应用、再去拉取，
/// 一个卡住的脚本最多把第一次拉取推迟这么久。
pub const MAX_SCRIPT_TIMEOUT_SECS: u64 = 30 * 60;
/// The newest settings syntax version (`format`) this code reads (phase B design §15.1). The
/// number goes up only when the meaning of what is written changes; added keys still go through
/// feature gates.
pub const MAX_FORMAT: u32 = 2;
/// The name of the IT maintenance account every managed Device gets with `it_account`.
pub const IT_ACCOUNT_USER: &str = "itadmin";

/// The feature string a Device reports to say it reads `format = n` (`format_<n>`).
pub fn format_feature(n: u32) -> String {
    format!("format_{n}")
}

fn format_one() -> u32 {
    1
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BundleError {
    #[error("Cannot parse the settings: {0}")]
    Parse(String),
    /// The text's `format` is newer than [`MAX_FORMAT`]: found before parsing the rest, so that
    /// keys this OS does not know yet are not reported as unknown.
    #[error(
        "these settings use format {found}, newer than this OS understands ({max}); update the OS first"
    )]
    FormatTooNew { found: u32, max: u32 },
    #[error("The settings are invalid: {0}")]
    Invalid(String),
    #[error("The bundle contains an unsafe path: {0}")]
    UnsafePath(String),
    #[error("The settings bundle exceeds the size limit")]
    TooLarge,
    #[error("The signature is incorrect")]
    BadSignature,
    #[error("The signing public key is not in the trust list: {0}")]
    UnknownKey(String),
    #[error(
        "The version is not newer than the current one (current {current}, received {offered})"
    )]
    NotNewer { current: u64, offered: u64 },
    #[error("Read or write failed: {0}")]
    Io(String),
    /// The bundle does not name the school of the machine's seed ([`check_school`]).
    #[error("bundle is for another school")]
    OtherSchool,
    /// Rules R7/R8 on the machine ([`crate::check_recovery_signed`]): the trust or escrow
    /// recipients change, and the signer is not a recovery-kit key of the current trust.
    #[error(
        "{} change not signed by a recovery kit: only an Ed25519 recovery key in the current trust \
         can change trust or escrow recipients",
        .0.as_str()
    )]
    KitRequired(crate::KitChange),
}

/// A MastersOS settings file (`manifest.toml`): the school's settings, its Configs (what a Device
/// looks like), its Groups (which Devices, using which Config) and which Device belongs to which
/// Group. One signed file per school; each Device applies the Config of its own Group.
///
/// Parse it with [`Manifest::parse`] (or the check functions): deserializing it directly reads
/// only the new shape.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// The settings syntax version: absent is 1. The server writes the lowest one the text needs
    /// (2 once `[defaults]`, `drop`, `it_account` or `[school] name`/`logo_sha256`/
    /// `logo_icon_sha256` are used);
    /// leave it as the server wrote it.
    #[serde(default = "format_one")]
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 2)))]
    pub format: u32,
    /// The Version number, increasing with every Publish. The server writes it on Publish; leave
    /// it out of a Draft.
    pub version: u64,
    /// When the Version was published (RFC 3339 text). The server writes it on Publish; leave it
    /// out of a Draft.
    #[serde(default)]
    pub issued_at: Option<String>,
    /// The signing keys Devices trust: a Version is accepted only when signed by one of them.
    /// Written from the Keys page; at least one key is required.
    #[serde(default)]
    pub trust: Vec<TrustKey>,
    /// Settings shared by the whole school.
    #[serde(default)]
    pub school: School,
    /// What every Config starts from: the same keys as a `[[config]]` without `id` and `name`.
    /// A Config's written single value replaces the Defaults' one; its collection entries are
    /// added, replacing a Defaults entry of the same name (`format = 2`).
    #[serde(default)]
    pub defaults: Option<Defaults>,
    /// The Configs as written: what a Device looks like (mode, sign-in, Wi-Fi, apps, Chrome…),
    /// on top of `[defaults]` ([`effective_config`]). Groups name them; several Groups can share
    /// one.
    #[serde(default, rename = "config")]
    pub configs: Vec<ConfigLayer>,
    /// The Groups: each is a set of Devices and the Config they use. Exactly one has id `default`.
    #[serde(default, rename = "group")]
    pub groups: Vec<Group>,
    /// Device to Group assignments, Lock and the legacy reset request.
    #[serde(default, rename = "device")]
    pub devices: Vec<DeviceEntry>,
    /// Which shape the text was written in; not part of the text.
    #[serde(skip)]
    pub shape: Shape,
}

/// The shape a settings text was written in (config profiles design §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Shape {
    /// `[[config]]` tables plus `[[group]]`s with only `id`, `name` and `config`.
    #[default]
    New,
    /// `[[group]]`s carrying the settings themselves (before config profiles). Parsed into one
    /// implied Config per Group with the Group's id.
    Legacy,
}

/// Why a text did not parse into a [`Manifest`]: TOML or serde, or a mix of the two shapes.
#[derive(Debug)]
pub(crate) enum ShapeError {
    Toml(toml::de::Error),
    /// The text has `[[config]]` (or a `[[group]]` naming a config), yet `[[group]]` number
    /// `index` (0-based) carries settings keys.
    Mixed {
        index: usize,
        group: String,
    },
    /// `format` is not 1 or 2, or a format 1 text writes a key that needs format 2.
    Format(String),
    /// `format` is newer than [`MAX_FORMAT`].
    TooNew {
        found: u32,
    },
}

impl ShapeError {
    /// English, one sentence; never echoes a value from the text other than the group id.
    pub(crate) fn message(&self) -> String {
        match self {
            ShapeError::Toml(e) => e.to_string(),
            ShapeError::Mixed { group, .. } => format!(
                "Group {group:?} carries settings, but this file uses [[config]]: move its \
                 settings into a [[config]] and keep only id, name and config in the [[group]]."
            ),
            ShapeError::Format(m) => m.clone(),
            ShapeError::TooNew { found } => BundleError::FormatTooNew {
                found: *found,
                max: MAX_FORMAT,
            }
            .to_string(),
        }
    }

    /// As a [`BundleError`]: [`BundleError::FormatTooNew`] for a newer format, else a parse error.
    pub(crate) fn into_bundle_error(self) -> BundleError {
        match self {
            ShapeError::TooNew { found } => BundleError::FormatTooNew {
                found,
                max: MAX_FORMAT,
            },
            other => BundleError::Parse(other.message()),
        }
    }
}

/// Keys that make a `[[group]]` carry settings: the legacy `mode` and every [`Config`] field
/// other than `id` and `name`. Any other unknown key is left to deserializing, which reports it
/// as an unknown field (a typo such as `nmae` is not a shape mix).
const SETTINGS_KEYS: [&str; 15] = [
    "mode",
    "it_account",
    "drop",
    "interface",
    "login_methods",
    "local_users_admin",
    "wifi",
    "apps",
    "printers",
    "scanners",
    "chrome_policy",
    "chrome",
    "files",
    "downloads",
    "scripts",
];

/// Which shape the parsed text `doc` is written in. The new shape has a root `config` or
/// `defaults` key or `[[group]]`s naming a config; the legacy shape has none of these but has
/// `[[group]]`s. A text with neither groups nor configs is new.
fn detect_shape(doc: &toml::Table) -> Result<Shape, ShapeError> {
    let groups: Vec<&toml::Table> = doc
        .get("group")
        .and_then(toml::Value::as_array)
        .map(|a| a.iter().filter_map(toml::Value::as_table).collect())
        .unwrap_or_default();
    let names_config = groups.iter().any(|g| g.contains_key("config"));
    if doc.contains_key("config") || doc.contains_key("defaults") || names_config {
        let fat = groups
            .iter()
            .position(|g| g.keys().any(|k| SETTINGS_KEYS.contains(&k.as_str())));
        if let Some(index) = fat {
            let group = groups[index]
                .get("id")
                .and_then(toml::Value::as_str)
                .unwrap_or_default()
                .to_string();
            return Err(ShapeError::Mixed { index, group });
        }
        return Ok(Shape::New);
    }
    Ok(if groups.is_empty() {
        Shape::New
    } else {
        Shape::Legacy
    })
}

/// The text's `format` (absent: 1), read before anything else is deserialized: a newer one is
/// [`ShapeError::TooNew`] whatever else the text holds. Then a format 1 text must not write a key
/// that needs format 2.
fn check_format(doc: &toml::Table) -> Result<u32, ShapeError> {
    let format =
        match doc.get("format") {
            None => 1,
            Some(toml::Value::Integer(n)) if *n > i64::from(MAX_FORMAT) => {
                return Err(ShapeError::TooNew {
                    found: u32::try_from(*n).unwrap_or(u32::MAX),
                })
            }
            Some(toml::Value::Integer(n)) if *n >= 1 => *n as u32,
            Some(_) => return Err(ShapeError::Format(
                "format must be the integer 1 or 2 (format = 2); leave it as the server wrote it"
                    .into(),
            )),
        };
    if format >= 2 {
        return Ok(format);
    }
    let used = format2_key(doc);
    match used {
        Some(key) => Err(ShapeError::Format(format!(
            "{key} needs format = 2: write format = 2 as the first line (the server does this \
             when it saves the draft)"
        ))),
        None => Ok(format),
    }
}

/// Whether the text writes a key that needs `format = 2` (phase B §15): `[defaults]`, a Config's
/// `drop` or `it_account`, `[school] name`, `logo_sha256` or `logo_icon_sha256`. The server writes
/// `format = 2` exactly
/// when this holds; a format 1 text that writes one of them does not parse.
pub fn needs_format2(doc: &toml::Table) -> bool {
    format2_key(doc).is_some()
}

/// The first key of `doc` that needs `format = 2`, as error messages name it.
/// The key that makes a text without `format` need `format = 2` (`[defaults]`, `drop`, ...), when the
/// text leaves `format` out and writes one; `None` otherwise, or when it is not TOML. A save writes
/// `format = 2` for it, so a live check can say so instead of reporting the missing line as an error.
pub fn format2_key_unwritten(text: &str) -> Option<&'static str> {
    let doc = text.parse::<toml::Table>().ok()?;
    if doc.contains_key("format") {
        return None;
    }
    format2_key(&doc)
}

fn format2_key(doc: &toml::Table) -> Option<&'static str> {
    let school = doc.get("school").and_then(toml::Value::as_table);
    let configs = || {
        doc.get("config")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_table)
    };
    if doc.contains_key("defaults") {
        Some("[defaults]")
    } else if configs().any(|c| c.contains_key("drop")) {
        Some("drop")
    } else if configs().any(|c| c.contains_key("it_account")) {
        Some("it_account")
    } else if school.is_some_and(|s| s.contains_key("name")) {
        Some("[school] name")
    } else if school.is_some_and(|s| s.contains_key("logo_sha256")) {
        Some("[school] logo_sha256")
    } else if school.is_some_and(|s| s.contains_key("logo_icon_sha256")) {
        Some("[school] logo_icon_sha256")
    } else {
        None
    }
}

/// Parse either shape; the legacy one is expanded ([`LegacyManifest::expand`]). Not TOML: parsed
/// as the new shape, so that deserializing reports the error.
pub(crate) fn parse_shapes(text: &str) -> Result<Manifest, ShapeError> {
    let shape = match text.parse::<toml::Table>() {
        Ok(doc) => {
            check_format(&doc)?;
            detect_shape(&doc)?
        }
        Err(_) => Shape::New,
    };
    match shape {
        Shape::New => toml::from_str::<Manifest>(text).map_err(ShapeError::Toml),
        Shape::Legacy => toml::from_str::<LegacyManifest>(text)
            .map(LegacyManifest::expand)
            .map_err(ShapeError::Toml),
    }
}

/// The legacy settings file: `[[group]]`s carry the settings. Only parsed, then expanded.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyManifest {
    #[serde(default = "format_one")]
    format: u32,
    version: u64,
    #[serde(default)]
    issued_at: Option<String>,
    #[serde(default)]
    trust: Vec<TrustKey>,
    #[serde(default)]
    school: School,
    #[serde(default, rename = "group")]
    groups: Vec<LegacyGroup>,
    #[serde(default, rename = "device")]
    devices: Vec<DeviceEntry>,
}

/// A legacy `[[group]]`: today's [`Config`] fields with `mode` instead of `interface`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyGroup {
    id: String,
    name: String,
    #[serde(default)]
    login_methods: Vec<LoginMethod>,
    #[serde(default)]
    local_users_admin: bool,
    #[serde(default)]
    mode: LegacyMode,
    #[serde(default)]
    wifi: Vec<Wifi>,
    #[serde(default)]
    apps: Apps,
    #[serde(default)]
    printers: Vec<NetDevice>,
    #[serde(default)]
    scanners: Vec<NetDevice>,
    #[serde(default)]
    chrome_policy: toml::Table,
    #[serde(default)]
    chrome: ChromeUpdate,
    #[serde(default)]
    files: Vec<FileEntry>,
    #[serde(default)]
    downloads: Vec<Download>,
    #[serde(default)]
    scripts: Vec<Script>,
}

/// The legacy `mode` key: `browser` (the default) or `desktop`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum LegacyMode {
    Desktop,
    #[default]
    Browser,
}

impl LegacyManifest {
    /// One Config per Group, with the Group's id and name; the Group names it. `desktop` is
    /// `full`; `browser` is `learning` marked [`ConfigLayer::legacy_browser`]. Every single value
    /// is written (`Some`): a legacy Group meant exactly these values.
    fn expand(self) -> Manifest {
        let mut configs = Vec::with_capacity(self.groups.len());
        let mut groups = Vec::with_capacity(self.groups.len());
        for g in self.groups {
            groups.push(Group {
                id: g.id.clone(),
                name: g.name.clone(),
                config: g.id.clone(),
            });
            let browser = g.mode == LegacyMode::Browser;
            configs.push(ConfigLayer {
                id: g.id,
                name: g.name,
                interface: Some(if browser {
                    Interface::Learning
                } else {
                    Interface::Full
                }),
                login_methods: Some(g.login_methods),
                local_users_admin: Some(g.local_users_admin),
                it_account: None,
                wifi: g.wifi,
                apps: g.apps,
                printers: g.printers,
                scanners: g.scanners,
                chrome_policy: g.chrome_policy,
                chrome: g.chrome,
                files: g.files,
                downloads: g.downloads,
                scripts: g.scripts,
                drop: Drop::default(),
                legacy_browser: browser,
            });
        }
        Manifest {
            format: self.format,
            version: self.version,
            issued_at: self.issued_at,
            trust: self.trust,
            school: self.school,
            defaults: None,
            configs,
            groups,
            devices: self.devices,
            shape: Shape::Legacy,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
/// One trusted signing key: a Recovery kit key (`ed25519`) or a Passkey (`webauthn-es256`).
pub struct TrustKey {
    /// The key's name, unique within trust; signatures name the key by it.
    pub id: String,
    /// The key type.
    pub alg: KeyAlg,
    /// Standard base64. `ed25519`: 32 bytes when decoded; `webauthn-es256`: 65 bytes, the
    /// uncompressed P-256 point (`0x04 || x || y`).
    pub public_key: String,
    /// Only for `webauthn-es256`: the RP ID the Passkey was registered for (its
    /// host name), a lowercase ASCII host name without scheme, port or path. Signature checks
    /// compare the assertion's `rpIdHash` and `origin` with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum KeyAlg {
    /// A Recovery kit key (Ed25519).
    #[serde(rename = "ed25519")]
    Ed25519,
    /// A Passkey: WebAuthn assertion, ECDSA P-256 with SHA-256 (COSE -7).
    #[serde(rename = "webauthn-es256")]
    WebauthnEs256,
}

impl KeyAlg {
    /// 清单与签名文件里的写法。
    pub fn as_str(self) -> &'static str {
        match self {
            KeyAlg::Ed25519 => "ed25519",
            KeyAlg::WebauthnEs256 => "webauthn-es256",
        }
    }
}

/// `[school]`: settings shared by every Group.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct School {
    /// The school's immutable id (`school_id`, lowercase hyphenated UUID text), plan 6 Task 10b.
    /// Every school signs with the same signing origin (one WebAuthn rp_id), so one IT passkey can
    /// be in two schools' trust; this id binds the signed bundle to its school. A Device whose
    /// seed names a school accepts only bundles naming the same one ([`check_school`]). The cloud
    /// server writes it into every Draft and refuses to publish without it.
    #[serde(default, deserialize_with = "school_id_opt")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
            description = "The school's id, a lowercase UUID. The server writes it into every \
                           Draft; a Device accepts only settings naming its own school. Never \
                           change it."
        )
    )]
    pub id: Option<String>,
    /// The school's single sign-on (OpenID Connect) provider, used only to sign in on Devices.
    #[serde(default)]
    pub oidc: Option<Oidc>,
    /// SSO accounts may sign in only when the part after the last `@` is one of these domains
    /// (lowercase); empty: any account the provider accepts.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// SSO accounts (`name@domain`) that are administrators on every Device, whatever their
    /// Group, Lock or login methods. At most 200.
    #[serde(default)]
    pub admin_users: Vec<String>,
    /// The OS update channel: `stable` or `beta`.
    #[serde(default = "default_channel")]
    pub update_channel: String,
    /// School cache address (`http://` / `https://` plus a directory, same layout as `os.khundavid.com`).
    /// Devices try it first and fall back to the official source when it is unreachable. Updates are
    /// signed, so the cache is not trusted.
    #[serde(default)]
    pub update_mirror: Option<String>,
    /// The Devices' time zone, an IANA name such as `Asia/Bangkok`; absent: Devices keep theirs.
    #[serde(default)]
    pub timezone: Option<String>,
    /// The Devices' language, such as `th_TH.UTF-8`; only languages built into the image work.
    /// Absent: Devices keep theirs.
    #[serde(default)]
    pub locale: Option<String>,
    /// The age X25519 recipients (`age1…`) a Device seals its disk recovery key to before
    /// escrowing it (rulings 10, 27); empty: no escrow. Format rules in
    /// [`checks::escrow_recipients`](crate::checks::escrow_recipients). Written, it is never
    /// empty: `escrow_recipients = []` would mean the same as leaving the key out, yet Devices
    /// whose agent predates the key reject it, and [`features_used`] could not tell.
    #[serde(default, deserialize_with = "non_empty_list")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            length(min = 1, max = 8),
            description = "1 to 8 age X25519 public keys (`age1…`, canonical lowercase, none \
                           twice) that Devices encrypt their disk recovery key to before sending \
                           it to the cloud. Written by `mastersos init` and `mastersos keys add`. Leave the key out rather \
                           than writing an empty list."
        )
    )]
    pub escrow_recipients: Vec<String>,
    /// Moved to `[defaults] wifi`; still accepted for good (published Versions carry it). Its
    /// networks come before the Defaults' ones, a Defaults entry of the same SSID replacing the
    /// school's ([`effective_config`]). Written, it is never empty (like `escrow_recipients`):
    /// `wifi = []` adds nothing, yet Devices whose agent predates school Wi-Fi reject the key,
    /// and [`features_used`] could not tell.
    #[serde(default, deserialize_with = "non_empty_list")]
    pub wifi: Vec<Wifi>,
    /// The school's display name, shown on Devices ("Managed by …"). The server writes it on
    /// Publish; do not write it by hand (`format = 2`).
    #[serde(default)]
    pub name: Option<String>,
    /// The SHA-256 (64 lowercase hex digits) of the sign-in screen logo, a PNG 96 pixels high
    /// and at most 480 wide, which Devices download from `<server>/logos/<sha256>.png`; a logo
    /// that does not match is not shown. The server writes it, with `logo_icon_sha256`, when IT
    /// uploads a logo; do not write it by hand (`format = 2`).
    #[serde(default)]
    pub logo_sha256: Option<String>,
    /// The SHA-256 (64 lowercase hex digits) of the quick menu icon, a PNG of 40 x 40 pixels,
    /// downloaded like `logo_sha256`. Written by the server together with `logo_sha256`; one
    /// without the other is `logo_incomplete` (`format = 2`).
    #[serde(default)]
    pub logo_icon_sha256: Option<String>,
}

fn default_channel() -> String {
    "stable".into()
}

impl Default for School {
    fn default() -> Self {
        School {
            id: None,
            oidc: None,
            allowed_domains: Vec::new(),
            admin_users: Vec::new(),
            update_channel: default_channel(),
            update_mirror: None,
            timezone: None,
            locale: None,
            escrow_recipients: Vec::new(),
            wifi: Vec::new(),
            name: None,
            logo_sha256: None,
            logo_icon_sha256: None,
        }
    }
}

/// `[school.oidc]`: the OpenID Connect provider Devices sign in with (authorization code on the
/// login screen). `client_secret` and `card_hosts` are [`FEATURE_OIDC_CARD`].
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Oidc {
    /// The provider's issuer URL (`https://…`). Not Google: Devices do not sign in with Google
    /// accounts.
    pub issuer: String,
    /// The client id registered with the provider for MastersOS Devices.
    pub client_id: String,
    /// The client secret, only for a provider that requires one even for a desktop app. Every
    /// Device holds it, so it is not a secret in any real sense.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// Hostnames the sign-in page may load from besides the issuer: the provider's other hosts,
    /// its CDN, the school's upstream provider. Each is an exact `https` host; subdomains are not
    /// included. At most 20.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub card_hosts: Vec<String>,
}

/// What a Device using a Config gets: the Config as written laid over `[defaults]`
/// ([`effective_config`]). Every agent step reads this, never a [`ConfigLayer`]. Not a settings
/// table itself: the settings file writes [`Defaults`] and [`ConfigLayer`]s.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The Config's id, unique among Configs; `[[group]]` entries name it.
    pub id: String,
    /// The name shown in the console.
    pub name: String,
    /// The mode: `learning` (like a ChromeOS student laptop) or `full` (the full desktop).
    #[serde(default)]
    pub interface: Interface,
    /// Who can sign in on the Devices: any of `guest`, `local`, `sso`. Guest is always allowed
    /// (except on a locked Device), whether or not `guest` is listed; `local` and `sso` are
    /// opt-in. Administrators sign in with `sso`, so they need it too.
    #[serde(default)]
    pub login_methods: Vec<LoginMethod>,
    /// Whether local (non-SSO) accounts on the Devices are administrators.
    #[serde(default)]
    pub local_users_admin: bool,
    /// The IT maintenance account ([`IT_ACCOUNT_USER`]); `None`: no such account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub it_account: Option<ItAccount>,
    /// Wi-Fi networks the Devices join, available from the login screen: the school's, the
    /// Defaults' and the Config's, merged by SSID.
    #[serde(default)]
    pub wifi: Vec<Wifi>,
    /// Web apps, Flatpak apps and kiosk apps.
    #[serde(default)]
    pub apps: Apps,
    /// Network printers (IPP Everywhere, no driver needed).
    #[serde(default)]
    pub printers: Vec<NetDevice>,
    /// Network scanners (eSCL).
    #[serde(default)]
    pub scanners: Vec<NetDevice>,
    /// Chrome managed policies, passed to Chrome as written (Chrome's policy names and values).
    #[serde(default)]
    pub chrome_policy: toml::Table,
    /// When Chrome may change version: an update window and a pause. Absent: no limit.
    #[serde(default, skip_serializing_if = "ChromeUpdate::is_empty")]
    pub chrome: ChromeUpdate,
    /// Files from the bundle placed at absolute paths on the Devices.
    #[serde(default)]
    pub files: Vec<FileEntry>,
    /// Files downloaded by URL and checked against their SHA-256 before being placed.
    #[serde(default)]
    pub downloads: Vec<Download>,
    /// Scripts from the bundle, run as root when settings are applied or as the user at sign-in.
    #[serde(default)]
    pub scripts: Vec<Script>,
    /// Set only on the Config implied by a legacy `mode = "browser"` Group (§3.1): the agent
    /// reproduces the old browser mode byte for byte (no Flatpak installed, none in the Dock).
    /// Never written in any text.
    #[serde(skip)]
    pub legacy_browser: bool,
}

/// `[defaults]`: what every Config starts from (`format = 2`). The same keys as `[[config]]`
/// without `id`, `name` and `drop`. A Config's written single value (`interface`,
/// `login_methods`, `local_users_admin`, `it_account`, `chrome.update_window`,
/// `chrome.pause_until`) replaces the one here; its collection entries (`wifi`, `apps`,
/// `printers`, `scanners`, `chrome_policy`, `files`, `downloads`, `scripts`) are added, an entry
/// with the same name replacing the one here as a whole.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    /// The mode every Config has unless it writes its own: `learning` or `full`. Absent:
    /// `learning`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<Interface>,
    /// Who can sign in, unless a Config writes its own list: any of `guest`, `local`, `sso`.
    /// Absent: none besides guest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_methods: Option<Vec<LoginMethod>>,
    /// Whether local accounts are administrators, unless a Config writes its own. Absent: false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_users_admin: Option<bool>,
    /// The IT maintenance account (`itadmin`) on every Device, unless a Config writes its own.
    /// Set its password on the console; absent: no such account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub it_account: Option<ItAccount>,
    /// Wi-Fi networks every Config gets, after the school's legacy `[[school.wifi]]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wifi: Vec<Wifi>,
    /// Web apps, Flatpak apps and kiosk apps every Config gets.
    #[serde(default, skip_serializing_if = "Apps::is_empty")]
    pub apps: Apps,
    /// Network printers every Config gets.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub printers: Vec<NetDevice>,
    /// Network scanners every Config gets.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scanners: Vec<NetDevice>,
    /// Chrome managed policies every Config gets, by policy name.
    #[serde(default, skip_serializing_if = "toml::Table::is_empty")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "serde_json::Map<String, serde_json::Value>")
    )]
    pub chrome_policy: toml::Table,
    /// When Chrome may change version, unless a Config writes its own window or pause.
    #[serde(default, skip_serializing_if = "ChromeUpdate::is_empty")]
    pub chrome: ChromeUpdate,
    /// Files from the bundle every Config places.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<FileEntry>,
    /// Downloaded files every Config places.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub downloads: Vec<Download>,
    /// Scripts every Config runs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scripts: Vec<Script>,
}

/// `[[config]]` as written: what a Device looks like, whoever signs in, on top of `[defaults]`.
/// Groups name it by `id`. A single value left out is inherited from `[defaults]` (`None` here);
/// [`effective_config`] gives what Devices get.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ConfigLayer {
    /// The Config's id, unique among Configs; `[[group]]` entries name it.
    pub id: String,
    /// The name shown in the console.
    pub name: String,
    /// The mode: `learning` (like a ChromeOS student laptop) or `full` (the full desktop).
    /// Absent: the Defaults' mode, else `learning`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<Interface>,
    /// Who can sign in on the Devices: any of `guest`, `local`, `sso`. Guest is always allowed
    /// (except on a locked Device), whether or not `guest` is listed; `local` and `sso` are
    /// opt-in. Administrators sign in with `sso`, so they need it too. Absent: the Defaults'
    /// list, else none besides guest; written (even `[]`), it replaces the Defaults' list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_methods: Option<Vec<LoginMethod>>,
    /// Whether local (non-SSO) accounts on the Devices are administrators. Absent: the
    /// Defaults' value, else false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_users_admin: Option<bool>,
    /// This Config's own IT maintenance account password hash, replacing the Defaults' one
    /// (`format = 2`). Absent: the Defaults' account, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub it_account: Option<ItAccount>,
    /// Wi-Fi networks the Devices join, available from the login screen: added after the
    /// Defaults' (and the school's); an entry with the same SSID replaces the inherited one.
    #[serde(default)]
    pub wifi: Vec<Wifi>,
    /// Web apps, Flatpak apps and kiosk apps, added to the Defaults' ones.
    #[serde(default)]
    pub apps: Apps,
    /// Network printers (IPP Everywhere, no driver needed).
    #[serde(default)]
    pub printers: Vec<NetDevice>,
    /// Network scanners (eSCL).
    #[serde(default)]
    pub scanners: Vec<NetDevice>,
    /// Chrome managed policies, passed to Chrome as written (Chrome's policy names and values).
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "serde_json::Map<String, serde_json::Value>")
    )]
    pub chrome_policy: toml::Table,
    /// When Chrome may change version: an update window and a pause. Absent: no limit.
    #[serde(default, skip_serializing_if = "ChromeUpdate::is_empty")]
    pub chrome: ChromeUpdate,
    /// Files from the bundle placed at absolute paths on the Devices.
    #[serde(default)]
    pub files: Vec<FileEntry>,
    /// Files downloaded by URL and checked against their SHA-256 before being placed.
    #[serde(default)]
    pub downloads: Vec<Download>,
    /// Scripts from the bundle, run as root when settings are applied or as the user at sign-in.
    #[serde(default)]
    pub scripts: Vec<Script>,
    /// Entries inherited from `[defaults]` this Config does not want, by name (`format = 2`).
    #[serde(default, skip_serializing_if = "Drop::is_empty")]
    pub drop: Drop,
    /// Set only on the Config implied by a legacy `mode = "browser"` Group (§3.1): the agent
    /// reproduces the old browser mode byte for byte (no Flatpak installed, none in the Dock).
    /// Never written in any text.
    #[serde(skip)]
    pub legacy_browser: bool,
}

/// `[config.drop]`: inherited entries a Config leaves out, each list naming entries by the name
/// that makes them "the same entry": `wifi` by SSID, `printers`/`scanners`/`apps.web` by `name`,
/// `apps.flatpak` by app id, `apps.kiosk` by key, `files`/`downloads` by `dest`, `scripts` by
/// `path`, `chrome_policy` by policy name. Written as `drop.printers = ["Library"]`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Drop {
    /// SSIDs of inherited networks to leave out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wifi: Vec<String>,
    /// Inherited apps to leave out.
    #[serde(default, skip_serializing_if = "DropApps::is_empty")]
    pub apps: DropApps,
    /// Names of inherited printers to leave out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub printers: Vec<String>,
    /// Names of inherited scanners to leave out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scanners: Vec<String>,
    /// `dest` paths of inherited files to leave out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
    /// `dest` paths of inherited downloads to leave out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub downloads: Vec<String>,
    /// `path`s of inherited scripts to leave out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scripts: Vec<String>,
    /// Names of inherited Chrome policies to leave out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chrome_policy: Vec<String>,
}

impl Drop {
    pub fn is_empty(&self) -> bool {
        self.wifi.is_empty()
            && self.apps.is_empty()
            && self.printers.is_empty()
            && self.scanners.is_empty()
            && self.files.is_empty()
            && self.downloads.is_empty()
            && self.scripts.is_empty()
            && self.chrome_policy.is_empty()
    }
}

/// `[config.drop.apps]`: inherited apps a Config leaves out.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct DropApps {
    /// Names of inherited web apps to leave out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub web: Vec<String>,
    /// Inherited Flatpak app ids to leave out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flatpak: Vec<String>,
    /// Keys (app ids) of inherited kiosk apps to leave out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kiosk: Vec<String>,
}

impl DropApps {
    pub fn is_empty(&self) -> bool {
        self.web.is_empty() && self.flatpak.is_empty() && self.kiosk.is_empty()
    }
}

/// `it_account`: the IT maintenance account [`IT_ACCOUNT_USER`] (phase B design §10.4). The
/// console turns the password IT types into the hash; nobody writes it by hand.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ItAccount {
    /// The password as a crypt(3) hash (`$y$…` yescrypt, or `$6$rounds=500000$…`). Written by the
    /// console; a secret: never shown to AI tokens.
    pub password_hash: String,
}

impl ItAccount {
    /// The fields whose values are secrets: kept out of reports, logs and AI tokens' view.
    pub const SECRET_FIELDS: [&'static str; 1] = ["password_hash"];
}

/// The hash stays out of debug output, so that no log line carries it.
impl std::fmt::Debug for ItAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ItAccount")
            .field("password_hash", &"<redacted>")
            .finish()
    }
}

/// Entries of `inherited` whose name is neither among `own`'s nor in `drop`, in order, then
/// `own`'s, in order: an own entry replaces the inherited one of the same name as a whole.
fn merge_list<T: Clone>(
    inherited: &[T],
    own: &[T],
    drop: &[String],
    name: fn(&T) -> &str,
) -> Vec<T> {
    inherited
        .iter()
        .filter(|i| {
            let n = name(i);
            !own.iter().any(|o| name(o) == n) && !drop.iter().any(|d| d == n)
        })
        .chain(own)
        .cloned()
        .collect()
}

/// [`merge_list`] for tables keyed by name (`apps.kiosk`, `chrome_policy`): an own entry replaces
/// the inherited one of the same key.
fn merge_map<V: Clone, M>(inherited: &M, own: &M, drop: &[String]) -> M
where
    for<'a> &'a M: IntoIterator<Item = (&'a String, &'a V)>,
    M: FromIterator<(String, V)> + Extend<(String, V)>,
{
    let mut out: M = inherited
        .into_iter()
        .filter(|(k, _)| !drop.contains(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    out.extend(own.into_iter().map(|(k, v)| (k.clone(), v.clone())));
    out
}

/// `[[group]]`: a set of Devices and the Config they use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Group {
    /// The Group's id, unique; `[[device]]` entries name it. One Group must be `default`.
    pub id: String,
    /// The name shown in the console.
    pub name: String,
    /// The id of the `[[config]]` the Group's Devices use.
    pub config: String,
}

/// `[config.chrome]`: only delays, never downgrades; the first install is not limited (no browser
/// is much worse than an update during class). Format rules are in `checks::chrome_window` /
/// `checks::chrome_pause` (shared by lint and agent), not checked here.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "schema",
    schemars(
        description = "`[config.chrome]`: when Chrome may change version. Only delays updates, never downgrades; a Device without Chrome always installs it."
    )
)]
#[serde(deny_unknown_fields)]
pub struct ChromeUpdate {
    /// `HH:MM-HH:MM`, Device local time, may cross midnight, at least 2 hours: Chrome changes
    /// version only inside this window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_window: Option<String>,
    /// `YYYY-MM-DD`: no Chrome version change until this day (inclusive), at most 14 days after
    /// the Publish day. A quoted string or a bare TOML date.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "date_or_string"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<String>", extend("format" = "date"))
    )]
    pub pause_until: Option<String>,
}

impl ChromeUpdate {
    pub fn is_empty(&self) -> bool {
        self.update_window.is_none() && self.pause_until.is_none()
    }
}

/// A string is taken as is; a TOML datetime (`pause_until = 2026-11-20`) becomes its text (`2026-11-20`); checks judge the format.
fn date_or_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum V {
        S(String),
        D(toml::value::Datetime),
    }
    let v = V::deserialize(d).map_err(|_| {
        serde::de::Error::custom("pause_until must be a date, for example \"2026-11-20\"")
    })?;
    Ok(Some(match v {
        V::S(s) => s,
        V::D(t) => t.to_string(),
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
/// A way to sign in on a Device.
pub enum LoginMethod {
    /// A temporary guest session; its home folder is wiped at sign-out.
    Guest,
    /// Local accounts on the Device.
    Local,
    /// School accounts through `[school.oidc]`.
    Sso,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
/// The mode: what a session on the Device offers. A `create` mode (a sandboxed Linux
/// environment) is planned and not accepted yet.
pub enum Interface {
    /// Like a ChromeOS student laptop: Chrome, the web apps, kiosk app entries and the Config's
    /// Flatpak apps; no terminal, file manager or system settings.
    #[default]
    Learning,
    /// The full desktop: files, terminal, settings, Flatpak apps, printing and scanning.
    Full,
}

/// A Wi-Fi network written as a system connection: available to everyone, from the login screen.
/// The same shape in `[[school.wifi]]` and `[[config.wifi]]`. Its kind follows from its fields
/// ([`Wifi::kind`]): `eap` makes it enterprise (802.1X), `psk` personal, otherwise open. Format
/// and combination rules are in [`checks::wifi`](crate::checks::wifi).
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Wifi {
    /// The network name, exactly as broadcast: 1-32 bytes, unique in its list.
    pub ssid: String,
    /// Whether the network does not broadcast its name.
    #[serde(default, skip_serializing_if = "is_false")]
    pub hidden: bool,
    /// An open network (no password): only `true` is allowed, and not together with `psk` or
    /// `eap`. Write it for open networks: an entry with no `open`, `psk` or `eap` is still read as
    /// open but is warned about (it is usually a forgotten password).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open: Option<bool>,
    /// The WPA personal password: 8-63 printable ASCII characters or 64 hex digits. Makes the
    /// network WPA personal (WPA2, and WPA3 transition mode). A secret: never shown to AI tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psk: Option<String>,
    /// Only WPA3 (SAE): write `true` only for a network that accepts nothing else. Only with `psk`.
    /// Absent means WPA2 and WPA3 transition mode; a written value of either kind (even `false`)
    /// counts as a newer key ([`Wifi::uses_ext_keys`]), since older agents reject the key itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wpa3_only: Option<bool>,
    /// The enterprise (802.1X) method: `peap`, `ttls`, `tls` or `pwd`. Makes the network
    /// enterprise; not together with `psk` or `open`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eap: Option<EapMethod>,
    /// The account name. Required with `eap`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    /// The account password. Required with `eap` `peap`, `ttls` and `pwd`; not allowed with `tls`.
    /// A secret: never shown to AI tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// The inner authentication of `peap` and `ttls`: `mschapv2` (the default), `pap`, `gtc` or
    /// `md5`. Not allowed with other methods.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase2: Option<Phase2>,
    /// The outer (anonymous) identity sent before the encrypted tunnel; absent: none is sent.
    /// Only with `eap`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anonymous_identity: Option<String>,
    /// The domain the RADIUS server's certificate must match (a suffix match), such as
    /// `radius.school.ac.th`. With `eap`, write it or `ca_cert` (or `check_server = false`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_domain: Option<String>,
    /// The CA certificate of the RADIUS server, PEM text inline. Absent: the system's trusted CAs
    /// (allowed only with `server_domain`). Only with `eap`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_cert: Option<String>,
    /// Whether the RADIUS server is checked; `true` when absent. Write `false` only to connect
    /// without `server_domain` or `ca_cert` (not recommended: a nearby hotspot with the same name
    /// can capture the password). Only with `eap`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_server: Option<bool>,
    /// The client certificate of `tls`, PEM text inline. Required with `tls`, not allowed
    /// otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert: Option<String>,
    /// The client private key of `tls`, PEM text inline. Required with `tls`, not allowed
    /// otherwise. A secret: never shown to AI tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_key: Option<String>,
    /// The passphrase of an encrypted `client_key`. Only with `tls`. A secret: never shown to AI
    /// tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_key_password: Option<String>,
}

/// The secret fields stay out of debug output, so that no log line carries them.
impl std::fmt::Debug for Wifi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact = |s: &Option<String>| s.as_ref().map(|_| "<redacted>");
        f.debug_struct("Wifi")
            .field("ssid", &self.ssid)
            .field("hidden", &self.hidden)
            .field("open", &self.open)
            .field("psk", &redact(&self.psk))
            .field("wpa3_only", &self.wpa3_only)
            .field("eap", &self.eap)
            .field("identity", &self.identity)
            .field("password", &redact(&self.password))
            .field("phase2", &self.phase2)
            .field("anonymous_identity", &self.anonymous_identity)
            .field("server_domain", &self.server_domain)
            .field("ca_cert", &self.ca_cert.as_ref().map(|_| "<pem>"))
            .field("check_server", &self.check_server)
            .field("client_cert", &self.client_cert.as_ref().map(|_| "<pem>"))
            .field("client_key", &redact(&self.client_key))
            .field("client_key_password", &redact(&self.client_key_password))
            .finish()
    }
}

/// An enterprise (802.1X) method of [`Wifi::eap`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum EapMethod {
    /// Protected EAP: account and password inside a TLS tunnel (the common school setup).
    Peap,
    /// Tunneled TLS: account and password inside a TLS tunnel.
    Ttls,
    /// A client certificate and key instead of a password.
    Tls,
    /// EAP-pwd: account and password, no certificates.
    Pwd,
}

impl EapMethod {
    /// As written in the settings file.
    pub fn as_str(self) -> &'static str {
        match self {
            EapMethod::Peap => "peap",
            EapMethod::Ttls => "ttls",
            EapMethod::Tls => "tls",
            EapMethod::Pwd => "pwd",
        }
    }
}

/// The inner authentication of `peap` and `ttls` ([`Wifi::phase2`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum Phase2 {
    /// MS-CHAPv2, the default.
    Mschapv2,
    /// PAP (plain password inside the tunnel).
    Pap,
    /// GTC.
    Gtc,
    /// MD5.
    Md5,
}

impl Phase2 {
    /// As written in the settings file.
    pub fn as_str(self) -> &'static str {
        match self {
            Phase2::Mschapv2 => "mschapv2",
            Phase2::Pap => "pap",
            Phase2::Gtc => "gtc",
            Phase2::Md5 => "md5",
        }
    }
}

/// What kind of network a [`Wifi`] is, inferred from its fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiKind {
    /// No password: `open = true`, or (older entries) no `psk` and no `eap`.
    Open,
    /// WPA personal (`psk`); `sae_only` when `wpa3_only = true`.
    Personal { sae_only: bool },
    /// Enterprise 802.1X (`eap`).
    Enterprise(EapMethod),
}

impl Wifi {
    /// The fields whose values are secrets: kept out of reports, logs and AI tokens' view.
    pub const SECRET_FIELDS: [&'static str; 4] =
        ["psk", "password", "client_key", "client_key_password"];

    /// `eap` makes it enterprise, else `psk` personal, else open (including the older entries
    /// with only `ssid` and `hidden`, which always meant an open network).
    pub fn kind(&self) -> WifiKind {
        match (self.eap, &self.psk) {
            (Some(m), _) => WifiKind::Enterprise(m),
            (None, Some(_)) => WifiKind::Personal {
                sae_only: self.wpa3_only == Some(true),
            },
            (None, None) => WifiKind::Open,
        }
    }

    /// Whether it writes any key added with full Wi-Fi support ([`FEATURE_WIFI_EXT`]): `open`,
    /// `wpa3_only` (either value), `eap` or any 802.1X field. Older agents reject such an entry.
    pub fn uses_ext_keys(&self) -> bool {
        self.open.is_some()
            || self.wpa3_only.is_some()
            || self.eap.is_some()
            || self.has_8021x_fields()
    }

    /// Whether any of the fields that belong to `eap` is written.
    pub(crate) fn has_8021x_fields(&self) -> bool {
        self.identity.is_some()
            || self.password.is_some()
            || self.phase2.is_some()
            || self.anonymous_identity.is_some()
            || self.server_domain.is_some()
            || self.ca_cert.is_some()
            || self.check_server.is_some()
            || self.client_cert.is_some()
            || self.client_key.is_some()
            || self.client_key_password.is_some()
    }

    /// The inner authentication to use: `phase2`, or `mschapv2` when absent, for `peap` and
    /// `ttls`; `None` for every other kind.
    pub fn phase2_or_default(&self) -> Option<Phase2> {
        match self.eap {
            Some(EapMethod::Peap | EapMethod::Ttls) => {
                Some(self.phase2.unwrap_or(Phase2::Mschapv2))
            }
            _ => None,
        }
    }
}

/// What a Device using Config `c` of `m` gets: `c` laid over `[defaults]` (phase B design §4.2),
/// the only place the inheritance rule is implemented.
///
/// Single values: `c`'s when written, else the Defaults', else today's default (`learning`,
/// `[]`, `false`, none); `chrome.update_window` and `chrome.pause_until` each on its own.
/// Collections: the Defaults' entries whose name is neither among `c`'s nor in `c.drop`, in
/// order, then `c`'s, in order. The Defaults' Wi-Fi is the legacy `[school] wifi` (minus the
/// SSIDs the Defaults list) followed by `[defaults] wifi`.
pub fn effective_config(m: &Manifest, c: &ConfigLayer) -> Config {
    let none = Defaults::default();
    let d = m.defaults.as_ref().unwrap_or(&none);
    fn wifi(w: &Wifi) -> &str {
        &w.ssid
    }
    fn by_name(n: &NetDevice) -> &str {
        &n.name
    }
    let school_and_defaults_wifi = merge_list(&m.school.wifi, &d.wifi, &[], wifi);
    let drop = &c.drop;
    Config {
        id: c.id.clone(),
        name: c.name.clone(),
        interface: c.interface.or(d.interface).unwrap_or_default(),
        login_methods: c
            .login_methods
            .as_ref()
            .or(d.login_methods.as_ref())
            .cloned()
            .unwrap_or_default(),
        local_users_admin: c
            .local_users_admin
            .or(d.local_users_admin)
            .unwrap_or_default(),
        it_account: c.it_account.as_ref().or(d.it_account.as_ref()).cloned(),
        wifi: merge_list(&school_and_defaults_wifi, &c.wifi, &drop.wifi, wifi),
        apps: Apps {
            web: merge_list(&d.apps.web, &c.apps.web, &drop.apps.web, |a| {
                a.name.as_str()
            }),
            flatpak: merge_list(&d.apps.flatpak, &c.apps.flatpak, &drop.apps.flatpak, |id| {
                id.as_str()
            }),
            kiosk: merge_map(&d.apps.kiosk, &c.apps.kiosk, &drop.apps.kiosk),
        },
        printers: merge_list(&d.printers, &c.printers, &drop.printers, by_name),
        scanners: merge_list(&d.scanners, &c.scanners, &drop.scanners, by_name),
        chrome_policy: merge_map(&d.chrome_policy, &c.chrome_policy, &drop.chrome_policy),
        chrome: ChromeUpdate {
            update_window: c
                .chrome
                .update_window
                .clone()
                .or(d.chrome.update_window.clone()),
            pause_until: c
                .chrome
                .pause_until
                .clone()
                .or(d.chrome.pause_until.clone()),
        },
        files: merge_list(&d.files, &c.files, &drop.files, |f| f.dest.as_str()),
        downloads: merge_list(&d.downloads, &c.downloads, &drop.downloads, |f| {
            f.dest.as_str()
        }),
        scripts: merge_list(&d.scripts, &c.scripts, &drop.scripts, |f| f.path.as_str()),
        legacy_browser: c.legacy_browser,
    }
}

/// `[config.apps]`: the apps of a Config.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Apps {
    /// Web apps: launchers that open a site in its own Chrome window.
    #[serde(default)]
    pub web: Vec<WebApp>,
    /// Flatpak app ids installed from Flathub (in both modes).
    #[serde(default)]
    pub flatpak: Vec<String>,
    /// Kiosk apps (plan 9), keyed by app id; id rules and other checks are in [`crate::kiosk`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            description = "Kiosk apps keyed by app id: the id starts with a lowercase letter, has only lowercase letters, digits and -, and is at most 24 characters. At most 32 per Config."
        )
    )]
    pub kiosk: BTreeMap<String, KioskApp>,
}

impl Apps {
    pub fn is_empty(&self) -> bool {
        self.web.is_empty() && self.flatpak.is_empty() && self.kiosk.is_empty()
    }
}

/// `[config.apps.kiosk.<id>]`: an app IT defines that runs in an isolated, disposable kiosk
/// session (kiosk design §3). Only parsing here; rules such as "exactly one of `url` and `exec`"
/// are judged by [`crate::kiosk::check`] (shared by lint and agent).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "schema",
    schemars(
        description = "`[config.apps.kiosk.<id>]`: an app that runs alone in an isolated, disposable kiosk session, started from the login screen. Write exactly one of `url` and `exec`."
    )
)]
#[serde(deny_unknown_fields)]
pub struct KioskApp {
    /// The name shown on the login screen and in the Dock, at most 64 characters, no `:` or `,`.
    pub name: String,
    /// Like a web app's: a `files/…` file in the bundle or an `https://` link; absent: a generic
    /// icon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    /// The entry page of a web or PWA app (`https://`); exactly one of `url` and `exec`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Install and launch the `url` as a PWA; only with `url`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub pwa: bool,
    /// Host names the session may open (subdomains included); absent or empty: the host of
    /// `url` (see [`crate::kiosk::allow_hosts`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            description = "Host names the session may open (subdomains included, no `*`); absent or empty: the host of `url`. Only for web apps."
        )
    )]
    pub allow: Vec<String>,
    /// Only for web / PWA apps: a replacement user agent, at most 512 bytes, no control
    /// characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// Chrome extensions force-installed in the session (web / PWA apps).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<KioskExtension>,
    /// Chrome policies laid over the kiosk session's default locks (web / PWA apps); the
    /// Config's `chrome_policy` is not inherited, and the locked keys cannot be set.
    #[serde(default, skip_serializing_if = "toml::Table::is_empty")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "serde_json::Map<String, serde_json::Value>")
    )]
    pub chrome_policy: toml::Table,
    /// A Flatpak app id, or an absolute path under `/usr/` (no arguments); exactly one of `url`
    /// and `exec`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<String>,
    /// Reserved; Android apps are not supported. Any value parses only so that the check reports
    /// `kiosk_launch_invalid` instead of an unknown key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<serde_json::Value>"))]
    pub android: Option<toml::Value>,
    /// Listed on the login screen, where students start the app.
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    #[cfg_attr(feature = "schema", schemars(extend("default" = true)))]
    pub login_screen: bool,
    /// Listed in the Dock and app list of normal sessions (starting it ends the session and
    /// returns to the login screen).
    #[serde(default, skip_serializing_if = "is_false")]
    pub in_session: bool,
}

/// A Chrome extension a kiosk app force-installs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct KioskExtension {
    /// The extension id: 32 lowercase letters a-p.
    pub id: String,
    /// The extension's update manifest URL (`https://`).
    pub update_url: String,
    /// The extension's managed configuration, passed as written.
    #[serde(default, skip_serializing_if = "toml::Table::is_empty")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "serde_json::Map<String, serde_json::Value>")
    )]
    pub config: toml::Table,
}

fn yes() -> bool {
    true
}

fn is_true(b: &bool) -> bool {
    *b
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// A web app: a launcher that opens `url` in its own Chrome window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct WebApp {
    /// The launcher's name.
    pub name: String,
    /// The site address, `https://` (or `http://`, with a warning).
    pub url: String,
    /// A `files/…` file in the bundle or an `https://` link; absent: a generic browser icon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

/// A network printer or scanner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct NetDevice {
    /// The name users see, 1-64 characters.
    pub name: String,
    /// The address: `ipp://`, `ipps://`, `http://` or `https://` for printers; `http://` or
    /// `https://` (eSCL) for scanners. No credentials.
    pub uri: String,
}

/// A file from the bundle placed on the Devices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    /// Starts with `files/` and must be a file present in the bundle.
    pub src: String,
    /// An absolute path on the Device, in a writable place.
    pub dest: String,
}

/// A large file downloaded by URL instead of being carried in the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Download {
    /// Where to download the file from.
    pub url: String,
    /// The file's SHA-256, 64 lowercase hex digits; a download that does not match is not used.
    pub sha256: String,
    /// An absolute path on the Device, in a writable place.
    pub dest: String,
}

/// A script from the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Script {
    /// Starts with `scripts/` and must be a file present in the bundle.
    pub path: String,
    /// When it runs: `apply` (as root when settings are applied) or `login` (as the user at
    /// sign-in).
    #[serde(default)]
    pub when: When,
    /// How long the script may run, in seconds; default 300, at most 1800.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

/// When a script runs. A script runs again only when its content changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum When {
    /// As root, when the Device applies new settings.
    #[default]
    Apply,
    /// As the user, when they sign in.
    Login,
}

/// `[[device]]`: one Device's Group and Lock, found by serial number or device id.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct DeviceEntry {
    /// The hardware serial number (for Dell, the service tag); compared ignoring case and
    /// surrounding spaces.
    #[serde(default)]
    pub serial: Option<String>,
    /// The device id generated at install, shown in the console; for Devices without a serial.
    #[serde(default)]
    pub device_id: Option<String>,
    /// The id of the Group this Device belongs to.
    pub group: String,
    /// Lock the Device (lost or stolen): only administrators can sign in.
    #[serde(default)]
    pub locked: Option<Lock>,
    /// Legacy remote factory reset request (Ruling 22). Kept in the format so that bundles carrying
    /// it still parse (`deny_unknown_fields`); agents ignore it since factory reset moved to the
    /// per-machine inbox (MQTT push spec §6.3).
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(
            description = "Legacy, do not use: Devices ignore it. A Factory reset is sent from the Devices page as an Inbox command."
        )
    )]
    pub reset: Option<ResetRequest>,
}

/// `[[device]].reset = { id = "<UUIDv4>", requested_at = "<RFC 3339>" }`.
///
/// Legacy: agents no longer act on it (see [`DeviceEntry::reset`]). `requested_at` is a quoted
/// RFC 3339 string (TOML's bare datetimes are not accepted).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "schema",
    schemars(description = "Legacy factory reset request; Devices ignore it.")
)]
#[serde(deny_unknown_fields)]
pub struct ResetRequest {
    /// The request id: 1-64 letters, digits or `-` (a UUID).
    pub id: String,
    /// When the reset was requested: a quoted RFC 3339 timestamp.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub requested_at: chrono::DateTime<chrono::Utc>,
}

/// `reset.id` 最长这么多字符（UUID 是 36）。
pub const MAX_RESET_ID_LEN: usize = 64;

impl ResetRequest {
    /// `id` 是 1..=64 个 ASCII 字母、数字或 `-`。机器把执行过的 id 按行记在种子分区的 `reset-done` 里，
    /// 带换行或空白的 id 永远对不上已记下的行，会每次开机都恢复出厂；发布前 lint 以 error 拦下，
    /// 机器上同样校验、不合格就不执行（Manifest::validate 不收紧）。
    pub fn check_id(&self) -> Result<(), String> {
        let ok = !self.id.is_empty()
            && self.id.len() <= MAX_RESET_ID_LEN
            && self
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if ok {
            Ok(())
        } else {
            Err(format!(
                "The factory-reset request id must be 1-{MAX_RESET_ID_LEN} letters, digits or - (the panel generates a UUID)"
            ))
        }
    }
}

/// `[device.locked]`: a Lock.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Lock {
    /// The message on the login screen of the locked Device, at most 500 characters.
    pub message: String,
}

/// Manifest keys added after machines were already in the field (ruling 14). A machine whose
/// agent predates a key rejects the whole manifest (`deny_unknown_fields`), so the agent reports
/// the keys it understands (`StatusReport::manifest_features`) and publishing refuses a version
/// that uses one which recently seen machines do not understand.
pub const FEATURE_UPDATE_MIRROR: &str = "update_mirror";
/// See [`FEATURE_UPDATE_MIRROR`].
pub const FEATURE_ESCROW_RECIPIENTS: &str = "escrow_recipients";
/// See [`FEATURE_UPDATE_MIRROR`]: `[school] id` (plan 6 Task 10b).
pub const FEATURE_SCHOOL_ID: &str = "school_id";
/// See [`FEATURE_UPDATE_MIRROR`]: `[config.apps.kiosk]`（计划 9）。
pub const FEATURE_KIOSK: &str = "kiosk";
/// See [`FEATURE_UPDATE_MIRROR`]: the new shape itself (`[[config]]`, config profiles design
/// §3.1), reported for every new-shape text since an older agent cannot read it at all.
pub const FEATURE_CONFIG: &str = "config";
/// See [`FEATURE_UPDATE_MIRROR`]: full Wi-Fi support, that is `[[school.wifi]]` and the keys
/// [`Wifi::uses_ext_keys`] looks at (`open`, `wpa3_only`, `eap` and the 802.1X fields) in any
/// Wi-Fi list (the school's, the Defaults', a Config's).
pub const FEATURE_WIFI_EXT: &str = "wifi_ext";
/// See [`FEATURE_UPDATE_MIRROR`]: `client_secret` and `card_hosts` in `[school.oidc]`.
pub const FEATURE_OIDC_CARD: &str = "oidc_card";
/// See [`FEATURE_UPDATE_MIRROR`]: the Device reads `format = 2` (Defaults, `drop`, the IT account,
/// the school logo and name); the same string as [`format_feature`]`(2)`.
pub const FEATURE_FORMAT_2: &str = "format_2";

/// Whether `s` is a school id as written in manifests and seeds: a UUID in its canonical text
/// form, lowercase hex in 8-4-4-4-12 groups (36 characters). One spelling only, so the machine's
/// comparison with its seed is a plain string equality.
pub fn valid_school_id(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        })
}

/// An optional school id that, when written, is valid ([`valid_school_id`]).
pub(crate) fn school_id_opt<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<String>, D::Error> {
    let s = String::deserialize(d)?;
    if !valid_school_id(&s) {
        return Err(serde::de::Error::custom(
            "school id must be a lowercase UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)",
        ));
    }
    Ok(Some(s))
}

/// The message a machine reports when it refuses a bundle for not naming its school.
pub const OTHER_SCHOOL: &str = "bundle is for another school";

/// The school binding (plan 6 Task 10b): with `seed_school` (the school id of the machine's seed)
/// set, `m` must name exactly that school; missing or different is [`BundleError::OtherSchool`].
/// A seed without a school id (written before plan 6) checks nothing: such machines accept
/// bundles as before.
pub fn check_school(m: &Manifest, seed_school: Option<&str>) -> Result<(), BundleError> {
    match seed_school {
        Some(want) if m.school.id.as_deref() != Some(want) => Err(BundleError::OtherSchool),
        _ => Ok(()),
    }
}

/// A list key that, when written, has at least one entry.
fn non_empty_list<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    let v = Vec::<T>::deserialize(d)?;
    if v.is_empty() {
        return Err(serde::de::Error::custom(
            "must not be empty: leave the key out instead",
        ));
    }
    Ok(v)
}

/// The later-added keys (see [`FEATURE_UPDATE_MIRROR`]) that `m` uses, in a fixed order. A key
/// counts as used when it is written at all; the parsed value tells exactly that, since
/// `escrow_recipients` and `[school] wifi` are never written empty.
pub fn features_used(m: &Manifest) -> Vec<&'static str> {
    let s = &m.school;
    let mut out = Vec::new();
    if s.update_mirror.is_some() {
        out.push(FEATURE_UPDATE_MIRROR);
    }
    if !s.escrow_recipients.is_empty() {
        out.push(FEATURE_ESCROW_RECIPIENTS);
    }
    if s.id.is_some() {
        out.push(FEATURE_SCHOOL_ID);
    }
    let defaults = m.defaults.as_ref();
    if defaults.is_some_and(|d| !d.apps.kiosk.is_empty())
        || m.configs.iter().any(|c| !c.apps.kiosk.is_empty())
    {
        out.push(FEATURE_KIOSK);
    }
    if m.shape == Shape::New {
        out.push(FEATURE_CONFIG);
    }
    let ext = || {
        s.wifi
            .iter()
            .chain(defaults.into_iter().flat_map(|d| &d.wifi))
            .chain(m.configs.iter().flat_map(|c| &c.wifi))
            .any(Wifi::uses_ext_keys)
    };
    if !s.wifi.is_empty() || ext() {
        out.push(FEATURE_WIFI_EXT);
    }
    if s.oidc
        .as_ref()
        .is_some_and(|o| o.client_secret.is_some() || !o.card_hosts.is_empty())
    {
        out.push(FEATURE_OIDC_CARD);
    }
    out
}

/// An error-level lint of `validate_all`.
fn problem(code: &'static str, message: String) -> Lint {
    Lint::new(LintLevel::Error, code, message)
}

/// The lint for an empty trust; the server's draft check reports the same one.
pub fn trust_empty_lint() -> Lint {
    problem(
        "trust_empty",
        "trust cannot be empty: list the school's keys (at least one registered recovery \
         key, and the IT passkey for everyday publishing)"
            .into(),
    )
    .at("trust")
}

/// 序列号比较：去掉首尾空白、不区分大小写；空串视为没有。
pub fn normalize_id(s: &Option<String>) -> Option<String> {
    let s = s.as_deref()?.trim().to_lowercase();
    (!s.is_empty()).then_some(s)
}

/// `owner` names the layer in messages: `config <id>` or `[defaults]`.
fn check_dest(out: &mut Vec<Lint>, owner: &str, at: String, dest: &str) {
    if !dest.starts_with('/') {
        out.push(
            problem(
                "dest_not_absolute",
                format!(
                    "{at}: destination {dest:?} in {owner} is not an absolute path; \
                     write it starting with /"
                ),
            )
            .at(at)
            .param("dest", dest),
        );
    }
}

fn check_in_bundle(
    out: &mut Vec<Lint>,
    owner: &str,
    at: String,
    dir: &str,
    path: &str,
    present: &BTreeSet<String>,
) {
    if !path.starts_with(dir) {
        out.push(
            problem(
                "file_outside_dir",
                format!("{at}: {path:?} in {owner} is outside {dir}; move the file under {dir}"),
            )
            .at(at)
            .param("path", path)
            .param("dir", dir),
        );
    } else if !present.contains(path) {
        out.push(
            problem(
                "file_missing",
                format!(
                    "{at}: {path:?} in {owner} is not in the bundle; add the file or fix \
                     the path"
                ),
            )
            .at(at)
            .param("path", path),
        );
    }
}

impl Manifest {
    /// Parse either shape (§3.1); a legacy text is expanded and marked [`Shape::Legacy`].
    pub fn parse(text: &str) -> Result<Manifest, BundleError> {
        parse_shapes(text).map_err(ShapeError::into_bundle_error)
    }

    /// The Config with this id as written (the first, should ids repeat).
    pub fn config(&self, id: &str) -> Option<&ConfigLayer> {
        self.configs.iter().find(|c| c.id == id)
    }

    /// The Config the Group with this id uses, as written; `None` when either is missing.
    pub fn config_of_group(&self, group_id: &str) -> Option<&ConfigLayer> {
        let g = self.groups.iter().find(|g| g.id == group_id)?;
        self.config(&g.config)
    }

    /// What the Devices of the Group with this id get ([`effective_config`] of its Config);
    /// `None` when the Group or its Config is missing.
    pub fn effective_of_group(&self, group_id: &str) -> Option<Config> {
        Some(effective_config(self, self.config_of_group(group_id)?))
    }

    /// 检查清单内部与它引用的文件是否自洽。`present` 是包里实际存在的
    /// `files/…`、`scripts/…` 路径。返回 [`Manifest::validate_all`] 的第一个问题。
    pub fn validate(&self, present: &BTreeSet<String>) -> Result<(), BundleError> {
        match self.validate_all(present).into_iter().next() {
            None => Ok(()),
            Some(l) => Err(BundleError::Invalid(l.message)),
        }
    }

    /// Every problem `validate` would refuse, in the order `validate` meets them; empty exactly
    /// when `validate` accepts. Each check's condition is the one `validate` always had: a
    /// failed check never skips or changes a later one (only the second of two checks on the
    /// same path is skipped, where the first already says it is wrong).
    pub fn validate_all(&self, present: &BTreeSet<String>) -> Vec<Lint> {
        let mut out = Vec::new();
        if self.trust.is_empty() {
            out.push(trust_empty_lint());
        }
        let mut trust_ids = BTreeSet::new();
        for k in &self.trust {
            let id = k.id.as_str();
            let at = |code, message: String| problem(code, message).at("trust").param("id", id);
            if !trust_ids.insert(id) {
                out.push(at(
                    "trust_duplicate_id",
                    format!("trust: key id {id} appears more than once; give each key its own id"),
                ));
            }
            let raw = STANDARD.decode(&k.public_key).unwrap_or_default();
            match k.alg {
                KeyAlg::Ed25519 => {
                    if raw.len() != 32 {
                        out.push(at(
                            "trust_key_invalid",
                            format!(
                                "trust: key {id} is not 32 bytes of base64; an ed25519 \
                                 public_key is the base64 of its 32 raw bytes"
                            ),
                        ));
                    }
                    if k.rp_id.is_some() {
                        out.push(at(
                            "trust_rp_id_forbidden",
                            format!(
                                "trust: key {id} is ed25519 and cannot have an rp_id; remove \
                                 rp_id"
                            ),
                        ));
                    }
                }
                KeyAlg::WebauthnEs256 => {
                    if raw.len() != 65 || raw[0] != 0x04 {
                        out.push(at(
                            "trust_key_invalid",
                            format!(
                                "trust: key {id} is not a 65-byte P-256 point starting with \
                                 0x04 (base64); register the passkey again"
                            ),
                        ));
                    }
                    let rp_ok = matches!(k.rp_id.as_deref(),
                        Some(rp) if crate::webauthn::valid_rp_id(rp));
                    if !rp_ok {
                        out.push(at(
                            "trust_rp_id_invalid",
                            format!(
                                "trust: key {id} needs an rp_id that is a lowercase ASCII host \
                                 name (no scheme, port or path)"
                            ),
                        ));
                    }
                }
            }
        }

        let mut ids = BTreeSet::new();
        for g in &self.groups {
            if !ids.insert(g.id.as_str()) {
                out.push(
                    problem(
                        "group_duplicate_id",
                        format!(
                            "group.{0}: group id {0} appears more than once; give each group \
                             its own id",
                            g.id
                        ),
                    )
                    .at(format!("group.{}", g.id))
                    .param("id", &g.id),
                );
            }
        }
        if !ids.contains(DEFAULT_GROUP) {
            out.push(
                problem(
                    "default_group_missing",
                    format!(
                        "group: there is no group with id {DEFAULT_GROUP:?}; add one, new \
                         machines and machines without a group use it"
                    ),
                )
                .at("group"),
            );
        }

        // In the legacy shape the configs are the groups themselves: a repeated id is already
        // `group_duplicate_id`, and every group names its own config.
        if self.shape == Shape::New {
            let mut config_ids = BTreeSet::new();
            for c in &self.configs {
                if !config_ids.insert(c.id.as_str()) {
                    out.push(
                        problem(
                            "config_duplicate_id",
                            format!(
                                "config.{0}: config id {0} appears more than once; give each \
                                 config its own id",
                                c.id
                            ),
                        )
                        .at(format!("config.{}", c.id))
                        .param("id", &c.id),
                    );
                }
            }
            for g in &self.groups {
                if !config_ids.contains(g.config.as_str()) {
                    out.push(
                        problem(
                            "group_unknown_config",
                            format!(
                                "group.{}.config: group {} uses config {}, which does not \
                                 exist; name an existing [[config]] id or add the config",
                                g.id, g.id, g.config
                            ),
                        )
                        .at(format!("group.{}.config", g.id))
                        .param("group", &g.id)
                        .param("config", &g.config),
                    );
                }
            }
        }

        // The Defaults' files, scripts and downloads reach every Device through
        // `effective_config`: the same structural checks, at `defaults.…`.
        if let Some(d) = &self.defaults {
            let layer = Layer {
                base: "defaults".into(),
                owner: "[defaults]".into(),
                files: &d.files,
                scripts: &d.scripts,
                downloads: &d.downloads,
            };
            layer.validate(&mut out, present);
        }
        for c in &self.configs {
            let layer = Layer {
                base: format!("config.{}", c.id),
                owner: format!("config {}", c.id),
                files: &c.files,
                scripts: &c.scripts,
                downloads: &c.downloads,
            };
            layer.validate(&mut out, present);
        }

        // 一个文件的路径不能同时是另一个文件的上级目录（`files/a` 与 `files/a/b`）：
        // 机器解包到 current/ 时两者必有一个落不了地。
        for p in present {
            let dir = format!("{p}/");
            if let Some(q) = present.range(dir.clone()..).next() {
                if q.starts_with(&dir) {
                    out.push(
                        problem(
                            "path_file_and_dir",
                            format!(
                                "{p} is a file and also the parent directory of {q}; rename \
                                 one of them"
                            ),
                        )
                        .param("file", p)
                        .param("child", q),
                    );
                }
            }
        }

        let mut seen = BTreeSet::new();
        for (i, d) in self.devices.iter().enumerate() {
            let serial = normalize_id(&d.serial);
            let device_id = normalize_id(&d.device_id);
            if serial.is_none() && device_id.is_none() {
                out.push(
                    problem(
                        "device_no_identity",
                        format!(
                            "device[{i}] (group {}) has neither serial nor device_id; write \
                             one of them",
                            d.group
                        ),
                    )
                    .at(format!("device[{i}]")),
                );
            }
            if !ids.contains(d.group.as_str()) {
                let who = d
                    .serial
                    .as_deref()
                    .or(d.device_id.as_deref())
                    .unwrap_or("")
                    .trim();
                out.push(
                    problem(
                        "device_unknown_group",
                        format!(
                            "device[{i}].group: machine {who} points to group {}, which does \
                             not exist; use an existing group id",
                            d.group
                        ),
                    )
                    .at(format!("device[{i}].group"))
                    .param("group", &d.group),
                );
            }
            for (kind, v) in [("serial", serial), ("device_id", device_id)] {
                if let Some(v) = v {
                    if !seen.insert(v.clone()) {
                        out.push(
                            problem(
                                "device_duplicate_id",
                                format!(
                                    "device[{i}]: machine {kind} {v} appears more than once; \
                                     list each machine once"
                                ),
                            )
                            .at(format!("device[{i}]"))
                            .param("kind", kind)
                            .param("value", v),
                        );
                    }
                }
            }
        }
        out
    }
}

/// One layer (`[defaults]` or a `[[config]]`) as `validate_all` checks it: `base` is its lint
/// path, `owner` its name in messages.
struct Layer<'a> {
    base: String,
    owner: String,
    files: &'a [FileEntry],
    scripts: &'a [Script],
    downloads: &'a [Download],
}

impl Layer<'_> {
    /// The structural checks of one layer's files, scripts and downloads.
    fn validate(&self, out: &mut Vec<Lint>, present: &BTreeSet<String>) {
        let (base, owner) = (self.base.as_str(), self.owner.as_str());
        for (i, f) in self.files.iter().enumerate() {
            let at = format!("{base}.files[{i}]");
            check_in_bundle(out, owner, format!("{at}.src"), "files/", &f.src, present);
            check_dest(out, owner, format!("{at}.dest"), &f.dest);
        }
        for (i, s) in self.scripts.iter().enumerate() {
            let at = format!("{base}.scripts[{i}]");
            check_in_bundle(
                out,
                owner,
                format!("{at}.path"),
                "scripts/",
                &s.path,
                present,
            );
            if s.timeout_secs.is_some_and(|t| t > MAX_SCRIPT_TIMEOUT_SECS) {
                out.push(
                    problem(
                        "script_timeout_too_long",
                        format!(
                            "{at}.timeout_secs: script {} in {owner} has timeout_secs over \
                             the limit of {MAX_SCRIPT_TIMEOUT_SECS} seconds; lower it",
                            s.path
                        ),
                    )
                    .at(format!("{at}.timeout_secs"))
                    .param("max", MAX_SCRIPT_TIMEOUT_SECS),
                );
            }
        }
        for (i, d) in self.downloads.iter().enumerate() {
            let at = format!("{base}.downloads[{i}]");
            let ok = d.sha256.len() == 64
                && d.sha256
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
            if !ok {
                out.push(
                    problem(
                        "download_sha256_invalid",
                        format!(
                            "{at}.sha256: the sha256 of download {} in {owner} must be 64 \
                             lowercase hex digits",
                            d.url
                        ),
                    )
                    .at(format!("{at}.sha256"))
                    .param("url", &d.url),
                );
            }
            check_dest(out, owner, format!("{at}.dest"), &d.dest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{spec_example as example, spec_example_present as present};

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    /// 解析改过的例子并校验，返回校验错误的文本。
    fn invalid_after(from: &str, to: &str) -> String {
        let text = example();
        assert!(text.contains(from), "例子里没有 {from:?}");
        let m = Manifest::parse(&text.replacen(from, to, 1)).unwrap();
        match m.validate(&present()) {
            Err(BundleError::Invalid(msg)) => msg,
            other => panic!("期望 Invalid，得到 {other:?}"),
        }
    }

    #[test]
    fn parses_spec_example() {
        let m = Manifest::parse(&example()).unwrap();
        assert_eq!(m.shape, Shape::New);
        assert_eq!(m.groups.len(), 3);
        assert_eq!(m.configs.len(), 3);
        assert_eq!(m.configs[0].interface, Some(Interface::Full));
        assert_eq!(m.configs[1].interface, Some(Interface::Learning));
        assert_eq!(
            m.devices[1].locked.as_ref().unwrap().message,
            "本机已挂失，请交回 IT 办公室"
        );
        assert_eq!(m.configs[0].scripts[0].when, When::Login);
        assert_eq!(m.trust[0].alg, KeyAlg::Ed25519);
        assert_eq!(m.configs[2].interface, None, "not written");
        assert_eq!(
            m.effective_of_group("default").unwrap().interface,
            Interface::Learning
        );
        assert_eq!(m.groups[1].config, "cart");
        assert_eq!(
            m.configs[0].chrome.update_window.as_deref(),
            Some("16:00-07:00")
        );
        assert!(m.configs[1].chrome.is_empty());
        m.validate(&present()).unwrap();
    }

    /// `[config.chrome]`（旧形状 `[group.chrome]` 同样）：pause_until 写成字符串或裸日期都收成 `YYYY-MM-DD`；不认的键、别的类型报错；空的不序列化。
    #[test]
    fn parses_chrome_update_settings() {
        let parse = |extra: &str| {
            Manifest::parse(&format!(
                "version = 1\n[[group]]\nid = \"default\"\nname = \"d\"\n{extra}"
            ))
        };
        for p in ["\"2026-11-20\"", "2026-11-20"] {
            let m = parse(&format!("[group.chrome]\npause_until = {p}\n")).unwrap();
            assert_eq!(
                m.configs[0].chrome.pause_until.as_deref(),
                Some("2026-11-20")
            );
        }
        assert!(parse("[group.chrome]\npause_until = 3\n").is_err());
        assert!(parse("[group.chrome]\nmax_version = \"1\"\n").is_err());
        let g = &parse("").unwrap().configs[0];
        assert!(serde_json::to_value(g).unwrap().get("chrome").is_none());
    }

    #[test]
    fn rejects_missing_default_group() {
        let msg = invalid_after("id = \"default\"", "id = \"other\"");
        assert!(msg.contains("default"), "{msg}");
    }

    #[test]
    fn rejects_two_default_groups() {
        let msg = invalid_after("id = \"cart-g3\"", "id = \"default\"");
        assert!(msg.contains("default"), "{msg}");
    }

    #[test]
    fn rejects_duplicate_group_ids() {
        let msg = invalid_after("id = \"cart-g3\"", "id = \"teacher\"");
        assert!(msg.contains("teacher"), "{msg}");
    }

    #[test]
    fn rejects_device_pointing_to_unknown_group() {
        let msg = invalid_after("group = \"cart-g3\"", "group = \"nope\"");
        assert!(msg.contains("nope") && msg.contains("ABC1234"), "{msg}");
    }

    #[test]
    fn rejects_duplicate_serial_case_insensitive() {
        let msg = invalid_after("serial = \"XYZ9876\"", "serial = \"abc1234 \"");
        assert!(msg.to_lowercase().contains("abc1234"), "{msg}");
    }

    #[test]
    fn rejects_device_without_serial_or_id() {
        invalid_after("serial = \"XYZ9876\"\n", "serial = \"  \"\n");
        invalid_after("serial = \"ABC1234\"\n", "");
    }

    #[test]
    fn rejects_file_src_not_in_bundle() {
        let msg = invalid_after("files/wallpaper-teacher.jpg", "files/x.jpg");
        assert!(msg.contains("files/x.jpg"), "{msg}");
    }

    #[test]
    fn rejects_script_outside_scripts_dir() {
        let text = example().replacen("scripts/setup-scanner.sh", "files/a.sh", 1);
        let m = Manifest::parse(&text).unwrap();
        let mut p = present();
        p.insert("files/a.sh".into()); // 即便文件存在，路径也必须在 scripts/ 下
        assert!(matches!(m.validate(&p), Err(BundleError::Invalid(_))));
    }

    #[test]
    fn rejects_file_that_is_also_a_directory() {
        let m = Manifest::parse(&example()).unwrap();
        let mut p = present();
        p.insert("files/a".into());
        p.insert("files/a-b".into()); // 只是前缀相同，不冲突
        m.validate(&p).unwrap();
        p.insert("files/a/b".into());
        assert!(matches!(
            m.validate(&p),
            Err(BundleError::Invalid(msg)) if msg.contains("files/a/b")
        ));
    }

    #[test]
    fn caps_script_timeout() {
        let at = |t: u64| {
            example().replacen(
                "when = \"login\" }",
                &format!("when = \"login\", timeout_secs = {t} }}"),
                1,
            )
        };
        let m = Manifest::parse(&at(MAX_SCRIPT_TIMEOUT_SECS)).unwrap();
        m.validate(&present()).unwrap();
        for t in [MAX_SCRIPT_TIMEOUT_SECS + 1, i64::MAX as u64] {
            let m = Manifest::parse(&at(t)).unwrap();
            assert!(
                matches!(m.validate(&present()), Err(BundleError::Invalid(msg)) if msg.contains("timeout_secs")),
                "{t}"
            );
        }
    }

    #[test]
    fn rejects_relative_dest() {
        let msg = invalid_after("/usr/share/backgrounds/school.jpg", "etc/x");
        assert!(msg.contains("etc/x"), "{msg}");
        invalid_after("/opt/a.deb", "opt/a.deb");
    }

    #[test]
    fn rejects_bad_sha256() {
        let good = "a".repeat(64);
        invalid_after(&good, &"a".repeat(63));
        invalid_after(&good, &"A".repeat(64));
        invalid_after(&good, &"g".repeat(64));
    }

    #[test]
    fn rejects_empty_trust() {
        let mut m = Manifest::parse(&example()).unwrap();
        m.trust.clear();
        assert!(matches!(
            m.validate(&present()),
            Err(BundleError::Invalid(msg)) if msg.contains("trust")
        ));
    }

    #[test]
    fn rejects_duplicate_trust_ids() {
        let mut m = Manifest::parse(&example()).unwrap();
        m.trust.push(m.trust[0].clone());
        assert!(matches!(
            m.validate(&present()),
            Err(BundleError::Invalid(msg)) if msg.contains("school-2026")
        ));
    }

    #[test]
    fn rejects_trust_key_that_is_not_32_bytes() {
        invalid_after(KEY, "AAAA");
    }

    /// 65 字节、以 0x04 开头的点（validate 不检查是否在曲线上，验签时才检查）。
    fn p256_point() -> String {
        let mut raw = vec![0x04u8];
        raw.extend_from_slice(&[1u8; 64]);
        STANDARD.encode(raw)
    }

    fn with_passkey(rp_id: Option<&str>, public_key: String) -> Result<(), BundleError> {
        let mut m = Manifest::parse(&example()).unwrap();
        m.trust.push(TrustKey {
            id: "it-phone".into(),
            alg: KeyAlg::WebauthnEs256,
            public_key,
            rp_id: rp_id.map(String::from),
        });
        m.validate(&present())
    }

    #[test]
    fn ed25519_with_rp_id_invalid() {
        let mut m = Manifest::parse(&example()).unwrap();
        m.trust[0].rp_id = Some("school.ac.th".into());
        assert!(matches!(
            m.validate(&present()),
            Err(BundleError::Invalid(msg)) if msg.contains("rp_id")
        ));
        // TOML 里写上 rp_id 也一样。
        invalid_after(
            "alg = \"ed25519\"",
            "alg = \"ed25519\"\nrp_id = \"school.ac.th\"",
        );
    }

    #[test]
    fn webauthn_trust_key_shape() {
        with_passkey(Some("school.ac.th"), p256_point()).unwrap();
        with_passkey(Some("localhost"), p256_point()).unwrap();
        with_passkey(Some("mastersos-1.school.ac.th"), p256_point()).unwrap();
        // 没有 rp_id、空 rp_id。
        assert!(matches!(
            with_passkey(None, p256_point()),
            Err(BundleError::Invalid(_))
        ));
        assert!(matches!(
            with_passkey(Some(""), p256_point()),
            Err(BundleError::Invalid(_))
        ));
        // 32 字节（ed25519 的长度）、64 字节、首字节不是 0x04（压缩点也不收）。
        let mut compressed = vec![0x02u8];
        compressed.extend_from_slice(&[1u8; 64]);
        for pk in [
            KEY.to_string(),
            STANDARD.encode([4u8; 64]),
            STANDARD.encode(compressed),
            "不是 base64".to_string(),
        ] {
            assert!(
                matches!(
                    with_passkey(Some("school.ac.th"), pk.clone()),
                    Err(BundleError::Invalid(_))
                ),
                "{pk}"
            );
        }
    }

    #[test]
    fn rp_id_must_be_bare_lowercase_host() {
        for rp in [
            "School.ac.th",
            "https://school.ac.th",
            "school.ac.th:443",
            "school.ac.th/x",
            "school.ac.th.",
            ".school.ac.th",
            "school..ac.th",
            "-school.ac.th",
            "school-.ac.th",
            "sch ool.ac.th",
            "user@school.ac.th",
            "[::1]",
            "โรงเรียน.ac.th",
            &format!("{}.ac.th", "a".repeat(64)),
        ] {
            assert!(
                matches!(
                    with_passkey(Some(rp), p256_point()),
                    Err(BundleError::Invalid(_))
                ),
                "{rp:?} 应被拒"
            );
        }
    }

    #[test]
    fn trust_key_rp_id_roundtrips_and_is_omitted_when_absent() {
        let k = TrustKey {
            id: "it-phone".into(),
            alg: KeyAlg::WebauthnEs256,
            public_key: p256_point(),
            rp_id: Some("school.ac.th".into()),
        };
        let text = toml::to_string(&k).unwrap();
        assert!(text.contains("alg = \"webauthn-es256\""), "{text}");
        assert_eq!(toml::from_str::<TrustKey>(&text).unwrap(), k);
        let ed = TrustKey {
            alg: KeyAlg::Ed25519,
            rp_id: None,
            public_key: KEY.into(),
            ..k
        };
        assert!(!toml::to_string(&ed).unwrap().contains("rp_id"));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        for (from, to) in [
            ("update_channel = \"stable\"", "update_chanel = \"stable\""),
            ("local_users_admin = false", "local_user_admin = false"),
            ("version = 42", "version = 42\nbogus = 1"),
        ] {
            let text = example().replacen(from, to, 1);
            assert!(
                matches!(Manifest::parse(&text), Err(BundleError::Parse(_))),
                "{from}"
            );
        }
    }

    #[test]
    fn device_reset_parses_and_roundtrips() {
        let text = format!(
            "{}\n[[device]]\nserial = \"ABC1\"\ngroup = \"teacher\"\nreset = {{ id = \"3f1c2a9e-0b7d-4e2a-9c51-6a2f8d0e4b17\", requested_at = \"2026-10-15T03:04:05Z\" }}\n",
            example()
        );
        let m = Manifest::parse(&text).unwrap();
        let r = m.devices.last().unwrap().reset.clone().unwrap();
        assert_eq!(r.id, "3f1c2a9e-0b7d-4e2a-9c51-6a2f8d0e4b17");
        assert_eq!(
            r.requested_at,
            chrono::DateTime::parse_from_rfc3339("2026-10-15T03:04:05Z").unwrap()
        );
        // 回报给网页的 JSON 与清单里的 TOML 都能原样读回。
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<ResetRequest>(&json).unwrap(), r);
        assert_eq!(
            toml::from_str::<ResetRequest>(&toml::to_string(&r).unwrap()).unwrap(),
            r
        );
        // 没写 reset 的条目照旧；reset 里多一个字段整份拒收（deny_unknown_fields）。
        assert!(Manifest::parse(&example())
            .unwrap()
            .devices
            .iter()
            .all(|d| d.reset.is_none()));
        let extra = text.replace("requested_at =", "by = \"x\", requested_at =");
        assert!(matches!(
            Manifest::parse(&extra),
            Err(BundleError::Parse(_))
        ));
        let bad_time = text.replace("2026-10-15T03:04:05Z", "yesterday");
        assert!(matches!(
            Manifest::parse(&bad_time),
            Err(BundleError::Parse(_))
        ));
    }

    fn recipient() -> String {
        use age::secrecy::ExposeSecret as _;
        let id = age::x25519::Identity::generate();
        assert!(id
            .to_string()
            .expose_secret()
            .starts_with("AGE-SECRET-KEY-1"));
        id.to_public().to_string()
    }

    /// `[school].escrow_recipients`: age X25519 recipients in canonical form, none twice, at most
    /// eight; written, never empty.
    #[test]
    fn escrow_recipients_validate() {
        let (r1, r2) = (recipient(), recipient());
        let m = Manifest::parse(&example().replacen(
            "[school]",
            &format!("[school]\nescrow_recipients = [\"{r1}\", \"{r2}\"]"),
            1,
        ))
        .unwrap();
        assert_eq!(m.school.escrow_recipients, [r1.clone(), r2.clone()]);
        let check = |l: &[String]| crate::checks::escrow_recipients(l);
        check(&[r1.clone(), r2.clone()]).unwrap();
        check(&[]).unwrap();
        let eight: Vec<String> = (0..8).map(|_| recipient()).collect();
        check(&eight).unwrap();
        let mut nine = eight.clone();
        nine.push(recipient());
        assert!(check(&nine).unwrap_err().contains("at most 8"));
        assert!(check(&[r1.clone(), r1.clone()])
            .unwrap_err()
            .contains("more than once"));
        assert!(check(&[r1.to_uppercase()])
            .unwrap_err()
            .contains("canonical"));
        for bad in [
            "",
            "age1",
            "age1qqqq",
            "AGE-SECRET-KEY-1QQQQ",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA",
            &format!(" {r1}"),
            &r1[..r1.len() - 1],
        ] {
            assert!(check(&[bad.to_owned()]).is_err(), "{bad:?}");
        }
        // Written empty: refused at parse (same as absent, yet an old agent rejects the key).
        let empty = example().replacen("[school]", "[school]\nescrow_recipients = []", 1);
        assert!(matches!(
            Manifest::parse(&empty),
            Err(BundleError::Parse(e)) if e.contains("must not be empty")
        ));
    }

    /// Rulings 14 and 29: the later-added keys a manifest writes.
    #[test]
    fn features_used_lists_new_fields() {
        let m = Manifest::parse(&example()).unwrap();
        // 样例里有锁定应用（计划 9）、又是新形状；其余断言只看 [school] 的键，先把它们拿掉。
        assert_eq!(features_used(&m), [FEATURE_KIOSK, FEATURE_CONFIG]);
        let no_kiosk = |mut m: Manifest| {
            m.configs.iter_mut().for_each(|g| g.apps.kiosk.clear());
            m.shape = Shape::Legacy;
            m
        };
        assert!(features_used(&no_kiosk(m)).is_empty());
        let r = recipient();
        let text = example().replacen(
            "[school]",
            &format!(
                "[school]\nescrow_recipients = [\"{r}\"]\n\
                 update_mirror = \"https://cache.school.ac.th/mastersos\""
            ),
            1,
        );
        let m = no_kiosk(Manifest::parse(&text).unwrap());
        assert_eq!(
            features_used(&m),
            [FEATURE_UPDATE_MIRROR, FEATURE_ESCROW_RECIPIENTS]
        );
        let mut one = m.clone();
        one.school.update_mirror = None;
        assert_eq!(features_used(&one), [FEATURE_ESCROW_RECIPIENTS]);
        assert_eq!(
            [FEATURE_UPDATE_MIRROR, FEATURE_ESCROW_RECIPIENTS],
            ["update_mirror", "escrow_recipients"]
        );
        let mut all = m.clone();
        all.school.id = Some(SCHOOL_A.into());
        assert_eq!(
            features_used(&all),
            [
                FEATURE_UPDATE_MIRROR,
                FEATURE_ESCROW_RECIPIENTS,
                FEATURE_SCHOOL_ID
            ]
        );
        assert_eq!(FEATURE_SCHOOL_ID, "school_id");
    }

    #[test]
    fn oidc_card_keys_are_a_feature_and_stay_out_when_unused() {
        let with = |extra: &str| {
            let text = example().replacen(
                "client_id = \"mastersos\" }",
                &format!("client_id = \"mastersos\"{extra} }}"),
                1,
            );
            Manifest::parse(&text).unwrap()
        };
        assert!(!features_used(&with("")).contains(&FEATURE_OIDC_CARD));
        let m = with(", card_hosts = [\"cdn.school.ac.th\"]");
        assert!(features_used(&m).contains(&FEATURE_OIDC_CARD));
        let m = with(", client_secret = \"s\"");
        assert_eq!(
            m.school.oidc.as_ref().unwrap().client_secret.as_deref(),
            Some("s")
        );
        assert!(features_used(&m).contains(&FEATURE_OIDC_CARD));
        // A provider without the new keys serializes as before: old Devices keep reading it.
        let plain = toml::to_string(&with("").school.oidc).unwrap();
        assert!(
            !plain.contains("client_secret") && !plain.contains("card_hosts"),
            "{plain}"
        );
    }

    const SCHOOL_A: &str = "0192f3a4-5b6c-7d8e-9f00-112233445566";
    const SCHOOL_B: &str = "0192f3a4-5b6c-7d8e-9f00-aabbccddeeff";

    /// Plan 6 Task 10b: `[school] id` is the school's UUID in canonical lowercase text.
    #[test]
    fn manifest_school_id_parses() {
        let with =
            |id: &str| example().replacen("[school]", &format!("[school]\nid = \"{id}\""), 1);
        let m = Manifest::parse(&with(SCHOOL_A)).unwrap();
        assert_eq!(m.school.id.as_deref(), Some(SCHOOL_A));
        m.validate(&present()).unwrap();
        assert_eq!(Manifest::parse(&example()).unwrap().school.id, None);
        assert_eq!(School::default().id, None);
        for bad in [
            "",
            "school-a",
            "0192F3A4-5B6C-7D8E-9F00-112233445566",
            "0192f3a45b6c7d8e9f00112233445566",
            "0192f3a4-5b6c-7d8e-9f00-1122334455667",
            "0192f3a4_5b6c-7d8e-9f00-112233445566",
            "0192f3a4-5b6c-7d8e-9f00-11223344556g",
        ] {
            assert!(
                matches!(Manifest::parse(&with(bad)), Err(BundleError::Parse(e)) if e.contains("lowercase UUID")),
                "{bad:?}"
            );
        }
        let not_a_string = example().replacen("[school]", "[school]\nid = 7", 1);
        assert!(matches!(
            Manifest::parse(&not_a_string),
            Err(BundleError::Parse(_))
        ));
        assert!(valid_school_id(SCHOOL_A));
        assert!(!valid_school_id(&SCHOOL_A.to_uppercase()));
    }

    /// Plan 6 Task 10b: a seed with a school accepts only bundles naming it; a seed without one
    /// (before plan 6) accepts any.
    #[test]
    fn check_school_binds_bundle_to_seed() {
        let mut m = Manifest::parse(&example()).unwrap();
        check_school(&m, None).unwrap();
        assert_eq!(
            check_school(&m, Some(SCHOOL_A)),
            Err(BundleError::OtherSchool)
        );
        m.school.id = Some(SCHOOL_A.into());
        check_school(&m, None).unwrap();
        check_school(&m, Some(SCHOOL_A)).unwrap();
        assert_eq!(
            check_school(&m, Some(SCHOOL_B)),
            Err(BundleError::OtherSchool)
        );
        assert_eq!(BundleError::OtherSchool.to_string(), OTHER_SCHOOL);
    }

    /// A manifest without the new keys parses and validates exactly as before: the new fields are
    /// absent, and nothing else about it moves.
    #[test]
    fn old_manifest_without_new_fields_unchanged() {
        // 样例里的锁定应用（计划 9）也是新键：去掉那两行才是「旧清单」。
        let legacy = crate::testutil::legacy_spec_example();
        let old: String = legacy
            .lines()
            .filter(|l| *l != "[group.apps.kiosk]" && !l.starts_with("nwea = "))
            .map(|l| format!("{l}\n"))
            .collect();
        assert_ne!(old.len(), legacy.len());
        let m = Manifest::parse(&old).unwrap();
        assert_eq!(m.shape, Shape::Legacy);
        assert!(m.configs.iter().all(|g| g.apps.kiosk.is_empty()));
        assert!(m.school.escrow_recipients.is_empty());
        m.validate(&present()).unwrap();
        assert!(features_used(&m).is_empty());
        assert!(School::default().escrow_recipients.is_empty());
        // No lint about the new keys either.
        let lints = crate::lint(&m, &present());
        assert!(
            lints.iter().all(|l| !l.code.starts_with("escrow")),
            "{lints:?}"
        );
    }

    #[test]
    fn group_defaults() {
        let m = Manifest::parse(&example()).unwrap();
        let g = &m.effective_of_group("default").unwrap();
        assert!(g.login_methods.is_empty() && g.wifi.is_empty() && g.files.is_empty());
        assert_eq!(g.interface, Interface::Learning);
        assert!(!g.local_users_admin);
        let w = &m.configs[2];
        assert!(
            w.interface.is_none() && w.login_methods.is_none() && w.local_users_admin.is_none()
        );
        assert_eq!(m.school.update_channel, "stable");
        assert_eq!(DEFAULT_GROUP, "default");
    }

    fn codes(m: &Manifest, p: &BTreeSet<String>) -> Vec<&'static str> {
        m.validate_all(p).iter().map(|l| l.code).collect()
    }

    #[test]
    fn validate_all_collects_every_problem() {
        // No trust, duplicate group id, no default group, device pointing to a missing group.
        let text = example()
            .replacen("id = \"default\"", "id = \"teacher\"", 1)
            .replacen("group = \"cart-g3\"", "group = \"nope\"", 1);
        let mut m = Manifest::parse(&text).unwrap();
        m.trust.clear();
        assert_eq!(
            codes(&m, &present()),
            [
                "trust_empty",
                "group_duplicate_id",
                "default_group_missing",
                "device_unknown_group"
            ]
        );
        let lints = m.validate_all(&present());
        assert!(lints.iter().all(|l| l.level == crate::LintLevel::Error));
        assert_eq!(lints[0], trust_empty_lint());
        assert_eq!(lints[1].path.as_deref(), Some("group.teacher"));
        assert_eq!(lints[1].params["id"], "teacher");
        assert_eq!(lints[2].path.as_deref(), Some("group"));
        assert_eq!(lints[3].path.as_deref(), Some("device[0].group"));
        assert_eq!(lints[3].params["group"], "nope");
    }

    #[test]
    fn validate_all_paths_and_params() {
        // Every group-level problem at once, each at its own path.
        let text = example()
            .replacen("files/wallpaper-teacher.jpg", "files/x.jpg", 1)
            .replacen("/usr/share/backgrounds/school.jpg", "etc/x", 1)
            .replacen("scripts/setup-scanner.sh", "files/a.sh", 1)
            .replacen(
                "when = \"login\" }",
                "when = \"login\", timeout_secs = 99999 }",
                1,
            )
            .replacen(&"a".repeat(64), &"A".repeat(64), 1)
            .replacen("/opt/a.deb", "opt/a.deb", 1)
            .replacen("serial = \"XYZ9876\"", "serial = \"abc1234\"", 1);
        let m = Manifest::parse(&text).unwrap();
        let mut p = present();
        p.insert("files/a.sh".into());
        p.insert("files/q".into());
        p.insert("files/q/r".into());
        let lints = m.validate_all(&p);
        let got: Vec<_> = lints
            .iter()
            .map(|l| (l.code, l.path.as_deref().unwrap_or("")))
            .collect();
        assert_eq!(
            got,
            [
                ("file_missing", "config.teacher.files[0].src"),
                ("dest_not_absolute", "config.teacher.files[0].dest"),
                ("file_outside_dir", "config.teacher.scripts[0].path"),
                (
                    "script_timeout_too_long",
                    "config.teacher.scripts[0].timeout_secs"
                ),
                ("download_sha256_invalid", "config.cart.downloads[0].sha256"),
                ("dest_not_absolute", "config.cart.downloads[0].dest"),
                ("path_file_and_dir", ""),
                ("device_duplicate_id", "device[1]"),
            ]
        );
        assert_eq!(lints[0].params["path"], "files/x.jpg");
        assert_eq!(lints[1].params["dest"], "etc/x");
        assert_eq!(lints[2].params["dir"], "scripts/");
        assert_eq!(lints[3].params["max"], MAX_SCRIPT_TIMEOUT_SECS.to_string());
        assert_eq!(lints[4].params["url"], "https://example.com/a.deb");
        assert_eq!(lints[6].params["file"], "files/q");
        assert_eq!(lints[6].params["child"], "files/q/r");
        assert_eq!(lints[7].params["kind"], "serial");
        assert_eq!(lints[7].params["value"], "abc1234");
    }

    #[test]
    fn validate_all_trust_problems() {
        let mut m = Manifest::parse(&example()).unwrap();
        m.trust.push(m.trust[0].clone());
        m.trust.push(TrustKey {
            id: "short".into(),
            alg: KeyAlg::Ed25519,
            public_key: "AAAA".into(),
            rp_id: Some("school.ac.th".into()),
        });
        m.trust.push(TrustKey {
            id: "phone".into(),
            alg: KeyAlg::WebauthnEs256,
            public_key: KEY.into(),
            rp_id: Some("School.ac.th".into()),
        });
        let lints = m.validate_all(&present());
        let got: Vec<_> = lints
            .iter()
            .map(|l| (l.code, l.params["id"].as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("trust_duplicate_id", "school-2026"),
                ("trust_key_invalid", "short"),
                ("trust_rp_id_forbidden", "short"),
                ("trust_key_invalid", "phone"),
                ("trust_rp_id_invalid", "phone"),
            ]
        );
        assert!(lints.iter().all(|l| l.path.as_deref() == Some("trust")));
    }

    #[test]
    fn validate_all_device_without_identity() {
        let text = example().replacen("serial = \"ABC1234\"\n", "", 1);
        let m = Manifest::parse(&text).unwrap();
        let lints = m.validate_all(&present());
        assert_eq!(lints.len(), 1, "{lints:?}");
        assert_eq!(lints[0].code, "device_no_identity");
        assert_eq!(lints[0].path.as_deref(), Some("device[0]"));
    }

    /// Every manifest this file's tests build, valid and invalid, with its `present` set.
    fn fixtures() -> Vec<(String, Manifest, BTreeSet<String>)> {
        let mut out = Vec::new();
        let mut push = |label: &str, m: Manifest, p: BTreeSet<String>| {
            out.push((label.to_string(), m, p));
        };
        let base = || Manifest::parse(&example()).unwrap();
        let edited = |from: &str, to: &str| {
            let text = example();
            assert!(text.contains(from), "{from:?}");
            Manifest::parse(&text.replacen(from, to, 1)).unwrap()
        };
        push("spec example", base(), present());
        for (from, to) in [
            ("id = \"default\"", "id = \"other\""),
            ("id = \"cart-g3\"", "id = \"default\""),
            ("id = \"cart-g3\"", "id = \"teacher\""),
            ("group = \"cart-g3\"", "group = \"nope\""),
            ("serial = \"XYZ9876\"", "serial = \"abc1234 \""),
            ("serial = \"XYZ9876\"\n", "serial = \"  \"\n"),
            ("serial = \"ABC1234\"\n", ""),
            ("files/wallpaper-teacher.jpg", "files/x.jpg"),
            ("/usr/share/backgrounds/school.jpg", "etc/x"),
            ("/opt/a.deb", "opt/a.deb"),
            (KEY, "AAAA"),
            (
                "alg = \"ed25519\"",
                "alg = \"ed25519\"\nrp_id = \"school.ac.th\"",
            ),
        ] {
            push(&format!("{from:?} -> {to:?}"), edited(from, to), present());
        }
        let good = "a".repeat(64);
        for bad in ["a".repeat(63), "A".repeat(64), "g".repeat(64)] {
            push(&format!("sha256 {bad}"), edited(&good, &bad), present());
        }
        let mut p = present();
        p.insert("files/a.sh".into());
        push(
            "script outside scripts/",
            edited("scripts/setup-scanner.sh", "files/a.sh"),
            p,
        );
        let mut p = present();
        p.insert("files/a".into());
        p.insert("files/a-b".into());
        push("prefix only", base(), p.clone());
        p.insert("files/a/b".into());
        push("file and dir", base(), p);
        for t in [
            MAX_SCRIPT_TIMEOUT_SECS,
            MAX_SCRIPT_TIMEOUT_SECS + 1,
            i64::MAX as u64,
        ] {
            let m = edited(
                "when = \"login\" }",
                &format!("when = \"login\", timeout_secs = {t} }}"),
            );
            push(&format!("timeout {t}"), m, present());
        }
        let mut m = base();
        m.trust.clear();
        push("empty trust", m, present());
        let mut m = base();
        m.trust.push(m.trust[0].clone());
        push("duplicate trust", m, present());
        let mut m = base();
        m.trust[0].rp_id = Some("school.ac.th".into());
        push("ed25519 rp_id", m, present());
        let mut compressed = vec![0x02u8];
        compressed.extend_from_slice(&[1u8; 64]);
        let passkeys: Vec<(Option<&str>, String)> = vec![
            (Some("school.ac.th"), p256_point()),
            (Some("localhost"), p256_point()),
            (None, p256_point()),
            (Some(""), p256_point()),
            (Some("School.ac.th"), p256_point()),
            (Some("https://school.ac.th"), p256_point()),
            (Some("school.ac.th"), KEY.to_string()),
            (Some("school.ac.th"), STANDARD.encode([4u8; 64])),
            (Some("school.ac.th"), STANDARD.encode(compressed)),
            (Some("school.ac.th"), "不是 base64".to_string()),
        ];
        for (rp, pk) in passkeys {
            let mut m = base();
            m.trust.push(TrustKey {
                id: "it-phone".into(),
                alg: KeyAlg::WebauthnEs256,
                public_key: pk.clone(),
                rp_id: rp.map(String::from),
            });
            push(&format!("passkey {rp:?} {pk}"), m, present());
        }
        // Multi-error fixtures.
        let mut m = edited("id = \"default\"", "id = \"teacher\"");
        m.trust.clear();
        m.devices[0].group = "nope".into();
        push("many problems", m, present());
        let mut m = edited("files/wallpaper-teacher.jpg", "files/x.jpg");
        m.configs[1].downloads[0].sha256 = "x".into();
        m.devices[1].serial = None;
        push("group and device problems", m, present());
        // Config problems (new shape) and the legacy shape.
        push(
            "config duplicate",
            edited("id = \"standard\"", "id = \"cart\""),
            present(),
        );
        push(
            "unknown config",
            edited("config = \"cart\"", "config = \"nope\""),
            present(),
        );
        let legacy = Manifest::parse(&crate::testutil::legacy_spec_example()).unwrap();
        push("legacy example", legacy, present());
        out
    }

    #[test]
    fn validate_matches_first_of_validate_all() {
        let mut valid = 0;
        for (label, m, p) in fixtures() {
            let all = m.validate_all(&p);
            match m.validate(&p) {
                Ok(()) => {
                    assert!(all.is_empty(), "{label}: {all:?}");
                    valid += 1;
                }
                Err(BundleError::Invalid(msg)) => {
                    assert_eq!(
                        all.first().map(|l| l.message.as_str()),
                        Some(msg.as_str()),
                        "{label}"
                    );
                }
                Err(e) => panic!("{label}: {e:?}"),
            }
        }
        assert!(valid >= 4, "{valid}");
    }

    // ---- Config profiles (2026-10-28 design §3, §3.1) ----

    const NEW_SHAPE: &str = r#"
version = 1
[[config]]
id = "student"
name = "Student"
login_methods = ["guest"]
[config.apps]
flatpak = ["org.libreoffice.LibreOffice"]
[[config]]
id = "teacher"
name = "Teacher"
interface = "full"
[[group]]
id = "cart-g3"
name = "Grade 3 cart"
config = "student"
[[group]]
id = "cart-g4"
name = "Grade 4 cart"
config = "student"
[[group]]
id = "default"
name = "Ungrouped"
config = "teacher"
"#;

    fn parse_code(text: &str) -> &'static str {
        crate::check::parse_issue(text).unwrap_err().code
    }

    #[test]
    fn shape_new_parses() {
        let m = Manifest::parse(NEW_SHAPE).unwrap();
        assert_eq!(m.shape, Shape::New);
        assert_eq!(m.configs.len(), 2);
        assert_eq!(m.config_of_group("cart-g4").unwrap().id, "student");
        assert_eq!(m.config_of_group("cart-g3").unwrap().id, "student");
        assert_eq!(m.config_of_group("default").unwrap().id, "teacher");
        assert!(m.config_of_group("nope").is_none());
        assert_eq!(m.config("student").unwrap().interface, None);
        assert_eq!(
            m.effective_of_group("cart-g3").unwrap().interface,
            Interface::Learning
        );
        assert_eq!(
            m.config("teacher").unwrap().interface,
            Some(Interface::Full)
        );
        assert!(m.configs.iter().all(|c| !c.legacy_browser));
        assert!(features_used(&m).contains(&FEATURE_CONFIG));
        assert_eq!(FEATURE_CONFIG, "config");
        assert_eq!(codes(&m, &BTreeSet::new()), ["trust_empty"]);
    }

    #[test]
    fn shape_legacy_browser_expands() {
        let m = Manifest::parse(
            "version = 1\n[[group]]\nid = \"cart\"\nname = \"Cart\"\nmode = \"browser\"\n\
             apps.flatpak = [\"org.x.Y\"]\n",
        )
        .unwrap();
        assert_eq!(m.shape, Shape::Legacy);
        assert_eq!(m.configs.len(), 1);
        let c = &m.configs[0];
        assert_eq!((c.id.as_str(), c.name.as_str()), ("cart", "Cart"));
        assert_eq!(c.interface, Some(Interface::Learning));
        assert!(c.legacy_browser);
        assert_eq!(c.apps.flatpak, ["org.x.Y"]);
        assert_eq!(m.groups[0].config, "cart");
        assert_eq!(m.groups[0].name, "Cart");
        assert!(!features_used(&m).contains(&FEATURE_CONFIG));
    }

    #[test]
    fn shape_legacy_default_mode_is_legacy_browser() {
        let m =
            Manifest::parse("version = 1\n[[group]]\nid = \"default\"\nname = \"d\"\n").unwrap();
        assert_eq!(m.shape, Shape::Legacy);
        assert_eq!(m.configs[0].interface, Some(Interface::Learning));
        assert!(m.configs[0].legacy_browser);
        assert_eq!(m.groups[0].config, "default");
    }

    #[test]
    fn shape_legacy_desktop_is_full() {
        let m = Manifest::parse(
            "version = 1\n[[group]]\nid = \"default\"\nname = \"d\"\nmode = \"desktop\"\n",
        )
        .unwrap();
        assert_eq!(m.shape, Shape::Legacy);
        assert_eq!(m.configs[0].interface, Some(Interface::Full));
        assert!(!m.configs[0].legacy_browser);
    }

    #[test]
    fn shape_legacy_and_new_expand_to_the_same_structure() {
        let legacy = Manifest::parse(&crate::testutil::legacy_spec_example()).unwrap();
        let new = Manifest::parse(&example()).unwrap();
        assert_eq!(legacy.shape, Shape::Legacy);
        assert_eq!(new.shape, Shape::New);
        // The new example names its configs differently; compare what each group gets.
        for g in &legacy.groups {
            let old = legacy.effective_of_group(&g.id).unwrap();
            let now = new.effective_of_group(&g.id).unwrap();
            let strip = |c: Config| Config {
                id: String::new(),
                name: String::new(),
                legacy_browser: false,
                ..c.clone()
            };
            assert_eq!(strip(old), strip(now), "{}", g.id);
        }
        assert_eq!(legacy.devices, new.devices);
        assert_eq!(legacy.school, new.school);
    }

    #[test]
    fn shape_mixed_rejected() {
        let text = format!(
            "{NEW_SHAPE}[[group]]\nid = \"lab\"\nname = \"Lab\"\n\
             apps.web = [{{ name = \"a\", url = \"https://a.example\" }}]\n"
        );
        assert!(matches!(Manifest::parse(&text), Err(BundleError::Parse(_))));
        let e = crate::check::parse_issue(&text).unwrap_err();
        assert_eq!(e.code, "config_shape_mixed");
        assert_eq!(e.params["group"], "lab");
        let lab = text.lines().position(|l| l == "id = \"lab\"").unwrap() as u32;
        assert_eq!(e.span.unwrap().line, lab, "points at the [[group]] header");
        // A group that names a config next to one that carries settings, no [[config]] at all.
        let text = "version = 1\n[[group]]\nid = \"default\"\nname = \"d\"\nconfig = \"x\"\n\
                    [[group]]\nid = \"b\"\nname = \"b\"\nmode = \"desktop\"\n";
        assert_eq!(parse_code(text), "config_shape_mixed");
    }

    #[test]
    fn typo_in_new_shape_group_is_unknown_field_not_mixed() {
        let text =
            format!("{NEW_SHAPE}[[group]]\nid = \"lab\"\nnmae = \"Lab\"\nconfig = \"student\"\n");
        let e = crate::check::parse_issue(&text).unwrap_err();
        assert_eq!(e.code, "unknown_field");
        assert_eq!(e.params["field"], "nmae");
    }

    #[test]
    fn mixed_message_has_one_wording() {
        let text = format!("{NEW_SHAPE}[[group]]\nid = \"lab\"\nname = \"Lab\"\nwifi = []\n");
        let lint = crate::check::parse_issue(&text).unwrap_err();
        let Err(BundleError::Parse(msg)) = Manifest::parse(&text) else {
            panic!("mixed text parsed");
        };
        assert_eq!(lint.message, msg);
        // A mixed group without an id still has a path.
        let text = format!("{NEW_SHAPE}[[group]]\nname = \"Lab\"\nwifi = []\n");
        let lint = crate::check::parse_issue(&text).unwrap_err();
        assert_eq!(lint.code, "config_shape_mixed");
        assert_eq!(lint.path.as_deref(), Some("group"));
    }

    #[test]
    fn new_shape_rejects_mode_key() {
        let text = NEW_SHAPE.replacen("interface = \"full\"", "mode = \"desktop\"", 1);
        assert_eq!(parse_code(&text), "unknown_field");
        assert!(matches!(Manifest::parse(&text), Err(BundleError::Parse(_))));
    }

    #[test]
    fn legacy_shape_rejects_interface_key() {
        let text = "version = 1\n[[group]]\nid = \"default\"\nname = \"d\"\ninterface = \"full\"\n";
        assert_eq!(parse_code(text), "unknown_field");
    }

    #[test]
    fn interface_create_rejected() {
        let text = NEW_SHAPE.replacen("interface = \"full\"", "interface = \"create\"", 1);
        assert_eq!(parse_code(&text), "invalid_value");
    }

    #[test]
    fn group_needs_config_key_in_new_shape() {
        let text = format!("{NEW_SHAPE}[[group]]\nid = \"lab\"\nname = \"Lab\"\n");
        assert_eq!(parse_code(&text), "missing_field");
    }

    #[test]
    fn group_unknown_config() {
        let m =
            Manifest::parse(&NEW_SHAPE.replacen("config = \"teacher\"", "config = \"staff\"", 1))
                .unwrap();
        let lints = m.validate_all(&BTreeSet::new());
        let l: Vec<_> = lints.iter().filter(|l| l.code != "trust_empty").collect();
        assert_eq!(l.len(), 1, "{lints:?}");
        assert_eq!(l[0].code, "group_unknown_config");
        assert_eq!(l[0].path.as_deref(), Some("group.default.config"));
        assert_eq!(l[0].params["group"], "default");
        assert_eq!(l[0].params["config"], "staff");
    }

    #[test]
    fn config_duplicate_id() {
        let m = Manifest::parse(&NEW_SHAPE.replacen("id = \"teacher\"", "id = \"student\"", 1))
            .unwrap();
        let codes: Vec<_> = m
            .validate_all(&BTreeSet::new())
            .into_iter()
            .filter(|l| l.code != "trust_empty")
            .map(|l| (l.code, l.path))
            .collect();
        assert_eq!(
            codes,
            [
                ("config_duplicate_id", Some("config.student".to_string())),
                ("group_unknown_config", Some("group.default.config".into())),
            ]
        );
        // The legacy shape reports a repeated group id once, not again for its implied config.
        let legacy = Manifest::parse(
            "version = 1\n[[group]]\nid = \"default\"\nname = \"a\"\n\
             [[group]]\nid = \"default\"\nname = \"b\"\n",
        )
        .unwrap();
        let codes: Vec<_> = legacy
            .validate_all(&BTreeSet::new())
            .into_iter()
            .map(|l| l.code)
            .collect();
        assert_eq!(codes, ["trust_empty", "group_duplicate_id"]);
    }

    #[test]
    fn default_group_missing_new_shape() {
        let m =
            Manifest::parse(&NEW_SHAPE.replacen("id = \"default\"", "id = \"staff\"", 1)).unwrap();
        let codes: Vec<_> = m
            .validate_all(&BTreeSet::new())
            .into_iter()
            .map(|l| l.code)
            .collect();
        assert_eq!(codes, ["trust_empty", "default_group_missing"]);
    }

    #[test]
    fn config_unused_is_info() {
        let text = NEW_SHAPE.replacen("config = \"teacher\"", "config = \"student\"", 1);
        let m = Manifest::parse(&text).unwrap();
        assert_eq!(codes(&m, &BTreeSet::new()), ["trust_empty"]);
        let l: Vec<_> = crate::lint(&m, &BTreeSet::new())
            .into_iter()
            .filter(|l| l.code == "config_unused")
            .collect();
        assert_eq!(l.len(), 1, "{l:?}");
        assert_eq!(l[0].level, LintLevel::Info);
        assert_eq!(l[0].path.as_deref(), Some("config.teacher"));
        assert_eq!(l[0].params["config"], "teacher");
    }

    #[test]
    fn legacy_shape_is_error_in_check() {
        let today = chrono::NaiveDate::from_ymd_opt(2026, 11, 2).unwrap();
        let legacy = crate::testutil::legacy_spec_example();
        let c = crate::check::check_text(&legacy, &present(), today);
        assert!(c.manifest.is_some(), "parse itself succeeds");
        let l: Vec<_> = c
            .issues
            .iter()
            .filter(|l| l.code == "legacy_shape")
            .collect();
        assert_eq!(l.len(), 1, "{:?}", c.issues);
        assert_eq!(l[0].level, LintLevel::Error);
        assert_eq!(l[0].path.as_deref(), Some("group"));
        assert!(l[0].span.is_some());
        // The new shape has none.
        let c = crate::check::check_text(&example(), &present(), today);
        assert!(
            c.issues.iter().all(|l| l.code != "legacy_shape"),
            "{:?}",
            c.issues
        );
        // Config-level issues of a legacy text are still placed, at the [[group]] they came from.
        let bad = legacy.replacen("files/wallpaper-teacher.jpg", "files/x.jpg", 1);
        let c = crate::check::check_text(&bad, &present(), today);
        let missing = c.issues.iter().find(|l| l.code == "file_missing").unwrap();
        assert_eq!(missing.path.as_deref(), Some("config.teacher.files[0].src"));
        let line = bad.lines().position(|l| l.contains("files/x.jpg")).unwrap() as u32 + 1;
        assert_eq!(missing.span.unwrap().line, line);
    }

    #[test]
    fn config_legacy_browser_is_not_serialized() {
        let m =
            Manifest::parse("version = 1\n[[group]]\nid = \"default\"\nname = \"d\"\n").unwrap();
        let v = serde_json::to_value(&m.configs[0]).unwrap();
        assert!(v.get("legacy_browser").is_none(), "{v}");
        assert_eq!(v["interface"], "learning");
        assert_eq!(
            serde_json::to_value(&m.groups[0]).unwrap(),
            serde_json::json!({ "id": "default", "name": "d", "config": "default" })
        );
    }

    #[test]
    fn flatpak_now_installed_after_leaving_browser_mode() {
        let prev = Manifest::parse(
            "version = 1\n[[group]]\nid = \"cart\"\nname = \"c\"\nmode = \"browser\"\n\
             apps.flatpak = [\"org.libreoffice.LibreOffice\"]\n\
             [[group]]\nid = \"default\"\nname = \"d\"\nmode = \"desktop\"\n\
             apps.flatpak = [\"org.gnome.Calculator\"]\n",
        )
        .unwrap();
        let next = Manifest::parse(
            "version = 2\n[[config]]\nid = \"cart\"\nname = \"c\"\n\
             apps.flatpak = [\"org.libreoffice.LibreOffice\"]\n\
             [[config]]\nid = \"default\"\nname = \"d\"\ninterface = \"full\"\n\
             apps.flatpak = [\"org.gnome.Calculator\"]\n\
             [[group]]\nid = \"cart\"\nname = \"c\"\nconfig = \"cart\"\n\
             [[group]]\nid = \"default\"\nname = \"d\"\nconfig = \"default\"\n",
        )
        .unwrap();
        let l = crate::flatpak_now_installed(&prev, &next);
        assert_eq!(l.len(), 1, "{l:?}");
        assert_eq!(l[0].code, "flatpak_now_installed");
        assert_eq!(l[0].level, LintLevel::Warning);
        assert_eq!(l[0].path.as_deref(), Some("config.cart.apps.flatpak"));
        assert_eq!(l[0].params["config"], "cart");
        // Same shape on both sides, an empty list, or no such config: nothing.
        assert!(crate::flatpak_now_installed(&prev, &prev).is_empty());
        assert!(crate::flatpak_now_installed(&next, &next).is_empty());
        let mut empty = next.clone();
        empty.configs[0].apps.flatpak.clear();
        assert!(crate::flatpak_now_installed(&prev, &empty).is_empty());
        assert_eq!(l[0].params["groups"], "cart");
        // The group points at no config any more: nothing to install.
        let mut dangling = next.clone();
        dangling.configs[0].id = "student".into();
        assert!(crate::flatpak_now_installed(&prev, &dangling).is_empty());
        // The browser-mode group is re-pointed at another config that installs Flatpaks.
        let repointed = Manifest::parse(
            "version = 2\n[[config]]\nid = \"student\"\nname = \"s\"\n\
             apps.flatpak = [\"org.gnome.Calculator\"]\n\
             [[config]]\nid = \"default\"\nname = \"d\"\ninterface = \"full\"\n\
             apps.flatpak = [\"org.gnome.Calculator\"]\n\
             [[group]]\nid = \"cart\"\nname = \"c\"\nconfig = \"student\"\n\
             [[group]]\nid = \"default\"\nname = \"d\"\nconfig = \"default\"\n",
        )
        .unwrap();
        let l = crate::flatpak_now_installed(&prev, &repointed);
        assert_eq!(l.len(), 1, "{l:?}");
        assert_eq!(l[0].path.as_deref(), Some("config.student.apps.flatpak"));
        assert_eq!(l[0].params["config"], "student");
        assert_eq!(l[0].params["groups"], "cart");
        assert!(l[0].message.contains("cart"), "{}", l[0].message);
    }

    /// A new-shape manifest whose `[school]` gets `school` and whose one Config gets `config`.
    fn wifi_manifest(school: &str, config: &str) -> Manifest {
        Manifest::parse(&format!(
            "version = 1\n[school]\n{school}\n[[config]]\nid = \"c\"\nname = \"C\"\n{config}\n\
             [[group]]\nid = \"default\"\nname = \"D\"\nconfig = \"c\"\n"
        ))
        .unwrap()
    }

    fn net(ssid: &str) -> Wifi {
        Wifi {
            ssid: ssid.into(),
            ..Wifi::default()
        }
    }

    #[test]
    fn legacy_ssid_only_is_open_no_feature() {
        // The new shape and the legacy shape, each with an entry of only ssid (and hidden).
        let new = wifi_manifest("", "wifi = [{ ssid = \"x\", hidden = true }]");
        let legacy = Manifest::parse(
            "version = 1\n[[group]]\nid = \"default\"\nname = \"D\"\nwifi = [{ ssid = \"x\" }]\n",
        )
        .unwrap();
        for m in [&new, &legacy] {
            let w = &m.configs[0].wifi[0];
            assert_eq!(w.kind(), WifiKind::Open);
            assert!(!w.uses_ext_keys());
            assert!(!features_used(m).contains(&FEATURE_WIFI_EXT), "{m:?}");
        }
        assert_eq!(FEATURE_WIFI_EXT, "wifi_ext");
    }

    #[test]
    fn kind_inferred_from_fields() {
        let m = wifi_manifest(
            "",
            r#"wifi = [
  { ssid = "a", psk = "password1" },
  { ssid = "b", psk = "password1", wpa3_only = true },
  { ssid = "c", eap = "peap", identity = "i", password = "p", server_domain = "r.x" },
  { ssid = "d", open = true },
]"#,
        );
        let kinds: Vec<_> = m.configs[0].wifi.iter().map(Wifi::kind).collect();
        assert_eq!(
            kinds,
            [
                WifiKind::Personal { sae_only: false },
                WifiKind::Personal { sae_only: true },
                WifiKind::Enterprise(EapMethod::Peap),
                WifiKind::Open,
            ]
        );
        let w = &m.configs[0].wifi;
        assert_eq!(w[2].phase2_or_default(), Some(Phase2::Mschapv2));
        assert_eq!(w[0].phase2_or_default(), None);
        let mut ttls = w[2].clone();
        ttls.eap = Some(EapMethod::Ttls);
        ttls.phase2 = Some(Phase2::Pap);
        assert_eq!(ttls.phase2_or_default(), Some(Phase2::Pap));
        ttls.eap = Some(EapMethod::Tls);
        assert_eq!(ttls.phase2_or_default(), None);
        assert_eq!(
            Wifi::SECRET_FIELDS,
            ["psk", "password", "client_key", "client_key_password"]
        );
    }

    #[test]
    fn wifi_serializes_only_written_fields_and_debug_redacts_secrets() {
        let mut w = net("a");
        assert_eq!(toml::to_string(&w).unwrap(), "ssid = \"a\"\n");
        w.eap = Some(EapMethod::Tls);
        w.identity = Some("dev".into());
        w.client_key = Some("KEY-SECRET".into());
        w.client_key_password = Some("PASS-SECRET".into());
        w.password = Some("PW-SECRET".into());
        w.psk = Some("PSK-SECRET".into());
        let text = toml::to_string(&w).unwrap();
        assert!(text.contains("eap = \"tls\""), "{text}");
        assert!(
            !text.contains("hidden") && !text.contains("wpa3_only"),
            "{text}"
        );
        assert_eq!(toml::from_str::<Wifi>(&text).unwrap(), w);
        let dbg = format!("{w:?} {w:#?}");
        for secret in ["KEY-SECRET", "PASS-SECRET", "PW-SECRET", "PSK-SECRET"] {
            assert!(!dbg.contains(secret), "{dbg}");
        }
        assert!(dbg.contains("dev"));
    }

    #[test]
    fn school_wifi_then_config_override_by_ssid() {
        let mut m = wifi_manifest(
            "wifi = [{ ssid = \"A\", psk = \"aaaaaaaa\" }, { ssid = \"B\", open = true }]",
            "wifi = [{ ssid = \"A\", psk = \"zzzzzzzz\" }, { ssid = \"C\", open = true }]",
        );
        let got = eff(&m).wifi;
        let names: Vec<_> = got.iter().map(|w| w.ssid.as_str()).collect();
        assert_eq!(names, ["B", "A", "C"]);
        assert_eq!(got[1].psk.as_deref(), Some("zzzzzzzz"));
        // No Config networks: just the school's; no school networks: just the Config's.
        let school = m.school.wifi.clone();
        let own = std::mem::take(&mut m.configs[0].wifi);
        assert_eq!(eff(&m).wifi, school);
        m.configs[0].wifi = own.clone();
        m.school.wifi.clear();
        assert_eq!(eff(&m).wifi, own);
        assert!(School::default().wifi.is_empty());
    }

    /// `[school] wifi = []` is refused at parse like `escrow_recipients = []`: it adds nothing,
    /// yet older agents reject the key and `features_used` could not see it. Config lists may be
    /// empty (the key predates school Wi-Fi).
    #[test]
    fn empty_school_wifi_is_a_parse_error() {
        let text = "version = 1\n[school]\nwifi = []\n[[config]]\nid = \"c\"\nname = \"C\"\n\
                    wifi = []\n[[group]]\nid = \"default\"\nname = \"D\"\nconfig = \"c\"\n";
        match Manifest::parse(text) {
            Err(BundleError::Parse(e)) => {
                assert!(
                    e.contains("must not be empty: leave the key out instead"),
                    "{e}"
                )
            }
            other => panic!("wanted a parse error, got {other:?}"),
        }
        let ok = text.replacen("[school]\nwifi = []\n", "[school]\n", 1);
        assert!(Manifest::parse(&ok).unwrap().school.wifi.is_empty());
    }

    #[test]
    fn features_wifi_ext_on_school_wifi_or_ext_keys() {
        let school = wifi_manifest("wifi = [{ ssid = \"S\", psk = \"password1\" }]", "");
        assert_eq!(
            features_used(&school),
            [FEATURE_CONFIG, FEATURE_WIFI_EXT],
            "after FEATURE_CONFIG"
        );
        let open = wifi_manifest("", "wifi = [{ ssid = \"S\", open = true }]");
        assert!(features_used(&open).contains(&FEATURE_WIFI_EXT));
        let wpa3 = wifi_manifest(
            "",
            "wifi = [{ ssid = \"S\", psk = \"password1\", wpa3_only = true }]",
        );
        assert!(features_used(&wpa3).contains(&FEATURE_WIFI_EXT));
        // Final review I3: older agents reject the key itself, so a written `false` counts too
        // (and still means WPA2/WPA3 transition mode).
        let wpa3_false = wifi_manifest(
            "",
            "wifi = [{ ssid = \"S\", psk = \"password1\", wpa3_only = false }]",
        );
        assert!(features_used(&wpa3_false).contains(&FEATURE_WIFI_EXT));
        assert_eq!(
            wpa3_false.configs[0].wifi[0].kind(),
            WifiKind::Personal { sae_only: false }
        );
        assert!(toml::to_string(&wpa3_false.configs[0].wifi[0])
            .unwrap()
            .contains("wpa3_only = false"));
        let plain = wifi_manifest(
            "",
            "wifi = [{ ssid = \"S\", psk = \"password1\", hidden = true }, { ssid = \"T\" }]",
        );
        assert_eq!(features_used(&plain), [FEATURE_CONFIG]);
        let mut w = net("x");
        w.check_server = Some(true);
        assert!(w.uses_ext_keys());
    }

    // ---- Defaults, drop, it_account and format (phase B design §4, §10.4, §15) ----

    fn layered() -> Manifest {
        Manifest::parse(&crate::testutil::defaults_example()).unwrap()
    }

    /// A `format = 2` text with `defaults` in `[defaults]` and `config` in its one Config `c`,
    /// used by the `default` Group.
    fn layered_with(defaults: &str, config: &str) -> Manifest {
        Manifest::parse(&format!(
            "format = 2\nversion = 1\n[defaults]\n{defaults}\n[[config]]\nid = \"c\"\nname = \"C\"\n\
             {config}\n[[group]]\nid = \"default\"\nname = \"D\"\nconfig = \"c\"\n"
        ))
        .unwrap()
    }

    fn eff(m: &Manifest) -> Config {
        effective_config(m, &m.configs[0])
    }

    fn ssids(l: &[Wifi]) -> Vec<&str> {
        l.iter().map(|w| w.ssid.as_str()).collect()
    }

    fn dev_names(l: &[NetDevice]) -> Vec<&str> {
        l.iter().map(|d| d.name.as_str()).collect()
    }

    #[test]
    fn spec_example_teacher_and_student() {
        let m = layered();
        assert_eq!(m.format, 2);
        let t = effective_config(&m, m.config("teacher").unwrap());
        assert_eq!(t.interface, Interface::Full);
        assert_eq!(t.login_methods, [LoginMethod::Sso, LoginMethod::Guest]);
        assert_eq!(ssids(&t.wifi), ["Campus-IoT"]);
        assert_eq!(
            t.apps.flatpak,
            ["org.libreoffice.LibreOffice", "org.gimp.GIMP"]
        );
        assert!(t.printers.is_empty());
        let s = effective_config(&m, m.config("student").unwrap());
        assert_eq!((s.id.as_str(), s.name.as_str()), ("student", "Student"));
        assert_eq!(s.interface, Interface::Learning);
        assert_eq!(s.login_methods, [LoginMethod::Sso, LoginMethod::Guest]);
        assert_eq!(s.apps.flatpak, ["org.libreoffice.LibreOffice"]);
        assert_eq!(dev_names(&s.printers), ["Library"]);
        assert_eq!(ssids(&s.wifi), ["Campus-IoT"]);
        assert_eq!(m.effective_of_group("staff").unwrap(), t);
        assert_eq!(m.effective_of_group("default").unwrap(), s);
        assert!(m.effective_of_group("nope").is_none());
        assert_eq!(m.config_of_group("staff").unwrap().id, "teacher");
    }

    #[test]
    fn unwritten_single_value_inherits_defaults() {
        let d = "interface = \"full\"\nlocal_users_admin = true\nlogin_methods = [\"sso\"]";
        let c = eff(&layered_with(d, ""));
        assert_eq!(
            c.interface,
            Interface::Full,
            "not silently back to learning"
        );
        assert!(c.local_users_admin);
        assert_eq!(c.login_methods, [LoginMethod::Sso]);
        // Writing today's default value is writing it: it overrides; [] overrides to empty.
        let c = eff(&layered_with(
            d,
            "interface = \"learning\"\nlocal_users_admin = false\nlogin_methods = []",
        ));
        assert_eq!(c.interface, Interface::Learning);
        assert!(!c.local_users_admin);
        assert!(c.login_methods.is_empty());
        // Neither writes it: today's defaults.
        let c = eff(&layered_with("", ""));
        assert_eq!(c.interface, Interface::Learning);
        assert!(!c.local_users_admin && c.login_methods.is_empty());
        assert_eq!(c.it_account, None);
    }

    /// What a Config meant before Defaults: single values default to `learning`, `[]`, `false`;
    /// the school's networks come first unless the Config lists the same SSID.
    fn old_expand(m: &Manifest, c: &ConfigLayer) -> Config {
        Config {
            id: c.id.clone(),
            name: c.name.clone(),
            interface: c.interface.unwrap_or_default(),
            login_methods: c.login_methods.clone().unwrap_or_default(),
            local_users_admin: c.local_users_admin.unwrap_or_default(),
            it_account: None,
            wifi: m
                .school
                .wifi
                .iter()
                .filter(|w| !c.wifi.iter().any(|o| o.ssid == w.ssid))
                .chain(&c.wifi)
                .cloned()
                .collect(),
            apps: c.apps.clone(),
            printers: c.printers.clone(),
            scanners: c.scanners.clone(),
            chrome_policy: c.chrome_policy.clone(),
            chrome: c.chrome.clone(),
            files: c.files.clone(),
            downloads: c.downloads.clone(),
            scripts: c.scripts.clone(),
            legacy_browser: c.legacy_browser,
        }
    }

    #[test]
    fn versions_without_defaults_expand_unchanged() {
        let school_wifi = wifi_manifest(
            "wifi = [{ ssid = \"A\", psk = \"aaaaaaaa\" }, { ssid = \"B\", open = true }]",
            "wifi = [{ ssid = \"A\", psk = \"zzzzzzzz\" }]\nlocal_users_admin = true",
        );
        let legacy = Manifest::parse(&crate::testutil::legacy_spec_example()).unwrap();
        let new = Manifest::parse(&example()).unwrap();
        for m in [&new, &legacy, &school_wifi] {
            assert!(m.defaults.is_none());
            assert_eq!(m.format, 1);
            for c in &m.configs {
                assert_eq!(effective_config(m, c), old_expand(m, c), "{}", c.id);
            }
        }
        // The legacy shape writes every single value of its implied Configs.
        assert!(legacy.configs.iter().all(|c| c.interface.is_some()
            && c.login_methods.is_some()
            && c.local_users_admin.is_some()
            && c.it_account.is_none()));
        let t = new.effective_of_group("teacher").unwrap();
        assert_eq!(t.interface, Interface::Full);
        assert_eq!(t.login_methods, [LoginMethod::Sso, LoginMethod::Local]);
        assert_eq!(ssids(&t.wifi), ["staff"]);
        assert_eq!(t, {
            let mut l = legacy.effective_of_group("teacher").unwrap();
            l.legacy_browser = false;
            l
        });
        assert!(legacy.effective_of_group("cart-g3").unwrap().legacy_browser);
        let c = eff(&school_wifi);
        assert_eq!(ssids(&c.wifi), ["B", "A"]);
        assert_eq!(c.wifi[1].psk.as_deref(), Some("zzzzzzzz"));
    }

    #[test]
    fn same_name_replaces_whole_entry_order_kept() {
        let m = layered_with(
            "wifi = [{ ssid = \"A\", psk = \"aaaaaaaa\", hidden = true }, { ssid = \"B\", open = true }]",
            "wifi = [{ ssid = \"A\", psk = \"zzzzzzzz\" }, { ssid = \"C\", open = true }]",
        );
        let c = eff(&m);
        assert_eq!(ssids(&c.wifi), ["B", "A", "C"]);
        assert_eq!(c.wifi[1].psk.as_deref(), Some("zzzzzzzz"));
        assert!(!c.wifi[1].hidden, "no field merge");
    }

    const EVERY_COLLECTION: &str = r#"wifi = [{ ssid = "W1", psk = "password1" }, { ssid = "W2", psk = "password2" }]
printers = [{ name = "P1", uri = "ipp://p1/ipp/print" }, { name = "P2", uri = "ipp://p2/ipp/print" }]
scanners = [{ name = "S1", uri = "http://s1/eSCL" }, { name = "S2", uri = "http://s2/eSCL" }]
files = [{ src = "files/a", dest = "/opt/a" }, { src = "files/b", dest = "/opt/b" }]
downloads = [{ url = "https://x.example/a", sha256 = "SHA", dest = "/opt/da" }, { url = "https://x.example/b", sha256 = "SHA", dest = "/opt/db" }]
scripts = [{ path = "scripts/a.sh" }, { path = "scripts/b.sh" }]
apps.web = [{ name = "Web1", url = "https://w1.example" }, { name = "Web2", url = "https://w2.example" }]
apps.flatpak = ["org.a.A", "org.b.B"]
apps.kiosk.k1 = { name = "K1", url = "https://k1.example" }
apps.kiosk.k2 = { name = "K2", url = "https://k2.example" }
chrome_policy.PolA = true
chrome_policy.PolB = 1
"#;

    #[test]
    fn drop_removes_by_key_in_every_collection() {
        let drop = r#"drop.wifi = ["W1"]
drop.printers = ["P1"]
drop.scanners = ["S1"]
drop.files = ["/opt/a"]
drop.downloads = ["/opt/da"]
drop.scripts = ["scripts/a.sh"]
drop.apps.web = ["Web1"]
drop.apps.flatpak = ["org.a.A"]
drop.apps.kiosk = ["k1"]
drop.chrome_policy = ["PolA"]
"#;
        let m = layered_with(EVERY_COLLECTION, drop);
        assert!(!m.configs[0].drop.is_empty());
        let c = eff(&m);
        assert_eq!(ssids(&c.wifi), ["W2"]);
        assert_eq!(dev_names(&c.printers), ["P2"]);
        assert_eq!(dev_names(&c.scanners), ["S2"]);
        let dests: Vec<_> = c.files.iter().map(|f| f.dest.as_str()).collect();
        assert_eq!(dests, ["/opt/b"]);
        let dests: Vec<_> = c.downloads.iter().map(|d| d.dest.as_str()).collect();
        assert_eq!(dests, ["/opt/db"]);
        let paths: Vec<_> = c.scripts.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(paths, ["scripts/b.sh"]);
        let web: Vec<_> = c.apps.web.iter().map(|w| w.name.as_str()).collect();
        assert_eq!(web, ["Web2"]);
        assert_eq!(c.apps.flatpak, ["org.b.B"]);
        assert_eq!(c.apps.kiosk.keys().collect::<Vec<_>>(), ["k2"]);
        assert_eq!(c.chrome_policy.keys().collect::<Vec<_>>(), ["PolB"]);
        // Nothing dropped: everything inherited; dropping a name Defaults lacks changes nothing.
        let all = eff(&layered_with(EVERY_COLLECTION, ""));
        assert_eq!(all.wifi.len(), 2);
        assert_eq!(all.apps.kiosk.len(), 2);
        assert_eq!(all.chrome_policy.len(), 2);
        let unknown = eff(&layered_with(
            EVERY_COLLECTION,
            "drop.printers = [\"Nope\"]\ndrop.apps.kiosk = [\"nope\"]",
        ));
        assert_eq!(unknown, all);
        assert!(Drop::default().is_empty());
    }

    #[test]
    fn own_map_entries_replace_inherited_keys() {
        let c = eff(&layered_with(
            EVERY_COLLECTION,
            "apps.kiosk.k1 = { name = \"Mine\", url = \"https://m.example\" }\nchrome_policy.PolB = 2",
        ));
        assert_eq!(c.apps.kiosk["k1"].name, "Mine");
        assert_eq!(c.apps.kiosk.len(), 2);
        assert_eq!(c.chrome_policy["PolB"].as_integer(), Some(2));
        assert_eq!(c.chrome_policy["PolA"].as_bool(), Some(true));
    }

    #[test]
    fn chrome_fields_and_it_account_are_single_values() {
        let d =
            "chrome.update_window = \"16:00-07:00\"\nit_account = { password_hash = \"$y$H1\" }";
        let c = eff(&layered_with(d, "chrome.pause_until = \"2026-11-20\""));
        assert_eq!(c.chrome.update_window.as_deref(), Some("16:00-07:00"));
        assert_eq!(c.chrome.pause_until.as_deref(), Some("2026-11-20"));
        assert_eq!(c.it_account.unwrap().password_hash, "$y$H1");
        let c = eff(&layered_with(
            d,
            "chrome.update_window = \"18:00-06:00\"\nit_account = { password_hash = \"$y$H2\" }",
        ));
        assert_eq!(c.chrome.update_window.as_deref(), Some("18:00-06:00"));
        assert_eq!(c.chrome.pause_until, None);
        assert_eq!(c.it_account.unwrap().password_hash, "$y$H2");
        assert_eq!(IT_ACCOUNT_USER, "itadmin");
        assert_eq!(ItAccount::SECRET_FIELDS, ["password_hash"]);
        let dbg = format!(
            "{:?}",
            ItAccount {
                password_hash: "$y$SECRET".into()
            }
        );
        assert!(
            !dbg.contains("SECRET") && dbg.contains("<redacted>"),
            "{dbg}"
        );
    }

    /// The minimal valid new-shape text, `format` and `[school]` lines spliced in.
    const PLAIN: &str = "version = 1\n[[config]]\nid = \"c\"\nname = \"C\"\n\
                         [[group]]\nid = \"default\"\nname = \"D\"\nconfig = \"c\"\n";

    #[test]
    fn format_values_and_gated_keys() {
        assert_eq!(Manifest::parse(PLAIN).unwrap().format, 1);
        assert_eq!(
            Manifest::parse(&format!("format = 1\n{PLAIN}"))
                .unwrap()
                .format,
            1
        );
        assert_eq!(
            Manifest::parse(&format!("format = 2\n{PLAIN}"))
                .unwrap()
                .format,
            2
        );
        for bad in ["0", "-1", "\"2\"", "3.0", "true"] {
            assert!(
                matches!(
                    Manifest::parse(&format!("format = {bad}\n{PLAIN}")),
                    Err(BundleError::Parse(_))
                ),
                "{bad}"
            );
        }
        let in_config =
            |k: &str| PLAIN.replacen("name = \"C\"\n", &format!("name = \"C\"\n{k}\n"), 1);
        let gated = [
            format!("{PLAIN}[defaults]\ninterface = \"full\"\n"),
            format!("{PLAIN}[defaults]\n"),
            in_config("drop.printers = [\"x\"]"),
            in_config("it_account = { password_hash = \"$y$x\" }"),
            format!("{PLAIN}[school]\nname = \"EIS\"\n"),
            format!("{PLAIN}[school]\nlogo_sha256 = \"{}\"\n", "a".repeat(64)),
            format!(
                "{PLAIN}[school]\nlogo_icon_sha256 = \"{}\"\n",
                "a".repeat(64)
            ),
        ];
        for text in &gated {
            for head in ["", "format = 1\n"] {
                match Manifest::parse(&format!("{head}{text}")) {
                    Err(BundleError::Parse(e)) => assert!(e.contains("format = 2"), "{e}"),
                    other => panic!("{head}{text}: wanted Parse, got {other:?}"),
                }
            }
            Manifest::parse(&format!("format = 2\n{text}")).unwrap();
            assert!(needs_format2(&text.parse().unwrap()), "{text}");
        }
        assert!(!needs_format2(&PLAIN.parse().unwrap()));
        let school_wifi = format!("{PLAIN}[[school.wifi]]\nssid = \"Guest\"\nopen = true\n");
        assert!(!needs_format2(&school_wifi.parse().unwrap()));
        let m = Manifest::parse(&format!("format = 2\n{}", gated[4])).unwrap();
        assert_eq!(m.school.name.as_deref(), Some("EIS"));
        assert_eq!(format_feature(2), "format_2");
        assert_eq!(format_feature(MAX_FORMAT), FEATURE_FORMAT_2);
        assert_eq!(MAX_FORMAT, 2);
    }

    #[test]
    fn newer_format_refused_before_unknown_keys() {
        let text =
            "format = 3\nversion = 1\n[future]\nx = 1\n[[config]]\nid = \"c\"\nshiny = true\n";
        let e = Manifest::parse(text).unwrap_err();
        assert_eq!(e, BundleError::FormatTooNew { found: 3, max: 2 });
        assert_eq!(
            e.to_string(),
            "these settings use format 3, newer than this OS understands (2); update the OS first"
        );
        assert_eq!(
            Manifest::parse(&format!("format = 99999999999\n{PLAIN}")).unwrap_err(),
            BundleError::FormatTooNew {
                found: u32::MAX,
                max: 2
            }
        );
        // The check path says the same instead of an unknown-field issue.
        let l = crate::check::parse_issue(text).unwrap_err();
        assert!(l.message.contains("update the OS"), "{l:?}");
        assert_eq!(l.level, LintLevel::Error);
    }

    #[test]
    fn format1_files_unchanged() {
        let school_wifi =
            format!("{PLAIN}[school]\nwifi = [{{ ssid = \"S\", psk = \"password1\" }}]\n");
        for text in [
            example(),
            crate::testutil::legacy_spec_example(),
            school_wifi.clone(),
            format!("format = 1\n{school_wifi}"),
        ] {
            let m = Manifest::parse(&text).unwrap();
            assert_eq!(m.format, 1);
            assert!(m.defaults.is_none());
            assert!(m
                .configs
                .iter()
                .all(|c| c.drop.is_empty() && c.it_account.is_none()));
        }
        let m = Manifest::parse(&school_wifi).unwrap();
        assert_eq!(ssids(&m.effective_of_group("default").unwrap().wifi), ["S"]);
    }

    #[test]
    fn school_wifi_is_front_of_defaults() {
        let m = Manifest::parse(
            "format = 2\nversion = 1\n\
             [school]\nwifi = [{ ssid = \"A\", psk = \"aaaaaaaa\" }, { ssid = \"B\", open = true }]\n\
             [defaults]\nwifi = [{ ssid = \"B\", psk = \"bbbbbbb2\" }, { ssid = \"C\", open = true }]\n\
             [[config]]\nid = \"c\"\nname = \"C\"\nwifi = [{ ssid = \"D\", open = true }]\n\
             [[group]]\nid = \"default\"\nname = \"D\"\nconfig = \"c\"\n",
        )
        .unwrap();
        let c = eff(&m);
        assert_eq!(ssids(&c.wifi), ["A", "B", "C", "D"]);
        assert_eq!(c.wifi[1].psk.as_deref(), Some("bbbbbbb2"));
        // drop applies to the school's networks too: they are part of the Defaults side.
        let mut m = m;
        m.configs[0].drop.wifi = vec!["A".into()];
        assert_eq!(ssids(&eff(&m).wifi), ["B", "C", "D"]);
    }

    #[test]
    fn features_wifi_ext_unchanged() {
        let school = wifi_manifest("wifi = [{ ssid = \"S\", psk = \"password1\" }]", "");
        assert!(features_used(&school).contains(&FEATURE_WIFI_EXT));
        let eap = layered_with(
            "wifi = [{ ssid = \"E\", eap = \"peap\", identity = \"i\", password = \"p\", server_domain = \"r.x\" }]",
            "",
        );
        assert!(features_used(&eap).contains(&FEATURE_WIFI_EXT));
        let plain = layered_with("wifi = [{ ssid = \"P\", psk = \"password1\" }]", "");
        assert_eq!(features_used(&plain), [FEATURE_CONFIG]);
        for m in [&school, &eap, &plain, &layered()] {
            assert!(!features_used(m).contains(&"config_defaults"));
        }
    }

    #[test]
    fn defaults_with_fat_legacy_group_is_mixed() {
        let text = "format = 2\nversion = 1\n[defaults]\ninterface = \"full\"\n\
                    [[group]]\nid = \"default\"\nname = \"d\"\nmode = \"desktop\"\n";
        match Manifest::parse(text) {
            Err(BundleError::Parse(e)) => assert!(e.contains("[[config]]"), "{e}"),
            other => panic!("wanted Parse, got {other:?}"),
        }
        assert_eq!(parse_code(text), "config_shape_mixed");
    }

    #[test]
    fn defaults_rejects_id_name_and_drop() {
        for k in ["id = \"x\"", "name = \"x\"", "drop.printers = [\"x\"]"] {
            let text = format!("format = 2\n{PLAIN}[defaults]\n{k}\n");
            assert!(
                matches!(Manifest::parse(&text), Err(BundleError::Parse(_))),
                "{k}"
            );
            assert_eq!(parse_code(&text), "unknown_field", "{k}");
        }
    }

    #[test]
    fn layers_serialize_only_written_keys() {
        let m = layered();
        let t = serde_json::to_value(m.config("teacher").unwrap()).unwrap();
        assert_eq!(t["interface"], "full");
        assert!(
            t.get("login_methods").is_none() && t.get("it_account").is_none(),
            "{t}"
        );
        assert_eq!(t["drop"], serde_json::json!({ "printers": ["Library"] }));
        let s = serde_json::to_value(m.config("student").unwrap()).unwrap();
        assert!(
            s.get("drop").is_none() && s.get("interface").is_none(),
            "{s}"
        );
        let d = serde_json::to_value(m.defaults.as_ref().unwrap()).unwrap();
        assert_eq!(
            d.as_object().unwrap().keys().collect::<Vec<_>>(),
            ["apps", "interface", "login_methods", "printers", "wifi"]
        );
        assert_eq!(
            serde_json::to_value(Defaults::default()).unwrap(),
            serde_json::json!({})
        );
        // A layer written back as TOML parses to the same layer.
        let back: ConfigLayer =
            toml::from_str(&toml::to_string(m.config("teacher").unwrap()).unwrap()).unwrap();
        assert_eq!(&back, m.config("teacher").unwrap());
    }

    /// Defaults' files, scripts and downloads reach every Device through `effective_config`, so
    /// `validate` (the Device's gate too) checks them like a Config's, at `defaults.…`.
    #[test]
    fn defaults_files_checked_by_validate() {
        let present: BTreeSet<String> = ["files/a.png".to_string(), "scripts/s.sh".to_string()]
            .into_iter()
            .collect();
        let issues = |defaults: &str| {
            let mut m = layered_with(defaults, "");
            m.trust = Manifest::parse(&example()).unwrap().trust;
            let all: Vec<_> = m
                .validate_all(&present)
                .into_iter()
                .map(|l| (l.code, l.path.unwrap_or_default()))
                .collect();
            assert_eq!(all.is_empty(), m.validate(&present).is_ok());
            all
        };
        for src in ["/etc/shadow", "../etc/shadow", "scripts/s.sh"] {
            assert_eq!(
                issues(&format!(
                    "files = [{{ src = \"{src}\", dest = \"/opt/x\" }}]"
                )),
                [("file_outside_dir", "defaults.files[0].src".to_string())],
                "{src}"
            );
        }
        assert_eq!(
            issues("files = [{ src = \"files/../../etc/shadow\", dest = \"/opt/x\" }]"),
            [("file_missing", "defaults.files[0].src".to_string())]
        );
        assert_eq!(
            issues("files = [{ src = \"files/a.png\", dest = \"opt/x\" }]"),
            [("dest_not_absolute", "defaults.files[0].dest".to_string())]
        );
        assert_eq!(
            issues("scripts = [{ path = \"/bin/sh\" }]"),
            [("file_outside_dir", "defaults.scripts[0].path".to_string())]
        );
        assert_eq!(
            issues("downloads = [{ url = \"https://x.example/a\", sha256 = \"x\", dest = \"/opt/a\" }]"),
            [("download_sha256_invalid", "defaults.downloads[0].sha256".to_string())]
        );
        // Valid entries pass, and the message names the layer.
        assert!(issues(
            "files = [{ src = \"files/a.png\", dest = \"/opt/a.png\" }]\n\
             scripts = [{ path = \"scripts/s.sh\" }]"
        )
        .is_empty());
        let mut m = layered_with("files = [{ src = \"/etc/shadow\", dest = \"/opt/x\" }]", "");
        m.trust = Manifest::parse(&example()).unwrap().trust;
        match m.validate(&present) {
            Err(BundleError::Invalid(e)) => assert!(e.contains("in [defaults]"), "{e}"),
            other => panic!("wanted Invalid, got {other:?}"),
        }
    }
}
