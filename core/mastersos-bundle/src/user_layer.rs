//! Settings `format = 3`: the device layer and the user layer (user layer design §2, §3).
//!
//! A format 3 text is read into [`V3Manifest`] and converted into the existing [`Manifest`]: the
//! device layer becomes `defaults`/`configs` (so every reader of format 2 keeps working) and the
//! user layer becomes [`Manifest::user_layer`].

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::lint::{lint_app_formats, lint_deb_entries, lint_drop_sets, lint_web_app_entries};
use crate::lint::{DropOwner, DropSet};
use crate::manifest::*;
use crate::Lint;

/// What a user config lifts from the learning lock (design §2.3). Effective capabilities are
/// the preset's, plus `allow`, minus `deny` (deny wins).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// The terminal: lifts the terminal stubs, `disable-command-line` and the terminal
    /// keybinding. It defeats every other lock.
    Terminal,
    /// The file manager (Files) in the session and the Dash.
    FileManager,
    /// The system settings, including user administration.
    Settings,
    /// User GNOME extensions.
    Extensions,
    /// Every installed app, not only those in the Dash.
    AllApps,
    /// User Flatpaks and `~/.config/environment.d`.
    UserApps,
}

impl Capability {
    /// As written in the settings file.
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::Terminal => "terminal",
            Capability::FileManager => "file_manager",
            Capability::Settings => "settings",
            Capability::Extensions => "extensions",
            Capability::AllApps => "all_apps",
            Capability::UserApps => "user_apps",
        }
    }
}

/// A set of capabilities.
pub type Caps = BTreeSet<Capability>;

/// Every capability, in order: what preset `full` gives.
pub const ALL_CAPS: [Capability; 6] = [
    Capability::Terminal,
    Capability::FileManager,
    Capability::Settings,
    Capability::Extensions,
    Capability::AllApps,
    Capability::UserApps,
];

/// The starting point of a user config's capabilities: `learning` (none) or `full` (all).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum Preset {
    /// No capability: like a ChromeOS student laptop.
    #[default]
    Learning,
    /// Every capability: the full desktop.
    Full,
}

/// What happens to the home folder (design §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum HomeMode {
    /// The home folder is tidied (the default of preset `learning`).
    Tidy,
    /// The home folder is kept as the person left it (the default of preset `full`).
    Keep,
}

/// `apps` of a user config: what the person sees in the Dash.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct UserApps {
    /// Web apps: launchers that open a site in its own Chrome window.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub web: Vec<WebApp>,
    /// Flatpak app ids shown in the Dash; the Device installs the union over the user configs
    /// its Group can reach.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flatpak: Vec<String>,
    /// Third-party .deb apps (not kiosk) shown in the Dash, keyed by app id; installed like
    /// `flatpak`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub deb: BTreeMap<String, DebApp>,
}

impl UserApps {
    pub fn is_empty(&self) -> bool {
        self.web.is_empty() && self.flatpak.is_empty() && self.deb.is_empty()
    }
}

/// `drop.apps` of a user config: inherited apps to leave out.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct UserDropApps {
    /// Names of inherited web apps to leave out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub web: Vec<String>,
    /// Inherited Flatpak app ids to leave out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flatpak: Vec<String>,
    /// Keys (app ids) of inherited .deb apps to leave out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deb: Vec<String>,
}

impl UserDropApps {
    pub fn is_empty(&self) -> bool {
        self.web.is_empty() && self.flatpak.is_empty() && self.deb.is_empty()
    }
}

/// `drop` of a user config: entries inherited from `[user_defaults]` to leave out.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct UserDrop {
    /// Inherited apps to leave out.
    #[serde(default, skip_serializing_if = "UserDropApps::is_empty")]
    pub apps: UserDropApps,
    /// Names of inherited Chrome policies to leave out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chrome_policy: Vec<String>,
    /// `path`s of inherited login scripts to leave out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scripts: Vec<String>,
    /// Inherited `allow` capabilities to leave out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<Capability>,
    /// Inherited `deny` capabilities to leave out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<Capability>,
}

impl UserDrop {
    pub fn is_empty(&self) -> bool {
        self.apps.is_empty()
            && self.chrome_policy.is_empty()
            && self.scripts.is_empty()
            && self.allow.is_empty()
            && self.deny.is_empty()
    }
}

/// `[user_defaults]`: what every user config starts from; the keys of `[[user_config]]` without
/// `id`, `name` and `drop`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct UserDefaults {
    /// The preset every user config has unless it writes its own: `learning` or `full`.
    /// Absent: `learning`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<Preset>,
    /// Capabilities added to the preset.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<Capability>,
    /// Capabilities removed from the preset; deny wins over allow.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<Capability>,
    /// Apps every user config shows.
    #[serde(default, skip_serializing_if = "UserApps::is_empty")]
    pub apps: UserApps,
    /// Chrome managed policies every user config gets, by policy name, on top of the baseline.
    #[serde(default, skip_serializing_if = "toml::Table::is_empty")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "serde_json::Map<String, serde_json::Value>")
    )]
    pub chrome_policy: toml::Table,
    /// Login scripts (`when = "login"`) every user config runs as the person.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scripts: Vec<Script>,
    /// `tidy` or `keep`, unless a user config writes its own. Absent: follows the preset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home: Option<HomeMode>,
}

/// `[[user_config]]` as written: what a person sees and may do in their session, on top of
/// `[user_defaults]`. Rules name it by `id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct UserConfigLayer {
    /// The user config's id, unique among user configs; `[[assign]]` rules and `[user] fallback`
    /// name it.
    pub id: String,
    /// The name shown in the console.
    pub name: String,
    /// `learning` or `full`. Absent: the user defaults' preset, else `learning`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<Preset>,
    /// Capabilities added to the preset, after the user defaults' ones.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<Capability>,
    /// Capabilities removed from the preset, after the user defaults' ones; deny wins.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<Capability>,
    /// Apps shown, added to the user defaults' ones.
    #[serde(default, skip_serializing_if = "UserApps::is_empty")]
    pub apps: UserApps,
    /// Chrome managed policies, added to the user defaults' ones by policy name.
    #[serde(default, skip_serializing_if = "toml::Table::is_empty")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "serde_json::Map<String, serde_json::Value>")
    )]
    pub chrome_policy: toml::Table,
    /// Login scripts (`when = "login"`) run as the person.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scripts: Vec<Script>,
    /// `tidy` or `keep`. Absent: the user defaults' value, else follows the preset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home: Option<HomeMode>,
    /// Entries inherited from `[user_defaults]` this user config leaves out.
    #[serde(default, skip_serializing_if = "UserDrop::is_empty")]
    pub drop: UserDrop,
}

/// The kind of account signing in (rule condition `kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A school account through `[school.oidc]`.
    Sso,
    /// A local account on the Device.
    Local,
    /// The guest session.
    Guest,
}

/// The person's role in the organization, an issuer fact (rule condition `org_role`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum OrgRole {
    /// Owner of the organization.
    Owner,
    /// Administrator of the organization.
    Admin,
    /// Member of the organization.
    Member,
}

/// The person's role in at least one class, an issuer fact (rule condition `class_role`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum ClassRole {
    /// Teaches the class.
    Teacher,
    /// Assists in the class.
    Assistant,
    /// Studies in the class.
    Student,
}

/// The person's age band, an issuer fact (rule condition `age_band`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum AgeBand {
    /// Under 13 years old.
    #[serde(rename = "under13")]
    Under13,
    /// 13 to 17 years old.
    #[serde(rename = "13-17")]
    Teen,
    /// 18 years old or more.
    #[serde(rename = "18+")]
    Adult,
}

/// `[[assign]]`: a rule naming the user config of the people it matches (design §2.1). All
/// written conditions must hold; a list matches when any element does. First match wins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Assign {
    /// The id of the `[[user_config]]` the matched people get.
    pub user_config: String,
    /// Account kinds: `sso`, `local`, `guest`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<Vec<Kind>>,
    /// Whether the person is an administrator on the Device (`[school] admin_users`, `itadmin`,
    /// local accounts with `local_users_admin`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<bool>,
    /// Local user names (login names).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<Vec<String>>,
    /// Group ids of the Device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_group: Option<Vec<String>>,
    /// Organization roles (issuer fact): `owner`, `admin`, `member`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_role: Option<Vec<OrgRole>>,
    /// Class roles (issuer fact): `teacher`, `assistant`, `student`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class_role: Option<Vec<ClassRole>>,
    /// Class ids, lowercase UUIDs (issuer fact).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<Vec<String>>,
    /// Org-tree node ids, lowercase UUIDs (issuer fact); a node matches its sub-nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_node: Option<Vec<String>>,
    /// Age bands (issuer fact): `under13`, `13-17`, `18+`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_band: Option<Vec<AgeBand>>,
    /// Issuer subject ids, lowercase UUIDs (issuer fact).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<Vec<String>>,
}

/// `[user]`: what the rules fall back to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct UserSection {
    /// The id of the user config a person gets when no rule matches. Required.
    pub fallback: String,
}

/// The user layer of a `format = 3` text, as written.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct UserLayer {
    /// `[user_defaults]` (empty when absent).
    pub defaults: UserDefaults,
    /// The `[[user_config]]` tables, in order.
    pub configs: Vec<UserConfigLayer>,
    /// The `[[assign]]` rules, in order.
    pub rules: Vec<Assign>,
    /// `[user] fallback`; `None` when `[user]` is missing (a check error, not a parse error).
    pub fallback: Option<String>,
}

/// `apps` of a device config: only what the Device itself runs.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct DeviceApps {
    /// Kiosk apps keyed by app id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub kiosk: BTreeMap<String, KioskApp>,
    /// Third-party .deb apps keyed by app id (kiosk ones belong here).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub deb: BTreeMap<String, DebApp>,
    /// The Ubuntu archive root the .deb apps' dependencies come from; absent: the image's
    /// snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ubuntu_mirror: Option<String>,
}

impl DeviceApps {
    pub fn is_empty(&self) -> bool {
        self.kiosk.is_empty() && self.deb.is_empty() && self.ubuntu_mirror.is_none()
    }
}

/// `drop.apps` of a device config: inherited device apps to leave out.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct DeviceDropApps {
    /// Keys (app ids) of inherited kiosk apps to leave out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kiosk: Vec<String>,
    /// Keys (app ids) of inherited .deb apps to leave out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deb: Vec<String>,
}

impl DeviceDropApps {
    pub fn is_empty(&self) -> bool {
        self.kiosk.is_empty() && self.deb.is_empty()
    }
}

/// `drop` of a device config: entries inherited from `[device_defaults]` to leave out.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct DeviceDrop {
    /// SSIDs of inherited networks to leave out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wifi: Vec<String>,
    /// Inherited device apps to leave out.
    #[serde(default, skip_serializing_if = "DeviceDropApps::is_empty")]
    pub apps: DeviceDropApps,
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
}

impl DeviceDrop {
    pub fn is_empty(&self) -> bool {
        self.wifi.is_empty()
            && self.apps.is_empty()
            && self.printers.is_empty()
            && self.scanners.is_empty()
            && self.files.is_empty()
            && self.downloads.is_empty()
            && self.scripts.is_empty()
    }
}

/// `[device_defaults]`: what every device config starts from; `[defaults]` of format 2 without
/// the user-layer keys (`interface`, `chrome_policy`, `apps.web`, `apps.flatpak`).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct DeviceDefaults {
    /// Who can sign in, unless a device config writes its own list: any of `guest`, `local`,
    /// `sso`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_methods: Option<Vec<LoginMethod>>,
    /// Whether local accounts are administrators, unless a device config writes its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_users_admin: Option<bool>,
    /// The IT maintenance account (`itadmin`) on every Device, unless a device config writes
    /// its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub it_account: Option<ItAccount>,
    /// Wi-Fi networks every device config gets.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wifi: Vec<Wifi>,
    /// Kiosk apps, kiosk .deb apps and the Ubuntu mirror every device config gets.
    #[serde(default, skip_serializing_if = "DeviceApps::is_empty")]
    pub apps: DeviceApps,
    /// Network printers every device config gets.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub printers: Vec<NetDevice>,
    /// Network scanners every device config gets.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scanners: Vec<NetDevice>,
    /// When Chrome may change version, unless a device config writes its own.
    #[serde(default, skip_serializing_if = "ChromeUpdate::is_empty")]
    pub chrome: ChromeUpdate,
    /// Whether "Get help" shows, unless a device config writes its own.
    #[serde(default, skip_serializing_if = "Support::is_empty")]
    pub support: Support,
    /// The update channel of the Devices, unless a device config writes its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_channel: Option<String>,
    /// Files from the bundle every device config places.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<FileEntry>,
    /// Downloaded files every device config places.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub downloads: Vec<Download>,
    /// Scripts every device config runs as root (`when = "apply"`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scripts: Vec<Script>,
}

/// `[[device_config]]` as written: what a Device looks like before anyone signs in, on top of
/// `[device_defaults]`; `[[config]]` of format 2 without the user-layer keys. Groups name it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct DeviceConfigLayer {
    /// The device config's id, unique among device configs; `[[group]]` entries name it.
    pub id: String,
    /// The name shown in the console.
    pub name: String,
    /// Who can sign in on the Devices: any of `guest`, `local`, `sso`. Absent: the device
    /// defaults' list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_methods: Option<Vec<LoginMethod>>,
    /// Whether local accounts are administrators. Absent: the device defaults' value, else false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_users_admin: Option<bool>,
    /// This device config's own IT maintenance account, replacing the device defaults' one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub it_account: Option<ItAccount>,
    /// Wi-Fi networks, added after the device defaults' ones (same SSID replaces).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wifi: Vec<Wifi>,
    /// Kiosk apps, kiosk .deb apps and the Ubuntu mirror, added to the device defaults' ones.
    #[serde(default, skip_serializing_if = "DeviceApps::is_empty")]
    pub apps: DeviceApps,
    /// Network printers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub printers: Vec<NetDevice>,
    /// Network scanners.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scanners: Vec<NetDevice>,
    /// When Chrome may change version. Absent: the device defaults' window and pause.
    #[serde(default, skip_serializing_if = "ChromeUpdate::is_empty")]
    pub chrome: ChromeUpdate,
    /// Whether "Get help" shows on the Devices. Absent: the device defaults' value, else true.
    #[serde(default, skip_serializing_if = "Support::is_empty")]
    pub support: Support,
    /// The update channel of the Devices: `stable` or `beta`. Absent: the device defaults'
    /// value, else `[school] update_channel`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_channel: Option<String>,
    /// Files from the bundle placed at absolute paths on the Devices.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<FileEntry>,
    /// Files downloaded by URL and checked against their SHA-256 before being placed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub downloads: Vec<Download>,
    /// Scripts from the bundle run as root when settings are applied (`when = "apply"`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scripts: Vec<Script>,
    /// Entries inherited from `[device_defaults]` this device config leaves out.
    #[serde(default, skip_serializing_if = "DeviceDrop::is_empty")]
    pub drop: DeviceDrop,
}

/// A `format = 3` settings file as written (design §2): Groups, device configs, user configs
/// and rules. [`Manifest::parse`] reads it into a [`Manifest`] with a [`UserLayer`].
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct V3Manifest {
    /// The settings syntax version: 3.
    pub format: u32,
    /// The Version number, increasing with every Publish.
    pub version: u64,
    /// When the Version was published (RFC 3339 text).
    #[serde(default)]
    pub issued_at: Option<String>,
    /// The signing keys Devices trust.
    #[serde(default)]
    pub trust: Vec<TrustKey>,
    /// Settings shared by the whole school.
    #[serde(default)]
    pub school: School,
    /// What every device config starts from.
    #[serde(default)]
    pub device_defaults: Option<DeviceDefaults>,
    /// The device configs: what a Device looks like before anyone signs in.
    #[serde(default, rename = "device_config")]
    pub device_config: Vec<DeviceConfigLayer>,
    /// The Groups: each is a set of Devices and the device config they use.
    #[serde(default, rename = "group")]
    pub groups: Vec<Group>,
    /// Device to Group assignments and Lock.
    #[serde(default, rename = "device")]
    pub devices: Vec<DeviceEntry>,
    /// What every user config starts from.
    #[serde(default)]
    pub user_defaults: Option<UserDefaults>,
    /// The user configs: what a person sees and may do in their session.
    #[serde(default)]
    pub user_config: Vec<UserConfigLayer>,
    /// The rules choosing a person's user config, first match wins.
    #[serde(default)]
    pub assign: Vec<Assign>,
    /// The fallback user config.
    #[serde(default)]
    pub user: Option<UserSection>,
}

impl DeviceApps {
    fn into_apps(self) -> Apps {
        Apps {
            web: Vec::new(),
            flatpak: Vec::new(),
            kiosk: self.kiosk,
            deb: self.deb,
            ubuntu_mirror: self.ubuntu_mirror,
        }
    }
}

impl DeviceDrop {
    fn into_drop(self) -> Drop {
        Drop {
            wifi: self.wifi,
            apps: DropApps {
                web: Vec::new(),
                flatpak: Vec::new(),
                kiosk: self.apps.kiosk,
                deb: self.apps.deb,
            },
            printers: self.printers,
            scanners: self.scanners,
            files: self.files,
            downloads: self.downloads,
            scripts: self.scripts,
            chrome_policy: Vec::new(),
        }
    }
}

impl DeviceDefaults {
    fn into_defaults(self) -> Defaults {
        Defaults {
            interface: None,
            login_methods: self.login_methods,
            local_users_admin: self.local_users_admin,
            it_account: self.it_account,
            wifi: self.wifi,
            apps: self.apps.into_apps(),
            printers: self.printers,
            scanners: self.scanners,
            chrome_policy: toml::Table::new(),
            chrome: self.chrome,
            support: self.support,
            update_channel: self.update_channel,
            files: self.files,
            downloads: self.downloads,
            scripts: self.scripts,
        }
    }
}

impl DeviceConfigLayer {
    fn into_config_layer(self) -> ConfigLayer {
        ConfigLayer {
            id: self.id,
            name: self.name,
            interface: None,
            login_methods: self.login_methods,
            local_users_admin: self.local_users_admin,
            it_account: self.it_account,
            wifi: self.wifi,
            apps: self.apps.into_apps(),
            printers: self.printers,
            scanners: self.scanners,
            chrome_policy: toml::Table::new(),
            chrome: self.chrome,
            support: self.support,
            update_channel: self.update_channel,
            files: self.files,
            downloads: self.downloads,
            scripts: self.scripts,
            drop: self.drop.into_drop(),
            legacy_browser: false,
        }
    }
}

impl V3Manifest {
    /// The device layer as the existing [`Manifest`] structure (no mode, no Chrome policy, no
    /// web or Flatpak apps), plus the user layer. Only for a text whose `format` is 3, which
    /// [`parse_v3`]'s caller has checked.
    fn into_manifest(self) -> Manifest {
        debug_assert_eq!(
            self.format, 3,
            "V3Manifest read from a text that is not format 3"
        );
        Manifest {
            format: self.format,
            version: self.version,
            issued_at: self.issued_at,
            trust: self.trust,
            school: self.school,
            defaults: self.device_defaults.map(DeviceDefaults::into_defaults),
            configs: self
                .device_config
                .into_iter()
                .map(DeviceConfigLayer::into_config_layer)
                .collect(),
            groups: self.groups,
            devices: self.devices,
            shape: Shape::New,
            user_layer: Some(UserLayer {
                defaults: self.user_defaults.unwrap_or_default(),
                configs: self.user_config,
                rules: self.assign,
                fallback: self.user.map(|u| u.fallback),
            }),
        }
    }
}

/// Parse a `format = 3` text (its `format` already checked) into a [`Manifest`] with
/// [`Manifest::user_layer`] set.
pub(crate) fn parse_v3(text: &str) -> Result<Manifest, toml::de::Error> {
    toml::from_str::<V3Manifest>(text).map(V3Manifest::into_manifest)
}

/// The entry rules of a Config's `apps.web`, `apps.flatpak`, `apps.deb` and `drop`, with the
/// same codes and levels, run over `[user_defaults]` and every `[[user_config]]` at
/// `user_defaults.…` / `user_config.<id>.…` (scripts are checked in `validate_all` itself).
/// [`Manifest::validate_all`] keeps the errors, [`crate::lint_at`] the rest.
pub(crate) fn entry_lints(u: &UserLayer, present: &BTreeSet<String>) -> Vec<Lint> {
    let mut out = Vec::new();
    let d = &u.defaults;
    let tag_defaults = |l: Lint| l.param("layer", "user_defaults");
    lint_user_apps("user_defaults", &d.apps, present, &tag_defaults, &mut out);
    for c in &u.configs {
        let base = format!("user_config.{}", c.id);
        let tag = |l: Lint| l.param("user_config", &c.id);
        lint_user_apps(&base, &c.apps, present, &tag, &mut out);
        let caps = |v: &[Capability]| v.iter().map(|c| c.as_str().to_owned()).collect::<Vec<_>>();
        let (drop_allow, drop_deny) = (caps(&c.drop.allow), caps(&c.drop.deny));
        let names = |v: &[WebApp]| v.iter().map(|a| a.name.clone()).collect::<Vec<_>>();
        let paths = |v: &[Script]| v.iter().map(|s| s.path.clone()).collect::<Vec<_>>();
        let sets: Vec<DropSet> = vec![
            (
                "apps.web",
                &c.drop.apps.web,
                names(&d.apps.web),
                names(&c.apps.web),
            ),
            (
                "apps.flatpak",
                &c.drop.apps.flatpak,
                d.apps.flatpak.clone(),
                c.apps.flatpak.clone(),
            ),
            (
                "apps.deb",
                &c.drop.apps.deb,
                d.apps.deb.keys().cloned().collect(),
                c.apps.deb.keys().cloned().collect(),
            ),
            (
                "scripts",
                &c.drop.scripts,
                paths(&d.scripts),
                paths(&c.scripts),
            ),
            (
                "chrome_policy",
                &c.drop.chrome_policy,
                d.chrome_policy.keys().cloned().collect(),
                c.chrome_policy.keys().cloned().collect(),
            ),
            ("allow", &drop_allow, caps(&d.allow), caps(&c.allow)),
            ("deny", &drop_deny, caps(&d.deny), caps(&c.deny)),
        ];
        let who = DropOwner {
            path: format!("{base}.drop"),
            subject: format!("User config {}", c.id),
            defaults: "[user_defaults]",
            defaults_word: "the user defaults",
        };
        lint_drop_sets(&who, &sets, &tag, &mut out);
    }
    out
}

/// The app rules of one user-layer table at `base`.
fn lint_user_apps(
    base: &str,
    apps: &UserApps,
    present: &BTreeSet<String>,
    tag: &dyn Fn(Lint) -> Lint,
    out: &mut Vec<Lint>,
) {
    lint_web_app_entries(&format!("{base}.apps.web"), &apps.web, present, tag, out);
    lint_deb_entries(&format!("{base}.apps.deb"), &apps.deb, present, tag, out);
    lint_app_formats(base, &apps.web, &apps.flatpak, out);
}

/// What one session gets: a user config with `[user_defaults]` laid under it (format 3), or the
/// profile a format 1/2 Config implies ([`UserConfig::implied`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    /// The user config's id (a format 1/2 Config's id).
    pub id: String,
    /// The name shown in the console.
    pub name: String,
    /// The starting point of the capabilities.
    pub preset: Preset,
    /// The effective capabilities: preset plus `allow` minus `deny`.
    pub caps: Caps,
    /// What happens to the home folder.
    pub home: HomeMode,
    /// Web apps.
    pub web: Vec<WebApp>,
    /// Flatpak app ids shown in the Dash.
    pub flatpak: Vec<String>,
    /// Non-kiosk .deb apps shown in the Dash, keyed by app id.
    pub deb: BTreeMap<String, DebApp>,
    /// Chrome managed policies.
    #[cfg_attr(
        feature = "schema",
        schemars(with = "serde_json::Map<String, serde_json::Value>")
    )]
    pub chrome_policy: toml::Table,
    /// Scripts run as the person at sign-in.
    pub login_scripts: Vec<Script>,
    /// Set only for the profile implied by a legacy `mode = "browser"` Group.
    pub legacy_browser: bool,
}

/// Effective capabilities: the preset's (`learning` none, `full` all), plus `allow`, minus
/// `deny` (deny wins).
pub fn effective_caps(preset: Preset, allow: &[Capability], deny: &[Capability]) -> Caps {
    let mut caps: Caps = match preset {
        Preset::Learning => Caps::new(),
        Preset::Full => ALL_CAPS.into_iter().collect(),
    };
    caps.extend(allow.iter().copied());
    for d in deny {
        caps.remove(d);
    }
    caps
}

/// The home mode a preset gives when nobody writes one.
fn preset_home(preset: Preset) -> HomeMode {
    match preset {
        Preset::Learning => HomeMode::Tidy,
        Preset::Full => HomeMode::Keep,
    }
}

/// A capability list merged like any collection: the defaults' entries minus `drop`, then the
/// config's own, each capability once.
fn merge_caps(
    inherited: &[Capability],
    own: &[Capability],
    drop: &[Capability],
) -> Vec<Capability> {
    let drop: Vec<String> = drop.iter().map(|c| c.as_str().to_owned()).collect();
    let merged = merge_list(inherited, own, &drop, |c| c.as_str());
    let mut seen = BTreeSet::new();
    merged.into_iter().filter(|c| seen.insert(*c)).collect()
}

/// The user config `c` laid over `[user_defaults]`: the same rules as [`effective_config`]
/// (single values replace; entries add, the same name replaces; `drop` removes), `allow` and
/// `deny` being collections too. `home` is the config's own, else the defaults', else the
/// preset's.
pub fn effective_user_config(u: &UserLayer, c: &UserConfigLayer) -> UserConfig {
    let d = &u.defaults;
    let drop = &c.drop;
    let preset = c.preset.or(d.preset).unwrap_or_default();
    let allow = merge_caps(&d.allow, &c.allow, &drop.allow);
    let deny = merge_caps(&d.deny, &c.deny, &drop.deny);
    UserConfig {
        id: c.id.clone(),
        name: c.name.clone(),
        preset,
        caps: effective_caps(preset, &allow, &deny),
        home: c.home.or(d.home).unwrap_or_else(|| preset_home(preset)),
        web: merge_list(&d.apps.web, &c.apps.web, &drop.apps.web, |a| {
            a.name.as_str()
        }),
        flatpak: merge_list(&d.apps.flatpak, &c.apps.flatpak, &drop.apps.flatpak, |id| {
            id.as_str()
        }),
        deb: merge_map(&d.apps.deb, &c.apps.deb, &drop.apps.deb),
        chrome_policy: merge_map(&d.chrome_policy, &c.chrome_policy, &drop.chrome_policy),
        login_scripts: merge_list(&d.scripts, &c.scripts, &drop.scripts, |s| s.path.as_str()),
        legacy_browser: false,
    }
}

impl UserConfig {
    /// The profile a format 1/2 Config implies: `interface = full` is preset `full` with every
    /// capability, `learning` is preset `learning` with none; the Config's web apps, Chrome
    /// policy and login scripts, and its Flatpaks and non-kiosk .deb apps unless it is the
    /// legacy browser mode.
    pub fn implied(config: &Config) -> UserConfig {
        let preset = match config.interface {
            Interface::Full => Preset::Full,
            Interface::Learning => Preset::Learning,
        };
        let installs = !config.legacy_browser;
        UserConfig {
            id: config.id.clone(),
            name: config.name.clone(),
            preset,
            caps: effective_caps(preset, &[], &[]),
            home: preset_home(preset),
            web: config.apps.web.clone(),
            flatpak: if installs {
                config.apps.flatpak.clone()
            } else {
                Vec::new()
            },
            deb: if installs {
                config
                    .apps
                    .deb
                    .iter()
                    .filter(|(_, a)| !a.kiosk)
                    .map(|(k, a)| (k.clone(), a.clone()))
                    .collect()
            } else {
                BTreeMap::new()
            },
            chrome_policy: config.chrome_policy.clone(),
            login_scripts: config
                .scripts
                .iter()
                .filter(|s| s.when == When::Login)
                .cloned()
                .collect(),
            legacy_browser: config.legacy_browser,
        }
    }
}

/// The effective user config with this id: format 3 the layer, format 1/2 the profile implied by
/// the Config with that id.
pub fn user_config(m: &Manifest, id: &str) -> Option<UserConfig> {
    match &m.user_layer {
        Some(u) => {
            let c = u.configs.iter().find(|c| c.id == id)?;
            Some(effective_user_config(u, c))
        }
        None => {
            let layer = m.config(id)?;
            Some(UserConfig::implied(&effective_config(m, layer)))
        }
    }
}

/// The ids of the user configs a Device of this Group can give a person, in order: those named by
/// the rules whose `device_group` is absent or lists the Group, then the fallback, each once
/// (format 3); the Group's Config id (format 1/2).
pub fn reachable_user_configs(m: &Manifest, group_id: &str) -> Vec<String> {
    let Some(u) = &m.user_layer else {
        return m
            .groups
            .iter()
            .find(|g| g.id == group_id)
            .map(|g| vec![g.config.clone()])
            .unwrap_or_default();
    };
    let mut out: Vec<String> = Vec::new();
    let named = u
        .rules
        .iter()
        .filter(|r| {
            r.device_group
                .as_ref()
                .is_none_or(|gs| gs.iter().any(|g| g == group_id))
        })
        .map(|r| &r.user_config)
        .chain(u.fallback.iter());
    for id in named {
        if !out.contains(id) {
            out.push(id.clone());
        }
    }
    out
}

/// The Flatpak ids and non-kiosk .deb apps of the reachable user configs, in reachable order;
/// the first definition of an id wins.
pub fn install_union(m: &Manifest, group_id: &str) -> (Vec<String>, BTreeMap<String, DebApp>) {
    let mut flatpak: Vec<String> = Vec::new();
    let mut deb: BTreeMap<String, DebApp> = BTreeMap::new();
    for id in reachable_user_configs(m, group_id) {
        let Some(u) = user_config(m, &id) else {
            continue;
        };
        for f in u.flatpak {
            if !flatpak.contains(&f) {
                flatpak.push(f);
            }
        }
        for (k, a) in u.deb {
            if !a.kiosk {
                deb.entry(k).or_insert(a);
            }
        }
    }
    (flatpak, deb)
}

/// What the Devices of `group` get: [`effective_config`] of its Config; for format 3 also the
/// install union (`apps.flatpak`, and the union's .deb apps next to the device's own kiosk
/// ones, the device entry winning on an id clash). `None` when the Group's Config is missing.
pub fn effective_device_config(m: &Manifest, group: &Group) -> Option<Config> {
    let mut config = effective_config(m, m.config(&group.config)?);
    if m.user_layer.is_some() {
        let (flatpak, mut deb) = install_union(m, &group.id);
        config.apps.flatpak = flatpak;
        deb.extend(
            std::mem::take(&mut config.apps.deb)
                .into_iter()
                .filter(|(_, a)| a.kiosk),
        );
        config.apps.deb = deb;
    }
    Some(config)
}

/// What the Device knows about the person signing in, without asking the issuer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceFacts<'a> {
    /// The account kind.
    pub kind: Kind,
    /// Whether the person is an administrator on the Device.
    pub admin: bool,
    /// The login name; rules compare it case-insensitively.
    pub user: &'a str,
    /// The id of the Group of this Device.
    pub device_group: &'a str,
}

/// One class of the person, from the issuer facts (design §5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ClassFact {
    /// The class id, a lowercase UUID.
    pub id: String,
    /// The person's role in that class.
    pub role: ClassRole,
}

/// The issuer facts of one login: the userinfo JSON of design §5. Unknown claims are ignored
/// because the issuer may add some.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct IssuerFacts {
    /// The issuer subject id.
    pub sub: String,
    /// The organisation id.
    pub org: String,
    /// The person's role in the organisation, when the issuer says.
    #[serde(default)]
    pub org_role: Option<OrgRole>,
    /// The person's org-tree node and all its ancestors.
    #[serde(default)]
    pub org_nodes: Vec<String>,
    /// The classes the person is in.
    #[serde(default)]
    pub classes: Vec<ClassFact>,
    /// The person's age band, when the issuer says.
    #[serde(default)]
    pub age_band: Option<AgeBand>,
}

/// The outcome of [`resolve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// The id of the user config the person gets.
    pub user_config: String,
    /// The index of the rule that matched in the slice passed to [`resolve`]; `None` when the
    /// fallback applies. For [`UserRules::resolve`] it indexes `UserRules.rules` (renumbered),
    /// not the manifest's `[[assign]]` list.
    pub rule: Option<usize>,
}

/// Whether an optional condition holds for `value`: absent holds, an empty list never does.
fn cond<T>(c: &Option<Vec<T>>, any: impl Fn(&T) -> bool) -> bool {
    c.as_ref().is_none_or(|v| v.iter().any(any))
}

fn rule_matches(r: &Assign, d: &DeviceFacts, facts: Option<&IssuerFacts>) -> bool {
    if !(cond(&r.kind, |k| *k == d.kind)
        && r.admin.is_none_or(|a| a == d.admin)
        && cond(&r.user, |u| u.eq_ignore_ascii_case(d.user))
        && cond(&r.device_group, |g| g == d.device_group))
    {
        return false;
    }
    let has_fact_condition = r.org_role.is_some()
        || r.class_role.is_some()
        || r.class.is_some()
        || r.org_node.is_some()
        || r.age_band.is_some()
        || r.sub.is_some();
    if !has_fact_condition {
        return true;
    }
    let (Some(f), Kind::Sso) = (facts, d.kind) else {
        return false;
    };
    cond(&r.org_role, |x| f.org_role == Some(*x))
        && cond(&r.class_role, |x| f.classes.iter().any(|c| c.role == *x))
        && cond(&r.class, |x| f.classes.iter().any(|c| c.id == *x))
        && cond(&r.org_node, |x| f.org_nodes.iter().any(|n| n == x))
        && cond(&r.age_band, |x| f.age_band == Some(*x))
        && cond(&r.sub, |x| f.sub == *x)
}

/// The user config of a person: the first rule whose every written condition holds, else
/// `fallback`. Within a list any element matches, so an empty list never matches. `user` is
/// compared ASCII-case-insensitively (login names are ASCII, and this rules out Unicode
/// collisions such as the Kelvin sign); ids and `sub` compare exactly.
/// Fact conditions hold only when `facts` is `Some` and the account is `sso`.
pub fn resolve(
    rules: &[Assign],
    fallback: &str,
    device: &DeviceFacts,
    facts: Option<&IssuerFacts>,
) -> Resolution {
    match rules.iter().position(|r| rule_matches(r, device, facts)) {
        Some(i) => Resolution {
            user_config: rules[i].user_config.clone(),
            rule: Some(i),
        },
        None => Resolution {
            user_config: fallback.to_string(),
            rule: None,
        },
    }
}

/// What a Device of one Group needs at login (design §4): written root-only by the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct UserRules {
    /// The Group of this Device.
    pub group: String,
    /// The user config when no rule matches.
    pub fallback: String,
    /// The rules reachable on this Group, in order (indices re-numbered).
    pub rules: Vec<Assign>,
    /// The ids of the user configs reachable on this Group.
    pub configs: Vec<String>,
}

impl UserRules {
    /// The rules file for `group_id`. `None` for format 1/2 and for a format 3 manifest without
    /// `[user] fallback` (a check error).
    pub fn from_manifest(m: &Manifest, group_id: &str) -> Option<UserRules> {
        let u = m.user_layer.as_ref()?;
        let fallback = u.fallback.clone()?;
        let rules = u
            .rules
            .iter()
            .filter(|r| {
                r.device_group
                    .as_ref()
                    .is_none_or(|gs| gs.iter().any(|g| g == group_id))
            })
            .cloned()
            .collect();
        Some(UserRules {
            group: group_id.to_string(),
            fallback,
            rules,
            configs: reachable_user_configs(m, group_id),
        })
    }

    /// [`resolve`] over these rules and fallback. `device.device_group` must be this file's
    /// Group (checked in debug builds); the returned `rule` indexes `self.rules`.
    pub fn resolve(&self, device: &DeviceFacts, facts: Option<&IssuerFacts>) -> Resolution {
        debug_assert_eq!(device.device_group, self.group);
        resolve(&self.rules, &self.fallback, device, facts)
    }
}

/// The user config of the guest session on a Device of this Group: format 3 resolves a guest
/// without facts; format 1/2 the Group's Config id. `None` for an unknown Group (or no fallback).
pub fn guest_user_config(m: &Manifest, group_id: &str) -> Option<String> {
    if m.user_layer.is_none() {
        return m
            .groups
            .iter()
            .find(|g| g.id == group_id)
            .map(|g| g.config.clone());
    }
    m.groups.iter().find(|g| g.id == group_id)?;
    let device = DeviceFacts {
        kind: Kind::Guest,
        admin: false,
        user: "guest",
        device_group: group_id,
    };
    Some(
        UserRules::from_manifest(m, group_id)?
            .resolve(&device, None)
            .user_config,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BundleError, Manifest};

    fn v3_example() -> String {
        crate::testutil::spec_example_v3()
    }

    /// The v3 example with `t` written into the table it belongs to: `interface` and `apps.*`
    /// inside the `[[device_config]]`, `user_config` inside the `[[group]]`, a table header at the
    /// end of the text (after it, bare keys would belong to that table).
    fn v3_with(t: &str) -> String {
        let text = v3_example();
        let after = if t.starts_with("interface") || t.starts_with("apps.") {
            "name = \"Classroom laptops\"\n"
        } else if t.starts_with("user_config") {
            "config = \"classroom\"\n"
        } else {
            return format!("{text}\n{t}\n");
        };
        assert!(text.contains(after), "{after}");
        text.replacen(after, &format!("{after}{t}\n"), 1)
    }

    /// A valid format 2 text (new shape) without `format`.
    fn v2_minimal_body() -> String {
        "version = 1\n[[config]]\nid = \"c\"\nname = \"c\"\n\
         [[group]]\nid = \"default\"\nname = \"d\"\nconfig = \"c\""
            .to_string()
    }

    /// A format 3 text: one device config, groups `default` and `exam-room`, then `body`.
    fn v3_text(body: &str) -> String {
        format!(
            "format = 3\nversion = 1\n\
             [[device_config]]\nid = \"classroom\"\nname = \"C\"\n\
             [[group]]\nid = \"default\"\nname = \"D\"\nconfig = \"classroom\"\n\
             [[group]]\nid = \"exam-room\"\nname = \"E\"\nconfig = \"classroom\"\n{body}"
        )
    }

    fn names(v: &[WebApp]) -> Vec<&str> {
        v.iter().map(|a| a.name.as_str()).collect()
    }

    fn deb(name: &str, url: &str) -> String {
        format!("{{ name = \"{name}\", url = \"{url}\" }}")
    }

    #[test]
    fn caps_deny_wins() {
        assert_eq!(
            effective_caps(
                Preset::Learning,
                &[Capability::Terminal],
                &[Capability::Terminal]
            ),
            Caps::new()
        );
        assert_eq!(
            effective_caps(Preset::Full, &[], &[Capability::Terminal]).len(),
            5
        );
        assert_eq!(effective_caps(Preset::Full, &[], &[]).len(), 6);
        assert_eq!(
            effective_caps(Preset::Learning, &[Capability::Settings], &[]),
            Caps::from([Capability::Settings])
        );
    }

    #[test]
    fn merge_follows_defaults_rules() {
        let m = Manifest::parse(&v3_text(
            "[user_defaults]\n\
             apps.web = [{ name = \"Classroom\", url = \"https://c.example\" }]\n\
             chrome_policy = { URLBlocklist = [\"a.com\"] }\nallow = [\"file_manager\"]\n\
             [[user_config]]\nid = \"x\"\nname = \"X\"\n\
             apps.web = [{ name = \"Starfall\", url = \"https://s.example\" }]\n\
             drop.apps.web = [\"Classroom\"]\ndeny = [\"file_manager\"]\n\
             drop.chrome_policy = [\"URLBlocklist\"]\n",
        ))
        .unwrap();
        let u = user_config(&m, "x").unwrap();
        assert_eq!(names(&u.web), ["Starfall"]);
        assert!(u.caps.is_empty());
        assert!(u.chrome_policy.is_empty());
        assert!(user_config(&m, "nope").is_none());
    }

    #[test]
    fn allow_and_deny_merge_as_collections() {
        let m = Manifest::parse(&v3_text(
            "[user_defaults]\nallow = [\"settings\"]\ndeny = [\"file_manager\"]\n\
             [[user_config]]\nid = \"a\"\nname = \"A\"\npreset = \"full\"\n\
             [[user_config]]\nid = \"b\"\nname = \"B\"\npreset = \"full\"\n\
             drop.deny = [\"file_manager\"]\nallow = [\"settings\", \"terminal\"]\n",
        ))
        .unwrap();
        // The defaults' deny reaches `a`, and `b` undoes it with `drop.deny`.
        assert!(!user_config(&m, "a")
            .unwrap()
            .caps
            .contains(&Capability::FileManager));
        assert_eq!(user_config(&m, "b").unwrap().caps.len(), 6);
    }

    #[test]
    fn drop_allow_undoes_a_default_allow() {
        let m = Manifest::parse(&v3_text(
            "[user_defaults]\nallow = [\"terminal\", \"settings\"]\n\
             [[user_config]]\nid = \"a\"\nname = \"A\"\n\
             [[user_config]]\nid = \"b\"\nname = \"B\"\ndrop.allow = [\"terminal\"]\n",
        ))
        .unwrap();
        assert_eq!(user_config(&m, "a").unwrap().caps.len(), 2);
        assert_eq!(
            user_config(&m, "b").unwrap().caps,
            Caps::from([Capability::Settings])
        );
    }

    #[test]
    fn home_default_follows_preset() {
        let m = Manifest::parse(&v3_text(
            "[[user_config]]\nid = \"l\"\nname = \"L\"\nallow = [\"file_manager\"]\n\
             [[user_config]]\nid = \"f\"\nname = \"F\"\npreset = \"full\"\n\
             [[user_config]]\nid = \"k\"\nname = \"K\"\nhome = \"keep\"\n",
        ))
        .unwrap();
        let home = |id: &str| user_config(&m, id).unwrap().home;
        assert_eq!(home("l"), HomeMode::Tidy);
        assert_eq!(home("f"), HomeMode::Keep);
        assert_eq!(home("k"), HomeMode::Keep);
        let m = Manifest::parse(&v3_text(
            "[user_defaults]\nhome = \"keep\"\n\
             [[user_config]]\nid = \"d\"\nname = \"D\"\n\
             [[user_config]]\nid = \"t\"\nname = \"T\"\nhome = \"tidy\"\n",
        ))
        .unwrap();
        assert_eq!(user_config(&m, "d").unwrap().home, HomeMode::Keep);
        assert_eq!(user_config(&m, "t").unwrap().home, HomeMode::Tidy);
    }

    #[test]
    fn login_scripts_are_the_merged_scripts() {
        let m = Manifest::parse(&v3_text(
            "[user_defaults]\nscripts = [{ path = \"scripts/a.sh\", when = \"login\" }, \
             { path = \"scripts/b.sh\", when = \"login\" }]\n\
             [[user_config]]\nid = \"x\"\nname = \"X\"\ndrop.scripts = [\"scripts/a.sh\"]\n\
             scripts = [{ path = \"scripts/c.sh\", when = \"login\" }]\n",
        ))
        .unwrap();
        let paths: Vec<_> = user_config(&m, "x")
            .unwrap()
            .login_scripts
            .into_iter()
            .map(|s| s.path)
            .collect();
        assert_eq!(paths, ["scripts/b.sh", "scripts/c.sh"]);
    }

    #[test]
    fn implied_matches_todays_profiles() {
        let m = Manifest::parse(&crate::testutil::spec_example()).unwrap();
        let eff = |id: &str| effective_config(&m, m.config(id).unwrap());
        let student = UserConfig::implied(&eff("cart"));
        assert_eq!(
            (student.preset, student.home),
            (Preset::Learning, HomeMode::Tidy)
        );
        assert!(student.caps.is_empty() && !student.legacy_browser);
        let teacher = UserConfig::implied(&eff("teacher"));
        assert_eq!(
            (teacher.preset, teacher.home),
            (Preset::Full, HomeMode::Keep)
        );
        assert_eq!(teacher.caps.len(), 6);
        assert_eq!(teacher.id, "teacher");
        assert_eq!(teacher.name, eff("teacher").name);
        assert_eq!(teacher.web, eff("teacher").apps.web);
        assert_eq!(teacher.flatpak, eff("teacher").apps.flatpak);
        assert_eq!(teacher.chrome_policy, eff("teacher").chrome_policy);
        assert_eq!(user_config(&m, "teacher").unwrap(), teacher);
        assert_eq!(reachable_user_configs(&m, "teacher"), ["teacher"]);
        assert!(reachable_user_configs(&m, "nope").is_empty());

        let mut browser = eff("teacher");
        browser.legacy_browser = true;
        let b = UserConfig::implied(&browser);
        assert!(b.legacy_browser && b.flatpak.is_empty() && b.deb.is_empty());

        // Login scripts only; kiosk .deb apps stay on the device.
        let mut c = eff("teacher");
        c.scripts = vec![
            Script {
                path: "scripts/a.sh".into(),
                when: When::Apply,
                timeout_secs: None,
            },
            Script {
                path: "scripts/b.sh".into(),
                when: When::Login,
                timeout_secs: None,
            },
        ];
        let plain: DebApp =
            toml::from_str("name = \"P\"\nurl = \"https://x.example/p.deb\"").unwrap();
        let kiosk = DebApp {
            kiosk: true,
            ..plain.clone()
        };
        c.apps.deb = BTreeMap::from([("plain".into(), plain), ("kiosky".into(), kiosk)]);
        let i = UserConfig::implied(&c);
        assert_eq!(i.login_scripts.len(), 1);
        assert_eq!(i.login_scripts[0].path, "scripts/b.sh");
        assert_eq!(i.deb.keys().collect::<Vec<_>>(), ["plain"]);
    }

    /// Rules teacher(admin), exam(device_group exam-room), primary(org_node); fallback primary.
    fn reachable_text() -> String {
        v3_text(&format!(
            "[[user_config]]\nid = \"primary\"\nname = \"P\"\n\
             [[user_config]]\nid = \"teacher\"\nname = \"T\"\npreset = \"full\"\n\
             [[user_config]]\nid = \"exam\"\nname = \"E\"\n\
             apps.flatpak = [\"org.libreoffice.LibreOffice\"]\n\
             apps.deb.zoom = {}\n\
             [[assign]]\nuser_config = \"teacher\"\nadmin = true\n\
             [[assign]]\nuser_config = \"exam\"\ndevice_group = [\"exam-room\"]\n\
             [[assign]]\nuser_config = \"primary\"\n\
             org_node = [\"0193a0c2-0000-7000-8000-000000000001\"]\n\
             [user]\nfallback = \"primary\"\n",
            deb("Zoom", "https://x.example/zoom.deb")
        ))
    }

    #[test]
    fn reachable_respects_device_group_and_fallback() {
        let m = Manifest::parse(&reachable_text()).unwrap();
        assert_eq!(
            reachable_user_configs(&m, "default"),
            ["teacher", "primary"]
        );
        assert_eq!(
            reachable_user_configs(&m, "exam-room"),
            ["teacher", "exam", "primary"]
        );
    }

    #[test]
    fn install_union_keeps_first_definition() {
        let m = Manifest::parse(&v3_text(&format!(
            "[[user_config]]\nid = \"a\"\nname = \"A\"\n\
             apps.flatpak = [\"org.a.A\", \"org.b.B\"]\napps.deb.zoom = {}\n\
             [[user_config]]\nid = \"b\"\nname = \"B\"\n\
             apps.flatpak = [\"org.b.B\", \"org.c.C\"]\napps.deb.zoom = {}\n\
             [[assign]]\nuser_config = \"a\"\nadmin = true\n\
             [user]\nfallback = \"b\"\n",
            deb("First", "https://x.example/1.deb"),
            deb("Second", "https://x.example/2.deb")
        )))
        .unwrap();
        let (flatpak, debs) = install_union(&m, "default");
        assert_eq!(flatpak, ["org.a.A", "org.b.B", "org.c.C"]);
        assert_eq!(debs.len(), 1);
        assert_eq!(debs["zoom"].name, "First");
    }

    #[test]
    fn device_config_carries_install_union() {
        use crate::select::{select, DeviceIdent};
        let text = format!(
            "{}\n[[device]]\ndevice_id = \"dev-exam\"\ngroup = \"exam-room\"\n",
            reachable_text()
        );
        let m = Manifest::parse(&text).unwrap();
        let ident_in = |id: &str| DeviceIdent {
            serial: None,
            device_id: id.into(),
        };
        let sel = select(&m, &ident_in("dev-exam"), None);
        assert_eq!(sel.group.id, "exam-room");
        assert_eq!(sel.config.apps.flatpak, ["org.libreoffice.LibreOffice"]);
        assert!(sel.config.chrome_policy.is_empty());
        assert!(sel.config.apps.deb.contains_key("zoom"));
        let sel = select(&m, &ident_in("other"), None);
        assert_eq!(sel.group.id, "default");
        assert!(sel.config.apps.flatpak.is_empty());
    }

    #[test]
    fn device_deb_entry_wins_over_the_union() {
        let m = Manifest::parse(
            &v3_text(&format!(
                "[[user_config]]\nid = \"a\"\nname = \"A\"\napps.deb.zoom = {}\n\
             [user]\nfallback = \"a\"\n",
                deb("User", "https://x.example/u.deb")
            ))
            .replace(
                "name = \"C\"\n",
                &format!(
                    "name = \"C\"\napps.deb.zoom = {}\n",
                    "{ name = \"Device\", url = \"https://x.example/d.deb\", kiosk = true }"
                ),
            ),
        )
        .unwrap();
        let c = m.effective_of_group("default").unwrap();
        assert_eq!(c.apps.deb["zoom"].name, "Device");
        assert!(c.apps.deb["zoom"].kiosk);
    }

    #[test]
    fn parses_spec_example() {
        let m = Manifest::parse(&v3_example()).unwrap();
        assert_eq!(m.format, 3);
        assert_eq!(m.configs.len(), 1);
        assert_eq!(m.configs[0].interface, None);
        let u = m.user_layer.as_ref().unwrap();
        assert_eq!(
            u.configs.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            ["primary", "teacher"]
        );
        assert_eq!(u.rules.len(), 3);
        assert_eq!(u.rules[0].admin, Some(true));
        assert_eq!(u.fallback.as_deref(), Some("primary"));
    }

    #[test]
    fn spec_example_layers_land_where_they_belong() {
        use crate::{LoginMethod, Shape};
        let m = Manifest::parse(&v3_example()).unwrap();
        assert_eq!(m.shape, Shape::New);
        let d = m.defaults.as_ref().unwrap();
        assert_eq!(
            d.login_methods.as_deref(),
            Some(&[LoginMethod::Sso, LoginMethod::Guest][..])
        );
        assert!(d.interface.is_none() && d.chrome_policy.is_empty() && d.apps.web.is_empty());
        assert_eq!(m.config_of_group("default").unwrap().id, "classroom");
        let u = m.user_layer.as_ref().unwrap();
        assert_eq!(u.defaults.preset, Some(Preset::Learning));
        assert!(u.defaults.chrome_policy.contains_key("URLBlocklist"));
        assert_eq!(u.defaults.apps.web[0].name, "Classroom");
        let teacher = &u.configs[1];
        assert_eq!(teacher.preset, Some(Preset::Full));
        assert_eq!(teacher.drop.chrome_policy, ["URLBlocklist"]);
        assert_eq!(
            u.rules[1].class_role.as_deref(),
            Some(&[ClassRole::Teacher, ClassRole::Assistant][..])
        );
        assert_eq!(u.rules[2].user_config, "primary");
        assert!(u.rules[2].org_node.is_some() && u.rules[2].admin.is_none());
    }

    #[test]
    fn missing_user_section_parses_without_fallback() {
        let text = v3_example().replace("[user]\nfallback = \"primary\"\n", "");
        let m = Manifest::parse(&text).unwrap();
        assert_eq!(m.user_layer.unwrap().fallback, None);
    }

    #[test]
    fn rule_enums_use_their_written_names() {
        let a: Assign = toml::from_str(
            "user_config = \"x\"\nkind = [\"sso\", \"local\", \"guest\"]\n\
             org_role = [\"owner\", \"admin\", \"member\"]\nage_band = [\"under13\", \"13-17\", \"18+\"]",
        )
        .unwrap();
        assert_eq!(a.kind.unwrap(), [Kind::Sso, Kind::Local, Kind::Guest]);
        assert_eq!(
            a.age_band.unwrap(),
            [AgeBand::Under13, AgeBand::Teen, AgeBand::Adult]
        );
        let caps: Vec<Capability> = ALL_CAPS.to_vec();
        let names: Vec<String> = caps
            .iter()
            .map(|c| {
                toml::Value::try_from(c)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            names,
            [
                "terminal",
                "file_manager",
                "settings",
                "extensions",
                "all_apps",
                "user_apps"
            ]
        );
        assert!(toml::from_str::<Assign>("user_config = \"x\"\ncolour = 1").is_err());
        let a: Assign = toml::from_str("user_config = \"x\"\nclass_role = [\"student\"]").unwrap();
        assert_eq!(a.class_role.unwrap(), [ClassRole::Student]);
        let c: UserConfigLayer =
            toml::from_str("id = \"a\"\nname = \"a\"\npreset = \"learning\"\nhome = \"tidy\"")
                .unwrap();
        assert_eq!(
            (c.preset, c.home),
            (Some(Preset::Learning), Some(HomeMode::Tidy))
        );
        let c: UserConfigLayer =
            toml::from_str("id = \"a\"\nname = \"a\"\npreset = \"full\"\nhome = \"keep\"").unwrap();
        assert_eq!(
            (c.preset, c.home),
            (Some(Preset::Full), Some(HomeMode::Keep))
        );
        assert!(
            toml::from_str::<UserConfigLayer>("id = \"a\"\nname = \"a\"\nhome = \"wipe\"").is_err()
        );
        for cap in ALL_CAPS {
            assert_eq!(
                toml::Value::try_from(cap).unwrap().as_str(),
                Some(cap.as_str())
            );
        }
    }

    /// Written apps and drops serialize; empty ones are left out (Task 5's migrate writes them).
    #[test]
    fn empty_sub_tables_are_not_serialized() {
        let c: UserConfigLayer = toml::from_str("id = \"a\"\nname = \"A\"").unwrap();
        assert_eq!(toml::to_string(&c).unwrap(), "id = \"a\"\nname = \"A\"\n");
        let d: DeviceConfigLayer = toml::from_str("id = \"a\"\nname = \"A\"").unwrap();
        assert_eq!(toml::to_string(&d).unwrap(), "id = \"a\"\nname = \"A\"\n");
        assert!(toml::to_string(&UserDefaults::default())
            .unwrap()
            .is_empty());
        assert!(toml::to_string(&DeviceDefaults::default())
            .unwrap()
            .is_empty());
        let c: UserConfigLayer =
            toml::from_str("id = \"a\"\nname = \"A\"\ndrop.allow = [\"terminal\"]").unwrap();
        let back: UserConfigLayer = toml::from_str(&toml::to_string(&c).unwrap()).unwrap();
        assert_eq!(back, c);
    }

    /// `(code, path)` of every issue `validate_all` and lint give for the v3 example with
    /// `user_defaults` and `primary` extended by the given lines.
    fn issues(defaults_extra: &str, primary_extra: &str) -> Vec<(String, String)> {
        let text = v3_example()
            .replacen(
                "preset = \"learning\"\n",
                &format!("preset = \"learning\"\n{defaults_extra}\n"),
                1,
            )
            .replacen(
                "name = \"Grade 1-6\"\n",
                &format!("name = \"Grade 1-6\"\n{primary_extra}\n"),
                1,
            );
        let m = Manifest::parse(&text).unwrap();
        let present = ["scripts/ok.sh", "files/icon.png"]
            .into_iter()
            .map(String::from)
            .collect();
        let today = chrono::NaiveDate::from_ymd_opt(2026, 11, 19).unwrap();
        m.validate_all(&present)
            .into_iter()
            .chain(crate::lint_at(&m, &present, today))
            .map(|l| (l.code.to_string(), l.path.unwrap_or_default()))
            .collect()
    }

    fn has(all: &[(String, String)], code: &str, path: &str) -> bool {
        all.iter().any(|(c, p)| c == code && p == path)
    }

    #[test]
    fn spec_example_v3_validates_clean() {
        let m = Manifest::parse(&v3_example()).unwrap();
        assert_eq!(m.validate_all(&Default::default()), []);
        let all = issues("", "");
        assert!(!all.iter().any(|(_, p)| p.starts_with("user_")), "{all:?}");
    }

    #[test]
    fn user_layer_scripts_follow_the_script_rules() {
        let all = issues(
            "scripts = [{ path = \"scripts/missing.sh\", when = \"login\" }]",
            "scripts = [{ path = \"files/icon.png\", when = \"login\" }, \
             { path = \"scripts/ok.sh\", when = \"login\", timeout_secs = 99999 }]",
        );
        assert!(
            has(&all, "file_missing", "user_defaults.scripts[0].path"),
            "{all:?}"
        );
        assert!(
            has(
                &all,
                "file_outside_dir",
                "user_config.primary.scripts[0].path"
            ),
            "{all:?}"
        );
        assert!(
            has(
                &all,
                "script_timeout_too_long",
                "user_config.primary.scripts[1].timeout_secs"
            ),
            "{all:?}"
        );
        // A script that exists and is in place passes.
        let all = issues(
            "scripts = [{ path = \"scripts/ok.sh\", when = \"login\" }]",
            "",
        );
        assert!(!all.iter().any(|(_, p)| p.starts_with("user_")), "{all:?}");
    }

    #[test]
    fn user_layer_web_apps_follow_the_web_app_rules() {
        let all = issues(
            "apps.flatpak = [\"not an id\"]",
            "apps.web = [{ name = \"A\", url = \"ftp://a\" }, \
             { name = \"B\", url = \"http://b.org\", icon = \"files/none.png\" }]",
        );
        assert!(
            has(&all, "web_app_invalid", "user_config.primary.apps.web[0]"),
            "{all:?}"
        );
        assert!(
            has(&all, "icon_invalid", "user_config.primary.apps.web[1].icon"),
            "{all:?}"
        );
        assert!(
            has(
                &all,
                "web_app_not_https",
                "user_config.primary.apps.web[1].url"
            ),
            "{all:?}"
        );
        assert!(
            has(&all, "flatpak_id_invalid", "user_defaults.apps.flatpak[0]"),
            "{all:?}"
        );
        let all = issues("", "apps.flatpak = [\"org.ok.App\", \"bad/id\"]");
        assert!(
            has(
                &all,
                "flatpak_id_invalid",
                "user_config.primary.apps.flatpak[1]"
            ),
            "{all:?}"
        );
        // `[user_defaults]` already writes `apps.web`: change its entry.
        let m = Manifest::parse(&v3_example().replacen(
            "url = \"https://classroom.google.com\"",
            "url = \"nope\"",
            1,
        ))
        .unwrap();
        let v = m.validate_all(&Default::default());
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(
            (v[0].code, v[0].path.as_deref()),
            ("web_app_invalid", Some("user_defaults.apps.web[0]"))
        );
        // The errors stop validate, the warning does not.
        let m = Manifest::parse(&v3_example().replacen(
            "name = \"Grade 1-6\"\n",
            "name = \"Grade 1-6\"\napps.web = [{ name = \"H\", url = \"http://h.org\" }]\n",
            1,
        ))
        .unwrap();
        assert_eq!(m.validate_all(&Default::default()), []);
    }

    #[test]
    fn user_layer_deb_apps_follow_the_deb_rules() {
        let all = issues(
            "apps.deb.Bad = { name = \"X\", url = \"https://x.org/x.deb\" }",
            "apps.deb.zoom = { name = \"Zoom\", url = \"http://x.org/z.deb\" }\n\
             apps.deb.ok = { name = \"Ok\", url = \"https://x.org/o.deb\", icon = \"files/none.png\" }",
        );
        assert!(
            has(&all, "deb_id_invalid", "user_defaults.apps.deb.Bad.id"),
            "{all:?}"
        );
        assert!(
            has(
                &all,
                "deb_url_invalid",
                "user_config.primary.apps.deb.zoom.url"
            ),
            "{all:?}"
        );
        assert!(
            has(
                &all,
                "deb_icon_invalid",
                "user_config.primary.apps.deb.ok.icon"
            ),
            "{all:?}"
        );
    }

    #[test]
    fn user_layer_drops_follow_the_drop_rules() {
        let all = issues(
            "allow = [\"file_manager\"]",
            "chrome_policy = { URLBlocklist = [] }\n\
             drop.chrome_policy = [\"URLBlocklist\"]\n\
             drop.apps.web = [\"Nope\"]\n\
             drop.allow = [\"file_manager\", \"terminal\"]",
        );
        assert!(
            has(
                &all,
                "drop_conflict",
                "user_config.primary.drop.chrome_policy[0]"
            ),
            "{all:?}"
        );
        assert!(
            has(&all, "drop_unknown", "user_config.primary.drop.apps.web[0]"),
            "{all:?}"
        );
        assert!(
            has(&all, "drop_unknown", "user_config.primary.drop.allow[1]"),
            "{all:?}"
        );
        assert!(
            !has(&all, "drop_unknown", "user_config.primary.drop.allow[0]"),
            "{all:?}"
        );
        // The teacher's drop of the inherited URLBlocklist (the spec example) is fine.
        assert!(
            !all.iter()
                .any(|(_, p)| p.starts_with("user_config.teacher")),
            "{all:?}"
        );
        let m = Manifest::parse(&v3_example().replacen(
            "name = \"Grade 1-6\"\n",
            "name = \"Grade 1-6\"\nchrome_policy = { A = 1 }\ndrop.chrome_policy = [\"A\"]\n",
            1,
        ))
        .unwrap();
        let v = m.validate_all(&Default::default());
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].code, "drop_conflict");
        assert!(
            v[0].message.starts_with("User config primary both drops"),
            "{v:?}"
        );
    }

    /// The device layer of a format 3 text goes through the Config rules (it is `configs`).
    #[test]
    fn device_layer_goes_through_config_rules() {
        let m = Manifest::parse(&v3_example().replacen(
            "name = \"Classroom laptops\"\n",
            "name = \"Classroom laptops\"\nscripts = [{ path = \"scripts/missing.sh\" }]\n",
            1,
        ))
        .unwrap();
        let v = m.validate_all(&Default::default());
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].code, "file_missing");
        assert_eq!(
            v[0].path.as_deref(),
            Some("config.classroom.scripts[0].path")
        );
    }

    #[test]
    fn format2_rejects_v3_tables() {
        Manifest::parse(&format!("format = 2\n{}\n", v2_minimal_body())).unwrap();
        for t in [
            "[device_defaults]",
            "[[device_config]]\nid=\"a\"\nname=\"a\"",
            "[user_defaults]",
            "[[user_config]]\nid=\"a\"\nname=\"a\"",
            "[[assign]]\nuser_config=\"a\"",
            "[user]\nfallback=\"a\"",
        ] {
            let text = format!("format = 2\n{}\n{t}\n", v2_minimal_body());
            assert!(
                matches!(Manifest::parse(&text), Err(BundleError::Parse(_))),
                "{t}"
            );
        }
    }

    #[test]
    fn format3_rejects_v2_tables() {
        for (t, key) in [
            ("[defaults]", "defaults"),
            ("[[config]]\nid=\"x\"\nname=\"x\"", "config"),
            ("interface = \"full\"", "interface"),
            ("user_config = \"primary\"", "user_config"),
            ("apps.web = []", "web"),
            ("apps.flatpak = []", "flatpak"),
        ] {
            let err = Manifest::parse(&v3_with(t)).unwrap_err().to_string();
            let want = format!("unknown field `{key}`");
            assert!(err.contains(&want), "{t}: {err}");
        }
    }

    #[test]
    fn format_4_is_too_new() {
        assert!(matches!(
            Manifest::parse("format = 4\nversion = 1"),
            Err(BundleError::FormatTooNew { found: 4, max: 3 })
        ));
    }

    #[test]
    fn v2_texts_have_no_user_layer() {
        assert!(Manifest::parse(&crate::testutil::spec_example())
            .unwrap()
            .user_layer
            .is_none());
    }

    // ---- rule resolution ----

    const TEACHER: &str = "0193a0c2-0000-7000-8000-0000000000c1";
    const PRIMARY_CHILD: &str = "0193a0c2-0000-7000-8000-000000000001";
    const SUB: &str = "0193a0c2-0000-7000-8000-0000000000a1";

    fn sso(user: &str, admin: bool) -> (Kind, bool, String) {
        (Kind::Sso, admin, user.to_string())
    }

    fn guest() -> (Kind, bool, String) {
        (Kind::Guest, false, "guest".to_string())
    }

    struct F(IssuerFacts);

    fn facts() -> F {
        F(IssuerFacts {
            sub: SUB.to_string(),
            org: "o".to_string(),
            org_role: None,
            org_nodes: vec![],
            classes: vec![],
            age_band: None,
        })
    }

    impl F {
        fn class(mut self, id: &str) -> F {
            self.0.classes.push(ClassFact {
                id: id.to_string(),
                role: ClassRole::Teacher,
            });
            self
        }
        fn node(mut self, id: &str) -> F {
            self.0.org_nodes.push(id.to_string());
            self
        }
    }

    fn assign(extra: &str) -> Assign {
        let t = format!("user_config = \"x\"\n{extra}");
        toml::from_str(&t).unwrap()
    }

    fn run(rules: &[Assign], dev: &(Kind, bool, String), f: Option<&IssuerFacts>) -> Resolution {
        let d = DeviceFacts {
            kind: dev.0,
            admin: dev.1,
            user: &dev.2,
            device_group: "default",
        };
        resolve(rules, "fb", &d, f)
    }

    #[test]
    fn resolves_spec_example() {
        let m = Manifest::parse(&v3_example()).unwrap();
        let rules = m.user_layer.as_ref().unwrap().rules.clone();
        let cases = [
            (
                sso("t@s.ac.th", false),
                Some(facts().class(TEACHER)),
                "teacher",
                Some(1),
            ),
            (sso("a@s.ac.th", true), None, "teacher", Some(0)),
            (
                sso("k@s.ac.th", false),
                Some(facts().node(PRIMARY_CHILD)),
                "primary",
                Some(2),
            ),
            (guest(), None, "primary", None),
        ];
        for (dev, f, want, rule) in cases {
            let d = DeviceFacts {
                kind: dev.0,
                admin: dev.1,
                user: &dev.2,
                device_group: "default",
            };
            let r = resolve(&rules, "primary", &d, f.as_ref().map(|f| &f.0));
            assert_eq!((r.user_config.as_str(), r.rule), (want, rule), "{}", dev.2);
        }
    }

    #[test]
    fn fact_conditions_need_facts() {
        let rules = [assign(&format!("sub = [\"{SUB}\"]"))];
        let f = facts();
        assert_eq!(run(&rules, &sso("a@s", false), Some(&f.0)).rule, Some(0));
        assert_eq!(run(&rules, &sso("a@s", false), None).rule, None);
        let local = (Kind::Local, false, "a".to_string());
        assert_eq!(run(&rules, &local, Some(&f.0)).user_config, "fb");
        assert_eq!(run(&rules, &guest(), Some(&f.0)).rule, None);
        // A rule with only a fact condition does not shadow a later plain rule.
        let rules = [assign("org_role = [\"owner\"]"), assign("")];
        assert_eq!(run(&rules, &sso("a@s", false), None).rule, Some(1));
    }

    #[test]
    fn fact_values_must_be_present_and_equal() {
        let mut f = facts();
        let rules = [assign("org_role = [\"owner\"]")];
        assert_eq!(run(&rules, &sso("a@s", false), Some(&f.0)).rule, None);
        f.0.org_role = Some(OrgRole::Owner);
        assert_eq!(run(&rules, &sso("a@s", false), Some(&f.0)).rule, Some(0));
        let rules = [assign("age_band = [\"13-17\"]")];
        assert_eq!(run(&rules, &sso("a@s", false), Some(&f.0)).rule, None);
        f.0.age_band = Some(AgeBand::Teen);
        assert_eq!(run(&rules, &sso("a@s", false), Some(&f.0)).rule, Some(0));
        let rules = [assign("class_role = [\"student\"]")];
        assert_eq!(run(&rules, &sso("a@s", false), Some(&f.0)).rule, None);
    }

    #[test]
    fn empty_list_never_matches() {
        for c in [
            "kind = []",
            "user = []",
            "device_group = []",
            "org_role = []",
            "class_role = []",
            "class = []",
            "org_node = []",
            "age_band = []",
            "sub = []",
        ] {
            let rules = [assign(c)];
            let f = facts();
            assert_eq!(
                run(&rules, &sso("a@s", false), Some(&f.0)).rule,
                None,
                "{c}"
            );
            assert_eq!(run(&rules, &sso("a@s", false), None).rule, None, "{c}");
        }
    }

    #[test]
    fn user_condition_is_case_insensitive() {
        let rules = [assign("user = [\"alice@s.ac.th\"]")];
        assert_eq!(
            run(&rules, &sso("Alice@S.ac.th", false), None).rule,
            Some(0)
        );
        let rules = [assign("user = [\"Alice@S.ac.th\"]")];
        assert_eq!(
            run(&rules, &sso("alice@s.ac.th", false), None).rule,
            Some(0)
        );
        assert_eq!(run(&rules, &sso("bob@s.ac.th", false), None).rule, None);
    }

    #[test]
    fn user_condition_ignores_only_ascii_case() {
        let rules = [assign("user = [\"kim@s.ac.th\"]")];
        assert_eq!(
            run(&rules, &sso("\u{212A}im@s.ac.th", false), None).rule,
            None
        );
        assert_eq!(run(&rules, &sso("KIM@s.ac.th", false), None).rule, Some(0));
    }

    #[test]
    fn and_of_conditions_or_within_lists() {
        let rules = [assign("kind = [\"sso\", \"local\"]\nadmin = false")];
        assert_eq!(run(&rules, &sso("a@s", false), None).rule, Some(0));
        assert_eq!(run(&rules, &sso("a@s", true), None).rule, None);
        let local = (Kind::Local, false, "a".to_string());
        assert_eq!(run(&rules, &local, None).rule, Some(0));
        assert_eq!(run(&rules, &guest(), None).rule, None);
    }

    #[test]
    fn device_group_condition_uses_the_device_group() {
        let rules = [assign("device_group = [\"exam-room\"]")];
        assert_eq!(run(&rules, &sso("a@s", false), None).rule, None);
    }

    #[test]
    fn rules_file_round_trips_and_filters_by_group() {
        let text = v3_text(
            "[[user_config]]\nid = \"a\"\nname = \"A\"\n\
             [[user_config]]\nid = \"b\"\nname = \"B\"\n\
             [[assign]]\nuser_config = \"b\"\ndevice_group = [\"exam-room\"]\n\
             [[assign]]\nuser_config = \"a\"\nadmin = true\n\
             [user]\nfallback = \"a\"\n",
        );
        let m = Manifest::parse(&text).unwrap();
        let r = UserRules::from_manifest(&m, "default").unwrap();
        assert!(r.rules.iter().all(|a| a
            .device_group
            .as_ref()
            .is_none_or(|g| g.iter().any(|x| x == "default"))));
        assert_eq!(r.rules.len(), 1);
        assert_eq!(r.configs, vec!["a".to_string()]);
        assert_eq!(
            UserRules::from_manifest(&m, "exam-room")
                .unwrap()
                .rules
                .len(),
            2
        );
        let dev = sso("x@s", true);
        let d = DeviceFacts {
            kind: dev.0,
            admin: dev.1,
            user: &dev.2,
            device_group: "default",
        };
        assert_eq!(r.resolve(&d, None).rule, Some(0));
        assert_eq!(
            serde_json::from_str::<UserRules>(&serde_json::to_string(&r).unwrap()).unwrap(),
            r
        );
        assert!(serde_json::from_str::<UserRules>(
            r#"{"group":"g","fallback":"f","rules":[],"configs":[],"x":1}"#
        )
        .is_err());
        let v2 = Manifest::parse(&format!("format = 2\n{}", v2_minimal_body())).unwrap();
        assert!(UserRules::from_manifest(&v2, "default").is_none());
    }

    #[test]
    fn rules_file_none_without_fallback() {
        let m = Manifest::parse(&v3_text("")).unwrap();
        assert!(UserRules::from_manifest(&m, "default").is_none());
    }

    #[test]
    fn guest_resolution() {
        let m = Manifest::parse(&v3_example()).unwrap();
        assert_eq!(guest_user_config(&m, "default").as_deref(), Some("primary"));
        assert_eq!(guest_user_config(&m, "nope"), None);
        let v2 = Manifest::parse(&format!("format = 2\n{}", v2_minimal_body())).unwrap();
        assert_eq!(guest_user_config(&v2, "default").as_deref(), Some("c"));
        assert_eq!(guest_user_config(&v2, "nope"), None);
    }

    #[test]
    fn issuer_facts_ignore_unknown_claims() {
        let f: IssuerFacts = serde_json::from_str(
            r#"{"sub":"s","org":"o","org_role":"member","org_nodes":["n"],
                "classes":[{"id":"c","role":"student","extra":1}],"age_band":"13-17","foo":1}"#,
        )
        .unwrap();
        assert_eq!(f.org_role, Some(OrgRole::Member));
        assert_eq!(f.age_band, Some(AgeBand::Teen));
        assert_eq!(f.classes[0].role, ClassRole::Student);
        let min: IssuerFacts = serde_json::from_str(r#"{"sub":"s","org":"o"}"#).unwrap();
        assert!(min.org_nodes.is_empty() && min.classes.is_empty() && min.org_role.is_none());
    }
}
