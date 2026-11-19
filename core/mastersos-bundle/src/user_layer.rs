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
}
