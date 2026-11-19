//! `mastersos migrate`: rewrite a format 1/2 settings text as `format = 3` with unchanged
//! behaviour (user layer design §6).
//!
//! The semantics come from [`Manifest::parse`]: each Config (or each legacy Group's implied
//! Config) is split key by key into a `[[device_config]]` and a `[[user_config]]` with the same
//! `id` and `name` (design §3), `[defaults]` into `[device_defaults]` and `[user_defaults]`, and
//! one `[[assign]] device_group` rule per Group names the Group's Config; `[user] fallback` is the
//! `default` Group's Config. The text is rewritten with `toml_edit`, so `version`, `issued_at`,
//! `[[trust]]`, `[school]`, `[[device]]` and the `[[group]]` headers keep their comments; the
//! moved keys are written anew and lose theirs.

use serde::Serialize;
use toml_edit::{DocumentMut, Item, Table, Value};

use crate::manifest::*;
use crate::user_layer::*;

/// Why [`to_format3`] gave no text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MigrateError {
    /// The text does not parse as settings (the message says why).
    #[error("{0}")]
    Parse(String),
    /// The text is already `format = 3`.
    #[error("the settings are already format 3; there is nothing to migrate")]
    AlreadyFormat3,
    /// The text parses but cannot be written as format 3 with the same behaviour. It happens
    /// when there is no `default` Group (nothing to name as `[user] fallback`), and when a .deb
    /// id of the `default` Group's Config is defined differently (or as a kiosk app) by another
    /// Group's Config: format 3 installs the fallback's apps on every Device (design §4.6), so
    /// the two would clash (`user_deb_conflict`). It also carries the internal failures, which
    /// would be a migrate bug: the new tables cannot be serialized, or the written text does not
    /// parse back.
    #[error("the settings cannot be written as format 3: {0}")]
    Invalid(String),
}

/// The layer a setting belongs to (design §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Device,
    User,
}

fn script_side(s: &Script) -> Side {
    match s.when {
        When::Apply => Side::Device,
        When::Login => Side::User,
    }
}

fn deb_side(a: &DebApp) -> Side {
    if a.kiosk {
        Side::Device
    } else {
        Side::User
    }
}

fn preset_of(i: Interface) -> Preset {
    match i {
        Interface::Learning => Preset::Learning,
        Interface::Full => Preset::Full,
    }
}

fn dedup(v: &mut Vec<String>) {
    let mut seen = std::collections::BTreeSet::new();
    v.retain(|s| seen.insert(s.clone()));
}

/// `[defaults]` as a Config layer without id, name and drop, so it splits like one.
fn defaults_layer(d: &Defaults) -> ConfigLayer {
    ConfigLayer {
        id: String::new(),
        name: String::new(),
        interface: d.interface,
        login_methods: d.login_methods.clone(),
        local_users_admin: d.local_users_admin,
        it_account: d.it_account.clone(),
        wifi: d.wifi.clone(),
        apps: d.apps.clone(),
        printers: d.printers.clone(),
        scanners: d.scanners.clone(),
        chrome_policy: d.chrome_policy.clone(),
        chrome: d.chrome.clone(),
        support: d.support.clone(),
        update_channel: d.update_channel.clone(),
        files: d.files.clone(),
        downloads: d.downloads.clone(),
        scripts: d.scripts.clone(),
        drop: Drop::default(),
        legacy_browser: false,
    }
}

/// `c` split into its device keys and its user keys. `d` is the `[defaults]` it inherits from:
/// a dropped script or .deb goes to the layer of the inherited entry it names (the device layer
/// when it names none), and an own entry that replaces an inherited entry of the other layer
/// drops that entry there, as replacing did. `legacy` leaves out the values a legacy Group
/// always implies (`login_methods = []`, `local_users_admin = false`; there are no defaults).
fn split(c: &ConfigLayer, d: &Defaults, legacy: bool) -> (DeviceConfigLayer, UserConfigLayer) {
    let mut dev_drop = DeviceDrop {
        wifi: c.drop.wifi.clone(),
        apps: DeviceDropApps {
            kiosk: c.drop.apps.kiosk.clone(),
            deb: Vec::new(),
        },
        printers: c.drop.printers.clone(),
        scanners: c.drop.scanners.clone(),
        files: c.drop.files.clone(),
        downloads: c.drop.downloads.clone(),
        scripts: Vec::new(),
    };
    let mut user_drop = UserDrop {
        apps: UserDropApps {
            web: c.drop.apps.web.clone(),
            flatpak: c.drop.apps.flatpak.clone(),
            deb: Vec::new(),
        },
        chrome_policy: c.drop.chrome_policy.clone(),
        scripts: Vec::new(),
        allow: Vec::new(),
        deny: Vec::new(),
    };
    let inherited_script = |p: &str| d.scripts.iter().find(|s| s.path == p).map(script_side);
    for p in &c.drop.scripts {
        match inherited_script(p) {
            Some(Side::User) => user_drop.scripts.push(p.clone()),
            _ => dev_drop.scripts.push(p.clone()),
        }
    }
    for id in &c.drop.apps.deb {
        match d.apps.deb.get(id).map(deb_side) {
            Some(Side::User) => user_drop.apps.deb.push(id.clone()),
            _ => dev_drop.apps.deb.push(id.clone()),
        }
    }
    for s in &c.scripts {
        match inherited_script(&s.path) {
            Some(Side::User) if script_side(s) == Side::Device => {
                user_drop.scripts.push(s.path.clone())
            }
            Some(Side::Device) if script_side(s) == Side::User => {
                dev_drop.scripts.push(s.path.clone())
            }
            _ => {}
        }
    }
    for (id, a) in &c.apps.deb {
        match d.apps.deb.get(id).map(deb_side) {
            Some(Side::User) if deb_side(a) == Side::Device => user_drop.apps.deb.push(id.clone()),
            Some(Side::Device) if deb_side(a) == Side::User => dev_drop.apps.deb.push(id.clone()),
            _ => {}
        }
    }
    for v in [
        &mut dev_drop.scripts,
        &mut dev_drop.apps.deb,
        &mut user_drop.scripts,
        &mut user_drop.apps.deb,
    ] {
        dedup(v);
    }

    let scripts = |side: Side| -> Vec<Script> {
        c.scripts
            .iter()
            .filter(|s| script_side(s) == side)
            .cloned()
            .collect()
    };
    // Legacy `mode = "browser"`: no Flatpak and no .deb at all, kiosk ones included, on either
    // side (design §6, ruling R18): today's agent runs no .deb app for it. Kiosk apps stay.
    let installs = !c.legacy_browser;
    let device = DeviceConfigLayer {
        id: c.id.clone(),
        name: c.name.clone(),
        login_methods: c
            .login_methods
            .clone()
            .filter(|l| !(legacy && l.is_empty())),
        local_users_admin: c.local_users_admin.filter(|a| !(legacy && !a)),
        it_account: c.it_account.clone(),
        wifi: c.wifi.clone(),
        apps: DeviceApps {
            kiosk: c.apps.kiosk.clone(),
            deb: c
                .apps
                .deb
                .iter()
                .filter(|(_, a)| installs && a.kiosk)
                .map(|(k, a)| (k.clone(), a.clone()))
                .collect(),
            ubuntu_mirror: c.apps.ubuntu_mirror.clone(),
        },
        printers: c.printers.clone(),
        scanners: c.scanners.clone(),
        chrome: c.chrome.clone(),
        support: c.support.clone(),
        update_channel: c.update_channel.clone(),
        files: c.files.clone(),
        downloads: c.downloads.clone(),
        scripts: scripts(Side::Device),
        drop: dev_drop,
    };
    let user = UserConfigLayer {
        id: c.id.clone(),
        name: c.name.clone(),
        preset: c.interface.map(preset_of),
        allow: Vec::new(),
        deny: Vec::new(),
        apps: UserApps {
            web: c.apps.web.clone(),
            flatpak: if installs {
                c.apps.flatpak.clone()
            } else {
                Vec::new()
            },
            deb: if installs {
                c.apps
                    .deb
                    .iter()
                    .filter(|(_, a)| !a.kiosk)
                    .map(|(k, a)| (k.clone(), a.clone()))
                    .collect()
            } else {
                Default::default()
            },
        },
        chrome_policy: c.chrome_policy.clone(),
        scripts: scripts(Side::User),
        home: None,
        drop: user_drop,
    };
    (device, user)
}

/// The tables `to_format3` writes, in this order.
#[derive(Serialize)]
struct Layers {
    #[serde(skip_serializing_if = "Option::is_none")]
    device_defaults: Option<DeviceDefaults>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    device_config: Vec<DeviceConfigLayer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_defaults: Option<UserDefaults>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_config: Vec<UserConfigLayer>,
    assign: Vec<Assign>,
    user: UserSection,
}

fn layers(m: &Manifest) -> Result<Layers, MigrateError> {
    let fallback = m
        .groups
        .iter()
        .find(|g| g.id == "default")
        .map(|g| g.config.clone())
        .ok_or_else(|| {
            MigrateError::Invalid(
                "there is no Group with id \"default\", whose Config would be [user] fallback"
                    .into(),
            )
        })?;
    let legacy = m.shape == Shape::Legacy;
    let none = Defaults::default();
    let d = m.defaults.as_ref().unwrap_or(&none);
    let (dd, ud) = split(&defaults_layer(d), &none, legacy);
    let device_defaults = DeviceDefaults {
        login_methods: dd.login_methods,
        local_users_admin: dd.local_users_admin,
        it_account: dd.it_account,
        wifi: dd.wifi,
        apps: dd.apps,
        printers: dd.printers,
        scanners: dd.scanners,
        chrome: dd.chrome,
        support: dd.support,
        update_channel: dd.update_channel,
        files: dd.files,
        downloads: dd.downloads,
        scripts: dd.scripts,
    };
    let user_defaults = UserDefaults {
        preset: ud.preset,
        allow: Vec::new(),
        deny: Vec::new(),
        apps: ud.apps,
        chrome_policy: ud.chrome_policy,
        scripts: ud.scripts,
        home: None,
    };
    let (device_config, user_config) = m.configs.iter().map(|c| split(c, d, legacy)).unzip();
    let assign = m
        .groups
        .iter()
        .map(|g| Assign {
            user_config: g.config.clone(),
            kind: None,
            admin: None,
            user: None,
            device_group: Some(vec![g.id.clone()]),
            org_role: None,
            class_role: None,
            class: None,
            org_node: None,
            age_band: None,
            sub: None,
        })
        .collect();
    Ok(Layers {
        device_defaults: (device_defaults != DeviceDefaults::default()).then_some(device_defaults),
        device_config,
        user_defaults: (user_defaults != UserDefaults::default()).then_some(user_defaults),
        user_config,
        assign,
        user: UserSection { fallback },
    })
}

/// Lists of tables become inline arrays, and `drop`, `chrome`, `support` and `it_account`
/// dotted keys (`drop.apps.deb = [...]`), as people write them.
fn tidy(item: &mut Item, top: bool) {
    match item {
        Item::ArrayOfTables(a) if !top => {
            let arr = std::mem::take(a).into_array();
            *item = Item::Value(Value::Array(arr));
        }
        Item::ArrayOfTables(a) => {
            for t in a.iter_mut() {
                tidy_layer(t);
            }
        }
        Item::Table(t) if top => tidy_layer(t),
        Item::Table(t) => {
            if !t.is_dotted() {
                t.decor_mut().set_prefix("\n");
            }
            tidy_entries(t);
        }
        _ => {}
    }
}

/// [`tidy`] on every entry of `t`; a key whose value became an inline array gets the usual
/// spacing around `=` back.
fn tidy_entries(t: &mut Table) {
    for (mut k, v) in t.iter_mut() {
        let was_tables = v.is_array_of_tables();
        tidy(v, false);
        if was_tables {
            k.leaf_decor_mut().clear();
        }
    }
}

fn tidy_layer(t: &mut Table) {
    t.decor_mut().set_prefix("\n");
    tidy_entries(t);
    for (k, v) in t.iter_mut() {
        if let ("drop" | "chrome" | "support" | "it_account", Item::Table(st)) = (k.get(), v) {
            dot(st);
        }
    }
}

fn dot(t: &mut Table) {
    t.set_dotted(true);
    for (_, v) in t.iter_mut() {
        if let Item::Table(st) = v {
            dot(st);
        }
    }
}

/// Number every table under `item` in document order, so that `Display` prints them so.
fn number(item: &mut Item, n: &mut isize) {
    match item {
        Item::Table(t) => number_table(t, n),
        Item::ArrayOfTables(a) => {
            for t in a.iter_mut() {
                number_table(t, n);
            }
        }
        _ => {}
    }
}

fn number_table(t: &mut Table, n: &mut isize) {
    t.set_position(Some(*n));
    *n += 1;
    for (_, v) in t.iter_mut() {
        number(v, n);
    }
}

/// Keep only `id` and `name` of a legacy `[[group]]` and add `config`.
fn slim_group(t: &mut dyn toml_edit::TableLike, config: &str) {
    let extra: Vec<String> = t
        .iter()
        .map(|(k, _)| k.to_string())
        .filter(|k| k != "id" && k != "name")
        .collect();
    for k in extra {
        t.remove(&k);
    }
    t.insert("config", toml_edit::value(config));
}

/// The format 1/2 text `text` as `format = 3`, with the same behaviour on every Device and for
/// every login (design §6): Groups keep their Config as device config, and one rule per Group
/// gives everyone signing in on it the user config of the same id. The fallback's Flatpaks and
/// non-kiosk .deb apps are installed on every Device too (design §4.6); nobody sees them unless
/// their user config lists them. `home` is not written: it follows the preset, as today.
pub fn to_format3(text: &str) -> Result<String, MigrateError> {
    if let Ok(doc) = text.parse::<toml::Table>() {
        if doc.get("format").and_then(toml::Value::as_integer) == Some(3) {
            return Err(MigrateError::AlreadyFormat3);
        }
    }
    let m = Manifest::parse(text).map_err(|e| MigrateError::Parse(e.to_string()))?;
    let mut doc: DocumentMut = text
        .parse()
        .map_err(|e: toml_edit::TomlError| MigrateError::Parse(e.to_string()))?;
    let generated = toml::to_string(&layers(&m)?)
        .map_err(|e| MigrateError::Invalid(format!("cannot write the tables: {e}")))?;
    let mut generated: DocumentMut = generated
        .parse()
        .map_err(|e: toml_edit::TomlError| MigrateError::Invalid(e.to_string()))?;

    let root = doc.as_table_mut();
    // `trust` and `school` keep their written order; everything else is placed.
    let head: Vec<String> = root
        .iter()
        .map(|(k, _)| k.to_string())
        .filter(|k| k == "trust" || k == "school")
        .collect();
    root.remove("defaults");
    root.remove("config");
    if m.shape == Shape::Legacy {
        let configs: Vec<&str> = m.groups.iter().map(|g| g.config.as_str()).collect();
        let mut i = 0;
        let mut slim = |t: &mut dyn toml_edit::TableLike| -> Result<(), MigrateError> {
            let config = configs.get(i).ok_or_else(|| {
                MigrateError::Invalid("the [[group]] tables do not match the parsed Groups".into())
            })?;
            slim_group(t, config);
            i += 1;
            Ok(())
        };
        match root.get_mut("group") {
            Some(Item::ArrayOfTables(a)) => {
                for t in a.iter_mut() {
                    slim(t)?;
                }
            }
            Some(Item::Value(Value::Array(a))) => {
                for v in a.iter_mut() {
                    if let Some(t) = v.as_inline_table_mut() {
                        slim(t)?;
                        t.fmt();
                    }
                }
            }
            _ => {}
        }
    }
    match root.get_mut("format") {
        Some(Item::Value(v)) => {
            let decor = v.decor().clone();
            let mut n = Value::from(3i64);
            *n.decor_mut() = decor;
            *v = n;
        }
        _ => {
            root.insert("format", toml_edit::value(3i64));
        }
    }
    root.sort_values_by(|a, _, b, _| (a.get() != "format").cmp(&(b.get() != "format")));
    for key in [
        "device_defaults",
        "device_config",
        "user_defaults",
        "user_config",
        "assign",
        "user",
    ] {
        if let Some(mut item) = generated.remove(key) {
            tidy(&mut item, true);
            root.insert(key, item);
        }
    }
    let order = head.iter().map(String::as_str).chain([
        "device_defaults",
        "device_config",
        "group",
        "device",
        "user_defaults",
        "user_config",
        "assign",
        "user",
    ]);
    let mut n = 1;
    for key in order {
        if let Some(item) = root.get_mut(key) {
            number(item, &mut n);
        }
    }
    let out = doc.to_string();

    // The result must read back, and must not make one Group install two .deb apps of one id.
    let new = Manifest::parse(&out)
        .map_err(|e| MigrateError::Invalid(format!("the migrated text does not parse: {e}")))?;
    let mut issues = Vec::new();
    validate_user_layer(&new, &mut issues);
    if let Some(l) = issues.iter().find(|l| l.code == "user_deb_conflict") {
        return Err(MigrateError::Invalid(l.message.clone()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::testutil::{legacy_spec_example, spec_example, spec_example_v3};
    use crate::{
        install_union, user_config, Config, DeviceFacts, Interface, Kind, Manifest, UserConfig,
        UserRules, V3Manifest, When,
    };

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    /// The format 1 new-shape example: three Configs, no `[defaults]`.
    fn example_v2() -> String {
        spec_example()
    }

    fn v3_example() -> String {
        spec_example_v3()
    }

    /// Format 2 with `[defaults]` and `drop` on both layers. Config `staff` drops an apply
    /// script, a login script, a kiosk .deb, a printer and a Chrome policy, and shadows a login
    /// script with an apply one and a non-kiosk .deb with a kiosk one; `lab` shadows a kiosk .deb
    /// with a non-kiosk one and drops a non-kiosk .deb and an unknown network; `student` (the
    /// default Group's) drops `zoom`, so no Group reaches two definitions of it.
    fn example_v2_with_defaults_and_drop() -> String {
        format!(
            r#"format = 2
version = 3

[[trust]]
id = "school-2026"
alg = "ed25519"
public_key = "{KEY}"

[school]
allowed_domains = ["school.ac.th"]

[defaults]
interface = "learning"
login_methods = ["sso", "guest"]
wifi = [{{ ssid = "Campus", psk = "secret:defaults-campus--psk" }}]
printers = [{{ name = "Library", uri = "ipp://10.0.0.7/ipp/print" }}]
chrome_policy = {{ URLBlocklist = ["tiktok.com"], HomepageLocation = "https://school.example" }}
apps.web = [{{ name = "Classroom", url = "https://classroom.google.com" }}]
apps.flatpak = ["org.libreoffice.LibreOffice"]
scripts = [
  {{ path = "scripts/inventory.sh" }},
  {{ path = "scripts/greet.sh", when = "login" }},
  {{ path = "scripts/shared.sh", when = "login" }},
]

[defaults.apps.deb.zoom]
name = "Zoom"
url = "https://x.example/zoom.deb"

[defaults.apps.deb.exam]
name = "Exam"
url = "https://x.example/exam.deb"
kiosk = true

[[config]]
id = "staff"
name = "Staff"
interface = "full"
scripts = [{{ path = "scripts/shared.sh" }}]
apps.deb.zoom = {{ name = "Zoom Room", url = "https://x.example/zoom-room.deb", kiosk = true }}
drop.scripts = ["scripts/inventory.sh", "scripts/greet.sh"]
drop.printers = ["Library"]
drop.chrome_policy = ["URLBlocklist"]
drop.apps.deb = ["exam"]
drop.apps.flatpak = ["org.libreoffice.LibreOffice"]

[[config]]
id = "lab"
name = "Lab"
apps.deb.exam = {{ name = "Exam Practice", url = "https://x.example/exam-practice.deb" }}
apps.flatpak = ["org.gimp.GIMP"]
drop.apps.deb = ["zoom"]
drop.wifi = ["Nowhere"]

[[config]]
id = "student"
name = "Student"
drop.apps.deb = ["zoom"]

[[group]]
id = "staff"
name = "Staff"
config = "staff"

[[group]]
id = "lab"
name = "Lab"
config = "lab"

[[group]]
id = "lab-2"
name = "Second lab"
config = "lab"

[[group]]
id = "default"
name = "Ungrouped"
config = "student"
"#
        )
    }

    /// The legacy example whose `mode = "browser"` Group `cart-g3` also lists a Flatpak, a
    /// non-kiosk .deb and a kiosk .deb.
    fn example_legacy_browser() -> String {
        let text = legacy_spec_example();
        let mode = "mode = \"browser\"\n";
        assert_eq!(text.matches(mode).count(), 1);
        text.replacen(
            mode,
            &format!(
                "{mode}apps = {{ flatpak = [\"org.gnome.Calculator\"], deb = {{ \
                 calc = {{ name = \"Calc\", url = \"https://x.example/calc.deb\" }}, \
                 quiz = {{ name = \"Quiz\", url = \"https://x.example/quiz.deb\", kiosk = true }} }} }}\n"
            ),
            1,
        )
    }

    /// [`example_v2`] with comments on `version`, `[[trust]]`, `[school]` and a `[[device]]`.
    fn with_school_comment() -> String {
        let text = example_v2()
            .replacen("[school]\n", "# the school\n[school]\n", 1)
            .replacen("[[trust]]\n", "# signing keys\n[[trust]]\n", 1)
            .replacen("version = 42\n", "version = 42 # bumped on publish\n", 1)
            .replacen(
                "[[device]]\nserial = \"XYZ9876\"",
                "# the lost one\n[[device]]\nserial = \"XYZ9876\"",
                1,
            );
        assert_eq!(text.matches('#').count(), 4);
        text
    }

    /// Every `files/…` and `scripts/…` path the text names, as the bundle would carry them.
    fn files_of(text: &str) -> BTreeSet<String> {
        text.split('"')
            .filter(|s| s.starts_with("files/") || s.starts_with("scripts/"))
            .map(String::from)
            .collect()
    }

    fn dev(kind: Kind, admin: bool, group: &str) -> DeviceFacts<'_> {
        DeviceFacts {
            kind,
            admin,
            user: "someone",
            device_group: group,
        }
    }

    /// Every field of a Device's effective Config that the device layer decides: all but the
    /// mode, web apps, Flatpaks, non-kiosk .deb apps, Chrome policy, login scripts and the
    /// legacy browser mark (all user layer; Flatpaks and non-kiosk .deb apps are installed as
    /// the union over reachable user configs, which a format 1/2 Config does not have).
    fn device_part(c: &Config) -> Config {
        let mut c = c.clone();
        c.interface = Interface::default();
        c.apps.web.clear();
        c.apps.flatpak.clear();
        c.apps.deb.retain(|_, a| a.kiosk);
        c.chrome_policy.clear();
        c.scripts.retain(|s| s.when == When::Apply);
        // The agent runs no .deb app at all, kiosk ones included, for a legacy browser Config
        // (ruling R18); the migrated device config writes none.
        if c.legacy_browser {
            c.apps.deb.clear();
        }
        c.legacy_browser = false;
        c
    }

    fn v3(text: &str) -> V3Manifest {
        toml::from_str(text).unwrap()
    }

    #[test]
    fn migrate_preserves_every_group() {
        let mut browser_debs_checked = false;
        for text in [
            example_v2(),
            example_v2_with_defaults_and_drop(),
            example_legacy_browser(),
            legacy_spec_example(),
        ] {
            let old = Manifest::parse(&text).unwrap();
            let out = to_format3(&text).unwrap();
            let new = Manifest::parse(&out).unwrap();
            assert_eq!(new.format, 3);
            let issues = new.validate_all(&files_of(&text));
            assert!(issues.is_empty(), "{issues:?}\n{out}");
            for g in &old.groups {
                let o = old.effective_of_group(&g.id).unwrap();
                let n = new.effective_of_group(&g.id).unwrap();
                assert_eq!(device_part(&o), device_part(&n), "{}\n{out}", g.id);
                if o.legacy_browser {
                    // `device_part` hides it: the migrated device config itself has no .deb.
                    browser_debs_checked |= !o.apps.deb.is_empty();
                    let written = new.config_of_group(&g.id).unwrap();
                    assert!(written.apps.deb.is_empty(), "{}\n{out}", g.id);
                    assert!(n.apps.deb.is_empty(), "{}\n{out}", g.id);
                }
                // A legacy `mode = "browser"` Group becomes preset learning without Flatpak or
                // non-kiosk .deb apps (design §6); `UserConfig::implied` already leaves those out
                // and only marks it `legacy_browser`, which a format 3 user config never is.
                let mut want = UserConfig::implied(&o);
                want.legacy_browser = false;
                for kind in [Kind::Sso, Kind::Local, Kind::Guest] {
                    for admin in [false, true] {
                        let r = UserRules::from_manifest(&new, &g.id)
                            .unwrap()
                            .resolve(&dev(kind, admin, &g.id), None);
                        assert_eq!(
                            user_config(&new, &r.user_config).unwrap(),
                            want,
                            "{} {kind:?}\n{out}",
                            g.id
                        );
                    }
                }
            }
        }
        assert!(
            browser_debs_checked,
            "no legacy browser Group with .deb apps was checked"
        );
    }

    #[test]
    fn refuses_format3() {
        assert!(matches!(
            to_format3(&v3_example()),
            Err(MigrateError::AlreadyFormat3)
        ));
    }

    #[test]
    fn migrating_twice_is_already_format3() {
        for text in [example_v2(), example_v2_with_defaults_and_drop()] {
            let once = to_format3(&text).unwrap();
            assert_eq!(to_format3(&once), Err(MigrateError::AlreadyFormat3));
        }
    }

    #[test]
    fn refuses_what_does_not_parse() {
        assert!(matches!(
            to_format3("version = [1"),
            Err(MigrateError::Parse(_))
        ));
        assert!(matches!(
            to_format3("version = 1\n[[config]]\nid = \"a\"\nname = \"A\"\nnope = 1\n"),
            Err(MigrateError::Parse(_))
        ));
    }

    #[test]
    fn keeps_comments_on_school() {
        let out = to_format3(&with_school_comment()).unwrap();
        let issues = Manifest::parse(&out)
            .unwrap()
            .validate_all(&files_of(&with_school_comment()));
        assert!(issues.is_empty(), "{issues:?}");
        assert!(out.contains("# the school\n[school]"), "{out}");
        assert!(out.contains("# signing keys\n[[trust]]"), "{out}");
        assert!(out.contains("version = 42 # bumped on publish"), "{out}");
        assert!(out.contains("# the lost one\n[[device]]"), "{out}");
    }

    #[test]
    fn format_line_comes_first() {
        // Format 1 without the line, and format 2 with it.
        for text in [example_v2(), example_v2_with_defaults_and_drop()] {
            let out = to_format3(&text).unwrap();
            assert!(out.starts_with("format = 3\n"), "{out}");
            assert_eq!(out.matches("format = ").count(), 1, "{out}");
        }
    }

    #[test]
    fn device_tables_then_groups_then_user_tables() {
        let out = to_format3(&example_v2_with_defaults_and_drop()).unwrap();
        let at = |h: &str| out.find(h).unwrap_or_else(|| panic!("{h} missing\n{out}"));
        let order = [
            "[[trust]]",
            "[school]",
            "[device_defaults]",
            "[[device_config]]",
            "[[group]]",
            "[user_defaults]",
            "[[user_config]]",
            "[[assign]]",
            "[user]",
        ];
        for w in order.windows(2) {
            assert!(at(w[0]) < at(w[1]), "{} before {}\n{out}", w[0], w[1]);
        }
        // Written tables are spaced like hand-written ones.
        assert!(out.contains("\n\n[device_defaults]\n"), "{out}");
        assert!(out.contains("\nscripts = [{ path"), "{out}");
        assert!(out.contains("\ndrop.apps.deb = [\"exam\"]\n"), "{out}");
        // Deterministic.
        assert_eq!(
            to_format3(&example_v2_with_defaults_and_drop()).unwrap(),
            out
        );
    }

    #[test]
    fn one_rule_per_group_and_fallback_of_default() {
        let doc = v3(&to_format3(&example_v2_with_defaults_and_drop()).unwrap());
        let rules: Vec<(&str, Vec<String>)> = doc
            .assign
            .iter()
            .map(|r| (r.user_config.as_str(), r.device_group.clone().unwrap()))
            .collect();
        assert_eq!(
            rules,
            [
                ("staff", vec!["staff".to_string()]),
                ("lab", vec!["lab".to_string()]),
                ("lab", vec!["lab-2".to_string()]),
                ("student", vec!["default".to_string()]),
            ]
        );
        assert!(doc.assign.iter().all(|r| r.kind.is_none()
            && r.admin.is_none()
            && r.user.is_none()
            && r.org_role.is_none()));
        assert_eq!(doc.user.unwrap().fallback, "student");
        let ids: Vec<&str> = doc.user_config.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["staff", "lab", "student"]);
        let ids: Vec<&str> = doc.device_config.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["staff", "lab", "student"]);
        assert!(doc.user_config.iter().all(|c| c.home.is_none()));
    }

    /// R9: a non-default Group installs its own Config's Flatpaks and non-kiosk .deb apps plus
    /// the fallback's (the default Group's Config), in that order.
    #[test]
    fn install_set_is_own_plus_fallback() {
        let text = example_v2_with_defaults_and_drop();
        let old = Manifest::parse(&text).unwrap();
        let new = Manifest::parse(&to_format3(&text).unwrap()).unwrap();
        let fallback = old.effective_of_group("default").unwrap();
        for g in old.groups.iter().filter(|g| g.id != "default") {
            let own = old.effective_of_group(&g.id).unwrap();
            let mut flatpak = own.apps.flatpak.clone();
            for f in &fallback.apps.flatpak {
                if !flatpak.contains(f) {
                    flatpak.push(f.clone());
                }
            }
            let mut deb: std::collections::BTreeMap<_, _> = fallback.apps.deb.clone();
            deb.extend(own.apps.deb.clone());
            deb.retain(|_, a| !a.kiosk);
            assert_eq!(install_union(&new, &g.id), (flatpak, deb), "{}", g.id);
        }
        let (flatpak, deb) = install_union(&new, "lab");
        assert_eq!(flatpak, ["org.libreoffice.LibreOffice", "org.gimp.GIMP"]);
        assert_eq!(deb.keys().collect::<Vec<_>>(), ["exam"]);
    }

    #[test]
    fn keys_land_in_their_layer() {
        let doc = v3(&to_format3(&example_v2_with_defaults_and_drop()).unwrap());
        let dd = doc.device_defaults.as_ref().unwrap();
        let ud = doc.user_defaults.as_ref().unwrap();
        assert_eq!(dd.login_methods.as_ref().unwrap().len(), 2);
        assert_eq!(dd.wifi[0].ssid, "Campus");
        assert_eq!(dd.printers[0].name, "Library");
        let paths = |s: &[crate::Script]| s.iter().map(|s| s.path.clone()).collect::<Vec<_>>();
        assert_eq!(paths(&dd.scripts), ["scripts/inventory.sh"]);
        assert_eq!(dd.apps.deb.keys().collect::<Vec<_>>(), ["exam"]);
        assert_eq!(ud.preset, Some(crate::Preset::Learning));
        assert_eq!(
            paths(&ud.scripts),
            ["scripts/greet.sh", "scripts/shared.sh"]
        );
        assert_eq!(ud.apps.deb.keys().collect::<Vec<_>>(), ["zoom"]);
        assert_eq!(ud.apps.flatpak, ["org.libreoffice.LibreOffice"]);
        assert_eq!(ud.apps.web[0].name, "Classroom");
        assert_eq!(ud.chrome_policy.len(), 2);

        let staff_d = &doc.device_config[0];
        let staff_u = &doc.user_config[0];
        assert_eq!(staff_u.preset, Some(crate::Preset::Full));
        // The kiosk .deb stays on the device; the apply script too.
        assert!(staff_d.apps.deb["zoom"].kiosk);
        assert!(staff_u.apps.deb.is_empty());
        assert_eq!(paths(&staff_d.scripts), ["scripts/shared.sh"]);
        assert!(staff_u.scripts.is_empty());
        // Drops split by the layer of the inherited entry; shadowing across layers drops the
        // other layer's inherited entry.
        assert_eq!(staff_d.drop.scripts, ["scripts/inventory.sh"]);
        assert_eq!(
            staff_u.drop.scripts,
            ["scripts/greet.sh", "scripts/shared.sh"]
        );
        assert_eq!(staff_d.drop.printers, ["Library"]);
        assert_eq!(staff_d.drop.apps.deb, ["exam"]);
        assert_eq!(staff_u.drop.apps.deb, ["zoom"]);
        assert_eq!(staff_u.drop.chrome_policy, ["URLBlocklist"]);
        assert_eq!(staff_u.drop.apps.flatpak, ["org.libreoffice.LibreOffice"]);

        let lab_d = &doc.device_config[1];
        let lab_u = &doc.user_config[1];
        assert!(!lab_u.apps.deb["exam"].kiosk);
        assert!(lab_d.apps.deb.is_empty());
        assert_eq!(lab_d.drop.apps.deb, ["exam"]);
        assert_eq!(lab_u.drop.apps.deb, ["zoom"]);
        // A dropped name that matches nothing goes to the device side.
        assert_eq!(lab_d.drop.wifi, ["Nowhere"]);
        assert_eq!(lab_u.apps.flatpak, ["org.gimp.GIMP"]);
        assert!(lab_u.preset.is_none());
    }

    #[test]
    fn legacy_groups_become_configs() {
        let out = to_format3(&example_legacy_browser()).unwrap();
        let doc = v3(&out);
        let groups: Vec<(&str, &str)> = doc
            .groups
            .iter()
            .map(|g| (g.id.as_str(), g.config.as_str()))
            .collect();
        assert_eq!(
            groups,
            [
                ("teacher", "teacher"),
                ("cart-g3", "cart-g3"),
                ("default", "default")
            ]
        );
        let cart_d = &doc.device_config[1];
        let cart_u = &doc.user_config[1];
        assert_eq!(cart_u.id, "cart-g3");
        assert_eq!(cart_u.preset, Some(crate::Preset::Learning));
        // Browser mode: no Flatpak and no .deb on either side, the kiosk one included (R18).
        assert!(cart_u.apps.flatpak.is_empty() && cart_u.apps.deb.is_empty());
        assert!(cart_d.apps.deb.is_empty());
        assert_eq!(cart_d.downloads.len(), 1);
        let teacher_u = &doc.user_config[0];
        assert_eq!(teacher_u.preset, Some(crate::Preset::Full));
        assert_eq!(teacher_u.apps.flatpak.len(), 2);
        assert_eq!(teacher_u.scripts[0].when, When::Login);
        assert_eq!(doc.user.unwrap().fallback, "default");
        assert!(!out.contains("mode ="), "{out}");
    }

    #[test]
    fn secret_references_move_unchanged() {
        let text = example_v2_with_defaults_and_drop().replacen(
            "login_methods = [\"sso\", \"guest\"]\n",
            "login_methods = [\"sso\", \"guest\"]\n\
             it_account = { password_hash = \"secret:defaults-it--password_hash\" }\n",
            1,
        );
        let text = text.replacen(
            "id = \"lab\"\nname = \"Lab\"\n",
            "id = \"lab\"\nname = \"Lab\"\n\
             wifi = [{ ssid = \"Lab\", psk = \"secret:lab-lab--psk\" }]\n",
            1,
        );
        let out = to_format3(&text).unwrap();
        let doc = v3(&out);
        let dd = doc.device_defaults.unwrap();
        assert_eq!(
            dd.it_account.unwrap().password_hash,
            "secret:defaults-it--password_hash"
        );
        assert_eq!(
            dd.wifi[0].psk.as_deref(),
            Some("secret:defaults-campus--psk")
        );
        assert_eq!(
            doc.device_config[1].wifi[0].psk.as_deref(),
            Some("secret:lab-lab--psk")
        );
        assert_eq!(out.matches("secret:").count(), 3, "{out}");
        // Migration adds no error: the output has the input's (the reference is not a hash).
        let codes = |t: &str| -> Vec<&'static str> {
            Manifest::parse(t)
                .unwrap()
                .validate_all(&files_of(t))
                .into_iter()
                .map(|l| l.code)
                .collect()
        };
        assert_eq!(codes(&out), codes(&text));
    }

    #[test]
    fn no_default_group_is_invalid() {
        let text = "version = 1\n[[config]]\nid = \"c\"\nname = \"C\"\n\
                    [[group]]\nid = \"g\"\nname = \"G\"\nconfig = \"c\"\n";
        assert!(matches!(to_format3(text), Err(MigrateError::Invalid(_))));
    }

    /// A non-kiosk .deb of the default Group's Config that another Group's Config runs as a
    /// kiosk .deb: format 3 installs the fallback's apps on every Device, so the two clash.
    #[test]
    fn deb_clash_with_the_fallback_is_invalid() {
        let text = "version = 1\n\
             [[config]]\nid = \"c\"\nname = \"C\"\n\
             apps.deb.zoom = { name = \"Zoom\", url = \"https://x.example/z.deb\" }\n\
             [[config]]\nid = \"k\"\nname = \"K\"\n\
             apps.deb.zoom = { name = \"Zoom\", url = \"https://x.example/z.deb\", kiosk = true }\n\
             [[group]]\nid = \"kiosk\"\nname = \"K\"\nconfig = \"k\"\n\
             [[group]]\nid = \"default\"\nname = \"D\"\nconfig = \"c\"\n";
        assert!(Manifest::parse(text).is_ok());
        let e = to_format3(text).unwrap_err();
        assert!(
            matches!(&e, MigrateError::Invalid(m) if m.contains("zoom")),
            "{e:?}"
        );
    }
}
