//! `mastersos explain user` and `mastersos explain device`: offline answers from the local
//! settings text (user layer design §6). Which user config a person gets on each Group, and the
//! rule (with its line in `manifest.toml`) that gave it; which Group, device config, reachable user
//! configs and install set a Device gets.

use mastersos_bundle::check::Locator;
use mastersos_bundle::{
    reachable_user_configs, resolve, select, ClassFact, ClassRole, DeviceFacts, DeviceIdent,
    GroupSource, IssuerFacts, Kind, Manifest, DEFAULT_GROUP,
};
use serde::Serialize;

/// Who signs in, as `explain user` is asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserQuery {
    /// The account kind.
    pub kind: Kind,
    /// Whether the person is an administrator on the Device.
    pub admin: bool,
    /// The login name (`""` matches no `user` condition).
    pub user: String,
    /// The issuer facts; `None` when the account is not `sso` or no fact was given.
    pub facts: Option<IssuerFacts>,
}

/// What one Group gives the person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Explained {
    /// The Group id.
    pub group: String,
    /// The user config the person gets there.
    pub user_config: String,
    /// The index of the matching `[[assign]]` rule; `None` for the fallback and for format 1/2.
    pub rule: Option<usize>,
    /// The 1-based line of that rule's `[[assign]]` header in the text.
    pub line: Option<usize>,
}

/// The classes the `--class` and `--class-role` flags describe. One role applies to every class;
/// otherwise they pair by position. A role with no class left is a class with an unknown id
/// (`""`, matching only `class_role` conditions); a class with no role is an error.
pub fn class_facts(classes: &[String], roles: &[ClassRole]) -> Result<Vec<ClassFact>, String> {
    if roles.len() == 1 && !classes.is_empty() {
        return Ok(classes
            .iter()
            .map(|id| ClassFact {
                id: id.clone(),
                role: roles[0],
            })
            .collect());
    }
    if classes.len() > roles.len() {
        return Err(format!(
            "--class {} has no --class-role: give one --class-role for every class, or one for all of them",
            classes[roles.len()]
        ));
    }
    Ok(roles
        .iter()
        .enumerate()
        .map(|(i, role)| ClassFact {
            id: classes.get(i).cloned().unwrap_or_default(),
            role: *role,
        })
        .collect())
}

/// The user config the person of `q` gets on `group` (every Group in order when `None`; a Group
/// id that does not exist gives nothing). Format 3 evaluates the whole `[[assign]]` list with the
/// Group's id as `device_group`, so `rule` indexes `[[assign]]` and `line` is that rule's header
/// line in `text`; without `[user] fallback` the fallback is `""`. Format 1/2: the Group's Config.
pub fn explain_user(
    m: &Manifest,
    text: &str,
    q: &UserQuery,
    group: Option<&str>,
) -> Vec<Explained> {
    let groups = m
        .groups
        .iter()
        .filter(|g| group.is_none_or(|id| g.id == id));
    let Some(u) = &m.user_layer else {
        return groups
            .map(|g| Explained {
                group: g.id.clone(),
                user_config: g.config.clone(),
                rule: None,
                line: None,
            })
            .collect();
    };
    let fallback = u.fallback.as_deref().unwrap_or("");
    let loc = Locator::new(text);
    groups
        .map(|g| {
            let device = DeviceFacts {
                kind: q.kind,
                admin: q.admin,
                user: &q.user,
                device_group: &g.id,
            };
            let r = resolve(&u.rules, fallback, &device, q.facts.as_ref());
            let line = r.rule.and_then(|i| {
                let span = loc.as_ref()?.locate(&format!("assign[{i}]"))?;
                Some(span.line as usize)
            });
            Explained {
                group: g.id.clone(),
                user_config: r.user_config,
                rule: r.rule,
                line,
            }
        })
        .collect()
}

/// What a Device gets, as `explain device` prints it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceExplained {
    /// The Group of the Device.
    pub group: String,
    /// How the Group was found: `bundle` (a `[[device]]` entry) or `default`.
    #[serde(skip)]
    pub source: GroupSource,
    /// The Group's device config (format 1/2: its Config).
    pub device_config: String,
    /// The user configs a person can get on the Device, in order.
    pub user_configs: Vec<String>,
    /// The Flatpak ids the Device installs.
    pub flatpak: Vec<String>,
    /// The .deb app ids the Device installs (kiosk ones included).
    pub deb: Vec<String>,
}

/// The Group of the Device with this serial number, the way the agent picks it (no seed: an
/// unknown serial gets the `default` Group), and what the Device then gets: the install set is
/// the Device's effective config (for format 3 the install union of the reachable user configs
/// plus its own kiosk .deb apps). `Err` when the text has no `default` Group with a config.
pub fn explain_device(m: &Manifest, serial: &str) -> Result<DeviceExplained, String> {
    let default_ok = m
        .groups
        .iter()
        .any(|g| g.id == DEFAULT_GROUP && m.config(&g.config).is_some());
    if !default_ok {
        return Err(
            "the settings have no `default` Group naming an existing config: run `mastersos check`"
                .into(),
        );
    }
    let ident = DeviceIdent {
        serial: Some(serial.to_owned()),
        device_id: String::new(),
    };
    let s = select(m, &ident, None);
    Ok(DeviceExplained {
        group: s.group.id.clone(),
        source: s.source,
        device_config: s.group.config.clone(),
        user_configs: reachable_user_configs(m, &s.group.id),
        flatpak: s.config.apps.flatpak.clone(),
        deb: s.config.apps.deb.keys().cloned().collect(),
    })
}
