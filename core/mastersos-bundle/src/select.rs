//! 机器选分组：`[[device]]` 按序列号或机器 ID 命中 → 种子里的 `group` → `default`（spec §5.4），
//! then the Config that Group names (config profiles design §3).

use serde::{Deserialize, Serialize};

use crate::manifest::{
    effective_config, normalize_id, Config, DeviceEntry, Group, Lock, Manifest, ResetRequest,
    DEFAULT_GROUP,
};

/// 机器自己知道的身份。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdent {
    pub serial: Option<String>,
    pub device_id: String,
}

/// 分组是从哪里定下来的。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum GroupSource {
    Bundle,
    Seed,
    Default,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Selection<'a> {
    pub group: &'a Group,
    /// What the Devices of `group` get: the Config it names laid over `[defaults]`
    /// ([`effective_config`]).
    pub config: Config,
    pub source: GroupSource,
    pub lock: Option<&'a Lock>,
}

/// Picks this machine's Group and its expanded Config. Assumes the manifest passed `validate`
/// (exactly one default Group, every `[[device]]` names an existing Group, every Group's
/// `config` exists).
pub fn select<'a>(m: &'a Manifest, ident: &DeviceIdent, seed_group: Option<&str>) -> Selection<'a> {
    // A group counts only together with its config; `validate` guarantees both.
    let find = |id: &str| {
        let group = m.groups.iter().find(|g| g.id == id)?;
        Some((group, effective_config(m, m.config(&group.config)?)))
    };

    if let Some(d) = device_entry(m, ident.serial.as_deref(), &ident.device_id) {
        if let Some((group, config)) = find(&d.group) {
            return Selection {
                group,
                config,
                source: GroupSource::Bundle,
                lock: d.locked.as_ref(),
            };
        }
    }
    if let Some((group, config)) = seed_group.and_then(find) {
        return Selection {
            group,
            config,
            source: GroupSource::Seed,
            lock: None,
        };
    }
    let (group, config) =
        find(DEFAULT_GROUP).expect("a validated manifest has a default group with a config");
    Selection {
        group,
        config,
        source: GroupSource::Default,
        lock: None,
    }
}

/// 第一条命中这台机器的 `[[device]]`：序列号（去空白、不区分大小写）相等，或 `device_id` 相等。
fn device_entry<'a>(
    m: &'a Manifest,
    serial: Option<&str>,
    device_id: &str,
) -> Option<&'a DeviceEntry> {
    let serial = normalize_id(&serial.map(str::to_owned));
    let device_id = normalize_id(&Some(device_id.to_owned()));
    m.devices.iter().find(|d| {
        let by_serial = serial.is_some() && normalize_id(&d.serial) == serial;
        let by_id = device_id.is_some() && normalize_id(&d.device_id) == device_id;
        by_serial || by_id
    })
}

/// 这台机器的远程恢复出厂请求：与分组、锁定同样只看第一条命中的 `[[device]]`（Ruling 22）。
pub fn reset_request<'a>(
    m: &'a Manifest,
    serial: Option<&str>,
    device_id: &str,
) -> Option<&'a ResetRequest> {
    device_entry(m, serial, device_id)?.reset.as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Manifest {
        Manifest::parse(
            r#"
version = 1
[[group]]
id = "teacher"
name = "t"
[[group]]
id = "cart-g3"
name = "c"
[[group]]
id = "default"
name = "d"
[[device]]
serial = "ABC1234"
group = "cart-g3"
[[device]]
device_id = "dev-77"
group = "teacher"
locked = { message = "已挂失" }
"#,
        )
        .unwrap()
    }

    fn ident(serial: Option<&str>, id: &str) -> DeviceIdent {
        DeviceIdent {
            serial: serial.map(String::from),
            device_id: id.into(),
        }
    }

    #[test]
    fn device_entry_by_serial_wins() {
        let m = manifest();
        let s = select(&m, &ident(Some("ABC1234"), "x"), Some("teacher"));
        assert_eq!(
            (s.group.id.as_str(), s.source),
            ("cart-g3", GroupSource::Bundle)
        );
    }

    #[test]
    fn serial_match_trims_and_ignores_case() {
        let m = manifest();
        let s = select(&m, &ident(Some("  abc1234\n"), "x"), None);
        assert_eq!(
            (s.group.id.as_str(), s.source),
            ("cart-g3", GroupSource::Bundle)
        );
    }

    #[test]
    fn device_entry_by_device_id_when_no_serial() {
        let m = manifest();
        let s = select(&m, &ident(None, " DEV-77 "), None);
        assert_eq!(
            (s.group.id.as_str(), s.source),
            ("teacher", GroupSource::Bundle)
        );
    }

    #[test]
    fn empty_ident_never_matches() {
        let m = manifest();
        let s = select(&m, &ident(Some("  "), ""), None);
        assert_eq!(s.source, GroupSource::Default);
    }

    #[test]
    fn seed_group_used_when_not_listed() {
        let m = manifest();
        let s = select(&m, &ident(Some("other"), "x"), Some("teacher"));
        assert_eq!(
            (s.group.id.as_str(), s.source),
            ("teacher", GroupSource::Seed)
        );
    }

    #[test]
    fn seed_group_unknown_falls_back_to_default() {
        let m = manifest();
        let s = select(&m, &ident(None, "x"), Some("ghost"));
        assert_eq!(
            (s.group.id.as_str(), s.source),
            ("default", GroupSource::Default)
        );
    }

    #[test]
    fn default_when_nothing_matches() {
        let m = manifest();
        let s = select(&m, &ident(None, "x"), None);
        assert_eq!(
            (s.group.id.as_str(), s.source),
            ("default", GroupSource::Default)
        );
        assert!(s.lock.is_none());
    }

    #[test]
    fn lock_is_exposed() {
        let m = manifest();
        let s = select(&m, &ident(None, "dev-77"), None);
        assert_eq!(s.lock.unwrap().message, "已挂失");
        assert!(select(&m, &ident(Some("ABC1234"), "x"), None)
            .lock
            .is_none());
    }

    #[test]
    fn reset_request_matches_serial_case_insensitive() {
        let m = Manifest::parse(
            r#"
version = 1
[[group]]
id = "default"
name = "d"
[[device]]
serial = "QUIET"
group = "default"
[[device]]
serial = "ABC1234"
group = "default"
reset = { id = "r-1", requested_at = "2026-10-15T00:00:00Z" }
[[device]]
device_id = "dev-77"
group = "default"
reset = { id = "r-2", requested_at = "2026-10-15T00:00:00Z" }
"#,
        )
        .unwrap();
        let id = |s: Option<&str>, d: &str| reset_request(&m, s, d).map(|r| r.id.as_str());
        assert_eq!(id(Some("  abc1234\n"), "x"), Some("r-1"));
        // 读不到序列号时用 device_id。
        assert_eq!(id(None, " DEV-77 "), Some("r-2"));
        assert_eq!(id(Some("quiet"), "x"), None);
        assert_eq!(id(Some("other"), "y"), None);
        assert_eq!(id(Some(" "), ""), None);
        // 与分组、锁定一样只认第一条命中的：第一条没有 reset 就没有。
        assert_eq!(id(Some("QUIET"), "dev-77"), None);
    }

    fn new_shape() -> Manifest {
        Manifest::parse(
            r#"
version = 1
[[config]]
id = "student"
name = "s"
[[config]]
id = "teacher"
name = "t"
interface = "full"
[[group]]
id = "cart-g3"
name = "c3"
config = "student"
[[group]]
id = "staff"
name = "st"
config = "teacher"
[[group]]
id = "default"
name = "d"
config = "student"
[[device]]
serial = "ABC1234"
group = "staff"
"#,
        )
        .unwrap()
    }

    #[test]
    fn seed_group_honoured_new_shape() {
        let m = new_shape();
        let s = select(&m, &ident(Some("other"), "x"), Some("cart-g3"));
        assert_eq!(
            (s.group.id.as_str(), s.config.id.as_str(), s.source),
            ("cart-g3", "student", GroupSource::Seed)
        );
    }

    #[test]
    fn seed_group_unknown_falls_back_to_default_new_shape() {
        let m = new_shape();
        let s = select(&m, &ident(None, "x"), Some("ghost"));
        assert_eq!(
            (s.group.id.as_str(), s.config.id.as_str(), s.source),
            ("default", "student", GroupSource::Default)
        );
    }

    #[test]
    fn device_entry_wins() {
        let m = new_shape();
        let s = select(&m, &ident(Some("abc1234"), "x"), Some("cart-g3"));
        assert_eq!(
            (s.group.id.as_str(), s.config.id.as_str(), s.source),
            ("staff", "teacher", GroupSource::Bundle)
        );
    }

    #[test]
    fn legacy_shape_selects_the_implied_config() {
        let m = manifest();
        let s = select(&m, &ident(None, "dev-77"), None);
        assert_eq!(
            (s.group.id.as_str(), s.config.id.as_str()),
            ("teacher", "teacher")
        );
    }

    #[test]
    fn group_source_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&GroupSource::Bundle).unwrap(),
            "\"bundle\""
        );
        assert_eq!(
            serde_json::to_string(&GroupSource::Seed).unwrap(),
            "\"seed\""
        );
        assert_eq!(
            serde_json::to_string(&GroupSource::Default).unwrap(),
            "\"default\""
        );
    }

    #[test]
    fn select_returns_effective_config() {
        let text = format!(
            "{}[[device]]\nserial = \"T1\"\ngroup = \"staff\"\n",
            crate::testutil::defaults_example()
        );
        let m = Manifest::parse(&text).unwrap();
        let eff = |id: &str| crate::effective_config(&m, m.config(id).unwrap());
        // Device list, seed group, default: each gets the expanded Config of its Group.
        let s = select(&m, &ident(Some("t1"), "x"), None);
        assert_eq!(s.source, GroupSource::Bundle);
        assert_eq!(s.config, eff("teacher"));
        assert_eq!(s.config.interface, crate::Interface::Full);
        let s = select(&m, &ident(None, "x"), Some("staff"));
        assert_eq!(s.source, GroupSource::Seed);
        assert_eq!(s.config, eff("teacher"));
        let s = select(&m, &ident(None, "x"), None);
        assert_eq!(s.source, GroupSource::Default);
        assert_eq!(s.config, eff("student"));
        assert_eq!(s.config.printers.len(), 1, "inherited from Defaults");
    }
}
