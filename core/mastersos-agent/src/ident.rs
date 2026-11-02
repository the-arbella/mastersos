//! 机器身份：序列号、型号、系统版本来自 DMI 与 os-release，机器 ID 首次运行时生成。

use std::fs;

use mastersos_bundle::DeviceIdent;

use crate::config::AgentConfig;
use crate::state::State;

/// 厂商没填序列号时 BIOS 里常见的占位值（比较时不分大小写）。
const PLACEHOLDERS: &[&str] = &[
    "to be filled by o.e.m.",
    "default string",
    "system serial number",
    "not specified",
    "not applicable",
    "none",
    "n/a",
    "unknown",
    "0",
];

fn read_trimmed(path: &std::path::Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    let t = text.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// 读出身份；`device_id` 首次运行时生成 UUID v4 存进 `state`（落盘由调用方 `state::save`）。
pub fn read(cfg: &AgentConfig, state: &mut State) -> DeviceIdent {
    let serial = read_trimmed(&cfg.dmi_dir.join("product_serial"))
        .filter(|s| !PLACEHOLDERS.contains(&s.to_lowercase().as_str()));
    let device_id = state
        .device_id
        .get_or_insert_with(|| uuid::Uuid::new_v4().to_string())
        .clone();
    DeviceIdent { serial, device_id }
}

pub fn model(cfg: &AgentConfig) -> Option<String> {
    read_trimmed(&cfg.dmi_dir.join("product_name"))
}

/// os-release 里优先取 `IMAGE_VERSION`，其次 `VERSION_ID`。
pub fn os_version(cfg: &AgentConfig) -> Option<String> {
    let text = fs::read_to_string(&cfg.os_release).ok()?;
    let get = |key: &str| {
        text.lines().find_map(|l| {
            let v = l.trim().strip_prefix(key)?.strip_prefix('=')?;
            let v = v.trim().trim_matches(|c| c == '"' || c == '\'');
            (!v.is_empty()).then(|| v.to_string())
        })
    };
    get("IMAGE_VERSION").or_else(|| get("VERSION_ID"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(dir: &std::path::Path) -> AgentConfig {
        AgentConfig {
            dmi_dir: dir.to_path_buf(),
            os_release: dir.join("os-release"),
            ..AgentConfig::default()
        }
    }

    #[test]
    fn serial_placeholder_is_none() {
        let d = tempfile::tempdir().unwrap();
        let c = cfg(d.path());
        for v in ["To be filled by O.E.M.\n", "Default string", "  \n", ""] {
            fs::write(d.path().join("product_serial"), v).unwrap();
            assert_eq!(read(&c, &mut State::default()).serial, None, "{v:?}");
        }
        fs::write(d.path().join("product_serial"), " PF2ABC12 \n").unwrap();
        assert_eq!(
            read(&c, &mut State::default()).serial.as_deref(),
            Some("PF2ABC12")
        );
    }

    #[test]
    fn missing_serial_file_is_none() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(read(&cfg(d.path()), &mut State::default()).serial, None);
    }

    #[test]
    fn device_id_is_stable() {
        let d = tempfile::tempdir().unwrap();
        let c = cfg(d.path());
        let mut st = State::default();
        let a = read(&c, &mut st);
        let b = read(&c, &mut st);
        assert_eq!(a.device_id, b.device_id);
        assert_eq!(st.device_id.as_deref(), Some(a.device_id.as_str()));
        assert_eq!(a.device_id.len(), 36);
    }

    #[test]
    fn model_and_os_version() {
        let d = tempfile::tempdir().unwrap();
        let c = cfg(d.path());
        assert_eq!(model(&c), None);
        assert_eq!(os_version(&c), None);
        fs::write(d.path().join("product_name"), "ThinkPad 11e\n").unwrap();
        assert_eq!(model(&c).as_deref(), Some("ThinkPad 11e"));
        fs::write(
            d.path().join("os-release"),
            "NAME=MastersOS\nVERSION_ID=\"12\"\n",
        )
        .unwrap();
        assert_eq!(os_version(&c).as_deref(), Some("12"));
        fs::write(
            d.path().join("os-release"),
            "VERSION_ID=\"12\"\nIMAGE_VERSION=2026.10.1\n",
        )
        .unwrap();
        assert_eq!(os_version(&c).as_deref(), Some("2026.10.1"));
    }
}
