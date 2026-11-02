//! 安装器预检读的硬件事实（4b Task 22，spec §6.3、§6.9）：无线网卡的 PCI ID 与驱动、Dell BIOS 管理员密码。
//! 只读 sysfs，不跑命令。

use std::path::Path;

/// 支持清单里的无线网卡（vendor, device, 说明）。起步只放已核实的 Intel ID（Ubuntu 认证页）；以后加 ID 要以
/// 镜像内核 iwlwifi 的设备表为准、并在真机上验过，`image/docs/hardware.md` 同步。
pub const WIFI_ALLOW: &[(u16, u16, &str)] = &[
    (
        0x8086,
        0x9df0,
        "Intel Wireless-AC 9560（Cannon Point / Whiskey Lake）",
    ),
    (0x8086, 0x02f0, "Intel Wi-Fi 6 AX201 / 9560（Comet Lake）"),
    (0x8086, 0xa0f0, "Intel Wi-Fi 6 AX201（Tiger Lake）"),
    (0x8086, 0x2723, "Intel Wi-Fi 6 AX200"),
    (0x8086, 0x2725, "Intel Wi-Fi 6E AX210"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiDev {
    /// PCI 地址（`0000:00:14.3`）。
    pub slot: String,
    pub vendor: u16,
    pub device: u16,
    /// 绑上的驱动（`driver` 符号链接指向的目录名，如 `iwlwifi`）；没绑上为 `None`。
    pub driver: Option<String>,
}

impl WifiDev {
    pub fn allowed(&self) -> bool {
        WIFI_ALLOW
            .iter()
            .any(|&(v, d, _)| v == self.vendor && d == self.device)
    }

    /// `8086:a0f0`。
    pub fn id(&self) -> String {
        format!("{:04x}:{:04x}", self.vendor, self.device)
    }
}

fn read_hex(p: &Path) -> Option<u16> {
    let s = std::fs::read_to_string(p).ok()?;
    u16::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok()
}

/// `<sysfs>/bus/pci/devices/*` 里 class 以 `0x0280` 开头（网络控制器 / 其他，即无线）的设备，按 PCI 地址排序。
pub fn wifi_devices(sysfs: &Path) -> Vec<WifiDev> {
    let Ok(rd) = std::fs::read_dir(sysfs.join("bus/pci/devices")) else {
        return Vec::new();
    };
    let mut v: Vec<WifiDev> = rd
        .flatten()
        .filter_map(|e| {
            let dir = e.path();
            let class = std::fs::read_to_string(dir.join("class")).ok()?;
            if !class.trim().starts_with("0x0280") {
                return None;
            }
            Some(WifiDev {
                slot: e.file_name().to_string_lossy().into_owned(),
                vendor: read_hex(&dir.join("vendor"))?,
                device: read_hex(&dir.join("device"))?,
                driver: std::fs::read_link(dir.join("driver"))
                    .ok()
                    .and_then(|l| l.file_name().map(|n| n.to_string_lossy().into_owned())),
            })
        })
        .collect();
    v.sort_by(|a, b| a.slot.cmp(&b.slot));
    v
}

/// BIOS 管理员密码设没设：`<sysfs>/class/firmware-attributes/*/authentication/*/` 里 `role` 为 `bios-admin` 的那项的
/// `is_enabled`。没有这个目录（不是 Dell、或没加载 `dell-wmi-sysman`）或没有 `bios-admin` 那项 → `None`（不判断）。
pub fn bios_admin_password(sysfs: &Path) -> Option<bool> {
    let fa = std::fs::read_dir(sysfs.join("class/firmware-attributes")).ok()?;
    for drv in fa.flatten() {
        let Ok(auth) = std::fs::read_dir(drv.path().join("authentication")) else {
            continue;
        };
        for a in auth.flatten() {
            let role = std::fs::read_to_string(a.path().join("role")).unwrap_or_default();
            if role.trim() != "bios-admin" {
                continue;
            }
            let en = std::fs::read_to_string(a.path().join("is_enabled")).ok()?;
            return Some(en.trim() == "1");
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// 在临时 sysfs 里放一个 PCI 设备；`driver` 为 Some 时建 `driver` 符号链接。
    fn pci(sysfs: &Path, slot: &str, class: &str, id: (u16, u16), driver: Option<&str>) {
        let d = sysfs.join("bus/pci/devices").join(slot);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("class"), format!("{class}\n")).unwrap();
        fs::write(d.join("vendor"), format!("0x{:04x}\n", id.0)).unwrap();
        fs::write(d.join("device"), format!("0x{:04x}\n", id.1)).unwrap();
        if let Some(drv) = driver {
            let target = sysfs.join("bus/pci/drivers").join(drv);
            fs::create_dir_all(&target).unwrap();
            std::os::unix::fs::symlink(&target, d.join("driver")).unwrap();
        }
    }

    #[test]
    fn allow_list_has_only_verified_intel_ids() {
        let ids: Vec<(u16, u16)> = WIFI_ALLOW.iter().map(|&(v, d, _)| (v, d)).collect();
        assert_eq!(
            ids,
            vec![
                (0x8086, 0x9df0),
                (0x8086, 0x02f0),
                (0x8086, 0xa0f0),
                (0x8086, 0x2723),
                (0x8086, 0x2725)
            ]
        );
        assert!(WIFI_ALLOW.iter().all(|&(v, _, _)| v == 0x8086));
    }

    #[test]
    fn wifi_devices_reads_class_and_driver() {
        let t = tempfile::tempdir().unwrap();
        pci(
            t.path(),
            "0000:00:14.3",
            "0x028000",
            (0x8086, 0xa0f0),
            Some("iwlwifi"),
        );
        pci(
            t.path(),
            "0000:01:00.0",
            "0x020000",
            (0x10ec, 0x8168),
            Some("r8169"),
        );
        pci(t.path(), "0000:02:00.0", "0x028000", (0x14e4, 0x43a0), None);
        let v = wifi_devices(t.path());
        assert_eq!(
            v,
            vec![
                WifiDev {
                    slot: "0000:00:14.3".into(),
                    vendor: 0x8086,
                    device: 0xa0f0,
                    driver: Some("iwlwifi".into()),
                },
                WifiDev {
                    slot: "0000:02:00.0".into(),
                    vendor: 0x14e4,
                    device: 0x43a0,
                    driver: None,
                },
            ]
        );
        assert!(v[0].allowed());
        assert!(!v[1].allowed());
        assert_eq!(v[1].id(), "14e4:43a0");
        // 没有 PCI 目录：没有网卡
        assert!(wifi_devices(&t.path().join("nope")).is_empty());
    }

    fn admin(sysfs: &Path, role: &str, enabled: &str) {
        let d = sysfs.join("class/firmware-attributes/dell-wmi-sysman/authentication/Admin");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("role"), format!("{role}\n")).unwrap();
        fs::write(d.join("is_enabled"), format!("{enabled}\n")).unwrap();
    }

    #[test]
    fn bios_admin_password_detected() {
        let t = tempfile::tempdir().unwrap();
        admin(t.path(), "bios-admin", "1");
        assert_eq!(bios_admin_password(t.path()), Some(true));
        let t = tempfile::tempdir().unwrap();
        admin(t.path(), "bios-admin", "0");
        assert_eq!(bios_admin_password(t.path()), Some(false));
    }

    #[test]
    fn no_firmware_attributes_is_none() {
        let t = tempfile::tempdir().unwrap();
        assert_eq!(bios_admin_password(t.path()), None);
        // 有目录但只有系统密码（role 不是 bios-admin）：同样不判断
        let d = t
            .path()
            .join("class/firmware-attributes/dell-wmi-sysman/authentication/System");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("role"), "power-on\n").unwrap();
        fs::write(d.join("is_enabled"), "1\n").unwrap();
        assert_eq!(bios_admin_password(t.path()), None);
    }
}
