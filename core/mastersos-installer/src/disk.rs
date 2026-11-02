//! Picks the install target from `lsblk -J -b -o NAME,PATH,TYPE,SIZE,RM,TRAN,MODEL,PARTLABEL`.

use anyhow::{bail, Context, Result};
use serde_json::Value;

/// GPT label of the seed partition on the stick; the disk that has it is the installer itself.
pub const USB_SEED_PARTLABEL: &str = "mastersos-usb-seed";
pub const MIN_DISK_BYTES: u64 = 48 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disk {
    pub path: String,
    pub model: Option<String>,
    pub size: u64,
    pub removable: bool,
    pub tran: Option<String>,
    pub is_installer: bool,
    /// Device path of the `mastersos-usb-seed` partition on the installer stick (only disks with `is_installer` have one).
    pub seed_part: Option<String>,
    /// Device paths of all partitions lsblk lists under this disk.
    pub parts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    One(Disk),
    Choose(Vec<Disk>),
    None,
}

/// Old lsblk versions print numbers as strings and booleans as "0"/"1": both are accepted.
fn as_u64(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str()?.trim().parse().ok())
}

fn as_bool(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_u64() == Some(1),
        Value::String(s) => s == "1" || s == "true",
        _ => false,
    }
}

fn as_text(v: &Value) -> Option<String> {
    let s = v.as_str()?.trim();
    (!s.is_empty()).then(|| s.to_string())
}

fn skipped_name(name: &str) -> bool {
    (name.starts_with("mmcblk") && name.contains("boot"))
        || name.starts_with("zram")
        || name.starts_with("loop")
}

pub fn parse_lsblk(json: &str) -> Result<Vec<Disk>> {
    let root: Value = serde_json::from_str(json).context("lsblk output is not JSON")?;
    let Some(devs) = root.get("blockdevices").and_then(Value::as_array) else {
        bail!("lsblk output has no blockdevices");
    };
    let mut out = Vec::new();
    for d in devs {
        let name = d.get("name").and_then(Value::as_str).unwrap_or("");
        if d.get("type").and_then(Value::as_str) != Some("disk") || skipped_name(name) {
            continue;
        }
        let path = match d.get("path").and_then(as_text) {
            Some(p) => p,
            None if !name.is_empty() => format!("/dev/{name}"),
            None => continue,
        };
        let seed_part = d.get("children").and_then(Value::as_array).and_then(|cs| {
            cs.iter().find_map(|c| {
                if c.get("partlabel").and_then(Value::as_str) != Some(USB_SEED_PARTLABEL) {
                    return None;
                }
                c.get("path").and_then(as_text).or_else(|| {
                    c.get("name")
                        .and_then(Value::as_str)
                        .map(|n| format!("/dev/{n}"))
                })
            })
        });
        let parts = d
            .get("children")
            .and_then(Value::as_array)
            .map(|cs| {
                cs.iter()
                    .filter_map(|c| {
                        c.get("path").and_then(as_text).or_else(|| {
                            c.get("name")
                                .and_then(Value::as_str)
                                .map(|n| format!("/dev/{n}"))
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.push(Disk {
            path,
            model: d.get("model").and_then(as_text),
            size: d.get("size").and_then(as_u64).unwrap_or(0),
            removable: d.get("rm").is_some_and(as_bool),
            tran: d.get("tran").and_then(as_text),
            is_installer: seed_part.is_some(),
            seed_part,
            parts,
        });
    }
    Ok(out)
}

fn is_nvme(d: &Disk) -> bool {
    d.tran.as_deref() == Some("nvme") || d.path.starts_with("/dev/nvme")
}

/// Leaves out the installer itself, removable disks, USB disks and disks under 48 GiB; of the rest, NVMe first, then by size, largest first.
pub fn choose_target(disks: &[Disk]) -> Target {
    let mut c: Vec<Disk> = disks
        .iter()
        .filter(|d| {
            !d.is_installer
                && !d.removable
                && d.tran.as_deref() != Some("usb")
                && d.size >= MIN_DISK_BYTES
        })
        .cloned()
        .collect();
    c.sort_by(|a, b| {
        is_nvme(b)
            .cmp(&is_nvme(a))
            .then(b.size.cmp(&a.size))
            .then(a.path.cmp(&b.path))
    });
    match c.len() {
        0 => Target::None,
        1 => Target::One(c.remove(0)),
        _ => Target::Choose(c),
    }
}

/// Ventoy mode: the disk that owns `part` (the exFAT partition the initrd attached) is the installer
/// stick, so it must never be offered as a target, whatever lsblk says about rm/tran/size.
pub fn mark_ventoy_disk(disks: &mut [Disk], part: &str) -> Result<()> {
    match disks.iter_mut().find(|d| d.parts.iter().any(|p| p == part)) {
        Some(d) => {
            d.is_installer = true;
            Ok(())
        }
        None => bail!(
            "The Ventoy stick is not in the disk list\nRe-plug the Ventoy stick and restart the installer"
        ),
    }
}

/// Exactly one installer disk: none (not booted from an installer stick) or several (two sticks plugged in) are refused,
/// since there is no telling which stick's seed to trust.
pub fn installer_disk(disks: &[Disk]) -> Result<&Disk> {
    let mut it = disks.iter().filter(|d| d.is_installer);
    match (it.next(), it.next()) {
        (Some(d), None) => Ok(d),
        (None, _) => bail!("Installer stick not found"),
        _ => bail!("More than one installer stick, keep only one"),
    }
}
