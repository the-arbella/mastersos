//! Hardware checks before installing (4b Task 22, spec §6.3): after the TPM, before choosing the disk. Three levels: refuse (disk untouched), warn (one `y` to continue), pass.
//!
//! - Active db unreadable / empty, no Microsoft UEFI CA 2023 in db, the shim to be installed does not chain to db: refused under the release profile, only a warning for lab
//!   (old PVE efidisks only have 2011). The refusal text gives the reason, then the fix in order: update BIOS -> Reset All Keys -> clear TPM -> reinstall.
//! - Release profile with a lab or pre-release MastersOS certificate enrolled in MokList: a warning, not a refusal (plan 5 Ruling 12), saying how to `mokutil --delete` after installing;
//!   an unreadable MokList gives no finding.
//! - BIOS admin password set: a warning (the installer cannot know whether "nobody knows" that password).
//! - Wi-Fi cards: in `mastersos_agent::hw::WIFI_ALLOW` -> no finding; not listed but with a driver -> warning "not verified"; no driver, Broadcom, or no Wi-Fi card ->
//!   warning "Wi-Fi will not work".
//! - Not checked: wired card, model, BIOS version, Absolute (Linux cannot read it; the shipping steps check it in BIOS, Task 21).

use std::path::Path;

use mastersos_agent::hw::{bios_admin_password, wifi_devices, WifiDev};
use mastersos_agent::runner::Runner;
use mastersos_agent::secureboot::{
    describe_cert, has_ms_ca, read_db, read_dbx, read_mok_list, shim_chains, DbRead, MsCa,
    ShimVerdict, REVOKED_ADVICE, UNTRUSTED_MOK_FILES, UNTRUSTED_MOK_SHA256,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Warn,
    Refuse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub level: Level,
    pub code: &'static str,
    /// English only (the console font has no CJK glyphs).
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Release,
    Lab,
}

impl Profile {
    /// Reads `usr/lib/mastersos/profile` (relative to `root`), written at build time into the signed `/usr`; unreadable or not `lab` counts as release.
    pub fn detect(root: &Path) -> Profile {
        if mastersos_agent::luks::image_is_lab(root) {
            Profile::Lab
        } else {
            Profile::Release
        }
    }
}

pub struct PrecheckEnv<'a> {
    pub runner: &'a dyn Runner,
    /// Usually `/sys`.
    pub sysfs: &'a Path,
    pub profile: Profile,
    /// The shim to be installed: `/usr/lib/mastersos/esp/BOOTX64.EFI` (the same bytes as on the stick's ESP, build.sh checks).
    pub shim: &'a Path,
    /// Directory for temporary PEMs.
    pub tmp: &'a Path,
}

/// The shim to be installed, normally.
pub const SHIM: &str = "/usr/lib/mastersos/esp/BOOTX64.EFI";

/// The fix when the 2023 certificate is missing, the shim does not chain or db is unreadable (order matters: certificates and TPM must be right before installing; changing db after installing changes PCR 7).
pub const FIX_ORDER: &str = "Fix, in this order:\n\
  1. Update the BIOS (Dell website or fwupd)\n\
  2. BIOS -> Secure Boot -> Expert Key Management -> turn on Custom Mode -> Reset All Keys; save and reboot, then turn Custom Mode off\n\
  3. Security -> TPM 2.0 Security -> Clear\n\
  4. Reinstall from the USB stick";

/// lab warnings get one more paragraph: how to add the 2023 certificate to an efidisk on PVE.
pub const LAB_PVE_NOTE: &str = "\
PVE: efidisks created with pve-edk2-firmware >= 4.2025.05-1 (pre-enrolled-keys) already carry the 2023 CA; update an old efidisk with \
PVE's `ms-cert=2023k`, or build a vars template with `virt-fw-vars --add-db 77fa9abd-0359-4d32-bd60-28f4e78f784b <Microsoft UEFI CA 2023.der>`";

/// Codes of the three Secure Boot certificate findings: they share one fix ([`advice`]), the text only gives the reason.
pub const SECURE_BOOT_CODES: &[&str] = &["db_unreadable", "db_no_2023", "shim_no_chain"];
/// The shim to be installed is revoked by this machine's dbx: also refused under release and a warning for lab, but the fix is a newer image (review N3).
pub const SHIM_REVOKED: &str = "shim_revoked";

/// With Secure Boot certificate findings the ordered fix is given once (not repeated when several show up; review Minor 9), lab adds the PVE note.
/// With a revoked shim only "use a newer installer image" is given, **not** Reset All Keys: that resets dbx to the factory copy, which may undo this revocation too.
pub fn advice(findings: &[Finding], profile: Profile) -> Option<String> {
    if findings.iter().any(|f| f.code == SHIM_REVOKED) {
        return Some(REVOKED_ADVICE.to_string());
    }
    if !findings.iter().any(|f| SECURE_BOOT_CODES.contains(&f.code)) {
        return None;
    }
    Some(match profile {
        Profile::Release => FIX_ORDER.to_string(),
        Profile::Lab => format!("{FIX_ORDER}\n{LAB_PVE_NOTE}"),
    })
}

/// One Secure Boot certificate finding: refused under release, a warning for lab; the text is the heading and the reason (the fix: see [`advice`]).
fn sb_finding(profile: Profile, code: &'static str, reason: String) -> Finding {
    let (level, head) = match profile {
        Profile::Release => (
            Level::Refuse,
            "Secure Boot certificates are not right, cannot install MastersOS",
        ),
        Profile::Lab => (
            Level::Warn,
            "Secure Boot certificates are not right (lab image: warning only)",
        ),
    };
    Finding {
        level,
        code,
        text: format!("{head}\nReason: {reason}"),
    }
}

fn warn(code: &'static str, text: String) -> Finding {
    Finding {
        level: Level::Warn,
        code,
        text,
    }
}

/// The finding for one Wi-Fi card (None when it is on the allow list).
fn wifi_finding(d: &WifiDev) -> Option<Finding> {
    if d.allowed() {
        return None;
    }
    let id = d.id();
    match &d.driver {
        // Broadcom does not count even when a driver is bound (wl and the like): the image has neither its firmware nor its driver
        Some(drv) if d.vendor != 0x14e4 => {
            let (code, kind) = if d.vendor == 0x8086 {
                ("wifi_unlisted", "")
            } else {
                ("wifi_non_intel", "non-Intel card, ")
            };
            Some(warn(
                code,
                format!(
                    "Wi-Fi card {id} ({kind}driver {drv}) is not on the support list: it works, but this model with this card has not been verified"
                ),
            ))
        }
        _ => Some(warn(
            "wifi_unusable",
            format!(
                "Wi-Fi card {id} has no usable driver: Wi-Fi will not work, only wired networking; replace it with an Intel AX210"
            ),
        )),
    }
}

/// Warning text for a MastersOS certificate that should not be enrolled, with the `mokutil --delete` steps for after installing.
fn mok_text(label: &str, stem: &str) -> String {
    format!(
        "This machine's MokList has the \"{label}\" certificate enrolled: it will boot images signed with that key set (the lab key has a publicly known root); \
         machines we ship must not show this warning. After installing, run as root `mokutil --delete /usr/share/mastersos/untrusted-mok/{stem}.der` \
         and confirm the deletion in MokManager on reboot"
    )
}

pub fn precheck(env: &PrecheckEnv) -> Vec<Finding> {
    let mut out = Vec::new();
    // --- Secure Boot: the active db and the shim to be installed ---
    match read_db(env.sysfs) {
        DbRead::Certs(certs) => {
            // dbx not understood: there is no telling whether the shim to be installed is revoked, so it counts as "does not chain" (refused under release); missing or empty = nothing revoked
            let dbx = read_dbx(env.sysfs);
            if !has_ms_ca(&certs, MsCa::Uefi2023) {
                out.push(sb_finding(
                    env.profile,
                    "db_no_2023",
                    format!(
                        "The active db has no Microsoft UEFI CA 2023 (Ubuntu shim updates from Q4 2026 need it); db has: {}",
                        certs
                            .iter()
                            .map(|c| describe_cert(&c.sha256))
                            .collect::<Vec<_>>()
                            .join("; ")
                    ),
                ));
            }
            let verdict = match dbx {
                Ok(dbx) => shim_chains(env.runner, env.shim, &certs, &dbx, env.tmp),
                Err(why) => ShimVerdict::CantCheck(why),
            };
            match verdict {
                ShimVerdict::Chains { .. } => {}
                ShimVerdict::NoChain => out.push(sb_finding(
                    env.profile,
                    "shim_no_chain",
                    format!(
                        "The shim to be installed ({}) does not chain to any certificate in the active db, it would not boot",
                        env.shim.display()
                    ),
                )),
                ShimVerdict::Revoked(why) => out.push(sb_finding(
                    env.profile,
                    SHIM_REVOKED,
                    format!(
                        "The shim to be installed ({}) is revoked by this machine's dbx: {why}",
                        env.shim.display()
                    ),
                )),
                ShimVerdict::CantCheck(why) => out.push(sb_finding(
                    env.profile,
                    "shim_no_chain",
                    format!(
                        "Could not check the shim to be installed ({}) against the active db: {why}",
                        env.shim.display()
                    ),
                )),
            }
        }
        r => {
            let why = match r {
                DbRead::Missing => "There is no db variable (the firmware gives no Secure Boot db)".to_string(),
                DbRead::Empty => "The active db has no certificates (most likely Setup Mode, or the keys were cleared)".to_string(),
                DbRead::Malformed(e) => format!("The active db could not be parsed: {e}"),
                DbRead::Certs(_) => unreachable!(),
            };
            out.push(sb_finding(env.profile, "db_unreadable", why));
        }
    }
    // --- lab / pre-release certificates in MokList (release profile only; an unreadable MokList gives no finding) ---
    if env.profile == Profile::Release {
        if let Ok(mok) = read_mok_list(env.sysfs) {
            for ((sha, label), stem) in UNTRUSTED_MOK_SHA256.iter().zip(UNTRUSTED_MOK_FILES) {
                if mok.iter().any(|c| &c.sha256 == sha) {
                    out.push(warn("mok_untrusted", mok_text(label, stem)));
                }
            }
        }
    }
    // --- BIOS admin password ---
    if bios_admin_password(env.sysfs) == Some(true) {
        out.push(warn(
            "bios_admin_password",
            "A BIOS admin password is set. Without it the Secure Boot certificates cannot be changed and the TPM cannot be cleared later; \
             machines we ship must have no BIOS password"
                .into(),
        ));
    }
    // --- Wi-Fi cards ---
    let wifi = wifi_devices(env.sysfs);
    if wifi.is_empty() {
        out.push(warn(
            "wifi_unusable",
            "No Wi-Fi card: Wi-Fi will not work, only wired networking; an Intel AX210 can be fitted"
                .into(),
        ));
    }
    out.extend(wifi.iter().filter_map(wifi_finding));
    out
}

#[cfg(test)]
mod tests;
