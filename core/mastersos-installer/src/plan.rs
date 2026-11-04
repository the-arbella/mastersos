//! Ordering the install steps: turns "the chosen disk + the seed + facts about the machine" into a list of commands. Runs nothing.

use anyhow::{bail, Result};
use mastersos_agent::runner::{Cmd, Runner};
use mastersos_agent::tpm::{TpmVerdict, Unusable};

use crate::disk::Disk;
use crate::seed::{display_fit, wifi_summary, SeedFound};

pub const MOK_PASSWORD: &str = "mastersos";
/// The installer's working directory (tmpfs).
pub const INSTALL_DIR: &str = "/run/mastersos-install";
/// The source of repart's `CopyFiles=/run/mastersos-install/seed:/`.
pub const SEED_DIR: &str = "/run/mastersos-install/seed";
/// The new disk's ESP is mounted here.
pub const NEW_ESP: &str = "/run/mastersos-install/esp";
/// The stick's ESP (read-only source), mounted here by `mastersos-installer.service` (Task 11).
pub const USB_ESP: &str = "/run/mastersos-usb-esp";
/// The stick's seed partition (mounted read-only), also mounted by Task 11.
pub const USB_SEED_DIR: &str = "/run/mastersos-usb-seed";
pub const MOK_HASH_FILE: &str = "/run/mastersos-install/mok.hash";
pub const LOADER_CONF: &str = "/usr/lib/mastersos/installer/loader.conf";
pub const MOK_CERT: &str = "/usr/share/mastersos/mastersos-mok.der";
/// The MOK certificate's name in the root of the installed ESP.
pub const MOK_FILE: &str = "mastersos-mok.der";
const UKI_TEMPLATE: &str = "EFI/Linux/MastersOS_<version>_x86-64.efi";
/// Directory of the main UKI on the stick's ESP. Not `EFI/Linux/`: systemd-boot would list every UKI there in the stick's boot menu,
/// and choosing the main system or "factory reset" would create partitions on the stick (Task 11 review I-1). `make-installer.sh` puts it here.
pub const USB_UKI_DIR: &str = "EFI/mastersos";

/// Where an ESP file (path relative to the internal ESP) comes from: the stick's ESP, the main UKI from another directory there;
/// the MOK certificate from the installer's own /usr ([`MOK_CERT`], under dm-verity), not from the stick's ESP, which no
/// signature or hash covers (Ventoy and whole-stick alike). Same bytes: mkosi.finalize installs both from keys/mastersos-mok.der.
fn usb_source(f: &str) -> String {
    if f == MOK_FILE {
        return MOK_CERT.to_string();
    }
    match f.strip_prefix("EFI/Linux/") {
        Some(name) => format!("{USB_ESP}/{USB_UKI_DIR}/{name}"),
        None => format!("{USB_ESP}/{f}"),
    }
}
const SECURE_BOOT_EFIVAR: &str =
    "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    pub secure_boot: bool,
    pub mok_enrolled: bool,
    pub image_version: String,
    /// `/usr/lib/mastersos/profile` says `lab`.
    pub lab: bool,
    /// Booted through Ventoy (set by the caller from the kernel command line; `detect` leaves it false).
    pub ventoy: bool,
}

/// `mokutil --import` only when Secure Boot is off at install time and the certificate is not enrolled yet (Ruling 12).
pub fn imports_mok(f: &Facts) -> bool {
    mok_step(f) == MokStep::Import
}

/// What the install must do about the MastersOS certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MokStep {
    /// Nothing: the certificate is already enrolled.
    None,
    /// Secure Boot is off: queue `mokutil --import` for the next boot.
    Import,
    /// Ventoy boot with Secure Boot on: `mokutil --import` is not allowed, so the
    /// blue screen must be driven by hand with "Enroll key from disk". Whole-stick installs never get
    /// this step (they behave as before the Ventoy work: no MOK command at all).
    EnrollFromDisk,
}

pub fn mok_step(f: &Facts) -> MokStep {
    match (f.secure_boot, f.mok_enrolled) {
        (false, false) => MokStep::Import,
        (true, false) if f.ventoy => MokStep::EnrollFromDisk,
        _ => MokStep::None,
    }
}

/// Files copied from the stick's ESP to the new ESP, paths relative to the new ESP's root (sources: see `usb_source`; the main UKI is in [`USB_UKI_DIR`] on the stick). [`plan`] fills the main UKI's `<version>`;
/// entries ending in `/*` are whole directories. The installer UKI is not among them; release images carry no `loader/keys/auto` (Task 4).
pub fn esp_files(lab: bool) -> Vec<&'static str> {
    let mut v = vec![
        "EFI/BOOT/BOOTX64.EFI",
        "EFI/BOOT/grubx64.efi",
        "EFI/BOOT/mmx64.efi",
        "EFI/systemd/systemd-bootx64.efi",
        UKI_TEMPLATE,
        // The MOK certificate: when the enroll prompt on the first boot was missed, or NVRAM was cleared, pick this file on the internal disk
        // under MokManager's "Enroll key from disk" (docs/install.md)
        MOK_FILE,
    ];
    if lab {
        v.push("loader/keys/auto/*");
    }
    v
}

/// GPT partition number of `mastersos-golden-sig` on a freshly installed disk: after ESP (1), A slot (2-4)
/// and B slot (5-7), before the seed partition. Matches the order of `install.repart.d`.
pub const GOLDEN_SIG_PARTNO: u32 = 8;

/// GPT partition number of `mastersos-golden-esp` on a freshly installed disk (after golden-sig 8, golden-verity 9, golden-usr 10).
pub const GOLDEN_ESP_PARTNO: u32 = 11;

/// FAT label of the internal ESP: the one volume MokManager's "Enroll key from disk" should offer.
pub const ESP_FAT_LABEL: &str = "MASTERSOS";

/// FAT label of the golden ESP, which firmware cannot see (GPT attribute bit 1). Its GPT name stays `mastersos-golden-esp`.
pub const GOLDEN_ESP_FAT_LABEL: &str = "MOS-GOLDEN";

/// Partition n of a disk: names ending in a digit (nvme0n1, mmcblk0) take a `p`.
pub fn partition(disk: &str, n: u32) -> String {
    if disk.ends_with(|c: char| c.is_ascii_digit()) {
        format!("{disk}p{n}")
    } else {
        format!("{disk}{n}")
    }
}

/// Partition 1 of a disk (the ESP).
pub fn esp_partition(disk: &str) -> String {
    partition(disk, 1)
}

pub fn plan(target: &Disk, seed: &SeedFound, facts: &Facts) -> Result<Vec<Cmd>> {
    if let SeedFound::Invalid(why) = seed {
        bail!("Invalid seed, refusing to install: {why}");
    }
    let disk = target.path.as_str();
    let mut v = vec![
        Cmd::new(
            "systemd-repart",
            &[
                "--dry-run=no",
                "--empty=force",
                "--definitions=/usr/lib/mastersos/install.repart.d",
                disk,
            ],
        ),
        // After repart rewrote the partition table, udev creates the new partitions' device nodes asynchronously.
        Cmd::new("udevadm", &["settle"]),
        // `--empty=force` only rewrites the partition table: a valid golden signature left by an earlier
        // install would survive in the same sectors, so wipe it. The first good boot fills the golden copy.
        Cmd::new(
            "dd",
            &[
                "if=/dev/zero",
                &format!("of={}", partition(disk, GOLDEN_SIG_PARTNO)),
                "bs=16K",
                "count=1",
                "conv=fsync",
            ],
        ),
        // repart names a FAT volume after the partition (cut to 11 characters), which would leave the golden ESP as
        // "mastersos-g": set both labels explicitly.
        Cmd::new("fatlabel", &[&esp_partition(disk), ESP_FAT_LABEL]),
        Cmd::new(
            "fatlabel",
            &[&partition(disk, GOLDEN_ESP_PARTNO), GOLDEN_ESP_FAT_LABEL],
        ),
        Cmd::new("mkdir", &["-p", NEW_ESP]),
        Cmd::new("mount", &[&esp_partition(disk), NEW_ESP]),
    ];
    for f in esp_files(facts.lab) {
        let f = f.replace("<version>", &facts.image_version);
        if let Some(dir) = f.strip_suffix("/*") {
            let dst = format!("{NEW_ESP}/{dir}");
            v.push(Cmd::new("mkdir", &["-p", &dst]));
            v.push(Cmd::new("cp", &["-r", &format!("{USB_ESP}/{dir}/."), &dst]));
        } else {
            // The main UKI is copied under its own name, without a boot counter: the first installed version has nothing to fall back to.
            v.push(install(&usb_source(&f), &format!("{NEW_ESP}/{f}")));
        }
    }
    v.push(install(
        LOADER_CONF,
        &format!("{NEW_ESP}/loader/loader.conf"),
    ));
    v.push(Cmd::new("umount", &[NEW_ESP]));
    v.push(Cmd::new(
        "efibootmgr",
        &[
            "--create",
            "--disk",
            disk,
            "--part",
            "1",
            "--label",
            "MastersOS",
            "--loader",
            "\\EFI\\BOOT\\BOOTX64.EFI",
        ],
    ));
    match mok_step(facts) {
        MokStep::Import => {
            // main wrote the hash file before plan, from mok_hash_cmd's output (write_mok_hash).
            v.push(Cmd::new(
                "mokutil",
                &["--import", MOK_CERT, "--hash-file", MOK_HASH_FILE],
            ));
        }
        // Make MokManager wait for the technician instead of counting down to a normal boot.
        // Best effort: see `is_best_effort`.
        MokStep::EnrollFromDisk => v.push(mok_timeout_cmd()),
        MokStep::None => {}
    }
    v.push(Cmd::new("sync", &[]));
    Ok(v)
}

/// `mokutil --timeout -1`: make MokManager wait for the technician. Some firmware ignores MokTimeout.
pub fn mok_timeout_cmd() -> Cmd {
    Cmd::new("mokutil", &["--timeout", "-1"])
}

/// Commands whose failure must not abort the install: they run after the disk is written, and the
/// finish screen (with the manual steps) has to be shown anyway.
pub fn is_best_effort(c: &Cmd) -> bool {
    c.program == "mokutil" && c.args == ["--timeout", "-1"]
}

/// The password is the public `mastersos` (Ruling 12); [`write_mok_hash`] puts the printed hash into [`MOK_HASH_FILE`].
pub fn mok_hash_cmd() -> Cmd {
    Cmd::new("mokutil", &[&format!("--generate-hash={MOK_PASSWORD}")])
}

pub fn write_mok_hash(path: &std::path::Path, stdout: &str) -> Result<()> {
    let h = stdout.trim();
    if h.is_empty() {
        bail!("mokutil --generate-hash printed nothing");
    }
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    if let Some(parent) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    // Remove the old file first: the mode in OpenOptions only applies when the file is created.
    let _ = std::fs::remove_file(path);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    f.write_all(format!("{h}\n").as_bytes())?;
    Ok(())
}

/// Source files that must exist before the disk is erased; returns the missing ones. `exists` is injected for tests.
pub fn missing_sources(facts: &Facts, exists: &dyn Fn(&str) -> bool) -> Vec<String> {
    let mut need: Vec<String> = esp_files(facts.lab)
        .into_iter()
        .map(|f| {
            let f = f.replace("<version>", &facts.image_version);
            usb_source(f.strip_suffix("/*").unwrap_or(&f))
        })
        .collect();
    need.push(LOADER_CONF.to_string());
    // MOK_CERT is always among them: the installed ESP's copy comes from /usr (`usb_source`), and `mokutil --import` uses it too.
    need.into_iter().filter(|p| !exists(p)).collect()
}

fn install(src: &str, dst: &str) -> Cmd {
    Cmd::new("install", &["-D", "-m", "0644", src, dst])
}

fn gib(bytes: u64) -> u64 {
    bytes / (1024 * 1024 * 1024)
}

/// The confirm screen: target disk model and size, and whether there is a seed (with a seed: `server_url` and the group). Only `y` continues.
pub fn confirm_text(target: &Disk, seed: &SeedFound, debug: bool) -> String {
    let model = target.model.as_deref().unwrap_or("(unknown model)");
    let mut t = format!(
        "This ERASES the whole disk and installs MastersOS\n  {} ({model}, {} GiB)\n",
        target.path,
        gib(target.size)
    );
    match seed {
        SeedFound::Valid { seed, .. } => {
            let wifi = if seed.wifi.is_empty() {
                "none (connect a cable or set it up after install)".to_string()
            } else {
                wifi_summary(seed, 32)
            };
            t.push_str(&format!(
                "Managed computer\n  Server: {}\n  Group: {}\n  School: {}\n  Wi-Fi: {wifi}\n",
                display_fit(&seed.server_url, 60),
                display_fit(seed.group.as_deref().unwrap_or("-"), 60),
                display_fit(seed.school_name.as_deref().unwrap_or("-"), 60),
            ));
        }
        _ => t.push_str("No seed: will be installed as an unmanaged personal computer\n"),
    }
    // d was held in the hidden window at the start: the one place that shows it worked
    if debug {
        t.push_str("Developer diagnostics: ON\n");
    }
    t.push_str("Type y to continue, anything else cancels: ");
    t
}

/// The end of the finish screen (all but `EnrollFromDisk`, whose steps say the same).
pub const AFTER_RESTART: &str = "Press Enter to restart. Remove the USB stick when the screen goes dark, before MastersOS starts.\n\
     If the Ventoy menu or the installer appears again, remove the USB stick and restart.\n";

/// The finish screen. `Import` gives the MOK password; `EnrollFromDisk` walks IT through enrolling the certificate from disk on the blue screen.
///
/// Never "remove the USB stick, then press Enter": the running installer's /usr lives on the stick (whole-stick and Ventoy),
/// so `systemctl reboot` fails with an I/O error once it is gone (seen on a real laptop). The stick comes out after the screen
/// goes dark; with it still in, the firmware boots the "MastersOS" entry efibootmgr put first in BootOrder.
pub fn finish_text(step: MokStep) -> String {
    let mut t = String::from("Installation complete\n");
    match step {
        MokStep::Import => t.push_str(&format!(
            "MOK password: {MOK_PASSWORD}\nAfter enabling Secure Boot, enroll the key when prompted.\n"
        )),
        MokStep::EnrollFromDisk => t.push_str(
            "\nNext: one blue screen to approve MastersOS (only the first time on this computer)\n\n\
             \x20 1. Press Enter to restart, then remove the USB stick when the screen goes dark\n\
             \x20 2. \"Security Violation\" -> press Enter\n\
             \x20 3. Choose \"Enroll key from disk\"\n\
             \x20 4. Choose MASTERSOS (not MOS-GOLDEN)\n\
             \x20 5. Choose mastersos-mok.der\n\
             \x20 6. \"Continue\" -> \"Yes\" -> \"Reboot\"\n\n\
             If anything goes wrong, just restart: the same blue screen comes back.\n\
             If the Ventoy menu or the installer appears again, remove the USB stick and restart.\n",
        ),
        MokStep::None => {}
    }
    if step != MokStep::EnrollFromDisk {
        t.push_str(AFTER_RESTART);
    }
    t
}

pub fn secure_boot_from_efivar(bytes: &[u8]) -> bool {
    // The first 4 bytes are attributes, the 5th is the value.
    bytes.get(4) == Some(&1)
}

pub fn image_version_from_os_release(text: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let v = l.strip_prefix("IMAGE_VERSION=")?.trim().trim_matches('"');
        (!v.is_empty()).then(|| v.to_string())
    })
}

impl Facts {
    /// Reads facts about this machine. When the Secure Boot state cannot be read, it counts as on: MOK is left alone.
    pub fn detect(r: &dyn Runner) -> Result<Facts> {
        let secure_boot = std::fs::read(SECURE_BOOT_EFIVAR)
            .map(|b| secure_boot_from_efivar(&b))
            .unwrap_or(true);
        let mok_enrolled = r
            .run(&Cmd::new("mokutil", &["--test-key", MOK_CERT]))
            .map(|o| o.stdout.contains("already enrolled"))
            .unwrap_or(false);
        let os = std::fs::read_to_string("/usr/lib/os-release").unwrap_or_default();
        let Some(image_version) = image_version_from_os_release(&os) else {
            bail!("os-release has no IMAGE_VERSION");
        };
        let lab = std::fs::read_to_string("/usr/lib/mastersos/profile")
            .map(|s| s.trim() == "lab")
            .unwrap_or(false);
        Ok(Facts {
            secure_boot,
            mok_enrolled,
            image_version,
            lab,
            ventoy: false,
        })
    }
}

/// The refusal text for a TPM verdict (the reason on one line, then what to change in BIOS); `Usable` is not refused (Ruling 17).
/// "Clear the TPM" is only given for lockout and the owner password: clearing does not help otherwise.
pub fn tpm_refusal_text(v: &TpmVerdict) -> Option<String> {
    const TURN_ON: &str = "Turn on TPM 2.0 under Security -> TPM 2.0 Security";
    const CLEAR: &str = "Clear the TPM in BIOS and try again";
    const SHA256: &str = "Switch the TPM PCR bank to SHA-256 in BIOS";
    const CONTACT: &str = "Could not tell whether this TPM works, please contact us";
    let (reason, advice) = match v {
        TpmVerdict::Usable => return None,
        TpmVerdict::Unusable(u) => (
            u.text(),
            match u {
                Unusable::NoTpm => TURN_ON,
                Unusable::NoSha256Bank => SHA256,
                Unusable::Lockout | Unusable::OwnerAuth => CLEAR,
            },
        ),
        TpmVerdict::Undecided(r) => (r.as_str(), CONTACT),
    };
    Some(format!(
        "No usable TPM 2.0, cannot install MastersOS\n\
         Reason: {reason}\n\
         {advice}"
    ))
}
