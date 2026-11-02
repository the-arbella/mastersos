use std::fs;
use std::path::{Path, PathBuf};

use super::*;
use mastersos_agent::runner::{FakeRunner, Output};
use mastersos_agent::secureboot::{
    pe_with_signatures, x509_signature_list, DB_VAR, SECURE_BOOT_VAR,
};

const MS_2011: &[u8] =
    include_bytes!("../../../../image/keys/microsoft/MicCorUEFCA2011_2011-06-27.der");
const MS_2023: &[u8] =
    include_bytes!("../../../../image/keys/microsoft/microsoft-uefi-ca-2023.der");

/// A temporary machine: sysfs (db, SecureBoot, PCI, firmware-attributes), the shim, a tmp for PEMs.
pub(crate) struct Machine {
    pub dir: tempfile::TempDir,
}

impl Machine {
    /// db holds 2011 and 2023, one AX201 (iwlwifi) from the allow list, nothing about a BIOS password.
    pub fn good() -> Machine {
        let m = Machine {
            dir: tempfile::tempdir().unwrap(),
        };
        fs::create_dir_all(m.sysfs().join("firmware/efi/efivars")).unwrap();
        fs::create_dir_all(m.tmp()).unwrap();
        fs::write(m.shim(), pe_with_signatures(&[&[0x30, 0x03, 1, 2, 3]])).unwrap();
        fs::write(m.sysfs().join(SECURE_BOOT_VAR), [6, 0, 0, 0, 1]).unwrap();
        m.db(Some(&[MS_2011, MS_2023]));
        m.pci(
            "0000:00:14.3",
            "0x028000",
            (0x8086, 0xa0f0),
            Some("iwlwifi"),
        );
        m
    }
    pub fn sysfs(&self) -> PathBuf {
        self.dir.path().join("sys")
    }
    pub fn shim(&self) -> PathBuf {
        self.dir.path().join("BOOTX64.EFI")
    }
    pub fn tmp(&self) -> PathBuf {
        self.dir.path().join("tmp")
    }
    /// None: remove the db variable; Some(&[]): attributes only.
    pub fn db(&self, certs: Option<&[&[u8]]>) {
        let p = self.sysfs().join(DB_VAR);
        match certs {
            None => {
                let _ = fs::remove_file(&p);
            }
            Some(cs) => {
                let mut v = vec![0x27, 0, 0, 0];
                for c in cs {
                    v.extend_from_slice(&x509_signature_list(&[c]));
                }
                fs::write(&p, v).unwrap();
            }
        }
    }
    pub fn raw_db(&self, bytes: &[u8]) {
        fs::write(self.sysfs().join(DB_VAR), bytes).unwrap();
    }
    pub fn pci(&self, slot: &str, class: &str, id: (u16, u16), driver: Option<&str>) {
        let d = self.sysfs().join("bus/pci/devices").join(slot);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("class"), format!("{class}\n")).unwrap();
        fs::write(d.join("vendor"), format!("0x{:04x}\n", id.0)).unwrap();
        fs::write(d.join("device"), format!("0x{:04x}\n", id.1)).unwrap();
        if let Some(drv) = driver {
            let t = self.sysfs().join("bus/pci/drivers").join(drv);
            fs::create_dir_all(&t).unwrap();
            std::os::unix::fs::symlink(&t, d.join("driver")).unwrap();
        }
    }
    pub fn no_pci(&self) {
        fs::remove_dir_all(self.sysfs().join("bus/pci/devices")).unwrap();
    }
    pub fn bios_admin(&self, enabled: bool) {
        let d = self
            .sysfs()
            .join("class/firmware-attributes/dell-wmi-sysman/authentication/Admin");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("role"), "bios-admin\n").unwrap();
        fs::write(d.join("is_enabled"), if enabled { "1\n" } else { "0\n" }).unwrap();
    }
    pub fn run(&self, r: &FakeRunner, profile: Profile) -> Vec<Finding> {
        let (sysfs, shim, tmp) = (self.sysfs(), self.shim(), self.tmp());
        precheck(&PrecheckEnv {
            runner: r,
            sysfs: &sysfs,
            profile,
            shim: &shim,
            tmp: &tmp,
        })
    }
}

/// openssl only counts as chaining with exit 0 and "Verification successful": the good machine's runner gets a few successes up front.
fn ok_runner() -> FakeRunner {
    let r = FakeRunner::new();
    for _ in 0..4 {
        r.respond("openssl smime", Output::ok("Verification successful\n"));
    }
    r
}

fn codes(f: &[Finding]) -> Vec<(&'static str, Level)> {
    f.iter().map(|f| (f.code, f.level)).collect()
}

/// openssl fails to chain every certificate in db (the shim does not chain).
fn no_chain(r: &FakeRunner, n: usize) {
    for _ in 0..n {
        r.respond(
            "openssl smime",
            Output::fail(4, "unable to get local issuer certificate"),
        );
    }
}

#[test]
fn all_pass_has_no_findings() {
    let m = Machine::good();
    let r = ok_runner();
    for p in [Profile::Release, Profile::Lab] {
        assert_eq!(m.run(&r, p), vec![]);
    }
    // Only the read-only openssl chain check and the sbverify hash check ran
    assert!(
        r.calls()
            .iter()
            .all(|c| c.starts_with("openssl smime -verify ") || c.starts_with("sbverify --cert ")),
        "{:?}",
        r.calls()
    );
    // A Dell without a password: no findings either
    m.bios_admin(false);
    assert_eq!(m.run(&ok_runner(), Profile::Release), vec![]);
}

#[test]
fn release_refuses_without_2023() {
    let m = Machine::good();
    m.db(Some(&[MS_2011]));
    let f = m.run(&ok_runner(), Profile::Release);
    assert_eq!(codes(&f), vec![("db_no_2023", Level::Refuse)]);
    let t = &f[0].text;
    assert!(t.contains("Microsoft UEFI CA 2023"), "{t}");
    let a = advice(&f, Profile::Release).unwrap();
    assert_eq!(a, FIX_ORDER);
    assert!(
        !a.contains("ms-cert=2023k"),
        "release gives no PVE note: {a}"
    );
}

#[test]
fn release_refuses_shim_no_chain() {
    // db has 2023 but not 2011, the shim only chains to 2011 (Canonical's shim today)
    let m = Machine::good();
    m.db(Some(&[MS_2023]));
    let r = FakeRunner::new();
    no_chain(&r, 1);
    let f = m.run(&r, Profile::Release);
    assert_eq!(codes(&f), vec![("shim_no_chain", Level::Refuse)]);
    assert_eq!(advice(&f, Profile::Release).as_deref(), Some(FIX_ORDER));
    // Cannot tell (sbverify missing): also refused, with the reason
    let r = ok_runner();
    r.respond("sbverify", Output::fail(127, "sbverify: not found"));
    let f = m.run(&r, Profile::Release);
    assert_eq!(codes(&f), vec![("shim_no_chain", Level::Refuse)]);
    assert!(f[0].text.contains("127"), "{}", f[0].text);
    // The shim cannot be read
    fs::remove_file(m.shim()).unwrap();
    let f = m.run(&FakeRunner::new(), Profile::Release);
    assert_eq!(codes(&f), vec![("shim_no_chain", Level::Refuse)]);
    assert!(f[0].text.contains("BOOTX64.EFI"), "{}", f[0].text);
}

#[test]
fn release_refuses_unreadable_db() {
    let m = Machine::good();
    type Set<'a> = &'a dyn Fn(&Machine);
    let cases: [(Set, &str); 3] = [
        (&|m| m.db(None), "no db variable"),
        (&|m| m.db(Some(&[])), "no certificates"),
        (
            &|m| m.raw_db(&[0x27, 0, 0, 0, 1, 2, 3]),
            "could not be parsed",
        ),
    ];
    for (set, why) in cases {
        set(&m);
        let r = FakeRunner::new();
        let f = m.run(&r, Profile::Release);
        assert_eq!(codes(&f), vec![("db_unreadable", Level::Refuse)], "{why}");
        assert!(f[0].text.contains(why), "{why}: {}", f[0].text);
        assert!(advice(&f, Profile::Release)
            .unwrap()
            .contains("Reset All Keys"));
        assert!(
            r.calls().is_empty(),
            "db unreadable: the shim is not checked: {:?}",
            r.calls()
        );
    }
}

#[test]
fn lab_warns_instead_of_refusing() {
    let m = Machine::good();
    m.db(Some(&[MS_2011]));
    let f = m.run(&ok_runner(), Profile::Lab);
    assert_eq!(codes(&f), vec![("db_no_2023", Level::Warn)]);
    m.db(Some(&[MS_2023]));
    let r = FakeRunner::new();
    no_chain(&r, 1);
    let f = m.run(&r, Profile::Lab);
    assert_eq!(codes(&f), vec![("shim_no_chain", Level::Warn)]);
    m.db(None);
    let f = m.run(&FakeRunner::new(), Profile::Lab);
    assert_eq!(codes(&f), vec![("db_unreadable", Level::Warn)]);
    let a = advice(&f, Profile::Lab).unwrap();
    assert!(a.contains("ms-cert=2023k"), "{a}");
    assert!(a.contains("virt-fw-vars"), "{a}");
    assert!(a.starts_with(FIX_ORDER), "{a}");
    // Warnings other than certificates come without a fix
    m.db(Some(&[MS_2011, MS_2023]));
    m.bios_admin(true);
    let f = m.run(&ok_runner(), Profile::Lab);
    assert_eq!(codes(&f), vec![("bios_admin_password", Level::Warn)]);
    assert_eq!(advice(&f, Profile::Lab), None);
}

#[test]
fn refusal_text_gives_fix_order() {
    let m = Machine::good();
    m.db(Some(&[MS_2011]));
    let f = m.run(&ok_runner(), Profile::Release);
    let t = &advice(&f, Profile::Release).unwrap();
    assert!(t.starts_with("Fix, in this order"), "{t}");
    assert!(
        !t.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)),
        "English only: {t}"
    );
    let in_order = |s: &str, words: &[&str]| {
        let pos: Vec<usize> = words
            .iter()
            .map(|w| s.find(w).unwrap_or_else(|| panic!("no \"{w}\": {s}")))
            .collect();
        assert!(
            pos.windows(2).all(|p| p[0] < p[1]),
            "{words:?} out of order: {s}"
        );
    };
    in_order(
        t,
        &["Update the BIOS", "Reset All Keys", "TPM", "Reinstall"],
    );
}

#[test]
fn bios_password_warns() {
    let m = Machine::good();
    m.bios_admin(true);
    for p in [Profile::Release, Profile::Lab] {
        let f = m.run(&ok_runner(), p);
        assert_eq!(codes(&f), vec![("bios_admin_password", Level::Warn)]);
        assert!(f[0].text.contains("BIOS admin password"), "{}", f[0].text);
    }
}

#[test]
fn wifi_tiers() {
    let run = |setup: &dyn Fn(&Machine)| {
        let m = Machine::good();
        m.no_pci();
        setup(&m);
        m.run(&ok_runner(), Profile::Release)
    };
    // On the allow list: no finding
    assert_eq!(
        run(&|m| m.pci(
            "0000:00:14.3",
            "0x028000",
            (0x8086, 0x2725),
            Some("iwlwifi")
        )),
        vec![]
    );
    // Intel, not listed, with a driver -> wifi_unlisted
    let f = run(&|m| {
        m.pci(
            "0000:00:14.3",
            "0x028000",
            (0x8086, 0x51f0),
            Some("iwlwifi"),
        )
    });
    assert_eq!(codes(&f), vec![("wifi_unlisted", Level::Warn)]);
    assert!(
        f[0].text.contains("8086:51f0") && f[0].text.contains("not been verified"),
        "{}",
        f[0].text
    );
    // Not Intel, with a driver -> wifi_non_intel
    let f = run(&|m| {
        m.pci(
            "0000:02:00.0",
            "0x028000",
            (0x168c, 0x003e),
            Some("ath10k_pci"),
        )
    });
    assert_eq!(codes(&f), vec![("wifi_non_intel", Level::Warn)]);
    assert!(
        f[0].text.contains("non-Intel") && f[0].text.contains("168c:003e"),
        "{}",
        f[0].text
    );
    // Broadcom without a driver -> wifi_unusable
    let f = run(&|m| m.pci("0000:02:00.0", "0x028000", (0x14e4, 0x43a0), None));
    assert_eq!(codes(&f), vec![("wifi_unusable", Level::Warn)]);
    assert!(f[0].text.contains("AX210"), "{}", f[0].text);
    // Broadcom counts as unusable even with a driver bound (wl)
    let f = run(&|m| m.pci("0000:02:00.0", "0x028000", (0x14e4, 0x43a0), Some("wl")));
    assert_eq!(codes(&f), vec![("wifi_unusable", Level::Warn)]);
    // Intel without a driver -> wifi_unusable
    let f = run(&|m| m.pci("0000:00:14.3", "0x028000", (0x8086, 0x51f0), None));
    assert_eq!(codes(&f), vec![("wifi_unusable", Level::Warn)]);
    // No Wi-Fi card (wired only) -> wifi_unusable
    let f = run(&|m| m.pci("0000:01:00.0", "0x020000", (0x10ec, 0x8168), Some("r8169")));
    assert_eq!(codes(&f), vec![("wifi_unusable", Level::Warn)]);
    assert!(f[0].text.contains("wired"), "{}", f[0].text);
    // Two cards: one listed, one not -> a warning only for the unlisted one
    let f = run(&|m| {
        m.pci(
            "0000:00:14.3",
            "0x028000",
            (0x8086, 0xa0f0),
            Some("iwlwifi"),
        );
        m.pci(
            "0000:02:00.0",
            "0x028000",
            (0x10ec, 0xc822),
            Some("rtw88_8822ce"),
        );
    });
    assert_eq!(codes(&f), vec![("wifi_non_intel", Level::Warn)]);
}

#[test]
fn profile_reads_usr_lib_mastersos_profile() {
    let d = tempfile::tempdir().unwrap();
    assert_eq!(Profile::detect(d.path()), Profile::Release);
    let p: &Path = &d.path().join("usr/lib/mastersos");
    fs::create_dir_all(p).unwrap();
    fs::write(p.join("profile"), "lab\n").unwrap();
    assert_eq!(Profile::detect(d.path()), Profile::Lab);
    fs::write(p.join("profile"), "release\n").unwrap();
    assert_eq!(Profile::detect(d.path()), Profile::Release);
}

/// 2023 missing and the shim does not chain: two refusals, the fix given once (review Minor 9).
#[test]
fn advice_given_once_for_several_findings() {
    let m = Machine::good();
    m.db(Some(&[MS_2011]));
    let r = FakeRunner::new();
    no_chain(&r, 1);
    let f = m.run(&r, Profile::Release);
    assert_eq!(
        codes(&f),
        vec![
            ("db_no_2023", Level::Refuse),
            ("shim_no_chain", Level::Refuse)
        ]
    );
    assert!(
        f.iter().all(|x| !x.text.contains("Fix, in this order")),
        "{f:?}"
    );
    assert_eq!(advice(&f, Profile::Release).as_deref(), Some(FIX_ORDER));
}

/// dbx: shim revoked -> shim_no_chain (refused under release); dbx not understood -> also refused, with the reason (review I1).
#[test]
fn dbx_revocation_refuses() {
    use mastersos_agent::secureboot::{
        authenticode_sha256, sha256_signature_list, DBX_VAR, REVOKED_ADVICE,
    };
    let m = Machine::good();
    let h = authenticode_sha256(&fs::read(m.shim()).unwrap()).unwrap();
    let mut dbx = vec![0x27, 0, 0, 0];
    dbx.extend_from_slice(&sha256_signature_list(&[h]));
    fs::write(m.sysfs().join(DBX_VAR), &dbx).unwrap();
    let f = m.run(&ok_runner(), Profile::Release);
    assert_eq!(codes(&f), vec![(SHIM_REVOKED, Level::Refuse)]);
    assert!(f[0].text.contains("dbx"), "{}", f[0].text);
    // The fix for a revoked shim is a newer image, never Reset All Keys (review N3)
    let a = advice(&f, Profile::Release).unwrap();
    assert_eq!(a, REVOKED_ADVICE);
    assert!(!a.contains("Reset All Keys"), "{a}");
    let f = m.run(&ok_runner(), Profile::Lab);
    assert_eq!(codes(&f), vec![(SHIM_REVOKED, Level::Warn)]);
    assert_eq!(advice(&f, Profile::Lab).as_deref(), Some(REVOKED_ADVICE));
    // 2023 missing as well: still only "use a newer image" (Reset All Keys may reset dbx to before the revocation)
    m.db(Some(&[MS_2011]));
    let f = m.run(&ok_runner(), Profile::Release);
    assert_eq!(
        codes(&f),
        vec![("db_no_2023", Level::Refuse), (SHIM_REVOKED, Level::Refuse)]
    );
    assert_eq!(
        advice(&f, Profile::Release).as_deref(),
        Some(REVOKED_ADVICE)
    );
    m.db(Some(&[MS_2011, MS_2023]));
    // dbx not understood: cannot tell, handled as "does not chain" (the Reset All Keys set)
    fs::write(m.sysfs().join(DBX_VAR), [0x27, 0, 0, 0, 1, 2]).unwrap();
    let r = ok_runner();
    let f = m.run(&r, Profile::Release);
    assert_eq!(codes(&f), vec![("shim_no_chain", Level::Refuse)]);
    assert!(f[0].text.contains("dbx"), "{}", f[0].text);
    assert!(r.calls().is_empty(), "{:?}", r.calls());
    // dbx with attributes only (empty): nothing revoked
    fs::write(m.sysfs().join(DBX_VAR), [0x27, 0, 0, 0]).unwrap();
    assert_eq!(m.run(&ok_runner(), Profile::Release), vec![]);
}

const LAB_MOK: &[u8] =
    include_bytes!("../../../../image/mkosi.extra/usr/share/mastersos/untrusted-mok/lab.der");
const OLD_LAB_MOK: &[u8] = include_bytes!(
    "../../../../image/mkosi.extra/usr/share/mastersos/untrusted-mok/lab-2026-10.der"
);
const PRE_MOK: &[u8] = include_bytes!(
    "../../../../image/mkosi.extra/usr/share/mastersos/untrusted-mok/pre-release.der"
);

fn set_mok(m: &Machine, certs: &[&[u8]]) {
    let mut v = vec![0x27, 0, 0, 0];
    for c in certs {
        v.extend_from_slice(&x509_signature_list(&[c]));
    }
    fs::write(m.sysfs().join(mastersos_agent::secureboot::MOK_LIST_VAR), v).unwrap();
}

fn mok_codes(f: &[Finding]) -> Vec<&Finding> {
    f.iter().filter(|f| f.code == "mok_untrusted").collect()
}

#[test]
fn warns_on_lab_mok() {
    let m = Machine::good();
    set_mok(&m, &[MS_2011, LAB_MOK]);
    let f = m.run(&ok_runner(), Profile::Release);
    assert_eq!(codes(&f), vec![("mok_untrusted", Level::Warn)]);
    assert!(f[0].text.contains("lab"), "{}", f[0].text);
    assert!(f[0].text.contains("mokutil --delete"), "{}", f[0].text);
    assert!(f[0].text.contains("untrusted-mok/lab.der"), "{}", f[0].text);
}

#[test]
fn warns_on_old_lab_mok() {
    let m = Machine::good();
    set_mok(&m, &[MS_2011, OLD_LAB_MOK]);
    let f = m.run(&ok_runner(), Profile::Release);
    assert_eq!(codes(&f), vec![("mok_untrusted", Level::Warn)]);
    assert!(f[0].text.contains("retired"), "{}", f[0].text);
    assert!(
        f[0].text.contains("untrusted-mok/lab-2026-10.der"),
        "{}",
        f[0].text
    );
}

#[test]
fn warns_on_retired_mok() {
    let m = Machine::good();
    set_mok(&m, &[PRE_MOK]);
    let f = m.run(&ok_runner(), Profile::Release);
    assert_eq!(codes(&f), vec![("mok_untrusted", Level::Warn)]);
    assert!(f[0].text.contains("pre-release"), "{}", f[0].text);
    assert!(f[0].text.contains("untrusted-mok/pre-release.der"));
}

#[test]
fn no_warning_for_release_mok_only() {
    let m = Machine::good();
    set_mok(&m, &[MS_2011]);
    assert_eq!(m.run(&ok_runner(), Profile::Release), vec![]);
}

#[test]
fn lab_profile_does_not_check_mok() {
    let m = Machine::good();
    set_mok(&m, &[LAB_MOK, PRE_MOK]);
    assert!(mok_codes(&m.run(&ok_runner(), Profile::Lab)).is_empty());
    assert_eq!(mok_codes(&m.run(&ok_runner(), Profile::Release)).len(), 2);
}

#[test]
fn mok_list_unreadable_is_silent() {
    let m = Machine::good();
    fs::write(
        m.sysfs().join(mastersos_agent::secureboot::MOK_LIST_VAR),
        [0x27, 0, 0, 0, 1, 2, 3],
    )
    .unwrap();
    assert_eq!(m.run(&ok_runner(), Profile::Release), vec![]);
}
