use super::*;
use crate::runner::{FakeRunner, Output};
use crate::system::tests::{paths, tmp_root};
use std::os::unix::fs::PermissionsExt;

// Fixtures from VM 170 (lab/results/2026-10-19-5/t8-shim-update.txt): the .sbatlevel sections of shim 15.7 and of the
// image's shim 15.8 (objcopy), the secure-boot authority component, event log, prediction and PCR 7 in the 15.7 state.
const SL_157: &[u8] = include_bytes!("../../tests/fixtures/shim/sbatlevel-shim-15.7.bin");
const SL_158: &[u8] = include_bytes!("../../tests/fixtures/shim/sbatlevel-shim-15.8.bin");
const GENERATED_157: &str = include_str!("../../tests/fixtures/shim/620-generated-15.7.pcrlock");
const LOG_157: &str = include_str!("../../tests/fixtures/shim/pcrlock-log-15.7.json");
const PREDICT_157: &str = include_str!("../../tests/fixtures/shim/predict-15.7.json");
const PCR7_157: &str = include_str!("../../tests/fixtures/shim/pcr7-15.7.txt");
const SBATRT_157: &[u8] = include_bytes!("../../tests/fixtures/shim/SbatLevelRT-15.7.bin");
const SEALED: &str = include_str!("../../tests/fixtures/luksdump-sealed.json");
const FIRST_BOOT: &str = include_str!("../../tests/fixtures/luksdump-first-boot.json");

const V157: &[u8] = b"sbat,1,2022052400\ngrub,2\n";
const V158: &[u8] = b"sbat,1,2023012900\nshim,2\ngrub,3\ngrub.debian,4\n";
/// Event-log digests of the two SbatLevel values (systemd-pcrlock log on VM 170).
const D157: &str = "12b3913481a767dc4c9a729a7287fcb85ca365bc808e3fb7d438c2d8823cea20";
const D158: &str = "e8e9578f5951ef16b1c1aa18ef02944b8375ec45ed4b5d8cdb30428db4a31016";
/// PCR 7 measured on VM 170 after the real swap to shim 15.8.
const PCR7_158: &str = "46a486abd7782f6ab3fb27df689e68ac49f8b49f5913d1632f8b5a29331082ec";
const UUID: &str = "f9fd9985-7280-4c3d-bab4-f132ac2336f2";

fn h(s: &str) -> [u8; 32] {
    parse_hex32(s).unwrap()
}

/// A minimal PE32+ image with a `.text` section and the section `name` holding `data`; names longer than 8 bytes go
/// through the COFF string table as `/4`, the way shim's own `.sbatlevel` does.
fn pe_with_section(name: &[u8], data: &[u8]) -> Vec<u8> {
    let mut pe = vec![0u8; 0x400];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    pe[0x40..0x44].copy_from_slice(b"PE\0\0");
    let coff = 0x44;
    pe[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    pe[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
    let strtab = 0x300u32;
    pe[coff + 8..coff + 12].copy_from_slice(&strtab.to_le_bytes());
    // no symbols, no optional header
    let sec = |pe: &mut Vec<u8>, i: usize, n: &[u8], ptr: u32, len: u32| {
        let s = coff + 20 + i * 40;
        pe[s..s + n.len()].copy_from_slice(n);
        pe[s + 8..s + 12].copy_from_slice(&len.to_le_bytes());
        pe[s + 16..s + 20].copy_from_slice(&len.next_multiple_of(16).to_le_bytes());
        pe[s + 20..s + 24].copy_from_slice(&ptr.to_le_bytes());
    };
    sec(&mut pe, 0, b".text", 0x200, 16);
    let short: Vec<u8> = if name.len() > 8 {
        let t = strtab as usize;
        pe[t + 4..t + 4 + name.len()].copy_from_slice(name);
        b"/4".to_vec()
    } else {
        name.to_vec()
    };
    sec(&mut pe, 1, &short, 0x400, data.len() as u32);
    pe.extend_from_slice(data);
    pe.resize(0x400 + (data.len()).next_multiple_of(16), 0);
    pe
}

// ---------- pure part ----------

#[test]
fn parses_sbatlevel_of_shim_15_8() {
    let l = parse_sbatlevel_payload(SL_158).unwrap();
    assert!(l.previous.starts_with(b"sbat,1,2023012900"), "{l:?}");
    assert_eq!(l.previous, V158);
    assert_eq!(
        l.latest,
        b"sbat,1,2024010900\nshim,4\ngrub,3\ngrub.debian,4\n"
    );
    // the same through a PE image with a long (string-table) section name
    let pe = pe_with_section(b".sbatlevel", SL_158);
    assert_eq!(parse_sbatlevel_section(&pe).unwrap(), l);
    assert_eq!(parse_sbatlevel_payload(SL_157).unwrap().previous, V157);
}

#[test]
fn finds_short_section_names_too() {
    let pe = pe_with_section(b".sbat", b"hello");
    assert_eq!(&pe_section(&pe, b".sbat").unwrap()[..5], b"hello");
}

/// A real shim, when one is given (`MASTERSOS_TEST_SHIM=<shimx64.efi>`; not in the repository).
#[test]
fn parses_a_real_shim_when_given() {
    let Ok(p) = std::env::var("MASTERSOS_TEST_SHIM") else {
        return;
    };
    let l = parse_sbatlevel_section(&std::fs::read(p).unwrap()).unwrap();
    assert!(l.previous.starts_with(b"sbat,1,"), "{l:?}");
}

#[test]
fn rejects_bad_section() {
    let mut v = SL_158.to_vec();
    v[0] = 1;
    assert!(parse_sbatlevel_payload(&v).unwrap_err().contains("version"));
    let mut v = SL_158.to_vec();
    v[4..8].copy_from_slice(&1000u32.to_le_bytes());
    assert!(parse_sbatlevel_payload(&v)
        .unwrap_err()
        .contains("out of bounds"));
    let v: Vec<u8> = SL_158
        .iter()
        .map(|&c| if c == 0 { b'x' } else { c })
        .collect();
    let mut v = v;
    v[0..12].copy_from_slice(&SL_158[0..12]);
    assert!(parse_sbatlevel_payload(&v).unwrap_err().contains("NUL"));
    assert!(parse_sbatlevel_payload(&SL_158[..6]).is_err());
    assert!(parse_sbatlevel_section(&pe_with_section(b".sbat", SL_158))
        .unwrap_err()
        .contains("no .sbatlevel"));
    assert!(parse_sbatlevel_section(b"not a pe").is_err());
}

#[test]
fn next_level_when_previous_is_newer() {
    let l = parse_sbatlevel_payload(SL_158).unwrap();
    assert_eq!(next_sbat_level(V157, &l).unwrap().as_deref(), Some(V158));
}

#[test]
fn no_change_when_same_or_older() {
    let l158 = parse_sbatlevel_payload(SL_158).unwrap();
    assert_eq!(next_sbat_level(V158, &l158).unwrap(), None);
    let l157 = parse_sbatlevel_payload(SL_157).unwrap();
    assert_eq!(next_sbat_level(V158, &l157).unwrap(), None);
}

#[test]
fn cannot_tell_is_an_error() {
    let l = parse_sbatlevel_payload(SL_158).unwrap();
    assert!(next_sbat_level(b"sbat,1,20230129\n", &l).is_err());
    assert!(next_sbat_level(b"", &l).is_err());
    let bad = SbatLevels {
        previous: b"sbat,2,2023012900\n".to_vec(),
        latest: vec![],
    };
    assert!(next_sbat_level(V157, &bad).is_err());
}

#[test]
fn authority_digest_matches_event_log() {
    assert_eq!(hex(&authority_digest("SbatLevel", SHIM_GUID, V157)), D157);
    assert_eq!(hex(&authority_digest("SbatLevel", SHIM_GUID, V158)), D158);
    // the 15.7 digest is the one in the fixture's event log and component
    assert!(LOG_157.contains(D157) && GENERATED_157.contains(D157));
    assert_eq!(&SBATRT_157[4..], V157);
}

#[test]
fn variant_replaces_exactly_one_record() {
    let v = variant_with_sbat(GENERATED_157, h(D157), h(D158)).unwrap();
    let a: Value = serde_json::from_str(GENERATED_157).unwrap();
    let b: Value = serde_json::from_str(&v).unwrap();
    let (ra, rb) = (
        a["records"].as_array().unwrap(),
        b["records"].as_array().unwrap(),
    );
    assert_eq!(ra.len(), rb.len());
    let changed: Vec<usize> = (0..ra.len()).filter(|&i| ra[i] != rb[i]).collect();
    assert_eq!(changed.len(), 1);
    assert_eq!(rb[changed[0]]["digests"][0]["digest"], D158);
    assert_eq!(rb[changed[0]]["pcr"], 7);
}

#[test]
fn variant_refuses_missing_or_duplicate() {
    // missing
    assert!(variant_with_sbat(GENERATED_157, h(D158), h(D157)).is_err());
    // duplicate
    let mut v: Value = serde_json::from_str(GENERATED_157).unwrap();
    let rec = v["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["digests"][0]["digest"] == D157)
        .unwrap()
        .clone();
    v["records"].as_array_mut().unwrap().push(rec.clone());
    assert!(variant_with_sbat(&v.to_string(), h(D157), h(D158))
        .unwrap_err()
        .contains("2 PCR 7 records"));
    // another hash algorithm in the matching record
    let mut v: Value = serde_json::from_str(GENERATED_157).unwrap();
    for r in v["records"].as_array_mut().unwrap() {
        if r["digests"][0]["digest"] == D157 {
            r["digests"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({"hashAlg": "sha384", "digest": "00"}));
        }
    }
    assert!(variant_with_sbat(&v.to_string(), h(D157), h(D158)).is_err());
    assert!(variant_with_sbat("{", h(D157), h(D158)).is_err());
}

#[test]
fn replay_reproduces_pcr7_and_predicts_the_swap() {
    assert_eq!(replay_pcr7(LOG_157, None).unwrap(), h(PCR7_157));
    assert_eq!(
        replay_pcr7(LOG_157, Some((h(D157), h(D158)))).unwrap(),
        h(PCR7_158)
    );
    // the digest to swap must be there exactly once
    assert!(replay_pcr7(LOG_157, Some((h(D158), h(D157)))).is_err());
}

#[test]
fn parses_prediction() {
    let v = predicted_pcr7(PREDICT_157).unwrap();
    assert!(v.contains(&h(PCR7_157)), "{v:?}");
    assert!(predicted_pcr7("{}").is_err());
}

// ---------- prepare ----------

struct Machine {
    _dir: tempfile::TempDir,
    paths: SysPaths,
    sysfs: std::path::PathBuf,
    fake: FakeRunner,
    shim: std::path::PathBuf,
}

const PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn predict_json(values: &[&str]) -> String {
    serde_json::json!({"sha256": [{"pcr": 7, "values": values}]}).to_string()
}

/// A machine in the 15.7 state: sealed to pcrlock, Secure Boot on, the agent's PIN, the 15.7 component; the new shim
/// is a PE carrying 15.8's `.sbatlevel`.
fn machine() -> Machine {
    let dir = tmp_root();
    let paths = paths(dir.path());
    let sysfs = dir.path().join("sys");
    let vars = sysfs.join("firmware/efi/efivars");
    std::fs::create_dir_all(&vars).unwrap();
    std::fs::write(
        sysfs.join(crate::secureboot::SECURE_BOOT_VAR),
        [6, 0, 0, 0, 1],
    )
    .unwrap();
    std::fs::write(sysfs.join(SBAT_LEVEL_RT_VAR), SBATRT_157).unwrap();
    std::fs::create_dir_all(sysfs.join("class/tpm/tpm0/pcr-sha256")).unwrap();
    std::fs::write(sysfs.join(PCR7_SYSFS), PCR7_157).unwrap();
    let comp = dir.path().join(AUTHORITY_DIR);
    std::fs::create_dir_all(&comp).unwrap();
    std::fs::write(comp.join(GENERATED), GENERATED_157).unwrap();
    std::fs::create_dir_all(&paths.state_dir).unwrap();
    std::fs::write(paths.state_dir.join(luks::PCRLOCK_PIN), PIN).unwrap();
    std::fs::create_dir_all(dir.path().join("proc/sys/kernel/random")).unwrap();
    std::fs::write(
        dir.path().join("proc/sys/kernel/random/boot_id"),
        "boot-a\n",
    )
    .unwrap();
    let shim = dir.path().join("BOOTX64.EFI");
    std::fs::write(&shim, pe_with_section(b".sbatlevel", SL_158)).unwrap();
    let fake = FakeRunner::new();
    let b = Machine {
        _dir: dir,
        paths,
        sysfs,
        fake,
        shim,
    };
    b.luks(SEALED);
    b.fake.respond(
        "/usr/lib/systemd/systemd-pcrlock log --json=short",
        Output::ok(LOG_157),
    );
    b
}

impl Machine {
    fn luks(&self, dump: &str) {
        self.fake
            .respond("cryptsetup luksUUID", Output::ok(&format!("{UUID}\n")));
        self.fake.respond("cryptsetup luksDump", Output::ok(dump));
    }
    fn predicts(&self, values: &[&str]) {
        self.fake.respond(
            "/usr/lib/systemd/systemd-pcrlock predict",
            Output::ok(&predict_json(values)),
        );
    }
    fn prepare(&self) -> PrepareOutcome {
        prepare(&self.sysfs, &self.paths, &self.fake, &self.shim)
    }
    fn comp(&self) -> std::path::PathBuf {
        self.paths.root.join(AUTHORITY_DIR)
    }
    fn variant(&self) -> std::path::PathBuf {
        self.comp().join(NEXT_SHIM_VARIANT)
    }
    fn state(&self) -> PrepareState {
        load_state(&self.paths).unwrap().unwrap()
    }
    fn make_policy_calls(&self) -> usize {
        self.fake
            .calls()
            .iter()
            .filter(|c| c.contains("make-policy --location=770 --pcr=7 --recovery-pin=query"))
            .count()
    }
    fn dir_snapshot(&self) -> Vec<(String, Vec<u8>)> {
        let mut v: Vec<(String, Vec<u8>)> = std::fs::read_dir(self.comp())
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (
                    e.file_name().to_string_lossy().into_owned(),
                    std::fs::read(e.path()).unwrap(),
                )
            })
            .collect();
        v.sort();
        v
    }
}

#[test]
fn prepare_adds_the_variant_and_checks_the_prediction() {
    let m = machine();
    m.predicts(&[PCR7_157.trim(), PCR7_158]);
    assert_eq!(m.prepare(), PrepareOutcome::Prepared);
    let v = std::fs::read_to_string(m.variant()).unwrap();
    assert_eq!(
        v,
        variant_with_sbat(GENERATED_157, h(D157), h(D158)).unwrap()
    );
    assert_eq!(
        std::fs::metadata(m.variant()).unwrap().permissions().mode() & 0o777,
        0o644
    );
    // generated.pcrlock untouched
    assert_eq!(
        std::fs::read_to_string(m.comp().join(GENERATED)).unwrap(),
        GENERATED_157
    );
    let calls = m.fake.calls();
    let make = calls
        .iter()
        .position(|c| c.contains("make-policy"))
        .unwrap();
    let pred = calls.iter().position(|c| c.contains("predict")).unwrap();
    assert!(make < pred, "{calls:?}");
    assert!(calls.iter().all(|c| !c.contains(PIN)), "{calls:?}");
    assert!(calls[make].contains("CREDENTIALS_DIRECTORY="));
    let s = m.state();
    assert_eq!(s.outcome, Outcome::Prepared);
    assert_eq!(
        s.predicted_sbat_sha256.as_deref(),
        Some(hex(&Sha256::digest(V158)).as_str())
    );
    assert_eq!(s.boot_id, "boot-a");
    assert_eq!(
        s.shim_sha256,
        hex(&Sha256::digest(std::fs::read(&m.shim).unwrap()))
    );
    assert_eq!(
        std::fs::metadata(m.paths.var_dir.join(STATE_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    // the PIN credential is gone
    assert!(!m
        .paths
        .root
        .join("run/mastersos-agent/shim-prepare-cred/pcrlock.recovery-pin")
        .exists());
}

#[test]
fn prepare_not_needed_without_pcrlock_slot() {
    let m = machine();
    let fresh = FakeRunner::new();
    fresh.respond("cryptsetup luksUUID", Output::ok(&format!("{UUID}\n")));
    fresh.respond("cryptsetup luksDump", Output::ok(FIRST_BOOT));
    let r = prepare(&m.sysfs, &m.paths, &fresh, &m.shim);
    assert!(
        matches!(r, PrepareOutcome::NotNeeded(ref w) if w.contains("pcrlock")),
        "{r:?}"
    );
    assert!(!m.variant().exists());
    assert!(!fresh.calls().iter().any(|c| c.contains("systemd-pcrlock")));
    assert_eq!(m.state().outcome, Outcome::NotNeeded);
}

#[test]
fn prepare_not_needed_when_sb_off() {
    let m = machine();
    std::fs::write(
        m.sysfs.join(crate::secureboot::SECURE_BOOT_VAR),
        [6, 0, 0, 0, 0],
    )
    .unwrap();
    let r = m.prepare();
    assert!(
        matches!(r, PrepareOutcome::NotNeeded(ref w) if w.contains("Secure Boot")),
        "{r:?}"
    );
    assert!(!m.variant().exists());
    assert_eq!(m.make_policy_calls(), 0);
}

#[test]
fn prepare_not_needed_when_the_new_shim_keeps_sbatlevel() {
    let m = machine();
    let mut rt = vec![6, 0, 0, 0];
    rt.extend_from_slice(V158);
    std::fs::write(m.sysfs.join(SBAT_LEVEL_RT_VAR), rt).unwrap();
    let r = m.prepare();
    assert!(
        matches!(r, PrepareOutcome::NotNeeded(ref w) if w.contains("does not rewrite")),
        "{r:?}"
    );
    assert!(!m.variant().exists());
}

#[test]
fn prepare_restores_files_on_policy_failure() {
    let m = machine();
    let before = m.dir_snapshot();
    m.fake.respond(
        "env CREDENTIALS_DIRECTORY=",
        Output::fail(1, "Failed to write policy"),
    );
    let r = m.prepare();
    assert!(matches!(r, PrepareOutcome::Failed(_)), "{r:?}");
    assert_eq!(m.dir_snapshot(), before);
    // the undo re-made the policy once more
    assert_eq!(m.make_policy_calls(), 2);
    let s = m.state();
    assert_eq!(s.outcome, Outcome::Failed);
    assert!(s.reason.unwrap().contains("PIN"));
}

#[test]
fn prepare_requires_both_values_in_prediction() {
    for values in [vec![PCR7_157.trim()], vec![PCR7_158]] {
        let m = machine();
        let before = m.dir_snapshot();
        m.predicts(&values);
        let r = m.prepare();
        assert!(
            matches!(r, PrepareOutcome::Failed(ref w) if w.contains("does not accept")),
            "{r:?}"
        );
        assert_eq!(m.dir_snapshot(), before);
        assert_eq!(m.make_policy_calls(), 2);
    }
}

#[test]
fn prepare_refuses_when_the_event_log_does_not_replay() {
    let m = machine();
    std::fs::write(m.sysfs.join(PCR7_SYSFS), "00".repeat(32)).unwrap();
    let r = m.prepare();
    assert!(
        matches!(r, PrepareOutcome::Failed(ref w) if w.contains("replaying")),
        "{r:?}"
    );
    assert!(!m.variant().exists());
    assert_eq!(m.make_policy_calls(), 0);
}

#[test]
fn prepare_without_pin_fails_before_writing() {
    let m = machine();
    std::fs::remove_file(m.paths.state_dir.join(luks::PCRLOCK_PIN)).unwrap();
    let r = m.prepare();
    assert!(
        matches!(r, PrepareOutcome::Failed(ref w) if w.contains("PIN")),
        "{r:?}"
    );
    assert!(!m.variant().exists());
}

fn mark_lab(root: &Path) {
    let p = root.join(luks::IMAGE_PROFILE.trim_start_matches('/'));
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, "lab\n").unwrap();
}

#[test]
fn test_fail_marker_only_on_lab_images() {
    let m = machine();
    let marker = m.paths.root.join(TEST_FAIL_MARKER);
    std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
    std::fs::write(&marker, "").unwrap();
    mark_lab(&m.paths.root);
    assert_eq!(
        m.prepare(),
        PrepareOutcome::Failed("test: forced failure".into())
    );
    assert!(!m.variant().exists());
}

#[test]
fn test_fail_marker_ignored_on_release_image() {
    let m = machine();
    let marker = m.paths.root.join(TEST_FAIL_MARKER);
    std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
    std::fs::write(&marker, "").unwrap();
    m.predicts(&[PCR7_157.trim(), PCR7_158]);
    assert_eq!(m.prepare(), PrepareOutcome::Prepared);
}

// ---------- follow-up ----------

fn reboot_into(m: &Machine, sbat: &[u8]) {
    let mut rt = vec![6, 0, 0, 0];
    rt.extend_from_slice(sbat);
    std::fs::write(m.sysfs.join(SBAT_LEVEL_RT_VAR), rt).unwrap();
    std::fs::write(
        m.paths.root.join("proc/sys/kernel/random/boot_id"),
        "boot-b\n",
    )
    .unwrap();
}

#[test]
fn followup_waits_in_the_same_boot() {
    let m = machine();
    m.predicts(&[PCR7_157.trim(), PCR7_158]);
    assert_eq!(m.prepare(), PrepareOutcome::Prepared);
    let f = FakeRunner::new();
    assert_eq!(
        followup(&m.sysfs, &m.paths, &f, false).unwrap(),
        Followup::Nothing
    );
    assert!(m.variant().exists());
    assert!(f.calls().is_empty());
}

#[test]
fn followup_completes_after_the_new_shim_boots() {
    let m = machine();
    m.predicts(&[PCR7_157.trim(), PCR7_158]);
    assert_eq!(m.prepare(), PrepareOutcome::Prepared);
    reboot_into(&m, V158);
    let f = FakeRunner::new();
    assert_eq!(
        followup(&m.sysfs, &m.paths, &f, false).unwrap(),
        Followup::Completed
    );
    assert!(!m.variant().exists());
    assert!(m.comp().join(GENERATED).exists());
    assert_eq!(m.state().outcome, Outcome::Completed);
    assert_eq!(
        f.calls()
            .iter()
            .filter(|c| c.contains("make-policy"))
            .count(),
        1
    );
}

#[test]
fn followup_reports_the_completion_until_the_next_boot() {
    let m = machine();
    m.predicts(&[PCR7_157.trim(), PCR7_158]);
    assert_eq!(m.prepare(), PrepareOutcome::Prepared);
    reboot_into(&m, V158);
    let f = FakeRunner::new();
    assert_eq!(
        followup(&m.sysfs, &m.paths, &f, false).unwrap(),
        Followup::Completed
    );
    // later rounds in the same boot: still reported, nothing re-made
    assert_eq!(
        followup(&m.sysfs, &m.paths, &f, false).unwrap(),
        Followup::Completed
    );
    assert_eq!(
        f.calls()
            .iter()
            .filter(|c| c.contains("make-policy"))
            .count(),
        1
    );
    std::fs::write(
        m.paths.root.join("proc/sys/kernel/random/boot_id"),
        "boot-c\n",
    )
    .unwrap();
    assert_eq!(
        followup(&m.sysfs, &m.paths, &f, false).unwrap(),
        Followup::Nothing
    );
    assert!(load_state(&m.paths).unwrap().is_none());
}

#[test]
fn followup_drops_the_variant_when_the_prediction_did_not_come_true() {
    let m = machine();
    m.predicts(&[PCR7_157.trim(), PCR7_158]);
    assert_eq!(m.prepare(), PrepareOutcome::Prepared);
    reboot_into(&m, V157);
    let f = FakeRunner::new();
    assert_eq!(
        followup(&m.sysfs, &m.paths, &f, false).unwrap(),
        Followup::Nothing
    );
    assert!(!m.variant().exists());
    assert!(load_state(&m.paths).unwrap().is_none());
}

#[test]
fn followup_reports_a_failed_prepare_until_the_reboot() {
    let m = machine();
    m.fake
        .respond("env CREDENTIALS_DIRECTORY=", Output::fail(1, "nope"));
    assert!(matches!(m.prepare(), PrepareOutcome::Failed(_)));
    let f = FakeRunner::new();
    assert!(matches!(
        followup(&m.sysfs, &m.paths, &f, false).unwrap(),
        Followup::PrepareFailed(_)
    ));
    reboot_into(&m, V158);
    assert_eq!(
        followup(&m.sysfs, &m.paths, &f, false).unwrap(),
        Followup::Nothing
    );
    assert!(load_state(&m.paths).unwrap().is_none());
}

#[test]
fn followup_removes_a_variant_without_a_record() {
    let m = machine();
    std::fs::write(m.variant(), "{}").unwrap();
    let f = FakeRunner::new();
    assert_eq!(
        followup(&m.sysfs, &m.paths, &f, false).unwrap(),
        Followup::Nothing
    );
    assert!(!m.variant().exists());
    assert_eq!(
        f.calls()
            .iter()
            .filter(|c| c.contains("make-policy"))
            .count(),
        1
    );
}

#[test]
fn followup_reports_a_misprediction_when_the_policy_failed_in_that_boot() {
    let m = machine();
    m.predicts(&[PCR7_157.trim(), PCR7_158]);
    assert_eq!(m.prepare(), PrepareOutcome::Prepared);
    reboot_into(&m, V158);
    let f = FakeRunner::new();
    // the SbatLevel came out as predicted, but the policy service failed in this boot: not "completed"
    assert_eq!(
        followup(&m.sysfs, &m.paths, &f, true).unwrap(),
        Followup::Mispredicted
    );
    assert!(!m.variant().exists());
    assert_eq!(m.state().outcome, Outcome::Mispredicted);
    // and it stays that way for the rest of the boot, even once the policy is fine again
    assert_eq!(
        followup(&m.sysfs, &m.paths, &f, false).unwrap(),
        Followup::Mispredicted
    );
}

#[test]
fn a_later_policy_failure_in_the_same_boot_overrides_completed() {
    let m = machine();
    m.predicts(&[PCR7_157.trim(), PCR7_158]);
    assert_eq!(m.prepare(), PrepareOutcome::Prepared);
    reboot_into(&m, V158);
    let f = FakeRunner::new();
    assert_eq!(
        followup(&m.sysfs, &m.paths, &f, false).unwrap(),
        Followup::Completed
    );
    assert_eq!(
        followup(&m.sysfs, &m.paths, &f, true).unwrap(),
        Followup::Mispredicted
    );
    assert_eq!(m.state().outcome, Outcome::Mispredicted);
}

#[test]
fn prepare_fails_when_sbat_policy_is_set() {
    let m = machine();
    std::fs::write(m.sysfs.join(SBAT_POLICY_VAR), [7, 0, 0, 0, 1]).unwrap();
    let r = m.prepare();
    assert!(
        matches!(r, PrepareOutcome::Failed(ref w) if w.contains("SbatPolicy")),
        "{r:?}"
    );
    assert!(!m.variant().exists());
    assert_eq!(m.make_policy_calls(), 0);
}

#[test]
fn zero_symbol_table_pointer_means_no_string_table() {
    let mut pe = pe_with_section(b".sbatlevel", SL_158);
    pe[0x44 + 8..0x44 + 12].copy_from_slice(&0u32.to_le_bytes());
    let e = pe_section(&pe, b".sbatlevel").unwrap_err();
    assert!(e.contains("without a string table"), "{e}");
}
