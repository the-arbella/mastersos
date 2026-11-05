use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use mastersos_agent::runner::Cmd;
use mastersos_bundle::{KeyAlg, Seed, TrustKey};
use mastersos_installer::disk::*;
use mastersos_installer::firstrun::*;
use mastersos_installer::mode::*;
use mastersos_installer::plan::*;
use mastersos_installer::seed::*;

fn fixture(name: &str) -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

fn disk(path: &str, size: u64, removable: bool, tran: Option<&str>) -> Disk {
    Disk {
        path: path.into(),
        model: Some("M".into()),
        size,
        removable,
        tran: tran.map(Into::into),
        is_installer: false,
        seed_part: None,
        parts: vec![],
    }
}

const GIB: u64 = 1024 * 1024 * 1024;

#[test]
fn picks_single_internal_nvme() {
    let disks = parse_lsblk(&fixture("lsblk-single-nvme.json")).unwrap();
    assert_eq!(disks.len(), 2);
    match choose_target(&disks) {
        Target::One(d) => {
            assert_eq!(d.path, "/dev/nvme0n1");
            assert_eq!(d.model.as_deref(), Some("SAMSUNG MZVLB512HBJQ-000L7"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn never_picks_installer_stick() {
    let disks = parse_lsblk(&fixture("lsblk-only-stick.json")).unwrap();
    assert!(disks[0].is_installer);
    assert!(matches!(choose_target(&disks), Target::None));
    // A stick marked "not removable, not usb" is recognised by its seed partition label alone.
    let d = parse_lsblk(&fixture("lsblk-single-nvme.json")).unwrap();
    let stick = d.iter().find(|x| x.path == "/dev/sda").unwrap();
    assert!(stick.is_installer);
}

#[test]
fn excludes_small_and_removable() {
    let disks = vec![
        disk("/dev/sdb", 16 * GIB, false, Some("sata")),
        disk("/dev/sdc", 500 * GIB, true, Some("sata")),
        disk("/dev/sdd", 500 * GIB, false, Some("usb")),
    ];
    assert!(matches!(choose_target(&disks), Target::None));
    let mut ok = disk("/dev/sde", 48 * GIB, false, Some("sata"));
    let mut v = disks.clone();
    v.push(ok.clone());
    assert!(matches!(choose_target(&v), Target::One(_)));
    ok.size = 48 * GIB - 1;
    assert!(matches!(choose_target(&[ok]), Target::None));
}

#[test]
fn lsblk_ignores_non_disks() {
    let disks = parse_lsblk(&fixture("lsblk-noise.json")).unwrap();
    let paths: Vec<_> = disks.iter().map(|d| d.path.as_str()).collect();
    assert_eq!(paths, vec!["/dev/sda"]);
    assert!(
        !disks[0].removable,
        "rm given as the string \"0\" counts too"
    );
}

#[test]
fn two_internal_disks_need_choice() {
    let disks = parse_lsblk(&fixture("lsblk-two-internal.json")).unwrap();
    match choose_target(&disks) {
        Target::Choose(v) => {
            let p: Vec<_> = v.iter().map(|d| d.path.as_str()).collect();
            assert_eq!(
                p,
                vec!["/dev/nvme0n1", "/dev/sda"],
                "NVMe first, even when smaller"
            );
        }
        other => panic!("{other:?}"),
    }
}

fn seed_toml() -> String {
    Seed {
        server_url: "https://mastersos.school.ac.th".into(),
        trust: vec![TrustKey {
            id: "k1".into(),
            alg: KeyAlg::Ed25519,
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            rp_id: None,
        }],
        fetch_token: Some("tok-SECRET".into()),
        group: Some("teacher".into()),
        oidc: None,
        min_version: None,
        school_id: None,
        wifi: vec![],
        school_name: None,
        it_account: None,
    }
    .to_toml()
}

/// The old single-seed view of a folder (tests that predate several seeds): none, or exactly one file.
fn read_seed(dir: &Path) -> SeedFound {
    let mut v = read_seeds(dir).unwrap();
    match v.len() {
        0 => SeedFound::None,
        1 => v.remove(0).found,
        n => panic!("{n} seeds"),
    }
}

/// What a fake `locate_seeds` returns for one seed (or none) on the stick.
fn as_files(f: SeedFound) -> Result<Vec<SeedFile>, String> {
    match f {
        SeedFound::None => Ok(vec![]),
        found => Ok(vec![SeedFile {
            name: "seed.toml".into(),
            found,
        }]),
    }
}

fn invalid_reason(f: SeedFound) -> String {
    match f {
        SeedFound::Invalid(r) => r,
        other => panic!("{other:?}"),
    }
}

#[test]
fn seed_missing_is_none() {
    let d = tempfile::tempdir().unwrap();
    assert!(matches!(read_seed(d.path()), SeedFound::None));
    assert!(matches!(
        read_seed(&d.path().join("nonexistent")),
        SeedFound::None
    ));
    fs::write(d.path().join("README.txt"), "x").unwrap();
    assert!(matches!(read_seed(d.path()), SeedFound::None));
    fs::write(d.path().join("seed.toml"), seed_toml()).unwrap();
    match read_seed(d.path()) {
        SeedFound::Valid { text, seed } => {
            assert_eq!(text, seed_toml());
            assert_eq!(seed.group.as_deref(), Some("teacher"));
        }
        other => panic!("{other:?}"),
    }
}

/// Plan 6 Task 24b review M2: a cloud seed (with school_id) without its fetch_token is refused
/// with the bundle crate's reason, not the generic "missing or unknown fields".
#[test]
fn cloud_seed_without_fetch_token_names_the_reason() {
    let d = tempfile::tempdir().unwrap();
    let mut seed = Seed::parse(&seed_toml()).unwrap();
    seed.fetch_token = None;
    seed.school_id = Some("0192f3a4-5b6c-7d8e-9f00-112233445566".into());
    fs::write(d.path().join("seed.toml"), seed.to_toml()).unwrap();
    let r = invalid_reason(read_seed(d.path()));
    assert!(r.contains("fetch_token") && r.contains("school_id"), "{r}");
    assert!(!r.contains("missing or unknown fields"), "{r}");
}

#[test]
fn seed_invalid_is_refused() {
    let facts = Facts {
        secure_boot: true,
        mok_enrolled: false,
        image_version: "20261012.1".into(),
        lab: false,
        ventoy: false,
    };
    let target = disk("/dev/nvme0n1", 512 * GIB, false, Some("nvme"));
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "bad toml",
            b"server_url = \"x\"\ntrust = [ tok-SECRET".to_vec(),
        ),
        (
            "empty trust",
            b"server_url = \"https://x\"\ntrust = []\nfetch_token = \"tok-SECRET\"\n".to_vec(),
        ),
        ("huge", vec![b'#'; MAX_SEED_BYTES as usize + 1]),
        ("not utf8", vec![0xff, 0xfe, 0x00, b'x']),
    ];
    for (name, bytes) in cases {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("seed.toml"), &bytes).unwrap();
        let found = read_seed(d.path());
        let reason = invalid_reason(read_seed(d.path()));
        assert!(!reason.is_empty(), "{name}");
        // The text console has no CJK glyphs (Task 11 showed boxes on a VM): the reason must be English only
        assert!(
            !reason
                .chars()
                .any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c))
                && reason.chars().any(|c| c.is_ascii_alphabetic()),
            "{name}: the reason must be English only: {reason}"
        );
        assert!(
            !reason.contains("tok-SECRET"),
            "{name}: the reason must not carry seed content: {reason}"
        );
        let err = plan(&target, &found, &facts).unwrap_err();
        assert!(!format!("{err:#}").contains("tok-SECRET"), "{name}");
    }
}

fn facts(secure_boot: bool, mok_enrolled: bool, lab: bool) -> Facts {
    Facts {
        secure_boot,
        mok_enrolled,
        image_version: "20261012.1".into(),
        lab,
        ventoy: false,
    }
}

fn target() -> Disk {
    disk("/dev/nvme0n1", 512 * GIB, false, Some("nvme"))
}

fn lines(cmds: &[Cmd]) -> Vec<String> {
    cmds.iter().map(Cmd::line).collect()
}

#[test]
fn plan_without_seed_has_no_seed_file() {
    let l = lines(&plan(&target(), &SeedFound::None, &facts(true, false, false)).unwrap());
    assert!(l.iter().all(|x| !x.contains("seed.toml")), "{l:?}");
    assert_eq!(
        l[0],
        "systemd-repart --dry-run=no --empty=force --definitions=/usr/lib/mastersos/install.repart.d /dev/nvme0n1"
    );
    assert!(l.iter().any(|x| x.starts_with(
        "efibootmgr --create --disk /dev/nvme0n1 --part 1 --label MastersOS --loader"
    )));
    assert_eq!(l.last().unwrap(), "sync");
    let pos = |p: &str| l.iter().position(|x| x.starts_with(p)).unwrap();
    assert!(pos("systemd-repart") < pos("udevadm settle") && pos("udevadm settle") < pos("mount "));
    // Folder 0700, file 0600; without a seed the folder is empty.
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().join("seed");
    write_seed_dir(&dir, &SeedFound::None).unwrap();
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
    assert_eq!(
        fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[test]
fn seed_dir_is_private() {
    let d = tempfile::tempdir().unwrap();
    let t = d.path().join("run/seed");
    let f = SeedFound::Valid {
        text: seed_toml(),
        seed: Box::new(Seed::parse(&seed_toml()).unwrap()),
    };
    write_seed_dir(&t, &f).unwrap();
    assert_eq!(
        fs::metadata(&t).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let p = t.join("seed.toml");
    assert_eq!(
        fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::read_to_string(&p).unwrap(), seed_toml());
    assert!(write_seed_dir(&d.path().join("x"), &SeedFound::Invalid("x".into())).is_err());
}

#[test]
fn plan_imports_mok_only_when_sb_off() {
    for (sb, enrolled, want) in [
        (true, false, false),
        (true, true, false),
        (false, true, false),
        (false, false, true),
    ] {
        let l = lines(&plan(&target(), &SeedFound::None, &facts(sb, enrolled, false)).unwrap());
        let has = l.iter().any(|x| x.contains("mokutil --import"));
        assert_eq!(has, want, "sb={sb} enrolled={enrolled}: {l:?}");
        assert_eq!(imports_mok(&facts(sb, enrolled, false)), want);
        if want {
            assert!(l.iter().all(|x| !x.starts_with("sh ")), "{l:?}");
            assert!(l.iter().any(|x| x.starts_with(
                "mokutil --import /usr/share/mastersos/mastersos-mok.der --hash-file "
            )));
        }
    }
}

#[test]
fn plan_never_copies_installer_uki() {
    let l = lines(&plan(&target(), &SeedFound::None, &facts(true, false, true)).unwrap());
    for x in &l {
        let rest = x.replace("/usr/lib/mastersos/installer/loader.conf", "");
        assert!(!rest.to_lowercase().contains("installer"), "{x}");
    }
    assert!(l
        .iter()
        .any(|x| x.contains("/usr/lib/mastersos/installer/loader.conf")));
}

#[test]
fn plan_installs_first_uki_without_counter() {
    let l = lines(&plan(&target(), &SeedFound::None, &facts(true, false, false)).unwrap());
    let cp: Vec<_> = l.iter().filter(|x| x.contains("MastersOS_")).collect();
    assert_eq!(cp.len(), 1, "{l:?}");
    assert!(
        cp[0].ends_with("/EFI/Linux/MastersOS_20261012.1_x86-64.efi"),
        "{}",
        cp[0]
    );
    assert!(!cp[0].contains('+'));
    // The source is EFI/mastersos/ on the stick's ESP (not EFI/Linux/, otherwise the stick's boot menu would grow the main system and "factory reset",
    // and choosing them would create partitions on the stick, Task 11 review I-1); the target is EFI/Linux/ on the internal disk
    assert!(
        cp[0].starts_with(
            "install -D -m 0644 /run/mastersos-usb-esp/EFI/mastersos/MastersOS_20261012.1_x86-64.efi "
        ),
        "{}",
        cp[0]
    );
    assert!(
        !cp[0].contains("/run/mastersos-usb-esp/EFI/Linux/"),
        "{}",
        cp[0]
    );
    assert_eq!(USB_UKI_DIR, "EFI/mastersos");
}

#[test]
fn formal_esp_has_no_auto_keys() {
    assert!(!esp_files(false)
        .iter()
        .any(|f| f.starts_with("loader/keys/auto")));
    assert!(esp_files(true)
        .iter()
        .any(|f| f.starts_with("loader/keys/auto")));
    for f in [
        "EFI/BOOT/BOOTX64.EFI",
        "EFI/BOOT/grubx64.efi",
        "EFI/BOOT/mmx64.efi",
        "EFI/systemd/systemd-bootx64.efi",
    ] {
        assert!(esp_files(false).contains(&f), "{f}");
    }
    let formal = lines(&plan(&target(), &SeedFound::None, &facts(true, false, false)).unwrap());
    assert!(formal.iter().all(|x| !x.contains("keys/auto")));
    let lab = lines(&plan(&target(), &SeedFound::None, &facts(true, false, true)).unwrap());
    assert!(lab.iter().any(|x| x.contains("keys/auto")));
}

/// The installed machine's ESP root carries the MOK certificate too: when the 10 seconds of "first boot after enabling Secure Boot" were missed, or NVRAM was cleared,
/// pick it on the internal disk under MokManager's "Enroll key from disk" after shim reports Security Violation, without looking for the stick again (Task 11).
#[test]
fn installed_esp_carries_mok_cert() {
    for lab in [false, true] {
        assert!(esp_files(lab).contains(&"mastersos-mok.der"));
    }
    let l = lines(&plan(&target(), &SeedFound::None, &facts(true, false, false)).unwrap());
    assert!(
        l.iter().any(|x| x
            == "install -D -m 0644 /usr/share/mastersos/mastersos-mok.der /run/mastersos-install/esp/mastersos-mok.der"),
        "{l:?}"
    );
    // Never from the stick's ESP: nothing hashes it, while /usr is under dm-verity
    assert!(
        !l.iter()
            .any(|x| x.contains("/run/mastersos-usb-esp/mastersos-mok.der")),
        "{l:?}"
    );
    // missing_sources looks for the /usr copy too
    let f = facts(true, false, false);
    assert_eq!(
        missing_sources(&f, &|p| p != MOK_CERT),
        vec![MOK_CERT.to_string()]
    );
}

#[test]
fn plan_sets_fat_labels_after_settle_before_mount() {
    for (disk_path, esp, golden) in [
        ("/dev/sda", "/dev/sda1", "/dev/sda11"),
        ("/dev/nvme0n1", "/dev/nvme0n1p1", "/dev/nvme0n1p11"),
    ] {
        let t = Disk {
            path: disk_path.into(),
            ..target()
        };
        let l = lines(&plan(&t, &SeedFound::None, &facts(true, false, false)).unwrap());
        let at = |want: String| {
            l.iter()
                .position(|c| *c == want)
                .unwrap_or_else(|| panic!("missing {want:?} in {l:?}"))
        };
        let settle = at("udevadm settle".into());
        let esp_l = at(format!("fatlabel {esp} MASTERSOS"));
        let gold_l = at(format!("fatlabel {golden} MOS-GOLDEN"));
        let mount = l.iter().position(|c| c.starts_with("mount ")).unwrap();
        assert!(
            settle < esp_l && settle < gold_l,
            "labels follow udevadm settle"
        );
        assert!(
            esp_l < mount && gold_l < mount,
            "labels are set before the ESP is mounted"
        );
    }
    assert_eq!(GOLDEN_ESP_PARTNO, 11);
}

#[test]
fn plan_zeroes_golden_sig() {
    for (disk_path, part) in [
        ("/dev/sda", "/dev/sda8"),
        ("/dev/nvme0n1", "/dev/nvme0n1p8"),
    ] {
        let t = Disk {
            path: disk_path.into(),
            ..target()
        };
        let l = lines(&plan(&t, &SeedFound::None, &facts(true, false, false)).unwrap());
        let want = Cmd::new(
            "dd",
            &[
                "if=/dev/zero",
                &format!("of={part}"),
                "bs=16K",
                "count=1",
                "conv=fsync",
            ],
        )
        .line();
        let at = l
            .iter()
            .position(|c| *c == want)
            .unwrap_or_else(|| panic!("no golden-sig zeroing for {disk_path}: {l:?}"));
        let settle = l.iter().position(|c| c == "udevadm settle").unwrap();
        assert!(settle < at, "zeroing must follow udevadm settle");
    }
    assert_eq!(GOLDEN_SIG_PARTNO, 8);
}

#[test]
fn partition_paths_follow_disk_naming() {
    assert_eq!(partition("/dev/nvme0n1", 12), "/dev/nvme0n1p12");
    assert_eq!(partition("/dev/sda", 8), "/dev/sda8");
    assert_eq!(esp_partition("/dev/nvme0n1"), "/dev/nvme0n1p1");
    assert_eq!(esp_partition("/dev/mmcblk0"), "/dev/mmcblk0p1");
    assert_eq!(esp_partition("/dev/sda"), "/dev/sda1");
}

const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
daemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n\
nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n\
guest:x:1999:1999::/home/guest:/bin/bash\n";

#[test]
fn firstrun_only_when_unmanaged_and_no_humans() {
    assert!(needs_firstrun(PASSWD, false));
    assert!(!needs_firstrun(PASSWD, true));
    let with_user = format!("{PASSWD}alice:x:1000:1000::/home/alice:/bin/bash\n");
    assert!(!needs_firstrun(&with_user, false));
    let sso = format!("{PASSWD}bob:x:59999:59999::/home/bob:/bin/bash\n");
    assert!(!needs_firstrun(&sso, false));
    let edge = format!("{PASSWD}x:x:60000:60000::/:/bin/false\ny:x:999:999::/:/bin/false\n");
    assert!(needs_firstrun(&edge, false));
    assert!(needs_firstrun("garbage\n\n::\n", false));
}

#[test]
fn firstrun_rejects_bad_usernames() {
    for bad in [
        "Root",
        "guest",
        "root",
        "a b",
        "",
        "-x",
        "1abc",
        &"a".repeat(33),
        "a:b",
        "a\nb",
    ] {
        assert!(!valid_username(bad), "{bad:?}");
    }
    for ok in ["alice", "_x", "a-b_c9", &"a".repeat(32)] {
        assert!(valid_username(ok), "{ok:?}");
    }
}

#[test]
fn firstrun_password_only_on_stdin() {
    let cmds = create_user("alice", "hunter2-PW");
    assert_eq!(
        cmds[0].line(),
        "useradd --create-home --user-group --groups sudo,lpadmin --shell /bin/bash alice"
    );
    for c in &cmds {
        assert!(!c.line().contains("hunter2-PW"), "{c:?}");
        assert!(!format!("{c:?}").contains("hunter2-PW"));
    }
    let ch = cmds.iter().find(|c| c.program == "chpasswd").unwrap();
    // Computes yescrypt itself, no PAM: the first entry of the image's common-password is authd's pam_authd_exec (default=die),
    // so a non-interactive chpasswd through PAM always fails (Task 11 saw "Authentication token manipulation error" on VM 168)
    assert_eq!(
        ch.args,
        vec!["--crypt-method".to_string(), "YESCRYPT".to_string()]
    );
    assert_eq!(ch.stdin.as_deref(), Some(&b"alice:hunter2-PW\n"[..]));
}

#[test]
fn password_pair_checks() {
    assert!(check_passwords("abc", "abc").is_ok());
    assert!(check_passwords("abc", "abd").is_err());
    assert!(check_passwords("", "").is_err());
    assert!(check_passwords("a\nb", "a\nb").is_err());
}

#[test]
fn screens_show_what_the_brief_requires() {
    let seed = SeedFound::Valid {
        text: seed_toml(),
        seed: Box::new(Seed::parse(&seed_toml()).unwrap()),
    };
    let t = confirm_text(&target(), &seed);
    assert!(
        t.contains("M")
            && t.contains("512")
            && t.contains("https://mastersos.school.ac.th")
            && t.contains("teacher")
    );
    assert!(!t.contains("tok-SECRET"));
    assert!(confirm_text(&target(), &SeedFound::None).contains("unmanaged"));
    assert!(finish_text(MokStep::Import).contains("mastersos"));
    assert!(!finish_text(MokStep::None).contains("MOK"));
}

#[test]
fn facts_parsing() {
    assert!(secure_boot_from_efivar(&[6, 0, 0, 0, 1]));
    assert!(!secure_boot_from_efivar(&[6, 0, 0, 0, 0]));
    assert!(!secure_boot_from_efivar(&[]));
    assert_eq!(
        image_version_from_os_release("NAME=\"MastersOS\"\nIMAGE_VERSION=20261012.1\n").as_deref(),
        Some("20261012.1")
    );
    assert_eq!(
        image_version_from_os_release("IMAGE_VERSION=\"20261012.2\"\n").as_deref(),
        Some("20261012.2")
    );
    assert_eq!(image_version_from_os_release("NAME=x\n"), None);
}

#[test]
fn installer_disk_must_be_exactly_one() {
    let disks = parse_lsblk(&fixture("lsblk-single-nvme.json")).unwrap();
    let inst = installer_disk(&disks).unwrap();
    assert_eq!(inst.path, "/dev/sda");
    assert_eq!(inst.seed_part.as_deref(), Some("/dev/sda2"));
    assert!(disks
        .iter()
        .find(|d| d.path == "/dev/nvme0n1")
        .unwrap()
        .seed_part
        .is_none());
    assert!(installer_disk(&[disks[0].clone()]).is_err());
    assert!(installer_disk(&[disks[1].clone(), disks[1].clone()]).is_err());
}

#[test]
fn seed_mount_check_fails_closed() {
    assert!(check_seed_mount(None, None, None).is_ok());
    assert!(check_seed_mount(Some("/dev/sda2"), None, Some(8)).is_err());
    assert!(check_seed_mount(Some("/dev/sda2"), Some(8), None).is_err());
    assert!(check_seed_mount(Some("/dev/sda2"), Some(64), Some(8)).is_err());
    assert!(check_seed_mount(Some("/dev/sda2"), Some(8), Some(8)).is_ok());
}

#[test]
fn locate_seeds_refuses_missing_or_unmounted_dir() {
    let d = tempfile::tempdir().unwrap();
    let r = locate_seeds(&d.path().join("gone"), Some("/dev/null")).unwrap_err();
    assert!(r.contains("not mounted"), "{r}");
    let r = locate_seeds(d.path(), Some("/dev/null")).unwrap_err();
    assert!(r.contains("not mounted"), "{r}");
    assert!(locate_seeds(&d.path().join("gone"), None)
        .unwrap()
        .is_empty());
}

#[test]
fn constants_match_task11_interface() {
    assert_eq!(USB_SEED_DIR, "/run/mastersos-usb-seed");
    assert_eq!(USB_ESP, "/run/mastersos-usb-esp");
    let l = lines(&plan(&target(), &SeedFound::None, &facts(true, false, false)).unwrap());
    assert!(l
        .iter()
        .any(|x| x.contains("/run/mastersos-usb-esp/EFI/BOOT/BOOTX64.EFI")));
}

#[test]
fn firstrun_needs_mounted_seed_partition() {
    assert!(is_mountpoint(1, 2));
    assert!(!is_mountpoint(7, 7));
}

#[test]
fn missing_sources_are_found_before_wipe() {
    let f = facts(false, false, true);
    let none_exist = missing_sources(&f, &|_| false);
    assert!(none_exist
        .iter()
        .any(|p| p == "/run/mastersos-usb-esp/EFI/mastersos/MastersOS_20261012.1_x86-64.efi"));
    assert!(none_exist.iter().any(|p| p == LOADER_CONF));
    assert!(none_exist.iter().any(|p| p == MOK_CERT));
    assert!(none_exist.iter().any(|p| p.ends_with("loader/keys/auto")));
    assert!(missing_sources(&f, &|_| true).is_empty());
    let none = missing_sources(&facts(true, false, false), &|_| false);
    assert!(!none.iter().any(|p| p.contains("keys/auto")));
    // The /usr certificate is needed in every case: the installed ESP's copy comes from it
    assert!(none.iter().any(|p| p == MOK_CERT));
}

#[test]
fn mok_hash_goes_through_runner_not_shell() {
    assert_eq!(mok_hash_cmd().line(), "mokutil --generate-hash=mastersos");
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("mok.hash");
    write_mok_hash(&p, "$6$abc$def\n").unwrap();
    assert_eq!(fs::read_to_string(&p).unwrap(), "$6$abc$def\n");
    assert!(write_mok_hash(&p, " \n").is_err());
    // N1/N2: creates the parent folder when missing (0700), the file is 0600, also when rewritten.
    let q = d.path().join("run/mastersos-install/mok.hash");
    write_mok_hash(&q, "h1").unwrap();
    write_mok_hash(&q, "h2").unwrap();
    assert_eq!(fs::read_to_string(&q).unwrap(), "h2\n");
    assert_eq!(
        fs::metadata(&q).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(q.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

#[test]
fn failed_rollback_is_fatal_not_retried() {
    use mastersos_agent::runner::{FakeRunner, Output};
    let r = FakeRunner::new();
    r.respond("chpasswd", Output::fail(1, ""));
    r.respond("userdel", Output::fail(8, "user is logged in"));
    let e = create_user_with(&r, "alice", "pw").unwrap_err();
    assert!(e.is::<CleanupFailed>());
    assert!(format!("{e:#}").contains("IT"));
    // When the cleanup works it is an ordinary error and the questions start over.
    let r = FakeRunner::new();
    r.respond("chpasswd", Output::fail(1, ""));
    assert!(!create_user_with(&r, "alice", "pw")
        .unwrap_err()
        .is::<CleanupFailed>());
}

#[test]
fn chpasswd_failure_rolls_back_user() {
    use mastersos_agent::runner::{FakeRunner, Output};
    let r = FakeRunner::new();
    r.respond("chpasswd", Output::fail(1, "echo hunter2-PW"));
    let e = create_user_with(&r, "alice", "hunter2-PW").unwrap_err();
    assert!(!format!("{e:#}").contains("hunter2-PW"), "{e:#}");
    assert!(
        r.calls().iter().any(|c| c == "userdel -r alice"),
        "{:?}",
        r.calls()
    );
    let r = FakeRunner::new();
    r.respond("useradd", Output::fail(9, "name in use"));
    assert!(create_user_with(&r, "sudo", "pw").is_err());
    assert_eq!(r.calls().len(), 1);
    let r = FakeRunner::new();
    create_user_with(&r, "alice", "pw").unwrap();
    assert_eq!(r.stdin_of("chpasswd"), Some(b"alice:pw\n".to_vec()));
}

// ---------- A TPM 2.0 is required (4b Task 3, Ruling 17) ----------

use mastersos_agent::runner::{FakeRunner, Output};
use mastersos_agent::tpm::{TpmVerdict, Unusable};
use mastersos_installer::precheck::Profile;
use mastersos_installer::tty::Tty;
use mastersos_installer::{failure_text, run_install_with, InstallEnv, Restart};

#[test]
fn refusal_text_is_english_only() {
    let turn_on = "Turn on TPM 2.0 under Security -> TPM 2.0 Security";
    let clear = "Clear the TPM in BIOS and try again";
    let sha256 = "Switch the TPM PCR bank to SHA-256 in BIOS";
    let cases = [
        (TpmVerdict::Unusable(Unusable::NoTpm), turn_on),
        (TpmVerdict::Unusable(Unusable::NoSha256Bank), sha256),
        (TpmVerdict::Unusable(Unusable::Lockout), clear),
        (TpmVerdict::Unusable(Unusable::OwnerAuth), clear),
        (
            TpmVerdict::Undecided("the firmware or the kernel reports a TPM, but /dev/tpmrm0 did not appear within 30 seconds".into()),
            "please contact us",
        ),
    ];
    for (v, advice) in cases {
        let t = tpm_refusal_text(&v).unwrap_or_else(|| panic!("{v:?} must be refused"));
        let reason = match &v {
            TpmVerdict::Unusable(u) => u.text().to_string(),
            TpmVerdict::Undecided(r) => r.clone(),
            TpmVerdict::Usable => unreachable!(),
        };
        assert!(t.contains(&reason), "the reason on its own line: {t}");
        assert!(t.contains(advice), "the fix: {t}");
        if matches!(v, TpmVerdict::Undecided(_)) {
            assert!(t.contains("please contact us"), "{t}");
        }
        // English only (the console font has no CJK glyphs)
        assert!(t.contains("TPM 2.0") && t.contains("cannot install"), "{t}");
        assert!(
            !t.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)),
            "{t}"
        );
        // The failure screen, not the reason, says whether the disk was touched
        assert!(!t.contains("disk has not been touched"), "{t}");
    }
    // Other refusal reasons do not get "clear the TPM": that wipes what the TPM holds, only right for lockout / owner password
    let t = tpm_refusal_text(&TpmVerdict::Unusable(Unusable::NoTpm)).unwrap();
    assert!(!t.contains(clear), "{t}");
}

#[test]
fn usable_tpm_has_no_refusal() {
    assert_eq!(tpm_refusal_text(&TpmVerdict::Usable), None);
}

/// The tty for tests: answers prompts in order, records every text shown. `typed_ahead` are lines typed before a prompt
/// (an Enter pressed during the copy): they answer first unless `flush_input` dropped them.
#[derive(Default)]
struct FakeTty {
    answers: Vec<String>,
    shown: Vec<String>,
    typed_ahead: Vec<String>,
    flushes: usize,
}

impl Tty for FakeTty {
    fn say(&mut self, text: &str) {
        self.shown.push(text.into());
    }
    fn prompt(&mut self, text: &str) -> anyhow::Result<String> {
        self.shown.push(text.into());
        self.read_line()
    }
    fn read_line(&mut self) -> anyhow::Result<String> {
        if !self.typed_ahead.is_empty() {
            return Ok(self.typed_ahead.remove(0));
        }
        if self.answers.is_empty() {
            anyhow::bail!("input closed");
        }
        Ok(self.answers.remove(0))
    }
    fn prompt_secret(&mut self, text: &str) -> anyhow::Result<String> {
        self.prompt(text)
    }
    fn flush_input(&mut self) {
        self.flushes += 1;
        self.typed_ahead.clear();
    }
}

/// The only commands allowed before a refusal (all read-only):
/// - `lsblk`: lists disks (choosing the disk, finding the installer stick);
/// - `udevadm settle`: only waits for udev to finish its events;
/// - `systemd-analyze has-tpm2`: only looks at firmware, driver and libraries;
/// - `systemd-creds encrypt`: only a trial seal of empty data in the TPM, output dropped, no disk touched.
///
/// An allow list rather than a deny list: the installer really writes disks through systemd-repart, mount/cp/install, efibootmgr, mokutil.
/// - `openssl smime -verify`, `sbverify --cert`: the pre-install check (4b Task 22) checks the shim's chain and hash against the active db's certificates,
///   reading only the image and the copies in the temporary folder, changing neither.
const READ_ONLY: &[&str] = &[
    "lsblk ",
    "udevadm settle",
    "systemd-analyze has-tpm2",
    "systemd-creds encrypt",
    "openssl smime -verify ",
    "sbverify --cert ",
];

/// Commands from the read-only list; openssl may only write /dev/null, sbverify only verifies --detached, never --output (review Minor 8: comparing prefixes only,
/// "openssl smime -verify ... -out /dev/sda" would slip through).
fn is_read_only(c: &str) -> bool {
    if !READ_ONLY.iter().any(|p| c.starts_with(p)) {
        return false;
    }
    if c.starts_with("openssl ") {
        let args: Vec<&str> = c.split(' ').collect();
        let outs: Vec<&str> = args
            .windows(2)
            .filter(|w| w[0] == "-out")
            .map(|w| w[1])
            .collect();
        return outs == ["/dev/null"];
    }
    if c.starts_with("sbverify ") {
        return c.contains(" --detached ") && !c.contains("--output");
    }
    true
}

#[test]
fn read_only_allowlist_checks_outputs() {
    assert!(is_read_only(
        "openssl smime -verify -nosigs -in /run/x.p7 -out /dev/null"
    ));
    assert!(!is_read_only(
        "openssl smime -verify -nosigs -in /run/x.p7 -out /dev/sda"
    ));
    assert!(!is_read_only(
        "openssl smime -verify -in /run/x.p7 -out /dev/null -out /dev/sda"
    ));
    assert!(!is_read_only("openssl smime -verify -in /run/x.p7"));
    assert!(is_read_only(
        "sbverify --cert /run/a.pem --detached /run/x.p7 /usr/lib/mastersos/esp/BOOTX64.EFI"
    ));
    assert!(!is_read_only(
        "sbverify --cert /run/a.pem /usr/lib/mastersos/esp/BOOTX64.EFI"
    ));
    assert!(!is_read_only(
        "sbverify --cert /run/a.pem --detached /run/x.p7 --output /dev/sda x"
    ));
}

fn no_tpm_machine() -> (tempfile::TempDir, FakeRunner) {
    no_tpm_machine_with("lsblk-single-nvme.json")
}

fn no_tpm_machine_with(lsblk: &str) -> (tempfile::TempDir, FakeRunner) {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("sys")).unwrap();
    fs::create_dir_all(tmp.path().join("dev")).unwrap();
    let r = FakeRunner::new();
    r.respond("lsblk", Output::ok(&fixture(lsblk)));
    r.respond(
        "systemd-analyze has-tpm2",
        Output::ok("no\n-firmware\n-driver\n+system\n+subsystem\n+libraries\n"),
    );
    (tmp, r)
}

#[test]
fn tpm_checked_before_any_disk_write() {
    // Refused with or without a seed (a personal computer needs a TPM too)
    let valid = || {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("seed.toml"), seed_toml()).unwrap();
        read_seed(d.path())
    };
    for seed_present in [false, true] {
        let (tmp, r) = no_tpm_machine();
        let mut tty = FakeTty {
            // Should the confirm screen be reached: answer y (so a missed check really carries on and the assertions below catch it)
            answers: vec!["y".into(), String::new()],
            ..Default::default()
        };
        let seen_part = std::cell::RefCell::new(None);
        let locate = |src: &SeedSource| {
            *seen_part.borrow_mut() = src.part.clone();
            if seed_present {
                as_files(valid())
            } else {
                Ok(vec![])
            }
        };
        let env = InstallEnv {
            sysfs: &tmp.path().join("sys"),
            dev: &tmp.path().join("dev"),
            proc_dir: &tmp.path().join("proc"),
            restart: Restart {
                sysrq: &tmp.path().join("sysrq"),
                sleep: &|_| {},
            },
            sleep: &|_| {},
            locate_seeds: &locate,
            profile: Profile::Release,
            shim: &tmp.path().join("BOOTX64.EFI"),
            tmp: tmp.path(),
            mode: Mode::Stick,
            ventoy_part_file: Path::new(VENTOY_PART_FILE),
            ventoy_mount: Path::new(VENTOY_MOUNT),
        };
        let e = run_install_with(&r, &mut tty, &env).unwrap_err();
        let msg = format!("{e:#}");
        assert!(msg.contains(Unusable::NoTpm.text()), "{msg}");
        assert!(msg.contains("Security -> TPM 2.0 Security"), "{msg}");
        // The seed check ran before the TPM (reading the seed partition lsblk found)
        assert_eq!(seen_part.borrow().as_deref(), Some("/dev/sda2"));
        let calls = r.calls();
        for c in &calls {
            assert!(
                is_read_only(c),
                "a command outside the read-only list ran before the refusal: {c} (all: {calls:?})"
            );
        }
        assert!(
            calls.iter().any(|c| c == "systemd-analyze has-tpm2"),
            "{calls:?}"
        );
        // The confirm screen was not reached
        assert!(
            !tty.shown.iter().any(|s| s.contains("ERASES")),
            "{:?}",
            tty.shown
        );
        assert_eq!(
            tty.answers.len(),
            2,
            "no input may be read before a refusal"
        );
    }
}

/// A usable TPM: the confirm screen only comes after the probe; any answer but y cancels, again without a single command that writes a disk.
#[test]
fn usable_tpm_reaches_confirm_screen() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("sys/class/tpm/tpm0/pcr-sha256")).unwrap();
    fs::create_dir_all(tmp.path().join("dev")).unwrap();
    fs::write(tmp.path().join("dev/tpmrm0"), "").unwrap();
    good_hw(tmp.path());
    let r = FakeRunner::new();
    r.respond("lsblk", Output::ok(&fixture("lsblk-single-nvme.json")));
    r.respond("openssl smime", Output::ok("Verification successful\n"));
    r.respond(
        "systemd-analyze has-tpm2",
        Output::ok("yes\n+firmware\n+driver\n+system\n+subsystem\n+libraries\n"),
    );
    let mut tty = FakeTty {
        answers: vec!["n".into()],
        ..Default::default()
    };
    let env = InstallEnv {
        sysfs: &tmp.path().join("sys"),
        dev: &tmp.path().join("dev"),
        proc_dir: &tmp.path().join("proc"),
        restart: Restart {
            sysrq: &tmp.path().join("sysrq"),
            sleep: &|_| {},
        },
        sleep: &|_| {},
        locate_seeds: &|_| Ok(vec![]),
        profile: Profile::Release,
        shim: &tmp.path().join("BOOTX64.EFI"),
        tmp: tmp.path(),
        mode: Mode::Stick,
        ventoy_part_file: Path::new(VENTOY_PART_FILE),
        ventoy_mount: Path::new(VENTOY_MOUNT),
    };
    let e = run_install_with(&r, &mut tty, &env).unwrap_err();
    assert!(format!("{e:#}").contains("Cancelled"), "{e:#}");
    let t = failure_text(&e);
    assert!(
        t.contains("Installation cancelled") && t.contains("The disk has not been touched."),
        "{t}"
    );
    assert!(
        tty.shown.iter().any(|s| s.contains("ERASES")),
        "{:?}",
        tty.shown
    );
    let calls = r.calls();
    assert!(
        calls.iter().any(|c| c.starts_with("systemd-creds encrypt")),
        "{calls:?}"
    );
    for c in &calls {
        assert!(is_read_only(c), "{c}");
    }
}

/// Several internal disks, no TPM: refused before choosing the disk, nobody picks a disk only to be refused (no input read).
#[test]
fn tpm_checked_before_disk_picker() {
    let disks = parse_lsblk(&fixture("lsblk-two-internal-stick.json")).unwrap();
    assert!(matches!(choose_target(&disks), Target::Choose(_)));
    let (tmp, r) = no_tpm_machine_with("lsblk-two-internal-stick.json");
    let mut tty = FakeTty {
        answers: vec!["1".into(), "y".into(), String::new()],
        ..Default::default()
    };
    let env = InstallEnv {
        sysfs: &tmp.path().join("sys"),
        dev: &tmp.path().join("dev"),
        proc_dir: &tmp.path().join("proc"),
        restart: Restart {
            sysrq: &tmp.path().join("sysrq"),
            sleep: &|_| {},
        },
        sleep: &|_| {},
        locate_seeds: &|_| Ok(vec![]),
        profile: Profile::Release,
        shim: &tmp.path().join("BOOTX64.EFI"),
        tmp: tmp.path(),
        mode: Mode::Stick,
        ventoy_part_file: Path::new(VENTOY_PART_FILE),
        ventoy_mount: Path::new(VENTOY_MOUNT),
    };
    let e = run_install_with(&r, &mut tty, &env).unwrap_err();
    assert!(format!("{e:#}").contains(Unusable::NoTpm.text()), "{e:#}");
    assert_eq!(
        tty.answers.len(),
        3,
        "no input may be read before a refusal: {:?}",
        tty.shown
    );
    assert!(
        !tty.shown.iter().any(|s| s.contains("Several disks")),
        "{:?}",
        tty.shown
    );
}

// ---------- Hardware checks before installing (4b Task 22): after the TPM, before choosing the disk ----------

use mastersos_agent::secureboot::{
    pe_with_signatures, x509_signature_list, DB_VAR, SECURE_BOOT_VAR,
};

const MS_2011: &[u8] =
    include_bytes!("../../../image/keys/microsoft/MicCorUEFCA2011_2011-06-27.der");
const MS_2023: &[u8] = include_bytes!("../../../image/keys/microsoft/microsoft-uefi-ca-2023.der");

/// The Secure Boot variable (on) and db (the given certificates) in `<root>/sys`; `<root>/BOOTX64.EFI` is the shim to be installed.
fn hw_db(root: &Path, certs: &[&[u8]]) {
    let ev = root.join("sys/firmware/efi/efivars");
    fs::create_dir_all(&ev).unwrap();
    fs::write(root.join("sys").join(SECURE_BOOT_VAR), [6, 0, 0, 0, 1]).unwrap();
    let mut db = vec![0x27, 0, 0, 0];
    for c in certs {
        db.extend_from_slice(&x509_signature_list(&[c]));
    }
    fs::write(root.join("sys").join(DB_VAR), db).unwrap();
    fs::write(
        root.join("BOOTX64.EFI"),
        pe_with_signatures(&[&[0x30, 0x03, 1, 2, 3]]),
    )
    .unwrap();
}

/// A machine the precheck reports nothing on: db has 2011 and 2023, one AX201 from the allow list (FakeRunner's openssl and sbverify exit 0 by default: chains).
fn good_hw(root: &Path) {
    hw_db(root, &[MS_2011, MS_2023]);
    wifi(root, (0x8086, 0xa0f0));
}

fn wifi(root: &Path, id: (u16, u16)) {
    let d = root.join("sys/bus/pci/devices/0000:00:14.3");
    fs::create_dir_all(&d).unwrap();
    fs::write(d.join("class"), "0x028000\n").unwrap();
    fs::write(d.join("vendor"), format!("0x{:04x}\n", id.0)).unwrap();
    fs::write(d.join("device"), format!("0x{:04x}\n", id.1)).unwrap();
    let drv = root.join("sys/bus/pci/drivers/iwlwifi");
    fs::create_dir_all(&drv).unwrap();
    std::os::unix::fs::symlink(&drv, d.join("driver")).unwrap();
}

/// A machine with a usable TPM (the precheck inputs are set up separately).
fn tpm_ok_machine(lsblk: &str) -> (tempfile::TempDir, FakeRunner) {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("sys/class/tpm/tpm0/pcr-sha256")).unwrap();
    fs::create_dir_all(tmp.path().join("dev")).unwrap();
    fs::write(tmp.path().join("dev/tpmrm0"), "").unwrap();
    let r = FakeRunner::new();
    r.respond("lsblk", Output::ok(&fixture(lsblk)));
    r.respond(
        "systemd-analyze has-tpm2",
        Output::ok("yes\n+firmware\n+driver\n+system\n+subsystem\n+libraries\n"),
    );
    // The precheck checks the shim's chain: openssl only counts as chaining with exit 0 and "Verification successful"
    r.respond("openssl smime", Output::ok("Verification successful\n"));
    (tmp, r)
}

fn install(r: &FakeRunner, tty: &mut FakeTty, root: &Path, profile: Profile) -> anyhow::Result<()> {
    let env = InstallEnv {
        sysfs: &root.join("sys"),
        dev: &root.join("dev"),
        proc_dir: &root.join("proc"),
        restart: Restart {
            sysrq: &root.join("sysrq"),
            sleep: &|_| {},
        },
        sleep: &|_| {},
        locate_seeds: &|_| Ok(vec![]),
        profile,
        shim: &root.join("BOOTX64.EFI"),
        tmp: root,
        mode: Mode::Stick,
        ventoy_part_file: Path::new(VENTOY_PART_FILE),
        ventoy_mount: Path::new(VENTOY_MOUNT),
    };
    run_install_with(r, tty, &env)
}

/// Warnings only (no Wi-Fi card): the warnings are listed, y continues; answering n cancels before choosing the disk and the confirm screen, only read-only commands ran.
#[test]
fn warnings_need_y() {
    let (tmp, r) = tpm_ok_machine("lsblk-single-nvme.json");
    hw_db(tmp.path(), &[MS_2011, MS_2023]); // no Wi-Fi card
    let mut tty = FakeTty {
        answers: vec!["n".into(), "y".into()],
        ..Default::default()
    };
    let e = install(&r, &mut tty, tmp.path(), Profile::Release).unwrap_err();
    assert!(format!("{e:#}").contains("Cancelled"), "{e:#}");
    assert_eq!(tty.answers.len(), 1, "asked only once: {:?}", tty.shown);
    let shown = tty.shown.join("\n");
    assert!(
        shown.contains("Checking hardware and Secure Boot certificates"),
        "{shown}"
    );
    assert!(shown.contains("Wi-Fi will not work"), "{shown}");
    assert!(shown.contains("type y to continue"), "{shown}");
    assert!(!shown.contains("ERASES"), "{shown}");
    let calls = r.calls();
    assert!(
        calls
            .iter()
            .any(|c| c.starts_with("openssl smime -verify ")),
        "{calls:?}"
    );
    for c in &calls {
        assert!(is_read_only(c), "{c}");
    }
    // Answer y: carries on to the confirm screen (where n cancels)
    let (tmp, r) = tpm_ok_machine("lsblk-single-nvme.json");
    hw_db(tmp.path(), &[MS_2011, MS_2023]);
    let mut tty = FakeTty {
        answers: vec!["y".into(), "n".into()],
        ..Default::default()
    };
    let e = install(&r, &mut tty, tmp.path(), Profile::Release).unwrap_err();
    assert!(format!("{e:#}").contains("Cancelled"), "{e:#}");
    assert!(
        tty.shown.iter().any(|s| s.contains("ERASES")),
        "{:?}",
        tty.shown
    );
    // lab with only 2011 in db: one more warning, db_no_2023, also continues after y
    let (tmp, r) = tpm_ok_machine("lsblk-single-nvme.json");
    hw_db(tmp.path(), &[MS_2011]);
    let mut tty = FakeTty {
        answers: vec!["n".into()],
        ..Default::default()
    };
    let e = install(&r, &mut tty, tmp.path(), Profile::Lab).unwrap_err();
    assert!(format!("{e:#}").contains("Cancelled"), "{e:#}");
    let shown = tty.shown.join("\n");
    assert!(
        shown.contains("Microsoft UEFI CA 2023") && shown.contains("ms-cert=2023k"),
        "{shown}"
    );
}

/// Release, no 2023 in db: refused before choosing the disk (with several disks) and the confirm screen, no input read, only read-only commands ran.
#[test]
fn refusal_before_disk_selection() {
    let (tmp, r) = tpm_ok_machine("lsblk-two-internal-stick.json");
    hw_db(tmp.path(), &[MS_2011]);
    wifi(tmp.path(), (0x8086, 0x51f0)); // one more warning: listed with the refusal, but no y asked
    let mut tty = FakeTty {
        answers: vec!["y".into(), "1".into(), "y".into()],
        ..Default::default()
    };
    let e = install(&r, &mut tty, tmp.path(), Profile::Release).unwrap_err();
    let msg = format!("{e:#}");
    assert!(msg.contains("Microsoft UEFI CA 2023"), "{msg}");
    assert!(msg.contains("Reset All Keys"), "{msg}");
    assert!(
        failure_text(&e).contains("Installation failed")
            && failure_text(&e).contains("The disk has not been touched."),
        "{msg}"
    );
    assert_eq!(
        tty.answers.len(),
        3,
        "no input may be read before a refusal: {:?}",
        tty.shown
    );
    assert!(
        !tty.shown
            .iter()
            .any(|s| s.contains("Several disks") || s.contains("ERASES")),
        "{:?}",
        tty.shown
    );
    for c in r.calls() {
        assert!(is_read_only(&c), "{c}");
    }
    // The precheck comes after the TPM: with an unusable TPM it is never reached (no openssl, no sbverify)
    let (tmp, r) = no_tpm_machine();
    hw_db(tmp.path(), &[MS_2011]);
    let mut tty = FakeTty::default();
    let e = install(&r, &mut tty, tmp.path(), Profile::Release).unwrap_err();
    assert!(format!("{e:#}").contains(Unusable::NoTpm.text()), "{e:#}");
    assert!(
        !r.calls()
            .iter()
            .any(|c| c.starts_with("sbverify") || c.starts_with("openssl")),
        "{:?}",
        r.calls()
    );
}

// ---- Ventoy mode ----

fn vfacts(sb: bool, enrolled: bool) -> Facts {
    Facts {
        image_version: "20261028.4".into(),
        ventoy: true,
        ..facts(sb, enrolled, false)
    }
}

#[test]
fn mok_step_matrix() {
    assert_eq!(mok_step(&vfacts(false, false)), MokStep::Import);
    assert_eq!(mok_step(&vfacts(true, false)), MokStep::EnrollFromDisk);
    assert_eq!(mok_step(&vfacts(true, true)), MokStep::None);
    assert_eq!(mok_step(&vfacts(false, true)), MokStep::None);
}

#[test]
fn stick_mode_never_gets_enroll_from_disk() {
    // Whole-stick installs keep the pre-Ventoy behaviour: SB on and not enrolled -> no MOK command.
    assert_eq!(mok_step(&facts(true, false, false)), MokStep::None);
    let l = lines(&plan(&target(), &SeedFound::None, &facts(true, false, false)).unwrap());
    assert!(!l.iter().any(|x| x.contains("mokutil")), "{l:?}");
}

#[test]
fn mok_timeout_is_best_effort_and_nothing_else_is() {
    assert!(is_best_effort(&mok_timeout_cmd()));
    assert!(!is_best_effort(&mok_hash_cmd()));
    assert!(!is_best_effort(&Cmd::new("sync", &[])));
    let l = plan(&target(), &SeedFound::None, &vfacts(true, false)).unwrap();
    assert_eq!(l.iter().filter(|c| is_best_effort(c)).count(), 1);
    for c in plan(&target(), &SeedFound::None, &vfacts(false, false)).unwrap() {
        assert!(!is_best_effort(&c), "{}", c.line());
    }
}

#[test]
fn plan_sets_mok_timeout_only_for_enroll_from_disk() {
    let l = lines(&plan(&target(), &SeedFound::None, &vfacts(true, false)).unwrap());
    assert!(l.iter().any(|x| x == "mokutil --timeout -1"), "{l:?}");
    assert!(!l.iter().any(|x| x.contains("--import")), "{l:?}");
    let sync = l.iter().position(|x| x == "sync").unwrap();
    let to = l.iter().position(|x| x == "mokutil --timeout -1").unwrap();
    assert!(to < sync);
    let l = lines(&plan(&target(), &SeedFound::None, &vfacts(true, true)).unwrap());
    assert!(!l.iter().any(|x| x.contains("mokutil")), "{l:?}");
}

#[test]
fn finish_text_enroll_from_disk() {
    let t = finish_text(MokStep::EnrollFromDisk);
    assert!(t.contains("Enroll key from disk"));
    assert!(t.contains("Choose MASTERSOS"));
    // PVE (Task 8): the firmware still lists the golden ESP, and MokManager waits on its menu for "Reboot"
    assert!(t.contains("not MOS-GOLDEN"), "{t}");
    assert!(t.contains("\"Yes\" -> \"Reboot\""), "{t}");
    assert!(!t.contains("restarts by itself"), "{t}");
    assert!(t.contains("mastersos-mok.der"));
    assert!(t.contains("blue screen"));
    assert!(!t.contains("MOK password"));
}

#[test]
fn finish_text_none_has_no_blue_screen() {
    let t = finish_text(MokStep::None);
    assert!(!t.contains("blue screen"));
    assert!(t.contains("Press Enter to restart"), "{t}");
}

#[test]
fn ventoy_ignores_raw_efi_readme() {
    let d = tempfile::tempdir().unwrap();
    for f in [
        "seed.toml",
        "MastersOS-system_x.raw",
        "._MastersOS-system_x.raw",
        "README.txt",
        ".efi",
    ] {
        let body = if f == "seed.toml" {
            seed_toml()
        } else {
            "x".into()
        };
        fs::write(d.path().join(f), body).unwrap();
    }
    assert!(matches!(read_seed(d.path()), SeedFound::Valid { .. }));
}

/// Run `run_install_with` in Ventoy mode; the seed step comes first, so these refusals happen
/// before any non-read-only command.
fn ventoy_run(
    part_file: &Path,
    mount: &Path,
    locate: &dyn Fn(&SeedSource) -> Result<Vec<SeedFile>, String>,
) -> (anyhow::Result<()>, FakeRunner) {
    let (tmp, r) = no_tpm_machine_with("lsblk-ventoy.json");
    let mut tty = FakeTty::default();
    let env = InstallEnv {
        sysfs: &tmp.path().join("sys"),
        dev: &tmp.path().join("dev"),
        proc_dir: &tmp.path().join("proc"),
        restart: Restart {
            sysrq: &tmp.path().join("sysrq"),
            sleep: &|_| {},
        },
        sleep: &|_| {},
        locate_seeds: locate,
        profile: Profile::Release,
        shim: &tmp.path().join("BOOTX64.EFI"),
        tmp: tmp.path(),
        mode: Mode::Ventoy {
            version: "20261028.4".into(),
        },
        ventoy_part_file: part_file,
        ventoy_mount: mount,
    };
    let res = run_install_with(&r, &mut tty, &env);
    (res, r)
}

#[test]
fn ventoy_seed_dir_not_mounted_refused() {
    let d = tempfile::tempdir().unwrap();
    let pf = d.path().join("part");
    fs::write(&pf, "/dev/sdb1\n").unwrap();
    // The real locate_seed: the folder sits on the temp fs, not on a mount of /dev/null's rdev.
    fs::create_dir(d.path().join("MastersOS")).unwrap();
    let seen = std::cell::RefCell::new(None);
    let (res, r) = ventoy_run(&pf, d.path(), &|s| {
        *seen.borrow_mut() = Some(s.clone());
        locate_seeds(&s.dir, s.part.as_deref())
    });
    let msg = format!("{:#}", res.unwrap_err());
    assert!(msg.contains("The seed is invalid"), "{msg}");
    let s = seen.borrow().clone().unwrap();
    assert_eq!(s.dir, d.path().join("MastersOS"));
    assert_eq!(s.part.as_deref(), Some("/dev/sdb1"));
    assert!(r.calls().iter().all(|c| !c.contains("repart")));
}

#[test]
fn ventoy_missing_part_file_refused() {
    let d = tempfile::tempdir().unwrap();
    for content in [None, Some("  \n")] {
        let pf = d.path().join("part");
        let _ = fs::remove_file(&pf);
        if let Some(c) = content {
            fs::write(&pf, c).unwrap();
        }
        let (res, r) = ventoy_run(&pf, d.path(), &|_| panic!("must not read the seed"));
        let msg = failure_text(&res.unwrap_err());
        assert!(
            msg.contains("MastersOS folder on the Ventoy stick not found")
                && msg.contains("The disk has not been touched."),
            "{msg}"
        );
        assert!(r.calls().iter().all(|c| !c.contains("repart")));
    }
}

fn usable_tpm_machine(lsblk: &str) -> (tempfile::TempDir, FakeRunner) {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("sys/class/tpm/tpm0/pcr-sha256")).unwrap();
    fs::create_dir_all(tmp.path().join("dev")).unwrap();
    fs::write(tmp.path().join("dev/tpmrm0"), "").unwrap();
    good_hw(tmp.path());
    let r = FakeRunner::new();
    r.respond("lsblk", Output::ok(&fixture(lsblk)));
    r.respond("openssl smime", Output::ok("Verification successful\n"));
    r.respond(
        "systemd-analyze has-tpm2",
        Output::ok("yes\n+firmware\n+driver\n+system\n+subsystem\n+libraries\n"),
    );
    (tmp, r)
}

/// Run to the confirm screen (answer "n") in Ventoy mode; returns the error, the screens and the SeedSource seen.
fn ventoy_to_confirm(
    seed: impl Fn() -> SeedFound,
) -> (String, Vec<String>, Option<SeedSource>, FakeRunner) {
    let (tmp, r) = usable_tpm_machine("lsblk-ventoy.json");
    let pf = tmp.path().join("part");
    fs::write(&pf, "/dev/sdb1\n").unwrap();
    let mut tty = FakeTty {
        answers: vec!["n".into()],
        ..Default::default()
    };
    let seen = std::cell::RefCell::new(None);
    let locate = |s: &SeedSource| {
        *seen.borrow_mut() = Some(s.clone());
        as_files(seed())
    };
    let env = InstallEnv {
        sysfs: &tmp.path().join("sys"),
        dev: &tmp.path().join("dev"),
        proc_dir: &tmp.path().join("proc"),
        restart: Restart {
            sysrq: &tmp.path().join("sysrq"),
            sleep: &|_| {},
        },
        sleep: &|_| {},
        locate_seeds: &locate,
        profile: Profile::Release,
        shim: &tmp.path().join("BOOTX64.EFI"),
        tmp: tmp.path(),
        mode: Mode::Ventoy {
            version: "20261028.4".into(),
        },
        ventoy_part_file: &pf,
        ventoy_mount: Path::new("/run/mastersos-ventoy"),
    };
    let e = run_install_with(&r, &mut tty, &env).unwrap_err();
    let s = seen.borrow().clone();
    (format!("{e:#}"), tty.shown.clone(), s, r)
}

/// The Ventoy stick looks internal to lsblk (rm=0, no tran, 64 GiB) and has no seed partition label:
/// it must still never be a target, and installer_disk() must not be needed.
#[test]
fn ventoy_disk_is_never_a_target() {
    let (e, shown, seen, r) = ventoy_to_confirm(|| SeedFound::None);
    assert!(e.contains("Cancelled"), "{e}");
    let confirm = shown
        .iter()
        .find(|s| s.contains("ERASES"))
        .expect("confirm screen");
    assert!(
        confirm.contains("/dev/nvme0n1") && !confirm.contains("/dev/sdb"),
        "{confirm}"
    );
    // No disk picker was shown: the Ventoy disk was not a second choice.
    assert!(
        !shown.iter().any(|s| s.contains("Several disks")),
        "{shown:?}"
    );
    assert_eq!(seen.unwrap().part.as_deref(), Some("/dev/sdb1"));
    assert!(r.calls().iter().all(|c| is_read_only(c)));
}

#[test]
fn ventoy_valid_seed_reaches_confirm_screen() {
    let valid = || {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("seed.toml"), seed_toml()).unwrap();
        read_seed(d.path())
    };
    let (_e, shown, seen, _r) = ventoy_to_confirm(valid);
    let confirm = shown.iter().find(|s| s.contains("ERASES")).unwrap();
    assert!(
        confirm.contains("https://mastersos.school.ac.th"),
        "{confirm}"
    );
    assert!(!confirm.contains("tok-SECRET"));
    let s = seen.unwrap();
    assert_eq!(s.dir, Path::new("/run/mastersos-ventoy/MastersOS"));
}

#[test]
fn ventoy_part_not_in_lsblk_refused() {
    let d = tempfile::tempdir().unwrap();
    let pf = d.path().join("part");
    fs::write(&pf, "/dev/sdz9\n").unwrap();
    let (res, r) = ventoy_run(&pf, d.path(), &|_| panic!("must not read the seed"));
    let msg = failure_text(&res.unwrap_err());
    assert!(
        msg.contains("The Ventoy stick is not in the disk list")
            && msg.contains("The disk has not been touched."),
        "{msg}"
    );
    assert!(r.calls().iter().all(|c| !c.contains("repart")));
}

// ---------- Failure screen, restart order, releasing the old partition table, disk report ----------

use mastersos_installer::{
    disk_report, fail_and_restart, release_cmd, run_plan, settle_cmd, DiskWritten, RELEASE_TRIES,
    RESTART_PROMPT,
};

fn has_cjk(s: &str) -> bool {
    s.chars().any(|c| {
        ('\u{4e00}'..='\u{9fff}').contains(&c)
            || ('\u{3000}'..='\u{303f}').contains(&c)
            || ('\u{ff00}'..='\u{ffef}').contains(&c)
    })
}

#[test]
fn failure_text_says_whether_the_disk_was_touched() {
    let e = anyhow::anyhow!("No suitable internal disk (>= 48 GiB, not USB)");
    let t = failure_text(&e);
    assert!(t.contains("Installation failed"), "{t}");
    assert!(t.contains("Reason: No suitable internal disk"), "{t}");
    assert!(t.contains("The disk has not been touched."), "{t}");
    assert!(!has_cjk(&t), "{t}");

    // Failed while releasing / partitioning / copying: erased, not installed
    let e: anyhow::Error = DiskWritten {
        disk: "/dev/nvme0n1".into(),
        copied: false,
        error: anyhow::anyhow!("systemd-repart exited with 1: Failed to reread partition table"),
    }
    .into();
    let t = failure_text(&e);
    assert!(t.contains("Reason: systemd-repart exited with 1"), "{t}");
    assert!(!t.contains("has not been touched"), "{t}");
    assert!(
        t.contains("The disk /dev/nvme0n1 was erased and MastersOS is not installed on it.")
            && t.contains("Run the installer again."),
        "{t}"
    );
    // A context on top of DiskWritten still counts as written
    let e = e.context("installing");
    assert!(!failure_text(&e).contains("has not been touched"));

    // Failed after the copy (boot entry, sync): copied, setup unfinished
    let e: anyhow::Error = DiskWritten {
        disk: "/dev/nvme0n1".into(),
        copied: true,
        error: anyhow::anyhow!("efibootmgr exited with 5"),
    }
    .into();
    let t = failure_text(&e);
    assert!(
        t.contains("MastersOS was copied to /dev/nvme0n1, but the setup did not finish.")
            && t.contains("Run the installer again to be safe."),
        "{t}"
    );
    assert!(!t.contains("was erased") && !has_cjk(&t), "{t}");
}

/// A Restart that writes the sysrq letters to a temporary file and never sleeps.
fn test_restart(d: &tempfile::TempDir) -> (std::path::PathBuf, Restart<'static>) {
    let p = d.path().join("sysrq");
    let leaked: &'static Path = Box::leak(p.clone().into_boxed_path());
    (
        p,
        Restart {
            sysrq: leaked,
            sleep: &|_| {},
        },
    )
}

#[test]
fn fail_and_restart_reboots_only_after_enter() {
    let d = tempfile::tempdir().unwrap();
    let (sysrq, restart) = test_restart(&d);
    let r = FakeRunner::new();
    let mut tty = FakeTty {
        answers: vec!["".into()],
        ..Default::default()
    };
    fail_and_restart(&r, &mut tty, &anyhow::anyhow!("x"), restart);
    assert_eq!(tty.shown.last().map(String::as_str), Some(RESTART_PROMPT));
    assert_eq!(r.calls(), vec!["systemctl reboot"]);
    assert!(!sysrq.exists(), "systemctl worked: sysrq untouched");
    // Input closed: the screen stays, no reboot, no shell
    let r = FakeRunner::new();
    let mut tty = FakeTty::default();
    fail_and_restart(&r, &mut tty, &anyhow::anyhow!("x"), restart);
    assert!(r.calls().is_empty(), "{:?}", r.calls());
    // Never ask to remove the stick before restarting: /usr lives on it
    assert!(!RESTART_PROMPT.to_lowercase().contains("remove"));
}

/// An Enter pressed during the long copy sits in the line buffer: it must not answer the failure prompt unread.
#[test]
fn typed_ahead_enter_does_not_answer_the_restart_prompt() {
    let d = tempfile::tempdir().unwrap();
    let (_, restart) = test_restart(&d);
    let r = FakeRunner::new();
    let mut tty = FakeTty {
        typed_ahead: vec!["".into()],
        ..Default::default()
    };
    fail_and_restart(&r, &mut tty, &anyhow::anyhow!("x"), restart);
    assert_eq!(tty.flushes, 1);
    assert!(
        r.calls().is_empty(),
        "the queued Enter was dropped, nobody answered: {:?}",
        r.calls()
    );
}

/// `systemctl reboot` fails (the stick with /usr was pulled: "Input/output error"): sysrq s, u, b through /proc.
#[test]
fn reboot_falls_back_to_sysrq() {
    let d = tempfile::tempdir().unwrap();
    let sysrq = d.path().join("sysrq");
    // Each write replaces the file: the sleep between letters records the one just written
    let seen = std::cell::RefCell::new(Vec::new());
    let record =
        |_: std::time::Duration| seen.borrow_mut().push(fs::read_to_string(&sysrq).unwrap());
    let restart = Restart {
        sysrq: &sysrq,
        sleep: &record,
    };
    let r = FakeRunner::new();
    r.respond("systemctl reboot", Output::fail(1, "Input/output error"));
    let mut tty = FakeTty {
        answers: vec!["".into()],
        ..Default::default()
    };
    fail_and_restart(&r, &mut tty, &anyhow::anyhow!("x"), restart);
    // sync, remount read-only (a second apart), then reboot
    assert_eq!(*seen.borrow(), vec!["s", "u"]);
    assert_eq!(fs::read_to_string(&sysrq).unwrap(), "b");
    let shown = tty.shown.join("\n");
    assert!(shown.contains("restarting through the kernel"), "{shown}");
    assert!(!shown.contains("hold the power button"), "{shown}");
    // No /proc either: says to hold the power button
    let r = FakeRunner::new();
    r.respond("systemctl reboot", Output::fail(1, "Input/output error"));
    let mut tty = FakeTty {
        answers: vec!["".into()],
        ..Default::default()
    };
    let gone = Restart {
        sysrq: Path::new("/nonexistent-mastersos-test/sysrq-trigger"),
        sleep: &|_| {},
    };
    fail_and_restart(&r, &mut tty, &anyhow::anyhow!("x"), gone);
    assert!(
        tty.shown.last().unwrap().contains("hold the power button"),
        "{:?}",
        tty.shown
    );
}

#[test]
fn panic_screen_is_english_and_honest_about_the_disk() {
    let t = mastersos_installer::panic_text("index out of bounds");
    assert!(t.contains("internal error: index out of bounds"), "{t}");
    assert!(t.contains("Run the installer again"), "{t}");
    assert!(!t.contains("has not been touched") && !has_cjk(&t), "{t}");
}

#[test]
fn finish_text_restarts_before_the_stick_comes_out() {
    for step in [MokStep::None, MokStep::Import, MokStep::EnrollFromDisk] {
        let t = finish_text(step);
        assert!(!has_cjk(&t), "{t}");
        let lower = t.to_lowercase();
        assert!(!lower.contains("remove the usb stick, then"), "{t}");
        let enter = lower.find("press enter to restart").expect(&t);
        let remove = lower.find("remove the usb stick").expect(&t);
        assert!(enter < remove, "{t}");
        assert!(
            t.contains("If the Ventoy menu or the installer appears again"),
            "{t}"
        );
    }
    assert!(finish_text(MokStep::EnrollFromDisk)
        .contains("1. Press Enter to restart, then remove the USB stick"));
}

/// A fake sysfs/proc: nvme0n1 with partitions p1..p3; p3 is held by dm-0 (/dev/mapper/old-root), p1 is mounted, p2 is swap.
fn busy_machine() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    let b = d.path().join("sys/class/block");
    for p in ["nvme0n1p1", "nvme0n1p2", "nvme0n1p3"] {
        fs::create_dir_all(b.join("nvme0n1").join(p).join("holders")).unwrap();
        fs::write(b.join("nvme0n1").join(p).join("partition"), "1\n").unwrap();
        // /sys/class/block/<part> exists too (a symlink in a real sysfs)
        fs::create_dir_all(b.join(p).join("holders")).unwrap();
    }
    fs::create_dir_all(b.join("nvme0n1/holders")).unwrap();
    fs::create_dir_all(b.join("nvme0n1p3/holders/dm-0")).unwrap();
    fs::create_dir_all(b.join("dm-0/dm")).unwrap();
    fs::write(b.join("dm-0/dm/name"), "old-root\n").unwrap();
    fs::create_dir_all(d.path().join("proc")).unwrap();
    fs::write(
        d.path().join("proc/mounts"),
        "/dev/sda1 /run/mastersos-usb-esp vfat ro 0 0\n/dev/nvme0n1p1 /mnt/probe ext4 ro 0 0\n/dev/mapper/old-root /mnt/x ext4 ro 0 0\n",
    )
    .unwrap();
    fs::write(
        d.path().join("proc/swaps"),
        "Filename Type Size Used Priority\n/dev/nvme0n1p2 partition 8388604 0 -2\n",
    )
    .unwrap();
    d
}

/// Nothing holds the disk: one partition, unused.
fn idle_machine() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    fs::create_dir_all(d.path().join("sys/class/block/nvme0n1/nvme0n1p1")).unwrap();
    fs::write(
        d.path().join("sys/class/block/nvme0n1/nvme0n1p1/partition"),
        "1",
    )
    .unwrap();
    fs::create_dir_all(d.path().join("proc")).unwrap();
    fs::write(
        d.path().join("proc/mounts"),
        "/dev/sda1 /run/x vfat ro 0 0\n",
    )
    .unwrap();
    fs::write(
        d.path().join("proc/swaps"),
        "Filename Type Size Used Priority\n",
    )
    .unwrap();
    d
}

#[test]
fn disk_report_lists_holders_mounts_and_swaps() {
    let d = busy_machine();
    let r = FakeRunner::new();
    r.respond("lsblk -o", Output::ok("NAME SIZE\nnvme0n1 512G\n"));
    r.respond("dmsetup ls", Output::ok("old-root\t(252:0)\n"));
    let sys = d.path().join("sys");
    let proc_dir = d.path().join("proc");
    let short = disk_report(&r, &sys, &proc_dir, "/dev/nvme0n1", false).join("\n");
    assert!(
        r.calls().is_empty(),
        "the short report runs nothing: {:?}",
        r.calls()
    );
    assert!(
        short.contains("partitions nvme0n1p1, nvme0n1p2, nvme0n1p3"),
        "{short}"
    );
    assert!(
        short.contains("nvme0n1p3 -> dm-0 (/dev/mapper/old-root)"),
        "{short}"
    );
    assert!(short.contains("/dev/nvme0n1p1 /mnt/probe"), "{short}");
    assert!(short.contains("/dev/mapper/old-root /mnt/x"), "{short}");
    assert!(short.contains("/dev/nvme0n1p2 partition"), "{short}");
    assert!(
        !short.contains("/dev/sda1"),
        "only the target disk: {short}"
    );
    let full = disk_report(&r, &sys, &proc_dir, "/dev/nvme0n1", true).join("\n");
    assert!(full.contains("nvme0n1 512G"), "{full}");
    assert!(full.contains("old-root\t(252:0)"), "{full}");
    assert_eq!(
        r.calls(),
        vec![
            "lsblk -o NAME,SIZE,FSTYPE,PARTLABEL,MOUNTPOINTS /dev/nvme0n1",
            "dmsetup ls"
        ]
    );
    // No dmsetup, unreadable /proc: said on the screen, never an error
    let r = FakeRunner::new();
    r.respond("dmsetup", Output::fail(127, "not found"));
    let full = disk_report(&r, &sys, &d.path().join("nope"), "/dev/nvme0n1", true).join("\n");
    assert!(full.contains("dmsetup ls: not available"), "{full}");
    assert!(full.contains("mounted: cannot read"), "{full}");
}

fn cmds_for(t: &Disk) -> Vec<Cmd> {
    plan(t, &SeedFound::None, &facts(true, false, false)).unwrap()
}

/// The target as found on the ChromeOS Flex laptop: 12 old partitions.
fn old_layout() -> Disk {
    let mut t = target();
    t.parts = (1..=12).map(|n| format!("/dev/nvme0n1p{n}")).collect();
    t
}

#[test]
fn run_plan_releases_the_old_table_before_repart() {
    let d = idle_machine();
    let t = old_layout();
    let r = FakeRunner::new();
    let mut tty = FakeTty::default();
    run_plan(
        &r,
        &mut tty,
        cmds_for(&t),
        &t,
        &d.path().join("sys"),
        &d.path().join("proc"),
        &|_| {},
    )
    .unwrap();
    let calls = r.calls();
    let release = release_cmd("/dev/nvme0n1", &t.parts).line();
    let i = calls
        .iter()
        .position(|c| *c == release)
        .expect("release ran");
    let repart = calls
        .iter()
        .position(|c| c.starts_with("systemd-repart"))
        .unwrap();
    assert!(i < repart, "{calls:?}");
    let settle = settle_cmd().line();
    assert_eq!(settle, "udevadm settle --timeout=30");
    assert_eq!(calls[i - 1], settle, "{calls:?}");
    assert_eq!(calls[i + 1], settle, "{calls:?}");
    // A bounded lock; partitions already gone from /dev are skipped, not an error
    assert!(release.contains("--timeout=30"), "{release}");
    assert!(release.contains("[ -b \"$p\" ] || continue"), "{release}");
    // The lock covers wiping every old partition, the disk, and the re-read
    assert!(
        release.starts_with("udevadm lock --device=/dev/nvme0n1 "),
        "{release}"
    );
    assert!(release.contains("wipefs --all --force") && release.contains("blockdev --rereadpt"));
    let tail: Vec<String> = std::iter::once("/dev/nvme0n1".to_string())
        .chain(t.parts.iter().cloned())
        .collect();
    assert!(release.ends_with(&tail.join(" ")), "{release}");
    // Nothing touches the disk before the release
    assert!(calls[..i].iter().all(|c| *c == settle), "{calls:?}");
    let shown = tty.shown.join("\n");
    assert!(
        shown.contains("Disk /dev/nvme0n1: partitions nvme0n1p1; holders none"),
        "{shown}"
    );
    assert!(!has_cjk(&shown), "{shown}");
}

#[test]
fn run_plan_retries_the_release() {
    let d = idle_machine();
    let t = old_layout();
    let r = FakeRunner::new();
    r.respond(
        "udevadm lock",
        Output::fail(1, "BLKRRPART: Device or resource busy"),
    );
    r.respond(
        "udevadm lock",
        Output::fail(1, "BLKRRPART: Device or resource busy"),
    );
    let mut tty = FakeTty::default();
    let slept = std::cell::Cell::new(0);
    run_plan(
        &r,
        &mut tty,
        cmds_for(&t),
        &t,
        &d.path().join("sys"),
        &d.path().join("proc"),
        &|_| slept.set(slept.get() + 1),
    )
    .unwrap();
    let calls = r.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|c| c.starts_with("udevadm lock"))
            .count(),
        3
    );
    assert_eq!(slept.get(), 2);
    assert!(calls.iter().any(|c| c.starts_with("systemd-repart")));
}

#[test]
fn run_plan_names_the_busy_partition_when_the_release_fails() {
    let d = busy_machine();
    let mut t = target();
    t.parts = vec![
        "/dev/nvme0n1p1".into(),
        "/dev/nvme0n1p2".into(),
        "/dev/nvme0n1p3".into(),
    ];
    let r = FakeRunner::new();
    for _ in 0..RELEASE_TRIES {
        r.respond(
            "udevadm lock",
            Output::fail(1, "BLKRRPART: Device or resource busy"),
        );
    }
    let mut tty = FakeTty::default();
    let e = run_plan(
        &r,
        &mut tty,
        cmds_for(&t),
        &t,
        &d.path().join("sys"),
        &d.path().join("proc"),
        &|_| {},
    )
    .unwrap_err();
    let calls = r.calls();
    assert!(
        !calls.iter().any(|c| c.starts_with("systemd-repart")),
        "{calls:?}"
    );
    assert_eq!(
        calls
            .iter()
            .filter(|c| c.starts_with("udevadm lock"))
            .count(),
        RELEASE_TRIES as usize
    );
    assert!(e.downcast_ref::<DiskWritten>().is_some(), "{e:#}");
    let msg = format!("{e:#}");
    assert!(msg.contains("could not be released"), "{msg}");
    assert!(
        msg.contains("/dev/nvme0n1p1")
            && msg.contains("/dev/nvme0n1p2")
            && msg.contains("/dev/nvme0n1p3"),
        "{msg}"
    );
    let shown = tty.shown.join("\n");
    assert!(shown.contains("What holds the disk"), "{shown}");
    assert!(calls.iter().any(|c| c == "dmsetup ls"), "{calls:?}");
    assert!(!has_cjk(&shown) && !has_cjk(&msg));
}

#[test]
fn run_plan_reports_and_marks_written_when_repart_fails() {
    let d = idle_machine();
    let t = old_layout();
    let r = FakeRunner::new();
    r.respond(
        "systemd-repart",
        Output::fail(
            1,
            "Failed to reread partition table: Device or resource busy",
        ),
    );
    let mut tty = FakeTty::default();
    let e = run_plan(
        &r,
        &mut tty,
        cmds_for(&t),
        &t,
        &d.path().join("sys"),
        &d.path().join("proc"),
        &|_| {},
    )
    .unwrap_err();
    assert!(e.downcast_ref::<DiskWritten>().is_some(), "{e:#}");
    assert!(failure_text(&e).contains("was erased and MastersOS is not installed"));
    let calls = r.calls();
    let repart = calls
        .iter()
        .position(|c| c.starts_with("systemd-repart"))
        .unwrap();
    assert_eq!(
        calls[repart + 1],
        "lsblk -o NAME,SIZE,FSTYPE,PARTLABEL,MOUNTPOINTS /dev/nvme0n1"
    );
    assert_eq!(calls[repart + 2], "dmsetup ls");
    assert_eq!(
        calls.len(),
        repart + 3,
        "nothing runs after the failure: {calls:?}"
    );
    assert!(tty
        .shown
        .iter()
        .any(|s| s.contains("systemd-repart failed")));
}

/// The copy went through, the boot entry failed: the screen says MastersOS was copied, not that the disk was erased.
#[test]
fn run_plan_failure_after_the_copy_says_copied() {
    let d = idle_machine();
    let t = old_layout();
    let r = FakeRunner::new();
    r.respond(
        "efibootmgr",
        Output::fail(5, "Could not prepare Boot variable"),
    );
    let mut tty = FakeTty::default();
    let e = run_plan(
        &r,
        &mut tty,
        cmds_for(&t),
        &t,
        &d.path().join("sys"),
        &d.path().join("proc"),
        &|_| {},
    )
    .unwrap_err();
    let w = e.downcast_ref::<DiskWritten>().expect("written");
    assert!(w.copied, "{e:#}");
    let text = failure_text(&e);
    assert!(
        text.contains("MastersOS was copied to /dev/nvme0n1"),
        "{text}"
    );
    assert!(!text.contains("was erased"), "{text}");
}

// ---------- Several seeds on one stick (wifi-seeds Task 4) ----------

fn seed_with(school: Option<&str>, url: &str, wifi: &[&str]) -> String {
    let mut s = Seed::parse(&seed_toml()).unwrap();
    s.server_url = url.into();
    s.school_name = school.map(str::to_string);
    s.wifi = wifi
        .iter()
        .map(|ssid| mastersos_bundle::Wifi {
            ssid: (*ssid).into(),
            open: Some(true),
            ..Default::default()
        })
        .collect();
    s.to_toml()
}

fn stick(files: &[(&str, String)]) -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    for (n, body) in files {
        fs::write(d.path().join(n), body).unwrap();
    }
    d
}

fn valid_text(f: &SeedFound) -> &str {
    match f {
        SeedFound::Valid { text, .. } => text,
        other => panic!("{other:?}"),
    }
}

#[test]
fn single_valid_seed_is_used_without_question() {
    let d = stick(&[("seed.toml", seed_toml())]);
    let files = read_seeds(d.path()).unwrap();
    let mut tty = FakeTty::default();
    let found = choose_seed(&files, &mut tty).unwrap();
    assert_eq!(valid_text(&found), seed_toml());
    assert!(tty.shown.is_empty(), "{:?}", tty.shown);
}

#[test]
fn no_seed_is_none_and_silent() {
    let d = tempfile::tempdir().unwrap();
    let files = read_seeds(d.path()).unwrap();
    let mut tty = FakeTty::default();
    assert!(matches!(
        choose_seed(&files, &mut tty).unwrap(),
        SeedFound::None
    ));
    assert!(tty.shown.is_empty());
}

#[test]
fn named_seed_alone_is_used() {
    let d = stick(&[("seed-eis.toml", seed_toml())]);
    let files = read_seeds(d.path()).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, "seed-eis.toml");
    let mut tty = FakeTty::default();
    let found = choose_seed(&files, &mut tty).unwrap();
    assert!(matches!(found, SeedFound::Valid { .. }));
    assert!(tty.shown.is_empty());
}

#[test]
fn two_seeds_prompt_and_pick_second() {
    let a = seed_with(Some("School A"), "https://a.example", &["wifi-a"]);
    let b = seed_with(Some("School B"), "https://b.example", &["wifi-b", "wifi-c"]);
    let d = stick(&[("seed-a.toml", a), ("seed-b.toml", b.clone())]);
    let files = read_seeds(d.path()).unwrap();
    let mut tty = FakeTty {
        answers: vec!["2".into()],
        ..Default::default()
    };
    let found = choose_seed(&files, &mut tty).unwrap();
    assert_eq!(valid_text(&found), b);
    let screen = tty.shown.join("\n");
    assert!(
        screen.contains("  1) School A  Wi-Fi: wifi-a  (a)"),
        "{screen}"
    );
    assert!(
        screen.contains("  2) School B  Wi-Fi: wifi-b +1  (b)"),
        "{screen}"
    );
    assert!(screen.contains("Choose a seed (number): "), "{screen}");
    assert!(!screen.contains("tok-SECRET"));
}

#[test]
fn menu_falls_back_to_server_url_and_marks_no_wifi() {
    let a = seed_with(None, "https://a.example", &[]);
    let d = stick(&[("seed-a.toml", a), ("seed-b.toml", seed_toml())]);
    let files = read_seeds(d.path()).unwrap();
    let mut tty = FakeTty {
        answers: vec!["1".into()],
        ..Default::default()
    };
    choose_seed(&files, &mut tty).unwrap();
    let screen = tty.shown.join("\n");
    assert!(
        screen.contains("1) https://a.example  Wi-Fi: none"),
        "{screen}"
    );
}

/// Final review M2: names that differ only at the end stay apart — the menu drops `seed-` and
/// `.toml` and cuts long names from the start.
#[test]
fn menu_keeps_the_end_of_long_seed_names() {
    assert_eq!(seed_label("seed-eis-primary-a.toml"), "eis-primary-a");
    assert_eq!(seed_label("SEED-EIS.TOML"), "EIS");
    assert_eq!(seed_label("seed.toml"), "seed");
    assert_eq!(display_fit_tail("abcdef", 6), "abcdef");
    assert_eq!(display_fit_tail("abcdefgh", 6), "...fgh");
    let a = seed_with(Some("EIS"), "https://eis.example", &["Campus"]);
    let long_a = "seed-eis-primary-campus-building-a.toml";
    let long_b = "seed-eis-primary-campus-building-b.toml";
    let d = stick(&[(long_a, a.clone()), (long_b, a)]);
    let files = read_seeds(d.path()).unwrap();
    let mut tty = FakeTty {
        answers: vec!["1".into()],
        ..Default::default()
    };
    choose_seed(&files, &mut tty).unwrap();
    let screen = tty.shown.join("\n");
    assert!(screen.contains("(...campus-building-a)"), "{screen}");
    assert!(screen.contains("(...campus-building-b)"), "{screen}");
    assert!(screen.is_ascii(), "{screen}");
}

/// Final review I1: a seed whose Wi-Fi entry fails the rules parses (an installed agent keeps
/// starting) but the installer lists it as invalid, naming the SSID and never the secret.
#[test]
fn seed_with_bad_wifi_is_invalid_in_the_menu() {
    let mut s = Seed::parse(&seed_toml()).unwrap();
    s.wifi = vec![mastersos_bundle::Wifi {
        ssid: "Campus".into(),
        psk: Some("SHORT-X".into()),
        ..Default::default()
    }];
    let text = s.to_toml();
    // The agent side: parsing succeeds.
    assert!(Seed::parse(&text).is_ok());
    let d = stick(&[("seed-a.toml", text), ("seed-b.toml", seed_toml())]);
    let files = read_seeds(d.path()).unwrap();
    let why = match &files[0].found {
        SeedFound::Invalid(why) => why.clone(),
        other => panic!("{other:?}"),
    };
    assert!(
        why.contains("seed-a.toml") && why.contains("Campus"),
        "{why}"
    );
    assert!(
        !why.contains("SHORT-X") && !why.contains("tok-SECRET"),
        "{why}"
    );
    // The same SSID twice is invalid too.
    let mut s = Seed::parse(&seed_toml()).unwrap();
    let open = mastersos_bundle::Wifi {
        ssid: "Campus".into(),
        open: Some(true),
        ..Default::default()
    };
    s.wifi = vec![open.clone(), open];
    let d = stick(&[("seed.toml", s.to_toml())]);
    assert!(matches!(
        read_seeds(d.path()).unwrap()[0].found,
        SeedFound::Invalid(_)
    ));
}

#[test]
fn lists_invalid_seed_unselectable() {
    let d = stick(&[
        (
            "seed-a.toml",
            "server_url = \"x\"\ntrust = [ tok-SECRET".into(),
        ),
        ("seed-b.toml", seed_toml()),
    ]);
    let files = read_seeds(d.path()).unwrap();
    let mut tty = FakeTty {
        // 2 is the bad file's position in the list but has no number: asked again
        answers: vec!["2".into(), "0".into(), "x".into(), "1".into()],
        ..Default::default()
    };
    let found = choose_seed(&files, &mut tty).unwrap();
    assert_eq!(valid_text(&found), seed_toml());
    let screen = tty.shown.join("\n");
    assert!(screen.contains("  -  seed-a.toml"), "{screen}");
    assert!(screen.contains("not valid TOML"), "{screen}");
    assert!(!screen.contains("tok-SECRET"), "{screen}");
    assert_eq!(
        tty.shown
            .iter()
            .filter(|s| s.contains("Choose a seed"))
            .count(),
        4
    );
}

#[test]
fn valid_seed_beside_an_invalid_one_still_asks() {
    let d = stick(&[("seed.toml", seed_toml()), ("seed (1).toml", seed_toml())]);
    let files = read_seeds(d.path()).unwrap();
    let mut tty = FakeTty {
        answers: vec!["1".into()],
        ..Default::default()
    };
    choose_seed(&files, &mut tty).unwrap();
    assert!(tty.shown.iter().any(|s| s.contains("seed (1).toml")));
}

#[test]
fn all_invalid_refuses() {
    let d = stick(&[
        ("seed.toml", "garbage = [".into()),
        (
            "seed-b.toml",
            "server_url = \"x\"\ntrust = []\nfetch_token = \"tok-SECRET\"\n".into(),
        ),
    ]);
    let files = read_seeds(d.path()).unwrap();
    let mut tty = FakeTty::default();
    let e = choose_seed(&files, &mut tty).unwrap_err();
    let msg = format!("{e:#}");
    assert!(
        msg.contains("seed.toml") && msg.contains("seed-b.toml"),
        "{msg}"
    );
    assert!(!msg.contains("tok-SECRET"), "{msg}");
    assert!(tty.shown.is_empty());
}

#[test]
fn ignores_appledouble() {
    let d = stick(&[
        ("seed-eis.toml", seed_toml()),
        ("._seed-eis.toml", "x".into()),
        ("._seed.toml", "x".into()),
    ]);
    let files = read_seeds(d.path()).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, "seed-eis.toml");
}

#[test]
fn bad_seed_name_is_invalid() {
    for name in [
        "seed_MIS.toml",
        "seed (1).toml",
        "seed-.toml",
        "seed-a_b.toml",
        "my.toml",
    ] {
        let d = stick(&[(name, seed_toml())]);
        let files = read_seeds(d.path()).unwrap();
        assert_eq!(files.len(), 1, "{name}");
        let r = match &files[0].found {
            SeedFound::Invalid(r) => r.clone(),
            other => panic!("{name}: {other:?}"),
        };
        assert!(r.contains(name), "{r}");
        assert!(
            r.contains("seed.toml") && r.contains("seed-<name>.toml"),
            "{r}"
        );
    }
    // Case is ignored, like the old seed.toml check.
    let d = stick(&[("SEED-EIS.TOML", seed_toml())]);
    assert!(matches!(
        read_seeds(d.path()).unwrap()[0].found,
        SeedFound::Valid { .. }
    ));
}

#[test]
fn seeds_are_sorted_by_name() {
    let d = stick(&[
        ("seed-b.toml", seed_toml()),
        ("seed.toml", seed_toml()),
        ("seed-a.toml", seed_toml()),
    ]);
    let names: Vec<String> = read_seeds(d.path())
        .unwrap()
        .into_iter()
        .map(|f| f.name)
        .collect();
    assert_eq!(names, ["seed-a.toml", "seed-b.toml", "seed.toml"]);
}

#[test]
fn unreadable_seed_folder_is_an_error() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("file");
    fs::write(&f, "x").unwrap();
    assert!(read_seeds(&f).is_err());
    assert!(read_seeds(&d.path().join("gone")).unwrap().is_empty());
}

#[test]
fn confirm_screen_shows_school_and_wifi() {
    let text = seed_with(Some("EIS"), "https://eis.example", &["Campus", "Guest"]);
    let seed = SeedFound::Valid {
        seed: Box::new(Seed::parse(&text).unwrap()),
        text,
    };
    let t = confirm_text(&target(), &seed);
    assert!(t.contains("School: EIS"), "{t}");
    assert!(t.contains("Wi-Fi: Campus +1"), "{t}");
    let text = seed_with(None, "https://eis.example", &[]);
    let seed = SeedFound::Valid {
        seed: Box::new(Seed::parse(&text).unwrap()),
        text,
    };
    let t = confirm_text(&target(), &seed);
    assert!(
        t.contains("Wi-Fi: none (connect a cable or set it up after install)"),
        "{t}"
    );
    assert!(t.contains("School: -"), "{t}");
}

#[test]
fn screen_text_is_ascii_only() {
    // A hand-edited seed may carry anything in these fields; the console has no glyphs for it.
    let text = seed_with(
        Some("\u{5b66}\u{6821} \u{1b}[31mMIS"),
        "https://eis.example/\u{7ec4}",
        &["\u{5496}\u{5561}Wi\u{7684}"],
    );
    let d = stick(&[
        ("seed-a.toml", text.clone()),
        ("seed-b.toml", seed_toml()),
        ("seed-\u{5b66}.toml", "x".into()),
    ]);
    let files = read_seeds(d.path()).unwrap();
    let mut tty = FakeTty {
        answers: vec!["1".into()],
        ..Default::default()
    };
    let found = choose_seed(&files, &mut tty).unwrap();
    let mut screen = tty.shown.join("\n");
    screen.push_str(&confirm_text(&target(), &found));
    assert!(screen.is_ascii(), "{screen:?}");
    assert!(
        !screen.chars().any(|c| c.is_control() && c != '\n'),
        "{screen:?}"
    );
    assert!(screen.contains('?'));
}

#[test]
fn long_fields_fit_in_80_columns() {
    let long = "x".repeat(200);
    let a = seed_with(
        Some(&long),
        &format!("https://{long}"),
        &[&"s".repeat(32), "b"],
    );
    let name = format!("seed-{}.toml", "n".repeat(100));
    let d = stick(&[(name.as_str(), a), ("seed-b.toml", "oops".into())]);
    let files = read_seeds(d.path()).unwrap();
    let mut tty = FakeTty {
        answers: vec!["1".into()],
        ..Default::default()
    };
    choose_seed(&files, &mut tty).unwrap();
    for line in &tty.shown {
        for l in line.lines() {
            assert!(l.len() <= 79, "{} cols: {l}", l.len());
        }
    }
    let t = confirm_text(
        &target(),
        &choose_seed(&files[1..], &mut FakeTty::default()).unwrap(),
    );
    for l in t.lines() {
        assert!(l.len() <= 79, "{} cols: {l}", l.len());
    }
}

/// Run `run_install_with` (Stick mode, usable TPM, one internal disk) with these seeds and answers.
fn run_with_seeds(
    seeds: Result<Vec<SeedFile>, String>,
    answers: &[&str],
) -> (anyhow::Result<()>, Vec<String>, FakeRunner) {
    let (tmp, r) = usable_tpm_machine("lsblk-single-nvme.json");
    let mut tty = FakeTty {
        answers: answers.iter().map(|a| a.to_string()).collect(),
        ..Default::default()
    };
    let env = InstallEnv {
        sysfs: &tmp.path().join("sys"),
        dev: &tmp.path().join("dev"),
        proc_dir: &tmp.path().join("proc"),
        restart: Restart {
            sysrq: &tmp.path().join("sysrq"),
            sleep: &|_| {},
        },
        sleep: &|_| {},
        locate_seeds: &|_| seeds.clone(),
        profile: Profile::Release,
        shim: &tmp.path().join("BOOTX64.EFI"),
        tmp: tmp.path(),
        mode: Mode::Stick,
        ventoy_part_file: Path::new(VENTOY_PART_FILE),
        ventoy_mount: Path::new(VENTOY_MOUNT),
    };
    let res = run_install_with(&r, &mut tty, &env);
    (res, tty.shown.clone(), r)
}

fn valid_file(name: &str, text: String) -> SeedFile {
    SeedFile {
        name: name.into(),
        found: SeedFound::Valid {
            seed: Box::new(Seed::parse(&text).unwrap()),
            text,
        },
    }
}

#[test]
fn menu_comes_after_hardware_checks_and_before_the_confirm_screen() {
    let a = seed_with(Some("School A"), "https://a.example", &["wifi-a"]);
    let b = seed_with(Some("School B"), "https://b.example", &[]);
    let seeds = vec![valid_file("seed-a.toml", a), valid_file("seed-b.toml", b)];
    let (res, shown, _r) = run_with_seeds(Ok(seeds), &["2", "n"]);
    assert!(format!("{:#}", res.unwrap_err()).contains("Cancelled"));
    let at = |p: &str| {
        shown
            .iter()
            .position(|s| s.contains(p))
            .unwrap_or_else(|| panic!("{p}: {shown:?}"))
    };
    assert!(at("Checking TPM") < at("Checking hardware"));
    assert!(at("Checking hardware") < at("Choose a seed"));
    assert!(at("Choose a seed") < at("ERASES"));
    let confirm = &shown[at("ERASES")];
    assert!(confirm.contains("School: School B"), "{confirm}");
}

#[test]
fn all_invalid_seeds_refuse_before_the_tpm_check() {
    let seeds = vec![SeedFile {
        name: "seed-a.toml".into(),
        found: SeedFound::Invalid("seed-a.toml is not valid TOML near line 1".into()),
    }];
    let (res, shown, r) = run_with_seeds(Ok(seeds), &[]);
    let msg = format!("{:#}", res.unwrap_err());
    assert!(
        msg.contains("The seed is invalid") && msg.contains("seed-a.toml"),
        "{msg}"
    );
    assert!(
        !shown.iter().any(|s| s.contains("Checking TPM")),
        "{shown:?}"
    );
    assert!(r.calls().iter().all(|c| is_read_only(c)));
}

/// A key held at power-on: the characters typed ahead must not answer the warnings prompt (or any later one).
#[test]
fn held_keys_do_not_answer_the_prompts() {
    let (tmp, r) = tpm_ok_machine("lsblk-single-nvme.json");
    hw_db(tmp.path(), &[MS_2011, MS_2023]); // no Wi-Fi card: the warnings prompt comes first
    let mut tty = FakeTty {
        typed_ahead: vec!["dddddddd".into()],
        answers: vec!["y".into(), "n".into()],
        ..Default::default()
    };
    let e = install(&r, &mut tty, tmp.path(), Profile::Release).unwrap_err();
    assert!(format!("{e:#}").contains("Cancelled"), "{e:#}");
    let shown = tty.shown.join("\n");
    assert!(
        shown.contains("ERASES"),
        "the keys typed ahead answered the warnings prompt: {shown}"
    );
    assert!(tty.answers.is_empty(), "{:?}", tty.answers);
}
