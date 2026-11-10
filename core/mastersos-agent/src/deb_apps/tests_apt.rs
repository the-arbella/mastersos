use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::apt::*;
use crate::runner::{FakeRunner, Output, Runner};
use crate::safefs;

const KEYRING: &str = "/usr/share/keyrings/ubuntu-archive-keyring.gpg";
/// The container test runs the same apt commands; every option of [`apt_args`] must appear in it verbatim.
const APT_TEST_SH: &str = include_str!("../../../../image/tests/deb-apps-apt-test.sh");

fn ubuntu() -> UbuntuSource {
    UbuntuSource {
        snapshot: "20261101T000000Z".into(),
        codename: "resolute".into(),
        components: vec!["main".into(), "universe".into(), "restricted".into()],
    }
}

fn lines(s: &str) -> Vec<&str> {
    s.lines().collect()
}

fn hex256(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// The line prefix of an apt-get call with `sub` (what [`resolve`] runs, before the package arguments).
fn apt_line(work: &Path, sub: &[&str]) -> String {
    apt_cmd(work, sub).line()
}

#[test]
fn reads_ubuntu_source() {
    let u = read_ubuntu_source(
        "SNAPSHOT=20261101T000000Z\nCODENAME=resolute\nCOMPONENTS=main universe restricted\n",
    )
    .unwrap();
    assert_eq!(u, ubuntu());
    for bad in [
        "",
        "SNAPSHOT=20261101T000000Z\nCODENAME=resolute\n",
        "SNAPSHOT=2026-11-01\nCODENAME=resolute\nCOMPONENTS=main\n",
        "SNAPSHOT=20261101T000000Z\nCODENAME=Res olute\nCOMPONENTS=main\n",
        "SNAPSHOT=20261101T000000Z\nCODENAME=resolute\nCOMPONENTS=\n",
        "SNAPSHOT=20261101T000000Z\nCODENAME=resolute\nCOMPONENTS=main [x]\n",
        "SNAPSHOT=20261101T000000Z\nCODENAME=resolute\nCOMPONENTS=main\nOTHER=1\n",
        "SNAPSHOT=20261101T000000Z\nSNAPSHOT=20261101T000000Z\nCODENAME=resolute\nCOMPONENTS=main\n",
    ] {
        assert!(read_ubuntu_source(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn sources_for_snapshot() {
    let s = sources_list(
        &Source::Snapshot {
            stamp: "20261101T000000Z".into(),
        },
        &ubuntu(),
        Path::new("/w/archives"),
    );
    let base = "https://snapshot.ubuntu.com/ubuntu/20261101T000000Z";
    assert_eq!(
        lines(&s),
        vec![
            format!("deb [signed-by={KEYRING}] {base} resolute main universe restricted"),
            format!("deb [signed-by={KEYRING}] {base} resolute-updates main universe restricted"),
            format!("deb [signed-by={KEYRING}] {base} resolute-security main universe restricted"),
        ]
    );
}

#[test]
fn sources_for_archive() {
    let s = sources_list(&Source::Archive, &ubuntu(), Path::new("/w/archives"));
    assert_eq!(
        lines(&s),
        vec![
            format!("deb [signed-by={KEYRING}] http://archive.ubuntu.com/ubuntu resolute main universe restricted"),
            format!("deb [signed-by={KEYRING}] http://archive.ubuntu.com/ubuntu resolute-updates main universe restricted"),
            format!("deb [signed-by={KEYRING}] http://security.ubuntu.com/ubuntu resolute-security main universe restricted"),
        ]
    );
}

#[test]
fn sources_for_mirror() {
    let s = sources_list(
        &Source::Mirror {
            url: "https://mirror.example.org/ubuntu".into(),
        },
        &ubuntu(),
        Path::new("/w/archives"),
    );
    let m = "https://mirror.example.org/ubuntu";
    assert_eq!(
        lines(&s),
        vec![
            format!("deb [signed-by={KEYRING}] {m} resolute main universe restricted"),
            format!("deb [signed-by={KEYRING}] {m} resolute-updates main universe restricted"),
            format!("deb [signed-by={KEYRING}] {m} resolute-security main universe restricted"),
        ]
    );
}

#[test]
fn sources_for_cache() {
    let s = sources_list(&Source::Cache, &ubuntu(), Path::new("/w/archives"));
    assert_eq!(lines(&s), vec!["deb [trusted=yes] file:/w/archives ./"]);
}

#[test]
fn apt_args_are_private() {
    let a = apt_args(Path::new("/w"));
    let want = [
        "Dir::State::status=/usr/share/factory/var/lib/dpkg/status",
        "Dir::Etc::sourcelist=/w/sources.list",
        "Dir::Etc::sourceparts=-",
        "Dir::Etc::trusted=-",
        "Dir::Etc::trustedparts=-",
        "Dir::Etc::preferences=/w/preferences",
        "Dir::Etc::preferencesparts=/w/preferences.d",
        "Dir::Etc::netrc=/w/auth.conf",
        "Dir::Etc::netrcparts=/w/auth.conf.d",
        "Dir::State::lists=/w/lists",
        "Dir::Cache=/w/cache",
        "Dir::Cache::archives=/w/archives",
        "Acquire::Languages=none",
        "APT::Install-Recommends=false",
        "APT::Get::AllowUnauthenticated=false",
        "Debug::NoLocking=true",
        "APT::Sandbox::User=root",
        "APT::Architecture=amd64",
        "APT::Architectures=amd64",
        "APT::Update::Error-Mode=any",
    ];
    for w in want {
        let i = a
            .iter()
            .position(|x| x == w)
            .unwrap_or_else(|| panic!("{w} missing from {a:?}"));
        assert_eq!(a[i - 1], "-o", "{w}");
    }
    // Exactly these, each after its own -o.
    assert_eq!(a.len(), 2 * want.len(), "{a:?}");
    assert_eq!(a.len() % 2, 0);
    assert!(a.iter().step_by(2).all(|x| x == "-o"), "{a:?}");
}

/// The container test (`image/tests/deb-apps-apt-test.sh`) runs apt with the same options: no drift.
#[test]
fn container_test_uses_the_same_options() {
    for (i, opt) in apt_args(Path::new("/w"))
        .iter()
        .enumerate()
        .skip(1)
        .step_by(2)
    {
        let generic = opt.replace("/w/", "$work/");
        assert!(
            APT_TEST_SH.contains(&format!("\t-o {generic}\n"))
                || APT_TEST_SH.contains(&format!("\t-o \"{generic}\"\n")),
            "option {i} {generic:?} not in deb-apps-apt-test.sh"
        );
    }
    // And nothing more (apart from the test's own status, which comes last).
    let in_sh = APT_TEST_SH
        .lines()
        .filter(|l| l.starts_with("\t-o "))
        .count();
    assert_eq!(in_sh, apt_args(Path::new("/w")).len() / 2);
    for line in APT_CONF.lines() {
        assert!(
            APT_TEST_SH.contains(line),
            "{line:?} not in deb-apps-apt-test.sh"
        );
    }
}

#[test]
fn simulation_new_packages_ok() {
    let out = "NOTE: This is only a simulation!\n\
               Inst libxxf86dga1 (2:1.1.5-1build1 Ubuntu:26.04/resolute [amd64])\n\
               Inst x11-utils (7.7+6 Ubuntu:26.04/resolute [amd64])\n\
               Conf libxxf86dga1 (2:1.1.5-1build1 Ubuntu:26.04/resolute [amd64])\n\
               Conf x11-utils (7.7+6 Ubuntu:26.04/resolute [amd64])\n";
    assert_eq!(
        parse_simulation(out).unwrap(),
        vec![
            ("libxxf86dga1".to_string(), "2:1.1.5-1build1".to_string()),
            ("x11-utils".to_string(), "7.7+6".to_string()),
        ]
    );
    assert_eq!(parse_simulation("").unwrap(), vec![]);
}

#[test]
fn simulation_upgrade_rejected() {
    let out = "Inst x11-utils (7.7+6 Ubuntu:26.04/resolute [amd64])\n\
               Inst libc6 [2.41-1] (2.42-1 Ubuntu:26.04/resolute-updates [amd64])\n";
    assert_eq!(
        parse_simulation(out).unwrap_err(),
        ResolveError::WouldChangeImage {
            package: "libc6".into(),
            image_version: "2.41-1".into(),
            wanted: "2.42-1".into(),
        }
    );
    // A downgrade is the same thing.
    let out = "Inst libc6 [2.42-1] (2.41-1 Ubuntu:26.04/resolute [amd64]) []\n";
    assert_eq!(
        parse_simulation(out).unwrap_err(),
        ResolveError::WouldChangeImage {
            package: "libc6".into(),
            image_version: "2.42-1".into(),
            wanted: "2.41-1".into(),
        }
    );
    let e = ResolveError::WouldChangeImage {
        package: "libc6".into(),
        image_version: "2.41-1".into(),
        wanted: "2.42-1".into(),
    };
    let s = e.to_string();
    assert!(
        s.contains("libc6") && s.contains("2.41-1") && s.contains("2.42-1"),
        "{s}"
    );
}

#[test]
fn simulation_remove_rejected() {
    let out = "Remv gnome-shell-extension-x [46.0-1]\n\
               Inst x11-utils (7.7+6 Ubuntu:26.04/resolute [amd64])\n";
    let e = parse_simulation(out).unwrap_err();
    assert_eq!(
        e,
        ResolveError::WouldChangeImage {
            package: "gnome-shell-extension-x".into(),
            image_version: "46.0-1".into(),
            wanted: String::new(),
        }
    );
    assert!(e.to_string().contains("remove"), "{e}");
    // An unparsable Inst line is not skipped.
    assert!(parse_simulation("Inst x11-utils\n").is_err());
}

#[test]
fn simulation_purge_rejected() {
    let out = "Inst x11-utils (7.7+6 Ubuntu:26.04/resolute [amd64])\n\
               Purg libpam-mastersos [1.0-1]\n\
               Conf x11-utils (7.7+6 Ubuntu:26.04/resolute [amd64])\n";
    assert_eq!(
        parse_simulation(out).unwrap_err(),
        ResolveError::WouldChangeImage {
            package: "libpam-mastersos".into(),
            image_version: "1.0-1".into(),
            wanted: String::new(),
        }
    );
    // Without a version too.
    assert!(matches!(
        parse_simulation("Purg foo\n"),
        Err(ResolveError::WouldChangeImage { .. })
    ));
}

#[test]
fn cache_index_has_sha256() {
    let dir = tempfile::tempdir().unwrap();
    let body = b"not really a deb";
    fs::write(dir.path().join("x11-utils_7.7+6_amd64.deb"), body).unwrap();
    let d = safefs::open_abs_dir(dir.path(), false).unwrap();
    let debs = vec![
        CachedDeb {
            file_name: "x11-utils_7.7+6_amd64.deb".into(),
            control: "Package: x11-utils\nVersion: 7.7+6\nArchitecture: amd64\nDepends: libc6 (>= 2.34)\nDescription: X11 utilities\n some more text\nSHA256: 00\nSize: 1\n\n".into(),
            size: body.len() as u64,
            sha256: hex256(body),
        },
        CachedDeb {
            file_name: "libxxf86dga1_2%3a1.1.5-1build1_amd64.deb".into(),
            control: "Package: libxxf86dga1\nVersion: 2:1.1.5-1build1\nArchitecture: amd64\n".into(),
            size: 3,
            sha256: "ab".repeat(32),
        },
    ];
    write_cache_index(&d, &debs).unwrap();
    let p = fs::read_to_string(dir.path().join("Packages")).unwrap();
    let want = format!(
        "Package: x11-utils\nVersion: 7.7+6\nArchitecture: amd64\nDepends: libc6 (>= 2.34)\nDescription: X11 utilities\n some more text\n\
         Filename: ./x11-utils_7.7+6_amd64.deb\nSize: {}\nSHA256: {}\n\n\
         Package: libxxf86dga1\nVersion: 2:1.1.5-1build1\nArchitecture: amd64\n\
         Filename: ./libxxf86dga1_2%3a1.1.5-1build1_amd64.deb\nSize: 3\nSHA256: {}\n\n",
        body.len(),
        hex256(body),
        "ab".repeat(32)
    );
    assert_eq!(p, want);
    // No path tricks, no blank lines inside a paragraph.
    for name in ["../x.deb", "a/b.deb", ".x.deb", "x.txt", ""] {
        let bad = CachedDeb {
            file_name: name.into(),
            ..debs[1].clone()
        };
        assert!(write_cache_index(&d, &[bad]).is_err(), "{name:?}");
    }
    let bad = CachedDeb {
        control: "Package: a\n\nPackage: b\n".into(),
        ..debs[1].clone()
    };
    assert!(write_cache_index(&d, &[bad]).is_err());
    let bad = CachedDeb {
        sha256: "xyz".into(),
        ..debs[1].clone()
    };
    assert!(write_cache_index(&d, &[bad]).is_err());
}

#[test]
fn cached_deb_reads_control_and_hash() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("x11-utils_7.7+6_amd64.deb");
    fs::write(&p, b"deb bytes").unwrap();
    let r = FakeRunner::new();
    r.respond(
        "dpkg-deb -f",
        Output::ok("Package: x11-utils\nVersion: 7.7+6\nArchitecture: amd64\n"),
    );
    let c = cached_deb(&r, &p).unwrap();
    assert_eq!(c.file_name, "x11-utils_7.7+6_amd64.deb");
    assert_eq!(c.size, 9);
    assert_eq!(c.sha256, hex256(b"deb bytes"));
    assert!(c.control.starts_with("Package: x11-utils\n"));
    assert_eq!(r.calls(), vec![format!("dpkg-deb -f {}", p.display())]);
}

#[test]
fn source_order_follows_the_spec() {
    let snap = || Source::Snapshot {
        stamp: "20261101T000000Z".into(),
    };
    let mirror = || Source::Mirror {
        url: "https://m.example.org/ubuntu".into(),
    };
    assert_eq!(
        source_order(None, &ubuntu(), false),
        vec![snap(), Source::Archive]
    );
    assert_eq!(
        source_order(None, &ubuntu(), true),
        vec![Source::Cache, snap(), Source::Archive]
    );
    assert_eq!(
        source_order(Some("https://m.example.org/ubuntu"), &ubuntu(), false),
        vec![mirror()]
    );
    assert_eq!(
        source_order(Some("https://m.example.org/ubuntu"), &ubuntu(), true),
        vec![Source::Cache, mirror()]
    );
}

/// A free-space check that always passes.
fn no_check(_: u64) -> anyhow::Result<()> {
    Ok(())
}

/// A private work directory with one main package; returns (work, the main package's path).
fn setup() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let main = dir.path().join("testnav.deb");
    fs::write(&main, b"main").unwrap();
    (dir, main)
}

const SIM_OK: &str = "Inst testnav (1.0 [amd64])\n\
                      Inst libxxf86dga1 (2:1.1.5-1build1 Ubuntu:26.04/resolute [amd64])\n\
                      Inst x11-utils (7.7+6 Ubuntu:26.04/resolute [amd64])\n";

/// apt "downloads" the two dependencies into `<work>/archives`.
fn fake_downloads(work: &Path) {
    let a = work.join("archives");
    fs::create_dir_all(&a).unwrap();
    fs::write(a.join("libxxf86dga1_2%3a1.1.5-1build1_amd64.deb"), b"1").unwrap();
    fs::write(a.join("x11-utils_7.7+6_amd64.deb"), b"2").unwrap();
}

#[tokio::test]
async fn resolve_runs_update_simulate_download() {
    let (dir, main) = setup();
    let work = dir.path().join("apt");
    let fake = Arc::new(FakeRunner::new());
    fake.respond("dpkg-deb -f", Output::ok("testnav\n"));
    fake.respond(&apt_line(&work, &["-s", "install"]), Output::ok(SIM_OK));
    let r: Arc<dyn Runner> = fake.clone();
    fs::create_dir_all(&work).unwrap();
    fake_downloads(&work);
    let got = resolve(
        &r,
        &work,
        &ubuntu(),
        &Source::Archive,
        std::slice::from_ref(&main),
        &["x11-utils".to_string()],
        &no_check,
    )
    .await
    .unwrap();
    assert_eq!(
        got,
        vec![
            work.join("archives/libxxf86dga1_2%3a1.1.5-1build1_amd64.deb"),
            work.join("archives/x11-utils_7.7+6_amd64.deb"),
        ]
    );
    let pkgs = format!("{} x11-utils", main.display());
    assert_eq!(
        fake.calls(),
        vec![
            apt_line(&work, &["update"]),
            format!("{} {pkgs}", apt_line(&work, &["-s", "install"])),
            format!("dpkg-deb -f {} Package", main.display()),
            format!("{} {pkgs}", apt_line(&work, PRINT_URIS)),
            format!(
                "{} {pkgs}",
                apt_line(&work, &["install", "--download-only", "-y", "--no-remove"])
            ),
        ]
    );
    let sl = fs::read_to_string(work.join("sources.list")).unwrap();
    assert!(
        sl.contains("http://archive.ubuntu.com/ubuntu resolute "),
        "{sl}"
    );
    assert_eq!(fs::read_to_string(work.join("apt.conf")).unwrap(), APT_CONF);
    for d in ["lists/partial", "archives/partial", "cache"] {
        assert!(work.join(d).is_dir(), "{d}");
    }
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        fs::metadata(&work).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[tokio::test]
async fn resolve_rejects_an_image_change_before_downloading() {
    let (dir, main) = setup();
    let work = dir.path().join("apt");
    let fake = Arc::new(FakeRunner::new());
    fake.respond(
        &apt_line(&work, &["-s", "install"]),
        Output::ok("Inst libc6 [2.41-1] (2.42-1 Ubuntu:26.04/resolute-updates [amd64])\n"),
    );
    let r: Arc<dyn Runner> = fake.clone();
    let e = resolve(
        &r,
        &work,
        &ubuntu(),
        &Source::Archive,
        &[main],
        &[],
        &no_check,
    )
    .await
    .unwrap_err();
    assert!(matches!(e, ResolveError::WouldChangeImage { .. }), "{e}");
    assert!(
        !fake.calls().iter().any(|c| c.contains("--download-only")),
        "{:?}",
        fake.calls()
    );
}

#[tokio::test]
async fn resolve_refuses_odd_arguments() {
    let (dir, main) = setup();
    let work = dir.path().join("apt");
    let fake = Arc::new(FakeRunner::new());
    let r: Arc<dyn Runner> = fake.clone();
    for (inputs, extra) in [
        (vec![PathBuf::from("relative.deb")], vec![]),
        (vec![dir.path().join("x.tar")], vec![]),
        (vec![main.clone()], vec!["-o".to_string()]),
        (vec![main.clone()], vec!["APT::x=y".to_string()]),
        (vec![main.clone()], vec!["foo bar".to_string()]),
        (vec![main.clone()], vec!["libc6-".to_string()]),
    ] {
        assert!(
            resolve(
                &r,
                &work,
                &ubuntu(),
                &Source::Archive,
                &inputs,
                &extra,
                &no_check
            )
            .await
            .is_err(),
            "{inputs:?} {extra:?}"
        );
    }
    assert!(fake.calls().is_empty(), "{:?}", fake.calls());
}

#[tokio::test]
async fn snapshot_failure_falls_back_to_archive() {
    let (dir, main) = setup();
    let work = dir.path().join("apt");
    let fake = Arc::new(FakeRunner::new());
    fake.respond(
        &apt_line(&work, &["update"]),
        Output::fail(
            100,
            "E: Failed to fetch https://snapshot.ubuntu.com/...  503\n",
        ),
    );
    fake.respond("dpkg-deb -f", Output::ok("testnav\n"));
    fake.respond(&apt_line(&work, &["-s", "install"]), Output::ok(SIM_OK));
    let r: Arc<dyn Runner> = fake.clone();
    fs::create_dir_all(&work).unwrap();
    fake_downloads(&work);
    let order = source_order(None, &ubuntu(), false);
    let (used, got) = resolve_in_order(&r, &work, &ubuntu(), &order, &[main], &[], &no_check)
        .await
        .unwrap();
    assert_eq!(used, Source::Archive);
    assert_eq!(got.len(), 2);
    let updates: Vec<String> = fake
        .calls()
        .into_iter()
        .filter(|c| c.starts_with(&apt_line(&work, &["update"])))
        .collect();
    assert_eq!(updates.len(), 2, "{:?}", fake.calls());
    let sl = fs::read_to_string(work.join("sources.list")).unwrap();
    assert!(
        sl.contains("archive.ubuntu.com") && !sl.contains("snapshot"),
        "{sl}"
    );
}

#[tokio::test]
async fn snapshot_rejection_does_not_fall_back() {
    // Only a failed `apt-get update` moves on from the snapshot: a plan that would change the image is the answer.
    let (dir, main) = setup();
    let work = dir.path().join("apt");
    let fake = Arc::new(FakeRunner::new());
    fake.respond(
        &apt_line(&work, &["-s", "install"]),
        Output::ok("Remv libfoo [1.0]\n"),
    );
    let r: Arc<dyn Runner> = fake.clone();
    let order = source_order(None, &ubuntu(), false);
    let e = resolve_in_order(&r, &work, &ubuntu(), &order, &[main], &[], &no_check)
        .await
        .unwrap_err();
    assert!(matches!(e, ResolveError::WouldChangeImage { .. }), "{e}");
    let sl = fs::read_to_string(work.join("sources.list")).unwrap();
    assert!(sl.contains("snapshot.ubuntu.com"), "{sl}");
}

#[tokio::test]
async fn mirror_never_falls_back() {
    let (dir, main) = setup();
    let work = dir.path().join("apt");
    let fake = Arc::new(FakeRunner::new());
    fake.respond(
        &apt_line(&work, &["update"]),
        Output::fail(100, "E: mirror down\n"),
    );
    let r: Arc<dyn Runner> = fake.clone();
    let order = source_order(Some("https://m.example.org/ubuntu"), &ubuntu(), false);
    let e = resolve_in_order(&r, &work, &ubuntu(), &order, &[main], &[], &no_check)
        .await
        .unwrap_err();
    assert!(matches!(e, ResolveError::Update(_)), "{e}");
    assert!(e.to_string().contains("mirror down"), "{e}");
    assert_eq!(fake.calls(), vec![apt_line(&work, &["update"])]);
    let sl = fs::read_to_string(work.join("sources.list")).unwrap();
    assert!(
        sl.contains("m.example.org") && !sl.contains("ubuntu.com"),
        "{sl}"
    );
}

#[tokio::test]
async fn cache_failure_goes_online() {
    // After an image change the cache goes first; any failure there (here: the image's new libc6 is older than what the
    // cached dependencies were built against) moves on to the online order.
    let (dir, main) = setup();
    let work = dir.path().join("apt");
    let fake = Arc::new(FakeRunner::new());
    fake.respond(
        &apt_line(&work, &["-s", "install"]),
        Output::fail(
            100,
            "E: Unable to correct problems, you have held broken packages.\n",
        ),
    );
    fake.respond("dpkg-deb -f", Output::ok("testnav\n"));
    fake.respond(&apt_line(&work, &["-s", "install"]), Output::ok(SIM_OK));
    let r: Arc<dyn Runner> = fake.clone();
    fs::create_dir_all(&work).unwrap();
    fake_downloads(&work);
    let order = source_order(None, &ubuntu(), true);
    let (used, _) = resolve_in_order(&r, &work, &ubuntu(), &order, &[main], &[], &no_check)
        .await
        .unwrap();
    assert_eq!(
        used,
        Source::Snapshot {
            stamp: "20261101T000000Z".into()
        }
    );
}

#[tokio::test]
async fn missing_download_is_an_error() {
    let (dir, main) = setup();
    let work = dir.path().join("apt");
    let fake = Arc::new(FakeRunner::new());
    fake.respond("dpkg-deb -f", Output::ok("testnav\n"));
    fake.respond(&apt_line(&work, &["-s", "install"]), Output::ok(SIM_OK));
    fake.respond(&apt_line(&work, PRINT_URIS), Output::ok(URIS));
    let r: Arc<dyn Runner> = fake.clone();
    let e = resolve(
        &r,
        &work,
        &ubuntu(),
        &Source::Archive,
        &[main],
        &[],
        &no_check,
    )
    .await
    .unwrap_err();
    assert!(
        e.to_string().contains("x11-utils") || e.to_string().contains("libxxf86dga1"),
        "{e}"
    );
}

/// What `apt-get install --print-uris -qq` prints: the files apt would fetch, with their sizes. A `file:` URI (the main
/// package given by path, the offline cache) is used in place and needs no space.
const URIS: &str = "'http://archive.ubuntu.com/ubuntu/pool/main/libx/libxxf86dga/libxxf86dga1_1.1.5-1build1_amd64.deb' \
libxxf86dga1_2%3a1.1.5-1build1_amd64.deb 17000 SHA512:00\n\
'http://archive.ubuntu.com/ubuntu/pool/main/x/x11-utils/x11-utils_7.7+6_amd64.deb' x11-utils_7.7+6_amd64.deb 3000 SHA512:00\n\
'file:/w/testnav.deb' testnav_1.0_amd64.deb 900000000 SHA256:00\n";

#[test]
fn download_size_sums_the_fetched_files() {
    assert_eq!(download_size(URIS, &[]).unwrap(), 20000);
    assert_eq!(download_size("", &[]).unwrap(), 0);
    // apt's notes are not URI lines
    assert_eq!(download_size("N: a note\n", &[]).unwrap(), 0);
    for bad in [
        "'http://x/a.deb' a.deb\n",
        "'http://x/a.deb' a.deb twelve SHA512:00\n",
        "'http://x/a.deb a.deb 12 SHA512:00\n",
    ] {
        assert!(download_size(bad, &[]).is_err(), "{bad:?}");
    }
}

#[tokio::test]
async fn resolve_checks_free_space_before_downloading() {
    let (dir, main) = setup();
    let work = dir.path().join("apt");
    let fake = Arc::new(FakeRunner::new());
    fake.respond("dpkg-deb -f", Output::ok("testnav\n"));
    fake.respond(&apt_line(&work, &["-s", "install"]), Output::ok(SIM_OK));
    fake.respond(&apt_line(&work, PRINT_URIS), Output::ok(URIS));
    let r: Arc<dyn Runner> = fake.clone();
    let asked = std::sync::Mutex::new(vec![]);
    let full = |n: u64| -> anyhow::Result<()> {
        asked.lock().unwrap().push(n);
        anyhow::bail!("not enough free disk space for downloading the dependencies")
    };
    let e = resolve(&r, &work, &ubuntu(), &Source::Archive, &[main], &[], &full)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("not enough free disk space"), "{e}");
    assert_eq!(*asked.lock().unwrap(), vec![20000]);
    assert!(
        !fake.calls().iter().any(|c| c.contains("--download-only")),
        "{:?}",
        fake.calls()
    );
}

#[test]
fn download_size_fails_closed_without_uri_lines() {
    // packages to fetch, but nothing apt printed is a URI line: the size is unknown, not 0
    let missing = vec!["x11-utils 7.7+6".to_string()];
    for out in ["", "N: a note\n", "x11-utils_7.7+6_amd64.deb 3000\n"] {
        let e = format!("{:#}", download_size(out, &missing).unwrap_err());
        assert!(e.contains("x11-utils 7.7+6"), "{e}");
    }
    // URI lines present, or nothing to fetch: fine
    assert_eq!(download_size(URIS, &missing).unwrap(), 20000);
    assert_eq!(download_size("", &[]).unwrap(), 0);
}

#[tokio::test]
async fn resolve_refuses_a_download_list_without_uris() {
    // the dependencies are not cached and apt lists nothing: refused before downloading, whatever the free space
    let (dir, main) = setup();
    let work = dir.path().join("apt");
    let fake = Arc::new(FakeRunner::new());
    fake.respond("dpkg-deb -f", Output::ok("testnav\n"));
    fake.respond(&apt_line(&work, &["-s", "install"]), Output::ok(SIM_OK));
    fake.respond(&apt_line(&work, PRINT_URIS), Output::ok(""));
    let r: Arc<dyn Runner> = fake.clone();
    let e = resolve(
        &r,
        &work,
        &ubuntu(),
        &Source::Archive,
        &[main],
        &[],
        &no_check,
    )
    .await
    .unwrap_err();
    assert!(e.to_string().contains("libxxf86dga1"), "{e}");
    assert!(
        !fake.calls().iter().any(|c| c.contains("--download-only")),
        "{:?}",
        fake.calls()
    );
}
