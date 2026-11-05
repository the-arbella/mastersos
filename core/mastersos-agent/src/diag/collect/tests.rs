use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;

use anyhow::anyhow;
use chrono::TimeZone;
use mastersos_bundle::diag::{DIAG_INBOX_MAX_BYTES, DIAG_TICKET_MAX_BYTES};

use super::*;
use crate::runner::{FakeRunner, Output};

const PNG: &[u8] = b"\x89PNG\r\n\x1a\nfake-image-bytes";

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 5, 9, 30, 0).unwrap()
}

fn put(root: &Path, rel: &str, data: &[u8]) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, data).unwrap();
}

/// A machine tree with the whitelisted files and, beside them, decoys that must never be read.
fn tree() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    let r = d.path();
    put(r, CMDLINE, b"BOOT_IMAGE=/vmlinuz quiet splash\n");
    put(
        r,
        INPUT_DEVICES,
        b"I: Bus=0011 Vendor=0001\nN: Name=\"AT keyboard\"\n",
    );
    put(r, MEM_SLEEP, b"s2idle [deep]\n");
    put(r, OS_RELEASE, b"NAME=MastersOS\nVERSION_ID=26.11\n");
    put(
        r,
        "sys/class/power_supply/BAT0/uevent",
        b"POWER_SUPPLY_NAME=BAT0\nPOWER_SUPPLY_CAPACITY=81\n",
    );
    put(
        r,
        "sys/class/power_supply/AC/uevent",
        b"POWER_SUPPLY_ONLINE=1\n",
    );
    put(
        r,
        AGENT_STATE,
        br#"{"device_id":"dev-1","inbox_after":4,"x_token":"DECOY-STATE-TOKEN"}"#,
    );
    put(r, STATUS_REPORT, br#"{"network":"ok","settings":"ok"}"#);
    // decoys
    put(r, "var/lib/mastersos-seed/identity.json", b"DECOY-IDENTITY");
    put(r, "var/lib/mastersos-seed/seed.toml", b"DECOY-SEED");
    put(r, "var/lib/mastersos-seed/fetch-token", b"DECOY-SEED-TOKEN");
    put(r, "var/lib/mastersos/seed.toml", b"DECOY-STATE-SEED");
    put(r, "var/lib/mastersos/fetch-token", b"DECOY-FETCH-TOKEN");
    put(
        r,
        "etc/NetworkManager/system-connections/School.nmconnection",
        b"[wifi-security]\nDECOY-NM-PSK\n",
    );
    put(r, "home/student/notes.txt", b"DECOY-HOME");
    put(r, "etc/ssh/ssh_host_ed25519_key", b"DECOY-HOST-KEY");
    d
}

fn opts(root: &Path) -> CollectOpts {
    CollectOpts {
        root: root.to_path_buf(),
        kind: DiagKind::Inbox,
        boots: 1,
        since_minutes: None,
        screenshot: None,
        max_bytes: DIAG_INBOX_MAX_BYTES,
    }
}

/// The decompressed archive, with the window limit the cloud uses.
fn decode(p: &Path) -> Vec<u8> {
    let mut d = zstd::stream::read::Decoder::new(File::open(p).unwrap()).unwrap();
    d.window_log_max(ZSTD_WINDOW_LOG).unwrap();
    let mut raw = Vec::new();
    d.read_to_end(&mut raw).unwrap();
    raw
}

/// The archive's files by path, in archive order.
fn unpack(p: &Path) -> Vec<(String, Vec<u8>)> {
    let raw = decode(p);
    let mut a = tar::Archive::new(raw.as_slice());
    a.entries()
        .unwrap()
        .map(|e| {
            let mut e = e.unwrap();
            let path = e.path().unwrap().to_string_lossy().into_owned();
            let mut b = Vec::new();
            e.read_to_end(&mut b).unwrap();
            (path, b)
        })
        .collect()
}

fn skipped_of<'a>(m: &'a DiagManifest, src: &str) -> Vec<&'a str> {
    m.skipped
        .iter()
        .filter(|s| s.source == src)
        .map(|s| s.reason.as_str())
        .collect()
}

/// Says that some programs are not installed (as `RealRunner` does), answers the rest from a [`FakeRunner`].
struct Missing<'a> {
    fake: &'a FakeRunner,
    programs: &'a [&'a str],
}

impl Runner for Missing<'_> {
    fn run(&self, cmd: &Cmd) -> Result<Output> {
        if self.programs.contains(&cmd.program.as_str()) {
            return Err(anyhow!("{} could not be started", cmd.program))
                .context("No such file or directory (os error 2)");
        }
        self.fake.run(cmd)
    }
}

#[test]
fn manifest_lists_every_file_with_type_and_bytes() {
    let root = tree();
    put(root.path(), "run/shot.png", PNG);
    let out = tempfile::tempdir().unwrap();
    let r = FakeRunner::new();
    r.respond("journalctl -b 0", Output::ok("Nov 05 boot zero line\n"));
    r.respond("nmcli general", Output::ok("STATE connected\n"));
    let mut o = opts(root.path());
    o.screenshot = Some("/run/shot.png".into());
    let c = collect(&o, "dev-1", out.path(), &r, now()).unwrap();

    let files = unpack(&c.path);
    assert_eq!(files[0].0, DIAG_MANIFEST_NAME, "the manifest comes first");
    let in_archive: BTreeMap<&str, &[u8]> = files[1..]
        .iter()
        .map(|(p, b)| (p.as_str(), b.as_slice()))
        .collect();
    let listed: Vec<&str> = c.manifest.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(
        listed
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>(),
        in_archive.keys().copied().collect(),
        "every file listed, nothing unlisted"
    );
    assert_eq!(listed.len(), in_archive.len(), "no duplicate paths");
    for f in &c.manifest.files {
        assert_eq!(
            f.bytes,
            in_archive[f.path.as_str()].len() as u64,
            "{}",
            f.path
        );
        let want = if f.source == source::SCREENSHOT {
            DiagFileType::Image
        } else {
            DiagFileType::Text
        };
        assert_eq!(f.kind, want, "{}", f.path);
    }
    let shot = c.manifest.files.iter().find(|f| f.path == "screenshot.png");
    assert_eq!(shot.map(|f| f.source.as_str()), Some(source::SCREENSHOT));
    assert_eq!(in_archive["screenshot.png"], PNG);
    assert_eq!(in_archive["journal/boot-0.txt"], b"Nov 05 boot zero line\n");
    assert_eq!(in_archive["nm-general.txt"], b"STATE connected\n");
    assert_eq!(in_archive["mem-sleep.txt"], b"s2idle [deep]\n");
    let ps = String::from_utf8_lossy(in_archive["power-supply.txt"]);
    assert!(
        ps.find("== AC ==").unwrap() < ps.find("== BAT0 ==").unwrap(),
        "{ps}"
    );
    assert!(ps.contains("POWER_SUPPLY_CAPACITY=81"), "{ps}");
    // The manifest inside is the one returned.
    let inner: DiagManifest = serde_json::from_slice(&files[0].1).unwrap();
    assert_eq!(inner, c.manifest);
    assert_eq!(inner.device_id, "dev-1");
    assert_eq!(inner.created_at, now());
    assert_eq!(inner.kind, DiagKind::Inbox);
    assert!(!inner.truncated);
}

#[test]
fn manifest_validates() {
    let root = tree();
    let out = tempfile::tempdir().unwrap();
    let r = FakeRunner::new();
    r.respond(
        "coredumpctl list",
        Output::ok(
            "TIME                        PID  UID  GID SIG     COREFILE EXE\n\
             Tue 2026-11-04 10:00:00 UTC 4242 1000 1000 SIGSEGV present  /usr/bin/x\n",
        ),
    );
    r.respond(
        "coredumpctl info --no-pager 4242",
        Output::ok("PID: 4242\n"),
    );
    r.respond(
        "loginctl list-sessions",
        Output::ok("SESSION UID USER SEAT\n      2 1000 alice seat0\n\n1 sessions listed.\n"),
    );
    r.respond("loginctl show-session 2", Output::ok("Id=2\nClass=user\n"));
    let mut o = opts(root.path());
    o.boots = 3;
    let c = collect(&o, "dev-1", out.path(), &r, now()).unwrap();
    c.manifest.validate().unwrap();
    // Each source has exactly one file (journal: one per boot), or is skipped.
    for src in source::ALL {
        let n = c.manifest.files.iter().filter(|f| f.source == *src).count();
        match *src {
            source::JOURNAL => assert_eq!(n, 3),
            source::JOURNAL_RECENT | source::SCREENSHOT => assert_eq!(n, 0, "{src}"),
            _ => assert_eq!(n, 1, "{src}: {:?}", c.manifest.skipped),
        }
    }
    assert!(c.manifest.skipped.is_empty(), "{:?}", c.manifest.skipped);
    let calls = r.calls();
    for want in [
        "journalctl -b 0 -o short-iso-precise --no-pager",
        "journalctl -b -1 -o short-iso-precise --no-pager",
        "journalctl -b -2 -o short-iso-precise --no-pager",
        "coredumpctl info --no-pager 4242",
        "loginctl show-session 2",
        "nmcli connection show",
    ] {
        assert!(calls.iter().any(|c| c == want), "{want}: {calls:?}");
    }
    assert!(
        !calls.iter().any(|c| c.contains("show-session 1")),
        "{calls:?}"
    );
    let files: BTreeMap<String, Vec<u8>> = unpack(&c.path).into_iter().collect();
    let login = String::from_utf8_lossy(&files["loginctl.txt"]);
    assert!(login.contains("== session 2 ==\nId=2"), "{login}");

    // Light mode (a help ticket): only the recent journal, and the screenshot when given.
    let mut o = opts(root.path());
    o.kind = DiagKind::Ticket;
    o.since_minutes = Some(30);
    o.max_bytes = DIAG_TICKET_MAX_BYTES;
    let r = FakeRunner::new();
    r.respond("journalctl --since -30min", Output::ok("recent\n"));
    let c = collect(&o, "dev-1", out.path(), &r, now()).unwrap();
    c.manifest.validate().unwrap();
    let journal: Vec<(&str, &str)> = c
        .manifest
        .files
        .iter()
        .filter(|f| f.source.starts_with("journal"))
        .map(|f| (f.path.as_str(), f.source.as_str()))
        .collect();
    assert_eq!(journal, [("journal/recent.txt", source::JOURNAL_RECENT)]);
    assert!(r
        .calls()
        .contains(&"journalctl --since -30min -o short-iso-precise --no-pager".to_string()));
    assert_eq!(c.manifest.kind, DiagKind::Ticket);
}

#[test]
fn missing_command_goes_to_skipped() {
    let root = tree();
    fs::remove_dir_all(root.path().join(POWER_SUPPLY)).unwrap();
    fs::remove_file(root.path().join(STATUS_REPORT)).unwrap();
    let out = tempfile::tempdir().unwrap();
    let fake = FakeRunner::new();
    fake.respond(
        "lspci",
        Output::fail(1, "pcilib: cannot open /sys/bus/pci\n"),
    );
    fake.respond(
        "journalctl -b -1",
        Output::fail(
            1,
            "Data from the specified boot (-1) is not available: No such boot ID in journal\n",
        ),
    );
    let r = Missing {
        fake: &fake,
        programs: &["iw", "coredumpctl"],
    };
    let mut o = opts(root.path());
    o.boots = 2;
    o.screenshot = Some("run/none.png".into());
    let c = collect(&o, "dev-1", out.path(), &r, now()).unwrap();
    c.manifest.validate().unwrap();
    let m = &c.manifest;
    for src in [source::IW_DEV, source::IW_REG, source::COREDUMP_LIST] {
        let why = skipped_of(m, src);
        assert_eq!(why.len(), 1, "{src}: {:?}", m.skipped);
        assert!(why[0].contains("could not be started"), "{src}: {why:?}");
        assert!(!m.files.iter().any(|f| f.source == src), "{src}");
    }
    assert_eq!(skipped_of(m, source::COREDUMP_INFO), ["no coredump list"]);
    let lspci = skipped_of(m, source::LSPCI);
    assert_eq!(
        lspci,
        ["lspci exited with 1: pcilib: cannot open /sys/bus/pci"]
    );
    let journal = skipped_of(m, source::JOURNAL);
    assert_eq!(journal.len(), 1, "{journal:?}");
    assert!(
        journal[0].starts_with("journalctl exited with 1: Data from"),
        "{journal:?}"
    );
    assert_eq!(
        m.files
            .iter()
            .filter(|f| f.source == source::JOURNAL)
            .count(),
        1,
        "boot 0 is still there"
    );
    assert!(skipped_of(m, source::POWER_SUPPLY)[0].starts_with("/sys/class/power_supply: "));
    assert!(skipped_of(m, source::STATUS_REPORT)[0]
        .starts_with("/var/lib/mastersos-public/status.json: "));
    assert!(skipped_of(m, source::SCREENSHOT)[0].starts_with("reading the screenshot"));
    // Collected sources that worked are still there.
    assert!(m.files.iter().any(|f| f.source == source::NM_GENERAL));

    // A file that is not a PNG is not attached.
    put(root.path(), "run/shot.png", b"GIF89a....");
    o.screenshot = Some("run/shot.png".into());
    let c = collect(&o, "dev-1", out.path(), &r, now()).unwrap();
    assert_eq!(
        skipped_of(&c.manifest, source::SCREENSHOT),
        ["the screenshot is not a PNG"]
    );
}

#[test]
fn never_reads_seed_or_system_connections() {
    let root = tree();
    put(root.path(), "run/shot.png", PNG);
    let out = tempfile::tempdir().unwrap();
    let r = FakeRunner::new();
    let mut o = opts(root.path());
    o.boots = MAX_BOOTS;
    o.screenshot = Some("run/shot.png".into());
    let c = collect(&o, "dev-1", out.path(), &r, now()).unwrap();

    let forbidden = [
        "mastersos-seed",
        "system-connections",
        "identity.json",
        "seed.toml",
        "fetch-token",
        "/home",
        "ssh",
        "--show-secrets",
        "-s ",
    ];
    for call in r.calls() {
        for f in forbidden {
            assert!(!call.contains(f), "{call:?} references {f}");
        }
    }
    for p in READ_PATHS {
        for f in forbidden {
            assert!(!p.contains(f), "{p} references {f}");
        }
        assert!(
            !p.starts_with("home") && !p.starts_with("etc/NetworkManager"),
            "{p}"
        );
    }
    for (path, data) in unpack(&c.path) {
        let text = String::from_utf8_lossy(&data);
        assert!(
            !text.contains("DECOY"),
            "{path} holds decoy content: {text}"
        );
    }
    let files: BTreeMap<String, Vec<u8>> = unpack(&c.path).into_iter().collect();
    let state = String::from_utf8_lossy(&files["agent-state.json"]);
    assert!(state.ends_with(r#""x_token":[redacted]"#), "{state}");
    assert!(state.contains(r#""device_id":"dev-1""#), "{state}");
}

#[test]
fn redaction_applies_to_command_output() {
    let root = tree();
    let out = tempfile::tempdir().unwrap();
    let r = FakeRunner::new();
    r.respond(
        "journalctl -b 0",
        Output::ok("wpa_supplicant[1]: psk=\"hunter2\"\nordinary line\n"),
    );
    let c = collect(&opts(root.path()), "dev-1", out.path(), &r, now()).unwrap();
    let files: BTreeMap<String, Vec<u8>> = unpack(&c.path).into_iter().collect();
    assert_eq!(
        String::from_utf8_lossy(&files["journal/boot-0.txt"]),
        "wpa_supplicant[1]: psk=[redacted]\nordinary line\n"
    );
    let f = c
        .manifest
        .files
        .iter()
        .find(|f| f.path == "journal/boot-0.txt")
        .unwrap();
    assert_eq!(f.bytes, files["journal/boot-0.txt"].len() as u64);
}

/// Text that does not compress below half its size: hex of a SHA-256 chain.
fn noise(seed: u8, len: usize) -> String {
    let mut out = String::with_capacity(len + 64);
    let mut h = Sha256::digest([seed]);
    while out.len() < len {
        out.push_str(&crate::apply::hex(&h));
        h = Sha256::digest(h);
    }
    out
}

#[test]
fn truncates_oldest_boot_first() {
    let root = tree();
    let out = tempfile::tempdir().unwrap();
    let boot_text = 400 * 1024;
    let r = FakeRunner::new();
    for k in ["0", "-1", "-2"] {
        r.respond(
            &format!("journalctl -b {k} "),
            Output::ok(&noise(k.len() as u8 + k.as_bytes()[k.len() - 1], boot_text)),
        );
    }
    let mut o = opts(root.path());
    o.boots = 3;
    // each boot packs to a little over 200 KiB: three do not fit, two do
    o.max_bytes = 520 * 1024;
    let c = collect(&o, "dev-1", out.path(), &r, now()).unwrap();
    assert!(c.bytes <= o.max_bytes, "{} > {}", c.bytes, o.max_bytes);
    assert_eq!(c.bytes, fs::metadata(&c.path).unwrap().len());
    assert!(c.manifest.truncated);
    let boots: Vec<&str> = c
        .manifest
        .files
        .iter()
        .filter(|f| f.source == source::JOURNAL)
        .map(|f| f.path.as_str())
        .collect();
    assert_eq!(boots, ["journal/boot-0.txt", "journal/boot-1.txt"]);
    assert_eq!(
        skipped_of(&c.manifest, source::JOURNAL),
        ["journal/boot-2.txt left out: over the size limit"]
    );
    let inner: DiagManifest = serde_json::from_slice(&unpack(&c.path)[0].1).unwrap();
    assert!(inner.truncated);
    assert_eq!(inner, c.manifest);

    // Tighter: only the newest boot is left.
    for k in ["0", "-1", "-2"] {
        r.respond(
            &format!("journalctl -b {k} "),
            Output::ok(&noise(
                10 + k.len() as u8 + k.as_bytes()[k.len() - 1],
                boot_text,
            )),
        );
    }
    o.max_bytes = 300 * 1024;
    let c = collect(&o, "dev-1", out.path(), &r, now()).unwrap();
    assert!(c.bytes <= o.max_bytes);
    let boots: Vec<&str> = c
        .manifest
        .files
        .iter()
        .filter(|f| f.source == source::JOURNAL)
        .map(|f| f.path.as_str())
        .collect();
    assert_eq!(boots, ["journal/boot-0.txt"]);
}

#[test]
fn over_limit_without_logs_is_an_error_and_leaves_nothing() {
    let root = tree();
    let out = tempfile::tempdir().unwrap();
    let r = FakeRunner::new();
    r.respond("journalctl -b 0", Output::ok(&noise(1, 64 * 1024)));
    r.respond("lsusb", Output::ok(&noise(2, 160 * 1024)));
    let mut o = opts(root.path());
    o.max_bytes = 40 * 1024;
    let e = collect(&o, "dev-1", out.path(), &r, now()).unwrap_err();
    assert!(format!("{e:#}").contains("without any log"), "{e:#}");
    assert_eq!(fs::read_dir(out.path()).unwrap().count(), 0);
}

#[test]
fn sha256_matches_file() {
    let root = tree();
    let out = tempfile::tempdir().unwrap();
    let r = FakeRunner::new();
    r.respond("journalctl -b 0", Output::ok("hello\n"));
    let c = collect(&opts(root.path()), "dev-1", out.path(), &r, now()).unwrap();
    let bytes = fs::read(&c.path).unwrap();
    assert_eq!(c.sha256, crate::apply::sha256_hex(&bytes));
    assert_eq!(c.sha256.len(), 64);
    assert_eq!(c.bytes, bytes.len() as u64);
    assert_eq!(c.path, out.path().join("diag-20261105T093000Z.tar.zst"));
    let mode = fs::metadata(&c.path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    // Only the archive: the temporary file was renamed.
    let names: Vec<_> = fs::read_dir(out.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["diag-20261105T093000Z.tar.zst"]);
}

#[test]
fn archive_decodes_with_the_cloud_window_and_holds_regular_files_only() {
    let root = tree();
    put(root.path(), "run/shot.png", PNG);
    let out = tempfile::tempdir().unwrap();
    let r = FakeRunner::new();
    // Over the 8 MiB window, with repeats far apart that only a larger window would reach.
    let block = noise(3, 1024 * 1024);
    r.respond("journalctl -b 0", Output::ok(&block.repeat(12)));
    let mut o = opts(root.path());
    o.screenshot = Some("run/shot.png".into());
    let c = collect(&o, "dev-1", out.path(), &r, now()).unwrap();
    assert_eq!(ZSTD_WINDOW_LOG, 23);
    // The decoder refuses a frame that needs a window over 2^23.
    let raw = decode(&c.path);
    let mut a = tar::Archive::new(raw.as_slice());
    let mut n = 0;
    for e in a.entries().unwrap() {
        let e = e.unwrap();
        let t = e.header().entry_type();
        assert!(
            t == tar::EntryType::Regular || t == tar::EntryType::Directory,
            "{:?} is {t:?}",
            e.path().unwrap()
        );
        n += 1;
    }
    assert_eq!(n, c.manifest.files.len() + 1);
}
