use std::os::unix::fs::PermissionsExt;

use mastersos_bundle::ItemResult;

use super::*;
use crate::runner::{FakeRunner, Output};
use crate::system::SysPaths;

const GENERAL: &str = "nmcli -t -f STATE,CONNECTIVITY general";
const DEVICES: &str = "nmcli -t -f TYPE,STATE,DEVICE device";
const WIFI_LIST: &str = "nmcli -t -f SSID device wifi list --rescan no";
const REASON: &str = "nmcli -t -f GENERAL.REASON device show wlan0";

fn known() -> Vec<String> {
    vec!["School".to_string(), "Other".to_string()]
}

fn runner(general: &str, devices: &str, list: &str, reason: &str) -> FakeRunner {
    let r = FakeRunner::new();
    r.respond(GENERAL, Output::ok(general));
    r.respond(DEVICES, Output::ok(devices));
    r.respond(WIFI_LIST, Output::ok(list));
    r.respond(REASON, Output::ok(reason));
    r
}

#[test]
fn full_connectivity_is_ok() {
    let r = runner("connected:full\n", "", "", "");
    assert_eq!(classify_network(&r, &known()), (Net::Ok, None));
    // Nothing else is asked once the network is fine.
    assert_eq!(r.calls(), vec![GENERAL.to_string()]);
}

#[test]
fn limited_and_portal() {
    let r = runner("connected:limited\n", "", "", "");
    assert_eq!(
        classify_network(&r, &known()),
        (
            Net::Limited,
            Some("Connected, but no internet access".to_string())
        )
    );
    let r = runner("connected:portal\n", "", "", "");
    assert_eq!(
        classify_network(&r, &known()),
        (
            Net::Limited,
            Some("Connected, but behind a sign-in page (captive portal)".to_string())
        )
    );
}

#[test]
fn connected_unknown_is_ok() {
    let r = runner("connected:unknown\n", "", "", "");
    assert_eq!(classify_network(&r, &known()), (Net::Ok, None));
}

#[test]
fn connected_none_is_limited() {
    let r = runner("connected:none\n", "", "", "");
    assert_eq!(
        classify_network(&r, &known()),
        (
            Net::Limited,
            Some("Connected, but no internet access".to_string())
        )
    );
}

#[test]
fn auth_failed_with_empty_known_ssids() {
    let r = runner(
        "disconnected:none\n",
        "wifi:disconnected:wlan0\n",
        "",
        "GENERAL.REASON:7 (No secrets were provided)\n",
    );
    assert_eq!(
        classify_network(&r, &[]),
        (
            Net::AuthFailed,
            Some("Wi-Fi: could not sign in (wrong password?)".to_string())
        )
    );
}

#[test]
fn no_wifi_device_no_ethernet_is_no_adapter() {
    let r = runner(
        "disconnected:none\n",
        "ethernet:unavailable:enp1s0\nloopback:unmanaged:lo\n",
        "",
        "",
    );
    assert_eq!(
        classify_network(&r, &known()),
        (Net::NoAdapter, Some("No Wi-Fi adapter found".to_string()))
    );
}

#[test]
fn wifi_unavailable_is_wifi_off() {
    let r = runner("disconnected:none\n", "wifi:unavailable:wlan0\n", "", "");
    let (net, detail) = classify_network(&r, &known());
    assert_eq!(net, Net::WifiOff);
    assert!(detail.is_some());
}

#[test]
fn known_ssid_missing_is_not_in_range() {
    let r = runner(
        "disconnected:none\n",
        "wifi:disconnected:wlan0\n",
        "Neighbour\nCafe\\: Free\n",
        "",
    );
    assert_eq!(
        classify_network(&r, &known()),
        (
            Net::NotInRange,
            Some("Wi-Fi \"School\" not found nearby".to_string())
        )
    );
}

#[test]
fn reason_secrets_is_auth_failed() {
    let r = runner(
        "disconnected:none\n",
        "wifi:disconnected:wlan0\n",
        "Neighbour\nOther\n",
        "GENERAL.REASON:7 (No secrets were provided)\n",
    );
    assert_eq!(
        classify_network(&r, &known()),
        (
            Net::AuthFailed,
            Some("Wi-Fi \"Other\": could not sign in (wrong password?)".to_string())
        )
    );
}

/// The text NetworkManager 1.4x prints for each auth-failure reason (`nmcli -t -f GENERAL.REASON device show`).
#[test]
fn auth_reason_codes_by_number() {
    for reason in [
        "GENERAL.REASON:7 (Secrets were required, but not provided)\n",
        "GENERAL.REASON:8 (802.1X supplicant disconnected)\n",
        "GENERAL.REASON:9 (802.1X supplicant configuration failed)\n",
        "GENERAL.REASON:10 (802.1X supplicant failed)\n",
        "GENERAL.REASON:11 (802.1X supplicant took too long to authenticate)\n",
        "7 (Secrets were required, but not provided)\n",
    ] {
        let r = runner(
            "disconnected:none\n",
            "wifi:disconnected:wlan0\n",
            "School\n",
            reason,
        );
        assert_eq!(
            classify_network(&r, &known()).0,
            Net::AuthFailed,
            "{reason}"
        );
    }
}

#[test]
fn reason_42_supplicant_available_is_not_auth_failed() {
    for reason in [
        "GENERAL.REASON:42 (The supplicant is now available)\n",
        "GENERAL.REASON:12 (The Wi-Fi network could not be found)\n",
        "GENERAL.REASON:70 (secrets 802.1X supplicant)\n",
        "GENERAL.REASON:\n",
    ] {
        let r = runner(
            "disconnected:none\n",
            "wifi:disconnected:wlan0\n",
            "School\n",
            reason,
        );
        assert_eq!(
            classify_network(&r, &known()),
            (Net::Disconnected, Some("Not connected".to_string())),
            "{reason}"
        );
    }
}

#[test]
fn in_range_without_failure_is_disconnected() {
    let r = runner(
        "disconnected:none\n",
        "wifi:disconnected:wlan0\n",
        "School\n",
        "GENERAL.REASON:0 (No reason given)\n",
    );
    assert_eq!(
        classify_network(&r, &known()),
        (Net::Disconnected, Some("Not connected".to_string()))
    );
}

#[test]
fn nmcli_failure_is_disconnected_not_answering() {
    let r = FakeRunner::new();
    r.respond(GENERAL, Output::fail(8, "NetworkManager is not running"));
    assert_eq!(
        classify_network(&r, &known()),
        (
            Net::Disconnected,
            Some("NetworkManager not answering".to_string())
        )
    );
}

#[test]
fn nm_activating_is_connecting() {
    let r = runner(
        "connecting:none\n",
        "wifi:connecting (configuring):wlan0\n",
        "",
        "",
    );
    assert_eq!(
        classify_network(&r, &known()),
        (Net::Connecting, Some("Connecting".to_string()))
    );
    // The global state may lag behind the Wi-Fi device: an activating device is enough.
    let r = runner(
        "disconnected:none\n",
        "wifi:connecting (getting IP configuration):wlan0\n",
        "",
        "",
    );
    assert_eq!(
        classify_network(&r, &known()),
        (Net::Connecting, Some("Connecting".to_string()))
    );
}

#[test]
fn connecting_is_not_a_headline() {
    let s = Status::new(
        Net::Connecting,
        Some("Connecting".into()),
        Settings::Ok,
        None,
        Browser::Ok,
        None,
    );
    assert_eq!(s.headline(), None);
    assert_eq!(s.message, None);
    let s = Status::new(
        Net::Connecting,
        None,
        Settings::Waiting,
        None,
        Browser::Ok,
        None,
    );
    assert_eq!(s.headline().unwrap().0, "Waiting for school settings.");
}

// ---------------------------------------------------------------------------
// Grace period
// ---------------------------------------------------------------------------

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn d(s: &str) -> Option<String> {
    Some(s.to_string())
}

#[test]
fn grace_holds_back_problems_that_may_clear() {
    let t0 = std::time::Instant::now();
    for net in [Net::NotInRange, Net::Limited, Net::Disconnected] {
        let mut g = NetGrace::new(t0);
        assert_eq!(
            g.observe(net, d("x"), t0 + secs(10)),
            (Net::Connecting, d("x")),
            "{net:?}"
        );
        assert_eq!(g.wake_at(), Some(t0 + NET_GRACE), "{net:?}");
    }
    assert_eq!(NET_GRACE, secs(45));
}

#[test]
fn grace_definite_problems_show_at_once() {
    let t0 = std::time::Instant::now();
    for net in [Net::NoAdapter, Net::WifiOff, Net::AuthFailed] {
        let mut g = NetGrace::new(t0);
        assert_eq!(g.observe(net, d("x"), t0 + secs(1)), (net, d("x")));
        assert_eq!(g.wake_at(), None, "{net:?}");
    }
}

#[test]
fn grace_shows_after_the_window() {
    let t0 = std::time::Instant::now();
    let mut g = NetGrace::new(t0);
    assert_eq!(
        g.observe(Net::NotInRange, d("x"), t0 + secs(44)).0,
        Net::Connecting
    );
    assert_eq!(
        g.observe(Net::NotInRange, d("x"), t0 + NET_GRACE),
        (Net::NotInRange, d("x"))
    );
    assert_eq!(g.wake_at(), None);
}

#[test]
fn grace_window_restarts_when_the_network_drops() {
    let t0 = std::time::Instant::now();
    let mut g = NetGrace::new(t0);
    assert_eq!(g.observe(Net::Ok, None, t0 + secs(100)), (Net::Ok, None));
    assert_eq!(g.wake_at(), None);
    assert_eq!(
        g.observe(Net::Disconnected, d("x"), t0 + secs(110)).0,
        Net::Connecting
    );
    assert_eq!(g.wake_at(), Some(t0 + secs(110) + NET_GRACE));
    assert_eq!(
        g.observe(Net::Disconnected, d("x"), t0 + secs(150)).0,
        Net::Connecting
    );
    assert_eq!(
        g.observe(Net::Disconnected, d("x"), t0 + secs(155)).0,
        Net::Disconnected
    );
    // After a definite problem (Wi-Fi switched back on), a new window.
    assert_eq!(
        g.observe(Net::WifiOff, None, t0 + secs(200)).0,
        Net::WifiOff
    );
    assert_eq!(
        g.observe(Net::NotInRange, None, t0 + secs(205)).0,
        Net::Connecting
    );
}

#[test]
fn grace_activation_is_held_and_restarts_the_window() {
    let t0 = std::time::Instant::now();
    let mut g = NetGrace::new(t0);
    // Still activating long after the start: never shown.
    assert_eq!(
        g.observe(Net::Connecting, d("Connecting"), t0 + secs(100)),
        (Net::Connecting, d("Connecting"))
    );
    assert_eq!(g.wake_at(), Some(t0 + secs(100) + NET_GRACE));
    // The attempt ended without a link: the window counts from the activation.
    assert_eq!(
        g.observe(Net::NotInRange, d("x"), t0 + secs(120)).0,
        Net::Connecting
    );
    assert_eq!(
        g.observe(Net::NotInRange, d("x"), t0 + secs(145)).0,
        Net::NotInRange
    );
}

#[test]
fn boot_grace_from_uptime() {
    assert!(in_boot_grace(Some(secs(10))));
    assert!(!in_boot_grace(Some(NET_GRACE)));
    assert!(!in_boot_grace(None), "no uptime: no grace");
}

#[test]
fn settings_waiting_vs_unreachable() {
    assert_eq!(settings_status(true, None), (Settings::Ok, None));
    assert_eq!(settings_status(false, None), (Settings::Waiting, None));
    let (s, d) = settings_status(
        false,
        Some("error sending request for url (https://x/v1/bundle?after=3&wait=0): connection refused"),
    );
    assert_eq!(s, Settings::Unreachable);
    let d = d.unwrap();
    assert!(!d.contains("?after"), "{d}");
    assert!(d.contains("connection refused"), "{d}");
}

#[test]
fn detail_truncates_to_160() {
    let long = "x".repeat(300);
    let d = short_detail(&long);
    assert_eq!(d.chars().count(), 161);
    assert!(d.ends_with('…'));
    assert_eq!(short_detail("first\nsecond"), "first");
    assert_eq!(short_detail("short"), "short");
}

#[test]
fn chrome_ok_installing_failed() {
    assert_eq!(chrome_status(true, None), (Browser::Ok, None));
    assert_eq!(chrome_status(false, None), (Browser::Installing, None));
    let ok = ItemResult {
        item: "chrome".into(),
        ok: true,
        detail: None,
    };
    assert_eq!(chrome_status(false, Some(&ok)), (Browser::Installing, None));
    let bad = ItemResult {
        item: "chrome".into(),
        ok: false,
        detail: Some("download failed\nmore".into()),
    };
    assert_eq!(
        chrome_status(false, Some(&bad)),
        (Browser::Failed, Some("download failed".to_string()))
    );
}

#[test]
fn headline_priority_and_copy() {
    let all_ok = Status::new(Net::Ok, None, Settings::Ok, None, Browser::Ok, None);
    assert_eq!(all_ok.headline(), None);
    assert_eq!(all_ok.message, None);

    let s = Status::new(
        Net::WifiOff,
        Some("d1".into()),
        Settings::Waiting,
        None,
        Browser::Installing,
        None,
    );
    let (sentence, detail) = s.headline().unwrap();
    assert_eq!(
        sentence,
        "No network. Connect to Wi-Fi from the top-right menu."
    );
    assert_eq!(detail, Some("d1"));
    assert_eq!(s.message.as_deref(), Some(sentence));

    let s = Status::new(
        Net::Ok,
        None,
        Settings::Waiting,
        None,
        Browser::Installing,
        None,
    );
    assert_eq!(s.headline().unwrap().0, "Waiting for school settings.");

    let s = Status::new(
        Net::Ok,
        None,
        Settings::Ok,
        None,
        Browser::Failed,
        Some("boom".into()),
    );
    let (sentence, detail) = s.headline().unwrap();
    assert_eq!(
        sentence,
        "The web browser could not be installed yet; it will try again. You can sign in."
    );
    assert_eq!(detail, Some("boom"));

    // Still installing (no failure yet): the reassuring sentence, no detail.
    let s = Status::new(Net::Ok, None, Settings::Ok, None, Browser::Installing, None);
    assert_eq!(
        s.headline().unwrap().0,
        "Installing the web browser. You can sign in; it will appear when ready."
    );
}

#[test]
fn write_status_is_0644_and_reports_change() {
    let d = tempfile::tempdir().unwrap();
    let paths = SysPaths {
        root: d.path().to_path_buf(),
        var_dir: d.path().join("var/lib/mastersos-system"),
        public_dir: d.path().join("var/lib/mastersos-public"),
        state_dir: d.path().join("var/lib/mastersos"),
    };
    std::fs::create_dir_all(d.path().join("var/lib")).unwrap();
    assert_eq!(read_status(&paths), None);
    let s = Status::new(
        Net::NoAdapter,
        Some("No Wi-Fi adapter found".into()),
        Settings::Waiting,
        None,
        Browser::Installing,
        None,
    );
    assert!(write_status(&paths, &s).unwrap());
    assert!(!write_status(&paths, &s).unwrap());
    let meta = std::fs::metadata(paths.public_dir.join(STATUS_FILE)).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o644);
    assert_eq!(read_status(&paths), Some(s.clone()));
    let text = std::fs::read_to_string(paths.public_dir.join(STATUS_FILE)).unwrap();
    assert!(text.contains("\"network\": \"no_adapter\""), "{text}");
    assert!(!text.contains("updated_at"));

    let s2 = Status::new(Net::Ok, None, Settings::Ok, None, Browser::Ok, None);
    assert!(write_status(&paths, &s2).unwrap());
}

// ---------------------------------------------------------------------------
// StatusJob
// ---------------------------------------------------------------------------

mod job {
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use mastersos_bundle::{DeviceIdent, Manifest, Seed};
    use tokio::sync::watch;

    use super::super::*;
    use super::{DEVICES, GENERAL, REASON};
    use crate::chrome_sysext::ChromeStatus;
    use crate::fetch::Fetcher;
    use crate::jobs::{CurrentGroup, Job, JobCtx};
    use crate::runner::{FakeRunner, Output};
    use crate::system::banner::{self, BANNER_FILE, GDM_DCONF_DIR};
    use crate::system::login::{self, LoginPolicy};
    use crate::system::SysPaths;

    const NET: &str = "No network. Connect to Wi-Fi from the top-right menu.";

    struct Lab {
        d: tempfile::TempDir,
        paths: SysPaths,
        runner: Arc<FakeRunner>,
        job: StatusJob,
        current: watch::Sender<Option<Arc<CurrentGroup>>>,
        fetch_error: watch::Sender<Option<String>>,
        cx: JobCtx,
        now: Arc<Mutex<Instant>>,
    }

    impl Lab {
        /// A job whose start is past the grace window, so network problems show at once.
        fn new() -> Lab {
            let lab = Lab::fresh();
            lab.advance(NET_GRACE);
            lab
        }

        /// A job that has just started (inside the grace window).
        fn fresh() -> Lab {
            let d = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(d.path().join("var/lib")).unwrap();
            let paths = SysPaths {
                root: d.path().to_path_buf(),
                var_dir: d.path().join("var/lib/mastersos-system"),
                public_dir: d.path().join("var/lib/mastersos-public"),
                state_dir: d.path().join("var/lib/mastersos"),
            };
            let runner = Arc::new(FakeRunner::new());
            let now = Arc::new(Mutex::new(Instant::now()));
            let clock = now.clone();
            let job = StatusJob::with_clock(
                ChromeStatus::new(paths.state_dir.join("chrome")),
                d.path().join("usr/bin/google-chrome-stable"),
                Arc::new(move || *clock.lock().unwrap()),
            );
            let (current, current_rx) = watch::channel(None);
            let (fetch_error, fetch_error_rx) = watch::channel(None);
            let cx = JobCtx {
                fetcher: Fetcher::from_seed(&Seed {
                    server_url: "http://127.0.0.1:9".into(),
                    trust: vec![],
                    fetch_token: None,
                    group: None,
                    oidc: None,
                    min_version: None,
                    school_id: None,
                    wifi: vec![],
                    school_name: None,
                    it_account: None,
                }),
                ident: DeviceIdent {
                    serial: None,
                    device_id: "d".into(),
                },
                paths: paths.clone(),
                runner: runner.clone(),
                identity: None,
                current: current_rx,
                reapply: Default::default(),
                fetch_error: fetch_error_rx,
            };
            Lab {
                d,
                paths,
                runner,
                job,
                current,
                fetch_error,
                cx,
                now,
            }
        }

        fn advance(&self, by: Duration) {
            *self.now.lock().unwrap() += by;
        }

        fn root(&self) -> &Path {
            self.d.path()
        }

        /// NetworkManager says: not connected, a Wi-Fi device that is disconnected, no failure reason.
        fn offline(&self) {
            self.runner
                .respond(GENERAL, Output::ok("disconnected:none\n"));
            self.runner
                .respond(DEVICES, Output::ok("wifi:disconnected:wlan0\n"));
            self.runner
                .respond(REASON, Output::ok("GENERAL.REASON:0\n"));
        }

        fn online(&self) {
            self.runner.respond(GENERAL, Output::ok("connected:full\n"));
        }

        fn have_bundle(&self) {
            let mut m =
                Manifest::parse("version = 1\n[[group]]\nid = \"a\"\nname = \"a\"\n").unwrap();
            let config = mastersos_bundle::effective_config(&m, &m.configs[0]);
            self.current.send_replace(Some(Arc::new(CurrentGroup {
                version: 1,
                group: m.groups.remove(0),
                config,
                escrow_recipients: vec![],
            })));
        }

        fn have_chrome(&self) {
            let bin = self.root().join("usr/bin/google-chrome-stable");
            std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
            std::fs::write(bin, b"#!/bin/sh\n").unwrap();
        }

        async fn round(&self) {
            assert!(self.job.run(&self.cx).await.is_empty(), "nothing reported");
        }

        fn banner_path(&self) -> PathBuf {
            self.root().join(GDM_DCONF_DIR).join(BANNER_FILE)
        }

        fn banner(&self) -> Option<String> {
            std::fs::read_to_string(self.banner_path()).ok()
        }

        fn dconf_updates(&self) -> usize {
            self.runner
                .calls()
                .iter()
                .filter(|c| *c == "dconf update")
                .count()
        }
    }

    #[test]
    fn job_schedule() {
        let lab = Lab::new();
        assert_eq!(lab.job.name(), "status");
        assert_eq!(lab.job.every(), std::time::Duration::from_secs(30));
        assert!(lab.job.wake_on_signal());
        assert!(lab.job.wake_on_new_bundle());
        assert!(!lab.job.gates_first_report());
    }

    #[tokio::test]
    async fn job_holds_the_network_banner_in_the_grace_window() {
        let lab = Lab::fresh();
        lab.have_bundle();
        lab.have_chrome();
        lab.offline();
        lab.round().await;
        let s = read_status(&lab.paths).unwrap();
        assert_eq!(s.network, Net::Connecting);
        assert_eq!(s.message, None);
        assert!(
            lab.banner().is_none(),
            "no banner while the network may still come"
        );
        // Woken again just after the window ends, not 30 s later.
        lab.advance(Duration::from_secs(40));
        assert_eq!(lab.job.every(), Duration::from_secs(6));
        lab.advance(Duration::from_secs(5));
        lab.offline();
        lab.round().await;
        assert_eq!(read_status(&lab.paths).unwrap().network, Net::Disconnected);
        assert_eq!(
            lab.banner().unwrap(),
            banner::render_gdm_banner(Some(&format!("{NET}\nNot connected")))
        );
        assert_eq!(lab.job.every(), Duration::from_secs(30));
    }

    #[tokio::test]
    async fn job_shows_definite_problems_in_the_grace_window() {
        let lab = Lab::fresh();
        lab.runner
            .respond(GENERAL, Output::ok("disconnected:none\n"));
        lab.runner
            .respond(DEVICES, Output::ok("wifi:unavailable:wlan0\n"));
        lab.round().await;
        assert_eq!(read_status(&lab.paths).unwrap().network, Net::WifiOff);
        assert!(lab.banner().unwrap().contains(NET));
        assert_eq!(lab.job.every(), Duration::from_secs(30));
    }

    #[tokio::test]
    async fn job_connecting_suppresses_the_banner() {
        let lab = Lab::new();
        lab.have_bundle();
        lab.have_chrome();
        lab.runner.respond(GENERAL, Output::ok("connecting:none\n"));
        lab.runner
            .respond(DEVICES, Output::ok("wifi:connecting (configuring):wlan0\n"));
        lab.round().await;
        assert_eq!(read_status(&lab.paths).unwrap().network, Net::Connecting);
        assert!(lab.banner().is_none());
    }

    #[test]
    fn refresh_once_at_boot_holds_the_network_banner() {
        let lab = Lab::new();
        lab.have_chrome();
        lab.offline();
        refresh_once_at(
            &lab.paths,
            lab.runner.as_ref(),
            true,
            None,
            Some(Duration::from_secs(12)),
        );
        assert_eq!(read_status(&lab.paths).unwrap().network, Net::Connecting);
        assert!(lab.banner().is_none());
        lab.offline();
        refresh_once_at(
            &lab.paths,
            lab.runner.as_ref(),
            true,
            None,
            Some(Duration::from_secs(60)),
        );
        assert_eq!(read_status(&lab.paths).unwrap().network, Net::Disconnected);
        assert!(lab.banner().unwrap().contains(NET));
    }

    #[tokio::test]
    async fn job_writes_status_and_banner_when_offline() {
        let lab = Lab::new();
        lab.offline();
        lab.round().await;
        let s = read_status(&lab.paths).unwrap();
        assert_eq!(s.network, Net::Disconnected);
        assert_eq!(s.network_detail.as_deref(), Some("Not connected"));
        assert_eq!(s.settings, Settings::Waiting);
        assert_eq!(s.chrome, Browser::Installing);
        let text = lab.banner().unwrap();
        assert_eq!(
            text,
            banner::render_gdm_banner(Some(&format!("{NET}\nNot connected")))
        );
        assert_eq!(lab.dconf_updates(), 1);
    }

    #[tokio::test]
    async fn job_second_round_unchanged_writes_nothing() {
        let lab = Lab::new();
        lab.offline();
        lab.round().await;
        let status_file = lab.paths.public_dir.join(STATUS_FILE);
        let mtime = |p: &Path| std::fs::metadata(p).unwrap().modified().unwrap();
        let (s0, b0) = (mtime(&status_file), mtime(&lab.banner_path()));
        assert_eq!(lab.dconf_updates(), 1);
        // Coarse file-system timestamps would hide a rewrite.
        std::thread::sleep(std::time::Duration::from_millis(20));
        lab.offline();
        lab.round().await;
        assert_eq!(
            lab.dconf_updates(),
            1,
            "no dconf update when nothing changed"
        );
        assert_eq!(mtime(&status_file), s0);
        assert_eq!(mtime(&lab.banner_path()), b0);
    }

    /// `apply-local` wrote the banner but its `dconf update` failed: the resident job's first round compiles once even
    /// though the file on disk is already what it would write; later rounds do not.
    #[tokio::test]
    async fn job_first_round_compiles_once_when_banner_unchanged() {
        let lab = Lab::new();
        lab.offline();
        let failing = FakeRunner::new();
        failing.respond(GENERAL, Output::ok("disconnected:none\n"));
        failing.respond(DEVICES, Output::ok("wifi:disconnected:wlan0\n"));
        failing.respond(REASON, Output::ok("GENERAL.REASON:0\n"));
        failing.respond("dconf update", Output::fail(1, "boom"));
        refresh_once(&lab.paths, &failing, false, None);
        let before = lab.banner().expect("apply-local wrote the banner");
        lab.round().await;
        assert_eq!(lab.banner().unwrap(), before, "the banner is unchanged");
        assert_eq!(lab.dconf_updates(), 1);
        lab.offline();
        lab.round().await;
        assert_eq!(lab.dconf_updates(), 1);
    }

    #[tokio::test]
    async fn job_all_ok_removes_banner() {
        let lab = Lab::new();
        lab.offline();
        lab.round().await;
        assert!(lab.banner().is_some());
        lab.online();
        lab.have_bundle();
        lab.have_chrome();
        lab.round().await;
        let s = read_status(&lab.paths).unwrap();
        assert_eq!(
            s,
            Status::new(Net::Ok, None, Settings::Ok, None, Browser::Ok, None)
        );
        assert_eq!(s.message, None);
        assert!(lab.banner().is_none());
        assert_eq!(lab.dconf_updates(), 2);
    }

    #[tokio::test]
    async fn fetch_error_reaches_status() {
        let lab = Lab::new();
        lab.online();
        lab.have_chrome();
        lab.fetch_error.send_replace(Some(
            "error sending request for url (https://cloud.example/v1/bundle?after=3&wait=0): connection refused"
                .into(),
        ));
        lab.round().await;
        let s = read_status(&lab.paths).unwrap();
        assert_eq!(s.settings, Settings::Unreachable);
        let detail = s.settings_detail.unwrap();
        assert!(!detail.contains("after=3"), "{detail}");
        assert!(detail.contains("connection refused"), "{detail}");
        assert!(lab
            .banner()
            .unwrap()
            .contains("Waiting for school settings."));
        // A good fetch clears it again.
        lab.fetch_error.send_replace(None);
        lab.online();
        lab.round().await;
        let s = read_status(&lab.paths).unwrap();
        assert_eq!((s.settings, s.settings_detail), (Settings::Waiting, None));
    }

    #[tokio::test]
    async fn chrome_failure_from_result_json() {
        let lab = Lab::new();
        lab.online();
        lab.have_bundle();
        let work = lab.paths.state_dir.join("chrome");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::write(
            work.join("result.json"),
            br#"{"item":"chrome","ok":false,"detail":"download failed: 404"}"#,
        )
        .unwrap();
        lab.round().await;
        let s = read_status(&lab.paths).unwrap();
        assert_eq!(s.chrome, Browser::Failed);
        assert_eq!(s.chrome_detail.as_deref(), Some("download failed: 404"));
    }

    #[tokio::test]
    async fn job_does_not_overwrite_lock_banner() {
        let lab = Lab::new();
        let msg = "Return this computer to the IT office";
        let policy = LoginPolicy {
            methods: vec!["sso".into()],
            allowed_domains: vec![],
            admin_users: vec![],
            locked: true,
            lock_message: Some(msg.into()),
            from_bundle: true,
            kiosk_users: vec![],
            it_account: false,
            it_account_uid: None,
        };
        login::write_policy(&lab.paths, &policy).unwrap();
        // What the lock step wrote (it runs its own batched `dconf update`).
        assert!(banner::update(&lab.paths, banner::lock_text(&policy)).unwrap());
        lab.offline();
        lab.round().await;
        assert_eq!(lab.banner().unwrap(), banner::render_gdm_banner(Some(msg)));
        assert_eq!(
            lab.dconf_updates(),
            1,
            "only the one compile at agent start"
        );
        lab.offline();
        lab.round().await;
        assert_eq!(lab.dconf_updates(), 1, "the banner did not change");
        // The status itself is still written for the locked session's window.
        assert_eq!(read_status(&lab.paths).unwrap().network, Net::Disconnected);
    }

    #[test]
    fn known_ssids_reads_mastersos_files_only() {
        let d = tempfile::tempdir().unwrap();
        assert!(known_ssids(d.path()).is_empty(), "no directory");
        let dir = d.path().join("etc/NetworkManager/system-connections");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("mastersos-b.nmconnection"),
            // How `system::wifi` writes it: a byte list.
            "[connection]\nid=b\n[wifi]\nssid=83;99;104;111;111;108;\n[wifi-security]\npsk=secret\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("mastersos-a.nmconnection"),
            "[wifi]\nssid=Campus IoT\n",
        )
        .unwrap();
        std::fs::write(dir.join("mastersos-wired.nmconnection"), "[ethernet]\n").unwrap();
        std::fs::write(dir.join("home.nmconnection"), "[wifi]\nssid=Home\n").unwrap();
        std::fs::write(dir.join("mastersos-c.bak"), "[wifi]\nssid=Old\n").unwrap();
        assert_eq!(known_ssids(d.path()), vec!["Campus IoT", "School"]);
    }

    #[test]
    fn refresh_once_writes_status() {
        let lab = Lab::new();
        lab.offline();
        refresh_once(&lab.paths, lab.runner.as_ref(), false, Some("boom"));
        let s = read_status(&lab.paths).unwrap();
        assert_eq!(s.network, Net::Disconnected);
        assert_eq!(s.settings, Settings::Unreachable);
        assert!(lab.banner().unwrap().contains("No network"));
    }
}
