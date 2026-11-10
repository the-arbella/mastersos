use std::fs;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Result;
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::runner::{Cmd, FakeRunner, Output, Runner};
use crate::safefs;

const REFRESH: &str = "systemctl reload-or-restart systemd-sysext.service";
const BODY: &[u8] = b"a .deb, more or less";

fn hex256(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

fn http() -> reqwest::Client {
    reqwest::Client::new()
}

fn open(p: &Path) -> OwnedFd {
    safefs::open_abs_dir(p, false).unwrap()
}

fn names(p: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(p)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

async fn serve(body: &[u8]) -> MockServer {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/x.deb"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
        .mount(&srv)
        .await;
    srv
}

#[test]
fn refresh_goes_through_pid1() {
    // the agent runs in its own mount namespace (PrivateTmp=yes): merging is left to PID 1's systemd-sysext.service
    assert_eq!(refresh_cmd().line(), REFRESH);
    assert_eq!(MERGE_LOCK, "/run/mastersos/sysext.lock");
}

#[tokio::test]
async fn download_checks_hash() {
    let srv = serve(BODY).await;
    let tmp = tempfile::tempdir().unwrap();
    let dir = open(tmp.path());
    let url = format!("{}/x.deb", srv.uri());
    let want = hex256(BODY);
    let got = download(
        &http(),
        &url,
        Some(&want),
        1024,
        Duration::from_secs(30),
        &dir,
        "x.deb",
        None,
    )
    .await
    .unwrap();
    let FetchOutcome::Fetched(f) = got else {
        panic!("expected a download")
    };
    assert_eq!(f.sha256, want);
    assert_eq!(fs::read(tmp.path().join("x.deb")).unwrap(), BODY);

    // without an expected hash: still downloaded, the hash is reported
    let FetchOutcome::Fetched(f) = download(
        &http(),
        &url,
        None,
        1024,
        Duration::from_secs(30),
        &dir,
        "y.deb",
        None,
    )
    .await
    .unwrap() else {
        panic!("expected a download")
    };
    assert_eq!(f.sha256, want);

    // a different hash: an error, and nothing is left behind (the earlier good files stay)
    let e = download(
        &http(),
        &url,
        Some(&hex256(b"something else")),
        1024,
        Duration::from_secs(30),
        &dir,
        "z.deb",
        None,
    )
    .await
    .unwrap_err();
    assert!(format!("{e:#}").contains("sha256"), "{e:#}");
    assert_eq!(names(tmp.path()), vec!["x.deb", "y.deb"]);
}

#[tokio::test]
async fn download_rejects_oversize() {
    let srv = serve(BODY).await;
    let tmp = tempfile::tempdir().unwrap();
    let dir = open(tmp.path());
    let e = download(
        &http(),
        &format!("{}/x.deb", srv.uri()),
        None,
        BODY.len() as u64 - 1,
        Duration::from_secs(30),
        &dir,
        "x.deb",
        None,
    )
    .await
    .unwrap_err();
    assert!(format!("{e:#}").contains("size limit"), "{e:#}");
    assert!(names(tmp.path()).is_empty(), "{:?}", names(tmp.path()));
    // exactly at the limit is fine
    assert!(download(
        &http(),
        &format!("{}/x.deb", srv.uri()),
        None,
        BODY.len() as u64,
        Duration::from_secs(30),
        &dir,
        "x.deb",
        None,
    )
    .await
    .is_ok());
}

#[tokio::test]
async fn download_non_success_status_is_an_error() {
    let srv = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let dir = open(tmp.path());
    let e = download(
        &http(),
        &format!("{}/x.deb", srv.uri()),
        None,
        1024,
        Duration::from_secs(30),
        &dir,
        "x.deb",
        None,
    )
    .await
    .unwrap_err();
    assert!(format!("{e:#}").contains("404"), "{e:#}");
    assert!(names(tmp.path()).is_empty());
}

#[tokio::test]
async fn download_304_not_modified() {
    let srv = MockServer::start().await;
    let etag = "\"v1-abc\"";
    let lm = "Tue, 10 Nov 2026 01:02:03 GMT";
    Mock::given(method("GET"))
        .and(path("/x.deb"))
        // raw values: wiremock's header() splits on commas, and an HTTP date has one
        .and(move |r: &wiremock::Request| {
            let h = |k: &str| {
                r.headers
                    .get(k)
                    .and_then(|v| v.to_str().ok())
                    .map(String::from)
            };
            h("If-None-Match").as_deref() == Some(etag)
                && h("If-Modified-Since").as_deref() == Some(lm)
        })
        .respond_with(ResponseTemplate::new(304))
        .with_priority(1)
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path("/x.deb"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("ETag", etag)
                .insert_header("Last-Modified", lm)
                .set_body_bytes(BODY.to_vec()),
        )
        .mount(&srv)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    let dir = open(tmp.path());
    let url = format!("{}/x.deb", srv.uri());
    let FetchOutcome::Fetched(first) = download(
        &http(),
        &url,
        None,
        1024,
        Duration::from_secs(30),
        &dir,
        "x.deb",
        None,
    )
    .await
    .unwrap() else {
        panic!("expected a download")
    };
    assert_eq!(
        first,
        Fetched {
            sha256: hex256(BODY),
            etag: Some(etag.into()),
            last_modified: Some(lm.into()),
        }
    );
    // the same validators back: 304, nothing written
    fs::write(tmp.path().join("x.deb"), b"cached").unwrap();
    let again = download(
        &http(),
        &url,
        None,
        1024,
        Duration::from_secs(30),
        &dir,
        "x.deb",
        Some(&first),
    )
    .await
    .unwrap();
    assert!(matches!(again, FetchOutcome::NotModified), "{again:?}");
    assert_eq!(fs::read(tmp.path().join("x.deb")).unwrap(), b"cached");
    assert_eq!(names(tmp.path()), vec!["x.deb"]);
    // a 304 without having asked conditionally is not success
    let srv2 = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(304))
        .mount(&srv2)
        .await;
    assert!(download(
        &http(),
        &format!("{}/x.deb", srv2.uri()),
        None,
        1024,
        Duration::from_secs(30),
        &dir,
        "w.deb",
        None,
    )
    .await
    .is_err());
}

#[tokio::test]
async fn download_with_calls_hook_only_once_bytes_arrive() {
    let srv = serve(BODY).await;
    Mock::given(method("GET"))
        .and(path("/missing.deb"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&srv)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    let dir = open(tmp.path());
    let mut calls = 0;
    assert!(download_with(
        &http(),
        &format!("{}/missing.deb", srv.uri()),
        None,
        1024,
        Duration::from_secs(30),
        &dir,
        "x.deb",
        None,
        &mut || {
            calls += 1;
            Ok(())
        },
    )
    .await
    .is_err());
    assert_eq!(calls, 0, "no bytes received: the hook does not run");
    let mut calls = 0;
    download_with(
        &http(),
        &format!("{}/x.deb", srv.uri()),
        Some(&hex256(BODY)),
        1024,
        Duration::from_secs(30),
        &dir,
        "x.deb",
        None,
        &mut || {
            calls += 1;
            Ok(())
        },
    )
    .await
    .unwrap();
    assert_eq!(calls, 1);
}

/// Wraps FakeRunner: at every refresh, records which entries of the extension directory exist and whether the merge
/// lock is held by someone (it must be: the caller holds it around the refresh).
struct Probe {
    fake: FakeRunner,
    dir: PathBuf,
    seen: Mutex<Vec<(Vec<String>, bool)>>,
}

impl Probe {
    fn new(dir: &Path) -> Probe {
        Probe {
            fake: FakeRunner::new(),
            dir: dir.into(),
            seen: Default::default(),
        }
    }

    fn seen(&self) -> Vec<(Vec<String>, bool)> {
        self.seen.lock().unwrap().clone()
    }
}

impl Runner for Probe {
    fn run(&self, cmd: &Cmd) -> Result<Output> {
        if cmd.line() == REFRESH {
            let held = lock_merge(Duration::ZERO).is_err();
            self.seen.lock().unwrap().push((names(&self.dir), held));
        }
        self.fake.run(cmd)
    }
}

fn tree(root: &Path, name: &str, marker: &[u8]) {
    fs::create_dir_all(root.join(name).join("opt/x")).unwrap();
    fs::write(root.join(name).join("opt/x/marker"), marker).unwrap();
}

fn marker(root: &Path, name: &str) -> Vec<u8> {
    fs::read(root.join(name).join("opt/x/marker")).unwrap()
}

#[test]
fn swap_first_install_renames() {
    let tmp = tempfile::tempdir().unwrap();
    tree(tmp.path(), "app-x.new", b"new");
    let r = Probe::new(tmp.path());
    swap_in(&r, &open(tmp.path()), "app-x", "app-x.new").unwrap();
    assert_eq!(names(tmp.path()), vec!["app-x"]);
    assert_eq!(marker(tmp.path(), "app-x"), b"new");
    assert_eq!(r.seen(), vec![(vec!["app-x".to_string()], true)]);
    assert_eq!(r.fake.calls(), vec![REFRESH]);
}

#[test]
fn swap_first_install_failure_removes_new() {
    let tmp = tempfile::tempdir().unwrap();
    tree(tmp.path(), "app-x.new", b"new");
    let r = Probe::new(tmp.path());
    r.fake.respond(REFRESH, Output::fail(1, "boom"));
    let e = swap_in(&r, &open(tmp.path()), "app-x", "app-x.new").unwrap_err();
    assert!(format!("{e:#}").contains("systemctl"), "{e:#}");
    // renamed back, merged again (succeeds), then the new tree is removed
    assert!(names(tmp.path()).is_empty(), "{:?}", names(tmp.path()));
    assert_eq!(
        r.seen(),
        vec![
            (vec!["app-x".to_string()], true),
            (vec!["app-x.new".to_string()], true)
        ]
    );
}

#[cfg(target_os = "linux")]
#[test]
fn swap_upgrade_exchanges_then_removes_old() {
    let tmp = tempfile::tempdir().unwrap();
    tree(tmp.path(), "app-x", b"old");
    tree(tmp.path(), "app-x.new", b"new");
    let r = Probe::new(tmp.path());
    swap_in(&r, &open(tmp.path()), "app-x", "app-x.new").unwrap();
    assert_eq!(names(tmp.path()), vec!["app-x"]);
    assert_eq!(marker(tmp.path(), "app-x"), b"new");
    // the old tree is still there while merging (it may be the merged layer), removed only after success
    assert_eq!(
        r.seen(),
        vec![(vec!["app-x".to_string(), "app-x.new".to_string()], true)]
    );
}

#[cfg(target_os = "linux")]
#[test]
fn swap_refresh_failure_rolls_back() {
    let tmp = tempfile::tempdir().unwrap();
    tree(tmp.path(), "app-x", b"old");
    tree(tmp.path(), "app-x.new", b"new");
    let r = Probe::new(tmp.path());
    r.fake.respond(REFRESH, Output::fail(1, "boom"));
    let e = swap_in(&r, &open(tmp.path()), "app-x", "app-x.new").unwrap_err();
    assert!(format!("{e:#}").contains("systemctl"), "{e:#}");
    assert_eq!(names(tmp.path()), vec!["app-x"], "the .new tree is removed");
    assert_eq!(marker(tmp.path(), "app-x"), b"old", "the old tree is back");
    assert_eq!(r.fake.calls(), vec![REFRESH, REFRESH]);
    assert!(r.seen().iter().all(|(_, held)| *held));
}

#[cfg(target_os = "linux")]
#[test]
fn swap_back_merge_failure_keeps_new_for_next_round() {
    let tmp = tempfile::tempdir().unwrap();
    tree(tmp.path(), "app-x", b"old");
    tree(tmp.path(), "app-x.new", b"new");
    let r = Probe::new(tmp.path());
    r.fake.respond(REFRESH, Output::fail(1, "boom"));
    r.fake.respond(REFRESH, Output::fail(1, "boom again"));
    assert!(swap_in(&r, &open(tmp.path()), "app-x", "app-x.new").is_err());
    // the .new tree may be half merged: kept, and the next round merges before removing it
    assert_eq!(names(tmp.path()), vec!["app-x", "app-x.new"]);
    assert_eq!(marker(tmp.path(), "app-x"), b"old");
    assert!(recover_leftover(&r, &open(tmp.path()), "app-x.new").unwrap());
    assert_eq!(names(tmp.path()), vec!["app-x"]);
    assert_eq!(r.fake.calls(), vec![REFRESH, REFRESH, REFRESH]);
    assert_eq!(
        r.seen().last().unwrap(),
        &(vec!["app-x".to_string(), "app-x.new".to_string()], true),
        "merged first, removed afterwards"
    );
    // nothing left over: no refresh
    assert!(!recover_leftover(&r, &open(tmp.path()), "app-x.new").unwrap());
    assert_eq!(r.fake.calls().len(), 3);
}

#[test]
fn remove_ext_refreshes_then_deletes() {
    let tmp = tempfile::tempdir().unwrap();
    tree(tmp.path(), "app-x", b"old");
    tree(tmp.path(), "app-y", b"other");
    let r = Probe::new(tmp.path());
    remove_ext(&r, &open(tmp.path()), "app-x").unwrap();
    assert_eq!(names(tmp.path()), vec!["app-y"]);
    // merged without it first (renamed away, still on disk), deleted afterwards
    assert_eq!(
        r.seen(),
        vec![(vec!["app-x.old".to_string(), "app-y".to_string()], true)]
    );
    // already gone: nothing to do
    remove_ext(&r, &open(tmp.path()), "app-x").unwrap();
    assert_eq!(r.fake.calls(), vec![REFRESH]);
}

#[test]
fn remove_ext_failure_puts_it_back() {
    let tmp = tempfile::tempdir().unwrap();
    tree(tmp.path(), "app-x", b"old");
    let r = Probe::new(tmp.path());
    r.fake.respond(REFRESH, Output::fail(1, "boom"));
    assert!(remove_ext(&r, &open(tmp.path()), "app-x").is_err());
    assert_eq!(names(tmp.path()), vec!["app-x"]);
    assert_eq!(marker(tmp.path(), "app-x"), b"old");
    assert_eq!(r.fake.calls(), vec![REFRESH, REFRESH]);
}

#[test]
fn remove_ext_merges_before_clearing_a_leftover_old() {
    // an earlier removal was cut between the rename and the merge: .old may be the merged layer
    let tmp = tempfile::tempdir().unwrap();
    tree(tmp.path(), "app-x.old", b"old");
    let r = Probe::new(tmp.path());
    remove_ext(&r, &open(tmp.path()), "app-x").unwrap();
    assert!(names(tmp.path()).is_empty());
    assert_eq!(r.seen(), vec![(vec!["app-x.old".to_string()], true)]);
}

#[test]
fn merge_lock_waits_then_times_out() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("sysext.lock");
    let held = lock_file(&p, Duration::ZERO).unwrap();
    let t = std::time::Instant::now();
    let e = lock_file(&p, Duration::from_millis(300)).unwrap_err();
    assert!(t.elapsed() >= Duration::from_millis(300));
    assert!(format!("{e:#}").contains("merge lock"), "{e:#}");
    // released when the holder's fd is dropped, also while someone waits
    let waiter = std::thread::spawn(move || lock_file(&p, Duration::from_secs(10)).map(drop));
    std::thread::sleep(Duration::from_millis(200));
    drop(held);
    waiter.join().unwrap().unwrap();
}
