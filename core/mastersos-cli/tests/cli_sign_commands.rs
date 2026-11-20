//! `mastersos recovery read` against a mock server, with the global
//! `--server` and `--token-file`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use mastersos_bundle::kit::Kit;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A recovery key in the form machines escrow (test value).
const RECOVERY_KEY: &str =
    "cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv";

/// A home folder with an owner-only token file and a new school key file in it.
fn home_with_key() -> (tempfile::TempDir, PathBuf, PathBuf, Kit) {
    let home = tempfile::tempdir().unwrap();
    let token = home.path().join("token");
    mastersos_cli::platform::write_private(&token, b"t\n").unwrap();
    let key = home.path().join("school.kit");
    mastersos_cli::sign::kit::kit_new(&key).unwrap();
    let kit = mastersos_cli::sign::kit::load_kit(&key).unwrap();
    (home, token, key, kit)
}

/// A mock server that accepts the token.
async fn server() -> MockServer {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/admin/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({ "label": "cli:IT", "kind": "token", "scopes": ["read"], "school_name": "Alpha School" }),
        ))
        .mount(&s)
        .await;
    s
}

/// `mastersos --server <uri> --token-file <token> <args>` with `home` as the home folder.
async fn run(home: &Path, uri: &str, token: &Path, args: &[&str]) -> Output {
    let mut all: Vec<String> = vec![
        "--server".into(),
        uri.into(),
        "--token-file".into(),
        token.to_str().unwrap().into(),
    ];
    all.extend(args.iter().map(|a| a.to_string()));
    let home = home.to_owned();
    tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_mastersos"))
            .args(&all)
            .env("HOME", &home)
            .env("APPDATA", &home)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    })
    .await
    .unwrap()
}

fn text(o: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_read_opens_the_sealed_key_of_the_device() {
    let (home, token, key, kit) = home_with_key();
    let s = server().await;
    let tk = kit.trust_key();
    Mock::given(method("GET"))
        .and(path("/v1/admin/signing-keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "key_id": tk.id, "kind": "recovery", "alg": "ed25519", "label": "key",
            "fingerprint": mastersos_bundle::trust_fingerprint(&tk), "in_published_trust": true
        }])))
        .mount(&s)
        .await;
    let sealed = mastersos_bundle::escrow::seal(RECOVERY_KEY, &[kit.escrow_recipient()]).unwrap();
    Mock::given(method("GET"))
        .and(path("/v1/admin/devices/dev-42/recovery-keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "luks_uuid": "0b6c1e1a-0000-4000-8000-000000000001",
            "received_at": "2026-11-03T09:00:00Z",
            "serial": "SN-1",
            "first_for_luks": true,
            "recipients_fp": "ab".repeat(32),
            "recovery_key_age": sealed,
        }])))
        .mount(&s)
        .await;

    let o = run(
        home.path(),
        &s.uri(),
        &token,
        &[
            "recovery",
            "read",
            "dev-42",
            "--key-file",
            key.to_str().unwrap(),
        ],
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    assert!(out.contains(RECOVERY_KEY), "{out}");
    assert!(out.contains("serial=SN-1"), "{out}");
    assert!(out.contains("1 recovery key(s) opened."), "{out}");
    // The device asked for is the one in the request.
    assert!(s
        .received_requests()
        .await
        .unwrap()
        .iter()
        .any(|r| r.url.path() == "/v1/admin/devices/dev-42/recovery-keys"));
}
