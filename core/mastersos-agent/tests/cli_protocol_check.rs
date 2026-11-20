//! `mastersos-agent protocol-check` as a process: output shape, exit codes, no secrets printed.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use mastersos_bundle::kit::Kit;
use mastersos_bundle::{pack, Contents, Ed25519Signer, Seed, TrustKey};
use ring::rand::{SecureRandom, SystemRandom};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SCHOOL: &str = "0b6c1a52-3d1e-4f7a-9c2b-1a2b3c4d5e6f";
const LUKS_UUID: &str = "f9fd9985-7280-4c3d-bab4-f132ac2336f2";
const FETCH_TOKEN: &str = "cli-fetch-token-0123456789";

/// A throwaway recovery key: 8 groups of 8 random modhex characters.
fn recovery_key() -> String {
    const MODHEX: &[u8] = b"cbdefghijklnrtuv";
    let mut raw = [0u8; 64];
    SystemRandom::new().fill(&mut raw).unwrap();
    let chars: Vec<char> = raw
        .iter()
        .map(|b| MODHEX[usize::from(b & 0x0f)] as char)
        .collect();
    chars
        .chunks(8)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

fn archive(trust: &[TrustKey], recipients: &[String], by: &Ed25519Signer) -> Vec<u8> {
    let mut text = format!("version = 3\n\n[school]\nid = \"{SCHOOL}\"\n");
    text += &format!(
        "escrow_recipients = [{}]\n",
        recipients
            .iter()
            .map(|r| format!("\"{r}\""))
            .collect::<Vec<_>>()
            .join(", ")
    );
    for k in trust {
        text += &format!(
            "\n[[trust]]\nid = \"{}\"\nalg = \"{}\"\npublic_key = \"{}\"\n",
            k.id,
            k.alg.as_str(),
            k.public_key
        );
    }
    text += "\n[[group]]\nid = \"default\"\nname = \"x\"\n";
    let c = Contents {
        manifest_text: text,
        files: Default::default(),
    };
    pack(&c, by).unwrap()
}

/// A server with one version (3); `bundle_status` answers the first bundle call.
async fn server(a: &Kit, bundle_status: u16) -> MockServer {
    let srv = MockServer::start().await;
    let first = if bundle_status == 200 {
        ResponseTemplate::new(200)
            .insert_header("X-Mastersos-Version", "3")
            .set_body_bytes(archive(
                &[a.trust_key()],
                &[a.escrow_recipient()],
                &a.signer(),
            ))
    } else {
        ResponseTemplate::new(bundle_status)
    };
    Mock::given(method("GET"))
        .and(path("/api/device/v1/bundle"))
        .and(query_param("after", "2"))
        .respond_with(first)
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/device/v1/bundle"))
        .and(query_param("after", "3"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/device/v1/heartbeat"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&srv)
        .await;
    for route in ["status", "escrow"] {
        Mock::given(method("POST"))
            .and(path(format!("/api/device/v1/{route}")))
            .respond_with(ResponseTemplate::new(204))
            .mount(&srv)
            .await;
    }
    srv
}

struct Files {
    _tmp: tempfile::TempDir,
    seed: PathBuf,
    dir: PathBuf,
    key: PathBuf,
}

fn files(url: &str, a: &Kit, key: &str) -> Files {
    let tmp = tempfile::tempdir().unwrap();
    let seed = Seed {
        server_url: url.into(),
        trust: vec![a.trust_key()],
        fetch_token: Some(FETCH_TOKEN.into()),
        group: None,
        oidc: None,
        min_version: Some(3),
        school_id: Some(SCHOOL.into()),
        wifi: vec![],
        school_name: None,
        it_account: None,
    };
    let seed_path = tmp.path().join("seed.toml");
    std::fs::write(&seed_path, seed.to_toml()).unwrap();
    let key_path = tmp.path().join("recovery-key");
    std::fs::write(&key_path, format!("{key}\n")).unwrap();
    Files {
        seed: seed_path,
        dir: tmp.path().join("dir"),
        key: key_path,
        _tmp: tmp,
    }
}

async fn run(args: Vec<std::ffi::OsString>) -> Output {
    tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_mastersos-agent"))
            .arg("protocol-check")
            .args(args)
            .output()
            .unwrap()
    })
    .await
    .unwrap()
}

fn base(f: &Files) -> Vec<std::ffi::OsString> {
    vec![
        "--seed".into(),
        f.seed.clone().into(),
        "--state".into(),
        f.dir.clone().into(),
    ]
}

fn identity_secret(dir: &Path) -> String {
    let text = std::fs::read_to_string(dir.join("seed-partition/identity.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    v["escrow_secret"].as_str().unwrap().to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn protocol_check_prints_one_json_object_and_exits_0() {
    let a = Kit::generate();
    let srv = server(&a, 200).await;
    let f = files(&srv.uri(), &a, &recovery_key());
    let mut args = base(&f);
    args.push("--json".into());
    let out = run(args).await;
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.ends_with('\n') && text.matches('\n').count() == 1,
        "{text:?}"
    );
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["protocol_check"], 1);
    assert_eq!(v["ok"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn protocol_check_exits_1_when_a_call_fails() {
    let a = Kit::generate();
    let srv = server(&a, 500).await;
    let key = recovery_key();
    let f = files(&srv.uri(), &a, &key);
    let mut args = base(&f);
    args.extend([
        "--recovery-key".into(),
        f.key.clone().into(),
        "--luks-uuid".into(),
        LUKS_UUID.into(),
    ]);
    let out = run(args).await;
    assert_eq!(out.status.code(), Some(1));
    // the failure details are where a leak would show
    let secret = identity_secret(&f.dir);
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    for s in [key.as_str(), secret.as_str(), FETCH_TOKEN] {
        assert!(!all.contains(s), "output holds a secret");
    }
    let text = String::from_utf8(out.stdout).unwrap();
    let line = text.lines().find(|l| l.starts_with("bundle ")).unwrap();
    // the route column holds the method and the path, e.g. `GET /api/device/v1/bundle?after=2`
    assert!(line.contains(" 500 FAIL "), "{line}");
}

#[tokio::test(flavor = "multi_thread")]
async fn luks_uuid_without_recovery_key_is_a_usage_error() {
    let a = Kit::generate();
    let f = files("https://server.example", &a, &recovery_key());
    let mut args = base(&f);
    args.extend(["--luks-uuid".into(), LUKS_UUID.into()]);
    let out = run(args).await;
    assert_eq!(out.status.code(), Some(2));
    let mut args = base(&f);
    args.extend(["--recovery-key".into(), f.key.clone().into()]);
    assert_eq!(run(args).await.status.code(), Some(2));
}

#[tokio::test(flavor = "multi_thread")]
async fn protocol_check_escrows_a_throwaway_key() {
    let a = Kit::generate();
    let srv = server(&a, 200).await;
    let key = recovery_key();
    let f = files(&srv.uri(), &a, &key);
    let mut args = base(&f);
    args.extend([
        "--recovery-key".into(),
        f.key.clone().into(),
        "--luks-uuid".into(),
        LUKS_UUID.into(),
    ]);
    let out = run(args).await;
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout.clone()).unwrap();
    let line = stdout.lines().find(|l| l.starts_with("escrow ")).unwrap();
    assert!(line.contains(" 204 ok "), "{line}");
    let reqs = srv.received_requests().await.unwrap();
    assert!(
        reqs.iter().any(|r| r.url.path() == "/api/device/v1/escrow"),
        "the escrow request did not reach the mock"
    );
    let secret = identity_secret(&f.dir);
    let all = format!("{stdout}{}", String::from_utf8_lossy(&out.stderr));
    for s in [key.as_str(), secret.as_str(), FETCH_TOKEN] {
        assert!(!all.contains(s), "output holds a secret");
    }
}
