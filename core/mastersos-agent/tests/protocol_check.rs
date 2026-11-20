//! `protocol-check`: one network cycle against a mock server, reported call by call.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chrono::Utc;
use mastersos_agent::protocol_check::{run_check, Call, CheckInput, CheckReport};
use mastersos_agent::report::SUPPORTED_FEATURES;
use mastersos_bundle::kit::Kit;
use mastersos_bundle::{
    content_digest, heartbeat_message, pack, Contents, Ed25519Signer, Heartbeat,
    HeartbeatStatement, KeyAlg, Seed, SignatureFile, Signer, TrustKey,
};
use ring::rand::{SecureRandom, SystemRandom};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// `writes_nothing_outside_dir` points HOME and TMPDIR elsewhere: every test of this file holds
/// this lock, so no other test creates a temporary directory meanwhile.
static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const SCHOOL: &str = "0b6c1a52-3d1e-4f7a-9c2b-1a2b3c4d5e6f";
const LUKS_UUID: &str = "f9fd9985-7280-4c3d-bab4-f132ac2336f2";
const OLD_TOKEN: &str = "old-fetch-token";
const NEW_TOKEN: &str = "new-fetch-token";
const STALE: &str = "x-mastersos-fetch-token";

/// A throwaway recovery key: 8 groups of 8 random modhex characters.
fn recovery_key() -> String {
    const MODHEX: &[u8] = b"cbdefghijklnrtuv";
    let mut raw = [0u8; 64];
    SystemRandom::new().fill(&mut raw).unwrap();
    let chars: Vec<char> = raw
        .iter()
        .map(|b| MODHEX[usize::from(b & 0x0f)] as char)
        .collect();
    let key = chars
        .chunks(8)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-");
    assert!(mastersos_bundle::is_recovery_key(&key));
    key
}

fn manifest(version: u64, trust: &[TrustKey], recipients: &[String]) -> String {
    let mut text = format!("version = {version}\n\n[school]\nid = \"{SCHOOL}\"\n");
    if !recipients.is_empty() {
        text += &format!(
            "escrow_recipients = [{}]\n",
            recipients
                .iter()
                .map(|r| format!("\"{r}\""))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    for k in trust {
        text += &format!(
            "\n[[trust]]\nid = \"{}\"\nalg = \"{}\"\npublic_key = \"{}\"\n",
            k.id,
            k.alg.as_str(),
            k.public_key
        );
    }
    text += "\n[[group]]\nid = \"default\"\nname = \"x\"\n";
    text
}

/// A signed archive and its content digest (hex).
fn bundle(
    version: u64,
    trust: &[TrustKey],
    recipients: &[String],
    by: &Ed25519Signer,
) -> (Vec<u8>, String) {
    let c = Contents {
        manifest_text: manifest(version, trust, recipients),
        files: Default::default(),
    };
    let digest: String = content_digest(&c)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    (pack(&c, by).unwrap(), digest)
}

fn heartbeat(version: u64, digest_hex: &str, by: &Ed25519Signer) -> String {
    let now = Utc::now().timestamp();
    let statement = HeartbeatStatement {
        version,
        digest_hex: digest_hex.into(),
        issued_at: now - 60,
        not_after: now + 20 * 86_400,
    };
    let signature = SignatureFile {
        key_id: by.key_id().into(),
        alg: KeyAlg::Ed25519,
        sig: STANDARD.encode(by.sign(&heartbeat_message(&statement))),
        authenticator_data: None,
        client_data_json: None,
    };
    Heartbeat {
        statement,
        signature,
    }
    .to_toml()
}

fn seed(url: &str, trust: Vec<TrustKey>, min_version: Option<u64>) -> Seed {
    Seed {
        server_url: url.into(),
        trust,
        fetch_token: Some(OLD_TOKEN.into()),
        group: None,
        oidc: None,
        min_version,
        school_id: Some(SCHOOL.into()),
        wifi: vec![],
        school_name: None,
        it_account: None,
    }
}

/// The inputs of a run: the seed and recovery key files live beside DIR, not in it.
struct Setup {
    _tmp: tempfile::TempDir,
    input: CheckInput,
    files: PathBuf,
}

fn setup(s: &Seed, recovery: Option<&str>) -> Setup {
    let tmp = tempfile::tempdir().unwrap();
    let files = tmp.path().join("in");
    std::fs::create_dir(&files).unwrap();
    std::fs::write(files.join("seed.toml"), s.to_toml()).unwrap();
    let recovery_key = recovery.map(|k| {
        let p = files.join("recovery-key");
        std::fs::write(&p, format!("{k}\n")).unwrap();
        p
    });
    let input = CheckInput {
        seed: files.join("seed.toml"),
        dir: tmp.path().join("dir"),
        luks_uuid: recovery_key.as_ref().map(|_| LUKS_UUID.to_string()),
        recovery_key,
    };
    Setup {
        _tmp: tmp,
        input,
        files,
    }
}

/// An answer that says the token it was sent with is retired.
fn stale(code: u16) -> ResponseTemplate {
    ResponseTemplate::new(code).insert_header(STALE, "stale")
}

fn calls(r: &CheckReport) -> Vec<(&str, Option<&str>, Option<u16>, bool)> {
    r.calls
        .iter()
        .map(|c| (c.step.as_str(), c.route.as_deref(), c.status, c.ok))
        .collect()
}

fn step<'a>(r: &'a CheckReport, name: &str) -> &'a Call {
    r.calls
        .iter()
        .find(|c| c.step == name)
        .unwrap_or_else(|| panic!("no {name} entry in {:?}", calls(r)))
}

fn received<'a>(reqs: &'a [Request], p: &str) -> Vec<&'a Request> {
    reqs.iter().filter(|r| r.url.path() == p).collect()
}

fn header_of(r: &Request, name: &str) -> String {
    r.headers
        .get(name)
        .unwrap_or_else(|| panic!("no {name} header"))
        .to_str()
        .unwrap()
        .to_string()
}

/// Kit A signs v3 (trust A, recipients A); v4 rotates to kit B (trust and recipients B), signed
/// by A, and B signs the heartbeat of v4. Every answer to the old token says it is stale.
async fn full_server(a: &Kit, b: &Kit) -> MockServer {
    let srv = MockServer::start().await;
    let (v3, _) = bundle(3, &[a.trust_key()], &[a.escrow_recipient()], &a.signer());
    let (v4, d4) = bundle(4, &[b.trust_key()], &[b.escrow_recipient()], &a.signer());
    for (after, archive, version) in [("2", v3, "3"), ("3", v4, "4")] {
        Mock::given(method("GET"))
            .and(path("/api/device/v1/bundle"))
            .and(query_param("after", after))
            .respond_with(
                stale(200)
                    .insert_header("X-Mastersos-Version", version)
                    .set_body_bytes(archive),
            )
            .mount(&srv)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/api/device/v1/bundle"))
        .and(query_param("after", "4"))
        .respond_with(stale(204))
        .mount(&srv)
        .await;
    let hb = heartbeat(4, &d4, &b.signer());
    Mock::given(method("GET"))
        .and(path("/api/device/v1/heartbeat"))
        .and(header(
            "authorization",
            format!("Bearer {OLD_TOKEN}").as_str(),
        ))
        .respond_with(stale(200).set_body_string(hb.clone()))
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/device/v1/heartbeat"))
        .and(header(
            "authorization",
            format!("Bearer {NEW_TOKEN}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string(hb))
        .mount(&srv)
        .await;
    for route in ["status", "escrow"] {
        Mock::given(method("POST"))
            .and(path(format!("/api/device/v1/{route}")))
            .and(header(
                "authorization",
                format!("Bearer {OLD_TOKEN}").as_str(),
            ))
            .respond_with(stale(204))
            .mount(&srv)
            .await;
    }
    Mock::given(method("POST"))
        .and(path("/api/device/v1/fetch-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "fetch_token": NEW_TOKEN })),
        )
        .mount(&srv)
        .await;
    srv
}

#[tokio::test]
async fn full_cycle_against_a_mock_server() {
    let _l = LOCK.lock().await;
    let (a, b) = (Kit::generate(), Kit::generate());
    let srv = full_server(&a, &b).await;
    let key = recovery_key();
    let s = setup(&seed(&srv.uri(), vec![a.trust_key()], Some(3)), Some(&key));
    let r = run_check(&s.input, Utc::now()).await;

    let (st, es, ft) = (
        Some("POST /api/device/v1/status"),
        Some("POST /api/device/v1/escrow"),
        Some("POST /api/device/v1/fetch-token"),
    );
    let hb = Some("GET /api/device/v1/heartbeat");
    assert_eq!(
        calls(&r),
        vec![
            ("seed_import", None, None, true),
            (
                "bundle",
                Some("GET /api/device/v1/bundle?after=2"),
                Some(200),
                true
            ),
            (
                "bundle",
                Some("GET /api/device/v1/bundle?after=3"),
                Some(200),
                true
            ),
            (
                "bundle",
                Some("GET /api/device/v1/bundle?after=4"),
                Some(204),
                true
            ),
            ("heartbeat", hb, Some(200), true),
            ("status", st, Some(204), true),
            ("escrow", es, Some(204), true),
            ("fetch_token", ft, Some(200), true),
            ("fetch_token_check", hb, Some(200), true),
        ],
        "{r:#?}"
    );
    assert!(r.ok);
    assert_eq!(r.protocol_check, 1);
    assert_eq!(r.server_url, srv.uri());
    assert_eq!(r.calls[1].version, Some(3));
    assert_eq!(r.calls[2].version, Some(4));
    assert_eq!(step(&r, "heartbeat").version, Some(4));
    assert!(r.calls.iter().all(|c| c.error_code.is_none()));

    let reqs = srv.received_requests().await.unwrap();
    // Status: both device headers, the device id of the report, the features.
    let status = received(&reqs, "/api/device/v1/status");
    assert_eq!(status.len(), 1);
    let device = r.device_id.clone().unwrap();
    assert_eq!(header_of(status[0], "x-mastersos-device"), device);
    let secret = header_of(status[0], "x-mastersos-device-secret");
    let body: serde_json::Value = serde_json::from_slice(&status[0].body).unwrap();
    assert_eq!(body["device_id"], device.as_str());
    assert_eq!(
        body["manifest_features"],
        serde_json::json!(SUPPORTED_FEATURES)
    );
    assert_eq!(body["bundle_version"], 4);

    // Escrow: exactly the six keys, a valid sealed request to v4's recipients.
    let escrow = received(&reqs, "/api/device/v1/escrow");
    assert_eq!(escrow.len(), 1);
    let v: serde_json::Value = serde_json::from_slice(&escrow[0].body).unwrap();
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "device_id",
            "escrow_secret",
            "luks_uuid",
            "recipients_fp",
            "recovery_key_age",
            "serial"
        ]
    );
    let req = mastersos_bundle::EscrowRequest::from_json(&escrow[0].body).unwrap();
    req.validate().unwrap();
    assert_eq!(req.device_id, device);
    assert_eq!(req.luks_uuid, LUKS_UUID);
    assert_eq!(req.escrow_secret, secret);
    assert_eq!(
        req.recipients_fp,
        mastersos_bundle::recipients_fp(&[b.escrow_recipient()])
    );
    assert_eq!(
        mastersos_bundle::x25519_stanza_count(&req.recovery_key_age),
        Some(1)
    );
    assert!(!String::from_utf8_lossy(&escrow[0].body).contains(&key));

    // The renewal: the token saved in both places, the check used it.
    let dir = &s.input.dir;
    for d in ["state", "seed-partition"] {
        assert_eq!(
            std::fs::read_to_string(dir.join(d).join("fetch-token")).unwrap(),
            NEW_TOKEN
        );
    }
    let last = received(&reqs, "/api/device/v1/heartbeat");
    assert_eq!(
        header_of(last.last().unwrap(), "authorization"),
        format!("Bearer {NEW_TOKEN}")
    );

    // No secret in the report.
    let json = serde_json::to_string(&r).unwrap();
    for s in [secret.as_str(), key.as_str(), OLD_TOKEN, NEW_TOKEN] {
        assert!(!json.contains(s), "the report carries a secret: {json}");
    }
}

#[test]
fn json_shape_is_pinned() {
    let call = |step: &str,
                route: Option<&str>,
                status: Option<u16>,
                skipped: bool,
                version: Option<u64>,
                detail: &str| Call {
        step: step.into(),
        route: route.map(String::from),
        status,
        ok: true,
        skipped,
        error_code: None,
        version,
        detail: detail.into(),
    };
    let r = CheckReport {
        protocol_check: 1,
        agent_version: "0.2.0".into(),
        server_url: "https://server.example".into(),
        device_id: Some("5b1e…".into()),
        ok: true,
        calls: vec![
            call(
                "seed_import",
                None,
                None,
                false,
                None,
                "imported; trust rk-1a2b3c4d; min_version 3",
            ),
            call(
                "bundle",
                Some("GET /api/device/v1/bundle?after=2"),
                Some(200),
                false,
                Some(3),
                "verified; signed by rk-1a2b3c4d",
            ),
            call(
                "bundle",
                Some("GET /api/device/v1/bundle?after=3"),
                Some(204),
                false,
                None,
                "no newer version",
            ),
            call(
                "heartbeat",
                Some("GET /api/device/v1/heartbeat"),
                Some(200),
                false,
                Some(3),
                "verified; not_after 2026-12-20T09:00:00Z",
            ),
            call(
                "status",
                Some("POST /api/device/v1/status"),
                Some(204),
                false,
                None,
                "",
            ),
            call(
                "escrow",
                Some("POST /api/device/v1/escrow"),
                Some(204),
                false,
                None,
                "",
            ),
            call(
                "fetch_token",
                None,
                None,
                true,
                None,
                "the token is not stale",
            ),
        ],
    };
    let pinned = r#"{
  "protocol_check": 1,
  "agent_version": "0.2.0",
  "server_url": "https://server.example",
  "device_id": "5b1e…",
  "ok": true,
  "calls": [
    {"step": "seed_import", "route": null, "status": null, "ok": true, "skipped": false, "error_code": null, "version": null, "detail": "imported; trust rk-1a2b3c4d; min_version 3"},
    {"step": "bundle", "route": "GET /api/device/v1/bundle?after=2", "status": 200, "ok": true, "skipped": false, "error_code": null, "version": 3, "detail": "verified; signed by rk-1a2b3c4d"},
    {"step": "bundle", "route": "GET /api/device/v1/bundle?after=3", "status": 204, "ok": true, "skipped": false, "error_code": null, "version": null, "detail": "no newer version"},
    {"step": "heartbeat", "route": "GET /api/device/v1/heartbeat", "status": 200, "ok": true, "skipped": false, "error_code": null, "version": 3, "detail": "verified; not_after 2026-12-20T09:00:00Z"},
    {"step": "status", "route": "POST /api/device/v1/status", "status": 204, "ok": true, "skipped": false, "error_code": null, "version": null, "detail": ""},
    {"step": "escrow", "route": "POST /api/device/v1/escrow", "status": 204, "ok": true, "skipped": false, "error_code": null, "version": null, "detail": ""},
    {"step": "fetch_token", "route": null, "status": null, "ok": true, "skipped": true, "error_code": null, "version": null, "detail": "the token is not stale"}
  ]
}"#;
    let want: serde_json::Value = serde_json::from_str(pinned).unwrap();
    assert_eq!(serde_json::to_value(&r).unwrap(), want);
    // The key order too: the compact text of the pinned JSON, byte for byte.
    let compact = pinned
        .lines()
        .map(str::trim)
        .collect::<String>()
        .replace("\": ", "\":")
        .replace(", \"", ",\"");
    assert_eq!(serde_json::to_string(&r).unwrap(), compact);
}

/// v3 (recipients A, signed by A) after 2, 204 after 3, heartbeat 204, status 204.
async fn simple_server(by: &Ed25519Signer, a: &Kit, recipients: bool) -> MockServer {
    let srv = MockServer::start().await;
    let r = if recipients {
        vec![a.escrow_recipient()]
    } else {
        vec![]
    };
    let (v3, _) = bundle(3, &[a.trust_key()], &r, by);
    Mock::given(method("GET"))
        .and(path("/api/device/v1/bundle"))
        .and(query_param("after", "2"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Mastersos-Version", "3")
                .set_body_bytes(v3),
        )
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
    Mock::given(method("POST"))
        .and(path("/api/device/v1/status"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&srv)
        .await;
    srv
}

#[tokio::test]
async fn bundle_signed_by_an_unknown_key_fails_the_bundle_step() {
    let _l = LOCK.lock().await;
    let a = Kit::generate();
    let srv = simple_server(&Kit::generate().signer(), &a, true).await;
    let s = setup(&seed(&srv.uri(), vec![a.trust_key()], Some(3)), None);
    let r = run_check(&s.input, Utc::now()).await;
    let b = step(&r, "bundle");
    assert!(!b.ok);
    assert_eq!(b.error_code.as_deref(), Some("verify_failed"));
    assert_eq!(b.status, Some(200));
    assert_eq!(b.version, None);
    assert_eq!(r.calls.iter().filter(|c| c.step == "bundle").count(), 1);
    step(&r, "heartbeat");
    assert!(step(&r, "status").ok);
    assert!(!r.ok);
}

#[tokio::test]
async fn escrow_skipped_without_a_recovery_key() {
    let _l = LOCK.lock().await;
    let a = Kit::generate();
    let srv = simple_server(&a.signer(), &a, true).await;
    let s = setup(&seed(&srv.uri(), vec![a.trust_key()], Some(3)), None);
    let r = run_check(&s.input, Utc::now()).await;
    let e = step(&r, "escrow");
    assert!(e.ok && e.skipped, "{e:?}");
    assert_eq!(e.route, None);
    let t = step(&r, "fetch_token");
    assert!(t.ok && t.skipped, "{t:?}");
    assert_eq!(t.detail, "the token is not stale");
    assert!(r.calls.iter().all(|c| c.step != "fetch_token_check"));
    assert!(r.ok, "{r:#?}");
}

#[tokio::test]
async fn escrow_without_recipients_is_not_ok() {
    let _l = LOCK.lock().await;
    let a = Kit::generate();
    let srv = simple_server(&a.signer(), &a, false).await;
    let key = recovery_key();
    let s = setup(&seed(&srv.uri(), vec![a.trust_key()], Some(3)), Some(&key));
    let r = run_check(&s.input, Utc::now()).await;
    let e = step(&r, "escrow");
    assert!(!e.ok && !e.skipped, "{e:?}");
    assert_eq!(e.error_code.as_deref(), Some("verify_failed"));
    assert_eq!(e.detail, "the settings name no escrow recipients");
    assert_eq!(e.route, None);
    assert!(!r.ok);
    let reqs = srv.received_requests().await.unwrap();
    assert!(received(&reqs, "/api/device/v1/escrow").is_empty());
}

#[tokio::test]
async fn not_available_and_server_errors_carry_the_code() {
    let _l = LOCK.lock().await;
    let a = Kit::generate();
    let srv = MockServer::start().await;
    let (v3, _) = bundle(3, &[a.trust_key()], &[a.escrow_recipient()], &a.signer());
    Mock::given(method("GET"))
        .and(path("/api/device/v1/bundle"))
        .and(query_param("after", "2"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Mastersos-Version", "3")
                .set_body_bytes(v3),
        )
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
    let err = |code: &str| serde_json::json!({ "error": { "code": code, "message": "no", "details": {} } });
    Mock::given(method("POST"))
        .and(path("/api/device/v1/status"))
        .respond_with(ResponseTemplate::new(401).set_body_json(err("device_auth_missing")))
        .mount(&srv)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/device/v1/escrow"))
        .respond_with(ResponseTemplate::new(404).set_body_json(err("not_available")))
        .mount(&srv)
        .await;
    let key = recovery_key();
    let s = setup(&seed(&srv.uri(), vec![a.trust_key()], Some(3)), Some(&key));
    let r = run_check(&s.input, Utc::now()).await;
    let st = step(&r, "status");
    assert_eq!(
        (st.ok, st.status, st.error_code.as_deref()),
        (false, Some(401), Some("device_auth_missing"))
    );
    assert_eq!(st.route.as_deref(), Some("POST /api/device/v1/status"));
    let e = step(&r, "escrow");
    assert_eq!(
        (e.ok, e.status, e.error_code.as_deref()),
        (false, Some(404), Some("not_available"))
    );
    assert!(!r.ok);
}

#[tokio::test]
async fn rerun_reuses_the_identity() {
    let _l = LOCK.lock().await;
    let a = Kit::generate();
    let srv = simple_server(&a.signer(), &a, true).await;
    let s = setup(&seed(&srv.uri(), vec![a.trust_key()], Some(3)), None);
    let first = run_check(&s.input, Utc::now()).await;
    let second = run_check(&s.input, Utc::now()).await;
    assert!(first.ok && second.ok, "{first:#?}\n{second:#?}");
    assert_eq!(first.device_id, second.device_id);
    assert!(step(&second, "seed_import").detail.starts_with("existing"));
    let reqs = srv.received_requests().await.unwrap();
    let status = received(&reqs, "/api/device/v1/status");
    assert_eq!(status.len(), 2);
    for h in ["x-mastersos-device", "x-mastersos-device-secret"] {
        assert_eq!(header_of(status[0], h), header_of(status[1], h), "{h}");
    }
}

fn entries(d: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(d)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
}

const HOME_VARS: &[&str] = &[
    "HOME",
    "TMPDIR",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_RUNTIME_DIR",
];

#[tokio::test]
async fn writes_nothing_outside_dir() {
    let _l = LOCK.lock().await;
    let (a, b) = (Kit::generate(), Kit::generate());
    let srv = full_server(&a, &b).await;
    let key = recovery_key();
    let s = setup(&seed(&srv.uri(), vec![a.trust_key()], Some(3)), Some(&key));
    let home = tempfile::tempdir().unwrap();
    let saved: Vec<_> = HOME_VARS.iter().map(|v| (v, std::env::var_os(v))).collect();
    for v in HOME_VARS {
        std::env::set_var(v, home.path());
    }
    let r = run_check(&s.input, Utc::now()).await;
    for (v, old) in saved {
        match old {
            Some(o) => std::env::set_var(v, o),
            None => std::env::remove_var(v),
        }
    }
    assert!(r.ok, "{r:#?}");
    assert!(
        entries(home.path()).is_empty(),
        "{:?}",
        entries(home.path())
    );
    assert_eq!(entries(&s.files), ["recovery-key", "seed.toml"]);
    let dir = &s.input.dir;
    assert_eq!(entries(dir), ["seed-partition", "state"]);
    assert_eq!(mode(dir), 0o700);
    for d in ["seed-partition", "state"] {
        assert_eq!(mode(&dir.join(d)), 0o700, "{d}");
    }
    assert_eq!(
        entries(&dir.join("seed-partition")),
        ["fetch-token", "identity.json", "seed.toml"]
    );
    assert_eq!(entries(&dir.join("state")), ["fetch-token", "seed.toml"]);
}

#[tokio::test]
async fn plain_http_to_a_non_loopback_host_is_refused_locally() {
    let _l = LOCK.lock().await;
    let a = Kit::generate();
    let key = recovery_key();
    let s = setup(
        &seed("http://192.0.2.1:8480", vec![a.trust_key()], None),
        Some(&key),
    );
    let r = run_check(&s.input, Utc::now()).await;
    for name in ["status", "escrow"] {
        let c = step(&r, name);
        assert_eq!(c.error_code.as_deref(), Some("local_refused"), "{c:?}");
        assert_eq!((c.route.as_deref(), c.status, c.ok), (None, None, false));
    }
    assert!(!r.ok);
}

/// Heartbeat 204 and status 204: the steps after the bundle succeed.
async fn mount_rest(srv: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/api/device/v1/heartbeat"))
        .respond_with(ResponseTemplate::new(204))
        .mount(srv)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/device/v1/status"))
        .respond_with(ResponseTemplate::new(204))
        .mount(srv)
        .await;
}

async fn mount_bundle(srv: &MockServer, after: &str, t: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path("/api/device/v1/bundle"))
        .and(query_param("after", after))
        .respond_with(t)
        .mount(srv)
        .await;
}

/// One run against a server whose `bundle?after=2` answers `t`; the bundle entry.
async fn first_bundle(a: &Kit, t: ResponseTemplate) -> Call {
    let srv = MockServer::start().await;
    mount_bundle(&srv, "2", t).await;
    mount_rest(&srv).await;
    let s = setup(&seed(&srv.uri(), vec![a.trust_key()], Some(3)), None);
    let r = run_check(&s.input, Utc::now()).await;
    assert!(!r.ok);
    assert_eq!(r.calls.iter().filter(|c| c.step == "bundle").count(), 1);
    assert!(step(&r, "status").ok);
    step(&r, "bundle").clone()
}

#[tokio::test]
async fn bundle_401_carries_the_server_code() {
    let _l = LOCK.lock().await;
    let a = Kit::generate();
    let json = ResponseTemplate::new(401).set_body_json(serde_json::json!({
        "error": { "code": "unauthorized", "message": "no" }
    }));
    let text = ResponseTemplate::new(401).set_body_string("Unauthorized");
    for (t, code) in [(json, "unauthorized"), (text, "invalid_answer")] {
        let b = first_bundle(&a, t).await;
        assert_eq!(
            (b.status, b.error_code.as_deref(), b.ok),
            (Some(401), Some(code), false),
            "{b:?}"
        );
        assert_eq!(
            b.route.as_deref(),
            Some("GET /api/device/v1/bundle?after=2")
        );
    }
}

#[tokio::test]
async fn bundle_answers_that_do_not_verify() {
    let _l = LOCK.lock().await;
    let a = Kit::generate();
    let r = [a.escrow_recipient()];
    let (v3, _) = bundle(3, &[a.trust_key()], &r, &a.signer());
    let (v2, _) = bundle(2, &[a.trust_key()], &r, &a.signer());
    let cases = [
        // The header names another version than the manifest.
        (
            ResponseTemplate::new(200)
                .insert_header("X-Mastersos-Version", "4")
                .set_body_bytes(v3.clone()),
            "verify_failed",
        ),
        // The first version is below the seed's min_version.
        (
            ResponseTemplate::new(200)
                .insert_header("X-Mastersos-Version", "2")
                .set_body_bytes(v2),
            "verify_failed",
        ),
        // No X-Mastersos-Version at all.
        (
            ResponseTemplate::new(200).set_body_bytes(v3),
            "invalid_answer",
        ),
    ];
    for (t, code) in cases {
        let b = first_bundle(&a, t).await;
        assert_eq!(
            (b.status, b.error_code.as_deref(), b.version),
            (Some(200), Some(code), None),
            "{b:?}"
        );
    }
}

#[tokio::test]
async fn heartbeat_with_another_digest_fails() {
    let _l = LOCK.lock().await;
    let a = Kit::generate();
    let srv = MockServer::start().await;
    let (v3, _) = bundle(3, &[a.trust_key()], &[a.escrow_recipient()], &a.signer());
    mount_bundle(
        &srv,
        "2",
        ResponseTemplate::new(200)
            .insert_header("X-Mastersos-Version", "3")
            .set_body_bytes(v3),
    )
    .await;
    mount_bundle(&srv, "3", ResponseTemplate::new(204)).await;
    Mock::given(method("GET"))
        .and(path("/api/device/v1/heartbeat"))
        .respond_with(ResponseTemplate::new(200).set_body_string(heartbeat(
            3,
            &"ab".repeat(32),
            &a.signer(),
        )))
        .mount(&srv)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/device/v1/status"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&srv)
        .await;
    let s = setup(&seed(&srv.uri(), vec![a.trust_key()], Some(3)), None);
    let r = run_check(&s.input, Utc::now()).await;
    let h = step(&r, "heartbeat");
    assert_eq!(
        (h.status, h.ok, h.error_code.as_deref(), h.version),
        (Some(200), false, Some("verify_failed"), Some(3)),
        "{h:?}"
    );
    assert!(!r.ok);
}

/// A DIR that holds anything but an earlier run's directories is refused and left as it was.
#[tokio::test]
async fn a_foreign_dir_is_refused_untouched() {
    let _l = LOCK.lock().await;
    let a = Kit::generate();
    let s = setup(
        &seed("https://server.example", vec![a.trust_key()], None),
        None,
    );
    let dir = &s.input.dir;
    std::fs::create_dir(dir).unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(dir.join("other.txt"), b"keep").unwrap();
    let r = run_check(&s.input, Utc::now()).await;
    assert_eq!(r.calls.len(), 1, "{r:#?}");
    let c = &r.calls[0];
    assert_eq!(
        (c.step.as_str(), c.ok, c.error_code.as_deref()),
        ("seed_import", false, Some("bad_input"))
    );
    assert_eq!(r.device_id, None);
    assert!(!r.ok);
    assert_eq!(mode(dir), 0o755);
    assert_eq!(entries(dir), ["other.txt"]);
}

/// A DIR of ours that is 0755 (empty, or an earlier run's layout) is tightened to 0700.
#[tokio::test]
async fn existing_dir_0755_is_tightened() {
    let _l = LOCK.lock().await;
    let a = Kit::generate();
    let srv = simple_server(&a.signer(), &a, true).await;
    let s = setup(&seed(&srv.uri(), vec![a.trust_key()], Some(3)), None);
    let dir = &s.input.dir;
    let open = |p: &Path| std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755));
    std::fs::create_dir(dir).unwrap();
    open(dir).unwrap();
    let r = run_check(&s.input, Utc::now()).await;
    assert!(r.ok, "{r:#?}");
    assert_eq!(mode(dir), 0o700);
    for d in ["", "seed-partition", "state"] {
        open(&dir.join(d)).unwrap();
    }
    let r = run_check(&s.input, Utc::now()).await;
    assert!(r.ok, "{r:#?}");
    for d in ["", "seed-partition", "state"] {
        assert_eq!(mode(&dir.join(d)), 0o700, "{d}");
    }
}

/// The only entry of a refused run.
fn refused_seed_import(r: &CheckReport) {
    assert_eq!(r.calls.len(), 1, "{r:#?}");
    let c = &r.calls[0];
    assert_eq!(
        (c.step.as_str(), c.ok, c.error_code.as_deref()),
        ("seed_import", false, Some("bad_input")),
        "{c:?}"
    );
    assert_eq!(r.device_id, None);
}

#[tokio::test]
async fn symlinked_dir_is_refused() {
    let _l = LOCK.lock().await;
    let a = Kit::generate();
    let s = setup(
        &seed("https://server.example", vec![a.trust_key()], None),
        None,
    );
    let target = s.files.parent().unwrap().join("target");
    std::fs::create_dir(&target).unwrap();
    std::os::unix::fs::symlink(&target, &s.input.dir).unwrap();
    let r = run_check(&s.input, Utc::now()).await;
    refused_seed_import(&r);
    assert!(entries(&target).is_empty());
    assert!(std::fs::symlink_metadata(&s.input.dir)
        .unwrap()
        .file_type()
        .is_symlink());
}

/// DIR/<name> is a symlink to another directory: refused, the target untouched.
async fn symlinked_sub_is_refused(name: &str) {
    let a = Kit::generate();
    let s = setup(
        &seed("https://server.example", vec![a.trust_key()], None),
        None,
    );
    let target = s.files.parent().unwrap().join("target");
    std::fs::create_dir(&target).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
    let dir = &s.input.dir;
    std::fs::create_dir(dir).unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(&target, dir.join(name)).unwrap();
    let r = run_check(&s.input, Utc::now()).await;
    refused_seed_import(&r);
    assert!(entries(&target).is_empty(), "{:?}", entries(&target));
    assert_eq!(mode(&target), 0o755);
    assert_eq!(entries(dir), [name]);
}

#[tokio::test]
async fn symlinked_state_is_refused() {
    let _l = LOCK.lock().await;
    symlinked_sub_is_refused("state").await;
}

#[tokio::test]
async fn symlinked_seed_partition_is_refused() {
    let _l = LOCK.lock().await;
    symlinked_sub_is_refused("seed-partition").await;
}

/// A DIR owned by another user is refused untouched. Changing the owner needs root: as another
/// user this test checks nothing (the decision itself has a unit test in the module).
#[tokio::test]
async fn a_dir_of_another_user_is_refused() {
    let _l = LOCK.lock().await;
    if !rustix::process::geteuid().is_root() {
        return;
    }
    let a = Kit::generate();
    let s = setup(
        &seed("https://server.example", vec![a.trust_key()], None),
        None,
    );
    let dir = &s.input.dir;
    std::fs::create_dir(dir).unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::chown(dir, Some(65534), Some(65534)).unwrap();
    let r = run_check(&s.input, Utc::now()).await;
    refused_seed_import(&r);
    assert_eq!(mode(dir), 0o755);
    assert!(entries(dir).is_empty());
}
