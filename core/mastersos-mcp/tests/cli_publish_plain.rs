//! `mastersos publish` in plain words: the check, the check code, then either the published
//! version or the approval link. With a school key the monthly check-in for the version just
//! published is signed too, and never mentioned unless it fails.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use mastersos_bundle::kit::Kit;
use mastersos_bundle::{content_digest, verify_statement, Contents, HeartbeatStatement};
use mastersos_bundle::{SignatureFile, TrustKey};
use serde_json::{json, Value};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const SID: &str = "11111111-1111-1111-1111-111111111111";
const STALE: &str =
    "Computers may soon show \"settings may be out of date\". Open the admin site to fix it.";

fn config_dir(home: &Path) -> PathBuf {
    if cfg!(windows) {
        home.join("mastersos")
    } else {
        home.join(".config").join("mastersos")
    }
}

/// A home folder connected to `uri` (the files `mastersos connect` writes).
fn connected_home(uri: &str) -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    let dir = config_dir(home.path());
    std::fs::create_dir_all(&dir).unwrap();
    let token = dir.join("token");
    mastersos_sign::platform::write_private(&token, b"t\n").unwrap();
    let cfg = toml::to_string(&json!({ "server": uri, "token_file": token })).unwrap();
    mastersos_sign::platform::write_private(&dir.join("config.toml"), cfg.as_bytes()).unwrap();
    home
}

fn school_key(dir: &Path) -> (PathBuf, Kit) {
    let p = dir.join("alpha.key");
    mastersos_sign::kit::kit_new(&p).unwrap();
    let kit = mastersos_sign::kit::load_kit(&p).unwrap();
    (p, kit)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The content digest of an upload body (lower-case hex), as the server computes it.
fn digest_of(upload: &Value) -> String {
    let files = upload["files"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(p, b)| (p.clone(), STANDARD.decode(b.as_str().unwrap()).unwrap()))
        .collect::<BTreeMap<_, _>>();
    hex(&content_digest(&Contents {
        manifest_text: upload["manifest_text"].as_str().unwrap().to_owned(),
        files,
    }))
}

/// The server keeps the uploaded bundle and serves it back as the pending bundle, files too.
#[derive(Clone, Default)]
struct Pending(Arc<Mutex<Option<Value>>>);

impl Respond for Pending {
    fn respond(&self, r: &Request) -> ResponseTemplate {
        if r.method.as_str() == "POST" {
            let up: Value = serde_json::from_slice(&r.body).unwrap();
            let digest = digest_of(&up);
            *self.0.lock().unwrap() = Some(up);
            return ResponseTemplate::new(200).set_body_json(json!({
                "pending_id": "p-1", "version": 1, "digest_hex": digest, "lints": []
            }));
        }
        let up = self.0.lock().unwrap().clone().expect("uploaded first");
        if let Some(file) = r
            .url
            .path()
            .strip_prefix("/v1/admin/publish/pending/p-1/files/")
        {
            let b = up["files"][file].as_str().unwrap();
            return ResponseTemplate::new(200).set_body_bytes(STANDARD.decode(b).unwrap());
        }
        let files: Vec<Value> = up["files"]
            .as_object()
            .unwrap()
            .keys()
            .map(|p| json!({ "path": p }))
            .collect();
        ResponseTemplate::new(200).set_body_json(json!({
            "pending_id": "p-1", "version": 1, "digest_hex": digest_of(&up),
            "manifest_text": up["manifest_text"], "files": files
        }))
    }
}

/// A school that has published nothing, with `kit` registered; the check-in commit answers
/// `checkin_status`.
async fn server(kit: &Kit, checkin_status: u16) -> (MockServer, Pending) {
    let s = MockServer::start().await;
    let get = |p: &str, body: Value| {
        Mock::given(method("GET"))
            .and(path(p.to_owned()))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
    };
    get(
        "/v1/admin/whoami",
        json!({ "label": "cli:IT", "kind": "token", "scopes": ["read", "draft"], "school_name": "Alpha School" }),
    )
    .mount(&s)
    .await;
    get(
        "/v1/auth/config",
        json!({ "name": "Alpha School", "slug": "alpha", "school_id": SID, "signing_origin": "https://sign.example" }),
    )
    .mount(&s)
    .await;
    get("/v1/admin/versions", json!([])).mount(&s).await;
    let tk = kit.trust_key();
    get(
        "/v1/admin/signing-keys",
        json!([{
            "key_id": tk.id, "kind": "recovery", "alg": "ed25519",
            "fingerprint": mastersos_bundle::trust_fingerprint(&tk),
            "public_key": tk.public_key, "previously_trusted": false,
            "label": "key", "rp_id": null, "synced": false,
            "in_published_trust": false, "created_by": "it",
            "created_at": "2026-11-03T09:00:00Z"
        }]),
    )
    .mount(&s)
    .await;
    get(
        "/v1/admin/escrow-recipients",
        json!([{
            "recipient": kit.escrow_recipient(), "bound_key_id": kit.key_id(),
            "label": "key", "created_by": "it", "created_at": "2026-11-03T09:00:00Z",
            "in_published": false
        }]),
    )
    .mount(&s)
    .await;
    let pending = Pending::default();
    Mock::given(method("POST"))
        .and(path("/v1/admin/publish/pending"))
        .respond_with(pending.clone())
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path_regex("^/v1/admin/publish/pending/p-1(/files/.*)?$"))
        .respond_with(pending.clone())
        .mount(&s)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/admin/publish/pending/p-1/commit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "version": 1 })))
        .mount(&s)
        .await;
    let checkin = if checkin_status == 204 {
        ResponseTemplate::new(204)
    } else {
        ResponseTemplate::new(checkin_status).set_body_json(json!({
            "error": { "code": "internal", "message": "database down" }
        }))
    };
    Mock::given(method("POST"))
        .and(path("/v1/admin/heartbeat/commit"))
        .respond_with(checkin)
        .mount(&s)
        .await;
    (s, pending)
}

/// Run `mastersos` with `stdin` as its input.
async fn run(home: &Path, args: Vec<std::ffi::OsString>, stdin: &str) -> Output {
    let home = home.to_owned();
    let stdin = stdin.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut child = Command::new(env!("CARGO_BIN_EXE_mastersos"))
            .args(&args)
            .env("HOME", &home)
            .env("APPDATA", &home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // The program may stop before reading it all.
        let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap()
}

fn args(a: &[&dyn AsRef<std::ffi::OsStr>]) -> Vec<std::ffi::OsString> {
    a.iter().map(|x| x.as_ref().to_owned()).collect()
}

fn text(o: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

/// A folder made by `mastersos init` trusting the school key at `key`.
async fn folder(home: &Path, t: &Path, key: &Path) -> PathBuf {
    let dir = t.join("school");
    let o = run(home, args(&[&"init", &dir, &"--school-key", &key]), "").await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    dir
}

async fn uploaded(p: &Pending) -> Value {
    p.0.lock().unwrap().clone().expect("uploaded")
}

async fn checkins(s: &MockServer) -> Vec<Value> {
    s.received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == "/v1/admin/heartbeat/commit")
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect()
}

/// Words IT does not need to see on a normal publish. The diff shows manifest.toml as it is
/// (`escrow_recipients`, `issued_at`), so only the words outside the file are checked for those.
fn plain_words(out: &str) {
    let lower = out.to_lowercase();
    for w in [
        "heartbeat",
        "digest",
        "kit",
        "escrow recipient",
        "luks",
        "(r1g)",
        "(r5)",
        "rp_id",
        "the pin",
        "not_after",
        "check-in",
    ] {
        assert!(!lower.contains(w), "{w}: {out}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_with_school_key_signs_checkin() {
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path());
    let (s, pending) = server(&kit, 204).await;
    let home = connected_home(&s.uri());
    let dir = folder(home.path(), t.path(), &key).await;
    let o = run(
        home.path(),
        args(&[&"publish", &dir, &"--school-key", &key]),
        "1\ntrust\n",
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let digest = digest_of(&uploaded(&pending).await);
    // In this order: the check, the check code, the published version.
    // The new folder has one warning (no administrator yet), listed above the line.
    let checked = out
        .find("Checked: no errors, 1 warning (above)")
        .expect(&out);
    let code = out
        .find(&format!("Check code: {}", &digest[..8]))
        .expect(&out);
    let published = out.find("Published version 1").expect(&out);
    assert!(checked < code && code < published, "{out}");
    assert!(!out.contains(&digest), "only the check code: {out}");
    plain_words(&out);
    assert!(!err.contains(STALE), "{err}");

    // Exactly one check-in, for the version and content just published, signed by the school key.
    let c = checkins(&s).await;
    assert_eq!(c.len(), 1, "{c:?}");
    let statement: HeartbeatStatement = serde_json::from_value(c[0]["statement"].clone()).unwrap();
    let signature: SignatureFile = serde_json::from_value(c[0]["signature"].clone()).unwrap();
    assert_eq!(statement.version, 1);
    assert_eq!(statement.digest_hex, digest);
    assert_eq!(statement.not_after - statement.issued_at, 30 * 86_400);
    let trust: Vec<TrustKey> = vec![kit.trust_key()];
    verify_statement(&statement, &signature, &trust).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_heartbeat_failure_keeps_version() {
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path());
    let (s, _pending) = server(&kit, 500).await;
    let home = connected_home(&s.uri());
    let dir = folder(home.path(), t.path(), &key).await;
    let o = run(
        home.path(),
        args(&[&"publish", &dir, &"--school-key", &key]),
        "1\ntrust\n",
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    assert!(out.contains("Published version 1"), "{out}");
    assert!(err.contains(STALE), "{err}");
    // Only that sentence: not the server's error, not the cryptography.
    assert!(!err.contains("database down"), "{err}");
    plain_words(&out);
    plain_words(&err);
    assert_eq!(checkins(&s).await.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_without_key_prints_link_and_check_code() {
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path());
    let (s, pending) = server(&kit, 204).await;
    let home = connected_home(&s.uri());
    let dir = folder(home.path(), t.path(), &key).await;
    let o = run(home.path(), args(&[&"publish", &dir]), "").await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let digest = digest_of(&uploaded(&pending).await);
    let short = &digest[..8];
    let link = format!("https://sign.example/#school=alpha&sid={SID}&op=commit&pending=p-1");
    let checked = out
        .find("Checked: no errors, 1 warning (above)")
        .expect(&out);
    let code = out.find(&format!("Check code: {short}")).expect(&out);
    let wait = out
        .find(&format!("Waiting for approval: open {link}"))
        .expect(&out);
    let compare = out
        .find(&format!(
            "Compare the check code on that page with {short}."
        ))
        .expect(&out);
    assert!(checked < code && code < wait && wait < compare, "{out}");
    plain_words(&out);
    assert!(!out.replace(&link, "").contains("pending"), "{out}");
    // Nothing signed here, no check-in.
    assert!(checkins(&s).await.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn json_publish_reports_the_checkin() {
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path());
    let (s, _) = server(&kit, 204).await;
    let home = connected_home(&s.uri());
    let dir = folder(home.path(), t.path(), &key).await;
    let o = run(
        home.path(),
        args(&[&"--json", &"publish", &dir, &"--school-key", &key]),
        "1\ntrust\n",
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let v: Value = serde_json::from_str(out.trim()).expect(&out);
    assert_eq!(v["published"], true);
    assert_eq!(v["version"], 1);
    let until = v["checkin_until"].as_str().expect(&out);
    chrono::DateTime::parse_from_rfc3339(until).unwrap();
    assert!(v.get("checkin_error").is_none(), "{v}");

    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path());
    let (s, _) = server(&kit, 500).await;
    let home = connected_home(&s.uri());
    let dir = folder(home.path(), t.path(), &key).await;
    let o = run(
        home.path(),
        args(&[&"--json", &"publish", &dir, &"--school-key", &key]),
        "1\ntrust\n",
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let v: Value = serde_json::from_str(out.trim()).expect(&out);
    assert_eq!(v["published"], true);
    assert!(v["checkin_error"].as_str().is_some(), "{v}");
    assert!(v.get("checkin_until").is_none(), "{v}");
    assert!(err.contains(STALE), "{err}");
}
