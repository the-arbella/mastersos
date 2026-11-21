//! `mastersos key new|register|list|add|remove` over the protocol v1 CLI API: what is signed is
//! built here, the server's answers are compared, and the school key never leaves its file.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use mastersos_bundle::kit::{recipient_binding_message, Kit};
use mastersos_bundle::{trust_fingerprint, verify_signature, KeyAlg, SignatureFile};
use mastersos_cli::auth::store::{save_to, StoredLogin};
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const SID: &str = "0192f3a4-5b6c-7d8e-9f00-112233445566";

fn config_dir(home: &Path) -> PathBuf {
    if cfg!(windows) {
        home.join("mastersos")
    } else {
        home.join(".config").join("mastersos")
    }
}

fn prefix() -> String {
    format!("/api/cli/v1/schools/{SID}/mastersos/")
}

/// A home folder signed in to `uri` with `mastersos login` (no arbella on PATH).
fn signed_in(uri: &str) -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    let login = StoredLogin {
        version: 1,
        server_url: uri.to_owned(),
        issuer: "https://issuer.example".into(),
        client_id: "mastersos-cli".into(),
        audience: "fleet".into(),
        scopes: vec!["openid".into()],
        step_up_acr: String::new(),
        access_token: "SECRET-ACCESS".into(),
        expires_at: "2099-01-01T00:00:00Z".into(),
        refresh_token: None,
    };
    save_to(&config_dir(home.path()).join("credentials.json"), &login).unwrap();
    home
}

fn mastersos(home: &Path, cwd: Option<&Path>, args: &[std::ffi::OsString]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_mastersos"));
    c.args(args)
        .env("HOME", home)
        .env("APPDATA", home)
        // No arbella: the saved sign-in is used.
        .env("PATH", home)
        .stdin(Stdio::null());
    if let Some(d) = cwd {
        c.current_dir(d);
    }
    c.output().unwrap()
}

async fn run(home: &Path, cwd: Option<&Path>, args: &[&dyn AsRef<std::ffi::OsStr>]) -> Output {
    let args: Vec<std::ffi::OsString> = args.iter().map(|a| a.as_ref().to_owned()).collect();
    let (home, cwd) = (home.to_owned(), cwd.map(Path::to_owned));
    tokio::task::spawn_blocking(move || mastersos(&home, cwd.as_deref(), &args))
        .await
        .unwrap()
}

fn text(o: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

fn json_of(o: &Output) -> Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|_| panic!("{:?}", text(o)))
}

/// A new school key file in `dir`.
fn school_key(dir: &Path, name: &str) -> (PathBuf, Kit) {
    let p = dir.join(name);
    mastersos_cli::sign::kit::kit_new(&p).unwrap();
    let kit = mastersos_cli::sign::kit::load_kit(&p).unwrap();
    (p, kit)
}

/// The shared test vector `i` as a key file in `dir`, with its binding nonce and signature.
fn vector_key(dir: &Path, i: usize) -> (PathBuf, Kit, Value) {
    let file = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../mastersos-bundle/testdata/kit-vectors.json"
    );
    let all: Value = serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
    let v = all["vectors"][i].clone();
    let p = dir.join(format!("vector-{i}.kit"));
    mastersos_cli::platform::write_private(&p, v["text"].as_str().unwrap().as_bytes()).unwrap();
    let kit = mastersos_cli::sign::kit::load_kit(&p).unwrap();
    (p, kit, v)
}

/// The probe answer for `nonce`, as the server gives it.
fn probe_body(nonce: &[u8]) -> Value {
    json!({
        "nonce_b64": STANDARD.encode(nonce),
        "message_b64": STANDARD.encode(mastersos_bundle::keyid::keyprobe_message(nonce)),
    })
}

/// Probes with a nonce each: the n-th call gets `nonces[n]` (the last one repeats).
struct Probes {
    calls: AtomicUsize,
    nonces: Vec<Vec<u8>>,
}

impl Probes {
    fn new(nonces: Vec<Vec<u8>>) -> Probes {
        Probes {
            calls: AtomicUsize::new(0),
            nonces,
        }
    }
}

impl Respond for Probes {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let i = self
            .calls
            .fetch_add(1, Ordering::SeqCst)
            .min(self.nonces.len() - 1);
        ResponseTemplate::new(200).set_body_json(probe_body(&self.nonces[i]))
    }
}

fn error_body(code: &str) -> Value {
    json!({"error": {"code": code, "message": format!("the server says {code}")}})
}

/// A school server that gives probes and accepts the key and the recipient.
async fn registering_server(kit: &Kit, nonces: Vec<Vec<u8>>) -> MockServer {
    let s = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("{}keys/probe", prefix())))
        .respond_with(Probes::new(nonces))
        .mount(&s)
        .await;
    let tk = kit.trust_key();
    Mock::given(method("POST"))
        .and(path(format!("{}keys", prefix())))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({"key_id": tk.id, "fingerprint": trust_fingerprint(&tk)})),
        )
        .mount(&s)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("{}escrow-recipients", prefix())))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
        .mount(&s)
        .await;
    s
}

/// The POSTs the server saw: path below the school prefix, and the JSON body.
async fn posts(s: &MockServer) -> Vec<(String, Value)> {
    s.received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method.as_str() == "POST")
        .map(|r| {
            (
                r.url
                    .path()
                    .strip_prefix(&prefix())
                    .unwrap_or(r.url.path())
                    .to_owned(),
                serde_json::from_slice(&r.body).unwrap_or(Value::Null),
            )
        })
        .collect()
}

fn register_args(key: &Path, label: &str, extra: &[&str]) -> Vec<std::ffi::OsString> {
    let mut a: Vec<std::ffi::OsString> = vec![
        "key".into(),
        "register".into(),
        "--key-file".into(),
        key.into(),
        "--label".into(),
        label.into(),
    ];
    a.extend(extra.iter().map(|e| (*e).into()));
    a
}

async fn run_os(home: &Path, cwd: Option<&Path>, args: Vec<std::ffi::OsString>) -> Output {
    let (home, cwd) = (home.to_owned(), cwd.map(Path::to_owned));
    tokio::task::spawn_blocking(move || mastersos(&home, cwd.as_deref(), &args))
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn register_signs_the_local_probe_message() {
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path(), "school.kit");
    let s = registering_server(&kit, vec![vec![9; 32], vec![8; 32]]).await;
    let home = signed_in(&s.uri());
    let o = run_os(
        home.path(),
        None,
        register_args(&key, "Office USB", &["--school", SID]),
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let code = mastersos_bundle::keyid::key_code(&kit.key_id()).unwrap();
    assert!(
        out.contains(&format!("Registered school key {code}")),
        "{out}"
    );
    assert!(
        out.contains(&format!("Disk unlocking registered for school key {code}.")),
        "{out}"
    );

    let posts = posts(&s).await;
    let paths: Vec<&str> = posts.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(
        paths,
        ["keys/probe", "keys", "keys/probe", "escrow-recipients"]
    );
    let body = &posts[1].1;
    // Exactly the fields of the wire table, nothing else.
    let mut fields: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(fields, ["label", "nonce_b64", "signature", "trust_key"]);
    assert_eq!(body["label"], "Office USB");
    let tk = kit.trust_key();
    assert_eq!(
        body["trust_key"],
        json!({"id": tk.id, "alg": "ed25519", "public_key": tk.public_key})
    );
    assert_eq!(body["nonce_b64"], STANDARD.encode([9u8; 32]));
    assert_eq!(body["signature"]["key_id"], tk.id.as_str());
    assert_eq!(body["signature"]["alg"], "ed25519");
    // The signature verifies over "mastersos-keyprobe-v1\n" || nonce with the kit's key.
    let msg = [b"mastersos-keyprobe-v1\n".as_slice(), &[9u8; 32]].concat();
    let sig = SignatureFile {
        key_id: tk.id.clone(),
        alg: KeyAlg::Ed25519,
        sig: body["signature"]["sig"].as_str().unwrap().to_owned(),
        authenticator_data: None,
        client_data_json: None,
    };
    verify_signature(&msg, &sig, std::slice::from_ref(&tk)).unwrap();
    // The school key itself never reaches the output.
    for secret in [kit.to_text().to_string(), kit.to_display().to_string()] {
        assert!(!out.contains(&secret) && !err.contains(&secret));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn register_refuses_a_wrong_probe_message() {
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path(), "school.kit");
    let good = [7u8; 32];
    let cases: Vec<(&str, Value)> = vec![
        // The message of another nonce.
        (
            "message",
            json!({"nonce_b64": STANDARD.encode(good), "message_b64": probe_body(&[6u8; 32])["message_b64"]}),
        ),
        // The right bytes under another prefix.
        (
            "prefix",
            json!({"nonce_b64": STANDARD.encode(good),
                "message_b64": STANDARD.encode([b"mastersos-bundle-v1\n".as_slice(), &good].concat())}),
        ),
        // A nonce that is not 32 bytes, with its message.
        ("short nonce", probe_body(&[7u8; 31])),
        // Not std-pad: the padding is missing.
        (
            "unpadded",
            json!({"nonce_b64": STANDARD.encode(good).trim_end_matches('=') , "message_b64": probe_body(&good)["message_b64"]}),
        ),
        // Not base64 at all.
        (
            "garbage",
            json!({"nonce_b64": "!!not base64!!", "message_b64": probe_body(&good)["message_b64"]}),
        ),
    ];
    for (name, body) in cases {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("{}keys/probe", prefix())))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&s)
            .await;
        let home = signed_in(&s.uri());
        let o = run_os(
            home.path(),
            None,
            register_args(&key, "Office", &["--school", SID, "--json"]),
        )
        .await;
        assert!(!o.status.success(), "{name}: {:?}", text(&o));
        assert_eq!(json_of(&o)["error"]["code"], "invalid_answer", "{name}");
        let posted: Vec<String> = posts(&s).await.into_iter().map(|(p, _)| p).collect();
        assert_eq!(
            posted,
            ["keys/probe"],
            "{name}: nothing may be posted to keys"
        );
        let _ = &kit;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn register_refuses_another_key_in_the_answer() {
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path(), "school.kit");
    let (_, other) = school_key(t.path(), "other.kit");
    let s = registering_server(&kit, vec![vec![1; 32]]).await;
    // A later mock wins: the server answers with another key's id and fingerprint.
    let tk = other.trust_key();
    Mock::given(method("POST"))
        .and(path(format!("{}keys", prefix())))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({"key_id": tk.id, "fingerprint": trust_fingerprint(&tk)})),
        )
        .with_priority(1)
        .mount(&s)
        .await;
    let home = signed_in(&s.uri());
    let o = run_os(
        home.path(),
        None,
        register_args(&key, "Office", &["--school", SID, "--json"]),
    )
    .await;
    assert!(!o.status.success());
    assert_eq!(json_of(&o)["error"]["code"], "invalid_answer");
    let posted: Vec<String> = posts(&s).await.into_iter().map(|(p, _)| p).collect();
    assert!(
        !posted.contains(&"escrow-recipients".to_owned()),
        "{posted:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn register_then_binds_the_recipient_with_a_fresh_probe() {
    let t = tempfile::tempdir().unwrap();
    // A shared vector: its binding nonce, message and signature are fixed values.
    let (key, kit, v) = vector_key(t.path(), 0);
    let binding_nonce = STANDARD
        .decode(v["binding_nonce_b64"].as_str().unwrap())
        .unwrap();
    let s = registering_server(&kit, vec![vec![1; 32], binding_nonce.clone()]).await;
    let home = signed_in(&s.uri());
    let o = run_os(
        home.path(),
        None,
        register_args(&key, "Office USB", &["--school", SID]),
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let posts = posts(&s).await;
    let paths: Vec<&str> = posts.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(
        paths,
        ["keys/probe", "keys", "keys/probe", "escrow-recipients"]
    );
    // The key used the first probe, the recipient a fresh one.
    assert_eq!(posts[1].1["nonce_b64"], STANDARD.encode([1u8; 32]));
    let body = &posts[3].1;
    assert_eq!(body["nonce_b64"], v["binding_nonce_b64"]);
    let mut fields: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        ["bound_key_id", "label", "nonce_b64", "recipient", "sig_b64"]
    );
    assert_eq!(body["recipient"], v["escrow_recipient"]);
    assert_eq!(body["bound_key_id"], v["key_id"]);
    assert_eq!(body["label"], "Office USB");
    // The message is the one of the shared vector, and the (deterministic) signature is too.
    let msg = recipient_binding_message(v["escrow_recipient"].as_str().unwrap(), &binding_nonce);
    assert_eq!(
        STANDARD.encode(&msg),
        v["binding_message_b64"].as_str().unwrap()
    );
    assert_eq!(body["sig_b64"], v["binding_sig_b64"]);
    // sig_b64 is a bare string here, not the object of key registration.
    assert!(body["sig_b64"].is_string());
    let sig = SignatureFile {
        key_id: kit.key_id(),
        alg: KeyAlg::Ed25519,
        sig: body["sig_b64"].as_str().unwrap().to_owned(),
        authenticator_data: None,
        client_data_json: None,
    };
    let tk = kit.trust_key();
    verify_signature(&msg, &sig, std::slice::from_ref(&tk)).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn already_registered_key_still_registers_the_recipient() {
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path(), "school.kit");
    let s = registering_server(&kit, vec![vec![1; 32], vec![2; 32]]).await;
    Mock::given(method("POST"))
        .and(path(format!("{}keys", prefix())))
        .respond_with(ResponseTemplate::new(409).set_body_json(error_body("key_exists")))
        .with_priority(1)
        .mount(&s)
        .await;
    let home = signed_in(&s.uri());
    let o = run_os(
        home.path(),
        None,
        register_args(&key, "Office", &["--school", SID]),
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let code = mastersos_bundle::keyid::key_code(&kit.key_id()).unwrap();
    assert!(
        out.contains(&format!("School key {code} is already registered.")),
        "{out}"
    );
    assert!(
        out.contains(&format!("Disk unlocking registered for school key {code}.")),
        "{out}"
    );
    let posted: Vec<String> = posts(&s).await.into_iter().map(|(p, _)| p).collect();
    assert_eq!(
        posted,
        ["keys/probe", "keys", "keys/probe", "escrow-recipients"]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn already_registered_recipient_is_reported() {
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path(), "school.kit");
    let s = registering_server(&kit, vec![vec![1; 32], vec![2; 32]]).await;
    Mock::given(method("POST"))
        .and(path(format!("{}escrow-recipients", prefix())))
        .respond_with(ResponseTemplate::new(409).set_body_json(error_body("recipient_exists")))
        .with_priority(1)
        .mount(&s)
        .await;
    let home = signed_in(&s.uri());
    let o = run_os(
        home.path(),
        None,
        register_args(&key, "Office", &["--school", SID, "--json"]),
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let v = json_of(&o);
    assert_eq!(v["key_already_registered"], false);
    assert_eq!(v["recipient_already_registered"], true);
    assert_eq!(v["recipient"], kit.escrow_recipient());
    assert!(!out.contains(kit.to_text().as_str()));
}

#[tokio::test(flavor = "multi_thread")]
async fn register_without_a_school_asks_no_one_when_not_interactive() {
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path(), "school.kit");
    let s = registering_server(&kit, vec![vec![1; 32]]).await;
    Mock::given(method("GET"))
        .and(path("/api/cli/v1/schools"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": SID, "name": "Alpha", "time_zone": "UTC"},
            {"id": "0192f3a4-5b6c-7d8e-9f00-aabbccddeeff", "name": "Beta", "time_zone": "UTC"},
        ])))
        .mount(&s)
        .await;
    let home = signed_in(&s.uri());
    let o = run_os(home.path(), None, register_args(&key, "Office", &["--yes"])).await;
    assert!(!o.status.success());
    assert!(text(&o).1.contains("--school"), "{:?}", text(&o));
    assert!(posts(&s).await.is_empty());
}

/// A directory as `init` makes it, trusting `kit`, for the school on `uri`.
fn folder_with(t: &Path, uri: &str, kit: &Kit) -> PathBuf {
    use mastersos_cli::workdir::{set_trusted_keys, template, Meta, Workdir};
    let dir = t.join("school");
    let text = set_trusted_keys(
        &template(SID).unwrap(),
        &[(kit.trust_key(), kit.escrow_recipient())],
    )
    .unwrap();
    let meta = Meta {
        server: uri.to_owned(),
        school_id: SID.to_owned(),
        base_version: 0,
    };
    Workdir::init(&dir, meta, &text).unwrap();
    dir
}

fn key_entry(kit: &Kit, label: &str, latest: bool) -> Value {
    let tk = kit.trust_key();
    json!({"key_id": tk.id, "alg": "ed25519", "public_key": tk.public_key,
        "fingerprint": trust_fingerprint(&tk), "label": label,
        "created_at": "2026-11-03T09:00:00Z", "in_latest_trust": latest,
        "last_used_at": null, "future_field": {"kept": [1, 2]}})
}

async fn listing_server(keys: Vec<Value>, recipients: Vec<Value>) -> MockServer {
    let s = MockServer::start().await;
    for (route, body) in [("keys", keys), ("escrow-recipients", recipients)] {
        Mock::given(method("GET"))
            .and(path(format!("{}{route}", prefix())))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&s)
            .await;
    }
    s
}

#[tokio::test(flavor = "multi_thread")]
async fn key_list_json_shape() {
    let t = tempfile::tempdir().unwrap();
    let (_, a) = school_key(t.path(), "a.kit");
    let (_, b) = school_key(t.path(), "b.kit");
    let recipient = json!({"recipient": a.escrow_recipient(), "bound_key_id": a.key_id(),
        "label": "a", "created_at": "2026-11-03T09:00:00Z", "in_latest": true, "extra": 7});
    let ka = key_entry(&a, "first", true);
    let kb = key_entry(&b, "second", false);
    let s = listing_server(vec![ka.clone(), kb.clone()], vec![recipient.clone()]).await;
    let home = signed_in(&s.uri());
    let dir = folder_with(t.path(), &s.uri(), &a);
    let o = run(
        home.path(),
        None,
        &[&"key", &"list", &"--dir", &dir, &"--json"],
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let v = json_of(&o);
    let mut top: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    top.sort_unstable();
    assert_eq!(top, ["escrow_recipients", "keys"]);
    // As the server sent them (unknown fields too), plus in_directory per key.
    let mut want_a = ka;
    want_a["in_directory"] = json!(true);
    let mut want_b = kb;
    want_b["in_directory"] = json!(false);
    assert_eq!(v["keys"], json!([want_a, want_b]));
    assert_eq!(v["escrow_recipients"], json!([recipient]));
    // Only reads.
    let reqs = s.received_requests().await.unwrap();
    assert!(reqs.iter().all(|r| r.method.as_str() == "GET"), "{reqs:?}");

    // Without a directory every key is "not in the directory".
    let o = run(
        home.path(),
        Some(t.path()),
        &[&"key", &"list", &"--school", &SID, &"--json"],
    )
    .await;
    assert!(o.status.success(), "{:?}", text(&o));
    assert_eq!(json_of(&o)["keys"][0]["in_directory"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn key_list_table_has_the_columns_and_no_control_characters() {
    let t = tempfile::tempdir().unwrap();
    let (_, a) = school_key(t.path(), "a.kit");
    let mut ka = key_entry(&a, "l\u{1b}[31mabel\u{202e}", true);
    ka["last_used_at"] = json!("2026-11-10T01:02:03Z");
    let recipient = json!({"recipient": a.escrow_recipient(), "bound_key_id": a.key_id(),
        "label": "r\u{202e}gnp", "created_at": "2026-11-03T09:00:00Z", "in_latest": true});
    let s = listing_server(vec![ka], vec![recipient]).await;
    let home = signed_in(&s.uri());
    let dir = folder_with(t.path(), &s.uri(), &a);
    let o = run(home.path(), None, &[&"key", &"list", &"--dir", &dir]).await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    assert!(!out.contains(['\u{1b}', '\u{7}', '\u{202e}']), "{out:?}");
    // A bidi override is shown escaped, not obeyed.
    assert!(out.contains("abel\\u{202e}"), "{out:?}");
    assert!(out.contains("r\\u{202e}gnp"), "{out:?}");
    let header = out.lines().next().unwrap();
    for c in [
        "KEY CODE",
        "LABEL",
        "REGISTERED",
        "IN LATEST TRUST",
        "IN THIS DIRECTORY",
        "LAST USED",
    ] {
        assert!(header.contains(c), "{header}");
    }
    let row = out.lines().nth(1).unwrap();
    let code = mastersos_bundle::keyid::key_code(&a.key_id()).unwrap();
    assert!(row.starts_with(&code), "{row}");
    assert!(
        row.contains("[31mabel") && row.contains("2026-11-03"),
        "{row}"
    );
    assert!(row.contains("2026-11-10"), "{row}");
}

#[tokio::test(flavor = "multi_thread")]
async fn key_add_needs_the_server_to_list_the_key() {
    let t = tempfile::tempdir().unwrap();
    let (_, a) = school_key(t.path(), "a.kit");
    let (pb, b) = school_key(t.path(), "b.kit");
    // Listed, but under another public key: not the same key.
    let mut listed = key_entry(&b, "b", false);
    listed["public_key"] = json!(a.trust_key().public_key);
    let s = listing_server(vec![key_entry(&a, "a", true), listed], vec![]).await;
    let home = signed_in(&s.uri());
    let dir = folder_with(t.path(), &s.uri(), &a);
    let before = std::fs::read_to_string(dir.join("manifest.toml")).unwrap();
    let o = run(home.path(), None, &[&"key", &"add", &pb, &"--dir", &dir]).await;
    assert!(!o.status.success());
    assert!(
        text(&o).1.contains("is not registered for"),
        "{:?}",
        text(&o)
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("manifest.toml")).unwrap(),
        before
    );
    let _ = b;
}

#[tokio::test(flavor = "multi_thread")]
async fn key_add_then_remove_edit_only_the_directory() {
    let t = tempfile::tempdir().unwrap();
    let (_, a) = school_key(t.path(), "a.kit");
    let (pb, b) = school_key(t.path(), "b.kit");
    let s = listing_server(
        vec![key_entry(&a, "a", true), key_entry(&b, "b", false)],
        vec![],
    )
    .await;
    let home = signed_in(&s.uri());
    let dir = folder_with(t.path(), &s.uri(), &a);
    let o = run(home.path(), None, &[&"key", &"add", &pb, &"--dir", &dir]).await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    assert!(out.contains("mastersos publish --key-file <file>"), "{out}");
    let m = std::fs::read_to_string(dir.join("manifest.toml")).unwrap();
    assert!(m.contains(&b.trust_key().public_key) && m.contains(&b.escrow_recipient()));
    // Without the comments that tie each disk-unlocking entry to its key, nothing can match
    // them offline: they are listed.
    let untagged: String = m
        .lines()
        .filter(|l| !l.trim_start().starts_with("# school key "))
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(dir.join("manifest.toml"), untagged).unwrap();
    // Removing it again is local and needs no server and no sign-in.
    let empty = tempfile::tempdir().unwrap();
    let code = mastersos_bundle::keyid::key_code(&b.key_id()).unwrap();
    let o = run(
        empty.path(),
        None,
        &[&"key", &"remove", &code, &"--dir", &dir, &"--json"],
    )
    .await;
    assert!(o.status.success(), "{:?}", text(&o));
    let m = std::fs::read_to_string(dir.join("manifest.toml")).unwrap();
    assert!(!m.contains(&b.trust_key().public_key), "{m}");
    // --json: one JSON value on stdout, nothing else.
    let v = json_of(&o);
    let code_a = mastersos_bundle::keyid::key_code(&a.key_id()).unwrap();
    assert_eq!(v["removed"], code.as_str(), "{v}");
    assert_eq!(v["trusted"], json!([code_a]), "{v}");
    assert_eq!(
        v["manifest"],
        std::path::absolute(dir.join("manifest.toml"))
            .unwrap()
            .display()
            .to_string()
    );
    assert_eq!(v["recipient_removed"], false, "{v}");
    let unmarked = v["unmarked"].as_array().unwrap();
    assert!(
        unmarked
            .iter()
            .any(|u| u["recipient"] == b.escrow_recipient()),
        "{v}"
    );
    // Not signed in: the server's word is missing, not guessed.
    assert!(unmarked.iter().all(|u| u["server_says"].is_null()), "{v}");
    // No write ever reached the server.
    let reqs = s.received_requests().await.unwrap();
    assert!(reqs.iter().all(|r| r.method.as_str() == "GET"), "{reqs:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn unregister_still_trusted_explains() {
    let t = tempfile::tempdir().unwrap();
    let (_, a) = school_key(t.path(), "a.kit");
    let s = MockServer::start().await;
    let route = format!("{}keys/{}", prefix(), a.key_id());
    Mock::given(method("DELETE"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(409).set_body_json(error_body("key_still_trusted")))
        .mount(&s)
        .await;
    let home = signed_in(&s.uri());
    let code = mastersos_bundle::keyid::key_code(&a.key_id()).unwrap();
    let o = run(
        home.path(),
        None,
        &[&"key", &"remove", &code, &"--unregister", &"--school", &SID],
    )
    .await;
    let (out, err) = text(&o);
    assert!(!o.status.success(), "{out}{err}");
    assert!(err.contains("publish a version without it first"), "{err}");
    let o = run(
        home.path(),
        None,
        &[
            &"key",
            &"remove",
            &code,
            &"--unregister",
            &"--school",
            &SID,
            &"--json",
        ],
    )
    .await;
    assert_eq!(json_of(&o)["error"]["code"], "key_still_trusted");
}

#[tokio::test(flavor = "multi_thread")]
async fn unregister_deletes_the_key_and_encodes_the_id() {
    let t = tempfile::tempdir().unwrap();
    let (pa, a) = school_key(t.path(), "a.kit");
    let (pb, b) = school_key(t.path(), "b.kit");
    let s = MockServer::start().await;
    Mock::given(method("DELETE"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&s)
        .await;
    let home = signed_in(&s.uri());
    let code = mastersos_bundle::keyid::key_code(&a.key_id()).unwrap();
    // With the key file the id comes from the file, which must be that key's.
    let o = run(
        home.path(),
        None,
        &[
            &"key",
            &"remove",
            &code,
            &"--unregister",
            &"--school",
            &SID,
            &"--key-file",
            &pa,
        ],
    )
    .await;
    assert!(o.status.success(), "{:?}", text(&o));
    let o = run(
        home.path(),
        None,
        &[
            &"key",
            &"remove",
            &code,
            &"--unregister",
            &"--school",
            &SID,
            &"--key-file",
            &pb,
        ],
    )
    .await;
    assert!(!o.status.success());
    let deletes: Vec<String> = s
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method.as_str() == "DELETE")
        .map(|r| r.url.path().to_owned())
        .collect();
    assert_eq!(deletes, [format!("{}keys/{}", prefix(), a.key_id())]);
    let _ = b;
}

// —— key new: the school key file ——

fn key_new(home: &Path, out: &Path, extra: &[&str]) -> Output {
    let mut args: Vec<std::ffi::OsString> = vec!["key".into(), "new".into(), "--out".into()];
    args.push(out.into());
    args.extend(extra.iter().map(|e| (*e).into()));
    mastersos(home, None, &args)
}

#[cfg(unix)]
#[test]
fn key_new_writes_a_private_file_and_prints_no_key() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let t = tempfile::tempdir().unwrap();
    let file = t.path().join("school.kit");
    let o = key_new(home.path(), &file, &[]);
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let kit = mastersos_cli::sign::kit::load_kit(&file).unwrap();
    let code = mastersos_bundle::keyid::key_code(&kit.key_id()).unwrap();
    assert!(out.contains(&code), "{out}");
    for secret in [
        kit.to_text().to_string(),
        kit.to_display().to_string(),
        kit.to_display().replace(' ', ""),
    ] {
        assert!(
            !out.contains(&secret) && !err.contains(&secret),
            "{out}{err}"
        );
    }
    // --json: the public parts only.
    let file2 = t.path().join("two.kit");
    let o = key_new(home.path(), &file2, &["--json"]);
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let v = json_of(&o);
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["fingerprint", "key_code", "key_id", "path"]);
    let kit2 = mastersos_cli::sign::kit::load_kit(&file2).unwrap();
    assert_eq!(v["key_id"], kit2.key_id());
    assert!(!out.contains(kit2.to_text().as_str()) && !err.contains(kit2.to_text().as_str()));
}

#[test]
fn key_new_in_a_directory_names_the_file() {
    let home = tempfile::tempdir().unwrap();
    let t = tempfile::tempdir().unwrap();
    let o = key_new(home.path(), t.path(), &["--school-name", "alpha", "--json"]);
    assert!(o.status.success(), "{:?}", text(&o));
    let v = json_of(&o);
    let file = PathBuf::from(v["path"].as_str().unwrap());
    assert!(file.is_file());
    assert_eq!(
        file.parent().unwrap(),
        std::path::absolute(t.path()).unwrap()
    );
    assert!(file
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("alpha-school-key-"));
}

#[test]
fn key_new_refuses_an_existing_path() {
    let home = tempfile::tempdir().unwrap();
    let t = tempfile::tempdir().unwrap();
    let file = t.path().join("school.kit");
    std::fs::write(&file, "precious").unwrap();
    let o = key_new(home.path(), &file, &[]);
    assert!(!o.status.success());
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "precious");
    let (out, err) = text(&o);
    assert!(
        format!("{out}{err}").contains("already exists"),
        "{out}{err}"
    );
}

/// The folder the key file goes into: one other users can write to (and not sticky) is refused,
/// with what to do instead; one only its owner can write to is accepted.
#[cfg(unix)]
#[test]
fn key_new_refuses_a_folder_others_can_write() {
    use std::os::unix::fs::PermissionsExt as _;
    let home = tempfile::tempdir().unwrap();
    let t = tempfile::tempdir().unwrap();
    let open = t.path().join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
    let o = key_new(home.path(), &open.join("school.kit"), &["--json"]);
    assert_eq!(o.status.code(), Some(1), "{:?}", text(&o));
    let v = json_of(&o);
    assert_eq!(v["error"]["code"], "local_file", "{v}");
    let message = v["error"]["message"].as_str().unwrap();
    assert!(message.contains("other users can write"), "{message}");
    assert!(message.contains("USB stick"), "{message}");
    assert!(!message.contains("seed"), "{message}");
    assert!(!open.join("school.kit").exists());
    // Group-writable but sticky: nobody else can replace the file.
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o1777)).unwrap();
    let o = key_new(home.path(), &open.join("school.kit"), &[]);
    assert!(o.status.success(), "{:?}", text(&o));
}

#[cfg(unix)]
#[test]
fn key_new_refuses_a_symlink_at_the_path() {
    let home = tempfile::tempdir().unwrap();
    let t = tempfile::tempdir().unwrap();
    // A link to a file that exists: the file is not written through it.
    let target = t.path().join("target");
    std::fs::write(&target, "precious").unwrap();
    let link = t.path().join("link.kit");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let o = key_new(home.path(), &link, &[]);
    assert!(!o.status.success(), "{:?}", text(&o));
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "precious");
    // A dangling link: the file it points at is not created.
    let missing = t.path().join("missing");
    let dangling = t.path().join("dangling.kit");
    std::os::unix::fs::symlink(&missing, &dangling).unwrap();
    let o = key_new(home.path(), &dangling, &[]);
    assert!(!o.status.success(), "{:?}", text(&o));
    assert!(!missing.exists());
}
