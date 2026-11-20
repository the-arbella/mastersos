//! `mastersos recovery read` and `mastersos devices list|show` over the protocol v1 CLI API.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use mastersos_bundle::kit::Kit;
use mastersos_bundle::trust_fingerprint;
use mastersos_cli::auth::store::{save_to, StoredLogin};
use serde_json::{json, Value};
use wiremock::matchers::{header, method, path, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SID: &str = "0192f3a4-5b6c-7d8e-9f00-112233445566";
const KEY_A: &str = "cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv";
const KEY_B: &str = "tuvrnlkj-ihgfedbc-tuvrnlkj-ihgfedbc-tuvrnlkj-ihgfedbc-tuvrnlkj-ihgfedbc";
const LUKS_1: &str = "0b6c1e1a-0000-4000-8000-000000000001";
const LUKS_2: &str = "0b6c1e1a-0000-4000-8000-000000000002";

fn prefix() -> String {
    format!("/api/cli/v1/schools/{SID}/mastersos/")
}

fn config_dir(home: &Path) -> PathBuf {
    if cfg!(windows) {
        home.join("mastersos")
    } else {
        home.join(".config").join("mastersos")
    }
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

/// A fake `arbella` that gives `TOK-PLAIN`, or `TOK-STEP` with `--step-up`, for `uri`.
#[cfg(unix)]
fn fake_arbella(bin: &Path, uri: &str) {
    use std::io::Write as _;
    let exe = bin.join("arbella");
    // Written by a child process: no write handle stays open here.
    let mut sh = Command::new("sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(&exe)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let script = format!(
        "#!/bin/sh\ntok=TOK-PLAIN\nfor a in \"$@\"; do [ \"$a\" = --step-up ] && tok=TOK-STEP; done\n\
         printf '{{\"fleet_url\":\"{uri}\",\"access_token\":\"%s\",\"expires_at\":\"2099-01-01T00:00:00Z\"}}' \"$tok\"\n"
    );
    sh.stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    assert!(sh.wait().unwrap().success());
}

fn school_key(dir: &Path, name: &str) -> (PathBuf, Kit) {
    let p = dir.join(name);
    mastersos_cli::sign::kit::kit_new(&p).unwrap();
    let kit = mastersos_cli::sign::kit::load_kit(&p).unwrap();
    (p, kit)
}

async fn run(home: &Path, path_var: &Path, args: Vec<String>) -> Output {
    let (home, path_var) = (home.to_owned(), path_var.to_owned());
    tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_mastersos"))
            .args(&args)
            .env("HOME", &home)
            .env("APPDATA", &home)
            .env("PATH", path_var)
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

fn error_body(code: &str) -> Value {
    json!({"error": {"code": code, "message": format!("the server says {code}")}})
}

fn registered(kit: &Kit) -> Value {
    let tk = kit.trust_key();
    json!([{"key_id": tk.id, "alg": "ed25519", "public_key": tk.public_key,
        "fingerprint": trust_fingerprint(&tk), "label": "Office",
        "created_at": "2026-11-03T09:00:00Z", "in_latest_trust": true, "last_used_at": null}])
}

fn row(kit: &Kit, key: &str, luks: &str, first: bool, serial: &str) -> Value {
    let recipients = [kit.escrow_recipient()];
    json!({
        "luks_uuid": luks,
        "recovery_key_age": mastersos_bundle::seal(key, &recipients).unwrap(),
        "recipients_fp": mastersos_bundle::recipients_fp(&recipients),
        "received_at": "2026-11-03T09:00:00Z",
        "serial": serial,
        "first_for_luks": first,
    })
}

/// A server that lists `kit` as registered and gives `rows` for device `dev-42`.
async fn recovery_server(kit: &Kit, rows: Vec<Value>) -> MockServer {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{}keys", prefix())))
        .respond_with(ResponseTemplate::new(200).set_body_json(registered(kit)))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{}devices/dev-42/recovery-keys", prefix())))
        .respond_with(ResponseTemplate::new(200).set_body_json(rows))
        .mount(&s)
        .await;
    s
}

fn read_args(key: &Path, extra: &[&str]) -> Vec<String> {
    let mut a: Vec<String> = extra.iter().map(|e| (*e).to_owned()).collect();
    a.extend(
        [
            "recovery",
            "read",
            "dev-42",
            "--school",
            SID,
            "--key-file",
            key.to_str().unwrap(),
        ]
        .map(String::from),
    );
    a
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_read_opens_rows_sealed_to_the_kit() {
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path(), "school.kit");
    let s = recovery_server(
        &kit,
        vec![
            row(&kit, KEY_A, LUKS_1, true, "SN-1"),
            row(&kit, KEY_B, LUKS_2, true, "SN-1"),
        ],
    )
    .await;
    let home = signed_in(&s.uri());
    let o = run(home.path(), home.path(), read_args(&key, &[])).await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    // Newest first, as the server sent them.
    let (a, b) = (out.find(KEY_A).expect(&out), out.find(KEY_B).expect(&out));
    assert!(a < b, "{out}");
    assert!(out.contains("serial=SN-1") && out.contains(LUKS_1), "{out}");
    assert!(out.contains("2 recovery key(s) opened."), "{out}");
    assert!(!out.contains("suspicious"), "{out}");
    // The key is never in stderr.
    assert!(!err.contains(KEY_A) && !err.contains(KEY_B), "{err}");
    // The device id is one encoded path segment of the request.
    let reqs = s.received_requests().await.unwrap();
    assert!(reqs
        .iter()
        .any(|r| r.url.path() == format!("{}devices/dev-42/recovery-keys", prefix())));
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_read_marks_rows_not_first_for_luks() {
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path(), "school.kit");
    let s = recovery_server(
        &kit,
        vec![
            row(&kit, KEY_A, LUKS_1, false, "SN-1"),
            row(&kit, KEY_B, LUKS_1, true, "SN-1"),
        ],
    )
    .await;
    let home = signed_in(&s.uri());
    let o = run(home.path(), home.path(), read_args(&key, &[])).await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let first_line = out.lines().find(|l| l.contains(KEY_A)).expect(&out);
    assert!(first_line.contains("not the first row"), "{out}");
    assert!(first_line.contains("suspicious"), "{out}");
    let second = out.lines().find(|l| l.contains(KEY_B)).expect(&out);
    assert!(!second.contains("suspicious"), "{out}");

    let o = run(home.path(), home.path(), read_args(&key, &["--json"])).await;
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v[0]["first_for_luks"], false);
    assert!(v[0]["note"].as_str().unwrap().contains("suspicious"));
    assert_eq!(v[1]["note"], Value::Null);
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_read_json_gives_null_for_a_row_that_does_not_open() {
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path(), "school.kit");
    let (_, other) = school_key(t.path(), "other.kit");
    let s = recovery_server(
        &kit,
        vec![
            row(&other, KEY_B, LUKS_2, true, "SN-1"),
            row(&kit, KEY_A, LUKS_1, true, "SN-1"),
        ],
    )
    .await;
    let home = signed_in(&s.uri());
    let o = run(home.path(), home.path(), read_args(&key, &["--json"])).await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 2);
    assert_eq!(v[0]["luks_uuid"], LUKS_2);
    assert_eq!(v[0]["recovery_key"], Value::Null);
    assert!(v[0]["note"]
        .as_str()
        .unwrap()
        .contains("not sealed to this school key"));
    assert_eq!(v[1]["recovery_key"], KEY_A);
    assert_eq!(v[1]["received_at"], "2026-11-03T09:00:00Z");
    assert_eq!(v[1]["serial"], "SN-1");
    assert!(!out.contains(KEY_B) && !err.contains(KEY_B));
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_read_fails_when_no_row_opens() {
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path(), "school.kit");
    let (_, other) = school_key(t.path(), "other.kit");
    let r = row(&other, KEY_B, LUKS_2, true, "SN-1");
    let armor = r["recovery_key_age"].as_str().unwrap().to_owned();
    let s = recovery_server(&kit, vec![r]).await;
    let home = signed_in(&s.uri());
    let o = run(home.path(), home.path(), read_args(&key, &["--json"])).await;
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "{out}{err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["error"]["code"], "not_opened");
    for s in [&out, &err] {
        assert!(!s.contains(KEY_B) && !s.contains("BEGIN AGE"), "{s}");
        assert!(!s.contains(armor.lines().nth(1).unwrap()), "{s}");
    }
    let o = run(home.path(), home.path(), read_args(&key, &[])).await;
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "{out}{err}");
    assert!(err.contains("none of the 1"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_read_without_rows_says_so() {
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path(), "school.kit");
    let s = recovery_server(&kit, vec![]).await;
    let home = signed_in(&s.uri());
    let o = run(home.path(), home.path(), read_args(&key, &[])).await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    assert!(out.contains("No recovery keys escrowed"), "{out}");
    let o = run(home.path(), home.path(), read_args(&key, &["--json"])).await;
    assert_eq!(
        serde_json::from_slice::<Value>(&o.stdout).unwrap(),
        json!([])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_read_refuses_a_kit_the_server_does_not_list() {
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path(), "school.kit");
    let (_, other) = school_key(t.path(), "other.kit");
    let s = recovery_server(&other, vec![row(&kit, KEY_A, LUKS_1, true, "SN-1")]).await;
    let home = signed_in(&s.uri());
    let o = run(home.path(), home.path(), read_args(&key, &[])).await;
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "{out}{err}");
    assert!(err.contains("not registered"), "{err}");
    assert!(!out.contains(KEY_A));
    // The rows were never asked for.
    let reqs = s.received_requests().await.unwrap();
    assert!(reqs.iter().all(|r| !r.url.path().contains("recovery-keys")));
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn recovery_read_needs_step_up() {
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path(), "school.kit");
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{}keys", prefix())))
        .respond_with(ResponseTemplate::new(200).set_body_json(registered(&kit)))
        .mount(&s)
        .await;
    let rows_path = format!("{}devices/dev-42/recovery-keys", prefix());
    Mock::given(method("GET"))
        .and(path(rows_path.clone()))
        .and(header("authorization", "Bearer TOK-STEP"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(vec![row(&kit, KEY_A, LUKS_1, true, "SN-1")]),
        )
        .with_priority(1)
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path(rows_path.clone()))
        .respond_with(ResponseTemplate::new(401).set_body_json(error_body("step_up_required")))
        .with_priority(2)
        .mount(&s)
        .await;
    let bin = tempfile::tempdir().unwrap();
    fake_arbella(bin.path(), &s.uri());
    let home = tempfile::tempdir().unwrap();
    let o = run(home.path(), bin.path(), read_args(&key, &[])).await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    assert!(out.contains(KEY_A), "{out}");
    let reqs = s.received_requests().await.unwrap();
    let on_rows: Vec<_> = reqs.iter().filter(|r| r.url.path() == rows_path).collect();
    assert_eq!(on_rows.len(), 2);
    assert_eq!(
        on_rows[0].headers.get("authorization").unwrap(),
        "Bearer TOK-PLAIN"
    );
}

fn device(id: &str, serial: &str, group: &str) -> Value {
    json!({"device_id": id, "serial": serial, "group": group, "bundle_version": 3,
        "last_seen": "2026-11-03T09:00:00Z", "fetch_token_stale": false, "behind": false,
        "has_errors": false, "removed_at": null, "future_field": [1, 2]})
}

async fn devices_server(list: Vec<Value>) -> MockServer {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{}devices", prefix())))
        .and(query_param_is_missing("group"))
        .respond_with(ResponseTemplate::new(200).set_body_json(list.clone()))
        .mount(&s)
        .await;
    for d in list {
        let mut one = d.clone();
        one["results"] = json!([{"name": "x", "ok": true}]);
        Mock::given(method("GET"))
            .and(path(format!(
                "{}devices/{}",
                prefix(),
                d["device_id"].as_str().unwrap()
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(one))
            .mount(&s)
            .await;
    }
    s
}

fn dev_args(rest: &[&str]) -> Vec<String> {
    let mut a: Vec<String> = vec!["devices".into()];
    a.extend(rest.iter().map(|e| (*e).to_owned()));
    a.extend(["--school".to_owned(), SID.to_owned()]);
    a
}

#[tokio::test(flavor = "multi_thread")]
async fn devices_show_by_serial() {
    let s = devices_server(vec![
        device("d-1", "SN-ONE", "default"),
        device("d-2", "SN-TWO", "default"),
    ])
    .await;
    let home = signed_in(&s.uri());
    let mut args = dev_args(&["show", "sn-two"]);
    args.insert(0, "--json".into());
    let o = run(home.path(), home.path(), args).await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["device_id"], "d-2");
    assert_eq!(v["results"][0]["name"], "x");
    assert_eq!(v["future_field"], json!([1, 2]));
    // An id is shown without a serial lookup in the way.
    let o = run(home.path(), home.path(), dev_args(&["show", "d-1"])).await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    assert!(
        out.contains("device_id: d-1") && out.contains("serial: SN-ONE"),
        "{out}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn devices_show_with_an_ambiguous_serial_lists_the_ids() {
    let s = devices_server(vec![
        device("d-1", "SN-SAME", "default"),
        device("d-2", "SN-SAME", "default"),
    ])
    .await;
    let home = signed_in(&s.uri());
    let o = run(home.path(), home.path(), dev_args(&["show", "SN-SAME"])).await;
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(2), "{out}{err}");
    assert!(err.contains("d-1") && err.contains("d-2"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn devices_show_asks_the_server_for_an_unlisted_id_and_encodes_it() {
    let s = devices_server(vec![device("d-1", "SN-ONE", "default")]).await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404).set_body_json(error_body("not_found")))
        .mount(&s)
        .await;
    let home = signed_in(&s.uri());
    let o = run(home.path(), home.path(), dev_args(&["show", "a/../b"])).await;
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "{out}{err}");
    let reqs = s.received_requests().await.unwrap();
    assert!(reqs
        .iter()
        .any(|r| r.url.path() == format!("{}devices/a%2F..%2Fb", prefix())));
}

#[tokio::test(flavor = "multi_thread")]
async fn devices_list_prints_a_table_and_the_servers_json() {
    let mut late = device("d-2", "SN-TWO", "lab");
    late["behind"] = json!(true);
    let s = devices_server(vec![device("d-1", "SN\u{1b}[31mONE", "default"), late]).await;
    let home = signed_in(&s.uri());
    let o = run(home.path(), home.path(), dev_args(&["list"])).await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    assert!(
        out.contains("DEVICE") && out.contains("d-1") && out.contains("behind"),
        "{out}"
    );
    assert!(!out.contains('\u{1b}'), "{out:?}");
    let mut args = dev_args(&["list", "--group", "lab"]);
    args.insert(0, "--json".into());
    let o = run(home.path(), home.path(), args).await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 1);
    assert_eq!(v[0]["device_id"], "d-2");
    assert_eq!(v[0]["future_field"], json!([1, 2]));
}
