//! `mastersos publish` and `mastersos heartbeat` over protocol v1: the frame and the digest
//! uploaded, the signed archive committed, the monthly check-in signed after it, in plain words.
//! Without a person to confirm, only `--yes` goes on.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use mastersos_bundle::kit::Kit;
use mastersos_bundle::{content_digest, read_archive, verify_heartbeat};
use mastersos_cli::auth::store::{save_to, StoredLogin};
use serde_json::{json, Value};
use wiremock::matchers::path_regex;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const SID: &str = "0192f3a4-5b6c-7d8e-9f00-112233445566";
const PID: &str = "0192f3a4-0000-4000-8000-0000000000aa";
const STALE: &str =
    "Computers may soon show \"settings may be out of date\". Open the admin site to fix it.";

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

fn school_key(dir: &Path) -> (PathBuf, Kit) {
    let p = dir.join("alpha.kit");
    mastersos_cli::sign::kit::kit_new(&p).unwrap();
    let kit = mastersos_cli::sign::kit::load_kit(&p).unwrap();
    (p, kit)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[derive(Default)]
struct Held {
    archives: Vec<Vec<u8>>,
    uploads: Vec<Value>,
    commits: usize,
    heartbeats: Vec<String>,
    requests: usize,
}

type Refusal = Arc<Mutex<Option<(u16, Value)>>>;

/// One school on the protocol v1 CLI API.
#[derive(Clone, Default)]
struct School {
    held: Arc<Mutex<Held>>,
    refuse_upload: Refusal,
    refuse_heartbeat: Refusal,
}

fn envelope(code: &str, details: Value) -> Value {
    json!({"error": {"code": code, "message": "refused", "details": details}})
}

impl Respond for School {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let mut held = self.held.lock().unwrap();
        held.requests += 1;
        let p = req.url.path().to_owned();
        if p == "/api/cli/v1/schools" {
            return ResponseTemplate::new(200).set_body_json(
                json!([{"id": SID, "name": "Alpha School", "time_zone": "Asia/Bangkok"}]),
            );
        }
        let route = p
            .strip_prefix(&prefix())
            .expect("a school route")
            .to_owned();
        let commit = format!("publish/pending/{PID}/commit");
        match (req.method.as_str(), route.as_str()) {
            ("GET", "versions") => {
                let vs: Vec<Value> = (1..=held.archives.len())
                    .map(|v| {
                        json!({"version": v, "published_at": "2026-11-20T00:00:00Z",
                        "published_by": "it", "signed_by": "k", "digest_hex": "00"})
                    })
                    .collect();
                ResponseTemplate::new(200).set_body_json(vs)
            }
            ("GET", r) if r.starts_with("versions/") => {
                let v: usize = r
                    .trim_start_matches("versions/")
                    .trim_end_matches("/archive")
                    .parse()
                    .unwrap();
                ResponseTemplate::new(200)
                    .insert_header("X-Mastersos-Version", v.to_string().as_str())
                    .set_body_bytes(held.archives[v - 1].clone())
            }
            ("POST", "publish/pending") => {
                let body: Value = serde_json::from_slice(&req.body).unwrap();
                held.uploads.push(body.clone());
                if let Some((status, e)) = self.refuse_upload.lock().unwrap().clone() {
                    return ResponseTemplate::new(status).set_body_json(e);
                }
                let digest = body["digest_hex"].as_str().unwrap().to_owned();
                let mut msg = b"mastersos-bundle-v1\n".to_vec();
                msg.extend(
                    (0..32).map(|i| u8::from_str_radix(&digest[2 * i..2 * i + 2], 16).unwrap()),
                );
                ResponseTemplate::new(201).set_body_json(json!({
                    "pending_id": PID, "version": body["frame"]["version"],
                    "digest_hex": digest, "message_b64": STANDARD.encode(&msg),
                    "expires_at": "2026-11-21T05:30:00Z",
                    "trust_change": {"added": [], "removed": []}, "warnings": []
                }))
            }
            ("DELETE", _) => ResponseTemplate::new(204),
            ("POST", r) if r == commit => {
                held.commits += 1;
                held.archives.push(req.body.clone());
                let v = held.archives.len();
                ResponseTemplate::new(200).set_body_json(json!({ "version": v }))
            }
            ("POST", "heartbeat") => {
                let body: Value = serde_json::from_slice(&req.body).unwrap();
                held.heartbeats
                    .push(body["heartbeat"].as_str().unwrap().to_owned());
                match self.refuse_heartbeat.lock().unwrap().clone() {
                    Some((status, e)) => ResponseTemplate::new(status).set_body_json(e),
                    None => ResponseTemplate::new(204),
                }
            }
            other => panic!("unexpected request {other:?}"),
        }
    }
}

async fn new_school() -> (MockServer, School) {
    let s = MockServer::start().await;
    let school = School::default();
    Mock::given(path_regex("^/api/cli/v1/.*$"))
        .respond_with(school.clone())
        .mount(&s)
        .await;
    (s, school)
}

/// Run `mastersos` with `stdin` as its input (`None`: no input at all).
async fn run(home: &Path, cwd: Option<&Path>, args: &[&dyn AsRef<std::ffi::OsStr>]) -> Output {
    let args: Vec<std::ffi::OsString> = args.iter().map(|a| a.as_ref().to_owned()).collect();
    let (home, cwd) = (home.to_owned(), cwd.map(Path::to_owned));
    tokio::task::spawn_blocking(move || {
        let mut c = Command::new(env!("CARGO_BIN_EXE_mastersos"));
        c.args(&args)
            .env("HOME", &home)
            .env("APPDATA", &home)
            .env("PATH", &home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(d) = &cwd {
            c.current_dir(d);
        }
        let mut child = c.spawn().unwrap();
        // Nothing is typed: a pipe, not a terminal.
        let _ = child.stdin.take().unwrap().write_all(b"1\nyes\n");
        child.wait_with_output().unwrap()
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

/// A folder as `mastersos init` makes it for the school on `uri`, trusting `kit`.
fn folder(t: &Path, uri: &str, kit: &Kit) -> PathBuf {
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

fn manifest(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("manifest.toml")).unwrap()
}

/// Words IT does not need to see on a normal publish. The diff shows lines of manifest.toml as
/// they are: lines that are a line of one of `manifests` after their diff mark are left out.
fn plain_words(out: &str, manifests: &[String]) {
    let file_lines: std::collections::BTreeSet<&str> =
        manifests.iter().flat_map(|m| m.lines()).collect();
    let shown: Vec<&str> = out
        .lines()
        .filter(|l| {
            let body = l.get(1..).unwrap_or("");
            let mark = l.starts_with(['+', '-', ' ']);
            !(mark && file_lines.contains(body))
                && !l.starts_with("--- v")
                && !l.starts_with("+++ v")
        })
        .collect();
    let shown = shown.join("\n");
    // "Trusted keys" is the plain label, and `--trust-fingerprint` the flag's protocol name; any
    // other "trust" is not.
    let lower = shown
        .to_lowercase()
        .replace("trusted keys", "")
        .replace("--trust-fingerprint", "");
    for w in [
        "heartbeat",
        "digest",
        "kit",
        "trust",
        "escrow",
        "recipient",
        "luks",
        "(r1g)",
        "(r5)",
        "rp_id",
        "the pin",
        "not_after",
        "check-in",
        "signing page",
        "passkey",
        "frame",
        "pending",
    ] {
        assert!(!lower.contains(w), "{w}: {shown}");
    }
}

fn digest_of(archive: &[u8]) -> String {
    hex(&content_digest(&read_archive(archive).unwrap().contents))
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_twice_moves_the_base_and_checks_in() {
    let (s, school) = new_school().await;
    let home = signed_in(&s.uri());
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path());
    let dir = folder(t.path(), &s.uri(), &kit);
    let o = run(
        home.path(),
        None,
        &[&"publish", &dir, &"--key-file", &key, &"--yes"],
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let digest = digest_of(&school.held.lock().unwrap().archives[0]);
    let code = out
        .find(&format!("Check code: {}", &digest[..8]))
        .expect(&out);
    let published = out.find("Published version 1").expect(&out);
    assert!(code < published, "{out}");
    assert!(!out.contains(&digest), "only the check code: {out}");
    plain_words(&out, &[manifest(&dir)]);
    plain_words(&err, &[]);
    // The template is format 1: no `[school] name` is stamped into it (only format 2 and later).
    assert!(manifest(&dir).contains("version = 1"));

    // Version 2, verified from the pin version 1 left on this computer.
    let v1 = manifest(&dir);
    std::fs::write(
        dir.join("manifest.toml"),
        v1.replace("name = \"Ungrouped\"", "name = \"Everyone\""),
    )
    .unwrap();
    let o = run(
        home.path(),
        None,
        &[&"publish", &dir, &"--key-file", &key, &"--yes"],
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    assert!(out.contains("Published version 2"), "{out}");
    assert!(
        out.contains("The trusted keys are the same as in version 1."),
        "{out}"
    );
    plain_words(&out, &[v1, manifest(&dir)]);
    plain_words(&err, &[]);

    let held = school.held.lock().unwrap();
    assert_eq!(held.commits, 2);
    assert_eq!(held.heartbeats.len(), 2);
    let st = verify_heartbeat(&held.heartbeats[1], &[kit.trust_key()]).unwrap();
    assert_eq!(st.version, 2);
    assert_eq!(st.digest_hex, digest_of(&held.archives[1]));
    assert_eq!(st.not_after - st.issued_at, 30 * 86_400);
}

#[tokio::test(flavor = "multi_thread")]
async fn json_publish_prints_only_the_result() {
    for refuse in [false, true] {
        let (s, school) = new_school().await;
        if refuse {
            *school.refuse_heartbeat.lock().unwrap() =
                Some((500, envelope("unavailable", Value::Null)));
        }
        let home = signed_in(&s.uri());
        let t = tempfile::tempdir().unwrap();
        let (key, kit) = school_key(t.path());
        let dir = folder(t.path(), &s.uri(), &kit);
        let o = run(
            home.path(),
            None,
            &[&"--json", &"--yes", &"publish", &dir, &"--key-file", &key],
        )
        .await;
        let (out, err) = text(&o);
        assert!(o.status.success(), "{out}{err}");
        let v: Value = serde_json::from_str(out.trim()).expect(&out);
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            [
                "digest_hex",
                "heartbeat_not_after",
                "trust_change",
                "version",
                "warnings"
            ]
        );
        assert_eq!(v["version"], 1);
        assert_eq!(
            v["digest_hex"],
            digest_of(&school.held.lock().unwrap().archives[0])
        );
        assert_eq!(v["trust_change"]["added"], json!([kit.trust_key().id]));
        if refuse {
            assert_eq!(v["heartbeat_not_after"], Value::Null);
            assert!(err.contains(STALE), "{err}");
        } else {
            chrono::DateTime::parse_from_rfc3339(v["heartbeat_not_after"].as_str().unwrap())
                .unwrap();
            assert!(!err.contains(STALE), "{err}");
        }
        assert!(
            !out.contains("Check code"),
            "the dialogue is on stderr: {out}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn nobody_to_confirm_sends_nothing() {
    let (s, school) = new_school().await;
    let home = signed_in(&s.uri());
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path());
    let dir = folder(t.path(), &s.uri(), &kit);
    // stdin is a pipe, not a terminal: without --yes nothing goes on, and nothing is read.
    let o = run(home.path(), None, &[&"publish", &dir, &"--key-file", &key]).await;
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(2), "{out}{err}");
    assert!(err.contains("pass --yes"), "{err}");
    let o = run(
        home.path(),
        None,
        &[&"--json", &"publish", &dir, &"--key-file", &key],
    )
    .await;
    let (out, _) = text(&o);
    assert_eq!(o.status.code(), Some(2));
    let v: Value = serde_json::from_str(out.trim()).expect(&out);
    assert_eq!(v["error"]["code"], "usage");
    let o = run(
        home.path(),
        Some(&dir),
        &[&"heartbeat", &"--key-file", &key],
    )
    .await;
    assert_eq!(o.status.code(), Some(2), "{:?}", text(&o));
    assert_eq!(school.held.lock().unwrap().requests, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_without_school_key_uploads_nothing() {
    let (s, school) = new_school().await;
    let home = signed_in(&s.uri());
    let t = tempfile::tempdir().unwrap();
    let (_, kit) = school_key(t.path());
    let dir = folder(t.path(), &s.uri(), &kit);
    let o = run(home.path(), None, &[&"publish", &dir, &"--yes"]).await;
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(2), "{out}{err}");
    assert_eq!(
        err.trim_end(),
        "mastersos: Publishing needs the school key file: mastersos publish --key-file <PATH>"
    );
    assert_eq!(school.held.lock().unwrap().requests, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn feature_gate_refusal_lists_devices() {
    let (s, school) = new_school().await;
    *school.refuse_upload.lock().unwrap() = Some((
        422,
        envelope(
            "feature_unsupported",
            json!({"feature": "kiosk", "devices": [
                {"device_id": "lab-01", "serial": "SN-0001", "os_version": "1.4.0",
                    "last_seen": "2026-11-19T08:00:00Z"}
            ]}),
        ),
    ));
    let home = signed_in(&s.uri());
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path());
    let dir = folder(t.path(), &s.uri(), &kit);
    let o = run(
        home.path(),
        None,
        &[&"publish", &dir, &"--key-file", &key, &"--yes"],
    )
    .await;
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "{out}{err}");
    let table = err.find("DEVICE ID").expect(&err);
    let row = err.find("lab-01").expect(&err);
    assert!(table < row, "{err}");
    for col in [
        "SERIAL",
        "OS VERSION",
        "LAST SEEN",
        "SN-0001",
        "1.4.0",
        "2026-11-19T08:00:00Z",
    ] {
        assert!(err.contains(col), "{col}: {err}");
    }
    assert!(err.contains("`kiosk`"), "{err}");

    let o = run(
        home.path(),
        None,
        &[&"--json", &"--yes", &"publish", &dir, &"--key-file", &key],
    )
    .await;
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "{out}{err}");
    let v: Value = serde_json::from_str(out.trim()).expect(&out);
    assert_eq!(v["error"]["code"], "feature_unsupported");
    assert_eq!(
        v["error"]["problems"],
        json!([{"device_id": "lab-01", "serial": "SN-0001", "os_version": "1.4.0",
            "last_seen": "2026-11-19T08:00:00Z"}])
    );
    assert_eq!(school.held.lock().unwrap().commits, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn heartbeat_signs_the_latest_version() {
    let (s, school) = new_school().await;
    let home = signed_in(&s.uri());
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path());
    let dir = folder(t.path(), &s.uri(), &kit);
    let o = run(
        home.path(),
        None,
        &[&"publish", &dir, &"--key-file", &key, &"--yes"],
    )
    .await;
    assert!(o.status.success(), "{:?}", text(&o));
    let o = run(
        home.path(),
        Some(&dir),
        &[&"heartbeat", &"--key-file", &key, &"--days", &"7", &"--yes"],
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    assert!(
        out.contains("Monthly check-in signed for version 1, valid until"),
        "{out}"
    );
    let held = school.held.lock().unwrap();
    let st = verify_heartbeat(held.heartbeats.last().unwrap(), &[kit.trust_key()]).unwrap();
    assert_eq!(st.version, 1);
    assert_eq!(st.digest_hex, digest_of(&held.archives[0]));
    assert_eq!(st.not_after - st.issued_at, 7 * 86_400);
}

/// No help text of `mastersos` sends IT to a signing page, and none uses the words kept out of
/// IT-facing text.
#[test]
fn help_texts_are_in_plain_words() {
    let mut commands: Vec<Vec<&str>> = vec![vec![]];
    for c in [
        "init", "pull", "check", "diff", "devices", "spec", "publish", "key",
    ] {
        commands.push(vec![c]);
    }
    commands.push(vec!["key", "add"]);
    commands.push(vec!["key", "remove"]);
    for c in commands {
        let o = Command::new(env!("CARGO_BIN_EXE_mastersos"))
            .args(&c)
            .arg("--help")
            .output()
            .unwrap();
        let help = String::from_utf8_lossy(&o.stdout).into_owned();
        assert!(o.status.success(), "{c:?}: {help}");
        // The monthly check-in command keeps its name in the command list.
        let help: String = help
            .lines()
            .filter(|l| !l.trim_start().starts_with("heartbeat "))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !help.to_lowercase().contains("signing page"),
            "{c:?}: {help}"
        );
        plain_words(&help, &[]);
    }
}

/// A fake `arbella` that gives `TOK-PLAIN` for `uri`.
#[cfg(unix)]
fn fake_arbella(bin: &Path, uri: &str) {
    let exe = bin.join("arbella");
    let mut sh = Command::new("sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(&exe)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let script = format!(
        "#!/bin/sh\nprintf '{{\"fleet_url\":\"{uri}\",\"access_token\":\"TOK-PLAIN\",\"expires_at\":\"2099-01-01T00:00:00Z\"}}'\n"
    );
    sh.stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    assert!(sh.wait().unwrap().success());
}

/// With `--yes` and `--key-file` nothing is read from stdin: it is a pipe nobody ever writes to
/// or closes, so a read would hang (the test kills the run after a minute and fails).
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn yes_and_key_file_never_read_stdin() {
    let (s, school) = new_school().await;
    let bin = tempfile::tempdir().unwrap();
    fake_arbella(bin.path(), &s.uri());
    let home = tempfile::tempdir().unwrap();
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path());
    let dir = folder(t.path(), &s.uri(), &kit);
    let run_open = |args: Vec<std::ffi::OsString>| {
        let (home, bin) = (home.path().to_owned(), bin.path().to_owned());
        tokio::task::spawn_blocking(move || {
            let mut child = Command::new(env!("CARGO_BIN_EXE_mastersos"))
                .args(&args)
                .env("HOME", &home)
                .env("APPDATA", &home)
                .env("PATH", &bin)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            // Held open until the child is done.
            let _stdin = child.stdin.take().unwrap();
            let start = std::time::Instant::now();
            loop {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                if start.elapsed() > std::time::Duration::from_secs(60) {
                    child.kill().unwrap();
                    panic!("mastersos waited for stdin");
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            child.wait_with_output().unwrap()
        })
    };
    let os = |v: &[&dyn AsRef<std::ffi::OsStr>]| -> Vec<std::ffi::OsString> {
        v.iter().map(|a| a.as_ref().to_owned()).collect()
    };
    // The two-step publish (pending, commit, check-in), then a check-in of its own.
    let o = run_open(os(&[&"publish", &dir, &"--key-file", &key, &"--yes"]))
        .await
        .unwrap();
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let o = run_open(os(&[
        &"--json",
        &"--yes",
        &"heartbeat",
        &"--key-file",
        &key,
        &"--server",
        &s.uri(),
        &"--school",
        &SID,
    ]))
    .await
    .unwrap();
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let held = school.held.lock().unwrap();
    assert_eq!(held.uploads.len(), 1);
    assert_eq!(held.commits, 1);
    assert_eq!(held.heartbeats.len(), 2);
}

/// Two trust entries holding one public key (under two ids) are refused by the local check, and
/// nothing is uploaded.
#[tokio::test(flavor = "multi_thread")]
async fn a_trust_with_one_public_key_twice_is_refused_before_upload() {
    let (s, school) = new_school().await;
    let home = signed_in(&s.uri());
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path());
    let dir = folder(t.path(), &s.uri(), &kit);
    let tk = kit.trust_key();
    let mut doc = manifest(&dir);
    doc.push_str(&format!(
        "\n[[trust]]\nid = \"{}-again\"\nalg = \"ed25519\"\npublic_key = \"{}\"\n",
        tk.id, tk.public_key
    ));
    std::fs::write(dir.join("manifest.toml"), doc).unwrap();
    let o = run(
        home.path(),
        None,
        &[&"--json", &"publish", &dir, &"--key-file", &key, &"--yes"],
    )
    .await;
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(2), "{out}{err}");
    let v: Value = serde_json::from_str(out.trim()).expect(&out);
    assert_eq!(v["error"]["code"], "check_failed");
    assert!(
        out.contains("trust_duplicate_key"),
        "the issue is named: {out}"
    );
    assert!(school.held.lock().unwrap().uploads.is_empty());
    // `mastersos check` says the same.
    let o = run(home.path(), None, &[&"check", &dir]).await;
    assert_eq!(o.status.code(), Some(2));
    assert!(text(&o).0.contains("trust_duplicate_key"));
}
