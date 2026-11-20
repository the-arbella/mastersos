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
    hex(&content_digest(&contents_of(upload)))
}

/// What the test server holds: every upload, and the archive of every published version.
#[derive(Default)]
struct Held {
    uploads: Vec<Value>,
    archives: Vec<Vec<u8>>,
}

/// An honest server for one school: it keeps each upload as pending bundle `p-<version>`,
/// publishes it with the signature committed, and serves the published versions back.
#[derive(Clone, Default)]
struct School(Arc<Mutex<Held>>);

impl School {
    fn upload(&self, version: u64) -> Value {
        self.0.lock().unwrap().uploads[version as usize - 1].clone()
    }
}

fn contents_of(upload: &Value) -> Contents {
    let files = upload["files"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(p, b)| (p.clone(), STANDARD.decode(b.as_str().unwrap()).unwrap()))
        .collect::<BTreeMap<_, _>>();
    Contents {
        manifest_text: upload["manifest_text"].as_str().unwrap().to_owned(),
        files,
    }
}

impl Respond for School {
    fn respond(&self, r: &Request) -> ResponseTemplate {
        let mut held = self.0.lock().unwrap();
        let p = r.url.path().to_owned();
        let post = r.method.as_str() == "POST";
        if p == "/v1/admin/versions" {
            let vs: Vec<Value> = (1..=held.archives.len())
                .map(|v| json!({ "version": v }))
                .collect();
            return ResponseTemplate::new(200).set_body_json(vs);
        }
        if let Some(v) = p
            .strip_prefix("/v1/admin/versions/")
            .and_then(|rest| rest.strip_suffix("/archive"))
        {
            let v: usize = v.parse().unwrap();
            return ResponseTemplate::new(200).set_body_bytes(held.archives[v - 1].clone());
        }
        if post && p == "/v1/admin/publish/pending" {
            let up: Value = serde_json::from_slice(&r.body).unwrap();
            let digest = digest_of(&up);
            held.uploads.push(up);
            let v = held.uploads.len();
            return ResponseTemplate::new(200).set_body_json(json!({
                "pending_id": format!("p-{v}"), "version": v, "digest_hex": digest, "lints": []
            }));
        }
        let rest = p.strip_prefix("/v1/admin/publish/pending/p-").unwrap();
        let (v, tail) = rest.split_once('/').unwrap_or((rest, ""));
        let v: usize = v.parse().unwrap();
        let up = held.uploads[v - 1].clone();
        if post && tail == "commit" {
            let body: Value = serde_json::from_slice(&r.body).unwrap();
            let sig: SignatureFile = serde_json::from_value(body["signature"].clone()).unwrap();
            let archive = mastersos_bundle::assemble(&contents_of(&up), &sig).unwrap();
            held.archives.push(archive);
            return ResponseTemplate::new(200).set_body_json(json!({ "version": v }));
        }
        if let Some(file) = tail.strip_prefix("files/") {
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
            "pending_id": format!("p-{v}"), "version": v, "digest_hex": digest_of(&up),
            "manifest_text": up["manifest_text"], "files": files
        }))
    }
}

/// A school that has published nothing, with `kit` registered; the check-in commit answers
/// `checkin_status`.
async fn server(kit: &Kit, checkin_status: u16) -> (MockServer, School) {
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
        json!({ "name": "Alpha School", "slug": "alpha", "school_id": SID }),
    )
    .mount(&s)
    .await;
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
    let school = School::default();
    Mock::given(path_regex(
        "^/v1/admin/(versions(/[0-9]+/archive)?|publish/pending(/p-[0-9]+(/commit|/files/.*)?)?)$",
    ))
    .respond_with(school.clone())
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
    (s, school)
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

async fn checkins(s: &MockServer) -> Vec<Value> {
    s.received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == "/v1/admin/heartbeat/commit")
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect()
}

/// Words IT does not need to see on a normal publish. The diff shows lines of manifest.toml as
/// they are (`[[trust]]`, `escrow_recipients`, `issued_at`): lines that are a line of one of
/// `manifests` after their diff mark are left out; every other line is checked.
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
    // "Trusted keys" is the plain label; any other "trust" is not.
    let lower = shown.to_lowercase().replace("trusted keys", "");
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
    ] {
        assert!(!lower.contains(w), "{w}: {shown}");
    }
}

/// manifest.toml of `dir` as it is now.
fn manifest(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("manifest.toml")).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_with_school_key_signs_checkin() {
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path());
    let (s, school) = server(&kit, 204).await;
    let home = connected_home(&s.uri());
    let dir = folder(home.path(), t.path(), &key).await;
    let o = run(
        home.path(),
        args(&[&"publish", &dir, &"--school-key", &key]),
        "1\nyes\n",
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let digest = digest_of(&school.upload(1));
    // The first version adds the school key: the second question, in plain words.
    assert!(
        out.contains("changes which school keys computers accept and who can unlock their disks")
            && out.contains("type yes: "),
        "{out}"
    );
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
    plain_words(&out, &[manifest(&dir)]);
    plain_words(&err, &[]);
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
    let (s, _) = server(&kit, 500).await;
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
    plain_words(&out, &[manifest(&dir)]);
    plain_words(&err, &[]);
    assert_eq!(checkins(&s).await.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_without_school_key_uploads_nothing() {
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path());
    let (s, school) = server(&kit, 204).await;
    let home = connected_home(&s.uri());
    let dir = folder(home.path(), t.path(), &key).await;
    let before = s.received_requests().await.unwrap().len();
    let o = run(home.path(), args(&[&"publish", &dir]), "").await;
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "{out}{err}");
    assert_eq!(
        err.trim_end(),
        "mastersos: Publishing needs the school key file: mastersos publish --school-key <FILE>"
    );
    assert!(out.is_empty(), "{out}");
    // Nothing was uploaded: no request to create a pending bundle, and none at all after init.
    let reqs = s.received_requests().await.unwrap();
    assert!(
        !reqs
            .iter()
            .any(|r| r.url.path().starts_with("/v1/admin/publish/pending")),
        "{reqs:?}"
    );
    assert_eq!(reqs.len(), before, "no network call at all");
    assert!(school.0.lock().unwrap().uploads.is_empty());
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

#[tokio::test(flavor = "multi_thread")]
async fn publish_later_version_signs_its_checkin() {
    // Version 2 goes through the history check from the record version 1 left on this computer.
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path());
    let (s, school) = server(&kit, 204).await;
    let home = connected_home(&s.uri());
    let dir = folder(home.path(), t.path(), &key).await;
    let o = run(
        home.path(),
        args(&[&"publish", &dir, &"--school-key", &key]),
        "1\nyes\n",
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let v1 = manifest(&dir);
    let edited = v1.replace("name = \"Ungrouped\"", "name = \"Everyone\"");
    assert_ne!(edited, v1);
    std::fs::write(dir.join("manifest.toml"), edited).unwrap();

    // The trusted keys do not change: only the version number is asked for.
    let o = run(
        home.path(),
        args(&[&"publish", &dir, &"--school-key", &key]),
        "2\n",
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let digest = digest_of(&school.upload(2));
    let code = out
        .find(&format!("Check code: {}", &digest[..8]))
        .expect(&out);
    let published = out.find("Published version 2").expect(&out);
    assert!(code < published, "{out}");
    assert!(
        out.contains("The trusted keys are the same as in version 1."),
        "{out}"
    );
    plain_words(&out, &[v1, manifest(&dir)]);
    plain_words(&err, &[]);
    assert!(!err.contains(STALE), "{err}");

    let c = checkins(&s).await;
    assert_eq!(c.len(), 2, "{c:?}");
    let statement: HeartbeatStatement = serde_json::from_value(c[1]["statement"].clone()).unwrap();
    let signature: SignatureFile = serde_json::from_value(c[1]["signature"].clone()).unwrap();
    assert_eq!(statement.version, 2);
    assert_eq!(statement.digest_hex, digest);
    verify_statement(&statement, &signature, &[kit.trust_key()]).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_key_change_answered_no_publishes_nothing() {
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path());
    let (s, school) = server(&kit, 204).await;
    let home = connected_home(&s.uri());
    let dir = folder(home.path(), t.path(), &key).await;
    let before = manifest(&dir);
    let o = run(
        home.path(),
        args(&[&"publish", &dir, &"--school-key", &key]),
        "1\nno\n",
    )
    .await;
    let (out, err) = text(&o);
    assert!(!o.status.success(), "{out}{err}");
    assert!(out.contains("type yes: "), "{out}");
    assert!(
        err.contains("not confirmed") && err.contains("nothing was approved"),
        "{err}"
    );
    assert!(!out.contains("Published version"), "{out}");
    // Nothing signed, nothing published, no check-in; the folder still has nothing published.
    let reqs = s.received_requests().await.unwrap();
    assert!(
        !reqs.iter().any(|r| r.url.path().ends_with("/commit")),
        "{reqs:?}"
    );
    assert!(school.0.lock().unwrap().archives.is_empty());
    assert!(checkins(&s).await.is_empty());
    assert_eq!(manifest(&dir), before);
}

/// Answers the publish commit like [`School`], after removing the folder's record of the upload,
/// so that the folder cannot note the published version.
struct LoseUploadRecord {
    school: School,
    record: PathBuf,
}

impl Respond for LoseUploadRecord {
    fn respond(&self, r: &Request) -> ResponseTemplate {
        std::fs::remove_file(&self.record).unwrap();
        self.school.respond(r)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_checks_in_even_when_the_folder_cannot_record_it() {
    let t = tempfile::tempdir().unwrap();
    let (key, kit) = school_key(t.path());
    let (s, school) = server(&kit, 204).await;
    let home = connected_home(&s.uri());
    let dir = folder(home.path(), t.path(), &key).await;
    Mock::given(method("POST"))
        .and(path("/v1/admin/publish/pending/p-1/commit"))
        .respond_with(LoseUploadRecord {
            school: school.clone(),
            record: dir.join(".mastersos").join("uploaded").join("upload.toml"),
        })
        .with_priority(1)
        .mount(&s)
        .await;
    let o = run(
        home.path(),
        args(&[&"publish", &dir, &"--school-key", &key]),
        "1\nyes\n",
    )
    .await;
    let (out, err) = text(&o);
    // Published on the server and checked in, but the local bookkeeping failed: an error.
    assert_eq!(school.0.lock().unwrap().archives.len(), 1);
    assert_eq!(checkins(&s).await.len(), 1, "{out}{err}");
    assert!(!o.status.success(), "{out}{err}");
    assert!(err.contains("Published version 1"), "{err}");
    assert!(err.contains("could not record"), "{err}");
}

/// No help text of `mastersos` sends IT to a signing page, and none uses the words kept out of
/// IT-facing text.
#[test]
fn help_texts_are_in_plain_words() {
    let mut commands: Vec<Vec<&str>> = vec![vec![]];
    for c in [
        "init", "pull", "check", "diff", "devices", "spec", "publish", "keys", "connect",
    ] {
        commands.push(vec![c]);
    }
    commands.push(vec!["keys", "add"]);
    commands.push(vec!["keys", "remove"]);
    for c in commands {
        let o = Command::new(env!("CARGO_BIN_EXE_mastersos"))
            .args(&c)
            .arg("--help")
            .output()
            .unwrap();
        let help = String::from_utf8_lossy(&o.stdout).into_owned();
        assert!(o.status.success(), "{c:?}: {help}");
        assert!(
            !help.to_lowercase().contains("signing page"),
            "{c:?}: {help}"
        );
        plain_words(&help, &[]);
    }
}
