//! `mastersos init --school-key` and `mastersos keys add|remove|list`: the trusted keys and the
//! disk-unlocking recipients come only from school key files; the server is only asked whether
//! they are registered.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use mastersos_bundle::keyid::key_code;
use mastersos_bundle::kit::Kit;
use mastersos_bundle::TrustKey;
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SID: &str = "11111111-1111-1111-1111-111111111111";

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
    let cfg = toml::to_string(&json!({
        "server": uri,
        "token_file": token,
    }))
    .unwrap();
    mastersos_sign::platform::write_private(&dir.join("config.toml"), cfg.as_bytes()).unwrap();
    home
}

/// A new school key file in `dir`.
fn school_key(dir: &Path, name: &str) -> (PathBuf, Kit) {
    let p = dir.join(name);
    mastersos_sign::kit::kit_new(&p).unwrap();
    let kit = mastersos_sign::kit::load_kit(&p).unwrap();
    (p, kit)
}

fn code(kit: &Kit) -> String {
    key_code(&kit.key_id()).unwrap()
}

/// A school whose registered school keys are `registered`.
async fn server(registered: &[&Kit]) -> MockServer {
    server_with(signing_keys(registered), registered).await
}

/// The server's list of signing keys with `registered`.
fn signing_keys(registered: &[&Kit]) -> Value {
    let keys: Vec<Value> = registered
        .iter()
        .enumerate()
        .map(|(i, k)| {
            let tk = k.trust_key();
            json!({
                "key_id": tk.id, "kind": "recovery", "alg": "ed25519",
                "fingerprint": mastersos_bundle::trust_fingerprint(&tk),
                "public_key": tk.public_key, "previously_trusted": false,
                "label": format!("key {i}"), "rp_id": null, "synced": false,
                "in_published_trust": false, "created_by": "it",
                "created_at": "2026-11-03T09:00:00Z"
            })
        })
        .collect();
    Value::Array(keys)
}

/// A school listing `keys` as its signing keys and the recipients of `recipients`.
async fn server_with(keys: Value, recipients: &[&Kit]) -> MockServer {
    let recipients: Vec<Value> = recipients
        .iter()
        .map(|k| {
            json!({
                "recipient": k.escrow_recipient(), "bound_key_id": k.key_id(),
                "label": "key", "created_by": "it", "created_at": "2026-11-03T09:00:00Z",
                "in_published": false
            })
        })
        .collect();
    server_listing(keys, Value::Array(recipients)).await
}

/// A school listing `keys` as its signing keys and `recipients` as its recipients.
async fn server_listing(keys: Value, recipients: Value) -> MockServer {
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
    get("/v1/admin/versions", json!([])).mount(&s).await;
    get("/v1/admin/signing-keys", keys).mount(&s).await;
    get("/v1/admin/escrow-recipients", recipients)
        .mount(&s)
        .await;
    s
}

fn mastersos(home: &Path, args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mastersos"))
        .args(args)
        .env("HOME", home)
        .env("APPDATA", home)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

async fn run(home: &Path, args: Vec<std::ffi::OsString>) -> Output {
    let home = home.to_owned();
    tokio::task::spawn_blocking(move || {
        let refs: Vec<&std::ffi::OsStr> = args.iter().map(|a| a.as_os_str()).collect();
        mastersos(&home, &refs)
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

fn manifest(dir: &Path) -> (Vec<TrustKey>, Vec<String>) {
    #[derive(serde::Deserialize)]
    struct School {
        #[serde(default)]
        escrow_recipients: Vec<String>,
    }
    #[derive(serde::Deserialize)]
    struct M {
        trust: Vec<TrustKey>,
        school: School,
    }
    let text = std::fs::read_to_string(dir.join("manifest.toml")).unwrap();
    let m: M = toml::from_str(&text).unwrap();
    (m.trust, m.school.escrow_recipients)
}

/// Trusted-key words IT does not need to see.
fn plain_words(out: &str) {
    let lower = out.to_lowercase().replace("trusted keys:", "");
    for w in ["trust", "kit", "escrow"] {
        assert!(!lower.contains(w), "{w}: {out}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn init_writes_trust_from_school_keys() {
    let t = tempfile::tempdir().unwrap();
    let (pa, a) = school_key(t.path(), "a.key");
    let (pb, b) = school_key(t.path(), "b.key");
    let s = server(&[&a, &b]).await;
    let home = connected_home(&s.uri());
    let dir = t.path().join("school");
    let o = run(
        home.path(),
        args(&[&"init", &dir, &"--school-key", &pa, &"--school-key", &pb]),
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let (trust, recipients) = manifest(&dir);
    assert_eq!(trust, [a.trust_key(), b.trust_key()]);
    assert_eq!(recipients, [a.escrow_recipient(), b.escrow_recipient()]);
    assert!(
        out.contains(&format!("Trusted keys: {}, {}", code(&a), code(&b))),
        "{out}"
    );
    let abs = std::path::absolute(&dir).unwrap().display().to_string();
    assert!(out.contains(&abs), "{out}");
    assert!(
        out.contains("manifest.toml") && out.contains("secrets.toml"),
        "{out}"
    );
    plain_words(&out.replace(&abs, ""));
    // The new folder passes its own check.
    let o = run(home.path(), args(&[&"check", &dir])).await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn init_refuses_unregistered_key() {
    let t = tempfile::tempdir().unwrap();
    let (pa, _a) = school_key(t.path(), "a.key");
    let (_, other) = school_key(t.path(), "other.key");
    let s = server(&[&other]).await;
    let home = connected_home(&s.uri());
    let dir = t.path().join("school");
    let o = run(home.path(), args(&[&"init", &dir, &"--school-key", &pa])).await;
    let (out, err) = text(&o);
    assert!(!o.status.success(), "{out}{err}");
    assert!(
        err.contains("is not registered for")
            && err.contains("mastersos-sign register")
            && !err.contains("signing page"),
        "{err}"
    );
    assert!(err.contains("Alpha School"), "{err}");
    assert!(!dir.exists(), "nothing may be written");
}

#[tokio::test(flavor = "multi_thread")]
async fn init_refuses_key_registered_with_another_public_key() {
    // The server lists the key's id, but with a different public key: not registered.
    let t = tempfile::tempdir().unwrap();
    let (pa, a) = school_key(t.path(), "a.key");
    let (_, other) = school_key(t.path(), "other.key");
    // `a`'s id and recipient are listed, but with `other`'s public key.
    let tk = other.trust_key();
    let s = server_with(
        json!([{
            "key_id": a.key_id(), "kind": "recovery", "alg": "ed25519", "fingerprint": "x",
            "public_key": tk.public_key, "label": "a", "in_published_trust": false,
            "created_at": "2026-11-03T09:00:00Z"
        }]),
        &[&a],
    )
    .await;
    let home = connected_home(&s.uri());
    let dir = t.path().join("school");
    let o = run(home.path(), args(&[&"init", &dir, &"--school-key", &pa])).await;
    assert!(!o.status.success());
    assert!(text(&o).1.contains("is not registered for"));
    assert!(!dir.exists());
}

#[test]
fn init_without_key_points_to_mastersos_sign() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join("school");
    let o = mastersos(home.path(), &["init".as_ref(), dir.as_os_str()]);
    assert!(!o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("--school-key"), "{err}");
    assert!(err.contains("mastersos-sign school-key new"), "{err}");
    assert!(err.contains("mastersos-sign register"), "{err}");
    assert!(!err.contains("signing page"), "{err}");
    assert!(!dir.exists(), "nothing may be created");
}

/// A folder made by `init` trusting `a`.
async fn folder_with(home: &Path, t: &Path, pa: &Path) -> PathBuf {
    let dir = t.join("school");
    let o = run(home, args(&[&"init", &dir, &"--school-key", &pa])).await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    dir
}

#[tokio::test(flavor = "multi_thread")]
async fn keys_add_then_remove_round_trip() {
    let t = tempfile::tempdir().unwrap();
    let (pa, a) = school_key(t.path(), "a.key");
    let (pb, b) = school_key(t.path(), "b.key");
    let s = server(&[&a, &b]).await;
    let home = connected_home(&s.uri());
    let dir = folder_with(home.path(), t.path(), &pa).await;
    // A comment elsewhere in manifest.toml survives the edits.
    let m = std::fs::read_to_string(dir.join("manifest.toml")).unwrap();
    std::fs::write(
        dir.join("manifest.toml"),
        m.replace("[[group]]", "# my note\n[[group]]"),
    )
    .unwrap();

    let o = run(home.path(), args(&[&"keys", &"add", &pb, &"--dir", &dir])).await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    assert!(
        out.contains("Now publish with a school key that is already trusted: mastersos publish --school-key <file>"),
        "{out}"
    );
    let abs = std::path::absolute(&dir).unwrap().display().to_string();
    plain_words(&out.replace("already trusted", "").replace(&abs, ""));
    let (trust, recipients) = manifest(&dir);
    assert_eq!(trust, [a.trust_key(), b.trust_key()]);
    assert_eq!(recipients, [a.escrow_recipient(), b.escrow_recipient()]);

    // Adding it again changes nothing.
    let o = run(home.path(), args(&[&"keys", &"add", &pb, &"--dir", &dir])).await;
    assert!(!o.status.success());
    assert_eq!(manifest(&dir).0.len(), 2);

    // The code works with or without its dash.
    let code_b = code(&b).replace('-', "");
    let o = run(
        home.path(),
        args(&[&"keys", &"remove", &code_b, &"--dir", &dir]),
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    assert!(
        out.contains("mastersos publish --school-key <file>"),
        "{out}"
    );
    let (trust, recipients) = manifest(&dir);
    assert_eq!(trust, [a.trust_key()]);
    assert_eq!(recipients, [a.escrow_recipient()]);
    let m = std::fs::read_to_string(dir.join("manifest.toml")).unwrap();
    assert!(m.contains("# my note\n[[group]]"), "{m}");
}

#[tokio::test(flavor = "multi_thread")]
async fn keys_add_refuses_unregistered_key() {
    let t = tempfile::tempdir().unwrap();
    let (pa, a) = school_key(t.path(), "a.key");
    let (pb, _b) = school_key(t.path(), "b.key");
    let s = server(&[&a]).await;
    let home = connected_home(&s.uri());
    let dir = folder_with(home.path(), t.path(), &pa).await;
    let before = std::fs::read_to_string(dir.join("manifest.toml")).unwrap();
    let o = run(home.path(), args(&[&"keys", &"add", &pb, &"--dir", &dir])).await;
    assert!(!o.status.success());
    assert!(text(&o).1.contains("is not registered for"));
    assert_eq!(
        std::fs::read_to_string(dir.join("manifest.toml")).unwrap(),
        before
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn keys_remove_refuses_last_key() {
    let t = tempfile::tempdir().unwrap();
    let (pa, a) = school_key(t.path(), "a.key");
    let s = server(&[&a]).await;
    let home = connected_home(&s.uri());
    let dir = folder_with(home.path(), t.path(), &pa).await;
    let before = std::fs::read_to_string(dir.join("manifest.toml")).unwrap();
    let o = run(
        home.path(),
        args(&[&"keys", &"remove", &code(&a), &"--dir", &dir]),
    )
    .await;
    let (out, err) = text(&o);
    assert!(!o.status.success(), "{out}{err}");
    assert!(err.contains("cannot remove the last school key"), "{err}");
    assert_eq!(
        std::fs::read_to_string(dir.join("manifest.toml")).unwrap(),
        before
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn keys_list_marks_local_trust() {
    let t = tempfile::tempdir().unwrap();
    let (pa, a) = school_key(t.path(), "a.key");
    let (_, b) = school_key(t.path(), "b.key");
    let s = server(&[&a, &b]).await;
    let home = connected_home(&s.uri());
    let dir = folder_with(home.path(), t.path(), &pa).await;
    let o = run(home.path(), args(&[&"keys", &"list", &"--dir", &dir])).await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let row = |c: &str| {
        out.lines()
            .find(|l| l.starts_with(c))
            .unwrap_or_else(|| panic!("no row for {c}: {out}"))
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    let header = out.lines().next().unwrap();
    assert!(
        header.contains("KEY CODE") && header.contains("IN THIS FOLDER"),
        "{out}"
    );
    let ra = row(&code(&a));
    assert!(ra.contains(&"2026-11-03".to_owned()), "{ra:?}");
    assert_eq!(ra.last().unwrap(), "yes", "{ra:?}");
    assert_eq!(row(&code(&b)).last().unwrap(), "no", "{out}");
    plain_words(&out);
}

#[tokio::test(flavor = "multi_thread")]
async fn keys_remove_keeps_unmarked_recipients_and_needs_no_server() {
    let t = tempfile::tempdir().unwrap();
    let (pa, a) = school_key(t.path(), "a.key");
    let (pb, b) = school_key(t.path(), "b.key");
    let s = server(&[&a, &b]).await;
    let home = connected_home(&s.uri());
    let dir = folder_with(home.path(), t.path(), &pa).await;
    let o = run(home.path(), args(&[&"keys", &"add", &pb, &"--dir", &dir])).await;
    assert!(o.status.success(), "{:?}", text(&o));
    // Written by hand: nothing ties b's recipient to b any more.
    let m = std::fs::read_to_string(dir.join("manifest.toml")).unwrap();
    let tag = format!("# school key {}", code(&b));
    assert!(m.contains(&tag), "{m}");
    std::fs::write(dir.join("manifest.toml"), m.replace(&tag, "# by hand")).unwrap();
    // No config and no token: the command never asks the server.
    let empty = tempfile::tempdir().unwrap();
    drop(s);
    let o = run(
        empty.path(),
        args(&[&"keys", &"remove", &code(&b), &"--dir", &dir]),
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let (trust, recipients) = manifest(&dir);
    assert_eq!(trust, [a.trust_key()]);
    assert_eq!(recipients, [a.escrow_recipient(), b.escrow_recipient()]);
    assert!(out.contains("could not match"), "{out}");
    assert!(out.contains(&b.escrow_recipient()), "{out}");
    assert!(out.contains("by hand"), "{out}");
    assert!(
        out.contains("If you still have that key's file, run again with --school-key <file>"),
        "{out}"
    );
    assert!(!out.contains("the server says"), "{out}");
    assert!(!out.contains(&a.escrow_recipient()), "a's is marked: {out}");
    let abs = std::path::absolute(&dir).unwrap().display().to_string();
    plain_words(
        &out.replace("already trusted", "")
            .replace(&abs, "")
            .replace(&b.escrow_recipient(), ""),
    );
}

/// A folder trusting `a` and `b` whose recipients carry no `# school key` comment (as written
/// before key codes were noted there).
async fn untagged_folder(home: &Path, t: &Path, pa: &Path, pb: &Path, kits: &[&Kit]) -> PathBuf {
    let dir = folder_with(home, t, pa).await;
    let o = run(home, args(&[&"keys", &"add", &pb, &"--dir", &dir])).await;
    assert!(o.status.success(), "{:?}", text(&o));
    let mut m = std::fs::read_to_string(dir.join("manifest.toml")).unwrap();
    for k in kits {
        let tag = format!("# school key {}", code(k));
        assert!(m.contains(&tag), "{m}");
        m = m.replace(&tag, "");
    }
    std::fs::write(dir.join("manifest.toml"), m).unwrap();
    dir
}

#[tokio::test(flavor = "multi_thread")]
async fn keys_remove_with_school_key_file_removes_its_untagged_recipient() {
    let t = tempfile::tempdir().unwrap();
    let (pa, a) = school_key(t.path(), "a.key");
    let (pb, b) = school_key(t.path(), "b.key");
    let s = server(&[&a, &b]).await;
    let home = connected_home(&s.uri());
    let dir = untagged_folder(home.path(), t.path(), &pa, &pb, &[&a, &b]).await;
    // Offline: the file alone says which entry is b's.
    let empty = tempfile::tempdir().unwrap();
    drop(s);
    let o = run(
        empty.path(),
        args(&[
            &"keys",
            &"remove",
            &code(&b),
            &"--school-key",
            &pb,
            &"--dir",
            &dir,
        ]),
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let (trust, recipients) = manifest(&dir);
    assert_eq!(trust, [a.trust_key()]);
    assert_eq!(recipients, [a.escrow_recipient()]);
    assert!(!out.contains("by hand"), "{out}");
    assert!(!out.contains(&a.escrow_recipient()), "{out}");
    let abs = std::path::absolute(&dir).unwrap().display().to_string();
    plain_words(&out.replace("already trusted", "").replace(&abs, ""));
}

#[tokio::test(flavor = "multi_thread")]
async fn keys_remove_refuses_school_key_file_of_another_key() {
    let t = tempfile::tempdir().unwrap();
    let (pa, a) = school_key(t.path(), "a.key");
    let (pb, b) = school_key(t.path(), "b.key");
    let s = server(&[&a, &b]).await;
    let home = connected_home(&s.uri());
    let dir = untagged_folder(home.path(), t.path(), &pa, &pb, &[&a, &b]).await;
    let before = std::fs::read_to_string(dir.join("manifest.toml")).unwrap();
    let o = run(
        home.path(),
        args(&[
            &"keys",
            &"remove",
            &code(&b),
            &"--school-key",
            &pa,
            &"--dir",
            &dir,
        ]),
    )
    .await;
    let (out, err) = text(&o);
    assert!(!o.status.success(), "{out}{err}");
    assert!(
        err.contains(&code(&a)) && err.contains(&code(&b)),
        "names both codes: {err}"
    );
    assert!(err.contains("Nothing was changed"), "{err}");
    assert_eq!(
        std::fs::read_to_string(dir.join("manifest.toml")).unwrap(),
        before
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn keys_remove_shows_what_the_server_says_but_removes_nothing_more() {
    let t = tempfile::tempdir().unwrap();
    let (pa, a) = school_key(t.path(), "a.key");
    let (pb, b) = school_key(t.path(), "b.key");
    // The server ties b's entry to b, and a's entry to a name with control characters.
    let s = server_listing(
        signing_keys(&[&a, &b]),
        json!([
            { "recipient": b.escrow_recipient(), "bound_key_id": b.key_id() },
            { "recipient": a.escrow_recipient(), "bound_key_id": "evil\u{1b}[2J\u{7}id" },
        ]),
    )
    .await;
    let home = connected_home(&s.uri());
    let dir = untagged_folder(home.path(), t.path(), &pa, &pb, &[&a, &b]).await;
    let before = s.received_requests().await.unwrap().len();
    let o = run(
        home.path(),
        args(&[&"keys", &"remove", &code(&b), &"--dir", &dir]),
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    // Only the trusted key goes; both entries stay for IT to decide.
    let (trust, recipients) = manifest(&dir);
    assert_eq!(trust, [a.trust_key()]);
    assert_eq!(recipients, [a.escrow_recipient(), b.escrow_recipient()]);
    let line = |r: &str| {
        out.lines()
            .find(|l| l.contains(r))
            .unwrap_or_else(|| panic!("no line for {r}: {out}"))
            .to_owned()
    };
    assert!(
        line(&b.escrow_recipient())
            .contains(&format!("(the server says: school key {})", code(&b))),
        "{out}"
    );
    let la = line(&a.escrow_recipient());
    assert!(
        la.contains("(the server says: school key evil[2Jid)"),
        "{out}"
    );
    assert!(!out.contains(['\u{1b}', '\u{7}']), "{out:?}");
    assert!(out.contains("--school-key <file>"), "{out}");
    assert!(out.contains("by hand"), "{out}");
    // Only reads.
    let reqs = s.received_requests().await.unwrap();
    assert!(
        reqs[before..].iter().all(|r| r.method.as_str() == "GET"),
        "{reqs:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn keys_list_filters_control_characters() {
    let t = tempfile::tempdir().unwrap();
    let (_, a) = school_key(t.path(), "a.key");
    let tk = a.trust_key();
    let s = server_listing(
        json!([{
            "key_id": "k\u{1b}[31mid", "alg": "ed25519", "public_key": tk.public_key,
            "label": "l\u{1b}[0m", "in_published_trust": false,
            "created_at": "\u{1b}\u{7}2026-11-03T09:00:00Z"
        }]),
        json!([]),
    )
    .await;
    let home = connected_home(&s.uri());
    let o = run(home.path(), args(&[&"keys", &"list"])).await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    assert!(!out.contains(['\u{1b}', '\u{7}']), "{out:?}");
    assert!(out.contains("k[31mid"), "{out}");
    assert!(out.contains("2026-11-03"), "{out}");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn loose_token_file_says_how_to_fix_it() {
    use std::os::unix::fs::PermissionsExt;
    let s = server(&[]).await;
    let home = connected_home(&s.uri());
    let token = config_dir(home.path()).join("token");
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o644)).unwrap();
    let o = run(home.path(), args(&[&"keys", &"list"])).await;
    let (out, err) = text(&o);
    assert!(!o.status.success(), "{out}{err}");
    assert!(err.contains("mastersos connect"), "{err}");
}
