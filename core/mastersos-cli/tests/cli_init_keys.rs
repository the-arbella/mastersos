//! `mastersos key add|remove`: the trusted keys and the disk-unlocking recipients of the local
//! manifest.toml come only from school key files; the server is only asked whether a key is
//! registered (and, for display, which key a recipient is bound to).

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use mastersos_bundle::keyid::key_code;
use mastersos_bundle::kit::Kit;
use mastersos_bundle::{trust_fingerprint, TrustKey};
use mastersos_cli::auth::store::{save_to, StoredLogin};
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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

/// A new school key file in `dir`.
fn school_key(dir: &Path, name: &str) -> (PathBuf, Kit) {
    let p = dir.join(name);
    mastersos_cli::sign::kit::kit_new(&p).unwrap();
    let kit = mastersos_cli::sign::kit::load_kit(&p).unwrap();
    (p, kit)
}

fn code(kit: &Kit) -> String {
    key_code(&kit.key_id()).unwrap()
}

/// A school whose registered school keys are `registered`.
async fn server(registered: &[&Kit]) -> MockServer {
    server_listing(keys_json(registered), json!([])).await
}

/// The server's list of keys with `registered`.
fn keys_json(registered: &[&Kit]) -> Value {
    let keys: Vec<Value> = registered
        .iter()
        .enumerate()
        .map(|(i, k)| {
            let tk = k.trust_key();
            json!({
                "key_id": tk.id, "alg": "ed25519", "public_key": tk.public_key,
                "fingerprint": trust_fingerprint(&tk), "label": format!("key {i}"),
                "created_at": "2026-11-03T09:00:00Z", "in_latest_trust": false,
                "last_used_at": null
            })
        })
        .collect();
    Value::Array(keys)
}

/// A school listing `keys` and `recipients`.
async fn server_listing(keys: Value, recipients: Value) -> MockServer {
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

fn mastersos(home: &Path, args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mastersos"))
        .args(args)
        .env("HOME", home)
        .env("APPDATA", home)
        // No arbella: the saved sign-in is used.
        .env("PATH", home)
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

/// A folder as `init` makes it, trusting the school key at `pa`, for the school on `uri` (built
/// here: `init` itself is tested in cli_init_pull.rs).
async fn folder_with(uri: &str, t: &Path, pa: &Path) -> PathBuf {
    use mastersos_cli::workdir::{set_trusted_keys, template, Meta, Workdir};
    let kit = mastersos_cli::sign::kit::load_kit(pa).unwrap();
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

#[tokio::test(flavor = "multi_thread")]
async fn keys_add_then_remove_round_trip() {
    let t = tempfile::tempdir().unwrap();
    let (pa, a) = school_key(t.path(), "a.key");
    let (pb, b) = school_key(t.path(), "b.key");
    let s = server(&[&a, &b]).await;
    let home = signed_in(&s.uri());
    let dir = folder_with(&s.uri(), t.path(), &pa).await;
    // A comment elsewhere in manifest.toml survives the edits.
    let m = std::fs::read_to_string(dir.join("manifest.toml")).unwrap();
    std::fs::write(
        dir.join("manifest.toml"),
        m.replace("[[group]]", "# my note\n[[group]]"),
    )
    .unwrap();

    let o = run(home.path(), args(&[&"key", &"add", &pb, &"--dir", &dir])).await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    assert!(
        out.contains("Now publish with a school key that is already trusted: mastersos publish --key-file <file>"),
        "{out}"
    );
    let abs = std::path::absolute(&dir).unwrap().display().to_string();
    plain_words(&out.replace("already trusted", "").replace(&abs, ""));
    let (trust, recipients) = manifest(&dir);
    assert_eq!(trust, [a.trust_key(), b.trust_key()]);
    assert_eq!(recipients, [a.escrow_recipient(), b.escrow_recipient()]);

    // Adding it again changes nothing.
    let o = run(home.path(), args(&[&"key", &"add", &pb, &"--dir", &dir])).await;
    assert!(!o.status.success());
    assert_eq!(manifest(&dir).0.len(), 2);

    // The code works with or without its dash.
    let code_b = code(&b).replace('-', "");
    let o = run(
        home.path(),
        args(&[&"key", &"remove", &code_b, &"--dir", &dir]),
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    assert!(out.contains("mastersos publish --key-file <file>"), "{out}");
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
    let home = signed_in(&s.uri());
    let dir = folder_with(&s.uri(), t.path(), &pa).await;
    let before = std::fs::read_to_string(dir.join("manifest.toml")).unwrap();
    let o = run(home.path(), args(&[&"key", &"add", &pb, &"--dir", &dir])).await;
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
    let home = signed_in(&s.uri());
    let dir = folder_with(&s.uri(), t.path(), &pa).await;
    let before = std::fs::read_to_string(dir.join("manifest.toml")).unwrap();
    let o = run(
        home.path(),
        args(&[&"key", &"remove", &code(&a), &"--dir", &dir]),
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
async fn keys_remove_keeps_unmarked_recipients_and_needs_no_server() {
    let t = tempfile::tempdir().unwrap();
    let (pa, a) = school_key(t.path(), "a.key");
    let (pb, b) = school_key(t.path(), "b.key");
    let s = server(&[&a, &b]).await;
    let home = signed_in(&s.uri());
    let dir = folder_with(&s.uri(), t.path(), &pa).await;
    let o = run(home.path(), args(&[&"key", &"add", &pb, &"--dir", &dir])).await;
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
        args(&[&"key", &"remove", &code(&b), &"--dir", &dir]),
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
        out.contains("If you still have that key's file, run again with --key-file <file>"),
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
async fn untagged_folder(
    home: &Path,
    uri: &str,
    t: &Path,
    pa: &Path,
    pb: &Path,
    kits: &[&Kit],
) -> PathBuf {
    let dir = folder_with(uri, t, pa).await;
    let o = run(home, args(&[&"key", &"add", &pb, &"--dir", &dir])).await;
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
    let home = signed_in(&s.uri());
    let dir = untagged_folder(home.path(), &s.uri(), t.path(), &pa, &pb, &[&a, &b]).await;
    // Offline: the file alone says which entry is b's.
    let empty = tempfile::tempdir().unwrap();
    drop(s);
    let o = run(
        empty.path(),
        args(&[
            &"key",
            &"remove",
            &code(&b),
            &"--key-file",
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
    let home = signed_in(&s.uri());
    let dir = untagged_folder(home.path(), &s.uri(), t.path(), &pa, &pb, &[&a, &b]).await;
    let before = std::fs::read_to_string(dir.join("manifest.toml")).unwrap();
    let o = run(
        home.path(),
        args(&[
            &"key",
            &"remove",
            &code(&b),
            &"--key-file",
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
        keys_json(&[&a, &b]),
        json!([
            { "recipient": b.escrow_recipient(), "bound_key_id": b.key_id() },
            { "recipient": a.escrow_recipient(), "bound_key_id": "evil\u{1b}[2J\u{7}id" },
        ]),
    )
    .await;
    let home = signed_in(&s.uri());
    let dir = untagged_folder(home.path(), &s.uri(), t.path(), &pa, &pb, &[&a, &b]).await;
    let before = s.received_requests().await.unwrap().len();
    let o = run(
        home.path(),
        args(&[&"key", &"remove", &code(&b), &"--dir", &dir]),
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
    assert!(out.contains("--key-file <file>"), "{out}");
    assert!(out.contains("by hand"), "{out}");
    // Only reads.
    let reqs = s.received_requests().await.unwrap();
    assert!(
        reqs[before..].iter().all(|r| r.method.as_str() == "GET"),
        "{reqs:?}"
    );
}
