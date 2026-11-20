//! `mastersos init`, `pull` and `verify` over the protocol v1 CLI API: the school from `--school`,
//! the folder's mastersos.toml or the server's list; the chain verified here; the folder private.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use mastersos_bundle::kit::Kit;
use mastersos_bundle::{pack, trust_fingerprint, Contents, Ed25519Signer, TrustKey};
use mastersos_cli::auth::store::{save_to, StoredLogin};
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SID: &str = "0192f3a4-5b6c-7d8e-9f00-112233445566";
const OTHER: &str = "0192f3a4-5b6c-7d8e-9f00-aabbccddeeff";
const PSK: &str = "wifi-SECRET-psk-77";
const HASH: &str = "$y$j9T$SECRETHASH";

fn config_dir(home: &Path) -> PathBuf {
    if cfg!(windows) {
        home.join("mastersos")
    } else {
        home.join(".config").join("mastersos")
    }
}

fn prefix(school: &str) -> String {
    format!("/api/cli/v1/schools/{school}/mastersos/")
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

fn get(mock_path: String, body: Value) -> Mock {
    Mock::given(method("GET"))
        .and(path(mock_path))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
}

/// The entry of `GET keys` for `kit`.
fn key_entry(kit: &Kit) -> Value {
    let tk = kit.trust_key();
    json!({"key_id": tk.id, "alg": "ed25519", "public_key": tk.public_key,
        "fingerprint": trust_fingerprint(&tk), "label": "key", "created_at": "2026-11-03T09:00:00Z",
        "in_latest_trust": false, "last_used_at": null})
}

/// A school with nothing published, `registered` keys and `schools` listed for the account.
async fn empty_school(registered: &[&Kit], schools: Value) -> MockServer {
    let s = MockServer::start().await;
    get("/api/cli/v1/schools".into(), schools).mount(&s).await;
    for school in [SID, OTHER] {
        get(format!("{}versions", prefix(school)), json!([]))
            .mount(&s)
            .await;
        let keys: Vec<Value> = registered.iter().map(|k| key_entry(k)).collect();
        get(format!("{}keys", prefix(school)), Value::Array(keys))
            .mount(&s)
            .await;
    }
    s
}

fn manifest_trust(dir: &Path) -> (Vec<TrustKey>, Vec<String>, String) {
    #[derive(serde::Deserialize)]
    struct School {
        id: String,
        #[serde(default)]
        escrow_recipients: Vec<String>,
    }
    #[derive(serde::Deserialize)]
    struct M {
        trust: Vec<TrustKey>,
        school: School,
    }
    let m: M =
        toml::from_str(&std::fs::read_to_string(dir.join("manifest.toml")).unwrap()).unwrap();
    (m.trust, m.school.escrow_recipients, m.school.id)
}

/// The fingerprint of `k`, as `--trust-fingerprint` takes it.
fn fp(k: &Ed25519Signer) -> String {
    trust_fingerprint(&k.trust_key())
}

fn meta(dir: &Path) -> Value {
    let t: toml::Value =
        toml::from_str(&std::fs::read_to_string(dir.join("mastersos.toml")).unwrap()).unwrap();
    serde_json::to_value(t).unwrap()
}

/// The folder and its secret-bearing files are the owner's only.
#[cfg(unix)]
fn assert_private(dir: &Path, files: &[&str]) {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(dir), 0o700, "{}", dir.display());
    assert_eq!(mode(&dir.join(".mastersos")), 0o700);
    for f in files {
        assert_eq!(mode(&dir.join(f)), 0o600, "{f}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn init_writes_trust_from_school_keys() {
    let t = tempfile::tempdir().unwrap();
    let (pa, a) = school_key(t.path(), "a.key");
    let (pb, b) = school_key(t.path(), "b.key");
    let s = empty_school(&[&a, &b], json!([])).await;
    let home = signed_in(&s.uri());
    let dir = t.path().join("school");
    let o = run(
        home.path(),
        None,
        &[
            &"init",
            &dir,
            &"--school",
            &SID,
            &"--key-file",
            &pa,
            &"--key-file",
            &pb,
        ],
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let (trust, recipients, id) = manifest_trust(&dir);
    assert_eq!(trust, [a.trust_key(), b.trust_key()]);
    assert_eq!(recipients, [a.escrow_recipient(), b.escrow_recipient()]);
    assert_eq!(id, SID);
    assert_eq!(
        meta(&dir),
        json!({"server": s.uri(), "school_id": SID, "base_version": 0})
    );
    let abs = std::path::absolute(&dir).unwrap().display().to_string();
    assert!(out.contains(&abs), "{out}");
    assert!(out.contains("Trusted keys: "), "{out}");
    assert!(!out.contains("SECRET") && !err.contains("SECRET"));
    #[cfg(unix)]
    assert_private(
        &dir,
        &[
            "manifest.toml",
            "secrets.toml",
            "mastersos.toml",
            ".mastersos/base/manifest.toml",
        ],
    );
    // Only `keys` and `versions` of the school were asked; the folder passes its own check.
    for r in s.received_requests().await.unwrap() {
        assert!(r.url.path().starts_with(&prefix(SID)), "{}", r.url);
        assert_eq!(
            r.headers.get("authorization").unwrap().to_str().unwrap(),
            "Bearer SECRET-ACCESS"
        );
    }
    let o = run(home.path(), None, &[&"check", &dir]).await;
    assert!(o.status.success(), "{:?}", text(&o));
}

#[tokio::test(flavor = "multi_thread")]
async fn init_refuses_an_unregistered_key() {
    let t = tempfile::tempdir().unwrap();
    let (pa, a) = school_key(t.path(), "a.key");
    let (_, other) = school_key(t.path(), "other.key");
    let s = empty_school(&[&other], json!([])).await;
    let home = signed_in(&s.uri());
    let dir = t.path().join("school");
    let o = run(
        home.path(),
        None,
        &[
            &"--json",
            &"init",
            &dir,
            &"--school",
            &SID,
            &"--key-file",
            &pa,
        ],
    )
    .await;
    assert_eq!(o.status.code(), Some(1), "{:?}", text(&o));
    let v = json_of(&o);
    assert_eq!(v["error"]["code"], "key_not_trusted");
    let msg = v["error"]["message"].as_str().unwrap();
    assert!(msg.contains("mastersos key register"), "{msg}");
    assert!(!dir.exists(), "nothing may be written");
    // The same key id listed with another public key is not registered either.
    let mut forged = key_entry(&a);
    forged["public_key"] = json!(other.trust_key().public_key);
    s.reset().await;
    get(format!("{}versions", prefix(SID)), json!([]))
        .mount(&s)
        .await;
    get(format!("{}keys", prefix(SID)), json!([forged]))
        .mount(&s)
        .await;
    let o = run(
        home.path(),
        None,
        &[
            &"--json",
            &"init",
            &dir,
            &"--school",
            &SID,
            &"--key-file",
            &pa,
        ],
    )
    .await;
    assert_eq!(json_of(&o)["error"]["code"], "key_not_trusted");
    assert!(!dir.exists());
}

#[test]
fn init_without_key_points_to_key_new() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join("school");
    let o = mastersos(home.path(), None, &["init".into(), dir.clone().into()]);
    assert_eq!(o.status.code(), Some(2));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("--key-file"), "{err}");
    assert!(err.contains("mastersos key new"), "{err}");
    assert!(err.contains("mastersos key register"), "{err}");
    assert!(!dir.exists(), "nothing may be created");
}

#[tokio::test(flavor = "multi_thread")]
async fn init_takes_the_only_school() {
    let t = tempfile::tempdir().unwrap();
    let (pa, a) = school_key(t.path(), "a.key");
    let s = empty_school(
        &[&a],
        json!([{"id": OTHER, "name": "Beta School", "time_zone": "Asia/Bangkok"}]),
    )
    .await;
    let home = signed_in(&s.uri());
    let dir = t.path().join("school");
    let o = run(home.path(), None, &[&"init", &dir, &"--key-file", &pa]).await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    assert!(out.contains("Beta School") && out.contains(OTHER), "{out}");
    assert_eq!(meta(&dir)["school_id"], OTHER);
    assert_eq!(manifest_trust(&dir).2, OTHER);
}

#[tokio::test(flavor = "multi_thread")]
async fn init_without_a_school_to_administer_is_not_configured() {
    let t = tempfile::tempdir().unwrap();
    let (pa, a) = school_key(t.path(), "a.key");
    let s = empty_school(&[&a], json!([])).await;
    let home = signed_in(&s.uri());
    let dir = t.path().join("school");
    let o = run(
        home.path(),
        None,
        &[&"--json", &"init", &dir, &"--key-file", &pa],
    )
    .await;
    assert_eq!(o.status.code(), Some(1), "{:?}", text(&o));
    let v = json_of(&o);
    assert_eq!(v["error"]["code"], "not_configured");
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("administers no school"));
    assert!(!dir.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn init_with_several_schools_lists_them_without_a_terminal() {
    let t = tempfile::tempdir().unwrap();
    let (pa, a) = school_key(t.path(), "a.key");
    let s = empty_school(
        &[&a],
        json!([{"id": SID, "name": "Alpha School", "time_zone": "UTC"},
               {"id": OTHER, "name": "Beta School", "time_zone": "UTC", "extra": 1}]),
    )
    .await;
    let home = signed_in(&s.uri());
    let dir = t.path().join("school");
    // stdin is not a terminal.
    let o = run(home.path(), None, &[&"init", &dir, &"--key-file", &pa]).await;
    assert_eq!(o.status.code(), Some(2), "{:?}", text(&o));
    let err = text(&o).1;
    for want in [SID, OTHER, "Alpha School", "Beta School", "--school"] {
        assert!(err.contains(want), "{want}: {err}");
    }
    // --json and --yes never ask either.
    for yes in [false, true] {
        let o = if yes {
            run(
                home.path(),
                None,
                &[&"--yes", &"--json", &"init", &dir, &"--key-file", &pa],
            )
            .await
        } else {
            run(
                home.path(),
                None,
                &[&"--json", &"init", &dir, &"--key-file", &pa],
            )
            .await
        };
        assert_eq!(o.status.code(), Some(2), "yes: {yes}");
        let v = json_of(&o);
        assert_eq!(v["error"]["code"], "usage");
        assert_eq!(v["error"]["problems"].as_array().unwrap().len(), 2);
    }
    assert!(!dir.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn init_refuses_a_listed_school_id_that_is_not_lowercase() {
    let t = tempfile::tempdir().unwrap();
    let (pa, a) = school_key(t.path(), "a.key");
    let s = empty_school(
        &[&a],
        json!([{"id": SID.to_uppercase(), "name": "Alpha", "time_zone": "UTC"}]),
    )
    .await;
    let home = signed_in(&s.uri());
    let dir = t.path().join("school");
    let o = run(
        home.path(),
        None,
        &[&"--json", &"init", &dir, &"--key-file", &pa],
    )
    .await;
    assert_eq!(json_of(&o)["error"]["code"], "invalid_answer");
    assert!(!dir.exists());
}

// —— pull and verify ——

/// Version `v` of school `SID`, with a Wi-Fi key and the IT password hash, signed by `k`.
fn version(v: u64, k: &Ed25519Signer, note: &str) -> Vec<u8> {
    let t = k.trust_key();
    let text = format!(
        "format = 2\nversion = {v}\nissued_at = \"2026-11-03T00:00:00Z\"\n\n[[trust]]\nid = \"{}\"\nalg = \"ed25519\"\npublic_key = \"{}\"\n\n[school]\nid = \"{SID}\"\n\n[defaults]\nwifi = [{{ ssid = \"Staff\", psk = \"{PSK}\" }}]\n\n[defaults.it_account]\npassword_hash = \"{HASH}\"\n\n[[config]]\nid = \"default\"\nname = \"Default {note}\"\ninterface = \"learning\"\nlogin_methods = [\"local\"]\n\n[[group]]\nid = \"default\"\nname = \"Ungrouped\"\nconfig = \"default\"\n",
        t.id, t.public_key
    );
    pack(
        &Contents {
            manifest_text: text,
            files: Default::default(),
        },
        k,
    )
    .unwrap()
}

/// A school that published `archives` (version 1, 2, ...).
async fn published(archives: &[Vec<u8>]) -> MockServer {
    let s = MockServer::start().await;
    published_into(&s, archives).await;
    s
}

/// Mount `archives` (version 1, 2, ...) on `s`, each with its version header.
async fn published_into(s: &MockServer, archives: &[Vec<u8>]) {
    let list: Vec<Value> = (1..=archives.len())
        .map(|v| json!({"version": v, "published_at": "2026-11-03T00:00:00Z", "published_by": "it", "signed_by": "k", "digest_hex": "00"}))
        .collect();
    get(format!("{}versions", prefix(SID)), Value::Array(list))
        .mount(s)
        .await;
    for (i, a) in archives.iter().enumerate() {
        let v = (i + 1).to_string();
        Mock::given(method("GET"))
            .and(path(format!("{}versions/{v}/archive", prefix(SID))))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("X-Mastersos-Version", v.as_str())
                    .insert_header("Content-Type", "application/gzip")
                    .set_body_bytes(a.clone()),
            )
            .mount(s)
            .await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pull_writes_meta_with_origin_and_school() {
    let k = Ed25519Signer::from_seed("key-1", &[1; 32]);
    let s = published(&[version(1, &k, "a")]).await;
    let home = signed_in(&s.uri());
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("school");
    let pins = t.path().join("pins");
    let o = run(
        home.path(),
        None,
        &[
            &"--json",
            &"--yes",
            &"--trust-fingerprint",
            &fp(&k),
            &"--pin-dir",
            &pins,
            &"pull",
            &dir,
            &"--school",
            &SID,
        ],
    )
    .await;
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}{err}");
    let v = json_of(&o);
    assert_eq!(v["version"], 1);
    assert_eq!(v["school_id"], SID);
    // No secret value in the output; the fingerprints went to stderr with --json.
    for secret in [PSK, HASH, "SECRETHASH", "SECRET-ACCESS"] {
        assert!(!out.contains(secret) && !err.contains(secret), "{secret}");
    }
    assert!(err.contains(&trust_fingerprint(&k.trust_key())), "{err}");
    assert_eq!(
        meta(&dir),
        json!({"server": s.uri(), "school_id": SID, "base_version": 1})
    );
    let secrets = std::fs::read_to_string(dir.join("secrets.toml")).unwrap();
    assert!(secrets.contains(PSK) && secrets.contains(HASH), "{secrets}");
    let port = reqwest::Url::parse(&s.uri()).unwrap().port().unwrap();
    let pin = pins.join(format!("127.0.0.1_{port}+{SID}.toml"));
    assert!(pin.is_file(), "{}", pin.display());
    #[cfg(unix)]
    {
        assert_private(
            &dir,
            &[
                "manifest.toml",
                "secrets.toml",
                "mastersos.toml",
                ".mastersos/base/manifest.toml",
                ".mastersos/base/secrets.toml",
            ],
        );
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&pin).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    // The folder passes its own check against the pin.
    let o = run(home.path(), None, &[&"--pin-dir", &pins, &"check", &dir]).await;
    assert!(o.status.success(), "{:?}", text(&o));

    // Pulling again takes the server and school from mastersos.toml; another school is refused.
    let o = run(home.path(), None, &[&"--pin-dir", &pins, &"pull", &dir]).await;
    assert!(o.status.success(), "{:?}", text(&o));
    let o = run(
        home.path(),
        None,
        &[
            &"--json",
            &"--pin-dir",
            &pins,
            &"pull",
            &dir,
            &"--school",
            &OTHER,
        ],
    )
    .await;
    assert_eq!(json_of(&o)["error"]["code"], "school_mismatch");
    let o = run(
        home.path(),
        None,
        &[
            &"--json",
            &"--pin-dir",
            &pins,
            &"--server",
            &"https://server.example",
            &"pull",
            &dir,
        ],
    )
    .await;
    assert_eq!(json_of(&o)["error"]["code"], "school_mismatch");
}

#[tokio::test(flavor = "multi_thread")]
async fn first_pull_without_a_person_or_fingerprints_is_refused() {
    let k = Ed25519Signer::from_seed("key-1", &[1; 32]);
    let s = published(&[version(1, &k, "a")]).await;
    let home = signed_in(&s.uri());
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("school");
    let pins = t.path().join("pins");
    // stdin is not a terminal, with or without --yes, or with a wrong fingerprint: not
    // confirmed, nothing written, no pin.
    for extra in [
        &[][..],
        &["--yes"],
        &["--yes", "--trust-fingerprint", "0000-0000-0000-0000"],
    ] {
        let mut args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![&"--json", &"--pin-dir", &pins];
        for e in extra {
            args.push(e);
        }
        args.extend([
            &"pull" as &dyn AsRef<std::ffi::OsStr>,
            &dir,
            &"--school",
            &SID,
        ]);
        let o = run(home.path(), None, &args).await;
        assert_eq!(o.status.code(), Some(1), "{extra:?}");
        assert_eq!(
            json_of(&o)["error"]["code"],
            "trust_not_confirmed",
            "{extra:?}"
        );
        assert!(!dir.join("mastersos.toml").exists());
        let pinned: Vec<_> = std::fs::read_dir(&pins).map_or(Vec::new(), |d| d.collect());
        assert!(pinned.is_empty(), "{pinned:?}");
    }
    assert!(!dir.join("mastersos.toml").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn tampered_version_stops_pull() {
    let k = Ed25519Signer::from_seed("key-1", &[1; 32]);
    let stranger = Ed25519Signer::from_seed("key-1", &[9; 32]);
    let a1 = version(1, &k, "a");
    let s = published(std::slice::from_ref(&a1)).await;
    let home = signed_in(&s.uri());
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("school");
    let pins = t.path().join("pins");
    let o = run(
        home.path(),
        None,
        &[
            &"--yes",
            &"--trust-fingerprint",
            &fp(&k),
            &"--pin-dir",
            &pins,
            &"pull",
            &dir,
            &"--school",
            &SID,
        ],
    )
    .await;
    assert!(o.status.success(), "{:?}", text(&o));
    // Version 2 is signed by a key version 1 does not trust.
    s.reset().await;
    published_into(&s, &[a1, version(2, &stranger, "b")]).await;
    let o = run(
        home.path(),
        None,
        &[&"--json", &"--yes", &"--pin-dir", &pins, &"pull", &dir],
    )
    .await;
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(json_of(&o)["error"]["code"], "chain_tampered");
    assert_eq!(meta(&dir)["base_version"], 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_takes_server_and_school_from_the_folder() {
    let k = Ed25519Signer::from_seed("key-1", &[1; 32]);
    let s = published(&[version(1, &k, "a")]).await;
    let home = signed_in(&s.uri());
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("school");
    let pins = t.path().join("pins");
    let o = run(
        home.path(),
        None,
        &[
            &"--yes",
            &"--trust-fingerprint",
            &fp(&k),
            &"--pin-dir",
            &pins,
            &"pull",
            &dir,
            &"--school",
            &SID,
        ],
    )
    .await;
    assert!(o.status.success(), "{:?}", text(&o));
    let o = run(
        home.path(),
        Some(&dir),
        &[&"--json", &"--pin-dir", &pins, &"verify"],
    )
    .await;
    let v = json_of(&o);
    assert_eq!(v["version"], 1, "{v}");
    assert_eq!(
        v["trust"][0]["fingerprint"],
        trust_fingerprint(&k.trust_key())
    );
    // Outside a settings folder and without --school: no school.
    let o = run(
        home.path(),
        Some(t.path()),
        &[&"--json", &"--pin-dir", &pins, &"verify"],
    )
    .await;
    assert_eq!(json_of(&o)["error"]["code"], "not_configured");
}

/// `init --key-file -` reads the school key from stdin before anything else does.
#[tokio::test(flavor = "multi_thread")]
async fn init_reads_the_key_file_from_stdin() {
    use std::io::Write as _;
    let t = tempfile::tempdir().unwrap();
    let (pa, a) = school_key(t.path(), "a.key");
    let s = empty_school(&[&a], json!([])).await;
    let home = signed_in(&s.uri());
    let dir = t.path().join("school");
    let key_text = std::fs::read(&pa).unwrap();
    let (home_p, dir_p) = (home.path().to_owned(), dir.clone());
    let o = tokio::task::spawn_blocking(move || {
        let mut child = Command::new(env!("CARGO_BIN_EXE_mastersos"))
            .args(["init".as_ref(), dir_p.as_os_str()])
            .args(["--school", SID, "--key-file", "-"])
            .env("HOME", &home_p)
            .env("APPDATA", &home_p)
            .env("PATH", &home_p)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let _ = child.stdin.take().unwrap().write_all(&key_text);
        // A deadlock fails the test instead of hanging the suite.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                panic!("mastersos init --key-file - did not finish");
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap();
    assert!(o.status.success(), "{:?}", text(&o));
    assert_eq!(manifest_trust(&dir).0, [a.trust_key()]);
}

/// `check` and `diff` work offline: they read the pins but never create the pins directory.
#[tokio::test]
async fn offline_commands_do_not_create_the_pins_directory() {
    let home = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    for cmd in ["check", "diff"] {
        let _ = run(home.path(), Some(dir.path()), &[&cmd]).await;
        assert!(
            !home.path().join(".config/mastersos/pins").exists(),
            "{cmd} made the pins directory"
        );
    }
}
