//! `mastersos seed make` and `mastersos seed check` over the protocol v1 CLI API: trust and
//! `min_version` only from the chain verified here, the Group resolved before `POST seed`, the
//! answer checked, the seed written owner-only, and the fetch token never shown.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use mastersos_bundle::{pack, trust_fingerprint, Contents, Ed25519Signer, Seed};
use mastersos_cli::auth::store::{save_to, StoredLogin};
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SID: &str = "0192f3a4-5b6c-7d8e-9f00-112233445566";
const OTHER: &str = "0192f3a4-5b6c-7d8e-9f00-aabbccddeeff";
const PSK: &str = "wifi-SECRET-psk-77";
const PSK_OFFICE: &str = "wifi-OFFICE-psk-88";
const HASH: &str = "$y$j9T$SECRETHASH";
const TOKEN: &str = "FETCH-TOKEN-s3cret-0123456789";

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

fn mastersos(home: &Path, args: &[std::ffi::OsString]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mastersos"))
        .args(args)
        .env("HOME", home)
        .env("APPDATA", home)
        // No arbella: the saved sign-in is used.
        .env("PATH", home)
        .current_dir(home)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

async fn run(home: &Path, args: &[&dyn AsRef<std::ffi::OsStr>]) -> Output {
    let args: Vec<std::ffi::OsString> = args.iter().map(|a| a.as_ref().to_owned()).collect();
    let home = home.to_owned();
    tokio::task::spawn_blocking(move || mastersos(&home, &args))
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

/// No secret anywhere in what the command printed.
fn assert_no_secret(o: &Output, extra: &[&str]) {
    let (out, err) = text(o);
    for s in [TOKEN, PSK, PSK_OFFICE, HASH, "SECRETHASH", "SECRET-ACCESS"]
        .iter()
        .chain(extra)
    {
        assert!(
            !out.contains(s) && !err.contains(s),
            "{s} shown:\n{out}\n{err}"
        );
    }
}

fn fp(k: &Ed25519Signer) -> String {
    trust_fingerprint(&k.trust_key())
}

/// Version `v` of school `SID` trusting `trust`, signed by `signer`: a default Group that signs
/// in locally, and a `staff` Group with SSO and its own Wi-Fi.
fn version(v: u64, trust: &[&Ed25519Signer], signer: &Ed25519Signer) -> Vec<u8> {
    version_with(v, trust, signer, PSK_OFFICE)
}

/// [`version`] with `office_psk` for the `staff` Group's own network.
fn version_with(
    v: u64,
    trust: &[&Ed25519Signer],
    signer: &Ed25519Signer,
    office_psk: &str,
) -> Vec<u8> {
    let mut text = format!("format = 2\nversion = {v}\nissued_at = \"2026-11-03T00:00:00Z\"\n\n");
    for k in trust {
        let t = k.trust_key();
        text.push_str(&format!(
            "[[trust]]\nid = \"{}\"\nalg = \"ed25519\"\npublic_key = \"{}\"\n\n",
            t.id, t.public_key
        ));
    }
    text.push_str(&format!(
        "[school]\nid = \"{SID}\"\nname = \"Alpha School\"\n\n\
         [school.oidc]\nissuer = \"https://issuer.example\"\nclient_id = \"mastersos\"\n\n\
         [defaults]\nwifi = [{{ ssid = \"Staff\", psk = \"{PSK}\" }}]\n\n\
         [defaults.it_account]\npassword_hash = \"{HASH}\"\n\n\
         [[config]]\nid = \"default\"\nname = \"Default\"\ninterface = \"learning\"\nlogin_methods = [\"local\"]\n\n\
         [[config]]\nid = \"staff\"\nname = \"Staff\"\ninterface = \"full\"\nlogin_methods = [\"sso\", \"local\"]\n\
         wifi = [{{ ssid = \"Office\", psk = \"{office_psk}\" }}]\n\n\
         [[group]]\nid = \"default\"\nname = \"Ungrouped\"\nconfig = \"default\"\n\n\
         [[group]]\nid = \"staff\"\nname = \"Staff\"\nconfig = \"staff\"\n"
    ));
    pack(
        &Contents {
            manifest_text: text,
            files: Default::default(),
        },
        signer,
    )
    .unwrap()
}

/// Mount `archives` (version 1, 2, ...) on `s`, each with its version header.
async fn publish(s: &MockServer, archives: &[Vec<u8>]) {
    let list: Vec<Value> = (1..=archives.len())
        .map(|v| json!({"version": v, "published_at": "2026-11-03T00:00:00Z", "published_by": "it", "signed_by": "k", "digest_hex": "00"}))
        .collect();
    Mock::given(method("GET"))
        .and(path(format!("{}versions", prefix())))
        .respond_with(ResponseTemplate::new(200).set_body_json(Value::Array(list)))
        .mount(s)
        .await;
    for (i, a) in archives.iter().enumerate() {
        let v = (i + 1).to_string();
        Mock::given(method("GET"))
            .and(path(format!("{}versions/{v}/archive", prefix())))
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

/// `POST seed` answers `body`.
async fn seed_answer(s: &MockServer, body: Value) {
    Mock::given(method("POST"))
        .and(path(format!("{}seed", prefix())))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(s)
        .await;
}

/// A school that published `archives` and hands out `TOKEN`.
async fn school(archives: &[Vec<u8>]) -> MockServer {
    let s = MockServer::start().await;
    publish(&s, archives).await;
    seed_answer(
        &s,
        json!({"server_url": s.uri(), "school_id": SID, "fetch_token": TOKEN, "later": 1}),
    )
    .await;
    s
}

async fn seed_requests(s: &MockServer) -> Vec<wiremock::Request> {
    s.received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path().ends_with("/seed"))
        .collect()
}

/// `--json --pin-dir PINS --trust-fingerprint FP... seed make --school SID --server URI --out OUT EXTRA...`
async fn make(
    home: &Path,
    s: &MockServer,
    pins: &Path,
    anchors: &[&Ed25519Signer],
    out: &Path,
    extra: &[&str],
) -> Output {
    let fps: Vec<String> = anchors.iter().map(|k| fp(k)).collect();
    let uri = s.uri();
    let mut args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![&"--json", &"--pin-dir", &pins];
    for f in &fps {
        args.push(&"--trust-fingerprint");
        args.push(f);
    }
    args.extend([
        &"seed" as &dyn AsRef<std::ffi::OsStr>,
        &"make",
        &"--school",
        &SID,
        &"--server",
        &uri,
        &"--out",
        &out,
    ]);
    for e in extra {
        args.push(e);
    }
    run(home, &args).await
}

/// `--json --pin-dir PINS seed check FILE --school SID --server URI`
async fn check(home: &Path, s: &MockServer, pins: &Path, file: &Path) -> Output {
    let uri = s.uri();
    run(
        home,
        &[
            &"--json",
            &"--pin-dir",
            &pins,
            &"seed",
            &"check",
            &file,
            &"--school",
            &SID,
            &"--server",
            &uri,
        ],
    )
    .await
}

fn read_seed(p: &Path) -> Seed {
    Seed::parse(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn seed_takes_trust_and_min_version_from_the_latest_verified_version() {
    let k1 = Ed25519Signer::from_seed("key-1", &[1; 32]);
    let k2 = Ed25519Signer::from_seed("key-2", &[2; 32]);
    // Version 2 adds key 2, approved by key 1.
    let s = school(&[version(1, &[&k1], &k1), version(2, &[&k1, &k2], &k1)]).await;
    let home = signed_in(&s.uri());
    let t = tempfile::tempdir().unwrap();
    let (pins, out) = (t.path().join("pins"), t.path().join("school.seed"));
    let o = make(home.path(), &s, &pins, &[&k1, &k2], &out, &[]).await;
    let (stdout, stderr) = text(&o);
    assert!(o.status.success(), "{stdout}{stderr}");
    assert_no_secret(&o, &[]);
    let v = json_of(&o);
    assert_eq!(v["school_id"], SID);
    assert_eq!(v["min_version"], 2);
    assert_eq!(v["group"], Value::Null);
    let shown = v["trust_fingerprints"].to_string();
    assert!(shown.contains(&fp(&k1)) && shown.contains(&fp(&k2)), "{v}");
    assert!(v["out"].as_str().unwrap().ends_with("school.seed"), "{v}");
    assert!(v.get("fetch_token").is_none(), "{v}");

    let seed = read_seed(&out);
    assert_eq!(seed.trust, vec![k1.trust_key(), k2.trust_key()]);
    assert_eq!(seed.min_version, Some(2));
    assert_eq!(seed.server_url, s.uri());
    assert_eq!(seed.school_id.as_deref(), Some(SID));
    assert_eq!(seed.fetch_token.as_deref(), Some(TOKEN));
    assert_eq!(seed.school_name.as_deref(), Some("Alpha School"));
    assert_eq!(seed.group, None);
    // The default Group signs in locally only: no oidc.
    assert!(seed.oidc.is_none());
    assert_eq!(seed.wifi.len(), 1);
    assert_eq!(seed.wifi[0].ssid, "Staff");
    assert!(seed.it_account.is_some());

    // One POST seed, without a body, after the chain was read.
    let reqs = s.received_requests().await.unwrap();
    let at = |p: &str| {
        reqs.iter()
            .rposition(|r| r.url.path().ends_with(p))
            .unwrap()
    };
    let seeds = seed_requests(&s).await;
    assert_eq!(seeds.len(), 1);
    assert_eq!(seeds[0].method.as_str(), "POST");
    assert!(seeds[0].body.is_empty());
    assert!(at("/seed") > at("versions/2/archive"));
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_group_is_refused_before_post_seed() {
    let k1 = Ed25519Signer::from_seed("key-1", &[1; 32]);
    let s = school(&[version(1, &[&k1], &k1)]).await;
    let home = signed_in(&s.uri());
    let t = tempfile::tempdir().unwrap();
    let (pins, out) = (t.path().join("pins"), t.path().join("school.seed"));
    let o = make(home.path(), &s, &pins, &[&k1], &out, &["--group", "nope"]).await;
    assert_eq!(o.status.code(), Some(1), "{:?}", text(&o));
    assert_eq!(json_of(&o)["error"]["code"], "seed_invalid");
    assert!(seed_requests(&s).await.is_empty());
    assert!(!out.exists());

    // Nothing published: refused here, before any fetch token is handed out.
    let empty = school(&[]).await;
    let home = signed_in(&empty.uri());
    let pins = t.path().join("pins-empty");
    let o = make(home.path(), &empty, &pins, &[&k1], &out, &[]).await;
    assert_eq!(o.status.code(), Some(1), "{:?}", text(&o));
    let v = json_of(&o);
    assert_eq!(v["error"]["code"], "no_published_version");
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("publish the first version first"));
    assert!(seed_requests(&empty).await.is_empty());
    assert!(!out.exists());
}

/// A `POST seed` answer for the server at the given address.
type Answer = Box<dyn Fn(&str) -> Value>;

#[tokio::test(flavor = "multi_thread")]
async fn school_id_mismatch_is_refused() {
    let k1 = Ed25519Signer::from_seed("key-1", &[1; 32]);
    let archive = version(1, &[&k1], &k1);
    let long = "x".repeat(257);
    let answers: Vec<Answer> = vec![
        Box::new(|uri| json!({"server_url": uri, "school_id": OTHER, "fetch_token": TOKEN})),
        Box::new(
            |_| json!({"server_url": "https://server.example", "school_id": SID, "fetch_token": TOKEN}),
        ),
        Box::new(
            |uri| json!({"server_url": format!("{uri}/devices"), "school_id": SID, "fetch_token": TOKEN}),
        ),
        Box::new(|uri| json!({"server_url": uri, "school_id": SID, "fetch_token": "FETCH TOKEN"})),
        Box::new(|uri| json!({"server_url": uri, "school_id": SID, "fetch_token": ""})),
        Box::new(move |uri| json!({"server_url": uri, "school_id": SID, "fetch_token": long})),
        Box::new(|uri| json!({"server_url": uri, "school_id": SID})),
    ];
    for (i, answer) in answers.iter().enumerate() {
        let s = MockServer::start().await;
        publish(&s, std::slice::from_ref(&archive)).await;
        seed_answer(&s, answer(&s.uri())).await;
        let home = signed_in(&s.uri());
        let t = tempfile::tempdir().unwrap();
        let (pins, out) = (t.path().join("pins"), t.path().join("school.seed"));
        let o = make(home.path(), &s, &pins, &[&k1], &out, &[]).await;
        assert_eq!(o.status.code(), Some(1), "{i}: {:?}", text(&o));
        assert_eq!(json_of(&o)["error"]["code"], "invalid_answer", "{i}");
        assert_no_secret(&o, &["FETCH TOKEN"]);
        assert!(!out.exists(), "{i}");
        assert_eq!(seed_requests(&s).await.len(), 1, "{i}");
    }
    // The server answers that nothing is published yet.
    let s = MockServer::start().await;
    publish(&s, std::slice::from_ref(&archive)).await;
    Mock::given(method("POST"))
        .and(path(format!("{}seed", prefix())))
        .respond_with(ResponseTemplate::new(409).set_body_json(
            json!({"error": {"code": "no_published_version", "message": "nothing yet"}}),
        ))
        .mount(&s)
        .await;
    let home = signed_in(&s.uri());
    let t = tempfile::tempdir().unwrap();
    let (pins, out) = (t.path().join("pins"), t.path().join("school.seed"));
    let o = make(home.path(), &s, &pins, &[&k1], &out, &[]).await;
    let v = json_of(&o);
    assert_eq!(v["error"]["code"], "no_published_version");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("publish the first version first"),
        "{v}"
    );
    assert!(!out.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn seed_file_is_owner_only_with_header() {
    let k1 = Ed25519Signer::from_seed("key-1", &[1; 32]);
    let s = school(&[version(1, &[&k1], &k1)]).await;
    let home = signed_in(&s.uri());
    let t = tempfile::tempdir().unwrap();
    let (pins, out) = (t.path().join("pins"), t.path().join("staff.seed"));
    let o = make(home.path(), &s, &pins, &[&k1], &out, &["--group", "staff"]).await;
    assert!(o.status.success(), "{:?}", text(&o));
    assert_no_secret(&o, &[]);
    assert_eq!(json_of(&o)["group"], "staff");
    let written = std::fs::read_to_string(&out).unwrap();
    assert!(
        written.starts_with(&format!("# key-1  ed25519  {}\n", fp(&k1))),
        "{written}"
    );
    assert!(written
        .contains("# Compare these fingerprints with the ones IT verified (mastersos verify).\n"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let seed = read_seed(&out);
    assert_eq!(seed.group.as_deref(), Some("staff"));
    assert!(seed.oidc.is_some());
    let ssids: Vec<&str> = seed.wifi.iter().map(|w| w.ssid.as_str()).collect();
    assert!(
        ssids.contains(&"Staff") && ssids.contains(&"Office"),
        "{ssids:?}"
    );

    // An existing file is kept: refused before anything is asked of the server.
    let before = seed_requests(&s).await.len();
    let o = make(home.path(), &s, &pins, &[&k1], &out, &[]).await;
    assert_eq!(o.status.code(), Some(1), "{:?}", text(&o));
    assert_eq!(json_of(&o)["error"]["code"], "local_file");
    assert_eq!(seed_requests(&s).await.len(), before);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), written);
    // --yes replaces it.
    let o = {
        let uri = s.uri();
        let f = fp(&k1);
        run(
            home.path(),
            &[
                &"--json",
                &"--yes",
                &"--pin-dir",
                &pins,
                &"--trust-fingerprint",
                &f,
                &"seed",
                &"make",
                &"--school",
                &SID,
                &"--server",
                &uri,
                &"--out",
                &out,
            ],
        )
        .await
    };
    assert!(o.status.success(), "{:?}", text(&o));
    assert_eq!(read_seed(&out).group, None);

    // A link at the path is never followed, --yes or not.
    #[cfg(unix)]
    {
        let target = t.path().join("elsewhere");
        std::fs::write(&target, "keep\n").unwrap();
        let link = t.path().join("link.seed");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let uri = s.uri();
        let f = fp(&k1);
        let o = run(
            home.path(),
            &[
                &"--json",
                &"--yes",
                &"--pin-dir",
                &pins,
                &"--trust-fingerprint",
                &f,
                &"seed",
                &"make",
                &"--school",
                &SID,
                &"--server",
                &uri,
                &"--out",
                &link,
            ],
        )
        .await;
        assert_eq!(o.status.code(), Some(1), "{:?}", text(&o));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep\n");
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());

        // A folder other users can write to (and not sticky) is refused.
        use std::os::unix::fs::PermissionsExt as _;
        let open = t.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        let o = make(home.path(), &s, &pins, &[&k1], &open.join("x.seed"), &[]).await;
        assert_eq!(o.status.code(), Some(1), "{:?}", text(&o));
        assert_eq!(json_of(&o)["error"]["code"], "local_file");
        assert!(!open.join("x.seed").exists());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn seed_check_accepts_a_fresh_seed() {
    let k1 = Ed25519Signer::from_seed("key-1", &[1; 32]);
    let s = school(&[version(1, &[&k1], &k1)]).await;
    let home = signed_in(&s.uri());
    let t = tempfile::tempdir().unwrap();
    let (pins, out) = (t.path().join("pins"), t.path().join("school.seed"));
    let o = make(home.path(), &s, &pins, &[&k1], &out, &["--group", "staff"]).await;
    assert!(o.status.success(), "{:?}", text(&o));
    let o = check(home.path(), &s, &pins, &out).await;
    assert!(o.status.success(), "{:?}", text(&o));
    assert_no_secret(&o, &[]);
    let v = json_of(&o);
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["problems"], json!([]));
    // For people: the fingerprints, exit 0.
    let uri = s.uri();
    let o = run(
        home.path(),
        &[
            &"--pin-dir",
            &pins,
            &"seed",
            &"check",
            &out,
            &"--school",
            &SID,
            &"--server",
            &uri,
        ],
    )
    .await;
    let (stdout, stderr) = text(&o);
    assert!(o.status.success(), "{stdout}{stderr}");
    assert!(stdout.contains(&fp(&k1)), "{stdout}");
    assert_no_secret(&o, &[]);
    // Checking asks nothing of the seed route.
    assert_eq!(seed_requests(&s).await.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn seed_check_flags_wrong_server_school_and_token_shape() {
    let k1 = Ed25519Signer::from_seed("key-1", &[1; 32]);
    let s = school(&[version(1, &[&k1], &k1)]).await;
    let home = signed_in(&s.uri());
    let t = tempfile::tempdir().unwrap();
    let (pins, out) = (t.path().join("pins"), t.path().join("school.seed"));
    let o = make(home.path(), &s, &pins, &[&k1], &out, &[]).await;
    assert!(o.status.success(), "{:?}", text(&o));
    let mut seed = read_seed(&out);
    seed.server_url = "https://server.example".into();
    seed.school_id = Some(OTHER.into());
    seed.fetch_token = Some("BAD TOKEN with spaces".into());
    let bad = t.path().join("bad.seed");
    std::fs::write(&bad, seed.to_toml_with_header()).unwrap();
    let o = check(home.path(), &s, &pins, &bad).await;
    assert_eq!(o.status.code(), Some(1), "{:?}", text(&o));
    assert_no_secret(&o, &["BAD TOKEN"]);
    let v = json_of(&o);
    assert_eq!(v["ok"], false, "{v}");
    let problems = v["problems"].to_string();
    for word in ["server_url", "school_id", "fetch_token"] {
        assert!(problems.contains(word), "{word}: {problems}");
    }
    assert!(!problems.contains("trust"), "{problems}");

    // A file that is not TOML never echoes its lines.
    let broken = t.path().join("broken.seed");
    std::fs::write(
        &broken,
        format!(
            "server_url = \"{}\"\nfetch_token = \"{TOKEN}\npsk = \"{PSK}\"\n",
            s.uri()
        ),
    )
    .unwrap();
    let o = check(home.path(), &s, &pins, &broken).await;
    assert_eq!(o.status.code(), Some(1), "{:?}", text(&o));
    assert_no_secret(&o, &[]);
}

#[tokio::test(flavor = "multi_thread")]
async fn seed_check_flags_trust_not_in_the_chain() {
    let k1 = Ed25519Signer::from_seed("key-1", &[1; 32]);
    let k2 = Ed25519Signer::from_seed("key-2", &[2; 32]);
    let stranger = Ed25519Signer::from_seed("key-1", &[9; 32]);
    let v1 = version(1, &[&k1], &k1);
    let s = school(std::slice::from_ref(&v1)).await;
    let home = signed_in(&s.uri());
    let t = tempfile::tempdir().unwrap();
    let (pins, out) = (t.path().join("pins"), t.path().join("v1.seed"));
    let o = make(home.path(), &s, &pins, &[&k1], &out, &[]).await;
    assert!(o.status.success(), "{:?}", text(&o));

    // A key the chain does not trust.
    let mut seed = read_seed(&out);
    seed.trust = vec![stranger.trust_key()];
    let wrong = t.path().join("wrong.seed");
    std::fs::write(&wrong, seed.to_toml_with_header()).unwrap();
    let o = check(home.path(), &s, &pins, &wrong).await;
    assert_eq!(o.status.code(), Some(1), "{:?}", text(&o));
    let v = json_of(&o);
    assert_eq!(v["ok"], false);
    assert!(v["problems"].to_string().contains(&fp(&stranger)), "{v}");
    assert_no_secret(&o, &[]);

    // The header names other fingerprints than the body.
    let good = std::fs::read_to_string(&out).unwrap();
    let forged = good.replacen(&fp(&k1), &fp(&stranger), 1);
    let header = t.path().join("header.seed");
    std::fs::write(&header, forged).unwrap();
    let o = check(home.path(), &s, &pins, &header).await;
    assert_eq!(o.status.code(), Some(1), "{:?}", text(&o));
    let v = json_of(&o);
    assert!(v["problems"].to_string().contains("header"), "{v}");

    // min_version after the latest verified version.
    let mut ahead = read_seed(&out);
    ahead.min_version = Some(5);
    let p = t.path().join("ahead.seed");
    std::fs::write(&p, ahead.to_toml_with_header()).unwrap();
    let o = check(home.path(), &s, &pins, &p).await;
    assert_eq!(o.status.code(), Some(1), "{:?}", text(&o));
    assert!(json_of(&o)["problems"].to_string().contains("min_version"));

    // Version 2 adds key 2: the version 1 seed is older but verified here, so it passes with a
    // note; the same trust claiming version 2 does not.
    s.reset().await;
    publish(&s, &[v1, version(2, &[&k1, &k2], &k1)]).await;
    let o = check(home.path(), &s, &pins, &out).await;
    let (stdout, stderr) = text(&o);
    assert!(o.status.success(), "{stdout}{stderr}");
    let v = json_of(&o);
    assert_eq!(v["ok"], true, "{v}");
    assert!(
        v["notes"]
            .to_string()
            .contains("older seed: Devices will update"),
        "{v}"
    );
    let mut claims = read_seed(&out);
    claims.min_version = Some(2);
    let p = t.path().join("claims.seed");
    std::fs::write(&p, claims.to_toml_with_header()).unwrap();
    let o = check(home.path(), &s, &pins, &p).await;
    assert_eq!(o.status.code(), Some(1), "{:?}", text(&o));
    let v = json_of(&o);
    assert!(v["problems"].to_string().contains(&fp(&k2)), "{v}");
}

#[tokio::test(flavor = "multi_thread")]
async fn seed_check_compares_an_older_min_version_with_that_version() {
    let k1 = Ed25519Signer::from_seed("key-1", &[1; 32]);
    let k2 = Ed25519Signer::from_seed("key-2", &[2; 32]);
    // Version 1 trusts keys 1 and 2; version 2 removes key 2.
    let v1 = version(1, &[&k1, &k2], &k1);
    let s = school(std::slice::from_ref(&v1)).await;
    let home = signed_in(&s.uri());
    let t = tempfile::tempdir().unwrap();
    let (pins, out) = (t.path().join("pins"), t.path().join("v1.seed"));
    let o = make(home.path(), &s, &pins, &[&k1, &k2], &out, &[]).await;
    assert!(o.status.success(), "{:?}", text(&o));
    s.reset().await;
    publish(&s, &[v1, version(2, &[&k1], &k1)]).await;

    // The honest version 1 seed: older, passes with the note.
    let o = check(home.path(), &s, &pins, &out).await;
    let v = json_of(&o);
    assert_eq!(v["ok"], true, "{v}");
    assert!(v["notes"].to_string().contains("older seed"), "{v}");

    // The latest trust with min_version 1: a Device would accept version 1 and trust key 2
    // again. Refused, naming key 2.
    let mut mixed = read_seed(&out);
    mixed.trust = vec![k1.trust_key()];
    let p = t.path().join("mixed.seed");
    std::fs::write(&p, mixed.to_toml_with_header()).unwrap();
    let o = check(home.path(), &s, &pins, &p).await;
    assert_eq!(o.status.code(), Some(1), "{:?}", text(&o));
    let v = json_of(&o);
    assert_eq!(v["ok"], false, "{v}");
    assert!(v["problems"].to_string().contains(&fp(&k2)), "{v}");

    // A computer that never verified version 1 cannot check such a seed: refused.
    let fresh = t.path().join("pins-fresh");
    let uri = s.uri();
    let f1 = fp(&k1);
    let o = run(
        home.path(),
        &[
            &"--json",
            &"--pin-dir",
            &fresh,
            &"--trust-fingerprint",
            &f1,
            &"seed",
            &"check",
            &p,
            &"--school",
            &SID,
            &"--server",
            &uri,
        ],
    )
    .await;
    assert_eq!(o.status.code(), Some(1), "{:?}", text(&o));
    let v = json_of(&o);
    assert!(v["problems"].to_string().contains("version 1"), "{v}");
}

#[tokio::test(flavor = "multi_thread")]
async fn seed_check_flags_each_field_a_device_takes() {
    const OTHER_PSK: &str = "other-SECRET-psk-99";
    const OTHER_HASH: &str = "$y$j9T$OTHERSECRETHASH";
    const CLIENT_SECRET: &str = "CLIENT-SECRET-42";
    let k1 = Ed25519Signer::from_seed("key-1", &[1; 32]);
    let v1 = version(1, &[&k1], &k1);
    let s = school(std::slice::from_ref(&v1)).await;
    let home = signed_in(&s.uri());
    let t = tempfile::tempdir().unwrap();
    let (pins, out) = (t.path().join("pins"), t.path().join("staff.seed"));
    let o = make(home.path(), &s, &pins, &[&k1], &out, &["--group", "staff"]).await;
    assert!(o.status.success(), "{:?}", text(&o));
    let good = read_seed(&out);
    let secrets = [OTHER_PSK, OTHER_HASH, "OTHERSECRETHASH", CLIENT_SECRET];

    type Change = Box<dyn Fn(&mut Seed)>;
    let changes: Vec<(&str, Change)> = vec![
        (
            "wifi",
            Box::new(|s: &mut Seed| s.wifi[0].psk = Some(OTHER_PSK.into())),
        ),
        (
            "it_account",
            Box::new(|s: &mut Seed| {
                s.it_account.as_mut().unwrap().password_hash = OTHER_HASH.into()
            }),
        ),
        (
            "oidc",
            Box::new(|s: &mut Seed| {
                s.oidc.as_mut().unwrap().client_secret = Some(CLIENT_SECRET.into())
            }),
        ),
        ("oidc", Box::new(|s: &mut Seed| s.oidc = None)),
        (
            "school_name",
            Box::new(|s: &mut Seed| s.school_name = Some("Beta School".into())),
        ),
        (
            "group",
            Box::new(|s: &mut Seed| s.group = Some("nope".into())),
        ),
    ];
    for (i, (field, change)) in changes.iter().enumerate() {
        let mut seed = good.clone();
        change(&mut seed);
        let p = t.path().join(format!("changed-{i}.seed"));
        std::fs::write(&p, seed.to_toml_with_header()).unwrap();
        let o = check(home.path(), &s, &pins, &p).await;
        assert_eq!(o.status.code(), Some(1), "{field}: {:?}", text(&o));
        assert_no_secret(&o, &secrets);
        let v = json_of(&o);
        assert_eq!(v["ok"], false, "{field}: {v}");
        let problems = v["problems"].to_string();
        assert!(problems.contains(field), "{field}: {problems}");
        assert!(!problems.contains("trust"), "{field}: {problems}");
    }

    // Version 2 changes the office Wi-Fi key: the version 1 seed is older, not tampered: it
    // matches version 1 exactly. The same seed claiming version 2 is refused.
    s.reset().await;
    publish(&s, &[v1, version_with(2, &[&k1], &k1, OTHER_PSK)]).await;
    let o = check(home.path(), &s, &pins, &out).await;
    assert!(o.status.success(), "{:?}", text(&o));
    assert_no_secret(&o, &secrets);
    let v = json_of(&o);
    assert_eq!(v["ok"], true, "{v}");
    assert!(
        v["notes"]
            .to_string()
            .contains("older seed: Devices will update"),
        "{v}"
    );
    let mut claims = good.clone();
    claims.min_version = Some(2);
    let p = t.path().join("claims.seed");
    std::fs::write(&p, claims.to_toml_with_header()).unwrap();
    let o = check(home.path(), &s, &pins, &p).await;
    assert_eq!(o.status.code(), Some(1), "{:?}", text(&o));
    assert_no_secret(&o, &secrets);
    let v = json_of(&o);
    assert!(v["problems"].to_string().contains("wifi"), "{v}");
}

/// Trust is compared as whole entries, not by fingerprint: the same key under another id (same
/// fingerprint) is a different trust entry.
#[tokio::test(flavor = "multi_thread")]
async fn seed_check_compares_trust_entries_not_fingerprints() {
    let k1 = Ed25519Signer::from_seed("key-1", &[1; 32]);
    let s = school(&[version(1, &[&k1], &k1)]).await;
    let home = signed_in(&s.uri());
    let t = tempfile::tempdir().unwrap();
    let (pins, out) = (t.path().join("pins"), t.path().join("school.seed"));
    let o = make(home.path(), &s, &pins, &[&k1], &out, &[]).await;
    assert!(o.status.success(), "{:?}", text(&o));
    let mut seed = read_seed(&out);
    seed.trust[0].id = "key-renamed".into();
    let p = t.path().join("renamed.seed");
    std::fs::write(&p, seed.to_toml_with_header()).unwrap();
    let o = check(home.path(), &s, &pins, &p).await;
    assert_eq!(o.status.code(), Some(1), "{:?}", text(&o));
    let v = json_of(&o);
    assert!(v["problems"].to_string().contains("trusted keys"), "{v}");
}

/// Ruling R23: a seed's Devices verify their first version under the seed's own trust, so a
/// latest version signed by a key that is not among its own trusted keys (key 1 removing itself:
/// an honest server refuses it with `trust_rule`) gives no seed. Refused with `seed_invalid`
/// before `POST seed`, nothing written; once key 2 has signed a version, the seed is made.
#[tokio::test(flavor = "multi_thread")]
async fn seed_needs_a_latest_version_signed_by_its_own_trust() {
    let k1 = Ed25519Signer::from_seed("key-1", &[1; 32]);
    let k2 = Ed25519Signer::from_seed("key-2", &[2; 32]);
    let v1 = version(1, &[&k1], &k1);
    let s = school(std::slice::from_ref(&v1)).await;
    let home = signed_in(&s.uri());
    let t = tempfile::tempdir().unwrap();
    let pins = t.path().join("pins");
    // The pin at version 1, so version 2 is verified forward from it (as key 1 signed it).
    let o = make(
        home.path(),
        &s,
        &pins,
        &[&k1],
        &t.path().join("one.seed"),
        &[],
    )
    .await;
    assert!(o.status.success(), "{:?}", text(&o));

    s.reset().await;
    let v2 = version(2, &[&k2], &k1);
    publish(&s, &[v1.clone(), v2.clone()]).await;
    seed_answer(
        &s,
        json!({"server_url": s.uri(), "school_id": SID, "fetch_token": TOKEN}),
    )
    .await;
    let out = t.path().join("two.seed");
    let o = make(home.path(), &s, &pins, &[], &out, &[]).await;
    assert_eq!(o.status.code(), Some(1), "{:?}", text(&o));
    let v = json_of(&o);
    assert_eq!(v["error"]["code"], "seed_invalid", "{v}");
    let m = v["error"]["message"].as_str().unwrap();
    assert!(m.contains("version 2"), "{m}");
    assert!(m.contains("not among its own trusted keys"), "{m}");
    assert!(m.contains("publish"), "{m}");
    assert!(seed_requests(&s).await.is_empty(), "POST seed was sent");
    assert!(!out.exists());

    s.reset().await;
    publish(&s, &[v1, v2, version(3, &[&k2], &k2)]).await;
    seed_answer(
        &s,
        json!({"server_url": s.uri(), "school_id": SID, "fetch_token": TOKEN}),
    )
    .await;
    let o = make(home.path(), &s, &pins, &[], &out, &[]).await;
    assert!(o.status.success(), "{:?}", text(&o));
    assert_eq!(json_of(&o)["min_version"], 3);
    assert_eq!(read_seed(&out).trust, vec![k2.trust_key()]);
}

/// R23: the package `seed make` checks again must be the version verified here. The server
/// answers version 1's archive with other content the second time: `chain_tampered`, before
/// `POST seed`, nothing written.
#[tokio::test(flavor = "multi_thread")]
async fn seed_refuses_a_package_that_differs_from_the_verified_one() {
    let k1 = Ed25519Signer::from_seed("key-1", &[1; 32]);
    let s = MockServer::start().await;
    let list = json!([{"version": 1, "published_at": "2026-11-03T00:00:00Z", "published_by": "it", "signed_by": "k", "digest_hex": "00"}]);
    Mock::given(method("GET"))
        .and(path(format!("{}versions", prefix())))
        .respond_with(ResponseTemplate::new(200).set_body_json(list))
        .mount(&s)
        .await;
    let archive_route = format!("{}versions/1/archive", prefix());
    for (a, times) in [
        (version(1, &[&k1], &k1), Some(1)),
        (version_with(1, &[&k1], &k1, "another-psk"), None),
    ] {
        let m = Mock::given(method("GET"))
            .and(path(archive_route.as_str()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("X-Mastersos-Version", "1")
                    .set_body_bytes(a),
            );
        match times {
            Some(n) => m.up_to_n_times(n).mount(&s).await,
            None => m.mount(&s).await,
        }
    }
    seed_answer(
        &s,
        json!({"server_url": s.uri(), "school_id": SID, "fetch_token": TOKEN}),
    )
    .await;
    let home = signed_in(&s.uri());
    let t = tempfile::tempdir().unwrap();
    let out = t.path().join("school.seed");
    let o = make(home.path(), &s, &t.path().join("pins"), &[&k1], &out, &[]).await;
    assert_eq!(o.status.code(), Some(1), "{:?}", text(&o));
    let v = json_of(&o);
    assert_eq!(v["error"]["code"], "chain_tampered", "{v}");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("differs from the one verified here"),
        "{v}"
    );
    assert!(seed_requests(&s).await.is_empty(), "POST seed was sent");
    assert!(!out.exists());
}

/// R23: a latest version signed under a key id of its own trust, but whose own entry for that id
/// is another public key, does not verify under its own trust either: the generic message.
#[tokio::test(flavor = "multi_thread")]
async fn seed_refuses_a_version_its_own_trust_does_not_verify() {
    let k1 = Ed25519Signer::from_seed("key-1", &[1; 32]);
    // The same key id, another public key.
    let k1_other = Ed25519Signer::from_seed("key-1", &[3; 32]);
    let v1 = version(1, &[&k1], &k1);
    let s = school(std::slice::from_ref(&v1)).await;
    let home = signed_in(&s.uri());
    let t = tempfile::tempdir().unwrap();
    let pins = t.path().join("pins");
    let o = make(
        home.path(),
        &s,
        &pins,
        &[&k1],
        &t.path().join("one.seed"),
        &[],
    )
    .await;
    assert!(o.status.success(), "{:?}", text(&o));

    s.reset().await;
    publish(&s, &[v1, version(2, &[&k1_other], &k1)]).await;
    seed_answer(
        &s,
        json!({"server_url": s.uri(), "school_id": SID, "fetch_token": TOKEN}),
    )
    .await;
    let out = t.path().join("two.seed");
    let o = make(home.path(), &s, &pins, &[], &out, &[]).await;
    assert_eq!(o.status.code(), Some(1), "{:?}", text(&o));
    let v = json_of(&o);
    assert_eq!(v["error"]["code"], "seed_invalid", "{v}");
    let m = v["error"]["message"].as_str().unwrap();
    assert!(
        m.contains("version 2 does not verify with its own trusted keys"),
        "{m}"
    );
    assert!(!m.contains("not among its own trusted keys"), "{m}");
    assert!(seed_requests(&s).await.is_empty(), "POST seed was sent");
    assert!(!out.exists());
}
