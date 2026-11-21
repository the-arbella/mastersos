//! `mastersos login` and `logout`: the device grant against the server's issuer, saved for this
//! user only; tokens never printed.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config_dir(home: &Path) -> PathBuf {
    if cfg!(windows) {
        home.join("mastersos")
    } else {
        home.join(".config").join("mastersos")
    }
}

/// Run `mastersos <args>` with `home` as the home folder and `path` as PATH.
fn mastersos(args: &[&str], home: &Path, path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mastersos"))
        .args(args)
        .env("HOME", home)
        .env("APPDATA", home)
        .env("PATH", path)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

async fn run(args: &[&str], home: &Path, path: &Path) -> Output {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let (home, path) = (home.to_path_buf(), path.to_path_buf());
    tokio::task::spawn_blocking(move || {
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        mastersos(&a, &home, &path)
    })
    .await
    .unwrap()
}

/// A server whose `auth-config` names itself as the issuer, with a device grant that is
/// confirmed at the first poll.
async fn server() -> MockServer {
    let s = MockServer::start().await;
    let uri = s.uri();
    Mock::given(method("GET"))
        .and(path("/api/cli/v1/auth-config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": uri, "client_id": "mastersos-cli", "audience": "fleet-api",
            "scopes": ["openid", "offline_access"], "step_up_acr": ""})))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": uri, "token_endpoint": format!("{uri}/token"),
            "authorization_endpoint": format!("{uri}/authorize"),
            "device_authorization_endpoint": format!("{uri}/device")})))
        .mount(&s)
        .await;
    Mock::given(method("POST"))
        .and(path("/device"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "device_code": "SECRET-DEVICE-CODE", "user_code": "WXYZ-1234",
            "verification_uri": "https://issuer.example/device",
            "expires_in": 600, "interval": 1})))
        .mount(&s)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "SECRET-ACCESS", "token_type": "Bearer", "expires_in": 3600,
            "refresh_token": "SECRET-REFRESH"})))
        .mount(&s)
        .await;
    s
}

fn texts(out: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn login_saves_credentials_and_logout_removes_them() {
    let s = server().await;
    let home = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let out = run(
        &["--json", "login", "--server", &s.uri(), "--no-browser"],
        home.path(),
        bin.path(),
    )
    .await;
    let (stdout, stderr) = texts(&out);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    let v: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["server_url"], s.uri());
    // With --json the code goes to stderr.
    assert!(stderr.contains("WXYZ-1234"), "{stderr}");
    assert!(stderr.contains("https://issuer.example/device"), "{stderr}");
    assert!(!stderr.contains("arbella"), "{stderr}");
    for secret in ["SECRET-ACCESS", "SECRET-REFRESH", "SECRET-DEVICE-CODE"] {
        assert!(!stdout.contains(secret) && !stderr.contains(secret));
    }
    let file = config_dir(home.path()).join("credentials.json");
    let saved: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    assert_eq!(saved["version"], 1);
    assert_eq!(saved["server_url"], s.uri());
    assert_eq!(saved["issuer"], s.uri());
    assert_eq!(saved["access_token"], "SECRET-ACCESS");
    assert_eq!(saved["refresh_token"], "SECRET-REFRESH");
    assert_eq!(saved["scopes"], json!(["openid", "offline_access"]));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&file), 0o600);
        assert_eq!(mode(&config_dir(home.path())), 0o700);
    }

    let out = run(&["logout"], home.path(), bin.path()).await;
    let (stdout, stderr) = texts(&out);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(!file.exists());
    assert!(!stdout.contains("arbella") && !stderr.contains("arbella"));
    // Logging out again is not an error.
    let out = run(&["logout"], home.path(), bin.path()).await;
    assert!(out.status.success(), "{:?}", texts(&out));
}

#[tokio::test(flavor = "multi_thread")]
async fn login_prints_the_code_on_stdout_without_json() {
    let s = server().await;
    let home = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let out = run(
        &["login", "--server", &s.uri(), "--no-browser"],
        home.path(),
        bin.path(),
    )
    .await;
    let (stdout, stderr) = texts(&out);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("WXYZ-1234"), "{stdout}");
    assert!(stdout.contains(&s.uri()), "{stdout}");
    assert!(!stdout.contains("SECRET") && !stderr.contains("SECRET"));
}

#[tokio::test(flavor = "multi_thread")]
async fn login_needs_a_server_origin() {
    let home = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let out = run(&["--json", "login"], home.path(), bin.path()).await;
    assert_eq!(out.status.code(), Some(2));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "usage");
    for bad in ["http://server.example", "https://server.example/org/x"] {
        let out = run(&["login", "--server", bad], home.path(), bin.path()).await;
        assert_eq!(out.status.code(), Some(2), "{bad}: {:?}", texts(&out));
    }
    assert!(!config_dir(home.path()).join("credentials.json").exists());
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn login_with_arbella_installed_says_arbella_is_used_first() {
    use std::io::Write as _;
    let s = server().await;
    let home = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    // Written by a child process: no write handle stays open here.
    let exe = bin.path().join("arbella");
    let mut sh = Command::new("sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(&exe)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    sh.stdin
        .take()
        .unwrap()
        .write_all(b"#!/bin/sh\nexit 3\n")
        .unwrap();
    assert!(sh.wait().unwrap().success());
    let out = run(
        &["login", "--server", &s.uri(), "--no-browser"],
        home.path(),
        bin.path(),
    )
    .await;
    let (stdout, stderr) = texts(&out);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(stderr.contains("arbella"), "{stderr}");
    assert!(config_dir(home.path()).join("credentials.json").exists());
}
