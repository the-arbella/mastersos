//! `mastersos connect`: the token is checked with `whoami`, then saved with the server address.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn server(who: Value) -> MockServer {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/admin/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(who))
        .mount(&s)
        .await;
    s
}

fn config_dir(home: &std::path::Path) -> PathBuf {
    if cfg!(windows) {
        home.join("mastersos")
    } else {
        home.join(".config").join("mastersos")
    }
}

/// Run `mastersos connect <uri>` with `stdin` as the pasted token and `home` as the home folder.
fn connect(uri: &str, home: &std::path::Path, stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_mastersos"))
        .args(["connect", uri])
        .env("HOME", home)
        .env("APPDATA", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

async fn run(uri: String, home: PathBuf, stdin: &'static str) -> Output {
    tokio::task::spawn_blocking(move || connect(&uri, &home, stdin))
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_saves_token_and_config() {
    let s = server(json!({
        "label": "cli:IT", "kind": "token", "scopes": ["read", "draft"], "school_name": "Alpha School"
    }))
    .await;
    let home = tempfile::tempdir().unwrap();
    let out = run(s.uri(), home.path().to_owned(), "secret-token\n").await;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "{stdout}{stderr}");
    let dir = config_dir(home.path());
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "{stdout}");
    assert_eq!(lines[0], "Connected to Alpha School.");
    assert_eq!(
        lines[1],
        format!("Token saved in {}", dir.join("token").display())
    );
    assert_eq!(
        lines[2],
        format!("Settings saved in {}", dir.join("config.toml").display())
    );
    assert!(dir.join("token").is_absolute());
    assert_eq!(
        std::fs::read_to_string(dir.join("token")).unwrap().trim(),
        "secret-token"
    );
    let cfg: toml::Table = std::fs::read_to_string(dir.join("config.toml"))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(cfg["server"].as_str().unwrap(), s.uri());
    assert_eq!(
        PathBuf::from(cfg["token_file"].as_str().unwrap()),
        dir.join("token")
    );
    // The token never appears in the output.
    assert!(!stdout.contains("secret-token") && !stderr.contains("secret-token"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for f in ["token", "config.toml"] {
            let mode = std::fs::metadata(dir.join(f)).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "{f} is {mode:o}");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_without_school_name_says_the_host() {
    let s =
        server(json!({ "label": "token:it", "kind": "token", "scopes": ["read", "draft"] })).await;
    let home = tempfile::tempdir().unwrap();
    let out = run(s.uri(), home.path().to_owned(), "t\n").await;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(out.status.success(), "{stdout}");
    // An operator-issued `token:` label counts as IT's own.
    assert_eq!(stdout.lines().next(), Some("Connected to 127.0.0.1."));
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_refuses_ai_token() {
    let s =
        server(json!({ "label": "ai:bot", "kind": "token", "scopes": ["read", "draft"] })).await;
    let home = tempfile::tempdir().unwrap();
    let out = run(s.uri(), home.path().to_owned(), "t\n").await;
    assert!(!out.status.success());
    assert!(!config_dir(home.path()).exists(), "nothing may be written");
    assert!(String::from_utf8_lossy(&out.stderr).contains("nothing was saved"));
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_refuses_token_without_draft() {
    let s = server(json!({ "label": "cli:IT", "kind": "token", "scopes": ["read"] })).await;
    let home = tempfile::tempdir().unwrap();
    let out = run(s.uri(), home.path().to_owned(), "t\n").await;
    assert!(!out.status.success());
    assert!(!config_dir(home.path()).exists(), "nothing may be written");
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_refuses_token_with_more_rights() {
    let s = server(json!({
        "label": "cli:IT", "kind": "token", "scopes": ["read", "draft", "recovery"]
    }))
    .await;
    let home = tempfile::tempdir().unwrap();
    let out = run(s.uri(), home.path().to_owned(), "t\n").await;
    assert!(!out.status.success());
    assert!(!config_dir(home.path()).exists(), "nothing may be written");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("more rights than the command line needs")
            && err.contains("nothing was saved"),
        "{err}"
    );
}

#[test]
fn connect_rejects_the_global_server_flag() {
    let home = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_mastersos"))
        .args([
            "connect",
            "https://school.example",
            "--server",
            "https://other.example",
        ])
        .env("HOME", home.path())
        .env("APPDATA", home.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("takes the server address as its argument"),
        "{err}"
    );
    assert!(!config_dir(home.path()).exists());
}

#[test]
fn help_hides_setup_and_uses_school_key_words() {
    let out = Command::new(env!("CARGO_BIN_EXE_mastersos"))
        .arg("--help")
        .output()
        .unwrap();
    let help = String::from_utf8_lossy(&out.stdout).to_lowercase();
    assert!(help.contains("connect"), "{help}");
    assert!(!help.contains("setup"), "{help}");
    let out = Command::new(env!("CARGO_BIN_EXE_mastersos"))
        .args(["publish", "--help"])
        .output()
        .unwrap();
    let help = String::from_utf8_lossy(&out.stdout).to_lowercase();
    assert!(help.contains("--school-key"), "{help}");
    for word in ["heartbeat", "kit", "trust", "escrow", "digest", "0600"] {
        assert!(!help.contains(word), "{word}: {help}");
    }
}
