//! The sign-in of `mastersos login`: `~/.config/mastersos/credentials.json` (Windows
//! `%APPDATA%\mastersos\credentials.json`), for this user only (protocol §6).
//!
//! - Written only through [`platform::write_private`] (0600, a new file renamed over the old one)
//!   in a directory [`platform::private_dir`] made or checked (0700, ours, not a link).
//! - Read with [`platform::read_private`]: a link, a file of another user or one others can read
//!   is refused.
//! - A token that ends within 60 seconds is refreshed (`grant_type=refresh_token`) and saved; a
//!   failed refresh is `not_logged_in`.

use std::path::{Path, PathBuf};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use super::oidc::TokenSet;
use crate::platform;
use crate::server::{AuthConfig, CliError};

/// The file name in the settings directory.
pub const FILE_NAME: &str = "credentials.json";
/// The version of the file's form.
pub const VERSION: u32 = 1;
/// The most bytes read from the file.
const MAX_FILE: u64 = 64 * 1024;
/// A token that ends within this many seconds is refreshed first.
const REFRESH_BEFORE: i64 = 60;

/// What `mastersos login` saved.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredLogin {
    pub version: u32,
    pub server_url: String,
    pub issuer: String,
    pub client_id: String,
    pub audience: String,
    pub scopes: Vec<String>,
    pub step_up_acr: String,
    pub access_token: String,
    pub expires_at: String,
    pub refresh_token: Option<String>,
}

/// The tokens never show in Debug output.
impl std::fmt::Debug for StoredLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredLogin")
            .field("version", &self.version)
            .field("server_url", &self.server_url)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("access_token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
}

/// RFC 3339 UTC with seconds and `Z`.
pub(crate) fn timestamp(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

impl StoredLogin {
    /// The sign-in of `server_url` (an origin) with the issuer settings and tokens given.
    pub fn new(server_url: &str, cfg: &AuthConfig, t: &TokenSet) -> StoredLogin {
        StoredLogin {
            version: VERSION,
            server_url: server_url.to_string(),
            issuer: cfg.issuer.clone(),
            client_id: cfg.client_id.clone(),
            audience: cfg.audience.clone(),
            scopes: cfg.scopes.clone(),
            step_up_acr: cfg.step_up_acr.clone(),
            access_token: t.access_token.clone(),
            expires_at: timestamp(t.expires_at),
            refresh_token: t.refresh_token.clone(),
        }
    }

    /// The issuer settings saved at login.
    pub fn auth_config(&self) -> AuthConfig {
        AuthConfig {
            issuer: self.issuer.clone(),
            client_id: self.client_id.clone(),
            audience: self.audience.clone(),
            scopes: self.scopes.clone(),
            step_up_acr: self.step_up_acr.clone(),
        }
    }
}

/// A local file problem: the message names the file, never its content.
fn local(e: anyhow::Error) -> CliError {
    CliError::new("local_file", &e.to_string())
}

/// The credentials file of this user.
pub fn path() -> Result<PathBuf, CliError> {
    platform::config_dir("mastersos")
        .map(|d| d.join(FILE_NAME))
        .map_err(local)
}

pub fn load() -> Result<Option<StoredLogin>, CliError> {
    load_from(&path()?)
}

pub fn save(login: &StoredLogin) -> Result<(), CliError> {
    save_to(&path()?, login)
}

/// Remove the file; whether there was one.
pub fn remove() -> Result<bool, CliError> {
    remove_at(&path()?)
}

/// The directory holding `path`.
fn dir_of(path: &Path) -> Result<&Path, CliError> {
    path.parent()
        .filter(|d| !d.as_os_str().is_empty())
        .ok_or_else(|| CliError::new("local_file", "the credentials file has no directory"))
}

fn unreadable() -> CliError {
    CliError::new(
        "not_logged_in",
        "the saved sign-in cannot be read: run `mastersos login --server <URL>` again",
    )
}

pub fn load_from(path: &Path) -> Result<Option<StoredLogin>, CliError> {
    if !platform::private_dir(dir_of(path)?, false).map_err(local)? {
        return Ok(None);
    }
    let Some(bytes) = platform::read_private(path, MAX_FILE).map_err(local)? else {
        return Ok(None);
    };
    let login: StoredLogin = serde_json::from_slice(&bytes).map_err(|_| unreadable())?;
    if login.version != VERSION {
        return Err(unreadable());
    }
    Ok(Some(login))
}

pub fn save_to(path: &Path, login: &StoredLogin) -> Result<(), CliError> {
    platform::private_dir(dir_of(path)?, true).map_err(local)?;
    let bytes = zeroize::Zeroizing::new(
        serde_json::to_vec_pretty(login)
            .map_err(|_| CliError::new("local_file", "the sign-in cannot be encoded"))?,
    );
    platform::write_private(path, &bytes).map_err(local)
}

pub fn remove_at(path: &Path) -> Result<bool, CliError> {
    if !platform::private_dir(dir_of(path)?, false).map_err(local)? {
        return Ok(false);
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(CliError::new(
            "local_file",
            &format!("cannot remove {}: {e}", path.display()),
        )),
    }
}

/// Whether a token ending at `expires_at` (RFC 3339) must be refreshed at `now`. An unreadable
/// time counts as ended.
pub(crate) fn expires_soon(expires_at: &str, now: DateTime<Utc>) -> bool {
    DateTime::parse_from_rfc3339(expires_at)
        .map(|t| t.with_timezone(&Utc) - now < chrono::Duration::seconds(REFRESH_BEFORE))
        .unwrap_or(true)
}

/// The stored sign-in in use: refreshed and saved again when its token ends soon.
pub struct Session {
    path: PathBuf,
    login: tokio::sync::Mutex<StoredLogin>,
    open_browser: bool,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Session(<redacted>)")
    }
}

impl Session {
    /// `open_browser`: the step-up opens the browser (the address is printed either way).
    pub fn new(path: PathBuf, login: StoredLogin, open_browser: bool) -> Session {
        Session {
            path,
            login: tokio::sync::Mutex::new(login),
            open_browser,
        }
    }

    /// The server origin this sign-in is for.
    pub async fn server_url(&self) -> String {
        self.login.lock().await.server_url.clone()
    }

    /// The access token, refreshed first when it ends within 60 seconds.
    pub async fn token(&self) -> Result<String, CliError> {
        let mut login = self.login.lock().await;
        if !expires_soon(&login.expires_at, Utc::now()) {
            return Ok(login.access_token.clone());
        }
        let again = format!(
            "run `mastersos login --server {}` again",
            crate::safe::field(&login.server_url)
        );
        let ended = |why: &str| CliError::new("not_logged_in", &format!("{why}: {again}"));
        let Some(rt) = login.refresh_token.clone() else {
            return Err(ended("the sign-in has ended"));
        };
        let d = super::oidc::discover(&login.issuer)
            .await
            .map_err(|_| ended("the sign-in could not be renewed"))?;
        let t = super::oidc::refresh(&d, &login.client_id, &rt)
            .await
            .map_err(|_| ended("the sign-in could not be renewed"))?;
        login.access_token = t.access_token;
        login.expires_at = timestamp(t.expires_at);
        if let Some(r) = t.refresh_token {
            login.refresh_token = Some(r);
        }
        // Known race (deferred): two processes refreshing at once may each rotate the refresh token.
        save_to(&self.path, &login)?;
        Ok(login.access_token.clone())
    }

    /// A fresh sign-in in the browser (the loopback step-up). Its token is kept in memory only;
    /// the saved sign-in (tokens and refresh token) is not changed.
    pub async fn step_up(&self) -> Result<String, CliError> {
        let cfg = self.login.lock().await.auth_config();
        let d = super::oidc::discover(&cfg.issuer).await?;
        let t = super::oidc::loopback_step_up(&cfg, &d, self.open_browser).await?;
        Ok(t.access_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path as wpath};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    pub(crate) fn login(server: &str, issuer: &str, expires_at: &str) -> StoredLogin {
        StoredLogin {
            version: 1,
            server_url: server.into(),
            issuer: issuer.into(),
            client_id: "mastersos-cli".into(),
            audience: "devices".into(),
            scopes: vec!["openid".into()],
            step_up_acr: String::new(),
            access_token: "SECRET-ACCESS".into(),
            expires_at: expires_at.into(),
            refresh_token: Some("SECRET-REFRESH".into()),
        }
    }

    #[test]
    fn stored_login_debug_redacts_tokens() {
        let l = login("https://server.example", "https://issuer.example", "x");
        let d = format!("{l:?}");
        assert!(!d.contains("SECRET"), "{d}");
        assert!(d.contains("https://server.example"), "{d}");
        let s = Session::new(PathBuf::from("/x"), l, false);
        assert!(!format!("{s:?}").contains("SECRET"));
    }

    #[test]
    fn save_load_remove_round_trip() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("mastersos").join(FILE_NAME);
        assert!(load_from(&p).unwrap().is_none());
        assert!(!remove_at(&p).unwrap());
        let l = login("https://server.example", "https://issuer.example", "x");
        save_to(&p, &l).unwrap();
        let back = load_from(&p).unwrap().unwrap();
        assert_eq!(back.access_token, "SECRET-ACCESS");
        assert_eq!(back.server_url, "https://server.example");
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        assert_eq!(v["version"], 1);
        assert!(remove_at(&p).unwrap());
        assert!(!p.exists());
    }

    #[cfg(unix)]
    #[test]
    fn credentials_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("config").join("mastersos");
        let p = dir.join(FILE_NAME);
        save_to(&p, &login("https://server.example", "https://i", "x")).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&p), 0o600);
        assert_eq!(mode(&dir), 0o700);
        // Saved again over a file others could read: owner-only again.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        save_to(&p, &login("https://server.example", "https://i", "x")).unwrap();
        assert_eq!(mode(&p), 0o600);
        // A file others can read is not loaded.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(load_from(&p).unwrap_err().code, "local_file");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_credentials_or_directory_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let real = t.path().join("real");
        save_to(
            &real.join(FILE_NAME),
            &login("https://server.example", "https://i", "x"),
        )
        .unwrap();
        // The file is a link.
        let dir = t.path().join("mastersos");
        std::fs::create_dir(&dir).unwrap();
        let p = dir.join(FILE_NAME);
        std::os::unix::fs::symlink(real.join(FILE_NAME), &p).unwrap();
        let e = load_from(&p).unwrap_err();
        assert_eq!(e.code, "local_file");
        assert!(!format!("{e:?}").contains("SECRET"), "{e:?}");
        // Saving replaces the link itself; the file it pointed at is untouched.
        let other = login("https://other.example", "https://i", "x");
        save_to(&p, &other).unwrap();
        assert!(!std::fs::symlink_metadata(&p)
            .unwrap()
            .file_type()
            .is_symlink());
        let kept = load_from(&real.join(FILE_NAME)).unwrap().unwrap();
        assert_eq!(kept.server_url, "https://server.example");
        // The directory is a link.
        let linked = t.path().join("linked");
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        let p = linked.join(FILE_NAME);
        assert_eq!(load_from(&p).unwrap_err().code, "local_file");
        assert_eq!(save_to(&p, &other).unwrap_err().code, "local_file");
        assert_eq!(remove_at(&p).unwrap_err().code, "local_file");
        assert!(real.join(FILE_NAME).exists());
    }

    #[test]
    fn unreadable_or_other_version_is_not_logged_in() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("m").join(FILE_NAME);
        let mut l = login("https://server.example", "https://i", "x");
        l.version = 2;
        save_to(&p, &l).unwrap();
        assert_eq!(load_from(&p).unwrap_err().code, "not_logged_in");
        platform::write_private(&p, b"{not json").unwrap();
        assert_eq!(load_from(&p).unwrap_err().code, "not_logged_in");
    }

    #[test]
    fn expiry_window_is_sixty_seconds() {
        let now: DateTime<Utc> = "2026-11-20T10:00:00Z".parse().unwrap();
        assert!(expires_soon("2026-11-20T10:00:59Z", now));
        assert!(!expires_soon("2026-11-20T10:01:01Z", now));
        assert!(expires_soon("2026-11-20T09:00:00Z", now));
        assert!(expires_soon("not a time", now));
    }

    async fn issuer(mock: &MockServer, token: ResponseTemplate) {
        let uri = mock.uri();
        Mock::given(method("GET"))
            .and(wpath("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": uri, "token_endpoint": format!("{uri}/token")})))
            .mount(mock)
            .await;
        Mock::given(method("POST"))
            .and(wpath("/token"))
            .respond_with(token)
            .mount(mock)
            .await;
    }

    #[tokio::test]
    async fn fresh_token_is_used_without_a_request() {
        let mock = MockServer::start().await;
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("m").join(FILE_NAME);
        let later = timestamp(Utc::now() + chrono::Duration::hours(1));
        let s = Session::new(
            p,
            login("https://server.example", &mock.uri(), &later),
            false,
        );
        assert_eq!(s.token().await.unwrap(), "SECRET-ACCESS");
        assert!(mock.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn expiring_token_is_refreshed_and_saved() {
        let mock = MockServer::start().await;
        issuer(
            &mock,
            ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "new-access", "token_type": "Bearer", "expires_in": 3600})),
        )
        .await;
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("m").join(FILE_NAME);
        let soon = timestamp(Utc::now() + chrono::Duration::seconds(30));
        let l = login("https://server.example", &mock.uri(), &soon);
        save_to(&p, &l).unwrap();
        let s = Session::new(p.clone(), l, false);
        assert_eq!(s.token().await.unwrap(), "new-access");
        let saved = load_from(&p).unwrap().unwrap();
        assert_eq!(saved.access_token, "new-access");
        assert!(!expires_soon(&saved.expires_at, Utc::now()));
        // No new refresh token in the answer: the old one is kept.
        assert_eq!(saved.refresh_token.as_deref(), Some("SECRET-REFRESH"));
        let reqs = mock.received_requests().await.unwrap();
        let token_req = reqs.iter().find(|r| r.url.path() == "/token").unwrap();
        let body = String::from_utf8(token_req.body.clone()).unwrap();
        assert!(body.contains("grant_type=refresh_token"), "{body}");
        assert!(body.contains("refresh_token=SECRET-REFRESH"), "{body}");
        // Now fresh: no second refresh.
        assert_eq!(s.token().await.unwrap(), "new-access");
        assert_eq!(mock.received_requests().await.unwrap().len(), reqs.len());
    }

    #[tokio::test]
    async fn rotated_refresh_token_is_saved() {
        let mock = MockServer::start().await;
        issuer(
            &mock,
            ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "a2", "expires_in": 3600, "refresh_token": "r2"})),
        )
        .await;
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("m").join(FILE_NAME);
        let s = Session::new(
            p.clone(),
            login(
                "https://server.example",
                &mock.uri(),
                "2020-01-01T00:00:00Z",
            ),
            false,
        );
        assert_eq!(s.token().await.unwrap(), "a2");
        assert_eq!(
            load_from(&p).unwrap().unwrap().refresh_token.as_deref(),
            Some("r2")
        );
    }

    #[tokio::test]
    async fn failed_refresh_is_not_logged_in() {
        let mock = MockServer::start().await;
        issuer(
            &mock,
            ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_grant"})),
        )
        .await;
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("m").join(FILE_NAME);
        let old = "2020-01-01T00:00:00Z";
        let s = Session::new(
            p.clone(),
            login("https://server.example", &mock.uri(), old),
            false,
        );
        let e = s.token().await.unwrap_err();
        assert_eq!(e.code, "not_logged_in");
        assert!(e.message.contains("mastersos login"), "{e:?}");
        assert!(!format!("{e:?}").contains("SECRET"), "{e:?}");
        // Without a refresh token there is nothing to try.
        let mut l = login("https://server.example", &mock.uri(), old);
        l.refresh_token = None;
        let s = Session::new(p, l, false);
        assert_eq!(s.token().await.unwrap_err().code, "not_logged_in");
    }
}
