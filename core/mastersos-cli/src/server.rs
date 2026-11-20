//! The protocol v1 CLI API client: `<origin>/api/cli/v1/...`.
//!
//! - The bearer token only goes in the `Authorization` header (marked sensitive): never in a URL,
//!   an error, a log or Debug output.
//! - Answers are data. Errors are read by `code` only; unknown fields are ignored (protocol §2).
//! - No redirects: a compromised server cannot send a request, and the token, elsewhere.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE};
use reqwest::{Method, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::Credentials;
use crate::safe;

/// How long a step-up token is reused by later calls of the same process.
const STEP_UP_REUSE: Duration = Duration::from_secs(4 * 60);
/// The most characters of a server's error message or code kept.
const MAX_ERROR_CHARS: usize = 300;
/// The most bytes read from an error body.
const MAX_ERROR_BODY: usize = 64 * 1024;
/// The most bytes of a JSON answer.
const MAX_JSON_BODY: usize = 4 * 1024 * 1024;
/// The most bytes of an archive download (protocol §4.4).
const MAX_ARCHIVE_BODY: usize = 20 * 1024 * 1024;
/// Total time of a JSON call, and of an upload or download.
const JSON_TIMEOUT: Duration = Duration::from_secs(60);
const BYTES_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const VERSION_HEADER: &str = "x-mastersos-version";

/// An error the command line reports: a server answer or a local failure. `code` is the only thing
/// callers branch on.
#[derive(Debug, Clone, Serialize)]
pub struct CliError {
    pub code: String,
    pub message: String,
    #[serde(skip)]
    pub status: Option<u16>,
    /// The envelope's `details` (e.g. `latest_version` of a `version_conflict`).
    #[serde(skip)]
    pub details: Value,
    pub problems: Vec<Value>,
}

impl CliError {
    pub fn new(code: &str, message: &str) -> CliError {
        CliError {
            code: code.to_string(),
            message: message.to_string(),
            status: None,
            details: Value::Null,
            problems: Vec::new(),
        }
    }

    pub fn usage(message: &str) -> CliError {
        CliError::new("usage", message)
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

/// What `--json` and the terminal show for an error: `(stdout, stderr)`.
pub fn render_error(e: &CliError, json: bool) -> (String, String) {
    if json {
        let v = serde_json::json!({"error": {
            "code": e.code, "message": e.message, "problems": e.problems}});
        return (format!("{v}\n"), String::new());
    }
    let mut err = format!("mastersos: {}\n", safe::field(&e.message));
    // Devices (a feature gate refusal): one row each, in columns.
    if !e.problems.is_empty() && e.problems.iter().all(|p| p.get("device_id").is_some()) {
        const COLUMNS: [(&str, &str); 4] = [
            ("DEVICE ID", "device_id"),
            ("SERIAL", "serial"),
            ("OS VERSION", "os_version"),
            ("LAST SEEN", "last_seen"),
        ];
        let mut rows: Vec<Vec<String>> = vec![COLUMNS.iter().map(|c| c.0.to_owned()).collect()];
        for p in &e.problems {
            rows.push(
                COLUMNS
                    .iter()
                    .map(|c| {
                        p.get(c.1)
                            .and_then(Value::as_str)
                            .map_or("-".to_owned(), safe::field)
                    })
                    .collect(),
            );
        }
        let widths: Vec<usize> = (0..COLUMNS.len())
            .map(|i| rows.iter().map(|r| r[i].chars().count()).max().unwrap_or(0))
            .collect();
        for r in &rows {
            let line: Vec<String> = r
                .iter()
                .zip(&widths)
                .map(|(c, w)| format!("{c:<w$}"))
                .collect();
            err.push_str(&format!("  {}\n", line.join("  ").trim_end()));
        }
        return (String::new(), err);
    }
    for p in &e.problems {
        let line = match p {
            Value::String(s) => s.clone(),
            Value::Object(o) => {
                let get = |k: &str| o.get(k).and_then(Value::as_str);
                match (get("path"), get("message")) {
                    (Some(a), Some(b)) => format!("{a}: {b}"),
                    (None, Some(b)) => b.to_string(),
                    _ => p.to_string(),
                }
            }
            other => other.to_string(),
        };
        err.push_str(&format!("  - {}\n", safe::field(&line)));
    }
    (String::new(), err)
}

/// Print an error: with `--json` on stdout, else `mastersos: <message>` on stderr.
pub fn print_error(e: &CliError, json: bool) {
    let (out, err) = render_error(e, json);
    print!("{out}");
    eprint!("{err}");
}

/// The process exit code for an error: 2 for a local check error or a usage error, else 1. A
/// server answer is always 1, whatever code it carries.
pub fn exit_code(e: &CliError) -> i32 {
    match (e.status, e.code.as_str()) {
        (None, "check_failed" | "reroute_refused" | "usage") => 2,
        _ => 1,
    }
}

/// One URL path segment, percent-encoded: an id cannot leave its own segment. `.` and `..` cannot
/// be written in a segment at all, and an empty segment is no id.
pub fn segment(s: &str) -> Result<String, CliError> {
    if s.is_empty() || s == "." || s == ".." {
        return Err(CliError::usage("an identifier is empty or a dot segment"));
    }
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    Ok(out)
}

pub(crate) fn clean(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(MAX_ERROR_CHARS)
        .collect()
}

/// Exactly `localhost`, `127.0.0.1` and `::1`.
pub(crate) fn is_loopback(url: &Url) -> bool {
    matches!(
        url.host_str().map(str::to_ascii_lowercase).as_deref(),
        Some("localhost" | "127.0.0.1" | "[::1]")
    )
}

/// An origin that passes the bundle's check, `https` or `http` to the loopback only.
pub(crate) fn check_origin(origin: &str) -> Result<Url, CliError> {
    mastersos_bundle::checks::server_origin(origin).map_err(|e| {
        CliError::usage(&format!(
            "the server address is not valid: {}",
            safe::field(&e)
        ))
    })?;
    let url = Url::parse(origin).map_err(|_| CliError::usage("the server address is not a URL"))?;
    require_secure(&url)?;
    Ok(url)
}

pub(crate) fn require_secure(url: &Url) -> Result<(), CliError> {
    if url.scheme() == "https" || (url.scheme() == "http" && is_loopback(url)) {
        Ok(())
    } else {
        Err(CliError::usage(
            "the server address must be https:// (http only to localhost, 127.0.0.1 or ::1)",
        ))
    }
}

/// A lowercase UUID, as `{school}` must be (protocol §4.1).
pub(crate) fn is_school_id(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}

pub(crate) fn build_client() -> Result<reqwest::Client, CliError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(JSON_TIMEOUT)
        .build()
        .map_err(|_| CliError::new("network", "could not build the HTTP client"))
}

fn network_error(e: reqwest::Error) -> CliError {
    CliError::new(
        "network",
        &format!(
            "could not reach the server: {}",
            safe::field(&e.without_url().to_string())
        ),
    )
}

/// The request body of one attempt (rebuilt for a retry).
enum Body<'a> {
    None,
    Json(&'a [u8]),
    Bytes(&'a [u8], &'a str),
}

/// A CLI API client for one server and, for school routes, one school.
pub struct Server {
    origin: Url,
    school: Option<String>,
    creds: Credentials,
    client: reqwest::Client,
    /// A step-up token and when it was obtained.
    step_up: Mutex<Option<(String, Instant)>>,
    now: Box<dyn Fn() -> Instant + Send + Sync>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("origin", &self.origin.as_str())
            .field("school", &self.school)
            .finish_non_exhaustive()
    }
}

impl Server {
    pub fn new(origin: &str, school: Option<&str>, creds: Credentials) -> Result<Server, CliError> {
        let origin = check_origin(origin)?;
        if let Some(s) = school {
            if !is_school_id(s) {
                return Err(CliError::usage("the school id is not a lowercase UUID"));
            }
        }
        Ok(Server {
            origin,
            school: school.map(str::to_string),
            creds,
            client: build_client()?,
            step_up: Mutex::new(None),
            now: Box::new(Instant::now),
        })
    }

    #[cfg(test)]
    fn set_clock(&mut self, now: Box<dyn Fn() -> Instant + Send + Sync>) {
        self.now = now;
    }

    pub fn origin(&self) -> &Url {
        &self.origin
    }

    pub fn school(&self) -> Result<&str, CliError> {
        self.school.as_deref().ok_or_else(|| {
            CliError::new(
                "not_configured",
                "no school is set: run `mastersos init`, or pass --school",
            )
        })
    }

    fn join(&self, prefix: &str, route: &str) -> Result<Url, CliError> {
        let base = self.origin.as_str().trim_end_matches('/');
        let bad = || CliError::usage("the route is not a valid path below the API prefix");
        // No dot segment at all, however it is written: a route is below the prefix by itself.
        let path_part = route.split(['?', '#']).next().unwrap_or_default();
        if path_part.split('/').any(|seg| {
            let seg = seg.to_ascii_lowercase().replace("%2e", ".");
            seg == "." || seg == ".."
        }) {
            return Err(bad());
        }
        let url = Url::parse(&format!("{base}{prefix}{route}")).map_err(|_| bad())?;
        // The joined path must be strictly below the prefix.
        if url.path().len() > prefix.len() && url.path().starts_with(prefix) {
            Ok(url)
        } else {
            Err(bad())
        }
    }

    /// `<origin>/api/cli/v1/schools/<school>/mastersos/<route>`. The route's segments are
    /// already encoded (see [`segment`]). `not_configured` without a school: no request is built.
    pub fn school_url(&self, route: &str) -> Result<Url, CliError> {
        let school = self.school()?;
        self.join(&format!("/api/cli/v1/schools/{school}/mastersos/"), route)
    }

    /// `<origin>/api/cli/v1/<route>`.
    pub fn cli_url(&self, route: &str) -> Result<Url, CliError> {
        self.join("/api/cli/v1/", route)
    }

    /// The token for a call: a fresh-enough step-up token, else the ordinary one.
    async fn current_token(&self) -> Result<String, CliError> {
        let cached = {
            let guard = self.step_up.lock().unwrap_or_else(|p| p.into_inner());
            guard.as_ref().and_then(|(t, at)| {
                ((self.now)().saturating_duration_since(*at) < STEP_UP_REUSE).then(|| t.clone())
            })
        };
        match cached {
            Some(t) => Ok(t),
            None => self.creds.token().await,
        }
    }

    async fn attempt(
        &self,
        method: &Method,
        url: &Url,
        body: &Body<'_>,
        token: &str,
        timeout: Duration,
    ) -> Result<reqwest::Response, CliError> {
        let mut auth = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| CliError::new("not_logged_in", "the access token is unusable"))?;
        auth.set_sensitive(true);
        let mut rb = self
            .client
            .request(method.clone(), url.clone())
            .timeout(timeout)
            .header(AUTHORIZATION, auth);
        rb = match body {
            Body::None if *method == Method::POST => rb.header(CONTENT_LENGTH, "0"),
            Body::None => rb,
            Body::Json(b) => rb.header(CONTENT_TYPE, "application/json").body(b.to_vec()),
            Body::Bytes(b, ct) => rb.header(CONTENT_TYPE, *ct).body(b.to_vec()),
        };
        rb.send().await.map_err(network_error)
    }

    /// One call with the step-up retry: a `401 step_up_required` asks `creds` for a step-up
    /// token once and retries once. A second `step_up_required` is the answer.
    async fn call(
        &self,
        method: Method,
        url: Url,
        body: Body<'_>,
        timeout: Duration,
    ) -> Result<reqwest::Response, CliError> {
        let token = self.current_token().await?;
        let mut res = self.attempt(&method, &url, &body, &token, timeout).await?;
        if res.status().as_u16() == 401 {
            let err = read_error(res).await;
            if err.code != "step_up_required" {
                return Err(err);
            }
            // A cached step-up token the server no longer accepts is replaced like any other.
            let fresh = self.creds.step_up().await?;
            res = self.attempt(&method, &url, &body, &fresh, timeout).await?;
            if res.status().is_success() {
                let mut guard = self.step_up.lock().unwrap_or_else(|p| p.into_inner());
                *guard = Some((fresh, (self.now)()));
            }
        }
        if res.status().is_success() {
            Ok(res)
        } else {
            Err(read_error(res).await)
        }
    }

    async fn json_of<T: DeserializeOwned>(res: reqwest::Response) -> Result<T, CliError> {
        let bytes = read_capped(res, MAX_JSON_BODY).await?;
        // An empty answer reads as `null`: `()` and `Option` accept it.
        let slice: &[u8] = if bytes.is_empty() { b"null" } else { &bytes };
        serde_json::from_slice(slice).map_err(|_| {
            CliError::new(
                "invalid_answer",
                "the server's answer is not what was expected",
            )
        })
    }

    pub async fn get_json<T: DeserializeOwned>(&self, route: &str) -> Result<T, CliError> {
        let url = self.school_url(route)?;
        let res = self
            .call(Method::GET, url, Body::None, JSON_TIMEOUT)
            .await?;
        Self::json_of(res).await
    }

    pub async fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        route: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let bytes = serde_json::to_vec(body)
            .map_err(|_| CliError::new("invalid_answer", "the request body cannot be encoded"))?;
        let url = self.school_url(route)?;
        let res = self
            .call(Method::POST, url, Body::Json(&bytes), JSON_TIMEOUT)
            .await?;
        Self::json_of(res).await
    }

    /// A POST with no body (`Content-Length: 0`).
    pub async fn post_empty<T: DeserializeOwned>(&self, route: &str) -> Result<T, CliError> {
        let url = self.school_url(route)?;
        let res = self
            .call(Method::POST, url, Body::None, JSON_TIMEOUT)
            .await?;
        Self::json_of(res).await
    }

    pub async fn post_bytes<T: DeserializeOwned>(
        &self,
        route: &str,
        bytes: Vec<u8>,
        content_type: &str,
    ) -> Result<T, CliError> {
        let url = self.school_url(route)?;
        let res = self
            .call(
                Method::POST,
                url,
                Body::Bytes(&bytes, content_type),
                BYTES_TIMEOUT,
            )
            .await?;
        Self::json_of(res).await
    }

    pub async fn delete(&self, route: &str) -> Result<(), CliError> {
        let url = self.school_url(route)?;
        self.call(Method::DELETE, url, Body::None, JSON_TIMEOUT)
            .await
            .map(|_| ())
    }

    /// `GET <origin>/api/cli/v1/<route>` as JSON (routes outside a school, such as `schools`).
    pub async fn get_cli_json<T: DeserializeOwned>(&self, route: &str) -> Result<T, CliError> {
        let url = self.cli_url(route)?;
        let res = self
            .call(Method::GET, url, Body::None, JSON_TIMEOUT)
            .await?;
        Self::json_of(res).await
    }

    /// The schools this account administers (`GET /api/cli/v1/schools`); every id must be a
    /// lowercase UUID.
    pub async fn schools(&self) -> Result<Vec<SchoolEntry>, CliError> {
        let list: Vec<SchoolEntry> = self.get_cli_json("schools").await?;
        if list.iter().any(|s| !is_school_id(&s.id)) {
            return Err(CliError::new(
                "invalid_answer",
                "the server listed a school whose id is not a lowercase UUID",
            ));
        }
        Ok(list)
    }

    /// The latest published version (`GET versions`): the largest `version`, 0 when none.
    pub async fn latest_version(&self) -> Result<u64, CliError> {
        #[derive(Deserialize)]
        struct V {
            version: u64,
        }
        let vs: Vec<V> = self.get_json("versions").await?;
        Ok(vs.iter().map(|v| v.version).max().unwrap_or(0))
    }

    /// The signed archive of version `v` (`GET versions/{v}/archive`); its
    /// `X-Mastersos-Version` must be `v`.
    pub async fn version_archive(&self, v: u64) -> Result<Vec<u8>, CliError> {
        let (bytes, header) = self.get_bytes(&format!("versions/{v}/archive")).await?;
        if header != Some(v) {
            return Err(CliError::new(
                "invalid_answer",
                &format!("the server's archive for version {v} is not labelled as version {v}"),
            ));
        }
        Ok(bytes)
    }

    /// The body bytes and the `X-Mastersos-Version` header, when present.
    pub async fn get_bytes(&self, route: &str) -> Result<(Vec<u8>, Option<u64>), CliError> {
        let url = self.school_url(route)?;
        let res = self
            .call(Method::GET, url, Body::None, BYTES_TIMEOUT)
            .await?;
        let version = res
            .headers()
            .get(VERSION_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        let bytes = read_capped(res, MAX_ARCHIVE_BODY).await?;
        Ok((bytes, version))
    }
}

/// One entry of `GET /api/cli/v1/schools` (unknown fields ignored).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct SchoolEntry {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub time_zone: String,
}

/// The body of an answer, read chunk by chunk and refused (`invalid_answer`) as soon as it passes
/// `cap` bytes, also when `Content-Length` announces more.
pub(crate) async fn read_capped(
    mut res: reqwest::Response,
    cap: usize,
) -> Result<Vec<u8>, CliError> {
    let too_big = || CliError::new("invalid_answer", "the server's answer is too large");
    if res.content_length().is_some_and(|n| n > cap as u64) {
        return Err(too_big());
    }
    let mut out = Vec::new();
    while let Some(chunk) = res.chunk().await.map_err(network_error)? {
        if out.len() + chunk.len() > cap {
            return Err(too_big());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Turn a non-success answer into an error: the envelope's `code`, `message` and `details`, or
/// `invalid_answer` (with no body text) when the body is not an envelope.
async fn read_error(res: reqwest::Response) -> CliError {
    let status = res.status().as_u16();
    let mut err = CliError::new(
        "invalid_answer",
        &format!("the server answered HTTP {status} without an error body"),
    );
    err.status = Some(status);
    let Ok(bytes) = read_capped(res, MAX_ERROR_BODY).await else {
        return err;
    };
    #[derive(Deserialize)]
    struct Envelope {
        error: Inner,
    }
    #[derive(Deserialize)]
    struct Inner {
        code: String,
        #[serde(default)]
        message: String,
        #[serde(default)]
        details: Value,
    }
    if let Ok(Envelope { error }) = serde_json::from_slice::<Envelope>(&bytes) {
        let code = clean(&error.code);
        if !code.is_empty() {
            err.code = code;
            err.message = clean(&error.message);
            if err.message.is_empty() {
                err.message = format!("the server refused the request ({})", err.code);
            }
            err.details = error.details;
        }
    }
    err
}

/// What `GET /api/cli/v1/auth-config` answers (unknown fields ignored).
#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    pub issuer: String,
    pub client_id: String,
    pub audience: String,
    pub scopes: Vec<String>,
    pub step_up_acr: String,
}

/// The sign-in settings of a server; no token is sent.
pub async fn auth_config(origin: &Url) -> Result<AuthConfig, CliError> {
    let origin = check_origin(origin.as_str())?;
    let base = origin.as_str().trim_end_matches('/');
    let url = Url::parse(&format!("{base}/api/cli/v1/auth-config"))
        .map_err(|_| CliError::usage("the server address is not a URL"))?;
    let res = build_client()?
        .get(url)
        .send()
        .await
        .map_err(network_error)?;
    if !res.status().is_success() {
        return Err(read_error(res).await);
    }
    Server::json_of(res).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Credentials;
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SCHOOL: &str = "0192f3a4-5b6c-7d8e-9f00-112233445566";
    const PREFIX: &str = "/api/cli/v1/schools/0192f3a4-5b6c-7d8e-9f00-112233445566/mastersos/";

    fn server(creds: Credentials) -> Server {
        Server::new("https://server.example", Some(SCHOOL), creds).unwrap()
    }

    fn local(mock: &MockServer, creds: Credentials) -> Server {
        Server::new(&mock.uri(), Some(SCHOOL), creds).unwrap()
    }

    fn envelope(status: u16, code: &str) -> ResponseTemplate {
        ResponseTemplate::new(status)
            .set_body_json(json!({"error": {"code": code, "message": "m", "extra": 1}}))
    }

    #[test]
    fn school_routes_are_under_the_cli_prefix() {
        let s = server(Credentials::fixed("t"));
        assert_eq!(
            s.school_url("publish/pending").unwrap().as_str(),
            format!("https://server.example{PREFIX}publish/pending")
        );
        assert_eq!(
            s.cli_url("auth-config").unwrap().as_str(),
            "https://server.example/api/cli/v1/auth-config"
        );
    }

    #[test]
    fn device_id_segment_is_encoded() {
        let s = server(Credentials::fixed("t"));
        let seg = segment("a/../b").unwrap();
        assert_eq!(seg, "a%2F..%2Fb");
        assert_eq!(
            s.school_url(&format!("devices/{seg}/recovery-keys"))
                .unwrap()
                .path(),
            format!("{PREFIX}devices/a%2F..%2Fb/recovery-keys")
        );
        assert!(segment("..").is_err());
        assert!(segment("").is_err());
    }

    #[test]
    fn origin_with_a_path_is_refused() {
        for bad in [
            "https://server.example/api",
            "https://server.example?x=1",
            "ftp://server.example",
        ] {
            let e = Server::new(bad, Some(SCHOOL), Credentials::fixed("t")).unwrap_err();
            assert_eq!(e.code, "usage", "{bad}");
        }
        let e = Server::new(
            "https://server.example",
            Some("ABC"),
            Credentials::fixed("t"),
        );
        assert_eq!(e.unwrap_err().code, "usage");
    }

    #[test]
    fn plain_http_only_to_loopback() {
        let ok = |o: &str| Server::new(o, None, Credentials::fixed("t")).is_ok();
        assert!(ok("http://127.0.0.1:8080"));
        assert!(ok("http://[::1]:8080"));
        assert!(ok("http://localhost:8080"));
        assert!(!ok("http://127.0.0.2:8080"));
        assert!(ok("https://server.example"));
        assert!(!ok("http://server.example"));
        assert!(!ok("http://10.0.0.1"));
    }

    #[test]
    fn school_is_not_configured_without_one() {
        let s = Server::new("https://server.example", None, Credentials::fixed("t")).unwrap();
        assert_eq!(s.school().unwrap_err().code, "not_configured");
    }

    #[tokio::test]
    async fn error_envelope_is_parsed() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("{PREFIX}publish/commit")))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({"error": {
                "code": "version_conflict", "message": "stale\u{1b}[31m base",
                "details": {"latest_version": 8}, "unknown": true}})))
            .mount(&mock)
            .await;
        let s = local(&mock, Credentials::fixed("t"));
        let e = s
            .post_json::<_, Value>("publish/commit", &json!({}))
            .await
            .unwrap_err();
        assert_eq!(e.code, "version_conflict");
        assert_eq!(e.status, Some(409));
        assert_eq!(e.details["latest_version"], 8);
        assert!(!e.message.contains('\u{1b}'));
    }

    #[tokio::test]
    async fn long_server_message_is_cut() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(400).set_body_json(
                    json!({"error": {"code": "invalid", "message": "x".repeat(1000)}}),
                ),
            )
            .mount(&mock)
            .await;
        let e = local(&mock, Credentials::fixed("t"))
            .get_json::<Value>("a")
            .await
            .unwrap_err();
        assert_eq!(e.message.chars().count(), 300);
    }

    #[tokio::test]
    async fn non_json_error_body_is_invalid_answer_without_text() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(502).set_body_string("<html>SECRET-BODY</html>"))
            .mount(&mock)
            .await;
        let e = local(&mock, Credentials::fixed("t"))
            .get_json::<Value>("a")
            .await
            .unwrap_err();
        assert_eq!(e.code, "invalid_answer");
        assert_eq!(e.status, Some(502));
        assert!(!format!("{e:?}").contains("SECRET-BODY"));
    }

    #[tokio::test]
    async fn step_up_is_retried_once() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("{PREFIX}seed")))
            .and(header("authorization", "Bearer plain"))
            .respond_with(envelope(401, "step_up_required"))
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("{PREFIX}seed")))
            .and(header("authorization", "Bearer stepped"))
            .respond_with(envelope(401, "step_up_required"))
            .mount(&mock)
            .await;
        let s = local(&mock, Credentials::fixed_with_step_up("plain", "stepped"));
        let e = s.post_empty::<Value>("seed").await.unwrap_err();
        assert_eq!(e.code, "step_up_required");
        let reqs = mock.received_requests().await.unwrap();
        let auth: Vec<_> = reqs
            .iter()
            .map(|r| {
                r.headers
                    .get("authorization")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(auth, ["Bearer plain", "Bearer stepped"]);
    }

    #[tokio::test]
    async fn step_up_without_a_step_up_token_is_not_logged_in() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(envelope(401, "step_up_required"))
            .mount(&mock)
            .await;
        let e = local(&mock, Credentials::fixed("plain"))
            .post_empty::<Value>("seed")
            .await
            .unwrap_err();
        assert_eq!(e.code, "not_logged_in");
        assert_eq!(mock.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn step_up_token_is_reused_within_four_minutes() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("authorization", "Bearer plain"))
            .respond_with(envelope(401, "step_up_required"))
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(header("authorization", "Bearer stepped"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
            .mount(&mock)
            .await;
        let mut s = local(&mock, Credentials::fixed_with_step_up("plain", "stepped"));
        let base = Instant::now();
        let offset = Arc::new(AtomicU64::new(0));
        let o = offset.clone();
        s.set_clock(Box::new(move || {
            base + Duration::from_secs(o.load(Ordering::SeqCst))
        }));
        let auth = |n: usize, reqs: &[wiremock::Request]| {
            reqs[n]
                .headers
                .get("authorization")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        };
        s.post_empty::<Value>("seed").await.unwrap(); // plain, then stepped
        offset.store(239, Ordering::SeqCst);
        s.post_empty::<Value>("seed").await.unwrap(); // cached: one request
        let reqs = mock.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 3);
        assert_eq!(auth(2, &reqs), "Bearer stepped");
        offset.store(240, Ordering::SeqCst);
        s.post_empty::<Value>("seed").await.unwrap(); // expired: plain, then stepped
        let reqs = mock.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 5);
        assert_eq!(auth(3, &reqs), "Bearer plain");
    }

    #[tokio::test]
    async fn post_empty_sends_content_length_zero() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("content-length", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": 1})))
            .mount(&mock)
            .await;
        let v: Value = local(&mock, Credentials::fixed("t"))
            .post_empty("seed")
            .await
            .unwrap();
        assert_eq!(v["ok"], 1);
    }

    #[tokio::test]
    async fn bytes_and_delete_and_version_header() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("{PREFIX}versions/7/bundle")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("X-Mastersos-Version", "7")
                    .set_body_bytes(vec![1u8, 2, 3]),
            )
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("{PREFIX}up")))
            .and(header("content-type", "application/gzip"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"n": 3})))
            .mount(&mock)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!("{PREFIX}keys/k1")))
            .respond_with(ResponseTemplate::new(204))
            .mount(&mock)
            .await;
        let s = local(&mock, Credentials::fixed("t"));
        let (b, v) = s.get_bytes("versions/7/bundle").await.unwrap();
        assert_eq!((b, v), (vec![1, 2, 3], Some(7)));
        let r: Value = s
            .post_bytes("up", vec![9, 9, 9], "application/gzip")
            .await
            .unwrap();
        assert_eq!(r["n"], 3);
        s.delete("keys/k1").await.unwrap();
    }

    #[tokio::test]
    async fn auth_config_ignores_unknown_fields_and_sends_no_token() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/cli/v1/auth-config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": "https://issuer.example", "client_id": "c", "audience": "a",
                "scopes": ["openid"], "step_up_acr": "", "future": 1})))
            .mount(&mock)
            .await;
        let c = auth_config(&Url::parse(&mock.uri()).unwrap())
            .await
            .unwrap();
        assert_eq!(c.issuer, "https://issuer.example");
        assert_eq!(c.scopes, ["openid"]);
        let reqs = mock.received_requests().await.unwrap();
        assert!(reqs[0].headers.get("authorization").is_none());
    }

    #[test]
    fn json_error_shape() {
        let mut e = CliError::new("check_failed", "bad manifest");
        e.problems = vec![json!({"path": "a", "message": "wrong"})];
        let (out, err) = render_error(&e, true);
        assert_eq!(err, "");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            v,
            json!({"error": {"code": "check_failed", "message": "bad manifest",
                "problems": [{"path": "a", "message": "wrong"}]}})
        );
        let (out, err) = render_error(&e, false);
        assert_eq!(out, "");
        assert!(err.starts_with("mastersos: bad manifest\n"));
        assert!(err.contains("wrong"));
        assert_eq!(exit_code(&e), 2);
        assert_eq!(exit_code(&CliError::new("usage", "x")), 2);
        assert_eq!(exit_code(&CliError::new("reroute_refused", "x")), 2);
        // A server answer exits 1, whatever code it carries.
        for code in ["check_failed", "usage"] {
            let mut from_server = CliError::new(code, "x");
            from_server.status = Some(400);
            assert_eq!(exit_code(&from_server), 1, "{code}");
        }
        assert_eq!(exit_code(&CliError::new("network", "x")), 1);
    }

    #[tokio::test]
    async fn token_never_in_error_text() {
        let secret = "SECRET-TOKEN-VALUE";
        // Refused connection: the transport error must not carry the token.
        let s = Server::new(
            "http://127.0.0.1:1",
            Some(SCHOOL),
            Credentials::fixed(secret),
        )
        .unwrap();
        let e = s.get_json::<Value>("a").await.unwrap_err();
        assert_eq!(e.code, "network");
        assert!(!format!("{e:?} {} {:?}", e.message, serde_json::to_string(&e)).contains(secret));
        // A server that echoes the token back in its message does not leak it through Debug of the
        // credentials either.
        assert!(!format!("{:?}", Credentials::fixed(secret)).contains(secret));
        assert!(!format!("{s:?}").contains(secret));
        // An unusable token is refused without being shown.
        let bad = Server::new(
            "http://127.0.0.1:1",
            Some(SCHOOL),
            Credentials::fixed("a\nSECRET-TOKEN-VALUE"),
        )
        .unwrap();
        let e = bad.get_json::<Value>("a").await.unwrap_err();
        assert!(!format!("{e:?}").contains(secret));
    }

    #[tokio::test]
    async fn no_school_sends_nothing() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&mock)
            .await;
        let s = Server::new(&mock.uri(), None, Credentials::fixed("t")).unwrap();
        let codes = [
            s.get_json::<Value>("a").await.unwrap_err().code,
            s.post_json::<_, Value>("a", &json!({}))
                .await
                .unwrap_err()
                .code,
            s.post_empty::<Value>("a").await.unwrap_err().code,
            s.post_bytes::<Value>("a", vec![1], "application/gzip")
                .await
                .unwrap_err()
                .code,
            s.delete("a").await.unwrap_err().code,
            s.get_bytes("a").await.unwrap_err().code,
        ];
        assert!(codes.iter().all(|c| c == "not_configured"), "{codes:?}");
        assert!(mock.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn route_climbing_out_of_the_prefix_is_refused() {
        let mock = MockServer::start().await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&mock)
            .await;
        let s = local(&mock, Credentials::fixed("t"));
        assert_eq!(s.delete("keys/../..").await.unwrap_err().code, "usage");
        assert!(s.school_url("../../x").is_err());
        for route in ["keys/..", "..", "keys/./x", "a/%2e%2e", "../mastersos"] {
            assert_eq!(s.delete(route).await.unwrap_err().code, "usage", "{route}");
            assert!(s.school_url(route).is_err(), "{route}");
        }
        assert!(mock.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn oversized_answers_are_refused() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("{PREFIX}big-json")))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(vec![b' '; 4 * 1024 * 1024 + 1]),
            )
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{PREFIX}big-archive")))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(vec![0u8; 20 * 1024 * 1024 + 1]),
            )
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{PREFIX}big-error")))
            .respond_with(ResponseTemplate::new(500).set_body_bytes(vec![b'x'; 100 * 1024]))
            .mount(&mock)
            .await;
        let s = local(&mock, Credentials::fixed("t"));
        let e = s.get_json::<Value>("big-json").await.unwrap_err();
        assert_eq!(e.code, "invalid_answer");
        assert!(e.message.contains("too large"));
        let e = s.get_bytes("big-archive").await.unwrap_err();
        assert!(e.message.contains("too large"), "{e:?}");
        let e = s.get_json::<Value>("big-error").await.unwrap_err();
        assert_eq!((e.code.as_str(), e.status), ("invalid_answer", Some(500)));
    }

    #[tokio::test]
    async fn auth_config_checks_the_origin() {
        for bad in [
            "http://server.example",
            "http://127.0.0.2:9",
            "https://server.example/x",
        ] {
            let e = auth_config(&Url::parse(bad).unwrap()).await.unwrap_err();
            assert_eq!(e.code, "usage", "{bad}");
        }
    }

    #[tokio::test]
    async fn empty_message_falls_back_to_the_code() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_json(json!({"error": {"code": "forbidden", "message": "\u{7}"}})),
            )
            .mount(&mock)
            .await;
        let e = local(&mock, Credentials::fixed("t"))
            .get_json::<Value>("a")
            .await
            .unwrap_err();
        assert_eq!(e.message, "the server refused the request (forbidden)");
    }

    #[tokio::test]
    async fn error_body_cap_holds_without_content_length() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let _ = sock
                .write_all(
                    b"HTTP/1.1 500 Internal Server Error\r\nTransfer-Encoding: chunked\r\n\r\n",
                )
                .await;
            // A valid envelope far larger than the cap, in 16 KiB chunks.
            let mut first = br#"{"error":{"code":"boom","message":""#.to_vec();
            first.resize(16 * 1024, b'x');
            let mut chunks = vec![first];
            for _ in 0..8 {
                chunks.push(vec![b'x'; 16 * 1024]);
            }
            chunks.push(br#""}}"#.to_vec());
            for c in chunks {
                let head = format!("{:x}\r\n", c.len());
                if sock.write_all(head.as_bytes()).await.is_err()
                    || sock.write_all(&c).await.is_err()
                    || sock.write_all(b"\r\n").await.is_err()
                {
                    return;
                }
            }
            let _ = sock.write_all(b"0\r\n\r\n").await;
        });
        let s = Server::new(
            &format!("http://{addr}"),
            Some(SCHOOL),
            Credentials::fixed("t"),
        )
        .unwrap();
        let e = s.get_json::<Value>("a").await.unwrap_err();
        assert_eq!((e.code.as_str(), e.status), ("invalid_answer", Some(500)));
    }
}
