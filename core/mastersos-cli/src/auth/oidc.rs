//! OpenID Connect for `mastersos login` (protocol §6): discovery, the device grant (RFC 8628),
//! refresh, and the code exchange of the loopback step-up ([`super::loopback`]).
//!
//! - Every endpoint is https (http only to the loopback), and discovery must name exactly the
//!   issuer the server's `auth-config` gave: tokens never go over plain http to another host.
//! - The audience goes as `resource=<audience>` (RFC 8707) on the device authorization request
//!   (and on the step-up authorization request), never as `audience=`.
//! - Token answers are read by their `error` code only; descriptions are never shown.
//! - Tokens never appear in Debug output, errors or logs.

use std::future::Future;
use std::io::Write;
use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::Url;
use serde::Deserialize;

use crate::safe;
use crate::server::{self, AuthConfig, CliError};

pub use super::loopback::loopback_step_up;

/// The most bytes of a discovery document or a token answer.
const MAX_ANSWER: usize = 256 * 1024;
/// RFC 8628 §3.2: the poll interval when the answer names none.
const DEFAULT_INTERVAL: u64 = 5;
/// RFC 8628 §3.5: `slow_down` adds 5 seconds.
const SLOW_DOWN: u64 = 5;
/// The longest poll interval kept, whatever the issuer asks.
const MAX_INTERVAL: u64 = 60;
const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// The lifetime assumed for a token answer without `expires_in`.
const DEFAULT_LIFETIME: i64 = 300;

/// The endpoints of an issuer, from `<issuer>/.well-known/openid-configuration`.
#[derive(Debug, Clone)]
pub struct Discovery {
    pub issuer: String,
    pub token_endpoint: Url,
    pub authorization_endpoint: Option<Url>,
    pub device_authorization_endpoint: Option<Url>,
}

/// What a token endpoint gave.
#[derive(Clone)]
pub struct TokenSet {
    pub access_token: String,
    pub expires_at: DateTime<Utc>,
    pub refresh_token: Option<String>,
}

/// The tokens never show in Debug output.
impl std::fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSet")
            .field("access_token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

fn invalid(what: &str) -> CliError {
    CliError::new("invalid_answer", what)
}

/// An endpoint the issuer named: https, or http to the loopback; no user name or password.
fn endpoint(s: &str, what: &str) -> Result<Url, CliError> {
    let bad = || {
        invalid(&format!(
            "the sign-in service's {what} is not an https address"
        ))
    };
    let url = Url::parse(s).map_err(|_| bad())?;
    let secure = url.scheme() == "https" || (url.scheme() == "http" && server::is_loopback(&url));
    if !secure || url.host_str().is_none() || !url.username().is_empty() || url.password().is_some()
    {
        return Err(bad());
    }
    Ok(url)
}

fn unreachable(e: reqwest::Error) -> CliError {
    CliError::new(
        "network",
        &format!(
            "could not reach the sign-in service: {}",
            safe::field(&e.without_url().to_string())
        ),
    )
}

/// The issuer's discovery document, checked: its `issuer` equals `issuer` exactly and every
/// endpoint is https (http only to the loopback).
pub async fn discover(issuer: &str) -> Result<Discovery, CliError> {
    let base = endpoint(issuer, "issuer")?;
    if base.query().is_some() || base.fragment().is_some() {
        return Err(invalid(
            "the sign-in service's issuer is not a plain address",
        ));
    }
    let url = Url::parse(&format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    ))
    .map_err(|_| invalid("the sign-in service's issuer is not an https address"))?;
    let res = server::build_client()?
        .get(url)
        .send()
        .await
        .map_err(unreachable)?;
    let status = res.status().as_u16();
    if !res.status().is_success() {
        return Err(invalid(&format!(
            "the sign-in service answered HTTP {status} for its settings"
        )));
    }
    let bytes = server::read_capped(res, MAX_ANSWER).await?;
    #[derive(Deserialize)]
    struct Doc {
        issuer: String,
        token_endpoint: String,
        authorization_endpoint: Option<String>,
        device_authorization_endpoint: Option<String>,
    }
    let doc: Doc = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("the sign-in service's settings are not what was expected"))?;
    if doc.issuer != issuer {
        return Err(invalid(
            "the sign-in service names another issuer than the server's settings",
        ));
    }
    let optional = |s: Option<String>, what: &str| s.map(|s| endpoint(&s, what)).transpose();
    Ok(Discovery {
        issuer: doc.issuer,
        token_endpoint: endpoint(&doc.token_endpoint, "token endpoint")?,
        authorization_endpoint: optional(doc.authorization_endpoint, "authorization endpoint")?,
        device_authorization_endpoint: optional(
            doc.device_authorization_endpoint,
            "device authorization endpoint",
        )?,
    })
}

/// A form POST; the status and the body (capped).
async fn post_form(
    client: &reqwest::Client,
    url: &Url,
    form: &[(&str, &str)],
) -> Result<(u16, Vec<u8>), CliError> {
    let res = client
        .post(url.clone())
        .form(form)
        .send()
        .await
        .map_err(unreachable)?;
    let status = res.status().as_u16();
    Ok((status, server::read_capped(res, MAX_ANSWER).await?))
}

/// A token endpoint's answer: tokens, or the `error` code of a refusal (cleaned).
enum Answer {
    Token(TokenSet),
    Refused(String),
}

/// The `error` code of an OAuth error body, cleaned; `None` when the body is not one.
fn refusal(body: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct ErrorBody {
        error: String,
    }
    serde_json::from_slice::<ErrorBody>(body)
        .ok()
        .map(|e| error_code(&e.error))
}

async fn token_request(
    client: &reqwest::Client,
    d: &Discovery,
    form: &[(&str, &str)],
) -> Result<Answer, CliError> {
    let (status, body) = post_form(client, &d.token_endpoint, form).await?;
    if !(200..300).contains(&status) {
        return refusal(&body).map(Answer::Refused).ok_or_else(|| {
            invalid(&format!(
                "the sign-in service answered HTTP {status} without an error code"
            ))
        });
    }
    #[derive(Deserialize)]
    struct Tokens {
        access_token: String,
        token_type: Option<String>,
        expires_in: Option<i64>,
        refresh_token: Option<String>,
    }
    let bad = || invalid("the sign-in service's token answer is not usable");
    let t: Tokens = serde_json::from_slice(&body).map_err(|_| bad())?;
    let usable = |s: &str| !s.is_empty() && s.bytes().all(|b| (0x21..=0x7e).contains(&b));
    if !usable(&t.access_token)
        || t.refresh_token.as_deref().is_some_and(|r| !usable(r))
        || t.token_type
            .as_deref()
            .is_some_and(|k| !k.eq_ignore_ascii_case("bearer"))
    {
        return Err(bad());
    }
    let lifetime = t
        .expires_in
        .unwrap_or(DEFAULT_LIFETIME)
        .clamp(0, 10 * 365 * 24 * 3600);
    Ok(Answer::Token(TokenSet {
        access_token: t.access_token,
        expires_at: Utc::now() + chrono::Duration::seconds(lifetime),
        refresh_token: t.refresh_token,
    }))
}

/// RFC 8628: ask for a device code, print where to confirm it on `out`, open the browser there
/// when `open_browser`, and poll until the person confirms, refuses, or the code expires.
pub async fn device_grant(
    cfg: &AuthConfig,
    d: &Discovery,
    out: &mut dyn Write,
    open_browser: bool,
) -> Result<TokenSet, CliError> {
    let opener = |url: &Url| {
        if open_browser {
            self::open_browser(url);
        }
    };
    device_grant_with(cfg, d, out, &opener, tokio::time::sleep).await
}

fn login_failed(why: &str) -> CliError {
    CliError::new(
        "login_failed",
        &format!("{why}; run `mastersos login` again"),
    )
}

/// [`device_grant`] with the browser and the wait given, so tests do not wait real seconds.
pub(crate) async fn device_grant_with<S, F>(
    cfg: &AuthConfig,
    d: &Discovery,
    out: &mut dyn Write,
    open: &dyn Fn(&Url),
    mut sleep: S,
) -> Result<TokenSet, CliError>
where
    S: FnMut(Duration) -> F,
    F: Future<Output = ()>,
{
    let device_endpoint = d
        .device_authorization_endpoint
        .as_ref()
        .ok_or_else(|| invalid("the sign-in service offers no sign-in with a code"))?;
    let client = server::build_client()?;
    let scope = cfg.scopes.join(" ");
    let (status, body) = post_form(
        &client,
        device_endpoint,
        &[
            ("client_id", &cfg.client_id),
            ("scope", &scope),
            ("resource", &cfg.audience),
        ],
    )
    .await?;
    if !(200..300).contains(&status) {
        let why = match refusal(&body) {
            Some(code) => format!("the sign-in service refused to start the sign-in ({code})"),
            None => format!("the sign-in service answered HTTP {status}"),
        };
        return Err(login_failed(&why));
    }
    #[derive(Deserialize)]
    struct DeviceAnswer {
        device_code: String,
        user_code: String,
        verification_uri: String,
        verification_uri_complete: Option<String>,
        expires_in: u64,
        interval: Option<u64>,
    }
    let a: DeviceAnswer = serde_json::from_slice(&body)
        .map_err(|_| invalid("the sign-in service's code answer is not what was expected"))?;
    let plain = endpoint(&a.verification_uri, "verification address")?;
    let complete = a
        .verification_uri_complete
        .as_deref()
        .map(|u| endpoint(u, "verification address"))
        .transpose()?;
    let code = safe::field(&a.user_code);
    let _ = match &complete {
        Some(u) => writeln!(
            out,
            "To sign in, open {} and check that it shows the code {code}.",
            u.as_str()
        ),
        None => writeln!(
            out,
            "To sign in, open {} and enter the code {code}.",
            plain.as_str()
        ),
    };
    let _ = out.flush();
    open(complete.as_ref().unwrap_or(&plain));
    let mut interval = a
        .interval
        .unwrap_or(DEFAULT_INTERVAL)
        .clamp(1, MAX_INTERVAL);
    let mut waited = 0u64;
    loop {
        if waited + interval > a.expires_in {
            return Err(login_failed("the code expired before it was confirmed"));
        }
        sleep(Duration::from_secs(interval)).await;
        waited += interval;
        let form = [
            ("grant_type", DEVICE_CODE_GRANT),
            ("device_code", a.device_code.as_str()),
            ("client_id", cfg.client_id.as_str()),
        ];
        match token_request(&client, d, &form).await? {
            Answer::Token(t) => return Ok(t),
            Answer::Refused(c) => match c.as_str() {
                "authorization_pending" => {}
                "slow_down" => interval = (interval + SLOW_DOWN).min(MAX_INTERVAL),
                "expired_token" => {
                    return Err(login_failed("the code expired before it was confirmed"))
                }
                "access_denied" => return Err(login_failed("the sign-in was refused")),
                _ => {
                    return Err(login_failed(&format!(
                        "the sign-in service refused the sign-in ({c})"
                    )))
                }
            },
        }
    }
}

/// A new access token for a refresh token. Any failure is `not_logged_in`.
pub async fn refresh(
    d: &Discovery,
    client_id: &str,
    refresh_token: &str,
) -> Result<TokenSet, CliError> {
    let ended = |why: String| {
        CliError::new(
            "not_logged_in",
            &format!("the sign-in could not be renewed ({why}); run `mastersos login` again"),
        )
    };
    let client = server::build_client()?;
    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    match token_request(&client, d, &form).await {
        Ok(Answer::Token(t)) => Ok(t),
        Ok(Answer::Refused(c)) => Err(ended(c)),
        Err(e) => Err(ended(e.code)),
    }
}

/// The authorization code exchange of the loopback step-up (with the PKCE verifier and the same
/// redirect URI). A refusal is `step_up_failed`.
pub(crate) async fn exchange_code(
    d: &Discovery,
    client_id: &str,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> Result<TokenSet, CliError> {
    let client = server::build_client()?;
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", verifier),
    ];
    match token_request(&client, d, &form).await? {
        Answer::Token(t) => Ok(t),
        Answer::Refused(c) => Err(CliError::new(
            "step_up_failed",
            &format!("the sign-in service refused the fresh sign-in ({c})"),
        )),
    }
}

/// An OAuth `error` code as it may be shown: `[A-Za-z0-9_.-]`, at most 64 characters.
pub(crate) fn error_code(s: &str) -> String {
    let c: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        .take(64)
        .collect();
    if c.is_empty() {
        "unknown".to_string()
    } else {
        c
    }
}

/// Open `url` in the browser, if it is https (http only to the loopback). The URL goes as one
/// argument to `open` (macOS), `xdg-open` (Linux) or `rundll32 url.dll,FileProtocolHandler`
/// (Windows): never through a shell (`cmd /c start` would split the URL at `&`).
pub(crate) fn open_browser(url: &Url) {
    use std::process::{Command, Stdio};
    if !(url.scheme() == "https" || (url.scheme() == "http" && server::is_loopback(url))) {
        return;
    }
    #[cfg(target_os = "macos")]
    let mut cmd = Command::new("open");
    #[cfg(windows)]
    let mut cmd = {
        let mut c = Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler");
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = Command::new("xdg-open");
    let spawned = cmd
        .arg(url.as_str())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    if let Ok(mut child) = spawned {
        // Reaped in the background; the address was printed whatever happens here.
        std::thread::spawn(move || child.wait());
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    pub(crate) fn config(issuer: &str, acr: &str) -> AuthConfig {
        AuthConfig {
            issuer: issuer.to_string(),
            client_id: "mastersos-cli".into(),
            audience: "devices".into(),
            scopes: vec!["openid".into(), "offline_access".into()],
            step_up_acr: acr.into(),
        }
    }

    pub(crate) fn discovery(mock: &MockServer) -> Discovery {
        let u = |p: &str| Url::parse(&format!("{}{p}", mock.uri())).unwrap();
        Discovery {
            issuer: mock.uri(),
            token_endpoint: u("/token"),
            authorization_endpoint: Some(u("/authorize")),
            device_authorization_endpoint: Some(u("/device")),
        }
    }

    /// The form fields of a request body.
    pub(crate) fn form(r: &Request) -> Vec<(String, String)> {
        let url = Url::parse(&format!(
            "http://x/?{}",
            String::from_utf8(r.body.clone()).unwrap()
        ))
        .unwrap();
        url.query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    pub(crate) fn get<'a>(f: &'a [(String, String)], k: &str) -> Option<&'a str> {
        f.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }

    fn token(n: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "access_token": n, "token_type": "Bearer", "expires_in": 3600,
            "refresh_token": format!("r-{n}"), "id_token": "ignored"}))
    }

    fn oauth_error(code: &str) -> ResponseTemplate {
        ResponseTemplate::new(400).set_body_json(json!({
            "error": code, "error_description": "SECRET-DESCRIPTION"}))
    }

    async fn device_endpoint(mock: &MockServer, extra: Value) {
        let mut body = json!({
            "device_code": "dc-1", "user_code": "ABCD-EFGH",
            "verification_uri": "https://issuer.example/device",
            "verification_uri_complete": "https://issuer.example/device?user_code=ABCD-EFGH",
            "expires_in": 600, "interval": 5});
        for (k, v) in extra.as_object().unwrap() {
            if v.is_null() {
                body.as_object_mut().unwrap().remove(k);
            } else {
                body[k] = v.clone();
            }
        }
        Mock::given(method("POST"))
            .and(path("/device"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(mock)
            .await;
    }

    type Sleeps = Arc<Mutex<Vec<u64>>>;

    async fn grant(mock: &MockServer, out: &mut Vec<u8>) -> (Result<TokenSet, CliError>, Sleeps) {
        let sleeps: Sleeps = Arc::default();
        let s = sleeps.clone();
        let cfg = config(&mock.uri(), "");
        let r = device_grant_with(&cfg, &discovery(mock), out, &|_| {}, move |d| {
            s.lock().unwrap().push(d.as_secs());
            async {}
        })
        .await;
        (r, sleeps)
    }

    #[tokio::test]
    async fn device_grant_polls_until_approved() {
        let mock = MockServer::start().await;
        device_endpoint(&mock, json!({})).await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(oauth_error("authorization_pending"))
            .up_to_n_times(2)
            .with_priority(1)
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(oauth_error("slow_down"))
            .up_to_n_times(1)
            .with_priority(2)
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(token("access-1"))
            .with_priority(3)
            .mount(&mock)
            .await;
        let mut out = Vec::new();
        let (r, sleeps) = grant(&mock, &mut out).await;
        let t = r.unwrap();
        assert_eq!(t.access_token, "access-1");
        assert_eq!(t.refresh_token.as_deref(), Some("r-access-1"));
        // slow_down raises the interval by 5 seconds.
        assert_eq!(*sleeps.lock().unwrap(), [5, 5, 5, 10]);
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("https://issuer.example/device?user_code=ABCD-EFGH"),
            "{out}"
        );
        assert!(out.contains("ABCD-EFGH"), "{out}");
        assert!(!out.contains("dc-1"), "{out}");
        let reqs = mock.received_requests().await.unwrap();
        let dev = form(&reqs[0]);
        assert_eq!(reqs[0].url.path(), "/device");
        assert_eq!(get(&dev, "client_id"), Some("mastersos-cli"));
        assert_eq!(get(&dev, "scope"), Some("openid offline_access"));
        // RFC 8707: the audience is a resource, never `audience=`.
        assert_eq!(get(&dev, "resource"), Some("devices"));
        assert_eq!(get(&dev, "audience"), None);
        for r in &reqs[1..] {
            let f = form(r);
            assert_eq!(get(&f, "grant_type"), Some(DEVICE_CODE_GRANT));
            assert_eq!(get(&f, "device_code"), Some("dc-1"));
            assert_eq!(get(&f, "client_id"), Some("mastersos-cli"));
            assert_eq!(get(&f, "resource"), None);
            assert_eq!(get(&f, "audience"), None);
        }
        assert_eq!(reqs.len(), 5);
    }

    #[tokio::test]
    async fn device_grant_without_complete_uri_prints_the_code() {
        let mock = MockServer::start().await;
        device_endpoint(
            &mock,
            json!({"verification_uri_complete": null, "interval": null}),
        )
        .await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(token("a"))
            .mount(&mock)
            .await;
        let mut out = Vec::new();
        let (r, sleeps) = grant(&mock, &mut out).await;
        r.unwrap();
        // The default interval is 5 seconds.
        assert_eq!(*sleeps.lock().unwrap(), [5]);
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("https://issuer.example/device "), "{out}");
        assert!(out.contains("ABCD-EFGH"), "{out}");
    }

    #[tokio::test]
    async fn device_grant_ends_on_refusal_and_expiry() {
        for (code, polls) in [("access_denied", 1), ("expired_token", 1)] {
            let mock = MockServer::start().await;
            device_endpoint(&mock, json!({})).await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(oauth_error(code))
                .mount(&mock)
                .await;
            let (r, _) = grant(&mock, &mut Vec::new()).await;
            let e = r.unwrap_err();
            assert_eq!(e.code, "login_failed", "{code}");
            assert!(!e.message.contains("SECRET-DESCRIPTION"), "{e:?}");
            assert_eq!(mock.received_requests().await.unwrap().len(), 1 + polls);
        }
        // Still pending when `expires_in` runs out: polling stops there.
        let mock = MockServer::start().await;
        device_endpoint(&mock, json!({"expires_in": 12})).await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(oauth_error("authorization_pending"))
            .mount(&mock)
            .await;
        let (r, sleeps) = grant(&mock, &mut Vec::new()).await;
        assert_eq!(r.unwrap_err().code, "login_failed");
        assert_eq!(*sleeps.lock().unwrap(), [5, 5]);
    }

    #[tokio::test]
    async fn device_grant_refuses_a_plain_http_verification_address() {
        let mock = MockServer::start().await;
        device_endpoint(
            &mock,
            json!({"verification_uri": "http://issuer.example/device",
                   "verification_uri_complete": null}),
        )
        .await;
        let (r, _) = grant(&mock, &mut Vec::new()).await;
        assert_eq!(r.unwrap_err().code, "invalid_answer");
    }

    async fn discovery_doc(mock: &MockServer, doc: Value) {
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(doc))
            .mount(mock)
            .await;
    }

    #[tokio::test]
    async fn discovery_reads_the_endpoints() {
        let mock = MockServer::start().await;
        let uri = mock.uri();
        discovery_doc(
            &mock,
            json!({"issuer": uri, "token_endpoint": format!("{uri}/token"),
                "authorization_endpoint": "https://issuer.example/authorize",
                "device_authorization_endpoint": format!("{uri}/device"), "jwks_uri": "x"}),
        )
        .await;
        let d = discover(&uri).await.unwrap();
        assert_eq!(d.issuer, uri);
        assert_eq!(d.token_endpoint.as_str(), format!("{uri}/token"));
        assert_eq!(
            d.authorization_endpoint.unwrap().as_str(),
            "https://issuer.example/authorize"
        );
    }

    #[tokio::test]
    async fn discovery_refuses_another_issuer_and_plain_http() {
        let mock = MockServer::start().await;
        let uri = mock.uri();
        discovery_doc(
            &mock,
            json!({"issuer": format!("{uri}/"), "token_endpoint": format!("{uri}/token")}),
        )
        .await;
        assert_eq!(discover(&uri).await.unwrap_err().code, "invalid_answer");

        let mock = MockServer::start().await;
        let uri = mock.uri();
        discovery_doc(
            &mock,
            json!({"issuer": uri, "token_endpoint": "http://issuer.example/token"}),
        )
        .await;
        assert_eq!(discover(&uri).await.unwrap_err().code, "invalid_answer");

        // A plain http issuer on another host is never asked.
        assert_eq!(
            discover("http://issuer.example").await.unwrap_err().code,
            "invalid_answer"
        );
    }

    #[tokio::test]
    async fn refresh_sends_the_refresh_grant_only() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(token("new"))
            .mount(&mock)
            .await;
        let t = refresh(&discovery(&mock), "mastersos-cli", "r-old")
            .await
            .unwrap();
        assert_eq!(t.access_token, "new");
        let f = form(&mock.received_requests().await.unwrap()[0]);
        assert_eq!(get(&f, "grant_type"), Some("refresh_token"));
        assert_eq!(get(&f, "refresh_token"), Some("r-old"));
        assert_eq!(get(&f, "client_id"), Some("mastersos-cli"));
        assert_eq!(get(&f, "resource"), None);
    }

    #[tokio::test]
    async fn refused_refresh_is_not_logged_in_without_the_description() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(oauth_error("invalid_grant\u{1b}[31m"))
            .mount(&mock)
            .await;
        let e = refresh(&discovery(&mock), "c", "r").await.unwrap_err();
        assert_eq!(e.code, "not_logged_in");
        assert!(!e.message.contains("SECRET-DESCRIPTION"), "{e:?}");
        assert!(!e.message.contains('\u{1b}'), "{e:?}");
    }

    #[tokio::test]
    async fn unusable_token_answers_are_refused() {
        for body in [
            json!({"access_token": "a b", "expires_in": 60}),
            json!({"access_token": "", "expires_in": 60}),
            json!({"access_token": "a", "token_type": "mac"}),
            json!({"no_token": 1}),
        ] {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
                .mount(&mock)
                .await;
            let e = refresh(&discovery(&mock), "c", "r").await.unwrap_err();
            assert_eq!(e.code, "not_logged_in", "{body}");
        }
    }

    #[test]
    fn error_codes_are_cleaned() {
        assert_eq!(error_code("invalid_grant"), "invalid_grant");
        assert_eq!(error_code("a\u{1b}[31mb <script>"), "a31mbscript");
        assert_eq!(error_code(&"x".repeat(100)).len(), 64);
        assert_eq!(error_code("\u{1b}"), "unknown");
    }

    #[test]
    fn token_set_debug_is_redacted() {
        let t = TokenSet {
            access_token: "SECRET-ACCESS".into(),
            expires_at: Utc::now(),
            refresh_token: Some("SECRET-REFRESH".into()),
        };
        let d = format!("{t:?}");
        assert!(!d.contains("SECRET"), "{d}");
    }
}
