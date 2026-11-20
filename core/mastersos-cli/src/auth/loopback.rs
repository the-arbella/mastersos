//! The step-up sign-in (protocol §6, Erratum 1): an authorization code with PKCE (S256) on a
//! loopback redirect, `http://127.0.0.1:<port>/callback`, with `prompt=login` and `max_age=0`,
//! `resource=<audience>` (RFC 8707), and `acr_values` only when `step_up_acr` is not empty.
//!
//! - The listener binds 127.0.0.1 only. Only `GET /callback` counts; anything else gets 404 and is
//!   ignored.
//! - `state` is compared in constant time. A wrong `state` or an `error` answer ends the sign-in;
//!   what the request carried is never shown unescaped and never put on the page.
//! - Each connection is served on its own task, with a size limit on the request head and a time
//!   limit, so a stalled connection cannot hold up the browser's; the sign-in waits 5 minutes.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use reqwest::Url;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};

use super::oidc::{Discovery, TokenSet};
use crate::server::{AuthConfig, CliError};

/// How long the browser's answer is awaited.
const OVERALL: Duration = Duration::from_secs(5 * 60);
/// How long one connection may take to send its request head.
const PER_CONNECTION: Duration = Duration::from_secs(10);
/// The most bytes of one request head.
const MAX_HEAD: usize = 8 * 1024;
/// The most connections served at once; more are closed.
const MAX_CONNECTIONS: usize = 32;
/// The page the browser shows for this sign-in's answer: neutral, since the code exchange that
/// decides the sign-in comes after it.
pub const RECEIVED_PAGE: &str = "Sign-in received. Return to the command line.";
/// The page after a refused or foreign answer: nothing from the request is shown.
const FAILED_PAGE: &str = "Sign-in failed. Return to the command line.";

/// A fresh sign-in in the browser. The address is always printed on stderr; the browser is opened
/// too when `open_browser`.
pub async fn loopback_step_up(
    cfg: &AuthConfig,
    d: &Discovery,
    open_browser: bool,
) -> Result<TokenSet, CliError> {
    let opener = |url: &Url| {
        eprintln!(
            // Url serialization percent-encodes every control character.
            "To confirm it is you, sign in again in the browser: {}",
            url.as_str()
        );
        if open_browser {
            super::oidc::open_browser(url);
        }
    };
    run(cfg, d, &opener, OVERALL).await
}

fn failed(why: &str) -> CliError {
    CliError::new("step_up_failed", why)
}

/// 32 random bytes, base64url without padding.
fn random_b64() -> Result<String, CliError> {
    use ring::rand::SecureRandom as _;
    let mut b = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| failed("no random numbers are available"))?;
    Ok(URL_SAFE_NO_PAD.encode(b))
}

/// Equal bytes, compared in constant time for equal lengths.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// [`loopback_step_up`] with the browser and the overall wait given.
pub(crate) async fn run(
    cfg: &AuthConfig,
    d: &Discovery,
    opener: &dyn Fn(&Url),
    overall: Duration,
) -> Result<TokenSet, CliError> {
    let auth = d.authorization_endpoint.as_ref().ok_or_else(|| {
        CliError::new(
            "invalid_answer",
            "the sign-in service offers no browser sign-in",
        )
    })?;
    let verifier = random_b64()?;
    let state = random_b64()?;
    let challenge = URL_SAFE_NO_PAD
        .encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref());
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|_| failed("cannot listen on 127.0.0.1 for the sign-in answer"))?;
    let port = listener
        .local_addr()
        .map_err(|_| failed("cannot listen on 127.0.0.1 for the sign-in answer"))?
        .port();
    let redirect = format!("http://127.0.0.1:{port}/callback");
    let mut url = auth.clone();
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code")
            .append_pair("client_id", &cfg.client_id)
            .append_pair("redirect_uri", &redirect)
            .append_pair("scope", &cfg.scopes.join(" "))
            .append_pair("state", &state)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("prompt", "login")
            .append_pair("max_age", "0")
            .append_pair("resource", &cfg.audience);
        if !cfg.step_up_acr.is_empty() {
            q.append_pair("acr_values", &cfg.step_up_acr);
        }
    }
    opener(&url);
    let code = match tokio::time::timeout(
        overall,
        wait_for_callback(
            listener,
            Expected {
                state,
                issuer: d.issuer.clone(),
            },
        ),
    )
    .await
    {
        Ok(r) => r?,
        Err(_) => {
            return Err(failed(&format!(
                "no sign-in answer came within {} seconds",
                overall.as_secs()
            )))
        }
    };
    super::oidc::exchange_code(d, &cfg.client_id, &code, &verifier, &redirect).await
}

/// Serve connections until one is a `GET /callback`; its verdict ends the wait.
/// What the callback must carry.
struct Expected {
    state: String,
    issuer: String,
}

async fn wait_for_callback(listener: TcpListener, expected: Expected) -> Result<String, CliError> {
    let state = Arc::new(expected);
    let (tx, mut rx) = mpsc::channel::<Result<String, CliError>>(1);
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        tokio::select! {
            Some(verdict) = rx.recv() => return verdict,
            accepted = listener.accept() => {
                let Ok((sock, _)) = accepted else {
                    // Out of file handles, say: try again shortly.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                // Too many open connections: this one is closed unanswered.
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    continue;
                };
                let (state, tx) = (state.clone(), tx.clone());
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Some(verdict) = serve(sock, &state).await {
                        let _ = tx.try_send(verdict);
                    }
                });
            }
        }
    }
}

/// The request head, up to the blank line; `None` when the connection ends or sends too much.
async fn read_head(sock: &mut TcpStream) -> Result<String, bool> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = sock.read(&mut chunk).await.map_err(|_| false)?;
        if n == 0 {
            return Err(false);
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return String::from_utf8(buf).map_err(|_| false);
        }
        if buf.len() >= MAX_HEAD {
            // Too large.
            return Err(true);
        }
    }
}

async fn respond(sock: &mut TcpStream, status: &str, body: &str) {
    let answer = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = tokio::time::timeout(PER_CONNECTION, async {
        let _ = sock.write_all(answer.as_bytes()).await;
        let _ = sock.shutdown().await;
    })
    .await;
}

/// One connection: `None` unless it is a `GET /callback`.
async fn serve(mut sock: TcpStream, state: &Expected) -> Option<Result<String, CliError>> {
    let head = match tokio::time::timeout(PER_CONNECTION, read_head(&mut sock)).await {
        Ok(Ok(h)) => h,
        Ok(Err(true)) => {
            respond(
                &mut sock,
                "431 Request Header Fields Too Large",
                "Too large.",
            )
            .await;
            return None;
        }
        _ => return None,
    };
    let line = head.split("\r\n").next().unwrap_or_default();
    let mut parts = line.split(' ');
    let (method, target) = (parts.next(), parts.next());
    let target = match (method, target) {
        (Some("GET"), Some(t)) if t.split('?').next() == Some("/callback") => t,
        _ => {
            respond(&mut sock, "404 Not Found", "Not found.").await;
            return None;
        }
    };
    let verdict = Url::parse(&format!("http://127.0.0.1{target}"))
        .map_err(|_| failed("the sign-in answer is not readable"))
        .and_then(|u| judge(&u, state));
    match &verdict {
        Ok(_) => respond(&mut sock, "200 OK", RECEIVED_PAGE).await,
        Err(_) => respond(&mut sock, "400 Bad Request", FAILED_PAGE).await,
    }
    Some(verdict)
}

/// The code of a callback whose single `state` is ours, with no `error`.
fn judge(url: &Url, expected: &Expected) -> Result<String, CliError> {
    let (mut states, mut codes, mut errors, mut issuers) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "state" => states.push(v),
            "code" => codes.push(v),
            "error" => errors.push(v),
            "iss" => issuers.push(v),
            _ => {}
        }
    }
    if states.len() != 1 || !same(states[0].as_bytes(), expected.state.as_bytes()) {
        // Not this sign-in's answer: nothing it carries is shown.
        return Err(failed(
            "the browser's answer does not belong to this sign-in; nothing was accepted",
        ));
    }
    // RFC 9207: when the answer names its issuer, it must be the one discovered.
    if !issuers.is_empty() && (issuers.len() != 1 || issuers[0] != expected.issuer) {
        return Err(failed(
            "the browser's answer comes from another sign-in service; nothing was accepted",
        ));
    }
    if let Some(e) = errors.first() {
        return Err(failed(&format!(
            "the sign-in service refused the fresh sign-in ({})",
            super::oidc::error_code(e)
        )));
    }
    match codes.as_slice() {
        [c] if !c.is_empty() => Ok(c.to_string()),
        _ => Err(failed("the browser's answer has no sign-in code")),
    }
}

#[cfg(test)]
mod tests {
    use super::super::oidc::tests::{config, discovery, form, get};
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn token_endpoint(mock: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "stepped", "token_type": "Bearer", "expires_in": 300})))
            .mount(mock)
            .await;
    }

    /// The address the browser would open, delivered to the test's "browser".
    fn browser() -> (impl Fn(&Url), mpsc::UnboundedReceiver<Url>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (move |u: &Url| tx.send(u.clone()).unwrap(), rx)
    }

    fn param(url: &Url, k: &str) -> Option<String> {
        url.query_pairs()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.into_owned())
    }

    /// The redirect the issuer would answer with, for the given state and extra query.
    fn callback(auth: &Url, state: &str, extra: &str) -> String {
        let redirect = param(auth, "redirect_uri").unwrap();
        let state: String = url_encode(state);
        format!("{redirect}?state={state}{extra}")
    }

    fn url_encode(s: &str) -> String {
        let mut u = Url::parse("http://x/").unwrap();
        u.query_pairs_mut().append_pair("v", s);
        u.query().unwrap()[2..].to_string()
    }

    async fn follow(url: &str) -> (u16, String, String) {
        let res = reqwest::Client::new().get(url).send().await.unwrap();
        let status = res.status().as_u16();
        let ct = res
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        (status, ct, res.text().await.unwrap())
    }

    #[tokio::test]
    async fn loopback_step_up_sends_prompt_login_and_max_age_zero() {
        let mock = MockServer::start().await;
        token_endpoint(&mock).await;
        let (open, mut rx) = browser();
        let driver = tokio::spawn(async move {
            let auth = rx.recv().await.unwrap();
            let state = param(&auth, "state").unwrap();
            let page = follow(&callback(&auth, &state, "&code=c1")).await;
            (auth, page)
        });
        let cfg = config(&mock.uri(), "");
        let t = run(&cfg, &discovery(&mock), &open, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(t.access_token, "stepped");
        let (auth, (status, ct, body)) = driver.await.unwrap();
        assert_eq!(status, 200);
        assert!(ct.starts_with("text/plain"), "{ct}");
        assert_eq!(body, "Sign-in received. Return to the command line.");

        assert_eq!(auth.path(), "/authorize");
        let p = |k: &str| param(&auth, k);
        assert_eq!(p("response_type").as_deref(), Some("code"));
        assert_eq!(p("client_id").as_deref(), Some("mastersos-cli"));
        assert_eq!(p("scope").as_deref(), Some("openid offline_access"));
        assert_eq!(p("prompt").as_deref(), Some("login"));
        assert_eq!(p("max_age").as_deref(), Some("0"));
        assert_eq!(p("resource").as_deref(), Some("fleet-api"));
        assert_eq!(p("audience"), None);
        assert_eq!(p("acr_values"), None);
        assert_eq!(p("code_challenge_method").as_deref(), Some("S256"));
        let redirect = Url::parse(&p("redirect_uri").unwrap()).unwrap();
        assert_eq!(redirect.scheme(), "http");
        assert_eq!(redirect.host_str(), Some("127.0.0.1"));
        assert_eq!(redirect.path(), "/callback");
        let state = p("state").unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(&state).unwrap().len(), 32);

        let reqs = mock.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1);
        let f = form(&reqs[0]);
        assert_eq!(get(&f, "grant_type"), Some("authorization_code"));
        assert_eq!(get(&f, "code"), Some("c1"));
        assert_eq!(get(&f, "client_id"), Some("mastersos-cli"));
        assert_eq!(get(&f, "redirect_uri"), Some(redirect.as_str()));
        assert_eq!(get(&f, "resource"), None);
        let verifier = get(&f, "code_verifier").unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(verifier).unwrap().len(), 32);
        let digest = ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes());
        assert_eq!(
            p("code_challenge").unwrap(),
            URL_SAFE_NO_PAD.encode(digest.as_ref())
        );
    }

    #[tokio::test]
    async fn loopback_sends_acr_values_when_set() {
        let mock = MockServer::start().await;
        token_endpoint(&mock).await;
        let (open, mut rx) = browser();
        let driver = tokio::spawn(async move {
            let auth = rx.recv().await.unwrap();
            let state = param(&auth, "state").unwrap();
            follow(&callback(&auth, &state, "&code=c1")).await;
            auth
        });
        let cfg = config(&mock.uri(), "urn:example:mfa");
        run(&cfg, &discovery(&mock), &open, Duration::from_secs(30))
            .await
            .unwrap();
        let auth = driver.await.unwrap();
        assert_eq!(
            param(&auth, "acr_values").as_deref(),
            Some("urn:example:mfa")
        );
        assert_eq!(param(&auth, "resource").as_deref(), Some("fleet-api"));
        assert_eq!(param(&auth, "audience"), None);
    }

    /// Runs a sign-in whose browser sends `extra` with the given state; returns the error.
    async fn refused(wrong_state: bool, extra: &'static str) -> (CliError, (u16, String, String)) {
        let mock = MockServer::start().await;
        token_endpoint(&mock).await;
        let (open, mut rx) = browser();
        let driver = tokio::spawn(async move {
            let auth = rx.recv().await.unwrap();
            let mut state = param(&auth, "state").unwrap();
            if wrong_state {
                state.replace_range(0..1, if state.starts_with('A') { "B" } else { "A" });
            }
            follow(&callback(&auth, &state, extra)).await
        });
        let cfg = config(&mock.uri(), "");
        let e = run(&cfg, &discovery(&mock), &open, Duration::from_secs(30))
            .await
            .unwrap_err();
        let page = driver.await.unwrap();
        // Nothing was exchanged.
        assert!(mock.received_requests().await.unwrap().is_empty());
        (e, page)
    }

    #[tokio::test]
    async fn loopback_refuses_wrong_state() {
        let (e, (status, _, body)) = refused(true, "&code=c1").await;
        assert_eq!(e.code, "step_up_failed");
        assert_ne!(status, 200);
        assert!(!body.contains("c1"), "{body}");
    }

    #[tokio::test]
    async fn loopback_refuses_an_error_answer() {
        let (e, (status, _, body)) = refused(false, "&error=access_denied").await;
        assert_eq!(e.code, "step_up_failed");
        assert!(e.message.contains("access_denied"), "{e:?}");
        assert_ne!(status, 200);
        assert!(!body.contains("access_denied"), "{body}");
        // An error with a wrong state ends it too, and its text is never shown.
        let (e, (_, _, body)) = refused(true, "&error=%1B%5B31m%3Cb%3Eevil").await;
        assert_eq!(e.code, "step_up_failed");
        assert!(!e.message.contains('\u{1b}'), "{e:?}");
        assert!(!e.message.contains("evil"), "{e:?}");
        assert!(!body.contains("evil"), "{body}");
        // A repeated state is not a match.
        let (e, _) = refused(false, "&state=other&code=c1").await;
        assert_eq!(e.code, "step_up_failed");
    }

    #[tokio::test]
    async fn loopback_ignores_other_paths() {
        let mock = MockServer::start().await;
        token_endpoint(&mock).await;
        let (open, mut rx) = browser();
        let driver = tokio::spawn(async move {
            let auth = rx.recv().await.unwrap();
            let state = param(&auth, "state").unwrap();
            let good = callback(&auth, &state, "&code=c1");
            let base = good.split("/callback").next().unwrap().to_string();
            let mut statuses = Vec::new();
            for p in ["/", "/favicon.ico", "/callback/x", "/CALLBACK"] {
                let wrong = format!("{base}{p}?state={}&code=c1", url_encode(&state));
                statuses.push(follow(&wrong).await.0);
            }
            // Only GET counts.
            let post = reqwest::Client::new().post(&good).send().await.unwrap();
            statuses.push(post.status().as_u16());
            statuses.push(follow(&good).await.0);
            statuses
        });
        let cfg = config(&mock.uri(), "");
        run(&cfg, &discovery(&mock), &open, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(driver.await.unwrap(), [404, 404, 404, 404, 404, 200]);
    }

    #[tokio::test]
    async fn loopback_is_not_held_up_by_a_stalled_or_huge_request() {
        let mock = MockServer::start().await;
        token_endpoint(&mock).await;
        let (open, mut rx) = browser();
        let driver = tokio::spawn(async move {
            let auth = rx.recv().await.unwrap();
            let redirect = Url::parse(&param(&auth, "redirect_uri").unwrap()).unwrap();
            let addr = format!("127.0.0.1:{}", redirect.port().unwrap());
            // Connected, says nothing.
            let _stalled = tokio::net::TcpStream::connect(&addr).await.unwrap();
            // A head larger than the limit is cut off.
            let mut big = tokio::net::TcpStream::connect(&addr).await.unwrap();
            let head = format!("GET /callback?x={} HTTP/1.1\r\n", "a".repeat(9000));
            let _ = big.write_all(head.as_bytes()).await;
            let mut answer = Vec::new();
            let _ = big.read_to_end(&mut answer).await;
            let state = param(&auth, "state").unwrap();
            follow(&callback(&auth, &state, "&code=c1")).await;
            String::from_utf8_lossy(&answer).into_owned()
        });
        let cfg = config(&mock.uri(), "");
        let started = std::time::Instant::now();
        run(&cfg, &discovery(&mock), &open, Duration::from_secs(30))
            .await
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(8));
        let big = driver.await.unwrap();
        assert!(!big.starts_with("HTTP/1.1 200"), "{big}");
    }

    #[tokio::test]
    async fn loopback_gives_up_after_the_overall_wait() {
        let mock = MockServer::start().await;
        let cfg = config(&mock.uri(), "");
        let e = run(&cfg, &discovery(&mock), &|_| {}, Duration::from_millis(300))
            .await
            .unwrap_err();
        assert_eq!(e.code, "step_up_failed");
    }

    #[tokio::test]
    async fn loopback_listens_on_127_0_0_1_only() {
        let mock = MockServer::start().await;
        let (open, mut rx) = browser();
        let driver = tokio::spawn(async move {
            let auth = rx.recv().await.unwrap();
            let redirect = Url::parse(&param(&auth, "redirect_uri").unwrap()).unwrap();
            let port = redirect.port().unwrap();
            let reach = |host: &'static str| async move {
                tokio::net::TcpStream::connect((host, port)).await.is_ok()
            };
            // 127.0.0.1 answers; another loopback address (Linux routes all of 127/8 to the
            // loopback, so a wildcard listener would answer there) and ::1 do not.
            (
                reach("127.0.0.1").await,
                cfg!(target_os = "linux").then_some(reach("127.0.0.2").await),
                reach("::1").await,
            )
        });
        let cfg = config(&mock.uri(), "");
        let _ = run(&cfg, &discovery(&mock), &open, Duration::from_millis(500)).await;
        let (v4, other, v6) = driver.await.unwrap();
        assert!(v4);
        assert_ne!(other, Some(true));
        assert!(!v6);
    }

    #[tokio::test]
    async fn loopback_page_is_neutral() {
        let mock = MockServer::start().await;
        token_endpoint(&mock).await;
        let (open, mut rx) = browser();
        let driver = tokio::spawn(async move {
            let auth = rx.recv().await.unwrap();
            let state = param(&auth, "state").unwrap();
            follow(&callback(&auth, &state, "&code=c1")).await
        });
        let cfg = config(&mock.uri(), "");
        run(&cfg, &discovery(&mock), &open, Duration::from_secs(30))
            .await
            .unwrap();
        let (_, _, body) = driver.await.unwrap();
        assert_eq!(body, "Sign-in received. Return to the command line.");
    }

    /// RFC 9207: an `iss` on the answer must be the discovered issuer.
    #[tokio::test]
    async fn loopback_checks_iss_when_present() {
        let (e, _) = refused(false, "&code=c1&iss=https%3A%2F%2Fevil.example").await;
        assert_eq!(e.code, "step_up_failed");
        assert!(!e.message.contains("evil"), "{e:?}");
        let (e, _) = refused(false, "&code=c1&iss=a&iss=b").await;
        assert_eq!(e.code, "step_up_failed");

        let mock = MockServer::start().await;
        token_endpoint(&mock).await;
        let (open, mut rx) = browser();
        let iss = url_encode(&mock.uri());
        let driver = tokio::spawn(async move {
            let auth = rx.recv().await.unwrap();
            let state = param(&auth, "state").unwrap();
            follow(&callback(&auth, &state, &format!("&code=c1&iss={iss}"))).await
        });
        let cfg = config(&mock.uri(), "");
        run(&cfg, &discovery(&mock), &open, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(driver.await.unwrap().0, 200);
    }
}
