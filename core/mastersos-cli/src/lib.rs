//! mastersos: the command line. Settings are edited in a local directory ([`workdir`]) and
//! published from there ([`publish`]); the server holds no draft.
//!
//! - Server responses are data: they are returned as they are and never acted on.
//! - The token only goes in the `Authorization` header (marked sensitive): not in logs or errors.

// Unsafe code only in `platform`, for the Windows API calls.
#![cfg_attr(not(windows), forbid(unsafe_code))]
#![cfg_attr(windows, deny(unsafe_code))]

pub mod cli;
pub mod explain;
pub mod itpass;
pub mod logo;
pub mod platform;
pub mod publish;
pub mod safe;
pub mod sign;
pub mod tools;
pub mod workdir;

use std::path::Path;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::Url;
use serde_json::{json, Value};

pub use tools::{Body, Req};

/// 错误文字最多留这么多字符：服务端的话不能把工具结果撑成一整页。
const MAX_ERROR_CHARS: usize = 2000;

/// Start failed: a wrong address, no connection, an invalid token, ...
#[derive(Debug)]
pub enum StartError {
    Other(String),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::Other(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for StartError {}

/// 管理 API 的客户端：服务器地址加一个 bearer token。
#[derive(Clone)]
pub struct Api {
    base: Url,
    client: reqwest::Client,
}

/// 不让 token 出现在任何 Debug 输出里（它本来也不在这个结构体里，只在客户端的默认头里）。
impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api")
            .field("base", &self.base.as_str())
            .finish_non_exhaustive()
    }
}

impl Api {
    pub fn new(server: &str, token: &str) -> Result<Api, StartError> {
        let other = |m: String| StartError::Other(m);
        let base = check_server(server)?;
        let token = token.trim();
        if token.is_empty() {
            return Err(other("The token is empty".into()));
        }
        let mut auth = HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| {
            other("The token has characters that cannot go into an HTTP header".into())
        })?;
        auth.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, auth);
        let client = reqwest::Client::builder()
            .default_headers(headers)
            // 不跟随重定向：被攻破的服务端不能借跳转把请求带到别处。
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| other(format!("Could not build the HTTP client: {e}")))?;
        Ok(Api { base, client })
    }

    fn url(&self, segments: &[String], query: &[(String, String)]) -> Url {
        let mut u = self.base.clone();
        {
            let mut p = u
                .path_segments_mut()
                .expect("an http(s) URL always has a path");
            p.pop_if_empty();
            // push 会把 `/`、`?`、`#` 之类转义，参数里的 id 逃不出自己那一段。
            for s in segments {
                p.push(s);
            }
        }
        u.set_query(None);
        if !query.is_empty() {
            u.query_pairs_mut().extend_pairs(query);
        }
        u
    }

    /// One request; any HTTP status comes back as `(status, body)`. Only a transport failure is an `Err`.
    pub async fn exchange(&self, req: Req) -> Result<Exchange, String> {
        let mut rb = self
            .client
            .request(req.method.clone(), self.url(&req.segments, &req.query));
        rb = match req.body {
            Body::None => rb,
            Body::Json(v) => rb.json(&v),
            Body::Text(t) => rb
                .header("content-type", "text/plain; charset=utf-8")
                .body(t),
            Body::Bytes(b) => rb
                .header("content-type", "application/octet-stream")
                .body(b),
        };
        let res = rb.send().await.map_err(|e| {
            // reqwest 的错误可能带 URL，但不带请求头，token 不会漏。
            format!(
                "Could not reach the server: {}",
                clip(&e.without_url().to_string())
            )
        })?;
        let status = res.status().as_u16();
        let is_json = res
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("application/json"));
        let body = res.text().await.map_err(|e| {
            format!(
                "Could not read the server response: {}",
                clip(&e.without_url().to_string())
            )
        })?;
        Ok(Exchange {
            status,
            is_json,
            body,
        })
    }

    /// Send one request: the JSON text of the answer on success, one line of error text on failure.
    pub async fn send(&self, req: Req) -> Result<String, String> {
        let x = self.exchange(req).await?;
        if !(200..300).contains(&x.status) {
            return Err(api_error(x.status, &x.body));
        }
        Ok(render(x.is_json, x.body))
    }
}

/// A complete HTTP answer, whatever its status.
pub struct Exchange {
    pub status: u16,
    pub is_json: bool,
    pub body: String,
}

/// The admin server address: an http(s) URL with a host; http only for the loopback address,
/// since it would send the token in clear text.
pub fn check_server(server: &str) -> Result<Url, StartError> {
    let other = |m: String| StartError::Other(m);
    let base = Url::parse(server)
        .map_err(|_| other(format!("The server address is not a valid URL: {server}")))?;
    if !matches!(base.scheme(), "http" | "https") || base.host_str().is_none() {
        return Err(other(format!(
            "The server address must be https://host[:port]: {server}"
        )));
    }
    // http 会把 token 明文送上网络；只有本机回环（测试、本机演示）可以。
    let host = base.host_str().unwrap_or_default();
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if base.scheme() == "http" && !loopback {
        return Err(other(format!(
                "The server address must be https:// (http is only allowed for localhost / 127.0.0.1 / ::1): {server}"
            )));
    }
    Ok(base)
}

fn clip(s: &str) -> String {
    let mut out: String = s.chars().take(MAX_ERROR_CHARS).collect();
    if s.chars().count() > MAX_ERROR_CHARS {
        out.push_str("... (truncated)");
    }
    out
}

/// A failed response as one line: the API's `error.message` and `error.code`.
fn api_error(status: u16, body: &str) -> String {
    let parsed: Option<Value> = serde_json::from_str(body).ok();
    let e = parsed.as_ref().map(|j| &j["error"]);
    let message = e.and_then(|e| e["message"].as_str());
    let code = e.and_then(|e| e["code"].as_str());
    let mut out = match (message, code) {
        (Some(m), Some(c)) => format!("{} ({c})", clip(m)),
        (Some(m), None) => clip(m),
        _ => format!("The server answered HTTP {status}: {}", clip(body)),
    };
    let sections = e
        .and_then(|e| e["details"]["sections"].as_array())
        .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .filter(|a| !a.is_empty());
    if let Some(sections) = sections {
        // The whole list, unclipped: the caller needs every id to pick the right one.
        out.push_str(&format!(". Available sections: {}", sections.join(", ")));
    } else if let Some(details) = e.and_then(|e| e.get("details")).filter(|d| !d.is_null()) {
        out.push_str(&format!(". Details: {}", clip(&details.to_string())));
    }
    out
}

/// A successful response as JSON text: JSON as it is, plain text as `{"text"}`, nothing as `{"ok"}`.
fn render(is_json: bool, body: String) -> String {
    if body.is_empty() {
        json!({ "ok": true }).to_string()
    } else if is_json {
        serde_json::from_str::<Value>(&body)
            .unwrap_or(Value::String(body))
            .to_string()
    } else {
        json!({ "text": body }).to_string()
    }
}

/// Read the token file and ask `whoami` once, only to fail early on a wrong address or a token the
/// server does not accept. What the token may do is the server's to decide.
pub async fn connect(server: &str, token_file: &Path) -> Result<Api, StartError> {
    let token = std::fs::read_to_string(token_file).map_err(|e| {
        StartError::Other(format!(
            "Could not read the token file {}: {e}",
            token_file.display()
        ))
    })?;
    let api = Api::new(server, &token)?;
    whoami(&api).await?;
    Ok(api)
}

/// `GET /v1/admin/whoami` as JSON.
pub async fn whoami(api: &Api) -> Result<Value, StartError> {
    let body = api
        .send(Req::get(&["v1", "admin", "whoami"]))
        .await
        .map_err(|e| StartError::Other(format!("whoami failed: {e}")))?;
    serde_json::from_str(&body)
        .map_err(|_| StartError::Other("The whoami response is not JSON".into()))
}

/// Why an operation did not happen.
#[derive(Debug)]
pub enum OpError {
    /// The local check refused it; nothing was sent. `issues` holds the check's issues. The command line exits 2.
    Refused {
        message: String,
        issues: Option<Vec<Value>>,
    },
    /// Bad parameters, the network, the token, or the server said no. The command line exits 1.
    Failed(String),
}

impl OpError {
    pub fn exit_code(&self) -> u8 {
        match self {
            OpError::Refused { .. } => 2,
            OpError::Failed(_) => 1,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            OpError::Refused { message, .. } | OpError::Failed(message) => message,
        }
    }
}

impl From<String> for OpError {
    fn from(m: String) -> OpError {
        OpError::Failed(m)
    }
}

/// Run one server operation by name with JSON arguments (see [`tools::build`]). Success is the JSON text of the result (`spec`: the Markdown itself).
pub async fn call(api: &Api, name: &str, args: Value) -> Result<String, OpError> {
    let device = (name == "device_show")
        .then(|| tools::device_wanted(args.clone()))
        .transpose()?;
    let req = tools::build(name, args).map_err(OpError::Failed)?;
    match name {
        "spec" => {
            let text = api.send(req).await?;
            let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            Ok(v["text"].as_str().map_or(text, str::to_owned))
        }
        "device_show" => {
            let device = device.unwrap_or_default();
            let all: Value = serde_json::from_str(&api.send(req).await?).unwrap_or(Value::Null);
            let want = device.trim().to_lowercase();
            // The list is the body itself, or under `data` next to `rev`.
            let data = match all.get("data") {
                Some(d) if all.get("rev").is_some() => d,
                _ => &all,
            };
            let list = data.as_array().cloned().unwrap_or_default();
            let found = list.into_iter().find(|d| {
                d["device_id"].as_str() == Some(device.as_str())
                    || d["serial"]
                        .as_str()
                        .is_some_and(|s| s.trim().to_lowercase() == want)
            });
            found
                .map(|d| d.to_string())
                .ok_or_else(|| OpError::Failed(format!("No such Device: {device}")))
        }
        _ => Ok(api.send(req).await?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn api_paths_are_joined_under_a_server_url_with_a_path() {
        let seg = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for server in [
            "https://cloud.example/org/example/devices",
            "https://cloud.example/org/example/devices/",
        ] {
            let api = Api::new(server, "tok").unwrap();
            assert_eq!(
                api.url(&seg(&["v1", "drafts"]), &[]).as_str(),
                "https://cloud.example/org/example/devices/v1/drafts",
                "{server}"
            );
        }
        // A query on the address is dropped, one asked for is kept, an id cannot leave its segment.
        let api = Api::new("https://cloud.example/org/example/devices?x=1", "tok").unwrap();
        let u = api.url(&seg(&["v1", "a/../b"]), &[("after".into(), "2".into())]);
        assert_eq!(
            u.as_str(),
            "https://cloud.example/org/example/devices/v1/a%2F..%2Fb?after=2"
        );
        // The check accepts it as a server address.
        assert!(check_server("https://cloud.example/org/example/devices").is_ok());
    }

    #[tokio::test]
    async fn connect_asks_whoami_and_does_not_look_at_the_token_kind() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/admin/whoami"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({ "label": "any:label", "kind": "token", "scopes": ["read", "publish"] }),
            ))
            .mount(&s)
            .await;
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("token");
        std::fs::write(&f, "tok").unwrap();
        connect(&s.uri(), &f).await.unwrap();
    }

    #[tokio::test]
    async fn connect_fails_early_when_the_server_refuses_the_token() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/admin/whoami"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&s)
            .await;
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("token");
        std::fs::write(&f, "tok").unwrap();
        let e = connect(&s.uri(), &f).await.unwrap_err();
        assert!(e.to_string().contains("whoami failed"), "{e}");
    }
}
