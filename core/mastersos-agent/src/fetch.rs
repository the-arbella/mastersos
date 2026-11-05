//! Talking to mastersos-server: fetch the bundle (`wait=0`, never a long poll), the signed
//! heartbeat, status reports, recovery-key escrow, fetch-token renewal, push grants, the inbox and
//! the diagnostics upload (`POST /v1/diagnostics`, the presigned S3 `PUT`, the complete call).
//!
//! agent 的 HTTP 客户端只在这里构造（Ruling 27 m6）：跟随重定向的一律经 [`http_client`]
//! （带 [`no_downgrade_redirects`]），托管与换领令牌经 [`no_redirect_client`]（不跟随）。

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use mastersos_bundle::archive::MAX_BUNDLE_BYTES;
use mastersos_bundle::diag::{
    error_action, ApiError, DiagUploadRequest, DiagUploadResponse, ErrorAction, PresignedUpload,
};
use mastersos_bundle::{
    FetchTokenRequest, FetchTokenResponse, InboxPage, InboxResult, PushTokenRequest,
    PushTokenResponse, Seed, StatusReport,
};
use reqwest::{Client, StatusCode};

use crate::seedpart::Identity;

/// 心跳文件的大小上限：正常的一份不到 1 KiB（passkey 签名也只多几百字节）。
const MAX_HEARTBEAT_BYTES: usize = 16 * 1024;
/// 托管请求的总超时（不是长轮询，不必等那么久；连不上就下一轮再试）。
const ESCROW_TIMEOUT: Duration = Duration::from_secs(30);
/// 托管被拒时读服务端错误体的上限，以及错误信息里带服务端 message 的上限（字符）。
const MAX_ERROR_BODY_BYTES: usize = 16 * 1024;
const MAX_ERROR_MESSAGE_CHARS: usize = 300;
/// 换领响应体的上限（正常不到 100 字节）。
const MAX_RENEW_BODY_BYTES: usize = 4 * 1024;
/// Total timeout of the heartbeat and the status report.
const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
/// The bundle download may give up after this long in all. A bundle is up to `MAX_BUNDLE_BYTES`
/// (20 MiB), and a doorbell sends every machine of a school at once over a shared link, so this is
/// far above the 30 s of the small calls. The server never holds a `wait=0` request, so a long
/// total only ever covers a slow transfer.
pub const BUNDLE_TOTAL_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// The bundle download gives up when no bytes arrive for this long.
pub const BUNDLE_READ_TIMEOUT: Duration = Duration::from_secs(60);
/// Connecting to the server gives up after this long.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Client options of the bundle download (`fetch_now`).
pub fn bundle_opts() -> HttpOpts {
    HttpOpts {
        connect: CONNECT_TIMEOUT,
        read: Some(BUNDLE_READ_TIMEOUT),
        total: Some(BUNDLE_TOTAL_TIMEOUT),
    }
}

/// Client options of the heartbeat and the status report.
pub fn short_opts() -> HttpOpts {
    HttpOpts {
        connect: CONNECT_TIMEOUT,
        read: None,
        total: Some(SHORT_TIMEOUT),
    }
}
/// Cap for push-token and inbox response bodies.
const MAX_PUSH_BODY_BYTES: usize = 256 * 1024;
/// Device auth headers for inbox calls (ruling R2).
const DEVICE_HEADER: &str = "x-mastersos-device";
const DEVICE_SECRET_HEADER: &str = "x-mastersos-device-secret";
/// 带退役令牌的响应上的头（值 `stale`）。
pub const STALE_HEADER: &str = "x-mastersos-fetch-token";

/// Total timeout of the presigned diagnostics `PUT`: up to 50 MiB over a slow school link. S3
/// checks the URL's expiry when the request starts, so a long transfer is fine.
pub const DIAG_PUT_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Cap of a `POST /v1/diagnostics` answer (a URL and a few headers: well under 8 KiB).
const MAX_DIAG_BODY_BYTES: usize = 64 * 1024;
/// The longest `Retry-After` honoured; longer values are clamped to this.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(24 * 3600);

/// 构造跟随重定向的 HTTP 客户端的参数。
#[derive(Debug, Clone, Copy)]
pub struct HttpOpts {
    pub connect: Duration,
    /// 两次读之间最长的间隔（大文件下载用它，不用总超时）。
    pub read: Option<Duration>,
    /// 整个请求的总超时。
    pub total: Option<Duration>,
}

/// agent 跟随重定向的 HTTP 客户端（拉包、心跳、回报，设置包里的文件下载，Chrome 的 apt 源），
/// 一律带 [`no_downgrade_redirects`]。用系统 CA。
pub fn http_client(o: HttpOpts) -> Client {
    let mut b = Client::builder()
        .connect_timeout(o.connect)
        .redirect(no_downgrade_redirects());
    if let Some(r) = o.read {
        b = b.read_timeout(r);
    }
    if let Some(t) = o.total {
        b = b.timeout(t);
    }
    b.build()
        .expect("building the HTTP client failed (the TLS backend could not initialize)")
}

/// 托管与换领令牌用的客户端：不跟随任何重定向（307/308 会带着恢复密钥、托管凭据重发到 Location）。
fn no_redirect_client(total: Duration) -> Client {
    Client::builder()
        .timeout(total)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("building the HTTP client failed (the TLS backend could not initialize)")
}

/// 机器侧接口回了 401：当前令牌被拒（主循环据此换用别的来源的令牌）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unauthorized;

impl std::fmt::Display for Unauthorized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the server returned 401 Unauthorized (fetch token rejected)")
    }
}

impl std::error::Error for Unauthorized {}

/// The server rejected the device credential (403 on `/v1/push-token`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredRejected;

impl std::fmt::Display for CredRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("server rejected the device credential (403)")
    }
}

impl std::error::Error for CredRejected {}

/// An inbox call got 401 `device_auth_missing`: the device headers were not accepted.
/// Not [`Unauthorized`]: the fetch token is fine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceAuthMissing;

impl std::fmt::Display for DeviceAuthMissing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("server says the device auth headers are missing (401 device_auth_missing)")
    }
}

impl std::error::Error for DeviceAuthMissing {}

/// An inbox result call got 404: the server has no such message for this machine (never, or
/// purged after its retention).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboxSeqUnknown;

impl std::fmt::Display for InboxSeqUnknown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("server has no such inbox message (404)")
    }
}

impl std::error::Error for InboxSeqUnknown {}

/// How the server took an inbox result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultAck {
    /// 2xx: recorded.
    Recorded,
    /// 409: not recorded, the message is already final there (finished, expired, cancelled).
    /// Fine for `done` / `failed`; for `running` it means "do not start".
    Refused,
}

/// A failed step of the diagnostics upload. `action` is what the caller does next, always from
/// [`error_action`] for cloud answers (Ruling P5); `retry_after` is the answer's `Retry-After`
/// with [`ErrorAction::RetryAfter`]. `detail` names the step and the status or code, never the
/// presigned URL (its query string is the upload grant), the device secret or a token.
/// `Display` is `upload: <detail>`, ready for an inbox ack detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagUploadError {
    pub action: ErrorAction,
    pub retry_after: Option<Duration>,
    pub detail: String,
}

impl DiagUploadError {
    pub fn new(action: ErrorAction, detail: impl Into<String>) -> Self {
        DiagUploadError {
            action,
            retry_after: None,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for DiagUploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "upload: {}", self.detail)
    }
}

impl std::error::Error for DiagUploadError {}

/// How the cloud took `POST /v1/diagnostics/{id}/complete`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompleteOutcome {
    /// 2xx: size and SHA-256 matched; the archive has arrived.
    Done,
    /// The object did not match and was deleted (`409 upload_mismatch`, or any answer that
    /// [`error_action`] says to restart on): start again from `POST /v1/diagnostics`.
    Rejected,
}

/// Per-machine credential for push and inbox: `device_id` from `state.json`,
/// `secret` is `identity.json`'s `escrow_secret`. `Debug` hides the secret.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceCred {
    pub device_id: String,
    pub secret: String,
}

impl std::fmt::Debug for DeviceCred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceCred")
            .field("device_id", &self.device_id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// 换领的结果（`Debug` 不打印令牌）。
#[derive(Clone, PartialEq, Eq)]
pub enum RenewOutcome {
    /// 服务端给了当前令牌。
    New(String),
    /// 服务端拒绝（403），带服务端的说明。
    Refused(String),
}

impl std::fmt::Debug for RenewOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RenewOutcome::New(_) => f.write_str("New(<redacted>)"),
            RenewOutcome::Refused(m) => f.debug_tuple("Refused").field(m).finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    New { archive: Vec<u8>, version: u64 },
    NoChange,
}

/// 克隆便宜（HTTP 客户端内部共享连接池）：主循环、心跳与后台任务各拿一份。
/// 令牌与旧令牌标记放在共享的 `Arc` 里：任何一份上 [`Fetcher::set_token`]、任何一份收到
/// `X-Mastersos-Fetch-Token: stale`，所有克隆都看得到。
#[derive(Clone)]
pub struct Fetcher {
    /// Heartbeat and status: [`short_opts`].
    client: Client,
    /// The bundle download (`fetch_now`): [`bundle_opts`].
    bundle_client: Client,
    /// 托管与换领专用：不跟随任何重定向（307/308 会带着恢复密钥与托管凭据重发到 Location）。
    escrow_client: Client,
    /// The presigned diagnostics `PUT`: [`diag_put_client`].
    upload_client: Client,
    base: String,
    token: Arc<RwLock<Option<String>>>,
    stale: Arc<AtomicBool>,
}

impl Fetcher {
    /// `token` is the fetch token the machine should use now ([`crate::token::effective`]).
    /// System CAs; every request is short (the agent never long-polls).
    pub fn new(seed: &Seed, token: Option<String>) -> Self {
        Fetcher {
            client: http_client(short_opts()),
            bundle_client: http_client(bundle_opts()),
            escrow_client: no_redirect_client(ESCROW_TIMEOUT),
            upload_client: diag_put_client(),
            base: seed.server_url.trim_end_matches('/').to_string(),
            token: Arc::new(RwLock::new(token)),
            stale: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 用 `seed.toml` 里的令牌（不看换领存下的令牌文件；测试与只读种子的场合用）。
    pub fn from_seed(seed: &Seed) -> Self {
        Self::new(seed, seed.fetch_token.clone())
    }

    /// 换上新令牌（所有克隆共用），并清掉旧令牌标记。
    pub fn set_token(&self, t: String) {
        *self.token.write().unwrap_or_else(|e| e.into_inner()) = Some(t);
        self.stale.store(false, Ordering::SeqCst);
    }

    /// 眼下用的令牌（主循环比对别的来源用；不要打印它）。
    pub fn current_token(&self) -> Option<String> {
        self.token.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// 最近一个机器侧响应说这把令牌已退役（`X-Mastersos-Fetch-Token: stale`）。
    pub fn token_is_stale(&self) -> bool {
        self.stale.load(Ordering::SeqCst)
    }

    /// 看一个机器侧响应：401 之外，带 stale 头就置位、不带就清掉（服务端回退了轮换时不再去换领）。
    /// `used` is the token the request carried: if the token was switched meanwhile (a request in
    /// flight across a renewal), the response speaks of the old token and is ignored.
    fn observe(&self, resp: &reqwest::Response, used: &Option<String>) {
        if resp.status() == StatusCode::UNAUTHORIZED || *used != self.current_token() {
            return;
        }
        let stale = resp
            .headers()
            .get(STALE_HEADER)
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"stale"));
        self.stale.store(stale, Ordering::SeqCst);
    }

    /// 服务端地址（去掉了结尾的 `/`）。
    pub fn base(&self) -> &str {
        &self.base
    }

    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        self.auth_as(req, &self.current_token())
    }

    /// 带上 `used` 这把令牌（调用方记下它，响应回来时交给 `observe`）。
    fn auth_as(
        &self,
        req: reqwest::RequestBuilder,
        used: &Option<String>,
    ) -> reqwest::RequestBuilder {
        match used {
            Some(t) => req.bearer_auth(t),
            None => req,
        }
    }

    /// `GET /v1/bundle?after=N&wait=0`: the server answers at once, never holds the request.
    /// 200 → New, 204 → NoChange, 401 → [`Unauthorized`], anything else is an error. A body over
    /// `MAX_BUNDLE_BYTES` is aborted.
    pub async fn fetch_now(&self, after: u64) -> Result<FetchOutcome> {
        let req = self
            .bundle_client
            .get(format!("{}/v1/bundle", self.base))
            .query(&[("after", after)])
            .query(&[("wait", 0u8)]);
        self.fetch_bundle(req).await
    }

    async fn fetch_bundle(&self, req: reqwest::RequestBuilder) -> Result<FetchOutcome> {
        let used = self.current_token();
        let mut resp = self
            .auth_as(req, &used)
            .send()
            .await
            .context("request to /v1/bundle failed")?;
        self.observe(&resp, &used);
        match resp.status() {
            StatusCode::UNAUTHORIZED => Err(anyhow::Error::new(Unauthorized)),
            StatusCode::NO_CONTENT => Ok(FetchOutcome::NoChange),
            StatusCode::OK => {
                let version = resp
                    .headers()
                    .get("x-mastersos-version")
                    .ok_or_else(|| anyhow!("the response has no X-Mastersos-Version"))?
                    .to_str()
                    .ok()
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .ok_or_else(|| anyhow!("X-Mastersos-Version is not an integer"))?;
                if resp
                    .content_length()
                    .is_some_and(|n| n > MAX_BUNDLE_BYTES as u64)
                {
                    bail!("the bundle exceeds the size limit");
                }
                let mut archive = Vec::new();
                while let Some(chunk) = resp.chunk().await.context("reading the bundle failed")? {
                    if archive.len() + chunk.len() > MAX_BUNDLE_BYTES {
                        bail!("the bundle exceeds the size limit");
                    }
                    archive.extend_from_slice(&chunk);
                }
                Ok(FetchOutcome::New { archive, version })
            }
            other => bail!("the server returned {other}"),
        }
    }

    /// 取最新版的签名心跳：200 → 正文，204 → None，其余报错。这里不验签，由调用方用
    /// 机器当前信任的钥匙验。
    pub async fn heartbeat(&self) -> Result<Option<String>> {
        let used = self.current_token();
        let mut resp = self
            .auth_as(
                self.client.get(format!("{}/v1/heartbeat", self.base)),
                &used,
            )
            .send()
            .await
            .context("request to /v1/heartbeat failed")?;
        self.observe(&resp, &used);
        match resp.status() {
            StatusCode::NO_CONTENT => Ok(None),
            StatusCode::OK => {
                let mut body = Vec::new();
                while let Some(chunk) =
                    resp.chunk().await.context("reading the heartbeat failed")?
                {
                    if body.len() + chunk.len() > MAX_HEARTBEAT_BYTES {
                        bail!("the heartbeat exceeds the size limit");
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(Some(
                    String::from_utf8(body).context("the heartbeat is not UTF-8")?,
                ))
            }
            other => bail!("the server returned {other}"),
        }
    }

    /// `POST /v1/escrow` with `r` as the JSON body. Only the sealed form exists
    /// ([`mastersos_bundle::EscrowRequest`], plan 6 Task 13): a plaintext recovery key cannot be sent.
    /// `POST /v1/escrow`：2xx 为成功（服务端对重复的同一把密钥也回 204）。被拒时错误信息是
    /// 「托管被拒（<状态码>）：<服务端的 message>」——403（凭据不符）与 429（超上限）都原样带上
    /// 服务端的说明，IT 在回报里就能看到该做什么。错误里不带 URL（`without_url`），也不带请求体：
    /// 请求体里有恢复密钥与托管凭据。不跟随重定向（3xx 当被拒）。地址不是 https 时不发（[`escrow_transport_ok`]；`lab` 是镜像的 profile）。
    pub async fn escrow(&self, r: &mastersos_bundle::EscrowRequest, lab: bool) -> Result<()> {
        if let Err(why) = escrow_transport_ok(&self.base, lab) {
            bail!("escrow refused (locally): {why}");
        }
        let used = self.current_token();
        let resp = self
            .auth_as(
                self.escrow_client
                    .post(format!("{}/v1/escrow", self.base))
                    .json(r),
                &used,
            )
            .send()
            .await
            .map_err(reqwest::Error::without_url)
            .context("request to /v1/escrow failed")?;
        self.observe(&resp, &used);
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let message = read_error_message(resp).await;
        match message {
            Some(m) => bail!("escrow refused ({}): {m}", status.as_u16()),
            None => bail!("escrow refused ({})", status.as_u16()),
        }
    }

    /// `POST /v1/fetch-token`：凭 `identity.json` 的托管凭据换领当前令牌（Ruling 20）。
    /// 200 → [`RenewOutcome::New`]（令牌不合格当错误）；403 → [`RenewOutcome::Refused`]（带服务端的说明）；
    /// 其余（401、3xx、5xx、连不上）是错误。不跟随重定向；地址不是 https 时不发（[`escrow_transport_ok`]，
    /// `lab` 是镜像的 profile）。错误里不带 URL、凭据与令牌。
    pub async fn renew_token(&self, id: &Identity, lab: bool) -> Result<RenewOutcome> {
        if escrow_transport_ok(&self.base, lab).is_err() {
            bail!(
                "token renewal refused (locally): the seed's server_url is not https://; escrow credentials and tokens are only sent over https (only lab images allow http)"
            );
        }
        let req = FetchTokenRequest {
            device_id: id.device_id.clone(),
            escrow_secret: id.escrow_secret.clone(),
        };
        let mut resp = self
            .auth(
                self.escrow_client
                    .post(format!("{}/v1/fetch-token", self.base))
                    .json(&req),
            )
            .send()
            .await
            .map_err(reqwest::Error::without_url)
            .context("request to /v1/fetch-token failed")?;
        let status = resp.status();
        match status {
            StatusCode::OK => {
                let mut body = Vec::new();
                while let Some(chunk) = resp
                    .chunk()
                    .await
                    .map_err(reqwest::Error::without_url)
                    .context("reading the renewal response failed")?
                {
                    if body.len() + chunk.len() > MAX_RENEW_BODY_BYTES {
                        bail!("the renewal response exceeds the size limit");
                    }
                    body.extend_from_slice(&chunk);
                }
                let r: FetchTokenResponse = serde_json::from_slice(&body)
                    .map_err(|_| anyhow!("the renewal response is not valid JSON"))?;
                if !crate::token::is_valid(&r.fetch_token) {
                    bail!("the new token from the server is invalid (empty, too long, or has unprintable characters)");
                }
                Ok(RenewOutcome::New(r.fetch_token))
            }
            StatusCode::FORBIDDEN => Ok(RenewOutcome::Refused(
                read_error_message(resp)
                    .await
                    .unwrap_or_else(|| "the server refused token renewal (403)".into()),
            )),
            other => bail!("token renewal failed ({})", other.as_u16()),
        }
    }

    /// `POST /v1/push-token`: trade the escrow credential for an MQTT grant. 403 is
    /// [`CredRejected`], 401 is [`Unauthorized`]; other statuses (429, 503, 400) are plain errors.
    /// No redirects; errors never carry the URL, body or secret.
    pub async fn push_token(&self, cred: &DeviceCred, lab: bool) -> Result<PushTokenResponse> {
        self.secret_transport(lab)?;
        let req = PushTokenRequest {
            device_id: cred.device_id.clone(),
            secret: cred.secret.clone(),
        };
        let used = self.current_token();
        let resp = self
            .auth_as(
                self.escrow_client
                    .post(format!("{}/v1/push-token", self.base))
                    .json(&req),
                &used,
            )
            .send()
            .await
            .map_err(reqwest::Error::without_url)
            .context("request to /v1/push-token failed")?;
        self.observe(&resp, &used);
        match resp.status() {
            StatusCode::OK => read_json(resp, "push-token response").await,
            StatusCode::UNAUTHORIZED => Err(anyhow::Error::new(Unauthorized)),
            StatusCode::FORBIDDEN => Err(anyhow::Error::new(CredRejected)),
            other => bail!("push-token failed ({})", other.as_u16()),
        }
    }

    /// `GET /v1/inbox?after=N` with the device headers. 401 with error code
    /// `device_auth_missing` is [`DeviceAuthMissing`]; any other 401 is [`Unauthorized`].
    pub async fn inbox(&self, cred: &DeviceCred, after: u64, lab: bool) -> Result<InboxPage> {
        let used = self.current_token();
        let resp = self
            .device_request(reqwest::Method::GET, "/v1/inbox", cred, &used, lab)?
            .query(&[("after", after)])
            .send()
            .await
            .map_err(reqwest::Error::without_url)
            .context("request to /v1/inbox failed")?;
        self.observe(&resp, &used);
        match resp.status() {
            StatusCode::OK => read_json(resp, "inbox response").await,
            StatusCode::UNAUTHORIZED => Err(unauthorized_kind(resp).await),
            other => bail!("inbox failed ({})", other.as_u16()),
        }
    }

    /// `POST /v1/inbox/{seq}/result`: 2xx is [`ResultAck::Recorded`], 409 (already final there)
    /// [`ResultAck::Refused`], 404 the error [`InboxSeqUnknown`]; anything else is an error.
    pub async fn inbox_result(
        &self,
        cred: &DeviceCred,
        seq: u64,
        r: &InboxResult,
        lab: bool,
    ) -> Result<ResultAck> {
        let used = self.current_token();
        let resp = self
            .device_request(
                reqwest::Method::POST,
                &format!("/v1/inbox/{seq}/result"),
                cred,
                &used,
                lab,
            )?
            .json(r)
            .send()
            .await
            .map_err(reqwest::Error::without_url)
            .context("request to inbox result failed")?;
        self.observe(&resp, &used);
        match resp.status() {
            s if s.is_success() => Ok(ResultAck::Recorded),
            StatusCode::CONFLICT => Ok(ResultAck::Refused),
            StatusCode::NOT_FOUND => Err(anyhow::Error::new(InboxSeqUnknown)),
            StatusCode::UNAUTHORIZED => Err(unauthorized_kind(resp).await),
            other => bail!("inbox result rejected ({})", other.as_u16()),
        }
    }

    /// The device secret travels only over https (`lab` images may use http), same rule as
    /// [`Fetcher::escrow`]. Runs before any request is built.
    fn secret_transport(&self, lab: bool) -> Result<()> {
        if escrow_transport_ok(&self.base, lab).is_err() {
            bail!("refused (local): server_url is not https://, the device secret is only sent over https (only the lab image allows http)");
        }
        Ok(())
    }

    /// The only way to build a device-authenticated request: gates the transport first, then
    /// adds the bearer token and the device headers (ruling R2).
    fn device_request(
        &self,
        method: reqwest::Method,
        path: &str,
        cred: &DeviceCred,
        used: &Option<String>,
        lab: bool,
    ) -> Result<reqwest::RequestBuilder> {
        self.secret_transport(lab)?;
        let req = self
            .escrow_client
            .request(method, format!("{}{path}", self.base));
        Ok(self
            .auth_as(req, used)
            .header(DEVICE_HEADER, &cred.device_id)
            .header(DEVICE_SECRET_HEADER, &cred.secret))
    }

    /// `POST /v1/status`. With `cred` the report also carries the device headers, so the server
    /// can tell it from one sent with the school's token alone; they are left off (the report
    /// still goes) where the device secret may not travel ([`Fetcher::secret_transport`]). With
    /// the headers the request goes through [`Fetcher::device_request`], which never follows a
    /// redirect, so the secret cannot be carried to another address.
    pub async fn report(
        &self,
        r: &StatusReport,
        cred: Option<&DeviceCred>,
        lab: bool,
    ) -> Result<()> {
        let used = self.current_token();
        let req = match cred.filter(|_| self.secret_transport(lab).is_ok()) {
            Some(cred) => self
                .device_request(reqwest::Method::POST, "/v1/status", cred, &used, lab)?
                .json(r),
            None => self.auth_as(
                self.client.post(format!("{}/v1/status", self.base)).json(r),
                &used,
            ),
        };
        let resp = req.send().await.context("request to /v1/status failed")?;
        self.observe(&resp, &used);
        if !resp.status().is_success() {
            bail!("status report refused: {}", resp.status());
        }
        Ok(())
    }
}

/// The diagnostics upload (spec「接口: 上传」). Every failure is a [`DiagUploadError`] whose
/// action comes from [`error_action`]; [`crate::diag::upload::upload`] drives the three steps.
impl Fetcher {
    /// Step 1, `POST /v1/diagnostics` with the device headers: `200` / `201` →
    /// [`DiagUploadResponse`] (either `complete: true`, or an `upload` to use). Any other answer
    /// is a [`DiagUploadError`] with the [`error_action`] of its status and error code. No
    /// redirects; the device secret only travels over https (`lab` images may use http).
    pub async fn diag_upload_url(
        &self,
        cred: &DeviceCred,
        r: &DiagUploadRequest,
        lab: bool,
    ) -> std::result::Result<DiagUploadResponse, DiagUploadError> {
        const STEP: &str = "POST /v1/diagnostics";
        if let Err(e) = r.validate() {
            return Err(DiagUploadError::new(
                ErrorAction::Drop,
                format!("{STEP}: invalid request: {e}"),
            ));
        }
        let used = self.current_token();
        let req = self
            .device_request(reqwest::Method::POST, "/v1/diagnostics", cred, &used, lab)
            .map_err(|e| DiagUploadError::new(ErrorAction::Drop, format!("{STEP}: {e}")))?;
        let resp = req.json(r).send().await.map_err(|e| net_error(STEP, e))?;
        self.observe(&resp, &used);
        let status = resp.status();
        if !(status == StatusCode::OK || status == StatusCode::CREATED) {
            return Err(api_failure(STEP, resp).await);
        }
        let body = read_capped(resp, MAX_DIAG_BODY_BYTES)
            .await
            .map_err(|why| DiagUploadError::new(ErrorAction::Backoff, format!("{STEP}: {why}")))?;
        let a: DiagUploadResponse = serde_json::from_slice(&body).map_err(|_| {
            DiagUploadError::new(
                ErrorAction::Backoff,
                format!("{STEP}: the answer is not valid JSON of the expected shape"),
            )
        })?;
        if !valid_diag_id(&a.id) {
            return Err(DiagUploadError::new(
                ErrorAction::Backoff,
                format!("{STEP}: the answer's id is not a plain identifier"),
            ));
        }
        if !a.complete && a.upload.is_none() {
            return Err(DiagUploadError::new(
                ErrorAction::Backoff,
                format!("{STEP}: the answer has neither complete nor upload"),
            ));
        }
        Ok(a)
    }

    /// Step 2, the presigned `PUT` of `file`: [`diag_put_with`] on this fetcher's upload client.
    pub async fn diag_put(
        &self,
        u: &PresignedUpload,
        file: &Path,
        lab: bool,
    ) -> std::result::Result<u16, DiagUploadError> {
        diag_put_with(&self.upload_client, u, file, lab).await
    }

    /// Step 3, `POST /v1/diagnostics/{id}/complete` with the device headers: 2xx →
    /// [`CompleteOutcome::Done`]; an answer whose [`error_action`] is
    /// [`ErrorAction::Restart`] (`409 upload_mismatch`) → [`CompleteOutcome::Rejected`]; any
    /// other answer is a [`DiagUploadError`].
    pub async fn diag_complete(
        &self,
        cred: &DeviceCred,
        id: &str,
        lab: bool,
    ) -> std::result::Result<CompleteOutcome, DiagUploadError> {
        const STEP: &str = "complete";
        if !valid_diag_id(id) {
            return Err(DiagUploadError::new(
                ErrorAction::Drop,
                format!("{STEP}: the id is not a plain identifier"),
            ));
        }
        let used = self.current_token();
        let req = self
            .device_request(
                reqwest::Method::POST,
                &format!("/v1/diagnostics/{id}/complete"),
                cred,
                &used,
                lab,
            )
            .map_err(|e| DiagUploadError::new(ErrorAction::Drop, format!("{STEP}: {e}")))?;
        let resp = req.send().await.map_err(|e| net_error(STEP, e))?;
        self.observe(&resp, &used);
        if resp.status().is_success() {
            return Ok(CompleteOutcome::Done);
        }
        let e = api_failure(STEP, resp).await;
        if e.action == ErrorAction::Restart {
            log::info!("diagnostics {e}; starting again");
            return Ok(CompleteOutcome::Rejected);
        }
        Err(e)
    }
}

/// The client of the presigned diagnostics `PUT`: never follows a redirect, [`DIAG_PUT_TIMEOUT`].
fn diag_put_client() -> Client {
    no_redirect_client(DIAG_PUT_TIMEOUT)
}

/// The presigned `PUT` of `file` ([`Fetcher::diag_put`]). Returns the 2xx status.
///
/// Sends exactly `u.headers` (values verbatim; names are case-insensitive in HTTP): no
/// `Content-MD5`, no `Content-Type`, no auth or device headers. The body streams from the file,
/// whose length must equal the signed `Content-Length`. Only `PUT`, only https (`lab` images may
/// use http). Errors never carry the URL or S3's error body (it can echo the canonical request,
/// query string included): only the status and S3's `<Code>`. S3 `403` "Request has expired" is
/// [`ErrorAction::Restart`]; S3 `RequestTimeout` (the body came in too slowly: a slow link, not
/// a bad request) is [`ErrorAction::Backoff`]; other S3 answers go through [`error_action`] by
/// status alone.
async fn diag_put_with(
    client: &Client,
    u: &PresignedUpload,
    file: &Path,
    lab: bool,
) -> std::result::Result<u16, DiagUploadError> {
    const STEP: &str = "PUT";
    let bad = |a, why: &str| DiagUploadError::new(a, format!("{STEP}: {why}"));
    if !u.method.eq_ignore_ascii_case("PUT") {
        return Err(bad(ErrorAction::Backoff, "the presigned method is not PUT"));
    }
    let url = reqwest::Url::parse(&u.url)
        .map_err(|_| bad(ErrorAction::Backoff, "the presigned URL is not a valid URL"))?;
    match url.scheme() {
        "https" => {}
        "http" if lab => {}
        _ => {
            return Err(bad(
                ErrorAction::Drop,
                "the presigned URL is not https:// (only lab images allow http)",
            ))
        }
    }
    let mut headers = reqwest::header::HeaderMap::new();
    for (k, v) in &u.headers {
        let name = reqwest::header::HeaderName::from_bytes(k.as_bytes())
            .map_err(|_| bad(ErrorAction::Backoff, "a presigned header name is invalid"))?;
        let value = reqwest::header::HeaderValue::from_str(v)
            .map_err(|_| bad(ErrorAction::Backoff, "a presigned header value is invalid"))?;
        headers.insert(name, value);
    }
    let signed_len = headers
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .ok_or_else(|| {
            bad(
                ErrorAction::Backoff,
                "the presigned headers have no valid Content-Length",
            )
        })?;
    let f = tokio::fs::File::open(file).await.map_err(|e| {
        bad(
            ErrorAction::Drop,
            &format!("opening the archive failed: {e}"),
        )
    })?;
    let len = f
        .metadata()
        .await
        .map_err(|e| {
            bad(
                ErrorAction::Drop,
                &format!("reading the archive failed: {e}"),
            )
        })?
        .len();
    if len != signed_len {
        return Err(bad(
            ErrorAction::Drop,
            &format!("the archive is {len} bytes, the signed Content-Length is {signed_len}"),
        ));
    }
    // A body of unknown length with an explicit Content-Length header: hyper sends exactly that
    // many bytes, without chunked encoding.
    let resp = client
        .put(url)
        .headers(headers)
        .body(reqwest::Body::from(f))
        .send()
        .await
        .map_err(|e| net_error(STEP, e))?;
    let status = resp.status();
    if status.is_success() {
        return Ok(status.as_u16());
    }
    let body = read_capped(resp, MAX_ERROR_BODY_BYTES)
        .await
        .unwrap_or_default();
    let body = String::from_utf8_lossy(&body);
    let code = s3_error_code(&body);
    let action = if status == StatusCode::FORBIDDEN && body.contains("Request has expired") {
        ErrorAction::Restart
    } else if code.as_deref() == Some("RequestTimeout") {
        ErrorAction::Backoff
    } else {
        error_action(status.as_u16(), None)
    };
    let detail = match code {
        Some(c) => format!("{STEP}: S3 answered {} {c}", status.as_u16()),
        None => format!("{STEP}: S3 answered {}", status.as_u16()),
    };
    Err(DiagUploadError::new(action, detail))
}

/// S3's `<Code>` from an XML error body, if it is a plain word (the only part of the body that
/// goes into an error).
fn s3_error_code(body: &str) -> Option<String> {
    let start = body.find("<Code>")? + "<Code>".len();
    let end = start + body[start..].find("</Code>")?;
    let c = &body[start..end];
    (!c.is_empty() && c.len() <= 64 && c.bytes().all(|b| b.is_ascii_alphanumeric()))
        .then(|| c.to_string())
}

/// An upload id goes into a URL path: letters, digits, `-` and `_` only, at most 128.
fn valid_diag_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A request that got no answer: [`ErrorAction::Backoff`]; the text has no URL.
fn net_error(step: &str, e: reqwest::Error) -> DiagUploadError {
    let e = e.without_url();
    let mut text = e.to_string();
    let mut src = std::error::Error::source(&e);
    while let Some(s) = src {
        text.push_str(": ");
        text.push_str(&s.to_string());
        src = s.source();
    }
    DiagUploadError::new(
        ErrorAction::Backoff,
        format!("{step}: request failed: {text}"),
    )
}

/// A non-2xx cloud answer: the action from [`error_action`] with the parsed [`ApiError`], and
/// `Retry-After` for [`ErrorAction::RetryAfter`]. Only the status and the code (a plain word)
/// go into the detail, never the server's message.
async fn api_failure(step: &str, resp: reqwest::Response) -> DiagUploadError {
    let status = resp.status().as_u16();
    let retry_after = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|s| Duration::from_secs(s).min(MAX_RETRY_AFTER));
    let body = read_capped(resp, MAX_ERROR_BODY_BYTES).await.ok();
    let parsed = body.as_deref().and_then(ApiError::parse);
    if parsed.as_ref().is_some_and(|p| p.is_machine_bug()) {
        log::error!("diagnostics upload, {step}: the server says this machine's request is malformed ({status})");
    }
    let action = error_action(status, parsed.as_ref());
    let code = parsed.as_ref().map(|p| p.code.as_str()).filter(|c| {
        !c.is_empty()
            && c.len() <= 64
            && c.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    });
    let detail = match code {
        Some(c) => format!("{step}: the server answered {status} {c}"),
        None => format!("{step}: the server answered {status}"),
    };
    DiagUploadError {
        action,
        retry_after: retry_after.filter(|_| action == ErrorAction::RetryAfter),
        detail,
    }
}

/// Reads a body of at most `cap` bytes.
async fn read_capped(
    mut resp: reqwest::Response,
    cap: usize,
) -> std::result::Result<Vec<u8>, String> {
    let mut body = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > cap {
                    return Err("the answer exceeds the size cap".into());
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(body),
            Err(e) => return Err(format!("reading the answer failed: {}", e.without_url())),
        }
    }
}

/// 托管请求（恢复密钥与托管凭据）与换领令牌能不能发到这个地址（终审 I4，Ruling 27 m4）：只走
/// `https://`；`http://` 只在 lab 镜像（试验网的 mastersos-server 是明文的）时放行——本机回环也不例外，
/// 测试在临时 root 里写 `usr/lib/mastersos/profile = lab`。
/// 拒绝时的说明里不带地址本身（回报里不出现 URL，与 [`Fetcher::escrow`] 的其他错误一致）。
pub fn escrow_transport_ok(base: &str, lab: bool) -> std::result::Result<(), String> {
    let Ok(url) = reqwest::Url::parse(base) else {
        return Err("the seed's server_url is not a valid URL; the recovery key is only escrowed over https".into());
    };
    match url.scheme() {
        "https" => Ok(()),
        "http" if lab => Ok(()),
        "http" => Err(
            "the seed's server_url is plaintext http://: the recovery key and escrow credentials are only sent over https \
             (only lab images allow http); the recovery key stays on this device until an https seed is used"
                .into(),
        ),
        _ => Err("the seed's server_url is not https://; the recovery key is only escrowed over https".into()),
    }
}

/// 重定向的次数上限：已跟随 `MAX_REDIRECTS - 1` 次之后再遇到重定向就停（比 reqwest 默认的 10 次少一次）。
const MAX_REDIRECTS: usize = 10;

/// 按 [`redirect_allowed`] 跟随重定向的策略；agent 所有跟随重定向的 HTTP 客户端都用它
/// （拉包、心跳、回报，设置包里的文件下载，Chrome 的 apt 源）。
pub fn no_downgrade_redirects() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|a| {
        if redirect_allowed(a.previous(), a.url()) {
            a.follow()
        } else {
            a.error("redirect refused (downgrade from https, or too many redirects)")
        }
    })
}

/// 拉包、心跳、回报的重定向策略：一旦走过 https，就只许跳到 https（不降级到明文、带着 `fetch_token`
/// 与设置包），最多 [`MAX_REDIRECTS`] 次。托管请求根本不跟随重定向（[`Fetcher::escrow`]）。
pub fn redirect_allowed(previous: &[reqwest::Url], next: &reqwest::Url) -> bool {
    if previous.len() >= MAX_REDIRECTS {
        return false;
    }
    let was_https = previous.iter().any(|u| u.scheme() == "https");
    match next.scheme() {
        "https" => true,
        "http" => !was_https,
        _ => false,
    }
}

/// 服务端错误体 `{"error": {"code", "message"}}` 里的 message（截短、去掉控制字符）；读不出就是 None。
async fn read_error_message(mut resp: reqwest::Response) -> Option<String> {
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = resp.chunk().await {
        if body.len() + chunk.len() > MAX_ERROR_BODY_BYTES {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    let v: serde_json::Value = serde_json::from_slice(&body).ok()?;
    let m = v.get("error")?.get("message")?.as_str()?;
    let m: String = m
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_ERROR_MESSAGE_CHARS)
        .collect();
    (!m.is_empty()).then_some(m)
}

/// Classifies a 401 from an inbox call by its JSON error code.
async fn unauthorized_kind(mut resp: reqwest::Response) -> anyhow::Error {
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = resp.chunk().await {
        if body.len() + chunk.len() > MAX_ERROR_BODY_BYTES {
            return anyhow::Error::new(Unauthorized);
        }
        body.extend_from_slice(&chunk);
    }
    let code = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("error")?.get("code")?.as_str().map(String::from));
    match code.as_deref() {
        Some("device_auth_missing") => anyhow::Error::new(DeviceAuthMissing),
        _ => anyhow::Error::new(Unauthorized),
    }
}

/// Reads a size-capped JSON body.
async fn read_json<T: serde::de::DeserializeOwned>(
    mut resp: reqwest::Response,
    what: &str,
) -> Result<T> {
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(reqwest::Error::without_url)
        .with_context(|| format!("reading {what} failed"))?
    {
        if body.len() + chunk.len() > MAX_PUSH_BODY_BYTES {
            bail!("{what} exceeds the size cap");
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|_| anyhow!("{what} is not valid JSON of the expected shape"))
}
