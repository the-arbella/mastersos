//! Talking to mastersos-server: fetch the bundle (`wait=0`, never a long poll), the signed
//! heartbeat, status reports, recovery-key escrow, fetch-token renewal, push grants and the inbox.
//!
//! agent 的 HTTP 客户端只在这里构造（Ruling 27 m6）：跟随重定向的一律经 [`http_client`]
//! （带 [`no_downgrade_redirects`]），托管与换领令牌经 [`no_redirect_client`]（不跟随）。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use mastersos_bundle::archive::MAX_BUNDLE_BYTES;
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
        .expect("构造 HTTP 客户端失败（TLS 后端无法初始化）")
}

/// 托管与换领令牌用的客户端：不跟随任何重定向（307/308 会带着恢复密钥、托管凭据重发到 Location）。
fn no_redirect_client(total: Duration) -> Client {
    Client::builder()
        .timeout(total)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("构造 HTTP 客户端失败（TLS 后端无法初始化）")
}

/// 机器侧接口回了 401：当前令牌被拒（主循环据此换用别的来源的令牌）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unauthorized;

impl std::fmt::Display for Unauthorized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("服务器返回 401 Unauthorized（拉取令牌被拒）")
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
            .context("请求 /v1/bundle 失败")?;
        self.observe(&resp, &used);
        match resp.status() {
            StatusCode::UNAUTHORIZED => Err(anyhow::Error::new(Unauthorized)),
            StatusCode::NO_CONTENT => Ok(FetchOutcome::NoChange),
            StatusCode::OK => {
                let version = resp
                    .headers()
                    .get("x-mastersos-version")
                    .ok_or_else(|| anyhow!("响应缺少 X-Mastersos-Version"))?
                    .to_str()
                    .ok()
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .ok_or_else(|| anyhow!("X-Mastersos-Version 不是整数"))?;
                if resp
                    .content_length()
                    .is_some_and(|n| n > MAX_BUNDLE_BYTES as u64)
                {
                    bail!("设置包超过大小上限");
                }
                let mut archive = Vec::new();
                while let Some(chunk) = resp.chunk().await.context("读取设置包失败")? {
                    if archive.len() + chunk.len() > MAX_BUNDLE_BYTES {
                        bail!("设置包超过大小上限");
                    }
                    archive.extend_from_slice(&chunk);
                }
                Ok(FetchOutcome::New { archive, version })
            }
            other => bail!("服务器返回 {other}"),
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
            .context("请求 /v1/heartbeat 失败")?;
        self.observe(&resp, &used);
        match resp.status() {
            StatusCode::NO_CONTENT => Ok(None),
            StatusCode::OK => {
                let mut body = Vec::new();
                while let Some(chunk) = resp.chunk().await.context("读取心跳失败")? {
                    if body.len() + chunk.len() > MAX_HEARTBEAT_BYTES {
                        bail!("心跳超过大小上限");
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(Some(String::from_utf8(body).context("心跳不是 UTF-8")?))
            }
            other => bail!("服务器返回 {other}"),
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
            bail!("托管被拒（本机）：{why}");
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
            .context("请求 /v1/escrow 失败")?;
        self.observe(&resp, &used);
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let message = read_error_message(resp).await;
        match message {
            Some(m) => bail!("托管被拒（{}）：{m}", status.as_u16()),
            None => bail!("托管被拒（{}）", status.as_u16()),
        }
    }

    /// `POST /v1/fetch-token`：凭 `identity.json` 的托管凭据换领当前令牌（Ruling 20）。
    /// 200 → [`RenewOutcome::New`]（令牌不合格当错误）；403 → [`RenewOutcome::Refused`]（带服务端的说明）；
    /// 其余（401、3xx、5xx、连不上）是错误。不跟随重定向；地址不是 https 时不发（[`escrow_transport_ok`]，
    /// `lab` 是镜像的 profile）。错误里不带 URL、凭据与令牌。
    pub async fn renew_token(&self, id: &Identity, lab: bool) -> Result<RenewOutcome> {
        if escrow_transport_ok(&self.base, lab).is_err() {
            bail!(
                "换领被拒（本机）：种子里的 server_url 不是 https://，托管凭据与令牌只经 https 发送（只有 lab 镜像放行 http）"
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
            .context("请求 /v1/fetch-token 失败")?;
        let status = resp.status();
        match status {
            StatusCode::OK => {
                let mut body = Vec::new();
                while let Some(chunk) = resp
                    .chunk()
                    .await
                    .map_err(reqwest::Error::without_url)
                    .context("读取换领响应失败")?
                {
                    if body.len() + chunk.len() > MAX_RENEW_BODY_BYTES {
                        bail!("换领响应超过大小上限");
                    }
                    body.extend_from_slice(&chunk);
                }
                let r: FetchTokenResponse = serde_json::from_slice(&body)
                    .map_err(|_| anyhow!("换领响应不是合法的 JSON"))?;
                if !crate::token::is_valid(&r.fetch_token) {
                    bail!("服务端给的新令牌不合格（空、过长或含不可打印字符）");
                }
                Ok(RenewOutcome::New(r.fetch_token))
            }
            StatusCode::FORBIDDEN => Ok(RenewOutcome::Refused(
                read_error_message(resp)
                    .await
                    .unwrap_or_else(|| "服务端拒绝换领（403）".into()),
            )),
            other => bail!("换领失败（{}）", other.as_u16()),
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
    /// still goes) where the device secret may not travel ([`Fetcher::secret_transport`]).
    pub async fn report(
        &self,
        r: &StatusReport,
        cred: Option<&DeviceCred>,
        lab: bool,
    ) -> Result<()> {
        let used = self.current_token();
        let mut req = self.auth_as(
            self.client.post(format!("{}/v1/status", self.base)).json(r),
            &used,
        );
        if let Some(cred) = cred.filter(|_| self.secret_transport(lab).is_ok()) {
            req = req
                .header(DEVICE_HEADER, &cred.device_id)
                .header(DEVICE_SECRET_HEADER, &cred.secret);
        }
        let resp = req.send().await.context("请求 /v1/status 失败")?;
        self.observe(&resp, &used);
        if !resp.status().is_success() {
            bail!("回报状态被拒：{}", resp.status());
        }
        Ok(())
    }
}

/// 托管请求（恢复密钥与托管凭据）与换领令牌能不能发到这个地址（终审 I4，Ruling 27 m4）：只走
/// `https://`；`http://` 只在 lab 镜像（试验网的 mastersos-server 是明文的）时放行——本机回环也不例外，
/// 测试在临时 root 里写 `usr/lib/mastersos/profile = lab`。
/// 拒绝时的说明里不带地址本身（回报里不出现 URL，与 [`Fetcher::escrow`] 的其他错误一致）。
pub fn escrow_transport_ok(base: &str, lab: bool) -> std::result::Result<(), String> {
    let Ok(url) = reqwest::Url::parse(base) else {
        return Err("种子里的 server_url 不是合法的 URL，恢复密钥只经 https 托管".into());
    };
    match url.scheme() {
        "https" => Ok(()),
        "http" if lab => Ok(()),
        "http" => Err(
            "种子里的 server_url 是明文的 http://：恢复密钥与托管凭据只经 https 发送（只有 lab 镜像放行 http），\
             恢复密钥留在本机，改用 https 的种子后再托管"
                .into(),
        ),
        _ => Err("种子里的 server_url 不是 https://，恢复密钥只经 https 托管".into()),
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
            a.error("重定向被拒（从 https 降级，或次数过多）")
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
