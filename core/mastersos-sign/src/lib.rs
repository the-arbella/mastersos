//! `mastersos-sign`：学校恢复钥匙的离线命令行（Ruling 1、2、15）。
//!
//! 它是 trust 变化的信任锚，所以**不信任服务端**：
//! - 签名前像 agent 一样逐版验证 pin 之后发布的每一版（[`chain`]），差异、摘要、trust 的
//!   增删全在本地从验证过的内容算出；服务端给的 `diff`、`lints` 只作参考打印。
//! - 只签自己构造或验证过的字节：设置包签名的消息由本地下载的内容重算，登记探针的消息
//!   由 nonce 按 `keyid::keyprobe_message` 自己拼，绝不签服务端给的 `message_b64`。
//! - 私钥文件 0600、不覆盖已有文件，私钥不打印到终端、不进日志。
//! - 服务端给的字符串一律经 [`safe`] 转义后才打印：控制序列藏不了行、伪造不了行。
#![forbid(unsafe_code)]

pub mod chain;
pub mod kit;
pub mod safe;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use mastersos_bundle::kit::Kit;
use mastersos_bundle::recipients_changed;
use mastersos_bundle::{
    accept, assemble, check_member_path, content_digest, heartbeat_message, keyid, signed_message,
    trust_fingerprint, verify_heartbeat, Contents, Ed25519Signer, Heartbeat, HeartbeatStatement,
    KeyAlg, Manifest, Seed, SignatureFile, Signer as _, TrustKey, MAX_HEARTBEAT_DAYS,
};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};

use chain::Verified;

// —— 服务端接口 ——

/// A non-2xx answer of the server, kept in the error chain so callers can tell codes apart
/// (`anyhow::Error::chain` + `downcast_ref`) instead of matching the text.
#[derive(Debug)]
pub struct ServerError {
    pub status: u16,
    /// `error.code` of the JSON body, as the server sent it (not escaped: compare, don't print).
    pub code: Option<String>,
    /// What is shown: the action, the status and the escaped message and code.
    text: String,
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

impl std::error::Error for ServerError {}

/// The server's error code in `e`'s chain, if `e` is a non-2xx answer with one.
pub fn server_error_code(e: &anyhow::Error) -> Option<&str> {
    e.chain()
        .find_map(|c| c.downcast_ref::<ServerError>())
        .and_then(|s| s.code.as_deref())
}

/// 管理 API 的客户端：服务器地址加一个 bearer token。token 只从文件读，不接受命令行明文。
pub struct Api {
    base: reqwest::Url,
    token: String,
    client: reqwest::Client,
}

/// 不让 token 出现在任何 Debug 输出里。
impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api")
            .field("base", &self.base.as_str())
            .field("token", &"<redacted>")
            .finish()
    }
}

impl Api {
    pub fn new(server: &str, token: String) -> Result<Api> {
        let base = reqwest::Url::parse(server)
            .with_context(|| format!("服务器地址不是合法的 URL：{server}"))?;
        if !matches!(base.scheme(), "http" | "https") || base.host_str().is_none() {
            bail!("服务器地址要是 https://主机[:端口]：{server}");
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
            bail!("服务器地址必须是 https://（http 只允许 localhost / 127.0.0.1 / ::1）：{server}");
        }
        let token = token.trim().to_owned();
        if token.is_empty() {
            bail!("token 为空");
        }
        Ok(Api {
            base,
            token,
            client: reqwest::Client::new(),
        })
    }

    /// token 从文件读（去掉首尾空白）。
    pub fn from_token_file(server: &str, token_file: &Path) -> Result<Api> {
        let token = std::fs::read_to_string(token_file)
            .with_context(|| format!("读 token 文件 {} 失败", token_file.display()))?;
        Api::new(server, token)
    }

    /// `主机[:端口]`，记在 pin 里。
    pub fn host(&self) -> String {
        let host = self.base.host_str().unwrap_or_default();
        match self.base.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.to_owned(),
        }
    }

    /// pin 的文件名（不含 `.toml`）：主机名，带端口时是 `主机_端口`。
    pub fn pin_name(&self) -> String {
        self.host().replace(':', "_")
    }

    fn url(&self, segments: &[&str]) -> reqwest::Url {
        let mut u = self.base.clone();
        {
            let mut p = u.path_segments_mut().expect("http(s) 的 URL 都有路径");
            p.pop_if_empty();
            for s in segments {
                p.push(s);
            }
        }
        u.set_query(None);
        u
    }

    async fn send(&self, req: reqwest::RequestBuilder, what: &str) -> Result<reqwest::Response> {
        let res = req
            .bearer_auth(&self.token)
            .send()
            .await
            .with_context(|| format!("{what}：连不上服务端"))?;
        let status = res.status();
        if status.is_success() {
            return Ok(res);
        }
        let body = res.text().await.unwrap_or_default();
        let parsed = serde_json::from_str::<Value>(&body).ok();
        let code = parsed
            .as_ref()
            .and_then(|j| j["error"]["code"].as_str())
            .map(str::to_owned);
        let detail = parsed
            .as_ref()
            .and_then(|j| {
                let e = &j["error"];
                Some(format!(
                    "{}（{}）",
                    safe::field(e["message"].as_str()?),
                    safe::field(e["code"].as_str().unwrap_or(""))
                ))
            })
            .unwrap_or_else(|| safe::field(&body));
        Err(ServerError {
            status: status.as_u16(),
            code,
            text: format!("{what}：服务端回 {status}：{detail}"),
        }
        .into())
    }

    async fn get_json<T: DeserializeOwned>(&self, segments: &[&str], what: &str) -> Result<T> {
        let res = self.send(self.client.get(self.url(segments)), what).await?;
        res.json()
            .await
            .with_context(|| format!("{what}：响应不是预期的 JSON"))
    }

    async fn post_json<T: DeserializeOwned>(
        &self,
        segments: &[&str],
        body: Option<&Value>,
        what: &str,
    ) -> Result<T> {
        let mut req = self.client.post(self.url(segments));
        if let Some(b) = body {
            req = req.json(b);
        }
        let res = self.send(req, what).await?;
        res.json()
            .await
            .with_context(|| format!("{what}：响应不是预期的 JSON"))
    }

    async fn get_bytes(&self, segments: &[&str], what: &str) -> Result<Vec<u8>> {
        let res = self.send(self.client.get(self.url(segments)), what).await?;
        Ok(res
            .bytes()
            .await
            .with_context(|| format!("{what}：读响应失败"))?
            .to_vec())
    }

    /// POST 一个 JSON，不要响应体（204）。
    async fn post_no_content(&self, segments: &[&str], body: &Value, what: &str) -> Result<()> {
        self.send(self.client.post(self.url(segments)).json(body), what)
            .await?;
        Ok(())
    }

    /// 已发布的最新版本号；还没发布过时是 0。
    pub async fn latest_version(&self) -> Result<u64> {
        #[derive(Deserialize)]
        struct V {
            version: u64,
        }
        let vs: Vec<V> = self
            .get_json(&["v1", "admin", "versions"], "取版本列表")
            .await?;
        Ok(vs.iter().map(|v| v.version).max().unwrap_or(0))
    }

    /// 第 `v` 版的原始签名包。
    pub async fn version_archive(&self, v: u64) -> Result<Vec<u8>> {
        let vs = v.to_string();
        self.get_bytes(
            &["v1", "admin", "versions", &vs, "archive"],
            &format!("取第 {v} 版的包"),
        )
        .await
    }
}

// —— 钥匙文件与纸面备份 ——

const PEM_BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
const PEM_END: &str = "-----END PRIVATE KEY-----";
const PAPER_BEGIN: &str = "-----BEGIN MASTERSOS RECOVERY KEY-----";
const PAPER_END: &str = "-----END MASTERSOS RECOVERY KEY-----";
/// 纸面备份每行的 base64 字符数（不算分组的空格）。
const PAPER_LINE: usize = 48;
const PAPER_GROUP: usize = 4;

pub struct KeygenOutput {
    pub trust_key: TrustKey,
    /// 可打印的纸面备份。**含私钥**：只写进 0600 的文件去打印，不往终端打。
    pub paper: String,
}

/// 纸面备份含私钥：Debug 输出里打码。
impl std::fmt::Debug for KeygenOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeygenOutput")
            .field("trust_key", &self.trust_key)
            .field("paper", &"<redacted>")
            .finish()
    }
}

/// 从 PKCS#8 得到签名器与 trust 里的那把钥匙（id 按 `keyid::recovery_key_id` 由公钥算出）。
fn key_from_pkcs8(pkcs8: &[u8]) -> Result<(Ed25519Signer, TrustKey)> {
    let probe = Ed25519Signer::from_pkcs8("", pkcs8)?;
    let raw = STANDARD
        .decode(probe.trust_key().public_key)
        .expect("trust_key 的公钥是本库编的 base64");
    let id = keyid::recovery_key_id(&raw);
    let signer = Ed25519Signer::from_pkcs8(&id, pkcs8)?;
    let tk = signer.trust_key();
    Ok((signer, tk))
}

/// 以 0600 新建文件写入私钥材料；文件已存在就拒绝。
fn write_secret(path: &Path, data: &[u8]) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow!(
                "{} already exists; refusing to overwrite it",
                path.display()
            )
        } else {
            anyhow!("cannot create {}: {e}", path.display())
        }
    })?;
    let written = f.write_all(data).and_then(|()| f.sync_all());
    if let Err(e) = written {
        drop(f);
        let _ = std::fs::remove_file(path);
        bail!("cannot write {}: {e}", path.display());
    }
    Ok(())
}

/// 纸面备份写进文件去打印：同私钥一样 0600、不覆盖。
pub fn write_paper(path: &Path, paper: &str) -> Result<()> {
    write_secret(path, paper.as_bytes())
}

fn pem(pkcs8: &[u8]) -> String {
    let b64 = STANDARD.encode(pkcs8);
    let mut s = format!("{PEM_BEGIN}\n");
    for chunk in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(chunk).expect("base64 是 ASCII"));
        s.push('\n');
    }
    s.push_str(PEM_END);
    s.push('\n');
    s
}

/// Open a private key or kit file once, so the owner and mode checked are those of the file
/// read. On unix it must belong to the current user and not be readable or writable by group or
/// others, so another account can neither read nor swap it.
pub(crate) fn open_private(path: &Path) -> Result<std::fs::File> {
    let f = std::fs::File::open(path)
        .with_context(|| format!("cannot open the key file {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let meta = f
            .metadata()
            .with_context(|| format!("cannot read the metadata of {}", path.display()))?;
        let me = nix::unistd::getuid().as_raw();
        if meta.uid() != me {
            bail!(
                "the key file {} belongs to uid {}, not to the current user (uid {me})",
                path.display(),
                meta.uid()
            );
        }
        if meta.mode() & 0o077 != 0 {
            bail!(
                "the key file {} has mode {:o}, other accounts can read or write it: chmod 600 it first",
                path.display(),
                meta.mode() & 0o777
            );
        }
    }
    Ok(f)
}

/// 读钥匙文件（PEM 或裸 DER 的 PKCS#8），属主与权限见 [`open_private`]。
pub fn load_key(path: &Path) -> Result<(Ed25519Signer, TrustKey)> {
    use std::io::Read as _;
    let mut f = open_private(path)?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)
        .with_context(|| format!("读钥匙文件 {} 失败", path.display()))?;
    let der = match std::str::from_utf8(&data) {
        Ok(text) if text.trim_start().starts_with(PEM_BEGIN) => {
            let body: String = text
                .lines()
                .skip_while(|l| l.trim() != PEM_BEGIN)
                .skip(1)
                .take_while(|l| l.trim() != PEM_END)
                .collect::<String>()
                .split_whitespace()
                .collect();
            STANDARD
                .decode(body)
                .with_context(|| format!("{} 不是合法的 PEM", path.display()))?
        }
        _ => data,
    };
    key_from_pkcs8(&der).with_context(|| format!("{} 不是 Ed25519 的 PKCS#8 私钥", path.display()))
}

fn paper(tk: &TrustKey, pkcs8: &[u8], date: &str) -> String {
    let b64 = STANDARD.encode(pkcs8);
    let mut s = String::new();
    s.push_str("MastersOS 恢复钥匙 · 纸面备份\n");
    s.push_str("==========================\n");
    s.push_str(&format!("生成日期：{date}\n"));
    s.push_str(&format!("key id：{}\n", tk.id));
    s.push_str(&format!("指纹：{}\n", trust_fingerprint(tk)));
    s.push_str(&format!("公钥：{}\n\n", tk.public_key));
    s.push_str("私钥（PKCS#8，base64；4 字符一组，每行 48 字符）：\n");
    s.push_str(PAPER_BEGIN);
    s.push('\n');
    for line in b64.as_bytes().chunks(PAPER_LINE) {
        let groups: Vec<&str> = line
            .chunks(PAPER_GROUP)
            .map(|g| std::str::from_utf8(g).expect("base64 是 ASCII"))
            .collect();
        s.push_str(&groups.join(" "));
        s.push('\n');
    }
    s.push_str(PAPER_END);
    s.push_str("\n\n恢复步骤：\n");
    s.push_str("1. 在可信的电脑上把上面 BEGIN 到 END 的几行（连同这两行）照抄进一个文本文件，空格与换行无所谓。\n");
    s.push_str("2. 运行 mastersos-sign restore-from-paper --paper <文本文件> --out <钥匙文件>，核对打印的 key id 与指纹和本页一致。\n");
    s.push_str("3. 签完立即删除钥匙文件与文本文件，本页锁回柜子。\n");
    s
}

/// 生成一把恢复钥匙，私钥以 PKCS#8 PEM 写进 `out`（0600，已存在就拒绝），返回公钥与纸面备份。
pub fn keygen(out: &Path) -> Result<KeygenOutput> {
    let pkcs8 = Ed25519Signer::generate_pkcs8();
    let (_, tk) = key_from_pkcs8(&pkcs8)?;
    write_secret(out, pem(&pkcs8).as_bytes())?;
    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    Ok(KeygenOutput {
        paper: paper(&tk, &pkcs8, &date),
        trust_key: tk,
    })
}

/// 从纸面备份还原私钥写进 `out`（0600，已存在就拒绝）。忽略空白与分组；纸上有 key id 时
/// 还原出来的必须与它一致，抄错一个字符不会悄悄变成另一把钥匙。
pub fn restore_from_paper(paper_text: &str, out: &Path) -> Result<TrustKey> {
    // 每行去掉全部空白再比：标记行与 key id 行抄的时候空格多少都无所谓。
    let squash = |l: &str| l.split_whitespace().collect::<String>();
    let lines: Vec<String> = paper_text.lines().map(squash).collect();
    let (begin, end) = (squash(PAPER_BEGIN), squash(PAPER_END));
    let body: String = match lines.iter().position(|l| *l == begin) {
        Some(start) => {
            let len = lines[start..]
                .iter()
                .position(|l| *l == end)
                .ok_or_else(|| anyhow!("纸面备份里有 {PAPER_BEGIN} 却没有 {PAPER_END}"))?;
            lines[start + 1..start + len].concat()
        }
        None => lines.concat(),
    };
    let pkcs8 = STANDARD
        .decode(&body)
        .context("私钥部分不是合法的 base64：检查是否抄错（0/O、1/l/I）")?;
    let (_, tk) =
        key_from_pkcs8(&pkcs8).context("私钥部分不是合法的 Ed25519 PKCS#8：检查是否抄错")?;
    let written_id = lines
        .iter()
        .find_map(|l| l.strip_prefix("keyid：").map(str::to_owned));
    if let Some(id) = written_id {
        if id != tk.id {
            bail!("还原出的钥匙是 {}，纸上写的是 {id}：私钥部分有抄错", tk.id);
        }
    }
    write_secret(out, pem(&pkcs8).as_bytes())?;
    Ok(tk)
}

// —— 签名钥匙：钥匙文件或恢复钥匙包 ——

/// What signs: a PKCS#8 key file (`--key`) or a recovery kit (`--kit`).
#[derive(Debug, Clone, Copy)]
pub enum SigningKey<'a> {
    File(&'a Path),
    Kit(&'a Kit),
}

impl<'a> From<&'a Path> for SigningKey<'a> {
    fn from(p: &'a Path) -> Self {
        SigningKey::File(p)
    }
}

impl<'a> From<&'a PathBuf> for SigningKey<'a> {
    fn from(p: &'a PathBuf) -> Self {
        SigningKey::File(p)
    }
}

impl<'a> From<&'a Kit> for SigningKey<'a> {
    fn from(k: &'a Kit) -> Self {
        SigningKey::Kit(k)
    }
}

/// The signer and its trust key. A kit must first be a recovery key registered on this server
/// ([`kit::ensure_registered`]), unless `registering`: a wrong kit (another school's, a spare
/// never registered) stops here instead of failing later at the chain or the commit.
async fn load_signer(
    api: &Api,
    key: SigningKey<'_>,
    registering: bool,
) -> Result<(Ed25519Signer, TrustKey)> {
    match key {
        SigningKey::File(p) => load_key(p),
        SigningKey::Kit(k) => {
            let signer = k.signer();
            let tk = signer.trust_key();
            if !registering {
                kit::ensure_registered(api, &tk).await?;
            }
            Ok((signer, tk))
        }
    }
}

// —— 登记 ——

/// 用探针登记恢复钥匙（要带 `keys` 范围的 token）。探针消息由 nonce 在本地拼出，
/// 不签服务端给的 `message_b64`；服务端回的 key_id 必须与本地算的相同。
pub async fn register(api: &Api, key: impl Into<SigningKey<'_>>, label: &str) -> Result<String> {
    let (signer, tk) = load_signer(api, key.into(), true).await?;
    #[derive(Deserialize)]
    struct Probe {
        nonce_b64: String,
    }
    let probe: Probe = api
        .post_json(
            &["v1", "admin", "signing-keys", "probe"],
            None,
            "要登记探针",
        )
        .await?;
    let nonce = STANDARD
        .decode(&probe.nonce_b64)
        .context("探针的 nonce 不是合法的 base64")?;
    if nonce.len() != 32 {
        bail!("探针的 nonce 应为 32 字节，服务端给了 {} 字节", nonce.len());
    }
    let msg = keyid::keyprobe_message(&nonce);
    let signature = SignatureFile {
        key_id: tk.id.clone(),
        alg: KeyAlg::Ed25519,
        sig: STANDARD.encode(signer.sign(&msg)),
        authenticator_data: None,
        client_data_json: None,
    };
    #[derive(Deserialize)]
    struct Registered {
        key_id: String,
        fingerprint: String,
    }
    let body = json!({
        "kind": "recovery",
        "label": label,
        "trust_key": tk,
        "nonce_b64": probe.nonce_b64,
        "signature": signature,
    });
    let r: Registered = api
        .post_json(&["v1", "admin", "signing-keys"], Some(&body), "登记钥匙")
        .await?;
    if r.key_id != tk.id {
        bail!(
            "服务端登记的 key_id 是 {}，本地按公钥算出的是 {}：不一致",
            safe::field(&r.key_id),
            tk.id
        );
    }
    let fp = trust_fingerprint(&tk);
    if r.fingerprint != fp {
        bail!(
            "服务端给的指纹是 {}，本地算出的是 {fp}：不一致",
            safe::field(&r.fingerprint)
        );
    }
    Ok(r.key_id)
}

// —— 打印与确认 ——

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn key_line(k: &TrustKey) -> String {
    format!(
        "{}  {}  {}  rp_id={}",
        safe::field(&k.id),
        k.alg.as_str(),
        trust_fingerprint(k),
        k.rp_id.as_deref().map_or("-".to_owned(), safe::field)
    )
}

pub(crate) fn print_trust(out: &mut dyn Write, trust: &[TrustKey]) -> Result<()> {
    for k in trust {
        writeln!(out, "    {}", key_line(k))?;
    }
    Ok(())
}

/// 两份 trust 的增删改（按 id 配对，同 id 任何字段不同即为改动）。
pub(crate) struct TrustDelta<'a> {
    pub added: Vec<&'a TrustKey>,
    pub removed: Vec<&'a TrustKey>,
    pub modified: Vec<(&'a TrustKey, &'a TrustKey)>,
}

impl<'a> TrustDelta<'a> {
    pub fn between(old: &'a [TrustKey], new: &'a [TrustKey]) -> Self {
        let o: BTreeMap<&str, &TrustKey> = old.iter().map(|k| (k.id.as_str(), k)).collect();
        let n: BTreeMap<&str, &TrustKey> = new.iter().map(|k| (k.id.as_str(), k)).collect();
        TrustDelta {
            added: new
                .iter()
                .filter(|k| !o.contains_key(k.id.as_str()))
                .collect(),
            removed: old
                .iter()
                .filter(|k| !n.contains_key(k.id.as_str()))
                .collect(),
            modified: new
                .iter()
                .filter_map(|k| {
                    o.get(k.id.as_str())
                        .filter(|ok| **ok != k)
                        .map(|ok| (*ok, k))
                })
                .collect(),
        }
    }

    /// 没有增删改。钥匙顺序不影响机器验签，只换顺序不算变化。
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }

    pub fn print(&self, out: &mut dyn Write) -> Result<()> {
        for k in &self.added {
            writeln!(out, "    + 新增  {}", key_line(k))?;
        }
        for k in &self.removed {
            writeln!(out, "    - 移除  {}", key_line(k))?;
        }
        for (o, n) in &self.modified {
            writeln!(out, "    ~ 改动  {}", key_line(o))?;
            writeln!(out, "         →  {}", key_line(n))?;
        }
        Ok(())
    }
}

/// 打印提示，读一行（去掉首尾空白）。读到结尾（没有输入）算取消。
pub(crate) fn ask(confirm: &mut dyn BufRead, out: &mut dyn Write, prompt: &str) -> Result<String> {
    write!(out, "{prompt}")?;
    out.flush()?;
    let mut line = String::new();
    if confirm.read_line(&mut line)? == 0 {
        bail!("没有读到输入，已取消");
    }
    Ok(line.trim().to_owned())
}

// —— 签名 ——

#[derive(Deserialize)]
struct PendingFile {
    path: String,
}

/// 服务端的待发布内容。只取签名要用的字段；`diff`、`lints` 只作参考打印。
#[derive(Deserialize)]
struct Pending {
    pending_id: String,
    version: u64,
    digest_hex: String,
    manifest_text: String,
    files: Vec<PendingFile>,
    #[serde(default)]
    diff: Value,
    #[serde(default)]
    lints: Value,
}

/// The secret values of both sides, longest first, for hiding them in the server's notes; `None`
/// when a side's secrets could not be separated (then nothing the server says about the manifest
/// is printed).
type SecretValues = Option<Vec<String>>;

/// The local diff. Secret values are never printed: both manifests are split into references
/// first ([`mastersos_bundle::secret_ref::split`]), the split texts are diffed, and each secret
/// whose value differs gets one line with its name only.
fn print_local_diff(
    out: &mut dyn Write,
    old: &Verified,
    new_version: u64,
    new: &Contents,
) -> Result<SecretValues> {
    use mastersos_bundle::secret_ref::split;
    let old_v = format!("v{}", old.version);
    let new_v = format!("v{new_version}（待签）");
    writeln!(
        out,
        "\n== 本地算出的差异（第 {} 版 → 第 {new_version} 版）==",
        old.version
    )?;
    let mut values = None;
    match (
        split(&old.contents.manifest_text),
        split(&new.manifest_text),
    ) {
        (Ok((old_split, old_secrets)), Ok((new_split, new_secrets))) => {
            let (old_text, new_text) = (
                safe::escape_lines(&old_split),
                safe::escape_lines(&new_split),
            );
            let text = similar::TextDiff::from_lines(&old_text, &new_text)
                .unified_diff()
                .header(&old_v, &new_v)
                .to_string();
            if text.is_empty() {
                writeln!(out, "manifest.toml：没有变化")?;
            } else {
                writeln!(out, "manifest.toml：")?;
                write!(out, "{}", safe::cap_lines(&text))?;
            }
            let names: BTreeSet<&String> = old_secrets.keys().chain(new_secrets.keys()).collect();
            for name in names {
                let what = match (old_secrets.get(name), new_secrets.get(name)) {
                    (None, Some(_)) => "added",
                    (Some(_), None) => "removed",
                    (Some(a), Some(b)) if a != b => "changed",
                    _ => continue,
                };
                writeln!(out, "secret {}: {what}", safe::field(name))?;
            }
            let mut v: Vec<String> = old_secrets
                .into_values()
                .chain(new_secrets.into_values())
                .filter(|v| !v.is_empty())
                .collect();
            v.sort_by_key(|s| std::cmp::Reverse(s.len()));
            v.dedup();
            values = Some(v);
        }
        _ if old.contents.manifest_text == new.manifest_text => {
            writeln!(out, "manifest.toml：没有变化")?;
        }
        _ => writeln!(
            out,
            "manifest changed (diff hidden: could not separate secrets)"
        )?,
    }
    let short = |b: &[u8]| hex(&<sha2::Sha256 as sha2::Digest>::digest(b))[..16].to_owned();
    let (of, nf) = (&old.contents.files, &new.files);
    let mut any = false;
    for (path, b) in nf {
        let p = safe::field(path);
        match of.get(path) {
            None => writeln!(
                out,
                "  + 新增文件 {p}（{} 字节，sha256 {}…）",
                b.len(),
                short(b)
            )?,
            Some(o) if o != b => writeln!(
                out,
                "  ~ 改动文件 {p}（{} → {} 字节，sha256 {}… → {}…）",
                o.len(),
                b.len(),
                short(o),
                short(b)
            )?,
            Some(_) => continue,
        }
        any = true;
    }
    for (path, b) in of {
        if !nf.contains_key(path) {
            writeln!(
                out,
                "  - 删除文件 {}（{} 字节）",
                safe::field(path),
                b.len()
            )?;
            any = true;
        }
    }
    if !any {
        writeln!(out, "文件：没有变化")?;
    }
    Ok(values)
}

/// Every secret value in `s` replaced with `<secret>`.
fn hide_values(s: &str, values: &[String]) -> String {
    values
        .iter()
        .fold(s.to_owned(), |acc, v| acc.replace(v.as_str(), "<secret>"))
}

fn print_server_notes(out: &mut dyn Write, p: &Pending, secrets: &SecretValues) -> Result<()> {
    writeln!(
        out,
        "\n== 服务端说明（仅供参考：不是将要签名的内容，以上面本地算出的为准）=="
    )?;
    let hide = |s: &str| secrets.as_deref().map(|v| hide_values(s, v));
    if let Some(d) = p.diff["manifest_diff"].as_str().filter(|d| !d.is_empty()) {
        match hide(d) {
            Some(d) => {
                writeln!(out, "服务端给的清单差异：")?;
                write!(out, "{}", safe::text(&d))?;
                if !d.ends_with('\n') {
                    writeln!(out)?;
                }
            }
            None => writeln!(
                out,
                "The server's manifest diff is hidden: secrets could not be separated"
            )?,
        }
    }
    match p.lints.as_array() {
        Some(ls) if !ls.is_empty() => {
            for l in ls {
                writeln!(
                    out,
                    "  [{}] {}：{}",
                    safe::field(l["level"].as_str().unwrap_or("?")),
                    safe::field(l["code"].as_str().unwrap_or("?")),
                    safe::field(
                        &hide(l["message"].as_str().unwrap_or(""))
                            .unwrap_or_else(|| "(message hidden)".into())
                    )
                )?;
            }
        }
        _ => writeln!(out, "  （没有 lint）")?,
    }
    Ok(())
}

/// 取待发布内容（`pending` 是上传得到的待签名包 id），本地验链、算差异、打印完整 trust，
/// 人键入版本号（trust 有变化时再键入 `trust`）后用恢复钥匙签名提交，pin 前进到新版本。
/// 返回新版本号。
pub async fn sign_pending(
    api: &Api,
    key: impl Into<SigningKey<'_>>,
    pin_dir: &Path,
    pending: &str,
    confirm: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<u64> {
    let mut out = safe::SafeWriter::new(out);
    let out: &mut dyn Write = &mut out;
    let (signer, me) = load_signer(api, key.into(), false).await?;
    let p: Pending = api
        .get_json(
            &["v1", "admin", "publish", "pending", pending],
            "取待发布内容",
        )
        .await?;

    // 1. 逐个下载文件，本地重算摘要。
    let mut files = BTreeMap::new();
    for f in &p.files {
        check_member_path(&f.path)
            .with_context(|| format!("待发布内容里有不安全的路径：{}", safe::field(&f.path)))?;
        let mut segs = vec!["v1", "admin", "publish", "pending", &p.pending_id, "files"];
        segs.extend(f.path.split('/'));
        let bytes = api
            .get_bytes(&segs, &format!("下载待发布文件 {}", safe::field(&f.path)))
            .await?;
        if files.insert(f.path.clone(), bytes).is_some() {
            bail!("待发布内容的文件列表里 {} 出现了两次", safe::field(&f.path));
        }
    }
    let contents = Contents {
        manifest_text: p.manifest_text.clone(),
        files,
    };
    let digest = hex(&content_digest(&contents));
    if !digest.eq_ignore_ascii_case(p.digest_hex.trim()) {
        bail!(
            "摘要不一致：本地按下载的内容算出 {digest}，服务端说是 {}。服务端给的内容与它要提交的不是同一份，不签",
            p.digest_hex
        );
    }
    let manifest = Manifest::parse(&contents.manifest_text)?;
    let present: BTreeSet<String> = contents.files.keys().cloned().collect();
    manifest
        .validate(&present)
        .context("待发布内容机器会拒收（清单校验不过），不签")?;

    // 2. 本地逐版验链。Nothing published yet: there is no chain. The first version (R1g) is
    //    verified with its own trust, and that whole trust counts as added, so the human checks
    //    every key's fingerprint and types `trust` before it is signed.
    let genesis = api.latest_version().await? == 0;
    let pin_file = chain::pin_path(pin_dir, api);
    if genesis {
        // A server that says nothing is published while a version was verified here is lying or
        // was replaced: signing a "first version" would hand it a recovery-key signature over a
        // trust it chose, and reset the local anchor to its chain.
        if let Some(pin) = chain::load_pin(&pin_file)? {
            bail!(
                "the server reports nothing published, but version {} was verified here (pin {}): \
                 possible rollback or wrong server; not signing. Delete that pin file only if you \
                 are sure the server was reset on purpose",
                pin.version,
                pin_file.display()
            );
        }
    }
    let (verified, base_trust) = if genesis {
        let base = Verified {
            version: 0,
            digest_hex: String::new(),
            trust: manifest.trust.clone(),
            contents: Contents {
                manifest_text: String::new(),
                files: BTreeMap::new(),
            },
            latest: 0,
            history: Vec::new(),
        };
        (base, Vec::new())
    } else {
        let v = chain::verify_chain(api, pin_dir, confirm, out).await?;
        let t = v.trust.clone();
        (v, t)
    };

    // 3. 版本相接，且本钥匙在已验证的 trust 里。`verified.version` is the version machines
    //    accept (the base for every check below); `verified.latest` the newest on the chain.
    let next = verified.latest + 1;
    if manifest.version != next || p.version != next {
        bail!(
            "待发布内容是第 {} 版（服务端标的是第 {} 版），而本地验证到的最新版是第 {} 版：应当是第 {next} 版，不签",
            manifest.version,
            p.version,
            verified.latest
        );
    }
    if !verified.trust.contains(&me) {
        bail!(
            "这把钥匙（{}）不在本地验证过的第 {} 版 trust 里：机器不认它的签名",
            key_line(&me),
            verified.version
        );
    }
    if !manifest.trust.contains(&me) {
        bail!(
            "新 trust 里没有这把钥匙（{}）：签名者不能把自己移出 trust（R5），要移除它请用另一把留下的钥匙签",
            me.id
        );
    }

    // 4. 本地差异。
    let secret_values = print_local_diff(out, &verified, next, &contents)?;

    // 5. 完整 trust 与增删改。
    writeln!(
        out,
        "\n== 第 {next} 版的完整 trust（共 {} 把；机器从这一版起只认这些钥匙）==",
        manifest.trust.len()
    )?;
    print_trust(out, &manifest.trust)?;
    let delta = TrustDelta::between(&base_trust, &manifest.trust);
    if genesis {
        writeln!(
            out,
            "This is the first version (R1g): machines verify it with its own trust. Check every \
             fingerprint against what you hold, not against this server's pages: your recovery key's \
             fingerprint as printed by `mastersos-sign keygen` / `register` (or on the printed kit), and \
             each passkey's fingerprint shown when it was registered on your device."
        )?;
        delta.print(out)?;
    } else if delta.is_empty() {
        writeln!(out, "trust 与第 {} 版相同。", verified.version)?;
    } else {
        writeln!(
            out,
            "trust 有变化（相对本地验证过的第 {} 版）：",
            verified.version
        )?;
        delta.print(out)?;
        writeln!(
            out,
            "请逐把对照钥匙页上的指纹：多出一把不认识的钥匙，就等于把机器交给了它。"
        )?;
    }

    // Escrow recipients against the same base (machines seal their LUKS recovery keys to them).
    let base_recipients = if genesis {
        Vec::new()
    } else {
        Manifest::parse(&verified.contents.manifest_text)
            .context("the verified base version's manifest does not parse")?
            .school
            .escrow_recipients
    };
    let recipients_change =
        recipients_changed(&base_recipients, &manifest.school.escrow_recipients);
    if recipients_change {
        writeln!(
            out,
            "Escrow recipients change (against version {} that machines run; they will seal their \
             LUKS recovery keys to these):",
            verified.version
        )?;
        for r in &base_recipients {
            if !manifest.school.escrow_recipients.contains(r) {
                writeln!(out, "  - {}", safe::field(r))?;
            }
        }
        for r in &manifest.school.escrow_recipients {
            if !base_recipients.contains(r) {
                writeln!(out, "  + {}", safe::field(r))?;
            }
        }
        writeln!(
            out,
            "Check every added recipient against your kits: an unknown one receives the machines' \
             recovery keys."
        )?;
    }

    print_server_notes(out, &p, &secret_values)?;

    // 6. 人工确认。
    writeln!(out, "\n本地算出的摘要：{digest}")?;
    let typed = ask(confirm, out, &format!("输入版本号 {next} 确认签名："))?;
    if typed != next.to_string() {
        bail!("输入的版本号「{typed}」与待签的第 {next} 版不符，已取消，没有签名");
    }
    if !delta.is_empty() || recipients_change {
        let typed = ask(
            confirm,
            out,
            "这一版改变了机器信任的钥匙或托管收件人（见上面的增删）。确认无误请再输入 trust：",
        )?;
        if typed != "trust" {
            bail!("没有确认 trust 或托管收件人的变化，已取消，没有签名");
        }
    }

    // 7. 签名（消息由本地内容算出）→ 本地像机器一样收一遍 → 提交 → pin 前进。
    let signature = SignatureFile {
        key_id: me.id.clone(),
        alg: KeyAlg::Ed25519,
        sig: STANDARD.encode(signer.sign(&signed_message(&contents))),
        authenticator_data: None,
        client_data_json: None,
    };
    let archive = assemble(&contents, &signature)?;
    accept(
        &archive,
        &verified.trust,
        (!genesis).then_some(verified.version),
    )
    .context("签好的包本地自检不过：机器会拒收，不提交")?;
    #[derive(Deserialize)]
    struct Committed {
        version: u64,
    }
    let body = json!({ "confirm_digest": digest, "signature": signature });
    let c: Committed = api
        .post_json(
            &["v1", "admin", "publish", "pending", &p.pending_id, "commit"],
            Some(&body),
            "提交签名",
        )
        .await?;
    if c.version != next {
        bail!(
            "服务端说发布成了第 {} 版，签的是第 {next} 版：pin 不前进，请运行 mastersos-sign verify 重新核对",
            c.version
        );
    }
    // The pin on disk is the one this run verified from (none for the first version).
    let prev = (!genesis).then(|| chain::pin_of(api, &verified));
    let mut history = verified.history.clone();
    chain::record_verified(&mut history, next, &digest);
    chain::save_pin(
        &pin_file,
        prev.as_ref(),
        &chain::Pin {
            host: api.host(),
            version: next,
            digest_hex: digest,
            trust: manifest.trust.clone(),
            verified: history,
        },
    )?;
    writeln!(out, "已签名并发布第 {next} 版，pin 前进到第 {next} 版。")?;
    Ok(next)
}

// —— 心跳续签 ——

/// Unix 秒 → 「本地时区 / UTC」两种写法；超出可表示范围时只写秒数。
fn both_zones(secs: i64) -> String {
    match chrono::DateTime::from_timestamp(secs, 0) {
        Some(t) => format!(
            "{}（本地）/ {}",
            t.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S %:z"),
            t.format("%Y-%m-%d %H:%M:%S UTC")
        ),
        None => format!("Unix {secs}"),
    }
}

/// 学校钥匙模式下续签心跳（Ruling 11、C3）。同 [`sign_heartbeat_at`]，时刻取本机现在。
pub async fn sign_heartbeat(
    api: &Api,
    key: impl Into<SigningKey<'_>>,
    pin_dir: &Path,
    days: i64,
    confirm: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<()> {
    sign_heartbeat_at(api, key, pin_dir, days, chrono::Utc::now(), confirm, out).await
}

/// 续签心跳，`issued_at` 取 `now`：
///
/// 1. `days` 不在 1..=31 → 报错。
/// 2. 本地逐版验链（[`chain::verify_chain`]）；签名钥匙必须在验证过的最新 trust 里。
/// 3. **自己构造**声明：版本与摘要取自本地验证过的最新版（摘要本地算），`issued_at = now`，
///    `not_after = now + days 天`。不用服务端的 `heartbeat/prepare`。
/// 4. 打印版本、摘要前 16 位、`issued_at` 与 `not_after`（本地时区与 UTC 各一份），
///    键入版本号确认后签名，本地像机器一样验一遍，再提交 `heartbeat/commit`。
pub async fn sign_heartbeat_at(
    api: &Api,
    key: impl Into<SigningKey<'_>>,
    pin_dir: &Path,
    days: i64,
    now: chrono::DateTime<chrono::Utc>,
    confirm: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<()> {
    if !(1..=MAX_HEARTBEAT_DAYS).contains(&days) {
        bail!("--days 要在 1 到 {MAX_HEARTBEAT_DAYS} 之间（心跳最长 {MAX_HEARTBEAT_DAYS} 天）");
    }
    let mut out = safe::SafeWriter::new(out);
    let out: &mut dyn Write = &mut out;
    let (signer, me) = load_signer(api, key.into(), false).await?;
    let verified = chain::verify_chain(api, pin_dir, confirm, out).await?;
    if !verified.trust.contains(&me) {
        bail!(
            "这把钥匙（{}）不在本地验证过的第 {} 版 trust 里：机器不认它签的心跳",
            key_line(&me),
            verified.version
        );
    }
    let issued_at = now.timestamp();
    let statement = HeartbeatStatement {
        version: verified.version,
        digest_hex: verified.digest_hex.clone(),
        issued_at,
        not_after: issued_at + days * 86_400,
    };
    statement.check()?;

    writeln!(out, "\n== 续签心跳（内容由本机从验证过的版本算出）==")?;
    writeln!(
        out,
        "版本：      第 {} 版（本地验证过的最新版）",
        statement.version
    )?;
    writeln!(out, "摘要前 16 位：{}", &statement.digest_hex[..16])?;
    writeln!(out, "issued_at： {}", both_zones(statement.issued_at))?;
    writeln!(
        out,
        "not_after： {}（{days} 天）",
        both_zones(statement.not_after)
    )?;
    writeln!(
        out,
        "到期之前，机器把第 {} 版当作最新设置；服务端在这段时间里扣住新版本，机器看不出来。",
        statement.version
    )?;
    let typed = ask(
        confirm,
        out,
        &format!("输入版本号 {} 确认签名：", statement.version),
    )?;
    if typed != statement.version.to_string() {
        bail!(
            "输入的版本号「{typed}」与第 {} 版不符，已取消，没有签名",
            statement.version
        );
    }

    let signature = SignatureFile {
        key_id: me.id.clone(),
        alg: KeyAlg::Ed25519,
        sig: STANDARD.encode(signer.sign(&heartbeat_message(&statement))),
        authenticator_data: None,
        client_data_json: None,
    };
    let text = Heartbeat {
        statement: statement.clone(),
        signature: signature.clone(),
    }
    .to_toml();
    verify_heartbeat(&text, &verified.trust)
        .context("签好的心跳本地自检不过：机器会拒收，不提交")?;
    api.post_no_content(
        &["v1", "admin", "heartbeat", "commit"],
        &json!({ "statement": statement, "signature": signature }),
        "提交心跳",
    )
    .await?;
    writeln!(
        out,
        "已续签第 {} 版的心跳，到 {} 为止。",
        statement.version,
        both_zones(statement.not_after)
    )?;
    Ok(())
}

// —— 种子核对 ——

/// 种子开头的指纹注释：`# <id>  <alg>  <xxxx-xxxx-xxxx-xxxx>`。
fn seed_header(seed_text: &str) -> Vec<(String, String)> {
    let is_fp = |s: &str| {
        s.len() == 19
            && s.split('-').count() == 4
            && s.split('-')
                .all(|g| g.len() == 4 && g.bytes().all(|b| b.is_ascii_hexdigit()))
    };
    seed_text
        .lines()
        .take_while(|l| l.trim().is_empty() || l.trim_start().starts_with('#'))
        .filter_map(|l| {
            let words: Vec<&str> = l
                .trim_start()
                .strip_prefix('#')?
                .split_whitespace()
                .collect();
            match words.as_slice() {
                [id @ .., _alg, fp] if !id.is_empty() && is_fp(fp) => {
                    Some((id.join(" "), (*fp).to_owned()))
                }
                _ => None,
            }
        })
        .collect()
}

/// 先本地验链，再核对种子：`trust` 要等于验证过的最新 trust，`min_version` 要等于最新版本号，
/// 开头注释的指纹要与 trust 一一对应。不一致 → 列出差异并报错。要先有 pin（首次用 `verify`）。
pub async fn seed_check(
    api: &Api,
    pin_dir: &Path,
    seed_text: &str,
    out: &mut dyn Write,
) -> Result<()> {
    let mut out = safe::SafeWriter::new(out);
    let out: &mut dyn Write = &mut out;
    if !chain::pin_path(pin_dir, api).exists() {
        bail!(
            "还没有 {} 的 pin：先运行 mastersos-sign verify，对照钥匙页确认一次 trust 指纹",
            api.host()
        );
    }
    let verified = chain::verify_chain(api, pin_dir, &mut std::io::empty(), out).await?;
    let seed = Seed::parse(seed_text).context("种子不是合法的 TOML")?;
    let mut problems: Vec<String> = Vec::new();
    // The strict Wi-Fi checks parsing leaves out; the message never carries a secret.
    if let Err(e) = seed.validate() {
        problems.push(format!(
            "the seed's Wi-Fi does not pass the checks: {}",
            safe::field(&e.to_string())
        ));
    }

    let delta = TrustDelta::between(&verified.trust, &seed.trust);
    if !delta.is_empty() {
        let mut buf = Vec::new();
        delta.print(&mut buf)?;
        problems.push(format!(
            "种子的 trust 与本地验证过的第 {} 版不同（+ 是种子多出的，- 是种子缺的）：\n{}",
            verified.version,
            String::from_utf8_lossy(&buf).trim_end()
        ));
    }
    if seed.min_version != Some(verified.version) {
        problems.push(format!(
            "种子的 min_version 是 {}，应为最新版本 {}",
            seed.min_version
                .map_or("（没有）".to_owned(), |v| v.to_string()),
            verified.version
        ));
    }
    let header = seed_header(seed_text);
    let expected: Vec<(String, String)> = seed
        .trust
        .iter()
        .map(|k| (k.id.replace(['\r', '\n'], " "), trust_fingerprint(k)))
        .collect();
    if header != expected {
        let mut s = String::from("种子开头注释的指纹与种子的 trust 对不上：\n    注释：");
        for (id, fp) in &header {
            s.push_str(&format!("\n      {}  {}", safe::field(id), safe::field(fp)));
        }
        s.push_str("\n    按 trust 算：");
        for (id, fp) in &expected {
            s.push_str(&format!("\n      {}  {}", safe::field(id), safe::field(fp)));
        }
        problems.push(s);
    }

    if problems.is_empty() {
        writeln!(
            out,
            "种子与本地验证过的第 {} 版一致：trust {} 把、min_version = {}。",
            verified.version,
            seed.trust.len(),
            verified.version
        )?;
        print_trust(out, &seed.trust)?;
        return Ok(());
    }
    writeln!(out, "种子与本地验证过的内容不一致：")?;
    for p in &problems {
        writeln!(out, "  * {p}")?;
    }
    bail!("种子与本地验证过的 trust / 版本不一致：不要用它装机器")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verified(text: &str) -> Verified {
        Verified {
            version: 1,
            digest_hex: String::new(),
            trust: Vec::new(),
            contents: Contents {
                manifest_text: text.into(),
                files: BTreeMap::new(),
            },
            latest: 1,
            history: Vec::new(),
        }
    }

    #[test]
    fn sign_diff_never_prints_secret_values() {
        let old = verified(
            "version = 1\n[defaults]\nwifi = [{ ssid = \"Staff\", psk = \"oldpass-111\" }, { ssid = \"Lab\", psk = \"labpass-333\" }]\n",
        );
        let new = Contents {
            manifest_text: "version = 2\n[defaults]\nwifi = [{ ssid = \"Staff\", psk = \"newpass-222\" }, { ssid = \"Guest\", psk = \"guestpass-444\" }]\n".into(),
            files: BTreeMap::new(),
        };
        let mut out = Vec::new();
        let values = print_local_diff(&mut out, &old, 2, &new).unwrap();
        let text = String::from_utf8(out).unwrap();
        for v in ["oldpass-111", "newpass-222", "labpass-333", "guestpass-444"] {
            assert!(!text.contains(v), "{text}");
        }
        assert!(
            text.contains("secret defaults-staff-psk: changed"),
            "{text}"
        );
        assert!(text.contains("secret defaults-guest-psk: added"), "{text}");
        assert!(text.contains("secret defaults-lab-psk: removed"), "{text}");
        assert!(text.contains("+version = 2"), "{text}");

        // The server's notes are cleaned with the same values.
        let p = Pending {
            pending_id: "p".into(),
            version: 2,
            digest_hex: String::new(),
            manifest_text: String::new(),
            files: Vec::new(),
            diff: json!({ "manifest_diff": "-psk = \"oldpass-111\"\n+psk = \"newpass-222\"\n" }),
            lints: json!([{ "level": "warning", "code": "x", "message": "psk newpass-222 is weak" }]),
        };
        let mut out = Vec::new();
        print_server_notes(&mut out, &p, &values).unwrap();
        let notes = String::from_utf8(out).unwrap();
        assert!(
            !notes.contains("oldpass-111") && !notes.contains("newpass-222"),
            "{notes}"
        );

        // A side whose secrets cannot be separated: no text diff at all.
        let bad = Contents {
            manifest_text: "version = 2\n[defaults]\nwifi = [{ ssid = \"Staff\", psk = 12345678 }]\n# newpass-222\n".into(),
            files: BTreeMap::new(),
        };
        let mut out = Vec::new();
        let values = print_local_diff(&mut out, &old, 2, &bad).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(values.is_none());
        assert!(
            text.contains("manifest changed (diff hidden: could not separate secrets)"),
            "{text}"
        );
        assert!(
            !text.contains("oldpass-111") && !text.contains("newpass-222"),
            "{text}"
        );
        let mut out = Vec::new();
        print_server_notes(&mut out, &p, &values).unwrap();
        let notes = String::from_utf8(out).unwrap();
        assert!(
            !notes.contains("oldpass-111") && !notes.contains("newpass-222"),
            "{notes}"
        );
    }

    #[test]
    fn local_diff_escapes_control_chars() {
        let old = Verified {
            version: 1,
            digest_hex: String::new(),
            trust: Vec::new(),
            contents: Contents {
                manifest_text: "version = 1\n".into(),
                files: BTreeMap::new(),
            },
            latest: 1,
            history: Vec::new(),
        };
        let mut files = BTreeMap::new();
        files.insert("files/a\u{1b}[2K\r.txt".to_owned(), b"x".to_vec());
        let new = Contents {
            // TOML refuses raw control characters even in comments (such a manifest never reaches
            // the diff: it is parsed first), so the manifest side carries only a bidi override.
            manifest_text: "version = 2\n# 伪造的一行\u{202e}\n".into(),
            files,
        };
        let mut out = Vec::new();
        print_local_diff(&mut out, &old, 2, &new).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            !out.chars()
                .any(|c| (c.is_control() && c != '\n') || c == '\u{202e}'),
            "{out:?}"
        );
        assert!(out.contains("+# 伪造的一行\\u{202e}"), "{out}");
        assert!(out.contains("files/a\\x1b[2K\\r.txt"), "{out}");
    }
}
