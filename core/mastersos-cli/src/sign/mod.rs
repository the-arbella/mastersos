//! Signing with the school key on this computer: register it, verify the published history,
//! approve a version, sign the monthly check-in, compare an install file (Ruling 1, 2, 15).
//!
//! It is the trust anchor for trust changes, so it **does not trust the server**:
//! - Before signing, every version published after the pin is verified one by one, as the agent
//!   does ([`chain`]); differences, digests and trust additions and removals are all computed
//!   here from verified content. The server's `diff` and `lints` are printed for information only.
//! - Only bytes built or verified here are signed: the bundle signature's message is recomputed
//!   from the downloaded content, the registration probe's message is built from the nonce with
//!   `keyid::keyprobe_message`; the server's `message_b64` is never signed.
//! - The school key is never printed to the terminal or written to a log.
//! - Every string from the server is escaped by [`safe`] before it is printed: control sequences
//!   can neither hide a line nor forge one.
pub mod chain;
pub mod kit;

use crate::safe;

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};
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

// —— The server API ——

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

/// The admin API client: the server address and a bearer token. The token is read from a file
/// only, never taken in clear text on the command line.
pub struct Api {
    base: reqwest::Url,
    token: String,
    client: reqwest::Client,
}

/// Keeps the token out of every Debug output.
impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api")
            .field("base", &self.base.as_str())
            .field("token", &"<redacted>")
            .finish()
    }
}

/// `host[:port]` of a server URL (an explicit non-default port only).
fn host_of(url: &reqwest::Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_owned(),
    }
}

/// What a pin records for a server: `host[:port]` plus the path without a trailing `/`. Several
/// organisations can share one host and differ only by path (`https://h/org/a/devices`, `https://h/org/b/devices`);
/// each has its own version chain, so the path is part of the key. A server without a path keeps the plain `host[:port]`.
fn server_key(url: &reqwest::Url) -> String {
    format!("{}{}", host_of(url), url.path().trim_end_matches('/'))
}

/// The pin file name (without `.toml`): `host[_port]`, then `+<segment>` for every path segment, each segment
/// percent-encoded down to `[A-Za-z0-9.-]` (`+` and `_` cannot appear in a host or be confused with a port). A server
/// without a path gets the same name as before paths were part of the key.
fn pin_file_name(url: &reqwest::Url) -> String {
    let mut name = host_of(url).replace(':', "_");
    for seg in url.path().split('/').filter(|s| !s.is_empty()) {
        name.push('+');
        for b in seg.bytes() {
            if b.is_ascii_alphanumeric() || b == b'.' || b == b'-' {
                name.push(b as char);
            } else {
                name.push_str(&format!("%{b:02X}"));
            }
        }
    }
    name
}

/// The pin file name (without `.toml`) for a server address, the same as [`Api::pin_name`]; no
/// token is needed, so offline commands can find the pin.
pub fn pin_name_for(server: &str) -> Result<String> {
    let url = reqwest::Url::parse(server)
        .with_context(|| format!("the server address is not a valid URL: {server}"))?;
    if url.host_str().is_none() {
        bail!("the server address has no host: {server}");
    }
    Ok(pin_file_name(&url))
}

impl Api {
    pub fn new(server: &str, token: String) -> Result<Api> {
        let base = reqwest::Url::parse(server)
            .with_context(|| format!("The server address is not a valid URL: {server}"))?;
        if !matches!(base.scheme(), "http" | "https") || base.host_str().is_none() {
            bail!("The server address must be https://host[:port]: {server}");
        }
        // http would send the token in clear text: only the loopback address (tests, local demos) may.
        let host = base.host_str().unwrap_or_default();
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback());
        if base.scheme() == "http" && !loopback {
            bail!("The server address must be https:// (http is only allowed for localhost / 127.0.0.1 / ::1): {server}");
        }
        let token = token.trim().to_owned();
        if token.is_empty() {
            bail!("The token is empty");
        }
        Ok(Api {
            base,
            token,
            client: reqwest::Client::new(),
        })
    }

    /// The token read from a file (surrounding whitespace removed).
    pub fn from_token_file(server: &str, token_file: &Path) -> Result<Api> {
        let token = std::fs::read_to_string(token_file)
            .with_context(|| format!("Could not read the token file {}", token_file.display()))?;
        Api::new(server, token)
    }

    /// `host[:port][/path]`, recorded in the pin (organisations on one host differ only by path,
    /// and each has its own version chain).
    pub fn host(&self) -> String {
        server_key(&self.base)
    }

    /// The pin file name (without `.toml`): the host, `host_port` with a port, then `+segment`
    /// for every path segment.
    pub fn pin_name(&self) -> String {
        pin_file_name(&self.base)
    }

    fn url(&self, segments: &[&str]) -> reqwest::Url {
        let mut u = self.base.clone();
        {
            let mut p = u.path_segments_mut().expect("an http(s) URL has a path");
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
            .with_context(|| format!("{what}: cannot reach the server"))?;
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
                    "{} ({})",
                    safe::field(e["message"].as_str()?),
                    safe::field(e["code"].as_str().unwrap_or(""))
                ))
            })
            .unwrap_or_else(|| safe::field(&body));
        Err(ServerError {
            status: status.as_u16(),
            code,
            text: format!("{what}: the server answered {status}: {detail}"),
        }
        .into())
    }

    async fn get_json<T: DeserializeOwned>(&self, segments: &[&str], what: &str) -> Result<T> {
        let res = self.send(self.client.get(self.url(segments)), what).await?;
        res.json()
            .await
            .with_context(|| format!("{what}: the response is not the expected JSON"))
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
            .with_context(|| format!("{what}: the response is not the expected JSON"))
    }

    async fn get_bytes(&self, segments: &[&str], what: &str) -> Result<Vec<u8>> {
        let res = self.send(self.client.get(self.url(segments)), what).await?;
        Ok(res
            .bytes()
            .await
            .with_context(|| format!("{what}: could not read the response"))?
            .to_vec())
    }

    /// POST a JSON body and expect no response body (204).
    async fn post_no_content(&self, segments: &[&str], body: &Value, what: &str) -> Result<()> {
        self.send(self.client.post(self.url(segments)).json(body), what)
            .await?;
        Ok(())
    }

    /// The latest published version; 0 when nothing is published yet.
    pub async fn latest_version(&self) -> Result<u64> {
        #[derive(Deserialize)]
        struct V {
            version: u64,
        }
        let vs: Vec<V> = self
            .get_json(&["v1", "admin", "versions"], "list versions")
            .await?;
        Ok(vs.iter().map(|v| v.version).max().unwrap_or(0))
    }

    /// The signed package of version `v`, as it is.
    pub async fn version_archive(&self, v: u64) -> Result<Vec<u8>> {
        let vs = v.to_string();
        self.get_bytes(
            &["v1", "admin", "versions", &vs, "archive"],
            &format!("fetch the package of version {v}"),
        )
        .await
    }
}

// —— Signing with the school key ——

/// The signer and its trust key. The school key must first be a recovery key registered on this
/// server ([`kit::ensure_registered`]), unless `registering`: a wrong one (another school's, a
/// spare never registered) stops here instead of failing later at the chain or the commit.
async fn load_signer(api: &Api, kit: &Kit, registering: bool) -> Result<(Ed25519Signer, TrustKey)> {
    let signer = kit.signer();
    let tk = signer.trust_key();
    if !registering {
        kit::ensure_registered(api, &tk).await?;
    }
    Ok((signer, tk))
}

// —— Registration ——

/// Register the school key as a recovery key with a probe. The probe message is built here from
/// the nonce (the server's `message_b64` is never signed); the key_id the server answers must equal
/// the one computed here.
pub async fn register(api: &Api, kit: &Kit, label: &str) -> Result<String> {
    let (signer, tk) = load_signer(api, kit, true).await?;
    #[derive(Deserialize)]
    struct Probe {
        nonce_b64: String,
    }
    let probe: Probe = api
        .post_json(
            &["v1", "admin", "signing-keys", "probe"],
            None,
            "get the registration probe",
        )
        .await?;
    let nonce = STANDARD
        .decode(&probe.nonce_b64)
        .context("The probe nonce is not valid base64")?;
    if nonce.len() != 32 {
        bail!(
            "The probe nonce should be 32 bytes, the server gave {}",
            nonce.len()
        );
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
        .post_json(
            &["v1", "admin", "signing-keys"],
            Some(&body),
            "register the key",
        )
        .await?;
    if r.key_id != tk.id {
        bail!(
            "The server registered key_id {}, but the public key gives {} here: they differ",
            safe::field(&r.key_id),
            tk.id
        );
    }
    let fp = trust_fingerprint(&tk);
    if r.fingerprint != fp {
        bail!(
            "The server gave fingerprint {}, but this computer computed {fp}: they differ",
            safe::field(&r.fingerprint)
        );
    }
    Ok(r.key_id)
}

// —— Printing and confirmation ——

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// One trusted key for people: the school key's key code (or the id of another kind of key) and
/// its full fingerprint.
pub fn key_line(k: &TrustKey) -> String {
    let name = match mastersos_bundle::keyid::key_code(&k.id) {
        Some(code) => format!("school key {code}"),
        None => format!("key {}", safe::field(&k.id)),
    };
    // The site is part of what a computer checks, so a change to it must show on the screen.
    let site = match &k.rp_id {
        Some(rp) => format!(" (site {})", safe::field(rp)),
        None => String::new(),
    };
    format!("{name}  fingerprint {}{site}", trust_fingerprint(k))
}

pub(crate) fn print_trust(out: &mut dyn Write, trust: &[TrustKey]) -> Result<()> {
    for k in trust {
        writeln!(out, "    {}", key_line(k))?;
    }
    Ok(())
}

/// What changed between two trusts: keys added, removed and changed (paired by id; a key with
/// the same id and any other field different is changed).
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

    /// Nothing added, removed or changed. Key order does not matter to machines, so a new order
    /// alone is no change.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }

    pub fn print(&self, out: &mut dyn Write) -> Result<()> {
        for k in &self.added {
            writeln!(out, "    + added    {}", key_line(k))?;
        }
        for k in &self.removed {
            writeln!(out, "    - removed  {}", key_line(k))?;
        }
        for (o, n) in &self.modified {
            writeln!(out, "    ~ changed  {}", key_line(o))?;
            writeln!(out, "           ->  {}", key_line(n))?;
        }
        Ok(())
    }
}

/// Print the prompt and read one line (surrounding whitespace removed). End of input (nothing
/// typed) cancels.
pub(crate) fn ask(confirm: &mut dyn BufRead, out: &mut dyn Write, prompt: &str) -> Result<String> {
    write!(out, "{prompt}")?;
    out.flush()?;
    let mut line = String::new();
    if confirm.read_line(&mut line)? == 0 {
        bail!("No input was read; cancelled");
    }
    Ok(line.trim().to_owned())
}

// —— Approving a version ——

#[derive(Deserialize)]
struct PendingFile {
    path: String,
}

/// The server's pending bundle. Only the fields signing needs; `diff` and `lints` are printed for
/// information only.
#[derive(Deserialize)]
struct Pending {
    pending_id: String,
    version: u64,
    digest_hex: String,
    manifest_text: String,
    files: Vec<PendingFile>,
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
    let new_v = format!("v{new_version} (waiting for approval)");
    writeln!(
        out,
        "\n== Differences computed on this computer (version {} -> version {new_version}) ==",
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
                writeln!(out, "manifest.toml: no changes")?;
            } else {
                writeln!(out, "manifest.toml:")?;
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
            writeln!(out, "manifest.toml: no changes")?;
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
                "  + added file {p} ({} bytes, sha256 {}...)",
                b.len(),
                short(b)
            )?,
            Some(o) if o != b => writeln!(
                out,
                "  ~ changed file {p} ({} -> {} bytes, sha256 {}... -> {}...)",
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
                "  - removed file {} ({} bytes)",
                safe::field(path),
                b.len()
            )?;
            any = true;
        }
    }
    if !any {
        writeln!(out, "Files: no changes")?;
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
        "\n== The server's notes (for information only; go by the differences computed on this computer above) =="
    )?;
    // The server's `manifest_diff` is not printed: it holds the real secret values, and a
    // multi-line or escaped one cannot be hidden reliably in its text. The local diff above
    // shows the same change with secrets reported by name only.
    let hide = |s: &str| secrets.as_deref().map(|v| hide_values(s, v));
    match p.lints.as_array() {
        Some(ls) if !ls.is_empty() => {
            for l in ls {
                writeln!(
                    out,
                    "  [{}] {}: {}",
                    safe::field(l["level"].as_str().unwrap_or("?")),
                    safe::field(l["code"].as_str().unwrap_or("?")),
                    safe::field(
                        &hide(l["message"].as_str().unwrap_or(""))
                            .unwrap_or_else(|| "(message hidden)".into())
                    )
                )?;
            }
        }
        _ => writeln!(out, "  (no warnings)")?,
    }
    Ok(())
}

/// Fetch the pending bundle (`pending` is the id the upload got), verify the chain here, compute
/// the differences, print the whole trust, and after the human types the version number (and `yes`
/// when the trust or disk unlocking changes) sign it with the school key, submit it, and move the
/// pin to the new version. Returns the new version. When `expect_digest` is given (lower- or
/// upper-case hex), the pending bundle's content digest computed here from the downloaded content must equal it: the caller
/// uploaded that content and computed its digest itself, so a server that swapped the pending
/// bundle is refused before anything is shown or signed.
pub async fn sign_pending_expecting(
    api: &Api,
    kit: &Kit,
    pin_dir: &Path,
    pending: &str,
    expect_digest: Option<&str>,
    confirm: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<u64> {
    let mut out = safe::SafeWriter::new(out);
    let out: &mut dyn Write = &mut out;
    let (signer, me) = load_signer(api, kit, false).await?;
    let p: Pending = api
        .get_json(
            &["v1", "admin", "publish", "pending", pending],
            "fetch the upload",
        )
        .await?;

    // 1. Download every file and compute the digest here.
    let mut files = BTreeMap::new();
    for f in &p.files {
        check_member_path(&f.path)
            .with_context(|| format!("The upload has an unsafe path: {}", safe::field(&f.path)))?;
        let mut segs = vec!["v1", "admin", "publish", "pending", &p.pending_id, "files"];
        segs.extend(f.path.split('/'));
        let bytes = api
            .get_bytes(
                &segs,
                &format!("download upload file {}", safe::field(&f.path)),
            )
            .await?;
        if files.insert(f.path.clone(), bytes).is_some() {
            bail!("The upload lists {} twice", safe::field(&f.path));
        }
    }
    let contents = Contents {
        manifest_text: p.manifest_text.clone(),
        files,
    };
    let digest = hex(&content_digest(&contents));
    if !digest.eq_ignore_ascii_case(p.digest_hex.trim()) {
        bail!(
            "Content fingerprint mismatch: the downloaded content gives {digest} here, the server says {}. What the server gave is not what it will submit; not signing",
            p.digest_hex
        );
    }
    if let Some(want) = expect_digest {
        if !digest.eq_ignore_ascii_case(want.trim()) {
            bail!(
                "The upload's content fingerprint is {digest}, but the content uploaded from this computer has {}: the server holds other content under this upload id; not signing",
                want.trim()
            );
        }
    }
    let manifest = Manifest::parse(&contents.manifest_text)?;
    let present: BTreeSet<String> = contents.files.keys().cloned().collect();
    manifest
        .validate(&present)
        .context("Computers would reject this upload (the manifest check fails); not signing")?;

    // 2. Verify the chain here, version by version. Nothing published yet: there is no chain. The first version (R1g) is
    //    verified with its own trust, and that whole trust counts as added, so the human checks
    //    every key's fingerprint and types `trust` before it is signed.
    let genesis = api.latest_version().await? == 0;
    let pin_file = chain::pin_path(pin_dir, api.into())?;
    if genesis {
        // A server that says nothing is published while a version was verified here is lying or
        // was replaced: signing a "first version" would hand it a recovery-key signature over a
        // trust it chose, and reset the local anchor to its chain.
        if let Some(pin) = chain::load_pin(&pin_file)? {
            bail!(
                "the server reports nothing published, but version {} was checked on this computer \
                 before ({}): the server may have been rolled back, or this is the wrong server; \
                 nothing was approved. Delete that file only if you are sure the server was reset on purpose",
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
        let v = chain::verify_chain(api.into(), pin_dir, &chain::Anchors::key(&me), confirm, out)
            .await?;
        let t = v.trust.clone();
        (v, t)
    };

    // 3. The versions follow on, and this key is in the verified trust. `verified.version` is the version machines
    //    accept (the base for every check below); `verified.latest` the newest on the chain.
    let next = verified.latest + 1;
    if manifest.version != next || p.version != next {
        bail!(
            "The upload is version {} (the server labels it version {}), but the latest version verified here is {}: it should be version {next}; not signing",
            manifest.version,
            p.version,
            verified.latest
        );
    }
    if !verified.trust.contains(&me) {
        bail!(
            "This key ({}) is not among the trusted keys of version {} verified here: computers would not accept its signature",
            key_line(&me),
            verified.version
        );
    }
    if !manifest.trust.contains(&me) {
        bail!(
            "The new trusted keys do not include this key ({}): a key cannot approve its own removal; approve that with another school key that stays",
            key_line(&me)
        );
    }

    // 4. The differences computed here.
    let secret_values = print_local_diff(out, &verified, next, &contents)?;

    // 5. The whole trust and what changed in it.
    writeln!(
        out,
        "\n== All trusted keys of version {next} ({} in total; from this version on, computers accept only these keys) ==",
        manifest.trust.len()
    )?;
    print_trust(out, &manifest.trust)?;
    let delta = TrustDelta::between(&base_trust, &manifest.trust);
    if genesis {
        writeln!(
            out,
            "This is the first version: computers will accept settings approved only by these keys. Check each key code \
             and fingerprint against the paper copy of your school key, not against this server's pages."
        )?;
    } else if delta.is_empty() {
        writeln!(
            out,
            "The trusted keys are the same as in version {}.",
            verified.version
        )?;
    } else {
        writeln!(
            out,
            "The trusted keys change (compared with version {} verified here):",
            verified.version
        )?;
        delta.print(out)?;
        writeln!(
            out,
            "Compare each fingerprint with the School keys page: an unknown extra key hands every computer to whoever holds it."
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
            "Disk unlocking changes (against version {} that computers run; computers will keep \
             their disk recovery codes for these school keys):",
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
            "Each added line must come from one of your school keys: an unknown one could unlock \
             the computers' disks."
        )?;
    }

    print_server_notes(out, &p, &secret_values)?;

    // 6. The human confirms. The caller that passed `expect_digest` printed the check code already.
    if expect_digest.is_none() {
        writeln!(out, "\nContent fingerprint computed here: {digest}")?;
        writeln!(out, "Check code: {}", &digest[..8])?;
    }
    let typed = ask(
        confirm,
        out,
        &format!("Type the version number {next} to approve it: "),
    )?;
    if typed != next.to_string() {
        bail!("The version number you typed ({typed}) does not match version {next}; cancelled, nothing was approved");
    }
    if !delta.is_empty() || recipients_change {
        let typed = ask(
            confirm,
            out,
            "This version changes which school keys computers accept and who can unlock their disks (see the changes above). If that is right, type yes: ",
        )?;
        // `trust` was the word asked for before; old scripts still send it.
        if typed != "yes" && typed != "trust" {
            bail!("The change of trusted keys or disk unlocking was not confirmed; cancelled, nothing was approved");
        }
    }

    // 7. Sign (the message computed from the content here), accept it here as a machine would,
    //    submit it, move the pin forward.
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
    .context(
        "The signed package fails the local self-check: computers would reject it; not submitting",
    )?;
    #[derive(Deserialize)]
    struct Committed {
        version: u64,
    }
    let body = json!({ "confirm_digest": digest, "signature": signature });
    let c: Committed = api
        .post_json(
            &["v1", "admin", "publish", "pending", &p.pending_id, "commit"],
            Some(&body),
            "submit the signature",
        )
        .await?;
    if c.version != next {
        bail!(
            "The server says version {} was published, but version {next} was approved here: run `mastersos verify` to check the server again",
            c.version
        );
    }
    // The pin on disk is the one this run verified from (none for the first version).
    let prev = (!genesis)
        .then(|| chain::pin_of(api.into(), &verified))
        .transpose()?;
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
    Ok(next)
}

// —— The monthly check-in ——

/// Unix seconds as local time and UTC; just the seconds when out of range.
fn both_zones(secs: i64) -> String {
    match chrono::DateTime::from_timestamp(secs, 0) {
        Some(t) => format!(
            "{} (local) / {}",
            t.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S %:z"),
            t.format("%Y-%m-%d %H:%M:%S UTC")
        ),
        None => format!("Unix {secs}"),
    }
}

/// Sign the monthly check-in with the school key (Ruling 11, C3): [`sign_heartbeat_at`] at this
/// computer's current time.
pub async fn sign_heartbeat(
    api: &Api,
    kit: &Kit,
    pin_dir: &Path,
    days: i64,
    confirm: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<()> {
    sign_heartbeat_at(api, kit, pin_dir, days, chrono::Utc::now(), confirm, out).await
}

/// Sign the monthly check-in with `issued_at = now`:
///
/// 1. `days` outside 1..=31 is an error.
/// 2. Verify the chain here ([`chain::verify_chain`]); the signing key must be in the latest
///    verified trust.
/// 3. **Build** the statement here: version and digest from the latest version verified here
///    (digest computed here), `issued_at = now`, `not_after = now + days days`. The server's
///    `heartbeat/prepare` is not used.
/// 4. Print the version, the digest, `issued_at` and `not_after` (local time and UTC), sign after
///    the version number is typed, check it here as a machine would, then submit
///    `heartbeat/commit`.
pub async fn sign_heartbeat_at(
    api: &Api,
    kit: &Kit,
    pin_dir: &Path,
    days: i64,
    now: chrono::DateTime<chrono::Utc>,
    confirm: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<()> {
    if !(1..=MAX_HEARTBEAT_DAYS).contains(&days) {
        bail!("--days must be between 1 and {MAX_HEARTBEAT_DAYS} (a monthly check-in lasts at most {MAX_HEARTBEAT_DAYS} days)");
    }
    let mut out = safe::SafeWriter::new(out);
    let out: &mut dyn Write = &mut out;
    let (signer, me) = load_signer(api, kit, false).await?;
    let verified =
        chain::verify_chain(api.into(), pin_dir, &chain::Anchors::key(&me), confirm, out).await?;
    if !verified.trust.contains(&me) {
        bail!(
            "This key ({}) is not among the trusted keys of version {} verified here: computers would not accept its check-in",
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

    writeln!(
        out,
        "\n== Monthly check-in (computed on this computer from the verified version) =="
    )?;
    writeln!(
        out,
        "Version:     {} (the latest verified here)",
        statement.version
    )?;
    writeln!(out, "Content fingerprint: {}", statement.digest_hex)?;
    writeln!(out, "Check code: {}", &statement.digest_hex[..8])?;
    writeln!(out, "issued_at:   {}", both_zones(statement.issued_at))?;
    writeln!(
        out,
        "not_after:  {} ({days} days)",
        both_zones(statement.not_after)
    )?;
    writeln!(
        out,
        "Until it expires, computers treat version {} as the latest settings; if the server holds back a newer version meanwhile, computers cannot tell.",
        statement.version
    )?;
    let typed = ask(
        confirm,
        out,
        &format!("Type the version number {} to sign: ", statement.version),
    )?;
    if typed != statement.version.to_string() {
        bail!(
            "The version number you typed ({typed}) does not match version {}; cancelled, nothing was signed",
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
    verify_heartbeat(&text, &verified.trust).context(
        "The signed check-in fails the local self-check: computers would reject it; not submitting",
    )?;
    api.post_no_content(
        &["v1", "admin", "heartbeat", "commit"],
        &json!({ "statement": statement, "signature": signature }),
        "submit the check-in",
    )
    .await?;
    writeln!(
        out,
        "Monthly check-in signed for version {}, valid until {}.",
        statement.version,
        both_zones(statement.not_after)
    )?;
    Ok(())
}

/// The monthly check-in for the version `mastersos publish` has just approved, signed without a
/// prompt: `version` and `digest` are what the caller verified, signed and saw committed, and
/// `trust` is that version's trusted keys (what computers verify the check-in with). Nothing is
/// fetched to decide what to sign. The statement lasts `days` days from now; it is checked here the
/// way a computer checks it, then sent to `heartbeat/commit` (the server's `heartbeat/prepare` is
/// not used, as in [`sign_heartbeat_at`]). Prints nothing; returns the end of the check-in.
pub async fn checkin_after_publish(
    api: &Api,
    kit: &Kit,
    version: u64,
    digest: &[u8; 32],
    trust: &[TrustKey],
    days: i64,
) -> Result<chrono::DateTime<chrono::Utc>> {
    checkin_after_publish_at(api, kit, version, digest, trust, days, chrono::Utc::now()).await
}

/// [`checkin_after_publish`] with `issued_at = now`.
pub async fn checkin_after_publish_at(
    api: &Api,
    kit: &Kit,
    version: u64,
    digest: &[u8; 32],
    trust: &[TrustKey],
    days: i64,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<chrono::DateTime<chrono::Utc>> {
    if !(1..=MAX_HEARTBEAT_DAYS).contains(&days) {
        bail!("a monthly check-in lasts 1 to {MAX_HEARTBEAT_DAYS} days, not {days}");
    }
    // The caller checked the key against the server when it published; no second round trip.
    let (signer, me) = load_signer(api, kit, true).await?;
    if !trust.contains(&me) {
        bail!(
            "This key ({}) is not among the trusted keys of version {version}",
            key_line(&me)
        );
    }
    let issued_at = now.timestamp();
    let statement = HeartbeatStatement {
        version,
        digest_hex: hex(digest),
        issued_at,
        not_after: issued_at + days * 86_400,
    };
    statement.check()?;
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
    let checked = verify_heartbeat(&text, trust).context(
        "The signed check-in fails the local self-check: computers would reject it; not submitting",
    )?;
    if checked != statement {
        bail!("The check-in read back differs from the one signed; not submitting");
    }
    api.post_no_content(
        &["v1", "admin", "heartbeat", "commit"],
        &json!({ "statement": statement, "signature": signature }),
        "submit the monthly check-in",
    )
    .await?;
    chrono::DateTime::from_timestamp(statement.not_after, 0)
        .context("the check-in's end is out of range")
}

// —— Install file check ——

/// The fingerprint comments at the top of an install file: `# <id>  <alg>  <xxxx-xxxx-xxxx-xxxx>`.
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

/// Verify the chain here, then check the install file: `trust` must equal the latest verified
/// trust, `min_version` the latest version, and the fingerprint comments at the top must match the
/// trust one for one. Any difference is listed and is an error. A pin is needed first (`verify`).
pub async fn seed_check(
    api: &Api,
    pin_dir: &Path,
    seed_text: &str,
    out: &mut dyn Write,
) -> Result<()> {
    let mut out = safe::SafeWriter::new(out);
    let out: &mut dyn Write = &mut out;
    if !chain::pin_path(pin_dir, api.into())?.exists() {
        bail!(
            "There is no pin for {} yet: run mastersos verify first and compare the fingerprints with the School keys page",
            api.host()
        );
    }
    let verified = chain::verify_chain(
        api.into(),
        pin_dir,
        &chain::Anchors::default(),
        &mut std::io::empty(),
        out,
    )
    .await?;
    let seed = Seed::parse(seed_text).context("The install file is not valid TOML")?;
    let mut problems: Vec<String> = Vec::new();
    // The strict checks parsing leaves out (Wi-Fi, server_url); the message never carries a secret.
    if let Err(e) = seed.validate() {
        problems.push(format!(
            "the seed does not pass the checks: {}",
            safe::field(&e.to_string())
        ));
    }

    let delta = TrustDelta::between(&verified.trust, &seed.trust);
    if !delta.is_empty() {
        let mut buf = Vec::new();
        delta.print(&mut buf)?;
        problems.push(format!(
            "The trusted keys in the install file differ from version {} verified here (+ is extra in the install file, - is missing from it):\n{}",
            verified.version,
            String::from_utf8_lossy(&buf).trim_end()
        ));
    }
    if seed.min_version != Some(verified.version) {
        problems.push(format!(
            "The install file's min_version is {}, it should be the latest version {}",
            seed.min_version
                .map_or("(none)".to_owned(), |v| v.to_string()),
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
        let mut s = String::from("The fingerprints in the comment at the top of the install file do not match its trusted keys:\n    comment:");
        for (id, fp) in &header {
            s.push_str(&format!("\n      {}  {}", safe::field(id), safe::field(fp)));
        }
        s.push_str("\n    computed from the keys:");
        for (id, fp) in &expected {
            s.push_str(&format!("\n      {}  {}", safe::field(id), safe::field(fp)));
        }
        problems.push(s);
    }

    if problems.is_empty() {
        writeln!(
            out,
            "The install file matches version {} verified here: {} trusted keys, min_version = {}.",
            verified.version,
            seed.trust.len(),
            verified.version
        )?;
        print_trust(out, &seed.trust)?;
        return Ok(());
    }
    writeln!(
        out,
        "The install file does not match what was verified here:"
    )?;
    for p in &problems {
        writeln!(out, "  * {p}")?;
    }
    bail!("The install file does not match the verified trusted keys / version: do not use it to install computers")
}

#[cfg(test)]
mod tests {
    #[test]
    fn key_line_shows_the_site_of_a_key() {
        let mk = |rp: Option<&str>| TrustKey {
            id: "pk-1".into(),
            alg: mastersos_bundle::KeyAlg::WebauthnEs256,
            public_key: "AAAA".into(),
            rp_id: rp.map(str::to_owned),
        };
        let (a, b, none) = (
            key_line(&mk(Some("one.example"))),
            key_line(&mk(Some("two.example"))),
            key_line(&mk(None)),
        );
        assert_ne!(a, b);
        assert_ne!(a, none);
        assert!(a.ends_with(" (site one.example)"), "{a}");
        assert!(!none.contains("site"), "{none}");
        assert!(!a.to_lowercase().contains("passkey"), "{a}");
    }

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
    fn pin_name_for_matches_the_api() {
        for server in [
            "https://School.Example/",
            "https://school.example:8443/x",
            "http://127.0.0.1:9000",
        ] {
            let api = Api::new(server, "tok".into()).unwrap();
            assert_eq!(pin_name_for(server).unwrap(), api.pin_name(), "{server}");
        }
        assert!(pin_name_for("not a url").is_err());
    }

    #[test]
    fn api_paths_are_joined_under_a_server_url_with_a_path() {
        for server in [
            "https://cloud.example/org/example/devices",
            "https://cloud.example/org/example/devices/",
        ] {
            let api = Api::new(server, "tok".into()).unwrap();
            assert_eq!(
                api.url(&["v1", "keys"]).as_str(),
                "https://cloud.example/org/example/devices/v1/keys",
                "{server}"
            );
        }
    }

    #[test]
    fn a_host_only_pin_stays_the_pin_of_the_host_only_server() {
        use super::chain::{load_pin, pin_path, recorded_digest, Pin};
        const SCHOOL: &str = "0192f3a4-5b6c-7d8e-9f00-112233445566";
        let dir = tempfile::tempdir().unwrap();
        // A pin as written before paths were part of the key: file `<host>.toml`, `host = "<host>"`.
        let old = "host = \"cloud.example\"\nversion = 3\ndigest_hex = \"d3\"\ntrust = []\n";
        let old_file = dir.path().join("cloud.example.toml");
        std::fs::write(&old_file, old).unwrap();

        // The host-only address still finds it, and its recorded key is what the check compares.
        let host_only = Api::new("https://cloud.example", "t".into()).unwrap();
        assert_eq!(pin_path(dir.path(), (&host_only).into()).unwrap(), old_file);
        let pin: Pin = load_pin(&old_file).unwrap().unwrap();
        assert_eq!(pin.host, host_only.host());
        assert_eq!(
            recorded_digest(dir.path(), "https://cloud.example/", SCHOOL, 3).unwrap(),
            Some("d3".to_owned())
        );

        // An organisation under a path on the same host does not pick it up: its own file does not
        // exist yet (first use), its key differs, and the old file is left as it was.
        let org = Api::new("https://cloud.example/org/a/devices", "t".into()).unwrap();
        assert_ne!(pin_path(dir.path(), (&org).into()).unwrap(), old_file);
        assert!(load_pin(&pin_path(dir.path(), (&org).into()).unwrap())
            .unwrap()
            .is_none());
        assert_ne!(pin.host, org.host());
        assert_eq!(
            recorded_digest(dir.path(), "https://cloud.example/org/a/devices", SCHOOL, 3).unwrap(),
            None
        );
        assert_eq!(std::fs::read_to_string(&old_file).unwrap(), old);
    }

    #[test]
    fn pins_are_keyed_by_host_and_path() {
        let a = Api::new("https://cloud.example/org/a/devices", "t".into()).unwrap();
        let a2 = Api::new("https://Cloud.example/org/a/devices/", "t".into()).unwrap();
        let b = Api::new("https://cloud.example/org/b/devices", "t".into()).unwrap();
        let bare = Api::new("https://cloud.example/", "t".into()).unwrap();
        let port = Api::new("https://cloud.example:8443", "t".into()).unwrap();
        let port_path = Api::new("https://cloud.example/8443", "t".into()).unwrap();
        // Same server, spelled differently: one pin. Two organisations on one host: two pins.
        assert_eq!(a.pin_name(), a2.pin_name());
        assert_eq!(a.host(), a2.host());
        assert_ne!(a.pin_name(), b.pin_name());
        assert_ne!(a.host(), b.host());
        assert_eq!(a.host(), "cloud.example/org/a/devices");
        assert_eq!(a.pin_name(), "cloud.example+org+a+devices");
        // A server without a path keeps the name pins had before, and a path is never read as a port.
        assert_eq!(bare.pin_name(), "cloud.example");
        assert_eq!(bare.host(), "cloud.example");
        assert_eq!(port.pin_name(), "cloud.example_8443");
        assert_ne!(port.pin_name(), port_path.pin_name());
        // The name is one safe file name whatever the path holds.
        let odd = Api::new("https://cloud.example/o%2Fx/..%5C/a b", "t".into()).unwrap();
        assert!(odd
            .pin_name()
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-+%".contains(c)));
        assert_eq!(
            pin_name_for("https://cloud.example/org/a/devices").unwrap(),
            a.pin_name()
        );
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
        // The server's answer carries its manifest diff, with real values (an escaped one and a
        // multi-line PEM among them): it is never printed.
        let p: Pending = serde_json::from_value(json!({
            "pending_id": "p",
            "version": 2,
            "digest_hex": "",
            "manifest_text": "",
            "files": [],
            "diff": { "manifest_diff": "-psk = \"oldpass-111\"\n+psk = \"newpass-222\"\n+psk = \"esc\\\"aped-555\"\n+client_key = \"\"\"\n+MIIEvQIBADANBgkqhkiG9w0BAQEF\n+\"\"\"\n" },
            "lints": [{ "level": "warning", "code": "x", "message": "psk newpass-222 is weak" }],
        }))
        .unwrap();
        let mut out = Vec::new();
        print_server_notes(&mut out, &p, &values).unwrap();
        let notes = String::from_utf8(out).unwrap();
        assert!(
            !notes.contains("oldpass-111") && !notes.contains("newpass-222"),
            "{notes}"
        );
        for v in ["aped-555", "MIIEvQIBADANBgkqhkiG9w0BAQEF", "psk ="] {
            assert!(
                !notes.contains(v),
                "the server's diff is not printed: {notes}"
            );
        }

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
