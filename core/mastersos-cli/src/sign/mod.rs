//! Signing with the school key on this computer: the bundle signature and the monthly check-in
//! (built here, never from the server's words), the local diff shown before a publish, and the
//! install file check (Ruling 1, 2, 15).
//!
//! It is the trust anchor for trust changes, so it **does not trust the server**:
//! - The chain is verified here one version at a time, as the agent does ([`chain`]);
//!   differences, digests and trust additions and removals are computed here from verified
//!   content.
//! - Only bytes built or verified here are signed: the bundle signature's message is computed from
//!   the content ([`sign_bundle`]); a message the server sends is never signed.
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
use mastersos_bundle::{
    heartbeat_message, signed_message, trust_fingerprint, verify_heartbeat, Contents, Heartbeat,
    HeartbeatStatement, KeyAlg, Seed, SignatureFile, Signer, TrustKey, MAX_HEARTBEAT_DAYS,
};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;

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

    async fn get_bytes(&self, segments: &[&str], what: &str) -> Result<Vec<u8>> {
        let res = self.send(self.client.get(self.url(segments)), what).await?;
        Ok(res
            .bytes()
            .await
            .with_context(|| format!("{what}: could not read the response"))?
            .to_vec())
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

// —— Publishing ——

/// The secret values of both sides, longest first; `None` when a side's secrets could not be
/// separated.
type SecretValues = Option<Vec<String>>;

/// The local diff. Secret values are never printed: both manifests are split into references
/// first ([`mastersos_bundle::secret_ref::split`]), the split texts are diffed, and each secret
/// whose value differs gets one line with its name only.
pub(crate) fn print_local_diff(
    out: &mut dyn Write,
    old: &Verified,
    new_version: u64,
    new: &Contents,
) -> Result<SecretValues> {
    use mastersos_bundle::secret_ref::split;
    let old_v = format!("v{}", old.version);
    let new_v = format!("v{new_version} (to publish)");
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

// —— Signing here, without the server ——

/// The bundle signature over `contents`, made here: the message is computed from the content on
/// this computer (`b"mastersos-bundle-v1\n" || content_digest`), never taken from the server.
pub fn sign_bundle(signer: &dyn Signer, contents: &Contents) -> SignatureFile {
    SignatureFile {
        key_id: signer.key_id().to_owned(),
        alg: KeyAlg::Ed25519,
        sig: STANDARD.encode(signer.sign(&signed_message(contents))),
        authenticator_data: None,
        client_data_json: None,
    }
}

/// The monthly check-in for `version` with content digest `digest_hex` (from what was verified or
/// signed here), issued at `issued_at` (Unix seconds) and lasting `days` days, signed here and read
/// back the way a Device reads it with `trust`. Returns the TOML text `POST heartbeat` carries and
/// the statement. Nothing is fetched to decide what is signed.
pub fn sign_heartbeat(
    signer: &dyn Signer,
    version: u64,
    digest_hex: &str,
    issued_at: i64,
    days: i64,
    trust: &[TrustKey],
) -> Result<(String, HeartbeatStatement)> {
    if !(1..=MAX_HEARTBEAT_DAYS).contains(&days) {
        bail!("a monthly check-in lasts 1 to {MAX_HEARTBEAT_DAYS} days, not {days}");
    }
    let not_after = days
        .checked_mul(86_400)
        .and_then(|s| issued_at.checked_add(s))
        .context("the check-in's end is out of range")?;
    let statement = HeartbeatStatement {
        version,
        digest_hex: digest_hex.to_owned(),
        issued_at,
        not_after,
    };
    statement.check()?;
    let signature = SignatureFile {
        key_id: signer.key_id().to_owned(),
        alg: KeyAlg::Ed25519,
        sig: STANDARD.encode(signer.sign(&heartbeat_message(&statement))),
        authenticator_data: None,
        client_data_json: None,
    };
    let text = Heartbeat {
        statement: statement.clone(),
        signature,
    }
    .to_toml();
    let checked = verify_heartbeat(&text, trust).context(
        "The signed check-in fails the local self-check: computers would reject it; not submitting",
    )?;
    if checked != statement {
        bail!("The check-in read back differs from the one signed; not submitting");
    }
    Ok((text, statement))
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
        // Offline, only a protocol v1 pin (origin and school) records a digest: the old host-only
        // pin is not read (the chain loader alone migrates it, by verifying forward from it).
        assert_eq!(
            recorded_digest(dir.path(), "https://cloud.example", SCHOOL, 3).unwrap(),
            None
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
        assert!(values.is_some());
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
