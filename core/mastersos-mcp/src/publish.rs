//! `mastersos publish`: the local directory is checked, its secrets are filled back in, version
//! and time are stamped, and the result is uploaded as a pending bundle. With a recovery key the
//! bundle is then verified and signed on this computer ([`mastersos_sign::sign_pending_expecting`]);
//! without one, the signing page link is returned for IT to open and sign with a Passkey (or, for
//! the first version, the recovery kit). Either way the content digest is computed here from what
//! was uploaded and must equal the server's, and only that digest is signed.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, SecondsFormat, Utc};
use mastersos_bundle::secret_ref;
use mastersos_bundle::stamp::{school_name_to_write, stamp};
use mastersos_bundle::{content_digest, has_errors, Contents, Lint, LintLevel};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::tools::Req;
use crate::workdir::{self, UploadInfo, Workdir};
use crate::{api_error, Api};

/// What signing needs on this computer.
pub struct SignOpts<'a> {
    /// The recovery key file.
    pub key: &'a Path,
    /// The token file (the signing client talks to the same server with it).
    pub token_file: &'a Path,
    /// Where the pins (the keys this computer verified) are kept.
    pub pin_dir: &'a Path,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PublishOutcome {
    /// Signed here and accepted: this is the new version, and the directory's base now is it.
    Published(u64),
    /// Uploaded, not signed: IT opens `url` and signs with a Passkey (the first version: with the
    /// recovery kit), then runs `mastersos pull`.
    NeedsPasskey {
        url: String,
        pending_id: String,
        /// The version uploaded (1: the first, which only the recovery kit may sign).
        version: u64,
        /// The content digest computed here from what was uploaded (lower-case hex); the signing
        /// page shows its first 8 characters.
        digest_hex: String,
    },
}

/// How many characters of the digest are printed: as many as the signing page shows.
pub const DIGEST_SHOWN: usize = 8;

/// The lines printed after a pending bundle is uploaded but not signed here.
pub fn needs_signing_text(url: &str, pending_id: &str, version: u64, digest_hex: &str) -> String {
    let short = &digest_hex[..digest_hex.len().min(DIGEST_SHOWN)];
    let how = if version == 1 {
        format!("Uploaded pending bundle {pending_id} (version 1, the first). Nothing is published yet: sign it with your recovery kit on this page:\n{url}")
    } else {
        format!("Uploaded pending bundle {pending_id} (version {version}). Nothing is published yet: IT signs it with a Passkey at\n{url}")
    };
    format!(
        "{how}\nDigest, first {DIGEST_SHOWN} characters: {short}\nCheck that the signing page shows the same digest before you sign; if it differs, do not sign.\nAfter signing in the browser, run `mastersos pull` to update your base."
    )
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
        let names = self.names.join(", ");
        let flags: Vec<String> = self
            .names
            .iter()
            .map(|n| format!("--allow-reroute {n}"))
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
    slug: String,
    school_id: String,
    signing_origin: String,
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

/// The domain of the school's host `<slug>.<domain>` (what the admin page's `domainOfHost` gives):
/// the signing page needs it when the cloud serves several domains. `None` for another host (a
/// local server).
fn domain_of(server: &str, slug: &str) -> Option<String> {
    let url = reqwest::Url::parse(server).ok()?;
    let host = url.host_str()?;
    let rest = host.strip_prefix(slug)?.strip_prefix('.')?;
    (!rest.is_empty()).then(|| rest.to_ascii_lowercase())
}

/// The signing page link for a pending bundle; `server` is the school's address.
fn sign_link(c: &AuthConfig, server: &str, pending_id: &str) -> String {
    let domain = domain_of(server, &c.slug)
        .map(|d| format!("&domain={d}"))
        .unwrap_or_default();
    format!(
        "{}/#school={}&sid={}&op=commit{domain}&pending={}",
        c.signing_origin.trim_end_matches('/'),
        c.slug,
        c.school_id,
        pending_id
    )
}

/// `allow_reroute` holds the secret names IT approved with `--allow-reroute`: every secret a
/// `secret_rerouted` warning names must be among them, or nothing is uploaded.
pub async fn publish(
    api: &Api,
    w: &Workdir,
    sign: Option<SignOpts<'_>>,
    allow_reroute: &[String],
    now: DateTime<Utc>,
    confirm: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<PublishOutcome> {
    let meta = w.meta()?;
    // The first version (no base) is uploaded like any other: without `--key` the signing page
    // offers only the recovery kit for it, and the server's commit enforces R1g.
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
        writeln!(
            out,
            "Note: --allow-reroute {} approves nothing: no secret of that name is rerouted",
            clean(a, &snap.secrets)
        )?;
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
    let stamped = stamp(
        &filled,
        version,
        &issued_at,
        school_name_to_write(&filled, &cfg.name),
    )?;
    // The digest is computed here over exactly what is uploaded: the server's must equal it, and
    // only this digest is signed (here) or shown to compare (on the signing page).
    let local_digest = hex(&content_digest(&Contents {
        manifest_text: stamped.clone(),
        files: files.clone(),
    }));
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
            "the server reports digest {} for the upload, but its content has digest {local_digest} as computed here: the server does not hold what was uploaded. Nothing was signed; do not sign pending bundle {} on the signing page",
            prepared.digest_hex.trim(),
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
    match sign {
        Some(s) => {
            let sign_api = mastersos_sign::Api::from_token_file(&meta.server, s.token_file)?;
            let v = mastersos_sign::sign_pending_expecting(
                &sign_api,
                s.key,
                s.pin_dir,
                &prepared.pending_id,
                Some(&local_digest),
                confirm,
                out,
            )
            .await?;
            w.mark_published(v)?;
            Ok(PublishOutcome::Published(v))
        }
        None => Ok(PublishOutcome::NeedsPasskey {
            url: sign_link(&cfg, &meta.server, &prepared.pending_id),
            pending_id: prepared.pending_id,
            version,
            digest_hex: local_digest,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workdir::Meta;
    use mastersos_bundle::Contents;
    use std::collections::BTreeMap;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    const SID: &str = "11111111-1111-1111-1111-111111111111";

    fn manifest_text() -> String {
        let key = STANDARD.encode([7u8; 32]);
        format!(
            "format = 2\n[school]\nid = \"{SID}\"\n\n[[trust]]\nid = \"rk\"\nalg = \"ed25519\"\npublic_key = \"{key}\"\n\n[defaults]\nwifi = [{{ ssid = \"Guest\", psk = \"guestpass1\" }}]\n\n[[config]]\nid = \"default\"\nname = \"Default\"\ninterface = \"learning\"\nlogin_methods = [\"local\"]\n\n[[group]]\nid = \"default\"\nname = \"Ungrouped\"\nconfig = \"default\"\n"
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
        let w = Workdir::write_pulled(dir, meta, &c, false).unwrap();
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
                "name": "Demo School", "slug": "demo", "school_id": SID,
                "signing_origin": "https://sign.example"
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
        let r = publish(
            &api,
            w,
            None,
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
            text.contains(&format!("mastersos publish --allow-reroute {GUEST}")),
            "{text}"
        );
        // Nothing touched the server, and nothing was recorded as uploaded.
        assert!(s.received_requests().await.unwrap().is_empty());
        assert!(Workdir::uploaded_unchanged(&w.root).unwrap().is_none());
        assert_eq!(w.meta().unwrap().base_version, 4);
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
        assert!(matches!(r.unwrap(), PublishOutcome::NeedsPasskey { .. }));
        assert_eq!(uploads(&s).await.len(), 1);
        // Every local warning is printed, before the server's answer.
        let local = out.find("The local check:").expect(&out);
        let rerouted = out.find("secret_rerouted").expect(&out);
        let server = out.find("The server's check:").expect(&out);
        assert!(local < rerouted && rerouted < server, "{out}");
        assert!(
            out.contains("--allow-reroute unused-name approves nothing"),
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
        run(&s, &w).await.unwrap();
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
    async fn publish_without_key_returns_sign_link() {
        let s = server().await;
        Mock::given(method("POST"))
            .and(path("/v1/admin/publish/pending"))
            .respond_with(accepted(5))
            .mount(&s)
            .await;
        let t = tempfile::tempdir().unwrap();
        let w = workdir(&t.path().join("school"));
        let got = run(&s, &w).await.unwrap();
        let digest = digest_of(&uploads(&s).await[0]);
        assert_eq!(
            got,
            PublishOutcome::NeedsPasskey {
                url: format!("https://sign.example/#school=demo&sid={SID}&op=commit&pending=p-1"),
                pending_id: "p-1".into(),
                version: 5,
                digest_hex: digest.clone(),
            }
        );
        // Not signed here: the base stays until IT signs and pulls; the upload is recorded (with
        // the digest computed here) so that pull accepts the directory as clean once it is
        // published.
        assert_eq!(w.meta().unwrap().base_version, 4);
        assert!(Workdir::is_published_upload(&w.root, 5, &digest).unwrap());
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

    #[tokio::test]
    async fn first_version_without_key_uploads_for_the_kit() {
        // C1: a new school has only recovery kits (no key file): the first version is uploaded
        // and the link says to sign it with the kit on the signing page.
        let s = server().await;
        Mock::given(method("POST"))
            .and(path("/v1/admin/publish/pending"))
            .respond_with(accepted(1))
            .mount(&s)
            .await;
        let t = tempfile::tempdir().unwrap();
        let meta = Meta {
            server: "https://school.example".into(),
            school_id: SID.into(),
            base_version: 0,
        };
        let w = Workdir::init(&t.path().join("school"), meta, &manifest_text()).unwrap();
        let got = run(&s, &w).await.unwrap();
        let up = uploads(&s).await;
        assert!(up[0]["manifest_text"]
            .as_str()
            .unwrap()
            .contains("version = 1"));
        let PublishOutcome::NeedsPasskey {
            url,
            pending_id,
            version,
            digest_hex,
        } = got
        else {
            panic!("not uploaded for signing: {got:?}");
        };
        assert_eq!(version, 1);
        assert_eq!(digest_hex, digest_of(&up[0]));
        let text = needs_signing_text(&url, &pending_id, version, &digest_hex);
        assert!(
            text.contains("sign it with your recovery kit on this page"),
            "{text}"
        );
        assert!(text.contains(&url), "{text}");
        assert!(text.contains(&digest_hex[..8]), "{text}");
        assert!(!text.contains(&digest_hex), "only 8 characters: {text}");
        assert_eq!(w.meta().unwrap().base_version, 0);
    }

    #[test]
    fn later_versions_name_the_passkey_and_the_digest() {
        let text = needs_signing_text("https://sign.example/#x", "p-1", 5, "0123456789abcdef");
        assert!(
            text.contains("signs it with a Passkey at\nhttps://sign.example/#x"),
            "{text}"
        );
        assert!(
            text.contains("Digest, first 8 characters: 01234567\n"),
            "{text}"
        );
        assert!(
            text.contains("signing page shows the same digest"),
            "{text}"
        );
        assert!(text.contains("mastersos pull"), "{text}");
        assert!(!text.contains("recovery kit"), "{text}");
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
        assert!(err.contains("do not sign pending bundle p-1"), "{err}");
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
        let c = Contents {
            manifest_text: manifest_text(),
            files,
        };
        let w = Workdir::write_pulled(&t.path().join("school"), meta, &c, false).unwrap();
        let text = format!("{}# edited\n", w.manifest().unwrap());
        std::fs::write(w.root.join("manifest.toml"), text).unwrap();
        let key = t.path().join("rk.pem");
        mastersos_sign::keygen(&key).unwrap();
        let token = t.path().join("token");
        std::fs::write(&token, "tok").unwrap();
        let pins = t.path().join("pins");
        let api = Api::new(&s.uri(), "tok").unwrap();
        let mut out = Vec::new();
        let err = publish(
            &api,
            &w,
            Some(SignOpts {
                key: &key,
                token_file: &token,
                pin_dir: &pins,
            }),
            &[],
            now(),
            &mut std::io::empty(),
            &mut out,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("the server holds other content under this pending id"),
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

    #[test]
    fn sign_link_names_the_domain_of_the_school_host() {
        let c = AuthConfig {
            name: "Demo".into(),
            slug: "demo".into(),
            school_id: SID.into(),
            signing_origin: "https://sign.os.example.com/".into(),
        };
        assert_eq!(
            sign_link(&c, "https://demo.os.example.com", "p-1"),
            format!("https://sign.os.example.com/#school=demo&sid={SID}&op=commit&domain=os.example.com&pending=p-1")
        );
        // Another host (a local server, or a name that is not `<slug>.<domain>`): no domain.
        for server in [
            "http://localhost:8080",
            "https://demo2.os.example.com",
            "https://demo",
        ] {
            assert_eq!(
                sign_link(&c, server, "p-1"),
                format!("https://sign.os.example.com/#school=demo&sid={SID}&op=commit&pending=p-1"),
                "{server}"
            );
        }
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
        let (r, out) = run_out(&s, &w).await;
        r.unwrap();
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
        run(&s, &w).await.unwrap();
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
}
