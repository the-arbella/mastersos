//! `mastersos publish`: the local directory is checked, its secrets are filled back in, version
//! and time are stamped, and the result is uploaded as a pending bundle. With a recovery key the
//! bundle is then verified and signed on this computer ([`mastersos_sign::sign_pending`]);
//! without one, the signing page link is returned for IT to open with a Passkey.

use std::io::{BufRead, Write};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, SecondsFormat, Utc};
use mastersos_bundle::secret_ref;
use mastersos_bundle::stamp::{school_name_to_write, stamp};
use mastersos_bundle::{has_errors, Lint};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::tools::Req;
use crate::workdir::{self, Workdir};
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
    /// Uploaded, not signed: IT opens `url` and signs with a Passkey, then runs `mastersos pull`.
    NeedsPasskey { url: String, pending_id: String },
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
}

/// The signing page link for a pending bundle.
fn sign_link(c: &AuthConfig, pending_id: &str) -> String {
    format!(
        "{}/#school={}&sid={}&op=commit&pending={}",
        c.signing_origin.trim_end_matches('/'),
        c.slug,
        c.school_id,
        pending_id
    )
}

pub async fn publish(
    api: &Api,
    w: &Workdir,
    sign: Option<SignOpts<'_>>,
    now: DateTime<Utc>,
    confirm: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<PublishOutcome> {
    let meta = w.meta()?;
    let lints = workdir::check(w)?;
    if has_errors(&lints) {
        return Err(CheckFailed(lints).into());
    }
    let manifest = w.manifest()?;
    let filled = secret_ref::fill(&manifest, &w.secrets()?).map_err(CheckFailed)?;
    let files = w.files()?;

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
    let body = json!({
        "manifest_text": stamped,
        "files": files.iter().map(|(p, b)| (p.clone(), STANDARD.encode(b))).collect::<std::collections::BTreeMap<String, String>>(),
    });
    let x = api
        .exchange(Req::post_json(&["v1", "admin", "publish", "pending"], body))
        .await
        .map_err(|e| anyhow!("{e}"))?;
    match x.status {
        200 => {}
        409 => {
            let newest = serde_json::from_str::<Value>(&x.body)
                .ok()
                .and_then(|v| v["error"]["details"]["current_version"].as_u64());
            return Err(match newest {
                Some(n) => anyhow!(
                    "Someone published v{n} after your base v{}; run `mastersos pull` and redo your change",
                    meta.base_version
                ),
                None => anyhow!(
                    "Someone published a newer version after your base v{}; run `mastersos pull` and redo your change",
                    meta.base_version
                ),
            });
        }
        s => bail!("{}", api_error(s, &x.body)),
    }
    let prepared: Prepared = serde_json::from_str(&x.body)
        .context("the server's upload answer is not what was expected")?;
    if prepared.version != version {
        bail!(
            "the server prepared version {} but this directory publishes version {version}; nothing was signed",
            prepared.version
        );
    }

    match sign {
        Some(s) => {
            let sign_api = mastersos_sign::Api::from_token_file(&meta.server, s.token_file)?;
            let v = mastersos_sign::sign_pending(
                &sign_api,
                s.key,
                s.pin_dir,
                &prepared.pending_id,
                confirm,
                out,
            )
            .await?;
            w.mark_published(v)?;
            Ok(PublishOutcome::Published(v))
        }
        None => Ok(PublishOutcome::NeedsPasskey {
            url: sign_link(&cfg, &prepared.pending_id),
            pending_id: prepared.pending_id,
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
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
        Workdir::write_pulled(dir, meta, &c, false).unwrap()
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
        let api = Api::new(&s.uri(), "tok").unwrap();
        publish(&api, w, None, now(), &mut std::io::empty(), &mut Vec::new()).await
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

    fn accepted(version: u64) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "pending_id": "p-1", "version": version, "digest": "00", "lints": []
        }))
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
                "error": { "code": "version_conflict", "message": "newer version", "details": { "current_version": 6 } }
            })))
            .mount(&s)
            .await;
        let t = tempfile::tempdir().unwrap();
        let w = workdir(&t.path().join("school"));
        let err = run(&s, &w).await.unwrap_err().to_string();
        assert!(err.contains("mastersos pull"), "{err}");
        assert!(err.contains("v6") && err.contains("base v4"), "{err}");
        assert_eq!(w.meta().unwrap().base_version, 4);
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
        assert_eq!(
            got,
            PublishOutcome::NeedsPasskey {
                url: format!("https://sign.example/#school=demo&sid={SID}&op=commit&pending=p-1"),
                pending_id: "p-1".into()
            }
        );
        // Not signed here: the base stays until IT signs and pulls.
        assert_eq!(w.meta().unwrap().base_version, 4);
    }
}
