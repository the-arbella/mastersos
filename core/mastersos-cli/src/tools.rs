//! The server requests the command line makes (`key list`, `spec`): a name plus JSON
//! arguments become one read-only admin API request ([`build`]).

use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};

/// An HTTP request to send.
pub struct Req {
    pub method: Method,
    pub segments: Vec<String>,
    pub query: Vec<(String, String)>,
    pub body: Body,
}

pub enum Body {
    None,
    Json(Value),
    Text(String),
    Bytes(Vec<u8>),
}

impl Req {
    fn new(method: Method, segments: &[&str]) -> Req {
        Req {
            method,
            segments: segments.iter().map(|s| s.to_string()).collect(),
            query: Vec::new(),
            body: Body::None,
        }
    }

    pub fn get(segments: &[&str]) -> Req {
        Req::new(Method::GET, segments)
    }

    /// A POST with a JSON body (for the checks the server itself makes before a write).
    pub fn post_json(segments: &[&str], body: Value) -> Req {
        Req::new(Method::POST, segments).json(body)
    }

    fn json(mut self, v: Value) -> Req {
        self.body = Body::Json(v);
        self
    }
}

// -- Parameters --

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoParams {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestSpec {
    /// One section: an issue code, a table name or top-level; none for the short version.
    section: Option<String>,
}

fn args<P: DeserializeOwned>(name: &str, v: Value) -> Result<P, String> {
    serde_json::from_value(v).map_err(|e| format!("Bad parameters for tool {name}: {e}"))
}

/// Tool name plus arguments -> HTTP request, for the tools that are one API call. Bad arguments
/// return text for the model.
pub fn build(name: &str, a: Value) -> Result<Req, String> {
    let admin = |rest: &str| Req::get(&["v1", "admin", rest]);
    Ok(match name {
        "keys_list" => {
            args::<NoParams>(name, a)?;
            admin("signing-keys")
        }
        "spec" => {
            let p: ManifestSpec = args(name, a)?;
            let mut r = Req::get(&["v1", "spec", "manifest"]);
            match p.section {
                Some(sec) => r.query.push(("section".into(), sec)),
                None => r.query.push(("profile".into(), "prompt".into())),
            }
            r
        }
        other => return Err(format!("No such tool: {other}")),
    })
}

/// The check's result, for `mastersos --json check`: `{issues, publishable,
/// rerouted_secrets}`. A rerouted secret stops publishing until IT approves it, so a directory
/// with one is not publishable as it stands.
pub fn check_result(issues: &[mastersos_bundle::Lint]) -> Value {
    let rerouted = mastersos_bundle::secret_ref::rerouted_names(issues);
    let publishable = rerouted.is_empty() && !mastersos_bundle::has_errors(issues);
    json!({
        "issues": issues,
        "publishable": publishable,
        "rerouted_secrets": rerouted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workdir::{self, Meta, Workdir};
    use mastersos_bundle::Contents;
    use std::collections::BTreeMap;

    #[test]
    fn keys_list_reads_the_signing_keys_endpoint() {
        let r = build("keys_list", serde_json::json!({})).unwrap();
        assert_eq!(r.segments, ["v1", "admin", "signing-keys"]);
        assert!(r.query.is_empty());
    }

    #[test]
    fn unknown_names_and_parameters_are_refused() {
        assert!(build("publish", json!({})).is_err());
        assert!(build("keys_list", json!({ "x": 1 })).is_err());
    }

    const SAMPLE: &str = "format = 2\n[school]\nid = \"11111111-1111-1111-1111-111111111111\"\n\n[defaults]\nwifi = [{ ssid = \"Guest\", psk = \"oldpass1\" }]\n\n[[config]]\nid = \"default\"\nname = \"Default\"\ninterface = \"learning\"\nlogin_methods = [\"local\"]\n\n[[group]]\nid = \"default\"\nname = \"Ungrouped\"\nconfig = \"default\"\n";

    fn pulled(dir: &std::path::Path) -> Workdir {
        let mut files = BTreeMap::new();
        files.insert("files/a.txt".to_string(), b"hello".to_vec());
        let c = Contents {
            manifest_text: SAMPLE.to_string(),
            files,
        };
        let meta = Meta {
            server: "https://school.example".into(),
            school_id: "11111111-1111-1111-1111-111111111111".into(),
            base_version: 1,
        };
        Workdir::write_pulled(dir, meta, &c, false)
            .unwrap()
            .pinned()
    }

    #[test]
    fn check_lists_rerouted_secrets_as_not_publishable() {
        let t = tempfile::tempdir().unwrap();
        let w = pulled(&t.path().join("school"));
        let name = w.secrets().unwrap().keys().next().unwrap().clone();
        let v = check_result(&workdir::check(&w).unwrap());
        assert_eq!(v["rerouted_secrets"], json!([]));
        let text = w.manifest().unwrap().replace("\"Guest\"", "\"Lobby\"");
        std::fs::write(w.root.join("manifest.toml"), text).unwrap();
        let v = check_result(&workdir::check(&w).unwrap());
        assert_eq!(v["rerouted_secrets"], json!([name]));
        assert_eq!(v["publishable"], false);
    }

    #[test]
    fn tampered_base_error_shows_no_digest() {
        // A digest of the filled base would let a weak password be guessed offline.
        let t = tempfile::tempdir().unwrap();
        let w = pulled(&t.path().join("school"));
        let base = w.root.join(".mastersos/base/manifest.toml");
        let text = std::fs::read_to_string(&base).unwrap();
        std::fs::write(&base, format!("{text}# changed\n")).unwrap();
        let errors = [
            format!("{:#}", workdir::check(&w).unwrap_err()),
            format!("{:#}", workdir::diff(&w).unwrap_err()),
        ];
        for e in errors {
            assert!(e.contains("mastersos pull --force"), "{e}");
            let longest_hex = e
                .split(|c: char| !c.is_ascii_hexdigit())
                .map(str::len)
                .max()
                .unwrap_or(0);
            assert!(longest_hex < 64, "{e}");
        }
    }
}
