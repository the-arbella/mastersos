//! The tool table and parameters. Nine read-only tools: five work on the local settings directory
//! (`mastersos mcp --dir <dir>`) and never read `secrets.toml`; four are read-only admin API calls.
//!
//! The parameter structs are both the source of the JSON schema (schemars) and the deserialization target.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use reqwest::Method;
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::workdir::{self, redact, Workdir};

/// Where a tool runs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// On the settings directory; no network.
    Local,
    /// One read-only admin API call.
    Server,
}

/// One tool.
pub struct Tool {
    pub name: &'static str,
    pub kind: Kind,
    /// For the model: when to use it and what the parameters mean.
    pub description: &'static str,
}

/// The one rule the model must know about secrets; part of every tool that touches settings text.
macro_rules! secret_rule {
    () => {
        "Secrets (Wi-Fi passwords and the like) never appear in manifest.toml: a secret field holds a reference such as psk = \"secret:guest-wifi\". The values live in secrets.toml, which these tools never read or show. To add a password network, write psk = \"secret:<name>\" (name: a-z, 0-9, hyphen) and ask IT to fill in that name in secrets.toml; do not ask for or write the password yourself."
    };
}

/// Every tool, read-only. The command line runs the server ones by these names too.
pub const TOOLS: &[Tool] = &[
    Tool {
        name: "read_manifest",
        kind: Kind::Local,
        description: concat!(
            "Read manifest.toml of the local settings directory, the Settings text you edit. No parameters. ",
            secret_rule!()
        ),
    },
    Tool {
        name: "list_files",
        kind: Kind::Local,
        description: "List the files the settings carry (under files/ and scripts/) with their sizes. No parameters. secrets.toml and the .mastersos/ folder are not listed.",
    },
    Tool {
        name: "read_file",
        kind: Kind::Local,
        description: "Read one text file under files/ or scripts/. Parameter path, such as \"files/wallpaper.txt\" or \"scripts/setup.sh\". Any other path (secrets.toml, .mastersos/, .., absolute paths, links) is refused.",
    },
    Tool {
        name: "check",
        kind: Kind::Local,
        description: concat!(
            "Check the local settings directory the way publishing would, without the network. Returns {issues, publishable, rerouted_secrets}; each issue has level, code, message, path and a span where known. Run it after every edit and fix every error. Use spec with an issue code as the section to read how to fix it. rerouted_secrets lists the secrets a secret_rerouted warning names: publishing refuses until IT approves each one on the command line; tell IT which secrets and why, and leave the decision to IT (you have no way to approve it and must not suggest the approval flag as a fix). No parameters. ",
            secret_rule!()
        ),
    },
    Tool {
        name: "diff",
        kind: Kind::Local,
        description: "Show what changed in the local settings directory since the last pull: a unified diff of manifest.toml, then one line per changed secret (its name and added, removed or changed, never its value) and per changed file. No parameters.",
    },
    Tool {
        name: "devices_list",
        kind: Kind::Server,
        description: "List Devices with their latest report. Optional parameters: group (only this group), offline_days (last report older than this many days), status (behind: not on the latest version / errors: had execution errors / stale: Settings may be out of date / locked: locked Devices).",
    },
    Tool {
        name: "device_show",
        kind: Kind::Server,
        description: "One Device's latest report. Parameter device is the device id or the serial number.",
    },
    Tool {
        name: "keys_list",
        kind: Kind::Server,
        description: "The school keys registered for the school: key_id (its first 8 hex digits are the key code), kind, alg, label, and whether each is one of the trusted keys of the latest published version (in_published_trust). No parameters.",
    },
    Tool {
        name: "spec",
        kind: Kind::Server,
        description: "The Settings reference in Markdown: every field, its rules, and every issue code with how to fix it. Without parameters it returns the short version meant for prompts. Parameter section (optional) returns just one section: an issue code such as icon_invalid, a table name such as config, group, config.apps.web or school.oidc, or top-level. An unknown section is an error that lists the available sections.",
    },
];

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

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct NoParams {}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReadFile {
    /// A path under files/ or scripts/, for example files/wallpaper.txt.
    path: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ListDevices {
    /// Only Devices in this group.
    group: Option<String>,
    /// Last report older than this many days.
    offline_days: Option<i64>,
    /// behind | errors | stale | locked
    status: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ShowDevice {
    /// The device id or the serial number.
    device: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ManifestSpec {
    /// One section: an issue code (icon_invalid), a table name (config, group, config.apps.web) or top-level.
    /// Leave out for the short version of the whole reference.
    section: Option<String>,
}

fn schema<P: JsonSchema>() -> Map<String, Value> {
    match serde_json::to_value(schemars::schema_for!(P)) {
        Ok(Value::Object(m)) => m,
        _ => Map::new(),
    }
}

/// The JSON schema of a tool's parameters.
pub fn input_schema(name: &str) -> Map<String, Value> {
    match name {
        "read_file" => schema::<ReadFile>(),
        "devices_list" => schema::<ListDevices>(),
        "device_show" => schema::<ShowDevice>(),
        "spec" => schema::<ManifestSpec>(),
        _ => schema::<NoParams>(),
    }
}

/// The tool definitions for `tools/list`.
pub fn mcp_tools() -> Vec<rmcp::model::Tool> {
    TOOLS
        .iter()
        .map(|t| rmcp::model::Tool::new(t.name, t.description, input_schema(t.name)))
        .collect()
}

fn args<P: DeserializeOwned>(name: &str, v: Value) -> Result<P, String> {
    serde_json::from_value(v).map_err(|e| format!("Bad parameters for tool {name}: {e}"))
}

/// Tool name plus arguments -> HTTP request, for the tools that are one API call
/// (`device_show` lists and picks, see `call`). Bad arguments return text for the model.
pub fn build(name: &str, a: Value) -> Result<Req, String> {
    let admin = |rest: &str| Req::get(&["v1", "admin", rest]);
    Ok(match name {
        "devices_list" | "device_show" => {
            let mut r = admin("devices");
            if name == "devices_list" {
                let p: ListDevices = args(name, a)?;
                if let Some(g) = p.group {
                    r.query.push(("group".into(), g));
                }
                if let Some(d) = p.offline_days {
                    r.query.push(("offline_days".into(), d.to_string()));
                }
                if let Some(s) = p.status {
                    r.query.push(("status".into(), s));
                }
            } else {
                args::<ShowDevice>(name, a)?;
            }
            r
        }
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

/// The device id or serial number a `device_show` call asks for.
pub fn device_wanted(a: Value) -> Result<String, String> {
    Ok(args::<ShowDevice>("device_show", a)?.device)
}

// -- Local tools --

/// Largest file `read_file` returns.
const MAX_READ: u64 = 1024 * 1024;

/// Run a local tool on the settings directory `dir`, its base checked against the pins in `pins`.
/// Success is the text for the model. Neither the output nor the error holds a secret value: both
/// go through the same scrub as `check`.
pub fn call_local(dir: &Path, pins: &Path, name: &str, a: Value) -> Result<String, String> {
    let w = Workdir::open(dir)
        .map_err(|e| format!("{e:#}"))?
        .with_pins(pins);
    // Values to scrub with; if secrets.toml cannot be read nothing can be scrubbed, so nothing that
    // may hold settings text is returned (the error text of that failure never quotes the file).
    let secrets = w.secrets();
    let result = run_local(&w, secrets.as_ref().ok(), name, a);
    match result {
        Ok(text) => Ok(text),
        Err(e) => Err(match &secrets {
            Ok(s) => redact(&e, s),
            Err(_) => e,
        }),
    }
}

fn run_local(
    w: &Workdir,
    secrets: Option<&std::collections::BTreeMap<String, String>>,
    name: &str,
    a: Value,
) -> Result<String, String> {
    let fail = |e: anyhow::Error| format!("{e:#}");
    let need = || {
        secrets.ok_or_else(|| {
            "secrets.toml could not be read, so the output cannot be scrubbed; ask IT to fix it"
                .to_string()
        })
    };
    match name {
        "read_manifest" => {
            args::<NoParams>(name, a)?;
            // A person may have pasted a plain secret into manifest.toml: scrub like `check` does.
            Ok(redact(&w.manifest().map_err(fail)?, need()?))
        }
        "list_files" => {
            args::<NoParams>(name, a)?;
            let files: Vec<Value> = w
                .files()
                .map_err(fail)?
                .iter()
                .filter(|(k, _)| mastersos_bundle::check_member_path(k).is_ok())
                .map(|(k, v)| json!({ "path": k, "size": v.len() }))
                .collect();
            Ok(Value::Array(files).to_string())
        }
        "read_file" => {
            let p: ReadFile = args(name, a)?;
            Ok(redact(
                &read_member(&w.root, &p.path).map_err(fail)?,
                need()?,
            ))
        }
        "check" => {
            args::<NoParams>(name, a)?;
            let issues = workdir::check(w).map_err(fail)?;
            Ok(check_result(&issues).to_string())
        }
        "diff" => {
            args::<NoParams>(name, a)?;
            let text = workdir::diff(w).map_err(fail)?;
            // The manifest diff holds references only; scrub with the base's secrets too in case
            // a plain value was pasted into either side.
            let base_secrets = w.base().map(|b| b.1).map_err(fail)?;
            Ok(redact(&redact(&text, need()?), &base_secrets))
        }
        other => Err(format!("No such tool: {other}")),
    }
}

/// The check's result, for the `check` tool and `mastersos --json check`: `{issues, publishable,
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

/// The text of one member file. Only `files/…` and `scripts/…` paths that pass the bundle's path
/// check; never through a link; text only.
fn read_member(root: &Path, path: &str) -> anyhow::Result<String> {
    if mastersos_bundle::check_member_path(path).is_err() {
        bail!(
            "Only files under files/ or scripts/ can be read (secrets.toml and .mastersos/ never)"
        );
    }
    let mut cur: PathBuf = root.to_path_buf();
    for part in path.split('/') {
        cur.push(part);
        let meta =
            std::fs::symlink_metadata(&cur).with_context(|| format!("There is no file {path}"))?;
        if mastersos_sign::platform::is_link(&cur, &meta) {
            bail!("{path} goes through a link, which is refused");
        }
    }
    let meta = std::fs::symlink_metadata(&cur)?;
    if !meta.is_file() {
        bail!("{path} is not a file");
    }
    if meta.len() > MAX_READ {
        bail!("{path} is larger than {MAX_READ} bytes");
    }
    let bytes = std::fs::read(&cur).with_context(|| format!("Could not read {path}"))?;
    String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("{path} is not a text file"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workdir::Meta;
    use mastersos_bundle::Contents;
    use std::collections::BTreeMap;

    const SAMPLE: &str = "format = 2\n[school]\nid = \"11111111-1111-1111-1111-111111111111\"\n\n[defaults]\nwifi = [{ ssid = \"Guest\", psk = \"oldpass1\" }]\n\n[[config]]\nid = \"default\"\nname = \"Default\"\ninterface = \"learning\"\nlogin_methods = [\"local\"]\n\n[[group]]\nid = \"default\"\nname = \"Ungrouped\"\nconfig = \"default\"\n";

    fn pulled(dir: &Path) -> Workdir {
        let mut files = BTreeMap::new();
        files.insert("files/a.txt".to_string(), b"hello".to_vec());
        files.insert("scripts/s.sh".to_string(), b"echo oldpass1\n".to_vec());
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

    fn run(w: &Workdir, name: &str) -> Result<String, String> {
        call_local(&w.root, &w.test_pins(), name, json!({}))
    }

    fn read(w: &Workdir, path: &str) -> Result<String, String> {
        call_local(
            &w.root,
            &w.test_pins(),
            "read_file",
            json!({ "path": path }),
        )
    }

    #[test]
    fn keys_list_reads_the_signing_keys_endpoint() {
        let r = build("keys_list", serde_json::json!({})).unwrap();
        assert_eq!(r.segments, ["v1", "admin", "signing-keys"]);
        assert!(r.query.is_empty());
    }

    #[test]
    fn read_file_refuses_secrets() {
        let t = tempfile::tempdir().unwrap();
        let w = pulled(&t.path().join("school"));
        for p in [
            "secrets.toml",
            "../secrets.toml",
            ".mastersos/base/secrets.toml",
            "/etc/passwd",
            "files/../secrets.toml",
            "manifest.toml",
        ] {
            let e = read(&w, p).unwrap_err();
            assert!(!e.contains("oldpass1"), "{p}: {e}");
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(w.root.join("secrets.toml"), w.root.join("files/link"))
                .unwrap();
            assert!(read_member(&w.root, "files/link").is_err());
            std::fs::create_dir(t.path().join("outside")).unwrap();
            std::fs::write(t.path().join("outside/x"), "x").unwrap();
            std::os::unix::fs::symlink(t.path().join("outside"), w.root.join("files/dir")).unwrap();
            assert!(read_member(&w.root, "files/dir/x").is_err());
            // A link in the directory makes the whole snapshot unreadable: every tool fails closed.
            assert!(read(&w, "files/a.txt").is_err());
            std::fs::remove_file(w.root.join("files/link")).unwrap();
            std::fs::remove_file(w.root.join("files/dir")).unwrap();
        }
        assert_eq!(read(&w, "files/a.txt").unwrap(), "hello");
        // Values in a readable file are scrubbed too.
        assert_eq!(
            read(&w, "scripts/s.sh").unwrap(),
            "echo secret:guest-wifi\n".replace("guest-wifi", &only_secret_name(&w))
        );
        let listed = run(&w, "list_files").unwrap();
        assert!(
            listed.contains("files/a.txt") && listed.contains("scripts/s.sh"),
            "{listed}"
        );
        assert!(
            !listed.contains("secrets") && !listed.contains(".mastersos"),
            "{listed}"
        );
    }

    fn only_secret_name(w: &Workdir) -> String {
        w.secrets().unwrap().keys().next().unwrap().clone()
    }

    #[test]
    fn diff_never_prints_secret_values() {
        let t = tempfile::tempdir().unwrap();
        let w = pulled(&t.path().join("school"));
        let name = only_secret_name(&w);
        std::fs::write(
            w.root.join("secrets.toml"),
            format!("{name} = \"newpass2\"\n"),
        )
        .unwrap();
        let out = run(&w, "diff").unwrap();
        assert!(
            !out.contains("oldpass1") && !out.contains("newpass2"),
            "{out}"
        );
        assert!(out.contains(&name) && out.contains("changed"), "{out}");
    }

    #[test]
    fn read_manifest_scrubs_plain_secret() {
        let t = tempfile::tempdir().unwrap();
        let w = pulled(&t.path().join("school"));
        let name = only_secret_name(&w);
        let pasted = w
            .manifest()
            .unwrap()
            .replace(&format!("secret:{name}"), "oldpass1");
        assert!(pasted.contains("oldpass1"));
        std::fs::write(w.root.join("manifest.toml"), pasted).unwrap();
        let out = run(&w, "read_manifest").unwrap();
        assert!(!out.contains("oldpass1"), "{out}");
        assert!(out.contains(&format!("secret:{name}")), "{out}");
        // The diff and check do not leak it either.
        assert!(!run(&w, "diff").unwrap().contains("oldpass1"));
        assert!(!run(&w, "check").unwrap().contains("oldpass1"));
        // An unreadable secrets.toml fails closed.
        std::fs::write(w.root.join("secrets.toml"), "oldpass1 oops").unwrap();
        let e = run(&w, "read_manifest").unwrap_err();
        assert!(!e.contains("oldpass1"), "{e}");
    }

    #[test]
    fn check_lists_rerouted_secrets_as_not_publishable() {
        let t = tempfile::tempdir().unwrap();
        let w = pulled(&t.path().join("school"));
        let name = only_secret_name(&w);
        let v: Value = serde_json::from_str(&run(&w, "check").unwrap()).unwrap();
        assert_eq!(v["rerouted_secrets"], json!([]));
        let text = w.manifest().unwrap().replace("\"Guest\"", "\"Lobby\"");
        std::fs::write(w.root.join("manifest.toml"), text).unwrap();
        let v: Value = serde_json::from_str(&run(&w, "check").unwrap()).unwrap();
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
        for tool in ["check", "diff"] {
            let e = run(&w, tool).unwrap_err();
            assert!(e.contains("mastersos pull --force"), "{e}");
            let longest_hex = e
                .split(|c: char| !c.is_ascii_hexdigit())
                .map(str::len)
                .max()
                .unwrap_or(0);
            assert!(longest_hex < 64, "{e}");
        }
    }

    #[test]
    fn no_tool_can_approve_a_reroute() {
        // Only IT approves a rerouted secret (`mastersos publish --allow-reroute`): no tool
        // publishes, and no tool's parameters mention an approval.
        for t in mcp_tools() {
            let schema = serde_json::to_string(&t.input_schema).unwrap();
            assert!(!t.name.contains("publish"), "{}", t.name);
            assert!(
                !schema.contains("allow") && !schema.contains("reroute"),
                "{schema}"
            );
        }
    }

    #[test]
    fn tool_list_is_read_only() {
        let mut names: Vec<String> = mcp_tools().iter().map(|t| t.name.to_string()).collect();
        names.sort();
        let mut want = [
            "read_manifest",
            "list_files",
            "read_file",
            "check",
            "diff",
            "devices_list",
            "device_show",
            "keys_list",
            "spec",
        ]
        .map(String::from)
        .to_vec();
        want.sort();
        assert_eq!(names, want);
        for t in TOOLS
            .iter()
            .filter(|t| t.name == "read_manifest" || t.name == "check")
        {
            assert!(
                t.description.contains("secrets.toml") && t.description.contains("secret:<name>")
            );
        }
    }
}
