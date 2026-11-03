//! The tool table and parameters: one tool per admin API operation, read and draft scopes only.
//!
//! The parameter structs are both the source of the JSON schema (schemars) and the deserialization target.

use reqwest::Method;
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Map, Value};

/// One tool.
pub struct Tool {
    pub name: &'static str,
    /// The matching OpenAPI `operationId` (`/v1/openapi.json`).
    pub operation_id: &'static str,
    /// For the model: when to use it and what the parameters mean.
    pub description: &'static str,
}

/// Every tool (the command line runs the same operations by these names): read-only. Task 5 settles the final set.
pub const TOOLS: &[Tool] = &[
    Tool {
        name: "whoami",
        operation_id: "whoami",
        description: "Who you are: your scopes and the school's current signing mode. No parameters.",
    },
    Tool {
        name: "summary",
        operation_id: "get_summary",
        description: "Overview: the latest version, whether the draft has unpublished changes, Device counts by state, and publish requests awaiting confirmation. Use it first to get the big picture. No parameters.",
    },
    Tool {
        name: "list_devices",
        operation_id: "list_devices",
        description: "List Devices with their latest report. Optional parameters: group (only this group), offline_days (last report older than this many days), status (behind: not on the latest version / errors: had execution errors / stale: Settings may be out of date / locked: locked Devices).",
    },
    Tool {
        name: "list_versions",
        operation_id: "list_versions",
        description: "The published versions (version number, time, who published, who signed). No parameters.",
    },
    Tool {
        name: "get_version",
        operation_id: "get_version",
        description: "The Settings text and file list of one published version. Parameter version is the version number. Wi-Fi secrets (psk, password, client_key, client_key_password) always read as \"<kept>\": you never see their values.",
    },
    Tool {
        name: "get_version_diff",
        operation_id: "diff_version",
        description: "The difference between version-1 and version. Parameter version is the version number. Both sides show Wi-Fi secrets as \"<kept>\", so a changed password does not show as a difference.",
    },
    Tool {
        name: "check_manifest",
        operation_id: "check_manifest",
        description: "Check a Settings text (TOML) without saving it. Returns {issues, publishable}; each issue has level, code, message, path and a span (line and column) where known. Always run this before put_draft_manifest; fix every error first. Use get_manifest_spec with an issue code as the section to read how to fix it. Parameter text is the full Settings text. Wi-Fi secrets follow the put_draft_manifest rule: \"<kept>\" is checked as the current value, any other secret value is refused (secret_via_web).",
    },
    Tool {
        name: "get_manifest_spec",
        operation_id: "get_manifest_spec",
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

    fn with(mut self, extra: &[&str]) -> Req {
        self.segments.extend(extra.iter().map(|s| s.to_string()));
        self
    }

    fn id(mut self, seg: impl ToString) -> Req {
        self.segments.push(seg.to_string());
        self
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
struct VersionNo {
    /// Version number.
    version: u64,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct CheckManifest {
    /// The full Settings text (TOML) to check.
    text: String,
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
        "list_devices" => schema::<ListDevices>(),
        "get_version" | "get_version_diff" => schema::<VersionNo>(),
        "check_manifest" => schema::<CheckManifest>(),
        "get_manifest_spec" => schema::<ManifestSpec>(),
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

/// Tool name plus arguments -> HTTP request. Bad arguments return text for the model.
pub fn build(name: &str, a: Value) -> Result<Req, String> {
    let admin = |rest: &[&str]| Req::new(Method::GET, &["v1", "admin"]).with(rest);
    let post = |r: Req| Req {
        method: Method::POST,
        ..r
    };
    Ok(match name {
        "whoami" => {
            args::<NoParams>(name, a)?;
            admin(&["whoami"])
        }
        "summary" => {
            args::<NoParams>(name, a)?;
            admin(&["summary"])
        }
        "list_devices" => {
            let p: ListDevices = args(name, a)?;
            let mut r = admin(&["devices"]);
            if let Some(g) = p.group {
                r.query.push(("group".into(), g));
            }
            if let Some(d) = p.offline_days {
                r.query.push(("offline_days".into(), d.to_string()));
            }
            if let Some(s) = p.status {
                r.query.push(("status".into(), s));
            }
            r
        }
        "list_versions" => {
            args::<NoParams>(name, a)?;
            admin(&["versions"])
        }
        "get_version" => admin(&["versions"]).id(args::<VersionNo>(name, a)?.version),
        "get_version_diff" => admin(&["versions"])
            .id(args::<VersionNo>(name, a)?.version)
            .with(&["diff"]),
        "check_manifest" => {
            let p: CheckManifest = args(name, a)?;
            post(admin(&["manifest", "check"])).json(json!({ "text": p.text }))
        }
        "get_manifest_spec" => {
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
