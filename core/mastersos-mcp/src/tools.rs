//! The tool table and parameters: one tool per admin API operation, read and draft scopes only.
//!
//! The parameter structs are both the source of the JSON schema (schemars) and the deserialization target.

use base64::{engine::general_purpose::STANDARD, Engine as _};
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

/// Every tool (the command line runs the same operations by these names). Not here: `publish/prepare`, `pending/{id}/commit`, `DELETE pending/{id}`,
/// `draft/trust`, the factory reset and the rest of the inbox (`devices/reset`, `inbox/{seq}/cancel`,
/// `push-secret`: `recovery` scope), dismissing publish requests, the seed and keys.
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
        name: "list_configs",
        operation_id: "list_configs",
        description: "The configs in the draft (a config is what Devices get: mode, login methods, apps, Wi-Fi ...): id, name, interface (the mode: learning or full), the ids of the groups that use it and how many apps it lists. The rev in the result is the draft's current rev. No parameters.",
    },
    Tool {
        name: "get_config",
        operation_id: "get_config",
        description: "All fields of one config in the draft (same as [[config]] in the Settings file). has_inner_comments being true means saving with update_config drops the comments inside the config table. Parameter id is the config id. Wi-Fi secrets (psk, password, client_key, client_key_password) always read as \"<kept>\": you never see their values.",
    },
    Tool {
        name: "list_groups",
        operation_id: "list_groups",
        description: "The groups in the draft: id, name, config (the id of the config its Devices use) with that config's name and interface, the number of Devices assigned to each in the draft and the number whose latest report is in that group. The rev in the result is the draft's current rev. No parameters.",
    },
    Tool {
        name: "get_group",
        operation_id: "get_group",
        description: "One group in the draft: id, name and config (same as [[group]] in the Settings file; the settings themselves are in the config, see get_config). Parameter id is the group id.",
    },
    Tool {
        name: "get_draft_manifest",
        operation_id: "get_draft_manifest",
        description: "Read the draft Settings file as TOML text. Pass the returned rev unchanged to every later tool that edits the draft. No parameters. Wi-Fi secrets (psk, password, client_key, client_key_password) always read as \"<kept>\": you never see their values.",
    },
    Tool {
        name: "get_draft_diff",
        operation_id: "diff_draft",
        description: "The difference between the draft and the latest published version. Use it after editing to explain to the person what changed. No parameters. Both sides show Wi-Fi secrets as \"<kept>\", so a changed password does not show as a difference.",
    },
    Tool {
        name: "get_draft_lint",
        operation_id: "lint_draft",
        description: "Whether the draft can be published now: parse and validation errors plus the pre-publish lint (error blocks publishing, warning is advice, info is a note, for example which groups pause Chrome updates). Look at it after editing the draft. No parameters.",
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
    Tool {
        name: "put_draft_manifest",
        operation_id: "put_draft_manifest",
        description: "Replace the whole draft Settings file (full TOML text). First read the current text with get_draft_manifest and edit on top of it, then run check_manifest. This tool checks the text again and refuses to write when there is a toml_syntax, unknown_field, wrong_type or missing_field issue (the result is an error with the issues); otherwise it writes and the result carries the remaining issues. Parameter rev is the rev from your latest read and manifest is the new full text. Fails when the draft rev has changed: read again, then redo the edit. Only changes the draft; nothing is published. Wi-Fi secrets (psk, password, client_key, client_key_password): write \"<kept>\" to keep the value of the same network (same school or config layer, same SSID); any other value, \"<kept>\" on a new or renamed network, or \"<kept>\" while changing where the secret is sent (eap, phase2, identity, anonymous_identity, server_domain, ca_cert, check_server), is refused with secret_via_web. Never create a WPA password network: an entry with none of open, psk and eap is refused with secret_via_web (Devices would join it as open); password networks are created in the admin web page. You can add an open network (open = true) or an enterprise network (eap) without its password, client_key or client_key_password: the draft check then reports wifi_invalid until IT types the secret in the admin web page.",
    },
    Tool {
        name: "put_draft_file",
        operation_id: "put_draft_file",
        description: "Write one file in the draft (for example an icon). Parameter rev as in put_draft_manifest; path is the path inside the bundle (such as files/logo.png); give exactly one of text (a text file) or content_base64 (base64 of a binary file). Only changes the draft.",
    },
    Tool {
        name: "create_config",
        operation_id: "create_config",
        description: "Add a config to the draft. Parameter rev as in put_draft_manifest; config is the config object (id, name, interface (learning or full), login_methods, wifi, apps (web, flatpak, kiosk), chrome ..., fields as in [[config]] of the Settings file). apps.kiosk holds locked apps (an object keyed by id; the id starts with a lowercase letter, uses [a-z0-9-], at most 24 characters, at most 32 per group): each app needs a name (at most 64 characters, no colon : or comma ,); icon is optional (files/... in the bundle or an https link); a web app / PWA takes url (https) and optional allow (array of allowed domains, default the domain of url) and pwa (true installs it as a PWA, only with url); a local program takes exec instead (a Flatpak id or a path under /usr), exclusive with url; user_agent, extensions ([{id, update_url, config}]) and chrome_policy (no locked keys) apply to web apps / PWA only; login_screen defaults to true and in_session to false; when in_session is true, login_screen must not be false (entering from the desktop returns to the login screen, then taps the app). To enable sso login, [school].oidc must be set in the Settings file first, or the pre-publish check blocks it. A new config is used by no Device until a group points at it (create_group or update_group). Only changes the draft. Wi-Fi secrets (psk, password, client_key, client_key_password): write \"<kept>\" to keep the value of the same network (same school or config layer, same SSID); any other value, \"<kept>\" on a new or renamed network, or \"<kept>\" while changing where the secret is sent (eap, phase2, identity, anonymous_identity, server_domain, ca_cert, check_server), is refused with secret_via_web. Never create a WPA password network: an entry with none of open, psk and eap is refused with secret_via_web (Devices would join it as open); password networks are created in the admin web page. You can add an open network (open = true) or an enterprise network (eap) without its password, client_key or client_key_password: the draft check then reports wifi_invalid until IT types the secret in the admin web page.",
    },
    Tool {
        name: "update_config",
        operation_id: "put_config",
        description: "Replace a config in the draft with a whole object (fields you leave out are removed: read it with get_config first and edit that). Parameter rev as in put_draft_manifest; id is the config id; config is the new config object, fields as in create_config (including apps.kiosk locked apps, login_screen defaults to true). It changes the Devices of every group that uses this config. Only changes the draft. Wi-Fi secrets (psk, password, client_key, client_key_password): write \"<kept>\" to keep the value of the same network (same school or config layer, same SSID); any other value, \"<kept>\" on a new or renamed network, or \"<kept>\" while changing where the secret is sent (eap, phase2, identity, anonymous_identity, server_domain, ca_cert, check_server), is refused with secret_via_web. Never create a WPA password network: an entry with none of open, psk and eap is refused with secret_via_web (Devices would join it as open); password networks are created in the admin web page. You can add an open network (open = true) or an enterprise network (eap) without its password, client_key or client_key_password: the draft check then reports wifi_invalid until IT types the secret in the admin web page.",
    },
    Tool {
        name: "delete_config",
        operation_id: "delete_config",
        description: "Delete a config from the draft; fails with config_in_use while a group uses it (point those groups at another config first). Parameter rev as in put_draft_manifest; id is the config id. Only changes the draft.",
    },
    Tool {
        name: "create_group",
        operation_id: "create_group",
        description: "Add a group to the draft. A group only says which config its Devices use; the settings live in the config. Parameters: rev as in put_draft_manifest; id (the new group id); name (shown to IT); config (the id of an existing config, from list_configs). Then move Devices into it with assign_devices. Only changes the draft.",
    },
    Tool {
        name: "update_group",
        operation_id: "put_group",
        description: "Replace a group in the draft: rename it or point it at another config. Parameters: rev as in put_draft_manifest; id is the group id; name and config (the id of an existing config) are both required: read the group with get_group first. Only changes the draft.",
    },
    Tool {
        name: "delete_group",
        operation_id: "delete_group",
        description: "Delete a group from the draft; fails while a Device or the default group still refers to it. Parameter rev as in put_draft_manifest; id is the group id. Only changes the draft.",
    },
    Tool {
        name: "assign_devices",
        operation_id: "assign_devices",
        description: "Move a batch of Devices into one group in the draft (all succeed or all fail). Parameter rev as in put_draft_manifest; device_ids is a list of device_id values (from list_devices); group is the group id. Devices change group only after publishing.",
    },
    Tool {
        name: "set_device_lock",
        operation_id: "set_device_lock",
        description: "Lock a Device in the draft with a message, or unlock it. Parameter rev as in put_draft_manifest; device_id comes from list_devices; with message the Device is locked and shows it, without message it is unlocked. Takes effect on the Device only after publishing.",
    },
    Tool {
        name: "restore_version_to_draft",
        operation_id: "restore_version",
        description: "Copy the content of a published version back into the draft (overwrites the current draft; nothing is published). Parameter rev as in put_draft_manifest; version is the version number.",
    },
    Tool {
        name: "request_publish",
        operation_id: "create_publish_request",
        description: "Ask IT to publish the current draft. This publishes nothing: it only leaves a request, the web console alerts IT, and a person checks the diff and confirms. Parameter note says what changed and why (at most 2000 characters). Use it only after the draft is edited, check_manifest and get_draft_lint show no errors, and the person has seen get_draft_diff and agreed.",
    },
];

/// An HTTP request to send.
pub struct Req {
    pub method: Method,
    pub segments: Vec<String>,
    pub query: Vec<(String, String)>,
    /// For requests that change the draft: sent as `If-Match` unchanged.
    pub rev: Option<u64>,
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
            rev: None,
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

    /// `PUT draft/manifest` with the full text, If-Match `rev`.
    pub fn put_manifest(manifest: String, rev: u64) -> Req {
        let mut r = Req::new(Method::PUT, &["v1", "admin", "draft", "manifest"]).rev(rev);
        r.body = Body::Text(manifest);
        r
    }

    /// `POST versions/{version}/restore`, If-Match `rev`.
    pub fn restore(version: u64, rev: u64) -> Req {
        Req::new(Method::POST, &["v1", "admin", "versions"])
            .id(version)
            .with(&["restore"])
            .rev(rev)
    }

    /// A PUT with a JSON body and If-Match `rev` (for the command line's requests outside the tools).
    pub fn put_json(segments: &[&str], rev: u64, body: Value) -> Req {
        Req::new(Method::PUT, segments).rev(rev).json(body)
    }

    fn with(mut self, extra: &[&str]) -> Req {
        self.segments.extend(extra.iter().map(|s| s.to_string()));
        self
    }

    fn id(mut self, seg: impl ToString) -> Req {
        self.segments.push(seg.to_string());
        self
    }

    fn rev(mut self, rev: u64) -> Req {
        self.rev = Some(rev);
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
struct GroupId {
    /// Group id.
    id: String,
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

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct PutManifest {
    /// The rev returned by your latest read of the draft.
    rev: u64,
    /// The new full Settings text (TOML).
    manifest: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct PutFile {
    /// The rev returned by your latest read of the draft.
    rev: u64,
    /// Path inside the bundle, for example files/logo.png.
    path: String,
    /// Content of a text file; give exactly one of this and content_base64.
    text: Option<String>,
    /// Base64 (standard alphabet) of a binary file; give exactly one of this and text.
    content_base64: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ConfigId {
    /// Config id.
    id: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct CreateConfig {
    /// The rev returned by your latest read of the draft.
    rev: u64,
    /// The config object: id, name, interface, login_methods, wifi, apps (web, flatpak, kiosk) ... fields as in [[config]] of the Settings file.
    config: Map<String, Value>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct UpdateConfig {
    /// The rev returned by your latest read of the draft.
    rev: u64,
    /// Config id.
    id: String,
    /// The new, complete config object.
    config: Map<String, Value>,
}

/// Creating and replacing a group take the same three fields: a group holds nothing else.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct GroupForm {
    /// The rev returned by your latest read of the draft.
    rev: u64,
    /// Group id.
    id: String,
    /// The group's name, shown to IT.
    name: String,
    /// The id of the config the group's Devices use.
    config: String,
}

/// Deleting a group or a config: the rev and the id.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RevId {
    /// The rev returned by your latest read of the draft.
    rev: u64,
    /// The id.
    id: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct AssignDevices {
    /// The rev returned by your latest read of the draft.
    rev: u64,
    /// List of Device device_id values.
    device_ids: Vec<String>,
    /// Target group id.
    group: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SetLock {
    /// The rev returned by your latest read of the draft.
    rev: u64,
    /// The Device's device_id.
    device_id: String,
    /// Message shown while locked; leave out to unlock.
    message: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Restore {
    /// The rev returned by your latest read of the draft.
    rev: u64,
    /// The version to copy back into the draft.
    version: u64,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RequestPublish {
    /// What changed and why, for the person who confirms (at most 2000 characters).
    note: String,
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
        "get_group" => schema::<GroupId>(),
        "get_config" => schema::<ConfigId>(),
        "delete_group" | "delete_config" => schema::<RevId>(),
        "update_group" | "create_group" => schema::<GroupForm>(),
        "create_config" => schema::<CreateConfig>(),
        "update_config" => schema::<UpdateConfig>(),
        "get_version" | "get_version_diff" => schema::<VersionNo>(),
        "check_manifest" => schema::<CheckManifest>(),
        "get_manifest_spec" => schema::<ManifestSpec>(),
        "put_draft_manifest" => schema::<PutManifest>(),
        "put_draft_file" => schema::<PutFile>(),
        "assign_devices" => schema::<AssignDevices>(),
        "set_device_lock" => schema::<SetLock>(),
        "restore_version_to_draft" => schema::<Restore>(),
        "request_publish" => schema::<RequestPublish>(),
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

/// Every path segment must be a plain name: no `..` or empty segment may reach another endpoint.
fn file_segments(path: &str) -> Result<Vec<&str>, String> {
    let segs: Vec<&str> = path.split('/').collect();
    if path.is_empty()
        || segs
            .iter()
            .any(|s| s.is_empty() || *s == "." || *s == ".." || s.contains('\\'))
    {
        return Err(format!("Invalid file path: {path}"));
    }
    Ok(segs)
}

/// Tool name plus arguments -> HTTP request. Bad arguments return text for the model.
pub fn build(name: &str, a: Value) -> Result<Req, String> {
    let admin = |rest: &[&str]| Req::new(Method::GET, &["v1", "admin"]).with(rest);
    let post = |r: Req| Req {
        method: Method::POST,
        ..r
    };
    let put = |r: Req| Req {
        method: Method::PUT,
        ..r
    };
    let delete = |r: Req| Req {
        method: Method::DELETE,
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
        "list_groups" => {
            args::<NoParams>(name, a)?;
            admin(&["draft", "groups"])
        }
        "list_configs" => {
            args::<NoParams>(name, a)?;
            admin(&["draft", "configs"])
        }
        "get_config" => admin(&["draft", "configs"]).id(args::<ConfigId>(name, a)?.id),
        "get_group" => admin(&["draft", "groups"]).id(args::<GroupId>(name, a)?.id),
        "get_draft_manifest" => {
            args::<NoParams>(name, a)?;
            admin(&["draft", "manifest"])
        }
        "get_draft_diff" => {
            args::<NoParams>(name, a)?;
            admin(&["draft", "diff"])
        }
        "get_draft_lint" => {
            args::<NoParams>(name, a)?;
            admin(&["draft", "lint"])
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
        "put_draft_manifest" => {
            let p: PutManifest = args(name, a)?;
            Req::put_manifest(p.manifest, p.rev)
        }
        "put_draft_file" => {
            let p: PutFile = args(name, a)?;
            let bytes = match (p.text, p.content_base64) {
                (Some(t), None) => t.into_bytes(),
                (None, Some(b)) => STANDARD
                    .decode(b.trim())
                    .map_err(|_| "content_base64 is not valid base64".to_string())?,
                _ => return Err("give exactly one of text and content_base64".into()),
            };
            let mut r = put(admin(&["draft", "files"])).rev(p.rev);
            for s in file_segments(&p.path)? {
                r.segments.push(s.to_string());
            }
            r.body = Body::Bytes(bytes);
            r
        }
        "create_group" => {
            let p: GroupForm = args(name, a)?;
            post(admin(&["draft", "groups"]))
                .rev(p.rev)
                .json(json!({ "id": p.id, "name": p.name, "config": p.config }))
        }
        "update_group" => {
            let p: GroupForm = args(name, a)?;
            put(admin(&["draft", "groups"]))
                .id(&p.id)
                .rev(p.rev)
                .json(json!({ "id": p.id, "name": p.name, "config": p.config }))
        }
        "delete_group" => {
            let p: RevId = args(name, a)?;
            delete(admin(&["draft", "groups"])).id(p.id).rev(p.rev)
        }
        "create_config" => {
            let p: CreateConfig = args(name, a)?;
            post(admin(&["draft", "configs"]))
                .rev(p.rev)
                .json(Value::Object(p.config))
        }
        "update_config" => {
            let p: UpdateConfig = args(name, a)?;
            put(admin(&["draft", "configs"]))
                .id(p.id)
                .rev(p.rev)
                .json(Value::Object(p.config))
        }
        "delete_config" => {
            let p: RevId = args(name, a)?;
            delete(admin(&["draft", "configs"])).id(p.id).rev(p.rev)
        }
        "assign_devices" => {
            let p: AssignDevices = args(name, a)?;
            post(admin(&["devices", "assign"]))
                .rev(p.rev)
                .json(json!({ "device_ids": p.device_ids, "group": p.group }))
        }
        "set_device_lock" => {
            let p: SetLock = args(name, a)?;
            put(admin(&["devices"]))
                .id(p.device_id)
                .with(&["lock"])
                .rev(p.rev)
                .json(match p.message {
                    Some(m) => json!({ "message": m }),
                    None => Value::Null,
                })
        }
        "restore_version_to_draft" => {
            let p: Restore = args(name, a)?;
            Req::restore(p.version, p.rev)
        }
        "request_publish" => {
            let p: RequestPublish = args(name, a)?;
            post(admin(&["publish-requests"])).json(json!({ "note": p.note }))
        }
        other => return Err(format!("No such tool: {other}")),
    })
}
