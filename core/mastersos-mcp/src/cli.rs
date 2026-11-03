//! The `mastersos` command line. Every subcommand that touches the server runs the same
//! operations as the MCP tools ([`crate::call`], [`crate::write_manifest`]): one check before a
//! write and one guard on trust and factory resets for both. `mastersos mcp` serves those tools.
//!
//! Output is a table or the text itself for people; `--json` prints the server's JSON (draft
//! reads wrapped as `{"rev", "data"}`, exactly what the MCP tool returns) for scripts and AI.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::workdir::{self, Meta, Workdir};
use crate::{
    call, check_server, connect, draft_rev, serve_stdio, write_manifest, Api, OpError, Req,
};

const EXIT_CODES: &str = "Exit codes: 0 success; 1 failure (network, token, the server refused); \
2 `draft check` found errors, or `draft put` was refused by the check or by the guard on trust and factory resets.";

#[derive(Parser)]
#[command(
    name = "mastersos",
    version,
    about = "MastersOS admin command line: inspect Devices, edit the draft Settings and file a publish request. It cannot publish: IT confirms in the web console.",
    after_help = EXIT_CODES
)]
pub struct Cli {
    /// Admin server address, for example https://school.os.khundavid.com (default: `server` in ~/.config/mastersos/config.toml)
    #[arg(long, global = true)]
    server: Option<String>,
    /// File holding the token, which is never accepted on the command line; it may only have read and draft scopes
    /// (default: `token_file` in the config file, else ~/.config/mastersos/token)
    #[arg(long, global = true)]
    token_file: Option<PathBuf>,
    /// Print the server's JSON instead of tables (draft reads as {"rev", "data"}): for scripts and AI
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Save --server (and --token-file) to ~/.config/mastersos/config.toml, then test the connection
    Setup,
    /// Start a local settings directory for a school that has published nothing yet
    Init {
        /// The directory to create (it must be empty or not exist)
        dir: PathBuf,
    },
    /// Download the latest published settings (verified against the pinned keys) into a local directory
    Pull {
        /// The settings directory (default: the current directory)
        dir: Option<PathBuf>,
        /// Pull this published version instead of the latest
        #[arg(long)]
        version: Option<u64>,
        /// Overwrite local changes that are not published
        #[arg(long)]
        force: bool,
    },
    /// Check the local settings directory the way publishing would (no network)
    Check {
        /// The settings directory (default: the current directory)
        dir: Option<PathBuf>,
    },
    /// Show what changed in the local settings directory since the last pull (no network; secrets by name only)
    Diff {
        /// The settings directory (default: the current directory)
        dir: Option<PathBuf>,
    },
    /// Devices and their latest reports
    #[command(subcommand)]
    Devices(DevicesCmd),
    /// The draft Settings file
    #[command(subcommand)]
    Draft(DraftCmd),
    /// Configs ([[config]]): what Devices get (mode, login methods, apps, Wi-Fi ...)
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Groups ([[group]]): which config a set of Devices uses
    #[command(subcommand)]
    Group(GroupCmd),
    /// The school-wide settings ([school])
    #[command(subcommand)]
    School(SchoolCmd),
    /// What every config starts from ([defaults]): mode, login methods, Wi-Fi ...
    #[command(subcommand)]
    Defaults(DefaultsCmd),
    /// The Settings reference (Markdown): the short version, one section, or all of it
    Spec {
        /// One section: an issue code (icon_invalid), a table name (config, group, config.apps.web, school.oidc) or top-level
        #[arg(long)]
        section: Option<String>,
        /// The whole reference (long)
        #[arg(long, conflicts_with = "section")]
        full: bool,
    },
    /// Ask IT to publish the draft
    #[command(subcommand)]
    Publish(PublishCmd),
    /// Publish requests
    #[command(subcommand)]
    Requests(RequestsCmd),
    /// Serve the same operations as an MCP server over stdio (for clients that only speak MCP)
    Mcp,
}

#[derive(Subcommand)]
enum DevicesCmd {
    /// List Devices with their latest report
    List {
        /// Only Devices in this group
        #[arg(long)]
        group: Option<String>,
    },
    /// One Device's latest report (by device id or serial number)
    Show { device: String },
    /// Move Devices into a group in the draft (they change group after publishing)
    Assign {
        group: String,
        #[arg(required = true)]
        device_ids: Vec<String>,
        /// The rev from your last read (`show` or `draft get`): refuses with draft_conflict when someone changed the draft since (default: the draft as it is now)
        #[arg(long)]
        rev: Option<u64>,
    },
}

#[derive(Subcommand)]
enum DraftCmd {
    /// Print the draft Settings file as the server formats it (the rev goes to stderr). Writing it back with `put` is checked as usual
    Get {
        /// Write it to this file instead of stdout
        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,
    },
    /// Check a Settings file (`-` for stdin) without saving it; without a file, check the draft itself
    Check { file: Option<String> },
    /// Replace the draft with a Settings file (`-` for stdin): checked first, and refused when it changes trust or factory resets
    Put {
        file: String,
        /// The rev from your `draft get`: refuses when someone changed the draft since (default: the draft as it is now)
        #[arg(long)]
        rev: Option<u64>,
    },
    /// What the draft changes compared with the latest published version
    Diff,
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// List the configs
    List,
    /// Print one config as a [[config]] TOML fragment: only what it writes, a single value left out is inherited from Defaults (the rev goes to stderr)
    Show { id: String },
    /// Add a config from a file: a TOML fragment ([[config]] or bare keys) or JSON (.json)
    Create { file: String },
    /// Replace a whole config with a file (as for create; fields left out are removed, and a single value left out is inherited from Defaults)
    Set {
        id: String,
        file: String,
        /// The rev from your last read (`show` or `draft get`): refuses with draft_conflict when someone changed the draft since (default: the draft as it is now)
        #[arg(long)]
        rev: Option<u64>,
    },
    /// Delete a config no group uses
    Delete {
        id: String,
        /// The rev from your last read (`show` or `draft get`): refuses with draft_conflict when someone changed the draft since (default: the draft as it is now)
        #[arg(long)]
        rev: Option<u64>,
    },
}

#[derive(Subcommand)]
enum GroupCmd {
    /// List the groups
    List,
    /// Print one group as a [[group]] TOML fragment
    Show { id: String },
    /// Add a group that uses a config
    Create {
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: String,
        /// The id of the config its Devices use
        #[arg(long)]
        config: String,
    },
    /// Rename a group or point it at another config
    Set {
        id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        config: Option<String>,
        /// The rev from your last read (`show` or `draft get`): refuses with draft_conflict when someone changed the draft since (default: the draft as it is now)
        #[arg(long)]
        rev: Option<u64>,
    },
    /// Delete a group no Device refers to
    Delete {
        id: String,
        /// The rev from your last read (`show` or `draft get`): refuses with draft_conflict when someone changed the draft since (default: the draft as it is now)
        #[arg(long)]
        rev: Option<u64>,
    },
}

#[derive(Subcommand)]
enum SchoolCmd {
    /// Print [school] as TOML (the rev goes to stderr). Wi-Fi is edited in Defaults: see `defaults wifi`
    Show,
    /// Replace [school] with a file: TOML ([school] or bare keys) or JSON (.json); keys left out are removed
    Set {
        file: String,
        /// The rev from your last read (`show` or `draft get`): refuses with draft_conflict when someone changed the draft since (default: the draft as it is now)
        #[arg(long)]
        rev: Option<u64>,
    },
    /// Gone: Wi-Fi is edited in Defaults (`mastersos defaults wifi`)
    #[command(hide = true)]
    Wifi {
        #[arg(num_args = 0.., trailing_var_arg = true, allow_hyphen_values = true)]
        _args: Vec<String>,
    },
}

#[derive(Subcommand)]
enum DefaultsCmd {
    /// Print [defaults] as TOML: only the keys written (the rev goes to stderr). A config inherits every single value it does not write
    Show,
    /// Replace the whole [defaults] table with a file: TOML ([defaults] or bare keys) or JSON (.json); keys left out are removed, so start from `show`. The draft is checked again on write
    Set {
        file: String,
        /// The rev from your last read (`show` or `draft get`): refuses with draft_conflict when someone changed the draft since (default: the draft as it is now)
        #[arg(long)]
        rev: Option<u64>,
    },
    /// The Wi-Fi networks every config inherits ([[defaults.wifi]])
    #[command(subcommand)]
    Wifi(WifiCmd),
}

#[derive(Subcommand)]
enum WifiCmd {
    /// List the Wi-Fi networks in Defaults (secrets read as "<kept>" with an AI token)
    List,
    /// Add an open or enterprise network. Passwords and keys are never typed here: IT enters them on the admin web page
    Add(Box<WifiAdd>),
    /// Remove a network by its ssid
    Remove {
        #[arg(long)]
        ssid: String,
        /// The rev from your last read: refuses with draft_conflict when someone changed the draft since (default: the draft as it is now)
        #[arg(long)]
        rev: Option<u64>,
    },
}

#[derive(clap::Args)]
struct WifiAdd {
    /// The network name, exactly as broadcast
    #[arg(long)]
    ssid: String,
    /// The network does not broadcast its name
    #[arg(long)]
    hidden: bool,
    /// An open network (no password)
    #[arg(long, conflicts_with = "enterprise")]
    open: bool,
    /// An enterprise (802.1X) network: its EAP method. It is created without a password; IT enters it on the admin web page
    #[arg(long, value_name = "METHOD", value_parser = ["peap", "ttls", "tls", "pwd"])]
    enterprise: Option<String>,
    /// The account name (required with --enterprise)
    #[arg(long, requires = "enterprise")]
    identity: Option<String>,
    /// The outer identity sent before the encrypted tunnel
    #[arg(long, requires = "enterprise")]
    anonymous_identity: Option<String>,
    /// The inner authentication: mschapv2, pap, gtc or md5
    #[arg(long, requires = "enterprise", value_parser = ["mschapv2", "pap", "gtc", "md5"])]
    phase2: Option<String>,
    /// The domain on the RADIUS server's certificate
    #[arg(long, requires = "enterprise")]
    server_domain: Option<String>,
    /// A PEM file with the CA that signed the RADIUS server's certificate
    #[arg(long, requires = "enterprise", value_name = "FILE")]
    ca_cert_file: Option<PathBuf>,
    /// Connect without checking the RADIUS server (unsafe)
    #[arg(long, requires = "enterprise")]
    no_check_server: bool,
    // Secrets are refused by `wifi_add_body` before any request; they are declared only so the
    // parser can point to the admin web page instead of printing a generic unknown-flag error.
    #[arg(long, hide = true, num_args = 0..=1)]
    psk: Option<Option<String>>,
    #[arg(long, hide = true, num_args = 0..=1)]
    password: Option<Option<String>>,
    #[arg(long, hide = true, num_args = 0..=1)]
    client_key: Option<Option<String>>,
    #[arg(long, hide = true, num_args = 0..=1)]
    client_key_password: Option<Option<String>>,
}

#[derive(Subcommand)]
enum PublishCmd {
    /// Leave a publish request for IT; this publishes nothing
    Request {
        /// What changed and why, for the person who confirms
        #[arg(long, default_value = "")]
        note: String,
    },
}

#[derive(Subcommand)]
enum RequestsCmd {
    /// List publish requests
    List,
}

/// `~/.config/mastersos/config.toml`.
#[derive(Default, Deserialize, Serialize)]
struct ConfigFile {
    server: Option<String>,
    token_file: Option<PathBuf>,
}

fn config_dir() -> Result<PathBuf, OpError> {
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .ok_or_else(|| OpError::Failed("HOME is not set".into()))?;
    Ok(PathBuf::from(home).join(".config").join("mastersos"))
}

fn load_config() -> Result<ConfigFile, OpError> {
    let path = config_dir()?.join("config.toml");
    match std::fs::read_to_string(&path) {
        Ok(text) => toml::from_str(&text)
            .map_err(|e| OpError::Failed(format!("{} is not valid: {e}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ConfigFile::default()),
        Err(e) => Err(OpError::Failed(format!(
            "Could not read {}: {e}",
            path.display()
        ))),
    }
}

/// The command line's entry point.
pub async fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;
    match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            if let OpError::Refused { message, issues } = &e {
                if json {
                    // Every refusal in the shape of the check's: {"written": false, "error", "issues"?}.
                    let mut v = json!({ "written": false, "error": message });
                    if let Some(i) = issues {
                        v["issues"] = Value::Array(i.clone());
                    }
                    println!("{v}");
                } else if let Some(i) = issues {
                    print_issues(i);
                }
            }
            // The message never holds the token: only scope names, the address and the server's error text.
            eprintln!("mastersos: {}", e.message());
            ExitCode::from(e.exit_code())
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode, OpError> {
    let Cli {
        server,
        token_file,
        json,
        cmd,
    } = cli;
    if let Cmd::Setup = cmd {
        // Before the config file is read: setup is how a broken one gets rewritten.
        return setup(server, token_file).await;
    }
    // Offline commands: no server address, no token.
    match &cmd {
        Cmd::Check { dir } => return local_check(dir.as_deref(), json),
        Cmd::Diff { dir } => return local_diff(dir.as_deref()),
        _ => {}
    }
    // Refuse a Wi-Fi secret flag before the config, the token or the network is touched.
    if let Cmd::School(SchoolCmd::Wifi { .. }) = &cmd {
        return Err(OpError::Failed(
            "`school wifi` is gone: Wi-Fi networks live in Defaults. Use `mastersos defaults wifi list|add|remove`".into(),
        ));
    }
    if let Cmd::Defaults(DefaultsCmd::Wifi(WifiCmd::Add(a))) = &cmd {
        wifi_add_body(a)?;
    }
    let cfg = load_config()?;
    let server = server.or(cfg.server).ok_or_else(|| {
        OpError::Failed(
            "No server address: run `mastersos setup --server https://<school>.os.khundavid.com` first, or pass --server"
                .into(),
        )
    })?;
    let token_file = match token_file.or(cfg.token_file) {
        Some(p) => p,
        None => config_dir()?.join("token"),
    };
    check_private(&token_file)?;
    if let Cmd::Mcp = cmd {
        // The MCP server keeps its own exit codes: 2 for a token that must not be given to an AI.
        let api = match connect(&server, &token_file).await {
            Ok(api) => api,
            Err(e) => {
                eprintln!("mastersos: {e}");
                return Ok(ExitCode::from(e.exit_code()));
            }
        };
        serve_stdio(api)
            .await
            .map_err(|e| OpError::Failed(format!("{e:#}")))?;
        return Ok(ExitCode::SUCCESS);
    }
    let api = connect(&server, &token_file)
        .await
        .map_err(|e| OpError::Failed(e.to_string()))?;
    let out = Out { json };
    match cmd {
        Cmd::Setup | Cmd::Mcp | Cmd::Check { .. } | Cmd::Diff { .. } => {
            unreachable!("handled above")
        }
        Cmd::Init { dir } => init_dir(&api, &server, &token_file, &dir).await,
        Cmd::Pull {
            dir,
            version,
            force,
        } => {
            let dir = dir.unwrap_or_else(|| PathBuf::from("."));
            pull_dir(&api, &server, &token_file, &dir, version, force).await
        }
        Cmd::Devices(c) => devices(&api, &out, c).await,
        Cmd::Draft(c) => draft(&api, &out, c).await,
        Cmd::Config(c) => config(&api, &out, c).await,
        Cmd::Group(c) => group(&api, &out, c).await,
        Cmd::School(c) => school(&api, &out, c).await,
        Cmd::Defaults(c) => defaults(&api, &out, c).await,
        Cmd::Spec { section, full } => spec(&api, section, full).await,
        Cmd::Publish(PublishCmd::Request { note }) => {
            let text = call(&api, "request_publish", json!({ "note": note })).await?;
            out.print(&text, |v| {
                format!(
                    "Filed publish request {}. IT checks the diff and confirms it in the web console; nothing is published until then.",
                    cell(&v["id"])
                )
            });
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Requests(RequestsCmd::List) => {
            let text = api
                .send(Req::get(&["v1", "admin", "publish-requests"]))
                .await?;
            out.print(&text, |v| {
                table(
                    &["ID", "STATUS", "CREATED", "BY", "NOTE"],
                    rows(v, &["id", "status", "created_at", "created_by", "note"]),
                )
            });
            Ok(ExitCode::SUCCESS)
        }
    }
}

async fn setup(server: Option<String>, token_file: Option<PathBuf>) -> Result<ExitCode, OpError> {
    let server = server.ok_or_else(|| {
        OpError::Failed("setup needs --server https://<school>.os.khundavid.com".into())
    })?;
    check_server(&server).map_err(|e| OpError::Failed(e.to_string()))?;
    let dir = config_dir()?;
    let token_file = match token_file {
        Some(p) => std::path::absolute(&p)
            .map_err(|e| OpError::Failed(format!("Bad token file path {}: {e}", p.display())))?,
        None => dir.join("token"),
    };
    let have_token = token_file.exists();
    if have_token {
        check_private(&token_file)?;
    }
    std::fs::create_dir_all(&dir)
        .map_err(|e| OpError::Failed(format!("Could not create {}: {e}", dir.display())))?;
    let path = dir.join("config.toml");
    let text = toml::to_string(&ConfigFile {
        server: Some(server.clone()),
        token_file: Some(token_file.clone()),
    })
    .map_err(|e| OpError::Failed(format!("Could not write the config: {e}")))?;
    std::fs::write(&path, text)
        .map_err(|e| OpError::Failed(format!("Could not write {}: {e}", path.display())))?;
    println!("Saved {}", path.display());
    if !have_token {
        println!(
            "Next: create a token on the school's admin page (AI tools), save it to {} and run `chmod 600` on that file. Then try `mastersos devices list`.",
            token_file.display()
        );
        return Ok(ExitCode::SUCCESS);
    }
    let api = connect(&server, &token_file)
        .await
        .map_err(|e| OpError::Failed(e.to_string()))?;
    let who: Value =
        serde_json::from_str(&call(&api, "whoami", json!({})).await?).unwrap_or(Value::Null);
    println!(
        "Connected to {server} as {} (scopes: {})",
        cell(&who["label"]),
        cell(&who["scopes"])
    );
    Ok(ExitCode::SUCCESS)
}

/// The token file must be readable by its owner only.
fn check_private(path: &Path) -> Result<(), OpError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)
            .map_err(|e| OpError::Failed(format!("Could not read {}: {e}", path.display())))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(OpError::Failed(format!(
                "Other users can read the token file {p}; run: chmod 600 {p}",
                p = path.display()
            )));
        }
    }
    let _ = path;
    Ok(())
}

async fn devices(api: &Api, out: &Out, c: DevicesCmd) -> Result<ExitCode, OpError> {
    match c {
        DevicesCmd::List { group } => {
            let mut args = Map::new();
            if let Some(g) = group {
                args.insert("group".into(), Value::String(g));
            }
            let text = call(api, "list_devices", Value::Object(args)).await?;
            out.print(&text, |v| {
                let rows = items(v)
                    .iter()
                    .map(|d| {
                        let mut state: Vec<&str> = Vec::new();
                        for (k, label) in [
                            ("behind", "behind"),
                            ("has_errors", "errors"),
                            ("locked", "locked"),
                            ("stale", "stale"),
                        ] {
                            if d[k] == true {
                                state.push(label);
                            }
                        }
                        vec![
                            cell(&d["device_id"]),
                            cell(&d["serial"]),
                            cell(&d["group"]),
                            cell(&d["draft_group"]),
                            cell(&d["bundle_version"]),
                            cell(&d["last_seen"]),
                            if state.is_empty() {
                                "ok".into()
                            } else {
                                state.join(",")
                            },
                        ]
                    })
                    .collect();
                table(
                    &[
                        "DEVICE",
                        "SERIAL",
                        "GROUP",
                        "DRAFT GROUP",
                        "VERSION",
                        "LAST SEEN",
                        "STATE",
                    ],
                    rows,
                )
            });
        }
        DevicesCmd::Show { device } => {
            let text = call(api, "list_devices", json!({})).await?;
            let all: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            let want = device.trim().to_lowercase();
            let found = items(&all)
                .iter()
                .find(|d| {
                    d["device_id"].as_str() == Some(device.as_str())
                        || d["serial"]
                            .as_str()
                            .is_some_and(|s| s.trim().to_lowercase() == want)
                })
                .cloned()
                .ok_or_else(|| OpError::Failed(format!("No such Device: {device}")))?;
            if out.json {
                println!("{found}");
            } else if let Value::Object(m) = &found {
                for (k, v) in m {
                    println!("{k}: {}", cell(v));
                }
            }
        }
        DevicesCmd::Assign {
            group,
            device_ids,
            rev,
        } => {
            let rev = rev_or_current(api, rev).await?;
            let text = call(
                api,
                "assign_devices",
                json!({ "rev": rev, "device_ids": device_ids, "group": group }),
            )
            .await?;
            out.print(&text, |v| {
                format!(
                    "Assigned {} Device(s) to group {group} in the draft (rev {}). They change group after publishing.",
                    cell(&data(v)["assigned"]),
                    cell(&v["rev"])
                )
            });
        }
    }
    Ok(ExitCode::SUCCESS)
}

async fn draft(api: &Api, out: &Out, c: DraftCmd) -> Result<ExitCode, OpError> {
    match c {
        DraftCmd::Get { output } => {
            let text = call(api, "get_draft_manifest", json!({})).await?;
            let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            let manifest = v["text"].as_str().unwrap_or_default();
            match &output {
                Some(path) => std::fs::write(path, manifest).map_err(|e| {
                    OpError::Failed(format!("Could not write {}: {e}", path.display()))
                })?,
                None if !out.json => print!("{manifest}"),
                None => {}
            }
            if out.json {
                if output.is_some() {
                    println!("{}", json!({ "rev": v["rev"] }));
                } else {
                    println!("{text}");
                }
            } else {
                eprintln!("rev {}", cell(&v["rev"]));
            }
            Ok(ExitCode::SUCCESS)
        }
        DraftCmd::Check { file } => {
            let text = match file {
                Some(f) => {
                    let manifest = read_input(&f)?;
                    call(api, "check_manifest", json!({ "text": manifest })).await?
                }
                None => call(api, "get_draft_lint", json!({})).await?,
            };
            let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            let issues = data(&v)["issues"].as_array().cloned().unwrap_or_default();
            if out.json {
                println!("{text}");
            } else {
                print_issues(&issues);
            }
            let errors = issues.iter().any(|i| i["level"] == "error");
            Ok(if errors {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            })
        }
        DraftCmd::Put { file, rev } => {
            let manifest = read_input(&file)?;
            if rev.is_none() {
                eprintln!("{NO_REV_WARNING}");
            }
            let v = write_manifest(api, &manifest, rev).await?;
            if out.json {
                println!("{v}");
            } else {
                println!(
                    "Wrote the draft (rev {}). Nothing is published until IT confirms a publish request.",
                    cell(&v["rev"])
                );
                let issues = v["issues"].as_array().cloned().unwrap_or_default();
                if !issues.is_empty() {
                    print_issues(&issues);
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        DraftCmd::Diff => {
            let text = call(api, "get_draft_diff", json!({})).await?;
            out.print(&text, |v| {
                let d = data(v);
                let mut s = d["manifest_diff"].as_str().unwrap_or_default().to_owned();
                for (k, label) in [
                    ("files_added", "Files added"),
                    ("files_changed", "Files changed"),
                    ("files_removed", "Files removed"),
                ] {
                    if d[k].as_array().is_some_and(|a| !a.is_empty()) {
                        s.push_str(&format!("\n{label}: {}", cell(&d[k])));
                    }
                }
                if s.trim().is_empty() {
                    "The draft is the same as the latest published version.".into()
                } else {
                    s
                }
            });
            Ok(ExitCode::SUCCESS)
        }
    }
}

async fn config(api: &Api, out: &Out, c: ConfigCmd) -> Result<ExitCode, OpError> {
    match c {
        ConfigCmd::List => {
            let text = call(api, "list_configs", json!({})).await?;
            out.print(&text, |v| {
                table(
                    &["ID", "NAME", "MODE", "GROUPS", "APPS"],
                    rows(data(v), &["id", "name", "interface", "groups", "apps"]),
                )
            });
        }
        ConfigCmd::Show { id } => {
            let text = call(api, "get_config", json!({ "id": id })).await?;
            show_fragment(out, &text, "config", true)?;
        }
        ConfigCmd::Create { file } => {
            let config = read_object(&file, "config")?;
            let rev = draft_rev(api).await?;
            let text = call(
                api,
                "create_config",
                json!({ "rev": rev, "config": config }),
            )
            .await?;
            out.wrote(&text, "Added the config");
        }
        ConfigCmd::Set { id, file, rev } => {
            let mut config = read_object(&file, "config")?;
            config
                .entry("id")
                .or_insert_with(|| Value::String(id.clone()));
            let rev = rev_or_current(api, rev).await?;
            let text = call(
                api,
                "update_config",
                json!({ "rev": rev, "id": id, "config": config }),
            )
            .await?;
            out.wrote(&text, "Replaced the config");
        }
        ConfigCmd::Delete { id, rev } => {
            let rev = rev_or_current(api, rev).await?;
            let text = call(api, "delete_config", json!({ "rev": rev, "id": id })).await?;
            out.wrote(&text, "Deleted the config");
        }
    }
    Ok(ExitCode::SUCCESS)
}

async fn group(api: &Api, out: &Out, c: GroupCmd) -> Result<ExitCode, OpError> {
    match c {
        GroupCmd::List => {
            let text = call(api, "list_groups", json!({})).await?;
            out.print(&text, |v| {
                table(
                    &["ID", "NAME", "CONFIG", "MODE", "MEMBERS", "REPORTING"],
                    rows(
                        data(v),
                        &[
                            "id",
                            "name",
                            "config",
                            "interface",
                            "draft_members",
                            "reporting",
                        ],
                    ),
                )
            });
        }
        GroupCmd::Show { id } => {
            let text = call(api, "get_group", json!({ "id": id })).await?;
            show_fragment(out, &text, "group", true)?;
        }
        GroupCmd::Create { id, name, config } => {
            let rev = draft_rev(api).await?;
            let text = call(
                api,
                "create_group",
                json!({ "rev": rev, "id": id, "name": name, "config": config }),
            )
            .await?;
            out.wrote(&text, "Added the group");
        }
        GroupCmd::Set {
            id,
            name,
            config,
            rev,
        } => {
            if name.is_none() && config.is_none() {
                return Err(OpError::Failed("Give --name, --config or both".into()));
            }
            let cur: Value =
                serde_json::from_str(&call(api, "get_group", json!({ "id": id })).await?)
                    .unwrap_or(Value::Null);
            let g = &cur["data"]["group"];
            let text = call(
                api,
                "update_group",
                json!({
                    "rev": rev.map_or_else(|| cur["rev"].clone(), Value::from),
                    "id": id,
                    "name": name.map_or_else(|| g["name"].clone(), Value::String),
                    "config": config.map_or_else(|| g["config"].clone(), Value::String),
                }),
            )
            .await?;
            out.wrote(&text, "Changed the group");
        }
        GroupCmd::Delete { id, rev } => {
            let rev = rev_or_current(api, rev).await?;
            let text = call(api, "delete_group", json!({ "rev": rev, "id": id })).await?;
            out.wrote(&text, "Deleted the group");
        }
    }
    Ok(ExitCode::SUCCESS)
}

const SCHOOL: &[&str] = &["v1", "admin", "draft", "school"];

async fn school(api: &Api, out: &Out, c: SchoolCmd) -> Result<ExitCode, OpError> {
    match c {
        SchoolCmd::Show => {
            let text = api.send(Req::get(SCHOOL)).await?;
            show_fragment(out, &text, "school", false)?;
        }
        SchoolCmd::Set { file, rev } => {
            let school = read_object(&file, "school")?;
            let rev = rev_or_current(api, rev).await?;
            let text = api
                .send(Req::put_json(SCHOOL, rev, Value::Object(school)))
                .await?;
            out.wrote(&text, "Replaced [school]");
        }
        SchoolCmd::Wifi { .. } => unreachable!("refused in run"),
    }
    Ok(ExitCode::SUCCESS)
}

const DEFAULTS: &[&str] = &["v1", "admin", "draft", "defaults"];

async fn defaults(api: &Api, out: &Out, c: DefaultsCmd) -> Result<ExitCode, OpError> {
    match c {
        DefaultsCmd::Show => {
            let text = api.send(Req::get(DEFAULTS)).await?;
            show_fragment(out, &text, "defaults", false)?;
        }
        DefaultsCmd::Set { file, rev } => {
            let table = read_object(&file, "defaults")?;
            let rev = rev_or_current(api, rev).await?;
            let text = api
                .send(Req::put_json(DEFAULTS, rev, Value::Object(table)))
                .await?;
            out.wrote(&text, "Replaced [defaults]");
        }
        DefaultsCmd::Wifi(w) => defaults_wifi(api, out, w).await?,
    }
    Ok(ExitCode::SUCCESS)
}

/// The `[[defaults.wifi]]` entry for `mastersos defaults wifi add`, or the refusal. Secrets are not
/// accepted here, the same rule the server applies to AI tokens (`secret_via_web`).
fn wifi_add_body(a: &WifiAdd) -> Result<Value, OpError> {
    let secret = [
        ("--psk", &a.psk),
        ("--password", &a.password),
        ("--client-key", &a.client_key),
        ("--client-key-password", &a.client_key_password),
    ]
    .into_iter()
    .find(|(_, v)| v.is_some());
    if let Some((flag, _)) = secret {
        return Err(OpError::Failed(format!(
            "{flag} is not accepted: Wi-Fi passwords and keys are never typed on the command line or given to AI tools. \
Add the network without it (`--open`, or `--enterprise <method>` which is created without a password), then IT enters the secret on the admin web page. \
A WPA password network is created on the admin web page."
        )));
    }
    let mut m = Map::new();
    m.insert("ssid".into(), json!(a.ssid));
    if a.hidden {
        m.insert("hidden".into(), json!(true));
    }
    match (&a.enterprise, a.open) {
        (Some(eap), _) => {
            let Some(identity) = &a.identity else {
                return Err(OpError::Failed("--enterprise needs --identity".into()));
            };
            m.insert("eap".into(), json!(eap));
            m.insert("identity".into(), json!(identity));
            for (k, v) in [
                ("anonymous_identity", &a.anonymous_identity),
                ("phase2", &a.phase2),
                ("server_domain", &a.server_domain),
            ] {
                if let Some(v) = v {
                    m.insert(k.into(), json!(v));
                }
            }
            if let Some(f) = &a.ca_cert_file {
                let pem = std::fs::read_to_string(f).map_err(|e| {
                    OpError::Failed(format!("Could not read {}: {e}", f.display()))
                })?;
                m.insert("ca_cert".into(), json!(pem));
            }
            if a.no_check_server {
                m.insert("check_server".into(), json!(false));
            }
        }
        (None, true) => {
            m.insert("open".into(), json!(true));
        }
        (None, false) => {
            return Err(OpError::Failed(
                "Say which kind of network: --open or --enterprise <peap|ttls|tls|pwd>. A WPA password network is created on the admin web page (passwords are never typed here).".into(),
            ))
        }
    }
    Ok(Value::Object(m))
}

async fn defaults_wifi(api: &Api, out: &Out, c: WifiCmd) -> Result<(), OpError> {
    // Refuse before any request.
    let add = match &c {
        WifiCmd::Add(a) => Some(wifi_add_body(a)?),
        _ => None,
    };
    // Read the rev first, then [defaults]: the write is refused if anyone changed the draft between.
    // The PUT replaces the whole table (and a legacy [school] wifi), so the table is read whole,
    // changed here and written back whole; an AI token reads secrets as "<kept>", which keeps them.
    let (rev_arg, ssid) = match &c {
        WifiCmd::Remove { rev, ssid } => (*rev, Some(ssid.clone())),
        _ => (None, None),
    };
    let rev = if matches!(c, WifiCmd::List) {
        0
    } else {
        rev_or_current(api, rev_arg).await?
    };
    let text = api.send(Req::get(DEFAULTS)).await?;
    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let mut defaults_tbl = data(&v)["defaults"].clone();
    let Some(sm) = defaults_tbl.as_object_mut() else {
        return Err(OpError::Failed("Could not read [defaults]".into()));
    };
    let mut wifi: Vec<Value> = sm
        .get("wifi")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    match c {
        WifiCmd::List => {
            if out.json {
                println!("{}", json!({ "rev": v["rev"], "data": wifi }));
            } else {
                let rows = wifi.iter().map(wifi_row).collect();
                println!("{}", table(&["SSID", "TYPE", "HIDDEN", "DETAILS"], rows));
                eprintln!("rev {}", cell(&v["rev"]));
            }
            return Ok(());
        }
        WifiCmd::Add(_) => {
            let entry = add.unwrap_or(Value::Null);
            if wifi.iter().any(|w| w["ssid"] == entry["ssid"]) {
                return Err(OpError::Failed(format!(
                    "A Wi-Fi network named {} already exists in [defaults]: remove it first",
                    cell(&entry["ssid"])
                )));
            }
            wifi.push(entry);
        }
        WifiCmd::Remove { .. } => {
            let ssid = ssid.unwrap_or_default();
            let before = wifi.len();
            wifi.retain(|w| w["ssid"] != json!(ssid));
            if wifi.len() == before {
                return Err(OpError::Failed(format!(
                    "No Wi-Fi network named {ssid} in [defaults]"
                )));
            }
        }
    }
    // An empty list is left out: older agents reject the `wifi` key itself.
    if wifi.is_empty() {
        sm.remove("wifi");
    } else {
        sm.insert("wifi".into(), Value::Array(wifi));
    }
    let text = api.send(Req::put_json(DEFAULTS, rev, defaults_tbl)).await?;
    out.wrote(&text, "Changed the Wi-Fi networks in Defaults");
    Ok(())
}

/// One table row for `defaults wifi list`: ssid, kind, hidden, and the other keys as the server
/// gave them (certificates are long, so only their presence shows).
fn wifi_row(w: &Value) -> Vec<String> {
    let kind = if w.get("eap").is_some_and(|x| !x.is_null()) {
        format!("enterprise/{}", cell(&w["eap"]))
    } else if w["open"] == true {
        "open".into()
    } else if w.get("psk").is_some_and(|x| !x.is_null()) {
        "personal".into()
    } else {
        "open (implicit)".into()
    };
    let details = w
        .as_object()
        .map(|m| {
            m.iter()
                .filter(|(k, v)| {
                    !matches!(k.as_str(), "ssid" | "hidden" | "open" | "eap") && !v.is_null()
                })
                .map(|(k, v)| match k.as_str() {
                    "ca_cert" | "client_cert" => format!("{k}=<pem>"),
                    _ => format!("{k}={}", cell(v)),
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    vec![
        cell(&w["ssid"]),
        kind,
        cell(&w["hidden"]).replace('-', "false"),
        details,
    ]
}

async fn spec(api: &Api, section: Option<String>, full: bool) -> Result<ExitCode, OpError> {
    let text = if full {
        let body = api.send(Req::get(&["v1", "spec", "manifest"])).await?;
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        v["text"].as_str().map_or(body, str::to_owned)
    } else {
        let args = match section {
            Some(s) => json!({ "section": s }),
            None => json!({}),
        };
        call(api, "get_manifest_spec", args).await?
    };
    print!("{text}");
    if !text.ends_with('\n') {
        println!();
    }
    Ok(ExitCode::SUCCESS)
}

const NO_REV_WARNING: &str = "Warning: no --rev given, so this replaces the draft as it is now and overwrites any change made since you read it. Pass the rev from your read to be refused (draft_conflict) instead.";

/// The rev to send as If-Match: the one the caller read, else the draft's current rev (the write
/// then applies to the draft as it is now).
async fn rev_or_current(api: &Api, rev: Option<u64>) -> Result<u64, OpError> {
    match rev {
        Some(r) => Ok(r),
        None => draft_rev(api).await,
    }
}

/// How results are printed.
struct Out {
    json: bool,
}

impl Out {
    /// The server's JSON with `--json`, else what `human` makes of it.
    fn print(&self, text: &str, human: impl FnOnce(&Value) -> String) {
        if self.json {
            println!("{text}");
        } else {
            let v: Value = serde_json::from_str(text).unwrap_or(Value::Null);
            println!("{}", human(&v));
        }
    }

    /// The result of a draft write: `{"ok", "rev"}`.
    fn wrote(&self, text: &str, what: &str) {
        self.print(text, |v| {
            format!("{what} in the draft (rev {}).", cell(&v["rev"]))
        });
    }
}

/// A `get_config` / `get_group` / school result as a TOML fragment (`--json`: the JSON itself).
fn show_fragment(out: &Out, text: &str, kind: &str, array: bool) -> Result<(), OpError> {
    if out.json {
        println!("{text}");
        return Ok(());
    }
    let v: Value = serde_json::from_str(text).unwrap_or(Value::Null);
    let d = data(&v);
    print!("{}", toml_fragment(kind, array, &d[kind])?);
    // Pass it to `set --rev`, so a change someone made in between is not overwritten.
    eprintln!("rev {}", cell(&v["rev"]));
    if d["has_inner_comments"] == true {
        eprintln!(
            "Note: the draft has comments inside this table; saving it with `set` drops them."
        );
    }
    Ok(())
}

/// `[[kind]]` (or `[kind]`) with the object's fields, as in the Settings file.
fn toml_fragment(kind: &str, array: bool, v: &Value) -> Result<String, OpError> {
    let value = toml::Value::try_from(strip_nulls(v.clone()))
        .map_err(|e| OpError::Failed(format!("Could not show it as TOML: {e}")))?;
    let mut doc = toml::Table::new();
    doc.insert(
        kind.to_owned(),
        if array {
            toml::Value::Array(vec![value])
        } else {
            value
        },
    );
    toml::to_string(&doc).map_err(|e| OpError::Failed(format!("Could not show it as TOML: {e}")))
}

fn strip_nulls(v: Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.into_iter()
                .filter(|(_, x)| !x.is_null())
                .map(|(k, x)| (k, strip_nulls(x)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.into_iter().map(strip_nulls).collect()),
        other => other,
    }
}

/// A file's text, or stdin for `-`.
fn read_input(arg: &str) -> Result<String, OpError> {
    if arg == "-" {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| OpError::Failed(format!("Could not read stdin: {e}")))?;
        Ok(s)
    } else {
        std::fs::read_to_string(arg)
            .map_err(|e| OpError::Failed(format!("Could not read {arg}: {e}")))
    }
}

/// A config or `[school]` from a file: JSON for `.json` (or stdin starting with `{`), else TOML.
/// A TOML fragment may be wrapped as in the Settings file (`[[config]]`, `[school]`) or be bare keys.
fn read_object(arg: &str, kind: &str) -> Result<Map<String, Value>, OpError> {
    let text = read_input(arg)?;
    let is_json = arg.ends_with(".json") || (arg == "-" && text.trim_start().starts_with('{'));
    let v = if is_json {
        serde_json::from_str(&text)
            .map_err(|e| OpError::Failed(format!("{arg} is not valid JSON: {e}")))?
    } else {
        let t: toml::Table = text
            .parse()
            .map_err(|e| OpError::Failed(format!("{arg} is not valid TOML: {e}")))?;
        toml_to_json(toml::Value::Table(t))
    };
    let v = match v {
        Value::Object(mut m) if m.len() == 1 && m.contains_key(kind) => match m.remove(kind) {
            Some(Value::Array(mut a)) if a.len() == 1 => a.remove(0),
            Some(o @ Value::Object(_)) => o,
            Some(other) => {
                m.insert(kind.to_owned(), other);
                Value::Object(m)
            }
            None => Value::Object(m),
        },
        other => other,
    };
    match v {
        Value::Object(m) => Ok(m),
        _ => Err(OpError::Failed(format!(
            "{arg} does not hold one {kind} table"
        ))),
    }
}

/// TOML to JSON as the forms take it: dates and times become their TOML text.
fn toml_to_json(v: toml::Value) -> Value {
    match v {
        toml::Value::String(s) => Value::String(s),
        toml::Value::Integer(i) => json!(i),
        toml::Value::Float(f) => json!(f),
        toml::Value::Boolean(b) => Value::Bool(b),
        toml::Value::Datetime(d) => Value::String(d.to_string()),
        toml::Value::Array(a) => Value::Array(a.into_iter().map(toml_to_json).collect()),
        toml::Value::Table(t) => {
            Value::Object(t.into_iter().map(|(k, x)| (k, toml_to_json(x))).collect())
        }
    }
}

/// The server's JSON inside a `{"rev", "data"}` wrapper, or the value itself.
fn data(v: &Value) -> &Value {
    match v.get("data") {
        Some(d) if v.get("rev").is_some() => d,
        _ => v,
    }
}

fn items(v: &Value) -> &[Value] {
    data(v).as_array().map_or(&[], Vec::as_slice)
}

fn rows(v: &Value, keys: &[&str]) -> Vec<Vec<String>> {
    items(v)
        .iter()
        .map(|x| keys.iter().map(|k| cell(&x[*k])).collect())
        .collect()
}

/// One value for a table cell or a line.
fn cell(v: &Value) -> String {
    match v {
        Value::Null => "-".into(),
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(cell).collect::<Vec<_>>().join(", "),
        other => other.to_string(),
    }
}

fn table(headers: &[&str], rows: Vec<Vec<String>>) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for r in &rows {
        for (w, c) in widths.iter_mut().zip(r) {
            *w = (*w).max(c.chars().count());
        }
    }
    let line = |cells: Vec<&str>| {
        let mut s = String::new();
        for (i, (c, w)) in cells.iter().zip(&widths).enumerate() {
            if i + 1 == cells.len() {
                s.push_str(c);
            } else {
                s.push_str(c);
                s.push_str(&" ".repeat(w - c.chars().count() + 2));
            }
        }
        s.trim_end().to_owned()
    };
    let mut out = vec![line(headers.to_vec())];
    out.extend(
        rows.iter()
            .map(|r| line(r.iter().map(String::as_str).collect())),
    );
    out.join("\n")
}

fn fail(e: impl std::fmt::Display) -> OpError {
    OpError::Failed(format!("{e:#}"))
}

fn open_dir(dir: Option<&Path>) -> Result<Workdir, OpError> {
    Workdir::open(dir.unwrap_or_else(|| Path::new("."))).map_err(fail)
}

/// `mastersos check`: the lints of the local directory; exit code 2 when any is an error.
fn local_check(dir: Option<&Path>, json: bool) -> Result<ExitCode, OpError> {
    let lints = workdir::check(&open_dir(dir)?).map_err(fail)?;
    let issues: Vec<Value> = lints
        .iter()
        .map(|l| serde_json::to_value(l).unwrap_or(Value::Null))
        .collect();
    if json {
        println!("{}", Value::Array(issues));
    } else {
        print_issues(&issues);
    }
    Ok(if mastersos_bundle::has_errors(&lints) {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

/// `mastersos diff`.
fn local_diff(dir: Option<&Path>) -> Result<ExitCode, OpError> {
    print!("{}", workdir::diff(&open_dir(dir)?).map_err(fail)?);
    Ok(ExitCode::SUCCESS)
}

/// The school id the server says this token belongs to.
async fn school_id(api: &Api) -> Result<String, OpError> {
    let text = api.send(Req::get(&["v1", "auth", "config"])).await?;
    let v: Value = serde_json::from_str(&text).map_err(fail)?;
    v["school_id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| OpError::Failed("the server did not say which school this is".into()))
}

fn sign_api(server: &str, token_file: &Path) -> Result<mastersos_sign::Api, OpError> {
    mastersos_sign::Api::from_token_file(server, token_file).map_err(fail)
}

/// `mastersos init <dir>`.
async fn init_dir(
    api: &Api,
    server: &str,
    token_file: &Path,
    dir: &Path,
) -> Result<ExitCode, OpError> {
    let id = school_id(api).await?;
    let latest = sign_api(server, token_file)?
        .latest_version()
        .await
        .map_err(fail)?;
    if latest > 0 {
        return Err(OpError::Failed(format!(
            "the school already has published settings (version {latest}): use `mastersos pull {}`",
            dir.display()
        )));
    }
    let meta = Meta {
        server: server.to_owned(),
        school_id: id.clone(),
        base_version: 0,
    };
    Workdir::init(dir, meta, &workdir::template(&id).map_err(fail)?).map_err(fail)?;
    println!(
        "Created {} for school {id}. Edit manifest.toml, then run `mastersos check`.",
        dir.display()
    );
    Ok(ExitCode::SUCCESS)
}

/// `mastersos pull`: the chain is verified from the pin first; a given `--version` is then read
/// from its own archive and must have been signed with the keys it lists itself.
async fn pull_dir(
    api: &Api,
    server: &str,
    token_file: &Path,
    dir: &Path,
    version: Option<u64>,
    force: bool,
) -> Result<ExitCode, OpError> {
    let id = school_id(api).await?;
    if let Ok(w) = Workdir::open(dir) {
        let m = w.meta().map_err(fail)?;
        if m.school_id != id || m.server != server {
            return Err(OpError::Failed(format!(
                "{} belongs to school {} on {}, not to {id} on {server}",
                dir.display(),
                m.school_id,
                m.server
            )));
        }
    }
    let sign = sign_api(server, token_file)?;
    let pins = config_dir()?.join("pins");
    let verified = mastersos_sign::chain::verify_chain(
        &sign,
        &pins,
        &mut std::io::stdin().lock(),
        &mut std::io::stdout(),
    )
    .await
    .map_err(fail)?;
    let (n, contents) = match version {
        None => (verified.version, verified.contents),
        Some(n) if n == verified.version => (n, verified.contents),
        Some(n) => {
            if n == 0 || n > verified.latest {
                return Err(OpError::Failed(format!(
                    "version {n} does not exist: the newest published version is {}",
                    verified.latest
                )));
            }
            let archive = sign.version_archive(n).await.map_err(fail)?;
            (n, open_version(&archive, n).map_err(fail)?)
        }
    };
    let meta = Meta {
        server: server.to_owned(),
        school_id: id,
        base_version: n,
    };
    Workdir::write_pulled(dir, meta, &contents, force).map_err(fail)?;
    println!("Pulled version {n} into {}.", dir.display());
    Ok(ExitCode::SUCCESS)
}

/// An old version's contents, after its signature is checked against the keys the version lists.
fn open_version(archive: &[u8], n: u64) -> anyhow::Result<mastersos_bundle::Contents> {
    use anyhow::Context as _;
    let unpacked = mastersos_bundle::read_archive(archive).context("the archive cannot be read")?;
    let sig: mastersos_bundle::SignatureFile =
        toml::from_str(&unpacked.signature_toml).context("the signature file is not valid")?;
    let manifest = mastersos_bundle::Manifest::parse(&unpacked.contents.manifest_text)
        .context("the manifest cannot be read")?;
    mastersos_bundle::verify_signature(
        &mastersos_bundle::signed_message(&unpacked.contents),
        &sig,
        &manifest.trust,
    )
    .context("the signature does not match the keys the version lists")?;
    anyhow::ensure!(
        manifest.version == n,
        "the archive holds version {}, not {n}",
        manifest.version
    );
    Ok(unpacked.contents)
}

/// Issues for people: one per line (level, code, where, message), then a count.
fn print_issues(issues: &[Value]) {
    let mut counts = [0usize; 3];
    for i in issues {
        let level = i["level"].as_str().unwrap_or("info");
        match level {
            "error" => counts[0] += 1,
            "warning" => counts[1] += 1,
            _ => counts[2] += 1,
        }
        let mut place = String::new();
        if let (Some(l), Some(c)) = (i["span"]["line"].as_u64(), i["span"]["column"].as_u64()) {
            place.push_str(&format!("line {l}:{c} "));
        }
        if let Some(p) = i["path"].as_str() {
            place.push_str(p);
        }
        println!(
            "{level:<7} {:<24} {:<28} {}",
            cell(&i["code"]),
            place.trim_end(),
            cell(&i["message"])
        );
    }
    println!(
        "{} error(s), {} warning(s), {} note(s)",
        counts[0], counts[1], counts[2]
    );
}
