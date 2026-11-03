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

use crate::workdir::{self, Meta, Workdir};
use crate::{call, check_server, connect, serve_stdio, Api, OpError, Req};

const EXIT_CODES: &str = "Exit codes: 0 success; 1 failure (network, token, the server refused); \
2 `check` or `publish` found errors in the local settings.";

#[derive(Parser)]
#[command(
    name = "mastersos",
    version,
    about = "MastersOS admin command line: edit a school's settings in a local directory (pull, edit manifest.toml, check, diff) and publish them; inspect Devices.",
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
    /// Print the server's JSON instead of tables: for scripts and AI
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
    /// The Settings reference (Markdown): the short version, one section, or all of it
    Spec {
        /// One section: an issue code (icon_invalid), a table name (config, group, config.apps.web, school.oidc) or top-level
        #[arg(long)]
        section: Option<String>,
        /// The whole reference (long)
        #[arg(long, conflicts_with = "section")]
        full: bool,
    },
    /// Publish the local settings directory: check, fill in secrets, stamp, upload, then sign with --key or print the signing page link
    Publish {
        /// The settings directory (default: the current directory)
        dir: Option<PathBuf>,
        /// A recovery key file: verify and sign on this computer (without it, IT signs on the signing page with a Passkey)
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// The signing keys the server knows
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
    /// List the keys: id, algorithm, label
    List,
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
        _ => {}
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
    if let Cmd::Mcp { dir } = &cmd {
        let dir = dir.clone().unwrap_or_else(|| PathBuf::from("."));
        Workdir::open(&dir).map_err(fail)?;
        // The MCP server keeps its own exit codes: 2 for a token that must not be given to an AI.
        let api = match connect(&server, &token_file).await {
            Ok(api) => api,
            Err(e) => {
                eprintln!("mastersos: {e}");
                return Ok(ExitCode::from(e.exit_code()));
            }
        };
        serve_stdio(api, dir)
            .await
            .map_err(|e| OpError::Failed(format!("{e:#}")))?;
        return Ok(ExitCode::SUCCESS);
    }
    let api = connect(&server, &token_file)
        .await
        .map_err(|e| OpError::Failed(e.to_string()))?;
    let out = Out { json };
    match cmd {
        Cmd::Setup | Cmd::Mcp { .. } | Cmd::Check { .. } | Cmd::Diff { .. } => {
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
        Cmd::Spec { section, full } => spec(&api, section, full).await,
        Cmd::Publish { dir, key } => {
            publish_dir(&api, &server, &token_file, dir.as_deref(), key.as_deref()).await
        }
        Cmd::Keys(KeysCmd::List) => {
            let text = api.send(Req::get(&["v1", "admin", "keys"])).await?;
            out.print(&text, |v| {
                table(
                    &["ID", "ALGORITHM", "LABEL"],
                    rows(v, &["id", "alg", "label"]),
                )
            });
            Ok(ExitCode::SUCCESS)
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
    let who: Value = serde_json::from_str(&api.send(Req::get(&["v1", "admin", "whoami"])).await?)
        .unwrap_or(Value::Null);
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
fn prompt_secret(text: &str) -> Result<String, OpError> {
    use rustix::termios::{tcgetattr, tcsetattr, LocalModes, OptionalActions};
    use std::io::{BufRead as _, Write as _};
    eprint!("{text}");
    std::io::stderr().flush().ok();
    let stdin = std::io::stdin();
    let saved = tcgetattr(&stdin).map_err(|_| {
        OpError::Failed("stdin is not a terminal, so a password cannot be read safely".into())
    })?;
    let mut quiet = saved.clone();
    quiet.local_modes.remove(LocalModes::ECHO);
    tcsetattr(&stdin, OptionalActions::Flush, &quiet).map_err(fail)?;
    let mut line = String::new();
    let read = stdin.lock().read_line(&mut line);
    // Echo comes back whether or not the read worked.
    let restored = tcsetattr(&stdin, OptionalActions::Flush, &saved);
    eprintln!();
    restored.map_err(fail)?;
    if read.map_err(fail)? == 0 {
        return Err(OpError::Failed("input closed".into()));
    }
    Ok(line.trim_end_matches(['\n', '\r']).to_owned())
}

/// `mastersos publish`.
async fn publish_dir(
    api: &Api,
    server: &str,
    token_file: &Path,
    dir: Option<&Path>,
    key: Option<&Path>,
) -> Result<ExitCode, OpError> {
    use crate::publish::{publish, CheckFailed, PublishOutcome, SignOpts};
    let w = open_dir(dir)?;
    let m = w.meta().map_err(fail)?;
    if m.server != server {
        return Err(OpError::Failed(format!(
            "{} belongs to {}, not to {server}",
            w.root.display(),
            m.server
        )));
    }
    let pins = config_dir()?.join("pins");
    let sign = key.map(|key| SignOpts {
        key,
        token_file,
        pin_dir: &pins,
    });
    let r = publish(
        api,
        &w,
        sign,
        chrono::Utc::now(),
        &mut std::io::stdin().lock(),
        &mut std::io::stdout(),
    )
    .await;
    match r {
        Ok(PublishOutcome::Published(v)) => {
            println!(
                "Published version {v}. {} is now based on it.",
                w.root.display()
            );
            Ok(ExitCode::SUCCESS)
        }
        Ok(PublishOutcome::NeedsPasskey { url, pending_id }) => {
            println!("Uploaded pending bundle {pending_id}. Nothing is published yet: IT signs it with a Passkey at\n{url}");
            println!("After signing in the browser, run `mastersos pull` to update your base.");
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => match e.downcast::<CheckFailed>() {
            Ok(c) => {
                let issues: Vec<Value> =
                    c.0.iter()
                        .map(|l| serde_json::to_value(l).unwrap_or(Value::Null))
                        .collect();
                Err(OpError::Refused {
                    message: c.to_string(),
                    issues: Some(issues),
                })
            }
            Err(e) => Err(fail(e)),
        },
    }
}
