//! The `mastersos-sign` command line: argument parsing only; the logic is in the library.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use mastersos_bundle::kit::Kit;
use mastersos_sign::kit::{
    escrow_read, is_already_registered, kit_new_in, load_kit, read_kit, register_escrow_recipient,
};
use mastersos_sign::{
    chain, keygen, register, restore_from_paper, seed_check, sign_heartbeat, sign_pending, Api,
    SigningKey,
};

#[derive(Parser)]
#[command(
    name = "mastersos-sign",
    version,
    about = "MastersOS school key: create it, register it, and approve settings on this computer after checking the whole history locally"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args)]
struct Server {
    /// Admin server address, for example https://mastersos.school.ac.th
    #[arg(long)]
    server: String,
    /// File holding the token (a token is never accepted on the command line). `sign`, `heartbeat`,
    /// `seed-check` and `verify` need read + draft. `register` takes a key token from the admin
    /// site's Tokens page (valid 60 minutes); `escrow-read` takes a recovery token from the same
    /// page (valid 60 minutes).
    #[arg(long)]
    token_file: PathBuf,
}

impl Server {
    fn api(&self) -> Result<Api> {
        Api::from_token_file(&self.server, &self.token_file)
    }
}

#[derive(Args)]
struct PinDir {
    /// Where the pins are kept (default: ~/.config/mastersos-sign/; Windows: %APPDATA%\mastersos-sign\)
    #[arg(long)]
    pin_dir: Option<PathBuf>,
}

impl PinDir {
    fn get(&self) -> Result<PathBuf> {
        if let Some(d) = &self.pin_dir {
            return Ok(d.clone());
        }
        mastersos_sign::platform::config_dir("mastersos-sign")
            .context("give the pin directory with --pin-dir")
    }
}

/// The signing key: the school key file (or, hidden, a PKCS#8 key file); exactly one.
#[derive(Args)]
#[group(multiple = false)]
struct KeyArg {
    /// A PKCS#8 key file (kept for old scripts)
    #[arg(long, hide = true)]
    key: Option<PathBuf>,
    /// The school key file (keep it on a USB stick; only you should be able to read it), or `-` to read it from the first line of stdin
    #[arg(long = "school-key", alias = "kit", value_name = "FILE")]
    school_key: Option<PathBuf>,
}

/// A loaded `--key` / `--school-key`.
enum Loaded {
    File(PathBuf),
    Kit(Kit),
}

impl Loaded {
    fn signing(&self) -> SigningKey<'_> {
        match self {
            Loaded::File(p) => SigningKey::File(p),
            Loaded::Kit(k) => SigningKey::Kit(k),
        }
    }
}

/// A school key file, or `-` for the first line of stdin.
fn kit_arg(p: &Path, stdin: &std::io::Stdin) -> Result<Kit> {
    if p.as_os_str() == "-" {
        read_kit(&mut stdin.lock())
    } else {
        load_kit(p)
    }
}

/// Read `--school-key`; `--key` stays a path.
fn load_key_arg(k: KeyArg, stdin: &std::io::Stdin) -> Result<Loaded> {
    match (k.key, k.school_key) {
        (Some(p), None) => Ok(Loaded::File(p)),
        (None, Some(p)) => Ok(Loaded::Kit(kit_arg(&p, stdin)?)),
        (None, None) => anyhow::bail!("--school-key <FILE> is required"),
        _ => anyhow::bail!("Give --school-key once."),
    }
}

#[derive(Subcommand)]
enum KitCmd {
    /// Create a school key on this computer, without the network. It is never written over an
    /// existing file. Prints only its key code and fingerprint.
    New {
        /// The file to write, or an existing directory (the file is then named
        /// `<school>-school-key-<key code>.kit`)
        #[arg(long)]
        out: PathBuf,
        /// A short school name for the file name, such as `alpha`
        #[arg(long)]
        school: Option<String>,
    },
}

#[derive(Subcommand)]
enum Cmd {
    /// The school key file
    #[command(subcommand, name = "school-key", alias = "kit")]
    Kit(KitCmd),
    /// Unlock a computer's disk: open its stored recovery keys on this computer with the school
    /// key (--token-file holds a recovery token from the admin site's Tokens page, valid 60 minutes; every read is recorded)
    EscrowRead {
        #[command(flatten)]
        server: Server,
        /// The school key file (keep it on a USB stick; only you should be able to read it), or `-` for stdin
        #[arg(long = "school-key", alias = "kit", value_name = "FILE")]
        school_key: PathBuf,
        /// The computer's device_id
        #[arg(long)]
        device: String,
    },
    /// Create an old-style PKCS#8 key with a paper copy (kept for old scripts)
    #[command(hide = true)]
    Keygen {
        #[arg(long)]
        out: PathBuf,
        /// The paper copy file (default: <out>.paper.txt)
        #[arg(long)]
        paper: Option<PathBuf>,
    },
    /// Restore an old-style PKCS#8 key from its paper copy (kept for old scripts)
    #[command(hide = true)]
    RestoreFromPaper {
        /// The text file copied from the paper copy
        #[arg(long)]
        paper: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Register the school key with the server (--token-file holds a key token from the admin site's Tokens page, valid 60 minutes)
    Register {
        #[command(flatten)]
        server: Server,
        #[command(flatten)]
        key: KeyArg,
        /// A name people will recognise
        #[arg(long)]
        label: String,
    },
    /// Check every published version on this computer (the first time, you confirm the key fingerprints)
    Verify {
        #[command(flatten)]
        server: Server,
        #[command(flatten)]
        pin_dir: PinDir,
    },
    /// Check the history and the changes on this computer, then approve the upload with the school key
    Sign {
        #[command(flatten)]
        server: Server,
        #[command(flatten)]
        pin_dir: PinDir,
        #[command(flatten)]
        key: KeyArg,
        /// The pending bundle's id (printed by `mastersos publish`)
        #[arg(long)]
        pending: String,
    },
    /// Monthly check-in: confirm to every computer that the latest settings are current
    Heartbeat {
        #[command(flatten)]
        server: Server,
        #[command(flatten)]
        pin_dir: PinDir,
        #[command(flatten)]
        key: KeyArg,
        /// How many days the check-in lasts, 1 to 31
        #[arg(long, default_value_t = 30)]
        days: i64,
    },
    /// Compare an install file with the keys and version verified on this computer
    SeedCheck {
        #[command(flatten)]
        server: Server,
        #[command(flatten)]
        pin_dir: PinDir,
        /// The install file
        seed: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    if let Err(e) = run(Cli::parse()).await {
        // An error may hold strings from the server: escape them as well.
        eprintln!("Error: {}", mastersos_sign::safe::text(&format!("{e:#}")));
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    match cli.cmd {
        Cmd::Kit(KitCmd::New {
            out: out_arg,
            school,
        }) => {
            let (k, path) = kit_new_in(&out_arg, school.as_deref())?;
            println!(
                "key code:    {}",
                mastersos_bundle::keyid::key_code(&k.key_id).unwrap_or(k.key_id)
            );
            println!("fingerprint: {}", k.fingerprint);
            let shown = std::path::absolute(&path).unwrap_or(path);
            println!("school key:  {}", shown.display());
            println!(
                "Print the school key file on paper and lock the printout away, register it with \
                 `mastersos-sign register --school-key <file>`, then move the file to a USB stick \
                 and delete it from this computer."
            );
        }
        Cmd::EscrowRead {
            server,
            school_key,
            device,
        } => {
            let kit = kit_arg(&school_key, &stdin)?;
            let n = escrow_read(&server.api()?, &kit, &device, &mut out).await?;
            println!("{n} recovery key(s) opened.");
        }
        Cmd::Keygen { out: key, paper } => {
            let paper_path = paper.unwrap_or_else(|| {
                let mut p = key.clone().into_os_string();
                p.push(".paper.txt");
                PathBuf::from(p)
            });
            let k = keygen(&key)?;
            if let Err(e) = mastersos_sign::write_paper(&paper_path, &k.paper) {
                let _ = std::fs::remove_file(&key);
                return Err(e);
            }
            println!("key id:       {}", k.trust_key.id);
            println!(
                "fingerprint: {}",
                mastersos_bundle::trust_fingerprint(&k.trust_key)
            );
            println!("public key:  {}", k.trust_key.public_key);
            println!("private key: {} (owner only)", key.display());
            println!(
                "paper copy:  {} (owner only; it holds the private key). Print it, lock the printout away, then delete this file.",
                paper_path.display()
            );
            println!(
                "After registering, delete {}. To sign, restore it for a moment with `mastersos-sign restore-from-paper` and delete it again.",
                key.display()
            );
        }
        Cmd::RestoreFromPaper { paper, out: key } => {
            let text = std::fs::read_to_string(&paper)
                .with_context(|| format!("Could not read {}", paper.display()))?;
            let k = restore_from_paper(&text, &key)?;
            println!("Restored to {} (owner only)", key.display());
            println!("key id:      {}", k.id);
            println!("fingerprint: {}", mastersos_bundle::trust_fingerprint(&k));
            println!(
                "Check that they match the paper copy; delete {} as soon as you have signed.",
                key.display()
            );
        }
        Cmd::Register { server, key, label } => {
            let key = load_key_arg(key, &stdin)?;
            let api = server.api()?;
            match (register(&api, key.signing(), &label).await, &key) {
                (Ok(id), _) => match mastersos_bundle::keyid::key_code(&id) {
                    Some(code) => println!("Registered school key {code} ({id})."),
                    None => println!("Registered key {id}."),
                },
                // A kit registered before (say the recipient step failed): go on to the
                // recipient.
                (Err(e), Loaded::Kit(kit)) if is_already_registered(&e) => {
                    println!(
                        "School key {} is already registered.",
                        mastersos_bundle::keyid::key_code(&kit.key_id())
                            .unwrap_or_else(|| kit.key_id())
                    )
                }
                (Err(e), _) => return Err(e),
            }
            if let Loaded::Kit(kit) = &key {
                register_escrow_recipient(&api, kit, &label, &mut out).await?;
            }
            println!("When done, ask the operator to delete this keys token (mastersos-server cloud school token delete).");
        }
        Cmd::Verify { server, pin_dir } => {
            let v =
                chain::verify_chain(&server.api()?, &pin_dir.get()?, &mut stdin.lock(), &mut out)
                    .await?;
            if v.latest != v.version {
                println!(
                    "Verified up to version {}; computers accept up to version {}. Its trusted keys:",
                    v.latest, v.version
                );
            } else {
                println!("Verified up to version {}. Trusted keys:", v.version);
            }
            for k in &v.trust {
                println!("    {}", mastersos_sign::key_line(k));
            }
        }
        Cmd::Sign {
            server,
            pin_dir,
            key,
            pending,
        } => {
            let key = load_key_arg(key, &stdin)?;
            let v = sign_pending(
                &server.api()?,
                key.signing(),
                &pin_dir.get()?,
                &pending,
                &mut stdin.lock(),
                &mut out,
            )
            .await?;
            println!("Published version {v}");
        }
        Cmd::Heartbeat {
            server,
            pin_dir,
            key,
            days,
        } => {
            let key = load_key_arg(key, &stdin)?;
            sign_heartbeat(
                &server.api()?,
                key.signing(),
                &pin_dir.get()?,
                days,
                &mut stdin.lock(),
                &mut out,
            )
            .await?;
        }
        Cmd::SeedCheck {
            server,
            pin_dir,
            seed,
        } => {
            let text = std::fs::read_to_string(&seed)
                .with_context(|| format!("Could not read {}", seed.display()))?;
            seed_check(&server.api()?, &pin_dir.get()?, &text, &mut out).await?;
        }
    }
    Ok(())
}
