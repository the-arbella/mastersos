//! The recovery kit on the command line (plan 6 design §5.2, ruling 10): `kit new`, `--kit` for
//! `sign` / `heartbeat` / `register` (which registers the kit's escrow recipient too), and
//! `escrow-read`.
//!
//! The kit text is the school's master secret: it is written only to a 0600 file that did not
//! exist, read from such a file or from stdin, and never printed, logged or put in an error.
//! Before a kit signs or opens anything, the server must list it as a registered recovery key
//! ([`ensure_registered`]): that catches another school's kit or a spare that was never
//! registered. It is a guard against mistakes, not against a lying server: what machines accept
//! is still decided by the locally verified chain.

use std::io::{BufRead, Read as _, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};
use mastersos_bundle::kit::Kit;
use mastersos_bundle::{is_recovery_key, trust_fingerprint, TrustKey};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{safe, write_secret, Api};

/// Longest kit file or stdin line read; a kit text is 69 characters, 87 when grouped.
const KIT_INPUT_MAX: u64 = 1024;
/// Largest sealed row opened; the server keeps them at most 2 KiB.
const SEALED_MAX: usize = 8 * 1024;

/// What `kit new` may print: the kit's public parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KitSummary {
    pub key_id: String,
    pub fingerprint: String,
    /// The escrow recipient (`age1…`).
    pub recipient: String,
}

impl KitSummary {
    pub fn of(kit: &Kit) -> KitSummary {
        KitSummary {
            key_id: kit.key_id(),
            fingerprint: trust_fingerprint(&kit.trust_key()),
            recipient: kit.escrow_recipient(),
        }
    }
}

/// Generate a kit offline and write its text to `out` (0600; an existing file is refused).
pub fn kit_new(out: &Path) -> Result<KitSummary> {
    kit_new_in(out, None).map(|(summary, _)| summary)
}

/// The file name `kit new` gives a school key written into a directory:
/// `<slug>-school-key-<code8>.kit`, or `school-key-<code8>.kit` without a usable school name.
/// `<code8>` is the key code without its dash.
pub fn school_key_file_name(school: Option<&str>, key_id: &str) -> String {
    let code8 = mastersos_bundle::keyid::key_code(key_id)
        .unwrap_or_default()
        .replace('-', "");
    let slug: String = school
        .unwrap_or("")
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if slug.is_empty() {
        format!("school-key-{code8}.kit")
    } else {
        format!("{slug}-school-key-{code8}.kit")
    }
}

/// `kit new --out <FILE|DIR> [--school <slug>]`: when `out` is an existing directory the file is
/// named by [`school_key_file_name`]. Returns the summary and the path written.
pub fn kit_new_in(out: &Path, school: Option<&str>) -> Result<(KitSummary, std::path::PathBuf)> {
    let kit = Kit::generate();
    let path = if out.is_dir() {
        out.join(school_key_file_name(school, &kit.key_id()))
    } else {
        out.to_path_buf()
    };
    let mut text = kit.to_display();
    text.push('\n');
    write_secret(&path, text.as_bytes())?;
    Ok((KitSummary::of(&kit), path))
}

fn parse(text: &str, from: &str) -> Result<Kit> {
    Kit::parse(text).with_context(|| format!("cannot read the school key from {from}"))
}

/// Read a school key (kit) file. Another owner is refused; access by other users only gets
/// [`crate::platform::KEY_FILE_NOTE`] on stderr (a USB stick cannot keep a file private).
pub fn load_kit(path: &Path) -> Result<Kit> {
    let (f, note) = crate::platform::open_school_key(path)?;
    if let Some(note) = note {
        eprintln!("{}: {note}", path.display());
    }
    // Sized for the whole bounded read, so the buffer never reallocates while holding the kit.
    let mut text = Zeroizing::new(String::with_capacity(KIT_INPUT_MAX as usize + 1));
    f.take(KIT_INPUT_MAX)
        .read_to_string(&mut text)
        .with_context(|| format!("cannot read {}", path.display()))?;
    parse(&text, &path.display().to_string())
}

/// Read a kit from the first line of `input` (`--kit -`); later lines stay for the prompts.
pub fn read_kit(input: &mut dyn BufRead) -> Result<Kit> {
    let mut line = Zeroizing::new(String::with_capacity(KIT_INPUT_MAX as usize + 1));
    input
        .take(KIT_INPUT_MAX)
        .read_line(&mut line)
        .context("cannot read the school key from stdin")?;
    if line.trim().is_empty() {
        bail!("no school key on stdin");
    }
    parse(&line, "stdin")
}

/// The server must list `tk` as a registered recovery key with the same fingerprint.
pub async fn ensure_registered(api: &Api, tk: &TrustKey) -> Result<()> {
    #[derive(Deserialize)]
    struct Listed {
        key_id: String,
        kind: String,
        fingerprint: String,
    }
    let keys: Vec<Listed> = api
        .get_json(&["v1", "admin", "signing-keys"], "list the signing keys")
        .await?;
    let fp = trust_fingerprint(tk);
    if !keys
        .iter()
        .any(|k| k.kind == "recovery" && k.key_id == tk.id && k.fingerprint == fp)
    {
        bail!("this school key is not registered with {}", api.host());
    }
    Ok(())
}

/// Whether `e` is the server's `key_exists` (the key or recipient is registered already), read
/// from the structured error ([`crate::ServerError`]), not its text.
pub fn is_already_registered(e: &anyhow::Error) -> bool {
    crate::server_error_code(e) == Some("key_exists")
}

/// Register the kit's escrow recipient (`POST /v1/admin/escrow-recipients`, `keys` scope), bound
/// to the kit's recovery key: the kit signs the binding message over a fresh probe nonce of this
/// school, built locally from the nonce (the server's `message_b64` is never signed). A
/// recipient registered already is reported and left as it is.
pub async fn register_escrow_recipient(
    api: &Api,
    kit: &Kit,
    label: &str,
    out: &mut dyn Write,
) -> Result<()> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use mastersos_bundle::Signer as _;

    #[derive(Deserialize)]
    struct Probe {
        nonce_b64: String,
    }
    #[derive(Deserialize)]
    struct Registered {
        recipient: String,
        bound_key_id: String,
    }
    let recipient = kit.escrow_recipient();
    let probe: Probe = api
        .post_json(
            &["v1", "admin", "signing-keys", "probe"],
            None,
            "get a probe for the escrow recipient",
        )
        .await?;
    let nonce = STANDARD
        .decode(&probe.nonce_b64)
        .context("the probe nonce is not base64")?;
    if nonce.len() != 32 {
        bail!(
            "the probe nonce should be 32 bytes, the server gave {}",
            nonce.len()
        );
    }
    let msg = mastersos_bundle::kit::recipient_binding_message(&recipient, &nonce);
    let body = serde_json::json!({
        "recipient": recipient,
        "bound_key_id": kit.key_id(),
        "nonce_b64": probe.nonce_b64,
        "sig_b64": STANDARD.encode(kit.signer().sign(&msg)),
        "label": label,
    });
    let r: Registered = match api
        .post_json(
            &["v1", "admin", "escrow-recipients"],
            Some(&body),
            "register the escrow recipient",
        )
        .await
    {
        Ok(r) => r,
        Err(e) if is_already_registered(&e) => {
            writeln!(
                out,
                "Disk unlocking for school key {} is already registered.",
                code_of(kit)
            )?;
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    if r.recipient != recipient || r.bound_key_id != kit.key_id() {
        bail!(
            "the server registered {} bound to {}, not {recipient} bound to {}",
            safe::field(&r.recipient),
            safe::field(&r.bound_key_id),
            kit.key_id()
        );
    }
    writeln!(
        out,
        "Disk unlocking registered for school key {}.",
        code_of(kit)
    )?;
    Ok(())
}

/// The key code of `kit` (its key id where there is none).
fn code_of(kit: &Kit) -> String {
    mastersos_bundle::keyid::key_code(&kit.key_id()).unwrap_or_else(|| kit.key_id())
}

/// One escrowed row as `GET …/recovery-keys` lists it. Only the sealed form is opened.
#[derive(Deserialize)]
struct Row {
    luks_uuid: String,
    received_at: String,
    #[serde(default)]
    serial: Option<String>,
    #[serde(default)]
    first_for_luks: Option<bool>,
    #[serde(default)]
    recipients_fp: Option<String>,
    #[serde(default)]
    recovery_key_age: Option<String>,
}

/// Fetch a machine's escrowed rows and open the sealed ones locally with the kit's escrow
/// identity; prints one line per row and returns how many were opened. Needs a token with
/// `read` and `recovery`; every read leaves an audit row on the server.
pub async fn escrow_read(
    api: &Api,
    kit: &Kit,
    device_id: &str,
    out: &mut dyn Write,
) -> Result<usize> {
    ensure_registered(api, &kit.trust_key()).await?;
    let mut out = safe::SafeWriter::new(out);
    let out: &mut dyn Write = &mut out;
    let rows: Vec<Row> = api
        .get_json(
            &["v1", "admin", "devices", device_id, "recovery-keys"],
            "fetch the escrowed recovery keys",
        )
        .await?;
    if rows.is_empty() {
        writeln!(
            out,
            "No recovery keys escrowed for {}.",
            safe::field(device_id)
        )?;
        return Ok(0);
    }
    let identity = kit.escrow_identity();
    let mut opened = 0;
    for r in &rows {
        let head = format!(
            "{}  {}  serial={}",
            safe::field(&r.luks_uuid),
            safe::field(&r.received_at),
            r.serial.as_deref().map_or("-".to_owned(), safe::field)
        );
        let suspicious = if r.first_for_luks == Some(false) {
            "  (not the first row for this partition: suspicious)"
        } else {
            ""
        };
        let Some(sealed) = &r.recovery_key_age else {
            writeln!(out, "{head}  not sealed: skipped{suspicious}")?;
            continue;
        };
        let fp = r
            .recipients_fp
            .as_deref()
            .map_or("-".to_owned(), safe::field);
        if sealed.len() > SEALED_MAX {
            writeln!(out, "{head}  sealed row too large: skipped{suspicious}")?;
            continue;
        }
        match age::decrypt(&identity, sealed.as_bytes()) {
            Ok(plain) => {
                let plain = Zeroizing::new(plain);
                match std::str::from_utf8(&plain) {
                    Ok(key) if is_recovery_key(key) => {
                        writeln!(out, "{head}  {key}{suspicious}")?;
                        opened += 1;
                    }
                    _ => writeln!(
                        out,
                        "{head}  opened, but it is not a recovery key: skipped{suspicious}"
                    )?,
                }
            }
            Err(_) => writeln!(
                out,
                "{head}  not sealed to this school key (recipients {fp}){suspicious}"
            )?,
        }
    }
    Ok(opened)
}

#[cfg(test)]
mod name_tests {
    use super::*;

    #[test]
    fn file_name_uses_slug_and_key_code() {
        assert_eq!(
            school_key_file_name(Some("Alpha School!"), "rk-11d903eb"),
            "alpha-school-school-key-11d903eb.kit"
        );
        assert_eq!(
            school_key_file_name(None, "rk-11d903eb"),
            "school-key-11d903eb.kit"
        );
        assert_eq!(
            school_key_file_name(Some("  ?? "), "rk-11d903eb"),
            "school-key-11d903eb.kit"
        );
    }

    #[test]
    fn new_in_a_directory_names_the_file_and_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let (s, path) = kit_new_in(dir.path(), Some("alpha")).unwrap();
        let code8 = mastersos_bundle::keyid::key_code(&s.key_id)
            .unwrap()
            .replace('-', "");
        assert_eq!(
            path,
            dir.path().join(format!("alpha-school-key-{code8}.kit"))
        );
        assert!(path.is_file());
        // A file path is used as given, and an existing file is refused.
        let own = dir.path().join("own.kit");
        let (_, p2) = kit_new_in(&own, None).unwrap();
        assert_eq!(p2, own);
        assert!(kit_new_in(&own, None).is_err());
    }
}
