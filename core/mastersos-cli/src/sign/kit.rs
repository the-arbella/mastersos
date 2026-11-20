//! The school key (recovery kit) on the command line (plan 6 design §5.2, ruling 10): `key new`,
//! `--key-file` for `publish`, `heartbeat` and `key register` (which registers the kit's escrow
//! recipient too), and `recovery read`.
//!
//! The kit text is the school's master secret: it is written only to a 0600 file that did not
//! exist, read from such a file or from stdin, and never printed, logged or put in an error.
//! Before a kit signs or opens anything, the server must list it as a registered recovery key
//! (`ensure_keys_registered` in the command line): that catches another school's kit or a spare
//! that was never registered. It is a guard against mistakes, not against a lying server: what machines accept
//! is still decided by the locally verified chain.

use std::io::{BufRead, Read as _, Write as _};
use std::path::Path;

use anyhow::{bail, Context, Result};
use mastersos_bundle::kit::Kit;
use mastersos_bundle::{is_recovery_key, trust_fingerprint};
use serde::Deserialize;
use zeroize::Zeroizing;

use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::safe;
use crate::server::{segment, CliError, Server};

/// Longest kit file or stdin line read; a kit text is 69 characters, 87 when grouped.
const KIT_INPUT_MAX: u64 = 1024;
/// Largest sealed row opened; the server keeps them at most 2 KiB.
const SEALED_MAX: usize = 8 * 1024;

/// What `key new` may print: the kit's public parts.
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

/// The file name `key new` gives a school key written into a directory:
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

/// `key new --out <FILE|DIR> [--school <slug>]`: when `out` is an existing directory the file is
/// named by [`school_key_file_name`]. Returns the summary and the path written.
pub fn kit_new_in(out: &Path, school: Option<&str>) -> Result<(KitSummary, std::path::PathBuf)> {
    let kit = Kit::generate();
    let path = if out.is_dir() {
        out.join(school_key_file_name(school, &kit.key_id()))
    } else {
        out.to_path_buf()
    };
    // The folder must be ours (another account could swap files in it); the file itself is made
    // by create_private: new, owner-only, and never through a link.
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    crate::platform::check_dir_owner(parent)?;
    let mut text = kit.to_display();
    text.push('\n');
    write_new_private(&path, text.as_bytes())?;
    Ok((KitSummary::of(&kit), path))
}

/// Write the school key to a new owner-only file ([`crate::platform::create_private`]); an
/// existing file is refused, and a half-written one removed.
fn write_new_private(path: &Path, data: &[u8]) -> Result<()> {
    let mut f = crate::platform::create_private(path)?;
    let written = f.write_all(data).and_then(|()| f.sync_all());
    if let Err(e) = written {
        drop(f);
        let _ = std::fs::remove_file(path);
        bail!("cannot write {}: {e}", path.display());
    }
    Ok(())
}

/// A key file that is a PEM file (an old PKCS#8 key) is refused by name, before it is parsed.
fn parse(text: &str, from: &str) -> Result<Kit> {
    if text.trim_start().starts_with("-----BEGIN") {
        bail!("{from} is a PEM key, not a school key file; school keys are made with mastersos key new");
    }
    Kit::parse(text).with_context(|| format!("cannot read the school key from {from}"))
}

/// Read a school key (kit) file. Another owner is refused; access by other users only gets
/// [`crate::platform::KEY_FILE_NOTE`] on stderr (a USB stick cannot keep a file private).
pub fn load_kit(path: &Path) -> Result<Kit> {
    let (f, note) = crate::platform::open_school_key(path)?;
    if let Some(note) = note {
        let shown = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
        eprintln!("{}: {note}", shown.display());
    }
    // Sized for the whole bounded read, so the buffer never reallocates while holding the kit.
    let mut text = Zeroizing::new(String::with_capacity(KIT_INPUT_MAX as usize + 1));
    f.take(KIT_INPUT_MAX)
        .read_to_string(&mut text)
        .with_context(|| format!("cannot read {}", path.display()))?;
    parse(&text, &path.display().to_string())
}

/// A `--key-file`: a school key file, or `-` for the first line of stdin (later lines stay for
/// the prompts).
pub fn load_key_file(path: &Path) -> Result<Kit> {
    if path.as_os_str() == "-" {
        read_kit(&mut std::io::stdin().lock())
    } else {
        load_kit(path)
    }
}

/// Read a kit from the first line of `input` (`--key-file -`); later lines stay for the prompts.
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

/// What `key register` did, for the person and for `--json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    pub key_id: String,
    pub fingerprint: String,
    /// The server had the key already (`409 key_exists`).
    pub key_already: bool,
    pub recipient: String,
    /// The server had the recipient already (`409 recipient_exists`).
    pub recipient_already: bool,
}

fn invalid_answer(what: &str) -> CliError {
    CliError::new("invalid_answer", what)
}

/// The label as the server counts it: trimmed, 1 to 64 characters.
fn checked_label(label: &str) -> Result<&str, CliError> {
    let l = mastersos_bundle::keyid::trim_label(label);
    if l.is_empty() || l.chars().count() > 64 {
        return Err(CliError::usage("the label must be 1 to 64 characters"));
    }
    Ok(l)
}

/// `POST keys/probe`: a nonce of 32 bytes (std-pad base64, strict), and the server's message
/// equal to `"mastersos-keyprobe-v1\n" || nonce` computed here. Nothing is signed or posted
/// when either differs. Returns the nonce text as sent and the nonce bytes.
async fn probe(server: &Server) -> Result<(String, Vec<u8>), CliError> {
    #[derive(Deserialize)]
    struct Probe {
        nonce_b64: String,
        message_b64: String,
    }
    let p: Probe = server.post_empty("keys/probe").await?;
    let nonce = probe_nonce(&p.nonce_b64, &p.message_b64)?;
    Ok((p.nonce_b64, nonce))
}

/// The nonce of a probe answer: `nonce_b64` strict std-pad of 32 bytes, and `message_b64`
/// exactly the std-pad of `"mastersos-keyprobe-v1\n" || nonce` computed here.
fn probe_nonce(nonce_b64: &str, message_b64: &str) -> Result<Vec<u8>, CliError> {
    let nonce = STANDARD
        .decode(nonce_b64)
        .map_err(|_| invalid_answer("the probe nonce is not standard base64"))?;
    if nonce.len() != 32 {
        return Err(invalid_answer("the probe nonce is not 32 bytes"));
    }
    if STANDARD.encode(mastersos_bundle::keyid::keyprobe_message(&nonce)) != message_b64 {
        return Err(invalid_answer(
            "the probe message is not the one this computer expects; nothing was signed",
        ));
    }
    Ok(nonce)
}

/// `key register`: the school key (`POST keys/probe`, `POST keys`), then the escrow recipient
/// bound to it with a fresh probe (`POST escrow-recipients`). Both messages are built here from
/// the nonce; the server's `message_b64` is only compared. A key or recipient that is registered
/// already is reported and left as it is.
pub async fn register(server: &Server, kit: &Kit, label: &str) -> Result<Registered, CliError> {
    use mastersos_bundle::Signer as _;
    let label = checked_label(label)?;
    let tk = kit.trust_key();
    let fingerprint = trust_fingerprint(&tk);
    let recipient = kit.escrow_recipient();
    if recipient.len() != 62
        || !recipient.starts_with("age1")
        || recipient != recipient.to_lowercase()
    {
        return Err(CliError::new(
            "local_file",
            "the school key gives no canonical disk-unlocking recipient",
        ));
    }

    let (nonce_b64, nonce) = probe(server).await?;
    let body = serde_json::json!({
        "label": label,
        "trust_key": {"id": tk.id, "alg": "ed25519", "public_key": tk.public_key},
        "nonce_b64": nonce_b64,
        "signature": {
            "key_id": tk.id,
            "alg": "ed25519",
            "sig": STANDARD.encode(kit.signer().sign(&mastersos_bundle::keyid::keyprobe_message(&nonce))),
        },
    });
    #[derive(Deserialize)]
    struct Answer {
        key_id: String,
        fingerprint: String,
    }
    let key_already = match server.post_json::<_, Answer>("keys", &body).await {
        Ok(a) if a.key_id == tk.id && a.fingerprint == fingerprint => false,
        Ok(_) => {
            return Err(invalid_answer(
                "the server registered a different key than this computer computed",
            ))
        }
        Err(e) if e.code == "key_exists" => true,
        Err(e) => return Err(e),
    };

    let (nonce_b64, nonce) = probe(server).await?;
    let msg = mastersos_bundle::kit::recipient_binding_message(&recipient, &nonce);
    let body = serde_json::json!({
        "recipient": recipient,
        "bound_key_id": tk.id,
        "nonce_b64": nonce_b64,
        "sig_b64": STANDARD.encode(kit.signer().sign(&msg)),
        "label": label,
    });
    let recipient_already = match server
        .post_json::<_, serde_json::Value>("escrow-recipients", &body)
        .await
    {
        Ok(_) => false,
        Err(e) if e.code == "recipient_exists" => true,
        Err(e) => return Err(e),
    };
    Ok(Registered {
        key_id: tk.id,
        fingerprint,
        key_already,
        recipient,
        recipient_already,
    })
}

/// The key code of `kit` (its key id where there is none).
pub fn code_of(kit: &Kit) -> String {
    mastersos_bundle::keyid::key_code(&kit.key_id()).unwrap_or_else(|| kit.key_id())
}

/// One escrowed row as `GET devices/{id}/recovery-keys` lists it. Only the sealed form is opened.
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

/// One escrowed row after opening: the recovery key when the school key opens it, else why not.
/// Not `Debug`: the key must not reach a log by accident.
pub struct RecoveryRow {
    pub luks_uuid: String,
    pub received_at: String,
    pub serial: Option<String>,
    /// `false` only when the server says an earlier row exists for the partition.
    pub first_for_luks: bool,
    pub recovery_key: Option<Zeroizing<String>>,
    /// What is odd about the row (never the key or the sealed text).
    pub note: Option<String>,
}

/// Fetch a machine's escrowed rows (newest first, as the server sends them) and open the sealed
/// ones locally with the kit's escrow identity. What the token may read is the server's to
/// decide; every read leaves an audit row on the server. The device id is one path segment.
pub async fn recovery_rows(
    server: &Server,
    kit: &Kit,
    device_id: &str,
) -> Result<Vec<RecoveryRow>, CliError> {
    let route = format!("devices/{}/recovery-keys", segment(device_id)?);
    let rows: Vec<Row> = server.get_json(&route).await?;
    let identity = kit.escrow_identity();
    Ok(rows.into_iter().map(|r| open_row(&identity, r)).collect())
}

fn open_row(identity: &age::x25519::Identity, r: Row) -> RecoveryRow {
    let mut notes: Vec<String> = Vec::new();
    let mut recovery_key = None;
    match &r.recovery_key_age {
        None => notes.push("not sealed: skipped".to_owned()),
        Some(sealed) if sealed.len() > SEALED_MAX => {
            notes.push("sealed row too large: skipped".to_owned());
        }
        Some(sealed) => match age::decrypt(identity, sealed.as_bytes()) {
            Ok(plain) => {
                let plain = Zeroizing::new(plain);
                match std::str::from_utf8(&plain) {
                    Ok(key) if is_recovery_key(key) => {
                        recovery_key = Some(Zeroizing::new(key.to_owned()));
                    }
                    _ => notes.push("opened, but it is not a recovery key: skipped".to_owned()),
                }
            }
            Err(_) => notes.push(format!(
                "not sealed to this school key (recipients {})",
                r.recipients_fp
                    .as_deref()
                    .map_or("-".to_owned(), safe::field)
            )),
        },
    }
    if r.first_for_luks == Some(false) {
        notes.push("not the first row for this partition: suspicious".to_owned());
    }
    RecoveryRow {
        luks_uuid: r.luks_uuid,
        received_at: r.received_at,
        serial: r.serial,
        first_for_luks: r.first_for_luks != Some(false),
        recovery_key,
        note: (!notes.is_empty()).then(|| notes.join("; ")),
    }
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

    /// The paper kits already handed out stay readable: every text form of the shared vectors
    /// loads from an owner-only file and gives the vector's key id and recipient.
    #[test]
    fn kit_vectors_still_parse() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../mastersos-bundle/testdata/kit-vectors.json"
        );
        let file: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let vectors = file["vectors"].as_array().unwrap();
        assert!(!vectors.is_empty());
        let dir = tempfile::tempdir().unwrap();
        for (i, v) in vectors.iter().enumerate() {
            for form in ["text", "display"] {
                let p = dir.path().join(format!("{i}-{form}.kit"));
                let mut f = crate::platform::create_private(&p).unwrap();
                std::io::Write::write_all(&mut f, v[form].as_str().unwrap().as_bytes()).unwrap();
                drop(f);
                let kit = load_kit(&p).unwrap();
                assert_eq!(kit.key_id(), v["key_id"].as_str().unwrap(), "{i} {form}");
                assert_eq!(
                    kit.escrow_recipient(),
                    v["escrow_recipient"].as_str().unwrap(),
                    "{i} {form}"
                );
            }
        }
    }
}

#[cfg(test)]
mod probe_tests {
    use super::*;

    fn wire_vectors() -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../mastersos-bundle/testdata/wire-vectors.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    /// The key probes of the shared wire vectors are read back to their nonce; every invalid
    /// `nonce_b64` (no padding, non-canonical trailing bits, a line break) is refused, with the
    /// valid message of the first probe beside it.
    #[test]
    fn wire_vector_probes() {
        let w = wire_vectors();
        let probes = w["key_probes"].as_array().unwrap();
        assert!(!probes.is_empty());
        for p in probes {
            let nonce = probe_nonce(
                p["nonce_b64"].as_str().unwrap(),
                p["message_b64"].as_str().unwrap(),
            )
            .unwrap();
            let hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(hex, p["nonce_hex"].as_str().unwrap(), "{}", p["name"]);
        }
        let message = probes[0]["message_b64"].as_str().unwrap();
        let invalid: Vec<&serde_json::Value> = w["invalid"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["field"] == "nonce_b64")
            .collect();
        assert_eq!(invalid.len(), 3);
        for v in invalid {
            let e = probe_nonce(v["value"].as_str().unwrap(), message).unwrap_err();
            assert_eq!(e.code, "invalid_answer", "{}", v["name"]);
        }
    }
}
