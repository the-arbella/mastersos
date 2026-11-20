//! `mastersos publish` and `mastersos heartbeat` over protocol v1 (§4.4, §4.7).
//!
//! `publish`: the local directory is checked, its secrets are filled back in, the chain is
//! verified here ([`chain::verify_chain`], with the school key file as the anchor), and version,
//! time and the organisation's name are stamped. The frame and the content digest computed here
//! are uploaded (`POST publish/pending`); the answer must echo the version, the digest and the
//! bundle message exactly as computed here, or the upload is deleted and nothing is signed. Then
//! the person confirms (the version number, unless `--yes`), the school key signs the message
//! computed here ([`crate::sign::sign_bundle`]), the signed archive is committed, and a 30-day
//! check-in for exactly that version and digest is signed and posted. A failed check-in leaves the
//! version published.
//!
//! Every refusal after the upload deletes it first: nothing is left pending on the server.
//!
//! `heartbeat`: the check-in for the latest version verified here, with its digest from the chain.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, SecondsFormat, Utc};
use mastersos_bundle::kit::Kit;
use mastersos_bundle::secret_ref;
use mastersos_bundle::stamp::{school_name_to_write, stamp};
use mastersos_bundle::{
    accept, assemble, content_digest, frame_of, has_errors, recipients_changed, signed_message,
    Contents, Lint, LintLevel, Manifest, Signer, TrustKey, MAX_HEARTBEAT_DAYS,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::safe;
use crate::server::{segment, CliError, Server};
use crate::sign::chain::{self, Anchors, Verified};
use crate::sign::{ask, hex, key_line, print_local_diff, print_trust, TrustDelta};
use crate::workdir::{self, Snapshot, UploadInfo, Workdir};

/// How long the check-in signed after a publish lasts.
pub const CHECKIN_DAYS: i64 = 30;

/// What people read when the check-in after a publish fails.
pub const CHECKIN_FAILED_TEXT: &str =
    "Computers may soon show \"settings may be out of date\". Open the admin site to fix it.";

/// How many characters of the digest are printed: as many as the check code shows.
pub const DIGEST_SHOWN: usize = 8;

/// The check code: the first [`DIGEST_SHOWN`] characters of the content digest.
pub fn check_code(digest_hex: &str) -> &str {
    &digest_hex[..digest_hex.len().min(DIGEST_SHOWN)]
}

/// What `publish` is given besides the directory and the school key.
pub struct PublishOpts<'a> {
    /// The secret names IT approved with `--allow-reroute`.
    pub allow_reroute: &'a [String],
    /// `--yes`: no person answers, so nothing is asked. Without it a person answers every
    /// question: the caller refuses first when nobody can (`--json`, or stdin not a terminal).
    pub yes: bool,
    /// Where the pins are kept.
    pub pin_dir: &'a Path,
    /// `--trust-fingerprint`: anchors of a first use without a person.
    pub fingerprints: &'a [String],
}

/// The monthly check-in signed after a publish here.
#[derive(Debug, PartialEq, Eq)]
pub enum CheckIn {
    /// Computers treat the version as current until then.
    Until(DateTime<Utc>),
    /// Not signed or not accepted: why (for `--json` only; people get one plain sentence).
    Failed(String),
}

/// The trusted keys a publish adds and removes, computed here against the latest verified
/// version (key ids; a key whose id stays but whose key changes is in both).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TrustChange {
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PublishOutcome {
    /// Signed here and committed: the new version, and the directory's base now is it.
    Published {
        version: u64,
        /// The content digest computed here (lowercase hex).
        digest_hex: String,
        checkin: CheckIn,
        trust_change: TrustChange,
        /// The server's warnings (`{"code","message"}`), cleaned: secret values replaced by
        /// their references, control characters escaped.
        warnings: Vec<Value>,
    },
}

/// A secret would be sent to a changed network (`secret_rerouted`) and IT has not approved it by
/// name with `--allow-reroute`; nothing was sent.
struct RerouteRefused {
    /// The rerouted secrets not approved, sorted.
    names: Vec<String>,
}

impl std::fmt::Display for RerouteRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A name goes into a command IT may paste: only names that cannot run anything else.
        if !self.names.iter().all(|n| secret_ref::is_valid_name(n)) {
            return write!(
                f,
                "Not published: a secret would be sent somewhere new (secret_rerouted), and its name is not valid; fix the secret names (`mastersos check`) first"
            );
        }
        let names = self.names.join(", ");
        let flags: Vec<String> = self
            .names
            .iter()
            .map(|n| format!("--allow-reroute={n}"))
            .collect();
        write!(
            f,
            "Not published: the network using secret(s) {names} changed, so the secret would be sent somewhere new (secret_rerouted). Only IT decides this: check the change with `mastersos diff`; if each secret really belongs to its changed network, run `mastersos publish {}`",
            flags.join(" ")
        )
    }
}

fn lint_values(lints: &[Lint]) -> Vec<Value> {
    lints
        .iter()
        .map(|l| serde_json::to_value(l).unwrap_or(Value::Null))
        .collect()
}

/// The local check found errors (`check_failed`, exit 2); nothing was sent.
fn check_failed(lints: &[Lint]) -> CliError {
    let n = lints.iter().filter(|l| l.level == LintLevel::Error).count();
    let mut e = CliError::new(
        "check_failed",
        &format!(
            "Not published: the settings have {n} error(s); fix them and run `mastersos check`"
        ),
    );
    e.problems = lint_values(lints);
    e
}

/// A local failure; the message names files, never their content.
fn local(e: impl std::fmt::Display) -> CliError {
    CliError::new("local_file", &safe::text(&format!("{e:#}")))
}

/// A text from the server, safe to print: secret values replaced by their references, control
/// characters escaped.
fn clean(s: &str, secrets: &BTreeMap<String, String>) -> String {
    safe::field(&workdir::redact(s, secrets))
}

/// The local check's warnings and notes, one per line, before anything is uploaded.
fn print_local_lints(
    out: &mut dyn Write,
    lints: &[Lint],
    secrets: &BTreeMap<String, String>,
) -> std::io::Result<()> {
    if lints.is_empty() {
        return Ok(());
    }
    writeln!(out, "The local check:")?;
    for l in lints {
        let level = match l.level {
            LintLevel::Error => "error",
            LintLevel::Warning => "warning",
            LintLevel::Info => "info",
        };
        writeln!(
            out,
            "{level:<7} {:<24} {}",
            l.code,
            clean(&l.message, secrets)
        )?;
    }
    Ok(())
}

/// The line after the checks (errors would have stopped the publish): how many warnings are
/// listed above it. Notes (info) are not problems.
fn checked_line(local: &[Lint], server_warnings: usize) -> String {
    let warnings = local
        .iter()
        .filter(|l| l.level == LintLevel::Warning)
        .count()
        + server_warnings;
    match warnings {
        0 => "Checked: no problems".to_owned(),
        1 => "Checked: no errors, 1 warning (above)".to_owned(),
        n => format!("Checked: no errors, {n} warnings (above)"),
    }
}

/// A UUID (8-4-4-4-12 hex digits), as `pending_id` must be.
fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

/// Someone published after the directory's base (or the server's latest is behind it).
fn newer(latest: u64, base: u64) -> CliError {
    if latest < base {
        return CliError::new(
            "chain_tampered",
            &format!(
                "the server says its latest is version {latest}, older than this directory's base version {base}: the server may have been rolled back, or this is the wrong server; nothing was uploaded"
            ),
        );
    }
    CliError::new(
        "version_conflict",
        &format!(
            "Someone published v{latest} after your base v{base}. Your edits are not published. Save your changes elsewhere, then run `mastersos pull --force` (this discards local edits) and redo them."
        ),
    )
}

fn key_not_trusted(me: &TrustKey, why: &str) -> CliError {
    CliError::new(
        "key_not_trusted",
        &format!("Not uploaded: {} {why}", key_line(me)),
    )
}

/// A refusal of the server, in words that say what to do. The code and status stay the server's;
/// the message is ours, or the server's with secret values replaced and control characters
/// escaped. `details` are not passed on except the devices of a feature gate refusal (cleaned).
fn refusal(mut e: CliError, base: u64, secrets: &BTreeMap<String, String>) -> CliError {
    let detail = |k: &str| e.details.get(k).and_then(Value::as_str).map(safe::field);
    let message = match e.code.as_str() {
        "version_conflict" => match e.details.get("latest_version").and_then(Value::as_u64) {
            Some(n) => newer(n, base).message,
            None => format!(
                "Someone published a newer version after your base v{base}. Your edits are not published. Save your changes elsewhere, then run `mastersos pull --force` (this discards local edits) and redo them."
            ),
        },
        "clock_skew" => "Not published: this computer's clock is off by more than 10 minutes. Set the clock (automatic date and time), then publish again.".to_owned(),
        "school_mismatch" => "Not published: the settings name another school than the one this server publishes for (the directory's school id).".to_owned(),
        "trust_key_unregistered" => format!(
            "Not published: {} among the trusted keys is not registered for this school. Register it with `mastersos key register --key-file <file> --label <name>`, then publish again.",
            detail("key_id").map_or("a school key".to_owned(), |id| format!(
                "school key {}",
                workdir::shown_code(&id)
            ))
        ),
        "recipient_unregistered" => "Not published: a disk-unlocking entry in manifest.toml is not registered for this school, or not tied to one of the trusted keys. Register its school key with `mastersos key register --key-file <file> --label <name>`, then publish again.".to_owned(),
        "feature_unsupported" => {
            let feature = detail("feature").unwrap_or_else(|| "?".to_owned());
            let devices: Vec<Value> = e
                .details
                .get("devices")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .map(|d| {
                            let s = |k: &str| {
                                d.get(k)
                                    .and_then(Value::as_str)
                                    .map_or(Value::Null, |v| Value::String(safe::field(v)))
                            };
                            json!({"device_id": s("device_id"), "serial": s("serial"),
                                "os_version": s("os_version"), "last_seen": s("last_seen")})
                        })
                        .collect()
                })
                .unwrap_or_default();
            let n = devices.len();
            e.problems = devices;
            format!(
                "Not published: these settings use `{feature}`, which {n} Device(s) seen in the last 30 days do not support. Update them (or remove Devices that are not real), then publish again."
            )
        }
        "pending_expired" => "Not published: the upload expired before it was approved (after 30 minutes). Run `mastersos publish` again.".to_owned(),
        "archive_invalid" => "Not published: the server refused the signed package as not valid.".to_owned(),
        "digest_mismatch" => "Not published: the server does not hold what was uploaded.".to_owned(),
        "signature_invalid" => "Not published: the server did not accept the school key's signature (it checks it with the trusted keys of the latest published version).".to_owned(),
        "trust_rule" => "Not published: the school key that signed is not among the new trusted keys; a school key cannot approve its own removal.".to_owned(),
        _ => clean(&e.message, secrets),
    };
    e.message = message;
    e
}

/// Delete an upload; best effort (the refusal that led here is what is reported).
async fn discard(server: &Server, pending_id: &str) {
    if let Ok(seg) = segment(pending_id) {
        let _ = server.delete(&format!("publish/pending/{seg}")).await;
    }
}

/// The answer of `POST publish/pending` (the fields checked or shown).
#[derive(Deserialize)]
struct PendingAnswer {
    pending_id: String,
    version: u64,
    digest_hex: String,
    message_b64: String,
    #[serde(default)]
    warnings: Vec<Value>,
}

/// Before the first version: nothing may be published yet, and this computer must not have
/// verified a version of this school (a server that forgot its chain would get a signature over a
/// trust it chose).
async fn first_version(server: &Server, pin_dir: &Path) -> Result<(), CliError> {
    let latest = server.latest_version().await?;
    if latest != 0 {
        return Err(newer(latest, 0));
    }
    let path = chain::pin_path(pin_dir, server.into())?;
    if let Some(pin) = chain::load_pin(&path).map_err(local)? {
        return Err(CliError::new(
            "chain_tampered",
            &format!(
                "the server reports nothing published, but version {} was checked on this computer before ({}): the server may have been rolled back, or this is the wrong server; nothing was uploaded. Delete that file only if you are sure the server was reset on purpose",
                pin.version,
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Record the version just published in the pin: the base it was verified from (`None` for the
/// first version) moves forward to it.
fn record_published(
    server: &Server,
    pin_dir: &Path,
    base: Option<&Verified>,
    version: u64,
    digest_hex: &str,
    trust: &[TrustKey],
) -> anyhow::Result<()> {
    let path = chain::pin_path(pin_dir, server.into())?;
    let prev = base.map(|v| chain::pin_of(server.into(), v)).transpose()?;
    let mut history = base.map(|v| v.history.clone()).unwrap_or_default();
    chain::record_verified(&mut history, version, digest_hex);
    chain::save_pin(
        &path,
        prev.as_ref(),
        &chain::Pin {
            host: chain::pin_key_v1(server.origin(), server.school()?),
            version,
            digest_hex: digest_hex.to_owned(),
            trust: trust.to_vec(),
            verified: history,
        },
    )
}

/// Sign the check-in for `version` and `digest_hex` here and post it; returns its end.
async fn post_checkin(
    server: &Server,
    signer: &dyn Signer,
    version: u64,
    digest_hex: &str,
    now: DateTime<Utc>,
    days: i64,
    trust: &[TrustKey],
) -> Result<DateTime<Utc>, CliError> {
    let (text, statement) =
        crate::sign::sign_heartbeat(signer, version, digest_hex, now.timestamp(), days, trust)
            .map_err(local)?;
    server
        .post_json::<_, ()>("heartbeat", &json!({ "heartbeat": text }))
        .await?;
    DateTime::from_timestamp(statement.not_after, 0)
        .ok_or_else(|| local("the check-in's end is out of range"))
}

/// What the person is shown before the signature (steps 6 and 7 of a publish).
struct Approval<'a> {
    /// The latest verified version (`None` before the first version).
    base: Option<&'a Verified>,
    manifest: &'a Manifest,
    contents: &'a Contents,
    version: u64,
    digest_hex: &'a str,
    lints: &'a [Lint],
    warnings: &'a [Value],
    delta: &'a TrustDelta<'a>,
    yes: bool,
}

/// Show what changes (computed here), ask the person (unless `--yes`), sign the message computed
/// here, check the signed package as a computer would, and keep what was uploaded (0600 files in
/// a 0700 directory). Returns the signed archive.
fn approve_and_sign(
    a: &Approval<'_>,
    signer: &dyn Signer,
    w: &Workdir,
    snap: &Snapshot,
    confirm: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Vec<u8>, CliError> {
    let (version, manifest) = (a.version, a.manifest);
    if let Some(v) = a.base {
        print_local_diff(out, v, version, a.contents).map_err(local)?;
    }
    writeln!(
        out,
        "\n== All trusted keys of version {version} ({} in total; from this version on, computers accept only these keys) ==",
        manifest.trust.len()
    )
    .map_err(local)?;
    print_trust(out, &manifest.trust).map_err(local)?;
    match a.base {
        None => writeln!(
            out,
            "This is the first version: computers will accept settings approved only by these keys. Check each key code and fingerprint against the paper copy of your school key, not against this server's pages."
        )
        .map_err(local)?,
        Some(v) if a.delta.is_empty() => writeln!(
            out,
            "The trusted keys are the same as in version {}.",
            v.version
        )
        .map_err(local)?,
        Some(v) => {
            writeln!(
                out,
                "The trusted keys change (compared with version {} verified here):",
                v.version
            )
            .map_err(local)?;
            a.delta.print(out).map_err(local)?;
            writeln!(
                out,
                "Compare each fingerprint with the School keys page: an unknown extra key hands every computer to whoever holds it."
            )
            .map_err(local)?;
        }
    }
    // Escrow recipients against the same base (machines seal their recovery keys to them).
    let base_recipients = match a.base {
        Some(v) => {
            Manifest::parse(&v.contents.manifest_text)
                .map_err(local)?
                .school
                .escrow_recipients
        }
        None => Vec::new(),
    };
    let new_recipients = &manifest.school.escrow_recipients;
    let recipients_change = recipients_changed(&base_recipients, new_recipients);
    if recipients_change {
        writeln!(
            out,
            "Disk unlocking changes (computers will keep their disk recovery codes for these school keys):"
        )
        .map_err(local)?;
        for r in base_recipients
            .iter()
            .filter(|r| !new_recipients.contains(r))
        {
            writeln!(out, "  - {}", safe::field(r)).map_err(local)?;
        }
        for r in new_recipients
            .iter()
            .filter(|r| !base_recipients.contains(r))
        {
            writeln!(out, "  + {}", safe::field(r)).map_err(local)?;
        }
        writeln!(
            out,
            "Each added line must come from one of your school keys: an unknown one could unlock the computers' disks."
        )
        .map_err(local)?;
    }
    if !a.warnings.is_empty() {
        writeln!(out, "The server's check:").map_err(local)?;
        for w in a.warnings {
            writeln!(
                out,
                "warning {:<24} {}",
                w["code"].as_str().unwrap_or(""),
                w["message"].as_str().unwrap_or("")
            )
            .map_err(local)?;
        }
    }
    writeln!(out, "{}", checked_line(a.lints, a.warnings.len())).map_err(local)?;
    writeln!(out, "Check code: {}", check_code(a.digest_hex)).map_err(local)?;
    if !a.yes {
        let cancelled = |_| {
            CliError::new(
                "cancelled",
                "No input was read; cancelled, nothing was published",
            )
        };
        let typed = ask(
            confirm,
            out,
            &format!("Type the version number {version} to publish it: "),
        )
        .map_err(cancelled)?;
        if typed != version.to_string() {
            return Err(CliError::new(
                "cancelled",
                &format!(
                    "The version number you typed ({}) does not match version {version}; cancelled, nothing was published",
                    safe::field(&typed)
                ),
            ));
        }
        if !a.delta.is_empty() || recipients_change {
            let typed = ask(
                confirm,
                out,
                "This version changes which school keys computers accept and who can unlock their disks (see the changes above). If that is right, type yes: ",
            )
            .map_err(cancelled)?;
            if typed != "yes" {
                return Err(CliError::new(
                    "cancelled",
                    "The change of trusted keys or disk unlocking was not confirmed; cancelled, nothing was published",
                ));
            }
        }
    }
    // Signed: the message computed here from the content, never the server's.
    let signature = crate::sign::sign_bundle(signer, a.contents);
    let archive = assemble(a.contents, &signature).map_err(local)?;
    // Checked here as a computer would: with the trust computers run now (the first version with
    // its own).
    let (trust, current) = match a.base {
        Some(v) => (&v.trust[..], Some(v.version)),
        None => (&manifest.trust[..], None),
    };
    accept(&archive, trust, current).map_err(|e| {
        CliError::new(
            "self_check_failed",
            &format!(
                "The signed package fails the check on this computer: computers would reject it; nothing was published ({})",
                safe::field(&e.to_string())
            ),
        )
    })?;
    w.save_uploaded(
        snap,
        &UploadInfo {
            version,
            digest_hex: a.digest_hex.to_owned(),
        },
    )
    .map_err(local)?;
    Ok(archive)
}

/// Publish the directory `w` with the school key `kit` (see the module documentation).
pub async fn publish(
    server: &Server,
    w: &Workdir,
    kit: &Kit,
    opts: PublishOpts<'_>,
    now: DateTime<Utc>,
    confirm: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<PublishOutcome, CliError> {
    let signer = kit.signer();
    publish_with(
        server,
        w,
        &signer,
        &kit.trust_key(),
        opts,
        now,
        confirm,
        out,
    )
    .await
}

/// [`publish`] with the signer given (`me` is its trusted key).
#[allow(clippy::too_many_arguments)]
async fn publish_with(
    server: &Server,
    w: &Workdir,
    signer: &dyn Signer,
    me: &TrustKey,
    opts: PublishOpts<'_>,
    now: DateTime<Utc>,
    confirm: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<PublishOutcome, CliError> {
    let mut out = safe::SafeWriter::new(out);
    let out: &mut dyn Write = &mut out;
    let meta = w.meta().map_err(local)?;
    if server.school()? != meta.school_id {
        return Err(CliError::new(
            "school_mismatch",
            &format!(
                "the directory belongs to school {}, not to {}",
                meta.school_id,
                server.school()?
            ),
        ));
    }

    // 1. The local check, the reroute approval, the secrets.
    // One read: what is checked, uploaded, kept and later made the base is this snapshot.
    let snap = w.freeze().map_err(local)?;
    if w.equals_base(&snap).map_err(local)? {
        return Err(CliError::new(
            "unchanged",
            &format!(
                "Nothing to publish: the directory equals version {}",
                meta.base_version
            ),
        ));
    }
    let lints = workdir::check_snapshot(w, &snap).map_err(local)?;
    if has_errors(&lints) {
        return Err(check_failed(&lints));
    }
    // A secret pointed at a changed network would be handed to whoever runs it: only IT may
    // approve that, by name, on the command line.
    let names = secret_ref::unapproved_reroutes(&lints, opts.allow_reroute);
    if !names.is_empty() {
        let mut e = CliError::new("reroute_refused", &RerouteRefused { names }.to_string());
        e.problems = lint_values(&lints);
        return Err(e);
    }
    print_local_lints(out, &lints, &snap.secrets).map_err(local)?;
    let rerouted = secret_ref::rerouted_names(&lints);
    for a in opts.allow_reroute.iter().filter(|a| !rerouted.contains(*a)) {
        if secret_ref::is_valid_name(a) {
            writeln!(
                out,
                "Note: --allow-reroute={a} approves nothing: no secret of that name is rerouted"
            )
            .map_err(local)?;
        } else {
            writeln!(
                out,
                "Note: an --allow-reroute value is not a valid secret name and approves nothing"
            )
            .map_err(local)?;
        }
    }

    // 2. The chain, verified here; the directory's base must be its latest.
    let base: Option<Verified> = if meta.base_version == 0 {
        first_version(server, opts.pin_dir).await?;
        None
    } else {
        let anchors = Anchors {
            keys: vec![me.clone()],
            fingerprints: opts.fingerprints.to_vec(),
            interactive: !opts.yes,
        };
        let v = if opts.yes {
            chain::verify_chain(
                server.into(),
                opts.pin_dir,
                &anchors,
                &mut std::io::empty(),
                out,
            )
            .await?
        } else {
            chain::verify_chain(server.into(), opts.pin_dir, &anchors, confirm, out).await?
        };
        Some(v)
    };
    let latest = base.as_ref().map_or(0, |v| v.latest);
    if latest != meta.base_version {
        return Err(newer(latest, meta.base_version));
    }
    if let Some(v) = &base {
        if !v.trust.contains(me) {
            return Err(key_not_trusted(
                me,
                &format!(
                    "is not among the trusted keys of version {} verified here: computers would not accept its signature",
                    v.version
                ),
            ));
        }
    }

    // 3. The stamp: version, time, and the organisation's name from the server's list.
    let version = meta.base_version + 1;
    let issued_at = now.to_rfc3339_opts(SecondsFormat::Secs, true);
    let schools = server.schools().await?;
    let entry = schools
        .iter()
        .find(|s| s.id == meta.school_id)
        .ok_or_else(|| {
            CliError::new(
                "not_configured",
                &format!(
                    "the server does not list school {} for this account",
                    meta.school_id
                ),
            )
        })?;
    // Stamped with the secrets still as references, then filled: the stamped reference text is
    // what becomes the base once this version is published, and filling it gives exactly what
    // is signed, so the base keeps the published digest ([`Workdir::verify_base`]).
    let stamped_refs = stamp(
        &snap.manifest,
        version,
        &issued_at,
        school_name_to_write(&snap.manifest, &entry.name),
    )
    .map_err(local)?;
    let stamped = secret_ref::fill(&stamped_refs, &snap.secrets).map_err(|l| check_failed(&l))?;
    let manifest = Manifest::parse(&stamped).map_err(|e| {
        CliError::new(
            "check_failed",
            &format!("Not published: {}", safe::field(&e.to_string())),
        )
    })?;
    if !manifest.trust.contains(me) {
        return Err(key_not_trusted(
            me,
            "is not among the trusted keys in manifest.toml. Computers accept only trusted keys, and a school key cannot approve its own removal",
        ));
    }

    // 4. What is signed, computed here.
    let contents = Contents {
        manifest_text: stamped.clone(),
        files: snap.files.clone(),
    };
    let digest_hex = hex(&content_digest(&contents));
    let message_b64 = STANDARD.encode(signed_message(&contents));
    let frame = frame_of(&stamped).map_err(|e| {
        CliError::new(
            "check_failed",
            &format!("Not published: {}", safe::field(&e.to_string())),
        )
    })?;
    if frame.school_id != meta.school_id || frame.version != version {
        return Err(CliError::new(
            "school_mismatch",
            &format!(
                "Not published: manifest.toml names school {}, but this directory belongs to school {}",
                safe::field(&frame.school_id),
                meta.school_id
            ),
        ));
    }

    // 5. The upload, and the server's echo of it.
    let answer: Value = server
        .post_json(
            "publish/pending",
            &json!({ "frame": frame, "digest_hex": digest_hex }),
        )
        .await
        .map_err(|e| refusal(e, meta.base_version, &snap.secrets))?;
    let echoed = serde_json::from_value::<PendingAnswer>(answer.clone())
        .ok()
        .filter(|p| {
            is_uuid(&p.pending_id)
                && p.version == version
                && p.digest_hex == digest_hex
                && p.message_b64 == message_b64
        });
    let Some(pending) = echoed else {
        if let Some(id) = answer.get("pending_id").and_then(Value::as_str) {
            discard(server, id).await;
        }
        return Err(CliError::new(
            "digest_mismatch",
            &format!(
                "Not published: the server does not hold what was uploaded (its answer does not name version {version} with check code {} as computed on this computer). The upload was deleted; nothing was signed.",
                check_code(&digest_hex)
            ),
        ));
    };
    let warnings: Vec<Value> = pending
        .warnings
        .iter()
        .map(|w| {
            let s = |k: &str| {
                clean(
                    w.get(k).and_then(Value::as_str).unwrap_or(""),
                    &snap.secrets,
                )
            };
            json!({"code": s("code"), "message": s("message")})
        })
        .collect();

    // 6 and 7. What changes, the person's confirmation, the signature ([`approve_and_sign`]).
    // Any refusal there deletes the upload first.
    let base_trust: &[TrustKey] = base.as_ref().map_or(&[][..], |v| v.trust.as_slice());
    let delta = TrustDelta::between(base_trust, &manifest.trust);
    let mut trust_change = TrustChange {
        added: delta.added.iter().map(|k| k.id.clone()).collect(),
        removed: delta.removed.iter().map(|k| k.id.clone()).collect(),
    };
    for (_, k) in &delta.modified {
        trust_change.added.push(k.id.clone());
        trust_change.removed.push(k.id.clone());
    }
    let approval = Approval {
        base: base.as_ref(),
        manifest: &manifest,
        contents: &contents,
        version,
        digest_hex: &digest_hex,
        lints: &lints,
        warnings: &warnings,
        delta: &delta,
        yes: opts.yes,
    };
    let archive = match approve_and_sign(&approval, signer, w, &snap, confirm, out) {
        Ok(a) => a,
        Err(e) => {
            discard(server, &pending.pending_id).await;
            return Err(e);
        }
    };

    // 8. The commit.
    #[derive(Deserialize)]
    struct Committed {
        version: u64,
    }
    let route = format!("publish/pending/{}/commit", segment(&pending.pending_id)?);
    let committed: Committed = match server.post_bytes(&route, archive, "application/gzip").await {
        Ok(c) => c,
        Err(e) => {
            discard(server, &pending.pending_id).await;
            return Err(refusal(e, meta.base_version, &snap.secrets));
        }
    };
    if committed.version != version {
        return Err(CliError::new(
            "invalid_answer",
            &format!(
                "The server says version {} was published, but version {version} was approved here: run `mastersos verify` to check the server again",
                committed.version
            ),
        ));
    }

    // 9. The check-in for exactly the version and digest just committed, with that version's
    // trust. It goes before this computer's own bookkeeping, so a published version always gets
    // its check-in.
    let checkin = match post_checkin(
        server,
        signer,
        version,
        &digest_hex,
        now,
        CHECKIN_DAYS,
        &manifest.trust,
    )
    .await
    {
        Ok(until) => CheckIn::Until(until),
        Err(e) => CheckIn::Failed(format!("{} ({})", clean(&e.message, &snap.secrets), e.code)),
    };

    // 10. This computer's records: the pin, then the directory's base.
    let recorded = record_published(
        server,
        opts.pin_dir,
        base.as_ref(),
        version,
        &digest_hex,
        &manifest.trust,
    )
    .and_then(|()| w.mark_published(version, &stamped_refs));
    if let Err(e) = recorded {
        let also = match &checkin {
            CheckIn::Failed(_) => format!(" {CHECKIN_FAILED_TEXT}"),
            CheckIn::Until(_) => String::new(),
        };
        return Err(CliError::new(
            "local_file",
            &format!(
                "Published version {version}, but this computer could not record it: {}.{also}",
                safe::field(&format!("{e:#}"))
            ),
        ));
    }
    Ok(PublishOutcome::Published {
        version,
        digest_hex,
        checkin,
        trust_change,
        warnings,
    })
}

/// What `heartbeat` is given besides the school key.
pub struct HeartbeatOpts<'a> {
    /// How many days the check-in lasts, 1 to 31.
    pub days: i64,
    /// `--yes`: nothing is asked (see [`PublishOpts::yes`]).
    pub yes: bool,
    pub pin_dir: &'a Path,
    pub fingerprints: &'a [String],
}

/// A check-in the server accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedIn {
    pub version: u64,
    pub digest_hex: String,
    pub not_after: DateTime<Utc>,
}

/// `mastersos heartbeat`: the check-in for the latest version verified here (its digest from the
/// chain), signed here and posted.
pub async fn heartbeat(
    server: &Server,
    kit: &Kit,
    opts: HeartbeatOpts<'_>,
    now: DateTime<Utc>,
    confirm: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<CheckedIn, CliError> {
    let signer = kit.signer();
    heartbeat_with(server, &signer, &kit.trust_key(), opts, now, confirm, out).await
}

async fn heartbeat_with(
    server: &Server,
    signer: &dyn Signer,
    me: &TrustKey,
    opts: HeartbeatOpts<'_>,
    now: DateTime<Utc>,
    confirm: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<CheckedIn, CliError> {
    if !(1..=MAX_HEARTBEAT_DAYS).contains(&opts.days) {
        return Err(CliError::usage(&format!(
            "--days must be between 1 and {MAX_HEARTBEAT_DAYS}"
        )));
    }
    let mut out = safe::SafeWriter::new(out);
    let out: &mut dyn Write = &mut out;
    let anchors = Anchors {
        keys: vec![me.clone()],
        fingerprints: opts.fingerprints.to_vec(),
        interactive: !opts.yes,
    };
    let v = if opts.yes {
        chain::verify_chain(
            server.into(),
            opts.pin_dir,
            &anchors,
            &mut std::io::empty(),
            out,
        )
        .await?
    } else {
        chain::verify_chain(server.into(), opts.pin_dir, &anchors, confirm, out).await?
    };
    if !v.trust.contains(me) {
        return Err(CliError::new(
            "key_not_trusted",
            &format!(
                "{} is not among the trusted keys of version {} verified here: computers would not accept its check-in",
                key_line(me),
                v.version
            ),
        ));
    }
    if v.version != v.latest {
        return Err(CliError::new(
            "not_latest",
            &format!(
                "computers stay on version {}: version {} after it is refused on this computer. Publish a new version instead",
                v.version, v.latest
            ),
        ));
    }
    let until = now + chrono::Duration::days(opts.days);
    writeln!(
        out,
        "Monthly check-in for version {} (check code {}), valid for {} days, until {}.",
        v.version,
        check_code(&v.digest_hex),
        opts.days,
        until.format("%Y-%m-%d %H:%M UTC")
    )
    .map_err(local)?;
    writeln!(
        out,
        "Until it expires, computers treat version {} as the latest settings; if the server holds back a newer version meanwhile, computers cannot tell.",
        v.version
    )
    .map_err(local)?;
    if !opts.yes {
        let typed = ask(
            confirm,
            out,
            &format!("Type the version number {} to sign: ", v.version),
        )
        .map_err(|_| {
            CliError::new(
                "cancelled",
                "No input was read; cancelled, nothing was signed",
            )
        })?;
        if typed != v.version.to_string() {
            return Err(CliError::new(
                "cancelled",
                &format!(
                    "The version number you typed ({}) does not match version {}; cancelled, nothing was signed",
                    safe::field(&typed),
                    v.version
                ),
            ));
        }
    }
    let not_after = post_checkin(
        server,
        signer,
        v.version,
        &v.digest_hex,
        now,
        opts.days,
        &v.trust,
    )
    .await
    .map_err(|mut e| {
        e.message = match e.code.as_str() {
            "not_latest" => "Not signed: someone published meanwhile; run it again.".to_owned(),
            "clock_skew" => "Not signed: this computer's clock is off by more than 10 minutes. Set the clock (automatic date and time), then run it again.".to_owned(),
            "signature_invalid" => "Not signed: the server did not accept the school key's signature (it checks it with the trusted keys of the latest published version).".to_owned(),
            _ => e.message,
        };
        e
    })?;
    Ok(CheckedIn {
        version: v.version,
        digest_hex: v.digest_hex,
        not_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Credentials;
    use crate::workdir::Meta;
    use mastersos_bundle::{pack, read_archive, verify_signature, Ed25519Signer, Heartbeat};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use wiremock::matchers::path_regex;
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    const SID: &str = "0192f3a4-5b6c-7d8e-9f00-112233445566";
    const PID: &str = "0192f3a4-0000-4000-8000-0000000000aa";

    fn prefix() -> String {
        format!("/api/cli/v1/schools/{SID}/mastersos/")
    }

    fn kit() -> Kit {
        Kit::from_master(&[7; 32])
    }

    fn other_kit() -> Kit {
        Kit::from_master(&[9; 32])
    }

    fn now() -> DateTime<Utc> {
        "2026-11-21T05:00:00Z".parse().unwrap()
    }

    /// The test settings with `k`'s key as the only trusted key.
    fn manifest_trusting(k: &Kit) -> String {
        let tk = k.trust_key();
        format!(
            "format = 2\n[school]\nid = \"{SID}\"\n\n[[trust]]\nid = \"{}\"\nalg = \"ed25519\"\npublic_key = \"{}\"\n\n[defaults]\nwifi = [{{ ssid = \"Guest\", psk = \"guestpass1\" }}]\n\n[[config]]\nid = \"default\"\nname = \"Default\"\ninterface = \"learning\"\nlogin_methods = [\"local\"]\n\n[[group]]\nid = \"default\"\nname = \"Ungrouped\"\nconfig = \"default\"\n",
            tk.id, tk.public_key
        )
    }

    /// Signs like the school key and counts the signatures made.
    struct Counting {
        inner: Ed25519Signer,
        count: AtomicUsize,
    }

    impl Counting {
        fn of(k: &Kit) -> Counting {
            Counting {
                inner: k.signer(),
                count: AtomicUsize::new(0),
            }
        }

        fn signed(&self) -> usize {
            self.count.load(Ordering::SeqCst)
        }
    }

    impl Signer for Counting {
        fn key_id(&self) -> &str {
            self.inner.key_id()
        }

        fn sign(&self, msg: &[u8]) -> Vec<u8> {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.inner.sign(msg)
        }
    }

    /// What the test server holds and was sent.
    #[derive(Default)]
    struct Held {
        /// Published versions 1, 2, ...
        archives: Vec<Vec<u8>>,
        /// Bodies of `POST publish/pending`.
        uploads: Vec<Value>,
        /// The digest of the upload waiting for its commit.
        pending: Option<String>,
        /// Bodies of the commits.
        commits: Vec<Vec<u8>>,
        /// Routes deleted.
        deletes: Vec<String>,
        /// The `heartbeat` texts posted.
        heartbeats: Vec<String>,
    }

    type Refusal = Arc<Mutex<Option<(u16, Value)>>>;

    /// One school on the protocol v1 CLI API, honest unless told otherwise.
    #[derive(Clone, Default)]
    struct School {
        held: Arc<Mutex<Held>>,
        /// Fields that replace those of the `201` answer to an upload (a lying server).
        lie: Arc<Mutex<Value>>,
        /// An error answer to the upload, instead of `201`.
        refuse_upload: Refusal,
        /// An error answer to the commit, instead of `200`.
        refuse_commit: Refusal,
        /// An error answer to the check-in, instead of `204`.
        refuse_heartbeat: Refusal,
        /// The schools listed for the account (default: this one, "Demo School").
        schools: Arc<Mutex<Option<Value>>>,
    }

    fn envelope(code: &str, details: Value) -> Value {
        json!({"error": {"code": code, "message": "refused", "details": details}})
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    impl Respond for School {
        fn respond(&self, req: &Request) -> ResponseTemplate {
            let mut held = self.held.lock().unwrap();
            let p = req.url.path().to_owned();
            if p == "/api/cli/v1/schools" {
                let list = self.schools.lock().unwrap().clone().unwrap_or_else(
                    || json!([{"id": SID, "name": "Demo School", "time_zone": "Asia/Bangkok"}]),
                );
                return ResponseTemplate::new(200).set_body_json(list);
            }
            let route = p
                .strip_prefix(&prefix())
                .expect("a school route")
                .to_owned();
            let commit = format!("publish/pending/{PID}/commit");
            match (req.method.as_str(), route.as_str()) {
                ("GET", "versions") => {
                    let vs: Vec<Value> = (1..=held.archives.len())
                        .map(|v| {
                            json!({"version": v, "published_at": "2026-11-20T00:00:00Z",
                            "published_by": "it", "signed_by": "k", "digest_hex": "00"})
                        })
                        .collect();
                    ResponseTemplate::new(200).set_body_json(vs)
                }
                ("GET", r) if r.starts_with("versions/") => {
                    let v: usize = r
                        .trim_start_matches("versions/")
                        .trim_end_matches("/archive")
                        .parse()
                        .unwrap();
                    ResponseTemplate::new(200)
                        .insert_header("X-Mastersos-Version", v.to_string().as_str())
                        .set_body_bytes(held.archives[v - 1].clone())
                }
                ("POST", "publish/pending") => {
                    let body: Value = serde_json::from_slice(&req.body).unwrap();
                    held.uploads.push(body.clone());
                    if let Some((status, e)) = self.refuse_upload.lock().unwrap().clone() {
                        return ResponseTemplate::new(status).set_body_json(e);
                    }
                    let digest = body["digest_hex"].as_str().unwrap().to_owned();
                    let mut msg = b"mastersos-bundle-v1\n".to_vec();
                    msg.extend_from_slice(&hex_decode(&digest));
                    held.pending = Some(digest.clone());
                    let mut answer = json!({
                        "pending_id": PID, "version": body["frame"]["version"],
                        "digest_hex": digest, "message_b64": STANDARD.encode(&msg),
                        "expires_at": "2026-11-21T05:30:00Z",
                        "trust_change": {"added": [], "removed": []},
                        "warnings": [{"code": "wifi_weak",
                            "message": "psk guestpass1 is weak\u{1b}[2K"}]
                    });
                    if let Value::Object(lie) = &*self.lie.lock().unwrap() {
                        for (k, v) in lie {
                            answer[k] = v.clone();
                        }
                    }
                    ResponseTemplate::new(201).set_body_json(answer)
                }
                ("DELETE", r) if r.starts_with("publish/pending/") => {
                    held.deletes.push(r.to_owned());
                    held.pending = None;
                    ResponseTemplate::new(204)
                }
                ("POST", r) if r == commit => {
                    held.commits.push(req.body.clone());
                    if let Some((status, e)) = self.refuse_commit.lock().unwrap().clone() {
                        return ResponseTemplate::new(status).set_body_json(e);
                    }
                    let up = read_archive(&req.body).unwrap();
                    let digest = hex(&content_digest(&up.contents));
                    assert_eq!(
                        held.pending.take(),
                        Some(digest),
                        "the commit is the upload"
                    );
                    held.archives.push(req.body.clone());
                    let v = held.archives.len();
                    ResponseTemplate::new(200).set_body_json(json!({ "version": v }))
                }
                ("POST", "heartbeat") => {
                    let body: Value = serde_json::from_slice(&req.body).unwrap();
                    held.heartbeats
                        .push(body["heartbeat"].as_str().unwrap().to_owned());
                    match self.refuse_heartbeat.lock().unwrap().clone() {
                        Some((status, e)) => ResponseTemplate::new(status).set_body_json(e),
                        None => ResponseTemplate::new(204),
                    }
                }
                other => panic!("unexpected request {other:?}"),
            }
        }
    }

    async fn new_school() -> (MockServer, School) {
        let s = MockServer::start().await;
        let school = School::default();
        Mock::given(path_regex("^/api/cli/v1/.*$"))
            .respond_with(school.clone())
            .mount(&s)
            .await;
        (s, school)
    }

    fn server(s: &MockServer) -> Server {
        Server::new(&s.uri(), Some(SID), Credentials::fixed("t")).unwrap()
    }

    /// A directory for a school that has published nothing, trusting `k`; edited after `init`
    /// would leave it equal to its base, so there is something to publish.
    fn first_dir(t: &Path, s: &MockServer, k: &Kit) -> Workdir {
        let meta = Meta {
            server: s.uri(),
            school_id: SID.into(),
            base_version: 0,
        };
        let w = Workdir::init(&t.join("school"), meta, &manifest_trusting(k)).unwrap();
        let pins = w.test_pins();
        w.with_pins(pins)
    }

    /// Version 1 trusting `trusted`, signed by `trusted`, published on `school`, and a directory
    /// pulled from it on this computer (its pin holds version 1 and its trust), then edited.
    fn published_dir(t: &Path, s: &MockServer, school: &School, trusted: &Kit) -> Workdir {
        let text = stamp(
            &manifest_trusting(trusted),
            1,
            "2026-11-20T00:00:00Z",
            Some("Demo School"),
        )
        .unwrap();
        let mut files = BTreeMap::new();
        files.insert("files/a.txt".to_string(), b"hello".to_vec());
        let contents = Contents {
            manifest_text: text,
            files,
        };
        school
            .held
            .lock()
            .unwrap()
            .archives
            .push(pack(&contents, &trusted.signer()).unwrap());
        let meta = Meta {
            server: s.uri(),
            school_id: SID.into(),
            base_version: 1,
        };
        let w = Workdir::write_pulled(&t.join("school"), meta, &contents, false)
            .unwrap()
            .pinned();
        // The pin `pinned` wrote, with version 1's trust.
        let origin = crate::server::check_origin(&s.uri()).unwrap();
        let pin_file = w
            .test_pins()
            .join(format!("{}.toml", chain::pin_name_v1(&origin, SID)));
        let mut pin = chain::load_pin(&pin_file).unwrap().unwrap();
        assert_eq!(pin.digest_hex, hex(&content_digest(&contents)));
        pin.trust = vec![trusted.trust_key()];
        std::fs::write(&pin_file, toml::to_string(&pin).unwrap()).unwrap();
        edit(&w);
        w
    }

    fn edit(w: &Workdir) {
        let text = w
            .manifest()
            .unwrap()
            .replace("name = \"Ungrouped\"", "name = \"Everyone\"");
        std::fs::write(w.root.join("manifest.toml"), text).unwrap();
    }

    /// Publish `w` with `signer` (its key `me`), `--yes` or the answers in `confirm`.
    async fn run(
        s: &MockServer,
        w: &Workdir,
        signer: &Counting,
        yes: bool,
        confirm: &str,
    ) -> (Result<PublishOutcome, CliError>, String) {
        let server = server(s);
        let pins = w.test_pins();
        let mut out = Vec::new();
        let r = publish_with(
            &server,
            w,
            signer,
            &signer.inner.trust_key(),
            PublishOpts {
                allow_reroute: &[],
                yes,
                pin_dir: &pins,
                fingerprints: &[],
            },
            now(),
            &mut confirm.as_bytes(),
            &mut out,
        )
        .await;
        (r, String::from_utf8(out).unwrap())
    }

    fn uploaded_record(w: &Workdir) -> bool {
        w.root.join(".mastersos").join("uploaded").exists()
    }

    #[tokio::test]
    async fn publish_posts_frame_then_commits_signed_archive() {
        let (s, school) = new_school().await;
        let t = tempfile::tempdir().unwrap();
        let k = kit();
        let w = published_dir(t.path(), &s, &school, &k);
        let signer = Counting::of(&k);
        let (r, out) = run(&s, &w, &signer, true, "").await;
        let PublishOutcome::Published {
            version,
            digest_hex,
            checkin,
            trust_change,
            warnings,
        } = r.unwrap_or_else(|e| panic!("{e:?}\n{out}"));
        assert_eq!(version, 2);
        assert_eq!(trust_change, TrustChange::default());
        let held = school.held.lock().unwrap();

        // The upload: the frame of the stamped text and the digest computed here.
        assert_eq!(held.uploads.len(), 1);
        let archive = read_archive(held.archives.last().unwrap()).unwrap();
        let stamped = &archive.contents.manifest_text;
        assert!(stamped.contains("version = 2"), "{stamped}");
        assert!(
            stamped.contains("issued_at = \"2026-11-21T05:00:00Z\""),
            "{stamped}"
        );
        assert!(stamped.contains("guestpass1"), "the secret is filled in");
        assert_eq!(
            held.uploads[0]["frame"],
            serde_json::to_value(frame_of(stamped).unwrap()).unwrap()
        );
        assert_eq!(held.uploads[0]["digest_hex"], digest_hex);
        assert_eq!(digest_hex, hex(&content_digest(&archive.contents)));
        let body_keys: Vec<&String> = held.uploads[0].as_object().unwrap().keys().collect();
        assert_eq!(body_keys, ["digest_hex", "frame"]);

        // The commit: the signed archive, its signature by the school key over the digest.
        assert_eq!(held.commits.len(), 1);
        let sig: mastersos_bundle::SignatureFile = toml::from_str(&archive.signature_toml).unwrap();
        verify_signature(&signed_message(&archive.contents), &sig, &[k.trust_key()]).unwrap();
        assert!(held.deletes.is_empty(), "{:?}", held.deletes);

        // The check-in: for that version and digest, 30 days.
        assert_eq!(held.heartbeats.len(), 1);
        let hb = Heartbeat::parse(&held.heartbeats[0]).unwrap();
        assert_eq!(hb.statement.version, 2);
        assert_eq!(hb.statement.digest_hex, digest_hex);
        assert_eq!(hb.statement.issued_at, now().timestamp());
        assert_eq!(hb.statement.not_after - hb.statement.issued_at, 30 * 86_400);
        mastersos_bundle::verify_heartbeat(&held.heartbeats[0], &[k.trust_key()]).unwrap();
        assert_eq!(checkin, CheckIn::Until(now() + chrono::Duration::days(30)));
        // Two signatures: the version and its check-in.
        assert_eq!(signer.signed(), 2);

        // The server's warning, cleaned of the secret value and the control sequence.
        assert_eq!(warnings.len(), 1);
        let shown = warnings[0]["message"].as_str().unwrap();
        assert!(
            !shown.contains("guestpass1") && !shown.contains('\u{1b}'),
            "{shown}"
        );
        assert!(
            !out.contains("guestpass1") && !out.contains('\u{1b}'),
            "{out}"
        );
        assert!(out.contains("Check code: "), "{out}");

        // This computer moved on: the base is version 2, verified against the advanced pin.
        assert_eq!(w.meta().unwrap().base_version, 2);
        w.verify_base().unwrap();
        assert!(!uploaded_record(&w));
    }

    #[tokio::test]
    async fn publish_stamps_the_organisation_name() {
        let (s, school) = new_school().await;
        let t = tempfile::tempdir().unwrap();
        let k = kit();
        let w = first_dir(t.path(), &s, &k);
        let signer = Counting::of(&k);
        let (r, out) = run(&s, &w, &signer, true, "").await;
        r.unwrap_or_else(|e| panic!("{e:?}\n{out}"));
        let archive = read_archive(&school.held.lock().unwrap().archives[0]).unwrap();
        assert!(
            archive
                .contents
                .manifest_text
                .contains("name = \"Demo School\""),
            "{}",
            archive.contents.manifest_text
        );
        assert!(w.manifest().unwrap().contains("name = \"Demo School\""));

        // A school the server does not list for this account: nothing is uploaded.
        let (s, school) = school_listing(json!([
            {"id": "0192f3a4-5b6c-7d8e-9f00-aabbccddeeff", "name": "Other", "time_zone": "UTC"}
        ]))
        .await;
        let t = tempfile::tempdir().unwrap();
        let w = first_dir(t.path(), &s, &k);
        let (r, _) = run(&s, &w, &signer, true, "").await;
        let e = r.unwrap_err();
        assert_eq!(e.code, "not_configured");
        assert_eq!(
            e.message,
            format!("the server does not list school {SID} for this account")
        );
        assert!(school.held.lock().unwrap().uploads.is_empty());
    }

    async fn school_listing(list: Value) -> (MockServer, School) {
        let (s, school) = new_school().await;
        *school.schools.lock().unwrap() = Some(list);
        (s, school)
    }

    /// A lying answer to the upload: the upload is deleted, nothing is signed or committed, and
    /// nothing is recorded as uploaded.
    async fn lie_signs_nothing(lie: Value) {
        let (s, school) = new_school().await;
        let t = tempfile::tempdir().unwrap();
        let k = kit();
        let w = published_dir(t.path(), &s, &school, &k);
        *school.lie.lock().unwrap() = lie.clone();
        let signer = Counting::of(&k);
        let (r, out) = run(&s, &w, &signer, true, "").await;
        let e = r.unwrap_err();
        assert_eq!(e.code, "digest_mismatch", "{lie}: {e:?}");
        assert!(
            e.message.contains("does not hold what was uploaded"),
            "{}",
            e.message
        );
        assert_eq!(signer.signed(), 0, "{lie}");
        let held = school.held.lock().unwrap();
        assert!(held.commits.is_empty(), "{lie}");
        assert!(held.heartbeats.is_empty(), "{lie}");
        assert_eq!(held.deletes, [format!("publish/pending/{PID}")], "{lie}");
        assert!(!uploaded_record(&w), "{lie}");
        assert_eq!(w.meta().unwrap().base_version, 1);
        assert!(!out.contains("Check code"), "{out}");
    }

    #[tokio::test]
    async fn echoed_digest_mismatch_signs_nothing() {
        lie_signs_nothing(json!({"digest_hex": "ab".repeat(32)})).await;
    }

    #[tokio::test]
    async fn echoed_digest_must_be_exact_lowercase_hex() {
        // The server's own digest, in capitals: not the wire form, refused like any other.
        let (s, school) = new_school().await;
        let t = tempfile::tempdir().unwrap();
        let k = kit();
        let w = published_dir(t.path(), &s, &school, &k);
        let signer = Counting::of(&k);
        // Learn the digest (the same in every run: the content and the time are fixed).
        *school.lie.lock().unwrap() = json!({"digest_hex": "X"});
        let (r, _) = run(&s, &w, &signer, true, "").await;
        assert_eq!(r.unwrap_err().code, "digest_mismatch");
        let digest = school.held.lock().unwrap().uploads[0]["digest_hex"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(digest, digest.to_lowercase());
        lie_signs_nothing(json!({"digest_hex": digest.to_uppercase()})).await;
    }

    #[tokio::test]
    async fn echoed_message_mismatch_signs_nothing() {
        let mut other = b"mastersos-bundle-v1\n".to_vec();
        other.extend_from_slice(&[0u8; 32]);
        lie_signs_nothing(json!({"message_b64": STANDARD.encode(&other)})).await;
    }

    #[tokio::test]
    async fn echoed_version_or_id_mismatch_signs_nothing() {
        lie_signs_nothing(json!({"version": 3})).await;
        let (s, school) = new_school().await;
        let t = tempfile::tempdir().unwrap();
        let k = kit();
        let w = published_dir(t.path(), &s, &school, &k);
        *school.lie.lock().unwrap() = json!({"pending_id": "../../keys"});
        let signer = Counting::of(&k);
        let (r, _) = run(&s, &w, &signer, true, "").await;
        assert_eq!(r.unwrap_err().code, "digest_mismatch");
        assert_eq!(signer.signed(), 0);
        let held = school.held.lock().unwrap();
        assert!(held.commits.is_empty());
        // The id stays in its own segment.
        assert_eq!(held.deletes, ["publish/pending/..%2F..%2Fkeys"]);
    }

    #[tokio::test]
    async fn version_conflict_names_the_newer_version() {
        let (s, school) = new_school().await;
        let t = tempfile::tempdir().unwrap();
        let k = kit();
        let w = published_dir(t.path(), &s, &school, &k);
        *school.refuse_upload.lock().unwrap() = Some((
            409,
            envelope("version_conflict", json!({"latest_version": 6})),
        ));
        let signer = Counting::of(&k);
        let (r, _) = run(&s, &w, &signer, true, "").await;
        let e = r.unwrap_err();
        assert_eq!(e.code, "version_conflict");
        assert!(
            e.message.contains("v6") && e.message.contains("base v1"),
            "{}",
            e.message
        );
        assert!(e.message.contains("pull --force"), "{}", e.message);
        assert_eq!(signer.signed(), 0);
        assert_eq!(w.meta().unwrap().base_version, 1);

        // Seen here first: the verified chain is ahead of the base; nothing is uploaded.
        let (s, school) = new_school().await;
        let t = tempfile::tempdir().unwrap();
        let w = published_dir(t.path(), &s, &school, &k);
        let v2 = Contents {
            manifest_text: stamp(
                &manifest_trusting(&k),
                2,
                "2026-11-20T01:00:00Z",
                Some("Demo School"),
            )
            .unwrap(),
            files: BTreeMap::new(),
        };
        school
            .held
            .lock()
            .unwrap()
            .archives
            .push(pack(&v2, &k.signer()).unwrap());
        let (r, out) = run(&s, &w, &signer, true, "").await;
        let e = r.unwrap_err();
        assert_eq!(e.code, "version_conflict", "{out}");
        assert!(e
            .message
            .contains("Someone published v2 after your base v1"));
        assert!(school.held.lock().unwrap().uploads.is_empty());
    }

    #[tokio::test]
    async fn feature_unsupported_lists_devices() {
        let (s, school) = new_school().await;
        let t = tempfile::tempdir().unwrap();
        let k = kit();
        let w = published_dir(t.path(), &s, &school, &k);
        *school.refuse_upload.lock().unwrap() = Some((
            422,
            envelope(
                "feature_unsupported",
                json!({"feature": "kiosk", "devices": [
                    {"device_id": "lab-01", "serial": "SN1\u{1b}[2K", "os_version": "1.4.0",
                        "last_seen": "2026-11-19T08:00:00Z", "extra": "x"},
                    {"device_id": "lab-02", "serial": null, "os_version": "1.3.9",
                        "last_seen": "2026-11-18T08:00:00Z"}
                ]}),
            ),
        ));
        let signer = Counting::of(&k);
        let (r, _) = run(&s, &w, &signer, true, "").await;
        let e = r.unwrap_err();
        assert_eq!(e.code, "feature_unsupported");
        assert!(e.message.contains("`kiosk`"), "{}", e.message);
        assert!(e.message.contains("2 Device(s)"), "{}", e.message);
        assert_eq!(e.problems.len(), 2);
        assert_eq!(e.problems[0]["device_id"], "lab-01");
        assert_eq!(e.problems[0]["os_version"], "1.4.0");
        assert_eq!(e.problems[0]["last_seen"], "2026-11-19T08:00:00Z");
        assert!(e.problems[0].get("extra").is_none());
        assert!(!e.problems[0]["serial"].as_str().unwrap().contains('\u{1b}'));
        assert_eq!(e.problems[1]["serial"], Value::Null);

        // The terminal: a table with one row per Device.
        let (stdout, stderr) = crate::server::render_error(&e, false);
        assert!(stdout.is_empty());
        let lines: Vec<&str> = stderr.lines().collect();
        assert!(lines[0].starts_with("mastersos: Not published"), "{stderr}");
        for col in ["DEVICE ID", "SERIAL", "OS VERSION", "LAST SEEN"] {
            assert!(lines[1].contains(col), "{stderr}");
        }
        assert!(
            lines[2].contains("lab-01") && lines[2].contains("1.4.0"),
            "{stderr}"
        );
        assert!(
            lines[3].contains("lab-02") && lines[3].contains(" - "),
            "{stderr}"
        );
        assert!(!stderr.contains('\u{1b}'), "{stderr}");
        // --json: the same rows in `problems`.
        let (stdout, _) = crate::server::render_error(&e, true);
        let v: Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(v["error"]["code"], "feature_unsupported");
        assert_eq!(v["error"]["problems"][1]["device_id"], "lab-02");
        assert_eq!(v["error"]["problems"][1]["os_version"], "1.3.9");
    }

    #[tokio::test]
    async fn clock_skew_is_explained() {
        let (s, school) = new_school().await;
        let t = tempfile::tempdir().unwrap();
        let k = kit();
        let w = published_dir(t.path(), &s, &school, &k);
        *school.refuse_upload.lock().unwrap() = Some((422, envelope("clock_skew", Value::Null)));
        let (r, _) = run(&s, &w, &Counting::of(&k), true, "").await;
        let e = r.unwrap_err();
        assert_eq!(e.code, "clock_skew");
        assert!(
            e.message
                .contains("this computer's clock is off by more than 10 minutes"),
            "{}",
            e.message
        );
    }

    #[tokio::test]
    async fn kit_not_in_latest_trust_uploads_nothing() {
        let (s, school) = new_school().await;
        let t = tempfile::tempdir().unwrap();
        // Version 1 trusts another key; the directory now trusts ours too.
        let w = published_dir(t.path(), &s, &school, &other_kit());
        let k = kit();
        let text = workdir::add_trusted_key(
            &w.manifest().unwrap(),
            &k.trust_key(),
            &k.escrow_recipient(),
        )
        .unwrap();
        std::fs::write(w.root.join("manifest.toml"), text).unwrap();
        let signer = Counting::of(&k);
        let (r, out) = run(&s, &w, &signer, true, "").await;
        let e = r.unwrap_err();
        assert_eq!(e.code, "key_not_trusted", "{e:?}\n{out}");
        assert!(school.held.lock().unwrap().uploads.is_empty());
        assert_eq!(signer.signed(), 0);

        // The first version: the key must be in the text's own trust.
        let (s, school) = new_school().await;
        let t = tempfile::tempdir().unwrap();
        let w = first_dir(t.path(), &s, &other_kit());
        let (r, _) = run(&s, &w, &signer, true, "").await;
        assert_eq!(r.unwrap_err().code, "key_not_trusted");
        assert!(school.held.lock().unwrap().uploads.is_empty());
    }

    #[tokio::test]
    async fn heartbeat_failure_still_publishes() {
        let (s, school) = new_school().await;
        let t = tempfile::tempdir().unwrap();
        let k = kit();
        let w = published_dir(t.path(), &s, &school, &k);
        *school.refuse_heartbeat.lock().unwrap() =
            Some((500, envelope("unavailable", Value::Null)));
        let (r, out) = run(&s, &w, &Counting::of(&k), true, "").await;
        let PublishOutcome::Published {
            version, checkin, ..
        } = r.unwrap_or_else(|e| panic!("{e:?}\n{out}"));
        assert_eq!(version, 2);
        assert!(matches!(checkin, CheckIn::Failed(_)), "{checkin:?}");
        assert_eq!(school.held.lock().unwrap().heartbeats.len(), 1);
        assert_eq!(w.meta().unwrap().base_version, 2);
        w.verify_base().unwrap();
    }

    #[tokio::test]
    async fn yes_skips_the_confirmation() {
        // --yes: nothing is read.
        let (s, school) = new_school().await;
        let t = tempfile::tempdir().unwrap();
        let k = kit();
        let w = first_dir(t.path(), &s, &k);
        let (r, out) = run(&s, &w, &Counting::of(&k), true, "").await;
        r.unwrap_or_else(|e| panic!("{e:?}\n{out}"));
        assert!(!out.contains("Type the version number"), "{out}");
        assert_eq!(school.held.lock().unwrap().commits.len(), 1);

        // A person: the version number, then `yes` for the first version's trusted keys.
        let (s, school) = new_school().await;
        let t = tempfile::tempdir().unwrap();
        let w = first_dir(t.path(), &s, &k);
        let (r, out) = run(&s, &w, &Counting::of(&k), false, "1\nyes\n").await;
        r.unwrap_or_else(|e| panic!("{e:?}\n{out}"));
        assert!(
            out.contains("Type the version number 1 to publish it: "),
            "{out}"
        );
        assert!(out.contains("type yes: "), "{out}");
        assert_eq!(school.held.lock().unwrap().commits.len(), 1);

        // A wrong number: nothing signed, the upload deleted, nothing left pending.
        let (s, school) = new_school().await;
        let t = tempfile::tempdir().unwrap();
        let w = first_dir(t.path(), &s, &k);
        let signer = Counting::of(&k);
        let (r, _) = run(&s, &w, &signer, false, "7\n").await;
        assert_eq!(r.unwrap_err().code, "cancelled");
        assert_eq!(signer.signed(), 0);
        let held = school.held.lock().unwrap();
        assert!(held.commits.is_empty());
        assert_eq!(held.deletes, [format!("publish/pending/{PID}")]);
        assert_eq!(w.meta().unwrap().base_version, 0);
    }

    #[tokio::test]
    async fn refused_commit_keeps_the_upload_private_and_deletes_it() {
        let (s, school) = new_school().await;
        let t = tempfile::tempdir().unwrap();
        let k = kit();
        let w = published_dir(t.path(), &s, &school, &k);
        *school.refuse_commit.lock().unwrap() =
            Some((422, envelope("signature_invalid", Value::Null)));
        let (r, _) = run(&s, &w, &Counting::of(&k), true, "").await;
        let e = r.unwrap_err();
        assert_eq!(e.code, "signature_invalid");
        let held = school.held.lock().unwrap();
        assert_eq!(held.deletes, [format!("publish/pending/{PID}")]);
        assert!(held.heartbeats.is_empty());
        assert_eq!(w.meta().unwrap().base_version, 1);
        // What was uploaded is kept (it holds the Wi-Fi key): private.
        let up = w.root.join(".mastersos").join("uploaded");
        assert!(std::fs::read_to_string(up.join("secrets.toml"))
            .unwrap()
            .contains("guestpass1"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&up), 0o700);
            for f in [
                "manifest.toml",
                "secrets.toml",
                "upload.toml",
                "files/a.txt",
            ] {
                assert_eq!(mode(&up.join(f)), 0o600, "{f}");
            }
        }
    }

    #[tokio::test]
    async fn heartbeat_command_signs_the_latest_verified_version() {
        let (s, school) = new_school().await;
        let t = tempfile::tempdir().unwrap();
        let k = kit();
        let w = published_dir(t.path(), &s, &school, &k);
        let digest = {
            let held = school.held.lock().unwrap();
            hex(&content_digest(
                &read_archive(&held.archives[0]).unwrap().contents,
            ))
        };
        let pins = w.test_pins();
        let signer = Counting::of(&k);
        let run_hb = |yes: bool, confirm: &'static str| {
            let server = server(&s);
            let pins = pins.clone();
            let signer = &signer;
            async move {
                let mut out = Vec::new();
                let r = heartbeat_with(
                    &server,
                    signer,
                    &signer.inner.trust_key(),
                    HeartbeatOpts {
                        days: 7,
                        yes,
                        pin_dir: &pins,
                        fingerprints: &[],
                    },
                    now(),
                    &mut confirm.as_bytes(),
                    &mut out,
                )
                .await;
                (r, String::from_utf8(out).unwrap())
            }
        };
        let (r, out) = run_hb(false, "1\n").await;
        let c = r.unwrap_or_else(|e| panic!("{e:?}\n{out}"));
        assert_eq!(c.version, 1);
        assert_eq!(c.digest_hex, digest);
        assert_eq!(c.not_after, now() + chrono::Duration::days(7));
        assert!(out.contains("Type the version number 1 to sign: "), "{out}");
        let text = school.held.lock().unwrap().heartbeats[0].clone();
        let st = mastersos_bundle::verify_heartbeat(&text, &[k.trust_key()]).unwrap();
        assert_eq!(st.version, 1);
        assert_eq!(st.digest_hex, digest);
        assert_eq!(st.not_after - st.issued_at, 7 * 86_400);

        // Someone published meanwhile.
        *school.refuse_heartbeat.lock().unwrap() = Some((409, envelope("not_latest", Value::Null)));
        let (r, _) = run_hb(true, "").await;
        let e = r.unwrap_err();
        assert_eq!(e.code, "not_latest");
        assert!(
            e.message
                .contains("someone published meanwhile; run it again"),
            "{}",
            e.message
        );

        // A key the verified version does not trust signs nothing.
        let stranger = Counting::of(&other_kit());
        let server = server(&s);
        let r = heartbeat_with(
            &server,
            &stranger,
            &stranger.inner.trust_key(),
            HeartbeatOpts {
                days: 7,
                yes: true,
                pin_dir: &pins,
                fingerprints: &[],
            },
            now(),
            &mut std::io::empty(),
            &mut Vec::new(),
        )
        .await;
        assert_eq!(r.unwrap_err().code, "key_not_trusted");
        assert_eq!(stranger.signed(), 0);
    }

    #[test]
    fn reroute_refusal_never_renders_an_invalid_name() {
        let r = RerouteRefused {
            names: vec!["ok-name".into(), "x; curl evil | sh".into()],
        };
        let text = r.to_string();
        assert!(
            !text.contains("curl") && !text.contains("--allow-reroute"),
            "{text}"
        );
        let r = RerouteRefused {
            names: vec!["Upper".into()],
        };
        assert!(!r.to_string().contains("Upper"));
    }

    #[test]
    fn checked_line_says_no_problems_only_without_warnings() {
        assert_eq!(checked_line(&[], 0), "Checked: no problems");
        let warn = Lint::new(LintLevel::Warning, "no_admins", "x");
        assert_eq!(
            checked_line(std::slice::from_ref(&warn), 0),
            "Checked: no errors, 1 warning (above)"
        );
        assert_eq!(
            checked_line(std::slice::from_ref(&warn), 1),
            "Checked: no errors, 2 warnings (above)"
        );
        let info = Lint::new(LintLevel::Info, "note", "x");
        assert_eq!(checked_line(&[info], 0), "Checked: no problems");
    }

    #[test]
    fn pending_ids_are_uuids() {
        assert!(is_uuid(PID));
        assert!(is_uuid(&PID.to_uppercase()));
        for bad in [
            "p1",
            "",
            "../../keys",
            &format!("{PID}0"),
            &PID.replace('-', "_"),
        ] {
            assert!(!is_uuid(bad), "{bad}");
        }
    }
}
