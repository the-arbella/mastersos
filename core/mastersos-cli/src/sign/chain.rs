//! Verifying the chain here: from the pinned version to the latest, one version at a time, as the
//! agent does (Ruling 15).
//!
//! The pin is `<pin_dir>/<host>[_<port>]+<school>.toml` (one chain per origin and school): the
//! version verified last time, its content digest and its trust.
//! - **No pin** (first use): the fingerprint of every key in the latest version's trust is
//!   printed, a school key file's own key marked. Without a person (`--yes`, `--json`, or stdin
//!   not a terminal) the trust is taken only when every key in it is anchored ([`Anchors`]): a
//!   school key file given to the command with that key, or a `--trust-fingerprint` equal to its
//!   fingerprint. A key file anchors its own key only, never the rest of the set; a fingerprint
//!   that is not one of the keys is refused. Otherwise `trust_not_confirmed` names the keys not
//!   anchored and nothing is written. A person at a terminal confirms the whole set by typing
//!   `yes` after comparing it with the keys page. The package must then verify under the
//!   anchored set before the pin is recorded.
//! - **A pin of the old admin API only** (`<host>[_<port>].toml`, made before protocol v1): the
//!   chain is verified forward from it exactly as from a pin; one that does not lead to the chain
//!   the server serves now is refused (`chain_tampered`), `--yes` or not. When it connects the new
//!   pin is written and the old file is left as it is.
//! - **A pin**: first the pinned version's content must be unchanged (same digest), then every
//!   later version goes through `accept(package, current trust, Some(current version))`; any
//!   version that fails is reported as an earlier version failing verification, and the pin stays.
//!
//! A chain is identified by the pin on disk: (host, version, content digest, trust). A new pin
//! replaces it only when the caller verified forward from exactly that pin and the version is
//! strictly higher ([`save_pin`]). Anything else (a lower or equal version, a pin that came from
//! another chain, a pin that changed meanwhile) is refused; there is no override flag, the
//! operator deletes the pin file to start over.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use mastersos_bundle::{
    accept, accept_signed, check_recovery_signed, content_digest, read_archive, recipients_changed,
    BundleError, Contents, KitChange, Manifest, TrustKey,
};
use serde::{Deserialize, Serialize};

use super::{ask, hex, key_line, TrustDelta};
use crate::server::{CliError, Server};

/// `<host>[_<port>]+<school>`: the pin file name (without `.toml`) of a protocol v1 school. A
/// `:` (an IPv6 host) becomes `_` as well, so the name is a file name everywhere.
pub fn pin_name_v1(origin: &reqwest::Url, school: &str) -> String {
    let mut name = origin.host_str().unwrap_or_default().replace(':', "_");
    if let Some(p) = origin.port() {
        name.push_str(&format!("_{p}"));
    }
    format!("{name}+{school}")
}

/// What a protocol v1 pin records as its chain: `<origin>+<school>`.
pub fn pin_key_v1(origin: &reqwest::Url, school: &str) -> String {
    format!("{}+{school}", origin.origin().ascii_serialization())
}

/// The pin file name (without `.toml`) of the school `s` speaks for.
fn pin_name(s: &Server) -> Result<String, CliError> {
    Ok(pin_name_v1(s.origin(), s.school()?))
}

/// What the pin records as its `host`.
fn pin_key(s: &Server) -> Result<String, CliError> {
    Ok(pin_key_v1(s.origin(), s.school()?))
}

/// For people: what this computer checks.
fn describe(s: &Server) -> String {
    format!(
        "school {} on {}",
        s.school().unwrap_or("?"),
        s.origin().origin().ascii_serialization()
    )
}

/// The chain does not verify: a version fails its checks, the version went backwards, or the pin
/// belongs to another chain. Reported as `chain_tampered`.
#[derive(Debug)]
pub struct Tampered(pub String);

impl std::fmt::Display for Tampered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Tampered {}

/// The person did not confirm. Reported as `cancelled`.
#[derive(Debug)]
pub struct Cancelled(pub String);

impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Cancelled {}

fn tamper(msg: String) -> anyhow::Error {
    anyhow::Error::new(Tampered(msg))
}

fn cancel(msg: &str) -> anyhow::Error {
    anyhow::Error::new(Cancelled(msg.to_owned()))
}

/// A chain error as the command line reports it: a server or transport error keeps its code;
/// [`Tampered`] is `chain_tampered`, [`Cancelled`] `cancelled`, anything else (the pin files) is
/// `local_file`. Strings from the server are escaped.
pub fn to_cli_error(e: anyhow::Error) -> CliError {
    if let Some(c) = e.downcast_ref::<CliError>() {
        return c.clone();
    }
    let text = crate::safe::text(&format!("{e:#}"));
    if e.downcast_ref::<Tampered>().is_some() {
        CliError::new("chain_tampered", &text)
    } else if e.downcast_ref::<Cancelled>().is_some() {
        CliError::new("cancelled", &text)
    } else {
        CliError::new("local_file", &text)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    /// The chain this pin is for: `<origin>+<school>` ([`pin_key_v1`]).
    pub host: String,
    pub version: u64,
    /// This version's `content_digest` (lower-case hex): checked next time, so the server cannot
    /// swap the pinned version.
    pub digest_hex: String,
    pub trust: Vec<TrustKey>,
    /// Every version this computer verified, with its content digest, in order. The only record
    /// of history that can be trusted later: the manifests link to no earlier digest, so a past
    /// version cannot be authenticated from the pin alone. Pin files from before this field read
    /// as empty (see [`load_pin`], which adds the pinned version).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified: Vec<VerifiedVersion>,
}

impl Pin {
    /// The pinned version itself is always a verified one (pin files from before the list
    /// existed have none): add it.
    fn normalized(mut self) -> Pin {
        let digest = self.digest_hex.clone();
        record_verified(&mut self.verified, self.version, &digest);
        self
    }
}

/// A version this computer verified and the `content_digest` (lower-case hex) it had.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedVersion {
    pub version: u64,
    pub digest_hex: String,
}

/// Add `version` to a verified list (once; the list stays ordered by version).
pub fn record_verified(list: &mut Vec<VerifiedVersion>, version: u64, digest_hex: &str) {
    if !list.iter().any(|e| e.version == version) {
        list.push(VerifiedVersion {
            version,
            digest_hex: digest_hex.to_owned(),
        });
        list.sort_by_key(|e| e.version);
    }
}

/// The contents of an old version, taken only if this computer verified it before: `archive` must
/// hold exactly the digest recorded for `want`. A version that is not recorded (published before
/// the first use here, or refused by machines) cannot be checked and is an error.
pub fn recorded_contents(
    verified: &[VerifiedVersion],
    want: u64,
    archive: &[u8],
) -> Result<Contents> {
    let rec = recorded_version(verified, want)?;
    let contents = read_archive(archive)
        .map_err(|e| tampered(want, e))?
        .contents;
    if hex(&content_digest(&contents)) != rec.digest_hex {
        return Err(tampered(
            want,
            "content differs from what this computer verified",
        ));
    }
    Ok(contents)
}

/// The record of `want`, or the error [`recorded_contents`] gives when there is none.
pub fn recorded_version(verified: &[VerifiedVersion], want: u64) -> Result<&VerifiedVersion> {
    verified
        .iter()
        .find(|e| e.version == want)
        .with_context(|| {
            format!(
                "version {want} was published before this computer started verifying this school; \
             it cannot be checked"
            )
        })
}

/// The latest verified version.
///
/// `version`, `digest_hex`, `trust` and `contents` are the last version machines accept: the base
/// the next signature is checked and diffed against, and what the pin records. `latest` is the
/// newest version on the server's chain. They differ only after the operator confirmed past a
/// version that violates R7/R8 (machines refuse it and stay on the version before it; Task 24c
/// fix round 1, I2): the next version is `latest + 1`, but its trust and recipient changes are
/// still shown against what machines actually run.
#[derive(Clone)]
pub struct Verified {
    pub version: u64,
    pub digest_hex: String,
    pub trust: Vec<TrustKey>,
    /// The manifest and files of the latest verified version.
    pub contents: Contents,
    /// The newest version on the chain (`>= version`).
    pub latest: u64,
    /// Every version verified so far on this computer (the pin's [`Pin::verified`]).
    pub history: Vec<VerifiedVersion>,
}

/// The contents hold the filled manifest (Wi-Fi keys, the IT password hash): Debug shows only
/// their size.
impl std::fmt::Debug for Verified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verified")
            .field("version", &self.version)
            .field("digest_hex", &self.digest_hex)
            .field("trust", &self.trust)
            .field(
                "contents",
                &format_args!(
                    "<redacted: manifest {} bytes, {} files>",
                    self.contents.manifest_text.len(),
                    self.contents.files.len()
                ),
            )
            .field("latest", &self.latest)
            .field("history", &self.history)
            .finish()
    }
}

pub fn pin_path(pin_dir: &Path, src: &Server) -> Result<PathBuf, CliError> {
    Ok(pin_dir.join(format!("{}.toml", pin_name(src)?)))
}

/// The content digest (lower-case hex) this computer recorded for `version` of school `school` on
/// `server` in its pin under `pin_dir`: `None` when there is no pin or the version was never
/// verified here. Read offline, so a local copy of a version can be checked against what was
/// verified. Only the protocol v1 pin (`<host>[_<port>]+<school>`, one per origin and school) is
/// read: a pin of the old admin API is taken over only by [`verify_chain`], which verifies forward
/// from it.
pub fn recorded_digest(
    pin_dir: &Path,
    server: &str,
    school: &str,
    version: u64,
) -> Result<Option<String>> {
    let Some(path) = crate::server::check_origin(server)
        .ok()
        .filter(|_| crate::server::is_school_id(school))
        .map(|o| pin_dir.join(format!("{}.toml", pin_name_v1(&o, school))))
    else {
        return Ok(None);
    };
    Ok(load_pin(&path)?.and_then(|p| {
        p.verified
            .into_iter()
            .find(|e| e.version == version)
            .map(|e| e.digest_hex)
    }))
}

pub(crate) fn load_pin(path: &Path) -> Result<Option<Pin>> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let pin: Pin = toml::from_str(&text)
                .with_context(|| format!("Cannot read the pin file {}", path.display()))?;
            Ok(Some(pin.normalized()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("Could not read the pin file {}", path.display())),
    }
}

/// Write `pin`, which the caller derived by verifying forward from `prev` (the pin on disk when
/// it started; `None` when there was none). Refused when the pin on disk is not `prev` (another
/// chain, or it changed meanwhile), when `pin` would not move forward, or when the host differs.
///
/// The compare and the write happen under an exclusive `flock` on `<pin>.lock`, so two
/// `mastersos` runs against the same server cannot both pass the compare and overwrite each
/// other. The new pin goes to a fresh temporary file (created exclusively, so it never follows a
/// planted symlink), is fsynced, renamed over the pin, and the directory is fsynced: a crash
/// leaves the old pin or the new one, never half of one.
pub fn save_pin(path: &Path, prev: Option<&Pin>, pin: &Pin) -> Result<()> {
    let dir = path.parent().context("the pin path has no directory")?;
    crate::platform::private_dir(dir, true)?;
    let _lock = lock_pin(path)?;
    let prev = prev.cloned().map(Pin::normalized);
    let prev = prev.as_ref();
    let pin = &pin.clone().normalized();
    match (load_pin(path)?, prev) {
        (None, None) => {}
        (Some(cur), Some(prev)) if cur == *prev => {
            if pin.host != cur.host {
                return Err(tamper(format!(
                    "refusing to replace the pin in {}: it is for {}, the new one for {}",
                    path.display(),
                    cur.host,
                    pin.host
                )));
            }
            if pin.version <= cur.version {
                return Err(tamper(format!(
                    "refusing to move the pin in {} backwards from version {} to {}: possible rollback",
                    path.display(),
                    cur.version,
                    pin.version
                )));
            }
        }
        (Some(cur), _) => return Err(tamper(format!(
            "refusing to replace the pin in {} (version {}): the new pin was not verified forward \
             from it (another chain, or the pin changed meanwhile). Delete that file only if you are \
             sure the server was reset on purpose",
            path.display(),
            cur.version
        ))),
        (None, Some(_)) => bail!(
            "the pin {} disappeared while verifying; run mastersos verify again",
            path.display()
        ),
    }
    let text = toml::to_string(pin).context("Could not serialise the pin")?;
    write_replace(dir, path, text.as_bytes())
}

/// Hold an exclusive advisory lock on `<pin>.lock` until the guard drops. The lock file is
/// opened without following a symlink.
#[cfg(unix)]
fn lock_pin(path: &Path) -> Result<nix::fcntl::Flock<std::fs::File>> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    let lock_path = PathBuf::from(name);
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(&lock_path)
        .with_context(|| format!("cannot open the pin lock {}", lock_path.display()))?;
    nix::fcntl::Flock::lock(f, nix::fcntl::FlockArg::LockExclusive)
        .map_err(|(_, e)| anyhow::anyhow!("cannot lock {}: {e}", lock_path.display()))
}

#[cfg(not(unix))]
fn lock_pin(_path: &Path) -> Result<()> {
    Ok(())
}

/// Replace `path` with `data`: a new uniquely named temporary file in `dir` (O_EXCL), fsync,
/// rename, fsync the directory. The temporary file is removed when anything fails.
fn write_replace(dir: &Path, path: &Path, data: &[u8]) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let file_name = path
        .file_name()
        .context("the pin path has no file name")?
        .to_string_lossy()
        .into_owned();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let tmp = dir.join(format!(
        ".{file_name}.{}.{}.{nanos}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let written = opts.open(&tmp).and_then(|mut f| {
        f.write_all(data)?;
        f.sync_all()
    });
    let renamed = written.and_then(|()| std::fs::rename(&tmp, path));
    if let Err(e) = renamed {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("cannot write the pin {}", path.display()));
    }
    #[cfg(unix)]
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .with_context(|| {
            format!(
                "the pin {} was written, but syncing its directory {} failed: it may not survive a \
                 power loss",
                path.display(),
                dir.display()
            )
        })?;
    Ok(())
}

fn tampered(v: u64, why: impl std::fmt::Display) -> anyhow::Error {
    tamper(format!(
        "An earlier version fails verification; the server may have been tampered with: version {v} {}",
        crate::safe::field(&why.to_string())
    ))
}

/// What a first use may take the trusted keys from (see the module documentation).
#[derive(Debug, Clone, Default)]
pub struct Anchors {
    /// The keys of the school key files given to the command.
    pub keys: Vec<TrustKey>,
    /// `--trust-fingerprint` values (`xxxx-xxxx-xxxx-xxxx`).
    pub fingerprints: Vec<String>,
    /// A person at a terminal may confirm (not with `--yes`, not when stdin is not a terminal).
    pub interactive: bool,
}

/// Verify from the pin to the server's latest version, update the pin, and return the latest
/// verified version: the only way a chain is loaded. See the module documentation for the first
/// use and the old pins.
pub async fn verify_chain(
    src: &Server,
    pin_dir: &Path,
    anchors: &Anchors,
    confirm: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Verified, CliError> {
    verify_inner(src, pin_dir, anchors, confirm, out)
        .await
        .map_err(to_cli_error)
}

/// The pin the old admin API wrote for a protocol v1 source's host (`<host>[_<port>].toml`), with
/// the `host` it must record.
pub(crate) fn legacy_pin_path(s: &Server, pin_dir: &Path) -> Option<(PathBuf, String)> {
    let o = s.origin();
    let host = o.host_str()?.to_owned();
    let key = match o.port() {
        Some(p) => format!("{host}:{p}"),
        None => host,
    };
    Some((pin_dir.join(format!("{}.toml", key.replace(':', "_"))), key))
}

async fn verify_inner(
    src: &Server,
    pin_dir: &Path,
    anchors: &Anchors,
    confirm: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Verified> {
    let mut out = crate::safe::SafeWriter::new(out);
    let out: &mut dyn Write = &mut out;
    let path = pin_path(pin_dir, src)?;
    let key = pin_key(src)?;
    let latest = src.latest_version().await?;
    let (pin, legacy) = match load_pin(&path)? {
        Some(pin) => {
            if pin.host != key {
                return Err(tamper(format!(
                    "The pin file {} is for {}, not {key}",
                    path.display(),
                    pin.host,
                )));
            }
            (pin, None)
        }
        None => match legacy_pin_path(src, pin_dir) {
            Some((old, host)) if load_pin(&old)?.is_some() => {
                let pin = load_pin(&old)?.context("the old pin disappeared")?;
                if pin.host != host {
                    return Err(tamper(format!(
                        "The old pin file {} is for {}, not {host}",
                        old.display(),
                        pin.host
                    )));
                }
                writeln!(
                    out,
                    "Checking {} from the pin this computer recorded for {host} before ({}).",
                    describe(src),
                    old.display()
                )?;
                (pin, Some(old))
            }
            _ => return first_use(src, &path, latest, anchors, confirm, out).await,
        },
    };
    let cur = forward(src, &pin, latest, anchors.interactive, confirm, out)
        .await
        .map_err(|e| match (&legacy, e.downcast_ref::<Tampered>()) {
            (Some(old), Some(t)) => tamper(format!(
                "{t} (checked forward from the old pin {}: it does not lead to the chain the \
                 server serves now; delete that file only if it belonged to another school on \
                 this server)",
                old.display()
            )),
            _ => e,
        })?;
    if legacy.is_some() {
        save_pin(&path, None, &pin_of(src, &cur)?)?;
    } else if cur.version != pin.version {
        save_pin(&path, Some(&pin), &pin_of(src, &cur)?)?;
    }
    Ok(cur)
}

/// Verify every version after `pin` up to `latest`, one by one.
async fn forward(
    src: &Server,
    pin: &Pin,
    latest: u64,
    interactive: bool,
    confirm: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Verified> {
    if latest < pin.version {
        return Err(tamper(format!(
            "The server says the latest is version {latest}, but this computer already verified version {}: the version went backwards, the server may have been tampered with",
            pin.version
        )));
    }

    // The pinned version: its content must still be what was verified then.
    let archive = src.version_archive(pin.version).await?;
    let contents = read_archive(&archive)
        .map_err(|e| tampered(pin.version, e))?
        .contents;
    if hex(&content_digest(&contents)) != pin.digest_hex {
        return Err(tampered(
            pin.version,
            "content differs from what was verified last time",
        ));
    }

    let mut cur = Verified {
        version: pin.version,
        digest_hex: pin.digest_hex.clone(),
        trust: pin.trust.clone(),
        contents,
        latest: pin.version,
        history: pin.verified.clone(),
    };
    for v in pin.version + 1..=latest {
        let archive = src.version_archive(v).await?;
        let (b, signer) =
            accept_signed(&archive, &cur.trust, Some(cur.version)).map_err(|e| tampered(v, e))?;
        if b.manifest.version != v {
            return Err(tampered(
                v,
                format!("package says it is version {}", b.manifest.version),
            ));
        }
        let delta = TrustDelta::between(&cur.trust, &b.manifest.trust);
        if !delta.is_empty() {
            writeln!(
                out,
                "Version {v} changes the trusted keys (its signature was checked with the trusted keys of version {}):",
                cur.version
            )?;
            delta.print(out)?;
        }
        let old_recipients = Manifest::parse(&cur.contents.manifest_text)
            .map_err(|e| tampered(cur.version, e))?
            .school
            .escrow_recipients;
        if recipients_changed(&old_recipients, &b.manifest.school.escrow_recipients) {
            writeln!(
                out,
                "Version {v} changes disk unlocking (computers keep their disk recovery codes for \
                 these school keys):"
            )?;
            for r in &old_recipients {
                if !b.manifest.school.escrow_recipients.contains(r) {
                    writeln!(out, "  - {}", crate::safe::field(r))?;
                }
            }
            for r in &b.manifest.school.escrow_recipients {
                if !old_recipients.contains(r) {
                    writeln!(out, "  + {}", crate::safe::field(r))?;
                }
            }
        }
        // R7/R8: a trust or escrow-recipient change needs a recovery-kit signature. Machines
        // check this themselves (mastersos_bundle::check_recovery_signed, the same function) and
        // refuse such a version, staying on the one before it; an honest server never publishes
        // one. It showing up here means the server was compromised. Make the
        // operator look and confirm before going on; once confirmed, go on as machines do: the
        // base (trust, contents, pin) stays at the version they accept, only `latest` moves, so
        // a later kit signature is never shown the forged additions as already present.
        if let Err(BundleError::KitRequired(what)) =
            check_recovery_signed(&cur.trust, &old_recipients, &b.manifest, &signer)
        {
            // The rule ids stay out of the sentence; they are in the code above.
            let changes = match what {
                KitChange::Trust => "the trusted keys",
                KitChange::Recipients => "disk unlocking",
                KitChange::TrustAndRecipients => "the trusted keys and disk unlocking",
            };
            writeln!(
                out,
                "!!! WARNING: version {v} changes {changes} but was not approved with a school key.\n\
                 !!! An honest server never accepts this, and computers refuse it (they stay on version {}).\n\
                 !!! The server may be compromised. Check every added or changed key\n\
                 !!! above; one you do not know means someone tried to take over the computers or unlock\n\
                 !!! their disks. Approve a corrected version with a school key and check the server.",
                cur.version
            )?;
            // Only a person may go on: a piped "yes" or --yes never confirms this.
            if !interactive {
                return Err(cancel(&format!(
                    "version {v} changes {changes} without a school key's approval, and nobody \
                     can confirm going on here (--yes, --json, or stdin is not a terminal); \
                     cancelled. Check the change, then run again at a terminal"
                )));
            }
            let typed = ask(
                confirm,
                out,
                &format!("Checked version {v}'s change and still continue from it? Type yes: "),
            )
            // No input (`seed check` and other calls without a dialogue) is no confirmation either.
            .unwrap_or_default();
            if typed != "yes" {
                return Err(cancel(&format!(
                    "version {v} changes {changes} without a school key's approval; not \
                     confirmed, cancelled"
                )));
            }
            cur.latest = v;
            continue;
        }
        let digest_hex = hex(&content_digest(&b.contents));
        let mut history = std::mem::take(&mut cur.history);
        record_verified(&mut history, v, &digest_hex);
        cur = Verified {
            version: v,
            digest_hex,
            trust: b.manifest.trust,
            contents: b.contents,
            latest: v,
            history,
        };
    }
    if cur.latest != pin.version {
        writeln!(
            out,
            "Verified versions {} to {} on this computer, one by one.",
            pin.version + 1,
            cur.latest
        )?;
    }
    if cur.version != cur.latest {
        writeln!(
            out,
            "Computers stay on version {}: the versions after it that change the trusted keys or \
             disk unlocking without a school key's approval are refused. Checks start from version \
             {} again next time; the next version is {}.",
            cur.version,
            cur.version,
            cur.latest + 1
        )?;
    }
    Ok(cur)
}

pub(crate) fn pin_of(src: &Server, v: &Verified) -> Result<Pin, CliError> {
    Ok(Pin {
        host: pin_key(src)?,
        version: v.version,
        digest_hex: v.digest_hex.clone(),
        trust: v.trust.clone(),
        verified: v.history.clone(),
    })
}

/// The key id that signed an archive (its `signature` member) when no entry of the archive's own
/// trust has that id (ruling R23): a computer or Device that starts from that version cannot
/// verify it. `None` when the signer is in the trust or the member cannot be read.
pub(crate) fn signer_outside_own_trust(signature_toml: &str, trust: &[TrustKey]) -> Option<String> {
    let s: mastersos_bundle::SignatureFile = toml::from_str(signature_toml).ok()?;
    (!trust.iter().any(|t| t.id == s.key_id)).then_some(s.key_id)
}

/// First use: there is no pin to verify forward from, so the latest version's trust is taken only
/// from an anchor (a key file, `--trust-fingerprint`, or a person at a terminal).
async fn first_use(
    src: &Server,
    path: &Path,
    latest: u64,
    anchors: &Anchors,
    confirm: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Verified> {
    if latest == 0 {
        return Err(anyhow::Error::new(CliError::new(
            "no_published_version",
            "the server has not published any version yet: nothing to verify. Approve the first \
             version with a school key: `mastersos publish --key-file <FILE>`",
        )));
    }
    let archive = src.version_archive(latest).await?;
    let unpacked = read_archive(&archive).map_err(|e| {
        tamper(format!(
            "The latest package cannot be opened: {}",
            crate::safe::field(&e.to_string())
        ))
    })?;
    let m = Manifest::parse(&unpacked.contents.manifest_text).map_err(|e| {
        tamper(format!(
            "The latest manifest cannot be read: {}",
            crate::safe::field(&e.to_string())
        ))
    })?;
    writeln!(
        out,
        "This computer has not checked {} before. The server's latest is version {latest}; it names these keys as the ones computers accept:",
        describe(src)
    )?;
    let own = |t: &TrustKey| {
        anchors
            .keys
            .iter()
            .any(|k| k.alg == t.alg && k.public_key == t.public_key)
    };
    for t in &m.trust {
        let mark = if own(t) {
            "  (your school key file)"
        } else {
            ""
        };
        writeln!(out, "    {}{mark}", key_line(t))?;
    }
    writeln!(
        out,
        "Compare each one with the School keys page and the comment at the top of the install file. Every later version is verified from here on."
    )?;
    let shown: std::collections::BTreeSet<String> = m
        .trust
        .iter()
        .map(mastersos_bundle::trust_fingerprint)
        .collect();
    let given: std::collections::BTreeSet<String> = anchors
        .fingerprints
        .iter()
        .map(|f| f.trim().to_ascii_lowercase())
        .collect();
    let not_confirmed = |why: &str, problems: Vec<serde_json::Value>| {
        anyhow::Error::new(CliError {
            problems,
            ..CliError::new(
                "trust_not_confirmed",
                &format!(
                    "the trusted keys of version {latest} were not confirmed: {why}. Compare them \
                     with the School keys page, then run again at a terminal without --yes or --json, or \
                     pass --trust-fingerprint once for each key that is not your school key file"
                ),
            )
        })
    };
    // Every given fingerprint must be one shown: a wrong one is a mistake, never ignored.
    let unknown: Vec<serde_json::Value> = given
        .difference(&shown)
        .map(|f| serde_json::json!(crate::safe::field(f)))
        .collect();
    if !unknown.is_empty() {
        return Err(not_confirmed(
            "a --trust-fingerprint value is not one of the keys shown",
            unknown,
        ));
    }
    // A fingerprint is a short hash: one shared by two of the keys names neither of them.
    let ambiguous: Vec<serde_json::Value> = given
        .iter()
        .filter(|f| {
            m.trust
                .iter()
                .filter(|t| mastersos_bundle::trust_fingerprint(t) == **f)
                .count()
                > 1
        })
        .map(|f| serde_json::json!(crate::safe::field(f)))
        .collect();
    if !ambiguous.is_empty() {
        return Err(not_confirmed(
            "a --trust-fingerprint value is ambiguous: more than one of the keys shown has it",
            ambiguous,
        ));
    }
    let unanchored: Vec<String> = m
        .trust
        .iter()
        .filter(|t| !own(t) && !given.contains(&mastersos_bundle::trust_fingerprint(t)))
        .map(mastersos_bundle::trust_fingerprint)
        .collect();
    if unanchored.is_empty() {
        writeln!(
            out,
            "Accepted: every key is your school key file or a --trust-fingerprint value given."
        )?;
    } else if !anchors.interactive {
        return Err(not_confirmed(
            "not every key is your school key file or a --trust-fingerprint value, and nobody \
             can confirm them here (--yes, --json, or stdin is not a terminal)",
            unanchored
                .into_iter()
                .map(serde_json::Value::from)
                .collect(),
        ));
    } else {
        let typed = ask(
            confirm,
            out,
            "If every key above matches the School keys page and the install file, type yes: ",
        )
        .map_err(|_| cancel("No input was read; cancelled"))?;
        if typed != "yes" {
            return Err(cancel("The trusted keys were not confirmed; cancelled"));
        }
    }
    // Every key is now anchored (by a key file, a fingerprint, or the person): the latest
    // version must verify under that set.
    let anchored: Vec<TrustKey> = m.trust.clone();
    let b = accept(&archive, &anchored, None).map_err(|e| {
        match signer_outside_own_trust(&unpacked.signature_toml, &m.trust) {
            // Ruling R23: still refused, with what happened and what IT does about it.
            Some(signer) => tamper(format!(
                "The latest version {latest} is signed by school key {}, which is not among its \
                 own trusted keys, so a computer starting from it cannot verify it. An honest \
                 server refuses such a version: do not trust this server until IT has published \
                 once with one of the trusted keys (`mastersos publish --key-file <FILE>`)",
                crate::safe::field(&signer)
            )),
            None => tamper(format!(
                "The latest version does not verify even with its own trusted keys: do not trust this server ({})",
                crate::safe::field(&e.to_string())
            )),
        }
    })?;
    if b.manifest.version != latest {
        return Err(tamper(format!(
            "The server says the latest is version {latest}, but the package says version {}",
            b.manifest.version
        )));
    }
    let digest_hex = hex(&content_digest(&b.contents));
    let mut history = Vec::new();
    record_verified(&mut history, latest, &digest_hex);
    let v = Verified {
        version: latest,
        digest_hex,
        trust: b.manifest.trust,
        contents: b.contents,
        latest,
        history,
    };
    save_pin(path, None, &pin_of(src, &v)?)?;
    writeln!(
        out,
        "Recorded the trusted keys of version {latest} ({}).",
        path.display()
    )?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(host: &str, version: u64, digest: &str) -> Pin {
        Pin {
            host: host.to_owned(),
            version,
            digest_hex: digest.to_owned(),
            trust: Vec::new(),
            verified: Vec::new(),
        }
        .normalized()
    }

    /// The verified contents hold the filled manifest (Wi-Fi keys, the IT password hash): Debug
    /// never shows them.
    #[test]
    fn verified_debug_hides_the_contents() {
        let mut files = std::collections::BTreeMap::new();
        files.insert("files/a.txt".to_owned(), b"SECRET-FILE".to_vec());
        let v = Verified {
            version: 3,
            digest_hex: "ab".repeat(32),
            trust: Vec::new(),
            contents: Contents {
                manifest_text: "psk = \"SECRET-PSK\"\n".to_owned(),
                files,
            },
            latest: 3,
            history: Vec::new(),
        };
        let d = format!("{v:?} {v:#?}");
        assert!(!d.contains("SECRET"), "{d}");
        assert!(d.contains("version: 3") || d.contains("version: 3,"), "{d}");
    }

    #[test]
    fn save_pin_refuses_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.toml");
        let p3 = pin("h", 3, "aa");
        save_pin(&path, None, &p3).unwrap();
        for v in [3, 2, 1] {
            let err = save_pin(&path, Some(&p3), &pin("h", v, "bb"))
                .unwrap_err()
                .to_string();
            assert!(err.contains("backwards"), "{err}");
        }
        assert_eq!(load_pin(&path).unwrap(), Some(p3.clone()));
        // Forward from exactly the pin on disk is fine.
        save_pin(&path, Some(&p3), &pin("h", 4, "cc")).unwrap();
        assert_eq!(load_pin(&path).unwrap().unwrap().version, 4);
    }

    /// The temporary file is unique and created exclusively: a symlink planted at the old fixed
    /// `.toml.tmp` name is neither followed nor needed, and nothing is left behind.
    #[cfg(unix)]
    #[test]
    fn save_pin_writes_through_a_fresh_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.toml");
        let target = dir.path().join("elsewhere");
        std::os::unix::fs::symlink(&target, dir.path().join("h.toml.tmp")).unwrap();
        save_pin(&path, None, &pin("h", 1, "aa")).unwrap();
        save_pin(&path, Some(&pin("h", 1, "aa")), &pin("h", 2, "bb")).unwrap();
        assert!(!target.exists(), "followed the planted symlink");
        assert_eq!(load_pin(&path).unwrap().unwrap().version, 2);
        let mut names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["h.toml", "h.toml.lock", "h.toml.tmp"]);
    }

    #[test]
    fn save_pin_refuses_other_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.toml");
        let p3 = pin("h", 3, "aa");
        save_pin(&path, None, &p3).unwrap();
        // A first-use or genesis pin (no previous pin) over an existing one.
        let err = save_pin(&path, None, &pin("h", 9, "bb"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not verified forward"), "{err}");
        assert!(err.contains(&path.display().to_string()), "{err}");
        // Verified from some other version-3 pin (different content): another chain.
        let other = pin("h", 3, "ff");
        let err = save_pin(&path, Some(&other), &pin("h", 4, "bb"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not verified forward"), "{err}");
        let err = save_pin(&path, Some(&p3), &pin("other", 4, "bb"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("is for h"), "{err}");
        assert_eq!(load_pin(&path).unwrap(), Some(p3));
        // A pin that vanished while verifying.
        let gone = dir.path().join("gone.toml");
        assert!(save_pin(&gone, Some(&pin("h", 1, "aa")), &pin("h", 2, "bb")).is_err());
    }

    mod history {
        use super::super::*;
        use mastersos_bundle::{pack, Ed25519Signer};

        fn archive(v: u64, note: &str) -> Vec<u8> {
            let k = Ed25519Signer::from_seed("key-1", &[1; 32]);
            let t = k.trust_key();
            let text = format!(
                "version = {v}\nissued_at = \"2026-11-03T00:00:00Z\"\n\n[[trust]]\nid = \"{}\"\nalg = \"ed25519\"\npublic_key = \"{}\"\n\n[school]\nid = \"11111111-1111-1111-1111-111111111111\"\n\n[[config]]\nid = \"default\"\nname = \"Default {note}\"\ninterface = \"learning\"\nlogin_methods = [\"local\"]\n\n[[group]]\nid = \"default\"\nname = \"Ungrouped\"\nconfig = \"default\"\n",
                t.id, t.public_key
            );
            pack(
                &Contents {
                    manifest_text: text,
                    files: Default::default(),
                },
                &k,
            )
            .unwrap()
        }

        fn digest(a: &[u8]) -> String {
            hex(&content_digest(&read_archive(a).unwrap().contents))
        }

        #[test]
        fn pinned_history_records_each_verified_version() {
            let mut list = Vec::new();
            for v in [3, 4, 4, 5] {
                record_verified(&mut list, v, &format!("d{v}"));
            }
            assert_eq!(
                list.iter().map(|e| e.version).collect::<Vec<_>>(),
                [3, 4, 5]
            );
            // It survives the pin file, and a pin file without the field still loads, with the
            // pinned version recorded.
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("h.toml");
            let mut p = super::pin("h", 5, "d5");
            p.verified = list.clone();
            save_pin(&path, None, &p).unwrap();
            assert_eq!(load_pin(&path).unwrap().unwrap().verified, list);
            let old = dir.path().join("old.toml");
            std::fs::write(
                &old,
                "host = \"h\"\nversion = 2\ndigest_hex = \"d2\"\ntrust = []\n",
            )
            .unwrap();
            let loaded = load_pin(&old).unwrap().unwrap();
            assert_eq!(
                loaded.verified,
                [VerifiedVersion {
                    version: 2,
                    digest_hex: "d2".into()
                }]
            );
        }

        #[test]
        fn pull_version_requires_recorded_digest() {
            let (a2, a3) = (archive(2, "real"), archive(2, "forged"));
            let mut list = Vec::new();
            record_verified(&mut list, 2, &digest(&a2));
            assert!(recorded_contents(&list, 2, &a2)
                .unwrap()
                .manifest_text
                .contains("real"));
            assert!(recorded_contents(&list, 2, &a3).is_err());
        }

        #[test]
        fn pull_version_before_first_use_refused() {
            let a = archive(1, "x");
            let mut list = Vec::new();
            record_verified(&mut list, 2, &digest(&archive(2, "y")));
            let err = recorded_contents(&list, 1, &a).unwrap_err().to_string();
            assert!(
                err.contains("before this computer started verifying"),
                "{err}"
            );
        }
    }

    /// Protocol v1: the versions come from the CLI API of one school.
    mod v1 {
        use super::super::*;
        use crate::auth::Credentials;
        use mastersos_bundle::{pack, trust_fingerprint, Ed25519Signer};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        const SCHOOL: &str = "0192f3a4-5b6c-7d8e-9f00-112233445566";
        const OTHER: &str = "0192f3a4-5b6c-7d8e-9f00-aabbccddeeff";

        fn prefix(school: &str) -> String {
            format!("/api/cli/v1/schools/{school}/mastersos/")
        }

        fn signer(seed: u8) -> Ed25519Signer {
            Ed25519Signer::from_seed("key-1", &[seed; 32])
        }

        /// Version `v` of `school`, trusting key 1 and signed by the key of `seed`.
        fn archive(v: u64, school: &str, seed: u8, note: &str) -> Vec<u8> {
            let t = signer(1).trust_key();
            let text = format!(
                "version = {v}\nissued_at = \"2026-11-03T00:00:00Z\"\n\n[[trust]]\nid = \"{}\"\nalg = \"ed25519\"\npublic_key = \"{}\"\n\n[school]\nid = \"{school}\"\n\n[[config]]\nid = \"default\"\nname = \"Default {note}\"\ninterface = \"learning\"\nlogin_methods = [\"local\"]\n\n[[group]]\nid = \"default\"\nname = \"Ungrouped\"\nconfig = \"default\"\n",
                t.id, t.public_key
            );
            pack(
                &Contents {
                    manifest_text: text,
                    files: Default::default(),
                },
                &signer(seed),
            )
            .unwrap()
        }

        /// Serve `archives` (version 1, 2, ...) of `school` with their version header.
        async fn serve(mock: &MockServer, school: &str, archives: &[Vec<u8>]) {
            let list: Vec<serde_json::Value> = (1..=archives.len())
                .map(|v| {
                    serde_json::json!({"version": v, "published_at": "2026-11-03T00:00:00Z",
                    "published_by": "it", "signed_by": "key-1", "digest_hex": "00"})
                })
                .collect();
            Mock::given(method("GET"))
                .and(path(format!("{}versions", prefix(school))))
                .respond_with(ResponseTemplate::new(200).set_body_json(list))
                .mount(mock)
                .await;
            for (i, a) in archives.iter().enumerate() {
                let v = i + 1;
                Mock::given(method("GET"))
                    .and(path(format!("{}versions/{v}/archive", prefix(school))))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .insert_header("X-Mastersos-Version", v.to_string().as_str())
                            .set_body_bytes(a.clone()),
                    )
                    .mount(mock)
                    .await;
            }
        }

        fn server(mock: &MockServer, school: &str) -> Server {
            Server::new(&mock.uri(), Some(school), Credentials::fixed("t")).unwrap()
        }

        /// The fingerprint of key 1, which every [`archive`] trusts.
        fn fp1() -> String {
            trust_fingerprint(&signer(1).trust_key())
        }

        /// `yes`: anchored by `--trust-fingerprint` of key 1 (no person); else a person at a
        /// terminal who types `input`.
        async fn verify(
            s: &Server,
            pins: &Path,
            yes: bool,
            input: &str,
        ) -> (Result<Verified, CliError>, String) {
            let anchors = if yes {
                Anchors {
                    fingerprints: vec![fp1()],
                    ..Anchors::default()
                }
            } else {
                Anchors {
                    interactive: true,
                    ..Anchors::default()
                }
            };
            verify_with(s, pins, &anchors, input).await
        }

        async fn verify_with(
            s: &Server,
            pins: &Path,
            anchors: &Anchors,
            input: &str,
        ) -> (Result<Verified, CliError>, String) {
            let mut out = Vec::new();
            let r = verify_chain(s, pins, anchors, &mut input.as_bytes(), &mut out).await;
            (r, String::from_utf8(out).unwrap())
        }

        /// The files in the pin directory.
        fn pin_files(pins: &Path) -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(pins)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }

        /// Two trusted keys with one fingerprint (here the same public key under two ids): a
        /// `--trust-fingerprint` value cannot tell them apart, so it anchors neither.
        #[tokio::test]
        async fn a_fingerprint_shared_by_two_keys_is_ambiguous() {
            let mock = MockServer::start().await;
            let t = signer(1).trust_key();
            let text = format!(
                "version = 1\nissued_at = \"2026-11-03T00:00:00Z\"\n\n[[trust]]\nid = \"key-1\"\nalg = \"ed25519\"\npublic_key = \"{pk}\"\n\n[[trust]]\nid = \"key-1b\"\nalg = \"ed25519\"\npublic_key = \"{pk}\"\n\n[school]\nid = \"{SCHOOL}\"\n\n[[config]]\nid = \"default\"\nname = \"Default\"\ninterface = \"learning\"\nlogin_methods = [\"local\"]\n\n[[group]]\nid = \"default\"\nname = \"Ungrouped\"\nconfig = \"default\"\n",
                pk = t.public_key
            );
            let a1 = pack(
                &Contents {
                    manifest_text: text,
                    files: Default::default(),
                },
                &signer(1),
            )
            .unwrap();
            serve(&mock, SCHOOL, &[a1]).await;
            let pins = tempfile::tempdir().unwrap();
            let s = server(&mock, SCHOOL);
            let (r, _) = verify(&s, pins.path(), true, "").await;
            let e = r.unwrap_err();
            assert_eq!(e.code, "trust_not_confirmed", "{}", e.message);
            assert!(e.message.contains("ambiguous"), "{}", e.message);
            assert!(pin_files(pins.path()).is_empty());
        }

        #[tokio::test]
        async fn chain_reads_versions_from_the_cli_routes() {
            let mock = MockServer::start().await;
            let a1 = archive(1, SCHOOL, 1, "a");
            serve(&mock, SCHOOL, std::slice::from_ref(&a1)).await;
            let pins = tempfile::tempdir().unwrap();
            let s = server(&mock, SCHOOL);
            let (r, _) = verify(&s, pins.path(), true, "").await;
            assert_eq!(r.unwrap().version, 1);
            mock.reset().await;
            serve(
                &mock,
                SCHOOL,
                &[a1, archive(2, SCHOOL, 1, "b"), archive(3, SCHOOL, 1, "c")],
            )
            .await;
            let (r, _) = verify(&s, pins.path(), false, "").await;
            let v = r.unwrap();
            assert_eq!((v.version, v.latest), (3, 3));
            assert_eq!(
                v.history.iter().map(|h| h.version).collect::<Vec<_>>(),
                [1, 2, 3]
            );
            let paths: Vec<String> = mock
                .received_requests()
                .await
                .unwrap()
                .iter()
                .map(|r| r.url.path().to_owned())
                .collect();
            let p = prefix(SCHOOL);
            assert_eq!(
                paths,
                [
                    format!("{p}versions"),
                    format!("{p}versions/1/archive"),
                    format!("{p}versions/2/archive"),
                    format!("{p}versions/3/archive"),
                ]
            );
        }

        #[tokio::test]
        async fn pins_are_per_origin_and_school() {
            let mock = MockServer::start().await;
            serve(&mock, SCHOOL, &[archive(1, SCHOOL, 1, "a")]).await;
            serve(
                &mock,
                OTHER,
                &[archive(1, OTHER, 1, "a"), archive(2, OTHER, 1, "b")],
            )
            .await;
            let pins = tempfile::tempdir().unwrap();
            let (a, b) = (server(&mock, SCHOOL), server(&mock, OTHER));
            assert_eq!(
                verify(&a, pins.path(), true, "").await.0.unwrap().version,
                1
            );
            assert_eq!(
                verify(&b, pins.path(), true, "").await.0.unwrap().version,
                2
            );
            let port = reqwest::Url::parse(&mock.uri()).unwrap().port().unwrap();
            let mut names: Vec<String> = std::fs::read_dir(pins.path())
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(".toml"))
                .collect();
            names.sort();
            assert_eq!(
                names,
                [
                    format!("127.0.0.1_{port}+{SCHOOL}.toml"),
                    format!("127.0.0.1_{port}+{OTHER}.toml"),
                ]
            );
            let pin = load_pin(&pins.path().join(&names[0])).unwrap().unwrap();
            assert_eq!(pin.host, format!("{}+{SCHOOL}", mock.uri()));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                for n in &names {
                    let mode = std::fs::metadata(pins.path().join(n))
                        .unwrap()
                        .permissions()
                        .mode();
                    assert_eq!(mode & 0o777, 0o600, "{n}");
                }
            }
            // The same school's pin is found again: no question the second time.
            assert_eq!(
                verify(&a, pins.path(), false, "").await.0.unwrap().version,
                1
            );
        }

        #[tokio::test]
        async fn first_use_with_yes_accepts_and_prints_fingerprints() {
            let mock = MockServer::start().await;
            serve(&mock, SCHOOL, &[archive(1, SCHOOL, 1, "a")]).await;
            let pins = tempfile::tempdir().unwrap();
            let s = server(&mock, SCHOOL);
            // A person who types nothing, or no: cancelled, nothing pinned.
            let (r, _) = verify(&s, pins.path(), false, "").await;
            assert_eq!(r.unwrap_err().code, "cancelled");
            let (r, _) = verify(&s, pins.path(), false, "no\n").await;
            assert_eq!(r.unwrap_err().code, "cancelled");
            assert!(pin_files(pins.path()).is_empty());
            // --yes with fingerprints equal to the ones shown (any case): printed and pinned.
            let anchors = Anchors {
                fingerprints: vec![fp1().to_uppercase()],
                ..Anchors::default()
            };
            let (r, out) = verify_with(&s, pins.path(), &anchors, "").await;
            assert_eq!(r.unwrap().version, 1);
            assert!(out.contains(&fp1()), "{out}");
            assert!(out.contains("--trust-fingerprint"), "{out}");
            assert!(out.contains(SCHOOL), "{out}");
            assert_eq!(pin_files(pins.path()).len(), 2); // the pin and its lock
        }

        #[tokio::test]
        async fn first_use_with_yes_and_the_key_file_in_trust_is_pinned() {
            let mock = MockServer::start().await;
            serve(&mock, SCHOOL, &[archive(1, SCHOOL, 1, "a")]).await;
            let pins = tempfile::tempdir().unwrap();
            let s = server(&mock, SCHOOL);
            // A key that is not in the trust anchors nothing.
            let other = Anchors {
                keys: vec![signer(7).trust_key()],
                ..Anchors::default()
            };
            let (r, _) = verify_with(&s, pins.path(), &other, "").await;
            assert_eq!(r.unwrap_err().code, "trust_not_confirmed");
            assert!(pin_files(pins.path()).is_empty());
            let mine = Anchors {
                keys: vec![signer(1).trust_key()],
                ..Anchors::default()
            };
            let (r, out) = verify_with(&s, pins.path(), &mine, "").await;
            assert_eq!(r.unwrap().version, 1, "{out}");
            assert!(load_pin(&pin_path(pins.path(), &s).unwrap())
                .unwrap()
                .is_some());
        }

        /// Version 1 of `SCHOOL` trusting keys 1 and 2, signed by the key of `seed`.
        fn two_keys(seed: u8) -> Vec<u8> {
            let (t1, t2) = (signer(1).trust_key(), signer(2).trust_key());
            let text = format!(
                "version = 1\nissued_at = \"2026-11-03T00:00:00Z\"\n\n[[trust]]\nid = \"{}\"\nalg = \"ed25519\"\npublic_key = \"{}\"\n\n[[trust]]\nid = \"key-2\"\nalg = \"ed25519\"\npublic_key = \"{}\"\n\n[school]\nid = \"{SCHOOL}\"\n\n[[config]]\nid = \"default\"\nname = \"Default\"\ninterface = \"learning\"\nlogin_methods = [\"local\"]\n\n[[group]]\nid = \"default\"\nname = \"Ungrouped\"\nconfig = \"default\"\n",
                t1.id, t1.public_key, t2.public_key
            );
            pack(
                &Contents {
                    manifest_text: text,
                    files: Default::default(),
                },
                &Ed25519Signer::from_seed(&format!("key-{seed}"), &[seed; 32]),
            )
            .unwrap()
        }

        /// The key file of key 1 alone does not anchor key 2: refused, key 2's fingerprint in
        /// `problems`, nothing pinned; key 2's fingerprint given as well, accepted.
        #[tokio::test]
        async fn key_file_does_not_anchor_the_other_keys() {
            let mock = MockServer::start().await;
            serve(&mock, SCHOOL, &[two_keys(1)]).await;
            let pins = tempfile::tempdir().unwrap();
            let s = server(&mock, SCHOOL);
            let fp2 = trust_fingerprint(&signer(2).trust_key());
            let own = Anchors {
                keys: vec![signer(1).trust_key()],
                ..Anchors::default()
            };
            let (r, _) = verify_with(&s, pins.path(), &own, "yes\n").await;
            let e = r.unwrap_err();
            assert_eq!(e.code, "trust_not_confirmed");
            assert_eq!(e.problems, [serde_json::json!(fp2)]);
            assert!(
                e.message.contains("without --yes or --json"),
                "{}",
                e.message
            );
            assert!(pin_files(pins.path()).is_empty());
            // A wrong fingerprint next to the key file is refused too.
            let wrong = Anchors {
                fingerprints: vec!["0000-0000-0000-0000".into()],
                ..own.clone()
            };
            let (r, _) = verify_with(&s, pins.path(), &wrong, "").await;
            assert_eq!(r.unwrap_err().code, "trust_not_confirmed");
            assert!(pin_files(pins.path()).is_empty());
            let both = Anchors {
                fingerprints: vec![fp2],
                ..own
            };
            let (r, out) = verify_with(&s, pins.path(), &both, "").await;
            assert_eq!(r.unwrap().version, 1, "{out}");
        }

        /// Trust {1, 2} signed by key 2 with the key file of key 1: refused, nothing pinned.
        #[tokio::test]
        async fn key_file_does_not_anchor_a_set_signed_by_another_key() {
            let mock = MockServer::start().await;
            serve(&mock, SCHOOL, &[two_keys(2)]).await;
            let pins = tempfile::tempdir().unwrap();
            let s = server(&mock, SCHOOL);
            let own = Anchors {
                keys: vec![signer(1).trust_key()],
                ..Anchors::default()
            };
            let (r, _) = verify_with(&s, pins.path(), &own, "yes\n").await;
            let e = r.unwrap_err();
            assert_eq!(e.code, "trust_not_confirmed");
            assert_eq!(
                e.problems,
                [serde_json::json!(trust_fingerprint(&signer(2).trust_key()))]
            );
            assert!(std::fs::read_dir(pins.path()).unwrap().next().is_none());
        }

        /// Ruling R23: a first use facing a latest version signed by a key that is not among its
        /// own trusted keys is still refused (`chain_tampered`, nothing pinned), with the plain
        /// explanation: an honest server refuses such a version; IT publishes once with a trusted
        /// key. A signature by a trusted key id that does not verify keeps the bare refusal.
        #[tokio::test]
        async fn first_use_of_a_version_signed_outside_its_own_trust_explains() {
            let mock = MockServer::start().await;
            let gone = Ed25519Signer::from_seed("key-9", &[9; 32]);
            let t = signer(1).trust_key();
            let text = format!(
                "version = 1\nissued_at = \"2026-11-03T00:00:00Z\"\n\n[[trust]]\nid = \"{}\"\nalg = \"ed25519\"\npublic_key = \"{}\"\n\n[school]\nid = \"{SCHOOL}\"\n\n[[config]]\nid = \"default\"\nname = \"Default\"\ninterface = \"learning\"\nlogin_methods = [\"local\"]\n\n[[group]]\nid = \"default\"\nname = \"Ungrouped\"\nconfig = \"default\"\n",
                t.id, t.public_key
            );
            let a = pack(
                &Contents {
                    manifest_text: text,
                    files: Default::default(),
                },
                &gone,
            )
            .unwrap();
            serve(&mock, SCHOOL, &[a]).await;
            let pins = tempfile::tempdir().unwrap();
            let s = server(&mock, SCHOOL);
            let (r, _) = verify(&s, pins.path(), true, "").await;
            let e = r.unwrap_err();
            assert_eq!(e.code, "chain_tampered");
            assert!(
                e.message.contains("not among its own trusted keys"),
                "{}",
                e.message
            );
            assert!(e.message.contains("publish"), "{}", e.message);
            assert!(
                e.message.contains("do not trust this server"),
                "{}",
                e.message
            );
            assert!(pin_files(pins.path()).is_empty());

            // Signed under a trusted key id, but not by that key: the bare refusal.
            let mock = MockServer::start().await;
            serve(&mock, SCHOOL, &[archive(1, SCHOOL, 7, "x")]).await;
            let s = server(&mock, SCHOOL);
            let (r, _) = verify(&s, pins.path(), true, "").await;
            let e = r.unwrap_err();
            assert_eq!(e.code, "chain_tampered");
            assert!(
                !e.message.contains("not among its own trusted keys"),
                "{}",
                e.message
            );
        }

        /// A person sees every key, the key file's own marked, and confirms the whole set.
        #[tokio::test]
        async fn interactive_first_use_shows_every_key_and_marks_the_own() {
            let mock = MockServer::start().await;
            serve(&mock, SCHOOL, &[two_keys(2)]).await;
            let pins = tempfile::tempdir().unwrap();
            let s = server(&mock, SCHOOL);
            let fp2 = trust_fingerprint(&signer(2).trust_key());
            let person = Anchors {
                keys: vec![signer(1).trust_key()],
                interactive: true,
                ..Anchors::default()
            };
            let (r, out) = verify_with(&s, pins.path(), &person, "no\n").await;
            assert_eq!(r.unwrap_err().code, "cancelled");
            assert!(pin_files(pins.path()).is_empty());
            let line = |fp: &str| {
                out.lines()
                    .find(|l| l.contains(fp))
                    .unwrap_or("")
                    .to_owned()
            };
            assert!(line(&fp1()).contains("(your school key file)"), "{out}");
            assert!(!line(&fp2).is_empty(), "{out}");
            assert!(!line(&fp2).contains("your school key file"), "{out}");
            assert!(out.contains("type yes"), "{out}");
            let (r, _) = verify_with(&s, pins.path(), &person, "yes\n").await;
            assert_eq!(r.unwrap().version, 1);
        }

        /// Version `v` of `SCHOOL` trusting `trust` (any algorithm).
        fn manifest_trusting(v: u64, trust: &[TrustKey]) -> Contents {
            let mut text = format!("version = {v}\nissued_at = \"2026-11-03T00:00:00Z\"\n");
            for t in trust {
                let alg = match t.alg {
                    mastersos_bundle::KeyAlg::Ed25519 => "ed25519",
                    mastersos_bundle::KeyAlg::WebauthnEs256 => "webauthn-es256",
                };
                text += &format!(
                    "\n[[trust]]\nid = \"{}\"\nalg = \"{alg}\"\npublic_key = \"{}\"\n",
                    t.id, t.public_key
                );
                if let Some(rp) = &t.rp_id {
                    text += &format!("rp_id = \"{rp}\"\n");
                }
            }
            text += &format!("\n[school]\nid = \"{SCHOOL}\"\n\n[[config]]\nid = \"default\"\nname = \"Default\"\ninterface = \"learning\"\nlogin_methods = [\"local\"]\n\n[[group]]\nid = \"default\"\nname = \"Ungrouped\"\nconfig = \"default\"\n");
            Contents {
                manifest_text: text,
                files: Default::default(),
            }
        }

        /// A trust change signed by a passkey (R7) asks a person to go on; without one (piped
        /// stdin, `--yes`) a piped "yes" never confirms it: cancelled, the pin stays.
        #[tokio::test]
        async fn kit_warning_needs_a_person() {
            use mastersos_bundle::testutil::FakePasskey;
            let phone =
                FakePasskey::new("server.example", "https://server.example").with_key_id("phone");
            let t1 = vec![signer(1).trust_key(), phone.trust_key("phone")];
            let mut t2 = t1.clone();
            t2.push(Ed25519Signer::from_seed("key-9", &[9; 32]).trust_key());
            let v1 = pack(&manifest_trusting(1, &t1), &signer(1)).unwrap();
            let c2 = manifest_trusting(2, &t2);
            let v2 = mastersos_bundle::assemble(
                &c2,
                &phone.sign(&mastersos_bundle::signed_message(&c2), 0x05),
            )
            .unwrap();
            let mock = MockServer::start().await;
            serve(&mock, SCHOOL, std::slice::from_ref(&v1)).await;
            let pins = tempfile::tempdir().unwrap();
            let s = server(&mock, SCHOOL);
            let first = Anchors {
                keys: vec![signer(1).trust_key()],
                fingerprints: vec![trust_fingerprint(&phone.trust_key("phone"))],
                interactive: false,
            };
            let (r, out) = verify_with(&s, pins.path(), &first, "").await;
            assert_eq!(r.unwrap().version, 1, "{out}");
            mock.reset().await;
            serve(&mock, SCHOOL, &[v1, v2]).await;
            let nobody = Anchors {
                interactive: false,
                ..first.clone()
            };
            let (r, out) = verify_with(&s, pins.path(), &nobody, "yes\n").await;
            let e = r.unwrap_err();
            assert_eq!(e.code, "cancelled", "{out}");
            assert!(e.message.contains("nobody"), "{}", e.message);
            assert!(!out.contains("Type yes"), "{out}");
            let person = Anchors {
                interactive: true,
                ..first
            };
            let (r, out) = verify_with(&s, pins.path(), &person, "yes\n").await;
            let v = r.unwrap();
            assert_eq!((v.version, v.latest), (1, 2), "{out}");
        }

        #[tokio::test]
        async fn first_use_with_yes_and_no_anchor_is_refused() {
            let mock = MockServer::start().await;
            // Version 1 trusts keys 1 and 2.
            let t2 = signer(2).trust_key();
            let a = two_keys(1);
            serve(&mock, SCHOOL, &[a]).await;
            let pins = tempfile::tempdir().unwrap();
            let s = server(&mock, SCHOOL);
            let fp2 = trust_fingerprint(&t2);
            for given in [
                vec![],                                                 // --yes alone
                vec![fp1()],                                            // partial
                vec!["0000-0000-0000-0000".to_owned()],                 // wrong
                vec![fp1(), fp2.clone(), "0000-0000-0000-0000".into()], // more
            ] {
                let anchors = Anchors {
                    fingerprints: given.clone(),
                    ..Anchors::default()
                };
                let (r, _) = verify_with(&s, pins.path(), &anchors, "yes\n").await;
                assert_eq!(r.unwrap_err().code, "trust_not_confirmed", "{given:?}");
                assert!(pin_files(pins.path()).is_empty(), "{given:?}");
            }
            let all = Anchors {
                fingerprints: vec![fp2, fp1()],
                ..Anchors::default()
            };
            assert_eq!(
                verify_with(&s, pins.path(), &all, "")
                    .await
                    .0
                    .unwrap()
                    .version,
                1
            );
        }

        /// A pin the old admin API wrote for this host (`<host>_<port>.toml`).
        fn old_pin(mock: &MockServer, pins: &Path, a: &[u8], v: u64) -> PathBuf {
            let url = reqwest::Url::parse(&mock.uri()).unwrap();
            let host = format!("127.0.0.1:{}", url.port().unwrap());
            let path = pins.join(format!("{}.toml", host.replace(':', "_")));
            let digest = hex(&content_digest(&read_archive(a).unwrap().contents));
            let pin = Pin {
                host,
                version: v,
                digest_hex: digest,
                trust: vec![signer(1).trust_key()],
                verified: Vec::new(),
            };
            save_pin(&path, None, &pin).unwrap();
            path
        }

        #[tokio::test]
        async fn old_pin_that_connects_is_carried_over() {
            let mock = MockServer::start().await;
            let a1 = archive(1, SCHOOL, 1, "a");
            serve(&mock, SCHOOL, &[a1.clone(), archive(2, SCHOOL, 1, "b")]).await;
            let pins = tempfile::tempdir().unwrap();
            let old = old_pin(&mock, pins.path(), &a1, 1);
            let before = std::fs::read(&old).unwrap();
            let s = server(&mock, SCHOOL);
            // No anchor at all: the old pin is the anchor.
            let (r, out) = verify_with(&s, pins.path(), &Anchors::default(), "").await;
            assert_eq!(r.unwrap().version, 2, "{out}");
            let new = load_pin(&pin_path(pins.path(), &s).unwrap())
                .unwrap()
                .unwrap();
            assert_eq!(new.version, 2);
            assert_eq!(new.host, format!("{}+{SCHOOL}", mock.uri()));
            assert_eq!(std::fs::read(&old).unwrap(), before, "the old pin is left");
        }

        #[tokio::test]
        async fn old_pin_that_does_not_connect_is_refused_even_with_yes() {
            let mock = MockServer::start().await;
            serve(&mock, SCHOOL, &[archive(1, SCHOOL, 1, "a")]).await;
            let pins = tempfile::tempdir().unwrap();
            // The old pin recorded other content for version 1 (another chain).
            let old = old_pin(&mock, pins.path(), &archive(1, OTHER, 1, "x"), 1);
            let s = server(&mock, SCHOOL);
            let (r, _) = verify(&s, pins.path(), true, "yes\n").await;
            let e = r.unwrap_err();
            assert_eq!(e.code, "chain_tampered");
            assert!(
                e.message.contains(&old.display().to_string()),
                "{}",
                e.message
            );
            assert!(load_pin(&pin_path(pins.path(), &s).unwrap())
                .unwrap()
                .is_none());
            // A rollback below the old pin is refused too.
            mock.reset().await;
            serve(&mock, SCHOOL, &[]).await;
            let (r, _) = verify(&s, pins.path(), true, "").await;
            assert_eq!(r.unwrap_err().code, "chain_tampered");
        }

        #[tokio::test]
        async fn tampered_archive_stops_the_chain() {
            let mock = MockServer::start().await;
            let a1 = archive(1, SCHOOL, 1, "a");
            serve(&mock, SCHOOL, std::slice::from_ref(&a1)).await;
            let pins = tempfile::tempdir().unwrap();
            let s = server(&mock, SCHOOL);
            verify(&s, pins.path(), true, "").await.0.unwrap();
            // Version 2 signed by a key that is not trusted.
            mock.reset().await;
            serve(&mock, SCHOOL, &[a1, archive(2, SCHOOL, 9, "b")]).await;
            let (r, _) = verify(&s, pins.path(), true, "").await;
            assert_eq!(r.unwrap_err().code, "chain_tampered");
            // The pinned version swapped for other content.
            mock.reset().await;
            serve(&mock, SCHOOL, &[archive(1, SCHOOL, 1, "forged")]).await;
            let (r, _) = verify(&s, pins.path(), true, "").await;
            assert_eq!(r.unwrap_err().code, "chain_tampered");
            // Fewer versions than were verified: rolled back.
            mock.reset().await;
            serve(&mock, SCHOOL, &[]).await;
            let (r, _) = verify(&s, pins.path(), true, "").await;
            assert_eq!(r.unwrap_err().code, "chain_tampered");
            let pin = load_pin(&pin_path(pins.path(), &s).unwrap())
                .unwrap()
                .unwrap();
            assert_eq!(pin.version, 1);
        }

        #[tokio::test]
        async fn archive_must_carry_its_version_header() {
            let mock = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path(format!("{}versions", prefix(SCHOOL))))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(serde_json::json!([{"version": 1}])),
                )
                .mount(&mock)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("{}versions/1/archive", prefix(SCHOOL))))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("X-Mastersos-Version", "2")
                        .set_body_bytes(archive(1, SCHOOL, 1, "a")),
                )
                .mount(&mock)
                .await;
            let pins = tempfile::tempdir().unwrap();
            let s = server(&mock, SCHOOL);
            let (r, _) = verify(&s, pins.path(), true, "").await;
            assert_eq!(r.unwrap_err().code, "invalid_answer");
            assert_eq!(s.latest_version().await.unwrap(), 1);
        }

        #[tokio::test]
        async fn nothing_published_is_latest_zero() {
            let mock = MockServer::start().await;
            serve(&mock, SCHOOL, &[]).await;
            let s = server(&mock, SCHOOL);
            assert_eq!(s.latest_version().await.unwrap(), 0);
            let pins = tempfile::tempdir().unwrap();
            let (r, _) = verify(&s, pins.path(), true, "").await;
            assert_eq!(r.unwrap_err().code, "no_published_version");
        }
    }
}
