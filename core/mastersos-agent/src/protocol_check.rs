//! `protocol-check`: one network cycle of a Device against a server (protocol v1), reported call
//! by call as JSON ([`CheckReport`]). The server team drives it in their end-to-end run.
//!
//! It writes only under its DIR: `DIR/seed-partition/` (the seed copied from `--seed`,
//! `identity.json`, `fetch-token`) and `DIR/state/` (the imported seed, `fetch-token` after a
//! renewal), both 0700. Re-runs reuse both, so the server sees the same device identity. It holds
//! no key of its own; the device secret, the recovery key and the fetch token never appear in the
//! report or in an error text. `http://` is allowed only to `127.0.0.1`, `::1` or `localhost`
//! (the lab rule, §2); any other `http://` refuses every network step locally and sends nothing:
//! the bundle and heartbeat steps would carry the fetch token, the others the device secret.

use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use mastersos_bundle::{
    accept_for_school, accept_update_for_school, content_digest, is_luks_uuid, is_recovery_key,
    read_archive, select, trust_fingerprint, verify_heartbeat, Bundle, DeviceIdent, GroupSource,
    ItemResult, Seed, SignatureFile, StatusReport, DEFAULT_GROUP, MAX_SEED_BYTES,
};
use serde::{Deserialize, Serialize};

use crate::fetch::{
    escrow_transport_ok, DeviceAuthMissing, DeviceCred, EscrowRefused, Exchange, FetchOutcome,
    Fetcher, NotAvailable, Recorder, RenewFailed, RenewOutcome, ServerRefused, StatusNotSent,
};
use crate::luks::{escrow_request, SealedKey};
use crate::safefs;
use crate::seedpart::{self, Identity, Imported};

/// The version of the report's shape (`protocol_check`).
pub const PROTOCOL_CHECK: u32 = 1;
/// The bundle step stops after this many downloads without a `204`.
const MAX_BUNDLE_ROUNDS: usize = 1000;
/// A heartbeat issued further ahead of the local clock is not taken (as the agent does).
const HEARTBEAT_FUTURE_SLACK: TimeDelta = TimeDelta::days(1);
const SEED_PART: &str = "seed-partition";
const STATE: &str = "state";
const SEED_FILE: &str = "seed.toml";

/// What `mastersos-agent protocol-check` was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckInput {
    /// The seed file (`--seed`).
    pub seed: PathBuf,
    /// Where the run keeps its device (`DIR`).
    pub dir: PathBuf,
    /// A file holding a throwaway recovery key (`--recovery-key`); without it escrow is skipped.
    pub recovery_key: Option<PathBuf>,
    /// The LUKS UUID escrowed with the recovery key (`--luks-uuid`).
    pub luks_uuid: Option<String>,
}

/// The report (pinned: the server team consumes `protocol_check`, `ok` and
/// `calls[].{step,route,status,ok,skipped,error_code}`; `detail` is display only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckReport {
    pub protocol_check: u32,
    pub agent_version: String,
    pub server_url: String,
    /// `None` when `seed_import` failed.
    pub device_id: Option<String>,
    /// Every call is ok.
    pub ok: bool,
    pub calls: Vec<Call>,
}

/// One step's entry: one per HTTP exchange, or one for a step that sent nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Call {
    pub step: String,
    /// `METHOD /path?query` exactly as sent; `None` when no request was made.
    pub route: Option<String>,
    /// The HTTP status; `None` without an answer.
    pub status: Option<u16>,
    pub ok: bool,
    pub skipped: bool,
    /// The server's `error.code`, else one local code: `network`, `local_refused`,
    /// `verify_failed`, `invalid_answer`, `bad_input`.
    pub error_code: Option<String>,
    /// The settings version the entry is about.
    pub version: Option<u64>,
    pub detail: String,
}

impl Call {
    fn new(step: &str) -> Call {
        Call {
            step: step.into(),
            route: None,
            status: None,
            ok: true,
            skipped: false,
            error_code: None,
            version: None,
            detail: String::new(),
        }
    }

    fn sent(mut self, ex: Option<Exchange>) -> Call {
        if let Some(ex) = ex {
            self.route = Some(format!("{} {}", ex.method, ex.route));
            self.status = ex.status;
        }
        self
    }

    fn detail(mut self, d: impl Into<String>) -> Call {
        self.detail = d.into();
        self
    }

    fn fail(mut self, code: &str, detail: impl Into<String>) -> Call {
        self.ok = false;
        self.error_code = Some(code.into());
        self.detail = detail.into();
        self
    }

    /// The entry of a failed request: the error code and detail from [`classify`].
    fn error(self, e: &anyhow::Error) -> Call {
        let (code, detail) = classify(e, self.status);
        self.fail(&code, detail)
    }
}

/// The error code and the detail of a failed request. Typed refusals give the server's code (a
/// refusal without a readable JSON code is `invalid_answer`); a request without an answer is
/// `network`; an answer the agent could not use is `invalid_answer`. Details carry the status and
/// the code, never the server's message.
fn classify(e: &anyhow::Error, status: Option<u16>) -> (String, String) {
    let refused = |r: &ServerRefused| {
        (
            r.code.clone().unwrap_or_else(|| "invalid_answer".into()),
            r.to_string(),
        )
    };
    if let Some(n) = e.downcast_ref::<StatusNotSent>() {
        return ("local_refused".into(), n.to_string());
    }
    if let Some(r) = e.downcast_ref::<ServerRefused>() {
        return refused(r);
    }
    if let Some(r) = e.downcast_ref::<EscrowRefused>() {
        return refused(&r.refused);
    }
    if let Some(r) = e.downcast_ref::<RenewFailed>() {
        return refused(&r.refused);
    }
    if let Some(n) = e.downcast_ref::<NotAvailable>() {
        return ("not_available".into(), n.to_string());
    }
    if let Some(d) = e.downcast_ref::<DeviceAuthMissing>() {
        return ("device_auth_missing".into(), d.to_string());
    }
    match status {
        Some(_) => ("invalid_answer".into(), format!("{e:#}")),
        None => ("network".into(), format!("no answer: {e:#}")),
    }
}

/// `server_url` is `http://` to `127.0.0.1`, `::1` or `localhost`.
fn is_lab(server_url: &str) -> bool {
    reqwest::Url::parse(server_url).is_ok_and(|u| {
        u.scheme() == "http" && matches!(u.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"))
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The device a run uses, from `seed_import`.
struct Device {
    /// DIR, open for the whole run: `seed_part` and `state` are paths through this fd.
    _dir: OwnedFd,
    seed: Seed,
    identity: Identity,
    seed_part: PathBuf,
    state: PathBuf,
}

/// Runs the steps in order and reports each call. Never panics on a server's answer; a failed
/// `seed_import` ends the run.
pub async fn run_check(input: &CheckInput, now: DateTime<Utc>) -> CheckReport {
    let mut calls = Vec::new();
    let (dev, server_url) = match seed_import(input) {
        Ok((dev, detail)) => {
            calls.push(Call::new("seed_import").detail(detail));
            let url = dev.seed.server_url.clone();
            (dev, url)
        }
        Err((detail, url)) => {
            calls.push(Call::new("seed_import").fail("bad_input", detail));
            return finish(url, None, calls, &[]);
        }
    };
    let rec: Recorder = Arc::new(Mutex::new(Vec::new()));
    let token = crate::token::effective(&dev.state, &dev.seed_part, &dev.seed);
    let f = Fetcher::new(&dev.seed, token.clone()).with_recorder(rec.clone());
    let take = || {
        rec.lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
            .next_back()
    };
    let lab = is_lab(&dev.seed.server_url);
    let mut secrets = vec![dev.identity.escrow_secret.clone()];
    secrets.extend(token);
    secrets.extend(dev.seed.fetch_token.clone());

    // The fetch token travels only where the device secret may (§2: TLS, or http to loopback).
    let latest = if escrow_transport_ok(f.base(), lab).is_err() {
        for step in ["bundle", "heartbeat"] {
            calls.push(Call::new(step).fail("local_refused", LOCAL_TOKEN_TRANSPORT));
        }
        None
    } else {
        let latest = bundles(&f, &dev.seed, &take, &mut calls).await;
        calls.push(heartbeat(&f, &dev.seed, latest.as_ref(), now, &take).await);
        latest
    };
    calls.push(status(&f, &dev, latest.as_ref(), lab, &take).await);
    calls.push(escrow(&f, input, &dev, latest.as_ref(), lab, &take, &mut secrets).await);
    renewal(&f, &dev, lab, &take, &mut calls, &mut secrets).await;
    finish(
        server_url,
        Some(dev.identity.device_id.clone()),
        calls,
        &secrets,
    )
}

fn finish(
    server_url: String,
    device_id: Option<String>,
    mut calls: Vec<Call>,
    secrets: &[String],
) -> CheckReport {
    // A server may echo a secret back, also as an error code that passes the code check.
    let redact = |text: &mut String| {
        for s in secrets.iter().filter(|s| !s.is_empty()) {
            if text.contains(s.as_str()) {
                *text = text.replace(s.as_str(), "<redacted>");
            }
        }
    };
    for c in &mut calls {
        redact(&mut c.detail);
        if let Some(code) = &mut c.error_code {
            redact(code);
        }
    }
    CheckReport {
        protocol_check: PROTOCOL_CHECK,
        agent_version: env!("CARGO_PKG_VERSION").into(),
        server_url,
        device_id,
        ok: calls.iter().all(|c| c.ok),
        calls,
    }
}

/// An existing directory of the run is used only when it belongs to the process's effective uid
/// and no group or other user can write to it: files another user could have planted there
/// (an `identity.json`, a `fetch-token`) would be trusted. Read bits are fine (tightened to 0700).
fn private_enough(uid: u32, mode: u32, euid: u32, what: &str) -> Result<()> {
    if uid != euid {
        anyhow::bail!("{what} is owned by another user (uid {uid}); use a directory of your own");
    }
    if mode & 0o022 != 0 {
        anyhow::bail!(
            "{what} is writable by group or others (mode {:o}): files in it may come from another user; use a new DIR",
            mode & 0o7777
        );
    }
    Ok(())
}

/// [`private_enough`] for an open directory.
fn check_private(fd: &OwnedFd, what: &str) -> Result<()> {
    let st = rustix::fs::fstat(fd).map_err(|e| anyhow::anyhow!("checking {what} failed: {e}"))?;
    private_enough(
        st.st_uid,
        st.st_mode,
        rustix::process::geteuid().as_raw(),
        what,
    )
}

fn set_private(fd: &OwnedFd, what: &str) -> Result<()> {
    rustix::fs::fchmod(fd, rustix::fs::Mode::from_raw_mode(0o700))
        .map_err(|e| anyhow::anyhow!("setting the mode of {what} failed: {e}"))
}

/// The path of an open directory through its fd (Linux): opening it resolves to that very
/// directory, whatever was renamed or swapped since.
fn fd_path(fd: &OwnedFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

/// Opens DIR exactly once (`O_DIRECTORY|O_NOFOLLOW`: a symlink is refused); a missing DIR is
/// created 0700 first (its parent must exist). It must be ours and hold nothing but an earlier
/// run's `seed-partition/` and `state/` directories, and no group or other may write to it
/// ([`private_enough`]); anything else is refused untouched. It is not tightened here: the
/// caller checks the existing subdirectories first, so a refusal changes no mode.
fn open_run_dir(dir: &Path) -> Result<OwnedFd> {
    use rustix::fs::{Mode, OFlags};
    let (Some(parent), Some(name)) = (dir.parent(), dir.file_name()) else {
        anyhow::bail!("DIR must be a directory below another");
    };
    let parent = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| anyhow::anyhow!("opening the parent of DIR failed: {e}"))?;
    let name = Path::new(name);
    let fd = match safefs::open_dir_at(&parent, name, false) {
        Ok(fd) => fd,
        Err(e) if crate::apply::is_not_found(&e) => {
            rustix::fs::mkdirat(&parent, name, Mode::from_raw_mode(0o700))
                .map_err(|e| anyhow::anyhow!("creating DIR failed: {e}"))?;
            safefs::open_dir_at(&parent, name, false).map_err(|e| e.context("opening DIR"))?
        }
        Err(e) => return Err(e.context("opening DIR")),
    };
    check_private(&fd, "DIR")?;
    for entry in std::fs::read_dir(fd_path(&fd))? {
        let entry = entry?;
        let name = entry.file_name();
        // `file_type` does not follow a symlink.
        if !((name == SEED_PART || name == STATE) && entry.file_type()?.is_dir()) {
            anyhow::bail!(
                "DIR holds {name:?}, not only an earlier run's {SEED_PART}/ and {STATE}/ directories; use an empty or new DIR"
            );
        }
    }
    Ok(fd)
}

/// Opens DIR and its two directories, checks all that exist ([`private_enough`]) before any
/// change, then tightens DIR to 0700 and opens or creates `seed-partition/` and `state/` relative
/// to the DIR fd with `O_NOFOLLOW` (a symlink is refused), 0700. Returns DIR, seed-partition and
/// state.
fn open_run_dirs(dir: &Path) -> Result<(OwnedFd, OwnedFd, OwnedFd)> {
    let dir_fd = open_run_dir(dir)?;
    let mut existing = Vec::new();
    for name in [SEED_PART, STATE] {
        let fd = safefs::open_child_dir(&dir_fd, name)?;
        if let Some(fd) = &fd {
            check_private(fd, name)?;
        }
        existing.push(fd);
    }
    set_private(&dir_fd, "DIR")?;
    let mut opened = Vec::new();
    for (name, fd) in [SEED_PART, STATE].into_iter().zip(existing) {
        let fd = match fd {
            Some(fd) => fd,
            // Created now inside our DIR: tightened below.
            None => safefs::open_dir_at(&dir_fd, Path::new(name), true)?,
        };
        set_private(&fd, name)?;
        opened.push(fd);
    }
    let state = opened.pop().expect("two directories");
    let part = opened.pop().expect("two directories");
    Ok((dir_fd, part, state))
}

/// Step 1.
/// The `Err` is the detail (`bad_input`) and the seed's `server_url` when it was read.
fn seed_import(input: &CheckInput) -> std::result::Result<(Device, String), (String, String)> {
    let bad = |detail: String, url: &str| (detail, url.to_string());
    let bytes = match std::fs::read(&input.seed) {
        Ok(b) if b.len() <= MAX_SEED_BYTES => b,
        Ok(_) => return Err(bad("the seed file is larger than 64 KiB".into(), "")),
        Err(e) => return Err(bad(format!("reading the seed file failed: {e}"), "")),
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return Err(bad("the seed file is not UTF-8".into(), ""));
    };
    // The parse error may quote a line of the seed (the fetch token): a fixed text only.
    let Ok(seed) = Seed::parse(text) else {
        return Err(bad("the seed file is not a valid seed".into(), ""));
    };
    let url = seed.server_url.clone();
    if let Err(e) = seed.validate() {
        return Err(bad(format!("{e}"), &url));
    }
    // DIR is resolved by its path once; every later open goes through its fd: here directly, and
    // in the library calls (which take paths) through `/proc/self/fd/<DIR fd>/<name>`, whose last
    // part `safefs` opens with `O_NOFOLLOW` relative to the already-open DIR. DIR is ours and
    // 0700, so no one else can rename or swap its entries.
    let set_up = || -> Result<(OwnedFd, PathBuf, PathBuf, Imported, Identity)> {
        let dir = std::path::absolute(&input.dir)?;
        let (dir_fd, part_fd, state_fd) = open_run_dirs(&dir)?;
        for (fd, what) in [(&part_fd, SEED_PART), (&state_fd, STATE)] {
            if safefs::read_at(fd, SEED_FILE)?.is_some_and(|h| h != bytes) {
                anyhow::bail!(
                    "{what}/{SEED_FILE} in DIR is another seed than --seed; use a new DIR"
                );
            }
        }
        safefs::write_at(&part_fd, SEED_FILE, &bytes, 0o600)?;
        let base = fd_path(&dir_fd);
        let (seed_part, state) = (base.join(SEED_PART), base.join(STATE));
        let imported = seedpart::import_if_fresh(&state, &seed_part)?;
        let identity = seedpart::load_or_create_identity(&seed_part, None)?;
        Ok((dir_fd, seed_part, state, imported, identity))
    };
    let (dir_fd, seed_part, state, imported, identity) = match set_up() {
        Ok(v) => v,
        Err(e) => return Err(bad(format!("{e:#}"), &url)),
    };
    let verb = match imported {
        Imported::Fresh { .. } => "imported",
        Imported::Existing => "existing",
        Imported::Unmanaged => return Err(bad("the seed was not imported".into(), &url)),
    };
    let trust: Vec<&str> = seed.trust.iter().map(|k| k.id.as_str()).collect();
    let min = match seed.min_version {
        Some(m) => format!("min_version {m}"),
        None => "no min_version".into(),
    };
    let detail = format!("{verb}; trust {}; {min}", trust.join(", "));
    Ok((
        Device {
            seed,
            identity,
            _dir: dir_fd,
            seed_part,
            state,
        },
        detail,
    ))
}

/// The key id in an archive's `signature` member (read after the archive verified).
fn signer_of(archive: &[u8]) -> String {
    read_archive(archive)
        .ok()
        .and_then(|u| toml::from_str::<SignatureFile>(&u.signature_toml).ok())
        .map_or_else(|| "an unknown key".into(), |s| s.key_id)
}

/// Verifies a downloaded archive: the first against the seed (and its `min_version`), later ones
/// as updates of `latest`; the `X-Mastersos-Version` header must equal the manifest's version.
fn verify_bundle(
    archive: &[u8],
    header_version: u64,
    latest: Option<&Bundle>,
    seed: &Seed,
) -> std::result::Result<Bundle, String> {
    let school = seed.school_id.as_deref();
    let b = match latest {
        None => {
            let b =
                accept_for_school(archive, &seed.trust, None, school).map_err(|e| e.to_string())?;
            if let Some(min) = seed.min_version.filter(|m| b.manifest.version < *m) {
                return Err(format!(
                    "v{} is below the seed's min_version {min}",
                    b.manifest.version
                ));
            }
            b
        }
        Some(cur) => accept_update_for_school(
            archive,
            &cur.manifest.trust,
            Some(cur.manifest.school.escrow_recipients.as_slice()),
            Some(cur.manifest.version),
            school,
        )
        .map_err(|e| e.to_string())?,
    };
    if b.manifest.version != header_version {
        return Err(format!(
            "X-Mastersos-Version {header_version} differs from the manifest's version {}",
            b.manifest.version
        ));
    }
    Ok(b)
}

/// Step 2: `GET bundle?after=N` until `204`, a failure, or [`MAX_BUNDLE_ROUNDS`]. Returns the
/// latest verified bundle.
async fn bundles(
    f: &Fetcher,
    seed: &Seed,
    take: &impl Fn() -> Option<Exchange>,
    calls: &mut Vec<Call>,
) -> Option<Bundle> {
    let mut latest: Option<Bundle> = None;
    let mut after = seed.min_version.map_or(0, |m| m.saturating_sub(1));
    for _ in 0..MAX_BUNDLE_ROUNDS {
        let res = f.fetch_now(after).await;
        let c = Call::new("bundle").sent(take());
        match res {
            Ok(FetchOutcome::NoChange) => {
                calls.push(c.detail("no newer version"));
                return latest;
            }
            Ok(FetchOutcome::New { archive, version }) => {
                match verify_bundle(&archive, version, latest.as_ref(), seed) {
                    Ok(b) => {
                        let mut c =
                            c.detail(format!("verified; signed by {}", signer_of(&archive)));
                        c.version = Some(b.manifest.version);
                        calls.push(c);
                        after = b.manifest.version;
                        latest = Some(b);
                    }
                    Err(why) => {
                        calls.push(c.fail("verify_failed", why));
                        return latest;
                    }
                }
            }
            Err(e) => {
                calls.push(c.error(&e));
                return latest;
            }
        }
    }
    calls.push(Call::new("bundle").fail(
        "invalid_answer",
        format!("no 204 after {MAX_BUNDLE_ROUNDS} downloads"),
    ));
    latest
}

/// Step 3: `GET heartbeat`, verified with the latest verified trust (the seed's without one); it
/// must name the latest verified bundle.
async fn heartbeat(
    f: &Fetcher,
    seed: &Seed,
    latest: Option<&Bundle>,
    now: DateTime<Utc>,
    take: &impl Fn() -> Option<Exchange>,
) -> Call {
    let res = f.heartbeat().await;
    let mut c = Call::new("heartbeat").sent(take());
    let text = match res {
        Ok(None) => return c.detail("no heartbeat"),
        Ok(Some(t)) => t,
        Err(e) => return c.error(&e),
    };
    let trust = latest.map_or(&seed.trust, |b| &b.manifest.trust);
    let s = match verify_heartbeat(&text, trust) {
        Ok(s) => s,
        Err(e) => return c.fail("verify_failed", e.to_string()),
    };
    c.version = Some(s.version);
    if s.issued_at > (now + HEARTBEAT_FUTURE_SLACK).timestamp() {
        return c.fail(
            "verify_failed",
            "the heartbeat is issued more than 1 day ahead of the local clock",
        );
    }
    let Some(b) = latest else {
        return c.fail(
            "verify_failed",
            "no verified settings to compare the heartbeat with",
        );
    };
    if s.version != b.manifest.version || s.digest_hex != hex(&content_digest(&b.contents)) {
        return c.fail(
            "verify_failed",
            format!(
                "the heartbeat names v{} and another digest than the latest verified settings v{}",
                s.version, b.manifest.version
            ),
        );
    }
    let not_after = DateTime::from_timestamp(s.not_after, 0).map_or_else(
        || s.not_after.to_string(),
        |t| t.to_rfc3339_opts(SecondsFormat::Secs, true),
    );
    c.detail(format!("verified; not_after {not_after}"))
}

/// Step 4: a status report sent with the device credential.
async fn status(
    f: &Fetcher,
    dev: &Device,
    latest: Option<&Bundle>,
    lab: bool,
    take: &impl Fn() -> Option<Exchange>,
) -> Call {
    let device_id = dev.identity.device_id.clone();
    let picked = latest
        .filter(|b| b.manifest.effective_of_group(DEFAULT_GROUP).is_some())
        .map(|b| {
            let ident = DeviceIdent {
                serial: None,
                device_id: device_id.clone(),
            };
            let s = select(&b.manifest, &ident, dev.seed.group.as_deref());
            (s.group.id.clone(), s.source)
        });
    let (group, group_source) = picked.unwrap_or_else(|| match &dev.seed.group {
        Some(g) => (g.clone(), GroupSource::Seed),
        None => (DEFAULT_GROUP.into(), GroupSource::Default),
    });
    let r = StatusReport {
        device_id: device_id.clone(),
        serial: None,
        model: None,
        os_version: None,
        agent_version: env!("CARGO_PKG_VERSION").into(),
        bundle_version: latest.map(|b| b.manifest.version),
        group,
        group_source,
        locked: false,
        stale: false,
        last_fetch_ok: None,
        results: vec![ItemResult {
            item: "protocol-check".into(),
            ok: true,
            detail: None,
        }],
        fresh_until: None,
        newer_withheld: None,
        seed_trust_fingerprints: dev.seed.trust.iter().map(trust_fingerprint).collect(),
        imported_from_seed_at: None,
        manifest_features: crate::report::SUPPORTED_FEATURES
            .iter()
            .map(|f| (*f).to_owned())
            .collect(),
        os_pending_version: None,
        quiet_since: None,
        user_config: None,
    };
    let cred = DeviceCred {
        device_id,
        secret: dev.identity.escrow_secret.clone(),
    };
    let res = f.report(&r, &cred, lab).await;
    let c = Call::new("status").sent(take());
    match res {
        Ok(()) => c,
        Err(e) => c.error(&e),
    }
}

/// The transport refusal of the steps that carry the device secret.
const LOCAL_TRANSPORT: &str =
    "the device secret is only sent over https (http only to 127.0.0.1, ::1 or localhost)";
/// The transport refusal of the steps that carry the fetch token.
const LOCAL_TOKEN_TRANSPORT: &str =
    "the fetch token is only sent over https (http only to 127.0.0.1, ::1 or localhost)";

/// Step 5: the throwaway recovery key sealed to the latest verified escrow recipients.
async fn escrow(
    f: &Fetcher,
    input: &CheckInput,
    dev: &Device,
    latest: Option<&Bundle>,
    lab: bool,
    take: &impl Fn() -> Option<Exchange>,
    secrets: &mut Vec<String>,
) -> Call {
    let c = Call::new("escrow");
    let Some(path) = &input.recovery_key else {
        let mut c = c.detail("no --recovery-key given");
        c.skipped = true;
        return c;
    };
    let key = match std::fs::read_to_string(path) {
        Ok(k) => k.trim().to_string(),
        Err(e) => {
            return c.fail(
                "bad_input",
                format!("reading the recovery key file failed: {e}"),
            )
        }
    };
    if !is_recovery_key(&key) {
        return c.fail(
            "bad_input",
            "the recovery key file does not hold a recovery key (8 groups of 8 modhex characters)",
        );
    }
    secrets.push(key.clone());
    let Some(uuid) = &input.luks_uuid else {
        return c.fail("bad_input", "--recovery-key needs --luks-uuid");
    };
    // The server takes only lowercase; lsblk and blkid may print it in capitals.
    let uuid = uuid.trim().to_ascii_lowercase();
    if !is_luks_uuid(&uuid) {
        return c.fail("bad_input", "the LUKS UUID is not an 8-4-4-4-12 UUID");
    }
    if escrow_transport_ok(f.base(), lab).is_err() {
        return c.fail("local_refused", LOCAL_TRANSPORT);
    }
    let Some(recipients) = latest
        .map(|b| &b.manifest.school.escrow_recipients)
        .filter(|r| !r.is_empty())
    else {
        return c.fail("verify_failed", "the settings name no escrow recipients");
    };
    let sealed = match SealedKey::seal(&key, recipients) {
        Ok(s) => s,
        Err(e) => {
            return c.fail(
                "verify_failed",
                format!("sealing the recovery key failed: {e}"),
            )
        }
    };
    let req = match escrow_request(
        &dev.identity.device_id,
        None,
        &uuid,
        &sealed,
        &dev.identity.escrow_secret,
    ) {
        Ok(r) => r,
        Err(e) => return c.fail("bad_input", format!("invalid escrow request: {e}")),
    };
    let res = f.escrow(&req, lab).await;
    let c = c.sent(take());
    match res {
        Ok(()) => c,
        Err(e) => c.error(&e),
    }
}

/// Steps 6 and 7: renew a stale token, save it under DIR, and check the server takes it.
async fn renewal(
    f: &Fetcher,
    dev: &Device,
    lab: bool,
    take: &impl Fn() -> Option<Exchange>,
    calls: &mut Vec<Call>,
    secrets: &mut Vec<String>,
) {
    let c = Call::new("fetch_token");
    // Before the stale check: over a refused transport no bundle went out to mark the token, and
    // the renewal (with `fetch_token_check` after it) is refused as well.
    if escrow_transport_ok(f.base(), lab).is_err() {
        calls.push(c.fail("local_refused", LOCAL_TRANSPORT));
        return;
    }
    if !f.token_is_stale() {
        let mut c = c.detail("the token is not stale");
        c.skipped = true;
        calls.push(c);
        return;
    }
    let res = f.renew_token(&dev.identity, lab).await;
    let c = c.sent(take());
    let token = match res {
        Ok(RenewOutcome::New(t)) => t,
        Ok(RenewOutcome::Refused(r)) => {
            let code = r
                .refused
                .code
                .clone()
                .unwrap_or_else(|| "invalid_answer".into());
            calls.push(c.fail(&code, r.refused.to_string()));
            return;
        }
        Err(e) => {
            calls.push(c.error(&e));
            return;
        }
    };
    secrets.push(token.clone());
    // DIR/seed-partition is a plain directory, not a mount point: skip that check.
    // Saving is local (a disk problem under DIR, no answer to blame): the fixed code list has no
    // closer match than `local_refused`.
    if let Err(e) = crate::token::save_with(&dev.state, &dev.seed_part, &token, false) {
        calls.push(c.fail(
            "local_refused",
            format!("saving the new token failed: {e:#}"),
        ));
        return;
    }
    f.set_token(token);
    calls.push(c.detail("renewed; saved in DIR"));

    let res = f.heartbeat().await;
    let c = Call::new("fetch_token_check").sent(take());
    calls.push(match res {
        Err(e) => c.error(&e),
        Ok(_) if f.token_is_stale() => c.fail(
            "invalid_answer",
            "the server still says the renewed token is stale",
        ),
        Ok(_) => c.detail("the renewed token is taken"),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DIR owned by someone else is refused whoever runs the check (the integration test that
    /// chowns a DIR needs root); so is one group or others may write to. Read bits are fine.
    #[test]
    fn only_a_private_directory_of_our_own_is_used() {
        for m in [0o700, 0o755, 0o750, 0o40755] {
            assert!(private_enough(1000, m, 1000, "DIR").is_ok(), "{m:o}");
        }
        assert!(private_enough(0, 0o700, 0, "DIR").is_ok());
        let e = private_enough(65534, 0o700, 1000, "DIR")
            .unwrap_err()
            .to_string();
        assert!(e.contains("another user"), "{e}");
        assert!(private_enough(1000, 0o700, 0, "state").is_err());
        for m in [0o720, 0o702, 0o775, 0o757, 0o777, 0o41777] {
            let e = private_enough(1000, m, 1000, "state")
                .unwrap_err()
                .to_string();
            assert!(e.contains("writable"), "{m:o}: {e}");
        }
    }
}
