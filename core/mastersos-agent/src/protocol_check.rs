//! `protocol-check`: one network cycle of a Device against a server (protocol v1), reported call
//! by call as JSON ([`CheckReport`]). The server team drives it in their end-to-end run.
//!
//! It writes only under its DIR: `DIR/seed-partition/` (the seed copied from `--seed`,
//! `identity.json`, `fetch-token`) and `DIR/state/` (the imported seed, `fetch-token` after a
//! renewal), both 0700. Re-runs reuse both, so the server sees the same device identity. It holds
//! no key of its own; the device secret, the recovery key and the fetch token never appear in the
//! report or in an error text. `http://` is allowed only to `127.0.0.1`, `::1` or `localhost`
//! (the lab rule, §2); any other `http://` refuses status, escrow and renewal locally, as a
//! release image does.

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
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
    Unauthorized,
};
use crate::luks::{escrow_request, SealedKey};
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
    // The bundle and heartbeat do not read a 401's body: the server's code there is
    // `unauthorized` (wire table, "every device route checks the fetch token first").
    if let Some(u) = e.downcast_ref::<Unauthorized>() {
        return ("unauthorized".into(), u.to_string());
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

    let latest = bundles(&f, &dev.seed, &take, &mut calls).await;
    calls.push(heartbeat(&f, &dev.seed, latest.as_ref(), now, &take).await);
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
    for c in &mut calls {
        for s in secrets.iter().filter(|s| !s.is_empty()) {
            if c.detail.contains(s.as_str()) {
                c.detail = c.detail.replace(s.as_str(), "<redacted>");
            }
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

/// Creates `p` 0700 when missing (its parent must exist: nothing is created above DIR); refuses
/// a symlink or a non-directory, and sets 0700.
fn private_dir(p: &Path) -> Result<()> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => anyhow::bail!("{} is not a directory", p.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(p)
                .map_err(|e| anyhow::anyhow!("creating {} failed: {e}", p.display()))?;
        }
        Err(e) => anyhow::bail!("checking {} failed: {e}", p.display()),
    }
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| anyhow::anyhow!("setting the mode of {} failed: {e}", p.display()))
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
    let set_up = || -> Result<(PathBuf, PathBuf, Imported, Identity)> {
        let dir = std::path::absolute(&input.dir)?;
        private_dir(&dir)?;
        let (seed_part, state) = (dir.join(SEED_PART), dir.join(STATE));
        private_dir(&seed_part)?;
        let fd = crate::safefs::open_abs_dir(&seed_part, false)?;
        for (d, what) in [(&seed_part, "seed-partition"), (&state, "state")] {
            let held = match crate::safefs::open_abs_dir(d, false) {
                Ok(fd) => crate::safefs::read_at(&fd, SEED_FILE)?,
                Err(e) if crate::apply::is_not_found(&e) => None,
                Err(e) => return Err(e),
            };
            if held.is_some_and(|h| h != bytes) {
                anyhow::bail!(
                    "{what}/{SEED_FILE} in DIR is another seed than --seed; use a new DIR"
                );
            }
        }
        crate::safefs::write_at(&fd, SEED_FILE, &bytes, 0o600)?;
        let imported = seedpart::import_if_fresh(&state, &seed_part)?;
        private_dir(&state)?;
        let identity = seedpart::load_or_create_identity(&seed_part, None)?;
        Ok((seed_part, state, imported, identity))
    };
    let (seed_part, state, imported, identity) = match set_up() {
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
    if !is_luks_uuid(uuid) {
        return c.fail(
            "bad_input",
            "the LUKS UUID is not a lowercase 8-4-4-4-12 UUID",
        );
    }
    let Some(recipients) = latest
        .map(|b| &b.manifest.school.escrow_recipients)
        .filter(|r| !r.is_empty())
    else {
        return c.fail("verify_failed", "the settings name no escrow recipients");
    };
    if escrow_transport_ok(f.base(), lab).is_err() {
        return c.fail("local_refused", LOCAL_TRANSPORT);
    }
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
        uuid,
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
    if !f.token_is_stale() {
        let mut c = c.detail("the token is not stale");
        c.skipped = true;
        calls.push(c);
        return;
    }
    if escrow_transport_ok(f.base(), lab).is_err() {
        calls.push(c.fail("local_refused", LOCAL_TRANSPORT));
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
