//! Shim updates without the recovery key (plan 5 Task 8, ruling 14; `image/docs/secure-boot.md`
//! 「引导程序更新与 TPM」).
//!
//! The data partition's TPM slot needs pcrlock's PCR 7 policy. A new shim that raises `SbatLevel` changes exactly one
//! PCR 7 event: `EV_EFI_VARIABLE_AUTHORITY` for `SbatLevel-605dab50-…` (its data). Before `mastersos-bootloader-update`
//! swaps `BOOTX64.EFI` it runs `mastersos-agent shim-prepare <new shim>` ([`prepare`]):
//!
//! 1. Read the new shim's `.sbatlevel` section and work out what it writes on its first boot ([`next_sbat_level`]:
//!    shim's default policy takes `previous` when its datestamp is newer than the current variable's).
//! 2. systemd-pcrlock keeps the secure-boot authority component as
//!    `/var/lib/pcrlock.d/620-secureboot-authority.pcrlock.d/generated.pcrlock`, rewritten from the event log at every
//!    boot by `systemd-pcrlock-secureboot-authority.service` (measured on systemd 259, `lab/results/2026-10-19-5`).
//!    Every `*.pcrlock` in that directory is an alternative. We write a copy of `generated.pcrlock` with the one
//!    `SbatLevel` record swapped ([`variant_with_sbat`]) as `400-mastersos-next-shim.pcrlock` in the same directory.
//! 3. Rebuild the policy with the agent's PIN (as the luks job does), then require `systemd-pcrlock predict` to list
//!    both the current PCR 7 and the value expected after the swap (a replay of the event log's PCR 7 records with the
//!    one digest swapped, [`replay_pcr7`]).
//! 4. Any failure removes the variant again and re-makes the policy with the PIN; `bootloader-update` swaps the shim
//!    anyway and that machine's next boot asks for the recovery key once (the pre-Task-8 behaviour).
//!
//! The result goes to `<var_dir>/shim-prepare.json` (0600). The luks job ([`followup`]) finishes the job after the new
//! shim's first boot: at that boot `generated.pcrlock` already carries the new value, so the variant is redundant —
//! it is removed and the policy re-made with the PIN, and `luks:pcrlock` reports the completion for the rest of that
//! boot — unless the policy service failed in that boot (the recovery key was needed after all: something else in PCR 7
//! changed), which is reported as a failure instead. A failed prediction is reported on `luks:pcrlock` until the next boot.

use std::os::fd::OwnedFd;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::luks;
use crate::runner::{run_ok, Cmd, Runner};
use crate::safefs;
use crate::secureboot::{secure_boot_state, SecureBootState};
use crate::system::SysPaths;

/// Shim's vendor GUID 605dab50-e046-4300-abb6-3dd810dd8b23 in EFI (mixed-endian) byte order.
pub const SHIM_GUID: [u8; 16] = [
    0x50, 0xab, 0x5d, 0x60, 0x46, 0xe0, 0x00, 0x43, 0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23,
];
/// The name shim measures (`Authority: SbatLevel-605dab50-…`).
pub const SBAT_VAR_NAME: &str = "SbatLevel";
/// The runtime copy shim leaves for the OS (relative to sysfs): 4 attribute bytes, then the CSV (no NUL).
pub const SBAT_LEVEL_RT_VAR: &str =
    "firmware/efi/efivars/SbatLevelRT-605dab50-e046-4300-abb6-3dd810dd8b23";
/// shim's `SbatPolicy` (set by `mokutil --set-sbat-policy`): when present, shim does not apply its default policy and
/// the prediction would be wrong.
pub const SBAT_POLICY_VAR: &str =
    "firmware/efi/efivars/SbatPolicy-605dab50-e046-4300-abb6-3dd810dd8b23";
/// PCR 7 of the SHA-256 bank (relative to sysfs), upper-case hex.
pub const PCR7_SYSFS: &str = "class/tpm/tpm0/pcr-sha256/7";
/// The secure-boot authority component (relative to the system root).
pub const AUTHORITY_DIR: &str = "var/lib/pcrlock.d/620-secureboot-authority.pcrlock.d";
/// The variant systemd-pcrlock generates from the event log at every boot.
pub const GENERATED: &str = "generated.pcrlock";
/// Our variant: the generated one with the next shim's SbatLevel.
pub const NEXT_SHIM_VARIANT: &str = "400-mastersos-next-shim.pcrlock";
/// `<var_dir>/shim-prepare.json` (0600).
pub const STATE_FILE: &str = "shim-prepare.json";
const LOCK_FILE: &str = "shim-prepare.lock";
/// On lab images only: this file makes `shim-prepare` fail on purpose (VM acceptance of the fallback).
pub const TEST_FAIL_MARKER: &str = "run/mastersos-test/shim-prepare-fail";
/// Credentials directory for the PIN (relative to the root; separate from the luks job's).
const CRED_DIR: &str = "run/mastersos-agent/shim-prepare-cred";
/// Panel texts (`luks:pcrlock`).
pub const DONE_DETAIL: &str = "shim update completed without the recovery key";
pub const MISPREDICTED_DETAIL: &str =
    "shim replaced, but the prediction did not hold: this boot needed the recovery key; \
the agent re-sealed the pcrlock policy with its PIN";

// ---------------------------------------------------------------------------------------------
// Pure part
// ---------------------------------------------------------------------------------------------

/// The two values in a shim's `.sbatlevel` section. Layout (shim's `sbat_var_payload_header`): `u32 version` (0),
/// `u32 previous`, `u32 latest`; both offsets count from the end of `version` and each points at a NUL-terminated CSV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbatLevels {
    pub previous: Vec<u8>,
    pub latest: Vec<u8>,
}

fn le16(b: &[u8], at: usize) -> Option<u16> {
    b.get(at..at.checked_add(2)?)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at.checked_add(4)?)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// The contents of the PE section called `name` (cut to `VirtualSize`, never past `SizeOfRawData`). Names longer than
/// 8 bytes are stored as `/<offset>` into the COFF string table (shim's `.sbatlevel` is, measured on shim 15.8).
pub fn pe_section<'a>(pe: &'a [u8], name: &[u8]) -> Result<&'a [u8], String> {
    let bad = |w: &str| format!("not a readable PE image: {w}");
    if pe.get(0..2) != Some(b"MZ".as_slice()) {
        return Err(bad("no MZ header"));
    }
    let nt = le32(pe, 0x3c).ok_or_else(|| bad("too short"))? as usize;
    if pe.get(nt..nt.saturating_add(4)) != Some(b"PE\0\0".as_slice()) {
        return Err(bad("no PE signature"));
    }
    let coff = nt + 4;
    let n = le16(pe, coff + 2).ok_or_else(|| bad("truncated COFF header"))? as usize;
    let opt = le16(pe, coff + 16).ok_or_else(|| bad("truncated COFF header"))? as usize;
    let table = coff + 20 + opt;
    // COFF string table: right after the symbol table (18-byte entries)
    // (a zero PointerToSymbolTable means there is none, hence no string table)
    let strtab = le32(pe, coff + 8)
        .filter(|&p| p != 0)
        .zip(le32(pe, coff + 12))
        .and_then(|(p, n)| (p as usize).checked_add((n as usize).checked_mul(18)?));
    for i in 0..n {
        let s = table + i * 40;
        let hdr = pe
            .get(s..s + 40)
            .ok_or_else(|| bad("section table out of bounds"))?;
        let short = &hdr[0..8];
        let short = &short[..short.iter().position(|&c| c == 0).unwrap_or(8)];
        let full: &[u8] = match short.strip_prefix(b"/") {
            Some(off) => {
                let off: usize = std::str::from_utf8(off)
                    .ok()
                    .and_then(|o| o.parse().ok())
                    .ok_or_else(|| bad("malformed long section name"))?;
                let at = strtab
                    .and_then(|t| t.checked_add(off))
                    .ok_or_else(|| bad("long section name without a string table"))?;
                let rest = pe
                    .get(at..)
                    .ok_or_else(|| bad("string table out of bounds"))?;
                &rest[..rest.iter().position(|&c| c == 0).unwrap_or(rest.len())]
            }
            None => short,
        };
        if full != name {
            continue;
        }
        let vsize = le32(hdr, 8).unwrap_or(0) as usize;
        let raw = le32(hdr, 16).unwrap_or(0) as usize;
        let ptr = le32(hdr, 20).unwrap_or(0) as usize;
        let len = if vsize == 0 { raw } else { vsize.min(raw) };
        return ptr
            .checked_add(len)
            .and_then(|end| pe.get(ptr..end))
            .ok_or_else(|| bad("section data outside the file"));
    }
    Err(format!(
        "the PE image has no {} section",
        String::from_utf8_lossy(name)
    ))
}

/// The NUL-terminated string at `base + off` (without the NUL).
fn cstr(b: &[u8], base: usize, off: u32) -> Result<Vec<u8>, String> {
    let start = base
        .checked_add(off as usize)
        .filter(|&s| s < b.len())
        .ok_or_else(|| format!(".sbatlevel offset {off} is out of bounds"))?;
    let len = b[start..]
        .iter()
        .position(|&c| c == 0)
        .ok_or_else(|| ".sbatlevel string has no NUL terminator".to_string())?;
    Ok(b[start..start + len].to_vec())
}

/// Parse the `.sbatlevel` section of a shim PE image. No section, version ≠ 0, offsets out of bounds or a
/// missing NUL → `Err`.
pub fn parse_sbatlevel_section(pe: &[u8]) -> Result<SbatLevels, String> {
    parse_sbatlevel_payload(pe_section(pe, b".sbatlevel")?)
}

/// The same, given the raw section bytes.
pub fn parse_sbatlevel_payload(s: &[u8]) -> Result<SbatLevels, String> {
    let short = || ".sbatlevel is too short".to_string();
    let version = le32(s, 0).ok_or_else(short)?;
    if version != 0 {
        return Err(format!(".sbatlevel version {version} (expected 0)"));
    }
    let prev = le32(s, 4).ok_or_else(short)?;
    let latest = le32(s, 8).ok_or_else(short)?;
    Ok(SbatLevels {
        previous: cstr(s, 4, prev)?,
        latest: cstr(s, 4, latest)?,
    })
}

/// The datestamp of an SbatLevel value: its first line must be `sbat,1,<10 digits>`.
fn datestamp(v: &[u8]) -> Option<u64> {
    let first = v.split(|&c| c == b'\n').next()?;
    let ds = first.strip_prefix(b"sbat,1,")?;
    if ds.len() != 10 || !ds.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(ds).ok()?.parse().ok()
}

/// What the new shim writes into `SbatLevel` on its first boot, under shim's default policy (`SBAT_POLICY_PREVIOUS`):
/// the `previous` value if its datestamp is newer than the current variable's, otherwise `None` (shim keeps the
/// variable, PCR 7 does not change). `Err` when either first line is not `sbat,1,<YYYYMMDDNN>` (cannot tell).
pub fn next_sbat_level(current: &[u8], levels: &SbatLevels) -> Result<Option<Vec<u8>>, String> {
    let cur =
        datestamp(current).ok_or("the current SbatLevel does not start with sbat,1,<datestamp>")?;
    let new = datestamp(&levels.previous)
        .ok_or("the new shim's previous SbatLevel does not start with sbat,1,<datestamp>")?;
    Ok((new > cur).then(|| levels.previous.clone()))
}

/// SHA-256 of a `UEFI_VARIABLE_DATA` (TCG PC Client PFP: VariableName GUID, `u64` UnicodeNameLength in characters,
/// `u64` VariableDataLength, the name in UTF-16LE without NUL, then the data) — the digest of an
/// `EV_EFI_VARIABLE_AUTHORITY` event, as systemd-pcrlock computes it. `guid` is in EFI (mixed-endian) byte order.
pub fn authority_digest(var_name: &str, guid: [u8; 16], data: &[u8]) -> [u8; 32] {
    let name: Vec<u16> = var_name.encode_utf16().collect();
    let mut h = Sha256::new();
    h.update(guid);
    h.update((name.len() as u64).to_le_bytes());
    h.update((data.len() as u64).to_le_bytes());
    for c in &name {
        h.update(c.to_le_bytes());
    }
    h.update(data);
    h.finalize().into()
}

fn hex(b: &[u8]) -> String {
    crate::secureboot::hex(b)
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// A `.pcrlock` component (`{"records":[{"pcr":7,"digests":[{"hashAlg":"sha256","digest":"…"}]}, …]}`) with the one
/// PCR 7 record whose sha256 digest is `old_digest` changed to `new_digest`; everything else unchanged. No such record,
/// more than one, or a matching record that also carries other hash algorithms → `Err`.
pub fn variant_with_sbat(
    component: &str,
    old_digest: [u8; 32],
    new_digest: [u8; 32],
) -> Result<String, String> {
    let mut v: Value =
        serde_json::from_str(component).map_err(|e| format!("component is not JSON: {e}"))?;
    let records = v
        .get_mut("records")
        .and_then(Value::as_array_mut)
        .ok_or("component has no records[]")?;
    let old = hex(&old_digest);
    let mut hits = 0;
    for r in records.iter_mut() {
        if r.get("pcr").and_then(Value::as_u64) != Some(7) {
            continue;
        }
        let Some(digests) = r.get_mut("digests").and_then(Value::as_array_mut) else {
            continue;
        };
        let matches = digests.iter().any(|d| {
            d.get("hashAlg").and_then(Value::as_str) == Some("sha256")
                && d.get("digest")
                    .and_then(Value::as_str)
                    .is_some_and(|x| x.eq_ignore_ascii_case(&old))
        });
        if !matches {
            continue;
        }
        if digests.len() != 1 {
            return Err("the SbatLevel record also has digests for other hash algorithms".into());
        }
        hits += 1;
        digests[0]["digest"] = Value::String(hex(&new_digest));
    }
    match hits {
        1 => serde_json::to_string(&v).map_err(|e| e.to_string()),
        0 => Err("no PCR 7 record with the current SbatLevel digest".into()),
        n => Err(format!(
            "{n} PCR 7 records with the current SbatLevel digest"
        )),
    }
}

/// Replay the PCR 7 records of `systemd-pcrlock log --json=short` (`{"log":[{"pcr":7,"sha256":"…"}, …]}`) from zero.
/// With `swap = Some((old, new))`, exactly one PCR 7 record must have digest `old` and is extended as `new` instead.
pub fn replay_pcr7(log_json: &str, swap: Option<([u8; 32], [u8; 32])>) -> Result<[u8; 32], String> {
    let v: Value =
        serde_json::from_str(log_json).map_err(|e| format!("event log is not JSON: {e}"))?;
    let log = v
        .get("log")
        .and_then(Value::as_array)
        .ok_or("event log has no log[]")?;
    let mut pcr = [0u8; 32];
    let mut swapped = 0;
    for e in log {
        if e.get("pcr").and_then(Value::as_u64) != Some(7) {
            continue;
        }
        let mut d = e
            .get("sha256")
            .and_then(Value::as_str)
            .and_then(parse_hex32)
            .ok_or("a PCR 7 event has no sha256 digest")?;
        if let Some((old, new)) = swap {
            if d == old {
                d = new;
                swapped += 1;
            }
        }
        let mut h = Sha256::new();
        h.update(pcr);
        h.update(d);
        pcr = h.finalize().into();
    }
    if swap.is_some() && swapped != 1 {
        return Err(format!(
            "{swapped} PCR 7 events carry the current SbatLevel digest (expected 1)"
        ));
    }
    Ok(pcr)
}

/// PCR 7 values from `systemd-pcrlock predict --pcr=7 --json=short` (`{"sha256":[{"pcr":7,"values":[…]}]}`).
pub fn predicted_pcr7(json: &str) -> Result<Vec<[u8; 32]>, String> {
    let v: Value =
        serde_json::from_str(json).map_err(|e| format!("prediction is not JSON: {e}"))?;
    let banks = v
        .get("sha256")
        .and_then(Value::as_array)
        .ok_or("prediction has no sha256 bank")?;
    let mut out = vec![];
    for b in banks {
        if b.get("pcr").and_then(Value::as_u64) != Some(7) {
            continue;
        }
        for x in b
            .get("values")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            out.push(
                x.as_str()
                    .and_then(parse_hex32)
                    .ok_or("prediction has a malformed value")?,
            );
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Prepared,
    NotNeeded,
    Failed,
    /// Written by the luks job once the new shim booted with the predicted value; reported for the rest of that boot.
    Completed,
    /// The new shim booted with the predicted SbatLevel but the policy service still failed in that boot (the recovery
    /// key was needed: something else in PCR 7 changed too); reported for the rest of that boot.
    Mispredicted,
}

/// `<var_dir>/shim-prepare.json` (0600).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepareState {
    pub shim_sha256: String,
    /// sha256 of the SbatLevel value the new shim will write (Prepared only).
    #[serde(default)]
    pub predicted_sbat_sha256: Option<String>,
    pub outcome: Outcome,
    #[serde(default)]
    pub reason: Option<String>,
    /// The boot in which shim-prepare ran: the follow-up acts only after a reboot.
    pub boot_id: String,
    /// Unix seconds.
    pub at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepareOutcome {
    NotNeeded(String),
    Prepared,
    Failed(String),
}

fn var_dir(paths: &SysPaths) -> Result<OwnedFd> {
    let dir = safefs::open_abs_dir(&paths.var_dir, true)?;
    safefs::set_mode(&dir, 0o700)?;
    Ok(dir)
}

pub fn load_state(paths: &SysPaths) -> Result<Option<PrepareState>> {
    let Some(b) = safefs::read_at(&var_dir(paths)?, STATE_FILE)? else {
        return Ok(None);
    };
    serde_json::from_slice(&b)
        .map(Some)
        .with_context(|| format!("{STATE_FILE} cannot be parsed"))
}

fn save_state(paths: &SysPaths, s: &PrepareState) -> Result<()> {
    safefs::write_at(
        &var_dir(paths)?,
        STATE_FILE,
        &serde_json::to_vec_pretty(s)?,
        0o600,
    )?;
    Ok(())
}

fn remove_state(paths: &SysPaths) -> Result<()> {
    safefs::remove_at(&var_dir(paths)?, STATE_FILE)
}

/// An exclusive flock on `<var_dir>/shim-prepare.lock` (shim-prepare runs in its own process next to the agent's luks
/// job); released when the returned fd is dropped.
pub(crate) fn lock(paths: &SysPaths) -> Result<OwnedFd> {
    use rustix::fs::{flock, openat, FlockOperation, Mode, OFlags};
    let dir = var_dir(paths)?;
    let fd = openat(
        &dir,
        LOCK_FILE,
        OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )
    .map_err(std::io::Error::from)
    .context("opening the shim-prepare lock")?;
    flock(&fd, FlockOperation::LockExclusive)
        .map_err(std::io::Error::from)
        .context("locking the shim-prepare lock")?;
    Ok(fd)
}

fn boot_id(root: &Path) -> String {
    std::fs::read_to_string(root.join("proc/sys/kernel/random/boot_id"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// SbatLevelRT's data (without the 4 attribute bytes).
pub fn read_sbat_level_rt(sysfs: &Path) -> Result<Vec<u8>> {
    let p = sysfs.join(SBAT_LEVEL_RT_VAR);
    let b = std::fs::read(&p).with_context(|| format!("reading {}", p.display()))?;
    if b.len() < 5 {
        return Err(anyhow!("{} is too short", p.display()));
    }
    Ok(b[4..].to_vec())
}

fn authority_dir(paths: &SysPaths, create: bool) -> Result<OwnedFd> {
    safefs::open_dir(&paths.root, Path::new(AUTHORITY_DIR), create)
        .with_context(|| format!("opening /{AUTHORITY_DIR}"))
}

fn variant_exists(paths: &SysPaths) -> Result<bool> {
    match authority_dir(paths, false) {
        Ok(d) => Ok(safefs::read_at(&d, NEXT_SHIM_VARIANT)?.is_some()),
        Err(e)
            if e.chain().any(|c| {
                c.downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
            }) =>
        {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

/// Remove our variant and re-make the policy with the PIN (the TPM policy must match the files again).
fn drop_variant(r: &dyn Runner, paths: &SysPaths) -> Result<()> {
    let d = authority_dir(paths, false)?;
    safefs::remove_at(&d, NEXT_SHIM_VARIANT)?;
    let pin = luks::read_pin(paths)?.ok_or_else(|| anyhow!("no pcrlock PIN on this machine"))?;
    luks::make_policy_with_pin_blocking(r, paths, CRED_DIR, &pin)
}

// ---------------------------------------------------------------------------------------------
// shim-prepare
// ---------------------------------------------------------------------------------------------

/// `mastersos-agent shim-prepare <new shim>`: see the module docs. Never prints or returns the PIN.
///
/// Precondition: the caller has verified `new_shim` (`mastersos-agent shim-check` passed on this very file, which lives on
/// the dm-verity `/usr`). The `.sbatlevel` section is trusted only because the Authenticode signature covers it.
pub fn prepare(sysfs: &Path, paths: &SysPaths, r: &dyn Runner, new_shim: &Path) -> PrepareOutcome {
    let shim = std::fs::read(new_shim);
    let shim_sha256 = shim
        .as_ref()
        .map(|b| hex(&Sha256::digest(b)))
        .unwrap_or_default();
    let _lock = match lock(paths) {
        Ok(l) => l,
        Err(e) => return PrepareOutcome::Failed(format!("{e:#}")),
    };
    let (outcome, predicted) = match shim {
        Ok(b) => prepare_locked(sysfs, paths, r, &b),
        Err(e) => (
            PrepareOutcome::Failed(format!("reading {}: {e}", new_shim.display())),
            None,
        ),
    };
    let (kind, reason) = match &outcome {
        PrepareOutcome::Prepared => (Outcome::Prepared, None),
        PrepareOutcome::NotNeeded(w) => (Outcome::NotNeeded, Some(w.clone())),
        PrepareOutcome::Failed(w) => (Outcome::Failed, Some(w.clone())),
    };
    let st = PrepareState {
        shim_sha256,
        predicted_sbat_sha256: predicted.map(|p| hex(&Sha256::digest(p))),
        outcome: kind,
        reason,
        boot_id: boot_id(&paths.root),
        at: now(),
    };
    if let Err(e) = save_state(paths, &st) {
        // Without the state file the luks job would treat the variant as stale; undo it so both agree.
        if outcome == PrepareOutcome::Prepared {
            let undo = drop_variant(r, paths)
                .err()
                .map(|u| format!("; undoing the variant failed too: {u:#}"))
                .unwrap_or_default();
            return PrepareOutcome::Failed(format!("writing {STATE_FILE}: {e:#}{undo}"));
        }
        // (shim-prepare runs as its own process; stderr goes to bootloader-update's journal)
        eprintln!("writing {STATE_FILE}: {e:#}");
    }
    outcome
}

fn prepare_locked(
    sysfs: &Path,
    paths: &SysPaths,
    r: &dyn Runner,
    shim: &[u8],
) -> (PrepareOutcome, Option<Vec<u8>>) {
    use PrepareOutcome::*;
    if luks::image_is_lab(&paths.root) && paths.root.join(TEST_FAIL_MARKER).exists() {
        return (Failed("test: forced failure".into()), None);
    }
    // 1. Only machines whose data partition is bound to pcrlock, with Secure Boot on
    let info = (|| -> Result<luks::LuksInfo> {
        let uuid = run_ok(
            r,
            Cmd::new("cryptsetup", &["luksUUID", luks::ROOT_LUKS_DEV]),
        )?;
        let json = run_ok(
            r,
            Cmd::new(
                "cryptsetup",
                &["luksDump", "--dump-json-metadata", luks::ROOT_LUKS_DEV],
            ),
        )?;
        luks::parse_luks_dump(&json, &uuid, None)
    })();
    match info {
        Ok(i) if !i.any_pcrlock => return (NotNeeded("no pcrlock TPM slot".into()), None),
        Ok(_) => {}
        Err(e) => return (Failed(format!("reading the LUKS header: {e:#}")), None),
    }
    match secure_boot_state(sysfs) {
        SecureBootState::On => {}
        SecureBootState::Off => return (NotNeeded("Secure Boot is off".into()), None),
        SecureBootState::Unknown(w) => {
            return (
                Failed(format!("cannot tell whether Secure Boot is on: {w}")),
                None,
            )
        }
    }
    if sysfs.join(SBAT_POLICY_VAR).exists() {
        return (
            Failed(
                "shim's SbatPolicy variable is set, so its default policy does not apply".into(),
            ),
            None,
        );
    }
    // 2. What the new shim will write
    let current = match read_sbat_level_rt(sysfs) {
        Ok(c) => c,
        Err(e) => return (Failed(format!("{e:#}")), None),
    };
    let next = match parse_sbatlevel_section(shim).and_then(|l| next_sbat_level(&current, &l)) {
        Ok(Some(n)) => n,
        Ok(None) => {
            return (
                NotNeeded("the new shim does not rewrite SbatLevel".into()),
                None,
            )
        }
        Err(e) => return (Failed(e), None),
    };
    match add_variant(sysfs, paths, r, &current, &next) {
        Ok(()) => (Prepared, Some(next)),
        Err(e) => (Failed(e), None),
    }
}

/// Steps 3–5: write the variant, re-make the policy with the PIN, check the prediction; undo on any failure after the
/// variant was written.
fn add_variant(
    sysfs: &Path,
    paths: &SysPaths,
    r: &dyn Runner,
    current: &[u8],
    next: &[u8],
) -> Result<(), String> {
    let old_d = authority_digest(SBAT_VAR_NAME, SHIM_GUID, current);
    let new_d = authority_digest(SBAT_VAR_NAME, SHIM_GUID, next);
    let dir = authority_dir(paths, false).map_err(|e| format!("{e:#}"))?;
    let generated = safefs::read_at(&dir, GENERATED)
        .map_err(|e| format!("{e:#}"))?
        .ok_or_else(|| format!("/{AUTHORITY_DIR}/{GENERATED} does not exist"))?;
    let generated = String::from_utf8(generated).map_err(|_| format!("{GENERATED} is not text"))?;
    let variant = variant_with_sbat(&generated, old_d, new_d)?;
    // Expected PCR 7 after the swap: replay the event log with the one digest swapped. The plain replay must reproduce
    // the TPM's current PCR 7, or the log is not what we think it is.
    let log = run_ok(r, Cmd::new(luks::PCRLOCK_BIN, &["log", "--json=short"]))
        .map_err(|e| format!("{e:#}"))?;
    let pcr_path = sysfs.join(PCR7_SYSFS);
    let cur_pcr = std::fs::read_to_string(&pcr_path)
        .ok()
        .and_then(|s| parse_hex32(&s))
        .ok_or_else(|| format!("cannot read {}", pcr_path.display()))?;
    if replay_pcr7(&log, None)? != cur_pcr {
        return Err("replaying the event log does not give the current PCR 7".into());
    }
    let expected = replay_pcr7(&log, Some((old_d, new_d)))?;
    let pin = luks::read_pin(paths)
        .map_err(|e| format!("{e:#}"))?
        .ok_or("no pcrlock PIN on this machine")?;
    safefs::write_at(&dir, NEXT_SHIM_VARIANT, variant.as_bytes(), 0o644)
        .map_err(|e| format!("writing {NEXT_SHIM_VARIANT}: {e:#}"))?;
    let check = (|| -> Result<(), String> {
        luks::make_policy_with_pin_blocking(r, paths, CRED_DIR, &pin)
            .map_err(|e| format!("{e:#}"))?;
        let out = run_ok(
            r,
            Cmd::new(
                luks::PCRLOCK_BIN,
                &["predict", "--pcr=7", "--location=770", "--json=short"],
            ),
        )
        .map_err(|e| format!("{e:#}"))?;
        let values = predicted_pcr7(&out)?;
        if !values.contains(&cur_pcr) {
            return Err("the new policy does not accept the current PCR 7".into());
        }
        if !values.contains(&expected) {
            return Err(format!(
                "the new policy does not accept the expected PCR 7 {}",
                hex(&expected)
            ));
        }
        Ok(())
    })();
    if let Err(e) = check {
        let undo = drop_variant(r, paths)
            .err()
            .map(|u| format!("; undoing it failed too: {u:#}"))
            .unwrap_or_default();
        return Err(format!("{e}{undo}"));
    }
    Ok(())
}

/// `mastersos-agent shim-prepare [--sysfs <dir>] <shim>`: exit 0 for Prepared / NotNeeded, 1 for Failed; one line on stdout.
/// Same precondition as [`prepare`]: only for a shim that `shim-check` has verified.
pub fn shim_prepare_main(args: impl Iterator<Item = std::ffi::OsString>) -> std::process::ExitCode {
    let mut sysfs = std::path::PathBuf::from("/sys");
    let mut shim = None;
    let mut args = args;
    while let Some(a) = args.next() {
        if a == "--sysfs" {
            match args.next() {
                Some(v) => sysfs = v.into(),
                None => return usage(),
            }
        } else if shim.is_none() {
            shim = Some(std::path::PathBuf::from(a));
        } else {
            return usage();
        }
    }
    let Some(shim) = shim else { return usage() };
    match prepare(
        &sysfs,
        &SysPaths::default(),
        &crate::runner::RealRunner,
        &shim,
    ) {
        PrepareOutcome::Prepared => {
            println!("prepared: the pcrlock policy accepts the new shim's SbatLevel");
            std::process::ExitCode::SUCCESS
        }
        PrepareOutcome::NotNeeded(w) => {
            println!("not needed: {w}");
            std::process::ExitCode::SUCCESS
        }
        PrepareOutcome::Failed(w) => {
            println!("failed: {w}");
            std::process::ExitCode::from(1)
        }
    }
}

fn usage() -> std::process::ExitCode {
    eprintln!("usage: mastersos-agent shim-prepare [--sysfs <dir>] <shim.efi>");
    std::process::ExitCode::from(1)
}

// ---------------------------------------------------------------------------------------------
// Follow-up in the luks job
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Followup {
    /// Nothing to report.
    Nothing,
    /// The new shim booted with the predicted SbatLevel; the variant is gone, the policy re-made.
    Completed,
    /// shim-prepare failed in this boot: the shim was replaced and the next boot needs the recovery key.
    PrepareFailed(String),
    /// The predicted SbatLevel came true but this boot still needed the recovery key (the policy service failed).
    Mispredicted,
}

/// Run by the luks job each round (data partition sealed, Secure Boot on), after its policy repair and while holding
/// [`lock`]. `sysfs` is `<root>/sys` in the job. `policy_failed`: `systemd-pcrlock-make-policy` failed in this boot
/// (the luks job repaired it with the PIN this round, or could not) — i.e. this boot did not unlock with the TPM, so a
/// matching SbatLevel must not be reported as "completed without the recovery key".
pub fn followup(
    sysfs: &Path,
    paths: &SysPaths,
    r: &dyn Runner,
    policy_failed: bool,
) -> Result<Followup> {
    let st = load_state(paths)?;
    let this_boot = boot_id(&paths.root);
    let rebooted = |s: &PrepareState| s.boot_id != this_boot;
    match st {
        None => {
            if variant_exists(paths)? {
                drop_variant(r, paths).context("removing a stale next-shim variant")?;
                log::info!("removed a next-shim pcrlock variant without a shim-prepare record");
            }
            Ok(Followup::Nothing)
        }
        Some(s) if s.outcome == Outcome::Failed && !rebooted(&s) => Ok(Followup::PrepareFailed(
            s.reason.unwrap_or_else(|| "unknown".into()),
        )),
        Some(s) if s.outcome == Outcome::Prepared && !rebooted(&s) => Ok(Followup::Nothing),
        // Keep reporting the outcome for the rest of the boot in which it happened (the report is what IT sees). A policy
        // failure later in that boot (the service finished after the round that marked it completed) overrides it.
        Some(s) if s.outcome == Outcome::Completed && !rebooted(&s) && policy_failed => {
            save_state(
                paths,
                &PrepareState {
                    outcome: Outcome::Mispredicted,
                    at: now(),
                    ..s
                },
            )?;
            Ok(Followup::Mispredicted)
        }
        Some(s) if s.outcome == Outcome::Completed && !rebooted(&s) => Ok(Followup::Completed),
        Some(s) if s.outcome == Outcome::Mispredicted && !rebooted(&s) => {
            Ok(Followup::Mispredicted)
        }
        Some(s) if s.outcome == Outcome::Prepared => {
            let now_sbat = read_sbat_level_rt(sysfs).map(|b| hex(&Sha256::digest(b)))?;
            let done = s.predicted_sbat_sha256.as_deref() == Some(now_sbat.as_str());
            if variant_exists(paths)? {
                drop_variant(r, paths).context("removing the next-shim variant")?;
            }
            if done {
                let outcome = if policy_failed {
                    Outcome::Mispredicted
                } else {
                    Outcome::Completed
                };
                save_state(
                    paths,
                    &PrepareState {
                        outcome: outcome.clone(),
                        boot_id: this_boot,
                        at: now(),
                        ..s
                    },
                )?;
                if outcome == Outcome::Completed {
                    log::info!("{DONE_DETAIL}");
                    Ok(Followup::Completed)
                } else {
                    log::warn!("{MISPREDICTED_DETAIL}");
                    Ok(Followup::Mispredicted)
                }
            } else {
                remove_state(paths)?;
                log::info!(
                    "rebooted without the predicted SbatLevel: removed the next-shim variant"
                );
                Ok(Followup::Nothing)
            }
        }
        // NotNeeded, Failed, Completed or Mispredicted after a reboot (a failed one: the policy repair already ran this
        // round)
        Some(_) => {
            if variant_exists(paths)? {
                drop_variant(r, paths).context("removing a stale next-shim variant")?;
            }
            remove_state(paths)?;
            Ok(Followup::Nothing)
        }
    }
}

/// `luks:pcrlock` detail for a failed prediction.
pub fn failed_detail(reason: &str) -> String {
    format!(
        "shim replaced, prediction failed ({reason}); this machine needs the recovery key at its next boot"
    )
}

#[cfg(test)]
mod tests;
