//! The diagnostics collector: a fixed whitelist of commands and files, one archive file per
//! [`source`] (one per boot for the journal), every text file through [`redact`], a
//! `manifest.json` at the root, packed as `tar.zst`.
//!
//! Never collected (Global Constraints): the seed partition (seed, `identity.json`, tokens),
//! `/etc/NetworkManager/system-connections/`, private keys and token files, home folders. The
//! collector reads only the files in [`READ_PATHS`] (plus the screenshot it is handed) and runs
//! only the commands below; it never lists or copies a directory except `/sys/class/power_supply`.
//!
//! Command output over the runner's cap ([`JOURNAL_MAX_BYTES`] for the journal) keeps its newest
//! part; the cut is recorded in `skipped` and marks the archive `truncated`.
//!
//! Every file read goes through [`CollectOpts::root`] (`/` in production; a fake tree in tests,
//! Ruling P2).

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use mastersos_bundle::diag::{
    source, DiagFile, DiagFileType, DiagKind, DiagManifest, DiagSkipped, DIAG_MANIFEST_FORMAT,
    DIAG_MANIFEST_NAME,
};

use super::redact::redact;
use crate::runner::{Cmd, Runner};

/// At most this many boots of the journal (`collect-diagnostics` allows 1..=5).
pub const MAX_BOOTS: u8 = 5;
/// A screenshot larger than this is not attached.
pub const SCREENSHOT_MAX_BYTES: u64 = 5 * 1024 * 1024;
const ZSTD_LEVEL: i32 = 9;
/// The cloud decompresses with a window of at most 8 MiB (its server is small): the encoder's
/// window is set explicitly, no long-distance matching, no ultra levels.
pub const ZSTD_WINDOW_LOG: u32 = mastersos_bundle::diag::DIAG_ZSTD_WINDOW_LOG_MAX;
const CMD_TIMEOUT: Duration = Duration::from_secs(20);
/// A boot of the journal with debug logging is easily a million lines.
const JOURNAL_TIMEOUT: Duration = Duration::from_secs(300);
/// The newest this much of one journal (a boot, or the recent minutes) is kept; an older
/// beginning is left out and the archive marked truncated.
pub const JOURNAL_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Files under /proc, /sys and the agent's own JSON are small; anything longer is cut.
const FILE_MAX_BYTES: u64 = 4 * 1024 * 1024;
/// At most this many `coredumpctl info` and `loginctl show-session` calls.
const MAX_COREDUMPS: usize = 10;
const MAX_SESSIONS: usize = 20;
const REASON_MAX_CHARS: usize = 200;
const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

const CMDLINE: &str = "proc/cmdline";
const INPUT_DEVICES: &str = "proc/bus/input/devices";
const MEM_SLEEP: &str = "sys/power/mem_sleep";
const OS_RELEASE: &str = "etc/os-release";
const OS_RELEASE_FALLBACK: &str = "usr/lib/os-release";
const POWER_SUPPLY: &str = "sys/class/power_supply";
/// The agent's own state (no secrets in it, still redacted). Only this file of the state
/// directory: `seed.toml` and `fetch-token` beside it are never read.
const AGENT_STATE: &str = "var/lib/mastersos/state.json";
/// The latest device status the agent classified (network, settings, Chrome): `status.json` in
/// the public dir ([`crate::status::STATUS_FILE`]). The status report sent to the server is not
/// kept on disk; this is the newest status the agent keeps.
const STATUS_REPORT: &str = "var/lib/mastersos-public/status.json";

/// Every path (relative to the root) the collector reads, besides the screenshot it is handed
/// and the `uevent` files of the entries of [`POWER_SUPPLY`].
pub const READ_PATHS: &[&str] = &[
    CMDLINE,
    INPUT_DEVICES,
    MEM_SLEEP,
    OS_RELEASE,
    OS_RELEASE_FALLBACK,
    POWER_SUPPLY,
    AGENT_STATE,
    STATUS_REPORT,
];

/// One plain command per source, in [`source::ALL`] order.
const COMMANDS: &[(&str, &str, &[&str])] = &[
    (
        source::COREDUMP_LIST,
        "coredumpctl",
        &["list", "--no-pager"],
    ),
    (
        source::SYSTEMD_FAILED,
        "systemctl",
        &["--failed", "--no-pager"],
    ),
    (
        source::SYSTEMD_UNITS,
        "systemctl",
        &["list-units", "--all", "--no-pager"],
    ),
    (source::NM_GENERAL, "nmcli", &["general"]),
    (source::NM_DEVICE, "nmcli", &["device"]),
    // never --show-secrets
    (source::NM_CONNECTION, "nmcli", &["connection", "show"]),
    (source::IP_ADDR, "ip", &["addr"]),
    (source::IP_ROUTE, "ip", &["route"]),
    (source::RESOLVECTL, "resolvectl", &["status", "--no-pager"]),
    (source::RFKILL, "rfkill", &["list"]),
    (source::IW_DEV, "iw", &["dev"]),
    (source::IW_REG, "iw", &["reg", "get"]),
    (source::WIFI_SCAN, "nmcli", &["device", "wifi", "list"]),
    (source::LSPCI, "lspci", &["-nnk"]),
    (source::LSUSB, "lsusb", &[]),
    (source::BOOTCTL, "bootctl", &["status", "--no-pager"]),
];

pub struct CollectOpts {
    /// Prefix of every file read: `/` in production (Ruling P2).
    pub root: PathBuf,
    pub kind: DiagKind,
    /// How many boots of the journal (1..=[`MAX_BOOTS`]); ignored when `since_minutes` is set.
    pub boots: u8,
    /// Light mode (help tickets): only the journal of the last M minutes, as `journal/recent.txt`.
    pub since_minutes: Option<u32>,
    /// Light mode anchored to a moment (help tickets, Task 5b): only the journal from `since` to `until`, as
    /// `journal/recent.txt`; wins over `since_minutes` and `boots`.
    pub journal_window: Option<(DateTime<Utc>, DateTime<Utc>)>,
    /// A PNG the student chose to attach (read through `root` too).
    pub screenshot: Option<PathBuf>,
    /// The archive never exceeds this (`DIAG_INBOX_MAX_BYTES` / `DIAG_TICKET_MAX_BYTES`).
    pub max_bytes: u64,
}

#[derive(Debug)]
pub struct Collected {
    /// The archive (mode 0600) in `out_dir`.
    pub path: PathBuf,
    pub bytes: u64,
    /// Lower-case hex of the archive's SHA-256.
    pub sha256: String,
    pub manifest: DiagManifest,
}

struct Entry {
    file: DiagFile,
    data: Vec<u8>,
    /// Logs can be left out to fit the limit, the largest first: boot k is k + 1, the recent journal 0.
    log_age: Option<u32>,
}

#[derive(Default)]
struct Gather {
    entries: Vec<Entry>,
    skipped: Vec<DiagSkipped>,
    /// Some output was cut for size ([`crate::runner::CUT_MARKER`]).
    cut: bool,
}

impl Gather {
    fn text(&mut self, src: &str, path: String, text: &str, log_age: Option<u32>) {
        let text = match text.strip_prefix(crate::runner::CUT_MARKER) {
            Some(rest) => {
                self.cut = true;
                self.skip(
                    src,
                    &format!("{path}: the beginning was left out: over the size limit"),
                );
                rest
            }
            None => text,
        };
        let data = redact(text).into_owned().into_bytes();
        self.entries.push(Entry {
            file: DiagFile {
                path,
                source: src.to_string(),
                kind: DiagFileType::Text,
                bytes: data.len() as u64,
            },
            data,
            log_age,
        });
    }

    fn skip(&mut self, src: &str, reason: &str) {
        let reason: String = redact(reason)
            .trim()
            .chars()
            .take(REASON_MAX_CHARS)
            .collect();
        self.skipped.push(DiagSkipped {
            source: src.to_string(),
            reason,
        });
    }

    /// Runs `program args`; its output, or why not.
    fn run(
        &mut self,
        runner: &dyn Runner,
        src: &str,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Option<String> {
        let mut cmd = Cmd::new(program, args).timeout(timeout);
        if program == "journalctl" {
            cmd = cmd.max_output(JOURNAL_MAX_BYTES);
        }
        match runner.run(&cmd) {
            Ok(out) if out.code == 0 => {
                let mut text = out.stdout;
                if !out.stderr.trim().is_empty() {
                    text.push_str("\n--- stderr ---\n");
                    text.push_str(&out.stderr);
                }
                Some(text)
            }
            Ok(out) => {
                let last = out.stderr.trim_end().lines().last().unwrap_or("").trim();
                self.skip(src, &format!("{program} exited with {}: {last}", out.code));
                None
            }
            Err(e) => {
                self.skip(src, &format!("{e:#}"));
                None
            }
        }
    }

    fn command(&mut self, runner: &dyn Runner, src: &str, program: &str, args: &[&str]) {
        if let Some(text) = self.run(runner, src, program, args, CMD_TIMEOUT) {
            self.text(src, format!("{src}.txt"), &text, None);
        }
    }

    fn file(&mut self, root: &Path, src: &str, rels: &[&str], path: String) {
        let mut last = String::new();
        for rel in rels {
            match read_capped(&under(root, rel), FILE_MAX_BYTES) {
                Ok(b) => return self.text(src, path, &String::from_utf8_lossy(&b), None),
                Err(e) => last = format!("/{rel}: {e}"),
            }
        }
        self.skip(src, &last);
    }
}

/// `p` inside `root` (an absolute `p` loses its leading `/`).
fn under(root: &Path, p: impl AsRef<Path>) -> PathBuf {
    let p = p.as_ref();
    root.join(p.strip_prefix("/").unwrap_or(p))
}

fn read_capped(p: &Path, cap: u64) -> std::io::Result<Vec<u8>> {
    let mut b = Vec::new();
    File::open(p)?.take(cap).read_to_end(&mut b)?;
    Ok(b)
}

/// Collects the whitelist, writes the archive to `out_dir` (temporary name, then renamed; 0600)
/// and returns it. Over `max_bytes`, the oldest boot's journal is left out first (then the
/// newer ones, then the recent journal) and the manifest says `truncated`; still over without
/// any log, an error and no file.
pub fn collect(
    o: &CollectOpts,
    device_id: &str,
    out_dir: &Path,
    runner: &dyn Runner,
    now: DateTime<Utc>,
) -> Result<Collected> {
    let root = o.root.as_path();
    let mut g = Gather::default();

    match (o.journal_window, o.since_minutes) {
        (Some((since, until)), _) => journal_window(&mut g, runner, since, until),
        (None, Some(m)) => {
            let since = format!("-{m}min");
            let args = [
                "--since",
                since.as_str(),
                "-o",
                "short-iso-precise",
                "--no-pager",
            ];
            let src = source::JOURNAL_RECENT;
            if let Some(t) = g.run(runner, src, "journalctl", &args, JOURNAL_TIMEOUT) {
                g.text(src, "journal/recent.txt".into(), &t, Some(0));
            }
        }
        (None, None) => {
            for k in 0..o.boots.clamp(1, MAX_BOOTS) {
                let boot = if k == 0 {
                    "0".to_string()
                } else {
                    format!("-{k}")
                };
                let args = ["-b", boot.as_str(), "-o", "short-iso-precise", "--no-pager"];
                let src = source::JOURNAL;
                if let Some(t) = g.run(runner, src, "journalctl", &args, JOURNAL_TIMEOUT) {
                    g.text(
                        src,
                        format!("journal/boot-{k}.txt"),
                        &t,
                        Some(u32::from(k) + 1),
                    );
                }
            }
        }
    }

    for (src, program, args) in COMMANDS {
        match *src {
            source::COREDUMP_LIST => coredumps(&mut g, runner),
            source::SYSTEMD_UNITS => {
                g.command(runner, src, program, args);
                sessions(&mut g, runner);
            }
            _ => g.command(runner, src, program, args),
        }
    }

    g.file(root, source::CMDLINE, &[CMDLINE], "cmdline.txt".into());
    g.file(
        root,
        source::INPUT_DEVICES,
        &[INPUT_DEVICES],
        "input-devices.txt".into(),
    );
    g.file(
        root,
        source::MEM_SLEEP,
        &[MEM_SLEEP],
        "mem-sleep.txt".into(),
    );
    power_supply(&mut g, root);
    g.file(
        root,
        source::OS_RELEASE,
        &[OS_RELEASE, OS_RELEASE_FALLBACK],
        "os-release.txt".into(),
    );
    g.file(
        root,
        source::AGENT_STATE,
        &[AGENT_STATE],
        "agent-state.json".into(),
    );
    g.file(
        root,
        source::STATUS_REPORT,
        &[STATUS_REPORT],
        "status-report.json".into(),
    );
    if let Some(p) = &o.screenshot {
        screenshot(&mut g, &under(root, p));
    }

    let Gather {
        mut entries,
        skipped,
        cut,
    } = g;
    let mut manifest = DiagManifest {
        format: DIAG_MANIFEST_FORMAT,
        created_at: now,
        device_id: device_id.to_string(),
        kind: o.kind,
        truncated: cut,
        files: vec![],
        skipped,
    };
    let mtime = now.timestamp().max(0) as u64;
    let packed = loop {
        manifest.files = entries.iter().map(|e| e.file.clone()).collect();
        manifest
            .validate()
            .map_err(|e| anyhow::anyhow!("diagnostics manifest: {e}"))?;
        let packed = pack(&manifest, &entries, mtime)?;
        if packed.len() as u64 <= o.max_bytes {
            break packed;
        }
        let oldest = entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| e.log_age.map(|a| (a, i)))
            .max();
        let Some((_, i)) = oldest else {
            bail!(
                "the diagnostics archive is {} bytes without any log, over the limit of {}",
                packed.len(),
                o.max_bytes
            );
        };
        let e = entries.remove(i);
        manifest.truncated = true;
        manifest.skipped.push(DiagSkipped {
            source: e.file.source,
            reason: format!("{} left out: over the size limit", e.file.path),
        });
    };

    let name = format!("diag-{}.tar.zst", now.format("%Y%m%dT%H%M%SZ"));
    let path = out_dir.join(&name);
    write_new(out_dir, &name, &packed)?;
    Ok(Collected {
        path,
        bytes: packed.len() as u64,
        sha256: crate::apply::sha256_hex(&packed),
        manifest,
    })
}

/// `coredumpctl list`, then `coredumpctl info <pid>` for the newest few (no core files).
fn coredumps(g: &mut Gather, runner: &dyn Runner) {
    let Some(list) = g.run(
        runner,
        source::COREDUMP_LIST,
        "coredumpctl",
        &["list", "--no-pager"],
        CMD_TIMEOUT,
    ) else {
        g.skip(source::COREDUMP_INFO, "no coredump list");
        return;
    };
    g.text(
        source::COREDUMP_LIST,
        "coredump-list.txt".into(),
        &list,
        None,
    );
    // TIME is four columns ("Tue 2026-11-05 10:00:00 UTC"), then PID
    let pids: Vec<&str> = list
        .lines()
        .filter_map(|l| l.split_whitespace().nth(4))
        .filter(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()))
        .collect();
    if pids.is_empty() {
        g.skip(source::COREDUMP_INFO, "no coredumps");
        return;
    }
    let mut text = String::new();
    for pid in &pids[pids.len().saturating_sub(MAX_COREDUMPS)..] {
        let args = ["info", "--no-pager", pid];
        if let Some(t) = g.run(
            runner,
            source::COREDUMP_INFO,
            "coredumpctl",
            &args,
            CMD_TIMEOUT,
        ) {
            text.push_str(&format!("== coredump {pid} ==\n{t}\n"));
        }
    }
    if !text.is_empty() {
        g.text(
            source::COREDUMP_INFO,
            "coredump-info.txt".into(),
            &text,
            None,
        );
    }
}

/// `loginctl list-sessions`, then `loginctl show-session` for each.
fn sessions(g: &mut Gather, runner: &dyn Runner) {
    let src = source::LOGINCTL;
    let Some(list) = g.run(
        runner,
        src,
        "loginctl",
        &["list-sessions", "--no-pager"],
        CMD_TIMEOUT,
    ) else {
        return;
    };
    let mut text = list.clone();
    let ids: Vec<&str> = list
        .lines()
        .skip(1)
        .filter(|l| !l.contains("listed."))
        .filter_map(|l| l.split_whitespace().next())
        .filter(|s| s.bytes().all(|c| c.is_ascii_alphanumeric()))
        .take(MAX_SESSIONS)
        .collect();
    for id in ids {
        let cmd = Cmd::new("loginctl", &["show-session", id]).timeout(CMD_TIMEOUT);
        if let Ok(out) = runner.run(&cmd) {
            if out.code == 0 {
                text.push_str(&format!("\n== session {id} ==\n{}", out.stdout));
            }
        }
    }
    g.text(src, "loginctl.txt".into(), &text, None);
}

/// The `uevent` of every entry of `/sys/class/power_supply`, in name order.
fn power_supply(g: &mut Gather, root: &Path) {
    let src = source::POWER_SUPPLY;
    let dir = under(root, POWER_SUPPLY);
    let mut names: Vec<String> = match fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect(),
        Err(e) => return g.skip(src, &format!("/{POWER_SUPPLY}: {e}")),
    };
    names.sort();
    let mut text = String::new();
    for n in &names {
        match read_capped(&dir.join(n).join("uevent"), FILE_MAX_BYTES) {
            Ok(b) => text.push_str(&format!("== {n} ==\n{}\n", String::from_utf8_lossy(&b))),
            Err(e) => text.push_str(&format!("== {n} ==\n(uevent: {e})\n")),
        }
    }
    if names.is_empty() {
        g.skip(src, "no power supplies");
    } else {
        g.text(src, "power-supply.txt".into(), &text, None);
    }
}

/// The journal from `since` to `until` as `journal/recent.txt` (a help ticket's window around its
/// request). When the journal has nothing before `since` it was rotated (or the machine was off)
/// and the window may be cut: `skipped` says so, beside what is left.
fn journal_window(g: &mut Gather, runner: &dyn Runner, since: DateTime<Utc>, until: DateTime<Utc>) {
    let stamp = |t: DateTime<Utc>| t.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let (s, u) = (stamp(since), stamp(until));
    let src = source::JOURNAL_RECENT;
    let args = [
        "--since",
        s.as_str(),
        "--until",
        u.as_str(),
        "-o",
        "short-iso-precise",
        "--no-pager",
    ];
    if let Some(t) = g.run(runner, src, "journalctl", &args, JOURNAL_TIMEOUT) {
        g.text(src, "journal/recent.txt".into(), &t, Some(0));
    }
    let before = [
        "--until",
        s.as_str(),
        "-n",
        "1",
        "-q",
        "-o",
        "short-unix",
        "--no-pager",
    ];
    let older = runner
        .run(&Cmd::new("journalctl", &before).timeout(JOURNAL_TIMEOUT))
        .ok()
        .filter(|o| o.code == 0)
        .is_some_and(|o| !o.stdout.trim().is_empty());
    if !older {
        g.skip(
            src,
            &format!("the journal has nothing before {s}: the window from {s} to {u} may be cut (rotated)"),
        );
    }
}

fn screenshot(g: &mut Gather, p: &Path) {
    let src = source::SCREENSHOT;
    let data = match read_capped(p, SCREENSHOT_MAX_BYTES + 1) {
        Ok(d) => d,
        Err(e) => return g.skip(src, &format!("reading the screenshot: {e}")),
    };
    if data.len() as u64 > SCREENSHOT_MAX_BYTES {
        return g.skip(src, "the screenshot is over 5 MiB");
    }
    if !data.starts_with(PNG_MAGIC) {
        return g.skip(src, "the screenshot is not a PNG");
    }
    g.entries.push(Entry {
        file: DiagFile {
            path: "screenshot.png".into(),
            source: src.to_string(),
            kind: DiagFileType::Image,
            bytes: data.len() as u64,
        },
        data,
        log_age: None,
    });
}

fn pack(manifest: &DiagManifest, entries: &[Entry], mtime: u64) -> Result<Vec<u8>> {
    let mut b = tar::Builder::new(Vec::new());
    let json = serde_json::to_vec_pretty(manifest).context("serializing the manifest")?;
    let mut add = |path: &str, data: &[u8]| -> Result<()> {
        let mut h = tar::Header::new_ustar();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(mtime);
        b.append_data(&mut h, path, data)
            .with_context(|| format!("adding {path} to the archive"))
    };
    add(DIAG_MANIFEST_NAME, &json)?;
    for e in entries {
        add(&e.file.path, &e.data)?;
    }
    let tar = b.into_inner().context("finishing the archive")?;
    compress(&tar)
}

fn compress(data: &[u8]) -> Result<Vec<u8>> {
    use zstd::zstd_safe::CParameter;
    let mut c = zstd::bulk::Compressor::new(ZSTD_LEVEL).context("starting zstd")?;
    c.set_parameter(CParameter::WindowLog(ZSTD_WINDOW_LOG))
        .context("setting the zstd window")?;
    c.set_parameter(CParameter::EnableLongDistanceMatching(false))
        .context("turning off zstd long-distance matching")?;
    c.compress(data).context("compressing the archive")
}

/// `dir/name` with `bytes`, mode 0600: written as a hidden temporary file, synced, renamed.
fn write_new(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let tmp = dir.join(format!(".{name}.tmp"));
    let _ = fs::remove_file(&tmp);
    let r = (|| -> Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("syncing {}", tmp.display()))?;
        fs::rename(&tmp, dir.join(name))
            .with_context(|| format!("renaming {} to {name}", tmp.display()))
    })();
    if r.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    r
}

#[cfg(test)]
mod tests;
