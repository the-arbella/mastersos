//! Device status for people at the machine: why they cannot sign in or have no browser.
//!
//! Three independent facts (network, school settings, Chrome) are classified here as plain data and written to
//! `status.json` under the public dir, where the login screen banner and the locked session can read it.
//! No timestamp is stored: content comparison is how callers decide whether anything changed.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use mastersos_bundle::ItemResult;
use serde::{Deserialize, Serialize};

use crate::chrome_sysext::ChromeStatus;
use crate::jobs::{Job, JobCtx};
use crate::runner::{Cmd, Runner};
use crate::safefs;
use crate::system::desktop::CHROME_BIN;
use crate::system::wifi;
use crate::system::{banner, public_dir, SysPaths};

pub const STATUS_FILE: &str = "status.json";

const NMCLI_TIMEOUT: Duration = Duration::from_secs(5);
const DETAIL_MAX_CHARS: usize = 160;

const MSG_NETWORK: &str = "No network. Connect to Wi-Fi from the top-right menu.";
const MSG_SETTINGS: &str = "Waiting for school settings.";
const MSG_CHROME: &str = "Installing the web browser. You can sign in; it will appear when ready.";
const MSG_CHROME_FAILED: &str =
    "The web browser could not be installed yet; it will try again. You can sign in.";

/// Every sentence the login-screen banner can start with. The login extension translates the
/// banner's first line through gettext, so each must be a msgid in
/// `image/mkosi.extra/usr/share/gnome-shell/extensions/mastersos-login@mastersos.org/strings.js`
/// (checked by `image/tests/check-tree.sh`).
pub const BANNER_SENTENCES: [&str; 4] = [MSG_NETWORK, MSG_SETTINGS, MSG_CHROME, MSG_CHROME_FAILED];

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Copy, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Net {
    Ok,
    NoAdapter,
    WifiOff,
    NotInRange,
    AuthFailed,
    Limited,
    Disconnected,
    /// NetworkManager is still activating a connection, or a problem that may clear by itself is inside the grace
    /// window ([`NetGrace`]). Not a banner: the network may still come.
    Connecting,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Copy, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Settings {
    Ok,
    Waiting,
    Unreachable,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Copy, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Browser {
    Ok,
    Installing,
    Failed,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct Status {
    pub network: Net,
    pub network_detail: Option<String>,
    pub settings: Settings,
    pub settings_detail: Option<String>,
    pub chrome: Browser,
    pub chrome_detail: Option<String>,
    /// The headline sentence (see [`Status::headline`]); `None` when everything is fine.
    /// Only [`Status::new`] sets it, so it cannot drift from the three states.
    #[serde(default)]
    pub message: Option<String>,
    /// IT is collecting diagnostics until about then (the login screen shows a line until it
    /// passes): from the drain's marker ([`set_collecting`]), absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diag_collecting_until: Option<chrono::DateTime<chrono::Utc>>,
}

impl Status {
    pub fn new(
        network: Net,
        network_detail: Option<String>,
        settings: Settings,
        settings_detail: Option<String>,
        chrome: Browser,
        chrome_detail: Option<String>,
    ) -> Status {
        let mut s = Status {
            network,
            network_detail,
            settings,
            settings_detail,
            chrome,
            chrome_detail,
            message: None,
            diag_collecting_until: None,
        };
        s.message = s.headline().map(|(m, _)| m.to_string());
        s
    }

    /// The first problem by priority network > settings > chrome, as (sentence, detail); `None` when all three are fine.
    pub fn headline(&self) -> Option<(&'static str, Option<&str>)> {
        if !matches!(self.network, Net::Ok | Net::Connecting) {
            Some((MSG_NETWORK, self.network_detail.as_deref()))
        } else if self.settings != Settings::Ok {
            Some((MSG_SETTINGS, self.settings_detail.as_deref()))
        } else if self.chrome == Browser::Failed {
            Some((MSG_CHROME_FAILED, self.chrome_detail.as_deref()))
        } else if self.chrome != Browser::Ok {
            Some((MSG_CHROME, self.chrome_detail.as_deref()))
        } else {
            None
        }
    }
}

/// Drops a query string (`?` up to the next space, `)` or quote), keeps the first line, cuts to 160 chars plus `…`.
pub fn short_detail(s: &str) -> String {
    let line = s.lines().next().unwrap_or("");
    let mut out = String::with_capacity(line.len());
    let mut in_query = false;
    for c in line.chars() {
        if in_query {
            if c.is_whitespace() || matches!(c, ')' | '"' | '\'') {
                in_query = false;
            } else {
                continue;
            }
        } else if c == '?' {
            in_query = true;
            continue;
        }
        out.push(c);
    }
    let out = out.trim();
    if out.chars().count() > DETAIL_MAX_CHARS {
        let mut cut: String = out.chars().take(DETAIL_MAX_CHARS).collect();
        cut.push('…');
        cut
    } else {
        out.to_string()
    }
}

pub fn settings_status(
    has_bundle: bool,
    last_fetch_error: Option<&str>,
) -> (Settings, Option<String>) {
    match (has_bundle, last_fetch_error) {
        (true, _) => (Settings::Ok, None),
        (false, None) => (Settings::Waiting, None),
        (false, Some(e)) => (Settings::Unreachable, Some(short_detail(e))),
    }
}

pub fn chrome_status(
    chrome_bin_exists: bool,
    last: Option<&ItemResult>,
) -> (Browser, Option<String>) {
    if chrome_bin_exists {
        return (Browser::Ok, None);
    }
    match last {
        Some(r) if !r.ok => (
            Browser::Failed,
            r.detail
                .as_deref()
                .map(short_detail)
                .filter(|d| !d.is_empty()),
        ),
        _ => (Browser::Installing, None),
    }
}

fn nmcli(runner: &dyn Runner, args: &[&str]) -> Option<String> {
    let out = runner
        .run(&Cmd::new("nmcli", args).timeout(NMCLI_TIMEOUT))
        .ok()?;
    (out.code == 0).then_some(out.stdout)
}

/// `nmcli -t` escapes `:` and `\` in values with a backslash.
fn unescape_terse(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            if let Some(n) = it.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Why there is no working network, from NetworkManager. See the table in the plan (Task 1); field names are
/// checked on a real machine in Task 5.
pub fn classify_network(runner: &dyn Runner, known_ssids: &[String]) -> (Net, Option<String>) {
    let Some(general) = nmcli(runner, &["-t", "-f", "STATE,CONNECTIVITY", "general"]) else {
        return (
            Net::Disconnected,
            Some("NetworkManager not answering".to_string()),
        );
    };
    let general = general.trim();
    // The image ships no NetworkManager connectivity-check config, so a working link may report `unknown`.
    if general == "connected:full" || general == "connected:unknown" {
        return (Net::Ok, None);
    }
    if general == "connected:none" || general.ends_with(":limited") {
        return (
            Net::Limited,
            Some("Connected, but no internet access".to_string()),
        );
    }
    if general.ends_with(":portal") {
        return (
            Net::Limited,
            Some("Connected, but behind a sign-in page (captive portal)".to_string()),
        );
    }

    if general.starts_with("connecting:") {
        return (Net::Connecting, Some("Connecting".to_string()));
    }

    // TYPE:STATE:DEVICE per line (the device name last, so it needs no unescaping of a middle field).
    let devices = nmcli(runner, &["-t", "-f", "TYPE,STATE,DEVICE", "device"]).unwrap_or_default();
    let mut wifi: Option<(String, String)> = None;
    let mut ethernet_up = false;
    for line in devices.lines() {
        let mut f = line.splitn(3, ':');
        let (ty, state, dev) = (
            f.next().unwrap_or(""),
            f.next().unwrap_or(""),
            f.next().unwrap_or(""),
        );
        match ty {
            "wifi" if wifi.is_none() => wifi = Some((state.to_string(), dev.to_string())),
            "ethernet" if state == "connected" => ethernet_up = true,
            _ => {}
        }
    }
    let Some((wifi_state, wifi_dev)) = wifi else {
        if ethernet_up {
            return (Net::Disconnected, Some("Not connected".to_string()));
        }
        return (Net::NoAdapter, Some("No Wi-Fi adapter found".to_string()));
    };
    // `connecting (configuring)`, `connecting (getting IP configuration)`, ...: the global state can lag behind.
    if wifi_state.starts_with("connecting") {
        return (Net::Connecting, Some("Connecting".to_string()));
    }
    if wifi_state == "unavailable" {
        return (Net::WifiOff, Some("Wi-Fi is turned off".to_string()));
    }

    let mut in_range: Option<&String> = None;
    if !known_ssids.is_empty() {
        let list = nmcli(
            runner,
            &[
                "-t", "-f", "SSID", "device", "wifi", "list", "--rescan", "no",
            ],
        )
        .unwrap_or_default();
        let seen: Vec<String> = list.lines().map(unescape_terse).collect();
        in_range = known_ssids.iter().find(|k| seen.iter().any(|s| s == *k));
        if in_range.is_none() {
            return (
                Net::NotInRange,
                Some(format!("Wi-Fi \"{}\" not found nearby", known_ssids[0])),
            );
        }
    }

    if let Some(reason) = nmcli(
        runner,
        &["-t", "-f", "GENERAL.REASON", "device", "show", &wifi_dev],
    ) {
        if reason_code(&reason).is_some_and(is_auth_reason) {
            let detail = match in_range {
                Some(ssid) => format!("Wi-Fi \"{ssid}\": could not sign in (wrong password?)"),
                None => "Wi-Fi: could not sign in (wrong password?)".to_string(),
            };
            return (Net::AuthFailed, Some(detail));
        }
    }
    (Net::Disconnected, Some("Not connected".to_string()))
}

/// The numeric NetworkManager device-state reason in `nmcli -t -f GENERAL.REASON device show` output
/// (`GENERAL.REASON:7 (Secrets were required, but not provided)`; the field name is optional).
fn reason_code(out: &str) -> Option<u32> {
    let line = out.lines().map(str::trim).find(|l| !l.is_empty())?;
    let v = line
        .strip_prefix("GENERAL.REASON:")
        .unwrap_or(line)
        .trim_start();
    let end = v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len());
    v[..end].parse().ok()
}

/// NetworkManager's `NMDeviceStateReason` codes that mean the Wi-Fi sign-in failed: 7 no secrets, 8 802.1X supplicant
/// disconnected, 9 supplicant configuration failed, 10 supplicant failed, 11 supplicant timed out. Matched by number,
/// not text: 42 "The supplicant is now available" is no failure.
fn is_auth_reason(code: u32) -> bool {
    matches!(code, 7..=11)
}

/// How long a network problem that may clear by itself stays off the banner: after the agent starts (boot), after the
/// network was last fine, after a definite problem, and after NetworkManager last tried to connect. A school laptop's
/// Wi-Fi often needs 10-30 s after boot to scan and associate.
pub const NET_GRACE: Duration = Duration::from_secs(45);

/// Whether `net` may clear without the person doing anything (held back in the grace window) or needs them now.
fn may_clear_by_itself(net: Net) -> bool {
    match net {
        // Nothing to hold back.
        Net::Ok | Net::Connecting => false,
        // No Wi-Fi hardware: waiting does not change it; a cable or a USB phone is needed.
        Net::NoAdapter => false,
        // The radio is switched off (switch, key or rfkill): only the person can turn it on.
        Net::WifiOff => false,
        // NetworkManager tried and the password was refused: retrying will not help.
        Net::AuthFailed => false,
        // The first scan after boot or resume may not have found the school network yet.
        Net::NotInRange => true,
        // Just associated: DHCP, DNS or the connectivity check may still be under way.
        Net::Limited => true,
        // NetworkManager not up yet, or between autoconnect attempts.
        Net::Disconnected => true,
    }
}

/// Holds back network problems that may clear by themselves for [`NET_GRACE`] (see [`may_clear_by_itself`]), so the
/// login screen does not say "No network" while the Wi-Fi is still connecting. The clock is passed in.
#[derive(Debug)]
pub struct NetGrace {
    /// Start of the current window; `None` while the network is fine or a definite problem is shown.
    since: Option<Instant>,
    /// When the window holding a problem back ends (the status job runs again then).
    wake_at: Option<Instant>,
}

impl NetGrace {
    /// A window that starts at `start` (the agent's start).
    pub fn new(start: Instant) -> NetGrace {
        NetGrace {
            since: Some(start),
            wake_at: None,
        }
    }

    /// The network state to publish for the classified `net` at `now`: [`Net::Connecting`] while it is held back.
    pub fn observe(
        &mut self,
        net: Net,
        detail: Option<String>,
        now: Instant,
    ) -> (Net, Option<String>) {
        self.wake_at = None;
        if net == Net::Connecting {
            self.since = Some(now);
            self.wake_at = Some(now + NET_GRACE);
            return (net, detail);
        }
        if !may_clear_by_itself(net) {
            self.since = None;
            return (net, detail);
        }
        let end = *self.since.get_or_insert(now) + NET_GRACE;
        if now < end {
            self.wake_at = Some(end);
            return (Net::Connecting, detail);
        }
        (net, detail)
    }

    /// When a held-back problem would show, so the status is looked at again then; `None` when nothing is held back.
    pub fn wake_at(&self) -> Option<Instant> {
        self.wake_at
    }
}

/// The one-shot round before GDM starts has no history: it holds problems back while the machine has been up for
/// less than [`NET_GRACE`]. Unknown uptime: no grace.
fn in_boot_grace(uptime: Option<Duration>) -> bool {
    uptime.is_some_and(|u| u < NET_GRACE)
}

/// Time since boot from `/proc/uptime` (includes suspend); `None` when unreadable.
fn boot_uptime() -> Option<Duration> {
    let text = std::fs::read_to_string("/proc/uptime").ok()?;
    let secs: f64 = text.split_whitespace().next()?.parse().ok()?;
    Duration::try_from_secs_f64(secs).ok()
}

/// Writes `status.json` (0644) in the public dir; `true` when the content changed.
pub fn write_status(paths: &SysPaths, s: &Status) -> Result<bool> {
    let dir = public_dir(paths)?;
    let mut bytes = serde_json::to_vec_pretty(s)?;
    bytes.push(b'\n');
    safefs::write_at(&dir, STATUS_FILE, &bytes, 0o644)
}

/// The marker of a diagnostics collection under way (RFC 3339 of when the notice ends), in the
/// state directory: written by the upload drain, read by every status round.
pub const COLLECTING_FILE: &str = "upload-collecting";

/// When the collection under way ends at the latest, from the marker.
pub fn collecting_until(paths: &SysPaths) -> Option<chrono::DateTime<chrono::Utc>> {
    let text = std::fs::read_to_string(paths.state_dir.join(COLLECTING_FILE)).ok()?;
    chrono::DateTime::parse_from_rfc3339(text.trim())
        .ok()
        .map(|t| t.to_utc())
}

/// Starts (`Some(until)`) or ends (`None`) the "IT is collecting" notice of the login screen:
/// writes or removes the marker, then puts it into the `status.json` already on disk at once
/// (the next status round keeps it from the marker). No `status.json` yet: only the marker.
pub fn set_collecting(
    paths: &SysPaths,
    until: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<()> {
    let dir = safefs::open_abs_dir(&paths.state_dir, false)?;
    match until {
        Some(t) => {
            let line = format!("{}\n", t.to_rfc3339());
            safefs::write_at(&dir, COLLECTING_FILE, line.as_bytes(), 0o600)?;
        }
        None => safefs::remove_at(&dir, COLLECTING_FILE)?,
    }
    if let Some(mut s) = read_status(paths) {
        if s.diag_collecting_until != until {
            s.diag_collecting_until = until;
            write_status(paths, &s).context("writing status.json")?;
        }
    }
    Ok(())
}

/// `None` when the file or directory is missing or unreadable.
pub fn read_status(paths: &SysPaths) -> Option<Status> {
    let dir = safefs::open_abs_dir(&paths.public_dir, false).ok()?;
    let bytes = safefs::read_at(&dir, STATUS_FILE).ok()??;
    serde_json::from_slice(&bytes).ok()
}

/// SSIDs of the school's Wi-Fi connections (`mastersos-*.nmconnection` under `root`), in file-name order. `system::wifi`
/// writes `ssid=` as a byte list (`83;99;`); a plain string is taken as is. Unreadable files are skipped.
fn known_ssids(root: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(root.join(wifi::CONN_DIR)) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            let n = e.file_name();
            let n = n.to_string_lossy();
            n.starts_with(wifi::PREFIX) && n.ends_with(wifi::SUFFIX)
        })
        .map(|e| e.path())
        .collect();
    files.sort();
    let mut out: Vec<String> = Vec::new();
    for f in files {
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        for line in text.lines() {
            let Some(v) = line.trim().strip_prefix("ssid=") else {
                continue;
            };
            let ssid = decode_ssid(v.trim());
            if !ssid.is_empty() && !out.contains(&ssid) {
                out.push(ssid);
            }
        }
    }
    out
}

/// `83;99;104;` → `Sch`; anything that is not a byte list stays as it is.
fn decode_ssid(v: &str) -> String {
    let parts: Vec<&str> = v.split(';').filter(|p| !p.is_empty()).collect();
    if v.contains(';') && !parts.is_empty() {
        if let Ok(bytes) = parts
            .iter()
            .map(|p| p.parse::<u8>())
            .collect::<Result<Vec<u8>, _>>()
        {
            return String::from_utf8_lossy(&bytes).into_owned();
        }
    }
    v.to_string()
}

/// One status round (blocking: `nmcli`, `dconf update`): classify the network (through `grace`, see [`NetGrace`]),
/// write `status.json` with it and `chrome`, then refresh the banner with the lock text from the login policy on disk.
/// `dconf_pending` carries a failed `dconf update` to the next round (the banner file is already written then, so the
/// next round sees no change); the resident job starts with it set, so its first round compiles once even when the banner on disk is unchanged (repairs a failed `apply-local` compile).
fn round(
    paths: &SysPaths,
    runner: &dyn Runner,
    has_bundle: bool,
    fetch_error: Option<&str>,
    chrome: (Browser, Option<String>),
    dconf_pending: &AtomicBool,
    grace: impl FnOnce(Net, Option<String>) -> (Net, Option<String>),
) -> Result<()> {
    let (network, network_detail) = classify_network(runner, &known_ssids(&paths.root));
    let (network, network_detail) = grace(network, network_detail);
    let (settings, settings_detail) = settings_status(has_bundle, fetch_error);
    let (chrome, chrome_detail) = chrome;
    let mut status = Status::new(
        network,
        network_detail,
        settings,
        settings_detail,
        chrome,
        chrome_detail,
    );
    status.diag_collecting_until = collecting_until(paths);
    write_status(paths, &status).context("writing status.json")?;
    match banner::refresh_from_policy(paths, runner) {
        Ok(true) => dconf_pending.store(false, Ordering::SeqCst),
        Ok(false) if dconf_pending.load(Ordering::SeqCst) => {
            banner::dconf_update(runner)?;
            dconf_pending.store(false, Ordering::SeqCst);
        }
        Ok(false) => {}
        Err(e) => {
            dconf_pending.store(true, Ordering::SeqCst);
            return Err(e.context("login screen banner"));
        }
    }
    Ok(())
}

/// One round outside the resident `run` (`apply-local`, before GDM starts), with the installed Chrome paths under
/// `paths`. Errors are logged.
pub fn refresh_once(
    paths: &SysPaths,
    runner: &dyn Runner,
    has_bundle: bool,
    fetch_error: Option<&str>,
) {
    refresh_once_at(paths, runner, has_bundle, fetch_error, boot_uptime());
}

/// [`refresh_once`] with the time since boot passed in.
pub fn refresh_once_at(
    paths: &SysPaths,
    runner: &dyn Runner,
    has_bundle: bool,
    fetch_error: Option<&str>,
    uptime: Option<Duration>,
) {
    let hold = in_boot_grace(uptime);
    let chrome = ChromeStatus::new(paths.state_dir.join("chrome"));
    let bin = paths.root.join(CHROME_BIN.trim_start_matches('/'));
    if let Err(e) = round(
        paths,
        runner,
        has_bundle,
        fetch_error,
        chrome_status(bin.exists(), chrome.last_result().as_ref()),
        &AtomicBool::new(false),
        |net, detail| {
            if hold && may_clear_by_itself(net) {
                (Net::Connecting, detail)
            } else {
                (net, detail)
            }
        },
    ) {
        log::warn!("device status: {e:#}");
    }
}

/// The time source of [`StatusJob`] (tests move it by hand).
pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

const EVERY: Duration = Duration::from_secs(30);

/// Background job of the resident `run`: recomputes the status every 30 s, on a wake (SIGUSR1: the NetworkManager
/// dispatcher, the Chrome service), on a new bundle, and just after a grace window holding a network problem back
/// ends (no dispatcher event comes then). Reports nothing.
pub struct StatusJob {
    chrome: ChromeStatus,
    chrome_bin: PathBuf,
    dconf_pending: Arc<AtomicBool>,
    clock: Clock,
    grace: Arc<Mutex<NetGrace>>,
    /// The last error logged (logged again only when it changes: the job runs every 30 s).
    last_error: Mutex<Option<String>>,
}

impl StatusJob {
    pub fn new(chrome: ChromeStatus, chrome_bin: PathBuf) -> Self {
        Self::with_clock(chrome, chrome_bin, Arc::new(Instant::now))
    }

    /// The grace window starts at `clock()` now (the agent's start).
    pub fn with_clock(chrome: ChromeStatus, chrome_bin: PathBuf, clock: Clock) -> Self {
        let start = clock();
        StatusJob {
            chrome,
            chrome_bin,
            // One `dconf update` per agent start: `apply-local`'s may have failed with the banner already on disk.
            dconf_pending: Arc::new(AtomicBool::new(true)),
            clock,
            grace: Arc::new(Mutex::new(NetGrace::new(start))),
            last_error: Mutex::new(None),
        }
    }
}

impl Job for StatusJob {
    fn name(&self) -> &'static str {
        "status"
    }

    /// 30 s, or sooner: 1 s after a grace window holding a network problem back ends.
    fn every(&self) -> Duration {
        let wake_at = self
            .grace
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .wake_at();
        match wake_at {
            Some(t) => {
                (t.saturating_duration_since((self.clock)()) + Duration::from_secs(1)).min(EVERY)
            }
            None => EVERY,
        }
    }

    fn wake_on_signal(&self) -> bool {
        true
    }

    fn wake_on_new_bundle(&self) -> bool {
        true
    }

    fn run<'a>(
        &'a self,
        cx: &'a JobCtx,
    ) -> Pin<Box<dyn Future<Output = Vec<ItemResult>> + Send + 'a>> {
        Box::pin(async move {
            let has_bundle = cx.current.borrow().is_some();
            let fetch_error = cx.fetch_error.borrow().clone();
            let chrome_last = self.chrome.last_result();
            let (paths, runner, bin, pending, grace, clock) = (
                cx.paths.clone(),
                cx.runner.clone(),
                self.chrome_bin.clone(),
                self.dconf_pending.clone(),
                self.grace.clone(),
                self.clock.clone(),
            );
            let r = tokio::task::spawn_blocking(move || {
                round(
                    &paths,
                    runner.as_ref(),
                    has_bundle,
                    fetch_error.as_deref(),
                    chrome_status(bin.exists(), chrome_last.as_ref()),
                    &pending,
                    |net, detail| {
                        let mut g = grace.lock().unwrap_or_else(|e| e.into_inner());
                        g.observe(net, detail, clock())
                    },
                )
            })
            .await;
            let err = match r {
                Ok(Ok(())) => None,
                Ok(Err(e)) => Some(format!("{e:#}")),
                Err(e) => Some(format!("status round did not finish: {e}")),
            };
            let mut last = self.last_error.lock().unwrap_or_else(|e| e.into_inner());
            if err != *last {
                if let Some(e) = &err {
                    log::warn!("device status: {e}");
                }
                *last = err;
            }
            vec![]
        })
    }
}

#[cfg(test)]
mod tests;
