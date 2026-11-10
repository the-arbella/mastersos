//! What a `mastersos-agent deb-apps` round leaves behind, and the resident job that reports it (spec §4.9).
//!
//! Split as Chrome's ([`crate::chrome_sysext::ChromeStatus`]): the one-shot unit `mastersos-deb-apps.service` does the work
//! ([`super::round`]); the resident agent's [`DebAppsStatus`] only hands it the settings and reads what it wrote.
//!
//! - `<work>/wanted.json` (0600): the effective `[config.apps.deb]` and `ubuntu_mirror` of this device, and the applied
//!   bundle's directory (icons). Written by [`DebAppsStatus`] from the settings the main loop publishes (the unit runs
//!   under `ProtectSystem=strict` and cannot unpack or select a bundle itself); a changed one starts the unit at once.
//! - `<work>/result.json` (0600): the last round's [`AppResult`] per app and the round's own error.
//! - `/var/lib/mastersos-public/deb-apps.json` (0644, [`PUBLIC_FILE`]): only what the kiosk and desktop steps need,
//!   `{"v":1,"apps":{"<id>":{"state","exec","kiosk","desktop"}}}` — no URLs, versions or paths beyond `exec`.

use std::collections::BTreeMap;
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use mastersos_bundle::{DebApp, ItemResult};
use serde::{Deserialize, Serialize};

use super::WORK_DIR;
use crate::jobs::{CurrentGroup, Job, JobCtx};
use crate::runner::{run_ok, Cmd, Runner};
use crate::safefs;

/// The public status file.
pub const PUBLIC_FILE: &str = "/var/lib/mastersos-public/deb-apps.json";
/// The unit that runs a round.
pub const UNIT: &str = "mastersos-deb-apps.service";
pub(crate) const WANTED_FILE: &str = "wanted.json";
pub(crate) const RESULT_FILE: &str = "result.json";
/// The report item for the round as a whole (a source that cannot be read, the lock, …).
pub const ITEM: &str = "deb-apps";
/// The prefix of the per-app report items.
pub const ITEM_PREFIX: &str = "deb:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppState {
    /// Installed and merged for this image.
    Ready,
    /// Not installed yet (first install under way or postponed).
    Installing,
    /// A new version (or the removal) waits until nobody uses the app.
    WaitingForClose,
    Failed,
}

/// One app's outcome of a round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppResult {
    pub id: String,
    pub state: AppState,
    /// The main package's `Package` and `Version` (the one installed when `Ready`, otherwise the one fetched, if any).
    pub package: Option<String>,
    pub version: Option<String>,
    /// The shared dependencies added to the image (`name version`), for every app alike (they are resolved together).
    pub deps: Vec<String>,
    /// Paths removed from the app's tree (outside the allowlist, covering the system).
    pub pruned: usize,
    /// Files whose setuid or setgid bit was cleared.
    pub setid: Vec<String>,
    /// Why it failed, what it waits for, or a note.
    pub detail: Option<String>,
}

impl AppResult {
    pub(crate) fn new(id: &str, state: AppState) -> Self {
        AppResult {
            id: id.to_string(),
            state,
            package: None,
            version: None,
            deps: vec![],
            pruned: 0,
            setid: vec![],
            detail: None,
        }
    }

    /// The report's one English line.
    pub fn summary(&self) -> String {
        let state = match self.state {
            AppState::Ready => "ready",
            AppState::Installing => "installing",
            AppState::WaitingForClose => "waiting for the app to close",
            AppState::Failed => "failed",
        };
        let mut s = state.to_string();
        if let (Some(p), Some(v)) = (&self.package, &self.version) {
            s.push_str(&format!(": {p} {v}"));
        }
        if self.state == AppState::Ready || !self.deps.is_empty() {
            s.push_str(&format!(
                ", {} shared dependencies, {} paths pruned",
                self.deps.len(),
                self.pruned
            ));
            if !self.setid.is_empty() {
                let shown: Vec<&str> = self.setid.iter().take(3).map(String::as_str).collect();
                let more = self.setid.len().saturating_sub(3);
                s.push_str(&format!(", setuid/setgid cleared on {}", shown.join(" ")));
                if more > 0 {
                    s.push_str(&format!(" and {more} more"));
                }
            }
        }
        if let Some(d) = &self.detail {
            s.push_str(&format!(" ({d})"));
        }
        s
    }
}

/// One app in the public status file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicApp {
    pub state: AppState,
    /// The program, when `Ready`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<String>,
    pub kiosk: bool,
    /// `mastersos-app-<id>.desktop`.
    pub desktop: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PublicFile {
    v: u32,
    apps: BTreeMap<String, PublicApp>,
}

/// The public status; anything unreadable (missing, malformed, another version) is empty.
pub fn read_public(path: &Path) -> BTreeMap<String, PublicApp> {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice::<PublicFile>(&b).ok())
        .filter(|f| f.v == 1)
        .map(|f| f.apps)
        .unwrap_or_default()
}

/// Writes the public status atomically, 0644 (its directory is made 0755 when missing).
pub(crate) fn write_public(path: &Path, apps: &BTreeMap<String, PublicApp>) -> Result<()> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str()))
    else {
        return Err(anyhow!("malformed path {}", path.display()));
    };
    let dir = safefs::open_abs_dir(parent, true)?;
    let body = serde_json::to_vec(&PublicFile {
        v: 1,
        apps: apps.clone(),
    })?;
    safefs::write_at(&dir, name, &body, 0o644)?;
    Ok(())
}

/// The settings a round works from (see the module docs).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Wanted {
    #[serde(default)]
    pub apps: BTreeMap<String, DebApp>,
    #[serde(default)]
    pub ubuntu_mirror: Option<String>,
    /// The applied bundle's unpacked directory (`files/…` icons); `None` when unknown.
    #[serde(default)]
    pub bundle_dir: Option<PathBuf>,
}

/// `<work>/wanted.json`; `None` when missing or unreadable (a round then changes nothing).
pub fn read_wanted(work: &Path) -> Option<Wanted> {
    let w = safefs::open_abs_dir(work, false).ok()?;
    let b = safefs::read_at(&w, WANTED_FILE).ok()??;
    serde_json::from_slice(&b).ok()
}

fn write_wanted(work: &Path, wanted: &Wanted) -> Result<()> {
    let w = safefs::open_abs_dir(work, true)?;
    safefs::set_mode(&w, 0o700)?;
    safefs::write_at(&w, WANTED_FILE, &serde_json::to_vec(wanted)?, 0o600)?;
    Ok(())
}

/// `<work>/result.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct Saved {
    #[serde(default)]
    pub apps: BTreeMap<String, AppResult>,
    /// The round's own failure.
    #[serde(default)]
    pub error: Option<String>,
    /// When the round finished (Unix seconds).
    #[serde(default)]
    pub finished_at: i64,
}

pub(crate) fn read_saved(work: &std::os::fd::OwnedFd) -> Option<Saved> {
    let b = safefs::read_at(work, RESULT_FILE).ok()??;
    serde_json::from_slice(&b).ok()
}

pub(crate) fn write_saved(work: &std::os::fd::OwnedFd, s: &Saved) -> Result<()> {
    let mut t = safefs::TmpFile::create(work, RESULT_FILE, 0o600)?;
    t.write_all(&serde_json::to_vec(s)?)
        .context("writing result.json")?;
    t.commit()
}

/// The settings for the unit from the main loop's current group; `state_dir` locates the applied bundle.
pub fn wanted_from(cur: &CurrentGroup, state_dir: &Path) -> Wanted {
    Wanted {
        apps: cur.config.apps.deb.clone(),
        ubuntu_mirror: cur.config.apps.ubuntu_mirror.clone(),
        bundle_dir: crate::state::current_version_name(state_dir)
            .map(|n| state_dir.join("versions").join(n)),
    }
}

/// The resident job (items `deb:<id>` and `deb-apps`): hands new settings to the unit and starts it, reports its results.
pub struct DebAppsStatus {
    runner: Arc<dyn Runner>,
    work: PathBuf,
    /// The settings changed while the unit could not be started (exam quiet, systemctl failed): start it later.
    start_pending: AtomicBool,
}

impl DebAppsStatus {
    pub fn new(runner: Arc<dyn Runner>) -> Self {
        Self::with_paths(runner, WORK_DIR.into())
    }

    /// Tests: another work directory.
    pub fn with_paths(runner: Arc<dyn Runner>, work: PathBuf) -> Self {
        DebAppsStatus {
            runner,
            work,
            start_pending: AtomicBool::new(false),
        }
    }

    /// Records `wanted` for the unit when it differs from what it has, and starts the unit unless `quiet` (then later).
    /// Settings without .deb apps replacing settings without them start nothing.
    pub async fn offer(&self, wanted: Wanted, quiet: bool) {
        let old = read_wanted(&self.work);
        if old.as_ref() != Some(&wanted) {
            if let Err(e) = write_wanted(&self.work, &wanted) {
                log::warn!("deb-apps: cannot record the settings for {UNIT}: {e:#}");
                return;
            }
            let idle = wanted.apps.is_empty() && old.is_none_or(|o| o.apps.is_empty());
            if !idle {
                self.start_pending.store(true, Ordering::SeqCst);
            }
        }
        if quiet || !self.start_pending.load(Ordering::SeqCst) {
            return;
        }
        let r = self.runner.clone();
        let started = tokio::task::spawn_blocking(move || {
            run_ok(
                r.as_ref(),
                Cmd::new("systemctl", &["start", "--no-block", UNIT])
                    .timeout(Duration::from_secs(30)),
            )
        })
        .await;
        match started {
            Ok(Ok(_)) => self.start_pending.store(false, Ordering::SeqCst),
            Ok(Err(e)) => {
                log::warn!("deb-apps: starting {UNIT} failed (retrying next round): {e:#}")
            }
            Err(e) => log::warn!("deb-apps: starting {UNIT} exited abnormally: {e}"),
        }
    }

    /// The items of the last round's results.
    pub(crate) fn report(&self) -> Vec<ItemResult> {
        let saved = safefs::open_abs_dir(&self.work, false)
            .ok()
            .and_then(|w| read_saved(&w));
        let wanted = read_wanted(&self.work).unwrap_or_default();
        let Some(saved) = saved else {
            return if wanted.apps.is_empty() {
                vec![]
            } else {
                vec![ItemResult {
                    item: ITEM.into(),
                    ok: true,
                    detail: Some("no round has finished yet".into()),
                }]
            };
        };
        if saved.apps.is_empty() && saved.error.is_none() && wanted.apps.is_empty() {
            return vec![];
        }
        let mut items: Vec<ItemResult> = saved
            .apps
            .values()
            .map(|a| ItemResult {
                item: format!("{ITEM_PREFIX}{}", a.id),
                ok: a.state != AppState::Failed,
                detail: Some(a.summary()),
            })
            .collect();
        let when = chrono::DateTime::from_timestamp(saved.finished_at, 0)
            .map(|d| d.format("%Y-%m-%d %H:%M:%SZ").to_string())
            .unwrap_or_else(|| "unknown".into());
        items.push(match &saved.error {
            Some(e) => ItemResult {
                item: ITEM.into(),
                ok: false,
                detail: Some(format!("{e} (round at {when})")),
            },
            None => ItemResult {
                item: ITEM.into(),
                ok: true,
                detail: Some(format!("{} apps (round at {when})", saved.apps.len())),
            },
        });
        items
    }
}

impl Job for DebAppsStatus {
    fn name(&self) -> &'static str {
        "deb-apps-status"
    }

    /// The unit wakes the agent (SIGUSR1) when it finishes; this is the fallback.
    fn every(&self) -> Duration {
        Duration::from_secs(15 * 60)
    }

    fn runs_in_quiet(&self) -> bool {
        true
    }

    fn wake_on_new_bundle(&self) -> bool {
        true
    }

    fn replaces_items(&self) -> Option<&'static str> {
        Some(ITEM_PREFIX)
    }

    fn run<'a>(
        &'a self,
        cx: &'a JobCtx,
    ) -> Pin<Box<dyn Future<Output = Vec<ItemResult>> + Send + 'a>> {
        Box::pin(async move {
            let cur = cx.current.borrow().clone();
            if let Some(cur) = cur {
                let quiet = cx.quiet.borrow().is_some();
                self.offer(wanted_from(&cur, &cx.paths.state_dir), quiet)
                    .await;
            }
            self.report()
        })
    }
}
