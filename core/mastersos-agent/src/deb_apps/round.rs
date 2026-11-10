//! One `mastersos-agent deb-apps` round (spec §4.2-§4.9), run by `mastersos-deb-apps.service`.
//!
//! **Flow.** Take the work directory's `flock` (a second round fails at once) → the exam quiet is on: stop here, nothing
//! downloaded, resolved or merged, results untouched → merge away and delete `app-*.new` / `.old` left by an interrupted
//! round → fetch every main package ([`fetch`]: a pinned `sha256` downloads once, a mismatch is not retried for a day;
//! without one a conditional GET at most once a day, `apps/<id>/checked-at`; a download that is not an amd64 package
//! never replaces the last good one) → resolve the dependencies of all apps in **one** apt run when anything they depend
//! on changed (main packages, `packages`, `ubuntu_mirror`, the image's `SYSEXT_LEVEL`; with a mirror also once a day;
//! after an image change the cached packages first, offline) → build the changed trees into `<ext>.new` ([`super::build`];
//! a changed app whose build failed is not built again from the same inputs for a day)
//! → check overlaps against `google-chrome`, the installed and the new trees (the later-built one fails) → check the quiet
//! again → swap in, except what is in use ([`in_use`]; a first install is exempt) → uninstall removed apps → write
//! `state.json`, `result.json` and the public status.
//!
//! **Lock order.** The work directory's `flock` for the whole round; [`sysext::MERGE_LOCK`] only inside
//! [`sysext::swap_in`], [`sysext::remove_ext`] and [`sysext::recover_leftover`] (as Chrome), never the other way round.
//!
//! **Quiet during the build.** A locked session that starts while trees are being built is seen right before the first
//! swap: every `.new` is deleted (not kept: the next round's leftover recovery would merge and delete it anyway, and the
//! settings may change before then) and the round ends without merging; the next round builds again.
//!
//! **Work directory** (`/var/lib/mastersos/deb-apps`, 0700): `wanted.json` (from the resident agent), `state.json` (what is
//! installed and the last resolution), `result.json`, `apps/<id>/` (`app.deb`, `fetched.json` with the validators,
//! `checked-at`, an `https://` icon, `installed.deb` — the package the merged tree was built from, used when it must be
//! rebuilt for a new image (always for an unpinned app; a pinned one while its source is unreachable) — and `pin-failed` after a pinned download did not match),
//! `apt/` (apt's private directory; `apt/archives` is the dependency cache, kept under
//! apt's own names and pruned to what the latest resolution uses), `opt-root/` (see [`super::build`]).
//! `apps/` and `apt/` are separate levels because an app id may be any lowercase word, `apt` or `archives` included.

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use super::assemble::ImageOwned;
pub use super::build::FreeSpace;
use super::build::{self, app_ext, AppSpec, Build, BuiltApp, DEPS_EXT};
pub use super::busy::{in_use, in_use_why, Evidence};
use super::busy::{kiosk_of, sessions_json};
use super::inputs::{
    app_key, check_record, dep_label, dependencies, fetch, icon_for, keep_installed,
    prune_archives, when, Main,
};
use super::status::{
    read_saved, write_public, write_saved, AppResult, AppState, PublicApp, Saved, Wanted,
    PUBLIC_FILE,
};
use super::{apt, UBUNTU_SOURCE, WORK_DIR};
use crate::runner::Runner;
use crate::safefs;
use crate::sysext;

pub(super) const DAY: i64 = 86_400;
const STATE_FILE: &str = "state.json";
const CHROME_EXT: &str = "google-chrome";

/// Where a round reads and writes; [`Default`] is the system's.
#[derive(Debug, Clone)]
pub struct RoundPaths {
    pub work: PathBuf,
    /// `/var/lib/extensions`.
    pub ext_dir: PathBuf,
    pub public_file: PathBuf,
    pub proc_root: PathBuf,
    /// `/opt` as the unit sees it (merged).
    pub opt_root: PathBuf,
    /// The image's factory dpkg file lists.
    pub factory_info: PathBuf,
    /// The image's list of `/usr` ([`super::assemble::USR_PATHS`]).
    pub usr_paths: PathBuf,
    pub ubuntu_source: PathBuf,
}

impl Default for RoundPaths {
    fn default() -> Self {
        RoundPaths {
            work: WORK_DIR.into(),
            ext_dir: "/var/lib/extensions".into(),
            public_file: PUBLIC_FILE.into(),
            proc_root: "/proc".into(),
            opt_root: "/opt".into(),
            factory_info: "/usr/share/factory/var/lib/dpkg/info".into(),
            usr_paths: super::assemble::USR_PATHS.into(),
            ubuntu_source: UBUNTU_SOURCE.into(),
        }
    }
}

pub struct RoundEnv {
    pub runner: Arc<dyn Runner>,
    pub http: reqwest::Client,
    pub paths: RoundPaths,
    /// Unix seconds.
    pub now: i64,
    /// The effective settings (`<work>/wanted.json`); `None`: none recorded yet, the round changes nothing.
    pub wanted: Option<Wanted>,
    /// The image's `SYSEXT_LEVEL` (`/usr/lib/os-release`).
    pub sysext_level: String,
    /// Free space of a path's file system ([`build::statvfs_free`]).
    pub free_space: FreeSpace,
}

impl RoundEnv {
    /// The system's: settings from `<work>/wanted.json`, the level from `/usr/lib/os-release`.
    pub fn production(runner: Arc<dyn Runner>) -> Result<RoundEnv> {
        let os = std::fs::read_to_string("/usr/lib/os-release").context("reading os-release")?;
        let level = os
            .lines()
            .find_map(|l| l.strip_prefix("SYSEXT_LEVEL="))
            .map(|v| v.trim().trim_matches(|c| c == '"' || c == '\'').to_string())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| anyhow!("/usr/lib/os-release has no SYSEXT_LEVEL"))?;
        let paths = RoundPaths::default();
        Ok(RoundEnv {
            runner,
            http: crate::fetch::http_client(crate::fetch::HttpOpts {
                connect: Duration::from_secs(30),
                read: None,
                total: None,
            }),
            wanted: super::status::read_wanted(&paths.work),
            paths,
            now: chrono::Utc::now().timestamp(),
            sysext_level: level,
            free_space: Arc::new(build::statvfs_free),
        })
    }
}

/// What is in `/var/lib/extensions` and how it was built.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct RoundState {
    #[serde(default)]
    pub(super) apps: BTreeMap<String, Installed>,
    #[serde(default)]
    pub(super) deps: Option<DepsInstalled>,
    #[serde(default)]
    pub(super) resolved: Option<Resolved>,
    /// Extension name → since when (Unix seconds) only a process's arguments have held its change back ([`busy`]).
    #[serde(default)]
    pub(super) argv_since: BTreeMap<String, i64>,
    /// App id → the last failed build of a changed app: the same inputs ([`app_key`]) are not built again for a day.
    #[serde(default)]
    pub(super) build_failed: BTreeMap<String, BuildFailed>,
    /// The extensions [`busy`] held back on arguments alone this round; the others' `argv_since` is dropped at its end.
    #[serde(skip)]
    pub(super) argv_held: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Installed {
    /// [`app_key`] of what was built.
    pub(super) key: String,
    /// The sha256 of the main package it was built from (empty in state written before it was recorded).
    #[serde(default)]
    pub(super) deb_sha256: String,
    pub(super) package: String,
    pub(super) version: String,
    pub(super) exec: String,
    pub(super) kiosk: bool,
    pub(super) level: String,
    pub(super) pruned: usize,
    pub(super) setid: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct BuildFailed {
    pub(super) key: String,
    /// Unix seconds.
    pub(super) at: i64,
    pub(super) why: String,
}

impl BuildFailed {
    /// Still holding back a build of `key` at `now`?
    fn holds(&self, key: &str, now: i64) -> bool {
        self.key == key && self.at <= now + DAY && now - self.at < DAY
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct DepsInstalled {
    pub(super) files: Vec<String>,
    pub(super) level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Resolved {
    pub(super) key: String,
    pub(super) level: String,
    /// File names in `apt/archives`.
    pub(super) files: Vec<String>,
    /// Unix seconds.
    pub(super) at: i64,
}

/// Runs a blocking closure with the runner off the async threads.
pub(super) async fn blocking<T: Send + 'static>(
    env: &RoundEnv,
    f: impl FnOnce(&dyn Runner) -> Result<T> + Send + 'static,
) -> Result<T> {
    let r = env.runner.clone();
    tokio::task::spawn_blocking(move || f(r.as_ref()))
        .await
        .map_err(|e| anyhow!("a blocking step exited abnormally: {e}"))?
}

async fn quiet_active(env: &RoundEnv) -> bool {
    blocking(env, |r| Ok(crate::quiet::target_active(r)))
        .await
        .unwrap_or(false)
}

fn lock_work(work: &Path) -> Result<OwnedFd> {
    let w = safefs::open_abs_dir(work, true)?;
    safefs::set_mode(&w, 0o700)?;
    if rustix::fs::flock(&w, rustix::fs::FlockOperation::NonBlockingLockExclusive).is_err() {
        bail!("another .deb apps round is in progress; skipping this one");
    }
    Ok(w)
}
/// `id` failed this round; the installed version (if any) stays.
fn failed(id: &str, st: &RoundState, why: String) -> AppResult {
    let mut r = AppResult::new(id, AppState::Failed);
    r.detail = Some(match st.apps.get(id) {
        Some(i) => {
            r.package = Some(i.package.clone());
            r.version = Some(i.version.clone());
            format!("{why}; keeping the installed version")
        }
        None => why,
    });
    r
}

fn ready_from(id: &str, i: &Installed, deps: &[String], note: Option<String>) -> AppResult {
    AppResult {
        id: id.to_string(),
        state: AppState::Ready,
        package: Some(i.package.clone()),
        version: Some(i.version.clone()),
        deps: deps.to_vec(),
        pruned: i.pruned,
        setid: i.setid.clone(),
        detail: note,
    }
}

fn has(ext: &OwnedFd, name: &str) -> bool {
    safefs::open_child_dir(ext, name).ok().flatten().is_some()
}

/// The image's file list and the root partition's `/opt` skeleton, made once per round before the first build.
type Prepared = (Arc<ImageOwned>, PathBuf);

async fn prepare(env: &RoundEnv, cache: &mut Option<Prepared>) -> Result<Prepared> {
    if let Some(x) = cache {
        return Ok(x.clone());
    }
    let p = &env.paths;
    let (fi, up, opt, ext_dir, w) = (
        p.factory_info.clone(),
        p.usr_paths.clone(),
        p.opt_root.clone(),
        p.ext_dir.clone(),
        p.work.clone(),
    );
    let x: Prepared = blocking(env, move |_| {
        let owned = super::assemble::image_owned(&fi, &up)?;
        let mirror = build::mirror_root_opt(&opt, &ext_dir, &w)?;
        Ok((Arc::new(owned), mirror))
    })
    .await?;
    *cache = Some(x.clone());
    Ok(x)
}

/// One round (see the module docs); the result per app, or the error of the round as a whole.
pub async fn run_once(env: &RoundEnv) -> Vec<AppResult> {
    let work = match lock_work(&env.paths.work) {
        Ok(w) => w,
        Err(e) => {
            log::warn!("deb-apps: {e:#}");
            return safefs::open_abs_dir(&env.paths.work, false)
                .ok()
                .and_then(|w| read_saved(&w))
                .map(|s| s.apps.into_values().collect())
                .unwrap_or_default();
        }
    };
    let prev = read_saved(&work).map(|s| s.apps).unwrap_or_default();
    if quiet_active(env).await {
        log::info!("deb-apps: a locked session is running (exam quiet); nothing done this round");
        return prev.into_values().collect();
    }
    let Some(wanted) = env.wanted.clone() else {
        log::info!("deb-apps: no settings recorded yet; nothing done this round");
        return prev.into_values().collect();
    };
    let mut st: RoundState = safefs::read_at(&work, STATE_FILE)
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let mut notes = vec![];
    let (apps, error) = match round(env, &work, &wanted, &mut st, &mut notes).await {
        Ok(a) => (a, None),
        Err(e) => {
            log::warn!("deb-apps: {e:#}");
            let kept = prev
                .into_iter()
                .filter(|(k, _)| wanted.apps.contains_key(k))
                .collect();
            (kept, Some(format!("{e:#}")))
        }
    };
    // the day counts from the first of an unbroken run of rounds held back on arguments alone: a round without one
    // (nothing pending, other evidence, the change went ahead or was dropped) starts it over
    let held = std::mem::take(&mut st.argv_held);
    st.argv_since.retain(|k, _| held.contains(k));
    if let Err(e) = serde_json::to_vec(&st)
        .map_err(anyhow::Error::from)
        .and_then(|b| safefs::write_at(&work, STATE_FILE, &b, 0o600).map(drop))
    {
        log::warn!("deb-apps: cannot write {STATE_FILE}: {e:#}");
    }
    let saved = Saved {
        apps,
        error,
        notes,
        finished_at: env.now,
    };
    if let Err(e) = write_saved(&work, &saved) {
        log::warn!("deb-apps: cannot write the results: {e:#}");
    }
    let ext = safefs::open_abs_dir(&env.paths.ext_dir, false).ok();
    let merged = |id: &str| -> Option<&Installed> {
        st.apps.get(id).filter(|i| {
            i.level == env.sysext_level && ext.as_ref().is_some_and(|e| has(e, &app_ext(id)))
        })
    };
    let ready = |id: &str, i: &Installed| PublicApp {
        state: AppState::Ready,
        exec: Some(i.exec.clone()),
        kiosk: i.kiosk,
        desktop: format!("mastersos-app-{id}.desktop"),
    };
    let mut public: BTreeMap<String, PublicApp> = wanted
        .apps
        .iter()
        .map(|(id, cfg)| {
            let p = match merged(id) {
                Some(i) => ready(id, i),
                None => PublicApp {
                    state: saved
                        .apps
                        .get(id)
                        .map(|a| a.state)
                        .filter(|s| *s != AppState::Ready)
                        .unwrap_or(AppState::Installing),
                    exec: None,
                    kiosk: cfg.kiosk,
                    desktop: format!("mastersos-app-{id}.desktop"),
                },
            };
            (id.clone(), p)
        })
        .collect();
    // removed from the settings but still merged (in use, or the round stopped first): it is there until it is gone
    for id in st.apps.keys().filter(|id| !wanted.apps.contains_key(*id)) {
        if let Some(i) = merged(id) {
            public.insert(id.clone(), ready(id, i));
        }
    }
    if let Err(e) = write_public(&env.paths.public_file, &public) {
        log::warn!("deb-apps: cannot write the public status: {e:#}");
    }
    drop(work);
    saved.apps.into_values().collect()
}

async fn round(
    env: &RoundEnv,
    work: &OwnedFd,
    wanted: &Wanted,
    st: &mut RoundState,
    notes: &mut Vec<String>,
) -> Result<BTreeMap<String, AppResult>> {
    let p = &env.paths;
    let level = env.sysext_level.clone();
    let ext = safefs::open_abs_dir(&p.ext_dir, true)?;

    // 1. what an interrupted round left: merge first, then delete (sysext::recover_leftover)
    for n in safefs::list_at(&ext)? {
        if n.starts_with("app-") && (n.ends_with(".new") || n.ends_with(".old")) {
            let dir = p.ext_dir.clone();
            blocking(env, move |r| {
                sysext::recover_leftover(r, &safefs::open_abs_dir(&dir, false)?, &n).map(drop)
            })
            .await?;
        }
    }
    let u = apt::read_ubuntu_source(
        &std::fs::read_to_string(&p.ubuntu_source)
            .with_context(|| format!("reading {}", p.ubuntu_source.display()))?,
    )?;

    // 2. the main packages
    let mut out: BTreeMap<String, AppResult> = BTreeMap::new();
    let mut mains: BTreeMap<String, Main> = BTreeMap::new();
    for (id, app) in &wanted.apps {
        if let Err(why) = check_record(id, app) {
            out.insert(id.clone(), failed(id, st, why));
            continue;
        }
        match fetch(env, work, id, app, st.apps.get(id)).await {
            Ok(m) => {
                mains.insert(id.clone(), m);
            }
            Err(e) => {
                out.insert(id.clone(), failed(id, st, format!("{e:#}")));
            }
        }
    }

    // 3. the shared dependencies, all apps together. An installed app whose package is not at hand this round (its
    // download or record check failed) still runs on the installed dependencies: they are neither resolved again nor
    // changed (nor the cache pruned) until it is back, and nothing that would need new ones is merged meanwhile.
    let held: Vec<String> = st
        .apps
        .iter()
        .filter(|(id, i)| {
            wanted.apps.contains_key(*id) && i.level == level && !mains.contains_key(*id)
        })
        .map(|(id, _)| id.clone())
        .collect();
    let deps = if held.is_empty() {
        dependencies(env, &u, wanted, &mains, st, notes).await
    } else {
        notes.push(format!(
            "the shared dependencies stay as they are while {} cannot be fetched or checked",
            held.join(", ")
        ));
        Ok(st
            .deps
            .as_ref()
            .filter(|d| d.level == level)
            .map(|d| d.files.clone())
            .unwrap_or_default())
    };
    let frozen = !held.is_empty();
    let labels: Vec<String> = deps
        .as_ref()
        .map(|f| f.iter().map(|n| dep_label(n)).collect())
        .unwrap_or_default();

    // 4. build what changed (staged privately, then <ext>.new)
    let mut prepared: Option<Prepared> = None;
    let mut new_deps = false;
    let mut new_apps: BTreeMap<String, (BuiltApp, String)> = BTreeMap::new();
    match &deps {
        Err(e) => {
            for id in mains.keys() {
                out.insert(
                    id.clone(),
                    failed(id, st, format!("resolving the dependencies failed: {e}")),
                );
            }
        }
        Ok(files) => {
            let want = DepsInstalled {
                files: files.clone(),
                level: level.clone(),
            };
            // what each app tree would be built from (IT's icon included)
            let mut inputs = BTreeMap::new();
            for (id, m) in &mains {
                let app = &wanted.apps[id];
                let (icon, icon_note) = icon_for(env, wanted, id, app).await;
                let key = app_key(m, app, &icon, &level);
                inputs.insert(id.clone(), (icon, icon_note, key));
            }
            // An installed app whose changed package failed to build within the day stays as it is, so the
            // dependencies resolved for its new version would only be built to be discarded (step 7): not built
            let waiting: Vec<String> = mains
                .iter()
                .filter(|(id, m)| {
                    st.apps.get(*id).is_some_and(|i| i.level == level)
                        && main_changed(st, id, m, &level)
                        && st
                            .build_failed
                            .get(*id)
                            .is_some_and(|f| f.holds(&inputs[*id].2, env.now))
                })
                .map(|(id, _)| id.clone())
                .collect();
            let deps_change = !frozen
                && !files.is_empty()
                && (st.deps.as_ref() != Some(&want) || !has(&ext, DEPS_EXT));
            let deps_skipped = deps_change && !waiting.is_empty();
            if deps_skipped {
                notes.push(format!(
                    "the shared dependencies change together with {}, whose update failed to build; tried again 24 hours later",
                    waiting.join(", ")
                ));
            }
            let mut deps_ok = true;
            if deps_change && !deps_skipped {
                let built = async {
                    let (owned, mirror) = prepare(env, &mut prepared).await?;
                    let debs: Vec<PathBuf> = files
                        .iter()
                        .map(|f| p.work.join("apt/archives").join(f))
                        .collect();
                    let (ext_dir, w, lv) = (p.ext_dir.clone(), p.work.clone(), level.clone());
                    let free = env.free_space.clone();
                    blocking(env, move |r| {
                        let b = Build {
                            runner: r,
                            ext_dir: &ext_dir,
                            work: &w,
                            owned: &owned,
                            opt_root: &mirror,
                            level: &lv,
                            free: &free,
                        };
                        build::build_deps(&b, &debs)
                    })
                    .await
                }
                .await;
                match built {
                    Ok(()) => new_deps = true,
                    Err(e) => {
                        build::discard(&p.ext_dir, &format!("{DEPS_EXT}.new"));
                        deps_ok = false;
                        for id in mains.keys() {
                            out.insert(
                                id.clone(),
                                failed(id, st, format!("building the dependencies failed: {e:#}")),
                            );
                        }
                    }
                }
            }
            for (id, m) in mains.iter().filter(|_| deps_ok) {
                let app = &wanted.apps[id];
                let (icon, icon_note, key) = inputs.remove(id).expect("every main has its inputs");
                let note = [m.note.clone(), icon_note]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();
                let note = (!note.is_empty()).then(|| note.join("; "));
                if let Some(i) = st.apps.get(id).filter(|i| i.key == key) {
                    if has(&ext, &app_ext(id)) {
                        out.insert(id.clone(), ready_from(id, i, &labels, note));
                        continue;
                    }
                }
                if frozen && main_changed(st, id, m, &level) {
                    let why = format!(
                        "the update waits until {} can be fetched again (the shared dependencies are held)",
                        held.join(", ")
                    );
                    out.insert(id.clone(), held_back(st, id, m, &labels, why));
                    continue;
                }
                if let Some(f) = st.build_failed.get(id).filter(|f| f.holds(&key, env.now)) {
                    let why = format!(
                        "building it failed at {} ({}); tried again 24 hours later, or as soon as the package or its settings change",
                        when(f.at),
                        f.why
                    );
                    out.insert(id.clone(), failed(id, st, why));
                    continue;
                }
                if deps_skipped && main_changed(st, id, m, &level) {
                    out.insert(
                        id.clone(),
                        held_back(
                            st,
                            id,
                            m,
                            &labels,
                            "the update waits for the shared dependencies to change".into(),
                        ),
                    );
                    continue;
                }
                let spec = AppSpec {
                    id: id.clone(),
                    name: app.name.clone(),
                    kiosk: app.kiosk,
                    exec: app.exec.clone(),
                    deb: m.path.clone(),
                    package: m.package.clone(),
                    icon,
                };
                let built = async {
                    let (owned, mirror) = prepare(env, &mut prepared).await?;
                    let (ext_dir, w, lv) = (p.ext_dir.clone(), p.work.clone(), level.clone());
                    let free = env.free_space.clone();
                    blocking(env, move |r| {
                        let b = Build {
                            runner: r,
                            ext_dir: &ext_dir,
                            work: &w,
                            owned: &owned,
                            opt_root: &mirror,
                            level: &lv,
                            free: &free,
                        };
                        build::build_app(&b, &spec)
                    })
                    .await
                }
                .await;
                let mut r = AppResult::new(id, AppState::Installing);
                r.package = Some(m.package.clone());
                r.version = Some(m.version.clone());
                r.deps = labels.clone();
                r.detail = note;
                match built {
                    Ok(b) => {
                        st.build_failed.remove(id);
                        r.pruned = b.pruned;
                        r.setid = b.setid.clone();
                        new_apps.insert(id.clone(), (b, key));
                    }
                    Err(e) => {
                        build::discard(&p.ext_dir, &format!("{}.new", app_ext(id)));
                        // free space comes back: only a failure of the package itself waits a day
                        if !e.chain().any(|c| c.is::<build::NoSpace>()) {
                            st.build_failed.insert(
                                id.clone(),
                                BuildFailed {
                                    key,
                                    at: env.now,
                                    why: format!("{e:#}"),
                                },
                            );
                        }
                        r.state = AppState::Failed;
                        r = AppResult {
                            detail: failed(id, st, format!("{e:#}")).detail,
                            ..r
                        };
                    }
                }
                out.insert(id.clone(), r);
            }
        }
    }

    // 5. overlaps: Chrome, the installed trees that stay, then the new ones; the later one fails. (google-chrome is read
    // without the merge lock: only its own unit changes it, and a tree swapped meanwhile is caught by the next round.)
    {
        let mut trees: Vec<(String, OwnedFd)> = vec![];
        let add = |name: &str, trees: &mut Vec<(String, OwnedFd)>| {
            if let Some(d) = safefs::open_child_dir(&ext, name).ok().flatten() {
                trees.push((name.to_string(), d));
            }
        };
        add(CHROME_EXT, &mut trees);
        if !new_deps {
            add(DEPS_EXT, &mut trees);
        }
        for id in wanted.apps.keys().filter(|id| !new_apps.contains_key(*id)) {
            add(&app_ext(id), &mut trees);
        }
        let check = |trees: &[(String, OwnedFd)], name: &str| -> Result<OwnedFd> {
            let new = safefs::open_child_dir(&ext, &format!("{name}.new"))?
                .ok_or_else(|| anyhow!("{name}.new is missing"))?;
            let mut v: Vec<(String, &OwnedFd)> =
                trees.iter().map(|(n, d)| (n.clone(), d)).collect();
            v.push((name.to_string(), &new));
            super::assemble::check_overlaps(&v)?;
            Ok(new)
        };
        if new_deps {
            match check(&trees, DEPS_EXT) {
                Ok(d) => trees.push((DEPS_EXT.into(), d)),
                Err(e) => {
                    new_deps = false;
                    build::discard(&p.ext_dir, &format!("{DEPS_EXT}.new"));
                    for id in std::mem::take(&mut new_apps).into_keys() {
                        build::discard(&p.ext_dir, &format!("{}.new", app_ext(&id)));
                        out.insert(id.clone(), failed(&id, st, format!("{e:#}")));
                    }
                }
            }
        }
        for id in new_apps.keys().cloned().collect::<Vec<_>>() {
            match check(&trees, &app_ext(&id)) {
                Ok(d) => trees.push((app_ext(&id), d)),
                Err(e) => {
                    new_apps.remove(&id);
                    build::discard(&p.ext_dir, &format!("{}.new", app_ext(&id)));
                    let keep = out.get(&id).cloned();
                    let mut r = failed(&id, st, format!("{e:#}"));
                    if let Some(k) = keep {
                        r.package = r.package.or(k.package);
                        r.version = r.version.or(k.version);
                    }
                    out.insert(id, r);
                }
            }
        }
    }

    // 6. right before anything is merged or removed: a locked session may have started during the round
    if quiet_active(env).await {
        log::info!("deb-apps: a locked session started during the round; nothing merged or removed this round");
        notes.push(
            "a locked session started during the round; nothing was merged or removed".into(),
        );
        if new_deps {
            build::discard(&p.ext_dir, &format!("{DEPS_EXT}.new"));
        }
        for id in std::mem::take(&mut new_apps).into_keys() {
            build::discard(&p.ext_dir, &format!("{}.new", app_ext(&id)));
            let m = &mains[&id];
            let r = held_back(
                st,
                &id,
                m,
                &labels,
                "waiting for the exam quiet to end".into(),
            );
            out.insert(id, r);
        }
        return Ok(out);
    }

    // 7. what is in use stays (a first install is exempt); the dependencies and the apps resolved with them go together
    let mut sessions: Option<String> = None;
    let installed_trees = |ext: &OwnedFd| -> Vec<PathBuf> {
        safefs::list_at(ext)
            .unwrap_or_default()
            .into_iter()
            .filter(|n| n.starts_with("app-") && !n.ends_with(".new") && !n.ends_with(".old"))
            .map(|n| p.ext_dir.join(n))
            .collect()
    };
    let deps_built = new_deps;
    if new_deps && has(&ext, DEPS_EXT) {
        let all_kiosk: Vec<String> = wanted
            .apps
            .keys()
            .chain(st.apps.keys())
            .flat_map(|id| kiosk_of(wanted, st, id))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let trees = installed_trees(&ext);
        let (b, note) = busy(env, st, DEPS_EXT, &trees, &all_kiosk, &mut sessions).await;
        notes.extend(note);
        if b {
            new_deps = false;
            notes.push("the shared dependencies change once no .deb app is running".into());
        }
    }
    for id in new_apps.keys().cloned().collect::<Vec<_>>() {
        let name = app_ext(&id);
        if !has(&ext, &name) {
            continue;
        }
        let kiosk = kiosk_of(wanted, st, &id);
        let (b, note) = busy(
            env,
            st,
            &name,
            &[p.ext_dir.join(&name)],
            &kiosk,
            &mut sessions,
        )
        .await;
        let r = out.get_mut(&id).expect("built apps have a result");
        if let Some(n) = note {
            r.detail = Some(match r.detail.take() {
                Some(d) => format!("{d}; {n}"),
                None => n,
            });
        }
        if b {
            new_apps.remove(&id);
            build::discard(&p.ext_dir, &format!("{name}.new"));
            r.state = AppState::WaitingForClose;
            r.detail = Some(match st.apps.get(&id) {
                Some(i) => format!(
                    "waiting for the app to close; {} stays installed until then",
                    i.version
                ),
                None => "waiting for the app to close".into(),
            });
        }
    }
    // An installed app whose package changed is not being updated (failed, overlapping, in use): the new dependencies
    // were resolved for its new version, so they are not merged under its old one
    if new_deps {
        let blockers: Vec<String> = mains
            .iter()
            .filter(|(id, m)| {
                st.apps.get(*id).is_some_and(|i| i.level == level)
                    && main_changed(st, id, m, &level)
                    && !new_apps.contains_key(*id)
            })
            .map(|(id, _)| id.clone())
            .collect();
        if !blockers.is_empty() {
            new_deps = false;
            notes.push(format!(
                "the shared dependencies change together with {}, which is not updated this round",
                blockers.join(", ")
            ));
        }
    }
    if deps_built && !new_deps {
        build::discard(&p.ext_dir, &format!("{DEPS_EXT}.new"));
        // the apps whose package changed need the new dependencies
        for id in new_apps.keys().cloned().collect::<Vec<_>>() {
            let m = &mains[&id];
            if main_changed(st, &id, m, &level) {
                new_apps.remove(&id);
                build::discard(&p.ext_dir, &format!("{}.new", app_ext(&id)));
                let r = held_back(
                    st,
                    &id,
                    m,
                    &labels,
                    "the update waits for the shared dependencies to change".into(),
                );
                out.insert(id, r);
            }
        }
    }

    // 8. swap in, all as one change (one refresh; a failure puts every one of them back)
    let mut pairs: Vec<(String, String)> = vec![];
    if new_deps {
        pairs.push((DEPS_EXT.into(), format!("{DEPS_EXT}.new")));
    }
    for id in new_apps.keys() {
        pairs.push((app_ext(id), format!("{}.new", app_ext(id))));
    }
    if !pairs.is_empty() {
        let dir = p.ext_dir.clone();
        let swapped = blocking(env, move |r| {
            let refs: Vec<(&str, &str)> = pairs
                .iter()
                .map(|(a, b)| (a.as_str(), b.as_str()))
                .collect();
            sysext::swap_in_all(r, &safefs::open_abs_dir(&dir, false)?, &refs)
        })
        .await;
        match swapped {
            Ok(()) => {
                if new_deps {
                    st.deps = Some(DepsInstalled {
                        files: deps.as_ref().cloned().unwrap_or_default(),
                        level: level.clone(),
                    });
                }
                for (id, (b, key)) in std::mem::take(&mut new_apps) {
                    keep_installed(&p.work, &id, &mains[&id]);
                    let r = out.get_mut(&id).expect("built apps have a result");
                    r.state = AppState::Ready;
                    st.apps.insert(
                        id.clone(),
                        Installed {
                            key,
                            deb_sha256: mains[&id].sha256.clone(),
                            package: r.package.clone().unwrap_or_default(),
                            version: r.version.clone().unwrap_or_default(),
                            exec: b.exec,
                            kiosk: wanted.apps.get(&id).is_some_and(|a| a.kiosk),
                            level: level.clone(),
                            pruned: b.pruned,
                            setid: b.setid,
                        },
                    );
                }
            }
            Err(e) => {
                if new_deps {
                    notes.push(format!("merging the shared dependencies failed: {e:#}"));
                }
                for id in std::mem::take(&mut new_apps).into_keys() {
                    let f = failed(&id, st, format!("merging failed: {e:#}"));
                    let r = out.get_mut(&id).expect("built apps have a result");
                    r.state = AppState::Failed;
                    r.detail = f.detail;
                }
            }
        }
    }

    // 9. uninstall what the settings no longer have
    let mut gone: BTreeSet<String> = st.apps.keys().cloned().collect();
    for n in safefs::list_at(&ext)? {
        if let Some(id) = n.strip_prefix("app-") {
            if n != DEPS_EXT && !id.contains('.') {
                gone.insert(id.to_string());
            }
        }
    }
    gone.retain(|id| !wanted.apps.contains_key(id));
    for id in gone {
        let name = app_ext(&id);
        if has(&ext, &name) {
            let kiosk = kiosk_of(wanted, st, &id);
            let (b, note) = busy(
                env,
                st,
                &name,
                &[p.ext_dir.join(&name)],
                &kiosk,
                &mut sessions,
            )
            .await;
            if b {
                let mut r = AppResult::new(&id, AppState::WaitingForClose);
                r.detail = Some("removed from the settings; waiting for the app to close".into());
                out.insert(id, r);
                continue;
            }
            notes.extend(note.map(|n| format!("{id}: {n}")));
        }
        let dir = p.ext_dir.clone();
        let n2 = name.clone();
        if let Err(e) = blocking(env, move |r| {
            sysext::remove_ext(r, &safefs::open_abs_dir(&dir, false)?, &n2)
        })
        .await
        {
            let mut r = AppResult::new(&id, AppState::Failed);
            r.detail = Some(format!("removing failed: {e:#}"));
            out.insert(id, r);
            continue;
        }
        st.apps.remove(&id);
        st.build_failed.remove(&id);
        st.argv_since.remove(&name);
        if let Ok(apps) = safefs::open_dir_at(work, Path::new("apps"), true) {
            if let Err(e) = safefs::remove_tree_at(&apps, &id) {
                log::warn!("deb-apps: removing the work directory of {id}: {e:#}");
            }
        }
        log::info!("deb-apps: uninstalled {id}");
    }
    // the shared dependencies: gone when no app is installed, or when every installed app was resolved to need none
    let no_deps_needed =
        matches!(&deps, Ok(f) if f.is_empty()) && st.apps.keys().all(|id| mains.contains_key(id));
    if (st.apps.is_empty() || no_deps_needed) && has(&ext, DEPS_EXT) {
        let trees = installed_trees(&ext);
        let all_kiosk: Vec<String> = st
            .apps
            .keys()
            .flat_map(|id| kiosk_of(wanted, st, id))
            .collect();
        let (b, note) = busy(env, st, DEPS_EXT, &trees, &all_kiosk, &mut sessions).await;
        notes.extend(note);
        if !b {
            let dir = p.ext_dir.clone();
            match blocking(env, move |r| {
                sysext::remove_ext(r, &safefs::open_abs_dir(&dir, false)?, DEPS_EXT)
            })
            .await
            {
                Ok(()) => st.deps = None,
                Err(e) => log::warn!("deb-apps: removing the shared dependencies: {e:#}"),
            }
        }
    }
    st.build_failed
        .retain(|id, _| wanted.apps.contains_key(id) || st.apps.contains_key(id));
    if wanted.apps.is_empty() && st.apps.is_empty() {
        prune_archives(&p.work.join("apt/archives"), &[]);
        st.resolved = None;
    }
    // work directories of apps neither wanted nor installed
    if let Some(apps) = safefs::open_child_dir(work, "apps")? {
        for n in safefs::list_at(&apps)? {
            if !wanted.apps.contains_key(&n) && !st.apps.contains_key(&n) {
                let _ = safefs::remove_tree_at(&apps, &n);
            }
        }
    }
    Ok(out)
}

/// Is the main package of `id` not the one its installed tree was built from (or is it not installed for this image)?
fn main_changed(st: &RoundState, id: &str, m: &Main, level: &str) -> bool {
    st.apps
        .get(id)
        .is_none_or(|i| i.deb_sha256 != m.sha256 || i.level != level)
}

/// The result of an app whose new tree is not merged this round: the installed one stays ready, else it is installing.
fn held_back(st: &RoundState, id: &str, m: &Main, labels: &[String], why: String) -> AppResult {
    match st.apps.get(id) {
        Some(i) => ready_from(id, i, labels, Some(why)),
        None => AppResult {
            package: Some(m.package.clone()),
            version: Some(m.version.clone()),
            deps: labels.to_vec(),
            detail: Some(why),
            ..AppResult::new(id, AppState::Installing)
        },
    }
}

/// Is `key`'s extension (`trees`) in use ([`in_use_why`])? A session or a readable program link holds it back; evidence
/// from a process's arguments alone holds it back for at most a day from the first time it did (`argv_since`), then the
/// round goes ahead and says so (the returned note).
async fn busy(
    env: &RoundEnv,
    st: &mut RoundState,
    key: &str,
    trees: &[PathBuf],
    kiosk: &[String],
    sessions: &mut Option<String>,
) -> (bool, Option<String>) {
    let s = if kiosk.is_empty() {
        String::new()
    } else {
        sessions_json(env, sessions).await
    };
    match in_use_why(&env.paths.proc_root, trees, kiosk, &s) {
        None => {
            st.argv_since.remove(key);
            (false, None)
        }
        Some(Evidence::Argv(prog)) => {
            let since = *st.argv_since.entry(key.to_string()).or_insert(env.now);
            if env.now - since >= DAY || since > env.now + DAY {
                st.argv_since.remove(key);
                log::warn!("deb-apps: {key}: only a process's arguments name {prog}, for over a day; going ahead");
                (
                    false,
                    Some(format!(
                        "went ahead although a process named {prog} seemed to run the app for over 24 hours (its program could not be read)"
                    )),
                )
            } else {
                st.argv_held.insert(key.to_string());
                (true, None)
            }
        }
        Some(_) => (true, None),
    }
}
