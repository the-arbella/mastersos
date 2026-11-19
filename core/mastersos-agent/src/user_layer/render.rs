//! The `user-layer` step (design `docs/specs/2026-11-19-user-layer-design.md` §4.2): with a format 3 bundle, every
//! user config reachable on this Device, plus the fully blocked [`neutral`] one, is pre-rendered into its own
//! directory, so that a login only switches files (renames and a symlink, Task 4) and never renders.
//!
//! For one config directory `d` ([`config_dir_name`] of the id, or [`NEUTRAL_DIR`]):
//!
//! - `<var_dir>/user-layer/<d>/chrome.json`: the managed Chrome policy ([`chrome_policy::render_policy`]), plus a
//!   copy `/etc/opt/chrome/policies/.mastersos-staging/<d>.json` (root 0700, on the file system of `managed/` so the
//!   switch is a rename; never inside `managed/`, which Chrome reads in full);
//! - `/etc/dconf/db/mastersos-<d>.d/50-mastersos` and `locks/50-mastersos`, compiled into `/etc/dconf/db/mastersos-<d>`
//!   by the one `dconf update` of the round (this step runs it, after `desktop`);
//! - `/var/lib/mastersos-public/user-layer/<d>/`: `xdg/` (web app launchers and icons, `Hidden=true` overrides, D-Bus
//!   overrides), `login-scripts/` (with its index) and `session-mode` (`full` iff `user_apps` is lifted).
//!
//! And `<var_dir>/user-layer/index.json` (root 0600, [`Index`]): the rules of this Device's Group and where each
//! config was rendered. Directories of configs no longer reachable are removed, except the one the signed-in
//! session uses ([`read_active`]). Under format 3 the legacy `/var/lib/mastersos-public/session-mode` stays
//! `learning`: an older image after a rollback reads only that file.
//!
//! With a format 1/2 bundle the step does nothing, unless an earlier format 3 bundle left its state: then it
//! removes everything it created, and the format 1/2 steps own the session as before.

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::OwnedFd;
use std::path::Path;

use anyhow::{Context, Result};
use mastersos_bundle::{
    reachable_user_configs, user_config, Capability, Caps, HomeMode, ItemResult, Manifest, Preset,
    UserConfig, UserRules,
};
use serde::{Deserialize, Serialize};

use super::{active_marker, config_dir_name, is_config_dir, NEUTRAL_DIR};
use crate::apply::{is_not_found, ApplyContext};
use crate::deb_apps;
use crate::deb_apps::status::PublicApp;
use crate::safefs;
use crate::system::desktop::{self, Downloads, SessionDconf};
use crate::system::{
    chrome_policy, exec_block, failed, flatpak, ok, public_dir, var_dir, Env, Step, SysPaths,
};

/// The report item of the step; each user config adds `user-layer:<id>`.
pub const ITEM: &str = "user-layer";
/// The step's directory under `var_dir` (root 0700) and under `public_dir` (0755).
pub const STATE_SUB: &str = "user-layer";
/// The rules and the rendered configs, in the `var_dir` part of [`STATE_SUB`] (0600).
pub const INDEX_FILE: &str = "index.json";
/// A config's managed Chrome policy, in its `var_dir` directory.
pub const CHROME_FILE: &str = "chrome.json";
/// The managed policy directory's parent and the staging directory in it (relative to the system root).
pub const POLICIES_DIR: &str = "etc/opt/chrome/policies";
pub const STAGING_SUB: &str = ".mastersos-staging";
/// The dconf databases (relative to the system root).
pub const DCONF_DB_DIR: &str = "etc/dconf/db";
/// The compiled dconf database of the current session (switched in by Task 4; never has a `.d` directory).
pub const SESSION_DB: &str = "mastersos-session";
/// The dconf profile of user sessions under the user layer (relative to the system root): it takes precedence over the
/// image's `/usr/share/dconf/profile/user` (`user-db:user`, `system-db:mastersos`), which format 1/2 Devices keep using.
/// Written by the switch once [`SESSION_DB`] exists (a profile naming a missing database makes every dconf client warn),
/// removed with the rest of this layer's state under format 1/2.
pub const PROFILE_DIR: &str = "etc/dconf/profile";
pub const PROFILE_FILE: &str = "user";
pub const SESSION_PROFILE: &str =
    "user-db:user\nsystem-db:mastersos-session\nsystem-db:mastersos\n";
/// The symlink in `public_dir` to the current session's config directory (Task 4).
pub const SESSION_LINK: &str = "session";
/// The parts of a config's `public_dir` directory.
pub const XDG_SUB: &str = "xdg";
/// The public [`STATE_SUB`]: traversable, not listable; the config dirs in it decide who reads them.
pub const PUBLIC_STATE_MODE: u32 = 0o711;
pub const SCRIPTS_SUB: &str = "login-scripts";

/// The dconf database name of a config directory: `mastersos-<d>` (keyfiles in `mastersos-<d>.d`).
pub fn db_name(dir: &str) -> String {
    format!("mastersos-{dir}")
}

/// The compiled dconf database of the config directory `dir` (root 0600), which the switch copies to [`SESSION_DB`].
/// The one place that names it; `_var_dir` is where it will live once it moves out of `/etc/dconf/db`.
pub fn compiled_db(root: &Path, _var_dir: &Path, dir: &str) -> std::path::PathBuf {
    root.join(DCONF_DB_DIR).join(db_name(dir))
}

/// The configuration of a session without a user config: everything blocked, no apps, the baseline Chrome policy.
pub fn neutral() -> UserConfig {
    UserConfig {
        id: String::new(),
        name: String::new(),
        preset: Preset::Learning,
        caps: Caps::new(),
        home: HomeMode::Tidy,
        web: Vec::new(),
        flatpak: Vec::new(),
        deb: BTreeMap::new(),
        chrome_policy: toml::Table::new(),
        login_scripts: Vec::new(),
        legacy_browser: false,
    }
}

/// Where one config was rendered and what the switch needs to know about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rendered {
    /// The config directory ([`config_dir_name`] or [`NEUTRAL_DIR`]).
    pub dir: String,
    pub caps: Caps,
    pub home: HomeMode,
}

/// `<var_dir>/user-layer/index.json`: everything the login needs besides the facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Index {
    /// This Device's Group.
    pub group: String,
    pub rules: UserRules,
    /// By user config id.
    pub configs: BTreeMap<String, Rendered>,
    pub neutral: Rendered,
}

/// The index under `var_dir`; `None` when missing or unreadable.
pub fn read_index(var_dir: &Path) -> Option<Index> {
    let dir = safefs::open_abs_dir(&var_dir.join(STATE_SUB), false).ok()?;
    let bytes = safefs::read_at(&dir, INDEX_FILE).ok()??;
    serde_json::from_slice(&bytes).ok()
}

pub fn step() -> Step {
    Step {
        name: "user-layer",
        fast: true,
        run,
        without_bundle: None,
    }
}

fn run(ctx: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
    match ctx.user_layer() {
        Some(m) => render_all(ctx, m, env),
        None => match remove_state(env.paths) {
            Ok(false) => vec![],
            Ok(true) => vec![ItemResult {
                detail: Some("removed the user configs of an earlier settings format 3".into()),
                ..ok(ITEM)
            }],
            Err(e) => vec![failed(
                ITEM,
                format!("removing the user configs of an earlier settings format 3: {e:#}"),
            )],
        },
    }
}

/// What rendering one config gave: errors and remarks for its report item, and whether its dconf keyfiles changed.
#[derive(Default)]
struct Outcome {
    errs: Vec<String>,
    notes: Vec<String>,
    dconf_changed: bool,
}

fn render_all(ctx: &ApplyContext, m: &Manifest, env: &mut Env) -> Vec<ItemResult> {
    let (paths, runner) = (env.paths, env.runner);
    let sys = &mut *env.sys;
    let mut out = Vec::new();
    let mut errs = Vec::new();
    // Tightening first (R17): the legacy file is the only one an older image reads after a rollback.
    if let Err(e) = exec_block::write_session_mode(paths, true) {
        errs.push(format!("session mode: {e:#}"));
    }
    let group = ctx.group.id.as_str();
    let mut configs = Vec::new();
    for id in reachable_user_configs(m, group) {
        match user_config(m, &id) {
            Some(c) => configs.push(c),
            None => out.push(failed(
                &item_of(&id),
                "the settings have no user config with this id".into(),
            )),
        }
    }
    let kiosk = desktop::kiosk_dock(paths);
    let public =
        deb_apps::status::read_public(&paths.public_dir.join(deb_apps::status::PUBLIC_NAME));
    let neutral = neutral();
    // The signed-in session's config dir keeps its mode (the switch opened it) and is never removed. A marker that
    // exists but cannot be read keeps every dir this round.
    let active = active_marker(&paths.root).map(|a| a.map(|a| a.dir).filter(|d| is_config_dir(d)));
    let active_dir = active.as_ref().ok().cloned().flatten();
    let mut index = BTreeMap::new();
    let mut dconf_changed = false;
    {
        let lists: Vec<_> = configs.iter().map(|c| &c.web).collect();
        let mut dl = Downloads::new(sys, desktop::icon_key(&lists));
        for c in &configs {
            let dir = config_dir_name(&c.id);
            let r = render_one(
                ctx,
                paths,
                c,
                &dir,
                active_dir.as_deref(),
                &kiosk,
                &public,
                &mut dl,
            );
            dconf_changed |= r.dconf_changed;
            out.push(item(&item_of(&c.id), r));
            index.insert(
                c.id.clone(),
                Rendered {
                    dir,
                    caps: c.caps.clone(),
                    home: c.home,
                },
            );
        }
        let r = render_one(
            ctx,
            paths,
            &neutral,
            NEUTRAL_DIR,
            None,
            &kiosk,
            &public,
            &mut dl,
        );
        dconf_changed |= r.dconf_changed;
        errs.extend(r.errs.into_iter().map(|e| format!("neutral: {e}")));
    }
    let mut keep: BTreeSet<String> = index.values().map(|r| r.dir.clone()).collect();
    keep.insert(NEUTRAL_DIR.into());
    match &active {
        Ok(a) => {
            keep.extend(a.iter().cloned());
            if let Err(e) = remove_unreachable(paths, &keep) {
                errs.push(format!("removing user configs no longer used: {e:#}"));
            }
        }
        Err(e) => errs.push(format!(
            "the signed-in session's marker cannot be read ({e:#}); kept every user config this round"
        )),
    }
    sys.dconf_update_pending |= dconf_changed;
    if let Err(e) = desktop::dconf_update(runner, sys) {
        errs.push(format!("dconf: {e:#}"));
    }
    // `dconf update` writes the compiled databases world-readable; only the switch may publish one.
    if let Err(e) = close_databases(paths, &keep) {
        errs.push(format!("dconf: {e:#}"));
    }
    // The index last: it names only directories rendered above.
    let written = match UserRules::from_manifest(m, group) {
        Some(rules) => write_index(
            paths,
            &Index {
                group: group.to_string(),
                rules,
                configs: index,
                neutral: Rendered {
                    dir: NEUTRAL_DIR.into(),
                    caps: neutral.caps.clone(),
                    home: neutral.home,
                },
            },
        ),
        None => {
            errs.push("the settings have no fallback user config".into());
            remove_index(paths)
        }
    };
    if let Err(e) = written {
        errs.push(format!("index: {e:#}"));
    }
    out.push(if errs.is_empty() {
        ok(ITEM)
    } else {
        failed(ITEM, errs.join("; "))
    });
    out
}

fn item_of(id: &str) -> String {
    format!("{ITEM}:{id}")
}

fn item(name: &str, r: Outcome) -> ItemResult {
    if r.errs.is_empty() {
        ItemResult {
            detail: (!r.notes.is_empty()).then(|| r.notes.join("; ")),
            ..ok(name)
        }
    } else {
        let mut all = r.errs;
        all.extend(r.notes);
        failed(name, all.join("; "))
    }
}

/// Opens (creating) `rel` under `dir` and forces `mode`.
fn sub(dir: &OwnedFd, rel: &str, mode: u32) -> Result<OwnedFd> {
    let d = safefs::open_dir_at(dir, Path::new(rel), true)?;
    safefs::set_mode(&d, mode)?;
    Ok(d)
}

fn state_dir(paths: &SysPaths) -> Result<OwnedFd> {
    sub(&var_dir(paths)?, STATE_SUB, 0o700)
}

fn staging_dir(paths: &SysPaths) -> Result<OwnedFd> {
    let policies = safefs::open_dir(&paths.root, Path::new(POLICIES_DIR), true)?;
    sub(&policies, STAGING_SUB, 0o700)
}

/// Renders `c` into the config directory `dir`. Each part that fails is reported and the others still run; a
/// Chrome policy that cannot be rendered leaves no policy file, so that the switch to this config fails (closed).
#[allow(clippy::too_many_arguments)]
fn render_one(
    ctx: &ApplyContext,
    paths: &SysPaths,
    c: &UserConfig,
    dir: &str,
    active_dir: Option<&str>,
    kiosk: &[String],
    public: &BTreeMap<String, PublicApp>,
    dl: &mut Downloads,
) -> Outcome {
    let mut r = Outcome::default();
    if let Err(e) = render_chrome(paths, c, dir) {
        r.errs.push(format!("Chrome policy: {e:#}"));
    }
    let lifted = |cap: Capability| c.caps.contains(&cap);
    let pdir = match public_dir(paths)
        .and_then(|p| sub(&p, STATE_SUB, PUBLIC_STATE_MODE))
        .and_then(|s| config_dir(&s, dir, active_dir))
    {
        Ok(d) => d,
        Err(e) => {
            r.errs.push(format!("session files: {e:#}"));
            return r;
        }
    };
    let xdg_abs = paths.public_dir.join(STATE_SUB).join(dir).join(XDG_SUB);
    let (webapps, flatpaks, debs) = match sub(&pdir, XDG_SUB, 0o755) {
        Ok(xdg) => {
            let webapps = match desktop::write_webapps(ctx, &c.web, &xdg, &xdg_abs, dl) {
                Ok((ids, items)) => {
                    for i in items {
                        match (i.ok, i.detail) {
                            (false, d) => {
                                r.errs
                                    .push(format!("{}: {}", i.item, d.unwrap_or_default()))
                            }
                            (true, Some(d)) => r.notes.push(format!("{}: {d}", i.item)),
                            (true, None) => {}
                        }
                    }
                    ids
                }
                Err(e) => {
                    r.errs.push(format!("web apps: {e:#}"));
                    Vec::new()
                }
            };
            let flatpaks = flatpak::dock_apps(paths, &c.flatpak);
            let debs = desktop::deb_dock_from(&c.deb, public);
            if let Err(e) = write_overrides(paths, &xdg, c, &webapps, &flatpaks, &debs) {
                r.errs.push(format!("overrides: {e:#}"));
            }
            (webapps, flatpaks, debs)
        }
        Err(e) => {
            r.errs.push(format!("xdg directory: {e:#}"));
            (Vec::new(), Vec::new(), Vec::new())
        }
    };
    let mode: &[u8] = if lifted(Capability::UserApps) {
        b"full\n"
    } else {
        b"learning\n"
    };
    if let Err(e) = safefs::write_at(&pdir, exec_block::SESSION_MODE_FILE, mode, 0o644) {
        r.errs.push(format!("session mode: {e:#}"));
    }
    let scripts: Vec<_> = c.login_scripts.iter().collect();
    for i in
        crate::login_queue::export_into(&scripts, ctx.bundle_dir, sub(&pdir, SCRIPTS_SUB, 0o755))
    {
        r.errs.push(format!(
            "login script {}: {}",
            i.item,
            i.detail.unwrap_or_default()
        ));
    }
    let locks = desktop::session_locks(&c.caps);
    let session = SessionDconf {
        locks: &locks,
        dock_files: lifted(Capability::FileManager),
        dock_apps: true,
    };
    let (keyfile, lockfile) =
        desktop::render_session_dconf(&session, &webapps, kiosk, &debs, &flatpaks);
    let keydir = format!("{DCONF_DB_DIR}/{}.d", db_name(dir));
    let written = desktop::write_dconf(&paths.root, &keydir, &keyfile, &lockfile).and_then(|c| {
        let d = safefs::open_dir(&paths.root, Path::new(&keydir), false)?;
        safefs::set_mode(&d, 0o700)?;
        Ok(c)
    });
    match written {
        Ok(changed) => r.dconf_changed = changed,
        Err(e) => r.errs.push(format!("dconf: {e:#}")),
    }
    r
}

/// The public config dir `dir` under the public [`STATE_SUB`] `parent`, created when missing. Its mode: 0755 for
/// [`NEUTRAL_DIR`] (nothing in it is private; the greeter and boot state use it); 0700 for a user config, so that a
/// signed-in person cannot read the other configs' scripts and settings, except that the signed-in session's own
/// dir (`active_dir`) keeps 0755 when the switch has opened it. A re-render never opens a dir.
fn config_dir(parent: &OwnedFd, dir: &str, active_dir: Option<&str>) -> Result<OwnedFd> {
    let d = safefs::open_dir_at(parent, Path::new(dir), true)?;
    let open = dir == NEUTRAL_DIR || (active_dir == Some(dir) && mode_of(&d)? == 0o755);
    let mode = if open { 0o755 } else { 0o700 };
    safefs::set_mode(&d, mode)?;
    Ok(d)
}

fn mode_of(fd: &OwnedFd) -> Result<u32> {
    let st = rustix::fs::fstat(fd).map_err(std::io::Error::from)?;
    Ok(st.st_mode & 0o7777)
}

/// Makes each existing compiled database `mastersos-<d>` of the dirs `dirs` 0600.
fn close_databases(paths: &SysPaths, dirs: &BTreeSet<String>) -> Result<()> {
    let Some(db) = open_existing(&paths.root, DCONF_DB_DIR)? else {
        return Ok(());
    };
    for d in dirs {
        if let Some(f) = safefs::open_file_at(&db, &db_name(d))? {
            rustix::fs::fchmod(&f, rustix::fs::Mode::from_raw_mode(0o600))
                .map_err(std::io::Error::from)
                .with_context(|| format!("making {} root-only", db_name(d)))?;
        }
    }
    Ok(())
}

/// The policy file of `c` and its staging copy; on a render error both are removed.
fn render_chrome(paths: &SysPaths, c: &UserConfig, dir: &str) -> Result<()> {
    let cdir = sub(&state_dir(paths)?, dir, 0o700)?;
    let staging = staging_dir(paths)?;
    let staged = format!("{dir}.json");
    match chrome_policy::render_policy(&c.chrome_policy) {
        Ok(text) => {
            safefs::write_at(&cdir, CHROME_FILE, text.as_bytes(), 0o644)
                .with_context(|| format!("write {CHROME_FILE}"))?;
            safefs::write_at(&staging, &staged, text.as_bytes(), 0o644)
                .with_context(|| format!("write the staging copy {staged}"))?;
            Ok(())
        }
        Err(e) => {
            safefs::remove_at(&cdir, CHROME_FILE)?;
            safefs::remove_at(&staging, &staged)?;
            Err(e)
        }
    }
}

/// The `Hidden=true` overrides (none when `all_apps` is lifted) and the D-Bus overrides of the file manager and the
/// settings (unless lifted) of `c`, in its xdg directory.
fn write_overrides(
    paths: &SysPaths,
    xdg: &OwnedFd,
    c: &UserConfig,
    webapps: &[String],
    flatpaks: &[String],
    debs: &[String],
) -> Result<()> {
    let lifted = |cap: Capability| c.caps.contains(&cap);
    let mut dbus = Vec::new();
    if !lifted(Capability::FileManager) {
        dbus.extend([desktop::NAUTILUS_SERVICE, desktop::FILE_MANAGER1_SERVICE]);
    }
    if !lifted(Capability::Settings) {
        dbus.push(desktop::SETTINGS_SERVICE);
    }
    desktop::write_dbus_overrides(xdg, &dbus)?;
    if lifted(Capability::AllApps) {
        return desktop::remove_hidden_in(xdg);
    }
    let mut keep = vec![desktop::CHROME_DESKTOP.to_string()];
    keep.extend(webapps.iter().cloned());
    keep.extend(debs.iter().cloned());
    if lifted(Capability::FileManager) {
        keep.push(desktop::NAUTILUS_DESKTOP.to_string());
    }
    desktop::write_overrides_in(&paths.root, xdg, &keep, flatpaks)
}

fn write_index(paths: &SysPaths, index: &Index) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(index)?;
    safefs::write_at(&state_dir(paths)?, INDEX_FILE, &bytes, 0o600)
        .with_context(|| format!("write {INDEX_FILE}"))?;
    Ok(())
}

fn remove_index(paths: &SysPaths) -> Result<()> {
    safefs::remove_at(&state_dir(paths)?, INDEX_FILE)
}

/// Removes the config directories not in `keep`, everywhere this step writes them. Only names of the exact shape
/// of a config directory ([`is_config_dir`]) are touched.
fn remove_unreachable(paths: &SysPaths, keep: &BTreeSet<String>) -> Result<()> {
    let gone = |name: &str| is_config_dir(name) && !keep.contains(name);
    let state = state_dir(paths)?;
    let public = public_dir(paths).and_then(|p| sub(&p, STATE_SUB, PUBLIC_STATE_MODE))?;
    for d in [&state, &public] {
        for name in safefs::list_at(d)? {
            if gone(&name) {
                safefs::remove_tree_at(d, &name)?;
            }
        }
    }
    if let Some(db) = open_existing(&paths.root, DCONF_DB_DIR)? {
        for name in safefs::list_at(&db)? {
            let Some(rest) = name.strip_prefix("mastersos-") else {
                continue;
            };
            if let Some(d) = rest.strip_suffix(".d") {
                if gone(d) {
                    safefs::remove_tree_at(&db, &name)?;
                }
            } else if gone(rest) {
                safefs::remove_at(&db, &name)?;
            }
        }
    }
    let staging = staging_dir(paths)?;
    for name in safefs::list_at(&staging)? {
        if name.strip_suffix(".json").is_some_and(gone) {
            safefs::remove_at(&staging, &name)?;
        }
    }
    Ok(())
}

/// `root/rel` when it exists.
fn open_existing(root: &Path, rel: &str) -> Result<Option<OwnedFd>> {
    match safefs::open_dir(root, Path::new(rel), false) {
        Ok(d) => Ok(Some(d)),
        Err(e) if is_not_found(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

/// With a format 1/2 bundle: removes everything an earlier format 3 bundle had this step (and the switch) create,
/// the state directory last so a failure is retried. `Ok(false)` when there is no such state.
fn remove_state(paths: &SysPaths) -> Result<bool> {
    let Some(var) = open_existing_abs(&paths.var_dir)? else {
        return Ok(false);
    };
    let Some(state) = safefs::open_child_dir(&var, STATE_SUB)? else {
        return Ok(false);
    };
    let mut dirs: BTreeSet<String> = safefs::list_at(&state)?
        .into_iter()
        .filter(|n| is_config_dir(n))
        .collect();
    if let Some(index) = read_index(&paths.var_dir) {
        dirs.extend(index.configs.into_values().map(|r| r.dir));
        dirs.insert(index.neutral.dir);
    }
    dirs.insert(NEUTRAL_DIR.into());
    // The profile first: it must never name a database that is gone.
    if let Some(profile) = open_existing(&paths.root, PROFILE_DIR)? {
        safefs::remove_at(&profile, PROFILE_FILE)?;
    }
    if let Some(db) = open_existing(&paths.root, DCONF_DB_DIR)? {
        for d in dirs.iter().filter(|d| is_config_dir(d)) {
            safefs::remove_tree_at(&db, &format!("{}.d", db_name(d)))?;
            safefs::remove_at(&db, &db_name(d))?;
        }
        safefs::remove_at(&db, SESSION_DB)?;
    }
    if let Some(policies) = open_existing(&paths.root, POLICIES_DIR)? {
        safefs::remove_tree_at(&policies, STAGING_SUB)?;
    }
    if let Some(public) = open_existing_abs(&paths.public_dir)? {
        if safefs::read_link_at(&public, SESSION_LINK).is_some() {
            rustix::fs::unlinkat(&public, SESSION_LINK, rustix::fs::AtFlags::empty())
                .map_err(std::io::Error::from)
                .with_context(|| format!("removing {SESSION_LINK}"))?;
        }
        safefs::remove_tree_at(&public, STATE_SUB)?;
    }
    drop(state);
    safefs::remove_tree_at(&var, STATE_SUB)?;
    Ok(true)
}

fn open_existing_abs(path: &Path) -> Result<Option<OwnedFd>> {
    match safefs::open_abs_dir(path, false) {
        Ok(d) => Ok(Some(d)),
        Err(e) if is_not_found(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests;
