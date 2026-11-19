//! The `user-layer` step (design `docs/specs/2026-11-19-user-layer-design.md` §4.2): with a format 3 bundle, every
//! user config reachable on this Device, plus the fully blocked [`neutral`] one, is pre-rendered into its own
//! directory, so that a login only switches files (renames and a symlink, Task 4) and never renders.
//!
//! For one config directory `d` ([`config_dir_name`] of the id, or [`NEUTRAL_DIR`]):
//!
//! - `<var_dir>/user-layer/<d>/chrome.json`: the managed Chrome policy ([`chrome_policy::render_policy`]), plus a
//!   copy `/etc/opt/chrome/policies/.mastersos-staging/<d>.json` (root 0700, on the file system of `managed/` so the
//!   switch is a rename; never inside `managed/`, which Chrome reads in full);
//! - `<var_dir>/user-layer/<d>/dconf.d/50-mastersos` and `locks/50-mastersos`, compiled by `dconf compile` into
//!   `<var_dir>/user-layer/<d>/dconf.db` (root only; never in `/etc/dconf/db`, where `dconf update` would compile
//!   them world-readable); the step also runs the round's one `dconf update` (the device database, after `desktop`);
//! - `/var/lib/mastersos-public/user-layer/<d>/`: `xdg/` (web app launchers and icons, `Hidden=true` overrides, D-Bus
//!   overrides), `login-scripts/` (with its index) and `session-mode` (`full` iff `user_apps` is lifted).
//!
//! And `<var_dir>/user-layer/index.json` (root 0600, [`Index`]): the rules of this Device's Group and where each
//! config was rendered. Under format 3 the legacy `/var/lib/mastersos-public/session-mode` stays
//! `learning`: an older image after a rollback reads only that file.
//!
//! Last, the step follows the session (design §4.2: the reapply, and the boot apply, render from the active session's
//! user config or neutral, never from the device config alone), under [`switch::lock_active`]:
//!
//! - nobody signed in: neutral is switched in and everything blocked;
//! - a person signed in whose user config is still reachable: its re-rendered files are switched in at once, and a
//!   capability it no longer has is blocked at once; one it gained is lifted only by the agent's
//!   [`session::after_login`] (tighten now, loosen later, §4.4);
//! - a person signed in whose user config was removed: the fallback is switched in with nothing lifted, held until
//!   their next login ([`super::Active::held`]), and [`ACTIVE_ITEM`] fails with [`REMOVED_CONFIG`];
//! - a session being closed is left to the agent's revert; a marker that cannot be read changes nothing.
//!
//! The render creates a user config dir root-only (0700) and never changes the mode of an existing one (a login may
//! open its dir while the step runs). This last part, under the same lock, also tidies the user config dirs no session
//! uses (the marker, read under the lock, and the session link name the ones a session uses): those of configs no
//! longer reachable are removed, the others closed. A busy lock or an unreadable marker leaves them all to the next
//! round.
//!
//! With a format 1/2 bundle the step does nothing, unless an earlier format 3 bundle left its state: then, under the
//! marker's lock, it removes everything it created, and the format 1/2 steps own the session as before. While a session
//! marker exists it removes nothing and marks the cleanup deferred: that session's revert does it.

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::OwnedFd;
use std::path::Path;

use anyhow::{bail, Context, Result};
use mastersos_bundle::{
    reachable_user_configs, user_config, Capability, Caps, HomeMode, ItemResult, Manifest, Preset,
    UserConfig, UserRules,
};
use serde::{Deserialize, Serialize};

use super::switch::{self, switch_to};
use super::{
    active_marker, config_dir_name, is_config_dir, session, Active, ActiveState, NEUTRAL_DIR,
};
use crate::apply::{is_not_found, ApplyContext};
use crate::deb_apps;
use crate::deb_apps::status::PublicApp;
use crate::runner::{run_ok, Cmd, Runner};
use crate::safefs;
use crate::system::desktop::{self, Downloads, SessionDconf};
use crate::system::{
    chrome_policy, exec_block, failed, flatpak, ok, public_dir, var_dir, Env, Step, SysPaths,
};

/// The report item of the step; each user config adds `user-layer:config:<id>` (the `config:` keeps them apart from the
/// agent's session items such as `user-layer:session`).
pub const ITEM: &str = "user-layer";
/// The report item of the signed-in session at the end of the step (only when something is wrong or worth saying).
pub const ACTIVE_ITEM: &str = "user-layer:active";
/// Why [`ACTIVE_ITEM`] fails when the signed-in person's user config is no longer in the settings.
pub const REMOVED_CONFIG: &str =
    "the signed-in person's user config was removed; they get it at their next login";
/// The step's directory under `var_dir` (root 0700) and under `public_dir` (0755).
pub const STATE_SUB: &str = "user-layer";
/// In the `var_dir` part of [`STATE_SUB`] while the format 1/2 cleanup waits for a session to end (a marker exists): the
/// agent's revert of that session then removes this layer's files instead of switching to neutral. Removed with the
/// rest of the state, and by any format 3 render.
pub const CLEANUP_DEFERRED_FILE: &str = "cleanup-deferred";
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

/// The dconf database name of a config directory in the first layout: `/etc/dconf/db/mastersos-<d>` (keyfiles in
/// `mastersos-<d>.d`). Nothing is written there any more (`dconf update` compiles every `.d` there world-readable);
/// leftovers are removed.
pub fn db_name(dir: &str) -> String {
    format!("mastersos-{dir}")
}

/// A config's dconf keyfile directory (with `locks/`) and its compiled database, in its `var_dir` directory (root
/// 0700). `dconf compile` writes the database there, where no one else can read it and `dconf update` never looks.
pub const DCONF_KEYFILE_SUB: &str = "dconf.d";
pub const DCONF_DB_FILE: &str = "dconf.db";
/// What `dconf compile` writes before it is renamed over [`DCONF_DB_FILE`].
pub const DCONF_DB_TMP: &str = "dconf.db.tmp";

/// The compiled dconf database of the config directory `dir` (root only), which the switch copies to [`SESSION_DB`].
/// The one place that names it.
pub fn compiled_db(_root: &Path, var_dir: &Path, dir: &str) -> std::path::PathBuf {
    var_dir.join(STATE_SUB).join(dir).join(DCONF_DB_FILE)
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
        None => match cleanup(env.paths) {
            Ok(Cleanup::Nothing) => vec![],
            Ok(Cleanup::Removed) => vec![ItemResult {
                detail: Some("removed the user configs of an earlier settings format 3".into()),
                ..ok(ITEM)
            }],
            Ok(Cleanup::Deferred) => vec![ItemResult {
                detail: Some(
                    "a session is signed in: the user configs of an earlier settings format 3 are removed when it ends"
                        .into(),
                ),
                ..ok(ITEM)
            }],
            Ok(Cleanup::Busy) => vec![failed(
                ITEM,
                "the session is changing: the user configs of an earlier settings format 3 are removed at the next apply"
                    .into(),
            )],
            Err(e) => vec![failed(
                ITEM,
                format!("removing the user configs of an earlier settings format 3: {e:#}"),
            )],
        },
    }
}

/// What rendering one config gave: errors and remarks for its report item, and whether its dconf keyfiles (and
/// locks) were all written.
#[derive(Default)]
struct Outcome {
    errs: Vec<String>,
    notes: Vec<String>,
    keyfiles_written: bool,
}

fn render_all(ctx: &ApplyContext, m: &Manifest, env: &mut Env) -> Vec<ItemResult> {
    let (paths, runner) = (env.paths, env.runner);
    let sys = &mut *env.sys;
    let mut out = Vec::new();
    let mut errs = Vec::new();
    // Format 3 again: a format 1/2 cleanup that waited for a session is off
    if let Err(e) = state_dir(paths).and_then(|s| safefs::remove_at(&s, CLEANUP_DEFERRED_FILE)) {
        errs.push(format!("state: {e:#}"));
    }
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
    let mut index = BTreeMap::new();
    {
        let lists: Vec<_> = configs.iter().map(|c| &c.web).collect();
        let mut dl = Downloads::new(sys, desktop::icon_key(&lists));
        for c in &configs {
            let dir = config_dir_name(&c.id);
            let mut r = render_one(ctx, paths, c, &dir, &kiosk, &public, &mut dl);
            if let Err(e) = compile_db(paths, runner, &dir, r.keyfiles_written) {
                r.errs.push(format!("dconf: {e:#}"));
            }
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
        let mut r = render_one(ctx, paths, &neutral, NEUTRAL_DIR, &kiosk, &public, &mut dl);
        if let Err(e) = compile_db(paths, runner, NEUTRAL_DIR, r.keyfiles_written) {
            r.errs.push(format!("dconf: {e:#}"));
        }
        errs.extend(r.errs.into_iter().map(|e| format!("neutral: {e}")));
    }
    if let Err(e) = remove_old_dconf(paths) {
        errs.push(format!("removing the old dconf databases: {e:#}"));
    }
    // The device's `mastersos` database (the `desktop` step leaves its update to this step: one per round)
    if let Err(e) = desktop::dconf_update(runner, sys) {
        errs.push(format!("dconf: {e:#}"));
    }
    // The index last: it names only directories rendered above.
    let rules = UserRules::from_manifest(m, group);
    let fallback = rules.as_ref().map(|r| r.fallback.clone());
    let written = match rules {
        Some(rules) => write_index(
            paths,
            &Index {
                group: group.to_string(),
                rules,
                configs: index.clone(),
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
    // Last, under the marker's lock: the session follows, and the dirs no session uses are removed or closed
    let followed = follow_session(paths, runner, &index, fallback.as_deref());
    errs.extend(followed.tidy_errs);
    out.push(if errs.is_empty() {
        ok(ITEM)
    } else {
        failed(ITEM, errs.join("; "))
    });
    out.extend(followed.active);
    out
}

fn neutral_rendered() -> Rendered {
    let n = neutral();
    Rendered {
        dir: NEUTRAL_DIR.into(),
        caps: n.caps,
        home: n.home,
    }
}

/// What [`follow_session`] gives the step: the [`ACTIVE_ITEM`], if any, and what went wrong removing the config dirs no
/// longer reachable (reported in [`ITEM`]).
#[derive(Debug, Default)]
struct Followed {
    active: Option<ItemResult>,
    tidy_errs: Vec<String>,
}

impl Followed {
    fn active(item: Option<ItemResult>) -> Followed {
        Followed {
            active: item,
            tidy_errs: Vec::new(),
        }
    }
}

/// The end of the step: the session follows the configs just rendered (see the module documentation). `configs` are
/// this round's rendered user configs by id, `fallback` the rules' fallback (none without rules).
///
/// Also under the marker's lock, and only there: the user config dirs of no session are removed (no longer reachable)
/// or closed ([`tidy`]). The lock is the one `on_open` holds while it switches a person in from the index it read, so a
/// dir a login has just claimed is always named by the marker or the session link when this runs. A busy lock or a
/// marker that cannot be read removes and closes nothing this round.
fn follow_session(
    paths: &SysPaths,
    runner: &dyn Runner,
    configs: &BTreeMap<String, Rendered>,
    fallback: Option<&str>,
) -> Followed {
    let root = paths.root.as_path();
    let lock = match switch::lock_active(root, switch::LOCK_WAIT) {
        Ok(l) => l,
        Err(e) if switch::is_lock_busy(&e) => {
            return Followed::active(Some(busy(paths, configs, &e)))
        }
        Err(e) => return Followed::active(Some(failed(ACTIVE_ITEM, format!("{e:#}")))),
    };
    let a = match active_marker(root) {
        Ok(Some(a)) => a,
        Ok(None) => {
            let done = session::to_neutral(paths, runner);
            return Followed {
                tidy_errs: tidy(paths, configs, &[]),
                active: done
                    .err()
                    .map(|e| failed(ACTIVE_ITEM, format!("nobody is signed in: {e:#}"))),
            };
        }
        Err(e) => {
            return Followed {
                active: Some(failed(
                    ACTIVE_ITEM,
                    format!(
                    "the signed-in session's marker cannot be read ({e:#}); nothing was switched"
                ),
                )),
                tidy_errs: vec![
                "the signed-in session's marker cannot be read; kept every user config this round"
                    .into(),
            ],
            }
        }
    };
    if a.state == ActiveState::Closing {
        return Followed {
            tidy_errs: tidy(paths, configs, &[&a.dir]),
            active: None,
        };
    }
    let named = a.dir.clone();
    let Some(r) = configs.get(&a.user_config) else {
        let item = removed(paths, runner, a, configs, fallback);
        // `removed` rewrote the marker's dir; the dir it named before stays this round too (unreadable now: nothing is
        // removed or closed)
        let tidy_errs = match active_marker(root) {
            Ok(Some(now)) => tidy(paths, configs, &[&named, &now.dir]),
            _ => vec![
                "the signed-in session's marker cannot be read after the switch to the fallback; kept every user config this round"
                    .into(),
            ],
        };
        return Followed {
            active: Some(item),
            tidy_errs,
        };
    };
    let (mut errs, loosen) = keep(paths, runner, a, r);
    let tidy_errs = tidy(paths, configs, &[&named, &r.dir]);
    drop(lock);
    // A capability the config gained: lifted by the agent's after-login step, which takes the lock itself
    if loosen {
        match session::after_login(paths, runner) {
            Ok(()) => {}
            Err(e) if switch::is_lock_busy(&e) => {
                log::info!(
                    "user layer: lifting the session's new capabilities: {e:#}; left to the agent"
                );
            }
            Err(e) => errs.push(format!("{e:#}")),
        }
    }
    Followed {
        active: (!errs.is_empty()).then(|| failed(ACTIVE_ITEM, errs.join("; "))),
        tidy_errs,
    }
}

/// The user config dirs no session uses, called under the marker's lock (see [`follow_session`]). A dir is spared when it
/// is [`NEUTRAL_DIR`], in `live` (the dirs the marker names, read under the lock) or the [`SESSION_LINK`]'s target (a
/// switch that failed half way may leave the session there). Of the others, those of no config in `configs` are removed
/// everywhere the step writes them (the root-only state, the public dir, the staging copy), and those still reachable
/// are closed (0700) in the public dir: the render never changes an existing dir's mode, since a login may open one while
/// it runs. Only names of the exact shape of a config dir ([`is_config_dir`]) are touched. Each entry that fails is
/// logged and the next one is still done; removal failures are returned for the step's report, close failures only
/// logged (a dir left open is closed by the next round, and the session is never looser for it).
fn tidy(paths: &SysPaths, configs: &BTreeMap<String, Rendered>, live: &[&str]) -> Vec<String> {
    let reachable: BTreeSet<&str> = configs.values().map(|r| r.dir.as_str()).collect();
    let mut errs = Vec::new();
    let linked = open_existing_abs(&paths.public_dir)
        .ok()
        .flatten()
        .and_then(|p| safefs::read_link_at(&p, SESSION_LINK));
    let linked = linked
        .as_deref()
        .and_then(|l| l.strip_prefix(&format!("{STATE_SUB}/")));
    let spared = |name: &str| name == NEUTRAL_DIR || live.contains(&name) || Some(name) == linked;
    let gone = |name: &str| is_config_dir(name) && !spared(name) && !reachable.contains(name);
    let mut remove_failed = |what: &str, e: anyhow::Error| {
        let msg = format!("removing the user config {what} no longer used: {e:#}");
        log::warn!("user layer: {msg}");
        errs.push(msg);
    };
    match state_dir(paths) {
        Ok(state) => remove_each(&state, &gone, |n, e| remove_failed(n, e)),
        Err(e) => remove_failed("state", e),
    }
    match staging_dir(paths) {
        Ok(staging) => match safefs::list_at(&staging) {
            Ok(names) => {
                for name in names {
                    if name.strip_suffix(".json").is_some_and(gone) {
                        if let Err(e) = safefs::remove_at(&staging, &name) {
                            remove_failed(&name, e);
                        }
                    }
                }
            }
            Err(e) => remove_failed("staging copies", e),
        },
        Err(e) => remove_failed("staging copies", e),
    }
    let public = match open_existing_abs(&paths.public_dir)
        .and_then(|p| p.map(|p| safefs::open_child_dir(&p, STATE_SUB)).transpose())
    {
        Ok(p) => p.flatten(),
        Err(e) => {
            remove_failed("session files", e);
            None
        }
    };
    let Some(public) = public else {
        return errs;
    };
    remove_each(&public, &gone, |n, e| remove_failed(n, e));
    let names = match safefs::list_at(&public) {
        Ok(n) => n,
        Err(e) => {
            log::warn!("user layer: closing the config directories no session uses: {e:#}");
            return errs;
        }
    };
    for name in names {
        if !is_config_dir(&name) || spared(&name) {
            continue;
        }
        let closed = safefs::open_dir_at(&public, Path::new(&name), false).and_then(|d| {
            if mode_of(&d)? != 0o700 {
                safefs::set_mode(&d, 0o700)?;
            }
            Ok(())
        });
        if let Err(e) = closed {
            log::warn!("user layer: closing the config directory {name} no session uses: {e:#}");
        }
    }
    errs
}

/// Removes every entry of `dir` that is `gone`; each failure goes to `failed` and the next entry is still done.
fn remove_each(
    dir: &OwnedFd,
    gone: &dyn Fn(&str) -> bool,
    mut failed: impl FnMut(&str, anyhow::Error),
) {
    match safefs::list_at(dir) {
        Ok(names) => {
            for name in names.iter().filter(|n| gone(n)) {
                if let Err(e) = safefs::remove_tree_at(dir, name) {
                    failed(name, e);
                }
            }
        }
        Err(e) => failed("directory listing", e),
    }
}

/// The capabilities the marker `a` may keep under its config's rendering `r`: the config's, or only those it already had
/// when it is held.
fn allowed(a: &Active, r: &Rendered) -> Caps {
    if a.held {
        a.caps.intersection(&r.caps).copied().collect()
    } else {
        r.caps.clone()
    }
}

/// The capabilities lifted now; unreadable state counts as nothing lifted (the caller then blocks everything).
fn lifted_now(paths: &SysPaths) -> Caps {
    exec_block::read_lifted(paths)
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// The signed-in session `a` keeps its config `r`, under the marker's lock: what is lifted and no longer allowed is
/// blocked first (even when the switch then fails), then `r` is switched in and the marker updated. Returns the errors
/// and whether something allowed is not lifted yet; never that after an error (a failed step leaves the session
/// stricter, never looser, §4.4), and after an error the marker's capabilities only narrow.
fn keep(paths: &SysPaths, runner: &dyn Runner, mut a: Active, r: &Rendered) -> (Vec<String>, bool) {
    let mut errs = Vec::new();
    let caps = allowed(&a, r);
    let kept: Caps = lifted_now(paths).intersection(&caps).copied().collect();
    if let Err(e) = exec_block::apply_lifted(paths, runner, &kept) {
        errs.push(format!(
            "blocking the capabilities the user config no longer has: {e:#}"
        ));
    }
    if let Err(e) = switch_to(
        &paths.root,
        &paths.public_dir,
        &paths.var_dir,
        r,
        Some(a.uid),
    ) {
        errs.push(format!("switching to the re-rendered user config: {e:#}"));
    }
    let record: Caps = if errs.is_empty() {
        caps.clone()
    } else {
        a.caps.intersection(&caps).copied().collect()
    };
    if a.caps != record || a.dir != r.dir {
        a.caps = record;
        a.dir = r.dir.clone();
        // A marker that cannot be written keeps its old capabilities; `session::after_login` lifts only what the
        // rendered config still grants, so a capability removed here is never lifted from it.
        if let Err(e) = switch::write_active(&paths.root, &a) {
            errs.push(format!("updating the session marker: {e:#}"));
        }
    }
    let loosen = errs.is_empty() && !a.held && !caps.is_subset(&kept);
    (errs, loosen)
}

/// The signed-in session `a` lost its user config: everything blocked, the fallback switched in (neutral when there is
/// none or it cannot be switched in) and the marker held with nothing lifted until the next login.
fn removed(
    paths: &SysPaths,
    runner: &dyn Runner,
    mut a: Active,
    configs: &BTreeMap<String, Rendered>,
    fallback: Option<&str>,
) -> ItemResult {
    let mut errs = vec![REMOVED_CONFIG.to_string()];
    if let Err(e) = exec_block::apply_lifted(paths, runner, &Caps::new()) {
        errs.push(format!("blocking everything: {e:#}"));
    }
    let go = |r: &Rendered, uid: Option<u32>| {
        switch_to(&paths.root, &paths.public_dir, &paths.var_dir, r, uid)
    };
    let target = match fallback.and_then(|f| configs.get(f).map(|r| (f, r))) {
        None => {
            errs.push("the settings have no fallback user config".into());
            None
        }
        Some((f, r)) => match go(r, Some(a.uid)) {
            Ok(()) => Some((f.to_string(), r.dir.clone())),
            Err(e) => {
                errs.push(format!("switching to the fallback {f:?}: {e:#}"));
                None
            }
        },
    };
    let dir = match target {
        Some((id, dir)) => {
            a.user_config = id;
            dir
        }
        None => {
            if let Err(e) = go(&neutral_rendered(), None) {
                errs.push(format!("switching to neutral: {e:#}"));
            }
            NEUTRAL_DIR.to_string()
        }
    };
    a.dir = dir;
    a.caps = Caps::new();
    a.held = true;
    a.reason = Some(REMOVED_CONFIG.into());
    // Unwritten, the marker still names the removed config, which `session::after_login` never lifts anything for
    if let Err(e) = switch::write_active(&paths.root, &a) {
        errs.push(format!("updating the session marker: {e:#}"));
    }
    failed(ACTIVE_ITEM, errs.join("; "))
}

/// The marker's lock is held (a sign-in, sign-out or revert is changing the session): nothing is done and the next round
/// tries again. Read without the lock: when a capability the session may no longer have is still lifted, the item fails
/// so that the next apply comes soon.
fn busy(paths: &SysPaths, configs: &BTreeMap<String, Rendered>, e: &anyhow::Error) -> ItemResult {
    let allowed = match super::read_active(&paths.root) {
        Some(a) if a.state == ActiveState::Closing => None,
        Some(a) => Some(
            configs
                .get(&a.user_config)
                .map(|r| allowed(&a, r))
                .unwrap_or_default(),
        ),
        None => Some(Caps::new()),
    };
    match allowed {
        Some(caps) if !lifted_now(paths).is_subset(&caps) => failed(
            ACTIVE_ITEM,
            format!("{e:#}; a capability the session no longer has is still lifted; retried at the next apply"),
        ),
        _ => ItemResult {
            detail: Some(format!("{e:#}; retried next round")),
            ..ok(ACTIVE_ITEM)
        },
    }
}

fn item_of(id: &str) -> String {
    format!("{ITEM}:config:{id}")
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
        .and_then(|s| config_dir(&s, dir))
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
    let written = state_dir(paths)
        .and_then(|s| sub(&s, dir, 0o700))
        .and_then(|c| sub(&c, DCONF_KEYFILE_SUB, 0o700))
        .and_then(|k| {
            let shown = format!("{dir}/{DCONF_KEYFILE_SUB}");
            desktop::write_dconf_at(&k, &shown, &keyfile, &lockfile)
        });
    match written {
        Ok(_) => r.keyfiles_written = true,
        Err(e) => r.errs.push(format!("dconf: {e:#}")),
    }
    r
}

/// The public config dir `dir` under the public [`STATE_SUB`] `parent`. [`NEUTRAL_DIR`] is always 0755 (nothing in it
/// is private; the greeter and boot state use it). A user config dir is created 0700, so that a signed-in person cannot
/// read the other configs' scripts and settings; an existing one keeps its mode: only the switch opens one (for the
/// session it signs in, possibly after this step read the marker) and the end of the step closes the others
/// ([`close_others`], under the marker's lock).
fn config_dir(parent: &OwnedFd, dir: &str) -> Result<OwnedFd> {
    if dir != NEUTRAL_DIR {
        match safefs::open_dir_at(parent, Path::new(dir), false) {
            Ok(d) => return Ok(d),
            Err(e) if is_not_found(&e) => {}
            Err(e) => return Err(e),
        }
    }
    let d = safefs::open_dir_at(parent, Path::new(dir), true)?;
    let mode = if dir == NEUTRAL_DIR { 0o755 } else { 0o700 };
    safefs::set_mode(&d, mode)?;
    Ok(d)
}

fn mode_of(fd: &OwnedFd) -> Result<u32> {
    let st = rustix::fs::fstat(fd).map_err(std::io::Error::from)?;
    Ok(st.st_mode & 0o7777)
}

/// Compiles the keyfiles of the config dir `dir` into its [`DCONF_DB_FILE`] (`dconf compile`, which reads the
/// keyfile directory and its `locks/` exactly as `dconf update` does), every round: through a temporary file renamed
/// over it (0600), so the database always matches the keyfiles of this round. When the keyfiles could not all be
/// written (`keyfiles_written` false) or the compile fails, the database is removed: the switch to this config then
/// fails (closed) instead of using an older one, and the next round compiles again.
fn compile_db(
    paths: &SysPaths,
    runner: &dyn Runner,
    dir: &str,
    keyfiles_written: bool,
) -> Result<()> {
    let cdir = sub(&state_dir(paths)?, dir, 0o700)?;
    let compiled = if keyfiles_written {
        compile_into(paths, runner, &cdir, dir)
    } else {
        Ok(())
    };
    if !keyfiles_written || compiled.is_err() {
        let _ = safefs::remove_at(&cdir, DCONF_DB_TMP);
        safefs::remove_at(&cdir, DCONF_DB_FILE)?;
    }
    compiled
}

fn compile_into(paths: &SysPaths, runner: &dyn Runner, cdir: &OwnedFd, dir: &str) -> Result<()> {
    safefs::remove_at(cdir, DCONF_DB_TMP)?;
    let abs = paths.var_dir.join(STATE_SUB).join(dir);
    let (out, src) = (abs.join(DCONF_DB_TMP), abs.join(DCONF_KEYFILE_SUB));
    let (Some(out), Some(src)) = (out.to_str(), src.to_str()) else {
        bail!("the state directory's path is not UTF-8");
    };
    run_ok(runner, Cmd::new("dconf", &["compile", out, src]))?;
    let Some(f) = safefs::open_file_at(cdir, DCONF_DB_TMP)? else {
        bail!("dconf compile wrote no database");
    };
    rustix::fs::fchmod(&f, rustix::fs::Mode::from_raw_mode(0o600))
        .map_err(std::io::Error::from)
        .context("making the compiled database root-only")?;
    safefs::rename_at(cdir, DCONF_DB_TMP, DCONF_DB_FILE)
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

/// Removes what the first layout put in `/etc/dconf/db` for any config dir: `mastersos-<d>.d` and the compiled
/// `mastersos-<d>`, `<d>` of the exact shape of [`is_config_dir`] (never `mastersos`, `mastersos-session`, ...).
fn remove_old_dconf(paths: &SysPaths) -> Result<()> {
    let Some(db) = open_existing(&paths.root, DCONF_DB_DIR)? else {
        return Ok(());
    };
    for name in safefs::list_at(&db)? {
        let Some(rest) = name.strip_prefix("mastersos-") else {
            continue;
        };
        match rest.strip_suffix(".d") {
            Some(d) if is_config_dir(d) => safefs::remove_tree_at(&db, &name)?,
            None if is_config_dir(rest) => safefs::remove_at(&db, &name)?,
            _ => {}
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

/// What the format 1/2 [`cleanup`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cleanup {
    /// No state of an earlier format 3 bundle.
    Nothing,
    Removed,
    /// A session marker exists (or cannot be read): nothing removed, [`CLEANUP_DEFERRED_FILE`] written; the session's
    /// revert removes it all ([`super::session`]), or a later apply once the marker is gone.
    Deferred,
    /// The marker's lock is busy: nothing removed, [`CLEANUP_DEFERRED_FILE`] written; retried at the next apply.
    Busy,
}

/// With a format 1/2 bundle: [`remove_state`] under the marker's lock, but never while a session marker exists (open,
/// closing or unreadable), since a settings apply never removes the config dir of a person signed in or signing in.
/// Without a marker under the lock nobody is: `on_open` writes it before it releases the lock. A session link left on a
/// user config without a marker (a neutral switch that failed) does not hold the cleanup up, since nothing under format
/// 1/2 would ever re-point it.
fn cleanup(paths: &SysPaths) -> Result<Cleanup> {
    if !layer_state_present(paths)? {
        return Ok(Cleanup::Nothing);
    }
    let _lock = match switch::lock_active(&paths.root, switch::LOCK_WAIT) {
        Ok(l) => l,
        Err(e) if switch::is_lock_busy(&e) => {
            mark_deferred(paths)?;
            return Ok(Cleanup::Busy);
        }
        Err(e) => return Err(e),
    };
    if !matches!(active_marker(&paths.root), Ok(None)) {
        mark_deferred(paths)?;
        return Ok(Cleanup::Deferred);
    }
    Ok(if remove_state(paths)? {
        Cleanup::Removed
    } else {
        Cleanup::Nothing
    })
}

/// Whether the `var_dir` part of [`STATE_SUB`] exists.
fn layer_state_present(paths: &SysPaths) -> Result<bool> {
    let Some(var) = open_existing_abs(&paths.var_dir)? else {
        return Ok(false);
    };
    Ok(safefs::open_child_dir(&var, STATE_SUB)?.is_some())
}

fn mark_deferred(paths: &SysPaths) -> Result<()> {
    let Some(var) = open_existing_abs(&paths.var_dir)? else {
        return Ok(());
    };
    let Some(state) = safefs::open_child_dir(&var, STATE_SUB)? else {
        return Ok(());
    };
    safefs::write_at(&state, CLEANUP_DEFERRED_FILE, b"", 0o600)?;
    Ok(())
}

/// Whether a format 1/2 apply deferred its cleanup ([`CLEANUP_DEFERRED_FILE`]): the revert then calls
/// [`remove_state`] instead of switching to neutral.
pub(crate) fn cleanup_deferred(paths: &SysPaths) -> bool {
    std::fs::symlink_metadata(paths.var_dir.join(STATE_SUB).join(CLEANUP_DEFERRED_FILE)).is_ok()
}

/// With a format 1/2 bundle: removes everything an earlier format 3 bundle had this step (and the switch) create,
/// the state directory last so a failure is retried. `Ok(false)` when there is no such state. The caller holds the
/// marker's lock and has made sure no session uses the state ([`cleanup`], the revert).
pub(crate) fn remove_state(paths: &SysPaths) -> Result<bool> {
    let Some(var) = open_existing_abs(&paths.var_dir)? else {
        return Ok(false);
    };
    let Some(state) = safefs::open_child_dir(&var, STATE_SUB)? else {
        return Ok(false);
    };
    // The profile first: it must never name a database that is gone.
    if let Some(profile) = open_existing(&paths.root, PROFILE_DIR)? {
        safefs::remove_at(&profile, PROFILE_FILE)?;
    }
    remove_old_dconf(paths)?;
    if let Some(db) = open_existing(&paths.root, DCONF_DB_DIR)? {
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
pub(crate) mod tests;
