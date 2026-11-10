//! Building one round's extension trees (spec §4.3) into `<ext>.new`, outside the merge lock; [`super::round`] then
//! checks overlaps and swaps them in. Everything here is blocking (file system walks and `dpkg-deb -x`).
//!
//! **The root partition's `/opt`.** [`drop_image_files`] must not let a tree cover what the root partition has in
//! `/opt` (not in the signed image). But inside `mastersos-deb-apps.service` `/opt` is the *merged* view: the root
//! partition's `/opt` plus every merged extension (Chrome's `opt/google`, the apps' own `opt/<…>`). Passing it as is would
//! drop an already-merged app's whole tree when it is rebuilt. The unmerged `/opt` is not reachable from the unit (no mount
//! namespace of its own, `RestrictNamespaces=yes`, no `CAP_SYS_ADMIN`), so [`mirror_root_opt`] reconstructs it: an entry of the
//! merged `/opt` belongs to the root partition when no extension tree in `/var/lib/extensions` (`google-chrome`, `app-*`,
//! `app-deps`) has it. The result is a skeleton in `<work>/opt-root` (directories as directories, everything else as an
//! empty file — [`drop_image_files`] only compares types), rebuilt each round that builds something. A directory present in
//! an extension is mirrored too and walked into: its entries that no extension has are the root partition's. (A file both
//! the root partition and an extension have is shadowed by the extension and cannot be told apart; it counts as the
//! extension's, which is what a rebuild of that extension needs.)
//!
//! Trees are unpacked and sanitized in the private `<work>/stage` and only then moved to `/var/lib/extensions` ([`STAGE`]).

use std::collections::HashSet;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, ensure, Context, Result};
use rustix::fs::{AtFlags, FileType};

use super::assemble::{
    drop_image_files, pick_launcher, prune, strip_setid, write_desktop, write_release, Policy,
};
use crate::runner::{run_ok, Cmd, Runner};
use crate::safefs;

/// The skeleton of the root partition's `/opt`, in the work directory.
pub(crate) const OPT_MIRROR: &str = "opt-root";
/// The shared dependencies' extension.
pub(crate) const DEPS_EXT: &str = "app-deps";
const EXTRACT_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const MAX_DEPTH: usize = 64;

/// The extension of app `id`.
pub(crate) fn app_ext(id: &str) -> String {
    format!("app-{id}")
}

/// What to build for one app.
pub(crate) struct AppSpec {
    pub id: String,
    pub name: String,
    pub kiosk: bool,
    pub exec: Option<String>,
    pub deb: PathBuf,
    pub package: String,
    /// IT's icon: bytes and `png` or `svg`.
    pub icon: Option<(Vec<u8>, &'static str)>,
}

/// What a built app tree provides.
pub(crate) struct BuiltApp {
    pub exec: String,
    pub pruned: usize,
    pub setid: Vec<String>,
}

fn stat_type(dir: &OwnedFd, name: &str) -> Option<FileType> {
    rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)
        .ok()
        .map(|st| FileType::from_raw_mode(st.st_mode))
}

/// Rebuilds `<work>/opt-root` (see the module docs) from the merged `merged_opt` and the trees in `ext_dir`; returns its path.
pub(crate) fn mirror_root_opt(merged_opt: &Path, ext_dir: &Path, work: &Path) -> Result<PathBuf> {
    let w = safefs::open_abs_dir(work, false)?;
    safefs::remove_tree_at(&w, OPT_MIRROR)?;
    let out = safefs::open_dir_at(&w, Path::new(OPT_MIRROR), true)?;
    let path = work.join(OPT_MIRROR);
    let merged = match std::fs::symlink_metadata(merged_opt) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(path),
        _ => safefs::open_abs_dir(merged_opt, false)
            .with_context(|| format!("opening {}", merged_opt.display()))?,
    };
    let ext = safefs::open_abs_dir(ext_dir, true)?;
    let mut exts = vec![];
    for n in safefs::list_at(&ext)? {
        if n.ends_with(".new") || n.ends_with(".old") {
            continue;
        }
        if let Some(opt) = safefs::open_child_dir(&ext, &n)
            .ok()
            .flatten()
            .and_then(|d| safefs::open_child_dir(&d, "opt").ok().flatten())
        {
            exts.push(opt);
        }
    }
    mirror(&merged, &exts, &out, "opt", 0)?;
    Ok(path)
}

fn mirror(merged: &OwnedFd, exts: &[OwnedFd], out: &OwnedFd, at: &str, depth: usize) -> Result<()> {
    ensure!(depth < MAX_DEPTH, "/{at} is nested too deeply");
    for n in safefs::list_at(merged)? {
        let Some(t) = stat_type(merged, &n) else {
            continue;
        };
        let provided = exts.iter().any(|e| stat_type(e, &n).is_some());
        if t != FileType::Directory {
            if !provided {
                safefs::write_at(out, &n, b"", 0o600)?;
            }
            continue;
        }
        let sub_exts: Vec<OwnedFd> = exts
            .iter()
            .filter_map(|e| safefs::open_child_dir(e, &n).ok().flatten())
            .collect();
        let sub_out = safefs::open_dir_at(out, Path::new(&n), true)?;
        let sub =
            safefs::open_child_dir(merged, &n)?.ok_or_else(|| anyhow!("/{at}/{n} disappeared"))?;
        mirror(&sub, &sub_exts, &sub_out, &format!("{at}/{n}"), depth + 1)?;
    }
    Ok(())
}

/// Removes `<ext_dir>/<name>` if it is there (best effort, logged).
pub(crate) fn discard(ext_dir: &Path, name: &str) {
    let r = safefs::open_abs_dir(ext_dir, false).and_then(|d| safefs::remove_tree_at(&d, name));
    if let Err(e) = r {
        log::warn!("deb-apps: removing {name}: {e:#}");
    }
}

/// The private place trees are unpacked and sanitized in: `<work>/stage` (0700, inside the 0700 work directory). A vendor
/// package may carry setuid files; until [`strip_setid`] has run they must not be reachable by anyone but root, so the
/// tree reaches `/var/lib/extensions` (0755) only afterwards ([`publish`]).
pub(crate) const STAGE: &str = "stage";

/// An empty `<work>/stage/<new_name>` and `dpkg-deb -x` of every package into it; returns the stage and the tree.
fn unpack(
    runner: &dyn Runner,
    work: &Path,
    new_name: &str,
    debs: &[PathBuf],
) -> Result<(OwnedFd, OwnedFd)> {
    let w = safefs::open_abs_dir(work, false)?;
    let stage = safefs::open_dir_at(&w, Path::new(STAGE), true)?;
    safefs::set_mode(&stage, 0o700)?;
    safefs::remove_tree_at(&stage, new_name)?;
    let tree = safefs::open_dir_at(&stage, Path::new(new_name), true)?;
    safefs::set_mode(&tree, 0o700)?;
    drop(tree);
    let target = work.join(STAGE).join(new_name);
    for d in debs {
        run_ok(
            runner,
            Cmd::new(
                "dpkg-deb",
                &["-x", &d.to_string_lossy(), &target.to_string_lossy()],
            )
            .timeout(EXTRACT_TIMEOUT),
        )
        .with_context(|| format!("unpacking {}", d.display()))?;
    }
    let tree = safefs::open_child_dir(&stage, new_name)?
        .ok_or_else(|| anyhow!("{new_name} is missing"))?;
    Ok((stage, tree))
}

/// Moves the sanitized `<work>/stage/<new_name>` to `<ext_dir>/<new_name>` (one file system: both are on `/var`), its root
/// made 0755 first.
fn publish(stage: &OwnedFd, tree: &OwnedFd, ext_dir: &Path, new_name: &str) -> Result<()> {
    safefs::set_mode(tree, 0o755)?;
    let ext = safefs::open_abs_dir(ext_dir, true)?;
    safefs::remove_tree_at(&ext, new_name)?;
    rustix::fs::renameat(stage, new_name, &ext, new_name)
        .map_err(std::io::Error::from)
        .with_context(|| format!("moving {new_name} into {}", ext_dir.display()))
}

/// Runs `f` on a freshly unpacked tree, then publishes it; the stage is cleaned up either way.
fn staged(
    runner: &dyn Runner,
    work: &Path,
    ext_dir: &Path,
    new_name: &str,
    debs: &[PathBuf],
    f: impl FnOnce(&OwnedFd) -> Result<()>,
) -> Result<()> {
    let (stage, tree) = unpack(runner, work, new_name, debs)?;
    let r = f(&tree).and_then(|()| publish(&stage, &tree, ext_dir, new_name));
    if r.is_err() {
        let _ = safefs::remove_tree_at(&stage, new_name);
    }
    r
}

/// Builds `app-<id>.new`: unpack the main package, keep the allowlist, drop what covers the system, clear setuid bits,
/// find the launcher, add IT's icon, write our `.desktop` and the extension-release. The caller removes `.new` on error.
pub(crate) fn build_app(
    runner: &dyn Runner,
    ext_dir: &Path,
    work: &Path,
    owned: &HashSet<String>,
    opt_root: &Path,
    level: &str,
    s: &AppSpec,
) -> Result<BuiltApp> {
    let name = app_ext(&s.id);
    let mut out = None;
    staged(
        runner,
        work,
        ext_dir,
        &format!("{name}.new"),
        std::slice::from_ref(&s.deb),
        |root| {
            let mut pruned = prune(
                root,
                &Policy::VendorAllow {
                    package: s.package.clone(),
                },
            )?;
            pruned.extend(drop_image_files(root, owned, opt_root)?);
            if !pruned.is_empty() {
                log::info!("deb-apps: {}: removed {}", s.id, pruned.join(", "));
            }
            let setid = strip_setid(root)?;
            let launcher = pick_launcher(root, s.exec.as_deref())?;
            let icon = match &s.icon {
                None => None,
                Some((bytes, ext)) => {
                    let dir = if *ext == "svg" {
                        "usr/share/icons/hicolor/scalable/apps"
                    } else {
                        "usr/share/icons/hicolor/256x256/apps"
                    };
                    let file = format!("mastersos-app-{}.{ext}", s.id);
                    let d = safefs::open_dir_at(root, Path::new(dir), true)?;
                    safefs::write_at(&d, &file, bytes, 0o644)?;
                    Some(format!("/{dir}/{file}"))
                }
            };
            write_desktop(root, &s.id, &s.name, &launcher, icon.as_deref(), s.kiosk)?;
            write_release(root, &name, level)?;
            out = Some(BuiltApp {
                exec: launcher.exec,
                pruned: pruned.len(),
                setid,
            });
            Ok(())
        },
    )?;
    out.ok_or_else(|| anyhow!("building {name} gave no result"))
}

/// Builds `app-deps.new` from the dependency packages (the Ubuntu deny list). The caller removes `.new` on error.
pub(crate) fn build_deps(
    runner: &dyn Runner,
    ext_dir: &Path,
    work: &Path,
    owned: &HashSet<String>,
    opt_root: &Path,
    level: &str,
    debs: &[PathBuf],
) -> Result<()> {
    staged(
        runner,
        work,
        ext_dir,
        &format!("{DEPS_EXT}.new"),
        debs,
        |root| {
            let mut pruned = prune(root, &Policy::UbuntuDeny)?;
            pruned.extend(drop_image_files(root, owned, opt_root)?);
            if !pruned.is_empty() {
                log::info!("deb-apps: dependencies: removed {}", pruned.join(", "));
            }
            let setid = strip_setid(root)?;
            if !setid.is_empty() {
                log::warn!(
                    "deb-apps: dependencies: cleared setuid/setgid on {}",
                    setid.join(", ")
                );
            }
            write_release(root, DEPS_EXT, level)
        },
    )
}
