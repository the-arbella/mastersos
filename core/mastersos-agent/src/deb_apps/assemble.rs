//! Assembling unpacked packages into systemd-sysext trees (spec §4.3, §4.6, §4.7).
//!
//! This is the boundary that keeps a vendor package (and the Ubuntu dependencies it pulls in) from changing the signed
//! system's boot, login or permission paths. Every function works on an already unpacked tree (`dpkg-deb -x`, Task 6)
//! given as a directory fd, walks it one level at a time with `openat`/`fstatat(AT_SYMLINK_NOFOLLOW)` and **never
//! follows a symbolic link** of the tree.
//!
//! **Symbolic links** ([`prune`] checks every link left after pruning). The tree is `/` once merged, and systemd-sysext
//! only merges `/usr` and `/opt`, both root-controlled (`/usr` is the signed image, `/opt` the root partition plus
//! extensions). So a link is accepted only when it resolves *below* one of the allowed roots — `/usr/` and `/opt/` for
//! the vendor package, also `/etc/` (root-only) for Ubuntu dependencies, which routinely ship links such as
//! `usr/lib/ssl/openssl.cnf -> /etc/ssl/openssl.cnf`:
//! - absolute targets must start with an allowed root and contain no `..` (`usr/bin/foo -> /opt/foo/bin/foo`, how
//!   vendors expose binaries, is accepted; so is a link to an image file such as `/usr/bin/sh`);
//! - relative targets are resolved from the link's own directory; `..` may only appear as leading components (they pop
//!   real directories of the tree, never a link), must not climb above the tree, and the result must again be below an
//!   allowed root (`usr/bin/x -> ../../etc/passwd` is refused for a vendor although it stays "inside the tree").
//!
//! Without a `..` after the first name, resolution only descends from a checked place, so a chain of accepted links
//! cannot end outside the allowed roots. Any other link refuses a vendor tree (the error names it) and is dropped and
//! recorded in a dependency tree (a bad link in one Ubuntu package must not cost every app its dependencies). Device
//! nodes, FIFOs and sockets refuse either tree.

use std::collections::{HashMap, HashSet, VecDeque};
use std::os::fd::OwnedFd;
use std::path::Path;

use anyhow::{anyhow, bail, ensure, Context, Result};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, RawMode};
use rustix::io::Errno;

use crate::safefs;

/// Paths removed from every tree (spec §4.3 item 3): anything loaded by system services, the boot, login, permission
/// paths, the login screen, GNOME Shell or other session processes goes. A name ending in `*` matches every entry of
/// that directory starting with the rest. Applied to Ubuntu dependencies ([`Policy::UbuntuDeny`]) and, after the
/// allowlist, to vendor packages too (a vendor package called `systemd` must not fill `usr/lib/systemd`).
pub const UBUNTU_DENY: &[&str] = &[
    // systemd, udev, kernel and the boot
    "usr/lib/systemd",
    "usr/lib/udev",
    "usr/lib/sysusers.d",
    "usr/lib/tmpfiles.d",
    "usr/lib/modules",
    "usr/lib/firmware",
    "usr/lib/modules-load.d",
    "usr/lib/modprobe.d",
    "usr/lib/sysctl.d",
    "usr/lib/binfmt.d",
    "usr/lib/environment.d",
    "usr/lib/kernel",
    "usr/lib/dracut",
    "usr/lib/initramfs-tools",
    "usr/share/initramfs-tools",
    "usr/lib/extension-release.d",
    "usr/lib/os-release",
    // login, permissions and privileged helpers
    "usr/lib/pam.d",
    "usr/lib/security",
    "usr/lib/x86_64-linux-gnu/security",
    "usr/share/pam-configs",
    "usr/share/polkit-1",
    "usr/lib/polkit-1",
    "usr/share/dbus-1",
    "usr/share/accountsservice",
    "usr/sbin",
    "usr/lib/sudo",
    "usr/libexec/sudo",
    "usr/lib/x86_64-linux-gnu/libnss_*",
    "usr/lib/x86_64-linux-gnu/gconv",
    "usr/lib/x86_64-linux-gnu/pkcs11",
    "usr/share/p11-kit/modules",
    "usr/lib/NetworkManager",
    "usr/lib/x86_64-linux-gnu/NetworkManager",
    // the login screen, sessions and GNOME Shell
    "usr/share/gdm",
    "usr/share/gnome-shell",
    "usr/share/gnome-session",
    "usr/share/xsessions",
    "usr/share/wayland-sessions",
    "usr/share/gnome/autostart",
    "usr/share/glib-2.0/schemas",
    "usr/share/xdg-desktop-portal",
    "usr/share/thumbnailers",
    "usr/share/gvfs/mounts",
    "usr/share/ibus/component",
    "usr/share/gnome/applications",
    "usr/share/factory",
    // dependencies bring no launchers (spec §4.3 item 6)
    "usr/share/applications",
    // plugins loaded into the login screen, GNOME Shell and session processes
    "usr/lib/x86_64-linux-gnu/gio/modules",
    "usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0",
    "usr/lib/x86_64-linux-gnu/gtk-2.0",
    "usr/lib/x86_64-linux-gnu/gtk-3.0",
    "usr/lib/x86_64-linux-gnu/gtk-4.0",
    "usr/lib/x86_64-linux-gnu/gstreamer-1.0",
    "usr/lib/x86_64-linux-gnu/dri",
    "usr/lib/x86_64-linux-gnu/gbm",
    "usr/share/glvnd",
    "usr/share/vulkan",
    "usr/lib/x86_64-linux-gnu/pipewire-0.3",
    "usr/lib/x86_64-linux-gnu/spa-0.2",
    "usr/lib/x86_64-linux-gnu/wireplumber-0.5",
    "usr/share/pipewire",
    "usr/share/wireplumber",
    "usr/lib/xorg",
    "usr/share/X11/xorg.conf.d",
    // the image's own
    "usr/lib/mastersos",
    "usr/share/mastersos",
    "usr/libexec/mastersos",
];

/// Vendor packages (no Ubuntu signature): directory → the children kept there (each must be a real directory). Below
/// a kept directory everything stays, except in `usr/lib` (only `usr/lib/<package>`) and `usr/bin` (files and links
/// only); the deny list and the link check still apply.
const VENDOR_ALLOW: &[(&str, &[&str])] = &[
    ("usr", &["bin", "lib", "share"]),
    (
        "usr/share",
        &[
            "applications",
            "icons",
            "pixmaps",
            "doc",
            "man",
            "metainfo",
            "mime",
        ],
    ),
    ("usr/share/mime", &["packages"]),
];

/// Entries of [`UBUNTU_DENY`] a vendor package keeps: its own launchers, which [`write_desktop`] replaces.
const VENDOR_KEEPS: &[&str] = &["usr/share/applications"];

/// Caches the image builds by trigger (the same `*` rules as [`UBUNTU_DENY`], plus `*` as a whole middle component for
/// any directory there). A package's copy would shadow the image's: a `gschemas.compiled` replaces its dconf defaults,
/// an `icon-theme.cache` or `mime.cache` hides what the image has. Dropped from every tree; `usr/share/mime` keeps only
/// `packages/*.xml`, and font directories lose their `.uuid` and `fonts.cache-*` files ([`drop_generated`]).
const GENERATED: &[&str] = &[
    "usr/share/glib-2.0/schemas/gschemas.compiled",
    "usr/share/applications/mimeinfo.cache",
    "usr/share/icons/*/icon-theme.cache",
    "usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/*/loaders.cache",
    "usr/lib/x86_64-linux-gnu/gio/modules/giomodule.cache",
    "usr/lib/locale/locale-archive",
];

/// How much of an unpacked package survives [`prune`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {
    /// The app's own package (`package` is its `Package:` name): an allowlist.
    VendorAllow { package: String },
    /// Ubuntu dependencies (`app-deps`): everything but [`UBUNTU_DENY`].
    UbuntuDeny,
}

/// What starts the app: `exec` is the program's absolute path only (no arguments, no field codes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launcher {
    pub exec: String,
    pub icon: Option<String>,
    /// `type/subtype;` entries, each ending in `;`.
    pub mime: Option<String>,
}

const MAX_DEPTH: usize = 64;
const MAX_LINK_HOPS: usize = 40;
const MAX_DESKTOP_BYTES: u64 = 1024 * 1024;
pub const OUR_DESKTOP_PREFIX: &str = "mastersos-app-";
const FIELD_CODES: &[&str] = &[
    "%u", "%U", "%f", "%F", "%i", "%c", "%k", "%d", "%D", "%n", "%N", "%v", "%m",
];

/// One `fstatat(AT_SYMLINK_NOFOLLOW)`.
struct Ent {
    ty: FileType,
    mode: RawMode,
    size: u64,
}

fn join(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}/{name}")
    }
}

fn lstat(dir: &OwnedFd, name: &str, path: &str) -> Result<Option<Ent>> {
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => Ok(Some(Ent {
            ty: FileType::from_raw_mode(st.st_mode),
            mode: st.st_mode,
            size: u64::try_from(st.st_size).unwrap_or(0),
        })),
        Err(Errno::NOENT) => Ok(None),
        Err(e) => Err(std::io::Error::from(e)).with_context(|| format!("checking {path}")),
    }
}

/// Removes `dir/name` (a directory with everything below it, anything else as the entry itself), never following links.
fn remove_entry(dir: &OwnedFd, name: &str, e: &Ent, path: &str) -> Result<()> {
    if e.ty == FileType::Directory {
        safefs::remove_tree_at(dir, name).with_context(|| format!("removing {path}"))
    } else {
        match rustix::fs::unlinkat(dir, name, AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => Ok(()),
            Err(e) => Err(std::io::Error::from(e)).with_context(|| format!("removing {path}")),
        }
    }
}

/// Visits every entry below `dir` (sorted, depth first). `f(dir, name, path, entry)` returns whether to descend into a
/// directory; links are never descended.
fn walk(
    dir: &OwnedFd,
    prefix: &str,
    depth: usize,
    f: &mut dyn FnMut(&OwnedFd, &str, &str, &Ent) -> Result<bool>,
) -> Result<()> {
    ensure!(depth < MAX_DEPTH, "{prefix} is nested too deeply");
    let names = safefs::list_at(dir).with_context(|| format!("listing {}", shown(prefix)))?;
    for n in names {
        let path = join(prefix, &n);
        let Some(e) = lstat(dir, &n, &path)? else {
            continue;
        };
        if f(dir, &n, &path, &e)? && e.ty == FileType::Directory {
            let sub =
                safefs::open_child_dir(dir, &n)?.ok_or_else(|| anyhow!("{path} disappeared"))?;
            walk(&sub, &path, depth + 1, f)?;
        }
    }
    Ok(())
}

fn shown(prefix: &str) -> &str {
    if prefix.is_empty() {
        "the tree"
    } else {
        prefix
    }
}

/// Opens `rel` (`a/b/c`, empty = the root) one level at a time. `None` when a level is missing; a level that is not a
/// real directory (a link, a file) refuses the tree.
fn open_level(root: &OwnedFd, rel: &str) -> Result<Option<OwnedFd>> {
    let mut d = safefs::open_dir_at(root, Path::new(""), false)?;
    let mut path = String::new();
    for part in rel.split('/').filter(|p| !p.is_empty()) {
        path = join(&path, part);
        match lstat(&d, part, &path)? {
            None => return Ok(None),
            Some(e) if e.ty == FileType::Directory => {}
            Some(e) => bail!(
                "{path} in the unpacked package is not a directory ({:?}); refusing the package",
                e.ty
            ),
        }
        d = safefs::open_child_dir(&d, part)?.ok_or_else(|| anyhow!("{path} disappeared"))?;
    }
    Ok(Some(d))
}

/// A Debian package name (policy §5.6.1): lowercase letters, digits, `+`, `-`, `.`; at least two characters, starting
/// with a letter or digit. It becomes a directory name (`usr/lib/<package>`).
fn package_ok(p: &str) -> bool {
    p.len() >= 2
        && p.len() <= 128
        && p.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && p.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.')
        })
}

/// Removes what may not be merged (top-level entries other than `usr/` and `opt/`, the vendor allowlist, the deny
/// list), then checks every remaining link and refuses special files (see the module documentation). Returns the
/// removed paths (relative, e.g. `etc`, `usr/lib/systemd`); the caller reports them.
pub fn prune(root: &OwnedFd, policy: &Policy) -> Result<Vec<String>> {
    if let Policy::VendorAllow { package } = policy {
        ensure!(package_ok(package), "malformed package name {package:?}");
    }
    let mut removed = vec![];
    for n in safefs::list_at(root).context("listing the unpacked package")? {
        let Some(e) = lstat(root, &n, &n)? else {
            continue;
        };
        if n == "usr" || n == "opt" {
            ensure!(
                e.ty == FileType::Directory,
                "{n} in the unpacked package is not a directory ({:?}); refusing the package",
                e.ty
            );
        } else {
            remove_entry(root, &n, &e, &n)?;
            removed.push(n);
        }
    }
    if let Policy::VendorAllow { package } = policy {
        prune_vendor(root, package, &mut removed)?;
    }
    let vendor = matches!(policy, Policy::VendorAllow { .. });
    for d in UBUNTU_DENY {
        if vendor && VENDOR_KEEPS.contains(d) {
            continue;
        }
        remove_pattern(root, d, &mut removed)?;
    }
    drop_generated(root, &mut removed)?;
    check_entries(root, policy, &mut removed)?;
    Ok(removed)
}

/// Removes what `pattern` names (`a/b/c`; a middle component `*` means every real directory there, a last component
/// `x*` every entry starting with `x`). A missing level is fine; a named level that is not a real directory refuses the
/// tree (it would hide the system's directory once merged).
fn remove_pattern(root: &OwnedFd, pattern: &str, removed: &mut Vec<String>) -> Result<()> {
    let parts: Vec<&str> = pattern.split('/').collect();
    let dir = safefs::open_dir_at(root, Path::new(""), false)?;
    remove_parts(&dir, "", &parts, removed)
}

fn remove_parts(
    dir: &OwnedFd,
    prefix: &str,
    parts: &[&str],
    removed: &mut Vec<String>,
) -> Result<()> {
    let (first, rest) = parts
        .split_first()
        .ok_or_else(|| anyhow!("empty pattern"))?;
    if rest.is_empty() {
        let names = match first.strip_suffix('*') {
            Some(p) => safefs::list_at(dir)?
                .into_iter()
                .filter(|n| n.starts_with(p))
                .collect(),
            None => vec![first.to_string()],
        };
        for n in names {
            let path = join(prefix, &n);
            if let Some(e) = lstat(dir, &n, &path)? {
                remove_entry(dir, &n, &e, &path)?;
                removed.push(path);
            }
        }
        return Ok(());
    }
    let names = if *first == "*" {
        safefs::list_at(dir)?
    } else {
        vec![first.to_string()]
    };
    for n in names {
        let path = join(prefix, &n);
        let Some(e) = lstat(dir, &n, &path)? else {
            continue;
        };
        if e.ty != FileType::Directory {
            if *first == "*" {
                continue;
            }
            bail!(
                "{path} in the unpacked package is not a directory ({:?}); refusing the package",
                e.ty
            );
        }
        let sub = safefs::open_child_dir(dir, &n)?.ok_or_else(|| anyhow!("{path} disappeared"))?;
        remove_parts(&sub, &path, rest, removed)?;
    }
    Ok(())
}

/// Drops [`GENERATED`], everything in `usr/share/mime` but `packages/*.xml` (regular files), and the fontconfig files
/// below `usr/share/fonts`.
fn drop_generated(root: &OwnedFd, removed: &mut Vec<String>) -> Result<()> {
    for g in GENERATED {
        remove_pattern(root, g, removed)?;
    }
    if let Some(mime) = open_level(root, "usr/share/mime")? {
        for n in safefs::list_at(&mime)? {
            let path = join("usr/share/mime", &n);
            let Some(e) = lstat(&mime, &n, &path)? else {
                continue;
            };
            if n == "packages" && e.ty == FileType::Directory {
                let pk = safefs::open_child_dir(&mime, &n)?
                    .ok_or_else(|| anyhow!("{path} disappeared"))?;
                for x in safefs::list_at(&pk)? {
                    let xp = join(&path, &x);
                    if let Some(xe) = lstat(&pk, &x, &xp)? {
                        if !(xe.ty == FileType::RegularFile && x.ends_with(".xml")) {
                            remove_entry(&pk, &x, &xe, &xp)?;
                            removed.push(xp);
                        }
                    }
                }
            } else {
                remove_entry(&mime, &n, &e, &path)?;
                removed.push(path);
            }
        }
    }
    if let Some(fonts) = open_level(root, "usr/share/fonts")? {
        let mut drop = vec![];
        walk(&fonts, "usr/share/fonts", 1, &mut |dir, name, path, e| {
            if e.ty != FileType::Directory && (name == ".uuid" || name.starts_with("fonts.cache-"))
            {
                remove_entry(dir, name, e, path)?;
                drop.push(path.to_string());
            }
            Ok(true)
        })?;
        removed.extend(drop);
    }
    Ok(())
}

fn prune_vendor(root: &OwnedFd, package: &str, removed: &mut Vec<String>) -> Result<()> {
    let lib = [package];
    let levels = VENDOR_ALLOW
        .iter()
        .copied()
        .chain(std::iter::once(("usr/lib", &lib[..])));
    for (dir, keep) in levels {
        let Some(d) = open_level(root, dir)? else {
            continue;
        };
        for n in safefs::list_at(&d)? {
            let path = join(dir, &n);
            let Some(e) = lstat(&d, &n, &path)? else {
                continue;
            };
            if keep.contains(&n.as_str()) {
                ensure!(
                    e.ty == FileType::Directory,
                    "{path} in the unpacked package is not a directory ({:?}); refusing the package",
                    e.ty
                );
            } else {
                remove_entry(&d, &n, &e, &path)?;
                removed.push(path);
            }
        }
    }
    // usr/share/applications: launchers only (regular *.desktop files; write_desktop then leaves just ours). Anything
    // else there would still reach GLib: subdirectories become launchers, mimeapps.list/defaults.list set defaults.
    if let Some(d) = open_level(root, "usr/share/applications")? {
        for n in safefs::list_at(&d)? {
            let path = join("usr/share/applications", &n);
            if let Some(e) = lstat(&d, &n, &path)? {
                if !(e.ty == FileType::RegularFile && n.ends_with(".desktop")) {
                    remove_entry(&d, &n, &e, &path)?;
                    removed.push(path);
                }
            }
        }
    }
    // usr/bin/*: programs (files or links), not directories
    if let Some(d) = open_level(root, "usr/bin")? {
        for n in safefs::list_at(&d)? {
            let path = join("usr/bin", &n);
            if let Some(e) = lstat(&d, &n, &path)? {
                if e.ty == FileType::Directory {
                    remove_entry(&d, &n, &e, &path)?;
                    removed.push(path);
                }
            }
        }
    }
    Ok(())
}

/// Checks every link (see the module documentation) and refuses anything that is not a file, directory or link. A
/// vendor link outside `/usr` and `/opt` refuses the tree; an Ubuntu dependency may also point into `/etc` (OpenJDK,
/// OpenSSL and Python ship such links) and any other bad link is dropped and recorded in `removed`.
fn check_entries(root: &OwnedFd, policy: &Policy, removed: &mut Vec<String>) -> Result<()> {
    let roots: &[&str] = match policy {
        Policy::VendorAllow { .. } => &["usr", "opt"],
        Policy::UbuntuDeny => &["usr", "opt", "etc"],
    };
    let mut dropped = vec![];
    walk(root, "", 0, &mut |dir, name, path, e| match e.ty {
        FileType::Directory | FileType::RegularFile => Ok(true),
        FileType::Symlink => {
            let target = read_link(dir, name, path)?;
            if let Err(err) = link_target(path, &target, roots) {
                if matches!(policy, Policy::VendorAllow { .. }) {
                    return Err(err.context("refusing the package"));
                }
                log::warn!("deb-apps: dropping {err:#}");
                remove_entry(dir, name, e, path)?;
                dropped.push(path.to_string());
            }
            Ok(false)
        }
        t => bail!("{path} in the unpacked package is a {t:?}; refusing the package"),
    })?;
    removed.extend(dropped);
    Ok(())
}

fn read_link(dir: &OwnedFd, name: &str, path: &str) -> Result<String> {
    rustix::fs::readlinkat(dir, name, Vec::new())
        .map_err(std::io::Error::from)
        .with_context(|| format!("reading the link {path}"))?
        .into_string()
        .map_err(|_| anyhow!("the link {path} has a non-UTF-8 target; refusing the package"))
}

/// Where the link at `path` points once merged, as a relative path below one of `roots` (see the module documentation).
fn link_target(path: &str, target: &str, roots: &[&str]) -> Result<String> {
    let refuse = |why: &str| anyhow!("{path} is a link to {target:?}, which {why}");
    let mut out: Vec<&str> = vec![];
    if let Some(abs) = target.strip_prefix('/') {
        for c in abs.split('/') {
            match c {
                "" | "." => {}
                ".." => return Err(refuse("contains ..")),
                c => out.push(c),
            }
        }
    } else {
        ensure!(!target.is_empty(), refuse("is empty"));
        out.extend(path.split('/'));
        out.pop();
        let mut leading = true;
        for c in target.split('/') {
            match c {
                "" | "." => {}
                ".." if leading => {
                    if out.pop().is_none() {
                        return Err(refuse("leaves the tree"));
                    }
                }
                ".." => return Err(refuse("has .. after a name")),
                c => {
                    leading = false;
                    out.push(c);
                }
            }
        }
    }
    if out.len() < 2 || !roots.contains(&out[0]) {
        let allowed: Vec<String> = roots.iter().map(|r| format!("/{r}")).collect();
        return Err(refuse(&format!("is not below {}", allowed.join(", "))));
    }
    Ok(out.join("/"))
}

/// The paths the image owns, from the factory dpkg file lists (`<factory_info>/*.list`, e.g.
/// `/usr/share/factory/var/lib/dpkg/info`), plus the targets of dpkg diversions (`<factory_info>/../diversions`).
/// Relative to `/`, without the leading `/`; `/bin`, `/sbin` and `/lib*` are mapped below `usr/` (usrmerge).
pub fn image_owned(factory_info: &Path) -> Result<HashSet<String>> {
    let dir = safefs::open_abs_dir(factory_info, false)
        .with_context(|| format!("opening {}", factory_info.display()))?;
    let mut owned = HashSet::new();
    let mut lists = 0;
    for n in safefs::list_at(&dir)? {
        if !n.ends_with(".list") {
            continue;
        }
        lists += 1;
        let bytes = safefs::read_at(&dir, &n)?.ok_or_else(|| anyhow!("{n} disappeared"))?;
        owned.extend(
            String::from_utf8_lossy(&bytes)
                .lines()
                .filter_map(owned_path),
        );
    }
    ensure!(
        lists > 0,
        "{} has no dpkg file lists",
        factory_info.display()
    );
    if let Some(parent) = factory_info.parent() {
        let pd = safefs::open_abs_dir(parent, false)?;
        if let Some(bytes) = safefs::read_at(&pd, "diversions")? {
            // Triplets: diverted path, where it went, the diverting package
            owned.extend(
                String::from_utf8_lossy(&bytes)
                    .lines()
                    .skip(1)
                    .step_by(3)
                    .filter_map(owned_path),
            );
        }
    }
    Ok(owned)
}

fn owned_path(line: &str) -> Option<String> {
    let mut parts: Vec<&str> = line
        .strip_prefix('/')?
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    if parts.is_empty() || parts.contains(&"..") {
        return None;
    }
    if matches!(
        parts[0],
        "bin" | "sbin" | "lib" | "lib32" | "lib64" | "libx32"
    ) {
        parts.insert(0, "usr");
    }
    Some(parts.join("/"))
}

/// Drops every entry that would cover something of the system (spec §4.3 item 4): below `usr/` a path the image owns
/// (`owned`, from [`image_owned`]), below `opt/` anything already in `opt_root` (the root partition's `/opt`, not
/// covered by an extension: `/opt` is not in the signed image). A directory present on both sides is merged (walked
/// into); a directory where the system has a file, a link or (in `/usr`) an empty directory is dropped whole, since it
/// would hide what is there. Returns the dropped paths.
pub fn drop_image_files(
    root: &OwnedFd,
    owned: &HashSet<String>,
    opt_root: &Path,
) -> Result<Vec<String>> {
    // Every directory that has something of the image below it
    let mut parents: HashSet<&str> = HashSet::new();
    for p in owned {
        for (i, b) in p.bytes().enumerate() {
            if b == b'/' {
                parents.insert(&p[..i]);
            }
        }
    }
    let mut dropped = vec![];
    if let Some(usr) = open_level(root, "usr")? {
        drop_usr(&usr, "usr", owned, &parents, &mut dropped, 0)?;
    }
    if let Some(opt) = open_level(root, "opt")? {
        let real = match std::fs::symlink_metadata(opt_root) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            _ => Some(
                safefs::open_abs_dir(opt_root, false)
                    .with_context(|| format!("opening {}", opt_root.display()))?,
            ),
        };
        if let Some(real) = real {
            drop_opt(&opt, &real, "opt", &mut dropped, 0)?;
        }
    }
    Ok(dropped)
}

fn drop_usr(
    dir: &OwnedFd,
    prefix: &str,
    owned: &HashSet<String>,
    parents: &HashSet<&str>,
    dropped: &mut Vec<String>,
    depth: usize,
) -> Result<()> {
    ensure!(depth < MAX_DEPTH, "{prefix} is nested too deeply");
    for n in safefs::list_at(dir)? {
        let path = join(prefix, &n);
        let Some(e) = lstat(dir, &n, &path)? else {
            continue;
        };
        let merge = e.ty == FileType::Directory && parents.contains(path.as_str());
        if merge {
            let sub =
                safefs::open_child_dir(dir, &n)?.ok_or_else(|| anyhow!("{path} disappeared"))?;
            drop_usr(&sub, &path, owned, parents, dropped, depth + 1)?;
        } else if owned.contains(&path) || parents.contains(path.as_str()) {
            remove_entry(dir, &n, &e, &path)?;
            dropped.push(path);
        }
    }
    Ok(())
}

fn drop_opt(
    dir: &OwnedFd,
    real: &OwnedFd,
    prefix: &str,
    dropped: &mut Vec<String>,
    depth: usize,
) -> Result<()> {
    ensure!(depth < MAX_DEPTH, "{prefix} is nested too deeply");
    for n in safefs::list_at(dir)? {
        let path = join(prefix, &n);
        let Some(e) = lstat(dir, &n, &path)? else {
            continue;
        };
        let Some(r) = lstat(real, &n, &format!("/{path}"))? else {
            continue;
        };
        if e.ty == FileType::Directory && r.ty == FileType::Directory {
            let sub =
                safefs::open_child_dir(dir, &n)?.ok_or_else(|| anyhow!("{path} disappeared"))?;
            let real_sub =
                safefs::open_child_dir(real, &n)?.ok_or_else(|| anyhow!("/{path} disappeared"))?;
            drop_opt(&sub, &real_sub, &path, dropped, depth + 1)?;
        } else {
            remove_entry(dir, &n, &e, &path)?;
            dropped.push(path);
        }
    }
    Ok(())
}

/// Clears the setuid and setgid bits of every regular file (spec §4.3 item 5) and returns their paths. Directories keep
/// theirs (setgid on a directory only sets the group of new files, and the merged tree is read-only).
pub fn strip_setid(root: &OwnedFd) -> Result<Vec<String>> {
    let mut out = vec![];
    walk(root, "", 0, &mut |dir, name, path, e| {
        if e.ty == FileType::RegularFile && e.mode & 0o6000 != 0 {
            let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
            let fd = rustix::fs::openat(dir, name, flags, Mode::empty())
                .map_err(std::io::Error::from)
                .with_context(|| format!("opening {path}"))?;
            let st = rustix::fs::fstat(&fd).map_err(std::io::Error::from)?;
            ensure!(
                FileType::from_raw_mode(st.st_mode) == FileType::RegularFile,
                "{path} changed while clearing setuid"
            );
            rustix::fs::fchmod(&fd, Mode::from_raw_mode(st.st_mode & 0o1777))
                .map_err(std::io::Error::from)
                .with_context(|| format!("clearing setuid/setgid of {path}"))?;
            out.push(path.to_string());
        }
        Ok(true)
    })?;
    Ok(out)
}

/// A usable `[Desktop Entry]`.
struct Found {
    exec: String,
    icon: Option<String>,
    mime: Option<String>,
}

/// Unescapes a desktop-file string value (`\s`, `\n`, `\t`, `\r`, `\\`).
fn unescape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut it = v.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('s') => out.push(' '),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some(o) => {
                out.push('\\');
                out.push(o);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// `Type=Application`, not `NoDisplay`/`Hidden`, with an `Exec`: the keys of `[Desktop Entry]`, else `None`.
fn parse_desktop(text: &str) -> Option<Found> {
    let mut in_entry = false;
    let mut keys: HashMap<&str, &str> = HashMap::new();
    for l in text.lines() {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if l.starts_with('[') {
            in_entry = l == "[Desktop Entry]";
            continue;
        }
        if !in_entry {
            continue;
        }
        if let Some((k, v)) = l.split_once('=') {
            keys.entry(k.trim()).or_insert(v.trim());
        }
    }
    let yes = |k: &str| keys.get(k).is_some_and(|v| v.eq_ignore_ascii_case("true"));
    if keys.get("Type") != Some(&"Application") || yes("NoDisplay") || yes("Hidden") {
        return None;
    }
    let exec = unescape(keys.get("Exec")?);
    if exec.trim().is_empty() {
        return None;
    }
    let icon = keys
        .get("Icon")
        .map(|v| unescape(v))
        .filter(|v| !v.is_empty());
    let mime = keys.get("MimeType").and_then(|v| normalize_mime(v));
    Some(Found { exec, icon, mime })
}

fn mime_ok(m: &str) -> bool {
    let ok = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$&^_.+-".contains(&b))
    };
    m.split_once('/').is_some_and(|(a, b)| ok(a) && ok(b))
}

/// `a/b;c/d` → `a/b;c/d;`, keeping only well-formed entries; `None` when nothing is left.
fn normalize_mime(v: &str) -> Option<String> {
    let entries: Vec<&str> = v.split(';').map(str::trim).filter(|m| mime_ok(m)).collect();
    (!entries.is_empty()).then(|| entries.iter().map(|m| format!("{m};")).collect())
}

/// Splits an (unescaped) `Exec` value into arguments, with the spec's double-quote rules.
fn exec_args(exec: &str) -> Result<Vec<String>> {
    let mut args = vec![];
    let mut it = exec.chars().peekable();
    loop {
        while it.peek().is_some_and(|c| *c == ' ' || *c == '\t') {
            it.next();
        }
        let Some(&c) = it.peek() else {
            return Ok(args);
        };
        let mut arg = String::new();
        if c == '"' {
            it.next();
            loop {
                match it.next() {
                    Some('"') => break,
                    Some('\\') => arg.push(it.next().ok_or_else(|| anyhow!("unterminated quote"))?),
                    Some(c) => arg.push(c),
                    None => bail!("unterminated quote in Exec"),
                }
            }
        } else {
            while let Some(&c) = it.peek() {
                if c == ' ' || c == '\t' {
                    break;
                }
                arg.push(c);
                it.next();
            }
        }
        args.push(arg);
    }
}

/// The program of an `Exec` value: absolute, or a bare name meaning `/usr/bin/<name>`. Field codes and any other
/// arguments are dropped (our `.desktop` and the kiosk session start the program alone).
fn program_of(exec: &str) -> Result<String> {
    let args = exec_args(exec)?;
    let (prog, rest) = args
        .split_first()
        .ok_or_else(|| anyhow!("the package's Exec is empty"))?;
    let extra: Vec<&String> = rest
        .iter()
        .filter(|a| !FIELD_CODES.contains(&a.as_str()))
        .collect();
    if !extra.is_empty() {
        log::warn!("deb-apps: dropping the arguments {extra:?} of the package's Exec {exec:?}");
    }
    if prog.starts_with('/') {
        Ok(prog.clone())
    } else if !prog.contains('/') && !prog.is_empty() {
        Ok(format!("/usr/bin/{prog}"))
    } else {
        bail!("the package's Exec {exec:?} has no usable program; write exec")
    }
}

/// The shape every program path must have: absolute, below `/opt/` or `/usr/`, clean, no control characters or `%`.
fn check_exec_shape(p: &str) -> Result<()> {
    let clean = (p.starts_with("/opt/") || p.starts_with("/usr/"))
        && p[1..]
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..")
        && !p.chars().any(|c| c.is_control() || c == '%');
    ensure!(
        clean,
        "exec {p:?} must be a clean absolute path below /opt/ or /usr/"
    );
    Ok(())
}

/// `p` must be provided by this tree: resolved inside it (following the tree's own links, never leaving it) to an
/// executable regular file.
fn check_exec(root: &OwnedFd, p: &str) -> Result<()> {
    check_exec_shape(p)?;
    let mut todo: VecDeque<String> = p.split('/').map(str::to_string).collect();
    let mut cur: Vec<String> = vec![];
    let mut hops = 0;
    while let Some(c) = todo.pop_front() {
        match c.as_str() {
            "" | "." => continue,
            ".." => {
                cur.pop()
                    .ok_or_else(|| anyhow!("exec {p:?} leaves this package through a link"))?;
                continue;
            }
            _ => {}
        }
        let rel = cur.join("/");
        let dir =
            open_level(root, &rel)?.ok_or_else(|| anyhow!("exec {p:?} is not in this package"))?;
        let path = join(&rel, &c);
        let Some(e) = lstat(&dir, &c, &path)? else {
            bail!("exec {p:?} is not in this package (/{path} is missing)");
        };
        if e.ty == FileType::Symlink {
            hops += 1;
            ensure!(hops <= MAX_LINK_HOPS, "exec {p:?}: too many links");
            let t = read_link(&dir, &c, &path)?;
            if t.starts_with('/') {
                cur.clear();
            }
            for part in t.split('/').rev() {
                todo.push_front(part.to_string());
            }
        } else if todo.iter().all(|t| t.is_empty() || t == ".") {
            ensure!(
                e.ty == FileType::RegularFile && e.mode & 0o111 != 0,
                "exec {p:?} is not an executable file in this package"
            );
            return Ok(());
        } else {
            ensure!(
                e.ty == FileType::Directory,
                "exec {p:?}: /{path} is not a directory"
            );
            cur.push(c);
        }
    }
    bail!("exec {p:?} is not an executable file in this package")
}

/// Usable `.desktop` files (regular files, links ignored) directly in `dir` (`prefix`) or, with `deep`, anywhere below it
/// except `usr/share/applications`.
fn find_desktops(root: &OwnedFd, deep: bool) -> Result<Vec<Found>> {
    let mut found = vec![];
    let mut take = |dir: &OwnedFd, name: &str, path: &str, e: &Ent| -> Result<()> {
        if e.ty == FileType::RegularFile
            && name.ends_with(".desktop")
            && e.size <= MAX_DESKTOP_BYTES
        {
            let bytes = safefs::read_at(dir, name)?.ok_or_else(|| anyhow!("{path} disappeared"))?;
            if let Some(f) = parse_desktop(&String::from_utf8_lossy(&bytes)) {
                found.push(f);
            }
        }
        Ok(())
    };
    if deep {
        walk(root, "", 0, &mut |dir, name, path, e| {
            take(dir, name, path, e)?;
            Ok(path != "usr/share/applications")
        })?;
    } else if let Some(apps) = open_level(root, "usr/share/applications")? {
        for n in safefs::list_at(&apps)? {
            let path = join("usr/share/applications", &n);
            if let Some(e) = lstat(&apps, &n, &path)? {
                take(&apps, &n, &path, &e)?;
            }
        }
    }
    Ok(found)
}

/// The app's launcher (spec §4.3 item 6): the one usable `.desktop` in `usr/share/applications/`, else in the whole
/// tree (TestNav keeps it in `/opt/testnav/lib/`). With `exec_override` (IT's `exec`) that path is used instead, and the
/// icon and MIME types come from the `.desktop` starting it (or the only one). Either way the program must be an
/// executable file this tree provides.
pub fn pick_launcher(root: &OwnedFd, exec_override: Option<&str>) -> Result<Launcher> {
    let mut found = find_desktops(root, false)?;
    if found.is_empty() {
        found = find_desktops(root, true)?;
    }
    let Some(exec) = exec_override else {
        ensure!(
            found.len() == 1,
            "no single launcher (found {}); write exec",
            found.len()
        );
        let f = found.remove(0);
        let exec = program_of(&f.exec)?;
        check_exec(root, &exec)?;
        return Ok(Launcher {
            exec,
            icon: f.icon,
            mime: f.mime,
        });
    };
    check_exec(root, exec)?;
    let mut matching: Vec<Found> = found
        .iter()
        .filter(|f| program_of(&f.exec).is_ok_and(|p| p == exec))
        .map(|f| Found {
            exec: f.exec.clone(),
            icon: f.icon.clone(),
            mime: f.mime.clone(),
        })
        .collect();
    if matching.is_empty() && found.len() == 1 {
        matching = found;
    }
    let (icon, mime) = match matching.len() {
        1 => {
            let f = matching.remove(0);
            (f.icon, f.mime)
        }
        _ => (None, None),
    };
    Ok(Launcher {
        exec: exec.to_string(),
        icon,
        mime,
    })
}

/// A desktop-file string: non-empty, no control characters (no injected lines), `\` escaped.
fn text_value(v: &str, what: &str) -> Result<String> {
    ensure!(
        !v.is_empty() && !v.chars().any(char::is_control),
        "{what} {v:?} must be non-empty and contain no control characters"
    );
    Ok(v.replace('\\', "\\\\"))
}

/// The program as one `Exec` argument: bare when it has only plain characters, else double-quoted with the spec's
/// escapes; then escaped as a string value.
fn exec_value(p: &str) -> Result<String> {
    check_exec_shape(p)?;
    let plain = p
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/._+-@,:=".contains(&b));
    let arg = if plain {
        p.to_string()
    } else {
        let mut q = String::from("\"");
        for c in p.chars() {
            if matches!(c, '"' | '`' | '$' | '\\') {
                q.push('\\');
            }
            q.push(c);
        }
        q.push('"');
        q
    };
    Ok(arg.replace('\\', "\\\\"))
}

/// Replaces everything in `usr/share/applications/` (the package's launchers, subdirectories, `mimeapps.list` and the
/// like) with ours alone, `mastersos-app-<id>.desktop` (spec §4.3 item 6): `Name` is IT's `name`, `Exec` the program (plus `%U` when it handles MIME types, so links like `tnav:` reach
/// it), `Icon` IT's icon or the package's, `NoDisplay=true` for kiosk apps (§4.7). Every value is checked first, so a
/// refused value leaves the tree as it was.
pub fn write_desktop(
    root: &OwnedFd,
    id: &str,
    name: &str,
    l: &Launcher,
    icon: Option<&str>,
    kiosk: bool,
) -> Result<()> {
    ensure!(
        mastersos_bundle::kiosk::id_ok(id),
        "malformed app id {id:?}"
    );
    let name = text_value(name, "name")?;
    let exec = exec_value(&l.exec)?;
    let icon = icon
        .or(l.icon.as_deref())
        .map(|i| text_value(i, "icon"))
        .transpose()?;
    let mime = match &l.mime {
        Some(m) => {
            let entries: Vec<&str> = m.split(';').filter(|e| !e.is_empty()).collect();
            ensure!(
                !entries.is_empty() && entries.iter().all(|e| mime_ok(e)),
                "malformed MimeType {m:?}"
            );
            Some(entries.iter().map(|e| format!("{e};")).collect::<String>())
        }
        None => None,
    };
    let mut text = format!("[Desktop Entry]\nType=Application\nName={name}\nExec={exec}");
    if mime.is_some() {
        text.push_str(" %U");
    }
    text.push('\n');
    if let Some(i) = &icon {
        text.push_str(&format!("Icon={i}\n"));
    }
    if let Some(m) = &mime {
        text.push_str(&format!("MimeType={m}\n"));
    }
    text.push_str("Terminal=false\n");
    if kiosk {
        text.push_str("NoDisplay=true\n");
    }

    let apps = safefs::open_dir_at(root, Path::new("usr/share/applications"), true)?;
    let ours = format!("{OUR_DESKTOP_PREFIX}{id}.desktop");
    for n in safefs::list_at(&apps)? {
        if n != ours {
            let path = join("usr/share/applications", &n);
            if let Some(e) = lstat(&apps, &n, &path)? {
                remove_entry(&apps, &n, &e, &path)?;
            }
        }
    }
    safefs::write_at(&apps, &ours, text.as_bytes(), 0o644)?;
    Ok(())
}

fn release_word(v: &str, extra: &[u8]) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && v.starts_with(|c: char| c.is_ascii_alphanumeric())
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
}

/// `usr/lib/extension-release.d/extension-release.<ext_name>`: `ID=ubuntu`, the image's `SYSEXT_LEVEL` (spec §4.6:
/// systemd-sysext then refuses to merge it on another image version) and `SYSEXT_SCOPE=system`.
pub fn write_release(root: &OwnedFd, ext_name: &str, level: &str) -> Result<()> {
    ensure!(
        release_word(ext_name, b"-") && !ext_name.bytes().any(|b| b.is_ascii_uppercase()),
        "malformed extension name {ext_name:?}"
    );
    ensure!(
        release_word(level, b"._-"),
        "malformed SYSEXT_LEVEL {level:?}"
    );
    let dir = safefs::open_dir_at(root, Path::new("usr/lib/extension-release.d"), true)?;
    safefs::write_at(
        &dir,
        &format!("extension-release.{ext_name}"),
        format!("ID=ubuntu\nSYSEXT_LEVEL={level}\nSYSEXT_SCOPE=system\n").as_bytes(),
        0o644,
    )?;
    Ok(())
}

/// Refuses two trees (`(extension name, tree)`, in assembly order) providing the same path (spec §4.3 item 4); a
/// directory present in both merges. The error names the path and both extensions.
pub fn check_overlaps(trees: &[(String, &OwnedFd)]) -> Result<()> {
    let mut seen: HashMap<String, (usize, bool)> = HashMap::new();
    for (i, (name, fd)) in trees.iter().enumerate() {
        walk(fd, "", 0, &mut |_, _, path, e| {
            let is_dir = e.ty == FileType::Directory;
            match seen.get(path) {
                Some((_, true)) if is_dir => Ok(true),
                Some((j, _)) => bail!("/{path} is provided by both {} and {name}", trees[*j].0),
                None => {
                    seen.insert(path.to_string(), (i, is_dir));
                    Ok(true)
                }
            }
        })
        .with_context(|| format!("checking {name} against the other extensions"))?;
    }
    Ok(())
}
