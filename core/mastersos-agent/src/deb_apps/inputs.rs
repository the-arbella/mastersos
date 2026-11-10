//! The inputs of a round: the main packages ([`fetch`], with IT's icon, [`icon_for`]) and the shared dependencies
//! ([`dependencies`]). See [`super::round`] for the work directory and when each is fetched or resolved again.

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use mastersos_bundle::DebApp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::apt::{self, UbuntuSource};
use super::build;
use super::round::{blocking, Installed, Resolved, RoundEnv, RoundState, DAY};
use super::status::Wanted;
use crate::apply::hex;
use crate::runner::{Cmd, Runner};
use crate::safefs;
use crate::sysext::{self, FetchOutcome, Fetched, ShaMismatch};

/// Spec §4.4.
const MAX_DEB_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const DEB_TIMEOUT: Duration = Duration::from_secs(90 * 60);
const ICON_TIMEOUT: Duration = Duration::from_secs(60);
const DEB: &str = "app.deb";
/// A download being checked before it becomes [`DEB`].
const DEB_NEW: &str = "app.deb.new";
/// The package the installed tree was built from ([`keep_installed`]).
const INSTALLED: &str = "installed.deb";
const PIN_FAILED: &str = "pin-failed";
const META: &str = "fetched.json";
const CHECKED: &str = "checked-at";
const ICON: &str = "icon";
const ICON_URL: &str = "icon-url";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Meta {
    url: String,
    fetched: Fetched,
}

/// A main package ready to build from.
pub(super) struct Main {
    pub(super) path: PathBuf,
    pub(super) sha256: String,
    pub(super) package: String,
    pub(super) version: String,
    pub(super) note: Option<String>,
}

pub(super) fn read_secs(dir: &OwnedFd, name: &str) -> Option<i64> {
    safefs::read_at(dir, name)
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8_lossy(&b).trim().parse().ok())
}

pub(super) fn sha_hex(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

/// `name_version_arch.deb` (apt's quoting) → `name version`.
pub(super) fn dep_label(file: &str) -> String {
    let unquote = |s: &str| {
        s.replace("%3a", ":")
            .replace("%5f", "_")
            .replace("%25", "%")
    };
    let base = file.strip_suffix(".deb").unwrap_or(file);
    let mut it = base.splitn(3, '_');
    match (it.next(), it.next()) {
        (Some(n), Some(v)) => format!("{} {}", unquote(n), unquote(v)),
        _ => file.to_string(),
    }
}

/// The URL rules of the record (lint already checked them; a hand-edited `wanted.json` is checked again).
pub(super) fn check_record(id: &str, app: &DebApp) -> Result<(), String> {
    // Tests serve the packages over plain http from 127.0.0.1.
    #[cfg(test)]
    let app = &{
        let mut a = app.clone();
        if let Some(rest) = a.url.strip_prefix("http://127.0.0.1") {
            a.url = format!("https://127.0.0.1{rest}");
        }
        a
    };
    mastersos_bundle::deb::check(id, app).map_err(|e| e.message)
}

/// A main package's `Package` and `Version` (`dpkg-deb -f`, runs nothing from it). Anything that is not a .deb (an HTML
/// error page served with 200) fails here, and so does a package for another architecture than `amd64` or `all`.
fn control_of(r: &dyn Runner, deb: &Path) -> Result<(String, String)> {
    let c = crate::runner::run_ok(r, Cmd::new("dpkg-deb", &["-f", &deb.to_string_lossy()]))
        .context("the file is not a readable .deb package")?;
    let get = |k: &str| {
        c.lines()
            .find_map(|l| l.strip_prefix(&format!("{k}:")))
            .map(|v| v.trim().to_string())
            .filter(|v| {
                !v.is_empty()
                    && v.len() <= 128
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".+~:-".contains(&b))
            })
            .ok_or_else(|| anyhow!("the package has no usable {k} field"))
    };
    let arch = get("Architecture")?;
    ensure!(
        arch == "amd64" || arch == "all",
        "the package is for {arch}, not amd64"
    );
    Ok((get("Package")?, get("Version")?))
}

/// A pinned download that did not match (`apps/<id>/pin-failed`): the same `url` and `sha256` are not tried again for a
/// day.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PinFailed {
    url: String,
    want: String,
    got: String,
    /// Unix seconds.
    at: i64,
}

pub(super) fn when(at: i64) -> String {
    chrono::DateTime::from_timestamp(at, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| at.to_string())
}

/// Downloads `url` into `apps/<id>/app.deb.new` and checks it is a package ([`control_of`]) before it replaces `app.deb`:
/// a bad download never replaces the last good file. Refused before anything is written when the work directory or
/// `/var/lib/extensions` would be left without the free space for it ([`build::check_space`], with the response's
/// `Content-Length`). `None`: not modified (`cond` given and the server answered 304).
async fn download_main(
    env: &RoundEnv,
    dir: &OwnedFd,
    id: &str,
    url: &str,
    want: Option<&str>,
    cond: Option<&Fetched>,
) -> Result<Option<(Fetched, (String, String))>> {
    let free = env.free_space.clone();
    let (work, ext_dir) = (env.paths.work.clone(), env.paths.ext_dir.clone());
    let mut on_length = move |len: Option<u64>| {
        build::check_space(
            &free,
            &[&work, &ext_dir],
            len.unwrap_or(0),
            "downloading the package",
        )
    };
    let got = sysext::download_sized(
        &env.http,
        url,
        want,
        MAX_DEB_BYTES,
        DEB_TIMEOUT,
        dir,
        DEB_NEW,
        cond,
        &mut on_length,
    )
    .await
    .with_context(|| format!("downloading {url}"))?;
    let FetchOutcome::Fetched(f) = got else {
        return Ok(None);
    };
    let file = env.paths.work.join("apps").join(id).join(DEB_NEW);
    match blocking(env, move |r| control_of(r, &file)).await {
        Ok(c) => {
            safefs::rename_at(dir, DEB_NEW, DEB)?;
            Ok(Some((f, c)))
        }
        Err(e) => {
            let _ = safefs::remove_at(dir, DEB_NEW);
            Err(e.context(format!("{url} did not give a usable .deb package")))
        }
    }
}

/// The main package of `id` (see the module docs of [`super::round`]): `apps/<id>/app.deb`, or `apps/<id>/installed.deb`
/// (the package the installed tree was built from, [`keep_installed`]) when the app must be rebuilt for a new image and
/// its source cannot be reached, or when `app.deb` is not at hand. `installed` is the app's entry in the round state.
pub(super) async fn fetch(
    env: &RoundEnv,
    work: &OwnedFd,
    id: &str,
    app: &DebApp,
    installed: Option<&Installed>,
) -> Result<Main> {
    let apps = safefs::open_dir_at(work, Path::new("apps"), true)?;
    safefs::set_mode(&apps, 0o700)?;
    let dir = safefs::open_dir_at(&apps, Path::new(id), true)?;
    safefs::set_mode(&dir, 0o700)?;
    // a download an interrupted round left
    let _ = safefs::remove_at(&dir, DEB_NEW);
    let app_dir = env.paths.work.join("apps").join(id);
    let have = safefs::read_at(&dir, META)
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice::<Meta>(&b).ok())
        .filter(|m| m.url == app.url)
        .filter(|_| matches!(safefs::open_file_at(&dir, DEB), Ok(Some(_))));
    // the package the installed tree was built from, and whether the image changed under it
    let kept = installed
        .filter(|i| !i.deb_sha256.is_empty())
        .filter(|_| matches!(safefs::open_file_at(&dir, INSTALLED), Ok(Some(_))))
        .map(|i| (i.deb_sha256.clone(), i.level != env.sysext_level));
    let save = |f: &Fetched| -> Result<()> {
        let m = Meta {
            url: app.url.clone(),
            fetched: f.clone(),
        };
        safefs::write_at(&dir, META, &serde_json::to_vec(&m)?, 0o600)?;
        Ok(())
    };
    let stamp = || -> Result<()> {
        safefs::write_at(&dir, CHECKED, format!("{}\n", env.now).as_bytes(), 0o600)?;
        Ok(())
    };
    type Picked = (
        &'static str,
        String,
        Option<(String, String)>,
        Option<String>,
    );
    let from_installed =
        |sha: &str, why: String| -> Picked { (INSTALLED, sha.to_string(), None, Some(why)) };
    let (file, sha256, control, note): Picked = match &app.sha256 {
        Some(want) => match have {
            Some(m) if m.fetched.sha256 == *want => (DEB, m.fetched.sha256, None, None),
            _ => match (pinned_download(env, &dir, id, app, want).await, &kept) {
                (Ok((f, c)), _) => {
                    save(&f)?;
                    (DEB, f.sha256, Some(c), None)
                }
                // the pinned package is the installed one: it is still at hand
                (Err(e), Some((sha, _))) if sha == want => from_installed(
                    sha,
                    format!("{e:#}; using the installed copy of the same package"),
                ),
                (Err(e), _) => return Err(e),
            },
        },
        None => {
            let fresh =
                read_secs(&dir, CHECKED).is_some_and(|c| c <= env.now + DAY && env.now - c < DAY);
            match have {
                Some(m) if fresh => (DEB, m.fetched.sha256, None, None),
                have => {
                    let cond = have.as_ref().map(|m| m.fetched.clone());
                    match download_main(env, &dir, id, &app.url, None, cond.as_ref()).await {
                        Ok(None) => {
                            stamp()?;
                            let m = have.ok_or_else(|| anyhow!("304 without a cached package"))?;
                            (DEB, m.fetched.sha256, None, None)
                        }
                        Ok(Some((f, c))) => {
                            save(&f)?;
                            stamp()?;
                            (DEB, f.sha256, Some(c), None)
                        }
                        Err(e) => match (&kept, have) {
                            // a rebuild for a new image: from what was running, not from a package never installed
                            (Some((sha, true)), _) => from_installed(
                                sha,
                                format!(
                                    "checking for a new version failed: {e:#}; rebuilt from the installed package for the new system version"
                                ),
                            ),
                            (_, Some(m)) => (
                                DEB,
                                m.fetched.sha256,
                                None,
                                Some(format!("checking for a new version failed: {e:#}")),
                            ),
                            (Some((sha, false)), None) => from_installed(
                                sha,
                                format!("checking for a new version failed: {e:#}; using the installed package"),
                            ),
                            (None, None) => return Err(e),
                        },
                    }
                }
            }
        }
    };
    let path = app_dir.join(file);
    let (package, version) = match control {
        Some(c) => c,
        None => {
            let p = path.clone();
            blocking(env, move |r| control_of(r, &p)).await?
        }
    };
    Ok(Main {
        path,
        sha256,
        package,
        version,
        note,
    })
}

/// A pinned download, at most once a day for the same `url` and `sha256` after a mismatch (`apps/<id>/pin-failed`): a
/// wrong pin would otherwise download the whole file every round.
async fn pinned_download(
    env: &RoundEnv,
    dir: &OwnedFd,
    id: &str,
    app: &DebApp,
    want: &str,
) -> Result<(Fetched, (String, String))> {
    let failed = safefs::read_at(dir, PIN_FAILED)
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice::<PinFailed>(&b).ok())
        .filter(|p| p.url == app.url && p.want == want);
    if let Some(p) = &failed {
        if p.at <= env.now + DAY && env.now - p.at < DAY {
            bail!(
                "the file at {} did not match sha256 at {} (it was {}); it is downloaded again 24 hours later, or as \
                 soon as url or sha256 changes",
                p.url,
                when(p.at),
                p.got
            );
        }
    }
    match download_main(env, dir, id, &app.url, Some(want), None).await {
        Ok(Some(x)) => {
            let _ = safefs::remove_at(dir, PIN_FAILED);
            Ok(x)
        }
        Ok(None) => bail!("unexpected 304 for {}", app.url),
        Err(e) => {
            if let Some(m) = e.chain().find_map(|c| c.downcast_ref::<ShaMismatch>()) {
                let rec = PinFailed {
                    url: app.url.clone(),
                    want: want.to_string(),
                    got: m.got.clone(),
                    at: env.now,
                };
                safefs::write_at(dir, PIN_FAILED, &serde_json::to_vec(&rec)?, 0o600)?;
                return Err(e.context(
                    "the file does not match the pinned sha256; it is downloaded again 24 hours later, or as soon as url or sha256 changes",
                ));
            }
            Err(e)
        }
    }
}

/// After `id`'s tree built from `m` was merged: `apps/<id>/installed.deb` becomes that package (a hard link, so a later
/// `app.deb` replaces only its own name). Best effort, logged.
pub(super) fn keep_installed(work: &Path, id: &str, m: &Main) {
    if m.path.file_name().and_then(|n| n.to_str()) == Some(INSTALLED) {
        return;
    }
    let r = (|| -> Result<()> {
        let dir = safefs::open_abs_dir(&work.join("apps").join(id), false)?;
        safefs::remove_at(&dir, INSTALLED)?;
        rustix::fs::linkat(&dir, DEB, &dir, INSTALLED, rustix::fs::AtFlags::empty())
            .map_err(std::io::Error::from)
            .context("linking installed.deb")?;
        Ok(())
    })();
    if let Err(e) = r {
        log::warn!("deb-apps: {id}: keeping the installed package: {e:#}");
    }
}

/// IT's icon for `app` (bytes and extension), or why it is not used (the package's icon is used then).
pub(super) async fn icon_for(
    env: &RoundEnv,
    wanted: &Wanted,
    id: &str,
    app: &DebApp,
) -> (Option<(Vec<u8>, &'static str)>, Option<String>) {
    use crate::system::desktop::{icon_problem, read_bundle_file, sniff_icon, MAX_ICON_BYTES};
    let Some(src) = app.icon.as_deref() else {
        return (None, None);
    };
    let bytes: Result<Vec<u8>> = if src.starts_with("files/") {
        match &wanted.bundle_dir {
            None => Err(anyhow!("the applied bundle is not known")),
            Some(b) => read_bundle_file(b, src),
        }
    } else {
        async {
            let dir = safefs::open_abs_dir(&env.paths.work.join("apps").join(id), false)?;
            let cached = safefs::read_at(&dir, ICON_URL)?;
            if cached.as_deref() == Some(src.as_bytes()) {
                if let Some(b) = safefs::read_at(&dir, ICON)? {
                    return Ok(b);
                }
            }
            sysext::download(
                &env.http,
                src,
                None,
                MAX_ICON_BYTES as u64,
                ICON_TIMEOUT,
                &dir,
                ICON,
                None,
            )
            .await?;
            safefs::write_at(&dir, ICON_URL, src.as_bytes(), 0o600)?;
            safefs::read_at(&dir, ICON)?.ok_or_else(|| anyhow!("the icon disappeared"))
        }
        .await
    };
    match bytes {
        Err(e) => (None, Some(format!("icon {src} not used: {e:#}"))),
        Ok(b) => match (icon_problem(&b), sniff_icon(&b)) {
            (None, Some(ext)) => (Some((b, ext)), None),
            (p, _) => (
                None,
                Some(format!(
                    "icon {src} not used: {}",
                    p.unwrap_or_else(|| "not PNG or SVG".into())
                )),
            ),
        },
    }
}

/// What an app tree is built from: changes rebuild it.
pub(super) fn app_key(
    m: &Main,
    app: &DebApp,
    icon: &Option<(Vec<u8>, &'static str)>,
    level: &str,
) -> String {
    let v = serde_json::json!({
        "deb": m.sha256, "name": app.name, "kiosk": app.kiosk, "exec": app.exec,
        "icon": icon.as_ref().map(|(b, _)| sha_hex(b)), "level": level,
    });
    sha_hex(v.to_string().as_bytes())
}

fn archives_debs(archives: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(archives)
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(".deb"))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Keeps only `keep` among the cached dependency packages.
pub(super) fn prune_archives(archives: &Path, keep: &[String]) {
    let Ok(dir) = safefs::open_abs_dir(archives, false) else {
        return;
    };
    for n in archives_debs(archives) {
        if !keep.contains(&n) {
            if let Err(e) = safefs::remove_at(&dir, &n) {
                log::warn!("deb-apps: removing the cached {n}: {e:#}");
            }
        }
    }
}

/// The shared dependencies (file names in `apt/archives`) of `mains`, resolved again only when needed (module docs).
pub(super) async fn dependencies(
    env: &RoundEnv,
    u: &UbuntuSource,
    wanted: &Wanted,
    mains: &BTreeMap<String, Main>,
    st: &mut RoundState,
    notes: &mut Vec<String>,
) -> Result<Vec<String>, String> {
    if mains.is_empty() {
        return Ok(vec![]);
    }
    let apt_dir = env.paths.work.join("apt");
    let archives = apt_dir.join("archives");
    let extra: BTreeSet<String> = mains
        .keys()
        .filter_map(|id| wanted.apps.get(id))
        .flat_map(|a| a.packages.iter().cloned())
        .collect();
    let level = &env.sysext_level;
    let key = sha_hex(
        serde_json::json!({
            "mains": mains.iter().map(|(id, m)| (id, &m.sha256)).collect::<Vec<_>>(),
            "extra": extra, "mirror": wanted.ubuntu_mirror, "level": level,
        })
        .to_string()
        .as_bytes(),
    );
    if let Some(r) = &st.resolved {
        let daily =
            wanted.ubuntu_mirror.is_some() && (env.now - r.at >= DAY || r.at > env.now + DAY);
        if r.key == key && !daily && r.files.iter().all(|f| archives.join(f).is_file()) {
            return Ok(r.files.clone());
        }
    }
    let mut cache_first = st.resolved.as_ref().is_some_and(|r| r.level != *level)
        && !archives_debs(&archives).is_empty();
    if cache_first {
        let a = archives.clone();
        let indexed = blocking(env, move |r| {
            let debs: Result<Vec<_>> = archives_debs(&a)
                .iter()
                .map(|n| apt::cached_deb(r, &a.join(n)))
                .collect();
            apt::write_cache_index(&safefs::open_abs_dir(&a, false)?, &debs?)
        })
        .await;
        if let Err(e) = indexed {
            log::warn!("deb-apps: indexing the dependency cache failed, resolving online: {e:#}");
            cache_first = false;
        }
    }
    let order = apt::source_order(wanted.ubuntu_mirror.as_deref(), u, cache_first);
    let inputs: Vec<PathBuf> = mains.values().map(|m| m.path.clone()).collect();
    let extra: Vec<String> = extra.into_iter().collect();
    match apt::resolve_in_order(&env.runner, &apt_dir, u, &order, &inputs, &extra).await {
        Ok((src, files)) => {
            let mut names: Vec<String> = files
                .iter()
                .filter_map(|f| f.file_name().map(|n| n.to_string_lossy().into_owned()))
                .collect();
            names.sort();
            names.dedup();
            log::info!("deb-apps: {} dependencies from {src}", names.len());
            prune_archives(&archives, &names);
            st.resolved = Some(Resolved {
                key,
                level: level.clone(),
                files: names.clone(),
                at: env.now,
            });
            Ok(names)
        }
        // Only the daily re-check against IT's mirror failed (nothing the apps depend on changed): keep the previous
        // resolution, its packages are all cached; retried next round
        Err(e) => match &st.resolved {
            Some(r) if r.key == key && r.files.iter().all(|f| archives.join(f).is_file()) => {
                log::warn!("deb-apps: the daily dependency check failed, keeping the previous resolution: {e}");
                notes.push(format!(
                    "the daily dependency check against the Ubuntu mirror failed ({e}); keeping the dependencies resolved before"
                ));
                Ok(r.files.clone())
            }
            _ => Err(e.to_string()),
        },
    }
}
