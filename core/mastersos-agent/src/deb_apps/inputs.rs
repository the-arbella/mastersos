//! The inputs of a round: the main packages ([`fetch`], with IT's icon, [`icon_for`]) and the shared dependencies
//! ([`dependencies`]). See [`super::round`] for the work directory and when each is fetched or resolved again.

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use mastersos_bundle::DebApp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::apt::{self, UbuntuSource};
use super::round::{blocking, Resolved, RoundEnv, RoundState, DAY};
use super::status::Wanted;
use crate::apply::hex;
use crate::runner::{Cmd, Runner};
use crate::safefs;
use crate::sysext::{self, FetchOutcome, Fetched};

/// Spec §4.4.
const MAX_DEB_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const DEB_TIMEOUT: Duration = Duration::from_secs(90 * 60);
const ICON_TIMEOUT: Duration = Duration::from_secs(60);
const DEB: &str = "app.deb";
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

/// A main package's `Package` and `Version` (`dpkg-deb -f`, runs nothing from it).
fn control_of(r: &dyn Runner, deb: &Path) -> Result<(String, String)> {
    let c = crate::runner::run_ok(r, Cmd::new("dpkg-deb", &["-f", &deb.to_string_lossy()]))?;
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
    Ok((get("Package")?, get("Version")?))
}

/// The main package of `id` in `apps/<id>/app.deb` (see the module docs).
pub(super) async fn fetch(env: &RoundEnv, work: &OwnedFd, id: &str, app: &DebApp) -> Result<Main> {
    let apps = safefs::open_dir_at(work, Path::new("apps"), true)?;
    safefs::set_mode(&apps, 0o700)?;
    let dir = safefs::open_dir_at(&apps, Path::new(id), true)?;
    safefs::set_mode(&dir, 0o700)?;
    let have = safefs::read_at(&dir, META)
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice::<Meta>(&b).ok())
        .filter(|m| m.url == app.url)
        .filter(|_| matches!(safefs::open_file_at(&dir, DEB), Ok(Some(_))));
    let get = |cond: Option<Fetched>, want: Option<String>| {
        let (http, url) = (env.http.clone(), app.url.clone());
        let d = dir.try_clone();
        async move {
            let d = d.context("duplicating the app directory fd")?;
            sysext::download(
                &http,
                &url,
                want.as_deref(),
                MAX_DEB_BYTES,
                DEB_TIMEOUT,
                &d,
                DEB,
                cond.as_ref(),
            )
            .await
            .with_context(|| format!("downloading {url}"))
        }
    };
    let save = |f: &Fetched| -> Result<()> {
        let m = Meta {
            url: app.url.clone(),
            fetched: f.clone(),
        };
        safefs::write_at(&dir, META, &serde_json::to_vec(&m)?, 0o600)?;
        Ok(())
    };
    let mut note = None;
    let fetched = match &app.sha256 {
        Some(want) => match have {
            Some(m) if m.fetched.sha256 == *want => m.fetched,
            _ => match get(None, Some(want.clone())).await? {
                FetchOutcome::Fetched(f) => {
                    save(&f)?;
                    f
                }
                FetchOutcome::NotModified => bail!("unexpected 304 for {}", app.url),
            },
        },
        None => {
            let fresh =
                read_secs(&dir, CHECKED).is_some_and(|c| c <= env.now + DAY && env.now - c < DAY);
            match have {
                Some(m) if fresh => m.fetched,
                have => match get(have.as_ref().map(|m| m.fetched.clone()), None).await {
                    Ok(FetchOutcome::NotModified) => {
                        safefs::write_at(
                            &dir,
                            CHECKED,
                            format!("{}\n", env.now).as_bytes(),
                            0o600,
                        )?;
                        have.ok_or_else(|| anyhow!("304 without a cached package"))?
                            .fetched
                    }
                    Ok(FetchOutcome::Fetched(f)) => {
                        save(&f)?;
                        safefs::write_at(
                            &dir,
                            CHECKED,
                            format!("{}\n", env.now).as_bytes(),
                            0o600,
                        )?;
                        f
                    }
                    Err(e) => match have {
                        Some(m) => {
                            note = Some(format!("checking for a new version failed: {e:#}"));
                            m.fetched
                        }
                        None => return Err(e),
                    },
                },
            }
        }
    };
    let path = env.paths.work.join("apps").join(id).join(DEB);
    let p = path.clone();
    let (package, version) = blocking(env, move |r| control_of(r, &p)).await?;
    Ok(Main {
        path,
        sha256: fetched.sha256,
        package,
        version,
        note,
    })
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
