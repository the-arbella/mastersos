//! The private apt run (spec §4.2, §4.6): real `apt-get`, against the image's factory dpkg status, only to compute and
//! download the packages the image lacks. Nothing is ever installed, and any plan that would upgrade, downgrade or remove
//! a package of the image is refused ([`ResolveError::WouldChangeImage`]).
//!
//! **Isolation.** Every run is `env -i` with `LC_ALL=C` (the output is parsed) and a fixed `PATH`. `APT_CONFIG` points at
//! [`APT_CONF`] in the work directory, which apt reads *before* the system configuration and which turns the system
//! configuration off (`/etc/apt/apt.conf`, `apt.conf.d` with its update hooks, proxies and pins). [`apt_args`] then puts
//! the source list, lists, caches and preferences into the work directory, reads the status from
//! [`FACTORY_STATUS`](super::FACTORY_STATUS) and trusts only the image's Ubuntu keyring (`signed-by=` on every online
//! line, no `trusted.gpg`). The agent runs as root without `CAP_SETUID`, so apt is told not to drop to `_apt`.
//!
//! **Work directory** (`work`, 0700): `apt.conf`, `sources.list`, `lists/`, `cache/` (apt's binary caches),
//! `archives/` (the downloaded dependencies, kept under apt's own file names), `preferences.d/` (empty). `archives/` is
//! also the offline cache source ([`Source::Cache`]): [`write_cache_index`] writes its `Packages`, and apt finds every
//! file already in place there, so an offline run downloads nothing.
//!
//! **Order** ([`source_order`], [`resolve_in_order`]): IT's `ubuntu_mirror` alone; otherwise the build's snapshot and,
//! only when its `apt-get update` fails, the Ubuntu archive. After an image change the cache goes first, and any failure
//! there moves on to the online order.

use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use sha2::{Digest, Sha256};

use super::{ARCHIVE_URL, FACTORY_STATUS, SECURITY_URL, SNAPSHOT_BASE, UBUNTU_KEYRING};
use crate::runner::{last_lines, run_ok, was_cut, Cmd, Output, Runner};
use crate::safefs;

/// The file `APT_CONFIG` names. apt reads `APT_CONFIG` first, then `Dir::Etc::parts` and `Dir::Etc::main`: pointing both
/// at `/dev/null` here skips the whole system configuration (apt special-cases `/dev/null` and does not warn).
pub const APT_CONF: &str = "Dir::Etc::main \"/dev/null\";\nDir::Etc::parts \"/dev/null\";\n";
const PATH_ENV: &str = "PATH=/usr/sbin:/usr/bin:/sbin:/bin";

const UPDATE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const SIMULATE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60 * 60);
/// Lines of apt's stderr kept in an error.
const ERR_LINES: usize = 10;

/// Where the dependencies come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// `snapshot.ubuntu.com` at the build's time stamp: exactly the image's versions.
    Snapshot { stamp: String },
    /// `archive.ubuntu.com` (`-security` from `security.ubuntu.com`).
    Archive,
    /// IT's `ubuntu_mirror`.
    Mirror { url: String },
    /// The dependencies downloaded before (`<work>/archives`), offline.
    Cache,
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::Snapshot { stamp } => write!(f, "the Ubuntu snapshot {stamp}"),
            Source::Archive => f.write_str("the Ubuntu archive"),
            Source::Mirror { url } => write!(f, "the Ubuntu mirror {url}"),
            Source::Cache => f.write_str("the local dependency cache"),
        }
    }
}

/// `/usr/lib/mastersos/ubuntu-source`: what the image was built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UbuntuSource {
    /// `YYYYMMDDTHHMMSSZ`.
    pub snapshot: String,
    pub codename: String,
    pub components: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// `apt-get update` failed for this source (the snapshot then falls back to the archive).
    Update(String),
    /// The plan would change a package of the image. `wanted` is empty for a removal.
    WouldChangeImage {
        package: String,
        image_version: String,
        wanted: String,
    },
    /// Anything else: unresolvable dependencies, a failed download, bad arguments.
    Other(String),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::Update(d) => write!(f, "apt-get update failed: {d}"),
            ResolveError::WouldChangeImage {
                package,
                image_version,
                wanted,
            } if wanted.is_empty() => write!(
                f,
                "the dependencies would remove {package} {image_version} from the image; the image's packages are never changed"
            ),
            ResolveError::WouldChangeImage {
                package,
                image_version,
                wanted,
            } => write!(
                f,
                "a dependency needs {package} {wanted}, the image has {image_version}; the image's packages are never changed"
            ),
            ResolveError::Other(d) => f.write_str(d),
        }
    }
}

impl std::error::Error for ResolveError {}

fn other(e: impl std::fmt::Display) -> ResolveError {
    ResolveError::Other(e.to_string())
}

/// One line of `apt-get -s install`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// `Inst <pkg> (<version> …)`: not in the image, to be downloaded.
    Install { package: String, version: String },
    /// `Inst <pkg> [<image version>] (<version> …)`: an upgrade or downgrade of an image package.
    Change {
        package: String,
        image_version: String,
        wanted: String,
    },
    /// `Remv <pkg> [<image version>]` or `Purg <pkg> [<image version>]`.
    Remove {
        package: String,
        image_version: String,
    },
}

/// Parses `/usr/lib/mastersos/ubuntu-source`: exactly `SNAPSHOT=`, `CODENAME=` and `COMPONENTS=`, once each.
pub fn read_ubuntu_source(text: &str) -> Result<UbuntuSource> {
    let (mut snapshot, mut codename, mut components) = (None, None, None);
    for line in text.lines() {
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("ubuntu-source: malformed line {line:?}"))?;
        let slot = match k {
            "SNAPSHOT" => &mut snapshot,
            "CODENAME" => &mut codename,
            "COMPONENTS" => &mut components,
            _ => bail!("ubuntu-source: unknown key {k:?}"),
        };
        ensure!(slot.is_none(), "ubuntu-source: {k} appears twice");
        *slot = Some(v.to_string());
    }
    let (Some(snapshot), Some(codename), Some(components)) = (snapshot, codename, components)
    else {
        bail!("ubuntu-source: SNAPSHOT, CODENAME and COMPONENTS are all required");
    };
    let b = snapshot.as_bytes();
    ensure!(
        b.len() == 16
            && b[8] == b'T'
            && b[15] == b'Z'
            && b[..8].iter().chain(&b[9..15]).all(u8::is_ascii_digit),
        "ubuntu-source: SNAPSHOT {snapshot:?} is not YYYYMMDDTHHMMSSZ"
    );
    let word = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_lowercase());
    ensure!(
        word(&codename),
        "ubuntu-source: CODENAME {codename:?} is not a release code name"
    );
    let components: Vec<String> = components.split(' ').map(str::to_string).collect();
    ensure!(
        components.iter().all(|c| word(c)),
        "ubuntu-source: malformed COMPONENTS {:?}",
        components.join(" ")
    );
    Ok(UbuntuSource {
        snapshot,
        codename,
        components,
    })
}

/// The `sources.list` for `src`. Online sources carry `<codename>`, `-updates` and `-security`, each signed by the image's
/// Ubuntu keyring; the cache is a flat local repository (`<cache_dir>/Packages`) of files already verified.
pub fn sources_list(src: &Source, u: &UbuntuSource, cache_dir: &Path) -> String {
    let comps = u.components.join(" ");
    let three = |main: &str, security: &str| {
        [("", main), ("-updates", main), ("-security", security)]
            .iter()
            .map(|(suffix, url)| {
                format!(
                    "deb [signed-by={UBUNTU_KEYRING}] {url} {}{suffix} {comps}\n",
                    u.codename
                )
            })
            .collect::<String>()
    };
    match src {
        Source::Snapshot { stamp } => {
            let base = format!("{SNAPSHOT_BASE}/{stamp}");
            three(&base, &base)
        }
        Source::Archive => three(ARCHIVE_URL, SECURITY_URL),
        Source::Mirror { url } => {
            let url = url.trim_end_matches('/');
            three(url, url)
        }
        Source::Cache => format!("deb [trusted=yes] file:{} ./\n", cache_dir.display()),
    }
}

/// The `-o` options of every apt-get run (see the module docs).
pub fn apt_args(work: &Path) -> Vec<String> {
    let w = work.display();
    [
        format!("Dir::State::status={FACTORY_STATUS}"),
        format!("Dir::Etc::sourcelist={w}/sources.list"),
        "Dir::Etc::sourceparts=-".into(),
        "Dir::Etc::trusted=-".into(),
        "Dir::Etc::trustedparts=-".into(),
        format!("Dir::Etc::preferences={w}/preferences"),
        format!("Dir::Etc::preferencesparts={w}/preferences.d"),
        // No credentials of the host's apt (/etc/apt/auth.conf, auth.conf.d) go to any source: both point into the
        // private directory, where nothing writes them.
        format!("Dir::Etc::netrc={w}/auth.conf"),
        format!("Dir::Etc::netrcparts={w}/auth.conf.d"),
        format!("Dir::State::lists={w}/lists"),
        format!("Dir::Cache={w}/cache"),
        format!("Dir::Cache::archives={w}/archives"),
        "Acquire::Languages=none".into(),
        "APT::Install-Recommends=false".into(),
        "APT::Get::AllowUnauthenticated=false".into(),
        "Debug::NoLocking=true".into(),
        // Root without CAP_SETUID (and 0700 private directories): no drop to _apt.
        "APT::Sandbox::User=root".into(),
        // Only amd64 and all (dpkg's foreign architectures are not asked).
        "APT::Architecture=amd64".into(),
        "APT::Architectures=amd64".into(),
        // A source that cannot be fetched is a failure, not a warning with old lists.
        "APT::Update::Error-Mode=any".into(),
    ]
    .into_iter()
    .flat_map(|o| ["-o".to_string(), o])
    .collect()
}

/// `env -i … apt-get <apt_args> <sub>`; the caller appends the package arguments.
pub(crate) fn apt_cmd(work: &Path, sub: &[&str]) -> Cmd {
    let conf = format!("APT_CONFIG={}/apt.conf", work.display());
    let mut args: Vec<String> = ["-i", &conf, "LC_ALL=C", PATH_ENV, "apt-get"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    args.extend(apt_args(work));
    args.extend(sub.iter().map(|s| s.to_string()));
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    Cmd::new("env", &refs)
}

/// One line of the simulation; `None` for lines that are not `Inst` / `Remv` / `Purg` (`Conf`, notes).
pub fn parse_plan_line(line: &str) -> Result<Option<Plan>, ResolveError> {
    let bad = || other(format!("unexpected line in apt's plan: {line:?}"));
    // `pkg:arch` only appears with several architectures; strip it anyway.
    let name = |s: &str| s.split(':').next().unwrap_or(s).to_string();
    // A purge removes an image package (and its configuration) just like Remv: never part of a plan
    if let Some(rest) = line
        .strip_prefix("Remv ")
        .or_else(|| line.strip_prefix("Purg "))
    {
        let mut it = rest.split_whitespace();
        let package = name(it.next().ok_or_else(bad)?);
        let image_version = it
            .next()
            .and_then(|v| v.strip_prefix('['))
            .and_then(|v| v.strip_suffix(']'))
            .unwrap_or_default()
            .to_string();
        return Ok(Some(Plan::Remove {
            package,
            image_version,
        }));
    }
    let Some(rest) = line.strip_prefix("Inst ") else {
        return Ok(None);
    };
    let (pkg, mut rest) = rest.split_once(' ').ok_or_else(bad)?;
    let package = name(pkg);
    let mut image_version = None;
    if let Some(r) = rest.strip_prefix('[') {
        let (old, r) = r.split_once(']').ok_or_else(bad)?;
        image_version = Some(old.to_string());
        rest = r.trim_start();
    }
    let version = rest
        .strip_prefix('(')
        .and_then(|r| r.split_whitespace().next())
        .map(|v| v.trim_end_matches(')'))
        .filter(|v| !v.is_empty())
        .ok_or_else(bad)?
        .to_string();
    Ok(Some(match image_version {
        None => Plan::Install { package, version },
        Some(image_version) => Plan::Change {
            package,
            image_version,
            wanted: version,
        },
    }))
}

/// The packages `apt-get -s install` would install, `(name, version)` in apt's order; the first upgrade, downgrade or
/// removal of an image package is an error.
pub fn parse_simulation(out: &str) -> Result<Vec<(String, String)>, ResolveError> {
    let mut v = vec![];
    for line in out.lines() {
        match parse_plan_line(line)? {
            None => {}
            Some(Plan::Install { package, version }) => v.push((package, version)),
            Some(Plan::Change {
                package,
                image_version,
                wanted,
            }) => {
                return Err(ResolveError::WouldChangeImage {
                    package,
                    image_version,
                    wanted,
                })
            }
            Some(Plan::Remove {
                package,
                image_version,
            }) => {
                return Err(ResolveError::WouldChangeImage {
                    package,
                    image_version,
                    wanted: String::new(),
                })
            }
        }
    }
    Ok(v)
}

/// A .deb in the cache directory, for [`write_cache_index`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedDeb {
    /// The file's name in the cache directory (apt's own name for it).
    pub file_name: String,
    /// Its control paragraph (`dpkg-deb -f <file>`).
    pub control: String,
    pub size: u64,
    /// Lower-case hex.
    pub sha256: String,
}

/// Describes the .deb at `path`: size, sha256 and control paragraph (`dpkg-deb -f`, runs nothing from the package).
pub fn cached_deb(r: &dyn Runner, path: &Path) -> Result<CachedDeb> {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("{}: no file name", path.display()))?
        .to_string();
    let mut f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut h = Sha256::new();
    let mut size = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f
            .read(&mut buf)
            .with_context(|| format!("reading {}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        size += n as u64;
    }
    let p = path.to_string_lossy();
    let control = run_ok(r, Cmd::new("dpkg-deb", &["-f", &p]))?;
    Ok(CachedDeb {
        file_name,
        control,
        size,
        sha256: h.finalize().iter().map(|b| format!("{b:02x}")).collect(),
    })
}

/// Fields of a control paragraph that [`write_cache_index`] writes itself.
const INDEX_FIELDS: [&str; 6] = ["filename", "size", "md5sum", "sha1", "sha256", "sha512"];

/// Writes `Packages` into the cache directory: each control paragraph plus `Filename`, `Size` and `SHA256` (no dpkg-dev).
pub fn write_cache_index(cache: &OwnedFd, debs: &[CachedDeb]) -> Result<()> {
    let mut out = String::new();
    for d in debs {
        let n = &d.file_name;
        ensure!(
            n.ends_with(".deb")
                && !n.starts_with('.')
                && n.bytes().all(|b| b.is_ascii_graphic() && b != b'/'),
            "cache index: malformed file name {n:?}"
        );
        ensure!(
            d.sha256.len() == 64
                && d.sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "cache index: malformed sha256 for {n}"
        );
        let control = d.control.trim_end_matches('\n');
        ensure!(
            control.starts_with("Package: "),
            "cache index: the control of {n} does not start with Package:"
        );
        let mut skipping = false;
        for line in control.lines() {
            ensure!(
                !line.trim().is_empty(),
                "cache index: the control of {n} has an empty line"
            );
            if line.starts_with([' ', '\t']) {
                if !skipping {
                    out.push_str(line);
                    out.push('\n');
                }
                continue;
            }
            let field = line.split(':').next().unwrap_or("").to_ascii_lowercase();
            skipping = INDEX_FIELDS.contains(&field.as_str());
            if !skipping {
                out.push_str(line);
                out.push('\n');
            }
        }
        out.push_str(&format!(
            "Filename: ./{n}\nSize: {}\nSHA256: {}\n\n",
            d.size, d.sha256
        ));
    }
    safefs::write_at(cache, "Packages", out.as_bytes(), 0o644)?;
    Ok(())
}

/// The order of sources (spec §4.2, §4.6): see the module docs.
pub fn source_order(mirror: Option<&str>, u: &UbuntuSource, cache_first: bool) -> Vec<Source> {
    let mut v = if cache_first {
        vec![Source::Cache]
    } else {
        vec![]
    };
    match mirror {
        Some(url) => v.push(Source::Mirror {
            url: url.to_string(),
        }),
        None => v.extend([
            Source::Snapshot {
                stamp: u.snapshot.clone(),
            },
            Source::Archive,
        ]),
    }
    v
}

/// apt's name for a downloaded archive: `QuoteString(_, "_:")` of name, version and architecture.
fn quote(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b == b'_' || b == b':' || b == b'%' || b <= 0x20 || b >= 0x7f {
            o.push_str(&format!("%{b:02x}"));
        } else {
            o.push(b as char);
        }
    }
    o
}

/// Debian package names (`[a-z0-9][a-z0-9+.-]+`), not ending in `-` or `+` (apt reads those as remove / install).
fn package_name_ok(s: &str) -> bool {
    s.len() >= 2
        && s.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"+.-".contains(&b))
        && !s.ends_with(['-', '+'])
}

async fn exec(runner: &Arc<dyn Runner>, cmd: Cmd) -> Result<Output> {
    let r = runner.clone();
    let program = cmd.program.clone();
    tokio::task::spawn_blocking(move || r.run(&cmd))
        .await
        .map_err(|e| anyhow!("{program} exited abnormally: {e}"))?
}

/// Creates the work directory layout (0700) and writes `apt.conf` and `sources.list`.
fn prepare(work: &Path, src: &Source, u: &UbuntuSource) -> Result<()> {
    let w = safefs::open_abs_dir(work, true)?;
    safefs::set_mode(&w, 0o700)?;
    for d in [
        "lists/partial",
        "archives/partial",
        "cache",
        "preferences.d",
    ] {
        let fd = safefs::open_dir_at(&w, Path::new(d), true)?;
        safefs::set_mode(&fd, 0o700)?;
    }
    safefs::write_at(&w, "apt.conf", APT_CONF.as_bytes(), 0o600)?;
    let list = sources_list(src, u, &work.join("archives"));
    safefs::write_at(&w, "sources.list", list.as_bytes(), 0o600)?;
    Ok(())
}

/// Resolves the dependencies of the main packages `inputs` (absolute paths of .deb files) and the Ubuntu packages `extra`
/// from `src`, all in one apt run: writes `sources.list`, `apt-get update`, checks `apt-get -s install`, then
/// `apt-get install --download-only`. Returns the downloaded .deb files in `<work>/archives` (not the main packages).
pub async fn resolve(
    runner: &Arc<dyn Runner>,
    work: &Path,
    u: &UbuntuSource,
    src: &Source,
    inputs: &[PathBuf],
    extra: &[String],
) -> Result<Vec<PathBuf>, ResolveError> {
    let mut pkgs = vec![];
    for p in inputs {
        let s = p
            .to_str()
            .filter(|s| p.is_absolute() && s.ends_with(".deb") && !s.contains(char::is_whitespace))
            .ok_or_else(|| other(format!("not an absolute .deb path: {}", p.display())))?;
        pkgs.push(s.to_string());
    }
    for e in extra {
        if !package_name_ok(e) {
            return Err(other(format!("not a package name: {e:?}")));
        }
        pkgs.push(e.clone());
    }
    if let Source::Mirror { url } = src {
        mastersos_bundle::deb::check_mirror(url).map_err(other)?;
    }
    prepare(work, src, u).map_err(|e| other(format!("preparing {}: {e:#}", work.display())))?;

    let out = exec(runner, apt_cmd(work, &["update"]).timeout(UPDATE_TIMEOUT))
        .await
        .map_err(|e| ResolveError::Update(format!("{src}: {e:#}")))?;
    if out.code != 0
        || out.stderr.contains("Failed to fetch")
        || out.stderr.contains("Some index files failed to download")
    {
        return Err(ResolveError::Update(format!(
            "{src}: exit {}: {}",
            out.code,
            last_lines(&out.stderr, ERR_LINES)
        )));
    }

    let with_pkgs = |sub: &[&str]| {
        let mut c = apt_cmd(work, sub);
        c.args.extend(pkgs.iter().cloned());
        c
    };
    let out = exec(
        runner,
        with_pkgs(&["-s", "install"]).timeout(SIMULATE_TIMEOUT),
    )
    .await
    .map_err(other)?;
    if out.code != 0 {
        return Err(other(format!(
            "apt could not resolve the dependencies from {src}: {}",
            last_lines(&out.stderr, ERR_LINES)
        )));
    }
    if was_cut(&out.stdout) {
        return Err(other("apt's plan is too long to check"));
    }
    let plan = parse_simulation(&out.stdout)?;

    // --no-remove: belt and braces, the plan was checked above with the same state.
    let out = exec(
        runner,
        with_pkgs(&["install", "--download-only", "-y", "--no-remove"]).timeout(DOWNLOAD_TIMEOUT),
    )
    .await
    .map_err(other)?;
    if out.code != 0 {
        return Err(other(format!(
            "downloading the dependencies from {src} failed: {}",
            last_lines(&out.stderr, ERR_LINES)
        )));
    }

    let mut mains = vec![];
    for p in inputs {
        let s = p.to_string_lossy();
        let name = exec(runner, Cmd::new("dpkg-deb", &["-f", &s, "Package"]))
            .await
            .and_then(|o| {
                ensure!(
                    o.code == 0,
                    "dpkg-deb exited with {}: {}",
                    o.code,
                    last_lines(&o.stderr, ERR_LINES)
                );
                Ok(o.stdout.trim().to_string())
            })
            .map_err(|e| {
                other(format!(
                    "reading the package name of {}: {e:#}",
                    p.display()
                ))
            })?;
        mains.push(name);
    }

    let archives = work.join("archives");
    let mut files = vec![];
    for (pkg, ver) in plan.iter().filter(|(p, _)| !mains.contains(p)) {
        let found = ["amd64", "all"]
            .iter()
            .map(|arch| archives.join(format!("{}_{}_{arch}.deb", quote(pkg), quote(ver))))
            .find(|f| f.is_file())
            .ok_or_else(|| {
                other(format!(
                    "apt reported success but {pkg} {ver} is not in {}",
                    archives.display()
                ))
            })?;
        files.push(found);
    }
    Ok(files)
}

/// [`resolve`] over `order` ([`source_order`]): the cache falls through on any failure, the snapshot only when its
/// `apt-get update` fails; everything else is the answer. Returns the source that worked.
pub async fn resolve_in_order(
    runner: &Arc<dyn Runner>,
    work: &Path,
    u: &UbuntuSource,
    order: &[Source],
    inputs: &[PathBuf],
    extra: &[String],
) -> Result<(Source, Vec<PathBuf>), ResolveError> {
    for (i, src) in order.iter().enumerate() {
        let e = match resolve(runner, work, u, src, inputs, extra).await {
            Ok(files) => return Ok((src.clone(), files)),
            Err(e) => e,
        };
        let falls_through = match src {
            Source::Cache => true,
            Source::Snapshot { .. } => matches!(e, ResolveError::Update(_)),
            Source::Archive | Source::Mirror { .. } => false,
        };
        if !falls_through || i + 1 == order.len() {
            return Err(e);
        }
        log::info!("deb-apps: {src}: {e}; trying the next source");
    }
    Err(other("no source to resolve the dependencies from"))
}
