//! One `mastersos-agent deb-apps` round end to end: a local HTTP server serves the main packages, a fake runner plays
//! `dpkg-deb` (fake packages are text: a control paragraph, a blank line, then `F <mode> <path> <content>` lines),
//! `apt-get` (prints a plan and "downloads" the dependencies into the cache), `systemctl` and `loginctl`.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use mastersos_bundle::DebApp;
use sha2::{Digest, Sha256};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::round::*;
use super::status::*;
use crate::jobs::Job;
use crate::runner::{Cmd, FakeRunner, Output, Runner};

const HOUR: i64 = 3600;
const T0: i64 = 1_800_000_000;
const REFRESH: &str = "systemctl reload-or-restart systemd-sysext.service";
const PNG: &[u8] = b"\x89PNG\r\n\x1a\nnot really a picture";

const TESTNAV_DESKTOP: &str = "[Desktop Entry]\nName=TestNav\nExec=/opt/testnav/bin/testnav %u\n\
Icon=/opt/testnav/lib/testnav.png\nType=Application\nMimeType=x-scheme-handler/tnav\n";
const OTHER_DESKTOP: &str =
    "[Desktop Entry]\nName=Other\nExec=/opt/otherapp/bin/otherapp\nType=Application\n";

fn hex(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// A fake .deb (see the module docs). Files below a `bin/` are executable.
fn fake_deb(package: &str, version: &str, files: &[(&str, &str)]) -> Vec<u8> {
    let mut s = format!("Package: {package}\nVersion: {version}\nArchitecture: amd64\n\n");
    for (p, body) in files {
        let mode = if p.contains("/bin/") { "755" } else { "644" };
        s.push_str(&format!("F {mode} {p} {}\n", body.replace('\n', "\\n")));
    }
    s.into_bytes()
}

fn testnav(version: &str) -> Vec<u8> {
    fake_deb(
        "testnav",
        version,
        &[
            ("opt/testnav/bin/testnav", "#!/bin/sh\n"),
            ("opt/testnav/lib/testnav-testnav.desktop", TESTNAV_DESKTOP),
            ("opt/testnav/lib/testnav.png", "png"),
            ("opt/testnav/VERSION", version),
        ],
    )
}

fn otherapp() -> Vec<u8> {
    fake_deb(
        "otherapp",
        "3.0",
        &[
            ("opt/otherapp/bin/otherapp", "#!/bin/sh\n"),
            ("opt/rootstuff/file", "covers the root partition's /opt"),
            ("usr/share/applications/otherapp.desktop", OTHER_DESKTOP),
        ],
    )
}

/// `libfoo1`, asked for by name, is the only package it pulls in.
const FOO: (&str, &str, &str, &str) = (
    "libfoo1",
    "1.0-1",
    "libfoo1_1.0-1_amd64.deb",
    "usr/lib/x86_64-linux-gnu/libfoo.so.1",
);

/// A TestNav that cannot be built: no launcher.
fn broken() -> Vec<u8> {
    fake_deb("testnav", "3.0", &[("opt/testnav/VERSION", "3.0")])
}

/// The Ubuntu packages the fake apt knows: `x11-utils` pulls in `libxxf86dga1`.
const DEPS: &[(&str, &str, &str, &str)] = &[
    (
        "x11-utils",
        "7.7+6",
        "x11-utils_7.7+6_amd64.deb",
        "usr/bin/xprop",
    ),
    (
        "libxxf86dga1",
        "2:1.1.5-1",
        "libxxf86dga1_2%3a1.1.5-1_amd64.deb",
        "usr/lib/x86_64-linux-gnu/libXxf86dga.so.1",
    ),
];

/// The entries of a fake package: `(mode, path, content)`; a directory (`D <mode> <path>` line) has `None` content.
type Entries = Vec<(u32, String, Option<String>)>;

fn parse_deb(bytes: &[u8]) -> (String, Entries) {
    let text = String::from_utf8_lossy(bytes).into_owned();
    let (control, files) = text.split_once("\n\n").unwrap_or((&text, ""));
    let files = files
        .lines()
        .filter_map(|l| {
            if let Some(d) = l.strip_prefix("D ") {
                let (mode, p) = d.split_once(' ')?;
                return Some((u32::from_str_radix(mode, 8).ok()?, p.to_string(), None));
            }
            let mut it = l.splitn(4, ' ');
            (it.next()? == "F").then_some(())?;
            let mode = u32::from_str_radix(it.next()?, 8).ok()?;
            // a space in a path is written %20
            let p = it.next()?.replace("%20", " ");
            let body = it.next().unwrap_or("").replace("\\n", "\n");
            Some((mode, p, Some(body)))
        })
        .collect();
    (format!("{control}\n"), files)
}

fn field(control: &str, key: &str) -> String {
    control
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{key}: ")))
        .unwrap_or_default()
        .to_string()
}

/// The fake system.
#[derive(Default)]
struct World {
    calls: Mutex<Vec<String>>,
    quiet: AtomicBool,
    /// Every online apt source fails (`apt-get update`); the local cache still works.
    offline: AtomicBool,
    /// Replaces the plan apt prints.
    plan: Mutex<Option<String>>,
    sessions: Mutex<String>,
    /// `systemctl is-active` calls so far, and from which one on (1-based; 0: never) the quiet target is active.
    active_calls: AtomicUsize,
    quiet_from: AtomicUsize,
    /// Every `dpkg-deb -x` target, with its mode and its parent's when it ran.
    extracts: Mutex<Vec<(PathBuf, u32, u32)>>,
}

impl World {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn count(&self, needle: &str) -> usize {
        self.calls().iter().filter(|c| c.contains(needle)).count()
    }

    fn apt(&self, a: &[&str]) -> Result<Output> {
        let opt = |k: &str| {
            a.iter()
                .find_map(|x| x.strip_prefix(&format!("{k}=")))
                .map(PathBuf::from)
                .unwrap()
        };
        let archives = opt("Dir::Cache::archives");
        let sources = fs::read_to_string(opt("Dir::Etc::sourcelist")).unwrap_or_default();
        let pkgs: Vec<&str> = a
            .iter()
            .skip_while(|x| !["install", "update"].contains(x))
            .skip(1)
            .filter(|x| !x.starts_with('-'))
            .copied()
            .collect();
        if a.contains(&"update") {
            if self.offline.load(Ordering::SeqCst) && !sources.contains("file:") {
                return Ok(Output::fail(
                    100,
                    "E: Failed to fetch http://archive.example/ 503\n",
                ));
            }
            return Ok(Output::ok(""));
        }
        let mut deps: Vec<(&str, &str, &str, &str)> = vec![];
        if pkgs.contains(&"x11-utils") {
            deps.extend(DEPS.iter().copied());
        }
        if pkgs.contains(&"libfoo1") {
            deps.push(FOO);
        }
        if a.contains(&"-s") {
            if let Some(p) = self.plan.lock().unwrap().clone() {
                return Ok(Output::ok(&p));
            }
            let mut out = String::new();
            for p in pkgs.iter().filter(|p| p.ends_with(".deb")) {
                let (c, _) = parse_deb(&fs::read(p).unwrap());
                out.push_str(&format!(
                    "Inst {} ({} [amd64])\n",
                    field(&c, "Package"),
                    field(&c, "Version")
                ));
            }
            for (n, v, _, _) in &deps {
                out.push_str(&format!("Inst {n} ({v} Ubuntu:26.04/resolute [amd64])\n"));
            }
            return Ok(Output::ok(&out));
        }
        if a.contains(&"--print-uris") {
            // the files still to fetch, 100 MiB each
            let mut out = String::new();
            for (_, _, file, _) in &deps {
                if !archives.join(file).exists() {
                    out.push_str(&format!(
                        "'http://archive.example/pool/{file}' {file} {} SHA512:00\n",
                        100 * 1024 * 1024
                    ));
                }
            }
            return Ok(Output::ok(&out));
        }
        if a.contains(&"--download-only") && !deps.is_empty() {
            fs::create_dir_all(&archives).unwrap();
            for (n, v, file, content) in deps {
                let f = archives.join(file);
                if !f.exists() {
                    fs::write(f, fake_deb(n, v, &[(content, "elf")])).unwrap();
                }
            }
        }
        Ok(Output::ok(""))
    }
}

impl Runner for World {
    fn run(&self, cmd: &Cmd) -> Result<Output> {
        self.calls.lock().unwrap().push(cmd.line());
        let a: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
        match (cmd.program.as_str(), a.first().copied()) {
            ("systemctl", _) if a.contains(&"is-active") => {
                let n = self.active_calls.fetch_add(1, Ordering::SeqCst) + 1;
                let from = self.quiet_from.load(Ordering::SeqCst);
                Ok(
                    if self.quiet.load(Ordering::SeqCst) || (from > 0 && n >= from) {
                        Output::ok("")
                    } else {
                        Output::fail(3, "")
                    },
                )
            }
            ("loginctl", _) => Ok(Output::ok(&self.sessions.lock().unwrap())),
            ("dpkg-deb", Some("-x")) => {
                let (_, files) = parse_deb(&fs::read(a[1])?);
                let root = Path::new(a[2]);
                let mode =
                    |p: &Path| fs::metadata(p).map_or(0, |m| m.permissions().mode() & 0o7777);
                self.extracts.lock().unwrap().push((
                    root.to_path_buf(),
                    mode(root),
                    mode(root.parent().unwrap()),
                ));
                for (mode, p, body) in files {
                    let f = root.join(p);
                    match body {
                        Some(body) => {
                            fs::create_dir_all(f.parent().unwrap())?;
                            fs::write(&f, body)?;
                        }
                        None => fs::create_dir_all(&f)?,
                    }
                    fs::set_permissions(&f, fs::Permissions::from_mode(mode))?;
                }
                Ok(Output::ok(""))
            }
            ("dpkg-deb", Some("-f")) => {
                let (control, _) = parse_deb(&fs::read(a[1])?);
                Ok(Output::ok(&match a.get(2) {
                    Some(k) => format!("{}\n", field(&control, k)),
                    None => control,
                }))
            }
            ("env", _) => self.apt(&a),
            _ => Ok(Output::ok("")),
        }
    }
}

struct Fx {
    tmp: tempfile::TempDir,
    world: Arc<World>,
    srv: MockServer,
    level: Mutex<String>,
    /// What the free-space function answers, and how many times it was asked.
    free: Arc<(AtomicU64, AtomicUsize)>,
}

/// The image's list of `/usr` in the fixture (`mkosi.finalize`'s `usr-paths`): a few dpkg paths plus files no dpkg list
/// has.
const USR_PATHS: &str = "d usr\nd usr/bin\nf usr/bin/mastersos-agent\nf usr/bin/mastersos-kiosk\nf usr/bin/sh\n\
d usr/lib\nd usr/lib/mastersos\nf usr/lib/mastersos/usr-paths\nd usr/lib/python3\nd usr/lib/python3/dist-packages\n\
d usr/share\nd usr/share/doc\n";

impl Fx {
    async fn new() -> Fx {
        let tmp = tempfile::tempdir().unwrap();
        let r = tmp.path();
        for d in [
            "work",
            "ext",
            "public",
            "proc",
            "opt",
            "factory/info",
            "bundle/files",
        ] {
            fs::create_dir_all(r.join(d)).unwrap();
        }
        fs::write(
            r.join("factory/info/base.list"),
            "/.\n/usr\n/usr/bin\n/usr/bin/sh\n/usr/share\n/usr/share/doc\n",
        )
        .unwrap();
        fs::write(r.join("usr-paths"), USR_PATHS).unwrap();
        fs::write(
            r.join("ubuntu-source"),
            "SNAPSHOT=20261101T000000Z\nCODENAME=resolute\nCOMPONENTS=main universe\n",
        )
        .unwrap();
        fs::write(r.join("bundle/files/x.png"), PNG).unwrap();
        let srv = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/testnav.deb"))
            .and(header("If-None-Match", "\"v1\""))
            .respond_with(ResponseTemplate::new(304))
            .with_priority(1)
            .mount(&srv)
            .await;
        for (p, body) in [
            ("/testnav.deb", testnav("1.0")),
            ("/testnav2.deb", testnav("2.0")),
            ("/otherapp.deb", otherapp()),
            ("/broken.deb", broken()),
        ] {
            Mock::given(method("GET"))
                .and(path(p))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("ETag", "\"v1\"")
                        .set_body_bytes(body),
                )
                .mount(&srv)
                .await;
        }
        Fx {
            tmp,
            world: Arc::new(World::default()),
            srv,
            level: Mutex::new("1.0".into()),
            free: Arc::new((AtomicU64::new(u64::MAX), AtomicUsize::new(0))),
        }
    }

    fn root(&self) -> &Path {
        self.tmp.path()
    }

    fn url(&self, name: &str) -> String {
        format!("{}/{name}", self.srv.uri())
    }

    fn paths(&self) -> RoundPaths {
        let r = self.root();
        RoundPaths {
            work: r.join("work"),
            ext_dir: r.join("ext"),
            public_file: r.join("public/deb-apps.json"),
            proc_root: r.join("proc"),
            opt_root: r.join("opt"),
            factory_info: r.join("factory/info"),
            usr_paths: r.join("usr-paths"),
            ubuntu_source: r.join("ubuntu-source"),
        }
    }

    fn env(&self, wanted: &Wanted, now: i64) -> RoundEnv {
        RoundEnv {
            runner: self.world.clone(),
            http: crate::fetch::http_client(crate::fetch::HttpOpts {
                connect: std::time::Duration::from_secs(5),
                read: None,
                total: None,
            }),
            paths: self.paths(),
            now,
            wanted: Some(wanted.clone()),
            sysext_level: self.level.lock().unwrap().clone(),
            free_space: {
                let f = self.free.clone();
                Arc::new(move |_: &Path| {
                    f.1.fetch_add(1, Ordering::SeqCst);
                    Ok(f.0.load(Ordering::SeqCst))
                })
            },
        }
    }

    async fn round_at(&self, wanted: &Wanted, now: i64) -> BTreeMap<String, AppResult> {
        run_once(&self.env(wanted, now))
            .await
            .into_iter()
            .map(|r| (r.id.clone(), r))
            .collect()
    }

    async fn round(&self, wanted: &Wanted) -> BTreeMap<String, AppResult> {
        self.round_at(wanted, T0).await
    }

    async fn requests(&self, p: &str) -> usize {
        self.srv
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|r| r.url.path() == p)
            .count()
    }

    fn ext(&self, rel: &str) -> PathBuf {
        self.root().join("ext").join(rel)
    }

    fn public(&self) -> BTreeMap<String, PublicApp> {
        read_public(&self.paths().public_file)
    }
}

fn app(url: String, sha256: Option<String>) -> DebApp {
    DebApp {
        name: "TestNav".into(),
        url,
        sha256,
        kiosk: false,
        packages: vec![],
        exec: None,
        icon: None,
    }
}

fn wanted(apps: Vec<(&str, DebApp)>) -> Wanted {
    Wanted {
        apps: apps.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        ubuntu_mirror: None,
        bundle_dir: None,
    }
}

fn pinned(fx: &Fx) -> DebApp {
    app(fx.url("testnav.deb"), Some(hex(&testnav("1.0"))))
}

fn ready(r: &BTreeMap<String, AppResult>, id: &str) -> AppResult {
    let a = r
        .get(id)
        .unwrap_or_else(|| panic!("no result for {id}: {r:?}"));
    assert_eq!(a.state, AppState::Ready, "{a:?}");
    a.clone()
}

#[tokio::test]
async fn pinned_sha_downloads_once() {
    let fx = Fx::new().await;
    let w = wanted(vec![("testnav", pinned(&fx))]);
    let a = ready(&fx.round(&w).await, "testnav");
    assert_eq!(a.package.as_deref(), Some("testnav"));
    assert_eq!(a.version.as_deref(), Some("1.0"));
    assert!(fx.ext("app-testnav/opt/testnav/bin/testnav").is_file());
    let desktop = fs::read_to_string(
        fx.ext("app-testnav/usr/share/applications/mastersos-app-testnav.desktop"),
    )
    .unwrap();
    assert!(
        desktop.contains("Exec=/opt/testnav/bin/testnav %U\n"),
        "{desktop}"
    );
    let rel = fs::read_to_string(
        fx.ext("app-testnav/usr/lib/extension-release.d/extension-release.app-testnav"),
    )
    .unwrap();
    assert!(rel.contains("SYSEXT_LEVEL=1.0\n"), "{rel}");
    assert_eq!(fx.world.count(REFRESH), 1);

    ready(&fx.round(&w).await, "testnav");
    assert_eq!(fx.requests("/testnav.deb").await, 1);
    assert_eq!(
        fx.world.count("dpkg-deb -x"),
        1,
        "nothing changed: no rebuild"
    );
    assert_eq!(fx.world.count(REFRESH), 1);

    // the public status: what the kiosk and desktop steps need, nothing more
    let p = fx.public();
    assert_eq!(
        p.get("testnav"),
        Some(&PublicApp {
            state: AppState::Ready,
            exec: Some("/opt/testnav/bin/testnav".into()),
            kiosk: false,
            desktop: "mastersos-app-testnav.desktop".into(),
        })
    );
    let f = fx.paths().public_file;
    assert_eq!(
        fs::metadata(&f).unwrap().permissions().mode() & 0o777,
        0o644
    );
    let text = fs::read_to_string(&f).unwrap();
    assert!(text.contains("\"v\":1"), "{text}");
    assert!(!text.contains("http") && !text.contains("1.0"), "{text}");
}

#[tokio::test]
async fn unpinned_uses_conditional_get() {
    let fx = Fx::new().await;
    let w = wanted(vec![("testnav", app(fx.url("testnav.deb"), None))]);
    ready(&fx.round_at(&w, T0).await, "testnav");
    let built = fx.world.count("dpkg-deb -x");
    ready(&fx.round_at(&w, T0 + 25 * HOUR).await, "testnav");
    let reqs = fx.srv.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 2);
    assert_eq!(
        reqs[1]
            .headers
            .get("If-None-Match")
            .map(|v| v.to_str().unwrap()),
        Some("\"v1\"")
    );
    assert_eq!(fx.world.count("dpkg-deb -x"), built, "304: no reassembly");
    assert_eq!(fx.world.count(REFRESH), 1);
}

#[tokio::test]
async fn unpinned_checked_once_a_day() {
    let fx = Fx::new().await;
    let mut a = app(fx.url("testnav.deb"), None);
    a.packages = vec!["x11-utils".into()];
    let mut w = wanted(vec![("testnav", a)]);
    w.ubuntu_mirror = Some("http://mirror.example.org/ubuntu".into());
    let updates = || fx.world.count(" update");

    ready(&fx.round_at(&w, T0).await, "testnav");
    assert_eq!(fx.requests("/testnav.deb").await, 1);
    assert_eq!(updates(), 1);

    ready(&fx.round_at(&w, T0 + 23 * HOUR).await, "testnav");
    assert_eq!(fx.requests("/testnav.deb").await, 1, "checked 23 hours ago");
    assert_eq!(
        updates(),
        1,
        "the mirror's dependencies follow the same day"
    );

    ready(&fx.round_at(&w, T0 + 25 * HOUR).await, "testnav");
    assert_eq!(fx.requests("/testnav.deb").await, 2, "checked 25 hours ago");
    assert_eq!(updates(), 2);
    assert_eq!(
        fx.world.count(REFRESH),
        1,
        "the dependencies and the app merged as one change, and since then nothing swapped"
    );
}

#[tokio::test]
async fn config_icon_used() {
    let fx = Fx::new().await;
    let mut a = pinned(&fx);
    a.icon = Some("files/x.png".into());
    let mut w = wanted(vec![("testnav", a)]);
    w.bundle_dir = Some(fx.root().join("bundle"));
    ready(&fx.round(&w).await, "testnav");
    let icon = "usr/share/icons/hicolor/256x256/apps/mastersos-app-testnav.png";
    assert_eq!(
        fs::read(fx.ext(&format!("app-testnav/{icon}"))).unwrap(),
        PNG
    );
    let desktop = fs::read_to_string(
        fx.ext("app-testnav/usr/share/applications/mastersos-app-testnav.desktop"),
    )
    .unwrap();
    assert!(desktop.contains(&format!("Icon=/{icon}\n")), "{desktop}");
}

#[tokio::test]
async fn deps_resolved_jointly() {
    let fx = Fx::new().await;
    let mut a = pinned(&fx);
    a.packages = vec!["x11-utils".into()];
    let mut b = app(fx.url("otherapp.deb"), Some(hex(&otherapp())));
    b.name = "Other".into();
    b.packages = vec!["x11-utils".into()];
    let r = fx.round(&wanted(vec![("testnav", a), ("other", b)])).await;
    let t = ready(&r, "testnav");
    ready(&r, "other");
    let sims: Vec<String> = fx
        .world
        .calls()
        .into_iter()
        .filter(|c| c.contains(" -s install"))
        .collect();
    assert_eq!(sims.len(), 1, "{sims:?}");
    assert_eq!(sims[0].matches("x11-utils").count(), 1, "{}", sims[0]);
    assert!(
        sims[0].contains("testnav") && sims[0].contains("other"),
        "{}",
        sims[0]
    );
    assert!(fx.ext("app-deps/usr/bin/xprop").is_file());
    let mut names: Vec<String> = fs::read_dir(fx.root().join("ext"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, vec!["app-deps", "app-other", "app-testnav"]);
    assert!(
        t.deps.contains(&"x11-utils 7.7+6".to_string()),
        "{:?}",
        t.deps
    );
    assert!(
        t.deps.contains(&"libxxf86dga1 2:1.1.5-1".to_string()),
        "{:?}",
        t.deps
    );
}

#[tokio::test]
async fn image_change_rebuilds_from_cache_offline() {
    let fx = Fx::new().await;
    let mut a = pinned(&fx);
    a.packages = vec!["x11-utils".into()];
    let w = wanted(vec![("testnav", a)]);
    ready(&fx.round(&w).await, "testnav");
    let requests = fx.requests("/testnav.deb").await;

    *fx.level.lock().unwrap() = "1.1".into();
    fx.world.offline.store(true, Ordering::SeqCst);
    let before = fx.world.calls().len();
    ready(&fx.round(&w).await, "testnav");
    assert_eq!(fx.requests("/testnav.deb").await, requests);
    let updates: Vec<String> = fx.world.calls()[before..]
        .iter()
        .filter(|c| c.contains(" update"))
        .cloned()
        .collect();
    assert_eq!(
        updates.len(),
        1,
        "the cache first, and it worked: {updates:?}"
    );
    let sources = fs::read_to_string(fx.root().join("work/apt/sources.list")).unwrap();
    assert!(sources.contains("file:"), "{sources}");
    for (ext, name) in [("app-testnav", "app-testnav"), ("app-deps", "app-deps")] {
        let rel = fs::read_to_string(fx.ext(&format!(
            "{ext}/usr/lib/extension-release.d/extension-release.{name}"
        )))
        .unwrap();
        assert!(rel.contains("SYSEXT_LEVEL=1.1\n"), "{ext}: {rel}");
    }
    assert!(fx.ext("app-deps/usr/bin/xprop").is_file());
}

#[tokio::test]
async fn in_use_defers_swap() {
    let fx = Fx::new().await;
    // the first install is not held back by a running program
    let proc_ = fx.root().join("proc/4242");
    fs::create_dir_all(&proc_).unwrap();
    symlink("/opt/testnav/bin/testnav", proc_.join("exe")).unwrap();
    ready(
        &fx.round(&wanted(vec![("testnav", pinned(&fx))])).await,
        "testnav",
    );

    let v2 = app(fx.url("testnav2.deb"), Some(hex(&testnav("2.0"))));
    let w2 = wanted(vec![("testnav", v2)]);
    let r = fx.round(&w2).await;
    let a = &r["testnav"];
    assert_eq!(a.state, AppState::WaitingForClose, "{a:?}");
    assert!(
        a.detail
            .as_deref()
            .unwrap_or("")
            .contains("waiting for the app to close"),
        "{a:?}"
    );
    assert_eq!(
        fs::read_to_string(fx.ext("app-testnav/opt/testnav/VERSION")).unwrap(),
        "1.0"
    );
    assert!(!fx.ext("app-testnav.new").exists());
    assert_eq!(
        fx.public()["testnav"].state,
        AppState::Ready,
        "the old version still runs"
    );

    fs::remove_dir_all(&proc_).unwrap();
    ready(&fx.round(&w2).await, "testnav");
    assert_eq!(
        fs::read_to_string(fx.ext("app-testnav/opt/testnav/VERSION")).unwrap(),
        "2.0"
    );
}

#[tokio::test]
async fn removed_app_uninstalled() {
    let fx = Fx::new().await;
    let mut a = pinned(&fx);
    a.packages = vec!["x11-utils".into()];
    ready(&fx.round(&wanted(vec![("testnav", a)])).await, "testnav");
    assert!(fx.ext("app-testnav").is_dir() && fx.ext("app-deps").is_dir());
    let refreshes = fx.world.count(REFRESH);

    let r = fx.round(&wanted(vec![])).await;
    assert!(r.is_empty(), "{r:?}");
    assert!(!fx.ext("app-testnav").exists());
    assert!(!fx.ext("app-deps").exists());
    assert!(fx.world.count(REFRESH) > refreshes);
    assert!(!fx.root().join("work/apps/testnav").exists());
    assert!(fx.public().is_empty());
    let archives: Vec<_> = fs::read_dir(fx.root().join("work/apt/archives"))
        .map(|d| {
            d.filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().ends_with(".deb"))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        archives.is_empty(),
        "no app left: no cached dependency either"
    );
}

#[tokio::test]
async fn upgrade_conflict_reported() {
    let fx = Fx::new().await;
    *fx.world.plan.lock().unwrap() = Some(
        "Inst testnav (1.0 [amd64])\nInst libc6 [2.41-1] (2.42-1 Ubuntu:26.04/resolute-updates [amd64])\n"
            .into(),
    );
    let r = fx.round(&wanted(vec![("testnav", pinned(&fx))])).await;
    let a = &r["testnav"];
    assert_eq!(a.state, AppState::Failed, "{a:?}");
    let d = a.detail.as_deref().unwrap_or("");
    assert!(
        d.contains("libc6") && d.contains("2.41-1") && d.contains("2.42-1"),
        "{d}"
    );
    assert!(!fx.ext("app-testnav").exists());
    assert!(fx.world.count("--download-only") == 0);
    assert_eq!(fx.public()["testnav"].state, AppState::Failed);
}

#[tokio::test]
async fn quiet_round_does_nothing() {
    let fx = Fx::new().await;
    let first = fx.round(&wanted(vec![("testnav", pinned(&fx))])).await;
    ready(&first, "testnav");
    let public = fs::read(fx.paths().public_file).unwrap();
    let calls = fx.world.calls().len();

    fx.world.quiet.store(true, Ordering::SeqCst);
    let v2 = app(fx.url("testnav2.deb"), Some(hex(&testnav("2.0"))));
    let r = fx
        .round(&wanted(vec![("testnav", v2), ("other", pinned(&fx))]))
        .await;
    assert_eq!(r, first, "results unchanged");
    assert_eq!(fx.requests("/testnav2.deb").await, 0);
    let new_calls: Vec<String> = fx.world.calls()[calls..].to_vec();
    assert!(
        new_calls
            .iter()
            .all(|c| c.starts_with("systemctl is-active")),
        "{new_calls:?}"
    );
    assert_eq!(fs::read(fx.paths().public_file).unwrap(), public);
    assert_eq!(
        fs::read_to_string(fx.ext("app-testnav/opt/testnav/VERSION")).unwrap(),
        "1.0"
    );
}

#[tokio::test]
async fn rebuild_keeps_the_merged_opt_and_drops_the_root_partitions() {
    // /opt as seen by the unit is the root partition's /opt plus every merged extension: a rebuilt app must keep the
    // files its own (merged) extension provides, while a file only the root partition has is still not covered.
    let fx = Fx::new().await;
    ready(
        &fx.round(&wanted(vec![("testnav", pinned(&fx))])).await,
        "testnav",
    );
    let opt = fx.root().join("opt");
    fs::create_dir_all(opt.join("testnav/bin")).unwrap();
    fs::write(opt.join("testnav/bin/testnav"), "merged").unwrap();
    fs::create_dir_all(opt.join("rootstuff")).unwrap();
    fs::write(opt.join("rootstuff/file"), "the root partition's").unwrap();

    let v2 = app(fx.url("testnav2.deb"), Some(hex(&testnav("2.0"))));
    let mut b = app(fx.url("otherapp.deb"), Some(hex(&otherapp())));
    b.name = "Other".into();
    let r = fx.round(&wanted(vec![("testnav", v2), ("other", b)])).await;
    ready(&r, "testnav");
    let o = ready(&r, "other");
    assert!(fx.ext("app-testnav/opt/testnav/bin/testnav").is_file());
    assert_eq!(
        fs::read_to_string(fx.ext("app-testnav/opt/testnav/VERSION")).unwrap(),
        "2.0"
    );
    assert!(!fx.ext("app-other/opt/rootstuff/file").exists());
    assert!(fx.ext("app-other/opt/otherapp/bin/otherapp").is_file());
    assert!(o.pruned >= 1, "{o:?}");
}

#[tokio::test]
async fn overlapping_app_fails_the_later_one() {
    let fx = Fx::new().await;
    // google-chrome is merged too: an app providing one of its paths is refused
    let chrome = fx.ext("google-chrome/opt/testnav/bin");
    fs::create_dir_all(&chrome).unwrap();
    fs::write(chrome.join("testnav"), "chrome's").unwrap();
    let r = fx.round(&wanted(vec![("testnav", pinned(&fx))])).await;
    let a = &r["testnav"];
    assert_eq!(a.state, AppState::Failed, "{a:?}");
    assert!(
        a.detail.as_deref().unwrap_or("").contains("google-chrome"),
        "{a:?}"
    );
    assert!(!fx.ext("app-testnav").exists());
    assert!(!fx.ext("app-testnav.new").exists());
}

#[test]
fn in_use_sees_kiosk_session_and_programs() {
    let tmp = tempfile::tempdir().unwrap();
    let proc_ = tmp.path().join("proc");
    let ext = tmp.path().join("app-testnav");
    fs::create_dir_all(proc_.join("self")).unwrap();
    fs::create_dir_all(ext.join("opt/testnav/bin")).unwrap();
    fs::write(ext.join("opt/testnav/bin/testnav"), "").unwrap();
    let users = vec!["kiosk-testnav".to_string()];
    let row = |user: &str, state: &str| {
        format!(
            r#"[{{"session":"5","uid":61234,"user":"{user}","seat":"seat0","class":"user","state":"{state}"}}]"#
        )
    };
    let exts = vec![ext.clone()];
    assert!(in_use(
        &proc_,
        &exts,
        &users,
        &row("kiosk-testnav", "active")
    ));
    assert!(in_use(
        &proc_,
        &exts,
        &users,
        &row("kiosk-testnav", "online")
    ));
    assert!(!in_use(
        &proc_,
        &exts,
        &users,
        &row("kiosk-testnav", "closing")
    ));
    assert!(!in_use(
        &proc_,
        &exts,
        &users,
        &row("kiosk-other", "active")
    ));
    assert!(!in_use(&proc_, &exts, &users, "[]"));
    // cannot tell whether the account has a session: in use
    assert!(in_use(&proc_, &exts, &users, "not json"));
    assert!(!in_use(&proc_, &exts, &[], "not json"));

    // a process whose program the extension provides
    fs::create_dir_all(proc_.join("77")).unwrap();
    symlink("/usr/bin/sh", proc_.join("77/exe")).unwrap();
    assert!(!in_use(&proc_, &exts, &[], "[]"));
    fs::create_dir_all(proc_.join("78")).unwrap();
    symlink("/opt/testnav/bin/testnav (deleted)", proc_.join("78/exe")).unwrap();
    assert!(in_use(&proc_, &exts, &[], "[]"));
}

#[test]
fn read_public_tolerates_anything() {
    let tmp = tempfile::tempdir().unwrap();
    let f = tmp.path().join("deb-apps.json");
    assert!(read_public(&f).is_empty());
    fs::write(&f, "{").unwrap();
    assert!(read_public(&f).is_empty());
    fs::write(&f, r#"{"v":2,"apps":{}}"#).unwrap();
    assert!(read_public(&f).is_empty());
    fs::write(
        &f,
        r#"{"v":1,"apps":{"testnav":{"state":"ready","exec":"/opt/testnav/bin/testnav","kiosk":true,"desktop":"mastersos-app-testnav.desktop"}}}"#,
    )
    .unwrap();
    let p = read_public(&f);
    assert_eq!(p["testnav"].state, AppState::Ready);
    assert!(p["testnav"].kiosk);
}

#[test]
fn app_state_is_lowercase() {
    assert_eq!(
        serde_json::to_string(&AppState::WaitingForClose).unwrap(),
        "\"waitingforclose\""
    );
    assert_eq!(
        serde_json::to_string(&AppState::Ready).unwrap(),
        "\"ready\""
    );
}

#[tokio::test]
async fn status_reports_items_and_starts_the_unit_on_new_settings() {
    let fx = Fx::new().await;
    let w = wanted(vec![("testnav", pinned(&fx))]);
    ready(&fx.round(&w).await, "testnav");

    let fake = Arc::new(FakeRunner::new());
    let st = DebAppsStatus::with_paths(fake.clone(), fx.root().join("work"));
    let items = st.report();
    let t = items.iter().find(|i| i.item == "deb:testnav").unwrap();
    assert!(t.ok, "{t:?}");
    assert!(t.detail.as_deref().unwrap_or("").contains("1.0"), "{t:?}");
    assert!(
        items.iter().any(|i| i.item == "deb-apps" && i.ok),
        "{items:?}"
    );
    assert!(st.runs_in_quiet());
    assert!(st.wake_on_new_bundle());
    assert_eq!(st.replaces_items(), Some("deb:"));

    // new settings: written for the unit, which is started (not during the exam quiet)
    let start = "systemctl start --no-block mastersos-deb-apps.service";
    let mut w2 = w.clone();
    w2.apps.get_mut("testnav").unwrap().kiosk = true;
    st.offer(w2.clone(), true).await;
    assert_eq!(read_wanted(&fx.root().join("work")), Some(w2.clone()));
    assert!(
        !fake.calls().iter().any(|c| c == start),
        "{:?}",
        fake.calls()
    );
    st.offer(w2.clone(), false).await;
    assert_eq!(fake.calls().iter().filter(|c| *c == start).count(), 1);
    // the same settings again: nothing to start
    st.offer(w2, false).await;
    assert_eq!(fake.calls().iter().filter(|c| *c == start).count(), 1);
}

/// The kiosk and desktop steps read the public status: a round that changes it asks for another apply (Task 7), the
/// same status seen again does not.
#[test]
fn changed_public_status_asks_for_an_apply() {
    let dir = tempfile::tempdir().unwrap();
    let public = dir.path().join("deb-apps.json");
    let st = DebAppsStatus::with_paths(Arc::new(FakeRunner::new()), dir.path().join("work"))
        .with_public(public.clone());
    // nothing yet: no app to show
    assert!(!st.public_changed());
    assert!(!st.public_changed());
    let write = |state: &str| {
        fs::write(
            &public,
            format!(
                r#"{{"v":1,"apps":{{"testnav":{{"state":"{state}","kiosk":true,"desktop":"mastersos-app-testnav.desktop"}}}}}}"#
            ),
        )
        .unwrap()
    };
    write("installing");
    assert!(st.public_changed());
    assert!(!st.public_changed());
    write("ready");
    assert!(st.public_changed());
    assert!(!st.public_changed());
    // a fresh job (agent restart) that finds apps listed applies once more
    let again = DebAppsStatus::with_paths(Arc::new(FakeRunner::new()), dir.path().join("work"))
        .with_public(public);
    assert!(again.public_changed());
}

/// §4.1: the legacy browser mode installs no .deb app — the unit is handed none, so it removes the installed ones —
/// while the desktop mode hands over the Config's.
#[tokio::test]
async fn legacy_browser_wants_no_deb_app() {
    let fx = Fx::new().await;
    let cur = |mode: &str| {
        let mut m = mastersos_bundle::Manifest::parse(&format!(
            "version = 1\n[[group]]\nid = \"a\"\nname = \"a\"\n{mode}"
        ))
        .unwrap();
        let mut config = mastersos_bundle::effective_config(&m, &m.configs[0]);
        config.apps.deb.insert("testnav".into(), pinned(&fx));
        crate::jobs::CurrentGroup {
            version: 1,
            group: m.groups.remove(0),
            config,
            escrow_recipients: vec![],
        }
    };
    let state = fx.root().join("state");
    let desktop = wanted_from(&cur("mode = \"desktop\"\n"), &state);
    assert_eq!(desktop.apps.keys().collect::<Vec<_>>(), ["testnav"]);
    let legacy_cur = cur("");
    assert!(legacy_cur.config.legacy_browser);
    let legacy = wanted_from(&legacy_cur, &state);
    assert!(legacy.apps.is_empty(), "{legacy:?}");

    ready(&fx.round(&desktop).await, "testnav");
    assert!(fx.ext("app-testnav").is_dir());
    let r = fx.round(&legacy).await;
    assert!(r.is_empty(), "{r:?}");
    assert!(!fx.ext("app-testnav").exists());
    assert!(fx.public().is_empty());
}

impl Fx {
    /// The quiet target becomes active from the `k`th `is-active` call on, counting from the next one.
    fn quiet_from_next(&self, k: usize) {
        let n = self.world.active_calls.load(Ordering::SeqCst);
        self.world.quiet_from.store(n + k, Ordering::SeqCst);
    }

    fn report(&self) -> Vec<mastersos_bundle::ItemResult> {
        DebAppsStatus::with_paths(Arc::new(FakeRunner::new()), self.root().join("work")).report()
    }

    fn has_archive(&self, file: &str) -> bool {
        self.root().join("work/apt/archives").join(file).is_file()
    }
}

fn other(fx: &Fx) -> DebApp {
    let mut b = app(fx.url("otherapp.deb"), Some(hex(&otherapp())));
    b.name = "Other".into();
    b
}

fn testnav2(fx: &Fx) -> DebApp {
    app(fx.url("testnav2.deb"), Some(hex(&testnav("2.0"))))
}

fn version(fx: &Fx) -> String {
    fs::read_to_string(fx.ext("app-testnav/opt/testnav/VERSION")).unwrap()
}

fn detail(a: &AppResult) -> &str {
    a.detail.as_deref().unwrap_or("")
}

#[tokio::test]
async fn held_installed_app_keeps_the_shared_dependencies() {
    let fx = Fx::new().await;
    let mut a = pinned(&fx);
    a.packages = vec!["x11-utils".into()];
    let mut b = other(&fx);
    b.packages = vec!["libfoo1".into()];
    let r = fx
        .round(&wanted(vec![("testnav", a.clone()), ("other", b.clone())]))
        .await;
    ready(&r, "testnav");
    ready(&r, "other");
    assert!(fx
        .ext("app-deps/usr/lib/x86_64-linux-gnu/libfoo.so.1")
        .is_file());
    let (sims, extracts, refreshes) = (
        fx.world.count(" -s install"),
        fx.world.count("dpkg-deb -x"),
        fx.world.count(REFRESH),
    );

    // other's package cannot be had this round, and testnav has a new version that would need new dependencies
    b.sha256 = Some(hex(b"something else"));
    let mut a2 = testnav2(&fx);
    a2.packages = a.packages.clone();
    let w = wanted(vec![("testnav", a2), ("other", b)]);
    let r = fx.round(&w).await;
    let o = &r["other"];
    assert_eq!(o.state, AppState::Failed, "{o:?}");
    assert!(detail(o).contains("keeping the installed version"), "{o:?}");
    let t = ready(&r, "testnav");
    assert_eq!(t.version.as_deref(), Some("1.0"));
    assert!(detail(&t).contains("other"), "{t:?}");
    assert_eq!(fx.world.count(" -s install"), sims, "not resolved again");
    assert_eq!(fx.world.count("dpkg-deb -x"), extracts, "nothing built");
    assert_eq!(fx.world.count(REFRESH), refreshes, "nothing swapped");
    assert!(fx
        .ext("app-deps/usr/lib/x86_64-linux-gnu/libfoo.so.1")
        .is_file());
    assert!(fx.ext("app-other/opt/otherapp/bin/otherapp").is_file());
    assert_eq!(version(&fx), "1.0");
    assert!(fx.has_archive(FOO.2), "the cache is not pruned");
    assert_eq!(fx.public()["other"].state, AppState::Ready);
    let deb = fx.report();
    let d = deb.iter().find(|i| i.item == "deb-apps").unwrap();
    assert!(d.detail.as_deref().unwrap_or("").contains("other"), "{d:?}");
}

#[tokio::test]
async fn deps_not_swapped_when_a_changed_app_fails_to_build() {
    let fx = Fx::new().await;
    let mut a = pinned(&fx);
    a.packages = vec!["x11-utils".into()];
    ready(&fx.round(&wanted(vec![("testnav", a)])).await, "testnav");
    let refreshes = fx.world.count(REFRESH);

    // the new version needs libfoo1 too, but cannot be built
    let mut a3 = app(fx.url("broken.deb"), Some(hex(&broken())));
    a3.packages = vec!["x11-utils".into(), "libfoo1".into()];
    let r = fx.round(&wanted(vec![("testnav", a3)])).await;
    let t = &r["testnav"];
    assert_eq!(t.state, AppState::Failed, "{t:?}");
    assert!(
        fx.world.calls().iter().any(|c| c.contains("libfoo1_1.0-1")),
        "the new dependencies were built: {:?}",
        fx.world.calls()
    );
    assert!(!fx
        .ext("app-deps/usr/lib/x86_64-linux-gnu/libfoo.so.1")
        .exists());
    assert!(fx.ext("app-deps/usr/bin/xprop").is_file());
    assert!(!fx.ext("app-deps.new").exists());
    assert_eq!(fx.world.count(REFRESH), refreshes, "nothing swapped");
    assert_eq!(version(&fx), "1.0");
    assert_eq!(fx.public()["testnav"].state, AppState::Ready);
}

#[tokio::test]
async fn failed_daily_mirror_check_keeps_the_previous_resolution() {
    let fx = Fx::new().await;
    let mut a = pinned(&fx);
    a.packages = vec!["x11-utils".into()];
    let mut w = wanted(vec![("testnav", a)]);
    w.ubuntu_mirror = Some("http://mirror.example.org/ubuntu".into());
    ready(&fx.round_at(&w, T0).await, "testnav");
    let refreshes = fx.world.count(REFRESH);

    fx.world.offline.store(true, Ordering::SeqCst);
    let before = fx.world.count(" update");
    let t = ready(&fx.round_at(&w, T0 + 25 * HOUR).await, "testnav");
    assert!(fx.world.count(" update") > before, "the daily check ran");
    assert!(t.deps.contains(&"x11-utils 7.7+6".to_string()), "{t:?}");
    assert!(fx.ext("app-deps/usr/bin/xprop").is_file());
    assert_eq!(fx.world.count(REFRESH), refreshes);
    assert_eq!(fx.public()["testnav"].state, AppState::Ready);
    let items = fx.report();
    let d = items.iter().find(|i| i.item == "deb-apps").unwrap();
    assert!(
        d.detail
            .as_deref()
            .unwrap_or("")
            .contains("daily dependency check"),
        "{d:?}"
    );
}

#[tokio::test]
async fn quiet_starting_during_the_round_stops_merges_and_removals() {
    let fx = Fx::new().await;
    ready(
        &fx.round(&wanted(vec![("testnav", pinned(&fx))])).await,
        "testnav",
    );
    let refreshes = fx.world.count(REFRESH);

    // an update: built, then the quiet starts before the merge
    fx.quiet_from_next(2);
    let r = fx.round(&wanted(vec![("testnav", testnav2(&fx))])).await;
    let t = ready(&r, "testnav");
    assert_eq!(t.version.as_deref(), Some("1.0"));
    assert!(!fx.ext("app-testnav.new").exists());
    assert_eq!(version(&fx), "1.0");
    assert_eq!(fx.world.count(REFRESH), refreshes);

    // a removal: nothing built, the quiet still stops it
    fx.world.quiet_from.store(0, Ordering::SeqCst);
    fx.quiet_from_next(2);
    fx.round(&wanted(vec![])).await;
    assert!(fx.ext("app-testnav/opt/testnav/bin/testnav").is_file());
    assert_eq!(fx.world.count(REFRESH), refreshes);
    assert_eq!(
        fx.public()["testnav"].state,
        AppState::Ready,
        "still merged"
    );

    fx.world.quiet_from.store(0, Ordering::SeqCst);
    fx.round(&wanted(vec![])).await;
    assert!(!fx.ext("app-testnav").exists());
    assert!(fx.world.count(REFRESH) > refreshes);
}

#[tokio::test]
async fn removal_waits_while_in_use() {
    let fx = Fx::new().await;
    ready(
        &fx.round(&wanted(vec![("testnav", pinned(&fx))])).await,
        "testnav",
    );
    let proc_ = fx.root().join("proc/4242");
    fs::create_dir_all(&proc_).unwrap();
    symlink("/opt/testnav/bin/testnav", proc_.join("exe")).unwrap();
    let refreshes = fx.world.count(REFRESH);

    let r = fx.round(&wanted(vec![])).await;
    let t = &r["testnav"];
    assert_eq!(t.state, AppState::WaitingForClose, "{t:?}");
    assert!(fx.ext("app-testnav/opt/testnav/bin/testnav").is_file());
    assert_eq!(fx.world.count(REFRESH), refreshes);
    assert_eq!(
        fx.public()["testnav"].state,
        AppState::Ready,
        "still merged"
    );

    fs::remove_dir_all(&proc_).unwrap();
    let r = fx.round(&wanted(vec![])).await;
    assert!(r.is_empty(), "{r:?}");
    assert!(!fx.ext("app-testnav").exists());
    assert!(fx.public().is_empty());
}

#[tokio::test]
async fn unpacked_in_a_private_stage() {
    let fx = Fx::new().await;
    let mut a = pinned(&fx);
    a.packages = vec!["x11-utils".into()];
    ready(&fx.round(&wanted(vec![("testnav", a)])).await, "testnav");
    let extracts = fx.world.extracts.lock().unwrap().clone();
    assert!(!extracts.is_empty());
    let stage = fx.root().join("work/stage");
    for (target, mode, parent) in &extracts {
        assert!(target.starts_with(&stage), "{target:?}");
        assert_eq!((*mode, *parent), (0o700, 0o700), "{target:?}");
    }
    for t in ["app-testnav", "app-deps"] {
        let m = fs::metadata(fx.ext(t)).unwrap().permissions().mode() & 0o7777;
        assert_eq!(m, 0o755, "{t}");
    }
    assert_eq!(
        fs::read_dir(&stage).unwrap().count(),
        0,
        "nothing left staged"
    );
}

#[test]
fn in_use_from_arguments_when_the_program_is_unreadable() {
    let tmp = tempfile::tempdir().unwrap();
    let proc_ = tmp.path().join("proc");
    let ext = tmp.path().join("app-testnav");
    fs::create_dir_all(ext.join("opt/testnav/bin")).unwrap();
    fs::write(ext.join("opt/testnav/bin/testnav"), "").unwrap();
    let exts = vec![ext];
    let cmdline = |pid: &str, args: &[&str]| {
        let d = proc_.join(pid);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("cmdline"), args.join("\0") + "\0").unwrap();
    };
    // another user's process: no exe link to read
    cmdline("90", &["/usr/bin/python3", "-u", "/usr/lib/other.py"]);
    assert_eq!(in_use_why(&proc_, &exts, &[], "[]"), None);
    cmdline(
        "91",
        &["/usr/bin/python3", "/opt/testnav/bin/testnav", "--x"],
    );
    assert_eq!(
        in_use_why(&proc_, &exts, &[], "[]"),
        Some(Evidence::Argv("/opt/testnav/bin/testnav".into()))
    );
    assert!(in_use(&proc_, &exts, &[], "[]"));
    // only the first two absolute paths count
    fs::remove_dir_all(proc_.join("91")).unwrap();
    cmdline(
        "92",
        &[
            "/usr/bin/env",
            "/usr/bin/python3",
            "/opt/testnav/bin/testnav",
        ],
    );
    assert_eq!(in_use_why(&proc_, &exts, &[], "[]"), None);
    // a readable program link is stronger
    fs::create_dir_all(proc_.join("93")).unwrap();
    symlink("/opt/testnav/bin/testnav", proc_.join("93/exe")).unwrap();
    cmdline("94", &["/opt/testnav/bin/testnav"]);
    assert_eq!(
        in_use_why(&proc_, &exts, &[], "[]"),
        Some(Evidence::Program("/opt/testnav/bin/testnav".into()))
    );
}

#[tokio::test]
async fn argument_evidence_defers_for_a_day_at_most() {
    let fx = Fx::new().await;
    let w1 = wanted(vec![("testnav", pinned(&fx))]);
    ready(&fx.round_at(&w1, T0).await, "testnav");
    let d = fx.root().join("proc/90");
    fs::create_dir_all(&d).unwrap();
    fs::write(
        d.join("cmdline"),
        "/usr/bin/python3\0/opt/testnav/bin/testnav\0",
    )
    .unwrap();

    let w2 = wanted(vec![("testnav", testnav2(&fx))]);
    for at in [T0 + HOUR, T0 + 23 * HOUR, T0 + 24 * HOUR] {
        let r = fx.round_at(&w2, at).await;
        assert_eq!(r["testnav"].state, AppState::WaitingForClose, "at {at}");
        assert_eq!(version(&fx), "1.0");
    }
    // a day after it first held the update back
    let r = fx.round_at(&w2, T0 + 25 * HOUR).await;
    let t = ready(&r, "testnav");
    assert!(detail(&t).contains("24 hours"), "{t:?}");
    assert_eq!(version(&fx), "2.0");
}

#[tokio::test]
async fn argument_deferral_clock_restarts_after_a_round_without_one() {
    let fx = Fx::new().await;
    let w1 = wanted(vec![("testnav", pinned(&fx))]);
    ready(&fx.round_at(&w1, T0).await, "testnav");
    let d = fx.root().join("proc/90");
    fs::create_dir_all(&d).unwrap();
    fs::write(
        d.join("cmdline"),
        "/usr/bin/python3\0/opt/testnav/bin/testnav\0",
    )
    .unwrap();
    let w2 = wanted(vec![("testnav", testnav2(&fx))]);
    let r = fx.round_at(&w2, T0 + HOUR).await;
    assert_eq!(r["testnav"].state, AppState::WaitingForClose);

    // the settings go back: nothing pending, nothing held back on arguments
    ready(&fx.round_at(&w1, T0 + 2 * HOUR).await, "testnav");

    // weeks later the update comes again: it waits a day again, from now
    let later = T0 + 30 * 24 * HOUR;
    let r = fx.round_at(&w2, later).await;
    assert_eq!(r["testnav"].state, AppState::WaitingForClose, "{r:?}");
    let r = fx.round_at(&w2, later + 23 * HOUR).await;
    assert_eq!(r["testnav"].state, AppState::WaitingForClose, "{r:?}");
    assert_eq!(version(&fx), "1.0");
    let t = ready(&fx.round_at(&w2, later + 24 * HOUR).await, "testnav");
    assert!(detail(&t).contains("24 hours"), "{t:?}");
    assert_eq!(version(&fx), "2.0");
}

// ---- final review fixes ----

/// Serves `body` at `p` (replacing what the fixture serves there).
async fn serve(fx: &Fx, p: &str, body: Vec<u8>) {
    Mock::given(method("GET"))
        .and(path(p))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&fx.srv)
        .await;
}

#[tokio::test]
async fn vendor_cannot_cover_image_files_outside_dpkg() {
    let fx = Fx::new().await;
    let evil = fake_deb(
        "python3",
        "1.0",
        &[
            ("opt/evil/bin/evil", "#!/bin/sh\n"),
            ("usr/bin/mastersos-agent", "#!/bin/sh\nrm -rf /\n"),
            (
                "usr/bin/mastersos-kiosk/x",
                "a directory over an image file",
            ),
            ("usr/bin/evil", "#!/bin/sh\n"),
            ("usr/lib/python3/dist-packages/evil.pth", "import os"),
            (
                "usr/share/applications/evil.desktop",
                "[Desktop Entry]\nType=Application\nName=E\nExec=/opt/evil/bin/evil\n",
            ),
        ],
    );
    serve(&fx, "/evil.deb", evil).await;
    let a = app(fx.url("evil.deb"), None);
    let r = fx.round(&wanted(vec![("evil", a)])).await;
    ready(&r, "evil");
    assert!(fx.ext("app-evil/opt/evil/bin/evil").is_file());
    assert!(fx.ext("app-evil/usr/bin/evil").is_file());
    for gone in [
        "usr/bin/mastersos-agent",
        "usr/bin/mastersos-kiosk",
        "usr/lib/python3",
    ] {
        assert!(
            fs::symlink_metadata(fx.ext("app-evil").join(gone)).is_err(),
            "{gone} must not be in the tree"
        );
    }
}

#[tokio::test]
async fn no_list_of_usr_installs_nothing() {
    let fx = Fx::new().await;
    fs::remove_file(fx.root().join("usr-paths")).unwrap();
    let r = fx.round(&wanted(vec![("testnav", pinned(&fx))])).await;
    let t = &r["testnav"];
    assert_eq!(t.state, AppState::Failed, "{t:?}");
    assert!(detail(t).contains("usr-paths"), "{t:?}");
    assert!(!fx.ext("app-testnav").exists());
    assert_eq!(fx.world.count(REFRESH), 0);
}

#[tokio::test]
async fn trees_owned_by_the_agent_without_group_or_other_write() {
    let fx = Fx::new().await;
    // world-writable files and directories, as dpkg-deb -x (as root) would keep them from the archive
    let wide = String::from_utf8(fake_deb(
        "wide",
        "1.0",
        &[
            ("opt/wide/bin/wide", "#!/bin/sh\n"),
            ("opt/wide/data/x", "x"),
            (
                "usr/share/applications/wide.desktop",
                "[Desktop Entry]\nType=Application\nName=W\nExec=/opt/wide/bin/wide\n",
            ),
        ],
    ))
    .unwrap()
    .replace("F 755 ", "F 777 ")
    .replace("F 644 ", "F 666 ")
        + "D 777 opt/wide/data\nD 2777 opt/wide/shared\n";
    serve(&fx, "/wide.deb", wide.into_bytes()).await;
    let mut w = app(fx.url("wide.deb"), None);
    w.name = "Wide".into();
    ready(&fx.round(&wanted(vec![("wide", w)])).await, "wide");
    use std::os::unix::fs::MetadataExt;
    let me = rustix::process::geteuid().as_raw();
    for rel in [
        "",
        "opt",
        "opt/wide",
        "opt/wide/bin/wide",
        "opt/wide/data",
        "opt/wide/data/x",
        "opt/wide/shared",
    ] {
        let m = fs::symlink_metadata(fx.ext("app-wide").join(rel)).unwrap();
        assert_eq!(m.mode() & 0o022, 0, "{rel}: {:o}", m.mode());
        assert_eq!(m.uid(), me, "{rel}");
    }
    let m = fs::metadata(fx.ext("app-wide/opt/wide/bin/wide")).unwrap();
    assert_eq!(m.mode() & 0o7777, 0o755);
}

#[tokio::test]
async fn deps_id_is_refused() {
    let fx = Fx::new().await;
    let r = fx.round(&wanted(vec![("deps", pinned(&fx))])).await;
    let d = &r["deps"];
    assert_eq!(d.state, AppState::Failed, "{d:?}");
    assert!(detail(d).contains("reserved"), "{d:?}");
    assert_eq!(fx.world.count("dpkg-deb -x"), 0);
    assert!(!fx.ext("app-deps").exists());
}

#[tokio::test]
async fn kiosk_program_follows_the_kiosk_rule() {
    let fx = Fx::new().await;
    serve(
        &fx,
        "/spaced.deb",
        fake_deb(
            "spaced",
            "1.0",
            &[
                ("opt/Some%20App/bin/app", "#!/bin/sh\n"),
                (
                    "usr/share/applications/spaced.desktop",
                    "[Desktop Entry]\nType=Application\nName=S\nExec=\"/opt/Some App/bin/app\"\n",
                ),
            ],
        ),
    )
    .await;
    let mut a = app(fx.url("spaced.deb"), None);
    a.kiosk = true;
    let r = fx.round(&wanted(vec![("spaced", a.clone())])).await;
    let s = &r["spaced"];
    assert_eq!(s.state, AppState::Failed, "{s:?}");
    assert!(detail(s).contains("locked app"), "{s:?}");
    assert!(!fx.ext("app-spaced").exists());
    // the same package is fine as an ordinary app
    a.kiosk = false;
    let s = ready(
        &fx.round_at(&wanted(vec![("spaced", a)]), T0 + 1).await,
        "spaced",
    );
    assert!(fx.ext("app-spaced/opt/Some App/bin/app").is_file(), "{s:?}");
}

#[tokio::test]
async fn wrong_pin_is_retried_once_a_day() {
    let fx = Fx::new().await;
    let mut a = pinned(&fx);
    a.sha256 = Some("0".repeat(64));
    let w = wanted(vec![("testnav", a.clone())]);
    let r = fx.round(&w).await;
    assert_eq!(r["testnav"].state, AppState::Failed);
    assert_eq!(fx.requests("/testnav.deb").await, 1);
    let r = fx.round_at(&w, T0 + HOUR).await;
    let t = &r["testnav"];
    assert_eq!(t.state, AppState::Failed);
    assert!(detail(t).contains("24 hours later"), "{t:?}");
    assert!(
        detail(t).contains(&hex(&testnav("1.0"))),
        "it says what came: {t:?}"
    );
    assert_eq!(fx.requests("/testnav.deb").await, 1, "not downloaded again");
    fx.round_at(&w, T0 + 25 * HOUR).await;
    assert_eq!(fx.requests("/testnav.deb").await, 2, "a day later");
    // a corrected pin is tried at once
    let w = wanted(vec![("testnav", pinned(&fx))]);
    ready(&fx.round_at(&w, T0 + 26 * HOUR).await, "testnav");
    assert_eq!(fx.requests("/testnav.deb").await, 3);
    assert!(!fx.root().join("work/apps/testnav/pin-failed").exists());
}

#[tokio::test]
async fn failed_build_of_a_changed_app_waits_a_day() {
    let fx = Fx::new().await;
    let mut a = pinned(&fx);
    a.packages = vec!["x11-utils".into()];
    ready(&fx.round(&wanted(vec![("testnav", a)])).await, "testnav");
    let mut a3 = app(fx.url("broken.deb"), Some(hex(&broken())));
    a3.packages = vec!["x11-utils".into(), "libfoo1".into()];
    let w = wanted(vec![("testnav", a3)]);
    assert_eq!(
        fx.round_at(&w, T0 + HOUR).await["testnav"].state,
        AppState::Failed
    );
    let extracts = fx.world.count("dpkg-deb -x");

    // an hour later: neither the app nor the dependencies resolved for it are built again
    let r = fx.round_at(&w, T0 + 2 * HOUR).await;
    let t = &r["testnav"];
    assert_eq!(t.state, AppState::Failed, "{t:?}");
    assert!(detail(t).contains("24 hours later"), "{t:?}");
    assert!(detail(t).contains("keeping the installed version"), "{t:?}");
    assert_eq!(fx.world.count("dpkg-deb -x"), extracts, "nothing built");
    assert!(!fx.ext("app-deps.new").exists());
    assert_eq!(version(&fx), "1.0");
    assert_eq!(fx.public()["testnav"].state, AppState::Ready);

    // a day later it is tried again
    fx.round_at(&w, T0 + 26 * HOUR).await;
    assert!(fx.world.count("dpkg-deb -x") > extracts);
}

#[tokio::test]
async fn no_free_space_refuses_download_and_unpack() {
    let fx = Fx::new().await;
    let w = wanted(vec![("testnav", pinned(&fx))]);
    fx.free.0.store(1024 * 1024 * 1024, Ordering::SeqCst);
    let r = fx.round(&w).await;
    let t = &r["testnav"];
    assert_eq!(t.state, AppState::Failed, "{t:?}");
    assert!(
        detail(t).contains("not enough free disk space for downloading"),
        "{t:?}"
    );
    assert!(!fx.root().join("work/apps/testnav/app.deb").exists());
    assert_eq!(fx.world.count("dpkg-deb -x"), 0);

    // enough for the download (asked for the work directory and the extensions), not for the unpack after it
    fx.free.0.store(u64::MAX, Ordering::SeqCst);
    let asked = fx.free.1.load(Ordering::SeqCst);
    let free = fx.free.clone();
    let mut env = fx.env(&w, T0 + 1);
    env.free_space = Arc::new(move |_: &Path| {
        let n = free.1.fetch_add(1, Ordering::SeqCst);
        Ok(if n < asked + 2 { u64::MAX } else { 0 })
    });
    let r: BTreeMap<String, AppResult> = run_once(&env)
        .await
        .into_iter()
        .map(|r| (r.id.clone(), r))
        .collect();
    let t = &r["testnav"];
    assert_eq!(t.state, AppState::Failed, "{t:?}");
    assert!(
        detail(t).contains("not enough free disk space for unpacking"),
        "{t:?}"
    );
    assert!(fx.root().join("work/apps/testnav/app.deb").is_file());
    assert_eq!(fx.world.count("dpkg-deb -x"), 0);
    assert!(!fx.ext("app-testnav").exists());

    // space again: built at once (a lack of space is not a failed build that waits a day)
    ready(&fx.round_at(&w, T0 + 2).await, "testnav");
}

#[tokio::test]
async fn bad_download_keeps_the_good_package() {
    let fx = Fx::new().await;
    let w = wanted(vec![("testnav", app(fx.url("testnav.deb"), None))]);
    ready(&fx.round(&w).await, "testnav");
    let deb = fx.root().join("work/apps/testnav/app.deb");
    assert_eq!(fs::read(&deb).unwrap(), testnav("1.0"));
    assert_eq!(
        fs::read(fx.root().join("work/apps/testnav/installed.deb")).unwrap(),
        testnav("1.0")
    );

    // a day later the link serves an HTML error page with 200
    fx.srv.reset().await;
    serve(
        &fx,
        "/testnav.deb",
        b"<html><body>Service unavailable</body></html>".to_vec(),
    )
    .await;
    let t = ready(&fx.round_at(&w, T0 + 25 * HOUR).await, "testnav");
    assert_eq!(t.version.as_deref(), Some("1.0"));
    assert!(
        detail(&t).contains("checking for a new version failed"),
        "{t:?}"
    );
    assert_eq!(
        fs::read(&deb).unwrap(),
        testnav("1.0"),
        "the good file stays"
    );
    assert!(!fx.root().join("work/apps/testnav/app.deb.new").exists());
    assert_eq!(version(&fx), "1.0");

    // a package for another architecture is refused the same way
    fx.srv.reset().await;
    let arm = String::from_utf8(testnav("2.0"))
        .unwrap()
        .replace("Architecture: amd64", "Architecture: arm64");
    serve(&fx, "/testnav.deb", arm.into_bytes()).await;
    let t = ready(&fx.round_at(&w, T0 + 50 * HOUR).await, "testnav");
    assert!(detail(&t).contains("arm64"), "{t:?}");
    assert_eq!(fs::read(&deb).unwrap(), testnav("1.0"));
}

#[tokio::test]
async fn image_change_rebuilds_from_the_installed_package() {
    let fx = Fx::new().await;
    let w = wanted(vec![("testnav", app(fx.url("testnav.deb"), None))]);
    ready(&fx.round(&w).await, "testnav");

    // a new version arrives that cannot be built: the installed one stays
    fx.srv.reset().await;
    serve(&fx, "/testnav.deb", broken()).await;
    let r = fx.round_at(&w, T0 + 25 * HOUR).await;
    assert_eq!(r["testnav"].state, AppState::Failed);
    assert_eq!(
        fs::read(fx.root().join("work/apps/testnav/app.deb")).unwrap(),
        broken()
    );

    // a system update while the link cannot be reached: rebuilt from what was installed, not from app.deb
    fx.srv.reset().await;
    *fx.level.lock().unwrap() = "2.0".into();
    let t = ready(&fx.round_at(&w, T0 + 50 * HOUR).await, "testnav");
    assert_eq!(t.version.as_deref(), Some("1.0"));
    assert!(detail(&t).contains("installed package"), "{t:?}");
    let rel = fs::read_to_string(
        fx.ext("app-testnav/usr/lib/extension-release.d/extension-release.app-testnav"),
    )
    .unwrap();
    assert!(rel.contains("SYSEXT_LEVEL=2.0\n"), "{rel}");
    assert_eq!(version(&fx), "1.0");
}

/// Serves `body` once per connection over plain HTTP/1.1 without a `Content-Length` (the body ends when the connection
/// closes); returns the URL.
async fn serve_without_length(body: Vec<u8>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let body = body.clone();
            tokio::spawn(async move {
                let mut req = vec![0u8; 4096];
                let _ = s.read(&mut req).await;
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/octet-stream\r\n\r\n")
                    .await;
                let _ = s.write_all(&body).await;
                let _ = s.shutdown().await;
            });
        }
    });
    format!("http://{addr}/testnav.deb")
}

#[tokio::test]
async fn download_without_length_needs_space_for_the_largest_package() {
    // No Content-Length: the size is not known before the download, so the check assumes the largest allowed package
    // (2 GiB): 3 × 2 GiB + 1 GiB kept free. 2 GiB free is not enough.
    let fx = Fx::new().await;
    let url = serve_without_length(testnav("1.0")).await;
    let w = wanted(vec![("testnav", app(url, None))]);
    fx.free.0.store(2 * 1024 * 1024 * 1024, Ordering::SeqCst);
    let r = fx.round(&w).await;
    let t = &r["testnav"];
    assert_eq!(t.state, AppState::Failed, "{t:?}");
    assert!(
        detail(t).contains("not enough free disk space for downloading"),
        "{t:?}"
    );
    assert!(!fx.root().join("work/apps/testnav/app.deb").exists());

    // with the space for it the same server works
    fx.free.0.store(u64::MAX, Ordering::SeqCst);
    let t = ready(&fx.round_at(&w, T0 + 1).await, "testnav");
    assert_eq!(t.version.as_deref(), Some("1.0"));
}

#[tokio::test]
async fn image_change_within_the_day_rebuilds_from_the_installed_package() {
    let fx = Fx::new().await;
    let w = wanted(vec![("testnav", app(fx.url("testnav.deb"), None))]);
    ready(&fx.round(&w).await, "testnav");

    // a new version arrives that cannot be built: the installed one stays
    fx.srv.reset().await;
    serve(&fx, "/testnav.deb", broken()).await;
    let r = fx.round_at(&w, T0 + 25 * HOUR).await;
    assert_eq!(r["testnav"].state, AppState::Failed);

    // an hour later (the link was checked less than a day ago) a system update while the link cannot be reached: the
    // tree is rebuilt from what was installed, not from the cached app.deb that failed to build
    fx.srv.reset().await;
    *fx.level.lock().unwrap() = "2.0".into();
    let t = ready(&fx.round_at(&w, T0 + 26 * HOUR).await, "testnav");
    assert_eq!(t.version.as_deref(), Some("1.0"));
    assert!(detail(&t).contains("installed package"), "{t:?}");
    let rel = fs::read_to_string(
        fx.ext("app-testnav/usr/lib/extension-release.d/extension-release.app-testnav"),
    )
    .unwrap();
    assert!(rel.contains("SYSEXT_LEVEL=2.0\n"), "{rel}");
    assert_eq!(version(&fx), "1.0");
    assert_eq!(
        fs::read(fx.root().join("work/apps/testnav/app.deb")).unwrap(),
        broken(),
        "the newer package stays as a pending update"
    );

    // afterwards the newer package is an ordinary pending update: tried at the new level, the installed tree stays
    let r = fx.round_at(&w, T0 + 27 * HOUR).await;
    assert_eq!(r["testnav"].state, AppState::Failed, "{:?}", r["testnav"]);
    assert_eq!(version(&fx), "1.0");
    assert_eq!(fx.public()["testnav"].state, AppState::Ready);
}

#[tokio::test]
async fn no_free_space_refuses_the_dependency_download() {
    // Enough for the main package and its unpack, not for 2 × the dependencies apt would fetch plus 1 GiB kept free
    let fx = Fx::new().await;
    let mut a = pinned(&fx);
    a.packages = vec!["x11-utils".into()];
    let w = wanted(vec![("testnav", a)]);
    fx.free
        .0
        .store(1024 * 1024 * 1024 + 1024 * 1024, Ordering::SeqCst);
    let r = fx.round(&w).await;
    let t = &r["testnav"];
    assert_eq!(t.state, AppState::Failed, "{t:?}");
    assert!(
        detail(t).contains("not enough free disk space for downloading the dependencies"),
        "{t:?}"
    );
    assert_eq!(
        fx.world.count("--download-only"),
        0,
        "{:?}",
        fx.world.calls()
    );
    assert!(fx.root().join("work/apps/testnav/app.deb").is_file());

    // space again: resolved, downloaded and built at once
    fx.free.0.store(u64::MAX, Ordering::SeqCst);
    ready(&fx.round_at(&w, T0 + 1).await, "testnav");
    assert_eq!(fx.world.count("--download-only"), 1);
}
