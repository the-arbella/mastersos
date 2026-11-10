//! One `mastersos-agent deb-apps` round end to end: a local HTTP server serves the main packages, a fake runner plays
//! `dpkg-deb` (fake packages are text: a control paragraph, a blank line, then `F <mode> <path> <content>` lines),
//! `apt-get` (prints a plan and "downloads" the dependencies into the cache), `systemctl` and `loginctl`.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
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

fn parse_deb(bytes: &[u8]) -> (String, Vec<(u32, String, String)>) {
    let text = String::from_utf8_lossy(bytes).into_owned();
    let (control, files) = text.split_once("\n\n").unwrap_or((&text, ""));
    let files = files
        .lines()
        .filter_map(|l| {
            let mut it = l.splitn(4, ' ');
            (it.next()? == "F").then_some(())?;
            let mode = u32::from_str_radix(it.next()?, 8).ok()?;
            let p = it.next()?.to_string();
            let body = it.next().unwrap_or("").replace("\\n", "\n");
            Some((mode, p, body))
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
        let wants_x11 = pkgs.contains(&"x11-utils");
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
            if wants_x11 {
                for (n, v, _, _) in DEPS {
                    out.push_str(&format!("Inst {n} ({v} Ubuntu:26.04/resolute [amd64])\n"));
                }
            }
            return Ok(Output::ok(&out));
        }
        if a.contains(&"--download-only") && wants_x11 {
            fs::create_dir_all(&archives).unwrap();
            for (n, v, file, content) in DEPS {
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
                Ok(if self.quiet.load(Ordering::SeqCst) {
                    Output::ok("")
                } else {
                    Output::fail(3, "")
                })
            }
            ("loginctl", _) => Ok(Output::ok(&self.sessions.lock().unwrap())),
            ("dpkg-deb", Some("-x")) => {
                let (_, files) = parse_deb(&fs::read(a[1])?);
                let root = Path::new(a[2]);
                for (mode, p, body) in files {
                    let f = root.join(p);
                    fs::create_dir_all(f.parent().unwrap())?;
                    fs::write(&f, body)?;
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
}

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
        2,
        "same dependencies: nothing swapped"
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
