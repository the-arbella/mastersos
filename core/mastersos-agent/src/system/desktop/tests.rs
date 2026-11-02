use super::super::exec_block::tests::{image_root, is_stub, MountSim};
use super::super::tests::{config_of, group, paths, Kind};
use super::*;
use crate::runner::Output;
use mastersos_bundle::School;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

fn app(name: &str, url: &str, icon: Option<&str>) -> WebApp {
    WebApp {
        name: name.into(),
        url: url.into(),
        icon: icon.map(String::from),
    }
}

fn grp(kind: Kind, web: Vec<WebApp>) -> Config {
    let mut g = config_of(kind);
    g.apps.web = web;
    g
}

/// Switches `g` to `kind`, keeping its apps.
fn set_kind(g: &mut Config, kind: Kind) {
    let c = config_of(kind);
    g.interface = c.interface;
    g.legacy_browser = c.legacy_browser;
}

/// 临时根：镜像里的桩与几个可执行文件（见 `exec_block::tests::image_root`），加上几个 `.desktop`。
fn root() -> tempfile::TempDir {
    let root = image_root();
    let apps = root.path().join("usr/share/applications");
    fs::create_dir_all(&apps).unwrap();
    let entry = |name: &str, extra: &str| {
        fs::write(
            apps.join(name),
            format!("[Desktop Entry]\nType=Application\nName={name}\nExec=x\n{extra}"),
        )
        .unwrap();
    };
    entry("google-chrome.desktop", "");
    entry("org.gnome.Nautilus.desktop", "");
    entry("org.gnome.Terminal.desktop", "");
    entry("org.gnome.Settings.desktop", "");
    entry("org.gnome.Shell.desktop", "NoDisplay=true\n");
    entry("old.desktop", "Hidden=true\n");
    entry(
        "gnome-wifi-panel.desktop",
        "[Desktop Action x]\nName=y\n\n[Desktop Entry]\nNoDisplay=true\n",
    );
    fs::write(apps.join("mimeinfo.cache"), "x").unwrap();
    // 系统 Flatpak：导出目录里是指向 app 目录的链接。
    let fp = root.path().join("var/lib/flatpak");
    let real = fp.join("app/org.gnome.Calculator/export/org.gnome.Calculator.desktop");
    fs::create_dir_all(real.parent().unwrap()).unwrap();
    fs::write(&real, "[Desktop Entry]\nType=Application\nName=Calc\n").unwrap();
    let exp = fp.join("exports/share/applications");
    fs::create_dir_all(&exp).unwrap();
    std::os::unix::fs::symlink(&real, exp.join("org.gnome.Calculator.desktop")).unwrap();
    root
}

struct Run {
    out: Vec<ItemResult>,
}

/// 跑一次 `desktop` 步骤。`bundle` 是包目录（图标的 `files/…` 从这里读）。
fn run_step(
    root: &Path,
    r: &MountSim,
    sys: &mut SysState,
    g: &Config,
    bundle: &Path,
    phase: Phase,
) -> Run {
    run_step_with(root, r, sys, g, bundle, phase, false)
}

/// 同 [`run_step`]，`superseded` 一开始就是给定的值（有更新的应用请求）。
fn run_step_with(
    root: &Path,
    r: &MountSim,
    sys: &mut SysState,
    g: &Config,
    bundle: &Path,
    phase: Phase,
    superseded: bool,
) -> Run {
    let school = School::default();
    let flag = AtomicBool::new(superseded);
    let ctx = ApplyContext {
        seed: &crate::system::tests::test_seed(),
        school: &school,
        group: &group(),
        config: g,
        lock: None,
        bundle_dir: bundle,
        phase,
        superseded: &flag,
    };
    let p = paths(root);
    let mut env = Env {
        paths: &p,
        runner: r,
        sys,
    };
    Run {
        out: run(&ctx, &mut env),
    }
}

fn xdg(root: &Path) -> PathBuf {
    root.join("var/lib/mastersos-public/xdg")
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect(),
        Err(_) => vec![],
    };
    v.sort();
    v
}

fn item<'a>(out: &'a [ItemResult], name: &str) -> &'a ItemResult {
    out.iter()
        .find(|r| r.item == name)
        .unwrap_or_else(|| panic!("没有回报项 {name}：{out:?}"))
}

fn launcher(root: &Path, url: &str) -> String {
    fs::read_to_string(xdg(root).join("applications").join(webapp_file(url))).unwrap()
}

fn icon_line(text: &str) -> &str {
    text.lines()
        .find_map(|l| l.strip_prefix("Icon="))
        .expect("没有 Icon=")
}

#[test]
fn browser_mode_locks_and_favorites() {
    let g = grp(Kind::LegacyBrowser, vec![]);
    let web = vec!["mastersos-web-aaaaaaaaaaaa.desktop".to_string()];
    let (k, locks) = render_dconf(&g, &web, &[], &["org.example.Flat".into()]);
    assert!(
        k.contains(
            "[org/gnome/shell]\nfavorite-apps=['google-chrome.desktop', 'mastersos-web-aaaaaaaaaaaa.desktop']\n"
        ),
        "{k}"
    );
    assert!(
        !k.contains("Nautilus") && !k.contains("org.example.Flat"),
        "{k}"
    );
    for want in [
        "[org/gnome/desktop/screensaver]\nlock-enabled=true\n",
        "[org/gnome/desktop/lockdown]\ndisable-command-line=true\nuser-administration-disabled=true\n",
        "[org/gnome/settings-daemon/plugins/media-keys]\nterminal=['']\n",
        // Ubuntu 的桌面图标扩展（DING）自己就能在 ~/Desktop 上建、删、改名文件、「在终端中打开」，还一直拉
        // Nautilus；Dock 的回收站与外接盘也是打开文件管理器（VM 上实测）
        "disabled-extensions=['ding@rastersoft.com']\n",
        // 复审 T13 发现 5：用户自己装、自己开的扩展与自定义快捷键都关掉、锁住；Ubuntu 会话自带的（去掉 DING）照开
        "disable-user-extensions=true\n",
        "allow-extension-installation=false\n",
        "enabled-extensions=['ubuntu-dock@ubuntu.com', 'ubuntu-appindicators@ubuntu.com', \
         'tiling-assistant@ubuntu.com', 'snapd-prompting@canonical.com', \
         'snapd-search-provider@canonical.com', 'web-search-provider@ubuntu.com', \
         'mastersos-managed@mastersos.org']\n",
        "custom-keybindings=@as []\n",
        "always-center-icons=true\ndock-fixed=true\ndash-max-icon-size=44\nshow-trash=false\nshow-mounts=false\n",
    ] {
        assert!(k.contains(want), "缺 {want:?}：\n{k}");
    }
    let keys: BTreeSet<&str> = locks
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "/org/gnome/shell/favorite-apps",
            "/org/gnome/desktop/lockdown/disable-command-line",
            "/org/gnome/desktop/lockdown/user-administration-disabled",
            "/org/gnome/settings-daemon/plugins/media-keys/terminal",
            "/org/gnome/shell/disabled-extensions",
            "/org/gnome/shell/extensions/dash-to-dock/show-trash",
            "/org/gnome/shell/extensions/dash-to-dock/show-mounts",
            "/org/gnome/shell/disable-user-extensions",
            "/org/gnome/shell/enabled-extensions",
            "/org/gnome/shell/allow-extension-installation",
            "/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings",
        ])
    );
}

#[test]
fn desktop_mode_has_no_locks() {
    let g = grp(Kind::Full, vec![]);
    let web = vec!["mastersos-web-aaaaaaaaaaaa.desktop".to_string()];
    let (k, locks) = render_dconf(&g, &web, &[], &["org.example.Flat".into()]);
    assert_eq!(locks, "");
    assert!(
        k.contains(
            "favorite-apps=['google-chrome.desktop', 'mastersos-web-aaaaaaaaaaaa.desktop', \
             'org.gnome.Nautilus.desktop', 'org.example.Flat.desktop']\n"
        ),
        "{k}"
    );
    assert!(k.contains("lock-enabled=true"));
    assert!(k.contains("dock-position='BOTTOM'"), "{k}");
    assert!(
        !k.contains("lockdown")
            && !k.contains("media-keys")
            && !k.contains("disabled-extensions")
            && !k.contains("show-trash")
            && !k.contains("extensions=")
            && !k.contains("custom-keybindings"),
        "{k}"
    );
}

/// Review Focus 1、Ruling 15：用 GLib 读回。
#[cfg(target_os = "linux")]
#[test]
fn webapp_name_and_url_escaping() {
    let name = "ห้องเรียน \"A\"; 1";
    let url = "https://x.th/a?b=1%20c&d=$HOME\\x";
    for (n, u) in [
        (name, url),
        (" leading\tspace\\", "https://x.th/`echo hi` \"q\" 50%"),
    ] {
        let (file, text) = render_webapp(&app(n, u, None), None);
        let stem = file
            .strip_prefix(WEB_PREFIX)
            .and_then(|s| s.strip_suffix(".desktop"))
            .unwrap();
        assert!(
            stem.len() == 12 && stem.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "{file}"
        );
        let kf = glib::KeyFile::new();
        kf.load_from_data(&text, glib::KeyFileFlags::NONE).unwrap();
        assert_eq!(kf.string("Desktop Entry", "Name").unwrap().as_str(), n);
        assert_eq!(
            kf.string("Desktop Entry", "Icon").unwrap().as_str(),
            GENERIC_ICON
        );
        let exec = kf
            .string("Desktop Entry", "Exec")
            .unwrap()
            .replace("%%", "%");
        let argv = glib::shell_parse_argv(exec.as_str()).unwrap();
        assert_eq!(argv.len(), 2, "{argv:?}");
        assert_eq!(argv[0].to_str().unwrap(), CHROME_BIN);
        assert_eq!(argv[1].to_str().unwrap(), format!("--app={u}"));
    }
}

#[test]
fn icon_source_rules() {
    let present = BTreeSet::from(["files/a.png".to_string()]);
    assert_eq!(
        icon_source(Some("files/a.png"), &present),
        IconSource::Bundle("files/a.png".into())
    );
    assert_eq!(
        icon_source(Some("files/b.png"), &present),
        IconSource::Generic
    );
    assert_eq!(
        icon_source(Some("https://i.th/x.png"), &present),
        IconSource::Https("https://i.th/x.png".into())
    );
    assert_eq!(
        icon_source(Some("http://i.th/x.png"), &present),
        IconSource::Generic
    );
    assert_eq!(icon_source(None, &present), IconSource::Generic);
}

const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDRfake";

/// 一个 wiremock，`https://<host>/` 改写到它（每个测试用自己的 host）。
async fn icon_server(host: &str) -> wiremock::MockServer {
    let s = wiremock::MockServer::start().await;
    TEST_URL_MAP
        .lock()
        .unwrap()
        .push((format!("https://{host}/"), format!("{}/", s.uri())));
    s
}

/// 在阻塞线程里跑步骤（下载借运行时的 `block_on`，与 agent 的应用任务一样）。
async fn run_blocking(
    root: PathBuf,
    g: Config,
    sys: SysState,
    phase: Phase,
) -> (Vec<ItemResult>, SysState) {
    run_blocking_with(root, g, sys, phase, false, 0).await
}

async fn run_blocking_with(
    root: PathBuf,
    g: Config,
    sys: SysState,
    phase: Phase,
    superseded: bool,
    budget_ms: u64,
) -> (Vec<ItemResult>, SysState) {
    tokio::task::spawn_blocking(move || {
        TEST_ICON_BUDGET_MS.with(|c| c.set(budget_ms));
        let r = MountSim::new(&root);
        let mut sys = sys;
        let bundle = tempfile::tempdir().unwrap();
        let out = run_step_with(&root, &r, &mut sys, &g, bundle.path(), phase, superseded).out;
        (out, sys)
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn https_icon_downloaded_only_in_full_phase() {
    use wiremock::matchers::{method, path};
    let s = icon_server("icons-full.test").await;
    // 不带 User-Agent 的请求 Wikimedia 等站点回 403（VM 上实测）：图标下载要带上
    wiremock::Mock::given(method("GET"))
        .and(path("/logo.png"))
        .and(wiremock::matchers::header_regex(
            "user-agent",
            "^mastersos-agent/[0-9]",
        ))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(PNG))
        .expect(1)
        .mount(&s)
        .await;
    let root = root();
    let rp = root.path().to_path_buf();
    let url = "https://lms.school.th/";
    let icon = "https://icons-full.test/logo.png";
    let g = grp(Kind::LegacyBrowser, vec![app("LMS", url, Some(icon))]);

    let (out, sys) = run_blocking(rp.clone(), g.clone(), SysState::default(), Phase::Boot).await;
    let w = item(&out, "webapp:LMS");
    assert!(w.ok, "{w:?}");
    assert!(w.detail.as_deref().unwrap().contains("通用图标"), "{w:?}");
    assert_eq!(icon_line(&launcher(&rp, url)), GENERIC_ICON);
    assert_eq!(
        s.received_requests().await.unwrap().len(),
        0,
        "开机阶段不下载"
    );

    let (out, sys) = run_blocking(rp.clone(), g.clone(), sys, Phase::Full).await;
    let w = item(&out, "webapp:LMS");
    assert_eq!(w, &ok("webapp:LMS"));
    let name = format!("{WEB_PREFIX}{}.png", slug(icon));
    let cached = xdg(&rp).join("icons").join(&name);
    assert_eq!(fs::read(&cached).unwrap(), PNG);
    assert_eq!(
        fs::metadata(&cached).unwrap().permissions().mode() & 0o7777,
        0o644
    );
    assert_eq!(icon_line(&launcher(&rp, url)), cached.to_str().unwrap());

    // 再跑一轮完整的、再开一次机：都用缓存，不再请求（expect(1) 在 drop 时核对）。
    let (_, sys) = run_blocking(rp.clone(), g.clone(), sys, Phase::Full).await;
    let (out, _) = run_blocking(rp.clone(), g, sys, Phase::Boot).await;
    assert_eq!(item(&out, "webapp:LMS"), &ok("webapp:LMS"));
    assert_eq!(icon_line(&launcher(&rp, url)), cached.to_str().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_or_non_image_icon_falls_back() {
    use wiremock::matchers::{method, path};
    let s = icon_server("icons-bad.test").await;
    let mut big = PNG.to_vec();
    big.resize(600 * 1024, 0);
    wiremock::Mock::given(method("GET"))
        .and(path("/big.png"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(big))
        .mount(&s)
        .await;
    wiremock::Mock::given(method("GET"))
        .and(path("/page.png"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_string("<!doctype html><html><body><svg></svg></body></html>"),
        )
        .mount(&s)
        .await;
    let root = root();
    let rp = root.path().to_path_buf();
    let g = grp(
        Kind::LegacyBrowser,
        vec![
            app(
                "Big",
                "https://big.th/",
                Some("https://icons-bad.test/big.png"),
            ),
            app(
                "Page",
                "https://page.th/",
                Some("https://icons-bad.test/page.png"),
            ),
        ],
    );
    let (out, _) = run_blocking(rp.clone(), g, SysState::default(), Phase::Full).await;
    for (n, u, why) in [
        ("Big", "https://big.th/", "512 KiB"),
        ("Page", "https://page.th/", "不是 PNG 或 SVG"),
    ] {
        let w = item(&out, &format!("webapp:{n}"));
        assert!(w.ok, "{w:?}");
        let d = w.detail.as_deref().unwrap();
        assert!(d.contains("通用图标") && d.contains(why), "{d}");
        assert_eq!(icon_line(&launcher(&rp, u)), GENERIC_ICON);
    }
    assert!(names(&xdg(&rp).join("icons")).is_empty());
}

#[test]
fn bundle_icon_is_copied_and_missing_one_falls_back() {
    let root = root();
    let bundle = tempfile::tempdir().unwrap();
    fs::create_dir_all(bundle.path().join("files/icons")).unwrap();
    fs::write(
        bundle.path().join("files/icons/a.svg"),
        "<?xml version=\"1.0\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\"/>",
    )
    .unwrap();
    let g = grp(
        Kind::Full,
        vec![
            app("A", "https://a.th/", Some("files/icons/a.svg")),
            app("B", "https://b.th/", Some("files/icons/none.png")),
        ],
    );
    let r = MountSim::new(root.path());
    let out = run_step(
        root.path(),
        &r,
        &mut SysState::default(),
        &g,
        bundle.path(),
        Phase::Boot,
    )
    .out;
    assert_eq!(item(&out, "webapp:A"), &ok("webapp:A"));
    let name = format!("{WEB_PREFIX}{}.svg", slug("https://a.th/"));
    let icon = xdg(root.path()).join("icons").join(&name);
    assert!(icon.exists());
    assert_eq!(
        icon_line(&launcher(root.path(), "https://a.th/")),
        icon.to_str().unwrap()
    );
    let b = item(&out, "webapp:B");
    assert!(
        b.ok && b.detail.as_deref().unwrap().contains("通用图标"),
        "{b:?}"
    );
}

#[test]
fn bad_webapp_item_is_skipped_not_fatal() {
    let root = root();
    let g = grp(
        Kind::LegacyBrowser,
        vec![
            app("Bad", "https://x.th/\"onload", None),
            app("Good", "https://good.th/", None),
            app("Dup", "https://good.th/", None),
        ],
    );
    let r = MountSim::new(root.path());
    let bundle = tempfile::tempdir().unwrap();
    let mut sys = SysState::default();
    let out = run_step(root.path(), &r, &mut sys, &g, bundle.path(), Phase::Full).out;
    assert!(!item(&out, "webapp:Bad").ok);
    assert!(!item(&out, "webapp:Dup").ok);
    assert_eq!(item(&out, "webapp:Good"), &ok("webapp:Good"));
    assert_eq!(item(&out, ITEM), &ok(ITEM), "一项不合格不让整步失败");
    let launchers: Vec<String> = names(&xdg(root.path()).join("applications"))
        .into_iter()
        .filter(|n| n.starts_with(WEB_PREFIX))
        .collect();
    assert_eq!(launchers, vec![webapp_file("https://good.th/")]);
    // Dock 里只有合格的那一个。
    let k = fs::read_to_string(root.path().join(DCONF_DIR).join(DCONF_FILE)).unwrap();
    assert!(
        k.contains(&format!(
            "favorite-apps=['google-chrome.desktop', '{}']",
            webapp_file("https://good.th/")
        )),
        "{k}"
    );
}

/// Visible ids: `system` in /usr/share/applications, `flatpak` in the Flatpak exports.
fn vis(system: &[&str], flatpak: &[&str]) -> VisibleApps {
    VisibleApps {
        system: system.iter().map(|s| s.to_string()).collect(),
        flatpak: flatpak.iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn hidden_overrides_keep_chrome_and_webapps() {
    let v = vis(
        &[
            "google-chrome.desktop",
            "org.gnome.Nautilus.desktop",
            "mastersos-web-0123456789ab.desktop",
            "org.gnome.Terminal.desktop",
        ],
        &["org.gnome.Terminal.desktop"],
    );
    assert_eq!(
        hidden_overrides(&v, &["google-chrome.desktop".into()], &[]),
        vec!["org.gnome.Nautilus.desktop", "org.gnome.Terminal.desktop"]
    );
    // A kept Flatpak keeps every launcher it exports (`<app id>.desktop`, `<app id>.<x>.desktop`);
    // another app whose id merely starts the same way does not.
    let v = vis(
        &[],
        &[
            "org.libreoffice.LibreOffice.desktop",
            "org.libreoffice.LibreOffice.writer.desktop",
            "org.libreoffice.LibreOfficeKit.desktop",
        ],
    );
    assert_eq!(
        hidden_overrides(&v, &[], &["org.libreoffice.LibreOffice".into()]),
        vec!["org.libreoffice.LibreOfficeKit.desktop"]
    );

    let root = root();
    let g = grp(
        Kind::LegacyBrowser,
        vec![app("LMS", "https://lms.th/", None)],
    );
    let r = MountSim::new(root.path());
    let bundle = tempfile::tempdir().unwrap();
    let mut sys = SysState::default();
    let out = run_step(root.path(), &r, &mut sys, &g, bundle.path(), Phase::Boot).out;
    assert_eq!(item(&out, ITEM), &ok(ITEM));
    let apps = xdg(root.path()).join("applications");
    assert_eq!(
        names(&apps),
        vec![
            webapp_file("https://lms.th/"),
            "org.gnome.Calculator.desktop".into(),
            "org.gnome.Nautilus.desktop".into(),
            "org.gnome.Settings.desktop".into(),
            "org.gnome.Terminal.desktop".into(),
        ],
        "Chrome、NoDisplay、本来就 Hidden 的不覆盖；系统 Flatpak 的也藏"
    );
    let h = fs::read_to_string(apps.join("org.gnome.Terminal.desktop")).unwrap();
    assert!(h.contains("\nHidden=true\n"), "{h}");
    let services = xdg(root.path()).join("dbus-1/services");
    assert_eq!(names(&services).len(), 3);
    assert_eq!(
        fs::read_to_string(services.join("org.freedesktop.FileManager1.service")).unwrap(),
        "[D-BUS Service]\nName=org.freedesktop.FileManager1\nExec=/bin/false\n"
    );
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode(&xdg(root.path())), 0o755);
    assert_eq!(mode(&apps), 0o755);
    assert_eq!(mode(&services), 0o755);
    assert_eq!(mode(&apps.join("org.gnome.Terminal.desktop")), 0o644);
    // 执行层：桩挂上了，状态记下了（sysext 刷新后的 exec-block 按它重挂）。
    assert_eq!(
        super::super::exec_block::read_mode(&paths(root.path())).unwrap(),
        Some(true)
    );
    assert!(is_stub(root.path(), "/usr/bin/nautilus"));
    assert!(is_stub(root.path(), "/usr/libexec/gnome-terminal-server"));
    assert!(is_stub(root.path(), "/usr/bin/gnome-control-center"));
}

#[test]
fn switching_to_desktop_removes_overrides() {
    let root = root();
    let r = MountSim::new(root.path());
    let bundle = tempfile::tempdir().unwrap();
    let mut sys = SysState::default();
    let web = vec![app("LMS", "https://lms.th/", None)];
    run_step(
        root.path(),
        &r,
        &mut sys,
        &grp(Kind::LegacyBrowser, web.clone()),
        bundle.path(),
        Phase::Full,
    );
    let out = run_step(
        root.path(),
        &r,
        &mut sys,
        &grp(Kind::Full, web),
        bundle.path(),
        Phase::Full,
    )
    .out;
    assert_eq!(item(&out, ITEM), &ok(ITEM));
    assert_eq!(
        names(&xdg(root.path()).join("applications")),
        vec![webapp_file("https://lms.th/")]
    );
    assert!(names(&xdg(root.path()).join("dbus-1/services")).is_empty());
    assert!(!root.path().join(DCONF_LOCKS_DIR).join(DCONF_FILE).exists());
    assert_eq!(
        super::super::exec_block::read_mode(&paths(root.path())).unwrap(),
        Some(false)
    );
    for t in super::super::exec_block::tests::PRESENT {
        assert!(!is_stub(root.path(), t), "{t}");
    }
    // 回到浏览器模式又挂上。
    run_step(
        root.path(),
        &r,
        &mut sys,
        &grp(Kind::LegacyBrowser, vec![]),
        bundle.path(),
        Phase::Full,
    );
    assert!(is_stub(root.path(), "/usr/bin/nautilus"));
}

#[test]
fn exec_block_failure_is_reported_on_desktop_item() {
    let root = root();
    let r = MountSim::new(root.path());
    r.fail_on("nsenter --mount=/proc/1/ns/mnt -- mount --bind");
    let bundle = tempfile::tempdir().unwrap();
    let mut sys = SysState::default();
    let out = run_step(
        root.path(),
        &r,
        &mut sys,
        &grp(Kind::LegacyBrowser, vec![]),
        bundle.path(),
        Phase::Boot,
    )
    .out;
    let d = item(&out, ITEM);
    assert!(!d.ok, "{d:?}");
    assert!(
        d.detail.as_deref().unwrap().contains("/usr/bin/nautilus"),
        "{d:?}"
    );
    // 其余的照做：覆盖写了。
    assert!(xdg(root.path())
        .join("applications/org.gnome.Terminal.desktop")
        .exists());
}

#[test]
fn dropped_webapp_is_removed() {
    let root = root();
    let bundle = tempfile::tempdir().unwrap();
    fs::create_dir_all(bundle.path().join("files")).unwrap();
    fs::write(bundle.path().join("files/b.png"), PNG).unwrap();
    let r = MountSim::new(root.path());
    let mut sys = SysState::default();
    let both = vec![
        app("A", "https://a.th/", None),
        app("B", "https://b.th/", Some("files/b.png")),
    ];
    run_step(
        root.path(),
        &r,
        &mut sys,
        &grp(Kind::Full, both),
        bundle.path(),
        Phase::Full,
    );
    let icons = xdg(root.path()).join("icons");
    assert_eq!(names(&icons).len(), 1);
    let out = run_step(
        root.path(),
        &r,
        &mut sys,
        &grp(Kind::Full, vec![app("A", "https://a.th/", None)]),
        bundle.path(),
        Phase::Full,
    )
    .out;
    assert_eq!(item(&out, ITEM), &ok(ITEM));
    assert_eq!(
        names(&xdg(root.path()).join("applications")),
        vec![webapp_file("https://a.th/")]
    );
    assert!(names(&icons).is_empty(), "B 的图标也删了");
    let k = fs::read_to_string(root.path().join(DCONF_DIR).join(DCONF_FILE)).unwrap();
    assert!(!k.contains(&webapp_file("https://b.th/")), "{k}");
}

#[test]
fn dconf_update_only_on_change() {
    let root = root();
    let r = MountSim::new(root.path());
    let bundle = tempfile::tempdir().unwrap();
    let mut sys = SysState::default();
    let count = |r: &MountSim| r.calls().iter().filter(|c| *c == "dconf update").count();
    let browser = grp(Kind::LegacyBrowser, vec![]);
    run_step(
        root.path(),
        &r,
        &mut sys,
        &browser,
        bundle.path(),
        Phase::Boot,
    );
    assert_eq!(count(&r), 1);
    assert!(root.path().join(DCONF_LOCKS_DIR).join(DCONF_FILE).exists());
    run_step(
        root.path(),
        &r,
        &mut sys,
        &browser,
        bundle.path(),
        Phase::Full,
    );
    assert_eq!(count(&r), 1, "没变就不编译");
    // 变了但编译失败：回报失败，下一轮没变也再编译。
    r.fake.respond("dconf update", Output::fail(1, "boom"));
    let desktop = grp(Kind::Full, vec![]);
    let out = run_step(
        root.path(),
        &r,
        &mut sys,
        &desktop,
        bundle.path(),
        Phase::Full,
    )
    .out;
    assert!(!item(&out, ITEM).ok);
    assert!(sys.dconf_update_pending);
    let out = run_step(
        root.path(),
        &r,
        &mut sys,
        &desktop,
        bundle.path(),
        Phase::Full,
    )
    .out;
    assert_eq!(item(&out, ITEM), &ok(ITEM));
    assert_eq!(count(&r), 3);
    assert!(!sys.dconf_update_pending);
    run_step(
        root.path(),
        &r,
        &mut sys,
        &desktop,
        bundle.path(),
        Phase::Full,
    );
    assert_eq!(count(&r), 3);
    // 状态读失败（记录可能丢了）：再编译一次。
    sys.load_failed = true;
    run_step(
        root.path(),
        &r,
        &mut sys,
        &desktop,
        bundle.path(),
        Phase::Full,
    );
    assert_eq!(count(&r), 4);
}

#[test]
fn sniff_icon_png_svg_only() {
    assert_eq!(sniff_icon(PNG), Some("png"));
    assert_eq!(
        sniff_icon(b"\xef\xbb\xbf  <svg viewBox='0 0 1 1'/>"),
        Some("svg")
    );
    assert_eq!(
        sniff_icon(b"<?xml version='1.0'?><!-- c --><svg/>"),
        Some("svg")
    );
    assert_eq!(sniff_icon(b"<!doctype html><svg/>"), None);
    assert_eq!(sniff_icon(b"GIF89a"), None);
    // 复审 T13 发现 8：根元素必须是 <svg；注释后面是 HTML、只是里面嵌了 <svg 的不算
    assert_eq!(
        sniff_icon(b"<!-- x --><html><body><svg></svg></body></html>"),
        None
    );
    assert_eq!(
        sniff_icon(b"<?xml version='1.0'?><html><svg/></html>"),
        None
    );
    assert_eq!(sniff_icon(b"<svgfoo/>"), None);
    assert_eq!(
        sniff_icon(
            b"<?xml version=\"1.0\"?>\n<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"x.dtd\">\n<!-- a -->\n<svg xmlns='x'>"
        ),
        Some("svg")
    );
    assert_eq!(sniff_icon(b"<svg>"), Some("svg"));
    assert_eq!(sniff_icon(b""), None);
}

/// 复审 T13 发现 1：步骤切了模式之后，sysext 刷新跑的 exec-block（从盘上读）按新模式收敛——不等整轮应用存 SysState。
#[test]
fn mode_switch_reaches_exec_block_before_state_is_saved() {
    use super::super::exec_block::{sync, tests::drop_binds};
    let root = root();
    let r = MountSim::new(root.path());
    let bundle = tempfile::tempdir().unwrap();
    let mut sys = SysState::default();
    let p = paths(root.path());
    run_step(
        root.path(),
        &r,
        &mut sys,
        &grp(Kind::LegacyBrowser, vec![]),
        bundle.path(),
        Phase::Full,
    );
    drop_binds(root.path());
    assert_eq!(sync(&p, &r).unwrap(), Some(true));
    assert!(is_stub(root.path(), "/usr/bin/nautilus"));
    run_step(
        root.path(),
        &r,
        &mut sys,
        &grp(Kind::Full, vec![]),
        bundle.path(),
        Phase::Full,
    );
    assert_eq!(sync(&p, &r).unwrap(), Some(false));
    assert!(!is_stub(root.path(), "/usr/bin/nautilus"));
}

/// 复审 T13 发现 6：下载失败的图标地址记下来，网页应用清单不变就不再请求；清单变了再试。
#[tokio::test(flavor = "multi_thread")]
async fn failed_icon_is_not_refetched_until_web_apps_change() {
    use wiremock::matchers::{method, path};
    let s = icon_server("icons-neg.test").await;
    wiremock::Mock::given(method("GET"))
        .and(path("/gone.png"))
        .respond_with(wiremock::ResponseTemplate::new(404))
        .mount(&s)
        .await;
    let root = root();
    let rp = root.path().to_path_buf();
    let a = app(
        "A",
        "https://a.th/",
        Some("https://icons-neg.test/gone.png"),
    );
    let g = grp(Kind::LegacyBrowser, vec![a.clone()]);
    let (out, sys) = run_blocking(rp.clone(), g.clone(), SysState::default(), Phase::Full).await;
    assert!(item(&out, "webapp:A")
        .detail
        .as_deref()
        .unwrap()
        .contains("下载图标失败"));
    assert_eq!(s.received_requests().await.unwrap().len(), 1);
    let (out, sys) = run_blocking(rp.clone(), g, sys, Phase::Full).await;
    let d = item(&out, "webapp:A").detail.clone().unwrap();
    assert!(d.contains("上次下载失败") && d.contains("通用图标"), "{d}");
    assert_eq!(s.received_requests().await.unwrap().len(), 1, "不再请求");
    // 清单变了（多一个网页应用）：再试一次
    let g = grp(
        Kind::LegacyBrowser,
        vec![a, app("B", "https://b.th/", None)],
    );
    let _ = run_blocking(rp.clone(), g, sys, Phase::Full).await;
    assert_eq!(s.received_requests().await.unwrap().len(), 2);
}

/// 复审 T13 发现 6：一轮里所有图标下载合计有时限；超了的下一轮再下，不再发请求。
#[tokio::test(flavor = "multi_thread")]
async fn icon_downloads_share_one_budget() {
    use wiremock::matchers::{method, path};
    let s = icon_server("icons-slow.test").await;
    for n in ["/1.png", "/2.png"] {
        wiremock::Mock::given(method("GET"))
            .and(path(n))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_bytes(PNG)
                    .set_delay(std::time::Duration::from_secs(3)),
            )
            .mount(&s)
            .await;
    }
    let root = root();
    let g = grp(
        Kind::LegacyBrowser,
        vec![
            app(
                "One",
                "https://one.th/",
                Some("https://icons-slow.test/1.png"),
            ),
            app(
                "Two",
                "https://two.th/",
                Some("https://icons-slow.test/2.png"),
            ),
        ],
    );
    let (out, _) = run_blocking_with(
        root.path().to_path_buf(),
        g,
        SysState::default(),
        Phase::Full,
        false,
        1500,
    )
    .await;
    assert_eq!(
        s.received_requests().await.unwrap().len(),
        1,
        "第二个不请求"
    );
    let d = item(&out, "webapp:Two").detail.clone().unwrap();
    assert!(d.contains("下载时间用完") && d.contains("通用图标"), "{d}");
    // 第一个被这一轮剩下的时间截断（服务端要 3 秒才回），不是等满 60 秒
    let d1 = item(&out, "webapp:One").detail.clone().unwrap();
    assert!(d1.contains("timed out"), "{d1}");
    assert!(item(&out, "webapp:One").ok && item(&out, "webapp:Two").ok);
}

/// 复审 T13 发现 6：有更新的应用请求时不下载（挂失锁定最多等一个步骤）。
#[tokio::test(flavor = "multi_thread")]
async fn superseded_apply_downloads_nothing() {
    use wiremock::matchers::method;
    let s = icon_server("icons-sup.test").await;
    wiremock::Mock::given(method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(PNG))
        .mount(&s)
        .await;
    let root = root();
    let g = grp(
        Kind::LegacyBrowser,
        vec![app(
            "A",
            "https://a.th/",
            Some("https://icons-sup.test/a.png"),
        )],
    );
    let (out, _) = run_blocking_with(
        root.path().to_path_buf(),
        g,
        SysState::default(),
        Phase::Full,
        true,
        0,
    )
    .await;
    assert_eq!(s.received_requests().await.unwrap().len(), 0);
    assert!(item(&out, "webapp:A")
        .detail
        .as_deref()
        .unwrap()
        .contains("有更新的应用请求"));
}

/// 复审 T13 R3：一时的失败（5xx、超时、连不上、时间用完）下一轮完整应用再试；只有 4xx、太大、不是图片才记下。
#[tokio::test(flavor = "multi_thread")]
async fn transient_icon_failures_are_retried() {
    use wiremock::matchers::{method, path};
    let s = icon_server("icons-5xx.test").await;
    wiremock::Mock::given(method("GET"))
        .and(path("/busy.png"))
        .respond_with(wiremock::ResponseTemplate::new(503))
        .mount(&s)
        .await;
    let root = root();
    let rp = root.path().to_path_buf();
    let g = grp(
        Kind::LegacyBrowser,
        vec![app(
            "A",
            "https://a.th/",
            Some("https://icons-5xx.test/busy.png"),
        )],
    );
    let (_, sys) = run_blocking(rp.clone(), g.clone(), SysState::default(), Phase::Full).await;
    let (_, sys) = run_blocking(rp.clone(), g.clone(), sys, Phase::Full).await;
    assert_eq!(
        s.received_requests().await.unwrap().len(),
        2,
        "503 下一轮再试"
    );
    assert!(sys.icon_failures.urls.is_empty());
    // 被这一轮的时间截断的（超时）同样下一轮再试
    let slow = icon_server("icons-cut.test").await;
    wiremock::Mock::given(method("GET"))
        .and(path("/s.png"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_bytes(PNG)
                .set_delay(std::time::Duration::from_secs(3)),
        )
        .mount(&slow)
        .await;
    let g = grp(
        Kind::LegacyBrowser,
        vec![app(
            "S",
            "https://s.th/",
            Some("https://icons-cut.test/s.png"),
        )],
    );
    let (_, sys) = run_blocking_with(
        rp.clone(),
        g.clone(),
        SysState::default(),
        Phase::Full,
        false,
        1500,
    )
    .await;
    assert!(sys.icon_failures.urls.is_empty(), "截断不记");
    let (out, _) = run_blocking(rp.clone(), g, sys, Phase::Full).await;
    assert_eq!(slow.received_requests().await.unwrap().len(), 2);
    assert_eq!(item(&out, "webapp:S"), &ok("webapp:S"));
}

/// Task 16：桌面模式的 Dock 里有清单里已按清单装好的 Flatpak（`flatpak-state.json` 的 managed）；文件读不出 → 没有，不报错。
#[test]
fn desktop_favorites_include_managed_flatpaks() {
    let root = root();
    let r = MountSim::new(root.path());
    let mut sys = SysState::default();
    let mut g = grp(Kind::Full, vec![]);
    g.apps.flatpak = vec!["org.libreoffice.LibreOffice".into()];
    let bundle = tempfile::tempdir().unwrap();
    let keyfile = root.path().join("etc/dconf/db/mastersos.d/50-mastersos");
    let var = root.path().join("var/lib/mastersos-system");
    fs::create_dir_all(&var).unwrap();
    fs::write(
        var.join(super::super::flatpak::STATE_FILE),
        r#"{"managed":["org.libreoffice.LibreOffice"]}"#,
    )
    .unwrap();
    let out = run_step(root.path(), &r, &mut sys, &g, bundle.path(), Phase::Full).out;
    assert!(item(&out, ITEM).ok, "{out:?}");
    let k = fs::read_to_string(&keyfile).unwrap();
    assert!(
        k.contains(
            "favorite-apps=['google-chrome.desktop', 'org.gnome.Nautilus.desktop', \
             'org.libreoffice.LibreOffice.desktop']\n"
        ),
        "{k}"
    );
    // 读不出：Dock 里没有它，desktop 照样成功
    fs::write(var.join(super::super::flatpak::STATE_FILE), "{bad").unwrap();
    let out = run_step(root.path(), &r, &mut sys, &g, bundle.path(), Phase::Full).out;
    assert!(item(&out, ITEM).ok, "{out:?}");
    let k = fs::read_to_string(&keyfile).unwrap();
    assert!(!k.contains("LibreOffice"), "{k}");
}

fn kiosk_app(toml_text: &str) -> mastersos_bundle::KioskApp {
    toml::from_str(toml_text).unwrap()
}

/// kiosk 步骤（排在 desktop 之前）写好的启动描述：有它才说明这个应用在这台机器上建好了。
fn kiosk_launch(root: &Path, id: &str) {
    let d = root.join("var/lib/mastersos-public/kiosk").join(id);
    fs::create_dir_all(&d).unwrap();
    fs::write(d.join("launch.json"), "{}").unwrap();
}

/// 计划 9 Task 6：`in_session = true` 且 kiosk 步骤建好了的锁定应用，在 `applications/` 里有
/// `mastersos-kiosk-<id>.desktop`（执行 `mastersos-kiosk enter <id>`）并进 Dock；没开 `in_session`、没建好（没有
/// `launch.json`）、校验不过的都没有。浏览器模式的 `Hidden=true` 覆盖不盖它、也不当覆盖删掉；切回桌面模式照样留着；
/// 关掉 `in_session` 就删掉。
#[test]
fn desktop_writes_in_session_launcher_only_when_enabled() {
    let root = root();
    let r = MountSim::new(root.path());
    let bundle = tempfile::tempdir().unwrap();
    let mut sys = SysState::default();
    let mut g = grp(
        Kind::LegacyBrowser,
        vec![app("LMS", "https://lms.th/", None)],
    );
    g.apps.kiosk.insert(
        "nwea".into(),
        kiosk_app(
            "name = 'NWEA \"MAP\" ห้องสอบ'\nurl = \"https://test.mapnwea.org/\"\nin_session = true\n",
        ),
    );
    g.apps.kiosk.insert(
        "forms".into(),
        kiosk_app("name = \"Forms\"\nurl = \"https://docs.google.com/\"\n"),
    );
    g.apps.kiosk.insert(
        "calc".into(),
        kiosk_app("name = \"Calc\"\nexec = \"org.example.Calc\"\nin_session = true\n"),
    );
    g.apps.kiosk.insert(
        "bad".into(),
        kiosk_app("name = \"Bad\"\nexec = \"/opt/x\"\nin_session = true\n"),
    );
    kiosk_launch(root.path(), "nwea");
    kiosk_launch(root.path(), "forms");
    kiosk_launch(root.path(), "bad");
    // calc 没有 launch.json：kiosk 步骤没建好它
    let icon = root.path().join("var/lib/mastersos-public/kiosk/nwea/icon");
    fs::write(&icon, b"\x89PNG\r\n\x1a\n").unwrap();

    let out = run_step(root.path(), &r, &mut sys, &g, bundle.path(), Phase::Full).out;
    assert_eq!(item(&out, ITEM), &ok(ITEM));
    let apps = xdg(root.path()).join("applications");
    let all = names(&apps);
    let kiosk: Vec<&String> = all.iter().filter(|n| n.starts_with(KIOSK_PREFIX)).collect();
    assert_eq!(kiosk, ["mastersos-kiosk-nwea.desktop"], "{all:?}");
    let text = fs::read_to_string(apps.join("mastersos-kiosk-nwea.desktop")).unwrap();
    assert!(text.starts_with("[Desktop Entry]\n"), "{text}");
    assert!(
        text.contains("\nName=NWEA \"MAP\" ห้องสอบ\n"),
        "名字原样（GKeyFile 不转义引号与泰文）：{text}"
    );
    assert!(
        text.contains("\nExec=/usr/bin/mastersos-kiosk enter nwea\n"),
        "{text}"
    );
    assert_eq!(icon_line(&text), icon.to_str().unwrap());
    assert!(
        !text.contains("Hidden=") && !text.contains("NoDisplay="),
        "{text}"
    );
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode(&apps.join("mastersos-kiosk-nwea.desktop")), 0o644);
    // Dock：Chrome、网页应用之后
    let k = fs::read_to_string(root.path().join(DCONF_DIR).join(DCONF_FILE)).unwrap();
    assert!(
        k.contains(&format!(
            "favorite-apps=['google-chrome.desktop', '{}', 'mastersos-kiosk-nwea.desktop']\n",
            webapp_file("https://lms.th/")
        )),
        "{k}"
    );

    // 切到桌面模式：删覆盖时不碰它
    set_kind(&mut g, Kind::Full);
    run_step(root.path(), &r, &mut sys, &g, bundle.path(), Phase::Full);
    assert!(apps.join("mastersos-kiosk-nwea.desktop").exists());
    let k = fs::read_to_string(root.path().join(DCONF_DIR).join(DCONF_FILE)).unwrap();
    assert!(k.contains("'mastersos-kiosk-nwea.desktop'"), "{k}");

    // 关掉 in_session：删掉，Dock 里也没了；没有图标缓存时用通用图标
    g.apps.kiosk.get_mut("nwea").unwrap().in_session = false;
    g.apps.kiosk.get_mut("forms").unwrap().in_session = true;
    run_step(root.path(), &r, &mut sys, &g, bundle.path(), Phase::Full);
    assert!(!apps.join("mastersos-kiosk-nwea.desktop").exists());
    let text = fs::read_to_string(apps.join("mastersos-kiosk-forms.desktop")).unwrap();
    assert_eq!(icon_line(&text), KIOSK_GENERIC_ICON);
    let k = fs::read_to_string(root.path().join(DCONF_DIR).join(DCONF_FILE)).unwrap();
    assert!(!k.contains("mastersos-kiosk-nwea"), "{k}");
    assert!(k.contains("'mastersos-kiosk-forms.desktop'"), "{k}");

    // 应用整个删掉：启动器也删
    g.apps.kiosk.clear();
    set_kind(&mut g, Kind::LegacyBrowser);
    run_step(root.path(), &r, &mut sys, &g, bundle.path(), Phase::Full);
    assert!(names(&apps).iter().all(|n| !n.starts_with(KIOSK_PREFIX)));

    // hidden_overrides 也不盖 mastersos-kiosk-*
    let v = vis(
        &["mastersos-kiosk-nwea.desktop", "org.gnome.Terminal.desktop"],
        &[],
    );
    assert_eq!(
        hidden_overrides(&v, &[], &[]),
        vec!["org.gnome.Terminal.desktop"]
    );
}

/// 复审 M7：`kiosk/` 目录根本不存在（kiosk 步骤还没跑过或失败了）：不写启动器、不报错。
#[test]
fn kiosk_launcher_skipped_without_kiosk_dir() {
    let root = root();
    let r = MountSim::new(root.path());
    let bundle = tempfile::tempdir().unwrap();
    let mut sys = SysState::default();
    let mut g = grp(Kind::Full, vec![]);
    g.apps.kiosk.insert(
        "nwea".into(),
        kiosk_app("name = \"NWEA\"\nurl = \"https://test.mapnwea.org/\"\nin_session = true\n"),
    );
    assert!(!root.path().join("var/lib/mastersos-public/kiosk").exists());
    let out = run_step(root.path(), &r, &mut sys, &g, bundle.path(), Phase::Full).out;
    assert_eq!(item(&out, ITEM), &ok(ITEM));
    let apps = xdg(root.path()).join("applications");
    assert!(names(&apps).iter().all(|n| !n.starts_with(KIOSK_PREFIX)));
    let k = fs::read_to_string(root.path().join(DCONF_DIR).join(DCONF_FILE)).unwrap();
    assert!(!k.contains("mastersos-kiosk"), "{k}");
}

/// The settings text of the legacy browser-mode snapshot: a web app, a Flatpak that is installed
/// (and in the Flatpak exports), and an in-session kiosk app.
const LEGACY_BROWSER_TOML: &str = r#"
version = 1
[[group]]
id = "default"
name = "d"
mode = "browser"
[group.apps]
web = [{ name = "LMS", url = "https://lms.th/" }]
flatpak = ["org.gnome.Calculator"]
[group.apps.kiosk.nwea]
name = "NWEA"
url = "https://test.mapnwea.org/"
in_session = true
"#;

/// Every file the desktop step owns (dconf keyfile and locks, the XDG overrides, launchers and
/// D-Bus overrides), with its mode and content, in path order; then the commands run (the stub's
/// path, renamed on purpose, written as `<stub>`).
fn dump_desktop_output(root: &Path, calls: &[String]) -> String {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(base, &p, out);
            } else {
                let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o7777;
                let rel = p.strip_prefix(base).unwrap().display().to_string();
                let body = String::from_utf8_lossy(&fs::read(&p).unwrap()).into_owned();
                out.push((rel, format!("{mode:o}\n{body}")));
            }
        }
    }
    let mut files = Vec::new();
    walk(root, &root.join("etc/dconf"), &mut files);
    walk(root, &root.join("var/lib/mastersos-public/xdg"), &mut files);
    files.sort();
    let mut s = String::new();
    for (rel, body) in files {
        s.push_str(&format!("== {rel} {body}\n"));
    }
    for c in calls {
        s.push_str(&format!(
            "$ {}\n",
            c.replace(super::super::exec_block::STUB, "<stub>")
        ));
    }
    s
}

/// Writes the kiosk step's output for `nwea` and a Flatpak state in which `managed` were installed
/// by us.
fn installed(root: &Path, managed: &[&str]) {
    kiosk_launch(root, "nwea");
    let var = root.join("var/lib/mastersos-system");
    fs::create_dir_all(&var).unwrap();
    let st = serde_json::json!({ "managed": managed });
    fs::write(var.join(super::super::flatpak::STATE_FILE), st.to_string()).unwrap();
}

/// Config profiles design §3.1/§4.3: a legacy `mode = "browser"` Group reproduces the old browser
/// mode byte for byte. `legacy_browser.snap` was captured by running the same step on the same
/// text with the agent of commit 1300a82 (before configs existed); only the stub's path is
/// normalised, since renaming it is the point.
#[test]
fn legacy_browser_output_unchanged() {
    let root = root();
    let r = MountSim::new(root.path());
    let bundle = tempfile::tempdir().unwrap();
    let mut sys = SysState::default();
    let c = mastersos_bundle::Manifest::parse(LEGACY_BROWSER_TOML)
        .unwrap()
        .effective_of_group("default")
        .unwrap();
    assert!(c.legacy_browser && c.interface == Interface::Learning);
    installed(root.path(), &["org.gnome.Calculator"]);
    let out = run_step(root.path(), &r, &mut sys, &c, bundle.path(), Phase::Full).out;
    assert_eq!(
        out,
        vec![ok("webapp:LMS"), ok(ITEM)],
        "the same report items as before"
    );
    let got = dump_desktop_output(root.path(), &r.calls());
    let want = include_str!("legacy_browser.snap");
    assert!(got == want, "got:\n{got}\nwant:\n{want}");
}

/// §4.2: `learning` is the browser mode plus the Config's installed Flatpaks in the Dock; the
/// rest of the dconf (every lock, the cleared terminal shortcut, the extensions) is the same.
#[test]
fn learning_lists_flatpak_in_favorites() {
    let lo = "org.libreoffice.LibreOffice".to_string();
    let web = vec!["mastersos-web-aaaaaaaaaaaa.desktop".to_string()];
    let kiosk = vec!["mastersos-kiosk-nwea.desktop".to_string()];
    let mut learning = grp(Kind::Learning, vec![]);
    learning.apps.flatpak = vec![lo.clone()];
    let (k, locks) = render_dconf(&learning, &web, &kiosk, std::slice::from_ref(&lo));
    assert!(
        k.contains(
            "favorite-apps=['google-chrome.desktop', 'mastersos-web-aaaaaaaaaaaa.desktop', \
             'mastersos-kiosk-nwea.desktop', 'org.libreoffice.LibreOffice.desktop']\n"
        ),
        "{k}"
    );
    assert!(!k.contains("Nautilus"), "{k}");
    assert!(
        k.contains("[org/gnome/settings-daemon/plugins/media-keys]\nterminal=['']\n"),
        "{k}"
    );
    let mut legacy = grp(Kind::LegacyBrowser, vec![]);
    legacy.apps.flatpak = vec![lo.clone()];
    let (lk, llocks) = render_dconf(&legacy, &web, &kiosk, std::slice::from_ref(&lo));
    assert_eq!(locks, llocks, "the same locks as the browser mode");
    let fav = |s: &str| {
        s.lines()
            .filter(|l| !l.starts_with("favorite-apps="))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(fav(&k), fav(&lk), "only the Dock differs");
    assert!(!lk.contains("LibreOffice"), "{lk}");

    // The whole step: LibreOffice's exported launchers stay visible, other Flatpaks are still
    // hidden, and the terminal, file manager and settings are still stubbed out.
    let root = root();
    let exp = root
        .path()
        .join("var/lib/flatpak/exports/share/applications");
    for f in [
        "org.libreoffice.LibreOffice.desktop",
        "org.libreoffice.LibreOffice.writer.desktop",
    ] {
        fs::write(exp.join(f), "[Desktop Entry]\nType=Application\nName=LO\n").unwrap();
    }
    installed(root.path(), &[&lo]);
    let r = MountSim::new(root.path());
    let bundle = tempfile::tempdir().unwrap();
    let mut sys = SysState::default();
    let out = run_step(
        root.path(),
        &r,
        &mut sys,
        &learning,
        bundle.path(),
        Phase::Full,
    )
    .out;
    assert_eq!(item(&out, ITEM), &ok(ITEM));
    let keyfile = fs::read_to_string(root.path().join(DCONF_DIR).join(DCONF_FILE)).unwrap();
    assert!(
        keyfile.contains("'org.libreoffice.LibreOffice.desktop']\n"),
        "{keyfile}"
    );
    let apps = names(&xdg(root.path()).join("applications"));
    assert!(
        apps.iter().all(|n| !n.starts_with("org.libreoffice.")),
        "{apps:?}"
    );
    for hidden in [
        "org.gnome.Calculator.desktop",
        "org.gnome.Nautilus.desktop",
        "org.gnome.Terminal.desktop",
    ] {
        assert!(apps.contains(&hidden.to_string()), "{hidden}: {apps:?}");
    }
    for t in super::super::exec_block::tests::PRESENT {
        assert!(is_stub(root.path(), t), "{t}");
    }
    assert_eq!(
        super::super::exec_block::read_mode(&paths(root.path())).unwrap(),
        Some(true)
    );
}

/// A Flatpak that is listed but not installed yet has no place in the Dock (§4.4: only once it
/// is installed).
#[test]
fn learning_dock_skips_flatpak_not_installed() {
    let root = root();
    installed(root.path(), &[]);
    let mut learning = grp(Kind::Learning, vec![]);
    learning.apps.flatpak = vec!["org.libreoffice.LibreOffice".into()];
    let r = MountSim::new(root.path());
    let bundle = tempfile::tempdir().unwrap();
    let mut sys = SysState::default();
    run_step(
        root.path(),
        &r,
        &mut sys,
        &learning,
        bundle.path(),
        Phase::Full,
    );
    let keyfile = fs::read_to_string(root.path().join(DCONF_DIR).join(DCONF_FILE)).unwrap();
    assert!(!keyfile.contains("LibreOffice"), "{keyfile}");
}

/// Review fix 2: a kept Flatpak only keeps launchers found in the Flatpak exports. An image
/// launcher whose name starts with the app id stays hidden, also when the same id is in both.
#[test]
fn kept_flatpak_does_not_unhide_image_launchers() {
    let lo = "org.libreoffice.LibreOffice".to_string();
    let v = vis(
        &[
            "org.libreoffice.LibreOffice.calc.desktop",
            "org.libreoffice.LibreOffice.desktop",
        ],
        &[
            "org.libreoffice.LibreOffice.desktop",
            "org.libreoffice.LibreOffice.writer.desktop",
        ],
    );
    assert_eq!(
        hidden_overrides(&v, &[], std::slice::from_ref(&lo)),
        vec![
            "org.libreoffice.LibreOffice.calc.desktop",
            "org.libreoffice.LibreOffice.desktop",
        ]
    );

    // The same through the step: the image's launcher is hidden, the exported one is not.
    let root = root();
    fs::write(
        root.path()
            .join("usr/share/applications/org.libreoffice.LibreOffice.calc.desktop"),
        "[Desktop Entry]\nType=Application\nName=Calc\n",
    )
    .unwrap();
    let exp = root.path().join(FLATPAK_APPS_DIR);
    fs::write(
        exp.join("org.libreoffice.LibreOffice.writer.desktop"),
        "[Desktop Entry]\nType=Application\nName=Writer\n",
    )
    .unwrap();
    installed(root.path(), &[&lo]);
    let mut learning = grp(Kind::Learning, vec![]);
    learning.apps.flatpak = vec![lo.clone()];
    let r = MountSim::new(root.path());
    let bundle = tempfile::tempdir().unwrap();
    let mut sys = SysState::default();
    run_step(
        root.path(),
        &r,
        &mut sys,
        &learning,
        bundle.path(),
        Phase::Full,
    );
    let apps = names(&xdg(root.path()).join("applications"));
    assert!(
        apps.contains(&"org.libreoffice.LibreOffice.calc.desktop".to_string()),
        "{apps:?}"
    );
    assert!(
        !apps.contains(&"org.libreoffice.LibreOffice.writer.desktop".to_string()),
        "{apps:?}"
    );
}

/// Writes LibreOffice's exported launchers (main and writer) into the Flatpak exports.
fn export_libreoffice(root: &Path) {
    let exp = root.join(FLATPAK_APPS_DIR);
    for f in [
        "org.libreoffice.LibreOffice.desktop",
        "org.libreoffice.LibreOffice.writer.desktop",
    ] {
        fs::write(exp.join(f), "[Desktop Entry]\nType=Application\nName=LO\n").unwrap();
    }
}

fn lo_hidden(root: &Path) -> [bool; 2] {
    let apps = xdg(root).join("applications");
    [
        apps.join("org.libreoffice.LibreOffice.desktop").exists(),
        apps.join("org.libreoffice.LibreOffice.writer.desktop")
            .exists(),
    ]
}

fn dock(root: &Path) -> String {
    let k = fs::read_to_string(root.join(DCONF_DIR).join(DCONF_FILE)).unwrap();
    k.lines()
        .find(|l| l.starts_with("favorite-apps="))
        .unwrap()
        .to_string()
}

/// Review fix 3: a Flatpak that is listed but not installed by us (not in `managed`) keeps its
/// `Hidden=true` override in `learning`, and has no place in the Dock.
#[test]
fn learning_hides_listed_flatpak_not_managed() {
    let root = root();
    export_libreoffice(root.path());
    installed(root.path(), &[]);
    let mut learning = grp(Kind::Learning, vec![]);
    learning.apps.flatpak = vec!["org.libreoffice.LibreOffice".into()];
    let r = MountSim::new(root.path());
    let bundle = tempfile::tempdir().unwrap();
    let mut sys = SysState::default();
    run_step(
        root.path(),
        &r,
        &mut sys,
        &learning,
        bundle.path(),
        Phase::Full,
    );
    assert_eq!(lo_hidden(root.path()), [true, true]);
    assert!(!dock(root.path()).contains("LibreOffice"));
}

/// Review fix 3: with LibreOffice installed and exported, switching `learning` → legacy browser
/// hides it and drops it from the Dock; `learning` → `full` removes every override and puts
/// Files and LibreOffice in the Dock; back to `learning` shows it again without Files.
#[test]
fn switching_from_learning_changes_overrides_and_dock() {
    let root = root();
    export_libreoffice(root.path());
    installed(root.path(), &["org.libreoffice.LibreOffice"]);
    let r = MountSim::new(root.path());
    let bundle = tempfile::tempdir().unwrap();
    let mut sys = SysState::default();
    let mut g = grp(Kind::Learning, vec![]);
    g.apps.flatpak = vec!["org.libreoffice.LibreOffice".into()];
    let lo = "'org.libreoffice.LibreOffice.desktop'";

    run_step(root.path(), &r, &mut sys, &g, bundle.path(), Phase::Full);
    assert_eq!(lo_hidden(root.path()), [false, false]);
    assert!(dock(root.path()).contains(lo));
    assert!(!dock(root.path()).contains("Nautilus"));

    set_kind(&mut g, Kind::LegacyBrowser);
    run_step(root.path(), &r, &mut sys, &g, bundle.path(), Phase::Full);
    assert_eq!(lo_hidden(root.path()), [true, true]);
    assert!(!dock(root.path()).contains("LibreOffice"));

    set_kind(&mut g, Kind::Learning);
    run_step(root.path(), &r, &mut sys, &g, bundle.path(), Phase::Full);
    assert_eq!(lo_hidden(root.path()), [false, false]);

    set_kind(&mut g, Kind::Full);
    run_step(root.path(), &r, &mut sys, &g, bundle.path(), Phase::Full);
    assert_eq!(lo_hidden(root.path()), [false, false]);
    let apps = names(&xdg(root.path()).join("applications"));
    assert!(
        apps.iter().all(|n| !n.starts_with("org.gnome.")),
        "full removes every override: {apps:?}"
    );
    let d = dock(root.path());
    assert!(
        d.contains(lo) && d.contains("'org.gnome.Nautilus.desktop'"),
        "{d}"
    );
    assert!(!is_stub(root.path(), "/usr/bin/nautilus"));

    set_kind(&mut g, Kind::Learning);
    run_step(root.path(), &r, &mut sys, &g, bundle.path(), Phase::Full);
    assert_eq!(lo_hidden(root.path()), [false, false]);
    let d = dock(root.path());
    assert!(d.contains(lo) && !d.contains("Nautilus"), "{d}");
    assert!(is_stub(root.path(), "/usr/bin/nautilus"));
}

#[test]
fn locked_profile_enables_managed_extension() {
    let g = grp(Kind::Learning, vec![]);
    let (k, _) = render_dconf(&g, &[], &[], &[]);
    let line = k
        .lines()
        .find(|l| l.starts_with("enabled-extensions="))
        .unwrap_or_else(|| panic!("no enabled-extensions line:\n{k}"));
    assert!(line.contains("'mastersos-managed@mastersos.org'"), "{line}");
}
