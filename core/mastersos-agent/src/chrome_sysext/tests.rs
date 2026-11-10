//! fixture：`tests/fixtures/chrome-Release` 是 2026-10-13 从 `https://dl.google.com/linux/chrome/deb/dists/stable/InRelease`
//! 取下、用 Google 的钥匙 `gpgv` 验过之后的明文（原样，没截）；`chrome-Packages` 是同一时刻的
//! `main/binary-amd64/Packages` 截成三个包（beta、repo、stable），所以它的 sha256 **对不上** Release 里那一行
//! ——单元测试不靠真的签名与哈希链：`gpgv` 由 [`LabRunner`]（包着 `FakeRunner`）代替，job 测试里的
//! Release 把 Packages 那一行换成实际提供的内容的哈希。

use std::fs;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use mastersos_bundle::{DeviceIdent, ItemResult, Seed};
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::fetch::Fetcher;
use crate::runner::{Cmd, FakeRunner, Output, Runner};
use crate::system::SysPaths;
use std::time::SystemTime;

const RELEASE: &str = include_str!("../../tests/fixtures/chrome-Release");
const PACKAGES: &str = include_str!("../../tests/fixtures/chrome-Packages");
const STABLE: &str = "google-chrome-stable";
/// fixture 里 Release 的 `Date: Tue, 13 Oct 2026 09:06:51 UTC`。
const RELEASE_EPOCH: i64 = 1_791_882_411;
/// agent 跑在自己的挂载命名空间里（PrivateTmp=yes），合并要交给 PID 1 的 systemd-sysext.service 做。
const REFRESH: &str = "systemctl reload-or-restart systemd-sysext.service";
const DEB_PATH: &str =
    "/pool/main/g/google-chrome-stable/google-chrome-stable_155.0.8059.39-1_amd64.deb";

fn hex256(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

#[test]
fn finds_packages_hash_in_release() {
    assert_eq!(
        release_sha256(RELEASE, "main/binary-amd64/Packages").as_deref(),
        Some("baa2f44e77775b041d34cf8e3498a697ca932152277bf4dbd643a4c9cad046c5"),
        "取 SHA256 段的那一行，不是 MD5Sum / SHA1 段里同名的"
    );
    assert_eq!(
        release_sha256(RELEASE, "main/binary-amd64/Packages.gz").as_deref(),
        Some("f8f85003ba37b7c99124e70e956cf76e198705818aa751a4c2e5ce54c1363b1a")
    );
    assert_eq!(release_sha256(RELEASE, "main/binary-i386/Packages"), None);
    assert_eq!(
        release_sha256(RELEASE, "binary-amd64/Packages"),
        None,
        "整段路径相等，不是后缀"
    );
    // 只有 MD5Sum 段的 Release：没有 SHA256 就是没有
    let md5_only = "MD5Sum:\n 97e59177d2bb1b9ebbaa667aaf9fc939 6207 main/binary-amd64/Packages\n";
    assert_eq!(release_sha256(md5_only, "main/binary-amd64/Packages"), None);
    // 哈希不是 64 位十六进制：不认
    let bad = "SHA256:\n xyz 6207 main/binary-amd64/Packages\n";
    assert_eq!(release_sha256(bad, "main/binary-amd64/Packages"), None);
}

#[test]
fn finds_chrome_stable_entry() {
    assert_eq!(
        find_package(PACKAGES, STABLE).unwrap(),
        DebEntry {
            version: "155.0.8059.39-1".into(),
            filename: DEB_PATH.trim_start_matches('/').into(),
            sha256: "c58aa0f2cd66179c9f050e062c882d27aa9b9f8c2b7c73fee3498560b5ed0b38".into(),
        }
    );
    assert_eq!(
        find_package(PACKAGES, "google-chrome-beta")
            .unwrap()
            .version,
        "156.0.8078.12-1"
    );
    let e = find_package(PACKAGES, "google-chrome-unstable").unwrap_err();
    assert!(format!("{e:#}").contains("google-chrome-unstable"), "{e:#}");
    // 名字整段相等：不按前缀
    assert!(find_package(PACKAGES, "google-chrome").is_err());
}

#[test]
fn duplicate_stanzas_are_an_error() {
    let extra = PACKAGES.replace(
        "Package: google-chrome-beta",
        "Package: google-chrome-stable",
    );
    let e = find_package(&extra, STABLE).unwrap_err();
    assert!(format!("{e:#}").contains("more than once"), "{e:#}");
}

#[test]
fn odd_filename_or_version_is_an_error() {
    let entry = find_package(PACKAGES, STABLE).unwrap();
    for (from, to) in [
        (entry.filename.as_str(), "pool/../../etc/passwd.deb"),
        (entry.filename.as_str(), "/pool/x.deb"),
        (entry.filename.as_str(), "pool/main/x.deb?x=1"),
        (entry.filename.as_str(), "pool/main/x.tar"),
        (entry.version.as_str(), "--admindir=/tmp"),
        (entry.version.as_str(), "1.0 2"),
    ] {
        let p = PACKAGES.replace(from, to);
        assert!(find_package(&p, STABLE).is_err(), "{to}");
    }
    let p = PACKAGES.replace(&entry.sha256, "c58aa0f2");
    assert!(
        find_package(&p, STABLE).is_err(),
        "sha256 不是 64 位十六进制"
    );
}

#[test]
fn maps_product_logos_to_hicolor() {
    let names: Vec<String> = [
        "chrome",
        "product_logo_16.png",
        "product_logo_256.png",
        "product_logo_32.xpm",
        "product_logo_.png",
        "product_logo_x.png",
        "product_logo_48.png.bak",
    ]
    .map(String::from)
    .to_vec();
    assert_eq!(
        icon_targets(&names),
        vec![
            (
                "opt/google/chrome/product_logo_16.png".to_string(),
                "usr/share/icons/hicolor/16x16/apps/google-chrome.png".to_string()
            ),
            (
                "opt/google/chrome/product_logo_256.png".to_string(),
                "usr/share/icons/hicolor/256x256/apps/google-chrome.png".to_string()
            ),
        ]
    );
}

/// 真实 .desktop 的相关几行（Google 的 deb 里 `Icon=` 只在主段出现一次）。
const DESKTOP: &str = "[Desktop Entry]\nName=Google Chrome\nExec=/usr/bin/google-chrome-stable %U\nStartupWMClass=google-chrome\nIcon=google-chrome\n\n[Desktop Action new-window]\nName=New Window\n";

/// 包着 FakeRunner：`gpgv` 退出 0 时把 `--output` 写成给定的 Release；`dpkg-deb -x` 退出 0 时在目标目录里
/// 放一棵像 Chrome 的树（可选不带 .desktop）。
struct LabRunner {
    fake: Arc<FakeRunner>,
    release: String,
    desktop: bool,
    /// `<ext>.new`：每次合并时记下它在不在（先合并、后删）。
    new_dir: PathBuf,
    new_at_refresh: std::sync::Mutex<Vec<bool>>,
    /// 这个程序起不来（Runner 返回错误，例如找不到可执行文件）。
    spawn_fail: std::sync::Mutex<Option<String>>,
}

impl LabRunner {
    fn new(fake: Arc<FakeRunner>, release: String, desktop: bool, ext: &Path) -> Self {
        LabRunner {
            fake,
            release,
            desktop,
            new_dir: ext.with_file_name("google-chrome.new"),
            new_at_refresh: Default::default(),
            spawn_fail: Default::default(),
        }
    }
}

impl Runner for LabRunner {
    fn run(&self, cmd: &Cmd) -> Result<Output> {
        if cmd.line() == REFRESH {
            self.new_at_refresh
                .lock()
                .unwrap()
                .push(self.new_dir.exists());
        }
        if self.spawn_fail.lock().unwrap().as_deref() == Some(cmd.program.as_str()) {
            self.fake.run(cmd)?;
            anyhow::bail!("{} 无法运行", cmd.program);
        }
        let out = self.fake.run(cmd)?;
        let a = &cmd.args;
        if cmd.program == "gpgv" {
            // 真的 gpgv 验不过时照样把明文写进 --output（VM 165 实测）
            let i = a.iter().position(|x| x == "--output").unwrap();
            fs::write(&a[i + 1], &self.release)?;
        }
        if out.code != 0 {
            return Ok(out);
        }
        if cmd.program == "dpkg-deb" && a[0] == "-x" {
            let deb = fs::read(&a[1])?;
            let t = Path::new(&a[2]);
            fs::create_dir_all(t.join("opt/google/chrome"))?;
            fs::create_dir_all(t.join("etc/cron.daily"))?;
            fs::create_dir_all(t.join("usr/share/applications"))?;
            fs::write(t.join("opt/google/chrome/chrome"), &deb)?;
            fs::write(t.join("opt/google/chrome/product_logo_48.png"), b"png48")?;
            fs::write(t.join("opt/google/chrome/product_logo_256.png"), b"png256")?;
            fs::write(t.join("opt/google/chrome/product_logo_32.xpm"), b"xpm")?;
            fs::write(t.join("etc/cron.daily/google-chrome"), b"#!/bin/sh")?;
            // 允许清单之外的东西（sysext 会把整个 usr/ 盖在只读的系统上）：解开后删掉
            fs::create_dir_all(t.join("usr/lib/systemd/system"))?;
            fs::write(t.join("usr/lib/systemd/system/evil.service"), b"[Service]")?;
            fs::create_dir_all(t.join("usr/bin"))?;
            fs::write(t.join("usr/bin/evil"), b"#!/bin/sh")?;
            fs::write(t.join("usr/bin/google-chrome-stable"), b"#!/bin/sh")?;
            fs::create_dir_all(t.join("opt/other"))?;
            fs::create_dir_all(t.join("usr/share/man/man1"))?;
            fs::create_dir_all(t.join("usr/share/zz-other"))?;
            fs::create_dir_all(t.join("usr/share/applications"))?;
            fs::write(
                t.join("usr/share/applications/org.gnome.Nautilus.desktop"),
                b"[Desktop Entry]",
            )?;
            if self.desktop {
                fs::write(
                    t.join("usr/share/applications/google-chrome.desktop"),
                    DESKTOP,
                )?;
                fs::write(
                    t.join("usr/share/applications/com.google.Chrome.desktop"),
                    DESKTOP,
                )?;
            }
        }
        Ok(out)
    }
}

/// Lab 里的「本机现在」：2026-11-10 12:00（本机时区 UTC+7）。
fn lab_noon() -> chrono::DateTime<chrono::FixedOffset> {
    at("2026-11-10 12:00")
}

/// 本机时区 UTC+7 的某个时刻（`YYYY-MM-DD HH:MM`）。
fn at(s: &str) -> chrono::DateTime<chrono::FixedOffset> {
    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M")
        .unwrap()
        .and_local_timezone(chrono::FixedOffset::east_opt(7 * 3600).unwrap())
        .unwrap()
}

struct Lab {
    _dir: tempfile::TempDir,
    /// 主 agent 的 `SysState` 放在这里（`chrome_window`、`chrome_pause_until`）。
    sys: SysPaths,
    work: PathBuf,
    ext: PathBuf,
    fake: Arc<FakeRunner>,
    runner: Arc<LabRunner>,
    job: ChromeJob,
    cx: JobCtx,
    srv: MockServer,
}

impl Lab {
    /// 源里提供 `deb`（Packages 里写的哈希是 `listed` 的），Release 里的 Packages 哈希与提供的一致。
    async fn new(deb: &[u8], listed: &[u8], desktop: bool) -> Lab {
        let srv = MockServer::start().await;
        let packages = PACKAGES.replace(
            "c58aa0f2cd66179c9f050e062c882d27aa9b9f8c2b7c73fee3498560b5ed0b38",
            &hex256(listed),
        );
        let release = RELEASE.replace(
            "baa2f44e77775b041d34cf8e3498a697ca932152277bf4dbd643a4c9cad046c5",
            &hex256(packages.as_bytes()),
        );
        Mock::given(method("GET"))
            .and(path("/dists/stable/InRelease"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("-----BEGIN PGP SIGNED MESSAGE-----"),
            )
            .mount(&srv)
            .await;
        Mock::given(method("GET"))
            .and(path("/dists/stable/main/binary-amd64/Packages"))
            .respond_with(ResponseTemplate::new(200).set_body_string(packages))
            .mount(&srv)
            .await;
        Mock::given(method("GET"))
            .and(path(DEB_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(deb.to_vec()))
            .mount(&srv)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("var/lib/mastersos/chrome");
        let ext = dir.path().join("var/lib/extensions/google-chrome");
        // 真机上 /var/lib/mastersos 与 /var/lib 本来就在
        fs::create_dir_all(work.parent().unwrap()).unwrap();
        let fake = Arc::new(FakeRunner::new());
        let runner = Arc::new(LabRunner::new(fake.clone(), release, desktop, &ext));
        let sys = SysPaths {
            root: dir.path().into(),
            var_dir: dir.path().join("var/lib/mastersos-system"),
            public_dir: dir.path().join("var/lib/mastersos-public"),
            state_dir: dir.path().join("var/lib/mastersos"),
        };
        let job = ChromeJob::with_paths(runner.clone(), &srv.uri(), work.clone(), ext.clone())
            .with_boot_id(|| Some("this-boot".into()))
            .with_settings(sys.clone())
            .with_now(lab_noon);
        let cx = JobCtx {
            fetcher: Fetcher::from_seed(&Seed {
                server_url: "http://127.0.0.1:9".into(),
                trust: vec![],
                fetch_token: None,
                group: None,
                oidc: None,
                min_version: None,
                school_id: None,
                wifi: vec![],
                school_name: None,
                it_account: None,
            }),
            ident: DeviceIdent {
                serial: None,
                device_id: "d".into(),
            },
            paths: SysPaths::default(),
            runner: runner.clone(),
            current: tokio::sync::watch::channel(None).1,
            reapply: Default::default(),
            identity: None,
            fetch_error: tokio::sync::watch::channel(None).1,
            quiet: tokio::sync::watch::channel(None).1,
        };
        Lab {
            _dir: dir,
            sys,
            work,
            ext,
            fake,
            runner,
            job,
            cx,
            srv,
        }
    }

    /// 已装了某个版本：扩展目录里有 `.mastersos-version` 与一个记号文件。
    fn installed(&self, version: &str) {
        fs::create_dir_all(self.ext.join("opt/google/chrome")).unwrap();
        fs::write(self.ext.join(".mastersos-version"), format!("{version}\n")).unwrap();
        fs::write(self.ext.join("opt/google/chrome/chrome"), b"old").unwrap();
    }

    /// 主 agent 应用设置时写下的 Chrome 更新时段与暂停。
    fn settings(&self, window: Option<&str>, pause: Option<&str>) {
        crate::system::SysState {
            chrome_window: window.map(Into::into),
            chrome_pause_until: pause.map(Into::into),
            ..Default::default()
        }
        .save(&self.sys)
        .unwrap();
    }

    /// 上一次真的查过源（取到并核对了索引）是 `ago` 之前（相对 [`lab_noon`]）。
    fn checked_ago(&self, ago: Duration) {
        fs::create_dir_all(&self.work).unwrap();
        let t = lab_noon().timestamp() - ago.as_secs() as i64;
        fs::write(self.work.join("checked-at"), format!("{t}\n")).unwrap();
    }

    fn checked_at(&self) -> Option<i64> {
        fs::read_to_string(self.work.join("checked-at"))
            .ok()
            .map(|s| s.trim().parse().unwrap())
    }

    fn window_clock(&self) -> Option<i64> {
        fs::read_to_string(self.work.join("window-clock"))
            .ok()
            .map(|s| s.trim().parse().unwrap())
    }

    async fn asked_source(&self) -> bool {
        self.paths_requested()
            .await
            .iter()
            .any(|p| p.ends_with("/InRelease"))
    }

    async fn run(&self) -> ItemResult {
        let r = self.job.update_once().await;
        assert_eq!(r.item, "chrome");
        r
    }

    async fn paths_requested(&self) -> Vec<String> {
        self.srv
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect()
    }

    fn ran(&self, prefix: &str) -> bool {
        self.fake.calls().iter().any(|c| c.starts_with(prefix))
    }

    fn old_untouched(&self) {
        assert_eq!(
            fs::read(self.ext.join("opt/google/chrome/chrome")).unwrap(),
            b"old"
        );
        let parent = self.ext.parent().unwrap();
        let names: Vec<String> = fs::read_dir(parent)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["google-chrome"], "不留半成品");
    }
}

#[tokio::test]
async fn bad_inrelease_signature_stops_before_download() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("154.0.1-1");
    lab.fake
        .respond("gpgv", Output::fail(1, "gpgv: BAD signature"));
    let r = lab.run().await;
    assert!(!r.ok, "{r:?}");
    assert!(r.detail.as_deref().unwrap().contains("signature"), "{r:?}");
    assert!(
        r.detail.as_deref().unwrap().contains("BAD signature"),
        "带上 gpgv 的说明（换子钥时看得出）：{r:?}"
    );
    let req = lab.paths_requested().await;
    assert_eq!(
        req,
        vec!["/dists/stable/InRelease"],
        "验签失败后什么都不再下载：{req:?}"
    );
    assert!(!lab.ran("dpkg-deb") && !lab.ran(REFRESH));
    lab.old_untouched();
    assert!(!lab.work.join("Release").exists(), "没验过的明文不留在盘上");
    // gpgv 的参数：镜像里固定的钥匙，输出到 work/Release
    let w = lab.work.display();
    assert_eq!(
        lab.fake.calls()[0],
        format!("gpgv --keyring {CHROME_KEYRING} --output {w}/Release {w}/InRelease")
    );
}

#[tokio::test]
async fn packages_hash_mismatch_stops_before_download() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("154.0.1-1");
    // Release 里写的 Packages 哈希换成别的
    let job = ChromeJob::with_paths(
        Arc::new(LabRunner::new(
            lab.fake.clone(),
            RELEASE.to_string(),
            true,
            &lab.ext,
        )),
        &lab.srv.uri(),
        lab.work.clone(),
        lab.ext.clone(),
    );
    let r = job.update_once().await;
    assert!(!r.ok);
    assert!(r.detail.as_deref().unwrap().contains("Packages"), "{r:?}");
    assert!(!lab
        .paths_requested()
        .await
        .iter()
        .any(|p| p.ends_with(".deb")));
    lab.old_untouched();
}

#[tokio::test]
async fn wrong_deb_hash_leaves_old_extension() {
    let lab = Lab::new(b"tampered deb", b"real deb", true).await;
    lab.installed("154.0.1-1");
    lab.fake
        .respond("dpkg --compare-versions", Output::fail(1, ""));
    let r = lab.run().await;
    assert!(!r.ok, "{r:?}");
    assert!(r.detail.as_deref().unwrap().contains("sha256"), "{r:?}");
    assert!(lab.paths_requested().await.iter().any(|p| p == DEB_PATH));
    assert!(!lab.ran("dpkg-deb") && !lab.ran(REFRESH));
    lab.old_untouched();
    assert!(
        fs::read_dir(&lab.work).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("deb")),
        "哈希不对的 .deb 不留在盘上"
    );
}

#[tokio::test]
async fn same_version_does_nothing() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("155.0.8059.39-1");
    let r = lab.run().await;
    assert!(r.ok, "{r:?}");
    assert_eq!(r.detail.as_deref(), Some("155.0.8059.39-1"));
    assert!(!lab.ran("dpkg-deb") && !lab.ran(REFRESH) && !lab.ran("dpkg "));
    assert!(
        !lab.work.join("download-started").exists(),
        "没下载就不留时间戳"
    );
    assert!(!lab
        .paths_requested()
        .await
        .iter()
        .any(|p| p.ends_with(".deb")));
    lab.old_untouched();
}

#[tokio::test]
async fn lower_version_is_refused() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("130.0");
    lab.fake.respond("dpkg --compare-versions", Output::ok(""));
    let r = lab.run().await;
    assert!(!r.ok, "{r:?}");
    assert!(
        r.detail
            .as_deref()
            .unwrap()
            .contains("refusing to downgrade"),
        "{r:?}"
    );
    assert!(
        lab.ran("dpkg --compare-versions 155.0.8059.39-1 lt 130.0"),
        "{:?}",
        lab.fake.calls()
    );
    assert!(!lab
        .paths_requested()
        .await
        .iter()
        .any(|p| p.ends_with(".deb")));
    assert!(!lab.ran("dpkg-deb") && !lab.ran(REFRESH));
    lab.old_untouched();
}

#[tokio::test]
async fn compare_versions_error_is_not_an_upgrade() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("130.0");
    lab.fake
        .respond("dpkg --compare-versions", Output::fail(2, "dpkg: error"));
    let r = lab.run().await;
    assert!(!r.ok, "{r:?}");
    assert!(!lab
        .paths_requested()
        .await
        .iter()
        .any(|p| p.ends_with(".deb")));
    lab.old_untouched();
}

#[tokio::test]
async fn first_install_builds_extension() {
    let lab = Lab::new(b"good deb", b"good deb", true).await;
    let r = lab.run().await;
    assert!(r.ok, "{r:?}");
    assert_eq!(r.detail.as_deref(), Some("155.0.8059.39-1"));
    let e = &lab.ext;
    assert_eq!(
        fs::read(e.join("opt/google/chrome/chrome")).unwrap(),
        b"good deb"
    );
    assert!(!e.join("etc").exists(), "deb 里的 etc/ 删掉");
    assert_eq!(
        fs::read_to_string(e.join("usr/lib/extension-release.d/extension-release.google-chrome"))
            .unwrap(),
        "ID=_any\nSYSEXT_SCOPE=system\n"
    );
    assert_eq!(
        fs::read(e.join("usr/share/icons/hicolor/48x48/apps/google-chrome.png")).unwrap(),
        b"png48"
    );
    // 图标主题的缓存是镜像构建时生成的，扩展里新加的主题图标查不到（VM 165 实测 Dock 是通用图标）：
    // .desktop 改指扩展里最大的那张绝对路径，其余不动
    assert_eq!(
        fs::read_to_string(e.join("usr/share/applications/google-chrome.desktop")).unwrap(),
        DESKTOP.replace(
            "Icon=google-chrome\n",
            "Icon=/opt/google/chrome/product_logo_256.png\n"
        )
    );
    assert_eq!(
        fs::read_to_string(e.join(".mastersos-version"))
            .unwrap()
            .trim(),
        "155.0.8059.39-1"
    );
    assert!(!e.with_file_name("google-chrome.new").exists());
    assert_eq!(lab.fake.calls().last().unwrap(), REFRESH);
    assert!(!lab.ran("dpkg --compare-versions"), "没装过就不比");
    // 两个 .desktop 都改指绝对路径
    assert!(
        fs::read_to_string(e.join("usr/share/applications/com.google.Chrome.desktop"))
            .unwrap()
            .contains("Icon=/opt/google/chrome/product_logo_256.png\n")
    );
    // 允许清单：只留 opt/google、usr/bin/google-chrome*、usr/share 里认得的几样，加上我们自己写的
    for gone in [
        "usr/lib/systemd",
        "usr/bin/evil",
        "opt/other",
        "usr/share/zz-other",
        "usr/share/applications/org.gnome.Nautilus.desktop",
    ] {
        assert!(!e.join(gone).exists(), "{gone} 应被删掉");
    }
    for kept in [
        "usr/bin/google-chrome-stable",
        "usr/share/man/man1",
        "usr/lib/extension-release.d/extension-release.google-chrome",
    ] {
        assert!(e.join(kept).exists(), "{kept} 应保留");
    }
    // 记下签名索引的日期，之后更旧的索引不收
    assert_eq!(
        fs::read_to_string(lab.work.join("release-date"))
            .unwrap()
            .trim(),
        RELEASE_EPOCH.to_string()
    );
    assert!(!lab.work.join("chrome.deb").exists(), "装完删掉 .deb");
    assert!(
        lab.work.join("download-started").exists(),
        "下载 .deb 之前留下时间戳（NetworkManager 钩子据此限流）"
    );
}

#[tokio::test]
async fn missing_desktop_file_is_an_error() {
    let lab = Lab::new(b"good deb", b"good deb", false).await;
    let r = lab.run().await;
    assert!(!r.ok, "{r:?}");
    assert!(
        r.detail
            .as_deref()
            .unwrap()
            .contains("google-chrome.desktop"),
        "{r:?}"
    );
    assert!(!lab.ext.exists() && !lab.ext.with_file_name("google-chrome.new").exists());
    assert!(!lab.ran(REFRESH));
}

#[tokio::test]
async fn leftover_new_dir_is_cleared_and_refreshed() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("155.0.8059.39-1");
    // 上一轮在互换之后、refresh 之前断电：换下来的旧目录还在 .new
    fs::create_dir_all(lab.ext.with_file_name("google-chrome.new").join("opt")).unwrap();
    let r = lab.run().await;
    assert!(r.ok, "{r:?}");
    assert!(!lab.ext.with_file_name("google-chrome.new").exists());
    // 先合并（.new 可能正是合并着的那一层）、再删
    assert_eq!(*lab.runner.new_at_refresh.lock().unwrap(), vec![true]);
    assert!(!lab.ran("dpkg-deb"));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn upgrade_swaps_and_removes_old() {
    let lab = Lab::new(b"new deb", b"new deb", true).await;
    lab.installed("154.0.1-1");
    lab.fake
        .respond("dpkg --compare-versions", Output::fail(1, ""));
    let r = lab.run().await;
    assert!(r.ok, "{r:?}");
    assert_eq!(
        fs::read(lab.ext.join("opt/google/chrome/chrome")).unwrap(),
        b"new deb"
    );
    assert!(
        !lab.ext.with_file_name("google-chrome.new").exists(),
        "换下来的旧目录删掉"
    );
    let calls = lab.fake.calls();
    let refresh = calls.iter().position(|c| c == REFRESH).unwrap();
    assert_eq!(refresh, calls.len() - 1);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn refresh_failure_swaps_back() {
    let lab = Lab::new(b"new deb", b"new deb", true).await;
    lab.installed("154.0.1-1");
    lab.fake
        .respond("dpkg --compare-versions", Output::fail(1, ""));
    lab.fake.respond(REFRESH, Output::fail(1, "boom"));
    let r = lab.run().await;
    assert!(!r.ok, "{r:?}");
    assert!(r.detail.as_deref().unwrap().contains("systemctl"), "{r:?}");
    // 换回旧的之后再合并一次（失败的那次可能已经卸下了旧的），成功了才删 .new
    assert_eq!(*lab.runner.new_at_refresh.lock().unwrap(), vec![true, true]);
    lab.old_untouched();
    assert_eq!(
        fs::read_to_string(lab.ext.join(".mastersos-version"))
            .unwrap()
            .trim(),
        "154.0.1-1"
    );
}

#[test]
fn reads_release_date() {
    assert_eq!(release_date(RELEASE), Some(RELEASE_EPOCH));
    assert_eq!(
        release_date("Date: Tue, 13 Oct 2026 09:06:51 +0000\n"),
        Some(RELEASE_EPOCH)
    );
    assert_eq!(release_date("Origin: x\n"), None);
    assert_eq!(release_date("Date: yesterday\n"), None);
}

#[tokio::test]
async fn replayed_older_index_is_refused() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("154.0.1-1");
    fs::create_dir_all(&lab.work).unwrap();
    fs::write(
        lab.work.join("release-date"),
        format!("{}\n", RELEASE_EPOCH + 1),
    )
    .unwrap();
    let r = lab.run().await;
    assert!(!r.ok, "{r:?}");
    assert!(r.detail.as_deref().unwrap().contains("replay"), "{r:?}");
    let req = lab.paths_requested().await;
    assert_eq!(req, vec!["/dists/stable/InRelease"], "{req:?}");
    lab.old_untouched();
    // 下限不被调低
    assert_eq!(
        fs::read_to_string(lab.work.join("release-date"))
            .unwrap()
            .trim(),
        (RELEASE_EPOCH + 1).to_string()
    );
}

#[tokio::test]
async fn same_index_date_is_accepted() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("155.0.8059.39-1");
    fs::create_dir_all(&lab.work).unwrap();
    fs::write(lab.work.join("release-date"), RELEASE_EPOCH.to_string()).unwrap();
    assert!(lab.run().await.ok);
}

#[tokio::test]
async fn second_updater_is_locked_out() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    fs::create_dir_all(&lab.work).unwrap();
    let held = safefs::open_abs_dir(&lab.work, false).unwrap();
    rustix::fs::flock(&held, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    let r = lab.run().await;
    assert!(!r.ok, "{r:?}");
    assert!(
        r.detail
            .as_deref()
            .unwrap()
            .contains("another Chrome update"),
        "{r:?}"
    );
    assert!(lab.paths_requested().await.is_empty());
    assert!(
        !lab.work.join("result.json").exists(),
        "锁不到的那一轮不写结果（不覆盖正在跑的那一轮的）"
    );
    drop(held);
    assert!(lab.run().await.ok, "锁放开之后照常");
}

#[tokio::test]
async fn status_job_reports_last_result() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    assert!(
        status_at(&lab, Duration::from_secs(60), "this-boot")
            .run(&lab.cx)
            .await
            .is_empty(),
        "开机不久还没跑过：没有这一项"
    );
    // 与 mastersos-agent chrome 写结果时同一次开机、同一个单调时钟
    let status = ChromeStatus::with_clock(
        lab.work.clone(),
        Box::new(monotonic_now),
        Box::new(|| Some("this-boot".into())),
    );
    lab.installed("155.0.8059.39-1");
    let r = lab.run().await;
    assert_eq!(status.run(&lab.cx).await, vec![r]);
    lab.fake.respond("gpgv", Output::fail(1, "BAD"));
    let r = lab.run().await;
    assert!(!r.ok);
    assert_eq!(status.run(&lab.cx).await, vec![r]);
}

// ---- 失败即拒绝（fail closed）：每个校验在出错、读不懂时都拒绝，不当成「通过」 ----

#[test]
fn ambiguous_release_lines_are_not_trusted() {
    // 同一路径在 SHA256 段里出现两次（哪怕哈希相同也不猜）
    let dup = format!(
        "SHA256:\n {a} 1 main/binary-amd64/Packages\n {b} 1 main/binary-amd64/Packages\n",
        a = "a".repeat(64),
        b = "b".repeat(64)
    );
    assert_eq!(release_sha256(&dup, "main/binary-amd64/Packages"), None);
    // 两个 SHA256 段
    let two = format!(
        "{RELEASE}SHA256:\n {} 1 main/binary-amd64/Packages\n",
        "c".repeat(64)
    );
    assert_eq!(release_sha256(&two, "main/binary-amd64/Packages"), None);
    // 两行 Date
    let d = "Date: Tue, 13 Oct 2026 09:06:51 UTC\nDate: Tue, 13 Oct 2099 09:06:51 UTC\n";
    assert_eq!(release_date(d), None);
}

#[test]
fn duplicate_field_in_stanza_is_an_error() {
    let entry = find_package(PACKAGES, STABLE).unwrap();
    let p = PACKAGES.replace(
        &format!("SHA256: {}", entry.sha256),
        &format!("SHA256: {}\nSHA256: {}", "d".repeat(64), entry.sha256),
    );
    let e = find_package(&p, STABLE).unwrap_err();
    assert!(format!("{e:#}").contains("SHA256"), "{e:#}");
}

#[tokio::test]
async fn unreadable_date_floor_refuses() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("154.0.1-1");
    fs::create_dir_all(&lab.work).unwrap();
    fs::write(lab.work.join("release-date"), "garbage\n").unwrap();
    let r = lab.run().await;
    assert!(!r.ok, "{r:?}");
    assert!(
        r.detail.as_deref().unwrap().contains("release-date"),
        "{r:?}"
    );
    assert_eq!(lab.paths_requested().await, vec!["/dists/stable/InRelease"]);
    lab.old_untouched();
    assert_eq!(
        fs::read_to_string(lab.work.join("release-date")).unwrap(),
        "garbage\n",
        "不覆盖读不懂的下限"
    );
}

#[tokio::test]
async fn release_without_date_refuses() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("154.0.1-1");
    let job = ChromeJob::with_paths(
        Arc::new(LabRunner::new(
            lab.fake.clone(),
            RELEASE.replace("Date: ", "X-Date: "),
            true,
            &lab.ext,
        )),
        &lab.srv.uri(),
        lab.work.clone(),
        lab.ext.clone(),
    );
    let r = job.update_once().await;
    assert!(!r.ok, "{r:?}");
    assert!(r.detail.as_deref().unwrap().contains("Date"), "{r:?}");
    lab.old_untouched();
}

#[tokio::test]
async fn extension_without_version_file_refuses() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("154.0.1-1");
    fs::remove_file(lab.ext.join(".mastersos-version")).unwrap();
    let r = lab.run().await;
    assert!(!r.ok, "{r:?}");
    assert!(
        r.detail.as_deref().unwrap().contains(".mastersos-version"),
        "{r:?}"
    );
    assert!(!lab
        .paths_requested()
        .await
        .iter()
        .any(|p| p.ends_with(".deb")));
    assert!(!lab.ran("dpkg-deb"));
}

#[tokio::test]
async fn empty_version_file_refuses() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("");
    let r = lab.run().await;
    assert!(!r.ok, "{r:?}");
    assert!(!lab
        .paths_requested()
        .await
        .iter()
        .any(|p| p.ends_with(".deb")));
}

#[tokio::test]
async fn compare_versions_that_cannot_run_refuses() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("130.0");
    *lab.runner.spawn_fail.lock().unwrap() = Some("dpkg".into());
    let r = lab.run().await;
    assert!(!r.ok, "{r:?}");
    assert!(r.detail.as_deref().unwrap().contains("dpkg"), "{r:?}");
    assert!(!lab
        .paths_requested()
        .await
        .iter()
        .any(|p| p.ends_with(".deb")));
    lab.old_untouched();
}

#[tokio::test]
async fn gpgv_that_cannot_run_refuses() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("154.0.1-1");
    *lab.runner.spawn_fail.lock().unwrap() = Some("gpgv".into());
    let r = lab.run().await;
    assert!(!r.ok, "{r:?}");
    assert_eq!(lab.paths_requested().await, vec!["/dists/stable/InRelease"]);
    lab.old_untouched();
}

#[tokio::test]
async fn oversized_deb_is_refused() {
    // Content-Length 说超过上限：不读、不留文件（上限之内、流里超的那一支由同一个计数挡住）
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.fake
        .respond("dpkg --compare-versions", Output::fail(1, ""));
    lab.installed("154.0.1-1");
    let job = ChromeJob::with_paths(
        lab.runner.clone(),
        &lab.srv.uri(),
        lab.work.clone(),
        lab.ext.clone(),
    )
    .max_deb_bytes(2);
    let r = job.update_once().await;
    assert!(!r.ok, "{r:?}");
    assert!(r.detail.as_deref().unwrap().contains("size limit"), "{r:?}");
    assert!(!lab.ran("dpkg-deb"));
    lab.old_untouched();
}

#[test]
fn prune_refuses_symlinked_levels() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::create_dir_all(outside.path().join("lib/systemd")).unwrap();
    fs::create_dir(root.path().join("opt")).unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("usr")).unwrap();
    let fd = safefs::open_dir(root.path(), Path::new(""), false).unwrap();
    let e = format!("{:#}", prune_tree(&fd).unwrap_err());
    assert!(e.contains("Symlink") || e.contains("symlink"), "{e}");
    assert!(
        outside.path().join("lib/systemd").exists(),
        "不跟随链接去删"
    );
    // usr 是普通文件也不行
    fs::remove_file(root.path().join("usr")).unwrap();
    fs::write(root.path().join("usr"), b"x").unwrap();
    assert!(prune_tree(&fd).is_err());
}

#[test]
fn duplicate_package_line_is_an_error() {
    let p = PACKAGES.replace(
        "Package: google-chrome-stable",
        "Package: google-chrome-stable\nPackage: other",
    );
    let e = find_package(&p, STABLE).unwrap_err();
    assert!(format!("{e:#}").contains("Package"), "{e:#}");
}

#[test]
fn allowlisted_entries_must_have_the_right_type() {
    let mk = || {
        let root = tempfile::tempdir().unwrap();
        for d in ["opt/google/chrome", "usr/share/applications", "usr/bin"] {
            fs::create_dir_all(root.path().join(d)).unwrap();
        }
        root
    };
    // usr/share/icons 是普通文件：合并后会盖住整个 /usr/share/icons
    let root = mk();
    fs::write(root.path().join("usr/share/icons"), b"x").unwrap();
    let fd = safefs::open_dir(root.path(), Path::new(""), false).unwrap();
    let e = prune_tree(&fd).unwrap_err();
    assert!(format!("{e:#}").contains("usr/share/icons"), "{e:#}");
    // usr/share/doc 是符号链接
    let root = mk();
    std::os::unix::fs::symlink("/etc", root.path().join("usr/share/doc")).unwrap();
    let fd = safefs::open_dir(root.path(), Path::new(""), false).unwrap();
    assert!(prune_tree(&fd).is_err());
    // usr/bin/google-chrome-stable 是指向 /opt 的链接（deb 里就是这样）：允许；是目录则不行
    let root = mk();
    std::os::unix::fs::symlink(
        "/opt/google/chrome/google-chrome",
        root.path().join("usr/bin/google-chrome-stable"),
    )
    .unwrap();
    let fd = safefs::open_dir(root.path(), Path::new(""), false).unwrap();
    assert_eq!(prune_tree(&fd).unwrap(), Vec::<String>::new());
    fs::create_dir(root.path().join("usr/bin/google-chrome-x")).unwrap();
    assert!(prune_tree(&fd).is_err());
    // .desktop 是指向别处的链接
    let root = mk();
    std::os::unix::fs::symlink(
        "/usr/share/applications/org.gnome.Nautilus.desktop",
        root.path()
            .join("usr/share/applications/google-chrome.desktop"),
    )
    .unwrap();
    let fd = safefs::open_dir(root.path(), Path::new(""), false).unwrap();
    assert!(prune_tree(&fd).is_err());
}

#[tokio::test]
async fn result_is_rewritten_every_round() {
    // 同样的内容也要重写：ChromeStatus 按 mtime 判断最近有没有跑完一轮
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("155.0.8059.39-1");
    assert!(lab.run().await.ok);
    let p = lab.work.join("result.json");
    let old = SystemTime::now() - Duration::from_secs(20 * 3600);
    fs::File::options()
        .write(true)
        .open(&p)
        .unwrap()
        .set_modified(old)
        .unwrap();
    assert!(lab.run().await.ok);
    let m = fs::metadata(&p).unwrap().modified().unwrap();
    assert!(m > old + Duration::from_secs(3600), "{m:?}");
}

fn status_at(lab: &Lab, mono: Duration, boot: &str) -> ChromeStatus {
    let boot = boot.to_string();
    ChromeStatus::with_clock(
        lab.work.clone(),
        Box::new(move || mono),
        Box::new(move || Some(boot.clone())),
    )
}

fn saved_monotonic(lab: &Lab) -> Duration {
    let v: serde_json::Value =
        serde_json::from_slice(&fs::read(lab.work.join("result.json")).unwrap()).unwrap();
    assert_eq!(v["boot_id"], "this-boot", "{v}");
    Duration::from_secs(v["monotonic_secs"].as_u64().unwrap())
}

const H: u64 = 3600;

#[tokio::test]
async fn status_without_any_result_waits_for_grace_on_the_monotonic_clock() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    assert!(status_at(&lab, Duration::from_secs(30 * 60), "this-boot")
        .run(&lab.cx)
        .await
        .is_empty());
    let r = status_at(&lab, Duration::from_secs(2 * H), "this-boot")
        .run(&lab.cx)
        .await;
    assert!(
        !r[0].ok
            && r[0]
                .detail
                .as_deref()
                .unwrap()
                .contains("has ever finished"),
        "{r:?}"
    );
}

#[tokio::test]
async fn suspend_does_not_make_the_result_stale() {
    // 合盖一夜：墙上时间过了 16 小时，单调时钟（与定时器同一个）只走了 1 小时——不是「没跑」
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("155.0.8059.39-1");
    let ok = lab.run().await;
    let p = lab.work.join("result.json");
    fs::File::options()
        .write(true)
        .open(&p)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(16 * H))
        .unwrap();
    let t0 = saved_monotonic(&lab);
    assert_eq!(
        status_at(&lab, t0 + Duration::from_secs(H), "this-boot")
            .run(&lab.cx)
            .await,
        vec![ok.clone()]
    );
    assert_eq!(
        status_at(&lab, t0 + Duration::from_secs(13 * H), "this-boot")
            .run(&lab.cx)
            .await,
        vec![ok]
    );
    // 醒着过了 15 小时还没有新结果：真的没跑
    let r = status_at(&lab, t0 + Duration::from_secs(15 * H), "this-boot")
        .run(&lab.cx)
        .await;
    assert!(!r[0].ok, "{r:?}");
    let d = r[0].detail.as_deref().unwrap();
    assert!(
        d.contains("hours without a finished") && d.contains("155.0.8059.39-1"),
        "{d}"
    );
}

#[tokio::test]
async fn result_from_previous_boot_is_kept_until_grace() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("155.0.8059.39-1");
    assert!(lab.run().await.ok);
    // 重启后 10 分钟：照报上次开机的结果（注明），不报失败
    let r = status_at(&lab, Duration::from_secs(10 * 60), "next-boot")
        .run(&lab.cx)
        .await;
    assert!(r[0].ok, "{r:?}");
    let d = r[0].detail.as_deref().unwrap();
    assert!(
        d.contains("155.0.8059.39-1") && d.contains("previous boot"),
        "{d}"
    );
    // 这次开机 2 小时还没跑完一轮：失败
    let r = status_at(&lab, Duration::from_secs(2 * H), "next-boot")
        .run(&lab.cx)
        .await;
    assert!(!r[0].ok, "{r:?}");
    assert!(
        r[0].detail
            .as_deref()
            .unwrap()
            .contains("in this boot without"),
        "{r:?}"
    );
    // 读不出 boot id：当作不同的一次开机（宽限之后失败）
    let s = ChromeStatus::with_clock(
        lab.work.clone(),
        Box::new(|| Duration::from_secs(2 * H)),
        Box::new(|| None),
    );
    assert!(!s.run(&lab.cx).await[0].ok);
}

#[tokio::test]
async fn failed_deb_request_does_not_arm_the_hook_limit() {
    // 取到索引、.deb 的请求却立即失败（还没收到任何字节）：不留 download-started，钩子下次连网照样能触发
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("154.0.1-1");
    lab.fake
        .respond("dpkg --compare-versions", Output::fail(1, ""));
    Mock::given(method("GET"))
        .and(path(DEB_PATH))
        .respond_with(ResponseTemplate::new(404))
        .with_priority(1)
        .mount(&lab.srv)
        .await;
    let r = lab.run().await;
    assert!(!r.ok, "{r:?}");
    assert!(!lab.work.join("download-started").exists());
}

#[tokio::test]
async fn floor_error_says_how_to_recover() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("154.0.1-1");
    fs::create_dir_all(&lab.work).unwrap();
    fs::write(
        lab.work.join("release-date"),
        format!("{}\n", RELEASE_EPOCH + 1),
    )
    .unwrap();
    let r = lab.run().await;
    assert!(
        r.detail
            .as_deref()
            .unwrap()
            .contains("/var/lib/mastersos/chrome/release-date"),
        "{r:?}"
    );
}

#[tokio::test]
async fn index_fetch_is_retried() {
    // 刚连上网时 DNS 往往还没好：取索引失败稍后重试几次，不必等 6 小时的定时器
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/dists/stable/InRelease"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(2)
        .mount(&srv)
        .await;
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("155.0.8059.39-1");
    // 前两次 503（挂在另一个服务器上），第三次转到 lab 的服务器
    let job = ChromeJob::with_paths(
        lab.runner.clone(),
        &srv.uri(),
        lab.work.clone(),
        lab.ext.clone(),
    )
    .retry_delays(vec![Duration::ZERO, Duration::ZERO]);
    let r = job.update_once().await;
    assert!(!r.ok, "三次都失败才报失败：{r:?}");
    assert_eq!(srv.received_requests().await.unwrap().len(), 3, "试三次");
    // 503 两次之后就好了
    srv.reset().await;
    Mock::given(method("GET"))
        .and(path("/dists/stable/InRelease"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(2)
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path("/dists/stable/InRelease"))
        .respond_with(ResponseTemplate::new(200).set_body_string("x"))
        .mount(&srv)
        .await;
    let packages = reqwest::get(format!(
        "{}/dists/stable/main/binary-amd64/Packages",
        lab.srv.uri()
    ))
    .await
    .unwrap()
    .text()
    .await
    .unwrap();
    Mock::given(method("GET"))
        .and(path("/dists/stable/main/binary-amd64/Packages"))
        .respond_with(ResponseTemplate::new(200).set_body_string(packages))
        .mount(&srv)
        .await;
    let r = job.update_once().await;
    assert!(r.ok, "第三次取到了：{r:?}");
}

// ---- Task 23：更新时段与暂停 ----

#[tokio::test]
async fn outside_window_skips_download_and_reports_ok() {
    let lab = Lab::new(b"new deb", b"new deb", true).await;
    lab.installed("154.0.1-1");
    lab.settings(Some("16:00-07:00"), None);
    let r = lab.run().await;
    assert!(r.ok, "{r:?}");
    let d = r.detail.as_deref().unwrap();
    assert!(
        d.contains("waiting for the update window") && d.contains("16:00-07:00"),
        "{d}"
    );
    assert!(d.contains("154.0.1-1"), "带上当前版本：{d}");
    assert!(
        lab.paths_requested().await.is_empty(),
        "不发 InRelease 请求：{:?}",
        lab.paths_requested().await
    );
    assert!(!lab.ran("gpgv") && !lab.ran("dpkg"));
    lab.old_untouched();
    // 结果照样写进 result.json（ChromeStatus 回报它）
    assert!(lab.work.join("result.json").exists());
}

#[tokio::test]
async fn paused_skips_download() {
    let lab = Lab::new(b"new deb", b"new deb", true).await;
    lab.installed("154.0.1-1");
    // 暂停到今天（含）：今天也不换
    lab.settings(Some("11:00-14:00"), Some("2026-11-10"));
    let r = lab.run().await;
    assert!(r.ok, "{r:?}");
    let d = r.detail.as_deref().unwrap();
    assert!(
        d.contains("paused until 2026-11-10") && d.contains("154.0.1-1"),
        "{d}"
    );
    assert!(lab.paths_requested().await.is_empty());
    lab.old_untouched();
    // 暂停已过（昨天为止）、又在时段内：照常查源
    lab.settings(Some("11:00-14:00"), Some("2026-11-09"));
    let r = lab.run().await;
    assert!(
        lab.paths_requested()
            .await
            .iter()
            .any(|p| p.ends_with("/InRelease")),
        "{r:?}"
    );
}

#[tokio::test]
async fn first_install_ignores_window_and_pause() {
    let lab = Lab::new(b"good deb", b"good deb", true).await;
    lab.settings(Some("16:00-07:00"), Some("2026-11-20"));
    let r = lab.run().await;
    assert!(r.ok, "{r:?}");
    assert_eq!(r.detail.as_deref(), Some("155.0.8059.39-1"));
    assert_eq!(
        fs::read(lab.ext.join("opt/google/chrome/chrome")).unwrap(),
        b"good deb"
    );
}

#[tokio::test]
async fn no_downgrade_unchanged_when_window_opens() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("160.0");
    lab.settings(Some("11:00-14:00"), Some("2026-11-01"));
    lab.fake.respond("dpkg --compare-versions", Output::ok(""));
    let r = lab.run().await;
    assert!(!r.ok, "{r:?}");
    assert!(
        r.detail
            .as_deref()
            .unwrap()
            .contains("refusing to downgrade"),
        "{r:?}"
    );
    assert!(!lab
        .paths_requested()
        .await
        .iter()
        .any(|p| p.ends_with(".deb")));
    lab.old_untouched();
}

#[tokio::test]
async fn unmanaged_machine_unaffected() {
    // 没有种子的机器：没有 system-state.json（连目录都没有）→ 照常查源
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("155.0.8059.39-1");
    assert!(!lab.sys.var_dir.exists());
    let r = lab.run().await;
    assert!(r.ok, "{r:?}");
    assert_eq!(r.detail.as_deref(), Some("155.0.8059.39-1"));
    assert!(lab
        .paths_requested()
        .await
        .iter()
        .any(|p| p.ends_with("/InRelease")));
    assert!(!lab.sys.var_dir.exists(), "只读，不建目录");
    // 受管但这两项没设、或状态文件坏了：同样照常（宁可更新，也不因读不懂而一直不更新）
    for text in [&b"{}"[..], b"{garbage"] {
        fs::create_dir_all(&lab.sys.var_dir).unwrap();
        fs::write(lab.sys.var_dir.join("system-state.json"), text).unwrap();
        let before = lab.paths_requested().await.len();
        let r = lab.run().await;
        assert!(r.ok, "{r:?}");
        assert!(lab.paths_requested().await.len() > before);
    }
    // 设了、但值读不懂（只可能是手改的）：不限制
    lab.settings(Some("bad"), Some("bad"));
    let before = lab.paths_requested().await.len();
    assert!(lab.run().await.ok);
    assert!(lab.paths_requested().await.len() > before);
}

// ---- Task 23 复审修复 1 ----

const DAY: Duration = Duration::from_secs(86_400);
const HOUR: Duration = Duration::from_secs(3600);

/// 复审 I1：只因时段被挡、而上一次真的查源已超过 7 天（例如推车夜里都关机）——不再等，这一轮照常查，detail 里说明。
#[tokio::test]
async fn window_is_overridden_after_7_days_without_a_check() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("155.0.8059.39-1");
    lab.settings(Some("16:00-07:00"), None);
    lab.checked_ago(8 * DAY);
    let r = lab.run().await;
    assert!(r.ok, "{r:?}");
    assert!(lab.asked_source().await);
    let d = r.detail.unwrap();
    assert!(
        d.contains("155.0.8059.39-1") && d.contains("超过 7 天"),
        "{d}"
    );
    assert_eq!(
        lab.checked_at(),
        Some(lab_noon().timestamp()),
        "真查过源：记下时刻"
    );
}

/// 7 天以内照样等；还没有记录（升级上来的机器）时从现在开始算，不立刻破例。
#[tokio::test]
async fn window_holds_within_7_days_and_starts_the_clock() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("154.0.1-1");
    lab.settings(Some("16:00-07:00"), None);
    let r = lab.run().await;
    assert!(r.detail.unwrap().contains("waiting for the update window"));
    assert!(!lab.asked_source().await);
    assert_eq!(lab.checked_at(), None, "没查源就不写 checked-at（复审 N3）");
    assert_eq!(
        lab.window_clock(),
        Some(lab_noon().timestamp()),
        "从现在开始算 7 天"
    );
    lab.checked_ago(6 * DAY);
    let r = lab.run().await;
    assert!(r.detail.unwrap().contains("waiting for the update window"));
    assert!(!lab.asked_source().await);
    assert_eq!(
        lab.checked_at(),
        Some(lab_noon().timestamp() - (6 * DAY).as_secs() as i64),
        "被挡下的一轮不改记录"
    );
}

/// 暂停不破例（它本来最多 14 天）。
#[tokio::test]
async fn pause_is_never_overridden() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("154.0.1-1");
    lab.settings(Some("16:00-07:00"), Some("2026-11-12"));
    lab.checked_ago(30 * DAY);
    let r = lab.run().await;
    assert!(r.detail.unwrap().contains("paused until 2026-11-12"));
    assert!(!lab.asked_source().await);
}

/// 定时器触发（`--scheduled`）、没设时段：上一次查源不到 6 小时就不联网；手动跑（不带 --scheduled）照查；
/// 设了时段的机器在时段内每小时都查。
#[tokio::test]
async fn scheduled_round_without_window_checks_at_most_every_6_hours() {
    let mut lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("155.0.8059.39-1");
    lab.job = lab.job.scheduled(true);
    lab.checked_ago(HOUR);
    let r = lab.run().await;
    assert!(r.ok, "{r:?}");
    assert_eq!(r.detail.as_deref(), Some("155.0.8059.39-1"));
    assert!(!lab.asked_source().await, "不到 6 小时：不联网");
    // 设了时段、正在时段内：每小时都查
    lab.settings(Some("11:00-14:00"), None);
    assert!(lab.run().await.ok);
    assert!(lab.asked_source().await);
    // 没设时段、上一次查过 7 小时：查
    let mut lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("155.0.8059.39-1");
    lab.job = lab.job.scheduled(true);
    lab.checked_ago(7 * HOUR);
    assert!(lab.run().await.ok);
    assert!(lab.asked_source().await);
    // 手动跑（IT 在 shell 里）：不看 6 小时
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("155.0.8059.39-1");
    lab.checked_ago(HOUR);
    assert!(lab.run().await.ok);
    assert!(lab.asked_source().await);
}

/// 时段与暂停的判断（纯函数）：跨午夜的两端、写进 SysState 的离谱日期（复审 M1、M8）。
#[test]
fn hold_reason_edges() {
    let sys = |w: Option<&str>, p: Option<&str>| crate::system::SysState {
        chrome_window: w.map(Into::into),
        chrome_pause_until: p.map(Into::into),
        ..Default::default()
    };
    let w = sys(Some("16:00-07:00"), None);
    assert!(hold_reason(&w, at("2026-11-10 06:59")).is_none());
    assert!(matches!(
        hold_reason(&w, at("2026-11-10 07:00")),
        Some(Hold::Window(_))
    ));
    assert!(matches!(
        hold_reason(&w, at("2026-11-10 15:59")),
        Some(Hold::Window(_))
    ));
    assert!(hold_reason(&w, at("2026-11-10 16:00")).is_none());
    match hold_reason(&w, at("2026-11-10 12:00")) {
        Some(Hold::Window(d)) => assert!(d.contains("UTC+7"), "{d}"),
        other => panic!("{other:?}"),
    }
    // 暂停到今天（含）在暂停；离今天超过 14 天（+1 天余量）的不当真
    assert!(matches!(
        hold_reason(&sys(None, Some("2026-11-10")), at("2026-11-10 23:59")),
        Some(Hold::Pause(_))
    ));
    assert!(hold_reason(&sys(None, Some("2026-11-09")), at("2026-11-10 00:00")).is_none());
    assert!(matches!(
        hold_reason(&sys(None, Some("2026-11-25")), at("2026-11-10 12:00")),
        Some(Hold::Pause(_))
    ));
    assert!(hold_reason(&sys(None, Some("2027-01-01")), at("2026-11-10 12:00")).is_none());
    // 太短的时段（只可能是手改的）：不限
    assert!(hold_reason(&sys(Some("16:30-17:00"), None), at("2026-11-10 12:00")).is_none());
}

// ---- Task 23 复审修复 2 ----

/// 复审 N1：查到 Packages 之后失败（这里是 .deb 的哈希不对）——不写 checked-at，下一轮定时器照常重试；
/// 被 6 小时限流跳过的轮次不覆盖上一轮的结果（失败照样是失败）。
#[tokio::test]
async fn failure_after_index_is_retried_and_not_hidden_by_the_throttle() {
    let mut lab = Lab::new(b"deb", b"other", true).await;
    lab.installed("154.0.1-1");
    lab.fake
        .respond("dpkg --compare-versions", Output::fail(1, ""));
    lab.job = lab.job.scheduled(true);
    let r = lab.run().await;
    assert!(!r.ok, "{r:?}");
    assert_eq!(lab.checked_at(), None, "失败的一轮不写 checked-at");
    let before = lab.paths_requested().await.len();
    assert!(!lab.run().await.ok);
    assert!(lab.paths_requested().await.len() > before, "下一轮照常重试");
    // 一小时前成功查过（checked-at 新），之后手动跑失败了：定时器那一轮跳过，但回报的仍是那次失败
    lab.checked_ago(HOUR);
    let failed = lab.run().await;
    assert!(!failed.ok);
    let before = lab.paths_requested().await.len();
    let r = lab.run().await;
    assert_eq!(lab.paths_requested().await.len(), before, "限流：不联网");
    assert_eq!(r, failed, "保留上一轮的结果");
    let saved: serde_json::Value =
        serde_json::from_slice(&fs::read(lab.work.join("result.json")).unwrap()).unwrap();
    assert_eq!(saved["ok"], false);
}

/// 复审 N1：同版本（已是最新）算成功，写 checked-at；拒绝降级不写。
#[tokio::test]
async fn checked_at_only_after_a_successful_round() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("155.0.8059.39-1");
    assert!(lab.run().await.ok);
    assert_eq!(lab.checked_at(), Some(lab_noon().timestamp()));
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("160.0");
    lab.fake.respond("dpkg --compare-versions", Output::ok(""));
    assert!(!lab.run().await.ok);
    assert_eq!(lab.checked_at(), None);
}

/// 复审 N1：被时段挡下的一轮，上一轮失败时仍回报失败（带上在等的原因）。
#[tokio::test]
async fn held_round_keeps_a_previous_failure() {
    let lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("160.0");
    lab.fake.respond("dpkg --compare-versions", Output::ok(""));
    assert!(!lab.run().await.ok, "refusing to downgrade");
    lab.settings(Some("16:00-07:00"), None);
    let r = lab.run().await;
    assert!(!r.ok, "{r:?}");
    let d = r.detail.unwrap();
    assert!(
        d.contains("refusing to downgrade") && d.contains("waiting for the update window"),
        "{d}"
    );
    let again = lab.run().await;
    assert_eq!(again.detail.unwrap(), d, "连着被挡下不越接越长");
}

fn nov21_0740() -> chrono::DateTime<chrono::FixedOffset> {
    at("2026-11-21 07:40")
}
fn nov28_0740() -> chrono::DateTime<chrono::FixedOffset> {
    at("2026-11-28 07:40")
}

/// 复审 N2：brief 的例子——放学后的时段加考试周暂停。暂停期间不算进 7 天，暂停结束后的第一个早上不在上课时更新；
/// 暂停结束 7 天以后仍没查过源才破例。
#[tokio::test]
async fn pause_days_do_not_count_toward_the_window_override() {
    let mut lab = Lab::new(b"deb", b"deb", true).await;
    lab.installed("155.0.8059.39-1");
    lab.settings(Some("16:00-07:00"), Some("2026-11-20"));
    fs::create_dir_all(&lab.work).unwrap();
    let t = at("2026-11-11 16:30").timestamp();
    fs::write(lab.work.join("checked-at"), format!("{t}\n")).unwrap();
    lab.job = lab.job.with_now(nov21_0740);
    let r = lab.run().await;
    assert!(
        r.detail.unwrap().contains("waiting for the update window"),
        "暂停刚结束：照样等时段"
    );
    assert!(!lab.asked_source().await);
    lab.job = lab.job.with_now(nov28_0740);
    let r = lab.run().await;
    assert!(
        r.detail.unwrap().contains("超过 7 天"),
        "暂停结束 7 天后破例"
    );
    assert!(lab.asked_source().await);
}

/// 复审 N4：checked-at 读不懂、或在将来超过一天（时钟被往回拨过）：当作没有记录，时段照样等、从现在开始算。
#[tokio::test]
async fn corrupt_or_future_checked_at_holds_and_restarts_the_clock() {
    for content in [
        "garbage".to_string(),
        format!("{}", lab_noon().timestamp() + 30 * 86_400),
    ] {
        let lab = Lab::new(b"deb", b"deb", true).await;
        lab.installed("155.0.8059.39-1");
        lab.settings(Some("16:00-07:00"), None);
        fs::create_dir_all(&lab.work).unwrap();
        fs::write(lab.work.join("checked-at"), &content).unwrap();
        let r = lab.run().await;
        assert!(
            r.ok && r.detail.unwrap().contains("waiting for the update window"),
            "{content}"
        );
        assert!(!lab.asked_source().await);
        assert_eq!(
            lab.window_clock(),
            Some(lab_noon().timestamp()),
            "{content}"
        );
    }
}
