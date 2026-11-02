//! Chrome 装成 systemd-sysext（Task 9；试验见 `spikes/s2/chrome/mastersos-chrome-sysext.sh`）。
//!
//! Chrome 不打进镜像（spec：Google 的条款一般不许再分发），每 6 小时从 Google 官方 apt 源取一次，
//! 放在可写的 `/var/lib/extensions/google-chrome`，`systemd-sysext` 把它的 `/usr` 与 `/opt` 合并进只读的系统。
//!
//! **只有一条更新路径**：`mastersos-agent chrome`（一轮就退出），由 `mastersos-chrome.timer` 驱动、不看有没有种子——
//! 浏览器是系统的一部分（spec §3），没有种子的个人电脑也要有。常驻的 `run`（只在受管的机器上）不更新 Chrome，
//! 只用 [`ChromeStatus`] 读这一轮写下的结果（`<work>/result.json`）随回报上送；`mastersos-chrome.service` 跑完发
//! SIGUSR1 叫醒它。两边不会同时装：更新只在这一个单元里跑，另外持有 `<work>` 的 `flock`（第二个更新者直接失败）。
//!
//! 校验链：镜像里**固定**的 Google 公钥（`CHROME_KEYRING`，不像试验脚本那样每次从网上取）→ `gpgv` 验
//! `InRelease`，只用它输出的明文 → 明文 `SHA256:` 段里的哈希验 `Packages` → `Packages` 里的哈希验 .deb。
//! 任何一步不对都保留现有版本、回报 `chrome` 失败。
//!
//! **不降级**：Google 的 `InRelease` 没有 `Valid-Until`，一份旧的、签名照样有效的索引可以被回放来冻结或降级
//! Chrome。两道下限：签名的 Release 的 `Date:` 不得早于见过的最新一份（`<work>/release-date`，恢复出厂随 /var 清零）；
//! 源里的版本比已装的旧（`dpkg --compare-versions <新> lt <旧>`）就拒绝；一样就什么都不做。
//! 冻结（一直回放同一份最新见过的索引）挡不住——那只等于网络断了，回报的版本号停着不动，IT 看得到。
//!
//! 换版本：解到 `<ext>.new`、补上 sysext 要的元数据与图标，`renameat2(RENAME_EXCHANGE)` 原子互换
//! `<ext>` 与 `<ext>.new`（第一次安装直接改名），让 systemd 重新合并（见 [`refresh_cmd`]），**然后**才删换下来的旧目录。
//! refresh 失败就换回去、再合并一次（失败的那次可能已经卸下了旧的），成功了才删 `<ext>.new`。上一轮中途断掉留下的
//! `<ext>.new` 开轮先合并、再删（互换之后、合并之前断掉时，`.new` 正是合并着的那一层，先删会从开着的 Chrome 脚下抽走文件）。
//!
//! **IT 控制什么时候换版本**（Task 23）：分组的 `[chrome]` 由主 agent 写进 `SysState`（`chrome_window`、`chrome_pause_until`），
//! 这里在**联网之前**读它：不在更新时段（本机时区）、或今天还没过暂停日期，就不取索引、不换版本，回报 `ok` 与当前版本。
//! 只推迟、不降级，上面的两道下限不变。**还没装过 Chrome 的不受限制**——没有浏览器的机器比「上课时更新」糟得多。
//! 没有 `SysState`（没有种子的机器）或读不懂：不限制。时段至少 2 小时，`mastersos-chrome.timer` 另有每小时一轮；
//! 只因时段被挡、而上一次成功查源（`<work>/checked-at`）、开始计时（`window-clock`）与暂停结束三者里最晚的一个已超过 7 天时，
//! 破例照常查（时段里机器一直关着或睡着），暂停不破例（本来最多 14 天），暂停的日子也不算进这 7 天。
//! 定时器触发（`--scheduled`）、没设时段的机器上一次成功查源不到 6 小时就不联网、保留上一轮的结果；IT 在 shell 里手动跑
//! `mastersos-agent chrome` 不受这个限制。被挡下的轮次不把上一轮的失败盖成成功。
//!
//! 解开的树只留允许清单里的路径（[`prune_tree`]）：sysext 把整个 `usr/` 盖在签名的只读系统上，deb 虽然有 Google 的签名，
//! 也不让它带进 `usr/lib/systemd` 之类的东西。

use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use mastersos_bundle::ItemResult;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::apply::hex;
use crate::jobs::{Job, JobCtx};
use crate::runner::{last_lines, run_ok, Cmd, Output, Runner};
use crate::safefs;
use crate::system::{SysPaths, SysState};

pub const CHROME_REPO: &str = "https://dl.google.com/linux/chrome/deb";
/// Google 的 apt 签名公钥（`gpg --dearmor` 过的 keyring），随镜像发布；来源与指纹见 `image/docs/keys.md`。
pub const CHROME_KEYRING: &str = "/usr/share/mastersos/google-chrome-keyring.gpg";
pub const EXT_DIR: &str = "/var/lib/extensions/google-chrome";
pub const CHROME_REFRESH_SECS: u64 = 6 * 3600;
/// 下载用的私有目录（加密根分区上，0700）：`InRelease`、`Release`、`chrome.deb`。
pub const WORK_DIR: &str = "/var/lib/mastersos/chrome";

const PACKAGE: &str = "google-chrome-stable";
const SUITE: &str = "dists/stable";
const PACKAGES_PATH: &str = "main/binary-amd64/Packages";
const EXT_NAME: &str = "google-chrome";
const VERSION_FILE: &str = ".mastersos-version";
const DEB_FILE: &str = "chrome.deb";
const DESKTOP_FILE: &str = "google-chrome.desktop";
/// 上一轮的结果（[`ItemResult`] 的 JSON），[`ChromeStatus`] 读。
const RESULT_FILE: &str = "result.json";
/// 见过的最新的签名 Release 的 `Date:`（Unix 秒）。
const FLOOR_FILE: &str = "release-date";
/// 开始下载 .deb 时更新 mtime（NetworkManager 钩子的限流看它）。
const DEB_STAMP: &str = "download-started";
/// 上一次**成功**查过源的时刻（Unix 秒）：取到并核对了签名索引与 Packages，而且这一轮成功结束（已是最新也算）。
/// 之后失败的（下载、解开、合并、拒绝降级）不写，下一轮定时器照常重试；被挡下或被限流跳过的轮次也不写（复审 N1、N3）。
const CHECKED_FILE: &str = "checked-at";
/// 时段的 7 天从哪一刻算起，当 `checked-at` 还没有（刚升级上来）或读不懂时由被时段挡下的一轮写下（Unix 秒）。
const WINDOW_CLOCK_FILE: &str = "window-clock";
/// 只因时段被挡、而上一次查源已超过这么久：这一轮不再等（复审 I1：时段里机器一直关着或睡着时，Chrome 不能永远不更新）。
pub const WINDOW_OVERRIDE_AFTER: Duration = Duration::from_secs(7 * 86_400);
/// 定时器触发（`--scheduled`）、没设时段的机器：上一次查源不到这么久就不联网（每小时一轮只为时段而设）。
pub const SCHEDULED_MIN_GAP: Duration = Duration::from_secs(6 * 3600);

const MAX_INDEX_BYTES: usize = 16 * 1024 * 1024;
/// 现在约 140 MB。
const MAX_DEB_BYTES: u64 = 1024 * 1024 * 1024;
const INDEX_TIMEOUT: Duration = Duration::from_secs(60);
const DEB_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const EXTRACT_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebEntry {
    pub version: String,
    pub filename: String,
    pub sha256: String,
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Release 明文 `SHA256:` 段里路径恰好是 `path` 的那一行的哈希（小写）。段里每行是
/// `<哈希> <大小> <路径>`，以空格开头；遇到下一个不以空白开头的行，段就结束。
/// 有歧义（这个路径出现不止一行，哪怕在两个 `SHA256:` 段里）或哈希不规范时为 `None`——不猜。
pub fn release_sha256(release: &str, path: &str) -> Option<String> {
    let mut in_sha256 = false;
    let mut found: Vec<&str> = vec![];
    for line in release.lines() {
        if !line.starts_with([' ', '\t']) {
            in_sha256 = line.trim_end() == "SHA256:";
            continue;
        }
        if !in_sha256 {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.last() == Some(&path) {
            found.push(f.first().copied().unwrap_or_default());
            if f.len() != 3 {
                return None;
            }
        }
    }
    match found[..] {
        [hash] if is_sha256_hex(hash) => Some(hash.to_ascii_lowercase()),
        _ => None,
    }
}

/// Debian 版本号里允许的字符，且以数字开头（它会作为 `dpkg --compare-versions` 的参数）。
fn valid_version(v: &str) -> bool {
    v.len() <= 128
        && v.starts_with(|c: char| c.is_ascii_digit())
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+~:-".contains(&b))
}

/// `pool/…/x.deb`：接在源地址后面，不许有 `..`、空的一级、查询串之类。
fn valid_filename(f: &str) -> bool {
    f.starts_with("pool/")
        && f.ends_with(".deb")
        && f.split('/').all(|p| !p.is_empty() && p != "." && p != "..")
        && f.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+~/-".contains(&b))
}

/// `Packages` 里 `Package: <name>` 的那一段。同名的段多于一个就报错——宁可不更新，也不猜哪个。
pub fn find_package(packages: &str, name: &str) -> Result<DebEntry> {
    let mut found: Option<DebEntry> = None;
    for stanza in packages.split("\n\n") {
        let field = |key: &str| {
            stanza.lines().find_map(|l| {
                let (k, v) = l.split_once(':')?;
                (!l.starts_with([' ', '\t']) && k == key).then(|| v.trim().to_string())
            })
        };
        let pkgs: Vec<&str> = stanza
            .lines()
            .filter_map(|l| {
                let (k, v) = l.split_once(':')?;
                (!l.starts_with([' ', '\t']) && k == "Package").then_some(v.trim())
            })
            .collect();
        if !pkgs.contains(&name) {
            continue;
        }
        ensure!(
            pkgs.len() == 1,
            "Packages 里 {name} 那一段的 Package 不止一行，不更新"
        );
        if found.is_some() {
            bail!("Packages 里 {name} 不止一个，不更新");
        }
        let get = |key: &str| {
            let n = stanza
                .lines()
                .filter(|l| {
                    !l.starts_with([' ', '\t']) && l.split_once(':').is_some_and(|(k, _)| k == key)
                })
                .count();
            ensure!(n <= 1, "Packages 里 {name} 的 {key} 不止一行，不更新");
            field(key).ok_or_else(|| anyhow!("Packages 里 {name} 缺 {key}"))
        };
        let e = DebEntry {
            version: get("Version")?,
            filename: get("Filename")?,
            sha256: get("SHA256")?.to_ascii_lowercase(),
        };
        ensure!(
            valid_version(&e.version),
            "Packages 里 {name} 的版本号不规范"
        );
        ensure!(
            valid_filename(&e.filename),
            "Packages 里 {name} 的文件路径不规范"
        );
        ensure!(
            is_sha256_hex(&e.sha256),
            "Packages 里 {name} 的 SHA256 不规范"
        );
        found = Some(e);
    }
    found.ok_or_else(|| anyhow!("Packages 里没有 {name}"))
}

/// `opt/google/chrome` 里的文件名 → 要复制的图标：`product_logo_<N>.png` →
/// `usr/share/icons/hicolor/<N>x<N>/apps/google-chrome.png`（.deb 的 postinst 本来做这件事，sysext 不跑它）。
pub fn icon_targets(names: &[String]) -> Vec<(String, String)> {
    names
        .iter()
        .filter_map(|n| {
            let size = n.strip_prefix("product_logo_")?.strip_suffix(".png")?;
            (!size.is_empty() && size.len() <= 4 && size.bytes().all(|b| b.is_ascii_digit())).then(
                || {
                    (
                        format!("opt/google/chrome/{n}"),
                        format!("usr/share/icons/hicolor/{size}x{size}/apps/google-chrome.png"),
                    )
                },
            )
        })
        .collect()
}

/// [`icon_targets`] 里尺寸最大的那张，作为合并后的绝对路径（`/opt/google/chrome/product_logo_<N>.png`）。
fn largest_logo(icons: &[(String, String)]) -> Option<String> {
    icons
        .iter()
        .filter_map(|(from, _)| {
            let n: u32 = from
                .rsplit_once("product_logo_")?
                .1
                .strip_suffix(".png")?
                .parse()
                .ok()?;
            Some((n, from))
        })
        .max_by_key(|(n, _)| *n)
        .map(|(_, from)| format!("/{from}"))
}

/// 签名 Release 的 `Date:`（RFC 2822，Google 写 `UTC`）→ Unix 秒。
/// 没有、不止一行、或读不懂时为 `None`。
pub fn release_date(release: &str) -> Option<i64> {
    let mut dates = release.lines().filter_map(|l| l.strip_prefix("Date:"));
    let v = dates.next()?.trim();
    if dates.next().is_some() {
        return None;
    }
    let v = v
        .strip_suffix(" UTC")
        .map_or(v.to_string(), |d| format!("{d} +0000"));
    chrono::DateTime::parse_from_rfc2822(&v)
        .ok()
        .map(|d| d.timestamp())
}

/// 允许清单里一项应是什么。
#[derive(Clone, Copy)]
enum Kind {
    Dir,
    /// 普通文件或符号链接（例如 `usr/bin/google-chrome-stable` → `/opt/google/chrome/google-chrome`）
    FileOrLink,
    /// 只能是普通文件（例如 `.desktop`：链接可能指向系统里别的 .desktop）
    File,
}

/// 解开的 deb 里允许留下的路径：`(目录, [(名字, 类型)])`；名字以 `*` 结尾表示前缀。名字不在清单里的删掉；
/// 在清单里、类型却不对（目录成了文件或链接——合并后会盖住整个系统目录）的整个拒绝。不在清单里的目录不管
/// （例如 `opt/google/chrome` 里面、`usr/share/man` 里面）。我们自己之后写的 `usr/lib/extension-release.d`
/// 与 `usr/share/icons/hicolor/…` 在剪完之后才加。
const ALLOW: &[(&str, &[(&str, Kind)])] = &[
    ("", &[("opt", Kind::Dir), ("usr", Kind::Dir)]),
    ("opt", &[("google", Kind::Dir)]),
    ("opt/google", &[("chrome", Kind::Dir)]),
    (
        "usr",
        &[("bin", Kind::Dir), ("share", Kind::Dir), ("lib", Kind::Dir)],
    ),
    ("usr/lib", &[("extension-release.d", Kind::Dir)]),
    ("usr/bin", &[("google-chrome*", Kind::FileOrLink)]),
    (
        "usr/share",
        &[
            ("applications", Kind::Dir),
            ("appdata", Kind::Dir),
            ("metainfo", Kind::Dir),
            ("doc", Kind::Dir),
            ("man", Kind::Dir),
            ("menu", Kind::Dir),
            ("gnome-control-center", Kind::Dir),
            ("icons", Kind::Dir),
        ],
    ),
    (
        "usr/share/applications",
        &[
            ("google-chrome*", Kind::File),
            ("com.google.Chrome*", Kind::File),
        ],
    ),
    ("usr/share/appdata", &[("google-chrome*", Kind::File)]),
];

/// 按 [`ALLOW`] 删掉 `root` 里不认得的东西（不跟随链接），类型不对就报错。返回删掉的路径。
pub fn prune_tree(root: &std::os::fd::OwnedFd) -> Result<Vec<String>> {
    use rustix::fs::{AtFlags, FileType};
    let mut removed = vec![];
    'level: for (dir, names) in ALLOW {
        // 逐级 open_child_dir：不存在就跳过这一级；是符号链接、不是目录或打不开都报错（不当成「没有」放过去）
        let mut d = safefs::open_dir_at(root, Path::new(""), false)?;
        for part in dir.split('/').filter(|p| !p.is_empty()) {
            match safefs::open_child_dir(&d, part)
                .with_context(|| format!("解开的 deb 里的 {dir}"))?
            {
                Some(next) => d = next,
                None => continue 'level,
            }
        }
        for n in safefs::list_at(&d)? {
            let path = if dir.is_empty() {
                n.clone()
            } else {
                format!("{dir}/{n}")
            };
            let kind = names.iter().find_map(|(a, k)| {
                let hit = match a.strip_suffix('*') {
                    Some(prefix) => n.starts_with(prefix),
                    None => *a == n,
                };
                hit.then_some(*k)
            });
            let Some(kind) = kind else {
                safefs::remove_tree_at(&d, &n)?;
                removed.push(path);
                continue;
            };
            let st = rustix::fs::statat(&d, n.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                .map_err(std::io::Error::from)
                .with_context(|| format!("检查 {path}"))?;
            let t = FileType::from_raw_mode(st.st_mode);
            let ok = match kind {
                Kind::Dir => t == FileType::Directory,
                Kind::FileOrLink => t == FileType::RegularFile || t == FileType::Symlink,
                Kind::File => t == FileType::RegularFile,
            };
            ensure!(ok, "解开的 deb 里的 {path} 类型不对（{t:?}），不更新");
        }
    }
    Ok(removed)
}

/// Chrome sysext 的后台任务（回报项 `chrome`，`detail` 是版本号或失败原因）。
pub struct ChromeJob {
    runner: Arc<dyn Runner>,
    http: reqwest::Client,
    repo: String,
    work: PathBuf,
    ext: PathBuf,
    max_deb: u64,
    /// 取索引失败时，每次重试前等这么久（次数 = 长度）。
    retry: Vec<Duration>,
    /// 这次开机的 id（记进 result.json，[`ChromeStatus`] 据此判断结果是不是这次开机的）。
    boot_id: fn() -> Option<String>,
    /// 主 agent 的状态（只读）：更新时段与暂停。
    sys: SysPaths,
    /// 本机时区的现在。
    now: fn() -> chrono::DateTime<chrono::FixedOffset>,
    /// 由 mastersos-chrome.timer 触发（`mastersos-agent chrome --scheduled`）：没设时段时按 [`SCHEDULED_MIN_GAP`] 限流。
    scheduled: bool,
}

/// IT 让这一轮先别换版本的原因。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hold {
    Pause(String),
    Window(String),
}

/// 按 `SysState` 里的时段与暂停判断 `now`（本机时区）这一轮该不该等。值不对（只可能是手改的）就不限制（记日志）；
/// 暂停在这里按本机日期再校一次 14 天（复审 M1：主 agent 不再应用时，这里也不无限期地信它）。
pub fn hold_reason(sys: &SysState, now: chrono::DateTime<chrono::FixedOffset>) -> Option<Hold> {
    use mastersos_bundle::checks;
    let local = now.naive_local();
    if let Some(p) = sys.chrome_pause_until.as_deref() {
        match checks::chrome_date(p)
            .and_then(|d| checks::chrome_pause_on_machine(p, local.date()).map(|()| d))
        {
            Ok(d) if local.date() <= d => return Some(Hold::Pause(format!("暂停到 {p}（含）"))),
            Ok(_) => {}
            Err(e) => log::warn!("chrome：{e}，不暂停"),
        }
    }
    if let Some(w) = sys.chrome_window.as_deref() {
        use chrono::Timelike;
        match checks::chrome_window(w) {
            Ok(win) => {
                let minute = (local.hour() * 60 + local.minute()) as u16;
                if !checks::chrome_in_window(win, minute) {
                    let tz = checks::utc_offset_label(now.offset().local_minus_utc());
                    return Some(Hold::Window(format!("在等更新时段 {w}（本机时间 {tz}）")));
                }
            }
            Err(e) => log::warn!("chrome：{e}，不限时段"),
        }
    }
    None
}

/// 在这一轮联网之前决定的事。
enum Gate {
    /// IT 的暂停或时段挡下了：不联网，回报这个 detail（上一轮失败时仍回报失败，见 [`ChromeJob::update_once`]）。
    Held(String),
    /// 定时器触发、没设时段、6 小时内成功查过：不联网，保留上一轮的结果（参数是已装的版本，没有上一轮时用它）。
    Throttled(String),
    /// 照常查源；`Some` 是要附在结果后面的说明。
    Go(Option<String>),
}

/// 一轮的结果（失败是 `Err`）。
enum RoundOut {
    Done(String),
    Held(String),
    Throttled(String),
}

/// 读一个记着 Unix 秒的文件；没有或读不懂为 `None`。
fn read_secs(work: &std::os::fd::OwnedFd, name: &str) -> Result<Option<i64>> {
    Ok(safefs::read_at(work, name)?
        .and_then(|b| String::from_utf8_lossy(&b).trim().parse::<i64>().ok()))
}

fn write_secs(work: &std::os::fd::OwnedFd, name: &str, t: i64) -> Result<()> {
    safefs::write_at(work, name, format!("{t}\n").as_bytes(), 0o600)?;
    Ok(())
}

impl ChromeJob {
    pub fn new(runner: Arc<dyn Runner>) -> Self {
        Self::with_paths(runner, CHROME_REPO, WORK_DIR.into(), EXT_DIR.into())
    }

    /// 测试用：别的源、别的目录。
    pub fn with_paths(runner: Arc<dyn Runner>, repo: &str, work: PathBuf, ext: PathBuf) -> Self {
        let http = crate::fetch::http_client(crate::fetch::HttpOpts {
            connect: Duration::from_secs(30),
            read: None,
            total: None,
        });
        ChromeJob {
            runner,
            http,
            repo: repo.trim_end_matches('/').to_string(),
            work,
            ext,
            max_deb: MAX_DEB_BYTES,
            retry: vec![Duration::from_secs(5), Duration::from_secs(20)],
            boot_id: current_boot_id,
            sys: SysPaths::default(),
            now: local_now,
            scheduled: false,
        }
    }

    /// 由定时器触发（`mastersos-agent chrome --scheduled`）。
    pub fn scheduled(mut self, yes: bool) -> Self {
        self.scheduled = yes;
        self
    }

    /// 测试用：别处的 `SysState`。
    pub fn with_settings(mut self, sys: SysPaths) -> Self {
        self.sys = sys;
        self
    }

    /// 测试用：换掉「本机时区的现在」。
    pub fn with_now(mut self, f: fn() -> chrono::DateTime<chrono::FixedOffset>) -> Self {
        self.now = f;
        self
    }

    /// 已装了 Chrome 时，这一轮联网之前的判断：IT 的暂停与时段（时段挡了 7 天以上就破例），定时器触发且没设时段时的 6 小时限流。
    /// 读不到或读不懂设置都不限制（记日志）。
    fn gate(&self, work: &std::os::fd::OwnedFd, installed: &str) -> Result<Gate> {
        let sys = match SysState::peek(&self.sys) {
            Ok(s) => s.unwrap_or_default(),
            Err(e) => {
                log::warn!("chrome：读不出更新时段与暂停的设置，不限制：{e:#}");
                SysState::default()
            }
        };
        let now = (self.now)();
        let t = now.timestamp();
        // 记录在将来超过一天（时钟被往回拨过）当作没有
        let sane = |v: Option<i64>| v.filter(|x| *x <= t + 86_400);
        let checked = sane(read_secs(work, CHECKED_FILE)?);
        let since_checked = checked.map(|c| Duration::from_secs((t - c).max(0) as u64));
        match hold_reason(&sys, now) {
            Some(Hold::Pause(why)) => return Ok(Gate::Held(format!("{why}，当前 {installed}"))),
            Some(Hold::Window(why)) => {
                // 时段的 7 天：从上一次成功查源、开始计时、暂停结束（暂停那天的第二天 0 点）三者里最晚的一个算起——
                // 暂停的日子不算（复审 N2：考试周暂停一结束，第一个早上不能在上课时更新）
                let pause_end = sys.chrome_pause_until.as_deref().and_then(|p| {
                    let d = mastersos_bundle::checks::chrome_date(p).ok()?;
                    mastersos_bundle::checks::chrome_pause_on_machine(p, now.date_naive()).ok()?;
                    d.succ_opt()?
                        .and_hms_opt(0, 0, 0)?
                        .and_local_timezone(*now.offset())
                        .single()
                        .map(|x| x.timestamp())
                });
                let clock = sane(read_secs(work, WINDOW_CLOCK_FILE)?);
                let Some(from) = [checked, clock, pause_end].into_iter().flatten().max() else {
                    // 还没有记录（刚升级上来）或读不懂：从现在开始算 7 天，不立刻破例
                    write_secs(work, WINDOW_CLOCK_FILE, t)?;
                    return Ok(Gate::Held(format!("{why}，当前 {installed}")));
                };
                let waited = Duration::from_secs((t - from).max(0) as u64);
                if waited < WINDOW_OVERRIDE_AFTER {
                    return Ok(Gate::Held(format!("{why}，当前 {installed}")));
                }
                log::warn!(
                    "chrome：{why}，但已 {} 天没查过源（时段里一直没开机或睡着），这一轮照常查",
                    waited.as_secs() / 86_400
                );
                return Ok(Gate::Go(Some(
                    "更新时段内一直没开机，已超过 7 天，照常更新 / no check inside the update window for over 7 days, updated anyway"
                        .into(),
                )));
            }
            None => {}
        }
        let windowed = sys
            .chrome_window
            .as_deref()
            .is_some_and(|w| mastersos_bundle::checks::chrome_window(w).is_ok());
        if self.scheduled && !windowed && since_checked.is_some_and(|a| a < SCHEDULED_MIN_GAP) {
            log::info!(
                "chrome：{} 小时内查过源，这一轮（定时器）不联网、保留上一轮的结果；要立刻查，在 shell 里跑 mastersos-agent chrome",
                SCHEDULED_MIN_GAP.as_secs() / 3600
            );
            return Ok(Gate::Throttled(installed.to_string()));
        }
        Ok(Gate::Go(None))
    }

    /// 测试用：换掉「这次开机的 id」。
    pub fn with_boot_id(mut self, f: fn() -> Option<String>) -> Self {
        self.boot_id = f;
        self
    }

    /// 测试用：取索引的重试间隔。
    pub fn retry_delays(mut self, d: Vec<Duration>) -> Self {
        self.retry = d;
        self
    }

    /// 测试用：换一个 .deb 的大小上限。
    pub fn max_deb_bytes(mut self, n: u64) -> Self {
        self.max_deb = n;
        self
    }

    /// 在阻塞线程里跑一条命令。
    async fn exec(&self, cmd: Cmd) -> Result<Output> {
        let r = self.runner.clone();
        let program = cmd.program.clone();
        tokio::task::spawn_blocking(move || r.run(&cmd))
            .await
            .map_err(|e| anyhow!("{program} 异常退出：{e}"))?
    }

    async fn exec_ok(&self, cmd: Cmd) -> Result<String> {
        let r = self.runner.clone();
        let program = cmd.program.clone();
        tokio::task::spawn_blocking(move || run_ok(r.as_ref(), cmd))
            .await
            .map_err(|e| anyhow!("{program} 异常退出：{e}"))?
    }

    /// GET 一个索引文件，失败就按 `retry` 隔一会儿再试（刚连上网时 DNS 往往还没好；索引只有几 KB）。
    async fn get_index(&self, rel: &str) -> Result<Vec<u8>> {
        let mut delays = self.retry.iter();
        loop {
            match self.get_index_once(rel).await {
                Ok(b) => return Ok(b),
                Err(e) => match delays.next() {
                    Some(d) => {
                        log::info!("chrome：{e:#}，{} 秒后重试", d.as_secs());
                        tokio::time::sleep(*d).await;
                    }
                    None => return Err(e),
                },
            }
        }
    }

    /// GET 一个索引文件（200 才算），不超过 `MAX_INDEX_BYTES`。
    async fn get_index_once(&self, rel: &str) -> Result<Vec<u8>> {
        let mut resp = self
            .http
            .get(format!("{}/{rel}", self.repo))
            .timeout(INDEX_TIMEOUT)
            .send()
            .await
            .with_context(|| format!("下载 {rel} 失败"))?;
        ensure!(
            resp.status().is_success(),
            "下载 {rel}：源返回 {}",
            resp.status()
        );
        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .with_context(|| format!("读取 {rel} 失败"))?
        {
            ensure!(
                body.len() + chunk.len() <= MAX_INDEX_BYTES,
                "{rel} 超过大小上限"
            );
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// 把 .deb 边下边算 sha256 写进 `<work>/chrome.deb`；哈希对不上时不留文件。
    async fn download_deb(&self, work: &std::os::fd::OwnedFd, e: &DebEntry) -> Result<()> {
        let mut resp = self
            .http
            .get(format!("{}/{}", self.repo, e.filename))
            .timeout(DEB_TIMEOUT)
            .send()
            .await
            .context("下载 Chrome 的 .deb 失败")?;
        ensure!(
            resp.status().is_success(),
            "下载 Chrome 的 .deb：源返回 {}",
            resp.status()
        );
        ensure!(
            resp.content_length().is_none_or(|n| n <= self.max_deb),
            "Chrome 的 .deb 超过大小上限"
        );
        let mut tmp = safefs::TmpFile::create(work, DEB_FILE, 0o600)?;
        let mut h = Sha256::new();
        let mut n: u64 = 0;
        let mut stamped = false;
        while let Some(chunk) = resp.chunk().await.context("读取 Chrome 的 .deb 失败")? {
            // 收到第一批字节时留时间戳：NetworkManager 钩子看到一小时内下载过就不再触发（下载之后才失败的，不因
            // Wi‑Fi 时断时续一遍遍重下约 140 MB）。请求立刻失败、一个字节都没收到的不算，钩子下次连网照样触发
            if !stamped {
                safefs::TmpFile::create(work, DEB_STAMP, 0o600)?.commit()?;
                stamped = true;
            }
            n += chunk.len() as u64;
            ensure!(n <= self.max_deb, "Chrome 的 .deb 超过大小上限");
            h.update(&chunk);
            tmp.write_all(&chunk).context("写入 Chrome 的 .deb")?;
        }
        let got = hex(&h.finalize());
        ensure!(
            got == e.sha256,
            "Chrome 的 .deb sha256 与 Packages 不符（{got} ≠ {}），保留现有版本",
            e.sha256
        );
        tmp.commit()
    }

    async fn round(&self) -> Result<RoundOut> {
        let (ext_parent, ext_name) = split(&self.ext)?;
        ensure!(ext_name == EXT_NAME, "扩展目录必须叫 {EXT_NAME}");
        let new_name = format!("{ext_name}.new");

        let work = safefs::open_abs_dir(&self.work, true)?;
        safefs::set_mode(&work, 0o700)?;
        let ext_dir = safefs::open_abs_dir(ext_parent, true)?;

        // 上一轮中途断掉留下的 .new：它可能正是合并着的那一层（互换之后、合并之前断掉），先合并、再删。
        if safefs::open_child_dir(&ext_dir, &new_name)?.is_some() {
            log::warn!("chrome：上一轮留下了 {new_name}，先重新合并再删掉");
            self.exec_ok(refresh_cmd()).await?;
            safefs::remove_tree_at(&ext_dir, &new_name)?;
        }
        let _ = safefs::remove_at(&work, DEB_FILE);

        // 扩展目录在、却读不出版本：不当成「没装过」（那样任何签名过的旧版本都会被装上），拒绝
        let installed = match safefs::open_child_dir(&ext_dir, ext_name)? {
            Some(d) => Some(
                safefs::read_at(&d, VERSION_FILE)?
                    .map(|b| String::from_utf8_lossy(&b).trim().to_string())
                    .ok_or_else(|| {
                        anyhow!("{EXT_DIR} 在，但没有 {VERSION_FILE}：不知道装的是哪个版本，不更新")
                    })?,
            ),
            None => None,
        };
        // 0. IT 的更新时段与暂停、定时器的限流：联网之前判断；还没装过的照装
        let mut note = None;
        if let Some(old) = installed.as_deref() {
            match self.gate(&work, old)? {
                Gate::Held(detail) => {
                    log::info!("chrome：{detail}，这一轮不换版本");
                    return Ok(RoundOut::Held(detail));
                }
                Gate::Throttled(v) => return Ok(RoundOut::Throttled(v)),
                Gate::Go(n) => note = n,
            }
        }
        // 成功结束：记下这次成功查源的时刻
        let done = |v: String| -> Result<RoundOut> {
            write_secs(&work, CHECKED_FILE, (self.now)().timestamp())?;
            Ok(RoundOut::Done(match &note {
                Some(n) => format!("{v}（{n}）"),
                None => v,
            }))
        };

        // 1. InRelease → gpgv（钥匙固定在镜像里）→ 只用它输出的明文
        let inrelease = self.get_index(&format!("{SUITE}/InRelease")).await?;
        safefs::write_at(&work, "InRelease", &inrelease, 0o600)?;
        safefs::remove_at(&work, "Release")?;
        let w = self.work.display();
        let gpgv = Cmd::new(
            "gpgv",
            &[
                "--keyring",
                CHROME_KEYRING,
                "--output",
                &format!("{w}/Release"),
                &format!("{w}/InRelease"),
            ],
        );
        let out = self.exec(gpgv).await?;
        if out.code != 0 {
            // gpgv 验不过时照样把明文写进 --output（VM 165 实测）：没验过的东西不留在盘上
            let _ = safefs::remove_at(&work, "Release");
        }
        ensure!(
            out.code == 0,
            "InRelease 的签名验不过（gpgv 退出码 {}：{}），保留现有版本",
            out.code,
            last_lines(&out.stderr, 2).replace('\n', "；")
        );
        let release =
            safefs::read_at(&work, "Release")?.ok_or_else(|| anyhow!("gpgv 没有写出 Release"))?;
        let release = String::from_utf8(release).context("Release 不是 UTF-8")?;
        let date = release_date(&release).ok_or_else(|| anyhow!("Release 里没有可读的 Date"))?;
        let floor = match safefs::read_at(&work, FLOOR_FILE)? {
            None => None,
            Some(b) => Some(
                String::from_utf8_lossy(&b)
                    .trim()
                    .parse::<i64>()
                    .ok()
                    .ok_or_else(|| {
                        anyhow!("{WORK_DIR}/{FLOOR_FILE} 读不懂（防回放的下限），不更新；确认无误后删掉它")
                    })?,
            ),
        };
        if let Some(f) = floor {
            ensure!(
                date >= f,
                "源里的签名索引比见过的旧（Date {} 早于 {}），保留现有版本：可能是回放，也可能是 CDN 的边缘节点\
                 还没同步（下一轮自己恢复）；一直这样且确认源没问题时，删掉 {WORK_DIR}/{FLOOR_FILE} 重来",
                fmt_date(date),
                fmt_date(f)
            );
        }
        if floor != Some(date) {
            safefs::write_at(&work, FLOOR_FILE, format!("{date}\n").as_bytes(), 0o600)?;
        }

        // 2. Packages 的哈希
        let want = release_sha256(&release, PACKAGES_PATH)
            .ok_or_else(|| anyhow!("Release 里没有 {PACKAGES_PATH} 的 SHA256"))?;
        let packages = self.get_index(&format!("{SUITE}/{PACKAGES_PATH}")).await?;
        let got = hex(&Sha256::digest(&packages));
        ensure!(
            got == want,
            "Packages 的 sha256 与 Release 不符，保留现有版本"
        );
        let packages = String::from_utf8(packages).context("Packages 不是 UTF-8")?;
        let entry = find_package(&packages, PACKAGE)?;

        // 3. 版本：一样就结束（中途断掉的 .new 已在开头先合并、再删）；更旧就拒绝
        if let Some(old) = installed.as_deref() {
            if old == entry.version {
                return done(entry.version);
            }
            ensure!(valid_version(old), "已装的版本号不规范：{old:?}");
            let lt = self
                .exec(Cmd::new(
                    "dpkg",
                    &["--compare-versions", &entry.version, "lt", old],
                ))
                .await?;
            match lt.code {
                0 => bail!(
                    "源里的版本比已装的旧，拒绝降级（源里 {}，已装 {old}）",
                    entry.version
                ),
                1 => {}
                c => bail!("dpkg --compare-versions 退出码 {c}"),
            }
        }

        // 4. 下载、核对、解开、装好
        self.download_deb(&work, &entry).await?;
        let built = self.build_new(&ext_dir, &new_name, &entry).await;
        let _ = safefs::remove_at(&work, DEB_FILE);
        if let Err(e) = built {
            let _ = safefs::remove_tree_at(&ext_dir, &new_name);
            return Err(e);
        }

        // 5. 换上：已装过就原子互换，第一次直接改名
        let first = installed.is_none();
        if first {
            safefs::rename_at(&ext_dir, &new_name, ext_name)?;
        } else {
            safefs::exchange_at(&ext_dir, ext_name, &new_name)?;
        }
        if let Err(e) = self.exec_ok(refresh_cmd()).await {
            // 换回去，再合并一次（失败的那次可能已经卸下了旧的）；这次也成功了才删 .new——它可能已被合并了一半，
            // 留着的话下一轮开头先合并再删
            let back = if first {
                safefs::rename_at(&ext_dir, ext_name, &new_name)
            } else {
                safefs::exchange_at(&ext_dir, ext_name, &new_name)
            };
            match back {
                Err(b) => log::warn!("chrome：合并失败后换回旧版本也失败：{b:#}"),
                Ok(()) => match self.exec_ok(refresh_cmd()).await {
                    Ok(_) => {
                        let _ = safefs::remove_tree_at(&ext_dir, &new_name);
                    }
                    Err(r) => log::warn!("chrome：换回旧版本后重新合并也失败（下一轮再试）：{r:#}"),
                },
            }
            return Err(e.context("合并新版本 Chrome 失败，保留现有版本"));
        }
        if let Err(e) = safefs::remove_tree_at(&ext_dir, &new_name) {
            log::warn!("chrome：删除换下来的旧版本失败（下一轮再删）：{e:#}");
        }
        log::info!(
            "chrome：装好 {}（原来 {}）",
            entry.version,
            installed.as_deref().unwrap_or("未装")
        );
        done(entry.version)
    }

    /// `dpkg-deb -x` 到 `<ext>.new`，再补上 sysext 要的东西。
    async fn build_new(
        &self,
        ext_dir: &std::os::fd::OwnedFd,
        new_name: &str,
        entry: &DebEntry,
    ) -> Result<()> {
        safefs::remove_tree_at(ext_dir, new_name)?;
        drop(safefs::open_dir_at(ext_dir, Path::new(new_name), true)?);
        let new_path = self.ext.with_file_name(new_name);
        let deb = self.work.join(DEB_FILE);
        self.exec_ok(
            Cmd::new(
                "dpkg-deb",
                &["-x", &deb.to_string_lossy(), &new_path.to_string_lossy()],
            )
            .timeout(EXTRACT_TIMEOUT),
        )
        .await?;
        let new = safefs::open_child_dir(ext_dir, new_name)?
            .ok_or_else(|| anyhow!("{new_name} 不见了"))?;
        // sysext 只合并 /usr 与 /opt；deb 自带的 cron 加源脚本（etc/）与清单外的东西都不要
        let pruned = prune_tree(&new)?;
        if pruned.iter().any(|p| p != "etc") {
            log::warn!(
                "chrome：deb 里有允许清单之外的路径，已删掉：{}",
                pruned.join("、")
            );
        }
        let rel = safefs::open_dir_at(&new, Path::new("usr/lib/extension-release.d"), true)?;
        safefs::write_at(
            &rel,
            &format!("extension-release.{EXT_NAME}"),
            b"ID=_any\nSYSEXT_SCOPE=system\n",
            0o644,
        )?;
        let chrome = safefs::open_dir_at(&new, Path::new("opt/google/chrome"), false)
            .context("deb 里没有 opt/google/chrome")?;
        let icons = icon_targets(&safefs::list_at(&chrome)?);
        for (from, to) in &icons {
            let name = from.rsplit('/').next().unwrap_or_default();
            let bytes = safefs::read_at(&chrome, name)?.ok_or_else(|| anyhow!("{from} 不见了"))?;
            let (dir, file) = to.rsplit_once('/').unwrap_or_default();
            let d = safefs::open_dir_at(&new, Path::new(dir), true)?;
            safefs::write_at(&d, file, &bytes, 0o644)?;
        }
        let apps = safefs::open_dir_at(&new, Path::new("usr/share/applications"), false)
            .context("deb 里没有 usr/share/applications/google-chrome.desktop")?;
        ensure!(
            safefs::open_file_at(&apps, DESKTOP_FILE)?.is_some(),
            "deb 里没有 usr/share/applications/{DESKTOP_FILE}"
        );
        // 上面复制进 hicolor 的图标 GNOME 多半查不到：图标主题的 icon-theme.cache 是镜像构建时生成的，比扩展的目录新，
        // GTK 认为缓存有效就只查缓存（VM 165 实测 Dock 里是通用图标；S2 也是）。每个 .desktop 都改指扩展里最大的那张
        // （deb 里还有一个 NoDisplay 的 com.google.Chrome.desktop）。
        if let Some(abs) = largest_logo(&icons) {
            for name in safefs::list_at(&apps)? {
                if !name.ends_with(".desktop") {
                    continue;
                }
                let Some(text) = safefs::read_at(&apps, &name)? else {
                    continue;
                };
                let text = String::from_utf8_lossy(&text);
                let patched: String = text
                    .split_inclusive('\n')
                    .map(|l| {
                        if l.trim_end() == "Icon=google-chrome" {
                            format!("Icon={abs}\n")
                        } else {
                            l.to_string()
                        }
                    })
                    .collect();
                if patched != text {
                    safefs::write_at(&apps, &name, patched.as_bytes(), 0o644)?;
                }
            }
        }
        safefs::write_at(
            &new,
            VERSION_FILE,
            format!("{}\n", entry.version).as_bytes(),
            0o644,
        )?;
        Ok(())
    }
}

/// 重新合并扩展。不能自己跑 `systemd-sysext refresh`：agent 的单元有 `PrivateTmp=yes`，跑在自己的挂载命名空间里，
/// 在那里合并只有 agent 自己看得见（VM 165 实测：agent 回报装好了，系统里 `/opt/google` 不存在）。交给 PID 1 的
/// `systemd-sysext.service`：在跑就 `reload`（= `systemd-sysext refresh`），没在跑（开机时 `/var/lib/extensions` 是空的，
/// 条件不满足）就 `start`（同样是 refresh）。
fn refresh_cmd() -> Cmd {
    Cmd::new(
        "systemctl",
        &["reload-or-restart", "systemd-sysext.service"],
    )
}

fn split(p: &Path) -> Result<(&Path, &str)> {
    match (p.parent(), p.file_name().and_then(|n| n.to_str())) {
        (Some(parent), Some(name)) => Ok((parent, name)),
        _ => bail!("扩展目录路径不规范：{}", p.display()),
    }
}

// ChromeJob 故意不实现 `Job`：Chrome 只由 `mastersos-agent chrome`（mastersos-chrome.timer）更新，常驻的 `run` 只用
// [`ChromeStatus`] 回报——别再把它加回 `run`，那样就是两个更新者。
impl ChromeJob {
    /// 一轮更新（`mastersos-agent chrome` 用它）：持有 `<work>` 的 flock 跑完，**仍持有锁时**把结果写进 `<work>/result.json`
    /// （每轮都重写，mtime 是「最近一次跑完」）。锁不到就不写（不覆盖正在跑的那一轮）。
    pub async fn update_once(&self) -> ItemResult {
        let fail = |e: anyhow::Error| {
            log::warn!("chrome：{e:#}");
            ItemResult {
                item: "chrome".into(),
                ok: false,
                detail: Some(format!("{e:#}")),
            }
        };
        let work = match self.lock_work() {
            Ok(w) => w,
            Err(e) => return fail(e),
        };
        // 上一轮的结果：被挡下或被限流跳过的轮次不能把一次失败盖成成功（复审 N1）
        let prev = safefs::read_at(&work, RESULT_FILE)
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice::<Saved>(&b).ok())
            .map(|s| s.result);
        let okr = |detail: String| ItemResult {
            item: "chrome".into(),
            ok: true,
            detail: Some(detail),
        };
        let r = match self.round().await {
            Ok(RoundOut::Done(version)) => okr(version),
            Ok(RoundOut::Held(why)) => match prev {
                Some(p) if !p.ok => ItemResult {
                    detail: Some(format!(
                        "{}；这一轮：{why}",
                        // 连着几轮被挡下时不越接越长
                        p.detail
                            .as_deref()
                            .unwrap_or("失败")
                            .split("；这一轮：")
                            .next()
                            .unwrap_or_default()
                    )),
                    ..p
                },
                _ => okr(why),
            },
            // 照样重写（ChromeStatus 按写下的时刻判断定时器在不在跑），内容是上一轮的
            Ok(RoundOut::Throttled(installed)) => prev.unwrap_or_else(|| okr(installed)),
            Err(e) => fail(e),
        };
        let saved = Saved {
            result: r.clone(),
            boot_id: (self.boot_id)(),
            monotonic_secs: Some(monotonic_now().as_secs()),
        };
        if let Err(e) = save_result(&work, &saved) {
            log::warn!("chrome：写不了 {RESULT_FILE}：{e:#}");
        }
        drop(work); // 放锁
        r
    }

    /// 打开（必要时建出）`<work>` 并拿到它的排他 flock；锁跟着返回的 fd。
    fn lock_work(&self) -> Result<std::os::fd::OwnedFd> {
        let work = safefs::open_abs_dir(&self.work, true)?;
        safefs::set_mode(&work, 0o700)?;
        if rustix::fs::flock(&work, rustix::fs::FlockOperation::NonBlockingLockExclusive).is_err() {
            bail!("另一个 Chrome 更新正在进行，这一轮跳过");
        }
        Ok(work)
    }
}

/// `result.json`：结果，加上写下它时的开机 id 与 CLOCK_MONOTONIC（与 mastersos-chrome.timer 同一个时钟：挂起时不走、
/// 开机从零算）。旧格式（只有结果）读出来两项为空，当作「不是这次开机的」。
#[derive(Debug, Serialize, Deserialize)]
struct Saved {
    #[serde(flatten)]
    result: ItemResult,
    #[serde(default)]
    boot_id: Option<String>,
    #[serde(default)]
    monotonic_secs: Option<u64>,
}

/// 本机时区的现在（`/etc/localtime`，Task 17 按 `school.timezone` 设）。
fn local_now() -> chrono::DateTime<chrono::FixedOffset> {
    chrono::Local::now().fixed_offset()
}

/// 这次开机的 id；读不出为 None（当作与任何结果都不是同一次开机）。
pub fn current_boot_id() -> Option<String> {
    let s = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

/// CLOCK_MONOTONIC：开机以来醒着的时间（挂起时不走），systemd 的 OnBootSec/OnUnitActiveSec 用的就是它。
pub fn monotonic_now() -> Duration {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    Duration::new(
        t.tv_sec.max(0) as u64,
        t.tv_nsec.clamp(0, 999_999_999) as u32,
    )
}

/// 总是重写（同样的内容也写）。
fn save_result(work: &std::os::fd::OwnedFd, r: &Saved) -> Result<()> {
    let mut t = safefs::TmpFile::create(work, RESULT_FILE, 0o600)?;
    t.write_all(&serde_json::to_vec(r)?)
        .context("写入 result.json")?;
    t.commit()
}

fn fmt_date(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0)
        .map(|d| d.format("%Y-%m-%d %H:%M:%SZ").to_string())
        .unwrap_or_else(|| t.to_string())
}

/// 结果比这更旧就报失败：两轮（6 小时 + 最多 20 分钟随机延迟）加一轮的超时（45 分钟）还多一点。
pub const RESULT_STALE_AFTER: Duration = Duration::from_secs(14 * 3600);
/// 开机这么久还没有任何结果就报失败：定时器开机 2 分钟 + 最多 20 分钟随机延迟 + 一轮最多 45 分钟，再留余量。
pub const RESULT_BOOT_GRACE: Duration = Duration::from_secs(90 * 60);

type Mono = Box<dyn Fn() -> Duration + Send + Sync>;
type BootId = Box<dyn Fn() -> Option<String> + Send + Sync>;

/// 常驻的 `run` 里的回报：读 `mastersos-agent chrome` 最近一轮写下的结果，作为 `chrome` 一项上送。新旧都按
/// CLOCK_MONOTONIC（与 mastersos-chrome.timer 同一个时钟）算，合盖挂起、关机过夜都不算「没跑」：
/// - 这次开机写的结果：单调时钟走过 [`RESULT_STALE_AFTER`] 还没有新的——失败，带上最后一次的结果；
/// - 上次开机（或更早、或不知道哪次）写的：这次开机不到 [`RESULT_BOOT_GRACE`] 照报它并注明「上次开机」，过了就失败；
/// - 还没有结果：不到 [`RESULT_BOOT_GRACE`] 没有这一项，过了失败。
pub struct ChromeStatus {
    work: PathBuf,
    mono: Mono,
    boot_id: BootId,
}

impl ChromeStatus {
    pub fn new(work: PathBuf) -> Self {
        Self::with_clock(work, Box::new(monotonic_now), Box::new(current_boot_id))
    }

    /// 测试用：换掉单调时钟与开机 id。
    pub fn with_clock(work: PathBuf, mono: Mono, boot_id: BootId) -> Self {
        ChromeStatus {
            work,
            mono,
            boot_id,
        }
    }

    fn read(&self) -> Result<Option<Saved>> {
        let Some(work) = safefs::open_child_dir(
            &safefs::open_abs_dir(self.work.parent().unwrap_or(Path::new("/")), false)?,
            self.work
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| anyhow!("目录名不规范"))?,
        )?
        else {
            return Ok(None);
        };
        match safefs::read_at(&work, RESULT_FILE)? {
            None => Ok(None),
            Some(b) => Ok(Some(
                serde_json::from_slice(&b).context("result.json 读不懂")?,
            )),
        }
    }

    /// The result of the latest `mastersos-agent chrome` round as written, with no staleness check; `None` when there
    /// is none or it cannot be read.
    pub fn last_result(&self) -> Option<ItemResult> {
        self.read().ok().flatten().map(|s| s.result)
    }

    fn report(&self) -> Vec<ItemResult> {
        let fail = |detail: String| {
            vec![ItemResult {
                item: "chrome".into(),
                ok: false,
                detail: Some(detail),
            }]
        };
        let describe = |r: &ItemResult| match (&r.ok, &r.detail) {
            (true, Some(v)) => format!("成功，{v}"),
            (false, Some(d)) => format!("失败：{d}"),
            _ => "无说明".into(),
        };
        let now = (self.mono)();
        let in_grace = now < RESULT_BOOT_GRACE;
        let saved = match self.read() {
            Err(e) => return fail(format!("读不出 Chrome 更新的结果：{e:#}")),
            Ok(s) => s,
        };
        let Some(saved) = saved else {
            return if in_grace {
                vec![]
            } else {
                fail(format!(
                    "开机后醒着超过 {} 分钟还没有跑完过一轮 Chrome 更新（mastersos-chrome.timer）",
                    RESULT_BOOT_GRACE.as_secs() / 60
                ))
            };
        };
        let this_boot = match (&saved.boot_id, (self.boot_id)()) {
            (Some(a), Some(b)) => *a == b,
            _ => false,
        };
        match (this_boot, saved.monotonic_secs) {
            (true, Some(then)) => {
                let age = now.saturating_sub(Duration::from_secs(then));
                if age <= RESULT_STALE_AFTER {
                    vec![saved.result]
                } else {
                    fail(format!(
                        "醒着 {} 小时没有跑完一轮 Chrome 更新（mastersos-chrome.timer）；最后一次：{}",
                        age.as_secs() / 3600,
                        describe(&saved.result)
                    ))
                }
            }
            _ if in_grace => {
                let mut r = saved.result;
                r.detail = Some(format!(
                    "{}（上次开机的结果，这次开机还没跑完一轮）",
                    r.detail.unwrap_or_default()
                ));
                vec![r]
            }
            _ => fail(format!(
                "这次开机醒着超过 {} 分钟还没有跑完一轮 Chrome 更新；上次开机：{}",
                RESULT_BOOT_GRACE.as_secs() / 60,
                describe(&saved.result)
            )),
        }
    }
}

impl Job for ChromeStatus {
    fn name(&self) -> &'static str {
        "chrome-status"
    }

    /// `mastersos-chrome.service` 跑完会叫醒 agent，这里只是兜底。
    fn every(&self) -> Duration {
        Duration::from_secs(15 * 60)
    }

    fn run<'a>(
        &'a self,
        _cx: &'a JobCtx,
    ) -> Pin<Box<dyn Future<Output = Vec<ItemResult>> + Send + 'a>> {
        Box::pin(async move { self.report() })
    }
}

#[cfg(test)]
mod tests;
