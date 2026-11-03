//! `mastersos-kiosk`：锁定会话里的三个子命令（计划 9 设计 §4.4、§4.7）。镜像的 `/usr/bin/mastersos-kiosk` 是
//! `exec /usr/bin/mastersos-agent kiosk "$@"`；`main.rs` 在建 tokio 运行时之前按 `argv[1] == "kiosk"` 分到 [`main`]。
//! 以会话的用户身份运行（不是 root），同步，进程管理只用 `std::process`。
//!
//! - `run [<id>]`：gnome-kiosk 会话（镜像的 `mastersos-kiosk.desktop`）起它。id 由 `$USER`（`kiosk-<id>`）得出，参数里
//!   的 id 只核对；读 kiosk 步骤写的启动描述（[`Launch`]，root 0644，kiosk 账号写不了）。网页 / PWA 进 Chrome
//!   （[`chrome_argv`]），退出（Alt+F4、Ctrl+Shift+Q、崩溃）就原地重开，60 秒内退出 5 次改开本机的错误页（[`ERROR_PAGE`]），
//!   错误页再关掉就结束会话（[`Supervisor`]）；本地程序（[`exec_argv`]）退出就结束会话，不重开。不在 `mastersos-kiosk`
//!   会话里（[`session_is_kiosk`]）不起，结束会话：`pam-session` 已经挡住在登录界面换会话，这里是纵深防御（控制者裁定 4）。
//!   起应用之前核对托管策略目录里恰好是这个应用自己的那一份（[`check_managed_policy`]，计划 9 Task 8 复审 C1；本地程序
//!   也核对，终审 I1——程序里的链接同样起 Chrome）：pam_namespace 没在这个进程所在的命名空间里换好时 Chrome 会照整机的
//!   策略开，宁可弹错误框、结束会话。
//! - `exit-host`：考试扩展「退出」按钮的 native messaging 宿主（宿主清单的 `path` 带不了参数，镜像里
//!   `/usr/lib/mastersos/mastersos-kiosk-exit` 包一层；Chrome 追加的调用方 origin 等参数不看）。只认一条 `{"cmd":"exit"}`
//!   （[`read_request`]），回 `{"ok":true}` 之后结束会话；别的一律回 `{"ok":false}`。`ok:true` 只说明请求收下了、会话
//!   **要**结束（结束之后就回不了话，只能先回），不保证 loginctl 成功；扩展（Task 7）照「已请求」对待。stdout 是消息
//!   通道，日志只走 stderr 与 journald。
//! - `enter <id>`：桌面与 Dock 上 `in_session` 的启动器（`system/desktop.rs`）。zenity 确认后结束当前会话，回到登录界面
//!   再点这个应用（一次性自动登录留给 Task 10 的 VM 验收定）。结束不了就弹错误框（[`ENTER_FAILED`]），不静静地不动。
//!
//! 结束会话（[`terminate_target`]）：`loginctl terminate-session $XDG_SESSION_ID`；没有 `XDG_SESSION_ID`（gnome-shell
//! 与它起的启动器都在 systemd 用户实例里，gnome-session 不把这个变量交给用户实例）时问 logind 这个账号的图形会话
//! （`loginctl show-user $USER -p Display`）；还没有的话，只有 `kiosk-*` 账号退回 `loginctl terminate-user $USER`（锁定
//! 账号只有这一个会话），别的账号什么都不结束（控制者裁定 3、复审 I1）。`$USER` 是会话自己的环境，改了它也只能结束
//! 自己的会话。
//!
//! 进入、退出、异常结束各写一行 journald（`MASTERSOS_KIOSK=<id>`，[`journal_record`]），不上报（设计 §1）。

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use mastersos_bundle::kiosk;

use crate::runner::{run_ok, Cmd, RealRunner, Runner};
use crate::system::desktop::CHROME_BIN;
use crate::system::ephemeral::KIOSK_UIDS;
use crate::system::kiosk::{
    Launch, LaunchKind, LAUNCH_FILE, NS_POLYDIR, POLICIES_DIR, POLICY_FILE, PUBLIC_DIR, SESSION,
};

pub use mastersos_bundle::kiosk::ERROR_PAGE;

/// Chrome 的 profile 在家目录（每次会话一份新的 tmpfs）下的名字。
pub const CHROME_PROFILE: &str = ".kiosk-chrome";
/// native messaging 一条消息的上限（字节）：`{"cmd":"exit"}` 用不了这么多，超了不读就拒。
pub const MAX_MESSAGE: usize = 4096;
/// 启动描述的读取上限。
const MAX_LAUNCH_BYTES: u64 = 64 * 1024;
/// `loginctl` 的时限。
const LOGINCTL_TIMEOUT: Duration = Duration::from_secs(15);
/// journald 的原生协议套接字。
const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

/// journald 的三种 `MESSAGE`。
pub const MSG_ENTER: &str = "entered";
pub const MSG_EXIT: &str = "exited";
pub const MSG_ABNORMAL: &str = "ended abnormally";
pub const MSG_WRONG_SESSION: &str = "not the locked app session; ending it";

/// 各子命令共用的外部依赖，测试里换掉。
pub struct Ctx<'a> {
    /// 环境变量（真的是 `std::env::var`）。
    pub env: &'a dyn Fn(&str) -> Option<String>,
    pub runner: &'a dyn Runner,
    /// 写一行 journald：(id, MESSAGE, 补充说明)。
    pub journal: &'a dyn Fn(&str, &str, Option<&str>),
    /// 系统根（启动描述在它下面的 [`PUBLIC_DIR`]）。
    pub root: &'a Path,
    /// 会话里 Chrome 读的托管策略目录（真的是 [`NS_POLYDIR`]，pam_namespace 把它换成这个应用的实例）。
    pub managed_dir: &'a Path,
}

// ---------------------------------------------------------------------------
// 守护
// ---------------------------------------------------------------------------

/// Chrome 退出之后做什么（设计 §4.4）：[`Supervisor::window`] 之内退出不到 [`Supervisor::max_exits`] 次就重开；到了就
/// 开错误页；错误页再关掉就结束会话。不无限重启。
#[derive(Debug, Clone)]
pub struct Supervisor {
    pub window: Duration,
    pub max_exits: u32,
    /// 窗口之内的退出时刻。
    exits: VecDeque<Instant>,
    /// 已经开过错误页：之后的退出（就是错误页关掉）一律结束会话。
    error_shown: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    Restart,
    ShowError,
    EndSession,
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl Supervisor {
    /// 60 秒内 5 次。
    pub fn new() -> Self {
        Supervisor {
            window: Duration::from_secs(60),
            max_exits: 5,
            exits: VecDeque::new(),
            error_shown: false,
        }
    }

    /// 在 `now` 退出了一次。早于 `now - window`（含恰好等于）的旧退出不计。
    pub fn next_action(&mut self, now: Instant) -> Next {
        if self.error_shown {
            return Next::EndSession;
        }
        let window = self.window;
        self.exits
            .retain(|t| now.saturating_duration_since(*t) < window);
        self.exits.push_back(now);
        if self.exits.len() >= self.max_exits as usize {
            self.error_shown = true;
            Next::ShowError
        } else {
            Next::Restart
        }
    }
}

// ---------------------------------------------------------------------------
// 命令行
// ---------------------------------------------------------------------------

/// `--kiosk --no-first-run --user-data-dir=<home>/.kiosk-chrome`：网页、PWA 与错误页同一个 profile。
fn chrome_base(home: &Path) -> Vec<String> {
    vec![
        CHROME_BIN.into(),
        "--kiosk".into(),
        "--no-first-run".into(),
        format!("--user-data-dir={}", home.join(CHROME_PROFILE).display()),
    ]
}

/// 网页：`google-chrome-stable --kiosk --no-first-run --user-data-dir=<home>/.kiosk-chrome [--user-agent=…] <url>`；
/// PWA 把 `<url>` 换成 `--app=<url>`（裁定 R3：不算 app id，策略里另有 `WebAppInstallForceList`）。每一项是一个 argv
/// 元素，不经 shell：UA 里的空格、引号原样是一个参数。本地程序不经 Chrome，同 [`exec_argv`]。
pub fn chrome_argv(l: &Launch, home: &Path) -> Vec<String> {
    let target = match &l.kind {
        LaunchKind::Web { url } => url.clone(),
        LaunchKind::Pwa { url } => format!("--app={url}"),
        LaunchKind::Exec { target } => return exec_argv(target),
    };
    let mut v = chrome_base(home);
    if let Some(ua) = &l.user_agent {
        v.push(format!("--user-agent={ua}"));
    }
    v.push(target);
    v
}

/// 本地程序：`/` 开头的是 `/usr/` 下的路径（kiosk 步骤校验过），直接执行；其余是 Flatpak id，`flatpak run <id>`。
pub fn exec_argv(target: &str) -> Vec<String> {
    if target.starts_with('/') {
        vec![target.into()]
    } else {
        vec!["flatpak".into(), "run".into(), target.into()]
    }
}

/// 这个应用怎么起。
pub fn app_argv(l: &Launch, home: &Path) -> Vec<String> {
    match &l.kind {
        LaunchKind::Exec { target } => exec_argv(target),
        LaunchKind::Web { .. } | LaunchKind::Pwa { .. } => chrome_argv(l, home),
    }
}

/// 错误页：同一个 profile 以 `--kiosk` 打开 [`ERROR_PAGE`]（策略的放行名单里有它）。
pub fn error_argv(home: &Path) -> Vec<String> {
    let mut v = chrome_base(home);
    v.push(ERROR_PAGE.into());
    v
}

/// `kiosk-<id>` → `<id>`；id 要过 [`kiosk::check_id`]（与账号名的来源同一条规则）。
pub fn id_from_user(user: &str) -> Result<String, String> {
    let id = user
        .strip_prefix("kiosk-")
        .ok_or_else(|| format!("{user:?} is not a locked app account (kiosk-<id>)"))?;
    kiosk::check_id(id).map_err(|e| e.message)?;
    Ok(id.to_string())
}

// ---------------------------------------------------------------------------
// 会话
// ---------------------------------------------------------------------------

/// 环境里的 `XDG_SESSION_DESKTOP` 是不是 `mastersos-kiosk`。
///
/// 选它而不是 `XDG_CURRENT_DESKTOP`：GDM 按所选会话的 `.desktop` **文件名**设 `XDG_SESSION_DESKTOP`（同时设
/// `DESKTOP_SESSION`、`GDMSESSION`），`XDG_CURRENT_DESKTOP` 却取自文件里的 `DesktopNames`，镜像的
/// `mastersos-kiosk.desktop`（Task 8：`Exec=env DCONF_PROFILE=… gnome-session --session=mastersos-kiosk`）不一定写它，
/// 写了也可能是 `GNOME` 之类别的会话也用的名字。文件名只有我们这一个，与 `pam-session` 看的是同一个值。
pub fn in_kiosk_session(env: &dyn Fn(&str) -> Option<String>) -> bool {
    env("XDG_SESSION_DESKTOP").as_deref() == Some(SESSION)
}

/// 会话 id 与 `loginctl` 列出的会话名：只有字母与数字（不会被当成选项）。
fn session_id_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Whether this account is only in `mastersos-kiosk` sessions. `XDG_SESSION_DESKTOP` in the environment decides when
/// present ([`in_kiosk_session`]); otherwise ask logind whether every session of the account has `Desktop` =
/// `mastersos-kiosk` (at least one). On GDM 50 logind's `Desktop` is empty (pam_systemd reads the PAM environment, where
/// GDM has not put the variable yet), so this fallback answers no — the safe side. Unreadable is no.
pub fn session_is_kiosk(ctx: &Ctx, user: &str) -> bool {
    if (ctx.env)("XDG_SESSION_DESKTOP").is_some() {
        return in_kiosk_session(ctx.env);
    }
    let loginctl = |args: &[&str]| {
        run_ok(
            ctx.runner,
            Cmd::new("loginctl", args).timeout(LOGINCTL_TIMEOUT),
        )
    };
    let Ok(out) = loginctl(&["show-user", user, "-p", "Sessions", "--value"]) else {
        return false;
    };
    let ids: Vec<&str> = out.split_whitespace().collect();
    !ids.is_empty()
        && ids.iter().all(|id| {
            session_id_ok(id)
                && loginctl(&["show-session", id, "-p", "Desktop", "--value"])
                    .is_ok_and(|d| d.trim() == SESSION)
        })
}

/// 结束什么。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Terminate {
    Session(String),
    User(String),
}

/// 像账号名：不空、不以 `-` 开头（不会被 loginctl 当成选项）、只有字母数字与 `-_.@`。
fn user_name_ok(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= 256
        && !u.starts_with('-')
        && u.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@'))
}

/// 控制者裁定 3 与复审 I1：有 `XDG_SESSION_ID` 就结束这个会话；没有就问 logind 这个账号的图形会话（`Display`）；
/// 还没有时只有 `kiosk-*` 账号结束整个账号；否则不结束。
pub fn terminate_target(ctx: &Ctx) -> Option<Terminate> {
    if let Some(s) = (ctx.env)("XDG_SESSION_ID").filter(|s| session_id_ok(s)) {
        return Some(Terminate::Session(s));
    }
    let user = (ctx.env)("USER").filter(|u| user_name_ok(u))?;
    let display = run_ok(
        ctx.runner,
        Cmd::new(
            "loginctl",
            &["show-user", &user, "-p", "Display", "--value"],
        )
        .timeout(LOGINCTL_TIMEOUT),
    );
    if let Some(s) = display
        .ok()
        .map(|d| d.trim().to_string())
        .filter(|d| session_id_ok(d))
    {
        return Some(Terminate::Session(s));
    }
    id_from_user(&user).is_ok().then_some(Terminate::User(user))
}

pub fn terminate(runner: &dyn Runner, t: &Terminate) -> Result<()> {
    let (verb, arg) = match t {
        Terminate::Session(s) => ("terminate-session", s),
        Terminate::User(u) => ("terminate-user", u),
    };
    run_ok(
        runner,
        Cmd::new("loginctl", &[verb, arg.as_str()]).timeout(LOGINCTL_TIMEOUT),
    )
    .map(|_| ())
}

/// 结束这个会话；不成就只打 stderr（进程反正要退出，gnome-session 少了必需的组件同样会结束会话）。
fn end_session(ctx: &Ctx) {
    match terminate_target(ctx) {
        Some(t) => {
            if let Err(e) = terminate(ctx.runner, &t) {
                eprintln!("mastersos-kiosk: failed to end the session: {e:#}");
            }
        }
        None => eprintln!("mastersos-kiosk: no current session found and not a locked app account: not ending the session"),
    }
}

/// 托管策略没有隔离好时的错误框（复审 C1）。
pub const POLICY_NOT_ISOLATED: &str = "这个应用的锁定设置没有生效，不能启动，请举手找老师 / This app's lock settings are not in effect, so it cannot start. Please ask your teacher.";
/// 策略文件的读取上限。
const MAX_POLICY_BYTES: u64 = 1024 * 1024;

fn read_capped(p: &Path) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    std::fs::File::open(p)
        .and_then(|f| f.take(MAX_POLICY_BYTES + 1).read_to_end(&mut buf))
        .with_context(|| format!("read {}", p.display()))?;
    if buf.len() as u64 > MAX_POLICY_BYTES {
        bail!("{} is over {MAX_POLICY_BYTES} bytes", p.display());
    }
    Ok(buf)
}

/// `managed` 里恰好只有 [`POLICY_FILE`] 一项、是普通文件（不是符号链接），字节与 agent 写的
/// `<root>/PUBLIC_DIR/<id>/policies/POLICY_FILE` 相同；否则是原因。
pub fn check_managed_policy(root: &Path, managed: &Path, id: &str) -> Result<()> {
    let ours = read_capped(
        &root
            .join(PUBLIC_DIR)
            .join(id)
            .join(POLICIES_DIR)
            .join(POLICY_FILE),
    )?;
    let mut names = Vec::new();
    for e in std::fs::read_dir(managed).with_context(|| format!("list {}", managed.display()))? {
        names.push(
            e.with_context(|| format!("list {}", managed.display()))?
                .file_name()
                .to_string_lossy()
                .into_owned(),
        );
    }
    names.sort();
    if names != [POLICY_FILE] {
        bail!(
            "{} contains {names:?}; it must be exactly [{POLICY_FILE:?}]",
            managed.display()
        );
    }
    let p = managed.join(POLICY_FILE);
    let md = std::fs::symlink_metadata(&p).with_context(|| format!("stat {}", p.display()))?;
    if !md.file_type().is_file() {
        bail!("{} is not a regular file", p.display());
    }
    if read_capped(&p)? != ours {
        bail!("{} differs from the policy of this app", p.display());
    }
    Ok(())
}

/// 读 `<root>/PUBLIC_DIR/<id>/launch.json`，里面的 id 要对得上。
pub fn read_launch(root: &Path, id: &str) -> Result<Launch> {
    let p: PathBuf = root.join(PUBLIC_DIR).join(id).join(LAUNCH_FILE);
    let mut buf = Vec::new();
    std::fs::File::open(&p)
        .and_then(|f| f.take(MAX_LAUNCH_BYTES).read_to_end(&mut buf))
        .with_context(|| format!("read {}", p.display()))?;
    let l: Launch =
        serde_json::from_slice(&buf).with_context(|| format!("parse {}", p.display()))?;
    if l.id != id {
        bail!("the id in {} is {:?}, not {id:?}", p.display(), l.id);
    }
    Ok(l)
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

/// `mastersos-kiosk run [<id>]`。`spawn` 起一个进程并等它退出（起不来是错误，同样算一次退出），`now` 是时钟。
/// 返回是否正常走完（应用退出、会话已结束）；不在锁定会话里、id 对不上、启动描述读不到都是 false，也结束会话。
/// 不是 `kiosk-*` 的账号（在登录界面的齿轮里选了锁定会话）同样结束它**自己的**会话、写一行 journald（没有 id），
/// 免得留下一个什么都没起的 gnome-kiosk 黑屏（复审 M2）。
pub fn run(
    ctx: &Ctx,
    arg_id: Option<&str>,
    spawn: &mut dyn FnMut(&[String]) -> std::io::Result<()>,
    now: &mut dyn FnMut() -> Instant,
) -> bool {
    let user = (ctx.env)("USER").unwrap_or_default();
    let id = match id_from_user(&user) {
        Ok(id) => id,
        Err(why) => {
            let detail = format!("{why}: not starting the app; ending this session");
            eprintln!("mastersos-kiosk run: {detail}");
            (ctx.journal)("", MSG_ABNORMAL, Some(&detail));
            end_session(ctx);
            return false;
        }
    };
    let refuse = |detail: String| {
        eprintln!("mastersos-kiosk run: {detail}");
        (ctx.journal)(&id, MSG_ABNORMAL, Some(&detail));
        end_session(ctx);
        false
    };
    if !session_is_kiosk(ctx, &user) {
        return refuse(format!(
            "not in the {SESSION} session (XDG_SESSION_DESKTOP = {:?}); not starting the app",
            (ctx.env)("XDG_SESSION_DESKTOP")
        ));
    }
    if let Some(a) = arg_id {
        if a != id {
            return refuse(format!(
                "the id {a:?} in the arguments does not belong to this account ({id})"
            ));
        }
    }
    let launch = match read_launch(ctx.root, &id) {
        Ok(l) => l,
        Err(e) => return refuse(format!("{e:#}")),
    };
    // 家目录照账号名（与 ephemeral::kiosk 同一个），不信 $HOME
    let home = PathBuf::from(format!("/home/{user}"));
    // 复审 C1 的纵深防御：应用只在 Chrome 读到的托管策略恰好是这个应用自己的那一份时才起。pam_namespace 没把
    // 实例换进这个进程所在的挂载命名空间（应用跑在 user@<uid>.service 里，那里的 PAM 栈是 systemd-user）、实例是空的或
    // 多了整机的策略时，Chrome 会照整机（分组）的策略开，没有任何锁定——宁可不起。错误页也不开（同样是这个 Chrome）。
    // 本地程序同样核对（终审 I1）：程序里的链接会在这个命名空间里起 Chrome，它也该拿到这个应用的禁止一切的那份
    if let Err(e) = check_managed_policy(ctx.root, ctx.managed_dir, &id) {
        let detail = format!("the Chrome managed policy is not the one for this app ({e:#}); not starting the app, ending the session");
        eprintln!("mastersos-kiosk run: {detail}");
        (ctx.journal)(&id, MSG_ABNORMAL, Some(&detail));
        if let Err(e) = spawn(&zenity_error_argv(POLICY_NOT_ISOLATED)) {
            eprintln!("mastersos-kiosk run: cannot show the error dialog: {e}");
        }
        end_session(ctx);
        return false;
    }
    (ctx.journal)(&id, MSG_ENTER, None);
    let argv = app_argv(&launch, &home);
    if let LaunchKind::Exec { .. } = launch.kind {
        // 本地程序没有考试扩展，退出靠它自己的「退出」：退出就结束会话（设计 §4.4）
        match spawn(&argv) {
            Ok(()) => (ctx.journal)(&id, MSG_EXIT, None),
            Err(e) => (ctx.journal)(&id, MSG_ABNORMAL, Some(&format!("failed to start: {e}"))),
        }
    } else {
        let mut sup = Supervisor::new();
        let error = error_argv(&home);
        let mut current = &argv;
        loop {
            if let Err(e) = spawn(current) {
                eprintln!("mastersos-kiosk run: {} failed to start: {e}", current[0]);
            }
            match sup.next_action(now()) {
                Next::Restart => {}
                Next::ShowError => {
                    (ctx.journal)(
                        &id,
                        MSG_ABNORMAL,
                        Some(&format!(
                            "exited {1} times within {0} seconds; opening the error page",
                            sup.window.as_secs(),
                            sup.max_exits
                        )),
                    );
                    current = &error;
                }
                Next::EndSession => break,
            }
        }
    }
    end_session(ctx);
    true
}

/// 真的起进程并等它退出（退出码不看：退出就是退出）。
fn spawn_wait(argv: &[String]) -> std::io::Result<()> {
    spawn_status(argv).map(|_| ())
}

// ---------------------------------------------------------------------------
// exit-host
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    Exit,
    Invalid,
}

/// 读一条 native messaging 消息：4 字节小端长度 + JSON。只认恰好 `{"cmd":"exit"}`（不多一个键）；长度超过
/// [`MAX_MESSAGE`] 的不读内容，头或内容读不满、不是这个形状的都是 `Invalid`。
pub fn read_request(r: &mut dyn Read) -> Request {
    let mut len = [0u8; 4];
    if r.read_exact(&mut len).is_err() {
        return Request::Invalid;
    }
    let n = u32::from_le_bytes(len) as usize;
    if n > MAX_MESSAGE {
        return Request::Invalid;
    }
    let mut body = vec![0u8; n];
    if r.read_exact(&mut body).is_err() {
        return Request::Invalid;
    }
    // 按 Value 看：反序列化成结构体的话，serde 也收 `["exit"]` 这样的数组
    match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(serde_json::Value::Object(m))
            if m.len() == 1 && m.get("cmd").and_then(|c| c.as_str()) == Some("exit") =>
        {
            Request::Exit
        }
        _ => Request::Invalid,
    }
}

/// 回给扩展的一帧：`{"ok":true}` 或 `{"ok":false}`。
pub fn reply(ok: bool) -> Vec<u8> {
    let body: &[u8] = if ok {
        br#"{"ok":true}"#
    } else {
        br#"{"ok":false}"#
    };
    let mut v = (body.len() as u32).to_le_bytes().to_vec();
    v.extend_from_slice(body);
    v
}

/// `mastersos-kiosk exit-host`：读一条消息，是 `exit` 而且结束得了会话（[`terminate_target`]）就先回 `{"ok":true}`
/// （结束会话之后就回不了了）、写 journald 的「退出」、再结束会话；否则回 `{"ok":false}`。返回回的是不是 true。
pub fn exit_host(input: &mut dyn Read, output: &mut dyn Write, ctx: &Ctx) -> bool {
    let target = match read_request(input) {
        Request::Exit => terminate_target(ctx),
        Request::Invalid => None,
    };
    let ok = target.is_some();
    let _ = output.write_all(&reply(ok)).and_then(|()| output.flush());
    if let Some(t) = target {
        if let Some(id) = (ctx.env)("USER").and_then(|u| id_from_user(&u).ok()) {
            (ctx.journal)(&id, MSG_EXIT, None);
        }
        if let Err(e) = terminate(ctx.runner, &t) {
            eprintln!("mastersos-kiosk exit-host: failed to end the session: {e:#}");
        }
    }
    ok
}

// ---------------------------------------------------------------------------
// enter
// ---------------------------------------------------------------------------

/// 结束不了当前会话时错误框的文字（中英）。
pub const ENTER_FAILED: &str = "结束不了当前会话，请注销后在登录界面点这个应用 / Could not end your session. Please sign out and open this app from the sign-in screen";

/// 确认框的文字（中英）。
pub fn enter_text(name: &str) -> String {
    format!("将结束当前会话，进入 {name} 锁定模式 / This will end your session and open {name}")
}

/// zenity 的确认框。`--no-markup`：应用名里的 `<`、`&` 原样显示，不当 Pango 标记。
pub fn zenity_argv(text: &str) -> Vec<String> {
    vec![
        "zenity".into(),
        "--question".into(),
        "--no-markup".into(),
        "--title=MastersOS".into(),
        format!("--text={text}"),
    ]
}

/// zenity 的错误框，同样不解析标记。
pub fn zenity_error_argv(text: &str) -> Vec<String> {
    vec![
        "zenity".into(),
        "--error".into(),
        "--no-markup".into(),
        "--title=MastersOS".into(),
        format!("--text={text}"),
    ]
}

/// `mastersos-kiosk enter <id>`：id 合规、这个应用在这台机器上建好了（有启动描述）才问；`confirm` 回 true 就结束当前
/// 会话，false 什么都不做。确认了却找不到当前会话、或 loginctl 失败：`error` 弹 [`ENTER_FAILED`]、返回错误。
pub fn enter(
    ctx: &Ctx,
    id: &str,
    confirm: &mut dyn FnMut(&str) -> bool,
    error: &mut dyn FnMut(&str),
) -> Result<()> {
    kiosk::check_id(id).map_err(|e| anyhow!(e.message))?;
    let l = read_launch(ctx.root, id)?;
    if !confirm(&enter_text(&l.name)) {
        return Ok(());
    }
    let r = terminate_target(ctx)
        .ok_or_else(|| {
            anyhow!(
                "no current session found (no XDG_SESSION_ID and no graphical session in logind)"
            )
        })
        .and_then(|t| terminate(ctx.runner, &t));
    if r.is_err() {
        error(ENTER_FAILED);
    }
    r
}

/// 起进程、等它退出：stdin 接空，stdout / stderr 照会话的（进 journald）。
fn spawn_status(argv: &[String]) -> std::io::Result<std::process::ExitStatus> {
    let (prog, args) = argv
        .split_first()
        .ok_or_else(|| std::io::Error::other("empty command line"))?;
    Command::new(prog).args(args).stdin(Stdio::null()).status()
}

fn zenity_confirm(text: &str) -> bool {
    spawn_status(&zenity_argv(text)).is_ok_and(|s| s.success())
}

fn zenity_error(text: &str) {
    let _ = spawn_status(&zenity_error_argv(text));
}

// ---------------------------------------------------------------------------
// journald
// ---------------------------------------------------------------------------

/// journald 原生协议的一条记录（字段一行一个）。`id` 已校验（空的是不是锁定应用的账号，不写 `MASTERSOS_KIOSK`）、
/// `msg` 是固定的文字；`detail` 里的控制字符换成空格，
/// 不会拆出新的字段。
pub fn journal_record(id: &str, msg: &str, detail: Option<&str>) -> Vec<u8> {
    let clean = |s: &str| -> String {
        s.chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect()
    };
    let mut s = format!("MESSAGE={}\n", clean(msg));
    if !id.is_empty() {
        s.push_str(&format!("MASTERSOS_KIOSK={}\n", clean(id)));
    }
    if let Some(d) = detail {
        s.push_str(&format!("MASTERSOS_KIOSK_DETAIL={}\n", clean(d)));
    }
    let priority = if msg == MSG_ABNORMAL || msg == MSG_WRONG_SESSION {
        4
    } else {
        5
    };
    s.push_str(&format!(
        "SYSLOG_IDENTIFIER=mastersos-kiosk\nPRIORITY={priority}\n"
    ));
    s.into_bytes()
}

/// 发给 journald；发不出去就打到 stderr（会话的 stderr 同样进 journal，只是没有 `MASTERSOS_KIOSK` 字段）。
fn journal_send(id: &str, msg: &str, detail: Option<&str>) {
    let rec = journal_record(id, msg, detail);
    let sent =
        std::os::unix::net::UnixDatagram::unbound().and_then(|s| s.send_to(&rec, JOURNAL_SOCKET));
    if sent.is_err() {
        eprintln!(
            "mastersos-kiosk: MASTERSOS_KIOSK={id} {msg}{}",
            detail.map(|d| format!(": {d}")).unwrap_or_default()
        );
    }
}

/// `mastersos-kiosk guard`: a user unit required by `gnome-session-pre.target`, so it runs in every GNOME session after
/// GDM has set `XDG_SESSION_DESKTOP` to the session it actually started and before GNOME Shell. A kiosk uid
/// ([`KIOSK_UIDS`]) in any other session — or with the variable missing — fails, and the target's `OnFailure` ends
/// the session. This backs up pam-session, which can only see what GDM saved to AccountsService (review I1). Other
/// uids pass; `run` ends a non-kiosk account that picked the kiosk session.
pub fn guard(ctx: &Ctx, uid: u32) -> bool {
    if !KIOSK_UIDS.contains(&uid) || in_kiosk_session(ctx.env) {
        return true;
    }
    let user = (ctx.env)("USER").unwrap_or_default();
    let id = user.strip_prefix("kiosk-").unwrap_or(&user);
    let desktop = (ctx.env)("XDG_SESSION_DESKTOP");
    (ctx.journal)(
        id,
        MSG_WRONG_SESSION,
        Some(&format!("uid {uid}, XDG_SESSION_DESKTOP={desktop:?}")),
    );
    false
}

// ---------------------------------------------------------------------------
// 入口
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sub {
    Run(Option<String>),
    ExitHost,
    Enter(String),
    Guard,
}

/// `run [<id>]`、`exit-host [Chrome 追加的参数…]`、`enter <id>`。
pub fn parse(args: &[String]) -> Result<Sub, String> {
    match args {
        [s] if s == "run" => Ok(Sub::Run(None)),
        [s, id] if s == "run" => Ok(Sub::Run(Some(id.clone()))),
        [s, ..] if s == "exit-host" => Ok(Sub::ExitHost),
        [s, id] if s == "enter" => Ok(Sub::Enter(id.clone())),
        [s] if s == "guard" => Ok(Sub::Guard),
        _ => Err("usage: mastersos-kiosk run [<id>] | exit-host | enter <id> | guard".into()),
    }
}

/// `mastersos-agent kiosk …`（`args` 是 `kiosk` 之后的参数）。
pub fn main(args: impl Iterator<Item = OsString>) -> ExitCode {
    let args: Option<Vec<String>> = args.map(|a| a.into_string().ok()).collect();
    let sub = match args
        .ok_or_else(|| "argument is not UTF-8".to_string())
        .and_then(|a| parse(&a))
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("mastersos-kiosk: {e}");
            return ExitCode::from(2);
        }
    };
    let env = |k: &str| std::env::var(k).ok();
    let ctx = Ctx {
        env: &env,
        runner: &RealRunner,
        journal: &journal_send,
        root: Path::new("/"),
        managed_dir: Path::new(NS_POLYDIR),
    };
    let done = match sub {
        Sub::Run(id) => run(&ctx, id.as_deref(), &mut spawn_wait, &mut Instant::now),
        Sub::ExitHost => exit_host(
            &mut std::io::stdin().lock(),
            &mut std::io::stdout().lock(),
            &ctx,
        ),
        Sub::Enter(id) => match enter(&ctx, &id, &mut zenity_confirm, &mut zenity_error) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("mastersos-kiosk enter: {e:#}");
                false
            }
        },
        Sub::Guard => guard(&ctx, rustix::process::getuid().as_raw()),
    };
    if done {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests;
