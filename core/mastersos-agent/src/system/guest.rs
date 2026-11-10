//! 访客（Ruling 5）：账号 `guest`（uid 1999、无口令），家目录每次会话前是一份新挂的 tmpfs。
//!
//! 家目录的清理与开会话的检查是所有临时账号共用的机制，在 [`super::ephemeral`]（模块文档记着顺序与理由：等 slice
//! 停下之后才碰访客能写的东西、按 fd 卸载、标记在 `/run/mastersos`）；访客是其中的 [`super::ephemeral::guest`]。
//! 这里只剩访客自己的部分：
//! - 盘上与单元里的名字（[`READY_MARK`]、[`OPENING_MARK`]、[`CLEANUP_UNIT`]、[`SLICE`]……），`ephemeral::guest()`
//!   取自它们，一个都不变。
//! - 清理（`mastersos-agent guest-cleanup`，`ephemeral-cleanup guest` 的别名，root，`mastersos-guest-cleanup.service`，
//!   在 `system.slice`）：访客的 user manager 停下时（`user@1999.service` 的 `OnSuccess=`/`OnFailure=`）、开机时、
//!   失败后 30 秒（`Restart=on-failure`）与访客点登录被拒时跑。
//! - `mastersos-agent pam-session`：临时账号（访客、登录策略名单里的 `kiosk-<id>`）在 GDM 上开会话走
//!   [`super::ephemeral::session_open`]；访客之后与其余用户一样进登录队列，锁定应用的会话不进（不跑分组的 login 脚本、
//!   不发过期提示）。锁定应用的账号只许开 `mastersos-kiosk` 会话（PAM 环境的 `XDG_SESSION_DESKTOP`），在登录界面换成
//!   Ubuntu 会话的拒绝（[`login::DENY_KIOSK_SESSION`]）。
//! - Step `guest`: always keeps the guest account (guest sign-in is always on; a locked device is denied in `pam-check`
//!   via `decide`). The removal path is reachable only through `converge(false)` and is kept for a possible future switch.
//!
//! 访客与锁定应用的账号能从哪个 PAM 服务登录由 `pam-check`（[`super::login::GUEST_SERVICES`]）管，这里只认同一张表。

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::ffi::OsStr;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{bail, Result};
use mastersos_bundle::{ItemResult, Seed};

use super::ephemeral::{
    self, account, remove_named, reset_password, run_dir, session_open, wait_slice_gone, Ephemeral,
    EphemeralEnv, ProcMounts, SystemdProcs, CMD_TIMEOUT, LINGER_DIR, PAM_CMD_TIMEOUT,
};
use super::kiosk;
use super::login::{self, LoginPolicy, GUEST_SERVICES};
use super::{failed, ok, Env, Step};
use crate::apply::ApplyContext;
use crate::runner::{run_ok, Cmd, RealRunner};
use crate::safefs;

pub const GUEST_USER: &str = login::GUEST_USER;
pub const GUEST_UID: u32 = 1999;
pub const GUEST_HOME: &str = "/home/guest";
pub const READY_MARK: &str = "/run/mastersos/guest-ready";
/// `session_open` 拿走标记时把它改名成这个（同在 `/run/mastersos`）：会话正在打开、还没进 `user-1999.slice` 的那几秒，
/// 别的访客登录被拒时不拉起清理（清理会把正在打开的会话的家目录卸掉）。清理开头删掉它（提交安全审查：授权）。
pub const OPENING_MARK: &str = "guest-opening";

/// 回报项的名字。
pub const ITEM: &str = "guest";
/// 清理服务（`system.slice`）。
pub const CLEANUP_UNIT: &str = "mastersos-guest-cleanup.service";
/// 访客的 slice：会话、user manager 都在它下面；它不再 active 就说明访客的进程都没了。
pub const SLICE: &str = "user-1999.slice";
/// 访客的账号在每次清理后恢复的名字（复审 I3）。
pub const GUEST_COMMENT: &str = "访客 Guest";

/// `session_open` 拒绝时打到 stdout 的话（pam_exec 的 `stdout`，GDM 显示它）。
pub const DENY_BUSY: &str = "上一位访客还没有完全退出，请稍候再试 / The previous guest session is still closing, please try again shortly";
/// 同上，锁定应用的账号（计划 9 Task 4）。
pub const DENY_BUSY_KIOSK: &str = "上一位还没有完全退出，请稍候再试 / The previous session is still closing, please try again shortly";

// ---------------------------------------------------------------------------
// 步骤 `guest`
// ---------------------------------------------------------------------------

pub fn step() -> Step {
    Step {
        name: "guest",
        fast: true,
        run,
        without_bundle: Some(run_seed),
    }
}

fn run(ctx: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
    let p = login::policy_from_bundle(ctx.school, ctx.config, ctx.lock);
    converge(env, p.methods.iter().any(|m| m == "guest"))
}

fn run_seed(seed: &Seed, env: &mut Env) -> Vec<ItemResult> {
    let p = login::policy_from_seed(seed);
    converge(env, p.methods.iter().any(|m| m == "guest"))
}

/// `want == false` is not reachable from the step today (guest is always on); kept for a possible future switch.
fn converge(env: &mut Env, want: bool) -> Vec<ItemResult> {
    vec![match converge_inner(env, want) {
        Ok(()) => ok(ITEM),
        Err(e) => failed(ITEM, format!("{e:#}")),
    }]
}

fn converge_inner(env: &mut Env, want: bool) -> Result<()> {
    let r = env.runner;
    match (want, account(r, GUEST_USER)?) {
        (true, None) => {
            run_ok(
                r,
                Cmd::new(
                    "useradd",
                    &[
                        "--uid",
                        &GUEST_UID.to_string(),
                        "--user-group",
                        "--no-create-home",
                        "--home-dir",
                        GUEST_HOME,
                        "--shell",
                        "/bin/bash",
                        "--comment",
                        GUEST_COMMENT,
                        GUEST_USER,
                    ],
                ),
            )?;
            reset_password(r, &ephemeral::guest())?;
            // 备好第一份 tmpfs。--no-block：开机快速应用（mastersos-agent-local）里也跑这一步
            run_ok(
                r,
                Cmd::new("systemctl", &["start", "--no-block", CLEANUP_UNIT]),
            )?;
            Ok(())
        }
        (true, Some((uid, _))) if uid != GUEST_UID => {
            bail!("the existing {GUEST_USER} account has uid {uid}, not {GUEST_UID}; leaving it alone")
        }
        (true, Some(_)) | (false, None) => Ok(()),
        (false, Some((uid, _))) => {
            if uid != GUEST_UID {
                bail!("the existing {GUEST_USER} account has uid {uid}, not {GUEST_UID}; leaving it alone");
            }
            let acct = ephemeral::guest();
            let procs = SystemdProcs {
                runner: r,
                timeout: CMD_TIMEOUT,
            };
            let genv = EphemeralEnv {
                runner: r,
                procs: &procs,
                root: &env.paths.root,
                uid: acct.uid,
                mounts: &ProcMounts,
                acct: &acct,
            };
            // linger 文件 userdel 不删，留着 user manager 就停不下（复审 I2）
            remove_named(&genv, LINGER_DIR, GUEST_USER)?;
            // 没登录时 terminate-user 退出码非 0：不算错，下面等 slice 停下才是判据
            let _ = r.run(&Cmd::new("loginctl", &["terminate-user", GUEST_USER]));
            wait_slice_gone(&genv)?;
            run_ok(r, Cmd::new("userdel", &[GUEST_USER]))?;
            // user@1999 停下时拉起的清理可能在 userdel 之前看到账号、写了标记（复审 M3）：账号没了，标记也不该在
            let run = run_dir(&genv, true)?;
            safefs::remove_at(&run, &acct.ready_mark)?;
            // 卸载与清 /tmp 交给清理服务（账号没了它就不再挂 tmpfs）
            run_ok(
                r,
                Cmd::new("systemctl", &["start", "--no-block", CLEANUP_UNIT]),
            )?;
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// `mastersos-agent pam-session` 与 `mastersos-agent guest-cleanup`
// ---------------------------------------------------------------------------

/// `pam-session` 对一次调用做什么。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionAction {
    /// 不是临时账号、又不是 open_session（close_session 等）；或临时账号的 close_session：什么都不做，退出 0。
    Ignore,
    /// 临时账号（访客、名单里的 `kiosk-<id>`）在 GDM 上开会话：[`ephemeral::session_open`]。访客成功后与别的用户一样
    /// 进登录队列（Task 18）。
    EphemeralOpen(Ephemeral),
    /// 临时账号在 GDM 以外的服务上、PAM_TYPE 认不出、或 kiosk 账号对不上（名单外、uid 不在 1900–1989）：拒绝，
    /// 把这句话打到 stdout。钩子是 requisite，退出 0 就等于放行一个没检查过的会话（钩子只装在 gdm-password 与
    /// gdm-authd 里，服务这条走不到；照样往拒绝的方向落。提交安全审查：授权逻辑）。
    DenyEphemeral(&'static str),
    /// 其他用户：进登录队列。
    Enqueue(String),
}

/// The session GDM is about to start, for open_session only: `XDG_SESSION_DESKTOP` from the PAM environment when the
/// display manager put it there; otherwise, for a kiosk account (reserved name, uid 1900–1989), AccountsService's
/// `Session`. GDM 50 sets the variable only when it starts the session, after `pam_open_session`, but its worker saves
/// the chosen session to AccountsService before opening the PAM session (state ACCOUNT_DETAILS_SAVED). That record can
/// still differ from what GDM starts (a session file GDM rejects, a later SelectSession), so `mastersos-kiosk guard`
/// checks again inside the session (kiosk design §4.3). Unreadable is `None`, which denies a kiosk login as the wrong
/// session. Any other PAM_TYPE gets `env` back without asking (logout must not wait on accounts-daemon).
pub fn session_desktop(
    pam_type: &str,
    env: Option<String>,
    user: &str,
    uid: impl FnOnce() -> Option<u32>,
    runner: &dyn crate::runner::Runner,
) -> Option<String> {
    if env.is_some() || pam_type != "open_session" {
        return env;
    }
    if !login::is_reserved_kiosk_name(user) {
        return None;
    }
    let uid = uid().filter(|u| ephemeral::KIOSK_UIDS.contains(u))?;
    let path = format!("/org/freedesktop/Accounts/User{uid}");
    let out = run_ok(
        runner,
        Cmd::new(
            "busctl",
            &[
                "--json=short",
                "get-property",
                "org.freedesktop.Accounts",
                path.as_str(),
                "org.freedesktop.Accounts.User",
                "Session",
            ],
        )
        .timeout(PAM_CMD_TIMEOUT),
    );
    let read = out.ok().and_then(|o| {
        let v: serde_json::Value = serde_json::from_str(o.trim()).ok()?;
        (v["type"] == "s").then(|| v["data"].as_str().map(str::to_string))?
    });
    match read {
        Some(s) if !s.is_empty() => Some(s),
        _ => {
            eprintln!("mastersos-agent pam-session: {user}: could not read the session from AccountsService");
            None
        }
    }
}

/// 名字精确比较（`Guest`、`guest `、`Kiosk-x` 是别的账号）。访客只有 GDM 的 open_session 走 [`ephemeral::session_open`]，
/// close_session 放行，其余一律拒绝。锁定应用的账号与 `pam-check` 同一个分法（[`login::classify`] 加上受管机器上保留的
/// `kiosk-` 前缀）：名单里的同样只有 GDM 的 open_session 开会话，临时账号由 [`ephemeral::kiosk_account`] 按策略里的名字与
/// `uid`（`getent` 现查，只在要开会话时才查）造，uid 不在 1900–1989 就拒；名单外的（受管机器上）open_session 拒、
/// close_session 放行。其他用户只有 open_session 进登录队列，其余什么都不做。
///
/// `desktop` is what [`session_desktop`] found (the PAM environment's `XDG_SESSION_DESKTOP`, or AccountsService for a
/// kiosk account on GDM 50). A listed kiosk account may only open [`kiosk::SESSION`]: a full Ubuntu session picked in
/// the greeter's gear is an unlocked desktop (controller ruling 4), denied; no value is denied too, both before the uid
/// lookup and the marks. Guests and other users ignore it.
pub fn session_action(
    pam_type: &str,
    service: &str,
    user: &str,
    desktop: Option<&str>,
    managed: bool,
    policy: Option<&LoginPolicy>,
    uid: impl FnOnce() -> Option<u32>,
) -> SessionAction {
    if user == GUEST_USER {
        return match pam_type {
            "open_session" if GUEST_SERVICES.contains(&service) => {
                SessionAction::EphemeralOpen(ephemeral::guest())
            }
            "close_session" => SessionAction::Ignore,
            _ => SessionAction::DenyEphemeral(login::DENY_GUEST_SERVICE),
        };
    }
    let listed = login::classify(user, policy) == login::UserClass::Kiosk;
    // 带 @ 的 SSO 账号不算（login::is_reserved_kiosk_name）：与 pam-check 同一个分法
    if listed || (managed && login::is_reserved_kiosk_name(user)) {
        return match pam_type {
            "close_session" => SessionAction::Ignore,
            _ if !listed => SessionAction::DenyEphemeral(login::DENY_KIOSK_UNKNOWN),
            "open_session"
                if GUEST_SERVICES.contains(&service) && desktop != Some(kiosk::SESSION) =>
            {
                eprintln!(
                    "mastersos-agent pam-session: {user}: session is {desktop:?}, not {}; denied",
                    kiosk::SESSION
                );
                SessionAction::DenyEphemeral(login::DENY_KIOSK_SESSION)
            }
            "open_session" if GUEST_SERVICES.contains(&service) => {
                match ephemeral::kiosk_account(policy, user, uid) {
                    Ok(acct) => SessionAction::EphemeralOpen(acct),
                    Err(why) => {
                        eprintln!("mastersos-agent pam-session: {user}: {why}; denied");
                        SessionAction::DenyEphemeral(login::DENY_KIOSK_UNKNOWN)
                    }
                }
            }
            _ => SessionAction::DenyEphemeral(login::DENY_KIOSK),
        };
    }
    if pam_type == "open_session" {
        SessionAction::Enqueue(user.to_string())
    } else {
        SessionAction::Ignore
    }
}

/// 复审 I2：kiosk 账号因为会话不对被拒（[`login::DENY_KIOSK_SESSION`]）时，GDM 可能已经把选的会话记进
/// accounts-daemon（GDM 经 D-Bus 读它）：不改回去的话，下一位点这个应用默认还是那个会话、同样被拒，直到清理或重启。
/// 这里经 accounts-daemon 自己的接口把 `Session`、`XSession` 改回 [`kiosk::SESSION`]（与清理恢复模板时同一个办法）。
/// 不清理、不结束会话（这个账号这时可能另有会话开着，清理会杀掉它）；uid 要在 1900–1989；调用失败只记一行，拒绝照旧。
/// 别的动作什么都不做。
pub fn after_action(
    action: &SessionAction,
    user: &str,
    uid: impl FnOnce() -> Option<u32>,
    runner: &dyn crate::runner::Runner,
) {
    if *action != SessionAction::DenyEphemeral(login::DENY_KIOSK_SESSION) {
        return;
    }
    let Some(uid) = uid().filter(|u| ephemeral::KIOSK_UIDS.contains(u)) else {
        eprintln!(
            "mastersos-agent pam-session: uid of {user} is not in 1900-1989; not changing AccountsService"
        );
        return;
    };
    let path = format!("/org/freedesktop/Accounts/User{uid}");
    for method in ["SetSession", "SetXSession"] {
        let r = runner.run(
            &Cmd::new(
                "busctl",
                &[
                    "call",
                    "org.freedesktop.Accounts",
                    path.as_str(),
                    "org.freedesktop.Accounts.User",
                    method,
                    "s",
                    kiosk::SESSION,
                ],
            )
            .timeout(PAM_CMD_TIMEOUT),
        );
        match r {
            Ok(o) if o.code == 0 => {}
            Ok(o) => eprintln!(
                "mastersos-agent pam-session: {user}: {method} exited with code {}: {}",
                o.code,
                o.stderr.trim()
            ),
            Err(e) => eprintln!("mastersos-agent pam-session: {user}: {method}: {e:#}"),
        }
    }
}

/// 终审 C1（Switch User 的逃逸）：锁定会话不许开在座位上另一个还活着的用户会话旁边——否则学生在桌面会话里「切换用户」、
/// 在登录界面点锁定应用，再用 `loginctl activate`（会话的主人不需要 polkit）或再切一次回到完整的桌面，两边来回切。
/// 只管 kiosk 账号的 [`SessionAction::EphemeralOpen`]：问 logind 这个座位上的会话（[`seat_sessions_busy`]），有别的 `user*`
/// 类会话不在 `closing` 就拒（[`login::DENY_KIOSK_OTHER_SESSION`]），查不到也拒（[`login::DENY_KIOSK_SEAT_UNKNOWN`]）。
/// 访客、普通用户与已经是拒绝的动作原样返回、不查。
///
/// 正在打开的这个会话不会把自己挡住：`pam-session` 排在 session 段第一行、早于 `pam_systemd`
/// （测试 `open_runs_before_pam_systemd` 核对），logind 的 `CreateSession` 由后者发出，这时还没有它。
/// 从桌面「进入」（`mastersos-kiosk enter`）先结束当前会话：那个会话在 logind 里马上变成 `closing`，不挡。
/// 不在全局锁 `disable-user-switching`：那会改掉每个分组的桌面（控制者裁定）。
pub fn seat_guard(
    action: SessionAction,
    seat: Option<&str>,
    runner: &dyn crate::runner::Runner,
) -> SessionAction {
    let SessionAction::EphemeralOpen(acct) = &action else {
        return action;
    };
    if acct.user == GUEST_USER {
        return action;
    }
    match seat_sessions_busy(runner, seat) {
        Ok(None) => action,
        Ok(Some(other)) => {
            eprintln!(
                "mastersos-agent pam-session: {}: seat still has session {other}; denied",
                acct.user
            );
            SessionAction::DenyEphemeral(login::DENY_KIOSK_OTHER_SESSION)
        }
        Err(e) => {
            eprintln!(
                "mastersos-agent pam-session: {}: cannot list the sessions on the seat ({e:#}); denied",
                acct.user
            );
            SessionAction::DenyEphemeral(login::DENY_KIOSK_SEAT_UNKNOWN)
        }
    }
}

/// `loginctl --json=short list-sessions`（[`PAM_CMD_TIMEOUT`]）：`seat` 上第一个挡路的会话（`"<id> <user> <class> <state>"`），
/// 没有就是 `None`。挡路 = class 以 `user` 开头（`user`、`user-early`、`user-incomplete`、`user-light`；`greeter`、
/// `lock-screen`、`manager`、`background` 不算）且 state 不是 `closing`（`online`、`active`、`opening` 与认不出的都算）。
/// `seat` 是 `None`（PAM 环境里没有 `XDG_SEAT`）时任何座位上的都算；没有座位的（ssh）不算。
/// 每一行都要有 `class` 与 `seat`：缺了就报错，不猜。Rows without `state` (systemd 259 dropped it from the JSON) that
/// could block get it from `loginctl show-session <id> -p State --value`; failing or empty output is an error too.
pub fn seat_sessions_busy(
    runner: &dyn crate::runner::Runner,
    seat: Option<&str>,
) -> Result<Option<String>> {
    use anyhow::Context;
    let out = run_ok(
        runner,
        Cmd::new("loginctl", &["--json=short", "list-sessions"]).timeout(PAM_CMD_TIMEOUT),
    )?;
    let v: serde_json::Value =
        serde_json::from_str(out.trim()).context("loginctl output is not JSON")?;
    let rows = v.as_array().context("loginctl output is not an array")?;
    for row in rows {
        let o = row.as_object().context("loginctl row is not an object")?;
        let field = |k: &str| o.get(k).and_then(|x| x.as_str());
        let class = field("class").context("loginctl row has no class")?;
        // seat 栏同样要有：null、"" 与 "-" 是没有座位（ssh）；缺栏或别的类型读不懂，往拒绝的方向落
        let on = match o.get("seat").context("loginctl row has no seat")? {
            serde_json::Value::Null => "",
            serde_json::Value::String(s) if s == "-" => "",
            serde_json::Value::String(s) => s.as_str(),
            _ => anyhow::bail!("loginctl seat field is not a string"),
        };
        let same_seat = match seat {
            Some(want) => on == want,
            None => !on.is_empty(),
        };
        if !same_seat || !class.starts_with("user") {
            continue;
        }
        let id = field("session").context("loginctl row has no session")?;
        // systemd 259 dropped `state` from list-sessions JSON: ask logind for this one session instead of guessing
        let state = match field("state") {
            Some(s) => s.to_string(),
            None => {
                let out = run_ok(
                    runner,
                    Cmd::new("loginctl", &["show-session", id, "-p", "State", "--value"])
                        .timeout(PAM_CMD_TIMEOUT),
                )?;
                let s = out.trim();
                anyhow::ensure!(!s.is_empty(), "loginctl show-session {id} printed no State");
                s.to_string()
            }
        };
        if state != "closing" {
            return Ok(Some(format!(
                "{id} {} {class} {state}",
                field("user").unwrap_or("?")
            )));
        }
    }
    Ok(None)
}

fn env_str(name: &str) -> String {
    std::env::var_os(name)
        .and_then(|v| v.into_string().ok())
        .unwrap_or_default()
}

/// `mastersos-agent pam-session`（PAM 的 session 段最前面，root）。访客开会话失败退出 1 并把 [`DENY_BUSY`] 打到
/// stdout；其他情况永远退出 0（登录队列失败不挡登录）。不 panic、不建 tokio 运行时、不往 stderr 打日志之外的事。
pub fn pam_session_main() -> ExitCode {
    // 只有 root（PAM 里的 gdm-session-worker 经 pam_exec）调它才算数：PAM_* 环境变量谁都能伪造，普通用户自己跑它
    // 什么都不许做——不拿标记、不复制、不拉起清理、不进登录队列（提交安全审查：授权）
    if !rustix::process::geteuid().is_root() {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(
            out,
            "mastersos-agent pam-session must be called by PAM as root"
        );
        let _ = out.flush();
        return ExitCode::FAILURE;
    }
    let user = env_str("PAM_USER");
    // 与 pam-check 读同一份策略（锁定应用的名单）；读不到时名单为空，kiosk 账号往拒绝的方向落
    let (managed, policy) = login::installed_policy();
    // pam_exec hands the PAM environment to the child; GDM 50 has no XDG_SESSION_DESKTOP there yet (session_desktop)
    let pam_type = env_str("PAM_TYPE");
    let desktop = session_desktop(
        &pam_type,
        std::env::var_os("XDG_SESSION_DESKTOP").and_then(|v| v.into_string().ok()),
        &user,
        || login::lookup_uid_checked(&user),
        &RealRunner,
    );
    let action = session_action(
        &pam_type,
        &env_str("PAM_SERVICE"),
        &user,
        desktop.as_deref(),
        managed,
        policy.as_ref(),
        || login::lookup_uid_checked(&user),
    );
    // GDM 把座位放进 PAM 环境（pam_systemd 也从那里读）；没有就按任何座位算
    let seat = std::env::var_os("XDG_SEAT").and_then(|v| v.into_string().ok());
    let action = seat_guard(action, seat.as_deref(), &RealRunner);
    after_action(
        &action,
        &user,
        || login::lookup_uid_checked(&user),
        &RealRunner,
    );
    match action {
        SessionAction::Ignore => ExitCode::SUCCESS,
        SessionAction::DenyEphemeral(msg) => {
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "{msg}");
            let _ = out.flush();
            ExitCode::FAILURE
        }
        SessionAction::Enqueue(user) => {
            if let Some(uid) = login::lookup_uid_checked(&user) {
                // a school account that just signed in with the card claims the card's cookies (never fails the login)
                crate::signin_handoff::claim_from_pam(&env_str("PAM_SERVICE"), &user, uid);
                let _ = crate::login_queue::enqueue(uid);
            }
            ExitCode::SUCCESS
        }
        SessionAction::EphemeralOpen(acct) => {
            let runner = RealRunner;
            let procs = SystemdProcs {
                runner: &runner,
                timeout: PAM_CMD_TIMEOUT,
            };
            let env = EphemeralEnv {
                runner: &runner,
                procs: &procs,
                root: Path::new("/"),
                uid: acct.uid,
                mounts: &ProcMounts,
                acct: &acct,
            };
            match session_open(&env) {
                Ok(()) => {
                    // 访客也是一次登录：叫醒 agent 拉取、跑 login 脚本（访客每次会话都跑）、发过期提示。不挡登录。
                    // 锁定应用的会话不进队列：分组的 login 脚本与过期提示不该出现在锁定会话里
                    if acct.user == GUEST_USER {
                        let _ = crate::login_queue::enqueue(GUEST_UID);
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    let _ = writeln!(std::io::stderr(), "mastersos-agent pam-session: {e:#}");
                    let mut out = std::io::stdout().lock();
                    let _ = writeln!(out, "{}", busy_message(&acct));
                    let _ = out.flush();
                    ExitCode::FAILURE
                }
            }
        }
    }
}

/// `session_open` 被拒时打给 GDM 的话。
pub fn busy_message(acct: &Ephemeral) -> &'static str {
    if acct.user == GUEST_USER {
        DENY_BUSY
    } else {
        DENY_BUSY_KIOSK
    }
}

/// `mastersos-agent guest-cleanup`（`mastersos-guest-cleanup.service`）：`ephemeral-cleanup guest` 的别名，现有单元不改。
pub fn guest_cleanup_main() -> ExitCode {
    ephemeral::cleanup_main(Some(OsStr::new(GUEST_USER)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::super::ephemeral::{
        account_mount_under, cleanup, rel, unescape_findmnt, Ephemeral, MountOps, Procs, TMP_DIRS,
    };
    use super::super::tests::{group, paths, tmp_root};
    use super::*;
    use crate::apply::Phase;
    use crate::runner::{FakeRunner, Output};
    use crate::system::SysState;
    use anyhow::anyhow;
    use mastersos_bundle::{Manifest, School};
    use std::collections::VecDeque;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, LazyLock, Mutex};
    use std::time::Duration;

    /// 这些测试测的都是访客这一个临时账号。
    static G: LazyLock<Ephemeral> = LazyLock::new(ephemeral::guest);

    /// 前几次按 `seq` 回答，之后一直回答 `then`；记下每次回答时 runner 已有几次调用（排序用）。
    struct FakeProcs {
        seq: Mutex<VecDeque<bool>>,
        then: bool,
        runner: Arc<FakeRunner>,
        /// (runner 已有的调用数, 回答)
        polls: Mutex<Vec<(usize, bool)>>,
        sleeps: Mutex<u32>,
    }

    impl FakeProcs {
        fn new(runner: &Arc<FakeRunner>, seq: &[bool], then: bool) -> FakeProcs {
            FakeProcs {
                seq: Mutex::new(seq.iter().copied().collect()),
                then,
                runner: runner.clone(),
                polls: Mutex::new(Vec::new()),
                sleeps: Mutex::new(0),
            }
        }
        /// 第一次回答 inactive 时 runner 已有几次调用。
        fn first_inactive(&self) -> Option<usize> {
            self.polls
                .lock()
                .unwrap()
                .iter()
                .find(|(_, a)| !a)
                .map(|(n, _)| *n)
        }
    }

    impl Procs for FakeProcs {
        fn slice_active(&self, _slice: &str) -> Result<bool> {
            let a = self.seq.lock().unwrap().pop_front().unwrap_or(self.then);
            self.polls
                .lock()
                .unwrap()
                .push((self.runner.calls().len(), a));
            Ok(a)
        }
        fn sleep(&self, _: Duration) {
            *self.sleeps.lock().unwrap() += 1;
        }
    }

    /// 访客与普通用户的判定与是否受管、名单无关：未受管、没有策略、查不到 uid。
    fn sa(pam_type: &str, service: &str, user: &str) -> SessionAction {
        session_action(pam_type, service, user, None, false, None, || None)
    }

    fn me() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    /// 临时的系统根：/run/mastersos、/home、几个 tmp 目录、/etc/skel、linger、AccountsService、journal。
    fn sysroot() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for p in [
            "run/mastersos",
            "home",
            "tmp",
            "var/tmp",
            "dev/shm",
            "run/lock",
            "etc/skel",
            "var/lib/systemd/linger",
            "var/lib/AccountsService/users",
            "var/lib/AccountsService/icons",
            "var/log/journal/0123abcd",
        ] {
            fs::create_dir_all(d.path().join(p)).unwrap();
        }
        fs::write(d.path().join("etc/skel/.bashrc"), b"# skel\n").unwrap();
        // 不随 umask：/home 要是组与其他人不可写的
        fs::set_permissions(d.path().join("home"), fs::Permissions::from_mode(0o755)).unwrap();
        d
    }

    fn mark(root: &Path) -> PathBuf {
        root.join(rel(Path::new(READY_MARK)))
    }

    fn home_line(root: &Path) -> String {
        root.join("home/guest").to_string_lossy().into_owned()
    }

    fn getent_line(uid: u32) -> Output {
        Output::ok(&format!(
            "guest:x:{uid}:{uid}:访客 Guest:/home/guest:/bin/bash\n"
        ))
    }

    fn idx(calls: &[String], prefix: &str) -> Option<usize> {
        calls.iter().position(|c| c.starts_with(prefix))
    }

    /// 假的按 fd 卸载：登记过的目录（按 dev/ino 认）对应一个挂载 id；记下卸了哪些、卸的时候 runner 已有几次调用。
    struct FakeMounts {
        ids: Mutex<std::collections::HashMap<(u64, u64), u64>>,
        detached: Mutex<Vec<(u64, usize)>>,
        runner: Arc<FakeRunner>,
    }

    impl FakeMounts {
        fn new(r: &Arc<FakeRunner>) -> FakeMounts {
            FakeMounts {
                ids: Mutex::new(std::collections::HashMap::new()),
                detached: Mutex::new(Vec::new()),
                runner: r.clone(),
            }
        }
        /// `path`（建出来）登记为挂载 `id`。
        fn add(&self, path: &Path, id: u64) {
            use std::os::unix::fs::MetadataExt;
            fs::create_dir_all(path).unwrap();
            let m = fs::metadata(path).unwrap();
            self.ids.lock().unwrap().insert((m.dev(), m.ino()), id);
        }
        fn detached_ids(&self) -> Vec<u64> {
            self.detached
                .lock()
                .unwrap()
                .iter()
                .map(|(i, _)| *i)
                .collect()
        }
    }

    impl MountOps for FakeMounts {
        fn mount_id(&self, fd: &std::os::fd::OwnedFd) -> Result<u64> {
            let st = rustix::fs::fstat(fd).map_err(std::io::Error::from)?;
            self.ids
                .lock()
                .unwrap()
                .get(&(st.st_dev as u64, st.st_ino as u64))
                .copied()
                .ok_or_else(|| anyhow!("not a registered mount"))
        }
        fn detach(&self, fd: &std::os::fd::OwnedFd) -> Result<()> {
            let id = self.mount_id(fd)?;
            let n = self.runner.calls().len();
            self.detached.lock().unwrap().push((id, n));
            Ok(())
        }
    }

    /// 挂载表的一行：`路径 [类型 [选项]]`（默认 tmpfs、rw），id 从 100 起依次给；登记到 `fm`。
    fn mount_list(fm: &FakeMounts, mounts: &[String]) -> String {
        let mut list = String::from("1 ext4 rw /\n");
        for (i, m) in mounts.iter().enumerate() {
            let f: Vec<&str> = m.splitn(3, ' ').collect();
            let id = 100 + i as u64;
            let (t, fstype, opts) = (
                f[0],
                f.get(1).copied().unwrap_or("tmpfs"),
                f.get(2).copied().unwrap_or("rw"),
            );
            // 只登记测试的临时目录下的（tempfile 的目录名以 .tmp 开头），/proc 这类不碰
            if t.contains("/.tmp") {
                fm.add(Path::new(t), id);
            }
            list.push_str(&format!("{id} {fstype} {opts} {t}\n"));
        }
        list
    }

    /// 一次正常清理要的回答：uid 是访客的、挂载表（读两次：家目录一次、/tmp 等一次）、账号在（查两次：挂之前与写标记之前）。
    fn answers(r: &Arc<FakeRunner>, uid: u32, mounts: &[String]) -> FakeMounts {
        let fm = FakeMounts::new(r);
        r.respond(&format!("getent passwd {uid}"), getent_line(uid));
        let list = mount_list(&fm, mounts);
        r.respond(FINDMNT, Output::ok(&list));
        r.respond(FINDMNT, Output::ok(&list));
        r.respond("getent passwd guest", getent_line(uid));
        r.respond("getent passwd guest", getent_line(uid));
        fm
    }

    const FINDMNT: &str = "findmnt -rn -o ID,FSTYPE,OPTIONS,TARGET";

    fn genv<'a>(
        r: &'a FakeRunner,
        p: &'a FakeProcs,
        root: &'a Path,
        uid: u32,
        fm: &'a FakeMounts,
    ) -> EphemeralEnv<'a> {
        EphemeralEnv {
            runner: r,
            procs: p,
            root,
            uid,
            mounts: fm,
            acct: &G,
        }
    }

    /// Review Focus 3：等 slice 停下之后才卸载、挂载；cleanup 自己从不 terminate-user（会话由 logind 结束）。
    #[test]
    fn cleanup_waits_for_slice_inactive_outside_session() {
        let root = sysroot();
        fs::write(mark(root.path()), b"").unwrap();
        let r = Arc::new(FakeRunner::new());
        let home = home_line(root.path());
        let fm = answers(&r, me(), std::slice::from_ref(&home));
        let procs = FakeProcs::new(&r, &[true, true, true], false);
        cleanup(&genv(&r, &procs, root.path(), me(), &fm)).unwrap();
        let calls = r.calls();
        let inactive = procs.first_inactive().unwrap();
        assert_eq!(procs.polls.lock().unwrap().len(), 4);
        assert_eq!(*procs.sleeps.lock().unwrap(), 3);
        let det = fm.detached.lock().unwrap().clone();
        assert_eq!(
            det.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            vec![100],
            "按 fd 卸了旧的 tmpfs"
        );
        let mt = idx(&calls, "mount -c -t tmpfs").expect("挂了新的 tmpfs");
        assert!(inactive <= det[0].1 && det[0].1 <= mt, "{calls:?} {det:?}");
        assert!(
            calls.iter().all(|c| !c.starts_with("umount")),
            "不按路径卸：{calls:?}"
        );
        assert!(
            calls.iter().all(|c| !c.starts_with("loginctl")),
            "{calls:?}"
        );
        assert!(
            calls.iter().all(|c| !c.contains("--signal=KILL")),
            "{calls:?}"
        );
        assert!(mark(root.path()).exists());
    }

    #[test]
    fn stubborn_slice_gets_sigkill() {
        let root = sysroot();
        let r = Arc::new(FakeRunner::new());
        let fm = answers(&r, me(), &[]);
        // 30 秒（150 次）一直 active，SIGKILL 之后第 2 次看不再 active
        let mut seq = vec![true; 151];
        seq.push(false);
        let procs = FakeProcs::new(&r, &seq, false);
        cleanup(&genv(&r, &procs, root.path(), me(), &fm)).unwrap();
        let calls = r.calls();
        let kill = idx(&calls, "systemctl kill --signal=KILL user-1999.slice").unwrap();
        let mt = idx(&calls, "mount -c -t tmpfs").unwrap();
        assert!(kill < mt);
        let polls = procs.polls.lock().unwrap().clone();
        assert_eq!(polls.len(), 152);
        assert!(polls[149].0 <= kill && kill < polls[150].0, "{polls:?}");
        assert!(mark(root.path()).exists());
    }

    #[test]
    fn cleanup_gives_up_without_ready_mark() {
        let root = sysroot();
        fs::write(mark(root.path()), b"").unwrap();
        let r = Arc::new(FakeRunner::new());
        let fm = answers(&r, me(), &[]);
        let procs = FakeProcs::new(&r, &[], true);
        let e = cleanup(&genv(&r, &procs, root.path(), me(), &fm)).unwrap_err();
        assert!(format!("{e:#}").contains("user-1999.slice"), "{e:#}");
        let calls = r.calls();
        assert!(idx(&calls, "systemctl kill --signal=KILL").is_some());
        assert!(
            calls
                .iter()
                .all(|c| !c.starts_with("umount") && !c.starts_with("mount")),
            "{calls:?}"
        );
        assert!(!mark(root.path()).exists(), "开头就删了标记，放弃时不再写");
        assert_eq!(procs.polls.lock().unwrap().len(), 175);
    }

    /// The networks that list the guest go once its processes are gone (also one it shares with someone else); the
    /// device's and other people's stay. Every nmcli call names the connection by `uuid`.
    #[test]
    fn cleanup_removes_the_guests_networks() {
        let root = sysroot();
        let r = Arc::new(FakeRunner::new());
        let fm = answers(&r, GUEST_UID, &[]);
        r.respond(
            "nmcli -t -f UUID connection show",
            Output::ok("11111111-1111-4111-8111-111111111111\n22222222-2222-4222-8222-222222222222\n33333333-3333-4333-8333-333333333333\n44444444-4444-4444-8444-444444444444\n"),
        );
        for (u, p) in [
            ("11111111-1111-4111-8111-111111111111", "user\\:guest\n"),
            ("22222222-2222-4222-8222-222222222222", "\n"),
            ("33333333-3333-4333-8333-333333333333", "user\\:alice\n"),
            (
                "44444444-4444-4444-8444-444444444444",
                "user\\:alice,user\\:guest\n",
            ),
        ] {
            r.respond(
                &format!("nmcli -g connection.permissions connection show uuid {u}"),
                Output::ok(p),
            );
        }
        let procs = FakeProcs::new(&r, &[], false);
        cleanup(&genv(&r, &procs, root.path(), GUEST_UID, &fm)).unwrap();
        let calls = r.calls();
        let deletes: Vec<&String> = calls
            .iter()
            .filter(|c| c.starts_with("nmcli connection delete"))
            .collect();
        assert_eq!(
            deletes,
            vec![
                "nmcli connection delete uuid 11111111-1111-4111-8111-111111111111",
                "nmcli connection delete uuid 44444444-4444-4444-8444-444444444444"
            ],
            "{calls:?}"
        );
        let del = idx(&calls, "nmcli connection delete").unwrap();
        assert!(
            procs.first_inactive().is_some_and(|i| i <= del),
            "only after the guest's processes are gone: {calls:?}"
        );
        assert!(mark(root.path()).exists());
    }

    /// NetworkManager not answering, or a listed name that is not a UUID: the cleanup fails and leaves no ready mark
    /// (the unit tries again), so the next guest never gets the last one's networks.
    #[test]
    fn cleanup_fails_closed_without_networkmanager() {
        for out in [
            Output::fail(8, "Error: NetworkManager is not running."),
            Output::ok("school-wifi\n"),
        ] {
            let root = sysroot();
            let r = Arc::new(FakeRunner::new());
            let fm = answers(&r, GUEST_UID, &[]);
            r.respond("nmcli -t -f UUID connection show", out);
            let procs = FakeProcs::new(&r, &[], false);
            assert!(cleanup(&genv(&r, &procs, root.path(), GUEST_UID, &fm)).is_err());
            assert!(!mark(root.path()).exists());
            assert!(r
                .calls()
                .iter()
                .all(|c| !c.starts_with("nmcli connection delete")));
        }
    }

    #[test]
    fn cleanup_mounts_fresh_tmpfs_and_marks_ready() {
        let root = sysroot();
        let r = Arc::new(FakeRunner::new());
        let fm = answers(&r, GUEST_UID, &[]);
        let procs = FakeProcs::new(&r, &[], false);
        cleanup(&genv(&r, &procs, root.path(), GUEST_UID, &fm)).unwrap();
        let calls = r.calls();
        let m = &calls[idx(&calls, "mount -c -t tmpfs").unwrap()];
        for o in [
            "size=30%",
            "mode=0700",
            "uid=1999",
            "gid=1999",
            "nosuid",
            "nodev",
        ] {
            assert!(m.contains(o), "{m}");
        }
        assert!(
            m.ends_with(&format!("tmpfs {}", home_line(root.path()))),
            "{m}"
        );
        assert!(mark(root.path()).exists());
        let h = root.path().join("home/guest");
        assert!(h.is_dir() && !h.is_symlink());
        assert_eq!(
            fs::metadata(&h).unwrap().permissions().mode() & 0o7777,
            0o755
        );
        let rk = root.path().join("run/mastersos");
        assert_eq!(
            fs::metadata(&rk).unwrap().permissions().mode() & 0o7777,
            0o700
        );
    }

    /// 复审 I3：每次清理都把账号恢复原样（口令清空、名字与 shell），删掉 AccountsService 按名字存的名字与头像。
    #[test]
    fn cleanup_resets_account_state() {
        let root = sysroot();
        let p = root.path();
        fs::write(
            p.join("var/lib/AccountsService/users/guest"),
            b"[User]\nRealName=x\n",
        )
        .unwrap();
        fs::write(p.join("var/lib/AccountsService/icons/guest"), b"png").unwrap();
        fs::write(p.join("var/lib/AccountsService/users/alice"), b"[User]\n").unwrap();
        let r = Arc::new(FakeRunner::new());
        let fm = answers(&r, me(), &[]);
        let procs = FakeProcs::new(&r, &[], false);
        cleanup(&genv(&r, &procs, p, me(), &fm)).unwrap();
        assert!(!p.join("var/lib/AccountsService/users/guest").exists());
        assert!(!p.join("var/lib/AccountsService/icons/guest").exists());
        assert!(p.join("var/lib/AccountsService/users/alice").exists());
        let calls = r.calls();
        let mt = idx(&calls, "mount -c -t tmpfs").unwrap();
        let pw = idx(&calls, "passwd -d guest").unwrap();
        let ch = idx(&calls, "chage -m 99999 -d ").expect("口令不许访客自己改（最短天数）");
        let um = idx(&calls, "usermod -c 访客 Guest -s /bin/bash guest").unwrap();
        let icon = idx(&calls, &format!("busctl call org.freedesktop.Accounts /org/freedesktop/Accounts/User{} org.freedesktop.Accounts.User SetIconFile s ", me()))
            .expect("经 accounts-daemon 清掉内存里的头像");
        assert!(mt < pw && pw < ch && ch < um && um < icon, "{calls:?}");
        assert!(!calls[ch].ends_with(" -d 0 guest"), "上次修改不能是 0");
        // 访客没有模板：会话不经 accounts-daemon 改（只有锁定应用的账号改回 mastersos-kiosk）
        assert!(
            calls
                .iter()
                .all(|c| !c.contains("SetSession") && !c.contains("SetXSession")),
            "{calls:?}"
        );
        assert!(mark(p).exists());
    }

    /// 复审 I2：linger 文件在清理等 slice 之前就删掉（不然 user manager 永远不停）。
    #[test]
    fn cleanup_removes_linger_before_waiting() {
        let root = sysroot();
        let linger = root.path().join("var/lib/systemd/linger/guest");
        fs::write(&linger, b"").unwrap();
        fs::write(root.path().join("var/lib/systemd/linger/alice"), b"").unwrap();
        let r = Arc::new(FakeRunner::new());
        let fm = answers(&r, me(), &[]);
        struct Check<'a>(&'a Path, FakeProcs);
        impl Procs for Check<'_> {
            fn slice_active(&self, slice: &str) -> Result<bool> {
                assert!(!self.0.exists(), "等 slice 时 linger 文件还在");
                self.1.slice_active(slice)
            }
            fn sleep(&self, _: Duration) {}
        }
        let c = Check(&linger, FakeProcs::new(&r, &[true], false));
        cleanup(&EphemeralEnv {
            runner: r.as_ref(),
            procs: &c,
            root: root.path(),
            uid: me(),
            mounts: &fm,
            acct: &G,
        })
        .unwrap();
        assert!(!linger.exists());
        assert!(root.path().join("var/lib/systemd/linger/alice").exists());
    }

    /// 复审 I1：以前 SplitMode=uid 留下的访客 journal（1999 读得到）被删掉，别人的不动。
    #[test]
    fn cleanup_removes_guest_user_journals() {
        let root = sysroot();
        let j = root.path().join("var/log/journal/0123abcd");
        let uid = me();
        for f in [
            format!("user-{uid}.journal"),
            format!("user-{uid}@0005-abc.journal"),
            format!("user-{uid}@0005-abc.journal~"),
            format!("user-{uid}0.journal"),
            "system.journal".into(),
            format!("user-{}.journal", uid + 1),
        ] {
            fs::write(j.join(f), b"j").unwrap();
        }
        let r = Arc::new(FakeRunner::new());
        let fm = answers(&r, uid, &[]);
        let procs = FakeProcs::new(&r, &[], false);
        cleanup(&genv(&r, &procs, root.path(), uid, &fm)).unwrap();
        let mut left: Vec<String> = fs::read_dir(&j)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        let mut want = vec![
            format!("user-{uid}0.journal"),
            "system.journal".to_string(),
            format!("user-{}.journal", uid + 1),
        ];
        want.sort();
        assert_eq!(left, want);
    }

    /// 复审 I4：家目录下的子挂载由深到浅卸，卸不掉改懒卸载；访客在 /tmp 自己目录上挂的东西先懒卸载再删。
    #[test]
    fn cleanup_unmounts_submounts_deepest_first() {
        let root = sysroot();
        let p = root.path();
        let home = home_line(p);
        let tmp_m = p.join("tmp/d/m").to_string_lossy().into_owned();
        let r = Arc::new(FakeRunner::new());
        let fm = answers(
            &r,
            me(),
            &[
                home.clone(),
                format!("{home}/x"),
                format!("{home}/x/y"),
                tmp_m,
                "/proc proc rw".into(),
            ],
        );
        let procs = FakeProcs::new(&r, &[], false);
        cleanup(&genv(&r, &procs, p, me(), &fm)).unwrap();
        // 由深到浅：y、x、家目录本身；再是 /tmp 下访客目录里的挂载；/proc 不在任何要清的地方，不碰
        assert_eq!(fm.detached_ids(), vec![102, 101, 100, 103]);
        assert!(
            r.calls().iter().all(|c| !c.starts_with("umount")),
            "不按路径卸"
        );
        assert!(!p.join("tmp/d").exists(), "卸完再删");
        assert!(mark(p).exists());
    }

    /// FUSE 挂载在 /tmp 下一律懒卸载（只有用户自己会挂；它的根的属主可能看不出是访客）。
    #[test]
    fn fuse_mounts_under_tmp_are_unmounted() {
        let root = sysroot();
        let p = root.path();
        // 用一个不是当前用户的 uid 当访客：路径上每一级都「不是访客的」，只剩 FUSE 的 user_id 能认出来
        let other = if me() == 54_321 { 54_322 } else { 54_321 };
        let mine = p.join("tmp/rootdir/m").to_string_lossy().into_owned();
        let theirs = p.join("tmp/rootdir/n").to_string_lossy().into_owned();
        let tmpfs = p.join("tmp/rootdir").to_string_lossy().into_owned();
        let r = Arc::new(FakeRunner::new());
        let fm = answers(
            &r,
            other,
            &[
                format!("{tmpfs} tmpfs rw"),
                format!("{mine} fuse.sshfs rw,nosuid,user_id={other},group_id={other}"),
                // 别的用户的 FUSE（例如 AppImage 的 /tmp/.mount_*）：不碰（复审 T11 N2）
                format!(
                    "{theirs} fuse.squashfuse ro,user_id={},group_id={}",
                    me(),
                    me()
                ),
            ],
        );
        let procs = FakeProcs::new(&r, &[], false);
        let _ = cleanup(&genv(&r, &procs, p, other, &fm));
        assert_eq!(fm.detached_ids(), vec![101]);
    }

    /// 别人的挂载（路径上每一级都不是访客的）留着。
    #[test]
    fn foreign_mounts_under_tmp_are_left_alone() {
        let root = sysroot();
        let p = root.path();
        fs::create_dir_all(p.join("tmp/rootdir/m")).unwrap();
        assert!(!account_mount_under(
            &p.join("tmp"),
            &p.join("tmp/rootdir/m"),
            54_321
        ));
        assert!(account_mount_under(
            &p.join("tmp"),
            &p.join("tmp/rootdir/m"),
            me()
        ));
        assert!(!account_mount_under(&p.join("tmp"), &p.join("tmp"), me()));
        assert!(!account_mount_under(&p.join("tmp"), &p.join("var/x"), me()));
    }

    #[test]
    fn findmnt_escapes_are_decoded() {
        assert_eq!(unescape_findmnt(r"/tmp/a\x20b"), "/tmp/a b");
        assert_eq!(unescape_findmnt(r"/tmp/a\x5cb\x"), r"/tmp/a\b\x");
        assert_eq!(unescape_findmnt("/plain"), "/plain");
    }

    /// 复审 M1：属主不是访客、带 sticky 位的子目录往下看一层；/run/lock 也清。
    #[test]
    fn sticky_subdirs_are_cleaned_one_level() {
        assert!(TMP_DIRS.contains(&"run/lock") && TMP_DIRS.contains(&"dev/mqueue"));
        let root = sysroot();
        fs::write(root.path().join("run/lock/guest.lock"), b"x").unwrap();
        let r = Arc::new(FakeRunner::new());
        let fm = answers(&r, me(), &[]);
        let procs = FakeProcs::new(&r, &[], false);
        cleanup(&genv(&r, &procs, root.path(), me(), &fm)).unwrap();
        assert!(!root.path().join("run/lock/guest.lock").exists());
    }

    /// 复审 M6：uid 1999 现在是别人的：一样都不碰。
    #[test]
    fn cleanup_does_nothing_when_uid_belongs_to_someone_else() {
        let root = sysroot();
        fs::write(root.path().join("tmp/theirs"), b"x").unwrap();
        fs::write(mark(root.path()), b"").unwrap();
        let r = Arc::new(FakeRunner::new());
        r.respond(
            &format!("getent passwd {}", me()),
            Output::ok(&format!("bob:x:{}:{}::/home/bob:/bin/bash\n", me(), me())),
        );
        let procs = FakeProcs::new(&r, &[], true);
        let fm = FakeMounts::new(&r);
        cleanup(&genv(&r, &procs, root.path(), me(), &fm)).unwrap();
        assert_eq!(r.calls(), vec![format!("getent passwd {}", me())]);
        assert!(procs.polls.lock().unwrap().is_empty(), "连 slice 都不看");
        assert!(root.path().join("tmp/theirs").exists());
    }

    /// 复审 M3：挂好之后、写标记之前账号没了（agent 刚删）：卸掉刚挂的，不写标记。
    #[test]
    fn cleanup_rechecks_account_before_marking() {
        let root = sysroot();
        let r = Arc::new(FakeRunner::new());
        let fm = FakeMounts::new(&r);
        let home = home_line(root.path());
        r.respond(&format!("getent passwd {}", me()), getent_line(me()));
        r.respond(FINDMNT, Output::ok("1 ext4 rw /\n"));
        r.respond(FINDMNT, Output::ok("1 ext4 rw /\n"));
        r.respond("getent passwd guest", getent_line(me()));
        r.respond("getent passwd guest", Output::fail(2, ""));
        // 挂好之后再读一次挂载表：刚挂的 tmpfs 在里面
        r.respond(
            FINDMNT,
            Output::ok(&mount_list(&fm, std::slice::from_ref(&home))),
        );
        let procs = FakeProcs::new(&r, &[], false);
        cleanup(&genv(&r, &procs, root.path(), me(), &fm)).unwrap();
        let calls = r.calls();
        let mt = idx(&calls, "mount -c -t tmpfs").unwrap();
        let det = fm.detached.lock().unwrap().clone();
        assert_eq!(det.len(), 1);
        assert!(mt < det[0].1, "{calls:?} {det:?}");
        assert!(!mark(root.path()).exists());
    }

    #[test]
    fn cleanup_without_account_only_unmounts_and_cleans() {
        let root = sysroot();
        fs::write(root.path().join("tmp/f"), b"x").unwrap();
        fs::write(
            root.path().join("var/lib/AccountsService/icons/guest"),
            b"png",
        )
        .unwrap();
        let r = Arc::new(FakeRunner::new());
        let fm = FakeMounts::new(&r);
        let home = home_line(root.path());
        r.respond(&format!("getent passwd {}", me()), Output::fail(2, ""));
        let list = mount_list(&fm, std::slice::from_ref(&home));
        r.respond(FINDMNT, Output::ok(&list));
        r.respond(FINDMNT, Output::ok(&list));
        r.respond("getent passwd guest", Output::fail(2, ""));
        let procs = FakeProcs::new(&r, &[], false);
        cleanup(&genv(&r, &procs, root.path(), me(), &fm)).unwrap();
        let calls = r.calls();
        assert_eq!(fm.detached_ids(), vec![100]);
        assert!(idx(&calls, "mount -c -t tmpfs").is_none());
        assert!(idx(&calls, "passwd").is_none() && idx(&calls, "usermod").is_none());
        assert!(!root.path().join("tmp/f").exists());
        assert!(!root
            .path()
            .join("var/lib/AccountsService/icons/guest")
            .exists());
        assert!(!mark(root.path()).exists());
    }

    /// 复审 T11 N1：按 fd 打开的挂载 id 与挂载表里的对不上（路径在读表之后被换过）：一个都不卸、不写标记。
    #[test]
    fn mount_id_mismatch_unmounts_nothing() {
        let root = sysroot();
        let home = home_line(root.path());
        let r = Arc::new(FakeRunner::new());
        let fm = answers(&r, me(), std::slice::from_ref(&home));
        fm.add(Path::new(&home), 999);
        let procs = FakeProcs::new(&r, &[], false);
        let e = cleanup(&genv(&r, &procs, root.path(), me(), &fm)).unwrap_err();
        assert!(
            format!("{e:#}").contains("does not match")
                || format!("{e:#}").contains("path changed"),
            "{e:#}"
        );
        assert!(fm.detached_ids().is_empty());
        assert!(idx(&r.calls(), "mount -c -t tmpfs").is_none());
        assert!(!mark(root.path()).exists());
    }

    /// 复审 T11 N1：别的本机用户把 /tmp 下路径的一级换成指向别处的链接（静态的情形）：清理不跟随链接，什么都不卸、
    /// 不写标记（30 秒后再来）；链接指向的那边原样。
    #[test]
    fn symlink_in_mount_path_unmounts_nothing() {
        let root = sysroot();
        let p = root.path();
        let outside = tempfile::tempdir().unwrap();
        let target = p.join("tmp/g/x/usr").to_string_lossy().into_owned();
        let r = Arc::new(FakeRunner::new());
        let fm = answers(
            &r,
            me(),
            &[format!(
                "{target} fuse.sshfs rw,user_id={},group_id={}",
                me(),
                me()
            )],
        );
        // 外面也有一个登记过的挂载：路径被换到这里也不能卸它
        fm.add(&outside.path().join("usr"), 500);
        fs::rename(p.join("tmp/g/x"), p.join("tmp/g/x.real")).unwrap();
        std::os::unix::fs::symlink(outside.path(), p.join("tmp/g/x")).unwrap();
        let procs = FakeProcs::new(&r, &[], false);
        let e = cleanup(&genv(&r, &procs, p, me(), &fm)).unwrap_err();
        assert!(format!("{e:#}").contains("symlink"), "{e:#}");
        assert!(fm.detached_ids().is_empty(), "{:?}", fm.detached_ids());
        assert!(outside.path().join("usr").exists());
        assert!(!mark(p).exists());
        assert!(r.calls().iter().all(|c| !c.starts_with("umount")));
    }

    #[test]
    fn home_that_is_a_link_is_refused() {
        let root = sysroot();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("home/guest")).unwrap();
        let r = Arc::new(FakeRunner::new());
        let fm = answers(&r, me(), &[]);
        let procs = FakeProcs::new(&r, &[], false);
        let e = cleanup(&genv(&r, &procs, root.path(), me(), &fm)).unwrap_err();
        assert!(format!("{e:#}").contains("symlink"), "{e:#}");
        assert!(idx(&r.calls(), "mount -c -t tmpfs").is_none());
        assert!(!mark(root.path()).exists());
    }

    /// 提交安全审查：tmpfs 按路径挂到 /home/guest 上，/home 必须是 root 的、组与其他人不可写（别人换不了里面的名字）。
    #[test]
    fn writable_home_parent_is_refused() {
        let root = sysroot();
        fs::set_permissions(root.path().join("home"), fs::Permissions::from_mode(0o777)).unwrap();
        let r = Arc::new(FakeRunner::new());
        let fm = answers(&r, me(), &[]);
        let procs = FakeProcs::new(&r, &[], false);
        let e = cleanup(&genv(&r, &procs, root.path(), me(), &fm)).unwrap_err();
        assert!(format!("{e:#}").contains("not writable"), "{e:#}");
        assert!(idx(&r.calls(), "mount -c -t tmpfs").is_none());
        assert!(!mark(root.path()).exists());
    }

    /// 准备好一次可以开会话的状态：标记在、findmnt 说 tmpfs。
    fn ready(root: &Path, r: &FakeRunner) {
        r.respond("getent passwd guest", getent_line(me()));
        fs::write(mark(root), b"").unwrap();
        fs::create_dir_all(root.join("home/guest")).unwrap();
        r.respond(
            &format!("findmnt -n -o FSTYPE --mountpoint {}", home_line(root)),
            Output::ok("tmpfs\n"),
        );
    }

    const KICK: &str = "systemctl start --no-block mastersos-guest-cleanup.service";

    #[test]
    fn stale_guest_processes_block_next_open() {
        // slice 还 active：拒绝，不拉清理（清理会等它）
        let root = sysroot();
        let r = Arc::new(FakeRunner::new());
        ready(root.path(), &r);
        let procs = FakeProcs::new(&r, &[], true);
        let fm = FakeMounts::new(&r);
        assert!(session_open(&genv(&r, &procs, root.path(), me(), &fm)).is_err());
        assert!(mark(root.path()).exists(), "被拒时不消耗标记");
        assert!(!root.path().join("home/guest/.bashrc").exists());
        assert!(!r.calls().contains(&KICK.to_string()));
        // 没有标记、slice 不在：拒绝，并拉起清理再来一次（复审 I4）
        let root = sysroot();
        let r = Arc::new(FakeRunner::new());
        ready(root.path(), &r);
        fs::remove_file(mark(root.path())).unwrap();
        let procs = FakeProcs::new(&r, &[], false);
        let fm = FakeMounts::new(&r);
        assert!(session_open(&genv(&r, &procs, root.path(), me(), &fm)).is_err());
        assert!(!root.path().join("home/guest/.bashrc").exists());
        assert!(r.calls().contains(&KICK.to_string()), "{:?}", r.calls());
        // 家目录不是 tmpfs（findmnt 没有输出）：拒绝、标记不动、拉起清理
        let root = sysroot();
        let r = Arc::new(FakeRunner::new());
        fs::write(mark(root.path()), b"").unwrap();
        fs::create_dir_all(root.path().join("home/guest")).unwrap();
        let fm = FakeMounts::new(&r);
        assert!(session_open(&genv(&r, &procs, root.path(), me(), &fm)).is_err());
        assert!(mark(root.path()).exists());
        assert!(!root.path().join("home/guest/.bashrc").exists());
        assert!(r.calls().contains(&KICK.to_string()));
    }

    /// 提交安全审查（授权）：上次打开留下的 guest-opening 超过 60 秒才算「那次打开已结束」，之后被拒才拉起清理；
    /// 清理开头删掉它。
    #[test]
    fn stale_opening_mark_allows_kick_and_cleanup_removes_it() {
        let root = sysroot();
        let r = Arc::new(FakeRunner::new());
        ready(root.path(), &r);
        fs::remove_file(mark(root.path())).unwrap();
        let opening = root.path().join("run/mastersos").join(OPENING_MARK);
        fs::write(&opening, b"").unwrap();
        let old = rustix::fs::Timespec {
            tv_sec: 1_000_000,
            tv_nsec: 0,
        };
        rustix::fs::utimensat(
            rustix::fs::CWD,
            &opening,
            &rustix::fs::Timestamps {
                last_access: old,
                last_modification: old,
            },
            rustix::fs::AtFlags::empty(),
        )
        .unwrap();
        let procs = FakeProcs::new(&r, &[], false);
        let fm = FakeMounts::new(&r);
        assert!(session_open(&genv(&r, &procs, root.path(), me(), &fm)).is_err());
        assert!(r.calls().contains(&KICK.to_string()), "{:?}", r.calls());
        let r = Arc::new(FakeRunner::new());
        let fm = answers(&r, me(), &[]);
        let procs = FakeProcs::new(&r, &[], false);
        cleanup(&genv(&r, &procs, root.path(), me(), &fm)).unwrap();
        assert!(!opening.exists());
    }

    #[test]
    fn open_consumes_ready_mark() {
        let root = sysroot();
        let r = Arc::new(FakeRunner::new());
        ready(root.path(), &r);
        let procs = FakeProcs::new(&r, &[], false);
        let fm = FakeMounts::new(&r);
        // 标记是清理很久以前写的（访客几小时后才来）：改名之后 guest-opening 的时间也要是现在（复审 T11 N3）
        let old = rustix::fs::Timespec {
            tv_sec: 1_000_000,
            tv_nsec: 0,
        };
        rustix::fs::utimensat(
            rustix::fs::CWD,
            mark(root.path()),
            &rustix::fs::Timestamps {
                last_access: old,
                last_modification: old,
            },
            rustix::fs::AtFlags::empty(),
        )
        .unwrap();
        let env = genv(&r, &procs, root.path(), me(), &fm);
        session_open(&env).unwrap();
        assert!(!mark(root.path()).exists());
        assert!(root
            .path()
            .join("run/mastersos")
            .join(OPENING_MARK)
            .exists());
        assert_eq!(
            fs::read(root.path().join("home/guest/.bashrc")).unwrap(),
            b"# skel\n"
        );
        // 第二个访客会话（标记已用掉）：拒绝
        r.respond(
            &format!(
                "findmnt -n -o FSTYPE --mountpoint {}",
                home_line(root.path())
            ),
            Output::ok("tmpfs\n"),
        );
        r.respond("getent passwd guest", getent_line(me()));
        let e = session_open(&env).unwrap_err();
        assert!(format!("{e:#}").contains("guest-ready"), "{e:#}");
        // 刚打开的会话可能还没进 slice：这时被拒的第二个会话不拉起清理
        assert!(!r.calls().contains(&KICK.to_string()), "{:?}", r.calls());
    }

    #[test]
    fn tmp_cleanup_only_after_processes_gone() {
        let root = sysroot();
        for d in TMP_DIRS.iter().filter(|d| **d != "dev/mqueue") {
            fs::write(root.path().join(d).join("guestfile"), b"x").unwrap();
        }
        // 一直 active：一个都不删
        let r = Arc::new(FakeRunner::new());
        let fm = answers(&r, me(), &[]);
        let procs = FakeProcs::new(&r, &[], true);
        assert!(cleanup(&genv(&r, &procs, root.path(), me(), &fm)).is_err());
        for d in TMP_DIRS.iter().filter(|d| **d != "dev/mqueue") {
            assert!(root.path().join(d).join("guestfile").exists(), "{d}");
        }
        // 停下之后：都删了
        let r = Arc::new(FakeRunner::new());
        let fm = answers(&r, me(), &[]);
        let procs = FakeProcs::new(&r, &[true], false);
        cleanup(&genv(&r, &procs, root.path(), me(), &fm)).unwrap();
        for d in TMP_DIRS.iter().filter(|d| **d != "dev/mqueue") {
            assert!(!root.path().join(d).join("guestfile").exists(), "{d}");
        }
    }

    /// 提交安全审查（授权逻辑）：访客只在 GDM 的两个服务上、open_session 时走 session_open；同一个 `guest` 在别的服务、
    /// 别的 PAM_TYPE 上一律拒绝（不是「什么都不做、退出 0」：钩子是 requisite，退出 0 就等于放行一个没检查过的会话）；
    /// close_session 照常放行。名字精确比较：大小写、前后空白不同的是别的（本机）账号，走普通用户那条路。
    #[test]
    fn pam_session_refuses_guest_outside_gdm() {
        for svc in [
            "login",
            "sshd",
            "su",
            "gdm-autologin",
            "gdm-fingerprint",
            "cron",
            "",
        ] {
            assert_eq!(
                sa("open_session", svc, "guest"),
                SessionAction::DenyEphemeral(login::DENY_GUEST_SERVICE),
                "{svc}"
            );
        }
        for svc in GUEST_SERVICES {
            assert_eq!(
                sa("open_session", svc, "guest"),
                SessionAction::EphemeralOpen(ephemeral::guest())
            );
            assert_eq!(sa("close_session", svc, "guest"), SessionAction::Ignore);
            for t in [
                "",
                "open_session ",
                "OPEN_SESSION",
                "auth",
                "account",
                "password",
            ] {
                assert_eq!(
                    sa(t, svc, "guest"),
                    SessionAction::DenyEphemeral(login::DENY_GUEST_SERVICE),
                    "{t:?}"
                );
            }
        }
        for user in [
            "Guest",
            "GUEST",
            "guest ",
            " guest",
            "guest\t",
            "guest@school.ac.th",
        ] {
            assert_eq!(
                sa("open_session", "gdm-authd", user),
                SessionAction::Enqueue(user.into()),
                "{user:?}"
            );
            assert_ne!(
                sa("open_session", "gdm-authd", user),
                SessionAction::EphemeralOpen(ephemeral::guest())
            );
        }
        assert_eq!(
            sa("open_session", "gdm-authd", "a@school.ac.th"),
            SessionAction::Enqueue("a@school.ac.th".into())
        );
        assert_eq!(sa("", "gdm-password", "alice"), SessionAction::Ignore);
        assert_eq!(
            sa("close_session", "gdm-password", "alice"),
            SessionAction::Ignore
        );
    }

    // --- 锁定应用的账号（计划 9 Task 4） ---

    fn kpol() -> LoginPolicy {
        let mut p = login::policy_from_seed(
            &Seed::parse("server_url = \"https://m.school.ac.th\"\ntrust = []\n").unwrap(),
        );
        p.kiosk_users = vec![login::KioskUser {
            user: "kiosk-nwea".into(),
            name: "NWEA MAP".into(),
        }];
        p
    }

    fn ka(pam_type: &str, service: &str, user: &str, uid: Option<u32>) -> SessionAction {
        session_action(
            pam_type,
            service,
            user,
            Some(super::super::kiosk::SESSION),
            true,
            Some(&kpol()),
            || uid,
        )
    }

    /// 名单里的 `kiosk-nwea` 在 GDM 上开会话：按策略里的名字与 getent 的 uid 造的临时账号；其余都拒。
    #[test]
    fn kiosk_open_dispatches_ephemeral() {
        let want = ephemeral::kiosk("nwea", 1900, "NWEA MAP");
        for svc in GUEST_SERVICES {
            assert_eq!(
                ka("open_session", svc, "kiosk-nwea", Some(1900)),
                SessionAction::EphemeralOpen(want.clone()),
                "{svc}"
            );
            assert_eq!(
                ka("close_session", svc, "kiosk-nwea", Some(1900)),
                SessionAction::Ignore
            );
            for t in ["", "OPEN_SESSION", "auth", "account"] {
                assert_eq!(
                    ka(t, svc, "kiosk-nwea", Some(1900)),
                    SessionAction::DenyEphemeral(login::DENY_KIOSK),
                    "{t:?}"
                );
            }
        }
        assert_eq!(
            ka("open_session", "gdm-authd", "kiosk-nwea", Some(1989)),
            SessionAction::EphemeralOpen(ephemeral::kiosk("nwea", 1989, "NWEA MAP"))
        );
        for svc in ["login", "sshd", "su", "gdm-autologin", "cron", ""] {
            assert_eq!(
                ka("open_session", svc, "kiosk-nwea", Some(1900)),
                SessionAction::DenyEphemeral(login::DENY_KIOSK),
                "{svc}"
            );
        }
        // uid 不在 1900–1989（访客的 1999、系统账号、查不到）：不猜，拒
        for uid in [
            Some(1999),
            Some(1899),
            Some(1990),
            Some(0),
            Some(1001),
            None,
        ] {
            assert_eq!(
                ka("open_session", "gdm-authd", "kiosk-nwea", uid),
                SessionAction::DenyEphemeral(login::DENY_KIOSK_UNKNOWN),
                "{uid:?}"
            );
        }
        // 受管机器上名单外的 kiosk- 名字：开会话拒，关会话放行
        assert_eq!(
            ka("open_session", "gdm-authd", "kiosk-old", Some(1901)),
            SessionAction::DenyEphemeral(login::DENY_KIOSK_UNKNOWN)
        );
        assert_eq!(
            ka("close_session", "gdm-authd", "kiosk-old", Some(1901)),
            SessionAction::Ignore
        );
        // 受管而读不到策略：同样拒
        assert_eq!(
            session_action(
                "open_session",
                "gdm-authd",
                "kiosk-nwea",
                Some(super::super::kiosk::SESSION),
                true,
                None,
                || Some(1900)
            ),
            SessionAction::DenyEphemeral(login::DENY_KIOSK_UNKNOWN)
        );
        // 未受管：kiosk-x 是普通的本机账号
        assert_eq!(
            sa("open_session", "gdm-authd", "kiosk-x"),
            SessionAction::Enqueue("kiosk-x".into())
        );
        // kiosk- 开头的 SSO 账号与别的 SSO 账号一样进登录队列
        assert_eq!(
            ka(
                "open_session",
                "gdm-authd",
                "kiosk-it@school.ac.th",
                Some(10001)
            ),
            SessionAction::Enqueue("kiosk-it@school.ac.th".into())
        );
        assert_eq!(
            ka(
                "close_session",
                "gdm-authd",
                "kiosk-it@school.ac.th",
                Some(10001)
            ),
            SessionAction::Ignore
        );
        // 名字精确比较
        assert_eq!(
            ka("open_session", "gdm-authd", "Kiosk-nwea", Some(1900)),
            SessionAction::Enqueue("Kiosk-nwea".into())
        );
        // 访客照旧
        assert_eq!(
            ka("open_session", "gdm-authd", "guest", None),
            SessionAction::EphemeralOpen(ephemeral::guest())
        );
    }

    /// 控制者裁定 4（登录界面换会话的逃逸）：kiosk 账号在 GDM 的齿轮里选了完整的 Ubuntu 会话就没有锁定可言。
    /// PAM 环境里的 `XDG_SESSION_DESKTOP`（GDM 在 open_session 之前按会话的 .desktop 文件名设）不是 `mastersos-kiosk`
    /// 就拒；没有也拒（往拒绝的方向落）。查 uid 之前就拒，标记不动。访客与普通用户不看它。
    #[test]
    fn kiosk_session_desktop_guard() {
        let open = |desktop: Option<&str>, user: &str| {
            session_action(
                "open_session",
                "gdm-authd",
                user,
                desktop,
                true,
                Some(&kpol()),
                || Some(1900),
            )
        };
        for d in [
            None,
            Some(""),
            Some("mastersos"),
            Some("ubuntu"),
            Some("ubuntu-xorg"),
            Some("gnome"),
            Some("Mastersos-kiosk"),
            Some("mastersos-kiosk "),
            Some("mastersos-kiosk:ubuntu"),
        ] {
            assert_eq!(
                open(d, "kiosk-nwea"),
                SessionAction::DenyEphemeral(login::DENY_KIOSK_SESSION),
                "{d:?}"
            );
        }
        assert_eq!(
            open(Some("mastersos-kiosk"), "kiosk-nwea"),
            SessionAction::EphemeralOpen(ephemeral::kiosk("nwea", 1900, "NWEA MAP"))
        );
        // 会话不对不等于要查 uid：先拒
        let asked = std::cell::Cell::new(false);
        assert_eq!(
            session_action(
                "open_session",
                "gdm-password",
                "kiosk-nwea",
                Some("mastersos"),
                true,
                Some(&kpol()),
                || {
                    asked.set(true);
                    Some(1900)
                },
            ),
            SessionAction::DenyEphemeral(login::DENY_KIOSK_SESSION)
        );
        assert!(!asked.get());
        // close_session 照旧放行（会话本来就没开成）；GDM 以外的服务照旧是 DENY_KIOSK
        assert_eq!(
            session_action(
                "close_session",
                "gdm-authd",
                "kiosk-nwea",
                Some("mastersos"),
                true,
                Some(&kpol()),
                || Some(1900),
            ),
            SessionAction::Ignore
        );
        assert_eq!(
            session_action(
                "open_session",
                "sshd",
                "kiosk-nwea",
                Some("mastersos-kiosk"),
                true,
                Some(&kpol()),
                || Some(1900),
            ),
            SessionAction::DenyEphemeral(login::DENY_KIOSK)
        );
        // 访客、普通用户、SSO 账号不受这个变量影响
        for d in [
            None,
            Some("mastersos"),
            Some("ubuntu"),
            Some("mastersos-kiosk"),
        ] {
            assert_eq!(
                open(d, "guest"),
                SessionAction::EphemeralOpen(ephemeral::guest()),
                "{d:?}"
            );
            assert_eq!(
                open(d, "alice"),
                SessionAction::Enqueue("alice".into()),
                "{d:?}"
            );
            assert_eq!(
                open(d, "kiosk-it@school.ac.th"),
                SessionAction::Enqueue("kiosk-it@school.ac.th".into()),
                "{d:?}"
            );
        }
        assert!(login::DENY_KIOSK_SESSION.contains(" / "));
    }

    /// `loginctl --json=short list-sessions` 的一行（systemd 256 起有 class 与 state 两栏）。
    fn ls_row(id: &str, user: &str, seat: Option<&str>, class: &str, state: &str) -> String {
        format!(
            r#"{{"session":"{id}","uid":1001,"user":"{user}","seat":{},"leader":1234,"class":"{class}","tty":null,"state":"{state}","idle":false,"since":null}}"#,
            seat.map_or("null".to_string(), |s| format!("\"{s}\""))
        )
    }

    fn ls(rows: &[String]) -> Output {
        Output::ok(&format!("[{}]\n", rows.join(",")))
    }

    fn guard(
        seat: Option<&str>,
        out: Output,
        action: SessionAction,
    ) -> (SessionAction, Vec<String>) {
        let r = FakeRunner::new();
        r.respond("loginctl --json=short list-sessions", out);
        let a = seat_guard(action, seat, &r);
        (a, r.calls())
    }

    /// The real `loginctl --json=short list-sessions` row on systemd 259 (VM 170, image 20261026.1): no `state` field.
    fn ls_row_259(id: &str, user: &str, seat: Option<&str>, class: &str) -> String {
        format!(
            r#"{{"session":"{id}","uid":1001,"user":"{user}","seat":{},"leader":1234,"class":"{class}","tty":null,"idle":false,"since":null}}"#,
            seat.map_or("null".to_string(), |s| format!("\"{s}\""))
        )
    }

    /// systemd 259 dropped `state` from `list-sessions` JSON, so every kiosk open was denied as SEAT_UNKNOWN
    /// (found on VM 170, 2026-10-27). A row without `state` that could block (same seat, `user*` class) gets its state
    /// from `loginctl show-session <id> -p State --value`; rows that cannot block are not queried; an unreadable state
    /// still denies.
    #[test]
    fn kiosk_open_reads_state_when_list_lacks_it() {
        let kiosk = || SessionAction::EphemeralOpen(ephemeral::kiosk("nwea", 1900, "NWEA MAP"));
        let list = "loginctl --json=short list-sessions";
        let show = |id: &str| format!("loginctl show-session {id} -p State --value");
        let run = |rows: &[String], states: &[(&str, Output)]| {
            let r = FakeRunner::new();
            r.respond(list, ls(rows));
            for (id, out) in states {
                r.respond(&show(id), out.clone());
            }
            let a = seat_guard(kiosk(), Some("seat0"), &r);
            (a, r.calls())
        };
        // Exactly what VM 170 showed at the greeter: greeter + manager-early, nothing to ask about
        let (a, calls) = run(
            &[
                ls_row_259("6", "gdm-greeter", None, "manager-early"),
                ls_row_259("c2", "gdm-greeter", Some("seat0"), "greeter"),
            ],
            &[],
        );
        assert_eq!(a, kiosk());
        assert_eq!(calls, [list]);
        // A desktop session on the seat: closing passes, online/active/opening denies
        for (state, want) in [
            ("closing\n", kiosk()),
            (
                "online\n",
                SessionAction::DenyEphemeral(login::DENY_KIOSK_OTHER_SESSION),
            ),
            (
                "active\n",
                SessionAction::DenyEphemeral(login::DENY_KIOSK_OTHER_SESSION),
            ),
            (
                "opening\n",
                SessionAction::DenyEphemeral(login::DENY_KIOSK_OTHER_SESSION),
            ),
        ] {
            let (a, calls) = run(
                &[
                    ls_row_259("c2", "gdm-greeter", Some("seat0"), "greeter"),
                    ls_row_259("3", "student", Some("seat0"), "user"),
                    ls_row_259("4", "student", None, "manager"),
                ],
                &[("3", Output::ok(state))],
            );
            assert_eq!(a, want, "{state:?}");
            assert_eq!(calls, [list.to_string(), show("3")], "{state:?}");
        }
        // Other seat / no seat: not asked
        let (a, calls) = run(
            &[
                ls_row_259("7", "bob", None, "user"),
                ls_row_259("8", "carol", Some("seat1"), "user"),
            ],
            &[],
        );
        assert_eq!(a, kiosk());
        assert_eq!(calls, [list]);
        // show-session fails or prints nothing: deny, do not guess
        for out in [
            Output::fail(1, "No session '3' known"),
            Output::ok(""),
            Output::ok("\n"),
        ] {
            let (a, _) = run(
                &[ls_row_259("3", "student", Some("seat0"), "user")],
                &[("3", out.clone())],
            );
            assert_eq!(
                a,
                SessionAction::DenyEphemeral(login::DENY_KIOSK_SEAT_UNKNOWN),
                "{out:?}"
            );
        }
    }

    /// 终审 C1（Switch User 的逃逸）：学生在桌面会话里切换用户、在 GDM 点锁定应用，锁定会话会开在还活着的桌面旁边，
    /// 两边来回切。kiosk 账号开会话时座位上有别的 user 类会话（online 或 active）就拒；closing 的（刚注销、进程还在退）、
    /// 登录界面自己的（greeter）与锁屏的不算；查不到（loginctl 失败、超时、输出读不懂）也拒。访客与普通用户不查。
    /// pam-session 排在 pam_systemd 之前（`open_runs_before_pam_systemd`），正在打开的这个会话还没在 logind 里登记。
    #[test]
    fn kiosk_open_denied_while_other_session_on_seat() {
        let kiosk = || SessionAction::EphemeralOpen(ephemeral::kiosk("nwea", 1900, "NWEA MAP"));
        let greeter = ls_row("c1", "gdm-greeter", Some("seat0"), "greeter", "active");
        let q = "loginctl --json=short list-sessions";
        // 别的会话 online（切换用户之后）或 active：拒
        for state in ["online", "active", "opening"] {
            let (a, calls) = guard(
                Some("seat0"),
                ls(&[
                    greeter.clone(),
                    ls_row("3", "somchai@school.ac.th", Some("seat0"), "user", state),
                ]),
                kiosk(),
            );
            assert_eq!(
                a,
                SessionAction::DenyEphemeral(login::DENY_KIOSK_OTHER_SESSION),
                "{state}"
            );
            assert_eq!(calls, [q]);
        }
        // 另一个锁定应用的会话、访客的会话也算
        for user in ["kiosk-forms", "guest", "alice"] {
            for class in ["user", "user-early", "user-incomplete", "user-light"] {
                let (a, _) = guard(
                    Some("seat0"),
                    ls(&[ls_row("4", user, Some("seat0"), class, "online")]),
                    kiosk(),
                );
                assert_eq!(
                    a,
                    SessionAction::DenyEphemeral(login::DENY_KIOSK_OTHER_SESSION),
                    "{user} {class}"
                );
            }
        }
        // 只有 closing 的（enter 刚结束的会话）、登录界面、锁屏、user manager、没有座位的（ssh）、别的座位：放行
        let (a, _) = guard(
            Some("seat0"),
            ls(&[
                greeter.clone(),
                ls_row("3", "alice", Some("seat0"), "user", "closing"),
                ls_row("5", "alice", Some("seat0"), "lock-screen", "online"),
                ls_row("6", "alice", None, "manager", "active"),
                ls_row("7", "bob", None, "user", "active"),
                ls_row("8", "carol", Some("seat1"), "user", "active"),
                ls_row("9", "root", None, "background", "online"),
            ]),
            kiosk(),
        );
        assert_eq!(a, kiosk());
        let (a, _) = guard(Some("seat0"), ls(&[]), kiosk());
        assert_eq!(a, kiosk());
        // 没有座位写成 "" 或 "-"：与 null 一样不算，没有 XDG_SEAT 时也不会被它挡住
        for seat in ["", "-"] {
            let (a, _) = guard(
                None,
                ls(&[ls_row("7", "bob", Some(seat), "user", "active")]),
                kiosk(),
            );
            assert_eq!(a, kiosk(), "{seat:?}");
        }
        // PAM 环境里没有 XDG_SEAT：哪个座位上的 user 会话都算（往拒绝的方向落），没有座位的照样不算
        let (a, _) = guard(
            None,
            ls(&[ls_row("8", "carol", Some("seat1"), "user", "active")]),
            kiosk(),
        );
        assert_eq!(
            a,
            SessionAction::DenyEphemeral(login::DENY_KIOSK_OTHER_SESSION)
        );
        let (a, _) = guard(
            None,
            ls(&[greeter.clone(), ls_row("7", "bob", None, "user", "active")]),
            kiosk(),
        );
        assert_eq!(a, kiosk());
        // 查不到：拒
        for out in [
            Output::fail(1, "Failed to connect to bus"),
            Output::ok(""),
            Output::ok("not json"),
            Output::ok("{}"),
            Output::ok("[1]"),
            // 没有 class 栏（老 systemd）：不猜。没有 state 栏的（systemd 259）由 show-session 补，见下一个测试
            Output::ok(r#"[{"session":"3","user":"alice","seat":"seat0","state":"active"}]"#),
            // 没有 seat 栏，或 seat 不是字符串：同样不猜
            Output::ok(r#"[{"session":"3","user":"alice","class":"user","state":"active"}]"#),
            Output::ok(
                r#"[{"session":"3","user":"alice","seat":0,"class":"user","state":"active"}]"#,
            ),
        ] {
            let (a, _) = guard(Some("seat0"), out.clone(), kiosk());
            assert_eq!(
                a,
                SessionAction::DenyEphemeral(login::DENY_KIOSK_SEAT_UNKNOWN),
                "{out:?}"
            );
        }
        // 访客与普通用户、别的动作：不查 logind，原样返回
        for action in [
            SessionAction::EphemeralOpen(ephemeral::guest()),
            SessionAction::Enqueue("alice".into()),
            SessionAction::Ignore,
            SessionAction::DenyEphemeral(login::DENY_KIOSK_SESSION),
        ] {
            let (a, calls) = guard(
                Some("seat0"),
                ls(&[ls_row("3", "alice", Some("seat0"), "user", "active")]),
                action.clone(),
            );
            assert_eq!(a, action);
            assert!(calls.is_empty(), "{action:?}");
        }
        for m in [
            login::DENY_KIOSK_OTHER_SESSION,
            login::DENY_KIOSK_SEAT_UNKNOWN,
        ] {
            assert!(m.contains(" / "), "{m}");
        }
    }

    /// GDM 50 puts `XDG_SESSION_DESKTOP` in the environment only when it starts the session, after `pam_open_session`
    /// (gdm-session.c `set_up_session_environment`); found on VM 170, where every kiosk login was denied as the wrong
    /// session. But the worker saves the chosen session to AccountsService (state ACCOUNT_DETAILS_SAVED) before it opens
    /// the PAM session, so for a kiosk account without the variable the answer is AccountsService's `Session`.
    #[test]
    fn session_desktop_falls_back_to_accountsservice() {
        let q = "busctl --json=short get-property org.freedesktop.Accounts /org/freedesktop/Accounts/User1901 \
                 org.freedesktop.Accounts.User Session";
        let go = |env: Option<&str>, user: &str, uid: Option<u32>, out: Option<Output>| {
            let r = FakeRunner::new();
            if let Some(o) = out {
                r.respond("busctl", o);
            }
            let d = session_desktop("open_session", env.map(str::to_string), user, || uid, &r);
            (d, r.calls())
        };
        // The variable wins when the display manager sets it; nothing asked
        let (d, calls) = go(Some("mastersos"), "kiosk-nwea", Some(1901), None);
        assert_eq!(d.as_deref(), Some("mastersos"));
        assert!(calls.is_empty());
        // GDM 50: no variable, AccountsService has the session GDM is about to start
        for (data, want) in [
            ("mastersos-kiosk", Some("mastersos-kiosk")),
            ("mastersos", Some("mastersos")),
            // a record left from before the mastersos session (design 2026-11-10)
            ("ubuntu", Some("ubuntu")),
            ("", None),
        ] {
            let (d, calls) = go(
                None,
                "kiosk-nwea",
                Some(1901),
                Some(Output::ok(&format!(r#"{{"type":"s","data":"{data}"}}"#))),
            );
            assert_eq!(d.as_deref(), want, "{data:?}");
            assert_eq!(calls, [q]);
        }
        // Unreadable: None (the kiosk login is then denied as the wrong session)
        for out in [
            Output::fail(1, "Failed to get property"),
            Output::ok(""),
            Output::ok("s \"mastersos-kiosk\""),
            Output::ok(r#"{"type":"u","data":3}"#),
        ] {
            let (d, _) = go(None, "kiosk-nwea", Some(1901), Some(out.clone()));
            assert_eq!(d, None, "{out:?}");
        }
        // close_session (logout) never asks: only open_session looks at the session (review M2)
        let r = FakeRunner::new();
        r.respond(
            "busctl",
            Output::ok(r#"{"type":"s","data":"mastersos-kiosk"}"#),
        );
        assert_eq!(
            session_desktop("close_session", None, "kiosk-nwea", || Some(1901), &r),
            None
        );
        assert!(r.calls().is_empty());
        // Not a kiosk account, or a uid outside 1900–1989: not asked
        for (user, uid) in [
            ("alice", Some(1001)),
            ("kiosk-it@school.ac.th", Some(1001)),
            ("kiosk-nwea", Some(1001)),
            ("kiosk-nwea", None),
        ] {
            let (d, calls) = go(None, user, uid, None);
            assert_eq!(d, None, "{user}");
            assert!(calls.is_empty(), "{user}");
        }
    }

    /// 复审 I2：会话不对被拒时，GDM 可能已经把选的会话（ubuntu）记进 accounts-daemon——下一位点这个应用默认就是它、
    /// 同样被拒。拒的同时经 D-Bus 把这个账号的 Session 与 XSession 改回 mastersos-kiosk（不清理、不结束会话）；
    /// 放行的、别的拒绝、访客、uid 不在 1900–1989 的都不碰。
    #[test]
    fn wrong_session_deny_resets_accountsservice() {
        let calls = |action: SessionAction, user: &str, uid: Option<u32>| {
            let r = FakeRunner::new();
            after_action(&action, user, || uid, &r);
            r.calls()
        };
        let set = |m: &str| {
            format!(
                "busctl call org.freedesktop.Accounts /org/freedesktop/Accounts/User1900 \
                 org.freedesktop.Accounts.User {m} s mastersos-kiosk"
            )
        };
        assert_eq!(
            calls(
                SessionAction::DenyEphemeral(login::DENY_KIOSK_SESSION),
                "kiosk-nwea",
                Some(1900)
            ),
            [set("SetSession"), set("SetXSession")]
        );
        // busctl 失败也不影响（返回值没有，拒绝照旧）
        let r = FakeRunner::new();
        r.respond("busctl", Output::fail(1, "no accounts-daemon"));
        after_action(
            &SessionAction::DenyEphemeral(login::DENY_KIOSK_SESSION),
            "kiosk-nwea",
            || Some(1900),
            &r,
        );
        assert_eq!(r.calls().len(), 2);
        for (action, user, uid) in [
            (
                SessionAction::DenyEphemeral(login::DENY_KIOSK_SESSION),
                "kiosk-nwea",
                Some(1999),
            ),
            (
                SessionAction::DenyEphemeral(login::DENY_KIOSK_SESSION),
                "kiosk-nwea",
                None,
            ),
            (
                SessionAction::DenyEphemeral(login::DENY_KIOSK),
                "kiosk-nwea",
                Some(1900),
            ),
            (
                SessionAction::EphemeralOpen(ephemeral::kiosk("nwea", 1900, "NWEA MAP")),
                "kiosk-nwea",
                Some(1900),
            ),
            (
                SessionAction::EphemeralOpen(ephemeral::guest()),
                "guest",
                Some(1999),
            ),
            (SessionAction::Ignore, "kiosk-nwea", Some(1900)),
            (SessionAction::Enqueue("alice".into()), "alice", Some(1001)),
        ] {
            assert!(calls(action, user, uid).is_empty(), "{user}");
        }
    }

    /// Review Focus：上一位的清理还没完成就有人点同一个应用——与访客一样拒绝并提示「上一位还没有完全退出」，
    /// 不让新会话用上一位的家目录；访客的标记帮不了 kiosk 账号。
    #[test]
    fn kiosk_open_denied_while_not_ready() {
        let acct = ephemeral::kiosk("nwea", me(), "NWEA MAP");
        let root = sysroot();
        let r = Arc::new(FakeRunner::new());
        let home = root.path().join("home/kiosk-nwea");
        fs::create_dir_all(&home).unwrap();
        let fstype = format!("findmnt -n -o FSTYPE --mountpoint {}", home.display());
        let line = Output::ok(&format!(
            "kiosk-nwea:x:{0}:{0}:NWEA MAP:/home/kiosk-nwea:/bin/sh\n",
            me()
        ));
        r.respond(&fstype, Output::ok("tmpfs\n"));
        r.respond("getent passwd kiosk-nwea", line.clone());
        // 访客的标记在、kiosk 的不在
        fs::write(mark(root.path()), b"").unwrap();
        let procs = FakeProcs::new(&r, &[], false);
        let fm = FakeMounts::new(&r);
        let env = EphemeralEnv {
            runner: &*r,
            procs: &procs,
            root: root.path(),
            uid: me(),
            mounts: &fm,
            acct: &acct,
        };
        let e = session_open(&env).unwrap_err();
        assert!(format!("{e:#}").contains("kiosk-nwea-ready"), "{e:#}");
        assert!(!home.join(".bashrc").exists());
        assert!(mark(root.path()).exists(), "访客的标记不动");
        let kick = "systemctl start --no-block mastersos-ephemeral-cleanup@kiosk-nwea.service";
        assert!(r.calls().contains(&kick.to_string()), "{:?}", r.calls());
        assert!(!r.calls().contains(&KICK.to_string()));
        assert_eq!(busy_message(&acct), DENY_BUSY_KIOSK);
        assert!(DENY_BUSY_KIOSK.starts_with("上一位还没有完全退出，请稍候再试 / "));
        assert_eq!(busy_message(&ephemeral::guest()), DENY_BUSY);
        // 清理写了 kiosk 的标记之后：放行，家目录拿到 skel
        let run = root.path().join("run/mastersos");
        fs::write(run.join("kiosk-nwea-ready"), b"").unwrap();
        r.respond(&fstype, Output::ok("tmpfs\n"));
        r.respond("getent passwd kiosk-nwea", line);
        session_open(&env).unwrap();
        assert!(!run.join("kiosk-nwea-ready").exists());
        assert!(run.join("kiosk-nwea-opening").exists());
        assert_eq!(fs::read(home.join(".bashrc")).unwrap(), b"# skel\n");
    }

    /// 提交安全审查（授权逻辑）：`guest` 解析出来的 uid 不是访客的（账号被换成了别人的同名账号）：拒绝、标记不动。
    #[test]
    fn open_refuses_guest_with_wrong_uid() {
        let root = sysroot();
        let r = Arc::new(FakeRunner::new());
        // 先排的回答先用：1500 排在 ready() 的那条前面
        r.respond("getent passwd guest", getent_line(1500));
        ready(root.path(), &r);
        let procs = FakeProcs::new(&r, &[], false);
        let fm = FakeMounts::new(&r);
        let e = session_open(&genv(&r, &procs, root.path(), me(), &fm)).unwrap_err();
        assert!(format!("{e:#}").contains("uid"), "{e:#}");
        assert!(mark(root.path()).exists());
        assert!(!root.path().join("home/guest/.bashrc").exists());
        // 账号不在：同样拒绝
        let r = Arc::new(FakeRunner::new());
        r.respond("getent passwd guest", Output::fail(2, ""));
        ready(root.path(), &r);
        let e = session_open(&genv(&r, &procs, root.path(), me(), &fm)).unwrap_err();
        assert!(format!("{e:#}").contains("guest"), "{e:#}");
        assert!(mark(root.path()).exists());
    }

    /// pam-session 那一行排在 gdm-password 与 gdm-authd 的 session 段第一行：早于 `@include common-session`
    /// 与任何 pam_systemd（它把会话进程移进访客的 slice 之前就要检查完）。两处都是 required（访客从哪个都能进）。
    #[test]
    fn open_runs_before_pam_systemd() {
        let img = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../image");
        let d = tempfile::tempdir().unwrap();
        for f in fs::read_dir(img.join("tests/fixtures/pam.d")).unwrap() {
            let f = f.unwrap();
            fs::copy(f.path(), d.path().join(f.file_name())).unwrap();
        }
        // 样本里没有 pam_systemd 的显式行（它在 common-session 里）；加一行确认钩子也在它前面
        let gp = d.path().join("gdm-password");
        let t = fs::read_to_string(&gp).unwrap();
        fs::write(
            &gp,
            t.replace(
                "@include common-session",
                "@include common-session\nsession optional pam_systemd.so",
            ),
        )
        .unwrap();
        // systemd-user（user@<uid> 的栈）在 vendor 目录：拷一份，pam-hooks.sh 改的是副本
        let v = tempfile::tempdir().unwrap();
        fs::copy(
            img.join("tests/fixtures/pam.d-vendor/systemd-user"),
            v.path().join("systemd-user"),
        )
        .unwrap();
        let st = std::process::Command::new("bash")
            .arg(img.join("pam-hooks.sh"))
            .arg(d.path())
            .arg(v.path())
            .output()
            .unwrap();
        assert!(
            st.status.success(),
            "{}",
            String::from_utf8_lossy(&st.stderr)
        );
        for svc in GUEST_SERVICES {
            let text = fs::read_to_string(d.path().join(svc)).unwrap();
            let lines: Vec<&str> = text
                .lines()
                .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
                .collect();
            let first_session = lines
                .iter()
                .position(|l| {
                    let l = l.trim_start();
                    l.starts_with("session")
                        || l.starts_with("-session")
                        || l.starts_with("@include common-session")
                })
                .unwrap();
            assert_eq!(
                lines[first_session],
                "session requisite pam_exec.so quiet stdout /usr/bin/mastersos-agent pam-session",
                "{svc}"
            );
            let sysd = lines.iter().position(|l| l.contains("pam_systemd"));
            let inc = lines
                .iter()
                .position(|l| l.starts_with("@include common-session"));
            assert!(inc.is_some_and(|i| i > first_session), "{svc}");
            assert!(sysd.is_none_or(|i| i > first_session), "{svc}");
        }
    }

    fn manifest_group(methods: &str) -> mastersos_bundle::Config {
        Manifest::parse(&format!(
            "version = 1\n[[group]]\nid = \"default\"\nname = \"d\"\nlogin_methods = {methods}\n"
        ))
        .unwrap()
        .effective_of_group("default")
        .unwrap()
    }

    fn run_step(r: &Arc<FakeRunner>, root: &Path, methods: &str) -> Vec<ItemResult> {
        let p = paths(root);
        let g = manifest_group(methods);
        let mut sys = SysState::default();
        let mut env = Env {
            paths: &p,
            runner: r.as_ref(),
            sys: &mut sys,
        };
        let flag = AtomicBool::new(false);
        let school = School::default();
        let bundle = tempfile::tempdir().unwrap();
        let ctx = ApplyContext {
            seed: &crate::system::tests::test_seed(),
            school: &school,
            group: &group(),
            config: &g,
            lock: None,
            bundle_dir: bundle.path(),
            phase: Phase::Full,
            superseded: &flag,
        };
        (step().run)(&ctx, &mut env)
    }

    /// Guest sign-in is always on, so the step never asks for removal; exercise the removal path of `converge` directly.
    fn run_want(r: &Arc<FakeRunner>, root: &Path, want: bool) -> Vec<ItemResult> {
        let p = paths(root);
        let mut sys = SysState::default();
        let mut env = Env {
            paths: &p,
            runner: r.as_ref(),
            sys: &mut sys,
        };
        converge(&mut env, want)
    }

    /// The step ends up wanting the guest even when the configuration lists no login methods.
    #[test]
    fn step_always_wants_guest() {
        let root = tmp_root();
        let r = Arc::new(FakeRunner::new());
        r.respond("getent passwd guest", Output::fail(2, ""));
        assert_eq!(run_step(&r, root.path(), "[]"), vec![ok(ITEM)]);
        assert!(
            idx(&r.calls(), "passwd -d guest").is_some(),
            "{:?}",
            r.calls()
        );
    }

    #[test]
    fn guest_created_when_enabled_and_removed_when_disabled() {
        let root = tmp_root();
        // Account missing: create it, drop the password, prepare the tmpfs
        let r = Arc::new(FakeRunner::new());
        r.respond("getent passwd guest", Output::fail(2, ""));
        let out = run_step(&r, root.path(), r#"["guest", "local"]"#);
        assert_eq!(out, vec![ok(ITEM)]);
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        assert_eq!(
            r.calls(),
            vec![
                "getent passwd guest".to_string(),
                "useradd --uid 1999 --user-group --no-create-home --home-dir /home/guest --shell /bin/bash --comment 访客 Guest guest".into(),
                "passwd -d guest".into(),
                format!("chage -m 99999 -d {today} guest"),
                "systemctl start --no-block mastersos-guest-cleanup.service".into(),
            ]
        );
        // 已经有了：什么都不做
        let r = Arc::new(FakeRunner::new());
        r.respond("getent passwd guest", getent_line(GUEST_UID));
        assert_eq!(run_step(&r, root.path(), r#"["guest"]"#), vec![ok(ITEM)]);
        assert_eq!(r.calls(), vec!["getent passwd guest"]);
        // Removal path (`converge(false)`, account present): end the session, wait for the slice to stop, delete the account, clean up
        let r = Arc::new(FakeRunner::new());
        r.respond("getent passwd guest", getent_line(GUEST_UID));
        r.respond(
            "systemctl is-active user-1999.slice",
            Output::ok("active\n"),
        );
        r.respond(
            "systemctl is-active user-1999.slice",
            Output {
                code: 3,
                stdout: "inactive\n".into(),
                stderr: String::new(),
            },
        );
        assert_eq!(run_want(&r, root.path(), false), vec![ok(ITEM)]);
        let calls = r.calls();
        let term = idx(&calls, "loginctl terminate-user guest").unwrap();
        let del = idx(&calls, "userdel guest").unwrap();
        let last_poll = calls
            .iter()
            .rposition(|c| c == "systemctl is-active user-1999.slice")
            .unwrap();
        assert!(term < last_poll && last_poll < del, "{calls:?}");
        assert_eq!(
            calls.last().unwrap(),
            "systemctl start --no-block mastersos-guest-cleanup.service"
        );
        // Removal path, account already absent: do nothing
        let r = Arc::new(FakeRunner::new());
        r.respond("getent passwd guest", Output::fail(2, ""));
        assert_eq!(run_want(&r, root.path(), false), vec![ok(ITEM)]);
        assert_eq!(r.calls(), vec!["getent passwd guest"]);
    }

    /// 复审 I2、M3：关掉访客时 linger 文件先删（userdel 不删它），userdel 之后清理服务可能刚写的标记也删掉。
    #[test]
    fn guest_removal_drops_linger_and_mark() {
        let root = tmp_root();
        let p = root.path();
        for d in ["var/lib/systemd/linger", "run/mastersos"] {
            fs::create_dir_all(p.join(d)).unwrap();
        }
        fs::write(p.join("var/lib/systemd/linger/guest"), b"").unwrap();
        fs::write(mark(p), b"").unwrap();
        let r = Arc::new(FakeRunner::new());
        r.respond("getent passwd guest", getent_line(GUEST_UID));
        r.respond(
            "systemctl is-active user-1999.slice",
            Output {
                code: 3,
                stdout: "inactive\n".into(),
                stderr: String::new(),
            },
        );
        assert_eq!(run_want(&r, p, false), vec![ok(ITEM)]);
        assert!(!p.join("var/lib/systemd/linger/guest").exists());
        assert!(!mark(p).exists());
        assert!(idx(&r.calls(), "userdel guest").is_some());
    }

    #[test]
    fn guest_removal_waits_for_slice_and_reports_failure() {
        let root = tmp_root();
        let r = Arc::new(FakeRunner::new());
        r.respond("getent passwd guest", getent_line(GUEST_UID));
        r.respond("systemctl is-active user-1999.slice", Output::ok("bogus\n"));
        let out = run_want(&r, root.path(), false);
        assert_eq!(out.len(), 1);
        assert!(!out[0].ok);
        assert!(
            r.calls().iter().all(|c| !c.starts_with("userdel")),
            "{:?}",
            r.calls()
        );
        // uid 不是 1999 的 guest 账号：不动它
        let r = Arc::new(FakeRunner::new());
        r.respond("getent passwd guest", getent_line(1500));
        let out = run_want(&r, root.path(), false);
        assert!(!out[0].ok);
        assert_eq!(r.calls(), vec!["getent passwd guest"]);
    }
}
