//! 挂失锁定（Ruling 11）：设置包里这台机器的 `[[device]].locked`。
//!
//! `lock` 是 [`super::steps`] 的第一步（fast，开机在 GDM 之前也跑），按序：
//! 1. 用 [`login::write_policy`] 写整份登录策略（与 `login` 步骤写的相同，`locked`、`lock_message` 在里面）——
//!    **先**写策略、**再**结束会话：否则被踢下去的学生在 `login` 步骤跑到之前还能再登录；
//! 2. 经 [`banner::update`] 写或删 GDM 的横幅片段（锁定消息优先于离线状态；片段归 `banner` 模块），变了就 `dconf update`。
//!    原因只能经横幅告诉学生：GDM 的 `gdm-authd` 流程不显示 PAM 的文字消息，`pam-check` 打的拒绝原因学生看不到；
//! 3. 锁定时对 [`sessions_to_end`] 的每个 uid 先 `loginctl disable-linger`（否则学生自己开的 linger 让他的
//!    `systemd --user` 服务下次开机又起来）、再 `loginctl terminate-user`：学生（SSO 账号不论 uid）、本机账号、访客与锁定应用
//!    （`kiosk-<id>`，uid 1900–1989，裁定 K10）的会话结束，管理员（`admin_users`，SSO 名字、不区分大小写）、root、GDM 的登录界面与其他系统账号不动——
//!    否则锁定时登录界面跟着闪退。`disable-linger` 失败时在 `terminate-user` 之后再 `systemctl stop user@<uid>.service`
//!    （开着 linger 时 `terminate-user` 留下用户的 systemd 管理器）。结束了人的那一轮之后停 [`END_PAUSE`] 再列一遍：
//!    写策略之前刚过了 PAM 账号检查的登录，要几百毫秒到几秒才开出会话；新出现的也结束，最多 [`END_ROUNDS`] 轮，
//!    还有新的就回报失败、由重试再来。`loginctl` 与 `systemctl` 都限 [`LOGIN_CMD_TIMEOUT`]，logind 卡住时不拖住应用。
//!
//! 回报项 `lock`。

use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::{Context, Result};
use mastersos_bundle::ItemResult;
use serde::Deserialize;

use super::banner;
use super::login;
use super::{failed, ok, Env, Step};
use crate::apply::ApplyContext;
use crate::runner::{run_ok, Cmd, Runner};

/// 回报项的名字。
pub const ITEM: &str = "lock";

pub fn step() -> Step {
    Step {
        name: "lock",
        fast: true,
        run,
        without_bundle: None,
    }
}

/// One row of `loginctl list-users --json=short` (only the columns used; a column older versions lack defaults).
#[derive(Deserialize)]
pub(crate) struct LoginUser {
    pub(crate) uid: u32,
    pub(crate) user: String,
    #[serde(default)]
    pub(crate) linger: bool,
}

/// 解析 `loginctl list-users --no-legend --json=short`；空输出是没有用户。
pub(crate) fn parse_users(json: &str) -> Result<Vec<LoginUser>> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(json).context("parse the output of loginctl list-users")
}

/// 是不是要结束的人：名字里有 `@`（SSO 账号）的不论 uid（与 `login::decide` 一致：authd 的 uid 范围哪天配到 60000 以上，
/// 学校账号也不能因此躲过锁定）；没有 `@` 的看 uid 在不在 1000–59999（`!login::is_system_uid`；访客 1999 在内）。
/// root（uid 0）无论名字一律不结束。
pub(crate) fn is_person(u: &LoginUser) -> bool {
    u.uid != 0 && (u.user.contains('@') || !login::is_system_uid(u.uid))
}

/// 锁定时要结束的会话。`loginctl_users` 是 `loginctl list-users --no-legend --json=short` 的输出；返回 [`is_person`] 成立、
/// 且用户名不在 `admins` 里（不区分大小写）的 uid。root、GDM 的 `gdm` 与动态的 `gdm-greeter*`、其他系统账号一律不结束。
/// 输出解析不了是错误（调用方回报，不当作「没有人」）。
pub fn sessions_to_end(loginctl_users: &str, admins: &[String]) -> Result<Vec<u32>> {
    Ok(parse_users(loginctl_users)?
        .iter()
        .filter(|u| is_person(u))
        .filter(|u| !admins.iter().any(|a| a.eq_ignore_ascii_case(&u.user)))
        .map(|u| u.uid)
        .collect())
}

/// `loginctl list-users --no-legend --json=short` 里的全部 uid（不论是谁：Task 19 拿它判断「正在用」）。
/// 解析不了是错误。
pub fn logged_in_uids(loginctl_users: &str) -> Result<BTreeSet<u32>> {
    Ok(parse_users(loginctl_users)?.iter().map(|u| u.uid).collect())
}

/// 结束会话之后再列几轮（见模块文档第 3 条）。
pub const END_ROUNDS: usize = 3;
/// 上一轮结束了人，下一轮列之前停这么久（没结束人的锁定不停）。
pub const END_PAUSE: Duration = Duration::from_secs(1);
/// `loginctl`、`systemctl stop user@…` 的超时。
pub const LOGIN_CMD_TIMEOUT: Duration = Duration::from_secs(10);

/// 轮与轮之间真的停；单元测试里不停（时序由直接调 `end_sessions` 的测试核对）。
fn pause(d: Duration) {
    if cfg!(test) {
        return;
    }
    std::thread::sleep(d);
}

fn login_cmd(program: &str, args: &[&str]) -> Cmd {
    Cmd::new(program, args).timeout(LOGIN_CMD_TIMEOUT)
}

fn run(ctx: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
    let mut problems = Vec::new();
    // 与 `login` 步骤写的同一份；写不下时同样改写为锁定的策略（超限的原因由 `login` 步骤回报）。
    let want = login::bundle_policy(ctx, env);
    let policy = match login::policy_json(&want) {
        Ok(_) => want,
        Err(_) => login::fail_closed(&want),
    };
    if let Err(e) = login::write_policy(env.paths, &policy) {
        problems.push(format!("writing the login policy failed: {e:#}"));
    }
    // 策略锁定（挂失，或设置太大）就在登录界面说明原因：被拒的人看不到 pam-check 打的文字。
    match banner::update(env.paths, banner::lock_text(&policy)) {
        Ok(changed) => env.sys.dconf_update_pending |= changed,
        Err(e) => problems.push(format!("login screen banner: {e:#}")),
    }
    // `dconf update` 一次编译全部数据库：`desktop` 步骤没编译成功的也在这里补上。
    if env.sys.dconf_update_pending || env.sys.load_failed {
        match run_ok(env.runner, Cmd::new("dconf", &["update"])) {
            Ok(_) => env.sys.dconf_update_pending = false,
            Err(e) => problems.push(format!("dconf update: {e:#}")),
        }
    }
    // 只有挂失才结束会话；设置太大而改写的锁定只挡新的登录。
    if ctx.lock.is_some() {
        if let Err(e) = end_sessions(env.runner, &policy.admin_users, &pause) {
            problems.push(format!("end sessions: {e:#}"));
        }
    }
    vec![if problems.is_empty() {
        ok(ITEM)
    } else {
        failed(ITEM, problems.join("; "))
    }]
}

/// `loginctl list-users --no-legend --json=short` 的原样输出（Task 19 的家目录清理也用它）。
pub(crate) fn list_users(runner: &dyn Runner) -> Result<String> {
    run_ok(
        runner,
        // JSON 由 `--json=` 选；`--output=json` 是日志的输出格式，list-users 照样打表格（systemd 259 在 VM 165 实测）。
        login_cmd("loginctl", &["list-users", "--no-legend", "--json=short"]),
    )
}

/// 列出登录着的用户，对 [`sessions_to_end`] 里还没处理过的每个 uid 先 `disable-linger`、再 `terminate-user`（关 linger 失败的
/// 再 `systemctl stop user@<uid>.service`），一个失败不挡其余的；结束了人就停 `END_PAUSE`（经 `pause`，测试里换掉）再列，
/// 直到没有新的人。已经 `terminate-user` 过的 uid 不再管（logind 收拾会话要一两秒，期间它还在列表里）。第一轮之后列表
/// 拿不到或解析不了，与之前各轮的错误一起回报。
fn end_sessions(runner: &dyn Runner, admins: &[String], pause: &dyn Fn(Duration)) -> Result<()> {
    let mut done = BTreeSet::new();
    let mut errs = Vec::new();
    for round in 0..=END_ROUNDS {
        let listed = list_users(runner).and_then(|out| sessions_to_end(&out, admins));
        let fresh: Vec<u32> = match listed {
            Ok(v) => v.into_iter().filter(|u| !done.contains(u)).collect(),
            Err(e) if round == 0 => return Err(e),
            Err(e) => {
                errs.push(format!("list users in round {}: {e:#}", round + 1));
                break;
            }
        };
        if fresh.is_empty() {
            break;
        }
        if round == END_ROUNDS {
            errs.push(format!(
                "new sessions still appear after {END_ROUNDS} rounds (uid {fresh:?}); ending them on the next retry"
            ));
            break;
        }
        for uid in fresh {
            done.insert(uid);
            let id = uid.to_string();
            let linger_off = run_ok(runner, login_cmd("loginctl", &["disable-linger", &id]));
            if let Err(e) = &linger_off {
                errs.push(format!("uid {id} disable linger: {e:#}"));
            }
            if let Err(e) = run_ok(runner, login_cmd("loginctl", &["terminate-user", &id])) {
                errs.push(format!("uid {id}: {e:#}"));
            }
            if linger_off.is_err() {
                let unit = format!("user@{id}.service");
                if let Err(e) = run_ok(runner, login_cmd("systemctl", &["stop", &unit])) {
                    errs.push(format!("stop {unit}: {e:#}"));
                }
            }
        }
        pause(END_PAUSE);
    }
    if errs.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("{}", errs.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{config, group, paths, tmp_root};
    use super::super::{steps, SysPaths, SysState};
    use super::banner::{BANNER_FILE, GDM_DCONF_DIR};
    use super::login::DENY_LOCKED;
    use super::*;
    use crate::apply::Phase;
    use crate::runner::{FakeRunner, Output};
    use mastersos_bundle::{Lock, LoginMethod, School};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicBool;
    use std::sync::Mutex;

    const LIST: &str = "loginctl list-users --no-legend --json=short";
    const ADMIN: &str = "Boss@School.ac.th";

    /// root、gdm、动态的 gdm-greeter、学生、管理员（名字大小写与 admin_users 不同）、访客。
    const USERS: &str = r#"[
        {"uid":0,"user":"root","linger":false,"state":"online"},
        {"uid":120,"user":"gdm","linger":false,"state":"online"},
        {"uid":60578,"user":"gdm-greeter","linger":false,"state":"active"},
        {"uid":10001,"user":"student@school.ac.th","linger":false,"state":"active"},
        {"uid":10002,"user":"boss@school.ac.th","linger":false,"state":"online"},
        {"uid":1999,"user":"guest","linger":false,"state":"online"}
    ]"#;

    fn school() -> School {
        School {
            admin_users: vec![ADMIN.into()],
            ..School::default()
        }
    }

    fn run_lock(
        p: &SysPaths,
        runner: &dyn Runner,
        sys: &mut SysState,
        lock: Option<&Lock>,
    ) -> Vec<ItemResult> {
        let s = school();
        let mut g = config();
        g.login_methods = vec![LoginMethod::Sso];
        let dir = tempfile::tempdir().unwrap();
        let flag = AtomicBool::new(false);
        let ctx = ApplyContext {
            seed: &crate::system::tests::test_seed(),
            school: &s,
            group: &group(),
            config: &g,
            lock,
            bundle_dir: dir.path(),
            phase: Phase::Full,
            superseded: &flag,
            quiet: &std::sync::atomic::AtomicBool::new(false),
        };
        run(
            &ctx,
            &mut Env {
                paths: p,
                runner,
                sys,
            },
        )
    }

    fn lost() -> Lock {
        Lock {
            message: "本机已挂失，请交回 IT 办公室".into(),
        }
    }

    fn banner_path(root: &Path) -> PathBuf {
        root.join(GDM_DCONF_DIR).join(BANNER_FILE)
    }

    fn terminated(r: &FakeRunner) -> Vec<String> {
        r.calls()
            .into_iter()
            .filter(|c| c.starts_with("loginctl terminate-user"))
            .collect()
    }

    #[test]
    fn lock_terminates_non_admin_sessions() {
        let root = tmp_root();
        let p = paths(root.path());
        let r = FakeRunner::new();
        r.respond(LIST, Output::ok(USERS));
        let mut sys = SysState::default();
        let out = run_lock(&p, &r, &mut sys, Some(&lost()));
        assert_eq!(out, vec![ok(ITEM)]);
        assert_eq!(
            terminated(&r),
            vec![
                "loginctl terminate-user 10001",
                "loginctl terminate-user 1999"
            ]
        );
        // 每个 uid 先关 linger 再结束；结束之后再列一遍（这里没有新的人）。
        let ending: Vec<String> = r
            .calls()
            .into_iter()
            .filter(|c| c.starts_with("loginctl"))
            .collect();
        assert_eq!(
            ending,
            vec![
                LIST,
                "loginctl disable-linger 10001",
                "loginctl terminate-user 10001",
                "loginctl disable-linger 1999",
                "loginctl terminate-user 1999",
                LIST,
            ]
        );
        // 横幅写好、编译过。
        let text = std::fs::read_to_string(banner_path(root.path())).unwrap();
        assert_eq!(text, banner::render_gdm_banner(Some(&lost().message)));
        assert!(r.calls().contains(&"dconf update".to_string()));
        assert!(!sys.dconf_update_pending);
    }

    /// 被踢下去的学生不能趁 `login` 步骤之前再登录：第一条 terminate-user 时策略文件已是锁定的。
    #[test]
    fn lock_writes_policy_before_terminating() {
        struct Probe {
            inner: FakeRunner,
            policy: PathBuf,
            seen: Mutex<Vec<Option<bool>>>,
        }
        impl Runner for Probe {
            fn run(&self, cmd: &Cmd) -> Result<Output> {
                if cmd.line().starts_with("loginctl terminate-user") {
                    let locked = std::fs::read(&self.policy)
                        .ok()
                        .and_then(|b| serde_json::from_slice::<login::LoginPolicy>(&b).ok())
                        .map(|p| p.locked);
                    self.seen.lock().unwrap().push(locked);
                }
                self.inner.run(cmd)
            }
        }
        let root = tmp_root();
        let p = paths(root.path());
        let probe = Probe {
            inner: FakeRunner::new(),
            policy: p.var_dir.join("login/policy.json"),
            seen: Mutex::new(Vec::new()),
        };
        probe.inner.respond(LIST, Output::ok(USERS));
        let mut sys = SysState::default();
        run_lock(&p, &probe, &mut sys, Some(&lost()));
        let seen = probe.seen.lock().unwrap().clone();
        assert!(!seen.is_empty());
        assert!(seen.iter().all(|s| *s == Some(true)), "{seen:?}");
        let pol: login::LoginPolicy =
            serde_json::from_slice(&std::fs::read(&probe.policy).unwrap()).unwrap();
        assert_eq!(pol.lock_message.as_deref(), Some(lost().message.as_str()));
        assert_eq!(pol.admin_users, vec![ADMIN.to_ascii_lowercase()]);
    }

    /// 裁定 K10：锁定时正在跑的锁定应用会话也结束（kiosk 账号不是管理员，uid 1900–1989 不是系统账号）。
    #[test]
    fn sessions_to_end_includes_kiosk() {
        let json = r#"[
            {"uid":120,"user":"gdm","linger":false,"state":"online"},
            {"uid":1900,"user":"kiosk-nwea","linger":false,"state":"active"},
            {"uid":1989,"user":"kiosk-zz","linger":false,"state":"online"},
            {"uid":1999,"user":"guest","linger":false,"state":"online"}
        ]"#;
        assert_eq!(
            sessions_to_end(json, &["admin@school.ac.th".to_string()]).unwrap(),
            vec![1900, 1989, 1999]
        );
    }

    #[test]
    fn lock_skips_greeter_root_and_system_uids() {
        let json = r#"[
            {"uid":0,"user":"root","linger":false,"state":"online"},
            {"uid":120,"user":"gdm","linger":false,"state":"online"},
            {"uid":60578,"user":"gdm-greeter","linger":false,"state":"active"},
            {"uid":1001,"user":"student","linger":false,"state":"active"},
            {"uid":1002,"user":"admin@school.ac.th","linger":false,"state":"online"},
            {"uid":65534,"user":"nobody","linger":false,"state":"online"}
        ]"#;
        assert_eq!(
            sessions_to_end(json, &["ADMIN@school.ac.th".to_string()]).unwrap(),
            vec![1001]
        );
        assert_eq!(sessions_to_end("", &[]).unwrap(), Vec::<u32>::new());
        assert_eq!(sessions_to_end("[]", &[]).unwrap(), Vec::<u32>::new());
        // 解析不了是错误，不是「没有人」。
        assert!(sessions_to_end("not json", &[]).is_err());
    }

    /// Task 19：`loginctl list-users` 里的全部 uid（root、gdm 也算「正在用」），解析不了是错误。
    #[test]
    fn logged_in_uids_lists_everyone() {
        let json = r#"[{"uid":0,"user":"root"},{"uid":10001,"user":"s@school.ac.th"},{"uid":120,"user":"gdm"}]"#;
        assert_eq!(
            logged_in_uids(json).unwrap(),
            BTreeSet::from([0, 120, 10001])
        );
        assert!(logged_in_uids("").unwrap().is_empty());
        assert!(logged_in_uids("UID USER").is_err());
    }

    /// 复审 I1：SSO 账号（名字有 @）不论 uid 都结束，与 pam-check 的 `decide` 一致——authd 的 uid 范围配到 60000 以上时
    /// 学校账号不能因此躲过锁定。没有 @ 的仍按 uid 范围；root 一律不动。
    #[test]
    fn sso_students_end_regardless_of_uid() {
        let json = r#"[
            {"uid":1000000123,"user":"student2@school.ac.th","linger":false,"state":"active"},
            {"uid":70000,"user":"s3@school.ac.th","linger":true,"state":"lingering"},
            {"uid":70001,"user":"boss@school.ac.th","linger":false,"state":"active"},
            {"uid":70002,"user":"gdm-greeter-2","linger":false,"state":"active"},
            {"uid":0,"user":"root@x","linger":false,"state":"online"}
        ]"#;
        assert_eq!(
            sessions_to_end(json, &["boss@school.ac.th".to_string()]).unwrap(),
            vec![1000000123, 70000]
        );
    }

    /// 复审 m3：列表与写策略之间刚过了 PAM 的会话，在第二轮里结束；已经结束过的不再碰。
    #[test]
    fn late_session_is_ended_in_next_round() {
        let root = tmp_root();
        let p = paths(root.path());
        let r = FakeRunner::new();
        r.respond(LIST, Output::ok(USERS));
        let late = r#"[{"uid":10001,"user":"student@school.ac.th","linger":false,"state":"closing"},
            {"uid":10003,"user":"late@school.ac.th","linger":false,"state":"active"}]"#;
        r.respond(LIST, Output::ok(late));
        let out = run_lock(&p, &r, &mut SysState::default(), Some(&lost()));
        assert_eq!(out, vec![ok(ITEM)]);
        assert_eq!(
            terminated(&r),
            vec![
                "loginctl terminate-user 10001",
                "loginctl terminate-user 1999",
                "loginctl terminate-user 10003"
            ]
        );
        assert_eq!(r.calls().iter().filter(|c| *c == LIST).count(), 3);
    }

    /// 复审 N1：结束了人的那一轮之后才停 END_PAUSE 再列；没人可结束时一次都不停。
    #[test]
    fn pause_only_after_a_round_that_ended_someone() {
        let pauses = Mutex::new(Vec::new());
        let rec = |d: Duration| pauses.lock().unwrap().push(d);
        // 第一轮结束两个人、第二轮没有新的：停一次、列两次。
        let r = FakeRunner::new();
        r.respond(LIST, Output::ok(USERS));
        end_sessions(&r, &[ADMIN.to_ascii_lowercase()], &rec).unwrap();
        assert_eq!(*pauses.lock().unwrap(), vec![END_PAUSE]);
        assert_eq!(r.calls().iter().filter(|c| *c == LIST).count(), 2);
        // 没有可结束的人：不停、只列一次。
        pauses.lock().unwrap().clear();
        let r = FakeRunner::new();
        r.respond(LIST, Output::ok(r#"[{"uid":60578,"user":"gdm-greeter"}]"#));
        end_sessions(&r, &[], &rec).unwrap();
        assert!(pauses.lock().unwrap().is_empty());
        assert_eq!(r.calls(), vec![LIST]);
    }

    /// 复审 N2：关 linger 失败时，terminate-user 之后再停用户的 systemd 管理器；关 linger 成功的不停。
    #[test]
    fn failed_disable_linger_stops_user_manager() {
        let r = FakeRunner::new();
        r.respond(LIST, Output::ok(USERS));
        r.respond(
            "loginctl disable-linger 10001",
            Output::fail(1, "no such user"),
        );
        let err = end_sessions(&r, &[ADMIN.to_ascii_lowercase()], &|_| {}).unwrap_err();
        let calls: Vec<String> = r.calls().into_iter().filter(|c| c != LIST).collect();
        assert_eq!(
            calls,
            vec![
                "loginctl disable-linger 10001",
                "loginctl terminate-user 10001",
                "systemctl stop user@10001.service",
                "loginctl disable-linger 1999",
                "loginctl terminate-user 1999",
            ]
        );
        assert!(format!("{err:#}").contains("disable linger"), "{err:#}");
    }

    /// 复审 N3：第一轮之后列表拿不到时，之前各轮的错误留在回报里。
    #[test]
    fn later_list_failure_keeps_earlier_errors() {
        let r = FakeRunner::new();
        r.respond(LIST, Output::ok(USERS));
        r.respond("loginctl terminate-user 10001", Output::fail(1, "boom"));
        r.respond(LIST, Output::fail(1, "logind gone"));
        let err = format!(
            "{:#}",
            end_sessions(&r, &[ADMIN.to_ascii_lowercase()], &|_| {}).unwrap_err()
        );
        assert!(err.contains("uid 10001"), "{err}");
        assert!(err.contains("list users in round 2"), "{err}");
    }

    /// 复审 N4：loginctl 与 systemctl 都带短超时。
    #[test]
    fn login_commands_have_short_timeout() {
        assert_eq!(login_cmd("loginctl", &["x"]).timeout, LOGIN_CMD_TIMEOUT);
        assert!(LOGIN_CMD_TIMEOUT <= Duration::from_secs(10));
    }

    /// 每一轮都有新的人：做满 END_ROUNDS 轮后回报失败（由重试再来），不无限循环。
    #[test]
    fn endless_new_sessions_are_reported() {
        let root = tmp_root();
        let p = paths(root.path());
        let r = FakeRunner::new();
        for i in 0..=END_ROUNDS {
            r.respond(
                LIST,
                Output::ok(&format!(r#"[{{"uid":{},"user":"s{i}@x.th"}}]"#, 20000 + i)),
            );
        }
        let out = run_lock(&p, &r, &mut SysState::default(), Some(&lost()));
        assert!(!out[0].ok);
        assert!(
            out[0]
                .detail
                .as_deref()
                .unwrap()
                .contains("new sessions still appear after"),
            "{out:?}"
        );
        assert_eq!(terminated(&r).len(), END_ROUNDS);
    }

    /// 复审 m5：设置太大而改写的锁定，横幅是「设置太大」的原因而不是「已被学校锁定」，也不结束会话。
    #[test]
    fn oversize_policy_banner_says_why_and_ends_nothing() {
        let root = tmp_root();
        let p = paths(root.path());
        let r = FakeRunner::new();
        r.respond(LIST, Output::ok(USERS));
        let mut s = school();
        s.admin_users = (0..6000)
            .map(|i| format!("{}{i}@school.ac.th", "a".repeat(200)))
            .collect();
        let g = config();
        let dir = tempfile::tempdir().unwrap();
        let flag = AtomicBool::new(false);
        let ctx = ApplyContext {
            seed: &crate::system::tests::test_seed(),
            school: &s,
            group: &group(),
            config: &g,
            lock: None,
            bundle_dir: dir.path(),
            phase: Phase::Full,
            superseded: &flag,
            quiet: &std::sync::atomic::AtomicBool::new(false),
        };
        let out = run(
            &ctx,
            &mut Env {
                paths: &p,
                runner: &r,
                sys: &mut SysState::default(),
            },
        );
        assert_eq!(out, vec![ok(ITEM)]);
        let text = std::fs::read_to_string(banner_path(root.path())).unwrap();
        assert_eq!(
            text,
            banner::render_gdm_banner(Some(login::OVERSIZE_LOCK_MESSAGE))
        );
        assert!(!text.contains(DENY_LOCKED));
        assert!(terminated(&r).is_empty());
    }

    /// systemd 259（26.04）上 `--json=short` 的原样输出；`--output=json` 打的是表格，解析失败要回报出来、不结束任何会话。
    #[test]
    fn real_loginctl_output() {
        let json = "[{\"uid\":1000,\"user\":\"student\",\"linger\":false,\"state\":\"active\"}]\n";
        assert_eq!(sessions_to_end(json, &[]).unwrap(), vec![1000]);
        assert!(parse_users("1000 student no active\n").is_err());
    }

    #[test]
    fn unparsable_user_list_is_reported() {
        let root = tmp_root();
        let p = paths(root.path());
        let r = FakeRunner::new();
        r.respond(LIST, Output::ok("garbage"));
        let out = run_lock(&p, &r, &mut SysState::default(), Some(&lost()));
        assert_eq!(out.len(), 1);
        assert!(!out[0].ok);
        assert!(terminated(&r).is_empty());
    }

    #[test]
    fn unlock_removes_banner() {
        let root = tmp_root();
        let p = paths(root.path());
        let r = FakeRunner::new();
        r.respond(LIST, Output::ok(USERS));
        let mut sys = SysState::default();
        run_lock(&p, &r, &mut sys, Some(&lost()));
        assert!(banner_path(root.path()).exists());
        // 别人放在 gdm.d 里的片段不动。
        std::fs::write(root.path().join(GDM_DCONF_DIR).join("00-other"), b"x").unwrap();

        let r = FakeRunner::new();
        let out = run_lock(&p, &r, &mut sys, None);
        assert_eq!(out, vec![ok(ITEM)]);
        assert!(!banner_path(root.path()).exists());
        assert!(root.path().join(GDM_DCONF_DIR).join("00-other").exists());
        assert_eq!(
            r.calls(),
            vec!["dconf update"],
            "解锁不结束会话、只重编数据库"
        );
        let pol: login::LoginPolicy =
            serde_json::from_slice(&std::fs::read(p.var_dir.join("login/policy.json")).unwrap())
                .unwrap();
        assert!(!pol.locked);

        // 再跑一次：没变化，什么命令都不跑。
        let r = FakeRunner::new();
        assert_eq!(run_lock(&p, &r, &mut sys, None), vec![ok(ITEM)]);
        assert!(r.calls().is_empty(), "{:?}", r.calls());
    }

    #[test]
    fn failed_dconf_update_is_retried() {
        let root = tmp_root();
        let p = paths(root.path());
        let r = FakeRunner::new();
        r.respond("dconf update", Output::fail(1, "boom"));
        let mut sys = SysState::default();
        let out = run_lock(&p, &r, &mut sys, Some(&lost()));
        assert!(!out[0].ok);
        assert!(sys.dconf_update_pending);
        let r = FakeRunner::new();
        assert_eq!(run_lock(&p, &r, &mut sys, Some(&lost())), vec![ok(ITEM)]);
        assert!(r.calls().contains(&"dconf update".to_string()));
        assert!(!sys.dconf_update_pending);
    }

    #[test]
    fn empty_message_shows_generic_reason() {
        let root = tmp_root();
        let p = paths(root.path());
        let r = FakeRunner::new();
        run_lock(
            &p,
            &r,
            &mut SysState::default(),
            Some(&Lock {
                message: "  ".into(),
            }),
        );
        let text = std::fs::read_to_string(banner_path(root.path())).unwrap();
        assert_eq!(text, banner::render_gdm_banner(Some(DENY_LOCKED)));
    }

    #[test]
    fn lock_is_first_step() {
        let all = steps();
        assert_eq!(all[0].name, "lock");
        assert!(all[0].fast);
    }
}
