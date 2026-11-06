#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::runner::{FakeRunner, Output};
use crate::system::kiosk::{Launch, LaunchKind};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::time::{Duration, Instant};

fn web(url: &str, ua: Option<&str>) -> Launch {
    Launch {
        id: "nwea".into(),
        name: "NWEA MAP".into(),
        kind: LaunchKind::Web { url: url.into() },
        user_agent: ua.map(String::from),
        start: None,
    }
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

/// 注入的环境变量。
fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let m: BTreeMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    move |k| m.get(k).cloned()
}

/// 记下写给 journald 的行：(id, MESSAGE)。
#[derive(Default)]
struct Journal(RefCell<Vec<(String, String)>>);

impl Journal {
    fn sink(&self) -> impl Fn(&str, &str, Option<&str>) + '_ {
        move |id, msg, _detail| self.0.borrow_mut().push((id.into(), msg.into()))
    }
    fn lines(&self) -> Vec<(String, String)> {
        self.0.borrow().clone()
    }
}

#[test]
fn supervisor_restarts_then_errors_then_ends() {
    let mut sup = Supervisor::new();
    assert_eq!(sup.window, Duration::from_secs(60));
    assert_eq!(sup.max_exits, 5);
    let t0 = Instant::now();
    // 窗口外的旧退出不计：先在 t0 退出 3 次，过了 61 秒再退出 4 次——都是 Restart
    for _ in 0..3 {
        assert_eq!(sup.next_action(t0), Next::Restart);
    }
    let t1 = t0 + Duration::from_secs(61);
    for i in 0..4 {
        assert_eq!(
            sup.next_action(t1 + Duration::from_secs(i)),
            Next::Restart,
            "{i}"
        );
    }
    // 60 秒内第 5 次：错误页
    assert_eq!(
        sup.next_action(t1 + Duration::from_secs(59)),
        Next::ShowError
    );
    // 错误页再关掉：结束会话（不论隔了多久）
    assert_eq!(
        sup.next_action(t1 + Duration::from_secs(3600)),
        Next::EndSession
    );
    assert_eq!(
        sup.next_action(t1 + Duration::from_secs(7200)),
        Next::EndSession
    );
    // 恰好 60 秒前的那次已在窗口外
    let mut sup = Supervisor::new();
    for i in 0..4 {
        assert_eq!(sup.next_action(t0 + Duration::from_secs(i)), Next::Restart);
    }
    assert_eq!(sup.next_action(t0 + Duration::from_secs(60)), Next::Restart);
    assert_eq!(
        sup.next_action(t0 + Duration::from_secs(60)),
        Next::ShowError
    );
}

#[test]
fn chrome_argv_web() {
    let home = Path::new("/home/kiosk-nwea");
    assert_eq!(
        chrome_argv(&web("https://test.mapnwea.org/", None), home),
        s(&[
            "/usr/bin/google-chrome-stable",
            "--kiosk",
            "--no-first-run",
            "--user-data-dir=/home/kiosk-nwea/.kiosk-chrome",
            "https://test.mapnwea.org/",
        ])
    );
    // PWA（裁定 R3）：同一个 profile，`--app=<url>` 代替网址，不算 app id
    let mut l = web("https://test.mapnwea.org/", None);
    l.kind = LaunchKind::Pwa {
        url: "https://test.mapnwea.org/".into(),
    };
    assert_eq!(
        chrome_argv(&l, home),
        s(&[
            "/usr/bin/google-chrome-stable",
            "--kiosk",
            "--no-first-run",
            "--user-data-dir=/home/kiosk-nwea/.kiosk-chrome",
            "--app=https://test.mapnwea.org/",
        ])
    );
    // 错误页：同一个 profile，本机的 file:// 页面
    assert_eq!(
        error_argv(home),
        s(&[
            "/usr/bin/google-chrome-stable",
            "--kiosk",
            "--no-first-run",
            "--user-data-dir=/home/kiosk-nwea/.kiosk-chrome",
            "file:///usr/share/mastersos/kiosk-error.html",
        ])
    );
    assert_eq!(ERROR_PAGE, mastersos_bundle::kiosk::ERROR_PAGE);
}

#[test]
fn chrome_argv_user_agent_is_single_arg() {
    let ua = "Mozilla/5.0 (X11; \"Linux\" x86_64) 'q' $HOME `x` \\ --no-sandbox";
    let a = chrome_argv(
        &web("https://x.example/", Some(ua)),
        Path::new("/home/kiosk-x"),
    );
    assert_eq!(a.len(), 6, "{a:?}");
    assert_eq!(a[4], format!("--user-agent={ua}"));
    assert_eq!(a[5], "https://x.example/");
    // 网址里的空格之类同样只占一个元素，不经 shell
    let a = chrome_argv(&web("https://x.example/a b?c=$d", None), Path::new("/h"));
    assert_eq!(a.last().unwrap(), "https://x.example/a b?c=$d");
    assert_eq!(a.len(), 5);
}

#[test]
fn exec_argv_flatpak_vs_path() {
    assert_eq!(
        exec_argv("org.example.Calc"),
        s(&["flatpak", "run", "org.example.Calc"])
    );
    assert_eq!(exec_argv("/usr/bin/foo"), s(&["/usr/bin/foo"]));
    // Exec 的启动描述不经 Chrome
    let l = Launch {
        id: "calc".into(),
        name: "Calc".into(),
        kind: LaunchKind::Exec {
            target: "org.example.Calc".into(),
        },
        user_agent: None,
        start: None,
    };
    assert_eq!(
        app_argv(&l, Path::new("/home/kiosk-calc")),
        s(&["flatpak", "run", "org.example.Calc"])
    );
    assert_eq!(
        app_argv(&web("https://x.example/", None), Path::new("/h")),
        chrome_argv(&web("https://x.example/", None), Path::new("/h"))
    );
}

/// native messaging 的一帧：4 字节小端长度 + 内容。
fn frame(body: &[u8]) -> Vec<u8> {
    let mut v = (body.len() as u32).to_le_bytes().to_vec();
    v.extend_from_slice(body);
    v
}

#[test]
fn exit_host_accepts_only_exit() {
    let req = |b: Vec<u8>| read_request(&mut std::io::Cursor::new(b));
    assert_eq!(req(frame(br#"{"cmd":"exit"}"#)), Request::Exit);
    assert_eq!(req(frame(br#" { "cmd" : "exit" } "#)), Request::Exit);
    for bad in [
        &br#"{"cmd":"Exit"}"#[..],
        br#"{"cmd":"exit","x":1}"#,
        br#"{"cmd":"run"}"#,
        br#"{"cmd":["exit"]}"#,
        br#"["exit"]"#,
        br#""exit""#,
        br#"{}"#,
        b"exit",
        b"",
        b"\xff\xfe",
    ] {
        assert_eq!(req(frame(bad)), Request::Invalid, "{bad:?}");
    }
    // 超长：长度头说 4097 字节，不读内容就拒
    let mut big = 4097u32.to_le_bytes().to_vec();
    big.extend(std::iter::repeat_n(b' ', 4097));
    assert_eq!(req(big), Request::Invalid);
    assert_eq!(req(u32::MAX.to_le_bytes().to_vec()), Request::Invalid);
    // 正好 4096 字节的合法消息照收
    let mut body = br#"{"cmd":"exit"}"#.to_vec();
    body.resize(MAX_MESSAGE, b' ');
    assert_eq!(req(frame(&body)), Request::Exit);
    // 坏长度：头不满 4 字节、内容比头说的短
    assert_eq!(req(vec![]), Request::Invalid);
    assert_eq!(req(vec![14, 0]), Request::Invalid);
    let mut short = 14u32.to_le_bytes().to_vec();
    short.extend_from_slice(br#"{"cmd":"#);
    assert_eq!(req(short), Request::Invalid);

    // 整个宿主：回什么、结束哪个会话
    let host_with = |input: Vec<u8>, env: &dyn Fn(&str) -> Option<String>, display: Output| {
        let r = FakeRunner::new();
        r.respond("loginctl show-user ", display);
        let j = Journal::default();
        let mut out = Vec::new();
        let ok = exit_host(
            &mut std::io::Cursor::new(input),
            &mut out,
            &Ctx {
                env,
                runner: &r,
                journal: &j.sink(),
                root: Path::new("/"),
                managed_dir: Path::new("/nonexistent-managed"),
            },
        );
        (ok, out, r.calls(), j.lines())
    };
    let host = |input: Vec<u8>, env: &dyn Fn(&str) -> Option<String>| {
        host_with(input, env, Output::ok("\n"))
    };
    let ok_true = frame(br#"{"ok":true}"#);
    let ok_false = frame(br#"{"ok":false}"#);
    let kiosk = vars(&[("USER", "kiosk-nwea"), ("XDG_SESSION_ID", "c7")]);
    let (ok, out, calls, lines) = host(frame(br#"{"cmd":"exit"}"#), &kiosk);
    assert!(ok);
    assert_eq!(out, ok_true);
    assert_eq!(calls, ["loginctl terminate-session c7"]);
    assert_eq!(lines, [("nwea".to_string(), "exited".to_string())]);
    // 别的消息：回 {"ok":false}，什么都不结束
    let (ok, out, calls, lines) = host(frame(br#"{"cmd":"run"}"#), &kiosk);
    assert!(!ok);
    assert_eq!(out, ok_false);
    assert!(calls.is_empty() && lines.is_empty());
    let (_, out, calls, _) = host(vec![1, 0], &kiosk);
    assert_eq!(out, ok_false);
    assert!(calls.is_empty());
    // 没有 XDG_SESSION_ID：先问 logind 这个账号的图形会话（Display）
    let display = "loginctl show-user kiosk-nwea -p Display --value";
    let (ok, out, calls, _) = host_with(
        frame(br#"{"cmd":"exit"}"#),
        &vars(&[("USER", "kiosk-nwea")]),
        Output::ok("c4\n"),
    );
    assert!(ok);
    assert_eq!(out, ok_true);
    assert_eq!(calls, [display, "loginctl terminate-session c4"]);
    // 问不到（空、失败、不像会话 id）：kiosk 账号退回 terminate-user
    for d in [Output::ok("\n"), Output::fail(1, "x"), Output::ok("-h\n")] {
        let (ok, out, calls, _) = host_with(
            frame(br#"{"cmd":"exit"}"#),
            &vars(&[("USER", "kiosk-nwea")]),
            d,
        );
        assert!(ok);
        assert_eq!(out, ok_true);
        assert_eq!(calls, [display, "loginctl terminate-user kiosk-nwea"]);
    }
    // 不是 kiosk 账号、又问不到会话：什么都不结束，回 {"ok":false}
    let (ok, out, calls, _) = host(frame(br#"{"cmd":"exit"}"#), &vars(&[("USER", "alice")]));
    assert!(!ok);
    assert_eq!(out, ok_false);
    assert_eq!(calls, ["loginctl show-user alice -p Display --value"]);
    // 账号名不像账号名（或没有）：连问都不问
    for env in [
        vars(&[("USER", "-h")]),
        vars(&[("USER", "kiosk-../x")]),
        vars(&[("USER", "")]),
        vars(&[]),
    ] {
        let (ok, out, calls, _) = host(frame(br#"{"cmd":"exit"}"#), &env);
        assert!(!ok);
        assert_eq!(out, ok_false);
        assert!(calls.is_empty(), "{calls:?}");
    }
    // 空的 XDG_SESSION_ID 当没有
    let (_, _, calls, _) = host(
        frame(br#"{"cmd":"exit"}"#),
        &vars(&[("USER", "kiosk-nwea"), ("XDG_SESSION_ID", "")]),
    );
    assert_eq!(calls, [display, "loginctl terminate-user kiosk-nwea"]);
}

#[test]
fn id_from_user() {
    assert_eq!(super::id_from_user("kiosk-nwea").unwrap(), "nwea");
    assert_eq!(super::id_from_user("kiosk-map-2").unwrap(), "map-2");
    for bad in [
        "guest",
        "alice",
        "kiosk-",
        "kiosk-Nwea",
        "kiosk-1abc",
        "kiosk-a/b",
        "kiosk-a.b",
        "Kiosk-nwea",
        "kiosk-it@school.ac.th",
        "",
    ] {
        assert!(super::id_from_user(bad).is_err(), "{bad}");
    }
}

/// 控制者裁定 4 的纵深防御：`run` 只在 GDM 按 `mastersos-kiosk.desktop` 起的会话里起应用。
#[test]
fn run_refuses_outside_kiosk_session() {
    assert!(in_kiosk_session(&vars(&[(
        "XDG_SESSION_DESKTOP",
        "mastersos-kiosk"
    )])));
    for env in [
        vars(&[]),
        vars(&[("XDG_SESSION_DESKTOP", "ubuntu")]),
        vars(&[("XDG_SESSION_DESKTOP", "")]),
        vars(&[
            ("XDG_SESSION_DESKTOP", "ubuntu"),
            ("XDG_CURRENT_DESKTOP", "mastersos-kiosk"),
        ]),
        vars(&[("XDG_CURRENT_DESKTOP", "mastersos-kiosk")]),
    ] {
        assert!(!in_kiosk_session(&env));
    }

    let root = tempfile::tempdir().unwrap();
    write_launch(root.path(), &web("https://test.mapnwea.org/", None));
    let r = FakeRunner::new();
    let j = Journal::default();
    let env = vars(&[
        ("USER", "kiosk-nwea"),
        ("XDG_SESSION_ID", "c3"),
        ("XDG_SESSION_DESKTOP", "ubuntu"),
    ]);
    let spawned = RefCell::new(Vec::<Vec<String>>::new());
    let ok = run(
        &Ctx {
            env: &env,
            runner: &r,
            journal: &j.sink(),
            root: root.path(),
            managed_dir: &root.path().join("managed"),
        },
        None,
        &mut |argv: &[String]| {
            spawned.borrow_mut().push(argv.to_vec());
            Ok(())
        },
        &mut Instant::now,
    );
    assert!(!ok);
    assert!(spawned.borrow().is_empty(), "不起应用");
    assert_eq!(r.calls(), ["loginctl terminate-session c3"]);
    assert_eq!(
        j.lines(),
        [("nwea".to_string(), "ended abnormally".to_string())]
    );

    // 不是 kiosk 账号（在登录界面选了锁定会话）：不起，结束它自己的会话，别留下一个黑屏的 gnome-kiosk
    let r = FakeRunner::new();
    let j = Journal::default();
    let env = vars(&[
        ("USER", "alice"),
        ("XDG_SESSION_ID", "c3"),
        ("XDG_SESSION_DESKTOP", "mastersos-kiosk"),
    ]);
    let ok = run(
        &Ctx {
            env: &env,
            runner: &r,
            journal: &j.sink(),
            root: root.path(),
            managed_dir: &root.path().join("managed"),
        },
        None,
        &mut |_: &[String]| panic!("不该起"),
        &mut Instant::now,
    );
    assert!(!ok);
    assert_eq!(r.calls(), ["loginctl terminate-session c3"]);
    assert_eq!(j.lines(), [(String::new(), "ended abnormally".to_string())]);
    // 没有 XDG_SESSION_ID：同样经 Display 找到自己的会话
    let r = FakeRunner::new();
    r.respond(
        "loginctl show-user alice -p Display --value",
        Output::ok("7\n"),
    );
    let env = vars(&[
        ("USER", "alice"),
        ("XDG_SESSION_DESKTOP", "mastersos-kiosk"),
    ]);
    let ok = run(
        &Ctx {
            env: &env,
            runner: &r,
            journal: &j.sink(),
            root: root.path(),
            managed_dir: &root.path().join("managed"),
        },
        None,
        &mut |_: &[String]| panic!("不该起"),
        &mut Instant::now,
    );
    assert!(!ok);
    assert_eq!(
        r.calls(),
        [
            "loginctl show-user alice -p Display --value",
            "loginctl terminate-session 7"
        ]
    );
}

/// 应用的策略（网页、PWA 与本地程序都有，终审 I1）：agent 写的那份与 pam_namespace 换进会话的那份
/// （测试里是 `<root>/managed/`）字节相同。
const TEST_POLICY: &[u8] = br#"{"URLBlocklist":["*"]}"#;

fn write_launch(root: &Path, l: &Launch) {
    let d = root.join(crate::system::kiosk::PUBLIC_DIR).join(&l.id);
    fs::create_dir_all(&d).unwrap();
    fs::write(
        d.join(crate::system::kiosk::LAUNCH_FILE),
        serde_json::to_vec(l).unwrap(),
    )
    .unwrap();
    let pd = d.join(crate::system::kiosk::POLICIES_DIR);
    fs::create_dir_all(&pd).unwrap();
    fs::write(pd.join(crate::system::kiosk::POLICY_FILE), TEST_POLICY).unwrap();
    let m = root.join("managed");
    fs::create_dir_all(&m).unwrap();
    fs::write(m.join(crate::system::kiosk::POLICY_FILE), TEST_POLICY).unwrap();
}

/// 复审 C1（纵深防御）：会话里 Chrome 读的托管策略目录不是恰好这个应用的那一份（pam_namespace 没生效、实例是空的、
/// 多了别的文件、字节不同、是符号链接、agent 那份不见了），网页应用一律不起：弹错误框、写一行 journald、结束会话。
/// 终审 I1：本地程序同样核对——程序里的链接会在同一个命名空间里起 Chrome，策略不对就是一个没锁的浏览器。
#[test]
fn run_refuses_app_when_policy_not_isolated() {
    let calc = Launch {
        id: "calc".into(),
        name: "Calc".into(),
        kind: LaunchKind::Exec {
            target: "org.example.Calc".into(),
        },
        user_agent: None,
        start: None,
    };
    for launch in [web("https://test.mapnwea.org/", None), calc] {
        policy_not_isolated_cases(&launch);
    }
    assert!(POLICY_NOT_ISOLATED.contains("Please ask your teacher"));
}

/// The session's LANG picks the dialog's language: gettext is asked with that locale and its answer is shown.
#[test]
fn policy_not_isolated_dialog_is_translated() {
    let root = tempfile::tempdir().unwrap();
    write_launch(root.path(), &web("https://test.mapnwea.org/", None));
    // the managed policy directory does not exist: not isolated
    fs::remove_dir_all(root.path().join("managed")).unwrap();
    let r = FakeRunner::new();
    r.respond(
        "/usr/bin/env LC_ALL=th_TH.UTF-8 LANGUAGE=th_TH ",
        Output::ok("การตั้งค่าล็อกของแอปนี้ไม่มีผล"),
    );
    let j = Journal::default();
    let env = vars(&[
        ("USER", "kiosk-nwea"),
        ("XDG_SESSION_ID", "c3"),
        ("XDG_SESSION_DESKTOP", "mastersos-kiosk"),
        ("LANG", "th_TH.UTF-8"),
    ]);
    let spawned = RefCell::new(Vec::<Vec<String>>::new());
    let ok = run(
        &Ctx {
            env: &env,
            runner: &r,
            journal: &j.sink(),
            root: root.path(),
            managed_dir: &root.path().join("managed"),
        },
        None,
        &mut |argv: &[String]| {
            spawned.borrow_mut().push(argv.to_vec());
            Ok(())
        },
        &mut Instant::now,
    );
    assert!(!ok);
    assert_eq!(
        *spawned.borrow(),
        [zenity_error_argv("การตั้งค่าล็อกของแอปนี้ไม่มีผล")]
    );
    let calls = r.calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert!(
        calls[0].ends_with(&format!("/usr/bin/gettext -- {POLICY_NOT_ISOLATED}")),
        "{calls:?}"
    );
    assert_eq!(calls[1], "loginctl terminate-session c3");
}

fn policy_not_isolated_cases(launch: &Launch) {
    let id = launch.id.as_str();
    let user = format!("kiosk-{id}");
    let pol = crate::system::kiosk::POLICY_FILE;
    type Break<'a> = Box<dyn Fn(&Path) + 'a>;
    let cases: Vec<(&str, Break<'_>)> = vec![
        (
            "托管目录里没有策略（namespace 没生效、实例是空的）",
            Box::new(|m: &Path| fs::remove_file(m.join(pol)).unwrap()),
        ),
        (
            "托管目录不存在",
            Box::new(|m: &Path| fs::remove_dir_all(m).unwrap()),
        ),
        (
            "多了一份整机的策略",
            Box::new(|m: &Path| fs::write(m.join("mastersos.json"), b"{}").unwrap()),
        ),
        (
            "字节不同",
            Box::new(|m: &Path| fs::write(m.join(pol), b"{}").unwrap()),
        ),
        (
            "是符号链接",
            Box::new(|m: &Path| {
                let agent = m
                    .parent()
                    .unwrap()
                    .join(crate::system::kiosk::PUBLIC_DIR)
                    .join(id)
                    .join("policies")
                    .join(pol);
                fs::remove_file(m.join(pol)).unwrap();
                std::os::unix::fs::symlink(agent, m.join(pol)).unwrap();
            }),
        ),
        (
            "agent 那份不见了",
            Box::new(|m: &Path| {
                let agent = m
                    .parent()
                    .unwrap()
                    .join(crate::system::kiosk::PUBLIC_DIR)
                    .join(id)
                    .join("policies")
                    .join(pol);
                fs::remove_file(agent).unwrap();
            }),
        ),
    ];
    for (name, break_it) in cases {
        let root = tempfile::tempdir().unwrap();
        write_launch(root.path(), launch);
        break_it(&root.path().join("managed"));
        let r = FakeRunner::new();
        let j = Journal::default();
        let env = vars(&[
            ("USER", user.as_str()),
            ("XDG_SESSION_ID", "c3"),
            ("XDG_SESSION_DESKTOP", "mastersos-kiosk"),
        ]);
        let spawned = RefCell::new(Vec::<Vec<String>>::new());
        let ok = run(
            &Ctx {
                env: &env,
                runner: &r,
                journal: &j.sink(),
                root: root.path(),
                managed_dir: &root.path().join("managed"),
            },
            None,
            &mut |argv: &[String]| {
                spawned.borrow_mut().push(argv.to_vec());
                Ok(())
            },
            &mut Instant::now,
        );
        assert!(!ok, "{name}");
        assert_eq!(
            *spawned.borrow(),
            [zenity_error_argv(POLICY_NOT_ISOLATED)],
            "{id} {name}：只弹错误框，不起应用"
        );
        assert_eq!(r.calls(), ["loginctl terminate-session c3"], "{name}");
        assert_eq!(
            j.lines(),
            [(id.to_string(), "ended abnormally".to_string())],
            "{name}"
        );
    }
}

/// `run` 起网页应用：退出就重开，60 秒内第 5 次退出改开错误页，错误页关掉就结束会话；进入与异常结束各一行 journald。
#[test]
fn run_supervises_web_app() {
    let root = tempfile::tempdir().unwrap();
    write_launch(root.path(), &web("https://test.mapnwea.org/", None));
    let r = FakeRunner::new();
    let j = Journal::default();
    let env = vars(&[
        ("USER", "kiosk-nwea"),
        ("XDG_SESSION_ID", "c3"),
        ("XDG_SESSION_DESKTOP", "mastersos-kiosk"),
    ]);
    let spawned = RefCell::new(Vec::<Vec<String>>::new());
    let t0 = Instant::now();
    let tick = std::cell::Cell::new(0u64);
    let ok = run(
        &Ctx {
            env: &env,
            runner: &r,
            journal: &j.sink(),
            root: root.path(),
            managed_dir: &root.path().join("managed"),
        },
        Some("nwea"),
        &mut |argv: &[String]| {
            spawned.borrow_mut().push(argv.to_vec());
            // 起不来同样算一次退出
            if spawned.borrow().len() == 2 {
                return Err(std::io::Error::other("no chrome"));
            }
            Ok(())
        },
        &mut || {
            tick.set(tick.get() + 1);
            t0 + Duration::from_secs(tick.get())
        },
    );
    assert!(ok);
    let sp = spawned.borrow();
    let home = Path::new("/home/kiosk-nwea");
    let app = chrome_argv(&web("https://test.mapnwea.org/", None), home);
    assert_eq!(sp.len(), 6, "{sp:?}");
    assert!(sp[..5].iter().all(|a| *a == app));
    assert_eq!(sp[5], error_argv(home));
    assert_eq!(r.calls(), ["loginctl terminate-session c3"]);
    assert_eq!(
        j.lines(),
        [
            ("nwea".to_string(), "entered".to_string()),
            ("nwea".to_string(), "ended abnormally".to_string()),
        ]
    );
}

/// 本机程序退出就结束会话（不重开）；`run <id>` 的 id 与账号对不上、启动描述读不到或对不上：不起，结束会话。
#[test]
fn run_exec_app_ends_on_exit() {
    let root = tempfile::tempdir().unwrap();
    let calc = Launch {
        id: "calc".into(),
        name: "Calc".into(),
        kind: LaunchKind::Exec {
            target: "/usr/bin/gnome-calculator".into(),
        },
        user_agent: None,
        start: None,
    };
    write_launch(root.path(), &calc);
    let env = vars(&[
        ("USER", "kiosk-calc"),
        ("XDG_SESSION_ID", "c9"),
        ("XDG_SESSION_DESKTOP", "mastersos-kiosk"),
    ]);
    let go = |id: Option<&str>| {
        let r = FakeRunner::new();
        let j = Journal::default();
        let spawned = RefCell::new(Vec::<Vec<String>>::new());
        let ok = run(
            &Ctx {
                env: &env,
                runner: &r,
                journal: &j.sink(),
                root: root.path(),
                managed_dir: &root.path().join("managed"),
            },
            id,
            &mut |argv: &[String]| {
                spawned.borrow_mut().push(argv.to_vec());
                Ok(())
            },
            &mut Instant::now,
        );
        let sp = spawned.borrow().clone();
        (ok, sp, r.calls(), j.lines())
    };
    let (ok, sp, calls, lines) = go(None);
    assert!(ok);
    assert_eq!(sp, [s(&["/usr/bin/gnome-calculator"])]);
    assert_eq!(calls, ["loginctl terminate-session c9"]);
    assert_eq!(
        lines,
        [
            ("calc".to_string(), "entered".to_string()),
            ("calc".to_string(), "exited".to_string()),
        ]
    );
    // 参数里的 id 不是这个账号的
    let (ok, sp, calls, _) = go(Some("nwea"));
    assert!(!ok);
    assert!(sp.is_empty());
    assert_eq!(calls, ["loginctl terminate-session c9"]);
    // launch.json 里的 id 对不上
    write_launch(
        root.path(),
        &Launch {
            id: "calc".into(),
            ..web("https://x.example/", None)
        },
    );
    let p = root
        .path()
        .join(crate::system::kiosk::PUBLIC_DIR)
        .join("calc/launch.json");
    let mut v: serde_json::Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
    v["id"] = "other".into();
    fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
    let (ok, sp, calls, lines) = go(None);
    assert!(!ok);
    assert!(sp.is_empty());
    assert_eq!(calls, ["loginctl terminate-session c9"]);
    assert_eq!(
        lines,
        [("calc".to_string(), "ended abnormally".to_string())]
    );
    // 没有 launch.json
    fs::remove_file(&p).unwrap();
    let (ok, sp, _, _) = go(None);
    assert!(!ok);
    assert!(sp.is_empty());
}

/// 本地程序起不来：写「异常结束」，照样结束会话，不重试。
#[test]
fn run_exec_spawn_failure_ends_session() {
    let root = tempfile::tempdir().unwrap();
    write_launch(
        root.path(),
        &Launch {
            id: "calc".into(),
            name: "Calc".into(),
            kind: LaunchKind::Exec {
                target: "org.example.Calc".into(),
            },
            user_agent: None,
            start: None,
        },
    );
    let env = vars(&[
        ("USER", "kiosk-calc"),
        ("XDG_SESSION_ID", "c9"),
        ("XDG_SESSION_DESKTOP", "mastersos-kiosk"),
    ]);
    let r = FakeRunner::new();
    let j = Journal::default();
    let n = std::cell::Cell::new(0);
    let ok = run(
        &Ctx {
            env: &env,
            runner: &r,
            journal: &j.sink(),
            root: root.path(),
            managed_dir: &root.path().join("managed"),
        },
        None,
        &mut |_: &[String]| {
            n.set(n.get() + 1);
            Err(std::io::Error::other("no flatpak"))
        },
        &mut Instant::now,
    );
    assert!(ok);
    assert_eq!(n.get(), 1);
    assert_eq!(r.calls(), ["loginctl terminate-session c9"]);
    assert_eq!(
        j.lines(),
        [
            ("calc".to_string(), "entered".to_string()),
            ("calc".to_string(), "ended abnormally".to_string()),
        ]
    );
}

/// 从桌面进入：确认（文字带应用名）之后结束当前会话；取消什么都不做；id 不合规或没建好不问。
#[test]
fn enter_confirms_then_ends_session() {
    let root = tempfile::tempdir().unwrap();
    let mut l = web("https://test.mapnwea.org/", None);
    l.name = "NWEA <b>MAP</b> & \"ห้องสอบ\"".into();
    write_launch(root.path(), &l);
    let env = vars(&[("USER", "alice"), ("XDG_SESSION_ID", "5")]);
    let go = |id: &str, answer: bool| {
        let r = FakeRunner::new();
        let j = Journal::default();
        let asked = RefCell::new(Vec::<String>::new());
        let res = enter(
            &Ctx {
                env: &env,
                runner: &r,
                journal: &j.sink(),
                root: root.path(),
                managed_dir: &root.path().join("managed"),
            },
            id,
            &mut |text: &str| {
                asked.borrow_mut().push(text.into());
                answer
            },
            &mut |e: &str| panic!("不该报错：{e}"),
        );
        let a = asked.borrow().clone();
        (res, a, r.calls())
    };
    let (res, asked, calls) = go("nwea", true);
    assert!(res.is_ok(), "{res:?}");
    // no LANG and no locale.conf: English, and gettext is not run
    assert_eq!(
        asked,
        ["This will end your session and open NWEA <b>MAP</b> & \"ห้องสอบ\" in locked mode."]
    );
    assert_eq!(calls, ["loginctl terminate-session 5"]);
    let (res, asked, calls) = go("nwea", false);
    assert!(res.is_ok());
    assert_eq!(asked.len(), 1);
    assert!(calls.is_empty());
    for bad in ["../nwea", "Nwea", "missing"] {
        let (res, asked, calls) = go(bad, true);
        assert!(res.is_err(), "{bad}");
        assert!(asked.is_empty() && calls.is_empty(), "{bad}");
    }
    // 没有 XDG_SESSION_ID（gnome-shell 起的启动器就是这样）：经 logind 的 Display 找到当前会话；找不到就弹错误框、
    // 返回错误，不是静静地什么都不做
    let no_id = vars(&[("USER", "alice")]);
    let go2 = |display: Output, terminate: Output| {
        let r = FakeRunner::new();
        r.respond("loginctl show-user alice -p Display --value", display);
        r.respond("loginctl terminate-session", terminate);
        let j = Journal::default();
        let errors = RefCell::new(Vec::<String>::new());
        let res = enter(
            &Ctx {
                env: &no_id,
                runner: &r,
                journal: &j.sink(),
                root: root.path(),
                managed_dir: &root.path().join("managed"),
            },
            "nwea",
            &mut |_: &str| true,
            &mut |e: &str| errors.borrow_mut().push(e.into()),
        );
        let e = errors.borrow().clone();
        (res, e, r.calls())
    };
    let (res, errors, calls) = go2(Output::ok("c2\n"), Output::ok(""));
    assert!(res.is_ok(), "{res:?}");
    assert!(errors.is_empty());
    assert_eq!(
        calls,
        [
            "loginctl show-user alice -p Display --value",
            "loginctl terminate-session c2"
        ]
    );
    for d in [Output::ok("\n"), Output::fail(1, "no")] {
        let (res, errors, calls) = go2(d, Output::ok(""));
        assert!(res.is_err());
        assert_eq!(errors, [ENTER_FAILED]);
        assert_eq!(calls, ["loginctl show-user alice -p Display --value"]);
    }
    // loginctl 结束失败：同样弹错误框
    let (res, errors, _) = go2(Output::ok("c2\n"), Output::fail(1, "denied"));
    assert!(res.is_err());
    assert_eq!(errors, [ENTER_FAILED]);
    let z = zenity_error_argv(ENTER_FAILED);
    assert_eq!(z[..3], ["zenity", "--error", "--no-markup"]);

    // zenity 不解析标记（名字里的 <b>、& 原样显示）
    let z = zenity_argv("a <b> & c");
    assert!(z.contains(&"--no-markup".to_string()), "{z:?}");
    assert!(z.contains(&"--text=a <b> & c".to_string()), "{z:?}");
    assert_eq!(z[0], "zenity");
}

/// Without LANG in the session the dialogs follow /etc/locale.conf; the app name goes into the translated sentence.
#[test]
fn enter_dialogs_follow_the_system_locale() {
    let root = tempfile::tempdir().unwrap();
    write_launch(root.path(), &web("https://test.mapnwea.org/", None));
    fs::create_dir_all(root.path().join("etc")).unwrap();
    fs::write(
        root.path().join("etc/locale.conf"),
        "LANG=\"zh_CN.UTF-8\"\n",
    )
    .unwrap();
    let gt = |msgid: &str| {
        format!(
            "/usr/bin/env LC_ALL=zh_CN.UTF-8 LANGUAGE=zh_CN TEXTDOMAIN=mastersos-system \
             TEXTDOMAINDIR=/usr/share/locale /usr/bin/gettext -- {msgid}"
        )
    };
    let r = FakeRunner::new();
    r.respond(
        &gt(ENTER_CONFIRM),
        Output::ok("将结束当前会话，以锁定模式打开 %s。"),
    );
    r.respond(&gt(ENTER_FAILED), Output::ok("无法结束你的会话。"));
    r.respond("loginctl terminate-session", Output::fail(1, "denied"));
    let env = vars(&[("USER", "alice"), ("XDG_SESSION_ID", "5")]);
    let j = Journal::default();
    let (asked, errors) = (RefCell::new(Vec::new()), RefCell::new(Vec::new()));
    let res = enter(
        &Ctx {
            env: &env,
            runner: &r,
            journal: &j.sink(),
            root: root.path(),
            managed_dir: &root.path().join("managed"),
        },
        "nwea",
        &mut |t: &str| {
            asked.borrow_mut().push(t.to_string());
            true
        },
        &mut |e: &str| errors.borrow_mut().push(e.to_string()),
    );
    assert!(res.is_err());
    assert_eq!(
        *asked.borrow(),
        ["将结束当前会话，以锁定模式打开 NWEA MAP。"]
    );
    assert_eq!(*errors.borrow(), ["无法结束你的会话。"]);
    assert_eq!(
        r.calls(),
        [
            gt(ENTER_CONFIRM),
            "loginctl terminate-session 5".to_string(),
            gt(ENTER_FAILED)
        ]
    );
}

/// journald 原生协议的一条：字段一行一个，只有已校验的 id 与固定的文字。
#[test]
fn journal_record_fields() {
    let rec = journal_record("nwea", "entered", None);
    assert_eq!(
        String::from_utf8(rec).unwrap(),
        "MESSAGE=entered\nMASTERSOS_KIOSK=nwea\nSYSLOG_IDENTIFIER=mastersos-kiosk\nPRIORITY=5\n"
    );
    let rec = String::from_utf8(journal_record("nwea", "ended abnormally", Some("a\nb"))).unwrap();
    assert!(
        rec.contains("MASTERSOS_KIOSK_DETAIL=a b\n"),
        "换行不能拆出新字段：{rec}"
    );
    // 不是锁定应用的账号：没有 id，不写这个字段
    let rec = String::from_utf8(journal_record("", "ended abnormally", None)).unwrap();
    assert!(!rec.contains("MASTERSOS_KIOSK="), "{rec}");
}

/// 会话里没有 `XDG_SESSION_DESKTOP`（gnome-session 交给 systemd 用户实例的环境可能不带它）：问 logind 这个账号的会话的
/// Desktop——与 `pam-session` 看的是同一个来源（pam_systemd 照 PAM 环境的 XDG_SESSION_DESKTOP 记下）。全是
/// `mastersos-kiosk` 才起；问不到、没有会话、有一个不是，都不起。
#[test]
fn run_falls_back_to_logind_desktop() {
    let root = tempfile::tempdir().unwrap();
    let calc = Launch {
        id: "calc".into(),
        name: "Calc".into(),
        kind: LaunchKind::Exec {
            target: "org.example.Calc".into(),
        },
        user_agent: None,
        start: None,
    };
    write_launch(root.path(), &calc);
    let env = vars(&[("USER", "kiosk-calc")]);
    let go = |sessions: Output, desktops: &[(&str, Output)]| {
        let r = FakeRunner::new();
        r.respond(
            "loginctl show-user kiosk-calc -p Sessions --value",
            sessions,
        );
        for (id, out) in desktops {
            r.respond(
                &format!("loginctl show-session {id} -p Desktop --value"),
                out.clone(),
            );
        }
        let j = Journal::default();
        let n = std::cell::Cell::new(0);
        let ok = run(
            &Ctx {
                env: &env,
                runner: &r,
                journal: &j.sink(),
                root: root.path(),
                managed_dir: &root.path().join("managed"),
            },
            None,
            &mut |_: &[String]| {
                n.set(n.get() + 1);
                Ok(())
            },
            &mut Instant::now,
        );
        (ok, n.get(), r.calls())
    };
    let kiosk = || Output::ok("mastersos-kiosk\n");
    let (ok, n, calls) = go(Output::ok("c9\n"), &[("c9", kiosk())]);
    assert!(ok);
    assert_eq!(n, 1);
    assert_eq!(calls.last().unwrap(), "loginctl terminate-user kiosk-calc");
    for (sessions, desktops) in [
        (
            Output::ok("c9 c10\n"),
            vec![("c9", kiosk()), ("c10", Output::ok("ubuntu\n"))],
        ),
        (Output::ok("\n"), vec![]),
        (Output::fail(1, "no such user"), vec![]),
        (Output::ok("c9\n"), vec![("c9", Output::fail(1, "x"))]),
        (Output::ok("--help\n"), vec![]),
    ] {
        let (ok, n, calls) = go(sessions, &desktops);
        assert!(!ok, "{calls:?}");
        assert_eq!(n, 0);
        assert_eq!(calls.last().unwrap(), "loginctl terminate-user kiosk-calc");
    }
}

#[test]
fn dispatch_rejects_unknown_subcommands() {
    assert_eq!(parse(&["run".into()]), Ok(Sub::Run(None)));
    assert_eq!(
        parse(&["run".into(), "nwea".into()]),
        Ok(Sub::Run(Some("nwea".into())))
    );
    // Chrome 给宿主带上调用方的 origin（与 --parent-window）：多的参数不看
    assert_eq!(
        parse(&[
            "exit-host".into(),
            "chrome-extension://abc/".into(),
            "--parent-window=0".into()
        ]),
        Ok(Sub::ExitHost)
    );
    assert_eq!(
        parse(&["enter".into(), "nwea".into()]),
        Ok(Sub::Enter("nwea".into()))
    );
    assert!(parse(&["enter".into()]).is_err());
    assert_eq!(parse(&["guard".into()]), Ok(Sub::Guard));
    assert!(parse(&["guard".into(), "x".into()]).is_err());
    assert!(parse(&[]).is_err());
    assert!(parse(&["shell".into()]).is_err());
    assert!(parse(&["run".into(), "a".into(), "b".into()]).is_err());
}

/// Session guard (review I1): pam-session can only see the session GDM saved to AccountsService; the guard runs in the
/// session itself (user unit before gnome-session-pre.target) and sees the one GDM actually started. A kiosk uid
/// (1900–1989) in anything but mastersos-kiosk fails, which ends the session before GNOME Shell starts; a missing
/// variable fails too. Other uids pass whatever their session (`run` handles them in the kiosk session).
#[test]
fn guard_ends_kiosk_accounts_outside_the_kiosk_session() {
    let go = |uid: u32, env: &[(&str, &str)]| {
        let j = Journal::default();
        let r = FakeRunner::new();
        let env = vars(env);
        let ok = guard(
            &Ctx {
                env: &env,
                runner: &r,
                journal: &j.sink(),
                root: Path::new("/"),
                managed_dir: Path::new("/nonexistent-managed"),
            },
            uid,
        );
        assert!(r.calls().is_empty());
        (ok, j.lines())
    };
    fn kiosk(d: &str) -> Vec<(&str, &str)> {
        vec![("USER", "kiosk-nwea"), ("XDG_SESSION_DESKTOP", d)]
    }
    assert_eq!(go(1901, &kiosk("mastersos-kiosk")), (true, vec![]));
    for d in ["ubuntu", "gnome", "", "mastersos-kiosk2"] {
        let (ok, lines) = go(1901, &kiosk(d));
        assert!(!ok, "{d:?}");
        assert_eq!(
            lines,
            [("nwea".to_string(), MSG_WRONG_SESSION.to_string())],
            "{d:?}"
        );
    }
    let (ok, lines) = go(1900, &[("USER", "kiosk-exttest")]);
    assert!(!ok);
    assert_eq!(
        lines,
        [("exttest".to_string(), MSG_WRONG_SESSION.to_string())]
    );
    // The uid decides, not the name: a kiosk uid with an odd USER still fails
    let (ok, _) = go(1989, &[("USER", "x"), ("XDG_SESSION_DESKTOP", "ubuntu")]);
    assert!(!ok);
    // Everyone else passes, journal untouched
    for uid in [0, 1000, 1899, 1990, 60578] {
        for d in [Some("ubuntu"), Some("mastersos-kiosk"), None] {
            let mut env = vec![("USER", "kiosk-nwea")];
            if let Some(d) = d {
                env.push(("XDG_SESSION_DESKTOP", d));
            }
            assert_eq!(go(uid, &env), (true, vec![]), "{uid} {d:?}");
        }
    }
}

/// Design 2026-11-06-kiosk-platform-inject §3.3: a web app with a start page opens it instead of its url.
#[test]
fn chrome_argv_opens_the_start_page() {
    let start = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/start.html#%7B%7D";
    let l = Launch {
        start: Some(start.into()),
        ..web("https://home.testnav.com/", None)
    };
    let a = chrome_argv(&l, Path::new("/home/kiosk-tn"));
    assert_eq!(a.last().unwrap(), start);
    assert!(!a.iter().any(|x| x.contains("home.testnav.com")), "{a:?}");
    // launch.json without the key (older agents) still reads
    let old: Launch = serde_json::from_str(
        r#"{"id":"x","name":"X","kind":{"type":"web","url":"https://x.example/"}}"#,
    )
    .unwrap();
    assert_eq!(old.start, None);
}
