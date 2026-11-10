use super::super::tests::{config_of, group, paths, tmp_root, Kind};
use super::*;
use crate::fetch::Fetcher;
use crate::jobs::{spawn_all, SideResults};
use crate::runner::{FakeRunner, Output};
use mastersos_bundle::{DeviceIdent, Seed};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tokio::sync::{watch, Notify};
use tokio_util::sync::CancellationToken;

const LO: &str = "org.libreoffice.LibreOffice";
const TOOL: &str = "org.example.Tool";
const LIST: &str = "flatpak list --system --app --columns=application";
const INSTALL: &str = "flatpak install --system --noninteractive -y flathub";
const UNINSTALL: &str = "flatpak uninstall --system --noninteractive -y";

fn s(ids: &[&str]) -> Vec<String> {
    ids.iter().map(|i| i.to_string()).collect()
}

fn set(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|i| i.to_string()).collect()
}

fn cur(kind: Kind, list: &[&str]) -> CurrentGroup {
    let mut config = config_of(kind);
    config.apps.flatpak = s(list);
    CurrentGroup {
        version: 1,
        group: group(),
        config,
        escrow_recipients: vec![],
    }
}

fn write_state(p: &SysPaths, managed: &[&str]) {
    fs::create_dir_all(&p.var_dir).unwrap();
    let st = FlatpakState {
        managed: set(managed),
        ..Default::default()
    };
    fs::write(p.var_dir.join(STATE_FILE), serde_json::to_vec(&st).unwrap()).unwrap();
}

/// 对账一次，这一轮里一直没有新包。
fn rec(r: &FakeRunner, p: &SysPaths, c: Option<&CurrentGroup>) -> (Vec<ItemResult>, bool) {
    reconcile(r, p, c, &|| true)
}

fn find<'a>(out: &'a [ItemResult], id: &str) -> &'a ItemResult {
    out.iter()
        .find(|r| r.item == format!("flatpak:{id}"))
        .unwrap_or_else(|| panic!("没有 flatpak:{id}：{out:?}"))
}

/// Adds the Flathub remote and installs `LO` under `kind`; returns the calls and `flatpak:LO`.
fn install_lo(kind: Kind) -> (Vec<String>, ItemResult) {
    let root = tmp_root();
    let p = paths(root.path());
    let r = FakeRunner::new();
    let (out, _) = rec(&r, &p, Some(&cur(kind, &[LO])));
    (r.calls(), find(&out, LO).clone())
}

/// Config profiles design §4.2: `learning` installs the Config's Flatpaks (the one difference
/// from the old browser mode).
#[test]
fn learning_installs_flatpak() {
    let (calls, it) = install_lo(Kind::Learning);
    assert!(calls.iter().any(|c| c.contains("remote-add")), "{calls:?}");
    assert!(calls.contains(&format!("{INSTALL} {LO}")), "{calls:?}");
    assert_eq!(it, ok(&format!("flatpak:{LO}")));
}

#[test]
fn full_installs_flatpak() {
    let (calls, it) = install_lo(Kind::Full);
    assert!(calls.contains(&format!("{INSTALL} {LO}")), "{calls:?}");
    assert_eq!(it, ok(&format!("flatpak:{LO}")));
}

/// §3.1: a legacy `mode = "browser"` Group installs nothing, exactly as before.
#[test]
fn legacy_browser_skips_flatpak() {
    let (calls, it) = install_lo(Kind::LegacyBrowser);
    assert!(
        !calls
            .iter()
            .any(|c| c.contains("remote-add") || c.starts_with(INSTALL)),
        "{calls:?}"
    );
    assert!(it.ok, "{it:?}");
    assert_eq!(it.detail.as_deref(), Some("browser mode: not installing"));
}

#[test]
fn plan_installs_missing_only() {
    let (install, uninstall) = plan(
        &s(&[LO, "org.gnome.Calculator", LO]),
        &set(&["org.gnome.Calculator"]),
        &set(&[]),
    );
    assert_eq!(install, s(&[LO]));
    assert!(uninstall.is_empty());
}

/// Review Focus 2：IT 在本机装的 org.example.Tool 不在 managed → 不卸。
#[test]
fn uninstalls_only_managed_apps() {
    let (install, uninstall) = plan(&[], &set(&[LO, TOOL]), &set(&[LO]));
    assert!(install.is_empty());
    assert_eq!(uninstall, s(&[LO]));

    // 整轮对账：清单清空了
    let root = tmp_root();
    let p = paths(root.path());
    write_state(&p, &[LO]);
    let r = FakeRunner::new();
    r.respond(LIST, Output::ok(&format!("{LO}\n{TOOL}\n")));
    let (out, changed) = rec(&r, &p, Some(&cur(Kind::Full, &[])));
    assert!(changed);
    let calls = r.calls();
    assert!(calls.contains(&format!("{UNINSTALL} {LO}")), "{calls:?}");
    assert!(!calls.iter().any(|c| c.contains(TOOL)), "{calls:?}");
    assert!(find(&out, LO).ok);
    assert!(load_state(&p).unwrap().managed.is_empty());
    let mode = fs::metadata(p.var_dir.join(STATE_FILE))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    // 清单里也有 Tool（IT 先装了）：不装、不记成我们的；从清单删掉后照样不卸
    let r = FakeRunner::new();
    r.respond(LIST, Output::ok(&format!("{TOOL}\n")));
    let (out, _) = rec(&r, &p, Some(&cur(Kind::Full, &[TOOL])));
    assert!(find(&out, TOOL).ok);
    assert!(!r.calls().iter().any(|c| c.starts_with(INSTALL)));
    assert!(load_state(&p).unwrap().managed.is_empty());
    let r = FakeRunner::new();
    r.respond(LIST, Output::ok(&format!("{TOOL}\n")));
    rec(&r, &p, Some(&cur(Kind::Full, &[])));
    assert!(!r.calls().iter().any(|c| c.starts_with(UNINSTALL)));
}

/// 装失败：不进 managed，下一轮再试。
#[test]
fn failed_install_not_recorded() {
    let root = tmp_root();
    let p = paths(root.path());
    let r = FakeRunner::new();
    r.respond(INSTALL, Output::fail(1, "error: 网断了"));
    let c = cur(Kind::Full, &[LO]);
    let (out, changed) = rec(&r, &p, Some(&c));
    assert!(!changed);
    let it = find(&out, LO);
    assert!(
        !it.ok && it.detail.as_deref().unwrap().contains("网断了"),
        "{it:?}"
    );
    assert!(load_state(&p).unwrap().managed.is_empty());
    // 下一轮：再装，这次成功
    let (out, changed) = rec(&r, &p, Some(&c));
    assert!(changed);
    assert!(find(&out, LO).ok);
    assert_eq!(
        r.calls()
            .iter()
            .filter(|l| **l == format!("{INSTALL} {LO}"))
            .count(),
        2
    );
    assert_eq!(load_state(&p).unwrap().managed, set(&[LO]));
}

#[test]
fn adds_remote_before_install() {
    let root = tmp_root();
    let p = paths(root.path());
    let r = FakeRunner::new();
    rec(&r, &p, Some(&cur(Kind::Full, &[LO])));
    let calls = r.calls();
    let remote = calls
        .iter()
        .position(|c| {
            c == "flatpak remote-add --system --if-not-exists flathub /usr/share/mastersos/flathub.flatpakrepo"
        })
        .expect("没加源");
    let install = calls
        .iter()
        .position(|c| *c == format!("{INSTALL} {LO}"))
        .expect("没装");
    assert!(remote < install, "{calls:?}");
    // 浏览器模式：不加源、不装；我们装过的照清单卸
    let r = FakeRunner::new();
    write_state(&p, &[LO, "org.gnome.Calculator"]);
    r.respond(LIST, Output::ok(&format!("{LO}\norg.gnome.Calculator\n")));
    let (out, _) = rec(&r, &p, Some(&cur(Kind::LegacyBrowser, &[LO])));
    let calls = r.calls();
    assert!(
        !calls
            .iter()
            .any(|c| c.contains("remote-add") || c.starts_with(INSTALL)),
        "{calls:?}"
    );
    assert!(
        calls.contains(&format!("{UNINSTALL} org.gnome.Calculator")),
        "{calls:?}"
    );
    assert!(!calls.contains(&format!("{UNINSTALL} {LO}")), "{calls:?}");
    assert!(find(&out, LO).ok);
    // 没有包：什么都不做
    let r = FakeRunner::new();
    assert_eq!(rec(&r, &p, None), (vec![], false));
    assert!(r.calls().is_empty());
}

#[test]
fn bad_flatpak_id_is_skipped() {
    let root = tmp_root();
    let p = paths(root.path());
    let r = FakeRunner::new();
    let (out, _) = rec(
        &r,
        &p,
        Some(&cur(Kind::Full, &["libreoffice", "org.x.Y; rm -rf /", LO])),
    );
    assert!(!find(&out, "libreoffice").ok);
    assert!(!find(&out, "org.x.Y; rm -rf /").ok);
    assert!(find(&out, LO).ok);
    let installs: Vec<String> = r
        .calls()
        .into_iter()
        .filter(|c| c.starts_with(INSTALL))
        .collect();
    assert_eq!(installs, vec![format!("{INSTALL} {LO}")]);
}

/// 复审 M1：状态文件内容坏了 → 改名成 .bad、回报一次 flatpak:state、当作空：之前记着的 LO 不再算我们的（不卸），
/// 清单里的照装。
#[test]
fn corrupt_state_is_quarantined_and_installs_continue() {
    let root = tmp_root();
    let p = paths(root.path());
    fs::create_dir_all(&p.var_dir).unwrap();
    fs::write(p.var_dir.join(STATE_FILE), "{bad").unwrap();
    let r = FakeRunner::new();
    r.respond(LIST, Output::ok(&format!("{LO}\n")));
    let (out, changed) = rec(&r, &p, Some(&cur(Kind::Full, &[TOOL])));
    assert!(changed);
    let st = out
        .iter()
        .find(|i| i.item == STATE_ITEM)
        .expect("没报 flatpak:state");
    assert!(
        !st.ok && st.detail.as_deref().unwrap().contains(BAD_STATE_FILE),
        "{st:?}"
    );
    assert!(find(&out, TOOL).ok);
    let calls = r.calls();
    assert!(calls.contains(&format!("{INSTALL} {TOOL}")), "{calls:?}");
    assert!(
        !calls.iter().any(|c| c.starts_with(UNINSTALL)),
        "坏状态下不卸：{calls:?}"
    );
    assert_eq!(
        fs::read_to_string(p.var_dir.join(BAD_STATE_FILE)).unwrap(),
        "{bad"
    );
    assert_eq!(load_state(&p).unwrap().managed, set(&[TOOL]));
    // 下一轮：不再报 flatpak:state
    let r = FakeRunner::new();
    r.respond(LIST, Output::ok(&format!("{LO}\n{TOOL}\n")));
    let (out, _) = rec(&r, &p, Some(&cur(Kind::Full, &[TOOL])));
    assert!(out.iter().all(|i| i.item != STATE_ITEM), "{out:?}");
}

/// 复审 I1：装到最后一步超时（install 报错），其实已经装上了 → 下一轮收进 managed，清单删掉后照样卸。
#[test]
fn timed_out_but_installed_is_adopted() {
    let root = tmp_root();
    let p = paths(root.path());
    let r = FakeRunner::new();
    r.respond(
        INSTALL,
        Output::fail(124, "flatpak 超时：900 秒内没有结束，已终止"),
    );
    let (out, changed) = rec(&r, &p, Some(&cur(Kind::Full, &[LO])));
    assert!(!find(&out, LO).ok);
    assert!(!changed);
    let st = load_state(&p).unwrap();
    assert_eq!((st.pending, st.managed), (set(&[LO]), set(&[])));
    // 下一轮：已装 → 收下，不再装
    r.respond(LIST, Output::ok(&format!("{LO}\n")));
    let (out, changed) = rec(&r, &p, Some(&cur(Kind::Full, &[LO])));
    assert!(changed);
    assert!(
        find(&out, LO).ok && find(&out, LO).detail.is_none(),
        "{out:?}"
    );
    let st = load_state(&p).unwrap();
    assert_eq!((st.pending, st.managed), (set(&[]), set(&[LO])));
    assert_eq!(dock_apps(&p, &s(&[LO])), s(&[LO]));
    // 清单删掉：卸
    r.respond(LIST, Output::ok(&format!("{LO}\n")));
    rec(&r, &p, Some(&cur(Kind::Full, &[])));
    assert!(r.calls().contains(&format!("{UNINSTALL} {LO}")));
}

/// 复审 I1：记录意图失败 → 不装；装好了但记不下 → 盘上的 pending 让下一轮收下。
#[test]
fn save_failure_paths() {
    let root = tmp_root();
    let p = paths(root.path());
    let c = cur(Kind::Full, &[LO]);
    // 第一次写（pending）就失败：不装
    let r = FakeRunner::new();
    TEST_SAVE_BUDGET.with(|b| b.set(Some(0)));
    let (out, _) = rec(&r, &p, Some(&c));
    TEST_SAVE_BUDGET.with(|b| b.set(None));
    assert!(!find(&out, LO).ok, "{out:?}");
    assert!(
        !r.calls().iter().any(|l| l.starts_with(INSTALL)),
        "{:?}",
        r.calls()
    );
    // pending 写下了、装好之后那次写失败
    let r = FakeRunner::new();
    TEST_SAVE_BUDGET.with(|b| b.set(Some(1)));
    let (out, _) = rec(&r, &p, Some(&c));
    TEST_SAVE_BUDGET.with(|b| b.set(None));
    let it = find(&out, LO);
    assert!(
        !it.ok && it.detail.as_deref().unwrap().contains("recording failed"),
        "{it:?}"
    );
    assert_eq!(load_state(&p).unwrap().pending, set(&[LO]));
    // 下一轮：已装 → 收进 managed，不再装
    let r = FakeRunner::new();
    r.respond(LIST, Output::ok(&format!("{LO}\n")));
    let (out, changed) = rec(&r, &p, Some(&c));
    assert!(changed && find(&out, LO).ok);
    assert!(!r.calls().iter().any(|l| l.starts_with(INSTALL)));
    assert_eq!(load_state(&p).unwrap().managed, set(&[LO]));
}

/// 复审 I1：pending 里的从清单删掉了——已装上的收下再卸；没装上的直接丢掉，不卸任何东西。
#[test]
fn dropped_while_pending() {
    let root = tmp_root();
    let p = paths(root.path());
    fs::create_dir_all(&p.var_dir).unwrap();
    let st = FlatpakState {
        pending: set(&[LO, TOOL]),
        ..Default::default()
    };
    fs::write(p.var_dir.join(STATE_FILE), serde_json::to_vec(&st).unwrap()).unwrap();
    let r = FakeRunner::new();
    // LO 装上了（上一轮超时在最后），TOOL 没装上
    r.respond(LIST, Output::ok(&format!("{LO}\norg.gnome.Calculator\n")));
    let (out, changed) = rec(&r, &p, Some(&cur(Kind::Full, &[])));
    let calls = r.calls();
    assert!(calls.contains(&format!("{UNINSTALL} {LO}")), "{calls:?}");
    assert!(
        !calls
            .iter()
            .any(|c| c.contains(TOOL) || c.contains("Calculator")),
        "{calls:?}"
    );
    assert!(find(&out, LO).ok);
    assert!(!changed, "收下又卸掉：managed 前后都是空");
    let st = load_state(&p).unwrap();
    assert!(st.pending.is_empty() && st.managed.is_empty(), "{st:?}");
}

/// 复审 M2：一次 list 是空的不清 managed；人手动卸掉、清单里也没了的才丢掉（changed → 再应用）。
#[test]
fn managed_pruning() {
    let root = tmp_root();
    let p = paths(root.path());
    write_state(&p, &[LO, TOOL]);
    let r = FakeRunner::new();
    r.respond(LIST, Output::ok(""));
    let (_, changed) = rec(&r, &p, Some(&cur(Kind::Full, &[LO])));
    assert_eq!(
        load_state(&p).unwrap().managed,
        set(&[LO, TOOL]),
        "空的 list 不当真"
    );
    assert!(!changed);
    // TOOL 被人手动卸了、清单里也没有：丢掉；LO 被卸了但清单里还有：留着并重装
    let r = FakeRunner::new();
    r.respond(LIST, Output::ok("org.gnome.Calculator\n"));
    let (out, changed) = rec(&r, &p, Some(&cur(Kind::Full, &[LO])));
    assert!(changed);
    assert!(r.calls().contains(&format!("{INSTALL} {LO}")));
    assert!(find(&out, LO).ok);
    assert_eq!(load_state(&p).unwrap().managed, set(&[LO]));
}

/// list 失败：什么都不装不卸、状态不动，清单里与记着的都报失败。
#[test]
fn list_failure_changes_nothing() {
    let root = tmp_root();
    let p = paths(root.path());
    write_state(&p, &[TOOL]);
    let r = FakeRunner::new();
    r.respond(LIST, Output::fail(1, "error: 仓库锁住了"));
    let (out, changed) = rec(&r, &p, Some(&cur(Kind::Full, &[LO])));
    assert!(!changed);
    assert!(!find(&out, LO).ok && !find(&out, TOOL).ok);
    assert!(!r
        .calls()
        .iter()
        .any(|c| c.starts_with(INSTALL) || c.starts_with(UNINSTALL)));
    assert_eq!(load_state(&p).unwrap().managed, set(&[TOOL]));
}

/// 卸过应用就清不用的运行时；它失败只记在 flatpak:runtimes，不连累应用那一项。没卸东西就不跑。
#[test]
fn unused_runtimes_removed_after_uninstall() {
    let root = tmp_root();
    let p = paths(root.path());
    write_state(&p, &[LO]);
    let r = FakeRunner::new();
    r.respond(LIST, Output::ok(&format!("{LO}\n")));
    r.respond(
        "flatpak uninstall --system --noninteractive -y --unused",
        Output::fail(1, "x"),
    );
    let (out, _) = rec(&r, &p, Some(&cur(Kind::Full, &[])));
    let calls = r.calls();
    let app = calls
        .iter()
        .position(|c| *c == format!("{UNINSTALL} {LO}"))
        .unwrap();
    let unused = calls
        .iter()
        .position(|c| c == "flatpak uninstall --system --noninteractive -y --unused")
        .expect("没清运行时");
    assert!(app < unused);
    assert!(find(&out, LO).ok);
    assert!(!out.iter().find(|i| i.item == RUNTIMES_ITEM).unwrap().ok);
    // 什么都没卸：不跑
    let r = FakeRunner::new();
    rec(&r, &p, Some(&cur(Kind::Full, &[])));
    assert!(!r.calls().iter().any(|c| c.contains("--unused")));
}

/// 复审 M5：这一轮开始后来了新包 → 下一个应用之前停下（剩下的不装、卸载留给马上要跑的下一轮）。
#[test]
fn new_bundle_stops_install_queue() {
    let root = tmp_root();
    let p = paths(root.path());
    write_state(&p, &["org.old.App"]);
    let r = FakeRunner::new();
    r.respond(LIST, Output::ok("org.old.App\n"));
    let calls = std::cell::Cell::new(0);
    let still = || {
        calls.set(calls.get() + 1);
        calls.get() == 1
    };
    let (out, _) = reconcile(&r, &p, Some(&cur(Kind::Full, &[LO, TOOL])), &still);
    let installs: Vec<String> = r
        .calls()
        .into_iter()
        .filter(|c| c.starts_with(INSTALL))
        .collect();
    assert_eq!(installs, vec![format!("{INSTALL} {LO}")]);
    assert!(!r.calls().iter().any(|c| c.starts_with(UNINSTALL)));
    assert!(out.iter().all(|i| i.item != format!("flatpak:{TOOL}")));
}

#[test]
fn dock_apps_reads_state_or_empty() {
    let root = tmp_root();
    let p = paths(root.path());
    assert!(dock_apps(&p, &s(&[LO])).is_empty());
    assert!(!p.var_dir.exists(), "只读，不建目录");
    write_state(&p, &[LO, TOOL]);
    assert_eq!(dock_apps(&p, &s(&[TOOL, LO])), s(&[TOOL, LO]));
    assert_eq!(
        dock_apps(&p, &s(&[LO])),
        s(&[LO]),
        "清单里没有了的不进 Dock"
    );
}

fn ctx(p: SysPaths, rx: watch::Receiver<Option<Arc<CurrentGroup>>>) -> Arc<JobCtx> {
    Arc::new(JobCtx {
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
        paths: p,
        runner: Arc::new(FakeRunner::new()),
        identity: None,
        current: rx,
        reapply: Arc::new(Notify::new()),
        fetch_error: tokio::sync::watch::channel(None).1,
        quiet: tokio::sync::watch::channel(None).1,
    })
}

/// 发布 current 的新值 → job 在 1 s 内跑了一次（every 远未到）；装好了叫主循环再应用。
#[tokio::test(start_paused = true)]
async fn new_bundle_wakes_flatpak_job() {
    let root = tmp_root();
    let r = Arc::new(FakeRunner::new());
    let (tx, rx) = watch::channel(None);
    let cx = ctx(paths(root.path()), rx);
    let shutdown = CancellationToken::new();
    let side: SideResults = Default::default();
    let s = spawn_all(
        vec![Arc::new(FlatpakJob::new(r.clone()))],
        cx.clone(),
        side.clone(),
        shutdown.clone(),
        Default::default(),
    );
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(r.calls().is_empty(), "还没有包：什么都不做");
    tx.send_replace(Some(Arc::new(cur(Kind::Full, &[LO]))));
    tokio::time::timeout(Duration::from_secs(1), cx.reapply.notified())
        .await
        .expect("1 秒内没对账");
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(r.calls().contains(&format!("{INSTALL} {LO}")));
    assert!(crate::jobs::snapshot(&side)
        .iter()
        .any(|i| i.item == format!("flatpak:{LO}")));
    // 清单删掉它：旧的回报项换成「已卸载」，下一轮就不再出现
    r.respond(LIST, Output::ok(&format!("{LO}\n")));
    tx.send_replace(Some(Arc::new(cur(Kind::Full, &[]))));
    tokio::time::timeout(Duration::from_secs(1), cx.reapply.notified())
        .await
        .expect("1 秒内没对账");
    tx.send_replace(Some(Arc::new(CurrentGroup {
        version: 3,
        ..cur(Kind::Full, &[])
    })));
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        crate::jobs::snapshot(&side)
            .iter()
            .all(|i| !i.item.starts_with("flatpak:")),
        "{:?}",
        crate::jobs::snapshot(&side)
    );
    shutdown.cancel();
    for h in s.handles {
        h.await.unwrap();
    }
}

/// 并行的测试里别的对账可能正拿着锁（update 这时返回 None）：等到真跑了为止。
/// The wait must outlast apply_worker's slow_install test, which holds the lock through a 15 s fake install.
fn upd(r: &FakeRunner, p: &SysPaths, now: chrono::DateTime<chrono::Utc>) -> ItemResult {
    for _ in 0..12000 {
        if let Some(i) = update(r, p, now) {
            return i;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("update 一直没跑");
}

#[test]
fn update_runs_once_a_day() {
    use chrono::{TimeDelta, Utc};
    let root = tmp_root();
    let p = paths(root.path());
    let now = Utc::now();
    assert!(update_due(None, now));
    assert!(!update_due(Some(now - TimeDelta::hours(23)), now));
    assert!(update_due(Some(now - TimeDelta::hours(24)), now));
    assert!(
        update_due(Some(now + TimeDelta::hours(1)), now),
        "记下的时刻在将来（时钟拨过）：照跑"
    );
    write_state(&p, &[LO]);
    let r = FakeRunner::new();
    assert!(upd(&r, &p, now).ok);
    assert_eq!(
        r.calls(),
        vec!["flatpak update --system --noninteractive -y"]
    );
    let st = load_state(&p).unwrap();
    assert_eq!(st.last_update, Some(now));
    assert_eq!(st.managed, set(&[LO]), "不动对账的记录");
    // 重启后同一天：不跑
    assert_eq!(update(&r, &p, now + TimeDelta::hours(2)), None);
    assert_eq!(r.calls().len(), 1);
    // 失败：报失败、不记时刻，下一小时再试
    r.respond("flatpak update", Output::fail(1, "x"));
    let later = now + TimeDelta::hours(25);
    let it = upd(&r, &p, later);
    assert_eq!(it.item, "flatpak-update");
    assert!(!it.ok);
    assert_eq!(load_state(&p).unwrap().last_update, Some(now));
    // 对账正拿着锁：跳过，不等
    let g = FLATPAK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(update(&r, &p, later), None);
    drop(g);
}

/// Task 15 复审的要求：`flatpak install` 开始的那一刻，盘上的 flatpak-state.json 里已经有这个 id 的 pending
/// （agent 死在安装中途也不丢）。
#[test]
fn pending_is_on_disk_when_install_starts() {
    struct Peek {
        inner: FakeRunner,
        state: std::path::PathBuf,
        seen: std::sync::Mutex<Vec<FlatpakState>>,
    }
    impl Runner for Peek {
        fn run(&self, cmd: &crate::runner::Cmd) -> anyhow::Result<Output> {
            if cmd.line().starts_with(INSTALL) {
                let st: FlatpakState =
                    serde_json::from_slice(&fs::read(&self.state).expect("装之前盘上没有状态文件"))
                        .unwrap();
                self.seen.lock().unwrap().push(st);
            }
            self.inner.run(cmd)
        }
    }
    let root = tmp_root();
    let p = paths(root.path());
    let r = Peek {
        inner: FakeRunner::new(),
        state: p.var_dir.join(STATE_FILE),
        seen: Default::default(),
    };
    reconcile(&r, &p, Some(&cur(Kind::Full, &[LO, TOOL])), &|| true);
    let seen = r.seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].pending, set(&[LO]));
    assert!(seen[0].managed.is_empty());
    assert_eq!(seen[1].pending, set(&[TOOL]));
    assert_eq!(seen[1].managed, set(&[LO]));
}
