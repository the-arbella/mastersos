use super::*;
use crate::fetch::Fetcher;
use crate::runner::{FakeRunner, Output};
use mastersos_bundle::{DeviceIdent, Seed};
use std::sync::Mutex as StdMutex;
use tokio::sync::watch;

fn t(s: &str) -> DateTime<Utc> {
    s.parse().unwrap()
}

fn e(name: &str, uid: u32, last: Option<&str>) -> HomeEntry {
    HomeEntry {
        name: name.into(),
        uid,
        last_login: last.map(t),
    }
}

fn uids(v: &[HomeEntry]) -> Vec<u32> {
    v.iter().map(|e| e.uid).collect()
}

#[test]
fn only_sso_users_are_candidates() {
    let entries = vec![
        e("alice", 1001, Some("2026-01-01T00:00:00Z")),
        e("guest", 1999, Some("2026-01-01T00:00:00Z")),
        // 锁定应用的账号（计划 9）：家目录是 tmpfs，由它自己的清理收拾，这里从不删
        e("kiosk-nwea", 1900, Some("2026-01-01T00:00:00Z")),
        e("it@school.ac.th", 10000, Some("2026-01-01T00:00:00Z")),
        e("s1@school.ac.th", 10001, Some("2026-01-02T00:00:00Z")),
    ];
    let c = candidates(&entries, &["IT@School.AC.th".into()], &BTreeSet::new());
    assert_eq!(uids(&c), vec![10001]);
}

#[test]
fn active_users_are_never_candidates() {
    let entries = vec![
        e("a@school.ac.th", 10001, Some("2026-01-01T00:00:00Z")),
        e("b@school.ac.th", 10002, Some("2026-01-02T00:00:00Z")),
    ];
    let c = candidates(&entries, &[], &BTreeSet::from([10001]));
    assert_eq!(uids(&c), vec![10002]);
}

#[test]
fn oldest_login_first() {
    let entries = vec![
        e("c@school.ac.th", 10003, Some("2026-03-01T00:00:00Z")),
        e("a@school.ac.th", 10001, Some("2026-01-01T00:00:00Z")),
        e("b@school.ac.th", 10002, Some("2026-02-01T00:00:00Z")),
    ];
    let c = candidates(&entries, &[], &BTreeSet::new());
    assert_eq!(uids(&c), vec![10001, 10002, 10003]);
}

#[test]
fn unseen_users_get_now_not_epoch() {
    let now = t("2026-10-17T00:00:00Z");
    let mut map = BTreeMap::from([
        (10001, t("2026-05-01T00:00:00Z")),
        (42, t("2020-01-01T00:00:00Z")),
    ]);
    let changed = fill_unseen(&mut map, &BTreeSet::from([10001, 10002]), now);
    assert!(changed);
    assert_eq!(map.get(&10002), Some(&now), "first seen: recorded as now");
    assert!(
        !map.contains_key(&42),
        "records of removed home directories are dropped"
    );
    // VM 实测（修复轮 1）：登录叫醒的那一轮可能在 pam_mkhomedir 建出家目录之前跑；刚记下的登录不能因为
    // 「还没有家目录」被删掉（之后又被补记成更晚的时刻）
    let fresh = now - chrono::TimeDelta::hours(1);
    map.insert(43, fresh);
    fill_unseen(&mut map, &BTreeSet::from([10001, 10002]), now);
    assert_eq!(
        map.get(&43),
        Some(&fresh),
        "a record with no home directory but a login within a week is kept"
    );
    let entries: Vec<HomeEntry> = [("new@school.ac.th", 10002), ("old@school.ac.th", 10001)]
        .iter()
        .map(|(n, u)| HomeEntry {
            name: (*n).into(),
            uid: *u,
            last_login: map.get(u).copied(),
        })
        .collect();
    assert_eq!(
        uids(&candidates(&entries, &[], &BTreeSet::new())),
        vec![10001, 10002],
        "users recorded as now sort after those with older records"
    );
    assert!(!fill_unseen(&mut map, &BTreeSet::from([10001, 10002]), now));
}

#[test]
fn record_login_round_trip_0600() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("homes/last-login.json");
    record_login(&p, 10001, t("2026-10-01T00:00:00Z")).unwrap();
    record_login(&p, 10002, t("2026-10-02T00:00:00Z")).unwrap();
    record_login(&p, 10001, t("2026-10-03T00:00:00Z")).unwrap();
    let m = load(&p);
    assert_eq!(m.get(&10001), Some(&t("2026-10-03T00:00:00Z")));
    assert_eq!(m.get(&10002), Some(&t("2026-10-02T00:00:00Z")));
    let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    // 乱码的文件：重新开始，不失败
    std::fs::write(&p, b"not json").unwrap();
    record_login(&p, 7, t("2026-10-04T00:00:00Z")).unwrap();
    assert_eq!(load(&p).len(), 1);
}

#[test]
fn corrupt_or_huge_record_is_kept_as_bad() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("homes/last-login.json");
    record_login(&p, 1, t("2026-10-01T00:00:00Z")).unwrap();
    std::fs::write(&p, b"{garbage").unwrap();
    record_login(&p, 10001, t("2026-10-02T00:00:00Z")).unwrap();
    assert_eq!(
        std::fs::read(d.path().join("homes").join(LAST_LOGIN_BAD)).unwrap(),
        b"{garbage",
        "the corrupt copy is kept"
    );
    assert_eq!(load(&p).len(), 1);
    // 超过上限的也当作坏了
    std::fs::write(&p, vec![b' '; MAX_LAST_LOGIN_BYTES as usize + 1]).unwrap();
    assert!(load(&p).is_empty());
    assert!(!p.exists(), "renamed");
}

#[test]
fn thresholds() {
    let total = 100 * GIB;
    assert!(needs_cleanup(15 * GIB - 1, total));
    assert!(!needs_cleanup(15 * GIB, total));
    // 小盘：10 GiB 的下限更大
    assert!(needs_cleanup(10 * GIB - 1, 20 * GIB));
    assert!(!needs_cleanup(10 * GIB, 20 * GIB));
    // 够了：25% 与 15 GiB 中较大的
    assert!(enough(25 * GIB, total));
    assert!(!enough(25 * GIB - 1, total));
    assert!(
        enough(15 * GIB, 40 * GIB),
        "40 GiB disk: 15 GiB is enough (25% would be only 10 GiB)"
    );
    assert!(!enough(15 * GIB - 1, 40 * GIB));
    // 够了之后一定不再需要清理（小盘也不会每小时再删一个）
    for t in [
        20 * GIB,
        40 * GIB,
        48 * GIB,
        64 * GIB,
        100 * GIB,
        1000 * GIB,
    ] {
        for f in (0..=t).step_by((GIB / 4) as usize) {
            assert!(!(enough(f, t) && needs_cleanup(f, t)), "{t} {f}");
        }
    }
    // 不溢出
    assert!(!needs_cleanup(u64::MAX, u64::MAX));
    assert!(enough(u64::MAX, u64::MAX));
}

// ---------------------------------------------------------------------------
// 一轮清理（假的文件系统）
// ---------------------------------------------------------------------------

/// 假的 `/home`：`space` 依次给出序列里的值（用完后一直给最后一个）；记下 `trash:<uid>` 与 `empty` 的顺序。
struct FakeFs {
    spaces: StdMutex<Vec<(u64, u64)>>,
    homes: Vec<(String, u32)>,
    events: StdMutex<Vec<String>>,
    /// 挪不走的 uid。
    refuse: BTreeSet<u32>,
    /// 挪走了但没收好的 uid（`to_trash` 回 `Ok(false)`）。
    unsealed: BTreeSet<u32>,
    /// `empty_trash` 依次给出的结果（用完后给默认值）。
    empties: StdMutex<Vec<Removal>>,
}

impl FakeFs {
    fn new(spaces: &[(u64, u64)], uids: &[u32]) -> Arc<FakeFs> {
        Self::build(spaces, uids, &[], vec![])
    }
    fn build(
        spaces: &[(u64, u64)],
        uids: &[u32],
        refuse: &[u32],
        empties: Vec<Removal>,
    ) -> Arc<FakeFs> {
        let homes = uids
            .iter()
            .map(|u| {
                let name = USERS
                    .iter()
                    .find(|(x, _)| x == u)
                    .map(|(_, n)| n.to_string())
                    .unwrap_or_else(|| format!("user{u}"));
                (name, *u)
            })
            .collect();
        Arc::new(FakeFs {
            spaces: StdMutex::new(spaces.to_vec()),
            homes,
            events: Default::default(),
            refuse: refuse.iter().copied().collect(),
            unsealed: Default::default(),
            empties: StdMutex::new(empties),
        })
    }
    fn removed(&self) -> Vec<u32> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| e.strip_prefix("trash:")?.parse().ok())
            .collect()
    }
    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

impl HomeFs for FakeFs {
    fn space(&self) -> Result<(u64, u64)> {
        let mut s = self.spaces.lock().unwrap();
        Ok(if s.len() > 1 { s.remove(0) } else { s[0] })
    }
    fn homes(&self) -> Result<Vec<(String, u32)>> {
        Ok(self.homes.clone())
    }
    fn to_trash(&self, _name: &str, uid: u32) -> Result<bool> {
        if self.refuse.contains(&uid) {
            anyhow::bail!("cannot be moved");
        }
        self.events.lock().unwrap().push(format!("trash:{uid}"));
        Ok(!self.unsealed.contains(&uid))
    }
    fn empty_trash(&self) -> Result<Removal> {
        self.events.lock().unwrap().push("empty".into());
        let mut e = self.empties.lock().unwrap();
        Ok(if e.is_empty() {
            Removal::default()
        } else {
            e.remove(0)
        })
    }
}

const LOW: (u64, u64) = (5 * GIB, 100 * GIB);
const PLENTY: (u64, u64) = (30 * GIB, 100 * GIB);
const STILL_LOW: (u64, u64) = (12 * GIB, 100 * GIB);

/// 三个 SSO 账号与一个本机账号、root：名字、登录记录（a 最旧）、管理员名单。
const USERS: &[(u32, &str)] = &[
    (0, "root"),
    (1001, "alice"),
    (10001, "a@school.ac.th"),
    (10002, "b@school.ac.th"),
    (10003, "c@school.ac.th"),
];

const ROOT_ONLY: &str = r#"[{"uid":0,"user":"root","linger":false,"state":"active"}]"#;

fn setup(admins: &[&str]) -> (tempfile::TempDir, SysPaths, Arc<FakeRunner>) {
    setup_with(admins, Output::ok(ROOT_ONLY))
}

fn write_policy(paths: &SysPaths, admins: &[&str], from_bundle: bool) {
    let policy = LoginPolicy {
        methods: vec!["sso".into()],
        allowed_domains: vec![],
        admin_users: admins.iter().map(|a| a.to_string()).collect(),
        locked: false,
        lock_message: None,
        from_bundle,
        kiosk_users: vec![],
        it_account: false,
        it_account_uid: None,
    };
    std::fs::write(
        paths.var_dir.join("login/policy.json"),
        serde_json::to_vec(&policy).unwrap(),
    )
    .unwrap();
}

fn setup_with(admins: &[&str], loginctl: Output) -> (tempfile::TempDir, SysPaths, Arc<FakeRunner>) {
    let d = tempfile::tempdir().unwrap();
    let paths = SysPaths {
        root: d.path().into(),
        var_dir: d.path().join("var"),
        public_dir: d.path().join("pub"),
        state_dir: d.path().join("state"),
    };
    std::fs::create_dir_all(paths.var_dir.join("login")).unwrap();
    write_policy(&paths, admins, true);
    let mut map = BTreeMap::new();
    for (i, (uid, _)) in USERS.iter().enumerate() {
        map.insert(*uid, t(&format!("2026-0{}-01T00:00:00Z", i + 1)));
    }
    save(&last_login_path(&paths), &map).unwrap();
    let r = Arc::new(FakeRunner::new());
    for (uid, name) in USERS {
        r.respond(
            &format!("getent passwd -- {uid}"),
            Output::ok(&format!("{name}:x:{uid}:{uid}::/home/{name}:/bin/bash\n")),
        );
    }
    r.respond("loginctl list-users", loginctl);
    (d, paths, r)
}

/// `user-<uid>.slice` 接下来的 `n` 次都回答 inactive（FakeRunner 没设的命令回退出码 0，会被当成 active）。
fn inactive(r: &FakeRunner, uid: u32, n: usize) {
    for _ in 0..n {
        r.respond(
            &format!("systemctl is-active user-{uid}.slice"),
            Output {
                code: 3,
                stdout: "inactive\n".into(),
                stderr: String::new(),
            },
        );
    }
}

fn cx(runner: Arc<FakeRunner>, paths: SysPaths) -> JobCtx {
    JobCtx {
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
        paths,
        runner,
        identity: None,
        current: watch::channel(None).1,
        reapply: Default::default(),
        fetch_error: watch::channel(None).1,
    }
}

async fn run_job(fs: Arc<dyn HomeFs>, r: Arc<FakeRunner>, paths: SysPaths) -> ItemResult {
    let job = HomeCleanupJob::with_fs(r.clone(), fs);
    assert_eq!(job.name(), "homes");
    assert_eq!(job.every(), Duration::from_secs(3600));
    let mut out = job.run(&cx(r, paths)).await;
    assert_eq!(out.len(), 1);
    out.remove(0)
}

#[tokio::test]
async fn stops_when_enough_space() {
    let (_d, paths, r) = setup(&[]);
    for u in [10001, 10002, 10003] {
        inactive(&r, u, 2);
    }
    let fs = FakeFs::new(&[LOW, PLENTY], &[0, 1001, 10001, 10002, 10003]);
    let res = run_job(fs.clone(), r, paths).await;
    assert_eq!(
        fs.removed(),
        vec![10001],
        "removing the oldest one is enough"
    );
    assert!(res.ok, "{res:?}");
    assert_eq!(res.item, ITEM);
}

/// 复审 I1：先清上一轮留下的回收目录，再把家目录挪进回收目录，然后才删。
#[tokio::test]
async fn trash_first_then_move_then_delete() {
    let (_d, paths, r) = setup(&[]);
    inactive(&r, 10001, 2);
    let fs = FakeFs::new(&[LOW, PLENTY], &[10001]);
    let res = run_job(fs.clone(), r.clone(), paths).await;
    assert!(res.ok, "{res:?}");
    assert_eq!(fs.events(), vec!["empty", "trash:10001", "empty"]);
    // 挪之前又列了一次 loginctl、又看了一次 slice
    let calls = r.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|c| c.starts_with("loginctl list-users"))
            .count(),
        2,
        "{calls:?}"
    );
}

#[tokio::test]
async fn plenty_of_space_touches_nothing() {
    let (_d, paths, r) = setup(&[]);
    let fs = FakeFs::new(&[PLENTY], &[10001]);
    let res = run_job(fs.clone(), r.clone(), paths).await;
    assert!(res.ok);
    assert!(fs.removed().is_empty());
    assert!(
        r.calls().is_empty(),
        "no commands run when there is enough space: {:?}",
        r.calls()
    );
}

#[tokio::test]
async fn admin_and_logged_in_users_are_kept_and_shortage_is_reported() {
    // 10001 是管理员；10002 登录着（loginctl 里有）；10003 没有会话但 slice 还 active（FakeRunner 默认退出码 0）
    let (_d, paths, r) = setup_with(
        &["A@School.ac.th"],
        Output::ok(r#"[{"uid":10002,"user":"b@school.ac.th","linger":false,"state":"active"}]"#),
    );
    let fs = FakeFs::new(&[LOW, STILL_LOW], &[0, 1001, 10001, 10002, 10003]);
    let res = run_job(fs.clone(), r.clone(), paths).await;
    assert!(
        fs.removed().is_empty(),
        "administrators, signed-in users and active slices are not removed"
    );
    assert!(!res.ok, "still low on space must report failure: {res:?}");
}

#[tokio::test]
async fn rechecks_slice_before_delete() {
    let (_d, paths, r) = setup(&[]);
    // 10001：枚举时 inactive，删除前已经 active（有人刚登录）
    inactive(&r, 10001, 1);
    r.respond(
        "systemctl is-active user-10001.slice",
        Output::ok("active\n"),
    );
    inactive(&r, 10002, 2);
    inactive(&r, 10003, 2);
    let fs = FakeFs::new(&[LOW, PLENTY], &[10001, 10002, 10003]);
    let res = run_job(fs.clone(), r, paths).await;
    assert_eq!(
        fs.removed(),
        vec![10002],
        "a home just put in use is skipped; the next one is removed"
    );
    assert!(res.ok, "{res:?}");
}

/// 删除前再列一次 loginctl：这时出现了就跳过。
#[tokio::test]
async fn rechecks_sessions_before_delete() {
    let (_d, paths, r) = setup(&[]);
    r.respond(
        "loginctl list-users",
        Output::ok(r#"[{"uid":10001,"user":"a@school.ac.th"}]"#),
    );
    for u in [10001, 10002] {
        inactive(&r, u, 2);
    }
    let fs = FakeFs::new(&[LOW, PLENTY], &[10001, 10002]);
    run_job(fs.clone(), r, paths).await;
    assert_eq!(fs.removed(), vec![10002]);
}

#[tokio::test]
async fn unknown_slice_state_counts_as_active() {
    let (_d, paths, r) = setup(&[]);
    r.respond(
        "systemctl is-active user-10001.slice",
        Output {
            code: 3,
            stdout: "activating\n".into(),
            stderr: String::new(),
        },
    );
    r.respond(
        "systemctl is-active user-10002.slice",
        Output::fail(1, "Failed to connect to bus"),
    );
    let fs = FakeFs::new(&[LOW, PLENTY], &[10001, 10002]);
    run_job(fs.clone(), r, paths).await;
    assert!(fs.removed().is_empty());
}

#[tokio::test]
async fn loginctl_failure_deletes_nothing() {
    let (_d, paths, r) = setup_with(&[], Output::fail(1, "timeout"));
    for u in [10001, 10002, 10003] {
        inactive(&r, u, 2);
    }
    let fs = FakeFs::new(&[LOW, PLENTY], &[10001, 10002, 10003]);
    let res = run_job(fs.clone(), r, paths).await;
    assert!(fs.removed().is_empty());
    assert!(!res.ok);
}

/// 复审 M8：getent 的第 3 列不是这个 uid、或目录名与用户名不同（复审 M3）：都不删。
#[tokio::test]
async fn mismatched_names_are_never_deleted() {
    let (_d, paths, r) = setup(&[]);
    let r2 = Arc::new(FakeRunner::new());
    r2.respond(
        "getent passwd -- 10001",
        Output::ok("a@school.ac.th:x:10009:10009::/home/a@school.ac.th:/bin/bash\n"),
    );
    r2.respond(
        "getent passwd -- 10002",
        Output::ok("other@school.ac.th:x:10002:10002::/home/other@school.ac.th:/bin/bash\n"),
    );
    r2.respond("loginctl list-users", Output::ok("[]"));
    for u in [10001, 10002] {
        inactive(&r2, u, 2);
    }
    drop(r);
    let fs = FakeFs::new(&[LOW, PLENTY], &[10001, 10002]);
    let res = run_job(fs.clone(), r2, paths).await;
    assert!(fs.removed().is_empty(), "{res:?}");
}

/// 复审 M8：挪不走的计一个失败、接着处理下一个；只删了一部分的回报出来。
#[tokio::test]
async fn failures_continue_and_are_counted() {
    let (_d, paths, r) = setup(&[]);
    for u in [10001, 10002, 10003] {
        inactive(&r, u, 2);
    }
    let partial = Removal {
        removed: 10,
        mounts: 1,
        ..Default::default()
    };
    let fs = FakeFs::build(
        &[LOW, STILL_LOW, PLENTY],
        &[10001, 10002, 10003],
        &[10001],
        vec![Removal::default(), partial],
    );
    let res = run_job(fs.clone(), r, paths).await;
    assert_eq!(fs.removed(), vec![10002, 10003]);
    assert!(!res.ok);
    let d = res.detail.unwrap();
    assert!(d.contains("home directories removed: 2"), "{d}");
    assert!(d.contains("partly removed: 1 (1 mount"), "{d}");
    assert!(d.contains("failed removals: 1"), "{d}");
}

/// 上一轮留下的回收目录删不干净：空间够也回报出来。
#[tokio::test]
async fn leftover_trash_problems_are_reported() {
    let (_d, paths, r) = setup(&[]);
    let fs = FakeFs::build(
        &[PLENTY],
        &[10001],
        &[],
        vec![Removal {
            errors: 2,
            ..Default::default()
        }],
    );
    let res = run_job(fs.clone(), r, paths).await;
    assert!(!res.ok);
    assert!(res.detail.unwrap().contains("still cannot be removed: 2"));
}

#[tokio::test]
async fn report_has_no_names() {
    let (_d, paths, r) = setup(&[]);
    for u in [10001, 10002, 10003] {
        inactive(&r, u, 2);
    }
    let fs = FakeFs::new(
        &[LOW, STILL_LOW, STILL_LOW, PLENTY],
        &[0, 1001, 10001, 10002, 10003],
    );
    let res = run_job(fs.clone(), r, paths).await;
    assert_eq!(fs.removed(), vec![10001, 10002, 10003]);
    let detail = res.detail.unwrap_or_default();
    assert!(detail.contains('3'), "{detail}");
    for (uid, name) in USERS {
        assert!(!detail.contains(name), "detail contains the name: {detail}");
        assert!(
            !detail.contains(&uid.to_string()) || *uid == 0,
            "detail contains the uid: {detail}"
        );
    }
    assert!(!detail.contains("school"), "{detail}");
}

#[tokio::test]
async fn unreadable_policy_deletes_nothing() {
    for garbage in [None, Some(&b"{not json"[..])] {
        let (_d, paths, r) = setup(&[]);
        for u in [10001, 10002, 10003] {
            inactive(&r, u, 2);
        }
        let p = paths.var_dir.join("login/policy.json");
        match garbage {
            None => std::fs::remove_file(&p).unwrap(),
            Some(b) => std::fs::write(&p, b).unwrap(),
        }
        let fs = FakeFs::new(&[LOW, PLENTY], &[10001, 10002, 10003]);
        let res = run_job(fs.clone(), r, paths).await;
        assert!(fs.removed().is_empty());
        assert!(!res.ok);
        assert_eq!(
            res.detail.as_deref(),
            Some("cannot read the administrator list; not cleaning up this round")
        );
    }
}

/// 复审 M2：种子写的默认策略（没有管理员）不算管理员名单：一个都不删。
#[tokio::test]
async fn seed_policy_deletes_nothing() {
    let (_d, paths, r) = setup(&[]);
    write_policy(&paths, &[], false);
    for u in [10001, 10002] {
        inactive(&r, u, 2);
    }
    let fs = FakeFs::new(&[LOW, PLENTY], &[10001, 10002]);
    let res = run_job(fs.clone(), r, paths).await;
    assert!(fs.removed().is_empty());
    assert!(!res.ok);
    assert!(res.detail.unwrap().contains("administrator list unknown"));
}

/// 没有登录记录的 uid：每轮都补记 now（空间够时也补），排在有旧记录的人后面。
#[tokio::test]
async fn unseen_uid_is_backfilled_by_the_job() {
    let (_d, paths, r) = setup(&[]);
    // 空间够的一轮：补记，不跑命令
    let fs = FakeFs::new(&[PLENTY], &[10009, 10001]);
    run_job(fs, r.clone(), paths.clone()).await;
    let m = load(&last_login_path(&paths));
    assert!(
        m.contains_key(&10009),
        "recorded even when there is enough space"
    );
    assert!(
        !m.contains_key(&10002),
        "records of removed home directories are dropped"
    );
    inactive(&r, 10001, 2);
    inactive(&r, 10009, 2);
    r.respond(
        "getent passwd -- 10009",
        Output::ok("new@school.ac.th:x:10009:10009::/home/new@school.ac.th:/bin/bash\n"),
    );
    let fs = FakeFs::build(&[LOW, PLENTY], &[10009, 10001], &[], vec![]);
    // FakeFs 给 10009 起名 user10009；换成 getent 的名字
    let fs = Arc::new(FakeFs {
        homes: vec![
            ("new@school.ac.th".into(), 10009),
            ("a@school.ac.th".into(), 10001),
        ],
        spaces: StdMutex::new(fs.spaces.lock().unwrap().clone()),
        events: Default::default(),
        refuse: Default::default(),
        unsealed: Default::default(),
        empties: Default::default(),
    });
    run_job(fs.clone(), r, paths).await;
    assert_eq!(fs.removed(), vec![10001]);
}

/// 复审 M5：登录记录坏了：改名为 .bad、回报一次（下一轮不再报）。
#[tokio::test]
async fn corrupt_record_is_reported_once() {
    let (_d, paths, r) = setup(&[]);
    std::fs::write(last_login_path(&paths), b"not json").unwrap();
    let job = HomeCleanupJob::with_fs(r.clone(), FakeFs::new(&[PLENTY], &[10001]));
    let c = cx(r, paths.clone());
    let first = job.run(&c).await.remove(0);
    assert!(!first.ok);
    assert!(first.detail.unwrap().contains(LAST_LOGIN_BAD));
    let second = job.run(&c).await.remove(0);
    assert!(second.ok, "{second:?}");
    assert!(paths.var_dir.join("homes").join(LAST_LOGIN_BAD).exists());
}

// ---------------------------------------------------------------------------
// 真的文件系统（回收目录与有界的删除）
// ---------------------------------------------------------------------------

fn me() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// tempdir 里的 `home/`，里面一个属于本进程的 `me@school.ac.th`（带内容）。
fn real_home() -> (tempfile::TempDir, PathBuf, RealHomeFs) {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("home");
    std::fs::create_dir_all(home.join("me@school.ac.th/docs/sub")).unwrap();
    std::fs::write(home.join("me@school.ac.th/docs/sub/f"), b"x").unwrap();
    std::fs::write(home.join("me@school.ac.th/.bashrc"), b"x").unwrap();
    let fs = RealHomeFs { dir: home.clone() };
    (d, home, fs)
}

fn trash_entries(home: &Path) -> Vec<PathBuf> {
    match std::fs::read_dir(home.join(trash::TRASH)) {
        Ok(rd) => rd.map(|e| e.unwrap().path()).collect(),
        Err(_) => vec![],
    }
}

/// 复审 I1：先原子地挪进回收目录（0700），挪的时候一样东西都不删；`/home/<名字>` 立即不在了。
#[test]
fn rename_happens_before_any_deletion() {
    use std::os::unix::fs::PermissionsExt;
    let (_d, home, fs) = real_home();
    assert_eq!(
        fs.homes().unwrap(),
        vec![("me@school.ac.th".to_string(), me())]
    );
    fs.to_trash("me@school.ac.th", me()).unwrap();
    assert!(!home.join("me@school.ac.th").exists());
    let t = home.join(trash::TRASH);
    assert_eq!(
        std::fs::metadata(&t).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let moved = trash_entries(&home);
    assert_eq!(moved.len(), 1);
    assert_eq!(
        std::fs::metadata(&moved[0]).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(
        moved[0].join("docs/sub/f").exists(),
        "nothing removed while moving"
    );
    assert!(
        fs.homes().unwrap().is_empty(),
        "the trash directory is nobody's home directory"
    );
    // 删
    let r = fs.empty_trash().unwrap();
    assert_eq!(r.left(), 0, "{r:?}");
    assert!(trash_entries(&home).is_empty());
}

/// 复审 I1：中途崩溃只留下回收目录里的东西；下一轮开头删掉它，不论空间够不够。
#[test]
fn crash_mid_delete_leaves_only_trash_and_next_round_cleans_it() {
    let (_d, home, fs) = real_home();
    fs.to_trash("me@school.ac.th", me()).unwrap();
    // 「删到一半」：删掉一部分
    let moved = trash_entries(&home).remove(0);
    std::fs::remove_file(moved.join("docs/sub/f")).unwrap();
    let names: Vec<_> = std::fs::read_dir(&home)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        names,
        vec![std::ffi::OsString::from(trash::TRASH)],
        "only the trash directory is left"
    );
    // 下一轮
    let (_d2, paths, r) = setup(&[]);
    let res = cleanup(&fs, r.as_ref(), &paths, Utc::now(), &Default::default());
    assert!(trash_entries(&home).is_empty(), "{res:?}");
}

/// 复审 I2：2000 层深的链也删得干净；显式栈不超过 MAX_DEPTH（同时打开的 fd 有上限）。
#[test]
fn deep_chain_is_removed_with_bounded_depth() {
    use rustix::fs::{mkdirat, openat, Mode, OFlags};
    let (_d, home, fs) = real_home();
    let top = home.join("me@school.ac.th");
    let mut cur = openat(
        rustix::fs::CWD,
        &top,
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .unwrap();
    for _ in 0..2000 {
        mkdirat(&cur, "d", Mode::from_raw_mode(0o755)).unwrap();
        cur = openat(&cur, "d", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap();
    }
    rustix::fs::openat(
        &cur,
        "leaf",
        OFlags::CREATE | OFlags::WRONLY,
        Mode::from_raw_mode(0o644),
    )
    .unwrap();
    drop(cur);
    fs.to_trash("me@school.ac.th", me()).unwrap();
    let r = fs.empty_trash().unwrap();
    assert_eq!(r.left(), 0, "{r:?}");
    // 同时打开的目录（每层一个 fd 加一个读目录的流）不超过 32 层，远低于 1024 的默认软上限
    assert!(r.max_depth <= 32, "{r:?}");
    assert!(r.flattened >= 2000 / 32, "{r:?}");
    assert!(r.removed >= 2001, "{r:?}");
    assert!(trash_entries(&home).is_empty());
}

/// 链接只删链接本身；链接指向的东西不动。顶层的链接不算家目录。
#[test]
fn links_are_never_followed() {
    use std::os::unix::fs::symlink;
    let (d, home, fs) = real_home();
    let outside = d.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("keep"), b"x").unwrap();
    symlink(&outside, home.join("me@school.ac.th/docs/link")).unwrap();
    symlink(&outside, home.join("toplink@school.ac.th")).unwrap();
    assert_eq!(
        fs.homes().unwrap().len(),
        1,
        "a top-level link is not a home directory"
    );
    assert!(fs.to_trash("toplink@school.ac.th", me()).is_err());
    fs.to_trash("me@school.ac.th", me()).unwrap();
    assert_eq!(fs.empty_trash().unwrap().left(), 0);
    assert!(
        outside.join("keep").exists(),
        "the link target is untouched"
    );
    assert!(home.join("toplink@school.ac.th").exists());
}

/// 属主不是这个 uid 的不挪。
#[test]
fn other_owner_is_refused() {
    let (_d, home, fs) = real_home();
    assert!(fs.to_trash("me@school.ac.th", me() + 1).is_err());
    assert!(home.join("me@school.ac.th/docs/sub/f").exists());
}

/// 复审 I2：单个项出错跳过、计数，别的照删；那个目录留在回收目录里。
#[test]
fn errors_are_skipped_and_counted() {
    use std::os::unix::fs::PermissionsExt;
    let (_d, home, fs) = real_home();
    let locked = home.join("me@school.ac.th/locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::write(locked.join("x"), b"x").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    fs.to_trash("me@school.ac.th", me()).unwrap();
    let moved = trash_entries(&home).remove(0);
    let r = fs.empty_trash().unwrap();
    let root = rustix::process::geteuid().is_root();
    if !root {
        assert!(r.errors >= 1, "{r:?}");
        assert!(!moved.join("docs").exists(), "the others are still removed");
        assert!(!moved.join(".bashrc").exists());
        std::fs::set_permissions(moved.join("locked"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        // 下一轮删干净
        assert_eq!(fs.empty_trash().unwrap().left(), 0);
    }
    assert!(trash_entries(&home).is_empty());
}

/// 复审 M1：跨了挂载（这里假装 `/home` 在别的设备上）的目录整棵留着、不进去删，计为挂载。
#[test]
fn other_mounts_are_left_alone() {
    let (_d, home, fs) = real_home();
    fs.to_trash("me@school.ac.th", me()).unwrap();
    let h = safefs::open_abs_dir(&home, false).unwrap();
    let t = trash::open_trash(&h, false).unwrap().unwrap();
    let r = trash::empty_trash(&t, &trash::Boundary::foreign_for_test(&h));
    assert_eq!(r.mounts, 1, "{r:?}");
    assert_eq!(r.removed, 0);
    let moved = trash_entries(&home).remove(0);
    assert!(moved.join("docs/sub/f").exists());
}

/// 回收目录不可信（不是 0700、是链接）：拒绝，什么都不动。
#[test]
fn untrusted_trash_is_refused() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let (d, home, fs) = real_home();
    let t = home.join(trash::TRASH);
    std::fs::create_dir(&t).unwrap();
    std::fs::set_permissions(&t, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(t.join("x"), b"x").unwrap();
    assert!(fs.empty_trash().is_err());
    assert!(fs.to_trash("me@school.ac.th", me()).is_err());
    assert!(t.join("x").exists());
    assert!(home.join("me@school.ac.th").exists());
    std::fs::remove_dir_all(&t).unwrap();
    symlink(d.path(), &t).unwrap();
    assert!(fs.empty_trash().is_err());
    assert!(fs.to_trash("me@school.ac.th", me()).is_err());
    assert!(home.join("me@school.ac.th").exists());
}

// ---------------------------------------------------------------------------
// 修复轮 2（复审 N1–N3）
// ---------------------------------------------------------------------------

/// 复审 N1：登录叫醒之后、会话出现之前（loginctl 里没有、slice inactive），刚登录的人不是候选——不论是已经记进
/// 登录记录（15 分钟内），还是记号还在登录队列里没被取走。
#[tokio::test]
async fn login_before_session_appears_is_never_a_candidate() {
    let (_d, paths, r) = setup(&[]);
    // 10001 最旧，但一分钟前刚登录（记录已写进去）；会话还没出现
    record_login(
        &last_login_path(&paths),
        10001,
        Utc::now() - chrono::TimeDelta::minutes(1),
    )
    .unwrap();
    // 10002 次旧：记号还在登录队列里（agent 还没取走）
    let q = paths.root.join("run/mastersos/login-queue");
    std::fs::create_dir_all(&q).unwrap();
    std::fs::write(q.join("10002"), b"").unwrap();
    for u in [10001, 10002, 10003] {
        inactive(&r, u, 2);
    }
    let fs = FakeFs::new(&[LOW, PLENTY], &[10001, 10002, 10003]);
    let res = run_job(fs.clone(), r, paths).await;
    assert_eq!(fs.removed(), vec![10003], "{res:?}");
}

/// 复审 N1：候选列出之后才登录的（挪走之前的最后一次核对时记录已在 15 分钟内）也跳过。
#[tokio::test]
async fn login_during_the_round_is_skipped_at_the_recheck() {
    struct LoginsDuringRound {
        inner: Arc<FakeFs>,
        path: PathBuf,
    }
    impl HomeFs for LoginsDuringRound {
        fn space(&self) -> Result<(u64, u64)> {
            // 读完登录记录、看空间的时候（候选还没定、记录已经读过），10001 登录了
            record_login(&self.path, 10001, Utc::now()).unwrap();
            self.inner.space()
        }
        fn homes(&self) -> Result<Vec<(String, u32)>> {
            self.inner.homes()
        }
        fn to_trash(&self, name: &str, uid: u32) -> Result<bool> {
            self.inner.to_trash(name, uid)
        }
        fn empty_trash(&self) -> Result<Removal> {
            self.inner.empty_trash()
        }
    }
    let (_d, paths, r) = setup(&[]);
    for u in [10001, 10002] {
        inactive(&r, u, 2);
    }
    let inner = FakeFs::new(&[LOW, PLENTY], &[10001, 10002]);
    let fs = Arc::new(LoginsDuringRound {
        inner: inner.clone(),
        path: last_login_path(&paths),
    });
    run_job(fs, r, paths).await;
    assert_eq!(inner.removed(), vec![10002]);
}

/// 复审 N1 附注：登录记录不往回拨。
#[test]
fn record_login_never_goes_back() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("homes/last-login.json");
    record_login(&p, 7, t("2026-10-10T00:00:00Z")).unwrap();
    record_login(&p, 7, t("2026-01-01T00:00:00Z")).unwrap();
    assert_eq!(load(&p).get(&7), Some(&t("2026-10-10T00:00:00Z")));
}

/// 复审 N2：上一轮留下、删不掉的那一处，不算到之后每个家目录头上。
#[tokio::test]
async fn stale_leftover_is_not_recounted_per_home() {
    let (_d, paths, r) = setup(&[]);
    for u in [10001, 10002] {
        inactive(&r, u, 2);
    }
    let stale = Removal {
        mounts: 1,
        ..Default::default()
    };
    let fs = FakeFs::build(
        &[LOW, STILL_LOW, PLENTY],
        &[10001, 10002],
        &[],
        vec![stale, stale, stale],
    );
    let res = run_job(fs.clone(), r, paths).await;
    assert_eq!(fs.removed(), vec![10001, 10002]);
    let d = res.detail.unwrap();
    assert!(!d.contains("partly removed"), "{d}");
    assert!(d.contains("still cannot be removed: 1"), "{d}");
}

/// 复审 N3：挪走了但没收好：照样删、算空间、看够不够（不去动下一个人），记一个错误。
#[tokio::test]
async fn moved_but_unsealed_still_counts_and_stops() {
    let (_d, paths, r) = setup(&[]);
    for u in [10001, 10002] {
        inactive(&r, u, 2);
    }
    let fs = Arc::new(FakeFs {
        unsealed: BTreeSet::from([10001]),
        ..Arc::into_inner(FakeFs::new(&[LOW, PLENTY], &[10001, 10002])).unwrap()
    });
    let res = run_job(fs.clone(), r, paths).await;
    assert_eq!(
        fs.removed(),
        vec![10001],
        "stops once there is enough; the next one is untouched"
    );
    assert_eq!(fs.events(), vec!["empty", "trash:10001", "empty"]);
    let d = res.detail.unwrap();
    assert!(d.contains("home directories removed: 1"), "{d}");
    assert!(d.contains("failed removals: 1"), "{d}");
}

/// 复审 N1：取走登录队列的那一步返回时，登录记录已经在盘上（主循环之后才叫醒后台任务）。
#[test]
fn drain_and_record_writes_before_returning() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let q = d.path().join("queue");
    std::fs::create_dir(&q).unwrap();
    std::fs::set_permissions(&q, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(q.join("10001"), b"").unwrap();
    let p = d.path().join("var/homes/last-login.json");
    std::fs::create_dir_all(d.path().join("var")).unwrap();
    let now = t("2026-10-17T00:00:00Z");
    assert_eq!(drain_and_record(&q, &p, now), vec![10001]);
    assert_eq!(load(&p).get(&10001), Some(&now));
    assert!(std::fs::read_dir(&q).unwrap().next().is_none());
}

fn queue_with(d: &Path, uids: &[u32]) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let q = d.join("run/mastersos/login-queue");
    std::fs::create_dir_all(&q).unwrap();
    std::fs::set_permissions(&q, std::fs::Permissions::from_mode(0o700)).unwrap();
    for u in uids {
        std::fs::write(q.join(u.to_string()), b"").unwrap();
    }
    q
}

/// 复审 R1：记录写进去的时候记号还在（清理那一轮先看队列再看记录：两处之一一定看得到刚登录的人）；写完才删记号。
#[test]
fn record_is_written_before_the_queue_marker_goes() {
    let (_d, paths, _r) = setup(&[]);
    let q = queue_with(&paths.root, &[10001]);
    let p = last_login_path(&paths);
    let now = Utc::now();
    let uids = crate::login_queue::drain_with(&q, |uids| {
        assert_eq!(uids, &[10001]);
        assert!(
            queued(&paths).unwrap().contains(&10001),
            "the marker is still there while the record is written"
        );
        record_logins(&p, uids, now).unwrap();
        assert!(
            queued(&paths).unwrap().contains(&10001),
            "after the record is written and before the marker is removed: both are visible"
        );
        true
    });
    assert_eq!(uids, vec![10001]);
    assert!(
        queued(&paths).unwrap().is_empty(),
        "the marker is removed after writing"
    );
    assert_eq!(load(&p).get(&10001), Some(&now));
}

/// 复审 R1：记录写不进去时队列里的记号留着（这个人仍算正在用），uid 照样交给登录脚本。
#[test]
fn failed_record_keeps_the_queue_marker() {
    let (_d, paths, _r) = setup(&[]);
    let q = queue_with(&paths.root, &[10001]);
    // homes/ 是个普通文件：记录写不进去
    let bad_var = paths.root.join("badvar");
    std::fs::create_dir_all(&bad_var).unwrap();
    std::fs::write(bad_var.join("homes"), b"x").unwrap();
    let p = bad_var.join("homes/last-login.json");
    assert_eq!(drain_and_record(&q, &p, Utc::now()), vec![10001]);
    assert!(
        queued(&paths).unwrap().contains(&10001),
        "the marker is kept"
    );
    // 第二次（例如下次叫醒）写得进去：这回删掉
    let good = last_login_path(&paths);
    assert_eq!(drain_and_record(&q, &good, Utc::now()), vec![10001]);
    assert!(queued(&paths).unwrap().is_empty());
}
