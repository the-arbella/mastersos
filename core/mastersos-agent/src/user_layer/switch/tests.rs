use super::*;
use crate::apply::{ApplyContext, Phase};
use crate::runner::FakeRunner;
use crate::system::tests::{paths, test_ident, test_seed, tmp_root};
use crate::system::{Env, SysState};
use crate::user_layer::render::{read_index, Index, DCONF_DB_DIR};
use crate::user_layer::{config_dir_name, read_active, FACTS_DIR};
use mastersos_bundle::testutil::spec_example_v3;
use mastersos_bundle::{select, Manifest, Seed};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

const ADMIN: &str = "it@school.ac.th";
const STUDENT: &str = "s1@school.ac.th";
const LOCAL_UID: u32 = 1500;

/// A system root (with the exec-block stub and targets) where the `user-layer` step rendered the spec example (Group
/// `default`: `teacher`, `primary` and neutral) and, nobody being signed in, switched neutral in; with a stand-in
/// compiled database for each config (the step's `dconf update` is a fake here), neutral's switched in again.
pub(crate) fn rendered() -> (tempfile::TempDir, SysPaths, Index) {
    let root = tmp_root();
    crate::system::exec_block::tests::put_image(root.path());
    let m = Manifest::parse(&spec_example_v3()).unwrap();
    let p = render_with(root.path(), &m);
    let index = read_index(&p.var_dir).unwrap();
    for d in index
        .configs
        .values()
        .map(|r| r.dir.clone())
        .chain([NEUTRAL_DIR.to_string()])
    {
        let db = render::compiled_db(&p.root, &p.var_dir, &d);
        fs::write(&db, format!("db of {d}")).unwrap();
        fs::set_permissions(&db, fs::Permissions::from_mode(0o600)).unwrap();
    }
    switch_to(&p.root, &p.public_dir, &p.var_dir, &index.neutral, None).unwrap();
    (root, p, index)
}

/// Runs the `user-layer` step with the settings `m` on the Device of Group `default`.
fn render_with(root: &Path, m: &Manifest) -> SysPaths {
    let ident = test_ident();
    let sel = select(m, &ident, None);
    let bundle = tempfile::tempdir().unwrap();
    let flag = AtomicBool::new(false);
    let ctx = ApplyContext {
        seed: &test_seed(),
        school: &m.school,
        group: sel.group,
        config: &sel.config,
        lock: None,
        bundle_dir: bundle.path(),
        phase: Phase::Full,
        superseded: &flag,
        quiet: &AtomicBool::new(false),
        device: None,
        ident: &ident,
        manifest: Some(m),
    };
    let p = paths(root);
    let r = render::tests::CompileRunner::default();
    let mut sys = SysState::default();
    let mut env = Env {
        paths: &p,
        runner: &r,
        sys: &mut sys,
    };
    let out = (render::step().run)(&ctx, &mut env);
    assert!(out.iter().all(|i| i.ok), "{out:?}");
    p
}

pub(crate) fn policy() -> LoginPolicy {
    let mut p = login::policy_from_seed(
        &Seed::parse("server_url = \"https://m.school.ac.th\"\ntrust = []\n").unwrap(),
    );
    p.admin_users = vec![ADMIN.into()];
    p.user_layer = true;
    p
}

fn dir_of(id: &str) -> String {
    config_dir_name(id)
}

fn managed(p: &SysPaths) -> PathBuf {
    p.root
        .join(chrome_policy::POLICY_DIR)
        .join(chrome_policy::POLICY_FILE)
}

fn chrome_of(p: &SysPaths, d: &str) -> PathBuf {
    p.var_dir.join(STATE_SUB).join(d).join(CHROME_FILE)
}

fn session_db(p: &SysPaths) -> PathBuf {
    p.root.join(DCONF_DB_DIR).join(SESSION_DB)
}

fn link(p: &SysPaths) -> Option<String> {
    fs::read_link(p.public_dir.join(SESSION_LINK))
        .ok()
        .map(|t| t.to_string_lossy().into_owned())
}

fn mode(path: PathBuf) -> u32 {
    fs::metadata(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .permissions()
        .mode()
        & 0o7777
}

fn rendered_of(index: &Index, id: &str) -> Rendered {
    index.configs[id].clone()
}

/// What a session that got `d` sees through the switched files.
pub(crate) fn assert_switched_to(p: &SysPaths, d: &str) {
    assert_eq!(
        fs::read(managed(p)).unwrap(),
        fs::read(chrome_of(p, d)).unwrap(),
        "Chrome policy of {d}"
    );
    assert_eq!(
        fs::read_to_string(session_db(p)).unwrap(),
        format!("db of {d}")
    );
    assert_eq!(mode(session_db(p)), 0o644);
    assert_eq!(
        fs::read_to_string(p.root.join("etc/dconf/profile/user")).unwrap(),
        "user-db:user\nsystem-db:mastersos-session\nsystem-db:mastersos\n"
    );
    assert_eq!(link(p).as_deref(), Some(format!("user-layer/{d}").as_str()));
    assert_eq!(mode(p.public_dir.join("user-layer").join(d)), 0o755);
    // The session mode the image reads is reached through the link; neutral is nobody's session
    assert!(p.public_dir.join("session/session-mode").is_file());
    if d == NEUTRAL_DIR {
        assert_eq!(session_uid(p), None);
    }
    // No temporary file or staging copy is left behind
    assert!(!p.root.join(DCONF_DB_DIR).join(SESSION_DB_TMP).exists());
    assert!(!p.public_dir.join(SESSION_LINK_TMP).exists());
    assert!(!p
        .root
        .join(POLICIES_DIR)
        .join(STAGING_SUB)
        .join(format!("{d}.json"))
        .exists());
}

/// The uid published next to the session's mode (R23).
pub(crate) fn session_uid(p: &SysPaths) -> Option<String> {
    fs::read_to_string(p.public_dir.join("session/uid")).ok()
}

fn facts_file(p: &SysPaths, user: &str, body: &str) -> PathBuf {
    let dir = p.root.join(FACTS_DIR);
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let f = dir.join(format!("{user}.json"));
    fs::write(&f, body).unwrap();
    f
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A teacher's facts, in the shape the broker's patch 0007 writes.
fn teacher_facts(user: &str) -> String {
    format!(
        r#"{{"version":1,"user":"{user}","granted_at":{},"facts":{{"sub":"s-1","org":"0193a0c2-0000-7000-8000-0000000000aa","org_role":"member","org_nodes":[],"classes":[{{"id":"0193a0c2-0000-7000-8000-0000000000c1","role":"teacher"}}],"age_band":"18+"}}}}"#,
        now_secs()
    )
}

fn open(p: &SysPaths, pol: &LoginPolicy, user: &str, uid: u32) -> OpenOutcome {
    on_open(&p.root, p, pol, user, uid)
}

fn switched(user_config: &str, reason: bool, out: &OpenOutcome) {
    match out {
        OpenOutcome::Switched {
            user_config: got,
            fallback_reason,
            ..
        } => {
            assert_eq!(got, user_config, "{out:?}");
            assert_eq!(fallback_reason.is_some(), reason, "{out:?}");
        }
        other => panic!("not switched: {other:?}"),
    }
}

/// All files of the tree under `dir` (paths relative to it), symlinks included.
fn tree(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        for e in fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            let path = e.path();
            out.push(path.strip_prefix(dir).unwrap().display().to_string());
            if e.file_type().unwrap().is_dir() {
                todo.push(path);
            }
        }
    }
    out.sort();
    out
}

#[test]
fn switch_renames_all_three_in_order() {
    let (_root, p, index) = rendered();
    let teacher = rendered_of(&index, "teacher");
    let primary = rendered_of(&index, "primary");
    switch_to(&p.root, &p.public_dir, &p.var_dir, &index.neutral, None).unwrap();
    assert_switched_to(&p, NEUTRAL_DIR);
    switch_to(
        &p.root,
        &p.public_dir,
        &p.var_dir,
        &teacher,
        Some(LOCAL_UID),
    )
    .unwrap();
    assert_switched_to(&p, &teacher.dir);
    assert_eq!(session_uid(&p).as_deref(), Some("1500\n"));
    assert_eq!(mode(p.public_dir.join("session/uid")), 0o644);
    // A neutral switch never leaves a uid there, even when one is passed
    switch_to(
        &p.root,
        &p.public_dir,
        &p.var_dir,
        &index.neutral,
        Some(LOCAL_UID),
    )
    .unwrap();
    assert_switched_to(&p, NEUTRAL_DIR);
    switch_to(
        &p.root,
        &p.public_dir,
        &p.var_dir,
        &teacher,
        Some(LOCAL_UID),
    )
    .unwrap();
    // Moving on closes the previous config's directory again; neutral stays open
    switch_to(
        &p.root,
        &p.public_dir,
        &p.var_dir,
        &primary,
        Some(LOCAL_UID),
    )
    .unwrap();
    assert_switched_to(&p, &primary.dir);
    assert_eq!(
        mode(p.public_dir.join("user-layer").join(&teacher.dir)),
        0o700
    );
    switch_to(&p.root, &p.public_dir, &p.var_dir, &index.neutral, None).unwrap();
    assert_eq!(
        mode(p.public_dir.join("user-layer").join(&primary.dir)),
        0o700
    );
    assert_eq!(
        mode(p.public_dir.join("user-layer").join(NEUTRAL_DIR)),
        0o755
    );

    // Order: Chrome policy, then dconf, then the link. Without teacher's database only the Chrome move happens.
    fs::remove_file(render::compiled_db(&p.root, &p.var_dir, &teacher.dir)).unwrap();
    let e = switch_to(
        &p.root,
        &p.public_dir,
        &p.var_dir,
        &teacher,
        Some(LOCAL_UID),
    )
    .unwrap_err();
    assert!(format!("{e:#}").contains("dconf"), "{e:#}");
    assert_eq!(
        fs::read(managed(&p)).unwrap(),
        fs::read(chrome_of(&p, &teacher.dir)).unwrap()
    );
    assert_eq!(fs::read_to_string(session_db(&p)).unwrap(), "db of neutral");
    assert_eq!(link(&p).as_deref(), Some("user-layer/neutral"));
    // Without primary's Chrome policy nothing moves at all
    let before = fs::read(managed(&p)).unwrap();
    fs::remove_file(chrome_of(&p, &primary.dir)).unwrap();
    let e = switch_to(
        &p.root,
        &p.public_dir,
        &p.var_dir,
        &primary,
        Some(LOCAL_UID),
    )
    .unwrap_err();
    assert!(format!("{e:#}").contains("Chrome"), "{e:#}");
    assert_eq!(fs::read(managed(&p)).unwrap(), before);
    assert_eq!(fs::read_to_string(session_db(&p)).unwrap(), "db of neutral");
    assert_eq!(link(&p).as_deref(), Some("user-layer/neutral"));
    // A name that is not a config directory is refused before anything is touched
    let bad = Rendered {
        dir: "../etc".into(),
        ..index.neutral.clone()
    };
    assert!(switch_to(&p.root, &p.public_dir, &p.var_dir, &bad, None).is_err());
    assert_eq!(fs::read(managed(&p)).unwrap(), before);
    // `switch_to` takes no runner: the switch spawns no command by construction.
}

#[test]
fn admin_rule_wins_for_itadmin() {
    let (_root, p, index) = rendered();
    let mut pol = policy();
    pol.it_account = true;
    pol.it_account_uid = Some(LOCAL_UID);
    let out = open(&p, &pol, IT_ACCOUNT_USER, LOCAL_UID);
    switched("teacher", false, &out);
    assert_switched_to(&p, &dir_of("teacher"));
    assert_eq!(session_uid(&p).as_deref(), Some("1500\n"));
    let a = read_active(&p.root).unwrap();
    assert_eq!(a.uid, LOCAL_UID);
    assert_eq!(a.user, IT_ACCOUNT_USER);
    assert_eq!(a.user_config, "teacher");
    assert_eq!(a.dir, dir_of("teacher"));
    assert_eq!(a.caps, index.configs["teacher"].caps);
    assert_eq!(a.state, ActiveState::Open);
    assert!(a.reason.is_none());
    assert!(!a.seen);
    assert!(a.opened_at + 60 > now_secs());
    assert_eq!(mode(p.root.join(RUN_DIR).join(ACTIVE_FILE)), 0o600);
    assert_eq!(mode(p.root.join(RUN_DIR)), 0o700);
    if let OpenOutcome::Switched { home, .. } = out {
        assert_eq!(home, index.configs["teacher"].home);
    }
}

#[test]
fn itadmin_of_another_uid_is_a_plain_local_account() {
    let (_root, p, _) = rendered();
    let mut pol = policy();
    pol.it_account = true;
    pol.it_account_uid = Some(LOCAL_UID);
    switched(
        "primary",
        false,
        &open(&p, &pol, IT_ACCOUNT_USER, LOCAL_UID + 1),
    );
}

#[test]
fn device_facts_classify_and_admin() {
    let mut pol = policy();
    pol.it_account = true;
    pol.it_account_uid = Some(LOCAL_UID);
    let f = |pol: &LoginPolicy, user: &'static str, uid: u32| {
        let d = device_facts(pol, user, uid, "default");
        (d.kind, d.admin)
    };
    assert_eq!(f(&pol, ADMIN, 20000), (Kind::Sso, true));
    assert_eq!(f(&pol, "IT@School.ac.th", 20000), (Kind::Sso, true));
    assert_eq!(f(&pol, STUDENT, 20000), (Kind::Sso, false));
    assert_eq!(f(&pol, IT_ACCOUNT_USER, LOCAL_UID), (Kind::Local, true));
    assert_eq!(
        f(&pol, IT_ACCOUNT_USER, LOCAL_UID + 1),
        (Kind::Local, false)
    );
    assert_eq!(f(&pol, "bob", 1600), (Kind::Local, false));
    assert_eq!(f(&pol, "guest", 1999), (Kind::Guest, false));
    pol.local_users_admin = true;
    assert_eq!(f(&pol, "bob", 1600), (Kind::Local, true));
    // Local administrators do not make school accounts or the guest administrators
    assert_eq!(f(&pol, STUDENT, 20000), (Kind::Sso, false));
    assert_eq!(f(&pol, "guest", 1999), (Kind::Guest, false));
    let d = device_facts(&pol, "bob", 1600, "default");
    assert_eq!((d.user, d.device_group), ("bob", "default"));
}

#[test]
fn sso_without_facts_gets_fallback_with_reason() {
    let (_root, p, _) = rendered();
    let mut pol = policy();
    pol.mastersos_claims = true;
    let out = open(&p, &pol, STUDENT, 20000);
    switched("primary", true, &out);
    assert_switched_to(&p, &dir_of("primary"));
    let a = read_active(&p.root).unwrap();
    assert!(a.reason.unwrap().contains("no facts"));
}

/// Owner ruling (design §5): missing facts only disable the fact conditions; the admin rule still applies.
#[test]
fn sso_admin_without_facts_gets_the_admin_rule() {
    let (_root, p, _) = rendered();
    let mut pol = policy();
    pol.mastersos_claims = true;
    switched("teacher", false, &open(&p, &pol, ADMIN, 20000));
    assert!(read_active(&p.root).unwrap().reason.is_none());
}

#[test]
fn sso_with_facts_matches_fact_rules_and_consumes_them() {
    let (_root, p, _) = rendered();
    let mut pol = policy();
    pol.mastersos_claims = true;
    let f = facts_file(&p, STUDENT, &teacher_facts(STUDENT));
    switched("teacher", false, &open(&p, &pol, STUDENT, 20000));
    assert!(!f.exists());
}

#[test]
fn stale_or_error_facts_give_the_fallback_with_reason() {
    let (_root, p, _) = rendered();
    let mut pol = policy();
    pol.mastersos_claims = true;
    let old = teacher_facts(STUDENT).replace(
        &format!("\"granted_at\":{}", now_secs()),
        &format!("\"granted_at\":{}", now_secs() - 600),
    );
    for body in [
        old,
        format!(
            r#"{{"version":1,"user":"{STUDENT}","granted_at":{},"error":"userinfo failed"}}"#,
            now_secs()
        ),
    ] {
        fs::remove_file(p.root.join(RUN_DIR).join(ACTIVE_FILE)).ok();
        let f = facts_file(&p, STUDENT, &body);
        switched("primary", true, &open(&p, &pol, STUDENT, 20000));
        assert!(!f.exists());
    }
}

#[test]
fn plain_oidc_never_reads_facts() {
    let (_root, p, _) = rendered();
    let pol = policy();
    assert!(!pol.mastersos_claims);
    let body = teacher_facts(STUDENT);
    let f = facts_file(&p, STUDENT, &body);
    // The rules see no facts (the fact rule does not match) and there is no fallback reason
    switched("primary", false, &open(&p, &pol, STUDENT, 20000));
    assert_eq!(fs::read_to_string(&f).unwrap(), body);
}

#[test]
fn broken_config_dir_falls_back() {
    let (_root, p, _) = rendered();
    fs::remove_file(chrome_of(&p, &dir_of("teacher"))).unwrap();
    let out = open(&p, &policy(), ADMIN, 20000);
    switched("primary", true, &out);
    assert_switched_to(&p, &dir_of("primary"));
    let a = read_active(&p.root).unwrap();
    assert_eq!(a.user_config, "primary");
    assert!(a.reason.unwrap().contains("teacher"));
}

#[test]
fn broken_fallback_refuses() {
    let (_root, p, _) = rendered();
    // A login before left the teacher config in place
    switch_to(
        &p.root,
        &p.public_dir,
        &p.var_dir,
        &read_index(&p.var_dir).unwrap().configs["teacher"],
        Some(2000),
    )
    .unwrap();
    fs::remove_file(render::compiled_db(&p.root, &p.var_dir, &dir_of("primary"))).unwrap();
    assert_eq!(open(&p, &policy(), STUDENT, 20000), OpenOutcome::Refused);
    assert!(read_active(&p.root).is_none());
    // R12: back to neutral, never the half-switched or the previous config
    assert_switched_to(&p, NEUTRAL_DIR);
    // The admin's chosen config fails too, then the fallback: refused as well
    fs::remove_file(chrome_of(&p, &dir_of("teacher"))).unwrap();
    assert_eq!(open(&p, &policy(), ADMIN, 20000), OpenOutcome::Refused);
    assert_switched_to(&p, NEUTRAL_DIR);
}

#[test]
fn missing_rules_refuse() {
    let (_root, p, _) = rendered();
    fs::remove_file(p.var_dir.join(STATE_SUB).join(render::INDEX_FILE)).unwrap();
    assert_eq!(open(&p, &policy(), STUDENT, 20000), OpenOutcome::Refused);
    assert!(read_active(&p.root).is_none());
    assert_eq!(link(&p).as_deref(), Some("user-layer/neutral"));
}

#[test]
fn other_uid_active_refuses() {
    let (_root, p, index) = rendered();
    let other = Active {
        uid: 2000,
        user: "bob".into(),
        user_config: "teacher".into(),
        dir: dir_of("teacher"),
        caps: index.configs["teacher"].caps.clone(),
        state: ActiveState::Open,
        reason: None,
        opened_at: 1,
        seen: true,
        held: false,
    };
    write_active(&p.root, &other).unwrap();
    assert_eq!(open(&p, &policy(), STUDENT, 20000), OpenOutcome::Refused);
    // Nothing of the other session was touched
    assert_eq!(read_active(&p.root).unwrap(), other);
    assert_switched_to(&p, NEUTRAL_DIR);
    // The same person again (a second session while theirs is open) keeps the first session's config: nothing is
    // resolved or switched again under the first session
    assert_eq!(
        open(&p, &policy(), "bob", 2000),
        OpenOutcome::Switched {
            user_config: "teacher".into(),
            fallback_reason: None,
            home: index.configs["teacher"].home,
        }
    );
    // ... and restarts the grace of the agent's watch
    let again = read_active(&p.root).unwrap();
    assert!(again.opened_at > 1, "{again:?}");
    assert_eq!(
        again,
        Active {
            opened_at: again.opened_at,
            seen: false,
            held: false,
            ..other.clone()
        }
    );
    assert_switched_to(&p, NEUTRAL_DIR);
    // A session being closed refuses every uid, its own too
    let mut closing = read_active(&p.root).unwrap();
    closing.state = ActiveState::Closing;
    write_active(&p.root, &closing).unwrap();
    assert_eq!(open(&p, &policy(), "bob", 2000), OpenOutcome::Refused);
    assert_eq!(open(&p, &policy(), STUDENT, 20000), OpenOutcome::Refused);
    assert_eq!(read_active(&p.root).unwrap(), closing);
    // An unreadable marker refuses too
    fs::write(p.root.join(RUN_DIR).join(ACTIVE_FILE), "{").unwrap();
    assert_eq!(open(&p, &policy(), STUDENT, 20000), OpenOutcome::Refused);
}

#[test]
fn format2_policy_is_not_user_layer() {
    let (root, p, _) = rendered();
    let mut pol = policy();
    pol.user_layer = false;
    pol.mastersos_claims = true;
    let f = facts_file(&p, STUDENT, &teacher_facts(STUDENT));
    let before = tree(root.path());
    assert_eq!(open(&p, &pol, STUDENT, 20000), OpenOutcome::NotUserLayer);
    assert_eq!(tree(root.path()), before);
    assert!(f.exists());
}

#[test]
fn close_marks_closing_and_signals() {
    let (_root, p, _) = rendered();
    switched("primary", false, &open(&p, &policy(), STUDENT, 20000));
    let r = FakeRunner::new();
    on_close(&p.root, 20000, &r);
    let a = read_active(&p.root).unwrap();
    assert_eq!(a.state, ActiveState::Closing);
    assert_eq!(a.user_config, "primary");
    assert_eq!(mode(p.root.join(RUN_DIR).join(ACTIVE_FILE)), 0o600);
    assert_eq!(
        r.calls(),
        ["systemctl --no-ask-password kill -s USR1 --kill-whom=main mastersos-agent.service"]
    );
    // Another uid's close leaves the marker alone (and still only wakes the agent)
    let mut open_again = a.clone();
    open_again.state = ActiveState::Open;
    write_active(&p.root, &open_again).unwrap();
    let r = FakeRunner::new();
    on_close(&p.root, 20001, &r);
    assert_eq!(read_active(&p.root).unwrap(), open_again);
    assert_eq!(r.calls().len(), 1);
    // No marker: nothing to mark, never a failure
    fs::remove_file(p.root.join(RUN_DIR).join(ACTIVE_FILE)).unwrap();
    on_close(&p.root, 20000, &FakeRunner::new());
    assert!(read_active(&p.root).is_none());
}

#[test]
fn guest_resolves_with_kind_guest() {
    let (_root, p, _) = rendered();
    let mut pol = policy();
    pol.local_users_admin = true;
    pol.mastersos_claims = true;
    let d = device_facts(&pol, "guest", 1999, "default");
    assert_eq!((d.kind, d.admin), (Kind::Guest, false));
    // The guest gets no admin rule even where local accounts are administrators, and no facts are asked for
    switched("primary", false, &open(&p, &pol, "guest", 1999));
    let a = read_active(&p.root).unwrap();
    assert_eq!((a.uid, a.user.as_str()), (1999, "guest"));
    assert_eq!(session_uid(&p).as_deref(), Some("1999\n"));
}

#[test]
fn opened_at_is_the_login_time() {
    let (_root, p, _) = rendered();
    let at = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    on_open_at(&p.root, &p, &policy(), STUDENT, 20000, at);
    assert_eq!(read_active(&p.root).unwrap().opened_at, 1_800_000_000);
}

/// A re-login of the same person while their marker is open (their first session may have vanished without a
/// close_session) restarts the watch's grace: `opened_at` is the new login and `seen` is cleared, so the agent does not
/// revert the new login before pam_systemd registers it (R9).
#[test]
fn same_person_again_restarts_the_grace() {
    let (_root, p, _) = rendered();
    let t0 = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    on_open_at(&p.root, &p, &policy(), STUDENT, 20000, t0);
    let mut first = read_active(&p.root).unwrap();
    first.seen = true;
    write_active(&p.root, &first).unwrap();
    let later = t0 + Duration::from_secs(600);
    switched(
        &first.user_config,
        first.reason.is_some(),
        &on_open_at(&p.root, &p, &policy(), STUDENT, 20000, later),
    );
    let again = read_active(&p.root).unwrap();
    assert_eq!(again.opened_at, 1_800_000_600);
    assert!(!again.seen);
    assert_eq!(
        again,
        Active {
            opened_at: 1_800_000_600,
            seen: false,
            held: false,
            ..first
        }
    );
}

/// Back to format 1/2: the profile goes before the session database, and the image's profile applies again.
#[test]
fn format2_after_a_switch_removes_profile_and_session_db() {
    let (root, p, index) = rendered();
    switch_to(
        &p.root,
        &p.public_dir,
        &p.var_dir,
        &index.configs["teacher"],
        Some(LOCAL_UID),
    )
    .unwrap();
    let v2 = Manifest::parse("version = 1\n[[group]]\nid = \"default\"\nname = \"d\"\n").unwrap();
    render_with(root.path(), &v2);
    assert!(!p.root.join("etc/dconf/profile/user").exists());
    assert!(!session_db(&p).exists());
    assert!(link(&p).is_none());
}

/// A second open of the same person after a real switch returns the marker's config (with its reason) and leaves
/// every switched file as the first open left it, even when the rules would now choose something else.
#[test]
fn same_person_again_keeps_the_first_sessions_config() {
    let (_root, p, index) = rendered();
    fs::remove_file(chrome_of(&p, &dir_of("teacher"))).unwrap();
    switched("primary", true, &open(&p, &policy(), ADMIN, 20000));
    let first = read_active(&p.root).unwrap();
    // teacher could be switched in now; the first session's config stays
    fs::copy(
        chrome_of(&p, &dir_of("primary")),
        chrome_of(&p, &dir_of("teacher")),
    )
    .unwrap();
    let before = tree(&p.root);
    let managed_before = fs::read(managed(&p)).unwrap();
    assert_eq!(
        open(&p, &policy(), ADMIN, 20000),
        OpenOutcome::Switched {
            user_config: "primary".into(),
            fallback_reason: first.reason.clone(),
            home: index.configs["primary"].home,
        }
    );
    let again = read_active(&p.root).unwrap();
    assert!(again.opened_at >= first.opened_at);
    assert_eq!(
        again,
        Active {
            opened_at: again.opened_at,
            ..first
        }
    );
    assert_eq!(tree(&p.root), before);
    assert_eq!(fs::read(managed(&p)).unwrap(), managed_before);
    assert_switched_to(&p, &dir_of("primary"));
}

/// Opens are serialized on `active.lock` (root 0600): while another open, close or revert holds it, an open waits at
/// most the given time and then refuses, touching nothing; a close still wakes the agent.
#[test]
fn a_held_lock_refuses_the_open() {
    let (_root, p, _) = rendered();
    let held = lock_active(&p.root, Duration::ZERO).unwrap();
    assert_eq!(mode(p.root.join(RUN_DIR).join(LOCK_FILE)), 0o600);
    assert_eq!(mode(p.root.join(RUN_DIR)), 0o700);
    // flock is per open file description: a second open of the file in this process conflicts like another process
    let started = std::time::Instant::now();
    assert!(lock_active(&p.root, Duration::from_millis(200)).is_err());
    assert!(started.elapsed() >= Duration::from_millis(200));
    assert!(started.elapsed() < LOCK_WAIT);
    assert_eq!(open(&p, &policy(), STUDENT, 20000), OpenOutcome::Refused);
    assert!(read_active(&p.root).is_none());
    assert_switched_to(&p, NEUTRAL_DIR);
    let r = FakeRunner::new();
    on_close(&p.root, 20000, &r);
    assert_eq!(r.calls().len(), 1);
    drop(held);
    switched("primary", false, &open(&p, &policy(), STUDENT, 20000));
    // The open released it
    drop(lock_active(&p.root, Duration::ZERO).unwrap());
}

/// Two opens of different people at the same time: exactly one gets the session, the other is refused.
#[test]
fn concurrent_opens_switch_once() {
    let (_root, p, _) = rendered();
    let outs: Vec<OpenOutcome> = std::thread::scope(|s| {
        let a = s.spawn(|| open(&p, &policy(), STUDENT, 20000));
        let b = s.spawn(|| open(&p, &policy(), ADMIN, 20001));
        vec![a.join().unwrap(), b.join().unwrap()]
    });
    let refused = outs.iter().filter(|o| **o == OpenOutcome::Refused).count();
    assert_eq!(refused, 1, "{outs:?}");
    let a = read_active(&p.root).unwrap();
    let winner = if outs[0] == OpenOutcome::Refused {
        20001
    } else {
        20000
    };
    assert_eq!(a.uid, winner);
    assert_switched_to(&p, &a.dir);
}

/// Every reason is kept: missing facts and the failed switch of the rules' choice both reach the marker.
#[test]
fn facts_reason_and_switch_failure_are_both_kept() {
    let (_root, p, _) = rendered();
    let mut pol = policy();
    pol.mastersos_claims = true;
    fs::remove_file(chrome_of(&p, &dir_of("teacher"))).unwrap();
    // The admin rule picks teacher without facts; teacher cannot be switched in
    let out = open(&p, &pol, ADMIN, 20000);
    switched("primary", true, &out);
    let a = read_active(&p.root).unwrap();
    let why = a.reason.unwrap();
    assert!(why.contains("the issuer handed over no facts"), "{why}");
    assert!(why.contains("switching to \"teacher\" failed"), "{why}");
}

/// The replaced session database is invalidated the way `dconf update` does it (8 zero bytes at its start), so that a
/// dconf client that still has it mapped reopens the new one; the new one is untouched.
#[test]
fn switch_invalidates_the_old_session_db() {
    use std::io::Read;
    let (_root, p, index) = rendered();
    // A client holding the current database (neutral's) open
    let mut held = fs::File::open(session_db(&p)).unwrap();
    switch_to(
        &p.root,
        &p.public_dir,
        &p.var_dir,
        &rendered_of(&index, "teacher"),
        Some(LOCAL_UID),
    )
    .unwrap();
    let mut old = Vec::new();
    held.read_to_end(&mut old).unwrap();
    assert_eq!(&old[..8], &[0u8; 8]);
    assert_eq!(&old[8..], &b"db of neutral"[8..]);
    assert_switched_to(&p, &dir_of("teacher"));
    // A replaced database still linked elsewhere is not an orphan: left alone
    let other = p.root.join("etc/dconf/db/elsewhere");
    fs::hard_link(session_db(&p), &other).unwrap();
    let mut linked = fs::File::open(session_db(&p)).unwrap();
    switch_to(&p.root, &p.public_dir, &p.var_dir, &index.neutral, None).unwrap();
    let mut kept = Vec::new();
    linked.read_to_end(&mut kept).unwrap();
    assert_eq!(kept, fs::read(&other).unwrap());
    assert_eq!(kept, format!("db of {}", dir_of("teacher")).into_bytes());
    fs::remove_file(&other).unwrap();
    // No database before (first switch): nothing to invalidate
    fs::remove_file(session_db(&p)).unwrap();
    switch_to(&p.root, &p.public_dir, &p.var_dir, &index.neutral, None).unwrap();
    assert_switched_to(&p, NEUTRAL_DIR);
}

/// The managed policy directory is read whole by Chrome: after any switch it holds only `mastersos.json`; the staging
/// copies stay beside it in `.mastersos-staging/`.
#[test]
fn card_policy_dir_has_no_staging_files() {
    let (_root, p, index) = rendered();
    let teacher = rendered_of(&index, "teacher");
    for r in [&teacher, &index.neutral] {
        switch_to(&p.root, &p.public_dir, &p.var_dir, r, None).unwrap();
        let managed = p.root.join(crate::system::chrome_policy::POLICY_DIR);
        let mut names: Vec<String> = fs::read_dir(&managed)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["mastersos.json"], "{}", r.dir);
    }
    assert!(p
        .root
        .join(crate::system::chrome_policy::POLICY_DIR)
        .parent()
        .unwrap()
        .join(".mastersos-staging")
        .is_dir());
}
