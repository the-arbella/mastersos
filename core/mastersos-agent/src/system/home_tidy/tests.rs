use super::*;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::homes::trash;

fn me() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// A tempdir standing in for `/home`, with one home directory `me` owned by this process.
struct Fx {
    d: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
}

fn fx() -> Fx {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("home");
    let home = root.join("me");
    std::fs::create_dir_all(&home).unwrap();
    Fx { d, root, home }
}

impl Fx {
    fn put(&self, rel: &str, body: &str) {
        let p = self.home.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    fn read(&self, rel: &str) -> Option<String> {
        std::fs::read_to_string(self.home.join(rel)).ok()
    }

    fn there(&self, rel: &str) -> bool {
        std::fs::symlink_metadata(self.home.join(rel)).is_ok()
    }

    fn run(&self, uid: u32) -> Tidy {
        let r = crate::safefs::open_dir(&self.root, Path::new(""), false).unwrap();
        let h = crate::safefs::open_child_dir(&r, "me").unwrap().unwrap();
        let t = trash::open_trash(&r, true).unwrap().unwrap();
        tidy_home(&h, &t, uid)
    }

    fn run_limited(&self, limits: Limits) -> Tidy {
        let r = crate::safefs::open_dir(&self.root, Path::new(""), false).unwrap();
        let h = crate::safefs::open_child_dir(&r, "me").unwrap().unwrap();
        let t = trash::open_trash(&r, true).unwrap().unwrap();
        tidy_home_limited(&h, &t, me(), limits)
    }

    fn trash_len(&self) -> usize {
        std::fs::read_dir(self.root.join(trash::TRASH))
            .map(|rd| rd.count())
            .unwrap_or(0)
    }

    fn no_temps(&self) {
        for e in std::fs::read_dir(&self.home).unwrap() {
            let n = e.unwrap().file_name();
            assert!(
                !n.as_bytes().starts_with(b".mastersos-tidy"),
                "a temporary directory was left: {n:?}"
            );
        }
    }
}

const KEPT: &[&str] = &[
    "Documents/a.txt",
    ".config/google-chrome/Default/Bookmarks",
    ".config/gtk-3.0/bookmarks",
    ".local/share/keyrings/login.keyring",
    ".var/app/org.x/data",
    ".pki/nssdb/cert9.db",
    ".pki/nssdb/key4.db",
];

const GONE: &[&str] = &[
    ".profile",
    ".bashrc",
    ".config/autostart/x.desktop",
    ".config/systemd/user/x.service",
    ".config/environment.d/x.conf",
    ".config/gtk-3.0/settings.ini",
    ".local/share/applications/x.desktop",
    ".local/share/dbus-1/services/x.service",
    ".local/share/gnome-shell/extensions/x/metadata.json",
    ".local/share/flatpak/exports/share/x",
    ".pki/nssdb/pkcs11.txt",
    ".config/user-dirs.dirs",
    ".config/user-dirs.locale",
];

fn populated() -> Fx {
    let f = fx();
    for p in KEPT.iter().chain(GONE) {
        f.put(p, &format!("body of {p}"));
    }
    f
}

fn assert_kept(f: &Fx) {
    for p in KEPT {
        assert_eq!(f.read(p), Some(format!("body of {p}")), "{p}");
    }
}

#[test]
fn keeps_only_the_keep_list() {
    let f = populated();
    let t = f.run(me());
    assert_kept(&f);
    for p in GONE {
        assert!(!f.there(p), "{p} should have been moved");
    }
    assert!(f.trash_len() > 0);
    assert!(t.moved > 0);
    assert!(t.skipped.is_empty(), "{:?}", t.skipped);
    f.no_temps();
}

#[test]
fn recovers_interrupted_swap() {
    let f = fx();
    f.put(
        ".mastersos-tidy.config/google-chrome/Default/Bookmarks",
        "B",
    );
    f.put(".config/autostart/x.desktop", "x");
    let t = f.run(me());
    assert_eq!(
        f.read(".config/google-chrome/Default/Bookmarks").as_deref(),
        Some("B")
    );
    assert!(!f.there(".config/autostart"));
    assert!(!f.there(".mastersos-tidy.config"));
    assert!(t.skipped.is_empty(), "{:?}", t.skipped);
}

/// Interrupted after the exchange: the temporary name holds the old content, the container holds only the keep items.
#[test]
fn recovers_after_the_exchange() {
    let f = fx();
    f.put(".config/google-chrome/Default/Bookmarks", "B");
    f.put(".config/dconf/user", "D");
    f.put(".mastersos-tidy.config/autostart/x.desktop", "x");
    f.put(".mastersos-tidy.config/gtk-3.0/settings.ini", "s");
    let t = f.run(me());
    assert_eq!(
        f.read(".config/google-chrome/Default/Bookmarks").as_deref(),
        Some("B")
    );
    assert_eq!(f.read(".config/dconf/user").as_deref(), Some("D"));
    assert!(!f.there(".config/autostart"));
    assert!(!f.there(".config/gtk-3.0"));
    f.no_temps();
    assert!(t.skipped.is_empty(), "{:?}", t.skipped);
}

/// A temporary directory the student planted only gives back keep items; nothing else in it reaches the container.
#[test]
fn planted_temporary_directory_gives_back_only_keep_items() {
    let f = fx();
    f.put(".config/google-chrome/Default/Bookmarks", "old");
    f.put(
        ".mastersos-tidy.config/google-chrome/Default/Bookmarks",
        "B",
    );
    f.put(".mastersos-tidy.config/autostart/evil.desktop", "x");
    f.put(".mastersos-tidy.local/share/applications/evil.desktop", "x");
    // A link as the temporary directory is moved, not followed.
    let outside = f.d.path().join("outside");
    std::fs::create_dir_all(outside.join("google-chrome")).unwrap();
    symlink(&outside, f.home.join(".mastersos-tidy.cache")).unwrap();
    let t = f.run(me());
    assert_eq!(
        f.read(".config/google-chrome/Default/Bookmarks").as_deref(),
        Some("B")
    );
    assert!(!f.there(".config/autostart"));
    assert!(!f.there(".local/share/applications"));
    assert!(!f.there(".cache/google-chrome"));
    assert!(outside.join("google-chrome").is_dir());
    f.no_temps();
    assert!(t.skipped.is_empty(), "{:?}", t.skipped);
}

#[test]
fn symlinked_container_is_moved_not_followed() {
    let f = fx();
    let outside = f.d.path().join("outside");
    std::fs::create_dir_all(outside.join("autostart")).unwrap();
    std::fs::write(outside.join("keep.txt"), "K").unwrap();
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(
        outside.join("keep.txt"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    symlink(&outside, f.home.join(".config")).unwrap();
    symlink(outside.join("keep.txt"), f.home.join(".profile")).unwrap();
    // Intermediate and keep-list paths that are links are not followed either.
    std::fs::create_dir_all(f.home.join(".local")).unwrap();
    symlink(&outside, f.home.join(".local/share")).unwrap();
    let t = f.run(me());
    assert_eq!(
        std::fs::read_to_string(outside.join("keep.txt")).unwrap(),
        "K"
    );
    assert!(outside.join("autostart").is_dir());
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode(&outside), 0o755);
    assert_eq!(mode(&outside.join("keep.txt")), 0o644);
    assert!(!f.there(".config"));
    assert!(!f.there(".profile"));
    assert!(!f.there(".local/share"));
    assert!(t.skipped.is_empty(), "{:?}", t.skipped);
}

#[test]
fn foreign_container_is_skipped() {
    let f = populated();
    let t = f.run(me() + 1);
    assert!(t.skipped.contains(&SkipReason::ForeignContainer));
    assert_eq!(
        f.read(".config/autostart/x.desktop").as_deref(),
        Some("body of .config/autostart/x.desktop")
    );
    assert_kept(&f);
    assert_eq!(t.moved, 0);
}

#[test]
fn too_many_top_entries_stops() {
    let f = fx();
    for n in 0..MAX_TOP_ENTRIES + 5 {
        std::fs::write(f.home.join(format!(".f{n}")), "").unwrap();
    }
    let t = f.run(me());
    assert!(t.skipped.contains(&SkipReason::TooManyEntries));
    assert!(t.moved <= MAX_TOP_ENTRIES + CONTAINERS.len());
    assert!(t.moved > 0, "the first batch is still moved");
}

/// Every entry read counts toward the scan bound, not only dot entries: a home with very many ordinary files is not
/// read in full on every login.
#[test]
fn scan_bound_counts_every_entry() {
    let f = fx();
    for n in 0..50 {
        std::fs::write(f.home.join(format!("f{n}")), "").unwrap();
    }
    let t = f.run_limited(Limits {
        max_top: 1_000,
        max_scan: 20,
    });
    assert!(t.skipped.contains(&SkipReason::TooManyEntries));
    // Ordinary files are never touched.
    assert_eq!(std::fs::read_dir(&f.home).unwrap().count(), 50);
}

/// Filling the home with junk dot entries beyond the cap does not keep the files that matter alive: they are moved
/// by name before the scan.
#[test]
fn known_dangerous_names_go_before_the_cap() {
    let f = fx();
    for n in 0..30 {
        std::fs::write(f.home.join(format!(".a{n}")), "").unwrap();
    }
    for n in [
        ".profile",
        ".bash_profile",
        ".bashrc",
        ".pam_environment",
        ".xsessionrc",
        ".zshenv",
    ] {
        f.put(n, "x");
    }
    let t = f.run_limited(Limits {
        max_top: 5,
        max_scan: 1_000,
    });
    assert!(t.skipped.contains(&SkipReason::TooManyEntries));
    for n in [
        ".profile",
        ".bash_profile",
        ".bashrc",
        ".pam_environment",
        ".xsessionrc",
        ".zshenv",
    ] {
        assert!(!f.there(n), "{n}");
    }
}

/// The same with the real cap: more than [`MAX_TOP_ENTRIES`] junk dot entries and `.profile` is still gone.
#[test]
fn profile_is_gone_despite_many_dotfiles() {
    let f = fx();
    for n in 0..MAX_TOP_ENTRIES + 5 {
        std::fs::write(f.home.join(format!(".a{n}")), "").unwrap();
    }
    f.put(".profile", "x");
    let t = f.run(me());
    assert!(t.skipped.contains(&SkipReason::TooManyEntries));
    assert!(!f.there(".profile"));
}

#[test]
fn non_utf8_dotfile_is_moved() {
    let f = fx();
    let name = std::ffi::OsStr::from_bytes(b".prof\xffile");
    std::fs::write(f.home.join(name), "x").unwrap();
    f.put(".bashrc", "x");
    let t = f.run(me());
    assert!(std::fs::symlink_metadata(f.home.join(name)).is_err());
    assert!(!f.there(".bashrc"));
    assert_eq!(t.moved, 2);
    assert!(t.skipped.is_empty(), "{:?}", t.skipped);
}

#[test]
fn idempotent() {
    let f = populated();
    let first = f.run(me());
    assert!(first.moved > 0);
    let second = f.run(me());
    assert_eq!(second.moved, 0);
    assert!(second.skipped.is_empty(), "{:?}", second.skipped);
    assert_kept(&f);
    f.no_temps();
}

/// Containers come back owned by the user with their original permissions.
#[test]
fn container_keeps_owner_and_mode() {
    let f = populated();
    std::fs::set_permissions(
        f.home.join(".config"),
        std::fs::Permissions::from_mode(0o750),
    )
    .unwrap();
    f.run(me());
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(f.home.join(".config")).unwrap();
    assert!(m.is_dir());
    assert_eq!(m.uid(), me());
    assert_eq!(m.mode() & 0o777, 0o750);
}

#[test]
fn keep_list_follows_the_rule() {
    // Nothing that is run, loaded or read as environment or configuration of other programs.
    for (_, keep) in CONTAINERS {
        for k in *keep {
            for bad in [
                "autostart",
                "applications",
                "systemd",
                "environment.d",
                "mimeapps",
                "user-dirs",
                "pkcs11",
            ] {
                assert!(!k.contains(bad), "{k}");
            }
            assert!(!k.starts_with('/') && !k.split('/').any(|p| p.is_empty() || p == ".."));
        }
    }
}

mod prepare {
    use super::super::{linger_off_for_students, prepare_user_manager, Prep};
    use crate::runner::{FakeRunner, Output};

    const SHOW: &str = "loginctl show-user 10001 -p State --value";

    #[test]
    fn prepare_skips_active() {
        for state in ["active\n", "online\n"] {
            let r = FakeRunner::new();
            r.respond(SHOW, Output::ok(state));
            assert_eq!(prepare_user_manager(&r, 10001), Prep::SkipActive);
            assert_eq!(r.calls(), vec![SHOW]);
        }
    }

    #[test]
    fn prepare_stops_leftovers() {
        for state in ["closing\n", "lingering\n"] {
            let r = FakeRunner::new();
            r.respond(SHOW, Output::ok(state));
            assert_eq!(prepare_user_manager(&r, 10001), Prep::Proceed);
            assert_eq!(
                r.calls(),
                vec![
                    SHOW,
                    "loginctl disable-linger 10001",
                    "loginctl terminate-user 10001",
                    "systemctl stop user@10001.service",
                ]
            );
        }
    }

    #[test]
    fn prepare_offline_proceeds() {
        let r = FakeRunner::new();
        r.respond(
            SHOW,
            Output::fail(
                1,
                "Failed to get user: User ID 10001 is not logged in or lingering",
            ),
        );
        assert_eq!(prepare_user_manager(&r, 10001), Prep::Proceed);
        assert_eq!(r.calls(), vec![SHOW]);
        let r = FakeRunner::new();
        r.respond(SHOW, Output::ok("offline\n"));
        assert_eq!(prepare_user_manager(&r, 10001), Prep::Proceed);
        assert_eq!(r.calls(), vec![SHOW]);
    }

    #[test]
    fn prepare_failure() {
        let r = FakeRunner::new();
        r.respond(SHOW, Output::ok("closing\n"));
        r.respond("loginctl terminate-user", Output::fail(1, "boom"));
        assert_eq!(prepare_user_manager(&r, 10001), Prep::Failed);
        // Other failures of the state query, and unknown states, are failures too.
        let r = FakeRunner::new();
        r.respond(SHOW, Output::fail(1, "Connection timed out"));
        assert_eq!(prepare_user_manager(&r, 10001), Prep::Failed);
        let r = FakeRunner::new();
        r.respond(SHOW, Output::ok("strange\n"));
        assert_eq!(prepare_user_manager(&r, 10001), Prep::Failed);
    }

    #[test]
    fn prepare_commands_are_bounded() {
        use crate::runner::{Cmd, Runner};
        use std::sync::Mutex;
        struct Spy(Mutex<Vec<std::time::Duration>>);
        impl Runner for Spy {
            fn run(&self, cmd: &Cmd) -> anyhow::Result<Output> {
                self.0.lock().unwrap().push(cmd.timeout);
                Ok(Output::ok("closing\n"))
            }
        }
        let s = Spy(Mutex::new(Vec::new()));
        assert_eq!(prepare_user_manager(&s, 10001), Prep::Proceed);
        let t = s.0.lock().unwrap();
        assert_eq!(t.len(), 4);
        assert!(t
            .iter()
            .all(|d| *d == crate::system::ephemeral::PAM_CMD_TIMEOUT));
    }

    #[test]
    fn linger_off_skips_admins_and_system() {
        let json = r#"[
            {"uid":10001,"user":"student@school.ac.th","linger":true,"state":"lingering"},
            {"uid":10002,"user":"Boss@school.ac.th","linger":true,"state":"lingering"},
            {"uid":0,"user":"root","linger":true,"state":"online"},
            {"uid":120,"user":"gdm","linger":true,"state":"online"},
            {"uid":10003,"user":"other@school.ac.th","linger":false,"state":"active"}
        ]"#;
        let r = FakeRunner::new();
        r.respond("loginctl list-users", Output::ok(json));
        linger_off_for_students(&r, &["boss@school.ac.th".to_string()]).unwrap();
        let calls = r.calls();
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert_eq!(calls[1], "loginctl disable-linger 10001");
    }

    #[test]
    fn linger_off_failures_are_counted_without_ids() {
        let json = r#"[{"uid":10001,"user":"a@s.th","linger":true,"state":"lingering"}]"#;
        let r = FakeRunner::new();
        r.respond("loginctl list-users", Output::ok(json));
        r.respond("loginctl disable-linger", Output::fail(1, "x"));
        let e = linger_off_for_students(&r, &[]).unwrap_err().to_string();
        assert!(
            e.contains('1') && !e.contains("10001") && !e.contains("a@s.th"),
            "{e}"
        );
    }
}

mod login {
    use super::super::{on_login, tidy_decision, LastTidy, RESULT_FILE};
    use crate::runner::{FakeRunner, Output};
    use crate::system::exec_block;
    use crate::system::tests::paths;

    const SHOW: &str = "loginctl show-user";

    fn uid() -> u32 {
        super::me()
    }

    /// A root with `/home/me/.profile` and the passwd answer for it.
    fn setup(mode: Option<&str>, home_field: &str) -> (tempfile::TempDir, FakeRunner) {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        std::fs::create_dir_all(d.path().join("home/me")).unwrap();
        std::fs::write(d.path().join("home/me/.profile"), "x").unwrap();
        std::fs::create_dir_all(&p.public_dir).unwrap();
        if let Some(m) = mode {
            std::fs::write(p.public_dir.join(exec_block::SESSION_MODE_FILE), m).unwrap();
        }
        let r = FakeRunner::new();
        r.respond(
            "getent passwd",
            Output::ok(&format!(
                "me:x:{}:{}:Me:{home_field}:/bin/bash\n",
                uid(),
                uid()
            )),
        );
        (d, r)
    }

    fn result(d: &tempfile::TempDir) -> Option<LastTidy> {
        let f = paths(d.path()).var_dir.join(RESULT_FILE);
        serde_json::from_slice(&std::fs::read(f).ok()?).ok()
    }

    fn profile(d: &tempfile::TempDir) -> bool {
        d.path().join("home/me/.profile").exists()
    }

    #[test]
    fn tidy_decision_by_mode() {
        for (mode, want) in [
            (None, false),
            (Some("full\n"), false),
            (Some("learning\n"), true),
            (Some("\u{1}garbage"), true),
        ] {
            let (d, _) = setup(mode, "/home/me");
            assert_eq!(tidy_decision(&paths(d.path()).public_dir), want, "{mode:?}");
        }
    }

    #[test]
    fn on_login_full_mode_touches_nothing() {
        for mode in [Some("full\n"), None] {
            let (d, r) = setup(mode, "/home/me");
            on_login(&paths(d.path()), &r, "me", uid());
            assert!(profile(&d));
            assert!(result(&d).is_none());
            assert!(!paths(d.path()).var_dir.join(RESULT_FILE).exists());
            assert!(r.calls().is_empty(), "{:?}", r.calls());
        }
    }

    #[test]
    fn on_login_learning_tidies() {
        let (d, r) = setup(Some("learning\n"), "/home/me");
        r.respond(SHOW, Output::ok("offline\n"));
        on_login(&paths(d.path()), &r, "me", uid());
        assert!(!profile(&d));
        let t = result(&d).unwrap();
        assert_eq!(t.outcome, "tidied");
        assert!(t.moved >= 1);
        assert!(t.skipped.is_empty());
        assert!(t.at > 0);
        use std::os::unix::fs::PermissionsExt;
        let f = paths(d.path()).var_dir.join(RESULT_FILE);
        assert_eq!(
            std::fs::metadata(f).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn on_login_active_skips() {
        let (d, r) = setup(Some("learning\n"), "/home/me");
        r.respond(SHOW, Output::ok("active\n"));
        on_login(&paths(d.path()), &r, "me", uid());
        assert!(profile(&d));
        assert_eq!(result(&d).unwrap().outcome, "skipped-active");
    }

    #[test]
    fn on_login_prepare_failed() {
        let (d, r) = setup(Some("learning\n"), "/home/me");
        r.respond(SHOW, Output::fail(1, "boom"));
        on_login(&paths(d.path()), &r, "me", uid());
        assert!(profile(&d));
        assert_eq!(result(&d).unwrap().outcome, "prepare-failed");
    }

    #[test]
    fn on_login_not_a_home() {
        for field in [
            "/srv/me",
            "/home/other",
            "/home/me/",
            "/home/../home/me",
            "",
        ] {
            let (d, r) = setup(Some("learning\n"), field);
            r.respond(SHOW, Output::ok("offline\n"));
            on_login(&paths(d.path()), &r, "me", uid());
            assert!(profile(&d), "{field}");
            assert_eq!(result(&d).unwrap().outcome, "not-a-home", "{field}");
        }
        // no passwd record at all
        let (d, _) = setup(Some("learning\n"), "/home/me");
        let r = FakeRunner::new();
        r.respond("getent passwd", Output::fail(2, ""));
        on_login(&paths(d.path()), &r, "me", uid());
        assert!(profile(&d));
        assert_eq!(result(&d).unwrap().outcome, "not-a-home");
    }

    #[test]
    fn on_login_never_fails_on_broken_setup() {
        // var_dir is a file, /home missing, odd names: nothing may panic
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        std::fs::create_dir_all(&p.public_dir).unwrap();
        std::fs::write(
            p.public_dir.join(exec_block::SESSION_MODE_FILE),
            "learning\n",
        )
        .unwrap();
        std::fs::create_dir_all(p.var_dir.parent().unwrap()).unwrap();
        std::fs::write(&p.var_dir, "not a dir").unwrap();
        let r = FakeRunner::new();
        r.respond(
            "getent passwd",
            Output::ok(&format!("me:x:{}:1:M:/home/me:/bin/sh\n", uid())),
        );
        r.respond(SHOW, Output::ok("offline\n"));
        on_login(&p, &r, "me", uid());
        on_login(&p, &r, "../x", uid());
        on_login(&p, &r, "", 0);
    }

    #[test]
    fn kebab_names_of_skip_reasons() {
        use super::super::SkipReason::*;
        assert_eq!(ForeignContainer.name(), "foreign-container");
        assert_eq!(ContainerBusy.name(), "container-busy");
        assert_eq!(TooManyEntries.name(), "too-many-entries");
        assert_eq!(Io.name(), "io");
    }
}
