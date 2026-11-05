//! `mastersos-agent signin-import`: the user's half of the sign-in handoff, run as the user by
//! `mastersos-signin-import.service` at the start of a desktop session (the unit's condition is the placeholder `pam-session`
//! leaves). Waits up to [`WAIT`] for the placeholder `<uid>` in [`super::HANDOFF_DIR`] to become this user's non-empty
//! database, reads it, empties it (it is used once, whatever happens next) and, when the user's Chrome is not running,
//! merges the identity provider's cookies into the profile or creates the profile's cookie database
//! ([`super::cookies`]).

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rustix::fs::{Mode, OFlags};

use super::cookies;
use super::{owner_of, HANDOFF_DIR, MAX_DB_BYTES};
use crate::safefs;
use crate::system::desktop::{CHROME_PROFILE, CHROME_USER_DATA};
use crate::system::login::{LOGIN_BROWSER_DIR, LOGIN_BROWSER_FILE};

/// How long the session waits for the card's cookies (the card stops a second or two after the session opens).
pub const WAIT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(250);
/// The card's Chrome policy is a few hundred bytes.
const MAX_POLICY_BYTES: u64 = 64 * 1024;
/// The cookie database file in the profile.
pub const COOKIES_FILE: &str = "Cookies";

/// Where things are, so the tests can point elsewhere.
pub struct ImportEnv<'a> {
    pub handoff_dir: &'a Path,
    pub uid: u32,
    /// The browser's user data directory (`~/`[`CHROME_USER_DATA`]).
    pub user_data: PathBuf,
    /// The card's Chrome policy (the identity provider's hosts).
    pub policy: PathBuf,
    pub wait: Duration,
    pub poll: Duration,
    pub now_unix: i64,
    /// Whether a process with this pid is alive.
    pub alive: &'a dyn Fn(u32) -> bool,
}

/// What [`import`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Imported {
    /// Nothing was handed over (no placeholder, or it stayed empty).
    Nothing,
    /// The browser was running: nothing written.
    BrowserRunning,
    /// Nothing worth writing (no identity provider hosts, every row dropped).
    Empty,
    /// Rows merged into the existing database.
    Merged(usize),
    /// A new database with this many rows.
    Created(usize),
    /// The browser made its own database while this one was being built: left alone.
    Raced,
}

/// Whether the browser holds the profile: its `SingletonLock` is a link to `<host>-<pid>` with that pid alive. A lock that is
/// there but unreadable counts as running.
pub fn browser_running(user_data: &Path, alive: &dyn Fn(u32) -> bool) -> bool {
    match std::fs::read_link(user_data.join("SingletonLock")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => true,
        Ok(target) => target
            .to_str()
            .and_then(|t| t.rsplit_once('-'))
            .and_then(|(_, pid)| pid.parse::<u32>().ok())
            .is_none_or(alive),
    }
}

fn pid_alive(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

/// Empties the delivered file (this user owns it): used once.
fn consume(dir: &OwnedFd, name: &str) {
    let r = rustix::fs::openat(
        dir,
        name,
        OFlags::WRONLY | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    );
    if let Err(e) = r {
        eprintln!("mastersos-agent signin-import: cannot empty the handed-over file: {e}");
    }
}

/// Waits for this user's database; `None` when the placeholder goes away or stays empty for `env.wait`.
fn wait_for(env: &ImportEnv, dir: &OwnedFd, name: &str) -> Result<Option<u64>> {
    let deadline = Instant::now() + env.wait;
    loop {
        let Some(f) = safefs::open_file_at(dir, name)? else {
            return Ok(None);
        };
        let (owner, _, size) = owner_of(&f)?;
        if owner == env.uid && size > 0 {
            return Ok(Some(size));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(env.poll);
    }
}

fn read_policy(path: &Path) -> String {
    use std::io::Read;
    let mut s = String::new();
    if let Ok(f) = std::fs::File::open(path) {
        let _ = f.take(MAX_POLICY_BYTES).read_to_string(&mut s);
    }
    s
}

/// The user's half: see the module documentation.
pub fn import(env: &ImportEnv) -> Result<Imported> {
    // The handover directory is 0711: search it, never list it.
    let dir = match safefs::open_abs_dir_search(env.handoff_dir) {
        Ok(d) => d,
        Err(e) if crate::apply::is_not_found(&e) => return Ok(Imported::Nothing),
        Err(e) => return Err(e),
    };
    let name = env.uid.to_string();
    let Some(size) = wait_for(env, &dir, &name)? else {
        return Ok(Imported::Nothing);
    };
    let card = if size > MAX_DB_BYTES {
        Err(anyhow::anyhow!("the handed-over database is {size} bytes"))
    } else {
        cookies::read_card(&env.handoff_dir.join(&name))
    };
    consume(&dir, &name);
    let mut card = card?;
    if browser_running(&env.user_data, env.alive) {
        return Ok(Imported::BrowserRunning);
    }
    let hosts = cookies::allowed_hosts(&read_policy(&env.policy));
    let p = cookies::prepare(&mut card, &hosts, env.now_unix)?;
    if p.kept == 0 {
        return Ok(Imported::Empty);
    }
    let profile = env.user_data.join(CHROME_PROFILE);
    let db = profile.join(COOKIES_FILE);
    if std::fs::symlink_metadata(&db).is_ok() {
        return Ok(Imported::Merged(cookies::merge_into(&db, &card)?));
    }
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&profile)
            .with_context(|| format!("creating {}", profile.display()))?;
    }
    Ok(if cookies::create_new(&profile, COOKIES_FILE, &card)? {
        Imported::Created(card.rows.len())
    } else {
        Imported::Raced
    })
}

/// The entry point: as the user (never root), with `HOME` from the user manager.
pub fn main() -> ExitCode {
    if rustix::process::geteuid().is_root() {
        eprintln!("mastersos-agent signin-import runs as the user, not as root");
        return ExitCode::FAILURE;
    }
    let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty()) else {
        eprintln!("mastersos-agent signin-import: no HOME");
        return ExitCode::FAILURE;
    };
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let env = ImportEnv {
        handoff_dir: Path::new(HANDOFF_DIR),
        uid: rustix::process::getuid().as_raw(),
        user_data: Path::new(&home).join(CHROME_USER_DATA),
        policy: Path::new("/var/lib/mastersos-public")
            .join(LOGIN_BROWSER_DIR)
            .join(LOGIN_BROWSER_FILE),
        wait: WAIT,
        poll: POLL,
        now_unix,
        alive: &pid_alive,
    };
    match import(&env) {
        Ok(Imported::Nothing) => {
            eprintln!("mastersos-agent signin-import: nothing was handed over")
        }
        Ok(Imported::BrowserRunning) => {
            eprintln!(
                "mastersos-agent signin-import: the web browser is already running; not signed in"
            )
        }
        Ok(Imported::Empty) => {
            eprintln!("mastersos-agent signin-import: no cookies of the identity provider")
        }
        Ok(Imported::Merged(n)) => eprintln!("mastersos-agent signin-import: {n} cookies merged"),
        Ok(Imported::Created(n)) => {
            eprintln!("mastersos-agent signin-import: {n} cookies in a new profile")
        }
        Ok(Imported::Raced) => {
            eprintln!("mastersos-agent signin-import: the web browser made its own profile first; not signed in")
        }
        Err(e) => eprintln!("mastersos-agent signin-import: {e:#}"),
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::signin_handoff::cookies::tests::{chrome_db, later, rows_of, NOW};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    const POLICY: &str = r#"{"URLBlocklist":["*"],"URLAllowlist":["https://.auth.school.ac.th:443","127.0.0.1:48123/callback"]}"#;

    struct T {
        _t: tempfile::TempDir,
        handoff: PathBuf,
        home: PathBuf,
        policy: PathBuf,
        uid: u32,
    }

    impl T {
        fn new() -> T {
            let t = tempfile::tempdir().unwrap();
            let handoff = t.path().join("signin");
            fs::create_dir(&handoff).unwrap();
            let home = t.path().join("home");
            fs::create_dir(&home).unwrap();
            let policy = t.path().join("policy.json");
            fs::write(&policy, POLICY).unwrap();
            T {
                handoff,
                home,
                policy,
                uid: rustix::process::geteuid().as_raw(),
                _t: t,
            }
        }

        fn delivered(&self) -> PathBuf {
            self.handoff.join(self.uid.to_string())
        }

        fn deliver_card(&self) {
            let _ = fs::remove_file(self.delivered());
            chrome_db(
                &self.delivered(),
                &[
                    ("auth.school.ac.th", "sessions", false, 0),
                    ("tracker.example", "t", true, later()),
                ],
            );
        }

        fn user_db(&self) -> PathBuf {
            self.home
                .join(CHROME_USER_DATA)
                .join(CHROME_PROFILE)
                .join(COOKIES_FILE)
        }

        fn env<'a>(&'a self, alive: &'a dyn Fn(u32) -> bool) -> ImportEnv<'a> {
            ImportEnv {
                handoff_dir: &self.handoff,
                uid: self.uid,
                user_data: self.home.join(CHROME_USER_DATA),
                policy: self.policy.clone(),
                wait: Duration::from_millis(60),
                poll: Duration::from_millis(10),
                now_unix: NOW,
                alive,
            }
        }

        fn run(&self, alive: &dyn Fn(u32) -> bool) -> Imported {
            import(&self.env(alive)).unwrap()
        }
    }

    fn dead(_: u32) -> bool {
        false
    }

    #[test]
    fn nothing_without_a_placeholder() {
        let t = T::new();
        assert_eq!(t.run(&dead), Imported::Nothing);
        let gone = T::new();
        fs::remove_dir(&gone.handoff).unwrap();
        assert_eq!(gone.run(&dead), Imported::Nothing);
    }

    /// The image's directory is 0711 root: the user may search it but not list it (found on VM 123, 2026-11-05).
    #[test]
    fn a_search_only_directory_is_enough() {
        let t = T::new();
        t.deliver_card();
        fs::set_permissions(&t.handoff, fs::Permissions::from_mode(0o311)).unwrap();
        let got = import(&t.env(&dead));
        fs::set_permissions(&t.handoff, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(got.unwrap(), Imported::Created(1));
        assert_eq!(fs::metadata(t.delivered()).unwrap().len(), 0, "used once");
    }

    #[test]
    fn an_empty_placeholder_is_waited_for_then_given_up() {
        let t = T::new();
        fs::write(t.delivered(), b"").unwrap();
        let start = Instant::now();
        assert_eq!(t.run(&dead), Imported::Nothing);
        assert!(start.elapsed() >= Duration::from_millis(60));
    }

    #[test]
    fn first_login_creates_the_profile() {
        let t = T::new();
        t.deliver_card();
        assert_eq!(t.run(&dead), Imported::Created(1));
        let rows = rows_of(&t.user_db());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "auth.school.ac.th");
        assert_eq!(rows[0].2, 1, "made persistent");
        assert_eq!(fs::metadata(t.delivered()).unwrap().len(), 0, "used once");
        let dir = t.user_db();
        let mode = fs::metadata(dir.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
        // used once: the next run finds an empty file
        assert_eq!(t.run(&dead), Imported::Nothing);
    }

    #[test]
    fn later_logins_merge() {
        let t = T::new();
        fs::create_dir_all(t.user_db().parent().unwrap()).unwrap();
        chrome_db(&t.user_db(), &[("news.example", "pref", true, later())]);
        t.deliver_card();
        assert_eq!(t.run(&dead), Imported::Merged(1));
        let hosts: Vec<_> = rows_of(&t.user_db()).into_iter().map(|r| r.0).collect();
        assert_eq!(hosts, ["auth.school.ac.th", "news.example"]);
    }

    #[test]
    fn a_running_browser_is_left_alone() {
        let t = T::new();
        let data = t.home.join(CHROME_USER_DATA);
        fs::create_dir_all(data.join(CHROME_PROFILE)).unwrap();
        chrome_db(&t.user_db(), &[]);
        std::os::unix::fs::symlink("laptop-4321", data.join("SingletonLock")).unwrap();
        t.deliver_card();
        assert_eq!(t.run(&|pid| pid == 4321), Imported::BrowserRunning);
        assert!(rows_of(&t.user_db()).is_empty());
        assert_eq!(
            fs::metadata(t.delivered()).unwrap().len(),
            0,
            "used once anyway"
        );
        // a lock left by a browser that is gone does not count
        t.deliver_card();
        assert_eq!(t.run(&dead), Imported::Merged(1));
    }

    #[test]
    fn running_check() {
        let d = tempfile::tempdir().unwrap();
        assert!(!browser_running(d.path(), &|_| true));
        std::os::unix::fs::symlink("host-name-77", d.path().join("SingletonLock")).unwrap();
        assert!(browser_running(d.path(), &|p| p == 77));
        assert!(!browser_running(d.path(), &|p| p != 77));
        fs::remove_file(d.path().join("SingletonLock")).unwrap();
        std::os::unix::fs::symlink("garbage", d.path().join("SingletonLock")).unwrap();
        assert!(
            browser_running(d.path(), &|_| false),
            "an unreadable lock counts as running"
        );
    }

    #[test]
    fn without_the_card_policy_nothing_is_written() {
        let t = T::new();
        fs::remove_file(&t.policy).unwrap();
        t.deliver_card();
        assert_eq!(t.run(&dead), Imported::Empty);
        assert!(!t.user_db().exists());
    }

    #[test]
    fn a_broken_database_is_consumed_and_refused() {
        let t = T::new();
        fs::write(t.delivered(), b"not sqlite at all").unwrap();
        assert!(import(&t.env(&dead)).is_err());
        assert_eq!(fs::metadata(t.delivered()).unwrap().len(), 0);
        assert!(!t.user_db().exists());
    }
}
