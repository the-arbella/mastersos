//! First-boot program for unmanaged machines (Ruling 18): with no seed and no local user, creates the first user on tty1.

use anyhow::Result;
use mastersos_agent::runner::{run_ok, run_ok_redacted, Cmd, Runner};

use crate::tty;

/// No seed, and no account in passwd with a uid in [1000, 60000) other than `guest`.
pub fn needs_firstrun(passwd: &str, seed_present: bool) -> bool {
    if seed_present {
        return false;
    }
    !passwd.lines().any(|l| {
        let mut f = l.split(':');
        let name = f.next().unwrap_or("");
        let uid = f.nth(1).and_then(|u| u.parse::<u32>().ok());
        name != "guest" && uid.is_some_and(|u| (1000..60000).contains(&u))
    })
}

/// `^[a-z_][a-z0-9_-]{0,31}$`, and not `guest` or `root`.
pub fn valid_username(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 32 || s == "guest" || s == "root" {
        return false;
    }
    (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// Both entries equal, not empty, no control characters (a newline would break chpasswd's input line).
pub fn check_passwords(a: &str, b: &str) -> std::result::Result<(), &'static str> {
    if a.is_empty() {
        return Err("Password must not be empty");
    }
    if a.chars().any(char::is_control) {
        return Err("No control characters in the password");
    }
    if a != b {
        return Err("The two entries differ");
    }
    Ok(())
}

/// The password reaches `chpasswd` only through stdin, never the arguments. `name` must pass [`valid_username`] first.
pub fn create_user(name: &str, password: &str) -> Vec<Cmd> {
    vec![
        Cmd::new(
            "useradd",
            &[
                "--create-home",
                "--user-group",
                "--groups",
                "sudo,lpadmin",
                "--shell",
                "/bin/bash",
                name,
            ],
        ),
        // --crypt-method makes chpasswd compute yescrypt itself, without PAM: the image's common-password starts with authd's
        // pam_authd_exec (default=die), and a non-interactive chpasswd through PAM always gets "Authentication token manipulation
        // error" (Task 11, VM 168). yescrypt is also Ubuntu's pam_unix default.
        Cmd::new("chpasswd", &["--crypt-method", "YESCRYPT"])
            .stdin(format!("{name}:{password}\n").into_bytes()),
    ]
}

/// `dir` is a mount point: its device number differs from its parent's. With the seed partition not mounted (a `nofail` mount may
/// be late or fail) there is no telling whether the machine is managed, so the first-boot program would rather not create a user.
pub fn is_mountpoint(parent_dev: u64, dir_dev: u64) -> bool {
    parent_dev != dir_dev
}

/// `userdel -r` also failed after `chpasswd` failed: a user without a password is left behind, no silent retry.
#[derive(Debug)]
pub struct CleanupFailed;

impl std::fmt::Display for CleanupFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("The user was created without a password and could not be removed; call IT")
    }
}

impl std::error::Error for CleanupFailed {}

/// Creates the user. When `useradd` works and `chpasswd` fails, undoes it (`userdel -r`), so no uid 1000 account without a password
/// is left behind: that would make [`needs_firstrun`] false forever.
pub fn create_user_with(r: &dyn Runner, name: &str, password: &str) -> Result<()> {
    let mut cmds = create_user(name, password).into_iter();
    if let Some(add) = cmds.next() {
        run_ok(r, add)?;
    }
    for c in cmds {
        // chpasswd's error message carries no stderr (the Global Constraints rule for commands holding secrets).
        if let Err(e) = run_ok_redacted(r, c) {
            let undone = r
                .run(&Cmd::new("userdel", &["-r", name]))
                .is_ok_and(|o| o.code == 0);
            if !undone {
                return Err(CleanupFailed.into());
            }
            return Err(e);
        }
    }
    Ok(())
}

/// The tty dialogue: asks for the username and the password (twice), asks again when something is wrong, then creates the user.
pub fn run_interactive(r: &dyn Runner) -> Result<()> {
    tty::say(
        "\nMastersOS first-time setup\nCreate the first user (administrator) of this computer.\n",
    );
    loop {
        let name = loop {
            let n = tty::prompt("Username: ")?;
            if valid_username(&n) {
                break n;
            }
            tty::say("Lowercase letters, digits, _ and - only; start with a letter or _; max 32; not root or guest.");
        };
        let password = loop {
            let a = tty::prompt_secret("Password: ")?;
            let b = tty::prompt_secret("Again: ")?;
            match check_passwords(&a, &b) {
                Ok(()) => break a,
                Err(why) => tty::say(why),
            }
        };
        match create_user_with(r, &name, &password) {
            Ok(()) => break,
            // Name taken and the like: start over instead of exiting and leaving the login screen with no user at all.
            Err(e) if e.is::<CleanupFailed>() => return Err(e),
            Err(e) => tty::say(&format!("Failed, try again: {e:#}")),
        }
    }
    tty::say("User created.");
    Ok(())
}
