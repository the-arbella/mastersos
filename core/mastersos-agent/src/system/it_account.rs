//! The IT maintenance account [`IT_ACCOUNT_USER`] (`itadmin`, phase B design §10.4): one local account per managed Device
//! that IT signs in with ("Not listed?" on the login screen) and that is always an administrator.
//!
//! - Wanted (the bundle's or the seed's `it_account` with a valid hash): no `itadmin` → `useradd -m -U` (uid from the
//!   system's normal range), then the uid is recorded in [`super::SysState::it_account_uid`]. Only an `itadmin` with that uid
//!   is ours: one with any other uid (or with nothing recorded) is left alone and reported — MastersOS does not adopt an
//!   account somebody else made, since adopting it would hand it administrator rights.
//! - The password: the hash in `/etc/shadow` is compared with the wanted one; when it differs it goes to `chpasswd -e`
//!   **on stdin only** (never in the arguments, a log line, a report or `SysState`), then `usermod -U -e ""` unlocks the
//!   account (undoing an earlier removal).
//! - AccountsService `/var/lib/AccountsService/users/itadmin` gets `SystemAccount=true` (other keys kept), so the login
//!   screen's user list does not show it.
//! - Not wanted (no `it_account`, or a hash that fails [`checks::it_password_hash`], which is also reported): our `itadmin`
//!   is locked with `usermod -L -e 1`; the home directory stays.
//! - Ownership must survive: the uid is saved to `system-state.json` right after `useradd` (not only at the end of the
//!   round), and nothing is created, changed or locked in a round whose state could not be read
//!   ([`super::SysState::load_failed`]) — such a round would lose the record and orphan the account. An `itadmin`
//!   without a matching record is reported both when wanted and when not (never a silent ok).
//! - The seed path only sets the account up on a device that has never applied a bundle
//!   ([`super::SysState::bundle_applied`], set by the bundle path and saved at once): on a managed device whose current
//!   bundle cannot be loaded the agent falls back to the seed, and the install-time hash must not bring back an account
//!   the school removed or a password it rotated. [`seed_gated`] is also what `admins` and `login` check.
//! - Who may sign in as it is `pam-check`'s business ([`super::login::LoginPolicy::it_account`]); its sudoers and polkit
//!   entries are the `admins` step's ([`owned`]).

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use anyhow::{bail, Context, Result};
use mastersos_bundle::{checks, ItAccount, ItemResult, Seed, IT_ACCOUNT_USER};

use super::{failed, ok, Env, Step};
use crate::apply::ApplyContext;
use crate::runner::{run_ok, run_ok_redacted, Cmd};
use crate::safefs;

/// The report item's name.
pub const ITEM: &str = "it_account";

/// AccountsService's per-user records (relative to the system root).
pub const ACCOUNTS_DIR: &str = "var/lib/AccountsService/users";

/// The account's GECOS comment.
pub const COMMENT: &str = "IT maintenance";

/// Reported when an `itadmin` exists that the agent did not create.
pub const FOREIGN: &str =
    "a local account named itadmin exists that MastersOS did not create; remove or rename it";

/// Reported when the IT account is not wanted and an `itadmin` exists that is not recorded as ours.
pub const NOT_LOCKING: &str =
    "itadmin exists but this agent has no record of creating it; not locking";

/// Reported when `system-state.json` could not be read this round.
pub const STATE_UNREADABLE: &str =
    "system-state.json could not be read this round; leaving the IT account as it is";

pub fn step() -> Step {
    Step {
        name: "it_account",
        fast: true,
        run,
        without_bundle: Some(run_seed),
    }
}

fn run(ctx: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
    let mut problems = Vec::new();
    // From now on the seed no longer governs the account. Saved at once: a later seed round must see it even when this
    // round ends early.
    if !env.sys.bundle_applied && !env.sys.load_failed {
        env.sys.bundle_applied = true;
        if let Err(e) = env.sys.save(env.paths) {
            problems.push(format!("saving system-state.json failed: {e:#}"));
        }
    }
    converge_with(env, ctx.config.it_account.as_ref(), problems)
}

fn run_seed(seed: &Seed, env: &mut Env) -> Vec<ItemResult> {
    if env.sys.load_failed {
        return vec![failed(ITEM, STATE_UNREADABLE.into())];
    }
    if seed_gated(env.sys) {
        // A bundle has been applied here before: its settings govern the account, not the install-time seed.
        return vec![ok(ITEM)];
    }
    converge(env, seed.it_account.as_ref())
}

/// The seed must leave the IT account (and its admin and login entries) alone: a bundle was applied on this device
/// before, or this round's state could not be read (so that is unknown).
pub fn seed_gated(sys: &super::SysState) -> bool {
    sys.bundle_applied || sys.load_failed
}

/// The account to keep: `it_account` when its hash passes [`checks::it_password_hash`], else `None`.
pub fn wanted(it: Option<&ItAccount>) -> Option<&ItAccount> {
    it.filter(|a| checks::it_password_hash(&a.password_hash).is_ok())
}

/// Brings `itadmin` to the wanted state. One report item; the hash never appears in it.
pub fn converge(env: &mut Env, want: Option<&ItAccount>) -> Vec<ItemResult> {
    converge_with(env, want, Vec::new())
}

fn converge_with(
    env: &mut Env,
    want: Option<&ItAccount>,
    mut problems: Vec<String>,
) -> Vec<ItemResult> {
    if env.sys.load_failed {
        problems.push(STATE_UNREADABLE.into());
        return vec![failed(ITEM, problems.join("; "))];
    }
    let valid = match want {
        Some(a) => match checks::it_password_hash(&a.password_hash) {
            Ok(()) => Some(a),
            Err(e) => {
                // The message never echoes the hash; the account is handled as not wanted.
                problems.push(e);
                None
            }
        },
        None => None,
    };
    let r = match valid {
        Some(a) => ensure(env, &a.password_hash, &mut problems),
        None => retire(env),
    };
    if let Err(e) = r {
        problems.push(format!("{e:#}"));
    }
    vec![if problems.is_empty() {
        ok(ITEM)
    } else {
        failed(ITEM, problems.join("; "))
    }]
}

/// Whether an `itadmin` exists and is the one the agent created (its uid is the recorded one).
pub fn owned(env: &Env) -> bool {
    match (passwd_uid(&env.paths.root), env.sys.it_account_uid) {
        (Ok(Some(uid)), Some(mine)) => uid == mine,
        _ => false,
    }
}

/// `problems` takes what went wrong without stopping the rest (recording ownership, refreshing the login policy).
fn ensure(env: &mut Env, hash: &str, problems: &mut Vec<String>) -> Result<()> {
    let root = env.paths.root.clone();
    let existing = passwd_uid(&root)?;
    if let Some(uid) = existing {
        if env.sys.it_account_uid != Some(uid) {
            bail!(FOREIGN);
        }
    }
    // Before useradd: accounts-daemon reads the record when it first sees the account.
    hide_from_user_list(&root)?;
    if existing.is_none() {
        run_ok(
            env.runner,
            Cmd::new(
                "useradd",
                &[
                    "-m",
                    "-U",
                    "-s",
                    "/bin/bash",
                    "-c",
                    COMMENT,
                    IT_ACCOUNT_USER,
                ],
            ),
        )?;
        let uid = passwd_uid(&root)?.with_context(|| {
            format!("useradd succeeded but /etc/passwd has no {IT_ACCOUNT_USER}")
        })?;
        env.sys.it_account_uid = Some(uid);
        // Saved now, not at the end of the round: a crash before then would leave an account nobody owns.
        if let Err(e) = env.sys.save(env.paths) {
            problems.push(format!(
                "recording the IT account in system-state.json failed: {e:#}"
            ));
        }
        // `login` ran before this step: give the policy the new uid so itadmin can sign in this round.
        if let Err(e) = super::login::set_it_account_uid(env.paths, uid) {
            problems.push(format!("updating the login policy failed: {e:#}"));
        }
    }
    let cur = shadow_entry(&root)?;
    let mut unlock = !cur.expire.is_empty();
    if cur.hash != hash {
        // Redacted: the error carries only the exit code, never chpasswd's stderr.
        let line = format!("{IT_ACCOUNT_USER}:{hash}\n").into_bytes();
        run_ok_redacted(env.runner, Cmd::new("chpasswd", &["-e"]).stdin(line))
            .context("setting the IT account password")?;
        unlock = true;
    }
    if unlock {
        run_ok(
            env.runner,
            Cmd::new("usermod", &["-U", "-e", "", IT_ACCOUNT_USER]),
        )?;
    }
    Ok(())
}

fn retire(env: &mut Env) -> Result<()> {
    let root = env.paths.root.clone();
    let Some(uid) = passwd_uid(&root)? else {
        return Ok(());
    };
    // Not recorded as ours: not locked (it may be somebody else's), but said, never a silent ok — it may also be ours
    // with the record lost.
    if env.sys.it_account_uid != Some(uid) {
        bail!(NOT_LOCKING);
    }
    let cur = shadow_entry(&root)?;
    if cur.hash.starts_with('!') && cur.expire == "1" {
        return Ok(());
    }
    run_ok(
        env.runner,
        Cmd::new("usermod", &["-L", "-e", "1", IT_ACCOUNT_USER]),
    )?;
    Ok(())
}

fn read_etc(root: &Path, name: &str) -> Result<Option<String>> {
    let etc = safefs::open_dir(root, Path::new("etc"), false).context("opening /etc")?;
    match safefs::read_at(&etc, name).with_context(|| format!("reading /etc/{name}"))? {
        None => Ok(None),
        Some(b) => String::from_utf8(b)
            .map(Some)
            .with_context(|| format!("/etc/{name} is not UTF-8")),
    }
}

/// The uid of `itadmin` in `/etc/passwd`; `None` when there is no such line (or no file).
fn passwd_uid(root: &Path) -> Result<Option<u32>> {
    let Some(text) = read_etc(root, "passwd")? else {
        return Ok(None);
    };
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() >= 7 && f[0] == IT_ACCOUNT_USER {
            let uid = f[2]
                .parse::<u32>()
                .with_context(|| format!("/etc/passwd: bad uid for {IT_ACCOUNT_USER}"))?;
            return Ok(Some(uid));
        }
    }
    Ok(None)
}

/// `itadmin`'s line in `/etc/shadow`: the password field and the account expiry field.
struct ShadowEntry {
    hash: String,
    expire: String,
}

fn shadow_entry(root: &Path) -> Result<ShadowEntry> {
    let text = read_etc(root, "shadow")?.context("/etc/shadow does not exist")?;
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.first() == Some(&IT_ACCOUNT_USER) {
            return Ok(ShadowEntry {
                hash: f.get(1).copied().unwrap_or_default().to_string(),
                expire: f.get(7).copied().unwrap_or_default().to_string(),
            });
        }
    }
    bail!("/etc/shadow has no entry for {IT_ACCOUNT_USER}")
}

/// Writes `SystemAccount=true` into the account's AccountsService record (0600), keeping every other key.
fn hide_from_user_list(root: &Path) -> Result<()> {
    let dir = safefs::open_dir(root, Path::new(ACCOUNTS_DIR), true)
        .with_context(|| format!("opening /{ACCOUNTS_DIR}"))?;
    let cur = safefs::read_at(&dir, IT_ACCOUNT_USER)?
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let text = with_system_account(&cur);
    safefs::write_at(&dir, IT_ACCOUNT_USER, text.as_bytes(), 0o600)
        .with_context(|| format!("writing /{ACCOUNTS_DIR}/{IT_ACCOUNT_USER}"))?;
    Ok(())
}

/// `keyfile` (a GKeyFile) with `SystemAccount=true` in its `[User]` group: an existing `SystemAccount=` line there is
/// replaced, otherwise the key goes right after the group header; no `[User]` group → one is added at the end.
pub fn with_system_account(keyfile: &str) -> String {
    const KEY: &str = "SystemAccount=true";
    let mut out: Vec<String> = Vec::new();
    let mut in_user = false;
    let mut seen_user = false;
    let mut done = false;
    for line in keyfile.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_user = t == "[User]";
            out.push(line.to_string());
            if in_user && !seen_user {
                seen_user = true;
                out.push(KEY.to_string());
                done = true;
            }
            continue;
        }
        if in_user && t.split('=').next().map(str::trim) == Some("SystemAccount") {
            // Already written right after the header: drop the old line.
            continue;
        }
        out.push(line.to_string());
    }
    if !done {
        out.push("[User]".to_string());
        out.push(KEY.to_string());
    }
    let mut s = out.join("\n");
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::super::tests::{paths, tmp_root};
    use super::super::{SysState, SystemApplier};
    use super::*;
    use crate::apply::{Applier, Phase};
    use crate::runner::{FakeRunner, Output, Runner};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::Arc;

    const H1: &str = "$y$j9T$saltsaltsaltsalt$H1hashhashhashhashhashhashhashhash";
    const H2: &str = "$y$j9T$saltsaltsaltsalt$H2hashhashhashhashhashhashhashhash";
    const PASSWD: &str =
        "root:x:0:0:root:/root:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/bash\n";
    const SHADOW: &str = "root:*:19000:0:99999:7:::\nalice:$y$alice:19000:0:99999:7:::\n";

    /// A fake runner that also plays `useradd`, `chpasswd -e` and `usermod -L/-U` on the temporary root's
    /// `/etc/passwd` and `/etc/shadow`, so a second round sees what the first did.
    struct SysRunner {
        root: PathBuf,
        fake: FakeRunner,
    }

    impl SysRunner {
        fn new(root: &Path) -> SysRunner {
            SysRunner {
                root: root.to_path_buf(),
                fake: FakeRunner::new(),
            }
        }

        fn edit_shadow(&self, f: impl Fn(&mut Vec<String>)) {
            let p = self.root.join("etc/shadow");
            let text = fs::read_to_string(&p).unwrap();
            let lines = text
                .lines()
                .map(|l| {
                    let mut v: Vec<String> = l.split(':').map(str::to_string).collect();
                    if v[0] == IT_ACCOUNT_USER {
                        f(&mut v);
                    }
                    v.join(":")
                })
                .collect::<Vec<_>>();
            fs::write(&p, lines.join("\n") + "\n").unwrap();
        }
    }

    impl Runner for SysRunner {
        fn run(&self, cmd: &Cmd) -> anyhow::Result<Output> {
            let out = self.fake.run(cmd)?;
            if out.code != 0 {
                return Ok(out);
            }
            let args: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
            match (cmd.program.as_str(), args.as_slice()) {
                ("useradd", [.., name]) => {
                    let mut p = fs::read_to_string(self.root.join("etc/passwd")).unwrap();
                    p.push_str(&format!(
                        "{name}:x:1002:1002:{COMMENT}:/home/{name}:/bin/bash\n"
                    ));
                    fs::write(self.root.join("etc/passwd"), p).unwrap();
                    let mut s = fs::read_to_string(self.root.join("etc/shadow")).unwrap();
                    s.push_str(&format!("{name}:!:19000:0:99999:7:::\n"));
                    fs::write(self.root.join("etc/shadow"), s).unwrap();
                }
                ("chpasswd", ["-e"]) => {
                    let input = String::from_utf8(cmd.stdin.clone().unwrap()).unwrap();
                    let (_, h) = input.trim_end().split_once(':').unwrap();
                    let h = h.to_string();
                    self.edit_shadow(|v| v[1] = h.clone());
                }
                ("usermod", ["-L", "-e", "1", _]) => self.edit_shadow(|v| {
                    if !v[1].starts_with('!') {
                        v[1] = format!("!{}", v[1]);
                    }
                    v[7] = "1".into();
                }),
                ("usermod", ["-U", "-e", "", _]) => self.edit_shadow(|v| {
                    v[1] = v[1].trim_start_matches('!').to_string();
                    v[7] = String::new();
                }),
                _ => {}
            }
            Ok(out)
        }
    }

    fn root_with(passwd: &str, shadow: &str) -> tempfile::TempDir {
        let root = tmp_root();
        fs::create_dir_all(root.path().join("etc")).unwrap();
        fs::write(root.path().join("etc/passwd"), passwd).unwrap();
        fs::write(root.path().join("etc/shadow"), shadow).unwrap();
        root
    }

    fn it(h: &str) -> ItAccount {
        ItAccount {
            password_hash: h.into(),
        }
    }

    fn go(
        root: &Path,
        r: &SysRunner,
        sys: &mut SysState,
        want: Option<&ItAccount>,
    ) -> Vec<ItemResult> {
        let p = paths(root);
        converge(
            &mut Env {
                paths: &p,
                runner: r,
                sys,
            },
            want,
        )
    }

    fn accounts_file(root: &Path) -> PathBuf {
        root.join(ACCOUNTS_DIR).join(IT_ACCOUNT_USER)
    }

    const CREATE: [&str; 3] = [
        "useradd -m -U -s /bin/bash -c IT maintenance itadmin",
        "chpasswd -e",
        "usermod -U -e  itadmin",
    ];

    fn assert_created(root: &Path, r: &SysRunner, uid: Option<u32>) {
        assert_eq!(r.fake.calls(), CREATE);
        assert_eq!(
            r.fake.stdin_of("chpasswd"),
            Some(format!("itadmin:{H1}\n").into_bytes())
        );
        assert_eq!(uid, Some(1002));
        let acc = accounts_file(root);
        assert!(fs::read_to_string(&acc)
            .unwrap()
            .contains("SystemAccount=true"));
        assert_eq!(
            fs::metadata(&acc).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }

    #[test]
    fn creates_account_and_sets_hash() {
        let root = root_with(PASSWD, SHADOW);
        let r = SysRunner::new(root.path());
        let mut sys = SysState::default();
        let out = go(root.path(), &r, &mut sys, Some(&it(H1)));
        assert_eq!(out, vec![ok(ITEM)]);
        assert_created(root.path(), &r, sys.it_account_uid);
    }

    #[test]
    fn hash_goes_to_chpasswd_stdin_only() {
        let root = root_with(PASSWD, SHADOW);
        let r = SysRunner::new(root.path());
        let mut sys = SysState::default();
        let mut out = go(root.path(), &r, &mut sys, Some(&it(H1)));
        out.extend(go(root.path(), &r, &mut sys, Some(&it(H2))));
        // And a broken hash: reported without echoing it.
        let bad = format!("{H1}!");
        out.extend(go(root.path(), &r, &mut sys, Some(&it(&bad))));
        for line in r.fake.calls() {
            assert!(
                !line.contains(H1) && !line.contains(H2),
                "argv carries the hash: {line}"
            );
            assert!(!line.contains("j9T"));
        }
        let json = serde_json::to_string(&out).unwrap() + &serde_json::to_string(&sys).unwrap();
        assert!(
            !json.contains("j9T"),
            "report or SysState carries the hash: {json}"
        );
        assert!(!format!("{:?}", it(H1)).contains("j9T"));
        assert!(!out.last().unwrap().ok);
    }

    #[test]
    fn unchanged_hash_runs_nothing() {
        let root = root_with(PASSWD, SHADOW);
        let r = SysRunner::new(root.path());
        let mut sys = SysState::default();
        go(root.path(), &r, &mut sys, Some(&it(H1)));
        let n = r.fake.calls().len();
        let out = go(root.path(), &r, &mut sys, Some(&it(H1)));
        assert_eq!(out, vec![ok(ITEM)]);
        assert_eq!(r.fake.calls().len(), n, "{:?}", r.fake.calls());
    }

    #[test]
    fn hash_change_updates_password() {
        let root = root_with(PASSWD, SHADOW);
        let r = SysRunner::new(root.path());
        let mut sys = SysState::default();
        go(root.path(), &r, &mut sys, Some(&it(H1)));
        let n = r.fake.calls().len();
        let out = go(root.path(), &r, &mut sys, Some(&it(H2)));
        assert_eq!(out, vec![ok(ITEM)]);
        let calls = r.fake.calls()[n..].to_vec();
        assert_eq!(
            calls
                .iter()
                .filter(|c| c.starts_with("chpasswd -e"))
                .count(),
            1
        );
        assert!(!calls.iter().any(|c| c.starts_with("useradd")));
        assert_eq!(
            r.fake.stdin_of("chpasswd"),
            Some(format!("itadmin:{H2}\n").into_bytes())
        );
        assert_eq!(sys.it_account_uid, Some(1002));
    }

    #[test]
    fn removed_locks_not_deletes() {
        let root = root_with(PASSWD, SHADOW);
        let r = SysRunner::new(root.path());
        let mut sys = SysState::default();
        go(root.path(), &r, &mut sys, Some(&it(H1)));
        let n = r.fake.calls().len();
        assert_eq!(go(root.path(), &r, &mut sys, None), vec![ok(ITEM)]);
        assert_eq!(r.fake.calls()[n..], ["usermod -L -e 1 itadmin"]);
        assert!(!r.fake.calls().iter().any(|c| c.starts_with("userdel")));
        // Already locked: nothing more.
        go(root.path(), &r, &mut sys, None);
        assert_eq!(r.fake.calls().len(), n + 1);
        // Wanted again: the password is set again and the account unlocked.
        go(root.path(), &r, &mut sys, Some(&it(H1)));
        assert_eq!(
            r.fake.calls()[n + 1..],
            ["chpasswd -e", "usermod -U -e  itadmin"]
        );
    }

    #[test]
    fn invalid_hash_is_reported_and_locks() {
        let root = root_with(PASSWD, SHADOW);
        let r = SysRunner::new(root.path());
        let mut sys = SysState::default();
        go(root.path(), &r, &mut sys, Some(&it(H1)));
        let n = r.fake.calls().len();
        let out = go(root.path(), &r, &mut sys, Some(&it("plaintext-password")));
        assert!(!out[0].ok);
        assert!(!out[0].detail.as_ref().unwrap().contains("plaintext"));
        assert_eq!(r.fake.calls()[n..], ["usermod -L -e 1 itadmin"]);
        // No account yet and a bad hash: nothing is created.
        let fresh = root_with(PASSWD, SHADOW);
        let r2 = SysRunner::new(fresh.path());
        let mut sys2 = SysState::default();
        let out = go(fresh.path(), &r2, &mut sys2, Some(&it("$1$md5")));
        assert!(!out[0].ok);
        assert!(r2.fake.calls().is_empty());
        assert_eq!(sys2.it_account_uid, None);
    }

    #[test]
    fn foreign_itadmin_not_adopted() {
        let passwd = format!("{PASSWD}itadmin:x:1005:1005::/home/itadmin:/bin/bash\n");
        let shadow = format!("{SHADOW}itadmin:$y$theirs:19000:0:99999:7:::\n");
        let root = root_with(&passwd, &shadow);
        let r = SysRunner::new(root.path());
        let mut sys = SysState::default();
        let out = go(root.path(), &r, &mut sys, Some(&it(H1)));
        assert!(!out[0].ok);
        assert!(out[0].detail.as_ref().unwrap().contains("did not create"));
        assert!(r.fake.calls().is_empty());
        assert!(!accounts_file(root.path()).exists());
        assert_eq!(sys.it_account_uid, None);
        // A recorded uid that is not this account's: still not ours.
        sys.it_account_uid = Some(1002);
        let out = go(root.path(), &r, &mut sys, Some(&it(H1)));
        assert!(out[0].detail.as_ref().unwrap().contains("did not create"));
        // Not wanted: not locked, but reported (never a silent ok).
        let out = go(root.path(), &r, &mut sys, None);
        assert_eq!(out, vec![failed(ITEM, NOT_LOCKING.into())]);
        assert!(r.fake.calls().is_empty());
        let p = paths(root.path());
        let env = Env {
            paths: &p,
            runner: &r,
            sys: &mut sys,
        };
        assert!(!owned(&env));
    }

    /// The uid is on disk right after `useradd`: a crash before the end of the round keeps ownership.
    #[test]
    fn uid_persisted_right_after_useradd() {
        let root = root_with(PASSWD, SHADOW);
        let p = paths(root.path());
        let r = SysRunner::new(root.path());
        let mut sys = SysState::default();
        go(root.path(), &r, &mut sys, Some(&it(H1)));
        // The in-memory state is dropped (as in a crash); only what was saved survives.
        drop(sys);
        let mut sys = SysState::load(&p).unwrap();
        assert_eq!(sys.it_account_uid, Some(1002));
        let n = r.fake.calls().len();
        assert_eq!(go(root.path(), &r, &mut sys, Some(&it(H2))), vec![ok(ITEM)]);
        assert_eq!(
            r.fake.calls()[n..],
            ["chpasswd -e", "usermod -U -e  itadmin"]
        );
        assert_eq!(go(root.path(), &r, &mut sys, None), vec![ok(ITEM)]);
        assert_eq!(r.fake.calls()[n + 2..], ["usermod -L -e 1 itadmin"]);
    }

    /// Ownership lost anyway (record gone): removing the account is reported, not a silent ok.
    #[test]
    fn retire_with_unknown_owner_reports_failure() {
        let root = root_with(PASSWD, SHADOW);
        let r = SysRunner::new(root.path());
        let mut sys = SysState::default();
        go(root.path(), &r, &mut sys, Some(&it(H1)));
        let n = r.fake.calls().len();
        let mut lost = SysState::default();
        let out = go(root.path(), &r, &mut lost, None);
        assert!(!out[0].ok);
        assert!(out[0]
            .detail
            .as_ref()
            .unwrap()
            .contains("no record of creating it"));
        assert_eq!(r.fake.calls().len(), n);
    }

    /// A round whose state could not be read creates, changes and locks nothing.
    #[test]
    fn useradd_refused_when_state_load_failed() {
        let root = root_with(PASSWD, SHADOW);
        let r = SysRunner::new(root.path());
        let mut sys = SysState {
            load_failed: true,
            ..SysState::default()
        };
        let out = go(root.path(), &r, &mut sys, Some(&it(H1)));
        assert_eq!(out, vec![failed(ITEM, STATE_UNREADABLE.into())]);
        assert!(r.fake.calls().is_empty());
        assert_eq!(sys.it_account_uid, None);
        // Through the applier, with system-state.json unreadable (a directory in its place).
        let r = Arc::new(SysRunner::new(root.path()));
        let a = SystemApplier::with_steps(paths(root.path()), r.clone(), vec![step()]);
        let state = paths(root.path()).var_dir.join("system-state.json");
        fs::create_dir_all(&state).unwrap();
        let mut seed =
            Seed::parse("server_url = \"https://m.school.ac.th\"\ntrust = []\n").unwrap();
        seed.it_account = Some(it(H1));
        let out = a.apply_without_bundle(&seed, Phase::Boot);
        assert!(out.iter().any(|o| o.item == ITEM && !o.ok));
        assert!(r.fake.calls().is_empty());
        assert!(!fs::read_to_string(root.path().join("etc/passwd"))
            .unwrap()
            .contains("itadmin"));
    }

    /// The new uid reaches the login policy that `login` wrote earlier in the same round.
    #[test]
    fn creation_refreshes_login_policy() {
        let root = root_with(PASSWD, SHADOW);
        let p = paths(root.path());
        let mut seed =
            Seed::parse("server_url = \"https://m.school.ac.th\"\ntrust = []\n").unwrap();
        seed.it_account = Some(it(H1));
        let pol = super::super::login::policy_from_seed(&seed);
        assert!(pol.it_account && pol.it_account_uid.is_none());
        super::super::login::write_policy(&p, &pol).unwrap();
        let r = SysRunner::new(root.path());
        let mut sys = SysState::default();
        go(root.path(), &r, &mut sys, Some(&it(H1)));
        let text = fs::read_to_string(p.var_dir.join("login/policy.json")).unwrap();
        let back: super::super::login::LoginPolicy = serde_json::from_str(&text).unwrap();
        assert_eq!(back.it_account_uid, Some(1002));
        assert!(!text.contains("j9T"));
    }

    fn seed_with(hash: &str) -> Seed {
        let mut seed =
            Seed::parse("server_url = \"https://m.school.ac.th\"\ntrust = []\n").unwrap();
        seed.it_account = Some(it(hash));
        seed
    }

    /// Fresh device: the seed sets the account up. Once a bundle has been applied (here one without `it_account`, which
    /// locks it), a later seed round (current bundle unreadable) neither re-passwords nor unlocks it, nor restores sudo.
    #[test]
    fn seed_does_not_revive_after_bundle() {
        use super::super::tests::with_ctx;
        use mastersos_bundle::School;
        use std::sync::atomic::AtomicBool;
        let root = root_with(PASSWD, SHADOW);
        let etc = root.path().join("etc");
        fs::create_dir_all(etc.join("sudoers.d")).unwrap();
        fs::create_dir_all(etc.join("polkit-1/rules.d")).unwrap();
        fs::write(
            etc.join("group"),
            "root:x:0:\nsudo:x:27:\nmastersos-localadmin:x:990:\n",
        )
        .unwrap();
        let r = Arc::new(SysRunner::new(root.path()));
        let a = SystemApplier::with_steps(
            paths(root.path()),
            r.clone(),
            vec![step(), super::super::admins::step()],
        );
        let sudoers = etc.join("sudoers.d/mastersos-admins");
        // Fresh: created, and admin.
        a.apply_without_bundle(&seed_with(H1), Phase::Boot);
        assert_eq!(r.fake.calls()[..3], CREATE);
        assert!(fs::read_to_string(&sudoers)
            .unwrap()
            .contains("itadmin ALL"));
        // Bundle without it_account: locked, sudo line gone, and the marker is on disk.
        let flag = AtomicBool::new(false);
        with_ctx(&School::default(), Phase::Full, &flag, |c| a.apply(c));
        assert!(r
            .fake
            .calls()
            .iter()
            .any(|c| c == "usermod -L -e 1 itadmin"));
        assert!(!sudoers.exists());
        assert!(SysState::load(&paths(root.path())).unwrap().bundle_applied);
        // Seed again (bundle unreadable), even with a different hash: nothing changes.
        let n = r.fake.calls().len();
        let out = a.apply_without_bundle(&seed_with(H2), Phase::Boot);
        assert!(out.iter().all(|o| o.ok), "{out:?}");
        assert_eq!(r.fake.calls().len(), n, "{:?}", &r.fake.calls()[n..]);
        assert!(!sudoers.exists());
        let shadow = fs::read_to_string(etc.join("shadow")).unwrap();
        assert!(shadow.contains(&format!("itadmin:!{H1}:")));
    }

    #[test]
    fn seed_creates_account_before_bundle() {
        let root = root_with(PASSWD, SHADOW);
        let r = Arc::new(SysRunner::new(root.path()));
        let a = SystemApplier::with_steps(paths(root.path()), r.clone(), vec![step()]);
        let mut seed =
            Seed::parse("server_url = \"https://m.school.ac.th\"\ntrust = []\n").unwrap();
        seed.it_account = Some(it(H1));
        let out = a.apply_without_bundle(&seed, Phase::Boot);
        assert_eq!(out, vec![ok(ITEM)]);
        let sys = SysState::load(&paths(root.path())).unwrap();
        assert_created(root.path(), &r, sys.it_account_uid);
    }

    #[test]
    fn accounts_record_keeps_other_keys() {
        assert_eq!(with_system_account(""), "[User]\nSystemAccount=true\n");
        assert_eq!(
            with_system_account("[User]\nLanguage=th_TH.UTF-8\nSystemAccount=false\nIcon=/x\n"),
            "[User]\nSystemAccount=true\nLanguage=th_TH.UTF-8\nIcon=/x\n"
        );
        assert_eq!(
            with_system_account("[Other]\nA=1\n"),
            "[Other]\nA=1\n[User]\nSystemAccount=true\n"
        );
        let once = with_system_account("[User]\nSession=mastersos\n");
        assert_eq!(with_system_account(&once), once);
    }

    #[test]
    fn sys_state_without_field_parses() {
        let s: SysState = serde_json::from_str("{}").unwrap();
        assert_eq!(s.it_account_uid, None);
    }
}
