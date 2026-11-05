//! Who sent a help request (design 2026-11-05 §5, plan Task 5, Ruling P4). Only the socket's peer credentials
//! (`SO_PEERCRED`: uid and pid) count; nothing the dialog sends names a user. The rules, in order:
//!
//! 1. **The login screen → `none`, session `login`.** GDM runs the greeter as its own accounts: `gdm`, and on GDM 49+
//!    dynamic `gdm-greeter`, `gdm-greeter-2`, … users (the same names `system/lock.rs` leaves alone). Their logind
//!    session has `Class=greeter` (GDM opens it through pam_systemd with `XDG_SESSION_CLASS=greeter`). We ask logind
//!    for the pid's session (`GetSessionByPID`, never the pid's cgroup path, which a user can fake with a scope of
//!    their own) and, when the pid is in no session (GDM 50 runs the greeter's shell under the greeter user's systemd
//!    user manager, outside the scope), for all sessions of the uid; any `greeter` decides. A session counts only when
//!    logind says its `User` is the peer's uid. A passwd name `gdm` or `gdm-greeter*`
//!    is the login screen too, whatever logind says: those accounts are never people. Not verified on a GDM 50
//!    machine yet: plan Task 8 checks it on a VM.
//! 2. **The guest → `guest`.** uid 1999 ([`GUEST_UID`]), named from passwd (`guest`).
//! 3. **A locked app (kiosk) → `none`, session `kiosk:<app id>`.** The kiosk step makes one account per app, named
//!    `kiosk-<id>` with a uid in [`KIOSK_UIDS`] (`system/kiosk.rs`; `kiosk_session.rs` derives the id from the name the
//!    same way, [`id_from_user`]) and records each one, id → uid and name, in `system-state.json`
//!    ([`SysState::kiosk_accounts`](crate::system::SysState::kiosk_accounts), written before `useradd`). All three must
//!    hold: a uid in the range with another name, a `kiosk-*` name outside it, or an account the kiosk step has no
//!    record of (or whose record cannot be read) is not a locked app. Nobody signs in to a kiosk account, so there is no
//!    person to name.
//! 4. **An SSO account → `sso`.** authd serves school accounts through its NSS module, never `/etc/passwd`: the entry
//!    is found with `getent -s authd passwd <uid>`. A name with `@` is an SSO account too (`login::decide` and
//!    `lock.rs` classify by the `@` the same way), so an authd range moved somewhere else still reads as SSO.
//! 5. **Anyone else → `local`**, named from passwd (no entry: no name).
//!
//! The session the dialog sends is never used: it follows from the identity (`login` for the greeter, `kiosk:<id>`
//! for a locked app, `desktop` otherwise), so the derived one always wins over a conflicting claim.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use mastersos_bundle::diag::{SupportUser, SupportUserKind};

use crate::kiosk_session::id_from_user;
use crate::runner::{run_ok, Cmd, Runner};
use crate::system::ephemeral::KIOSK_UIDS;
use crate::system::guest::GUEST_UID;
use crate::system::{SysPaths, SysState};

const CMD_TIMEOUT: Duration = Duration::from_secs(5);

/// The socket peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub uid: u32,
    /// `None` where the platform does not tell.
    pub pid: Option<u32>,
}

/// A passwd entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    /// Served by authd's NSS module (an SSO account).
    pub authd: bool,
}

/// What [`identify`] asks the system; tests use a fake.
pub trait Who: Send + Sync {
    fn account(&self, uid: u32) -> Option<Account>;
    /// The peer is GDM's login screen by its logind session class (rule 1).
    fn is_greeter(&self, peer: &Peer) -> bool;
    /// The kiosk step's record of the account for app `id`: its (uid, name). `None` when there is none or the state
    /// cannot be read (rule 3).
    fn kiosk_record(&self, id: &str) -> Option<(u32, String)>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub user: SupportUser,
    /// `login`, `desktop` or `kiosk:<app id>`.
    pub session: String,
}

fn is_gdm_name(name: &str) -> bool {
    name == "gdm" || name.starts_with("gdm-greeter")
}

/// The rules in the module comment.
pub fn identify(peer: &Peer, who: &dyn Who) -> Identity {
    let account = who.account(peer.uid);
    let nobody = |session: String| Identity {
        user: SupportUser {
            kind: SupportUserKind::None,
            name: None,
        },
        session,
    };
    if account.as_ref().is_some_and(|a| is_gdm_name(&a.name)) || who.is_greeter(peer) {
        return nobody("login".into());
    }
    let named = |kind| Identity {
        user: SupportUser {
            kind,
            name: account.as_ref().map(|a| a.name.clone()),
        },
        session: "desktop".into(),
    };
    if peer.uid == GUEST_UID {
        return named(SupportUserKind::Guest);
    }
    if KIOSK_UIDS.contains(&peer.uid) {
        if let Some(a) = &account {
            if let Ok(id) = id_from_user(&a.name) {
                if who.kiosk_record(&id) == Some((peer.uid, a.name.clone())) {
                    return nobody(format!("kiosk:{id}"));
                }
            }
        }
    }
    match &account {
        Some(a) if a.authd || a.name.contains('@') => named(SupportUserKind::Sso),
        _ => named(SupportUserKind::Local),
    }
}

/// The real lookups: `getent`, `busctl` and `loginctl` through the runner, the kiosk records under `root`.
pub struct SystemWho {
    runner: Arc<dyn Runner>,
    /// Where `system-state.json` is (`<root>/var/lib/mastersos-system`).
    sys: SysPaths,
}

impl SystemWho {
    pub fn new(runner: Arc<dyn Runner>, root: PathBuf) -> SystemWho {
        let d = SysPaths::default();
        let under = |p: &std::path::Path| root.join(p.strip_prefix("/").unwrap_or(p));
        let sys = SysPaths {
            var_dir: under(&d.var_dir),
            public_dir: under(&d.public_dir),
            state_dir: under(&d.state_dir),
            root: root.clone(),
        };
        SystemWho { runner, sys }
    }

    fn run(&self, args: &[&str], program: &str) -> Option<String> {
        run_ok(
            self.runner.as_ref(),
            Cmd::new(program, args).timeout(CMD_TIMEOUT),
        )
        .ok()
    }

    /// `getent [-s <service>] passwd <uid>`: the name, when the entry is for this uid.
    fn getent(&self, service: Option<&str>, uid: u32) -> Option<String> {
        let uid_s = uid.to_string();
        let mut args = Vec::new();
        if let Some(s) = service {
            args.extend(["-s", s]);
        }
        args.extend(["passwd", uid_s.as_str()]);
        let out = self.run(&args, "getent")?;
        let line = out.lines().next()?;
        let f: Vec<&str> = line.split(':').collect();
        (f.len() >= 7 && f[2] == uid_s && !f[0].is_empty()).then(|| f[0].to_string())
    }

    /// A session's `Class` and `User` (uid) from logind.
    fn session(&self, id: &str) -> Option<(String, u32)> {
        if !session_id_ok(id) {
            return None;
        }
        let out = self.run(
            &["show-session", id, "-p", "Class", "-p", "User"],
            "loginctl",
        )?;
        let (mut class, mut user) = (None, None);
        for l in out.lines() {
            match l.split_once('=') {
                Some(("Class", v)) => class = Some(v.trim().to_string()),
                Some(("User", v)) => user = v.trim().parse::<u32>().ok(),
                _ => {}
            }
        }
        Some((class?, user?))
    }

    /// logind's session for the pid (`GetSessionByPID`). Not the pid's cgroup path: a user can make a scope named
    /// `session-<id>.scope` under their own user manager (`systemd-run --user --scope -u …`), logind cannot be told so.
    fn session_of_pid(&self, pid: u32) -> Option<String> {
        let pid = pid.to_string();
        let out = self.run(
            &[
                "call",
                "org.freedesktop.login1",
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
                "GetSessionByPID",
                "u",
                pid.as_str(),
            ],
            "busctl",
        )?;
        // `o "/org/freedesktop/login1/session/<escaped id>"`
        let path = out.trim().strip_prefix("o ")?.trim_matches('"');
        let id = unescape_object_path(path.strip_prefix("/org/freedesktop/login1/session/")?)?;
        session_id_ok(&id).then_some(id)
    }

    /// The class of session `id` when it is `uid`'s; a session of someone else is never trusted.
    fn class_for(&self, id: &str, uid: u32) -> Option<String> {
        match self.session(id)? {
            (class, user) if user == uid => Some(class),
            (_, user) => {
                log::warn!(
                    "support: session {id} is uid {user}'s, not the peer's ({uid}); ignoring it"
                );
                None
            }
        }
    }
}

/// sd-bus object path labels escape every byte that is not a letter or digit as `_` and two hex digits.
fn unescape_object_path(label: &str) -> Option<String> {
    let b = label.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'_' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Session ids are letters and digits (never taken for an option).
fn session_id_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

impl Who for SystemWho {
    fn account(&self, uid: u32) -> Option<Account> {
        if let Some(name) = self.getent(Some("authd"), uid) {
            return Some(Account { name, authd: true });
        }
        self.getent(None, uid)
            .map(|name| Account { name, authd: false })
    }

    fn kiosk_record(&self, id: &str) -> Option<(u32, String)> {
        // One small JSON file, read only for uids in the kiosk range.
        let state = match SysState::peek(&self.sys) {
            Ok(s) => s?,
            Err(e) => {
                log::warn!("support: reading the kiosk accounts failed: {e:#}");
                return None;
            }
        };
        let a = state.kiosk_accounts.get(id)?;
        Some((a.uid, a.name.clone()))
    }

    fn is_greeter(&self, peer: &Peer) -> bool {
        if let Some(id) = peer.pid.and_then(|p| self.session_of_pid(p)) {
            if let Some(class) = self.class_for(&id, peer.uid) {
                return class == "greeter";
            }
        }
        let uid = peer.uid.to_string();
        let Some(ids) = self.run(
            &["show-user", uid.as_str(), "-p", "Sessions", "--value"],
            "loginctl",
        ) else {
            return false;
        };
        ids.split_whitespace()
            .any(|id| self.class_for(id, peer.uid).as_deref() == Some("greeter"))
    }
}
