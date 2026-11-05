//! Who sent a help request (design 2026-11-05 §5, plan Task 5, Ruling P4). Only the socket's peer credentials
//! (`SO_PEERCRED`: uid and pid) count; nothing the dialog sends names a user. The rules, in order:
//!
//! 1. **The login screen → `none`, session `login`.** GDM runs the greeter as its own accounts: `gdm`, and on GDM 49+
//!    dynamic `gdm-greeter`, `gdm-greeter-2`, … users (the same names `system/lock.rs` leaves alone). Their logind
//!    session has `Class=greeter` (GDM opens it through pam_systemd with `XDG_SESSION_CLASS=greeter`). We ask logind
//!    for the class of the pid's own session (`session-<id>.scope` in `/proc/<pid>/cgroup`) and, when the pid is not in
//!    a session scope (GDM 50 runs the greeter's shell under the greeter user's systemd user manager, outside the
//!    scope), for the classes of all sessions of the uid; any `greeter` decides. A passwd name `gdm` or `gdm-greeter*`
//!    is the login screen too, whatever logind says: those accounts are never people. Not verified on a GDM 50
//!    machine yet: plan Task 8 checks it on a VM.
//! 2. **The guest → `guest`.** uid 1999 ([`GUEST_UID`]), named from passwd (`guest`).
//! 3. **A locked app (kiosk) → `none`, session `kiosk:<app id>`.** The kiosk step makes one account per app, named
//!    `kiosk-<id>` with a uid in [`KIOSK_UIDS`] (`system/kiosk.rs`; `kiosk_session.rs` derives the id from the name the
//!    same way, [`id_from_user`]). Both must hold: a uid in the range with another name, or a `kiosk-*` name outside
//!    it, is not a locked app. Nobody signs in to a kiosk account, so there is no person to name.
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
        if let Some(id) = account.as_ref().and_then(|a| id_from_user(&a.name).ok()) {
            return nobody(format!("kiosk:{id}"));
        }
    }
    match &account {
        Some(a) if a.authd || a.name.contains('@') => named(SupportUserKind::Sso),
        _ => named(SupportUserKind::Local),
    }
}

/// The real lookups: `getent` and `loginctl` through the runner, `/proc` under `root`.
pub struct SystemWho {
    runner: Arc<dyn Runner>,
    root: PathBuf,
}

impl SystemWho {
    pub fn new(runner: Arc<dyn Runner>, root: PathBuf) -> SystemWho {
        SystemWho { runner, root }
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

    fn session_class(&self, id: &str) -> Option<String> {
        if !session_id_ok(id) {
            return None;
        }
        self.run(&["show-session", id, "-p", "Class", "--value"], "loginctl")
            .map(|s| s.trim().to_string())
    }

    /// The logind session of the pid from its cgroup (`…/session-<id>.scope/…`).
    fn session_of_pid(&self, pid: u32) -> Option<String> {
        let text = std::fs::read_to_string(self.root.join(format!("proc/{pid}/cgroup"))).ok()?;
        let path = text.lines().find_map(|l| l.strip_prefix("0::"))?;
        path.split('/').find_map(|c| {
            let id = c.strip_prefix("session-")?.strip_suffix(".scope")?;
            session_id_ok(id).then(|| id.to_string())
        })
    }
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

    fn is_greeter(&self, peer: &Peer) -> bool {
        if let Some(id) = peer.pid.and_then(|p| self.session_of_pid(p)) {
            if let Some(class) = self.session_class(&id) {
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
            .any(|id| self.session_class(id).as_deref() == Some("greeter"))
    }
}
