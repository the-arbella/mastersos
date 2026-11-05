//! "Get help" on the machine (design 2026-11-05 remote diagnostics and help §5, plan Task 5): the local half.
//!
//! - [`host`]: `mastersos-agent support host`, the root service behind `/run/mastersos-support/support.sock`; checks a help
//!   request, decides who sent it ([`identity`]), queues it ([`store`]) and starts the sender ([`kick_sender`]).
//! - [`native_host`]: `mastersos-agent support native-host`, the kiosk extension's native messaging host, which
//!   forwards to the same socket.
//! - [`step`]: the settings step that writes `support.json` (`{"enabled": bool}`, 0644) into the public directory for
//!   the dialogs and the host (`[config.support] enabled`; no file means off).
//!
//! Sending the queue to the cloud (`POST /v1/support`, the attachment) is the sender's job in
//! `mastersos-upload.service` (Task 5b).

pub mod host;
pub mod identity;
pub mod native_host;
pub mod store;

use std::ffi::OsString;
use std::process::ExitCode;
use std::time::Duration;

use mastersos_bundle::ItemResult;
use serde::Serialize;

use crate::apply::ApplyContext;
use crate::runner::{Cmd, Runner};
use crate::safefs;
use crate::system::{failed, ok, public_dir, Env, Step};

/// The socket the dialogs and the native host connect to (`mastersos-support.socket`).
pub const SOCKET_PATH: &str = "/run/mastersos-support/support.sock";
/// The local queue ([`store::Store`]).
pub const QUEUE_DIR: &str = "/var/lib/mastersos/support-queue";
/// In the public directory (`/var/lib/mastersos-public`).
pub const SUPPORT_JSON: &str = "support.json";
/// The longest request line.
pub const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
/// The largest screenshot (decoded PNG).
pub const MAX_SCREENSHOT_BYTES: usize = 5 * 1024 * 1024;
/// The oneshot unit that sends queued uploads (Task 4) and help requests (Task 5b).
pub const UPLOAD_UNIT: &str = "mastersos-upload.service";
/// Report item of [`step`].
pub const ITEM: &str = "support";

const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(10);

/// After a help request is queued: start the sender without waiting for it. Best effort: when it fails, the sender's
/// timer and the network hook send the queue later.
// Task 5b: the sender (`upload drain`) picks up the support queue; if 5b moves help requests into Task 4's upload
// queue, this is still the one place that starts it.
pub fn kick_sender(runner: &dyn Runner) {
    let cmd =
        Cmd::new("systemctl", &["start", "--no-block", UPLOAD_UNIT]).timeout(SYSTEMCTL_TIMEOUT);
    match runner.run(&cmd) {
        Ok(o) if o.code == 0 => {}
        Ok(o) => log::warn!(
            "support: starting {UPLOAD_UNIT} failed (systemctl exit code {}); it is sent later",
            o.code
        ),
        Err(e) => log::warn!("support: starting {UPLOAD_UNIT} failed: {e:#}; it is sent later"),
    }
}

/// `support.json`.
#[derive(Serialize)]
struct SupportJson {
    enabled: bool,
}

/// Writes `support.json` from the Config (fast: the login screen reads it at boot). Without settings nothing is
/// written: no file is off.
pub fn step() -> Step {
    Step {
        name: "support",
        fast: true,
        run,
        without_bundle: None,
    }
}

fn run(ctx: &ApplyContext, env: &mut Env) -> Vec<ItemResult> {
    let write = || -> anyhow::Result<()> {
        let dir = public_dir(env.paths)?;
        let mut bytes = serde_json::to_vec(&SupportJson {
            enabled: ctx.config.support_enabled,
        })?;
        bytes.push(b'\n');
        safefs::write_at(&dir, SUPPORT_JSON, &bytes, 0o644)?;
        Ok(())
    };
    match write() {
        Ok(()) => vec![ok(ITEM)],
        Err(e) => vec![failed(
            ITEM,
            format!("writing {SUPPORT_JSON} failed: {e:#}"),
        )],
    }
}

/// `mastersos-agent support host | native-host [what Chrome appends…]` (`args` are the ones after `support`).
pub fn main(mut args: impl Iterator<Item = OsString>) -> ExitCode {
    let sub = args.next();
    match sub.as_ref().and_then(|s| s.to_str()) {
        Some("host") if args.next().is_none() => match host::main() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("Error: {e:#}");
                ExitCode::FAILURE
            }
        },
        Some("native-host") => native_host::main(),
        _ => {
            eprintln!("usage: mastersos-agent support host | native-host");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests;
