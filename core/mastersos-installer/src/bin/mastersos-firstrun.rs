//! First-boot program: on an unmanaged machine with no local user yet, creates the first user on tty1.
#![forbid(unsafe_code)]

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use mastersos_agent::runner::RealRunner;
use mastersos_installer::firstrun::{is_mountpoint, needs_firstrun, run_interactive};

fn main() {
    // With the seed partition (nofail) not mounted there is no telling whether the machine is managed: do nothing, so no sudo account appears on a managed machine.
    let dev = |p: &str| std::fs::metadata(p).map(|m| m.dev());
    match (dev("/var/lib"), dev("/var/lib/mastersos-seed")) {
        (Ok(parent), Ok(seed)) if is_mountpoint(parent, seed) => {}
        _ => {
            eprintln!("mastersos-firstrun: /var/lib/mastersos-seed is not mounted, doing nothing");
            return;
        }
    }
    // An unreadable passwd must not count as "no users".
    let passwd = match std::fs::read_to_string("/etc/passwd") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("mastersos-firstrun: cannot read /etc/passwd: {e}");
            std::process::exit(1);
        }
    };
    let seed_present = [
        "/var/lib/mastersos/seed.toml",
        "/var/lib/mastersos-seed/seed.toml",
    ]
    .iter()
    .any(|p| Path::new(p).exists());
    if !needs_firstrun(&passwd, seed_present) {
        return;
    }
    if let Err(e) = run_interactive(&RealRunner) {
        eprintln!("mastersos-firstrun: {e:#}");
        std::process::exit(1);
    }
}
