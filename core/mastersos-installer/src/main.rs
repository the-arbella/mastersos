//! Installer: the plain-text flow on tty1. The flow is [`mastersos_installer::run_install`] in the lib; this only wires it up.
#![forbid(unsafe_code)]

use std::path::Path;

use mastersos_agent::runner::RealRunner;
use mastersos_installer::tty::{RealTty, Tty};
use mastersos_installer::{
    ask_and_restart, fail_and_restart, panic_text, run_install, Restart, RESTART_PROMPT,
};

fn main() {
    // Developer diagnostics: the hidden one-second window, before anything is on the screen (hold d from power-on)
    let debug = mastersos_installer::tty::sniff_debug();
    // A bug (panic) must not leave a dead screen either: show it, wait for Enter, restart (best effort).
    std::panic::set_hook(Box::new(|info| {
        let mut tty = RealTty;
        tty.say(&panic_text(&info.to_string()));
        ask_and_restart(&RealRunner, &mut tty, RESTART_PROMPT, Restart::system());
    }));
    if let Err(e) = run_install(
        &RealRunner,
        &mut RealTty,
        Path::new("/sys"),
        Path::new("/dev"),
        debug,
    ) {
        // stdout and stderr both go to tty1: the failure screen shows the reason, what happened to the disk, and waits for Enter.
        fail_and_restart(&RealRunner, &mut RealTty, &e, Restart::system());
        std::process::exit(1);
    }
}
