//! Terminal I/O shared by the installer and the first-boot program: prompts, reading a line, reading a password with echo off.

use std::io::{self, BufRead, Write};

use anyhow::{bail, Context, Result};
use rustix::termios::{tcflush, tcgetattr, tcsetattr, LocalModes, OptionalActions, QueueSelector};

pub fn say(text: &str) {
    println!("{text}");
}

/// Shows the prompt and reads one line (without the line ending); closed input (EOF) is an error, so loops do not spin.
pub fn prompt(text: &str) -> Result<String> {
    print!("{text}");
    io::stdout().flush().ok();
    read_line()
}

pub fn read_line() -> Result<String> {
    let mut s = String::new();
    if io::stdin()
        .lock()
        .read_line(&mut s)
        .context("reading input")?
        == 0
    {
        bail!("input closed");
    }
    Ok(s.trim_end_matches(['\n', '\r']).to_string())
}

/// Drops input typed but not read yet. The terminal is line-buffered: an Enter pressed during the long copy would answer the
/// next prompt at once, before anyone has read the screen. Not a terminal (tests, pipes): nothing to drop.
pub fn flush_input() {
    let _ = tcflush(io::stdin(), QueueSelector::IFlush);
}

/// Reads one line with echo off. When stdin is not a terminal (echo cannot be turned off) this fails instead of echoing a password.
pub fn prompt_secret(text: &str) -> Result<String> {
    print!("{text}");
    io::stdout().flush().ok();
    let stdin = io::stdin();
    let saved =
        tcgetattr(&stdin).context("stdin is not a terminal, cannot read a password safely")?;
    let mut quiet = saved.clone();
    quiet.local_modes.remove(LocalModes::ECHO);
    tcsetattr(&stdin, OptionalActions::Flush, &quiet).context("turning echo off")?;
    let line = read_line();
    // Restore echo whether or not the read worked.
    let restored = tcsetattr(&stdin, OptionalActions::Flush, &saved);
    println!();
    restored.context("restoring echo")?;
    line
}

/// The tty the install flow ([`crate::run_install`]) uses: one method per free function above, faked in tests.
pub trait Tty {
    fn say(&mut self, text: &str);
    fn prompt(&mut self, text: &str) -> Result<String>;
    fn read_line(&mut self) -> Result<String>;
    fn prompt_secret(&mut self, text: &str) -> Result<String>;
    /// Drops input typed before the next prompt (see [`flush_input`]); call it right before a prompt that must be read first.
    fn flush_input(&mut self);
}

/// The real tty: calls the free functions above.
pub struct RealTty;

impl Tty for RealTty {
    fn say(&mut self, text: &str) {
        say(text)
    }

    fn prompt(&mut self, text: &str) -> Result<String> {
        prompt(text)
    }

    fn read_line(&mut self) -> Result<String> {
        read_line()
    }

    fn prompt_secret(&mut self, text: &str) -> Result<String> {
        prompt_secret(text)
    }

    fn flush_input(&mut self) {
        flush_input()
    }
}
