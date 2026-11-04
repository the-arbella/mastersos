//! Terminal I/O shared by the installer and the first-boot program: prompts, reading a line, reading a password with echo off.

use std::io::{self, BufRead, Write};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use rustix::termios::{
    tcflush, tcgetattr, tcsetattr, LocalModes, OptionalActions, QueueSelector, SpecialCodeIndex,
};

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

/// Whether the bytes read in the developer diagnostics window hold a `d` (or `D`, with Caps Lock on): `d`, `dddd` and
/// `ssssdraf` all count (docs/specs/2026-11-03-diagnostics-design.md).
pub fn has_debug_key(input: &[u8]) -> bool {
    input.iter().any(|&b| b == b'd' || b == b'D')
}

/// How long the hidden window reads the keyboard; then how long the keys must stay quiet, at most how long to wait for that.
const DEBUG_WINDOW: Duration = Duration::from_secs(1);
const QUIET: u8 = 5; // tenths of a second (termios VTIME)
const QUIET_MAX: Duration = Duration::from_secs(10);

/// The developer diagnostics window, before the installer shows anything: reads the terminal for one second without echo and
/// without waiting for Enter, nothing on the screen. Someone who holds d from power-on gets `true`. Afterwards it waits until
/// no key came for half a second (at most 10 s) and drops the input, so held keys never answer a later prompt. Not a terminal
/// (tests, pipes) or a terminal error: `false`, nothing changed. Reads the file descriptor directly, never through std's
/// buffered stdin: bytes left in that buffer would survive the flush and answer the next prompt.
pub fn sniff_debug() -> bool {
    let stdin = io::stdin();
    let Ok(saved) = tcgetattr(&stdin) else {
        return false;
    };
    let mut raw = saved.clone();
    raw.local_modes
        .remove(LocalModes::ICANON | LocalModes::ECHO);
    raw.special_codes[SpecialCodeIndex::VMIN] = 0;
    raw.special_codes[SpecialCodeIndex::VTIME] = 1;
    if tcsetattr(&stdin, OptionalActions::Now, &raw).is_err() {
        return false;
    }
    let mut got = Vec::new();
    let mut buf = [0u8; 64];
    let start = Instant::now();
    while start.elapsed() < DEBUG_WINDOW {
        match rustix::io::read(&stdin, &mut buf) {
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    let debug = has_debug_key(&got);
    if !got.is_empty() {
        raw.special_codes[SpecialCodeIndex::VTIME] = QUIET;
        if tcsetattr(&stdin, OptionalActions::Now, &raw).is_ok() {
            let since = Instant::now();
            while since.elapsed() < QUIET_MAX {
                match rustix::io::read(&stdin, &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
    }
    let _ = tcflush(&stdin, QueueSelector::IFlush);
    let _ = tcsetattr(&stdin, OptionalActions::Now, &saved);
    debug
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
