//! Running outside commands. System steps (`SystemApplier`) call commands only through [`Runner`]; tests use [`FakeRunner`].
//!
//! Secrets (passwords, PSKs, recovery keys) go only through `stdin`: [`Cmd::line`] and error messages never contain stdin,
//! and secrets are never allowed in the arguments (Global Constraints). Commands whose output may hold a secret use [`run_ok_redacted`].

use std::fmt;
use std::io::{PipeReader, Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use nix::sys::signal::{killpg, Signal};
use nix::unistd::Pid;

/// Default timeout of `Cmd::new`.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
/// After the timeout, SIGTERM first; still running after this long, SIGKILL.
pub(crate) const TERM_GRACE: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(50);
/// At most this much of a command's stdout / stderr is kept (the beginning of anything longer is dropped); a command can
/// ask for more stdout ([`Cmd::max_output`]).
pub const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
/// The first line of a stdout whose beginning was dropped ([`RealRunner`]); the cut is made at a line start, so the
/// next line is whole. See [`was_cut`].
pub const CUT_MARKER: &str =
    "[mastersos: the beginning of this output was left out: over the size limit]\n";

/// Whether the beginning of `stdout` was dropped for size.
pub fn was_cut(stdout: &str) -> bool {
    stdout.starts_with(CUT_MARKER)
}
/// After the command exits, wait at most this long for its output pipes to reach EOF (stop waiting when a background process keeps them open).
const OUTPUT_GRACE: Duration = Duration::from_secs(2);
/// stdin up to this size is written straight into the pipe (the buffer holds it); larger stdin is written by a separate thread.
const INLINE_STDIN_BYTES: usize = 8 * 1024;
/// Error messages carry this many last lines of stderr.
const ERR_TAIL_LINES: usize = 20;

pub struct Cmd {
    pub program: String,
    pub args: Vec<String>,
    pub stdin: Option<Vec<u8>>,
    pub timeout: Duration,
    /// At most this much stdout is kept ([`MAX_OUTPUT_BYTES`] by default).
    pub max_output: usize,
}

impl Cmd {
    /// The timeout defaults to 120 seconds.
    pub fn new(program: &str, args: &[&str]) -> Cmd {
        Cmd {
            program: program.to_string(),
            args: args.iter().map(|a| a.to_string()).collect(),
            stdin: None,
            timeout: DEFAULT_TIMEOUT,
            max_output: MAX_OUTPUT_BYTES,
        }
    }

    /// Keep up to `bytes` of stdout instead of [`MAX_OUTPUT_BYTES`].
    pub fn max_output(mut self, bytes: usize) -> Cmd {
        self.max_output = bytes;
        self
    }

    pub fn stdin(mut self, b: Vec<u8>) -> Cmd {
        self.stdin = Some(b);
        self
    }

    pub fn timeout(mut self, d: Duration) -> Cmd {
        self.timeout = d;
        self
    }

    /// program and args joined by spaces; never contains stdin.
    pub fn line(&self) -> String {
        std::iter::once(self.program.as_str())
            .chain(self.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Does not print stdin (it may hold a password).
impl fmt::Debug for Cmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cmd")
            .field("line", &self.line())
            .field("stdin", &self.stdin.as_ref().map(|_| "<hidden>"))
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    /// Exit code; 128 + the signal number when killed by a signal (as in the shell).
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(stdout: &str) -> Output {
        Output {
            code: 0,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    pub fn fail(code: i32, stderr: &str) -> Output {
        Output {
            code,
            stdout: String::new(),
            stderr: stderr.to_string(),
        }
    }
}

pub trait Runner: Send + Sync {
    /// `Ok` when the command ran and ended (whatever the exit code); an error when it could not start or timed out.
    /// Error messages carry only the program name, not the arguments or stdin.
    fn run(&self, cmd: &Cmd) -> Result<Output>;
}

pub(crate) fn last_lines(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.trim_end().lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

/// Fails when the exit code is not 0: `"<program> exited with N: <last 20 lines of stderr>"` (no arguments). Returns stdout.
pub fn run_ok(r: &dyn Runner, cmd: Cmd) -> Result<String> {
    let out = r.run(&cmd)?;
    if out.code != 0 {
        bail!(
            "{} exited with {}: {}",
            cmd.program,
            out.code,
            last_lines(&out.stderr, ERR_TAIL_LINES)
        );
    }
    Ok(out.stdout)
}

/// Like [`run_ok`], but the error message is only `"<program> exited with N"`, without stderr
/// (`systemd-cryptenroll` may print the recovery key it just generated on stderr when it fails).
pub fn run_ok_redacted(r: &dyn Runner, cmd: Cmd) -> Result<String> {
    let out = r.run(&cmd)?;
    if out.code != 0 {
        bail!("{} exited with {}", cmd.program, out.code);
    }
    Ok(out.stdout)
}

/// Really runs the command: own process group; on timeout the whole group gets SIGTERM, then SIGKILL after 5 seconds (the same
/// scheme as the apply scripts, see [`wait_group`]). stdout / stderr are read into memory through pipes (never written to disk:
/// `systemd-cryptenroll` prints the recovery key on stdout); when a background process left by the command keeps a pipe open, it waits at most `OUTPUT_GRACE` after the command exits.
pub struct RealRunner;

impl Runner for RealRunner {
    fn run(&self, cmd: &Cmd) -> Result<Output> {
        let (out_r, out_w) = std::io::pipe().context("creating a pipe")?;
        let (err_r, err_w) = std::io::pipe().context("creating a pipe")?;
        let mut child = {
            // The Command and the pipe write ends it holds are dropped at the end of this block: otherwise the read ends never see EOF.
            let mut c = Command::new(&cmd.program);
            c.args(&cmd.args)
                .stdout(out_w)
                .stderr(err_w)
                .stdin(if cmd.stdin.is_some() {
                    Stdio::piped()
                } else {
                    Stdio::null()
                })
                .process_group(0);
            c.spawn()
                .with_context(|| format!("{} could not be started", cmd.program))?
        };
        let out = capture(out_r, cmd.max_output);
        let err = capture(err_r, MAX_OUTPUT_BYTES);
        if let (Some(bytes), Some(mut w)) = (cmd.stdin.as_ref(), child.stdin.take()) {
            if bytes.len() <= INLINE_STDIN_BYTES {
                // Fits in the pipe buffer: write it all and close, no extra thread (so no thread can hang).
                let _ = w.write_all(bytes);
            } else {
                // Large input is written by a separate thread: a command that does not read stdin cannot block us here; the write ends with EPIPE once it exits.
                let bytes = bytes.clone();
                std::thread::spawn(move || {
                    let _ = w.write_all(&bytes);
                });
            }
        }
        let st = match wait_group(&mut child, cmd.timeout)? {
            Waited::Exited(st) => st,
            Waited::TimedOut => bail!(
                "{} timed out: not finished within {} seconds, killed",
                cmd.program,
                cmd.timeout.as_secs_f32()
            ),
        };
        Ok(Output {
            code: exit_code(st),
            stdout: out.finish_marked(),
            stderr: err.finish(),
        })
    }
}

/// The output of one pipe, read into memory by a background thread; only the last `cap` bytes are kept.
pub(crate) struct Capture {
    buf: Arc<Mutex<Vec<u8>>>,
    done: mpsc::Receiver<()>,
    /// The beginning was dropped.
    cut: Arc<std::sync::atomic::AtomicBool>,
}

pub(crate) fn capture(mut r: PipeReader, cap: usize) -> Capture {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let cut = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (tx, done) = mpsc::channel();
    let b = buf.clone();
    let c = cut.clone();
    std::thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        loop {
            match r.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut g = b.lock().unwrap_or_else(|e| e.into_inner());
                    g.extend_from_slice(&chunk[..n]);
                    if g.len() > cap {
                        let cut = g.len() - cap;
                        g.drain(..cut);
                        c.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                }
            }
        }
        let _ = tx.send(());
    });
    Capture { buf, done, cut }
}

impl Capture {
    /// Wait for EOF (at most `OUTPUT_GRACE`) and return what was read.
    pub(crate) fn finish(self) -> String {
        let _ = self.done.recv_timeout(OUTPUT_GRACE);
        let g = self.buf.lock().unwrap_or_else(|e| e.into_inner());
        String::from_utf8_lossy(&g).into_owned()
    }

    /// Like [`Capture::finish`]; when the beginning was dropped, the partial first line goes too and the text starts
    /// with [`CUT_MARKER`].
    pub(crate) fn finish_marked(self) -> String {
        let cut = self.cut.clone();
        let text = self.finish();
        if !cut.load(std::sync::atomic::Ordering::SeqCst) {
            return text;
        }
        let rest = text.find('\n').map_or("", |i| &text[i + 1..]);
        format!("{CUT_MARKER}{rest}")
    }
}

fn exit_code(st: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    match (st.code(), st.signal()) {
        (Some(c), _) => c,
        (None, Some(sig)) => 128 + sig,
        _ => -1,
    }
}

/// For tests: hands out preset outputs by prefix of `line()`, first in first out (each one is used once); a command with no
/// match gets `Output::ok("")`. Records the `line()` and stdin of every call. [`FakeRunner::delay`] makes some commands block
/// for a while first (sleeping outside the lock, so other threads can still call it).
#[derive(Default)]
pub struct FakeRunner {
    inner: Mutex<FakeInner>,
}

#[derive(Default)]
struct FakeInner {
    responses: Vec<(String, Output)>,
    calls: Vec<(String, Option<Vec<u8>>)>,
    delays: Vec<(String, Duration)>,
}

impl FakeRunner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn respond(&self, line_prefix: &str, out: Output) {
        self.lock().responses.push((line_prefix.to_string(), out));
    }

    /// From now on every call whose `line()` starts with `line_prefix` blocks for `d` before returning (not used up; the call is recorded before blocking).
    pub fn delay(&self, line_prefix: &str, d: Duration) {
        self.lock().delays.push((line_prefix.to_string(), d));
    }

    /// The `line()` of every call, in call order.
    pub fn calls(&self) -> Vec<String> {
        self.lock().calls.iter().map(|(l, _)| l.clone()).collect()
    }

    /// The stdin received by the latest call whose `line()` starts with `line_prefix`.
    pub fn stdin_of(&self, line_prefix: &str) -> Option<Vec<u8>> {
        self.lock()
            .calls
            .iter()
            .rev()
            .find(|(l, _)| l.starts_with(line_prefix))
            .and_then(|(_, s)| s.clone())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FakeInner> {
        // When a failed assertion in a test poisoned the lock, still hand out the data inside.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Runner for FakeRunner {
    fn run(&self, cmd: &Cmd) -> Result<Output> {
        let line = cmd.line();
        let mut g = self.lock();
        g.calls.push((line.clone(), cmd.stdin.clone()));
        let hit = g.responses.iter().position(|(p, _)| line.starts_with(p));
        let out = match hit {
            Some(i) => g.responses.remove(i).1,
            None => Output::ok(""),
        };
        let delay = g
            .delays
            .iter()
            .find(|(p, _)| line.starts_with(p.as_str()))
            .map(|(_, d)| *d);
        drop(g);
        if let Some(d) = delay {
            sleep(d);
        }
        Ok(out)
    }
}

pub(crate) enum Waited {
    Exited(ExitStatus),
    TimedOut,
}

/// State of the leader process. As long as it has not been reaped its pid cannot be reused,
/// so signalling the whole process group is safe.
enum Leader {
    Running,
    /// Exited, not reaped yet (the zombie still holds the pid, nobody else can take the group id).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    ExitedUnreaped,
    /// Exited and reaped: no more signals to the process group.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    Reaped(ExitStatus),
}

/// On Linux, `waitid(WNOWAIT)` looks without reaping.
#[cfg(target_os = "linux")]
fn leader(child: &mut Child) -> std::io::Result<Leader> {
    use nix::sys::wait::{waitid, Id, WaitPidFlag, WaitStatus};
    let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT;
    match waitid(Id::Pid(Pid::from_raw(child.id() as i32)), flags) {
        Ok(WaitStatus::StillAlive) => Ok(Leader::Running),
        Ok(_) => Ok(Leader::ExitedUnreaped),
        Err(e) => Err(std::io::Error::from(e)),
    }
}

/// Other platforms (development machines) have no `waitid`: only `try_wait`, which reaps as a side effect.
#[cfg(not(target_os = "linux"))]
fn leader(child: &mut Child) -> std::io::Result<Leader> {
    Ok(match child.try_wait()? {
        Some(st) => Leader::Reaped(st),
        None => Leader::Running,
    })
}

/// Waits for a child started with `process_group(0)`. On timeout the whole group gets SIGTERM, SIGKILL after `TERM_GRACE`,
/// so the processes it started go too. The process group is signalled only while the leader has not been reaped.
pub(crate) fn wait_group(child: &mut Child, timeout: Duration) -> std::io::Result<Waited> {
    let pgid = Pid::from_raw(child.id() as i32);
    let now = Instant::now();
    let deadline = now
        .checked_add(timeout)
        .unwrap_or_else(|| now + Duration::from_secs(mastersos_bundle::MAX_SCRIPT_TIMEOUT_SECS));
    loop {
        match leader(child)? {
            Leader::Running => {}
            Leader::ExitedUnreaped => return Ok(Waited::Exited(child.wait()?)),
            Leader::Reaped(st) => return Ok(Waited::Exited(st)),
        }
        if Instant::now() >= deadline {
            break;
        }
        sleep(POLL);
    }
    // Getting here, the leader is certainly still running and not reaped.
    let _ = killpg(pgid, Signal::SIGTERM);
    let grace = Instant::now() + TERM_GRACE;
    let mut reaped = false;
    while Instant::now() < grace {
        match leader(child)? {
            Leader::Running => sleep(POLL),
            Leader::ExitedUnreaped => break,
            Leader::Reaped(_) => {
                reaped = true;
                break;
            }
        }
    }
    if !reaped {
        let _ = killpg(pgid, Signal::SIGKILL);
        child.wait()?;
    }
    Ok(Waited::TimedOut)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_runner_matches_prefix_fifo() {
        let r = FakeRunner::new();
        r.respond("nmcli con", Output::ok("first"));
        r.respond("nmcli con", Output::fail(2, "second"));
        r.respond("nmcli", Output::ok("generic"));
        let run = |args: &[&str]| r.run(&Cmd::new("nmcli", args)).unwrap();
        assert_eq!(run(&["con", "up"]), Output::ok("first"));
        assert_eq!(run(&["con", "down"]), Output::fail(2, "second"));
        // The two "nmcli con" answers are used up: falls back to the shorter prefix.
        assert_eq!(run(&["con", "x"]), Output::ok("generic"));
        // All used up: the default ok("").
        assert_eq!(run(&["con"]), Output::ok(""));
        assert_eq!(
            r.calls(),
            vec!["nmcli con up", "nmcli con down", "nmcli con x", "nmcli con"]
        );
        r.run(&Cmd::new("chpasswd", &[]).stdin(b"u:pw".to_vec()))
            .unwrap();
        assert_eq!(r.stdin_of("chpasswd"), Some(b"u:pw".to_vec()));
        assert_eq!(r.stdin_of("nmcli"), None);
    }

    #[test]
    fn run_ok_error_has_stderr_tail_not_stdin() {
        let r = FakeRunner::new();
        let stderr: String = (1..=25).map(|i| format!("line{i}\n")).collect();
        r.respond("useradd", Output::fail(3, &stderr));
        let cmd = Cmd::new("useradd", &["-m", "alice"]).stdin(b"s3cret".to_vec());
        assert!(!format!("{cmd:?}").contains("s3cret"));
        let e = format!("{:#}", run_ok(&r, cmd).unwrap_err());
        assert!(e.starts_with("useradd exited with 3: "), "{e}");
        assert!(e.contains("line25") && e.contains("line6\n"), "{e}");
        assert!(!e.contains("line5\n"), "only the last 20 lines: {e}");
        assert!(!e.contains("s3cret"), "{e}");
        assert!(!e.contains("alice"), "no arguments: {e}");

        r.respond("true", Output::ok("out"));
        assert_eq!(run_ok(&r, Cmd::new("true", &[])).unwrap(), "out");
    }

    #[test]
    fn run_ok_redacted_hides_stderr() {
        let r = FakeRunner::new();
        r.respond(
            "systemd-cryptenroll",
            Output::fail(1, "recovery key: ccccdddd-eeeeffff-gggghhhh\n"),
        );
        let e = run_ok_redacted(
            &r,
            Cmd::new("systemd-cryptenroll", &["--recovery-key", "/dev/x"]),
        )
        .unwrap_err();
        assert_eq!(format!("{e:#}"), "systemd-cryptenroll exited with 1");
    }

    /// Over the cap: the beginning goes, the cut is marked and lands on a line start.
    #[test]
    fn real_runner_marks_a_cut_stdout() {
        let out = RealRunner
            .run(
                &Cmd::new(
                    "sh",
                    &[
                        "-c",
                        "i=0; while [ $i -lt 5000 ]; do echo line-$i; i=$((i+1)); done",
                    ],
                )
                .max_output(10_000),
            )
            .unwrap();
        assert!(was_cut(&out.stdout), "{}", &out.stdout[..80]);
        let rest = &out.stdout[CUT_MARKER.len()..];
        assert!(rest.len() <= 10_000);
        assert!(rest.starts_with("line-"), "{}", &rest[..20]);
        assert!(rest.ends_with("line-4999\n"));
        // Under the cap: untouched.
        let out = RealRunner.run(&Cmd::new("echo", &["short"])).unwrap();
        assert_eq!(out.stdout, "short\n");
        assert!(!was_cut(&out.stdout));
    }

    #[test]
    fn real_runner_kills_on_timeout() {
        let t0 = Instant::now();
        let e = RealRunner
            .run(&Cmd::new("sleep", &["30"]).timeout(Duration::from_millis(200)))
            .unwrap_err();
        assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
        assert!(format!("{e:#}").contains("timed out"), "{e:#}");
    }

    #[test]
    fn real_runner_passes_stdin_and_captures_output() {
        let out = RealRunner
            .run(
                &Cmd::new("sh", &["-c", "cat; echo oops >&2; exit 3"])
                    .stdin(b"from stdin".to_vec()),
            )
            .unwrap();
        assert_eq!(out.code, 3);
        assert_eq!(out.stdout, "from stdin");
        assert_eq!(out.stderr, "oops\n");
        // A background process keeps stdout open: no waiting for it after the command itself exits.
        let t0 = Instant::now();
        let out = RealRunner
            .run(&Cmd::new("sh", &["-c", "echo hi; (sleep 30 &) ; exit 0"]))
            .unwrap();
        assert_eq!(out.stdout, "hi\n");
        assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
        // A command that does not read stdin does not block.
        let out = RealRunner
            .run(&Cmd::new("true", &[]).stdin(vec![b'x'; 1 << 20]))
            .unwrap();
        assert_eq!(out.code, 0);
        let e = RealRunner
            .run(&Cmd::new("/nonexistent/mastersos-x", &["secret-arg"]))
            .unwrap_err();
        assert!(!format!("{e:#}").contains("secret-arg"), "{e:#}");
    }
}
