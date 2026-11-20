//! Tokens from `arbella` (protocol §6): when it is on `PATH`, `mastersos` runs
//! `arbella auth token [--step-up] --json` and uses `{"fleet_url","access_token","expires_at"}`.
//!
//! - stdin is closed; stdout is read as one JSON object (unknown fields ignored).
//! - stderr is never read: discarded for a plain token, left on the terminal for `--step-up`,
//!   whose prompts are for the person. Nothing arbella prints goes into an error.
//! - Exit codes (the server team's answer): 3 not signed in, 4 forbidden, 5 conflict, 6 step-up
//!   failed. Any other failure, a timeout (the child is killed) or a bad answer is a local error
//!   naming arbella, without its output.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::server::CliError;

/// How long `arbella auth token --json` may take.
pub const TIMEOUT: Duration = Duration::from_secs(60);
/// How long `arbella auth token --step-up --json` may take: the same 60 seconds (ruling R5), though
/// the browser sign-in behind it may need longer.
pub const STEP_UP_TIMEOUT: Duration = Duration::from_secs(60);

/// What `arbella auth token --json` prints.
#[derive(Clone, Deserialize)]
pub struct ArbellaToken {
    #[serde(rename = "fleet_url")]
    pub server_url: String,
    pub access_token: String,
    pub expires_at: String,
}

/// The token never shows in Debug output.
impl std::fmt::Debug for ArbellaToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArbellaToken")
            .field("server_url", &self.server_url)
            .field("access_token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// `arbella` (`arbella.exe` on Windows) in an absolute directory of `PATH`.
pub fn find() -> Option<PathBuf> {
    find_in(std::env::var_os("PATH").as_deref())
}

/// [`find`] in the given `PATH` value. Empty and relative entries (the current directory) are
/// skipped; only a regular file that may be run counts.
pub fn find_in(path: Option<&OsStr>) -> Option<PathBuf> {
    let name = if cfg!(windows) {
        "arbella.exe"
    } else {
        "arbella"
    };
    std::env::split_paths(path?)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(name))
        .find(|p| runnable(p))
}

fn runnable(p: &Path) -> bool {
    let Ok(m) = std::fs::metadata(p) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        m.is_file() && m.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        m.is_file()
    }
}

/// Run arbella for a token (with `--step-up` for a fresh sign-in).
pub async fn token(exe: &Path, step_up: bool) -> Result<ArbellaToken, CliError> {
    let limit = if step_up { STEP_UP_TIMEOUT } else { TIMEOUT };
    run(exe, step_up, limit).await
}

/// The most bytes of arbella's answer.
const MAX_STDOUT: usize = 64 * 1024;

pub(crate) async fn run(
    exe: &Path,
    step_up: bool,
    limit: Duration,
) -> Result<ArbellaToken, CliError> {
    use std::process::Stdio;
    let local = |why: &str| CliError::new("invalid_answer", &format!("arbella {why}"));
    let mut cmd = tokio::process::Command::new(exe);
    cmd.args(["auth", "token"]);
    if step_up {
        cmd.arg("--step-up");
    }
    cmd.arg("--json")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(if step_up {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .kill_on_drop(true);
    let child = cmd.spawn().map_err(|_| local("could not be started"))?;
    // On a timeout the future, and with it the child, is dropped: kill_on_drop kills it.
    let out = match tokio::time::timeout(limit, child.wait_with_output()).await {
        Err(_) => {
            return Err(local(&format!(
                "did not answer within {} seconds",
                limit.as_secs()
            )))
        }
        Ok(Err(_)) => return Err(local("could not be run")),
        Ok(Ok(o)) => o,
    };
    match out.status.code() {
        Some(0) => {}
        Some(3) => {
            return Err(CliError::new(
                "not_logged_in",
                "arbella is not signed in: run `arbella login`",
            ))
        }
        Some(4) => {
            return Err(CliError::new(
                "forbidden",
                "arbella refused: this account may not get a token for the server",
            ))
        }
        Some(5) => return Err(CliError::new("conflict", "arbella reported a conflict")),
        Some(6) => {
            return Err(CliError::new(
                "step_up_failed",
                "the fresh sign-in through arbella failed",
            ))
        }
        Some(n) => return Err(local(&format!("failed (exit code {n})"))),
        None => return Err(local("was stopped by a signal")),
    }
    if out.stdout.len() > MAX_STDOUT {
        return Err(local("gave an answer that is too large"));
    }
    let t: ArbellaToken = serde_json::from_slice(&out.stdout)
        .map_err(|_| local("gave an answer that is not the expected JSON"))?;
    if t.access_token.is_empty() || !t.access_token.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(local("gave an unusable access token"));
    }
    Ok(t)
}

/// Write an executable script without keeping a write handle open in this process (a fork in
/// another test thread would keep it and make running it fail with "text file busy").
#[cfg(all(test, unix))]
pub(crate) fn write_script(path: &Path, body: &str) {
    use std::io::Write as _;
    let mut child = std::process::Command::new("sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(path)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("#!/bin/sh\n{body}\n").as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
}

/// A fake arbella in `dir` that writes its arguments to `dir/args` and runs `body`.
#[cfg(all(test, unix))]
pub(crate) fn fake(dir: &Path, body: &str) -> PathBuf {
    let exe = dir.join("arbella");
    write_script(
        &exe,
        &format!("printf '%s\\n' \"$@\" > \"$(dirname \"$0\")/args\"\n{body}"),
    );
    exe
}

#[cfg(all(test, unix))]
pub(crate) const GOOD: &str = r#"echo '{"fleet_url":"https://server.example","access_token":"t","expires_at":"2026-11-20T10:00:00Z","extra":1}'"#;

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn args(dir: &Path) -> Vec<String> {
        std::fs::read_to_string(dir.join("args"))
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[tokio::test]
    async fn arbella_token_is_parsed() {
        let t = tempfile::tempdir().unwrap();
        let exe = fake(t.path(), GOOD);
        let tok = token(&exe, false).await.unwrap();
        assert_eq!(tok.server_url, "https://server.example");
        assert_eq!(tok.access_token, "t");
        assert_eq!(tok.expires_at, "2026-11-20T10:00:00Z");
        assert_eq!(args(t.path()), ["auth", "token", "--json"]);
    }

    #[tokio::test]
    async fn arbella_step_up_passes_the_flag() {
        let t = tempfile::tempdir().unwrap();
        let exe = fake(t.path(), GOOD);
        token(&exe, true).await.unwrap();
        assert_eq!(args(t.path()), ["auth", "token", "--step-up", "--json"]);
    }

    #[tokio::test]
    async fn arbella_stdin_is_closed() {
        let t = tempfile::tempdir().unwrap();
        // `cat` ends at once on a closed stdin; on an open one it would wait for the timeout.
        let exe = fake(t.path(), &format!("cat >/dev/null\n{GOOD}"));
        run(&exe, false, Duration::from_secs(5)).await.unwrap();
    }

    #[tokio::test]
    async fn arbella_failure_is_not_logged_in() {
        let t = tempfile::tempdir().unwrap();
        let exe = fake(
            t.path(),
            r#"echo SECRET-STDERR >&2
echo '{"error":{"code":"not_signed_in","message":"SECRET-STDOUT","problems":[]}}'
exit 3"#,
        );
        let e = token(&exe, false).await.unwrap_err();
        assert_eq!(e.code, "not_logged_in");
        assert!(e.message.contains("arbella login"), "{e:?}");
        assert!(!format!("{e:?}").contains("SECRET"), "{e:?}");
    }

    #[tokio::test]
    async fn arbella_exit_codes_map_to_error_codes() {
        for (exit, code) in [
            (4, "forbidden"),
            (5, "conflict"),
            (6, "step_up_failed"),
            (2, "invalid_answer"),
            (1, "invalid_answer"),
            (7, "invalid_answer"),
        ] {
            let t = tempfile::tempdir().unwrap();
            let exe = fake(
                t.path(),
                &format!("echo SECRET-STDERR >&2\necho SECRET-STDOUT\nexit {exit}"),
            );
            let e = token(&exe, false).await.unwrap_err();
            assert_eq!(e.code, code, "exit {exit}");
            assert!(e.message.contains("arbella"), "{e:?}");
            assert!(!format!("{e:?}").contains("SECRET"), "{e:?}");
        }
    }

    #[tokio::test]
    async fn arbella_bad_answers_are_local_errors() {
        for body in [
            "echo SECRET-NOT-JSON",
            r#"echo '{"fleet_url":"https://server.example","expires_at":"x"}'"#,
            r#"echo '{"fleet_url":"https://server.example","access_token":"a b","expires_at":"x"}'"#,
            "kill -9 $$",
        ] {
            let t = tempfile::tempdir().unwrap();
            let exe = fake(t.path(), body);
            let e = token(&exe, false).await.unwrap_err();
            assert_eq!(e.code, "invalid_answer", "{body}");
            assert!(e.message.contains("arbella"), "{e:?}");
            assert!(!format!("{e:?}").contains("SECRET"), "{e:?}");
        }
    }

    #[tokio::test]
    async fn arbella_timeout_kills_it() {
        let t = tempfile::tempdir().unwrap();
        let exe = fake(t.path(), "exec sleep 30");
        let started = std::time::Instant::now();
        let e = run(&exe, false, Duration::from_millis(500))
            .await
            .unwrap_err();
        assert_eq!(e.code, "invalid_answer");
        assert!(e.message.contains("arbella"), "{e:?}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn arbella_is_found_in_absolute_path_entries_only() {
        let t = tempfile::tempdir().unwrap();
        let bin = t.path().join("bin");
        let empty = t.path().join("empty");
        std::fs::create_dir(&bin).unwrap();
        std::fs::create_dir(&empty).unwrap();
        let exe = fake(&bin, GOOD);
        let path = std::env::join_paths([&empty, &bin]).unwrap();
        assert_eq!(find_in(Some(&path)), Some(exe.clone()));
        assert_eq!(find_in(None), None);
        assert_eq!(find_in(Some(empty.as_os_str())), None);
        // A relative entry is never searched.
        assert_eq!(find_in(Some(OsStr::new("bin"))), None);
        assert_eq!(find_in(Some(OsStr::new(""))), None);
        // A file that may not be run does not count.
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(find_in(Some(bin.as_os_str())), None);
        // Nor does a directory named arbella.
        std::fs::create_dir(empty.join("arbella")).unwrap();
        assert_eq!(find_in(Some(empty.as_os_str())), None);
    }

    #[test]
    fn arbella_token_debug_is_redacted() {
        let tok: ArbellaToken = serde_json::from_str(
            r#"{"fleet_url":"https://server.example","access_token":"SECRET","expires_at":"x"}"#,
        )
        .unwrap();
        assert!(!format!("{tok:?}").contains("SECRET"));
    }
}
