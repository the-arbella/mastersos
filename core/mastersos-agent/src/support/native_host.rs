//! `mastersos-agent support native-host`: the Chrome native messaging host `org.mastersos.support` for the kiosk
//! extension's Get help (plan 2026-11-05 Task 5/7). Chrome starts the image's wrapper
//! `/usr/lib/mastersos/mastersos-support-host` as the kiosk account for each `sendNativeMessage` and appends the
//! caller's origin (and on some platforms a window handle) as arguments, which are ignored.
//!
//! One message in (4-byte little-endian length + JSON, at most [`MAX_MESSAGE`]), forwarded as one line to
//! `/run/mastersos/support.sock`; the socket's one-line reply goes back as one message. The extension sends
//! `{"op":"enabled"}`, `{"op":"status","client_id":…}` and
//! `{"op":"submit","category":…,"text":…,"session":"kiosk","screenshot_png_b64":null}`; in a submit the placeholder
//! session becomes `kiosk:<app id>` of this account. That is only for the record: the support host derives the session
//! from the peer credentials itself, and this process cannot vouch for anything.
//!
//! A message that is not a JSON object (or too long, or cut short) is answered `{"ok":false,"error":"invalid"}`
//! without touching the socket; no socket or a reply that is not a JSON object is `{"ok":false,"error":"unreachable"}`
//! (the extension shows its "ask a teacher" text for both). stdout is the message channel: nothing else is written
//! there, logs go to stderr.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

/// The longest message read from the extension (it never sends a screenshot, Ruling P1).
pub const MAX_MESSAGE: usize = 64 * 1024;
/// The longest reply line read from the socket.
const MAX_REPLY: u64 = 64 * 1024;
/// The socket has this long to answer (a submit writes the queue and starts the sender, quickly).
const SOCKET_TIMEOUT: Duration = Duration::from_secs(20);

fn read_message(r: &mut dyn Read) -> Option<Map<String, Value>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).ok()?;
    let n = u32::from_le_bytes(len) as usize;
    if n > MAX_MESSAGE {
        return None;
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).ok()?;
    match serde_json::from_slice(&body).ok()? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

fn write_message(w: &mut dyn Write, v: &Value) -> std::io::Result<()> {
    let body = serde_json::to_vec(v)?;
    let n = u32::try_from(body.len()).map_err(std::io::Error::other)?;
    w.write_all(&n.to_le_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

/// One message from `input` → `ask` (one request line → one reply line) → one message to `output`. `kiosk_session`
/// (`kiosk:<id>`) replaces the session of a submit. Returns whether the socket answered.
pub fn run(
    input: &mut dyn Read,
    output: &mut dyn Write,
    kiosk_session: Option<&str>,
    ask: &mut dyn FnMut(&[u8]) -> Result<Vec<u8>>,
) -> bool {
    let (reply, answered) = match read_message(input) {
        None => (json!({"ok": false, "error": "invalid"}), false),
        Some(mut m) => {
            if let (Some("submit"), Some(s)) = (m.get("op").and_then(Value::as_str), kiosk_session)
            {
                if m.contains_key("session") {
                    m.insert("session".into(), Value::String(s.to_string()));
                }
            }
            let mut line = serde_json::to_vec(&Value::Object(m)).unwrap_or_default();
            line.push(b'\n');
            let unreachable = json!({"ok": false, "error": "unreachable"});
            match ask(&line) {
                Ok(r) => match serde_json::from_slice::<Value>(r.strip_suffix(b"\n").unwrap_or(&r))
                {
                    Ok(v @ Value::Object(_)) => (v, true),
                    _ => {
                        eprintln!("mastersos-support-host: the support socket gave a broken reply");
                        (unreachable, false)
                    }
                },
                Err(e) => {
                    eprintln!("mastersos-support-host: {e:#}");
                    (unreachable, false)
                }
            }
        }
    };
    if let Err(e) = write_message(output, &reply) {
        eprintln!("mastersos-support-host: writing the reply failed: {e}");
        return false;
    }
    answered
}

/// One line to the socket at `path`, one line back.
pub fn ask_socket(path: &Path, line: &[u8]) -> Result<Vec<u8>> {
    let mut s =
        UnixStream::connect(path).with_context(|| format!("connecting to {}", path.display()))?;
    s.set_read_timeout(Some(SOCKET_TIMEOUT))?;
    s.set_write_timeout(Some(SOCKET_TIMEOUT))?;
    s.write_all(line).context("sending the request")?;
    let mut reply = Vec::new();
    BufReader::new(s.take(MAX_REPLY))
        .read_until(b'\n', &mut reply)
        .context("reading the reply")?;
    Ok(reply)
}

/// `kiosk:<id>` for this process's kiosk account (`$USER`, the name Chrome's session runs as), if it is one.
fn kiosk_session() -> Option<String> {
    let user = std::env::var("USER").ok()?;
    crate::kiosk_session::id_from_user(&user)
        .ok()
        .map(|id| format!("kiosk:{id}"))
}

pub fn main() -> ExitCode {
    let session = kiosk_session();
    let ok = run(
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
        session.as_deref(),
        &mut |line: &[u8]| ask_socket(Path::new(super::SOCKET_PATH), line),
    );
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
