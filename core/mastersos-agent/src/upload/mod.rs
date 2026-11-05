//! Uploads to the cloud without a resident uploader (spec design 3, Ruling P6): the agent (and,
//! with Task 5, the support host) writes an item into the [`queue`] on disk and [`kick`]s the
//! oneshot `mastersos-upload.service`, which runs `mastersos-agent upload drain`
//! ([`drain::drain`]) and exits once nothing is due soon. The NetworkManager dispatcher
//! (`mastersos-agent upload kick`) and `mastersos-upload.timer` (every 30 minutes, and after
//! boot) start it too.

pub mod drain;
pub mod queue;

use std::time::Duration;

use crate::runner::{Cmd, Runner};

/// The unit that drains the queue.
pub const SERVICE: &str = "mastersos-upload.service";
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(10);

/// `systemctl start --no-block mastersos-upload.service`: returns at once; a drain already
/// running is not started twice (it re-reads the queue between items). Best effort: a failure
/// is logged, and the timer starts the service within 30 minutes anyway.
pub fn kick(runner: &dyn Runner) {
    let cmd = Cmd::new(
        "systemctl",
        &["--no-ask-password", "start", "--no-block", SERVICE],
    )
    .timeout(SYSTEMCTL_TIMEOUT);
    match runner.run(&cmd) {
        Ok(o) if o.code == 0 => {}
        Ok(o) => log::warn!(
            "starting {SERVICE} failed (exit code {}): {}; the timer starts it later",
            o.code,
            o.stderr.trim()
        ),
        Err(e) => log::warn!("starting {SERVICE} failed: {e:#}; the timer starts it later"),
    }
}

/// `mastersos-agent upload kick` (the NetworkManager dispatcher, on full connectivity): every
/// queued item that failed before now is due again with its backoff started over, and the
/// service is started when anything is queued.
pub fn kick_main(state_dir: &std::path::Path, runner: &dyn Runner) -> anyhow::Result<()> {
    let q = queue::Queue::new(state_dir);
    if q.is_empty() {
        return Ok(());
    }
    q.mark_kicked(chrono::Utc::now())?;
    kick(runner);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::FakeRunner;

    #[test]
    fn kick_starts_the_service_only_with_work() {
        let d = tempfile::tempdir().unwrap();
        let r = FakeRunner::new();
        kick_main(d.path(), &r).unwrap();
        assert!(r.calls().is_empty(), "empty queue: nothing started");
        let q = queue::Queue::new(d.path());
        q.enqueue_collect(1, Default::default(), None, chrono::Utc::now())
            .unwrap();
        kick_main(d.path(), &r).unwrap();
        assert_eq!(
            r.calls(),
            ["systemctl --no-ask-password start --no-block mastersos-upload.service"]
        );
        assert!(q.kicked_at().is_some());
    }
}
