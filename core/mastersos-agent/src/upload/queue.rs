//! The upload queue on disk (spec design 3): `/var/lib/mastersos/upload-queue/` (root, 0700), one
//! JSON file per item (0600) plus the archive files the items name. Nothing is kept in memory
//! between runs: a shutdown or a crash loses nothing, and the next [`crate::upload::drain`] picks
//! up where the last one stopped.
//!
//! Item kinds ([`Job`]):
//! - `collect`: a `collect-diagnostics` command the agent acked `running`; the drain collects it
//!   into an `archive`.
//! - `archive`: a packed archive waiting for its three-step upload (size and SHA-256 computed
//!   when it was packed).
//! - `ack`: a final inbox result (`done` / `failed`) whose send failed; retried on its own so a
//!   finished upload is never uploaded again.
//!
//! - `support`: a help request to send (Task 5b). The request itself, its state and its ticket
//!   stay in the support store ([`crate::support::store`]); this item only says "send it" and
//!   carries the retry state. Once the ticket is in, the drain collects the attachment into an
//!   `archive` for [`Target::Ticket`] and this item goes.
//!
//! An item this version cannot read (a newer kind) is left alone.
//!
//! Every item carries its [`Retry`] state: exponential backoff from 1 minute up to 1 hour with
//! jitter, or the server's `Retry-After`. A kick ([`Queue::mark_kicked`], NetworkManager reaching full
//! connectivity) makes every item that failed before it due at once and restarts its backoff,
//! except a server's `Retry-After`. The kick time is kept beside the queue, not in it, so that
//! `ConditionDirectoryNotEmpty=` of the service only sees real work.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, TimeDelta, Utc};
use mastersos_bundle::diag::CollectDiagnostics;
use mastersos_bundle::push::InboxResultState;
use serde::{Deserialize, Serialize};

use crate::safefs;

/// The queue directory under the agent's state directory.
pub const QUEUE_DIR: &str = "upload-queue";
/// The last kick (RFC 3339), beside the queue directory.
pub const KICK_FILE: &str = "upload-kick";
/// The whole queue (items and archives) stays at or below this; the oldest archives go first.
pub const MAX_QUEUE_BYTES: u64 = 100 * 1024 * 1024;
/// A temporary file (dot name) older than this is a leftover of a crash.
pub const TMP_LEFTOVER_AGE: Duration = Duration::from_secs(10 * 60);
/// The first wait after a failure.
pub const BACKOFF_START: Duration = Duration::from_secs(60);
/// The longest wait between two tries (before the jitter).
pub const BACKOFF_MAX: Duration = Duration::from_secs(3600);

/// The work of one item.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Job {
    /// Collect for the `collect-diagnostics` inbox message `seq`.
    Collect {
        seq: u64,
        request: CollectDiagnostics,
        /// The message's own deadline; past it the command is acked `failed`.
        expires_at: Option<DateTime<Utc>>,
        /// Collections started (a collection that never finished, e.g. killed for memory,
        /// counts too).
        #[serde(default)]
        tries: u32,
    },
    /// Upload the archive `file` (in the queue directory).
    Archive {
        target: Target,
        file: String,
        bytes: u64,
        sha256: String,
        /// The command's deadline (inbox archives); past it the command is acked `failed`.
        expires_at: Option<DateTime<Utc>>,
        /// Why the latest try failed (`upload: …` without the prefix), for the final ack.
        #[serde(default)]
        last_error: Option<String>,
    },
    /// Send this final result for inbox message `seq`.
    Ack {
        seq: u64,
        state: InboxResultState,
        detail: String,
    },
    /// Send the help request `client_id` of the support store, then collect its attachment.
    Support {
        client_id: String,
        /// Attachment collections started (like [`Job::Collect`]'s `tries`).
        #[serde(default)]
        tries: u32,
    },
}

/// What an archive answers.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "for", rename_all = "snake_case")]
pub enum Target {
    Inbox { seq: u64 },
    Ticket { client_id: String },
}

/// Retry state of an item. Times are wall-clock: the drain is a fresh process every time.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct Retry {
    /// Consecutive failures.
    pub attempt: u32,
    /// When the latest try failed.
    pub last_try: Option<DateTime<Utc>>,
    /// Not tried again before this.
    pub not_before: Option<DateTime<Utc>>,
    /// `not_before` is the server's `Retry-After`: a kick does not override it.
    #[serde(default)]
    pub server_said: bool,
}

impl Retry {
    /// Whether the item may be tried at `now`, given the latest kick.
    pub fn due(&self, now: DateTime<Utc>, kicked: Option<DateTime<Utc>>) -> bool {
        let Some(nb) = self.not_before else {
            return true;
        };
        if nb <= now {
            return true;
        }
        !self.server_said && kicked.is_some_and(|k| self.last_try.is_none_or(|t| k >= t))
    }

    /// A kick after the latest failure starts the backoff over.
    pub fn take_kick(&mut self, kicked: Option<DateTime<Utc>>) {
        if !self.server_said
            && self.attempt > 0
            && kicked.is_some_and(|k| self.last_try.is_none_or(|t| k >= t))
        {
            self.attempt = 0;
        }
    }

    /// Records a failure at `now`: wait `retry_after` when the server gave one, else the
    /// backoff of this failure ([`crate::backoff::backoff`], `unit` its jitter).
    pub fn failed(&mut self, now: DateTime<Utc>, retry_after: Option<Duration>, unit: f64) {
        let wait = match retry_after {
            Some(d) => d,
            None => crate::backoff::backoff(self.attempt, BACKOFF_START, BACKOFF_MAX, unit),
        };
        self.server_said = retry_after.is_some();
        self.attempt = self.attempt.saturating_add(1);
        self.last_try = Some(now);
        self.not_before = Some(now + TimeDelta::from_std(wait).unwrap_or(TimeDelta::hours(1)));
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Item {
    pub created_at: DateTime<Utc>,
    #[serde(flatten)]
    pub job: Job,
    #[serde(default)]
    pub retry: Retry,
}

impl Item {
    pub fn new(job: Job, now: DateTime<Utc>) -> Item {
        Item {
            created_at: now,
            job,
            retry: Retry::default(),
        }
    }

    /// The queue file name of this item.
    pub fn name(&self) -> String {
        match &self.job {
            Job::Collect { seq, .. } => collect_name(*seq),
            Job::Archive { target, .. } => archive_name(target),
            Job::Ack { seq, .. } => ack_name(*seq),
            Job::Support { client_id, .. } => support_name(client_id),
        }
    }
}

pub fn collect_name(seq: u64) -> String {
    format!("collect-{seq}.json")
}

pub fn ack_name(seq: u64) -> String {
    format!("ack-{seq}.json")
}

pub fn support_name(client_id: &str) -> String {
    format!("support-{client_id}.json")
}

fn archive_stem(t: &Target) -> String {
    match t {
        Target::Inbox { seq } => format!("archive-inbox-{seq}"),
        Target::Ticket { client_id } => format!("archive-ticket-{client_id}"),
    }
}

pub fn archive_name(t: &Target) -> String {
    format!("{}.json", archive_stem(t))
}

/// The archive file of `t` in the queue directory.
pub fn archive_file(t: &Target) -> String {
    format!("{}.tar.zst", archive_stem(t))
}

/// The upload queue at one directory.
#[derive(Debug, Clone)]
pub struct Queue {
    dir: PathBuf,
}

impl Queue {
    /// The queue of the agent whose state directory is `state_dir`.
    pub fn new(state_dir: &Path) -> Queue {
        Queue {
            dir: state_dir.join(QUEUE_DIR),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The path of `name` in the queue directory.
    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn kick_path(&self) -> PathBuf {
        self.dir.with_file_name(KICK_FILE)
    }

    /// The directory, created (0700) when `create`; `None` when it is missing and not created.
    fn open(&self, create: bool) -> Result<Option<OwnedFd>> {
        match safefs::open_abs_dir(&self.dir, create) {
            Ok(fd) => {
                if create {
                    safefs::set_mode(&fd, 0o700)?;
                }
                Ok(Some(fd))
            }
            Err(e) if !create && crate::apply::is_not_found(&e) => Ok(None),
            Err(e) => Err(e.context(format!("opening {}", self.dir.display()))),
        }
    }

    /// The directory, created (0700) when missing: for writing archives into it.
    pub fn ensure(&self) -> Result<()> {
        self.open(true).map(|_| ())
    }

    /// Queues a new item (written like [`Queue::put`]); start the service afterwards with
    /// [`crate::upload::kick`]. An item of the same name already queued is replaced.
    pub fn enqueue(&self, item: &Item) -> Result<()> {
        self.put(item)
    }

    /// Writes `item` (0600, atomically) under its name: a new item, or an item's new state.
    pub fn put(&self, item: &Item) -> Result<()> {
        let dir = self.open(true)?.expect("created");
        let mut bytes = serde_json::to_vec_pretty(item)?;
        bytes.push(b'\n');
        safefs::write_at(&dir, &item.name(), &bytes, 0o600)
            .with_context(|| format!("writing {} in the upload queue", item.name()))?;
        Ok(())
    }

    /// Removes the item `name` and, for an archive, its file.
    pub fn remove(&self, item: &Item) -> Result<()> {
        let Some(dir) = self.open(false)? else {
            return Ok(());
        };
        safefs::remove_at(&dir, &item.name())?;
        if let Job::Archive { file, .. } = &item.job {
            safefs::remove_at(&dir, file)?;
        }
        Ok(())
    }

    /// Whether an item called `name` is queued.
    pub fn has(&self, name: &str) -> bool {
        self.dir.join(name).is_file()
    }

    /// The items this version can read, oldest first (then by name). Unreadable ones are
    /// logged and left alone.
    pub fn list(&self) -> Result<Vec<Item>> {
        let Some(dir) = self.open(false)? else {
            return Ok(vec![]);
        };
        let mut out = vec![];
        for name in safefs::list_at(&dir)? {
            if name.starts_with('.') || !name.ends_with(".json") {
                continue;
            }
            let item = safefs::read_at(&dir, &name)
                .and_then(|b| b.context("vanished"))
                .and_then(|b| serde_json::from_slice::<Item>(&b).map_err(Into::into));
            match item {
                Ok(i) if i.name() == name => out.push(i),
                Ok(_) => log::warn!("upload queue: {name} does not match its content, left alone"),
                Err(e) => log::warn!("upload queue: {name} not readable, left alone: {e:#}"),
            }
        }
        out.sort_by_key(|i| (i.created_at, i.name()));
        Ok(out)
    }

    /// True when the directory has anything in it (what `ConditionDirectoryNotEmpty=` sees).
    pub fn is_empty(&self) -> bool {
        std::fs::read_dir(&self.dir).map_or(true, |mut d| d.next().is_none())
    }

    /// Total bytes of the regular files in the queue directory.
    pub fn total_bytes(&self) -> u64 {
        let Ok(rd) = std::fs::read_dir(&self.dir) else {
            return 0;
        };
        rd.filter_map(|e| e.ok())
            .filter_map(|e| e.metadata().ok())
            .filter(|m| m.is_file())
            .map(|m| m.len())
            .sum()
    }

    /// Removes files nothing refers to: temporary files and archives of finished or lost items
    /// (only one drain runs at a time, so nothing is being written now).
    pub fn remove_orphans(&self) -> Result<()> {
        let Some(dir) = self.open(false)? else {
            return Ok(());
        };
        let items = self.list()?;
        let mut keep: Vec<String> = items.iter().map(Item::name).collect();
        keep.extend(items.iter().filter_map(|i| match &i.job {
            Job::Archive { file, .. } => Some(file.clone()),
            _ => None,
        }));
        for name in safefs::list_at(&dir)? {
            // Temporary files may belong to a writer at work right now (the agent queues items
            // while a drain runs): only old ones are leftovers.
            let ours = if name.starts_with('.') {
                safefs::mtime_at(&dir, &name)
                    .ok()
                    .flatten()
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|age| age >= TMP_LEFTOVER_AGE)
            } else {
                name.ends_with(".tar.zst")
            };
            if ours && !keep.contains(&name) {
                log::info!("upload queue: removing the leftover {name}");
                safefs::remove_at(&dir, &name)?;
            }
        }
        Ok(())
    }

    /// Queues a collection for inbox message `seq`; nothing when that command is already
    /// queued at any stage.
    pub fn enqueue_collect(
        &self,
        seq: u64,
        request: CollectDiagnostics,
        expires_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if self.has(&collect_name(seq))
            || self.has(&archive_name(&Target::Inbox { seq }))
            || self.has(&ack_name(seq))
        {
            return Ok(());
        }
        self.enqueue(&Item::new(
            Job::Collect {
                seq,
                request,
                expires_at,
                tries: 0,
            },
            now,
        ))
    }

    /// Queues the help request `client_id` (a lowercase UUID: it names files) for sending;
    /// nothing when it is already queued at any stage.
    pub fn enqueue_support(&self, client_id: &str, now: DateTime<Utc>) -> Result<()> {
        anyhow::ensure!(
            mastersos_bundle::valid_school_id(client_id),
            "not a client id: {client_id:?}"
        );
        let target = Target::Ticket {
            client_id: client_id.to_string(),
        };
        if self.has(&support_name(client_id)) || self.has(&archive_name(&target)) {
            return Ok(());
        }
        self.enqueue(&Item::new(
            Job::Support {
                client_id: client_id.to_string(),
                tries: 0,
            },
            now,
        ))
    }

    /// Records a kick at `now` (NetworkManager reached full connectivity).
    pub fn mark_kicked(&self, now: DateTime<Utc>) -> Result<()> {
        let p = self.kick_path();
        let parent = p.parent().context("the kick file has no folder")?;
        let dir = safefs::open_abs_dir(parent, false)?;
        safefs::write_at(
            &dir,
            KICK_FILE,
            format!("{}\n", now.to_rfc3339()).as_bytes(),
            0o600,
        )?;
        Ok(())
    }

    /// The latest kick, if any.
    pub fn kicked_at(&self) -> Option<DateTime<Utc>> {
        let text = std::fs::read_to_string(self.kick_path()).ok()?;
        DateTime::parse_from_rfc3339(text.trim())
            .ok()
            .map(|t| t.to_utc())
    }

    /// Removes archive items, oldest first, until the queue fits in `max` bytes; returns the
    /// removed items (the caller acks their commands). Other items are never removed.
    pub fn trim_to(&self, max: u64) -> Result<Vec<Item>> {
        let mut dropped = vec![];
        if self.total_bytes() <= max {
            return Ok(dropped);
        }
        for item in self.list()? {
            if !matches!(item.job, Job::Archive { .. }) {
                continue;
            }
            self.remove(&item)?;
            dropped.push(item);
            if self.total_bytes() <= max {
                break;
            }
        }
        Ok(dropped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().to_utc()
    }

    fn queue() -> (tempfile::TempDir, Queue) {
        let d = tempfile::tempdir().unwrap();
        let q = Queue::new(d.path());
        (d, q)
    }

    fn archive(q: &Queue, seq: u64, bytes: usize, at: &str) -> Item {
        let target = Target::Inbox { seq };
        q.ensure().unwrap();
        std::fs::write(q.path(&archive_file(&target)), vec![7u8; bytes]).unwrap();
        let item = Item::new(
            Job::Archive {
                file: archive_file(&target),
                target,
                bytes: bytes as u64,
                sha256: "a".repeat(64),
                expires_at: None,
                last_error: None,
            },
            t(at),
        );
        q.put(&item).unwrap();
        item
    }

    #[test]
    fn items_round_trip_with_private_modes() {
        let (_d, q) = queue();
        let now = t("2026-11-05T08:00:00Z");
        q.enqueue_collect(4, CollectDiagnostics::default(), None, now)
            .unwrap();
        // Queued twice (a resent message): still one item.
        q.enqueue_collect(4, CollectDiagnostics::default(), None, now)
            .unwrap();
        let items = q.list().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name(), "collect-4.json");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(q.dir()), 0o700);
        assert_eq!(mode(&q.path("collect-4.json")), 0o600);
        let text = std::fs::read_to_string(q.path("collect-4.json")).unwrap();
        assert!(text.contains("\"kind\": \"collect\""), "{text}");
        // An archive for the seq already exists: no new collection.
        archive(&q, 5, 10, "2026-11-05T08:00:00Z");
        q.enqueue_collect(5, CollectDiagnostics::default(), None, now)
            .unwrap();
        assert!(!q.has("collect-5.json"));
    }

    #[test]
    fn support_items_round_trip() {
        let (_d, q) = queue();
        let id = "0192f3a4-5b6c-7d8e-9f00-112233445566";
        let now = t("2026-11-05T08:00:00Z");
        q.enqueue_support(id, now).unwrap();
        q.enqueue_support(id, now).unwrap();
        let items = q.list().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name(), format!("support-{id}.json"));
        assert_eq!(
            items[0].job,
            Job::Support {
                client_id: id.into(),
                tries: 0
            }
        );
        assert!(q.enqueue_support("../x", now).is_err(), "names files");
    }

    #[test]
    fn unreadable_items_are_left_alone() {
        let (_d, q) = queue();
        q.ensure().unwrap();
        std::fs::write(q.path("later-x.json"), r#"{"kind":"later"}"#).unwrap();
        std::fs::write(q.path("collect-9.json"), "not json").unwrap();
        assert!(q.list().unwrap().is_empty());
        q.remove_orphans().unwrap();
        assert!(q.path("later-x.json").exists(), "a newer kind is kept");
        assert!(q.path("collect-9.json").exists());
    }

    #[test]
    fn orphans_are_removed() {
        let (_d, q) = queue();
        archive(&q, 1, 10, "2026-11-05T08:00:00Z");
        std::fs::write(q.path("diag-20261105T080000Z.tar.zst"), b"x").unwrap();
        std::fs::write(q.path(".diag-x.tar.zst.tmp"), b"x").unwrap();
        std::fs::File::options()
            .write(true)
            .open(q.path(".diag-x.tar.zst.tmp"))
            .unwrap()
            .set_modified(std::time::SystemTime::now() - Duration::from_secs(3600))
            .unwrap();
        q.remove_orphans().unwrap();
        let mut names: Vec<String> = std::fs::read_dir(q.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["archive-inbox-1.json", "archive-inbox-1.tar.zst"]);
    }

    /// A temporary file the agent is writing right now (safefs: create, then rename) is not
    /// touched; one left from a crash long ago is.
    #[test]
    fn fresh_temporary_files_are_kept() {
        let (_d, q) = queue();
        q.ensure().unwrap();
        let fresh = q.path(".collect-4.json.mastersos-tmp");
        std::fs::write(&fresh, b"{").unwrap();
        let old = q.path(".collect-3.json.mastersos-tmp");
        std::fs::write(&old, b"{").unwrap();
        let f = std::fs::File::options().write(true).open(&old).unwrap();
        f.set_modified(std::time::SystemTime::now() - Duration::from_secs(11 * 60))
            .unwrap();
        q.remove_orphans().unwrap();
        assert!(fresh.exists(), "being written");
        assert!(!old.exists(), "left over");
    }

    #[test]
    fn trim_drops_oldest_archives_only() {
        let (_d, q) = queue();
        q.enqueue_collect(
            9,
            CollectDiagnostics::default(),
            None,
            t("2026-11-05T07:00:00Z"),
        )
        .unwrap();
        archive(&q, 2, 600, "2026-11-05T08:00:00Z");
        archive(&q, 1, 600, "2026-11-05T07:30:00Z");
        archive(&q, 3, 600, "2026-11-05T09:00:00Z");
        let dropped = q.trim_to(1500).unwrap();
        let seqs: Vec<String> = dropped.iter().map(Item::name).collect();
        assert_eq!(seqs, ["archive-inbox-1.json", "archive-inbox-2.json"]);
        assert!(q.total_bytes() <= 1500);
        assert!(q.has("collect-9.json"));
        assert!(q.has("archive-inbox-3.json"));
        assert!(!q.path("archive-inbox-1.tar.zst").exists());
    }

    #[test]
    fn backoff_kick_and_retry_after() {
        let now = t("2026-11-05T08:00:00Z");
        let mut r = Retry::default();
        assert!(r.due(now, None));
        r.failed(now, None, 0.5);
        assert_eq!(r.not_before, Some(t("2026-11-05T08:01:00Z")));
        assert!(!r.due(t("2026-11-05T08:00:59Z"), None));
        assert!(r.due(t("2026-11-05T08:01:00Z"), None));
        r.failed(t("2026-11-05T08:01:00Z"), None, 0.5);
        assert_eq!(r.not_before, Some(t("2026-11-05T08:03:00Z")), "doubled");
        for _ in 0..20 {
            r.failed(now, None, 1.0);
        }
        assert_eq!(
            r.not_before,
            Some(now + TimeDelta::seconds(4320)),
            "1 h cap ×1.2"
        );
        // A kick after the failure: due now, the backoff starts over.
        let kick = Some(now + TimeDelta::seconds(5));
        assert!(r.due(now + TimeDelta::seconds(10), kick));
        assert!(!r.due(
            now + TimeDelta::seconds(10),
            Some(now - TimeDelta::seconds(5))
        ));
        r.take_kick(kick);
        assert_eq!(r.attempt, 0);
        // The server's Retry-After holds whatever the kicks.
        let mut s = Retry::default();
        s.failed(now, Some(Duration::from_secs(600)), 0.5);
        assert_eq!(s.not_before, Some(t("2026-11-05T08:10:00Z")));
        assert!(!s.due(
            now + TimeDelta::seconds(60),
            Some(now + TimeDelta::seconds(30))
        ));
        s.take_kick(Some(now + TimeDelta::seconds(30)));
        assert_eq!(s.attempt, 1);
    }

    #[test]
    fn kick_is_beside_the_queue() {
        let (d, q) = queue();
        assert_eq!(q.kicked_at(), None);
        q.mark_kicked(t("2026-11-05T08:00:00Z")).unwrap();
        assert_eq!(q.kicked_at(), Some(t("2026-11-05T08:00:00Z")));
        assert!(d.path().join(KICK_FILE).exists());
        assert!(q.is_empty(), "the kick does not make the queue look busy");
    }
}
