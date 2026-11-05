//! The local support queue (plan 2026-11-05 Task 5): `/var/lib/mastersos/support-queue/` (root 0700), one
//! `<client_id>.json` (0600, an [`Item`]) per help request and its `<client_id>.png` (0600) when the student attached a
//! screenshot, plus `rate.json` (0600), the submit times and uids of the last hour ([`SUPPORT_MAX_PER_HOUR`] per
//! machine, [`MAX_PER_UID_PER_HOUR`] per uid). The queue holds at most [`MAX_QUEUE_ITEMS`] unfinished items or
//! [`MAX_QUEUE_BYTES`]; when it is full new requests are refused, never queued ones dropped. The sender
//! ([`super::send`]) keeps finished items a week for `status`, then deletes them.
//!
//! Two processes write here: the support host (new items, the rate file) and the sender (Task 5b: ticket, state,
//! attachment). Every read-modify-write holds [`Store::lock`] (`flock` on `.lock`), so the single-writer rule of
//! [`safefs::TmpFile`] holds per file.
//!
//! An item survives a restart or a power cut: it is written (fsync, rename) before the student is told "queued", and its
//! `client_id` never changes, so a resend after a crash gets the same ticket from the cloud.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use mastersos_bundle::diag::{SupportRequest, SUPPORT_MAX_PER_HOUR};
use serde::{Deserialize, Serialize};

use crate::safefs;

pub const RATE_FILE: &str = "rate.json";
/// Most submits one uid makes per hour, inside the machine's [`SUPPORT_MAX_PER_HOUR`]: one account (the guest, a kiosk
/// app) cannot use the whole budget.
pub const MAX_PER_UID_PER_HOUR: usize = 2;
/// Most items in the queue.
pub const MAX_QUEUE_ITEMS: usize = 20;
/// Most bytes of the queue's items and screenshots together.
pub const MAX_QUEUE_BYTES: u64 = 50 * 1024 * 1024;
const LOCK_FILE: &str = ".lock";
const ITEM_EXT: &str = ".json";
const SCREENSHOT_EXT: &str = ".png";

/// Where a help request is, as the dialogs show it (`status` answers this).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ItemState {
    /// On this machine, not accepted by the cloud yet.
    Queued,
    /// The cloud gave it a ticket ([`Item::ticket`]).
    Sent,
    /// The cloud refused it for good (`invalid`); kept only so the dialog can say so.
    Failed,
    /// The school turned help requests off (`support_disabled`).
    Disabled,
}

/// `<client_id>.json`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// What goes to `POST /v1/support`, as built when the student pressed Send.
    pub request: SupportRequest,
    /// The peer uid that submitted it: only that uid may ask for its status.
    pub uid: u32,
    pub state: ItemState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
    pub created_at: DateTime<Utc>,
    /// The attachment archive has been uploaded (or given up on): nothing left to send.
    #[serde(default)]
    pub attach_done: bool,
}

impl Item {
    pub fn new(request: SupportRequest, uid: u32, now: DateTime<Utc>) -> Item {
        Item {
            request,
            uid,
            state: ItemState::Queued,
            ticket: None,
            created_at: now,
            attach_done: false,
        }
    }

    /// Nothing left to send: the ticket and its attachment are in (or given up on), or the cloud refused it.
    pub fn finished(&self) -> bool {
        match self.state {
            ItemState::Queued => false,
            ItemState::Sent => self.attach_done,
            ItemState::Failed | ItemState::Disabled => true,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct Rate {
    #[serde(default)]
    submitted: Vec<Submitted>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
struct Submitted {
    at: DateTime<Utc>,
    uid: u32,
}

/// The queue directory. Opening is lazy: every call opens the directory (creating it 0700) by its absolute path.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
    max_items: usize,
    max_bytes: u64,
}

/// Held while reading and writing the queue; released on drop.
pub struct StoreLock {
    _fd: OwnedFd,
}

/// A client id is a lowercase UUID, which is also what keeps it a plain file name.
fn item_name(client_id: &str, ext: &str) -> Result<String> {
    anyhow::ensure!(
        mastersos_bundle::valid_school_id(client_id),
        "not a client id: {client_id:?}"
    );
    Ok(format!("{client_id}{ext}"))
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>) -> Store {
        Store {
            dir: dir.into(),
            max_items: MAX_QUEUE_ITEMS,
            max_bytes: MAX_QUEUE_BYTES,
        }
    }

    /// Other queue limits than [`MAX_QUEUE_ITEMS`] and [`MAX_QUEUE_BYTES`] (tests).
    pub fn with_limits(mut self, max_items: usize, max_bytes: u64) -> Store {
        self.max_items = max_items;
        self.max_bytes = max_bytes;
        self
    }

    /// Whether the queue has room for one more item: fewer unfinished items ([`Item::finished`]) than its item limit,
    /// and all its items and screenshots together under its byte limit. Finished items stay a week for `status`
    /// (Task 5b) and are small. Hold the lock.
    pub fn has_room(&self) -> Result<bool> {
        let d = self.open()?;
        let finished = self.list()?.iter().filter(|i| i.finished()).count();
        let (mut items, mut bytes) = (0usize, 0u64);
        for name in safefs::list_at(&d)? {
            let Some(id) = name
                .strip_suffix(ITEM_EXT)
                .or_else(|| name.strip_suffix(SCREENSHOT_EXT))
            else {
                continue;
            };
            if !mastersos_bundle::valid_school_id(id) {
                continue;
            }
            if name.ends_with(ITEM_EXT) {
                items += 1;
            }
            let st = rustix::fs::statat(&d, name.as_str(), rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                .map_err(std::io::Error::from)
                .with_context(|| format!("checking {name}"))?;
            bytes = bytes.saturating_add(u64::try_from(st.st_size).unwrap_or(0));
        }
        Ok(items.saturating_sub(finished) < self.max_items && bytes < self.max_bytes)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn open(&self) -> Result<OwnedFd> {
        let d = safefs::open_abs_dir(&self.dir, true)
            .with_context(|| format!("opening {}", self.dir.display()))?;
        safefs::set_mode(&d, 0o700)?;
        Ok(d)
    }

    /// Takes the queue's lock (blocking).
    pub fn lock(&self) -> Result<StoreLock> {
        use rustix::fs::{flock, openat, FlockOperation, Mode, OFlags};
        let d = self.open()?;
        let fd = openat(
            &d,
            LOCK_FILE,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(std::io::Error::from)
        .context("opening the support queue lock")?;
        flock(&fd, FlockOperation::LockExclusive)
            .map_err(std::io::Error::from)
            .context("locking the support queue")?;
        Ok(StoreLock { _fd: fd })
    }

    /// Writes a new item and its screenshot (screenshot first: an item never points at a missing one). Hold the lock.
    pub fn put_new(&self, item: &Item, screenshot: Option<&[u8]>) -> Result<()> {
        let d = self.open()?;
        if let Some(png) = screenshot {
            safefs::write_at(
                &d,
                &item_name(&item.request.client_id, SCREENSHOT_EXT)?,
                png,
                0o600,
            )?;
        }
        self.write_item(&d, item)
    }

    /// Replaces an existing item (the sender: ticket, state, attachment). Hold the lock.
    pub fn update(&self, item: &Item) -> Result<()> {
        let d = self.open()?;
        self.write_item(&d, item)
    }

    fn write_item(&self, d: &OwnedFd, item: &Item) -> Result<()> {
        let name = item_name(&item.request.client_id, ITEM_EXT)?;
        safefs::write_at(d, &name, &serde_json::to_vec_pretty(item)?, 0o600)?;
        Ok(())
    }

    /// The item with this client id; `None` when there is none or the id is not a client id.
    pub fn get(&self, client_id: &str) -> Result<Option<Item>> {
        let Ok(name) = item_name(client_id, ITEM_EXT) else {
            return Ok(None);
        };
        let d = self.open()?;
        match safefs::read_at(&d, &name)? {
            None => Ok(None),
            Some(b) => Ok(Some(
                serde_json::from_slice(&b).with_context(|| format!("parsing {name}"))?,
            )),
        }
    }

    /// Every item, oldest first. One that does not parse is logged and skipped (left on disk for IT to look at).
    pub fn list(&self) -> Result<Vec<Item>> {
        let d = self.open()?;
        let mut out = Vec::new();
        for name in safefs::list_at(&d)? {
            let Some(id) = name.strip_suffix(ITEM_EXT) else {
                continue;
            };
            if !mastersos_bundle::valid_school_id(id) {
                continue;
            }
            let Some(b) = safefs::read_at(&d, &name)? else {
                continue;
            };
            match serde_json::from_slice::<Item>(&b) {
                Ok(i) => out.push(i),
                Err(e) => log::error!("support queue: {name} does not parse ({e}); skipping it"),
            }
        }
        out.sort_by_key(|i| i.created_at);
        Ok(out)
    }

    /// The screenshot of that item, if it has one.
    pub fn screenshot(&self, client_id: &str) -> Result<Option<Vec<u8>>> {
        let d = self.open()?;
        safefs::read_at(&d, &item_name(client_id, SCREENSHOT_EXT)?)
    }

    /// Removes the screenshot only (the attachment is done or given up). Hold the lock.
    pub fn remove_screenshot(&self, client_id: &str) -> Result<()> {
        let d = self.open()?;
        safefs::remove_at(&d, &item_name(client_id, SCREENSHOT_EXT)?)
    }

    /// Removes the item and its screenshot. Hold the lock.
    pub fn remove(&self, client_id: &str) -> Result<()> {
        let d = self.open()?;
        safefs::remove_at(&d, &item_name(client_id, SCREENSHOT_EXT)?)?;
        safefs::remove_at(&d, &item_name(client_id, ITEM_EXT)?)
    }

    /// The submits still inside the hour before `now`. Times after `now` (the clock was set back) are dropped, so a
    /// clock change cannot lock the machine out. A rate file that does not parse counts as empty.
    fn recent(&self, d: &OwnedFd, now: DateTime<Utc>) -> Result<Vec<Submitted>> {
        let rate: Rate = match safefs::read_at(d, RATE_FILE)? {
            None => Rate::default(),
            Some(b) => serde_json::from_slice(&b).unwrap_or_else(|e| {
                log::error!("support queue: {RATE_FILE} does not parse ({e}); starting it again");
                Rate::default()
            }),
        };
        let from = now - Duration::hours(1);
        Ok(rate
            .submitted
            .into_iter()
            .filter(|s| s.at > from && s.at <= now)
            .collect())
    }

    /// Whether `uid` may submit at `now`: under [`SUPPORT_MAX_PER_HOUR`] for the machine and
    /// [`MAX_PER_UID_PER_HOUR`] for the uid in the last hour. Hold the lock.
    pub fn rate_allows(&self, now: DateTime<Utc>, uid: u32) -> Result<bool> {
        let d = self.open()?;
        let recent = self.recent(&d, now)?;
        let mine = recent.iter().filter(|s| s.uid == uid).count();
        Ok(recent.len() < SUPPORT_MAX_PER_HOUR as usize && mine < MAX_PER_UID_PER_HOUR)
    }

    /// Counts a submit by `uid` at `now`. Hold the lock.
    pub fn record_submit(&self, now: DateTime<Utc>, uid: u32) -> Result<()> {
        let d = self.open()?;
        let mut submitted = self.recent(&d, now)?;
        submitted.push(Submitted { at: now, uid });
        let bytes = serde_json::to_vec(&Rate { submitted })?;
        safefs::write_at(&d, RATE_FILE, &bytes, 0o600)?;
        Ok(())
    }
}
