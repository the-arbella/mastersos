//! `mastersos-agent upload drain` (spec design 3 and 4): works through the [`Queue`] once,
//! oldest item first, and exits when nothing is due within [`LINGER`].
//!
//! - `collect`: past the command's `expires_at` → ack `failed` ([`crate::inbox::DETAIL_EXPIRED`]).
//!   Otherwise show the notice ([`NOTICE`] in every person's session, the login screen's line
//!   through `status.json`), collect ([`crate::diag::collect`]), and turn the item into an
//!   `archive` (the archive file first, then its item, then the `collect` item goes: a crash
//!   at any point leaves one of them, never neither). A collection that fails is acked
//!   `failed` `collect: …`; one that never finishes (killed) is given up after
//!   [`MAX_COLLECT_TRIES`] starts.
//! - `archive`: the three-step upload ([`crate::diag::upload::upload`]); done → ack `done`
//!   `diag:<id>`; a failure is handled by its [`ErrorAction`] (Ruling P5): drop or give up →
//!   ack `failed` `upload: …`; otherwise keep it and wait (the server's `Retry-After`, else the
//!   backoff); past the command's `expires_at` → ack `failed` `upload: <the last error>`.
//! - `ack`: a final result whose send failed before; sent again with the backoff, given up
//!   after [`ACK_KEEP_DAYS`] days (the server marks the command failed by itself then).
//!
//! On battery below [`LOW_BATTERY_PERCENT`] % with no power connected only the small items go
//! (acks, and Task 5's help requests); collections and archives wait for power. Over
//! [`MAX_QUEUE_BYTES`] the oldest archives are dropped (acked `failed` [`DETAIL_QUEUE_FULL`]).
//! Every final ack is sent at once; one that cannot be sent is queued as an `ack` item before
//! its source item goes.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, TimeDelta, Utc};
use mastersos_bundle::diag::{
    CollectDiagnostics, DiagKind, DiagRange, DiagUploadRequest, ErrorAction, DIAG_INBOX_MAX_BYTES,
};
use mastersos_bundle::push::{InboxResult, InboxResultState, INBOX_DETAIL_MAX_CHARS};

use super::queue::{archive_file, Item, Job, Queue, Target, MAX_QUEUE_BYTES};
use crate::backoff::Jitter;
use crate::diag::{collect, CollectOpts};
use crate::fetch::{DeviceCred, Fetcher, InboxSeqUnknown};
use crate::runner::Runner;
use crate::system::SysPaths;

/// Shown in every session (and as the login screen's line) when a collection starts.
pub const NOTICE: &str = "IT is collecting diagnostic info from this computer.";
/// The login screen's line stays up at most this long from the start of a collection (it is
/// cleared as soon as the collection ends).
pub const NOTICE_FOR: TimeDelta = TimeDelta::minutes(30);
/// A collection started this many times without finishing is given up.
pub const MAX_COLLECT_TRIES: u32 = 3;
/// An `ack` item older than this is given up.
pub const ACK_KEEP_DAYS: i64 = 7;
/// Below this battery level, without power, archives wait.
pub const LOW_BATTERY_PERCENT: u32 = 15;
pub const DETAIL_QUEUE_FULL: &str = "dropped: queue full";
/// Something due within this long keeps the drain waiting instead of exiting (the timer
/// covers longer waits).
pub const LINGER: Duration = Duration::from_secs(5 * 60);
/// While waiting, the queue and the kick file are looked at this often.
pub const POLL: Duration = Duration::from_secs(15);
/// One drain run never waits past this.
pub const MAX_RUN: Duration = Duration::from_secs(60 * 60);

pub struct DrainCtx<'a> {
    pub queue: &'a Queue,
    pub fetcher: &'a Fetcher,
    pub cred: &'a DeviceCred,
    /// Runs the collector's commands and the notices.
    pub runner: Arc<dyn Runner>,
    /// `root`: what the collector reads and where the batteries are; `public_dir`, `state_dir`:
    /// `status.json` and the collecting marker.
    pub paths: SysPaths,
    pub device_id: &'a str,
    pub lab: bool,
    pub clock: &'a (dyn Fn() -> DateTime<Utc> + Send + Sync),
    pub jitter: Jitter,
    pub max_queue_bytes: u64,
}

/// What one pass left behind.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Pass {
    /// Items still queued.
    pub remaining: usize,
    /// The earliest time a waiting item is due (items held for power not counted).
    pub next_due: Option<DateTime<Utc>>,
    /// An item that was not there when the pass started is due now: queued while the pass
    /// ran, when `systemctl start` of the running service did nothing. Run another pass.
    pub fresh: bool,
}

/// One pass over the queue (see the module docs).
pub async fn drain_once(cx: &DrainCtx<'_>) -> Pass {
    if let Err(e) = cx.queue.remove_orphans() {
        log::warn!("upload queue: {e:#}");
    }
    // A marker left by a run that was killed while collecting.
    if crate::status::collecting_until(&cx.paths).is_some() {
        set_notice(cx, None);
    }
    trim(cx).await;
    let low = low_battery(&cx.paths.root);
    let items = match cx.queue.list() {
        Ok(i) => i,
        Err(e) => {
            log::warn!("upload queue: {e:#}");
            return Pass::default();
        }
    };
    let seen: Vec<String> = items.iter().map(Item::name).collect();
    // A collect item beside the archive or ack of its command: a run was killed between writing
    // the archive and removing the collect item. Dropped first, so that finishing the archive
    // in this pass does not make it look like it still needs collecting.
    let names: Vec<String> = items.iter().map(Item::name).collect();
    let mut work = Vec::with_capacity(items.len());
    for item in items {
        if let Job::Collect { seq, .. } = item.job {
            let archive = super::queue::archive_name(&Target::Inbox { seq });
            if names.contains(&archive) || names.contains(&super::queue::ack_name(seq)) {
                remove(cx, &item);
                continue;
            }
        }
        work.push(item);
    }
    for item in work {
        step(cx, item, low).await;
    }
    let rest = cx.queue.list().unwrap_or_default();
    let now = (cx.clock)();
    let next_due = rest
        .iter()
        .filter(|i| !(low && needs_power(i)))
        .filter_map(|i| i.retry.not_before.filter(|t| *t > now))
        .min();
    let kicked = cx.queue.kicked_at();
    let fresh = rest
        .iter()
        .any(|i| !seen.contains(&i.name()) && !(low && needs_power(i)) && i.retry.due(now, kicked));
    Pass {
        remaining: rest.len(),
        next_due,
        fresh,
    }
}

/// Passes until the queue is empty or nothing is due within [`LINGER`]; waits in between,
/// looking again every [`POLL`] (a kick makes waiting items due at once).
pub async fn drain(cx: &DrainCtx<'_>) {
    let started = Instant::now();
    loop {
        let pass = drain_once(cx).await;
        if pass.fresh {
            continue;
        }
        let Some(next) = pass.next_due else {
            return;
        };
        let wait = (next - (cx.clock)()).to_std().unwrap_or_default();
        if wait > LINGER || started.elapsed() + wait > MAX_RUN {
            log::info!(
                "upload queue: next try in {} s, leaving it to the timer",
                wait.as_secs()
            );
            return;
        }
        let until = Instant::now() + wait;
        let kicked = cx.queue.kicked_at();
        while Instant::now() < until {
            tokio::time::sleep(POLL.min(until - Instant::now())).await;
            if cx.queue.kicked_at() != kicked {
                break;
            }
        }
    }
}

fn needs_power(i: &Item) -> bool {
    matches!(i.job, Job::Collect { .. } | Job::Archive { .. })
}

async fn step(cx: &DrainCtx<'_>, item: Item, low: bool) {
    let now = (cx.clock)();
    match &item.job {
        Job::Collect { .. } => collect_item(cx, item, now, low).await,
        Job::Archive { .. } => archive_item(cx, item, now, low).await,
        Job::Ack { .. } => ack_item(cx, item, now).await,
    }
}

fn remove(cx: &DrainCtx<'_>, item: &Item) {
    if let Err(e) = cx.queue.remove(item) {
        log::warn!("upload queue: removing {} failed: {e:#}", item.name());
    }
}

fn put(cx: &DrainCtx<'_>, item: &Item) -> bool {
    match cx.queue.put(item) {
        Ok(()) => true,
        Err(e) => {
            log::warn!("upload queue: {e:#}");
            false
        }
    }
}

/// Sends the final result of `seq`; when it cannot be sent, queues it as an `ack` item. False
/// only when even that failed (the caller keeps its item then).
async fn final_ack(cx: &DrainCtx<'_>, seq: u64, state: InboxResultState, detail: &str) -> bool {
    let detail: String = detail.chars().take(INBOX_DETAIL_MAX_CHARS).collect();
    log::info!("upload queue: inbox seq {seq}: {state:?}: {detail}");
    let r = InboxResult {
        state,
        detail: Some(detail.clone()),
    };
    match cx.fetcher.inbox_result(cx.cred, seq, &r, cx.lab).await {
        Ok(_) => return true,
        Err(e) if e.downcast_ref::<InboxSeqUnknown>().is_some() => {
            log::warn!("upload queue: the server no longer has inbox seq {seq} (404)");
            return true;
        }
        Err(e) => log::warn!("upload queue: acking inbox seq {seq} failed, kept for later: {e:#}"),
    }
    let now = (cx.clock)();
    let mut ack = Item::new(Job::Ack { seq, state, detail }, now);
    ack.retry.failed(now, None, cx.jitter.unit());
    put(cx, &ack)
}

async fn collect_item(cx: &DrainCtx<'_>, mut item: Item, now: DateTime<Utc>, low: bool) {
    let Job::Collect {
        seq,
        request,
        expires_at,
        tries,
    } = item.job.clone()
    else {
        return;
    };
    let target = Target::Inbox { seq };
    if cx.queue.has(&super::queue::archive_name(&target))
        || cx.queue.has(&super::queue::ack_name(seq))
    {
        // Collected already (a crash before this item went).
        remove(cx, &item);
        return;
    }
    if expires_at.is_some_and(|t| t <= now) {
        if final_ack(
            cx,
            seq,
            InboxResultState::Failed,
            crate::inbox::DETAIL_EXPIRED,
        )
        .await
        {
            remove(cx, &item);
        }
        return;
    }
    if low {
        log::info!("upload queue: battery low, collecting for seq {seq} waits for power");
        return;
    }
    if tries >= MAX_COLLECT_TRIES {
        let why = format!("collect: did not finish in {tries} tries");
        if final_ack(cx, seq, InboxResultState::Failed, &why).await {
            remove(cx, &item);
        }
        return;
    }
    if let Job::Collect { tries, .. } = &mut item.job {
        *tries += 1;
    }
    if !put(cx, &item) {
        return;
    }
    set_notice(cx, Some(now + NOTICE_FOR));
    let collected = run_collect(cx, request, now).await;
    set_notice(cx, None);
    let c = match collected {
        Ok(c) => c,
        Err(e) => {
            if final_ack(
                cx,
                seq,
                InboxResultState::Failed,
                &format!("collect: {e:#}"),
            )
            .await
            {
                remove(cx, &item);
            }
            return;
        }
    };
    let file = archive_file(&target);
    if let Err(e) = std::fs::rename(&c.path, cx.queue.path(&file)) {
        log::warn!("upload queue: keeping the archive of seq {seq} failed: {e}");
        let _ = std::fs::remove_file(&c.path);
        return;
    }
    let archive = Item::new(
        Job::Archive {
            target,
            file,
            bytes: c.bytes,
            sha256: c.sha256,
            expires_at,
            last_error: None,
        },
        (cx.clock)(),
    );
    if !put(cx, &archive) {
        return;
    }
    remove(cx, &item);
    trim(cx).await;
    if cx.queue.has(&archive.name()) {
        archive_item(cx, archive, (cx.clock)(), low).await;
    }
}

async fn run_collect(
    cx: &DrainCtx<'_>,
    request: CollectDiagnostics,
    now: DateTime<Utc>,
) -> Result<crate::diag::Collected> {
    let (boots, since_minutes) = match request.effective() {
        DiagRange::Boots(b) => (b, None),
        DiagRange::SinceHours(h) => (1, Some(u32::from(h) * 60)),
    };
    let o = CollectOpts {
        root: cx.paths.root.clone(),
        kind: DiagKind::Inbox,
        boots,
        since_minutes,
        screenshot: None,
        max_bytes: DIAG_INBOX_MAX_BYTES,
    };
    let runner = cx.runner.clone();
    let device_id = cx.device_id.to_string();
    let out = cx.queue.dir().to_path_buf();
    cx.queue.ensure()?;
    tokio::task::spawn_blocking(move || {
        crate::login_queue::notify_sessions(NOTICE, runner.as_ref());
        collect(&o, &device_id, &out, runner.as_ref(), now)
    })
    .await
    .context("the collector stopped")?
}

fn set_notice(cx: &DrainCtx<'_>, until: Option<DateTime<Utc>>) {
    if let Err(e) = crate::status::set_collecting(&cx.paths, until) {
        log::warn!("the collecting notice of the login screen: {e:#}");
    }
}

async fn archive_item(cx: &DrainCtx<'_>, mut item: Item, now: DateTime<Utc>, low: bool) {
    let Job::Archive {
        target,
        file,
        bytes,
        sha256,
        expires_at,
        last_error,
    } = item.job.clone()
    else {
        return;
    };
    let seq = match &target {
        Target::Inbox { seq } => Some(*seq),
        Target::Ticket { .. } => None,
    };
    if let (Some(_), Some(t)) = (seq, expires_at) {
        if t <= now {
            let last = last_error.unwrap_or_else(|| "not sent before the command expired".into());
            return give_up(cx, &item, seq, format!("upload: {last}")).await;
        }
    }
    if low {
        log::info!("upload queue: battery low, {} waits for power", item.name());
        return;
    }
    let kicked = cx.queue.kicked_at();
    if !item.retry.due(now, kicked) {
        return;
    }
    item.retry.take_kick(kicked);
    let path = cx.queue.path(&file);
    if !path.is_file() {
        return give_up(
            cx,
            &item,
            seq,
            "upload: the archive is missing from the queue".into(),
        )
        .await;
    }
    let req = match &target {
        Target::Inbox { seq } => DiagUploadRequest::Inbox {
            inbox_seq: *seq,
            bytes,
            sha256,
        },
        Target::Ticket { client_id } => DiagUploadRequest::Ticket {
            client_id: client_id.clone(),
            bytes,
            sha256,
        },
    };
    match crate::diag::upload::upload(cx.fetcher, cx.cred, req, &path, cx.lab).await {
        Ok(id) => {
            log::info!("upload queue: {} arrived as {id}", item.name());
            let acked = match seq {
                Some(seq) => {
                    final_ack(cx, seq, InboxResultState::Done, &format!("diag:{id}")).await
                }
                None => true,
            };
            if acked {
                remove(cx, &item);
            }
        }
        Err(e) => match e.action {
            ErrorAction::Drop | ErrorAction::DropSupportDisabled | ErrorAction::GiveUp => {
                give_up(cx, &item, seq, e.to_string()).await
            }
            ErrorAction::RetryAfter | ErrorAction::Backoff | ErrorAction::Restart => {
                log::warn!("upload queue: {}: {e}; trying again later", item.name());
                let after = e
                    .retry_after
                    .filter(|_| e.action == ErrorAction::RetryAfter);
                item.retry.failed((cx.clock)(), after, cx.jitter.unit());
                if let Job::Archive { last_error, .. } = &mut item.job {
                    *last_error = Some(e.detail);
                }
                put(cx, &item);
            }
        },
    }
}

/// Gives the archive up; its command (if any) is acked `failed` with `why` first.
async fn give_up(cx: &DrainCtx<'_>, item: &Item, seq: Option<u64>, why: String) {
    log::warn!("upload queue: giving up {}: {why}", item.name());
    let acked = match seq {
        Some(seq) => final_ack(cx, seq, InboxResultState::Failed, &why).await,
        None => true,
    };
    if acked {
        remove(cx, item);
    }
}

async fn ack_item(cx: &DrainCtx<'_>, mut item: Item, now: DateTime<Utc>) {
    let Job::Ack { seq, state, detail } = item.job.clone() else {
        return;
    };
    if item.created_at + TimeDelta::days(ACK_KEEP_DAYS) <= now {
        log::warn!("upload queue: giving up the result of inbox seq {seq}");
        return remove(cx, &item);
    }
    let kicked = cx.queue.kicked_at();
    if !item.retry.due(now, kicked) {
        return;
    }
    item.retry.take_kick(kicked);
    let r = InboxResult {
        state,
        detail: Some(detail),
    };
    match cx.fetcher.inbox_result(cx.cred, seq, &r, cx.lab).await {
        Ok(_) => remove(cx, &item),
        Err(e) if e.downcast_ref::<InboxSeqUnknown>().is_some() => remove(cx, &item),
        Err(e) => {
            log::warn!("upload queue: acking inbox seq {seq} failed again: {e:#}");
            item.retry.failed((cx.clock)(), None, cx.jitter.unit());
            put(cx, &item);
        }
    }
}

/// Keeps the queue within its size: the oldest archives go, their commands acked `failed`.
async fn trim(cx: &DrainCtx<'_>) {
    let dropped = match cx.queue.trim_to(cx.max_queue_bytes) {
        Ok(d) => d,
        Err(e) => {
            log::warn!("upload queue: {e:#}");
            return;
        }
    };
    for item in dropped {
        log::warn!(
            "upload queue: over {} bytes, dropped {}",
            cx.max_queue_bytes,
            item.name()
        );
        if let Job::Archive {
            target: Target::Inbox { seq },
            ..
        } = item.job
        {
            final_ack(cx, seq, InboxResultState::Failed, DETAIL_QUEUE_FULL).await;
        }
    }
}

/// On battery below [`LOW_BATTERY_PERCENT`] % (the mean of the batteries) with no power supply
/// online. No battery, or unreadable: not low.
pub fn low_battery(root: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(root.join("sys/class/power_supply")) else {
        return false;
    };
    let read = |p: &Path, f: &str| std::fs::read_to_string(p.join(f)).unwrap_or_default();
    let mut caps = vec![];
    for e in rd.filter_map(|e| e.ok()) {
        let p = e.path();
        // A mouse's or keyboard's own battery is not the computer's.
        if read(&p, "scope").trim() == "Device" {
            continue;
        }
        if read(&p, "type").trim() == "Battery" {
            if matches!(read(&p, "status").trim(), "Charging" | "Full") {
                return false;
            }
            if let Ok(c) = read(&p, "capacity").trim().parse::<u32>() {
                caps.push(c);
            }
        } else if read(&p, "online").trim() == "1" {
            return false;
        }
    }
    !caps.is_empty() && caps.iter().sum::<u32>() / (caps.len() as u32) < LOW_BATTERY_PERCENT
}

/// `mastersos-agent upload drain` on this machine: the device credential from `state.json` and
/// the seed partition's `identity.json` (never created here), the fetch token as the agent
/// keeps it. Without a credential nothing can be sent: the queue stays for later.
pub async fn drain_main(cfg: &crate::AgentConfig) -> Result<()> {
    let queue = Queue::new(&cfg.state_dir);
    if queue.list()?.is_empty() {
        queue.remove_orphans()?;
        return Ok(());
    }
    let (seed, state) = crate::state::load(&cfg.state_dir)?;
    let identity = crate::seedpart::load_identity(&cfg.seed_dir)
        .context("reading identity.json from the seed partition")?;
    let (Some(device_id), Some(id)) = (state.device_id.clone(), identity) else {
        log::warn!("upload queue: no device credential yet, nothing sent");
        return Ok(());
    };
    let cred = DeviceCred {
        device_id: device_id.clone(),
        secret: id.escrow_secret,
    };
    let fetcher = Fetcher::new(
        &seed,
        crate::token::effective(&cfg.state_dir, &cfg.seed_dir, &seed),
    );
    let cx = DrainCtx {
        queue: &queue,
        fetcher: &fetcher,
        cred: &cred,
        runner: Arc::new(crate::runner::RealRunner),
        paths: crate::run::sys_paths(cfg),
        device_id: &device_id,
        lab: crate::luks::image_is_lab(&cfg.root),
        clock: &Utc::now,
        jitter: cfg.jitter.clone(),
        max_queue_bytes: MAX_QUEUE_BYTES,
    };
    drain(&cx).await;
    Ok(())
}

#[cfg(test)]
mod tests;
