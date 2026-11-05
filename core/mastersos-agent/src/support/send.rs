//! Sending help requests (plan 2026-11-05 Task 5b, spec design 2 and 3), inside
//! `mastersos-agent upload drain`: the upload queue's `support` item for a request ([`step`]).
//!
//! The support store ([`Store`]) stays the record of each request (what the student sent, who,
//! its state and ticket, which `status` answers); the upload queue item only says "send it" and
//! carries the retry state, so backoff, `Retry-After`, kicks and the lost-wakeup rerun are the
//! queue's. Every read-modify-write of the store holds [`Store::lock`] (the host writes too),
//! never across a network call.
//!
//! 1. `queued`: fill the snapshot's `network` (NetworkManager, now) and `status` (the latest
//!    status report the agent kept, [`crate::report::LAST_REPORT_FILE`]) when missing, keep the
//!    filled request (a resend is the same request), `POST /v1/support`, record the ticket,
//!    state `sent`. Failures by [`ErrorAction`] (Ruling P5), never by status code:
//!    `too_many` waits for `Retry-After`, other keep-actions back off; `support_disabled` turns
//!    every queued request `disabled` and drops their items; `invalid` (and any drop or give-up)
//!    turns this one `failed`. Not held for low battery: it is a small JSON.
//! 2. `sent`: collect the attachment (journal of the last [`ATTACH_SINCE_MINUTES`] minutes, the
//!    screenshot if the student attached one) into an `archive` item for [`Target::Ticket`]; the
//!    archive then uploads like any other (held for power, trimmed for room). The screenshot
//!    leaves the store as soon as it is in the archive. The archive arriving or being given up
//!    (`expired` after the server's 48 hours, `not_yours`, dropped for room) marks the request's
//!    attachment done ([`attachment_finished`]); the ticket stays `sent`.
//!
//! [`sweep`] (every pass) deletes finished requests after [`FINISHED_KEEP_DAYS`] days and queues
//! again a request whose upload item was lost.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, TimeDelta, Utc};
use mastersos_bundle::diag::{
    DiagKind, ErrorAction, SupportRequest, DIAG_TICKET_MAX_BYTES, SUPPORT_SNAPSHOT_MAX_BYTES,
};

use super::store::{Item, ItemState, Store};
use crate::diag::{collect, CollectOpts};
use crate::runner::{Cmd, Runner};
use crate::system::SysPaths;
use crate::upload::drain::{self, DrainCtx, MAX_COLLECT_TRIES};
use crate::upload::queue::{
    archive_file, archive_name, support_name, Item as QueueItem, Job, Target,
};

/// The support store under the agent's state directory ([`super::QUEUE_DIR`] in production).
pub const STORE_DIR: &str = "support-queue";
/// A finished request (ticket and attachment in, or refused) is kept this long for `status`.
pub const FINISHED_KEEP_DAYS: i64 = 7;
/// The attachment's journal reaches back this far.
pub const ATTACH_SINCE_MINUTES: u32 = 30;
/// The snapshot's network line is at most this long.
pub const NETWORK_MAX_CHARS: usize = 200;
/// Sent this much later than it was made, the network line says it is from sending time.
const NETWORK_LATE: TimeDelta = TimeDelta::minutes(10);
const NMCLI_TIMEOUT: Duration = Duration::from_secs(5);

/// The support store of the machine at `paths`.
pub fn store(paths: &SysPaths) -> Store {
    Store::new(paths.state_dir.join(STORE_DIR))
}

/// `f` on the store under its lock; a failure is logged and is `None`.
fn locked<T>(store: &Store, f: impl FnOnce(&Store) -> Result<T>) -> Option<T> {
    let r = store.lock().and_then(|lock| {
        let r = f(store);
        drop(lock);
        r
    });
    match r {
        Ok(v) => Some(v),
        Err(e) => {
            log::warn!("support queue: {e:#}");
            None
        }
    }
}

/// The upload queue's `support` item of `client_id` (only its name matters to remove it).
fn support_job(client_id: &str, now: DateTime<Utc>) -> QueueItem {
    QueueItem::new(
        Job::Support {
            client_id: client_id.to_string(),
            tries: 0,
        },
        now,
    )
}

/// The upload queue's `support` item `job` (see the module docs).
pub async fn step(cx: &DrainCtx<'_>, mut job: QueueItem, now: DateTime<Utc>, low: bool) {
    let Job::Support { client_id, tries } = job.job.clone() else {
        return;
    };
    let store = store(&cx.paths);
    let Some(found) = locked(&store, |s| s.get(&client_id)) else {
        return;
    };
    let Some(mut item) = found else {
        log::warn!("support: {client_id} is not in the support queue; dropping its upload item");
        return drain::remove(cx, &job);
    };
    if item.finished() {
        return drain::remove(cx, &job);
    }
    if item.state == ItemState::Queued {
        let kicked = cx.queue.kicked_at();
        if !job.retry.due(now, kicked) {
            return;
        }
        job.retry.take_kick(kicked);
        match send(cx, &store, &mut job, item).await {
            Some(sent) => item = sent,
            None => return,
        }
    }
    attach(cx, &store, job, &item, tries, low).await;
}

/// `POST /v1/support`; the item as recorded `sent`, or `None` when nothing more happens now.
async fn send(cx: &DrainCtx<'_>, store: &Store, job: &mut QueueItem, item: Item) -> Option<Item> {
    let id = item.request.client_id.clone();
    let request = filled(cx, &item.request).await;
    if request != item.request {
        // Kept, so that a resend is the same request.
        locked(store, |s| {
            if let Some(mut cur) = s.get(&id)? {
                if cur.state == ItemState::Queued {
                    cur.request = request.clone();
                    s.update(&cur)?;
                }
            }
            Ok(())
        });
    }
    match cx.fetcher.support(cx.cred, &request, cx.lab).await {
        Ok(r) => {
            log::info!("support: {id} is ticket {}", r.ticket);
            let saved = locked(store, |s| {
                let mut cur = s.get(&id)?.context("the request vanished")?;
                cur.state = ItemState::Sent;
                cur.ticket = Some(r.ticket.clone());
                s.update(&cur)?;
                Ok(cur)
            });
            if saved.is_none() {
                // Sent again later: the same client id gets the same ticket.
                job.retry.failed((cx.clock)(), None, cx.jitter.unit());
                drain::put(cx, job);
            }
            saved
        }
        Err(e) => {
            match e.action {
                ErrorAction::RetryAfter | ErrorAction::Backoff | ErrorAction::Restart => {
                    log::warn!(
                        "support: sending {id} failed: {}; trying again later",
                        e.detail
                    );
                    let after = e
                        .retry_after
                        .filter(|_| e.action == ErrorAction::RetryAfter);
                    job.retry.failed((cx.clock)(), after, cx.jitter.unit());
                    drain::put(cx, job);
                }
                ErrorAction::DropSupportDisabled => disable_all(cx, store),
                ErrorAction::Drop | ErrorAction::GiveUp => {
                    log::error!("support: the cloud refused {id} for good: {}", e.detail);
                    let done = locked(store, |s| {
                        if let Some(mut cur) = s.get(&id)? {
                            cur.state = ItemState::Failed;
                            s.update(&cur)?;
                        }
                        s.remove_screenshot(&id)
                    });
                    if done.is_some() {
                        drain::remove(cx, job);
                    }
                }
            }
            None
        }
    }
}

/// `support_disabled`: every request not sent yet becomes `disabled` (the dialog says help
/// requests are turned off) and its upload item goes; their screenshots are deleted.
fn disable_all(cx: &DrainCtx<'_>, store: &Store) {
    log::warn!("support: help requests are turned off at this school; dropping the queued ones");
    let ids = locked(store, |s| {
        let mut ids = vec![];
        for mut i in s.list()? {
            if i.state == ItemState::Queued {
                i.state = ItemState::Disabled;
                s.update(&i)?;
                s.remove_screenshot(&i.request.client_id)?;
                ids.push(i.request.client_id);
            }
        }
        Ok(ids)
    });
    let now = (cx.clock)();
    for id in ids.unwrap_or_default() {
        drain::remove(cx, &support_job(&id, now));
    }
}

/// The request with the snapshot's missing `network` and `status` filled in, as long as it
/// still validates (a status report that makes it too big is left out).
async fn filled(cx: &DrainCtx<'_>, req: &SupportRequest) -> SupportRequest {
    let need_net = req.snapshot.network.is_none();
    let need_status = req.snapshot.status.is_none();
    if !need_net && !need_status {
        return req.clone();
    }
    let runner = cx.runner.clone();
    let state_dir = cx.paths.state_dir.clone();
    let late = (cx.clock)() - req.created_at > NETWORK_LATE;
    let (net, status) = tokio::task::spawn_blocking(move || {
        let net = need_net.then(|| network(runner.as_ref(), late)).flatten();
        let status = need_status
            .then(|| crate::report::load_last(&state_dir, SUPPORT_SNAPSHOT_MAX_BYTES as u64))
            .flatten();
        (net, status)
    })
    .await
    .unwrap_or_default();
    let mut r = req.clone();
    if need_net {
        r.snapshot.network = net;
    }
    if need_status {
        r.snapshot.status = status;
        if r.validate().is_err() {
            r.snapshot.status = None;
        }
    }
    if r.validate().is_err() {
        return req.clone();
    }
    r
}

/// `nmcli -t` fields of one line: split on `:`, `\:` and `\\` unescaped.
fn fields(line: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(n) = chars.next() {
                    out.last_mut().expect("never empty").push(n);
                }
            }
            ':' => out.push(String::new()),
            c => out.last_mut().expect("never empty").push(c),
        }
    }
    out
}

/// NetworkManager now, in one line: `connected (full); wifi: <connection>`. `late`: the request
/// was made a while ago, so the line says it is from sending time.
fn network(runner: &dyn Runner, late: bool) -> Option<String> {
    let run = |args: &[&str]| {
        runner
            .run(&Cmd::new("nmcli", args).timeout(NMCLI_TIMEOUT))
            .ok()
            .filter(|o| o.code == 0)
            .map(|o| o.stdout)
    };
    let general = run(&["-t", "-f", "STATE,CONNECTIVITY", "general"])?;
    let g = fields(general.lines().next()?.trim());
    let state = g.first().filter(|s| !s.is_empty())?;
    let connectivity = g.get(1).map(String::as_str).unwrap_or("unknown");
    let mut out = format!("{state} ({connectivity})");
    let devices = run(&["-t", "-f", "TYPE,STATE,CONNECTION", "device"]).unwrap_or_default();
    for line in devices.lines() {
        let f = fields(line);
        if let [kind, st, conn, ..] = f.as_slice() {
            if matches!(kind.as_str(), "wifi" | "ethernet") && st.starts_with("connected") {
                out.push_str(&format!("; {kind}: {conn}"));
            }
        }
    }
    if late {
        out = format!("when sent: {out}");
    }
    Some(out.chars().take(NETWORK_MAX_CHARS).collect())
}

/// The ticket is in: collect the attachment into a ticket archive and start its upload.
async fn attach(
    cx: &DrainCtx<'_>,
    store: &Store,
    mut job: QueueItem,
    item: &Item,
    tries: u32,
    low: bool,
) {
    let id = item.request.client_id.as_str();
    let target = Target::Ticket {
        client_id: id.to_string(),
    };
    if cx.queue.has(&archive_name(&target)) {
        // Collected already (a crash before this item went).
        return drain::remove(cx, &job);
    }
    if low {
        log::info!("support: battery low, the attachment of {id} waits for power");
        return;
    }
    if tries >= MAX_COLLECT_TRIES {
        attachment_finished(cx, id, &format!("collect: did not finish in {tries} tries"));
        return drain::remove(cx, &job);
    }
    if let Job::Support { tries, .. } = &mut job.job {
        *tries += 1;
    }
    if !drain::put(cx, &job) {
        return;
    }
    let shot = item
        .request
        .screenshot
        .then(|| store.dir().join(format!("{id}.png")));
    let c = match run_collect(cx, shot).await {
        Ok(c) => c,
        Err(e) => {
            attachment_finished(cx, id, &format!("collect: {e:#}"));
            return drain::remove(cx, &job);
        }
    };
    let file = archive_file(&target);
    if let Err(e) = std::fs::rename(&c.path, cx.queue.path(&file)) {
        log::warn!("support: keeping the attachment of {id} failed: {e}");
        let _ = std::fs::remove_file(&c.path);
        return;
    }
    let archive = QueueItem::new(
        Job::Archive {
            target,
            file,
            bytes: c.bytes,
            sha256: c.sha256,
            expires_at: None,
            last_error: None,
        },
        (cx.clock)(),
    );
    if !drain::put(cx, &archive) {
        return;
    }
    drain::remove(cx, &job);
    // In the archive now: the store's copy only takes room.
    locked(store, |s| s.remove_screenshot(id));
    drain::trim(cx).await;
    if cx.queue.has(&archive.name()) {
        drain::archive_item(cx, archive, (cx.clock)(), low).await;
    }
}

/// The ticket attachment: the recent journal and the screenshot (`shot`, in the store; the
/// collector reads it through the root and checks only its size and PNG signature).
async fn run_collect(cx: &DrainCtx<'_>, shot: Option<PathBuf>) -> Result<crate::diag::Collected> {
    let root = cx.paths.root.clone();
    let screenshot = shot.and_then(|p| match p.strip_prefix(&root) {
        Ok(rel) => Some(PathBuf::from("/").join(rel)),
        Err(_) => {
            log::warn!("support: the screenshot is outside the system root; not attached");
            None
        }
    });
    let o = CollectOpts {
        root,
        kind: DiagKind::Ticket,
        boots: 1,
        since_minutes: Some(ATTACH_SINCE_MINUTES),
        screenshot,
        max_bytes: DIAG_TICKET_MAX_BYTES,
    };
    let runner = cx.runner.clone();
    let device_id = cx.device_id.to_string();
    let out = cx.queue.dir().to_path_buf();
    let now = (cx.clock)();
    cx.queue.ensure()?;
    tokio::task::spawn_blocking(move || collect(&o, &device_id, &out, runner.as_ref(), now))
        .await
        .context("the collector stopped")?
}

/// The attachment of `client_id` arrived or was given up (`why`): nothing left to send for it.
/// Its screenshot goes; the ticket stays.
pub fn attachment_finished(cx: &DrainCtx<'_>, client_id: &str, why: &str) {
    log::info!("support: the attachment of {client_id}: {why}");
    let store = store(&cx.paths);
    locked(&store, |s| {
        if let Some(mut i) = s.get(client_id)? {
            i.attach_done = true;
            s.update(&i)?;
        }
        s.remove_screenshot(client_id)
    });
}

/// Every pass: deletes requests finished [`FINISHED_KEEP_DAYS`] days after they were made, and
/// queues again an unfinished one that has nothing in the upload queue.
pub fn sweep(cx: &DrainCtx<'_>, now: DateTime<Utc>) {
    let store = store(&cx.paths);
    if !store.dir().is_dir() {
        return;
    }
    locked(&store, |s| {
        for i in s.list()? {
            let id = i.request.client_id.as_str();
            if i.finished() {
                if i.created_at + TimeDelta::days(FINISHED_KEEP_DAYS) <= now {
                    log::info!("support: forgetting {id}");
                    s.remove(id)?;
                }
                continue;
            }
            let archive = archive_name(&Target::Ticket {
                client_id: id.to_string(),
            });
            if !cx.queue.has(&support_name(id)) && !cx.queue.has(&archive) {
                log::warn!("support: {id} had nothing queued to send it; queueing it again");
                cx.queue.enqueue_support(id, i.created_at)?;
            }
        }
        Ok(())
    });
}

#[cfg(test)]
mod tests;
