//! Streaming download into a private directory (spec §4.4): timeout, size cap, sha256 while downloading, conditional GET.

use std::io::Write;
use std::os::fd::OwnedFd;
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use reqwest::header::{
    HeaderMap, HeaderValue, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::apply::hex;
use crate::safefs;

/// Validators longer than this are not kept (and so not sent back).
const MAX_VALIDATOR: usize = 1024;

/// A completed download: the file's sha256 (lowercase hex) and the response's validators for the next conditional GET.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fetched {
    pub sha256: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    /// `cond` was given and the server answered 304: nothing was written.
    NotModified,
    Fetched(Fetched),
}

/// GETs `url` into `<dir>/<name>` (through a [`safefs::TmpFile`], committed only when complete and, with `want_sha256`,
/// matching). `timeout` covers the whole request including the body; a `Content-Length` above `max` is refused before reading,
/// and the streamed byte count is capped at `max` too. On any error nothing is left behind and an existing `<name>` stays.
/// With `cond`, sends `If-None-Match` / `If-Modified-Since` from it; a 304 then is [`FetchOutcome::NotModified`].
#[allow(clippy::too_many_arguments)]
pub async fn download(
    http: &reqwest::Client,
    url: &str,
    want_sha256: Option<&str>,
    max: u64,
    timeout: Duration,
    dir: &OwnedFd,
    name: &str,
    cond: Option<&Fetched>,
) -> Result<FetchOutcome> {
    download_with(
        http,
        url,
        want_sha256,
        max,
        timeout,
        dir,
        name,
        cond,
        &mut || Ok(()),
    )
    .await
}

/// [`download`], calling `first_bytes` once when the first chunk of the body arrives (before it is written). Chrome stamps
/// `download-started` there for the NetworkManager hook's rate limit; a request that fails before any byte arrives does not
/// call it.
#[allow(clippy::too_many_arguments)]
pub async fn download_with(
    http: &reqwest::Client,
    url: &str,
    want_sha256: Option<&str>,
    max: u64,
    timeout: Duration,
    dir: &OwnedFd,
    name: &str,
    cond: Option<&Fetched>,
    first_bytes: &mut (dyn FnMut() -> Result<()> + Send),
) -> Result<FetchOutcome> {
    let mut req = http.get(url).timeout(timeout);
    if let Some(c) = cond {
        if let Some(v) = c.etag.as_deref().and_then(header_value) {
            req = req.header(IF_NONE_MATCH, v);
        }
        if let Some(v) = c.last_modified.as_deref().and_then(header_value) {
            req = req.header(IF_MODIFIED_SINCE, v);
        }
    }
    let mut resp = req.send().await.context("the request failed")?;
    if cond.is_some() && resp.status() == StatusCode::NOT_MODIFIED {
        return Ok(FetchOutcome::NotModified);
    }
    ensure!(
        resp.status().is_success(),
        "the source returned {}",
        resp.status()
    );
    ensure!(
        resp.content_length().is_none_or(|n| n <= max),
        "the file exceeds the size limit ({max} bytes)"
    );
    let etag = validator(resp.headers(), ETAG);
    let last_modified = validator(resp.headers(), LAST_MODIFIED);
    let mut tmp = safefs::TmpFile::create(dir, name, 0o600)?;
    let mut h = Sha256::new();
    let mut n: u64 = 0;
    let mut started = false;
    while let Some(chunk) = resp.chunk().await.context("reading the response failed")? {
        if !started {
            first_bytes()?;
            started = true;
        }
        n += chunk.len() as u64;
        ensure!(n <= max, "the file exceeds the size limit ({max} bytes)");
        h.update(&chunk);
        tmp.write_all(&chunk)
            .with_context(|| format!("writing {name}"))?;
    }
    let got = hex(&h.finalize());
    if let Some(want) = want_sha256 {
        if !got.eq_ignore_ascii_case(want) {
            bail!("sha256 does not match ({got} ≠ {want})");
        }
    }
    tmp.commit()?;
    Ok(FetchOutcome::Fetched(Fetched {
        sha256: got,
        etag,
        last_modified,
    }))
}

fn header_value(v: &str) -> Option<HeaderValue> {
    HeaderValue::from_str(v).ok()
}

fn validator(h: &HeaderMap, key: reqwest::header::HeaderName) -> Option<String> {
    let v = h.get(key)?.to_str().ok()?.trim();
    (!v.is_empty() && v.len() <= MAX_VALIDATOR).then(|| v.to_string())
}
