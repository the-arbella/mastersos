//! The three-step diagnostics upload (spec「接口: 上传」): `POST /v1/diagnostics` →
//! presigned `PUT` to S3 → `POST /v1/diagnostics/{id}/complete`.
//!
//! A round starts at step 1 and every round gets a new URL. A round starts again when the
//! complete call says `upload_mismatch`, when the URL's `expires_in` has passed on the
//! monotonic clock before the `PUT` starts, or when S3 says "Request has expired"; after
//! [`MAX_ROUNDS`] rounds the upload fails with [`ErrorAction::Backoff`] and the caller retries
//! later. Every other failure comes back at once with the [`ErrorAction`] that
//! [`mastersos_bundle::diag::error_action`] gave it (Ruling P5).

use std::path::Path;
use std::time::{Duration, Instant};

use mastersos_bundle::diag::{DiagUploadRequest, ErrorAction};

pub use crate::fetch::{CompleteOutcome, DiagUploadError};
use crate::fetch::{DeviceCred, Fetcher};

/// Rounds (each from step 1) before an upload gives up for now.
pub const MAX_ROUNDS: u32 = 3;

/// Uploads `file`, described by `req`, and returns the upload id (for `diag:<id>`). An upload
/// the cloud already has complete returns its id without sending anything. `lab` lets the
/// device secret and the archive go over http (lab images only).
pub async fn upload(
    f: &Fetcher,
    cred: &DeviceCred,
    req: DiagUploadRequest,
    file: &Path,
    lab: bool,
) -> Result<String, DiagUploadError> {
    let mut last = String::new();
    for round in 1..=MAX_ROUNDS {
        // The URL's lifetime is counted from before the request went out: at most a little
        // early, never late, and never by the wall clock (which may be wrong).
        let asked = Instant::now();
        let answer = match f.diag_upload_url(cred, &req, lab).await {
            Ok(a) => a,
            Err(e) if e.action == ErrorAction::Restart => {
                last = e.detail;
                continue;
            }
            Err(e) => return Err(e),
        };
        if answer.complete {
            return Ok(answer.id);
        }
        let Some(u) = answer.upload else {
            // diag_upload_url only returns answers with complete or upload.
            return Err(DiagUploadError::new(
                ErrorAction::Backoff,
                "POST /v1/diagnostics: the answer has no upload",
            ));
        };
        if asked.elapsed() >= Duration::from_secs(u.expires_in) {
            log::info!("diagnostics upload: the URL expired before the PUT (round {round})");
            last = "PUT: the presigned URL expired before it was used".into();
            continue;
        }
        match f.diag_put(&u, file, lab).await {
            Ok(_) => {}
            Err(e) if e.action == ErrorAction::Restart => {
                log::info!("diagnostics {e} (round {round}); asking for a new URL");
                last = e.detail;
                continue;
            }
            Err(e) => return Err(e),
        }
        match f.diag_complete(cred, &answer.id, lab).await? {
            CompleteOutcome::Done => return Ok(answer.id),
            CompleteOutcome::Rejected => {
                last = "complete: the server answered upload_mismatch".into();
            }
        }
    }
    Err(DiagUploadError::new(
        ErrorAction::Backoff,
        format!("gave up after {MAX_ROUNDS} rounds; last: {last}"),
    ))
}
