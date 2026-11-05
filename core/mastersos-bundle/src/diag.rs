//! Wire types for remote diagnostics and "Get help" (remote diagnostics and help design,
//! section 接口). The cloud pins this repository and uses these exact types.
//!
//! Endpoints (all authenticated with the device credential, machine → cloud over HTTPS):
//!
//! - `POST /v1/support` with a [`SupportRequest`]: `201` or `200` with a [`SupportResponse`];
//!   the two mean the same. The same `client_id` always gets the same ticket (offline resends
//!   are idempotent); unknown categories are taken as `other`, unknown user kinds as
//!   `unknown`. Over the server's limit ([`SUPPORT_SERVER_MAX_PER_HOUR`]): `429`.
//! - `POST /v1/diagnostics` with a [`DiagUploadRequest`]: `201` with a [`DiagUploadResponse`]
//!   carrying a presigned S3 `PUT` ([`PresignedUpload`]); `200` `{"id","complete":true}`
//!   without `upload` when that seq or ticket is already complete (the machine skips the `PUT`
//!   and the complete call); an incomplete one gets the same id and a new URL. `413` over the
//!   size limit; `409` [`ERR_NOT_YOURS`] when the seq is not a `collect-diagnostics` message
//!   sent to this machine or the ticket is not this machine's; `410` [`ERR_EXPIRED`] when the
//!   ticket is older than [`TICKET_ATTACH_WINDOW_HOURS`].
//! - The machine `PUT`s the archive to `upload.url` with `upload.headers` exactly as given.
//!   An expired URL ([`PresignedUpload::expires_in`]): back to `POST /v1/diagnostics`.
//! - `POST /v1/diagnostics/{id}/complete`: the cloud checks size and SHA-256; `204` when they
//!   match (only then has the archive arrived). `409` [`ERR_UPLOAD_MISMATCH`] means the object
//!   was deleted: start again with `POST /v1/diagnostics`.
//!
//! Errors carry an [`ApiError`] body; [`error_action`] says what the machine does with one.
//!
//! IT asks for diagnostics through the inbox: a `command` of kind [`KIND_COLLECT_DIAGNOSTICS`]
//! with a [`CollectDiagnostics`] payload. The archive carries a [`DiagManifest`] as
//! [`DIAG_MANIFEST_NAME`].

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Inbox message kind: collect diagnostics and upload them ([`CollectDiagnostics`]).
pub const KIND_COLLECT_DIAGNOSTICS: &str = "collect-diagnostics";
/// Largest archive for a `collect-diagnostics` command; a bigger one is truncated, oldest boot
/// first ([`DiagManifest::truncated`]).
pub const DIAG_INBOX_MAX_BYTES: u64 = 50 * 1024 * 1024;
/// Largest attachment archive for a support ticket.
pub const DIAG_TICKET_MAX_BYTES: u64 = 10 * 1024 * 1024;
/// Most characters (Unicode scalar values, `chars().count()`) in [`SupportRequest::text`].
pub const SUPPORT_TEXT_MAX_CHARS: usize = 1000;
/// Most bytes of [`SupportRequest::snapshot`] serialized as JSON.
pub const SUPPORT_SNAPSHOT_MAX_BYTES: usize = 64 * 1024;
/// Most support requests one machine sends per hour (counted on the machine).
pub const SUPPORT_MAX_PER_HOUR: u32 = 3;
/// Most support requests the server accepts from one machine per hour, counted by the
/// server's receive time; above it the server answers `429` [`ERR_TOO_MANY`]. Higher than
/// [`SUPPORT_MAX_PER_HOUR`] so that a queue sent after a long time offline still gets through.
pub const SUPPORT_SERVER_MAX_PER_HOUR: u32 = 10;
/// How long after a ticket is created its attachment is still accepted, measured by the
/// server's receive times (of the ticket and of `POST /v1/diagnostics`), not the machine's
/// clock.
pub const TICKET_ATTACH_WINDOW_HOURS: i64 = 48;
/// Lifetime of a presigned upload URL as the cloud issues it today; the machine goes by
/// [`PresignedUpload::expires_in`], not by this.
pub const UPLOAD_URL_TTL_SECS: u64 = 900;
/// [`DiagManifest::format`] written by this version.
pub const DIAG_MANIFEST_FORMAT: u32 = 1;
/// File name of the [`DiagManifest`] inside a diagnostics archive.
pub const DIAG_MANIFEST_NAME: &str = "manifest.json";

const BOOTS_MAX: u8 = 5;
const SINCE_HOURS_MAX: u16 = 168;

/// Payload of a [`KIND_COLLECT_DIAGNOSTICS`] inbox command. At most one of `boots` and
/// `since_hours` is present; with neither, the machine collects the current boot
/// ([`CollectDiagnostics::effective`]).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CollectDiagnostics {
    /// How many boots of journal to collect, newest first: 1 to 5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boots: Option<u8>,
    /// The last this many hours of journal, whatever the boots: 1 to 168.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_hours: Option<u16>,
}

/// What a [`CollectDiagnostics`] asks for, once defaults are applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagRange {
    /// The newest this many boots.
    Boots(u8),
    /// The last this many hours.
    SinceHours(u16),
}

impl CollectDiagnostics {
    pub fn validate(&self) -> Result<(), String> {
        if self.boots.is_some() && self.since_hours.is_some() {
            return Err("boots and since_hours cannot both be set".to_owned());
        }
        if let Some(b) = self.boots {
            if !(1..=BOOTS_MAX).contains(&b) {
                return Err(format!("boots must be 1 to {BOOTS_MAX}, not {b}"));
            }
        }
        if let Some(h) = self.since_hours {
            if !(1..=SINCE_HOURS_MAX).contains(&h) {
                return Err(format!(
                    "since_hours must be 1 to {SINCE_HOURS_MAX}, not {h}"
                ));
            }
        }
        Ok(())
    }

    /// The range to collect: `since_hours` when given, else `boots`, else one boot. Call
    /// [`CollectDiagnostics::validate`] first.
    pub fn effective(&self) -> DiagRange {
        match (self.boots, self.since_hours) {
            (_, Some(h)) => DiagRange::SinceHours(h),
            (Some(b), None) => DiagRange::Boots(b),
            (None, None) => DiagRange::Boots(1),
        }
    }
}

/// `POST /v1/diagnostics`: what the machine is about to upload.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum DiagUploadRequest {
    /// The answer to a `collect-diagnostics` inbox message.
    Inbox {
        inbox_seq: u64,
        /// Size of the archive.
        bytes: u64,
        /// SHA-256 of the archive, 64 lowercase hex digits.
        sha256: String,
    },
    /// The attachment of a support ticket this machine created.
    Ticket {
        /// The [`SupportRequest::client_id`] of the ticket (lowercase UUID). Not the display
        /// ticket number: those are per school and can be renumbered after a school reset.
        client_id: String,
        /// Size of the archive.
        bytes: u64,
        /// SHA-256 of the archive, 64 lowercase hex digits.
        sha256: String,
    },
}

impl DiagUploadRequest {
    fn bytes(&self) -> u64 {
        match self {
            DiagUploadRequest::Inbox { bytes, .. } | DiagUploadRequest::Ticket { bytes, .. } => {
                *bytes
            }
        }
    }

    fn sha256(&self) -> &str {
        match self {
            DiagUploadRequest::Inbox { sha256, .. } | DiagUploadRequest::Ticket { sha256, .. } => {
                sha256
            }
        }
    }

    /// The size limit for this kind of upload.
    pub fn max_bytes(&self) -> u64 {
        match self {
            DiagUploadRequest::Inbox { .. } => DIAG_INBOX_MAX_BYTES,
            DiagUploadRequest::Ticket { .. } => DIAG_TICKET_MAX_BYTES,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if let DiagUploadRequest::Ticket { client_id, .. } = self {
            if !crate::valid_school_id(client_id) {
                return Err(CLIENT_ID_ERROR.to_owned());
            }
        }
        let sha = self.sha256();
        if sha.len() != 64 || !sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err("sha256 must be 64 lowercase hex digits".to_owned());
        }
        let (bytes, max) = (self.bytes(), self.max_bytes());
        if bytes == 0 {
            return Err("bytes must be more than 0".to_owned());
        }
        if bytes > max {
            return Err(format!("bytes must be at most {max}, not {bytes}"));
        }
        Ok(())
    }
}

const CLIENT_ID_ERROR: &str =
    "client_id must be a lowercase UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)";

/// A presigned S3 request: the machine sends the archive with exactly this method, URL and
/// headers, adding nothing and converting nothing.
///
/// Each `POST /v1/diagnostics` is a new attempt: the object path in the URL changes, so a URL
/// from an earlier answer is never reused.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PresignedUpload {
    /// `PUT`.
    pub method: String,
    pub url: String,
    /// Headers signed into the URL (`Content-Length`, `x-amz-checksum-sha256`,
    /// `x-amz-sdk-checksum-algorithm: SHA256`, tagging). Send exactly these: no `Content-MD5`
    /// and no `Content-Type` of the machine's own. `Expect: 100-continue` is allowed.
    pub headers: BTreeMap<String, String>,
    /// When the URL expires, by the cloud's clock. Informational only.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub expires_at: DateTime<Utc>,
    /// Seconds the URL stays valid from when this answer arrived. The machine must not judge
    /// expiry by its own wall clock (it may be wrong): it goes back to `POST /v1/diagnostics`
    /// once this many seconds have passed on a monotonic clock started when the response
    /// arrived, or when S3 answers `AccessDenied` with "Request has expired".
    pub expires_in: u64,
}

/// The signed query string grants the upload: it stays out of `Debug` output.
impl fmt::Debug for PresignedUpload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let url = match self.url.split_once('?') {
            Some((base, _)) => format!("{base}?<redacted>"),
            None => self.url.clone(),
        };
        f.debug_struct("PresignedUpload")
            .field("method", &self.method)
            .field("url", &url)
            .field("headers", &self.headers)
            .field("expires_at", &self.expires_at)
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

/// Answer to `POST /v1/diagnostics`: `201` with `upload`, or `200` `{"id","complete":true}`
/// when that upload is already complete (the machine then skips the `PUT` and the complete
/// call). Then `POST /v1/diagnostics/{id}/complete` gives `204`; `409` [`ERR_UPLOAD_MISMATCH`]
/// means the object was deleted and the machine starts again.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DiagUploadResponse {
    pub id: String,
    #[serde(default)]
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload: Option<PresignedUpload>,
}

/// Body of every error answer of these endpoints: `{"error": "<code>"}`. Newer clouds may add
/// fields; they are ignored.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApiError {
    /// One of the `ERR_*` codes.
    pub error: String,
}

/// `422`: the request does not validate. The machine drops it and logs why.
pub const ERR_INVALID: &str = "invalid";
/// `403`: the school turned help requests off (`[config.support] enabled = false`). The
/// machine drops its queued help requests and tells the student "Help requests are turned off
/// at this school."
pub const ERR_SUPPORT_DISABLED: &str = "support_disabled";
/// `429`: over [`SUPPORT_SERVER_MAX_PER_HOUR`] or another rate limit. The machine keeps the
/// request and retries after the `Retry-After` seconds.
pub const ERR_TOO_MANY: &str = "too_many";
/// `503`: diagnostics storage is not available. The machine keeps the upload and backs off.
pub const ERR_DIAGNOSTICS_UNAVAILABLE: &str = "diagnostics_unavailable";
/// `409`: the seq or ticket is not this machine's. The machine gives up this upload.
pub const ERR_NOT_YOURS: &str = "not_yours";
/// `410`: the command or the ticket's attachment window has passed. The machine gives up.
pub const ERR_EXPIRED: &str = "expired";
/// `409` from the complete call: size or SHA-256 did not match and the object was deleted.
/// The machine starts again from `POST /v1/diagnostics`.
pub const ERR_UPLOAD_MISMATCH: &str = "upload_mismatch";
/// `403`: the device check failed (for example the device is not enrolled any more). The
/// machine keeps what it has and backs off.
pub const ERR_FORBIDDEN: &str = "forbidden";
/// Admin side only, never sent to a machine: the action needs a newer agent than the device
/// reports (for example asking an old machine for diagnostics). A machine that sees it treats
/// it like any unknown code.
pub const ERR_AGENT_TOO_OLD: &str = "agent_too_old";

/// What the machine does with a failed answer ([`error_action`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorAction {
    /// Drop the request and log it; resending it cannot succeed.
    Drop,
    /// Drop the queued help requests and tell the student that help requests are turned off.
    DropSupportDisabled,
    /// Keep it; retry after the `Retry-After` seconds of the answer.
    RetryAfter,
    /// Keep it; retry with backoff.
    Backoff,
    /// Give up this upload.
    GiveUp,
    /// Start the upload again from `POST /v1/diagnostics`.
    Restart,
}

/// What the machine does with a non-2xx answer of `status` and its body, if the body parsed
/// as an [`ApiError`]. Network errors (no status) are [`ErrorAction::Backoff`].
///
/// | code                              | status | machine                                       |
/// |-----------------------------------|--------|-----------------------------------------------|
/// | [`ERR_INVALID`]                   | 422    | drop the request and log it                   |
/// | [`ERR_SUPPORT_DISABLED`]          | 403    | drop queued help requests; tell the student   |
/// | [`ERR_TOO_MANY`]                  | 429    | keep; retry after `Retry-After` seconds       |
/// | [`ERR_DIAGNOSTICS_UNAVAILABLE`]   | 503    | keep; back off                                |
/// | [`ERR_NOT_YOURS`]                 | 409    | give up this upload                           |
/// | [`ERR_EXPIRED`]                   | 410    | give up this upload                           |
/// | [`ERR_UPLOAD_MISMATCH`]           | 409    | start again from `POST /v1/diagnostics`       |
/// | [`ERR_FORBIDDEN`]                 | 403    | device check failed: keep; back off           |
/// | none (5xx, 404, 401 empty body)   |        | keep; back off                                |
///
/// A known code decides; `429` is always [`ErrorAction::RetryAfter`] and `5xx` always
/// [`ErrorAction::Backoff`]. An unknown or missing code falls back by status: `400`, `413`
/// and `422` are [`ErrorAction::Drop`] (the same request will never be accepted), everything
/// else [`ErrorAction::Backoff`] (it may be a proxy, a cloud being deployed, or a code this
/// version does not know yet, so nothing is thrown away).
pub fn error_action(status: u16, body: Option<&ApiError>) -> ErrorAction {
    if status == 429 {
        return ErrorAction::RetryAfter;
    }
    if status >= 500 {
        return ErrorAction::Backoff;
    }
    match body.map(|b| b.error.as_str()) {
        Some(ERR_INVALID) => ErrorAction::Drop,
        Some(ERR_SUPPORT_DISABLED) => ErrorAction::DropSupportDisabled,
        Some(ERR_TOO_MANY) => ErrorAction::RetryAfter,
        Some(ERR_DIAGNOSTICS_UNAVAILABLE) | Some(ERR_FORBIDDEN) => ErrorAction::Backoff,
        Some(ERR_NOT_YOURS) | Some(ERR_EXPIRED) => ErrorAction::GiveUp,
        Some(ERR_UPLOAD_MISMATCH) => ErrorAction::Restart,
        _ => match status {
            400 | 413 | 422 => ErrorAction::Drop,
            _ => ErrorAction::Backoff,
        },
    }
}

/// What a diagnostics archive answers.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum DiagKind {
    /// A `collect-diagnostics` command.
    Inbox,
    /// A support ticket's attachment.
    Ticket,
}

/// How the cloud should treat a file of the archive (for example when removing identifiers).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum DiagFileType {
    Text,
    Image,
    Binary,
}

/// The fixed names of diagnostic sources ([`DiagFile::source`], [`DiagSkipped::source`]).
/// Each source is its own file (or one file per boot for [`JOURNAL`]).
///
/// The cloud keys on them when it makes the vendor copy: [`WIFI_SCAN`] and [`COREDUMP_INFO`]
/// are dropped entirely; in the rest, IP and MAC/BSSID addresses, SSIDs, serial numbers and
/// `/home/<x>` paths are pseudonymized. Adding a source is a protocol change.
pub mod source {
    /// The journal, one file per boot.
    pub const JOURNAL: &str = "journal";
    /// The journal of the last minutes (help tickets).
    pub const JOURNAL_RECENT: &str = "journal-recent";
    /// `coredumpctl list`.
    pub const COREDUMP_LIST: &str = "coredump-list";
    /// `coredumpctl info` (no core files).
    pub const COREDUMP_INFO: &str = "coredump-info";
    /// `systemctl --failed`.
    pub const SYSTEMD_FAILED: &str = "systemd-failed";
    /// `systemctl list-units`.
    pub const SYSTEMD_UNITS: &str = "systemd-units";
    /// `loginctl` sessions.
    pub const LOGINCTL: &str = "loginctl";
    /// `nmcli general`.
    pub const NM_GENERAL: &str = "nm-general";
    /// `nmcli device`.
    pub const NM_DEVICE: &str = "nm-device";
    /// `nmcli connection show` (no secrets).
    pub const NM_CONNECTION: &str = "nm-connection";
    /// `ip addr`.
    pub const IP_ADDR: &str = "ip-addr";
    /// `ip route`.
    pub const IP_ROUTE: &str = "ip-route";
    /// `resolvectl status`.
    pub const RESOLVECTL: &str = "resolvectl";
    /// `rfkill`.
    pub const RFKILL: &str = "rfkill";
    /// `iw dev`.
    pub const IW_DEV: &str = "iw-dev";
    /// `iw reg get`.
    pub const IW_REG: &str = "iw-reg";
    /// The Wi-Fi scan list.
    pub const WIFI_SCAN: &str = "wifi-scan";
    /// `lspci -nnk`.
    pub const LSPCI: &str = "lspci";
    /// `lsusb`.
    pub const LSUSB: &str = "lsusb";
    /// `/proc/cmdline`.
    pub const CMDLINE: &str = "cmdline";
    /// Input devices (`/proc/bus/input/devices`).
    pub const INPUT_DEVICES: &str = "input-devices";
    /// `/sys/power/mem_sleep`.
    pub const MEM_SLEEP: &str = "mem-sleep";
    /// Batteries and chargers (`/sys/class/power_supply`).
    pub const POWER_SUPPLY: &str = "power-supply";
    /// `/etc/os-release`.
    pub const OS_RELEASE: &str = "os-release";
    /// `bootctl status`.
    pub const BOOTCTL: &str = "bootctl";
    /// The agent's `state.json`, with secrets removed.
    pub const AGENT_STATE: &str = "agent-state";
    /// The latest status report.
    pub const STATUS_REPORT: &str = "status-report";
    /// The screenshot the student chose to attach.
    pub const SCREENSHOT: &str = "screenshot";

    /// Every source name, in the order above.
    pub const ALL: &[&str] = &[
        JOURNAL,
        JOURNAL_RECENT,
        COREDUMP_LIST,
        COREDUMP_INFO,
        SYSTEMD_FAILED,
        SYSTEMD_UNITS,
        LOGINCTL,
        NM_GENERAL,
        NM_DEVICE,
        NM_CONNECTION,
        IP_ADDR,
        IP_ROUTE,
        RESOLVECTL,
        RFKILL,
        IW_DEV,
        IW_REG,
        WIFI_SCAN,
        LSPCI,
        LSUSB,
        CMDLINE,
        INPUT_DEVICES,
        MEM_SLEEP,
        POWER_SUPPLY,
        OS_RELEASE,
        BOOTCTL,
        AGENT_STATE,
        STATUS_REPORT,
        SCREENSHOT,
    ];
}

/// `manifest.json` ([`DIAG_MANIFEST_NAME`]) inside a diagnostics archive.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DiagManifest {
    /// [`DIAG_MANIFEST_FORMAT`].
    pub format: u32,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub created_at: DateTime<Utc>,
    pub device_id: String,
    pub kind: DiagKind,
    /// Whether the oldest boots' logs were left out to stay within the size limit.
    #[serde(default)]
    pub truncated: bool,
    pub files: Vec<DiagFile>,
    /// Sources that could not be collected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<DiagSkipped>,
}

impl DiagManifest {
    /// Every source is one of [`source::ALL`]; every path is relative, has no `..` component
    /// and is not the manifest itself.
    pub fn validate(&self) -> Result<(), String> {
        let known = |s: &str| source::ALL.contains(&s);
        for f in &self.files {
            if !known(&f.source) {
                return Err(format!("unknown source {:?} for {:?}", f.source, f.path));
            }
            let p = f.path.as_str();
            if p.is_empty() || p.starts_with('/') {
                return Err(format!("path must be relative, not {p:?}"));
            }
            if p.split('/').any(|c| c == "..") {
                return Err(format!("path must not contain .., not {p:?}"));
            }
            let mut parts = p.split('/').filter(|c| !c.is_empty() && *c != ".");
            if parts.next() == Some(DIAG_MANIFEST_NAME) && parts.next().is_none() {
                return Err(format!("{DIAG_MANIFEST_NAME} must not list itself"));
            }
        }
        for s in &self.skipped {
            if !known(&s.source) {
                return Err(format!("unknown skipped source {:?}", s.source));
            }
        }
        Ok(())
    }
}

/// One file of a diagnostics archive.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DiagFile {
    /// Path inside the archive (relative, no `..`).
    pub path: String,
    /// Where it came from: one of [`source::ALL`].
    pub source: String,
    #[serde(rename = "type")]
    pub kind: DiagFileType,
    pub bytes: u64,
}

/// A source the collector could not collect, and why.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DiagSkipped {
    /// One of [`source::ALL`].
    pub source: String,
    pub reason: String,
}

/// What a support request is about, picked by the student. Unknown values read as `other`.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum SupportCategory {
    Wifi,
    SignIn,
    App,
    Hardware,
    Battery,
    #[serde(other)]
    Other,
}

/// Who sent a support request, as the system (not the dialog) determined it. Unknown values
/// read as `unknown`.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum SupportUserKind {
    /// Nobody signed in (the login screen).
    None,
    Guest,
    Local,
    Sso,
    /// A kind this version does not know.
    #[serde(other)]
    Unknown,
}

/// The sender of a support request.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SupportUser {
    pub kind: SupportUserKind,
    /// The user name, taken from the system.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// The machine's state when the request was made.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SupportSnapshot {
    pub os_version: String,
    /// The active connection, as a short description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub battery_percent: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_ac: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_free_bytes: Option<u64>,
    /// The latest status report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<crate::StatusReport>,
}

/// `POST /v1/support`: a student's or staff member's "Get help" request.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SupportRequest {
    /// Made by the machine (lowercase UUID); a resend carries the same one and gets the same
    /// ticket.
    pub client_id: String,
    pub category: SupportCategory,
    /// What happened, at most [`SUPPORT_TEXT_MAX_CHARS`] characters; may be empty.
    pub text: String,
    pub user: SupportUser,
    /// Where it was sent from: `login`, `desktop` or `kiosk:<app id>`.
    pub session: String,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub created_at: DateTime<Utc>,
    /// At most [`SUPPORT_SNAPSHOT_MAX_BYTES`] when serialized as JSON.
    pub snapshot: SupportSnapshot,
    /// Whether the attachment will include a screenshot.
    pub screenshot: bool,
}

impl SupportRequest {
    pub fn validate(&self) -> Result<(), String> {
        if !crate::valid_school_id(&self.client_id) {
            return Err(CLIENT_ID_ERROR.to_owned());
        }
        let n = self.text.chars().count();
        if n > SUPPORT_TEXT_MAX_CHARS {
            return Err(format!(
                "text must be at most {SUPPORT_TEXT_MAX_CHARS} characters, not {n}"
            ));
        }
        let snapshot = serde_json::to_vec(&self.snapshot)
            .map_err(|e| format!("snapshot does not serialize: {e}"))?
            .len();
        if snapshot > SUPPORT_SNAPSHOT_MAX_BYTES {
            return Err(format!(
                "snapshot must be at most {SUPPORT_SNAPSHOT_MAX_BYTES} bytes of JSON, not {snapshot}"
            ));
        }
        let session_ok = match self.session.as_str() {
            "login" | "desktop" => true,
            s => s.strip_prefix("kiosk:").is_some_and(|id| !id.is_empty()),
        };
        if !session_ok {
            return Err(format!(
                "session must be login, desktop or kiosk:<app id>, not {:?}",
                self.session
            ));
        }
        Ok(())
    }
}

/// Answer to `POST /v1/support`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SupportResponse {
    pub ticket: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const CLIENT: &str = "0192f3a4-5b6c-7d8e-9f00-112233445566";

    fn at() -> DateTime<Utc> {
        "2026-11-05T08:30:00Z".parse().unwrap()
    }

    fn round_trip<T>(v: &T, want: serde_json::Value)
    where
        T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug,
    {
        assert_eq!(serde_json::to_value(v).unwrap(), want);
        let back: T = serde_json::from_value(want).unwrap();
        assert_eq!(&back, v);
    }

    #[test]
    fn constants() {
        assert_eq!(KIND_COLLECT_DIAGNOSTICS, "collect-diagnostics");
        assert_eq!(DIAG_INBOX_MAX_BYTES, 52_428_800);
        assert_eq!(DIAG_TICKET_MAX_BYTES, 10_485_760);
        assert_eq!(SUPPORT_TEXT_MAX_CHARS, 1000);
        assert_eq!(SUPPORT_MAX_PER_HOUR, 3);
        assert_eq!(SUPPORT_SERVER_MAX_PER_HOUR, 10);
        assert_eq!(SUPPORT_SNAPSHOT_MAX_BYTES, 65_536);
        assert_eq!(TICKET_ATTACH_WINDOW_HOURS, 48);
        assert_eq!(UPLOAD_URL_TTL_SECS, 900);
        assert_eq!(DIAG_MANIFEST_FORMAT, 1);
        assert_eq!(DIAG_MANIFEST_NAME, "manifest.json");
    }

    #[test]
    fn collect_diagnostics_wire_and_defaults() {
        let c = |boots, since_hours| CollectDiagnostics { boots, since_hours };
        round_trip(&c(Some(2), None), json!({"boots": 2}));
        round_trip(&c(None, Some(24)), json!({"since_hours": 24}));
        round_trip(&c(None, None), json!({}));
        let nulls: CollectDiagnostics =
            serde_json::from_value(json!({"boots": null, "since_hours": null})).unwrap();
        assert_eq!(nulls, c(None, None));
        assert_eq!(CollectDiagnostics::default(), c(None, None));
        assert_eq!(
            CollectDiagnostics::default().effective(),
            DiagRange::Boots(1)
        );
        assert_eq!(c(Some(3), None).effective(), DiagRange::Boots(3));
        assert_eq!(c(None, Some(48)).effective(), DiagRange::SinceHours(48));
    }

    #[test]
    fn collect_diagnostics_bounds() {
        let c = |boots, since_hours| CollectDiagnostics { boots, since_hours };
        assert!(c(None, None).validate().is_ok());
        assert!(c(Some(0), None).validate().is_err());
        assert!(c(Some(1), None).validate().is_ok());
        assert!(c(Some(5), None).validate().is_ok());
        assert!(c(Some(6), None).validate().is_err());
        assert!(c(None, Some(0)).validate().is_err());
        assert!(c(None, Some(1)).validate().is_ok());
        assert!(c(None, Some(168)).validate().is_ok());
        assert!(c(None, Some(169)).validate().is_err());
        // At most one of the two.
        assert!(c(Some(1), Some(24)).validate().is_err());
    }

    #[test]
    fn upload_request_wire() {
        round_trip(
            &DiagUploadRequest::Inbox {
                inbox_seq: 7,
                bytes: 123,
                sha256: SHA.into(),
            },
            json!({"kind": "inbox", "inbox_seq": 7, "bytes": 123, "sha256": SHA}),
        );
        round_trip(
            &DiagUploadRequest::Ticket {
                client_id: CLIENT.into(),
                bytes: 5,
                sha256: SHA.into(),
            },
            json!({"kind": "ticket", "client_id": CLIENT, "bytes": 5, "sha256": SHA}),
        );
        // The display ticket number is not an identifier on the wire.
        assert!(serde_json::from_value::<DiagUploadRequest>(
            json!({"kind": "ticket", "ticket": "1042", "bytes": 5, "sha256": SHA})
        )
        .is_err());
        assert!(serde_json::from_value::<DiagUploadRequest>(
            json!({"kind": "other", "bytes": 5, "sha256": SHA})
        )
        .is_err());
    }

    #[test]
    fn upload_request_limits() {
        let inbox = |bytes, sha: &str| DiagUploadRequest::Inbox {
            inbox_seq: 1,
            bytes,
            sha256: sha.into(),
        };
        let ticket = |bytes| DiagUploadRequest::Ticket {
            client_id: CLIENT.into(),
            bytes,
            sha256: SHA.into(),
        };
        assert_eq!(inbox(1, SHA).max_bytes(), DIAG_INBOX_MAX_BYTES);
        assert_eq!(ticket(1).max_bytes(), DIAG_TICKET_MAX_BYTES);
        assert!(inbox(1, SHA).validate().is_ok());
        assert!(inbox(0, SHA).validate().is_err());
        assert!(inbox(DIAG_INBOX_MAX_BYTES, SHA).validate().is_ok());
        assert!(inbox(DIAG_INBOX_MAX_BYTES + 1, SHA).validate().is_err());
        assert!(ticket(DIAG_TICKET_MAX_BYTES).validate().is_ok());
        assert!(ticket(DIAG_TICKET_MAX_BYTES + 1).validate().is_err());
        assert!(inbox(DIAG_TICKET_MAX_BYTES + 1, SHA).validate().is_ok());
        assert!(inbox(1, &SHA.to_uppercase()).validate().is_err());
        assert!(inbox(1, &SHA[1..]).validate().is_err());
        assert!(inbox(1, &format!("{}g", &SHA[1..])).validate().is_err());
        assert!(inbox(1, "").validate().is_err());
        let ticket_for = |id: &str| DiagUploadRequest::Ticket {
            client_id: id.into(),
            bytes: 1,
            sha256: SHA.into(),
        };
        assert!(ticket_for(CLIENT).validate().is_ok());
        assert!(ticket_for(&CLIENT.to_uppercase()).validate().is_err());
        assert!(ticket_for(&CLIENT.replace('-', "")).validate().is_err());
        assert!(ticket_for("1042").validate().is_err());
        assert!(ticket_for("").validate().is_err());
    }

    #[test]
    fn upload_response_wire() {
        let created = DiagUploadResponse {
            id: "d1".into(),
            complete: false,
            upload: Some(PresignedUpload {
                method: "PUT".into(),
                url: "https://bucket.example/obj".into(),
                headers: [("x-amz-tagging".to_owned(), "state=pending".to_owned())].into(),
                expires_at: at(),
                expires_in: 900,
            }),
        };
        round_trip(
            &created,
            json!({
                "id": "d1",
                "complete": false,
                "upload": {
                    "method": "PUT",
                    "url": "https://bucket.example/obj",
                    "headers": {"x-amz-tagging": "state=pending"},
                    "expires_at": "2026-11-05T08:30:00Z",
                    "expires_in": 900
                }
            }),
        );
        let done = DiagUploadResponse {
            id: "d1".into(),
            complete: true,
            upload: None,
        };
        round_trip(&done, json!({"id": "d1", "complete": true}));
        // The 201 body may leave `complete` out.
        let r: DiagUploadResponse = serde_json::from_value(json!({
            "id": "d2",
            "upload": {"method": "PUT", "url": "u", "headers": {}, "expires_at": "2026-11-05T08:30:00Z", "expires_in": 600}
        }))
        .unwrap();
        assert!(!r.complete);
        assert_eq!(r.upload.unwrap().expires_in, 600);
        // `expires_in` is required: the machine never judges expiry by its own clock.
        assert!(serde_json::from_value::<PresignedUpload>(json!({
            "method": "PUT", "url": "u", "headers": {}, "expires_at": "2026-11-05T08:30:00Z"
        }))
        .is_err());
    }

    #[test]
    fn presigned_query_not_in_debug() {
        let u = PresignedUpload {
            method: "PUT".into(),
            url: "https://bucket.example/obj?X-Amz-Signature=s1gn".into(),
            headers: BTreeMap::new(),
            expires_at: at(),
            expires_in: 900,
        };
        let d = format!("{u:?}");
        assert!(
            !d.contains("s1gn") && d.contains("https://bucket.example/obj") && d.contains("900"),
            "{d}"
        );
    }

    #[test]
    fn manifest_wire() {
        let m = DiagManifest {
            format: DIAG_MANIFEST_FORMAT,
            created_at: at(),
            device_id: "dev-1".into(),
            kind: DiagKind::Inbox,
            truncated: true,
            files: vec![
                DiagFile {
                    path: "journal/boot-0.txt".into(),
                    source: source::JOURNAL.into(),
                    kind: DiagFileType::Text,
                    bytes: 10,
                },
                DiagFile {
                    path: "screenshot.png".into(),
                    source: source::SCREENSHOT.into(),
                    kind: DiagFileType::Image,
                    bytes: 20,
                },
                DiagFile {
                    path: "x.bin".into(),
                    source: source::AGENT_STATE.into(),
                    kind: DiagFileType::Binary,
                    bytes: 1,
                },
            ],
            skipped: vec![DiagSkipped {
                source: source::IW_DEV.into(),
                reason: "command not found".into(),
            }],
        };
        round_trip(
            &m,
            json!({
                "format": 1,
                "created_at": "2026-11-05T08:30:00Z",
                "device_id": "dev-1",
                "kind": "inbox",
                "truncated": true,
                "files": [
                    {"path": "journal/boot-0.txt", "source": "journal", "type": "text", "bytes": 10},
                    {"path": "screenshot.png", "source": "screenshot", "type": "image", "bytes": 20},
                    {"path": "x.bin", "source": "agent-state", "type": "binary", "bytes": 1}
                ],
                "skipped": [{"source": "iw-dev", "reason": "command not found"}]
            }),
        );
        let small = DiagManifest {
            kind: DiagKind::Ticket,
            truncated: false,
            files: vec![],
            skipped: vec![],
            ..m
        };
        round_trip(
            &small,
            json!({
                "format": 1,
                "created_at": "2026-11-05T08:30:00Z",
                "device_id": "dev-1",
                "kind": "ticket",
                "truncated": false,
                "files": []
            }),
        );
        let lean: DiagManifest = serde_json::from_value(json!({
            "format": 1,
            "created_at": "2026-11-05T08:30:00Z",
            "device_id": "dev-1",
            "kind": "ticket",
            "files": []
        }))
        .unwrap();
        assert_eq!(lean, small);
    }

    #[test]
    fn source_names() {
        let want = [
            "journal",
            "journal-recent",
            "coredump-list",
            "coredump-info",
            "systemd-failed",
            "systemd-units",
            "loginctl",
            "nm-general",
            "nm-device",
            "nm-connection",
            "ip-addr",
            "ip-route",
            "resolvectl",
            "rfkill",
            "iw-dev",
            "iw-reg",
            "wifi-scan",
            "lspci",
            "lsusb",
            "cmdline",
            "input-devices",
            "mem-sleep",
            "power-supply",
            "os-release",
            "bootctl",
            "agent-state",
            "status-report",
            "screenshot",
        ];
        assert_eq!(source::ALL, &want);
        assert_eq!(source::JOURNAL, "journal");
        assert_eq!(source::JOURNAL_RECENT, "journal-recent");
        assert_eq!(source::WIFI_SCAN, "wifi-scan");
        assert_eq!(source::COREDUMP_INFO, "coredump-info");
        assert_eq!(source::SCREENSHOT, "screenshot");
    }

    fn manifest() -> DiagManifest {
        DiagManifest {
            format: DIAG_MANIFEST_FORMAT,
            created_at: at(),
            device_id: "dev-1".into(),
            kind: DiagKind::Inbox,
            truncated: false,
            files: vec![
                DiagFile {
                    path: "journal/boot-0.txt".into(),
                    source: source::JOURNAL.into(),
                    kind: DiagFileType::Text,
                    bytes: 10,
                },
                DiagFile {
                    path: "net/ip-addr.txt".into(),
                    source: source::IP_ADDR.into(),
                    kind: DiagFileType::Text,
                    bytes: 3,
                },
            ],
            skipped: vec![DiagSkipped {
                source: source::IW_DEV.into(),
                reason: "command not found".into(),
            }],
        }
    }

    #[test]
    fn manifest_validate() {
        assert!(manifest().validate().is_ok());
        let with_file = |path: &str, src: &str| {
            let mut m = manifest();
            m.files.push(DiagFile {
                path: path.into(),
                source: src.into(),
                kind: DiagFileType::Text,
                bytes: 1,
            });
            m
        };
        assert!(with_file("cmdline.txt", source::CMDLINE).validate().is_ok());
        assert!(with_file("x.txt", "journalctl -b 0").validate().is_err());
        assert!(with_file("x.txt", "").validate().is_err());
        for bad in [
            "",
            "/etc/passwd",
            "../x.txt",
            "a/../../x.txt",
            "a/..",
            "manifest.json",
            "./manifest.json",
        ] {
            assert!(with_file(bad, source::CMDLINE).validate().is_err(), "{bad}");
        }
        assert!(with_file("journal/manifest.json", source::JOURNAL)
            .validate()
            .is_ok());
        assert!(with_file("a/..b/x.txt", source::JOURNAL).validate().is_ok());
        let mut m = manifest();
        m.skipped[0].source = "iw dev".into();
        assert!(m.validate().is_err());
    }

    fn request() -> SupportRequest {
        SupportRequest {
            client_id: CLIENT.into(),
            category: SupportCategory::Wifi,
            text: "No internet".into(),
            user: SupportUser {
                kind: SupportUserKind::Sso,
                name: Some("student1".into()),
            },
            session: "desktop".into(),
            created_at: at(),
            snapshot: SupportSnapshot {
                os_version: "1.2.3".into(),
                network: Some("wifi:School".into()),
                battery_percent: Some(80),
                on_ac: Some(false),
                disk_free_bytes: Some(1000),
                status: None,
            },
            screenshot: true,
        }
    }

    #[test]
    fn support_request_wire() {
        round_trip(
            &request(),
            json!({
                "client_id": CLIENT,
                "category": "wifi",
                "text": "No internet",
                "user": {"kind": "sso", "name": "student1"},
                "session": "desktop",
                "created_at": "2026-11-05T08:30:00Z",
                "snapshot": {
                    "os_version": "1.2.3",
                    "network": "wifi:School",
                    "battery_percent": 80,
                    "on_ac": false,
                    "disk_free_bytes": 1000
                },
                "screenshot": true
            }),
        );
        let lean = SupportRequest {
            category: SupportCategory::SignIn,
            user: SupportUser {
                kind: SupportUserKind::None,
                name: None,
            },
            session: "login".into(),
            snapshot: SupportSnapshot {
                os_version: "1.2.3".into(),
                network: None,
                battery_percent: None,
                on_ac: None,
                disk_free_bytes: None,
                status: None,
            },
            screenshot: false,
            ..request()
        };
        round_trip(
            &lean,
            json!({
                "client_id": CLIENT,
                "category": "sign_in",
                "text": "No internet",
                "user": {"kind": "none"},
                "session": "login",
                "created_at": "2026-11-05T08:30:00Z",
                "snapshot": {"os_version": "1.2.3"},
                "screenshot": false
            }),
        );
        let mut v = serde_json::to_value(request()).unwrap();
        v["extra"] = json!(1);
        assert!(serde_json::from_value::<SupportRequest>(v).is_err());
    }

    #[test]
    fn support_enums_wire() {
        for (c, s) in [
            (SupportCategory::Wifi, "wifi"),
            (SupportCategory::SignIn, "sign_in"),
            (SupportCategory::App, "app"),
            (SupportCategory::Hardware, "hardware"),
            (SupportCategory::Battery, "battery"),
            (SupportCategory::Other, "other"),
        ] {
            assert_eq!(serde_json::to_value(c).unwrap(), json!(s));
            assert_eq!(
                serde_json::from_value::<SupportCategory>(json!(s)).unwrap(),
                c
            );
        }
        for (k, s) in [
            (SupportUserKind::None, "none"),
            (SupportUserKind::Guest, "guest"),
            (SupportUserKind::Local, "local"),
            (SupportUserKind::Sso, "sso"),
            (SupportUserKind::Unknown, "unknown"),
        ] {
            assert_eq!(serde_json::to_value(k).unwrap(), json!(s));
            assert_eq!(
                serde_json::from_value::<SupportUserKind>(json!(s)).unwrap(),
                k
            );
        }
    }

    #[test]
    fn unknown_user_kind_is_unknown() {
        assert_eq!(
            serde_json::from_value::<SupportUserKind>(json!("robot")).unwrap(),
            SupportUserKind::Unknown
        );
        let mut v = serde_json::to_value(request()).unwrap();
        v["user"]["kind"] = json!("robot");
        let r: SupportRequest = serde_json::from_value(v).unwrap();
        assert_eq!(r.user.kind, SupportUserKind::Unknown);
    }

    #[test]
    fn unknown_category_is_other() {
        assert_eq!(
            serde_json::from_value::<SupportCategory>(json!("printer")).unwrap(),
            SupportCategory::Other
        );
        let mut v = serde_json::to_value(request()).unwrap();
        v["category"] = json!("printer");
        let r: SupportRequest = serde_json::from_value(v).unwrap();
        assert_eq!(r.category, SupportCategory::Other);
    }

    #[test]
    fn support_request_validate() {
        assert!(request().validate().is_ok());
        let with_text = |text: String| SupportRequest { text, ..request() };
        assert!(with_text("é".repeat(1000)).validate().is_ok());
        assert!(with_text("é".repeat(1001)).validate().is_err());
        assert!(with_text(String::new()).validate().is_ok());
        let with_client = |id: &str| SupportRequest {
            client_id: id.into(),
            ..request()
        };
        assert!(with_client(&CLIENT.to_uppercase()).validate().is_err());
        assert!(with_client("not-a-uuid").validate().is_err());
        assert!(with_client(&CLIENT.replace('-', "")).validate().is_err());
        let with_session = |s: &str| SupportRequest {
            session: s.into(),
            ..request()
        };
        for ok in ["login", "desktop", "kiosk:khan-academy"] {
            assert!(with_session(ok).validate().is_ok(), "{ok}");
        }
        for bad in ["", "kiosk:", "kiosk", "Desktop", "shell"] {
            assert!(with_session(bad).validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn support_snapshot_size_limit() {
        // A snapshot whose `network` holds `n` ASCII bytes.
        let with_network = |n: usize| {
            let mut r = request();
            r.snapshot.network = Some("x".repeat(n));
            r
        };
        let base = serde_json::to_vec(&with_network(0).snapshot).unwrap().len();
        let fits = with_network(SUPPORT_SNAPSHOT_MAX_BYTES - base);
        assert_eq!(
            serde_json::to_vec(&fits.snapshot).unwrap().len(),
            SUPPORT_SNAPSHOT_MAX_BYTES
        );
        assert!(fits.validate().is_ok());
        assert!(with_network(SUPPORT_SNAPSHOT_MAX_BYTES - base + 1)
            .validate()
            .is_err());
    }

    #[test]
    fn api_error_wire() {
        round_trip(
            &ApiError {
                error: ERR_TOO_MANY.into(),
            },
            json!({"error": "too_many"}),
        );
        // Extra fields from a newer cloud are fine.
        let e: ApiError =
            serde_json::from_value(json!({"error": "invalid", "detail": "text too long"})).unwrap();
        assert_eq!(e.error, ERR_INVALID);
        for (c, s) in [
            (ERR_INVALID, "invalid"),
            (ERR_SUPPORT_DISABLED, "support_disabled"),
            (ERR_TOO_MANY, "too_many"),
            (ERR_DIAGNOSTICS_UNAVAILABLE, "diagnostics_unavailable"),
            (ERR_NOT_YOURS, "not_yours"),
            (ERR_EXPIRED, "expired"),
            (ERR_UPLOAD_MISMATCH, "upload_mismatch"),
            (ERR_FORBIDDEN, "forbidden"),
            (ERR_AGENT_TOO_OLD, "agent_too_old"),
        ] {
            assert_eq!(c, s);
        }
    }

    #[test]
    fn error_actions() {
        let e = |code: &str| ApiError { error: code.into() };
        use ErrorAction::*;
        let cases: &[(u16, Option<ApiError>, ErrorAction)] = &[
            (422, Some(e(ERR_INVALID)), Drop),
            (403, Some(e(ERR_SUPPORT_DISABLED)), DropSupportDisabled),
            (429, Some(e(ERR_TOO_MANY)), RetryAfter),
            (429, None, RetryAfter),
            (503, Some(e(ERR_DIAGNOSTICS_UNAVAILABLE)), Backoff),
            (409, Some(e(ERR_NOT_YOURS)), GiveUp),
            (410, Some(e(ERR_EXPIRED)), GiveUp),
            (409, Some(e(ERR_UPLOAD_MISMATCH)), Restart),
            (403, Some(e(ERR_FORBIDDEN)), Backoff),
            (500, None, Backoff),
            (502, Some(e("whatever")), Backoff),
            (503, None, Backoff),
            (404, None, Backoff),
            (404, Some(e("not_found")), Backoff),
            (401, None, Backoff),
            // Unknown or missing codes fall back by status.
            (400, None, Drop),
            (422, None, Drop),
            (400, Some(e("new_code")), Drop),
            (413, None, Drop),
            (403, None, Backoff),
            (409, None, Backoff),
            (410, None, Backoff),
            (418, Some(e("new_code")), Backoff),
            (403, Some(e(ERR_AGENT_TOO_OLD)), Backoff),
        ];
        for (status, body, want) in cases {
            assert_eq!(
                error_action(*status, body.as_ref()),
                *want,
                "{status} {body:?}"
            );
        }
    }

    #[test]
    fn support_response_wire() {
        round_trip(
            &SupportResponse {
                ticket: "1042".into(),
            },
            json!({"ticket": "1042"}),
        );
    }
}
