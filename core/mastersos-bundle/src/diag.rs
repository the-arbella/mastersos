//! Wire types for remote diagnostics and "Get help" (remote diagnostics and help design,
//! section 接口). The cloud pins this repository and uses these exact types.
//!
//! Endpoints (all authenticated with the device credential, machine → cloud over HTTPS):
//!
//! - `POST /v1/support` with a [`SupportRequest`]: `201` with a [`SupportResponse`]. The same
//!   `client_id` always gets the same ticket (offline resends are idempotent); `429` over the
//!   limit ([`SUPPORT_MAX_PER_HOUR`]); unknown categories are taken as `other`.
//! - `POST /v1/diagnostics` with a [`DiagUploadRequest`]: `201` with a [`DiagUploadResponse`]
//!   carrying a presigned S3 `PUT` ([`PresignedUpload`], valid [`UPLOAD_URL_TTL_SECS`]); `200`
//!   `{"id","complete":true}` without `upload` when that seq or ticket is already complete (the
//!   machine skips the `PUT` and the complete call); an incomplete one gets the same id and a
//!   new URL. `413` over the size limit; `409` when the seq is not a `collect-diagnostics`
//!   message sent to this machine, or the ticket is not this machine's (or older than
//!   [`TICKET_ATTACH_WINDOW_HOURS`]).
//! - The machine `PUT`s the archive to `upload.url` with `upload.headers` exactly as given (they
//!   carry the signed `Content-Length`, `x-amz-checksum-sha256` and tagging). An expired URL:
//!   back to `POST /v1/diagnostics`.
//! - `POST /v1/diagnostics/{id}/complete`: the cloud checks size and SHA-256; `204` when they
//!   match (only then has the archive arrived). `409` means the object was deleted: ask again
//!   with `POST /v1/diagnostics`.
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
/// Most characters (Unicode scalar values) in [`SupportRequest::text`].
pub const SUPPORT_TEXT_MAX_CHARS: usize = 1000;
/// Most support requests one machine sends per hour.
pub const SUPPORT_MAX_PER_HOUR: u32 = 3;
/// How long after a ticket is created its attachment is still accepted.
pub const TICKET_ATTACH_WINDOW_HOURS: i64 = 48;
/// Lifetime of a presigned upload URL.
pub const UPLOAD_URL_TTL_SECS: u64 = 900;
/// [`DiagManifest::format`] written by this version.
pub const DIAG_MANIFEST_FORMAT: u32 = 1;
/// File name of the [`DiagManifest`] inside a diagnostics archive.
pub const DIAG_MANIFEST_NAME: &str = "manifest.json";

const BOOTS_MAX: u8 = 5;
const SINCE_HOURS_MAX: u16 = 168;

fn one() -> u8 {
    1
}

/// Payload of a [`KIND_COLLECT_DIAGNOSTICS`] inbox command.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CollectDiagnostics {
    /// How many boots of journal to collect, newest first: 1 to 5.
    #[serde(default = "one")]
    pub boots: u8,
    /// Only the last this many hours of those boots: 1 to 168; `null`: the whole boots.
    pub since_hours: Option<u16>,
}

impl Default for CollectDiagnostics {
    fn default() -> Self {
        CollectDiagnostics {
            boots: 1,
            since_hours: None,
        }
    }
}

impl CollectDiagnostics {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=BOOTS_MAX).contains(&self.boots) {
            return Err(format!(
                "boots must be 1 to {BOOTS_MAX}, not {}",
                self.boots
            ));
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
        ticket: String,
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

/// A presigned S3 request: the machine sends the archive with exactly this method, URL and
/// headers, adding nothing and converting nothing.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PresignedUpload {
    /// `PUT`.
    pub method: String,
    pub url: String,
    /// Headers signed into the URL (`Content-Length`, `x-amz-checksum-sha256`, tagging).
    pub headers: BTreeMap<String, String>,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub expires_at: DateTime<Utc>,
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
            .finish()
    }
}

/// Answer to `POST /v1/diagnostics`: `201` with `upload`, or `200` `{"id","complete":true}`
/// when that upload is already complete (the machine then skips the `PUT` and the complete
/// call). Then `POST /v1/diagnostics/{id}/complete` gives `204`; `409` means the object was
/// deleted and the machine asks again.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DiagUploadResponse {
    pub id: String,
    #[serde(default)]
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload: Option<PresignedUpload>,
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

/// One file of a diagnostics archive.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DiagFile {
    /// Path inside the archive.
    pub path: String,
    /// Where it came from: a command line or a file path on the machine.
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

/// Who sent a support request, as the system (not the dialog) determined it.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum SupportUserKind {
    /// Nobody signed in (the login screen).
    None,
    Guest,
    Local,
    Sso,
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
    pub snapshot: SupportSnapshot,
    /// Whether the attachment will include a screenshot.
    pub screenshot: bool,
}

impl SupportRequest {
    pub fn validate(&self) -> Result<(), String> {
        if !crate::valid_school_id(&self.client_id) {
            return Err(
                "client_id must be a lowercase UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)"
                    .to_owned(),
            );
        }
        let n = self.text.chars().count();
        if n > SUPPORT_TEXT_MAX_CHARS {
            return Err(format!(
                "text must be at most {SUPPORT_TEXT_MAX_CHARS} characters, not {n}"
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
        assert_eq!(TICKET_ATTACH_WINDOW_HOURS, 48);
        assert_eq!(UPLOAD_URL_TTL_SECS, 900);
        assert_eq!(DIAG_MANIFEST_FORMAT, 1);
        assert_eq!(DIAG_MANIFEST_NAME, "manifest.json");
    }

    #[test]
    fn collect_diagnostics_wire_and_defaults() {
        round_trip(
            &CollectDiagnostics {
                boots: 2,
                since_hours: Some(24),
            },
            json!({"boots": 2, "since_hours": 24}),
        );
        round_trip(
            &CollectDiagnostics {
                boots: 1,
                since_hours: None,
            },
            json!({"boots": 1, "since_hours": null}),
        );
        let empty: CollectDiagnostics = serde_json::from_value(json!({})).unwrap();
        assert_eq!(
            empty,
            CollectDiagnostics {
                boots: 1,
                since_hours: None
            }
        );
        assert_eq!(CollectDiagnostics::default(), empty);
    }

    #[test]
    fn collect_diagnostics_bounds() {
        let c = |boots, since_hours| CollectDiagnostics { boots, since_hours };
        assert!(c(0, None).validate().is_err());
        assert!(c(1, None).validate().is_ok());
        assert!(c(5, None).validate().is_ok());
        assert!(c(6, None).validate().is_err());
        assert!(c(1, Some(0)).validate().is_err());
        assert!(c(1, Some(1)).validate().is_ok());
        assert!(c(1, Some(168)).validate().is_ok());
        assert!(c(1, Some(169)).validate().is_err());
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
                ticket: "1042".into(),
                bytes: 5,
                sha256: SHA.into(),
            },
            json!({"kind": "ticket", "ticket": "1042", "bytes": 5, "sha256": SHA}),
        );
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
            ticket: "1".into(),
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
                    "expires_at": "2026-11-05T08:30:00Z"
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
            "upload": {"method": "PUT", "url": "u", "headers": {}, "expires_at": "2026-11-05T08:30:00Z"}
        }))
        .unwrap();
        assert!(!r.complete);
        assert!(r.upload.is_some());
    }

    #[test]
    fn presigned_query_not_in_debug() {
        let u = PresignedUpload {
            method: "PUT".into(),
            url: "https://bucket.example/obj?X-Amz-Signature=s1gn".into(),
            headers: BTreeMap::new(),
            expires_at: at(),
        };
        let d = format!("{u:?}");
        assert!(
            !d.contains("s1gn") && d.contains("https://bucket.example/obj"),
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
                    source: "journalctl -b 0".into(),
                    kind: DiagFileType::Text,
                    bytes: 10,
                },
                DiagFile {
                    path: "screenshot.png".into(),
                    source: "screenshot".into(),
                    kind: DiagFileType::Image,
                    bytes: 20,
                },
                DiagFile {
                    path: "x.bin".into(),
                    source: "x".into(),
                    kind: DiagFileType::Binary,
                    bytes: 1,
                },
            ],
            skipped: vec![DiagSkipped {
                source: "iw dev".into(),
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
                    {"path": "journal/boot-0.txt", "source": "journalctl -b 0", "type": "text", "bytes": 10},
                    {"path": "screenshot.png", "source": "screenshot", "type": "image", "bytes": 20},
                    {"path": "x.bin", "source": "x", "type": "binary", "bytes": 1}
                ],
                "skipped": [{"source": "iw dev", "reason": "command not found"}]
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
        ] {
            assert_eq!(serde_json::to_value(k).unwrap(), json!(s));
        }
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
    fn support_response_wire() {
        round_trip(
            &SupportResponse {
                ticket: "1042".into(),
            },
            json!({"ticket": "1042"}),
        );
    }
}
