//! Wire types for MQTT push (doorbell) and the per-device inbox.
//!
//! MQTT only rings a doorbell; state and commands travel over HTTPS (settings
//! bundle and inbox). Secrets never appear in `Debug` output.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Lifetime of a machine's MQTT token.
pub const PUSH_TOKEN_TTL_SECS: u64 = 86400;
/// Default lifetime of an inbox command before it expires.
pub const COMMAND_DEFAULT_TTL_SECS: u64 = 86400;
/// Maximum pending inbox messages per machine.
pub const INBOX_MAX_PENDING: u64 = 100;
/// Maximum characters kept from a result `detail`.
pub const INBOX_DETAIL_MAX_CHARS: usize = 500;
/// Inbox message kind for a factory reset command.
pub const KIND_FACTORY_RESET: &str = "factory-reset";
/// Maximum machines in one factory-reset batch.
pub const RESET_BATCH_MAX: usize = 10;

/// Request for an MQTT token, authenticated by the machine's escrow secret.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PushTokenRequest {
    pub device_id: String,
    pub secret: String,
}

impl fmt::Debug for PushTokenRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushTokenRequest")
            .field("device_id", &self.device_id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// MQTT connection grant for one machine.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PushTokenResponse {
    pub token: String,
    pub broker: String,
    pub client_id: String,
    pub topics: Vec<String>,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub expires_at: DateTime<Utc>,
}

impl fmt::Debug for PushTokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushTokenResponse")
            .field("token", &"<redacted>")
            .field("broker", &self.broker)
            .field("client_id", &self.client_id)
            .field("topics", &self.topics)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Whether an inbox message is an action to run or a notice to show.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum InboxClass {
    Command,
    Notice,
}

/// One message in a machine's inbox.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct InboxMessage {
    pub seq: u64,
    pub class: InboxClass,
    pub kind: String,
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub payload: serde_json::Value,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub created_at: DateTime<Utc>,
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Messages after a given sequence number, plus the highest sequence seen.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct InboxPage {
    pub messages: Vec<InboxMessage>,
    pub last_seq: u64,
}

/// Progress of a command on the machine.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum InboxResultState {
    Running,
    Done,
    Failed,
}

/// Result a machine reports for an inbox message.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct InboxResult {
    pub state: InboxResultState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Content-free MQTT message: only says which counter moved.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum Doorbell {
    /// New settings bundle version.
    Settings(u64),
    /// New inbox sequence number.
    Inbox(u64),
}

impl Doorbell {
    /// Parses a doorbell payload; anything unrecognised yields `None`.
    pub fn parse(bytes: &[u8]) -> Option<Doorbell> {
        serde_json::from_slice(bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doorbell_wire_format() {
        assert_eq!(
            serde_json::to_string(&Doorbell::Settings(42)).unwrap(),
            r#"{"settings":42}"#
        );
        assert_eq!(
            serde_json::to_string(&Doorbell::Inbox(7)).unwrap(),
            r#"{"inbox":7}"#
        );
        assert_eq!(Doorbell::parse(br#"{"inbox":7}"#), Some(Doorbell::Inbox(7)));
        assert_eq!(Doorbell::parse(b"garbage"), None);
    }

    #[test]
    fn secrets_not_in_debug() {
        let r = PushTokenRequest {
            device_id: "d".into(),
            secret: "s3cr3t".into(),
        };
        assert!(!format!("{r:?}").contains("s3cr3t"));
        let t = PushTokenResponse {
            token: "tok3n".into(),
            broker: "b".into(),
            client_id: "c".into(),
            topics: vec![],
            expires_at: Utc::now(),
        };
        assert!(!format!("{t:?}").contains("tok3n"));
    }

    #[test]
    fn result_state_snake_case() {
        assert_eq!(
            serde_json::to_string(&InboxResultState::Running).unwrap(),
            r#""running""#
        );
    }
}
