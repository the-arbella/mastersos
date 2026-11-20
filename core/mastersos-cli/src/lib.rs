//! mastersos: the command line. Settings are edited in a local directory ([`workdir`]) and
//! published from there ([`publish`]); the server holds no draft. The school key signs on this
//! computer ([`sign`]).
//!
//! - Server responses are data: they are never acted on before they are checked.
//! - The token only goes in the `Authorization` header (marked sensitive): not in logs or errors.

// Unsafe code only in `platform`, for the Windows API calls.
#![cfg_attr(not(windows), forbid(unsafe_code))]
#![cfg_attr(windows, deny(unsafe_code))]

pub mod auth;
pub mod cli;
pub mod explain;
pub mod itpass;
pub mod platform;
pub mod publish;
pub mod safe;
pub mod seed;
pub mod server;
pub mod sign;
pub mod workdir;

use serde_json::Value;

/// Why an operation did not happen.
#[derive(Debug)]
pub enum OpError {
    /// The local check refused it; nothing was sent. `issues` holds the check's issues. The command line exits 2.
    Refused {
        message: String,
        issues: Option<Vec<Value>>,
    },
    /// The command line is misused (arguments that do not go together, nobody to type a password). The command line exits 2.
    Usage(String),
    /// A local file that cannot be used, or a failed operation. The command line exits 1.
    Failed(String),
}

impl OpError {
    pub fn exit_code(&self) -> u8 {
        match self {
            OpError::Refused { .. } | OpError::Usage(_) => 2,
            OpError::Failed(_) => 1,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            OpError::Refused { message, .. }
            | OpError::Usage(message)
            | OpError::Failed(message) => message,
        }
    }
}

impl From<String> for OpError {
    fn from(m: String) -> OpError {
        OpError::Failed(m)
    }
}
