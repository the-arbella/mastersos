//! Credentials for the CLI API. This is the minimal form; the `arbella` and stored-login
//! variants arrive in Task 3 of plan C.

use crate::server::CliError;

/// Where the bearer tokens come from.
#[derive(Clone)]
pub enum Credentials {
    /// Tokens given directly (tests, and the first form of the client).
    Fixed {
        token: String,
        step_up: Option<String>,
    },
}

/// The tokens never show in Debug output.
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Credentials::Fixed { .. } => f.write_str("Fixed(<redacted>)"),
        }
    }
}

impl Credentials {
    /// A token with no step-up token behind it.
    pub fn fixed(token: &str) -> Credentials {
        Credentials::Fixed {
            token: token.to_string(),
            step_up: None,
        }
    }

    /// A token and the token that answers a step-up challenge.
    pub fn fixed_with_step_up(token: &str, step_up: &str) -> Credentials {
        Credentials::Fixed {
            token: token.to_string(),
            step_up: Some(step_up.to_string()),
        }
    }

    /// The token for an ordinary call.
    pub async fn token(&self) -> Result<String, CliError> {
        match self {
            Credentials::Fixed { token, .. } => Ok(token.clone()),
        }
    }

    /// A token from a fresh sign-in, for a call the server wants stepped up.
    pub async fn step_up(&self) -> Result<String, CliError> {
        match self {
            Credentials::Fixed { step_up, .. } => step_up.clone().ok_or_else(|| {
                CliError::new(
                    "not_logged_in",
                    "this call needs a fresh sign-in and no step-up token is available",
                )
            }),
        }
    }
}
