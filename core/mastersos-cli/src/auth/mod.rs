//! Credentials for the CLI API (protocol §6): `arbella` when it is on `PATH`, else the sign-in of
//! `mastersos login` ([`store`]), else none (`not_logged_in`).
//!
//! - Tokens never appear in Debug output, errors, logs or `--json` output.
//! - Credentials are only used for the server they name: a `--server` (or work directory) naming
//!   another server is refused before any token is sent.

pub mod arbella;
pub mod loopback;
pub mod oidc;
pub mod store;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::server::{self, CliError};

/// Where the bearer tokens come from.
#[derive(Clone)]
pub enum Credentials {
    /// Tokens given directly (tests).
    Fixed {
        token: String,
        step_up: Option<String>,
    },
    /// `arbella auth token [--step-up] --json`, run from `exe`; its tokens are used only while it
    /// names the server `origin` it named when resolved.
    Arbella { exe: PathBuf, origin: String },
    /// The sign-in saved by `mastersos login`.
    Stored(Arc<store::Session>),
}

/// The tokens never show in Debug output.
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Credentials::Fixed { .. } => f.write_str("Fixed(<redacted>)"),
            Credentials::Arbella { exe, origin } => write!(f, "Arbella({exe:?}, {origin})"),
            Credentials::Stored(_) => f.write_str("Stored(<redacted>)"),
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
            Credentials::Arbella { exe, origin } => {
                same_server(arbella::token(exe, false).await?, origin)
            }
            Credentials::Stored(s) => s.token().await,
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
            Credentials::Arbella { exe, origin } => {
                same_server(arbella::token(exe, true).await?, origin)
            }
            Credentials::Stored(s) => s.step_up().await,
        }
    }
}

/// arbella's token, if arbella still names the server it named when resolved: one it signed in to
/// since must not receive a token meant for another (and the reverse).
fn same_server(t: arbella::ArbellaToken, origin: &str) -> Result<String, CliError> {
    match origin_of(&t.server_url) {
        Ok(o) if o == origin => Ok(t.access_token),
        _ => Err(CliError::new(
            "not_logged_in",
            &format!(
                "arbella is now signed in to another server than {origin}: sign in to {origin} with arbella again"
            ),
        )),
    }
}

/// The credentials to use and the server origin they name: `arbella` on `PATH` wins, else the
/// saved `mastersos login`, else `not_logged_in`. `server_flag` (from `--server` or the work
/// directory) must name the same server.
pub async fn resolve(server_flag: Option<&str>) -> Result<(Credentials, Option<String>), CliError> {
    resolve_with(arbella::find(), &store::path()?, server_flag, true).await
}

/// A server address as an origin (`https://host[:port]`), checked like `--server`.
fn origin_of(s: &str) -> Result<String, CliError> {
    Ok(server::check_origin(s)?.origin().ascii_serialization())
}

/// [`resolve`] with arbella's path and the credentials file given.
pub(crate) async fn resolve_with(
    arbella: Option<PathBuf>,
    creds: &Path,
    server_flag: Option<&str>,
    open_browser: bool,
) -> Result<(Credentials, Option<String>), CliError> {
    let wanted = server_flag.map(origin_of).transpose()?;
    if let Some(exe) = arbella {
        // A failing arbella is the answer: the saved login is not tried instead.
        let t = arbella::token(&exe, false).await?;
        let origin = origin_of(&t.server_url).map_err(|_| {
            CliError::new(
                "invalid_answer",
                "arbella named a server address that is not valid",
            )
        })?;
        if let Some(w) = wanted.filter(|w| *w != origin) {
            return Err(CliError::new(
                "not_logged_in",
                &format!(
                    "arbella is signed in to {origin}, not to {w}: sign in to {w} with arbella"
                ),
            ));
        }
        let creds = Credentials::Arbella {
            exe,
            origin: origin.clone(),
        };
        return Ok((creds, Some(origin)));
    }
    let Some(login) = store::load_from(creds)? else {
        return Err(CliError::new(
            "not_logged_in",
            "not signed in: run `mastersos login --server <URL>`, or install arbella",
        ));
    };
    let origin = origin_of(&login.server_url).map_err(|_| {
        CliError::new(
            "not_logged_in",
            "the saved sign-in names no valid server: run `mastersos login --server <URL>` again",
        )
    })?;
    if let Some(w) = wanted.filter(|w| *w != origin) {
        return Err(CliError::new(
            "not_logged_in",
            &format!(
                "you are signed in to {origin}, not to {w}: run `mastersos login --server {w}`"
            ),
        ));
    }
    let session = store::Session::new(creds.to_path_buf(), login, open_browser);
    Ok((Credentials::Stored(Arc::new(session)), Some(origin)))
}

/// `mastersos login --server URL [--no-browser]`: the device grant against the server's issuer,
/// saved in the credentials file. What to print on stdout (never a token).
pub async fn login(
    server_flag: Option<&str>,
    no_browser: bool,
    json: bool,
) -> Result<String, CliError> {
    let flag = server_flag.ok_or_else(|| {
        CliError::usage("mastersos login needs --server <URL>, for example https://server.example")
    })?;
    let origin = server::check_origin(flag)?;
    let origin_s = origin.origin().ascii_serialization();
    let path = store::path()?;
    if arbella::find().is_some() {
        eprintln!("Note: arbella is installed; mastersos uses arbella's sign-in before this one.");
    }
    let cfg = server::auth_config(&origin).await?;
    let d = oidc::discover(&cfg.issuer).await?;
    // With --json, stdout holds only the result.
    let t = if json {
        oidc::device_grant(&cfg, &d, &mut std::io::stderr(), !no_browser).await?
    } else {
        oidc::device_grant(&cfg, &d, &mut std::io::stdout(), !no_browser).await?
    };
    let saved = store::StoredLogin::new(&origin_s, &cfg, &t);
    store::save_to(&path, &saved)?;
    Ok(if json {
        format!(
            "{}\n",
            serde_json::json!({"server_url": origin_s, "expires_at": saved.expires_at})
        )
    } else {
        format!("Signed in to {origin_s}.\n")
    })
}

/// `mastersos logout`: remove the credentials file. What to print on stdout.
pub fn logout(json: bool) -> Result<String, CliError> {
    let removed = store::remove()?;
    Ok(if json {
        format!("{}\n", serde_json::json!({"signed_out": removed}))
    } else if removed {
        "Signed out.\n".to_string()
    } else {
        "Not signed in.\n".to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_debug_is_redacted() {
        let l = store::StoredLogin {
            version: 1,
            server_url: "https://server.example".into(),
            issuer: "https://issuer.example".into(),
            client_id: "c".into(),
            audience: "a".into(),
            scopes: vec![],
            step_up_acr: String::new(),
            access_token: "SECRET-A".into(),
            expires_at: "x".into(),
            refresh_token: Some("SECRET-R".into()),
        };
        let all = [
            Credentials::fixed_with_step_up("SECRET-1", "SECRET-2"),
            Credentials::Arbella {
                exe: PathBuf::from("/usr/bin/arbella"),
                origin: "https://server.example".into(),
            },
            Credentials::Stored(Arc::new(store::Session::new(PathBuf::from("/x"), l, false))),
        ];
        for c in all {
            let d = format!("{c:?}");
            assert!(!d.contains("SECRET"), "{d}");
        }
    }

    #[cfg(unix)]
    mod unix {
        use super::super::*;
        use crate::auth::arbella::{fake, GOOD};
        use crate::auth::store::{save_to, StoredLogin, FILE_NAME};

        fn stored(server: &str) -> StoredLogin {
            StoredLogin {
                version: 1,
                server_url: server.into(),
                issuer: "https://issuer.example".into(),
                client_id: "c".into(),
                audience: "a".into(),
                scopes: vec!["openid".into()],
                step_up_acr: String::new(),
                access_token: "stored-token".into(),
                expires_at: "2999-01-01T00:00:00Z".into(),
                refresh_token: None,
            }
        }

        #[tokio::test]
        async fn resolve_prefers_arbella() {
            let t = tempfile::tempdir().unwrap();
            let exe = fake(t.path(), GOOD);
            let p = t.path().join("m").join(FILE_NAME);
            save_to(&p, &stored("https://other.example")).unwrap();
            let (c, origin) = resolve_with(Some(exe.clone()), &p, None, false)
                .await
                .unwrap();
            assert!(matches!(&c, Credentials::Arbella { exe: e, .. } if *e == exe));
            assert_eq!(origin.as_deref(), Some("https://server.example"));
            assert_eq!(c.token().await.unwrap(), "t");
            // The same server, written another way, is the same server.
            resolve_with(Some(exe), &p, Some("https://SERVER.example/"), false)
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn resolve_uses_the_saved_login_without_arbella() {
            let t = tempfile::tempdir().unwrap();
            let p = t.path().join("m").join(FILE_NAME);
            save_to(&p, &stored("https://server.example")).unwrap();
            let (c, origin) = resolve_with(None, &p, Some("https://server.example"), false)
                .await
                .unwrap();
            assert!(matches!(c, Credentials::Stored(_)));
            assert_eq!(origin.as_deref(), Some("https://server.example"));
            assert_eq!(c.token().await.unwrap(), "stored-token");
        }

        #[tokio::test]
        async fn resolve_without_either_is_not_logged_in() {
            let t = tempfile::tempdir().unwrap();
            let p = t.path().join("m").join(FILE_NAME);
            let e = resolve_with(None, &p, None, false).await.unwrap_err();
            assert_eq!(e.code, "not_logged_in");
            assert!(e.message.contains("mastersos login --server"), "{e:?}");
            assert!(e.message.contains("arbella"), "{e:?}");
        }

        #[tokio::test]
        async fn resolve_refuses_credentials_of_another_server() {
            let t = tempfile::tempdir().unwrap();
            let p = t.path().join("m").join(FILE_NAME);
            save_to(&p, &stored("https://server.example")).unwrap();
            let e = resolve_with(None, &p, Some("https://other.example"), false)
                .await
                .unwrap_err();
            assert_eq!(e.code, "not_logged_in");
            assert!(e.message.contains("https://other.example"), "{e:?}");
            let exe = fake(t.path(), GOOD);
            let e = resolve_with(Some(exe), &p, Some("https://other.example"), false)
                .await
                .unwrap_err();
            assert_eq!(e.code, "not_logged_in");
            assert!(e.message.contains("arbella"), "{e:?}");
        }

        #[tokio::test]
        async fn failing_arbella_does_not_fall_back_to_the_saved_login() {
            let t = tempfile::tempdir().unwrap();
            let exe = fake(t.path(), "exit 3");
            let p = t.path().join("m").join(FILE_NAME);
            save_to(&p, &stored("https://server.example")).unwrap();
            let e = resolve_with(Some(exe), &p, None, false).await.unwrap_err();
            assert_eq!(e.code, "not_logged_in");
            assert!(e.message.contains("arbella login"), "{e:?}");
        }

        #[tokio::test]
        async fn arbella_credentials_run_arbella_for_each_kind_of_token() {
            let t = tempfile::tempdir().unwrap();
            let exe = fake(t.path(), GOOD);
            let c = Credentials::Arbella {
                exe,
                origin: "https://server.example".into(),
            };
            assert_eq!(c.step_up().await.unwrap(), "t");
            let args = std::fs::read_to_string(t.path().join("args")).unwrap();
            assert!(args.contains("--step-up"), "{args}");
        }

        /// arbella signed in to another server since `resolve`: its token is refused before
        /// any request carries it.
        #[tokio::test]
        async fn arbella_answering_another_server_later_is_refused() {
            use wiremock::{Mock, MockServer, ResponseTemplate};
            let mock = MockServer::start().await;
            Mock::given(wiremock::matchers::any())
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
                .mount(&mock)
                .await;
            let t = tempfile::tempdir().unwrap();
            let first = format!(
                r#"{{"fleet_url":"{}","access_token":"first","expires_at":"x"}}"#,
                mock.uri()
            );
            let later = r#"{"fleet_url":"https://other.example","access_token":"SECRET-LATER","expires_at":"x"}"#;
            let body = format!(
                "d=$(dirname \"$0\")\nn=$(cat \"$d/n\" 2>/dev/null || echo 0)\n\
                 echo $((n+1)) > \"$d/n\"\n\
                 if [ \"$n\" = 0 ]; then echo '{first}'; else echo '{later}'; fi"
            );
            let exe = fake(t.path(), &body);
            let p = t.path().join("m").join(FILE_NAME);
            let (c, origin) = resolve_with(Some(exe), &p, None, false).await.unwrap();
            assert_eq!(origin.as_deref(), Some(mock.uri().as_str()));
            for e in [c.token().await.unwrap_err(), c.step_up().await.unwrap_err()] {
                assert_eq!(e.code, "not_logged_in");
                assert!(!format!("{e:?}").contains("SECRET"), "{e:?}");
                assert!(!e.message.contains("first"), "{e:?}");
            }
            let s = crate::server::Server::new(
                &mock.uri(),
                Some("0192f3a4-5b6c-7d8e-9f00-112233445566"),
                c,
            )
            .unwrap();
            let e = s.get_json::<serde_json::Value>("keys").await.unwrap_err();
            assert_eq!(e.code, "not_logged_in");
            assert!(mock.received_requests().await.unwrap().is_empty());
        }
    }
}
