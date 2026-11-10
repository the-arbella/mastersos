//! Third-party .deb apps (`[config.apps.deb.<id>]`) and `ubuntu_mirror`: the rules shared by lint
//! and the agent. The types are in `manifest.rs`; design docs/specs/2026-11-10-deb-apps-design.md §4.1.
//!
//! [`check`] judges the shape of one entry. Whether `exec` is really provided by the app's
//! extension, and whether `icon` exists in the bundle, are decided later (agent, lint).

use crate::kiosk;
use crate::DebApp;

/// At most this many extra Ubuntu packages per app.
pub const MAX_PACKAGES: usize = 32;

/// One failed rule: `code` is the lint code, `field` the key under the app (`id` for the table name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebError {
    pub code: &'static str,
    pub message: String,
    pub field: &'static str,
}

fn fail<T>(code: &'static str, field: &'static str, message: String) -> Result<T, DebError> {
    Err(DebError {
        code,
        message,
        field,
    })
}

/// Debian package name: `^[a-z0-9][a-z0-9+.-]+$`.
pub fn package_name_ok(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 2
        && b.len() <= 128
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'+' | b'.' | b'-')
        })
}

/// 64 lowercase hexadecimal digits.
fn sha256_ok(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// All the format rules of one `[config.apps.deb.<id>]`, reporting the first failure. Whether the
/// icon file is in the bundle, and whether `exec` is provided by the app, are judged elsewhere.
pub fn check(id: &str, app: &DebApp) -> Result<(), DebError> {
    if !kiosk::id_ok(id) {
        return fail(
            "deb_id_invalid",
            "id",
            format!(
                "Deb app id {id:?} must start with a lowercase letter, contain only lowercase letters, digits and -, and be at most {} characters",
                kiosk::MAX_ID_LEN
            ),
        );
    }
    if let Err(why) = kiosk::name_problem(&app.name) {
        return fail("deb_name_invalid", "name", why);
    }
    if let Err(why) = kiosk::https_url(&app.url) {
        return fail(
            "deb_url_invalid",
            "url",
            format!(
                "url {:?} {why}; expected an https:// address of the .deb file",
                app.url
            ),
        );
    }
    if let Some(h) = app.sha256.as_deref().filter(|h| !sha256_ok(h)) {
        return fail(
            "deb_sha256_invalid",
            "sha256",
            format!("sha256 {h:?} must be 64 lowercase hexadecimal digits"),
        );
    }
    if app.packages.len() > MAX_PACKAGES {
        return fail(
            "deb_packages_invalid",
            "packages",
            format!(
                "There are {} packages, at most {MAX_PACKAGES} are allowed",
                app.packages.len()
            ),
        );
    }
    if let Some(p) = app.packages.iter().find(|p| !package_name_ok(p)) {
        return fail(
            "deb_packages_invalid",
            "packages",
            format!(
                "Package name {p:?} must be a Debian package name: lowercase letters, digits, + . -, starting with a letter or digit, at least 2 characters"
            ),
        );
    }
    if let Some(x) = app
        .exec
        .as_deref()
        .filter(|x| !kiosk::abs_path_under(x, &["/opt/", "/usr/"]))
    {
        return fail(
            "deb_exec_invalid",
            "exec",
            format!(
                "exec {x:?} must be an absolute path under /opt/ or /usr/ without ..; arguments are not allowed"
            ),
        );
    }
    if let Some(i) = app
        .icon
        .as_deref()
        .filter(|i| !(i.starts_with("https://") || i.starts_with("files/")) || i.len() > 2048)
    {
        return fail(
            "deb_icon_invalid",
            "icon",
            format!("icon {i:?} must be a files/... file in the bundle or an https:// link"),
        );
    }
    Ok(())
}

/// `ubuntu_mirror`: an `http://` or `https://` archive root (same spelling rules as `update_mirror`).
pub fn check_mirror(url: &str) -> Result<(), String> {
    crate::checks::update_mirror(url).map_err(|e| e.replacen("update_mirror", "ubuntu_mirror", 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn testnav() -> DebApp {
        DebApp {
            name: "TestNav".into(),
            url: "https://download.testnav.com/_testnavinstallers/testnav-1.15.7.deb".into(),
            sha256: Some("a".repeat(64)),
            kiosk: true,
            packages: vec!["x11-utils".into()],
            exec: None,
            icon: None,
        }
    }

    fn code(app: &DebApp) -> (&'static str, &'static str) {
        let e = check("testnav", app).unwrap_err();
        (e.code, e.field)
    }

    #[test]
    fn testnav_example_passes() {
        check("testnav", &testnav()).unwrap();
    }

    #[test]
    fn id_rules() {
        for bad in ["", "Testnav", "1abc", "a_b", &"a".repeat(25)] {
            let e = check(bad, &testnav()).unwrap_err();
            assert_eq!((e.code, e.field), ("deb_id_invalid", "id"), "{bad}");
        }
        check(&"a".repeat(24), &testnav()).unwrap();
    }

    #[test]
    fn name_rules() {
        for bad in ["", "a:b", "a,b", "a\nb"] {
            let mut a = testnav();
            a.name = bad.into();
            assert_eq!(code(&a), ("deb_name_invalid", "name"), "{bad:?}");
        }
    }

    #[test]
    fn http_url_rejected() {
        let mut a = testnav();
        a.url = "http://download.testnav.com/x.deb".into();
        assert_eq!(code(&a), ("deb_url_invalid", "url"));
        a.url = format!("https://x.example/{}", "a".repeat(2048));
        assert_eq!(code(&a), ("deb_url_invalid", "url"));
    }

    #[test]
    fn uppercase_sha_rejected() {
        let mut a = testnav();
        a.sha256 = Some("A".repeat(64));
        assert_eq!(code(&a), ("deb_sha256_invalid", "sha256"));
        a.sha256 = Some("a".repeat(63));
        assert_eq!(code(&a), ("deb_sha256_invalid", "sha256"));
        a.sha256 = None;
        check("testnav", &a).unwrap();
    }

    #[test]
    fn bad_package_name() {
        for bad in ["X11", "-x", "a", "a b", "a_b", "", "a;b"] {
            let mut a = testnav();
            a.packages = vec![bad.into()];
            assert_eq!(code(&a), ("deb_packages_invalid", "packages"), "{bad:?}");
        }
        for ok in ["x11-utils", "libstdc++6", "python3.12", "0ad"] {
            assert!(package_name_ok(ok), "{ok}");
        }
    }

    #[test]
    fn thirty_three_packages_rejected() {
        let mut a = testnav();
        a.packages = (0..32).map(|i| format!("pkg{i}")).collect();
        check("testnav", &a).unwrap();
        a.packages.push("pkg32".into());
        assert_eq!(code(&a), ("deb_packages_invalid", "packages"));
    }

    #[test]
    fn exec_relative_rejected() {
        let mut a = testnav();
        a.exec = Some("opt/testnav/bin/testnav".into());
        assert_eq!(code(&a), ("deb_exec_invalid", "exec"));
        a.exec = Some("testnav".into());
        assert_eq!(code(&a), ("deb_exec_invalid", "exec"));
    }

    #[test]
    fn exec_dotdot_rejected() {
        for bad in [
            "/opt/../bin/sh",
            "/usr/bin/../../bin/sh",
            "/opt/x y",
            "/etc/x",
            "/opt/",
            "org.example.App",
        ] {
            let mut a = testnav();
            a.exec = Some(bad.into());
            assert_eq!(code(&a), ("deb_exec_invalid", "exec"), "{bad}");
        }
    }

    #[test]
    fn exec_opt_ok() {
        for ok in ["/opt/testnav/bin/testnav", "/usr/bin/foo"] {
            let mut a = testnav();
            a.exec = Some(ok.into());
            check("testnav", &a).unwrap();
        }
    }

    #[test]
    fn icon_shape() {
        let mut a = testnav();
        for ok in ["files/testnav.png", "https://x.example/i.png"] {
            a.icon = Some(ok.into());
            check("testnav", &a).unwrap();
        }
        for bad in ["testnav.png", "/usr/share/i.png", "http://x/i.png", ""] {
            a.icon = Some(bad.into());
            assert_eq!(code(&a), ("deb_icon_invalid", "icon"), "{bad:?}");
        }
    }

    #[test]
    fn mirror_rules() {
        for ok in [
            "http://th.archive.ubuntu.com/ubuntu",
            "https://mirror.school.ac.th/ubuntu/",
            "http://10.0.0.5:8080/ubuntu",
        ] {
            check_mirror(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in [
            "",
            "file:///srv/ubuntu",
            "ftp://x/y",
            "https://u:p@x/y",
            "http://x/a b",
        ] {
            assert!(check_mirror(bad).is_err(), "{bad:?}");
        }
        assert!(check_mirror("ftp://x")
            .unwrap_err()
            .contains("ubuntu_mirror"));
    }
}
