//! The language of the notices and dialogs the agent shows on the laptop screen (`image/system-i18n/README.md`).
//!
//! Every such text is an English sentence, the msgid of the gettext domain [`DOMAIN`] (`image/system-i18n/
//! mastersos-system.pot`), which the system scripts share through `/usr/lib/mastersos/notice-lib`. [`text`] runs the
//! `gettext` command through the [`Runner`] with the same environment as notice-lib: `LANGUAGE` and `LC_ALL` from the
//! chosen locale ([`Locale::from_name`]; glibc ignores `LANGUAGE` in the C and C.UTF-8 locales, so `LC_ALL` is the UTF-8
//! locale of that language, and the image generates every UTF-8 locale). English, the msgid itself, whenever that does not
//! work: no language, C, a locale that is not generated, no `gettext`, no catalogue, no entry, a failure, or a translation
//! whose `%s` count differs from the msgid's.
//!
//! Which locale: a process in the person's session (the kiosk dialogs) passes its own `LANG`; the root daemon passes `None`
//! and so reads `/etc/locale.conf` ([`system_language`]), because the `LANG` systemd gave it at boot is stale once the
//! language is changed at the login screen.

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use crate::runner::{Cmd, Runner};

/// The gettext domain of the system notices (`/usr/share/locale/<lang>/LC_MESSAGES/mastersos-system.mo`).
pub const DOMAIN: &str = "mastersos-system";
pub const LOCALE_DIR: &str = "/usr/share/locale";
pub const GETTEXT: &str = "/usr/bin/gettext";
/// The system locale, under the system root.
pub const LOCALE_CONF_REL: &str = "etc/locale.conf";
/// A lookup in a local catalogue is instant; this only bounds a broken system.
const TIMEOUT: Duration = Duration::from_secs(5);
/// locale.conf is a few lines.
const MAX_LOCALE_CONF: u64 = 64 * 1024;

/// Every msgid the agent shows. `image/tests/check-tree.sh` (rule 73) requires each in `mastersos-system.pot`.
pub const AGENT_MSGIDS: [&str; 6] = [
    crate::kiosk_session::POLICY_NOT_ISOLATED,
    crate::kiosk_session::ENTER_FAILED,
    crate::kiosk_session::ENTER_CONFIRM,
    crate::login_queue::MSG_WITHHELD,
    crate::login_queue::MSG_STALE_DAYS,
    crate::upload::drain::NOTICE,
];

/// The gettext environment for one locale name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locale {
    /// `th_TH`, `sr_RS@latin`: gettext tries it, then the language alone (`pt_BR` → `pt`).
    pub language: String,
    /// `th_TH.UTF-8`, `sr_RS.UTF-8@latin`.
    pub lc_all: String,
}

impl Locale {
    /// `th_TH.UTF-8` → `th_TH` / `th_TH.UTF-8`; `sr_RS.UTF-8@latin` → `sr_RS@latin` / `sr_RS.UTF-8@latin`. `None` for C,
    /// POSIX, an empty name and anything that does not look like `ll[_CC]` (it reaches the command line).
    pub fn from_name(name: &str) -> Option<Locale> {
        let name = name.trim();
        let (rest, modifier) = match name.split_once('@') {
            Some((r, m)) => (r, m),
            None => (name, ""),
        };
        let base = rest.split('.').next().unwrap_or("");
        let (lang, country) = match base.split_once('_') {
            Some((l, c)) => (l, Some(c)),
            None => (base, None),
        };
        let lang_ok = (2..=3).contains(&lang.len()) && lang.bytes().all(|b| b.is_ascii_lowercase());
        let country_ok =
            country.is_none_or(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()));
        if !lang_ok || !country_ok || !modifier.bytes().all(|b| b.is_ascii_lowercase()) {
            return None;
        }
        let at = if modifier.is_empty() {
            String::new()
        } else {
            format!("@{modifier}")
        };
        Some(Locale {
            language: format!("{base}{at}"),
            lc_all: format!("{base}.UTF-8{at}"),
        })
    }
}

/// `LANG=` of `<root>/etc/locale.conf` (quotes removed), if any.
pub fn conf_lang(root: &Path) -> Option<String> {
    let mut s = String::new();
    std::fs::File::open(root.join(LOCALE_CONF_REL))
        .and_then(|f| f.take(MAX_LOCALE_CONF).read_to_string(&mut s))
        .ok()?;
    s.lines()
        .find_map(|l| l.strip_prefix("LANG="))
        .map(|v| v.trim().trim_matches(|c| c == '"' || c == '\'').to_string())
        .filter(|v| !v.is_empty())
}

/// The locale for a notice: `env_lang` when it is set and not empty, else `<root>/etc/locale.conf`; `None` = English.
pub fn system_language(env_lang: Option<&str>, root: &Path) -> Option<Locale> {
    match env_lang.map(str::trim).filter(|l| !l.is_empty()) {
        Some(l) => Locale::from_name(l),
        None => conf_lang(root).as_deref().and_then(Locale::from_name),
    }
}

/// The `gettext` command for `msgid` in `locale`.
pub fn gettext_cmd(locale: &Locale, msgid: &str) -> Cmd {
    let language = format!("LANGUAGE={}", locale.language);
    let lc_all = format!("LC_ALL={}", locale.lc_all);
    let domain = format!("TEXTDOMAIN={DOMAIN}");
    let dir = format!("TEXTDOMAINDIR={LOCALE_DIR}");
    Cmd::new(
        "/usr/bin/env",
        &[
            lc_all.as_str(),
            language.as_str(),
            domain.as_str(),
            dir.as_str(),
            GETTEXT,
            "--",
            msgid,
        ],
    )
    .timeout(TIMEOUT)
}

/// `msgid` translated into `locale` (see the module documentation); `msgid` itself when that is not possible.
pub fn text(runner: &dyn Runner, locale: Option<&Locale>, msgid: &str) -> String {
    let Some(locale) = locale else {
        return msgid.to_string();
    };
    match runner.run(&gettext_cmd(locale, msgid)) {
        Ok(o) if o.code == 0 => {
            let t = o.stdout.trim_end_matches('\n');
            if t.is_empty() || t.matches("%s").count() != msgid.matches("%s").count() {
                msgid.to_string()
            } else {
                t.to_string()
            }
        }
        Ok(o) => {
            log::info!(
                "gettext exited with {}; the notice stays in English",
                o.code
            );
            msgid.to_string()
        }
        Err(e) => {
            log::info!("gettext did not run ({e:#}); the notice stays in English");
            msgid.to_string()
        }
    }
}

/// [`text`] of a msgid with one `%s`, then `arg` in its place (`arg` itself is not looked at for `%s`).
pub fn text1(runner: &dyn Runner, locale: Option<&Locale>, msgid: &str, arg: &str) -> String {
    text(runner, locale, msgid).replacen("%s", arg, 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::{FakeRunner, Output};

    const MSG: &str = "The web browser is not installed yet.";

    fn loc(name: &str) -> Locale {
        Locale::from_name(name).unwrap()
    }

    #[test]
    fn locale_names() {
        assert_eq!(
            loc("th_TH.UTF-8"),
            Locale {
                language: "th_TH".into(),
                lc_all: "th_TH.UTF-8".into()
            }
        );
        assert_eq!(loc("zh_CN.utf8").language, "zh_CN");
        assert_eq!(loc("zh_TW.UTF-8").lc_all, "zh_TW.UTF-8");
        assert_eq!(loc("pt_BR").lc_all, "pt_BR.UTF-8");
        assert_eq!(loc("ast_ES.UTF-8").language, "ast_ES");
        let sr = loc("sr_RS.UTF-8@latin");
        assert_eq!(
            (sr.language.as_str(), sr.lc_all.as_str()),
            ("sr_RS@latin", "sr_RS.UTF-8@latin")
        );
        assert_eq!(loc("de").lc_all, "de.UTF-8");
        for bad in [
            "",
            "C",
            "C.UTF-8",
            "POSIX",
            "en_us",
            "th_TH;rm",
            "-n",
            "x",
            "abcd_EF",
            "th_THA",
            "sr_RS@La tin",
        ] {
            assert_eq!(Locale::from_name(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn locale_choice_env_first_then_locale_conf() {
        let root = tempfile::tempdir().unwrap();
        // no locale.conf, no LANG: English
        assert_eq!(system_language(None, root.path()), None);
        assert_eq!(system_language(Some(""), root.path()), None);
        std::fs::create_dir_all(root.path().join("etc")).unwrap();
        std::fs::write(
            root.path().join(LOCALE_CONF_REL),
            "LC_TIME=\"de_DE.UTF-8\"\nLANG=\"th_TH.UTF-8\"\n",
        )
        .unwrap();
        assert_eq!(system_language(None, root.path()), Some(loc("th_TH.UTF-8")));
        assert_eq!(
            system_language(Some("  "), root.path()),
            Some(loc("th_TH.UTF-8"))
        );
        // the session's LANG wins, even when it means English
        assert_eq!(
            system_language(Some("zh_CN.UTF-8"), root.path()),
            Some(loc("zh_CN.UTF-8"))
        );
        assert_eq!(system_language(Some("C.UTF-8"), root.path()), None);
        std::fs::write(root.path().join(LOCALE_CONF_REL), "LANG=C.UTF-8\n").unwrap();
        assert_eq!(system_language(None, root.path()), None);
    }

    #[test]
    fn gettext_gets_the_locale_and_the_domain() {
        let r = FakeRunner::new();
        r.respond("/usr/bin/env", Output::ok("ยังไม่ได้ติดตั้งเว็บเบราว์เซอร์"));
        assert_eq!(
            text(&r, Some(&loc("th_TH.UTF-8")), MSG),
            "ยังไม่ได้ติดตั้งเว็บเบราว์เซอร์"
        );
        assert_eq!(
            r.calls(),
            [format!(
                "/usr/bin/env LC_ALL=th_TH.UTF-8 LANGUAGE=th_TH TEXTDOMAIN=mastersos-system \
                 TEXTDOMAINDIR=/usr/share/locale /usr/bin/gettext -- {MSG}"
            )]
        );
    }

    #[test]
    fn english_without_a_language_runs_nothing() {
        let r = FakeRunner::new();
        assert_eq!(text(&r, None, MSG), MSG);
        assert!(r.calls().is_empty());
    }

    #[test]
    fn falls_back_to_english() {
        let th = loc("th_TH.UTF-8");
        // no translation (gettext prints the msgid), empty output, failure, a command that does not start
        let r = FakeRunner::new();
        r.respond("/usr/bin/env", Output::ok(MSG));
        assert_eq!(text(&r, Some(&th), MSG), MSG);
        let r = FakeRunner::new();
        assert_eq!(text(&r, Some(&th), MSG), MSG);
        let r = FakeRunner::new();
        r.respond(
            "/usr/bin/env",
            Output::fail(127, "env: '/usr/bin/gettext': No such file"),
        );
        assert_eq!(text(&r, Some(&th), MSG), MSG);
        struct Broken;
        impl Runner for Broken {
            fn run(&self, _: &Cmd) -> anyhow::Result<crate::runner::Output> {
                anyhow::bail!("/usr/bin/env could not be started")
            }
        }
        assert_eq!(text(&Broken, Some(&th), MSG), MSG);
    }

    #[test]
    fn placeholders_survive() {
        let th = loc("th_TH.UTF-8");
        let id = "This will end your session and open %s in locked mode.";
        let r = FakeRunner::new();
        r.respond("/usr/bin/env", Output::ok("จะเปิด %s\n"));
        assert_eq!(text1(&r, Some(&th), id, "Quiz %s <b>"), "จะเปิด Quiz %s <b>");
        // a catalogue that lost (or doubled) the %s is not used
        for bad in ["จะเปิด", "%s %s"] {
            let r = FakeRunner::new();
            r.respond("/usr/bin/env", Output::ok(bad));
            assert_eq!(
                text1(&r, Some(&th), id, "Quiz"),
                "This will end your session and open Quiz in locked mode."
            );
        }
    }
}
