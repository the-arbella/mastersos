# System notice text

`mastersos-system.pot` lists the sentences that the system itself shows on the laptop screen outside the login screen: desktop notifications and dialogs from the scripts in `mkosi.extra/usr/lib/mastersos/` (`update-run`, `integrity`, `browser-wait`, `interface-denied`) and from `mastersos-agent` (the locked-app dialogs, the stale-settings and diagnostics notices; `core/mastersos-agent/src/i18n.rs` lists its msgids in `AGENT_MSGIDS`). English is the source, the msgid and the fallback.

There is one `<language>.po` per language pack in `mkosi.conf`, the same set as `../login-i18n/` (`zh-hans` is `zh_CN.po`, `zh-hant` is `zh_TW.po`), machine-translated in one pass with no human review (design 2026-11-01). A `%s` stands for a value filled in after translation (an app name, a number of days) and must stay in every translation. `mkosi.build` compiles each catalogue to `/usr/share/locale/<language>/LC_MESSAGES/mastersos-system.mo`.

## Lookup

Scripts source `/usr/lib/mastersos/notice-lib` and call `notice_text '<English sentence>'`; the agent calls `i18n::text` (or `text1` for a sentence with `%s`). Both run `gettext` (package `gettext-base`) with `TEXTDOMAIN=mastersos-system`, `TEXTDOMAINDIR=/usr/share/locale`, `LANGUAGE=<language>[_<COUNTRY>][@<modifier>]` and `LC_ALL=<that>.UTF-8`: glibc ignores `LANGUAGE` in the C and C.UTF-8 locales, so the real locale is set too (the image generates every UTF-8 locale). gettext tries the full name and then the language alone, so `pt_BR` finds `pt.po`.

The language is `LANG` from the environment, else `LANG=` in `/etc/locale.conf`; the root daemon reads `/etc/locale.conf` only (its own `LANG` is the one it had at boot). English whenever the lookup cannot work: no language, C, a locale that is not generated, no `gettext`, no catalogue or entry, or a translation whose `%s` count differs from the msgid.

## Adding a sentence

Add the msgid to `mastersos-system.pot` (with a `#.` comment saying where it is shown) and a translation to every `.po`; `tests/check-tree.sh` rule 73 requires every msgid in every catalogue with the same `%s`, the same catalogue set as `login-i18n`, every `notice_text '...'` of the scripts and every `AGENT_MSGIDS` entry in the template, and no Chinese or Thai text in the scripts that show notices. The login screen's own text is the separate domain `mastersos-login` (`../login-i18n/`).
