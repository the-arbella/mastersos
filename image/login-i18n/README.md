# Login screen text

`mastersos-login.pot` lists the login screen's own strings (`mastersos-login@mastersos.org/strings.js`); English is the source and the fallback. One `<language>.po` per language pack in `mkosi.conf`, machine-translated in one pass, no human review (design 2026-11-01). `zh-hans` is `zh_CN.po`, `zh-hant` is `zh_TW.po`. `mkosi.build` compiles them into the extension's `locale/`. `check-tree.sh` rule 50 requires every msgid in every catalogue with the same `%s`.
