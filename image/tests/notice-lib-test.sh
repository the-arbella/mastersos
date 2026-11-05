#!/bin/bash
# notice-lib (system-i18n/README.md): the locale choice (LANG, else /etc/locale.conf), the gettext environment, the English
# fallbacks, and interface-denied on top of it. With msgfmt, gettext and a generated th_TH.UTF-8 / zh_CN.UTF-8 locale it
# also looks the real catalogues up through the real gettext (skipped otherwise). No root, no VM:
#   bash image/tests/notice-lib-test.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
lib=$here/../mkosi.extra/usr/lib/mastersos/notice-lib
si=$here/../system-i18n
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0 n=0
check() { # check <name> <want> <got>
	n=$((n + 1))
	if [ "$2" = "$3" ]; then
		echo "ok   $1"
	else
		printf 'FAIL %s: want %q, got %q\n' "$1" "$2" "$3" >&2
		fails=$((fails + 1))
	fi
}

bin=$tmp/bin
mkdir -p "$bin"
# gettext stub: records its environment and arguments; GT_OUT, when set, is its answer (else the msgid)
cat >"$bin/gettext" <<'EOF'
#!/bin/bash
printf '%s|%s|%s|%s|%s\n' "$LANGUAGE" "$LC_ALL" "$TEXTDOMAIN" "$TEXTDOMAINDIR" "$*" >>"$GT_LOG"
[ "$1" = -- ] && shift
printf '%s' "${GT_OUT-$1}"
EOF
chmod +x "$bin/gettext"
export GT_LOG=$tmp/gt.log MASTERSOS_GETTEXT=$bin/gettext MASTERSOS_LOCALE_CONF=$tmp/locale.conf
unset LANG LANGUAGE LC_ALL
# shellcheck source-path=SCRIPTDIR source=../mkosi.extra/usr/lib/mastersos/notice-lib
. "$lib"
msg='The web browser is not installed yet.'

# notice_locale
for c in 'th_TH.UTF-8:th_TH th_TH.UTF-8' 'zh_CN.utf8:zh_CN zh_CN.UTF-8' 'zh_TW:zh_TW zh_TW.UTF-8' 'pt_BR.UTF-8:pt_BR pt_BR.UTF-8' \
	'ast_ES.UTF-8:ast_ES ast_ES.UTF-8' 'sr_RS.UTF-8@latin:sr_RS@latin sr_RS.UTF-8@latin' 'de:de de.UTF-8'; do
	check "notice_locale ${c%%:*}" "${c#*:}" "$(notice_locale "${c%%:*}")"
done
for bad in '' C C.UTF-8 POSIX en_us 'th_TH;x' -n abcd_EF 'sr_RS@La tin'; do
	check "notice_locale '$bad' fails" 1 "$(notice_locale "$bad" >/dev/null && echo 0 || echo 1)"
done

# notice_lang: LANG, else locale.conf (quotes removed), else nothing
check "no LANG, no locale.conf" "" "$(notice_lang)"
printf 'LC_TIME="de_DE.UTF-8"\nLANG="th_TH.UTF-8"\n' >"$MASTERSOS_LOCALE_CONF"
check "locale.conf" th_TH.UTF-8 "$(notice_lang)"
check "LANG wins" zh_CN.UTF-8 "$(LANG=zh_CN.UTF-8 notice_lang)"
rm -f "$MASTERSOS_LOCALE_CONF"

# notice_text
: >"$GT_LOG"
check "no language: English" "$msg" "$(notice_text "$msg")"
check "no language: gettext not run" 0 "$(wc -l <"$GT_LOG" | tr -d ' ')"
check "C.UTF-8: English, gettext not run" "$msg 0" "$(LANG=C.UTF-8 notice_text "$msg") $(wc -l <"$GT_LOG" | tr -d ' ')"
check "th: the translation" 'ยังไม่ได้ติดตั้งเว็บเบราว์เซอร์' "$(LANG=th_TH.UTF-8 GT_OUT='ยังไม่ได้ติดตั้งเว็บเบราว์เซอร์' notice_text "$msg")"
check "th: gettext's environment and arguments" "th_TH|th_TH.UTF-8|mastersos-system|/usr/share/locale|-- $msg" "$(tail -n1 "$GT_LOG")"
printf 'LANG=zh_CN.UTF-8\n' >"$MASTERSOS_LOCALE_CONF"
LANG='' notice_text "$msg" >/dev/null
check "empty LANG: locale.conf's language" "zh_CN|zh_CN.UTF-8" "$(tail -n1 "$GT_LOG" | cut -d'|' -f1-2)"
check "TEXTDOMAINDIR override" /x "$(MASTERSOS_TEXTDOMAINDIR=/x notice_text "$msg" >/dev/null && tail -n1 "$GT_LOG" | cut -d'|' -f4)"
rm -f "$MASTERSOS_LOCALE_CONF"
check "msgid starting with a dash" "-n" "$(LANG=th_TH.UTF-8 notice_text -n)"
check "empty answer: English" "$msg" "$(LANG=th_TH.UTF-8 GT_OUT='' notice_text "$msg")"
check "no gettext: English" "$msg" "$(LANG=th_TH.UTF-8 MASTERSOS_GETTEXT=$tmp/none notice_text "$msg")"
check "failing gettext: English" "$msg" "$(LANG=th_TH.UTF-8 MASTERSOS_GETTEXT=/bin/false notice_text "$msg")"
p='This will end your session and open %s in locked mode.'
check "placeholder kept" 'เปิด %s' "$(LANG=th_TH.UTF-8 GT_OUT='เปิด %s' notice_text "$p")"
check "placeholder lost: English" "$p" "$(LANG=th_TH.UTF-8 GT_OUT='เปิด' notice_text "$p")"
check "placeholder doubled: English" "$p" "$(LANG=th_TH.UTF-8 GT_OUT='%s %s' notice_text "$p")"

# interface-denied: the stub's notification and stderr, exit 126
cat >"$bin/notify-send" <<'EOF'
#!/bin/bash
printf '%s\n' "${@: -1}" >>"$NS_LOG"
EOF
chmod +x "$bin/notify-send"
rc=0
err=$(env PATH="$bin:$PATH" NS_LOG="$tmp/ns.log" MASTERSOS_NOTICE_LIB="$lib" LANG=th_TH.UTF-8 GT_OUT='แอปนี้ใช้ไม่ได้' \
	bash "$here/../mkosi.extra/usr/lib/mastersos/interface-denied" 2>&1 >/dev/null) || rc=$?
check "interface-denied: exit 126" 126 "$rc"
check "interface-denied: translated notification" 'แอปนี้ใช้ไม่ได้' "$(cat "$tmp/ns.log")"
check "interface-denied: same text on stderr" 'แอปนี้ใช้ไม่ได้' "$err"
check "interface-denied: msgid" "th_TH|-- This app is not available on this device" "$(tail -n1 "$GT_LOG" | cut -d'|' -f1,5)"
: >"$tmp/ns.log"
env PATH="$bin:$PATH" NS_LOG="$tmp/ns.log" MASTERSOS_NOTICE_LIB="$tmp/none" LANG=th_TH.UTF-8 \
	bash "$here/../mkosi.extra/usr/lib/mastersos/interface-denied" 2>/dev/null || :
check "interface-denied without notice-lib: English" 'This app is not available on this device' "$(cat "$tmp/ns.log")"

# the real gettext and the real catalogues
real=/usr/bin/gettext
if [ -x "$real" ] && command -v msgfmt >/dev/null && locale -a 2>/dev/null | grep -qix 'th_TH.utf8' &&
	locale -a 2>/dev/null | grep -qix 'zh_CN.utf8'; then
	for l in th zh_CN zh_TW pt; do
		mkdir -p "$tmp/locale/$l/LC_MESSAGES"
		msgfmt --check -o "$tmp/locale/$l/LC_MESSAGES/mastersos-system.mo" "$si/$l.po"
	done
	want() { # want <po> <msgid>: the msgstr of <msgid> in <po>
		awk -v id="msgid \"$2\"" '$0 == id { getline; sub(/^msgstr "/, ""); sub(/"$/, ""); print; exit }' "$si/$1.po"
	}
	export MASTERSOS_GETTEXT=$real MASTERSOS_TEXTDOMAINDIR=$tmp/locale
	check "real: th" "$(want th "$msg")" "$(LANG=th_TH.UTF-8 notice_text "$msg")"
	check "real: zh_CN from locale.conf" "$(want zh_CN "$msg")" "$(printf 'LANG=zh_CN.UTF-8\n' >"$MASTERSOS_LOCALE_CONF" && notice_text "$msg")"
	rm -f "$MASTERSOS_LOCALE_CONF"
	check "real: %s survives" "$(want th "$p")" "$(LANG=th_TH.UTF-8 notice_text "$p")"
	check "real: no entry -> English" "Not a msgid." "$(LANG=th_TH.UTF-8 notice_text 'Not a msgid.')"
	if locale -a 2>/dev/null | grep -qix 'pt_BR.utf8'; then
		check "real: pt_BR falls back to pt.po" "$(want pt "$msg")" "$(LANG=pt_BR.UTF-8 notice_text "$msg")"
	fi
	if ! locale -a 2>/dev/null | grep -qix 'de_DE.utf8'; then
		check "real: a locale that is not generated -> English" "$msg" "$(LANG=de_DE.UTF-8 notice_text "$msg")"
	fi
else
	echo "skip real gettext (needs /usr/bin/gettext, msgfmt and the th_TH.UTF-8 and zh_CN.UTF-8 locales)"
fi

echo "notice-lib-test: $((n - fails))/$n passed"
[ "$fails" = 0 ]
