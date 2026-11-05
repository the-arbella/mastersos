#!/bin/bash
# update-run fallback and staleness detection (plan 5 Task 12; runs locally and in CI, no VM needed, needs
# timeout(1)):
#   bash image/tests/update-run-test.sh
# A fake systemd-sysupdate is driven by environment variables:
#   cache side (no --definitions=):   FAKE_MIRROR_RC for update, FAKE_CACHE_NEW for check-new
#   official side (--definitions=):   FAKE_FALLBACK_RC for update, FAKE_OFFICIAL_NEW for check-new, FAKE_OFFICIAL_ERR for
# a check-new failure (message on stderr, exit 1; "none" is exit 1 with no output)
# Cases: no cache set; cache fresh; cache broken (fallback works / both fail); cache stale within the grace
# window, beyond it (fallback update plus a "school cache stale" record), and caught up again.
# Restart prompt (last section): which UKI on the ESP counts as waiting (tries left, version order), the
# /run/mastersos-update-pending file, one notification per version (loginctl / runuser / notify-send are recording stubs,
# as in integrity-test.sh), the exit code untouched, and `update-run --remind` (the user unit's notification).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
var=$tmp/var
mkdir -p "$var"
fake=$tmp/sysupdate
cat >"$fake" <<'SH'
#!/bin/bash
echo "$*" >>"$FAKE_LOG"
official=0
verb=${*: -1}
[[ "${1:-}" == --definitions=* ]] && official=1
if [ "$verb" = check-new ]; then
	if [ "$official" = 1 ]; then v=${FAKE_OFFICIAL_NEW:-}; else v=${FAKE_CACHE_NEW:-}; fi
	[ -n "$v" ] && echo "$v" && exit 0
	# Real check-new: errors print a message on stderr; "no candidate" is silent. Both exit 1.
	# Info-level progress also goes to stderr unless the log level is raised.
	[ "${SYSTEMD_LOG_LEVEL:-info}" = warning ] || echo "Determining installed update sets..." >&2
	if [ "$official" = 1 ] && [ -n "${FAKE_OFFICIAL_ERR:-}" ]; then echo "Failed to download: $FAKE_OFFICIAL_ERR" >&2; fi
	exit 1
fi
if [ "$official" = 1 ]; then
	exit "${FAKE_FALLBACK_RC:-0}"
fi
exit "${FAKE_MIRROR_RC:-0}"
SH
chmod +x "$fake"
export MASTERSOS_SYSUPDATE=$fake MASTERSOS_SYSTEM_VAR=$var FAKE_LOG=$tmp/log
# no transfers anywhere: every update takes the direct path (staging: tests/update-run-staged-test.sh)
export MASTERSOS_SYSUPDATE_DIRS=$tmp/no-transfers
# restart prompt: an empty ESP until the last section, which tests it
export MASTERSOS_UPDATE_PENDING=$tmp/run/update-pending MASTERSOS_BOOT_PATH=$tmp/boot MASTERSOS_IMAGE_VERSION=20261105.9
mkdir -p "$tmp/run" "$tmp/boot/EFI/Linux"

fails=0
check() { # check <name> <expected> <actual>
	if [ "$2" = "$3" ]; then
		echo "ok   $1 → $3"
	else
		echo "FAIL ${1}: expected '$2', got '$3'" >&2
		fails=$((fails + 1))
	fi
}
istrue() { # istrue <name> <command...>: passes when the command succeeds
	local name=$1
	shift
	if "$@"; then
		echo "ok   $name"
	else
		echo "FAIL ${name}" >&2
		fails=$((fails + 1))
	fi
}
absent() { # absent <name> <path>
	if [ ! -e "$2" ]; then
		echo "ok   $1"
	else
		echo "FAIL ${1}: $2 still exists" >&2
		fails=$((fails + 1))
	fi
}
# run <cache update rc> <fallback update rc>; prints "<exit code>|<update calls>" (check-new calls not counted)
run() {
	: >"$FAKE_LOG"
	local rc=0
	FAKE_MIRROR_RC=$1 FAKE_FALLBACK_RC=$2 "$here/../mkosi.extra/usr/lib/mastersos/update-run" 2>/dev/null || rc=$?
	echo "$rc|$(grep -c 'update$' "$FAKE_LOG" || true)"
}
rec() { cat "$var/update-mirror-failed" 2>/dev/null || echo "<none>"; }
contains() { # contains <name> <text> <needle>
	case $2 in *"$3"*) echo "ok   $1" ;; *)
		echo "FAIL ${1}: '$2' lacks '$3'" >&2
		fails=$((fails + 1))
		;;
	esac
}

# --- no cache set
check "no cache: failure returned as is, one call" "1|1" "$(run 1 0)"
absent "no cache: no record written" "$var/update-mirror-failed"
check "no cache: no check-new" "1" "$(wc -l <"$FAKE_LOG" | tr -d ' ')"

mkdir -p "$var/sysupdate-fallback.d"
touch "$var/sysupdate-fallback.d/12-usr.transfer"

# --- cache broken
echo old >"$var/update-mirror-failed"
check "cache broken, fallback works: two calls, returns 0" "0|2" "$(run 1 0)"
check "fallback call carries --definitions=<fallback dir>" "--definitions=$var/sysupdate-fallback.d update" "$(grep -- '--definitions=.* update$' "$FAKE_LOG" | head -1)"
contains "record: cache not used" "$(rec)" "school cache not used: sysupdate exit code 1; this round updated from the official source"
absent "record leaves no temporary file" "$var/update-mirror-failed.tmp"
check "both broken: second exit code returned" "7|2" "$(run 1 7)"
contains "record is neutral when both fail" "$(rec)" "both the school cache and the official source failed: cache exit code 1, official exit code 7"
check "timeout (124) on the cache is a cache failure" "0|2" "$(run 124 0)"

# --- cache fresh
echo old >"$var/update-mirror-failed"
check "cache fresh: one update call" "0|1" "$(run 0 1)"
absent "cache fresh: stale record deleted" "$var/update-mirror-failed"
absent "cache fresh: no stale-since" "$var/update-mirror-stale-since"

# --- cache behind the official source
export FAKE_OFFICIAL_NEW=20261020.1 FAKE_CACHE_NEW=
export MASTERSOS_MIRROR_GRACE=3600
check "stale, first seen: cache update only, returns 0" "0|1" "$(run 0 0)"
if [ -s "$var/update-mirror-stale-since" ]; then
	echo "ok   stale-since written"
else
	echo "FAIL stale-since missing" >&2
	fails=$((fails + 1))
fi
absent "stale within grace: no record" "$var/update-mirror-failed"
first=$(cat "$var/update-mirror-stale-since")
check "stale within grace: still one update call" "0|1" "$(run 0 0)"
check "stale-since not moved" "$first" "$(cat "$var/update-mirror-stale-since")"
absent "stale within grace: still no record" "$var/update-mirror-failed"
echo $(($(date +%s) - 7200)) >"$var/update-mirror-stale-since"
check "stale beyond grace: cache update then fallback update" "0|2" "$(run 0 0)"
contains "stale record" "$(rec)" "school cache stale: official has 20261020.1, cache offers nothing newer than installed"
FAKE_CACHE_NEW=20261019.2 run 0 0 >/dev/null
contains "stale record names the cache's version" "$(rec)" "official has 20261020.1, cache offers 20261019.2"
check "stale beyond grace, fallback update fails: exit code returned" "5|2" "$(run 0 5)"
contains "stale record notes the failed official update" "$(rec)" "update from the official source failed (exit code 5)"

# F2: the stale record survives rounds in which the cache is still behind (grace not yet expired)
date +%s >"$var/update-mirror-stale-since"
run 0 0 >/dev/null
contains "stale record kept while the cache is still frozen" "$(rec)" "school cache stale"

# F1: an unknown answer (check-new fails) touches neither stale-since nor the record
export FAKE_OFFICIAL_NEW='' FAKE_OFFICIAL_ERR=timeout
echo $(($(date +%s) - 7200)) >"$var/update-mirror-stale-since"
before=$(cat "$var/update-mirror-stale-since")
check "unknown: one update call, returns 0" "0|1" "$(run 0 0)"
check "unknown: stale-since not reset" "$before" "$(cat "$var/update-mirror-stale-since")"
contains "unknown: stale record kept" "$(rec)" "school cache stale"
istrue "unknown-since written" test -s "$var/update-mirror-unknown-since"

# definitive "none" clears stale-since, unknown-since and the stale record
export FAKE_OFFICIAL_ERR=''
check "cache caught up: one update call" "0|1" "$(run 0 0)"
absent "cache caught up: stale-since cleared" "$var/update-mirror-stale-since"
absent "cache caught up: unknown-since cleared" "$var/update-mirror-unknown-since"
absent "cache caught up: record cleared" "$var/update-mirror-failed"

# F1: unknown for over 24 h with a working cache is reported
export FAKE_OFFICIAL_ERR="DNS failure"
run 0 0 >/dev/null
absent "unknown, first round: no record yet" "$var/update-mirror-failed"
echo $(($(date +%s) - 90000)) >"$var/update-mirror-unknown-since"
check "unknown over 24h: returns 0" "0|1" "$(run 0 0)"
contains "unknown over 24h: record" "$(rec)" "school cache: freshness unknown for over 24h (official source unreachable)"
# a definitive answer (newer here) clears unknown-since and its record
export FAKE_OFFICIAL_ERR='' FAKE_OFFICIAL_NEW=20261020.1
run 0 0 >/dev/null
absent "definitive answer clears unknown-since" "$var/update-mirror-unknown-since"
absent "definitive answer clears the unknown record" "$var/update-mirror-failed"

# F3: clock set back / garbage in the timestamp files
rm -f "$var/update-mirror-stale-since"
echo $(($(date +%s) + 100000)) >"$var/update-mirror-stale-since"
run 0 0 >/dev/null
istrue "future stale-since rewritten" test "$(cat "$var/update-mirror-stale-since")" -le "$(date +%s)"
echo garbage >"$var/update-mirror-stale-since"
run 0 0 >/dev/null
contains "garbage stale-since rewritten" "x$(cat "$var/update-mirror-stale-since")x" "x1"
export FAKE_OFFICIAL_NEW='' FAKE_OFFICIAL_ERR=down
echo $(($(date +%s) + 100000)) >"$var/update-mirror-unknown-since"
run 0 0 >/dev/null
istrue "future unknown-since rewritten" test "$(cat "$var/update-mirror-unknown-since")" -le "$(date +%s)"
absent "future unknown-since: no premature record" "$var/update-mirror-failed"
export FAKE_OFFICIAL_ERR=''

# --- restart prompt
bin=$tmp/bin
mkdir -p "$bin"
cat >"$bin/loginctl" <<'EOF'
#!/bin/bash
case $1 in
list-sessions) cat "$SESSIONS_FILE" 2>/dev/null || true ;;
show-session) sed -n "s/^$2: //p" "$SESSION_INFO" | tr ' ' '\n' ;;
esac
EOF
# runuser stub: runuser -u USER -- CMD... runs CMD (the notify stub) without switching user
printf '#!/bin/bash\nshift 3\nexec "$@"\n' >"$bin/runuser"
# shellcheck disable=SC2016 # the stub is written from single-quoted text on purpose
printf '#!/bin/bash\nprintf "%%s|" "${DBUS_SESSION_BUS_ADDRESS:-}" "$@" >>"$NOTIFY_LOG"\necho >>"$NOTIFY_LOG"\n' >"$bin/notify-send"
printf '#!/bin/bash\nexec sleep 30\n' >"$bin/notify-hang"
printf '#!/bin/bash\nexit 3\n' >"$bin/notify-fail"
# gettext stub: shows the environment notice-lib gave it around the msgid (notice-lib-test.sh runs the real one)
# shellcheck disable=SC2016 # the stub is written from single-quoted text on purpose
printf '#!/bin/bash\n[ "$1" = -- ] && shift\nprintf "[%%s %%s %%s %%s] %%s" "$LANGUAGE" "$LC_ALL" "$TEXTDOMAIN" "$TEXTDOMAINDIR" "$1"\n' >"$bin/gettext"
chmod +x "$bin"/*
export MASTERSOS_LOGINCTL=$bin/loginctl MASTERSOS_RUNUSER=$bin/runuser MASTERSOS_NOTIFY=$bin/notify-send
export NOTIFY_LOG=$tmp/notify.log SESSIONS_FILE=$tmp/sessions SESSION_INFO=$tmp/session-info
export MASTERSOS_LOCALE_CONF=$tmp/locale.conf
export MASTERSOS_NOTICE_LIB=$here/../mkosi.extra/usr/lib/mastersos/notice-lib MASTERSOS_GETTEXT=$bin/gettext
printf 'c1 120 gdm seat0\n2 1000 alice seat0 tty2\n' >"$SESSIONS_FILE"
printf 'c1: Active=yes Type=wayland Class=greeter Name=gdm User=120\n2: Active=yes Type=wayland Class=user Name=alice User=1000\n' >"$SESSION_INFO"
unset LANG
want_en="A system update is ready. Restart the computer to finish installing it."
# a fresh state directory: no school cache (the cache path has its own case below)
export MASTERSOS_SYSTEM_VAR=$tmp/var2
mkdir -p "$MASTERSOS_SYSTEM_VAR"
p=$MASTERSOS_UPDATE_PENDING
esp=$tmp/boot/EFI/Linux
uki() { for n in "$@"; do : >"$esp/MastersOS_$n.efi"; done; }
noukis() { rm -f "$esp"/*.efi; }
# prun [cache rc]: one round; prints the exit code
prun() {
	local rc=0
	FAKE_MIRROR_RC=${1:-0} FAKE_FALLBACK_RC=0 "$here/../mkosi.extra/usr/lib/mastersos/update-run" 2>>"$tmp/prompt.err" || rc=$?
	echo "$rc"
}
pend() { cat "$p" 2>/dev/null || echo "<none>"; }
notes() { wc -l <"$NOTIFY_LOG" 2>/dev/null | tr -d ' '; }
: >"$NOTIFY_LOG"

check "no UKIs: round returns 0" 0 "$(prun)"
absent "no UKIs: nothing pending" "$p"
uki 20261105.9_x86-64
check "only the running version: returns 0" 0 "$(prun)"
absent "only the running version: nothing pending" "$p"
check "only the running version: no notification" 0 "$(notes)"

uki 20261106.1_x86-64+3-0
check "failed round: exit code kept" 1 "$(prun 1)"
absent "failed round: no prompt written" "$p"
check "newer +3-0: returns 0" 0 "$(prun)"
check "newer +3-0: pending version" 20261106.1 "$(pend)"
check "pending file: exactly '<version>\\n'" "$(printf '20261106.1\n' | od -c)" "$(od -c <"$p")"
check "pending file: mode 0644" 644 "$(stat -c %a "$p")"
absent "pending file: no temporary file left" "$p.tmp"
check "newer: one notification" 1 "$(notes)"
check "notification: English, MastersOS title, session bus of the active user session (not the greeter)" \
	"unix:path=/run/user/1000/bus|--app-name=MastersOS|--urgency=normal|MastersOS|$want_en|" "$(tr -d '\n' <"$NOTIFY_LOG")"
check "same version next round: returns 0" 0 "$(prun)"
check "same version next round: no second notification" 1 "$(notes)"

noukis
uki 20261105.9_x86-64+2-1 20261106.1_x86-64+0-3
check "newer +0-3 (rolled back from): returns 0" 0 "$(prun)"
absent "newer +0-3: file removed, nothing pending" "$p"
check "newer +0-3: no notification" 1 "$(notes)"

noukis
uki 20261105.9_x86-64 20261106.2_x86-64
prun >/dev/null
check "newer without boot counter: pending" 20261106.2 "$(pend)"
check "new version: notified again" 2 "$(notes)"

noukis
uki 20261105.9_x86-64 20261106.3_x86-64+3 20261107.1_x86-64+1-2 20261106.4_x86-64+3-0
prun >/dev/null
check "several newer (+3, +1-2, +3-0): the highest wins" 20261107.1 "$(pend)"
noukis
uki 20261107.1_x86-64+0-3 20261106.4_x86-64+3-0
prun >/dev/null
check "highest used up its tries: the next one that can boot" 20261106.4 "$(pend)"

noukis
uki 20261105.9_x86-64+3-0 20261105.10_x86-64+3-0
prun >/dev/null
check "20261105.10 is newer than the running 20261105.9 (N compared as a number)" 20261105.10 "$(pend)"
noukis
uki 20261105.8_x86-64+3-0 20261105.10_x86-64
MASTERSOS_IMAGE_VERSION=20261105.10 prun >/dev/null
absent "running 20261105.10, 20261105.8 waiting: older, nothing pending" "$p"
noukis
uki 20261106.1_aarch64+3-0 20261106.1_x86-64.efi.part 2026110.1_x86-64 X_20261106.1_x86-64
prun >/dev/null
absent "names that are not this transfer's UKIs are ignored" "$p"
noukis
uki 20261106.5_x86-64+3-0
check "running version unreadable: round still returns 0" 0 "$(MASTERSOS_IMAGE_VERSION=garbage prun)"
absent "running version unreadable: no prompt" "$p"

# the language: LANG first, then /etc/locale.conf
: >"$NOTIFY_LOG"
LANG=zh_CN.UTF-8 prun >/dev/null
check "LANG=zh_CN.UTF-8: gettext asked in zh_CN" "[zh_CN zh_CN.UTF-8 mastersos-system /usr/share/locale] $want_en" "$(cut -d'|' -f5 "$NOTIFY_LOG")"
rm -f "$p"
: >"$NOTIFY_LOG"
printf 'LANG="th_TH.UTF-8"\n' >"$MASTERSOS_LOCALE_CONF"
prun >/dev/null
check "/etc/locale.conf th: gettext asked in th_TH" "[th_TH th_TH.UTF-8 mastersos-system /usr/share/locale] $want_en" "$(cut -d'|' -f5 "$NOTIFY_LOG")"
rm -f "$p"
: >"$NOTIFY_LOG"
MASTERSOS_GETTEXT=$tmp/no-gettext prun >/dev/null
check "no gettext: English" "$want_en" "$(cut -d'|' -f5 "$NOTIFY_LOG")"
rm -f "$p"
: >"$NOTIFY_LOG"
MASTERSOS_NOTICE_LIB=$tmp/no-lib prun >/dev/null
check "no notice-lib: English" "$want_en" "$(cut -d'|' -f5 "$NOTIFY_LOG")"
rm -f "$MASTERSOS_LOCALE_CONF"

# the prompt can never fail a round
rm -f "$p"
: >"$NOTIFY_LOG"
start=$SECONDS
check "hung notify-send: returns 0" 0 "$(MASTERSOS_NOTIFY=$bin/notify-hang MASTERSOS_NOTIFY_TIMEOUT=1 prun)"
istrue "hung notify-send: cut off within 10 s" test $((SECONDS - start)) -lt 10
check "hung notify-send: file written first" 20261106.5 "$(pend)"
rm -f "$p"
check "failing notify-send: returns 0" 0 "$(MASTERSOS_NOTIFY=$bin/notify-fail prun)"
rm -f "$p"
check "no active session: returns 0" 0 "$(SESSIONS_FILE=$tmp/none prun)"
check "no active session: still pending" 20261106.5 "$(pend)"
check "unwritable pending path: returns 0" 0 "$(MASTERSOS_UPDATE_PENDING=$tmp/no-such-dir/pending prun)"
check "unwritable pending path: failed round still returns its own code" 1 "$(MASTERSOS_UPDATE_PENDING=$tmp/no-such-dir/pending prun 1)"
contains "unwritable pending path: says so" "$(cat "$tmp/prompt.err")" "update-run: cannot write $tmp/no-such-dir/pending"

# the school cache path: a round through the cache gives the prompt too
mkdir -p "$MASTERSOS_SYSTEM_VAR/sysupdate-fallback.d"
touch "$MASTERSOS_SYSTEM_VAR/sysupdate-fallback.d/12-usr.transfer"
rm -f "$p"
noukis
uki 20261105.9_x86-64 20261106.6_x86-64+3-0
check "school cache round: returns 0" 0 "$(prun)"
check "school cache round: pending" 20261106.6 "$(pend)"
rm -f "$p"
check "cache broken, official works: returns 0" 0 "$(prun 1)"
check "cache broken, official works: pending" 20261106.6 "$(pend)"
noukis
uki 20261105.9_x86-64
prun >/dev/null
absent "nothing newer any more: file removed" "$p"

# update-run --remind (the user unit): reads the file, notifies on its own session bus, never fails
remind() { # remind [env...]: exit code of update-run --remind
	local rc=0
	env "$@" "$here/../mkosi.extra/usr/lib/mastersos/update-run" --remind 2>/dev/null || rc=$?
	echo "$rc"
}
: >"$NOTIFY_LOG"
rm -f "$p"
check "remind, no file: returns 0" 0 "$(remind USER=alice)"
check "remind, no file: no notification" 0 "$(notes)"
echo 20261106.6 >"$p"
check "remind: returns 0" 0 "$(remind USER=alice DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus)"
check "remind: one notification on the user's own bus, English" \
	"unix:path=/run/user/1000/bus|--app-name=MastersOS|--urgency=normal|MastersOS|$want_en|" "$(tr -d '\n' <"$NOTIFY_LOG")"
: >"$NOTIFY_LOG"
remind USER=alice LANG=th_TH.UTF-8 >/dev/null
check "remind: LANG=th -> gettext asked in th_TH" "[th_TH th_TH.UTF-8 mastersos-system /usr/share/locale] $want_en" "$(cut -d'|' -f5 "$NOTIFY_LOG")"
: >"$NOTIFY_LOG"
remind USER=kiosk-exam >/dev/null
check "remind: locked-app account gets nothing" 0 "$(notes)"
remind USER=alice MASTERSOS_IMAGE_VERSION=20261106.6 >/dev/null
check "remind: version already running gets nothing" 0 "$(notes)"
echo 'not-a-version' >"$p"
remind USER=alice >/dev/null
check "remind: malformed file gets nothing" 0 "$(notes)"
echo 20261106.6 >"$p"
check "remind: failing notify-send still returns 0" 0 "$(remind USER=alice MASTERSOS_NOTIFY="$bin/notify-fail")"

[ "$fails" = 0 ] || exit 1
echo "update-run-test: all passed"
