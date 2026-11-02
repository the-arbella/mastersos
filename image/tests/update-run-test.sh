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

[ "$fails" = 0 ] || exit 1
echo "update-run-test: all passed"
