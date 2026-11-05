#!/usr/bin/env bash
# coredump-filter passes only the login stack and the agent (uid 0) on to systemd-coredump, with the arguments unchanged
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
f=$here/../mkosi.extra/usr/lib/mastersos/coredump-filter
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
printf '#!/bin/sh\nprintf "%%s\\n" "$@" >"%s/args"\n' "$tmp" >"$tmp/helper"
chmod +x "$tmp/helper"
fail=0
run() { # <expect pass|drop> <comm> <uid>
	rm -f "$tmp/args"
	MASTERSOS_COREDUMP_HELPER=$tmp/helper bash "$f" "$2" 1234 "$3" "$3" 11 1700000000 0 host 1 5
	if [ "$1" = pass ]; then
		if [ "$(cat "$tmp/args" 2>/dev/null | tr '\n' ' ')" != "1234 $3 $3 11 1700000000 0 host 1 5 " ]; then
			echo "FAIL: $2 uid $3 should reach systemd-coredump with its arguments unchanged"
			fail=1
		fi
	elif [ -e "$tmp/args" ]; then
		echo "FAIL: $2 uid $3 should be dropped"
		fail=1
	fi
}
for c in gdm3 gdm-session-wor authd authd-oidc mastersos-agent; do run pass "$c" 0; done
run drop chrome 1000
run drop gnome-shell 1000
run drop authd 1000
run drop gdm-session-wor 60578
run drop "Web Content" 1000
run drop chrome 0
run drop gdm 0
[ "$fail" = 0 ] && echo "coredump-filter: ok"
exit "$fail"
