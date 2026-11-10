#!/bin/bash
# Tests for the exam-quiet ExecCondition= of the download services (exam-quiet Task 7). No VM, no root.
# The exact command string is taken from each unit file and run through /bin/sh with a stub `systemctl` first on PATH:
# quiet target active -> the condition fails (exit non-zero, the service does not start); inactive -> exit 0.
#   bash image/tests/quiet-units-test.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
units=$here/../mkosi.extra/usr/lib/systemd/system
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0

check() { # check <name> <want> <got>
	if [ "$2" = "$3" ]; then
		echo "ok   $1"
	else
		echo "FAIL $1: want '$2', got '$3'" >&2
		fails=$((fails + 1))
	fi
}

mkdir "$tmp/bin"
cat >"$tmp/bin/systemctl" <<'STUB'
#!/bin/sh
# only `is-active --quiet mastersos-quiet.target` is expected; STUB_STATE decides the answer
[ "$1 $2 $3" = "is-active --quiet mastersos-quiet.target" ] || exit 99
[ "$STUB_STATE" = active ]
STUB
chmod +x "$tmp/bin/systemctl"

for u in mastersos-update mastersos-chrome mastersos-golden-fetch; do
	line=$(grep -E '^ExecCondition=' "$units/$u.service")
	check "$u.service has one ExecCondition" 1 "$(printf '%s\n' "$line" | wc -l)"
	cmd=${line#ExecCondition=}
	for state in active inactive; do
		rc=0
		PATH="$tmp/bin:$PATH" STUB_STATE=$state sh -c "$cmd" || rc=$?
		if [ "$state" = active ]; then
			[ "$rc" != 0 ] && rc=nonzero
			check "$u: quiet active blocks the start" nonzero "$rc"
		else
			check "$u: quiet inactive lets it start" 0 "$rc"
		fi
	done
done

[ "$fails" = 0 ] || exit 1
echo "quiet-units-test: all ok"
