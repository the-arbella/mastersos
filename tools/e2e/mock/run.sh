#!/usr/bin/env bash
# Runs tools/e2e/protocol-v1.sh against the mock server (tools/e2e/mock/server.py) with our
# real binaries, and checks its summary. Our own verification of the driving script; the
# cross-repo run against the real server belongs to the server team's runner.
#
# Usage: tools/e2e/mock/run.sh --bin-dir DIR
#   --bin-dir  holds Linux builds of `mastersos` and `mastersos-agent` (this script builds nothing)
#   E2E_AWK_ROOT  optional: a folder with mawk and gawk unpacked from their .deb files
#                 (usr/bin/{mawk,gawk}); the script's --self-test then runs under each.
#
# It runs only as the `e2e-mock` suite of .labtest.yml on the remote build runner (needs Linux,
# bash, curl, coreutils and Python 3.11 or later); it is not part of GitHub CI.
#
# Checks: the mock's own self-test against the shared vectors; protocol-v1.sh --self-test under
# the default awk (and mawk and gawk when found); then the full run: exit 0, stdout one JSON value
# with "ok":true and every step of --dry-run present and ok; and containment: the fake HOME and
# the starting folder (both read-only) are unchanged. The mock is stopped on every exit.
# Exit 0 when all pass, 1 otherwise, 2 on a usage error.
set -euo pipefail
umask 077
export LC_ALL=C

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
root=$(cd "$here/../../.." && pwd -P)
script=$root/tools/e2e/protocol-v1.sh
vectors=$root/core/mastersos-bundle/testdata

bin=""
while [[ $# -gt 0 ]]; do
	case $1 in
	--bin-dir)
		[[ $# -ge 2 ]] || { echo "run.sh: --bin-dir needs a value" >&2; exit 2; }
		bin=$2
		shift 2
		;;
	*)
		echo "usage: run.sh --bin-dir DIR" >&2
		exit 2
		;;
	esac
done
[[ -n $bin && -d $bin ]] || { echo "run.sh: --bin-dir DIR is required and must exist" >&2; exit 2; }
bin=$(cd "$bin" && pwd -P)

fails=()
fail() {
	fails+=("$1")
	echo "FAIL: $1" >&2
}
pass() { echo "ok: $1" >&2; }

for c in python3 curl bash; do
	command -v "$c" >/dev/null || { echo "run.sh: $c is required" >&2; exit 1; }
done
python3 -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' ||
	{ echo "run.sh: Python 3.11 or later is required (tomllib)" >&2; exit 1; }

t=$(mktemp -d)
mock_pid=""
cleanup() {
	if [[ -n $mock_pid ]]; then
		kill "$mock_pid" 2>/dev/null || true
		wait "$mock_pid" 2>/dev/null || true
	fi
	chmod -R u+w "$t" 2>/dev/null || true
	rm -rf -- "$t"
}
trap cleanup EXIT

# ---- 1. The mock's self-test against the shared vectors ----
if out=$(python3 -I -B "$here/server.py" --self-test "$vectors" 2>&1); then
	pass "mock self-test $out"
else
	fail "mock self-test: $out"
fi

# ---- 2. The script's helpers under each awk ----
self_test_with() { # NAME AWK_PATH [LD_LIBRARY_PATH]
	local shim=$t/awk-$1 out rc=0
	mkdir -p "$shim"
	if [[ -n ${3:-} ]]; then
		printf '#!/bin/sh\nLD_LIBRARY_PATH=%s exec %s "$@"\n' "$3" "$2" >"$shim/awk"
	else
		printf '#!/bin/sh\nexec %s "$@"\n' "$2" >"$shim/awk"
	fi
	chmod 755 "$shim/awk"
	if ! echo | PATH="$shim:$PATH" awk '{ exit 0 }' 2>/dev/null; then
		echo "note: $1 ($2) does not start here; its self-test is skipped" >&2
		return 0
	fi
	out=$(PATH="$shim:$PATH" bash "$script" --self-test 2>"$t/self-test-$1.err") || rc=$?
	if [[ $rc -eq 0 ]] && printf '%s' "$out" | python3 -I -c 'import json,sys; v=json.load(sys.stdin); sys.exit(0 if v["ok"] is True else 1)'; then
		pass "protocol-v1.sh --self-test under $1 ($2)"
	else
		fail "protocol-v1.sh --self-test under $1 (exit $rc): $(grep FAIL "$t/self-test-$1.err" | head -5 | tr '\n' ' ')"
	fi
}
default_awk=$(command -v awk)
self_test_with default "$(readlink -f "$default_awk")"
ar=${E2E_AWK_ROOT:-}
for v in mawk gawk; do
	if [[ -n $ar && -x $ar/usr/bin/$v ]]; then
		self_test_with "$v" "$ar/usr/bin/$v" "$ar/usr/lib/x86_64-linux-gnu:$ar/lib/x86_64-linux-gnu"
	elif command -v "$v" >/dev/null; then
		self_test_with "$v" "$(command -v "$v")"
	else
		echo "note: $v not found (E2E_AWK_ROOT unset or without it); its self-test is skipped" >&2
	fi
done

# ---- 3. The full run against the mock ----
mkdir -p "$t/mock" "$t/home" "$t/start"
python3 -I -B "$here/server.py" --ready-file "$t/mock/ready.json" >"$t/mock/stdout" 2>"$t/mock/log" &
mock_pid=$!
for _ in $(seq 1 100); do
	[[ -s $t/mock/ready.json ]] && break
	kill -0 "$mock_pid" 2>/dev/null || break
	sleep 0.2
done
[[ -s $t/mock/ready.json ]] || {
	cat "$t/mock/log" >&2
	echo "run.sh: the mock did not start" >&2
	exit 1
}
ready() { python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$t/mock/ready.json" "$1"; }
server_url=$(ready server_url)
school_id=$(ready school_id)
control_url=$(ready control_url)
stub=$(ready arbella_stub)

# Containment: a fake HOME and starting folder, read-only, listed before and after.
snapshot() { (cd "$t" && find home start -exec ls -ldn --time-style=+%s {} + | sort); }
chmod 555 "$t/home" "$t/start"
before=$(snapshot)

rc=0
(cd "$t/start" && HOME=$t/home TMPDIR=$t/start bash "$script" \
	--server-url "$server_url" --school-id "$school_id" --arbella-stub "$stub" \
	--control-url "$control_url" --bin-dir "$bin" --work-dir "$t/work") \
	>"$t/summary.json" 2>"$t/e2e.err" || rc=$?
after=$(snapshot)

if [[ $rc -eq 0 ]]; then pass "protocol-v1.sh exit 0"; else fail "protocol-v1.sh exit $rc"; fi
expected=$(bash "$script" --dry-run)
if python3 -I - "$t/summary.json" "$expected" <<'PY'; then
import json, sys
text = open(sys.argv[1], encoding="ascii").read()
v = json.loads(text)  # one JSON value, or this raises
names = [s for s in sys.argv[2].split("\n") if s]
got = {s["name"]: s for s in v["steps"]}
bad = [n for n in names if n not in got or got[n]["ok"] is not True]
extra = [n for n in got if n not in names]
for s in v["steps"]:
    print(("ok   " if s["ok"] is True else "FAIL ") + s["name"] + ": " + s["detail"], file=sys.stderr)
if v["ok"] is not True or bad or extra or len(v["steps"]) != len(names):
    print(f"summary: ok={v['ok']} failed or missing={bad} unexpected={extra}", file=sys.stderr)
    sys.exit(1)
PY
	pass "summary: one JSON value, ok true, every step ok"
else
	fail "summary not ok (see above)"
fi
if [[ $before == "$after" ]]; then
	pass "containment: fake HOME and starting folder unchanged"
else
	fail "containment: written outside the work dir: $(diff <(printf '%s\n' "$before") <(printf '%s\n' "$after") | head -20 | tr '\n' ' ')"
fi
if grep -q 'INTERNAL ERROR' "$t/mock/log"; then
	fail "the mock hit an internal error (a mock bug)"
fi

if [[ ${#fails[@]} -gt 0 ]]; then
	echo "==== protocol-v1.sh stderr (last 80 lines)" >&2
	tail -n 80 "$t/e2e.err" >&2 || true
	echo "==== logs of the failing steps" >&2
	if [[ -d $t/work/logs ]]; then
		# The last calls' stdout and stderr (the recovery key was redacted by the script).
		find "$t/work/logs" -maxdepth 1 -type f \( -name '*.out' -o -name '*.err' \) | sort | tail -n 40 |
			while IFS= read -r f; do
				echo "--- ${f##*/}" >&2
				head -c 1500 "$f" >&2 || true
				echo >&2
			done
	fi
	echo "==== mock request log" >&2
	cat "$t/mock/log" >&2 || true
	echo "run.sh: FAILED: ${fails[*]}" >&2
	exit 1
fi
echo "==== summary" >&2
cat "$t/summary.json"
echo "run.sh: all checks passed (default awk: $(readlink -f "$default_awk"))" >&2
