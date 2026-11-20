#!/usr/bin/env bash
# Protocol v1 end to end: drives the `mastersos` command line and `mastersos-agent protocol-check`
# against a running server harness (a throwaway server, test issuer and stub `arbella` started by
# the server team's harness; this script never starts a server).
#
# Usage:
#   tools/e2e/protocol-v1.sh --server-url URL --school-id UUID --arbella-stub DIR \
#       --control-url URL --bin-dir DIR --work-dir DIR
#   tools/e2e/protocol-v1.sh --dry-run      the step names, one per line on stdout; exit 0
#   tools/e2e/protocol-v1.sh --self-test    tests of the JSON helpers; a summary on stdout
#   tools/e2e/protocol-v1.sh --help
#
#   --server-url    the server's origin (http only to 127.0.0.1, ::1 or localhost)
#   --school-id     the harness's school, a lowercase UUID
#   --arbella-stub  the folder holding the stub `arbella`; put first on PATH
#   --control-url   the harness's control endpoint (exported as FLEET_E2E_CONTROL for the stub)
#   --bin-dir       holds `mastersos` and `mastersos-agent` (Linux x86_64 builds)
#   --work-dir      absent or empty; everything is written under it (HOME, XDG_*, TMPDIR, pin
#                   folders, school keys, settings folders, seeds, logs/)
#
# Dependencies: bash, coreutils, grep, sed, awk and curl. No jq, python or node.
#
# Output: stdout holds exactly one JSON value, the summary:
#   {"ok":true|false,"server_url":"...","school_id":"...",
#    "steps":[{"name":"...","ok":true|false,"detail":"..."}, ...]}
# Progress goes to stderr; each command's stdout, stderr and flattened JSON go to
# <work-dir>/logs/. A step whose dependency failed is reported ok:false with
# "skipped: <dependency> failed"; independent steps still run.
#
# Exit codes: 0 every step ok; 1 a step failed (or a dependency is missing); 2 usage error
# (message on stderr, nothing on stdout).
#
# Secrets: the stub's access tokens and the seed's fetch token are never printed or logged; the
# throwaway recovery key is redacted from the logs once compared. The school key files, seeds and
# logs stay under the work directory (umask 077).
# The step functions run through run_step and the trap, which shellcheck does not follow.
# shellcheck disable=SC2329
set -euo pipefail
umask 077
export LC_ALL=C

STEP_NAMES=(
	preflight
	key_new
	key_register
	init
	publish_v1
	publish_v2_rotation
	publish_v3_new_key
	heartbeat
	pull
	verify
	seed_make
	seed_check
	protocol_check
	fetch_token_rotation
	recovery_read
	fail_wrong_key
	fail_stale_version
	fail_unregistered_key
	fail_feature_gate
	fail_step_up_required
	fail_signed_out
	containment
)

# A public Ed25519 key that is registered nowhere: RFC 8032 section 7.1, test 1. The command line
# cannot show a school key file's public key without registering it (`key add` and `init` refuse
# an unregistered key before writing), so the unregistered-key case trusts this one.
# What the script writes directly under the work dir (the containment check looks for these in the
# caller's directory).
OUR_NAMES="a b c d e home tmp logs keys seed.toml seed2.toml recovery.key dev1 dev2 pins-a pins-b"

UNREG_PK_HEX=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
UNREG_PK_B64=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=
UNREG_KEY_ID=rk-21fe31df

usage() {
	cat <<'EOF'
Usage: protocol-v1.sh --server-url URL --school-id UUID --arbella-stub DIR --control-url URL --bin-dir DIR --work-dir DIR
       protocol-v1.sh --dry-run | --self-test | --help

Drives the mastersos command line and mastersos-agent protocol-check against a running protocol v1
server harness. Prints one JSON summary on stdout; progress on stderr; logs under the work dir.
Exit 0 when every step is ok, 1 when one failed, 2 on a usage error.
EOF
}

die_usage() {
	printf 'protocol-v1.sh: %s\n' "$1" >&2
	usage >&2
	exit 2
}

log() { printf '[e2e] %s\n' "$*" >&2; }

# ---- JSON helpers (pure awk; tested by --self-test) ----

# shellcheck disable=SC2016 # awk program text, not shell expansions
AWK_ESCAPE='BEGIN {
	s = ENVIRON["JE_S"]
	for (i = 1; i < 32; i++) ctl = ctl sprintf("%c", i)
	for (i = 32; i < 127; i++) prn = prn sprintf("%c", i)
	del = sprintf("%c", 127)
	out = ""
	n = length(s)
	for (i = 1; i <= n; i++) {
		c = substr(s, i, 1)
		if (c == "\"") out = out "\\\""
		else if (c == "\\") out = out "\\\\"
		else if (index(prn, c) > 0) out = out c
		else if (c == "\n") out = out "\\n"
		else if (c == "\r") out = out "\\r"
		else if (c == "\t") out = out "\\t"
		else if ((k = index(ctl, c)) > 0) out = out sprintf("\\u%04x", k)
		else if (c == del) out = out "\\u007f"
		else out = out "?"
	}
	printf "%s", out
}'

# The JSON string body of $1 (without quotes) in REPLY: quote, backslash and control characters
# escaped; bytes outside ASCII become `?`, so the summary is always valid JSON.
json_escape() {
	REPLY=$(JE_S=$1 awk "$AWK_ESCAPE")
}

# shellcheck disable=SC2016 # awk program text, not shell expansions
AWK_FLAT='
function ws() {
	while (pos <= n) {
		ch = substr(s, pos, 1)
		if (ch == " " || ch == "\t" || ch == "\n" || ch == "\r") pos++
		else return
	}
}
function str(   out, c, d) {
	pos++
	out = ""
	while (pos <= n) {
		c = substr(s, pos, 1)
		if (c == "\"") { pos++; return out }
		if (c == "\\") {
			d = substr(s, pos + 1, 1)
			if (d == "\"" || d == "\\" || d == "/") out = out d
			else out = out "\\" d
			pos += 2
			continue
		}
		out = out c
		pos++
	}
	bad = 1
	return out
}
function join(p, k) { return (p == "" ? "" k : p "." k) }
function emit(p, t, v) { print p "\t" t "\t" v }
function val(p,   c, k, i, lit) {
	ws()
	if (pos > n) { bad = 1; return 0 }
	c = substr(s, pos, 1)
	if (c == "{") {
		pos++
		ws()
		if (substr(s, pos, 1) == "}") { pos++; return 1 }
		while (1) {
			ws()
			if (substr(s, pos, 1) != "\"") { bad = 1; return 0 }
			k = str()
			if (bad) return 0
			ws()
			if (substr(s, pos, 1) != ":") { bad = 1; return 0 }
			pos++
			if (!val(join(p, k))) return 0
			ws()
			c = substr(s, pos, 1)
			pos++
			if (c == ",") continue
			if (c == "}") return 1
			bad = 1
			return 0
		}
	}
	if (c == "[") {
		pos++
		ws()
		i = 0
		if (substr(s, pos, 1) == "]") { pos++; return 1 }
		while (1) {
			if (!val(join(p, i))) return 0
			i++
			ws()
			c = substr(s, pos, 1)
			pos++
			if (c == ",") continue
			if (c == "]") return 1
			bad = 1
			return 0
		}
	}
	if (c == "\"") {
		k = str()
		if (bad) return 0
		emit(p, "s", k)
		return 1
	}
	lit = ""
	while (pos <= n) {
		c = substr(s, pos, 1)
		if (index("-+.0123456789eEtrufalsn", c) == 0) break
		lit = lit c
		pos++
	}
	if (lit == "true" || lit == "false") { emit(p, "b", lit); return 1 }
	if (lit == "null") { emit(p, "z", lit); return 1 }
	if (lit ~ /^-?[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?$/) { emit(p, "n", lit); return 1 }
	bad = 1
	return 0
}
{ s = s $0 "\n" }
END {
	n = length(s)
	pos = 1
	bad = 0
	if (!val("")) exit 1
	ws()
	if (pos <= n) exit 1
	exit 0
}'

# Flattens the one JSON value on stdin into lines `path<TAB>type<TAB>value`: path joins object
# keys and array indexes with `.` (`error.code`, `calls.3.step`, `0.recovery_key`); type is s
# (string), n (number), b (true/false) or z (null). In string values \" \\ \/ are decoded and
# every other escape is kept as written, so a value is always one line. Exit 1 when the input
# is not one JSON value.
json_flat() {
	awk "$AWK_FLAT"
}

# fget FLAT PATH: the value at PATH of a flattened file in REPLY and its type in FTYPE; status 1
# when PATH is absent.
fget() {
	local line
	line=$(awk -F'\t' -v p="$2" '$1 == p { print $2 "\t" $3; f = 1; exit } END { exit !f }' "$1") || return 1
	FTYPE=${line%%$'\t'*}
	REPLY=${line#*$'\t'}
}

# fhas FLAT PATH_REGEX VALUE: some string at a path matching the (anchored) regex equals VALUE.
fhas() {
	# The regex goes through the environment: `awk -v` would eat its backslashes.
	FH_RE="^$2\$" FH_V=$3 awk -F'\t' '$1 ~ ENVIRON["FH_RE"] && $2 == "s" && $3 == ENVIRON["FH_V"] { f = 1 } END { exit !f }' "$1"
}

# call_get FLAT STEP FIELD: FIELD of the first protocol-check call whose step is STEP (REPLY).
call_get() {
	REPLY=$(awk -F'\t' -v st="$2" -v fld="$3" '
		{ n = split($1, a, "."); rec[$1] = $3 }
		n == 3 && a[1] == "calls" && a[3] == "step" && $3 == st && idx == "" { idx = a[2] }
		END { k = "calls." idx "." fld; if (idx == "" || !(k in rec)) exit 1; print rec[k] }' "$1")
}

# calls_line FLAT: `step=ok step=skipped step=FAIL(code) ...` for a protocol-check report.
calls_line() {
	REPLY=$(awk -F'\t' '
		{ n = split($1, a, "."); if (n == 3 && a[1] == "calls") { v[a[2] "." a[3]] = $3; if (a[2] + 1 > m) m = a[2] + 1 } }
		END {
			for (i = 0; i < m; i++) {
				r = v[i ".step"] "="
				if (v[i ".ok"] != "true") r = r "FAIL(" v[i ".error_code"] ")"
				else if (v[i ".skipped"] == "true") r = r "skipped"
				else r = r "ok"
				printf "%s%s", (i ? " " : ""), r
			}
		}' "$1")
}

# ---- Steps bookkeeping ----

S_NAME=()
S_OK=()
S_DETAIL=()
DETAIL=""

record() {
	S_NAME+=("$1")
	S_OK+=("$2")
	S_DETAIL+=("$3")
	if [[ $2 == true ]]; then log "ok   $1: $3"; else log "FAIL $1: $3"; fi
}

ok_of() {
	local i
	for i in "${!S_NAME[@]}"; do
		if [[ ${S_NAME[$i]} == "$1" ]]; then
			[[ ${S_OK[$i]} == true ]]
			return
		fi
	done
	return 1
}

# run_step NAME [DEPENDENCY...] -- FUNCTION: runs FUNCTION unless a dependency failed; FUNCTION
# returns 0 or 1 and leaves its detail in DETAIL.
run_step() {
	local name=$1 d
	shift
	local deps=()
	while [[ $1 != -- ]]; do
		deps+=("$1")
		shift
	done
	shift
	for d in ${deps[@]+"${deps[@]}"}; do
		if ! ok_of "$d"; then
			record "$name" false "skipped: $d failed"
			return 0
		fi
	done
	log "---- $name"
	DETAIL=""
	if "$@"; then
		record "$name" true "$DETAIL"
	else
		record "$name" false "${DETAIL:-failed}"
	fi
}

SUMMARY_DONE=0
print_summary() {
	local i all=true out sep="" ok detail
	for i in "${!S_NAME[@]}"; do
		[[ ${S_OK[$i]} == true ]] || all=false
	done
	[[ ${#S_NAME[@]} -gt 0 ]] || all=false
	json_escape "${SERVER:-}"
	out="{\"ok\":$all,\"server_url\":\"$REPLY\""
	json_escape "${SCHOOL:-}"
	out+=",\"school_id\":\"$REPLY\",\"steps\":["
	for i in "${!S_NAME[@]}"; do
		ok=${S_OK[$i]}
		[[ $ok == true ]] || ok=false
		detail=${S_DETAIL[$i]}
		detail=${detail:0:600}
		json_escape "${S_NAME[$i]}"
		out+="$sep{\"name\":\"$REPLY\",\"ok\":$ok"
		json_escape "$detail"
		out+=",\"detail\":\"$REPLY\"}"
		sep=","
	done
	out+="]}"
	printf '%s\n' "$out" >&3
	SUMMARY_DONE=1
	[[ $all == true ]]
}

on_exit() {
	local rc=$?
	if [[ $SUMMARY_DONE == 0 && ${STARTED:-0} == 1 ]]; then
		record internal_error false "the script stopped early (exit $rc); see stderr"
		print_summary || true
		exit 1
	fi
}

# ---- Running the binaries ----

N_LOG=0
next_log() {
	N_LOG=$((N_LOG + 1))
	LOG=$(printf '%s/%02d-%s' "$LOGS" "$N_LOG" "$1")
}

# ms [-C DIR] LABEL PIN_DIR [VAR=VALUE...] -- ARGS...: one `mastersos` call with the fixed global
# options, run in DIR (default: the work dir, which is not a settings folder), stdin from
# /dev/null. Sets RC and LOG (LOG.out, LOG.err, LOG.flat).
ms() {
	local cwd=$W
	if [[ $1 == -C ]]; then
		cwd=$2
		shift 2
	fi
	local label=$1 pins=$2
	shift 2
	local envs=()
	while [[ $1 != -- ]]; do
		envs+=("$1")
		shift
	done
	shift
	next_log "$label"
	log "mastersos $* (pins ${pins##*/}, in ${cwd#"$W"/})"
	(cd "$cwd" && exec env ${envs[@]+"${envs[@]}"} "$BIN/mastersos" --json --yes \
		--server "$SERVER" --school "$SCHOOL" --pin-dir "$pins" "$@") \
		>"$LOG.out" 2>"$LOG.err" </dev/null && RC=0 || RC=$?
	json_flat <"$LOG.out" >"$LOG.flat" 2>/dev/null || true
}

# agent LABEL ARGS...: one `mastersos-agent` call. Sets RC and LOG.
agent() {
	local label=$1
	shift
	next_log "$label"
	log "mastersos-agent $*"
	"$BIN/mastersos-agent" "$@" >"$LOG.out" 2>"$LOG.err" </dev/null && RC=0 || RC=$?
	json_flat <"$LOG.out" >"$LOG.flat" 2>/dev/null || true
}

# The failure of the last call, for DETAIL.
failed_call() {
	local code="(none)" message=""
	if fget "$LOG.flat" error.code; then code=$REPLY; fi
	if fget "$LOG.flat" error.message; then message=${REPLY:0:240}; fi
	DETAIL="$1: exit $RC, code $code${message:+: $message} (log ${LOG##*/})"
	return 1
}

# The last call must have been refused with exit 1 and code $1.
expect_refusal() {
	local got="(none)"
	if fget "$LOG.flat" error.code; then got=$REPLY; fi
	if [[ $RC -eq 1 && $got == "$1" ]]; then
		DETAIL="refused with $1"
		return 0
	fi
	DETAIL="expected exit 1 and code $1, got exit $RC and code $got (log ${LOG##*/})"
	return 1
}

# want PATH VALUE WHAT: the last call's JSON has VALUE at PATH.
want() {
	if fget "$LOG.flat" "$1" && [[ $REPLY == "$2" ]]; then return 0; fi
	DETAIL="$3: expected $1 = $2, got ${REPLY:-(absent)} (log ${LOG##*/})"
	REPLY=""
	return 1
}

mode_of() {
	stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"
}

# A throwaway recovery key in the shape protocol-check takes: 8 groups of 8 modhex characters.
gen_recovery_key() {
	local alphabet=cbdefghijklnrtuv bytes b out="" i=0
	bytes=$(od -An -tu1 -N64 /dev/urandom) || return 1
	for b in $bytes; do
		out+=${alphabet:$((b % 16)):1}
		i=$((i + 1))
		if ((i % 8 == 0 && i < 64)); then out+=-; fi
	done
	[[ ${#out} -eq 71 ]] || return 1
	REPLY=$out
}

# A random lowercase 8-4-4-4-12 UUID.
gen_uuid() {
	local hex
	hex=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n') || return 1
	[[ ${#hex} -eq 32 ]] || return 1
	REPLY="${hex:0:8}-${hex:8:4}-${hex:12:4}-${hex:16:4}-${hex:20:12}"
}

# A comment line appended to a settings folder's manifest.toml: publishing refuses a folder equal
# to its base (`unchanged`), and a comment is a byte change that alters nothing else.
touch_manifest() {
	printf '# e2e: %s\n' "$2" >>"$1/manifest.toml"
}

# The listing of a folder outside the work dir, to show it did not change ("absent" when missing).
listing() {
	if [[ -e $1 ]]; then
		find "$1" -exec ls -ld {} + 2>/dev/null | sort | cksum
	else
		echo absent
	fi
}

# ---- The steps ----

s_preflight() {
	local missing=() c
	for c in awk sed grep curl od tr head stat cksum env ls mkdir chmod mv cat; do
		command -v "$c" >/dev/null 2>&1 || missing+=("$c")
	done
	if [[ ${#missing[@]} -gt 0 ]]; then
		DETAIL="missing commands: ${missing[*]}"
		return 1
	fi
	for c in mastersos mastersos-agent; do
		if [[ ! -f $BIN/$c || ! -x $BIN/$c ]]; then
			DETAIL="$BIN/$c is not an executable file"
			return 1
		fi
	done
	if [[ ! -f $STUB/arbella || ! -x $STUB/arbella ]]; then
		DETAIL="$STUB/arbella is not an executable file"
		return 1
	fi
	if [[ $(command -v arbella) != "$STUB/arbella" ]]; then
		DETAIL="arbella on PATH is not the stub's"
		return 1
	fi
	local v1 v2
	v1=$("$BIN/mastersos" --version 2>&1) || {
		DETAIL="$BIN/mastersos --version failed (wrong architecture?): ${v1:0:200}"
		return 1
	}
	v2=$("$BIN/mastersos-agent" --version 2>&1) || {
		DETAIL="$BIN/mastersos-agent --version failed (wrong architecture?): ${v2:0:200}"
		return 1
	}
	if ! curl -fsS --max-time 15 -o /dev/null "$CONTROL/healthz"; then
		DETAIL="GET $CONTROL/healthz failed"
		return 1
	fi
	DETAIL="$v1; $v2; control endpoint healthy; work dir $W"
}

KCODE=()
KID=()
KFP=()
s_key_new() {
	local i mode
	if ! { mkdir -p "$W/keys" && chmod 700 "$W/keys"; }; then
		DETAIL="cannot create $W/keys"
		return 1
	fi
	for i in 1 2 3; do
		ms "key-new-k$i" "$W/pins-a" -- key new --out "$W/keys/k$i.kit"
		[[ $RC -eq 0 ]] || {
			failed_call "key new k$i"
			return
		}
		local f
		for f in key_code key_id fingerprint; do
			if ! fget "$LOG.flat" "$f" || [[ -z $REPLY ]]; then
				DETAIL="key new k$i: no $f in its answer (log ${LOG##*/})"
				return 1
			fi
			case $f in
			key_code) KCODE[i]=$REPLY ;;
			key_id) KID[i]=$REPLY ;;
			fingerprint) KFP[i]=$REPLY ;;
			esac
		done
		mode=$(mode_of "$W/keys/k$i.kit")
		if [[ $mode != 600 ]]; then
			DETAIL="$W/keys/k$i.kit has mode $mode, not 600"
			return 1
		fi
	done
	DETAIL="k1 ${KCODE[1]} (${KFP[1]}), k2 ${KCODE[2]} (${KFP[2]}), k3 ${KCODE[3]} (never registered); files 0600"
}

s_key_register() {
	local i
	for i in 1 2; do
		ms "key-register-k$i" "$W/pins-a" -- key register --key-file "$W/keys/k$i.kit" --label "e2e key $i"
		[[ $RC -eq 0 ]] || {
			failed_call "key register k$i"
			return
		}
		want key_id "${KID[i]}" "key register k$i" || return 1
	done
	DETAIL="k1 and k2 registered (step-up through the stub)"
}

s_init() {
	ms init "$W/pins-a" -- init "$W/a" --key-file "$W/keys/k1.kit"
	[[ $RC -eq 0 ]] || {
		failed_call "init"
		return
	}
	want trusted_keys.0 "${KCODE[1]}" "init" || return 1
	DETAIL="$W/a trusts k1"
}

LATEST=0
# publish_ok LABEL PINS DIR KEY EXPECTED_VERSION: a publish that must succeed.
publish_ok() {
	ms "$1" "$2" -- publish "$3" --key-file "$4"
	[[ $RC -eq 0 ]] || {
		failed_call "publish $3"
		return
	}
	want version "$5" "publish $3" || return 1
	LATEST=$5
	local hb="no check-in"
	if fget "$LOG.flat" heartbeat_not_after && [[ $FTYPE == s ]]; then hb="check-in until $REPLY"; fi
	DETAIL="version $5 ($hb)"
}

s_publish_v1() {
	publish_ok publish-v1 "$W/pins-a" "$W/a" "$W/keys/k1.kit" 1
}

s_publish_v2_rotation() {
	ms key-add-k2 "$W/pins-a" -- key add "$W/keys/k2.kit" --dir "$W/a"
	[[ $RC -eq 0 ]] || {
		failed_call "key add k2"
		return
	}
	# Local only; prints text even with --json, so only the exit code is checked.
	ms key-remove-k1 "$W/pins-a" -- key remove "${KCODE[1]}" --key-file "$W/keys/k1.kit" --dir "$W/a"
	[[ $RC -eq 0 ]] || {
		DETAIL="key remove k1: exit $RC (log ${LOG##*/})"
		return 1
	}
	if grep -q "${KID[1]}" "$W/a/manifest.toml" || ! grep -q "${KID[2]}" "$W/a/manifest.toml"; then
		DETAIL="after key add/remove, manifest.toml should trust k2 and not k1"
		return 1
	fi
	publish_ok publish-v2 "$W/pins-a" "$W/a" "$W/keys/k1.kit" 2 || return 1
	local hb=$DETAIL
	want trust_change.added.0 "${KID[2]}" "publish v2 trust change" || return 1
	want trust_change.removed.0 "${KID[1]}" "publish v2 trust change" || return 1
	DETAIL="$hb; trust {k1} -> {k2} and escrow recipient k1 -> k2, signed by k1"
}

s_publish_v3_new_key() {
	touch_manifest "$W/a" "first version approved by key 2"
	publish_ok publish-v3 "$W/pins-a" "$W/a" "$W/keys/k2.kit" 3 || return 1
	DETAIL="$DETAIL, signed by k2: the rotation version is signed by k1 only, so a computer or Device starting from it cannot verify it under its own trust"
}

s_heartbeat() {
	ms heartbeat "$W/pins-a" -- heartbeat --key-file "$W/keys/k2.kit"
	[[ $RC -eq 0 ]] || {
		failed_call "heartbeat"
		return
	}
	want version "$LATEST" "heartbeat" || return 1
	fget "$LOG.flat" not_after || REPLY="?"
	DETAIL="version $LATEST signed by k2, valid until $REPLY"
}

s_pull() {
	ms pull-b "$W/pins-b" -- --trust-fingerprint "${KFP[2]}" pull "$W/b"
	[[ $RC -eq 0 ]] || {
		failed_call "pull into $W/b"
		return
	}
	want version "$LATEST" "pull" || return 1
	DETAIL="version $LATEST into $W/b, fresh pins-b anchored by --trust-fingerprint of k2"
}

s_verify() {
	ms -C "$W/b" verify "$W/pins-b" -- verify
	[[ $RC -eq 0 ]] || {
		failed_call "verify"
		return
	}
	want version "$LATEST" "verify" || return 1
	want latest "$LATEST" "verify" || return 1
	want trust.0.fingerprint "${KFP[2]}" "verify" || return 1
	if fget "$LOG.flat" trust.1.key_id; then
		DETAIL="verify: more than one trusted key"
		return 1
	fi
	DETAIL="version $LATEST verified in $W/b; trust {k2}"
}

seed_make() {
	ms "$1" "$W/pins-a" -- seed make --out "$2"
	[[ $RC -eq 0 ]] || {
		failed_call "seed make"
		return
	}
	want min_version "$LATEST" "seed make" || return 1
	want trust_fingerprints.0.fingerprint "${KFP[2]}" "seed make" || return 1
	local mode
	mode=$(mode_of "$2")
	if [[ $mode != 600 ]]; then
		DETAIL="$2 has mode $mode, not 600"
		return 1
	fi
	DETAIL="$2 (min_version $LATEST, trust {k2}, mode 0600)"
}

s_seed_make() {
	seed_make seed-make "$W/seed.toml"
}

s_seed_check() {
	ms seed-check "$W/pins-a" -- seed check "$W/seed.toml"
	[[ $RC -eq 0 ]] || {
		failed_call "seed check"
		return
	}
	want ok true "seed check" || return 1
	DETAIL="the seed matches version $LATEST"
}

# check_report WHAT: the last protocol-check report is ok, with a device id (in DEVICE).
check_report() {
	calls_line "$LOG.flat"
	local calls=$REPLY
	if [[ $RC -ne 0 ]] || ! fget "$LOG.flat" ok || [[ $REPLY != true ]]; then
		DETAIL="$1: exit $RC, report not ok: ${calls:-no report} (log ${LOG##*/})"
		return 1
	fi
	if ! fget "$LOG.flat" device_id || [[ $FTYPE != s || -z $REPLY ]]; then
		DETAIL="$1: no device_id in the report"
		return 1
	fi
	DEVICE=$REPLY
	CALLS=$calls
}

RKEY=""
DEV1=""
s_protocol_check() {
	gen_recovery_key || {
		DETAIL="cannot make a recovery key"
		return 1
	}
	RKEY=$REPLY
	printf '%s\n' "$RKEY" >"$W/recovery.key"
	gen_uuid || {
		DETAIL="cannot make a LUKS UUID"
		return 1
	}
	LUKS=$REPLY
	agent protocol-check-1 protocol-check --seed "$W/seed.toml" --state "$W/dev1" --json \
		--recovery-key "$W/recovery.key" --luks-uuid "$LUKS"
	check_report "protocol-check" || return 1
	DEV1=$DEVICE
	if ! { call_get "$LOG.flat" escrow skipped && [[ $REPLY == false ]]; }; then
		DETAIL="protocol-check: the escrow call did not run ($CALLS)"
		return 1
	fi
	DETAIL="device $DEV1; $CALLS"
}

s_fetch_token_rotation() {
	next_log rotate
	if ! curl -fsS --max-time 30 -X POST -o /dev/null "$CONTROL/fetch-token/rotate" 2>"$LOG.err"; then
		DETAIL="POST $CONTROL/fetch-token/rotate failed (log ${LOG##*/})"
		return 1
	fi
	agent protocol-check-2 protocol-check --seed "$W/seed.toml" --state "$W/dev1" --json
	check_report "protocol-check after the rotation" || return 1
	local second=$CALLS
	if ! { call_get "$LOG.flat" fetch_token skipped && [[ $REPLY == false ]] &&
		call_get "$LOG.flat" fetch_token ok && [[ $REPLY == true ]] &&
		call_get "$LOG.flat" fetch_token route && [[ -n $REPLY && $REPLY != null ]] &&
		call_get "$LOG.flat" fetch_token_check ok && [[ $REPLY == true ]]; }; then
		DETAIL="after the rotation the token was not marked stale and renewed: $second (log ${LOG##*/})"
		return 1
	fi
	next_log drop-retired
	if ! curl -fsS --max-time 30 -X POST -o /dev/null "$CONTROL/fetch-token/drop-retired" 2>"$LOG.err"; then
		DETAIL="POST $CONTROL/fetch-token/drop-retired failed (log ${LOG##*/})"
		return 1
	fi
	agent protocol-check-3 protocol-check --seed "$W/seed.toml" --state "$W/dev1" --json
	check_report "protocol-check after drop-retired" || return 1
	if ! { call_get "$LOG.flat" fetch_token skipped && [[ $REPLY == true ]]; }; then
		DETAIL="after drop-retired the renewed token is still stale: $CALLS (log ${LOG##*/})"
		return 1
	fi
	DETAIL="stale marker seen and token renewed ($second); after drop-retired: $CALLS"
}

s_recovery_read() {
	ms recovery-read "$W/pins-a" -- recovery read "$DEV1" --key-file "$W/keys/k2.kit"
	local found=1
	if [[ $RC -eq 0 ]] && fhas "$LOG.flat" '[0-9]+\.recovery_key' "$RKEY"; then found=0; fi
	# The throwaway key is compared, then kept out of the logs.
	local f
	for f in "$LOG.out" "$LOG.flat"; do
		sed "s/$RKEY/<redacted>/g" "$f" >"$f.tmp" && mv "$f.tmp" "$f"
	done
	[[ $RC -eq 0 ]] || {
		failed_call "recovery read"
		return
	}
	if [[ $found -ne 0 ]]; then
		DETAIL="recovery read: no row holds the escrowed key (log ${LOG##*/})"
		return 1
	fi
	DETAIL="the escrowed recovery key of $DEV1 opened with k2, byte for byte"
}

s_fail_wrong_key() {
	touch_manifest "$W/b" "publish attempt with key 1"
	ms publish-b-k1 "$W/pins-b" -- publish "$W/b" --key-file "$W/keys/k1.kit"
	expect_refusal key_not_trusted || return 1
	DETAIL="$DETAIL (local: k1 is not in the trust of version $LATEST)"
}

s_fail_stale_version() {
	ms pull-c "$W/pins-a" -- pull "$W/c"
	[[ $RC -eq 0 ]] || {
		failed_call "pull into $W/c"
		return
	}
	want version "$LATEST" "pull c" || return 1
	touch_manifest "$W/b" "one more version from b"
	publish_ok publish-b-k2 "$W/pins-b" "$W/b" "$W/keys/k2.kit" $((LATEST + 1)) || return 1
	touch_manifest "$W/c" "publish attempt on a stale base"
	ms publish-c-stale "$W/pins-a" -- publish "$W/c" --key-file "$W/keys/k2.kit"
	expect_refusal version_conflict || return 1
	DETAIL="$DETAIL (base $((LATEST - 1)), latest $LATEST; the command line's local precheck refused it, so the server's 409 path was not exercised)"
}

s_fail_unregistered_key() {
	ms pull-d "$W/pins-a" -- pull "$W/d"
	[[ $RC -eq 0 ]] || {
		failed_call "pull into $W/d"
		return
	}
	printf '\n[[trust]]\nid = "%s"\nalg = "ed25519"\npublic_key = "%s"\n' \
		"$UNREG_KEY_ID" "$UNREG_PK_B64" >>"$W/d/manifest.toml"
	ms publish-d-unregistered "$W/pins-a" -- publish "$W/d" --key-file "$W/keys/k2.kit"
	expect_refusal trust_key_unregistered || return 1
	DETAIL="$DETAIL (trust entry $UNREG_KEY_ID, a key registered nowhere, added in the text)"
}

s_fail_feature_gate() {
	seed_make seed-make-2 "$W/seed2.toml" || return 1
	agent protocol-check-dev2 protocol-check --seed "$W/seed2.toml" --state "$W/dev2" --json \
		--omit-feature kiosk
	check_report "protocol-check of a second device without kiosk" || return 1
	local dev2=$DEVICE
	ms pull-e "$W/pins-a" -- pull "$W/e"
	[[ $RC -eq 0 ]] || {
		failed_call "pull into $W/e"
		return
	}
	if ! awk '!done && /^\[\[group\]\]/ {
			print "[config.apps.kiosk.e2e-exam]"
			print "name = \"E2E exam\""
			print "url = \"https://exam.example/\""
			print ""
			done = 1
		}
		{ print }
		END { exit !done }' "$W/e/manifest.toml" >"$W/e/manifest.toml.new"; then
		DETAIL="no [[group]] in $W/e/manifest.toml to put the kiosk app before"
		return 1
	fi
	mv "$W/e/manifest.toml.new" "$W/e/manifest.toml"
	ms publish-e-kiosk "$W/pins-a" -- publish "$W/e" --key-file "$W/keys/k2.kit"
	expect_refusal feature_unsupported || return 1
	if ! fhas "$LOG.flat" 'error\.problems\.[0-9]+\.device_id' "$dev2"; then
		DETAIL="feature_unsupported, but device $dev2 (reported without kiosk) is not in problems (log ${LOG##*/})"
		return 1
	fi
	DETAIL="$DETAIL, listing device $dev2 (reported without kiosk)"
}

s_fail_step_up_required() {
	local out tok code
	next_log step-up
	# The token stays in this function: never printed, logged or written to a file.
	out=$(arbella auth token --json 2>"$LOG.err") || {
		DETAIL="arbella auth token --json failed (log ${LOG##*/})"
		return 1
	}
	tok=$(printf '%s' "$out" | json_flat | awk -F'\t' '$1 == "access_token" && $2 == "s" { print $3; exit }')
	out=""
	if [[ -z $tok || ! $tok =~ ^[A-Za-z0-9._~+/=-]+$ ]]; then
		tok=""
		DETAIL="arbella auth token --json gave no usable access_token"
		return 1
	fi
	code=$(printf 'header = "Authorization: Bearer %s"\n' "$tok" |
		curl -sS --max-time 30 -o "$LOG.out" -w '%{http_code}' -X POST --config - \
			"$SERVER/api/cli/v1/schools/$SCHOOL/mastersos/seed" 2>>"$LOG.err") || code="(no answer)"
	tok=""
	json_flat <"$LOG.out" >"$LOG.flat" 2>/dev/null || true
	local got="(none)"
	if fget "$LOG.flat" error.code; then got=$REPLY; fi
	if [[ $code != 401 || $got != step_up_required ]]; then
		DETAIL="POST seed with a plain token: expected 401 step_up_required, got $code $got (log ${LOG##*/})"
		return 1
	fi
	DETAIL="POST seed with a plain token: 401 step_up_required"
}

s_fail_signed_out() {
	ms key-list-signed-out "$W/pins-a" FLEET_E2E_SIGNED_OUT=1 -- key list
	expect_refusal not_logged_in || return 1
	DETAIL="$DETAIL (arbella exit 3 mapped)"
}

s_containment() {
	local bad=()
	[[ $HOME == "$W"/* ]] || bad+=("HOME")
	[[ $XDG_CONFIG_HOME == "$W"/* ]] || bad+=("XDG_CONFIG_HOME")
	[[ $XDG_CACHE_HOME == "$W"/* ]] || bad+=("XDG_CACHE_HOME")
	[[ $XDG_DATA_HOME == "$W"/* ]] || bad+=("XDG_DATA_HOME")
	[[ $TMPDIR == "$W"/* ]] || bad+=("TMPDIR")
	if [[ $(listing "$ORIG_HOME/.config/mastersos") != "$BEFORE_CONFIG" ]]; then
		bad+=("$ORIG_HOME/.config/mastersos changed")
	fi
	local n
	for n in $OUR_NAMES; do
		if [[ -e $ORIG_PWD/$n && " $BEFORE_PWD_NAMES " != *" $n "* ]]; then
			bad+=("$ORIG_PWD/$n appeared")
		fi
	done
	if [[ ${#bad[@]} -gt 0 ]]; then
		DETAIL="outside the work dir: ${bad[*]}"
		return 1
	fi
	DETAIL="HOME, XDG_* and TMPDIR were under the work dir; the caller's ~/.config/mastersos and current directory unchanged (best effort)"
}

# ---- Self-test of the helpers ----

ST_N=0
st() {
	ST_N=$((ST_N + 1))
	if [[ $2 == "$3" ]]; then
		record "t$ST_N-$1" true "$4"
	else
		record "t$ST_N-$1" false "$4 | expected [$3] got [$2]"
	fi
}

self_test() {
	local nl=$'\n' tab=$'\t' cr=$'\r' c01=$'\001' c1f=$'\037' del=$'\177' bs=$'\b' ff=$'\f' flat
	json_escape 'say "hi"'
	st quote "$REPLY" 'say \"hi\"' 'say "hi"'
	json_escape 'a\b\\c'
	st backslash "$REPLY" 'a\\b\\\\c' 'a\b\\c'
	json_escape "l1${nl}l2${cr}${tab}x"
	st newline "$REPLY" 'l1\nl2\r\tx' "l1${nl}l2${cr}${tab}x"
	json_escape "a${c01}b${c1f}c${del}d${bs}e${ff}"
	st control "$REPLY" 'a\u0001b\u001fc\u007fd\u0008e\u000c' "a${c01}b${c1f}c${del}d${bs}e${ff}"
	json_escape $'caf\xc3\xa9'
	st non-ascii "$REPLY" 'caf??' 'non-ASCII bytes become ?'
	json_escape ''
	st empty "$REPLY" '' ''
	json_escape "\"\\${nl}\"}{]["
	st mixed "$REPLY" '\"\\\n\"}{][' "\"\\${nl}\"}{]["

	flat=$(printf '%s' '{"error":{"code":"not_logged_in","message":"a \"q\" \\ b \/ \n","problems":[{"device_id":"d1"},{"device_id":"d2"}]},"n":-3.5e2,"t":true,"f":false,"z":null,"e":"","arr":[[1,2],{},[]],"x":{"y":{"z":"deep"}}}' | json_flat) || flat="PARSE FAILED"
	local want_flat
	want_flat=$(printf '%s\n' \
		"error.code${tab}s${tab}not_logged_in" \
		"error.message${tab}s${tab}a \"q\" \\ b / \\n" \
		"error.problems.0.device_id${tab}s${tab}d1" \
		"error.problems.1.device_id${tab}s${tab}d2" \
		"n${tab}n${tab}-3.5e2" \
		"t${tab}b${tab}true" \
		"f${tab}b${tab}false" \
		"z${tab}z${tab}null" \
		"e${tab}s${tab}" \
		"arr.0.0${tab}n${tab}1" \
		"arr.0.1${tab}n${tab}2" \
		"x.y.z${tab}s${tab}deep")
	st flat-object "$flat" "$want_flat" 'flattening an error object'
	flat=$(printf '%s\n' '[ {"recovery_key" : "cbde-x", "note": null} ,{"recovery_key":"f"} ]' | json_flat) || flat="PARSE FAILED"
	st flat-array "$flat" "$(printf '%s\n' "0.recovery_key${tab}s${tab}cbde-x" "0.note${tab}z${tab}null" "1.recovery_key${tab}s${tab}f")" 'a top-level array'
	local r
	for r in '{"a":1' '{"a":1}x' '{"a" 1}' '' '[1,]' '{"a":tru}' 'Error: not json'; do
		if printf '%s' "$r" | json_flat >/dev/null 2>&1; then
			st invalid "accepted" "refused" "invalid JSON [$r]"
		else
			st invalid "refused" "refused" "invalid JSON [$r]"
		fi
	done

	local tmp
	tmp=$(mktemp)
	printf '%s' '{"protocol_check":1,"device_id":"dev-1","ok":true,"calls":[{"step":"bundle","route":"GET /x","status":200,"ok":true,"skipped":false,"error_code":null},{"step":"fetch_token","route":null,"status":null,"ok":true,"skipped":true,"error_code":null},{"step":"status","route":"POST /s","status":401,"ok":false,"skipped":false,"error_code":"unauthorized"}]}' | json_flat >"$tmp"
	call_get "$tmp" fetch_token skipped
	st call-get "$REPLY" true 'call_get finds a call by step'
	call_get "$tmp" bundle route
	st call-get-route "$REPLY" 'GET /x' 'call_get reads a string field'
	if call_get "$tmp" escrow ok; then st call-missing found absent 'a missing step'; else st call-missing absent absent 'a missing step'; fi
	calls_line "$tmp"
	st calls-line "$REPLY" 'bundle=ok fetch_token=skipped status=FAIL(unauthorized)' 'calls_line'
	fget "$tmp" device_id
	st fget "$REPLY/$FTYPE" 'dev-1/s' 'fget'
	if fget "$tmp" nothing.here; then st fget-missing found absent 'fget of an absent path'; else st fget-missing absent absent 'fget of an absent path'; fi
	printf '%s' '{"error":{"code":"feature_unsupported","problems":[{"device_id":"a1"},{"device_id":"b2"}]}}' | json_flat >"$tmp"
	if fhas "$tmp" 'error\.problems\.[0-9]+\.device_id' b2; then st fhas yes yes 'fhas finds a device id'; else st fhas no yes 'fhas finds a device id'; fi
	if fhas "$tmp" 'error\.problems\.[0-9]+\.device_id' b; then st fhas-exact partial whole 'fhas matches whole values'; else st fhas-exact whole whole 'fhas matches whole values'; fi
	rm -f "$tmp"

	gen_recovery_key
	if [[ $REPLY =~ ^[cbdefghijklnrtuv]{8}(-[cbdefghijklnrtuv]{8}){7}$ ]]; then st recovery-key ok ok 'recovery key shape'; else st recovery-key "$REPLY" 'modhex 8x8' 'recovery key shape'; fi
	gen_uuid
	if [[ $REPLY =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then st uuid ok ok 'LUKS UUID shape'; else st uuid "$REPLY" 'uuid' 'LUKS UUID shape'; fi

	if command -v sha256sum >/dev/null && command -v base64 >/dev/null; then
		local bin="" i id b64
		for ((i = 0; i < 64; i += 2)); do bin+="\\x${UNREG_PK_HEX:i:2}"; done
		# shellcheck disable=SC2059 # the format is the key's bytes as \x escapes
		id="rk-$(printf "$bin" | sha256sum | cut -c1-8)"
		# shellcheck disable=SC2059
		b64=$(printf "$bin" | base64)
		st unregistered-key "$id $b64" "$UNREG_KEY_ID $UNREG_PK_B64" 'the unregistered key id and base64 derive from the RFC 8032 public key'
	fi
}

# ---- Main ----

SERVER="" SCHOOL="" STUB="" CONTROL="" BIN="" W=""
MODE=run
while [[ $# -gt 0 ]]; do
	case $1 in
	--help | -h)
		usage
		exit 0
		;;
	--dry-run) MODE=dry ;;
	--self-test) MODE=self ;;
	--server-url | --school-id | --arbella-stub | --control-url | --bin-dir | --work-dir)
		[[ $# -ge 2 && -n $2 ]] || die_usage "$1 needs a value"
		case $1 in
		--server-url) SERVER=$2 ;;
		--school-id) SCHOOL=$2 ;;
		--arbella-stub) STUB=$2 ;;
		--control-url) CONTROL=$2 ;;
		--bin-dir) BIN=$2 ;;
		--work-dir) W=$2 ;;
		esac
		shift
		;;
	--server-url=* | --school-id=* | --arbella-stub=* | --control-url=* | --bin-dir=* | --work-dir=*)
		set -- "${1%%=*}" "${1#*=}" "${@:2}"
		continue
		;;
	*) die_usage "unknown argument: $1" ;;
	esac
	shift
done

if [[ $MODE == dry ]]; then
	printf '%s\n' "${STEP_NAMES[@]}"
	exit 0
fi

command -v awk >/dev/null 2>&1 || {
	echo "protocol-v1.sh: awk is required" >&2
	exit 1
}

if [[ $MODE == self ]]; then
	exec 3>&1 1>&2
	SERVER=self-test SCHOOL=""
	self_test
	if print_summary; then exit 0; else exit 1; fi
fi

[[ -n $SERVER ]] || die_usage "--server-url is required"
[[ -n $SCHOOL ]] || die_usage "--school-id is required"
[[ -n $STUB ]] || die_usage "--arbella-stub is required"
[[ -n $CONTROL ]] || die_usage "--control-url is required"
[[ -n $BIN ]] || die_usage "--bin-dir is required"
[[ -n $W ]] || die_usage "--work-dir is required"
SERVER=${SERVER%/}
CONTROL=${CONTROL%/}
[[ $SERVER =~ ^https?://[^/[:space:]]+$ ]] || die_usage "--server-url must be an origin such as http://127.0.0.1:8080"
[[ $CONTROL =~ ^https?://[^[:space:]]+$ ]] || die_usage "--control-url must be an http(s) URL"
[[ $SCHOOL =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] ||
	die_usage "--school-id must be a lowercase UUID"
[[ -d $STUB ]] || die_usage "--arbella-stub $STUB is not a directory"
[[ -d $BIN ]] || die_usage "--bin-dir $BIN is not a directory"
STUB=$(cd "$STUB" && pwd -P)
BIN=$(cd "$BIN" && pwd -P)
if [[ -e $W ]]; then
	[[ -d $W ]] || die_usage "--work-dir $W is not a directory"
	[[ -z $(ls -A "$W") ]] || die_usage "--work-dir $W is not empty"
else
	mkdir -p "$W" || die_usage "cannot create --work-dir $W"
fi
W=$(cd "$W" && pwd -P)
chmod 700 "$W"

ORIG_HOME=${HOME:-/nonexistent}
ORIG_PWD=$(pwd -P)
BEFORE_CONFIG=$(listing "$ORIG_HOME/.config/mastersos")
# The names this script writes under the work dir that already exist in the caller's directory.
BEFORE_PWD_NAMES=""
for n in $OUR_NAMES; do
	if [[ -e $ORIG_PWD/$n ]]; then BEFORE_PWD_NAMES+=" $n"; fi
done

LOGS=$W/logs
mkdir -p "$LOGS" "$W/home/.config" "$W/home/.cache" "$W/home/.local/share" "$W/tmp"
export HOME=$W/home
export XDG_CONFIG_HOME=$W/home/.config
export XDG_CACHE_HOME=$W/home/.cache
export XDG_DATA_HOME=$W/home/.local/share
export TMPDIR=$W/tmp
export PATH="$STUB:$PATH"
export FLEET_E2E_CONTROL=$CONTROL
unset FLEET_E2E_SIGNED_OUT
cd "$W"

# From here stdout is the summary's only: fd 3. Anything else written to stdout goes to stderr.
exec 3>&1 1>&2
STARTED=1
trap on_exit EXIT

run_step preflight -- s_preflight
run_step key_new preflight -- s_key_new
run_step key_register key_new -- s_key_register
run_step init key_register -- s_init
run_step publish_v1 init -- s_publish_v1
run_step publish_v2_rotation publish_v1 -- s_publish_v2_rotation
run_step publish_v3_new_key publish_v2_rotation -- s_publish_v3_new_key
run_step heartbeat publish_v3_new_key -- s_heartbeat
run_step pull publish_v3_new_key -- s_pull
run_step verify pull -- s_verify
run_step seed_make publish_v3_new_key -- s_seed_make
run_step seed_check seed_make -- s_seed_check
run_step protocol_check seed_make -- s_protocol_check
run_step fetch_token_rotation protocol_check -- s_fetch_token_rotation
run_step recovery_read protocol_check -- s_recovery_read
run_step fail_wrong_key pull -- s_fail_wrong_key
run_step fail_stale_version pull -- s_fail_stale_version
run_step fail_unregistered_key publish_v3_new_key -- s_fail_unregistered_key
run_step fail_feature_gate publish_v3_new_key -- s_fail_feature_gate
run_step fail_step_up_required preflight -- s_fail_step_up_required
run_step fail_signed_out preflight -- s_fail_signed_out
run_step containment -- s_containment

if print_summary; then exit 0; else exit 1; fi
