#!/usr/bin/env bash
# Protocol v1 end to end: drives the `mastersos` command line and `mastersos-agent protocol-check`
# against a running server harness (a throwaway server, test issuer and stub `arbella` started by
# the server team's harness; this script never starts a server).
#
# Usage:
#   tools/e2e/protocol-v1.sh --server-url URL --school-id UUID --arbella-stub DIR \
#       --control-url URL --bin-dir DIR --work-dir DIR [--second-school-id UUID]
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
#   --second-school-id  optional: the harness's second school, a lowercase UUID administered only
#                   by the second admin (the stub signs in as that admin when FLEET_E2E_ADMIN=second
#                   is in its environment). Without it the cross_school_* steps are reported
#                   "skipped":true and ok:true.
#
# Dependencies: bash, coreutils, grep, sed, awk and curl. No jq, python or node.
#
# Output: stdout holds exactly one JSON value, the summary:
#   {"ok":true|false,"server_url":"...","school_id":"...",
#    "steps":[{"name":"...","ok":true|false,"detail":"..."[,"skipped":true]}, ...]}
# Progress goes to stderr; each command's stdout, stderr and flattened JSON go to
# <work-dir>/logs/. A step whose dependency failed is reported ok:false with
# "skipped: <dependency> failed"; independent steps still run. A step that does not apply to
# this run (a second school was not given) is reported ok:true with "skipped":true.
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

# The steps in order, each `name:dependency,...`; step NAME runs function s_NAME, and is skipped
# (ok:false) when a dependency is not ok. --dry-run prints the names.
STEPS=(
	preflight:
	key_new:preflight
	key_register:key_new
	init:key_register
	publish_v1:init
	publish_v2_rotation:publish_v1
	publish_v3_new_key:publish_v2_rotation
	heartbeat:publish_v3_new_key
	pull:publish_v3_new_key
	verify:pull
	seed_make:publish_v3_new_key
	seed_check:seed_make
	protocol_check:seed_make
	fetch_token_rotation:protocol_check
	recovery_read:protocol_check
	fail_wrong_key:pull
	fail_stale_version:pull
	fail_unregistered_key:publish_v3_new_key
	fail_feature_gate:publish_v3_new_key
	fail_step_up_required:preflight
	fail_signed_out:preflight
	server_refuses_untrusted_signature:publish_v3_new_key
	server_refuses_stale_base:publish_v3_new_key
	cross_school_cli_refused:preflight
	cross_school_device_isolated:publish_v3_new_key
	escrow_secret_reset:publish_v3_new_key
	containment:
)

# What the script writes directly under the work dir (the containment check looks for these in the
# caller's directory).
OUR_NAMES="a b c d e s2 home tmp logs keys api seed.toml seed2.toml seed3.toml seed-iso.toml seed-s2.toml
recovery.key recovery3.key dev1 dev2 dev3 dev3b dev-s2 pins-a pins-b pins-s2"

# A public Ed25519 key that is registered nowhere: RFC 8032 section 7.1, test 1. The command line
# cannot show a school key file's public key without registering it (`key add` and `init` refuse
# an unregistered key before writing), so the unregistered-key case trusts this one.
UNREG_PK_HEX=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
UNREG_PK_B64=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=
UNREG_KEY_ID=rk-21fe31df

usage() {
	cat <<'EOF'
Usage: protocol-v1.sh --server-url URL --school-id UUID --arbella-stub DIR --control-url URL --bin-dir DIR --work-dir DIR
                      [--second-school-id UUID]
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
	REPLY=""
	FTYPE=""
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
S_SKIP=()
DETAIL=""
SKIPPED=0

# record NAME OK DETAIL [skipped]
record() {
	S_NAME+=("$1")
	S_OK+=("$2")
	S_DETAIL+=("$3")
	S_SKIP+=("${4:-}")
	if [[ -n ${4:-} ]]; then
		log "skip $1: $3"
	elif [[ $2 == true ]]; then log "ok   $1: $3"; else log "FAIL $1: $3"; fi
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
# returns 0 or 1 and leaves its detail in DETAIL. A FUNCTION that sets SKIPPED=1 and returns 0
# did not apply to this run: ok:true with "skipped":true.
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
	SKIPPED=0
	# fd 3 is the summary's: closed for the step and everything it runs.
	if "$@" 3>&-; then
		if [[ $SKIPPED == 1 ]]; then
			record "$name" true "$DETAIL" skipped
		else
			record "$name" true "$DETAIL"
		fi
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
		out+=",\"detail\":\"$REPLY\""
		[[ -z ${S_SKIP[$i]:-} ]] || out+=",\"skipped\":true"
		out+="}"
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

# ms [-C DIR] [-S SCHOOL] LABEL PIN_DIR [VAR=VALUE...] -- ARGS...: one `mastersos` call with the
# fixed global options, run in DIR (default: the work dir, which is not a settings folder), for
# SCHOOL (default: --school-id), stdin from /dev/null. Sets RC and LOG (LOG.out, LOG.err, LOG.flat).
ms() {
	local cwd=$W school=$SCHOOL
	while [[ $1 == -C || $1 == -S ]]; do
		if [[ $1 == -C ]]; then cwd=$2; else school=$2; fi
		shift 2
	done
	local label=$1 pins=$2
	shift 2
	local envs=()
	while [[ $1 != -- ]]; do
		envs+=("$1")
		shift
	done
	shift
	next_log "$label"
	log "mastersos $* (pins ${pins##*/}, in ${cwd#"$W"/}${envs[*]:+, ${envs[*]}})"
	(cd "$cwd" && exec env ${envs[@]+"${envs[@]}"} "$BIN/mastersos" --json --yes \
		--server "$SERVER" --school "$school" --pin-dir "$pins" "$@") \
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

# want PATH VALUE WHAT [TYPE]: the last call's JSON has VALUE at PATH (of TYPE: s, n, b or z,
# as json_flat writes it; default: any).
want() {
	if fget "$LOG.flat" "$1" && [[ $REPLY == "$2" && ( -z ${4:-} || $FTYPE == "$4" ) ]]; then return 0; fi
	DETAIL="$3: expected $1 = $2${4:+ (type $4)}, got ${REPLY:-(absent)}${FTYPE:+ (type $FTYPE)} (log ${LOG##*/})"
	REPLY=""
	return 1
}

# absent PATH WHAT: the last call's JSON has nothing at PATH or below it (PATH.*).
absent() {
	local hit
	hit=$(AB_P=$1 awk -F'\t' 'index($1 ".", ENVIRON["AB_P"] ".") == 1 { print $1; exit }' "$LOG.flat")
	if [[ -z $hit ]]; then return 0; fi
	DETAIL="$2: expected nothing at $1, found $hit (log ${LOG##*/})"
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
# to its base (`nothing_to_publish`), and a comment is a byte change that alters nothing else.
touch_manifest() {
	if ! printf '# e2e: %s\n' "$2" >>"$1/manifest.toml"; then
		DETAIL="cannot append to $1/manifest.toml"
		return 1
	fi
}

# redact KEY FILE...: KEY replaced by <redacted> in each FILE. When that fails the file is
# emptied (or removed), so the key never stays behind, and the status is 1.
redact() {
	local key=$1 f rc=0
	shift
	for f in "$@"; do
		[[ -e $f ]] || continue
		if ! { sed "s/$key/<redacted>/g" "$f" >"$f.tmp" && mv "$f.tmp" "$f"; } 2>/dev/null; then
			: >"$f" 2>/dev/null || rm -f "$f" 2>/dev/null
			rm -f "$f.tmp" 2>/dev/null
			rc=1
		fi
	done
	return $rc
}

# The listing of a folder outside the work dir, to show it did not change ("absent" when missing).
listing() {
	if [[ -e $1 ]]; then
		{ find "$1" -exec ls -ld {} + 2>/dev/null || true; } | sort | cksum || true
	else
		echo absent
	fi
}

# ---- The steps ----

s_preflight() {
	local missing=() c
	for c in awk sed grep curl od tr head stat cksum env ls mkdir chmod mv cat cp base64 date; do
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
	DETAIL="$v1; $v2; control endpoint healthy; work dir $W; second school ${SECOND:-not given}"
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

# The rotation takes two versions: a key that signs must be in the new trust (protocol 4.4, commit
# step 5, `trust_rule`; the command line refuses it first with `key_not_trusted`), so key 1 adds
# key 2 (v2), then key 2 removes key 1 (v3). Every version verifies under its own trust.
s_publish_v2_rotation() {
	ms key-add-k2 "$W/pins-a" -- key add "$W/keys/k2.kit" --dir "$W/a"
	[[ $RC -eq 0 ]] || {
		failed_call "key add k2"
		return
	}
	if ! grep -q "${KID[1]}" "$W/a/manifest.toml" || ! grep -q "${KID[2]}" "$W/a/manifest.toml"; then
		DETAIL="after key add, manifest.toml should trust k1 and k2"
		return 1
	fi
	publish_ok publish-v2 "$W/pins-a" "$W/a" "$W/keys/k1.kit" 2 || return 1
	local hb=$DETAIL
	want trust_change.added.0 "${KID[2]}" "publish v2 trust change" || return 1
	absent trust_change.added.1 "publish v2 trust change (one key added)" || return 1
	absent trust_change.removed.0 "publish v2 trust change (nothing removed)" || return 1
	DETAIL="$hb; trust {k1} -> {k1, k2} and escrow recipients k1 -> k1, k2, signed by k1"
}

s_publish_v3_new_key() {
	# Local only: the manifest changes, and --json prints what was removed.
	ms key-remove-k1 "$W/pins-a" -- key remove "${KCODE[1]}" --key-file "$W/keys/k1.kit" --dir "$W/a"
	[[ $RC -eq 0 ]] || {
		failed_call "key remove k1"
		return
	}
	want removed "${KCODE[1]}" "key remove k1" || return 1
	want trusted.0 "${KCODE[2]}" "key remove k1 (k2 left)" || return 1
	absent trusted.1 "key remove k1 (only k2 left)" || return 1
	want recipient_removed true "key remove k1 (its disk unlocking too)" b || return 1
	absent unmarked.0 "key remove k1 (nothing left unmatched)" || return 1
	if grep -q "${KID[1]}" "$W/a/manifest.toml" || ! grep -q "${KID[2]}" "$W/a/manifest.toml"; then
		DETAIL="after key remove, manifest.toml should trust k2 and not k1"
		return 1
	fi
	if [[ $({ grep -oE 'age1[02-9ac-hj-np-z]{58}' "$W/a/manifest.toml" || true; } | sort -u | wc -l) -ne 1 ]]; then
		DETAIL="after key remove, manifest.toml should hold exactly one escrow recipient (k2's)"
		return 1
	fi
	publish_ok publish-v3 "$W/pins-a" "$W/a" "$W/keys/k2.kit" 3 || return 1
	local hb=$DETAIL
	want trust_change.removed.0 "${KID[1]}" "publish v3 trust change" || return 1
	absent trust_change.removed.1 "publish v3 trust change (one key removed)" || return 1
	absent trust_change.added.0 "publish v3 trust change (nothing added)" || return 1
	DETAIL="$hb; trust {k1, k2} -> {k2} and escrow recipient -> k2 only, signed by k2"
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
	absent trust.1 "verify (exactly one trusted key)" || return 1
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
	absent trust_fingerprints.1 "seed make (exactly one trusted key)" || return 1
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
	want ok true "seed check" b || return 1
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
	if ! { (umask 077 && printf '%s\n' "$RKEY" >"$W/recovery.key") && chmod 600 "$W/recovery.key"; }; then
		DETAIL="cannot write $W/recovery.key"
		return 1
	fi
	local mode
	mode=$(mode_of "$W/recovery.key")
	if [[ $mode != 600 ]]; then
		DETAIL="$W/recovery.key has mode $mode, not 600"
		return 1
	fi
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
	if ! redact "$RKEY" "$LOG.out" "$LOG.flat"; then
		DETAIL="recovery read: removing the recovery key from the logs failed (the logs were emptied)"
		return 1
	fi
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
	touch_manifest "$W/b" "publish attempt with key 1" || return 1
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
	touch_manifest "$W/b" "one more version from b" || return 1
	publish_ok publish-b-k2 "$W/pins-b" "$W/b" "$W/keys/k2.kit" $((LATEST + 1)) || return 1
	touch_manifest "$W/c" "publish attempt on a stale base" || return 1
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
	if ! printf '\n[[trust]]\nid = "%s"\nalg = "ed25519"\npublic_key = "%s"\n' \
		"$UNREG_KEY_ID" "$UNREG_PK_B64" >>"$W/d/manifest.toml"; then
		DETAIL="cannot append to $W/d/manifest.toml"
		return 1
	fi
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
	if ! mv "$W/e/manifest.toml.new" "$W/e/manifest.toml"; then
		DETAIL="cannot replace $W/e/manifest.toml"
		return 1
	fi
	ms publish-e-kiosk "$W/pins-a" -- publish "$W/e" --key-file "$W/keys/k2.kit"
	expect_refusal feature_unsupported || return 1
	if ! fhas "$LOG.flat" 'error\.problems\.[0-9]+\.device_id' "$dev2"; then
		DETAIL="feature_unsupported, but device $dev2 (reported without kiosk) is not in problems (log ${LOG##*/})"
		return 1
	fi
	DETAIL="$DETAIL, listing device $dev2 (reported without kiosk)"
}

# The token must not reach an xtrace: tracing is off while it is in scope.
s_fail_step_up_required() {
	local traced=0 rc=0
	if [[ $- == *x* ]]; then traced=1; fi
	set +x
	step_up_probe || rc=$?
	if [[ $traced == 1 ]]; then set -x; fi
	return "$rc"
}

step_up_probe() {
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
	local n pwd_note="current directory unchanged"
	if [[ $ORIG_PWD == "$W" ]]; then
		pwd_note="current directory not checked (it is the work dir)"
	else
		for n in $OUR_NAMES; do
			if [[ -e $ORIG_PWD/$n && " $BEFORE_PWD_NAMES " != *" $n "* ]]; then
				bad+=("$ORIG_PWD/$n appeared")
			fi
		done
	fi
	if [[ ${#bad[@]} -gt 0 ]]; then
		DETAIL="outside the work dir: ${bad[*]}"
		return 1
	fi
	DETAIL="HOME, XDG_* and TMPDIR were under the work dir; the caller's ~/.config/mastersos unchanged; $pwd_note (best effort)"
}

# ---- The CLI and device APIs with curl, past the command line's local checks ----

# The tokens and fetch tokens below stay in these functions: never printed, logged or written to
# a file, and tracing is off while one is in scope (`quiet`).
quiet() {
	local traced=0 rc=0
	if [[ $- == *x* ]]; then traced=1; fi
	set +x
	"$@" || rc=$?
	if [[ $traced == 1 ]]; then set -x; fi
	return "$rc"
}

# cli_path SCHOOL REST: the path of a CLI API route of SCHOOL.
cli_path() {
	REPLY="/api/cli/v1/schools/$1/mastersos/$2"
}

# api LABEL WHO METHOD PATH [BODY_FILE [CONTENT_TYPE]]: one CLI API request with a token from the
# stub `arbella`. WHO: first or second (the admin; second runs the stub with FLEET_E2E_ADMIN=second),
# with `+` for a step-up token (first+, second+). Sets HTTP (the status, or `(none)`) and LOG
# (LOG.out holds the body as received, LOG.flat its flattened JSON when it is JSON).
api() {
	next_log "$1"
	quiet api_send "$@"
}

api_send() {
	local who=$2 method=$3 path=$4 body=${5:-} ctype=${6:-application/json} out tok
	local envs=() args=(auth token --json)
	[[ $who == second* ]] && envs+=(FLEET_E2E_ADMIN=second)
	[[ $who == *+ ]] && args+=(--step-up)
	local how=""
	[[ $who == *+ ]] && how=" (step-up)"
	log "curl $method $path as the ${who%+} admin$how"
	HTTP="(none)"
	: >"$LOG.out"
	: >"$LOG.flat"
	out=$(env ${envs[@]+"${envs[@]}"} arbella "${args[@]}" 2>>"$LOG.err") || {
		log "arbella auth token failed (log ${LOG##*/})"
		return 0
	}
	tok=$(printf '%s' "$out" | json_flat | awk -F'\t' '$1 == "access_token" && $2 == "s" { print $3; exit }')
	out=""
	if [[ -z $tok || ! $tok =~ ^[A-Za-z0-9._~+/=-]+$ ]]; then
		log "arbella auth token gave no usable access_token"
		return 0
	fi
	local data=()
	if [[ -n $body ]]; then data=(-H "Content-Type: $ctype" --data-binary "@$body"); fi
	HTTP=$(printf 'header = "Authorization: Bearer %s"\n' "$tok" |
		curl -sS --max-time 60 -o "$LOG.out" -w '%{http_code}' -X "$method" ${data[@]+"${data[@]}"} \
			--config - "$SERVER$path" 2>>"$LOG.err") || HTTP="(none)"
	tok=""
	json_flat <"$LOG.out" >"$LOG.flat" 2>/dev/null || : >"$LOG.flat"
}

# dev_get LABEL SEED PATH: GET a device API route (PATH after /api/device/v1/) with the fetch
# token of the seed file SEED. Sets HTTP and LOG as api does (LOG.out: the body as received).
dev_get() {
	next_log "$1"
	quiet dev_send "$@"
}

dev_send() {
	local tok
	HTTP="(none)"
	: >"$LOG.out"
	tok=$(awk '/^fetch_token[ \t]*=/ { sub(/^[^=]*=[ \t]*"/, ""); sub(/"[ \t]*$/, ""); print; exit }' "$2" 2>/dev/null) || tok=""
	if [[ -z $tok || ! $tok =~ ^[!-~]+$ || $tok == *'"'* || $tok == *\\* ]]; then
		log "no usable fetch_token in $2"
		return 0
	fi
	log "curl GET /api/device/v1/$3 with the fetch token of ${2##*/}"
	HTTP=$(printf 'header = "Authorization: Bearer %s"\n' "$tok" |
		curl -sS --max-time 60 -o "$LOG.out" -w '%{http_code}' --config - "$SERVER/api/device/v1/$3" 2>>"$LOG.err") || HTTP="(none)"
	tok=""
}

# The error code of the last api call in REPLY (`(none)` when it has none).
api_code() {
	fget "$LOG.flat" error.code && [[ -n $REPLY ]] || REPLY="(none)"
}

# versions_of FLAT KEY_ID: from a `GET versions` answer, the latest version in V_LATEST and its
# digest in V_LATEST_DIGEST; the newest version signed by KEY_ID in V_BY and its digest in
# V_BY_DIGEST (empty when it signed none).
versions_of() {
	local line
	line=$(awk -F'\t' -v who="$2" '
		{ n = split($1, a, "."); if (n == 2) v[a[1], a[2]] = $3; if (n == 2 && a[1] + 1 > m) m = a[1] + 1 }
		END {
			for (i = 0; i < m; i++) {
				x = v[i, "version"] + 0
				if (x > lat) { lat = x; latd = v[i, "digest_hex"] }
				if (v[i, "signed_by"] == who && x > by) { by = x; byd = v[i, "digest_hex"] }
			}
			printf "%d %s %d %s\n", lat, (latd == "" ? "-" : latd), by, (byd == "" ? "-" : byd)
		}' "$1") || return 1
	read -r V_LATEST V_LATEST_DIGEST V_BY V_BY_DIGEST <<<"$line"
	[[ $V_LATEST_DIGEST != - ]] || V_LATEST_DIGEST=""
	[[ $V_BY_DIGEST != - ]] || V_BY_DIGEST=""
	[[ $V_BY != 0 ]] || V_BY=""
}

# frame_json VERSION OUT: a pending upload's body for the first school, {frame, digest_hex}, with
# the frame of the server's latest trust and escrow recipients (from GET keys and GET
# escrow-recipients) at VERSION, issued now, using nothing new (features_used empty), and
# digest_hex $FRAME_DIGEST. The command line computes the frame from the text it signs; here it
# is built by hand so the server, not the command line, decides.
frame_json() {
	local trust recipients format
	cli_path "$SCHOOL" keys
	api frame-keys first GET "$REPLY"
	if [[ $HTTP != 200 ]]; then
		DETAIL="GET keys: HTTP $HTTP (log ${LOG##*/})"
		return 1
	fi
	trust=$(awk -F'\t' '
		{ n = split($1, a, "."); if (n == 2) { v[a[1], a[2]] = $3; if (a[1] + 1 > m) m = a[1] + 1 } }
		END {
			for (i = 0; i < m; i++) if (v[i, "in_latest_trust"] == "true") {
				printf "%s{\"id\":\"%s\",\"alg\":\"%s\",\"public_key\":\"%s\"}", sep, v[i, "key_id"], v[i, "alg"], v[i, "public_key"]
				sep = ","
			}
		}' "$LOG.flat")
	local trust_re='^[][{}":,A-Za-z0-9+/=_-]+$' rec_re='^[",a-z0-9]*$'
	if [[ -z $trust || ! $trust =~ $trust_re ]]; then
		DETAIL="GET keys: no usable key in the latest trust (log ${LOG##*/})"
		return 1
	fi
	cli_path "$SCHOOL" escrow-recipients
	api frame-recipients first GET "$REPLY"
	if [[ $HTTP != 200 ]]; then
		DETAIL="GET escrow-recipients: HTTP $HTTP (log ${LOG##*/})"
		return 1
	fi
	recipients=$(awk -F'\t' '
		{ n = split($1, a, "."); if (n == 2) { v[a[1], a[2]] = $3; if (a[1] + 1 > m) m = a[1] + 1 } }
		END { for (i = 0; i < m; i++) if (v[i, "in_latest"] == "true") { printf "%s\"%s\"", sep, v[i, "recipient"]; sep = "," } }' "$LOG.flat")
	if [[ ! $recipients =~ $rec_re ]]; then
		DETAIL="GET escrow-recipients: an unexpected recipient (log ${LOG##*/})"
		return 1
	fi
	format=$(awk '/^format[ \t]*=[ \t]*[0-9]+[ \t]*$/ { sub(/^[^=]*=[ \t]*/, ""); print $1; exit }' "$W/a/manifest.toml" 2>/dev/null)
	printf '{"frame":{"format":%s,"version":%s,"issued_at":"%s","school_id":"%s","trust":[%s],"escrow_recipients":[%s],"features_used":[]},"digest_hex":"%s"}\n' \
		"${format:-1}" "$1" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$SCHOOL" "$trust" "$recipients" "$FRAME_DIGEST" >"$2"
}

# drop_pending ID: delete a pending upload (best effort).
drop_pending() {
	cli_path "$SCHOOL" "publish/pending/$1"
	api drop-pending first DELETE "$REPLY"
}

# ---- Steps against the server's own checks ----

# A version's archive signed by key 1, which is registered but left the trust at version 3, is
# committed as the next version: the pending upload names that archive's content digest, and the
# archive is sent byte for byte as stored. Its signature is a real one of key 1 (nothing here can
# sign); the command line refuses the same locally (`key_not_trusted`, fail_wrong_key).
s_server_refuses_untrusted_signature() {
	cli_path "$SCHOOL" versions
	api versions first GET "$REPLY"
	if [[ $HTTP != 200 ]]; then
		DETAIL="GET versions: HTTP $HTTP (log ${LOG##*/})"
		return 1
	fi
	versions_of "$LOG.flat" "${KID[1]}" || {
		DETAIL="GET versions: not readable (log ${LOG##*/})"
		return 1
	}
	if [[ -z $V_BY || ! $V_BY_DIGEST =~ ^[0-9a-f]{64}$ ]]; then
		DETAIL="GET versions: no version signed by k1 (${KID[1]}) with a digest (log ${LOG##*/})"
		return 1
	fi
	local latest=$V_LATEST old=$V_BY archive pid code
	mkdir -p "$W/api"
	archive=$W/api/v$old-by-k1.tar.gz
	cli_path "$SCHOOL" "versions/$old/archive"
	api "archive-v$old" first GET "$REPLY"
	if [[ $HTTP != 200 ]] || ! cp "$LOG.out" "$archive"; then
		DETAIL="GET versions/$old/archive: HTTP $HTTP (log ${LOG##*/})"
		return 1
	fi
	FRAME_DIGEST=$V_BY_DIGEST
	frame_json $((latest + 1)) "$W/api/untrusted-pending.json" || return 1
	cli_path "$SCHOOL" publish/pending
	api untrusted-pending first POST "$REPLY" "$W/api/untrusted-pending.json"
	if [[ $HTTP != 201 ]] || ! fget "$LOG.flat" pending_id || [[ ! $REPLY =~ ^[0-9a-f-]{36}$ ]]; then
		api_code
		DETAIL="POST publish/pending (version $((latest + 1)), digest of v$old): expected 201 with a pending_id, got HTTP $HTTP $REPLY (log ${LOG##*/})"
		return 1
	fi
	pid=$REPLY
	if ! want digest_hex "$V_BY_DIGEST" "POST publish/pending echo"; then
		drop_pending "$pid"
		return 1
	fi
	cli_path "$SCHOOL" "publish/pending/$pid/commit"
	api untrusted-commit first POST "$REPLY" "$archive" application/gzip
	local status=$HTTP commit_log=${LOG##*/}
	api_code
	code=$REPLY
	drop_pending "$pid"
	cli_path "$SCHOOL" versions
	api versions-after first GET "$REPLY"
	versions_of "$LOG.flat" "${KID[1]}" || V_LATEST="?"
	if [[ $V_LATEST != "$latest" ]]; then
		DETAIL="commit answered HTTP $status $code, and the latest version is now $V_LATEST, not $latest (log $commit_log)"
		return 1
	fi
	if [[ ! $status =~ ^4[0-9][0-9]$ || $code == "(none)" ]]; then
		DETAIL="commit of v$old's archive (signed by k1) as version $((latest + 1)): expected a 4xx with an error code, got HTTP $status $code (log $commit_log)"
		return 1
	fi
	case $code in
	digest_mismatch | archive_invalid | version_conflict | pending_expired | invalid | not_found | too_large | feature_unsupported | unauthenticated | step_up_required)
		DETAIL="commit refused before the signature was judged: HTTP $status $code (log $commit_log)"
		return 1
		;;
	esac
	DETAIL="commit of v$old's archive (a real signature of k1, out of trust since v3) as version $((latest + 1)): HTTP $status $code (protocol 4.4 commit step 4 names 422 signature_invalid); latest still $latest"
}

# A pending upload whose version is the latest (a stale base: not latest+1), sent with curl: the
# command line refuses it locally first (fail_stale_version).
s_server_refuses_stale_base() {
	cli_path "$SCHOOL" versions
	api versions first GET "$REPLY"
	if [[ $HTTP != 200 ]] || ! versions_of "$LOG.flat" "${KID[2]}" || [[ ! $V_LATEST_DIGEST =~ ^[0-9a-f]{64}$ ]]; then
		DETAIL="GET versions: HTTP $HTTP, no latest version (log ${LOG##*/})"
		return 1
	fi
	local latest=$V_LATEST
	FRAME_DIGEST=$V_LATEST_DIGEST
	mkdir -p "$W/api"
	frame_json "$latest" "$W/api/stale-pending.json" || return 1
	cli_path "$SCHOOL" publish/pending
	api stale-pending first POST "$REPLY" "$W/api/stale-pending.json"
	api_code
	local code=$REPLY
	if [[ $HTTP == 201 ]]; then
		fget "$LOG.flat" pending_id && drop_pending "$REPLY"
		DETAIL="POST publish/pending with version $latest (latest $latest): accepted (201), expected 409 version_conflict"
		return 1
	fi
	if [[ $HTTP != 409 || $code != version_conflict ]]; then
		DETAIL="POST publish/pending with version $latest: expected 409 version_conflict, got HTTP $HTTP $code (log ${LOG##*/})"
		return 1
	fi
	want error.details.latest_version "$latest" "409 version_conflict" n || return 1
	DETAIL="POST publish/pending with version $latest (latest $latest): HTTP 409 version_conflict, details.latest_version $latest"
}

# expect_http WANT_STATUS WANT_CODE WHAT: the last api call answered so; DETAIL on failure.
expect_http() {
	api_code
	if [[ $HTTP == "$1" && $REPLY == "$2" ]]; then return 0; fi
	DETAIL="$3: expected $1 $2, got HTTP $HTTP $REPLY (log ${LOG##*/})"
	return 1
}

# Each admin on the other school's routes, with curl (routes without step-up, so the answer is
# about the school) and with the command line.
s_cross_school_cli_refused() {
	if [[ -z $SECOND ]]; then
		SKIPPED=1
		DETAIL="no --second-school-id"
		return 0
	fi
	local route who school checked=()
	for who in first second; do
		if [[ $who == first ]]; then school=$SECOND; else school=$SCHOOL; fi
		for route in keys versions; do
			cli_path "$school" "$route"
			api "cross-$who-$route" "$who" GET "$REPLY"
			expect_http 403 forbidden "the $who admin: GET $route of the other school" || return 1
			checked+=("$who admin GET $route: 403 forbidden")
		done
	done
	ms -S "$SECOND" cross-cli-first "$W/pins-s2" -- key list
	expect_refusal forbidden || {
		DETAIL="mastersos key list as the first admin on the second school: $DETAIL"
		return 1
	}
	ms cross-cli-second "$W/pins-a" FLEET_E2E_ADMIN=second -- key list
	expect_refusal forbidden || {
		DETAIL="mastersos key list as the second admin on the first school: $DETAIL"
		return 1
	}
	DETAIL="$(
		IFS=';'
		printf "%s" "${checked[*]}"
	); mastersos key list refused with forbidden both ways"
}

# The second school with its own key and version 1; its seed reaches only its versions, and the
# first school's fetch token never yields its archive.
s_cross_school_device_isolated() {
	if [[ -z $SECOND ]]; then
		SKIPPED=1
		DETAIL="no --second-school-id"
		return 0
	fi
	local f k4id k4fp
	ms -S "$SECOND" key-new-k4 "$W/pins-s2" -- key new --out "$W/keys/k4.kit"
	[[ $RC -eq 0 ]] || {
		failed_call "key new k4"
		return
	}
	for f in key_id fingerprint; do
		if ! fget "$LOG.flat" "$f" || [[ -z $REPLY ]]; then
			DETAIL="key new k4: no $f in its answer (log ${LOG##*/})"
			return 1
		fi
		if [[ $f == key_id ]]; then k4id=$REPLY; else k4fp=$REPLY; fi
	done
	ms -S "$SECOND" key-register-k4 "$W/pins-s2" FLEET_E2E_ADMIN=second -- key register --key-file "$W/keys/k4.kit" --label "e2e second school key"
	[[ $RC -eq 0 ]] || {
		failed_call "key register k4 (second admin)"
		return
	}
	ms -S "$SECOND" init-s2 "$W/pins-s2" FLEET_E2E_ADMIN=second -- init "$W/s2" --key-file "$W/keys/k4.kit"
	[[ $RC -eq 0 ]] || {
		failed_call "init of the second school"
		return
	}
	ms -S "$SECOND" publish-s2 "$W/pins-s2" FLEET_E2E_ADMIN=second -- publish "$W/s2" --key-file "$W/keys/k4.kit"
	[[ $RC -eq 0 ]] || {
		failed_call "publish of the second school"
		return
	}
	want version 1 "publish of the second school" || return 1
	ms -S "$SECOND" seed-make-s2 "$W/pins-s2" FLEET_E2E_ADMIN=second -- seed make --out "$W/seed-s2.toml"
	[[ $RC -eq 0 ]] || {
		failed_call "seed make for the second school"
		return
	}
	want min_version 1 "seed make for the second school" || return 1
	want trust_fingerprints.0.fingerprint "$k4fp" "seed make for the second school" || return 1
	absent trust_fingerprints.1 "seed make for the second school (only k4)" || return 1
	agent protocol-check-s2 protocol-check --seed "$W/seed-s2.toml" --state "$W/dev-s2" --json
	check_report "protocol-check of a second-school device" || return 1
	local devs2=$DEVICE
	if ! { call_get "$LOG.flat" bundle version && [[ $REPLY == 1 ]]; }; then
		DETAIL="protocol-check of a second-school device: its first bundle is not version 1 (got ${REPLY:-none}): $CALLS (log ${LOG##*/})"
		return 1
	fi
	# The device is listed by its own school only.
	cli_path "$SECOND" devices
	api devices-s2 second GET "$REPLY"
	if [[ $HTTP != 200 ]] || ! fhas "$LOG.flat" '[0-9]+\.device_id' "$devs2"; then
		DETAIL="GET devices of the second school: HTTP $HTTP, device $devs2 not listed (log ${LOG##*/})"
		return 1
	fi
	cli_path "$SCHOOL" devices
	api devices-first first GET "$REPLY"
	if [[ $HTTP != 200 ]] || fhas "$LOG.flat" '[0-9]+\.device_id' "$devs2"; then
		DETAIL="GET devices of the first school: HTTP $HTTP, or it lists the second school's device $devs2 (log ${LOG##*/})"
		return 1
	fi
	# Archives as published, to compare with what each fetch token gets.
	mkdir -p "$W/api"
	cli_path "$SECOND" versions/1/archive
	api archive-s2-v1 second GET "$REPLY"
	if [[ $HTTP != 200 ]] || ! cp "$LOG.out" "$W/api/s2-v1.tar.gz"; then
		DETAIL="GET versions/1/archive of the second school: HTTP $HTTP (log ${LOG##*/})"
		return 1
	fi
	cli_path "$SCHOOL" versions
	api versions-first first GET "$REPLY"
	if [[ $HTTP != 200 ]] || ! versions_of "$LOG.flat" "${KID[2]}"; then
		DETAIL="GET versions of the first school: HTTP $HTTP (log ${LOG##*/})"
		return 1
	fi
	local latest=$V_LATEST
	cli_path "$SCHOOL" "versions/$latest/archive"
	api archive-first-latest first GET "$REPLY"
	if [[ $HTTP != 200 ]] || ! cp "$LOG.out" "$W/api/first-latest.tar.gz"; then
		DETAIL="GET versions/$latest/archive of the first school: HTTP $HTTP (log ${LOG##*/})"
		return 1
	fi
	local s2sum firstsum
	s2sum=$(cksum <"$W/api/s2-v1.tar.gz")
	firstsum=$(cksum <"$W/api/first-latest.tar.gz")
	# The second school's token: its v1, and nothing after v1 although the first school is at v$latest.
	dev_get bundle-s2 "$W/seed-s2.toml" bundle
	if [[ $HTTP != 200 || $(cksum <"$LOG.out") != "$s2sum" ]]; then
		DETAIL="GET bundle with the second school's fetch token: HTTP $HTTP, not its version 1 archive (log ${LOG##*/})"
		return 1
	fi
	dev_get bundle-s2-after-1 "$W/seed-s2.toml" "bundle?after=1"
	if [[ $HTTP != 204 ]]; then
		DETAIL="GET bundle?after=1 with the second school's fetch token: expected 204, got HTTP $HTTP (log ${LOG##*/})"
		return 1
	fi
	# The first school's current fetch token (a new seed: seed.toml's token was dropped).
	seed_make seed-make-iso "$W/seed-iso.toml" || return 1
	dev_get bundle-first "$W/seed-iso.toml" bundle
	if [[ $HTTP != 200 || $(cksum <"$LOG.out") != "$firstsum" ]]; then
		DETAIL="GET bundle with the first school's fetch token: HTTP $HTTP, not the first school's version $latest archive (log ${LOG##*/})"
		return 1
	fi
	local after
	for after in 0 1; do
		dev_get "bundle-first-after-$after" "$W/seed-iso.toml" "bundle?after=$after"
		if [[ $HTTP != 200 || $(cksum <"$LOG.out") == "$s2sum" ]]; then
			DETAIL="GET bundle?after=$after with the first school's fetch token: HTTP $HTTP, or the second school's archive (log ${LOG##*/})"
			return 1
		fi
	done
	DETAIL="second school: k4 ($k4id) registered, init and version 1 by its admin; its seed (trust {k4}) gave device $devs2 version 1 and 204 after 1; listed only by its school; the first school's token gets its own v$latest (after 0 and 1 too), never the second school's archive"
}

# A device secret reset (protocol 3.1, 4.8, 5.6): before it, another secret for the same device id
# is refused; the reset needs step-up; after it the next request registers again (here a new
# secret, sent first), the old secret is then refused, and the recovery-key rows stay.
s_escrow_secret_reset() {
	seed_make seed-make-3 "$W/seed3.toml" || return 1
	gen_recovery_key || {
		DETAIL="cannot make a recovery key"
		return 1
	}
	local rkey3=$REPLY luks3 dev3 secret2
	if ! { (umask 077 && printf '%s\n' "$rkey3" >"$W/recovery3.key") && chmod 600 "$W/recovery3.key"; }; then
		DETAIL="cannot write $W/recovery3.key"
		return 1
	fi
	gen_uuid || {
		DETAIL="cannot make a LUKS UUID"
		return 1
	}
	luks3=$REPLY
	# 1. The device registers its secret (status) and escrows a recovery key.
	agent protocol-check-dev3 protocol-check --seed "$W/seed3.toml" --state "$W/dev3" --json \
		--recovery-key "$W/recovery3.key" --luks-uuid "$luks3"
	check_report "protocol-check of device 3" || return 1
	dev3=$DEVICE
	if ! { call_get "$LOG.flat" escrow skipped && [[ $REPLY == false ]]; }; then
		DETAIL="protocol-check of device 3: the escrow call did not run ($CALLS)"
		return 1
	fi
	# 2. The same device id with another secret (a second DIR holding its identity.json).
	secret2=$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n') || secret2=""
	if [[ ! $secret2 =~ ^[A-Za-z0-9_-]{43}$ ]]; then
		DETAIL="cannot make a device secret"
		return 1
	fi
	if ! { mkdir -p "$W/dev3b/seed-partition" && chmod 700 "$W/dev3b" "$W/dev3b/seed-partition" &&
		(umask 077 && printf '{"device_id":"%s","escrow_secret":"%s"}\n' "$dev3" "$secret2" >"$W/dev3b/seed-partition/identity.json"); }; then
		DETAIL="cannot write $W/dev3b/seed-partition/identity.json"
		return 1
	fi
	secret2=""
	agent protocol-check-dev3b-before protocol-check --seed "$W/seed3.toml" --state "$W/dev3b" --json
	if ! { call_get "$LOG.flat" status error_code && [[ $REPLY == secret_mismatch ]] &&
		call_get "$LOG.flat" status status && [[ $REPLY == 403 ]]; }; then
		calls_line "$LOG.flat"
		DETAIL="before the reset, another secret for device $dev3: expected status 403 secret_mismatch, got $REPLY (log ${LOG##*/})"
		return 1
	fi
	# 3. The reset: refused without step-up, then done with it.
	cli_path "$SCHOOL" "devices/$dev3/escrow-secret"
	local route=$REPLY
	api reset-plain first DELETE "$route"
	expect_http 401 step_up_required "DELETE escrow-secret with a plain token" || return 1
	api reset-step-up first+ DELETE "$route"
	local reset_status=$HTTP
	if [[ ! $HTTP =~ ^2[0-9][0-9]$ ]]; then
		api_code
		DETAIL="DELETE escrow-secret with a step-up token: expected 2xx, got HTTP $HTTP $REPLY (log ${LOG##*/})"
		return 1
	fi
	# 4. The next request registers again: the new secret, sent first.
	agent protocol-check-dev3b-after protocol-check --seed "$W/seed3.toml" --state "$W/dev3b" --json
	check_report "after the reset, the same device id with a new secret" || return 1
	if [[ $DEVICE != "$dev3" ]] || ! { call_get "$LOG.flat" status ok && [[ $REPLY == true ]] &&
		call_get "$LOG.flat" status skipped && [[ $REPLY == false ]]; }; then
		DETAIL="after the reset, device $dev3 with a new secret: status not sent and accepted ($CALLS)"
		return 1
	fi
	local after=$CALLS
	# 5. The old secret is refused now.
	agent protocol-check-dev3-old protocol-check --seed "$W/seed3.toml" --state "$W/dev3" --json
	if ! { call_get "$LOG.flat" status error_code && [[ $REPLY == secret_mismatch ]] &&
		call_get "$LOG.flat" status status && [[ $REPLY == 403 ]]; }; then
		calls_line "$LOG.flat"
		DETAIL="after the reset and re-registration, the old secret: expected status 403 secret_mismatch, got $REPLY (log ${LOG##*/})"
		return 1
	fi
	# 6. The recovery-key rows stay.
	ms recovery-read-3 "$W/pins-a" -- recovery read "$dev3" --key-file "$W/keys/k2.kit"
	local found=1
	if [[ $RC -eq 0 ]] && fhas "$LOG.flat" '[0-9]+\.recovery_key' "$rkey3"; then found=0; fi
	if ! redact "$rkey3" "$LOG.out" "$LOG.flat"; then
		DETAIL="recovery read: removing the recovery key from the logs failed (the logs were emptied)"
		return 1
	fi
	[[ $RC -eq 0 ]] || {
		failed_call "recovery read after the reset"
		return
	}
	if [[ $found -ne 0 ]]; then
		DETAIL="after the reset the escrowed recovery key of $dev3 is gone (log ${LOG##*/})"
		return 1
	fi
	DETAIL="device $dev3: another secret refused (403 secret_mismatch); DELETE escrow-secret 401 step_up_required, then $reset_status with step-up; a new secret registered again ($after); the old secret then 403 secret_mismatch; the recovery key still opens with k2"
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

	# fget clears REPLY, so a failure never shows the value of an earlier lookup.
	tmp=$(mktemp -d)
	printf '%s' '{"ok":"true","b":true,"t":[{"f":"x"}]}' | json_flat >"$tmp/c.flat"
	fget "$tmp/c.flat" b
	fget "$tmp/c.flat" missing || true
	st fget-clears "[$REPLY][$FTYPE]" '[][]' 'fget of an absent path clears REPLY and FTYPE'
	# want with a type: the string "true" is not the boolean true.
	LOG=$tmp/c
	if want ok true "t" b; then st want-type string-accepted refused 'want ok true b'; else st want-type refused refused 'want refuses the string "true" as a boolean'; fi
	if want b true "t" b; then st want-bool ok ok 'want accepts a JSON boolean'; else st want-bool "$DETAIL" ok 'want accepts a JSON boolean'; fi
	if absent t.1 "t"; then st absent ok ok 'absent: no second entry'; else st absent "$DETAIL" ok 'absent: no second entry'; fi
	if absent t.0.f "t"; then st absent-leaf ok refused 'absent of a present leaf'; else st absent-leaf refused refused 'absent of a present leaf'; fi
	if absent t.0.ff "t"; then st absent-prefix ok ok 'absent does not match a longer name'; else st absent-prefix "$DETAIL" ok 'absent does not match a longer name'; fi
	if absent t.0 "t"; then st absent-present ok refused 'absent of a present entry'; else st absent-present refused refused 'absent of a present entry'; fi
	# Every step has its function, and depends only on earlier steps.
	local seen=" " wrong="" stp dep deps
	for stp in "${STEPS[@]}"; do
		declare -F "s_${stp%%:*}" >/dev/null || wrong+=" no s_${stp%%:*};"
		deps=()
		IFS=, read -r -a deps <<<"${stp#*:}"
		for dep in ${deps[@]+"${deps[@]}"}; do
			[[ $seen == *" $dep "* ]] || wrong+=" ${stp%%:*} needs later or unknown $dep;"
		done
		seen+="${stp%%:*} "
	done
	st step-table "${wrong:-ok}" ok 'every step has a function and depends on earlier steps only'
	# listing survives an unreadable folder (pipefail and errexit are on here).
	mkdir -p "$tmp/l/locked" && chmod 000 "$tmp/l/locked"
	local lst
	lst=$(listing "$tmp/l")
	chmod 700 "$tmp/l/locked"
	st listing "$([[ -n $lst ]] && echo ok)" ok 'listing of a folder with an unreadable subfolder'
	st listing-absent "$(listing "$tmp/none")" absent 'listing of a missing folder'
	# redact replaces the key; when it cannot write, the file is emptied and the status is 1.
	printf 'a cbdefghi-x b\n' >"$tmp/r.out"
	if redact cbdefghi-x "$tmp/r.out"; then st redact "$(cat "$tmp/r.out")" 'a <redacted> b' 'redact'; else st redact failed ok 'redact'; fi
	mkdir "$tmp/ro" && printf 'key cbdefghi-x\n' >"$tmp/ro/f" && chmod 500 "$tmp/ro"
	if redact cbdefghi-x "$tmp/ro/f"; then st redact-fail succeeded failed 'redact in a read-only folder'; else st redact-fail "failed/$(cat "$tmp/ro/f")" 'failed/' 'redact in a read-only folder fails and leaves no key'; fi
	chmod 700 "$tmp/ro"
	rm -rf "$tmp"
	# fd 3 (the summary) is closed for the steps.
	fd3_closed() {
		if { : >&3; } 2>/dev/null; then DETAIL="fd 3 is open in a step"; return 1; fi
		DETAIL="fd 3 is closed in a step"
	}
	run_step fd3-closed -- fd3_closed
	# versions_of: the latest version, and the newest one a key signed.
	tmp=$(mktemp)
	printf '%s' '[{"version":1,"signed_by":"rk-a","digest_hex":"d1"},{"version":3,"signed_by":"rk-b","digest_hex":"d3"},{"version":2,"signed_by":"rk-a","digest_hex":"d2"}]' | json_flat >"$tmp"
	versions_of "$tmp" rk-a
	st versions-of "$V_LATEST $V_LATEST_DIGEST $V_BY $V_BY_DIGEST" '3 d3 2 d2' 'versions_of: latest, and the newest a key signed'
	versions_of "$tmp" rk-z
	st versions-of-none "[$V_BY][$V_BY_DIGEST]" '[][]' 'versions_of: a key that signed nothing'
	rm -f "$tmp"
	# A step that does not apply is ok and marked skipped; the summary stays ok.
	not_here() {
		SKIPPED=1
		DETAIL="not here"
	}
	local sum
	sum=$(
		S_NAME=() S_OK=() S_DETAIL=() S_SKIP=()
		run_step a -- not_here 2>/dev/null
		record b true "fine" 2>/dev/null
		print_summary 3>&1 || echo " rc=1"
	)
	st skipped-summary "$sum" '{"ok":true,"server_url":"self-test","school_id":"","steps":[{"name":"a","ok":true,"detail":"not here","skipped":true},{"name":"b","ok":true,"detail":"fine"}]}' 'a skipped step is ok:true with "skipped":true'

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

SERVER="" SCHOOL="" STUB="" CONTROL="" BIN="" W="" SECOND=""
MODE=run
while [[ $# -gt 0 ]]; do
	case $1 in
	--help | -h)
		usage
		exit 0
		;;
	--dry-run) MODE=dry ;;
	--self-test) MODE=self ;;
	--server-url | --school-id | --arbella-stub | --control-url | --bin-dir | --work-dir | --second-school-id)
		[[ $# -ge 2 && -n $2 ]] || die_usage "$1 needs a value"
		case $1 in
		--server-url) SERVER=$2 ;;
		--school-id) SCHOOL=$2 ;;
		--arbella-stub) STUB=$2 ;;
		--control-url) CONTROL=$2 ;;
		--bin-dir) BIN=$2 ;;
		--work-dir) W=$2 ;;
		--second-school-id) SECOND=$2 ;;
		esac
		shift
		;;
	--server-url=* | --school-id=* | --arbella-stub=* | --control-url=* | --bin-dir=* | --work-dir=* | --second-school-id=*)
		set -- "${1%%=*}" "${1#*=}" "${@:2}"
		continue
		;;
	*) die_usage "unknown argument: $1" ;;
	esac
	shift
done

if [[ $MODE == dry ]]; then
	for st in "${STEPS[@]}"; do printf '%s\n' "${st%%:*}"; done
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
if [[ -n $SECOND ]]; then
	[[ $SECOND =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] ||
		die_usage "--second-school-id must be a lowercase UUID"
	[[ $SECOND != "$SCHOOL" ]] || die_usage "--second-school-id must differ from --school-id"
fi
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

for st in "${STEPS[@]}"; do
	deps=()
	IFS=, read -r -a deps <<<"${st#*:}"
	run_step "${st%%:*}" ${deps[@]+"${deps[@]}"} -- "s_${st%%:*}"
done

if print_summary; then exit 0; else exit 1; fi
