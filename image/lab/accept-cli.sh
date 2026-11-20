#!/bin/bash
# The protocol v1 `mastersos` command line on the lab build VM, shared by accept-common.sh (4a, 4b) and accept-5.sh.
# Sourced, never run. It replaces the old server's admin API: settings are published, devices and recovery keys are read
# and seeds are made with `mastersos --json --yes` running on the build VM, against the server team's lab harness.
#
# Environment (all four required; a missing one fails with a message):
#   LAB_SERVER_URL    the harness server, as the build VM's command line reaches it (https, or http on loopback)
#   LAB_SCHOOL_ID     the lab school (lowercase UUID)
#   LAB_CONTROL_URL   the harness control endpoint, as the build VM reaches it (operator commands POST here)
#   LAB_ARBELLA_STUB  absolute path, on the build VM, of the folder holding the stub `arbella` (put first on PATH; it
#                     answers with FLEET_E2E_CONTROL=$LAB_CONTROL_URL, the same contract as tools/e2e/protocol-v1.sh)
# Optional:
#   LAB_BIN_DIR       absolute path, on the build VM, of the folder holding `mastersos` (default: already on PATH)
#   LAB_KEY_FILE      the lab school key file on this Mac (default $cfg/mastersos-lab-school.kit)
#   LAB_TRUST_FP_FILE fingerprints (xxxx-xxxx-xxxx-xxxx, one per line) of every key in the lab school's trust, on this
#                     Mac (default $cfg/mastersos-lab-school.fp); only the first use of a fresh pin folder reads them
#   LAB_RUN           the function that runs a command on the build VM (default b161; accept-5.sh sets bld)
# The caller sets: cfg (the Mac's lab config folder), state (0700 folder), and defines log.
#
# Secrets: the school key file reaches the build VM over stdin only (0600 under ~/accept-cli/<school>/); settings that may
# hold Wi-Fi keys travel as a tar stream on stdin and are removed from the VM when the publish ends; recovery keys and
# seeds come back on stdout only. Nothing secret is ever on a command line or in a log.
# shellcheck shell=bash disable=SC2016,SC2029,SC2154
set -euo pipefail

lab_run() { "${LAB_RUN:-b161}" "$@"; }
lab_q() { printf '%q' "$1"; }
lab_dir() { echo "accept-cli/$LAB_SCHOOL_ID"; }

lab_env_check() {
	local v miss=""
	for v in LAB_SERVER_URL LAB_SCHOOL_ID LAB_CONTROL_URL LAB_ARBELLA_STUB; do
		[ -n "${!v:-}" ] || miss="$miss $v"
	done
	if [ -n "$miss" ]; then
		echo "accept: these are not set:$miss (the server team's lab harness on the build VM; see image/lab/accept-cli.sh)" >&2
		return 1
	fi
	[[ $LAB_SCHOOL_ID =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || {
		echo "accept: LAB_SCHOOL_ID is not a lowercase UUID" >&2
		return 1
	}
	[[ $LAB_ARBELLA_STUB == /* && ${LAB_BIN_DIR:-/} == /* ]] || {
		echo "accept: LAB_ARBELLA_STUB and LAB_BIN_DIR must be absolute paths on the build VM" >&2
		return 1
	}
	local kf=${LAB_KEY_FILE:-$cfg/mastersos-lab-school.kit} mode
	[ -r "$kf" ] || {
		echo "accept: the lab school key file $kf is not readable (LAB_KEY_FILE)" >&2
		return 1
	}
	mode=$(stat -c %a "$kf" 2>/dev/null || stat -f %Lp "$kf")
	case "$mode" in 600 | 400) ;; *) echo "accept: warning: the lab school key file $kf has mode $mode, expected 600 (chmod 600 it)" >&2 ;; esac
}

# The environment the command line runs in on the build VM: the stub arbella first on PATH, the control endpoint for it.
lab_pre() {
	printf 'PATH=%s:%s$PATH FLEET_E2E_CONTROL=%s' "$(lab_q "$LAB_ARBELLA_STUB")" "${LAB_BIN_DIR:+$(lab_q "$LAB_BIN_DIR"):}" "$(lab_q "$LAB_CONTROL_URL")"
}

# --trust-fingerprint for every key of the lab school's trust (first use of a pin folder; harmless afterwards).
lab_fps() {
	local f=${LAB_TRUST_FP_FILE:-$cfg/mastersos-lab-school.fp}
	[ -r "$f" ] || return 0
	{ grep -E '^[0-9a-f]{4}(-[0-9a-f]{4}){3}$' "$f" || true; } | sed 's/^/--trust-fingerprint /' | tr '\n' ' '
}

# Copy the school key file to the build VM once per script run (stdin, 0600).
lab_setup() {
	[ ! -e "$state/cli-ready.$$" ] || return 0
	lab_env_check || return 1
	local d
	d=$(lab_dir)
	lab_run "umask 077 && mkdir -p -m 700 $d/pins && cat > $d/school.kit.new && mv $d/school.kit.new $d/school.kit && chmod 600 $d/school.kit" <"${LAB_KEY_FILE:-$cfg/mastersos-lab-school.kit}" || return 1
	: >"$state/cli-ready.$$"
}

# cli <mastersos arguments…>: one command on the build VM, in ~/accept-cli/<school>/ (school.kit and pins/ are there).
# stdout is the command's JSON (also its error object); the status is the command's.
cli() {
	local a args=""
	lab_setup || return 1
	for a in "$@"; do args="$args $(lab_q "$a")"; done
	lab_run "cd $(lab_dir) && umask 077 && $(lab_pre) mastersos --json --yes --server $(lab_q "$LAB_SERVER_URL") --school $(lab_q "$LAB_SCHOOL_ID") --pin-dir pins $(lab_fps)$args"
}

# The operator commands of the harness (the server team's control endpoint): rotate | drop-retired.
lab_operator() {
	case "$1" in rotate | drop-retired) ;; *) return 2 ;; esac
	lab_env_check || return 1
	lab_run "curl -fsS --max-time 30 -X POST -o /dev/null $(lab_q "$LAB_CONTROL_URL/fetch-token/$1")"
}

# The remote half of publish_manifest. It reads a tar stream (manifest.toml, files/…) on stdin, gets the school's current
# settings folder (init when nothing is published, else pull), keeps that folder's trust and escrow recipients, puts the
# given manifest and files over the rest, and publishes with the school key file.
LAB_PUBLISH_REMOTE='
set -eu
umask 077
server=$1 school=$2
shift 2
fps=("$@")
run() { mastersos --json --yes --server "$server" --school "$school" --pin-dir pins "${fps[@]}" "$@"; }
trap "rm -rf in wd" EXIT
rm -rf in wd
mkdir in
tar -xf - -C in
if ! out=$(run init wd --key-file school.kit); then
	case $out in
	*version_conflict*)
		rm -rf wd
		out=$(run pull wd) || { printf "%s\n" "$out"; exit 1; }
		;;
	*) printf "%s\n" "$out"; exit 1 ;;
	esac
fi
fmt=$(sed -n "/^\\[/q;/^format[[:space:]]*=/p" wd/manifest.toml | head -1)
if grep -q "^format[[:space:]]*=" in/manifest.toml; then fmt=""; fi
schoolpart=$(awk "/^\\[/{if(!d)s=(\$0==\"[school]\")} s&&!d&&/^(id|escrow_recipients)[[:space:]]*=/{print;d=gsub(/\\[/,\"[\")-gsub(/\\]/,\"]\");next} d>0{print;d+=gsub(/\\[/,\"[\")-gsub(/\\]/,\"]\")}" wd/manifest.toml)
trust=$(awk "/^\\[\\[trust\\]\\]/{p=1;print;next} /^\\[/{p=0} p" wd/manifest.toml)
inserted=0
{
	[ -z "$fmt" ] || printf "%s\n" "$fmt"
	while IFS= read -r line || [ -n "$line" ]; do
		printf "%s\n" "$line"
		if [ "$inserted" = 0 ] && [ "$line" = "[school]" ]; then
			printf "%s\n" "$schoolpart"
			inserted=1
		fi
	done <in/manifest.toml
	printf "\n%s\n" "$trust"
} >wd/manifest.toml.new
[ "$inserted" = 1 ] || { echo "{\"error\":{\"code\":\"lab_manifest_without_school\",\"message\":\"the manifest has no [school] table\",\"problems\":[]}}"; exit 1; }
mv wd/manifest.toml.new wd/manifest.toml
if [ -d in/files ]; then cp -R in/files/. wd/; fi
run publish wd --key-file school.kit
'

# publish_manifest <manifest file> [<path in the settings folder>=<local file> …]
# Publishes through `mastersos publish` (the lab school key signs). The version goes to $state/last-version.
publish_manifest() {
	local m=$1 st f rel out v rc=0
	shift
	lab_setup || return 1
	st=$(mktemp -d "$state/pub.XXXXXX") || return 1
	cp "$m" "$st/manifest.toml"
	# Every publish is a new version, as it was on the old server: publish refuses an unchanged folder
	printf '\n# lab publish %s\n' "$(date +%s)-$$-$RANDOM" >>"$st/manifest.toml"
	for f in "$@"; do
		rel=${f%%=*}
		case "$rel" in /* | *..* | "")
			rm -rf "$st"
			log "publish_manifest: bad path in the settings folder: $rel" >&2
			return 1
			;;
		esac
		mkdir -p "$st/files/$(dirname "$rel")"
		cp "${f#*=}" "$st/files/$rel"
	done
	out=$(tar -C "$st" -cf - . | lab_run "cd $(lab_dir) && $(lab_pre) bash -c $(lab_q "$LAB_PUBLISH_REMOTE") _ $(lab_q "$LAB_SERVER_URL") $(lab_q "$LAB_SCHOOL_ID") $(lab_fps)") || rc=$?
	rm -rf "$st"
	if [ "$rc" != 0 ]; then
		log "publish refused ($(basename "$m")): $(jq -c '.error | {code, problems}' <<<"$out" 2>/dev/null | cut -c1-600 || true) ${out:0:300}"
		return 1
	fi
	v=$(jq -r .version <<<"$out")
	[[ $v =~ ^[0-9]+$ ]] || {
		log "publish gave no version ($(basename "$m"))"
		return 1
	}
	printf '%s\n' "$v" >"$state/last-version"
	log "published settings v$v ($(basename "$m")); check-in until $(jq -r '.heartbeat_not_after // "none"' <<<"$out"); warnings $(jq -c '.warnings // []' <<<"$out" | cut -c1-300)"
}
# The version the last publish_manifest of this state folder made
latest_version() { cat "$state/last-version"; }

# 0 when the lab school has published settings, 1 when it has none, 2 when that could not be told: `init` is refused with
# version_conflict exactly when something is published.
lab_has_bundle() {
	local o
	if o=$(cli init "probe-$$" --key-file school.kit); then
		lab_run "rm -rf $(lab_dir)/probe-$$"
		return 1
	fi
	case "$o" in *version_conflict*) return 0 ;; esac
	log "cannot tell whether the lab school has settings: ${o:0:300}" >&2
	return 2
}

# One device's report (JSON; empty when the server does not know the device yet)
device_json() {
	local l
	l=$(cli devices list) || return 1
	jq -e --arg id "$1" 'any(.[]; .device_id == $id)' <<<"$l" >/dev/null || return 0
	cli devices show "$1" | jq -c .
}
# The device's recovery keys, opened with the school key (JSON array, as `mastersos --json recovery read`)
recovery_read() { cli recovery read "$1" --key-file school.kit; }
recovery_rows() { recovery_read "$1" | jq 'length'; }
# The newest recovery key of this device for this LUKS volume (stdout only)
recovery_key() { # recovery_key <device_id> <luks_uuid>
	recovery_read "$1" | jq -r --arg u "$2" '[.[] | select(.luks_uuid == $u)][0].recovery_key // empty'
}
