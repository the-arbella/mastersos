#!/bin/bash
# VM acceptance for plan 4b (Task 20). Runs on the Mac and drives, through lab-host, the lab VMs on PVE, the build VM 161
# and the IdP VM 163:
#   accept-4b.sh <vmid> <check…|all>
# Each check prints "PASS <name>" or "FAIL <name>: <reasons>". What the script cannot judge (for example "the Dock shows
# only these icons") is screenshotted and printed as "MANUAL <name>: see <png>"; a person looks at it and adds a PASS/FAIL
# line to the results file. All output is tee'd to results/<date>-4b/t20-<vmid>.txt and screenshots go to the same
# directory (screens showing a device code or a password only go to the state directory and are deleted after use).
# Exit code = number of failures.
#   165 all = mok_lab_only etc_upgrade login_methods sso_zitadel sso_kanidm domain_restriction modes print apply_within_10s
#             fallback_15min offline_login authd_passwd tamper_replay scripts lock admins homes guest_wipe guest_fuse
#             guest_tty_denied chrome_window user_units fetch_token_rotation shim_chain rollback retired_pcr_row8 reset_local reset_remote
#             lab_keys_untrusted tpm_userspace_refused
#   166 all = no_tpm_refused mok_lab_only_stick      167 all = groups mok_lab_only
#   168 all = no_tpm_refused reset_unmanaged hw_precheck groups mok_lab_only
#   fetch_token_rotation needs 167 installed first (groups; it plays the lost machine); hw_precheck uses the warnings
#   recorded when no_tpm_refused installed the same VM.
# Maps to spec §6.9 items 1–10 plus the plan's ship-blocker checks (the table in the Task 20 brief). Helpers shared with
# accept-4a.sh are in accept-common.sh.
#
# Prerequisites (not done by the script): the lab server on VM 161 (~/t12-server, http://192.0.2.99:8480) is running;
# Zitadel (~/idp) and Dex (~/dex, lab/idp/dex/) are running on VM 163; lab beta/stable carry A4B_V (default 20261017.18);
# VM 165 has the snapshot base-4b.
# Secrets: tokens and IdP passwords are read only from ~/.config/testlab/mastersos/ on the Mac; local passwords are random and
# kept in the state directory (outside the repo, 0700); passwords typed into a VM go through qm monitor's stdin (never a
# command line); recovery keys only go through stdin and the serial console; tokens are compared by sha256 only.
# Environment: A4B_DATE (date of the results directory, default today), A4B_V (version under test), A4B_SNAPSHOT, A4B_STATE.
# shellcheck disable=SC2029,SC2329,SC2016,SC2015,SC2001,SC2034,SC2119 # local expansion is intended (arguments are validated first); checks are called as "c_$c"; remote commands are single-quoted on purpose; pass cannot fail; accept-common.sh uses variables set here; reboot_wait's argument is optional (0.9 false positive)
set -euo pipefail

here=${A4_HERE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}
[ $# -ge 2 ] || {
	echo "usage: accept-4b.sh <vmid> <check…|all>" >&2
	exit 2
}
vmid=$1
shift
case "$vmid" in 165 | 166 | 167 | 168) ;; *)
	echo "accept-4b.sh: only VMIDs 165–168, got: $vmid" >&2
	exit 2
	;;
esac

date_=${A4B_DATE:-$(date +%Y-%m-%d)}
out=${A4_OUT:-$here/results/$date_-4b}
state=${A4B_STATE:-$HOME/.cache/mastersos-accept-4b/$date_}
mkdir -p "$out"
mkdir -p "$state" && chmod 700 "$state"
export SHOT_DIR=$out
ACC_SHOT=4b-t20

snapshot=${A4B_SNAPSHOT:-20261013T000000Z}
bhost=${A4_BUILD_HOST:-mastersos@192.0.2.99}
server=${A4_SERVER:-http://192.0.2.99:8480}
upd=http://192.0.2.99/mastersos
root161=/var/www/html/mastersos
lab=/var/lib/vz/mastersos-lab
cfg=$HOME/.config/testlab/mastersos
idp_host=${MASTERSOS_IDP_HOST:-mastersos-s1idp}
idp_ip=192.0.2.100
V_BASE=${A4B_V:-20261017.18}
V_BROKEN_USER=${A4B_V_BROKEN_USER:-20261017.19}
V_BROKEN_INITRD=${A4B_V_BROKEN_INITRD:-20261017.20}
V_BADSHIM=${A4B_V_BADSHIM:-20261017.21}
for v in "$V_BASE" "$V_BROKEN_USER" "$V_BROKEN_INITRD" "$V_BADSHIM"; do
	[[ $v =~ ^[0-9]{8}\.[0-9]+$ ]] || {
		echo "accept-4b.sh: version must look like 20261017.1, got: '$v'" >&2
		exit 2
	}
done
# every build's systemd-boot differs (signature timestamp), so test builds go to lab beta with --allow-bootloader-change
PUBLISH_FLAGS=--allow-bootloader-change
# IdPs on VM 163: Zitadel is the S1 instance, Dex sits in front of Kanidm (VM 105)
ZITADEL_ISSUER=https://zitadel.lan
ZITADEL_CLIENT=394475630609104899
DEX_ISSUER=https://dex.lan:5554
DEX_CLIENT=mastersos-authd

# A4_LIB=1: only define the functions; run no check and write no record
[ -n "${A4_LIB:-}" ] || exec > >(tee -a "$out/t20-$vmid.txt") 2>&1
# shellcheck source-path=SCRIPTDIR source=accept-common.sh
. "$here/accept-common.sh"
manual() { echo "MANUAL $1: see $2"; }

# --- typing (passwords only through qm monitor's stdin) --------------------------------------
# turn a string into qm sendkey key names, one per line
keynames() {
	python3 -c '
import sys
spec = {"@": "shift-2", "_": "shift-minus", "-": "minus", ".": "dot", " ": "spc", ":": "shift-semicolon",
        "/": "slash", "!": "shift-1", "=": "equal", "+": "shift-equal", "\"": "shift-apostrophe", "\x27": "apostrophe",
        ";": "semicolon", ",": "comma", "~": "shift-grave_accent", "#": "shift-3"}
for ch in sys.stdin.read():
    if ch == "\n": print("ret")
    elif ch.isupper(): print("shift-" + ch.lower())
    elif ch in spec: print(spec[ch])
    elif ch.isalnum(): print(ch)
    else: sys.exit("keynames: unsupported character")'
}
# text from stdin → qm monitor sendkey; the monitor's echo (which would show the keys) is discarded
type_stdin() {
	keynames | sed 's/^/sendkey /' | pve "qm monitor $vmid >/dev/null 2>&1"
}
type_text() { printf '%s' "$1" | type_stdin; }
# the contents of a password file, then Enter
type_file() { { tr -d '\n' <"$1"; printf '\n'; } | type_stdin; }
newpw() { # newpw <name in state>: random password (alphanumeric without l/1/0/O), 0600
	[ -s "$state/$1.pw" ] || { LC_ALL=C tr -dc 'a-km-zA-HJ-NP-Z2-9' </dev/urandom | head -c 12 >"$state/$1.pw"; }
	chmod 600 "$state/$1.pw"
	echo "$state/$1.pw"
}

# --- test-only changes (not in the image): IdP host names, lab autologin off ------------------------
# /etc/hosts is a read-only link to factory: zitadel.lan and dex.lan are added with a bind mount (gone after a reboot,
# so this runs again after every boot)
lab_prep() {
	gxm "set -e
if ! grep -q 'dex.lan' /etc/hosts; then
  { cat /usr/share/factory/etc/hosts 2>/dev/null || cat /etc/hosts; echo '$idp_ip zitadel.lan dex.lan'; } > /run/mastersos-t20-hosts
  mount --bind /run/mastersos-t20-hosts /etc/hosts
fi
if grep -q '^AutomaticLoginEnable=true' /etc/gdm3/custom.conf; then
  sed -i 's/^AutomaticLoginEnable=true/AutomaticLoginEnable=false/' /etc/gdm3/custom.conf
  echo 'gdm: autologin off'
  loginctl terminate-user student 2>/dev/null || true
  systemctl restart gdm
fi" >/dev/null || return 1
}
# back to a clean login screen: end everybody's graphical sessions, restart GDM, wait for the greeter
greeter() {
	gx 'for u in $(loginctl list-users --no-legend | awk "\$2 != \"gdm\" && \$2 !~ /^gdm-greeter/ {print \$2}"); do loginctl terminate-user "$u"; done; systemctl restart gdm' >/dev/null 2>&1 || true
	local end=$((SECONDS + 60))
	while [ "$SECONDS" -lt "$end" ]; do
		gx 'loginctl list-sessions --no-legend | grep -q greeter' >/dev/null 2>&1 && {
			sleep 6
			return 0
		}
		sleep 2
	done
	return 1
}
# does this user have a graphical session on seat0
has_session() { gx "loginctl list-sessions --no-legend | awk '\$3 == \"$1\" && \$4 == \"seat0\"' | grep -q ." >/dev/null 2>&1; }
wait_session() { # wait_session <user> [seconds]
	local end=$((SECONDS + ${2:-40}))
	while [ "$SECONDS" -lt "$end" ]; do
		has_session "$1" && return 0
		sleep 2
	done
	return 1
}
# GDM "Not listed?" → user name → Enter.
# On the greeter, Esc goes back to the user list (GDM may open straight into the last user's password prompt) with focus on
# the first user; Tab walks through every listed user before it reaches "Not listed?", so the number of Tabs = the number of
# users accountsservice has cached (those are the ones GDM lists)
gdm_notlisted() {
	local n i k=()
	n=$(gx 'busctl call org.freedesktop.Accounts /org/freedesktop/Accounts org.freedesktop.Accounts ListCachedUsers | awk "{print \$2}"' 2>/dev/null | tr -d '\n')
	[[ $n =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] || n=1
	for ((i = 0; i < n; i++)); do k+=(tab wait:0.5); done
	keys esc wait:2 "${k[@]}" ret wait:2
	type_text "$1"
	keys ret wait:4
}

# --- device code: screenshot (state only) → OCR → approve on VM 163 --------------------------------
read_code() {
	local f=$state/devcode.png code="" i
	for i in 1 2 3 4 5; do
		SHOT_DIR=$state "$here/shot.sh" "$vmid" devcode >/dev/null
		# Zitadel and Dex user codes use only the consonants BCDFGHJKLMNPQRSTVWXZ (RFC 8628's suggested charset): let
		# tesseract read only those and '-' (an O/0, I/L or E/F mix-up makes the approval fail)
		code=$(magick "$f" -colorspace Gray -resize 200% - | tesseract - - -c tessedit_char_whitelist=BCDFGHJKLMNPQRSTVWXZ- 2>/dev/null | tr -d ' ' | grep -oE '[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}' | head -1 || true)
		rm -f "$f"
		[ -n "$code" ] && break
		sleep 3
	done
	[ -n "$code" ] || return 1
	echo "$code"
}
approve() { # approve <zitadel|dex> <code> <IdP login name>
	local pwf=$cfg/s1-test-password o
	o=$("$here/idp/approve.sh" "$1" "$2" "$3" "t20-$vmid" <"$pwf" 2>&1 | grep -v Warning)
	if grep -qiE 'approved' <<<"$o"; then
		echo "approved"
	else
		echo "not approved: $(tail -1 <<<"$o" | cut -c1-160)"
		return 1
	fi
}
# first SSO login: Not listed? → name → OIDC broker → device code → approve → local password twice → desktop
#   sso_first_login <zitadel|dex> <name typed in GDM> <IdP login name> <screenshot tag>
sso_first_login() {
	local idp=$1 name=$2 idpuser=$3 tag=$4 code pwf lname
	lname=$(tr '[:upper:]' '[:lower:]' <<<"$name")
	pwf=$(newpw "${lname//[^a-z0-9]/_}")
	greeter || return 1
	gdm_notlisted "$name"
	shot "$tag-broker"
	keys ret wait:6
	code=$(read_code) || {
		log "$tag: could not read a device code from the screen"
		return 1
	}
	log "$tag: device code read (not recorded), approving on VM 163"
	if ! approve "$idp" "$code" "$idpuser" | sed 's/^/  approval: /' | tee /dev/stderr | grep -q ': approved'; then
		# read the screen again (the code is still shown) and retry once
		code=$(read_code) && approve "$idp" "$code" "$idpuser" | sed 's/^/  approval (retry): /' >&2
	fi
	sleep 8
	shot "$tag-local-pw"
	type_file "$pwf"
	sleep 2
	type_file "$pwf"
	wait_session "$lname" 40
}
# make sure an SSO user exists on this machine with the local password in state: checks that roll back to t20-up (taken
# before any SSO login) lose the account, so do a first login when it is missing. The bundle must already point the
# broker at the right IdP
ensure_sso() { # ensure_sso <zitadel|dex> <name> <IdP login name>
	local lname
	lname=$(tr '[:upper:]' '[:lower:]' <<<"$2")
	if gx "getent passwd '$lname'" >/dev/null 2>&1 && [ -s "$state/${lname//[^a-z0-9]/_}.pw" ]; then
		return 0
	fi
	log "$lname is not on this machine (rolled back): first login"
	sso_first_login "$1" "$2" "$3" "ensure-${lname%%@*}"
}
# an SSO user who logged in before, or a local user: Not listed? → name → password
pw_login() { # pw_login <name> <password file> [screenshot tag]
	greeter || return 1
	gdm_notlisted "$1"
	[ -z "${3:-}" ] || shot "$3-prompt"
	type_file "$2"
	wait_session "$(tr '[:upper:]' '[:lower:]' <<<"$1")" 30
}

# --- bundles ---------------------------------------------------------------------------------
fixtures=$here/fixtures/bundles
state_version() { gx 'jq -r .version /var/lib/mastersos/state.json' 2>/dev/null | tr -d '\n'; }
# wait until state.json's version is >= <v> (at most <seconds>); prints the seconds it took
wait_bundle() {
	local want=$1 t0=$SECONDS v
	while [ $((SECONDS - t0)) -le "${2:-60}" ]; do
		v=$(state_version)
		[[ $v =~ ^[0-9]+$ ]] && [ "$v" -ge "$want" ] && {
			echo $((SECONDS - t0))
			return 0
		}
		sleep 1
	done
	echo $((SECONDS - t0))
	return 1
}
latest_version() { api ops GET /v1/admin/summary | jq -r .latest_version; }
# assemble a manifest: [school] (B_IDP=zitadel|dex|none, B_CHANNEL, B_DOMAINS, B_ADMINS, B_TZ, B_LOCALE) + default +
# teacher + cart (the two fixture groups with their configs, rewritable with B_TEACHER_SED / B_CART_SED, B_TEACHER_EXTRA appended to
# the teacher config) + [[device]] (B_DEVICES as raw TOML; by default this VM is put into B_GROUP)
bundle() { # bundle <name> → local file path
	local f=$state/bundle-$1.toml iss="" cid=""
	case "${B_IDP:-zitadel}" in
	zitadel) iss=$ZITADEL_ISSUER cid=$ZITADEL_CLIENT ;;
	dex) iss=$DEX_ISSUER cid=$DEX_CLIENT ;;
	none) ;;
	esac
	{
		printf '[school]\nupdate_channel = "%s"\ntimezone = "%s"\n' "${B_CHANNEL:-beta}" "${B_TZ:-Asia/Bangkok}"
		[ -z "$iss" ] || printf 'oidc = { issuer = "%s", client_id = "%s" }\n' "$iss" "$cid"
		[ -z "${B_DOMAINS:-}" ] || printf 'allowed_domains = %s\n' "$B_DOMAINS"
		[ -z "${B_ADMINS:-}" ] || printf 'admin_users = %s\n' "$B_ADMINS"
		[ -z "${B_LOCALE:-}" ] || printf 'locale = "%s"\n' "$B_LOCALE"
		printf '\n[[config]]\nid = "default"\nname = "未分组"\nlogin_methods = %s\n\n' "${B_DEFAULT_METHODS:-[\"local\"]}"
		printf '[[group]]\nid = "default"\nname = "未分组"\nconfig = "default"\n\n'
		sed -e "${B_TEACHER_SED:-}" "$fixtures/teacher.toml"
		# extra TOML appended to the teacher config (for example a [config.chrome] table)
		[ -z "${B_TEACHER_EXTRA:-}" ] || printf '%s\n' "$B_TEACHER_EXTRA"
		echo
		sed -e "${B_CART_SED:-}" "$fixtures/cart.toml"
		echo
		if [ -n "${B_DEVICES+x}" ]; then
			printf '%s\n' "$B_DEVICES"
		elif [ -n "${B_GROUP:-}" ]; then
			printf '[[device]]\ndevice_id = "%s"\ngroup = "%s"\n' "$(my_id)" "$B_GROUP"
		fi
	} >"$f"
	echo "$f"
}
# the two scripts in the draft (teacher refers to them, so lint wants them in the bundle); S_APPLY / S_LOGIN replace them
script_files() {
	printf '%s\n' "${S_APPLY:-#!/bin/sh
echo \"apply \$(date -u +%FT%TZ)\" >> /var/lib/mastersos-system/t20-apply-ran}" >"$state/t20-apply.sh"
	printf '%s\n' "${S_LOGIN:-#!/bin/sh
echo \"login \$(date -u +%FT%TZ)\" >> \"\$HOME/login-ran\"}" >"$state/t20-login.sh"
	echo "scripts/t20-apply.sh=$state/t20-apply.sh scripts/t20-login.sh=$state/t20-login.sh"
}
pub() { # pub <name>: bundle + publish; prints the new version
	local f files
	f=$(bundle "$1")
	read -r -a files <<<"$(script_files)"
	publish_manifest "$f" "${files[@]}" >&2 || return 1
	latest_version
}
# cleanup: publish the default bundle again (stable / ["local"], no IdP, no device assignment), as Tasks 11–24 did
pub_default() {
	printf '[school]\ntimezone = "Asia/Bangkok"\nupdate_channel = "stable"\n\n[[config]]\nid = "default"\nname = "未分组"\nlogin_methods = ["local"]\n\n[[group]]\nid = "default"\nname = "未分组"\nconfig = "default"\n' >"$state/default.toml"
	publish_manifest "$state/default.toml"
}
my_id() { device_id; }
# one report item of this machine on the server
report_item() { device_json "$(my_id)" | jq -c --arg i "$1" '[.results[]? | select(.item == $i)][0] // empty'; }
# make the machine fetch now (the agent fetches immediately on SIGUSR1)
kick() { gx 'systemctl kill -s USR1 mastersos-agent' >/dev/null 2>&1 || true; }
# when the draft was changed in place (the panel's group / lock / remote-reset endpoints edit the draft): two-step publish
publish_draft() {
	local p pend dig
	p=$(api ops POST /v1/admin/publish/prepare) || {
		log "pre-publish lint failed: $(jq -c '[.error.details.lints[]? | select(.level == "error") | .code]' <<<"$p" 2>/dev/null || echo "$p")"
		return 1
	}
	pend=$(jq -r .pending_id <<<"$p")
	dig=$(jq -c .digest_hex <<<"$p")
	printf '{"confirm_digest": %s}' "$dig" >"$state/commit.json"
	api ops POST "/v1/admin/publish/pending/$pend/commit-server" "$state/commit.json" >/dev/null || return 1
	log "published the draft as v$(jq -r .version <<<"$p")"
	jq -r .version <<<"$p"
}
# the panel's endpoints: PUT /v1/admin/devices/<id>/<group|lock|reset> with a JSON body
panel_put() { # panel_put <device_id> <group|lock|reset> <JSON>
	printf '%s' "$3" >"$state/panel.json"
	api ops PUT "/v1/admin/devices/$1/$2" "$state/panel.json"
}

# --- pseudo-terminal that never answers terminal queries -----------------------------------------
#   printf '%s\n' answers… | pty_run <run as: root or a user name> <command…>
# Answers come only from stdin and are sent one at a time when a prompt shows up (see below). The answer "<enter>" sends a
# bare Enter. Prints the command's output (answers are not echoed) and a last line "rc=<exit code> s=<seconds>"; anything
# still running after 30 s is killed and reported as rc=124. The answers reach python through an environment variable
# because the heredoc occupies its stdin.
pty_run() {
	local who=$1
	shift
	gx_stdin "who='$who'
cmd='$*'"'
T20_ANS=$(cat) python3 - "$who" "$cmd" <<"PY"
import os, pty, re, select, sys, time
who, cmd = sys.argv[1], sys.argv[2]
answers = [l for l in os.environ.pop("T20_ANS", "").split("\n") if l]
argv = ["bash", "-c", cmd] if who == "root" else ["runuser", "-u", who, "--", "bash", "-c", cmd]
t0 = time.time()
pid, fd = pty.fork()
if pid == 0:
    os.environ["LC_ALL"] = "C.UTF-8"
    os.execvp(argv[0], argv)
out, pend, last, kw = b"", b"", time.time(), None
while time.time() - t0 < 30:
    r, _, _ = select.select([fd], [], [], 0.2)
    if r:
        try:
            d = os.read(fd, 4096)
        except OSError:
            break
        if not d:
            break
        out += d; pend += d; last = time.time()
    else:
        done, st = os.waitpid(pid, os.WNOHANG)
        if done:
            break
    # A prompt: new output containing "password" (pam_unix "Password:", the authd prompts "Enter your password" and
    # "New password"), answered 0.5 s after it appears; or output that stopped for 1 s. The authd terminal UI keeps
    # redrawing, so it never goes quiet and has to be recognised by the word.
    if kw is None and re.search(rb"(?i)password", pend):
        kw = time.time()
    if pend.strip() and answers and ((kw is not None and time.time() - kw > 0.5) or time.time() - last > 1.0):
        a = answers.pop(0)
        os.write(fd, (b"" if a == "<enter>" else a.encode()) + b"\r"); pend = b""; kw = None
try:
    _, st = os.waitpid(pid, 0) if time.time() - t0 < 30 else (os.kill(pid, 9), os.waitpid(pid, 0))[1]
    rc = os.waitstatus_to_exitcode(st)
except ChildProcessError:
    rc = 0
if time.time() - t0 >= 30:
    rc = 124
print(out.decode(errors="replace").replace("\r", "").strip())
print("rc=%d s=%.1f" % (rc, time.time() - t0))
PY'
}
# local user t20local (random password, only through chpasswd's stdin), used by the local-account checks
local_user() {
	local pwf
	pwf=$(newpw t20local)
	gx 'id t20local >/dev/null 2>&1 || useradd -m -s /bin/bash t20local' >/dev/null
	{ printf 't20local:'; cat "$pwf"; echo; } | gx_stdin 'chpasswd' || return 1
	echo "$pwf"
}
# guest login: Not listed? → guest (no password)
guest_login() {
	greeter || return 1
	gdm_notlisted guest
	keys ret
	wait_session guest 30
}
# run a command on a user's session bus (gsettings, gdbus)
as_user() { # as_user <user> <command>
	gx "u=\$(id -u '$1') && runuser -u '$1' -- env XDG_RUNTIME_DIR=/run/user/\$u DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/\$u/bus $2"
}
dock() { gx 'cat /etc/dconf/db/mastersos.d/50-mastersos 2>/dev/null | grep favorite-apps'; }

# ==================================================================================
# checks
# ==================================================================================

# VM 165 goes from base-4b (20261015.5) to V_BASE through sysupdate: every dir plan 4b added to the /etc policy is a real
# directory, /etc/locale.conf is a real file and /etc/default/locale resolves to it (Task 8 Step 3's method); also no
# "ordering cycle" in the boot log (Task 12 carry). Takes snapshot t20-up at the end (later checks start from it and
# destructive ones roll back to it).
c_etc_upgrade() {
	local name=etc_upgrade bad="" o v
	stop_vm
	rollback base-4b
	start_wait || {
		fail "$name" "base-4b does not boot"
		return
	}
	v=$(img_version)
	log "base-4b: IMAGE_VERSION=$v"
	B_CHANNEL=beta B_DEVICES="" pub etc-upgrade >/dev/null || {
		fail "$name" "cannot publish a beta-channel bundle"
		return
	}
	o=$(run_update)
	log "mastersos-update: ${o//$'\n'/ }"
	reboot_wait || bad="${bad}does not boot after the update; "
	v=$(img_version)
	log "after the update IMAGE_VERSION=$v"
	[ "$v" = "$V_BASE" ] || bad="${bad}not on $V_BASE (on $v); "
	o=$(gxm '
for d in /etc/default /etc/netplan /etc/dconf/db/mastersos.d /etc/dconf/db/mastersos.d/locks /etc/dconf/db/gdm.d /etc/sane.d/airscan.d /etc/authd/oidc /etc/authd/oidc/broker.conf.d; do
  test -d "$d" -a ! -L "$d" && echo "  ok $d $(stat -c %a "$d")" >&2 || echo "$d is not a real directory"
done
test -f /etc/locale.conf -a ! -L /etc/locale.conf || echo "/etc/locale.conf is not a real file"
[ "$(readlink -f /etc/default/locale)" = /etc/locale.conf ] || echo "/etc/default/locale resolves to $(readlink -f /etc/default/locale)"
n=$(journalctl -b --no-pager -o cat | grep -ci "ordering cycle"); [ "$n" = 0 ] || echo "$n ordering-cycle lines in the boot log"
journalctl -b -u systemd-tmpfiles-setup -u mastersos-etc-migrate -p warning --no-pager -o cat | grep -v "^-- No entries" | head -3 | sed "s/^/  tmpfiles\/etc-migrate warning: /" >&2
') || o="the remote check block did not finish"
	[ -z "$o" ] || bad="$bad${o//$'\n'/; }; "
	if [ -z "$bad" ]; then
		delsnap t20-up
		snap t20-up "4b Task 20: VM 165 base-4b upgraded to $V_BASE via lab beta (etc_upgrade passed)"
		pass "$name"
	else
		fail "$name" "$bad"
	fi
}

# Remove the release MOK (CN=MastersOS Secure Boot db) that 4a left on the lab VMs (Task 1 carry): mokutil --delete
# (password mastersos through stdin) → reboot into MokManager "Delete MOK" → password → reboot. Afterwards the release MOK is
# gone and the lab MOK is still there. If the machine stops at the recovery-key prompt (PCR 7 changed), the key is typed
# on the serial console.
c_mok_lab_only() {
	local name=mok_lab_only bad="" o b64
	start_wait || {
		fail "$name" "does not boot"
		return
	}
	b64=$(base64 <"$here/../keys/mastersos-mok.der" | tr -d '\n')
	o=$(gx "echo $b64 | base64 -d > /run/release-mok.der; mokutil --test-key /run/release-mok.der 2>&1; mokutil --test-key /usr/share/mastersos/mastersos-mok.der 2>&1" || true)
	log "before: ${o//$'\n'/ | }"
	if grep -q 'release-mok.der is already in db' <<<"$o"; then
		local did dluks
		did=$(my_id 2>/dev/null || true)
		dluks=$(gx 'cryptsetup luksUUID /dev/gpt-auto-root-luks 2>/dev/null' | tr -d '\n' || true)
		log "release certificate in the firmware db: removed $(db_remove_release) entry(ies) with the VM off"
		pve "qm start $vmid" >/dev/null
		# db is measured into PCR 7, which the TPM slot's pcrlock policy binds: this boot may ask for the recovery key
		# (listen on the serial console from power-on; if no prompt comes within 240 s the TPM unlocked)
		if [ -n "$did" ] && [ -n "$dluks" ] && type_recovery_key "$did" "$dluks" >/dev/null 2>&1; then
			log "PCR 7 changed: typed the escrowed recovery key on the serial console"
		fi
		wait_up 400 || bad="${bad}does not boot after editing db; "
	fi
	if grep -q 'release-mok.der is already enrolled' <<<"$o"; then
		local id luks
		id=$(my_id)
		luks=$(gx 'cryptsetup luksUUID /dev/gpt-auto-root-luks 2>/dev/null' | tr -d '\n' || true)
		printf 'mastersos\nmastersos\n' | gx_stdin 'mokutil --delete /run/release-mok.der' || bad="${bad}mokutil --delete failed; "
		gx 'mokutil --list-delete | grep -E "Subject:|CN="' | sed 's/^/  to delete: /'
		pve "qm reboot $vmid --timeout 180" >/dev/null
		keys mok-enroll
		shot mok-deleted-reboot
		sleep 20
		if ! wait_up 300; then
			# PCR 7 changed: recovery key
			[ -n "$luks" ] && type_recovery_key "$id" "$luks" >/dev/null && log "recovery key was asked for (PCR 7 changed); typed it from the server"
			wait_up 300 || bad="${bad}does not boot after deleting the MOK; "
		fi
	fi
	o=$(gx "test -e /run/release-mok.der || echo $b64 | base64 -d > /run/release-mok.der; mokutil --test-key /run/release-mok.der 2>&1; mokutil --test-key /usr/share/mastersos/mastersos-mok.der 2>&1; rm -f /run/release-mok.der" || true)
	log "after: ${o//$'\n'/ | }"
	grep -q 'release-mok.der is not enrolled' <<<"$o" || bad="${bad}release MOK still enrolled; "
	grep -q 'mastersos-mok.der is already enrolled' <<<"$o" || bad="${bad}lab MOK is gone; "
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# The release certificate can also sit in the firmware db (VMs created with vm-create.sh --own-db in 4a), where
# mokutil reports "already in db" and --delete does not apply. With the VM powered off, drop the EFI_SIGNATURE_LIST
# entry whose DER equals keys/mastersos-mok.der from db and write the variable store back (virt-fw-vars --set-json).
# Prints how many entries were removed.
db_remove_release() {
	local b64
	stop_vm
	b64=$(base64 <"$here/../keys/mastersos-mok.der" | tr -d '\n')
	pve "set -e; d=\$(mktemp -d); vol=\$(qm config $vmid | sed -n 's/^efidisk0: \([^,]*\),.*/\1/p'); dev=\$(pvesm path \$vol); [ -b \$dev ] || lvchange -ay \$dev
dd if=\$dev of=\$d/v.fd bs=540672 count=1 status=none
virt-fw-vars -i \$d/v.fd --output-json \$d/v.json >/dev/null 2>&1
echo $b64 | base64 -d > \$d/rel.der
python3 - \$d/v.json \$d/rel.der <<'PY'
import json, struct, sys
j = json.load(open(sys.argv[1])); rel = open(sys.argv[2], 'rb').read()
db = next(v for v in j['variables'] if v['name'] == 'db')
raw = bytes.fromhex(db['data']); out = b''; removed = 0; i = 0
while i < len(raw):
    lsize, hsize, ssize = struct.unpack_from('<III', raw, i + 16)
    lst = raw[i:i + lsize]
    sigs = lst[28 + hsize:]
    keep = [sigs[k:k + ssize] for k in range(0, len(sigs), ssize) if sigs[k + 16:k + ssize] != rel]
    removed += len(sigs) // ssize - len(keep)
    if keep:
        body = b''.join(keep)
        out += lst[:16] + struct.pack('<III', 28 + hsize + len(body), hsize, ssize) + lst[28:28 + hsize] + body
    i += lsize
db['data'] = out.hex()
json.dump(j, open(sys.argv[1], 'w'))
print(removed)
PY
virt-fw-vars -i \$d/v.fd --set-json \$d/v.json -o \$d/v2.fd >/dev/null 2>&1
dd if=\$d/v2.fd of=\$dev bs=540672 count=1 conv=notrunc status=none
rm -rf \$d"
}

# VM 166's old system (installed by 4a with an empty passphrase) no longer boots (Task 3 carry: dead end), so mokutil runs
# in the installer environment of the lab USB stick: the guest agent is still up after the installer refuses; after the
# delete request it reboots (from the stick again) into MokManager
c_mok_lab_only_stick() {
	local name=mok_lab_only bad="" o b64
	b64=$(base64 <"$here/../keys/mastersos-mok.der" | tr -d '\n')
	boot_stick plain
	wait_vcs 'No usable TPM 2.0|[Tt]ype y to continue' 240 || bad="${bad}the installer on the stick did not come up; "
	o=$(gx "echo $b64 | base64 -d > /run/release-mok.der; mokutil --test-key /run/release-mok.der 2>&1" || true)
	log "before (installer environment): $o"
	if grep -q 'already enrolled' <<<"$o"; then
		printf 'mastersos\nmastersos\n' | gx_stdin 'mokutil --delete /run/release-mok.der' || bad="${bad}mokutil --delete failed; "
		pve "qm reset $vmid" >/dev/null
		keys mok-enroll
		shot mok-deleted-reboot
		wait_vcs 'No usable TPM 2.0|[Tt]ype y to continue' 240 || bad="${bad}the installer did not come back after the reboot; "
		o=$(gx "echo $b64 | base64 -d > /run/release-mok.der; mokutil --test-key /run/release-mok.der 2>&1" || true)
		log "after: $o"
	fi
	if grep -q 'already in db' <<<"$o"; then
		unstick
		log "release certificate in the firmware db: removed $(db_remove_release) entry(ies) with the VM off"
		boot_stick plain
		wait_vcs 'No usable TPM 2.0|[Tt]ype y to continue' 240 || bad="${bad}the installer did not come back after editing db; "
		o=$(gx "echo $b64 | base64 -d > /run/release-mok.der; mokutil --test-key /run/release-mok.der 2>&1" || true)
		log "after editing db: $o"
	fi
	grep -q 'is not enrolled' <<<"$o" || bad="${bad}release certificate still trusted (MokList or db); "
	unstick
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# §6.9 item 1: a cart machine's login screen offers the guest and refuses local accounts with a reason; a teacher machine
# has no guest
c_login_methods() {
	local name=login_methods bad="" o pwf v
	start_wait && lab_prep || {
		fail "$name" "does not boot"
		return
	}
	pwf=$(local_user) || bad="${bad}cannot create the local user; "
	v=$(B_GROUP=cart pub login-cart) || bad="${bad}cannot publish the cart bundle; "
	wait_bundle "$v" 30 >/dev/null || bad="${bad}v$v not applied within 30 s; "
	sleep 3
	o=$(gx 'getent passwd guest; findmnt -no FSTYPE /home/guest; test -e /run/mastersos/guest-ready && echo ready; jq -c .methods /var/lib/mastersos-system/login/policy.json 2>/dev/null || cat /var/lib/mastersos-system/login/policy.json')
	log "cart: ${o//$'\n'/ | }"
	grep -q '^guest:x:1999:' <<<"$o" || bad="${bad}no guest account on cart; "
	grep -q ready <<<"$o" || bad="${bad}no guest-ready on cart; "
	greeter || bad="${bad}no login screen; "
	shot login-methods-cart-greeter
	manual "$name/cart-greeter" "$out/$ACC_SHOT-$vmid-login-methods-cart-greeter.png (the user list has the guest)"
	o=$(pty_run student 'su - t20local -c "id -un"' <"$pwf")
	log "cart: student runs su - t20local in a pty: ${o//$'\n'/ | }"
	# agent message (bilingual): 这台电脑不允许本机账号登录 / Local accounts cannot sign in on this computer
	grep -q 'Local accounts cannot sign in on this computer' <<<"$o" || bad="${bad}local account not refused on cart, or no reason shown; "
	grep -q 'rc=0' <<<"$o" && bad="${bad}su to the local account succeeded on cart; "
	# the local account in GDM: refused, no session (GDM does not show PAM text, Task 11 finding)
	gdm_notlisted t20local
	type_file "$pwf"
	sleep 6
	shot login-methods-cart-local-refused
	has_session t20local && bad="${bad}the local account logged in through GDM on cart; "
	gx "journalctl -b --since -2min -o cat --no-pager | grep -E 'pam_exec.*(failed|exit code)|mastersos-agent.*t20local' | tail -2" | sed 's/^/  journal: /'
	v=$(B_GROUP=teacher pub login-teacher) || bad="${bad}cannot publish the teacher bundle; "
	wait_bundle "$v" 30 >/dev/null || bad="${bad}v$v not applied within 30 s; "
	sleep 5
	o=$(gx 'getent passwd guest || echo "no guest"; test -e /run/mastersos/guest-ready && echo ready || echo "no guest-ready"')
	log "teacher: ${o//$'\n'/ | }"
	grep -q 'no guest$' <<<"$o" || bad="${bad}guest account still there on teacher; "
	greeter || true
	shot login-methods-teacher-greeter
	manual "$name/teacher-greeter" "$out/$ACC_SHOT-$vmid-login-methods-teacher-greeter.png (no guest in the user list)"
	pw_login t20local "$pwf" || bad="${bad}the local account cannot log in on teacher; "
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# §6.9 item 2: device-code login through Zitadel / through Dex→Kanidm reaches the desktop
sso_check() { # sso_check <name> <zitadel|dex> <name for GDM> <IdP login name>
	local name=$1 idp=$2 user=$3 iu=$4 bad="" o v lname
	lname=$(tr '[:upper:]' '[:lower:]' <<<"$user")
	start_wait && lab_prep || {
		fail "$name" "does not boot"
		return
	}
	v=$(B_IDP=$idp B_GROUP=teacher B_DOMAINS='["school.test"]' pub "$name") || bad="${bad}cannot publish; "
	wait_bundle "$v" 30 >/dev/null || bad="${bad}v$v not applied within 30 s; "
	sleep 3
	o=$(gx 'cat /etc/authd/oidc/broker.conf.d/10-mastersos.conf; stat -c "%a %U" /etc/authd/oidc/broker.conf.d/10-mastersos.conf')
	log "broker config: ${o//$'\n'/ | }"
	grep -q "issuer = $([ "$idp" = dex ] && echo "$DEX_ISSUER" || echo "$ZITADEL_ISSUER")" <<<"$o" || bad="${bad}wrong issuer in the broker config; "
	if sso_first_login "$idp" "$user" "$iu" "$name"; then
		sleep 12
		shot "$name-desktop"
		manual "$name/desktop" "$out/$ACC_SHOT-$vmid-$name-desktop.png (reached the desktop)"
		o=$(gx "getent passwd '$lname'; loginctl list-sessions --no-legend | grep '$lname'; runuser -u '$lname' -- id -un")
		log "${o//$'\n'/ | }"
		grep -qx "$lname" <<<"$(tail -1 <<<"$o")" || bad="${bad}id -un is not the lower-case $lname; "
	else
		shot "$name-failed"
		bad="${bad}did not reach the desktop; "
	fi
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}
c_sso_zitadel() { sso_check sso_zitadel zitadel s1zbob@school.test s1zbob@school.test; }
c_sso_kanidm() { sso_check sso_kanidm dex s1bob@school.test s1bob; }

# §6.9 item 2: only school.test is allowed; s1zeve@other.test is refused by pam-check after the IdP approved her, no session
c_domain_restriction() {
	local name=domain_restriction bad="" o v
	start_wait && lab_prep || {
		fail "$name" "does not boot"
		return
	}
	v=$(B_IDP=zitadel B_GROUP=teacher B_DOMAINS='["school.test"]' pub "$name") || bad="${bad}cannot publish; "
	wait_bundle "$v" 30 >/dev/null || bad="${bad}v$v not applied; "
	if sso_first_login zitadel s1zeve@other.test s1zeve@other.test domain; then
		bad="${bad}s1zeve@other.test reached the desktop; "
	fi
	shot domain-refused
	manual "$name/refused" "$out/$ACC_SHOT-$vmid-domain-refused.png (refused, back on the login screen)"
	o=$(gx "journalctl -b --since -5min -o cat --no-pager | grep -E 'pam_exec\\(gdm-authd:account\\)|PAM:accounting.*s1zeve' | tail -3; loginctl list-sessions --no-legend | grep -c s1zeve")
	log "${o//$'\n'/ | }"
	grep -qE 'acct="s1zeve@other.test".*res=failed|pam_exec\(gdm-authd:account\).*failed' <<<"$o" || bad="${bad}no account-stage refusal in the journal; "
	o=$(gx "PAM_USER=s1zeve@other.test PAM_SERVICE=gdm-authd PAM_TYPE=account mastersos-agent pam-check; echo rc=\$?")
	log "pam-check run directly: ${o//$'\n'/ | }"
	grep -q 'Accounts from this domain cannot sign in on this computer' <<<"$o" || bad="${bad}pam-check gave no domain reason; "
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# §6.9 item 5: offline, an SSO account that logged in before gets in with its local password and the settings stay
# (run sso_kanidm first)
c_offline_login() {
	local name=offline_login bad="" o before after pwf v
	pwf=$state/s1bob_school_test.pw
	[ -s "$pwf" ] || {
		fail "$name" "no local password for s1bob (run sso_kanidm first)"
		return
	}
	start_wait && lab_prep || {
		fail "$name" "does not boot"
		return
	}
	# s1bob was created through Dex: the broker must point at Dex (earlier checks may have switched the issuer to Zitadel)
	v=$(B_IDP=dex B_GROUP=teacher B_DOMAINS='["school.test"]' B_TEACHER_SED='/^flatpak = /d' pub offline-dex) || true
	wait_bundle "$v" 30 >/dev/null || true
	ensure_sso dex s1bob@school.test s1bob || bad="${bad}s1bob cannot log in online first; "
	sleep 3
	before=$(gx 'jq -c "{version}" /var/lib/mastersos/state.json; cat /var/lib/mastersos-system/exec-block-mode; md5sum < /etc/authd/oidc/broker.conf.d/10-mastersos.conf')
	link 1
	sleep 3
	if pw_login s1bob@school.test "$pwf" offline; then
		sleep 10
		shot offline-desktop
		manual "$name/desktop" "$out/$ACC_SHOT-$vmid-offline-desktop.png (offline, on the desktop, no network icon)"
	else
		shot offline-failed
		bad="${bad}s1bob could not log in offline; "
	fi
	o=$(gx 'nmcli -t -f STATE general; journalctl -b --since -3min -o cat --no-pager | grep -m1 "offline mode"')
	log "offline: ${o//$'\n'/ | }"
	after=$(gx 'jq -c "{version}" /var/lib/mastersos/state.json; cat /var/lib/mastersos-system/exec-block-mode; md5sum < /etc/authd/oidc/broker.conf.d/10-mastersos.conf')
	[ "$before" = "$after" ] || bad="${bad}settings changed by the offline login (${before//$'\n'/ } → ${after//$'\n'/ }); "
	link 0
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# §6.9 item 5: an SSO user changes the offline password with passwd in a terminal (offline the new one works, the old one
# is refused); local users as in 4a's local_password_change; a non-root user su's to the SSO user and to a local user in a
# pty that never answers terminal queries, the password is given only at the prompt, and it completes within 30 s
c_authd_passwd() {
	local name=authd_passwd bad="" o pwf new v
	pwf=$state/s1bob_school_test.pw
	[ -s "$pwf" ] || {
		fail "$name" "no local password for s1bob (run sso_kanidm first)"
		return
	}
	start_wait && lab_prep || {
		fail "$name" "does not boot"
		return
	}
	v=$(B_IDP=dex B_GROUP=teacher B_DOMAINS='["school.test"]' B_TEACHER_SED='/^flatpak = /d' pub passwd-dex) || true
	wait_bundle "$v" 30 >/dev/null || true
	ensure_sso dex s1bob@school.test s1bob || bad="${bad}s1bob cannot log in online first; "
	sleep 3
	new=$state/s1bob-new.pw
	LC_ALL=C tr -dc 'a-km-zA-HJ-NP-Z2-9' </dev/urandom | head -c 13 >"$new"
	chmod 600 "$new"
	o=$({ cat "$pwf"; echo; cat "$new"; echo; cat "$new"; echo; } | pty_run s1bob@school.test passwd)
	log "s1bob passwd: ${o//$'\n'/ | }"
	if grep -q 'password updated successfully' <<<"$o"; then
		cp "$new" "$pwf.next"
	else
		bad="${bad}passwd for the SSO user did not succeed; "
		rm -f "$new"
		new=$pwf
	fi
	link 1
	sleep 3
	# offline, authd may first show "Select your authentication method: 1. Local password": <enter> picks it
	o=$({ echo '<enter>'; cat "$pwf"; echo; } | pty_run student 'su - s1bob@school.test -c "id -un"')
	log "offline, old password: ${o//$'\n'/ | }"
	grep -q 'rc=0' <<<"$o" && bad="${bad}offline, the old password still works for su; "
	o=$({ echo '<enter>'; cat "$new"; echo; } | pty_run student 'su - s1bob@school.test -c "id -un"')
	log "offline, new password (student's pty, terminal queries unanswered): ${o//$'\n'/ | }"
	grep -q 'rc=0' <<<"$o" || bad="${bad}offline, su with the new password fails; "
	awk -F's=' '/rc=/ {exit !($2 < 30)}' <<<"$(grep rc= <<<"$o")" || bad="${bad}su took 30 s or more; "
	if pw_login s1bob@school.test "$new" passwd-offline; then
		sleep 8
		shot passwd-offline-newpw-desktop
	else
		bad="${bad}offline, the new password does not log in through GDM; "
	fi
	link 0
	[ ! -s "$pwf.next" ] || mv "$pwf.next" "$pwf"
	# local user: su in a pty, then 4a's local_password_change (it uses the user owner, password in state/owner.pw)
	gx 'id owner >/dev/null 2>&1 || useradd -m -s /bin/bash owner' >/dev/null
	newpw owner >/dev/null
	{ printf 'owner:'; cat "$state/owner.pw"; echo; } | gx_stdin chpasswd
	o=$({ cat "$state/owner.pw"; echo; } | pty_run student 'su - owner -c "id -un"')
	log "student → owner (pty, terminal queries unanswered): ${o//$'\n'/ | }"
	grep -q 'rc=0' <<<"$o" || bad="${bad}su to the local user fails; "
	local f0=$fails
	c_local_password_change
	[ "$fails" = "$f0" ] || bad="${bad}local_password_change failed; "
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# guest login on tty3 is refused (cart group, guest on)
c_guest_tty_denied() {
	local name=guest_tty_denied bad="" o v
	start_wait && lab_prep || {
		fail "$name" "does not boot"
		return
	}
	v=$(B_GROUP=cart pub "$name") || bad="${bad}cannot publish; "
	wait_bundle "$v" 30 >/dev/null || true
	sleep 3
	keys ctrl-alt-f3 wait:3 g u e s t ret wait:2.5
	shot guest-tty3-refused
	sleep 4
	manual "$name/tty3" "$out/$ACC_SHOT-$vmid-guest-tty3-refused.png (guest refused on tty3)"
	keys ctrl-alt-f1 wait:1
	o=$(gx "journalctl -b --since -1min -o cat --no-pager | grep -E 'login.*guest|PAM:accounting.*guest' | tail -3; loginctl list-sessions --no-legend | grep -c 'guest.*tty3'")
	log "${o//$'\n'/ | }"
	[ "$(tail -1 <<<"$o")" = 0 ] || bad="${bad}guest has a session on tty3; "
	o=$(pty_run root 'su - guest -c true')
	log "root su - guest: ${o//$'\n'/ | }"
	# agent message (bilingual): 访客只能在登录界面登录 / Guest can only sign in from the login screen
	grep -q 'Guest can only sign in from the login screen' <<<"$o" || bad="${bad}su - guest not refused, or no reason; "
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# §6.9 item 3: the learning mode (was browser mode, Task 13 Step 5) and the full-mode software list (Task 16 Step 5), plus the Task 24 carry:
# switching mode during a session (on a machine that was never in the learning mode)
c_modes() {
	local name=modes bad="" o v t0 pid1 pid2 pwf
	start_wait && lab_prep || {
		fail "$name" "does not boot"
		return
	}
	# a Flatpak IT installed on the machine by hand (not in the list): the learning mode must hide it, and removing LibreOffice
	# from the list must leave it alone
	o=$(GX_TIMEOUT=900 gx 'flatpak remote-add --system --if-not-exists flathub /usr/share/mastersos/flathub.flatpakrepo && flatpak install --system --noninteractive -y flathub org.gnome.Calculator >/dev/null 2>&1; flatpak list --system --app --columns=application')
	log "installed by hand: ${o//$'\n'/ }"
	grep -q org.gnome.Calculator <<<"$o" || bad="${bad}cannot install Calculator (prerequisite); "
	# --- a user logged in in the full mode, switched to the learning mode mid-session (Task 24 carry); the bundle without
	# LibreOffice also uninstalls it if an earlier check left it installed, so its install can be watched below
	pwf=$(local_user)
	v=$(B_GROUP=teacher B_TEACHER_SED='/^flatpak = /d' pub modes-desktop0) || bad="${bad}cannot publish; "
	wait_bundle "$v" 30 >/dev/null || true
	t0=$SECONDS
	until ! gx 'flatpak list --system --app --columns=application' | grep -q org.libreoffice.LibreOffice || [ $((SECONDS - t0)) -gt 300 ]; do sleep 5; done
	pw_login t20local "$pwf" || bad="${bad}t20local cannot log in; "
	sleep 8
	o=$(as_user t20local 'gdbus call --session --dest org.gnome.Settings --object-path /org/gnome/Settings --method org.freedesktop.Application.Activate "{}" 2>&1 | head -1; pkill -u t20local -x gnome-control-c; true')
	log "full mode: t20local activates Settings: ${o//$'\n'/ }"
	grep -qi 'exited with status 1\|Error' <<<"$o" && bad="${bad}Settings cannot be activated even in the full mode (bad precondition); "
	v=$(B_GROUP=cart pub modes-browser) || bad="${bad}cannot publish the cart bundle; "
	wait_bundle "$v" 30 >/dev/null || bad="${bad}v$v not applied; "
	sleep 3
	o=$(as_user t20local 'gdbus call --session --dest org.gnome.Settings --object-path /org/gnome/Settings --method org.freedesktop.Application.Activate "{}" 2>&1 | head -1; true')
	log "switched to the learning mode mid-session: t20local activates Settings: ${o//$'\n'/ }"
	# dbus-daemon says "exited with status 1"; dbus-broker (the user bus here) activates through systemd and says "unit failed"
	grep -qiE 'exited with status 1|unit failed' <<<"$o" || bad="${bad}Settings still activates after the mid-session switch (the session bus did not pick up the override); "
	# --- the learning mode (cart: two web apps, one with an https icon; URLBlocklist)
	o=$(gxm '
n=$(findmnt -rn | grep -c interface-denied); [ "$n" -ge 5 ] || echo "stub bind-mounted on only $n paths"
jq -e ".URLBlocklist | index(\"example.org\")" /etc/opt/chrome/policies/managed/mastersos.json >/dev/null || echo "no URLBlocklist in the Chrome policy: $(cat /etc/opt/chrome/policies/managed/mastersos.json 2>&1 | head -c 200)"
ls /var/lib/mastersos-public/xdg/icons/mastersos-web-*.png >/dev/null 2>&1 || echo "https icon not downloaded"
grep -q "Hidden=true" /var/lib/mastersos-public/xdg/applications/org.gnome.Calculator.desktop 2>/dev/null || echo "Calculator is not hidden"
fav=$(grep favorite-apps /etc/dconf/db/mastersos.d/50-mastersos); echo "  $fav" >&2
[ "$(grep -o "\.desktop" <<<"$fav" | wc -l)" = 3 ] || echo "the Dock is not Chrome plus two web apps"
for p in /usr/bin/gnome-terminal /usr/bin/nautilus /usr/bin/gnome-control-center; do cmp -s $p /usr/lib/mastersos/interface-denied || echo "$p is not the stub"; done
') || o="the remote check block did not finish"
	[ -z "$o" ] || bad="$bad${o//$'\n'/; }; "
	if guest_login; then
		sleep 10
		shot modes-browser-dock
		manual "$name/browser-dock" "$out/$ACC_SHOT-$vmid-modes-browser-dock.png (Dock: only Chrome and two web apps, Wikipedia with its downloaded icon)"
		# GNOME opens the overview at login: close it first so Super opens a fresh search
		keys esc wait:1 meta_l wait:2 c a l c u l a t o r wait:3
		shot modes-browser-search-calculator
		keys esc wait:1 meta_l wait:2 t e r m i n a l wait:3
		shot modes-browser-search-terminal
		manual "$name/browser-search" "$out/$ACC_SHOT-$vmid-modes-browser-search-{calculator,terminal}.png (no results)"
		keys esc wait:1 ctrl-alt-t wait:4
		o=$(gx 'pgrep -u guest -fa "gnome-terminal|ptyxis|kgx" || echo none')
		[ "$o" = none ] || bad="${bad}Ctrl+Alt+T opened a terminal in the learning mode ($o); "
		keys esc wait:1
		as_user guest 'WAYLAND_DISPLAY=wayland-0 setsid -f google-chrome-stable --ozone-platform=wayland --no-first-run --no-default-browser-check https://example.org/ >/dev/null 2>&1' || true
		sleep 12
		shot modes-browser-example-blocked
		manual "$name/blocked" "$out/$ACC_SHOT-$vmid-modes-browser-example-blocked.png (example.org blocked)"
	else
		bad="${bad}guest cannot log in (Dock not checked); "
	fi
	# --- the full mode + LibreOffice (Task 16 Step 5)
	greeter || true
	v=$(B_GROUP=teacher pub modes-desktop) || bad="${bad}cannot publish the teacher bundle; "
	wait_bundle "$v" 30 >/dev/null || bad="${bad}v$v not applied; "
	o=$(gx 'n=$(findmnt -rn | grep -c interface-denied); echo "stubs $n"')
	log "full mode: $o"
	grep -q 'stubs 0' <<<"$o" || bad="${bad}stubs still mounted in the full mode; "
	pid1=""
	for _ in $(seq 1 60); do
		pid1=$(gx 'pgrep -f "flatpak install.*org.libreoffice.LibreOffice" | head -1' | tr -d '\n')
		[ -n "$pid1" ] && break
		sleep 2
	done
	[ -n "$pid1" ] || bad="${bad}LibreOffice install not seen; "
	log "LibreOffice install pid ${pid1:-none}; changing the web app during the install"
	o=$(dock)
	v=$(B_GROUP=teacher B_TEACHER_SED='s|web = \[{ name = "Wikipedia", url = "https://www.wikipedia.org/" }\]|web = [{ name = "Khan Academy", url = "https://www.khanacademy.org/" }]|' pub modes-desktop-web2) || bad="${bad}cannot publish; "
	# timed from the end of the publish (as Task 16 did) until the Dock list in dconf changes
	t0=$SECONDS
	until [ "$(dock)" != "$o" ] || [ $((SECONDS - t0)) -gt 30 ]; do sleep 1; done
	o=$(dock)
	log "Dock $((SECONDS - t0)) s after the publish returned: $o"
	[ $((SECONDS - t0)) -le 10 ] || bad="${bad}web app change during the install took $((SECONDS - t0)) s after the publish (must be ≤10); "
	pid2=$(gx 'pgrep -f "flatpak install.*org.libreoffice.LibreOffice" | head -1' | tr -d '\n')
	log "install process now: ${pid2:-finished}"
	[ -z "$pid2" ] || [ "$pid2" = "$pid1" ] || bad="${bad}install restarted (pid $pid1 → $pid2); "
	t0=$SECONDS
	until dock | grep -q org.libreoffice.LibreOffice.desktop || [ $((SECONDS - t0)) -gt 900 ]; do sleep 10; done
	o=$(dock)
	log "Dock after the install ($((SECONDS - t0)) s): $o"
	grep -q org.libreoffice.LibreOffice.desktop <<<"$o" || bad="${bad}LibreOffice not in the Dock within 15 min; "
	if pw_login t20local "$pwf"; then
		sleep 10
		shot modes-desktop-dock
		manual "$name/desktop-dock" "$out/$ACC_SHOT-$vmid-modes-desktop-dock.png (full mode: Dock has Files and LibreOffice)"
	fi
	v=$(B_GROUP=teacher B_TEACHER_SED='/^flatpak = /d' pub modes-desktop-nolo) || bad="${bad}cannot publish; "
	t0=$SECONDS
	until ! gx 'flatpak list --system --app --columns=application' | grep -q org.libreoffice.LibreOffice || [ $((SECONDS - t0)) -gt 300 ]; do sleep 5; done
	o=$(gx 'flatpak list --system --app --columns=application; cat /var/lib/mastersos-system/flatpak-state.json')
	log "after removing LibreOffice from the list: ${o//$'\n'/ | }"
	grep -q org.libreoffice.LibreOffice <<<"$(head -2 <<<"$o")" && bad="${bad}LibreOffice not uninstalled; "
	grep -q org.gnome.Calculator <<<"$o" || bad="${bad}the hand-installed Calculator is gone too; "
	o=$(report_item flatpak:org.libreoffice.LibreOffice)
	log "report: $o"
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# §6.9 item 3: printing (Task 15 Step 5). cups-ipp-utils is installed on VM 161 for ippeveprinter and removed afterwards
c_print() {
	local name=print bad="" o v q
	start_wait && lab_prep || {
		fail "$name" "does not boot"
		return
	}
	b161 'set -e; dpkg -s cups-ipp-utils >/dev/null 2>&1 || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq cups-ipp-utils >/dev/null; mkdir -p ~/t20-ipp; pkill -x ippeveprinter || true; (setsid nohup ippeveprinter -k -r off -p 8631 -d ~/t20-ipp -f application/pdf,image/pwg-raster,image/urf,image/jpeg mastersos-lab-printer > ~/t20-ipp.log 2>&1 < /dev/null &); sleep 2; pgrep -xa ippeveprinter | cut -c1-60' | sed 's/^/  VM 161: /'
	v=$(B_GROUP=teacher B_TEACHER_SED='/^flatpak = /d' pub "$name") || bad="${bad}cannot publish; "
	wait_bundle "$v" 30 >/dev/null || bad="${bad}v$v not applied; "
	local t0=$SECONDS
	until gx 'LC_ALL=C lpstat -v 2>/dev/null' | grep -q 8631 || [ $((SECONDS - t0)) -gt 120 ]; do sleep 3; done
	o=$(gx 'LC_ALL=C.UTF-8 lpstat -v; LC_ALL=C.UTF-8 lpstat -d; jq -c .printers /var/lib/mastersos-system/system-state.json')
	log "${o//$'\n'/ | }"
	q=$(sed -n 's/^device for \(.*\): ipp:\/\/192.0.2.99:8631.*/\1/p' <<<"$o" | head -1)
	[ -n "$q" ] || bad="${bad}no queue pointing at ippeveprinter; "
	grep -q "system default destination: $q" <<<"$o" || bad="${bad}it is not the default printer; "
	o=$(gx "echo 'MastersOS T20 test page' | lp -d '$q' -t t20 && sleep 15 && LC_ALL=C lpstat -W completed -o '$q' | tail -1")
	log "print: ${o//$'\n'/ | }"
	o=$(b161 'ls ~/t20-ipp | head; grep -cE "Send-Document|Print-Job" ~/t20-ipp.log')
	log "ippeveprinter received: ${o//$'\n'/ | }"
	[ "$(tail -1 <<<"$o")" -ge 1 ] 2>/dev/null || bad="${bad}ippeveprinter received no job; "
	o=$(report_item "printer:教研室 T20")
	log "report: $o"
	[ "$(jq -r .ok <<<"$o" 2>/dev/null)" = true ] || bad="${bad}report item printer:教研室 T20 is not ok; "
	b161 'pkill -x ippeveprinter; rm -rf ~/t20-ipp ~/t20-ipp.log; sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq cups-ipp-utils >/dev/null 2>&1; sudo apt-get autoremove -y -qq >/dev/null 2>&1; dpkg -s cups-ipp-utils >/dev/null 2>&1 && echo "cups-ipp-utils still installed" || echo "cups-ipp-utils removed"' | sed 's/^/  VM 161: /'
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# §6.9 item 4: state.json's version changes within 10 s of the server publishing (timed by the script from the moment the
# commit returns; the time from the start of the publish, which includes several SSH round trips from the Mac through two
# jump hosts, is logged too)
c_apply_within_10s() {
	local name=apply_within_10s bad="" v t i
	start_wait || {
		fail "$name" "does not boot"
		return
	}
	for i in 1 2 3; do
		local t0=$SECONDS t1
		v=$(B_GROUP=teacher B_TEACHER_SED="/^flatpak = /d; /^\[\[config\]\]/,\$ s/^name = \"Teacher laptops\"/name = \"Teacher laptops $i\"/" pub "apply-$i") || {
			bad="${bad}cannot publish; "
			continue
		}
		t1=$SECONDS
		wait_bundle "$v" 30 >/dev/null || true
		t=$((SECONDS - t1))
		log "run $i: state.json at v$v $t s after the publish returned ($((SECONDS - t0)) s from the start of the publish)"
		[ "$t" -le 10 ] || bad="${bad}run $i took $t s after the publish (must be ≤10); "
	done
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# §6.9 item 4: with a proxy in front that does not support held connections (VM 161's nginx cuts /v1/bundle after 5 s),
# a publish still takes effect within 15 min. The server temporarily listens on 127.0.0.1:8481 behind nginx on
# 192.0.2.99:8480; everything is restored afterwards
c_fallback_15min() {
	local name=fallback_15min bad="" o v t0
	start_wait || {
		fail "$name" "does not boot"
		return
	}
	b161 'set -e; cd ~/t12-server
sed "s/^listen = .*/listen = \"127.0.0.1:8481\"/" server.toml > ~/t20-fb.toml
pkill -f "^\./mastersos-server\.bin --config server\.toml$" || true; sleep 1
(setsid nohup ./mastersos-server.bin --config ~/t20-fb.toml >>server.log 2>&1 </dev/null &)
sudo tee /etc/nginx/sites-enabled/t20-fallback >/dev/null <<NG
# Task 20 fallback_15min: a proxy that cannot hold long-poll connections (removed afterwards)
server {
  listen 192.0.2.99:8480;
  location = /v1/bundle { proxy_pass http://127.0.0.1:8481; proxy_read_timeout 5s; }
  location / { proxy_pass http://127.0.0.1:8481; proxy_read_timeout 120s; client_max_body_size 64m; }
}
NG
sudo nginx -t 2>/dev/null && sudo systemctl reload nginx; sleep 2; curl -s -o /dev/null -w "proxy %{http_code}\n" http://192.0.2.99:8480/v1/bundle'
	sleep 70
	o=$(b161 'sudo tail -n 400 /var/log/nginx/access.log | grep -c " 504 "')
	log "long polls cut by nginx (504): $o"
	t0=$SECONDS
	v=$(B_GROUP=teacher B_TEACHER_SED='/^flatpak = /d; /^\[\[config\]\]/,$ s/^name = "Teacher laptops"/name = "Teacher laptops fallback"/' pub "$name") || bad="${bad}cannot publish; "
	o=$(wait_bundle "$v" 960) || bad="${bad}not applied within 15 min; "
	log "through the proxy: state.json at v$v $o s after the publish"
	gx 'journalctl -u mastersos-agent --since -20min --no-pager -o cat | grep -E "长连接|long|504|拉取|已接受设置包" | tail -6' | sed 's/^/  agent: /'
	b161 'sudo rm -f /etc/nginx/sites-enabled/t20-fallback; sudo systemctl reload nginx; pkill -f "^\./mastersos-server\.bin --config /home/mastersos/t20-fb\.toml$" || true; sleep 1; cd ~/t12-server && (setsid nohup ./mastersos-server.bin --config server.toml >>server.log 2>&1 </dev/null &); rm -f ~/t20-fb.toml; sleep 2; curl -s -o /dev/null -w "server restored %{http_code}\n" http://192.0.2.99:8480/v1/bundle' | sed 's/^/  VM 161: /'
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# §6.9 item 9: an apply script runs once, runs again when its content changes, and a timed-out one is killed and reported;
# login scripts as in Task 18 Step 5 (~/login-ran has one line after two logins, the timed-out script is reported failed
# with 超时 (timeout), a fetch within 10 s of a login, SSO accounts run it too, offline + clock 8 days ahead shows the
# stale-settings notice). Also the Task 18 carries: login-queue directory root:root, SIGUSR1 handler installed early.
# The clock is moved last and undone by rolling back to t20-up
c_scripts() {
	local name=scripts bad="" o v pwf run a1 a2 l1 l2 ip
	start_wait && lab_prep || {
		fail "$name" "does not boot"
		return
	}
	pwf=$(local_user)
	# script contents unique to this run: a script only runs when its content hash is new to the machine, and earlier
	# checks already ran the default contents
	run=$(date +%s)
	a1="#!/bin/sh
echo \"apply $run-1 \$(date -u +%FT%TZ)\" >> /var/lib/mastersos-system/t20-apply-ran"
	a2="#!/bin/sh
echo \"apply $run-2 \$(date -u +%FT%TZ)\" >> /var/lib/mastersos-system/t20-apply-ran"
	l1="#!/bin/sh
echo \"login $run-1 \$(date -u +%FT%TZ)\" >> \"\$HOME/login-ran\""
	l2="#!/bin/sh
echo \"login $run-2 \$(date -u +%FT%TZ)\" >> \"\$HOME/login-ran\""
	gx 'rm -f /var/lib/mastersos-system/t20-apply-ran /home/t20local/login-ran'
	v=$(S_APPLY=$a1 S_LOGIN=$l1 B_GROUP=teacher B_TEACHER_SED='/^flatpak = /d' pub scripts-1) || bad="${bad}cannot publish; "
	wait_bundle "$v" 30 >/dev/null || bad="${bad}v$v not applied; "
	sleep 5
	v=$(S_APPLY=$a1 S_LOGIN=$l1 B_GROUP=teacher B_TEACHER_SED='/^flatpak = /d; /^\[\[config\]\]/,$ s/^name = "Teacher laptops"/name = "Teacher laptops 2"/' pub scripts-2) || true
	wait_bundle "$v" 30 >/dev/null || true
	sleep 5
	o=$(gx 'cat /var/lib/mastersos-system/t20-apply-ran')
	log "apply script after two bundles with the same script: ${o//$'\n'/ | }"
	[ "$(grep -c "apply $run-1" <<<"$o")" = 1 ] || bad="${bad}the unchanged apply script did not run exactly once; "
	v=$(S_APPLY=$a2 S_LOGIN=$l1 B_GROUP=teacher B_TEACHER_SED='/^flatpak = /d' pub scripts-3) || true
	wait_bundle "$v" 30 >/dev/null || true
	sleep 5
	o=$(gx 'cat /var/lib/mastersos-system/t20-apply-ran')
	log "after changing the content: ${o//$'\n'/ | }"
	[ "$(grep -c "apply $run-2" <<<"$o")" = 1 ] || bad="${bad}the changed apply script did not run exactly once; "
	v=$(S_APPLY='#!/bin/sh
echo $$ > /run/t20-sleeper.pid; sleep 600' S_LOGIN=$l1 B_GROUP=teacher B_TEACHER_SED='/^flatpak = /d; s|{ path = "scripts/t20-apply.sh", when = "apply" }|{ path = "scripts/t20-apply.sh", when = "apply", timeout_secs = 5 }|' pub scripts-timeout) || bad="${bad}cannot publish the timeout bundle; "
	sleep 25
	o=$(device_json "$(my_id)" | jq -c '[.results[]? | select(.item | test("t20-apply"))]')
	log "timed-out apply script: report ${o}; process $(gx 'p=$(cat /run/t20-sleeper.pid 2>/dev/null); [ -n "$p" ] && { kill -0 $p 2>/dev/null && echo "still running" || echo "killed"; } || echo "never started"')"
	# the agent's report detail says timeout / 超时
	grep -qE '超时|timeout' <<<"$o" || bad="${bad}no timeout in the report of the timed-out apply script; "
	gx 'p=$(cat /run/t20-sleeper.pid 2>/dev/null); [ -z "$p" ] || ! kill -0 $p 2>/dev/null' || bad="${bad}the timed-out apply script was not killed; "
	# login scripts (the apply script goes back to a2, which already ran)
	v=$(S_APPLY=$a2 S_LOGIN=$l1 B_GROUP=teacher B_TEACHER_SED='/^flatpak = /d' pub scripts-login) || true
	wait_bundle "$v" 30 >/dev/null || true
	o=$(gx 'stat -c "%U:%G %a %n" /run/mastersos/login-queue 2>/dev/null; grep -E "^SigCgt" /proc/$(systemctl show -p MainPID --value mastersos-agent)/status')
	log "login queue directory and SIGUSR1: ${o//$'\n'/ | }"
	grep -q '^root:root 700 /run/mastersos/login-queue' <<<"$o" || bad="${bad}login queue directory is not root:root 700; "
	# the fetch a login triggers: GET /v1/bundle from this VM, captured on VM 161, against the agent's "a session logged in"
	ip=$(gx "ip -4 -o addr show scope global | awk '{print \$4}' | cut -d/ -f1 | head -1" | tr -d '\n')
	b161 "rm -f ~/t20-cap.txt; (setsid sudo timeout 400 tcpdump -l -n -tttt -A -i any 'tcp dst port 8480 and src host $ip' 2>/dev/null </dev/null | awk '/^20[0-9][0-9]-/ {ts=\$2} /GET \/v1\/bundle/ {print ts; fflush()}' > ~/t20-cap.txt 2>/dev/null &) ; sleep 1"
	pw_login t20local "$pwf" || bad="${bad}t20local cannot log in; "
	sleep 15
	o=$(gx "journalctl -u mastersos-agent --since -2min -o short-iso-precise --no-pager | grep -m1 '会话登录' | awk '{print \$1}'")
	local caps
	caps=$(b161 'sudo pkill -x tcpdump; sleep 1; cat ~/t20-cap.txt; rm -f ~/t20-cap.txt')
	log "login seen by the agent at ${o:-?}; GET /v1/bundle from the VM at: ${caps//$'\n'/ }"
	o=$(python3 -c '
import sys, datetime
t = sys.argv[1].strip()
if not t: sys.exit("no login line")
login = datetime.datetime.fromisoformat(t).astimezone(datetime.timezone.utc).replace(tzinfo=None)
best = None
for c in sys.argv[2].split():
    h, m, rest = c.split(":"); sec = float(rest)
    g = login.replace(hour=int(h), minute=int(m), second=0, microsecond=0) + datetime.timedelta(seconds=sec)
    d = (g - login).total_seconds()
    for dd in (d, d - 25200, d + 25200):   # tcpdump prints local time on VM 161; the journal line is converted to UTC
        if 0 <= dd < 120 and (best is None or dd < best): best = dd
print("%.1f" % best if best is not None else "none")' "$o" "$caps" 2>&1)
	log "fetch $o s after the agent saw the login"
	awk -v d="$o" 'BEGIN{exit !(d+0 == d && d <= 10)}' || bad="${bad}no fetch within 10 s of the login ($o); "
	pw_login t20local "$pwf" || true
	sleep 8
	o=$(gx 'cat /home/t20local/login-ran')
	log "login-ran (in the home directory) after two logins: ${o//$'\n'/ | }"
	[ "$(grep -c "login $run-1" <<<"$o")" = 1 ] || bad="${bad}the login script did not run exactly once over two logins; "
	v=$(S_APPLY=$a2 S_LOGIN=$l2 B_GROUP=teacher B_TEACHER_SED='/^flatpak = /d' pub scripts-login2) || true
	wait_bundle "$v" 30 >/dev/null || true
	pw_login t20local "$pwf" || true
	sleep 8
	o=$(gx 'cat /home/t20local/login-ran')
	[ "$(grep -c "login $run-2" <<<"$o")" = 1 ] || bad="${bad}no new line after changing the login script; "
	if [ -s "$state/s1zbob_school_test.pw" ]; then
		v=$(S_APPLY=$a2 S_LOGIN=$l2 B_IDP=zitadel B_DOMAINS='["school.test"]' B_GROUP=teacher B_TEACHER_SED='/^flatpak = /d' pub scripts-login-sso) || true
		wait_bundle "$v" 30 >/dev/null || true
		ensure_sso zitadel s1zbob@school.test s1zbob@school.test || true
		pw_login s1zbob@school.test "$state/s1zbob_school_test.pw" || bad="${bad}s1zbob cannot log in; "
		sleep 10
		o=$(gx "cat '/home/s1zbob@school.test/login-ran' 2>&1")
		log "SSO user's login-ran: ${o//$'\n'/ | }"
		grep -q "login $run-2" <<<"$o" || bad="${bad}the SSO user did not run the login script; "
	fi
	v=$(S_APPLY=$a2 S_LOGIN='#!/bin/sh
sleep 600' B_GROUP=teacher B_TEACHER_SED='/^flatpak = /d; s|{ path = "scripts/t20-login.sh", when = "login" }|{ path = "scripts/t20-login.sh", when = "login", timeout_secs = 5 }|' pub scripts-login-timeout) || true
	wait_bundle "$v" 30 >/dev/null || true
	pw_login t20local "$pwf" || true
	sleep 30
	o=$(device_json "$(my_id)" | jq -c '[.results[]? | select(.item | test("^login-script:"))]')
	log "timed-out login script: report $o"
	grep -qE '超时|timeout' <<<"$o" || bad="${bad}no timeout in the report of the timed-out login script; "
	grep -qE 't20local|@' <<<"$o" && bad="${bad}the login-script report contains a user name; "
	# stale-settings notice: no server (offline), clock 8 days ahead, log in again
	lab_prep || true
	link 1
	gx 'timedatectl set-ntp false; date -s "+8 days" >/dev/null; date' | sed 's/^/  VM clock: /'
	pw_login t20local "$pwf" stale || bad="${bad}t20local cannot log in with the clock 8 days ahead; "
	sleep 12
	shot scripts-stale-notice
	manual "$name/stale" "$out/$ACC_SHOT-$vmid-scripts-stale-notice.png (the settings-may-be-stale notice)"
	# carry (Task 18): SSO user's local password offline with the clock 8 days ahead
	if [ -s "$state/s1zbob_school_test.pw" ]; then
		if pw_login s1zbob@school.test "$state/s1zbob_school_test.pw" stale-sso; then
			log "clock +8 days, offline: s1zbob logged in with the local password"
		else
			shot scripts-stale-sso-refused
			o=$(gx 'journalctl -b --since -3min -o cat --no-pager | grep -iE "authd|offline|expired|token" | tail -4')
			log "clock +8 days, offline: s1zbob's local password refused: ${o//$'\n'/ | }"
		fi
	fi
	link 0
	stop_vm
	rollback t20-up
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# §6.9 item 8 (Task 17 Step 5): locking while a student is logged in ends the session within 10 s and the login screen
# shows the message; the student is refused with a reason; an admin SSO account can still log in; unlocking restores;
# time zone and language; a language not in the image is reported as failed. Task 17 carries: locking a machine that is
# installing LibreOffice also ends the session within 10 s; a new user's Downloads folder name under Thai
c_lock() {
	local name=lock bad="" o v pwf t0 lockdev unlockdev
	start_wait && lab_prep || {
		fail "$name" "does not boot"
		return
	}
	pwf=$(local_user)
	lockdev=$(printf '[[device]]\ndevice_id = "%s"\ngroup = "teacher"\nlocked = { message = "本机已挂失，请交回 IT 办公室 / This laptop is reported lost, please return it to the IT office" }\n' "$(my_id)")
	unlockdev=$(printf '[[device]]\ndevice_id = "%s"\ngroup = "teacher"\n' "$(my_id)")
	v=$(B_IDP=zitadel B_DOMAINS='["school.test"]' B_ADMINS='["s1zbob@school.test"]' B_DEVICES=$unlockdev B_TEACHER_SED='/^flatpak = /d' pub lock-0) || bad="${bad}cannot publish; "
	wait_bundle "$v" 30 >/dev/null || true
	ensure_sso zitadel s1zbob@school.test s1zbob@school.test || bad="${bad}s1zbob cannot log in before the lock; "
	pw_login t20local "$pwf" || bad="${bad}t20local cannot log in; "
	sleep 5
	v=$(B_IDP=zitadel B_DOMAINS='["school.test"]' B_ADMINS='["s1zbob@school.test"]' B_DEVICES=$lockdev B_TEACHER_SED='/^flatpak = /d' pub lock-1) || bad="${bad}cannot publish the lock; "
	t0=$SECONDS
	until ! has_session t20local || [ $((SECONDS - t0)) -gt 30 ]; do sleep 1; done
	log "lock: t20local's session ended $((SECONDS - t0)) s after the publish returned"
	[ $((SECONDS - t0)) -le 10 ] || bad="${bad}session ended $((SECONDS - t0)) s after the publish (must be ≤10); "
	sleep 4
	keys spc wait:2
	shot lock-greeter
	manual "$name/greeter" "$out/$ACC_SHOT-$vmid-lock-greeter.png (the lost-laptop message on the login screen)"
	o=$(pty_run student 'su - t20local -c true' <"$pwf")
	log "t20local while locked: ${o//$'\n'/ | }"
	# agent message (bilingual): 这台电脑已被学校锁定，请联系 IT / This computer has been locked by the school; please contact IT
	grep -q 'This computer has been locked by the school' <<<"$o" || bad="${bad}local user not refused while locked, or no reason; "
	if [ -s "$state/s1zbob_school_test.pw" ]; then
		pw_login s1zbob@school.test "$state/s1zbob_school_test.pw" lock-admin && log "admin s1zbob logged in while locked" || bad="${bad}admin SSO account cannot log in while locked; "
		greeter || true
	fi
	o=$(report_item lock)
	log "report lock: $o"
	v=$(B_IDP=zitadel B_DOMAINS='["school.test"]' B_ADMINS='["s1zbob@school.test"]' B_DEVICES=$unlockdev B_TEACHER_SED='/^flatpak = /d' pub lock-2) || true
	wait_bundle "$v" 30 >/dev/null || true
	pw_login t20local "$pwf" || bad="${bad}t20local cannot log in after unlocking; "
	# lock while LibreOffice is installing
	v=$(B_IDP=zitadel B_DOMAINS='["school.test"]' B_ADMINS='["s1zbob@school.test"]' B_DEVICES=$unlockdev pub lock-lo) || true
	for _ in $(seq 1 60); do gx 'pgrep -f "flatpak install.*LibreOffice"' >/dev/null 2>&1 && break; sleep 2; done
	gx 'pgrep -fa "flatpak install.*LibreOffice" | cut -c1-80' | sed 's/^/  installing: /'
	has_session t20local || pw_login t20local "$pwf" || true
	v=$(B_IDP=zitadel B_DOMAINS='["school.test"]' B_ADMINS='["s1zbob@school.test"]' B_DEVICES=$lockdev pub lock-lo-1) || true
	t0=$SECONDS
	until ! has_session t20local || [ $((SECONDS - t0)) -gt 30 ]; do sleep 1; done
	log "lock during the LibreOffice install: session ended $((SECONDS - t0)) s after the publish returned; install process $(gx 'pgrep -f "flatpak install.*LibreOffice" >/dev/null && echo still running || echo finished')"
	[ $((SECONDS - t0)) -le 10 ] || bad="${bad}lock during the LibreOffice install took $((SECONDS - t0)) s to end the session; "
	# time zone and language
	v=$(B_IDP=zitadel B_DOMAINS='["school.test"]' B_ADMINS='["s1zbob@school.test"]' B_DEVICES=$unlockdev B_LOCALE=th_TH.UTF-8 B_TEACHER_SED='/^flatpak = /d' pub lock-th) || true
	wait_bundle "$v" 30 >/dev/null || true
	sleep 5
	o=$(gxm '
timedatectl show -p Timezone --value | grep -qx Asia/Bangkok || echo "time zone is not Asia/Bangkok"
localectl status | grep -q "LANG=th_TH.UTF-8" || echo "localectl is not th_TH.UTF-8"
test -f /etc/locale.conf -a ! -L /etc/locale.conf || echo "/etc/locale.conf is not a real file"
[ "$(readlink -f /etc/default/locale)" = /etc/locale.conf ] || echo "/etc/default/locale does not resolve to /etc/locale.conf"
') || o="the remote check block did not finish"
	[ -z "$o" ] || bad="$bad${o//$'\n'/; }; "
	reboot_wait || bad="${bad}does not boot again; "
	lab_prep || true
	o=$(gx 'localectl status | grep LANG; test -f /etc/locale.conf -a ! -L /etc/locale.conf && echo real-file')
	log "after a reboot: ${o//$'\n'/ | }"
	grep -q 'th_TH' <<<"$o" || bad="${bad}language lost after a reboot; "
	# a new user's first login under Thai: XDG folders get Thai names (Task 17 carry)
	gx 'userdel -r t20th >/dev/null 2>&1; useradd -m -s /bin/bash t20th' >/dev/null
	local thpw
	thpw=$(newpw t20th)
	{ printf 't20th:'; cat "$thpw"; echo; } | gx_stdin chpasswd
	pw_login t20th "$thpw" th || bad="${bad}new user cannot log in under Thai; "
	sleep 12
	shot lock-th-desktop
	o=$(gx 'ls /home/t20th; cat /home/t20th/.config/user-dirs.dirs 2>/dev/null | grep DOWNLOAD')
	log "new user under Thai: ${o//$'\n'/ | }"
	grep -q 'ดาวน์โหลด' <<<"$o" || bad="${bad}the new user's Downloads folder does not have the Thai name; "
	v=$(B_IDP=zitadel B_DOMAINS='["school.test"]' B_DEVICES=$unlockdev B_LOCALE=fr_FR.UTF-8 B_TEACHER_SED='/^flatpak = /d' pub lock-fr) || true
	wait_bundle "$v" 30 >/dev/null || true
	sleep 8
	o=$(report_item locale)
	log "fr_FR.UTF-8: report ${o}; $(gx 'localectl status | grep LANG')"
	[ "$(jq -r .ok <<<"$o" 2>/dev/null)" = false ] || bad="${bad}a language missing from the image is not reported as failed; "
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# Task 12 Step 5: admin_users = ["S1zBob@school.test"] (upper case on purpose) → s1zbob's id -un is lower case, sudo -v
# with the local password works, GNOME Settings' Users page; s1zeve (not listed) fails sudo -v; a local admin created in
# Settings (accountsservice account type 1) is not in the sudo group after the next apply when local_users_admin = false
c_admins() {
	local name=admins bad="" o v
	start_wait && lab_prep || {
		fail "$name" "does not boot"
		return
	}
	v=$(B_IDP=zitadel B_ADMINS='["S1zBob@school.test"]' B_GROUP=teacher B_TEACHER_SED='/^flatpak = /d' pub "$name") || bad="${bad}cannot publish; "
	wait_bundle "$v" 30 >/dev/null || true
	ensure_sso zitadel S1zBob@school.test s1zbob@school.test || bad="${bad}s1zbob cannot log in; "
	sleep 3
	o=$(gx 'grep -v "^#" /etc/sudoers.d/mastersos-admins; stat -c "%a %U" /etc/sudoers.d/mastersos-admins; grep -o "unix-user:[^\"]*" /etc/polkit-1/rules.d/49-mastersos-admins.rules')
	log "sudoers / polkit: ${o//$'\n'/ | }"
	grep -q 's1zbob@school.test' <<<"$o" || bad="${bad}lower-case s1zbob@school.test not in sudoers; "
	grep -q 'S1zBob' <<<"$o" && bad="${bad}upper-case name in sudoers; "
	grep -q 'unix-user:s1zbob@school.test' <<<"$o" || bad="${bad}s1zbob not in the polkit rule; "
	o=$({ cat "$state/s1zbob_school_test.pw"; echo; } | pty_run s1zbob@school.test 'id -un; sudo -v && echo SUDO-OK')
	log "s1zbob: ${o//$'\n'/ | }"
	grep -qx 's1zbob@school.test' <<<"$o" || bad="${bad}id -un is not lower case; "
	grep -q SUDO-OK <<<"$o" || bad="${bad}s1zbob's sudo -v failed; "
	if pw_login s1zbob@school.test "$state/s1zbob_school_test.pw"; then
		sleep 8
		# close whatever opens at login (the overview, GNOME's rename-folders dialog after a language change)
		keys esc wait:1 esc wait:1
		# open the Users panel through the session bus, as the Settings launcher does
		as_user s1zbob@school.test "gdbus call --session --dest org.gnome.Settings --object-path /org/gnome/Settings --method org.gtk.Actions.Activate launch-panel \"[<('users', @av [])>]\" '{}'" >/dev/null 2>&1 || true
		sleep 8
		shot admins-gnome-users
		manual "$name/gnome-users" "$out/$ACC_SHOT-$vmid-admins-gnome-users.png (GNOME Settings Users page; the admin can unlock)"
	fi
	if [ -s "$state/s1zeve_other_test.pw" ] && gx 'getent passwd s1zeve@other.test' >/dev/null 2>&1; then
		o=$({ cat "$state/s1zeve_other_test.pw"; echo; cat "$state/s1zeve_other_test.pw"; echo; } | pty_run s1zeve@other.test 'sudo -v && echo SUDO-OK')
		log "s1zeve (not listed): ${o//$'\n'/ | }"
		grep -q SUDO-OK <<<"$o" && bad="${bad}s1zeve can sudo too; "
	else
		# eve was refused by the domain rule earlier (no local password yet): no domain rule here, so log her in once
		if sso_first_login zitadel s1zeve@other.test s1zeve@other.test admins-eve; then
			o=$({ cat "$state/s1zeve_other_test.pw"; echo; } | pty_run s1zeve@other.test 'sudo -v && echo SUDO-OK')
			log "s1zeve (not listed): ${o//$'\n'/ | }"
			grep -q SUDO-OK <<<"$o" && bad="${bad}s1zeve can sudo too; "
		else
			bad="${bad}s1zeve cannot log in (the non-admin case is unchecked); "
		fi
	fi
	gx 'id t20adm >/dev/null 2>&1 || busctl call org.freedesktop.Accounts /org/freedesktop/Accounts org.freedesktop.Accounts CreateUser ssi t20adm "T20 Admin" 1 >/dev/null; id t20adm' | sed 's/^/  admin created in Settings: /'
	kick
	sleep 15
	o=$(gx 'id t20adm')
	log "after the next apply: $o"
	grep -qE '\(sudo\)|\(admin\)' <<<"$o" && bad="${bad}t20adm still in sudo/admin with local_users_admin = false; "
	gx 'userdel -r t20adm >/dev/null 2>&1' || true
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# Task 19 Step 5: s1zbob (admin, oldest login), s1zeve (next), s1zcarol (most recent) have each logged in; /home is filled
# to under 10 GiB free → s1zeve's home is removed, bob's and carol's stay, root's /home/fill stays, report homes carries no
# names; eve logging in again gets a new home. Logins within 15 min count as active (never removed), so the three
# last-login records are moved back in time (order kept). Also the Task 19 carry affb43f3: a record without a home is kept
# (7 days)
c_homes() {
	local name=homes bad="" o v free sz u pf t0 eu
	start_wait && lab_prep || {
		fail "$name" "does not boot"
		return
	}
	v=$(B_IDP=zitadel B_ADMINS='["s1zbob@school.test"]' B_GROUP=teacher B_TEACHER_SED='/^flatpak = /d' pub "$name") || bad="${bad}cannot publish; "
	wait_bundle "$v" 30 >/dev/null || true
	for u in s1zbob@school.test s1zeve@other.test s1zcarol@school.test; do
		pf=$state/${u//[^a-z0-9]/_}.pw
		if gx "getent passwd '$u'" >/dev/null 2>&1 && [ -s "$pf" ]; then
			pw_login "$u" "$pf" || bad="${bad}$u cannot log in; "
		else
			sso_first_login zitadel "$u" "$u" "homes-${u%%@*}" || bad="${bad}first login of $u failed; "
		fi
		sleep 5
	done
	greeter || true
	gx 'for u in $(loginctl list-users --no-legend | awk "\$1 >= 10000 {print \$2}"); do loginctl terminate-user "$u"; done; sleep 3; fallocate -l 7G "/home/s1zeve@other.test/big.bin"; chown s1zeve@other.test "/home/s1zeve@other.test/big.bin"' || true
	o=$(gx 'f=/var/lib/mastersos-system/homes/last-login.json; jq -c . $f; b=$(id -u s1zbob@school.test); e=$(id -u s1zeve@other.test); c=$(id -u s1zcarol@school.test)
jq --arg b $b --arg e $e --arg c $c --arg tb "$(date -u -d "-3 hours" +%FT%T.00Z)" --arg te "$(date -u -d "-2 hours" +%FT%T.00Z)" --arg tc "$(date -u -d "-1 hours" +%FT%T.00Z)" ".[\$b]=\$tb | .[\$e]=\$te | .[\$c]=\$tc" $f > $f.t20 && cat $f.t20 > $f && rm $f.t20; jq -c . $f')
	log "last-login: ${o//$'\n'/ → }"
	# eve's 7 GiB: the cleanup starts below max(15 %, 10 GiB) free and stops at max(25 %, 15 GiB) (Task 19 ruling C1), so
	# with 9 GiB free removing eve alone gets back over 15 GiB and carol (more recent) stays
	free=$(gx 'df -B1 --output=avail /home | tail -1' | tr -d ' \n')
	sz=$((free - 9 * 1024 * 1024 * 1024))
	gx "fallocate -l $sz /home/fill && df -h /home | tail -1" | sed 's/^/  filled: /'
	# the homes job runs hourly and on a new bundle, never on a signal (Task 19 review N1: logins send SIGUSR1); publish one
	B_IDP=zitadel B_ADMINS='["s1zbob@school.test"]' B_GROUP=teacher B_TEACHER_SED='/^flatpak = /d; /^\[\[config\]\]/,$ s/^name = "Teacher laptops"/name = "Teacher laptops homes"/' pub homes-wake >/dev/null || bad="${bad}cannot publish the wake-up bundle; "
	t0=$SECONDS
	until ! gx 'test -d "/home/s1zeve@other.test"' 2>/dev/null || [ $((SECONDS - t0)) -gt 180 ]; do sleep 5; done
	o=$(gx 'ls -A /home')
	log "after $((SECONDS - t0)) s: /home = ${o//$'\n'/ }; $(gx 'df -h /home | tail -1'); agent: $(gx 'journalctl -u mastersos-agent --since -5min -o cat --no-pager | grep -m1 "homes"')"
	grep -qx 's1zeve@other.test' <<<"$o" && bad="${bad}s1zeve's home not removed; "
	grep -qx 's1zbob@school.test' <<<"$o" || bad="${bad}admin s1zbob's home was removed; "
	grep -qx 's1zcarol@school.test' <<<"$o" || bad="${bad}most recent s1zcarol was removed; "
	grep -qx 'fill' <<<"$o" || bad="${bad}/home/fill is gone; "
	eu=$(gx 'id -u s1zeve@other.test' | tr -d '\n')
	o=$(gx 'jq -c . /var/lib/mastersos-system/homes/last-login.json')
	log "last-login after the cleanup: $o"
	grep -q "\"$eu\"" <<<"$o" || bad="${bad}eve's record was dropped with her home (affb43f3: keep 7 days); "
	o=$(report_item homes)
	log "report: $o"
	grep -qE 's1z|school.test|other.test' <<<"$(device_json "$(my_id)")" && bad="${bad}the report contains user names or domains; "
	gx 'rm -f /home/fill; fstrim /home 2>/dev/null; true'
	pw_login s1zeve@other.test "$state/s1zeve_other_test.pw" homes-eve-relogin || bad="${bad}eve cannot log in again after her home was removed; "
	sleep 8
	o=$(gx 'stat -c "%U %a" "/home/s1zeve@other.test"; ls -A "/home/s1zeve@other.test" | head -5 | tr "\n" " "')
	log "eve logged in again: ${o//$'\n'/ | }"
	grep -q 'big.bin' <<<"$o" && bad="${bad}eve's old files are still there; "
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# All of Task 11 Step 5 (cart group, guest on): write files and start background processes in a guest session;
# systemd-cgls shows no mastersos-agent under user-1999.slice; within 10 s of logout uid 1999 has no processes, the cleanup
# service succeeded and ran in system.slice, nothing left in /tmp and /dev/shm, /home/guest is a fresh empty tmpfs,
# guest-ready is back; the next guest does not see ~/mark; a local user's background process survives logout
# (KillOnlyUsers=guest)
c_guest_wipe() {
	local name=guest_wipe bad="" o v pwf t0
	start_wait && lab_prep || {
		fail "$name" "does not boot"
		return
	}
	pwf=$(local_user)
	v=$(B_GROUP=cart B_CART_SED='s/login_methods = \["sso", "guest"\]/login_methods = ["sso", "guest", "local"]/' pub "$name") || bad="${bad}cannot publish; "
	wait_bundle "$v" 30 >/dev/null || true
	gx 'mkdir -p /run/systemd/system/mastersos-guest-cleanup.service.d && printf "[Service]\nExecStartPre=/bin/sh -c \"cat /proc/self/cgroup > /run/t20-cleanup-cgroup\"\n" > /run/systemd/system/mastersos-guest-cleanup.service.d/t20-probe.conf && systemctl daemon-reload; rm -f /run/t20-cleanup-cgroup'
	guest_login || bad="${bad}guest cannot log in; "
	sleep 8
	# a background process the way a guest can leave one behind: started by the guest's own user manager (apps run there,
	# under user@1999.service). Its stdio goes to /dev/null, otherwise the guest-agent exec waits for it. (Moving a process
	# into the session scope from outside is refused: "Process migration not available on non-delegated units"; a
	# browser-mode guest has no terminal to start one there either.)
	gx 'runuser -u guest -- sh -c "echo x > /home/guest/mark; echo y > /tmp/guestfile; echo z > /dev/shm/guestshm; mkdir -p /var/tmp/guestdir"
runuser -u guest -- env XDG_RUNTIME_DIR=/run/user/1999 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1999/bus systemd-run --user -q --unit=t20-guest-usleep sleep 100002 </dev/null >/dev/null 2>&1
ps -o pid,cgroup -u guest | grep sleep >&2' || true
	o=$(gx 'systemd-cgls --no-pager /user.slice/user-1999.slice | grep -c "mastersos-agent"; pgrep -u 1999 -c')
	log "session open: $(head -1 <<<"$o") mastersos-agent under user-1999.slice, $(tail -1 <<<"$o") processes of uid 1999"
	[ "$(head -1 <<<"$o")" = 0 ] || bad="${bad}mastersos-agent under user-1999.slice; "
	t0=$SECONDS
	gx 'loginctl terminate-user guest'
	until [ -z "$(gx 'pgrep -u 1999' 2>/dev/null)" ] || [ $((SECONDS - t0)) -gt 30 ]; do sleep 1; done
	log "uid 1999 had no processes $((SECONDS - t0)) s after logout"
	[ $((SECONDS - t0)) -le 10 ] || bad="${bad}guest processes gone only after $((SECONDS - t0)) s (must be ≤10); "
	sleep 3
	o=$(gxm '
[ "$(systemctl show -p Result --value mastersos-guest-cleanup)" = success ] || echo "cleanup service is not success"
grep -qx "0::/system.slice/mastersos-guest-cleanup.service" /run/t20-cleanup-cgroup || echo "cleanup service cgroup is $(cat /run/t20-cleanup-cgroup 2>&1)"
for f in /tmp/guestfile /dev/shm/guestshm /var/tmp/guestdir; do [ ! -e $f ] || echo "$f is still there"; done
[ "$(findmnt -no FSTYPE /home/guest)" = tmpfs ] || echo "/home/guest is not tmpfs"
[ -z "$(ls -A /home/guest)" ] || echo "/home/guest is not empty"
test -e /run/mastersos/guest-ready || echo "guest-ready did not come back"
') || o="the remote check block did not finish"
	[ -z "$o" ] || bad="$bad${o//$'\n'/; }; "
	guest_login || bad="${bad}second guest cannot log in; "
	sleep 8
	o=$(gx 'ls -A /home/guest; test -e /home/guest/mark && echo "mark is still there"')
	log "second guest's home: ${o//$'\n'/ }"
	grep -q 'mark is still there' <<<"$o" && bad="${bad}second guest sees ~/mark; "
	shot guest-second-session
	gx 'loginctl terminate-user guest'
	# a local user's background process survives logout
	pw_login t20local "$pwf" || bad="${bad}t20local cannot log in; "
	gx 'u=$(id -u t20local); systemd-run -q --uid=t20local --slice=user-$u.slice --unit=t20-local-sleep sleep 200000; loginctl terminate-user t20local; sleep 15; systemctl is-active t20-local-sleep; systemctl stop t20-local-sleep' | sed 's/^/  local user, 15 s after logout, background process: /' | grep -q ': active' || bad="${bad}the local user's background process was killed at logout; "
	gx 'rm -rf /run/systemd/system/mastersos-guest-cleanup.service.d/t20-probe.conf /run/t20-cleanup-cgroup; systemctl daemon-reload'
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# Task 11 re-review parked N4 (carry): the guest stacks a FUSE mount under /tmp and /home/guest (the image has flatpak's
# revokefs-fuse and the setuid fusermount3). Does the cleanup then fail on every retry, leaving the guest unavailable
# until a reboot? Reproduce and record only
c_guest_fuse() {
	local name=guest_fuse bad="" o v
	start_wait && lab_prep || {
		fail "$name" "does not boot"
		return
	}
	v=$(B_GROUP=cart pub "$name") || bad="${bad}cannot publish; "
	wait_bundle "$v" 30 >/dev/null || true
	guest_login || {
		fail "$name" "guest cannot log in"
		return
	}
	sleep 6
	# revokefs-fuse daemonizes; its daemons are moved into the guest's session scope, as if the guest had run it from a
	# terminal (a transient service would kill them as soon as the main process exits)
	o=$(gx 'sid=$(loginctl list-sessions --no-legend | awk "\$3 == \"guest\" && \$4 == \"seat0\" {print \$1}" | head -1)
runuser -u guest -- sh -c "mkdir -p /tmp/fsrc /tmp/fmnt /home/guest/hsrc /home/guest/hmnt; /usr/libexec/revokefs-fuse /tmp/fsrc /tmp/fmnt; /usr/libexec/revokefs-fuse /home/guest/hsrc /home/guest/hmnt" </dev/null >/dev/null 2>&1
for p in $(pgrep -u guest -x revokefs-fuse); do busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager AttachProcessesToUnit ssau "session-$sid.scope" "" 1 "$p"; done
sleep 1; findmnt -rn -t fuse.revokefs-fuse -o TARGET,SOURCE')
	log "guest's FUSE mounts: ${o//$'\n'/ | }"
	grep -q fmnt <<<"$o" || bad="${bad}no FUSE mount was created (N4 not exercised); "
	gx 'loginctl terminate-user guest'
	sleep 20
	o=$(gx 'systemctl show -p Result --value mastersos-guest-cleanup; journalctl -u mastersos-guest-cleanup --since -1min -o cat --no-pager | tail -3; findmnt -rn -o TARGET,FSTYPE | grep -E "fmnt|hmnt|/home/guest"; test -e /run/mastersos/guest-ready && echo "guest-ready present" || echo "guest-ready missing"')
	log "after logout: ${o//$'\n'/ | }"
	if grep -q 'guest-ready missing' <<<"$o"; then
		sleep 70
		o=$(gx 'systemctl show -p Result --value mastersos-guest-cleanup; journalctl -u mastersos-guest-cleanup --since -2min -o cat --no-pager | tail -2; test -e /run/mastersos/guest-ready && echo "guest-ready present" || echo "guest-ready missing"')
		log "a minute later (after retries): ${o//$'\n'/ | }"
		grep -q 'guest-ready missing' <<<"$o" && bad="${bad}the guest's FUSE mount keeps the cleanup failing and the guest unavailable (N4 holds); "
	fi
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# --- serial console ------------------------------------------------------------------------------
# wait for several prompts in turn on the serial console and answer each (answers only from stdin, one per line; the
# prompt regexes are arguments). Same approach as accept-common.sh's serial_answer, but all in one connection so no
# prompt is missed between two connections
serial_answers() { # printf '%s\n' answers… | serial_answers <timeout seconds> <regex…>
	local t=$1
	shift
	pve "pkill -f '[k]hunos-serial-logger $vmid'; pkill -f '[s]ocat -u UNIX-CONNECT:/var/run/qemu-server/$vmid.serial0'; sleep 0.5
python3 -c '
import re, select, socket, sys, time
answers = [l.rstrip(\"\\n\") for l in sys.stdin]
limit = time.time() + float(sys.argv[1]); pats = sys.argv[3:]
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[2])
buf = b\"\"
for i, p in enumerate(pats):
    pat = re.compile(p.encode())
    while not pat.search(buf):
        if time.time() > limit:
            sys.exit(\"serial_answers: prompt %d never appeared: %s\" % (i + 1, p))
        if select.select([s], [], [], 1)[0]:
            buf = (buf + s.recv(4096))[-16384:]
    buf = b\"\"
    time.sleep(1)
    for c in answers[i] + chr(13):
        s.send(c.encode()); time.sleep(0.05)
    print(\"answered %d: %s\" % (i + 1, p))
out, end = b\"\", time.time() + 15
while time.time() < end:
    if select.select([s], [], [], 1)[0]:
        out += s.recv(4096)
txt = re.sub(rb\"\\x1b\\[[0-9;?]*[a-zA-Z]\", b\"\", out).decode(errors=\"replace\").replace(chr(13), \"\")
print(\"\\n\".join([l for l in txt.splitlines() if \"mastersos-factory-reset\" in l][:6]))
' '$t' /var/run/qemu-server/$vmid.serial0 $(printf "'%s' " "$@")"
	local rc=$?
	serial_logger
	return "$rc"
}
recovery_key() { # recovery_key <device_id> <luks_uuid>: stdout only, piped straight into serial_answers
	api recovery GET "/v1/admin/devices/$1/recovery-keys" | jq -r --arg u "$2" '[.[] | select(.luks_uuid == $u)][0].recovery_key // empty'
}
reset_entry() { gx '. /usr/lib/os-release; bootctl set-oneshot "MastersOS_${IMAGE_VERSION}_x86-64.efi@factory-reset" && echo "MastersOS_${IMAGE_VERSION}_x86-64.efi@factory-reset"' | tr -d '\n'; }
luks_uuid() { gx 'cryptsetup luksUUID /dev/gpt-auto-root-luks' | tr -d '\n'; }

# §6.9 item 7 (Task 5 Step 5): on the managed 165, three wrong recovery keys wipe nothing; the right key + ERASE wipes it
# and the school's settings come back. Rolls back to t20-up afterwards
c_reset_local() {
	local name=reset_local bad="" o id luks luks2 v0 rows0 rows1 t0
	start_wait || {
		fail "$name" "does not boot"
		return
	}
	v0=$(B_GROUP=teacher B_TEACHER_SED='/^flatpak = /d' pub reset-local) || bad="${bad}cannot publish; "
	wait_bundle "$v0" 30 >/dev/null || true
	gx 'runuser -u student -- sh -c "echo keep > /home/student/keep-me"'
	id=$(my_id)
	luks=$(luks_uuid)
	rows0=$(recovery_rows "$id")
	log "before: device $id, LUKS $luks, $rows0 recovery-key rows; boot entry $(reset_entry)"
	pve "qm reboot $vmid --timeout 180" >/dev/null
	o=$(printf 'WRONG-1111-2222\nWRONG-3333-4444\nWRONG-5555-6666\n' | serial_answers 300 'enter its recovery key' 'enter its recovery key' 'enter its recovery key') || bad="${bad}wrong key: the prompt did not appear three times; "
	log "three wrong recovery keys: ${o//$'\n'/ | }"
	wait_up 400 || bad="${bad}does not boot after the wrong keys; "
	o=$(gx 'test -e /home/student/keep-me && echo "keep-me present"; cryptsetup luksUUID /dev/gpt-auto-root-luks')
	log "after the wrong keys: ${o//$'\n'/ | }"
	grep -q 'keep-me present' <<<"$o" || bad="${bad}wrong keys wiped the data; "
	grep -q "$luks" <<<"$o" || bad="${bad}wrong keys changed the LUKS volume; "
	shot reset-local-wrong-key-gdm
	log "boot entry $(reset_entry)"
	pve "qm reboot $vmid --timeout 180" >/dev/null
	o=$({
		recovery_key "$id" "$luks"
		echo ERASE
	} | serial_answers 300 'enter its recovery key' 'Type ERASE') || bad="${bad}right key: prompts did not appear; "
	log "right recovery key + ERASE: ${o//$'\n'/ | }"
	sleep 20
	wait_up 600 || bad="${bad}does not boot after the factory reset; "
	shot reset-local-erased-gdm
	luks2=$(luks_uuid)
	o=$(gx 'test -e /home/student/keep-me && echo "keep-me still present" || echo "keep-me gone"')
	log "after the factory reset: LUKS $luks → $luks2; $o"
	[ "$luks2" != "$luks" ] || bad="${bad}LUKS volume not replaced; "
	grep -q 'still present' <<<"$o" && bad="${bad}keep-me is still there; "
	wait_bundle "$v0" 120 >/dev/null || bad="${bad}the school's bundle (v$v0) not back within 2 min of the reset; "
	t0=$SECONDS
	rows1=$rows0
	until [ "$rows1" -gt "$rows0" ] 2>/dev/null || [ $((SECONDS - t0)) -gt 240 ]; do
		sleep 10
		rows1=$(recovery_rows "$id" 2>/dev/null || echo "$rows0")
	done
	o=$(device_json "$id" | jq -c '{group, bundle_version, results: [.results[]? | select(.item | test("^(login|desktop|luks:escrow|fetch-token)$"))]}')
	log "server: recovery-key rows $rows0 → $rows1; $o"
	[ "$rows1" -gt "$rows0" ] 2>/dev/null || bad="${bad}no new recovery key escrowed after the reset; "
	[ "$(jq -r .group <<<"$o")" = teacher ] || bad="${bad}group is not teacher after the reset; "
	stop_vm
	rollback t20-up
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# an unmanaged machine (168, installed without a seed): the boot-menu factory reset only asks for ERASE, no recovery key
c_reset_unmanaged() {
	local name=reset_unmanaged bad="" o m
	start_wait 300 || wait_vcs 'Username:' 60 || {
		fail "$name" "does not boot"
		return
	}
	gx 'test -e /var/lib/mastersos-seed/seed.toml && echo "has a seed"' | grep -q 'has a seed' && {
		fail "$name" "this machine has a seed (managed), not an unmanaged one"
		return
	}
	log "boot entry $(reset_entry)"
	m=$(serial_mark)
	pve "qm reboot $vmid --timeout 180" >/dev/null
	o=$(printf 'ERASE\n' | serial_answers 300 'Type ERASE') || bad="${bad}no ERASE prompt; "
	log "ERASE: ${o//$'\n'/ | }"
	sleep 20
	serial_since "$m" | grep -qi 'enter its recovery key' && bad="${bad}the unmanaged machine asked for a recovery key; "
	wait_vcs 'Username:' 400 || bad="${bad}not back at the first-user prompt after the reset; "
	shot reset-unmanaged-firstrun
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# §6.9 item 7 (Task 5 Step 6): a remote factory reset from the panel runs once and does not loop (reset-done records the
# id; two more fetches and a reboot do not run it again), shows no prompt, and afterwards login methods, mode and web apps
# come back from the school's settings; after a reinstall with the same seed the reset still in the draft does not run;
# the reset is withdrawn. Rolls back to t20-up afterwards
c_reset_remote() {
	local name=reset_remote bad="" o id luks luks2 m v b0 rid t0 st
	start_wait || {
		fail "$name" "does not boot"
		return
	}
	v=$(B_GROUP=cart pub reset-remote-0) || bad="${bad}cannot publish; "
	wait_bundle "$v" 30 >/dev/null || true
	id=$(my_id)
	luks=$(luks_uuid)
	b0=$(boot_id)
	panel_put "$id" reset true >/dev/null || bad="${bad}PUT reset failed; "
	rid=$(api ops GET /v1/admin/draft/manifest | grep -A4 "\"$id\"" | sed -n 's/.*reset = { id = "\([^"]*\)".*/\1/p' | head -1)
	m=$(serial_mark)
	v=$(publish_draft | tail -1) || bad="${bad}publish failed; "
	log "remote factory reset: reset id in the draft ${rid:-(not read)}, published v$v"
	t0=$SECONDS
	st=""
	until [ -n "$st" ] || [ $((SECONDS - t0)) -gt 90 ]; do
		st=$(device_json "$id" | jq -c '[.results[]? | select(.item == "reset")][0] // empty')
		sleep 3
	done
	log "report reset within $((SECONDS - t0)) s: ${st:-none}"
	t0=$SECONDS
	until [ "$(boot_id 2>/dev/null)" != "$b0" ] && qga_up || [ $((SECONDS - t0)) -gt 600 ]; do sleep 5; done
	wait_up 400 || bad="${bad}does not boot after the reset; "
	# case-sensitive: the boot menu's entry title also says "…asks to type ERASE"
	serial_since "$m" | grep -qE 'enter its recovery key|Type ERASE' && bad="${bad}the remote reset showed a prompt; "
	luks2=$(luks_uuid)
	o=$(gx 'cat /var/lib/mastersos-seed/reset-done 2>/dev/null')
	log "LUKS $luks → $luks2; reset-done: ${o//$'\n'/ }"
	[ "$luks2" != "$luks" ] || bad="${bad}no factory reset (LUKS not replaced); "
	[ -n "$rid" ] && { grep -q "$rid" <<<"$o" || bad="${bad}this reset id is not in reset-done; "; }
	wait_bundle "$v" 120 >/dev/null || bad="${bad}v$v not received after the reset; "
	sleep 20
	o=$(gx 'cat /var/lib/mastersos-system/exec-block-mode; jq -c .methods /var/lib/mastersos-system/login/policy.json; ls /var/lib/mastersos-public/xdg/applications/ | grep -c mastersos-web')
	log "after the reset: ${o//$'\n'/ | }"
	# the mode file keeps the old words (browser = learning, desktop = full) so a rollback to a pre-config image still blocks
	grep -qx 'browser' <<<"$(head -1 <<<"$o")" || bad="${bad}not in the learning mode after the reset; "
	grep -q '"guest"' <<<"$o" || bad="${bad}wrong login methods after the reset; "
	[ "$(tail -1 <<<"$o")" = 2 ] || bad="${bad}not two web apps after the reset; "
	kick
	sleep 30
	kick
	sleep 30
	reboot_wait || bad="${bad}does not boot again; "
	[ "$(luks_uuid)" = "$luks2" ] || bad="${bad}reset ran a second time (loop); "
	# reinstall with the same seed: the reset is still in the draft and does not run
	install_from seeded reset-remote-reinstall up || bad="${bad}reinstall did not finish; "
	pve "qm start $vmid" >/dev/null
	wait_up 400 || bad="${bad}does not boot after the reinstall; "
	luks=$(luks_uuid)
	sleep 60
	kick
	sleep 30
	o=$(gx 'cat /var/lib/mastersos-seed/reset-done 2>/dev/null; jq -r .version /var/lib/mastersos/state.json')
	log "after the reinstall: reset-done ${o//$'\n'/ | }; LUKS $luks → $(luks_uuid)"
	[ "$(luks_uuid)" = "$luks" ] || bad="${bad}the old reset ran after the reinstall; "
	panel_put "$id" reset null >/dev/null || bad="${bad}withdrawing the reset failed; "
	publish_draft >/dev/null || bad="${bad}publish after withdrawing the reset failed; "
	stop_vm
	rollback t20-up
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# Task 22 Step 7: VM 165 updates to the bad-shim version (the same shim re-signed by a test CA, lab beta only); after a
# good boot bootloader-update refuses to install it, the three ESP files stay, the panel's system:shim-ca fails with
# Reset All Keys in the detail; the next reboot is normal, no recovery key. Rolls back to t20-up afterwards
c_shim_chain() {
	local name=shim_chain bad="" o before after
	built "$V_BADSHIM" || {
		fail "$name" "no bad-shim build $V_BADSHIM"
		return
	}
	b161 "grep -E '^broken=' mastersos-image/mkosi.output/$V_BADSHIM/build-info.txt" | grep -q bad-shim || {
		fail "$name" "$V_BADSHIM is not a bad-shim build"
		return
	}
	in_channel "$V_BADSHIM" beta || b161 "cd mastersos-image && ./publish.sh $V_BADSHIM beta --allow-shim-change --allow-unchained-shim --allow-bootloader-change 2>&1 | grep -E '→|闸门|链不到|拒绝' | head -4"
	in_channel "$V_BADSHIM" beta || {
		fail "$name" "bad-shim cannot be published to lab beta"
		return
	}
	start_wait || {
		fail "$name" "does not boot"
		return
	}
	before=$(gx 'e=$(bootctl -p); sha256sum $e/EFI/BOOT/BOOTX64.EFI $e/EFI/BOOT/grubx64.efi $e/EFI/BOOT/mmx64.efi | cut -c1-16')
	o=$(run_update)
	log "mastersos-update: ${o//$'\n'/ }"
	reboot_wait || bad="${bad}does not boot after the update; "
	log "IMAGE_VERSION=$(img_version)"
	sleep 30
	# bootloader-update's own (Chinese) log line: "…都不换" = "none of the three files replaced"
	o=$(gx 'journalctl -b -u mastersos-bootloader-update --no-pager -o cat | grep -E "链不到|不换" | tail -2; cat /var/lib/mastersos-system/shim-ca.json')
	log "${o//$'\n'/ | }"
	grep -q '都不换' <<<"$o" || bad="${bad}bootloader-update did not refuse; "
	after=$(gx 'e=$(bootctl -p); sha256sum $e/EFI/BOOT/BOOTX64.EFI $e/EFI/BOOT/grubx64.efi $e/EFI/BOOT/mmx64.efi | cut -c1-16')
	[ "$before" = "$after" ] || bad="${bad}boot files on the ESP changed; "
	local m
	m=$(serial_mark)
	reboot_wait || bad="${bad}does not boot again; "
	o=$(gx 'journalctl -b -o short-monotonic --no-pager | grep -E "Please enter recovery key|TPM2 token unlocks|systemd-cryptsetup|tpm2|pcrlock" | head -8; journalctl -b -o cat | grep -c "Please enter recovery key"')
	log "second reboot, cryptsetup/TPM lines: ${o//$'\n'/ | }"
	log "serial of that boot: $(serial_since "$m" | grep -aE 'recovery key|TPM2|cryptsetup' | head -4 | tr '\n' ' ')"
	[ "$(tail -1 <<<"$o")" = 0 ] || bad="${bad}the reboot asked for the recovery key; "
	sleep 30
	o=$(report_item system:shim-ca)
	log "report: $o"
	[ "$(jq -r .ok <<<"$o" 2>/dev/null)" = false ] && grep -q 'Reset All Keys' <<<"$o" || bad="${bad}system:shim-ca is not failed, or its detail lacks Reset All Keys; "
	stop_vm
	rollback t20-up
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# not rerun, only the recorded results are checked (brief): Task 1's reverse check and Task 4 matrix row 9
# (the patterns below are the wording of those Chinese result files)
c_lab_keys_untrusted() {
	local name=lab_keys_untrusted f=$here/results/2026-10-14-4b/t1-build.txt bad=""
	grep -q '## 反向验证' "$f" || bad="${bad}no reverse check in t1-build.txt; "
	grep -q 'Security Violation' "$f" || bad="${bad}no record of the lab stick being rejected; "
	test -f "$here/results/2026-10-14-4b/4b-t1-167-lab-usb-rejected.png" || bad="${bad}no screenshot of the rejection; "
	log "$(grep -m1 -A1 '插 lab U 盘' "$f")"
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}
c_tpm_userspace_refused() {
	local name=tpm_userspace_refused f=$here/results/2026-10-15-4b/t4-initrd-only.txt bad=""
	grep -q 'probe 成功激活' "$f" || bad="${bad}no record of 'unlocked' before the fix; "
	grep -q '解不开' "$f" || bad="${bad}no record of 'cannot unlock' after the fix; "
	log "before the fix: $(grep -m1 -o '\*\*probe 成功激活\*\*[^。]*' "$f")"
	log "after the fix: $(grep -m1 -o '→ \*\*解不开\*\*[^，]*' "$f")"
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# restart the lab server on VM 161 (optionally with another config file). pkill patterns are anchored to the server's
# exact command line: an unanchored pattern also matches the remote shell running this very command and kills it
# shellcheck disable=SC2120 # the argument is optional
srv_restart() { # srv_restart [config file, default server.toml]
	b161 "cd ~/t12-server && pkill -f '^\./mastersos-server\.bin --config ' ; sleep 1; (setsid nohup ./mastersos-server.bin --config ${1:-server.toml} >>server.log 2>&1 </dev/null &); sleep 3; curl -s -o /dev/null -w 'server %{http_code}\n' http://192.0.2.99:8480/v1/bundle"
}

# Task 2 Step 5 (renewal rerun on a built image, Task 2 carry): the lost machine (LOST_VM, default 167, installed by
# groups) has its escrow credential reset first, then fetch_token is rotated (old sha256 into [[retired_fetch_token]]);
# 165 renews within minutes, both token files are 600 root and hold the new token (compared by sha256), the panel no longer
# marks 165 stale but still marks the lost machine and its fetch-token item fails; after removing the retired token 165
# keeps working and the lost machine gets 401. Afterwards the server config is restored (machines whose seed has the old
# token keep working) and 165 rolls back to t20-up
c_fetch_token_rotation() {
	local name=fetch_token_rotation bad="" o id lost lostid newsha t0 st
	lost=${LOST_VM:-167}
	start_wait || {
		fail "$name" "does not boot"
		return
	}
	id=$(my_id)
	lostid=$("$here/gx.sh" "$lost" 'jq -r .device_id /var/lib/mastersos-seed/identity.json' 2>/dev/null | tr -d '\n')
	[ -n "$lostid" ] || {
		fail "$name" "VM $lost is not running or has no seed (run 167 groups first)"
		return
	}
	api recovery DELETE "/v1/admin/devices/$lostid/escrow-secret" >/dev/null && log "escrow credential of VM $lost ($lostid) reset (lost machine, before the rotation)" || bad="${bad}resetting the lost machine's escrow credential failed; "
	newsha=$(b161 'set -e; cd ~/t12-server; cp -p server.toml server.toml.pre-t20-rot
old=$(sed -n "s/^fetch_token = \"\(.*\)\"$/\1/p" server.toml | ./mastersos-server.bin hash-token)
new=$(./mastersos-server.bin new-token | sed -n "s/^token = //p")
python3 - "$new" "$old" "$(date -u +%FT%TZ)" <<"PY"
import re, sys
new, old, at = sys.argv[1:4]
s = open("server.toml").read()
s = re.sub(r"(?m)^fetch_token = \".*\"$", "fetch_token = \"%s\"" % new, s)
s = s.replace("[[api_token]]", "fetch_token_rotated_at = \"%s\"\n\n[[retired_fetch_token]]\nsha256 = \"%s\"\nnote = \"T20 rotation\"\n\n[[api_token]]" % (at, old), 1)
open("server.toml", "w").write(s)
PY
printf "%s" "$new" | sha256sum | cut -c1-16')
	log "rotation: new token sha256 ${newsha}… (token not recorded)"
	srv_restart | sed 's/^/  /'
	gx 'systemctl restart mastersos-agent'
	"$here/gx.sh" "$lost" 'systemctl restart mastersos-agent' || true
	t0=$SECONDS
	st=""
	until [ "$(jq -r .ok <<<"$st" 2>/dev/null)" = true ] || [ $((SECONDS - t0)) -gt 300 ]; do
		sleep 10
		st=$(report_item fetch-token)
	done
	log "$((SECONDS - t0)) s: 165 reports fetch-token $st"
	[ "$(jq -r .ok <<<"$st" 2>/dev/null)" = true ] || bad="${bad}165 did not renew; "
	o=$(gx 'for f in /var/lib/mastersos/fetch-token /var/lib/mastersos-seed/fetch-token; do echo "$f $(stat -c "%a %U" $f) $(tr -d "\n" < $f | sha256sum | cut -c1-16)"; done')
	log "165's token files: ${o//$'\n'/ | }"
	[ "$(grep -c "600 root $newsha" <<<"$o")" = 2 ] || bad="${bad}165's two token files are not 600 root with the new token; "
	sleep 30
	o=$(api ops GET /v1/admin/devices | jq -c --arg a "$id" --arg b "$lostid" '[.[] | select(.device_id == $a or .device_id == $b) | {device_id: .device_id[0:8], fetch_token_stale, ft: ([.results[]? | select(.item == "fetch-token")][0])}]')
	log "panel: $o"
	[ "$(jq -r --arg a "${id:0:8}" '.[] | select(.device_id == $a) | .fetch_token_stale' <<<"$o")" = false ] || bad="${bad}panel still marks 165 stale; "
	[ "$(jq -r --arg b "${lostid:0:8}" '.[] | select(.device_id == $b) | .fetch_token_stale' <<<"$o")" = true ] || bad="${bad}panel does not mark the lost machine stale; "
	[ "$(jq -r --arg b "${lostid:0:8}" '.[] | select(.device_id == $b) | .ft.ok' <<<"$o")" = false ] || bad="${bad}the lost machine's fetch-token is not failed; "
	# remove the retired token
	b161 'cd ~/t12-server && python3 - <<"PY"
import re
s = open("server.toml").read()
s = re.sub(r"(?ms)^fetch_token_rotated_at = .*?\n\n\[\[retired_fetch_token\]\]\nsha256 = \"[0-9a-f]+\"\nnote = \"T20 rotation\"\n\n", "", s)
open("server.toml", "w").write(s)
PY
grep -c retired_fetch_token server.toml || true' | sed 's/^/  retired-token lines: /'
	srv_restart | sed 's/^/  /'
	kick
	"$here/gx.sh" "$lost" 'systemctl kill -s USR1 mastersos-agent' || true
	sleep 30
	o=$(gx 'journalctl -u mastersos-agent --since -1min -o cat --no-pager | grep -c "401"')
	log "165's 401s after removing the retired token: $o"
	[ "$o" = 0 ] || bad="${bad}165 gets 401 after removing the retired token; "
	o=$("$here/gx.sh" "$lost" 'journalctl -u mastersos-agent --since -1min -o cat --no-pager | grep -m1 "401"')
	log "lost machine: $o"
	grep -q 401 <<<"$o" || bad="${bad}the lost machine does not get 401; "
	b161 'cd ~/t12-server && cp -p server.toml.pre-t20-rot server.toml && rm -f server.toml.pre-t20-rot'
	srv_restart | sed 's/^/  original token restored: /'
	stop_vm
	rollback t20-up
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# §6.9 item 6: a bundle with one byte changed, a bundle signed by another key and an old bundle, each delivered as a new
# version by "replacing the stored file" on the lab server (stop the server, edit the versions table in SQLite, start it)
# → all rejected, the report carries the reason, state.json's version does not change. The other key comes from a
# temporary second server (fresh key, 127.0.0.1 only)
c_tamper_replay() {
	local name=tamper_replay bad="" o v kind server0 sf
	start_wait || {
		fail "$name" "does not boot"
		return
	}
	v=$(B_GROUP=teacher B_TEACHER_SED='/^flatpak = /d' pub tamper-0) || bad="${bad}cannot publish; "
	wait_bundle "$v" 30 >/dev/null || true
	# v+1 signed by another key: a temporary server (new data dir, generates its key on first start) publishes once, its
	# row is renumbered to v, and the next publish is v+1
	o=$(b161 "set -e; d=~/t20-other; rm -rf \$d; mkdir -p \$d/data; cd ~/t12-server
sed -e 's#^listen = .*#listen = \"127.0.0.1:8482\"#' -e \"s#^data_dir = .*#data_data = \\\"\$d/data\\\"#\" -e 's#^data_data#data_dir#' -e 's#^public_url = .*#public_url = \"http://127.0.0.1:8482\"#' server.toml > \$d/server.toml
(setsid nohup ./mastersos-server.bin --config \$d/server.toml > \$d/log 2>&1 </dev/null &); sleep 3; echo started")
	log "temporary server: $o"
	server0=$server
	read -r -a sf <<<"$(script_files)"
	server=http://127.0.0.1:8482
	publish_manifest "$state/bundle-tamper-0.toml" "${sf[@]}" >/dev/null 2>&1 || bad="${bad}temporary server cannot publish; "
	b161 "pkill -f '^\./mastersos-server\.bin --config /home/mastersos/t20-other/server\.toml$'; sleep 1; python3 -c 'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"update versions set version=? where version=1\", (int(sys.argv[2]),)); c.commit()' ~/t20-other/data/mastersos.db $v; cd ~/t12-server; (setsid nohup ./mastersos-server.bin --config ~/t20-other/server.toml >> ~/t20-other/log 2>&1 </dev/null &); sleep 3"
	publish_manifest "$state/bundle-tamper-0.toml" "${sf[@]}" >/dev/null 2>&1 || bad="${bad}temporary server cannot publish a second time; "
	server=$server0
	b161 "pkill -f '^\./mastersos-server\.bin --config /home/mastersos/t20-other/server\.toml$'; true"
	for kind in flip otherkey replay; do
		o=$(b161 "set -e; cd ~/t12-server; pkill -f '^\./mastersos-server\.bin --config server\.toml$'; sleep 1; cp -p data/mastersos.db data/mastersos.db.t20-tamper
python3 - data/mastersos.db $v $kind /home/mastersos/t20-other/data/mastersos.db <<'PY'
import sqlite3, sys
db, v, kind, other = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
c = sqlite3.connect(db)
cols = [r[1] for r in c.execute('pragma table_info(versions)')]
row = dict(zip(cols, c.execute('select * from versions where version=?', (v,)).fetchone()))
if kind == 'flip':
    a = bytearray(row['archive']); a[len(a) // 2] ^= 0x01; row['archive'] = bytes(a)
elif kind == 'otherkey':
    o = sqlite3.connect(other).execute('select archive, manifest_text from versions where version=?', (v + 1,)).fetchone()
    row['archive'], row['manifest_text'] = o
else:
    old = dict(zip(cols, c.execute('select * from versions where version=?', (v - 3,)).fetchone()))
    row['archive'], row['manifest_text'] = old['archive'], old['manifest_text']
row['version'] = v + 1
c.execute('insert into versions (%s) values (%s)' % (','.join(cols), ','.join('?' * len(cols))), [row[k] for k in cols])
c.commit(); print('stored v%d in versions (%s, %d bytes)' % (v + 1, kind, len(row['archive'])))
PY
(setsid nohup ./mastersos-server.bin --config server.toml >>server.log 2>&1 </dev/null &); sleep 3")
		log "$kind: $o"
		kick
		sleep 25
		o=$(report_item bundle)
		log "$kind: state.json v$(state_version); report bundle $o"
		[ "$(state_version)" = "$v" ] || bad="${bad}the $kind bundle was accepted; "
		[ "$(jq -r .ok <<<"$o" 2>/dev/null)" = false ] && grep -q "v$((v + 1))" <<<"$o" || bad="${bad}no rejection report for $kind; "
		gx 'journalctl -u mastersos-agent --since -1min -o cat --no-pager | grep -E "拒|reject" | tail -1' | sed 's/^/  agent: /'
		b161 "cd ~/t12-server; pkill -f '^\./mastersos-server\.bin --config server\.toml$'; sleep 1; cp -p data/mastersos.db.t20-tamper data/mastersos.db; rm -f data/mastersos.db.t20-tamper data/mastersos.db-wal data/mastersos.db-shm; (setsid nohup ./mastersos-server.bin --config server.toml >>server.log 2>&1 </dev/null &); sleep 3"
	done
	b161 'rm -rf ~/t20-other'
	# a normal bundle afterwards is accepted. After three rejections the agent is in its retry backoff (it does not long-poll
	# again until the backoff ends), so it is kicked with SIGUSR1 as an operator would
	v=$(B_GROUP=teacher B_TEACHER_SED='/^flatpak = /d; /^\[\[config\]\]/,$ s/^name = "Teacher laptops"/name = "Teacher laptops after tamper"/' pub tamper-after) || true
	kick
	wait_bundle "$v" 60 >/dev/null || bad="${bad}the normal bundle v$v after the tampering was not accepted; "
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# §6.9 item 10 (config profiles design §6: the seed is school-level and carries no group): 167 and 168 are installed from
# the school's seed → the panel shows 未分组 (default); dragging 167 into teacher on the panel and publishing → 167 switches
# to the full mode; dragging 168 into cart → the learning mode
c_groups() {
	local name=groups bad="" o id g v
	g=teacher
	[ "$vmid" = 168 ] && g=cart
	B_DEVICES="" pub groups-draft >/dev/null || bad="${bad}cannot publish the draft; "
	install_from seeded "groups" up || {
		fail "$name" "the installer did not reach its final screen"
		return
	}
	pve "qm start $vmid" >/dev/null
	wait_up 400 || bad="${bad}does not boot after the install; "
	sleep 30
	id=$(my_id)
	o=$(device_json "$id" | jq -c '{group, group_source, bundle_version}')
	log "panel: $o"
	[ "$(jq -r .group <<<"$o")" = default ] || bad="${bad}the school's seed does not give default; "
	o=$(gx 'cat /var/lib/mastersos-system/exec-block-mode')
	log "$vmid (default): $o"
	panel_put "$id" group "{\"group\": \"$g\"}" >/dev/null || bad="${bad}moving it into $g failed; "
	v=$(publish_draft | tail -1)
	wait_bundle "$v" 60 >/dev/null || bad="${bad}v$v not received; "
	sleep 5
	o=$(device_json "$id" | jq -c '{group, group_source}')
	log "after moving it into $g: $o; $(gx 'cat /var/lib/mastersos-system/exec-block-mode; grep favorite-apps /etc/dconf/db/mastersos.d/50-mastersos')"
	[ "$(jq -r .group <<<"$o")" = "$g" ] || bad="${bad}group is not $g after the move; "
	# exec-block-mode keeps the old words (desktop = full, browser = learning): a rollback to a pre-config image reads it
	if [ "$g" = teacher ]; then
		gx 'grep -qx desktop /var/lib/mastersos-system/exec-block-mode' || bad="${bad}$vmid is not in the full mode; "
		gx 'grep -q org.gnome.Nautilus /etc/dconf/db/mastersos.d/50-mastersos' || bad="${bad}Files is not in $vmid's Dock (not the full mode); "
	else
		gx 'grep -qx browser /var/lib/mastersos-system/exec-block-mode' || bad="${bad}$vmid is not in the learning mode; "
	fi
	shot groups-gdm
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

disk_fp() { # fingerprint of the disk: partition table + sha256 of the first 1 GiB and the last 1 MiB
	pve "set -e; v=\$(qm config $vmid | sed -n 's/^scsi0: \([^,]*\),.*/\1/p'); d=\$(pvesm path \$v); [ -b \$d ] || lvchange -ay \$d >/dev/null; { sfdisk -d \$d 2>/dev/null; dd if=\$d bs=1M count=1024 status=none | sha256sum; dd if=\$d bs=1M skip=\$((\$(blockdev --getsize64 \$d) / 1048576 - 1)) count=1 status=none | sha256sum; } | sha256sum | cut -c1-16"
}
boot_stick() { # boot_stick <plain|seeded>: boot from the USB stick and stop there
	local img
	img=$(make_stick "$1")
	stop_vm
	pve "qm set $vmid --args '-device qemu-xhci -drive if=none,id=stick,format=raw,file=$img -device usb-storage,drive=stick,removable=on,bootindex=1'" >/dev/null
	pve "qm start $vmid" >/dev/null
}
unstick() {
	stop_vm
	pve "qm set $vmid --delete args" >/dev/null
}

# Task 3 Step 6: VM 166 without a vTPM and VM 168 with a TPM owner password → the installer refuses before the confirm
# screen and the disk is untouched; 168 installs once the owner password is cleared (no seed → unmanaged)
c_no_tpm_refused() {
	local name=no_tpm_refused bad="" fp0 fp1
	fp0=$(disk_fp)
	if [ "$vmid" = 166 ]; then
		boot_stick plain
		wait_vcs 'No usable TPM 2.0|No TPM 2.0' 240 || bad="${bad}no refusal; "
		shot no-tpm-refused
		manual "$name/166" "$out/$ACC_SHOT-$vmid-no-tpm-refused.png (bilingual reason and the BIOS fix; disk untouched)"
		gx 'fold -w 160 /dev/vcs1 | grep -aqE "Type y to continue|type y to continue"' 2>/dev/null && bad="${bad}a confirmation prompt after the refusal; "
		unstick
	else
		boot_stick plain
		wait_vcs '[Tt]ype y to continue' 240 || bad="${bad}the installer did not come up (before setting the owner password); "
		newpw tpm-owner >/dev/null
		gx_stdin 'cat > /run/t20-owner.pw; tpm2_changeauth -c owner file:/run/t20-owner.pw && tpm2_getcap properties-variable | grep -i ownerAuthSet; rm -f /run/t20-owner.pw' <"$state/tpm-owner.pw" | sed 's/^/  owner password set: /'
		pve "qm reset $vmid" >/dev/null
		sleep 5
		wait_vcs 'owner password|0x9a2' 240 || bad="${bad}no refusal with an owner password set; "
		shot tpm-owner-refused
		manual "$name/168-owner" "$out/$ACC_SHOT-$vmid-tpm-owner-refused.png (owner-password reason and how to clear the TPM)"
		gx 'fold -w 160 /dev/vcs1 | grep -aqE "Type y to continue"' 2>/dev/null && bad="${bad}a confirmation prompt after the refusal; "
		gx_stdin 'cat > /run/t20-owner.pw; tpm2_changeauth -c owner -p file:/run/t20-owner.pw && tpm2_getcap properties-variable | grep -i ownerAuthSet; rm -f /run/t20-owner.pw' <"$state/tpm-owner.pw" | sed 's/^/  owner password cleared: /'
		unstick
	fi
	fp1=$(disk_fp)
	log "disk fingerprint: $fp0 → $fp1"
	[ "$fp0" = "$fp1" ] || bad="${bad}the disk was changed; "
	if [ "$vmid" = 168 ]; then
		# installs once the owner password is cleared (no seed → unmanaged; reset_unmanaged uses it next)
		install_from plain no-tpm-cleared up || bad="${bad}cannot install after clearing the owner password; "
		pve "qm start $vmid" >/dev/null
		wait_vcs 'Username:' 300 || bad="${bad}no first-user prompt after the install; "
	fi
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# Task 22 Step 7: a VM whose db has the 2023 CA only gets the "Wi-Fi will not work" warning (recorded at its last install);
# with the 2023 CA removed (efidisk edited while powered off) the lab installer adds a certificate warning, and answering n
# leaves the disk untouched. Snapshot t20-pre-db before the edit, rolled back afterwards
c_hw_precheck() {
	local name=hw_precheck bad="" o fp0 fp1 w der
	w=$(cat "$state/warnings-$vmid.txt" 2>/dev/null)
	log "warnings at this VM's last install: ${w//$'\n'/ | }"
	grep -q 'Wi-Fi' <<<"$w" || bad="${bad}no Wi-Fi warning with the 2023 CA in db (or no install recorded); "
	# the header line "Checking hardware and Secure Boot certificates" is always there; the warning itself says "not right"
	grep -qi 'certificates are not right' <<<"$w" && bad="${bad}a certificate warning even with the 2023 CA in db; "
	stop_vm
	delsnap t20-pre-db
	snap t20-pre-db "4b Task 20 hw_precheck: before removing UEFI CA 2023 from db"
	der=$(base64 <"$here/../keys/microsoft/MicCorUEFCA2011_2011-06-27.der" | tr -d '\n')
	pve "set -e; d=\$(mktemp -d); echo $der | base64 -d > \$d/ca2011.der; openssl x509 -inform DER -in \$d/ca2011.der -out \$d/ca2011.pem; vol=\$(qm config $vmid | sed -n 's/^efidisk0: \([^,]*\),.*/\1/p'); dev=\$(pvesm path \$vol); [ -b \$dev ] || lvchange -ay \$dev; dd if=\$dev of=\$d/v.fd bs=540672 count=1 status=none; virt-fw-vars --inplace \$d/v.fd --delete db --add-db 77fa9abd-0359-4d32-bd60-28f4e78f784b \$d/ca2011.pem >/dev/null; dd if=\$d/v.fd of=\$dev bs=540672 count=1 conv=notrunc status=none; rm -rf \$d"
	"$here/fw-vars.sh" "$vmid" print | grep -E 'CN=' | sed 's/^/  db: /'
	fp0=$(disk_fp)
	boot_stick plain
	wait_vcs 'There are warnings above' 240 || bad="${bad}no warning screen; "
	o=$(gx 'fold -w 160 /dev/vcs1 | grep -aE "certificate|Wi-Fi|2023|Reason"')
	log "warnings: ${o//$'\n'/ | }"
	grep -qi 'certificates are not right\|UEFI CA 2023' <<<"$o" || bad="${bad}no missing-2023-CA warning; "
	shot hw-precheck-db-no-2023
	manual "$name/no-2023" "$out/$ACC_SHOT-$vmid-hw-precheck-db-no-2023.png (lab only warns and lists the four steps)"
	keys n ret wait:3
	shot hw-precheck-cancelled
	unstick
	fp1=$(disk_fp)
	log "disk fingerprint: $fp0 → $fp1"
	[ "$fp0" = "$fp1" ] || bad="${bad}the disk changed after answering n; "
	rollback t20-pre-db
	delsnap t20-pre-db
	"$here/fw-vars.sh" "$vmid" print | grep -c 'UEFI CA 2023' | sed 's/^/  UEFI CA 2023 entries in db after the rollback: /'
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# Task 4 matrix row 8 (carried from Task 4, ship-blocker): the pre-fix build (33aba393: a four-phase UKI signed with the
# retired 4phase lab PCR key) is built on VM 161 in a scratch tree (~/t20-row8; its keys are symlinks inside
# ~/mastersos-keys/t20-row8 pointing at the retired key, nothing copied) and published with that tree's own publish.sh into a
# one-time lab root (/var/www/html/mastersos-row8, the current gate rightly refuses retired-key builds). VM 165 installs it
# through sysupdate from that root (test-only /etc/sysupdate.d override, undone by the rollback), so its /usr partitions
# are there too, and it becomes the default as +3 → the TPM does not accept it on the re-keyed disk, every boot waits out
# the recovery-key prompt (5 min) and reboots, and after three tries the machine is back on V_BASE (TPM unlock).
# Rolls back to t20-up afterwards
ROW8_V=${A4B_ROW8_V:-20261017.90}
c_retired_pcr_row8() {
	local name=retired_pcr_row8 bad="" o m
	o=$(b161 "set -e; r=/var/www/html/mastersos-row8; sudo mkdir -p \$r/beta; sudo chown -R mastersos: \$r; printf 'base=http://192.0.2.99/mastersos\nlab=yes\n' > \$r/mastersos-root.conf
cd ~/t20-row8/image; test -f \$r/beta/MastersOS_${ROW8_V}_x86-64.efi || MASTERSOS_PUBLISH_ROOT=\$r MASTERSOS_KEYS=\$HOME/mastersos-keys/t20-row8 ./publish.sh $ROW8_V beta 2>&1 | tail -2
ls \$r/beta | grep -c $ROW8_V" 2>&1)
	log "one-time root: ${o//$'\n'/ | }"
	[ "$(tail -1 <<<"$o")" -ge 4 ] 2>/dev/null || {
		fail "$name" "the pre-fix build is not in the one-time root"
		return
	}
	start_wait || {
		fail "$name" "does not boot"
		return
	}
	o=$(GX_TIMEOUT=900 gx "set -e; mkdir -p /etc/sysupdate.d; for f in /etc/sysupdate.d/*.transfer; do [ -e \"\$f\" ] || cp /usr/lib/sysupdate.d/*.transfer /etc/sysupdate.d/; break; done
sed -i 's#^Path=http://192.0.2.99/mastersos/[a-z]*/#Path=http://192.0.2.99/mastersos-row8/beta/#' /etc/sysupdate.d/*.transfer
grep -h '^Path=http' /etc/sysupdate.d/*.transfer | sort -u
/usr/lib/systemd/systemd-sysupdate update 2>&1 | tail -2; ls \$(bootctl -p)/EFI/Linux")
	log "sysupdate from the one-time root: ${o//$'\n'/ | }"
	grep -q "MastersOS_${ROW8_V}_x86-64+3" <<<"$o" || bad="${bad}the pre-fix build was not installed as +3; "
	m=$(serial_mark)
	pve "qm reboot $vmid --timeout 180" >/dev/null
	log "rebooted: waiting for three recovery-key prompts to time out and the fallback to $V_BASE (about 6 min each)"
	wait_version "$V_BASE" 2700 || bad="${bad}not back on $V_BASE within 45 min; "
	o=$(serial_since "$m")
	log "serial: $(grep -ac 'Please enter recovery key' <<<"$o") 'Please enter recovery key'; $(grep -ac 'TPM2 token unlocks' <<<"$o") 'TPM2 token unlocks'; $(grep -ac 'Timed out waiting for device.*usr' <<<"$o") /usr timeouts; $(grep -ac '启动失败（initrd）' <<<"$o") initrd failures"
	[ "$(grep -ac 'Please enter recovery key' <<<"$o")" -ge 3 ] || bad="${bad}fewer than three recovery-key prompts; "
	o=$(gx 'ls "$(bootctl -p)/EFI/Linux" | tr "\n" " "')
	log "ESP after the fallback: $o"
	grep -q "MastersOS_${ROW8_V}_x86-64+0-3.efi" <<<"$o" || bad="${bad}the pre-fix UKI is not +0-3 (not tried three times); "
	tpm_unlocked "back on $V_BASE" || bad="${bad}not unlocked by the TPM on $V_BASE; "
	shot row8-back-gdm
	stop_vm
	rollback t20-up
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# Task 23 carry (its VM run predates fix rounds 1–2): on the built image the hourly timer triggers
# "mastersos-agent chrome --scheduled"; a window shorter than 2 h is refused at publish; with no window a scheduled run within
# 6 h of the last check does not go online; outside the window the round is held and the panel says so; a window that
# has blocked every check for more than 7 days is overridden. The agent's own log lines are matched (they are Chinese).
# Rolls back to t20-up afterwards
c_chrome_window() {
	local name=chrome_window bad="" o v h1 h2 runs
	start_wait || {
		fail "$name" "does not boot"
		return
	}
	o=$(gx 'systemctl cat mastersos-chrome.timer mastersos-chrome.service | grep -E "^(OnCalendar|ExecStart)="')
	log "units: ${o//$'\n'/ | }"
	grep -qx 'OnCalendar=hourly' <<<"$o" || bad="${bad}the timer has no OnCalendar=hourly; "
	grep -qE '^ExecStart=.*mastersos-agent chrome --scheduled$' <<<"$o" || bad="${bad}the service does not run chrome --scheduled; "
	# a 1-hour window is refused by the pre-publish lint
	if B_GROUP=teacher B_TEACHER_SED='/^flatpak = /d' B_TEACHER_EXTRA=$'\n[config.chrome]\nupdate_window = "01:00-02:00"' pub chrome-1h >/dev/null 2>&1; then
		bad="${bad}a 1-hour update window was published; "
	else
		log "a 1-hour window is refused at publish (chrome_window_invalid)"
	fi
	# no window: two scheduled runs; the second one stays offline (6-hour throttle)
	v=$(B_GROUP=teacher B_TEACHER_SED='/^flatpak = /d' pub chrome-none) || bad="${bad}cannot publish; "
	wait_bundle "$v" 30 >/dev/null || true
	runs=$(GX_TIMEOUT=600 gx 'systemctl start mastersos-chrome.service; systemctl start mastersos-chrome.service; journalctl -u mastersos-chrome --since -10min -o cat --no-pager | grep -E "小时内查过源|在等|照常查|已是最新|装好" | tail -3')
	log "no window, two scheduled runs: ${runs//$'\n'/ | }"
	grep -q '小时内查过源，这一轮（定时器）不联网' <<<"$runs" || bad="${bad}the second scheduled run was not throttled; "
	# a window that does not include now: the round is held
	h1=$(( ($(date +%H | sed 's/^0//') + 3) % 24 ))
	h2=$(( (h1 + 2) % 24 ))
	v=$(B_GROUP=teacher B_TEACHER_SED='/^flatpak = /d' B_TEACHER_EXTRA=$(printf '\n[config.chrome]\nupdate_window = "%02d:00-%02d:00"' "$h1" "$h2") pub chrome-window) || bad="${bad}cannot publish the window; "
	wait_bundle "$v" 30 >/dev/null || true
	sleep 3
	o=$(GX_TIMEOUT=600 gx 'systemctl start mastersos-chrome.service; cat /var/lib/mastersos/chrome/result.json 2>/dev/null | head -c 300')
	log "outside the window $(printf '%02d:00-%02d:00' "$h1" "$h2"): $o"
	grep -q '在等更新时段' <<<"$o" || bad="${bad}the round outside the window was not held; "
	# no check for more than 7 days while the window blocks: overridden
	o=$(GX_TIMEOUT=900 gx 'echo $(( $(date +%s) - 8 * 86400 )) > /var/lib/mastersos/chrome/checked-at; rm -f /var/lib/mastersos/chrome/window-clock; systemctl start mastersos-chrome.service; journalctl -u mastersos-chrome --since -15min -o cat --no-pager | grep -E "天没查过源" | tail -1; cat /var/lib/mastersos/chrome/result.json 2>/dev/null | head -c 300')
	log "window blocked for 8 days: ${o//$'\n'/ | }"
	grep -q '没查过源（时段里一直没开机或睡着），这一轮照常查' <<<"$o" || bad="${bad}the 7-day override did not happen; "
	stop_vm
	rollback t20-up
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# Task 24 carry: user units that Debian enables under /etc/systemd/user reach the machine (moved to /usr): checked in a
# local user's session
c_user_units() {
	local name=user_units bad="" o pwf
	start_wait && lab_prep || {
		fail "$name" "does not boot"
		return
	}
	pwf=$(local_user)
	B_GROUP=teacher B_TEACHER_SED='/^flatpak = /d' pub user-units >/dev/null || true
	pw_login t20local "$pwf" || bad="${bad}t20local cannot log in; "
	sleep 8
	# enabled through /usr/lib/systemd/user/*.wants links (Task 24), which systemctl is-enabled reports as "disabled";
	# what matters is that they are active in the session (xdg-user-dirs is a oneshot: its output file exists)
	o=$(as_user t20local 'sh -c "systemctl --user is-active gpg-agent.socket gpg-agent-ssh.socket ssh-agent.socket systemd-tmpfiles-clean.timer filter-chain.service pipewire.socket | paste -sd\" \"; systemctl --user show -p Id --value dbus.service; test -s \$HOME/.config/user-dirs.dirs && echo user-dirs-ok"')
	log "t20local's user units (gpg-agent, gpg-agent-ssh, ssh-agent, tmpfiles-clean.timer, filter-chain, pipewire.socket | dbus.service | xdg-user-dirs): ${o//$'\n'/ | }"
	grep -qE 'inactive|failed|unknown' <<<"$(head -1 <<<"$o")" && bad="${bad}a user unit is not active; "
	grep -qx 'dbus-broker.service' <<<"$o" || bad="${bad}the user bus is not dbus-broker; "
	grep -qx 'user-dirs-ok' <<<"$o" || bad="${bad}xdg-user-dirs did not run; "
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# ==================================================================================
case "$vmid" in
165) all="mok_lab_only etc_upgrade login_methods sso_zitadel sso_kanidm domain_restriction modes print apply_within_10s fallback_15min offline_login authd_passwd tamper_replay scripts lock admins homes guest_wipe guest_fuse guest_tty_denied chrome_window user_units fetch_token_rotation shim_chain rollback retired_pcr_row8 reset_local reset_remote lab_keys_untrusted tpm_userspace_refused" ;;
166) all="no_tpm_refused mok_lab_only_stick" ;;
167) all="groups mok_lab_only" ;;
168) all="no_tpm_refused reset_unmanaged hw_precheck groups mok_lab_only" ;;
esac
checks=()
for c in "$@"; do
	if [ "$c" = all ]; then
		read -r -a more <<<"$all"
		checks+=("${more[@]}")
	else
		checks+=("$c")
	fi
done
log "accept-4b.sh $vmid ${checks[*]} (results $out/t20-$vmid.txt; version $V_BASE)"
[ -z "${A4_LIB:-}" ] || return 0
for c in "${checks[@]}"; do
	if ! declare -F "c_$c" >/dev/null; then
		fail "$c" "no such check"
		continue
	fi
	log "== $c"
	"c_$c" || fail "$c" "the check itself exited with an error (script problem)"
done
log "done: ${#checks[@]} checks, $fails failed"
exit "$fails"
