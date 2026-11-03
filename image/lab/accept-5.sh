#!/bin/bash
# VM acceptance for plan 5 Task 8 (shim update without the recovery key). Runs on the Mac, drives PVE over lab-host:
#   accept-5.sh <vmid> <check…|all>
#   all = shim_update_no_prompt shim_update_predict_fail_falls_back shim_unchanged_no_prepare
# Setup steps (not part of all): install (seeded USB install of A5_V_BASE), old_shim (build the snapshot
# A5_SNAP_OLD: shim 15.7 + its SbatLevel on the ESP, pcrlock re-sealed by the agent's PIN).
# Each check prints "PASS <name>" or "FAIL <name>: <reason>"; output is tee'd to results/<date>-5/t8-<vmid>.txt,
# exit code = number of failures. Same conventions as 4b's accept-common.sh.
# Carries its own copy of the helpers it needs; dedupe with 4b's lab/accept-common.sh once plan 4b is merged.
#
# Lab parameters (env, defaults = the second builder VM 164 and its VM group 170–173):
#   A5_BUILD_HOST (mastersos@192.0.2.121)  A5_SERVER (http://192.0.2.121:8480)  A5_LAB_ROOT (/var/www/html/mastersos)
#   A5_SNAPSHOT (20261017T000000Z)  A5_V_BASE (20261017.100)  A5_V_NEW (20261017.102, the build with this task)
#   A5_SNAP_OLD (p5-old-shim)  A5_SNAP_BASE (p5-base)  A5_DATE  A5_STATE
# Secrets: API tokens only from ~/.config/testlab/mastersos/mastersos-lab-{ops,recovery}.token, passed over stdin to curl on
# the builder; recovery keys only over stdin / the serial console; never printed.
# shellcheck disable=SC2029,SC2329,SC2016,SC2015,SC2001 # local expansion is intended (arguments are validated first); checks are called as "c_$c"; remote commands are single-quoted on purpose; pass cannot fail; sed prefixes read better
set -euo pipefail

here=${A5_HERE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}
[ $# -ge 2 ] || {
	echo "usage: accept-5.sh <vmid> <check…|all>" >&2
	exit 2
}
vmid=$1
shift
case "$vmid" in 170 | 171 | 172 | 173) ;; *)
	echo "accept-5.sh: only VMs 170–173 (builder VM 164's group), got: $vmid" >&2
	exit 2
	;;
esac

date_=${A5_DATE:-$(date +%Y-%m-%d)}
out=${A5_OUT:-$here/results/$date_-5}
state=${A5_STATE:-$HOME/.cache/mastersos-accept-5}
mkdir -p "$out"
mkdir -p "$state" && chmod 700 "$state"
export SHOT_DIR=$out

snapshot=${A5_SNAPSHOT:-20261017T000000Z}
bhost=${A5_BUILD_HOST:-mastersos@192.0.2.121}
server=${A5_SERVER:-http://192.0.2.121:8480}
broot=${A5_LAB_ROOT:-/var/www/html/mastersos}
lab=/var/lib/vz/mastersos-lab
cfg=$HOME/.config/testlab/mastersos
V_BASE=${A5_V_BASE:-20261017.100}
V_NEW=${A5_V_NEW:-20261017.102}
SNAP_OLD=${A5_SNAP_OLD:-p5-old-shim}
SNAP_BASE=${A5_SNAP_BASE:-p5-base}
# The old shim (Ubuntu shim-signed 1.37, shim 15.7) and the SbatLevel it leaves behind, as in 4a Task 8
OLD_SHIM_PKG=oldshim/shim-signed_1.37~18.04.13+15.7-0ubuntu1_amd64/usr/lib/shim
OLD_SBAT='sbat,1,2022052400\ngrub,2\n'
# A version stamp newer than V_BASE and older than V_NEW: V_BASE's bootloader-update leaves the old shim alone,
# V_NEW's replaces it
OLD_STAMP=${A5_OLD_STAMP:-$V_BASE.5}
for v in "$V_BASE" "$V_NEW"; do
	[[ $v =~ ^[0-9]{8}\.[0-9]+$ ]] || {
		echo "accept-5.sh: version should look like 20261017.100, got: '$v'" >&2
		exit 2
	}
done

[ -n "${A5_LIB:-}" ] || exec > >(tee -a "$out/t8-$vmid.txt") 2>&1

fails=0
now() { date '+%H:%M:%S'; }
log() { echo "[$(now)] $*"; }
pass() { echo "PASS $1"; }
fail() {
	echo "FAIL $1: $2"
	fails=$((fails + 1))
}

# --- plumbing -------------------------------------------------------------------
pve() { ssh -o ServerAliveInterval=30 -o ServerAliveCountMax=6 lab-host "$@"; }
bld() { ssh -o ServerAliveInterval=30 -o ServerAliveCountMax=6 -J lab-host "$bhost" "$@"; }
gx() { "$here/gx.sh" "$vmid" "$@"; }
keys() { "$here/keys.sh" "$vmid" "$@"; }
shot() { "$here/shot.sh" "$vmid" "5-t8-$vmid-$1" >/dev/null && log "screenshot $(basename "$out")/5-t8-$vmid-$1.png"; }
qga_up() { pve "qm agent $vmid ping" >/dev/null 2>&1; }
vm_status() { pve "qm status $vmid" | awk '{print $2}'; }
boot_id() { gx 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null | tr -d '\n'; }
img_version() { gx '. /usr/lib/os-release; echo $IMAGE_VERSION' 2>/dev/null | tr -d '\n'; }

# Host RAM must leave room (coordinator rule): at least 6 GB available before starting the VM
ram_ok() {
	local a
	a=$(pve "free -g | awk '/^Mem:/ {print \$7}'")
	[ "${a:-0}" -ge 6 ] || {
		log "PVE has only ${a} GB available (need ≥ 6) — not starting VM $vmid"
		return 1
	}
}
pool() { pve 'lvs --noheadings -o data_percent pve/data' | tr -d ' \n'; }
check_pool() {
	local p
	p=$(pool)
	log "PVE thin pool ${p}%"
	if awk -v p="$p" 'BEGIN{exit !(p >= 90)}'; then
		echo "accept-5.sh: thin pool ${p}% ≥ 90%, stopping" >&2
		exit 99
	fi
}

wait_up() {
	local t=${1:-300} end=$((SECONDS + ${1:-300}))
	while [ "$SECONDS" -lt "$end" ]; do
		if qga_up && [ "$(GX_TIMEOUT=10 gx 'systemctl is-active display-manager' 2>/dev/null | tr -d '\n')" = active ]; then
			return 0
		fi
		sleep 3
	done
	log "wait_up: no active display-manager within $t s"
	return 1
}
start_vm() {
	[ "$(vm_status)" = running ] && return 0
	ram_ok || return 1
	pve "qm start $vmid" >/dev/null
}
start_wait() { start_vm && wait_up "${1:-400}"; }
stop_vm() {
	if [ "$(vm_status)" = running ]; then
		pve "qm shutdown $vmid --timeout 120 --forceStop 1" >/dev/null 2>&1 || pve "qm stop $vmid" >/dev/null
	fi
}
snap() { pve "qm snapshot $vmid $1 --description '$2'" >/dev/null && log "snapshot $1"; }
rollback() { pve "qm rollback $vmid $1" >/dev/null && log "rolled back to $1"; }
wait_vcs() {
	local re=$1 end=$((SECONDS + ${2:-300}))
	while [ "$SECONDS" -lt "$end" ]; do
		if qga_up && GX_TIMEOUT=10 gx "fold -w 160 /dev/vcs1 | grep -aqE '$re'" 2>/dev/null; then return 0; fi
		sleep 3
	done
	return 1
}

# --- serial console ---------------------------------------------------------------
serial_logger() { "$here/serial.sh" "$vmid" '^mastersos-a5-never$' 1 >/dev/null 2>&1 || true; }
serial_mark() {
	serial_logger
	pve "wc -c < $lab/serial-$vmid.log 2>/dev/null || echo 0" | tr -d '\n'
}
# Byte offsets, not lines: the recovery key prompt has no newline, so a line count would replay it
serial_since() { pve "tail -c +$(($1 + 1)) $lab/serial-$vmid.log | tr -d '\r' | sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g'"; }
# Wait for a prompt on the serial console, then type the answer read from stdin (one key at a time; QEMU's serial
# socket takes one client, so the logger is stopped first and restarted afterwards). Same as 4b's serial_answer, plus
# a third argument: 1 = the prompt is already on the console (seen by the logger), type right away.
serial_answer() {
	pve "pkill -f '[k]hunos-serial-logger $vmid'; pkill -f '[s]ocat -u UNIX-CONNECT:/var/run/qemu-server/$vmid.serial0'; sleep 0.5
python3 -c '
import re, select, socket, sys, time
ans = sys.stdin.readline().rstrip(\"\\n\")
pat, limit = re.compile(sys.argv[1].encode()), time.time() + float(sys.argv[2])
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[3])
buf = b\"\"
while sys.argv[4] != \"1\" and not pat.search(buf):
    if time.time() > limit:
        sys.exit(\"serial_answer: prompt did not appear\")
    if select.select([s], [], [], 1)[0]:
        buf = (buf + s.recv(4096))[-8192:]
time.sleep(1)
for c in ans + chr(13):
    s.send(c.encode()); time.sleep(0.05)
out, end = b\"\", time.time() + 15
while time.time() < end:
    if select.select([s], [], [], 1)[0]:
        out += s.recv(4096)
txt = re.sub(rb\"\\x1b\\[[0-9;?]*[a-zA-Z]\", b\"\", out).decode(errors=\"replace\").replace(chr(13), \"\")
print(\"\\n\".join([l for l in txt.splitlines() if l.strip()][:6]))
' '$1' '${2:-300}' /var/run/qemu-server/$vmid.serial0 '${3:-0}'"
	local rc=$?
	serial_logger
	return "$rc"
}

# --- lab server admin API (tokens over stdin to curl on the builder) ---------------------
api() { # api <ops|recovery> <METHOD> <path> [local request body file]
	local tok body_remote="" ct=""
	case "$3" in */draft/manifest) ct=text/plain ;; */commit-server) ct=application/json ;; esac
	tok=$(tr -d '\n' <"$cfg/mastersos-lab-$1.token")
	if [ -n "${4:-}" ]; then
		body_remote=p5-server/tmp/body.$$
		bld "mkdir -p -m 700 p5-server/tmp && cat > $body_remote" <"$4"
	fi
	printf 'Authorization: Bearer %s\n' "$tok" |
		bld "curl -sS --fail-with-body -X $2 -H @- ${ct:+-H 'content-type: $ct'} ${body_remote:+--data-binary @$body_remote} '$server$3'; rc=\$?; ${body_remote:+rm -f $body_remote;} exit \$rc"
}
publish_manifest() {
	local m=$1 p pend dig
	api ops PUT /v1/admin/draft/manifest "$m" >/dev/null
	p=$(api ops POST /v1/admin/publish/prepare) || {
		log "bundle pre-publish check failed: $p"
		return 1
	}
	pend=$(jq -r .pending_id <<<"$p")
	dig=$(jq -c .digest_hex <<<"$p")
	printf '{"confirm_digest": %s}' "$dig" >"$state/commit.json"
	api ops POST "/v1/admin/publish/pending/$pend/commit-server" "$state/commit.json" >/dev/null
	log "published settings bundle v$(jq -r .version <<<"$p") (channel $(sed -n 's/^update_channel = "\(.*\)"/\1/p' "$m"))"
}
manifest() { # manifest <channel> → local file
	local f=$state/manifest-$1.toml
	printf '[school]\ntimezone = "Asia/Bangkok"\nupdate_channel = "%s"\n\n[[config]]\nid = "default"\nname = "default"\nlogin_methods = ["local"]\n\n[[group]]\nid = "default"\nname = "default"\nconfig = "default"\n' "$1" >"$f"
	echo "$f"
}
device_id() { gx 'jq -r .device_id /var/lib/mastersos-seed/identity.json' | tr -d '\n'; }
luks_uuid() { gx 'cryptsetup luksUUID /dev/gpt-auto-root-luks' | tr -d '\n'; }
# Read the current recovery key from the server and type it on the serial console (never stored or printed)
type_recovery_key() { # type_recovery_key <device id> <luks uuid> [1 = prompt already shown]
	local key
	key=$(api recovery GET "/v1/admin/devices/$1/recovery-keys" | jq -r --arg u "$2" '[.[] | select(.luks_uuid == $u)][0].recovery_key // empty')
	[ -n "$key" ] || return 1
	printf '%s\n' "$key" | serial_answer 'Please enter recovery key' 240 "${3:-0}"
	unset key
}
tpm_unlocked() {
	local o
	o=$(gx 'journalctl -b -o cat --no-pager | grep -m1 -E "TPM2 token unlocks|Successfully extended NvPCR index .cryptsetup. with .cryptsetup-keyslot"')
	log "$1: ${o:-(no unlock line in the journal)}"
	grep -q 'TPM2 token unlocks' <<<"$o"
}
# Reboot; if the recovery key prompt shows up, answer it. Prints "prompt" or "noprompt" on stdout (last line).
reboot_maybe_key() {
	local m old id luks
	id=$(device_id)
	luks=$(luks_uuid)
	old=$(boot_id)
	m=$(serial_mark)
	pve "qm reboot $vmid --timeout 180" >/dev/null
	local end=$((SECONDS + 400))
	while [ "$SECONDS" -lt "$end" ]; do
		if serial_since "$m" | grep -q 'Please enter recovery key'; then
			type_recovery_key "$id" "$luks" 1 >&2 || log "typing the recovery key failed" >&2
			wait_up 300 >&2 || true
			echo prompt
			return 0
		fi
		if qga_up; then
			local b
			b=$(boot_id)
			if [ -n "$b" ] && [ "$b" != "$old" ] && wait_up 120 >&2; then
				echo noprompt
				return 0
			fi
		fi
		sleep 3
	done
	echo timeout
}
# Run the agent's luks round now (SIGUSR1 makes it fetch and run its jobs; the luks job runs at most once a minute)
agent_round() {
	gx 'systemctl kill -s USR1 --kill-whom=main mastersos-agent' >/dev/null 2>&1 || true
	sleep "${1:-75}"
}
luks_item() { # the device's last reported luks:pcrlock item (JSON)
	api ops GET /v1/admin/devices | jq -c --arg id "$1" '.[] | select(.device_id == $id) | .last_report.items[]? | select(.item == "luks:pcrlock")'
}

# --- builds -----------------------------------------------------------------------
built() { bld "test -f mastersos-image/mkosi.output/$1/build-info.txt"; }
build() { # build <v>
	built "$1" && return 0
	check_pool
	log "VM 164: build.sh $1 --profile lab (MASTERSOS_SNAPSHOT=$snapshot)"
	bld "cd mastersos-image && MASTERSOS_SNAPSHOT=$snapshot MASTERSOS_UPDATE_BASE=http://${bhost#*@}/mastersos ./build.sh $1 --profile lab > mkosi.output/build-$1.log 2>&1" || built "$1" || {
		bld "tail -20 mastersos-image/mkosi.output/build-$1.log"
		return 1
	}
	bld "grep -E '^(version|git_commit|update_base|shim_sha256)=' mastersos-image/mkosi.output/$1/build-info.txt" | tr '\n' ' '
	echo
}
in_channel() { bld "test -f $broot/$2/MastersOS_$1_x86-64.efi"; }
publish() { # publish <v> beta; the build outputs are removed afterwards (except the install version)
	in_channel "$1" "$2" && return 0
	# Each build signs systemd-boot anew (the sha256 differs from build to build), so the lab beta needs
	# --allow-bootloader-change (A5_PUBLISH_FLAGS); the shim gate is not touched (same shim-signed)
	bld "cd mastersos-image && ./publish.sh $1 $2 ${A5_PUBLISH_FLAGS---allow-bootloader-change} 2>&1 | tail -5"
	in_channel "$1" "$2" || return 1
	[ "$1" = "$V_BASE" ] || bld "rm -rf mastersos-image/mkosi.output/$1 && sudo fstrim / >/dev/null"
}

# ==================================================================================
# setup
# ==================================================================================

c_install() { # seeded USB install of V_BASE (bootindex=1), first boot until the agent has sealed pcrlock
	local name=install img=$lab/p5-$V_BASE-seeded.img o
	pve "test -f $img" || {
		fail "$name" "no USB image $img (make it from V_BASE's installer and the server's seed first)"
		return
	}
	stop_vm
	pve "qm set $vmid --args '-device qemu-xhci -drive if=none,id=stick,format=raw,file=$img -device usb-storage,drive=stick,removable=on,bootindex=1'" >/dev/null
	start_vm || {
		fail "$name" "not enough host RAM"
		return
	}
	log "booting from the USB stick ($(basename "$img"))"
	wait_vcs '[Tt]ype y to continue' 300 || {
		shot install-noprompt
		fail "$name" "installer prompt did not appear"
		return
	}
	if gx 'fold -w 160 /dev/vcs1 | grep -aq "There are warnings above"' 2>/dev/null; then
		gx 'fold -w 160 /dev/vcs1 | grep -aE "Warning|warning|Wi-Fi|certificate"' | sed 's/^/  warning: /'
		keys y ret
		sleep 3
	fi
	wait_vcs 'Type y to continue' 240 || {
		shot install-noconfirm
		fail "$name" "confirmation screen did not appear"
		return
	}
	keys y ret
	wait_vcs 'Installation complete' 900 || {
		shot install-nofinish
		fail "$name" "installer did not finish"
		return
	}
	pve "qm stop $vmid" >/dev/null
	pve "qm set $vmid --delete args" >/dev/null
	log "USB stick removed"
	start_wait 600 || {
		fail "$name" "no GDM within 600 s after install"
		return
	}
	# The agent escrows the recovery key, then seals pcrlock (needs the server)
	local end=$((SECONDS + 600))
	while [ "$SECONDS" -lt "$end" ]; do
		o=$(gx 'systemd-cryptenroll /dev/gpt-auto-root-luks 2>/dev/null; cryptsetup luksDump /dev/gpt-auto-root-luks | grep -E "tpm2-pcrlock"' 2>/dev/null || true)
		grep -q 'tpm2-pcrlock:.*true' <<<"$o" && break
		agent_round 60
	done
	log "LUKS: ${o//$'\n'/ | }"
	grep -q 'tpm2-pcrlock:.*true' <<<"$o" && pass "$name" || fail "$name" "pcrlock never sealed"
}

# Write files into the ESP of the (stopped) VM's disk from PVE: esp_put <local file> <path in the ESP>
esp_put() {
	pve "set -e; dev=\$(pvesm path \$(qm config $vmid | sed -n 's/^scsi0: \([^,]*\),.*/\1/p')); [ -b \$dev ] || lvchange -ay \$dev
off=\$(sfdisk -J \$dev | jq '.partitiontable.partitions[] | select(.type == \"C12A7328-F81F-11D2-BA4B-00A0C93EC93B\") | .start')
cat > /run/p5-esp-file && mcopy -o -i \$dev@@\$((off * 512)) /run/p5-esp-file ::$2; rc=\$?; rm -f /run/p5-esp-file; exit \$rc" <"$1"
}
# Set the SbatLevel variable in the (stopped) VM's efidisk: sbat_set <value with \n escapes>
sbat_set() {
	pve "set -e; vol=\$(qm config $vmid | sed -n 's/^efidisk0: \([^,]*\),.*/\1/p'); dev=\$(pvesm path \$vol); [ -b \$dev ] || lvchange -ay \$dev
tmp=\$(mktemp -d); trap 'rm -rf \$tmp' EXIT
dd if=\$dev of=\$tmp/vars.fd bs=540672 count=1 status=none
printf '$1' > \$tmp/sbat
virt-fw-vars --inplace \$tmp/vars.fd --set-sbat-level \$tmp/sbat >/dev/null
dd if=\$tmp/vars.fd of=\$dev bs=540672 count=1 conv=notrunc status=none"
}

c_old_shim() { # from the current state: ESP gets shim 15.7, SbatLevel goes back to 15.7's, stamp OLD_STAMP; one boot with the
	# recovery key, the agent re-seals pcrlock with its PIN, the next boot is silent → snapshot SNAP_OLD (4a Task 8's recipe)
	local name=old_shim d r o id luks
	start_wait || {
		fail "$name" "VM does not come up"
		return
	}
	id=$(device_id)
	luks=$(luks_uuid)
	d=$(mktemp -d)
	bld "cat '$OLD_SHIM_PKG/shimx64.efi.signed.latest'" >"$d/BOOTX64.EFI"
	bld "cat '$OLD_SHIM_PKG/mmx64.efi'" >"$d/mmx64.efi"
	printf '%s\n' "$OLD_STAMP" >"$d/stamp"
	log "old shim $(shasum -a 256 "$d/BOOTX64.EFI" | cut -c1-12)…, MokManager $(shasum -a 256 "$d/mmx64.efi" | cut -c1-12)…, stamp $OLD_STAMP"
	stop_vm
	esp_put "$d/BOOTX64.EFI" EFI/BOOT/BOOTX64.EFI && esp_put "$d/mmx64.efi" EFI/BOOT/mmx64.efi &&
		esp_put "$d/stamp" loader/mastersos-bootloader.version && sbat_set "$OLD_SBAT" || {
		rm -rf "$d"
		fail "$name" "writing the ESP or the SbatLevel variable failed"
		return
	}
	rm -rf "$d"
	serial_logger
	start_vm || {
		fail "$name" "not enough host RAM"
		return
	}
	# The first boot on the old shim asks for the recovery key (PCR 7 changed)
	if "$here/serial.sh" "$vmid" 'Please enter recovery key' 300 >/dev/null; then
		log "recovery key prompt on the old shim"
		type_recovery_key "$id" "$luks" 1 || {
			fail "$name" "typing the recovery key failed"
			return
		}
	else
		fail "$name" "no recovery key prompt on the first boot with the old shim"
		return
	fi
	wait_up 400 || {
		fail "$name" "no GDM after the recovery key"
		return
	}
	o=$(gx 'od -An -c /sys/firmware/efi/efivars/SbatLevelRT-605dab50-e046-4300-abb6-3dd810dd8b23 | tr -s " " | tr -d "\n"; echo; systemctl is-failed systemd-pcrlock-make-policy; true')
	log "old shim boot: ${o//$'\n'/ | }"
	agent_round 75
	gx 'journalctl -u mastersos-agent -b -o cat --no-pager | grep -i pcrlock | tail -3' | sed 's/^/  agent: /'
	r=$(reboot_maybe_key | tail -n 1)
	log "reboot after the PIN re-seal: $r"
	[ "$r" = noprompt ] && tpm_unlocked "old shim, second boot" || {
		fail "$name" "second boot on the old shim was not silent ($r)"
		return
	}
	stop_vm
	pve "qm delsnapshot $vmid $SNAP_OLD" >/dev/null 2>&1 || true
	snap "$SNAP_OLD" "plan5 t8: shim 15.7 + its SbatLevel on the ESP, pcrlock re-sealed by the agent, stamp $OLD_STAMP"
	pass "$name"
}

# ==================================================================================
# checks
# ==================================================================================

# The bundle puts the machine on the beta channel (the lab root's beta has V_NEW)
ensure_beta() {
	[ -f "$state/beta-published" ] && return 0
	publish_manifest "$(manifest beta)" && : >"$state/beta-published"
}
# From a running V_BASE: wait for the beta override, run mastersos-update, reboot into V_NEW (no recovery key expected:
# only the UKI changed, PCR 7 does not). Prints the reboot result.
update_to_new() {
	local t0=$SECONDS o
	until gx 'grep -lq "/beta/" /etc/sysupdate.d/*.transfer 2>/dev/null' || [ $((SECONDS - t0)) -gt 300 ]; do
		agent_round 10
	done
	o=$(gx 'systemctl start mastersos-update.service; systemctl show -p Result --value mastersos-update.service; ls "$(bootctl -p)/EFI/Linux"')
	log "mastersos-update: ${o//$'\n'/ }" >&2
	grep -q "MastersOS_${V_NEW}_x86-64" <<<"$o" || return 1
	reboot_maybe_key | tail -n 1
}
# Wait until mastersos-bootloader-update has run in this boot (it starts after the boot is marked good)
wait_bootloader_update() {
	local end=$((SECONDS + ${1:-300}))
	while [ "$SECONDS" -lt "$end" ]; do
		if gx 'journalctl -b -u mastersos-bootloader-update -o cat --no-pager | grep -qE "换好了|相同|不降级|都不换"' 2>/dev/null; then
			return 0
		fi
		sleep 5
	done
	return 1
}
bl_journal() { gx 'journalctl -b -u mastersos-bootloader-update -o cat --no-pager'; }
ensure_new_published() {
	in_channel "$V_NEW" beta && return 0
	build "$V_NEW" || return 1
	publish "$V_NEW" beta
}
# luks:pcrlock in the device's latest report on the server
pcrlock_report() {
	api ops GET /v1/admin/devices | jq -c --arg id "$1" '.[] | select(.device_id == $id) | .results[]? | select(.item == "luks:pcrlock")'
}

c_shim_update_no_prompt() {
	local name=shim_update_no_prompt bad="" o r id
	ensure_new_published || {
		fail "$name" "building or publishing $V_NEW failed"
		return
	}
	ensure_beta
	stop_vm
	rollback "$SNAP_OLD"
	start_wait || {
		fail "$name" "VM does not come up"
		return
	}
	id=$(device_id)
	r=$(update_to_new) || bad="${bad}update to $V_NEW failed; "
	log "reboot into $V_NEW: $r"
	[ "$(img_version)" = "$V_NEW" ] || bad="${bad}not running $V_NEW; "
	wait_bootloader_update 600 || bad="${bad}mastersos-bootloader-update did not finish; "
	o=$(bl_journal)
	echo "$o" | sed 's/^/  bootloader-update: /'
	# shim-prepare before the first write, and it prepared
	local first_prep first_write
	first_prep=$(grep -n 'shim-prepare (exit' <<<"$o" | head -n 1 | cut -d: -f1)
	first_write=$(grep -n '，替换$' <<<"$o" | head -n 1 | cut -d: -f1)
	[ -n "$first_prep" ] && [ -n "$first_write" ] && [ "$first_prep" -lt "$first_write" ] ||
		bad="${bad}shim-prepare is not before the first write; "
	grep -q 'shim-prepare (exit 0): prepared' <<<"$o" || bad="${bad}shim-prepare did not prepare; "
	grep -q '换好了：.*BOOTX64.EFI' <<<"$o" || bad="${bad}the shim was not replaced; "
	gx 'ls -la /var/lib/pcrlock.d/620-secureboot-authority.pcrlock.d; cat /var/lib/mastersos-system/shim-prepare.json' | sed 's/^/  /'
	# reboot: no recovery key
	r=$(reboot_maybe_key | tail -n 1)
	log "first boot on the new shim: $r"
	[ "$r" = noprompt ] || bad="${bad}first boot on the new shim: $r; "
	tpm_unlocked "first boot on the new shim" || bad="${bad}not unlocked by the TPM; "
	o=$(gx 'cat /sys/class/tpm/tpm0/pcr-sha256/7; tr "\n" " " < <(tail -c +5 /sys/firmware/efi/efivars/SbatLevelRT-605dab50-e046-4300-abb6-3dd810dd8b23); echo')
	log "PCR 7 / SbatLevelRT: ${o//$'\n'/ | }"
	grep -q 'sbat,1,2023012900' <<<"$o" || bad="${bad}SbatLevelRT is not 15.8's; "
	agent_round 75
	o=$(gx 'journalctl -u mastersos-agent -b -o cat --no-pager | grep -E "shim update completed|next-shim" | tail -3; ls /var/lib/pcrlock.d/620-secureboot-authority.pcrlock.d; jq -r .outcome /var/lib/mastersos-system/shim-prepare.json; true')
	echo "$o" | sed 's/^/  /'
	grep -q 'shim update completed without the recovery key' <<<"$o" || bad="${bad}the agent did not finish the shim update; "
	grep -q '400-mastersos-next-shim' <<<"$o" && bad="${bad}the next-shim variant is still there; "
	grep -qx completed <<<"$o" || bad="${bad}shim-prepare.json does not say completed; "
	o=$(pcrlock_report "$id")
	log "server: luks:pcrlock = $o"
	grep -q '"ok":true.*shim update completed without the recovery key' <<<"$o" || bad="${bad}luks:pcrlock on the server is not the completion; "
	r=$(reboot_maybe_key | tail -n 1)
	log "second boot on the new shim: $r"
	[ "$r" = noprompt ] && tpm_unlocked "second boot on the new shim" || bad="${bad}second boot: $r; "
	stop_vm
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

c_shim_update_predict_fail_falls_back() {
	local name=shim_update_predict_fail_falls_back bad="" o r id
	ensure_new_published || {
		fail "$name" "building or publishing $V_NEW failed"
		return
	}
	ensure_beta
	stop_vm
	rollback "$SNAP_OLD"
	start_wait || {
		fail "$name" "VM does not come up"
		return
	}
	id=$(device_id)
	# Keep V_NEW's automatic bootloader update from running before the marker is in place (/run is per boot): a stamp
	# newer than V_NEW makes it a no-op ("不降级"); after the marker, remove the stamp and run it by hand (4a's recipe)
	gx "printf '%s\n' $V_NEW.5 > \"\$(bootctl -p)/loader/mastersos-bootloader.version\""
	r=$(update_to_new) || bad="${bad}update to $V_NEW failed; "
	log "reboot into $V_NEW: $r"
	wait_bootloader_update 600 || true
	gx 'mkdir -p /run/mastersos-test && touch /run/mastersos-test/shim-prepare-fail; rm -f "$(bootctl -p)/loader/mastersos-bootloader.version"; systemctl restart mastersos-bootloader-update; true'
	o=$(bl_journal)
	echo "$o" | sed 's/^/  bootloader-update: /'
	grep -q 'prediction failed: failed: test: forced failure' <<<"$o" || bad="${bad}no \"prediction failed\" in the journal; "
	grep -q '换好了：.*BOOTX64.EFI' <<<"$o" || bad="${bad}the shim was not replaced; "
	agent_round 75
	o=$(pcrlock_report "$id")
	log "server, same boot: luks:pcrlock = $o"
	grep -q '"ok":false.*prediction failed (test: forced failure); this machine needs the recovery key' <<<"$o" ||
		bad="${bad}luks:pcrlock does not report the failed prediction; "
	r=$(reboot_maybe_key | tail -n 1)
	log "first boot on the new shim: $r"
	[ "$r" = prompt ] || bad="${bad}expected the recovery key prompt, got $r; "
	agent_round 75
	o=$(gx 'journalctl -u mastersos-agent -b -o cat --no-pager | grep -E "PIN" | tail -2; test -e /var/lib/mastersos-system/shim-prepare.json && echo STATE-LEFT; true')
	echo "$o" | sed 's/^/  /'
	grep -q STATE-LEFT <<<"$o" && bad="${bad}shim-prepare.json is still there after the reboot; "
	grep -q 'rewritten with the PIN' <<<"$o" || bad="${bad}the agent did not re-seal with its PIN; "
	# (the PIN repair's detail is reported only by the round that did it — 4b behaviour — so the server may show null)
	o=$(pcrlock_report "$id")
	log "server, after the recovery key: luks:pcrlock = $o"
	grep -q '"ok":true' <<<"$o" || bad="${bad}luks:pcrlock after the recovery key is not ok; "
	r=$(reboot_maybe_key | tail -n 1)
	log "second boot on the new shim: $r"
	[ "$r" = noprompt ] && tpm_unlocked "second boot after the fallback" || bad="${bad}second boot: $r; "
	stop_vm
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

c_shim_unchanged_no_prepare() {
	local name=shim_unchanged_no_prepare bad="" o r
	ensure_new_published || {
		fail "$name" "building or publishing $V_NEW failed"
		return
	}
	ensure_beta
	stop_vm
	rollback "$SNAP_BASE"
	start_wait || {
		fail "$name" "VM does not come up"
		return
	}
	r=$(update_to_new) || bad="${bad}update to $V_NEW failed; "
	log "reboot into $V_NEW: $r"
	[ "$r" = noprompt ] || bad="${bad}reboot into $V_NEW: $r; "
	wait_bootloader_update 600 || bad="${bad}mastersos-bootloader-update did not finish; "
	o=$(bl_journal)
	echo "$o" | sed 's/^/  bootloader-update: /'
	grep -q 'shim-prepare' <<<"$o" && bad="${bad}shim-prepare ran although the shim did not change; "
	stop_vm
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# ==================================================================================
# main
# ==================================================================================
[ -n "${A5_LIB:-}" ] && return 0
checks=("$@")
[ "${checks[*]}" = all ] && checks=(shim_update_no_prompt shim_update_predict_fail_falls_back shim_unchanged_no_prepare)
log "accept-5.sh VM $vmid: ${checks[*]} (base $V_BASE, new $V_NEW)"
for c in "${checks[@]}"; do
	declare -F "c_$c" >/dev/null || {
		fail "$c" "no such check"
		continue
	}
	log "=== $c"
	"c_$c"
done
log "done: $fails failure(s)"
exit "$fails"
