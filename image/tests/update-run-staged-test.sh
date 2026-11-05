#!/bin/bash
# update-run's resumable download (staged_update): no VM needed, needs GNU coreutils, curl, gpg and gpgv.
#   bash image/tests/update-run-staged-test.sh
# The image's four transfers are pointed at a file:// channel signed with a throwaway gpg key (MASTERSOS_STAGING_FILE_URLS=1 lets
# a test use file://; on a Device such a source runs sysupdate directly). A fake systemd-sysupdate answers check-new with
# $FAKE_NEW and, for update, records its arguments and the [Source] Path= of the transfers it was given, exiting $FAKE_RC.
# Cases: nothing new; a full download installs from the staged copy and removes it; an interrupted file is resumed, not
# restarted; a resumed file that comes out wrong is dropped; a half-published version keeps what it has; a bad signature
# downloads nothing; a failed install keeps the download; a newer version drops the older one's files; an unclear check-new
# and a non-url source update directly.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
skip() {
	if [ "${MASTERSOS_UPDATE_RUN_TEST_REQUIRE:-}" = 1 ]; then
		echo "update-run-staged-test: FAIL ($*)" >&2
		exit 1
	fi
	echo "update-run-staged-test: skip ($*)"
	exit 0
}
for t in curl gpg gpgv sha256sum; do command -v "$t" >/dev/null || skip "no $t"; done
df --output=avail / >/dev/null 2>&1 || skip "df has no --output (GNU coreutils); run it on Linux / CI"

tmp=$(mktemp -d)
trap 'gpgconf --homedir "$tmp/gpg" --kill all >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT
mkdir -m 700 "$tmp/gpg"
gpg --homedir "$tmp/gpg" --batch --passphrase '' --quick-gen-key 'update-run-test' ed25519 sign never 2>/dev/null
gpg --homedir "$tmp/gpg" --export >"$tmp/pubring.pgp"
mkdir -m 700 "$tmp/other"
gpg --homedir "$tmp/other" --batch --passphrase '' --quick-gen-key 'someone else' ed25519 sign never 2>/dev/null

ch=$tmp/channel defs=$tmp/defs var=$tmp/var
mkdir -p "$ch" "$defs" "$var"
for f in "$here"/../mkosi.extra/usr/lib/sysupdate.d/*.transfer; do
	sed "s#^Path=.*/stable/\$#Path=file://$ch/#" "$f" >"$defs/${f##*/}"
done
grep -q "^Path=file://$ch/\$" "$defs/12-usr.transfer" || {
	echo "update-run-staged-test: could not point the transfers at the test channel" >&2
	exit 1
}

cat >"$tmp/sysupdate" <<'SH'
#!/bin/bash
verb=${*: -1}
if [ "$verb" = check-new ]; then
	[ -n "${FAKE_NEW:-}" ] && echo "$FAKE_NEW" && exit 0
	[ -z "${FAKE_NEW_ERR:-}" ] || echo "Failed to download: $FAKE_NEW_ERR" >&2
	exit 1
fi
echo "$*" >>"$FAKE_LOG"
d=${1#--definitions=}
if [ "$d" != "$1" ]; then
	sed -n '/^\[Source\]/,/^\[/s/^Path=//p' "$d"/*.transfer | sort -u >>"$FAKE_LOG.paths"
fi
exit "${FAKE_RC:-0}"
SH
chmod +x "$tmp/sysupdate"
export MASTERSOS_SYSUPDATE=$tmp/sysupdate MASTERSOS_SYSTEM_VAR=$var FAKE_LOG=$tmp/log
export MASTERSOS_SYSUPDATE_DIRS=$defs MASTERSOS_STAGING_FILE_URLS=1 MASTERSOS_GPG_KEYRING=$tmp/pubring.pgp
export MASTERSOS_STAGED_DEFINITIONS=$tmp/run/definitions MASTERSOS_STAGING_MIN_FREE=1
# the restart prompt after each successful round sees an empty ESP here (tests/update-run-test.sh covers it)
export MASTERSOS_UPDATE_PENDING=$tmp/update-pending MASTERSOS_BOOT_PATH=$tmp/boot MASTERSOS_IMAGE_VERSION=20000101.1

# publish <version…>: the channel holds these versions (each: UKI, three partition files, build-info), signed
publish() {
	local v k
	rm -f "$ch"/*
	for v in "$@"; do
		head -c 300000 /dev/urandom >"$ch/MastersOS_${v}_x86-64.usr-x86-64.0f2b6c1e-1111-2222-3333-444455556666.raw.zst"
		for k in verity verity-sig; do
			head -c 5000 /dev/urandom >"$ch/MastersOS_${v}_x86-64.usr-x86-64-$k.0f2b6c1e-1111-2222-3333-44445555$((RANDOM % 9000 + 1000)).raw.zst"
		done
		head -c 70000 /dev/urandom >"$ch/MastersOS_${v}_x86-64.efi"
		echo "version=$v" >"$ch/MastersOS_${v}_x86-64.build-info.txt"
	done
	(cd "$ch" && sha256sum -- MastersOS_*) >"$ch/SHA256SUMS"
	gpg --homedir "$tmp/gpg" --batch --yes --detach-sign --output "$ch/SHA256SUMS.gpg" "$ch/SHA256SUMS" 2>/dev/null
}
stagedir() { echo "$var/update-staging/$(printf '%s' "file://$ch" | sha256sum | cut -c1-16)"; }
run() { # run → exit code of update-run; its output in $tmp/out
	local rc=0
	: >"$FAKE_LOG"
	: >"$FAKE_LOG.paths"
	"$here/../mkosi.extra/usr/lib/mastersos/update-run" >"$tmp/out" 2>&1 || rc=$?
	echo "$rc"
}

fails=0
check() { # check <name> <expected> <actual>
	if [ "$2" = "$3" ]; then
		echo "ok   $1"
	else
		echo "FAIL ${1}: expected '$2', got '$3'" >&2
		sed 's/^/    /' "$tmp/out" >&2 2>/dev/null || true
		fails=$((fails + 1))
	fi
}
istrue() {
	local name=$1
	shift
	if "$@"; then echo "ok   $name"; else
		echo "FAIL $name" >&2
		sed 's/^/    /' "$tmp/out" >&2 2>/dev/null || true
		fails=$((fails + 1))
	fi
}
calls() { wc -l <"$FAKE_LOG" | tr -d ' '; }

v1=20261106.1 v2=20261106.2
publish 20261030.1 "$v1"
usr1=$(cd "$ch" && ls MastersOS_${v1}_x86-64.usr-x86-64.*.raw.zst)

# --- nothing new
export FAKE_NEW=''
mkdir -p "$(stagedir)" "$var/update-staging/other-source"
check "nothing new: exit 0" 0 "$(run)"
check "nothing new: no update call" 0 "$(calls)"
istrue "nothing new: this source's staging removed" test ! -e "$(stagedir)"
istrue "nothing new: another source's download kept (the official source may be ahead of the cache)" test -d "$var/update-staging/other-source"
rm -rf "$var/update-staging"

# --- a full download, installed from the staged copy
export FAKE_NEW=$v1
check "new version: exit 0" 0 "$(run)"
check "one update call, with the staged definitions" "--definitions=$MASTERSOS_STAGED_DEFINITIONS update" "$(cat "$FAKE_LOG")"
check "all four transfers read from the staging directory" "file://$(stagedir)/" "$(cat "$FAKE_LOG.paths")"
istrue "staged definitions: one per transfer" test "$(find "$MASTERSOS_STAGED_DEFINITIONS" -name '*.transfer' | wc -l)" = 4
istrue "after the install the staging tree is gone" test ! -e "$var/update-staging"

# --- a failed install keeps the download for the next round
export FAKE_RC=3
check "install fails: its exit code" 3 "$(run)"
d=$(stagedir)
istrue "install fails: the four files of $v1 stay" test "$(find "$d" -name "MastersOS_${v1}_*" | wc -l)" = 4
istrue "install fails: the signed SHA256SUMS is kept next to them" test -f "$d/SHA256SUMS" -a -f "$d/SHA256SUMS.gpg"
istrue "nothing of other versions or build-info downloaded" test "$(find "$d" -name 'MastersOS_*' ! -name "MastersOS_${v1}_*" -o -name '*build-info*' | wc -l)" = 0
export FAKE_RC=0
touch -d '2001-01-01' "$d/MastersOS_${v1}_x86-64.efi"
FAKE_RC=3 run >/dev/null
check "next round reuses a complete staged file (not downloaded again)" 2001 "$(date -r "$d/MastersOS_${v1}_x86-64.efi" +%Y)"
check "next round installs" 0 "$(run)"
istrue "  and removes the staging tree" test ! -e "$d"

# --- an interrupted download is resumed, not restarted
FAKE_RC=3 run >/dev/null
rm -f "$d/$usr1"
head -c 120000 "$ch/$usr1" >"$d/$usr1.part"
FAKE_RC=3 run >/dev/null
istrue "a part file with the right first bytes is completed" cmp -s "$ch/$usr1" "$d/$usr1"
rm -f "$d/$usr1"
head -c 120000 /dev/urandom >"$d/$usr1.part"
check "a part file with wrong first bytes: not updated" 1 "$(run)"
istrue "  curl appended to it (resumed) and the result was dropped" test ! -e "$d/$usr1.part" -a ! -e "$d/$usr1"
case $(cat "$tmp/out") in *"does not match the signed SHA256SUMS"*) echo "ok     and it says so" ;; *)
	echo "FAIL no message about the mismatch" >&2
	fails=$((fails + 1))
	;;
esac
check "  the next round downloads it again and installs" 0 "$(run)"

# --- a part file can never grow past the per-file cap, whatever the source sends
FAKE_RC=3 run >/dev/null
rm -f "$d/$usr1"
head -c 120000 "$ch/$usr1" >"$d/$usr1.part"
check "cap reached by an earlier round: not updated" 1 "$(MASTERSOS_STAGING_MAX_FILE_BYTES=100000 run)"
istrue "  the oversized part file is gone, nothing past the cap was kept" test ! -e "$d/$usr1.part" -a ! -e "$d/$usr1"
check "  with a sane cap the next round completes it" 0 "$(run)"

# --- a half-published version: what is there stays, the rest comes later
mv "$ch/$usr1" "$tmp/held"
check "missing file: not updated" 1 "$(run)"
check "missing file: no install attempted" 0 "$(calls)"
istrue "missing file: the other three are kept" test "$(find "$d" -name "MastersOS_${v1}_*" ! -name '*.part' | wc -l)" = 3
touch -d '2001-01-01' "$d/MastersOS_${v1}_x86-64.efi"
mv "$tmp/held" "$ch/$usr1"
FAKE_RC=3 run >/dev/null
check "file there now: only the missing one is downloaded" 2001 "$(date -r "$d/MastersOS_${v1}_x86-64.efi" +%Y)"
istrue "  and it is complete" cmp -s "$ch/$usr1" "$d/$usr1"
check "  installed" 0 "$(run)"

# --- a bad signature downloads nothing
gpg --homedir "$tmp/other" --batch --yes --detach-sign --output "$ch/SHA256SUMS.gpg" "$ch/SHA256SUMS" 2>/dev/null
check "SHA256SUMS signed by another key: not updated" 1 "$(run)"
istrue "  no file of $v1 downloaded" test "$(find "$var" -name "MastersOS_${v1}_*" | wc -l)" = 0
gpg --homedir "$tmp/gpg" --batch --yes --detach-sign --output "$ch/SHA256SUMS.gpg" "$ch/SHA256SUMS" 2>/dev/null

# --- a newer version replaces the older one's files
FAKE_RC=3 run >/dev/null
publish 20261030.1 "$v1" "$v2"
FAKE_NEW=$v2 FAKE_RC=3 run >/dev/null
istrue "newer version: files of $v1 dropped" test "$(find "$d" -name "MastersOS_${v1}_*" | wc -l)" = 0
istrue "newer version: files of $v2 staged" test "$(find "$d" -name "MastersOS_${v2}_*" ! -name '*.part' | wc -l)" = 4
FAKE_NEW=$v2 run >/dev/null

# --- direct sysupdate: unclear check-new, a source that is not url-file
export FAKE_NEW='' FAKE_NEW_ERR=timeout
check "check-new unclear: exit 0 from the direct update" 0 "$(run)"
check "  sysupdate update without definitions" "update" "$(cat "$FAKE_LOG")"
export FAKE_NEW=$v1 FAKE_NEW_ERR=''
sed -i 's/^Type=url-file/Type=regular-file/' "$defs/20-uki.transfer"
check "a transfer with another source type: direct update" 0 "$(run)"
check "  sysupdate update without definitions" "update" "$(cat "$FAKE_LOG")"

[ "$fails" = 0 ] || exit 1
echo "update-run-staged-test: all passed"
