#!/bin/bash
# Tests for golden-fetch (usr self-repair Task 7; mkosi.extra/usr/lib/mastersos/golden-fetch). No VM, no root; needs curl, zstd,
# gpg/gpgv and jq:
#   bash image/tests/golden-fetch-test.sh
# A file:// directory is the update channel (as in update-run-test.sh): SHA256SUMS signed with a throwaway gpg key
# (MASTERSOS_GPG_KEYRING is its public key), the three .raw.zst files and the .efi of each version. Plain files stand in for the
# golden partitions and a directory for the golden ESP; verity_check, ukify, sbverify and openssl are stubs (golden-lib-test.sh
# covers golden-lib), dd is the real one behind a recorder.
# shellcheck disable=SC2016 # the stub scripts are written from single-quoted text on purpose
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
script=$here/../mkosi.extra/usr/lib/mastersos/golden-fetch
integrity=$here/../mkosi.extra/usr/lib/mastersos/integrity
lib=$here/../mkosi.extra/usr/lib/mastersos/golden-lib
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0 n=0

check() { # check <name> <want> <got>
	n=$((n + 1))
	if [ "$2" = "$3" ]; then
		echo "ok   $1"
	else
		echo "FAIL $1: want '$2', got '$3'" >&2
		fails=$((fails + 1))
	fi
}

RH=8e23106eae00986cafdf5579681645ec48477bbb52f1986e508a9c3139f70be4 # the running root hash
GH=1111111111111111111111111111111111111111111111111111111111111111 # another root hash
V=20261027.4                                                         # the booted version, in the channel

bin=$tmp/bin
mkdir -p "$bin"
# wrapper lib: the real library, then verity_check replaced by a recorder (rc from $STUB_VC_RC; $STUB_VC_RC_SIGNED for signed calls)
cat >"$tmp/lib" <<EOF
. "$lib"
verity_check() {
	echo "\$* sig=\$(sig_roothash "\$3" || echo none)" >>"\$VC_LOG"
	[ "\$(sig_roothash "\$3")" = "\$4" ] || return 1
	case " \$* " in
	*" --no-sig "*) return "\${STUB_VC_RC:-0}" ;;
	*) return "\${STUB_VC_RC_SIGNED:-\${STUB_VC_RC:-0}}" ;;
	esac
}
EOF
# ukify stub: the "UKI" is a text file "<version> <usrhash>"
cat >"$bin/ukify" <<'EOF'
#!/bin/bash
read -r ver hash <"$2"
printf '{".osrel":{"text":"IMAGE_VERSION=\\"%s\\"\\n"},".cmdline":{"text":"usrhash=%s root=dissect"}}\n' "$ver" "$hash"
EOF
printf '#!/bin/bash\nexit 0\n' >"$bin/sbverify"
printf '#!/bin/bash\n# openssl x509 -inform der -in X -out Y\nwhile [ $# -gt 0 ]; do [ "$1" = -out ] && : >"$2"; shift; done\n' >"$bin/openssl"
printf '#!/bin/bash\nexit 0\n' >"$bin/udevadm"
# dd recorder (MASTERSOS_DD): logs "<of name> <if name|stdin>[ fullblock] lock=held|free", then runs the real dd
cat >"$bin/dd-rec" <<'EOF'
#!/bin/bash
lock=held
if flock -n "$MASTERSOS_WHOLE_DISK" true 2>/dev/null; then lock=free; fi
of="" in=stdin
for a in "$@"; do case $a in of=*) of=${a#of=} ;; if=*) in=${a#if=} ;; iflag=*fullblock*) in="$in fullblock" ;; esac; done
echo "${of##*/} ${in##*/} lock=$lock" >>"$DD_LOG"
exec dd "$@"
EOF
# curl recorder: logs the URL's file name, then runs the real curl
cat >"$bin/curl" <<'EOF'
#!/bin/bash
echo "${*: -1}" | sed 's#.*/##' >>"$CURL_LOG"
exec /usr/bin/curl "$@"
EOF
printf '#!/bin/bash\necho "$*" >>"$SYSTEMCTL_LOG"\n' >"$bin/systemctl"
chmod +x "$bin"/*
: >"$tmp/mok.der"

# --- gpg keys: the trusted one signs the channel, the other one forges
export GNUPGHOME=$tmp/gnupg
mkdir -m 0700 "$GNUPGHOME" "$tmp/gnupg-bad"
gpg --batch --quiet --pinentry-mode loopback --passphrase '' --quick-gen-key 'MastersOS test <test@example.invalid>' ed25519 sign never 2>/dev/null
gpg --batch --quiet --export >"$tmp/pubring.pgp"
GNUPGHOME=$tmp/gnupg-bad gpg --batch --quiet --pinentry-mode loopback --passphrase '' --quick-gen-key 'Forger <forger@example.invalid>' ed25519 sign never 2>/dev/null

# --- payload of a version: erofs usr of 3 blocks in a 16 KiB image, verity superblock covering 3 blocks of 4096, signature, UKI
mkerofs() { # mkerofs <file> <blocks of 4096> <total bytes>
	local b=$2
	head -c "$3" /dev/urandom >"$1"
	printf '\xe2\xe1\xf5\xe0' | dd of="$1" bs=1 seek=1024 conv=notrunc status=none
	printf '\x0c' | dd of="$1" bs=1 seek=1036 conv=notrunc status=none
	# shellcheck disable=SC2059 # blocks as little-endian u32 at 1060
	printf "$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' $((b & 255)) $((b >> 8 & 255)) $((b >> 16 & 255)) $((b >> 24 & 255)))" |
		dd of="$1" bs=1 seek=1060 conv=notrunc status=none
}
mkverity() { # mkverity <file> <data blocks of 4096>
	head -c 8192 /dev/urandom >"$1"
	printf 'verity\0\0' | dd of="$1" bs=1 conv=notrunc status=none
	printf '\x00\x10\x00\x00' | dd of="$1" bs=1 seek=64 conv=notrunc status=none
	# shellcheck disable=SC2059
	printf "$(printf '\\x%02x' "$2")\0\0\0\0\0\0\0" | dd of="$1" bs=1 seek=72 conv=notrunc status=none
}
sig_json() { # sig_json <file> <roothash|->
	if [ "$2" = - ]; then
		dd if=/dev/zero of="$1" bs=16K count=1 status=none
	else
		printf '{"rootHash":"%s","signature":"AAAA"}' "$2" | dd of="$1" bs=16K count=1 conv=sync status=none
	fi
}
# version <dir> <version> <roothash> [<uki usrhash>]: the four files of a version (raw copies kept as <dir>/<version>.*.raw)
version() {
	local c=$1 v=$2 rh=$3 uh=${4:-$3} raw=$tmp/raw/$2
	mkdir -p "$raw"
	mkerofs "$raw/usr" 3 16384
	mkverity "$raw/verity" 3
	sig_json "$raw/sig" "$rh"
	echo "$v $uh" >"$raw/uki"
	zstd -q -c "$raw/usr" >"$c/MastersOS_${v}_x86-64.usr-x86-64.7e711a7f9d1b6328ec9ff74b3b416294.raw.zst"
	zstd -q -c "$raw/verity" >"$c/MastersOS_${v}_x86-64.usr-x86-64-verity.44af706efee2ef2636f17f9cf9afc9fd.raw.zst"
	zstd -q -c "$raw/sig" >"$c/MastersOS_${v}_x86-64.usr-x86-64-verity-sig.1b9180d829a345dd8b2966bfd2087635.raw.zst"
	cp "$raw/uki" "$c/MastersOS_${v}_x86-64.efi"
	echo "build-info of $v" >"$c/MastersOS_${v}_x86-64.build-info.txt"
}
seal() { # seal <channel dir> [gnupg home]: SHA256SUMS of everything there, detached signature
	(cd "$1" && find . -maxdepth 1 -type f -name 'MastersOS_*' -printf '%f\n' | LC_ALL=C sort | xargs sha256sum) >"$1/SHA256SUMS"
	rm -f "$1/SHA256SUMS.gpg"
	GNUPGHOME=${2:-$GNUPGHOME} gpg --batch --quiet --detach-sign --output "$1/SHA256SUMS.gpg" "$1/SHA256SUMS"
}
transfer() { # transfer <file> <url>
	mkdir -p "$(dirname "$1")"
	printf '[Transfer]\nVerify=yes\n\n[Source]\nType=url-file\nPath=%s\nMatchPattern=MastersOS_@v_%%a.usr-%%a.@u.raw.zst\n\n[Target]\nType=partition\nPath=auto\n' "$2" >"$1"
}

# the good channel: the booted version and an older one
chan=$tmp/chan/stable
mkdir -p "$chan"
version "$chan" 20261026.1 "$GH"
version "$chan" "$V" "$RH"
seal "$chan"

# fresh <case> -> a machine whose golden copy is invalid (signature area zeroed), /usr/lib transfers pointing at the good channel
fresh() {
	local d=$tmp/$1
	rm -rf "$d"
	mkdir -p "$d/gesp" "$d/var" "$d/vartmp" "$d/etc" "$d/usrlib"
	sig_json "$d/gsig" -
	head -c 8192 /dev/zero >"$d/gverity"
	head -c 16384 /dev/zero >"$d/gusr"
	echo "20261020.1 $GH" >"$d/gesp/MastersOS.efi"
	echo "BOOT_IMAGE=/x usrhash=$RH quiet" >"$d/cmdline"
	: >"$d/vc.log"
	: >"$d/dd.log"
	: >"$d/curl.log"
	: >"$d/disk"
	transfer "$d/usrlib/12-usr.transfer" "file://$chan/"
	echo "$d"
}

# run <case> [args...] -> golden-fetch's exit code; output in <case>/out. EXTRA_ENV words are added.
run() {
	local d=$1 extra=() rc=0
	shift
	read -ra extra <<<"${EXTRA_ENV:-}"
	env -i PATH="$bin:/usr/bin:/bin" HOME="$d" \
		MASTERSOS_GOLDEN_LIB="$tmp/lib" MASTERSOS_INTEGRITY="$integrity" MASTERSOS_SYSTEM_VAR="$d/var" \
		MASTERSOS_SYSUPDATE_ETC="$d/etc" MASTERSOS_SYSUPDATE_USR="$d/usrlib" MASTERSOS_GPG_KEYRING="$tmp/pubring.pgp" \
		MASTERSOS_FETCH_TMPDIR="$d/vartmp" MASTERSOS_FETCH_MIN_FREE_MB=1 \
		MASTERSOS_GOLDEN_SIG="$d/gsig" MASTERSOS_GOLDEN_VERITY="$d/gverity" MASTERSOS_GOLDEN_USR="$d/gusr" MASTERSOS_GOLDEN_ESP_DIR="$d/gesp" \
		MASTERSOS_CMDLINE="$d/cmdline" MASTERSOS_MOK_DER="$tmp/mok.der" \
		MASTERSOS_DD="$bin/dd-rec" MASTERSOS_WHOLE_DISK="$d/disk" DD_LOG="$d/dd.log" VC_LOG="$d/vc.log" CURL_LOG="$d/curl.log" \
		MASTERSOS_SYSTEMCTL="$bin/systemctl" SYSTEMCTL_LOG="$d/systemctl.log" MASTERSOS_FETCHED_MARKER="$d/golden-fetched" \
		"${extra[@]}" bash "$script" "$@" >"$d/out" 2>&1 || rc=$?
	echo "$rc"
}
gsig_rh() { # the root hash the golden signature area names, or "zero"
	local r
	r=$(dd if="$1/gsig" bs=16K count=1 status=none | tr -d '\0' | sed -nE 's/.*"rootHash":"([^"]*)".*/\1/p')
	echo "${r:-zero}"
}
nothing_written() { # "<dd log lines> <golden sig>|<golden esp UKI>"
	echo "$(wc -l <"$1/dd.log" | tr -d ' ') $(gsig_rh "$1")|$(cat "$1/gesp/MastersOS.efi")"
}
leftover() { find "$1/vartmp" -mindepth 1 | wc -l | tr -d ' '; }
same() { cmp -s "$1" "$2" && echo same || echo differs; }

# --- fetch_ok ------------------------------------------------------------------------------------------------------------------
d=$(fresh fetch_ok)
check "fetch_ok: exit 0" 0 "$(run "$d" "$V")"
check "fetch_ok: golden usr = the unpacked usr" same "$(cmp -s -n 16384 "$tmp/raw/$V/usr" "$d/gusr" && echo same || echo differs)"
check "fetch_ok: golden verity = the unpacked verity" same "$(same "$tmp/raw/$V/verity" "$d/gverity")"
check "fetch_ok: golden sig = the unpacked sig" same "$(same "$tmp/raw/$V/sig" "$d/gsig")"
check "fetch_ok: golden ESP UKI = the downloaded UKI" "$V $RH" "$(cat "$d/gesp/MastersOS.efi")"
check "fetch_ok: manifest" "version=$V sha256=$(sha256sum <"$tmp/raw/$V/uki" | cut -d' ' -f1)" "$(cat "$d/gesp/manifest")"
# write order: sig zeroed first, usr from the zstd stream (iflag=fullblock: uutils dd is 15x slower on a pipe without it), verity,
# sig written last; all under the disk lock
check "fetch_ok: write order" "gsig zero lock=held,gusr stdin fullblock lock=held,gverity verity.raw lock=held,gsig sig.raw lock=held," \
	"$(tr '\n' , <"$d/dd.log")"
# verity_check: full read with the downloaded signature (throttled), then a signed open from the written golden signature
check "fetch_ok: full signed read-through, then signed open of the written sig" \
	"$d/gusr $d/gverity sig.raw $RH --rate 150|$d/gusr $d/gverity $d/gsig $RH --no-read|" \
	"$(sed -E "s#[^ ]*/sig\.raw#sig.raw#; s/ sig=[0-9a-f]+\$//" "$d/vc.log" | tr '\n' '|')"
check "fetch_ok: download directory removed" 0 "$(leftover "$d")"
check "fetch_ok: bytes downloaded reported" 1 "$(grep -cE 'downloaded [0-9]+ bytes' "$d/out")"

# --- bad_gpg: SHA256SUMS signed by another key, or altered after signing -> nothing written, exit 1 ---------------------------------
bad=$tmp/chan-bad/stable
mkdir -p "$bad"
cp "$chan"/MastersOS_* "$bad/"
seal "$bad" "$tmp/gnupg-bad"
d=$(fresh bad_gpg)
transfer "$d/usrlib/12-usr.transfer" "file://$bad/"
check "bad_gpg: forged signature -> exit 1" 1 "$(run "$d" "$V")"
check "bad_gpg: nothing written" "0 zero|20261020.1 $GH" "$(nothing_written "$d")"
check "bad_gpg: download directory removed" 0 "$(leftover "$d")"
seal "$bad"
sed -i 's/^\([0-9a-f]\)/0/' "$bad/SHA256SUMS"
d=$(fresh bad_gpg2)
transfer "$d/usrlib/12-usr.transfer" "file://$bad/"
check "bad_gpg: SHA256SUMS altered after signing -> exit 1" 1 "$(run "$d" "$V")"
check "bad_gpg: altered, nothing written" "0 zero|20261020.1 $GH" "$(nothing_written "$d")"

# --- bad_sha: one file does not match SHA256SUMS -> golden-sig stays zeroed (nothing written), exit 1 -------------------------------
bad=$tmp/chan-sha/stable
mkdir -p "$bad"
cp "$chan"/MastersOS_* "$bad/"
seal "$bad"
printf 'x' >>"$bad/MastersOS_${V}_x86-64.usr-x86-64-verity.44af706efee2ef2636f17f9cf9afc9fd.raw.zst"
d=$(fresh bad_sha)
transfer "$d/usrlib/12-usr.transfer" "file://$bad/"
check "bad_sha: exit 1" 1 "$(run "$d" "$V")"
check "bad_sha: golden-sig zeroed, nothing written" "0 zero|20261020.1 $GH" "$(nothing_written "$d")"
check "bad_sha: download directory removed" 0 "$(leftover "$d")"

# --- not_in_channel: version not in SHA256SUMS -> exit 3 ------------------------------------------------------------------------
d=$(fresh not_in_channel)
check "not_in_channel: exit 3" 3 "$(run "$d" 19990101.1)"
check "not_in_channel: nothing written" "0 zero|20261020.1 $GH" "$(nothing_written "$d")"
check "not_in_channel: a prefix of a listed version does not match" 3 "$(run "$d" 20261027)"

# --- incomplete: the version is listed without its verity file -> exit 1 (not 3) ----------------------------------------------------
bad=$tmp/chan-inc/stable
mkdir -p "$bad"
cp "$chan"/MastersOS_* "$bad/"
rm "$bad"/MastersOS_"$V"_x86-64.usr-x86-64-verity.*
seal "$bad"
d=$(fresh incomplete)
transfer "$d/usrlib/12-usr.transfer" "file://$bad/"
check "incomplete: exit 1" 1 "$(run "$d" "$V")"
check "incomplete: nothing written" "0 zero|20261020.1 $GH" "$(nothing_written "$d")"
check "incomplete: picked before downloading, no payload downloaded" "SHA256SUMS,SHA256SUMS.gpg," "$(tr '\n' , <"$d/curl.log")"

# --- other_roothash: the channel's signature for the version names another root hash -> nothing written ----------------------------
d=$(fresh other_roothash)
echo "BOOT_IMAGE=/x usrhash=$GH" >"$d/cmdline"
sig_json "$d/gsig" "$RH" # a golden copy of another hash: not newer (20261020.1), so the guard lets it through
check "other_roothash: running hash differs from the download -> exit 1" 1 "$(run "$d" "$V")"
check "other_roothash: nothing written" "0 $RH|20261020.1 $GH" "$(nothing_written "$d")"
grep -q "not the running root hash" "$d/out" && r=yes || r=no
check "other_roothash: says why" yes "$r"

# --- uki_mismatch: the UKI of the version is for another root hash -> nothing written ------------------------------------------------
bad=$tmp/chan-uki/stable
mkdir -p "$bad"
cp "$chan"/MastersOS_* "$bad/"
echo "$V $GH" >"$bad/MastersOS_${V}_x86-64.efi"
seal "$bad"
d=$(fresh uki_mismatch)
transfer "$d/usrlib/12-usr.transfer" "file://$bad/"
check "uki_mismatch: exit 1" 1 "$(run "$d" "$V")"
check "uki_mismatch: nothing written" "0 zero|20261020.1 $GH" "$(nothing_written "$d")"

# --- verify_fails: the written copy does not read through -> sig stays zeroed, exit 1 -------------------------------------------------
d=$(fresh verify_fails)
check "verify_fails: exit 1" 1 "$(EXTRA_ENV="STUB_VC_RC=1" run "$d" "$V")"
check "verify_fails: golden-sig zeroed, sig never written" "zero gsig zero lock=held,gusr stdin fullblock lock=held,gverity verity.raw lock=held," \
	"$(gsig_rh "$d") $(tr '\n' , <"$d/dd.log")"

# --- written_sig_fails: the written golden sig does not open the copy (signed open of the partition fails) -> zeroed again -----------
d=$(fresh written_sig_fails)
cat >"$tmp/lib-written" <<EOF
. "$tmp/lib"
verity_check() {
	echo "\$*" >>"\$VC_LOG"
	case \$3 in */gsig) return 1 ;; esac
	return 0
}
EOF
check "written_sig_fails: exit 1" 1 "$(EXTRA_ENV="MASTERSOS_GOLDEN_LIB=$tmp/lib-written" run "$d" "$V")"
check "written_sig_fails: golden-sig zeroed again" "zero gsig zero lock=held" "$(gsig_rh "$d") $(tail -n 1 "$d/dd.log")"

# --- enokey: signed checks return 3 (keyring cannot judge) -> --no-sig accepted, the root hash being the running one ----------------
d=$(fresh enokey)
check "enokey: exit 0" 0 "$(EXTRA_ENV="STUB_VC_RC_SIGNED=3" run "$d" "$V")"
check "enokey: each signed check retried with --no-sig" "--rate 150|--no-sig --rate 150|--no-read|--no-sig --no-read|" \
	"$(sed -E "s/^[^ ]+ [^ ]+ [^ ]+ [0-9a-f]{64} //; s/ sig=[0-9a-f]+\$//" "$d/vc.log" | tr '\n' '|')"
check "enokey: golden sig written" "$RH" "$(gsig_rh "$d")"

# --- downgrade: the golden copy holds a newer version of another root hash -> refused, nothing downloaded ----------------------------
d=$(fresh downgrade)
sig_json "$d/gsig" "$GH"
echo "20261030.1 $GH" >"$d/gesp/MastersOS.efi"
check "downgrade: newer golden copy -> exit 1" 1 "$(run "$d" "$V")"
check "downgrade: nothing written" "0 $GH|20261030.1 $GH" "$(nothing_written "$d")"
check "downgrade: nothing downloaded" 0 "$(leftover "$d")"
grep -q "not downgrading" "$d/out" && r=yes || r=no
check "downgrade: says why" yes "$r"
d=$(fresh downgrade_unknown)
sig_json "$d/gsig" "$GH"
rm -rf "$d/gesp"
check "downgrade: golden copy of another hash with an unmountable ESP -> exit 1" 1 "$(run "$d" "$V")"
check "downgrade: unmountable, nothing written" 0 "$(wc -l <"$d/dd.log" | tr -d ' ')"
d=$(fresh same_hash)
sig_json "$d/gsig" "$RH" # a damaged golden copy of the running hash: refetched
echo "$V $RH" >"$d/gesp/MastersOS.efi"
check "same_hash: golden copy of the running hash is refetched -> exit 0" 0 "$(run "$d" "$V")"

# --- esp_rw_fails: the golden ESP does not mount -> nothing written --------------------------------------------------------------
d=$(fresh esp_fails)
rm -rf "$d/gesp"
check "esp_fails: exit 1" 1 "$(run "$d" "$V")"
check "esp_fails: golden-sig not touched" "0 zero" "$(wc -l <"$d/dd.log" | tr -d ' ') $(gsig_rh "$d")"

# --- sources: /etc first, school cache with the official source in sysupdate-fallback.d ------------------------------------------
d=$(fresh etc_first)
transfer "$d/usrlib/12-usr.transfer" "file://$tmp/nowhere/"
transfer "$d/etc/12-usr.transfer" "file://$chan/"
check "sources: /etc/sysupdate.d wins over /usr/lib" 0 "$(run "$d" "$V")"
d=$(fresh cache_down)
transfer "$d/etc/12-usr.transfer" "file://$tmp/nowhere/"
transfer "$d/var/sysupdate-fallback.d/12-usr.transfer" "file://$chan/"
check "sources: cache unreachable -> official source" 0 "$(run "$d" "$V")"
grep -q "trying file://$tmp/nowhere/" "$d/out" && r=yes || r=no
check "sources: the cache was tried first" yes "$r"
stale=$tmp/chan-stale/stable
mkdir -p "$stale"
version "$stale" 20261026.1 "$GH"
seal "$stale"
d=$(fresh cache_stale)
transfer "$d/etc/12-usr.transfer" "file://$stale/"
transfer "$d/var/sysupdate-fallback.d/12-usr.transfer" "file://$chan/"
check "sources: cache without the version -> official source" 0 "$(run "$d" "$V")"
d=$(fresh both_gone)
transfer "$d/etc/12-usr.transfer" "file://$chan/"
transfer "$d/var/sysupdate-fallback.d/12-usr.transfer" "file://$stale/"
check "sources: the last source's answer counts (official lacks it -> 3)" 3 "$(run "$d" 19990101.1)"
d=$(fresh official_down)
transfer "$d/etc/12-usr.transfer" "file://$stale/"
transfer "$d/var/sysupdate-fallback.d/12-usr.transfer" "file://$tmp/nowhere/"
check "sources: cache lacks it, official unreachable -> 1 (not 3)" 1 "$(run "$d" "$V")"
check "sources: download directories removed" 0 "$(leftover "$d")"

# --- bounded downloads: an oversized SHA256SUMS or payload file fails cleanly ----------------------------------------------------
d=$(fresh big_list)
check "big_list: SHA256SUMS over the limit -> exit 1" 1 "$(EXTRA_ENV="MASTERSOS_FETCH_MAX_LIST_BYTES=100" run "$d" "$V")"
check "big_list: nothing written, no payload downloaded" "0 zero|20261020.1 $GH SHA256SUMS," \
	"$(nothing_written "$d") $(tr '\n' , <"$d/curl.log")"
check "big_list: download directory removed" 0 "$(leftover "$d")"
d=$(fresh big_file)
check "big_file: a payload file over the limit -> exit 1" 1 "$(EXTRA_ENV="MASTERSOS_FETCH_MAX_FILE_BYTES=1000" run "$d" "$V")"
check "big_file: nothing written" "0 zero|20261020.1 $GH" "$(nothing_written "$d")"

# --- --booted (mastersos-golden-fetch.service): IMAGE_VERSION, then integrity again (0) or mastersos-update (3) -----------------
d=$(fresh booted_ok)
check "booted_ok: exit 0" 0 "$(EXTRA_ENV="MASTERSOS_IMAGE_VERSION=$V" run "$d" --booted)"
check "booted_ok: golden copy written, then integrity started again" "$RH start --no-block mastersos-integrity.service" \
	"$(gsig_rh "$d") $(cat "$d/systemctl.log")"
# the once-per-boot marker: integrity's network action does not start another download in this boot
check "booted_ok: /run marker left for integrity" yes "$([ -e "$d/golden-fetched" ] && echo yes || echo no)"
d=$(fresh booted_gone)
check "booted_gone: version not in the channel -> exit 0" 0 "$(EXTRA_ENV="MASTERSOS_IMAGE_VERSION=19990101.1" run "$d" --booted)"
check "booted_gone: mastersos-update started, nothing written, no marker" "start --no-block mastersos-update.service 0 no" \
	"$(cat "$d/systemctl.log") $(wc -l <"$d/dd.log" | tr -d ' ') $([ -e "$d/golden-fetched" ] && echo yes || echo no)"
d=$(fresh booted_fail)
transfer "$d/usrlib/12-usr.transfer" "file://$tmp/nowhere/"
check "booted_fail: fetch fails -> its exit code (1), nothing started, no marker" "1 none no" \
	"$(EXTRA_ENV="MASTERSOS_IMAGE_VERSION=$V" run "$d" --booted) $([ -s "$d/systemctl.log" ] && echo started || echo none) $([ -e "$d/golden-fetched" ] && echo yes || echo no)"
d=$(fresh booted_noversion)
check "booted_noversion: unusable IMAGE_VERSION -> exit 1, nothing started" "1 none" \
	"$(EXTRA_ENV="MASTERSOS_IMAGE_VERSION=../x" run "$d" --booted) $([ -s "$d/systemctl.log" ] && echo started || echo none)"

# --- space and usage --------------------------------------------------------------------------------------------------------
d=$(fresh no_space)
check "no_space: not enough free space -> exit 1" 1 "$(EXTRA_ENV="MASTERSOS_FETCH_MIN_FREE_MB=999999999" run "$d" "$V")"
check "no_space: nothing downloaded or written" "0 0" "$(leftover "$d") $(wc -l <"$d/dd.log" | tr -d ' ')"
check "usage: no argument -> exit 2" 2 "$(run "$d")"
check "usage: version with a slash -> exit 2" 2 "$(run "$d" ../x)"

echo
if [ "$fails" -gt 0 ]; then
	echo "golden-fetch-test: $fails of $n checks failed" >&2
	exit 1
fi
echo "golden-fetch-test: all $n checks passed"
