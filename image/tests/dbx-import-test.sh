#!/bin/bash
# dbx-import（微软 DBXUpdate.bin → keys/microsoft/dbx/）的测试，不要 VM：
#   bash image/tests/dbx-import-test.sh
# python 在测试里拼一个假的 DBXUpdate.bin（EFI_TIME、空签名的 WIN_CERTIFICATE_UEFI_GUID、SHA256 列表三项、X509 列表一项、
# X509_SHA256 列表一项），再用 openssl 的测试 CA 与 sbsign 给一个假 EFI 映像签名，把签名里记的映像摘要放进假 dbx，
# 导入后跑 keyset_shim_chains 看闸门拒收（返回 3）。最后一例要 openssl、sbsign、sbattach：缺了跳过；
# MASTERSOS_PUBLISH_TEST_REQUIRE=1（CI）时缺了算失败。
set -euo pipefail

img=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1" >&2; fail=1; }

# build.py <输出> [--hash <64 位十六进制>] [--cert <DER>]：拼 DBXUpdate.bin
cat >"$tmp/build.py" <<'PY'
import struct, sys, uuid
out = sys.argv[1]
args = sys.argv[2:]
extra_hash = args[args.index("--hash") + 1] if "--hash" in args else None
cert = open(args[args.index("--cert") + 1], "rb").read() if "--cert" in args else b"\x30\x03\x02\x01\x01"
owner = b"\x00" * 16
def slist(guid, items, hdr=b""):
    ssize = 16 + len(items[0])
    body = b"".join(owner + i for i in items)
    return uuid.UUID(guid).bytes_le + struct.pack("<III", 28 + len(hdr) + len(body), len(hdr), ssize) + hdr + body
hashes = [bytes([n]) * 32 for n in (0xCC, 0xAA, 0xBB)]
if extra_hash:
    hashes.append(bytes.fromhex(extra_hash))
auth_cert = struct.pack("<IHH", 24 + 0, 0x200, 0xEF1) + uuid.UUID("4aafd29d-68df-49ee-8aa9-347d375665a7").bytes_le
data = b"\x00" * 16 + auth_cert
data += slist("c1c41626-504c-4092-aca9-41f936934328", hashes)
data += slist("a5c059a1-94e4-4aa7-87b5-ab155c2bf072", [cert])
data += slist("3bd2a492-96c0-4079-b420-fcf98ef103ed", [b"\x11" * 32 + struct.pack("<Q", 0) + b"\x00" * 8])
open(out, "wb").write(data)
PY
imp() { python3 -I "$img/dbx-import" "$@"; }

mkdir "$tmp/in"
command -v openssl >/dev/null || { echo "dbx-import-test: 缺 openssl"; exit 1; }
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$tmp/ca.key" -out "$tmp/ca.crt" -days 3650 -subj "/CN=dbx-import-test CA" 2>/dev/null
openssl x509 -in "$tmp/ca.crt" -outform DER -out "$tmp/ca.der"
# dbx 里被吊销的证书是另一张（revoked），不是闸门要放行的 ca，免得「吊销」与「放行」的断言串在一起
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$tmp/rev.key" -out "$tmp/rev.crt" -days 3650 -subj "/CN=dbx-import-test revoked" 2>/dev/null
openssl x509 -in "$tmp/rev.crt" -outform DER -out "$tmp/rev.der"
python3 -I "$tmp/build.py" "$tmp/in/DBXUpdate.bin" --cert "$tmp/rev.der"
caname=$(sha256sum "$tmp/rev.der" 2>/dev/null | cut -d' ' -f1 || true)
[ -n "$caname" ] || caname=$(shasum -a 256 "$tmp/rev.der" | cut -d' ' -f1)

res=$(imp "$tmp/in/DBXUpdate.bin" "$tmp/out" 2>&1) || { bad "导入失败：$res"; exit 1; }

# imports_sha256_sorted_lowercase
want=$(printf '%s\n' "$(printf 'aa%.0s' {1..32})" "$(printf 'bb%.0s' {1..32})" "$(printf 'cc%.0s' {1..32})")
if [ "$(cat "$tmp/out/sha256.txt")" = "$want" ]; then ok "imports_sha256_sorted_lowercase"; else bad "imports_sha256_sorted_lowercase：$(cat "$tmp/out/sha256.txt")"; fi

# imports_x509_named_by_sha256
if [ -f "$tmp/out/$caname.der" ] && cmp -s "$tmp/out/$caname.der" "$tmp/rev.der" && [ "$(find "$tmp/out" -name '*.der' | wc -l | tr -d ' ')" = 1 ]; then
	ok "imports_x509_named_by_sha256"
else bad "imports_x509_named_by_sha256：$(ls "$tmp/out")"; fi

# skips_other_types_with_count
if grep -q '跳过 1 项（类型 X509_SHA256）' <<<"$res" && [ "$(find "$tmp/out" -type f | wc -l | tr -d ' ')" = 2 ]; then
	ok "skips_other_types_with_count"
else bad "skips_other_types_with_count：$res / $(ls "$tmp/out")"; fi

# truncated_input_writes_nothing（截掉最后 10 字节：最后一个列表被截断）
head -c $(($(wc -c <"$tmp/in/DBXUpdate.bin") - 10)) "$tmp/in/DBXUpdate.bin" >"$tmp/trunc.bin"
rc=0
imp "$tmp/trunc.bin" "$tmp/out-trunc" >/dev/null 2>&1 || rc=$?
if [ "$rc" = 1 ] && [ ! -e "$tmp/out-trunc" ] && [ -z "$(find "$tmp" -maxdepth 1 -name '.dbx-import.*')" ]; then
	ok "truncated_input_writes_nothing"
else bad "truncated_input_writes_nothing（退出 ${rc}）"; fi
# 已有的输出目录也原样不动
mkdir "$tmp/out-keep"
echo keep >"$tmp/out-keep/sha256.txt"
rc=0
imp "$tmp/trunc.bin" "$tmp/out-keep" >/dev/null 2>&1 || rc=$?
if [ "$rc" = 1 ] && [ "$(cat "$tmp/out-keep/sha256.txt")" = keep ]; then ok "truncated_input_keeps_existing_output"; else bad "truncated_input_keeps_existing_output"; fi

# gate_refuses_hash_from_import
for t in sbsign sbattach sbverify; do
	command -v "$t" >/dev/null || {
		if [ "${MASTERSOS_PUBLISH_TEST_REQUIRE:-}" = 1 ]; then
			bad "gate_refuses_hash_from_import（缺 ${t}；MASTERSOS_PUBLISH_TEST_REQUIRE=1 不许跳过）"
			exit 1
		fi
		echo "skip gate_refuses_hash_from_import（缺 ${t}；在 Linux / CI 上跑）"
		exit $fail
	}
done
efi=/usr/lib/systemd/boot/efi/systemd-bootx64.efi
if [ ! -f "$efi" ]; then
	if [ "${MASTERSOS_PUBLISH_TEST_REQUIRE:-}" = 1 ]; then bad "gate_refuses_hash_from_import（缺 ${efi}）"; exit 1; fi
	echo "skip gate_refuses_hash_from_import（缺 ${efi}；装 systemd-boot-efi）"
	exit $fail
fi
sbsign --key "$tmp/ca.key" --cert "$tmp/ca.crt" --output "$tmp/shim.efi" "$efi" 2>/dev/null
# shellcheck source-path=SCRIPTDIR source=../keyset.sh
. "$img/keyset.sh"
cp "$tmp/shim.efi" "$tmp/x.efi"
sbattach --detach "$tmp/sig.p7" "$tmp/x.efi" >/dev/null 2>&1
digest=$(_ks_digest "$tmp/sig.p7")
[ ${#digest} = 64 ] || { bad "gate_refuses_hash_from_import：取不到签名里的映像摘要"; exit 1; }
# 先确认不带 dbx 时是 0（链得上），免得 3 与别的返回值混淆
rc=0
keyset_shim_chains "$tmp/shim.efi" "$tmp/ca.der" || rc=$?
[ "$rc" = 0 ] || { bad "gate_refuses_hash_from_import：前提不成立，不带 dbx 应返回 0，得到 ${rc}"; exit 1; }
python3 -I "$tmp/build.py" "$tmp/in/with-hash.bin" --hash "$digest" --cert "$tmp/rev.der"
imp "$tmp/in/with-hash.bin" "$tmp/out-gate" >/dev/null
rc=0
MASTERSOS_TEST=1 MASTERSOS_DBX_DIR="$tmp/out-gate" keyset_shim_chains "$tmp/shim.efi" "$tmp/ca.der" "$tmp/out-gate" || rc=$?
if [ "$rc" = 3 ]; then ok "gate_refuses_hash_from_import"; else bad "gate_refuses_hash_from_import（返回 ${rc}，应是 3）"; fi
# 同一份不含这个哈希的导入结果放行
rc=0
keyset_shim_chains "$tmp/shim.efi" "$tmp/ca.der" "$tmp/out" || rc=$?
if [ "$rc" = 0 ]; then ok "gate_passes_without_hash"; else bad "gate_passes_without_hash（返回 ${rc}，应是 0）"; fi
exit $fail
