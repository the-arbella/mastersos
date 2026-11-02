#!/bin/bash
# 正式私钥只从 tmpfs 读（keyset.sh 的 keyset_priv release，计划 5 Task 4）与 key-leak-check.py 的测试，不要 root：
#   bash image/tests/keyset-test.sh
# 钥匙都是现生成的一次性测试钥匙，放在 /var/tmp 的临时目录（不在 tmpfs 上，测「不在 tmpfs 上就拒绝」），跑完删掉。
# 要 GNU stat、python3、openssl、gpg：没有的机器（macOS）跳过。
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
img=$(cd "$here/.." && pwd)
skip() {
	echo "keyset-test: skip（$*）"
	exit 0
}
stat -c %u / >/dev/null 2>&1 || skip "没有 GNU stat；在 Linux / CI 上跑"
for t in python3 openssl gpg gpgconf; do
	command -v "$t" >/dev/null || skip "缺少 ${t}"
done
# shellcheck source-path=SCRIPTDIR source=../keyset.sh
. "$img/keyset.sh"

tmp=$(mktemp -d -p /var/tmp keyset-test.XXXXXX)
trap 'gpgconf --homedir "$tmp/rel/gpg" --kill all >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT
case "$(stat -f -c %T "$tmp")" in tmpfs | ramfs)
	echo "keyset-test: FAIL（/var/tmp 在 tmpfs 上，测不了「不在 tmpfs 上就拒绝」）" >&2
	exit 1
	;;
esac
fails=0 n=0
pass() {
	n=$((n + 1))
	echo "ok   $1"
}
fail() {
	n=$((n + 1))
	fails=$((fails + 1))
	echo "FAIL $1" >&2
	[ -z "${2:-}" ] || printf '%s\n' "$2" | sed 's/^/    /' >&2
}

# 一套测试用的「正式」私钥：db/pcr 与考试扩展的 kiosk-ext.pem 是 RSA 2048，gpg 是无口令的 ed25519（参数从 stdin 给，不经命令行）
gen_keys() { # <目录>
	mkdir -m 0700 "$1" "$1/gpg"
	openssl req -new -x509 -newkey rsa:2048 -nodes -days 30 -sha256 -subj "/CN=keyset-test db/" \
		-keyout "$1/db.key" -out "$1/db.crt" 2>/dev/null
	openssl req -new -x509 -newkey rsa:2048 -nodes -days 30 -sha256 -subj "/CN=keyset-test pcr/" \
		-keyout "$1/pcr.key" -out "$1/pcr.crt" 2>/dev/null
	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1/kiosk-ext.pem" 2>/dev/null
	printf '%%no-protection\nKey-Type: eddsa\nKey-Curve: ed25519\nKey-Usage: sign\nName-Real: keyset-test\nExpire-Date: 0\n%%commit\n' |
		gpg --homedir "$1/gpg" --batch --generate-key 2>/dev/null
	gpgconf --homedir "$1/gpg" --kill all >/dev/null 2>&1 || true
}
gen_keys "$tmp/rel"

# priv <期望 rc> <名字> <stderr 里应有的片段，空表示不查> [env 赋值…]：在子 shell 里跑 keyset_priv release
priv() {
	local want=$1 name=$2 frag=$3 out err rc=0
	shift 3
	# shellcheck disable=SC2016 # $1 是给子 shell 的
	out=$(env -u MASTERSOS_TEST -u MASTERSOS_TEST_SWAP -u MASTERSOS_RELEASE_KEYS "$@" bash -c '. "$1"; keyset_priv release' _ "$img/keyset.sh" 2>"$tmp/err") || rc=$?
	err=$(cat "$tmp/err")
	if [ "$rc" = "$want" ] && { [ -z "$frag" ] || grep -qF -- "$frag" <<<"$err"; }; then
		pass "$name（rc=${rc}）"
		PRIV_OUT=$out
	else
		fail "$name：期望 rc=${want}、stderr 含「${frag}」，实际 rc=${rc}" "$out"$'\n'"$err"
		PRIV_OUT=""
	fi
}

# release_keys_refused_off_tmpfs：不带 MASTERSOS_TEST，目录在 /var/tmp（磁盘）上 → 2，提示 keys-load.sh
priv 2 release_keys_refused_off_tmpfs keys-load.sh MASTERSOS_RELEASE_KEYS="$tmp/rel"
# 不带 MASTERSOS_TEST 时 MASTERSOS_RELEASE_KEYS 本身就不认（指向 tmpfs 也不行）
priv 2 release_keys_override_needs_test 只给测试用 MASTERSOS_RELEASE_KEYS="$tmp/rel"
# 文件系统一项本身（MASTERSOS_TEST_CHECK_FS 让 MASTERSOS_TEST=1 时也核对）：磁盘上 → 2；/dev/shm（tmpfs）上 → 0
priv 2 release_keys_refused_on_disk "不是 tmpfs" MASTERSOS_TEST=1 MASTERSOS_TEST_CHECK_FS=1 MASTERSOS_RELEASE_KEYS="$tmp/rel"
if [ "$(stat -f -c %T /dev/shm 2>/dev/null)" = tmpfs ]; then
	shm=$(mktemp -d -p /dev/shm keyset-test.XXXXXX)
	priv 0 release_keys_accepted_on_tmpfs "" MASTERSOS_TEST=1 MASTERSOS_TEST_CHECK_FS=1 MASTERSOS_RELEASE_KEYS="$shm"
	rmdir "$shm"
fi
# 默认目录不存在（这台机器没有载入过）→ 同样 2
if [ ! -e /run/mastersos-release-keys ]; then
	priv 2 release_keys_refused_default_missing keys-load.sh
fi
# release_keys_refused_with_swap：MASTERSOS_TEST=1 时 swap 一项看 MASTERSOS_TEST_SWAP
priv 2 release_keys_refused_with_swap swap MASTERSOS_TEST=1 MASTERSOS_TEST_SWAP=1 MASTERSOS_RELEASE_KEYS="$tmp/rel"
# release_keys_refused_wrong_mode：0755 → 2（MASTERSOS_TEST=1 也不放过）
chmod 0755 "$tmp/rel"
priv 2 release_keys_refused_wrong_mode 0700 MASTERSOS_TEST=1 MASTERSOS_RELEASE_KEYS="$tmp/rel"
chmod 0700 "$tmp/rel"
# 符号链接指过去也不行
ln -s "$tmp/rel" "$tmp/link"
priv 2 release_keys_refused_symlink keys-load.sh MASTERSOS_TEST=1 MASTERSOS_RELEASE_KEYS="$tmp/link"
# release_keys_test_override_warns：MASTERSOS_TEST=1 → 返回这个目录，stderr 有警告
priv 0 release_keys_test_override_warns 警告 MASTERSOS_TEST=1 MASTERSOS_RELEASE_KEYS="$tmp/rel"
if [ "$PRIV_OUT" = "$tmp/rel" ]; then pass "  返回的是 MASTERSOS_RELEASE_KEYS"; else fail "  返回了 '$PRIV_OUT'"; fi

# lab_keys_unchanged
v=$(MASTERSOS_KEYS=/x/keys keyset_priv lab)
if [ "$v" = /x/keys/lab ]; then pass "lab_keys_unchanged：keyset_priv lab = \$MASTERSOS_KEYS/lab"; else fail "lab_keys_unchanged：$v"; fi
v=$(MASTERSOS_KEYS=/x/keys keyset_lab_local)
if [ "$v" = /x/keys/lab-local ]; then pass "  keyset_lab_local = \$MASTERSOS_KEYS/lab-local"; else fail "  keyset_lab_local：$v"; fi
# shellcheck disable=SC2016
v=$(HOME=/h env -u MASTERSOS_KEYS bash -c '. "$1"; keyset_lab_local' _ "$img/keyset.sh")
if [ "$v" = /h/mastersos-keys/lab-local ]; then pass "  默认 ~/mastersos-keys/lab-local"; else fail "  默认：$v"; fi

# --- key-leak-check.py ---------------------------------------------------------------
# leak <期望 rc> <名字> <路径…>：输出里不许有十六进制或 base64 的片段（16 位以上的十六进制、24 位以上的 base64 字符）
leak() {
	local want=$1 name=$2 out rc=0
	shift 2
	out=$(python3 -I "$img/key-leak-check.py" "$tmp/rel" "$@" 2>&1) || rc=$?
	if [ "$rc" != "$want" ]; then
		fail "$name：期望 rc=${want}，实际 rc=${rc}" "$out"
	elif grep -qE '[0-9A-Fa-f]{16}|[A-Za-z0-9+/=]{24}' <<<"$out"; then
		fail "$name：输出里像是有钥匙片段"
	else
		pass "$name（rc=${rc}）"
		LEAK_OUT=$out
	fi
}
mkdir "$tmp/clean" "$tmp/dirty"
# 干净的目录：公开的证书、仓库式的公钥、另一把无关的 RSA 私钥、随机数据
cp "$tmp/rel/db.crt" "$tmp/rel/pcr.crt" "$tmp/clean/"
openssl x509 -in "$tmp/rel/db.crt" -outform DER -out "$tmp/clean/mastersos-mok.der"
openssl x509 -in "$tmp/rel/pcr.crt" -pubkey -noout >"$tmp/clean/tpm2-pcr-public-key.pem"
openssl rsa -in "$tmp/rel/db.key" -pubout -outform DER -out "$tmp/clean/db.pub.der" 2>/dev/null
openssl rsa -in "$tmp/rel/db.key" -RSAPublicKey_out -outform DER -out "$tmp/clean/db.pkcs1.der" 2>/dev/null
gpg --homedir "$tmp/rel/gpg" --export >"$tmp/clean/import-pubring.pgp" 2>/dev/null
gpg --homedir "$tmp/rel/gpg" --export --armor >"$tmp/clean/import-pubring.asc" 2>/dev/null
gpgconf --homedir "$tmp/rel/gpg" --kill all >/dev/null 2>&1 || true
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tmp/clean/other.key" 2>/dev/null
head -c 1048576 /dev/urandom >"$tmp/clean/random.bin"
leak 0 leak_check_clean_dir "$tmp/clean"
# leak_check_finds_copied_key：DER 嵌进 1 MiB 随机文件的中间
openssl pkey -in "$tmp/rel/db.key" -outform DER -out "$tmp/db.der"
{ head -c 524288 /dev/urandom; cat "$tmp/db.der"; head -c 524288 /dev/urandom; } >"$tmp/dirty/blob.bin"
leak 1 leak_check_finds_copied_key "$tmp/dirty"
if grep -qF "$tmp/dirty/blob.bin：db.key" <<<"${LEAK_OUT:-}"; then pass "  报出路径与 db.key"; else fail "  没报出 blob.bin：db.key" "${LEAK_OUT:-}"; fi
rm "$tmp/dirty/blob.bin"
# 跨 16 MiB 读块边界：只放 DER 的最后 64 字节（结尾那段片段在里面），边界在倒数第 16 字节处
{ head -c $((16777216 - 48)) /dev/zero; tail -c 64 "$tmp/db.der"; } >"$tmp/dirty/big.bin"
leak 1 leak_check_finds_key_across_chunk "$tmp/dirty"
rm "$tmp/dirty/big.bin"
# PKCS#1 形式的 DER（openssl rsa -traditional）也找得到
openssl rsa -in "$tmp/rel/pcr.key" -traditional -outform DER -out "$tmp/dirty/pcr.pkcs1" 2>/dev/null
leak 1 leak_check_finds_pkcs1_der "$tmp/dirty"
if grep -qF "pcr.pkcs1：pcr.key" <<<"${LEAK_OUT:-}"; then pass "  报的是 pcr.key"; else fail "  没报 pcr.key" "${LEAK_OUT:-}"; fi
rm "$tmp/dirty/pcr.pkcs1"
# PEM 原样拷进日志里
{ echo "some log line"; cat "$tmp/rel/pcr.key"; echo "more"; } >"$tmp/dirty/build.log"
leak 1 leak_check_finds_pem_text "$tmp/dirty"
rm "$tmp/dirty/build.log"
# 重新编码成 PKCS#1 的 PEM（传统的 RSA 头，d 的起点模 3 与 PKCS#8 不同）
openssl rsa -in "$tmp/rel/db.key" -traditional -out "$tmp/dirty/db.pkcs1.pem" 2>/dev/null
leak 1 leak_check_finds_pkcs1_pem "$tmp/dirty"
rm "$tmp/dirty/db.pkcs1.pem"
# 同一份 DER 按 76 列重新折行（base64 默认），不带 PEM 头
base64 -w 76 "$tmp/db.der" >"$tmp/dirty/db.b64"
leak 1 leak_check_finds_rewrapped_76 "$tmp/dirty"
rm "$tmp/dirty/db.b64"
# 不折行（一整行），嵌在 JSON 里
printf '{"k":"%s"}\n' "$(base64 -w 0 "$tmp/db.der")" >"$tmp/dirty/db.json"
leak 1 leak_check_finds_unwrapped "$tmp/dirty"
rm "$tmp/dirty/db.json"
# 考试扩展的钥匙（计划 9 Task 10，正式的随仪式进 U 盘）：PKCS#8 PEM 拷走、导出的公钥不误报
cp "$tmp/rel/kiosk-ext.pem" "$tmp/dirty/ext.pem"
leak 1 leak_check_finds_kiosk_ext_key "$tmp/dirty"
if grep -qF "ext.pem：kiosk-ext.pem" <<<"${LEAK_OUT:-}"; then pass "  报的是 kiosk-ext.pem"; else fail "  没报 kiosk-ext.pem" "${LEAK_OUT:-}"; fi
rm "$tmp/dirty/ext.pem"
openssl pkey -in "$tmp/rel/kiosk-ext.pem" -pubout -out "$tmp/dirty/kiosk-ext-public.pem"
leak 0 leak_check_kiosk_ext_public_clean "$tmp/dirty"
rm "$tmp/dirty/kiosk-ext-public.pem"
# 读不了的文件（非 root 时）：没找到也不算干净 → 3
if [ "$(id -u)" != 0 ]; then
	head -c 100 /dev/urandom >"$tmp/clean/locked"
	chmod 000 "$tmp/clean/locked"
	leak 3 leak_check_unreadable_not_clean "$tmp/clean"
	rm -f "$tmp/clean/locked"
fi
# gpg 私钥文件拷走
cp "$tmp/rel/gpg/private-keys-v1.d/"*.key "$tmp/dirty/copy.key"
leak 1 leak_check_finds_gpg_key "$tmp/dirty"
if grep -qF "copy.key：gpg 私钥 " <<<"${LEAK_OUT:-}"; then pass "  报的是 gpg 私钥"; else fail "  没报 gpg 私钥" "${LEAK_OUT:-}"; fi
rm "$tmp/dirty/copy.key"
# gpg 导出的私钥（OpenPGP 包，d 的原始字节在里面）
gpg --homedir "$tmp/rel/gpg" --batch --pinentry-mode loopback --export-secret-keys >"$tmp/dirty/secret.pgp" 2>/dev/null
gpgconf --homedir "$tmp/rel/gpg" --kill all >/dev/null 2>&1 || true
leak 1 leak_check_finds_gpg_export "$tmp/dirty"
rm "$tmp/dirty/secret.pgp"
# 符号链接不跟随
ln -s "$tmp/rel/db.key" "$tmp/dirty/db.key.link"
leak 0 leak_check_ignores_symlink "$tmp/dirty"
rm "$tmp/dirty/db.key.link"
# 扫的路径包住了钥匙目录本身：跳过钥匙目录
leak 0 leak_check_skips_key_dir "$tmp/rel" "$tmp/clean"
# 钥匙目录不对 → 2
rc=0
python3 -I "$img/key-leak-check.py" "$tmp/clean" "$tmp/clean" >/dev/null 2>&1 || rc=$?
if [ "$rc" = 2 ]; then pass "leak_check_bad_key_dir（rc=2）"; else fail "leak_check_bad_key_dir：rc=$rc"; fi

echo "keyset-test: $((n - fails))/$n 通过"
[ "$fails" = 0 ]
