#!/bin/bash
# 正式钥匙仪式与签名会话的端到端测试（计划 5 Task 4）。要 root 与 loop 设备，不在 CI 跑（CI 只 shellcheck 它）：
#   sudo bash image/tests/ceremony-test.sh
# 用两个 64 MiB 的 loop 文件当 U 盘 A、B（write-stick 的 USB 检查由 MASTERSOS_TEST=1 放过），钥匙全是现生成的一次性测试钥匙：
# generate → write-stick A、B（口令经 stdin）→ export-public → seal 与 keys-load.sh --age（age 的口令经 pty）→ keys-load.sh 的核对函数与整个 keys-load.sh（--verify-only、
# 正常载入 + keys-unload.sh、公钥不符、--no-repo-check）对两根重新打开的盘 → wipe 之后 tmpfs 目录不在了、key-leak-check.py
# 扫 /tmp、/var/tmp 与测试目录都干净（loop 文件就是「U 盘」：上面没有明文）。db.crt 有效期 ≥ 7300 天、CN 对。
# 考试扩展的钥匙（计划 9 Task 10）：kiosk-ext.pem 是 RSA 2048、0600，FINGERPRINTS.txt 的 kiosk-ext-id 是它算出的 id，
# kiosk-ext-pack.sh 用它打包打印的是同一个 id（build.sh 取的就是这个文件名），export-public 的 kiosk-ext-public.pem 与它一对，
# kl_repo_check 对换了或缺了 kiosk-ext-public.pem 的公钥目录拒绝，key-leak-check.py 找得到拷走的 kiosk-ext.pem。
# 跑完卸载、关闭、删掉 loop 设备与临时文件。注意：盘的标签就是正式的 MASTERSOS-KEYS-A / -B，别在插着真 U 盘的机器上跑。
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
img=$(cd "$here/.." && pwd)
gen=$img/ceremony/gen-release-keys.sh
[ "$(id -u)" = 0 ] || {
	echo "ceremony-test: 要 root（sudo bash $0）" >&2
	exit 1
}
for t in losetup cryptsetup mkfs.ext4 udevadm openssl gpg python3 shred lsblk age; do
	command -v "$t" >/dev/null || {
		echo "ceremony-test: 缺少 $t" >&2
		exit 1
	}
done
for l in MASTERSOS-KEYS-A MASTERSOS-KEYS-B; do
	[ ! -e "/dev/disk/by-label/$l" ] || {
		echo "ceremony-test: 这台机器上已经有 $l 的盘，不跑" >&2
		exit 1
	}
done

work=$(mktemp -d -p /var/tmp ceremony-test.XXXXXX)
loops=()
cleanup() {
	set +e
	for m in mastersos-keys-A mastersos-keys-B mastersos-ceremony-A mastersos-ceremony-B; do
		[ -e "/dev/mapper/$m" ] && { umount "/dev/mapper/$m" 2>/dev/null; cryptsetup close "$m"; }
	done
	for d in "$work"/mnt*; do mountpoint -q "$d" 2>/dev/null && umount "$d"; done
	for l in "${loops[@]}"; do losetup -d "$l"; done
	for d in "$work/tmpfs" "$work/ref"; do
		if mountpoint -q "$d"; then
			find "$d" -type d -name gpg -exec gpgconf --homedir {} --kill all \; 2>/dev/null
			find "$d" -type f -exec shred -u {} + 2>/dev/null
			umount "$d"
		fi
	done
	rm -rf "$work"
}
trap cleanup EXIT

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
# run <期望 rc> <名字> <输出里应有的片段，空表示不查> <命令…>：stdin 照传
run() {
	local want=$1 name=$2 frag=$3 out rc=0
	shift 3
	out=$("$@" 2>&1) || rc=$?
	if grep -qF -- "$P" <<<"$out"; then
		fail "$name：输出里出现了口令"
	elif [ "$rc" = "$want" ] && { [ -z "$frag" ] || grep -qF -- "$frag" <<<"$out"; }; then
		pass "$name（rc=${rc}）"
	else
		fail "$name：期望 rc=${want}、输出含「${frag}」，实际 rc=${rc}" "$out"
	fi
}

# 测试口令：7 个词。只在环境变量与管道里（给子进程的 printf），不打印、不进命令行参数
export P='ceremony test only seven words right here'
PASS=$P
# fed <stdin 的模板，%P 处填口令> <命令…>
fed() {
	local tpl=$1
	shift
	bash -c 'printf "${1//%P/$P}" | "${@:2}"' _ "$tpl" "$@"
}
# agefed <命令…>：在 pty 里跑，age 每问一次口令就答一次（age 只从终端读口令）。默认都答 $P；AGE_ANSWERS 按换行分隔逐次给，
# 用完了重复最后一个。输出照转，里面的口令换成 <PW>（run 再查一遍口令没漏出来）
agefed() {
	python3 -I -c '
import os, pty, select, sys
p = os.environ["P"]
ans = os.environ.get("AGE_ANSWERS", p).split("\n")
pid, fd = pty.fork()
if pid == 0:
    os.execvp(sys.argv[1], sys.argv[1:])
buf, n = b"", 0
while True:
    try:
        if not select.select([fd], [], [], 300)[0]:
            break
        d = os.read(fd, 4096)
    except OSError:
        break
    if not d:
        break
    buf += d
    sys.stdout.buffer.write(d)
    sys.stdout.flush()
    while n < buf.count(b"assphrase:") + buf.count(b"assphrase (leave empty"):
        os.write(fd, ans[min(n, len(ans) - 1)].encode() + b"\n")
        n += 1
sys.exit(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]))
' "$@"
}
# agefed_with <逐次的回答，换行分隔> <命令…>
agefed_with() { AGE_ANSWERS=$1 agefed "${@:2}"; }
mkdir -m 0700 "$work/tmpfs" "$work/ref" "$work/disk"
mount -t tmpfs -o size=64m,mode=0700,nodev,nosuid tmpfs "$work/tmpfs"
mount -t tmpfs -o size=16m,mode=0700,nodev,nosuid tmpfs "$work/ref"
for s in A B; do
	truncate -s 64M "$work/stick-$s.img"
	loops+=("$(losetup -f --show "$work/stick-$s.img")")
done
devA=${loops[0]} devB=${loops[1]}
k=$work/tmpfs/k

# --- generate --------------------------------------------------------------------------
# swap：不带 MASTERSOS_TEST 时看真的 swapon（这台机器有 swap 才测得到）；MASTERSOS_TEST=1 时看 MASTERSOS_TEST_SWAP
if [ -n "$(swapon --show --noheadings 2>/dev/null)" ]; then
	run 1 "generate：这台机器有 swap → 拒绝" "swap" env -u MASTERSOS_TEST "$gen" generate "$k"
fi
export MASTERSOS_TEST=1 # 下面的 swap 一项改看 MASTERSOS_TEST_SWAP（开发机有 swap）、write-stick 放过 loop 设备
run 1 "generate：MASTERSOS_TEST_SWAP → 拒绝" "swap" env MASTERSOS_TEST_SWAP=1 "$gen" generate "$k"
if [ ! -e "$k" ]; then pass "  什么都没生成"; else fail "  $k 被建了"; fi
run 1 "generate 拒绝不在 tmpfs 上的目录" "tmpfs" "$gen" generate "$work/disk/k"
run 0 "generate" "gpg-fingerprint" "$gen" generate "$k"
run 1 "generate 拒绝已有东西的目录" "已经有东西" "$gen" generate "$k"
r=$k/mastersos-release-keys
subj=$(openssl x509 -in "$r/db.crt" -noout -subject -nameopt RFC2253)
if [ "$subj" = "subject=CN=MastersOS Secure Boot 2026" ]; then pass "db.crt 的 CN 是 MastersOS Secure Boot 2026"; else fail "db.crt 的 subject：$subj"; fi
subj=$(openssl x509 -in "$r/pcr.crt" -noout -subject -nameopt RFC2253)
if [ "$subj" = "subject=CN=MastersOS PCR 2026" ]; then pass "pcr.crt 的 CN 是 MastersOS PCR 2026"; else fail "pcr.crt 的 subject：$subj"; fi
days() {
	local s e
	s=$(date -d "$(openssl x509 -in "$1" -noout -startdate | cut -d= -f2)" +%s)
	e=$(date -d "$(openssl x509 -in "$1" -noout -enddate | cut -d= -f2)" +%s)
	echo $(((e - s) / 86400))
}
for c in db pcr; do
	d=$(days "$r/$c.crt")
	if [ "$d" -ge 7300 ]; then pass "$c.crt 有效期 $d 天（≥ 7300）"; else fail "$c.crt 有效期只有 $d 天"; fi
	bits=$(openssl pkey -in "$r/$c.key" -noout -text 2>/dev/null | sed -n 's/.*Private-Key: (\([0-9]*\) bit.*/\1/p')
	if [ "$bits" = 2048 ]; then pass "$c.key 是 RSA 2048"; else fail "$c.key：${bits:-?} 位"; fi
done
uid=$(gpg --homedir "$r/gpg" --batch --with-colons --list-secret-keys 2>/dev/null | awk -F: '$1 == "uid" {print $10}')
caps=$(gpg --homedir "$r/gpg" --batch --with-colons --list-secret-keys 2>/dev/null | awk -F: '$1 == "sec" {print $4 ":" $7 ":" $12 ":" $17}')
gpgconf --homedir "$r/gpg" --kill all >/dev/null 2>&1 || true
if [ "$uid" = "MastersOS updates 2026" ]; then pass "gpg 的 uid 是 MastersOS updates 2026"; else fail "gpg 的 uid：$uid"; fi
# 22 = EdDSA，到期日为空，能力只有 s（加主钥的 c），曲线 ed25519
if [[ $caps =~ ^22::[scSC]+:ed25519$ ]]; then pass "gpg 是 ed25519、只签名、不过期（$caps）"; else fail "gpg 主钥：$caps"; fi
if grep -q '^Key: (private-key ' "$r/gpg/private-keys-v1.d/"*.key; then pass "gpg 私钥不带口令（LUKS 是那一层）"; else fail "gpg 私钥带了口令"; fi
if [ "$(wc -l <"$k/FINGERPRINTS.txt")" = 4 ]; then pass "FINGERPRINTS.txt 四行"; else fail "FINGERPRINTS.txt：$(cat "$k/FINGERPRINTS.txt")"; fi
pkfp=$(openssl x509 -in "$r/pcr.crt" -pubkey -noout | openssl rsa -pubin -RSAPublicKey_out -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)
if grep -qx "pcr-pkfp $pkfp" "$k/FINGERPRINTS.txt"; then pass "  pcr-pkfp 是 PKCS#1 DER 的 sha256"; else fail "  pcr-pkfp 不对"; fi
if stat -c %a "$r/db.key" "$r/pcr.key" "$r/kiosk-ext.pem" | grep -qvx 600; then fail "私钥文件不是 0600"; else pass "私钥文件 0600"; fi
# 考试扩展的钥匙：RSA 2048、不加密的 PEM；id = sha256(SPKI DER) 前 16 字节、0–f → a–p
bits=$(openssl pkey -in "$r/kiosk-ext.pem" -passin pass: -noout -text 2>/dev/null | sed -n 's/.*Private-Key: (\([0-9]*\) bit.*/\1/p')
if [ "$bits" = 2048 ]; then pass "kiosk-ext.pem 是不加密的 RSA 2048"; else fail "kiosk-ext.pem：${bits:-?} 位（或加了口令）"; fi
ext_id=$(openssl pkey -in "$r/kiosk-ext.pem" -pubout -outform DER 2>/dev/null | sha256sum | cut -c1-32 | tr 0-9a-f a-p)
if [[ $ext_id =~ ^[a-p]{32}$ ]] && grep -qx "kiosk-ext-id $ext_id" "$k/FINGERPRINTS.txt"; then
	pass "  kiosk-ext-id 是公钥算出的扩展 id"
else
	fail "  kiosk-ext-id 不对（算出 ${ext_id:-?}）" "$(cat "$k/FINGERPRINTS.txt")"
fi
# build.sh 的正式构建取 <私钥目录>/kiosk-ext.pem 交给 kiosk-ext-pack.sh：仪式生成的这把它收、打出的 id 与 FINGERPRINTS.txt 相同
if [ -f "$img/../kiosk-extension/manifest.json" ]; then
	got=$("$img/kiosk-ext-pack.sh" "$r/kiosk-ext.pem" "$work/pack" https://os.example.org/chrome 2>&1) || got="失败：$got"
	if [ "$got" = "$ext_id" ]; then pass "  kiosk-ext-pack.sh 收这把钥匙、打印同一个 id"; else fail "  kiosk-ext-pack.sh：$got"; fi
fi

# --- write-stick -----------------------------------------------------------------------
run 1 "write-stick 不带 MASTERSOS_TEST 拒绝 loop 设备" "usb 1" fed 'YES\n%P\n%P\n' env -u MASTERSOS_TEST "$gen" write-stick "$k" "$devA" A
run 1 "write-stick：MASTERSOS_TEST_SWAP → 拒绝" "swap" fed 'YES\n%P\n%P\n' env MASTERSOS_TEST_SWAP=1 "$gen" write-stick "$k" "$devA" A
run 1 "write-stick 没输入 YES 什么都不做" "没有输入 YES" fed 'yes\n%P\n%P\n' "$gen" write-stick "$k" "$devA" A
run 1 "write-stick 两次口令不一样" "两次口令不一样" fed 'YES\n%P\n%P x\n' "$gen" write-stick "$k" "$devA" A
run 1 "write-stick 口令是空的" "passphrase is empty" fed 'YES\n\n\n' "$gen" write-stick "$k" "$devA" A
if [ -z "$(blkid -p -o value -s TYPE "$devA" 2>/dev/null)" ]; then pass "  被拒绝的几次都没碰盘"; else fail "  盘被写了"; fi
for s in A B; do
	dev=$devA
	[ "$s" = B ] && dev=$devB
	run 0 "write-stick $s" "重新打开核对过了" fed 'YES\n%P\n%P\n' "$gen" write-stick "$k" "$dev" "$s"
	lbl=$(blkid -p -o value -s LABEL "$dev" 2>/dev/null || true)
	typ=$(blkid -p -o value -s TYPE "$dev" 2>/dev/null || true)
	if [ "$typ $lbl" = "crypto_LUKS MASTERSOS-KEYS-$s" ]; then pass "  $s 是 LUKS，标签 MASTERSOS-KEYS-$s"; else fail "  $s：$typ $lbl"; fi
	if cryptsetup luksDump "$dev" | grep -q 'PBKDF:[[:space:]]*argon2id'; then pass "  $s 的 PBKDF 是 argon2id"; else fail "  $s 不是 argon2id"; fi
	if cryptsetup luksDump "$dev" | grep -q '^Version:[[:space:]]*2'; then pass "  $s 是 LUKS2"; else fail "  $s 不是 LUKS2"; fi
done

# --- export-public ---------------------------------------------------------------------
pub=$work/pub
run 0 "export-public" "公钥写到" "$gen" export-public "$k" "$pub"
for f in mastersos-mok.der tpm2-pcr-public-key.pem import-pubring.pgp kiosk-ext-public.pem FINGERPRINTS.txt; do
	[ -s "$pub/$f" ] || fail "export-public 没写 $f"
done
if openssl x509 -inform DER -in "$pub/mastersos-mok.der" -noout 2>/dev/null; then pass "  mastersos-mok.der 是 DER 证书"; else fail "  mastersos-mok.der"; fi
if head -1 "$pub/tpm2-pcr-public-key.pem" | grep -qx -- '-----BEGIN PUBLIC KEY-----'; then pass "  tpm2-pcr-public-key.pem 是 PEM 公钥"; else fail "  pem"; fi
case "$(head -c1 "$pub/import-pubring.pgp" | od -An -tx1 | tr -d ' \n')" in 98 | 99 | c6) pass "  import-pubring.pgp 是二进制 keyring" ;; *) fail "  import-pubring.pgp 不是二进制" ;; esac
if head -1 "$pub/kiosk-ext-public.pem" | grep -qx -- '-----BEGIN PUBLIC KEY-----' &&
	[ "$(openssl pkey -pubin -in "$pub/kiosk-ext-public.pem" -outform DER 2>/dev/null | sha256sum | cut -c1-32 | tr 0-9a-f a-p)" = "$ext_id" ]; then
	pass "  kiosk-ext-public.pem 是 PEM 公钥、算出的 id 与 FINGERPRINTS.txt 相同"
else
	fail "  kiosk-ext-public.pem"
fi
# 两份坏的公钥目录：kiosk-ext-public.pem 换成另一把、或缺了
mkdir "$work/pub-other" "$work/pub-noext"
cp "$pub"/* "$work/pub-other/"
cp "$pub"/* "$work/pub-noext/"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null | openssl pkey -pubout -out "$work/pub-other/kiosk-ext-public.pem"
rm "$work/pub-noext/kiosk-ext-public.pem"

# 留一份钥匙在另一个 tmpfs，wipe 之后给 key-leak-check.py 当参照
cp -a "$r" "$work/ref/"
ref=$work/ref/mastersos-release-keys

# --- keys-load.sh 的核对函数：分别对两根重新打开（只读）的盘 ------------------------------------
udevadm settle
# shellcheck source-path=SCRIPTDIR source=../keys-load.sh
. "$img/keys-load.sh"
for s in A B; do
	dev=$(readlink -f "/dev/disk/by-label/MASTERSOS-KEYS-$s" 2>/dev/null || true)
	if [ -b "$dev" ]; then pass "/dev/disk/by-label/MASTERSOS-KEYS-$s 在"; else fail "没有 /dev/disk/by-label/MASTERSOS-KEYS-$s"; continue; fi
	printf '%s' "$PASS" | cryptsetup open --readonly --type luks2 --key-file=- "$dev" "mastersos-keys-$s"
	mkdir -p "$work/mnt$s"
	mount -o ro,nodev,nosuid,noexec "/dev/mapper/mastersos-keys-$s" "$work/mnt$s"
	run 0 "kl_check_stick $s" "" kl_check_stick "$work/mnt$s"
	mkdir -m 0700 "$work/tmpfs/load$s"
	run 0 "kl_copy $s" "" kl_copy "$work/mnt$s" "$work/tmpfs/load$s"
	run 0 "kl_repo_check $s（导出的公钥）" "" kl_repo_check "$work/tmpfs/load$s" "$pub"
	run 1 "kl_repo_check $s 对 keys/lab/ 的公钥 → 不符" "不等于" kl_repo_check "$work/tmpfs/load$s" "$img/keys/lab"
	run 1 "kl_repo_check $s：kiosk-ext-public.pem 是另一把 → 不符" "kiosk-ext.pem 的公钥不等于" kl_repo_check "$work/tmpfs/load$s" "$work/pub-other"
	run 1 "kl_repo_check $s：仓库没有 kiosk-ext-public.pem → 拒绝" "缺少" kl_repo_check "$work/tmpfs/load$s" "$work/pub-noext"
	if [ -f "$work/tmpfs/load$s/kiosk-ext.pem" ]; then pass "  kiosk-ext.pem 随清单拷出来了（build.sh 取的名字）"; else fail "  没拷出 kiosk-ext.pem"; fi
	m=$(find "$work/tmpfs/load$s" -type f ! -perm 0600 | wc -l)
	d=$(find "$work/tmpfs/load$s" -type d ! -perm 0700 | wc -l)
	if [ "$m$d" = 00 ]; then pass "  拷出来的文件 0600、目录 0700"; else fail "  权限不对（$m 个文件、$d 个目录）"; fi
	umount "$work/mnt$s"
	cryptsetup close "mastersos-keys-$s"
	MASTERSOS_RELEASE_KEYS=$work/tmpfs/load$s "$img/keys-unload.sh" >/dev/null
done
# 清单被改过、或多了文件 → kl_check_stick 拒绝（在 tmpfs 里的一份可写的拷贝上测）
cp -a "$k" "$work/tmpfs/bad"
printf 'x' >>"$work/tmpfs/bad/mastersos-release-keys/db.crt"
run 1 "kl_check_stick：文件被改过" "核对不过" kl_check_stick "$work/tmpfs/bad"
rm -rf "$work/tmpfs/bad"
cp -a "$k" "$work/tmpfs/bad"
touch "$work/tmpfs/bad/mastersos-release-keys/gpg/extra"
run 1 "kl_check_stick：多了文件" "不一致" kl_check_stick "$work/tmpfs/bad"
find "$work/tmpfs/bad" -type f -exec shred -u {} +
rm -rf "$work/tmpfs/bad"

# --- 整个 keys-load.sh / keys-unload.sh（口令经 stdin 给 cryptsetup）---------------------------
export MASTERSOS_RELEASE_KEYS=$work/tmpfs/session MASTERSOS_PUB_DIR=$pub
kl() { fed '%P\n' "$img/keys-load.sh" "$@"; }
run 2 "keys-load.sh --no-repo-check 不带 --verify-only" "只许与 --verify-only" kl A --no-repo-check
run 1 "keys-load.sh 有 swap 就不载入" "swap" env MASTERSOS_TEST_SWAP=1 "$img/keys-load.sh" A </dev/null
run 2 "keys-load.sh 的测试变量不带 MASTERSOS_TEST=1" "只给测试用" env -u MASTERSOS_TEST "$img/keys-load.sh" A
for s in A B; do
	run 0 "keys-load.sh $s --verify-only" "核对通过" kl "$s" --verify-only
	if [ ! -e "$MASTERSOS_RELEASE_KEYS" ]; then pass "  副本已抹掉"; else fail "  $MASTERSOS_RELEASE_KEYS 还在"; fi
	if [ ! -e "/dev/mapper/mastersos-keys-$s" ]; then pass "  LUKS 已关闭"; else fail "  /dev/mapper/mastersos-keys-$s 还开着"; fi
done
run 0 "keys-load.sh B（签名会话）" "已在" kl B
v=$(bash -c '. "$1"; keyset_priv release' _ "$img/keyset.sh" 2>/dev/null || true)
if [ "$v" = "$MASTERSOS_RELEASE_KEYS" ]; then pass "  keyset_priv release 认它"; else fail "  keyset_priv release：$v"; fi
run 1 "keys-load.sh 已载入时再载入 → 拒绝" "已经在了" kl A
run 0 "keys-unload.sh" "已抹掉" "$img/keys-unload.sh"
if [ ! -e "$MASTERSOS_RELEASE_KEYS" ]; then pass "  目录不在了"; else fail "  目录还在"; fi
run 0 "keys-unload.sh 重复跑" "没有要抹的" "$img/keys-unload.sh"
run 1 "keys-load.sh 仓库公钥不符" "对不上" fed '%P\n' env MASTERSOS_PUB_DIR="$img/keys/lab" "$img/keys-load.sh" A
if [ ! -e "$MASTERSOS_RELEASE_KEYS" ]; then pass "  不符时副本已抹掉"; else fail "  不符时副本还在"; fi
run 0 "keys-load.sh --verify-only --no-repo-check（预发布公钥还在仓库时）" "gpg-fingerprint" \
	fed '%P\n' env MASTERSOS_PUB_DIR="$img/keys/lab" "$img/keys-load.sh" A --verify-only --no-repo-check
if [ ! -e "$MASTERSOS_RELEASE_KEYS" ]; then pass "  副本已抹掉"; else fail "  副本还在"; fi
run 1 "keys-load.sh 口令错" "cryptsetup open 失败" fed 'wrong\n' "$img/keys-load.sh" A
gone() { # <名字>：载入目录不在、LUKS 关了、没挂着
	if [ ! -e "$MASTERSOS_RELEASE_KEYS" ] && [ ! -e /dev/mapper/mastersos-keys-A ] && ! findmnt -rn -S /dev/mapper/mastersos-keys-A >/dev/null 2>&1; then
		pass "  $1：副本已抹掉、LUKS 已关闭"
	else
		fail "  $1：还有残留（$(find "$MASTERSOS_RELEASE_KEYS" /dev/mapper/mastersos-keys-A -maxdepth 0 2>/dev/null | tr '\n' ' ')）"
	fi
}
# 核对仓库公钥时意外失败（set -e 退出，不经 kl_die）：EXIT 的清理照样抹掉
run 1 "keys-load.sh 核对公钥时意外失败" "已抹掉" fed '%P\n' env MASTERSOS_TEST_FAIL_AT=repo-check "$img/keys-load.sh" A
gone "意外失败"
run 1 "keys-load.sh --verify-only 核对时意外失败" "已抹掉" fed '%P\n' env MASTERSOS_TEST_FAIL_AT=repo-check "$img/keys-load.sh" A --verify-only
gone "verify-only 意外失败"
# 载入到一半收到 SIGINT / SIGTERM（job control 下后台进程不忽略 SIGINT）：退出 130，副本抹掉
printf '%s\n' "$P" >"$work/tmpfs/pw"
for sig in INT TERM; do
	rm -f "$work/tmpfs/paused"
	set -m
	MASTERSOS_TEST_PAUSE_AT=repo-check MASTERSOS_TEST_PAUSE_FILE=$work/tmpfs/paused "$img/keys-load.sh" A <"$work/tmpfs/pw" >"$work/sig.log" 2>&1 &
	pid=$!
	set +m
	for ((i = 0; i < 300; i++)); do
		[ -e "$work/tmpfs/paused" ] && break
		sleep 0.1
	done
	if [ -e "$work/tmpfs/paused" ] && [ -d "$MASTERSOS_RELEASE_KEYS" ]; then pass "SIG$sig：停在核对公钥之前，钥匙已在 tmpfs"; else fail "SIG$sig：没停到那一步" "$(cat "$work/sig.log")"; fi
	kill -"$sig" "$pid"
	rc=0
	wait "$pid" || rc=$?
	if [ "$rc" = 130 ] && grep -qF "已抹掉" "$work/sig.log"; then pass "  SIG$sig → 退出 130、说副本已抹掉"; else fail "  SIG$sig：rc=$rc" "$(cat "$work/sig.log")"; fi
	if grep -qF -- "$P" "$work/sig.log"; then fail "  SIG$sig：输出里出现了口令"; fi
	gone "SIG$sig"
done
rm -f "$work/tmpfs/pw" "$work/tmpfs/paused" "$work/sig.log"

# --- seal 与 keys-load.sh --age（2026-10-27：钥匙用 age 加密放 S3，取代 U 盘）---------------------------
bundle=$work/keys.age
run 0 "seal" "sealed and checked" agefed "$gen" seal "$k" "$bundle"
if [ -s "$bundle" ] && [ ! -e "$bundle.part" ] && [ ! -e "$k.verify" ]; then pass "  写了 .age，没留 .part 与核对目录"; else fail "  seal 的产物不对"; fi
if head -c 64 "$bundle" | grep -q '^age-encryption.org/v1' && head -c 200 "$bundle" | grep -q 'scrypt'; then pass "  是 age 的 scrypt（口令）格式"; else fail "  不是 age scrypt"; fi
run 1 "seal 不覆盖已有的文件" "already exists" agefed "$gen" seal "$k" "$bundle"
run 1 "seal：核对时口令输错 → 不写" "does not match" agefed_with "$P"$'\n'"$P"$'\n'"wrong" "$gen" seal "$k" "$work/bad.age"
if [ ! -e "$work/bad.age" ] && [ ! -e "$work/bad.age.part" ] && [ ! -e "$k.verify" ]; then pass "  没写 .age、没留 .part 与核对目录"; else fail "  核对失败后有残留"; fi
run 1 "seal：MASTERSOS_TEST_SWAP → 拒绝" "swap" env MASTERSOS_TEST_SWAP=1 "$gen" seal "$k" "$work/swap.age"
ka() { agefed "$img/keys-load.sh" --age "$bundle" "$@"; }
shm_left() { find /dev/shm -maxdepth 1 -name 'mastersos-keys.*' | wc -l; }
run 2 "keys-load.sh 同时给 U 盘与 --age" "usage" "$img/keys-load.sh" A --age "$bundle"
run 0 "keys-load.sh --age --verify-only" "核对通过" ka --verify-only
if [ ! -e "$MASTERSOS_RELEASE_KEYS" ] && [ "$(shm_left)" = 0 ]; then pass "  副本与 /dev/shm 的解密目录都抹掉了"; else fail "  有残留"; fi
run 0 "keys-load.sh --age（签名会话）" "已在" ka
v=$(bash -c '. "$1"; keyset_priv release' _ "$img/keyset.sh" 2>/dev/null || true)
if [ "$v" = "$MASTERSOS_RELEASE_KEYS" ] && [ "$(shm_left)" = 0 ]; then pass "  keyset_priv release 认它，/dev/shm 已抹掉"; else fail "  keyset_priv：$v，/dev/shm 残留 $(shm_left)"; fi
if [ -f "$MASTERSOS_RELEASE_KEYS/kiosk-ext.pem" ] && [ -z "$(find "$MASTERSOS_RELEASE_KEYS" \( -type f ! -perm 0600 \) -o \( -type d ! -perm 0700 \))" ]; then
	pass "  载入的文件 0600、目录 0700"
else
	fail "  载入的权限不对"
fi
run 0 "keys-unload.sh" "已抹掉" "$img/keys-unload.sh"
run 1 "keys-load.sh --age 口令错" "could not decrypt" agefed_with wrong "$img/keys-load.sh" --age "$bundle"
if [ ! -e "$MASTERSOS_RELEASE_KEYS" ] && [ "$(shm_left)" = 0 ]; then pass "  口令错：什么都没留下"; else fail "  口令错：有残留"; fi
run 1 "keys-load.sh --age 仓库公钥不符" "对不上" agefed env MASTERSOS_PUB_DIR="$img/keys/lab" "$img/keys-load.sh" --age "$bundle"
if [ ! -e "$MASTERSOS_RELEASE_KEYS" ] && [ "$(shm_left)" = 0 ]; then pass "  不符：副本与解密目录都抹掉了"; else fail "  不符：有残留"; fi
run 1 "keys-load.sh --age 解密后意外失败" "模拟失败" agefed env MASTERSOS_TEST_FAIL_AT=age-decrypted "$img/keys-load.sh" --age "$bundle"
if [ "$(shm_left)" = 0 ]; then pass "  意外失败：/dev/shm 的解密目录抹掉了"; else fail "  意外失败：/dev/shm 有残留"; fi
run 1 "keys-load.sh --age 文件不在" "cannot read" "$img/keys-load.sh" --age "$work/nope.age"
unset MASTERSOS_RELEASE_KEYS MASTERSOS_PUB_DIR

# --- wipe 与泄漏检查 ----------------------------------------------------------------------
run 0 "wipe" "已抹掉" "$gen" wipe "$k"
if [ ! -e "$k" ]; then pass "  tmpfs 目录不在了"; else fail "  $k 还在"; fi
run 0 "wipe 重复跑" "没有要抹的" "$gen" wipe "$k"
run 0 "key-leak-check：/tmp、/var/tmp、测试目录（含两根「U 盘」）都干净" "没有" \
	python3 -I "$img/key-leak-check.py" "$ref" /tmp /var/tmp "$work"
# 对照：真泄漏了它找得到
mkdir "$work/leak"
cp "$ref/pcr.key" "$work/leak/"
run 1 "key-leak-check：拷到磁盘上的 pcr.key 找得到" "pcr.key" python3 -I "$img/key-leak-check.py" "$ref" "$work"
shred -u "$work/leak/pcr.key"
cp "$ref/kiosk-ext.pem" "$work/leak/ext-copy.pem"
run 1 "key-leak-check：拷到磁盘上的 kiosk-ext.pem 找得到" "kiosk-ext.pem" python3 -I "$img/key-leak-check.py" "$ref" "$work"
shred -u "$work/leak/ext-copy.pem"

echo "ceremony-test: $((n - fails))/$n 通过"
[ "$fails" = 0 ]
