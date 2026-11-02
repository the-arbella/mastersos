#!/bin/bash
# 真的 `mastersos-agent shim-check` 对真的 sbverify（4b Task 22）：不碰 VM。
#   bash image/tests/shim-chain-test.sh
# 用 openssl 生成两套一次性的测试 CA（A、B）与一套三级的（根 R → 中间 I → 签名者 S，签名里带着 I，像微软签的 shim），
# 拿 systemd-boot-efi 包里的 systemd-bootx64.efi 当映像，sbsign 出「A 签」「B 签」「A+B 双签」「S 签带 I」与一份改过的
# （先确认 sbverify --list 对双签那份列出两个签名）；用 printf 拼出 db 变量（4 字节属性 + EFI_SIGNATURE_LIST），
# 放进临时 sysfs，跑 `mastersos-agent shim-check --sysfs <临时 sysfs> <映像>`：
#   db 只有 A：A 签 → 0、B 签 → 1、双签 → 0、S 签 → 1、改过的 → 1；db 只有 I 或只有 R：S 签 → 0；db 只有冒充的 I → 1；
#   dbx 有 A（或 A 的签名者、或签名里带着的中间证书）：双签 → 1；dbx 有映像哈希（由 sbverify 另算）→ 1；dbx 空 → 照常；
#   dbx 有签名里带着的证书的 TBS 哈希（X509_SHA256/384/512，由 openssl asn1parse 另切）→ 1；dbx 读不懂 → 2；db 空（只有属性）或没有 db → 2；SecureBoot 为 0、不在、不是 UEFI 启动 → 0；SecureBoot 读不出、
#   efivars 没挂上 → 2。
# mastersos-agent：MASTERSOS_AGENT 指定，否则在 core 里 cargo build。
# 要 openssl、sbsign、sbverify、sbattach（sbsigntool）与 /usr/lib/systemd/boot/efi/systemd-bootx64.efi（systemd-boot-efi）：
# 缺了就跳过；MASTERSOS_SHIM_CHAIN_REQUIRE=1（CI）时缺了算失败。
set -euo pipefail

img=$(cd "$(dirname "$0")/.." && pwd)
efi=/usr/lib/systemd/boot/efi/systemd-bootx64.efi
skip() {
	if [ "${MASTERSOS_SHIM_CHAIN_REQUIRE:-}" = 1 ]; then
		echo "shim-chain-test: FAIL（$*；MASTERSOS_SHIM_CHAIN_REQUIRE=1 不许跳过）" >&2
		exit 1
	fi
	echo "shim-chain-test: skip（$*）"
	exit 0
}
for t in openssl sbsign sbverify sbattach od; do
	command -v "$t" >/dev/null || skip "缺少 $t"
done
[ -f "$efi" ] || skip "缺少 ${efi}（systemd-boot-efi）"

agent=${MASTERSOS_AGENT:-}
if [ -z "$agent" ]; then
	command -v cargo >/dev/null || skip "缺少 cargo，也没给 MASTERSOS_AGENT"
	(cd "$img/../core" && cargo build -q --locked -p mastersos-agent)
	agent=$img/../core/target/debug/mastersos-agent
fi
[ -x "$agent" ] || {
	echo "shim-chain-test: $agent 不能执行" >&2
	exit 1
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

# --- 两套一次性的测试 CA 与各自的签名证书 ------------------------------------------------
for n in A B; do
	openssl req -x509 -newkey rsa:2048 -nodes -keyout "ca$n.key" -out "ca$n.crt" -days 3650 \
		-subj "/CN=shim-chain-test CA $n" -addext basicConstraints=critical,CA:TRUE \
		-addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
	openssl req -newkey rsa:2048 -nodes -keyout "sign$n.key" -out "sign$n.csr" -subj "/CN=shim-chain-test signer $n" 2>/dev/null
	printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=codeSigning\n' >ext.cnf
	openssl x509 -req -in "sign$n.csr" -CA "ca$n.crt" -CAkey "ca$n.key" -CAcreateserial -days 3650 \
		-extfile ext.cnf -out "sign$n.crt" 2>/dev/null
	openssl x509 -in "ca$n.crt" -outform DER -out "ca$n.der"
done

# 像微软那样的三级：根 R（不在签名里）→ 中间 I（随签名带上，sbsign --addcert）→ 签名者 S。
# 这种签名 sbverify --cert <任意一张> 都报 OK（见 mastersos-agent 的 secureboot.rs 模块注释），所以链要另外验
openssl req -x509 -newkey rsa:2048 -nodes -keyout caR.key -out caR.crt -days 3650 -subj "/CN=shim-chain-test root R" \
	-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout caI.key -out caI.csr -subj "/CN=shim-chain-test intermediate I" 2>/dev/null
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' >ca.cnf
openssl x509 -req -in caI.csr -CA caR.crt -CAkey caR.key -CAcreateserial -days 3650 -extfile ca.cnf -out caI.crt 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout signS.key -out signS.csr -subj "/CN=shim-chain-test signer S" 2>/dev/null
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=codeSigning\n' >ext.cnf
openssl x509 -req -in signS.csr -CA caI.crt -CAkey caI.key -CAcreateserial -days 3650 -extfile ext.cnf -out signS.crt 2>/dev/null
for n in R I; do openssl x509 -in "ca$n.crt" -outform DER -out "ca$n.der"; done

# --- 映像 ---------------------------------------------------------------------------
cp "$efi" unsigned.efi
# 发行版的 systemd-bootx64.efi 不带签名；万一带了，先全部去掉（sbattach --remove 一次去一个）
for _ in 1 2 3 4; do
	sbverify --list unsigned.efi 2>&1 | grep -q '^signature 1' || break
	sbattach --remove unsigned.efi
done
sbsign --key signA.key --cert signA.crt --output a.efi unsigned.efi 2>/dev/null
sbsign --key signB.key --cert signB.crt --output b.efi unsigned.efi 2>/dev/null
sbsign --key signB.key --cert signB.crt --output ab.efi a.efi 2>/dev/null
sbsign --key signS.key --cert signS.crt --addcert caI.crt --output s.efi unsigned.efi 2>/dev/null
# 改过的映像：A 签之后在末尾多 100 字节（哈希对不上）
cp a.efi tampered.efi
head -c 100 /dev/urandom >>tampered.efi
nsig=$(sbverify --list ab.efi 2>/dev/null | grep -c '^signature [0-9]' || true)
if [ "$nsig" != 2 ]; then
	echo "shim-chain-test: 停下：这台的 sbsign 没能给已签的映像追加第二个签名（sbverify --list 列出 ${nsig} 个）；不用别的工具假装双签" >&2
	sbverify --list ab.efi >&2 || true
	exit 1
fi

# --- 拼 db 变量 ---------------------------------------------------------------------
# le32 <数>：小端 4 字节，写成 printf 的 \ooo 转义
le32() {
	local v=$1 i out=""
	for i in 0 1 2 3; do
		out+=$(printf '\\%03o' $(((v >> (8 * i)) & 255)))
	done
	printf '%s' "$out"
}
# EFI_CERT_X509_GUID a5c059a1-94e4-4aa7-87b5-ab155c2bf072 的磁盘字节序
x509_guid='\241\131\300\245\344\224\247\112\207\265\253\025\134\053\360\162'
# esl <der>：一个只有这张证书的 EFI_SIGNATURE_LIST（owner 16 个 0）
esl() {
	local n
	n=$(wc -c <"$1")
	# shellcheck disable=SC2059 # 格式串就是拼好的转义
	printf "${x509_guid}$(le32 $((28 + 16 + n)))$(le32 0)$(le32 $((16 + n)))"
	head -c 16 /dev/zero
	cat "$1"
}
# sysfs <名字> <SecureBoot：0|1|-> <db 里的证书…（- 表示没有 db 变量）>
sysfs() {
	local d=$tmp/$1 sb=$2 c
	shift 2
	mkdir -p "$d/firmware/efi/efivars"
	if [ "$sb" != - ]; then
		if [ "$sb" = 1 ]; then
			printf '\006\000\000\000\001'
		else
			printf '\006\000\000\000\000'
		fi >"$d/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
	fi
	if [ "${1:-}" != - ]; then
		{
			printf '\047\000\000\000'
			for c in "$@"; do esl "$c"; done
		} >"$d/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f"
	fi
	echo "$d"
}

# EFI_CERT_SHA256_GUID c1c41626-504c-4092-aca9-41f936934328 的磁盘字节序
sha256_guid='\046\026\304\301\114\120\222\100\254\251\101\371\066\223\103\050'
# hexbytes <十六进制>：原样输出这些字节
hexbytes() {
	local h=$1 x="" k
	for ((k = 0; k < ${#h}; k += 2)); do x+="\\x${h:k:2}"; done
	# shellcheck disable=SC2059 # 十六进制转成 \xHH 再交给 printf
	printf "$x"
}
# dbx <sysfs 目录> <项…>：写 dbx 变量。项是证书的 DER 文件、hash:<64 位十六进制>（映像的 Authenticode SHA-256）、
# tbs:<十六进制>（证书 TBSCertificate 的 SHA-256/384/512，按长度选 EFI_CERT_X509_SHA256/384/512），或 junk（读不懂的）
dbx() {
	local d=$1 i h n g
	shift
	{
		printf '\047\000\000\000'
		for i in "$@"; do
			case "$i" in
			junk) printf '\001\002\003' ;;
			tbs:*)
				h=${i#tbs:} n=$((${#h} / 2))
				case $n in
				32) g=92a4d23bc0967940b420fcf98ef103ed ;;
				48) g=6e877670c280e64eaad228b349a6865b ;;
				*) g=63bf6d440225da4cbcfa2465d2b0fe9d ;;
				esac
				hexbytes "$g"
				# shellcheck disable=SC2059 # 格式串就是拼好的转义
				printf "$(le32 $((28 + 16 + n + 16)))$(le32 0)$(le32 $((16 + n + 16)))"
				head -c 16 /dev/zero
				hexbytes "$h"
				head -c 16 /dev/zero
				;;
			hash:*)
				h=${i#hash:}
				# shellcheck disable=SC2059 # 格式串就是拼好的转义
				printf "${sha256_guid}$(le32 $((28 + 48)))$(le32 0)$(le32 48)"
				head -c 16 /dev/zero
				hexbytes "$h"
				;;
			*) esl "$i" ;;
			esac
		done
	} >"$d/firmware/efi/efivars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f"
}
# tbs_hash <证书 PEM> <256|384|512>：TBSCertificate 的哈希，不经 mastersos-agent——openssl asn1parse 报出第二行（d=1）的偏移与
# 长度，按字节切出来再算
tbs_hash() {
	local der line off hl l
	der=$(mktemp)
	openssl x509 -in "$1" -outform DER -out "$der"
	line=$(openssl asn1parse -inform DER -in "$der" | sed -n 2p)
	off=$(sed -E 's/^ *([0-9]+):.*/\1/' <<<"$line")
	hl=$(sed -E 's/.*hl= *([0-9]+).*/\1/' <<<"$line")
	l=$(sed -E 's/.* l= *([0-9]+).*/\1/' <<<"$line")
	tail -c +$((off + 1)) "$der" | head -c $((hl + l)) | "sha$2sum" | cut -d' ' -f1
	rm -f "$der"
}
# image_hash <映像>：映像的 Authenticode SHA-256，不经 mastersos-agent——拿别的映像的签名去验它，sbverify 报「expecting: <哈希>」（「got」是签名里记的那个）
openssl x509 -in caB.crt -out caB.pem
cp unsigned.efi other.efi
head -c 64 /dev/zero >>other.efi
sbsign --key signB.key --cert signB.crt --output other-signed.efi other.efi 2>/dev/null
sbattach --detach other.p7 other-signed.efi >/dev/null 2>&1
image_hash() {
	{ sbverify --cert caB.pem --detached other.p7 "$1" 2>&1 || true; } | sed -n 's/^ *expecting: *//p' | tr 'A-F' 'a-f'
}

t_fail=0 t_n=0
# want <名字> <期望退出码> <sysfs> <映像> [输出里应有的片段]
want() {
	local name=$1 exp=$2 sys=$3 image=$4 frag=${5:-} out rc=0
	out=$("$agent" shim-check --sysfs "$sys" "$tmp/$image" 2>&1) || rc=$?
	t_n=$((t_n + 1))
	if [ "$rc" = "$exp" ] && { [ -z "$frag" ] || grep -qF -- "$frag" <<<"$out"; }; then
		echo "ok   ${name}（退出 ${rc}）"
	else
		echo "FAIL ${name}：期望退出 ${exp}${frag:+、输出含「$frag」}，实际 ${rc}：" >&2
		printf '%s\n' "$out" | sed 's/^/    /' >&2
		t_fail=$((t_fail + 1))
	fi
}

onlyA=$(sysfs onlyA 1 caA.der)
onlyB=$(sysfs onlyB 1 caB.der)
both=$(sysfs both 1 caB.der caA.der)
empty=$(sysfs empty 1)
nodb=$(sysfs nodb 1 -)
onlyI=$(sysfs onlyI 1 caI.der)
onlyR=$(sysfs onlyR 1 caR.der)
sboff=$(sysfs sboff 0 caB.der)
sbnone=$(sysfs sbnone - caB.der)
fpA=$(openssl x509 -inform DER -in caA.der -outform DER | sha256sum | cut -d' ' -f1)

echo "     双签那份：sbverify --list 列出 $nsig 个签名"
want "db 只有 A：A 签" 0 "$onlyA" a.efi "$fpA"
want "db 只有 A：B 签" 1 "$onlyA" b.efi "does not chain"
want "db 只有 A：A+B 双签" 0 "$onlyA" ab.efi "$fpA"
want "db 只有 B：A+B 双签" 0 "$onlyB" ab.efi
want "db 只有 B：A 签" 1 "$onlyB" a.efi
want "db 有 B 与 A：A 签（逐张试，第二张链上）" 0 "$both" a.efi "$fpA"
want "db 有 A：没签名的映像" 1 "$onlyA" unsigned.efi
want "db 只有 I（像 db 里的 UEFI CA）：S 签、带着 I" 0 "$onlyI" s.efi
want "db 只有 R（不在签名里的根）：S 签、带着 I" 0 "$onlyR" s.efi
want "db 只有 A：S 签、带着 I（sbverify --cert 单独会报 OK 的情形）" 1 "$onlyA" s.efi "does not chain"
t_n=$((t_n + 1))
if openssl x509 -in caA.crt -out caA.pem 2>/dev/null && sbverify --cert caA.pem s.efi >/dev/null 2>&1; then
	echo "ok   旁证：这台的 sbverify --cert caA.pem s.efi 确实报 OK（所以链不能只交给它）"
else
	echo "ok   旁证：这台的 sbverify --cert caA.pem s.efi 没报 OK（sbsigntool 修过？链照样由 openssl 验）"
fi
want "db 只有 A：A 签之后被改过的映像" 1 "$onlyA" tampered.efi
# 冒充的中间证书：subject 与 I 相同、钥匙不同（自签）——信任锚按整张证书比，不按名字（复审 Minor 10）
openssl req -x509 -newkey rsa:2048 -nodes -keyout caF.key -outform DER -out caF.der -days 3650 \
	-subj "/CN=shim-chain-test intermediate I" -addext basicConstraints=critical,CA:TRUE 2>/dev/null
fakeI=$(sysfs fakeI 1 caF.der)
want "db 只有冒充的 I（同名、钥匙不同）：S 签、带着 I" 1 "$fakeI" s.efi "does not chain"

# --- dbx（复审 I1）------------------------------------------------------------------
# 双签：A 那个签名链到 dbx 里的证书、B 那个链得到 db → 照样拒绝（EDK2 一个签名被 dbx 拦下就拒绝整个映像）
dbxA=$(sysfs dbxA 1 caB.der)
dbx "$dbxA" caA.der
want "db 有 B、dbx 有 A：A+B 双签" 1 "$dbxA" ab.efi "dbx"
want "db 有 B、dbx 有 A：只有 B 签的不受影响" 0 "$dbxA" b.efi
openssl x509 -in signA.crt -outform DER -out signA.der
dbxLeaf=$(sysfs dbxLeaf 1 caB.der)
dbx "$dbxLeaf" signA.der
want "db 有 B、dbx 有 A 的签名者证书（叶子）：A+B 双签" 1 "$dbxLeaf" ab.efi "dbx"
dbxI=$(sysfs dbxI 1 caR.der)
dbx "$dbxI" caI.der
want "db 有根 R、dbx 有签名里带着的中间 I：S 签" 1 "$dbxI" s.efi "dbx"
# 映像的哈希在 dbx 里：哈希由 sbverify 另算（不经 mastersos-agent），与 agent 按 EDK2 算的必须一致
ha=$(image_hash a.efi)
hs=$(image_hash s.efi)
t_n=$((t_n + 1))
if [[ $ha =~ ^[0-9a-f]{64}$ && $hs =~ ^[0-9a-f]{64}$ ]]; then echo "ok   sbverify 另算的映像哈希：a.efi ${ha:0:16}…、s.efi ${hs:0:16}…"; else
	echo "FAIL 取不到映像哈希（$ha / $hs）" >&2
	t_fail=$((t_fail + 1))
fi
dbxH=$(sysfs dbxH 1 caA.der caR.der caB.der)
dbx "$dbxH" "hash:$(printf '0%.0s' {1..64})" "hash:$ha"
want "db 有 A、dbx 有 a.efi 的映像哈希：A 签" 1 "$dbxH" a.efi "Authenticode"
want "  同一个 dbx：A+B 双签（映像哈希相同：签名表不算在哈希里）" 1 "$dbxH" ab.efi "Authenticode"
want "  同一个 dbx：S 签（同一个 systemd-boot、带着 I：映像哈希也相同）" 1 "$dbxH" s.efi "Authenticode"
want "  同一个 dbx：内容不同的映像（多 64 字节，B 签）不受影响" 0 "$dbxH" other-signed.efi
dbxHs=$(sysfs dbxHs 1 caR.der)
dbx "$dbxHs" "hash:$hs"
want "db 有 R、dbx 有 s.efi 的映像哈希：S 签" 1 "$dbxHs" s.efi "Authenticode"
# dbx 的 X509_SHA256/384/512（复审第二轮 N1）：签名里带着的证书的 TBS 哈希在 dbx 里 → 吊销
dbxT1=$(sysfs dbxT1 1 caB.der)
dbx "$dbxT1" "tbs:$(tbs_hash signA.crt 256)"
want "db 有 B、dbx 有 A 的签名者的 TBS SHA-256：A+B 双签" 1 "$dbxT1" ab.efi "X509_SHA256"
want "  同一个 dbx：只有 B 签的不受影响" 0 "$dbxT1" b.efi
dbxT2=$(sysfs dbxT2 1 caR.der)
dbx "$dbxT2" "tbs:$(tbs_hash caI.crt 384)"
want "db 有 R、dbx 有签名里带着的中间 I 的 TBS SHA-384：S 签" 1 "$dbxT2" s.efi "X509_SHA384"
dbxT3=$(sysfs dbxT3 1 caR.der)
dbx "$dbxT3" "tbs:$(tbs_hash signS.crt 512)"
want "db 有 R、dbx 有签名者 S 的 TBS SHA-512：S 签" 1 "$dbxT3" s.efi "X509_SHA512"
dbxT4=$(sysfs dbxT4 1 caR.der)
dbx "$dbxT4" "tbs:$(tbs_hash caB.crt 256)"
want "db 有 R、dbx 有不相干的 B 的 TBS 哈希：S 签照常" 0 "$dbxT4" s.efi
dbxEmpty=$(sysfs dbxEmpty 1 caA.der)
dbx "$dbxEmpty"
want "dbx 只有属性（空）：没有吊销" 0 "$dbxEmpty" a.efi
dbxJunk=$(sysfs dbxJunk 1 caA.der)
dbx "$dbxJunk" junk
want "dbx 读不懂：判断不了" 2 "$dbxJunk" a.efi "dbx"

# --- Secure Boot 开没开判断不了（复审 I2）：退出 2，bootloader-update 不换 ------------------------
sbdir=$(sysfs sbdir - caA.der)
mkdir "$sbdir/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
want "SecureBoot 变量读不出（是个目录）" 2 "$sbdir" a.efi "cannot tell whether Secure Boot"
mkdir -p "$tmp/nomount/firmware/efi/efivars"
want "efivars 没挂上（目录是空的）" 2 "$tmp/nomount" a.efi "cannot tell whether Secure Boot"
mkdir -p "$tmp/legacy"
want "不是 UEFI 启动（没有 firmware/efi）：按关着" 0 "$tmp/legacy" a.efi "Secure Boot is off"

want "db 空（只有属性）" 2 "$empty" a.efi "has no certificates"
want "没有 db 变量" 2 "$nodb" a.efi "no db variable"
want "db 有 A：映像不在" 2 "$onlyA" nope.efi "cannot read the shim"
for f in a.efi b.efi ab.efi; do
	want "SecureBoot=0：$f 不核对" 0 "$sboff" "$f" "Secure Boot is off"
	want "没有 SecureBoot 变量：$f 不核对" 0 "$sbnone" "$f" "Secure Boot is off"
done
want "db 只有 A：A 签，PEM 没留在临时目录" 0 "$onlyA" a.efi
t_n=$((t_n + 1))
if find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'mastersos-shim-check.*' 2>/dev/null | grep -q .; then
	echo "FAIL 临时目录里留下了 mastersos-shim-check.*" >&2
	t_fail=$((t_fail + 1))
else
	echo "ok   临时目录里没有留下 mastersos-shim-check.*"
fi

echo "shim-chain-test: $((t_n - t_fail))/$t_n 通过"
[ "$t_fail" = 0 ]
