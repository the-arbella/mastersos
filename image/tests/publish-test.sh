#!/bin/bash
# publish.sh / promote.sh 的发布把关（不需要 VM，也不需要真镜像）：
#   bash image/tests/publish-test.sh
# 用临时 gpg 钥匙（正式与 lab 各一把）、假的构建产物（最小的 PE 文件，带仓库里 PCR 公钥的 .pcrpkey 与对应 pkfp 的
# .pcrsig：正式构建用 keys/ 的、lab 构建用 keys/lab/ 的）和两棵临时通道根（正式：https 域名、lab=no；试验网：lab=yes）
# 跑真的 publish.sh / promote.sh。
# 换 shim 时的证书链闸门（4b Task 22）用一次性的测试 CA 顶替 keys/microsoft/ 的两张（MASTERSOS_MS_CA_DIR），
# 拿 systemd-boot-efi 的 systemd-bootx64.efi 当 shim、sbsign 签出几种：要 sbsigntool 与 systemd-boot-efi。
# 要 flock（util-linux）、gpg、gpgv、zstd、python3、openssl、sha256sum、sbsign、sbverify、sbattach：没有的机器（macOS）跳过；
# MASTERSOS_PUBLISH_TEST_REQUIRE=1（CI）时缺了算失败，免得 CI 的包少装一个就整套绿着什么都没测（复审 Minor 2）。
set -euo pipefail

img=$(cd "$(dirname "$0")/.." && pwd)
skip() {
	if [ "${MASTERSOS_PUBLISH_TEST_REQUIRE:-}" = 1 ]; then
		echo "publish-test: FAIL（$*；MASTERSOS_PUBLISH_TEST_REQUIRE=1 不许跳过）" >&2
		exit 1
	fi
	echo "publish-test: skip（$*）"
	exit 0
}
for t in flock gpg gpgv zstd unzip python3 openssl sha256sum sbsign sbverify sbattach; do
	command -v "$t" >/dev/null || skip "缺少 ${t}；在 Linux / CI 上跑"
done

tmp=$(mktemp -d)
trap 'gpgconf --homedir "$tmp/release/gpg" --kill all >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT
mkdir -p "$tmp/keys"
# 正式根的测试钥匙经 MASTERSOS_RELEASE_KEYS（keyset_priv release；MASTERSOS_TEST=1 时不核对 tmpfs，属主与 0700 照样核对）
mkdir -m 700 "$tmp/release" "$tmp/release/gpg"
gpg --homedir "$tmp/release/gpg" --batch --passphrase '' --quick-gen-key 'publish-test' ed25519 sign never 2>/dev/null
gpg --homedir "$tmp/release/gpg" --export >"$tmp/pubring.pgp"
# lab 的根用 lab 的一套钥匙（keyset.sh：$MASTERSOS_KEYS/lab/gpg 签，keys/lab/ 的公钥验）
mkdir -p "$tmp/keys/lab"
mkdir -m 700 "$tmp/keys/lab/gpg"
gpg --homedir "$tmp/keys/lab/gpg" --batch --passphrase '' --quick-gen-key 'publish-test lab' ed25519 sign never 2>/dev/null
gpg --homedir "$tmp/keys/lab/gpg" --export >"$tmp/pubring-lab.pgp"
# MASTERSOS_PUBRING / MASTERSOS_PUBRING_LAB 只有同时 MASTERSOS_TEST=1 才生效（channel-common.sh），下面另测「单独设」会被拒绝
efi=/usr/lib/systemd/boot/efi/systemd-bootx64.efi
[ -f "$efi" ] || skip "缺少 ${efi}，装 systemd-boot-efi"
# 测试用的「微软 CA」：2011、2023 两张（文件名照 keys/microsoft/），再加一张谁都不认的 X；各签一份 shim
mkdir -p "$tmp/ms"
for n in 2011 2023 X; do
	openssl req -x509 -newkey rsa:2048 -nodes -keyout "$tmp/ca$n.key" -out "$tmp/ca$n.crt" -days 3650 \
		-subj "/CN=publish-test CA $n" 2>/dev/null
done
openssl x509 -in "$tmp/ca2011.crt" -outform DER -out "$tmp/ms/MicCorUEFCA2011_2011-06-27.der"
openssl x509 -in "$tmp/ca2023.crt" -outform DER -out "$tmp/ms/microsoft-uefi-ca-2023.der"
sbsign --key "$tmp/ca2011.key" --cert "$tmp/ca2011.crt" --output "$tmp/shim-a.efi" "$efi" 2>/dev/null  # 今天的 shim：只有 2011
sbsign --key "$tmp/ca2023.key" --cert "$tmp/ca2023.crt" --output "$tmp/shim-b.efi" "$tmp/shim-a.efi" 2>/dev/null # 2011 + 2023 双签
sbsign --key "$tmp/ca2023.key" --cert "$tmp/ca2023.crt" --output "$tmp/shim-2023.efi" "$efi" 2>/dev/null       # 只有 2023
sbsign --key "$tmp/caX.key" --cert "$tmp/caX.crt" --output "$tmp/shim-x.efi" "$efi" 2>/dev/null                # 链不到微软
sbsign --key "$tmp/ca2011.key" --cert "$tmp/ca2011.crt" --output "$tmp/shim-ba.efi" "$tmp/shim-2023.efi" 2>/dev/null # 2023 + 2011 双签（顺序反过来）
# 链不到微软、但签名里带着中间证书（根 RX → 中间 IX → 签名者 SX，像微软签的 shim 那样带 IX）：sbverify --cert <任意一张>
# 都会报 OK（mastersos-agent secureboot.rs 的模块注释），闸门必须另外验链
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$tmp/caRX.key" -out "$tmp/caRX.crt" -days 3650 -subj "/CN=publish-test root RX" \
	-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$tmp/caIX.key" -out "$tmp/caIX.csr" -subj "/CN=publish-test intermediate IX" 2>/dev/null
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' >"$tmp/ca.cnf"
openssl x509 -req -in "$tmp/caIX.csr" -CA "$tmp/caRX.crt" -CAkey "$tmp/caRX.key" -CAcreateserial -days 3650 -extfile "$tmp/ca.cnf" -out "$tmp/caIX.crt" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$tmp/sX.key" -out "$tmp/sX.csr" -subj "/CN=publish-test signer SX" 2>/dev/null
printf 'basicConstraints=CA:FALSE\nextendedKeyUsage=codeSigning\n' >"$tmp/s.cnf"
openssl x509 -req -in "$tmp/sX.csr" -CA "$tmp/caIX.crt" -CAkey "$tmp/caIX.key" -CAcreateserial -days 3650 -extfile "$tmp/s.cnf" -out "$tmp/sX.crt" 2>/dev/null
sbsign --key "$tmp/sX.key" --cert "$tmp/sX.crt" --addcert "$tmp/caIX.crt" --output "$tmp/shim-xi.efi" "$efi" 2>/dev/null
# 映像的 Authenticode 哈希，不经 keyset.sh：拿别的映像的签名去验它，sbverify 报「expecting: <这个映像的哈希>」（「got」是签名里记的那个）
cp "$efi" "$tmp/other.efi"
head -c 64 /dev/zero >>"$tmp/other.efi"
sbsign --key "$tmp/caX.key" --cert "$tmp/caX.crt" --output "$tmp/other-signed.efi" "$tmp/other.efi" 2>/dev/null
sbattach --detach "$tmp/other.p7" "$tmp/other-signed.efi" >/dev/null 2>&1
openssl x509 -in "$tmp/caX.crt" -out "$tmp/caX.pem"
efi_hash=$({ sbverify --cert "$tmp/caX.pem" --detached "$tmp/other.p7" "$tmp/shim-2023.efi" 2>&1 || true; } |
	sed -n 's/^ *expecting: *//p' | tr 'A-F' 'a-f')
[[ $efi_hash =~ ^[0-9a-f]{64}$ ]] || {
	echo "publish-test: 取不到映像的 Authenticode 哈希（$efi_hash）" >&2
	exit 1
}
# 测试用的 dbx：一份放吊销的「2011」证书，一份放映像哈希；平时的 MASTERSOS_DBX_DIR 是空目录（没有吊销）
mkdir -p "$tmp/dbx-none" "$tmp/dbx-cert" "$tmp/dbx-hash"
cp "$tmp/ms/MicCorUEFCA2011_2011-06-27.der" "$tmp/dbx-cert/revoked.der"
echo "$efi_hash" | tr 'a-f' 'A-F' >"$tmp/dbx-hash/sha256.txt"
export MASTERSOS_DBX_DIR=$tmp/dbx-none
export MASTERSOS_MS_CA_DIR=$tmp/ms
export MASTERSOS_KEYS=$tmp/keys MASTERSOS_RELEASE_KEYS=$tmp/release MASTERSOS_PUBRING=$tmp/pubring.pgp MASTERSOS_PUBRING_LAB=$tmp/pubring-lab.pgp MASTERSOS_TEST=1 MASTERSOS_OUTPUT_DIR=$tmp/out

PROD_BASE=https://updates.example.org/mastersos
LAB_BASE=http://192.0.2.99/mastersos
mkdir -p "$tmp/prod" "$tmp/lab" "$tmp/bare"
printf 'base=%s\nlab=no\n' "$PROD_BASE" >"$tmp/prod/mastersos-root.conf"
printf 'base=%s\nlab=yes\n' "$LAB_BASE" >"$tmp/lab/mastersos-root.conf"

pem_release=$img/keys/tpm2-pcr-public-key.pem
pem_lab=$img/keys/lab/tpm2-pcr-public-key.pem

# make_build <版本> <profile：release|lab> <broken：''|userspace|initrd> <update_base> [签名阶段数，默认 4]
#            [build-info 里 ESP 的两行，默认「esp_keys_auto=absent esp_secure_boot_enroll=off」；- 表示不写]
# UKI 的 .pcrpkey 默认按 profile 取 keys/ 或 keys/lab/ 的 PCR 公钥，PEM= 覆盖（.pcrsig 的 pkfp 跟着它）
make_build() {
	local v=$1 profile=$2 broken=$3 base=$4 phases=${5:-1} esp=${6:-esp_keys_auto=absent esp_secure_boot_enroll=off} d=$tmp/out/$1 k pem pkfp
	pem=${PEM:-}
	if [ -z "$pem" ]; then
		if [ "$profile" = lab ]; then pem=$pem_lab; else pem=$pem_release; fi
	fi
	pkfp=$(openssl rsa -pubin -in "$pem" -RSAPublicKey_out -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)
	rm -rf "$d"
	mkdir -p "$d"
	# 第一条签名的 pol 是按 PHASE（默认 enter-initrd）真算出来的 PolicyPCR 摘要（make-fake-uki.py）
	python3 -I "$img/tests/make-fake-uki.py" "$d/MastersOS_${v}_x86-64.efi" "$pem" "$pkfp" "$phases" "${PHASE:-enter-initrd}"
	for k in usr-x86-64 usr-x86-64-verity usr-x86-64-verity-sig; do
		head -c 4096 /dev/urandom >"$d/MastersOS_${v}_x86-64.$k.$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n').raw"
	done
	printf 'version=%s\nprofile=%s\nbroken=%s\nupdate_base=%s\n' "$v" "$profile" "$broken" "$base" >"$d/build-info.txt"
	[ "$esp" = - ] || tr ' ' '\n' <<<"$esp" >>"$d/build-info.txt"
	# shim：默认所有假构建同一个（只有 2011 签名的 shim-a）；SHIMFILE= 换一份，SHIM=- 不写这一行（像 Task 4 之前的构建）。
	# build.sh 把镜像里的 /usr/lib/mastersos/esp/BOOTX64.EFI 放成 MastersOS_<v>_x86-64.shim.bin，shim_sha256 是它的（4b Task 22）
	cp "${SHIMFILE:-$tmp/shim-a.efi}" "$d/MastersOS_${v}_x86-64.shim.bin"
	[ "${SHIM:-}" = - ] || printf 'shim_sha256=%s\nshim_sbatlevel=sbat,1,2023012900;shim,2;|\n' "$(sha256sum <"$d/MastersOS_${v}_x86-64.shim.bin" | cut -d' ' -f1)" >>"$d/build-info.txt"
	# systemd-boot（grubx64.efi）：同上，SDBOOT= 覆盖，SDBOOT=- 不写（终审 I5 之前的构建）
	[ "${SDBOOT:-}" = - ] || printf 'sdboot_sha256=%s\n' "${SDBOOT:-$(printf 'c%.0s' {1..64})}" >>"$d/build-info.txt"
	# 去掉签名后的 sha256 与签名证书的 sha256：SDBOOT_U= / SDBOOT_SIGNER= 给了才写（之前的构建没有这两行）
	[ -z "${SDBOOT_U:-}" ] || printf 'sdboot_unsigned_sha256=%s\n' "$SDBOOT_U" >>"$d/build-info.txt"
	[ -z "${SDBOOT_SIGNER:-}" ] || printf 'sdboot_signer_sha256=%s\n' "$SDBOOT_SIGNER" >>"$d/build-info.txt"
}

t_fail=0 t_n=0
# expect <名字> <ok|refused> <期望在输出里的片段（refused 时）> <命令…>
expect() {
	local name=$1 want=$2 frag=$3 out rc=0
	shift 3
	out=$("$@" 2>&1) || rc=$?
	t_n=$((t_n + 1))
	if { [ "$want" = ok ] && [ $rc = 0 ]; } || { [ "$want" = refused ] && [ $rc != 0 ] && grep -qF -- "$frag" <<<"$out"; }; then
		echo "ok   ${name}（rc=${rc}）"
	else
		echo "FAIL ${name}：期望 ${want}，rc=${rc}，输出：" >&2
		printf '%s\n' "$out" | sed 's/^/    /' >&2
		t_fail=$((t_fail + 1))
	fi
}
# 某根的某通道里有没有某版本的文件
has() { compgen -G "$1/$2/MastersOS_$3_x86-64.*" >/dev/null; }
hasnt() { ! has "$@"; }
empty_dir() { [ -z "$(ls -A "$1")" ]; }
check() { # check <名字> <条件命令…>
	t_n=$((t_n + 1))
	if "${@:2}"; then echo "ok   $1"; else
		echo "FAIL $1" >&2
		t_fail=$((t_fail + 1))
	fi
}
pub() { MASTERSOS_PUBLISH_ROOT=$1 "$img/publish.sh" "$2" "$3"; }
pro() { MASTERSOS_PUBLISH_ROOT=$1 "$img/promote.sh" "$2"; }

make_build 20261012.1 lab "" "$LAB_BASE"
make_build 20261012.2 release userspace "$PROD_BASE"
make_build 20261012.3 release "" "$PROD_BASE"
make_build 20261012.4 release "" https://other.example.org/mastersos
make_build 20261012.5 lab userspace "$LAB_BASE"
make_build 20261012.10 release "" "$PROD_BASE"

expect "lab 构建 → 正式根" refused "profile=lab" pub "$tmp/prod" 20261012.1 stable
check "  正式根的 stable 里没有它" hasnt "$tmp/prod" stable 20261012.1
expect "broken 构建 → 正式根" refused "broken=userspace" pub "$tmp/prod" 20261012.2 beta
check "  正式根的 beta 里没有它" hasnt "$tmp/prod" beta 20261012.2
expect "update_base 与根不同 → 正式根" refused "update_base" pub "$tmp/prod" 20261012.4 stable
expect "没有 mastersos-root.conf 的根" refused "mastersos-root.conf" pub "$tmp/bare" 20261012.3 stable
check "  没声明的根里什么都没写" empty_dir "$tmp/bare"
make_build 20261012.6 release "" "$PROD_BASE" 4
expect "签了四个阶段的 UKI（离开 initrd 也签了）→ 正式根" refused "只有一条 sha256 签名" pub "$tmp/prod" 20261012.6 beta
check "  正式根的 beta 里没有它" hasnt "$tmp/prod" beta 20261012.6
# ESP 上的 Secure Boot 自动导入（Task 4）：正式根只收 build.sh 查过 esp.raw、记下 absent / off 的构建
make_build 20261012.7 release "" "$PROD_BASE" 1 "esp_keys_auto=present esp_secure_boot_enroll=off"
expect "ESP 带 loader/keys/auto 的构建 → 正式根" refused "esp_keys_auto=absent" pub "$tmp/prod" 20261012.7 beta
make_build 20261012.7 release "" "$PROD_BASE" 1 "esp_keys_auto=absent esp_secure_boot_enroll=force"
expect "loader.conf 不是 secure-boot-enroll off 的构建 → 正式根" refused "esp_secure_boot_enroll=off" pub "$tmp/prod" 20261012.7 beta
make_build 20261012.7 release "" "$PROD_BASE" 1 -
expect "build-info 没有 ESP 两行的构建（Task 4 之前）→ 正式根" refused "esp_keys_auto=absent" pub "$tmp/prod" 20261012.7 beta
check "  三次都没进正式根的 beta" hasnt "$tmp/prod" beta 20261012.7
expect "update_base 相同的正式构建 → 正式根" ok "" pub "$tmp/prod" 20261012.3 beta
check "  build-info 跟着进了通道、列在签过的 SHA256SUMS 里" \
	grep -q 'MastersOS_20261012.3_x86-64.build-info.txt' "$tmp/prod/beta/SHA256SUMS"
gpgv_q() { gpgv "$@" 2>/dev/null; }
check "  SHA256SUMS 的签名验得过" gpgv_q --keyring "$tmp/pubring.pgp" "$tmp/prod/beta/SHA256SUMS.gpg" "$tmp/prod/beta/SHA256SUMS"
expect "promote 正式构建" ok "" pro "$tmp/prod" 20261012.3
check "  stable 里有它" has "$tmp/prod" stable 20261012.3
expect "lab 构建 → lab 根" ok "" pub "$tmp/lab" 20261012.1 stable
check "  lab 根的 SHA256SUMS 用 lab 的钥匙签" gpgv_q --keyring "$tmp/pubring-lab.pgp" "$tmp/lab/stable/SHA256SUMS.gpg" "$tmp/lab/stable/SHA256SUMS"
check "  正式的公钥验不过 lab 根的 SHA256SUMS" sh -c "! gpgv --keyring '$tmp/pubring.pgp' '$tmp/lab/stable/SHA256SUMS.gpg' '$tmp/lab/stable/SHA256SUMS' 2>/dev/null"
check "  lab 的公钥验不过正式根的 SHA256SUMS" sh -c "! gpgv --keyring '$tmp/pubring-lab.pgp' '$tmp/prod/beta/SHA256SUMS.gpg' '$tmp/prod/beta/SHA256SUMS' 2>/dev/null"
expect "lab 的 broken 构建 → lab 根" ok "" pub "$tmp/lab" 20261012.5 beta

# --- 根与钥匙一一对应（4b Task 1，Ruling 19）-------------------------------------------------
# 正式构建发进 lab 根：两套 gpg 钥匙之后，正式镜像验不过 lab 根的 SHA256SUMS，发了也装不上
make_build 20261012.60 release "" "$LAB_BASE"
expect "正式构建 → lab 根" refused "profile=release" pub "$tmp/lab" 20261012.60 beta
check "  lab 根的 beta 里没有它" hasnt "$tmp/lab" beta 20261012.60
# lab 构建却用了正式的 PCR 钥匙签：lab 根按 keys/lab/ 的公钥把关
PEM=$pem_release make_build 20261012.61 lab "" "$LAB_BASE"
expect "lab 构建、.pcrpkey 是正式公钥 → lab 根" refused ".pcrpkey" pub "$tmp/lab" 20261012.61 beta
check "  lab 根的 beta 里没有它" hasnt "$tmp/lab" beta 20261012.61
# 正式构建却用了 lab 的 PCR 钥匙签：正式根按 keys/ 的公钥把关
PEM=$pem_lab make_build 20261012.62 release "" "$PROD_BASE"
expect "正式构建、.pcrpkey 是 lab 公钥 → 正式根" refused ".pcrpkey" pub "$tmp/prod" 20261012.62 beta
check "  正式根的 beta 里没有它" hasnt "$tmp/prod" beta 20261012.62

# 只有一条签名、但签的是离开 initrd 之后的阶段（复审 M1）→ 拒
PHASE=enter-initrd:leave-initrd make_build 20261012.65 release "" "$PROD_BASE"
expect "一条签名、阶段是 leave-initrd 的 UKI → 正式根" refused "不是 enter-initrd 阶段的" pub "$tmp/prod" 20261012.65 beta
check "  正式根的 beta 里没有它" hasnt "$tmp/prod" beta 20261012.65

# 退役的 PCR 钥匙（4b Task 4，Ruling 28）：.pcrpkey 是 keys/retired/ 里那把（换掉之前的四阶段钥匙）→ 拒
PEM=$img/keys/retired/tpm2-pcr-public-key-4phase.pem make_build 20261012.63 release "" "$PROD_BASE"
expect "正式构建、.pcrpkey 是退役的 PCR 钥匙 → 正式根" refused "退役的 PCR 钥匙" pub "$tmp/prod" 20261012.63 beta
check "  正式根的 beta 里没有它" hasnt "$tmp/prod" beta 20261012.63
PEM=$img/keys/lab/retired/tpm2-pcr-public-key-4phase.pem make_build 20261012.64 lab "" "$LAB_BASE"
expect "lab 构建、.pcrpkey 是退役的 lab PCR 钥匙 → lab 根" refused "退役的 PCR 钥匙" pub "$tmp/lab" 20261012.64 beta
check "  lab 根的 beta 里没有它" hasnt "$tmp/lab" beta 20261012.64
# 单阶段、当前钥匙的正式构建 → 过：下面「update_base 相同的正式构建 → 正式根」就是这个（默认 phases=1）。

# 修好之前的 publish.sh 可能已经把 lab 构建放进了正式根的 beta：promote 必须拦下（版本比 stable 新，
# 拦它的只能是 build-info）
make_build 20261012.9 lab "" "$LAB_BASE"
expect "lab 构建 20261012.9 → lab 根" ok "" pub "$tmp/lab" 20261012.9 stable
cp "$tmp/lab/stable/"MastersOS_20261012.9_x86-64.* "$tmp/prod/beta/"
(
	export MASTERSOS_PUBLISH_ROOT=$tmp/prod
	# shellcheck disable=SC1091
	. "$img/channel-common.sh"
	read_root_conf sign # 按根选钥匙
	seal_channel "$tmp/prod/beta" >/dev/null
)
expect "promote 正式根 beta 里的 lab 构建" refused "profile=lab" pro "$tmp/prod" 20261012.9
check "  stable 里没有它" hasnt "$tmp/prod" stable 20261012.9

# 比 stable 最新的版本旧的不能 promote
expect "publish 20261012.10 → beta（版本比较按 sort -V：.10 > .9）" ok "" pub "$tmp/prod" 20261012.10 beta
expect "promote 20261012.10" ok "" pro "$tmp/prod" 20261012.10
make_build 20261012.0 release "" "$PROD_BASE"
expect "publish 比 beta 最新旧的 20261012.0" refused "比 beta 最新" pub "$tmp/prod" 20261012.0 beta
expect "promote 比 stable 最新（20261012.10）旧的 20261012.3" refused "比 stable 最新" pro "$tmp/prod" 20261012.3
expect "再 promote 一次 stable 最新的 20261012.10（只重签）" ok "" pro "$tmp/prod" 20261012.10

# --- 根声明里重复的键 -------------------------------------------------------------
mkdir -p "$tmp/dup"
printf 'base=%s\nlab=no\nlab=yes\n' "$PROD_BASE" >"$tmp/dup/mastersos-root.conf"
expect "mastersos-root.conf 里 lab= 写了两次" refused "出现了不止一次" pub "$tmp/dup" 20261012.3 stable
only_conf() { [ "$(find "$1" -mindepth 1 -maxdepth 1 -printf '%f\n')" = mastersos-root.conf ]; }
check "  什么都没写" only_conf "$tmp/dup"

# --- 镜像目标 mirror_s3= / mirror_cdn=（sync-s3.sh 用）：只许 lab=no 的根，要么都有要么都没有 ----------------
mkdir -p "$tmp/mirror"
mirror_conf() { printf '%s\n' "$@" >"$tmp/mirror/mastersos-root.conf"; }
mirror_read() {
	# shellcheck disable=SC2016 # 单引号里的变量是给 bash -c 展开的
	env MASTERSOS_PUBLISH_ROOT="$tmp/mirror" bash -c '. "$1/channel-common.sh"; read_root_conf >/dev/null; echo "s3=${root_mirror_s3} cdn=${root_mirror_cdn}"' _ "$img"
}
mirror_conf "base=$PROD_BASE" lab=no mirror_s3=s3://mastersos-os-x mirror_cdn=E1ABC
expect "mirror 键：lab=no 的根带两个键" ok "" mirror_read
mirror_is() { [ "$(mirror_read)" = "$1" ]; }
check "  read_root_conf 设了 root_mirror_s3 与 root_mirror_cdn" mirror_is "s3=s3://mastersos-os-x cdn=E1ABC"
mirror_conf "base=$PROD_BASE" lab=no
check "  没有键时为空" mirror_is "s3= cdn="
mirror_conf "base=$LAB_BASE" lab=yes mirror_s3=s3://mastersos-os-x mirror_cdn=E1ABC
expect "mirror 键：lab=yes 的根带了 → 拒绝" refused "只许 lab=no" mirror_read
mirror_conf "base=$PROD_BASE" lab=no mirror_s3=s3://mastersos-os-x
expect "mirror 键：只有 mirror_s3 → 拒绝" refused "要么都写" mirror_read
mirror_conf "base=$PROD_BASE" lab=no mirror_cdn=E1ABC
expect "mirror 键：只有 mirror_cdn → 拒绝" refused "要么都写" mirror_read
mirror_conf "base=$PROD_BASE" lab=no mirror_s3=s3://mastersos-os-x mirror_s3=s3://mastersos-os-y mirror_cdn=E1ABC
expect "mirror 键：mirror_s3 写了两次 → 拒绝" refused "出现了不止一次" mirror_read
mirror_conf "base=$PROD_BASE" lab=no mirror_s3=s3://mastersos-os-x/sub mirror_cdn=E1ABC
expect "mirror 键：mirror_s3 带路径 → 拒绝" refused "应形如 s3://" mirror_read

# --- 只设 MASTERSOS_PUBRING、没有 MASTERSOS_TEST=1：不许悄悄换掉信任的公钥 -----------------------
pub_notest() { env -u MASTERSOS_TEST MASTERSOS_PUBLISH_ROOT="$1" "$img/publish.sh" "$2" "$3"; }
expect "MASTERSOS_PUBRING 不带 MASTERSOS_TEST=1" refused "只给测试用" pub_notest "$tmp/prod" 20261012.3 stable
# 正式根不带 MASTERSOS_TEST=1：MASTERSOS_RELEASE_KEYS 不认 → keyset_priv release 拒绝，什么都不签
expect "正式根的 MASTERSOS_RELEASE_KEYS 不带 MASTERSOS_TEST=1" refused "keys-load.sh" env -u MASTERSOS_TEST -u MASTERSOS_PUBRING -u MASTERSOS_PUBRING_LAB -u MASTERSOS_MS_CA_DIR -u MASTERSOS_DBX_DIR MASTERSOS_PUBLISH_ROOT="$tmp/prod" "$img/publish.sh" 20261012.3 stable
pub_notest_lab() { env -u MASTERSOS_TEST -u MASTERSOS_PUBRING MASTERSOS_PUBLISH_ROOT="$1" "$img/publish.sh" "$2" "$3"; }
expect "MASTERSOS_PUBRING_LAB 不带 MASTERSOS_TEST=1" refused "只给测试用" pub_notest_lab "$tmp/lab" 20261012.1 stable

# --- 签名失败：不报成功、不删旧版本、撤下刚放进来的文件，重跑不被挡 ----------------------------
mkdir -p "$tmp/badbin" "$tmp/sig"
printf '#!/bin/sh\necho "stub gpg：签名失败" >&2\nexit 2\n' >"$tmp/badbin/gpg"
chmod +x "$tmp/badbin/gpg"
printf 'base=%s\nlab=no\n' "$PROD_BASE" >"$tmp/sig/mastersos-root.conf"
pub_badgpg() { env PATH="$tmp/badbin:$PATH" MASTERSOS_PUBLISH_ROOT="$1" "$img/publish.sh" "$2" "$3"; }
pro_badgpg() { env PATH="$tmp/badbin:$PATH" MASTERSOS_PUBLISH_ROOT="$1" "$img/promote.sh" "$2"; }
# 目录里的全部文件名（含 .SHA256SUMS.new、.publish-* 这类残留）+ 清单与签名的 sha256
snapshot() { (cd "$1" 2>/dev/null && find . -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort && sha256sum SHA256SUMS SHA256SUMS.gpg 2>/dev/null) || true; }
same_as() { [ "$1" = "$(snapshot "$2")" ]; }
for v in 20261012.20 20261012.21 20261012.22 20261012.23; do make_build "$v" release "" "$PROD_BASE"; done
for v in 20261012.20 20261012.21 20261012.22; do expect "publish $v → beta（签名失败前的三个版本）" ok "" pub "$tmp/sig" "$v" beta; done
before=$(snapshot "$tmp/sig/beta")
expect "publish 20261012.23，gpg 签名失败" refused "签名失败" pub_badgpg "$tmp/sig" 20261012.23 beta
check "  beta 目录与 SHA256SUMS{,.gpg} 前后一样（旧版本 20261012.20 没删，新版本撤下，没有 .new 残留）" \
	same_as "$before" "$tmp/sig/beta"
expect "  修好 gpg 后重跑 publish 20261012.23（不被「已经发过」挡住）" ok "" pub "$tmp/sig" 20261012.23 beta
check "  这次才删掉最旧的 20261012.20" hasnt "$tmp/sig" beta 20261012.20
before=$(snapshot "$tmp/sig/stable")
expect "promote 20261012.23，gpg 签名失败" refused "签名失败" pro_badgpg "$tmp/sig" 20261012.23
check "  stable 前后一样（没有留下 20261012.23 的文件）" same_as "$before" "$tmp/sig/stable"
expect "  修好 gpg 后重跑 promote 20261012.23" ok "" pro "$tmp/sig" 20261012.23
check "  stable 里有它" has "$tmp/sig" stable 20261012.23

# --- shim 闸门（Task 4 复审 I-1）：与通道最新版本的 shim 不同（升级、降级、没有记录）就拒绝，除非 --allow-shim-change
mkdir -p "$tmp/shim"
printf 'base=%s\nlab=no\n' "$PROD_BASE" >"$tmp/shim/mastersos-root.conf"
make_build 20261012.30 release "" "$PROD_BASE"
expect "shim 闸门：空通道 → beta" ok "" pub "$tmp/shim" 20261012.30 beta
make_build 20261012.31 release "" "$PROD_BASE"
expect "shim 闸门：同一个 shim → beta" ok "" pub "$tmp/shim" 20261012.31 beta
SHIMFILE=$tmp/shim-b.efi make_build 20261012.32 release "" "$PROD_BASE"
expect "shim 闸门：换了 shim → beta，不带 flag" refused "--allow-shim-change" pub "$tmp/shim" 20261012.32 beta
check "  beta 里没有它" hasnt "$tmp/shim" beta 20261012.32
SHIM=- make_build 20261012.33 release "" "$PROD_BASE"
expect "shim 闸门：build-info 没记 shim（Task 4 之前的构建）→ beta" refused "未记录" pub "$tmp/shim" 20261012.33 beta
pub_allow() { MASTERSOS_PUBLISH_ROOT=$1 "$img/publish.sh" "$2" "$3" --allow-shim-change; }
pro_allow() { MASTERSOS_PUBLISH_ROOT=$1 "$img/promote.sh" "$2" --allow-shim-change; }
out=$(pub_allow "$tmp/shim" 20261012.32 beta 2>&1) && rc=0 || rc=$?
check "shim 闸门：换了 shim 带 --allow-shim-change → beta（rc=${rc}）" [ "$rc" = 0 ]
check "  prints the shim-change warning (prediction, recovery key only if it fails)" grep -q 'a machine whose prediction fails needs it once at its next boot' <<<"$out"
expect "shim 闸门：promote .31（stable 空）" ok "" pro "$tmp/shim" 20261012.31
expect "shim 闸门：promote 换了 shim 的 .32，不带 flag" refused "--allow-shim-change" pro "$tmp/shim" 20261012.32
check "  stable 里没有它" hasnt "$tmp/shim" stable 20261012.32
expect "shim 闸门：promote .32 带 --allow-shim-change" ok "" pro_allow "$tmp/shim" 20261012.32
# 降级：比 .32 新的版本带回旧的 shim A，同样要 flag
make_build 20261012.34 release "" "$PROD_BASE"
expect "shim 闸门：更新的版本带回旧 shim（降级）→ beta，不带 flag" refused "--allow-shim-change" pub "$tmp/shim" 20261012.34 beta
expect "shim 闸门：publish 的参数顺序可以把 flag 放前面" ok "" env MASTERSOS_PUBLISH_ROOT="$tmp/shim" "$img/publish.sh" --allow-shim-change 20261012.34 beta

check "  shim 跟着进了通道、列在签过的 SHA256SUMS 里" grep -q 'MastersOS_20261012.32_x86-64.shim.bin' "$tmp/shim/stable/SHA256SUMS"

# --- 换 shim 时的证书链闸门（4b Task 22）：--allow-shim-change 之下，新 shim 要链到 keys/microsoft/ 两张之一 -------------
mkdir -p "$tmp/chain"
printf 'base=%s\nlab=no\n' "$PROD_BASE" >"$tmp/chain/mastersos-root.conf"
make_build 20261012.70 release "" "$PROD_BASE"
expect "证书链闸门：基线（shim 只有 2011）→ beta" ok "" pub "$tmp/chain" 20261012.70 beta
SHIMFILE=$tmp/shim-x.efi make_build 20261012.71 release "" "$PROD_BASE"
expect "证书链闸门：链不到任一微软 CA 的 shim，带 --allow-shim-change" refused "链不到" pub_allow "$tmp/chain" 20261012.71 beta
check "  beta 里没有它" hasnt "$tmp/chain" beta 20261012.71
SHIMFILE=$tmp/shim-xi.efi make_build 20261012.71 release "" "$PROD_BASE"
expect "证书链闸门：链不到微软、签名里带着中间证书的 shim（sbverify --cert 会被骗过）" refused "链不到" pub_allow "$tmp/chain" 20261012.71 beta
check "  beta 里没有它" hasnt "$tmp/chain" beta 20261012.71
SHIMFILE=$tmp/shim-2023.efi make_build 20261012.72 release "" "$PROD_BASE"
out=$(pub_allow "$tmp/chain" 20261012.72 beta 2>&1) && rc=0 || rc=$?
check "证书链闸门：只链 2023 的 shim → 放行（rc=${rc}）" [ "$rc" = 0 ]
check "  打印链到的是 2023 那张" grep -q '链到 microsoft-uefi-ca-2023.der' <<<"$out"
check "  警告 db 只有 2011 的机器会停在旧 shim" grep -q 'db 只有 2011 的机器会停在旧 shim' <<<"$out"
SHIMFILE=$tmp/shim-b.efi make_build 20261012.73 release "" "$PROD_BASE"
out=$(pub_allow "$tmp/chain" 20261012.73 beta 2>&1) && rc=0 || rc=$?
# shellcheck disable=SC2016 # eval 的条件里变量到 eval 时才展开
check "证书链闸门：双签 shim → 放行（rc=${rc}），两张都链得上、不警告" \
	eval '[ "$rc" = 0 ] && grep -q "链到 MicCorUEFCA2011_2011-06-27.der" <<<"$out" && grep -q "链到 microsoft-uefi-ca-2023.der" <<<"$out" && ! grep -q "停在旧 shim" <<<"$out"'
pub_unchained() { MASTERSOS_PUBLISH_ROOT=$1 "$img/publish.sh" "$2" "$3" --allow-shim-change --allow-unchained-shim; }
SHIMFILE=$tmp/shim-x.efi make_build 20261012.76 release "" "$PROD_BASE"
expect "证书链闸门：正式根带 --allow-unchained-shim → 拒绝" refused "--allow-unchained-shim" pub_unchained "$tmp/chain" 20261012.76 beta
check "  beta 里没有它" hasnt "$tmp/chain" beta 20261012.76
SHIMFILE=$tmp/shim-x.efi make_build 20261012.74 lab "" "$LAB_BASE"
mkdir -p "$tmp/labchain"
printf 'base=%s\nlab=yes\n' "$LAB_BASE" >"$tmp/labchain/mastersos-root.conf"
make_build 20261012.69 lab "" "$LAB_BASE"
expect "证书链闸门：lab 根的基线 → beta" ok "" pub "$tmp/labchain" 20261012.69 beta
expect "证书链闸门：lab 根、链不到的 shim、只带 --allow-shim-change" refused "链不到" pub_allow "$tmp/labchain" 20261012.74 beta
out=$(pub_unchained "$tmp/labchain" 20261012.74 beta 2>&1) && rc=0 || rc=$?
# shellcheck disable=SC2016 # 同上
check "证书链闸门：lab 根带 --allow-unchained-shim → 放行（rc=${rc}）并警告" \
	eval '[ "$rc" = 0 ] && grep -q "allow-unchained-shim" <<<"$out"'
pro_unchained() { MASTERSOS_PUBLISH_ROOT=$1 "$img/promote.sh" "$2" --allow-shim-change --allow-unchained-shim; }
expect "证书链闸门：lab 根 promote 基线 .69" ok "" pro "$tmp/labchain" 20261012.69
expect "证书链闸门：lab 根 promote 链不到的 .74、只带 --allow-shim-change" refused "链不到" pro_allow "$tmp/labchain" 20261012.74
expect "证书链闸门：lab 根 promote .74 带 --allow-unchained-shim" ok "" pro_unchained "$tmp/labchain" 20261012.74
# build-info 的 shim_sha256 与 shim 文件对不上：拒绝（核对的不是要发的那份）
SHIMFILE=$tmp/shim-a.efi make_build 20261012.77 release "" "$PROD_BASE"
cp "$tmp/shim-2023.efi" "$tmp/out/20261012.77/MastersOS_20261012.77_x86-64.shim.bin"
expect "证书链闸门：shim 文件与 build-info 的 shim_sha256 不符" refused "不符" pub_allow "$tmp/chain" 20261012.77 beta
rm "$tmp/out/20261012.77/MastersOS_20261012.77_x86-64.shim.bin"
expect "证书链闸门：没有 shim 文件（Task 22 之前的构建）" refused "shim.bin" pub_allow "$tmp/chain" 20261012.77 beta
# dbx（复审 I1）：双签 shim（2023 在前、2011 在后）里 2011 那个签名链到 dbx 里的证书 → 拒发，哪怕 2023 那个链得到
# （哪个开关都不放行）。shim 要与通道最新的（.73 的 shim-b）不同，闸门才会验
SHIMFILE=$tmp/shim-ba.efi make_build 20261012.78 release "" "$PROD_BASE"
pub_dbx() { MASTERSOS_DBX_DIR=$1 MASTERSOS_PUBLISH_ROOT=$2 "$img/publish.sh" "$3" "$4" --allow-shim-change; }
expect "dbx：双签 shim、2011 的签名链到 dbx 里的证书" refused "dbx 吊销" pub_dbx "$tmp/dbx-cert" "$tmp/chain" 20261012.78 beta
check "  beta 里没有它" hasnt "$tmp/chain" beta 20261012.78
expect "dbx：映像哈希在 dbx 的 sha256.txt 里（大写也认）" refused "dbx 吊销" pub_dbx "$tmp/dbx-hash" "$tmp/chain" 20261012.78 beta
expect "dbx：空的 dbx 目录 → 放行" ok "" pub_dbx "$tmp/dbx-none" "$tmp/chain" 20261012.78 beta
expect "MASTERSOS_DBX_DIR 不带 MASTERSOS_TEST=1" refused "只给测试用" env -u MASTERSOS_TEST -u MASTERSOS_PUBRING -u MASTERSOS_PUBRING_LAB -u MASTERSOS_MS_CA_DIR MASTERSOS_PUBLISH_ROOT="$tmp/chain" "$img/publish.sh" 20261012.78 beta

# 空通道也验证书链（复审 Minor 1）：新的根第一次发布、链不到微软 CA 的 shim → 拒发；链得到的 → 放行
mkdir -p "$tmp/fresh"
printf 'base=%s\nlab=no\n' "$PROD_BASE" >"$tmp/fresh/mastersos-root.conf"
SHIMFILE=$tmp/shim-xi.efi make_build 20261012.80 release "" "$PROD_BASE"
expect "空通道：链不到微软 CA 的 shim（带着中间证书）→ beta" refused "链不到" pub "$tmp/fresh" 20261012.80 beta
check "  beta 里没有它" hasnt "$tmp/fresh" beta 20261012.80
SHIMFILE=$tmp/shim-2023.efi make_build 20261012.81 release "" "$PROD_BASE"
out=$(pub "$tmp/fresh" 20261012.81 beta 2>&1) && rc=0 || rc=$?
# shellcheck disable=SC2016 # eval 的条件里变量到 eval 时才展开
check "空通道：只链 2023 的 shim → 放行（rc=${rc}）并警告" eval '[ "$rc" = 0 ] && grep -q "停在旧 shim" <<<"$out"'

# MASTERSOS_MS_CA_DIR 只给测试：不带 MASTERSOS_TEST=1 就拒绝
expect "MASTERSOS_MS_CA_DIR 不带 MASTERSOS_TEST=1" refused "只给测试用" env -u MASTERSOS_TEST -u MASTERSOS_PUBRING -u MASTERSOS_PUBRING_LAB MASTERSOS_PUBLISH_ROOT="$tmp/chain" "$img/publish.sh" 20261012.73 beta

# --- systemd-boot 闸门（终审 I5）：ESP 上的 grubx64.efi 只有一份、没有 A/B，换了它就拒绝，除非 --allow-bootloader-change；
# 通道里最新版本没有记录（I5 之前发的构建）不算拒绝的理由：没有基线，放行并警告
mkdir -p "$tmp/sdb"
printf 'base=%s\nlab=no\n' "$PROD_BASE" >"$tmp/sdb/mastersos-root.conf"
sdbD=$(printf 'd%.0s' {1..64})
SDBOOT=- make_build 20261012.50 release "" "$PROD_BASE"
expect "systemd-boot 闸门：没记录的构建 → 空通道" ok "" pub "$tmp/sdb" 20261012.50 beta
make_build 20261012.51 release "" "$PROD_BASE"
out=$(pub "$tmp/sdb" 20261012.51 beta 2>&1) && rc=0 || rc=$?
check "systemd-boot 闸门：通道最新的没有记录（没有基线）→ beta 放行（rc=${rc}）" [ "$rc" = 0 ]
check "  打印「没有基线」的警告" grep -q 'systemd-boot.*没有基线' <<<"$out"
make_build 20261012.52 release "" "$PROD_BASE"
expect "systemd-boot 闸门：同一个 systemd-boot → beta" ok "" pub "$tmp/sdb" 20261012.52 beta
SDBOOT=$sdbD make_build 20261012.53 release "" "$PROD_BASE"
expect "systemd-boot 闸门：换了 systemd-boot → beta，不带 flag" refused "--allow-bootloader-change" pub "$tmp/sdb" 20261012.53 beta
check "  beta 里没有它" hasnt "$tmp/sdb" beta 20261012.53
expect "systemd-boot 闸门：--allow-shim-change 不放行换 systemd-boot" refused "--allow-bootloader-change" pub_allow "$tmp/sdb" 20261012.53 beta
SDBOOT=- make_build 20261012.54 release "" "$PROD_BASE"
expect "systemd-boot 闸门：本构建没记录、通道里有 → beta" refused "未记录" pub "$tmp/sdb" 20261012.54 beta
pub_allow_bl() { MASTERSOS_PUBLISH_ROOT=$1 "$img/publish.sh" "$2" "$3" --allow-bootloader-change; }
pro_allow_bl() { MASTERSOS_PUBLISH_ROOT=$1 "$img/promote.sh" "$2" --allow-bootloader-change; }
out=$(pub_allow_bl "$tmp/sdb" 20261012.53 beta 2>&1) && rc=0 || rc=$?
check "systemd-boot 闸门：换了 systemd-boot 带 --allow-bootloader-change → beta（rc=${rc}）" [ "$rc" = 0 ]
check "  打印警告" grep -q '警告：--allow-bootloader-change' <<<"$out"
expect "systemd-boot 闸门：promote .52（stable 空）" ok "" pro "$tmp/sdb" 20261012.52
expect "systemd-boot 闸门：promote 换了 systemd-boot 的 .53，不带 flag" refused "--allow-bootloader-change" pro "$tmp/sdb" 20261012.53
check "  stable 里没有它" hasnt "$tmp/sdb" stable 20261012.53
expect "systemd-boot 闸门：promote .53 带 --allow-bootloader-change" ok "" pro_allow_bl "$tmp/sdb" 20261012.53
SHIMFILE=$tmp/shim-b.efi SDBOOT=$sdbD make_build 20261012.55 release "" "$PROD_BASE"
expect "两个闸门：shim 也换了，只带 --allow-bootloader-change" refused "--allow-shim-change" pub_allow_bl "$tmp/sdb" 20261012.55 beta
expect "两个闸门：两个 flag 都带" ok "" env MASTERSOS_PUBLISH_ROOT="$tmp/sdb" "$img/publish.sh" 20261012.55 beta --allow-bootloader-change --allow-shim-change

# 只是重新签了名（签名里的 signingTime 让签名后的字节次次不同，2026-10-27）：去掉签名后相同、签名证书相同 → 放行；
# 任一不同、或一边没记这两行 → 照旧按签名后的字节拒绝
mkdir -p "$tmp/sdb2"
printf 'base=%s\nlab=no\n' "$PROD_BASE" >"$tmp/sdb2/mastersos-root.conf"
h() { printf "$1%.0s" {1..64}; }
SDBOOT=$(h 1) SDBOOT_U=$(h a) SDBOOT_SIGNER=$(h e) make_build 20261012.56 release "" "$PROD_BASE"
expect "systemd-boot 闸门（重签）：基线 → 空通道" ok "" pub "$tmp/sdb2" 20261012.56 beta
SDBOOT=$(h 2) SDBOOT_U=$(h a) SDBOOT_SIGNER=$(h e) make_build 20261012.57 release "" "$PROD_BASE"
out=$(pub "$tmp/sdb2" 20261012.57 beta 2>&1) && rc=0 || rc=$?
check "systemd-boot 闸门（重签）：签名后不同、去掉签名后与签名证书都相同 → 不带 flag 放行（rc=${rc}）" [ "$rc" = 0 ]
check "  打印「只是重新签了名」" grep -q '只是重新签了名' <<<"$out"
SDBOOT=$(h 3) SDBOOT_U=$(h a) SDBOOT_SIGNER=$(h f) make_build 20261012.58 release "" "$PROD_BASE"
expect "systemd-boot 闸门（重签）：签名证书不同 → 拒绝" refused "--allow-bootloader-change" pub "$tmp/sdb2" 20261012.58 beta
SDBOOT=$(h 4) SDBOOT_U=$(h b) SDBOOT_SIGNER=$(h e) make_build 20261012.59 release "" "$PROD_BASE"
expect "systemd-boot 闸门（重签）：去掉签名后不同 → 拒绝" refused "--allow-bootloader-change" pub "$tmp/sdb2" 20261012.59 beta
SDBOOT=$(h 5) make_build 20261012.60 release "" "$PROD_BASE"
expect "systemd-boot 闸门（重签）：本构建没记这两行 → 照旧按签名后的字节拒绝" refused "--allow-bootloader-change" pub "$tmp/sdb2" 20261012.60 beta

# --- lab 的根不看 ESP 的两行（lab 镜像本来就带 loader/keys/auto）---------------------------
make_build 20261012.99 lab "" "$LAB_BASE" 1 "esp_keys_auto=present esp_secure_boot_enroll=unset"
expect "ESP 带 loader/keys/auto 的 lab 构建 → lab 根" ok "" pub "$tmp/lab" 20261012.99 beta

# --- 安装 U 盘（Task 11）：publish.sh <v> installer 只发已在 stable、UKI 字节相同的版本 -------------
mkdir -p "$tmp/inst"
printf 'base=%s\nlab=no\n' "$PROD_BASE" >"$tmp/inst/mastersos-root.conf"
# One make-installer run: the zip (with the system file as its member) is finished first, zstd writes the img.zst later
# from the same bytes. mkzip <v> <raw>: a zip with MastersOS/MastersOS-system_<v>_x86-64.raw and a stand-in UKI.
mkzip() {
	python3 -I -c 'import sys, zipfile
v, raw, dst = sys.argv[1:4]
z = zipfile.ZipFile(dst, "w", zipfile.ZIP_STORED)
z.writestr("MastersOS/MastersOS-installer_%s_x86-64.efi" % v, b"ventoy-uki")
z.write(raw, "MastersOS/MastersOS-system_%s_x86-64.raw" % v)
z.writestr("MastersOS/README.txt", "x")
z.close()' "$1" "$2" "$tmp/out/$1/MastersOS-ventoy_$1_x86-64.zip"
}
stick() {
	head -c 65536 /dev/urandom >"$tmp/raw.$1"
	mkzip "$1" "$tmp/raw.$1"
	zstd -q -f "$tmp/raw.$1" -o "$tmp/out/$1/MastersOS-installer_$1_x86-64.img.zst"
}
inst_has() { [ -f "$tmp/inst/installer/MastersOS-installer_$1_x86-64.img.zst" ] && [ -f "$tmp/inst/installer/MastersOS-ventoy_$1_x86-64.zip" ]; }
for v in 20261012.40 20261012.41 20261012.42 20261012.43; do make_build "$v" release "" "$PROD_BASE"; done
expect "U 盘：没有 U 盘镜像的构建" refused "make-installer.sh" pub "$tmp/inst" 20261012.40 installer
stick 20261012.40
expect "U 盘：版本还不在 stable" refused "stable 里没有" pub "$tmp/inst" 20261012.40 installer
check "  installer/ 里没有它" sh -c "! [ -e '$tmp/inst/installer/MastersOS-installer_20261012.40_x86-64.img.zst' ]"
expect "U 盘：先发到 stable" ok "" pub "$tmp/inst" 20261012.40 stable
expect "U 盘：已在 stable 的版本" ok "" pub "$tmp/inst" 20261012.40 installer
check "  installer/ 里有它" inst_has 20261012.40
check "  installer/ 里有 Ventoy 包，SHA256SUMS 也列着它" grep -q ' MastersOS-ventoy_20261012.40_x86-64.zip$' "$tmp/inst/installer/SHA256SUMS"
check "  installer/ 里没有 zip 里那个同名的 UKI" sh -c "! [ -e '$tmp/inst/installer/MastersOS-installer_20261012.40_x86-64.efi' ] && ! [ -e '$tmp/inst/installer/MastersOS' ]"
check "  installer/SHA256SUMS 签名验得过、列着它" sh -c "gpgv --keyring '$tmp/pubring.pgp' '$tmp/inst/installer/SHA256SUMS.gpg' '$tmp/inst/installer/SHA256SUMS' 2>/dev/null && grep -q 'MastersOS-installer_20261012.40_x86-64.img.zst' '$tmp/inst/installer/SHA256SUMS'"
expect "U 盘：同样字节再发一次（只重签）" ok "" pub "$tmp/inst" 20261012.40 installer
stick 20261012.40
expect "U 盘：同一版本换了字节" refused "字节不同" pub "$tmp/inst" 20261012.40 installer
# new zip next to the old published img.zst: not one run, refused before installer/ is touched
cp "$tmp/inst/installer/MastersOS-installer_20261012.40_x86-64.img.zst" "$tmp/out/20261012.40/MastersOS-installer_20261012.40_x86-64.img.zst"
expect "U 盘：同一版本只有 zip 是新的（内容对不上）" refused "different make-installer.sh runs" pub "$tmp/inst" 20261012.40 installer
stick 20261012.41
rm -f "$tmp/out/20261012.41/MastersOS-ventoy_20261012.41_x86-64.zip"
expect "U 盘：有 img.zst 没有 Ventoy 包" refused "MastersOS-ventoy_20261012.41_x86-64.zip" pub "$tmp/inst" 20261012.41 installer
check "  没发出去的 .41 在 installer/ 里什么都没有" sh -c "! ls '$tmp/inst/installer' | grep -q 20261012.41"
stick 20261012.41
cp "$tmp/out/20261012.41/MastersOS-installer_20261012.41_x86-64.img.zst" "$tmp/keep.41.zst"
stick 20261012.41
cp "$tmp/keep.41.zst" "$tmp/out/20261012.41/MastersOS-installer_20261012.41_x86-64.img.zst"
expect "U 盘：zip 与 img.zst 内容不同（两次 make-installer）" refused "different make-installer.sh runs" pub "$tmp/inst" 20261012.41 installer
check "  没发出去的 .41 在 installer/ 里什么都没有" sh -c "! ls '$tmp/inst/installer' | grep -q 20261012.41"
stick 20261012.41
expect "U 盘：.41 发到 stable" ok "" pub "$tmp/inst" 20261012.41 stable
echo rebuilt >>"$tmp/out/20261012.41/MastersOS_20261012.41_x86-64.efi"
stick 20261012.41
expect "U 盘：stable 里的 UKI 与构建目录的不同（重建过）" refused "不是同一份字节" pub "$tmp/inst" 20261012.41 installer
for v in 20261012.42 20261012.43; do
	stick "$v"
	# mtimes are no evidence of one run: .42 has an img.zst far older than the zip, .43 a zip far older than the img.zst
	case $v in
	*.42) touch -d '2 hours ago' "$tmp/out/$v/MastersOS-installer_${v}_x86-64.img.zst" ;;
	*.43) touch -d '2 hours ago' "$tmp/out/$v/MastersOS-ventoy_${v}_x86-64.zip" ;;
	esac
	expect "U 盘：发 $v（stable → installer）" ok "" sh -c "MASTERSOS_PUBLISH_ROOT='$tmp/inst' '$img/publish.sh' $v stable && MASTERSOS_PUBLISH_ROOT='$tmp/inst' '$img/publish.sh' $v installer"
done
check "  installer/ 只留最近 3 个（.40 .42 .43，.41 没发成）" inst_has 20261012.43
make_build 20261012.44 release "" "$PROD_BASE"
stick 20261012.44
expect "U 盘：第 4 个版本" ok "" sh -c "MASTERSOS_PUBLISH_ROOT='$tmp/inst' '$img/publish.sh' 20261012.44 stable && MASTERSOS_PUBLISH_ROOT='$tmp/inst' '$img/publish.sh' 20261012.44 installer"
check "  最旧的 .40 删掉了（img.zst 与 zip）" sh -c "! [ -e '$tmp/inst/installer/MastersOS-installer_20261012.40_x86-64.img.zst' ] && ! [ -e '$tmp/inst/installer/MastersOS-ventoy_20261012.40_x86-64.zip' ]"
check "  SHA256SUMS 正好列着 .42 .43 .44 的 img.zst 与 zip" sh -c "[ \"\$(awk '{print \$2}' '$tmp/inst/installer/SHA256SUMS' | tr '\n' ' ')\" = 'MastersOS-installer_20261012.42_x86-64.img.zst MastersOS-ventoy_20261012.42_x86-64.zip MastersOS-installer_20261012.43_x86-64.img.zst MastersOS-ventoy_20261012.43_x86-64.zip MastersOS-installer_20261012.44_x86-64.img.zst MastersOS-ventoy_20261012.44_x86-64.zip ' ]"
check "  installer/ 里的文件正好是这六个加签名与清单" sh -c "[ \"\$(ls '$tmp/inst/installer' | wc -l)\" = 8 ]"
make_build 20261012.45 lab "" "$LAB_BASE"
stick 20261012.45
expect "U 盘：lab 构建 → 正式根" refused "profile=lab" pub "$tmp/inst" 20261012.45 installer

# --- 考试扩展（计划 9 Task 8）：publish.sh <v> chrome 把构建打包的 crx 与 updates.xml 放进 <根>/chrome/ ----------------
# 用真的 kiosk-ext-pack.sh 与一次性钥匙打包（扩展源码拷一份、改 manifest 的 version）；build-info 照 build.sh 的写法记 kiosk_ext_*
openssl genrsa -out "$tmp/ext-a.pem" 2048 2>/dev/null
openssl genrsa -out "$tmp/ext-b.pem" 2048 2>/dev/null
# with_ext <版本> <钥匙> <chrome 地址> <扩展的 version>：给 $tmp/out/<版本> 加上 kiosk-ext/ 与 build-info 的几行
with_ext() {
	local v=$1 key=$2 cb=$3 ev=$4 d=$tmp/out/$1 src=$tmp/ext-src-$4 eid
	if [ ! -d "$src" ]; then
		cp -R "$img/../kiosk-extension" "$src"
		python3 -I -c 'import json, sys; p = sys.argv[1]; m = json.load(open(p)); m["version"] = sys.argv[2]; json.dump(m, open(p, "w"))' "$src/manifest.json" "$ev"
	fi
	rm -rf "$d/kiosk-ext"
	eid=$(MASTERSOS_KIOSK_EXT_SRC=$src "$img/kiosk-ext-pack.sh" "$key" "$d/kiosk-ext" "$cb")
	rm -f "$d/kiosk-ext/kiosk-ext.json" "$d/kiosk-ext/org.mastersos.kiosk_exit.json"
	sed -i '/^kiosk_ext/d' "$d/build-info.txt"
	printf 'kiosk_ext_id=%s\nkiosk_ext_version=%s\nkiosk_ext_update_url=%s/updates.xml\nkiosk_ext_crx_sha256=%s\nkiosk_ext_updates_sha256=%s\n' \
		"$eid" "$ev" "$cb" "$(sha256sum <"$d/kiosk-ext/mastersos-kiosk-ext.crx" | cut -d' ' -f1)" \
		"$(sha256sum <"$d/kiosk-ext/updates.xml" | cut -d' ' -f1)" >>"$d/build-info.txt"
}
mkdir -p "$tmp/cr"
printf 'base=%s\nlab=no\n' "$PROD_BASE" >"$tmp/cr/mastersos-root.conf"
CR=$PROD_BASE/chrome
cr_has() { cmp -s "$tmp/out/$1/kiosk-ext/mastersos-kiosk-ext.crx" "$tmp/cr/chrome/mastersos-kiosk-ext.crx" && cmp -s "$tmp/out/$1/kiosk-ext/updates.xml" "$tmp/cr/chrome/updates.xml"; }
cr_signed() { gpgv --keyring "$tmp/pubring.pgp" "$tmp/cr/chrome/SHA256SUMS.gpg" "$tmp/cr/chrome/SHA256SUMS" 2>/dev/null && (cd "$tmp/cr/chrome" && sha256sum --quiet -c SHA256SUMS) &&
	[ "$(awk '{print $2}' "$tmp/cr/chrome/SHA256SUMS" | tr '\n' ' ')" = "mastersos-kiosk-ext.crx updates.xml " ]; }

make_build 20261013.1 release "" "$PROD_BASE"
echo kiosk_ext=none >>"$tmp/out/20261013.1/build-info.txt"
expect "考试扩展：没带扩展的构建（kiosk_ext=none）" refused "没带考试扩展" pub "$tmp/cr" 20261013.1 chrome
check "  chrome/ 没建" sh -c "! [ -e '$tmp/cr/chrome' ]"
make_build 20261013.2 release "" "$PROD_BASE"
with_ext 20261013.2 "$tmp/ext-a.pem" "https://elsewhere.example.org/chrome" 1.0.2
expect "考试扩展：update_url 不是这棵根的 chrome/" refused "update_url" pub "$tmp/cr" 20261013.2 chrome
with_ext 20261013.2 "$tmp/ext-a.pem" "$CR" 1.0.2
echo tampered >>"$tmp/out/20261013.2/kiosk-ext/mastersos-kiosk-ext.crx"
expect "考试扩展：crx 构建后被改过" refused "sha256" pub "$tmp/cr" 20261013.2 chrome
with_ext 20261013.2 "$tmp/ext-a.pem" "$CR" 1.0.2
expect "考试扩展：版本还不在 beta / stable（复审 M1）" refused "不在这棵根的 beta 或 stable 里" pub "$tmp/cr" 20261013.2 chrome
check "  chrome/ 没建" sh -c "! [ -e '$tmp/cr/chrome' ]"
expect "考试扩展：先把 .2 发到 beta" ok "" pub "$tmp/cr" 20261013.2 beta
expect "考试扩展：正式构建 → 正式根的 chrome/" ok "" pub "$tmp/cr" 20261013.2 chrome
check "  crx 与 updates.xml 就是构建的那两份" cr_has 20261013.2
check "  chrome/SHA256SUMS 签过、正好列着这两个文件" cr_signed
expect "考试扩展：同一构建再发一次（只重签）" ok "" pub "$tmp/cr" 20261013.2 chrome
make_build 20261013.3 release "" "$PROD_BASE"
with_ext 20261013.3 "$tmp/ext-a.pem" "$CR" 1.0.2
printf 'x' >>"$tmp/out/20261013.3/kiosk-ext/mastersos-kiosk-ext.crx"
sed -i "s/^kiosk_ext_crx_sha256=.*/kiosk_ext_crx_sha256=$(sha256sum <"$tmp/out/20261013.3/kiosk-ext/mastersos-kiosk-ext.crx" | cut -d' ' -f1)/" "$tmp/out/20261013.3/build-info.txt"
pub "$tmp/cr" 20261013.3 beta >/dev/null 2>&1
expect "考试扩展：同一版本、字节不同" refused "字节不同" pub "$tmp/cr" 20261013.3 chrome
make_build 20261013.4 release "" "$PROD_BASE"
with_ext 20261013.4 "$tmp/ext-a.pem" "$CR" 1.0.1
pub "$tmp/cr" 20261013.4 beta >/dev/null 2>&1
expect "考试扩展：比根里的旧" refused "旧" pub "$tmp/cr" 20261013.4 chrome
make_build 20261013.5 release "" "$PROD_BASE"
with_ext 20261013.5 "$tmp/ext-b.pem" "$CR" 1.0.3
pub "$tmp/cr" 20261013.5 beta >/dev/null 2>&1
expect "考试扩展：换了钥匙（id 不同）" refused "换了扩展钥匙" pub "$tmp/cr" 20261013.5 chrome
check "  根里还是 .2 的那份" cr_has 20261013.2
make_build 20261013.6 release "" "$PROD_BASE"
with_ext 20261013.6 "$tmp/ext-a.pem" "$CR" 1.0.10
expect "考试扩展：先把 .6 发到 stable 也行" ok "" pub "$tmp/cr" 20261013.6 stable
expect "考试扩展：新版本（1.0.10 比 1.0.2 新，按数字比）" ok "" pub "$tmp/cr" 20261013.6 chrome
check "  换成了 .6 的那份、重签过" sh -c "cmp -s '$tmp/out/20261013.6/kiosk-ext/updates.xml' '$tmp/cr/chrome/updates.xml' && gpgv --keyring '$tmp/pubring.pgp' '$tmp/cr/chrome/SHA256SUMS.gpg' '$tmp/cr/chrome/SHA256SUMS' 2>/dev/null && (cd '$tmp/cr/chrome' && sha256sum --quiet -c SHA256SUMS)"
# A build carrying the extension in the image has nothing for chrome/, on either kind of root
before=$(cat "$tmp/cr/chrome/SHA256SUMS")
make_build 20261013.8 lab "" "$LAB_BASE"
with_ext 20261013.8 "$tmp/ext-a.pem" "file:///usr/lib/mastersos/kiosk-ext" 1.0.2
expect "exam extension in the image: lab root, nothing to do" ok "nothing to publish" pub "$tmp/lab" 20261013.8 chrome
check "  lab root has no chrome/" sh -c "! [ -e '$tmp/lab/chrome' ]"
make_build 20261013.9 release "" "$PROD_BASE"
with_ext 20261013.9 "$tmp/ext-a.pem" "file:///usr/lib/mastersos/kiosk-ext" 1.0.2
expect "exam extension in the image: release root, nothing to do" ok "nothing to publish" pub "$tmp/cr" 20261013.9 chrome
check "  chrome/ unchanged" sh -c "[ \"\$(cat '$tmp/cr/chrome/SHA256SUMS')\" = '$before' ]"
# lab 根：base 是 http，要 chrome_base=（https）；lab=no 的根不许写它
make_build 20261013.7 lab "" "$LAB_BASE"
with_ext 20261013.7 "$tmp/ext-a.pem" "https://lab.example.org/mastersos/chrome" 1.0.2
expect "考试扩展：lab 根没有 chrome_base=" refused "chrome_base" pub "$tmp/lab" 20261013.7 chrome
check "  lab 根里没有 chrome/" sh -c "! [ -e '$tmp/lab/chrome' ]"
mkdir -p "$tmp/labc"
printf 'base=%s\nlab=yes\nchrome_base=https://lab.example.org/mastersos/chrome\n' "$LAB_BASE" >"$tmp/labc/mastersos-root.conf"
pub "$tmp/labc" 20261013.7 beta >/dev/null 2>&1
expect "考试扩展：lab 构建 → 写了 chrome_base 的 lab 根" ok "" pub "$tmp/labc" 20261013.7 chrome
check "  lab 根的 chrome/SHA256SUMS 用 lab 的钥匙签" gpgv_q --keyring "$tmp/pubring-lab.pgp" "$tmp/labc/chrome/SHA256SUMS.gpg" "$tmp/labc/chrome/SHA256SUMS"
expect "考试扩展：lab 构建 → 正式根" refused "profile=lab" pub "$tmp/cr" 20261013.7 chrome
mkdir -p "$tmp/badc"
printf 'base=%s\nlab=no\nchrome_base=https://x.example.org/chrome\n' "$PROD_BASE" >"$tmp/badc/mastersos-root.conf"
expect "考试扩展：lab=no 的根写了 chrome_base=" refused "chrome_base= 只许 lab=yes" pub "$tmp/badc" 20261013.6 chrome

echo "publish-test: $((t_n - t_fail))/$t_n 通过"
[ "$t_fail" = 0 ]
