#!/bin/bash
# 钥匙在哪（4b Task 1，Ruling 19）：build.sh、make-installer.sh、channel-common.sh、mkosi.finalize 都 source 它，
# 钥匙路径只在这里拼（tests/check-tree.sh 第 15 条：那四个脚本自己不拼）。lab 与正式各一套，互不信任：
#   keyset_priv lab|release  私钥目录（只在构建机 VM 161，永不入库）：
#                              lab → $MASTERSOS_KEYS/lab（$MASTERSOS_KEYS 默认 ~/mastersos-keys，在磁盘上）；
#                              release → $MASTERSOS_RELEASE_KEYS（默认 /run/mastersos-release-keys）：正式私钥平时只在两根 LUKS
#                              U 盘上，签名会话时由 keys-load.sh 拷进 tmpfs、keys-unload.sh 抹掉（计划 5 裁定 9）。返回之前
#                              核对目录存在、属主是当前用户、权限 0700、在 tmpfs/ramfs 上、没有 swap，任何一项不符返回 2。
#                              MASTERSOS_RELEASE_KEYS 只在 MASTERSOS_TEST=1 时生效（不带就拒绝，与 keys-load/unload 一致）。
#                              MASTERSOS_TEST=1 时（只给测试）：目录可以在任何文件系统上（stderr 警告；MASTERSOS_TEST_CHECK_FS
#                              非空时照样核对，测这一项用），swap 改看 MASTERSOS_TEST_SWAP（非空当作有 swap）；属主与权限照样核对。
#                              里面：db.{key,crt}（Secure Boot 与 verity）、pcr.{key,crt}（PCR 11 签名）、gpg/（签 SHA256SUMS）、
#                              kiosk-ext.pem（考试扩展的 crx 签名，build.sh 取 $priv/kiosk-ext.pem；lab 的在 lab/ 下同名）
#   keyset_lab_local         试验用户的口令哈希与 authorized_keys：$MASTERSOS_KEYS/lab-local（不是签名钥匙，build.sh 用）
#   keyset_swap_on           有 swap 时返回 0（keys-load.sh 也用；MASTERSOS_TEST=1 时看 MASTERSOS_TEST_SWAP）
#   keyset_pub  lab|release  仓库里的公钥目录：release → <本目录>/keys，lab → <本目录>/keys/lab
#                              里面：mastersos-mok.der（db.crt 的 DER）、tpm2-pcr-public-key.pem（pcr.crt 的公钥）、
#                              import-pubring.pgp（gpg/ 的公钥）；release 另有 kiosk-ext-public.pem（keys-load.sh 核对用，
#                              不进镜像——镜像里的是 build.sh 由私钥算出的 kiosk-ext.json）
#   keyset_retired lab|release 退役的 PCR 公钥目录（4b Task 4，Ruling 28）：release → <本目录>/keys/retired，
#                              lab → <本目录>/keys/lab/retired。里面是旧的 pcr.crt 的公钥
#                              （tpm2-pcr-public-key-4phase.pem，四阶段签名）：它签过的 UKI 永远有效、不能再签任何东西，
#                              publish/promote 的 check_uki 据此拒收 .pcrpkey 等于它的构建。
# 被 source，不单独跑；set -euo pipefail 与 source 它的脚本相同。
set -euo pipefail

keyset_image=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

keyset_check() {
	case "${1:-}" in lab | release) ;; *)
		echo "keyset: 钥匙组只能是 lab 或 release，实际 '${1:-}'" >&2
		return 2
		;;
	esac
}

keyset_swap_on() {
	if [ "${MASTERSOS_TEST:-}" = 1 ]; then
		[ -n "${MASTERSOS_TEST_SWAP:-}" ]
		return
	fi
	local s
	# swapon 读不了（没装、/proc 不可读）时当作有 swap：宁可拒绝
	s=$(swapon --show --noheadings 2>/dev/null) || return 0
	[ -n "$s" ]
}

keyset_priv() {
	keyset_check "${1:-}" || return 2
	if [ "$1" = lab ]; then
		echo "${MASTERSOS_KEYS:-$HOME/mastersos-keys}/lab"
		return 0
	fi
	local d=${MASTERSOS_RELEASE_KEYS:-/run/mastersos-release-keys} why="" fs
	if [ -n "${MASTERSOS_RELEASE_KEYS:-}" ] && [ "${MASTERSOS_TEST:-}" != 1 ]; then
		why="MASTERSOS_RELEASE_KEYS 只给测试用（要同时 MASTERSOS_TEST=1），正式私钥只在 /run/mastersos-release-keys"
	elif [ ! -d "$d" ] || [ -L "$d" ]; then
		why="$d 不存在（或是符号链接）"
	elif [ "$(stat -c %u "$d")" != "$(id -u)" ]; then
		why="$d 的属主不是当前用户"
	elif [ "$(stat -c %a "$d")" != 700 ]; then
		why="$d 的权限是 $(stat -c %a "$d")，应是 0700"
	elif keyset_swap_on; then
		why="这台机器有 swap（swapon --show 不为空），tmpfs 里的私钥可能被换到磁盘上"
	elif [ "${MASTERSOS_TEST:-}" = 1 ] && [ -z "${MASTERSOS_TEST_CHECK_FS:-}" ]; then
		echo "keyset: 警告：MASTERSOS_TEST=1，正式私钥目录 $d 不核对是不是 tmpfs（只给测试）" >&2
	else
		fs=$(stat -f -c %T "$d" 2>/dev/null) || fs='?'
		case "$fs" in tmpfs | ramfs) ;; *) why="$d 在 $fs 上，不是 tmpfs / ramfs" ;; esac
	fi
	if [ -n "$why" ]; then
		echo "keyset: 拒绝使用正式私钥：${why}。正式私钥只经 keys-load.sh 载入 tmpfs（docs/key-ceremony.md「签名会话」）" >&2
		return 2
	fi
	echo "$d"
}

keyset_lab_local() {
	echo "${MASTERSOS_KEYS:-$HOME/mastersos-keys}/lab-local"
}

keyset_pub() {
	keyset_check "${1:-}" || return 2
	if [ "$1" = lab ]; then echo "$keyset_image/keys/lab"; else echo "$keyset_image/keys"; fi
}

keyset_retired() {
	keyset_check "${1:-}" || return 2
	echo "$(keyset_pub "$1")/retired"
}

# keyset_check_uki <uki> lab|release：UKI 的 PCR 签名把关（4b Task 4），build.sh（mkosi 之后、写 build-info 之前）、
# make-installer.sh（放进 U 盘的 UKI）与 channel-common.sh 的 check_uki（publish/promote）都调它。逻辑在 uki-pcrsig-check：
# .pcrpkey 是这一组的公钥、不是退役的，每个 profile 恰好一条 sha256 签名、且是 enter-initrd 阶段的。不过关返回非 0。
keyset_check_uki() {
	local uki=$1 pem pkfp retd f retired=()
	keyset_check "${2:-}" || return 2
	pem=$(keyset_pub "$2")/tpm2-pcr-public-key.pem
	[ -s "$pem" ] || {
		echo "keyset_check_uki: 缺少 $pem" >&2
		return 1
	}
	# systemd 的 pkfp 是 PKCS#1 RSAPublicKey DER 的 sha256
	pkfp=$(openssl rsa -pubin -in "$pem" -RSAPublicKey_out -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)
	retd=$(keyset_retired "$2")
	if [ -d "$retd" ]; then
		for f in "$retd"/*.pem; do
			[ -e "$f" ] && retired+=("$f")
		done
	fi
	python3 -I "$keyset_image/uki-pcrsig-check" "$uki" "$pem" "$pkfp" "${retired[@]}"
}

# keyset_shim_chains <EFI 映像> <CA 的 DER> [dbx 目录]（4b Task 22：channel-common.sh 的 check_shim_chain 与 build.sh 用）。
# 返回 0：某个签名链到这张 CA、且映像的哈希与这个签名本身验得过；1：链不上；2：判断不了（CA 读不懂、openssl 的结果看不懂）；
# 3：被 dbx 吊销。与 mastersos-agent 的 secureboot::shim_chains 同一做法：
#   - 每个签名（sbattach --detach、再 --remove 换下一个）先用 openssl 只验链（-nosigs -partial_chain -no_check_time，-CAfile 只有
#     这张），退出 0 **且**输出「Verification successful」才算（OpenSSL 3.0 对不认识的选项也退出 0），退出 4 算链不上，别的算判断不了；
#     链得上再 sbverify --cert <这张> --detached <这个签名> 验哈希。
#   - 不能只用 sbverify --cert：签名里带着中间证书时（微软签的 shim 都带），它对任意一张证书都报 OK（VM 161 实测）。
#   - dbx 目录（可选）：里面的 *.der 是吊销的证书（任何一个签名链到其中一张 → 3，EDK2 一个签名被拦就拒绝整个映像），
#     sha256.txt 每行一个吊销的映像 Authenticode SHA-256（十六进制）：任何一个签名里记的映像摘要（SpcIndirectData 的
#     messageDigest）在里面 → 3。机器上的 shim-check 自己按 EDK2 算哈希；这里取签名里记的那个——签名与映像对不上时它也
#     对不上映像，只会多拒、不会漏拒。
_ks_chain() { # <签名 DER> <CA PEM>
	local out rc=0
	out=$(openssl smime -verify -nosigs -inform DER -in "$1" -CAfile "$2" -no-CApath -no-CAstore \
		-partial_chain -purpose any -no_check_time -out /dev/null 2>&1) || rc=$?
	if [ "$rc" = 0 ] && grep -q 'Verification successful' <<<"$out"; then
		return 0
	fi
	[ "$rc" = 4 ] && return 1
	return 2
}
_ks_digest() { # <签名 DER>：SpcIndirectData（1.3.6.1.4.1.311.2.1.4）里的 SHA-256 摘要，小写十六进制
	openssl asn1parse -inform DER -in "$1" 2>/dev/null |
		awk '/:1\.3\.6\.1\.4\.1\.311\.2\.1\.4/ {f = 1} f && /prim: OCTET STRING/ && /l= *32 / {sub(/.*\[HEX DUMP\]:/, ""); print tolower($0); exit}'
}
keyset_shim_chains() {
	local efi=$1 ca=$2 dbx=${3:-} t n=0 i s rc d c
	t=$(mktemp -d) || return 2
	if ! openssl x509 -inform DER -in "$ca" -out "$t/ca.pem" 2>/dev/null; then
		rm -rf "$t"
		return 2
	fi
	cp "$efi" "$t/img.efi"
	for _ in 1 2 3 4 5 6 7 8; do
		sbverify --list "$t/img.efi" 2>/dev/null | grep -q '^signature 1' || break
		sbattach --detach "$t/sig$n.p7" "$t/img.efi" >/dev/null 2>&1 || break
		n=$((n + 1))
		sbattach --remove "$t/img.efi" >/dev/null 2>&1 || break
	done
	rc=1
	if [ -n "$dbx" ] && [ -d "$dbx" ]; then
		for ((i = 0; i < n; i++)); do
			d=$(_ks_digest "$t/sig$i.p7")
			if [ -n "$d" ] && [ -f "$dbx/sha256.txt" ] && tr 'A-F' 'a-f' <"$dbx/sha256.txt" | grep -qx "$d"; then
				rm -rf "$t"
				return 3
			fi
		done
		for c in "$dbx"/*.der; do
			[ -e "$c" ] || continue
			openssl x509 -inform DER -in "$c" -out "$t/dbx.pem" 2>/dev/null || { rm -rf "$t"; return 2; }
			for ((i = 0; i < n; i++)); do
				s=0
				_ks_chain "$t/sig$i.p7" "$t/dbx.pem" || s=$?
				case $s in
				0) rm -rf "$t"; return 3 ;;
				1) ;;
				*) rm -rf "$t"; return 2 ;;
				esac
			done
		done
	fi
	for ((i = 0; i < n; i++)); do
		s=0
		_ks_chain "$t/sig$i.p7" "$t/ca.pem" || s=$?
		case $s in
		0)
			if sbverify --cert "$t/ca.pem" --detached "$t/sig$i.p7" "$efi" >/dev/null 2>&1; then
				rc=0
				break
			fi
			;;
		1) ;;
		*)
			rc=2
			break
			;;
		esac
	done
	rm -rf "$t"
	return $rc
}
