#!/bin/bash
# Release key ceremony (plan 5 Task 4). Run as root with no network: an Ubuntu live system (docs/key-ceremony.md), or the
# network-less container that mac-ceremony.sh starts on the Mac:
#   gen-release-keys.sh generate      <tmpfs 目录>
#   gen-release-keys.sh write-stick   <tmpfs 目录> <块设备> A|B
#   gen-release-keys.sh seal          <tmpfs 目录> <输出.age>
#   gen-release-keys.sh export-public <tmpfs 目录> <输出目录>
#   gen-release-keys.sh wipe          <tmpfs 目录>
# 自成一体：脚本 U 盘上只有本目录，不 source 仓库里别的文件。
#
# <tmpfs 目录> 的布局与 U 盘的根相同：mastersos-release-keys/{db.key,db.crt,pcr.key,pcr.crt,kiosk-ext.pem,gpg/}、MANIFEST.sha256
# （mastersos-release-keys/ 下每个文件的 sha256，先五个文件、再 gpg/ 下 find -type f | sort）与 FINGERPRINTS.txt（四行：
# MOK DER 的 sha256、PCR 公钥 PKCS#1 DER 的 sha256 = systemd 的 pkfp、gpg 主钥指纹、考试扩展的 id）。
#   generate：db 与 PCR 是 RSA 2048、20 年（-days 7305），CN「MastersOS Secure Boot 2026」「MastersOS PCR 2026」；gpg 是 ed25519
#             只签名、不过期、uid「MastersOS updates 2026」；kiosk-ext.pem 是考试扩展（计划 9）的 crx 签名钥匙，RSA 2048 的
#             PKCS#8 PEM（kiosk-ext-pack.sh 要 ≥ 2048 位、不加密），扩展 id = sha256(公钥 DER) 前 16 字节、0–f 映射成 a–p。
#             私钥文件都不加口令：LUKS（write-stick）或 age（seal）是那一层（裁定 8）。
#   write-stick：只收可移动的 USB 盘（lsblk 的 TRAN,RM 是「usb 1」；MASTERSOS_TEST=1 时放过，只给 tests/ceremony-test.sh 的
#             loop 设备），打印型号与容量、要求输入 YES；口令从 stdin 读两次（不回显、不经参数，长度不限、不能为空）；
#             LUKS2 + argon2id、标签 MASTERSOS-KEYS-<A|B>，里面 ext4；写完关闭、再重新打开核对清单，不符退出 1。
#   seal: tar the <tmpfs dir> (same layout as a stick's root) and encrypt it with age's passphrase mode (scrypt). age reads the
#             passphrase from the terminal twice; it is then read a third time to decrypt into a scratch dir on the same tmpfs and
#             check the manifest (type it from the paper copy, so a miscopy shows up here). Only then is <out.age>.part renamed to
#             <out.age>. The file may live anywhere (S3); the passphrase is the only protection (user ruling 2026-10-27,
#             docs/key-ceremony.md).
#   export-public：写 mastersos-mok.der、tpm2-pcr-public-key.pem、import-pubring.pgp、kiosk-ext-public.pem 与 FINGERPRINTS.txt
#             （前四个拷回仓库的 keys/；keys-load.sh 拿它们核对 U 盘）。
#   wipe：同 keys-unload.sh：停 gpg-agent、shred -u 每个文件、rm -rf、核对目录已不存在。
set -euo pipefail
set +x      # 就算用 bash -x 跑，也不把口令打进跟踪输出
ulimit -c 0 # 不写 core dump（私钥与口令在内存里）

die() {
	echo "gen-release-keys: $*" >&2
	exit 1
}
usage() {
	sed -n '4,8p' "$0" | sed 's/^# *//' >&2
	exit 2
}
[ "$(id -u)" = 0 ] || die "要以 root 跑（离线机器上 sudo -i）"
umask 077

# 目录（或它不存在时的父目录）必须在 tmpfs / ramfs 上
need_tmpfs() {
	local p=$1 fs
	[ -e "$p" ] || p=$(dirname "$p")
	fs=$(stat -f -c %T "$p" 2>/dev/null) || fs='?'
	case "$fs" in tmpfs | ramfs) ;; *) die "$1 在 $fs 上：私钥只许放在 tmpfs（例如 /run/mastersos-ceremony）" ;; esac
}

# 有 swap（或读不出来）就不生成、不写盘：tmpfs 里的私钥与内存里的口令可能被换到磁盘上。
# 只给 tests/ceremony-test.sh：MASTERSOS_TEST=1 时改看 MASTERSOS_TEST_SWAP（非空当作有 swap），与 keyset.sh 相同
need_no_swap() {
	local s
	if [ "${MASTERSOS_TEST:-}" = 1 ]; then
		[ -z "${MASTERSOS_TEST_SWAP:-}" ] || die "有 swap（MASTERSOS_TEST_SWAP）：先 swapoff -a，或用 noswap 启动 live 系统"
		return 0
	fi
	s=$(swapon --show --noheadings 2>/dev/null) || die "读不出 swap 的状态（swapon --show 失败），不生成也不写盘"
	[ -z "$s" ] || die "这台机器有 swap：先 swapoff -a（最好用 noswap 启动 live 系统、拔掉内置硬盘）"
}

manifest_files() { # <mastersos-release-keys 目录>
	(cd "$1" && {
		printf '%s\n' db.key db.crt pcr.key pcr.crt kiosk-ext.pem
		find gpg -type f | LC_ALL=C sort
	})
}

# check_tree <根>：清单列的恰好是这些文件、sha256 都对
check_tree() {
	local r=$1
	{ [ -f "$r/MANIFEST.sha256" ] && [ -f "$r/FINGERPRINTS.txt" ] && [ -d "$r/mastersos-release-keys/gpg" ]; } ||
		{ echo "gen-release-keys: $r 缺 MANIFEST.sha256、FINGERPRINTS.txt 或 mastersos-release-keys/gpg/" >&2; return 1; }
	[ "$(manifest_files "$r/mastersos-release-keys")" = "$(sed -E 's/^[0-9a-f]{64}  //' "$r/MANIFEST.sha256")" ] ||
		{ echo "gen-release-keys: $r 的 MANIFEST.sha256 列的文件与实际不一致" >&2; return 1; }
	(cd "$r/mastersos-release-keys" && sha256sum --quiet --strict -c "$r/MANIFEST.sha256") ||
		{ echo "gen-release-keys: $r 的 MANIFEST.sha256 核对不过" >&2; return 1; }
}

# 考试扩展的 id（与 kiosk-ext-pack.py、Chrome 相同）：sha256(SubjectPublicKeyInfo 的 DER) 前 16 字节，十六进制 0–f 映射成 a–p
ext_id_of_key() { openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | sha256sum | cut -c1-32 | tr 0-9a-f a-p; }
ext_id_of_pub() { openssl pkey -pubin -in "$1" -outform DER 2>/dev/null | sha256sum | cut -c1-32 | tr 0-9a-f a-p; }

gpg_fpr() { # <homedir>：唯一一把主钥的指纹
	gpg --homedir "$1" --batch --with-colons --list-secret-keys 2>/dev/null |
		awk -F: '$1 == "sec" {s = 1; next} s && $1 == "fpr" {print $10; s = 0}'
}

cmd_generate() {
	local d=$1 k fpr ext
	need_no_swap
	need_tmpfs "$d"
	if [ -e "$d" ]; then
		{ [ -d "$d" ] && [ -z "$(ls -A "$d")" ]; } || die "$d 已经有东西了：换一个空目录"
		chmod 0700 "$d"
	else
		mkdir -p "$(dirname "$d")"
		mkdir -m 0700 "$d"
	fi
	k=$d/mastersos-release-keys
	mkdir -m 0700 "$k" "$k/gpg"
	echo "gen-release-keys: 生成 db（Secure Boot 与 verity）……"
	openssl req -new -x509 -newkey rsa:2048 -nodes -days 7305 -sha256 -subj "/CN=MastersOS Secure Boot 2026/" \
		-keyout "$k/db.key" -out "$k/db.crt" 2>/dev/null
	echo "gen-release-keys: 生成 PCR 签名钥匙……"
	openssl req -new -x509 -newkey rsa:2048 -nodes -days 7305 -sha256 -subj "/CN=MastersOS PCR 2026/" \
		-keyout "$k/pcr.key" -out "$k/pcr.crt" 2>/dev/null
	echo "gen-release-keys: 生成考试扩展的签名钥匙……"
	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$k/kiosk-ext.pem" 2>/dev/null
	echo "gen-release-keys: 生成更新源的 gpg 钥匙……"
	# 等同 --quick-gen-key 'MastersOS updates 2026' ed25519 sign never，无口令：参数从 stdin 给（%no-protection），不经命令行
	printf '%s\n' '%no-protection' 'Key-Type: eddsa' 'Key-Curve: ed25519' 'Key-Usage: sign' \
		'Name-Real: MastersOS updates 2026' 'Expire-Date: 0' '%commit' |
		gpg --homedir "$k/gpg" --batch --generate-key 2>/dev/null
	fpr=$(gpg_fpr "$k/gpg")
	gpgconf --homedir "$k/gpg" --kill all >/dev/null 2>&1 || true
	[[ $fpr =~ ^[0-9A-F]{40}$ ]] || die "gpg 钥匙没生成出来（或不止一把）"
	# 套接字与 gpg 的备份文件不进清单
	find "$k/gpg" ! -type f ! -type d -delete
	find "$k/gpg" -type f -name '*~' -delete
	chmod 0600 "$k/db.key" "$k/pcr.key" "$k/kiosk-ext.pem"
	ext=$(ext_id_of_key "$k/kiosk-ext.pem")
	[[ $ext =~ ^[a-p]{32}$ ]] || die "考试扩展的钥匙没生成出来（算不出 id）"
	(cd "$k" && manifest_files . | while read -r f; do sha256sum -- "$f"; done) >"$d/MANIFEST.sha256"
	{
		echo "mok-der-sha256 $(openssl x509 -in "$k/db.crt" -outform DER | sha256sum | cut -d' ' -f1)"
		echo "pcr-pkfp $(openssl x509 -in "$k/pcr.crt" -pubkey -noout | openssl rsa -pubin -RSAPublicKey_out -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)"
		echo "gpg-fingerprint $fpr"
		echo "kiosk-ext-id $ext"
	} >"$d/FINGERPRINTS.txt"
	check_tree "$d" || die "刚生成的清单就核对不过"
	echo "gen-release-keys: 生成好了。指纹（手抄到纸上）："
	sed 's/^/    /' "$d/FINGERPRINTS.txt"
}

read_pass() { # 从 stdin 读两次口令（不回显），放进全局 pass；只在 shell 变量里，不经 here-string（旧 bash 会写临时文件）
	local p2
	{ set +x; } 2>/dev/null
	[ -t 0 ] && printf 'Passphrase: ' >&2
	IFS= read -rs pass || die "没读到口令"
	[ -t 0 ] && printf '\n再输一次：' >&2
	IFS= read -rs p2 || die "没读到第二次口令"
	[ -t 0 ] && printf '\n' >&2
	[ "$pass" = "$p2" ] || die "两次口令不一样"
	p2=""
	# Any length (user ruling 2026-10-27 replaces ruling 10's seven-word minimum), just not empty
	[ -n "$pass" ] || die "the passphrase is empty"
}

cmd_write_stick() {
	local d=$1 dev=$2 which=$3 label map info ans mnt
	case "$which" in A | B) ;; *) usage ;; esac
	label=MASTERSOS-KEYS-$which map=mastersos-ceremony-$which
	need_tmpfs "$d"
	check_tree "$d" || die "$d 不是 generate 生成的完整目录"
	[ -b "$dev" ] || die "$dev 不是块设备"
	info=$(lsblk -dno TRAN,RM "$dev" | tr -s ' ' | sed 's/^ //; s/ $//')
	if [ "$info" != "usb 1" ]; then
		if [ "${MASTERSOS_TEST:-}" = 1 ]; then
			echo "gen-release-keys: 警告：MASTERSOS_TEST=1，$dev 不是可移动的 USB 盘（$info）也照写（只给测试）" >&2
		else
			die "$dev 不是可移动的 USB 盘（lsblk TRAN,RM：'$info'，应是 'usb 1'）"
		fi
	fi
	need_no_swap
	if lsblk -nro MOUNTPOINTS "$dev" 2>/dev/null | grep -q .; then
		die "$dev（或它的分区）正挂载着"
	fi
	echo "要写的盘：$dev  $(lsblk -dno MODEL,SIZE,SERIAL "$dev" | tr -s ' ')"
	echo "盘上的一切都会被抹掉，写成 U 盘 ${which}（$label）。确定就输入 YES："
	IFS= read -r ans || die "没读到确认"
	[ "$ans" = YES ] || die "没有输入 YES，什么都没做"
	read_pass

	echo "gen-release-keys: luksFormat（argon2id，要几秒）……"
	wipefs -aq "$dev"
	printf '%s' "$pass" | cryptsetup luksFormat --batch-mode --type luks2 --pbkdf argon2id --label "$label" --key-file=- "$dev"
	printf '%s' "$pass" | cryptsetup open --type luks2 --key-file=- "$dev" "$map"
	mnt=$(mktemp -d)
	# shellcheck disable=SC2064
	trap "umount '$mnt' 2>/dev/null || true; cryptsetup close '$map' 2>/dev/null || true; rmdir '$mnt' 2>/dev/null || true" EXIT
	mkfs.ext4 -q -m 0 "/dev/mapper/$map"
	mount -o nodev,nosuid,noexec "/dev/mapper/$map" "$mnt"
	# 盘上的文件给 VM 161 的 mastersos 用户读（0644 / 0755）：保护是 LUKS 本身，keys-load.sh 挂在一个 0700 的目录下面
	cp -r --no-preserve=mode "$d/mastersos-release-keys" "$d/MANIFEST.sha256" "$d/FINGERPRINTS.txt" "$mnt/"
	chmod -R u=rwX,go=rX "$mnt/mastersos-release-keys" "$mnt/MANIFEST.sha256" "$mnt/FINGERPRINTS.txt"
	chmod 0755 "$mnt"
	rm -rf "$mnt/lost+found"
	sync
	umount "$mnt"
	cryptsetup close "$map"
	# 重新打开（只读）核对：读回来的与 tmpfs 里的一致
	echo "gen-release-keys: 重新打开核对……"
	printf '%s' "$pass" | cryptsetup open --readonly --type luks2 --key-file=- "$dev" "$map"
	pass=""
	mount -o ro,nodev,nosuid,noexec "/dev/mapper/$map" "$mnt"
	if ! check_tree "$mnt" || ! cmp -s "$mnt/MANIFEST.sha256" "$d/MANIFEST.sha256" || ! cmp -s "$mnt/FINGERPRINTS.txt" "$d/FINGERPRINTS.txt"; then
		die "U 盘 $which 读回来核对不过：换一根盘重写"
	fi
	umount "$mnt"
	cryptsetup close "$map"
	rmdir "$mnt"
	trap - EXIT
	echo "gen-release-keys: U 盘 ${which}（$label）写好、重新打开核对过了"
}

# Wipe a directory on tmpfs (no gpg-agent to stop: nothing runs gpg in seal's check dir)
shred_dir() {
	find "$1" -xdev -type f -exec shred -u -- {} + 2>/dev/null
	rm -rf -- "$1"
}

cmd_seal() {
	local d=$1 out=$2 v
	need_tmpfs "$d"
	check_tree "$d" || die "$d 不是 generate 生成的完整目录"
	need_no_swap
	command -v age >/dev/null || die "age is missing"
	{ [ ! -e "$out" ] && [ ! -e "$out.part" ]; } || die "$out (or $out.part) already exists: pick another name"
	v=$d.verify
	need_tmpfs "$v"
	[ ! -e "$v" ] || die "$v already exists: a previous seal did not clean up? wipe it first"
	echo "gen-release-keys: encrypting with age (scrypt). Enter the passphrase twice (any length; if left empty age generates one and shows it)"
	if ! tar -C "$d" --owner=0 --group=0 --numeric-owner -cf - MANIFEST.sha256 FINGERPRINTS.txt mastersos-release-keys |
		age -p -o "$out.part"; then
		rm -f -- "$out.part"
		die "age failed, $out not written"
	fi
	mkdir -m 0700 "$v"
	echo "gen-release-keys: decrypting to check: type the passphrase once more, from the paper copy"
	if ! age -d "$out.part" | tar -C "$v" -xf - || ! check_tree "$v" ||
		! cmp -s "$v/MANIFEST.sha256" "$d/MANIFEST.sha256" || ! cmp -s "$v/FINGERPRINTS.txt" "$d/FINGERPRINTS.txt"; then
		shred_dir "$v"
		rm -f -- "$out.part"
		die "the decrypted copy does not match (passphrase mistyped?), $out not written: seal again"
	fi
	shred_dir "$v"
	[ ! -e "$v" ] || die "$v is still there, wipe failed"
	mv -- "$out.part" "$out"
	echo "gen-release-keys: sealed and checked by decrypting: $out (sha256 $(sha256sum "$out" | cut -c1-64))"
}

cmd_export_public() {
	local d=$1 o=$2 k=$1/mastersos-release-keys
	check_tree "$d" || die "$d 不是 generate 生成的完整目录"
	mkdir -p "$o"
	openssl x509 -in "$k/db.crt" -outform DER -out "$o/mastersos-mok.der"
	openssl x509 -in "$k/pcr.crt" -pubkey -noout >"$o/tpm2-pcr-public-key.pem"
	gpg --homedir "$k/gpg" --batch --export >"$o/import-pubring.pgp" 2>/dev/null
	gpgconf --homedir "$k/gpg" --kill all >/dev/null 2>&1 || true
	openssl pkey -in "$k/kiosk-ext.pem" -pubout -out "$o/kiosk-ext-public.pem" 2>/dev/null
	cp "$d/FINGERPRINTS.txt" "$o/FINGERPRINTS.txt"
	chmod 0644 "$o/mastersos-mok.der" "$o/tpm2-pcr-public-key.pem" "$o/import-pubring.pgp" "$o/kiosk-ext-public.pem" "$o/FINGERPRINTS.txt"
	# 导出的只能是公钥
	if grep -qF 'PRIVATE'' KEY' "$o/tpm2-pcr-public-key.pem" "$o/kiosk-ext-public.pem" ||
		gpg --batch --list-packets "$o/import-pubring.pgp" 2>/dev/null | grep -qi 'secret'; then
		die "导出的文件里有私钥"
	fi
	[ "$(gpg --batch --no-default-keyring --show-keys --with-colons "$o/import-pubring.pgp" 2>/dev/null |
		awk -F: '$1 == "pub" {s = 1; next} s && $1 == "fpr" {print $10; s = 0}')" = "$(sed -n 's/^gpg-fingerprint //p' "$d/FINGERPRINTS.txt")" ] ||
		die "导出的 import-pubring.pgp 指纹与 FINGERPRINTS.txt 不符"
	[ "$(ext_id_of_pub "$o/kiosk-ext-public.pem")" = "$(sed -n 's/^kiosk-ext-id //p' "$d/FINGERPRINTS.txt")" ] ||
		die "导出的 kiosk-ext-public.pem 算出的 id 与 FINGERPRINTS.txt 不符"
	echo "gen-release-keys: 公钥写到 $o（mastersos-mok.der、tpm2-pcr-public-key.pem、import-pubring.pgp、kiosk-ext-public.pem、FINGERPRINTS.txt）"
}

cmd_wipe() {
	local d=$1
	if [ ! -e "$d" ] && [ ! -L "$d" ]; then
		echo "gen-release-keys: $d 不存在，没有要抹的"
		return 0
	fi
	{ [ -d "$d" ] && [ ! -L "$d" ]; } || die "$d 不是目录"
	case "$(cd "$d" && pwd -P)" in / | /run | /tmp | /var/tmp | /dev/shm | /root | /home) die "拒绝抹 $d" ;; esac
	[ -d "$d/mastersos-release-keys/gpg" ] && { gpgconf --homedir "$d/mastersos-release-keys/gpg" --kill all >/dev/null 2>&1 || true; }
	find "$d" -xdev -type f -exec shred -u -- {} +
	rm -rf -- "$d"
	[ ! -e "$d" ] || die "$d 还在，抹掉失败"
	echo "gen-release-keys: 已抹掉 $d"
}

case "${1:-}" in
generate) [ $# = 2 ] || usage; cmd_generate "$2" ;;
write-stick) [ $# = 4 ] || usage; cmd_write_stick "$2" "$3" "$4" ;;
seal) [ $# = 3 ] || usage; cmd_seal "$2" "$3" ;;
export-public) [ $# = 3 ] || usage; cmd_export_public "$2" "$3" ;;
wipe) [ $# = 2 ] || usage; cmd_wipe "$2" ;;
*) usage ;;
esac
