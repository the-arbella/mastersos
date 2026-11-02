#!/bin/bash
# 签名会话开始：从正式钥匙的加密 U 盘把私钥读进 tmpfs（计划 5 Task 4，裁定 9、10）。在 VM 161 上以 mastersos 用户跑：
#   keys-load.sh A|B [--verify-only] [--no-repo-check]
#   keys-load.sh --age <mastersos-release-keys.age> [--verify-only] [--no-repo-check]
#     (bundle sealed by gen-release-keys.sh seal and kept in S3, user ruling 2026-10-27: age asks for the passphrase on the
#     terminal, decrypts into a 0700 scratch dir on /dev/shm, and from there it is the same check-and-copy as a stick)
# U 盘由 ceremony/gen-release-keys.sh write-stick 写成：LUKS2（标签 MASTERSOS-KEYS-A / MASTERSOS-KEYS-B），里面 ext4，
# 根目录 mastersos-release-keys/{db.key,db.crt,pcr.key,pcr.crt,kiosk-ext.pem,gpg/}、MANIFEST.sha256 与 FINGERPRINTS.txt。
# 步骤：核对没有 swap → 等 /dev/disk/by-label/MASTERSOS-KEYS-<A|B> 出现（最多 120 秒）→ cryptsetup open --readonly（口令由
# cryptsetup 自己从终端读，不经参数）→ 只读挂载 → 核对 MANIFEST.sha256 → 拷进 /run/mastersos-release-keys（0700，文件 0600）
# → 与仓库的四份公钥核对（mastersos-mok.der、tpm2-pcr-public-key.pem、import-pubring.pgp、kiosk-ext-public.pem）→ 卸载、关闭 → 「可以拔掉 U 盘」。之后 build.sh / make-installer.sh / publish.sh 经
# keyset_priv release 读它，会话结束跑 keys-unload.sh。
#   --verify-only    核对完就抹掉 tmpfs 里的副本（每半年的演练，docs/key-ceremony.md）
#   --no-repo-check  不与仓库的公钥核对，只认 MANIFEST.sha256 并打印 FINGERPRINTS.txt；只许与 --verify-only 同用
#                    （正式公钥入库之前，仓库里还是预发布的公钥）
# 仓库公钥与 U 盘不符、任何一步失败或被 INT/TERM/HUP 打断 → 抹掉副本（抹不掉就说出来、退出非 0）。sudo 只用于 cryptsetup、mount/umount 与在 /run 下建这一个目录。
# 只给测试（要同时 MASTERSOS_TEST=1）：MASTERSOS_RELEASE_KEYS 换目标目录，MASTERSOS_PUB_DIR 换仓库公钥的目录，
# MASTERSOS_TEST_SWAP 见 keyset.sh。被 source 时只定义函数（tests/ceremony-test.sh 用 kl_check_stick 与 kl_repo_check）。
set -euo pipefail

kl_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR source=keyset.sh
. "$kl_here/keyset.sh"

kl_die() {
	echo "keys-load.sh: $*" >&2
	exit 1
}
kl_as_root() { if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi; }

# kl_check_stick <U 盘的根>：MANIFEST.sha256 列的恰好是 mastersos-release-keys/ 下的五个文件加 gpg/ 的全部文件，且 sha256 都对
# （与 ceremony/gen-release-keys.sh 的 manifest_files 同一份名单，tests/check-tree.sh 第 35 条核对两边一致）
kl_check_stick() {
	local r=$1 want have
	{ [ -f "$r/MANIFEST.sha256" ] && [ -f "$r/FINGERPRINTS.txt" ] && [ -d "$r/mastersos-release-keys/gpg" ]; } || {
		echo "keys-load.sh: $r 不像正式钥匙的 U 盘（缺 MANIFEST.sha256、FINGERPRINTS.txt 或 mastersos-release-keys/gpg/）" >&2
		return 1
	}
	want=$(cd "$r/mastersos-release-keys" && { printf '%s\n' db.key db.crt pcr.key pcr.crt kiosk-ext.pem; find gpg -type f | LC_ALL=C sort; })
	have=$(sed -E 's/^[0-9a-f]{64}  //' "$r/MANIFEST.sha256")
	if [ "$want" != "$have" ]; then
		echo "keys-load.sh: MANIFEST.sha256 列的文件与 U 盘上的不一致" >&2
		diff <(echo "$have") <(echo "$want") >&2 || true
		return 1
	fi
	grep -qvE '^[0-9a-f]{64}  [^/][^[:cntrl:]]*$' "$r/MANIFEST.sha256" && {
		echo "keys-load.sh: MANIFEST.sha256 有格式不对的行" >&2
		return 1
	}
	(cd "$r/mastersos-release-keys" && sha256sum --quiet --strict -c "$r/MANIFEST.sha256") || {
		echo "keys-load.sh: MANIFEST.sha256 核对不过：U 盘上的钥匙坏了或被改过" >&2
		return 1
	}
}

# kl_copy <U 盘的根> <目标目录>：按清单逐个拷（目录 0700，文件 0600），再用同一份清单核对一遍
kl_copy() {
	local r=$1 d=$2 f
	while read -r _ f; do
		install -d -m 0700 "$d/$(dirname "$f")"
		install -m 0600 "$r/mastersos-release-keys/$f" "$d/$f"
	done <"$r/MANIFEST.sha256"
	(cd "$d" && sha256sum --quiet --strict -c "$r/MANIFEST.sha256") || {
		echo "keys-load.sh: 拷进 $d 之后清单核对不过" >&2
		return 1
	}
}

# kl_repo_check <私钥目录> <公钥目录>：四把钥匙与仓库的公钥对得上，私钥与自己的证书也对得上。kiosk-ext.pem（考试扩展，计划 9）
# 对 kiosk-ext-public.pem：公钥相同，扩展 id 就相同——build.sh 打进镜像的 kiosk-ext.json 与宿主清单的 id 就是仓库记的那个
kl_repo_check() {
	local k=$1 p=$2 rc=0 a b
	pubder() { openssl pkey -pubin -in "$1" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1; }
	keyder() { openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1; }
	certder() { openssl x509 -in "$1" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1; }
	a=$(openssl x509 -in "$k/db.crt" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)
	b=$(sha256sum <"$p/mastersos-mok.der" | cut -d' ' -f1)
	[ "$a" = "$b" ] || {
		echo "keys-load.sh: db.crt 的 DER 不等于 $p/mastersos-mok.der" >&2
		rc=1
	}
	[ "$(keyder "$k/db.key")" = "$(certder "$k/db.crt")" ] || {
		echo "keys-load.sh: db.key 与 db.crt 不是一对" >&2
		rc=1
	}
	[ "$(certder "$k/pcr.crt")" = "$(pubder "$p/tpm2-pcr-public-key.pem")" ] || {
		echo "keys-load.sh: pcr.crt 的公钥不等于 $p/tpm2-pcr-public-key.pem" >&2
		rc=1
	}
	[ "$(keyder "$k/pcr.key")" = "$(certder "$k/pcr.crt")" ] || {
		echo "keys-load.sh: pcr.key 与 pcr.crt 不是一对" >&2
		rc=1
	}
	if [ ! -s "$p/kiosk-ext-public.pem" ]; then
		echo "keys-load.sh: 缺少 $p/kiosk-ext-public.pem（仪式 export-public 写的考试扩展公钥，拷进仓库的 keys/）" >&2
		rc=1
	else
		# 读不懂的一边算出的是空输入的 sha256：两边都读不懂时不能算「相同」
		a=$(keyder "$k/kiosk-ext.pem") b=$(pubder "$p/kiosk-ext-public.pem")
		if [ "$a" != "$b" ] || [ "$a" = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ]; then
			echo "keys-load.sh: kiosk-ext.pem 的公钥不等于 $p/kiosk-ext-public.pem（或有一边读不懂）" >&2
			rc=1
		fi
	fi
	a=$(gpg --homedir "$k/gpg" --batch --with-colons --list-secret-keys 2>/dev/null | awk -F: '$1 == "sec" {s = 1; next} s && $1 == "fpr" {print $10; s = 0}')
	b=$(gpg --batch --no-default-keyring --show-keys --with-colons "$p/import-pubring.pgp" 2>/dev/null | awk -F: '$1 == "pub" {s = 1; next} s && $1 == "fpr" {print $10; s = 0}')
	gpgconf --homedir "$k/gpg" --kill all >/dev/null 2>&1 || true
	if [ -z "$a" ] || [ "$(wc -l <<<"$a")" != 1 ] || [ "$a" != "$b" ]; then
		echo "keys-load.sh: gpg/ 的主钥指纹（${a:-无}）不等于 $p/import-pubring.pgp 的（${b:-无}）" >&2
		rc=1
	fi
	return $rc
}

# 退出时的清理（EXIT；INT/TERM/HUP 先 exit 130 再到这里）：kl_keep=0 时先抹掉 $kl_dest（keys-unload.sh），再卸载、关闭
# U 盘——卸载或关闭失败不影响抹掉。kl_keep 为空：还没建目标目录，没有要抹的；=1：签名会话，留着。
kl_keep="" kl_dest="" kl_mnt="" kl_tmpd="" kl_map="" kl_sleep="" kl_stage=""
kl_cleanup() {
	local rc=$?
	set +e
	# 清理期间忽略信号（子进程也继承）：再按一次 Ctrl-C 不会把抹到一半的 keys-unload.sh 打断
	trap '' INT TERM HUP
	trap - EXIT
	[ -z "$kl_sleep" ] || kill "$kl_sleep" 2>/dev/null
	if [ "$kl_keep" = 0 ]; then
		if "$kl_here/keys-unload.sh" >/dev/null; then
			echo "keys-load.sh: 没有载入完（rc=$rc），tmpfs 里的副本已抹掉" >&2
		else
			echo "keys-load.sh: 抹掉失败，手动跑 keys-unload.sh（$kl_dest）" >&2
			[ "$rc" != 0 ] || rc=1
		fi
	fi
	if [ -n "$kl_mnt" ] && mountpoint -q "$kl_mnt" 2>/dev/null; then
		kl_as_root umount "$kl_mnt" || echo "keys-load.sh: 卸载 $kl_mnt 失败" >&2
	fi
	if [ -n "$kl_map" ] && [ -e "/dev/mapper/$kl_map" ]; then
		kl_as_root cryptsetup close "$kl_map" || echo "keys-load.sh: cryptsetup close $kl_map 失败" >&2
	fi
	if [ -n "$kl_stage" ] && [ -d "$kl_tmpd" ]; then
		# --age: the decrypted bundle sits in the scratch dir, wipe it like keys-unload.sh does
		find "$kl_tmpd" -xdev -type f -exec shred -u -- {} + 2>/dev/null
		rm -rf -- "$kl_tmpd"
		[ ! -e "$kl_tmpd" ] || {
			echo "keys-load.sh: could not wipe $kl_tmpd, remove it by hand" >&2
			[ "$rc" != 0 ] || rc=1
		}
	elif [ -n "$kl_tmpd" ]; then
		rmdir "$kl_mnt" "$kl_tmpd" 2>/dev/null
	fi
	exit "$rc"
}

# 只给 tests/ceremony-test.sh（要 MASTERSOS_TEST=1）：在某一步模拟意外失败（MASTERSOS_TEST_FAIL_AT）或停下等信号
# （MASTERSOS_TEST_PAUSE_AT，停之前 touch MASTERSOS_TEST_PAUSE_FILE）
kl_test_hook() {
	[ "${MASTERSOS_TEST:-}" = 1 ] || return 0
	if [ "${MASTERSOS_TEST_FAIL_AT:-}" = "$1" ]; then
		echo "keys-load.sh: MASTERSOS_TEST_FAIL_AT=$1：模拟失败" >&2
		false
	fi
	if [ "${MASTERSOS_TEST_PAUSE_AT:-}" = "$1" ]; then
		touch "${MASTERSOS_TEST_PAUSE_FILE:?}"
		# shellcheck disable=SC2217 # 不让 sleep 继承调用者的 stdin（测试里是 tmpfs 上的文件，会卡住卸载）
		sleep 60 </dev/null >/dev/null 2>&1 &
		kl_sleep=$!
		wait $!
	fi
}

# kl_open_stick A|B：等 U 盘出现、cryptsetup 打开、只读挂到 $kl_mnt、核对清单
kl_open_stick() {
	local stick=$1 label=MASTERSOS-KEYS-$1 dev i n
	[ ! -e "/dev/mapper/mastersos-keys-$stick" ] || kl_die "/dev/mapper/mastersos-keys-$stick 已经开着：先 sudo cryptsetup close mastersos-keys-$stick"
	echo "keys-load.sh: 插上 U 盘 ${stick}（PVE 上 qm set 161 -usb1 host=<vid:pid>），等 /dev/disk/by-label/$label ……"
	for ((i = 0; i < 120; i++)); do
		[ -e "/dev/disk/by-label/$label" ] && break
		sleep 1
	done
	[ -e "/dev/disk/by-label/$label" ] || kl_die "120 秒内没看到 /dev/disk/by-label/$label"
	n=$(lsblk -rno LABEL | grep -cxF "$label" || true)
	[ "$n" = 1 ] || kl_die "有 $n 个设备的标签是 ${label}，只插一根"
	dev=$(readlink -f "/dev/disk/by-label/$label")

	trap kl_cleanup EXIT
	trap 'exit 130' INT TERM HUP
	kl_tmpd=$(mktemp -d) # 0700：挂载点在它下面，别的用户进不去
	kl_mnt=$kl_tmpd/stick
	mkdir "$kl_mnt"

	echo "keys-load.sh: 打开 ${dev}（输入 U 盘的口令）"
	kl_map=mastersos-keys-$stick
	kl_as_root cryptsetup open --readonly --type luks2 "$dev" "$kl_map" || kl_die "cryptsetup open 失败"
	kl_as_root mount -o ro,nodev,nosuid,noexec "/dev/mapper/$kl_map" "$kl_mnt" || kl_die "挂载失败"
	kl_check_stick "$kl_mnt" || exit 1
}

# kl_load_age <file.age>: age (passphrase from the terminal) decrypts the bundle into $kl_mnt, a 0700 scratch dir on /dev/shm
# (tmpfs), then the manifest is checked like a stick's. kl_cleanup shreds the scratch dir on every exit.
kl_load_age() {
	local f=$1 fs
	{ [ -f "$f" ] && [ -r "$f" ]; } || kl_die "cannot read $f"
	command -v age >/dev/null || kl_die "age is missing (sudo apt install age)"
	trap kl_cleanup EXIT
	trap 'exit 130' INT TERM HUP
	kl_stage=1
	kl_tmpd=$(mktemp -d -p /dev/shm mastersos-keys.XXXXXX) || kl_die "cannot create a scratch dir on /dev/shm"
	fs=$(stat -f -c %T "$kl_tmpd" 2>/dev/null) || fs='?'
	case "$fs" in tmpfs | ramfs) ;; *) kl_die "/dev/shm is on $fs, not tmpfs: not decrypting there" ;; esac
	kl_mnt=$kl_tmpd/bundle
	mkdir -m 0700 "$kl_mnt"
	echo "keys-load.sh: decrypting $f (enter the passphrase)"
	age -d "$f" | tar -C "$kl_mnt" --no-same-owner -xf - || kl_die "could not decrypt $f (wrong passphrase?)"
	kl_test_hook age-decrypted
	kl_check_stick "$kl_mnt" || exit 1
}

kl_main() {
	local stick="" age_file="" verify_only=0 no_repo=0 pub src done_msg
	while [ $# -gt 0 ]; do
		case "$1" in
		A | B) stick=$1 ;;
		--age)
			{ [ $# -ge 2 ] && [ -n "$2" ]; } || {
				echo "usage: keys-load.sh --age <file.age> [--verify-only] [--no-repo-check]" >&2
				exit 2
			}
			age_file=$2
			shift
			;;
		--verify-only) verify_only=1 ;;
		--no-repo-check) no_repo=1 ;;
		*)
			echo "usage: keys-load.sh A|B|--age <file.age> [--verify-only] [--no-repo-check]" >&2
			exit 2
			;;
		esac
		shift
	done
	# exactly one source: stick A, stick B, or an age bundle
	if [ -z "$stick$age_file" ] || { [ -n "$stick" ] && [ -n "$age_file" ]; }; then
		echo "usage: keys-load.sh A|B|--age <file.age> [--verify-only] [--no-repo-check]" >&2
		exit 2
	fi
	if [ "$no_repo" = 1 ] && [ "$verify_only" = 0 ]; then
		echo "keys-load.sh: --no-repo-check 只许与 --verify-only 同用：没与仓库公钥核对过的钥匙不留下来签名" >&2
		exit 2
	fi
	if [ -n "${MASTERSOS_RELEASE_KEYS:-}${MASTERSOS_PUB_DIR:-}" ] && [ "${MASTERSOS_TEST:-}" != 1 ]; then
		echo "keys-load.sh: MASTERSOS_RELEASE_KEYS / MASTERSOS_PUB_DIR 只给测试用（要同时 MASTERSOS_TEST=1）" >&2
		exit 2
	fi
	if [ "${MASTERSOS_TEST:-}" = 1 ] && [ -z "${MASTERSOS_RELEASE_KEYS:-}" ]; then
		echo "keys-load.sh: MASTERSOS_TEST=1 时 swap 检查读 MASTERSOS_TEST_SWAP、不查真的——只许配测试目录 MASTERSOS_RELEASE_KEYS 用；真载入前 unset MASTERSOS_TEST" >&2
		exit 2
	fi
	ulimit -c 0 # 本进程与子进程不写 core dump
	kl_dest=${MASTERSOS_RELEASE_KEYS:-/run/mastersos-release-keys}
	pub=${MASTERSOS_PUB_DIR:-$(keyset_pub release)}

	! keyset_swap_on || kl_die "这台机器有 swap（swapon --show 不为空）：tmpfs 里的私钥可能被换到磁盘上，不载入"
	[ ! -e "$kl_dest" ] || kl_die "$kl_dest 已经在了：上一次会话没有 keys-unload.sh？先跑它"
	if [ -n "$age_file" ]; then
		kl_load_age "$age_file"
		src="the age bundle"
	else
		kl_open_stick "$stick"
		src="stick $stick"
	fi

	# 用 mkdir 不用 install -d：目录已经在（另一个会话同时在载入）时这里就失败，不会把 kl_keep 置 0 去抹别人的钥匙
	if [ -n "${MASTERSOS_RELEASE_KEYS:-}" ]; then
		mkdir -m 0700 "$kl_dest" || kl_die "建不了 $kl_dest（已经在了？）"
		kl_keep=0 # 从这里起，除了签名会话成功，任何退出都抹掉 $kl_dest
	else
		kl_as_root mkdir -m 0700 "$kl_dest" || kl_die "建不了 $kl_dest（已经在了？）"
		kl_keep=0
		kl_as_root chown "$(id -u):$(id -g)" "$kl_dest" || kl_die "改不了 $kl_dest 的属主"
	fi
	# 拷之前先核对目标在 tmpfs 上、0700、属主对、没有 swap
	keyset_priv release >/dev/null || kl_die "目标目录不合格（见上），没有拷"
	kl_copy "$kl_mnt" "$kl_dest" || kl_die "载入失败"
	keyset_priv release >/dev/null || kl_die "载入之后目标目录不合格（见上）"
	kl_test_hook repo-check
	if [ "$no_repo" = 1 ]; then
		echo "keys-load.sh: --no-repo-check：不与仓库公钥核对，只核对了 MANIFEST.sha256。${src} 上记的指纹："
		sed 's/^/    /' "$kl_mnt/FINGERPRINTS.txt"
	elif ! kl_repo_check "$kl_dest" "$pub"; then
		kl_die "${src} 的钥匙与仓库的公钥（${pub}）对不上"
	else
		echo "keys-load.sh: 四把钥匙与仓库的公钥（${pub}）对得上"
	fi

	if [ -n "$stick" ]; then
		kl_as_root umount "$kl_mnt"
		kl_as_root cryptsetup close "$kl_map"
		kl_map=""
		done_msg="可以拔掉 U 盘（PVE 上 qm set 161 -delete usb1）"
	else
		done_msg="the decrypted scratch copy on /dev/shm is wiped on exit"
	fi
	if [ "$verify_only" = 1 ]; then
		"$kl_here/keys-unload.sh" >/dev/null || kl_die "抹掉失败，手动跑 keys-unload.sh（$kl_dest）"
		kl_keep=""
		echo "keys-load.sh: ${src} 核对通过（--verify-only，副本已抹掉）。$done_msg"
	else
		kl_keep=1
		echo "keys-load.sh: 正式私钥已在 ${kl_dest}。${done_msg}；签完跑 keys-unload.sh"
	fi
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	kl_main "$@"
fi
