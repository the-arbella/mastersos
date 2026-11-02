#!/bin/bash
# publish.sh 与 promote.sh 共用（被 source，不单独跑）。在构建机 VM 161 上用。
#
# 更新源是纯静态目录（Ruling 4）：<根>/<通道>/ 下放 SHA256SUMS、SHA256SUMS.gpg 和每个版本的四个文件
#   MastersOS_<v>_x86-64.usr-x86-64.<uuid>.raw.zst          /usr（erofs）
#   MastersOS_<v>_x86-64.usr-x86-64-verity.<uuid>.raw.zst   dm-verity 哈希树
#   MastersOS_<v>_x86-64.usr-x86-64-verity-sig.<uuid>.raw.zst  roothash 的签名
#   MastersOS_<v>_x86-64.efi                                 UKI（sysupdate 装成 +3 带启动计数）
#   MastersOS_<v>_x86-64.build-info.txt                      build.sh 写的构建信息（promote 时据此再把关一次）
#   MastersOS_<v>_x86-64.shim.bin                            镜像里 /usr/lib/mastersos/esp/BOOTX64.EFI 的副本（4b Task 22：换 shim 时
#                                                         promote 也要验它的证书链；sysupdate 不下载它，Task 22 之前的版本没有）
# 每个通道只留最近 KEEP 个版本。
#
# 每棵根必须有 <根>/mastersos-root.conf，声明它对外的地址与是不是试验网的根：
#   base=https://updates.example.org/mastersos     # 机器上 transfer 的 @BASE@ 必须正好是它
#   lab=no                                      # yes 才收 lab profile 与 --broken 的构建
#   mirror_s3=s3://<桶>  mirror_cdn=<DistributionId>   # 可选，只许 lab=no 的根，两个一起写；sync-s3.sh 往那里镜像
#   chrome_base=https://<主机>/…/chrome             # 可选，只许 lab=yes 的根：<根>/chrome/ 对外的 https 地址（考试扩展，计划 9 Task 8）。
#                                               试验网的 base 是 http，Chrome 只从 https 装强制安装的扩展；lab=no 的根固定是 <base>/chrome
# publish/promote 只发 build-info 的 update_base 等于这里的 base 的构建；lab=no 的根拒绝 profile=lab 与
# broken= 非空的构建（lab 构建带 sshd、自动登录的试验用户和试验网的 http 源，发出去的机器就再也收不到
# 正式通道的更新）。
# 根与钥匙一一对应（4b Task 1，Ruling 19；keyset.sh）：
#   lab=yes：只收 profile=lab 的构建，用 $MASTERSOS_KEYS/lab/gpg 签，check_uki 对 keys/lab/tpm2-pcr-public-key.pem，
#            验签用 keys/lab/import-pubring.pgp（正式构建发进来也装不上：正式镜像只信正式的 gpg 公钥）；
#   lab=no： 只收 profile=release 的构建，用 tmpfs 里的正式 gpg/ 签（keyset_priv release，先 keys-load.sh），对 keys/ 的公钥。
#
# 环境变量：
#   MASTERSOS_PUBLISH_ROOT  通道目录的根，默认 /var/www/html/mastersos（试验网的 nginx，= lab 镜像的 MASTERSOS_UPDATE_BASE）
#   MASTERSOS_KEYS          lab 的钥匙目录，默认 ~/mastersos-keys（lab/gpg/ 签 lab 根的 SHA256SUMS）
#   MASTERSOS_RELEASE_KEYS  正式私钥目录，默认 /run/mastersos-release-keys（keys-load.sh 载入的 tmpfs；gpg/ 签正式根的）
#   MASTERSOS_OUTPUT_DIR    build.sh 的产物目录，默认 <本目录>/mkosi.output
#   MASTERSOS_PUBRING       只给 tests/publish-test.sh：换掉正式根验签用的公钥；与 MASTERSOS_TEST=1 同时设才生效
#                        （并在 stderr 警告），单独设就拒绝运行
#   MASTERSOS_PUBRING_LAB   同上，换掉 lab 根验签用的公钥
#   MASTERSOS_MS_CA_DIR     只给 tests/publish-test.sh：换掉 keys/microsoft/（换 shim 时验证书链的两张微软 CA）；同样要 MASTERSOS_TEST=1
#   MASTERSOS_DBX_DIR       只给 tests/publish-test.sh：换掉 keys/microsoft/dbx/（吊销的证书 *.der 与 sha256.txt，见 keyset.sh）；同样要 MASTERSOS_TEST=1
set -euo pipefail

CHANNELS="stable beta"
KEEP=3
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR source=keyset.sh
. "$here/keyset.sh"
root=${MASTERSOS_PUBLISH_ROOT:-/var/www/html/mastersos}
# 只给 tests/publish-test.sh：要同时有 MASTERSOS_TEST=1 才换掉信任的公钥，而且每次都在 stderr 说出来；
# 只设了 MASTERSOS_PUBRING / MASTERSOS_PUBRING_LAB（例如构建机上多 export 了一行）就拒绝运行，不悄悄换掉信任锚
if [ -n "${MASTERSOS_PUBRING:-}${MASTERSOS_PUBRING_LAB:-}${MASTERSOS_MS_CA_DIR:-}${MASTERSOS_DBX_DIR:-}" ] && [ "${MASTERSOS_TEST:-}" != 1 ]; then
	echo "$(basename "$0"): MASTERSOS_PUBRING / MASTERSOS_PUBRING_LAB / MASTERSOS_MS_CA_DIR / MASTERSOS_DBX_DIR 只给测试用（要同时 MASTERSOS_TEST=1）；正式发布一律用仓库里的公钥" >&2
	exit 1
fi
ms_ca_dir=${MASTERSOS_MS_CA_DIR:-$here/keys/microsoft}
[ -z "${MASTERSOS_MS_CA_DIR:-}" ] || echo "$(basename "$0"): 警告：MASTERSOS_TEST=1，验 shim 证书链的微软 CA 换成了 ${ms_ca_dir}" >&2
# 微软公布的 dbx（吊销的证书与映像哈希）：仓库里还没有这个目录时不查（机器上的 shim-check 按本机的 dbx 查，那才是权威的）
dbx_dir=${MASTERSOS_DBX_DIR:-$here/keys/microsoft/dbx}
[ -z "${MASTERSOS_DBX_DIR:-}" ] || echo "$(basename "$0"): 警告：MASTERSOS_TEST=1，验 shim 的 dbx 换成了 ${dbx_dir}" >&2
# 钥匙按根选（read_root_conf 里调 select_keys）；之前一律为空，签名与闸门用到时没选就失败
gnupghome="" pubring="" pcr_pem="" key_set=""
# shellcheck disable=SC2034 # publish.sh 用
outdir=${MASTERSOS_OUTPUT_DIR:-$here/mkosi.output}
root_conf=$root/mastersos-root.conf

die() {
	echo "$(basename "$0"): $*" >&2
	exit 1
}

check_version() {
	[[ $1 =~ ^[0-9]{8}\.[0-9]+$ ]] || die "版本号应形如 20261012.1，实际：$1"
}

check_channel() {
	case " $CHANNELS " in *" $1 "*) ;; *) die "通道只能是 ${CHANNELS// / 或 }，实际：$1" ;; esac
}

# 读 <根>/mastersos-root.conf：root_base、root_lab，以及只许 lab=no 的根带的镜像目标 root_mirror_s3、root_mirror_cdn
# （sync-s3.sh 用；没有时为空，两个要么都有要么都没有）。read_root_conf verify：只验签、不碰私钥（sync-s3.sh）
read_root_conf() {
	local mode=${1:-sign} k v seen=" "
	root_base="" root_lab="" root_mirror_s3="" root_mirror_cdn="" root_chrome_base=""
	[ -f "$root_conf" ] || die "$root 没有 mastersos-root.conf（先声明这棵根：printf 'base=https://…\nlab=no\n' > ${root_conf}）"
	while IFS='=' read -r k v; do
		case "$k" in base | lab | mirror_s3 | mirror_cdn | chrome_base)
			case "$seen" in *" $k "*) die "${root_conf}：键 $k 出现了不止一次" ;; esac
			seen="$seen$k "
			;;
		esac
		case "$k" in
		base) root_base=${v%/} ;;
		lab) root_lab=$v ;;
		mirror_s3) root_mirror_s3=$v ;;
		mirror_cdn) root_mirror_cdn=$v ;;
		chrome_base) root_chrome_base=${v%/} ;;
		'' | '#'*) ;;
		*) die "${root_conf}：不认识的键 $k" ;;
		esac
	done <"$root_conf"
	case "$root_lab" in yes | no) ;; *) die "${root_conf}：lab= 只能是 yes 或 no，实际 '$root_lab'" ;; esac
	[[ $root_base =~ ^https?://[^/]+ ]] || die "${root_conf}：base= 不是 URL：'$root_base'"
	if [ "$root_lab" = no ] && [[ $root_base != https://* ]]; then
		die "${root_conf}：lab=no 的根 base 必须是 https://，实际 '$root_base'"
	fi
	if [ -n "$root_mirror_s3$root_mirror_cdn" ]; then
		[ "$root_lab" = no ] || die "${root_conf}：mirror_s3= / mirror_cdn= 只许 lab=no 的根带（试验网的根不镜像到 S3）"
		if [ -z "$root_mirror_s3" ] || [ -z "$root_mirror_cdn" ]; then
			die "${root_conf}：mirror_s3= 与 mirror_cdn= 要么都写、要么都不写"
		fi
		[[ $root_mirror_s3 =~ ^s3://[a-z0-9][a-z0-9.-]*[a-z0-9]$ ]] || die "${root_conf}：mirror_s3= 应形如 s3://<桶>（不带路径），实际 '$root_mirror_s3'"
		[[ $root_mirror_cdn =~ ^[A-Z0-9]+$ ]] || die "${root_conf}：mirror_cdn= 应是 CloudFront 的 DistributionId，实际 '$root_mirror_cdn'"
	fi
	if [ -n "$root_chrome_base" ]; then
		[ "$root_lab" = yes ] || die "${root_conf}：chrome_base= 只许 lab=yes 的根（正式的根固定是 base/chrome）"
		[[ $root_chrome_base =~ ^https://[a-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~-]+)*$ ]] ||
			die "${root_conf}：chrome_base= 应是 https://<主机>/…，实际 '$root_chrome_base'"
	elif [ "$root_lab" = no ]; then
		root_chrome_base=$root_base/chrome
	fi
	select_keys "$mode"
}

# 按 root_lab 选这棵根的一套钥匙：gnupghome（签）、pubring（验签）、pcr_pem（日志里显示）、key_set（check_uki 用）
# select_keys verify：只要验签的公钥，gnupghome 留空——同步只核对签过的清单，不该为它把正式私钥载进 tmpfs
select_keys() {
	local mode=${1:-sign} set=release over=${MASTERSOS_PUBRING:-} pub
	if [ "$root_lab" = yes ]; then
		set=lab over=${MASTERSOS_PUBRING_LAB:-}
	fi
	pub=$(keyset_pub "$set")
	gnupghome=""
	if [ "$mode" != verify ]; then
		gnupghome=$(keyset_priv "$set")/gpg || exit 2
	fi
	pubring=$pub/import-pubring.pgp
	pcr_pem=$pub/tpm2-pcr-public-key.pem
	key_set=$set
	if [ -n "$over" ]; then # 上面已经保证 MASTERSOS_TEST=1
		pubring=$over
		echo "$(basename "$0"): 警告：MASTERSOS_TEST=1，验签用的公钥换成了 ${pubring}（不是仓库的 ${pub#"$here"/}/import-pubring.pgp）" >&2
	fi
	echo "$(basename "$0"): 钥匙组 ${set}：签 ${gnupghome:-（只验签，不用私钥）}，验 ${pubring}，PCR 公钥 ${pcr_pem#"$here"/}"
}

# 构建信息与这棵根对得上才发：update_base 相同；非试验网的根不收 lab profile 与坏版本
check_build_info() { # $1 build-info 文件
	local f=$1 profile broken base
	[ -f "$f" ] || die "没有 ${f}（不知道它是怎么构建的，不发）"
	profile=$(sed -n 's/^profile=//p' "$f")
	broken=$(sed -n 's/^broken=//p' "$f")
	base=$(sed -n 's/^update_base=//p' "$f")
	base=${base%/}
	echo "$(basename "$0"): build-info profile=${profile:-?} broken=${broken:-无} update_base=${base:-?}；根 base=$root_base lab=$root_lab"
	if [ "$root_lab" = yes ]; then
		# 两套钥匙之后，正式构建（只信正式的 gpg 公钥与 PCR 公钥）发进 lab 根也装不上，lab 根也不该替它签
		[ "$profile" = lab ] || die "profile=${profile:-?} 的构建不能发到 lab=yes 的根 ${root}（lab 根只收 lab 构建，用 lab 的钥匙签）"
	else
		[ "$profile" = release ] || die "profile=${profile:-?} 的构建不能发到非试验网的根 ${root}（lab 构建带 sshd、自动登录的试验用户和 http 的试验网源）"
		[ -z "$broken" ] || die "broken=$broken 的构建只能发到 lab=yes 的根"
		# 正式镜像的 ESP 不带 loader/keys/auto、loader.conf 写 secure-boot-enroll off（build.sh 查过 esp.raw 并记下；
		# 没有这两行的 build-info 是 Task 4 之前的构建，同样不收）
		[ "$(sed -n 's/^esp_keys_auto=//p' "$f")" = absent ] ||
			die "build-info 没写 esp_keys_auto=absent：ESP 上可能带着 loader/keys/auto，不能发到非试验网的根"
		[ "$(sed -n 's/^esp_secure_boot_enroll=//p' "$f")" = off ] ||
			die "build-info 没写 esp_secure_boot_enroll=off：不能发到非试验网的根"
	fi
	[ "$base" = "$root_base" ] ||
		die "构建的 update_base（${base:-空}）不是这棵根对外的地址（${root_base}）：装上它的机器会去别处找更新"
}

# shim 的证书链（4b Task 22，spec §6.2）：$1 = 新 shim（MastersOS_<v>_x86-64.shim.bin），$2 = build-info 里的 shim_sha256，
# $3 = 1 表示给了 --allow-unchained-shim。用 keys/microsoft/ 的两张各验一次（keyset.sh 的 keyset_shim_chains：openssl 验链、
# sbverify 验哈希；只用 sbverify --cert 会被带中间证书的签名骗过），打印链到哪一张：
#   两张都链不上 → 拒发（机器上 bootloader-update 也会拒绝换上它，全体停在旧 shim）；lab 根可以加 --allow-unchained-shim 放行
#   （只给 Task 22 Step 7 做坏的版本用）；
#   只链 2023 → 警告：db 只有 2011 的机器会停在旧 shim、回报 system:shim-ca；
#   被 keys/microsoft/dbx/ 吊销 → 拒发（哪个开关都不放行；仓库里还没有这个目录时不查）。
# 通道是空的（没有基线可比）时同样跑（check_shim）。
# 双签（2011 + 2023）的 shim 由 Canonical 发；我们不签 shim。
check_shim_chain() {
	local shim=$1 want=$2 unchained=$3 have n chained=() ca rc t
	[ -f "$shim" ] || die "没有 ${shim}（Task 22 之前的构建，或 build.sh 没放出镜像里的 shim）：核对不了新 shim 的证书链，不发"
	have=$(sha256sum <"$shim" | cut -d' ' -f1)
	[ "$have" = "$want" ] || die "$shim 的 sha256（${have}）与 build-info 的 shim_sha256（${want:-未记录}）不符：核对的不是要发的那份"
	for t in sbverify sbattach openssl; do
		command -v "$t" >/dev/null || die "没有 ${t}（装 sbsigntool、openssl）：核对不了新 shim 的证书链"
	done
	for ca in MicCorUEFCA2011_2011-06-27.der microsoft-uefi-ca-2023.der; do
		[ -f "$ms_ca_dir/$ca" ] || die "没有 $ms_ca_dir/$ca"
		rc=0
		keyset_shim_chains "$shim" "$ms_ca_dir/$ca" "$dbx_dir" || rc=$?
		case $rc in
		0)
			chained+=("$ca")
			echo "$(basename "$0"): 新 shim 链到 ${ca}"
			;;
		1) ;;
		3) die "新 shim 被 ${dbx_dir} 里的 dbx 吊销（某个签名链到吊销的证书，或映像哈希在 sha256.txt 里）：装上它的机器开不了机，不发（--allow-unchained-shim 也不放行）" ;;
		*) die "核对不了新 shim 与 ${ca} 的证书链（CA 读不懂，或 openssl 的结果看不懂），不发" ;;
		esac
	done
	n=${#chained[@]}
	if [ "$n" = 0 ]; then
		if [ "$unchained" = 1 ] && [ "$root_lab" = yes ]; then
			echo "$(basename "$0"): 警告：--allow-unchained-shim：新 shim 链不到 keys/microsoft/ 的任何一张（只给 lab 的坏版本用：装上它的机器 bootloader-update 不换、回报 system:shim-ca）" >&2
			return 0
		fi
		die "新 shim 链不到 keys/microsoft/ 的任何一张微软 CA（MicCorUEFCA2011、Microsoft UEFI CA 2023）：机器上的 bootloader-update 会拒绝换上它，不发"
	fi
	if [ "$n" = 1 ] && [ "${chained[0]}" = microsoft-uefi-ca-2023.der ]; then
		echo "$(basename "$0"): 警告：新 shim 只链 Microsoft UEFI CA 2023：db 只有 2011 的机器会停在旧 shim、回报 system:shim-ca（按 docs/hardware.md 升 BIOS、Reset All Keys）" >&2
	fi
}

# shim 闸门（Task 4 复审 I-1）：$1 = 要发的版本的 build-info，$2 = 目标通道目录，$3 = 1 表示给了 --allow-shim-change，
# $4 = 新 shim 的文件（换 shim 时验证书链，check_shim_chain），$5 = 1 表示给了 --allow-unchained-shim。
# A new shim that raises SbatLevel changes one PCR 7 event. Since plan 5 Task 8 a managed machine predicts the new value
# into its pcrlock policy before swapping the shim (mastersos-agent shim-prepare), so most need no recovery key; a machine
# whose prediction fails needs it once at the next boot, then the agent re-seals with its PIN (docs/secure-boot.md
# 「引导程序更新与 TPM」). Changing the shim is still a deliberate decision, so:
# 与通道里最新版本的 shim_sha256 不同、或任一边没有记录（Task 4 之前的构建）就拒绝，除非显式 --allow-shim-change。
check_shim() {
	local f=$1 dir=$2 allow=$3 shimfile=${4:-} unchained=${5:-0} newest prev mine theirs
	# 正式根不认 --allow-unchained-shim（不论 shim 换没换、链不链得上）
	if [ "$unchained" = 1 ] && [ "$root_lab" != yes ]; then
		die "--allow-unchained-shim 只给 lab=yes 的根（Task 22 的坏版本），${root} 不认"
	fi
	mine=$(sed -n 's/^shim_sha256=//p' "$f")
	newest=$(newest_in "$dir")
	if [ -z "$newest" ]; then
		echo "$(basename "$0"): ${dir##*/} 里还没有版本，shim ${mine:-未记录}（不比较）"
		# 空通道（新的根、清空过的通道）没有基线，照样验证书链：不然第一次发布就能带进一个链不到微软 CA 的 shim（复审 Minor 1）。
		# Task 22 之前的构建没有 shim 文件，这时没法验，只警告
		if [ -f "$shimfile" ]; then
			check_shim_chain "$shimfile" "$mine" "$unchained"
		else
			echo "$(basename "$0"): 警告：没有 ${shimfile}（Task 22 之前的构建），空通道的第一次发布没验 shim 的证书链" >&2
		fi
		return 0
	fi
	prev=$dir/MastersOS_${newest}_x86-64.build-info.txt
	theirs=$(sed -n 's/^shim_sha256=//p' "$prev" 2>/dev/null || true)
	if [ -n "$mine" ] && [ "$mine" = "$theirs" ]; then
		echo "$(basename "$0"): shim 与 ${dir##*/} 最新的 $newest 相同（${mine:0:12}）"
		return 0
	fi
	if [ "$allow" != 1 ]; then
		die "shim 与 ${dir##*/} 最新的 $newest 不同或无从比较（本构建 ${mine:-未记录}，$newest ${theirs:-未记录}；SbatLevel：$(sed -n 's/^shim_sbatlevel=//p' "$f")）。
Changing the shim: managed machines predict the new SbatLevel first and mostly need no recovery key; a machine whose prediction fails needs it once at its next boot (docs/secure-boot.md 「引导程序更新与 TPM」).
If the change is intended (or this is the first release with a shim record), add --allow-shim-change"
	fi
	check_shim_chain "$shimfile" "$mine" "$unchained"
	echo "$(basename "$0"): warning: --allow-shim-change: shim ${theirs:-not recorded} → ${mine:-not recorded}. Managed machines predict the new SbatLevel before swapping the shim, most need no recovery key; a machine whose prediction fails needs it once at its next boot (luks:pcrlock on the panel shows which)" >&2
}

# systemd-boot 闸门（终审 I5）：$1 = 要发的版本的 build-info，$2 = 目标通道目录，$3 = 1 表示给了 --allow-bootloader-change。
# ESP 上的 systemd-boot（EFI/BOOT/grubx64.efi，shim 之后、UKI 之前的那一级）只有一份、没有 A/B：
# mastersos-bootloader-update.service 在一次被标为「好」的开机之后把新的换上去，而那次开机用的还是旧的，新的没被验证过；
# 它起不来就是全体机器停在固件里，启动计数救不回来。所以与通道里最新版本的 sdboot_sha256 不同（升级、降级都算）、
# 或本构建没有记录就拒绝，除非显式 --allow-bootloader-change。
# 通道里最新版本**没有**记录（终审 I5 之前发的构建）时没有基线：放行并警告，不拒绝。
check_sdboot() {
	local f=$1 dir=$2 allow=$3 newest prev mine theirs
	mine=$(sed -n 's/^sdboot_sha256=//p' "$f")
	newest=$(newest_in "$dir")
	if [ -z "$newest" ]; then
		echo "$(basename "$0"): ${dir##*/} 里还没有版本，systemd-boot ${mine:-未记录}（不比较）"
		return 0
	fi
	prev=$dir/MastersOS_${newest}_x86-64.build-info.txt
	theirs=$(sed -n 's/^sdboot_sha256=//p' "$prev" 2>/dev/null || true)
	if [ -n "$mine" ] && [ "$mine" = "$theirs" ]; then
		echo "$(basename "$0"): systemd-boot 与 ${dir##*/} 最新的 $newest 相同（${mine:0:12}）"
		return 0
	fi
	# 每次构建都重新签 systemd-boot，签名里的 PKCS#7 signingTime 让签名后的字节次次不同（2026-10-27 计划 9 验收：
	# .0 与 .1 去掉签名后逐字节相同）。去掉签名后的字节与签名证书都相同，就是同一份程序、同一把钥匙：shim 验它的结果
	# 不会变，不算换了 systemd-boot。两边都记了这两行才这样比；缺一行照旧按签名后的字节比。
	local mine_u theirs_u mine_s theirs_s
	mine_u=$(sed -n 's/^sdboot_unsigned_sha256=//p' "$f")
	theirs_u=$(sed -n 's/^sdboot_unsigned_sha256=//p' "$prev" 2>/dev/null || true)
	mine_s=$(sed -n 's/^sdboot_signer_sha256=//p' "$f")
	theirs_s=$(sed -n 's/^sdboot_signer_sha256=//p' "$prev" 2>/dev/null || true)
	if [ -n "$mine_u" ] && [ "$mine_u" = "$theirs_u" ] && [ -n "$mine_s" ] && [ "$mine_s" = "$theirs_s" ]; then
		echo "$(basename "$0"): systemd-boot 与 ${dir##*/} 最新的 $newest 去掉签名后相同（${mine_u:0:12}）、签名证书相同（${mine_s:0:12}），只是重新签了名"
		return 0
	fi
	if [ -n "$mine" ] && [ -z "$theirs" ]; then
		echo "$(basename "$0"): 警告：${dir##*/} 最新的 $newest 没有记录 systemd-boot 的 sha256（终审 I5 之前的构建），没有基线可比，放行；本构建 ${mine:0:12}" >&2
		return 0
	fi
	if [ "$allow" != 1 ]; then
		die "systemd-boot 与 ${dir##*/} 最新的 $newest 不同或无从比较（本构建 ${mine:-未记录}，$newest ${theirs:-未记录}）。
ESP 上的 systemd-boot 没有 A/B：一次被标为「好」的开机之后就换成新的，而那次开机没用过它，起不来就是全体机器停在固件里，
启动计数救不回来（docs/secure-boot.md「引导程序更新与 TPM」）。先在 lab 的真机或 VM 上装过、确认能启动，再加 --allow-bootloader-change"
	fi
	echo "$(basename "$0"): 警告：--allow-bootloader-change：systemd-boot ${theirs:-未记录} → ${mine:-未记录}。装上这个版本的每台机器在下一次被标为「好」的开机之后换上它，没有回退的那一份" >&2
}

# publish/promote 的 --allow-shim-change、--allow-unchained-shim 与 --allow-bootloader-change：从参数里拿掉它们，其余参数放进 args，
# allow_shim=1|0、allow_unchained=1|0、allow_bootloader=1|0（两道闸门各管各的，一个 flag 不放行另一道）
# shellcheck disable=SC2034 # allow_shim、allow_unchained、allow_bootloader、args 给 source 它的 publish.sh / promote.sh 用
parse_allow_flags() {
	local a
	allow_shim=0 allow_unchained=0 allow_bootloader=0 args=()
	for a in "$@"; do
		case "$a" in
		--allow-shim-change) allow_shim=1 ;;
		--allow-unchained-shim) allow_unchained=1 ;;
		--allow-bootloader-change) allow_bootloader=1 ;;
		*) args+=("$a") ;;
		esac
	done
}

# 某通道里最新的版本（没有就空）
newest_in() { versions_in "$1" | tail -n 1; }

# $1 比 $2 旧（按 systemd/sort -V 的版本顺序）
older_than() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1)" = "$1" ]; }

# 同一时刻只许一个 publish/promote 动这棵树
lock_root() {
	[ -d "$root" ] || die "没有 $root"
	exec 9>"$root/.lock"
	flock -n 9 || die "$root 正被另一个 publish/promote 使用"
}

# 某通道里的版本，从旧到新
versions_in() {
	local f
	for f in "$1"/MastersOS_*_x86-64.efi; do
		[ -e "$f" ] || continue
		f=${f##*/MastersOS_}
		echo "${f%_x86-64.efi}"
	done | sort -V
}

# 某版本在某目录里的文件（只输出文件名）：UKI、shim 的副本（Task 22 起）、三个分区文件，通道里还有 build-info
files_of() { # $1 目录 $2 版本 $3 分区文件的后缀（.raw 或 .raw.zst）
	local d=$1 v=$2 sfx=$3 f
	for f in "$d/MastersOS_${v}_x86-64.efi" "$d/MastersOS_${v}_x86-64.build-info.txt" "$d/MastersOS_${v}_x86-64.shim.bin" "$d/MastersOS_${v}_x86-64.usr-x86-64."*"$sfx" \
		"$d/MastersOS_${v}_x86-64.usr-x86-64-verity."*"$sfx" "$d/MastersOS_${v}_x86-64.usr-x86-64-verity-sig."*"$sfx"; do
		if [ -e "$f" ]; then echo "${f##*/}"; fi
	done
}

# 四个文件齐全、每种恰好一个（同一版本重建留下的旧分区文件会让 sysupdate 不知道该用哪个）
require_complete() { # $1 目录 $2 版本 $3 后缀
	local d=$1 v=$2 sfx=$3 kind n
	[ -f "$d/MastersOS_${v}_x86-64.efi" ] || die "$d 里没有 MastersOS_${v}_x86-64.efi"
	for kind in usr-x86-64 usr-x86-64-verity usr-x86-64-verity-sig; do
		n=$(find "$d" -maxdepth 1 -name "MastersOS_${v}_x86-64.${kind}.*${sfx}" -printf . | wc -c)
		[ "$n" = 1 ] || die "$d 里 MastersOS_${v}_x86-64.${kind}.*${sfx} 应恰好 1 个，实际 $n 个"
	done
}

# 发布闸门（Ruling 4、4b Ruling 28）：UKI 的 .pcrpkey 与这棵根的 PCR 公钥（lab=no：keys/tpm2-pcr-public-key.pem；
# lab=yes：keys/lab/tpm2-pcr-public-key.pem）逐字节相同，且不等于 retired/ 里任何一把退役的 PCR 公钥；
# 每个 profile 都有 .pcrsig，其中每条签名的 pkfp 都是这把公钥，sha256 **恰好一条，且它的策略就是 enter-initrd 阶段的**
# （uki-pcrsig-check 按 systemd-stub 的量法重算 PCR 11 与 PolicyPCR 摘要比对；4b Task 4 复审 M1）。
# 签错 PCR 钥匙、用退役钥匙签、或多签了离开 initrd 的阶段，都会让全体机器的数据分区解不开或不该解开——发出去之前就拦下。
check_uki() {
	[ -n "$key_set" ] || die "check_uki：还没按根选钥匙（先 read_root_conf）"
	keyset_check_uki "$1" "$key_set" || exit 1
}

# 收尾一个通道：只留最近 KEEP 个版本，重写并签 SHA256SUMS（先用仓库里的公钥验过才换上去），再删旧文件。
# 不用 die、每一步自己查错：调用方写 `if ! seal_channel …`，条件里 set -e 不起作用（修复轮 2 的发现：
# 签名失败照样删了旧版本、退出 0）。返回值：
#   0  签好、换上、旧版本删完
#   1  在换上新 SHA256SUMS 之前失败：通道里原来的 SHA256SUMS{,.gpg} 与旧版本都没动，调用方应撤下刚放进来的文件
#   2  新 SHA256SUMS 已签好换上，但删旧版本时出错：调用方不能撤新文件（已在签过的清单里），只报错
seal_channel() {
	local dir=$1 v all=() keep=() drop=() f files=() rc=0
	local sums=$dir/.SHA256SUMS.new sig=$dir/.SHA256SUMS.gpg.new
	warn() { echo "$(basename "$0"): $*" >&2; }
	if [ -z "$gnupghome" ] || [ -z "$pubring" ]; then
		warn "seal_channel：还没按根选钥匙（先 read_root_conf）"
		return 1
	fi
	mapfile -t all < <(versions_in "$dir") || { warn "列不出 $dir 里的版本"; return 1; }
	if [ ${#all[@]} -gt $KEEP ]; then
		keep=("${all[@]: -$KEEP}")
		drop=("${all[@]:0:${#all[@]}-$KEEP}")
	else
		keep=("${all[@]}")
	fi
	for v in "${keep[@]}"; do
		mapfile -t -O "${#files[@]}" files < <(files_of "$dir" "$v" .raw.zst)
	done
	rm -f "$sums" "$sig"
	if ! (cd "$dir" && printf '%s\n' "${files[@]}" | LC_ALL=C sort | xargs -r sha256sum) >"$sums"; then
		warn "算不出 $dir 的 sha256"
		rm -f "$sums"
		return 1
	fi
	if ! gpg --homedir "$gnupghome" --batch --yes --detach-sign --output "$sig" "$sums"; then
		warn "gpg 签 SHA256SUMS 失败（${gnupghome}），通道没动"
		rm -f "$sums" "$sig"
		return 1
	fi
	if ! gpgv --keyring "$pubring" "$sig" "$sums" 2>/dev/null; then
		warn "新签的 SHA256SUMS 用 $pubring 验不过（$gnupghome 的钥匙不是镜像信任的那把？），通道没动"
		rm -f "$sums" "$sig"
		return 1
	fi
	# 两次 rename，各自原子；之间来下载的机器验签失败、下一轮再来
	if ! mv -f "$sig" "$dir/SHA256SUMS.gpg"; then
		warn "换不上 SHA256SUMS.gpg"
		rm -f "$sums" "$sig"
		return 1
	fi
	if ! mv -f "$sums" "$dir/SHA256SUMS"; then
		warn "SHA256SUMS.gpg 已换、SHA256SUMS 换不上：通道的签名与清单对不上，要人工处理"
		return 2
	fi
	# 新清单签好、换上之后才删旧版本
	for v in "${drop[@]}"; do
		for f in $(files_of "$dir" "$v" .raw.zst); do
			rm -f "${dir:?}/$f" || { warn "删不掉 $dir/$f"; rc=2; }
		done
		echo "$(basename "$0"): $(basename "$dir") 只留最近 $KEEP 个版本，删掉 $v"
	done
	echo "$(basename "$0"): $(basename "$dir") 现有版本：$(versions_in "$dir" | tr '\n' ' ')"
	return $rc
}
