#!/bin/bash
# 由 build.sh 构建好的某个版本做安装 U 盘镜像（在构建机 VM 161 上跑；build.sh 构建完会自己调用）：
#   make-installer.sh <version> [--profile lab]
# 输出 mkosi.output/<version>/MastersOS-installer_<version>_x86-64.img.zst（Rufus / Etcher / dd 直接写），
# 以及 U 盘 ESP 上的安装器 UKI 的一份副本 MastersOS-installer_<version>_x86-64.efi（看签名、看命令行用）。
# Also the Ventoy package MastersOS-ventoy_<version>_x86-64.zip: MastersOS/ with a second installer UKI (signed command line
# from installer/ventoy.cmdline: usrhash=, the version and the system file's size), MastersOS-system_<version>_x86-64.raw (this
# USB image, uncompressed) and README.txt. Needs zip and unzip on the build machine.
#
# U 盘 = mkosi 的 .raw（ESP + A 槽的 /usr 三个分区）原样，末尾加 64 MiB 的 MASTERSOS-SEED 分区：
#   - MASTERSOS-SEED：FAT、GPT 类型 Microsoft basic data、GPT 标签 mastersos-usb-seed——Windows 与 Mac 都能直接
#     打开它、把学校的 seed.toml 拖进去；里面先放一份 README.txt；
#   - ESP：加上安装器 UKI（EFI/Linux/MastersOS-installer_<v>_x86-64.efi：主 UKI 的内核与 initrd、
#     installer/installer.cmdline，用同一把 Secure Boot 钥匙签），loader.conf 换成 installer/usb-loader.conf
#     （默认启动安装器），根目录有 mastersos-mok.der（第一次从 U 盘启动时 MokManager「Enroll key from disk」选它）。
#     主 UKI 挪到 EFI/mastersos/MastersOS_<v>_x86-64.efi：安装器从这里把它复制到内置盘的 EFI/Linux/（Task 10）。
#     不留在 EFI/Linux/：systemd-boot 会把那里的每个 UKI 列进 U 盘的启动菜单，选了主系统或「恢复出厂」，
#     initrd 的 repart 就在 U 盘上建 B 槽、种子与根分区（Task 11 复审 I-1）。EFI/Linux/ 里只许有安装器 UKI。
# 全程不要 root、不要 loop 设备（sfdisk 改分区表，mtools 写 FAT）。
#
# 把关（Task 4 复审：ESP 不走更新通道，publish.sh 管不到 U 盘）：这个版本的 build-info 必须存在（build.sh
# 失败时不写，但 .raw 还在）、profile=release、broken 为空、esp_keys_auto=absent、esp_secure_boot_enroll=off；
# 写好的 U 盘 ESP 上再查一遍：没有 loader/keys/auto、loader.conf 是 secure-boot-enroll off。不符就不出 U 盘。
# lab 构建的 U 盘只有显式 --profile lab 才做（ESP 上带 loader/keys/auto，只给 PVE 的试验 VM 用）。
#
# 环境变量：db.key / db.crt 签安装器 UKI：正式的只从 tmpfs 读（MASTERSOS_RELEASE_KEYS，先 keys-load.sh），--profile lab 用
#           MASTERSOS_KEYS（默认 ~/mastersos-keys）的 lab/ 下的那一套（keyset.sh）、
#           MASTERSOS_OUTPUT_DIR（默认 <本目录>/mkosi.output）
set -euo pipefail

usage() {
	echo "用法：make-installer.sh <version> [--profile lab]" >&2
	exit 2
}
die() {
	echo "make-installer.sh: $*" >&2
	exit 1
}
[ $# -ge 1 ] || usage
version=$1
shift
profile=release
while [ $# -gt 0 ]; do
	case "$1" in
	--profile)
		[ "${2:-}" = lab ] || usage
		profile=lab
		shift 2
		;;
	*) usage ;;
	esac
done
[[ $version =~ ^[0-9]{8}\.[0-9]+$ ]] || die "版本号应形如 20261012.1，实际：$version"

here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source-path=SCRIPTDIR source=keyset.sh
. "$here/keyset.sh"
priv=$(keyset_priv "$profile")
mok=$(keyset_pub "$profile")/mastersos-mok.der
out=${MASTERSOS_OUTPUT_DIR:-$here/mkosi.output}/$version
info=$out/build-info.txt
raw=$out/MastersOS_${version}_x86-64.raw
uki=$out/MastersOS_${version}_x86-64.efi
name=MastersOS-installer_${version}_x86-64
for t in objcopy objdump python3 ukify sbverify sfdisk mformat mcopy mdir mtype mmd mmove jq zstd zip unzip; do
	command -v "$t" >/dev/null || die "缺少 $t"
done
for k in db.key db.crt; do
	[ -r "$priv/$k" ] || die "缺少 $priv/$k"
done

# --- 把关：build-info ---------------------------------------------------------------
[ -f "$info" ] || die "没有 ${info}：build.sh 没有成功完成（失败时不写 build-info），不出 U 盘"
for f in "$raw" "$uki"; do
	[ -f "$f" ] || die "没有 $f"
done
bi() { sed -n "s/^$1=//p" "$info"; }
[ "$(bi version)" = "$version" ] || die "build-info 的 version 是 '$(bi version)'，不是 $version"
build_profile=$(bi profile)
if [ "$profile" = release ]; then
	[ "$build_profile" = release ] ||
		die "这是 profile=${build_profile:-?} 的构建：正式 U 盘只能用 profile=release 的构建（lab 的 U 盘要显式 --profile lab）"
	[ -z "$(bi broken)" ] || die "broken=$(bi broken) 的构建不出正式 U 盘"
	[ "$(bi esp_keys_auto)" = absent ] || die "build-info 的 esp_keys_auto 是 '$(bi esp_keys_auto)'，正式 U 盘要 absent"
	[ "$(bi esp_secure_boot_enroll)" = off ] ||
		die "build-info 的 esp_secure_boot_enroll 是 '$(bi esp_secure_boot_enroll)'，正式 U 盘要 off"
else
	[ "$build_profile" = lab ] || die "--profile lab 只用于 profile=lab 的构建，这个是 profile=${build_profile:-?}"
fi
echo "make-installer.sh: $version profile=$build_profile"
# 主 UKI（原样放进 U 盘的 EFI/mastersos/，安装器把它复制到内置盘）：PCR 签名必须只签 enter-initrd、用这一组的当前钥匙
# （4b Task 4 复审 I1：ukify 包装要是没生效，四阶段签名的 UKI 进了 U 盘就永远有效，§6.12 (a) 重新敞开）
keyset_check_uki "$uki" "$profile" || die "$uki 的 PCR 签名不合格（见上），不出 U 盘"

work=$(mktemp -d "$out/.installer.XXXXXX")
trap 'rm -rf "$work"' EXIT

# --- 安装器 UKI -----------------------------------------------------------------------
# 主 UKI 有两个 profile（第二个是恢复出厂），.cmdline 等段名会重复：objcopy --only-section 会把同名的段
# 按地址拼在一起。只取第一个 .profile 之前的基础段（与 channel-common.sh 的 check_uki 同一个读法）。
# base_sections <uki> <dir>: writes the base .linux, .initrd, .osrel and .cmdline to <dir>/{linux,initrd,osrel,cmdline}
base_sections() {
	python3 -I - "$1" "$2" <<'PY'
import struct, sys
uki, work = sys.argv[1], sys.argv[2]
data = open(uki, "rb").read()
if data[:2] != b"MZ":
    sys.exit(f"{uki} 不是 PE 文件")
pe = struct.unpack_from("<I", data, 0x3C)[0]
if data[pe:pe + 4] != b"PE\0\0":
    sys.exit(f"{uki} 不是 PE 文件")
nsec, = struct.unpack_from("<H", data, pe + 6)
optsize, = struct.unpack_from("<H", data, pe + 20)
off = pe + 24 + optsize
base = {}
for _ in range(nsec):
    name = data[off:off + 8].rstrip(b"\0").decode("ascii", "replace")
    vsize, = struct.unpack_from("<I", data, off + 8)
    rsize, rptr = struct.unpack_from("<II", data, off + 16)
    off += 40
    if name == ".profile":
        break
    if name in base:
        sys.exit(f"{uki}：基础段里有两个 {name}")
    base[name] = data[rptr:rptr + min(vsize, rsize)]
for s in (".linux", ".initrd", ".osrel", ".cmdline"):
    if s not in base:
        sys.exit(f"{uki} 的基础段里没有 {s}")
    open(f"{work}/{s[1:]}", "wb").write(base[s])
PY
}
base_sections "$uki" "$work"
main_cmdline=$(tr -d '\0' <"$work/cmdline" | tr -s '[:space:]' ' ')
case " $main_cmdline " in *" root=dissect "*) ;; *) die "主 UKI 的命令行里没有 root=dissect：'$main_cmdline'" ;; esac
inherit=$(tr ' ' '\n' <<<"$main_cmdline" | grep -E '^(systemd\.image_policy|systemd\.image_filter|console)=' || true)
grep -q '^systemd\.image_policy=' <<<"$inherit" || die "主 UKI 的命令行里没有 systemd.image_policy="
cmdline="$(sed 's/#.*//' "$here/installer/installer.cmdline" | tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//') $(tr '\n' ' ' <<<"$inherit" | sed 's/ $//')"
printf '%s' "$cmdline" >"$work/cmdline.installer"
echo "make-installer.sh: 安装器命令行：$cmdline"
# 启动菜单里与主 UKI 区分开（其余字段不变，IMAGE_VERSION 仍是这个版本）
sed -E "s/^PRETTY_NAME=.*/PRETTY_NAME=\"MastersOS Installer ${version}\"/" "$work/osrel" >"$work/osrel.installer"
grep -qxE "IMAGE_VERSION=\"?${version//./\\.}\"?" "$work/osrel.installer" || die "主 UKI 的 .osrel 里 IMAGE_VERSION 不是 $version"

ukify build \
	--linux="$work/linux" \
	--initrd="$work/initrd" \
	--os-release="@$work/osrel.installer" \
	--cmdline="@$work/cmdline.installer" \
	--signtool=sbsign \
	--secureboot-private-key="$priv/db.key" \
	--secureboot-certificate="$priv/db.crt" \
	--output="$work/$name.efi"
# Signed by this profile's db key, whose certificate is the repo's MOK certificate for this profile (mkosi.finalize checked
# the systemd-boot side); used for both installer UKIs (full-disk and Ventoy)
mokpem=$work/mok.pem
openssl x509 -inform DER -in "$mok" -out "$mokpem"
check_installer_uki() { # $1 the UKI, $2 what it is (for messages)
	sbverify --cert "$priv/db.crt" "$1" >/dev/null 2>&1 || die "$2: signature does not verify with $priv/db.crt"
	# No PCR signature (.pcrsig / .pcrpkey): the installer's userspace is root; with our PCR signature it could unlock the
	# target machine's internal disk through the TPM (4b Task 4).
	# Read the section table first and refuse if objdump itself fails ("could not read" must not pass as "no .pcrsig", review N1)
	local hdrs
	hdrs=$(objdump -h "$1") || die "$2: objdump cannot read the section table"
	if grep -qE '[[:space:]]\.pcr(sig|pkey)[[:space:]]' <<<"$hdrs"; then
		die "$2 has .pcrsig / .pcrpkey (it must not sign PCRs)"
	fi
	sbverify --cert "$mokpem" "$1" >/dev/null 2>&1 || die "$2 is not signed by the key that matches $mok"
}
check_installer_uki "$work/$name.efi" "full-disk installer UKI"

# --- U 盘镜像 ---------------------------------------------------------------------------
img=$work/$name.img
cp --sparse=always "$raw" "$img"
truncate -s +64M "$img"
# 备份 GPT 先挪到新的末尾，否则追加分区会失败或写坏备份表
sfdisk -q --relocate gpt-bak-std "$img"
printf 'type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7, name=mastersos-usb-seed\n' | sfdisk -q --append "$img"
table=$(sfdisk -J "$img")
part_of() { # $1 字段（name、type） $2 值 → 每个匹配的分区一行「start size」（扇区）
	jq -r --arg f "$1" --arg x "$2" '.partitiontable.partitions[] | select(.[$f] == $x) | "\(.start) \(.size)"' <<<"$table"
}
[ "$(jq -r .partitiontable.sectorsize <<<"$table")" = 512 ] || die "扇区不是 512 字节"
read -r seed_start seed_size < <(part_of name mastersos-usb-seed)
read -r esp_start _ < <(part_of type C12A7328-F81F-11D2-BA4B-00A0C93EC93B)
if [ -z "${seed_start:-}" ] || [ -z "${esp_start:-}" ]; then die "新分区表里找不到 ESP 或 mastersos-usb-seed：$table"; fi
[ "$(part_of name mastersos-usb-seed | wc -l)" = 1 ] || die "mastersos-usb-seed 不止一个"
echo "make-installer.sh: MASTERSOS-SEED 起于扇区 ${seed_start}，$((seed_size / 2048)) MiB"
seed="$img@@$((seed_start * 512))"
esp="$img@@$((esp_start * 512))"

# MASTERSOS-SEED：FAT（64 MiB 是 FAT16），卷标 MASTERSOS-SEED；隐藏扇区数写成分区的起点
mformat -i "$seed" -T "$seed_size" -h 64 -s 32 -H "$seed_start" -v MASTERSOS-SEED ::
printf '%s\r\n' \
	'MastersOS installer / MastersOS 安装 U 盘' \
	'' \
	'Put your school'"'"'s seed.toml in this folder (MASTERSOS-SEED), and nothing else.' \
	'把学校的 seed.toml 放在这里（MASTERSOS-SEED），只放这一份。' \
	'' \
	'- If the browser saved it as "seed (1).toml", rename it to seed.toml and delete the other copies.' \
	'  浏览器存成「seed (1).toml」时改名为 seed.toml，并删掉多余的。' \
	'- Without seed.toml the computer is installed as an unmanaged personal computer.' \
	'  没有 seed.toml 时装成不受管理的个人电脑。' \
	'- On a Mac, eject the stick before unplugging it (hidden ._ files make the installer refuse).' \
	'  在 Mac 上先推出再拔（Mac 留下的 ._ 隐藏文件会让安装器拒装）。' \
	'' \
	"Image version / 镜像版本: $version" >"$work/README.txt"
mcopy -i "$seed" "$work/README.txt" ::/README.txt

# ESP：安装器 UKI、U 盘的 loader.conf、MOK 证书
mmd -i "$esp" ::/EFI/mastersos
mmove -i "$esp" "::/EFI/Linux/MastersOS_${version}_x86-64.efi" "::/EFI/mastersos/MastersOS_${version}_x86-64.efi"
mcopy -o -i "$esp" "$work/$name.efi" "::/EFI/Linux/$name.efi"
mcopy -o -i "$esp" "$here/installer/usb-loader.conf" ::/loader/loader.conf
mcopy -o -i "$esp" "$mok" ::/mastersos-mok.der

# --- 写好的 U 盘 ESP 再查一遍 ------------------------------------------------------------
mtype -i "$esp" "::/EFI/mastersos/MastersOS_${version}_x86-64.efi" | cmp -s - "$uki" ||
	die "U 盘 ESP 上没有与 $uki 相同的 EFI/mastersos/MastersOS_${version}_x86-64.efi（安装器从这里复制主 UKI）"
# 启动菜单只该有安装器：EFI/Linux/ 里除了它什么都不许有
linux_dir=$(mdir -a -b -i "$esp" ::/EFI/Linux | sed 's|^::/EFI/Linux/||' | sort)
[ "$linux_dir" = "$name.efi" ] || die "U 盘 ESP 的 EFI/Linux/ 里应只有 ${name}.efi，实际：$(tr '\n' ' ' <<<"$linux_dir")"
mtype -i "$esp" "::/EFI/Linux/$name.efi" | cmp -s - "$work/$name.efi" || die "U 盘 ESP 上的安装器 UKI 不对"
mtype -i "$esp" ::/mastersos-mok.der | cmp -s - "$mok" || die "U 盘 ESP 根目录的 mastersos-mok.der 不对"
for f in EFI/BOOT/BOOTX64.EFI EFI/BOOT/grubx64.efi EFI/BOOT/mmx64.efi EFI/systemd/systemd-bootx64.efi; do
	mtype -i "$esp" "::/$f" >/dev/null 2>&1 || die "U 盘 ESP 上没有 $f（安装器要把它复制到内置盘）"
done
if mdir -b -i "$esp" ::/loader/keys/auto >/dev/null 2>&1; then
	usb_keys_auto=present
else
	usb_keys_auto=absent
fi
usb_enroll=$(mtype -i "$esp" ::/loader/loader.conf 2>/dev/null | tr -d '\r' |
	sed -n 's/^[[:space:]]*secure-boot-enroll[[:space:]]\{1,\}\([^[:space:]]*\).*/\1/p' | tail -n 1)
usb_enroll=${usb_enroll:-unset}
if [ "$profile" = release ] && { [ "$usb_keys_auto" != absent ] || [ "$usb_enroll" != off ]; }; then
	die "U 盘 ESP 上 loader/keys/auto ${usb_keys_auto}、secure-boot-enroll ${usb_enroll}：正式 U 盘应为 absent 与 off"
fi
echo "make-installer.sh: U 盘 ESP：loader/keys/auto ${usb_keys_auto}，secure-boot-enroll ${usb_enroll}，EFI/Linux/ 只有安装器 UKI，主 UKI 在 EFI/mastersos/，有 mastersos-mok.der"
sfdisk -d "$img" | sed "s|$img|<img>|"

# --- Ventoy package ---------------------------------------------------------------------
# MastersOS-ventoy_<v>_x86-64.zip unpacks to MastersOS/ on the Ventoy stick: a second installer UKI (same kernel, initrd and
# .osrel, command line from ventoy.cmdline) and the system file, which is exactly this USB image (the same bytes as the
# .img.zst unpacked, not a separate build). The initrd checks only the system file's version and size from the command line; its
# bytes are not hashed (2026-10-29: the copy on the stick is trusted; a damaged copy is not detected at install time and shows
# up later as I/O errors on the installed machine, fixed by reinstalling from a fresh copy).
sys_name=MastersOS-system_${version}_x86-64.raw
zip_name=MastersOS-ventoy_${version}_x86-64.zip
sys_size=$(stat -c %s "$img")
# A FAT32 Ventoy stick cannot hold a file of 4 GiB or more (exFAT can); refuse rather than ship a zip that fails there
[ "$sys_size" -le 4294967295 ] ||
	die "system file is $sys_size bytes, more than 4 GiB - 1: it no longer fits on a FAT32 Ventoy stick (spec section 6)"
usrhash=$(tr ' ' '\n' <<<"$main_cmdline" | sed -n 's/^usrhash=//p')
[[ $usrhash =~ ^[0-9a-f]{64}$ ]] || die "main UKI's command line should have exactly one usrhash=<64 hex>, got: '$usrhash'"
[ "$(tr -s '[:space:]' '\n' <<<"$cmdline" | grep -cx 'mount.usr=dissect')" = 1 ] ||
	die "installer command line should have mount.usr=dissect exactly once: '$cmdline'"
ventoy_add=$(sed 's/#.*//' "$here/installer/ventoy.cmdline" | tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//')
ventoy_add=${ventoy_add//@USRHASH@/$usrhash}
ventoy_add=${ventoy_add//@VERSION@/$version}
ventoy_add=${ventoy_add//@SIZE@/$sys_size}
[[ $ventoy_add != *@* ]] || die "ventoy.cmdline has a placeholder that make-installer.sh does not fill: '$ventoy_add'"
installer_base=$(sed 's/#.*//' "$here/installer/installer.cmdline" | tr -s '[:space:]' '\n' | grep -vx 'mount.usr=dissect' | tr '\n' ' ' | sed 's/^ //; s/ $//')
ventoy_cmdline="$installer_base $ventoy_add $(tr '\n' ' ' <<<"$inherit" | sed 's/ $//')"
printf '%s' "$ventoy_cmdline" >"$work/cmdline.ventoy"
echo "make-installer.sh: Ventoy installer command line: $ventoy_cmdline"
vdir=$work/ventoy/MastersOS
mkdir -p "$vdir"
ukify build \
	--linux="$work/linux" \
	--initrd="$work/initrd" \
	--os-release="@$work/osrel.installer" \
	--cmdline="@$work/cmdline.ventoy" \
	--signtool=sbsign \
	--secureboot-private-key="$priv/db.key" \
	--secureboot-certificate="$priv/db.crt" \
	--output="$vdir/$name.efi"
check_installer_uki "$vdir/$name.efi" "Ventoy installer UKI"
# Read back what got signed: kernel, initrd and .osrel unchanged, the command line carries this build's usrhash= and the
# system file's size, no sha256 (the initrd no longer reads it) and no gpt-auto /usr
vsec=$work/ventoy-sections
mkdir "$vsec"
base_sections "$vdir/$name.efi" "$vsec"
for f in linux initrd; do
	cmp -s "$vsec/$f" "$work/$f" || die "Ventoy installer UKI's .$f differs from the main UKI's"
done
cmp -s "$vsec/osrel" "$work/osrel.installer" || die "Ventoy installer UKI's .osrel differs from the full-disk installer's"
signed=" $(tr -d '\0' <"$vsec/cmdline" | tr -s '[:space:]' ' ') "
for want in "usrhash=$usrhash" "mount.usr=/dev/mapper/usr" "mastersos.ventoy=$version" "mastersos.ventoy_size=$sys_size" \
	"systemd.verity_usr_data=/dev/disk/by-loop-ref/mastersos-ventoy-part4" \
	"systemd.verity_usr_hash=/dev/disk/by-loop-ref/mastersos-ventoy-part3" "rd.systemd.mask=mastersos-usr-repair.service"; do
	[[ $signed == *" $want "* ]] || die "Ventoy installer UKI's command line lacks '$want':$signed"
done
[[ $signed != *" mount.usr=dissect "* ]] || die "Ventoy installer UKI's command line has mount.usr=dissect:$signed"
[ "$(tr ' ' '\n' <<<"$signed" | grep -c '^usrhash=')" = 1 ] || die "Ventoy installer UKI's command line has more than one usrhash=:$signed"
[[ $signed != *" mastersos.ventoy_sha256="* ]] || die "Ventoy installer UKI's command line still has mastersos.ventoy_sha256=:$signed"
echo "make-installer.sh: Ventoy installer UKI ok: signed with db.crt and the MOK key, no .pcrsig/.pcrpkey, usrhash=$usrhash, mastersos.ventoy_size=$sys_size, no mount.usr=dissect"

printf '%s\r\n' \
	'MastersOS for Ventoy / MastersOS（Ventoy U 盘用）' \
	'' \
	'This MastersOS folder must sit at the top of the Ventoy stick (exFAT). Keep exactly one MastersOS folder on the stick.' \
	'这个 MastersOS 文件夹要放在 Ventoy 盘（exFAT）的根目录。盘上只放一个 MastersOS 文件夹。' \
	'To upgrade, delete the old MastersOS folder, then unzip the new zip.' \
	'升级时先删掉旧的 MastersOS 文件夹，再解压新的 zip。' \
	'' \
	'Put your school'"'"'s seed.toml in this folder (MastersOS), and no other .toml file.' \
	'把学校的 seed.toml 放在这个文件夹（MastersOS）里，不放别的 .toml 文件。' \
	'' \
	'- If the browser saved it as "seed (1).toml", rename it to seed.toml and delete the other copies.' \
	'  浏览器存成「seed (1).toml」时改名为 seed.toml，并删掉多余的。' \
	'- Without seed.toml the computer is installed as an unmanaged personal computer.' \
	'  没有 seed.toml 时装成不受管理的个人电脑。' \
	'- On a Mac, eject the stick before unplugging it (hidden ._ files make the installer refuse).' \
	'  在 Mac 上先推出再拔（Mac 留下的 ._ 隐藏文件会让安装器拒装）。' \
	'' \
	'With Secure Boot on there are two blue screens, each only once per computer:' \
	'Secure Boot 开着时有两次蓝屏，每台电脑各一次：' \
	'1. The first time this computer starts from the Ventoy stick: enroll Ventoy'"'"'s key (Ventoy'"'"'s own steps).' \
	'   第一次从 Ventoy 盘启动：登记 Ventoy 的钥匙（Ventoy 自己的步骤）。' \
	'2. After the installation, press Enter to restart and remove the stick when the screen goes dark: "Security Violation" -> Enter -> "Enroll key from disk"' \
	'   -> MASTERSOS -> mastersos-mok.der -> "Continue" -> "Yes". The installer'"'"'s last screen shows these steps.' \
	'   装完回车重启，屏幕黑了再拔盘：「Security Violation」→ 回车 → Enroll key from disk → MASTERSOS → mastersos-mok.der' \
	'   → Continue → Yes。安装器的最后一屏会写出这几步。' \
	'' \
	"Image version / 镜像版本: $version" >"$vdir/README.txt"
ln "$img" "$vdir/$sys_name"
# -1: fast deflate (the image has long runs of zeros); -X: no uid/gid extras; -D: no directory entries. zip 3.0 switches to
# zip64 by itself when a member needs it.
(cd "$work/ventoy" && zip -q -X -D -1 "$work/$zip_name" "MastersOS/$name.efi" "MastersOS/$sys_name" MastersOS/README.txt)
rm "$vdir/$sys_name"

# --- Ventoy zip: what IT unpacks is what the signed command line describes ------------------
listing=$(unzip -Z1 "$work/$zip_name" | sort)
[ "$listing" = "$(printf '%s\n' "MastersOS/$name.efi" "MastersOS/$sys_name" MastersOS/README.txt | sort)" ] ||
	die "$zip_name should hold exactly MastersOS/{$name.efi,$sys_name,README.txt}, holds: $(tr '\n' ' ' <<<"$listing")"
unzip -p "$work/$zip_name" "MastersOS/$name.efi" | cmp -s - "$vdir/$name.efi" || die "$zip_name: the installer UKI is not the one checked above"
unzip -p "$work/$zip_name" MastersOS/README.txt | cmp -s - "$vdir/README.txt" || die "$zip_name: README.txt differs"
unzip -p "$work/$zip_name" "MastersOS/$sys_name" | cmp -s - "$img" ||
	die "$zip_name: MastersOS/$sys_name is not byte-identical to the USB image $name.img"
echo "make-installer.sh: Ventoy zip ok: $(tr '\n' ' ' <<<"$listing"); MastersOS/$sys_name is byte-identical to $name.img ($sys_size bytes = signed command line)"

# --- 输出 -------------------------------------------------------------------------------
rm -f "$out/$name.img.zst" "$out/$zip_name"
zstd -q -T0 "$img" -o "$work/$name.img.zst"
mv "$work/$name.efi" "$out/$name.efi"
mv "$work/$name.img.zst" "$out/$name.img.zst"
mv "$work/$zip_name" "$out/$zip_name"
echo "make-installer.sh: $out/$zip_name ($(du -h "$out/$zip_name" | cut -f1))"
echo "make-installer.sh: $out/$name.img.zst（$(du -h "$out/$name.img.zst" | cut -f1)，解开 $(($(stat -c %s "$img") / 1048576)) MiB）"
