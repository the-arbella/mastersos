#!/bin/bash
# bootloader-update（mkosi.extra/usr/lib/mastersos/bootloader-update）的失败与断电注入，在一块 loop 挂载的
# FAT32 上跑真的脚本：
#   sudo bash image/tests/bootloader-update-test.sh
# 要 root（losetup、mount）、mkfs.vfat / fsck.vfat（dosfstools）、mtools；不是 root 或缺工具时跳过。
#
# 注入的办法：PATH 前面放 cp / mv / sync 的包装，脚本里每调用一次算一步。
#   - 失败：第 k 步直接返回 1（不做）。之后 ESP 上三个文件都必须完整（旧的或新的）、没有 .new 残留、
#     「shim 是新的 ⇒ systemd-boot 也是新的」；不注入再跑一次必须全部换好。
#   - 断电：每一步之前和之后，把 loop 设备的底层镜像文件原样复制一份（文件系统还挂着、不 sync：
#     复制到的就是这时已经写到块设备上的东西，页缓存里没刷下去的不算）。每份快照都必须满足上面三条里
#     的前两条（.new 可以在，固件不认它）；再把快照挂起来、不注入跑一次，必须全部换好、没有 .new。
#
# 测不出来的一处（如实记下）：「改名之后 fsync 文件与目录」去掉了，本测试照样全绿（Task 4 的 RED 变体 D）。断电快照
# 只能拍到 fsync 已经逼下去的东西，而下一个文件的 .new 的 fsync 会顺带把同一个目录扇区里上一次改名写下去；内核的
# 回写在测试的时间尺度里也不会自己跑。那个 fsync 防的是「shim 的目录项比 systemd-boot 的先被回写」——两条目录项落在
# 不同扇区、回写顺序又不巧时才会发生，这里构造不出来。所以它留在脚本里（防御性的），不能算被本测试证明过。
# 为了至少不让「同一扇区」成为测试通过的原因，new_esp 在 EFI/BOOT 里的三个文件之间各插 8 个长文件名的占位文件，
# 让三条目录项分在不同的扇区（每个占位约 5 条 32 字节的目录项）。
# shellcheck disable=SC2016 # check … eval '…'：条件里的变量要到 eval 时才展开，单引号是有意的
set -euo pipefail

img=$(cd "$(dirname "$0")/.." && pwd)
script=$img/mkosi.extra/usr/lib/mastersos/bootloader-update
if [ "$(id -u)" != 0 ]; then
	echo "bootloader-update-test: skip（要 root：sudo bash $0）"
	exit 0
fi
for t in losetup mount mkfs.vfat fsck.vfat mtype mdir sha256sum; do
	command -v "$t" >/dev/null || {
		echo "bootloader-update-test: skip（缺少 ${t}）"
		exit 0
	}
done

tmp=$(mktemp -d)
loops=()
cleanup() {
	local l
	for m in "$tmp"/mnt*; do mountpoint -q "$m" 2>/dev/null && umount "$m"; done
	for l in "${loops[@]}"; do losetup -d "$l" 2>/dev/null || true; done
	rm -rf "$tmp"
}
trap cleanup EXIT

NAMES=(grubx64.efi mmx64.efi BOOTX64.EFI)
# 「旧」与「新」的三个文件：随机内容，大小不同（shim ≈ 1 MB，MokManager ≈ 0.8 MB，systemd-boot ≈ 0.13 MB）
mkdir -p "$tmp/old" "$tmp/new"
head -c 966768 /dev/urandom >"$tmp/old/BOOTX64.EFI"
head -c 136640 /dev/urandom >"$tmp/old/grubx64.efi"
head -c 856280 /dev/urandom >"$tmp/old/mmx64.efi"
head -c 1003808 /dev/urandom >"$tmp/new/BOOTX64.EFI"
head -c 137216 /dev/urandom >"$tmp/new/grubx64.efi"
head -c 857600 /dev/urandom >"$tmp/new/mmx64.efi"
declare -A OLD NEW
for n in "${NAMES[@]}"; do
	OLD[$n]=$(sha256sum <"$tmp/old/$n" | cut -d' ' -f1)
	NEW[$n]=$(sha256sum <"$tmp/new/$n" | cut -d' ' -f1)
done

# 包装：每次调用把步数加一、记下命令；FAIL_AT 那一步返回 1；SNAPDIR 设了就在前后各复制一份底层镜像
mkdir -p "$tmp/bin"
for c in cp mv sync; do
	real=$(command -v "$c")
	cat >"$tmp/bin/$c" <<WRAP
#!/bin/bash
# shim-ca.json（4b Task 22）只是给 agent 回报的状态，不算换引导程序的一步：原样执行、不计步、不注入
case "\$*" in *shim-ca.json*) exec $real "\$@" ;; esac
n=\$((\$(cat "\$STEPS") + 1))
echo "\$n" >"\$STEPS"
echo "\$n $c \$*" >>"\$TRACE"
[ "\$n" = "\${FAIL_AT:-0}" ] && exit 1
[ -z "\${SNAPDIR:-}" ] || $(command -v cp) --sparse=always "\$BACKING" "\$SNAPDIR/\$(printf %03d \$n)-before-$c.img"
rc=0
$real "\$@" || rc=\$?
[ -z "\${SNAPDIR:-}" ] || $(command -v cp) --sparse=always "\$BACKING" "\$SNAPDIR/\$(printf %03d \$n)-after-$c.img"
exit \$rc
WRAP
	chmod +x "$tmp/bin/$c"
done

# mastersos-agent shim-check 的包装（4b Task 22）：记下参数，退出 SHIM_CHECK_RC（默认 0：链得上）
# shim-prepare (plan 5 Task 8): log the arguments plus the sha256 of the three ESP files at the moment of the call
# (ESP_AT_PREPARE), exit SHIM_PREPARE_RC (default 0 = prepared); SHIM_PREPARE_RC=127 behaves like an agent that cannot run
cat >"$tmp/bin/mastersos-agent" <<'WRAP'
#!/bin/bash
echo "$*" >>"$SHIMCHECK_LOG"
if [ "$1" = shim-prepare ]; then
	for n in grubx64.efi mmx64.efi BOOTX64.EFI; do
		printf '%s=%s ' "$n" "$(sha256sum <"$MASTERSOS_ESP/EFI/BOOT/$n" | cut -d' ' -f1)"
	done >>"$ESP_AT_PREPARE"
	echo >>"$ESP_AT_PREPARE"
	case "${SHIM_PREPARE_RC:-0}" in
	0) echo "prepared: PCR 7 policy accepts the new SbatLevel" ;;
	127) echo "mastersos-agent: cannot execute" >&2 ;;
	*) echo "failed: test reason" ;;
	esac
	exit "${SHIM_PREPARE_RC:-0}"
fi
[ "${SHIM_CHECK_RC:-0}" = 0 ] && echo "链到 db 里的 test" || echo "链不到活动 db 里的任何一张证书"
exit "${SHIM_CHECK_RC:-0}"
WRAP
chmod +x "$tmp/bin/mastersos-agent"

# pad <目录> <前缀>：8 个长文件名的空占位文件（每个占约 5 条目录项），把前后两个文件的目录项隔到不同扇区
pad() {
	local i
	for i in 1 2 3 4 5 6 7 8; do : >"$1/padding-to-spread-directory-entries-$2$i.txt"; done
}
# new_esp <名字>：建一个 64 MB 的 FAT32 镜像、挂在 $tmp/mnt-<名字>，装上旧的三个文件（grubx64 的扩展名照
# mkosi 写成大写 .EFI：vfat 查名字不分大小写，脚本用小写的名字也找得到它）
new_esp() {
	local f=$tmp/$1.img m=$tmp/mnt-$1 l
	truncate -s 64M "$f"
	mkfs.vfat -F 32 -n ESP "$f" >/dev/null
	mkdir -p "$m"
	l=$(losetup --show -f "$f")
	loops+=("$l")
	mount -t vfat "$l" "$m"
	mkdir -p "$m/EFI/BOOT" "$m/EFI/Linux" "$m/loader"
	cp "$tmp/old/BOOTX64.EFI" "$m/EFI/BOOT/BOOTX64.EFI"
	pad "$m/EFI/BOOT" a
	cp "$tmp/old/grubx64.efi" "$m/EFI/BOOT/grubx64.EFI"
	pad "$m/EFI/BOOT" b
	cp "$tmp/old/mmx64.efi" "$m/EFI/BOOT/mmx64.efi"
	echo fallback >"$m/EFI/BOOT/fbx64.efi"
	sync -f "$m"
}
# mount_image <镜像文件> <名字>：把一份快照挂起来（可写，跑「下一次开机」用）
mount_image() {
	local m=$tmp/mnt-$2 l
	mkdir -p "$m"
	l=$(losetup --show -f "$1")
	loops+=("$l")
	mount -t vfat "$l" "$m" 2>/dev/null
}
umount_esp() {
	local m=$tmp/mnt-$1 l
	l=$(findmnt -no SOURCE "$m")
	umount "$m"
	losetup -d "$l"
}

# run <ESP 挂载点> [环境变量…]：跑真的脚本（PATH 前面是包装），输出进 $tmp/last.log，返回脚本的退出码
run() {
	local m=$1 rc=0
	shift
	echo 0 >"$tmp/steps"
	: >"$tmp/trace"
	: >"$tmp/shimcheck.log"
	: >"$tmp/esp-at-prepare"
	env PATH="$tmp/bin:$PATH" STEPS="$tmp/steps" TRACE="$tmp/trace" MASTERSOS_ESP="$m" MASTERSOS_ESP_SRC="$tmp/new" \
		SHIMCHECK_LOG="$tmp/shimcheck.log" ESP_AT_PREPARE="$tmp/esp-at-prepare" MASTERSOS_SHIM_CA_STATE="$tmp/state/shim-ca.json" \
		MASTERSOS_IMAGE_VERSION="${VERSION:-20261013.20}" "$@" bash "$script" >"$tmp/last.log" 2>&1 || rc=$?
	return $rc
}

t_fail=0 t_n=0
check() { # check <名字> <条件命令…>
	t_n=$((t_n + 1))
	if "${@:2}"; then echo "ok   $1"; else
		echo "FAIL $1" >&2
		sed 's/^/    log: /' "$tmp/last.log" >&2 || true
		t_fail=$((t_fail + 1))
	fi
}

# 一块 ESP（挂着的目录）上三个文件的状态：每个输出 old / new / bad
state_dir() {
	local m=$1 n h out=""
	for n in "${NAMES[@]}"; do
		h=$(sha256sum <"$m/EFI/BOOT/$n" 2>/dev/null | cut -d' ' -f1) || h=""
		if [ "$h" = "${OLD[$n]}" ]; then out+="$n=old "; elif [ "$h" = "${NEW[$n]}" ]; then out+="$n=new "; else out+="$n=bad "; fi
	done
	echo "${out% }"
}
# 同上，但读镜像文件（mtools，不挂载）
state_img() {
	local f=$1 n h out=""
	for n in "${NAMES[@]}"; do
		h=$(mtype -i "$f" "::/EFI/BOOT/$n" 2>/dev/null | sha256sum | cut -d' ' -f1)
		mdir -b -i "$f" "::/EFI/BOOT/$n" >/dev/null 2>&1 || h=""
		if [ "$h" = "${OLD[$n]}" ]; then out+="$n=old "; elif [ "$h" = "${NEW[$n]}" ]; then out+="$n=new "; else out+="$n=bad "; fi
	done
	echo "${out% }"
}
# 能启动：三个都完整（旧或新），而且 shim 是新的时 systemd-boot 与 MokManager 也都是新的（shim 最后换）
bootable() {
	case "$1" in *=bad*) return 1 ;; esac
	case "$1" in *BOOTX64.EFI=new*) [[ $1 == *grubx64.efi=new* && $1 == *mmx64.efi=new* ]] ;; esac
}
all_new() { [ "$1" = "grubx64.efi=new mmx64.efi=new BOOTX64.EFI=new" ]; }
no_leftovers() { [ -z "$(find "$1" -iname '*.new')" ]; }
untouched_fallback() { [ "$(cat "$1/EFI/BOOT/fbx64.efi")" = fallback ]; }
stamp_is() { [ "$(cat "$1/loader/mastersos-bootloader.version" 2>/dev/null)" = "$2" ]; }

# --- 1. 正常跑一次 ----------------------------------------------------------------
new_esp base
m=$tmp/mnt-base
rc=0
run "$m" || rc=$?
check "正常：退出 0" [ $rc = 0 ]
s=$(state_dir "$m")
check "正常：三个都换成新的（$s）" all_new "$s"
check "正常：没有 .new 残留" no_leftovers "$m"
check "正常：fbx64.efi 没动" untouched_fallback "$m"
check "正常：版本标记 = 20261013.20" stamp_is "$m" 20261013.20
order=$(grep -oE 'mv -f \S+' "$tmp/trace" | sed -E 's|.*/||; s/\.new$//' | tr '\n' ' ')
check "正常：换的顺序是 grubx64 → mmx64 → shim（→ 版本标记）（${order% }）" \
	[ "${order% }" = "grubx64.efi mmx64.efi BOOTX64.EFI mastersos-bootloader.version" ]
total=$(cat "$tmp/steps")
echo "     一次完整的更新共 $total 步（cp / sync / mv 的调用）："
sed 's/^/       /' "$tmp/trace"
rc=0
run "$m" || rc=$?
check "再跑一次：退出 0、什么都不换" [ $rc = 0 ]
check "  没有 cp / mv（$(cat "$tmp/steps") 步）" [ "$(cat "$tmp/steps")" = 0 ]
check "  日志说相同" grep -q '相同' "$tmp/last.log"
umount_esp base

# --- 2. 第 k 步失败 --------------------------------------------------------------
for k in $(seq 1 "$total"); do
	new_esp "f$k"
	m=$tmp/mnt-f$k
	rc=0
	run "$m" FAIL_AT="$k" || rc=$?
	step=$(sed -n "${k}p" "$tmp/trace" | cut -d' ' -f2-3 | sed "s|$m/||; s|$tmp/new/||")
	s=$(state_dir "$m")
	check "失败于第 $k 步（${step}）：退出非零" [ $rc != 0 ]
	check "  三个都完整、shim 新 ⇒ systemd-boot 与 MokManager 新（$s）" bootable "$s"
	check "  没有 .new 残留" no_leftovers "$m"
	rc=0
	run "$m" || rc=$?
	check "  不注入再跑：退出 0、全部换好" eval '[ $rc = 0 ] && all_new "$(state_dir "$m")" && no_leftovers "$m" && stamp_is "$m" 20261013.20'
	umount_esp "f$k"
done

# --- 3. 每一步前后断电 ------------------------------------------------------------
new_esp p
m=$tmp/mnt-p
mkdir -p "$tmp/snaps"
rc=0
run "$m" SNAPDIR="$tmp/snaps" BACKING="$tmp/p.img" || rc=$?
check "断电注入的那次运行本身退出 0" [ $rc = 0 ]
umount_esp p
nsnap=0 fsck_dirty=0
for f in "$tmp"/snaps/*.img; do
	nsnap=$((nsnap + 1))
	b=$(basename "$f" .img)
	s=$(state_img "$f")
	check "断电于 ${b}：三个都完整、shim 新 ⇒ systemd-boot 与 MokManager 新（$s）" bootable "$s"
	# 挂着的 FAT 一定带「脏」标记（引导扇区偏移 65 与备份不同）：那两段不算，其余的（丢失的簇、交叉链接、
	# 孤立的长文件名……）记下来
	fsck.vfat -n "$f" >"$tmp/fsck.log" 2>&1 || true
	other=$(grep -vE -e '^fsck\.fat ' -e 'boot sector and its backup' -e 'mostly harmless' -e '^ +65:01/00$' \
		-e 'Not automatically fixing' -e 'Dirty bit is set' -e 'removing dirty bit' -e '^Leaving filesystem' \
		-e "^${f//./\\.}: [0-9]+ files" -e '^$' "$tmp/fsck.log" || true)
	if [ -n "$other" ]; then
		fsck_dirty=$((fsck_dirty + 1))
		echo "     fsck.vfat -n（只读）：$(tr '\n' ' ' <<<"$other")"
	fi
	mount_image "$f" snap
	rc=0
	run "$tmp/mnt-snap" || rc=$?
	check "  下一次被标好的开机：退出 0、全部换好、没有 .new" \
		eval '[ $rc = 0 ] && all_new "$(state_dir "$tmp/mnt-snap")" && no_leftovers "$tmp/mnt-snap"'
	umount_esp snap
done
echo "     断电快照 $nsnap 份，fsck.vfat -n 除「没卸载的脏标记」外还报告了问题的 $fsck_dirty 份（见上）"

# --- 3b. shim 链不到本机的 db（4b Task 22）：三个文件都不换、写 shim-ca.json、退出 0 -------------------
rm -rf "$tmp/state"
new_esp chain
m=$tmp/mnt-chain
before=$(state_dir "$m")
for rc_want in 1 2; do
	rc=0
	SHIM_CHECK_RC=$rc_want run "$m" || rc=$?
	check "shim-check 退出 ${rc_want}：脚本退出 0" [ $rc = 0 ]
	check "  先跑了 shim-check（参数是镜像里的 BOOTX64.EFI）" grep -qx "shim-check $tmp/new/BOOTX64.EFI" "$tmp/shimcheck.log"
	check "  ESP 上三个文件的 sha256 都没变（$(state_dir "$m")）" [ "$(state_dir "$m")" = "$before" ]
	check "  没有 cp / mv（$(cat "$tmp/steps") 步）、没有 .new" eval '[ "$(cat "$tmp/steps")" = 0 ] && no_leftovers "$m"'
	check "  shim-ca.json 是 ok:false、exit ${rc_want}、带版本" \
		grep -q "^{\"ok\":false,\"exit\":${rc_want},\"image_version\":\"20261013.20\",\"reason\":\"" "$tmp/state/shim-ca.json"
	check "  shim-ca.json 是 0600" [ "$(stat -c %a "$tmp/state/shim-ca.json")" = 600 ]
	check "  日志说三个文件都不换" grep -q '都不换' "$tmp/last.log"
	check "  没写版本标记" [ ! -e "$m/loader/mastersos-bootloader.version" ]
done
rc=0
run "$m" || rc=$?
check "shim-check 退出 0：照旧全部换完" eval '[ $rc = 0 ] && all_new "$(state_dir "$m")" && no_leftovers "$m" && stamp_is "$m" 20261013.20'
check "  shim-ca.json 改成 ok:true" grep -q '^{"ok":true,"exit":0,' "$tmp/state/shim-ca.json"
order=$(grep -oE 'mv -f \S+' "$tmp/trace" | sed -E 's|.*/||; s/\.new$//' | tr '\n' ' ')
check "  换的顺序不变（${order% }）" [ "${order% }" = "grubx64.efi mmx64.efi BOOTX64.EFI mastersos-bootloader.version" ]
# shim 没变（只换 systemd-boot）：不跑 shim-check
cp "$tmp/old/grubx64.efi" "$m/EFI/BOOT/grubx64.efi"
rc=0
SHIM_CHECK_RC=1 run "$m" || rc=$?
check "shim 没变、只有 grubx64.efi 不同：不跑 shim-check、照旧换" \
	eval '[ $rc = 0 ] && [ ! -s "$tmp/shimcheck.log" ] && all_new "$(state_dir "$m")"'
# 停在旧 shim（ok:false）之后，下一个镜像带的 shim 又与 ESP 上的相同：状态改回 ok:true
printf '{"ok":false,"exit":1,"image_version":"x","reason":"y"}\n' >"$tmp/state/shim-ca.json"
rc=0
run "$m" || rc=$?
check "shim 与 ESP 上的相同、旧状态是 ok:false：改成 ok:true" \
	eval '[ $rc = 0 ] && [ ! -s "$tmp/shimcheck.log" ] && grep -q "^{\"ok\":true," "$tmp/state/shim-ca.json"'
umount_esp chain

# --- 3c. shim-prepare (plan 5 Task 8): predict the new SbatLevel into pcrlock before any write --------------
old_state() { # the three old files, in the fake agent's format
	local n
	for n in "${NAMES[@]}"; do printf '%s=%s ' "$n" "${OLD[$n]}"; done
}
new_esp prep
m=$tmp/mnt-prep
rc=0
run "$m" || rc=$?
check "shim_prepare_runs_before_any_write: exit 0, everything replaced" eval '[ $rc = 0 ] && all_new "$(state_dir "$m")"'
check "  shim-prepare ran with the image's BOOTX64.EFI, after shim-check" \
	eval '[ "$(sed -n 1p "$tmp/shimcheck.log")" = "shim-check $tmp/new/BOOTX64.EFI" ] && [ "$(sed -n 2p "$tmp/shimcheck.log")" = "shim-prepare $tmp/new/BOOTX64.EFI" ]'
check "  when shim-prepare ran, all three ESP files were still the old ones" [ "$(cat "$tmp/esp-at-prepare")" = "$(old_state)" ]
check "  the log has the shim-prepare result" grep -q 'shim-prepare (exit 0)' "$tmp/last.log"
umount_esp prep
for rc_want in 1 127; do
	new_esp "prepfail$rc_want"
	m=$tmp/mnt-prepfail$rc_want
	rc=0
	SHIM_PREPARE_RC=$rc_want run "$m" || rc=$?
	check "shim_prepare_failure_still_swaps (agent exit $rc_want): exit 0, all three replaced" \
		eval '[ $rc = 0 ] && all_new "$(state_dir "$m")" && no_leftovers "$m" && stamp_is "$m" 20261013.20'
	check "  the log says the prediction failed and the next boot needs the recovery key" \
		grep -q 'prediction failed: .*the next boot needs the recovery key' "$tmp/last.log"
	order=$(grep -oE 'mv -f \S+' "$tmp/trace" | sed -E 's|.*/||; s/\.new$//' | tr '\n' ' ')
	check "  same order (${order% })" [ "${order% }" = "grubx64.efi mmx64.efi BOOTX64.EFI mastersos-bootloader.version" ]
	umount_esp "prepfail$rc_want"
done
new_esp prepsame
m=$tmp/mnt-prepsame
cp "$tmp/new/BOOTX64.EFI" "$m/EFI/BOOT/BOOTX64.EFI"
rc=0
run "$m" || rc=$?
check "shim_prepare_skipped_when_shim_unchanged: exit 0, others replaced, no shim-check / shim-prepare" \
	eval '[ $rc = 0 ] && all_new "$(state_dir "$m")" && [ ! -s "$tmp/shimcheck.log" ] && ! grep -q shim-prepare "$tmp/last.log"'
# shim-check refuses: shim-prepare does not run either (nothing is replaced)
rc=0
cp "$tmp/old/BOOTX64.EFI" "$m/EFI/BOOT/BOOTX64.EFI"
SHIM_CHECK_RC=1 run "$m" || rc=$?
check "shim-check exit 1: shim-prepare does not run" eval '[ $rc = 0 ] && ! grep -q shim-prepare "$tmp/shimcheck.log"'
umount_esp prepsame
rm -f "$tmp/state/shim-ca.json"

# --- 4. 其他情形 ------------------------------------------------------------------
new_esp misc
m=$tmp/mnt-misc
# 上一次断电留下的半截 .new
head -c 1000 /dev/urandom >"$m/EFI/BOOT/BOOTX64.EFI.new"
rm "$m/EFI/BOOT/mmx64.efi"
rc=0
run "$m" || rc=$?
check "ESP 上有上次留下的半截 BOOTX64.EFI.new、缺 mmx64.efi：退出 0、全部换好、没有 .new" \
	eval '[ $rc = 0 ] && all_new "$(state_dir "$m")" && no_leftovers "$m"'
# 不降级：ESP 上的引导程序来自更新的镜像
cp "$tmp/old/BOOTX64.EFI" "$m/EFI/BOOT/BOOTX64.EFI"
echo 20261013.30 >"$m/loader/mastersos-bootloader.version"
rc=0
VERSION=20261013.20 run "$m" || rc=$?
check "本次开机的镜像（20261013.20）比 ESP 上的标记（20261013.30）旧：退出 0、不动" \
	eval '[ $rc = 0 ] && [ "$(cat "$tmp/steps")" = 0 ] && stamp_is "$m" 20261013.30 && grep -q 不降级 "$tmp/last.log"'
# 版本号按 sort -V 比：.100 比 .30 新
rc=0
VERSION=20261013.100 run "$m" || rc=$?
check "20261013.100 比 20261013.30 新：换、标记改成 .100" \
	eval '[ $rc = 0 ] && all_new "$(state_dir "$m")" && stamp_is "$m" 20261013.100'
# 镜像里缺文件：什么都不动
cp "$tmp/old/grubx64.efi" "$m/EFI/BOOT/grubx64.efi"
mv "$tmp/new/mmx64.efi" "$tmp/mm.bak"
rc=0
VERSION=20261013.100 run "$m" || rc=$?
mv "$tmp/mm.bak" "$tmp/new/mmx64.efi"
check "镜像里缺 mmx64.efi：退出非零、ESP 一个字节都没动" \
	eval '[ $rc != 0 ] && [ "$(cat "$tmp/steps")" = 0 ] && [ "$(state_dir "$m")" = "grubx64.efi=old mmx64.efi=new BOOTX64.EFI=new" ]'
# 看不懂的版本号
rc=0
VERSION=garbage run "$m" || rc=$?
check "IMAGE_VERSION 看不懂：退出非零、不动" eval '[ $rc != 0 ] && [ "$(cat "$tmp/steps")" = 0 ]'
umount_esp misc
# ESP 满了：cp 写到一半失败
new_esp full
m=$tmp/mnt-full
free=$(df -B1 --output=avail "$m" | tail -1)
fallocate -l $((free - 200000)) "$m/filler" 2>/dev/null || head -c $((free - 200000)) /dev/zero >"$m/filler"
sync -f "$m"
rc=0
run "$m" || rc=$?
s=$(state_dir "$m")
check "ESP 只剩约 200 KB：退出非零、三个都完整（$s）、没有 .new" \
	eval '[ $rc != 0 ] && bootable "$s" && no_leftovers "$m"'
rm "$m/filler"
rc=0
run "$m" || rc=$?
check "  腾出地方后再跑：全部换好" eval '[ $rc = 0 ] && all_new "$(state_dir "$m")"'
umount_esp full

echo "bootloader-update-test: $((t_n - t_fail))/$t_n 通过"
[ "$t_fail" = 0 ]
