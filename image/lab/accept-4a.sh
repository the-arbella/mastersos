#!/bin/bash
# 计划 4a 的 VM 验收阶梯（Task 12）。在 Mac 上跑，经 lab-host 操作 PVE 上的试验机与构建机 VM 161：
#   accept-4a.sh <vmid> <check…|all>
# 每个 check 是下面的一个函数，打印「PASS <名字>」或「FAIL <名字>：<原因>」；全部输出 tee 到
# results/<日期>-4a/<vmid>.txt，截图放同一目录；退出码 = 失败个数。
#   165 all = install etc_policy seed_and_agent luks_sealed channel_beta update_interrupted rollback
#             bad_bundle_no_rollback bootloader_update factory_reset tpm_matrix tamper chrome
#   168 all = offline_first_boot online_first_boot unmanaged local_password_change
#   （factory_reset 只对 4a 的镜像：4b 的镜像用 accept-4b.sh 的 reset_local。
#    4a 在 VM 166 上验的「没有 TPM 装成空口令」已去掉：4b 起 TPM 2.0 是前提，没有 TPM 的机器安装器拒装，
#    这条验收换成 4b Task 20 的 no_tpm_refused。）
# 命令全经 gx.sh、shot.sh、keys.sh、serial.sh 与 lab 服务端的管理 API。令牌只从 Mac 的
# ~/.config/testlab/mastersos/mastersos-lab-{ops,recovery}.token 读、经 stdin 交给构建机上的 curl，不进命令行、不进记录；
# 恢复密钥同样只经 stdin（qm guest exec --pass-stdin、串口）。种子（含 fetch_token）只在 PVE 上临时放、做完 U 盘即删。
#
# 构建与发布（在 VM 161 上，MASTERSOS_SNAPSHOT 固定为 A4_SNAPSHOT）：check 需要的版本没构建过就先构建；只发 lab 根的
# beta（坏版本也只进 beta，不进 stable）；发布之后删掉构建产物，只留装机的那一版。版本号（都可用环境变量改）：
#   A4_V_BASE   U 盘装的版本          A4_V_BETA1  channel_beta      A4_V_BETA2  update_interrupted
#   A4_V_BROKEN_USER / A4_V_BROKEN_INITRD  rollback      A4_V_GOOD  bad_bundle_no_rollback   A4_V_TAMPER  tamper
#   A4_V_OLD    取旧 systemd-boot 的构建（bootloader_update；默认 lab stable 的 20261013.12）
# 环境变量：A4_DATE（结果目录的日期，默认今天）、A4_SNAPSHOT、A4_BUILD_HOST、A4_SERVER。
# shellcheck disable=SC2029,SC2329,SC2016,SC2015,SC2001,SC2034 # 本机展开是有意的（参数先校验再拼进远端命令）；check 经 "c_$c" 间接调用；远端命令有意用单引号；pass 不会失败；accept-common.sh 用到的变量在这里设
set -euo pipefail

here=${A4_HERE:-$(cd "$(dirname "$0")" && pwd)}
[ $# -ge 2 ] || {
	echo "用法：accept-4a.sh <vmid> <check…|all>" >&2
	exit 2
}
vmid=$1
shift
case "$vmid" in 165 | 168) ;; *)
	echo "accept-4a.sh: 只跑 165、168，实际：$vmid" >&2
	exit 2
	;;
esac

date_=${A4_DATE:-$(date +%Y-%m-%d)}
out=${A4_OUT:-$here/results/$date_-4a}
# 跨 check 的中间值（种子的 sha256、试验口令、清单）放在仓库外：试验口令绝不进 results/
state=${A4_STATE:-$HOME/.cache/mastersos-accept-4a/$date_}
mkdir -p "$out"
mkdir -p "$state" && chmod 700 "$state"
export SHOT_DIR=$out

snapshot=${A4_SNAPSHOT:-20261013T000000Z}
bhost=${A4_BUILD_HOST:-mastersos@192.0.2.99}
server=${A4_SERVER:-http://192.0.2.99:8480}
upd=http://192.0.2.99/mastersos
root161=/var/www/html/mastersos
lab=/var/lib/vz/mastersos-lab
cfg=$HOME/.config/testlab/mastersos
V_BASE=${A4_V_BASE:-20261014.20}
V_BETA1=${A4_V_BETA1:-20261014.31}
V_BETA2=${A4_V_BETA2:-20261014.32}
V_BROKEN_USER=${A4_V_BROKEN_USER:-20261014.33}
V_BROKEN_INITRD=${A4_V_BROKEN_INITRD:-20261014.34}
V_GOOD=${A4_V_GOOD:-20261014.35}
V_TAMPER=${A4_V_TAMPER:-20261014.36}
V_OLD=${A4_V_OLD:-20261013.12}
for v in "$V_BASE" "$V_BETA1" "$V_BETA2" "$V_BROKEN_USER" "$V_BROKEN_INITRD" "$V_GOOD" "$V_TAMPER" "$V_OLD"; do
	# 这些值会拼进远端的 rm -rf mastersos-image/mkosi.output/<v>：格式不对就停
	[[ $v =~ ^[0-9]{8}\.[0-9]+$ ]] || {
		echo "accept-4a.sh: 版本号应形如 20261014.1，实际：'$v'" >&2
		exit 2
	}
done

# A4_LIB=1：只定义函数、不跑 check、不写记录（负向测试 tests/accept-4a-vacuous-test.sh 用它 source 本文件）
[ -n "${A4_LIB:-}" ] || exec > >(tee -a "$out/$vmid.txt") 2>&1
# 共用的函数（底层、服务端 API、构建与发布、U 盘、rollback、local_password_change）：4b 的 accept-4b.sh 也用
# shellcheck source-path=SCRIPTDIR source=accept-common.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/accept-common.sh"

# ==================================================================================
# checks
# ==================================================================================

c_install() { # 165：从带种子的 U 盘重装（其余 check 的前提）
	install_from seeded "install" || {
		fail install "安装器没有走到结束屏"
		return
	}
	pve "qm start $vmid" >/dev/null
	if wait_up 300; then
		shot install-gdm
		pass install
	else
		fail install "装好后 300 秒内没有 GDM"
	fi
}

c_bundle() { # 发一份 stable 通道的设置包（服务端刚建好、或要把机器拉回 stable 时）
	publish_manifest "$(manifest stable)"
	pass bundle
}

c_etc_policy() {
	local name=etc_policy bad="" o
	start_wait || {
		fail "$name" "起不来"
		return
	}
	o=$(gxm '
test -L /etc/os-release || echo "os-release 不是链接"
for p in pam.d nsswitch.conf issue fstab; do [ ! -e /usr/share/factory/etc/$p ] || [ -L /etc/$p ] || echo "/etc/$p 应是指回 factory 的链接"; done
test -f /etc/passwd -a ! -L /etc/passwd || echo "passwd 不是真实文件"
for d in /etc/NetworkManager/system-connections /etc/opt/chrome/policies/managed; do test -d $d -a ! -L $d || echo "$d 不是真实目录"; done
src=$(findmnt -no SOURCE /var/lib/mastersos-seed); fs=$(findmnt -no FSTYPE /var/lib/mastersos-seed); opt=$(findmnt -no OPTIONS /var/lib/mastersos-seed)
echo "  种子：$src $fs $opt" >&2
[ "$fs" = ext4 ] || echo "种子分区不是 ext4"
for x in nosuid nodev noexec; do case ",$opt," in *",$x,"*) ;; *) echo "种子挂载没有 $x";; esac; done
ls "$(bootctl -p)" >/dev/null # ESP 是 automount，先碰一下
boot=$(lsblk -no PKNAME "$(findmnt -nr -o SOURCE,FSTYPE "$(bootctl -p)" | awk "\$2 == \"vfat\" {print \$1}")")
[ "$(lsblk -no PKNAME "$src")" = "$boot" ] || echo "种子分区不在启动盘 $boot 上"
for d in /var/lib/mastersos /var/lib/mastersos-seed /var/lib/mastersos-system; do [ "$(stat -c %a $d)" = 700 ] || echo "$d 不是 700"; done
[ -z "$(findmnt -no SOURCE /var/lib/mastersos)" ] || echo "/var/lib/mastersos 是单独的挂载"
[ "$(systemctl is-active display-manager)" = active ] || echo "display-manager 不是 active"
test ! -e /usr/share/applications/gnome-initial-setup.desktop || echo "有 gnome-initial-setup"
# 顶层的真实项只许：策略表的 copy/dir、包 tmpfiles 建的目录、开机生成的（machine-id、preset 写的 systemd、ldconfig）
allow=" "
for e in $(grep -E "^[Cd] /etc/[^/ ]+ " /usr/lib/tmpfiles.d/00-mastersos-factory-etc.conf | awk "{print \$2}" | sed "s|/etc/||"); do allow="$allow$e "; done
allow="$allow machine-id .updated systemd ld.so.cache credstore credstore.encrypted colord passwd- group- shadow- gshadow- subuid- subgid- .pwd.lock adjtime "
cd /etc; for e in * .[!.]*; do [ -e "$e" ] || continue; [ -L "$e" ] && continue; case "$allow" in *" $e "*) ;; *) echo "/etc/$e 是真实的，策略表与已知的开机生成项里都没有";; esac; done
') || o="远端检查块没有跑完（guest agent），一条都不算通过"
[ -z "$o" ] || bad="$bad${o//$'\n'/；}；"
log "常规项：${o:-全部成立}"

# 冒名的种子分区：第二块盘上 PARTLABEL=mastersos-seed、内容不同
local imp=$lab/a4-impostor.raw
pve "test -f $imp || { set -e; d=\$(mktemp -d); mkdir \$d/fs; echo 'server = \"http://impostor.invalid\"' > \$d/fs/seed.toml; truncate -s 62M \$d/p.img; mkfs.ext4 -q -d \$d/fs -L mastersos-seed \$d/p.img; truncate -s 64M $imp; printf 'label: gpt\nstart=2048, size=126976, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name=mastersos-seed\n' | sfdisk -q $imp; dd if=\$d/p.img of=$imp bs=512 seek=2048 conv=notrunc status=none; rm -rf \$d; }"
# 第二块盘：local-lvm 上 1 GiB 的卷，写进冒名的分区表与 ext4（local 存储不收虚拟盘）
pve "set -e; qm set $vmid --scsi1 local-lvm:1 >/dev/null; v=\$(qm config $vmid | sed -n 's/^scsi1: \([^,]*\),.*/\1/p'); dev=\$(pvesm path \$v); [ -b \$dev ] || lvchange -ay \$dev; dd if=$imp of=\$dev bs=1M conv=fsync status=none"
reboot_wait || bad="${bad}挂冒名盘后起不来；"
o=$(gx 'lsblk -no NAME,PARTLABEL | grep mastersos-seed; echo "挂载：$(findmnt -no SOURCE /var/lib/mastersos-seed)"; cat /run/mastersos/seed-generator.log 2>/dev/null')
echo "$o" | sed 's/^/  冒名盘：/'
gx 'ls "$(bootctl -p)" >/dev/null; boot=$(lsblk -no PKNAME "$(findmnt -nr -o SOURCE,FSTYPE "$(bootctl -p)" | awk "\$2 == \"vfat\" {print \$1}")"); s=$(findmnt -no SOURCE /var/lib/mastersos-seed) && [ "$(lsblk -no PKNAME "$s")" = "$boot" ] && grep -q "忽略" /run/mastersos/seed-generator.log' || bad="${bad}冒名盘时种子挂载不对或生成器没记下忽略；"
stop_vm
pve "v=\$(qm config $vmid | sed -n 's/^scsi1: \([^,]*\),.*/\1/p'); qm set $vmid --delete scsi1; u=\$(qm config $vmid | sed -n \"s|^\(unused[0-9]*\): \$v\$|\1|p\"); [ -z \"\$u\" ] || qm set $vmid --delete \$u" >/dev/null

# 种子分区坏了：快照 → wipefs → 重启照常进 GDM → 回滚
start_wait || true
snap a4-etc "accept-4a etc_policy: before wiping the seed partition"
gx 'p=$(findmnt -no SOURCE /var/lib/mastersos-seed); umount /var/lib/mastersos-seed && wipefs -a "$p" && blkid "$p"; echo "（blkid 之后）"' || bad="${bad}wipefs 失败；"
if reboot_wait 400; then
	o=$(gx 'echo "种子挂载：$(findmnt -no SOURCE /var/lib/mastersos-seed || echo 无)；is-system-running：$(systemctl is-system-running)"; systemctl is-active emergency.target rescue.target 2>/dev/null | tr "\n" " "')
	log "种子坏了：$o"
	shot etc-seed-wiped-gdm
else
	bad="${bad}种子分区坏了起不来；"
fi
stop_vm
rollback a4-etc
delsnap a4-etc
start_wait || bad="${bad}回滚后起不来；"
[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

c_seed_and_agent() {
	local name=seed_and_agent bad="" o id want
	start_wait || {
		fail "$name" "起不来"
		return
	}
	want=$(cat "$state/seed.sha256" 2>/dev/null || echo "?")
	o=$(gxm "
e=\$(bootctl -p)
ls \$e/EFI/Linux | grep -q '+' && echo 'ESP 的主 UKI 带启动计数（刚装好不该带）: '\$(ls \$e/EFI/Linux)
for f in /var/lib/mastersos-seed/seed.toml /var/lib/mastersos/seed.toml; do
  [ \"\$(sha256sum < \$f | cut -d' ' -f1)\" = '$want' ] || echo \"\$f 与 U 盘上的种子不同\"
  [ \"\$(stat -c '%a %U' \$f)\" = '600 root' ] || echo \"\$f 不是 600 root\"
done
for d in /var/lib/mastersos /var/lib/mastersos-seed; do [ \"\$(stat -c %a \$d)\" = 700 ] || echo \"\$d 不是 700\"; done
runuser -u student -- cat /var/lib/mastersos/current/manifest.toml >/dev/null 2>&1 && echo 'student 读得到 manifest'
[ \"\$(systemctl is-active mastersos-agent)\" = active ] || echo 'mastersos-agent 不是 active'
[ \"\$(systemctl show -p ConditionResult --value mastersos-firstrun)\" = no ] || echo 'mastersos-firstrun 在带种子的机器上跑了'
test ! -e /usr/libexec/gnome-initial-setup || echo '有 gnome-initial-setup'
mokutil --test-key /usr/share/mastersos/mastersos-mok.der 2>&1 | grep -q 'already enrolled' || echo 'MOK 没登记'
[ -z \"\$(mokutil --list-new 2>/dev/null)\" ] || echo '还有待登记的 MOK（安装器 mokutil --import 了？）'
bootctl list --no-pager 2>/dev/null | grep -qi installer && echo '启动菜单里有安装器'
bootctl list --no-pager 2>/dev/null | grep -qi 'factory reset' || echo '启动菜单里没有恢复出厂'
") || o="远端检查块没有跑完（guest agent），一条都不算通过"
[ -z "$o" ] || bad="$bad${o//$'\n'/；}；"
id=$(device_id)
o=$(device_json "$id")
log "服务端：$(jq -c '{device_id, group, bundle_version, os_version: .os_version}' <<<"$o" 2>/dev/null)"
[ "$(jq -r .group <<<"$o" 2>/dev/null)" = default ] || bad="${bad}服务端机器列表里没有 ${id}（或组不是 default）；"
gx 'bootctl list --no-pager | grep -E "title|id:"' | sed 's/^/  /'
[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

c_luks_sealed() {
	local name=luks_sealed bad="" o id luks key
	start_wait || {
		fail "$name" "起不来"
		return
	}
	o=$(gx 'cryptsetup luksDump /dev/gpt-auto-root-luks | grep -E "^ +[0-9]+: |tpm2-hash-pcrs|tpm2-pubkey-pcrs|tpm2-pcrlock|^UUID"')
	echo "$o" | sed 's/^/  /'
	grep -q 'systemd-recovery' <<<"$o" || bad="${bad}没有 recovery 槽；"
	grep -qE 'tpm2-pcrlock: +true' <<<"$o" || bad="${bad}tpm2 token 没有 pcrlock；"
	grep -qE 'tpm2-hash-pcrs: *$' <<<"$o" || bad="${bad}字面 PCR 不为空；"
	grep -qE 'tpm2-pubkey-pcrs: +11' <<<"$o" || bad="${bad}签名 PCR 不是 11；"
	gx 'test ! -e /var/lib/mastersos-system/escrow-pending.json' || bad="${bad}还有 escrow-pending.json；"
	id=$(device_id)
	luks=$(gx 'cryptsetup luksUUID /dev/gpt-auto-root-luks' | tr -d '\n')
	o=$(api recovery GET "/v1/admin/devices/$id/recovery-keys")
	log "服务端恢复密钥：$(jq -c --arg u "$luks" '[.[] | select(.luks_uuid == $u)] | length' <<<"$o") 行属于 ${luks}（共 $(jq length <<<"$o") 行）"
	key=$(jq -r --arg u "$luks" '[.[] | select(.luks_uuid == $u)][0].recovery_key // empty' <<<"$o")
	if [ -z "$key" ]; then
		bad="${bad}服务端没有这块 LUKS 的恢复密钥；"
	elif printf '%s' "$key" | gx_stdin 'cryptsetup open --test-passphrase --disable-external-tokens --key-file=- /dev/gpt-auto-root-luks'; then
		log "服务端那把恢复密钥能解开（--test-passphrase --disable-external-tokens rc=0）"
		printf 'wrong-%s' "$key" | gx_stdin 'cryptsetup open --test-passphrase --disable-external-tokens --key-file=- /dev/gpt-auto-root-luks' 2>/dev/null &&
			bad="${bad}错的口令也解开了；"
	else
		bad="${bad}服务端的恢复密钥解不开；"
	fi
	unset key
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

c_channel_beta() {
	local name=channel_beta bad="" t0 o
	start_wait || {
		fail "$name" "起不来"
		return
	}
	build "$V_BETA1" || {
		fail "$name" "构建 $V_BETA1 失败"
		return
	}
	gx 'ls /etc/sysupdate.d/ 2>/dev/null | wc -l' | grep -qx 0 || log "（之前 /etc/sysupdate.d 已有覆盖）"
	publish_manifest "$(manifest beta)"
	t0=$SECONDS
	until gx 'ls /etc/sysupdate.d/*.transfer 2>/dev/null | wc -l' | grep -qx 4 || [ $((SECONDS - t0)) -gt 30 ]; do sleep 1; done
	o=$(gx 'grep -h "^Path=http" /etc/sysupdate.d/*.transfer | sort | uniq -c')
	log "$((SECONDS - t0)) 秒后 /etc/sysupdate.d：$o"
	[ $((SECONDS - t0)) -le 10 ] || bad="${bad}覆盖 $((SECONDS - t0)) 秒才出现（要 ≤10）；"
	grep -q "4 Path=$upd/beta/" <<<"$o" || bad="${bad}覆盖不是四个指向 beta 的 transfer；"
	publish "$V_BETA1" beta || bad="${bad}publish $V_BETA1 beta 失败；"
	in_channel "$V_BETA1" stable && bad="${bad}$V_BETA1 也在 stable；"
	o=$(run_update)
	log "mastersos-update：${o//$'\n'/ }"
	reboot_wait || bad="${bad}更新后重启起不来；"
	o=$(img_version)
	log "重启后 IMAGE_VERSION=$o"
	[ "$o" = "$V_BETA1" ] || bad="${bad}重启后不是 ${V_BETA1}；"
	sleep 20
	gx 'journalctl -b -u systemd-bless-boot --no-pager -o cat | tail -2; ls "$(bootctl -p)/EFI/Linux"' | sed 's/^/  /'
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

c_update_interrupted() {
	local name=update_interrupted bad="" o
	start_wait || {
		fail "$name" "起不来"
		return
	}
	build "$V_BETA2" || {
		fail "$name" "构建 $V_BETA2 失败"
		return
	}
	publish "$V_BETA2" beta || bad="${bad}publish 失败；"
	# brief 写的是 20 秒；试验网是千兆局域网，整次下载约 15 秒就完（channel_beta 实测），20 秒时早已下完、测不到
	# 「下载到一半」——改为 A4_INTERRUPT_AFTER 秒（默认 5），并核对断网那一刻 mastersos-update 还在跑
	local after=${A4_INTERRUPT_AFTER:-5}
	gx 'systemctl start --no-block mastersos-update.service'
	sleep "$after"
	o=$(gx 'systemctl is-active mastersos-update.service; journalctl -u mastersos-update -b --no-pager -o cat | grep -vE "^$" | tail -2')
	log "${after} 秒时：${o//$'\n'/ | }"
	head -1 <<<"$o" | grep -qxE 'activating|active' || bad="${bad}断网前 mastersos-update 已经结束（没断在下载中）；"
	link 1
	pve "qm reboot $vmid --timeout 180" >/dev/null || pve "qm reset $vmid" >/dev/null
	sleep 10
	wait_up 400 || bad="${bad}中断后重启起不来；"
	o=$(img_version)
	log "中断后 IMAGE_VERSION=${o}；ESP：$(gx 'ls "$(bootctl -p)/EFI/Linux" | tr "\n" " "')"
	[ "$o" = "$V_BETA1" ] || bad="${bad}中断后不是旧版本 ${V_BETA1}；"
	shot update-interrupted-gdm
	link 0
	sleep 5
	o=$(run_update)
	log "恢复网络后 mastersos-update：${o//$'\n'/ }"
	grep -qx success <<<"$o" || bad="${bad}恢复网络后更新没成功；"
	reboot_wait || bad="${bad}更新后起不来；"
	o=$(img_version)
	log "IMAGE_VERSION=$o"
	[ "$o" = "$V_BETA2" ] || bad="${bad}没进 ${V_BETA2}；"
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

c_bad_bundle_no_rollback() {
	local name=bad_bundle_no_rollback bad="" o
	start_wait || {
		fail "$name" "起不来"
		return
	}
	build "$V_GOOD" || {
		fail "$name" "构建 $V_GOOD 失败"
		return
	}
	gx 'mkdir -p /etc/systemd/system/mastersos-agent-local.service.d && printf "[Service]\nExecStart=\nExecStart=/bin/false\n" > /etc/systemd/system/mastersos-agent-local.service.d/zz-a4-broken.conf && systemctl daemon-reload'
	publish "$V_GOOD" beta || bad="${bad}publish 失败；"
	run_update | sed 's/^/  /'
	reboot_wait || bad="${bad}重启起不来；"
	sleep 90
	o=$(gx 'echo "$(. /usr/lib/os-release; echo $IMAGE_VERSION) local=$(systemctl show -p Result --value mastersos-agent-local) up=$(cut -d. -f1 /proc/uptime)s"; journalctl -b -u systemd-bless-boot --no-pager -o cat | grep -m1 "Marked boot"; ls "$(bootctl -p)/EFI/Linux" | tr "\n" " "')
	log "${o//$'\n'/ | }"
	grep -q "^$V_GOOD local=exit-code" <<<"$o" || bad="${bad}不是「$V_GOOD 且 mastersos-agent-local 失败」；"
	grep -q "Marked boot as 'good'" <<<"$o" || bad="${bad}这次开机没有被标记为好；"
	grep -q "MastersOS_${V_GOOD}_x86-64.efi" <<<"$o" || bad="${bad}ESP 上 $V_GOOD 的 UKI 还带计数；"
	gx 'rm -rf /etc/systemd/system/mastersos-agent-local.service.d && systemctl daemon-reload'
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

c_bootloader_update() {
	local name=bootloader_update bad="" o
	start_wait || {
		fail "$name" "起不来"
		return
	}
	# 上一版镜像（A4_V_OLD）里签好的 systemd-boot，经 nginx 临时给 VM 取
	b161 "set -e; d=$root161/a4-tmp; mkdir -p \$d; mcopy -n -i mastersos-image/mkosi.output/$V_OLD/MastersOS_${V_OLD}_x86-64.esp.raw ::EFI/BOOT/grubx64.efi \$d/old-grubx64.efi; chmod -R a+rX \$d; sha256sum \$d/old-grubx64.efi"
	o=$(gx "set -e; e=\$(bootctl -p); f=\$(ls \$e/EFI/BOOT/ | grep -i '^grubx64.efi\$'); curl -fsS -o \$e/EFI/BOOT/\$f ${upd}/a4-tmp/old-grubx64.efi; sha256sum \$e/EFI/BOOT/\$f /usr/lib/mastersos/esp/grubx64.efi; systemctl restart mastersos-bootloader-update; journalctl -b -u mastersos-bootloader-update --no-pager -o cat | grep -E \"替换|换好了|相同\" | tail -2; sha256sum \$e/EFI/BOOT/\$f; find \$e -name '*.new' | wc -l")
	echo "$o" | sed 's/^/  /'
	b161 "rm -rf $root161/a4-tmp"
	[ "$(sed -n 1p <<<"$o" | cut -d' ' -f1)" != "$(sed -n 2p <<<"$o" | cut -d' ' -f1)" ] || bad="${bad}旧的 systemd-boot 与镜像里的一样（没换成功）；"
	[ "$(tail -2 <<<"$o" | head -1 | cut -d' ' -f1)" = "$(sed -n 2p <<<"$o" | cut -d' ' -f1)" ] || bad="${bad}更新后 ESP 上的 grubx64.efi 与 /usr/lib/mastersos/esp 的不同；"
	[ "$(tail -1 <<<"$o")" = 0 ] || bad="${bad}留下了 .new；"
	reboot_wait || bad="${bad}重启起不来；"
	gx 'bootctl status --no-pager 2>/dev/null | grep -E "Product|Secure Boot"' | sed 's/^/  /'
	o=$(cat "$state/bootloader-unblessed.txt" 2>/dev/null || echo "")
	log "坏版本（计数未用完）那次开机：${o:-没有记录（先跑 rollback）}"
	[ "$(grep -c 'health_failed=[1-9] marked_good=0 bootloader_update_lines=0' <<<"$o")" = 3 ] ||
		bad="${bad}坏版本（计数未用完）的三次开机里 mastersos-bootloader-update 跑过、被标好，或者没有记录；"
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# 4a 的恢复出厂只打 ERASE。4b Task 5 起受管机器先问恢复密钥（错的不清数据），这一条已由 accept-4b.sh 的 reset_local
# （与 reset_remote）取代，不再对 4b 的镜像跑；留着只为 4a 的镜像与 tests/accept-4a-vacuous-test.sh。
c_factory_reset() {
	local name=factory_reset bad="" o before after id rows0 v0 uki
	start_wait || {
		fail "$name" "起不来"
		return
	}
	# 包里放一个往 /var/lib/mastersos-system/ran 追加一行的脚本
	printf '#!/bin/sh\nset -e\necho "ran $(date -u +%%FT%%TZ) boot=$(cat /proc/sys/kernel/random/boot_id)" >> /var/lib/mastersos-system/ran\n' >"$state/ran.sh"
	publish_manifest "$(manifest beta script)" "scripts/ran.sh=$state/ran.sh"
	local t0=$SECONDS
	until gx 'test -s /var/lib/mastersos-system/ran' 2>/dev/null || [ $((SECONDS - t0)) -gt 120 ]; do sleep 3; done
	sleep 5
	id=$(device_id)
	rows0=$(recovery_rows "$id")
	before=$(gx 'cd /var/lib/mastersos-seed && sha256sum seed.toml cache/current.bundle identity.json; echo "luks $(cryptsetup luksUUID /dev/gpt-auto-root-luks)"; echo "machine-id $(cat /etc/machine-id)"; echo "version $(jq -r .version /var/lib/mastersos/state.json)"; echo "ran $(wc -l < /var/lib/mastersos-system/ran)"')
	echo "$before" | sed 's/^/  之前：/'
	v0=$(awk '/^version/{print $2}' <<<"$before")
	log "之前：device_id ${id}，服务端恢复密钥 $rows0 行"
	link 1
	uki=$(gx '. /usr/lib/os-release; bootctl list --no-pager | sed -n "s/^ *id: \(MastersOS_${IMAGE_VERSION}_x86-64\.efi@[^ ]*\).*/\1/p" | grep -v "@main" | head -1' | tr -d '\n')
	log "恢复出厂的启动项：$uki"
	gx "bootctl set-oneshot '$uki' && bootctl status --no-pager | grep -iE 'oneshot|One-shot'" | sed 's/^/  /'
	m=$(serial_mark)
	pve "qm reboot $vmid --timeout 180" >/dev/null
	if o=$(printf 'ERASE\n' | serial_answer 'Type ERASE to continue' 240); then
		log "串口：确认提示出现，敲了 ERASE；之后：${o//$'\n'/ | }"
	else
		bad="${bad}没有出现恢复出厂的确认提示；"
	fi
	sleep 20
	wait_up 400 || bad="${bad}恢复出厂后起不来；"
	sleep 30
	after=$(gx 'cd /var/lib/mastersos-seed && sha256sum seed.toml cache/current.bundle identity.json; echo "luks $(cryptsetup luksUUID /dev/gpt-auto-root-luks)"; echo "machine-id $(cat /etc/machine-id)"; echo "version $(jq -r .version /var/lib/mastersos/state.json 2>/dev/null)"; echo "ran $(wc -l < /var/lib/mastersos-system/ran 2>/dev/null || echo 0)"; grep -o "systemd.factory_reset=1" /proc/cmdline')
	echo "$after" | sed 's/^/  之后（断网）：/'
	log "串口：$(serial_since "$m" | grep -aE 'factory reset|Removing partition' | head -3 | tr '\n' ' ')"
	[ "$(head -3 <<<"$before")" = "$(head -3 <<<"$after")" ] || bad="${bad}种子分区的三个文件变了；"
	[ "$(grep ^luks <<<"$before")" != "$(grep ^luks <<<"$after")" ] || bad="${bad}LUKS UUID 没变；"
	if [ "$(grep ^machine-id <<<"$before")" = "$(grep ^machine-id <<<"$after")" ]; then
		# systemd 在虚拟机里用 SMBIOS/DMI 的 UUID 初始化 machine-id（journal：Initializing machine ID from SMBIOS/DMI UUID），
		# 所以 VM 上恢复出厂之后它不变；真机（不是虚拟机）是随机生成的。只在它确实等于 VM UUID 时放过
		if gx '[ "$(cat /etc/machine-id)" = "$(tr -d - < /sys/class/dmi/id/product_uuid)" ] && journalctl -b -o cat --no-pager | grep -q "Initializing machine ID from SMBIOS/DMI UUID"'; then
			log "machine-id 没变：它取自 VM 的 SMBIOS UUID（systemd 在虚拟机里的做法），真机上是随机的——这一条留给 4b 的 Dell"
		else
			bad="${bad}machine-id 没变；"
		fi
	fi
	[ "$(awk '/^version/{print $2}' <<<"$after")" = "$v0" ] || bad="${bad}断网时设置没按缓存包回来（version 不是 ${v0}）；"
	[ "$(awk '/^ran/{print $2}' <<<"$after")" -ge 1 ] 2>/dev/null || bad="${bad}apply 脚本没有重跑；"
	shot factory-reset-offline-gdm
	link 0
	local t1=$SECONDS rows1=$rows0
	while [ $((SECONDS - t1)) -lt 180 ]; do
		rows1=$(recovery_rows "$id" 2>/dev/null || echo "$rows0")
		[ "$rows1" -gt "$rows0" ] && break
		sleep 5
	done
	o=$(device_json "$id")
	log "联网后：服务端 $id last_seen $(jq -r .last_seen <<<"$o")，恢复密钥 $rows0 → $rows1 行；luks:escrow $(jq -c '.results[]? | select(.item=="luks:escrow")' <<<"$o")"
	[ "$rows1" -eq $((rows0 + 1)) ] || bad="${bad}服务端恢复密钥没有多一行（$rows0 → ${rows1}）；"
	gx 'journalctl -b -u mastersos-agent --no-pager -o cat | grep -E "403|托管|escrow" | tail -3' | sed 's/^/  /'
	o=$(gxm 'journalctl -b -u mastersos-agent --no-pager -o cat | grep -c " 403"') || o=""
	[ "$o" = 0 ] || bad="${bad}托管被 403，或 journal 没查成（${o:-无输出}）；"
	local t2=$SECONDS
	until gx 'systemd-sysext status --no-pager 2>/dev/null | grep -q google-chrome' 2>/dev/null || [ $((SECONDS - t2)) -gt 300 ]; do sleep 10; done
	gx 'systemd-sysext status --no-pager' | sed 's/^/  /'
	gx 'systemd-sysext status --no-pager | grep -q google-chrome' || bad="${bad}Chrome 没有重新装上；"

	# 手工一次：开机按空格出菜单、选恢复出厂（截图）
	m=$(serial_mark)
	pve "qm reboot $vmid --timeout 180" >/dev/null
	local i
	for i in $(seq 1 40); do
		pve "qm sendkey $vmid spc" >/dev/null 2>&1 || true
		sleep 0.5
	done
	shot factory-reset-menu
	keys down wait:1
	shot factory-reset-menu-selected
	keys ret
	if o=$(printf 'ERASE\n' | serial_answer 'Type ERASE to continue' 240); then
		shot factory-reset-confirm
		log "手工路线：确认提示出现，敲了 ERASE；之后：${o//$'\n'/ | }"
	else
		bad="${bad}手工路线没有出现确认提示；"
	fi
	sleep 20
	wait_up 400 || bad="${bad}手工恢复出厂后起不来；"
	o=$(gx 'echo "luks $(cryptsetup luksUUID /dev/gpt-auto-root-luks)"')
	log "手工路线之后：$o"
	[ "$o" != "$(grep ^luks <<<"$after")" ] || bad="${bad}手工路线 LUKS UUID 没变；"
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

c_tpm_matrix() {
	local name=tpm_matrix bad="" o id luks m pcr
	start_wait || {
		fail "$name" "起不来"
		return
	}
	id=$(device_id)
	luks=$(gx 'cryptsetup luksUUID /dev/gpt-auto-root-luks' | tr -d '\n')
	# 矩阵第 4、5、7 行说的是「托管之后、绑了 pcrlock」的槽：刚恢复出厂的机器在 agent 托管完之前只有签名 PCR 11
	# （Ruling 7），这时往 db 加证书照样无需输入。先等 pcrlock 绑上（最多 180 秒）
	local t0=$SECONDS
	until gx 'cryptsetup luksDump /dev/gpt-auto-root-luks | grep -qE "tpm2-pcrlock: +true"' 2>/dev/null || [ $((SECONDS - t0)) -gt 180 ]; do sleep 5; done
	gx 'cryptsetup luksDump /dev/gpt-auto-root-luks | grep -E "tpm2-pcrlock:|tpm2-pubkey-pcrs"' | sed 's/^/  /'
	gx 'cryptsetup luksDump /dev/gpt-auto-root-luks | grep -qE "tpm2-pcrlock: +true"' || {
		fail "$name" "180 秒内 TPM 槽没有绑上 pcrlock（托管没完成？）"
		return
	}
	# 第 4 行：关机时往 efidisk 的 db 追加一张无关的证书
	stop_vm
	pve "set -e; d=\$(mktemp -d); openssl req -x509 -newkey rsa:2048 -nodes -keyout \$d/k -out \$d/c.pem -days 30 -subj '/CN=mastersos dummy db cert (T12 row 4)' 2>/dev/null; vol=\$(qm config $vmid | sed -n 's/^efidisk0: \([^,]*\),.*/\1/p'); dev=\$(pvesm path \$vol); [ -b \$dev ] || lvchange -ay \$dev; dd if=\$dev of=\$d/v.fd bs=540672 count=1 status=none; virt-fw-vars --inplace \$d/v.fd --add-db 6b68756e-6f73-4b68-756e-4f5300000012 \$d/c.pem >/dev/null; dd if=\$d/v.fd of=\$dev bs=540672 count=1 conv=notrunc status=none; rm -rf \$d"
	log "第 4 行：db 追加了 CN=mastersos dummy db cert (T12 row 4)"
	m=$(serial_mark)
	pve "qm start $vmid" >/dev/null
	if o=$(type_recovery_key "$id" "$luks"); then
		shot tpm-row4-prompt
		log "第 4 行：出现口令提示，敲了服务端的恢复密钥；之后：${o//$'\n'/ | }"
	else
		bad="${bad}第 4 行：没有口令提示或服务端取不到恢复密钥；"
	fi
	wait_up 400 || bad="${bad}第 4 行：输了恢复密钥也起不来；"
	sleep 30
	gx 'journalctl -b --no-pager -o cat -u mastersos-agent | grep -E "pcrlock" | tail -2; systemctl is-failed systemd-pcrlock-make-policy' | sed 's/^/  /'
	reboot_wait || bad="${bad}第 4 行：第二次重启起不来；"
	tpm_unlocked "第 4 行第二次重启" || bad="${bad}第 4 行：第二次重启不是 TPM 解开的；"

	# 第 5 行：关掉 Secure Boot，菜单里给命令行加 init=/bin/sh → 解不开
	stop_vm
	"$here/fw-vars.sh" "$vmid" secureboot off
	m=$(serial_mark)
	pve "qm start $vmid" >/dev/null
	local i
	for i in $(seq 1 24); do
		pve "qm sendkey $vmid up" >/dev/null 2>&1 || true
		sleep 0.5
	done
	keys e wait:1 end spc i n i t equal slash b i n slash s h wait:1
	shot tpm-row5-edited
	keys ret
	if serial_wait 'Please enter recovery key' 240 >/dev/null; then
		shot tpm-row5-prompt
		o=$(serial_since "$m" | grep -a -m1 'Kernel command line')
		log "第 5 行：${o:0:60}…$(grep -o 'init=/bin/sh' <<<"$o")；只出口令提示"
		grep -q 'init=/bin/sh' <<<"$o" || bad="${bad}第 5 行：命令行里没有 init=/bin/sh（编辑没生效）；"
		serial_since "$m" | grep -q 'TPM2 token unlocks' && bad="${bad}第 5 行：TPM 解开了；"
	else
		bad="${bad}第 5 行：没有出现口令提示；"
	fi
	pve "qm stop $vmid" >/dev/null
	"$here/fw-vars.sh" "$vmid" secureboot on
	start_wait || bad="${bad}第 5 行：打开 Secure Boot 后起不来；"
	tpm_unlocked "第 5 行之后打开 Secure Boot" || bad="${bad}第 5 行之后：打开 Secure Boot 不是 TPM 解开的；"

	# 第 7 行：换固件代码（machine pc → OVMF_CODE_4M.fd）
	pcr=$(gx 'systemd-analyze pcrs 0 7 --no-pager | tail -2')
	stop_vm
	pve "qm set $vmid --machine pc" >/dev/null
	start_wait || bad="${bad}第 7 行：换固件后起不来；"
	tpm_unlocked "第 7 行换固件" || bad="${bad}第 7 行：换固件后不是 TPM 解开的；"
	o=$(gx 'systemd-analyze pcrs 0 7 --no-pager | tail -2; bootctl status --no-pager | grep "Secure Boot"')
	log "第 7 行：之前 ${pcr//$'\n'/ | }；之后 ${o//$'\n'/ | }"
	[ "$(sed -n 1p <<<"$pcr")" != "$(sed -n 1p <<<"$o")" ] || bad="${bad}第 7 行：PCR 0 没变（固件没换上）；"
	[ "$(sed -n 2p <<<"$pcr")" = "$(sed -n 2p <<<"$o")" ] || bad="${bad}第 7 行：PCR 7 变了；"
	stop_vm
	pve "qm set $vmid --machine q35" >/dev/null
	start_wait || bad="${bad}第 7 行：换回 q35 后起不来；"
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

c_tamper() {
	local name=tamper bad="" o cur
	start_wait || {
		fail "$name" "起不来"
		return
	}
	cur=$(img_version)
	# 1. 非活动槽的 /usr 改 4 KB → veritysetup verify 失败
	o=$(gx '
cur=$(. /usr/lib/os-release; echo $IMAGE_VERSION)
ls "$(bootctl -p)" >/dev/null # ESP 是 automount，先碰一下
disk=/dev/$(lsblk -no PKNAME "$(findmnt -nr -o SOURCE,FSTYPE "$(bootctl -p)" | awk "\$2 == \"vfat\" {print \$1}")")
other=$(lsblk -nro NAME,PARTLABEL "$disk" | awk -v c="MastersOS_$cur" "\$2 ~ /^MastersOS_[0-9.]+$/ && \$2 != c {print \$2; exit}")
[ -n "$other" ] || { echo "没有非活动槽"; exit 1; }
data=/dev/$(lsblk -nro NAME,PARTLABEL "$disk" | awk -v l="$other" "\$2 == l {print \$1}")
hash=/dev/$(lsblk -nro NAME,PARTLABEL "$disk" | awk -v l="${other}_verity" "\$2 == l {print \$1}")
sig=/dev/$(lsblk -nro NAME,PARTLABEL "$disk" | awk -v l="${other}_verity_sig" "\$2 == l {print \$1}")
rh=$(tr -d "\0" < "$sig" | jq -r .rootHash)
echo "非活动槽 ${other}：$data $hash"
veritysetup verify "$data" "$hash" "$rh" >/dev/null 2>&1 && echo "改之前 verify 通过" || echo "改之前 verify 就不过"
dd if=/dev/urandom of="$data" bs=4096 count=1 seek=1000 conv=notrunc,fsync status=none
veritysetup verify "$data" "$hash" "$rh" 2>&1 | tail -1; echo "verify rc=${PIPESTATUS[0]}"
' 2>&1)
	echo "$o" | sed 's/^/  /'
	grep -q '改之前 verify 通过' <<<"$o" || bad="${bad}改之前 verify 就不过；"
	grep -qE 'verify rc=[1-9]' <<<"$o" || bad="${bad}改了 4 KB 之后 verify 仍通过；"
	# 2. 新版本下载后（还没启动过的 +3 UKI）改 8 字节 → 重启时被拒、回到正在用的好版本
	build "$V_TAMPER" || {
		fail "$name" "构建 $V_TAMPER 失败"
		return
	}
	publish "$V_TAMPER" beta || bad="${bad}publish 失败；"
	run_update | sed 's/^/  /'
	o=$(gx "set -e; f=\$(ls -d \$(bootctl -p)/EFI/Linux/MastersOS_${V_TAMPER}_x86-64+3*.efi); test -f \$f; case \$f in *+3.efi|*+3-0.efi) ;; *) echo \"\$f 已经启动过\"; exit 1;; esac; sz=\$(stat -c %s \$f); printf '\\xde\\xad\\xbe\\xef\\xde\\xad\\xbe\\xef' | dd of=\$f bs=1 seek=\$((sz / 2)) conv=notrunc status=none; sync; echo \"改了 \$f 中间的 8 字节（\$sz 字节）\"; ls \$(bootctl -p)/EFI/Linux")
	echo "$o" | sed 's/^/  /'
	grep -q "改了" <<<"$o" || bad="${bad}ESP 上没有还没启动过的 MastersOS_${V_TAMPER}_x86-64+3(-0).efi；"
	local m
	m=$(serial_mark)
	pve "qm reboot $vmid --timeout 180" >/dev/null
	sleep 15
	shot tamper-reboot
	wait_version "$cur" 600 || bad="${bad}没有回到 ${cur}；"
	o=$(gx 'ls "$(bootctl -p)/EFI/Linux" | tr "\n" " "; journalctl --list-boots --no-pager | tail -2')
	log "重启后 $(img_version)：${o//$'\n'/ | }"
	log "串口：$(serial_since "$m" | grep -aiE 'security|violation|verif|denied|MastersOS_'"$V_TAMPER" | head -4 | tr '\n' ' ')"
	# 被拒的那个 UKI 计数用完（+0-3）才算「重启时被拒、试满三次」；之后删掉它
	grep -q "MastersOS_${V_TAMPER}_x86-64+0-3.efi" <<<"$o" || bad="${bad}ESP 上 ${V_TAMPER} 的 UKI 不是 +0-3（没被试满三次就被跳过？）；"
	gx "rm -f \"\$(bootctl -p)\"/EFI/Linux/MastersOS_${V_TAMPER}_x86-64+*.efi"
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

c_chrome() {
	local name=chrome bad="" o
	start_wait || {
		fail "$name" "起不来"
		return
	}
	o=$(gx 'systemd-sysext status --no-pager | grep -E "google-chrome"; sysctl -n kernel.apparmor_restrict_unprivileged_userns; runuser -u student -- env DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus gsettings get org.gnome.shell favorite-apps')
	echo "$o" | sed 's/^/  /'
	grep -q google-chrome <<<"$o" || bad="${bad}systemd-sysext 里没有 google-chrome；"
	grep -q "'google-chrome.desktop'" <<<"$o" || bad="${bad}Dock 里没有 Chrome；"
	shot chrome-dock
	gx 'pkill -u student -f /opt/google/chrome/chrome; sleep 2; runuser -u student -- env XDG_RUNTIME_DIR=/run/user/1000 WAYLAND_DISPLAY=wayland-0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus setsid -f /usr/bin/google-chrome-stable --ozone-platform=wayland --no-first-run --no-default-browser-check chrome://sandbox >/dev/null 2>&1' || true
	sleep 15
	# 命令行给的 chrome:// 地址 Chrome 不开（只开新标签页）：在地址栏里敲
	keys ctrl-l wait:1 c h r o m e shift-semicolon slash slash s a n d b o x ret wait:4
	shot chrome-sandbox
	o=$(gx '
b=$(pgrep -u student -xo chrome); r=$(pgrep -u student -f -- "--type=renderer" | head -1)
echo "browser $b renderer $r"
[ -n "$b" ] && [ -n "$r" ] || exit 1
for ns in user pid net; do echo "$ns $(readlink /proc/$b/ns/$ns) $(readlink /proc/$r/ns/$ns)"; done
grep -E "^Seccomp:" /proc/$r/status
cat /proc/$b/attr/current 2>/dev/null')
	echo "$o" | sed 's/^/  /'
	for ns in user pid net; do
		awk -v n="$ns" '$1==n && $2!=$3 {f=1} END{exit !f}' <<<"$o" || bad="${bad}渲染进程与浏览器在同一个 $ns 命名空间（没有沙箱）；"
	done
	grep -qE 'Seccomp:[[:space:]]+2' <<<"$o" || bad="${bad}渲染进程没有 seccomp-bpf；"
	gx 'pkill -u student -f /opt/google/chrome/chrome' || true
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

agent_local_report() {
	gxm 'echo "gdm $(systemctl show -p ActiveEnterTimestampMonotonic --value gdm) local $(systemctl show -p ExecMainStartTimestampMonotonic --value mastersos-agent-local)-$(systemctl show -p ExecMainExitTimestampMonotonic --value mastersos-agent-local) result $(systemctl show -p Result --value mastersos-agent-local)"'
}
c_offline_first_boot() {
	local name=offline_first_boot bad="" o g s e t0
	install_from seeded "offline" down || {
		fail "$name" "安装器没有走到结束屏"
		return
	}
	pve "qm start $vmid" >/dev/null
	wait_up 300 || bad="${bad}断网首次开机 300 秒内没有 GDM；"
	shot offline-first-boot-gdm
	o=$(agent_local_report) || o=""
	g="" se="" s="" e=""
	read -r _ g _ se _ _ <<<"$o"
	[ -n "$se" ] && s=${se%-*} e=${se#*-}
	# 三个时间都要是非零的整数（单调时钟的微秒）；缺一个就不比，直接失败——否则空值算成 0，「≤60 秒」「≤45 秒」白白通过
	if is_uint "$g" && is_uint "$s" && is_uint "$e" && [ "$g" -gt 0 ] && [ "$s" -gt 0 ] && [ "$e" -ge "$s" ]; then
		log "断网首次开机：GDM 在开机后 $((g / 1000000)) 秒 active；apply-local 跑了 $(((e - s) / 1000000)) 秒（${o}）"
		[ $((g / 1000000)) -le 60 ] || bad="${bad}GDM 在 $((g / 1000000)) 秒（要 ≤60）；"
		[ $(((e - s) / 1000000)) -le 45 ] || bad="${bad}apply-local 跑了 $(((e - s) / 1000000)) 秒（要 ≤45）；"
	else
		bad="${bad}拿不到 GDM / apply-local 的时间（'${o}'）；"
	fi
	o=$(gxm 'systemctl is-active mastersos-agent; jq -c "{version, last_fetch_ok}" /var/lib/mastersos/state.json 2>/dev/null || echo "没有 state.json"; journalctl -b --no-pager -o cat -u mastersos-agent -u mastersos-agent-local | grep -cE "已接受设置包"; cryptsetup luksDump /dev/gpt-auto-root-luks | grep -E "^ +[0-9]+: |tpm2-pcrlock"; ls /var/lib/mastersos-system/') || o=""
	echo "$o" | sed 's/^/  断网时：/'
	head -1 <<<"$o" | grep -qx active || bad="${bad}mastersos-agent 不是 active；"
	grep -qE '"version":[0-9]' <<<"$o" && bad="${bad}断网时 state.json 已有 version；"
	[ "$(sed -n 3p <<<"$o")" = 0 ] || bad="${bad}断网时有「已接受设置包」；"
	grep -q 'escrow-pending.json' <<<"$o" || bad="${bad}断网时没有待托管文件（Task 8：先登记恢复密钥再托管）；"
	grep -qE 'tpm2-pcrlock: +true' <<<"$o" && bad="${bad}托管之前就绑了 pcrlock；"
	link 0
	t0=$SECONDS
	until gx 'jq -e ".version != null" /var/lib/mastersos/state.json' >/dev/null 2>&1 || [ $((SECONDS - t0)) -gt 60 ]; do sleep 1; done
	log "link_down=0 之后 $((SECONDS - t0)) 秒 state.json 的 version = $(gx 'jq -r .version /var/lib/mastersos/state.json' | tr -d '\n')"
	[ $((SECONDS - t0)) -le 30 ] || bad="${bad}联网后 $((SECONDS - t0)) 秒才拿到设置（要 ≤30）；"
	# 托管失败后 agent 按退避重试（离上一轮不到 60 秒的推迟到满 60 秒，Task 8），联网后最多等 180 秒
	t0=$SECONDS
	until gx 'cryptsetup luksDump /dev/gpt-auto-root-luks | grep -qE "tpm2-pcrlock: +true"' 2>/dev/null || [ $((SECONDS - t0)) -gt 180 ]; do sleep 5; done
	log "联网后 $((SECONDS - t0)) 秒（再加上面拿到设置的时间）pcrlock 绑上"
	gx 'journalctl -b -u mastersos-agent --no-pager -o short-monotonic | grep -E "托管|pcrlock|escrow" | tail -4' | sed 's/^/  /'
	o=$(gx 'cryptsetup luksDump /dev/gpt-auto-root-luks | grep -E "tpm2-pcrlock"; ls /var/lib/mastersos-system/ | tr "\n" " "')
	log "联网后：${o//$'\n'/ | }"
	grep -qE 'tpm2-pcrlock: +true' <<<"$o" || bad="${bad}联网托管之后没补上 pcrlock；"
	grep -q 'escrow-pending' <<<"$o" && bad="${bad}联网后还有待托管文件；"
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

c_online_first_boot() {
	local name=online_first_boot bad="" o
	install_from seeded "online" up || {
		fail "$name" "安装器没有走到结束屏"
		return
	}
	pve "qm start $vmid" >/dev/null
	wait_up 300 || bad="${bad}首次开机 300 秒内没有 GDM；"
	shot online-first-boot-gdm
	gx 'journalctl -b --no-pager -o short-monotonic -u mastersos-agent-local -u NetworkManager-wait-online | grep -vE "^\s*$" | cut -c1-200' | sed 's/^/  agent-local：/'
	o=$(gx 'journalctl -b --no-pager -o short-monotonic -u mastersos-agent-local -u gdm | grep -E "已接受设置包|Started gdm|Starting gdm|Finished mastersos-agent-local"; jq -c "{version}" /var/lib/mastersos/state.json')
	echo "$o" | sed 's/^/  /'
	local acc gdm
	acc=$(grep -m1 '已接受设置包' <<<"$o" | sed -E 's/^\[ *([0-9.]+)\].*/\1/')
	gdm=$(grep -m1 'Starting gdm' <<<"$o" | sed -E 's/^\[ *([0-9.]+)\].*/\1/')
	[ -n "$acc" ] || bad="${bad}mastersos-agent-local 没有接受记录；"
	[ -n "$acc" ] && [ -n "$gdm" ] && awk -v a="$acc" -v g="$gdm" 'BEGIN{exit !(a < g)}' || bad="${bad}接受（${acc:-无}）不在 GDM 启动（${gdm:-无}）之前；"
	grep -qE '"version":[0-9]' <<<"$o" || bad="${bad}state.json 没有 version；"
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

c_unmanaged() {
	local name=unmanaged bad="" o pw
	install_from plain "unmanaged" up || {
		fail "$name" "安装器没有走到结束屏"
		return
	}
	grep -q 'unmanaged personal computer' "$state/confirm-$vmid.txt" || bad="${bad}确认屏没写「unmanaged personal computer」；"
	pve "qm start $vmid" >/dev/null
	wait_vcs 'Username:' 300 || bad="${bad}tty1 上没有 mastersos-firstrun 的提示；"
	shot unmanaged-firstrun
	o=$(gx 'systemctl show -p ConditionResult --value mastersos-agent; test -e /usr/libexec/gnome-initial-setup && echo has-gis || echo no-gis')
	log "mastersos-agent ConditionResult=$(head -1 <<<"$o")；$(tail -1 <<<"$o")"
	[ "$(head -1 <<<"$o")" = no ] || bad="${bad}mastersos-agent 在未受管的机器上启动了；"
	[ "$(tail -1 <<<"$o")" = no-gis ] || bad="${bad}有 gnome-initial-setup；"
	# 试验口令：只在本机 state 里（不入库，见 .gitignore 外的 state/ 由提交前删掉）
	pw=$(LC_ALL=C tr -dc 'a-km-z2-9' </dev/urandom | head -c 10)
	printf '%s' "$pw" >"$state/owner.pw"
	chmod 600 "$state/owner.pw"
	local pwkeys=()
	local i
	for ((i = 0; i < ${#pw}; i++)); do pwkeys+=("${pw:i:1}"); done
	keys o w n e r ret wait:1 "${pwkeys[@]}" ret wait:1 "${pwkeys[@]}" ret wait:3
	wait_up 120 || bad="${bad}建好用户后没有 GDM；"
	sleep 5
	shot unmanaged-gdm
	# 以 owner 登录 GDM：用户列表只有 owner，回车选中再输口令
	keys ret wait:2 "${pwkeys[@]}" ret wait:15
	shot unmanaged-owner-desktop
	o=$(gx 'id owner; loginctl list-sessions --no-legend | grep owner')
	echo "$o" | sed 's/^/  /'
	grep -q '(sudo)' <<<"$o" || bad="${bad}owner 不在 sudo 组；"
	grep -q 'seat0' <<<"$o" || bad="${bad}owner 没有登进图形会话；"
	printf '%s\n' "$pw" | gx_stdin 'runuser -u owner -- sudo -S -v -p ""' && log "owner 的 sudo -S -v 成功" || bad="${bad}owner sudo -v 失败；"
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# ==================================================================================
case "$vmid" in
165) all="install etc_policy seed_and_agent luks_sealed channel_beta update_interrupted rollback bad_bundle_no_rollback bootloader_update factory_reset tpm_matrix tamper chrome" ;;
168) all="offline_first_boot online_first_boot unmanaged local_password_change" ;;
esac
checks=()
for c in "$@"; do
	if [ "$c" = all ]; then
		read -r -a more <<<"$all"
		checks+=("${more[@]}")
	else
		checks+=("$c")
	fi
done
log "accept-4a.sh $vmid ${checks[*]}（结果 $out/$vmid.txt）"
[ -z "${A4_LIB:-}" ] || return 0
for c in "${checks[@]}"; do
	if ! declare -F "c_$c" >/dev/null; then
		fail "$c" "没有这个 check"
		continue
	fi
	log "== $c"
	"c_$c" || fail "$c" "check 自己出错退出（脚本问题）"
done
log "完成：${#checks[@]} 个 check，$fails 个失败"
exit "$fails"
