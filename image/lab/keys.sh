#!/bin/bash
# 往 VM 敲键：keys.sh <vmid> <键…>
# 每个参数是一个 qm sendkey 的键（ret、down、shift-semicolon、ctrl-alt-delete…），或者：
#   wait:<秒>   在两键之间停一下
#   wait:blue   等屏幕变成 shim / MokManager 的蓝底（最多 60 秒，每 0.5 秒截一次屏看左边缘中间那个像素）
#   具名序列（Task 4，Task 11、12 复用；docs/secure-boot.md 有每一屏的截图）：
#     mok-enroll-from-disk[:N]  默认路线。VM 刚开机、MOK 还没登记：shim 报 Security Violation → OK →
#                               「Press any key」→ Enroll key from disk → 第一个设备（ESP）→ 第 N+1 个文件
#                               （mastersos-mok.der；N 是要按几次 ↓，默认 4：装好的镜像的 ESP 根目录依次是
#                               EFI/、System.map…、config…、grub/、mastersos-mok.der）→ Continue → Yes → Reboot
#     mok-enroll                Secure Boot 关着时 mokutil --import 过（口令 mastersos），打开 Secure Boot 后的
#                               第一次开机：「Press any key」→ Enroll MOK → Continue → Yes → 口令 mastersos → Reboot。
#                               「Press any key」只等 10 秒，错过了这次请求就作废（shim 照样清掉 MokNew），
#                               所以序列以 wait:blue 开头，要在 qm start 之后立刻调用
#     ventoy-enroll[:D]         Ventoy 1.1.18 stick, VM just started, Ventoy's key not yet enrolled: shim reports
#                               Security Violation on Ventoy's grubx64 → OK → "Press any key" → Enroll key from disk →
#                               device D+1 (D = presses of down, default 0: VTOYEFI is the only FAT volume when the
#                               internal disk is blank) → 4th entry ENROLL_THIS_KEY_IN_MOKMANAGER.cer (the VTOYEFI root
#                               lists grub/, ventoy/, EFI/, ENROLL_THIS_KEY_IN_MOKMANAGER.cer, tool/) → Continue → Yes →
#                               Reboot. No password. Starts with wait:blue, so call it right after qm start
#                               (lab/results/2026-10-28-ventoy/ has a screenshot of every screen)
#     mok-enroll-mastersos-label  After a Ventoy install with Secure Boot on (the installer ran mokutil --timeout -1), stick
#                               removed, first boot from the internal disk: shim's Security Violation → OK → straight into the
#                               MokManager menu (MokTimeout -1: no "Press any key" countdown) → Enroll key from disk → the
#                               first volume, MASTERSOS (the internal ESP; MOS-GOLDEN is listed second when the firmware shows
#                               it) → 2nd entry mastersos-mok.der (the ESP root lists EFI/, mastersos-mok.der, loader/) →
#                               [Enroll MOK] Continue → "Enroll the key(s)?" Yes → Reboot (MokManager does not restart by
#                               itself). No password. Starts with wait:blue (lab/results/2026-10-28-ventoy/shots/t8-r1-mbr-*)
# MASTERSOS_PVE (default root@lab-pve) and MASTERSOS_PVE_SSH_OPTS (default -o HostKeyAlias=198.51.100.5) pick the Proxmox host.
# shellcheck disable=SC2029 # 本机展开是有意的：vmid 等参数先校验再拼进远端命令
set -euo pipefail
pve=${MASTERSOS_PVE:-root@lab-pve}
read -ra pve_opts <<<"${MASTERSOS_PVE_SSH_OPTS:--o HostKeyAlias=198.51.100.5}"
[ $# -ge 2 ] || {
	echo "用法：keys.sh <vmid> <qm sendkey 键 | wait:<秒> | wait:blue | mok-enroll-from-disk[:N] | mok-enroll | ventoy-enroll[:D] | mok-enroll-mastersos-label …>" >&2
	exit 2
}
vmid=$1
shift
# Only the lab VMs 121–129 (as vm-create.sh, fw-vars.sh): 106, 110, 120 and 101–105 are refused
case "$vmid" in 121 | 122 | 123 | 124 | 125 | 126 | 127 | 128 | 129) ;; *)
	echo "keys.sh: only VMIDs 121–129 are allowed, got: $vmid" >&2
	exit 2
	;;
esac

# 等 shim / MokManager 的蓝底：屏幕左边缘中间的像素是蓝的（GOP 黑底与 Proxmox 标志都不是）
wait_blue="for i in \$(seq 1 120); do echo 'screendump /tmp/mastersos-keys-$vmid.ppm' | qm monitor $vmid >/dev/null 2>&1; \
python3 -c 'import sys
d=open(\"/tmp/mastersos-keys-$vmid.ppm\",\"rb\").read().split(b\"\\n\",3)
w,h=map(int,d[1].split()); o=((h//2)*w+20)*3; r,g,b=d[3][o:o+3]
sys.exit(0 if b>120 and r<60 else 1)' && break; \
[ \$i = 120 ] && { echo 'keys.sh: 60 秒内没有等到 shim 的蓝底' >&2; exit 1; }; sleep 0.5; done"

# 展开具名序列
expanded=()
for k in "$@"; do
	case "$k" in
	mok-enroll-from-disk | mok-enroll-from-disk:*)
		n=${k#mok-enroll-from-disk}
		n=${n#:}
		n=${n:-4}
		[[ $n =~ ^[0-9]+$ ]] || {
			echo "keys.sh: mok-enroll-from-disk:<N> 的 N 应为数字：$n" >&2
			exit 2
		}
		# Security Violation 的 OK → 「Press any key」→ 菜单第 2 项 Enroll key from disk → 设备 ESP
		expanded+=(wait:blue ret wait:1.5 spc wait:1.5 down ret wait:1 ret wait:1)
		for ((i = 0; i < n; i++)); do expanded+=(down); done
		# mastersos-mok.der → [Enroll MOK] 的 Continue → 「Enroll the key(s)?」的 Yes → Reboot
		expanded+=(ret wait:1 down ret wait:1 down ret wait:1.5 ret)
		;;
	ventoy-enroll | ventoy-enroll:*)
		d=${k#ventoy-enroll}
		d=${d#:}
		d=${d:-0}
		[[ $d =~ ^[0-9]+$ ]] || {
			echo "keys.sh: ventoy-enroll:<D> needs a number: $d" >&2
			exit 2
		}
		# Security Violation OK → "Press any key" → 2nd item Enroll key from disk → device list
		expanded+=(wait:blue ret wait:1.5 spc wait:1.5 down ret wait:1)
		for ((i = 0; i < d; i++)); do expanded+=(down); done
		# VTOYEFI → 4th file ENROLL_THIS_KEY_IN_MOKMANAGER.cer → [Enroll MOK] Continue → "Enroll the key(s)?" Yes → Reboot
		expanded+=(ret wait:1 down down down ret wait:1 down ret wait:1 down ret wait:1.5 ret)
		;;
	mok-enroll-mastersos-label)
		# Security Violation OK → menu (no countdown) → Enroll key from disk → MASTERSOS → mastersos-mok.der →
		# Continue → Yes → Reboot
		expanded+=(wait:blue ret wait:1.5 down ret wait:1 ret wait:1 down ret wait:1 down ret wait:1 down ret wait:1.5 ret)
		;;
	mok-enroll)
		# 「Press any key」→ 菜单第 2 项 Enroll MOK → Continue → Yes → 口令 mastersos → Reboot
		# Call it right after qm start: shim counts down only 10 s here; missing it boots on (Security Violation); in Task 8 the request was gone after that.
		expanded+=(wait:blue spc wait:1.5 down ret wait:1 down ret wait:1 down ret wait:1 m a s t e r s o s ret wait:1.5 ret)
		;;
	*) expanded+=("$k") ;;
	esac
done

cmds=()
for k in "${expanded[@]}"; do
	if [ "$k" = wait:blue ]; then
		cmds+=("$wait_blue")
	elif [[ $k =~ ^wait:[0-9.]+$ ]]; then
		cmds+=("sleep ${k#wait:}")
	elif [[ $k =~ ^[a-z0-9_-]+$ ]]; then
		cmds+=("qm sendkey $vmid $k && sleep 0.3")
	else
		echo "keys.sh: 键名不合法：$k" >&2
		exit 2
	fi
done
script=$(printf '%s; ' "${cmds[@]}")
ssh "${pve_opts[@]}" "$pve" "set -e; $script"
