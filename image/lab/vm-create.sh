#!/bin/bash
# Create a trial VM on lab-pve (see MASTERSOS_PVE below):
#   vm-create.sh <vmid> <name> [--no-tpm] [--setup-mode | --own-db <crt>] [--disk <raw>] [--usb <raw>]
# q35 + OVMF + vTPM 2.0，4 核 4 GB，40 GB 磁盘（VM_DISK_GB），virtio 网卡接 vmbr0（VLAN tag 40，试验网），串口 socket（serial.sh 用）。
#   默认      efidisk 预置微软的钥匙（pre-enrolled-keys=1）：走 shim + MOK 路线
#   --setup-mode  efidisk 不带钥匙（setup mode）：lab 镜像的 systemd-boot 自动导入我们的钥匙（只有我们的 PK/KEK/db）。
#                 注意：镜像带 shim（ShimBootloader=signed）时，导入之后微软签名的 shim 就过不了固件
#                 （Access Denied，Task 1 实测）——这条只适合不带 shim 的镜像。
#   --own-db <crt>  预置微软的钥匙，再把我们的证书（PVE 上的 PEM 路径）**追加**进 db：Dell BIOS 里
#                 「追加 db」那条备选路线。shim 在 db 里认得我们签的 systemd-boot，不用 MokManager。
#   --no-tpm  不加 vTPM
#   --disk    PVE 上的 raw 镜像，导入成 scsi0 后扩到 40 GB（首次开机 repart 要地方建 B 槽与根分区）
#   --usb     PVE 上的 raw，以 USB 大容量存储（可拔）挂上，当安装 U 盘
# Only VMIDs 121–129 (lab-pve lab range) are allowed; everything else is refused, including 106 (EIS acceptance device),
# 110 (dev box), 120 (builder) and the school servers 101–105. Refuses an existing VM.
# MASTERSOS_PVE (default root@lab-pve) and MASTERSOS_PVE_SSH_OPTS (default -o HostKeyAlias=198.51.100.5) pick the Proxmox host.
# shellcheck disable=SC2029,SC2054 # 本机展开是有意的（参数先校验再拼进远端命令）；qm 的选项值本来就带逗号
set -euo pipefail
pve=${MASTERSOS_PVE:-root@lab-pve}
read -ra pve_opts <<<"${MASTERSOS_PVE_SSH_OPTS:--o HostKeyAlias=198.51.100.5}"

usage() {
	echo "用法：vm-create.sh <vmid> <name> [--no-tpm] [--setup-mode | --own-db <crt>] [--disk <raw>] [--usb <raw>]" >&2
	exit 2
}
[ $# -ge 2 ] || usage
vmid=$1 name=$2
shift 2
tpm=1 keys=1 disk="" usb="" own_db=""
while [ $# -gt 0 ]; do
	case "$1" in
	--no-tpm) tpm=0 && shift ;;
	--setup-mode) keys=0 && shift ;;
	--own-db)
		own_db=${2:-}
		shift 2 || usage
		;;
	--disk)
		disk=${2:-}
		shift 2 || usage
		;;
	--usb)
		usb=${2:-}
		shift 2 || usage
		;;
	*) usage ;;
	esac
done
case "$vmid" in 121 | 122 | 123 | 124 | 125 | 126 | 127 | 128 | 129) ;; *)
	echo "vm-create.sh: only VMIDs 121–129 are allowed (106 acceptance device, 110 dev box, 120 builder and 101–105 servers are refused), got: $vmid" >&2
	exit 2
	;;
esac
[[ $name =~ ^[a-z0-9-]+$ ]] || {
	echo "vm-create.sh: 名字只能是小写字母、数字和 -：$name" >&2
	exit 2
}
if [ "$keys" = 0 ] && [ -n "$own_db" ]; then
	echo "vm-create.sh: --setup-mode 与 --own-db 只能选一个" >&2
	exit 2
fi
for f in "$disk" "$usb" "$own_db"; do
	[ -z "$f" ] || [[ $f =~ ^/[A-Za-z0-9._/-]+$ ]] || {
		echo "vm-create.sh: 路径不合法：$f" >&2
		exit 2
	}
	[ -z "$f" ] || ssh "${pve_opts[@]}" "$pve" "test -f '$f'" || {
		echo "vm-create.sh: PVE 上没有 $f" >&2
		exit 2
	}
done
if ssh "${pve_opts[@]}" "$pve" "qm status $vmid" >/dev/null 2>&1; then
	echo "vm-create.sh: VM $vmid 已存在（先 qm destroy $vmid --purge）" >&2
	exit 1
fi

size=${VM_DISK_GB:-40}
st=${VM_STORAGE:-local-lvm}
opts=(
	--name "$name" --machine q35 --bios ovmf --cpu host --cores 4 --memory 4096 --ostype l26
	--scsihw virtio-scsi-single --net0 virtio,bridge=vmbr0,tag=40 --serial0 socket --vga virtio,memory=64
	--agent enabled=1 --boot order=scsi0
	--efidisk0 "$st:1,efitype=4m,pre-enrolled-keys=$keys"
)
[ "$tpm" = 1 ] && opts+=(--tpmstate0 "$st:1,version=v2.0")
if [ -n "$disk" ]; then
	opts+=(--scsi0 "$st:0,import-from=$disk,discard=on,ssd=1")
else
	opts+=(--scsi0 "$st:$size,discard=on,ssd=1")
fi
ssh "${pve_opts[@]}" "$pve" "qm create $vmid $(printf '%q ' "${opts[@]}")"
if [ -n "$disk" ]; then
	ssh "${pve_opts[@]}" "$pve" "qm disk resize $vmid scsi0 ${size}G"
fi
if [ -n "$own_db" ]; then
	# efidisk 开头就是 OVMF_VARS（540672 字节）：取出来、用 virt-fw-vars 往 db 追加证书、写回
	ssh "${pve_opts[@]}" "$pve" bash -s -- "$vmid" "$own_db" <<'REMOTE'
set -euo pipefail
vmid=$1 crt=$2
vol=$(qm config "$vmid" | sed -n 's/^efidisk0: \([^,]*\),.*/\1/p')
dev=$(pvesm path "$vol")
[ -b "$dev" ] || lvchange -ay "$dev"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
dd if="$dev" of="$tmp/vars.fd" bs=540672 count=1 status=none
# owner GUID 固定为 MastersOS 的（6b68756e = "khun"）
virt-fw-vars --inplace "$tmp/vars.fd" --add-db 6b68756e-6f73-4b68-756e-4f5300000001 "$crt" >/dev/null
dd if="$tmp/vars.fd" of="$dev" bs=540672 count=1 conv=notrunc status=none
echo "vm-create.sh: efidisk 里的证书（PK/KEK/db）："
virt-fw-vars -i "$tmp/vars.fd" --print --verbose 2>/dev/null | grep -E 'subject CN=' | sort -u
REMOTE
fi
if [ -n "$usb" ]; then
	args="-device qemu-xhci -drive if=none,id=stick,format=raw,file=$usb -device usb-storage,drive=stick,removable=on"
	ssh "${pve_opts[@]}" "$pve" "qm set $vmid --args $(printf '%q' "$args")"
fi
ssh "${pve_opts[@]}" "$pve" "qm config $vmid"
