#!/bin/bash
# 改一台关着的试验 VM 的固件变量（efidisk 开头的 OVMF_VARS），等于在固件设置里操作：
#   fw-vars.sh <vmid> secureboot on|off     打开 / 关掉 Secure Boot（SecureBootEnable）
#   fw-vars.sh <vmid> print                 列出 PK/KEK/db 的证书与 Secure Boot、MOK 相关的变量
# Only VMIDs 121–129 (as vm-create.sh); the VM must be stopped (a running firmware writes its in-memory copy back).
# MASTERSOS_PVE (default root@lab-pve) and MASTERSOS_PVE_SSH_OPTS (default -o HostKeyAlias=198.51.100.5) pick the Proxmox host.
# shellcheck disable=SC2029 # 本机展开是有意的：参数先校验再拼进远端命令
set -euo pipefail
pve=${MASTERSOS_PVE:-root@lab-pve}
read -ra pve_opts <<<"${MASTERSOS_PVE_SSH_OPTS:--o HostKeyAlias=198.51.100.5}"
usage() {
	echo "用法：fw-vars.sh <vmid> secureboot on|off | print" >&2
	exit 2
}
[ $# -ge 2 ] || usage
vmid=$1 op=$2
case "$vmid" in 121 | 122 | 123 | 124 | 125 | 126 | 127 | 128 | 129) ;; *)
	echo "fw-vars.sh: only VMIDs 121–129 are allowed, got: $vmid" >&2
	exit 2
	;;
esac
case "$op" in
secureboot)
	case "${3:-}" in on) arg=--set-true ;; off) arg=--set-false ;; *) usage ;; esac
	;;
print) arg=--print ;;
*) usage ;;
esac
ssh "${pve_opts[@]}" "$pve" bash -s -- "$vmid" "$arg" <<'REMOTE'
set -euo pipefail
vmid=$1 arg=$2
if [ "$(qm status "$vmid" | awk '{print $2}')" != stopped ]; then
	echo "fw-vars.sh: VM $vmid 没关机" >&2
	exit 1
fi
vol=$(qm config "$vmid" | sed -n 's/^efidisk0: \([^,]*\),.*/\1/p')
dev=$(pvesm path "$vol")
[ -b "$dev" ] || lvchange -ay "$dev"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# OVMF_VARS 的大小（4m 的 efidisk：540672 字节）
dd if="$dev" of="$tmp/vars.fd" bs=540672 count=1 status=none
if [ "$arg" = --print ]; then
	virt-fw-vars -i "$tmp/vars.fd" --print --verbose 2>/dev/null | grep -E 'subject CN=|SecureBootEnable|Mok|SbatLevel' | sort -u
	exit 0
fi
virt-fw-vars --inplace "$tmp/vars.fd" "$arg" SecureBootEnable >/dev/null
dd if="$tmp/vars.fd" of="$dev" bs=540672 count=1 conv=notrunc status=none
echo "fw-vars.sh: VM $vmid 的 SecureBootEnable ${arg#--set-}"
REMOTE
