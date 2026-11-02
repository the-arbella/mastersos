#!/bin/bash
# 截 VM 的屏：shot.sh <vmid> <name> → lab/results/shots/<name>.png（qm monitor 的 screendump）
# SHOT_DIR=<目录> 时放到那里（accept-4a.sh 放进 results/<日期>-4a/）
# MASTERSOS_PVE: the Proxmox host to ssh to (default root@lab-pve; home VMs were deleted 2026-10-30),
# MASTERSOS_PVE_SSH_OPTS: extra ssh options (default pins lab-pve's host key alias)
# shellcheck disable=SC2029 # 本机展开是有意的：vmid 等参数先校验再拼进远端命令
set -euo pipefail
[ $# -eq 2 ] || {
	echo "用法：shot.sh <vmid> <name>" >&2
	exit 2
}
vmid=$1 name=$2
[[ $vmid =~ ^[0-9]+$ ]] || {
	echo "vmid 应为数字：$vmid" >&2
	exit 2
}
dir=${SHOT_DIR:-$(cd "$(dirname "$0")" && pwd)/results/shots}
mkdir -p "$dir"
pve=${MASTERSOS_PVE:-root@lab-pve}
read -ra opts <<<"${MASTERSOS_PVE_SSH_OPTS:--o HostKeyAlias=198.51.100.5}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# A blanked screen (idle greeter) dumps as "Display output is not active": tap shift first.
ssh "${opts[@]}" "$pve" "qm sendkey $vmid shift >/dev/null 2>&1; sleep 2; echo 'screendump /tmp/mastersos-shot-$vmid.ppm' | qm monitor $vmid >/dev/null 2>&1"
scp -q "${opts[@]}" "$pve:/tmp/mastersos-shot-$vmid.ppm" "$tmp/shot.ppm"
if command -v magick >/dev/null; then
	magick "$tmp/shot.ppm" "$dir/$name.png"
else
	sips -s format png "$tmp/shot.ppm" --out "$dir/$name.png" >/dev/null
fi
echo "$dir/$name.png"
