#!/bin/bash
# 在 VM 里以 root 跑一条 shell 命令（qemu-guest-agent），打印 stdout/stderr，退出码随命令。
#   gx.sh <vmid> <cmd…>        GX_TIMEOUT=秒（默认 120）
# 先等 guest agent 起来（最多 5 分钟）。坑：用它执行 systemctl reboot 会让 agent 卡住，重启用 qm reboot。
# MASTERSOS_PVE (default root@lab-pve) and MASTERSOS_PVE_SSH_OPTS (default -o HostKeyAlias=198.51.100.5) pick the Proxmox host.
# shellcheck disable=SC2029 # 本机展开是有意的：vmid 等参数先校验再拼进远端命令
set -euo pipefail
pve=${MASTERSOS_PVE:-root@lab-pve}
read -ra pve_opts <<<"${MASTERSOS_PVE_SSH_OPTS:--o HostKeyAlias=198.51.100.5}"
[ $# -ge 2 ] || {
	echo "用法：gx.sh <vmid> <cmd…>" >&2
	exit 2
}
vmid=$1
shift
[[ $vmid =~ ^[0-9]+$ ]] || {
	echo "vmid 应为数字：$vmid" >&2
	exit 2
}
for _ in $(seq 1 60); do
	ssh "${pve_opts[@]}" "$pve" "qm agent $vmid ping" >/dev/null 2>&1 && break
	sleep 5
done
# 命令里有非 ASCII 字符（中文、→）时 qm guest exec 会一直 got timeout（Task 1 实测），所以以 base64 传进去
b64=$(printf '%s' "$*" | base64 | tr -d '\n')
ssh "${pve_opts[@]}" "$pve" "qm guest exec $vmid --timeout ${GX_TIMEOUT:-120} -- bash -c 'echo $b64 | base64 -d | bash'" | python3 -c '
import json, sys
raw = sys.stdin.read()
try:
    d = json.loads(raw)
except Exception:
    print(raw)
    sys.exit(1)
fx = lambda t: t.encode("latin-1", "replace").decode("utf-8", "replace")
sys.stdout.write(fx(d.get("out-data", "")))
sys.stderr.write(fx(d.get("err-data", "")))
sys.exit(d.get("exitcode", 0) or 0)'
