#!/bin/bash
# 等 VM 的串口输出出现某个正则：serial.sh <vmid> <正则> [超时秒，默认 300]
# 第一次调用时在 PVE 上起一个记录器，把 /var/run/qemu-server/<vmid>.serial0 一直追加到
# /var/lib/vz/mastersos-lab/serial-<vmid>.log（VM 关机、重启后自动重连）。默认只看调用之后新写的行；
# SERIAL_ALL=1 时从日志开头找。找到就打印匹配的行、退出 0；超时退出 1。
# VM 要有 serial0: socket，命令行要有 console=ttyS0（lab profile 带）。
# MASTERSOS_PVE (default root@lab-pve) and MASTERSOS_PVE_SSH_OPTS (default -o HostKeyAlias=198.51.100.5) pick the Proxmox host.
set -euo pipefail
pve=${MASTERSOS_PVE:-root@lab-pve}
read -ra pve_opts <<<"${MASTERSOS_PVE_SSH_OPTS:--o HostKeyAlias=198.51.100.5}"
[ $# -ge 2 ] || {
	echo "用法：serial.sh <vmid> <正则> [超时秒]" >&2
	exit 2
}
vmid=$1 re=$2 timeout=${3:-300}
[[ $vmid =~ ^[0-9]+$ ]] || exit 2
ssh "${pve_opts[@]}" "$pve" bash -s -- "$vmid" "$(printf '%q' "$re")" "$timeout" "${SERIAL_ALL:-0}" <<'REMOTE'
set -euo pipefail
vmid=$1 re=$2 timeout=$3 all=$4
d=/var/lib/vz/mastersos-lab
log=$d/serial-$vmid.log
mkdir -p "$d"
touch "$log"
if ! pgrep -f "mastersos-serial-logger $vmid" >/dev/null; then
	nohup bash -c "exec -a 'mastersos-serial-logger $vmid' bash -c 'while :; do [ -S /var/run/qemu-server/$vmid.serial0 ] && socat -u UNIX-CONNECT:/var/run/qemu-server/$vmid.serial0 STDOUT >>$log 2>/dev/null; sleep 1; done'" >/dev/null 2>&1 &
	sleep 1
fi
start=1
[ "$all" = 1 ] || start=$(($(wc -l <"$log") + 1))
end=$((SECONDS + timeout))
while [ $SECONDS -lt $end ]; do
	if m=$(tail -n "+$start" "$log" | tr -d '\r' | sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g' | grep -aE -- "$re"); then
		printf '%s\n' "$m"
		exit 0
	fi
	sleep 2
done
echo "serial.sh: $timeout 秒内没有等到 /$re/（日志 ${log}）" >&2
exit 1
REMOTE
