#!/bin/bash
# accept-4a.sh 与 accept-4b.sh 共用的函数（由它们 source，不单独跑）。调用方先设好：
#   here vmid out state snapshot bhost server upd root161 lab cfg V_BASE，以及 rollback 用的 V_BROKEN_USER V_BROKEN_INITRD；
#   ACC_SHOT（截图名前缀，4a-t12 / 4b-t20）。
# 每个 check 打印「PASS <名字>」或「FAIL <名字>：<原因>」，fails 是失败个数。
# 令牌只从 Mac 的 ~/.config/testlab/mastersos/mastersos-lab-{ops,recovery}.token 读、经 stdin 交给构建机上的 curl；恢复密钥同样只经 stdin。
# shellcheck shell=bash disable=SC2029,SC2016,SC2015,SC2154,SC2001 # 本机展开是有意的；远端命令有意用单引号；pass 不会失败；变量由调用方设；sed 加前缀比参数展开好读
set -euo pipefail
fails=0
now() { date '+%H:%M:%S'; }
log() { echo "[$(now)] $*"; }
pass() { echo "PASS $1"; }
fail() {
	echo "FAIL $1：$2"
	fails=$((fails + 1))
}

# --- 底层 -----------------------------------------------------------------
pve() { ssh -o ServerAliveInterval=30 -o ServerAliveCountMax=6 lab-host "$@"; }
b161() { ssh -o ServerAliveInterval=30 -o ServerAliveCountMax=6 -J lab-host "$bhost" "$@"; }
gx() { "$here/gx.sh" "$vmid" "$@"; }
# 一整块远端检查：末尾打印结束标记，输出里去掉它；标记没出来（guest agent 失败或超时、块半路退出）就返回 1。
# 「没有输出 = 全部成立」的检查块一律经它跑，传输失败不能被当成通过（Task 12 复审 I-2）
A4_END=__A4_END__
gxm() {
	local out
	out=$(gx "$1"$'\n'"echo $A4_END") || true
	[ "$(tail -n 1 <<<"$out")" = "$A4_END" ] || {
		echo "gxm：远端检查块没有跑完（没有结束标记）；输出：${out:0:200}" >&2
		return 1
	}
	sed '$d' <<<"$out"
}
# 正整数（毫秒、微秒、秒都用它核对）
is_uint() { [[ ${1:-} =~ ^[0-9]+$ ]]; }
# 带秘密的命令：秘密只经 stdin（qm guest exec --pass-stdin），不进 guest-exec 的命令行与 qemu-ga 的日志
gx_stdin() {
	local b64
	b64=$(printf '%s' "$*" | base64 | tr -d '\n')
	pve "qm guest exec $vmid --pass-stdin 1 --timeout 120 -- bash -c 'echo $b64 | base64 -d > /run/mastersos-a4.sh; bash /run/mastersos-a4.sh; rc=\$?; rm -f /run/mastersos-a4.sh; exit \$rc'" |
		python3 -c 'import json,sys; d=json.load(sys.stdin); fx=lambda t: t.encode("latin-1","replace").decode("utf-8","replace"); sys.stdout.write(fx(d.get("out-data",""))); sys.stderr.write(fx(d.get("err-data",""))); sys.exit(d.get("exitcode",0) or 0)'
}
# 截图名：<ACC_SHOT>-<vmid>-<名字>.png（4a 是 4a-t12，4b 是 4b-t20）
shot() { "$here/shot.sh" "$vmid" "${ACC_SHOT:-4a-t12}-$vmid-$1" >/dev/null && log "截图 $(basename "$out")/${ACC_SHOT:-4a-t12}-$vmid-$1.png"; }
keys() { "$here/keys.sh" "$vmid" "$@"; }
qga_up() { pve "qm agent $vmid ping" >/dev/null 2>&1; }
vm_status() { pve "qm status $vmid" | awk '{print $2}'; }
boot_id() { gx 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null | tr -d '\n'; }
img_version() { gx '. /usr/lib/os-release; echo $IMAGE_VERSION' 2>/dev/null | tr -d '\n'; }
esp() { gx 'bootctl -p' | tr -d '\n'; }

# 等 guest agent 应答且 display-manager active（最多 $1 秒）
wait_up() {
	local t=${1:-300} end=$((SECONDS + ${1:-300}))
	while [ "$SECONDS" -lt "$end" ]; do
		if qga_up && [ "$(GX_TIMEOUT=10 gx 'systemctl is-active display-manager' 2>/dev/null | tr -d '\n')" = active ]; then
			return 0
		fi
		sleep 3
	done
	log "wait_up：$t 秒内没有等到 display-manager active"
	return 1
}
# 重启并等到「换了一个开机 id、GDM 起来」
reboot_wait() {
	local old
	old=$(boot_id)
	pve "qm reboot $vmid --timeout 180" >/dev/null
	local end=$((SECONDS + ${1:-400}))
	while [ "$SECONDS" -lt "$end" ]; do
		if qga_up; then
			local b
			b=$(boot_id)
			if [ -n "$b" ] && [ "$b" != "$old" ] && wait_up 120; then return 0; fi
		fi
		sleep 5
	done
	return 1
}
# 参数可选（等待秒数，缺省 400）；调用处大多不带参数（shellcheck 0.9 的 SC2120/SC2119 误报）
# shellcheck disable=SC2120
start_wait() {
	[ "$(vm_status)" = running ] || pve "qm start $vmid" >/dev/null
	wait_up "${1:-400}"
}
stop_vm() {
	if [ "$(vm_status)" = running ]; then
		pve "qm shutdown $vmid --timeout 120 --forceStop 1" >/dev/null 2>&1 || pve "qm stop $vmid" >/dev/null
	fi
}
# 网卡 link_down=1|0（保持 MAC 与网桥不变）
link() {
	local cur
	cur=$(pve "qm config $vmid" | sed -n 's/^net0: //p' | sed 's/,link_down=[01]//')
	pve "qm set $vmid --net0 '$cur,link_down=$1'" >/dev/null
	log "net0 link_down=$1"
}
snap() { pve "qm snapshot $vmid $1 --description '$2'" >/dev/null && log "快照 $1"; }
rollback() {
	pve "qm rollback $vmid $1" >/dev/null && log "回滚到 $1"
}
delsnap() { pve "qm delsnapshot $vmid $1" >/dev/null 2>&1 && log "删快照 $1" || true; }
# 屏幕（tty1）上的文字：/dev/vcs1，等某个正则出现
wait_vcs() {
	local re=$1 end=$((SECONDS + ${2:-300}))
	while [ "$SECONDS" -lt "$end" ]; do
		if qga_up && GX_TIMEOUT=10 gx "fold -w 160 /dev/vcs1 | grep -aqE '$re'" 2>/dev/null; then return 0; fi
		sleep 3
	done
	return 1
}
# 等串口上出现某个提示、再回答（systemd-ask-password 在 console=ttyS0 上读）：答案只经 stdin。
#   printf '%s' "$answer" | serial_answer <正则> [超时秒]
# 在 PVE 上用一个连接完成「等提示 → 逐字敲 → 再读 15 秒」：QEMU 的串口 socket 只接一个客户端，所以先停掉 serial.sh 的
# 记录器（bash 循环与它的 socat 子进程；模式写成 [k]、[s]，不然 pkill -f 会连这条 ssh 命令自己的 bash 一起杀掉）；
# 一次写完 71 个字符就断开会丢字（客体的 UART FIFO 满时 QEMU 不读 socket，Task 12 实测），所以逐字敲、连接留着。
# 打印提示之后串口上的几行（不含答案：恢复密钥关了回显，只显示圆点）。
serial_answer() {
	pve "pkill -f '[k]hunos-serial-logger $vmid'; pkill -f '[s]ocat -u UNIX-CONNECT:/var/run/qemu-server/$vmid.serial0'; sleep 0.5
python3 -c '
import re, select, socket, sys, time
ans = sys.stdin.readline().rstrip(\"\\n\")
pat, limit = re.compile(sys.argv[1].encode()), time.time() + float(sys.argv[2])
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[3])
buf = b\"\"
while not pat.search(buf):
    if time.time() > limit:
        sys.exit(\"serial_answer: 没有等到提示\")
    if select.select([s], [], [], 1)[0]:
        buf = (buf + s.recv(4096))[-8192:]
time.sleep(1)
for c in ans + chr(13):
    s.send(c.encode()); time.sleep(0.05)
out, end = b\"\", time.time() + 15
while time.time() < end:
    if select.select([s], [], [], 1)[0]:
        out += s.recv(4096)
txt = re.sub(rb\"\\x1b\\[[0-9;?]*[a-zA-Z]\", b\"\", out).decode(errors=\"replace\").replace(chr(13), \"\")
print(\"\\n\".join([l for l in txt.splitlines() if l.strip()][:6]))
' '$1' '${2:-300}' /var/run/qemu-server/$vmid.serial0"
	local rc=$?
	serial_logger
	return "$rc"
}
serial_wait() { "$here/serial.sh" "$vmid" "$1" "${2:-300}"; }
# serial.sh 第一次调用时起记录器；serial_answer 停掉它之后要重新起
serial_logger() { "$here/serial.sh" "$vmid" '^mastersos-a4-never$' 1 >/dev/null 2>&1 || true; }
serial_mark() {
	serial_logger
	pve "wc -l < $lab/serial-$vmid.log 2>/dev/null || echo 0" | tr -d '\n'
}
serial_since() { pve "tail -n +$(($1 + 1)) $lab/serial-$vmid.log | tr -d '\r' | sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g'"; }

# --- lab 服务端的管理 API（令牌经 stdin 给 VM 161 上的 curl）--------------------------------
api() { # api <ops|recovery> <METHOD> <path> [本机的请求体文件]
	local tok body_remote="" ct=""
	case "$3" in */draft/files/*) ct=application/octet-stream ;; */draft/manifest) ct=text/plain ;; */commit-server | */commit | */group | */lock | */reset) ct=application/json ;; esac
	tok=$(tr -d '\n' <"$cfg/mastersos-lab-$1.token")
	if [ -n "${4:-}" ]; then
		body_remote=t12-server/tmp/body.$$
		b161 "mkdir -p -m 700 t12-server/tmp && cat > $body_remote" <"$4"
	fi
	printf 'Authorization: Bearer %s\n' "$tok" |
		b161 "curl -sS --fail-with-body -X $2 -H @- ${ct:+-H 'content-type: $ct'} ${body_remote:+--data-binary @$body_remote} '$server$3'; rc=\$?; ${body_remote:+rm -f $body_remote;} exit \$rc"
}
# 发布一份清单（server 钥匙两步发布）；之后的文件参数 <包内路径>=<本机文件> 先写进草稿
publish_manifest() {
	local m=$1 p pend dig
	shift
	for f in "$@"; do api ops PUT "/v1/admin/draft/files/${f%%=*}" "${f#*=}" >/dev/null; done
	api ops PUT /v1/admin/draft/manifest "$m" >/dev/null
	p=$(api ops POST /v1/admin/publish/prepare) || {
		log "发布前检查没过（$(basename "$m")）：$(jq -c '[.error.details.lints[]? | select(.level == "error") | .code]' <<<"$p" 2>/dev/null || echo "$p")"
		return 1
	}
	pend=$(jq -r .pending_id <<<"$p")
	dig=$(jq -c .digest_hex <<<"$p")
	printf '{"confirm_digest": %s}' "$dig" >"$state/commit.json"
	api ops POST "/v1/admin/publish/pending/$pend/commit-server" "$state/commit.json" >/dev/null
	log "发布设置包 v$(jq -r .version <<<"$p")（$(basename "$m")；lint $(jq -c '[.lints[]?.code]' <<<"$p")）"
}
manifest() { # manifest <channel> [with-script] → 本机的文件路径
	local f=$state/manifest-$1${2:+-script}.toml
	{
		printf '[school]\ntimezone = "Asia/Bangkok"\nupdate_channel = "%s"\n\n' "$1"
		printf '[[config]]\nid = "default"\nname = "未分组"\nlogin_methods = ["local"]\n'
		[ -z "${2:-}" ] || printf '\n[[config.scripts]]\npath = "scripts/ran.sh"\nwhen = "apply"\n'
		printf '\n[[group]]\nid = "default"\nname = "未分组"\nconfig = "default"\n'
	} >"$f"
	echo "$f"
}
device_json() { api ops GET /v1/admin/devices | jq -c --arg id "$1" '.[] | select(.device_id == $id)'; }
device_id() { gx 'jq -r .device_id /var/lib/mastersos-seed/identity.json' | tr -d '\n'; }
recovery_rows() { api recovery GET "/v1/admin/devices/$1/recovery-keys" | jq 'length'; }

# --- 构建、发布、U 盘 ----------------------------------------------------------
pool() { pve 'lvs --noheadings -o data_percent pve/data' | tr -d ' \n'; }
check_pool() {
	local p
	p=$(pool)
	log "PVE thin pool ${p}%"
	if awk -v p="$p" 'BEGIN{exit !(p >= 94.5)}'; then
		b161 'sudo fstrim / >/dev/null' || true
		p=$(pool)
		log "fstrim 之后 ${p}%"
		awk -v p="$p" 'BEGIN{exit !(p >= 95)}' && {
			echo "accept-4a.sh: thin pool ${p}% ≥ 95%，停下" >&2
			exit 99
		}
	fi
	return 0
}
built() { b161 "test -f mastersos-image/mkosi.output/$1/build-info.txt"; }
build() { # build <v> [userspace|initrd]
	# 之前手工起的同一版本的构建还在跑（build-info 写在 make-installer 之前）：等它跑完
	while b161 "pgrep -f '[b]uild.sh $1 ' >/dev/null"; do sleep 15; done
	built "$1" && return 0
	check_pool
	log "VM 161：build.sh $1 --profile lab${2:+ --broken $2}（MASTERSOS_SNAPSHOT=${snapshot}）"
	b161 "cd mastersos-image && MASTERSOS_SNAPSHOT=$snapshot ./build.sh $1 --profile lab ${2:+--broken $2} > mkosi.output/build-$1.log 2>&1" || built "$1" || {
		# （ssh 断了而构建其实跑完的话 build-info 在：build.sh 只在成功时写它）
		b161 "tail -20 mastersos-image/mkosi.output/build-$1.log"
		return 1
	}
	b161 "grep -E '^(version|profile|broken|git_commit|Snapshot|shim_sha256)=' mastersos-image/mkosi.output/$1/build-info.txt" | tr '\n' ' '
	echo
	# 只发通道的版本用不着整盘镜像与 U 盘镜像（publish 只要 /usr 三个分区、UKI 与 build-info）：先删掉，薄池余量小
	[ "$1" = "$V_BASE" ] || b161 "cd mastersos-image/mkosi.output/$1 && rm -f MastersOS_$1_x86-64.raw MastersOS_$1_x86-64.esp.raw MastersOS-installer_$1_x86-64.* && sudo fstrim / >/dev/null"
}
in_channel() { b161 "test -f $root161/$2/MastersOS_$1_x86-64.efi"; }
publish() { # publish <v> beta；发完删掉构建产物（装机版本除外）
	in_channel "$1" "$2" && return 0
	# PUBLISH_FLAGS: extra publish.sh flags from the caller (4b sets --allow-bootloader-change: systemd-boot differs on
	# every build, Task 22 carry)
	b161 "cd mastersos-image && ./publish.sh $1 $2 ${PUBLISH_FLAGS:-} 2>&1 | grep -E 'publish.sh: (stable|beta) 现有版本|→|闸门|拒绝|systemd-boot' | head -5"
	in_channel "$1" "$2" || return 1
	[ "$1" = "$V_BASE" ] || b161 "rm -rf mastersos-image/mkosi.output/$1 && sudo fstrim / >/dev/null"
}
# 服务端还没有发布过设置包时先发一份（stable 通道）：带种子的机器第一次开机要有包可拉
ensure_bundle() {
	[ "$(api ops GET /v1/admin/summary | jq -r .latest_version)" != 0 ] || publish_manifest "$(manifest stable)"
}
# 做 U 盘：<lab>/a4-<v>-<seeded|plain>.img（带种子的从服务端 GET /v1/admin/seed 拿学校层面的种子，不带分组——新机器进
# default，要别的分组在设备页改；sha256 记进 state/seed.sha256，种子文件即删）
make_stick() { # make_stick <seeded|plain>
	local kind=$1 img
	img=$lab/a4-$V_BASE-$1.img
	if pve "test -f $img"; then
		echo "$img"
		return 0
	fi
	built "$V_BASE" || build "$V_BASE" >&2
	pve "mkdir -p $lab && cd $lab && scp -q $bhost:mastersos-image/mkosi.output/$V_BASE/MastersOS-installer_${V_BASE}_x86-64.img.zst a4-tmp.img.zst && zstd -qdf --rm a4-tmp.img.zst -o $img.part && mv $img.part $img"
	if [ "$kind" = seeded ]; then
		ensure_bundle >&2
		api ops GET /v1/admin/seed >"$state/seed.toml.tmp"
		shasum -a 256 "$state/seed.toml.tmp" | awk '{print $1}' >"$state/seed.sha256"
		pve "off=\$(sfdisk -d $img | sed -n '/mastersos-usb-seed/s/.*start= *\([0-9]*\),.*/\1/p'); umask 077; cat > /run/a4-seed.toml && mcopy -o -i $img@@\$((off*512)) /run/a4-seed.toml ::seed.toml; rc=\$?; rm -f /run/a4-seed.toml; exit \$rc" <"$state/seed.toml.tmp"
		rm -f "$state/seed.toml.tmp"
		log "U 盘 $img 放了种子（sha256 $(cat "$state/seed.sha256")；fetch_token 不入记录）" >&2
	fi
	echo "$img"
}
# 从 U 盘重装这台：插 U 盘（bootindex=1，盘上已有系统）→［安装前检查的警告 → y］→ 安装器确认屏 → y → 结束屏 → 拔盘。
# 4b Task 22 起 VM 没有无线网卡，每次都先有一屏「No Wi-Fi card」的警告（There are warnings above, type y to continue）；
# 警告的文字记进 state/warnings-<vmid>.txt。
install_from() { # install_from <seeded|plain> <截图前缀> [first-boot-link: up|down]
	local img
	img=$(make_stick "$1")
	stop_vm
	pve "qm set $vmid --args '-device qemu-xhci -drive if=none,id=stick,format=raw,file=$img -device usb-storage,drive=stick,removable=on,bootindex=1'" >/dev/null
	link 0
	pve "qm start $vmid" >/dev/null
	log "从 U 盘（$(basename "$img")）启动"
	wait_vcs '[Tt]ype y to continue' 240 || {
		shot "$2-noprompt"
		return 1
	}
	: >"$state/warnings-$vmid.txt"
	if gx 'fold -w 160 /dev/vcs1 | grep -aq "There are warnings above"' 2>/dev/null; then
		gx 'fold -w 160 /dev/vcs1 | grep -aE "Warning|warning|Wi-Fi|certificate|Reason"' | tee "$state/warnings-$vmid.txt" | sed 's/^/  警告：/'
		shot "$2-warnings"
		keys y ret
		sleep 3
	fi
	wait_vcs 'Type y to continue' 240 || {
		shot "$2-noconfirm"
		return 1
	}
	shot "$2-confirm"
	gx 'fold -w 160 /dev/vcs1 | grep -aE "ERASES|seed|Seed|Managed|managed|Server|Group|/dev/"' | tee "$state/confirm-$vmid.txt" | sed 's/^/  屏幕：/'
	keys y ret
	wait_vcs 'Installation complete' 600 || {
		shot "$2-nofinish"
		return 1
	}
	shot "$2-finish"
	pve "qm stop $vmid" >/dev/null
	pve "qm set $vmid --delete args" >/dev/null
	log "拔掉 U 盘"
	[ "${3:-up}" = down ] && link 1
	return 0
}

# 发更新：mastersos-update → 等它结束 → 打印 ESP 上的 UKI
run_update() {
	gx 'systemctl start mastersos-update.service; systemctl show -p Result --value mastersos-update.service; ls "$(bootctl -p)/EFI/Linux"'
}
# 等机器跑在某个版本上（中间几次坏的开机 guest agent 可能起不来或很快重启）
wait_version() {
	local v=$1 end=$((SECONDS + ${2:-900}))
	while [ "$SECONDS" -lt "$end" ]; do
		if qga_up && [ "$(GX_TIMEOUT=10 img_version)" = "$v" ] && wait_up 60; then return 0; fi
		sleep 5
	done
	return 1
}
c_rollback() {
	local name=rollback bad="" o m b
	start_wait || {
		fail "$name" "起不来"
		return
	}
	local cur
	cur=$(img_version)
	# Step 3：用户态坏版本
	build "$V_BROKEN_USER" userspace || {
		fail "$name" "构建 $V_BROKEN_USER 失败"
		return
	}
	publish "$V_BROKEN_USER" beta || bad="${bad}publish $V_BROKEN_USER 失败；"
	run_update | sed 's/^/  /'
	m=$(serial_mark)
	b=$(gx 'journalctl --list-boots --no-pager | wc -l' | tr -d '\n')
	pve "qm reboot $vmid --timeout 180" >/dev/null
	wait_version "$cur" 900 || bad="${bad}用户态坏版本没退回 ${cur}；"
	o=$(gx "journalctl --list-boots --no-pager | tail -n +$((b + 1)) | wc -l; journalctl --no-pager -o cat -u mastersos-health -b -1 | grep -m1 'health failed'; ls \"\$(bootctl -p)/EFI/Linux\" | tr '\n' ' '")
	log "Step 3：$(img_version)；${o//$'\n'/ | }"
	gx 'ls "$(bootctl -p)/EFI/Linux"' | grep -qx "MastersOS_${V_BROKEN_USER}_x86-64+0-3.efi" || bad="${bad}ESP 上没有 MastersOS_${V_BROKEN_USER}_x86-64+0-3.efi；"
	# 坏的三次开机里 mastersos-bootloader-update 一次都没跑（Task 4 Step 3 的后半，结果交给 bootloader_update）：
	# 坏的开机几秒内就重启，guest agent 赶不上，改看那三次开机的 journal
	o=$(gx 'for i in -3 -2 -1; do echo "boot $i: health_failed=$(journalctl -q -b $i -u mastersos-health -o cat --no-pager | grep -c "health failed") marked_good=$(journalctl -q -b $i -u systemd-bless-boot -o cat --no-pager | grep -c "Marked boot") bootloader_update_lines=$(journalctl -q -b $i -u mastersos-bootloader-update -o cat --no-pager | grep -c .)"; done')
	echo "$o" | tee "$state/bootloader-unblessed.txt" | sed 's/^/  坏版本的开机：/'
	[ "$(grep -c 'health_failed=[1-9]' <<<"$o")" = 3 ] || bad="${bad}退回之前不是三次 health failed 的开机；"

	# Step 4b：坏版本是唯一的版本时不循环
	snap a4-rb3 "accept-4a rollback: on $cur after broken userspace $V_BROKEN_USER fell back"
	gx "e=\$(bootctl -p)/EFI/Linux; mv \$e/MastersOS_${V_BROKEN_USER}_x86-64+0-3.efi \$e/MastersOS_${V_BROKEN_USER}_x86-64+1.efi; rm -f \$e/MastersOS_${cur}_x86-64*.efi; ls \$e"
	pve "qm reboot $vmid --timeout 180" >/dev/null
	sleep 240
	o=$(gx 'echo "$(. /usr/lib/os-release; echo $IMAGE_VERSION) $(systemctl is-active display-manager) $(systemctl is-system-running) up=$(cut -d. -f1 /proc/uptime)s"; journalctl --list-boots --no-pager | tail -3; journalctl -b -u mastersos-health --no-pager -o cat | grep -m1 "no fallback"' 2>&1)
	log "Step 4b：${o//$'\n'/ | }"
	grep -q 'no fallback' <<<"$o" || bad="${bad}4b：没有 health failed, no fallback；"
	grep -q "^$V_BROKEN_USER active" <<<"$o" || bad="${bad}4b：没停在 $V_BROKEN_USER 或 GDM 没起来；"
	grep -q ' starting ' <<<"$o" && bad="${bad}4b：is-system-running 还是 starting；"
	# 再过 60 秒：还是同一次开机（开机 id 不变、uptime 跟着涨），之间没有重启。qm reboot 之后多久才真的起来不一定，
	# 所以不拿 uptime 的绝对值判断
	local b1 u1 b2 u2
	read -r b1 u1 < <(gx 'echo "$(cat /proc/sys/kernel/random/boot_id) $(cut -d. -f1 /proc/uptime)"')
	sleep 60
	read -r b2 u2 < <(gx 'echo "$(cat /proc/sys/kernel/random/boot_id) $(cut -d. -f1 /proc/uptime)"')
	log "4b：60 秒前后开机 id ${b1:0:8}… / ${b2:0:8}…，uptime ${u1}s → ${u2}s"
	[ -n "$b1" ] && [ "$b1" = "$b2" ] && [ "$((u2 - u1))" -ge 55 ] 2>/dev/null || bad="${bad}4b：这 60 秒里又重启了；"
	shot rollback-4b-only-broken-stays-up
	stop_vm
	rollback a4-rb3
	delsnap a4-rb3
	start_wait || bad="${bad}回滚 a4-rb3 后起不来；"

	# Step 4：initrd 坏版本
	build "$V_BROKEN_INITRD" initrd || {
		fail "$name" "构建 $V_BROKEN_INITRD 失败"
		return
	}
	publish "$V_BROKEN_INITRD" beta || bad="${bad}publish $V_BROKEN_INITRD 失败；"
	run_update | sed 's/^/  /'
	m=$(serial_mark)
	pve "qm reboot $vmid --timeout 180" >/dev/null
	sleep 30
	wait_version "$cur" 900 || bad="${bad}initrd 坏版本没退回 ${cur}；"
	log "Step 4：串口里「启动失败（initrd）」$(serial_since "$m" | grep -c '启动失败（initrd）') 次；ESP：$(gx 'ls "$(bootctl -p)/EFI/Linux" | tr "\n" " "')"
	gx 'ls "$(bootctl -p)/EFI/Linux"' | grep -qx "MastersOS_${V_BROKEN_INITRD}_x86-64+0-3.efi" || bad="${bad}ESP 上没有 MastersOS_${V_BROKEN_INITRD}_x86-64+0-3.efi；"
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

# 从服务端取当前 LUKS 的恢复密钥，敲进串口（不落盘、不打印）
type_recovery_key() {
	local id luks key
	id=$1 luks=$2
	key=$(api recovery GET "/v1/admin/devices/$id/recovery-keys" | jq -r --arg u "$luks" '[.[] | select(.luks_uuid == $u)][0].recovery_key // empty')
	[ -n "$key" ] || return 1
	printf '%s\n' "$key" | serial_answer 'Please enter recovery key' 240
	unset key
}
# 这次开机的根分区是 TPM 解开的（不是恢复密钥）。不看串口：停机前那次开机没刷完的输出会晚到记录器里
tpm_unlocked() {
	local o
	o=$(gx 'journalctl -b -o cat --no-pager | grep -m1 -E "TPM2 token unlocks|Successfully extended NvPCR index .cryptsetup. with .cryptsetup-keyslot"')
	log "$1：${o:-（journal 里没有解锁记录）}"
	grep -q 'TPM2 token unlocks' <<<"$o"
}
c_local_password_change() {
	local name=local_password_change bad="" o pw new pwl
	pw=$(cat "$state/owner.pw" 2>/dev/null) || {
		fail "$name" "没有 owner 的口令（先跑 unmanaged）"
		return
	}
	new=$(LC_ALL=C tr -dc 'a-km-z2-9' </dev/urandom | head -c 11)
	o=$(gx 'stat -c "%F %N" /etc/pam.d; grep -E "^password" /etc/pam.d/common-password; grep -c pam_authd_exec /etc/pam.d/common-auth')
	echo "$o" | sed 's/^/  /'
	grep -q "symbolic link '/etc/pam.d'" <<<"$o" || bad="${bad}/etc/pam.d 不是指回 factory 的链接；"
	# 4b Task 9：common-password 里 authd 只给名字含 @ 的用户（它前面一行是按用户名的分流），pam_unix 不带 use_authtok
	pwl=$(grep '^password' <<<"$o")
	if grep -q pam_authd_exec <<<"$pwl" && ! head -n 1 <<<"$pwl" | grep -qF 'pam_succeed_if.so quiet user !~ *@*'; then
		bad="${bad}common-password 里 authd 前面没有按用户名分流；"
	fi
	grep pam_unix <<<"$pwl" | grep -q use_authtok && bad="${bad}common-password 的 pam_unix 带 use_authtok；"
	# 1. GNOME 设置（gnome-control-center 的 passwd-handler 就是在 pty 里跑 /usr/bin/passwd、按提示回答）与终端里的
	#    passwd：同一条路。旧口令、新口令两次只经 stdin 进 VM。
	o=$(printf '%s\n%s\n' "$pw" "$new" | gx_stdin '
read -r old; read -r new
python3 - "$old" "$new" <<"PY"
import os, pty, select, sys, time
old, new = sys.argv[1], sys.argv[2]
pid, fd = pty.fork()
if pid == 0:
    os.environ["LC_ALL"] = "C"
    os.execvp("runuser", ["runuser", "-u", "owner", "--", "passwd"])
out = b""
def rd(t):
    global out
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                d = os.read(fd, 1024)
            except OSError:
                return
            if not d:
                return
            out += d
for a in (old, new, new):
    rd(2)
    os.write(fd, a.encode() + b"\n")
rd(4)
r, st = os.waitpid(pid, os.WNOHANG)
if r == 0:
    os.kill(pid, 9)
    print(out.decode(errors="replace")); print("passwd 还在等（被终端查询卡住？）"); sys.exit(1)
print(out.decode(errors="replace").strip()); sys.exit(os.waitstatus_to_exitcode(st))
PY')
	echo "$o" | sed 's/^/  passwd（pty）：/'
	grep -q 'password updated successfully' <<<"$o" || bad="${bad}passwd 没改成（${o##*$'\n'}）；"
	# 1b. GNOME 设置的「更改」按钮要 libpwquality 认可新口令（字典检查读镜像里的 cracklib 字典）
	o=$(gx 'python3 - <<"PY"
import ctypes
l = ctypes.CDLL("libpwquality.so.1")
l.pwquality_default_settings.restype = ctypes.c_void_p
l.pwquality_strerror.restype = ctypes.c_char_p
s = ctypes.c_void_p(l.pwquality_default_settings())
l.pwquality_read_config(s, None, None)
aux = ctypes.c_void_p()
for pw in (b"Tq7-Rm4.Wz9-Lb2X", b"password"):
    r = l.pwquality_check(s, pw, None, b"owner", ctypes.byref(aux))
    buf = ctypes.create_string_buffer(256)
    print(pw[:3].decode() + "…", r, l.pwquality_strerror(buf, 256, r, aux).decode())
PY')
	echo "$o" | sed 's/^/  pwquality：/'
	awk '$1=="Tq7…" && $2 >= 0 {f=1} END{exit !f}' <<<"$o" || bad="${bad}libpwquality 不认可强口令（GNOME 设置改不了口令）；"
	# 2. 新口令能在 tty3 登录
	keys ctrl-alt-f3 wait:2
	local nk=() i
	for ((i = 0; i < ${#new}; i++)); do nk+=("${new:i:1}"); done
	keys o w n e r ret wait:2 "${nk[@]}" ret wait:4
	shot local-password-tty3
	gx 'loginctl list-sessions --no-legend | grep -E "owner .* tty3"' >/dev/null || bad="${bad}新口令在 tty3 登不进去；"
	keys e x i t ret wait:1 ctrl-alt-f1
	# 3. accountsservice（GNOME 设置里管理员给别的用户设口令）：SetPassword 收已哈希的口令，不经 PAM
	o=$(gx 'busctl call org.freedesktop.Accounts /org/freedesktop/Accounts org.freedesktop.Accounts FindUserByName s owner')
	log "accountsservice：$o"
	grep -q '/org/freedesktop/Accounts/User' <<<"$o" || bad="${bad}accountsservice 找不到 owner；"
	printf '%s' "$new" >"$state/owner.pw"
	[ -z "$bad" ] && pass "$name" || fail "$name" "$bad"
}

