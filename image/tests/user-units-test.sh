#!/bin/bash
# user-units.sh（mkosi.finalize 调）的处理与拒绝（本机与 CI 都跑，不需要 VM）：
#   bash image/tests/user-units-test.sh
# 假的镜像根照 20261016 构建里的 /etc/systemd/user 与 /usr/lib/systemd/user 搭：/etc 里是 dpkg 建的绝对链接，
# mkosi.extra 的 PipeWire 链接原样拷进 /usr，dbus-user-session 的 dbus.service 是 dbus-daemon 的单元文件。
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
uus=$here/../user-units.sh
extra=$here/../mkosi.extra/usr/lib/systemd/user
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0 n=0

check() { # <名字> <条件命令…>
	local name=$1
	shift
	n=$((n + 1))
	if "$@"; then
		echo "ok   $name"
	else
		echo "FAIL $name" >&2
		fails=$((fails + 1))
	fi
}

DBUS_EXEC='ExecStart=/usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only'

# 允许清单（从 user-units.sh 里读，假的 /etc 就照它搭）
allow=$(sed -n "/^ALLOW='\$/,/^'\$/p" "$uus" | sed '1d;$d' | grep -vE '^[[:space:]]*(#|$)')

mkroot() { # <根>：/etc 里是清单的全部链接（绝对路径），/usr 里有每个单元文件、mkosi.extra 的链接、dbus-daemon 的 dbus.service
	local r=$1 p u
	mkdir -p "$r/etc/systemd/user" "$r/usr/lib/systemd/user"
	cp -a "$extra/." "$r/usr/lib/systemd/user/"
	while read -r p u; do
		mkdir -p "$(dirname "$r/etc/systemd/user/$p")"
		ln -s "/usr/lib/systemd/user/$u" "$r/etc/systemd/user/$p"
		[ -e "$r/usr/lib/systemd/user/$u" ] || printf '[Unit]\nDescription=%s\n' "$u" >"$r/usr/lib/systemd/user/$u"
	done <<<"$allow"
	printf '[Unit]\nDescription=D-Bus User Message Bus\n\n[Service]\n%s\n' "$DBUS_EXEC" >"$r/usr/lib/systemd/user/dbus.service"
}

run() { # <根> <输出文件>：退出码
	local rc=0
	bash "$uus" "$1" >"$2" 2>&1 || rc=$?
	return "$rc"
}

refused() { # <根> [输出文件]：user-units.sh 拒绝（非 0 退出）
	! bash "$uus" "$1" >"${2:-/dev/null}" 2>&1
}

# 1. 正常：全部搬到 /usr，PipeWire 不重复，dbus.service 换成别名
r=$tmp/ok
mkroot "$r"
check "正常的树通过" run "$r" "$tmp/ok.out"
U=$r/usr/lib/systemd/user
check "gpg-agent.socket 链到 /usr" test "$(readlink "$U/sockets.target.wants/gpg-agent.socket")" = ../gpg-agent.socket
check "ssh-agent.socket 链到 /usr" test "$(readlink "$U/sockets.target.wants/ssh-agent.socket")" = ../ssh-agent.socket
check "xdg-user-dirs 链到 /usr" test "$(readlink "$U/graphical-session-pre.target.wants/xdg-user-dirs.service")" = ../xdg-user-dirs.service
check "用户级 tmpfiles-clean.timer 链到 /usr" test "$(readlink "$U/timers.target.wants/systemd-tmpfiles-clean.timer")" = ../systemd-tmpfiles-clean.timer
check "filter-chain 链到 /usr" test "$(readlink "$U/default.target.wants/filter-chain.service")" = ../filter-chain.service
check "dbus.service 换成指向 dbus-broker.service 的别名" test "$(readlink "$U/dbus.service")" = dbus-broker.service
check "PipeWire 的别名原样（mkosi.extra 的相对链接）" test "$(readlink "$U/pipewire-session-manager.service")" = wireplumber.service
check "日志：PipeWire 的 6 个已有、不重复" grep -qE '已有 6、换掉包的单元文件 1' "$tmp/ok.out"
check "幂等：再跑一次也通过" run "$r" "$tmp/ok2.out"
check "幂等：第二次全是已有" grep -qE '新建 0、已有 21、换掉包的单元文件 0' "$tmp/ok2.out"

# 2. 清单外的新链接：拒绝
r=$tmp/new
mkroot "$r"
mkdir -p "$r/etc/systemd/user/default.target.wants"
printf '[Unit]\n' >"$r/usr/lib/systemd/user/tracker-miner.service"
ln -s /usr/lib/systemd/user/tracker-miner.service "$r/etc/systemd/user/default.target.wants/tracker-miner.service"
check "清单外的链接拒绝构建" refused "$r" "$tmp/new.out"
check "  原因是不在清单里、并说出是哪一个" grep -qF '/etc/systemd/user/default.target.wants/tracker-miner.service → /usr/lib/systemd/user/tracker-miner.service 不在允许清单里' "$tmp/new.out"

# 3. 清单里有、/etc 里没有：拒绝
r=$tmp/gone
mkroot "$r"
rm "$r/etc/systemd/user/sockets.target.wants/keyboxd.socket"
check "清单里有、/etc 里没了：拒绝" refused "$r" "$tmp/gone.out"
check "  原因是 /etc 里没有、并说出是哪一个" grep -qF '允许清单里的 sockets.target.wants/keyboxd.socket 在镜像的 /etc/systemd/user 里没有' "$tmp/gone.out"

# 4. 指向别的单元：拒绝
r=$tmp/retarget
mkroot "$r"
ln -sfn /usr/lib/systemd/user/dbus-daemon.service "$r/etc/systemd/user/dbus.service"
check "指向的单元与清单不同：拒绝" refused "$r" "$tmp/retarget.out"
check "  原因是指向别处" grep -qF '/etc/systemd/user/dbus.service 指向 /usr/lib/systemd/user/dbus-daemon.service，清单里是 dbus-broker.service' "$tmp/retarget.out"

# 5. 单元在镜像里不存在：拒绝
r=$tmp/dangling
mkroot "$r"
rm "$r/usr/lib/systemd/user/xdg-user-dirs.service"
check "单元文件不存在：拒绝" refused "$r" "$tmp/dangling.out"
check "  原因是没有单元文件" grep -qF 'xdg-user-dirs.service 在 /usr/lib/systemd/user 里没有单元文件' "$tmp/dangling.out"

# 6. 不是链接的文件（drop-in 之类）：拒绝
r=$tmp/file
mkroot "$r"
mkdir -p "$r/etc/systemd/user/pipewire.service.d"
printf '[Service]\n' >"$r/etc/systemd/user/pipewire.service.d/override.conf"
check "/etc/systemd/user 里的普通文件：拒绝" refused "$r" "$tmp/file.out"
check "  原因是不是链接" grep -qF '/etc/systemd/user/pipewire.service.d/override.conf 不是链接' "$tmp/file.out"

# 7. 要换掉的 dbus.service 不是预期的那个：拒绝，原文件不动
r=$tmp/dbus
mkroot "$r"
printf '[Service]\nExecStart=/usr/bin/something-else\n' >"$r/usr/lib/systemd/user/dbus.service"
check "dbus.service 内容不对：拒绝" refused "$r" "$tmp/dbus.out"
check "  原因是不是预期的单元" grep -qF '/usr/lib/systemd/user/dbus.service 不是预期的那个单元' "$tmp/dbus.out"
check "  原文件不动" test ! -L "$r/usr/lib/systemd/user/dbus.service"

# 8. /usr 里已有的链接指向别处（mkosi.extra 与包不一致）：拒绝
r=$tmp/extra
mkroot "$r"
ln -sfn ../pipewire-media-session.service "$r/usr/lib/systemd/user/pipewire.service.wants/wireplumber.service"
check "/usr 里已有的链接与 /etc 不一致：拒绝" refused "$r" "$tmp/extra.out"
check "  原因是已是指向别处的链接" grep -qF '/usr/lib/systemd/user/pipewire.service.wants/wireplumber.service 已是指向 ../pipewire-media-session.service 的链接' "$tmp/extra.out"

# 9. 包把 /usr 里的 dbus.service 改成了别的别名（不是 dbus-daemon 的单元文件，也不是指向 broker 的链接）：拒绝
r=$tmp/dbusalias
mkroot "$r"
ln -sfn dbus-daemon.service "$r/usr/lib/systemd/user/dbus.service"
check "/usr 里的 dbus.service 是指向别处的别名：拒绝" refused "$r" "$tmp/dbusalias.out"
check "  原因是已是指向别处的链接" grep -qF '/usr/lib/systemd/user/dbus.service 已是指向 dbus-daemon.service 的链接' "$tmp/dbusalias.out"

# 10. 没有 /etc/systemd/user：拒绝
r=$tmp/none
mkdir -p "$r/usr/lib/systemd/user"
check "没有 /etc/systemd/user：拒绝" refused "$r" "$tmp/none.out"
check "  原因是没有那个目录" grep -qF '镜像里没有 /etc/systemd/user' "$tmp/none.out"

# 11. 包没装（正式镜像没有 openssh-client）：/etc 里没有链接、单元也不在，跳过
r=$tmp/nopkg
mkroot "$r"
rm "$r/etc/systemd/user/sockets.target.wants/ssh-agent.socket" "$r/usr/lib/systemd/user/ssh-agent.socket"
check "包没装（链接与单元都没有）：通过" run "$r" "$tmp/nopkg.out"
check "  /usr 里不建它的链接" test ! -e "$r/usr/lib/systemd/user/sockets.target.wants/ssh-agent.socket"

echo "user-units-test: $((n - fails))/$n 通过"
[ "$fails" = 0 ]
