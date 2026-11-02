#!/bin/bash
# 发行版在 /etc/systemd/user 里启用的用户单元搬到 /usr/lib/systemd/user（4b Task 24）。mkosi.finalize 调它，
# tests/user-units-test.sh 拿假的根调它。用法：user-units.sh <镜像根>
#
# 为什么：Debian 的 postinst（deb-systemd-helper --user、systemctl --global enable）与 mkosi 的 systemctl --global preset-all
# 把用户单元的启用链接放在 /etc/systemd/user；机器的 /etc 由 etc-policy.conf 生成，那个目录到不了机器——gpg/ssh-agent 的
# socket、xdg-user-dirs、用户级的 tmpfiles 都没跑（Task 13 先发现 PipeWire 没声音，当时只补了 PipeWire：mkosi.extra 里的链接）。
# 这里对 /etc/systemd/user 里的每一项按下面的允许清单处理：
#   - 清单里有、/usr 里还没有：在 /usr/lib/systemd/user 的同一路径建链接（.wants/ 里是 ../<单元>，顶层别名是 <单元>）；
#   - /usr 里已有指向同一单元的链接（mkosi.extra 放的 PipeWire）：不重复建；
#   - 顶层别名在 /usr 里是包的真实单元文件（dbus.service）：只有 REPLACE 里列的才换成链接，且原文件必须是预期的那一个；
#   - 清单外的链接、不是链接的文件、指向别处的链接、单元在镜像里不存在：拒绝构建——以后包多启用一个，逼着人看一眼；
#   - 清单里有、/etc 里没有：同样拒绝（包不再启用它了，清单要跟着改）；单元在镜像里也没有的跳过（这个 profile 没装那个包，
#     如正式镜像没有 openssh-client）。
# 最后核对：/etc/systemd/user 里的每个链接，/usr/lib/systemd/user 的同一路径都有指向同一单元的链接。
set -euo pipefail

# <相对 /etc/systemd/user 的路径> <指向的单元>（20261016 的构建里 /etc/systemd/user 的全部内容；dpkg 与 mkosi 的 preset 各建了哪些
# 见构建日志的「Created symlink '…/etc/systemd/user/…'」）
ALLOW='
# gnupg：gpg-agent（含 ssh 与浏览器的 socket）、dirmngr、keyboxd
sockets.target.wants/dirmngr.socket                                 dirmngr.socket
sockets.target.wants/gpg-agent.socket                               gpg-agent.socket
sockets.target.wants/gpg-agent-browser.socket                       gpg-agent-browser.socket
sockets.target.wants/gpg-agent-extra.socket                         gpg-agent-extra.socket
sockets.target.wants/gpg-agent-ssh.socket                           gpg-agent-ssh.socket
sockets.target.wants/keyboxd.socket                                 keyboxd.socket
# openssh-client
sockets.target.wants/ssh-agent.socket                               ssh-agent.socket
# PipeWire（mkosi.extra 里已有同样的链接，Task 13）
sockets.target.wants/pipewire.socket                                pipewire.socket
sockets.target.wants/pipewire-pulse.socket                          pipewire-pulse.socket
default.target.wants/pipewire.service                               pipewire.service
default.target.wants/pipewire-pulse.service                         pipewire-pulse.service
default.target.wants/filter-chain.service                           filter-chain.service
pipewire.service.wants/wireplumber.service                          wireplumber.service
pipewire-session-manager.service                                    wireplumber.service
# 登录时建「文档、下载」等目录（按 locale）、会话迁移、portal 改写启动器
graphical-session-pre.target.wants/xdg-user-dirs.service            xdg-user-dirs.service
graphical-session-pre.target.wants/user-session-migration.service   user-session-migration.service
graphical-session-pre.target.wants/xdg-desktop-portal-rewrite-launchers.service xdg-desktop-portal-rewrite-launchers.service
# systemd 自己的用户 preset（mkosi 的 systemctl --global preset-all）
basic.target.wants/systemd-tmpfiles-setup.service                   systemd-tmpfiles-setup.service
timers.target.wants/systemd-tmpfiles-clean.timer                    systemd-tmpfiles-clean.timer
default.target.wants/machines.target                                machines.target
# dbus-broker 的 postinst：用户会话总线由 dbus-broker 跑（系统总线同样，由 preset 的 enable dbus-broker.service 建别名）。
# 换成 broker 之前核对过浏览器模式的 D-Bus 覆盖（agent 在会话中途写、删 /var/lib/mastersos-public/xdg/dbus-1/services）：
# dbus-broker-launch 用 inotify 看服务目录（日志「Noticed file-system modification, trigger reload」），会话中途切浏览器 ↔ 桌面
# 两个方向都即时生效，与 dbus-daemon 相同；两者都只看总线起来时已存在的目录，所以那个目录由 tmpfiles 开机就建（mastersos.conf）。
# VM 165 的记录：lab/results/2026-10-16-4b/t24-user-units.txt「复审修复 1」
dbus.service                                                        dbus-broker.service
'

# 顶层别名在 /usr 里是包的单元文件时，允许换成链接的：<路径> <原文件里必须有的一行>
# dbus.service：dbus-user-session 的 /usr/lib/systemd/user/dbus.service 是 dbus-daemon 的（/etc 里的别名在 Ubuntu 上盖过它）
REPLACE='
dbus.service    ExecStart=/usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
'

die() {
	echo "user-units: $*" >&2
	exit 1
}

R=${1:?用法：user-units.sh <镜像根>}
E=$R/etc/systemd/user
U=$R/usr/lib/systemd/user

declare -A want=() replace=()
while read -r p u extra; do
	case "$p" in '' | '#'*) continue ;; esac
	if [ -z "$u" ] || [ -n "$extra" ]; then die "ALLOW 的一行应是「<路径> <单元>」：$p $u $extra"; fi
	want[$p]=$u
done <<<"$ALLOW"
while read -r p line; do
	case "$p" in '' | '#'*) continue ;; esac
	replace[$p]=$line
done <<<"$REPLACE"

# 链接 $1 指向的单元名；只认 /usr/lib/systemd/user/<单元>、../<单元>、<单元> 三种写法
target_unit() {
	local t n
	t=$(readlink "$1")
	case "$t" in
	/usr/lib/systemd/user/*) n=${t#/usr/lib/systemd/user/} ;;
	../*) n=${t#../} ;;
	*) n=$t ;;
	esac
	case "$n" in */*) echo "" ;; *) echo "$n" ;; esac
}

[ -d "$E" ] || die "镜像里没有 /etc/systemd/user（包与 preset 应在那里建了启用链接）"
declare -A seen=()
nnew=0 nkeep=0 nrepl=0
while IFS= read -r -d '' f; do
	p=${f#"$E"/}
	[ -L "$f" ] || die "/etc/systemd/user/$p 不是链接（只认启用链接；别的东西放进来要先想清楚它怎么到机器上）"
	u=${want[$p]:-}
	[ -n "$u" ] || die "/etc/systemd/user/$p → $(readlink "$f") 不在允许清单里：看清它是什么、发行版是否默认启用，再加进 user-units.sh 的 ALLOW"
	[ "$(target_unit "$f")" = "$u" ] || die "/etc/systemd/user/$p 指向 $(readlink "$f")，清单里是 $u"
	{ [ -f "$U/$u" ] && [ ! -L "$U/$u" ]; } || die "/etc/systemd/user/$p 指向的 $u 在 /usr/lib/systemd/user 里没有单元文件"
	seen[$p]=1
	d=$U/$p
	case "$p" in */*) rel=../$u ;; *) rel=$u ;; esac
	if [ -L "$d" ]; then
		[ "$(target_unit "$d")" = "$u" ] || die "/usr/lib/systemd/user/$p 已是指向 $(readlink "$d") 的链接，/etc 里是 $u"
		nkeep=$((nkeep + 1))
		continue
	fi
	if [ -e "$d" ]; then
		[ -n "${replace[$p]:-}" ] || die "/usr/lib/systemd/user/$p 是包的单元文件，/etc 里的 $p 是盖过它的别名（→ ${u}）；换掉它要先在 REPLACE 里写明"
		grep -qxF -- "${replace[$p]}" "$d" || die "/usr/lib/systemd/user/$p 不是预期的那个单元（没有「${replace[$p]}」），先看清它再改 REPLACE"
		rm -f "$d"
		ln -s "$rel" "$d"
		echo "user-units: /usr/lib/systemd/user/$p 原是包的单元文件，换成指向 $rel 的别名（与 /etc 里的一致）"
		nrepl=$((nrepl + 1))
		continue
	fi
	mkdir -p "$(dirname "$d")"
	ln -s "$rel" "$d"
	nnew=$((nnew + 1))
done < <(find "$E" -mindepth 1 ! -type d -print0 | LC_ALL=C sort -z)

for p in "${!want[@]}"; do
	# The package is not in this profile (openssh-client is only pulled in by the lab profile's openssh-server): nothing to enable.
	[ -n "${seen[$p]:-}" ] || [ -e "$U/${want[$p]}" ] || continue
	[ -n "${seen[$p]:-}" ] || die "允许清单里的 $p 在镜像的 /etc/systemd/user 里没有（包不再启用它了？），先核对再改 ALLOW"
done

# 最后核对：/etc 里的每个链接在 /usr 里都有指向同一单元的对应项
while IFS= read -r -d '' f; do
	p=${f#"$E"/}
	{ [ -L "$U/$p" ] && [ "$(target_unit "$U/$p")" = "$(target_unit "$f")" ]; } ||
		die "/etc/systemd/user/$p 在 /usr/lib/systemd/user 里没有对应的链接"
done < <(find "$E" -mindepth 1 -type l -print0)

echo "user-units: /etc/systemd/user 的 ${#seen[@]} 个启用链接都在 /usr/lib/systemd/user（新建 ${nnew}、已有 ${nkeep}、换掉包的单元文件 ${nrepl}）"
