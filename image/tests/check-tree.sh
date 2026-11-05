#!/bin/bash
# 镜像树的静态检查（CI 的 image-lint 与本机都跑它）。任何一条不成立就打印原因、退出 1。
# 只看仓库里的文件，不构建镜像。用法：bash image/tests/check-tree.sh
set -euo pipefail

img=$(cd "$(dirname "$0")/.." && pwd)
top=$(git -C "$img" rev-parse --show-toplevel)
cd "$top"
rel=${img#"$top"/}          # image
core=$(dirname "$rel")/core # core

fail=0
bad() { echo "check-tree: FAIL [$1] $2" >&2; fail=1; }
ok() { echo "check-tree: ok   [$1] $2"; }

# 仓库里（已跟踪 + 未跟踪且没被忽略）的镜像树文件
mapfile -t files < <(git ls-files -co --exclude-standard -- "$rel")

# 1. 没有私钥、mkosi 的钥匙与本机配置入库
privkey='PRIVATE'' KEY' # 拆开写，免得本脚本自己命中
n=0
for f in "${files[@]}"; do
	[ -f "$f" ] || continue
	case "$(basename "$f")" in
	mkosi.key | mkosi.crt | mkosi.local.conf)
		bad 1 "$f 不应入库（钥匙只在构建机的 ~/mastersos-keys/）"
		n=$((n + 1))
		continue
		;;
	esac
	if grep -q "$privkey" "$f"; then
		bad 1 "$f 含私钥"
		n=$((n + 1))
	fi
done
[ "$n" = 0 ] && ok 1 "没有私钥与 mkosi.key / mkosi.crt / mkosi.local.conf"

# 2. 不得出现字面 PCR 绑定（Global Constraints：字面 PCR 一律为空，只许签名的 PCR 11 策略 + pcrlock）。
#    查镜像树（lab/results/ 是验收输出，含反例记录，不算）与 core（agent 调 systemd-cryptenroll）：
#    - repart 定义的 TPM2PCRs= 只能是空的
#    - systemd-cryptenroll / crypttab 的字面 PCR 参数只能带「=」且值为空：带值的、或者没有「=」
#      （值放在下一个参数里）的都算
pcr7='TPM2PCRs''=7' # 拆开写，免得本脚本自己命中
lit_re='^[[:space:]]*TPM2PCRs=[[:space:]]*[^[:space:]#]'
tp='tpm2''-pcrs'
# 「=」后面紧跟的只许是引号、反引号、空白、逗号、右括号、反斜杠或行尾
arg_re="$tp([^=]|\$)|$tp=[^]\"'\`[:space:],)}\\]"
mapfile -t core_files < <(git ls-files -co --exclude-standard -- "$core" | grep -v '/target/' || true)
hits=$(for f in "${files[@]}" "${core_files[@]}"; do
	case "$f" in "$rel"/lab/results/*) continue ;; esac
	[ -f "$f" ] || continue
	grep -HnF -- "$pcr7" "$f" || true
	# luksDump 的 JSON（agent 的测试 fixture）里字面 PCR 是一个列表，空列表（整行只有 "<键>":[]）不算
	grep -HnE -- "$arg_re" "$f" | grep -vE "^[^:]*:[0-9]+:[[:space:]]*\"$tp\":[[:space:]]*\[[[:space:]]*\],?[[:space:]]*\$" || true
	case "$f" in *.conf) grep -HnE -- "$lit_re" "$f" || true ;; esac
done)
if [ -n "$hits" ]; then
	bad 2 "出现了字面 PCR 绑定（只许签名的 PCR 11 策略 + pcrlock）："
	printf '%s\n' "$hits" | sed '/^$/d; s/^/    /' | sort -u >&2
else
	ok 2 "镜像树与 core 里没有字面 PCR 绑定"
fi

# 3. /etc 策略表：格式、/etc/ 前缀、不重复、dir 与 copy 的父目录都是 dir 或 /etc
check_policy() { # $1 = 策略表（可多个，合起来检查，例如正式 + lab）
	local -A kind=()
	local f line k p extra rc=0 ln
	for f in "$@"; do
		ln=0
		while IFS= read -r line || [ -n "$line" ]; do
			ln=$((ln + 1))
			line=${line%%#*}
			line=$(printf '%s' "$line" | sed 's/[[:space:]]*$//; s/^[[:space:]]*//')
			[ -z "$line" ] && continue
			read -r k p extra <<<"$line"
			if [ -n "${extra:-}" ] || [ -z "${p:-}" ]; then
				bad 3 "$f:$ln 格式应为「<kind> <绝对路径>」：$line"
				rc=1
				continue
			fi
			case "$k" in copy | dir) ;; *)
				bad 3 "$f:$ln kind 只能是 copy 或 dir：$k"
				rc=1
				continue
				;;
			esac
			case "$p" in
			/etc/*) ;;
			*)
				bad 3 "$f:$ln 路径必须以 /etc/ 开头：$p"
				rc=1
				continue
				;;
			esac
			case "$p" in */ | *//* | */./* | */../* | */. | */..)
				bad 3 "$f:$ln 路径不规范：$p"
				rc=1
				continue
				;;
			esac
			if [ -n "${kind[$p]:-}" ]; then
				bad 3 "$f:$ln 重复的路径：$p"
				rc=1
				continue
			fi
			kind[$p]=$k
		done <"$f"
	done
	for p in "${!kind[@]}"; do
		local parent
		parent=$(dirname "$p")
		[ "$parent" = /etc ] && continue
		if [ "${kind[$parent]:-}" != dir ]; then
			bad 3 "${p}（${kind[$p]}）的父目录 $parent 不是 dir——它会是指回 /usr 的只读链接"
			rc=1
		fi
	done
	return $rc
}
policy=$rel/etc-policy.conf
if [ ! -f "$policy" ]; then
	bad 3 "缺少 $policy"
else
	r=0
	check_policy "$policy" || r=1
	for extra in "$rel"/etc-policy.*.conf; do
		[ -e "$extra" ] || continue
		check_policy "$policy" "$extra" || r=1
	done
	[ "$r" = 0 ] && ok 3 "etc-policy 格式、前缀、去重与父目录"
fi

# 4. sysupdate 的 transfer：模板 sysupdate.d.in 的源是 @BASE@/@CHANNEL@/，/usr/lib/sysupdate.d 里的
#    四个与模板逐字节相同、只把 @CHANNEL@ 换成 stable；两边都不写死任何 URL（@BASE@ 由 finalize 换成
#    MASTERSOS_UPDATE_BASE，正式镜像只收 https://）
tin=$rel/mkosi.extra/usr/lib/mastersos/sysupdate.d.in
tout=$rel/mkosi.extra/usr/lib/sysupdate.d
r=0
names="10-usr-verity-sig.transfer 11-usr-verity.transfer 12-usr.transfer 20-uki.transfer"
list_transfers() { # 按名字排序（glob 已排好），空格分隔；本机 macOS 的 find 没有 -printf
	local f out=""
	for f in "$1"/*.transfer; do [ -f "$f" ] && out="$out${out:+ }${f##*/}"; done
	echo "$out"
}
have_in=$(list_transfers "$tin")
have_out=$(list_transfers "$tout")
if [ "$have_in" != "$names" ] || [ "$have_out" != "$names" ]; then
	bad 4 "transfer 应恰好是 ${names}；sysupdate.d.in：'${have_in}'，sysupdate.d：'${have_out}'"
	r=1
else
	for n in $names; do
		src=$(grep -E '^[[:space:]]*Path=' "$tin/$n" | grep -vE '^[[:space:]]*Path=(auto|/)' || true)
		if [ "$src" != "Path=@BASE@/@CHANNEL@/" ]; then
			bad 4 "$tin/$n 的源 Path= 应为 @BASE@/@CHANNEL@/，实际：${src:-<无>}"
			r=1
		fi
		if ! diff -q <(sed 's/@CHANNEL@/stable/g' "$tin/$n") "$tout/$n" >/dev/null; then
			bad 4 "$tout/$n 应与模板相同、只把 @CHANNEL@ 换成 stable："
			diff <(sed 's/@CHANNEL@/stable/g' "$tin/$n") "$tout/$n" | sed 's/^/    /' >&2 || true
			r=1
		fi
		if grep -nE '[a-z]+://' "$tin/$n" "$tout/$n" >&2; then
			bad 4 "$n 里写死了 URL（只许 @BASE@）"
			r=1
		fi
	done
fi
[ "$r" = 0 ] && ok 4 "transfer 模板与 stable 一致，源都是 @BASE@"

# 5. 安装器的分区定义（installer/install.repart.d）与首次开机的一致（除 40-root.conf）
seq_of() { # 按文件名排序，输出每个文件的 Type/Label/SizeMin/SizeMax
	local d=$1 f
	for f in "$d"/*.conf; do # glob 按文件名排好序
		f=${f##*/}
		[ "$f" = 40-root.conf ] && continue
		case $f in 2[5-8]-golden-*.conf) continue ;; esac # installer-only golden copy (rule 36)
		printf '%s ' "$f"
		grep -E '^(Type|Label|SizeMinBytes|SizeMaxBytes)=' "$d/$f" | tr '\n' ' '
		echo
	done
}
if [ -d "$rel/installer/install.repart.d" ]; then
	a=$(seq_of "$rel/installer/install.repart.d")
	b=$(seq_of "$rel/mkosi.extra/usr/lib/repart.d")
	r=0
	if [ "$a" != "$b" ]; then
		bad 5 "installer/install.repart.d 与 mkosi.extra/usr/lib/repart.d 不一致："
		diff <(echo "$a") <(echo "$b") | sed 's/^/    /' >&2 || true
		r=1
	fi
	ir=$rel/installer/install.repart.d
	# 根分区只由目标机首次开机建（TPM 登记在它自己身上）；A 槽逐块复制；ESP 不拷文件；种子从安装器摆好的目录来
	if [ -e "$ir/40-root.conf" ]; then
		bad 5 "$ir 里不能有 40-root.conf"
		r=1
	fi
	for f in 10-usr-verity-sig.conf 11-usr-verity.conf 12-usr.conf; do
		grep -qx 'CopyBlocks=auto' "$ir/$f" 2>/dev/null || {
			bad 5 "$ir/$f 应 CopyBlocks=auto"
			r=1
		}
	done
	if grep -qE '^(CopyFiles|CopyBlocks)=' "$ir/00-esp.conf" 2>/dev/null; then
		bad 5 "$ir/00-esp.conf 不拷文件（mastersos-installer 复制）"
		r=1
	fi
	grep -qx 'CopyFiles=/run/mastersos-install/seed:/' "$ir/30-seed.conf" 2>/dev/null || {
		bad 5 "$ir/30-seed.conf 应 CopyFiles=/run/mastersos-install/seed:/"
		r=1
	}
	[ "$r" = 0 ] && ok 5 "安装器与首次开机的分区定义一致（除根分区）、A 槽逐块复制、种子从安装器摆好的目录来"
else
	echo "check-tree: skip [5] 还没有 installer/install.repart.d（Task 11 之后生效）"
fi

# 6. 找本机分区只按启动盘：镜像附加树与 core 里不得用按标签找分区的路径
pl='by-''partlabel'
hits=$(grep -rn --exclude-dir=target -- "$pl" "$rel/mkosi.extra" "$core" 2>/dev/null || true)
if [ -n "$hits" ]; then
	bad 6 "用了 /dev/disk/${pl}（别的盘、U 盘可以带同名标签）："
	printf '%s\n' "$hits" | sed 's/^/    /' >&2
else
	ok 6 "没有按标签找分区"
fi

# 7. 包表里没有 gnome-initial-setup（Ruling 18）
[ -f "$rel/mkosi.conf" ] || bad 7 "缺少 $rel/mkosi.conf"
pkg_hits=$(awk '
	/^[[:space:]]*#/ { next }
	/^[A-Za-z]+=/ { key = $0; sub(/=.*/, "", key) }
	key == "Packages" && /(^|[=[:space:]])gnome-initial-setup([[:space:]]|$)/ { print FILENAME ":" FNR ": " $0 }
' "$rel/mkosi.conf" "$rel"/mkosi.profiles/*.conf 2>/dev/null || true)
if [ -n "$pkg_hits" ]; then
	bad 7 "包表里有 gnome-initial-setup："
	printf '%s\n' "$pkg_hits" | sed 's/^/    /' >&2
else
	ok 7 "包表里没有 gnome-initial-setup"
fi

# 8. 正式镜像不自动导入 Secure Boot 钥匙
loader=$rel/mkosi.extra/boot/loader/loader.conf
r=0
if ! grep -qE '^[[:space:]]*secure-boot-enroll[[:space:]]+off[[:space:]]*$' "$loader" 2>/dev/null; then
	bad 8 "$loader 应含 secure-boot-enroll off"
	r=1
fi
keys_auto=$(find "$rel/mkosi.extra" -path '*loader/keys/auto*' 2>/dev/null || true)
if [ -n "$keys_auto" ]; then
	bad 8 "mkosi.extra 下不应有 loader/keys/auto（只放 lab 的附加树）：$keys_auto"
	r=1
fi
# mkosi 的 SecureBootAutoEnroll=yes 让 bootctl 往 ESP 写 loader/keys/auto/：主配置必须是 no，只有 lab profile 打开
if ! grep -qxE 'SecureBootAutoEnroll=no' "$rel/mkosi.conf"; then
	bad 8 "$rel/mkosi.conf 应写 SecureBootAutoEnroll=no（正式镜像的 ESP 上不能有 loader/keys/auto）"
	r=1
fi
ae=$(grep -rlE '^[[:space:]]*SecureBootAutoEnroll=(yes|true|1|on)' "$rel" --include='*.conf' 2>/dev/null | grep -vxF "$rel/mkosi.profiles/lab.conf" || true)
if [ -n "$ae" ]; then
	bad 8 "SecureBootAutoEnroll=yes 只许出现在 mkosi.profiles/lab.conf：$(echo "$ae" | tr '\n' ' ')"
	r=1
fi
[ "$r" = 0 ] && ok 8 "正式 loader.conf 关掉自动导入、mkosi.extra 没有 loader/keys/auto、只有 lab profile 打开 SecureBootAutoEnroll"

# 9. 所有 shell 脚本都 set -euo pipefail（带 ERR trap 的写 set -Eeuo pipefail 也算）
r=0
for f in "${files[@]}"; do
	[ -f "$f" ] || continue
	# 测试样本是别人文件的原样副本（发行版的 namespace.init 之类），不是我们的脚本
	case "$f" in "$rel"/tests/fixtures/*) continue ;; esac
	head -1 "$f" | grep -qE '^#!.*\b(ba)?sh\b' || continue
	if ! grep -qE '^[[:space:]]*set -E?euo pipefail' "$f"; then
		bad 9 "$f 没有 set -euo pipefail"
		r=1
	fi
done
[ "$r" = 0 ] && ok 9 "shell 脚本都 set -euo pipefail"

# 10. 试验网的更新源（VM 161 的 http://192.168.x.x）只许出现在 lab profile、lab 工具与文档里：
#     进正式镜像的树（mkosi.conf、mkosi.extra、mkosi.initrd.conf、finalize、postinst）一处都不许有
lab_re='192\.168\.[0-9]+\.[0-9]+|http://'
# The SVG namespace (xmlns="http://www.w3.org/2000/svg") is a name, not a fetch: drop it before matching.
hits=$(grep -rnE --exclude-dir=keys -- "$lab_re" "$rel/mkosi.conf" "$rel/mkosi.extra" "$rel/mkosi.repart" \
	"$rel/mkosi.finalize" "$rel/mkosi.postinst.chroot" "$rel/mkosi.initrd.conf" 2>/dev/null |
	sed 's#xmlns="http://www\.w3\.org/2000/svg"##g' | grep -E -- "$lab_re" || true)
if [ -n "$hits" ]; then
	bad 10 "正式镜像的树里出现了试验网地址或 http://："
	printf '%s\n' "$hits" | sed 's/^/    /' >&2
else
	ok 10 "正式镜像的树里没有试验网地址与 http://"
fi

# 11. 公钥：sysupdate 的 gpg 公钥是二进制 keyring（S2：文件名必须是 import-pubring.pgp），PCR 公钥是 PEM 公钥
r=0
for pgp in $rel/keys/import-pubring.pgp $rel/keys/google-chrome-keyring.gpg; do
	if [ ! -s "$pgp" ]; then
		bad 11 "缺少 $pgp"
		r=1
	else
		b=$(head -c1 "$pgp" | od -An -tx1 | tr -d ' \n')
		case "$b" in 98 | 99 | c6) ;; *)
			bad 11 "$pgp 应是二进制 OpenPGP 公钥（gpg --export / --dearmor，不要 --armor），首字节是 0x$b"
			r=1
			;;
		esac
	fi
done
pem=$rel/keys/tpm2-pcr-public-key.pem
if ! head -1 "$pem" 2>/dev/null | grep -qx -- '-----BEGIN PUBLIC KEY-----'; then
	bad 11 "$pem 应是 PEM 公钥（publish.sh 用它核对 UKI 的 .pcrpkey）"
	r=1
fi
# Google 的 keyring：恰好一把主钥且指纹是钉住的那个、子钥只签名（与 mkosi.finalize 同一个脚本）
if ! gk=$("$rel/check-google-keyring.sh" "$rel/keys/google-chrome-keyring.gpg" 2>&1 >/dev/null); then
	bad 11 "$gk"
	r=1
fi
[ "$r" = 0 ] && ok 11 "keys/ 里的 import-pubring.pgp、google-chrome-keyring.gpg（主钥钉住）与 tpm2-pcr-public-key.pem 格式对"

# 12. mkosi.extra 里带 [Install] 的 mastersos 单元都由 /usr/lib 里的 .wants/.requires 链接启用：preset 只在
#     首次开机套用一次，已装好的机器更新到新镜像后，新加的单元只有这样才会起来（Task 1 的发现）
r=0
sysd=$rel/mkosi.extra/usr/lib/systemd/system
for u in "$sysd"/mastersos-*.service "$sysd"/mastersos-*.timer; do
	[ -f "$u" ] || continue
	grep -qE '^\[Install\]' "$u" || continue
	n=${u##*/}
	links=$(find "$sysd" -mindepth 2 -maxdepth 2 \( -path '*.wants/*' -o -path '*.requires/*' \) -name "$n" -type l)
	if [ -z "$links" ]; then
		bad 12 "$n 有 [Install] 但 /usr/lib/systemd/system/*.wants|*.requires 里没有指向它的链接"
		r=1
		continue
	fi
	for l in $links; do
		if [ "$(readlink "$l")" != "../$n" ]; then
			bad 12 "$l 应指向 ../${n}，实际 $(readlink "$l")"
			r=1
		fi
	done
done
# 访客（4b Task 11，Ruling 5）：清理服务开机启用（上面的链接检查覆盖它），在 system.slice、不用私有 /tmp；
# 访客的 user manager 停下就拉起它；logind 只杀访客的进程
gc=$sysd/mastersos-guest-cleanup.service
if [ ! -L "$sysd/multi-user.target.wants/mastersos-guest-cleanup.service" ] ||
	! grep -qxF 'ExecStart=/usr/bin/mastersos-agent guest-cleanup' "$gc" || ! grep -qxF 'Slice=system.slice' "$gc" ||
	! grep -qxF 'Type=oneshot' "$gc" || grep -qE '^PrivateTmp=' "$gc" || grep -qE '^Before=.*(display-manager|gdm)\.service' "$gc" ||
	! grep -qE '^After=.*mastersos-agent-local\.service' "$gc" || ! grep -qxF 'Restart=on-failure' "$gc" || ! grep -qxF 'RestartSec=30s' "$gc"; then
	bad 12 "$gc 应开机启用（multi-user.target.wants 链接）、Type=oneshot、ExecStart=…guest-cleanup、Slice=system.slice、排在 mastersos-agent-local 之后、不挡 GDM（没有 Before=display-manager）、Restart=on-failure 与 RestartSec=30s、不设 PrivateTmp="
	r=1
fi
# 临时账号（计划 9 Task 3）：模板单元与访客的清理服务同样在 system.slice、不用私有 /tmp、不挡 GDM、失败 30 秒后再来；
# 按实例名（账号名）清理；没有 [Install]，不开机启用（开机时由 agent 对每个 kiosk 账号拉起）
ec=$sysd/mastersos-ephemeral-cleanup@.service
if [ ! -f "$ec" ] ||
	! grep -qxF 'ExecStart=/usr/bin/mastersos-agent ephemeral-cleanup %i' "$ec" || ! grep -qxF 'Slice=system.slice' "$ec" ||
	! grep -qxF 'Type=oneshot' "$ec" || grep -qE '^PrivateTmp=' "$ec" || grep -qE '^Before=.*(display-manager|gdm)\.service' "$ec" ||
	! grep -qE '^After=.*mastersos-agent-local\.service' "$ec" || ! grep -qxF 'Restart=on-failure' "$ec" || ! grep -qxF 'RestartSec=30s' "$ec" ||
	grep -qE '^\[Install\]' "$ec" || [ -n "$(find "$sysd" -name 'mastersos-ephemeral-cleanup@*' -type l)" ]; then
	bad 12 "$ec 应有、Type=oneshot、ExecStart=…ephemeral-cleanup %i、Slice=system.slice、排在 mastersos-agent-local 之后、不挡 GDM、Restart=on-failure 与 RestartSec=30s、不设 PrivateTmp=、没有 [Install] 也没有启用链接"
	r=1
fi
gd=$sysd/user@1999.service.d/50-mastersos-guest.conf
if ! grep -qxF 'OnSuccess=mastersos-guest-cleanup.service' "$gd" 2>/dev/null ||
	! grep -qxF 'OnFailure=mastersos-guest-cleanup.service' "$gd"; then
	bad 12 "$gd 应在访客的 user manager 停下时（OnSuccess= 与 OnFailure=）拉起 mastersos-guest-cleanup.service"
	r=1
fi
# 更新记录（4b Task 12 复审 F3）：/etc/.updated 要在 sysext 合并之前记，否则更新上来的机器不再跑 sysusers（mastersos-localadmin
# 组）与 hwdb；上游的 systemd-update-done 停掉；旧镜像留下的假记录在 sysusers 之前删掉
ud=$sysd/mastersos-update-done.service
us=$sysd/mastersos-update-stamp.service
udd=$sysd/systemd-update-done.service.d/50-mastersos.conf
if ! grep -qE '^Before=.*systemd-sysext\.service' "$ud" 2>/dev/null || grep -qE '^ConditionNeedsUpdate=' "$ud" ||
	! grep -qE '^After=.*systemd-sysusers\.service' "$ud" || ! grep -qE '^After=.*systemd-hwdb-update\.service' "$ud" ||
	! grep -qE '^Before=.*systemd-sysusers\.service' "$us" 2>/dev/null ||
	! grep -qxF 'ConditionNeedsUpdate=' "$udd" 2>/dev/null || ! grep -qE '^ConditionPathExists=/usr/lib/mastersos/' "$udd" ||
	[ -e "$rel/mkosi.extra/usr/lib/mastersos/run-upstream-update-done" ] ||
	[ ! -L "$sysd/sysinit.target.wants/mastersos-update-done.service" ] || [ ! -L "$sysd/sysinit.target.wants/mastersos-update-stamp.service" ] ||
	! grep -qxF 'echo "g mastersos-localadmin -"' <(sed 's/^[[:space:]]*//' "$rel/mkosi.finalize"); then
	bad 12 "mastersos-update-done 应在 sysusers、hwdb 之后、systemd-sysext 之前无条件地跑（不用 ConditionNeedsUpdate=，/usr 是 overlay 时不记）systemd-update-done；mastersos-update-stamp 在 sysusers 之前删掉比 /usr 新的 /etc/.updated；上游 systemd-update-done 由 drop-in 停掉；两者由 sysinit.target.wants 启用；finalize 写 g mastersos-localadmin -"
	r=1
fi
# 复审 N1、N2：判断在 /usr/lib/mastersos/update-done（tests/update-done-test.sh 测），/usr 顶层的类型用 stat -f（findmnt <路径>
# 会打出叠着的两层）；两个单元不得排在 sysext 合并之后的任何东西后面（否则成环，或在合并之后才记）；mkosi 不得固定
# 源码时间（erofs 的 /usr 的 mtime 必须随每次构建变新，否则更新后 sysusers 永远不跑）；finalize 对新的 ConditionNeedsUpdate
# 单元把关。「开机日志里没有 ordering cycle」要跑起来的系统，不在这里查
udsh=$rel/mkosi.extra/usr/lib/mastersos/update-done
late='systemd-sysext|systemd-tmpfiles-setup|ldconfig|systemd-journal-catalog-update|systemd-update-done|sysinit\.target|basic\.target'
if ! grep -qxF 'ExecStart=/usr/lib/mastersos/update-done record' "$ud" 2>/dev/null ||
	! grep -qxF 'ExecStart=/usr/lib/mastersos/update-done drop-stale' "$us" 2>/dev/null ||
	! grep -qF 'stat -f -c %T /usr' "$udsh" 2>/dev/null || ! grep -qF '= overlayfs ]' "$udsh" || grep -qE '^[^#]*findmnt' "$udsh" ||
	grep -hE '^(After|Requires|Wants|BindsTo|Requisite)=' "$ud" "$us" | grep -qE "(^|[= ])($late)(\.service)?( |$)" ||
	! grep -qE '^Before=.*mastersos-update-done\.service' "$us" || ! grep -qE '^Before=.*systemd-hwdb-update\.service' "$us" ||
	grep -rqsE '^[^#]*(SourceDateEpoch=|SOURCE_DATE_EPOCH)' "$rel/mkosi.conf" "$rel"/mkosi.conf.d "$rel"/mkosi.profiles "$rel/build.sh" ||
	! grep -qF 'needs_update_ok=' "$rel/mkosi.finalize"; then
	bad 12 "update-done：单元调 /usr/lib/mastersos/update-done record|drop-stale；脚本用 stat -f 看 /usr 顶层是不是 overlayfs、不用 findmnt；两个单元不排在 sysext 合并之后的单元后面；mastersos-update-stamp 在 hwdb-update 与 mastersos-update-done 之前；mkosi 不固定 SourceDateEpoch；finalize 对 ConditionNeedsUpdate 单元把关"
	r=1
fi
# 管理员组的成员由 agent 管（复审 F6）：sysusers 的 m 行会在它跑的时候把人加回 sudo/admin/mastersos-localadmin。finalize 拒绝构建
# 出这样的镜像；仓库里的 sysusers.d 也不许有
if ! grep -qF 'sysusers 的 m 行把人加进管理员组' "$rel/mkosi.finalize" ||
	grep -rhsE '^m[[:space:]]+[^[:space:]]+[[:space:]]+(sudo|admin|mastersos-localadmin)([[:space:]]|$)' "$rel"/mkosi.extra/usr/lib/sysusers.d "$rel"/mkosi.profiles 2>/dev/null | grep -q .; then
	bad 12 "mkosi.finalize 应拒绝把成员加进 sudo/admin/mastersos-localadmin 的 sysusers m 行，仓库里也不许有这样的行"
	r=1
fi
gl=$rel/mkosi.extra/usr/lib/systemd/logind.conf.d/50-mastersos-guest.conf
if ! grep -qxF 'KillUserProcesses=yes' "$gl" 2>/dev/null || ! grep -qxF 'KillOnlyUsers=guest' "$gl" || ! grep -qxF 'RemoveIPC=yes' "$gl"; then
	bad 12 "$gl 应是 KillUserProcesses=yes、KillOnlyUsers=guest（只杀访客的进程）与 RemoveIPC=yes"
	r=1
fi
# 访客留给下一位访客的东西（复审 I1、I2、I3、M2）：journal 不按 uid 分文件；polkit 拒绝访客的 linger 与改自己的名字、
# 头像、口令；cron/at 拒绝访客，且镜像不装它们（装了要重新想这件事）
jd=$rel/mkosi.extra/usr/lib/systemd/journald.conf.d/50-mastersos.conf
if ! grep -qxF 'SplitMode=none' "$jd" 2>/dev/null; then
	bad 12 "$jd 应设 SplitMode=none（不然每位访客都读得到上一位访客的 user-1999.journal）"
	r=1
fi
pr=$rel/mkosi.extra/usr/share/polkit-1/rules.d/49-mastersos-guest.rules
for a in org.freedesktop.login1.set-self-linger org.freedesktop.login1.set-user-linger \
	org.freedesktop.accounts.change-own-user-data org.freedesktop.accounts.change-own-password; do
	if ! grep -qF "\"$a\"" "$pr" 2>/dev/null || ! grep -qF 'subject.user !== "guest"' "$pr" || ! grep -qF 'polkit.Result.NO' "$pr"; then
		bad 12 "$pr 应对 guest 拒绝 $a"
		r=1
	fi
done
for f in cron.deny at.deny; do
	if ! grep -qx 'guest' "$rel/mkosi.extra/etc/$f" 2>/dev/null; then
		bad 12 "mkosi.extra/etc/$f 应有一行 guest"
		r=1
	fi
done
if grep -qE '^[[:space:]]+(cron|cronie|at|anacron|systemd-cron|bcron)[[:space:]]*$' "$rel/mkosi.conf" "$rel"/mkosi.profiles/*.conf; then
	bad 12 "Packages 里有 cron/at 类的包：访客的定时任务会跑在 user-1999.slice 之外、留给下一位访客（复审 T11 M2），先想清楚再加"
	r=1
fi
[ "$r" = 0 ] && ok 12 "mastersos 单元都由 /usr/lib 的 wants/requires 链接启用；访客的清理服务、user@1999 的 drop-in 与 logind 配置对；/etc/.updated 在 sysext 合并之前记、sysusers 不往管理员组加人"

# 13. TPM 的接线（Task 3）：这几处改坏了，镜像照样构建得出来，坏处要到装机或换 db 时才显出来
r=0
sysd=$rel/mkosi.extra/usr/lib/systemd/system
initrd_sysd=$rel/mkosi.initrd.conf/mkosi.extra/usr/lib/systemd/system
mp=$sysd/systemd-pcrlock-make-policy.service.d/50-mastersos.conf
if ! grep -qE '^ExecStart=$' "$mp" 2>/dev/null ||
	[ "$(grep -E '^ExecStart=.*make-policy' "$mp" | grep -oE -- '--pcr=[^[:space:]]*' | tr '\n' ' ')" != "--pcr=7 " ]; then
	bad 13 "$mp 应先清空 ExecStart=，再以 make-policy … --pcr=7（只锁 PCR 7）运行"
	r=1
fi
cs=$initrd_sysd/systemd-cryptsetup@root.service.d/50-mastersos.conf
line=$(grep -E '^ExecStart=/usr/bin/systemd-cryptsetup attach ' "$cs" 2>/dev/null || true)
want="ExecStart=/usr/bin/systemd-cryptsetup attach 'root' '/dev/disk/by-designator/root-luks' '' 'tpm2-device=auto,tpm2-measure-pcr=yes,tpm2-measure-keyslot-nvpcr=cryptsetup,timeout=300'"
if [ "$line" != "$want" ]; then
	bad 13 "$cs 的 ExecStart 应恰好是 gpt-auto 生成的前四段加 timeout=300（不试空口令，Ruling 17）：$want"
	r=1
fi
dt=$initrd_sysd/'dev-disk-by\x2ddesignator-root.device.d'/50-mastersos.conf
if ! grep -qxE 'JobRunningTimeoutSec=3[0-9]{2}' "$dt" 2>/dev/null ||
	[ "$(sed -n 's/^JobRunningTimeoutSec=//p' "$dt")" -le 300 ]; then
	bad 13 "$dt 应把根设备的等待放宽到比口令提示的 300 秒长（否则 90 秒后就重启）"
	r=1
fi
# 根设备与加密根分区的等待都排在恢复出厂的确认之后（Task 5 复审 I1）：否则 330 秒在问恢复密钥时就在走
for d in "$dt" "$initrd_sysd/"'dev-disk-by\x2ddesignator-root\x2dluks.device.d'/50-mastersos-factory-reset.conf; do
	if ! grep -qx 'After=mastersos-factory-reset-confirm.service' "$d" 2>/dev/null; then
		bad 13 "$d 应有 After=mastersos-factory-reset-confirm.service（问恢复密钥时设备等待不能计时）"
		r=1
	fi
done
# TPM 2.0 是前提（4b Task 3，Ruling 17）：没有可用 TPM 的降级路径不许回来。查镜像树（lab/results/ 是验收记录，
# 本脚本自己列着这些词，都不算）与 core
pat='try-empty-password|notpm|--unlock-key-file=/dev/null|--wipe-slot=password'
nt=$(git ls-files -co --exclude-standard -- "$rel" "$core" |
	grep -vE "^$rel/lab/results/|^$rel/tests/check-tree\.sh$" |
	while IFS= read -r f; do [ -f "$f" ] && printf '%s\0' "$f"; done |
	xargs -0 grep -nIE -- "$pat" 2>/dev/null || true)
if [ -n "$nt" ]; then
	bad 13 "没有 TPM 的降级路径（空口令、notpm）不许回来："
	printf '%s\n' "$nt" | sed 's/^/    /' >&2
	r=1
fi
tp=$rel/mkosi.initrd.conf/mkosi.extra/usr/lib/mastersos/tpm-probe
if [ ! -x "$tp" ] || [ "$(git ls-files -s -- "$tp" | cut -c1-6)" = 100644 ]; then
	bad 13 "initrd 树里应有可执行的 usr/lib/mastersos/tpm-probe（恢复出厂的确认用它）"
	r=1
fi
# 用户态不再用 TPM 解锁（4b Task 4，Ruling 28）：进镜像的树（mkosi.extra、mkosi.initrd.conf）与 core 里
# 没有 --unlock-tpm2-device。docs/ 与 lab/results/ 里 4a 的记录照旧提到它，不查。
ut=$(git ls-files -co --exclude-standard -- "$rel" "$core" |
	grep -vE "^$rel/(lab/results|docs)/|^$rel/tests/check-tree\.sh$" |
	while IFS= read -r f; do [ -f "$f" ] && printf '%s\0' "$f"; done |
	xargs -0 grep -nIE -- '--unlock-tpm2-device' 2>/dev/null || true)
if [ -n "$ut" ]; then
	bad 13 "用户态不再用 TPM 解锁，不许有 --unlock-tpm2-device："
	printf '%s\n' "$ut" | sed 's/^/    /' >&2
	r=1
fi
# 首次开机的临时钥匙单元（4b Task 4）：两个脚本可执行、repart drop-in 用 --key-file 指到临时钥匙。
for s in luks-bootstrap-key luks-bootstrap-persist; do
	bs=$rel/mkosi.initrd.conf/mkosi.extra/usr/lib/mastersos/$s
	if [ ! -x "$bs" ] || [ "$(git ls-files -s -- "$bs" | cut -c1-6)" = 100644 ]; then
		bad 13 "initrd 树里应有可执行的 usr/lib/mastersos/$s"
		r=1
	fi
done
bk=$initrd_sysd/systemd-repart.service.d/50-mastersos-bootstrap-key.conf
if ! grep -qx 'ExecStart=systemd-repart --dry-run=no --key-file=/run/mastersos/luks-bootstrap-key' "$bk" 2>/dev/null ||
	! grep -qx 'Requires=mastersos-luks-bootstrap-key.service' "$bk" 2>/dev/null ||
	! grep -qx 'After=mastersos-luks-bootstrap-key.service' "$bk" 2>/dev/null; then
	bad 13 "$bk 应 Requires= 与 After= mastersos-luks-bootstrap-key.service（只有 Requires= 时 repart 会与它并行起），并把 systemd-repart 的 ExecStart 末尾加 --key-file=/run/mastersos/luks-bootstrap-key"
	r=1
fi
# 记「之前」的 UUID 要等盘认出来（复审 I4）：临时钥匙单元排在 initrd-usr-fs.target 之后、repart 之前
ks=$initrd_sysd/mastersos-luks-bootstrap-key.service
if ! grep -qx 'After=initrd-usr-fs.target' "$ks" 2>/dev/null || ! grep -qx 'Before=systemd-repart.service' "$ks" 2>/dev/null; then
	bad 13 "$ks 应 After=initrd-usr-fs.target、Before=systemd-repart.service（盘没认出来时读不到之前的 UUID，平常开机也会去做 PBKDF）"
	r=1
fi
# UKI 的 PCR 签名把关（复审 I1）：build.sh 在写 build-info 之前、make-installer.sh 在做安装器 UKI 之前调 keyset_check_uki
first_line() { { grep -nE -- "$2" "$1" || true; } | { grep -vE '^[0-9]+:[[:space:]]*#' || true; } | head -n 1 | cut -d: -f1; }
cb=$(first_line "$rel/build.sh" '^keyset_check_uki ')
# shellcheck disable=SC2016 # 字面的 $out，是要找的源码文本
wb=$(first_line "$rel/build.sh" '>"\$out/build-info\.txt"')
cm=$(first_line "$rel/make-installer.sh" '^keyset_check_uki ')
um=$(first_line "$rel/make-installer.sh" '^ukify build')
# shellcheck disable=SC2016 # 字面的 $f，是要找的源码文本
if [ -z "$cb" ] || [ -z "$wb" ] || [ "$cb" -ge "$wb" ] || [ -z "$cm" ] || [ -z "$um" ] || [ "$cm" -ge "$um" ] ||
	! grep -q '\.pcr(sig|pkey)' "$rel/make-installer.sh" || ! grep -q '"$f.rejected"' "$rel/build.sh"; then
	bad 13 "build.sh 要在写 build-info 之前、make-installer.sh 要在做安装器 UKI 之前调 keyset_check_uki（只签 enter-initrd），make-installer.sh 还要核对安装器 UKI 不带 .pcrsig/.pcrpkey；build.sh 闸门不过时要把产物改名成 *.rejected"
	r=1
fi
rp=$rel/mkosi.extra/usr/lib/repart.d/40-root.conf
if [ "$(grep -c '^Encrypt=' "$rp")" != 1 ] ||
	[ "$(grep -cxF 'Encrypt=key-file+tpm2' "$rp")" != 1 ]; then
	bad 13 "40-root.conf 应恰好一行 Encrypt=key-file+tpm2（TPM 槽 + 首次开机的临时钥匙槽，4b Task 4）"
	r=1
fi
# 退役的 PCR 公钥（4b Task 4，Ruling 28）：keys/retired 与 keys/lab/retired 各有一份、与当前的公钥不同。
for pair in "keys keys/retired" "keys/lab keys/lab/retired"; do
	read -r kd rd <<<"$pair"
	cur=$rel/$kd/tpm2-pcr-public-key.pem
	retd=$rel/$rd/tpm2-pcr-public-key-4phase.pem
	if [ ! -s "$retd" ]; then
		bad 13 "$retd 应有一份退役的 PCR 公钥（旧钥匙签的四阶段 UKI 永远有效但发不出去）"
		r=1
	elif cmp -s "$retd" "$cur"; then
		bad 13 "$retd 与当前的 $kd/tpm2-pcr-public-key.pem 相同：退役的应是换掉之前那把"
		r=1
	fi
done
frd=$initrd_sysd/systemd-repart.service.d/50-mastersos-factory-reset-confirm.conf
if ! grep -qx 'Requires=mastersos-factory-reset-confirm.service' "$frd" 2>/dev/null ||
	! grep -qx 'ConditionKernelCommandLine=systemd.factory_reset' "$initrd_sysd/mastersos-factory-reset-confirm.service" 2>/dev/null; then
	bad 13 "恢复出厂要先确认：$frd 应 Requires= mastersos-factory-reset-confirm.service（条件只写键名 systemd.factory_reset，=yes/=true/裸键名都要问）"
	r=1
fi
if [ "$(grep -cvE '^[[:space:]]*(#|$)' "$rel/systemd-version.verified" 2>/dev/null)" != 1 ]; then
	bad 13 "$rel/systemd-version.verified 应恰好一行 systemd 版本（initrd drop-in 照抄的 ExecStart 核对过的版本）"
	r=1
fi
fr=$rel/uki-profiles/factory-reset.conf
if ! grep -qE '^UnifiedKernelImageProfiles=uki-profiles/factory-reset\.conf$' "$rel/mkosi.conf" ||
	! grep -qE '^Cmdline=systemd\.factory_reset=1$' "$fr" 2>/dev/null; then
	bad 13 "mkosi.conf 应以 UnifiedKernelImageProfiles= 带上 ${fr}（Cmdline=systemd.factory_reset=1）"
	r=1
fi
[ "$r" = 0 ] && ok 13 "pcrlock 只锁 PCR 7、根分区解锁选项与等待、没有无 TPM 的降级路径与 --unlock-tpm2-device、tpm-probe、首次开机临时钥匙单元、Encrypt=key-file+tpm2、退役 PCR 公钥、恢复出厂 profile 与确认、systemd 版本都接上了"

# 14. Secure Boot 与引导程序更新（Task 4）：MOK 证书是 DER 的 X.509；更新单元只在被标好的开机之后跑
#     （Requisite=，不是 Requires=），由 /usr/lib 的链接启用；finalize 把签好的三个文件放进 /usr/lib/mastersos/esp
r=0
der=$rel/keys/mastersos-mok.der
# 真的按 X.509 解析（DER 的私钥开头也是 0x30，第 1 条只查 PEM 私钥的文字头）
if ! openssl x509 -inform DER -noout -in "$der" 2>/dev/null; then
	bad 14 "$der 应是 DER 编码的 X.509 证书（openssl x509 -outform DER），只放公钥证书"
	r=1
fi
bu=$rel/mkosi.extra/usr/lib/systemd/system/mastersos-bootloader-update.service
for l in 'Requisite=boot-complete.target' 'ConditionPathExists=/usr/lib/mastersos/esp/BOOTX64.EFI' 'ExecStart=/usr/lib/mastersos/bootloader-update'; do
	if ! grep -qxF -- "$l" "$bu" 2>/dev/null; then
		bad 14 "$bu 应有一行 $l"
		r=1
	fi
done
if ! grep -qE '^After=.*\bboot-complete\.target\b' "$bu" 2>/dev/null; then
	bad 14 "$bu 应排在 boot-complete.target 之后（After=）"
	r=1
fi
if grep -qE '^(Requires|Wants|BindsTo)=.*boot-complete' "$bu" 2>/dev/null; then
	bad 14 "$bu 不能 Requires/Wants/BindsTo boot-complete.target：会在没被标好的开机上重新拉起已经失败的健康检查（用 Requisite=）"
	r=1
fi
if [ "$(readlink "$rel/mkosi.extra/usr/lib/systemd/system/multi-user.target.wants/mastersos-bootloader-update.service" 2>/dev/null)" != ../mastersos-bootloader-update.service ]; then
	bad 14 "mastersos-bootloader-update.service 没有由 /usr/lib 的 multi-user.target.wants 链接启用"
	r=1
fi
for n in BOOTX64.EFI grubx64.efi mmx64.efi; do
	if ! grep -qF -- ":$n" "$rel/mkosi.finalize" || ! grep -qE "^NAMES=\(.*\b${n//./\\.}\b" "$rel/mkosi.extra/usr/lib/mastersos/bootloader-update"; then
		bad 14 "$n 应由 mkosi.finalize 放进 /usr/lib/mastersos/esp/、由 bootloader-update 换到 ESP"
		r=1
	fi
done
[ "$r" = 0 ] && ok 14 "MOK 证书是 DER、引导程序更新只在被标好的开机之后跑、三个文件都接上了"

# 15. lab 的钥匙（4b Task 1，Ruling 19）：keys/lab/ 有三份公钥、格式同第 11/14 条，而且与 keys/ 的同名文件都不同
#     （同一把钥匙就等于没分开）；进镜像的树里没有 keys/lab；四个用钥匙的脚本不自己拼钥匙路径，只经 keyset.sh
r=0
lab=$rel/keys/lab
lpgp=$lab/import-pubring.pgp lpem=$lab/tpm2-pcr-public-key.pem lder=$lab/mastersos-mok.der
if [ ! -s "$lpgp" ]; then
	bad 15 "缺少 $lpgp"
	r=1
else
	b=$(head -c1 "$lpgp" | od -An -tx1 | tr -d ' \n')
	case "$b" in 98 | 99 | c6) ;; *)
		bad 15 "$lpgp 应是二进制 OpenPGP 公钥（gpg --export，不要 --armor），首字节是 0x$b"
		r=1
		;;
	esac
fi
if ! head -1 "$lpem" 2>/dev/null | grep -qx -- '-----BEGIN PUBLIC KEY-----'; then
	bad 15 "$lpem 应是 PEM 公钥（openssl x509 -pubkey -noout）"
	r=1
fi
if ! openssl x509 -inform DER -noout -in "$lder" 2>/dev/null; then
	bad 15 "$lder 应是 DER 编码的 X.509 证书（openssl x509 -outform DER）"
	r=1
fi
if [ "$r" = 0 ]; then
	sha() { sha256sum <"$1" | cut -d' ' -f1; }
	pubder() { openssl pkey -pubin -in "$1" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1; }
	gpgfpr() { gpg --batch --no-default-keyring --show-keys --with-colons "$1" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }'; }
	if [ "$(sha "$lder")" = "$(sha "$rel/keys/mastersos-mok.der")" ]; then
		bad 15 "$lder 与 keys/mastersos-mok.der 相同：lab 与正式用的是同一把 Secure Boot 钥匙"
		r=1
	fi
	if [ "$(pubder "$lpem")" = "$(pubder "$rel/keys/tpm2-pcr-public-key.pem")" ]; then
		bad 15 "$lpem 与 keys/tpm2-pcr-public-key.pem 是同一把 PCR 公钥"
		r=1
	fi
	lf=$(gpgfpr "$lpgp") rf=$(gpgfpr "$rel/keys/import-pubring.pgp")
	if [ -z "$lf" ] || [ -z "$rf" ] || [ "$lf" = "$rf" ]; then
		bad 15 "$lpgp 与 keys/import-pubring.pgp 的主钥指纹相同或读不出（lab ${lf:-?}，正式 ${rf:-?}）"
		r=1
	fi
fi
# 进镜像的树里不许有 keys/lab（文件，或非注释行里的引用）
hits=$( (git ls-files -co --exclude-standard -- "$rel/mkosi.extra" "$rel/mkosi.conf" "$rel/mkosi.repart" "$rel/mkosi.initrd.conf" | grep -F 'keys/lab' || true
	grep -rnE -- 'keys/lab' "$rel/mkosi.extra" "$rel/mkosi.conf" "$rel/mkosi.repart" "$rel/mkosi.initrd.conf" 2>/dev/null |
		grep -vE '^[^:]*:[0-9]+:[[:space:]]*#' || true) | sed '/^$/d')
if [ -n "$hits" ]; then
	bad 15 "进镜像的树里出现了 keys/lab："
	printf '%s\n' "$hits" | sed 's/^/    /' >&2
	r=1
fi
# 钥匙路径只由 keyset.sh 拼：四个脚本的非注释行里
#   - 不提 MASTERSOS_KEYS / mastersos-keys（默认目录只在 keyset.sh）；
#   - 不自己拼仓库公钥的路径（…/keys/[lab/]{mastersos-mok,tpm2-pcr-public-key,import-pubring}…、…/keys/[lab/]{db,pcr}…）；
#   - 私钥文件 db./pcr.{key,crt} 只经 $priv（= keyset_priv 的结果）取，别的变量拼出来的一律算
kp='MASTERSOS_KEYS|mastersos-keys|/keys/(lab/)?(db|pcr|mastersos-mok|tpm2-pcr-public-key|import-pubring)'
for f in build.sh make-installer.sh channel-common.sh mkosi.finalize; do
	nc=$(grep -nvE '^[[:space:]]*#' "$rel/$f" | grep -vE '^[0-9]+:[[:space:]]*#' || true)
	hits=$(grep -E -- "$kp" <<<"$nc" || true)
	# db./pcr. 私钥文件：去掉所有 $priv/ 与 ${priv}/ 前缀的出现之后，还剩下的就是自己拼的
	hits2=$(sed -E 's/\$\{?priv\}?\/(db|pcr)\.(key|crt)//g' <<<"$nc" | grep -E -- '/(db|pcr)\.(key|crt)' || true)
	hits=$(printf '%s\n%s\n' "$hits" "$hits2" | sed '/^$/d' | sort -un)
	if [ -n "$hits" ]; then
		bad 15 "$f 自己拼了钥匙路径（应经 keyset.sh 的 keyset_priv / keyset_pub）："
		printf '%s\n' "$hits" | sed 's/^/    /' >&2
		r=1
	fi
	if ! grep -qE '^[[:space:]]*\.[[:space:]].*keyset\.sh' "$rel/$f"; then
		bad 15 "$f 没有 source keyset.sh"
		r=1
	fi
done
[ "$r" = 0 ] && ok 15 "keys/lab/ 三份公钥格式对、与正式的都不同，不进镜像；钥匙路径只由 keyset.sh 拼"


# 16. 只认公网信任的证书（Ruling 3）：进正式镜像的树（mkosi.extra、mkosi.initrd.conf、mkosi.repart、mkosi.conf 的
#     ExtraTrees=）里没有 PEM 证书、没有 ca-certificates 或 /etc/ssl 下的文件；试验 CA 只在 lab profile 的附加树里
r=0
cert='-----BEGIN ''CERTIFICATE-----' # 拆开写，免得本脚本自己命中
rel_trees=("$rel/mkosi.extra" "$rel/mkosi.initrd.conf" "$rel/mkosi.repart")
hits=$( (git ls-files -co --exclude-standard -- "${rel_trees[@]}" | grep -E '/(ca-certificates|ssl)/|\.(crt|pem|cer)$' || true
	grep -rlF -- "$cert" "${rel_trees[@]}" 2>/dev/null || true) | sed '/^$/d' | sort -u)
if [ -n "$hits" ]; then
	bad 16 "进正式镜像的树里有证书或 CA 目录（正式镜像只认公网信任的证书，试验 CA 只放 mkosi.profiles/lab.extra）："
	printf '%s\n' "$hits" | sed 's/^/    /' >&2
	r=1
fi
# mkosi.conf 主配置不另加附加树（附加树里的东西就没人查了）；lab 的附加树只在 lab.conf
et=$(awk '/^[[:space:]]*#/ { next } /^[A-Za-z]+=/ { key = $0; sub(/=.*/, "", key) } key == "ExtraTrees" { print }' "$rel/mkosi.conf")
if [ -n "$et" ]; then
	bad 16 "$rel/mkosi.conf 不应有 ExtraTrees=（正式镜像的附加文件只放 mkosi.extra）：$et"
	r=1
fi
lab_ca=$(git ls-files -co --exclude-standard -- "$rel/mkosi.profiles/lab.extra" | grep -E '/usr/local/share/ca-certificates/[^/]+\.crt$' || true)
if [ "$(printf '%s\n' "$lab_ca" | sed '/^$/d' | wc -l | tr -d ' ')" != 1 ] ||
	! openssl x509 -noout -in "$lab_ca" 2>/dev/null; then
	bad 16 "lab 的附加树里应恰好有一份试验 CA（usr/local/share/ca-certificates/*.crt，PEM 的 X.509）：${lab_ca:-<无>}"
	r=1
elif [ "$(openssl x509 -noout -ext basicConstraints -in "$lab_ca" 2>/dev/null | grep -c 'CA:TRUE')" != 1 ]; then
	bad 16 "$lab_ca 不是 CA 证书"
	r=1
fi
# 收进信任库的只有那个目录：postinst 的 update-ca-certificates 只在它有文件时跑，别处不往信任库加东西
if grep -nE -- '/etc/ssl|ca-certificates\.conf|/usr/share/ca-certificates' "$rel/mkosi.postinst.chroot" "$rel/mkosi.finalize" |
	grep -vE '^[^:]*:[0-9]+:[[:space:]]*#' >&2; then
	bad 16 "postinst / finalize 不应直接改信任库（只由 update-ca-certificates 收 /usr/local/share/ca-certificates）"
	r=1
fi
# build.sh 的附加树（agent 等二进制，正式构建也用）只放 usr/bin；考试扩展的附加树 $kext_tree 只放 kiosk-ext.json 与宿主清单
# （第 34 条核对）；构建完再核对正式镜像里的 /usr/local/share/ca-certificates 是空的
# shellcheck disable=SC2016 # 字面的 "$extra" / "$lab_local" / "$kext_tree"，是要找的源码文本
if grep -nE -- '--extra-tree=' "$rel/build.sh" | grep -vE '"\$extra"|"\$lab_local"|"\$kext_tree"' >&2 ||
	! grep -qF 'ca-certificates 不是空的' "$rel/build.sh"; then
	bad 16 "build.sh 的 --extra-tree 只许 \$extra（二进制）、考试扩展的 \$kext_tree 与 lab 的 \$lab_local，且构建后要核对正式镜像的 /usr/local/share/ca-certificates 是空的"
	r=1
fi
[ "$r" = 0 ] && ok 16 "正式镜像的树里没有证书与额外的 CA；试验 CA 只在 lab 的附加树里"

# 17. authd 的 OIDC broker 与登录的静态部分（4b Task 8）
r=0
ex=$rel/mkosi.extra
bus=com.ubuntu.authd.Oidc
reg=$ex/usr/lib/mastersos/authd/oidc-broker.conf
svc=$ex/usr/lib/systemd/system/authd-oidc.service
act=$ex/usr/share/dbus-1/system-services/$bus.service
pol=$ex/usr/share/dbus-1/system.d/$bus.conf
for l in "dbus_name = $bus" 'dbus_object = /com/ubuntu/authd/Oidc'; do
	grep -qxF -- "$l" "$reg" 2>/dev/null || {
		bad 17 "${reg} 应有一行「${l}」（上游 snap 的总线名与对象路径）"
		r=1
	}
done
for l in "Name=$bus" 'SystemdService=authd-oidc.service' 'User=root'; do
	grep -qxF -- "$l" "$act" 2>/dev/null || {
		bad 17 "$act 应有一行 $l"
		r=1
	}
done
# 总线策略：只有 root 能拥有名字与调它，默认策略两样都拒绝
if ! python3 - "$pol" "$bus" <<'PY'; then
import sys
import xml.etree.ElementTree as ET
path, bus = sys.argv[1:]
root = ET.parse(path).getroot()
want = {
    ("user", "root"): {("allow", "own"), ("allow", "send_destination")},
    ("context", "default"): {("deny", "own"), ("deny", "send_destination")},
}
got = {}
for p in root.findall("policy"):
    key = next(iter(p.attrib.items()))
    rules = got.setdefault(key, set())
    for r in p:
        for attr, val in r.attrib.items():
            if val != bus:
                sys.exit(f"{path}: {r.tag} {attr}={val} 不是 {bus}")
            rules.add((r.tag, attr))
if got != want:
    sys.exit(f"{path}: 策略应只有 root 能 own/send，默认 deny；实际 {got}")
PY
	bad 17 "$pol 的总线策略不对（见上）"
	r=1
fi
for l in 'Type=dbus' "BusName=$bus" 'ExecStart=/usr/libexec/authd-oidc --config /etc/authd/oidc/broker.conf' \
	'StateDirectory=authd-oidc' 'ConfigurationDirectory=authd/oidc' 'ProtectSystem=strict' 'ProtectHome=yes' \
	'PrivateTmp=yes' 'NoNewPrivileges=yes' 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' \
	'ReadWritePaths=/var/lib/authd-oidc' 'CapabilityBoundingSet=' \
	'ConditionDirectoryNotEmpty=/etc/authd/oidc/broker.conf.d'; do
	grep -qxF -- "$l" "$svc" 2>/dev/null || {
		bad 17 "$svc 应有一行 $l"
		r=1
	}
done
if [ "$(grep -c '^ReadWritePaths=' "$svc" 2>/dev/null)" != 1 ] || grep -q '^\[Install\]' "$svc" 2>/dev/null; then
	bad 17 "$svc 只许一行 ReadWritePaths=（它的状态目录），也不许有 [Install]（由 D-Bus 激活）"
	r=1
fi
# 骨架配置不带身份系统（issuer 由 agent 写进 broker.conf.d），allowed_users = ALL（域名限制在 pam-check）
bc=$ex/etc/authd/oidc/broker.conf
if grep -qE '^[[:space:]]*(issuer|client_id|client_secret)[[:space:]]*=' "$bc" 2>/dev/null ||
	! grep -qxF 'allowed_users = ALL' "$bc" 2>/dev/null; then
	bad 17 "$bc 应是不带 issuer/client_id/client_secret、allowed_users = ALL 的骨架"
	r=1
fi
# 构建脚本：固定 tag 与 40 位 commit、clone 之后核对、不自动下载工具链、按 go.sum 校验
mb=$rel/mkosi.build
# shellcheck disable=SC2016 # 字面的 $got / $COMMIT，是要找的源码文本
if ! grep -qE '^TAG=oidc-[0-9]+\.[0-9]+\.[0-9]+$' "$mb" 2>/dev/null || ! grep -qE '^COMMIT=[0-9a-f]{40}$' "$mb" ||
	! grep -qF '[ "$got" != "$COMMIT" ]' "$mb" || ! grep -qE 'GOTOOLCHAIN=local' "$mb" ||
	! grep -qE 'GOFLAGS=-mod=readonly' "$mb" || ! grep -qxE '[[:space:]]*go mod verify' "$mb" ||
	! grep -qE '^GO_VERSION=1\.[0-9]+\.[0-9]+$' "$mb" || ! grep -qE '^GO_SHA256=[0-9a-f]{64}$' "$mb" ||
	! grep -qF 'sha256sum -c --strict' "$mb" || ! grep -qF 'export PATH=$work/go/bin:$PATH' "$mb" ||
	[ "$(git ls-files -s -- "$mb" 2>/dev/null | cut -c1-6)" = 100644 ]; then
	bad 17 "$mb 应可执行、写死 TAG=oidc-x.y.z 与 40 位 COMMIT 并在 clone 后核对、GOTOOLCHAIN=local、GOFLAGS=-mod=readonly、go mod verify，Go 工具链钉 GO_VERSION 与 64 位 GO_SHA256、sha256sum -c 核对后放在 PATH 最前"
	r=1
fi
# PAM 钩子只在 MASTERSOS_PAM_HOOKS=1 时插；哪个 mkosi 配置把它设成 1，agent 就必须已经有 pam-check 与 pam-session
# shellcheck disable=SC2016 # 字面的 ${MASTERSOS_PAM_HOOKS:-}，是要找的源码文本
if ! grep -qF '"${MASTERSOS_PAM_HOOKS:-}" = 1' "$rel/mkosi.postinst.chroot"; then
	bad 17 "mkosi.postinst.chroot 应只在 MASTERSOS_PAM_HOOKS=1 时调 pam-hooks.sh"
	r=1
fi
# 扫所有能设环境变量的构建输入：mkosi.conf、mkosi.conf.d/、mkosi.profiles/ 的 .conf，以及 build.sh 的 --environment=
pam_inputs=()
for f in "$rel/mkosi.conf" "$rel"/mkosi.conf.d/*.conf "$rel"/mkosi.profiles/*.conf "$rel/build.sh"; do
	[ -f "$f" ] && pam_inputs+=("$f")
done
on=$(grep -lE '(^|[[:space:]=-])MASTERSOS_PAM_HOOKS=("|\$\{)?1' "${pam_inputs[@]}" 2>/dev/null || true)
if [ -n "$on" ]; then
	# 两个子命令各自都要有（字面的子命令名或 clap 的变体名），只有其中一个不算
	for pair in "pam-check PamCheck" "pam-session PamSession"; do
		read -r sub variant <<<"$pair"
		if ! grep -rqF -- "\"$sub\"" "$core/mastersos-agent/src" 2>/dev/null &&
			! grep -rqwF -- "$variant" "$core/mastersos-agent/src" 2>/dev/null; then
			bad 17 "$(echo "$on" | tr '\n' ' ')设了 MASTERSOS_PAM_HOOKS=1，但 mastersos-agent 还没有 $sub 子命令（插了就谁都登录不了）"
			r=1
		fi
	done
fi
# 两个 profile 都插钩子（Task 11）：正式的 mkosi.conf 与 lab 的 profile 各自写明 Environment=MASTERSOS_PAM_HOOKS=1；
# 访客走 gdm-authd，那里的 pam-session 要能拒绝（requisite），不许出现 optional / required 的 pam-session
for f in "$rel/mkosi.conf" "$rel/mkosi.profiles/lab.conf"; do
	if ! grep -qxF 'Environment=MASTERSOS_PAM_HOOKS=1' "$f"; then
		bad 17 "$f 应设 Environment=MASTERSOS_PAM_HOOKS=1（两个 profile 都插 PAM 钩子）"
		r=1
	fi
done
# shellcheck disable=SC2016 # 字面的 $AGENT，是要找的源码文本
# requisite 而不是 required：拒绝之后后面的 pam_systemd 不再跑，被拒的访客不会开出会话、拉起 user manager（VM 上见过）
if grep -qE '(optional|required)[[:space:]]+pam_exec\.so.*pam-session' "$rel/pam-hooks.sh" ||
	! grep -qF 'session requisite pam_exec.so quiet stdout $AGENT pam-session' "$rel/pam-hooks.sh"; then
	bad 17 "pam-hooks.sh 的 pam-session 应是 requisite：访客走 gdm-authd，tmpfs 没备好时要能拒绝，而且拒绝之后不再跑 pam_systemd"
	r=1
fi
# SSO 登录靠 pam_gnome_keyring 给 gdm-authd 的 setcred 一个成功（Task 8）：包要在，postinst 也要核对模块文件
if ! grep -qE '^[[:space:]]+libpam-gnome-keyring[[:space:]]*$' "$rel/mkosi.conf" ||
	! grep -qF 'pam_gnome_keyring.so' "$rel/mkosi.postinst.chroot"; then
	bad 17 "mkosi.conf 的 Packages= 要有 libpam-gnome-keyring，postinst 要核对 pam_gnome_keyring.so 在镜像里（没有它 SSO 用户进不了桌面）"
	r=1
fi
# dconf profile、XDG_DATA_DIRS 与用户读得到的目录
[ "$(cat "$ex/usr/share/dconf/profile/user" 2>/dev/null)" = "$(printf 'user-db:user\nsystem-db:mastersos')" ] || {
	bad 17 "$ex/usr/share/dconf/profile/user 应恰好是 user-db:user + system-db:mastersos"
	r=1
}
[ "$(cat "$ex/usr/share/dconf/profile/gdm" 2>/dev/null)" = "$(printf 'user-db:user\nsystem-db:gdm\nfile-db:/usr/share/gdm/greeter-dconf-defaults')" ] || {
	bad 17 "$ex/usr/share/dconf/profile/gdm 应恰好是 user-db:user + system-db:gdm + file-db:/usr/share/gdm/greeter-dconf-defaults"
	r=1
}
# shellcheck disable=SC2016 # 字面的 ${XDG_DATA_DIRS…}，是要找的文件内容
grep -qxF 'XDG_DATA_DIRS=/var/lib/mastersos-public/xdg:${XDG_DATA_DIRS:-/usr/local/share:/usr/share}' "$ex/usr/lib/environment.d/40-mastersos.conf" 2>/dev/null || {
	bad 17 "$ex/usr/lib/environment.d/40-mastersos.conf 应把 /var/lib/mastersos-public/xdg 排在 XDG_DATA_DIRS 最前面"
	r=1
}
tf=$ex/usr/lib/tmpfiles.d/mastersos.conf
for l in 'd /var/lib/mastersos-public 0755 root root -' 'd /var/lib/mastersos-public/xdg 0755 root root -' \
	'd /var/lib/mastersos-public/login-scripts 0755 root root -' 'd /var/lib/mastersos-system 0700 root root -'; do
	grep -qxF -- "$l" "$tf" 2>/dev/null || {
		bad 17 "$tf 应有一行 $l"
		r=1
	}
done
# AppArmor 按真实路径判：factory 的 /etc 要算作 @{etc_ro}，否则 unix-chkpwd 读不了 nsswitch.conf、GDM 的登录界面起不来
grep -qxF '@{etc_ro}+=/usr/share/factory/etc/' "$ex/etc/apparmor.d/tunables/etc.d/mastersos" 2>/dev/null || {
	bad 17 "$ex/etc/apparmor.d/tunables/etc.d/mastersos 应有一行 @{etc_ro}+=/usr/share/factory/etc/"
	r=1
}
[ "$r" = 0 ] && ok 17 "AppArmor 认 factory 的 /etc、authd 的 OIDC broker（总线名、策略、加固、骨架配置、固定 tag）、PAM 钩子的开关、dconf profile、XDG_DATA_DIRS 与 mastersos-public"

# 18. 口令段按用户名分流、authd 不查终端（4b Task 9）：postinst 经 pam-password.sh 改 profile（pam-auth-update 之前）、
#     插分流并逐行核对（之后）、末尾再核对一次；4a 的「common-password 里没有 authd」那条核对已被取代，不许留着与之矛盾
r=0
pi=$rel/mkosi.postinst.chroot
pp=$rel/pam-password.sh
ln_of() { grep -nF -- "$2" "$1" 2>/dev/null | head -n 1 | cut -d: -f1; }
l_prof=$(ln_of "$pi" 'pam-password.sh" profile /usr/share/pam-configs/authd')
l_upd=$(ln_of "$pi" 'pam-auth-update --package')
l_apply=$(ln_of "$pi" 'pam-password.sh" apply /etc/pam.d')
l_check=$(grep -nF 'pam-password.sh" check /etc/pam.d' "$pi" 2>/dev/null | tail -n 1 | cut -d: -f1)
l_hooks=$(grep -nF 'mastersos-agent pam-' "$pi" 2>/dev/null | tail -n 1 | cut -d: -f1)
if [ -z "$l_prof" ] || [ -z "$l_upd" ] || [ -z "$l_apply" ] || [ -z "$l_check" ] || [ -z "$l_hooks" ] ||
	[ "$l_prof" -ge "$l_upd" ] || [ "$l_upd" -ge "$l_apply" ] || [ "$l_check" -le "$l_hooks" ]; then
	bad 18 "$pi 应依次：pam-password.sh profile → pam-auth-update --package → pam-password.sh apply，并在最后的 PAM 钩子核对之后再 pam-password.sh check"
	r=1
fi
if grep -qE 'grep[^|]*pam_authd_exec[^|]*common-password' "$pi" || grep -qF '/^Password:/' "$pi"; then
	bad 18 "$pi 里还留着 4a 的「common-password 里没有 authd」核对或自己删 Password 段（已由 pam-password.sh 取代）"
	r=1
fi
# shellcheck disable=SC2016 # 字面的 ${T}、$NEW，是 pam-password.sh 里要找的源码
for l in 'pam_succeed_if.so quiet user !~ *@*' "NEW='pam_authd_exec.so --exec-env=CI=1 -- /usr/libexec/authd-pam'" \
	'password${T}[success=2 ignore=ignore default=die authinfo_unavail=ignore]${T}$NEW' \
	'password${T}[success=1 default=ignore]${T}pam_unix.so obscure yescrypt'; do
	grep -qF -- "$l" "$pp" 2>/dev/null || {
		bad 18 "$pp 应有 $l"
		r=1
	}
done
# 只核 profile 文本挡不住 authd 换版本（复审 I1）：要钉住装的包版本
if ! grep -qE '^AUTHD_VERSION=[0-9][^[:space:]]*$' "$pp" || ! grep -qF "dpkg-query -W -f='\${Version}' authd" "$pp"; then
	bad 18 "$pp 应钉住 authd 的包版本（AUTHD_VERSION=…，profile 子命令用 dpkg-query 核对）"
	r=1
fi
if grep -qE 'pam_unix\.so[^"]*use_authtok' "$pp"; then
	bad 18 "$pp 的期望文本里 pam_unix 不能带 use_authtok（本机用户改口令要 pam_unix 自己问）"
	r=1
fi
grep -qxF '      - run: bash image/tests/pam-password-test.sh' .github/workflows/mastersos.yml || {
	bad 18 ".github/workflows/mastersos.yml 的 image-lint 应跑 tests/pam-password-test.sh"
	r=1
}
[ "$r" = 0 ] && ok 18 "common-password 按用户名分流（含 @ 的经 authd、其余只走 pam_unix 不带 use_authtok）、authd 行带 --exec-env=CI=1、构建时逐行核对"


# 19. 锁住的会话（学习模式、旧的浏览器模式）在执行层堵终端、文件管理器、设置（4b Task 13；配置分层设计 §4.4）：agent 把桩
#     bind-mount 到它们的可执行文件上（core 的 system/exec_block.rs 写死 /usr/lib/mastersos/interface-denied）；sysext 合并或刷新会换掉 /usr 上的 overlay，
#     由 systemd-sysext.service 的 drop-in 之后重挂
r=0
stub=$rel/mkosi.extra/usr/lib/mastersos/interface-denied
if [ ! -x "$stub" ] || ! grep -qF "*) msg='This app is not available on this device' ;;" "$stub" || ! grep -qxF 'exit 126' "$stub"; then
	bad 19 "$stub should be executable, say 'This app is not available on this device' by default and exit 126"
	r=1
fi
if [ -e "$rel/mkosi.extra/usr/lib/mastersos/browser-mode-denied" ]; then
	bad 19 "the stub was renamed to interface-denied; browser-mode-denied should be gone"
	r=1
fi
grep -qF 'pub const STUB: &str = "/usr/lib/mastersos/interface-denied";' "$core/mastersos-agent/src/system/exec_block.rs" 2>/dev/null || {
	bad 19 "$core/mastersos-agent/src/system/exec_block.rs: STUB should be /usr/lib/mastersos/interface-denied"
	r=1
}
sx=$rel/mkosi.extra/usr/lib/systemd/system/systemd-sysext.service.d/50-mastersos-exec-block.conf
for l in 'ExecStartPost=-/usr/bin/mastersos-agent exec-block' 'ExecReload=-/usr/bin/mastersos-agent exec-block'; do
	grep -qxF -- "$l" "$sx" 2>/dev/null || {
		bad 19 "$sx 应有一行 $l"
		r=1
	}
done
grep -qE '^ +image/mkosi\.extra/usr/lib/mastersos/interface-denied$' .github/workflows/mastersos.yml || {
	bad 19 ".github/workflows/mastersos.yml 的 image-lint 应 shellcheck $stub"
	r=1
}
# 文件选择框不能跟着 Nautilus 一起被堵掉：FileChooser 走 xdg-desktop-portal-gtk（包要在包表里）
pc=$rel/mkosi.extra/usr/share/xdg-desktop-portal/ubuntu-portals.conf
if ! grep -qxF 'org.freedesktop.impl.portal.FileChooser=gtk;' "$pc" 2>/dev/null || ! grep -qxF 'default=gnome;gtk;' "$pc" ||
	! grep -qE '^ +xdg-desktop-portal-gtk$' "$rel/mkosi.conf"; then
	bad 19 "$pc 应让 FileChooser 走 gtk（其余照 gnome-portals.conf），mkosi.conf 应装 xdg-desktop-portal-gtk"
	r=1
fi
# 复审发现 4：GDM 之前再按盘上的模式挂一次桩
grep -qxF 'ExecStartPre=-/usr/bin/mastersos-agent exec-block' "$rel/mkosi.extra/usr/lib/systemd/system/gdm.service.d/50-mastersos-agent-local.conf" 2>/dev/null || {
	bad 19 "gdm.service.d/50-mastersos-agent-local.conf 应有 ExecStartPre=-/usr/bin/mastersos-agent exec-block"
	r=1
}
[ "$r" = 0 ] && ok 19 "锁住的会话的桩 interface-denied（可执行、英文默认提示、非 0 退出）、sysext 合并与刷新之后的重挂、文件选择框不靠 Nautilus"


# 20. 会话里的声音与终端快捷键（4b Task 13 复审）：PipeWire 的用户单元由 /usr/lib/systemd/user 里的链接启用（Debian 链在
#     /etc/systemd/user，那个目录机器上没有）；GNOME 50 的 Ctrl+Alt+T 要 xdg-terminal-exec
r=0
uu=$rel/mkosi.extra/usr/lib/systemd/user
for l in sockets.target.wants/pipewire.socket:../pipewire.socket sockets.target.wants/pipewire-pulse.socket:../pipewire-pulse.socket \
	default.target.wants/pipewire.service:../pipewire.service default.target.wants/pipewire-pulse.service:../pipewire-pulse.service \
	pipewire.service.wants/wireplumber.service:../wireplumber.service pipewire-session-manager.service:wireplumber.service; do
	[ "$(readlink "$uu/${l%%:*}" 2>/dev/null)" = "${l#*:}" ] || {
		bad 20 "$uu/${l%%:*} 应是指向 ${l#*:} 的链接"
		r=1
	}
done
for p in pipewire-audio xdg-terminal-exec; do
	grep -qE "^ +$p\$" "$rel/mkosi.conf" || {
		bad 20 "mkosi.conf 应装 $p"
		r=1
	}
done
[ "$r" = 0 ] && ok 20 "PipeWire 的用户单元经 /usr/lib 的链接启用、装了 xdg-terminal-exec"

# 21. 网络连接写得进去（4b Task 14）：agent 写 /etc/NetworkManager/system-connections（学校的 Wi‑Fi），NetworkManager 自己存连接
#     （nmcli、设置、快捷设置）经 netplan 写 /etc/netplan——两处都得是真实目录，不能是指向只读 factory 的链接（L）
r=0
for d in /etc/NetworkManager /etc/NetworkManager/system-connections /etc/netplan; do
	grep -qxF "dir $d" "$rel/etc-policy.conf" || {
		bad 21 "etc-policy.conf 应有 dir ${d}（否则是指向只读 factory 的链接，写连接的一方失败；NM 写 netplan 失败时直接 abort）"
		r=1
	}
done
for w in /etc/NetworkManager/system-connections /etc/netplan; do
	grep -qF "\"$w\"," "$core/mastersos-agent/src/system/mod.rs" || {
		bad 21 "mastersos-agent 的 WRITE_ROOTS 应含 ${w}（wifi 步骤写连接、收回被 NM 搬进 netplan 的连接）"
		r=1
	}
done
[ "$r" = 0 ] && ok 21 "/etc/NetworkManager/system-connections 与 /etc/netplan 是真实目录（学校的 Wi‑Fi 与本机手动加的连接都存得下）"

# 22. 打印与扫描写得进去（4b Task 15）：CUPS 的队列在 /etc/cups（copy，首次开机拷出的真实目录，cupsd 写 printers.conf 与 ppd/），
#     agent 写 /etc/sane.d/airscan.d/mastersos.conf——它得是真实目录，不能是指向只读 factory 的链接（L）
r=0
for l in "copy /etc/cups" "dir /etc/sane.d" "dir /etc/sane.d/airscan.d"; do
	grep -qxF "$l" "$rel/etc-policy.conf" || {
		bad 22 "etc-policy.conf 应有 ${l}（cupsd 存队列、agent 写扫描仪都要真实目录）"
		r=1
	}
done
grep -qF '"/etc/sane.d/airscan.d",' "$core/mastersos-agent/src/system/mod.rs" || {
	bad 22 "mastersos-agent 的 WRITE_ROOTS 应含 /etc/sane.d/airscan.d（scanners 步骤写 mastersos.conf）"
	r=1
}
for p in cups sane-airscan; do
	grep -qE "^ +$p\$" "$rel/mkosi.conf" || {
		bad 22 "mkosi.conf 应装 $p"
		r=1
	}
done
[ "$r" = 0 ] && ok 22 "/etc/cups 与 /etc/sane.d/airscan.d 是真实目录、装了 cups 与 sane-airscan（学校的打印机队列与扫描仪存得下）"

# 23. 挂失锁定、时区与语言写得进去（4b Task 17）：agent 写 /etc/dconf/db/gdm.d/90-mastersos-lock（登录界面的横幅），
#     localed 写 /etc/locale.conf、timedated 写 /etc/localtime——都得归这台机器（copy）；会话的 pam_env 读 /etc/default/locale
#     （→ ../locale.conf），/etc/default 得是真实目录，这个相对链接才解析到 /etc/locale.conf 而不是 factory 里的那份
r=0
for l in "dir /etc/dconf/db/gdm.d" "dir /etc/default" "copy /etc/locale.conf" "copy /etc/localtime"; do
	grep -qxF "$l" "$rel/etc-policy.conf" || {
		bad 23 "etc-policy.conf 应有 ${l}（登录界面的横幅、localectl、timedatectl 要写得进去）"
		r=1
	}
done
grep -qF '"/etc/dconf/db/gdm.d",' "$core/mastersos-agent/src/system/mod.rs" || {
	bad 23 "mastersos-agent 的 WRITE_ROOTS 应含 /etc/dconf/db/gdm.d（lock 步骤写登录界面的横幅）"
	r=1
}
# 镜像生成的每个语言（postinst.chroot 的 locale-gen）都要有 GNOME 的界面翻译，否则 school.locale 只改得了日期格式
for p in language-pack-th language-pack-gnome-th language-pack-zh-hans language-pack-gnome-zh-hans language-pack-en language-pack-gnome-en; do
	grep -qE "^ +$p\$" "$rel/mkosi.conf" || {
		bad 23 "mkosi.conf 应装 ${p}（school.locale 设成镜像里的语言时界面要有翻译）"
		r=1
	}
done
[ "$r" = 0 ] && ok 23 "/etc/dconf/db/gdm.d 与 /etc/default 是真实目录、/etc/locale.conf 与 /etc/localtime 首次开机拷出（横幅、语言与时区写得进去，会话读到的是这台机器的语言），装了 th / zh-hans / en 的界面翻译"

# 24. 发行版在 /etc/systemd/user 里启用的用户单元（4b Task 24）：那个目录到不了机器（/etc 由策略表生成），构建时由 user-units.sh
#     按允许清单搬到 /usr/lib/systemd/user，清单外的链接拒绝构建。这里核对：finalize 调它、清单里有已知的几项、mkosi.extra 里
#     PipeWire 的链接都在清单里（不重复建）、样本测试进了 CI。只查接线：「构建后 /etc 里每个链接在 /usr 都有对应」由 user-units.sh 自己在
#     构建时核对（check-tree 不构建），它的拒绝分支由 tests/user-units-test.sh 逐条覆盖
r=0
uus=$rel/user-units.sh
if [ ! -x "$uus" ]; then
	bad 24 "$uus 应存在且可执行"
	r=1
fi
grep -qxF "\"\$SRCDIR/user-units.sh\" \"\$R\"" "$rel/mkosi.finalize" || {
	bad 24 "mkosi.finalize 应调 \"\$SRCDIR/user-units.sh\" \"\$R\""
	r=1
}
allow=$(sed -n "/^ALLOW='\$/,/^'\$/p" "$uus" 2>/dev/null | sed '1d;$d' | grep -vE '^[[:space:]]*(#|$)' || true)
for l in sockets.target.wants/gpg-agent.socket:gpg-agent.socket sockets.target.wants/ssh-agent.socket:ssh-agent.socket \
	graphical-session-pre.target.wants/xdg-user-dirs.service:xdg-user-dirs.service \
	timers.target.wants/systemd-tmpfiles-clean.timer:systemd-tmpfiles-clean.timer \
	default.target.wants/filter-chain.service:filter-chain.service dbus.service:dbus-broker.service; do
	printf '%s\n' "$allow" | awk -v p="${l%%:*}" -v u="${l#*:}" '$1 == p && $2 == u {f=1} END {exit !f}' || {
		bad 24 "$uus 的 ALLOW 应有「${l%%:*} ${l#*:}」"
		r=1
	}
done
while IFS= read -r x; do
	p=${x#"$uu"/}
	u=$(basename "$(readlink "$x")")
	printf '%s\n' "$allow" | awk -v p="$p" -v u="$u" '$1 == p && $2 == u {f=1} END {exit !f}' || {
		bad 24 "mkosi.extra 里的 $p → $u 不在 $uus 的 ALLOW 里（与包在 /etc 里的链接对不上就拒绝构建）"
		r=1
	}
done < <(find "$uu" -type l | LC_ALL=C sort)
# 会话总线只监视起来时已存在的服务目录（dbus-broker 与 dbus-daemon 一样，复审 I1）：浏览器模式的 D-Bus 覆盖目录要开机就建
for l in 'd /var/lib/mastersos-public/xdg/dbus-1 0755 root root -' 'd /var/lib/mastersos-public/xdg/dbus-1/services 0755 root root -'; do
	grep -qxF -- "$l" "$rel/mkosi.extra/usr/lib/tmpfiles.d/mastersos.conf" || {
		bad 24 "tmpfiles.d/mastersos.conf 应有「${l}」（会话中途切到浏览器模式时总线才看得到新写的 D-Bus 覆盖）"
		r=1
	}
done
grep -qxF '      - run: bash image/tests/user-units-test.sh' .github/workflows/mastersos.yml || {
	bad 24 ".github/workflows/mastersos.yml 的 image-lint 应跑 tests/user-units-test.sh"
	r=1
}
[ "$r" = 0 ] && ok 24 "/etc/systemd/user 的启用链接按允许清单搬到 /usr（gpg/ssh-agent、xdg-user-dirs、tmpfiles-clean、filter-chain、dbus 别名；PipeWire 不重复）"

# 25. 硬件相关的包与微软的公开证书（4b Task 22，spec §6.2）：装 SOF 固件、thermald、sbsigntool 与 openssl（shim-check 用）；
#     不装指纹（fprintd、libpam-fprintd）与 dkms。keys/microsoft/ 恰好两个 .der，都是 openssl 读得出的证书、不是私钥
r=0
for p in firmware-sof-signed thermald sbsigntool openssl; do
	grep -qE "^ +$p\$" "$rel/mkosi.conf" || {
		bad 25 "mkosi.conf 应装 $p"
		r=1
	}
done
for p in fprintd libpam-fprintd dkms; do
	if grep -qE "^ +$p\$" "$rel/mkosi.conf"; then
		bad 25 "mkosi.conf 不应装 $p"
		r=1
	fi
done
mapfile -t ms < <(find "$rel/keys/microsoft" -maxdepth 1 -type f | LC_ALL=C sort)
mapfile -t msder < <(printf '%s\n' "${ms[@]}" | grep -E '\.der$' || true)
if [ "${#ms[@]}" != 2 ] || [ "${#msder[@]}" != 2 ]; then
	bad 25 "keys/microsoft/ 应恰好有两个 .der（实际：${ms[*]:-无}）"
	r=1
fi
if command -v openssl >/dev/null; then
	for f in "${msder[@]}"; do
		openssl x509 -inform DER -in "$f" -noout 2>/dev/null || {
			bad 25 "$f 不是 openssl 读得出的 DER 证书"
			r=1
		}
		if openssl pkey -inform DER -in "$f" -noout 2>/dev/null; then
			bad 25 "$f 是私钥"
			r=1
		fi
	done
else
	echo "check-tree: 没有 openssl，第 25 条跳过证书的解析"
fi
[ "$r" = 0 ] && ok 25 "装了 firmware-sof-signed、thermald、sbsigntool、openssl，没装 fprintd / libpam-fprintd / dkms；keys/microsoft/ 是两张公开的 DER 证书"

# 26. Chrome 的更新时段（4b Task 23）：IT 可以只让 Chrome 在某段时间（至少 2 小时，可能短于 6 小时）里换版本，mastersos-chrome.timer
#     除了开机 2 分钟、每 6 小时之外还要每小时一轮，否则短的时段会整段错过；不在时段内的轮次由 mastersos-agent chrome 自己只读状态就退出。
#     服务带 --scheduled：没设时段的机器上一次查源不到 6 小时就不联网（每小时一轮不变成每小时查源）；手动跑不带它
r=0
ct=$rel/mkosi.extra/usr/lib/systemd/system/mastersos-chrome.timer
for l in OnBootSec=2min OnUnitActiveSec=6h OnCalendar=hourly; do
	grep -qxF "$l" "$ct" || {
		bad 26 "mastersos-chrome.timer 应有 $l"
		r=1
	}
done
grep -qxF 'ExecStart=/usr/bin/mastersos-agent chrome --scheduled' "$rel/mkosi.extra/usr/lib/systemd/system/mastersos-chrome.service" || {
	bad 26 "mastersos-chrome.service 应是 ExecStart=/usr/bin/mastersos-agent chrome --scheduled"
	r=1
}
[ "$r" = 0 ] && ok 26 "mastersos-chrome.timer 开机 2 分钟、每 6 小时，另有每小时一轮；服务带 --scheduled（没设时段的仍约 6 小时查一次源）"

# 29. 发布闸门的 dbx 数据（plan 5 Task 6）：keys/microsoft/dbx/ 是 dbx-import 从微软 DBXUpdate.bin 导入的（keyset_shim_chains 读）。
#     存在时：SOURCE.txt 有 url=、sha256=、date= 三个键；sha256.txt 每行 64 个小写十六进制、无重复、已排序；
#     每个 .der 能被 openssl x509 -inform DER 读、文件名等于它的 sha256（没 openssl 时跳过证书的解析）
r=0
dbxd=$rel/keys/microsoft/dbx
if [ -d "$dbxd" ]; then
	for k in url sha256 date; do
		grep -qE "^${k}=.+" "$dbxd/SOURCE.txt" 2>/dev/null || {
			bad 29 "$dbxd/SOURCE.txt 缺 ${k}="
			r=1
		}
	done
	if [ ! -f "$dbxd/sha256.txt" ]; then
		bad 29 "$dbxd/sha256.txt 不存在"
		r=1
	else
		if grep -qvE '^[0-9a-f]{64}$' "$dbxd/sha256.txt"; then
			bad 29 "$dbxd/sha256.txt 有不是 64 个小写十六进制的行"
			r=1
		elif [ "$(LC_ALL=C sort -u "$dbxd/sha256.txt")" != "$(cat "$dbxd/sha256.txt")" ]; then
			bad 29 "$dbxd/sha256.txt 有重复的行或没排序（dbx-import 的输出是排序去重的）"
			r=1
		fi
	fi
	for f in "$dbxd"/*.der; do
		[ -e "$f" ] || continue
		if command -v openssl >/dev/null; then
			openssl x509 -inform DER -in "$f" -noout 2>/dev/null || {
				bad 29 "$f 不是 DER 证书"
				r=1
			}
		fi
		want=$(basename "$f" .der)
		got=$(openssl dgst -sha256 -r "$f" 2>/dev/null | cut -d' ' -f1 || true)
		[ -n "$got" ] || got=$(sha256sum "$f" | cut -d' ' -f1)
		[ "$want" = "$got" ] || {
			bad 29 "$f 的文件名应是它的 sha256（$got）"
			r=1
		}
	done
fi
[ "$r" = 0 ] && ok 29 "keys/microsoft/dbx/（有则查）：SOURCE.txt 三个键齐、sha256.txt 小写十六进制排序无重复、*.der 能读且以 sha256 命名"

# 28. 不该留在 MokList 里的 MastersOS 证书（计划 5 Task 5，裁定 12）：安装器在正式 profile 下发现机器登记着 lab 或预发布证书会警告，
#     并让 `mokutil --delete /usr/share/mastersos/untrusted-mok/<名>.der` 删掉——所以镜像要带这三张公开证书（lab、lab-2026-10、pre-release），secureboot.rs 里
#     UNTRUSTED_MOK_SHA256 的三个值必须等于它们的 sha256；lab.der 就是 keys/lab/mastersos-mok.der；lab-2026-10.der 是上一套 lab 证书（旧私钥还在没抹掉的盘上，所以继续列着），
#     与 lab.der 不同；三张都不是正式证书。
#     预发布证书：Task 7 之前它就是现在的 keys/mastersos-mok.der；Task 7 之后挪到 keys/retired/mastersos-mok-pre-ceremony.der，
#     keys/mastersos-mok.der 换成新的正式证书，这时 pre-release.der 必须等于 retired 里那张且不等于正式证书
r=0
um=$rel/mkosi.extra/usr/share/mastersos/untrusted-mok
sbrs=$core/mastersos-agent/src/secureboot.rs
sha_of() { sha256sum "$1" | cut -d' ' -f1; }
# 常量里的三个十六进制值：把 UNTRUSTED_MOK_SHA256 那块的 0x.. 字节按出现顺序每 32 个拼成一个
mapfile -t consts < <(awk '/^pub const UNTRUSTED_MOK_SHA256/{on=1;next} on&&/^\];/{on=0} on{while(match($0,/0x[0-9a-f][0-9a-f]/)){printf "%s",substr($0,RSTART+2,2);$0=substr($0,RSTART+RLENGTH);n++;if(n%32==0)printf "\n"}}' "$sbrs")
if [ "${#consts[@]}" != 4 ]; then
	bad 28 "secureboot.rs 的 UNTRUSTED_MOK_SHA256 应恰好四项（实际 ${#consts[@]}）"
	r=1
else
	for i in 0:lab 1:lab-2026-11 2:lab-2026-10 3:pre-release; do
		f=$um/${i#*:}.der
		if [ ! -f "$f" ]; then
			bad 28 "缺 $f"
			r=1
		elif [ "${consts[${i%%:*}]}" != "$(sha_of "$f")" ]; then
			bad 28 "UNTRUSTED_MOK_SHA256[${i%%:*}] 不等于 ${i#*:}.der 的 sha256"
			r=1
		fi
	done
	for n in lab lab-2026-11 lab-2026-10; do
		if [ -f "$um/$n.der" ] && [ "$(sha_of "$um/$n.der")" = "$(sha_of "$rel/keys/mastersos-mok.der")" ]; then
			bad 28 "$n.der 不应等于正式证书 keys/mastersos-mok.der"
			r=1
		fi
	done
	if [ -f "$um/lab.der" ] && [ -f "$um/lab-2026-11.der" ] && [ "$(sha_of "$um/lab.der")" = "$(sha_of "$um/lab-2026-11.der")" ]; then
		bad 28 "lab-2026-11.der（旧 lab 证书）应不同于 lab.der（现 lab 证书）"
		r=1
	fi
	if [ -f "$um/lab.der" ] && [ -f "$um/lab-2026-10.der" ] && [ "$(sha_of "$um/lab.der")" = "$(sha_of "$um/lab-2026-10.der")" ]; then
		bad 28 "lab-2026-10.der（旧 lab 证书）应不同于 lab.der（现 lab 证书）"
		r=1
	fi
	retired=$rel/keys/retired/mastersos-mok-pre-ceremony.der
	if [ -f "$retired" ]; then
		if [ "$(sha_of "$um/pre-release.der")" != "$(sha_of "$retired")" ]; then
			bad 28 "untrusted-mok/pre-release.der 应等于 keys/retired/mastersos-mok-pre-ceremony.der"
			r=1
		fi
		if [ "$(sha_of "$um/pre-release.der")" = "$(sha_of "$rel/keys/mastersos-mok.der")" ]; then
			bad 28 "untrusted-mok/pre-release.der 不应等于正式证书 keys/mastersos-mok.der（仪式之后正式证书已换）"
			r=1
		fi
	else
		[ "$(sha_of "$um/pre-release.der")" = "$(sha_of "$rel/keys/mastersos-mok.der")" ] || {
			bad 28 "Task 7 之前 untrusted-mok/pre-release.der 应等于 keys/mastersos-mok.der（预发布证书）"
			r=1
		}
	fi
	[ "$(sha_of "$um/lab.der")" = "$(sha_of "$rel/keys/lab/mastersos-mok.der")" ] || {
		bad 28 "untrusted-mok/lab.der 应与 keys/lab/mastersos-mok.der 逐字节相同"
		r=1
	}
fi
[ "$r" = 0 ] && ok 28 "镜像带 lab、旧 lab（lab-2026-10）与预发布三张公开证书（untrusted-mok/），sha256 等于 secureboot.rs 的 UNTRUSTED_MOK_SHA256；lab.der 就是 keys/lab/mastersos-mok.der"

# 27. 正式私钥只经 tmpfs（计划 5 Task 4，裁定 9）：用钥匙的脚本的非注释行里不拼 mastersos-keys/ 与 /run/mastersos-release-keys
#     （只有 keyset.sh、keys-load.sh、keys-unload.sh 拼）；离线仪式的脚本里口令不经参数（不出现 --passphrase、-pass pass:）
r=0
for f in build.sh make-installer.sh channel-common.sh mkosi.finalize sync-s3.sh; do
	[ -f "$rel/$f" ] || continue
	hits=$(grep -nvE '^[[:space:]]*#' "$rel/$f" | grep -E -- 'mastersos-keys/|/run/mastersos-release-keys' || true)
	if [ -n "$hits" ]; then
		bad 27 "$f 自己拼了私钥目录（应经 keyset.sh 的 keyset_priv / keyset_lab_local）："
		printf '%s\n' "$hits" | sed 's/^/    /' >&2
		r=1
	fi
done
cer=$rel/ceremony/gen-release-keys.sh
if [ ! -f "$cer" ]; then
	bad 27 "缺少 $cer"
	r=1
else
	hits=$(grep -nE -- '--passphrase|-pass pass:' "$cer" || true)
	if [ -n "$hits" ]; then
		bad 27 "$cer 里口令经了参数："
		printf '%s\n' "$hits" | sed 's/^/    /' >&2
		r=1
	fi
fi
[ "$r" = 0 ] && ok 27 "私钥目录只由 keyset.sh / keys-load.sh / keys-unload.sh 拼；仪式脚本的口令不经参数"

# 30. Release public keys after the ceremony (plan 5 Task 7, 2026-10-27): keys/mastersos-mok.der is CN "MastersOS Secure Boot 2026"
#     valid past 2046, keys/import-pubring.pgp holds exactly one primary key "MastersOS updates 2026" that only signs, and the
#     release, lab and retired pre-ceremony public keys are pairwise different (a reused key means nothing was retired)
r=0
k=$rel/keys
if ! openssl x509 -inform DER -in "$k/mastersos-mok.der" -noout -checkend $((20 * 365 * 86400 - 30 * 86400)) >/dev/null 2>&1; then
	bad 30 "$k/mastersos-mok.der is not a DER certificate valid for about 20 more years"
	r=1
elif [ "$(openssl x509 -inform DER -in "$k/mastersos-mok.der" -noout -subject -nameopt RFC2253 2>/dev/null)" != "subject=CN=MastersOS Secure Boot 2026" ]; then
	bad 30 "$k/mastersos-mok.der is not CN=MastersOS Secure Boot 2026"
	r=1
fi
cols=$(gpg --batch --no-default-keyring --show-keys --with-colons "$k/import-pubring.pgp" 2>/dev/null || true)
if [ "$(grep -c '^pub:' <<<"$cols")" != 1 ] || [ "$(awk -F: '$1 == "uid" {print $10}' <<<"$cols")" != "MastersOS updates 2026" ] ||
	! awk -F: '$1 == "pub" {print $12}' <<<"$cols" | grep -qxE '[scSC]*s[scSC]*'; then
	bad 30 "$k/import-pubring.pgp should be one sign-only primary key, uid MastersOS updates 2026"
	r=1
fi
sha() { sha256sum <"$1" | cut -d' ' -f1; }
pubder() { openssl pkey -pubin -in "$1" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1; }
gpgfpr() { gpg --batch --no-default-keyring --show-keys --with-colons "$1" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }'; }
pre=$k/retired
if [ -f "$pre/mastersos-mok-pre-ceremony.der" ]; then
	for f in mastersos-mok-pre-ceremony.der tpm2-pcr-public-key-pre-ceremony.pem import-pubring-pre-ceremony.pgp; do
		[ -s "$pre/$f" ] || { bad 30 "missing $pre/$f"; r=1; }
	done
	ders=$(for d in "$k" "$k/lab"; do sha "$d/mastersos-mok.der"; done; sha "$pre/mastersos-mok-pre-ceremony.der")
	pems=$(for d in "$k" "$k/lab"; do pubder "$d/tpm2-pcr-public-key.pem"; done; pubder "$pre/tpm2-pcr-public-key-pre-ceremony.pem")
	fprs=$(for d in "$k" "$k/lab"; do gpgfpr "$d/import-pubring.pgp"; done; gpgfpr "$pre/import-pubring-pre-ceremony.pgp")
	for set in "$ders" "$pems" "$fprs"; do
		if [ "$(sort -u <<<"$set" | grep -c .)" != 3 ]; then
			bad 30 "release, lab and pre-ceremony public keys are not pairwise different (or unreadable)"
			r=1
		fi
	done
fi
[ "$r" = 0 ] && ok 30 "release public keys are the 2026 ceremony's (MOK CN and 20 years, one sign-only gpg key) and differ from lab and pre-ceremony"

# 31. School cache fallback (plan 5 Task 12): mastersos-update.service runs update-run (update via the /etc
#     overrides first, on failure retry from the official source using the fallback directory the agent
#     writes) instead of calling systemd-sysupdate directly; the fallback directory and record names in
#     update-run must match the agent (FALLBACK_DIR / MIRROR_STATUS in update_channel.rs);
#     tests/update-run-test.sh tests the behaviour; every update goes through staged_update (resumable download,
#     tests/update-run-staged-test.sh)
r=0
upsvc=$rel/mkosi.extra/usr/lib/systemd/system/mastersos-update.service
upr=$rel/mkosi.extra/usr/lib/mastersos/update-run
agent_uc=$rel/../core/mastersos-agent/src/system/update_channel.rs
if ! grep -qxF 'ExecStart=/usr/bin/flock /run/mastersos-slots.lock /usr/lib/mastersos/update-run' "$upsvc" 2>/dev/null; then
	bad 31 "mastersos-update.service ExecStart should be /usr/lib/mastersos/update-run under flock /run/mastersos-slots.lock"
	r=1
fi
# shellcheck disable=SC2016 # the patterns are literal text of update-run
if [ ! -x "$upr" ] && [ ! -f "$upr" ]; then
	bad 31 "missing $upr"
	r=1
elif ! grep -qF 'fallback=$var/sysupdate-fallback.d' "$upr" || ! grep -qF 'status=$var/update-mirror-failed' "$upr" ||
	! grep -qF -- 'staged_update "$fallback"' "$upr" || ! grep -qF -- '--definitions="$1"' "$upr"; then
	bad 31 "update-run should use \$var/sysupdate-fallback.d and \$var/update-mirror-failed and fall back with staged_update \"\$fallback\" (sysupdate --definitions=)"
	r=1
fi
if [ -f "$agent_uc" ] && { ! grep -qF 'FALLBACK_DIR: &str = "sysupdate-fallback.d"' "$agent_uc" || ! grep -qF 'MIRROR_STATUS: &str = "update-mirror-failed"' "$agent_uc"; }; then
	bad 31 "agent FALLBACK_DIR / MIRROR_STATUS do not match update-run"
	r=1
fi
[ "$r" = 0 ] && ok 31 "mastersos-update.service runs update-run; fallback directory and record names match between agent and script"

# 32. Carried authd-oidc patches (plan 5 Task 13): patches/ holds only patches/authd-oidc/NNNN-<name>.patch; each one
#     changes only authd-oidc-brokers/ and brings its own Go test (func TestMastersOS…, the tests mkosi.build runs);
#     mkosi.build applies the whole directory in name order (git apply --check first) and records every patch's
#     sha256 in authd-oidc.build-info, and build.sh requires that line and compares it with the directory
r=0
pdir=$rel/patches/authd-oidc
n=0
for f in "${files[@]}"; do
	case "$f" in "$rel"/patches/*) ;; *) continue ;; esac
	[ -f "$f" ] || continue
	if ! [[ ${f#"$rel"/patches/} =~ ^authd-oidc/[0-9]{4}-[a-z0-9-]+\.patch$ ]]; then
		bad 32 "$f: only patches/authd-oidc/NNNN-<name>.patch belongs in patches/ (mkosi.build applies *.patch, anything else would be silently skipped)"
		r=1
		continue
	fi
	n=$((n + 1))
	paths=$(sed -n 's|^diff --git a/\([^ ]*\) b/.*|\1|p' "$f")
	if [ -z "$paths" ] || grep -qv '^authd-oidc-brokers/' <<<"$paths"; then
		bad 32 "$f should be a git patch against the authd repository root that changes only authd-oidc-brokers/"
		r=1
	fi
	if ! grep -q '^+func TestMastersOS' "$f"; then
		bad 32 "$f should bring its own test (func TestMastersOS…, run by mkosi.build)"
		r=1
	fi
done
# shellcheck disable=SC2016 # the patterns are literal text of mkosi.build / build.sh
if ! grep -qF 'for p in "$SRCDIR"/patches/authd-oidc/*.patch; do' "$mb" || ! grep -qF 'git -C "$work/authd" apply --check "$p"' "$mb" ||
	! grep -qF 'echo "authd_oidc_patches=$patches"' "$mb" || ! grep -qF "go test -count=1 -v -run '^TestMastersOS' ./internal/broker/" "$mb"; then
	bad 32 "$mb should apply every patches/authd-oidc/*.patch (git apply --check first), run their TestMastersOS tests and write authd_oidc_patches= into the build-info"
	r=1
fi
# shellcheck disable=SC2016 # the patterns are literal text of build.sh
if ! grep -qE '^for k in .*authd_oidc_patches' "$rel/build.sh" || ! grep -qF 'for p in "$here"/patches/authd-oidc/*.patch; do' "$rel/build.sh"; then
	bad 32 "build.sh should require authd_oidc_patches in the image's authd-oidc.build-info and compare it with patches/authd-oidc/"
	r=1
fi
[ "$r" = 0 ] && ok 32 "authd-oidc patches: $n in $pdir, each only under authd-oidc-brokers/ with its own TestMastersOS test; mkosi.build applies and records them, build.sh compares"

# 33. 锁定应用的两个入口（计划 9 Task 6）：/usr/bin/mastersos-kiosk 与 native messaging 宿主的包装（宿主清单的 path 带不了参数）
#     都只是 exec 进 agent 的 kiosk 子命令（core 的 kiosk_session.rs）；可执行、进 CI 的 shellcheck；desktop.rs 的启动器执行前者
r=0
for f in "usr/bin/mastersos-kiosk|exec /usr/bin/mastersos-agent kiosk \"\$@\"" \
	"usr/lib/mastersos/mastersos-kiosk-exit|exec /usr/bin/mastersos-agent kiosk exit-host \"\$@\"" \
	"usr/lib/mastersos/mastersos-support-host|exec /usr/bin/mastersos-agent support native-host \"\$@\""; do
	p=$rel/mkosi.extra/${f%%|*}
	if [ ! -x "$p" ] || [ "$(git ls-files -s -- "$p" | cut -c1-6)" = 100644 ] || [ "$(head -n1 "$p")" != '#!/bin/bash' ] ||
		! grep -qxF -- "${f#*|}" "$p"; then
		bad 33 "$p 应可执行、#!/bin/bash、一行 ${f#*|}"
		r=1
	fi
	grep -qE "^ +image/mkosi\.extra/${f%%|*}\$" .github/workflows/mastersos.yml || {
		bad 33 ".github/workflows/mastersos.yml 的 image-lint 应 shellcheck $p"
		r=1
	}
done
grep -qF 'pub const KIOSK_BIN: &str = "/usr/bin/mastersos-kiosk";' "$core/mastersos-agent/src/system/desktop.rs" 2>/dev/null || {
	bad 33 "$core/mastersos-agent/src/system/desktop.rs 的 KIOSK_BIN 应是 /usr/bin/mastersos-kiosk"
	r=1
}
[ "$r" = 0 ] && ok 33 "mastersos-kiosk、mastersos-kiosk-exit 与 mastersos-support-host 可执行、只 exec 进 agent 的子命令，CI shellcheck 它们"

# 34. 锁定应用的镜像这一侧（计划 9 Task 8，设计 §4.3、§4.4、§4.6、§5）：gnome-kiosk 会话、pam_namespace 的实例目录与 namespace.init、
#     kiosk 账号的 dconf、kernel.sysrq、错误页、考试扩展的打包与安装。路径与 agent / bundle 里的常量逐个对上
r=0
ex=$rel/mkosi.extra
kagent=$core/mastersos-agent/src/system/kiosk.rs
kbundle=$core/mastersos-bundle/src/kiosk.rs
const_of() { # $1 文件 $2 常量名：取 `pub const <名>: &str = "<值>";` 的值
	sed -n "s/^pub const $2: &str = \"\\(.*\\)\";\$/\\1/p" "$1"
}
k_session=$(const_of "$kagent" SESSION)
k_polydir=$(const_of "$kagent" NS_POLYDIR)
k_prefix=$(const_of "$kagent" NS_INSTANCE_PREFIX)
k_public=$(const_of "$kagent" PUBLIC_DIR)
k_policies=$(const_of "$kagent" POLICIES_DIR)
k_extfile=$(const_of "$kagent" EXAM_EXT_FILE)
k_errpage=$(const_of "$kbundle" ERROR_PAGE)
k_exithost=$(const_of "$kbundle" EXIT_HOST)
k_supporthost=$(const_of "$kbundle" SUPPORT_HOST)
for v in k_session k_polydir k_prefix k_public k_policies k_extfile k_errpage k_exithost k_supporthost; do
	[ -n "${!v}" ] || {
		bad 34 "读不出 agent / bundle 里的常量 ${v#k_}（$kagent、$kbundle）"
		r=1
	}
done
# 包：gnome-kiosk（会话的合成器）与 zenity（enter 的确认框）；不装 gnome-kiosk-script-session（会话由我们提供）
for p in gnome-kiosk zenity; do
	grep -qE "^ +$p\$" "$rel/mkosi.conf" || {
		bad 34 "mkosi.conf 的 Packages= 应有 $p"
		r=1
	}
done
if grep -qE '^ +gnome-kiosk-script-session$' "$rel/mkosi.conf"; then
	bad 34 "mkosi.conf 不应装 gnome-kiosk-script-session（它的会话跑 ~/.local/bin 里的任意脚本）"
	r=1
fi
# 会话：GDM 按文件名设 XDG_SESSION_DESKTOP（mastersos-kiosk run 核对它等于 SESSION）；gnome-session 50 的组件在
# gnome-session@<会话>.target 的 drop-in 里（.session 只剩名字），应用是 org.mastersos.KioskApp.service
sess=$ex/usr/share/wayland-sessions/$k_session.desktop
for l in '[Desktop Entry]' 'Type=Application' "Exec=env DCONF_PROFILE=$k_session gnome-session --session=$k_session"; do
	grep -qxF -- "$l" "$sess" 2>/dev/null || {
		bad 34 "$sess 应有一行「$l」"
		r=1
	}
done
# No NoDisplay/Hidden: gdm3 50 then ignores the kiosk account's saved Session and starts ubuntu while AccountsService
# still says mastersos-kiosk, which pam-session reads (VM 170, 2026-10-27, acceptance M2/M3)
if grep -qE '^(NoDisplay|Hidden)[[:space:]]*=' "$sess" 2>/dev/null; then
	bad 34 "$sess must not set NoDisplay or Hidden (GDM would start the default session for kiosk accounts)"
	r=1
fi
# Session guard (review I1): every GNOME session passes gnome-session-pre.target before the session manager and the
# shell; this oneshot, required by it, fails for a kiosk uid outside mastersos-kiosk and the session ends
gu=$ex/usr/lib/systemd/user/mastersos-kiosk-guard.service
for l in 'Type=oneshot' 'ExecStart=/usr/bin/mastersos-kiosk guard' 'Before=gnome-session-pre.target' 'DefaultDependencies=no' 'OnFailure=gnome-session-shutdown.target'; do
	grep -qxF -- "$l" "$gu" 2>/dev/null || {
		bad 34 "$gu should have the line \"$l\""
		r=1
	}
done
gd=$ex/usr/lib/systemd/user/gnome-session-pre.target.d/mastersos-kiosk-guard.conf
for l in 'Requires=mastersos-kiosk-guard.service' 'After=mastersos-kiosk-guard.service'; do
	grep -qxF -- "$l" "$gd" 2>/dev/null || {
		bad 34 "$gd should have the line \"$l\" (gnome-session-pre.target requires the guard)"
		r=1
	}
done
gs=$ex/usr/share/gnome-session/sessions/$k_session.session
if ! grep -qxF '[GNOME Session]' "$gs" 2>/dev/null || grep -q RequiredComponents "$gs"; then
	bad 34 "$gs 应是 [GNOME Session]、不写 RequiredComponents（gnome-session 50 不读它，组件在 target 的 drop-in 里）"
	r=1
fi
gsd=$ex/usr/lib/systemd/user/gnome-session@$k_session.target.d/session.conf
for l in 'Requires=org.gnome.Kiosk.target' 'Requires=org.mastersos.KioskApp.service'; do
	grep -qxF -- "$l" "$gsd" 2>/dev/null || {
		bad 34 "$gsd 应有「$l」"
		r=1
	}
done
app=$ex/usr/lib/systemd/user/org.mastersos.KioskApp.service
for l in 'ExecStart=/usr/bin/mastersos-kiosk run' 'BindsTo=gnome-session.target' 'After=gnome-session.target' \
	'OnFailure=gnome-session-shutdown.target' 'OnSuccess=gnome-session-shutdown.target'; do
	grep -qxF -- "$l" "$app" 2>/dev/null || {
		bad 34 "$app 应有「$l」"
		r=1
	}
done
if grep -q '^\[Install\]' "$app" 2>/dev/null; then
	bad 34 "$app 不应有 [Install]（只由锁定会话的 target 拉起，user-units.sh 也不收它的启用链接）"
	r=1
fi
# 不放 .desktop 形式的组件：gnome-session 50 用不上，放在 /usr/share/applications 里还能被平时的会话 gtk-launch
for d in "$ex/usr/share/applications/org.mastersos.KioskApp.desktop" "$ex/usr/share/applications/mastersos-kiosk-app.desktop"; do
	if [ -e "$d" ]; then
		bad 34 "$d 不应存在（会话的组件是 systemd 用户单元）"
		r=1
	fi
done
# dconf：profile 在 /usr/share/dconf/profile（与 user、gdm 同处），数据库是构建时编好的 file-db（在 /usr，不经 /etc 与 dconf update）
prof=$ex/usr/share/dconf/profile/$k_session
want_prof=$(printf 'user-db:user\nfile-db:/usr/share/mastersos/dconf/%s' "$k_session")
[ "$(cat "$prof" 2>/dev/null)" = "$want_prof" ] || {
	bad 34 "$prof 应恰好是 user-db:user 与 file-db:/usr/share/mastersos/dconf/$k_session 两行"
	r=1
}
kd=$ex/usr/share/mastersos/dconf/$k_session.d
for i in $(seq 1 12); do
	key=/org/gnome/mutter/wayland/keybindings/switch-to-session-$i
	awk -v k="switch-to-session-$i" '/^\[/ {sec = $0} sec == "[org/gnome/mutter/wayland/keybindings]" && $0 == k "=@as []" {f = 1} END {exit !f}' \
		"$kd/50-mastersos-kiosk" 2>/dev/null || {
		bad 34 "$kd/50-mastersos-kiosk 应把 switch-to-session-$i 设成 @as []"
		r=1
	}
	grep -qxF -- "$key" "$kd/locks/50-mastersos-kiosk" 2>/dev/null || {
		bad 34 "$kd/locks/50-mastersos-kiosk 应锁住 $key"
		r=1
	}
done
grep -qF "dconf compile /usr/share/mastersos/dconf/$k_session /usr/share/mastersos/dconf/$k_session.d" "$rel/mkosi.postinst.chroot" || {
	bad 34 "mkosi.postinst.chroot 应 dconf compile kiosk 的数据库"
	r=1
}
# pam_namespace：实例目录的父目录 root 0000（pam_namespace 不是 000 就拒绝），开机清空；namespace.init 可执行、bash、
# 认 agent 的常量，发行版的那一段原样保留（tests/fixtures/namespace.init.distro 是 resolute 的 libpam-modules 1.7.0-5ubuntu3.2）
grep -qxF -- "D ${k_prefix%/} 0000 root root -" "$ex/usr/lib/tmpfiles.d/mastersos.conf" || {
	bad 34 "tmpfiles.d/mastersos.conf 应有「D ${k_prefix%/} 0000 root root -」（pam_namespace 的实例父目录）"
	r=1
}
ni=$ex/etc/security/namespace.init
if [ ! -x "$ni" ] || [ "$(git ls-files -s -- "$ni" | cut -c1-6)" = 100644 ] || [ "$(head -n1 "$ni" 2>/dev/null)" != '#!/bin/bash' ]; then
	bad 34 "$ni 应可执行（git 里 100755）、#!/bin/bash"
	r=1
fi
for l in "POLYDIR=$k_polydir" "INSTANCE_PREFIX=$k_prefix" "PUBLIC=/$k_public" "POLICIES=$k_policies"; do
	grep -qxF -- "$l" "$ni" 2>/dev/null || {
		bad 34 "$ni 应有一行「$l」（与 agent 的常量相同）"
		r=1
	}
done
distro=$rel/tests/fixtures/namespace.init.distro
body=$(sed -n '/^# Executes only if the polydir path is safe$/,/^exit 0$/p' "$distro" 2>/dev/null)
ni_text=$(cat "$ni" 2>/dev/null || true)
if [ -z "$body" ] || [[ $ni_text != *"$body"* ]]; then
	bad 34 "$ni 应原样保留发行版 namespace.init（$distro）从「# Executes only if the polydir path is safe」到 exit 0 的那一段"
	r=1
fi
for f in "image/mkosi.extra/etc/security/namespace.init" "bash image/tests/namespace-init-test.sh"; do
	grep -qF -- "$f" .github/workflows/mastersos.yml || {
		bad 34 ".github/workflows/mastersos.yml 的 image-lint 应有 $f"
		r=1
	}
done
# kernel.sysrq = 0（设计 §4.6）；postinst 核对排在最后生效的那一行
grep -qxF 'kernel.sysrq = 0' "$ex/usr/lib/sysctl.d/99-mastersos-kiosk.conf" 2>/dev/null || {
	bad 34 "$ex/usr/lib/sysctl.d/99-mastersos-kiosk.conf 应有 kernel.sysrq = 0"
	r=1
}
grep -qF 'kernel.sysrq' "$rel/mkosi.postinst.chroot" || {
	bad 34 "mkosi.postinst.chroot 应核对生效的 kernel.sysrq"
	r=1
}
# 错误页：bundle 的 ERROR_PAGE 指的就是它；中英两句；不连外网、不跑脚本
ep=$ex${k_errpage#file://}
if [ ! -f "$ep" ] || ! grep -qF '这个应用无法启动，请举手找老师' "$ep" || ! grep -qF 'This app could not start. Please ask your teacher.' "$ep" ||
	grep -qiE 'https?://|<script' "$ep"; then
	bad 34 "$ep（bundle 的 ERROR_PAGE）应存在、有中英两句，不引外部资源、不跑脚本"
	r=1
fi
# /etc：namespace.init 与宿主清单跟着镜像走（父目录是 dir、它们自己不在策略表里 → 指回 factory 的 L）；
# pam_namespace 要绑上去的 policies/managed 是真实目录
for l in "dir /etc/security" "dir /etc/opt/chrome" "dir $k_polydir"; do
	grep -qxF -- "$l" "$rel/etc-policy.conf" || {
		bad 34 "etc-policy.conf 应有「$l」"
		r=1
	}
done
if grep -hE '^[[:space:]]*(dir|copy)[[:space:]]+/etc/(security/namespace\.init|opt/chrome/native-messaging-hosts)' "$rel"/etc-policy*.conf | grep -q .; then
	bad 34 "namespace.init 与 native-messaging-hosts 不应在策略表里（它们跟着镜像走）"
	r=1
fi
# 宿主清单：模板的 name 是 bundle 的 EXIT_HOST，path 是镜像里可执行的包装
tmpl=$rel/kiosk-ext/$k_exithost.json.in
if ! python3 -I -c 'import json, sys; d = json.load(open(sys.argv[1])); sys.exit(0 if d["name"] == sys.argv[2] and d["path"] == "/usr/lib/mastersos/mastersos-kiosk-exit" else 1)' "$tmpl" "$k_exithost" 2>/dev/null; then
	bad 34 "$tmpl 的 name 应是 ${k_exithost}、path 是 /usr/lib/mastersos/mastersos-kiosk-exit"
	r=1
fi
tmpl=$rel/kiosk-ext/$k_supporthost.json.in
if ! python3 -I -c 'import json, sys; d = json.load(open(sys.argv[1])); sys.exit(0 if d["name"] == sys.argv[2] and d["path"] == "/usr/lib/mastersos/mastersos-support-host" else 1)' "$tmpl" "$k_supporthost" 2>/dev/null; then
	bad 34 "$tmpl 的 name 应是 ${k_supporthost}、path 是 /usr/lib/mastersos/mastersos-support-host"
	r=1
fi
# build.sh：打包考试扩展、按 agent 读的路径装 kiosk-ext.json、宿主清单进 /etc/opt/chrome/native-messaging-hosts/<EXIT_HOST>.json；
# 钥匙经 keyset 的 $priv；agent 等二进制 0755（kiosk 账号要能执行 /usr/bin/mastersos-agent）
# shellcheck disable=SC2016 # 字面的 $here、$priv、$bin、$extra，是要找的源码文本
for l in '"$here/kiosk-ext-pack.sh"' 'kext_key=$priv/kiosk-ext.pem' 'rm -rf "$kext_tree" "$kext_out"' "\"\$kext_tree/$k_extfile\"" \
	"\"\$kext_tree/etc/opt/chrome/native-messaging-hosts/$k_exithost.json\"" \
	"\"\$kext_tree/etc/opt/chrome/native-messaging-hosts/$k_supporthost.json\"" 'install -m 0755 "$bin" "$extra/usr/bin/"'; do
	grep -qF -- "$l" "$rel/build.sh" || {
		bad 34 "build.sh 应有 $l"
		r=1
	}
done
# 复审 C1：kiosk 账号的 user manager（user@<uid>.service，PAM 栈 systemd-user，resolute 装在 /usr/lib/pam.d）也要过 pam_namespace
# shellcheck disable=SC2016 # 字面的 ${SRCDIR:?}
grep -qxF '	"${SRCDIR:?}/pam-hooks.sh" /etc/pam.d /usr/lib/pam.d' "$rel/mkosi.postinst.chroot" || {
	bad 34 "mkosi.postinst.chroot 应以 /etc/pam.d /usr/lib/pam.d 调 pam-hooks.sh（systemd-user 在 vendor 目录）"
	r=1
}
# 考试扩展的附加树里只有那两个文件（第 16 条只认 $kext_tree 这个名字，这里管它装了什么）
# shellcheck disable=SC2016 # 同上
kext_installs=$(grep -E '^[[:space:]]*install .*"\$kext_tree/' "$rel/build.sh" | grep -vE '^[[:space:]]*install -d ' | grep -oE '"\$kext_tree/[^"]*"' | LC_ALL=C sort | tr '\n' ' ')
[ "$kext_installs" = "\"\$kext_tree/\$kext_dir/mastersos-kiosk-ext.crx\" \"\$kext_tree/\$kext_dir/updates.xml\" \"\$kext_tree/etc/opt/chrome/native-messaging-hosts/$k_exithost.json\" \"\$kext_tree/etc/opt/chrome/native-messaging-hosts/$k_supporthost.json\" \"\$kext_tree/$k_extfile\" " ] || {
	bad 34 "build.sh 往 \$kext_tree 里只装 kiosk-ext.json、两份宿主清单、crx 与 updates.xml，实际：${kext_installs:-<无>}"
	r=1
}
[ "$r" = 0 ] && ok 34 "锁定应用：gnome-kiosk 会话（target drop-in + org.mastersos.KioskApp.service）、dconf file-db 锁住 switch-to-session、pam_namespace 实例父目录 0000 与 namespace.init、sysrq=0、错误页、考试扩展装进镜像"


# 35. 正式的考试扩展钥匙进仪式（计划 9 Task 10）：build.sh 取 <私钥目录>/kiosk-ext.pem（第 34 条），所以仪式生成的清单与
#     keys-load.sh 核对的清单是同一份名单、都有 kiosk-ext.pem；keys-load.sh 拿它对仓库的 kiosk-ext-public.pem；key-leak-check.py
#     也找它。仓库里的 keys/kiosk-ext-public.pem（仪式之后才有）必须是 PEM 公钥、RSA ≥ 2048 位
r=0
mlist="printf '%s\n' db.key db.crt pcr.key pcr.crt kiosk-ext.pem"
for f in "$rel/ceremony/gen-release-keys.sh" "$rel/keys-load.sh"; do
	if [ "$(grep -cF -- "$mlist" "$f")" != 1 ]; then
		bad 35 "$f 的钥匙清单应恰好一处是：$mlist"
		r=1
	fi
done
# shellcheck disable=SC2016 # 字面的源码文本
grep -qF '"$p/kiosk-ext-public.pem"' "$rel/keys-load.sh" || {
	bad 35 "keys-load.sh 的 kl_repo_check 应核对 kiosk-ext-public.pem"
	r=1
}
grep -qF '("db.key", "pcr.key", "kiosk-ext.pem")' "$rel/key-leak-check.py" || {
	bad 35 "key-leak-check.py 应找 kiosk-ext.pem"
	r=1
}
for e in "$rel/keys/kiosk-ext-public.pem" "$rel/keys/lab/kiosk-ext-public.pem"; do
	[ -e "$e" ] || continue
	eb=$(openssl pkey -pubin -in "$e" -noout -text 2>/dev/null | sed -n 's/.*Public-Key: (\([0-9]*\) bit.*/\1/p')
	if ! head -1 "$e" | grep -qx -- '-----BEGIN PUBLIC KEY-----' || [ "${eb:-0}" -lt 2048 ]; then
		bad 35 "$e 应是 RSA ≥ 2048 位的 PEM 公钥（gen-release-keys.sh export-public 写的）"
		r=1
	fi
done
[ "$r" = 0 ] && ok 35 "正式考试扩展钥匙 kiosk-ext.pem 在仪式清单、keys-load.sh 的清单与公钥核对、key-leak-check.py 里一致"

# 36. Golden /usr copy partitions (usr-self-repair Task 1, design 4.2): the four golden definitions live only in
#     installer/install.repart.d (first-boot repart must not know them), their Type= are exactly the four custom
#     UUIDs, and no Label= starts with MastersOS (labels are lower-case mastersos-golden-*; the slot labels are %M_%A…)
r=0
gold_types=$(printf '%s\n' 24fb2b7c-2400-4428-b63f-a3b9824db2b7 b86387b4-5385-488f-ab7b-7d8cc7a663de \
	d75b658d-fd52-45d1-b604-7503d3390430 dbd93f87-e4ab-4c62-8efe-21507a9f3575)
got_types=""
for f in 25-golden-sig.conf 26-golden-verity.conf 27-golden-usr.conf 28-golden-esp.conf; do
	if [ ! -f "$rel/installer/install.repart.d/$f" ]; then
		bad 36 "installer/install.repart.d/$f is missing"
		r=1
		continue
	fi
	if [ -e "$rel/mkosi.extra/usr/lib/repart.d/$f" ]; then
		bad 36 "mkosi.extra/usr/lib/repart.d must not contain $f (installer only)"
		r=1
	fi
	got_types="$got_types$(sed -n 's/^Type=//p' "$rel/installer/install.repart.d/$f")
"
	if grep -qE '^Label=MastersOS' "$rel/installer/install.repart.d/$f"; then
		bad 36 "$f: Label= must not start with MastersOS"
		r=1
	fi
done
if [ "$(printf '%s' "$got_types" | sort)" != "$gold_types" ]; then
	bad 36 "golden Type= values are not exactly the four custom UUIDs"
	r=1
fi
# the installer zeroes golden-sig by partition number (core/mastersos-installer/src/plan.rs GOLDEN_SIG_PARTNO = 8): repart numbers
# the definitions in file-name order, so 25-golden-sig.conf must be the 8th
eighth=$(find "$rel/installer/install.repart.d" -maxdepth 1 -name '*.conf' -printf '%f\n' 2>/dev/null | LC_ALL=C sort | sed -n 8p)
if [ "$eighth" != 25-golden-sig.conf ]; then
	bad 36 "installer/install.repart.d: the 8th definition is ${eighth:-none}, not 25-golden-sig.conf (the installer zeroes partition 8)"
	r=1
fi
if [ -f core/mastersos-installer/src/plan.rs ] && ! grep -qE '^pub const GOLDEN_SIG_PARTNO: u32 = 8;' core/mastersos-installer/src/plan.rs; then
	bad 36 "core/mastersos-installer/src/plan.rs GOLDEN_SIG_PARTNO is not 8"
	r=1
fi
[ "$r" = 0 ] && ok 36 "golden copy partitions are installer-only with the four custom type UUIDs, golden-sig is partition 8"

# 37. golden-lib (usr self-repair Task 2): the initrd copy is byte-identical to the userspace copy, and CI
#     lints both with shellcheck in CI and runs tests/golden-lib-test.sh
r=0
gl=mkosi.extra/usr/lib/mastersos/golden-lib
gli=mkosi.initrd.conf/mkosi.extra/usr/lib/mastersos/golden-lib
if [ ! -f "$rel/$gl" ] || [ ! -f "$rel/$gli" ]; then
	bad 37 "golden-lib must exist under both $rel/$gl and $rel/$gli"
	r=1
elif ! cmp -s "$rel/$gl" "$rel/$gli"; then
	bad 37 "$rel/$gli must be byte-identical to $rel/$gl (cp one over the other)"
	r=1
fi
for p in "$gl" "$gli"; do
	grep -qE "^ +image/${p//./\\.}\$" .github/workflows/mastersos.yml || {
		bad 37 ".github/workflows/mastersos.yml image-lint should shellcheck image/$p"
		r=1
	}
done
grep -qxF '      - run: bash image/tests/golden-lib-test.sh' .github/workflows/mastersos.yml || {
	bad 37 ".github/workflows/mastersos.yml image-lint should run tests/golden-lib-test.sh"
	r=1
}
[ "$r" = 0 ] && ok 37 "golden-lib: the two copies are identical and CI lints them and runs golden-lib-test.sh"

# 38. initrd /usr self-repair unit (usr self-repair Tasks 3 and 6): usr-repair is executable, linted in CI and tested by
#     tests/usr-repair-test.sh; its unit is pulled in by initrd.target.wants/, ordered before the /usr verity device and mount,
#     runs only on EFI machines with a 10 min timeout, and has no FailureAction (a failed check must never stop or reboot the
#     machine); the initrd's profile file comes only from its lab profile
r=0
ur=$rel/mkosi.initrd.conf/mkosi.extra/usr/lib/mastersos/usr-repair
uu=$initrd_sysd/mastersos-usr-repair.service
if [ ! -x "$ur" ] || [ "$(git ls-files -s -- "$ur" | cut -c1-6)" = 100644 ]; then
	bad 38 "$ur should exist and be executable"
	r=1
fi
grep -qE "^ +${ur//./\\.}\$" .github/workflows/mastersos.yml || {
	bad 38 ".github/workflows/mastersos.yml image-lint should shellcheck $ur"
	r=1
}
if [ "$(readlink "$initrd_sysd/initrd.target.wants/mastersos-usr-repair.service" 2>/dev/null)" != ../mastersos-usr-repair.service ]; then
	bad 38 "$initrd_sysd/initrd.target.wants/mastersos-usr-repair.service should link to ../mastersos-usr-repair.service"
	r=1
fi
for l in 'DefaultDependencies=no' 'Before=systemd-veritysetup@usr.service sysusr-usr.mount initrd-usr-fs.target' \
	'After=systemd-udevd.service systemd-udev-trigger.service' 'Type=oneshot' \
	'ConditionPathExists=/sys/firmware/efi/efivars' 'TimeoutStartSec=10min' 'ExecStart=/usr/lib/mastersos/usr-repair'; do
	grep -qxF "$l" "$uu" 2>/dev/null || {
		bad 38 "$uu should have the line: $l"
		r=1
	}
done
if grep -qE '^(FailureAction|SuccessAction)=' "$uu" 2>/dev/null; then
	bad 38 "$uu must not set FailureAction=/SuccessAction="
	r=1
fi
grep -qxF '      - run: bash image/tests/usr-repair-test.sh' .github/workflows/mastersos.yml || {
	bad 38 ".github/workflows/mastersos.yml image-lint should run tests/usr-repair-test.sh"
	r=1
}
# the lab-fail-verify hook reads the initrd's own profile file; only the initrd's lab profile may put it there
if [ "$(cat "$rel/mkosi.initrd.conf/mkosi.profiles/lab/mkosi.extra/usr/lib/mastersos/profile" 2>/dev/null)" != lab ] ||
	[ -e "$rel/mkosi.initrd.conf/mkosi.extra/usr/lib/mastersos/profile" ]; then
	bad 38 "the initrd's usr/lib/mastersos/profile must come only from $rel/mkosi.initrd.conf/mkosi.profiles/lab/mkosi.extra (content: lab)"
	r=1
fi
[ "$r" = 0 ] && ok 38 "initrd usr-repair is executable, linted and tested in CI, enabled by initrd.target.wants and ordered before /usr is opened"

# 39. userspace integrity (usr self-repair Task 4): integrity is executable and linted in CI, tests/integrity-test.sh runs in CI,
#     mastersos-boot-ok / mastersos-integrity are enabled from /usr/lib and run only after boot-complete.target;
#     the integrity script takes /run/mastersos-slots.lock (held by mastersos-update, rule 31) around restore-inactive, the one
#     action that writes the slot sysupdate writes (Task 5); the unit itself is not wrapped in it
r=0
ig=$rel/mkosi.extra/usr/lib/mastersos/integrity
if [ ! -x "$ig" ] || [ "$(git ls-files -s -- "$ig" | cut -c1-6)" = 100644 ]; then
	bad 39 "$ig should exist and be executable"
	r=1
fi
grep -qE "^ +${ig//./\\.}\$" .github/workflows/mastersos.yml || {
	bad 39 ".github/workflows/mastersos.yml image-lint should shellcheck $ig"
	r=1
}
# shellcheck disable=SC2016 # literal text of the script
grep -qxF 'SLOTS_LOCK=${MASTERSOS_SLOTS_LOCK:-/run/mastersos-slots.lock}' "$ig" 2>/dev/null || {
	bad 39 "$ig should take /run/mastersos-slots.lock (SLOTS_LOCK) around restore-inactive"
	r=1
}
grep -qxF '      - run: bash image/tests/integrity-test.sh' .github/workflows/mastersos.yml || {
	bad 39 ".github/workflows/mastersos.yml image-lint should run tests/integrity-test.sh"
	r=1
}
for u in mastersos-boot-ok mastersos-integrity; do
	if [ "$(readlink "$sysd/multi-user.target.wants/$u.service" 2>/dev/null)" != ../$u.service ]; then
		bad 39 "$sysd/multi-user.target.wants/$u.service should link to ../$u.service"
		r=1
	fi
	for l in 'Type=oneshot' 'Requisite=boot-complete.target'; do
		grep -qxF "$l" "$sysd/$u.service" 2>/dev/null || {
			bad 39 "$sysd/$u.service should have the line: $l"
			r=1
		}
	done
done
for l in 'After=boot-complete.target' 'ExecStart=/usr/lib/mastersos/integrity --boot-ok'; do
	grep -qxF "$l" "$sysd/mastersos-boot-ok.service" 2>/dev/null || {
		bad 39 "$sysd/mastersos-boot-ok.service should have the line: $l"
		r=1
	}
done
for l in 'After=boot-complete.target mastersos-boot-ok.service systemd-bless-boot.service mastersos-bootloader-update.service' \
	'ExecStart=/usr/lib/mastersos/integrity' 'Nice=19' 'IOSchedulingClass=idle' 'TimeoutStartSec=30min'; do
	grep -qxF "$l" "$sysd/mastersos-integrity.service" 2>/dev/null || {
		bad 39 "$sysd/mastersos-integrity.service should have the line: $l"
		r=1
	}
done
[ "$r" = 0 ] && ok 39 "integrity is executable, linted and tested in CI; its two units are enabled from /usr/lib and wait for boot-complete.target"

# 40. golden-fetch (usr self-repair Task 7): executable, linted in CI, tests/golden-fetch-test.sh runs in CI, it shares integrity's
#     write helpers (sources it) and the image carries the commands it needs (zstd, curl, gpgv in mkosi.conf's Packages=)
r=0
gf=$rel/mkosi.extra/usr/lib/mastersos/golden-fetch
if [ ! -x "$gf" ] || [ "$(git ls-files -s -- "$gf" | cut -c1-6)" = 100644 ]; then
	bad 40 "$gf should exist and be executable"
	r=1
fi
grep -qE "^ +${gf//./\\.}\$" .github/workflows/mastersos.yml || {
	bad 40 ".github/workflows/mastersos.yml image-lint should shellcheck $gf"
	r=1
}
grep -qxF '      - run: bash image/tests/golden-fetch-test.sh' .github/workflows/mastersos.yml || {
	bad 40 ".github/workflows/mastersos.yml image-lint should run tests/golden-fetch-test.sh"
	r=1
}
# shellcheck disable=SC2016 # literal text of the script
grep -qF '. "${MASTERSOS_INTEGRITY:-/usr/lib/mastersos/integrity}"' "$gf" 2>/dev/null || {
	bad 40 "$gf should source integrity for the shared write helpers (write_dd, finish_copy)"
	r=1
}
for p in zstd curl gpgv; do
	grep -qE "^ +$p\$" "$rel/mkosi.conf" || {
		bad 40 "mkosi.conf's Packages= should have $p (golden-fetch)"
		r=1
	}
done
# the download runs in its own unit (network-online, 3 h), started on demand by integrity's network action, never at boot
gu=$sysd/mastersos-golden-fetch.service
for l in 'Type=oneshot' 'Requisite=boot-complete.target' 'Wants=network-online.target' \
	'After=boot-complete.target network-online.target time-sync.target' 'ExecStart=/usr/lib/mastersos/golden-fetch --booted' \
	'TimeoutStartSec=3h' 'Nice=19' 'IOSchedulingClass=idle'; do
	grep -qxF "$l" "$gu" 2>/dev/null || {
		bad 40 "$gu should have the line: $l"
		r=1
	}
done
if grep -q '^\[Install\]' "$gu" 2>/dev/null || [ -n "$(find "$sysd" "$rel/mkosi.extra/etc/systemd/system" -name mastersos-golden-fetch.service -path '*.wants/*' 2>/dev/null)" ]; then
	bad 40 "$gu must not be enabled (integrity starts it on demand)"
	r=1
fi
grep -qF 'start --no-block mastersos-golden-fetch.service' "$ig" 2>/dev/null || {
	bad 40 "$ig's network action should start mastersos-golden-fetch.service (--no-block)"
	r=1
}
grep -qxF 'for t in zstd curl gpgv; do' "$rel/build.sh" || {
	bad 40 "build.sh should check that the built image has /usr/bin/zstd, curl and gpgv"
	r=1
}
[ "$r" = 0 ] && ok 40 "golden-fetch is executable, linted and tested in CI, shares integrity's write helpers, runs in its own on-demand unit; zstd, curl, gpgv are in the image and checked by build.sh"

# 41. Ventoy installer mount in the initrd (Ventoy installer Task 2): ventoy-attach is executable, linted and tested in CI; its
#     unit is pulled in by initrd.target.wants/, runs only with mastersos.ventoy on the command line, is ordered before the /usr
#     verity device, never times out and survives the switch-root; exfat is an initrd module; build.sh checks the initrd has it all
r=0
va=$rel/mkosi.initrd.conf/mkosi.extra/usr/lib/mastersos/ventoy-attach
vu=$initrd_sysd/mastersos-ventoy-attach.service
if [ ! -x "$va" ] || [ "$(git ls-files -s -- "$va" | cut -c1-6)" = 100644 ]; then
	bad 41 "$va should exist and be executable"
	r=1
fi
grep -qE "^ +${va//./\\.}\$" .github/workflows/mastersos.yml || {
	bad 41 ".github/workflows/mastersos.yml image-lint should shellcheck $va"
	r=1
}
grep -qxF '      - run: bash image/tests/ventoy-attach-test.sh' .github/workflows/mastersos.yml || {
	bad 41 ".github/workflows/mastersos.yml image-lint should run tests/ventoy-attach-test.sh"
	r=1
}
if [ "$(readlink "$initrd_sysd/initrd.target.wants/mastersos-ventoy-attach.service" 2>/dev/null)" != ../mastersos-ventoy-attach.service ]; then
	bad 41 "$initrd_sysd/initrd.target.wants/mastersos-ventoy-attach.service should link to ../mastersos-ventoy-attach.service"
	r=1
fi
for l in 'DefaultDependencies=no' 'ConditionKernelCommandLine=mastersos.ventoy' 'After=systemd-udevd.service systemd-udev-trigger.service' \
	'Before=systemd-veritysetup@usr.service sysusr-usr.mount initrd-usr-fs.target' 'IgnoreOnIsolate=yes' 'Type=oneshot' \
	'RemainAfterExit=yes' 'TimeoutStartSec=infinity' 'StandardOutput=tty' 'TTYPath=/dev/console' \
	'ExecStart=/usr/lib/mastersos/ventoy-attach'; do
	grep -qxF "$l" "$vu" 2>/dev/null || {
		bad 41 "$vu should have the line: $l"
		r=1
	}
done
if grep -qE '^(FailureAction|SuccessAction)=' "$vu" 2>/dev/null; then
	bad 41 "$vu must not set FailureAction=/SuccessAction= (a refusal stops on the screen, it does not reboot)"
	r=1
fi
# the /usr chain's device jobs (90 s running timeout) must wait for the attach unit, or a refusal screen / slow hash ends in a reboot
for d in 'dev-disk-by\x2dloop\x2dref-mastersos\x2dventoy\x2dpart3.device.d' 'dev-disk-by\x2dloop\x2dref-mastersos\x2dventoy\x2dpart4.device.d' \
	'dev-mapper-usr.device.d'; do
	grep -qxF 'After=mastersos-ventoy-attach.service' "$initrd_sysd/$d/50-mastersos-ventoy.conf" 2>/dev/null || {
		bad 41 "$initrd_sysd/$d/50-mastersos-ventoy.conf should have After=mastersos-ventoy-attach.service"
		r=1
	}
done
grep -qxF 'KernelInitrdModules=exfat' "$rel/mkosi.conf" || {
	bad 41 "$rel/mkosi.conf should have KernelInitrdModules=exfat (the initrd mounts the Ventoy stick)"
	r=1
}
grep -qF 'for t in stat blkid systemd-dissect; do' "$rel/build.sh" || {
	bad 41 "build.sh should check that the initrd has stat, blkid and systemd-dissect"
	r=1
}
# a refusal asks "Press Enter to restart." through the console agent and reboots (build.sh checks the initrd has both commands)
if ! grep -qF 'systemd-ask-password --timeout=0' "$va" || ! grep -qF 'systemctl reboot' "$va" ||
	! grep -qF 'usr/bin/systemd-ask-password' "$rel/build.sh" || ! grep -qF 'usr/bin/systemctl' "$rel/build.sh"; then
	bad 41 "$va should end a refusal with systemd-ask-password and systemctl reboot, and build.sh should check the initrd has both"
	r=1
fi
# the whole-file hash check is gone (2026-10-29): nothing reads mastersos.ventoy_sha256= any more
if grep -qE 'sha256sum|ventoy_sha256' "$va"; then
	bad 41 "$va must not hash the system file or read mastersos.ventoy_sha256="
	r=1
fi
[ "$r" = 0 ] && ok 41 "initrd ventoy-attach is executable, linted and tested in CI; its unit is enabled by initrd.target.wants, conditional on mastersos.ventoy and ordered before /usr is opened; exfat is an initrd module"

# 42. installer-mount knows Ventoy mode (Ventoy installer Task 3): linted and tested in CI; in Ventoy mode it mounts only the loop
#     disk's partition 1 as the ESP
r=0
im=$rel/mkosi.extra/usr/lib/mastersos/installer-mount
grep -qE "^ +${im//./\\.}\$" .github/workflows/mastersos.yml || {
	bad 42 ".github/workflows/mastersos.yml image-lint should shellcheck $im"
	r=1
}
grep -qxF '      - run: bash image/tests/installer-mount-test.sh' .github/workflows/mastersos.yml || {
	bad 42 ".github/workflows/mastersos.yml image-lint should run tests/installer-mount-test.sh"
	r=1
}
grep -qF 'mastersos-ventoy-part1' "$im" || {
	bad 42 "$im should take the ESP from /dev/disk/by-loop-ref/mastersos-ventoy-part1 in Ventoy mode"
	r=1
}
[ "$r" = 0 ] && ok 42 "installer-mount is linted and tested in CI and mounts the loop disk's partition 1 as the ESP in Ventoy mode"

# 43. Volume names MokManager shows (Ventoy installer Task 4): both ESP definitions carry Label=MASTERSOS (the FAT label the technician
#     picks under "Enroll key from disk"), the golden ESP keeps its GPT label; its Flags=0x2 (GPT attribute bit 1) is kept as intent only,
#     because systemd-repart v259 does not write it, so the golden ESP is NOT hidden from firmware (the finish screen's text guards it).
r=0
for f in installer/install.repart.d/00-esp.conf mkosi.extra/usr/lib/repart.d/00-esp.conf; do
	grep -qx 'Label=MASTERSOS' "$rel/$f" 2>/dev/null || {
		bad 43 "$f should have Label=MASTERSOS"
		r=1
	}
done
g=$rel/installer/install.repart.d/28-golden-esp.conf
grep -qx 'Label=mastersos-golden-esp' "$g" 2>/dev/null || {
	bad 43 "$g should keep Label=mastersos-golden-esp (GPT name)"
	r=1
}
grep -qx 'Flags=0x2' "$g" 2>/dev/null || {
	bad 43 "$g should keep Flags=0x2 (GPT attribute bit 1; intent only, ineffective under systemd-repart v259)"
	r=1
}
[ "$r" = 0 ] && ok 43 "ESP is labelled MASTERSOS and the golden ESP keeps its GPT label and Flags=0x2 (intent only; not hidden from firmware under repart v259)"

# 44. Ventoy installer UKI's command line (Ventoy installer Task 5): installer/ventoy.cmdline (what make-installer.sh adds to
#     installer.cmdline) fills in the version and size of the system file (no sha256 since 2026-10-29) and the main UKI's
#     usrhash=, points the /usr verity devices at the attached loop disk, masks usr-repair, and never uses gpt-auto's
#     mount.usr=dissect
r=0
vc=$rel/installer/ventoy.cmdline
vcl=$(sed 's/#.*//' "$vc" 2>/dev/null | tr -s '[:space:]' '\n' | sed '/^$/d')
if grep -q '^mastersos\.ventoy_sha256=' <<<"$vcl"; then
	bad 44 "$vc must not have mastersos.ventoy_sha256= (the initrd no longer hashes the system file)"
	r=1
fi
for l in mount.usr=/dev/mapper/usr usrhash=@USRHASH@ mastersos.ventoy=@VERSION@ mastersos.ventoy_size=@SIZE@ \
	rd.systemd.mask=mastersos-usr-repair.service \
	systemd.verity_usr_data=/dev/disk/by-loop-ref/mastersos-ventoy-part4 \
	systemd.verity_usr_hash=/dev/disk/by-loop-ref/mastersos-ventoy-part3; do
	grep -qxF -- "$l" <<<"$vcl" || {
		bad 44 "$vc should have $l"
		r=1
	}
done
if grep -q '^mount\.usr=dissect$' <<<"$vcl"; then
	bad 44 "$vc must not have mount.usr=dissect (the Ventoy UKI mounts /usr from the loop disk, not through gpt-auto)"
	r=1
fi
# shellcheck disable=SC2016 # literal ${version}: the source text being looked for
if ! grep -qF 'installer/ventoy.cmdline' "$rel/make-installer.sh" ||
	! grep -qF 'MastersOS-ventoy_${version}_x86-64.zip' "$rel/make-installer.sh"; then
	bad 44 "make-installer.sh should build the Ventoy UKI from installer/ventoy.cmdline and the MastersOS-ventoy_<v>_x86-64.zip"
	r=1
fi
[ "$r" = 0 ] && ok 44 "ventoy.cmdline pins the system file and usrhash=, points /usr at the loop disk and masks usr-repair"

# 45. Wi-Fi needs wpa_supplicant: NetworkManager only Recommends wpasupplicant and mkosi installs no Recommends, so 20261029.1
#     had Wi-Fi that never found a network (Dell Latitude 3420, AX201). mkosi.conf lists it; build.sh checks the built image.
r=0
grep -qE '^ +wpasupplicant$' "$rel/mkosi.conf" || {
	bad 45 "mkosi.conf's Packages= should have wpasupplicant (NetworkManager only Recommends it; without it Wi-Fi cannot scan)"
	r=1
}
# shellcheck disable=SC2016 # literal $usr_list: the source text being looked for
grep -qF 'grep -qxE "/?usr/s?bin/wpa_supplicant" <<<"$usr_list"' "$rel/build.sh" || {
	bad 45 "build.sh should check that the built image has wpa_supplicant"
	r=1
}
[ "$r" = 0 ] && ok 45 "wpasupplicant is in mkosi.conf's Packages= and build.sh checks the image has wpa_supplicant"

# 46. The wait for the web browser (offline status Task 4, design §3–4): browser-wait is executable, linted and tested in CI; the
#     user unit is pulled in only by the regular desktop sessions' targets (ubuntu from ubuntu-session, gnome from gnome-session)
#     through Wants= drop-ins that are plain files, never by gnome-session.target or the template gnome-session@.target, which the
#     locked-app session (gnome-session@mastersos-kiosk.target) reaches too, and never by a link; the script also skips kiosk-*
#     accounts and reads the public session-mode that exec_block.rs writes
r=0
bw=$rel/mkosi.extra/usr/lib/mastersos/browser-wait
bwu=$rel/mkosi.extra/usr/lib/systemd/user
if [ ! -x "$bw" ] || [ "$(git ls-files -s -- "$bw" | cut -c1-6)" = 100644 ]; then
	bad 46 "$bw should exist and be executable"
	r=1
fi
grep -qE "^ +${bw//./\\.}\$" .github/workflows/mastersos.yml || {
	bad 46 ".github/workflows/mastersos.yml image-lint should shellcheck $bw"
	r=1
}
grep -qxF '      - run: bash image/tests/browser-wait-test.sh' .github/workflows/mastersos.yml || {
	bad 46 ".github/workflows/mastersos.yml image-lint should run tests/browser-wait-test.sh"
	r=1
}
for l in 'kiosk-*) exit 0 ;;' 'zenity --progress --pulsate --no-cancel --auto-close --title=MastersOS'; do
	grep -qF -- "$l" "$bw" 2>/dev/null || {
		bad 46 "$bw should have: $l"
		r=1
	}
done
# shellcheck disable=SC2016 # literal $public: the source text being looked for
if ! grep -qF '"$public/session-mode"' "$bw" 2>/dev/null ||
	! grep -qxF 'pub const SESSION_MODE_FILE: &str = "session-mode";' "$core/mastersos-agent/src/system/exec_block.rs"; then
	bad 46 "$bw should read \$public/session-mode, the file exec_block.rs's SESSION_MODE_FILE names"
	r=1
fi
for l in 'PartOf=gnome-session.target' 'After=gnome-session.target' 'ConditionUser=!@system' 'Type=simple' \
	'ExecStart=/usr/lib/mastersos/browser-wait' 'Restart=no'; do
	grep -qxF -- "$l" "$bwu/mastersos-browser-wait.service" 2>/dev/null || {
		bad 46 "$bwu/mastersos-browser-wait.service should have the line: $l"
		r=1
	}
done
if grep -qxF '[Install]' "$bwu/mastersos-browser-wait.service" 2>/dev/null; then
	bad 46 "$bwu/mastersos-browser-wait.service must have no [Install] (drop-ins pull it in)"
	r=1
fi
for s in ubuntu gnome; do
	d=$bwu/gnome-session@$s.target.d/mastersos-browser-wait.conf
	if [ -L "$d" ] || [ ! -f "$d" ] || ! grep -qxF 'Wants=mastersos-browser-wait.service' "$d"; then
		bad 46 "$d should be a plain file with Wants=mastersos-browser-wait.service"
		r=1
	fi
done
while IFS= read -r x; do
	bad 46 "$x pulls in mastersos-browser-wait.service, which the locked-app session would then start too"
	r=1
done < <(grep -lF mastersos-browser-wait "$bwu"/gnome-session.target.d/* "$bwu"/gnome-session@.target.d/* \
	"$bwu"/gnome-session@mastersos-kiosk.target.d/* 2>/dev/null || true)
while IFS= read -r x; do
	bad 46 "$x: mastersos-browser-wait.service is enabled by drop-ins, not links"
	r=1
done < <(find "$bwu" -type l -name 'mastersos-browser-wait*' | LC_ALL=C sort)
[ "$r" = 0 ] && ok 46 "browser-wait is executable, linted and tested in CI; only the ubuntu and gnome session targets pull it in (plain drop-ins), not the kiosk session"

# 47. gnome-shell extensions (phase B Task 13): the login-screen and quick-settings extensions are in /usr with a metadata uuid equal to the
#     directory name and shell-version covering GNOME 50 (the version the image is built with: spike 2026-10-30, gnome-shell 50.1); the greeter
#     runs in the custom mode mastersos-gdm (mode JSON + user-unit drop-in forcing --mode); postinst adds the managed uuid to ubuntu.json and
#     checks it (the locked learning profile only loads extensions listed in the session-mode JSON).
r=0
gs=$ex/usr/share/gnome-shell
for u in mastersos-login@mastersos.org mastersos-managed@mastersos.org; do
	d=$gs/extensions/$u
	for f in metadata.json extension.js stylesheet.css; do
		[ -f "$d/$f" ] || {
			bad 47 "$d/$f is missing"
			r=1
		}
	done
	jq -e --arg u "$u" '.uuid == $u and (."shell-version" | index("50"))' "$d/metadata.json" >/dev/null 2>&1 || {
		bad 47 "$d/metadata.json should be valid JSON with uuid $u (the directory name) and shell-version containing \"50\""
		r=1
	}
done
jq -e '(."session-modes" | index("gdm")) and (."session-modes" | index("mastersos-gdm"))' "$gs/extensions/mastersos-login@mastersos.org/metadata.json" >/dev/null 2>&1 || {
	bad 47 "mastersos-login's metadata.json should declare session-modes gdm and mastersos-gdm"
	r=1
}
jq -e '.parentMode == "gdm" and .allowExtensions == true and (.enabledExtensions | index("mastersos-login@mastersos.org"))' "$gs/modes/mastersos-gdm.json" >/dev/null 2>&1 || {
	bad 47 "$gs/modes/mastersos-gdm.json should have parentMode gdm, allowExtensions true and enable mastersos-login@mastersos.org"
	r=1
}
dropin=$ex/usr/lib/systemd/user/org.gnome.Shell@gdm.service.d/50-mastersos-mode.conf
grep -qxF 'ExecStart=/usr/bin/gnome-shell --mode=mastersos-gdm' "$dropin" 2>/dev/null || {
	bad 47 "$dropin should reset ExecStart and run gnome-shell --mode=mastersos-gdm"
	r=1
}
# shellcheck disable=SC2016 # literal $mu: the source text being looked for
if ! grep -qF '.enabledExtensions |= (. - [$u] + [$u])' "$rel/mkosi.postinst.chroot" || ! grep -qF 'mu=mastersos-managed@mastersos.org' "$rel/mkosi.postinst.chroot"; then
	bad 47 "mkosi.postinst.chroot should add mastersos-managed@mastersos.org to ubuntu.json's enabledExtensions and check it"
	r=1
fi
[ "$r" = 0 ] && ok 47 "gnome-shell extensions: both in /usr (uuid = directory, shell-version 50), greeter mode mastersos-gdm with drop-in, postinst adds the managed uuid to ubuntu.json"

# 48. AppArmor waits for /etc (device trial 2026-10-31): /etc/apparmor.d is a tmpfiles symlink into the factory tree, so apparmor.service
#     must be ordered after systemd-tmpfiles-setup.service — otherwise the first boot loads no profile and the userns restriction kills
#     Chrome's sandbox.
r=0
aa=$ex/usr/lib/systemd/system/apparmor.service.d/50-mastersos-after-tmpfiles.conf
if ! grep -qxF 'After=systemd-tmpfiles-setup.service' "$aa" 2>/dev/null || ! grep -qxF '[Unit]' "$aa"; then
	bad 48 "$aa should order apparmor.service After=systemd-tmpfiles-setup.service in [Unit]"
	r=1
fi
[ "$r" = 0 ] && ok 48 "apparmor.service is ordered after systemd-tmpfiles-setup.service (first boot loads the profiles)"

# 49. The login screen's sign-in card (design 2026-10-31): the broker runs the authorization code flow, the card's browser is a system
#     unit with its own Chrome policy directory and a polkit rule limited to that unit and to gdm-greeter, the script is linted in CI,
#     the agent's redirect filter equals the patch's redirect, and build.sh pins gnome-shell (the extension patches its private code).
r=0
le=$gs/extensions/mastersos-login@mastersos.org
for f in area.js brand.js card.js help-model.js help.js people.js setup.js shelf.js strings.js watch.js; do
	[ -f "$le/$f" ] || {
		bad 49 "$le/$f is missing"
		r=1
	}
done
grep -qxF 'Environment=MASTERSOS_AUTH_CODE=1' "$ex/usr/lib/systemd/system/authd-oidc.service.d/50-mastersos-auth-code.conf" 2>/dev/null || {
	bad 49 "authd-oidc.service needs the drop-in with MASTERSOS_AUTH_CODE=1"
	r=1
}
lbu=$ex/usr/lib/systemd/system/mastersos-login-browser@.service
for l in 'User=%i' 'ExecStart=/usr/lib/mastersos/login-browser' 'PrivateTmp=yes' 'ProtectSystem=strict' \
	'BindReadOnlyPaths=/var/lib/mastersos-public/login-browser/policies:/etc/opt/chrome/policies/managed' \
	'AppArmorProfile=mastersos-login-browser' \
	'ConditionPathExists=/var/lib/mastersos-public/login-browser/policies/mastersos-login.json'; do
	grep -qxF "$l" "$lbu" 2>/dev/null || {
		bad 49 "$lbu should have $l"
		r=1
	}
done
[ -x "$ex/usr/lib/mastersos/login-browser" ] || {
	bad 49 "$ex/usr/lib/mastersos/login-browser should be executable"
	r=1
}
# The unit fails closed on a missing profile, the profile is in enforce mode and only ever runs Chrome's own binaries
lbp=$ex/etc/apparmor.d/mastersos-login-browser
if ! grep -qxF 'profile mastersos-login-browser flags=(attach_disconnected) {' "$lbp" 2>/dev/null ||
	grep -qE 'complain|unconfined\)|^ *[^#]*\b[pPcCuU]x\b' "$lbp" || grep -qE '^ *(/\*\*|/) +' "$lbp"; then
	bad 49 "$lbp should exist in enforce mode with no way out (no complain, unconfined or px/ux rule, no blanket path)"
	r=1
fi
grep -qE '^ +image/mkosi\.extra/usr/lib/mastersos/login-browser$' .github/workflows/mastersos.yml || {
	bad 49 "the workflow should shellcheck login-browser"
	r=1
}
lbr=$ex/usr/share/polkit-1/rules.d/49-mastersos-login-browser.rules
if ! grep -qF '"mastersos-login-browser@" + subject.user + ".service"' "$lbr" 2>/dev/null || ! grep -qF '/^gdm-greeter(-[0-9]+)?$/' "$lbr" ||
	! grep -qF '"org.freedesktop.systemd1.manage-units"' "$lbr"; then
	bad 49 "$lbr should allow only the greeter's users, each only its own instance of that unit"
	r=1
fi
{ grep -qF 'authCodeRedirect = "http://127.0.0.1:48123/callback"' "$rel/patches/authd-oidc/0003-authorization-code-on-greeter.patch" 2>/dev/null &&
	grep -qF 'LOGIN_REDIRECT_FILTER: &str = "127.0.0.1:48123/callback"' "$core/mastersos-agent/src/system/login.rs" 2>/dev/null; } || {
	bad 49 "the redirect in patch 0003 and LOGIN_REDIRECT_FILTER in login.rs should be the same address"
	r=1
}
grep -qE '^gnome_shell_pin=[0-9]' "$rel/build.sh" || {
	bad 49 "build.sh should pin gnome-shell (gnome_shell_pin)"
	r=1
}
grep -qF 'UnlockDialog.prototype._onReset = function () {};' "$ex/usr/share/gnome-shell/extensions/mastersos-managed@mastersos.org/session.js" 2>/dev/null || {
	bad 49 "a locked school desktop must not begin a sign-in: the broker's fixed port would end the card open on the login screen"
	r=1
}
[ "$r" = 0 ] && ok 49 "sign-in card: auth code drop-in, browser unit with its own policy directory and AppArmor profile, polkit limited to it, redirect matches the agent, gnome-shell pinned"

# 50. Language and keyboard from the login screen (design 2026-11-01): the greeter may set exactly those two polkit actions; localed can
#     write the keymap (Ubuntu blocks SetX11Keyboard with a D-Bus policy file and keeps xorg.conf.d read-only for localed, and /etc/X11 must not
#     be the read-only factory link); the image carries every Ubuntu language pack and generates every UTF-8 locale; each pack's language
#     has a complete catalogue.
r=0
llr=$ex/usr/share/polkit-1/rules.d/49-mastersos-login-language.rules
for l in '"org.freedesktop.locale1.set-locale"' '"org.freedesktop.locale1.set-keyboard"' '/^gdm-greeter(-[0-9]+)?$/'; do
	grep -qF "$l" "$llr" 2>/dev/null || {
		bad 50 "$llr should have $l"
		r=1
	}
done
if [ "$(grep -c 'action.id' "$llr")" != 1 ]; then
	bad 50 "$llr should look at two actions on one line and no others"
	r=1
fi
for l in 'dir /etc/X11' 'dir /etc/X11/xorg.conf.d'; do
	grep -qxF "$l" "$rel/etc-policy.conf" || {
		bad 50 "etc-policy.conf should have $l (localed writes 00-keyboard.conf there)"
		r=1
	}
done
for l in /usr/share/dbus-1/system.d/org.freedesktop.locale1.read-only.conf /usr/lib/systemd/system/systemd-localed.service.d/x11-keyboard.conf; do
	grep -qF "$l" "$rel/mkosi.conf" || {
		bad 50 "mkosi.conf should remove $l: with it localectl set-x11-keymap is refused"
		r=1
	}
done
[ "$(grep -cE '^ +language-pack-[a-z-]+$' "$rel/mkosi.conf")" -ge 170 ] || {
	bad 50 "mkosi.conf should list every language pack, plain and gnome (85 languages in resolute)"
	r=1
}
grep -qF '/usr/share/i18n/SUPPORTED' "$rel/mkosi.postinst.chroot" || {
	bad 50 "mkosi.postinst.chroot should generate every UTF-8 locale"
	r=1
}
if ! why=$(python3 -I - "$rel/login-i18n" "$rel/mkosi.conf" <<'CATALOGUES'
import glob, os, re, sys

def entries(path):
    text = open(path, encoding="utf-8").read()
    pairs = re.findall(r'^msgid "(.*)"\nmsgstr "(.*)"$', text, re.M)
    return {k: v for k, v in pairs if k}

d, conf = sys.argv[1:]
want = entries(os.path.join(d, "mastersos-login.pot"))
packs = set(re.findall(r"^ +language-pack-([a-z-]+)$", open(conf).read(), re.M))
packs = {p for p in packs if not p.startswith("gnome-") and not p.endswith("-base")} - {"en"}
names = {"zh-hans": "zh_CN", "zh-hant": "zh_TW"}
errs = []
for pack in sorted(packs):
    po = os.path.join(d, names.get(pack, pack) + ".po")
    if not os.path.exists(po):
        errs.append(f"{pack}: no catalogue")
        continue
    got = entries(po)
    for k in want:
        v = got.get(k, "")
        if not v.strip():
            errs.append(f"{pack}: {k!r} not translated")
        elif v.count("%s") != k.count("%s"):
            errs.append(f"{pack}: {k!r} has the wrong %s")
if errs:
    print("; ".join(errs[:6]), f"({len(errs)} in all)")
    sys.exit(1)
CATALOGUES
); then
	bad 50 "login-i18n: $why"
	r=1
fi
# The agent's banner sentences are msgids: status.rs, strings.js and the template must list the same ones.
if ! why=$(python3 -I - "$core/mastersos-agent/src/status.rs" "$rel/mkosi.extra/usr/share/gnome-shell/extensions/mastersos-login@mastersos.org/strings.js" "$rel/login-i18n/mastersos-login.pot" <<'BANNER'
import re, sys

rs, js, pot = (open(p, encoding="utf-8").read() for p in sys.argv[1:])
names = re.search(r"BANNER_SENTENCES: \[&str; \d+\] = \[([^\]]*)\]", rs)
if not names:
    sys.exit("status.rs has no BANNER_SENTENCES")
consts = dict(re.findall(r'^const (MSG_[A-Z_]+): &str =\s*"([^"]*)";', rs, re.M))
want = [consts.get(n.strip(), "?" + n.strip()) for n in names.group(1).split(",") if n.strip()]
block = re.search(r"export const BANNER = \(\) => \[(.*?)\];", js, re.S)
got = re.findall(r"_\('([^']*)'\)", block.group(1)) if block else []
if sorted(want) != sorted(got):
    sys.exit(f"strings.js BANNER differs from status.rs BANNER_SENTENCES: {sorted(set(want) ^ set(got))}")
missing = [w for w in want if f'msgid "{w}"' not in pot]
if missing:
    sys.exit(f"not in mastersos-login.pot: {missing}")
BANNER
); then
	bad 50 "banner sentences: $why"
	r=1
fi
[ "$r" = 0 ] && ok 50 "language: polkit limited to the two actions, localed can write the keymap, every pack and locale in the image, catalogues present"

# 51. MastersOS brand assets (design 2026-11-04 visual identity §5.1): both wallpapers are 3840x2400, the logo exists at every size
#     (each PNG's side equals its directory), the scalable and symbolic SVGs are XML, the background properties point at the day
#     (light) and night (dark) wallpapers, every file:// path in the GNOME defaults exists in the tree, and the rendered assets
#     together stay under 15 MiB.
r=0
if ! why=$(python3 -I - "$ex" 2>&1 <<'BRAND'
import os, re, struct, sys
import xml.etree.ElementTree as ET
ex = sys.argv[1]
def size(path):
    b = open(path, "rb").read()
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        return struct.unpack(">II", b[16:24])
    if b[:2] == b"\xff\xd8":
        i = 2
        while i < len(b):
            if b[i] != 0xFF:
                break
            m = b[i + 1]
            ln = struct.unpack(">H", b[i + 2:i + 4])[0]
            if m in (0xC0, 0xC1, 0xC2):
                h, w = struct.unpack(">HH", b[i + 5:i + 9])
                return w, h
            i += 2 + ln
    raise ValueError(f"{path}: not a PNG or JPEG")
errs = []
bg = f"{ex}/usr/share/backgrounds/mastersos"
total = 0
for name in ("mastersos-day.jpg", "mastersos-night.jpg"):
    f = f"{bg}/{name}"
    if not os.path.isfile(f):
        errs.append(f"missing {f}")
        continue
    total += os.path.getsize(f)
    if size(f) != (3840, 2400):
        errs.append(f"{f} is {size(f)}, want (3840, 2400)")
icons = f"{ex}/usr/share/icons/hicolor"
for n in (16, 24, 32, 48, 64, 128, 256, 512):
    f = f"{icons}/{n}x{n}/apps/mastersos-logo.png"
    if not os.path.isfile(f):
        errs.append(f"missing {f}")
        continue
    total += os.path.getsize(f)
    if size(f) != (n, n):
        errs.append(f"{f} is {size(f)}, want ({n}, {n})")
for f in (f"{icons}/scalable/apps/mastersos-logo.svg", f"{icons}/symbolic/apps/mastersos-logo-symbolic.svg",
          f"{ex}/usr/share/mastersos/brand/wordmark-light.svg"):
    try:
        ET.parse(f)
        total += os.path.getsize(f)
    except Exception as e:
        errs.append(f"{f}: {e}")
props = f"{ex}/usr/share/gnome-background-properties/mastersos.xml"
try:
    w = ET.parse(props).getroot().find("wallpaper")
    want = {"filename": "/usr/share/backgrounds/mastersos/mastersos-day.jpg",
            "filename-dark": "/usr/share/backgrounds/mastersos/mastersos-night.jpg"}
    for k, v in want.items():
        got = w.findtext(k) if w is not None else None
        if got != v:
            errs.append(f"{props}: {k} is {got!r}, want {v!r}")
except Exception as e:
    errs.append(f"{props}: {e}")
over = f"{ex}/usr/share/glib-2.0/schemas/90_mastersos.gschema.override"
for u in re.findall(r"file://(/[^'\"]+)", open(over).read()):
    if not os.path.isfile(ex + u):
        errs.append(f"{over} refers to {u}, not in the tree")
text = open(over).read()
for want in ("[org.gnome.desktop.background]",
             "picture-uri='file:///usr/share/backgrounds/mastersos/mastersos-day.jpg'",
             "picture-uri-dark='file:///usr/share/backgrounds/mastersos/mastersos-night.jpg'",
             "picture-options='zoom'", "[org.gnome.desktop.interface]", "color-scheme='default'", "accent-color=",
             "transparency-mode='FIXED'", "background-opacity=", "custom-background-color=true", "background-color="):
    if want not in text:
        errs.append(f"{over} lacks {want}")
# Ubuntu's own defaults are desktop-specific ([schema:ubuntu], 10_ubuntu-dock and 10_ubuntu-settings), and those beat every
# plain [schema] override whatever the file order: each section here must have a :ubuntu twin with the same keys.
sections, cur = {}, None
for line in text.splitlines():
    m = re.match(r"^\[([^\]]+)\]$", line.strip())
    if m:
        cur = m.group(1)
        sections.setdefault(cur, [])
    elif cur and "=" in line and not line.lstrip().startswith("#"):
        sections[cur].append(line.strip())
for name, keys in sections.items():
    if name.endswith(":ubuntu") or name == "org.gnome.login-screen":
        continue
    twin = sections.get(name + ":ubuntu")
    if twin != keys:
        errs.append(f"{over}: [{name}] has no identical [{name}:ubuntu] (the Ubuntu session would use Ubuntu's values)")
post = open(os.path.join(os.path.dirname(ex), "mkosi.postinst.chroot")).read()
if 'XDG_CURRENT_DESKTOP=ubuntu:GNOME' not in post:
    errs.append("mkosi.postinst.chroot: the defaults are not read back as the Ubuntu session sees them (XDG_CURRENT_DESKTOP=ubuntu:GNOME)")
if "LOGO=mastersos-logo" not in post:
    errs.append("mkosi.postinst.chroot: os-release has no LOGO=mastersos-logo")
if total > 15 * 1024 * 1024:
    errs.append(f"brand assets are {total} bytes, over 15 MiB")
if errs:
    sys.exit("; ".join(errs))
BRAND
); then
	bad 51 "brand: $why"
	r=1
fi
[ "$r" = 0 ] && ok 51 "brand: wallpapers 3840x2400, logo at every size, background properties, GNOME defaults (light, wallpapers, translucent Dock), about logo, total under 15 MiB"

# 52. Boot splash (design 2026-11-04 visual identity §5.2): the mastersos two-step theme is in the image and in the initrd, the two
#     copies identical (the initrd is built from packages and does not see mkosi.extra); both trees make it the default theme; the
#     kernel command line has quiet and splash; the factory reset confirmation (it reads the keyboard in the initrd) quits Plymouth
#     first; the initrd gets Plymouth with the text label plugin (the recovery key prompt needs it); the installer keeps Plymouth off.
r=0
th=usr/share/plymouth/themes/mastersos
ix=$rel/mkosi.initrd.conf/mkosi.extra
if [ ! -f "$ex/$th/mastersos.plymouth" ]; then
	bad 52 "$ex/$th/mastersos.plymouth missing"
	r=1
else
	for k in 'ModuleName=two-step' "ImageDir=/$th" 'BackgroundStartColor=0x090a16' 'UseProgressBar=true' 'MessageBelowAnimation=true'; do
		grep -qxF -- "$k" "$ex/$th/mastersos.plymouth" || {
			bad 52 "mastersos.plymouth lacks $k"
			r=1
		}
	done
	for f in throbber-0001.png entry.png bullet.png lock.png; do
		[ -f "$ex/$th/$f" ] || {
			bad 52 "theme lacks $f"
			r=1
		}
	done
	# Plymouth's own keyboard pictures, linked from plymouth-theme-spinner (installed in both trees; postinst checks they resolve)
	for f in capslock.png keyboard.png keymap-render.png; do
		[ "$(readlink "$ex/$th/$f" 2>/dev/null)" = "../spinner/$f" ] || {
			bad 52 "theme's $f should link to ../spinner/$f"
			r=1
		}
	done
	if ! diff -r --no-dereference "$ex/$th" "$ix/$th" >/dev/null 2>&1; then
		bad 52 "the theme in mkosi.extra and in mkosi.initrd.conf/mkosi.extra differ"
		r=1
	fi
fi
for t in "$ex" "$ix"; do
	grep -qx 'Theme=mastersos' "$t/usr/share/plymouth/plymouthd.defaults" 2>/dev/null || {
		bad 52 "$t/usr/share/plymouth/plymouthd.defaults should have Theme=mastersos"
		r=1
	}
done
cmp -s "$ex/usr/share/plymouth/plymouthd.defaults" "$ix/usr/share/plymouth/plymouthd.defaults" || {
	bad 52 "the two plymouthd.defaults differ"
	r=1
}
for w in quiet splash; do
	sed -n '/^KernelCommandLine=/,/^[^[:space:]]/p' "$rel/mkosi.conf" | grep -qE "^[[:space:]]+$w$" || {
		bad 52 "mkosi.conf KernelCommandLine lacks $w"
		r=1
	}
done
for pkg in plymouth plymouth-label plymouth-theme-spinner; do
	grep -qx "Packages=$pkg" "$rel/mkosi.initrd.conf/mkosi.conf" || {
		bad 52 "mkosi.initrd.conf/mkosi.conf lacks Packages=$pkg"
		r=1
	}
done
# The confirmation asks through systemd-ask-password. Once Plymouth runs, the console agent's path unit was skipped at boot
# (ConditionPathExists=!/run/plymouth/pid) and the Plymouth agent has no daemon after the quit: hand the questions back to the
# console agent, or nobody can answer (and the recovery key prompt after keep_data hangs until emergency).
frc=$ix/usr/lib/systemd/system/mastersos-factory-reset-confirm.service
for k in 'ExecStartPre=-/usr/bin/plymouth --wait quit' \
	'ExecStartPre=-/usr/bin/systemctl --no-block stop systemd-ask-password-plymouth.path systemd-ask-password-plymouth.service' \
	'ExecStartPre=-/usr/bin/systemctl --no-block start systemd-ask-password-console.path'; do
	grep -qxF -- "$k" "$frc" || {
		bad 52 "mastersos-factory-reset-confirm.service lacks $k"
		r=1
	}
done
# The initrd failure message must not sit behind the splash (upstream's emergency.service quits Plymouth; our drop-in empties
# ExecStartPre= and must put the quit back).
grep -qxF 'ExecStartPre=-/usr/bin/plymouth --wait quit' "$ix/usr/lib/systemd/system/emergency.service.d/50-mastersos-reboot.conf" || {
	bad 52 "emergency.service.d/50-mastersos-reboot.conf does not quit Plymouth before its message"
	r=1
}
# usr-repair decides between Plymouth and the console with plymouth --ping: Plymouth must already be up when it asks
grep -qE '^After=.*\bplymouth-start\.service\b' "$ix/usr/lib/systemd/system/mastersos-usr-repair.service" || {
	bad 52 "mastersos-usr-repair.service is not ordered after plymouth-start.service"
	r=1
}
# Lab: with the serial console, Plymouth uses its text mode, which shows the prompts on ttyS0 and reads answers there (the
# acceptance scripts answer over serial). Only a screenshot build (MASTERSOS_LAB_SPLASH=1) adds plymouth.ignore-serial-consoles.
if grep -qE '^KernelCommandLine=.*plymouth\.ignore-serial-consoles' "$rel/mkosi.profiles/lab.conf"; then
	bad 52 "mkosi.profiles/lab.conf must not hide the serial console from Plymouth (acceptance answers prompts over serial)"
	r=1
fi
if ! grep -qF -- '--kernel-command-line=plymouth.ignore-serial-consoles' "$rel/build.sh" || ! grep -qF 'MASTERSOS_LAB_SPLASH' "$rel/build.sh"; then
	bad 52 "build.sh has no MASTERSOS_LAB_SPLASH=1 switch for the screenshot build"
	r=1
fi
grep -qx 'plymouth.enable=0' "$rel/installer/installer.cmdline" || {
	bad 52 "installer.cmdline must keep plymouth.enable=0"
	r=1
}
[ "$r" = 0 ] && ok 52 "boot splash: mastersos two-step theme in the image and the initrd (identical), default theme, quiet splash, factory reset confirm quits plymouth, installer keeps plymouth off"

# 53. Login screen and lock screen look (design 2026-11-04 visual identity §5.4–5.5): the login background is the night picture,
#     both extensions put the MastersOS mark (class mastersos-brand-corner) in the top bar, no Google-blue focus ring is left in
#     their styles, and the locked app's error page uses the brand colours.
r=0
gse=$ex/usr/share/gnome-shell/extensions
lcss=$gse/mastersos-login@mastersos.org/stylesheet.css
grep -qF 'background-image: url("file:///usr/share/backgrounds/mastersos/mastersos-night.jpg");' "$lcss" || {
	bad 53 "$lcss: .mastersos-login-background has no night picture"
	r=1
}
grep -qF 'background-size: cover;' "$lcss" || {
	bad 53 "$lcss: the background is not background-size: cover"
	r=1
}
for e in mastersos-login@mastersos.org mastersos-managed@mastersos.org; do
	grep -qF "mastersos-brand-corner" "$gse/$e/extension.js" || {
		bad 53 "$e does not add the MastersOS mark (mastersos-brand-corner)"
		r=1
	}
	if grep -qiE '#8ab4f8|#0b57d0|#0842a0|#a8c7fa|138, 180, 248' "$gse/$e/stylesheet.css"; then
		bad 53 "$e/stylesheet.css still has the old blue"
		r=1
	fi
done
# The desktop runs the ubuntu session mode (parentMode user), so currentMode alone never matches; the overview keeps GNOME's bar
mext=$gse/mastersos-managed@mastersos.org
grep -qF "Main.sessionMode.parentMode === 'user'" "$mext/extension.js" || {
	bad 53 "mastersos-managed: the translucent top bar only checks currentMode === 'user' (the desktop's mode is ubuntu)"
	r=1
}
grep -qF '#panel.mastersos-panel:overview' "$mext/stylesheet.css" || {
	bad 53 "mastersos-managed/stylesheet.css: the overview's top bar is not left as GNOME has it"
	r=1
}
# The mark is small and at 85 % opacity (design §5.4)
for f in "$gse/mastersos-login@mastersos.org/brand.js" "$mext/extension.js"; do
	grep -qF 'opacity: 217' "$f" || {
		bad 53 "$f: the MastersOS mark is not at 85 % opacity (opacity: 217)"
		r=1
	}
done
grep -qF 'background: #090a16' "$ex/usr/share/mastersos/kiosk-error.html" || {
	bad 53 "kiosk-error.html does not use the brand background #090a16"
	r=1
}
[ "$r" = 0 ] && ok 53 "login and lock: night wallpaper background, MastersOS mark in the top bar of both, no old blue left, kiosk error page uses brand colours"

# 54. Look details (final review minors, design 2026-11-04 visual identity): white text on every solid button background in the
#     login styles reads at 4.5:1 or more (WCAG AA); no background-position keyword St does not know; the school card's
#     background is darkened like the username step; the icon cache rebuild cannot be skipped; the splash's English-only titles
#     are marked as such; the MastersOS mark (code and styles) is the same in both extensions; build.sh checks that the initrd
#     really starts Plymouth (its wants links).
r=0
if ! why=$(python3 -I - "$gse" "$rel" 2>&1 <<'LOOK'
import re, sys
gse, rel = sys.argv[1], sys.argv[2]
errs = []
def lum(h):
    c = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    c = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]
css = {e: open(f"{gse}/{e}/stylesheet.css").read() for e in ("mastersos-login@mastersos.org", "mastersos-managed@mastersos.org")}
for sel, body in re.findall(r"([^{}]+)\{([^}]*)\}", css["mastersos-login@mastersos.org"]):
    fg = re.search(r"(?<![-\w])color:\s*#([0-9a-fA-F]{6})", body)
    bg = re.search(r"background-color:\s*#([0-9a-fA-F]{6})", body)
    if fg and bg and fg.group(1).lower() == "ffffff":
        ratio = (1.05) / (lum(bg.group(1)) + 0.05)
        if ratio < 4.5:
            errs.append(f"{sel.strip()}: white on #{bg.group(1)} is {ratio:.2f}:1, under 4.5:1")
for e, text in css.items():
    if re.search(r"background-position:\s*(center|top|bottom|left|right)", text):
        errs.append(f"{e}/stylesheet.css: St's background-position takes lengths only")
login = css["mastersos-login@mastersos.org"]
if ".mastersos-card-scrim-shade" not in login or "mastersos-card-scrim-shade" not in open(f"{gse}/mastersos-login@mastersos.org/card.js").read():
    errs.append("the school card's background has no darkening layer (mastersos-card-scrim-shade)")
def rule(text, name):
    m = re.search(r"(^|\n)" + re.escape(name) + r"\s*\{[^}]*\}", text)
    return m.group(0).strip() if m else None
for name in (".mastersos-brand-corner", ".mastersos-brand-wordmark"):
    a, b = rule(login, name), rule(css["mastersos-managed@mastersos.org"], name)
    if not a or a != b:
        errs.append(f"{name} differs between the two extensions' styles")
def brand(text):
    m = re.search(r"function brandMark\(\) \{.*?\n\}", text, re.S)
    return m.group(0) if m else None
a = brand(open(f"{gse}/mastersos-login@mastersos.org/brand.js").read())
b = brand(open(f"{gse}/mastersos-managed@mastersos.org/extension.js").read())
if not a or a.replace("export ", "") != b:
    errs.append("brandMark() differs between mastersos-login/brand.js and mastersos-managed/extension.js")
post = open(f"{rel}/mkosi.postinst.chroot").read()
if "command -v gtk-update-icon-cache" in post or not re.search(r"^gtk-update-icon-cache -f -q /usr/share/icons/hicolor$", post, re.M):
    errs.append("mkosi.postinst.chroot: gtk-update-icon-cache must always run (a stale cache hides mastersos-logo)")
ply = open(f"{rel}/brand/mastersos.plymouth").read()
if "English only" not in ply:
    errs.append("brand/mastersos.plymouth: the fixed titles are not marked English only")
build = open(f"{rel}/build.sh").read()
for f in ("usr/lib/systemd/system/sysinit.target.wants/plymouth-start.service",
          "usr/lib/systemd/system/initrd-switch-root.target.wants/plymouth-start.service"):
    if f not in build:
        errs.append(f"build.sh does not check the initrd for {f}")
if errs:
    sys.exit("; ".join(errs))
LOOK
); then
	bad 54 "look: $why"
	r=1
fi
[ "$r" = 0 ] && ok 54 "look details: white button text at 4.5:1, St-valid background-position, darkened card background, icon cache always rebuilt, English-only splash titles marked, one MastersOS mark in both extensions, initrd starts Plymouth"

# 55. snapshot.ubuntu.com is often down (5xx, 401): the package lists of one snapshot never change and every package is checked
#     against them, so builds keep what they downloaded. The build host reuses a snapshot's cached lists (--cache-only=metadata)
#     but never in CI; CI keeps only the packages between runs (actions/cache restore and save, pinned by commit, saved even when
#     the build fails), never mkosi.cache with the lists: a release build always fetches and verifies fresh signed lists.
r=0
bsh=$rel/build.sh
wf=$rel/../.github/workflows/mastersos-image.yml
for k in '--cache-only=metadata' 'GITHUB_ACTIONS' '--package-cache-directory=' 'MASTERSOS_PACKAGE_CACHE'; do
	grep -qF -- "$k" "$bsh" || {
		bad 55 "build.sh lacks $k"
		r=1
	}
done
for a in restore save; do
	grep -qE "uses: actions/cache/$a@[0-9a-f]{40} " "$wf" || {
		bad 55 "mastersos-image.yml does not use actions/cache/$a pinned by commit"
		r=1
	}
done
if grep -A6 'actions/cache/' "$wf" | grep -qE '^\s+path:.*mkosi\.cache'; then
	bad 55 "mastersos-image.yml must not cache mkosi.cache (the package lists) for a release build"
	r=1
fi
# The restored cache is verified against the signed index before the build, and the verifier does what it says
order=$(grep -nE 'actions/cache/restore@|name: Verify the package cache|name: Build$' "$wf" | cut -d: -f1 | tr '\n' ' ')
read -r o_restore o_verify o_build _ <<<"$order"
if [ -z "${o_build:-}" ] || ! [ "$o_restore" -lt "$o_verify" ] || ! [ "$o_verify" -lt "$o_build" ]; then
	bad 55 "mastersos-image.yml must verify the restored package cache (ci-verify-package-cache.py) between restore and Build"
	r=1
fi
grep -qF 'image/ci-verify-package-cache.py' "$wf" || {
	bad 55 "mastersos-image.yml does not run image/ci-verify-package-cache.py"
	r=1
}
if ! out=$(bash "$rel/tests/verify-package-cache-test.sh" 2>&1); then
	bad 55 "verify-package-cache-test: $out"
	r=1
fi
grep -qF 'MASTERSOS_PACKAGE_CACHE' "$wf" || {
	bad 55 "mastersos-image.yml does not hand the package cache to build.sh (MASTERSOS_PACKAGE_CACHE)"
	r=1
}
[ "$r" = 0 ] && ok 55 "package cache: the build host reuses a snapshot's lists, CI keeps only packages between runs and verifies them against the signed index"

# 56. The lab build host (lab/build-host.sh packages) installs every package the CI runner adds for mkosi (ci-runner-setup.sh):
#     VM 121 lacked erofs-utils and its builds failed at "mkfs.erofs binary not available" after a full download, and its
#     check lists mkfs.erofs so `build-host.sh check` reports it.
r=0
bh=$rel/lab/build-host.sh
read -ra bh_pkgs <<<"$(sed -n 's/^packages=(\(.*\))$/\1/p' "$bh")"
ci_pkgs=$(sed -n '/^sudo apt-get install -y -qq /,/[^\\]$/p' "$rel/ci-runner-setup.sh" | sed 's/[\]//g' | tr -s ' \t' '\n' | grep -E '^[a-z0-9][a-z0-9.+-]+$' | grep -vxE 'sudo|apt-get|install')
if [ -z "$ci_pkgs" ] || [ "${#bh_pkgs[@]}" = 0 ]; then
	bad 56 "cannot read the package lists of ci-runner-setup.sh and lab/build-host.sh"
	r=1
fi
for p in $ci_pkgs; do
	printf '%s\n' "${bh_pkgs[@]}" | grep -qxF "$p" || {
		bad 56 "lab/build-host.sh packages lacks $p (ci-runner-setup.sh installs it for mkosi)"
		r=1
	}
done
grep -qE '^commands=\(.* mkfs\.erofs( |\))' "$bh" || {
	bad 56 "lab/build-host.sh check does not look for mkfs.erofs"
	r=1
}
[ "$r" = 0 ] && ok 56 "lab build host installs every package the CI runner adds for mkosi"

# 57. Plymouth two-step defaults UseAnimation to !UseProgressBar (plugin.c, "for compat. with older themes"): a section that turns
#     the progress bar on without UseAnimation=true hides the throbber, and the 20261104.6 splash showed only the bar, no M.
#     Every theme copy states UseAnimation in each section that shows the splash on boot, shutdown and reboot.
r=0
for f in "$rel/brand/mastersos.plymouth" "$rel/mkosi.extra/usr/share/plymouth/themes/mastersos/mastersos.plymouth" \
	"$rel/mkosi.initrd.conf/mkosi.extra/usr/share/plymouth/themes/mastersos/mastersos.plymouth"; do
	for s in boot-up shutdown reboot; do
		v=$(awk -v s="[$s]" '$0 == s {in_s = 1; next} /^\[/ {in_s = 0} in_s && /^UseAnimation=/ {sub(/^UseAnimation=/, ""); print}' "$f")
		[ "$v" = true ] || {
			bad 57 "${f#"$rel"/} [$s] lacks UseAnimation=true (two-step hides the M when the progress bar is on)"
			r=1
		}
	done
done
[ "$r" = 0 ] && ok 57 "boot splash: the M animation is on in every boot, shutdown and reboot section"

# 58. GDM's screen shield calls LoginDialog.activate() (show() and key focus on the user list) whenever the greeter wakes from
#     idle blanking (screenShield.js _ensureUnlockDialog, _showLockScreen). On 20261104.6 the first-run language screen then
#     had the login card showing through it. The extension hides the dialog again while the language screen is up, gives the
#     keys back to the language list, and undoes the handler on disable.
r=0
ld=$rel/mkosi.extra/usr/share/gnome-shell/extensions/mastersos-login@mastersos.org
adopt=$(awk '/^    _adoptDialog\(dlg\) \{/ {on = 1} on {print} on && /^    \}$/ {exit}' "$ld/extension.js")
if ! grep -qF "dlg.connect('notify::visible'" <<<"$adopt" || ! grep -qF 'this._language.focus()' <<<"$adopt" ||
	! grep -qE 'this\._restore\.push\(\(\) => dlg\.disconnect\(' <<<"$adopt"; then
	bad 58 "extension.js _adoptDialog does not keep the login dialog hidden behind the language screen (notify::visible, focus, undo)"
	r=1
fi
grep -qE '^    focus\(\) \{' "$ld/setup.js" || {
	bad 58 "setup.js LanguageScreen has no focus()"
	r=1
}
[ "$r" = 0 ] && ok 58 "first-run language screen: the login dialog stays hidden when the greeter wakes from idle"

# 59. GDM builds the login dialog and asks for the user name the stock way ("Username", a back arrow) before the extension is
#     enabled, so the patched _askForUsernameAndBeginVerification only runs from the next reset on: on 20261104.6 every fresh
#     greeter (boot, after the language screen) opened on GNOME's step until Escape. _adoptDialog resets a prompt that is not
#     on our step (its hint is not text.email) to a new username step, the path Escape takes.
r=0
adopt=$(awk '/^    _adoptDialog\(dlg\) \{/ {on = 1} on {print} on && /^    \}$/ {exit}' "$ld/extension.js")
if ! grep -qF 'hint_text !== this._text.email' <<<"$adopt" ||
	! grep -qF 'reset({beginRequestType: AuthPrompt.BeginRequestType.PROVIDE_USERNAME})' <<<"$adopt"; then
	bad 59 "extension.js _adoptDialog does not move a dialog that started on GNOME's username step to ours"
	r=1
fi
[ "$r" = 0 ] && ok 59 "login: a fresh greeter opens on the MastersOS username step, not GNOME's"

# 60. The installer UKI boots systemd.unit=mastersos-installer.target, which pulls basic.target and so timers.target: on
#     20261104.6 mastersos-chrome.timer (and the NetworkManager hook) started the Chrome updater inside the installer and its
#     failure printed a red [FAILED] line over the installer screen. Every unit a timer in /usr starts must not run there.
r=0
for t in "$rel"/mkosi.extra/usr/lib/systemd/system/timers.target.wants/*.timer; do
	svc=$rel/mkosi.extra/usr/lib/systemd/system/$(basename "$t" .timer).service
	if ! grep -qxF 'ConditionKernelCommandLine=!systemd.unit=mastersos-installer.target' "$svc"; then
		bad 60 "$svc runs from a timer but is not kept out of the installer"
		r=1
	fi
done
[ "$r" = 0 ] && ok 60 "installer: timer-started services (Chrome, system update) do not run in the installer"

# 61. GNOME 50 gives the class login-dialog-prompt-layout to both the AuthPrompt (avatar and input) and its _inputWell
#     (authPrompt.js), so on 20261104 ".login-dialog .login-dialog-prompt-layout" (visual identity) drew a second bordered box
#     around the entry (and the "Local manager" link of the time) inside the card. Only the AuthPrompt, the login dialog's own child, is the card;
#     the entry keeps its warm focus ring.
r=0
if ! why=$(python3 -I - "$ld/stylesheet.css" 2>&1 <<'CARD'
import re, sys
css = re.sub(r"/\*.*?\*/", "", open(sys.argv[1]).read(), flags=re.S)
rules = [([x.strip() for x in sel.split(",")], body) for sel, body in re.findall(r"([^{}]+)\{([^}]*)\}", css)]
errs = []
card = [body for sels, body in rules if ".login-dialog > .login-dialog-prompt-layout" in sels]
if not card or not all(re.search(p, card[0]) for p in (r"border:\s*1px", r"background-color:", r"box-shadow:")):
    errs.append("no frosted card on .login-dialog > .login-dialog-prompt-layout (border, background, shadow)")
for sels, body in rules:
    for one in sels:
        if re.fullmatch(r"(.*\s)?\.login-dialog-prompt-layout", one) and ">" not in one and \
                re.search(r"(^|[;\s])(border|background|background-color|box-shadow)\s*:", body):
            errs.append(f"{one} also paints the inner input well")
focus = [body for sels, body in rules if sels == [".login-dialog .login-dialog-prompt-entry:focus"]]
if not focus or "box-shadow" not in focus[0] or "border-color" not in focus[0]:
    errs.append("the entry lost its focus ring (.login-dialog .login-dialog-prompt-entry:focus)")
if errs:
    sys.exit("; ".join(errs))
CARD
); then
	bad 61 "login card: $why"
	r=1
fi
[ "$r" = 0 ] && ok 61 "login: one card around avatar and entry, no inner box, entry focus ring kept"

# 62. Domain completion (design 2026-11-03 login single field §3): the school domains are offered as soon as a name is typed,
#     in the same list as the people under the entry (people.js suggestDomains, unit-tested in login-people-test.mjs), not in
#     a PopupMenu that only a trailing '@' opened: that menu took the keyboard and was a second list beside the people.
#     Enter on a selected address fills it in instead of signing in.
r=0
lx=$ld/extension.js
grep -qE "^import \{[^}]*suggestDomains[^}]*\} from './people.js';" "$lx" || {
	bad 62 "extension.js does not take the domain suggestions from people.js suggestDomains"
	r=1
}
if grep -qF "endsWith('@')" "$lx" || grep -qF '_showDomains' "$lx"; then
	bad 62 "extension.js still opens the school domains only on a trailing '@' (_showDomains)"
	r=1
fi
keys=$(awk '/key-press-event/ {on = 1} on {print} on && /^        \}\);$/ {exit}' "$lx")
if ! grep -qF 'Clutter.KEY_Return' <<<"$keys" || ! grep -qF '_fillAddress' <<<"$keys"; then
	bad 62 "extension.js: Enter on a selected school address does not fill it in (_fillAddress in the key handler)"
	r=1
fi
grep -qE '^export function suggestDomains\(' "$ld/people.js" || {
	bad 62 "people.js has no suggestDomains"
	r=1
}
[ "$r" = 0 ] && ok 62 "login: school domains offered while the name is typed, in the people list, Enter fills the address"

# 63. New settings reach a login screen that is already up (Dell, 2026-11-05): the agent wrote new allowed domains to
#     branding.json and a new locked app under kiosk/<id>/, and the greeter kept the old ones until it restarted, because the
#     extension read them only in enable(). watch.js watches the branding directory (branding.json is replaced by rename) and
#     the kiosk directory with each app's own directory (its files are written one level down, after the directory appears),
#     waits until the writes settle, and the extension then applies domains, "Managed by" and Apps; monitors and the timeout
#     go in disable().
r=0
lw=$ld/watch.js
if ! grep -qF 'monitor_directory(' "$lw" 2>/dev/null || ! grep -qF 'GLib.timeout_add(' "$lw" ||
	! grep -qF '.cancel()' "$lw" || ! grep -qF 'GLib.source_remove(' "$lw" || ! grep -qE '^export const SETTLE_MS = [345][0-9]{2};' "$lw"; then
	bad 63 "watch.js does not watch directories (and their subdirectories), coalesce with a 300-500 ms timeout and cancel on destroy"
	r=1
fi
grep -qE "^import \{[^}]*Watch[^}]*\} from './watch.js';" "$lx" || {
	bad 63 "extension.js does not use watch.js"
	r=1
}
grep -qE "new Watch\(\[[^]]*BRANDING_DIR[^]]*KIOSK_DIR|new Watch\(\[[^]]*KIOSK_DIR[^]]*BRANDING_DIR" "$lx" || {
	bad 63 "extension.js does not watch both the branding and the kiosk directory"
	r=1
}
changed=$(awk '/^    _settingsChanged\(\) \{/ {on = 1} on {print} on && /^    \}$/ {exit}' "$lx")
for want in 'this._domains = domainList(' 'this._shelf?.setManaged(' 'this._shelf?.refreshApps()'; do
	grep -qF "$want" <<<"$changed" || {
		bad 63 "extension.js _settingsChanged does not apply $want"
		r=1
	}
done
off=$(awk '/^    disable\(\) \{/ {on = 1} on {print} on && /^    \}$/ {exit}' "$lx")
grep -qF 'this._watch?.destroy()' <<<"$off" || {
	bad 63 "extension.js disable() does not stop the settings watch"
	r=1
}
grep -qE '^    setManaged\(' "$ld/shelf.js" || {
	bad 63 "shelf.js has no setManaged"
	r=1
}
[ "$r" = 0 ] && ok 63 "login: new branding and locked apps are applied while the login screen is up"

# 64. The IT maintenance sign-in moved from a "Local manager" link under the email field to the "Managed by <school>" line on
#     the shelf (product owner, 2026-11-05): the card keeps only the entry, and the line reads as plain text until the pointer
#     or the keyboard reaches it. It is a focusable St.Button (track_hover for the hover look, an accessible name that says
#     what it opens) that starts exactly what the link did, _signInAs(IT_ACCOUNT), and like the link it is clickable only on
#     the username step: _askForUsernameAndBeginVerification turns it on, _beginVerification (any sign-in, the card) off.
r=0
for want in "itSignIn: () => this._signInAs(IT_ACCOUNT)" 'this._shelf?.setItSignIn('; do
	grep -qF "$want" "$lx" || {
		bad 64 "extension.js does not wire the Managed-by line to the IT sign-in ($want)"
		r=1
	}
done
if grep -qE '_itLink|itLink|mastersos-login-link' "$lx" "$ld/strings.js" "$ld/stylesheet.css" ||
	grep -qxF 'msgid "Local manager"' "$rel/login-i18n/mastersos-login.pot"; then
	bad 64 "the Local manager link (or its string or style) is still there"
	r=1
fi
step=$(awk '/_askForUsernameAndBeginVerification., original =>/ {on = 1} on {print} on && /^            \}\);$/ {exit}' "$lx")
begin=$(awk '/._beginVerification., original =>/ {on = 1} on {print} on && /^            \}\);$/ {exit}' "$lx")
on=$(awk '/^    _setItSignIn\(on\) \{/ {on = 1} on {print} on && /^    \}$/ {exit}' "$lx")
if ! grep -qF 'ext._setItSignIn(true)' <<<"$step" || ! grep -qF 'ext._setItSignIn(false)' <<<"$begin" ||
	! grep -qF 'this._shelf?.setItSignIn(' <<<"$on"; then
	bad 64 "extension.js: the IT sign-in is not on exactly on the username step (_setItSignIn true/false)"
	r=1
fi
sh=$(awk '/^    setItSignIn\(on\) \{/ {on = 1} on {print} on && /^    \}$/ {exit}' "$ld/shelf.js")
for want in 'reactive' 'can_focus' 'track_hover' 'accessible_name'; do
	grep -qF "$want" <<<"$sh" || {
		bad 64 "shelf.js setItSignIn does not set $want"
		r=1
	}
done
if ! grep -qF "this._managed = new St.Button(" "$ld/shelf.js" || ! grep -qF 'actions.itSignIn()' "$ld/shelf.js"; then
	bad 64 "shelf.js: the Managed-by line is not a button that calls actions.itSignIn()"
	r=1
fi
for sel in '.mastersos-login-managed:hover' '.mastersos-login-managed:focus'; do
	grep -qF "$sel {" "$ld/stylesheet.css" || {
		bad 64 "stylesheet.css has no $sel"
		r=1
	}
done
grep -qF "itSignIn: _('IT maintenance sign-in')," "$ld/strings.js" || {
	bad 64 "strings.js has no itSignIn text for the accessible name"
	r=1
}
[ "$r" = 0 ] && ok 64 "login: \"Managed by <school>\" opens the IT maintenance sign-in; no Local manager link in the card"

# 65. The USB developer diagnostics were removed (docs/specs/2026-11-05-remote-diagnostics-and-help-design.md, design 1):
#     none of their scripts, units, links, drop-ins, udev rule or tests may come back, and a machine installed with the old
#     switch loses /var/lib/mastersos-diag on its next boot (tmpfiles R).
r=0
sys=$rel/mkosi.extra/usr/lib/systemd/system
for gone in "$rel/mkosi.extra/usr/lib/mastersos/diag-export" "$rel/mkosi.extra/usr/lib/mastersos/diag-setup" \
	"$sys/mastersos-diag-adopt.service" "$sys/mastersos-diag-setup.service" "$sys/mastersos-diag-export@.service" \
	"$sys/sysinit.target.wants/mastersos-diag-adopt.service" "$sys/sysinit.target.wants/mastersos-diag-setup.service" \
	"$sys/authd.service.d/90-mastersos-diag.conf" "$sys/wpa_supplicant.service.d/90-mastersos-diag.conf" \
	"$sys/mastersos-agent.service.d/90-mastersos-diag.conf" "$sys/mastersos-agent-local.service.d/90-mastersos-diag.conf" \
	"$rel/mkosi.extra/usr/lib/udev/rules.d/91-mastersos-diag.rules" "$rel/check-execstart-copies.sh" \
	"$rel/tests/diag-export-test.sh" "$rel/tests/diag-setup-test.sh" "$rel/tests/execstart-copies-test.sh" \
	"$rel/tests/fixtures/diag"; do
	if [ -e "$gone" ] || [ -L "$gone" ]; then
		bad 65 "$gone belongs to the removed USB diagnostics"
		r=1
	fi
done
if grep -rqE 'diag\.env|MASTERSOS_DIAG_|mastersos-diag-(setup|adopt|export)|debug-install' "$rel/mkosi.extra" "$rel/mkosi.finalize" \
	"$rel/mkosi.conf" .github/workflows "$core/mastersos-installer/src" 2>/dev/null; then
	bad 65 "something still refers to the removed USB diagnostics (diag.env, MASTERSOS_DIAG_*, mastersos-diag-*, debug-install)"
	r=1
fi
grep -qxF 'R /var/lib/mastersos-diag' "$rel/mkosi.extra/usr/lib/tmpfiles.d/mastersos-diag-cleanup.conf" 2>/dev/null || {
	bad 65 "tmpfiles.d/mastersos-diag-cleanup.conf has no line R /var/lib/mastersos-diag"
	r=1
}
[ "$r" = 0 ] && ok 65 "the USB diagnostics are gone, and the old switch folder is removed on boot"

# 66. Get help (plan 2026-11-05 Task 6): the dialog (help.js) and its logic (help-model.js, unit-tested by help-model-test.sh,
#     which CI runs) are the same bytes in the login and the desktop extension, and so is their block of styles. Every text the
#     model marks N_ is a msgid of mastersos-login.pot (rule 50 then wants it in every catalogue). help.js takes the gettext
#     it is given; the desktop extension reads the login extension's catalogues. Both entries hide unless support.json says
#     enabled, each says which session it is, and the login screen shows the collecting notice from status.json.
r=0
md=$rel/mkosi.extra/usr/share/gnome-shell/extensions/mastersos-managed@mastersos.org
for f in help-model.js help.js; do
	if [ ! -f "$ld/$f" ] || [ ! -f "$md/$f" ]; then
		bad 66 "$f should be in both $ld and $md"
		r=1
	elif ! cmp -s "$ld/$f" "$md/$f"; then
		bad 66 "$ld/$f and $md/$f differ (they must be byte-identical copies)"
		r=1
	fi
done
if ! why=$(python3 -I - "$ld" "$md" "$rel/login-i18n/mastersos-login.pot" 2>&1 <<'HELP'
import re, sys
ld, md, pot = sys.argv[1:]
errs = []
def block(path):
    m = re.search(r"/\* Get help dialog \(help\.js\).*?/\* End of the Get help dialog\. \*/", open(path, encoding="utf-8").read(), re.S)
    return m.group(0) if m else None
a, b = block(f"{ld}/stylesheet.css"), block(f"{md}/stylesheet.css")
if not a or a != b:
    errs.append("the Get help styles are missing from a stylesheet.css or differ between the two extensions")
model = open(f"{ld}/help-model.js", encoding="utf-8").read()
ids = re.findall(r"""N_\((?:'([^'\\]*)'|"([^"\\]*)")\)""", model)
ids = [x or y for x, y in ids]
if len(ids) < 20:
    errs.append(f"help-model.js marks only {len(ids)} texts with N_")
text = open(pot, encoding="utf-8").read()
missing = [i for i in ids if f'msgid "{i}"' not in text]
if missing:
    errs.append(f"not in mastersos-login.pot: {missing}")
if errs:
    sys.exit("; ".join(errs))
HELP
); then
	bad 66 "help: $why"
	r=1
fi
hj=$ld/help.js
if grep -qF "from 'resource:///org/gnome/shell/extensions/extension.js'" "$hj" 2>/dev/null ||
	! grep -qF '_init({session, gettext})' "$hj" 2>/dev/null; then
	bad 66 "help.js should take session and gettext from its caller, not the extension's own gettext"
	r=1
fi
grep -qF "bindtextdomain('mastersos-login', LOGIN_LOCALE)" "$md/extension.js" || {
	bad 66 "mastersos-managed should translate Get help through the login extension's catalogues (mastersos-login)"
	r=1
}
for want in "$lx:session: 'login'" "$md/extension.js:session: 'desktop'" "$lx:setHelpAvailable(readSupportEnabled())" \
	"$md/extension.js:readSupportEnabled()" "$lx:collectingFor(" "$ld/shelf.js:setCollecting(on)" "$ld/shelf.js:actions.help()"; do
	grep -qF "${want#*:}" "${want%%:*}" || {
		bad 66 "${want%%:*} has no ${want#*:}"
		r=1
	}
done
grep -qxF '      - run: bash image/tests/help-model-test.sh' .github/workflows/mastersos.yml || {
	bad 66 "CI (mastersos.yml image-lint) does not run image/tests/help-model-test.sh"
	r=1
}
[ "$r" = 0 ] && ok 66 "Get help: one dialog and model in both extensions, every text in the catalogues, hidden unless enabled, collecting notice on the login screen"

# 67. The sign-in handoff (design 2026-11-05 browser sign-in handoff): the card unit stops Chrome with SIGINT (it writes its
#     cookies then) and runs the agent's begin and stash steps as root outside the sandbox; the names the agent uses are the
#     image's (the card's profile in login-browser, the unit, the URL file card.js writes, the handoff directory in tmpfiles
#     and in the user unit's condition); pam-session claims for the card; the user unit runs signin-import as the user and is
#     pulled in only by the regular desktop sessions' targets through plain-file drop-ins, never by a link or [Install].
r=0
sh=$core/mastersos-agent/src/signin_handoff.rs
su=$ex/usr/lib/systemd/user
for l in 'KillSignal=SIGINT' 'ExecStartPre=+/usr/bin/mastersos-agent signin-handoff begin %i' \
	'ExecStopPost=+/usr/bin/mastersos-agent signin-handoff stash %i' 'TimeoutStopSec=5' 'KillMode=control-group' 'PrivateTmp=yes'; do
	grep -qxF -- "$l" "$lbu" 2>/dev/null || {
		bad 67 "$lbu should have $l"
		r=1
	}
done
for want in 'pub const CARD_PROFILE: &str = "profile";' 'pub const CARD_UNIT: &str = "mastersos-login-browser";' \
	'pub const URL_FILE: &str = "mastersos-login-url";' 'pub const HANDOFF_DIR: &str = "/run/mastersos-signin";' \
	'const HANDOFF_REL: &str = "run/mastersos-signin";' 'pub const CLAIM_SERVICE: &str = "gdm-authd";'; do
	grep -qxF -- "$want" "$sh" || {
		bad 67 "$sh should have: $want"
		r=1
	}
done
grep -qE -- '--user-data-dir=/tmp/profile \\$' "$ex/usr/lib/mastersos/login-browser" || {
	bad 67 "login-browser should keep the card's profile at /tmp/profile (signin_handoff::CARD_PROFILE)"
	r=1
}
grep -qxF "const URL_FILE = 'mastersos-login-url';" "$ex/usr/share/gnome-shell/extensions/mastersos-login@mastersos.org/card.js" || {
	bad 67 "card.js should leave the URL in mastersos-login-url (signin_handoff::URL_FILE)"
	r=1
}
for l in 'd /run/mastersos-signin 0711 root root -' 'd /run/mastersos-signin/private 0700 root root -'; do
	grep -qxF -- "$l" "$ex/usr/lib/tmpfiles.d/mastersos.conf" || {
		bad 67 "tmpfiles.d/mastersos.conf should have: $l"
		r=1
	}
done
grep -qF 'crate::signin_handoff::claim_from_pam(&env_str("PAM_SERVICE"), &user, uid);' "$core/mastersos-agent/src/system/guest.rs" || {
	bad 67 "pam-session should claim the card's cookies (signin_handoff::claim_from_pam)"
	r=1
}
for sub in signin-handoff signin-import; do
	grep -qF "Some(OsStr::new(\"$sub\"))" "$core/mastersos-agent/src/main.rs" || {
		bad 67 "main.rs should dispatch $sub"
		r=1
	}
done
for l in 'PartOf=gnome-session.target' 'ConditionUser=!@system' 'ConditionPathExists=/run/mastersos-signin/%U' 'Type=oneshot' \
	'ExecStart=/usr/bin/mastersos-agent signin-import' 'Restart=no'; do
	grep -qxF -- "$l" "$su/mastersos-signin-import.service" 2>/dev/null || {
		bad 67 "$su/mastersos-signin-import.service should have the line: $l"
		r=1
	}
done
if grep -qxF '[Install]' "$su/mastersos-signin-import.service" 2>/dev/null; then
	bad 67 "$su/mastersos-signin-import.service must have no [Install] (drop-ins pull it in)"
	r=1
fi
for s in ubuntu gnome; do
	d=$su/gnome-session@$s.target.d/mastersos-signin-import.conf
	if [ -L "$d" ] || [ ! -f "$d" ] || ! grep -qxF 'Wants=mastersos-signin-import.service' "$d"; then
		bad 67 "$d should be a plain file with Wants=mastersos-signin-import.service"
		r=1
	fi
done
if grep -rlF 'mastersos-signin-import.service' "$su" | grep -vE '/(mastersos-signin-import\.service|gnome-session@(ubuntu|gnome)\.target\.d/mastersos-signin-import\.conf)$' | grep -q . ||
	find "$ex" -name 'mastersos-signin-import.service' -type l | grep -q .; then
	bad 67 "mastersos-signin-import.service is pulled in by something other than the two desktop session drop-ins"
	r=1
fi
[ "$r" = 0 ] && ok 67 "sign-in handoff: card unit stops on SIGINT with begin/stash, names match, pam-session claims, user unit only in desktop sessions"

# 68. The upload queue (plan 2026-11-05 Task 4, remote diagnostics design 3, Ruling P6): no resident uploader. The oneshot
#     mastersos-upload.service runs `mastersos-agent upload drain` with the resource limits, only when the queue folder is not
#     empty; the timer (enabled from /usr) runs every 30 minutes; the NetworkManager dispatcher kicks it when online. The
#     folder and unit names agree with the agent's.
r=0
sys=$rel/mkosi.extra/usr/lib/systemd/system
us=$sys/mastersos-upload.service
for want in 'Type=oneshot' 'ExecStart=/usr/bin/mastersos-agent upload drain' 'Nice=10' 'IOSchedulingClass=idle' 'CPUQuota=20%' \
	'ConditionDirectoryNotEmpty=/var/lib/mastersos/upload-queue' 'ConditionKernelCommandLine=!systemd.unit=mastersos-installer.target'; do
	grep -qxF "$want" "$us" 2>/dev/null || {
		bad 68 "$us has no line $want"
		r=1
	}
done
grep -qE '^MemoryMax=[0-9]+M$' "$us" 2>/dev/null || {
	bad 68 "$us has no MemoryMax="
	r=1
}
for want in 'OnBootSec=3min' 'OnCalendar=*:00/30' 'RandomizedDelaySec=10min'; do
	grep -qxF "$want" "$sys/mastersos-upload.timer" 2>/dev/null || {
		bad 68 "mastersos-upload.timer has no line $want"
		r=1
	}
done
[ "$(readlink "$sys/timers.target.wants/mastersos-upload.timer" 2>/dev/null)" = ../mastersos-upload.timer ] || {
	bad 68 "timers.target.wants/mastersos-upload.timer should link to ../mastersos-upload.timer"
	r=1
}
nd=$rel/mkosi.extra/usr/lib/NetworkManager/dispatcher.d/91-mastersos-upload
if [ ! -x "$nd" ] || ! grep -qF '/usr/bin/mastersos-agent upload kick' "$nd" || ! grep -qF 'CONNECTIVITY_STATE:-}" = FULL' "$nd"; then
	bad 68 "$nd should be executable and run mastersos-agent upload kick on full connectivity"
	r=1
fi
if command -v shellcheck >/dev/null && ! shellcheck "$nd" >&2; then
	bad 68 "shellcheck $nd"
	r=1
fi
if ! grep -qF 'pub const QUEUE_DIR: &str = "upload-queue";' "$core/mastersos-agent/src/upload/queue.rs" ||
	! grep -qF 'pub const SERVICE: &str = "mastersos-upload.service";' "$core/mastersos-agent/src/upload/mod.rs"; then
	bad 68 "the agent's queue folder or unit name differs from the image's (upload-queue, mastersos-upload.service)"
	r=1
fi
[ "$r" = 0 ] && ok 68 "upload queue: oneshot drain with resource limits, 30-minute timer, NetworkManager kick, names agree with the agent"

# 69. Get help, the machine side (plan 2026-11-05 Task 5): mastersos-support.socket (0666, Accept=no) is enabled through a
#     sockets.target.wants link and starts mastersos-support.service, which runs the agent's `support host` with the socket
#     as stdin and its output in the journal; the socket path, the queue directory and support.json are the agent's and
#     the dialogs' names, and the socket is in its own 0755 directory, never in the 0700 /run/mastersos; main.rs dispatches
#     `support`; the kiosk host manifest allows the same origin as the exit host's.
r=0
sd=$ex/usr/lib/systemd/system
ss=$sd/mastersos-support.socket
sv=$sd/mastersos-support.service
sm=$core/mastersos-agent/src/support/mod.rs
for l in 'ListenStream=/run/mastersos-support/support.sock' 'SocketMode=0666' 'DirectoryMode=0755' 'Accept=no' 'WantedBy=sockets.target'; do
	grep -qxF -- "$l" "$ss" 2>/dev/null || {
		bad 69 "$ss should have the line: $l"
		r=1
	}
done
# /run/mastersos is root 0700 (tmpfiles, and login_queue tightens it at every login): a socket in it is out of users' reach
sp=$(sed -n 's/^ListenStream=//p' "$ss" 2>/dev/null)
if [ "$(dirname "${sp:-/run/mastersos/x}")" = /run/mastersos ]; then
	bad 69 "$ss: the socket must not be in /run/mastersos (root 0700), not ${sp:-missing}"
	r=1
fi
if [ "$(readlink "$sd/sockets.target.wants/mastersos-support.socket" 2>/dev/null)" != ../mastersos-support.socket ]; then
	bad 69 "$sd/sockets.target.wants/mastersos-support.socket should be a link to ../mastersos-support.socket"
	r=1
fi
for l in 'ExecStart=/usr/bin/mastersos-agent support host' 'StandardInput=socket' 'StandardOutput=journal' \
	'Requires=mastersos-support.socket' 'StateDirectory=mastersos/support-queue' 'StateDirectoryMode=0700' 'ProtectSystem=strict' \
	'StartLimitIntervalSec=0' 'MemoryMax=64M' 'LimitNOFILE=256'; do
	grep -qxF -- "$l" "$sv" 2>/dev/null || {
		bad 69 "$sv should have the line: $l"
		r=1
	}
done
if [ "$(grep -c '^ExecStart=' "$sv" 2>/dev/null)" != 1 ] || grep -qxF '[Install]' "$sv" 2>/dev/null; then
	bad 69 "$sv should have exactly one ExecStart= and no [Install] (the socket starts it)"
	r=1
fi
for want in 'pub const SOCKET_PATH: &str = "/run/mastersos-support/support.sock";' \
	'pub const QUEUE_DIR: &str = "/var/lib/mastersos/support-queue";' 'pub const SUPPORT_JSON: &str = "support.json";' \
	'pub const UPLOAD_UNIT: &str = "mastersos-upload.service";'; do
	grep -qxF -- "$want" "$sm" || {
		bad 69 "$sm should have: $want"
		r=1
	}
done
for e in mastersos-login@mastersos.org mastersos-managed@mastersos.org; do
	h=$ex/usr/share/gnome-shell/extensions/$e/help.js
	if ! grep -qxF "export const SOCKET = '/run/mastersos-support/support.sock';" "$h" ||
		! grep -qxF "export const SUPPORT_JSON = '/var/lib/mastersos-public/support.json';" "$h"; then
		bad 69 "$h should use /run/mastersos-support/support.sock and /var/lib/mastersos-public/support.json (the agent's names)"
		r=1
	fi
done
grep -qF 'Some(OsStr::new("support"))' "$core/mastersos-agent/src/main.rs" || {
	bad 69 "main.rs should dispatch support"
	r=1
}
if ! python3 -I -c 'import json, sys; a, b = (json.load(open(p)) for p in sys.argv[1:]); sys.exit(0 if a["allowed_origins"] == b["allowed_origins"] and a["name"] == "org.mastersos.support" else 1)' \
	"$rel/kiosk-ext/org.mastersos.support.json.in" "$rel/kiosk-ext/org.mastersos.kiosk_exit.json.in" 2>/dev/null; then
	bad 69 "$rel/kiosk-ext/org.mastersos.support.json.in should be org.mastersos.support with the exit host's allowed_origins"
	r=1
fi
[ "$r" = 0 ] && ok 69 "Get help: support socket (0666, Accept=no, enabled) starts support host with the socket as stdin; names match the agent and the dialogs; kiosk host manifest"

# 70. Get help, sending (plan 2026-11-05 Task 5b): the support host queues each request for mastersos-upload.service as a
#     `support` item in /var/lib/mastersos/upload-queue, so its sandbox (ProtectSystem=strict) must make that folder
#     writable too; without it every submit fails on a read-only file system.
r=0
grep -qxF 'StateDirectory=mastersos/upload-queue' "$sv" 2>/dev/null || {
	bad 70 "$sv should have the line: StateDirectory=mastersos/upload-queue (the host writes the sender's items there)"
	r=1
}
grep -qF '.enqueue_support(' "$core/mastersos-agent/src/support/host.rs" || {
	bad 70 "support/host.rs should queue a support item for the sender (enqueue_support)"
	r=1
}
[ "$r" = 0 ] && ok 70 "Get help: the support host may write the upload queue, and queues each request there"

exit $fail
