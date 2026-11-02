#!/bin/bash
# 首次开机临时钥匙持久化脚本（mkosi.initrd.conf/…/usr/lib/mastersos/luks-bootstrap-persist）的测试（不需要 root）：
#   bash image/tests/luks-bootstrap-test.sh
# 路径变量（ROOT_LUKS、SYSROOT、RUN_DIR）指到临时目录；cryptsetup 是 PATH 前面的桩，记录每次调用、
# 按用例给退出码。source 被测脚本只定义函数（persist_bootstrap_key），本测试驱动它。
# 每个用例在自己的子 shell 里 export 环境再 source 被测脚本：变量只在子 shell 里改是有意的
# shellcheck disable=SC2030,SC2031
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
script=$here/../mkosi.initrd.conf/mkosi.extra/usr/lib/mastersos/luks-bootstrap-persist
[ -f "$script" ] || {
	echo "找不到被测脚本：$script" >&2
	exit 1
}

fails=0 n=0
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT

# 建一个 cryptsetup 桩：luksUUID 回显 ${AFTER_UUID}；open --test-passphrase 退 ${OPEN_RC}；全部调用记进 ${STUB_LOG}。
make_stub() {
	local bin=$1
	mkdir -p "$bin"
	cat >"$bin/cryptsetup" <<'STUB'
#!/bin/bash
printf '%s\n' "cryptsetup $*" >>"$STUB_LOG"
case "$1" in
luksUUID) [ "$AFTER_UUID" = FAIL ] && exit 4; printf '%s\n' "$AFTER_UUID" ;;
open) exit "${OPEN_RC:-0}" ;;
*) exit 0 ;;
esac
STUB
	chmod +x "$bin/cryptsetup"
	# INSTALL_FAIL=1：拷文件的那一次 install 失败（install -d 照常），模拟写到一半出错
	if [ "${INSTALL_FAIL:-}" = 1 ]; then
		cat >"$bin/install" <<'STUB'
#!/bin/bash
[ "$1" = -d ] && exec /usr/bin/env -i PATH=/usr/bin:/bin install "$@"
for a; do last=$a; done
printf 'partial' >"$last"
exit 1
STUB
		chmod +x "$bin/install"
	fi
}

# case <名字> <before> <after uuid> <open rc> <期望：persisted|skipped|notpersisted>
case_() {
	local name=$1 before=$2 after=$3 open_rc=$4 want=$5
	n=$((n + 1))
	local d="$root/case-$n" rc=0
	mkdir -p "$d/run" "$d/bin"
	if [ "${SYSROOT_FILE:-}" = 1 ]; then : >"$d/sysroot"; else mkdir -p "$d/sysroot"; fi
	# 临时钥匙（32 字节）在 run 里
	head -c 32 /dev/zero | tr '\0' 'K' >"$d/run/luks-bootstrap-key"
	printf '%s\n' "$before" >"$d/run/root-uuid-before"
	local stub_log="$d/stub.log"
	: >"$stub_log"
	make_stub "$d/bin"
	# 在子 shell 里跑：设好环境、source 脚本、调函数
	rc=0
	(
		export PATH="$d/bin:$PATH"
		export STUB_LOG="$stub_log" AFTER_UUID="$after" OPEN_RC="$open_rc"
		export RUN_DIR="$d/run" SYSROOT="$d/sysroot" ROOT_LUKS=/dev/fake-root-luks
		if [ "${DIRECT:-}" = 1 ]; then
			exec bash "$script"
		fi
		# shellcheck disable=SC1090
		. "$script"
		persist_bootstrap_key
	) >"$d/out.txt" 2>&1 || rc=$?

	local key="$d/sysroot/var/lib/mastersos-system/luks-bootstrap-key"
	local ok=1
	# /run 里那份一律应被删掉
	[ ! -e "$d/run/luks-bootstrap-key" ] || {
		echo "  FAIL ${name}：/run 的临时钥匙没删掉" >&2
		ok=0
	}
	case "$want" in
	persisted)
		grep -q -- "cryptsetup open --test-passphrase --disable-external-tokens --key-file=$d/run/luks-bootstrap-key /dev/fake-root-luks" "$stub_log" || {
			echo "  FAIL ${name}：没按 --test-passphrase --disable-external-tokens --key-file=<路径> 核对" >&2
			ok=0
		}
		[ "$rc" = 0 ] || {
			echo "  FAIL ${name}：退出码 ${rc}（应 0）" >&2
			ok=0
		}
		[ -f "$key" ] || {
			echo "  FAIL ${name}：没放进 $key" >&2
			ok=0
		}
		if [ -f "$key" ]; then
			[ "$(stat -c %a "$key" 2>/dev/null || stat -f %Lp "$key")" = 600 ] || {
				echo "  FAIL ${name}：$key 不是 0600" >&2
				ok=0
			}
			local dir
			dir=$(dirname "$key")
			[ "$(stat -c %a "$dir" 2>/dev/null || stat -f %Lp "$dir")" = 700 ] || {
				echo "  FAIL ${name}：$dir 不是 0700" >&2
				ok=0
			}
		fi
		;;
	skipped)
		[ "$rc" = 0 ] || {
			echo "  FAIL ${name}：退出码 ${rc}（应 0）" >&2
			ok=0
		}
		[ ! -e "$key" ] || {
			echo "  FAIL ${name}：不该写 $key" >&2
			ok=0
		}
		grep -q "cryptsetup open" "$stub_log" && {
			echo "  FAIL ${name}：UUID 相同不该调 cryptsetup open" >&2
			ok=0
		}
		;;
	notpersisted)
		[ "$rc" != 0 ] || {
			echo "  FAIL ${name}：应退出非 0" >&2
			ok=0
		}
		[ ! -e "$key" ] || {
			echo "  FAIL ${name}：不该留下 $key" >&2
			ok=0
		}
		;;
	esac
	if [ "$ok" = 1 ]; then
		echo "ok   $name"
	else
		echo "     （$name 的输出）"; sed 's/^/       /' "$d/out.txt" >&2
		fails=$((fails + 1))
	fi
}

NEW=11111111-2222-4333-8444-555566667777

case_ "persist_when_uuid_changed"          none        "$NEW"  0  persisted
case_ "skip_when_uuid_same"                "$NEW"      "$NEW"  0  skipped
case_ "not_persisted_when_key_does_not_open" none      "$NEW"  2  notpersisted
case_ "device_missing_after_repart"        none        FAIL    2  notpersisted
SYSROOT_FILE=1 case_ "sysroot_unwritable_cleans_run"  none  "$NEW"  0  notpersisted
INSTALL_FAIL=1 case_ "install_fails_mid_function"     none  "$NEW"  0  notpersisted
DIRECT=1 case_ "run_as_script_persists"               none  "$NEW"  0  persisted
DIRECT=1 SYSROOT_FILE=1 case_ "run_as_script_failure_cleans_run" none "$NEW" 0 notpersisted

# key_never_on_cmdline：桩记下的命令行里没有钥匙文件的内容（只传 --key-file=<路径>）
n=$((n + 1))
d="$root/case-$n"
mkdir -p "$d/run" "$d/sysroot" "$d/bin"
head -c 32 /dev/zero | tr '\0' 'K' >"$d/run/luks-bootstrap-key"
keycontent=$(cat "$d/run/luks-bootstrap-key")
printf 'none\n' >"$d/run/root-uuid-before"
: >"$d/stub.log"
make_stub "$d/bin"
(
	export PATH="$d/bin:$PATH"
	export STUB_LOG="$d/stub.log" AFTER_UUID="$NEW" OPEN_RC=0
	export RUN_DIR="$d/run" SYSROOT="$d/sysroot" ROOT_LUKS=/dev/fake-root-luks
	# shellcheck disable=SC1090
	. "$script"
	persist_bootstrap_key
) >/dev/null 2>&1 || true
if grep -qF "$keycontent" "$d/stub.log"; then
	echo "  FAIL key_never_on_cmdline：钥匙内容出现在 cryptsetup 命令行里" >&2
	fails=$((fails + 1))
else
	echo "ok   key_never_on_cmdline"
fi

echo
if [ "$fails" = 0 ]; then
	echo "luks-bootstrap-test: 全部通过（$n 个用例）"
else
	echo "luks-bootstrap-test: $fails 个用例失败（共 ${n}）" >&2
	exit 1
fi
