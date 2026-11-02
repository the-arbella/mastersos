#!/bin/bash
# browser-wait (offline status Task 4): the session's wait for the web browser. Fake zenity and notify-send record their
# calls; Chrome, the public dir and the poll interval are redirected through MASTERSOS_CHROME_BIN, MASTERSOS_PUBLIC and
# MASTERSOS_POLL. Linux only (CI image-lint, or colima ubuntu:24.04 as non-root):
#   bash image/tests/browser-wait-test.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
bw=$here/../mkosi.extra/usr/lib/mastersos/browser-wait

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0 n=0
check() { # check <name> <want> <got>
	n=$((n + 1))
	if [ "$2" = "$3" ]; then
		echo "ok   $1"
	else
		printf 'FAIL %s: want %q, got %q\n' "$1" "$2" "$3" >&2
		fails=$((fails + 1))
	fi
}
has() { if grep -qF -- "$1" "$2" 2>/dev/null; then echo yes; else echo no; fi; }
count() { if [ -e "$1" ]; then grep -c '^CALL' "$1" || true; else echo 0; fi; }

bin=$tmp/bin
mkdir -p "$bin"
# notify-send: one CALL line, then each argument on its own line
cat >"$bin/notify-send" <<'EOF'
#!/bin/bash
{ echo CALL; printf 'ARG %s\n' "$@"; } >>"$FAKE_LOG/notify"
EOF
# zenity: records its arguments and everything written to its stdin; FAKE_ZENITY=quit exits at once (the user's X)
cat >"$bin/zenity" <<'EOF'
#!/bin/bash
{ echo CALL; printf 'ARG %s\n' "$@"; } >>"$FAKE_LOG/zenity"
[ "${FAKE_ZENITY:-}" = quit ] && exit 1
while IFS= read -r l; do
	printf 'IN %s\n' "$l" >>"$FAKE_LOG/zenity"
	[ "$l" = 100 ] && exit 0
done
exit 0
EOF
chmod +x "$bin/notify-send" "$bin/zenity"

# run <case dir> [env...]: runs browser-wait with a 5 s cap; prints its exit code
run() {
	local c=$1
	shift
	mkdir -p "$c/log" "$c/pub"
	local rc=0
	env PATH="$bin:$PATH" FAKE_LOG="$c/log" MASTERSOS_PUBLIC="$c/pub" MASTERSOS_CHROME_BIN="$c/chrome" MASTERSOS_POLL=0.2 MASTERSOS_READY_HOLD=0.2 \
		USER=student LANG=en_US.UTF-8 "$@" timeout 5 bash "$bw" >"$c/out" 2>&1 || rc=$?
	echo "$rc"
}
status_json() { # status_json <dir> <message> <detail or null>
	printf '{"network":"not_in_range","network_detail":%s,"settings":"waiting","settings_detail":null,"chrome":"installing","chrome_detail":null,"message":"%s"}\n' "$3" "$2" >"$1/pub/status.json"
}
msg_net='No network. Choose a Wi-Fi network in the top-right menu, or plug in a network cable or a phone with USB tethering.'

# 1. Chrome is there: nothing at all
c=$tmp/c1
mkdir -p "$c/pub"
printf '#!/bin/sh\n' >"$c/chrome"
chmod +x "$c/chrome"
echo learning >"$c/pub/session-mode"
check "chrome present: exit 0" 0 "$(run "$c")"
check "chrome present: no notification" 0 "$(count "$c/log/notify")"
check "chrome present: no window" 0 "$(count "$c/log/zenity")"

# 2. full: one notification with the status sentence, no window
c=$tmp/c2
mkdir -p "$c/pub"
echo full >"$c/pub/session-mode"
status_json "$c" "$msg_net" '"Wi-Fi \"Campus-IoT\" is not in range"'
check "full: exit 0" 0 "$(run "$c")"
check "full: one notification" 1 "$(count "$c/log/notify")"
check "full: no window" 0 "$(count "$c/log/zenity")"
check "full: app name" yes "$(has 'ARG --app-name=MastersOS' "$c/log/notify")"
check "full: English first line" yes "$(has 'ARG The web browser is not installed yet.' "$c/log/notify")"
check "full: body is the status sentence" yes "$(has "ARG $msg_net" "$c/log/notify")"

# 3. no session-mode (no bundle yet): same as full
c=$tmp/c3
mkdir -p "$c/pub"
status_json "$c" 'Waiting for school settings.' null
check "no mode: exit 0" 0 "$(run "$c")"
check "no mode: one notification" 1 "$(count "$c/log/notify")"
check "no mode: no window" 0 "$(count "$c/log/zenity")"
check "no mode: body" yes "$(has 'ARG Waiting for school settings.' "$c/log/notify")"

# 4. learning, Chrome shows up later: zenity gets "# ..." lines (sentence and the escaped detail decoded), then 100
c=$tmp/c4
mkdir -p "$c/pub"
echo learning >"$c/pub/session-mode"
status_json "$c" "$msg_net" '"Wi-Fi \"Campus-IoT\" is not in range"'
(
	sleep 1
	printf '#!/bin/sh\n' >"$c/chrome"
	chmod +x "$c/chrome"
) &
check "learning: exit 0" 0 "$(run "$c")"
wait
check "learning: one window" 1 "$(count "$c/log/zenity")"
for a in --progress --pulsate --no-cancel --auto-close --title=MastersOS; do
	check "learning: zenity $a" yes "$(has "ARG $a" "$c/log/zenity")"
done
check "learning: no other zenity options" 5 "$(grep -c '^ARG' "$c/log/zenity")"
check "learning: '#' line with first line" yes "$(has 'IN # The web browser is not installed yet.\n' "$c/log/zenity")"
check "learning: sentence and decoded detail" yes "$(has "\\n$msg_net\\nWi-Fi \"Campus-IoT\" is not in range" "$c/log/zenity")"
# A sysext merged mid-session does not reach the running GNOME Shell (PVE, 2026-10-30): the Dock shows Chrome only after
# signing in again, so the last screen says so before the window closes
check "learning: last screen says to sign in again" "IN # The web browser is ready. Sign out and sign in again to see it." \
	"$(grep '^IN' "$c/log/zenity" | tail -n2 | head -n1)"
check "learning: then 100" 100 "$(grep '^IN' "$c/log/zenity" | tail -n1 | cut -c4-)"
check "learning: no notification" 0 "$(count "$c/log/notify")"

# 4b. learning, Chrome missing and the detail comes from settings (network ok)
c=$tmp/c4b
mkdir -p "$c/pub"
echo learning >"$c/pub/session-mode"
printf '%s\n' '{"network":"ok","network_detail":null,"settings":"unreachable","settings_detail":"HTTP 502 from server","chrome":"installing","chrome_detail":null,"message":"Waiting for school settings."}' >"$c/pub/status.json"
(
	sleep 1
	printf '#!/bin/sh\n' >"$c/chrome"
	chmod +x "$c/chrome"
) &
run "$c" >/dev/null
wait
check "learning: detail of the first non-ok part" yes "$(has '\nWaiting for school settings.\nHTTP 502 from server' "$c/log/zenity")"

# 4c. status.json as the agent writes it (serde_json::to_vec_pretty: one key per line, 2-space indent), escaped quotes in the detail
c=$tmp/c4c
mkdir -p "$c/pub"
echo learning >"$c/pub/session-mode"
cat >"$c/pub/status.json" <<EOF
{
  "network": "not_in_range",
  "network_detail": "Wi-Fi \\"Campus-IoT\\" is not in range",
  "settings": "waiting",
  "settings_detail": null,
  "chrome": "installing",
  "chrome_detail": null,
  "message": "$msg_net"
}
EOF
(
	sleep 1
	printf '#!/bin/sh\n' >"$c/chrome"
	chmod +x "$c/chrome"
) &
run "$c" >/dev/null
wait
check "pretty json: window text" "IN # The web browser is not installed yet.\\n$msg_net\\nWi-Fi \"Campus-IoT\" is not in range" \
	"$(grep -m1 '^IN #' "$c/log/zenity")"

# 4d. learning with no status text (no message, every part ok): the first line alone, no trailing \n (no empty second line)
c=$tmp/c4d
mkdir -p "$c/pub"
echo learning >"$c/pub/session-mode"
printf '%s\n' '{"network":"ok","network_detail":null,"settings":"ok","settings_detail":null,"chrome":"ok","chrome_detail":null,"message":null}' >"$c/pub/status.json"
(
	sleep 1
	printf '#!/bin/sh\n' >"$c/chrome"
	chmod +x "$c/chrome"
) &
run "$c" >/dev/null
wait
check "no status text: no empty second line" "IN # The web browser is not installed yet." "$(grep -m1 '^IN #' "$c/log/zenity")"

# 5. learning, the user closes the window (zenity exits at once): one notification, the script ends, no second window
c=$tmp/c5
mkdir -p "$c/pub"
echo learning >"$c/pub/session-mode"
status_json "$c" "$msg_net" null
check "closed: exit 0 (not killed by the timeout)" 0 "$(run "$c" FAKE_ZENITY=quit)"
check "closed: one window only" 1 "$(count "$c/log/zenity")"
check "closed: one notification" 1 "$(count "$c/log/notify")"
check "closed: notification body" yes "$(has "ARG $msg_net" "$c/log/notify")"

# 6. Thai and Chinese first lines
c=$tmp/c6
mkdir -p "$c/pub"
status_json "$c" "$msg_net" null
run "$c" LANG=th_TH.UTF-8 >/dev/null
check "th: Thai first line" yes "$(has 'ARG ยังไม่ได้ติดตั้งเว็บเบราว์เซอร์' "$c/log/notify")"
c=$tmp/c6z
mkdir -p "$c/pub"
status_json "$c" "$msg_net" null
run "$c" LANG=zh_CN.UTF-8 >/dev/null
check "zh: Chinese first line" yes "$(has 'ARG 浏览器还没有安装好。' "$c/log/notify")"

# 6b. the last screen in Chinese and Thai too
for l in 'zh_CN.UTF-8:浏览器已经装好。请注销后重新登录才能看到它。' 'th_TH.UTF-8:เว็บเบราว์เซอร์พร้อมแล้ว ออกจากระบบแล้วเข้าสู่ระบบใหม่เพื่อดูเบราว์เซอร์'; do
	c=$tmp/c6r-${l%%_*}
	mkdir -p "$c/pub"
	echo learning >"$c/pub/session-mode"
	status_json "$c" "$msg_net" null
	(
		sleep 1
		printf '#!/bin/sh\n' >"$c/chrome"
		chmod +x "$c/chrome"
	) &
	run "$c" LANG="${l%%:*}" >/dev/null
	wait
	check "${l%%_*}: last screen" "IN # ${l#*:}" "$(grep '^IN' "$c/log/zenity" | tail -n2 | head -n1)"
done

# 7. kiosk accounts get nothing (belt and braces next to the target drop-in); guest is an ordinary locked user
c=$tmp/c7
mkdir -p "$c/pub"
echo learning >"$c/pub/session-mode"
status_json "$c" "$msg_net" null
check "kiosk: exit 0" 0 "$(run "$c" USER=kiosk-nwea)"
check "kiosk: no notification" 0 "$(count "$c/log/notify")"
check "kiosk: no window" 0 "$(count "$c/log/zenity")"
c=$tmp/c8
mkdir -p "$c/pub"
echo learning >"$c/pub/session-mode"
status_json "$c" "$msg_net" null
check "guest: closed window still ends cleanly" 0 "$(run "$c" USER=guest FAKE_ZENITY=quit)"
check "guest: gets the window" 1 "$(count "$c/log/zenity")"

# 8. no status.json (an unmanaged machine: no agent writes it): nothing at all, whatever the session mode
c=$tmp/c9
mkdir -p "$c/pub"
check "no status: exit 0" 0 "$(run "$c")"
check "no status: no notification" 0 "$(count "$c/log/notify")"
check "no status: no window" 0 "$(count "$c/log/zenity")"
c=$tmp/c9l
mkdir -p "$c/pub"
echo learning >"$c/pub/session-mode"
check "no status, learning: exit 0" 0 "$(run "$c")"
check "no status, learning: no notification" 0 "$(count "$c/log/notify")"
check "no status, learning: no window" 0 "$(count "$c/log/zenity")"

echo "browser-wait-test: $((n - fails))/$n passed"
[ "$fails" -eq 0 ]
