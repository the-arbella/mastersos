#!/bin/bash
# The session environment comes from the system only on a learning-mode device (locked-session hardening, 2026-11-10): the
# image's user environment generators drop the user's ~/.config/environment.d (a DCONF_PROFILE there switches every dconf
# lock off) and Flatpak's per-user export dir (a user-writable XDG_DATA_DIRS entry, where gnome-shell would load a
# look-alike extension as a system one). In full mode, or before the device has any settings (no session-mode file), they
# hand over to the distribution's generators unchanged: teachers keep their own environment.d and user Flatpaks.
# Runs copies of the image's two generators with the session-mode file redirected, against a fake home; the first needs
# systemd's own generator, the second a fake flatpak on PATH that prints its arguments. Linux only (CI image-lint, or a
# ubuntu:24.04 container as non-root):
#   bash image/tests/user-env-test.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
gens=$here/../mkosi.extra/usr/local/lib/systemd/user-environment-generators
sysd=/usr/lib/systemd/user-environment-generators/30-systemd-environment-d-generator

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

[ -x "$sysd" ] || {
	echo "user-env-test: $sysd is missing (systemd not installed)" >&2
	exit 1
}
home=$tmp/home
mkdir -p "$home/.config/environment.d"
printf 'DCONF_PROFILE=%s/evil\nGSETTINGS_BACKEND=memory\n' "$home" >"$home/.config/environment.d/50-x.conf"
run() { env -i HOME="$home" PATH=/usr/bin:/bin "$@"; }

# The image's generators, reading the session-mode files from the test's public dir (their only paths to them): the
# legacy file and, under settings format 3, the `session` link (its session-mode and uid)
mkdir -p "$tmp/gen" "$tmp/public"
for g in 30-systemd-environment-d-generator 60-flatpak; do
	for l in mode_file=/var/lib/mastersos-public/session-mode session_dir=/var/lib/mastersos-public/session; do
		grep -qxF "$l" "$gens/$g" || {
			echo "user-env-test: $g has no line $l" >&2
			exit 1
		}
	done
	sed -e "s|^mode_file=/var/lib/mastersos-public/session-mode$|mode_file=$tmp/public/session-mode|" \
		-e "s|^session_dir=/var/lib/mastersos-public/session$|session_dir=$tmp/public/session|" \
		"$gens/$g" >"$tmp/gen/$g"
	chmod +x "$tmp/gen/$g"
done
mode() { if [ "$1" = none ]; then rm -f "$tmp/public/session-mode"; else printf '%s\n' "$1" >"$tmp/public/session-mode"; fi; }
has() { grep -q "$1" <<<"$2" && echo yes || echo no; }

# The setup is real: systemd's own generator reads the user's file
check "systemd's generator reads ~/.config/environment.d (setup)" yes "$(has "^DCONF_PROFILE=$home/evil$" "$(run "$sysd")")"

mode learning
out=$(run "$tmp/gen/30-systemd-environment-d-generator")
check "learning: DCONF_PROFILE left out" no "$(has '^DCONF_PROFILE=' "$out")"
check "learning: GSETTINGS_BACKEND left out" no "$(has '^GSETTINGS_BACKEND=' "$out")"
# The system's own environment.d may set XDG_CONFIG_HOME (GitHub's runners do, from /etc/environment): the generator
# adds none of its own to what systemd's gives a home with no files
mkdir -p "$tmp/empty-home"
base=$(env -i HOME="$tmp/empty-home" PATH=/usr/bin:/bin "$sysd" | grep '^XDG_CONFIG_HOME=' || true)
check "learning: no XDG_CONFIG_HOME of its own" "$base" "$(grep '^XDG_CONFIG_HOME=' <<<"$out" || true)"
# An XDG_CONFIG_HOME already in the manager's environment does not bring the user's files back either
mkdir -p "$home/cfg/environment.d"
cp "$home/.config/environment.d/50-x.conf" "$home/cfg/environment.d/"
check "learning: an inherited XDG_CONFIG_HOME is ignored too" no \
	"$(has '^DCONF_PROFILE=' "$(run XDG_CONFIG_HOME="$home/cfg" "$tmp/gen/30-systemd-environment-d-generator")")"
# A learning file with stray whitespace or case is still learning (fail towards the lock)
printf ' Learning \n' >"$tmp/public/session-mode"
check "learning (spaced, capitalised): DCONF_PROFILE left out" no "$(has '^DCONF_PROFILE=' "$(run "$tmp/gen/30-systemd-environment-d-generator")")"

# Garbage (not even text) is learning too: only a file reading `full` (trimmed, any case) or no file is full
printf '\377\n' >"$tmp/public/session-mode"
check "garbage: DCONF_PROFILE left out" no "$(has '^DCONF_PROFILE=' "$(run "$tmp/gen/30-systemd-environment-d-generator")")"
printf ' FULL \n' >"$tmp/public/session-mode"
check "full (spaced, capitalised): the user's environment.d is read" "$(run "$sysd")" "$(run "$tmp/gen/30-systemd-environment-d-generator")"

for m in full none; do
	mode "$m"
	check "$m: the user's environment.d is read as on Ubuntu" "$(run "$sysd")" "$(run "$tmp/gen/30-systemd-environment-d-generator")"
done

# Flatpak: system installation only in learning mode
mkdir -p "$tmp/bin"
# shellcheck disable=SC2016 # the fake flatpak expands these itself
printf '#!/bin/sh\necho "GIO_USE_VFS=$GIO_USE_VFS ARGS=$*"\n' >"$tmp/bin/flatpak"
chmod +x "$tmp/bin/flatpak"
fp() { env -i HOME="$home" PATH="$tmp/bin:/usr/bin:/bin" "$tmp/gen/60-flatpak"; }
mode learning
check "learning: 60-flatpak asks for the system installation only" "GIO_USE_VFS=local ARGS=--print-updated-env --print-system-only" "$(fp)"
printf '\377\n' >"$tmp/public/session-mode"
check "garbage: 60-flatpak asks for the system installation only" "GIO_USE_VFS=local ARGS=--print-updated-env --print-system-only" "$(fp)"
for m in full none; do
	mode "$m"
	check "$m: 60-flatpak includes the user's installation" "GIO_USE_VFS=local ARGS=--print-updated-env" "$(fp)"
done

# Settings format 3: with the `session` link (to the user config's dir) its mode decides, but only for the uid in
# session/uid; another uid, no uid file or a dangling link is locked, whatever the legacy file says (always `learning`
# under format 3; `full` here to show it is not read).
sd=$tmp/public/user-layer/u-0123456789abcdef
mkdir -p "$sd"
ln -s user-layer/u-0123456789abcdef "$tmp/public/session"
me=$(id -u)
mode full
printf 'full\n' >"$sd/session-mode"
printf '%s\n' "$me" >"$sd/uid"
check "format 3, own full session: the user's environment.d is read" "$(run "$sysd")" "$(run "$tmp/gen/30-systemd-environment-d-generator")"
check "format 3, own full session: 60-flatpak includes the user's installation" "GIO_USE_VFS=local ARGS=--print-updated-env" "$(fp)"
printf 'learning\n' >"$sd/session-mode"
check "format 3, own learning session: DCONF_PROFILE left out" no "$(has '^DCONF_PROFILE=' "$(run "$tmp/gen/30-systemd-environment-d-generator")")"
check "format 3, own learning session: 60-flatpak asks for the system installation only" "GIO_USE_VFS=local ARGS=--print-updated-env --print-system-only" "$(fp)"
printf 'full\n' >"$sd/session-mode"
printf '%s\n' "$((me + 1))" >"$sd/uid"
check "format 3, another uid's full session: DCONF_PROFILE left out" no "$(has '^DCONF_PROFILE=' "$(run "$tmp/gen/30-systemd-environment-d-generator")")"
check "format 3, another uid's full session: 60-flatpak asks for the system installation only" "GIO_USE_VFS=local ARGS=--print-updated-env --print-system-only" "$(fp)"
rm "$sd/uid"
check "format 3, no uid file: DCONF_PROFILE left out" no "$(has '^DCONF_PROFILE=' "$(run "$tmp/gen/30-systemd-environment-d-generator")")"
check "format 3, no uid file: 60-flatpak asks for the system installation only" "GIO_USE_VFS=local ARGS=--print-updated-env --print-system-only" "$(fp)"
rm -r "$sd"
check "format 3, dangling link: DCONF_PROFILE left out" no "$(has '^DCONF_PROFILE=' "$(run "$tmp/gen/30-systemd-environment-d-generator")")"
rm "$tmp/public/session"

# The login screen's account (its home, from the account database, is under gdm's runtime directory) keeps its own
# environment.d in every mode: gdm passes DCONF_PROFILE=gdm through it, and without it there is no login screen. Any
# other account stays locked (every check above ran with the real directory, which holds nobody's home here).
grep -qxF 'greeter_home=/run/gdm3/home' "$gens/30-systemd-environment-d-generator" || {
	echo "user-env-test: 30-systemd-environment-d-generator has no line greeter_home=/run/gdm3/home" >&2
	exit 1
}
acct_home=$(getent passwd "$(id -u)" | cut -d: -f6)
[ -n "$acct_home" ] || {
	echo "user-env-test: this user has no home in the account database" >&2
	exit 1
}
sed "s|^greeter_home=/run/gdm3/home$|greeter_home=${acct_home%/*}|" "$tmp/gen/30-systemd-environment-d-generator" >"$tmp/gen/greeter"
chmod +x "$tmp/gen/greeter"
mkdir -p "$sd"
ln -s user-layer/u-0123456789abcdef "$tmp/public/session"
printf 'learning\n' >"$sd/session-mode"
for m in learning full none; do
	mode "$m"
	check "login screen account, legacy mode $m, format 3 link: its environment.d is read" "$(run "$sysd")" "$(run "$tmp/gen/greeter")"
done
rm -r "$sd" "$tmp/public/session"
mode learning
check "login screen account, learning without the link: its environment.d is read" "$(run "$sysd")" "$(run "$tmp/gen/greeter")"
check "another account in the same mode stays locked" no "$(has '^DCONF_PROFILE=' "$(run "$tmp/gen/30-systemd-environment-d-generator")")"
# A home that only starts with the same text is not under the directory
sed "s|^greeter_home=/run/gdm3/home$|greeter_home=${acct_home%?}|" "$tmp/gen/30-systemd-environment-d-generator" >"$tmp/gen/prefix"
chmod +x "$tmp/gen/prefix"
check "a home that merely shares the prefix stays locked" no "$(has '^DCONF_PROFILE=' "$(run "$tmp/gen/prefix")")"

# The session's xdg dir (format 3) is the first data directory, before the device's
envd=$here/../mkosi.extra/usr/lib/environment.d/40-mastersos.conf
dirs=$(sed -n 's/^XDG_DATA_DIRS=//p' "$envd")
check "XDG_DATA_DIRS starts with the session's xdg dir" /var/lib/mastersos-public/session/xdg "${dirs%%:*}"
rest=${dirs#*:}
check "then the device's xdg dir" /var/lib/mastersos-public/xdg "${rest%%:*}"

echo "user-env-test: $((n - fails))/$n"
[ "$fails" = 0 ]
