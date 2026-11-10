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

# The image's generators, reading the session-mode file from the test's public dir (their only path to it)
mkdir -p "$tmp/gen" "$tmp/public"
for g in 30-systemd-environment-d-generator 60-flatpak; do
	l=mode_file=/var/lib/mastersos-public/session-mode
	grep -qxF "$l" "$gens/$g" || {
		echo "user-env-test: $g has no line $l" >&2
		exit 1
	}
	sed -e "s|^mode_file=/var/lib/mastersos-public/session-mode$|mode_file=$tmp/public/session-mode|" "$gens/$g" >"$tmp/gen/$g"
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
check "learning: no XDG_CONFIG_HOME of its own" no "$(has '^XDG_CONFIG_HOME=' "$out")"
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

echo "user-env-test: $((n - fails))/$n"
[ "$fails" = 0 ]
