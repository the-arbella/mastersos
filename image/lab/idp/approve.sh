#!/bin/bash
# Runs on the Mac: approves, as the "other device", a device-code login started in a laptop's GDM (in the playwright
# container on VM 163).
#   approve.sh zitadel <code> <loginname> <shotprefix>   spikes/s1/zitadel/approve.py (S1)
#   approve.sh dex <code> <kanidm user> <shotprefix>     lab/idp/dex/approve.py (Dex → Kanidm)
# The password is read from stdin and handed to the container through ssh's stdin (never on a command line).
# Screenshots are copied to APPROVE_SHOTS (not copied by default).
# shellcheck disable=SC2029 # local expansion is intended: arguments are validated before going into remote commands
set -euo pipefail
[ $# -eq 4 ] || {
	echo "usage: approve.sh zitadel|dex <code> <user> <screenshot prefix>" >&2
	exit 2
}
kind=$1 code=$2 user=$3 pre=$4
[[ $code =~ ^[A-Za-z0-9-]+$ && $user =~ ^[A-Za-z0-9._@-]+$ && $pre =~ ^[A-Za-z0-9._-]+$ ]] || {
	echo "approve.sh: argument contains a character that is not allowed" >&2
	exit 2
}
here=$(cd "$(dirname "$0")" && pwd)
host=${MASTERSOS_IDP_HOST:-mastersos-s1idp}
case "$kind" in
zitadel) src=$here/../../../spikes/s1/zitadel/approve.py ;;
dex) src=$here/dex/approve.py ;;
*)
	echo "approve.sh: unknown IdP $kind" >&2
	exit 2
	;;
esac
scp -q "$src" "$host:idp/approve-$kind.py"
ssh -n "$host" 'sudo docker image inspect s1-pw >/dev/null 2>&1 || (printf "FROM mcr.microsoft.com/playwright/python:v1.56.0-noble\nRUN pip install -q playwright==1.56.0\n" | sudo docker build -q -t s1-pw -) >/dev/null'
if [ "$kind" = zitadel ]; then
	# S1's script takes the password as an argument: read it from stdin into a variable on VM 163, never on the Mac's command line
	ssh "$host" "read -r pw; mkdir -p ~/out; sudo docker run --rm --network host -v ~/idp:/w -v ~/out:/out s1-pw python /w/approve-zitadel.py '$code' '$user' \"\$pw\" '$pre'"
else
	ssh "$host" "mkdir -p ~/out; sudo docker run --rm -i --network host -v ~/idp:/w -v ~/out:/out s1-pw python /w/approve-dex.py '$code' '$user' '$pre'"
fi
if [ -n "${APPROVE_SHOTS:-}" ]; then
	mkdir -p "$APPROVE_SHOTS"
	scp -q "$host:out/$pre-*.png" "$APPROVE_SHOTS/" 2>/dev/null || true
fi
ssh -n "$host" "rm -f ~/out/$pre-*.png"
