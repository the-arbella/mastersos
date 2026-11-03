#!/bin/bash
# Called by mkosi.finalize with the image root: the developer diagnostics drop-ins (docs/specs/2026-11-03-diagnostics-design.md)
# re-declare the packaged ExecStart of authd.service and wpa_supplicant.service with a $MASTERSOS_DIAG_* argument appended
# (empty without the switch). Those drop-ins apply on every machine, so the copy must stay the packaged line exactly: when an
# Ubuntu update changes it, the build stops here instead of our copy silently hiding the change.
#   check-execstart-copies.sh <root>
set -euo pipefail
root=${1:?usage: check-execstart-copies.sh <image root>}
sys=$root/usr/lib/systemd/system
rc=0
for unit in authd.service wpa_supplicant.service; do
	packaged=$(grep -E '^ExecStart=.+' "$sys/$unit" 2>/dev/null || true)
	# shellcheck disable=SC2016 # the sed pattern matches a literal $MASTERSOS_DIAG_...
	copy=$(grep -E '^ExecStart=.+' "$sys/$unit.d/90-mastersos-diag.conf" 2>/dev/null | sed -E 's/ \$MASTERSOS_DIAG_[A-Z_]+$//' || true)
	if [ -z "$packaged" ] || [ "$packaged" != "$copy" ]; then
		echo "check-execstart-copies: $unit: packaged '${packaged:-<missing>}', copy in $unit.d/90-mastersos-diag.conf '${copy:-<missing>}'; update the copy" >&2
		rc=1
	fi
done
[ "$rc" = 0 ] && echo "check-execstart-copies: authd and wpa_supplicant drop-ins match the packaged ExecStart"
exit "$rc"
