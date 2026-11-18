#!/usr/bin/env bash
# The sign-in card's Chrome policy in a real Chrome: for every fixture in fixtures/card-policy/ (the policies the agent
# renders, kept equal to the code by mastersos-agent's card_policy_fixtures_match_the_code test), install it as Chrome's
# only managed policy, start a headless Chrome and check each `allow` / `block` line of <name>.cases
# (card-policy-chrome-test.mjs). Needs google-chrome-stable (or $CHROME: the extracted .deb is enough), node >= 22 and
# unshare(1). Chrome on Linux reads managed policy only from /etc/opt/chrome/policies/managed, so the test runs in a mount
# namespace of its own (an unprivileged user namespace when not root) with a tmpfs on /etc/opt: the host's /etc is never
# touched.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
if [ "${1:-}" != --in-namespace ]; then
	if [ "$(id -u)" = 0 ]; then
		exec unshare --mount --propagation private bash "$0" --in-namespace
	fi
	exec unshare --map-root-user --mount --propagation private bash "$0" --in-namespace
fi

fixtures=$here/fixtures/card-policy
chrome=${CHROME:-$(command -v google-chrome-stable || command -v google-chrome || true)}
[ -n "$chrome" ] || {
	echo "card-policy-chrome-test: no google-chrome-stable (set CHROME)" >&2
	exit 1
}
command -v node >/dev/null || {
	echo "card-policy-chrome-test: no node" >&2
	exit 1
}
[ -d /etc/opt ] || {
	echo "card-policy-chrome-test: no /etc/opt to mount over" >&2
	exit 1
}
mount -t tmpfs -o mode=0755 tmpfs /etc/opt
policy_dir=/etc/opt/chrome/policies/managed
mkdir -p "$policy_dir"

work=$(mktemp -d)
trap 'rm -rf "$work" || true' EXIT

fail=0
n=0
for policy in "$fixtures"/*.json; do
	name=$(basename "$policy" .json)
	cases=$fixtures/$name.cases
	[ -f "$cases" ] || {
		echo "card-policy-chrome-test: $name.cases is missing" >&2
		exit 1
	}
	n=$((n + 1))
	echo "== $name"
	# Every key as the agent writes it but DeveloperToolsAvailability: its 2 (the card's, checked by the agent's tests) also
	# shuts the DevTools protocol this test drives Chrome with ("Target.attachToTarget: Not allowed").
	node -e '
const fs = require("node:fs");
const p = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
if (p.DeveloperToolsAvailability !== 2) throw new Error(process.argv[1] + ": DeveloperToolsAvailability is not 2");
delete p.DeveloperToolsAvailability;
fs.writeFileSync(process.argv[2], JSON.stringify(p, null, 2), {mode: 0o644});
' "$policy" "$policy_dir/mastersos-login.json"
	mkdir -p "$work/profile-$name"
	if ! node "$here/card-policy-chrome-test.mjs" "$chrome" "$work/profile-$name" "$work/chrome-$name.log" "$cases"; then
		fail=1
		echo "-- the end of Chrome's log for $name:"
		tail -n 20 "$work/chrome-$name.log"
	fi
done
[ "$n" -gt 0 ] || {
	echo "card-policy-chrome-test: no fixtures in $fixtures" >&2
	exit 1
}
exit "$fail"
