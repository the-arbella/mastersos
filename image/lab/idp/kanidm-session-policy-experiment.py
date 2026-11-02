#!/usr/bin/env python3
"""How long a real password login lasts at Kanidm 1.11.2 under two account-policy designs (docs/idp.md「会话期限」):
A: long value only on a "laptop users" group, idm_all_accounts left at the factory one day;
B: fleetd's — long on idm_all_accounts, one day on routerui_admin_sessions holding idm_high_privilege, pbx_admins,
pbx_operators.

Usage: kanidm-session-policy-experiment.py <kanidmd> <workdir>     (harness and setup: kanidm_lab.py)
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kanidm_lab import DAY, PW, Lab  # noqa: E402

lab = Lab(sys.argv[1], sys.argv[2])
A = dict(bearer=lab.admin)
G = "routerui_admin_sessions"
for g in ("pbx_admins", "pbx_operators"):
    lab.ok(lab.call("POST", "/v1/group", {"attrs": {"name": [g]}}, **A), g)
lab.person("a1", "laptop", "pbx_admins")
lab.set_pw("s1")
lab.set_pw("a1")


def days(who):
    tok = lab.login(who, PW, privileged=False)
    time.sleep(3)
    return max(lab.sessions(who, tok), key=lambda s: s[2] or 0)[2]


# A
lab.ok(lab.call("POST", "/v1/group/laptop/_attr/class", ["account_policy"], **A), "class")
lab.ok(lab.call("PUT", "/v1/group/laptop/_attr/authsession_expiry", [str(90 * DAY)], **A), "laptop")
print("A (laptop group=90d, idm_all_accounts=factory):", "s1", days("s1"), "a1", days("a1"))

# B
lab.ok(lab.call("DELETE", "/v1/group/laptop/_attr/authsession_expiry", **A), "unset")
lab.policy(90 * DAY)
lab.ok(lab.call("POST", "/v1/group", {"attrs": {"name": [G]}}, **A), "group")
lab.ok(lab.call("POST", f"/v1/group/{G}/_attr/class", ["account_policy"], **A), "class")
lab.ok(lab.call("POST", f"/v1/group/{G}/_attr/member", ["idm_high_privilege", "pbx_admins", "pbx_operators"], **A),
       "member")
lab.ok(lab.call("PUT", f"/v1/group/{G}/_attr/authsession_expiry", [str(DAY)], **A), "exp")
print("B (idm_all_accounts=90d, admin group=1d):", "s1", days("s1"), "a1 (pbx_admins)", days("a1"))
lab.close()
