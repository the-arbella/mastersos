#!/usr/bin/env python3
"""What bounds Dex's refresh chain at Kanidm 1.11.2, with short lifetimes (docs/idp.md「会话期限」).

Usage: kanidm-refresh-experiment.py <kanidmd> <workdir>     (harness and setup: kanidm_lab.py)
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kanidm_lab import DAY, PW, Lab, say  # noqa: E402

lab = Lab(sys.argv[1], sys.argv[2])
lab.set_pw("s1")
results = {}


def step(key, label, rt):
    r, rt = lab.refresh(rt)
    say(f"{label}:", r)
    results[key] = r
    return rt


# 1. Short login (60 s), long refresh-token lifetime. Refreshing does not extend the login: the first refresh after
#    the login expired still passes (the expired session is only swept by that write), every later one fails.
lab.policy(60, 3600)
rt = lab.device_login("s1", PW)
time.sleep(10)
rt = step("short_10s", "60 s login: refresh at 10 s", rt)
time.sleep(60)
rt = step("short_70s", "60 s login: refresh at 70 s (first after expiry)", rt)
rt = step("short_70s_again", "60 s login: refresh at 70 s (second after expiry)", rt)

# 2. The laptop case: log in, then nothing until after the login expired; then two online logins.
rt = lab.device_login("s1", PW)
time.sleep(70)
rt = step("idle_first", "60 s login, idle 70 s: first refresh", rt)
rt = step("idle_second", "60 s login, idle 70 s: second refresh", rt)

# 3. Long login (90 days) and refresh lifetime (90 days): the same gaps are fine.
lab.policy(90 * DAY, 90 * DAY)
rt2 = lab.device_login("s1", PW)
time.sleep(70)
for i in range(3):
    rt2 = step(f"long_{i + 1}", f"90 d login, after 70 s: refresh {i + 1}", rt2)

# 4. Account disabled (account_expire in the past): the next refresh fails at once; re-enabling revives the chain.
A = dict(bearer=lab.admin)
lab.ok(lab.call("PUT", "/v1/person/s1/_attr/account_expire", ["2020-01-01T00:00:00+00:00"], **A), "expire")
step("disabled", "90 d login: refresh right after disabling", rt2)
lab.ok(lab.call("DELETE", "/v1/person/s1/_attr/account_expire", **A), "unexpire")
step("reenabled", "90 d login: refresh after re-enabling (same chain)", rt2)

# 5. Password changed (credential rotated): the login is revoked and the next refresh fails at once.
rt3 = lab.device_login("s1", PW)
rt3 = step("pw_before", "password change: refresh before", rt3)
lab.set_pw("s1", PW + " (changed)")
step("pwchange", "password change: refresh right after", rt3)

# 6. The client's refresh-token lifetime (oauth2_refresh_token_expiry, default 16 h) is a separate, sliding limit.
lab.policy(90 * DAY, 20)
rt4 = lab.device_login("s1", PW + " (changed)")
time.sleep(10)
rt4 = step("rt_10s", "20 s refresh lifetime: refresh at 10 s", rt4)
time.sleep(15)
rt4 = step("rt_slides", "20 s refresh lifetime: refresh 15 s later (slides)", rt4)
time.sleep(25)
step("rt_idle", "20 s refresh lifetime: unused for 25 s", rt4)

print(results)
lab.close()
