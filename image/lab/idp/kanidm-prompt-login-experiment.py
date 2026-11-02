#!/usr/bin/env python3
"""Dex's `promptType: login` against Kanidm 1.11.2 (docs/idp.md「会话期限」): at a browser that still holds someone's
Kanidm login, does approving a device code need their password, and does the refresh chain still work afterwards?

Dex v2.44's oidc connector sends `access_type=offline&prompt=<promptType>` when it asks for offline_access
(connector/oidc/oidc.go:370-371); this drives Kanidm's HTML views with exactly those parameters, with a browser
that holds s1's live 90-day login.

Usage: kanidm-prompt-login-experiment.py <kanidmd> <workdir>     (harness and setup: kanidm_lab.py)
"""
import os
import re
import secrets
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kanidm_lab import DAY, PW, REDIRECT, Browser, Lab, code_from, say  # noqa: E402

lab = Lab(sys.argv[1], sys.argv[2])
lab.policy(90 * DAY, 90 * DAY)
# Dex v2.44 does not do PKCE: the lab's mastersos-dex has it off (docs/idp.md step 1).
lab.ok(lab.call("PATCH", "/v1/oauth2/mastersos-dex",
                {"attrs": {"oauth2_allow_insecure_client_disable_pkce": ["true"]}}, bearer=lab.admin), "pkce off")
lab.set_pw("s1")
# The shared browser: s1 logged into Kanidm there earlier.
t0 = lab.login("s1", PW, privileged=False)
time.sleep(2)
say("browser login before:", lab.sessions("s1", t0))


def dex_redirect(prompt):
    q = {"response_type": "code", "client_id": "mastersos-dex", "state": secrets.token_hex(8), "redirect_uri": REDIRECT,
         "scope": "openid email profile offline_access", "access_type": "offline", "prompt": prompt}
    return "/ui/oauth2?" + urllib.parse.urlencode(q)


def browser():
    b = Browser(lab)
    b.jar["bearer"] = t0
    return b


def finish(b, st, loc, text):
    """Follow resume / consent until Kanidm redirects to Dex's callback with a code."""
    for _ in range(6):
        if loc and loc.startswith(REDIRECT):
            return code_from(loc)
        if loc:
            st, loc, text = b.req("GET", loc if loc.startswith("/") else urllib.parse.urlparse(loc).path)
            continue
        m = re.search(r'name="consent_token"[^>]*value="([^"]+)"', text) or \
            re.search(r'value="([^"]+)"[^>]*name="consent_token"', text)
        if m:
            st, loc, text = b.req("POST", "/ui/oauth2/consent", {"consent_token": m.group(1)})
            continue
        raise SystemExit(f"stuck at {st}")
    raise SystemExit("too many steps")


# 1. promptType: consent (Dex's default): the live login approves without a password.
b = browser()
st, loc, text = b.req("GET", dex_redirect("consent"))
say("prompt=consent: password form shown:", 'name="password"' in text)
rt = lab.exchange(finish(b, st, loc, text))
say("prompt=consent: code issued without a password; refresh:", lab.refresh(rt)[0])

# 2. promptType: login: Kanidm asks the password again (a reauthentication of the same browser login).
b = browser()
st, loc, text = b.req("GET", dex_redirect("login"))
say("prompt=login: password form shown:", 'name="password"' in text)
st, loc, text = b.req("POST", "/ui/login/pw", {"password": PW})
say("prompt=login: right password ->", st, loc)
rt = lab.exchange(finish(b, st, loc, text))
time.sleep(1)
for i in range(3):
    r, rt = lab.refresh(rt)
    say(f"prompt=login: refresh {i + 1}:", r)
say("browser login after:", lab.sessions("s1", t0))

# 3. Someone else at that browser, without the password, gets no code. (Last: a wrong password softlocks the
#    credential for a while, which would make step 2 fail.)
b = browser()
b.req("GET", dex_redirect("login"))
st, loc, _ = b.req("POST", "/ui/login/pw", {"password": "not the password 1234"})
say("prompt=login: wrong password ->", st, "| code issued:", bool(loc and loc.startswith(REDIRECT)))
lab.close()
