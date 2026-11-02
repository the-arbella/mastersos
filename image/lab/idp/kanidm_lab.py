"""Shared harness for the kanidm-*-experiment.py scripts: a throwaway kanidmd and the calls Dex and a browser make.

Every experiment starts its own kanidmd on 127.0.0.1:18400 (domain idm.lan) in a work directory of its own, sets up
a person `s1` in group `laptop` and a confidential OAuth2 client `mastersos-dex` (redirect https://dex.test/callback),
and never touches anything else. Nothing here prints a password, token or client secret.

The kanidmd binary needs Kanidm's web UI files at the path compiled into it (router/idm/profiles/openwrt.toml:
/usr/share/kanidm/hpkg); copy them from a router running routerui-idm.
"""
import base64
import hashlib
import http.client
import json
import os
import secrets
import socket
import ssl
import subprocess
import time
import urllib.parse

PORT = 18400
REDIRECT = "https://dex.test/callback"
PW = "correct horse battery staple 2026"
DAY = 86400


def say(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


class Lab:
    def __init__(self, kanidmd, work):
        self.bin, self.work = kanidmd, work
        os.makedirs(work, exist_ok=True)
        self.conf = os.path.join(work, "server.toml")
        with open(self.conf, "w") as f:
            f.write(f"""version = "2"
bindaddress = "127.0.0.1:{PORT}"
adminbindpath = "{work}/kanidmd.sock"
db_path = "{work}/kanidm.db"
tls_chain = "{work}/chain.pem"
tls_key = "{work}/key.pem"
domain = "idm.lan"
origin = "https://idm.lan:{PORT}"
log_level = "info"
""")
        if not os.path.exists(f"{work}/chain.pem"):
            self.kanidmd("cert-generate")
        self.log = open(f"{work}/kanidmd.log", "w")
        self.srv = subprocess.Popen([kanidmd, "server", "-c", self.conf], stdout=self.log, stderr=self.log)
        self.ctx = ssl.create_default_context(cafile=f"{work}/chain.pem")
        for _ in range(60):
            try:
                if self.call("GET", "/status")[0] == 200:
                    break
            except OSError:
                pass
            time.sleep(1)
        else:
            raise SystemExit("kanidmd did not come up")
        self.admin = self.login("idm_admin", self.recover("idm_admin"))
        A = dict(bearer=self.admin)
        self.ok(self.call("PUT", "/v1/group/idm_all_persons/_attr/credential_type_minimum", ["any"], **A), "credmin")
        self.ok(self.call("POST", "/v1/group", {"attrs": {"name": ["laptop"]}}, **A), "group")
        self.person("s1", "laptop")
        self.ok(self.call("POST", "/v1/oauth2/_basic", {"attrs": {
            "name": ["mastersos-dex"], "displayname": ["MastersOS Dex"], "oauth2_rs_origin_landing": ["https://dex.test/"]}},
            **A), "oauth2")
        self.ok(self.call("POST", "/v1/oauth2/mastersos-dex/_attr/oauth2_rs_origin", [REDIRECT], **A), "origin")
        self.ok(self.call("POST", "/v1/oauth2/mastersos-dex/_scopemap/laptop",
                          ["openid", "email", "profile", "offline_access"], **A), "scopemap")
        self.secret = self.ok(self.call("GET", "/v1/oauth2/mastersos-dex/_basic_secret", **A), "secret")

    def close(self):
        self.srv.terminate()
        self.srv.wait()

    # --- plumbing ---------------------------------------------------------------------------------------------------

    def kanidmd(self, *args):
        return subprocess.run([self.bin, *args, "-c", self.conf], check=True, capture_output=True, text=True).stdout

    def recover(self, who):
        """A generated password (`kanidmd scripting recover-account`). Its logins are read-write, capped at 1 h."""
        for line in reversed(self.kanidmd("scripting", "recover-account", who).splitlines()):
            try:
                return json.loads(line)["output"]
            except Exception:
                pass
        raise SystemExit("recover-account: no json")

    def conn(self):
        lab = self

        class Conn(http.client.HTTPSConnection):
            def connect(self):
                self.sock = lab.ctx.wrap_socket(socket.create_connection(("127.0.0.1", PORT), 10),
                                                server_hostname="idm.lan")
        return Conn("idm.lan", PORT)

    def call(self, method, path, body=None, bearer=None, headers=None, form=None, basic=None):
        h = dict(headers or {})
        if bearer:
            h["Authorization"] = f"Bearer {bearer}"
        if basic:
            h["Authorization"] = "Basic " + base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
        data = None
        if form is not None:
            data = urllib.parse.urlencode(form)
            h["Content-Type"] = "application/x-www-form-urlencoded"
        elif body is not None:
            data = json.dumps(body)
            h["Content-Type"] = "application/json"
        c = self.conn()
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        raw = r.read()
        try:
            j = json.loads(raw) if raw else None
        except Exception:
            j = raw.decode(errors="replace")
        return r.status, {k.lower(): v for k, v in r.getheaders()}, j

    @staticmethod
    def ok(res, what):
        st, _, j = res
        if not 200 <= st < 300:
            raise SystemExit(f"{what}: {st} {j}")
        return j

    # --- people and sessions ----------------------------------------------------------------------------------------

    def person(self, name, *groups):
        A = dict(bearer=self.admin)
        self.ok(self.call("POST", "/v1/person", {"attrs": {"name": [name], "displayname": [name]}}, **A), name)
        for g in groups:
            self.ok(self.call("POST", f"/v1/group/{g}/_attr/member", [name], **A), f"{g} += {name}")

    def set_pw(self, who, new=PW):
        """A password the person chose (credential update), so logins are privilege-capable like a browser's."""
        A = dict(bearer=self.admin)
        tok = self.ok(self.call("GET", f"/v1/person/{who}/_credential/_update_intent/600", **A), "intent")["token"]
        sess = self.ok(self.call("POST", "/v1/credential/_exchange_intent", tok), "exchange")[0]
        self.ok(self.call("POST", "/v1/credential/_update", [{"password": new}, sess]), "update")
        self.ok(self.call("POST", "/v1/credential/_commit", sess), "commit")

    def login(self, user, pw, privileged=None):
        step = {"username": user, "issue": "token"}
        if privileged is not None:
            step["privileged"] = privileged
        st, h, _ = self.call("POST", "/v1/auth", {"step": {"init2": step}})
        hh = {"X-KANIDM-AUTH-SESSION-ID": h["x-kanidm-auth-session-id"]}
        self.ok(self.call("POST", "/v1/auth", {"step": {"begin": "password"}}, headers=hh), "begin")
        return self.ok(self.call("POST", "/v1/auth", {"step": {"cred": {"password": pw}}}, headers=hh),
                       "cred")["state"]["success"]

    def sessions(self, who, tok):
        """(session id prefix, state, lifetime in days) of each login of `who`, read with their own token."""
        j = self.ok(self.call("GET", f"/v1/account/{who}/_user_auth_token", bearer=tok), "uat")
        return [(x["session_id"][:8], x["state"],
                 round((x["state"]["expiresat"] - x["issued_at"]) / DAY, 2) if isinstance(x["state"], dict) else None)
                for x in j]

    def policy(self, session_secs=None, refresh_secs=None):
        A = dict(bearer=self.admin)
        if session_secs is not None:
            self.ok(self.call("PUT", "/v1/group/idm_all_accounts/_attr/authsession_expiry", [str(session_secs)], **A),
                    "session")
        if refresh_secs is not None:
            self.ok(self.call("PATCH", "/v1/oauth2/mastersos-dex",
                              {"attrs": {"oauth2_refresh_token_expiry": [str(refresh_secs)]}}, **A), "refresh expiry")

    # --- what Dex does ----------------------------------------------------------------------------------------------

    def device_login(self, who, pw):
        """The phone in the device flow, through the JSON API: log in, consent, and Dex exchanges the code (PKCE)."""
        uat = self.login(who, pw)
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        req = {"response_type": "code", "client_id": "mastersos-dex", "state": "x", "redirect_uri": REDIRECT,
               "scope": "openid email profile offline_access", "code_challenge": challenge,
               "code_challenge_method": "S256"}
        st, h, j = self.call("POST", "/oauth2/authorise", req, bearer=uat)
        if isinstance(j, dict) and "ConsentRequested" in j:
            st, h, _ = self.call("POST", "/oauth2/authorise/permit", j["ConsentRequested"]["consent_token"], bearer=uat)
        # Consent given before: Kanidm answers Permitted with the redirect straight away.
        return self.exchange(code_from(h["location"]), verifier)

    def exchange(self, code, verifier=None):
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT}
        if verifier:
            form["code_verifier"] = verifier
        t = self.ok(self.call("POST", "/oauth2/token", form=form, basic=("mastersos-dex", self.secret)), "token")
        assert "refresh_token" in t
        return t["refresh_token"]

    def refresh(self, rt):
        st, _, j = self.call("POST", "/oauth2/token", form={"grant_type": "refresh_token", "refresh_token": rt},
                             basic=("mastersos-dex", self.secret))
        if st == 200:
            return "ok", j["refresh_token"]
        return f"{st} {j.get('error') if isinstance(j, dict) else j}", rt


def code_from(loc):
    return urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)["code"][0]


class Browser:
    """Just enough of a browser for Kanidm's HTML views: a cookie jar and form posts."""

    def __init__(self, lab):
        self.lab, self.jar = lab, {}

    def req(self, method, path, form=None):
        h = {"Cookie": "; ".join(f"{k}={v}" for k, v in self.jar.items())} if self.jar else {}
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            h["Content-Type"] = "application/x-www-form-urlencoded"
            h["Origin"] = f"https://idm.lan:{PORT}"
        c = self.lab.conn()
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        text = r.read().decode(errors="replace")
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                name, _, rest = v.partition("=")
                val = rest.split(";")[0]
                if val == "" or "Max-Age=0" in v:
                    self.jar.pop(name, None)
                else:
                    self.jar[name] = val
        return r.status, r.getheader("Location"), text
