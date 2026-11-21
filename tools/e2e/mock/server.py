#!/usr/bin/env python3
"""A stateful mock of the protocol v1 settings server, for tools/e2e/protocol-v1.sh.

Our verification only: the server team's harness runs the real server. This mock stands in for
it on the remote build runner (tools/e2e/mock/run.sh) so the driving script can be run with our
real `mastersos` and `mastersos-agent` binaries. Python 3.11 or later, standard library only;
run it with `python3 -I`.

    python3 -I tools/e2e/mock/server.py [--ready-file PATH] [--school-id UUID] [--second-school-id UUID]
    python3 -I tools/e2e/mock/server.py --self-test VECTOR_DIR

It serves two origins on 127.0.0.1 (random free ports) and prints one JSON ready line on stdout:
{"server_url","school_id","second_school_id","control_url","arbella_stub"} (also written to
--ready-file).

Two schools, each with its own admin: a token belongs to the first admin, or to the second with
`?admin=second` on the control endpoint's `/token`. Neither administers the other's school
(`403 forbidden`); `GET schools` lists only the admin's own. Device routes pick the school from
the fetch token. `fetch-token/rotate` and `drop-retired` act on the first school only.

- The server: `/api/cli/v1/` (auth-config, schools, and the school's mastersos routes, with
  `DELETE devices/{id}/escrow-secret`) and
  `/api/device/v1/` (bundle, heartbeat, status, escrow, fetch-token, the reserved routes).
- The control endpoint: `POST /token[?admin=second]` (`{"step_up":true}` for a fresh sign-in; answers
  `{"fleet_url","access_token","expires_at"}`, what the stub `arbella` prints),
  `POST /fetch-token/rotate`, `POST /fetch-token/drop-retired`, `GET /healthz`.

What it checks, as protocol v1 and the wire table say: bearer tokens and step-up (a token is
"fresh" when its auth_time is at most 5 minutes old; plain tokens are minted with an old one),
strict request bodies (unknown members, duplicate members and wrong types are `400 invalid`;
`status` ignores unknown members), strict encodings (std-pad and url-nopad re-encoded and compared,
lowercase hex, lowercase UUIDs, canonical Bech32 `age1` recipients), key ids
(`rk-` + hex(sha256(public key)[:4])), fingerprints, probe nonces and `message_b64`, the publish
checks of section 4.4 in order (version, clock, school, trust registered, recipients registered
and bound, feature gate), the archive's member paths and limits, the content digest recomputed
from the archive (sorted paths, `path 0x00 sha256hex(content) \\n`, manifest.toml included,
signature excluded), the signer's key id (in the latest trust, version 1 its own, and in the new
trust), heartbeat statements (latest version and digest, clock, 1 to 31 days, signer's key id),
the rotation-step rule, fetch-token rotation, the stale marker and renewal, device secrets,
escrow envelopes (armor, X25519 stanza count, recipients_fp) and the recovery-key rows.

What it does NOT check (the real server does):
- No Ed25519 signature is verified (the standard library has no Ed25519): key probes, recipient
  bindings, the archive's `signature` member and heartbeats are checked for shape and key id only.
- age ciphertexts are not opened; X25519 stanzas are counted, not checked.
- Rate limits (429), the 5-pending-uploads-per-person cap, audit rows, the 90-day purge, device
  removal and restore, HMAC key versions, and the RFC 9470 challenge's exact parameters.
"""

import base64
import binascii
import datetime as dt
import gzip
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sys
import tarfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

try:
    import tomllib
except ImportError:  # pragma: no cover - checked at start
    tomllib = None

DEFAULT_SCHOOL = "0192f3a4-5b6c-7d8e-9f00-112233445566"
DEFAULT_SECOND_SCHOOL = "0192f3a4-5b6c-7d8e-9f00-665544332211"
SCHOOL_NAMES = ("E2E School", "E2E Second School")
STEP_UP_MAX_AGE = 300
TOKEN_LIFE = 3600
PROBE_LIFE = 300
PENDING_LIFE = 1800
CLOCK_SKEW = 600
MAX_ARCHIVE = 20 * 1024 * 1024
MAX_UNPACKED = 64 * 1024 * 1024
MAX_JSON = 1024 * 1024
MAX_STATUS = 64 * 1024
MAX_ESCROW = 4 * 1024
MAX_HEARTBEAT = 16 * 1024
I64_MAX = 2**63 - 1
U64_MAX = 2**64 - 1
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
KEY_ID_RE = re.compile(r"^rk-[0-9a-f]{8}$")
BUNDLE_PREFIX = b"mastersos-bundle-v1\n"
PROBE_PREFIX = b"mastersos-keyprobe-v1\n"
HEARTBEAT_PREFIX = b"mastersos-heartbeat-v1\n"
RECIPIENT_PREFIX = b"mastersos-escrow-recipient-v1\n"
RECIPIENTS_FP_PREFIX = b"mastersos-escrow-recipients-v1\n"
RESERVED = [
    ("POST", re.compile(r"^push-token$")),
    ("GET", re.compile(r"^inbox$")),
    ("POST", re.compile(r"^inbox/[^/]+/result$")),
    ("POST", re.compile(r"^diagnostics$")),
    ("POST", re.compile(r"^diagnostics/[^/]+/complete$")),
    ("POST", re.compile(r"^support$")),
]


class Refuse(Exception):
    """An error answer: status, code, message and optional details."""

    def __init__(self, status, code, message, details=None, headers=None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details
        self.headers = headers or {}


def invalid(message):
    return Refuse(400, "invalid", message)


# ---- Encodings (strict) ----


def std_pad(value, what, size=None):
    """Bytes of a strict standard base64 text with padding (canonical, no line breaks)."""
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", value) or len(value) % 4:
        raise invalid(f"{what} is not standard padded base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except binascii.Error:
        raise invalid(f"{what} is not standard padded base64") from None
    if base64.b64encode(raw).decode() != value:
        raise invalid(f"{what} is not canonical base64")
    if size is not None and len(raw) != size:
        raise invalid(f"{what} is not {size} bytes")
    return raw


def url_nopad(value, what, size=None):
    """Bytes of a strict URL-safe base64 text without padding (canonical)."""
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", value) or len(value) % 4 == 1:
        raise invalid(f"{what} is not URL-safe base64 without padding")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except binascii.Error:
        raise invalid(f"{what} is not URL-safe base64 without padding") from None
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != value:
        raise invalid(f"{what} is not canonical base64")
    if size is not None and len(raw) != size:
        raise invalid(f"{what} is not {size} bytes")
    return raw


def b64(raw):
    return base64.b64encode(raw).decode()


def b64url(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def key_id_of(public_key):
    return "rk-" + hashlib.sha256(public_key).digest()[:4].hex()


def fingerprint_of(public_key):
    h = hashlib.sha256(public_key).digest()[:8].hex()
    return "-".join(h[i : i + 4] for i in range(0, 16, 4))


BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def is_age_recipient(s):
    """Canonical lowercase Bech32 `age1...` of 62 characters with a valid checksum (32 bytes)."""
    if not isinstance(s, str) or len(s) != 62 or not s.startswith("age1"):
        return False
    data = s[4:]
    if any(c not in BECH32 for c in data):
        return False
    values = [BECH32.index(c) for c in data]
    hrp = [ord(c) >> 5 for c in "age"] + [0] + [ord(c) & 31 for c in "age"]
    if bech32_polymod(hrp + values) != 1:
        return False
    bits = 0
    acc = 0
    out = []
    for v in values[:-6]:
        acc = (acc << 5) | v
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    return len(out) == 32 and (acc & ((1 << bits) - 1)) == 0


def recipients_fp(recipients):
    h = hashlib.sha256(RECIPIENTS_FP_PREFIX)
    h.update("\n".join(sorted(set(recipients))).encode())
    return h.hexdigest()


def is_identifier(s, size=128):
    return (
        isinstance(s, str)
        and 1 <= len(s.encode()) <= size
        and not any(ord(c) < 0x20 or ord(c) == 0x7F for c in s)
    )


def is_fetch_token(s):
    return isinstance(s, str) and 1 <= len(s) <= 256 and all(0x21 <= ord(c) <= 0x7E for c in s)


def rfc3339(t):
    return dt.datetime.fromtimestamp(int(t), dt.timezone.utc).isoformat(timespec="seconds")


def parse_time(s, what):
    if not isinstance(s, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)", s):
        raise invalid(f"{what} is not an RFC 3339 time with an offset")
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        raise invalid(f"{what} is not an RFC 3339 time") from None


def no_duplicates(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise invalid(f"duplicate member {k!r}")
        seen[k] = v
    return seen


def strict(obj, required, optional=(), what="the body"):
    """The JSON object `obj` has every `required` member and nothing beyond `optional`."""
    if not isinstance(obj, dict):
        raise invalid(f"{what} is not a JSON object")
    missing = [k for k in required if k not in obj]
    if missing:
        raise invalid(f"{what} misses {', '.join(missing)}")
    extra = [k for k in obj if k not in required and k not in optional]
    if extra:
        raise invalid(f"{what} has unknown members: {', '.join(sorted(extra))}")
    return obj


def want_str(obj, key, what=None):
    v = obj.get(key)
    if not isinstance(v, str):
        raise invalid(f"{what or key} is not a string")
    return v


def want_u64(obj, key, top=U64_MAX):
    v = obj.get(key)
    if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= top:
        raise invalid(f"{key} is not an unsigned integer")
    return v


# ---- Archives ----


def content_digest(manifest, files):
    entries = {"manifest.toml": manifest}
    entries.update(files)
    outer = hashlib.sha256()
    for path in sorted(entries, key=lambda p: p.encode()):
        outer.update(path.encode() + b"\x00" + hashlib.sha256(entries[path]).hexdigest().encode() + b"\n")
    return outer.digest()


def member_ok(name, is_dir):
    parts = name.split("/")
    if name.startswith("/") or any(p in ("", ".", "..") for p in parts):
        return False
    if is_dir:
        return parts[0] in ("files", "scripts")
    if name in ("manifest.toml", "signature"):
        return True
    return parts[0] in ("files", "scripts") and len(parts) >= 2


def read_archive(data):
    """(manifest bytes, files, signature text) of a signed archive, with the shared limits."""
    bad = lambda why: Refuse(422, "archive_invalid", f"the archive is not valid: {why}")  # noqa: E731
    if len(data) > MAX_ARCHIVE:
        raise Refuse(413, "too_large", "the archive is larger than 20 MiB")
    try:
        raw = gzip.decompress(data)
    except (OSError, EOFError, gzip.BadGzipFile):
        raise bad("not gzip") from None
    if len(raw) > MAX_UNPACKED + 1024 * 1024:
        raise bad("unpacked larger than 64 MiB")
    manifest = None
    signature = None
    files = {}
    seen = set()
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:", encoding="utf-8", errors="strict") as tar:
            for m in tar:
                name = m.name[:-1] if m.isdir() and m.name.endswith("/") else m.name
                if name in seen:
                    raise bad(f"duplicate member {name!r}")
                seen.add(name)
                if m.isdir():
                    if not member_ok(name, True):
                        raise bad(f"member {name!r} is not allowed")
                    continue
                if not m.isfile() or not member_ok(name, False):
                    raise bad(f"member {name!r} is not allowed")
                total += m.size
                if total > MAX_UNPACKED:
                    raise bad("unpacked larger than 64 MiB")
                content = tar.extractfile(m).read()
                if name == "manifest.toml":
                    manifest = content
                elif name == "signature":
                    signature = content
                else:
                    files[name] = content
    except (tarfile.TarError, UnicodeError) as e:
        raise bad(f"not a tar archive ({type(e).__name__})") from None
    if manifest is None or signature is None:
        raise bad("manifest.toml or signature is missing")
    try:
        sig = tomllib.loads(signature.decode())
    except (UnicodeError, tomllib.TOMLDecodeError):
        raise bad("the signature member is not TOML") from None
    return manifest, files, sig


def check_signature_table(sig, what):
    """A shared `SignatureFile` / heartbeat `[signature]`: exactly key_id, alg, sig (64 bytes)."""
    if not isinstance(sig, dict) or set(sig) != {"key_id", "alg", "sig"}:
        raise Refuse(422, "invalid", f"{what} is not key_id, alg and sig")
    if not isinstance(sig["key_id"], str) or sig["alg"] != "ed25519":
        raise Refuse(422, "invalid", f"{what}: key_id or alg is wrong")
    try:
        std_pad(sig["sig"], f"{what} sig", 64)
    except Refuse as e:
        raise Refuse(422, "invalid", e.message) from None
    return sig["key_id"]


def frame_differences(frame, manifest):
    """The frame fields that differ from the signed manifest.toml (version, school id, trust,
    escrow recipients). A test-only check: the real server never parses the settings text
    (protocol 1.1), so a command line whose frame disagrees with what it signs would pass it."""
    try:
        m = tomllib.loads(manifest.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError):
        return ["manifest.toml (not TOML)"]
    school = m.get("school") if isinstance(m.get("school"), dict) else {}
    trust = m.get("trust") if isinstance(m.get("trust"), list) else []
    want = {
        "version": m.get("version"),
        "school_id": school.get("id"),
        "trust": [{"id": t.get("id"), "alg": t.get("alg"), "public_key": t.get("public_key")} for t in trust if isinstance(t, dict)],
        "escrow_recipients": school.get("escrow_recipients", []),
    }
    return [k for k, v in want.items() if frame.get(k) != v]


# ---- Age armor ----


def stanzas_of(armor):
    """The stanza types of an age ASCII-armored file (refusing what the server refuses)."""
    if not isinstance(armor, str) or len(armor.encode()) > 2048:
        raise invalid("recovery_key_age is not an armor text of at most 2048 bytes")
    text = armor.replace("\r\n", "\n")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    if len(lines) < 3 or lines[0] != "-----BEGIN AGE ENCRYPTED FILE-----" or lines[-1] != "-----END AGE ENCRYPTED FILE-----":
        raise invalid("recovery_key_age is not age ASCII armor")
    body = lines[1:-1]
    if any(len(line) > 64 for line in body) or any(len(line) != 64 for line in body[:-1]):
        raise invalid("recovery_key_age lines are not 64 columns")
    try:
        raw = base64.b64decode("".join(body), validate=True)
    except binascii.Error:
        raise invalid("recovery_key_age armor is not base64") from None
    head, sep, _ = raw.partition(b"\n--- ")
    if not sep or not head.startswith(b"age-encryption.org/v1\n"):
        raise invalid("recovery_key_age is not an age file")
    kinds = [line.split(b" ")[1].decode("ascii", "replace") for line in head.split(b"\n") if line.startswith(b"-> ")]
    if "scrypt" in kinds:
        raise invalid("a passphrase (scrypt) recipient is refused")
    return kinds


# ---- State ----


def now():
    return time.time()


class Mock:
    """The whole mock: the access tokens and the schools. Each token belongs to one admin, who
    administers exactly one school (the first or the second); neither administers the other."""

    def __init__(self, school_ids, server_url):
        self.lock = threading.Lock()
        self.server_url = server_url
        self.tokens = {}  # access token -> {"auth_time", "expires", "school"}
        self.schools = {sid: School(sid, name, self) for sid, name in zip(school_ids, SCHOOL_NAMES)}
        self.first = school_ids[0]

    def by_fetch_token(self, tok):
        """(school, stale) of a fetch token among every school's current and retired tokens."""
        for sc in self.schools.values():
            if hmac.compare_digest(tok, sc.fetch_current):
                return sc, False
        for sc in self.schools.values():
            if any(hmac.compare_digest(tok, r) for r in sc.fetch_retired):
                return sc, True
        return None, False


class School:
    """One school's state. Its attribute names are what the request handlers use as `st`."""

    def __init__(self, school_id, name, mock):
        self.mock = mock
        self.school = school_id
        self.name = name
        self.hmac_key = secrets.token_bytes(32)
        self.probes = {}  # nonce_b64 -> expiry
        self.keys = {}  # key id -> dict
        self.recipients = {}  # recipient -> dict
        self.versions = []  # dicts, index = version - 1
        self.pending = {}  # id -> dict
        self.heartbeats = []  # dicts
        self.devices = {}  # device id -> dict
        self.escrow = []  # rows
        self.seq = 0  # order of escrow rows
        self.fetch_current = b64url(secrets.token_bytes(32))
        self.fetch_retired = []
        self.cutoff = None

    # -- helpers --
    @property
    def server_url(self):
        return self.mock.server_url

    def latest(self):
        return self.versions[-1] if self.versions else None

    def latest_no(self):
        return len(self.versions)

    def secret_hash(self, secret):
        return hmac.new(self.hmac_key, secret.encode(), hashlib.sha256).hexdigest()


# ---- Request handling ----


def answer_json(status, body, headers=None):
    return status, "application/json", json.dumps(body).encode(), headers or {}


def empty(status=204, headers=None):
    return status, None, b"", headers or {}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "e2e-mock"
    sys_version = ""

    def log_message(self, fmt, *args):  # the access log is written in respond()
        pass

    def do_GET(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def do_DELETE(self):
        self.dispatch("DELETE")

    def do_PUT(self):
        self.dispatch("PUT")

    def take_body(self):
        """Read the whole request body first, so a refusal never leaves it on a kept-alive
        connection. Larger than an archive may be: the connection is closed after the answer."""
        self.body = b""
        self.body_error = None
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            self.body_error = Refuse(411, "invalid", "a body needs Content-Length")
            return
        n = self.headers.get("Content-Length")
        if n is None:
            return
        if not n.isdigit():
            self.close_connection = True
            self.body_error = invalid("Content-Length is not a number")
            return
        n = int(n)
        if n > MAX_ARCHIVE:
            self.close_connection = True
            self.body_error = Refuse(413, "too_large", "the body is larger than 20 MiB")
            return
        self.body = self.rfile.read(n)

    def read_body(self, limit):
        if self.body_error is not None:
            raise self.body_error
        if len(self.body) > limit:
            raise Refuse(413, "too_large", f"the body is larger than {limit} bytes")
        return self.body

    def json_body(self, limit=MAX_JSON):
        raw = self.read_body(limit)
        try:
            return json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
        except (UnicodeError, ValueError):
            raise invalid("the body is not JSON") from None

    def dispatch(self, method):
        self.extra_headers = {}
        self.code = ""
        self.take_body()
        try:
            status, ctype, body, headers = self.route(method)
        except Refuse as e:
            err = {"code": e.code, "message": e.message}
            if e.details is not None:
                err["details"] = e.details
            status, ctype, body, headers = answer_json(e.status, {"error": err}, e.headers)
            self.code = e.code
        except Exception as e:  # noqa: BLE001 - a mock bug answers 500 and is logged
            sys.stderr.write(f"[mock] INTERNAL ERROR on {method} {self.path}: {type(e).__name__}: {e}\n")
            status, ctype, body, headers = answer_json(500, {"error": {"code": "internal", "message": "mock bug"}})
            self.code = "internal"
        self.respond(method, status, ctype, body, headers)

    def respond(self, method, status, ctype, body, headers):
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        for k, v in {**self.extra_headers, **headers}.items():
            self.send_header(k, v)
        if status != 204 and status != 304:
            if ctype:
                self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if status != 204 and body:
            self.wfile.write(body)
        path = urlsplit(self.path).path
        sys.stderr.write(f"[mock] {self.server.role} {method} {path} -> {status}{' ' + self.code if self.code else ''}\n")
        sys.stderr.flush()

    # -- routing --
    def route(self, method):
        mock = self.server.state
        parts = urlsplit(self.path)
        path = parts.path
        query = parse_qs(parts.query, keep_blank_values=True)
        with mock.lock:
            if self.server.role == "control":
                return self.control(mock, method, path, query)
            if path.startswith("/api/device/v1/"):
                return self.device(mock, method, path[len("/api/device/v1/") :], query)
            if path.startswith("/api/cli/v1/"):
                return self.cli(mock, method, path[len("/api/cli/v1/") :])
            raise Refuse(404, "not_found", "no such route")

    # ---- control ----
    def control(self, mock, method, path, query):
        # fetch-token/rotate and drop-retired act on the first school only (as the real harness).
        st = mock.schools[mock.first]
        if method == "GET" and path == "/healthz":
            return answer_json(200, {"ok": True})
        if method == "POST" and path == "/token":
            admin = query.get("admin", ["first"])
            if admin not in (["first"], ["second"]) or (admin == ["second"] and len(mock.schools) < 2):
                raise invalid("admin is first or second")
            school = list(mock.schools)[0 if admin == ["first"] else 1]
            body = self.read_body(4096)
            step_up = False
            if body.strip():
                try:
                    obj = json.loads(body)
                except ValueError:
                    raise invalid("the body is not JSON") from None
                strict(obj, [], ["step_up"])
                step_up = obj.get("step_up") is True
            token = b64url(secrets.token_bytes(32))
            t = now()
            mock.tokens[token] = {
                "auth_time": t if step_up else t - 3 * 3600,
                "expires": t + TOKEN_LIFE,
                "school": school,
            }
            return answer_json(200, {"fleet_url": st.server_url, "access_token": token, "expires_at": rfc3339(t + TOKEN_LIFE)})
        if method == "POST" and path == "/fetch-token/rotate":
            self.read_body(4096)
            st.fetch_retired.append(st.fetch_current)
            st.fetch_current = b64url(secrets.token_bytes(32))
            t = now()
            st.cutoff = t if st.cutoff is None else min(st.cutoff, t)
            return empty()
        if method == "POST" and path == "/fetch-token/drop-retired":
            self.read_body(4096)
            st.fetch_retired = []
            st.cutoff = None
            return empty()
        raise Refuse(404, "not_found", "no such control route")

    # ---- CLI API ----
    def bearer(self, mock):
        h = self.headers.get("Authorization", "")
        if not h.startswith("Bearer "):
            raise Refuse(401, "unauthenticated", "no bearer token")
        tok = mock.tokens.get(h[len("Bearer ") :])
        if tok is None or tok["expires"] < now():
            raise Refuse(401, "unauthenticated", "unknown or expired token")
        return tok

    def step_up(self, tok):
        if now() - tok["auth_time"] > STEP_UP_MAX_AGE:
            raise Refuse(
                401,
                "step_up_required",
                "this action needs a fresh sign-in",
                headers={
                    "WWW-Authenticate": 'Bearer error="insufficient_user_authentication", '
                    'error_description="A fresh sign-in is required", max_age="300"'
                },
            )

    def cli(self, mock, method, rest):
        if rest == "auth-config" and method == "GET":
            return answer_json(
                200,
                {
                    "issuer": "https://issuer.example",
                    "client_id": "mastersos-cli",
                    "audience": "fleet",
                    "scopes": ["openid", "offline_access"],
                    "step_up_acr": "",
                },
            )
        tok = self.bearer(mock)
        if rest == "schools" and method == "GET":
            own = mock.schools[tok["school"]]
            return answer_json(200, [{"id": own.school, "name": own.name, "time_zone": "Asia/Bangkok"}])
        m = re.fullmatch(r"schools/([^/]+)/mastersos/(.*)", rest)
        if not m or m.group(1) not in mock.schools:
            raise Refuse(404, "not_found", "no such school or route")
        if m.group(1) != tok["school"]:
            raise Refuse(403, "forbidden", "you do not administer this school")
        st = mock.schools[m.group(1)]
        r = m.group(2)
        segs = [unquote(s) for s in r.split("/")]

        def need_step_up():
            self.step_up(tok)

        if r == "keys/probe" and method == "POST":
            self.read_body(4096)
            nonce = secrets.token_bytes(32)
            st.probes[b64(nonce)] = now() + PROBE_LIFE
            return answer_json(200, {"nonce_b64": b64(nonce), "message_b64": b64(PROBE_PREFIX + nonce)})
        if r == "keys" and method == "POST":
            need_step_up()
            return self.post_key(st)
        if r == "keys" and method == "GET":
            return answer_json(200, [self.key_row(st, k) for k in st.keys.values()])
        if len(segs) == 2 and segs[0] == "keys" and method == "DELETE":
            need_step_up()
            return self.delete_key(st, segs[1])
        if r == "escrow-recipients" and method == "POST":
            need_step_up()
            return self.post_recipient(st)
        if r == "escrow-recipients" and method == "GET":
            lat = st.latest()
            inl = set(lat["frame"]["escrow_recipients"]) if lat else set()
            return answer_json(
                200,
                [{"recipient": k, "bound_key_id": v["bound_key_id"], "label": v["label"], "created_at": v["created_at"], "in_latest": k in inl} for k, v in st.recipients.items()],
            )
        if r == "versions" and method == "GET":
            return answer_json(
                200,
                [{"version": v["version"], "published_at": v["published_at"], "published_by": "e2e", "signed_by": v["signed_by"], "digest_hex": v["digest_hex"]} for v in st.versions],
            )
        if len(segs) == 3 and segs[0] == "versions" and segs[2] == "archive" and method == "GET":
            if not segs[1].isdigit() or not 1 <= int(segs[1]) <= st.latest_no():
                raise Refuse(404, "not_found", "no such version")
            v = st.versions[int(segs[1]) - 1]
            return 200, "application/gzip", v["archive"], {"X-Mastersos-Version": str(v["version"])}
        if r == "publish/pending" and method == "POST":
            return self.post_pending(st)
        if len(segs) == 3 and segs[:2] == ["publish", "pending"] and method in ("GET", "DELETE"):
            p = st.pending.get(segs[2])
            if p is None:
                raise Refuse(404, "not_found", "no such upload")
            if method == "DELETE":
                del st.pending[segs[2]]
                return empty()
            if p["expires"] < now():
                raise Refuse(410, "pending_expired", "the upload expired")
            return answer_json(200, {**p["answer"], "frame": p["frame"]})
        if len(segs) == 4 and segs[:2] == ["publish", "pending"] and segs[3] == "commit" and method == "POST":
            return self.commit(st, segs[2])
        if r == "heartbeat" and method == "POST":
            return self.post_heartbeat(st)
        if r == "heartbeat" and method == "GET":
            hb = self.served_heartbeat(st)
            return answer_json(200, None if hb is None else {"version": hb["version"], "not_after": rfc3339(hb["not_after"]), "signed_by": hb["signed_by"]})
        if r == "devices" and method == "GET":
            return answer_json(200, [self.device_row(st, d) for d in st.devices.values() if d.get("status")])
        if len(segs) == 2 and segs[0] == "devices" and method == "GET":
            d = st.devices.get(segs[1])
            if d is None or not d.get("status"):
                raise Refuse(404, "not_found", "no such device")
            return answer_json(200, {**self.device_row(st, d), "results": d["status"].get("results", [])})
        if len(segs) == 3 and segs[0] == "devices" and segs[2] == "recovery-keys" and method == "GET":
            need_step_up()
            rows = [e for e in st.escrow if e["device_id"] == segs[1]]
            out = []
            for e in sorted(rows, key=lambda e: e["seq"], reverse=True):
                first = not any(o["luks_uuid"] == e["luks_uuid"] and o["seq"] < e["seq"] for o in rows)
                out.append(
                    {
                        "luks_uuid": e["luks_uuid"],
                        "recovery_key_age": e["recovery_key_age"],
                        "recipients_fp": e["recipients_fp"],
                        "received_at": rfc3339(e["received_at"]),
                        "serial": e["serial"],
                        "first_for_luks": first,
                    }
                )
            return answer_json(200, out)
        if len(segs) == 3 and segs[0] == "devices" and segs[2] == "escrow-secret" and method == "DELETE":
            # Section 4.8: clears the secret; the next request registers again (3.1); the
            # recovery-key rows stay (5.6).
            need_step_up()
            d = st.devices.get(segs[1])
            if d is None:
                raise Refuse(404, "not_found", "no such device")
            d["secret"] = None
            d["registered_at"] = None
            return empty()
        if r == "seed" and method == "POST":
            need_step_up()
            self.read_body(4096)
            if not st.versions:
                raise Refuse(409, "no_published_version", "nothing is published yet")
            return answer_json(200, {"server_url": st.server_url, "school_id": st.school, "fetch_token": st.fetch_current})
        raise Refuse(404, "not_found", "no such route")

    def key_row(self, st, k):
        lat = st.latest()
        in_latest = bool(lat) and any(t["id"] == k["key_id"] for t in lat["frame"]["trust"])
        used = [v["published_at"] for v in st.versions if v["signed_by"] == k["key_id"]]
        used += [rfc3339(h["received_at"]) for h in st.heartbeats if h["signed_by"] == k["key_id"]]
        return {
            "key_id": k["key_id"],
            "alg": "ed25519",
            "public_key": k["public_key"],
            "fingerprint": k["fingerprint"],
            "label": k["label"],
            "created_at": k["created_at"],
            "in_latest_trust": in_latest,
            "last_used_at": max(used) if used else None,
        }

    def spend_probe(self, st, nonce_b64):
        nonce = std_pad(nonce_b64, "nonce_b64", 32)
        exp = st.probes.pop(nonce_b64, None)
        if exp is None or exp < now():
            raise Refuse(410, "probe_expired", "the probe is unknown, used or expired")
        return nonce

    def post_key(self, st):
        body = strict(self.json_body(), ["label", "trust_key", "nonce_b64", "signature"])
        label = want_str(body, "label").strip()
        if not 1 <= len(label) <= 64:
            raise invalid("label is not 1 to 64 characters")
        tk = strict(body["trust_key"], ["id", "alg", "public_key"], what="trust_key")
        sig = strict(body["signature"], ["key_id", "alg", "sig"], what="signature")
        want_str(body, "nonce_b64")
        # The probe is spent before verification.
        self.spend_probe(st, body["nonce_b64"])
        if tk["alg"] != "ed25519" or sig["alg"] != "ed25519":
            raise Refuse(422, "key_invalid", "alg must be ed25519")
        try:
            pk = std_pad(tk["public_key"], "public_key", 32)
        except Refuse:
            raise Refuse(422, "key_invalid", "public_key is not 32 bytes of standard base64") from None
        if tk["id"] != key_id_of(pk):
            raise Refuse(422, "key_invalid", "the key id is not rk- + sha256(public key)[:4]")
        if sig["key_id"] != tk["id"]:
            raise Refuse(422, "signature_invalid", "the signature names another key")
        try:
            std_pad(sig["sig"], "sig", 64)
        except Refuse:
            raise Refuse(422, "signature_invalid", "sig is not 64 bytes of standard base64") from None
        if tk["id"] in st.keys:
            raise Refuse(409, "key_exists", "the key is registered already")
        st.keys[tk["id"]] = {
            "key_id": tk["id"],
            "public_key": tk["public_key"],
            "fingerprint": fingerprint_of(pk),
            "label": label,
            "created_at": rfc3339(now()),
        }
        return answer_json(201, {"key_id": tk["id"], "fingerprint": fingerprint_of(pk)})

    def delete_key(self, st, key_id):
        if key_id not in st.keys:
            raise Refuse(404, "not_found", "no such key")
        lat = st.latest()
        if lat:
            bound = {r for r, v in st.recipients.items() if v["bound_key_id"] == key_id}
            if any(t["id"] == key_id for t in lat["frame"]["trust"]) or bound & set(lat["frame"]["escrow_recipients"]):
                raise Refuse(409, "key_still_trusted", "the latest version trusts the key or its recipient")
        del st.keys[key_id]
        for r in [r for r, v in st.recipients.items() if v["bound_key_id"] == key_id]:
            del st.recipients[r]
        return empty()

    def post_recipient(self, st):
        body = strict(self.json_body(), ["recipient", "bound_key_id", "nonce_b64", "sig_b64", "label"])
        recipient = want_str(body, "recipient")
        label = want_str(body, "label").strip()
        if not 1 <= len(label) <= 64:
            raise invalid("label is not 1 to 64 characters")
        want_str(body, "bound_key_id")
        want_str(body, "nonce_b64")
        self.spend_probe(st, body["nonce_b64"])
        if not is_age_recipient(recipient):
            raise invalid("recipient is not a canonical lowercase age1 Bech32 recipient")
        if body["bound_key_id"] not in st.keys:
            raise Refuse(422, "key_invalid", "the bound key is not registered")
        try:
            std_pad(body["sig_b64"], "sig_b64", 64)
        except Refuse:
            raise Refuse(422, "signature_invalid", "sig_b64 is not 64 bytes of standard base64") from None
        if recipient in st.recipients:
            raise Refuse(409, "recipient_exists", "the recipient is registered already")
        st.recipients[recipient] = {"bound_key_id": body["bound_key_id"], "label": label, "created_at": rfc3339(now())}
        return answer_json(201, {"recipient": recipient, "bound_key_id": body["bound_key_id"]})

    # -- publish --
    @staticmethod
    def check_frame(frame):
        strict(frame, ["format", "version", "issued_at", "school_id", "trust", "escrow_recipients", "features_used"], what="frame")
        if not isinstance(frame["format"], int) or isinstance(frame["format"], bool) or frame["format"] < 1:
            raise invalid("frame.format is not a positive integer")
        want_u64(frame, "version", I64_MAX)
        parse_time(frame["issued_at"], "frame.issued_at")
        want_str(frame, "school_id", "frame.school_id")
        if not isinstance(frame["trust"], list):
            raise invalid("frame.trust is not a list")
        for t in frame["trust"]:
            strict(t, ["id", "alg", "public_key"], what="a frame.trust entry")
            if not isinstance(t["id"], str) or not isinstance(t["alg"], str):
                raise invalid("a frame.trust entry is not strings")
            std_pad(t["public_key"], "frame.trust public_key", 32)
        if not isinstance(frame["escrow_recipients"], list) or not all(is_age_recipient(r) for r in frame["escrow_recipients"]):
            raise invalid("frame.escrow_recipients are not canonical age1 recipients")
        f = frame["features_used"]
        if not isinstance(f, list) or not all(isinstance(x, str) and 1 <= len(x) <= 64 for x in f):
            raise invalid("frame.features_used is not a list of names")

    def gate(self, st, frame):
        """Section 4.5: (refusal or None, warnings)."""
        lat = st.latest()
        old = set(lat["frame"]["features_used"]) if lat else set()
        recent = [d for d in st.devices.values() if d.get("status") and d["last_seen"] >= now() - 30 * 86400]
        warnings = []
        for feature in frame["features_used"]:
            lacking = [d for d in recent if feature not in d["status"].get("manifest_features", [])]
            if not lacking:
                continue
            if feature in old:
                warnings.append({"code": "feature_unsupported_in_use", "message": f"{len(lacking)} device(s) do not report {feature}"})
                continue
            return (
                Refuse(
                    422,
                    "feature_unsupported",
                    f"{len(lacking)} device(s) do not support {feature}",
                    details={
                        "feature": feature,
                        "devices": [
                            {"device_id": d["device_id"], "serial": d["status"].get("serial"), "os_version": d["status"].get("os_version"), "last_seen": rfc3339(d["last_seen"])}
                            for d in lacking
                        ],
                    },
                ),
                warnings,
            )
        return None, warnings

    def post_pending(self, st):
        body = strict(self.json_body(), ["frame", "digest_hex"])
        frame = body["frame"]
        self.check_frame(frame)
        digest_hex = want_str(body, "digest_hex")
        if not HEX64_RE.match(digest_hex):
            raise invalid("digest_hex is not 64 lowercase hex digits")
        latest = st.latest_no()
        # 1. version
        if frame["version"] != latest + 1:
            raise Refuse(409, "version_conflict", f"the next version is {latest + 1}", details={"latest_version": latest})
        # 2. clock
        if abs(parse_time(frame["issued_at"], "issued_at") - now()) > CLOCK_SKEW:
            raise Refuse(422, "clock_skew", "issued_at is more than 10 minutes off")
        # 3. school
        if frame["school_id"] != st.school:
            raise Refuse(422, "school_mismatch", "the frame names another school")
        # 4. trust
        if not frame["trust"]:
            raise Refuse(422, "trust_key_unregistered", "the trust is empty")
        for t in frame["trust"]:
            k = st.keys.get(t["id"])
            if k is None or t["alg"] != "ed25519" or k["public_key"] != t["public_key"]:
                raise Refuse(422, "trust_key_unregistered", f"trust key {t['id']} is not registered", details={"key_id": t["id"]})
        # 5. recipients
        trust_ids = {t["id"] for t in frame["trust"]}
        for r in frame["escrow_recipients"]:
            rec = st.recipients.get(r)
            if rec is None or rec["bound_key_id"] not in trust_ids:
                raise Refuse(422, "recipient_unregistered", "an escrow recipient is not registered or not bound to a trusted key")
        # 6. feature gate
        refusal, warnings = self.gate(st, frame)
        if refusal:
            raise refusal
        lat = st.latest()
        old_ids = {t["id"] for t in lat["frame"]["trust"]} if lat else set()
        pid = str(uuid.uuid4())
        t = now()
        answer = {
            "pending_id": pid,
            "version": frame["version"],
            "digest_hex": digest_hex,
            "message_b64": b64(BUNDLE_PREFIX + bytes.fromhex(digest_hex)),
            "expires_at": rfc3339(t + PENDING_LIFE),
            "trust_change": {"added": sorted(trust_ids - old_ids), "removed": sorted(old_ids - trust_ids)},
            "warnings": warnings,
        }
        st.pending[pid] = {"frame": frame, "digest_hex": digest_hex, "expires": t + PENDING_LIFE, "answer": answer}
        return answer_json(201, answer)

    def commit(self, st, pid):
        p = st.pending.get(pid)
        data = self.read_body(MAX_ARCHIVE)
        if p is None:
            raise Refuse(404, "not_found", "no such upload")
        if p["expires"] < now():
            raise Refuse(410, "pending_expired", "the upload expired")
        if (self.headers.get("Content-Type") or "").split(";")[0].strip() != "application/gzip":
            raise invalid("the archive must be sent as application/gzip")
        manifest, files, sig = read_archive(data)
        if content_digest(manifest, files).hex() != p["digest_hex"]:
            raise Refuse(422, "digest_mismatch", "the archive's content digest is not the uploaded one")
        frame = p["frame"]
        if st.latest_no() != frame["version"] - 1:
            raise Refuse(409, "version_conflict", "another version was published meanwhile", details={"latest_version": st.latest_no()})
        signer = check_signature_table(sig, "the signature member")
        lat = st.latest()
        trust = lat["frame"]["trust"] if lat else frame["trust"]
        if signer not in {t["id"] for t in trust}:
            raise Refuse(422, "signature_invalid", "the signer is not in the latest trust")
        if signer not in {t["id"] for t in frame["trust"]}:
            raise Refuse(422, "trust_rule", "the signer is not in the new trust")
        # After the signer checks: an archive signed by a key outside the latest trust is refused
        # as the server refuses it, whatever its manifest says.
        diff = frame_differences(frame, manifest)
        if diff:
            # Not a protocol refusal: a bug in the command line. run.sh fails on this log line.
            sys.stderr.write(f"[mock] INTERNAL ERROR frame differs from the signed manifest.toml: {', '.join(diff)}\n")
            raise Refuse(500, "internal", "the frame differs from the signed manifest.toml (mock check)")
        refusal, _ = self.gate(st, frame)
        if refusal:
            raise refusal
        st.versions.append(
            {
                "version": frame["version"],
                "frame": frame,
                "digest_hex": p["digest_hex"],
                "archive": data,
                "published_at": rfc3339(now()),
                "signed_by": signer,
            }
        )
        del st.pending[pid]
        return answer_json(200, {"version": frame["version"]})

    def post_heartbeat(self, st):
        body = strict(self.json_body(), ["heartbeat"])
        text = want_str(body, "heartbeat")
        if len(text.encode()) > MAX_HEARTBEAT:
            raise Refuse(413, "too_large", "the heartbeat is larger than 16 KiB")
        try:
            doc = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            raise Refuse(422, "invalid", "the heartbeat is not TOML") from None
        if set(doc) != {"statement", "signature"} or not isinstance(doc["statement"], dict):
            raise Refuse(422, "invalid", "the heartbeat is not [statement] and [signature]")
        s = doc["statement"]
        if set(s) != {"version", "digest_hex", "issued_at", "not_after"}:
            raise Refuse(422, "invalid", "the statement is not version, digest_hex, issued_at, not_after")
        if not all(isinstance(s[k], int) and not isinstance(s[k], bool) for k in ("version", "issued_at", "not_after")):
            raise Refuse(422, "invalid", "the statement's numbers are not integers")
        if not isinstance(s["digest_hex"], str) or not HEX64_RE.match(s["digest_hex"]):
            raise Refuse(422, "invalid", "digest_hex is not 64 lowercase hex digits")
        signer = check_signature_table(doc["signature"], "the heartbeat signature")
        lat = st.latest()
        if lat is None or s["version"] != lat["version"] or s["digest_hex"] != lat["digest_hex"]:
            raise Refuse(409, "not_latest", "the heartbeat is not for the latest version")
        if abs(s["issued_at"] - now()) > CLOCK_SKEW:
            raise Refuse(422, "clock_skew", "issued_at is more than 10 minutes off")
        if not 86400 <= s["not_after"] - s["issued_at"] <= 31 * 86400:
            raise Refuse(422, "invalid", "the validity is not 1 to 31 days")
        if signer not in {t["id"] for t in lat["frame"]["trust"]}:
            raise Refuse(422, "signature_invalid", "the signer is not in the latest trust")
        st.heartbeats.append({"version": s["version"], "text": text, "not_after": s["not_after"], "signed_by": signer, "received_at": now(), "seq": len(st.heartbeats)})
        return empty()

    def served_heartbeat(self, st):
        lat = st.latest()
        if lat is None:
            return None
        hbs = [h for h in st.heartbeats if h["version"] == lat["version"]]
        if not hbs:
            return None
        return max(hbs, key=lambda h: (h["not_after"], h["seq"]))

    def device_row(self, st, d):
        s = d["status"]
        lat = st.latest_no()
        return {
            **s,
            "last_seen": rfc3339(d["last_seen"]),
            "fetch_token_stale": d.get("stale", False),
            "behind": (s.get("bundle_version") or 0) < lat,
            "has_errors": any(not r.get("ok", True) for r in s.get("results", []) if isinstance(r, dict)),
            "removed_at": None,
        }

    # ---- Device API ----
    def fetch_token(self, mock):
        """The school of the request's fetch token (device routes pick the school from the
        credential) and whether the token is retired."""
        h = self.headers.get("Authorization", "")
        tok = h[len("Bearer ") :] if h.startswith("Bearer ") else None
        if tok is None or not is_fetch_token(tok):
            raise Refuse(401, "unauthorized", "no valid fetch token")
        st, stale = mock.by_fetch_token(tok)
        if st is None:
            raise Refuse(401, "unauthorized", "unknown fetch token")
        if stale:
            self.extra_headers["X-Mastersos-Fetch-Token"] = "stale"
        return st, stale

    def register_or_verify(self, st, device_id, secret):
        """Section 3.1: the first request with a secret registers it; later ones must match.
        Returns True when this request registered it."""
        h = st.secret_hash(secret)
        d = st.devices.setdefault(device_id, {"device_id": device_id})
        if d.get("secret") is None:
            d["secret"] = h
            d["registered_at"] = now()
            return True
        if not hmac.compare_digest(d["secret"], h):
            raise Refuse(403, "secret_mismatch", "the device secret does not match")
        return False

    def device(self, mock, method, rest, query):
        st, stale = self.fetch_token(mock)
        for m, rx in RESERVED:
            if method == m and rx.fullmatch(rest):
                raise Refuse(404, "not_available", "not offered by this server yet")
        if method == "GET" and rest.startswith("logos/") and "/" not in rest[6:]:
            if rest.endswith(".png"):
                raise Refuse(404, "not_available", "not offered by this server yet")
            raise Refuse(404, "not_found", "no such logo")
        if method == "GET" and rest == "bundle":
            return self.bundle(st, query)
        if method == "GET" and rest == "heartbeat":
            hb = self.served_heartbeat(st)
            if hb is None:
                return empty()
            return 200, "text/plain; charset=utf-8", hb["text"].encode(), {}
        if method == "POST" and rest == "status":
            return self.status(st, stale)
        if method == "POST" and rest == "escrow":
            return self.post_escrow(st)
        if method == "POST" and rest == "fetch-token":
            body = strict(self.json_body(4096), ["device_id", "escrow_secret"])
            device_id = want_str(body, "device_id")
            if not is_identifier(device_id):
                raise invalid("device_id is not 1-128 bytes without control characters")
            secret = want_str(body, "escrow_secret")
            url_nopad(secret, "escrow_secret", 32)
            d = st.devices.get(device_id)
            ok = (
                st.cutoff is not None
                and d is not None
                and d.get("secret") is not None
                and hmac.compare_digest(d["secret"], st.secret_hash(secret))
                and d["registered_at"] < st.cutoff
            )
            if not ok:
                raise Refuse(403, "renew_refused", "renewal is not allowed for this device")
            return answer_json(200, {"fetch_token": st.fetch_current})
        raise Refuse(404, "not_found", "no such route")

    def bundle(self, st, query):
        latest = st.latest_no()
        after = query.get("after")
        if after is None:
            a = None
        else:
            if len(after) != 1 or not re.fullmatch(r"\d{1,20}", after[0]) or int(after[0]) > U64_MAX:
                raise invalid("after is not a u64")
            a = int(after[0])
        if latest == 0 or (a is not None and a >= latest):
            return empty()
        if a is None:
            v = latest
        else:
            key = lambda t: sorted((x["id"], x["alg"], x["public_key"]) for x in t)  # noqa: E731
            base = key(st.versions[max(a, 1) - 1]["frame"]["trust"])
            v = latest
            for n in range(a + 1, latest + 1):
                if key(st.versions[n - 1]["frame"]["trust"]) != base:
                    v = n
                    break
        rec = st.versions[v - 1]
        return 200, "application/gzip", rec["archive"], {"X-Mastersos-Version": str(v)}

    def status(self, st, stale):
        device_id = self.headers.get("X-Mastersos-Device")
        secret = self.headers.get("X-Mastersos-Device-Secret")
        if device_id is None or secret is None:
            raise Refuse(401, "device_auth_missing", "status needs the device headers")
        url_nopad(secret, "X-Mastersos-Device-Secret", 32)
        body = self.json_body(MAX_STATUS)
        if not isinstance(body, dict):
            raise invalid("the body is not a JSON object")
        if body.get("device_id") != device_id or not is_identifier(device_id):
            raise invalid("X-Mastersos-Device differs from device_id, or device_id is invalid")
        for k in ("serial", "model", "os_version", "group", "user_config"):
            if body.get(k) is not None and not is_identifier(body[k]):
                raise invalid(f"{k} is not 1-128 bytes without control characters")
        if not is_identifier(body.get("agent_version")):
            raise invalid("agent_version is missing or invalid")
        if body.get("bundle_version") is not None:
            want_u64(body, "bundle_version", I64_MAX)
        mf = body.get("manifest_features", [])
        if not isinstance(mf, list) or len(mf) > 32 or not all(isinstance(x, str) and 1 <= len(x.encode()) <= 64 for x in mf):
            raise invalid("manifest_features is not at most 32 names of 1-64 bytes")
        stf = body.get("seed_trust_fingerprints", [])
        if not isinstance(stf, list) or not all(isinstance(x, str) for x in stf):
            raise invalid("seed_trust_fingerprints is not a list of strings")
        results = body.get("results", [])
        if not isinstance(results, list):
            raise invalid("results is not a list")
        body["results"] = results[:200]
        self.register_or_verify(st, device_id, secret)
        d = st.devices[device_id]
        d["status"] = body
        d["last_seen"] = now()
        d["stale"] = stale
        return empty()

    def post_escrow(self, st):
        body = strict(
            self.json_body(MAX_ESCROW),
            ["device_id", "luks_uuid", "recovery_key_age", "recipients_fp", "escrow_secret"],
            ["serial"],
        )
        device_id = want_str(body, "device_id")
        if not is_identifier(device_id):
            raise invalid("device_id is not 1-128 bytes without control characters")
        serial = body.get("serial")
        if serial is not None and not (isinstance(serial, str) and len(serial.encode()) <= 128 and is_identifier(serial)):
            raise invalid("serial is not at most 128 bytes without control characters")
        luks = want_str(body, "luks_uuid")
        if not UUID_RE.match(luks):
            raise invalid("luks_uuid is not a lowercase 8-4-4-4-12 UUID")
        fp = want_str(body, "recipients_fp")
        if not HEX64_RE.match(fp):
            raise invalid("recipients_fp is not 64 lowercase hex digits")
        secret = want_str(body, "escrow_secret")
        url_nopad(secret, "escrow_secret", 32)
        armor = want_str(body, "recovery_key_age")
        kinds = stanzas_of(armor)
        # 1. register or verify
        fresh = self.register_or_verify(st, device_id, secret)
        lat = st.latest()
        latest_fp = recipients_fp(lat["frame"]["escrow_recipients"]) if lat else None
        # 2. stanza count
        if fp == latest_fp and kinds.count("X25519") != len(set(lat["frame"]["escrow_recipients"])):
            raise invalid("the number of X25519 stanzas is not the number of latest recipients")
        # 3. duplicates
        ch = hashlib.sha256(armor.encode()).hexdigest()
        for e in st.escrow:
            if e["device_id"] == device_id and e["luks_uuid"] == luks and e["sha"] == ch:
                if e["recipients_fp"] == fp:
                    return empty()
                raise invalid("the same ciphertext was stored with another recipients_fp")
        # 4. caps
        same = [e for e in st.escrow if e["device_id"] == device_id and e["luks_uuid"] == luks and e["recipients_fp"] == fp]
        recent = [e for e in st.escrow if e["device_id"] == device_id and e["received_at"] > now() - 30 * 86400]
        if len(same) >= 3 or len(recent) >= 20:
            raise Refuse(429, "too_many", "too many escrow rows", headers={"Retry-After": "3600"})
        # 5. insert, and drop older-fp rows received after registration
        t = now()
        if fp == latest_fp and not fresh:
            reg = st.devices[device_id]["registered_at"]
            st.escrow = [e for e in st.escrow if not (e["device_id"] == device_id and e["luks_uuid"] == luks and e["recipients_fp"] != fp and e["received_at"] > reg)]
        st.seq += 1
        st.escrow.append(
            {"device_id": device_id, "serial": serial, "luks_uuid": luks, "recovery_key_age": armor, "recipients_fp": fp, "sha": ch, "received_at": t, "seq": st.seq}
        )
        return empty()


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, role, state):
        super().__init__(("127.0.0.1", 0), Handler)
        self.role = role
        self.state = state


# ---- Self-test against the shared vectors ----


def self_test(vector_dir):
    fails = []

    def check(name, cond):
        if not cond:
            fails.append(name)

    def load(name):
        with open(os.path.join(vector_dir, name), encoding="utf-8") as f:
            return json.load(f)

    for v in load("digest-vectors.json"):
        files = {p: base64.b64decode(c) for p, c in v["files"].items()}
        check(f"digest {v['name']}", content_digest(v["manifest_text"].encode(), files).hex() == v["digest_hex"])
    w = load("wire-vectors.json")
    for v in w["key_probes"]:
        pk = std_pad(v["public_key"], "pk", 32)
        check(f"key id {v['name']}", key_id_of(pk) == v["key_id"])
        nonce = std_pad(v["nonce_b64"], "nonce", 32)
        check(f"probe message {v['name']}", b64(PROBE_PREFIX + nonce) == v["message_b64"])
    for v in w["recipient_bindings"]:
        check(f"recipient {v['name']}", is_age_recipient(v["recipient"]))
        check(f"recipient checksum {v['name']}", not is_age_recipient(v["recipient"][:-1] + ("q" if v["recipient"][-1] != "q" else "p")))
    for v in w["recipient_bindings"]:
        nonce = std_pad(v["nonce_b64"], "nonce", 32)
        check(f"binding message {v['name']}", b64(RECIPIENT_PREFIX + v["recipient"].encode() + b"\n" + nonce) == v["message_b64"])
        check(f"binding key id {v['name']}", key_id_of(std_pad(v["public_key"], "pk", 32)) == v["key_id"])
    for v in w["heartbeats"]:
        stt = v["statement"]
        msg = (
            HEARTBEAT_PREFIX
            + stt["version"].to_bytes(8, "big")
            + bytes.fromhex(stt["digest_hex"])
            + stt["issued_at"].to_bytes(8, "big", signed=True)
            + stt["not_after"].to_bytes(8, "big", signed=True)
        )
        check(f"heartbeat message {v['name']}", b64(msg) == v["message_b64"])
        doc = tomllib.loads(v["heartbeat_toml"])
        check(f"heartbeat toml statement {v['name']}", doc.get("statement") == stt)
        try:
            signer = check_signature_table(doc.get("signature"), "heartbeat signature")
        except Refuse:
            signer = None
        check(f"heartbeat signer {v['name']}", signer == key_id_of(std_pad(v["public_key"], "pk", 32)))
    for v in w["publish"]:
        frame = v["frame"]
        try:
            Handler.check_frame(frame)
            shape = True
        except Refuse:
            shape = False
        check(f"publish frame shape {v['name']}", shape)
        manifest = v["manifest_text"].encode()
        check(f"publish frame equals manifest {v['name']}", frame_differences(frame, manifest) == [])
        check(f"publish digest {v['name']}", content_digest(manifest, {}).hex() == v["digest_hex"])
        check(f"publish message {v['name']}", b64(BUNDLE_PREFIX + bytes.fromhex(v["digest_hex"])) == v["message_b64"])
        try:
            signer = check_signature_table(tomllib.loads(v["signature_toml"]), "signature")
        except Refuse:
            signer = None
        check(f"publish signer {v['name']}", signer in {t["id"] for t in frame["trust"]})
        bad = dict(frame, version=frame["version"] + 1)
        check(f"publish frame mismatch caught {v['name']}", frame_differences(bad, manifest) == ["version"])
    for v in w["bundle_signatures"]:
        check(f"bundle message {v['name']}", b64(BUNDLE_PREFIX + bytes.fromhex(v["digest_hex"])) == v["message_b64"])
    for v in w["seed_trust_fingerprints"]:
        fps = [fingerprint_of(std_pad(t["public_key"], "pk", 32)) for t in v["trust"]]
        check(f"fingerprints {v['name']}", fps == v["fingerprints"])
    for v in w["secrets"]:
        check(f"secret {v['name']}", url_nopad(v["encoded"], "s", 32).hex() == v["bytes_hex"])
    for v in w["fetch_tokens"]:
        check(f"fetch token {v['name']}", is_fetch_token(v["token"]))
    for v in w["luks_uuids"]:
        check(f"luks {v['name']}", bool(UUID_RE.match(v["value"])))
    for v in w["invalid"]:
        f, val = v["field"], v["value"]
        try:
            if f == "secret":
                url_nopad(val, f, 32)
                ok = True
            elif f in ("nonce_b64",):
                std_pad(val, f, 32)
                ok = True
            elif f == "sig":
                std_pad(val, f, 64)
                ok = True
            elif f == "fetch_token":
                ok = is_fetch_token(val)
            elif f == "luks_uuid":
                ok = bool(UUID_RE.match(val))
            elif f == "digest_hex":
                ok = bool(HEX64_RE.match(val))
            else:
                ok = None
        except Refuse:
            ok = False
        check(f"invalid {v['name']} refused", ok is False)
    summary = {"ok": not fails, "failed": fails}
    print(json.dumps(summary))
    return 0 if not fails else 1


def main(argv):
    if tomllib is None:
        sys.stderr.write("server.py needs Python 3.11 or later (tomllib)\n")
        return 1
    args = argv[1:]
    ready_file = None
    school = DEFAULT_SCHOOL
    second = DEFAULT_SECOND_SCHOOL
    while args:
        a = args.pop(0)
        if a == "--self-test" and args:
            return self_test(args.pop(0))
        if a == "--ready-file" and args:
            ready_file = args.pop(0)
        elif a in ("--school-id", "--second-school-id") and args:
            v = args.pop(0)
            if not UUID_RE.match(v):
                sys.stderr.write(f"{a} must be a lowercase UUID\n")
                return 2
            if a == "--school-id":
                school = v
            else:
                second = v
        else:
            sys.stderr.write(__doc__)
            return 2
    if school == second:
        sys.stderr.write("--school-id and --second-school-id must differ\n")
        return 2
    state = Mock([school, second], "")
    api = Server("server", state)
    control = Server("control", state)
    state.server_url = f"http://127.0.0.1:{api.server_address[1]}"
    for s in (api, control):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    ready = {
        "server_url": state.server_url,
        "school_id": school,
        "second_school_id": second,
        "control_url": f"http://127.0.0.1:{control.server_address[1]}",
        "arbella_stub": os.path.dirname(os.path.realpath(__file__)),
    }
    line = json.dumps(ready)
    if ready_file:
        tmp = ready_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(line + "\n")
        os.replace(tmp, ready_file)
    print(line, flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
