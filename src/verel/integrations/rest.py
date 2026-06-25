"""REST gate server + GitHub PR-webhook adapter (the "Reach" track, R1).

A language- and host-agnostic way to gate: any CI, script, or webhook `POST`s and gets a verdict —
no MCP host required. Reuses the hardened `verel.transport` (a routable bind REQUIRES auth + TLS;
loopback stays zero-config) and the `MemoryServer` shape, so the network surface is the same one the
brain/registry already survived a red-team on.

Security choices:
- **One configured repo.** The server gates exactly the repo it was constructed with — `POST /gate`
  takes no path, so an authenticated caller cannot point CI execution at an arbitrary directory.
- **Bearer auth**, constant-time (`hmac.compare_digest`); body-size cap; slowloris timeout; conn caps
  — all inherited from the transport layer.
- **Webhook HMAC.** `POST /github` verifies GitHub's `X-Hub-Signature-256` over the raw body
  (constant-time) before doing anything — an unsigned/forged event is rejected, no gate runs.
- **No SSRF.** The webhook never fetches a URL from the payload; it only gates the local configured
  repo. Posting status back to GitHub is an explicit, separate, opt-in outbound call.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import ssl
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler
from pathlib import Path

from ..transport import (
    _DEFAULT_MAX_CONNECTIONS,
    TLSThreadingHTTPServer,
    build_opener,
    build_server_context,
    enforce_bind_policy,
    make_client_context,
    scheme,
)

_MAX_BODY = 1 * 1024 * 1024  # 1 MiB — webhook payloads are small; reject oversize before allocating


# ---- GitHub webhook: pure, testable helpers ----
_SIG_RE = re.compile(r"sha256=[0-9a-f]{64}\Z")


def verify_github_signature(secret: str, body: bytes, signature_header: str | None) -> bool:
    """Constant-time check of GitHub's `X-Hub-Signature-256: sha256=<hex>` over the RAW body.
    Returns False on any missing/malformed input — never raises, never short-circuits early. The
    header is shape-validated (lowercase 64-hex) BEFORE the compare so a non-ASCII byte can't make
    `compare_digest` raise."""
    if not secret or not signature_header or not _SIG_RE.match(signature_header):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


_REPO_RE = re.compile(r"\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_SHA_RE = re.compile(r"\A[0-9a-fA-F]{7,64}\Z")


def parse_pr_event(payload: object) -> dict | None:
    """Extract the fields we need from a GitHub `pull_request` event, or None if it isn't one (incl.
    a non-object body, so an array/scalar yields a clean skip, not a 500). `repo`/`sha` are
    SHAPE-VALIDATED here so attacker-controlled webhook fields can't become a URL-injection / SSRF
    sink downstream (e.g. if a caller wires them into `post_commit_status`)."""
    if not isinstance(payload, dict):
        return None
    pr = payload.get("pull_request")
    if not isinstance(pr, dict) or "head" not in pr:
        return None
    repo = (payload.get("repository") or {}).get("full_name")
    head = pr.get("head") or {}
    sha = head.get("sha")
    if not (isinstance(repo, str) and _REPO_RE.match(repo)
            and isinstance(sha, str) and _SHA_RE.match(sha)):
        return None  # malformed/hostile owner/repo or sha → skip rather than trust it
    return {
        "action": payload.get("action"),
        "repo": repo,
        "number": payload.get("number") or pr.get("number"),
        "sha": sha,
    }


def post_commit_status(repo_full_name: str, sha: str, *, state: str, token: str,
                       description: str = "", context: str = "verel/gate",
                       api: str = "https://api.github.com", cafile: str | None = None) -> int:
    """Post a commit status back to GitHub (opt-in outbound). `state` ∈ pending|success|failure|error.
    Uses the transport opener (ignores ambient proxy env, applies secure redirects). Returns HTTP code.
    """
    if state not in ("pending", "success", "failure", "error"):
        raise ValueError(f"invalid status state {state!r}")
    if not _REPO_RE.match(repo_full_name) or not _SHA_RE.match(sha):
        raise ValueError("invalid repo/sha — refusing to build an outbound URL from unvalidated input")
    if not api.lower().startswith(("https://", "http://")):
        # never let a file:/ or custom-scheme `api` turn this into a local-file read / SSRF primitive
        raise ValueError(f"api must be http(s), got {api!r}")
    url = f"{api.rstrip('/')}/repos/{repo_full_name}/statuses/{sha}"
    data = json.dumps({"state": state, "description": description[:140], "context": context}).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
        "Content-Type": "application/json", "User-Agent": "verel"})
    ctx = make_client_context(cafile, None)
    opener = build_opener(ctx)
    with opener.open(req, timeout=15) as r:  # nosec B310 — scheme guarded http(s) above
        return r.status


# ---- the server ----
def _make_handler(repo: str, run_gate, token: str | None, webhook_secret: str | None,
                  on_event, gate_sem):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        timeout = 30  # slowloris guard — drop a slow/idle connection rather than pin a thread

        def log_message(self, *_a):  # quiet
            pass

        def _authed(self) -> bool:
            if token is None:
                return True
            try:
                return hmac.compare_digest(self.headers.get("Authorization", ""), f"Bearer {token}")
            except (TypeError, ValueError):
                return False  # non-ASCII / malformed header → deny cleanly (compare_digest would raise)

        def _send(self, code: int, body: dict) -> None:
            # Close the connection after EVERY response — this gate has no need for keep-alive (CI /
            # webhook traffic is low-volume), and with NO connection reuse the entire HTTP
            # request-smuggling / desync class is structurally impossible: an unconsumed body or a
            # header-parser differential (TE.CL / CL.CL / whitespace-before-colon truncation) can
            # never be re-read as a second request on a reused socket. The framing checks below stay
            # as defense-in-depth (clean early rejection), but this is the load-bearing guarantee.
            self.close_connection = True
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)

        def _check_framing(self) -> None:
            """Reject ambiguous framing a front-end proxy might interpret differently than we do —
            the classic TE.CL / CL.CL request-smuggling primitives. We only speak Content-Length."""
            if self.headers.get("Transfer-Encoding"):
                raise ValueError("Transfer-Encoding not supported")
            if len(self.headers.get_all("Content-Length") or []) > 1:
                raise ValueError("duplicate Content-Length")

        def _raw_body(self) -> bytes:
            n = int(self.headers.get("Content-Length", "0"))
            if n < 0 or n > _MAX_BODY:  # negative length → read(-1) reads to EOF, defeating the cap
                raise ValueError("bad request body length")
            return self.rfile.read(n) or b""

        def _gated(self):
            """Run the gate under a bounded semaphore so a flood of requests can't fork-bomb the host
            with unbounded concurrent pytest/ruff subprocesses. Returns the result, or None after
            sending 503 when too many gates are already in flight."""
            if not gate_sem.acquire(blocking=False):
                self._send(503, {"error": "gate busy — too many concurrent runs"})
                return None
            try:
                return run_gate()
            finally:
                gate_sem.release()

        def do_GET(self):  # noqa: N802
            try:
                self._check_framing()
                # Our GET endpoints take NO body. A GET carrying a (valid, single) Content-Length body
                # is never consumed by do_GET, so on a keep-alive socket those bytes would be re-parsed
                # as the next request (CL.0 desync / smuggling). Reject any non-zero body → 400 + close.
                if int(self.headers.get("Content-Length", "0") or "0") != 0:
                    raise ValueError("GET must not carry a body")
                if self.path == "/health":   # liveness: the process is up
                    return self._send(200, {"status": "ok"})
                if self.path == "/ready":    # readiness: can actually serve gates (repo accessible)
                    import os
                    ok = os.path.isdir(repo) and os.access(repo, os.R_OK)
                    return self._send(200 if ok else 503,
                                      {"status": "ready" if ok else "not-ready", "repo": repo})
                return self._send(404, {"error": "not found"})
            except ValueError as e:
                return self._send(400, {"error": str(e)})

        def do_POST(self):  # noqa: N802
            try:
                self._check_framing()
                if self.path == "/gate":
                    if not self._authed():
                        return self._send(401, {"error": "unauthorized"})
                    self._raw_body()  # consume + cap the body even though /gate ignores it
                    result = self._gated()
                    return None if result is None else self._send(200, result)
                if self.path == "/github":
                    body = self._raw_body()
                    sig = self.headers.get("X-Hub-Signature-256")
                    if not verify_github_signature(webhook_secret or "", body, sig):
                        return self._send(401, {"error": "bad signature"})
                    event = parse_pr_event(json.loads(body or b"{}"))
                    if event is None:
                        return self._send(200, {"skipped": "not a pull_request event"})
                    result = self._gated()
                    if result is None:
                        return None
                    if on_event is not None:
                        on_event(event, result)
                    return self._send(200, {"event": event, "gate": result})
                return self._send(404, {"error": "not found"})
            except ValueError as e:
                return self._send(400, {"error": str(e)})
            except Exception as e:  # never leak internals
                return self._send(500, {"error": type(e).__name__})

    return Handler


class GateServer:
    """An HTTP gate over ONE configured repo. `POST /gate` (bearer) → verdict; `POST /github`
    (HMAC-verified PR webhook) → gate + verdict; `GET /health`. Routable bind requires auth + TLS."""

    def __init__(self, repo: str | Path, *, host: str = "127.0.0.1", port: int = 0,
                 auth_token: str | None = None, webhook_secret: str | None = None,
                 lint: bool = True, on_event=None, max_concurrent_gates: int = 4,
                 certfile: str | Path | None = None, keyfile: str | Path | None = None,
                 ssl_context: ssl.SSLContext | None = None, insecure: bool = False,
                 max_connections: int = _DEFAULT_MAX_CONNECTIONS, max_per_ip: int | None = None):
        self.repo = os.path.realpath(str(repo))
        if not os.path.isdir(self.repo):
            raise ValueError(f"repo is not a directory: {self.repo}")
        # An empty/whitespace secret is NOT a credential — map it to None so it can never become a
        # matchable `Bearer ` token, and so the bind policy treats it as "no auth" (fail closed).
        auth_token = (auth_token or "").strip() or None
        webhook_secret = (webhook_secret or "").strip() or None
        self._lint = lint
        # Bound concurrent gate runs so a request flood can't fork-bomb the host with unbounded
        # pytest/ruff subprocesses (each gate spawns real subprocesses); excess requests get 503.
        self._gate_sem = threading.BoundedSemaphore(max(1, max_concurrent_gates))
        ssl_context = build_server_context(certfile, keyfile, ssl_context)
        self._tls = ssl_context is not None
        enforce_bind_policy(host, auth_token=auth_token, tls=self._tls, service="gate service",
                            insecure=insecure)
        self._httpd = TLSThreadingHTTPServer(
            (host, port), _make_handler(self.repo, lambda: self._run_gate(), auth_token,
                                        webhook_secret, on_event, self._gate_sem),
            ssl_context=ssl_context, max_connections=max_connections, max_per_ip=max_per_ip)
        self._thread: threading.Thread | None = None

    def _run_gate(self) -> dict:
        from ..mcp_server import dispatch
        return dispatch("verel_ci_check", {"repo": self.repo, "lint": self._lint})

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        if isinstance(host, (bytes, bytearray)):
            host = host.decode()
        return f"{scheme(self._tls)}://{host}:{port}"

    def start(self) -> GateServer:
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)
