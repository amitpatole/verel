"""Hosted control plane (§6.3) — the lease store + fencing authority behind an HTTP API.

The in-memory and sqlite lease stores need a shared filesystem. Managers on DIFFERENT machines
need the fencing authority over the network. This wraps a durable `SqliteLeaseStore` in a tiny,
dependency-free HTTP service and ships a `RemoteLeaseStore` client that speaks the SAME
`LeaseStore` Protocol — so `Scheduler(leases=RemoteLeaseStore(url), owner=host)` coordinates
cross-machine with no other change.

The server is the clock authority: it stamps `now` from its own clock on every acquire/renew, so
managers with skewed clocks can't disagree about expiry (the classic distributed-lease pitfall).
Stdlib only (`http.server` + `urllib` + `json`); an optional bearer token gates access. Terminal
writes are still fenced — a stale token's `complete` returns HTTP 409 and the client raises
`FencingError`, exactly as in-process.
"""

from __future__ import annotations

import hmac
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .lease import FencingError, Lease, SqliteLeaseStore

_MAX_BODY = 1 * 1024 * 1024  # 1 MiB — lease payloads are tiny; reject oversized bodies (DoS guard)


def _make_handler(store: SqliteLeaseStore, token: str | None):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        timeout = 30  # drop a slow/idle connection rather than pinning a thread (slowloris guard)

        def log_message(self, *_a):  # silence default stderr logging
            pass

        def _authed(self) -> bool:
            if token is None:
                return True
            return hmac.compare_digest(self.headers.get("Authorization", ""), f"Bearer {token}")

        def _send(self, code: int, body: dict) -> None:
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length", "0"))
            if n > _MAX_BODY:
                raise ValueError("request body too large")
            return json.loads(self.rfile.read(n) or b"{}")

        def do_GET(self):  # noqa: N802
            if not self._authed():
                return self._send(401, {"error": "unauthorized"})
            u = urlparse(self.path)
            q = parse_qs(u.query)
            key = (q.get("key") or [""])[0]
            if u.path == "/token":
                return self._send(200, {"token": store.current_token(key)})
            if u.path == "/outcome":
                return self._send(200, {"outcome": store.outcome(key)})
            if u.path == "/holder":  # server is the clock authority for expiry
                return self._send(200, {"holder": store.holder(key, now=time.time())})
            return self._send(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            if not self._authed():
                return self._send(401, {"error": "unauthorized"})
            try:
                b = self._body()
            except (ValueError, json.JSONDecodeError):
                return self._send(400, {"error": "bad json"})
            now = time.time()  # server is the clock authority
            if self.path == "/acquire":
                lease = store.acquire(b["key"], b["owner"], now=now, ttl=float(b["ttl"]))
                return self._send(200, {"lease": _lease_json(lease)})
            if self.path == "/renew":
                lease = store.renew(Lease(b["key"], b["owner"], int(b["token"]), 0.0),
                                    now=now, ttl=float(b["ttl"]))
                return self._send(200, {"lease": _lease_json(lease)})
            if self.path == "/release":
                store.release(Lease(b["key"], b.get("owner", ""), int(b["token"]), 0.0))
                return self._send(200, {"ok": True})
            if self.path == "/complete":
                try:
                    store.complete(Lease(b["key"], b.get("owner", ""), int(b["token"]), 0.0), b["state"])
                except FencingError as e:
                    return self._send(409, {"error": str(e)})
                return self._send(200, {"ok": True})
            return self._send(404, {"error": "not found"})

    return Handler


def _lease_json(lease: Lease | None) -> dict | None:
    if lease is None:
        return None
    return {"key": lease.key, "owner": lease.owner, "token": lease.token, "expires_at": lease.expires_at}


class ControlPlaneServer:
    """A threaded HTTP front-end for a durable `SqliteLeaseStore`. `start()` binds and serves in a
    background thread; `url` is the base address; `stop()` shuts it down."""

    def __init__(self, db_path: str | Path, *, host: str = "127.0.0.1", port: int = 0,
                 auth_token: str | None = None):
        if auth_token is None and host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError(f"refusing to bind {host!r} without auth_token — that exposes an "
                             "unauthenticated lease authority; pass auth_token=... or bind 127.0.0.1")
        self.store = SqliteLeaseStore(db_path)
        self._httpd = ThreadingHTTPServer((host, port), _make_handler(self.store, auth_token))
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        if isinstance(host, (bytes, bytearray)):
            host = host.decode()
        return f"http://{host}:{port}"

    def start(self) -> ControlPlaneServer:
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)


class RemoteLeaseStore:
    """A `LeaseStore` over HTTP — points the scheduler at a `ControlPlaneServer`. The `now` args in
    the Protocol are accepted but ignored: the server is the clock authority."""

    def __init__(self, base_url: str, *, auth_token: str | None = None, timeout: float = 10.0):
        self.base = base_url.rstrip("/")
        self.token = auth_token
        self.timeout = timeout

    def _req(self, method: str, path: str, body: dict | None = None) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 409:
                raise FencingError(json.loads(e.read()).get("error", "fenced")) from e
            raise

    def acquire(self, key: str, owner: str, *, now: float = 0.0, ttl: float) -> Lease | None:
        return _lease_from(self._req("POST", "/acquire", {"key": key, "owner": owner, "ttl": ttl})["lease"])

    def renew(self, lease: Lease, *, now: float = 0.0, ttl: float) -> Lease | None:
        return _lease_from(self._req("POST", "/renew",
                                     {"key": lease.key, "owner": lease.owner,
                                      "token": lease.token, "ttl": ttl})["lease"])

    def release(self, lease: Lease) -> None:
        self._req("POST", "/release", {"key": lease.key, "owner": lease.owner, "token": lease.token})

    def current_token(self, key: str) -> int:
        return int(self._req("GET", f"/token?key={key}")["token"])

    def is_current(self, lease: Lease, *, now: float = 0.0) -> bool:
        return lease.token == self.current_token(lease.key)

    def holder(self, key: str, *, now: float = 0.0) -> str | None:
        # the client clock is ignored: the server is the authority for lease expiry
        return self._req("GET", f"/holder?key={key}")["holder"]

    def complete(self, lease: Lease, state: str) -> None:
        self._req("POST", "/complete",
                  {"key": lease.key, "owner": lease.owner, "token": lease.token, "state": state})

    def outcome(self, key: str) -> str | None:
        return self._req("GET", f"/outcome?key={key}")["outcome"]


def _lease_from(d: dict | None) -> Lease | None:
    return Lease(d["key"], d["owner"], d["token"], d["expires_at"]) if d else None
