"""Hosted shared memory (§5) — a `MemoryView` behind an HTTP API, so a FLEET shares one brain.

`LocalMemory` and `mem0` are per-process. The shared team brain needs agents on different machines
reading and writing **one** store. This wraps a durable `MemoryView` in a tiny, dependency-free
HTTP service and ships a `RemoteMemory` client that implements the SAME `MemoryView` Protocol — so
everything that takes a memory (recall, the scope lattice, consolidation, the promotion gate) works
against the shared brain unchanged: `lattice_recall(RemoteMemory(url), ...)` just works.

The server is the **single writer**: every store access is serialized behind one lock, so the
interference rule (a new value for the same `(subject, predicate, scope)` supersedes) stays correct
under concurrent agents — no split-brain, because there is one authority. (Replicating the store
across several authorities — and fencing between them — is the next hardening, mirroring the
control plane.) Stdlib only; an optional bearer token gates access.
"""

from __future__ import annotations

import hmac
import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ..fleet.lease import FencingError
from .local import LocalMemory
from .replicated import NotLeaderError
from .view import MemoryKind, MemoryRecord, MemoryView, make_id, make_key

_MAX_BODY = 16 * 1024 * 1024  # 16 MiB — reject oversized bodies before allocating (DoS guard)


def _rec_json(r: MemoryRecord | None) -> dict | None:
    return r.model_dump() if r is not None else None


def _make_id_for(b: dict) -> str:
    return make_id(make_key(str(b.get("subject", "")), str(b.get("predicate", "")),
                            str(b.get("scope", "repo:default"))))


def _kind(v) -> MemoryKind | None:
    return MemoryKind(v) if v else None


# In signed-writes mode these are the ONLY POST paths a (bearer-authenticated) client may hit:
# authored writes must be signed (/write_signed), reads are fine, and replication is the cluster's
# own fenced channel. Everything else (/write with an arbitrary author, /promote → verified, the
# corroborate/contradict/annotate/flag mutators) would let a mere bearer holder forge authorship or
# trust, defeating the principal layer — so they are refused.
_SIGNED_MODE_POST = frozenset({"/write_signed", "/recall", "/all", "/apply", "/replicate"})


def _make_handler(store: MemoryView, lock: threading.Lock, token: str | None,
                  trusted: dict[str, str] | None = None, require_override: bool | None = None):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        timeout = 30  # drop a slow/idle connection rather than pinning a thread (slowloris guard)

        def log_message(self, *_a):
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
            if n < 0 or n > _MAX_BODY:  # negative length → read(-1) reads to EOF, defeating the cap
                raise ValueError("bad request body length")
            return json.loads(self.rfile.read(n) or b"{}")

        def do_GET(self):  # noqa: N802
            if not self._authed():
                return self._send(401, {"error": "unauthorized"})
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if u.path == "/get":
                with lock:
                    return self._send(200, {"record": _rec_json(store.get((q.get("id") or [""])[0]))})
            return self._send(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            if not self._authed():
                return self._send(401, {"error": "unauthorized"})
            try:
                b = self._body()
            except (ValueError, RecursionError, json.JSONDecodeError):
                return self._send(400, {"error": "bad json"})
            # Effective mode is read LIVE: explicit override wins, else ON whenever any principal is
            # enrolled (so a later enroll() auto-enables enforcement, no stale-closure bypass).
            require_signed = bool(trusted) if require_override is None else require_override
            if require_signed and self.path not in _SIGNED_MODE_POST:
                # multi-principal: a bearer token alone can't forge authorship or trust — authored
                # writes must be SIGNED; trust transitions come from server-side eval, not a client call.
                return self._send(403, {"error": "signed-writes mode: use /write_signed"})
            with lock:  # the server is the single writer: serialize every access
                # a replicated node fences/refuses writes when it isn't the leader; surface that as
                # 409 (FencingError) / 421 (NotLeaderError) so the client retries the leader.
                try:
                    return self._dispatch(b)
                except FencingError as e:
                    return self._send(409, {"error": str(e)})
                except NotLeaderError as e:
                    return self._send(421, {"error": str(e)})
                except (KeyError, ValueError, TypeError) as e:  # malformed body → clean 400
                    return self._send(400, {"error": f"bad request: {e}"})

        def _dispatch(self, b):  # noqa: C901 — flat command table
            if self.path == "/replicate":  # a leader replicating a record to this follower (fenced)
                rep = getattr(store, "apply_replica_fenced", None)
                if rep is None:
                    return self._send(400, {"error": "store is not replicated"})
                rep(b["record"], int(b["token"]))
                return self._send(200, {"ok": True})
            if self.path == "/apply":      # verbatim upsert (catch-up sync)
                r = store.apply_replica(MemoryRecord(**b["record"]))
                return self._send(200, {"record": _rec_json(r)})
            if self.path == "/write":
                r = store.write(MemoryRecord(**b["record"]), ts=b.get("ts", 0.0))
                return self._send(200, {"record": _rec_json(r)})
            if self.path == "/write_signed":
                # multi-principal: the author is the AUTHENTICATED key_id (signature verified against
                # an enrolled principal), never the caller's say-so. Trust does not travel.
                from .principal import authenticated_remember
                from .share import AuthorTrust
                res = authenticated_remember(
                    store, subject=str(b.get("subject", "")), predicate=str(b.get("predicate", "")),
                    scope=str(b.get("scope", "repo:default")), text=str(b["text"]),
                    signature=str(b.get("signature", "")), key_id=str(b.get("key_id", "")),
                    trusted=trusted or {}, kind=_kind(b.get("kind")) or MemoryKind.FACT,
                    author_trust=AuthorTrust(store), ts=b.get("ts", 0.0))
                if not res.authenticated:
                    return self._send(403, {"error": res.reason})
                rid = store.get(_make_id_for(b))
                return self._send(200, {"authenticated": res.authenticated, "written": res.written,
                                        "author": res.author, "conflict": res.conflict,
                                        "reason": res.reason, "record": _rec_json(rid)})
            if self.path == "/recall":
                hits = store.recall(b["query"], scope=b.get("scope"), kind=_kind(b.get("kind")),
                                    k=b.get("k", 5), ts=b.get("ts", 0.0))
                return self._send(200, {"records": [_rec_json(r) for r in hits]})
            if self.path == "/all":
                recs = store.all(scope=b.get("scope"), kind=_kind(b.get("kind")))
                return self._send(200, {"records": [_rec_json(r) for r in recs]})
            if self.path in ("/corroborate", "/contradict"):
                fn = store.corroborate if self.path == "/corroborate" else store.contradict
                kw = {"delta": b["delta"]} if "delta" in b else {}
                return self._send(200, {"record": _rec_json(fn(b["id"], **kw))})
            if self.path in ("/promote", "/demote", "/pin", "/unpin"):
                fn = {"/promote": store.promote, "/demote": store.demote,
                      "/pin": store.pin, "/unpin": store.unpin}[self.path]
                return self._send(200, {"record": _rec_json(fn(b["id"]))})
            if self.path == "/annotate":
                r = store.annotate(b["id"], **b.get("detail", {}))
                return self._send(200, {"record": _rec_json(r)})
            if self.path == "/set_flags":
                r = store.set_flags(b["id"], pinned=b.get("pinned"), volatile=b.get("volatile"),
                                    ttl_s=b.get("ttl_s"))
                return self._send(200, {"record": _rec_json(r)})
            if self.path == "/decay":
                n = store.decay(half_life_s=b.get("half_life_s", 604800.0), now=b.get("now", 0.0))
                return self._send(200, {"pruned": n})
            return self._send(404, {"error": "not found"})

    return Handler


class MemoryServer:
    """A threaded HTTP front-end for a durable `MemoryView`. Pass a `db_path` (a `LocalMemory` is
    created, opened cross-thread + lock-serialized) or your own `store`. `start()` serves in a
    background thread; `url` is the base address; `stop()` shuts it down."""

    def __init__(self, db_path: str | Path | None = None, *, store: MemoryView | None = None,
                 host: str = "127.0.0.1", port: int = 0, auth_token: str | None = None,
                 durable: bool = True, trusted_principals: dict[str, str] | None = None,
                 require_signed_writes: bool | None = None):
        if auth_token is None and host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError(f"refusing to bind {host!r} without auth_token — that exposes an "
                             "unauthenticated memory service; pass auth_token=... or bind 127.0.0.1")
        if store is None:
            if db_path is None:
                raise ValueError("MemoryServer needs a db_path or a store")
            store = LocalMemory(db_path, check_same_thread=False, durable=durable)
        self.store = store
        # Enrolled principals (key_id → public_key_b64) — only their SIGNED writes (/write_signed) are
        # accepted with an authenticated author. Bearer token = "can connect"; signature = "who wrote".
        self.trusted_principals = dict(trusted_principals or {})
        # Secure-by-default: enrolling principals turns ON signed-writes enforcement (the raw /write +
        # trust-mutation endpoints are refused), unless the operator explicitly opts out. Read live in
        # the handler, so a later enroll() also flips it on.
        self._require_override = require_signed_writes
        self._lock = threading.Lock()
        self._httpd = ThreadingHTTPServer(
            (host, port), _make_handler(self.store, self._lock, auth_token, self.trusted_principals,
                                        self._require_override))
        self._thread: threading.Thread | None = None

    def enroll(self, key_id: str, public_key_b64: str) -> None:
        """Trust a principal's signed writes (operator action). Reflected immediately (shared dict)."""
        self.trusted_principals[key_id] = public_key_b64

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        if isinstance(host, (bytes, bytearray)):
            host = host.decode()
        return f"http://{host}:{port}"

    def start(self) -> MemoryServer:
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)


class RemoteMemory:
    """A `MemoryView` over HTTP — point an agent at a `MemoryServer` and it shares the team brain.
    A drop-in for `LocalMemory`/`mem0`, so `lattice_recall`, `graduate`, consolidation, and the
    promotion gate all work against the shared store unchanged."""

    def __init__(self, base_url: str, *, auth_token: str | None = None, timeout: float = 15.0):
        self.base = base_url.rstrip("/")
        self.token = auth_token
        self.timeout = timeout

    def _req(self, method: str, path: str, body: dict | None = None) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read())

    @staticmethod
    def _rec(d: dict | None) -> MemoryRecord | None:
        return MemoryRecord(**d) if d else None

    # ---- MemoryView Protocol ----
    def write(self, record: MemoryRecord, *, ts: float = 0.0) -> MemoryRecord:
        out = self._req("POST", "/write", {"record": record.model_dump(), "ts": ts})
        return self._rec(out["record"])  # type: ignore[return-value]

    def remember_signed(self, principal, *, subject: str, predicate: str, scope: str, text: str,
                        kind: MemoryKind = MemoryKind.FACT, ts: float = 0.0) -> dict:
        """Author a belief on the shared brain as an AUTHENTICATED principal: sign the claim with the
        principal's key; the server derives `author` from the verified key (forge-proof). Returns the
        server's authn result {authenticated, written, author, conflict, reason, record}."""
        sig = principal.sign_write(subject=subject, predicate=predicate, scope=scope, text=text)
        try:
            return self._req("POST", "/write_signed", {
                "subject": subject, "predicate": predicate, "scope": scope, "text": text,
                "kind": kind.value, "signature": sig, "key_id": principal.key_id, "ts": ts})
        except urllib.error.HTTPError as e:
            if e.code == 403:  # unauthenticated write rejected — surface it, don't raise
                body = json.loads(e.read() or b"{}")
                return {"authenticated": False, "written": False,
                        "reason": body.get("error", "unauthenticated")}
            raise

    def apply_replica(self, record: MemoryRecord) -> MemoryRecord:
        out = self._req("POST", "/apply", {"record": record.model_dump()})
        return self._rec(out["record"])  # type: ignore[return-value]

    def get(self, record_id: str) -> MemoryRecord | None:
        return self._rec(self._req("GET", f"/get?id={record_id}")["record"])

    def recall(self, query: str, *, scope=None, kind=None, k: int = 5, ts: float = 0.0):
        body = {"query": query, "scope": scope, "kind": kind.value if kind else None, "k": k, "ts": ts}
        return [self._rec(d) for d in self._req("POST", "/recall", body)["records"]]

    def all(self, *, scope=None, kind=None):
        body = {"scope": scope, "kind": kind.value if kind else None}
        return [self._rec(d) for d in self._req("POST", "/all", body)["records"]]

    def corroborate(self, record_id, *, delta: float = 0.15):
        return self._rec(self._req("POST", "/corroborate", {"id": record_id, "delta": delta})["record"])

    def contradict(self, record_id, *, delta: float = 0.25):
        return self._rec(self._req("POST", "/contradict", {"id": record_id, "delta": delta})["record"])

    def promote(self, record_id):
        return self._rec(self._req("POST", "/promote", {"id": record_id})["record"])

    def demote(self, record_id):
        return self._rec(self._req("POST", "/demote", {"id": record_id})["record"])

    def annotate(self, record_id, **detail):
        return self._rec(self._req("POST", "/annotate", {"id": record_id, "detail": detail})["record"])

    def set_flags(self, record_id, *, pinned=None, volatile=None, ttl_s=None):
        body = {"id": record_id, "pinned": pinned, "volatile": volatile, "ttl_s": ttl_s}
        return self._rec(self._req("POST", "/set_flags", body)["record"])

    def pin(self, record_id):
        return self._rec(self._req("POST", "/pin", {"id": record_id})["record"])

    def unpin(self, record_id):
        return self._rec(self._req("POST", "/unpin", {"id": record_id})["record"])

    def decay(self, *, half_life_s: float = 604800.0, now: float = 0.0) -> int:
        return int(self._req("POST", "/decay", {"half_life_s": half_life_s, "now": now})["pruned"])


class ReplicaClient:
    """A replication peer over HTTP — give a `ReplicatedMemory` these as `peers` to replicate to
    follower `MemoryServer`s on other machines. `replicate` raises `FencingError` on a 409 so a
    deposed leader's in-flight write is rejected at the follower, exactly as in-process."""

    def __init__(self, base_url: str, *, auth_token: str | None = None, timeout: float = 10.0):
        self.base = base_url.rstrip("/")
        self.token = auth_token
        self.timeout = timeout

    def apply_replica_fenced(self, record: dict, token: int) -> None:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        data = json.dumps({"record": record, "token": token}).encode()
        req = urllib.request.Request(self.base + "/replicate", data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                r.read()
        except urllib.error.HTTPError as e:
            if e.code == 409:
                raise FencingError(json.loads(e.read()).get("error", "fenced")) from e
            raise
