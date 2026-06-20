"""Hosted skill registry (§2.2, §8.7) — the public registry behind an HTTP API.

The H2 model sweep measured ~88-89% cross-tenant transfer (BUILD; see docs/H2_RESULTS.md), so the
public registry is now justified, not assumed. This serves a `PublicRegistry` over HTTP so tenants
on different machines can publish and fetch signed skill artifacts:

  POST /publish   — store a signed, content-addressed artifact (the signature is verified; a
                    tampered or unsigned artifact is refused with 400);
  GET  /search?q= — capability search;  GET /fetch?hash= — by content hash;  GET /all.

The one rule that keeps the flywheel honest is preserved END TO END: **trust does not travel**. The
server stores artifacts and verifies their integrity, but a fetched skill enters the importer as a
`candidate` and only becomes `verified` by passing the importer's OWN held-out eval
(`registry.import_skill`). The network changes distribution, not the trust model. Stdlib only
(`http.server` + `urllib`); an optional bearer token gates writes and reads.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .artifact import SkillArtifact
from .store import PublicRegistry


def _make_handler(registry: PublicRegistry, token: str | None):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_a):
            pass

        def _authed(self) -> bool:
            return token is None or self.headers.get("Authorization") == f"Bearer {token}"

        def _send(self, code: int, body: dict) -> None:
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802
            if not self._authed():
                return self._send(401, {"error": "unauthorized"})
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if u.path == "/search":
                hits = registry.search((q.get("q") or [""])[0])
                return self._send(200, {"artifacts": [a.model_dump() for a in hits]})
            if u.path == "/fetch":
                art = registry.get((q.get("hash") or [""])[0])
                return self._send(200 if art else 404, {"artifact": art.model_dump() if art else None})
            if u.path == "/all":
                return self._send(200, {"artifacts": [a.model_dump() for a in registry.all()]})
            return self._send(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            if not self._authed():
                return self._send(401, {"error": "unauthorized"})
            if self.path != "/publish":
                return self._send(404, {"error": "not found"})
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
                art = SkillArtifact(**body["artifact"])
            except (ValueError, KeyError, json.JSONDecodeError):
                return self._send(400, {"error": "bad artifact"})
            try:
                registry.publish(art)  # verifies signature/content — refuses a tampered artifact
            except ValueError as e:
                return self._send(400, {"error": str(e)})
            return self._send(200, {"content_hash": art.content_hash})

    return Handler


class RegistryServer:
    """A threaded HTTP front-end for a `PublicRegistry`. `start()` serves in a background thread;
    `url` is the base address; `stop()` shuts it down."""

    def __init__(self, root: str | Path, *, host: str = "127.0.0.1", port: int = 0,
                 auth_token: str | None = None):
        self.registry = PublicRegistry(root)
        self._httpd = ThreadingHTTPServer((host, port), _make_handler(self.registry, auth_token))
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        if isinstance(host, (bytes, bytearray)):
            host = host.decode()
        return f"http://{host}:{port}"

    def start(self) -> RegistryServer:
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)


class RemoteRegistry:
    """A `PublicRegistry`-shaped client over HTTP — a drop-in for the local store, so
    `import_skill(remote.get(h), into=local, target_cases=...)` re-verifies exactly the same way.
    Trust still does not travel: this only moves bytes, never a verdict."""

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
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"artifact": None}
            raise ValueError(json.loads(e.read()).get("error", f"http {e.code}")) from e

    def publish(self, artifact: SkillArtifact) -> SkillArtifact:
        if not artifact.content_hash or not artifact.signature:
            artifact.finalize()
        self._req("POST", "/publish", {"artifact": artifact.model_dump()})
        return artifact

    def get(self, content_hash: str) -> SkillArtifact | None:
        d = self._req("GET", f"/fetch?hash={content_hash}")["artifact"]
        return SkillArtifact(**d) if d else None

    def search(self, capability: str) -> list[SkillArtifact]:
        from urllib.parse import quote
        hits = self._req("GET", f"/search?q={quote(capability)}")["artifacts"]
        return [SkillArtifact(**a) for a in hits]

    def all(self) -> list[SkillArtifact]:
        return [SkillArtifact(**a) for a in self._req("GET", "/all")["artifacts"]]
