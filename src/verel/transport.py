"""Shared transport security for the HTTP services (brain, lease authority, registry) — ONE source of
truth for the bind policy and TLS, so a routable bind can't be authenticated-but-cleartext on one
service while another is hardened. See docs/SUBSTRATE_DESIGN.md §15.4.

The rule, fail-closed:
  - **loopback** (`127.0.0.1`/`::1`/`localhost`) never leaves the box → plain HTTP, no token: zero-config.
  - **routable** (anything else) → requires BOTH an `auth_token` (else anonymous) AND TLS (else the
    token + payloads cross the wire in cleartext). Without either, the server refuses to start.
  - **client** → never attaches a bearer/cluster secret to a cleartext (`http://`) hop toward a routable
    host; `insecure=True` is the explicit opt-out for a TLS-terminating proxy that already encrypts it.
"""

from __future__ import annotations

import ssl
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

_DEFAULT_PORTS = {"http": 80, "https": 443}
# Cap concurrent connections so a flood of slow/stalled (pre-auth) connections can't park unbounded
# worker threads — each parked thread costs an ~8 MiB stack + an FD until the handler timeout reaps it.
# Generous for an internal cluster brain; operators can raise it via the server's max_connections=.
_DEFAULT_MAX_CONNECTIONS = 128

# Hosts that never leave the machine — plain HTTP and no token are fine (the zero-config dev roundtrip).
# NB: "" is deliberately NOT here — an empty host is the WILDCARD bind (ThreadingHTTPServer(("", p))
# listens on 0.0.0.0, all interfaces), the most exposed bind there is, not loopback. The servers default
# host="127.0.0.1", so "" only ever arrives as an explicit all-interfaces choice → treat it as routable.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
# Request headers that carry a secret — never let a redirect ferry these onto a cleartext/cross-origin hop.
_SENSITIVE_HEADERS = frozenset({"authorization", "x-cluster-token"})


def is_loopback(host: str) -> bool:
    return (host or "").strip().lower() in _LOOPBACK_HOSTS


def build_server_context(certfile: str | Path | None, keyfile: str | Path | None,
                         ssl_context: ssl.SSLContext | None) -> ssl.SSLContext | None:
    """The server-side TLS context: a ready context wins, else a default one loaded from cert/key.
    None → plaintext (only allowed on loopback per `enforce_bind_policy`)."""
    if ssl_context is not None:
        return ssl_context
    if certfile is not None:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(certfile=str(certfile),
                            keyfile=str(keyfile) if keyfile is not None else None)
        return ctx
    return None


def enforce_bind_policy(host: str, *, auth_token: str | None, tls: bool, service: str) -> None:
    """Fail closed on a routable bind: it must be BOTH authenticated AND encrypted. Loopback is exempt
    (never leaves the box). `service` names the surface in the error (e.g. 'memory service')."""
    if is_loopback(host):
        return
    if auth_token is None:
        raise ValueError(f"refusing to bind routable host {host!r} without auth_token — that exposes "
                         f"an unauthenticated {service}; pass auth_token=... or bind 127.0.0.1")
    if not tls:
        raise ValueError(f"refusing to bind routable host {host!r} without TLS — the bearer token and "
                         f"payloads would cross the network in cleartext; pass certfile=/keyfile= "
                         "(or ssl_context=) or bind 127.0.0.1")


def scheme(tls: bool) -> str:
    return "https" if tls else "http"


class TLSThreadingHTTPServer(ThreadingHTTPServer):
    """A `ThreadingHTTPServer` that (1) does the TLS handshake in the per-connection WORKER thread, not
    in the single-threaded accept loop, and (2) caps concurrent connections.

    (1) Wrapping the *listener* with the default `do_handshake_on_connect=True` makes `accept()` block on
    the handshake — one client that connects and never sends a ClientHello starves the whole server (an
    unauthenticated, pre-auth DoS on exactly the routable bind TLS exists for). Instead we wrap each
    accepted socket WITHOUT handshaking (fast, no I/O) in `get_request`, so the accept loop stays free;
    the handshake then happens lazily on the first read inside the worker thread, bounded by the
    handler's socket timeout (the slowloris guard).

    (2) Deferring the handshake stops accept-loop starvation but not unbounded CONCURRENCY: a flood of
    stalled connections would still park one worker thread each until the timeout. A bounded semaphore
    caps in-flight connections — over the cap, the connection is dropped (closed) rather than parking
    another thread. The cap self-heals as handlers finish or time out."""

    def __init__(self, server_address, handler_class, *, ssl_context: ssl.SSLContext | None = None,
                 max_connections: int = _DEFAULT_MAX_CONNECTIONS):
        if max_connections < 1:
            # a non-positive cap would silently drop EVERY connection (look like a total hang) — reject
            # the misconfiguration with a clear error instead.
            raise ValueError(f"max_connections must be >= 1, got {max_connections}")
        self._ssl_context = ssl_context
        self._slots = threading.BoundedSemaphore(max_connections)
        super().__init__(server_address, handler_class)

    def get_request(self):
        sock, addr = super().get_request()
        if self._ssl_context is not None:
            sock = self._ssl_context.wrap_socket(sock, server_side=True,
                                                  do_handshake_on_connect=False)
        return sock, addr

    def process_request(self, request, client_address):
        # Acquire a slot in the ACCEPT thread (before spawning a worker). Over the cap → drop now, so a
        # flood can't park more than `max_connections` threads. close_request (not shutdown_request)
        # avoids releasing a slot we never took.
        if not self._slots.acquire(blocking=False):
            self.close_request(request)
            return
        try:
            super().process_request(request, client_address)   # spawns the worker thread
        except BaseException:
            self._slots.release()   # the worker never started → release the slot we just took
            raise

    def process_request_thread(self, request, client_address):
        # Release is paired HERE (worker thread), not in shutdown_request: shutdown_request also runs on
        # the verify_request()==False path where process_request never acquired, which would over-release
        # the BoundedSemaphore. Pairing acquire(process_request)/release(here) is balanced on every path:
        # accepted+spawned → released here; over-cap drop → never acquired; spawn failure → released above.
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def make_client_context(cafile: str | Path | None,
                        ssl_context: ssl.SSLContext | None) -> ssl.SSLContext | None:
    """The client TLS context: a caller-supplied context wins (mTLS / pinning); else a default
    verifying context over `cafile` (an internal CA / self-signed cert). None → urllib's default
    (system roots) for https, ignored for http."""
    if ssl_context is not None:
        return ssl_context
    if cafile is not None:
        return ssl.create_default_context(cafile=str(cafile))
    return None


def guard_cleartext_secret(base_url: str, *, has_secret: bool, insecure: bool) -> None:
    """Refuse to put a bearer/cluster secret on a cleartext hop to a ROUTABLE host: `http://` + a
    non-loopback host + a configured secret = a token sniffable on the wire. Loopback http is fine;
    https is fine; `insecure=True` is the explicit opt-out for a TLS-terminating proxy / mesh."""
    if not has_secret or insecure:
        return
    parsed = urlparse(base_url)
    if parsed.scheme == "http" and not is_loopback(parsed.hostname or ""):
        raise ValueError(
            f"refusing to send a token to {base_url!r} over cleartext http — it would be sniffable on "
            "the wire; use an https:// URL (pass cafile= for an internal CA), or set insecure=True "
            "only if a TLS-terminating proxy already encrypts the hop")


class _SecureRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Don't let a 3xx redirect ferry a bearer/cluster secret onto a cleartext or cross-origin hop.
    urllib re-sends request headers (including `Authorization`) to a redirect target by default — even
    on an https→http downgrade — which would defeat the construction-time cleartext guard. So on every
    redirect: if a secret is attached, refuse a cleartext-routable target outright; and strip the
    sensitive headers whenever the origin (scheme, host, port) changes, so the secret never crosses to a
    different server than the one it was minted for."""

    @staticmethod
    def _origin(url: str) -> tuple:
        p = urlparse(url)
        return (p.scheme, p.hostname, p.port or _DEFAULT_PORTS.get(p.scheme))

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is None:
            return None
        carried = {k for k in req.headers if k.lower() in _SENSITIVE_HEADERS}
        if carried:
            guard_cleartext_secret(newurl, has_secret=True, insecure=False)  # raises on http-routable
        # Compare origins with default ports normalized, so https://h and https://h:443 are the SAME
        # origin (don't strip a legit same-server redirect that just adds/drops the explicit port).
        if self._origin(req.full_url) != self._origin(newurl):
            for k in carried:                       # cross-origin → never forward the secret
                new.headers.pop(k, None)
        return new


def build_opener(ssl_context: ssl.SSLContext | None) -> urllib.request.OpenerDirector:
    """A urllib opener that verifies TLS with `ssl_context` (None → system roots, verification ON),
    applies the secure-redirect policy above, and IGNORES ambient proxy env. Use this instead of the
    module-level `urlopen` so neither a redirect nor a proxy can leak a token.

    Proxy: these are internal cluster hops to a configured URL. urllib's default `ProxyHandler` honors
    `HTTP_PROXY`/`ALL_PROXY`, which for an http target (even loopback) ships `Authorization` to the
    proxy in CLEARTEXT — silently breaking "loopback never leaves the box". An empty `ProxyHandler({})`
    disables env proxies so the client connects directly to the URL it was given."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                       _SecureRedirectHandler,
                                       urllib.request.HTTPSHandler(context=ssl_context))


def send(opener: urllib.request.OpenerDirector, req: urllib.request.Request, *, base_url: str,
         has_secret: bool, insecure: bool, timeout: float):
    """Guard then open: re-checks the cleartext-secret policy on the LIVE token at request time (so a
    token set after construction can't skip it), then sends via the secure-redirect opener."""
    guard_cleartext_secret(base_url, has_secret=has_secret, insecure=insecure)
    return opener.open(req, timeout=timeout)
