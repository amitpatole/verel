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

import re
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
                         ssl_context: ssl.SSLContext | None,
                         *, client_ca: str | Path | None = None) -> ssl.SSLContext | None:
    """The server-side TLS context: a ready context wins, else a default one loaded from cert/key.
    None → plaintext (only allowed on loopback per `enforce_bind_policy`).

    `client_ca` turns on **mTLS**: the server then REQUIRES every client to present a certificate signed
    by that CA (`CERT_REQUIRED`) — transport-layer client authentication on top of the bearer/signature
    layers. mTLS needs the server to also present its own cert (certfile/ssl_context)."""
    if ssl_context is not None:
        ctx = ssl_context
    elif certfile is not None:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(certfile=str(certfile),
                            keyfile=str(keyfile) if keyfile is not None else None)
    else:
        if client_ca is not None:
            raise ValueError("client_ca (mTLS) requires the server to present a cert too "
                             "(pass certfile=/keyfile= or ssl_context=)")
        return None
    if client_ca is not None:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=str(client_ca))
    return ctx


def enforce_bind_policy(host: str, *, auth_token: str | None, tls: bool, service: str) -> None:
    """Fail closed on a routable bind: it must be BOTH authenticated AND encrypted. Loopback is exempt
    (never leaves the box). `service` names the surface in the error (e.g. 'memory service')."""
    if is_loopback(host):
        return
    # An EMPTY/whitespace token is "no auth", not "auth" — else a blank `VEREL_*_TOKEN=` misconfig
    # would bind a routable surface that authenticates an empty `Authorization: Bearer ` (fail-open).
    if not (auth_token and auth_token.strip()):
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
                 max_connections: int = _DEFAULT_MAX_CONNECTIONS, max_per_ip: int | None = None):
        if max_connections < 1:
            # a non-positive cap would silently drop EVERY connection (look like a total hang) — reject
            # the misconfiguration with a clear error instead.
            raise ValueError(f"max_connections must be >= 1, got {max_connections}")
        if max_per_ip is not None and max_per_ip < 1:
            raise ValueError(f"max_per_ip must be >= 1 or None, got {max_per_ip}")
        self._ssl_context = ssl_context
        self._slots = threading.BoundedSemaphore(max_connections)
        # Per-source-IP fairness: cap how many of the global slots ONE source can hold, so a single
        # routable peer can't monopolize the whole server (the global cap alone permits that). Off by
        # default (None) — all loopback traffic shares 127.0.0.1, so a per-IP cap there would throttle
        # legit local concurrency; it's meant for routable/exposed binds.
        self._max_per_ip = max_per_ip
        self._per_ip: dict[str, int] = {}
        self._per_ip_lock = threading.Lock()
        super().__init__(server_address, handler_class)

    def get_request(self):
        sock, addr = super().get_request()
        if self._ssl_context is not None:
            sock = self._ssl_context.wrap_socket(sock, server_side=True,
                                                  do_handshake_on_connect=False)
        return sock, addr

    def _admit_ip(self, ip: str) -> bool:
        if self._max_per_ip is None:
            return True
        with self._per_ip_lock:
            if self._per_ip.get(ip, 0) >= self._max_per_ip:
                return False
            self._per_ip[ip] = self._per_ip.get(ip, 0) + 1
            return True

    def _release_ip(self, ip: str) -> None:
        if self._max_per_ip is None:
            return
        with self._per_ip_lock:
            n = self._per_ip.get(ip, 0) - 1
            if n <= 0:
                self._per_ip.pop(ip, None)
            else:
                self._per_ip[ip] = n

    def process_request(self, request, client_address):
        # Acquire a global slot in the ACCEPT thread (before spawning a worker). Over the cap → drop now,
        # so a flood can't park more than `max_connections` threads. close_request (not shutdown_request)
        # avoids releasing a slot we never took.
        if not self._slots.acquire(blocking=False):
            self.close_request(request)
            return
        ip = client_address[0] if client_address else ""
        if not self._admit_ip(ip):           # this source already holds its per-IP share → drop
            self._slots.release()
            self.close_request(request)
            return
        try:
            super().process_request(request, client_address)   # spawns the worker thread
        except BaseException:
            self._release_ip(ip)
            self._slots.release()   # the worker never started → release what we just took
            raise

    def process_request_thread(self, request, client_address):
        # Release is paired HERE (worker thread), not in shutdown_request: shutdown_request also runs on
        # the verify_request()==False path where process_request never acquired, which would over-release
        # the BoundedSemaphore. Pairing acquire(process_request)/release(here) is balanced on every path:
        # accepted+spawned → released here; over-cap drop → never acquired; spawn failure → released above.
        ip = client_address[0] if client_address else ""
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._release_ip(ip)
            self._slots.release()


def make_client_context(cafile: str | Path | None, ssl_context: ssl.SSLContext | None,
                        *, client_cert: str | Path | None = None,
                        client_key: str | Path | None = None) -> ssl.SSLContext | None:
    """The client TLS context: a caller-supplied context wins; else a default verifying context over
    `cafile` (an internal CA / self-signed cert), or system roots. `client_cert`/`client_key` present a
    CLIENT certificate for mTLS (a server with `client_ca=` requires it). None → urllib's default
    (system roots) for https, ignored for http."""
    if ssl_context is not None:
        return ssl_context
    if cafile is not None:
        ctx = ssl.create_default_context(cafile=str(cafile))
    elif client_cert is not None:
        ctx = ssl.create_default_context()   # system roots for server verify; we add the client cert
    else:
        return None
    if client_cert is not None:
        ctx.load_cert_chain(certfile=str(client_cert),
                            keyfile=str(client_key) if client_key is not None else None)
    return ctx


def cert_sha256(certfile: str | Path) -> str:
    """The sha256 hex digest of a certificate's DER encoding — the value to pin via `pin_sha256=`.
    (Reads the leaf cert from a PEM file.)"""
    import hashlib

    try:
        pem = Path(certfile).read_text()
    except UnicodeDecodeError as e:
        raise ValueError(f"{certfile} is not a PEM certificate (expected text, got binary) — "
                         "pass a PEM file") from e
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha256(der).hexdigest()


_HEX64 = re.compile(r"[0-9a-f]{64}")


def _normalize_fp(fp: str) -> str:
    # drop ALL whitespace (spaces, tabs, newlines) + colons, lowercase — tolerant of openssl's
    # AA:BB:.. formatting and stray copy-paste whitespace.
    return "".join(fp.split()).replace(":", "").lower()


def _validated_fp(fp: str) -> str:
    """Normalize and REQUIRE a full sha256 (64 hex chars). A malformed/empty pin must fail LOUD at
    build time — never become a silent never-match (a typo'd pin) or an empty-string fail-open primitive."""
    norm = _normalize_fp(fp)
    if not _HEX64.fullmatch(norm):
        raise ValueError(f"invalid sha256 pin {fp!r} — expected 64 hex chars (see transport.cert_sha256)")
    return norm


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


def _pinning_https_handler(ssl_context: ssl.SSLContext | None,
                           pins: frozenset) -> urllib.request.HTTPSHandler:
    """An HTTPSHandler whose connections additionally pin the server's leaf certificate by sha256 — so a
    cert from a DIFFERENT (even validly-CA-signed) key is rejected, defeating a mis-issued/compromised
    CA. Additive to normal CA/hostname verification (which still runs via `ssl_context`)."""
    import hashlib
    import http.client

    class _PinnedConn(http.client.HTTPSConnection):
        def connect(self):
            super().connect()
            der = self.sock.getpeercert(binary_form=True)
            fp = hashlib.sha256(der).hexdigest() if der else ""
            if fp not in pins:
                self.close()
                raise ssl.SSLCertVerificationError(
                    f"server certificate pin mismatch (sha256 {fp or 'unavailable'} not in pinned set)")

    class _Handler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(_PinnedConn, req, context=ssl_context)

    return _Handler()


def build_opener(ssl_context: ssl.SSLContext | None,
                 *, pin_sha256: str | list | set | frozenset | None = None
                 ) -> urllib.request.OpenerDirector:
    """A urllib opener that verifies TLS with `ssl_context` (None → system roots, verification ON),
    applies the secure-redirect policy above, and IGNORES ambient proxy env. Use this instead of the
    module-level `urlopen` so neither a redirect nor a proxy can leak a token.

    `pin_sha256` (a hex digest or an iterable of them; see `cert_sha256`) additionally PINS the server's
    leaf certificate — a cert outside the pinned set is rejected even if a trusted CA signed it.

    Proxy: these are internal cluster hops to a configured URL. urllib's default `ProxyHandler` honors
    `HTTP_PROXY`/`ALL_PROXY`, which for an http target (even loopback) ships `Authorization` to the
    proxy in CLEARTEXT — silently breaking "loopback never leaves the box". An empty `ProxyHandler({})`
    disables env proxies so the client connects directly to the URL it was given."""
    if pin_sha256 is not None:
        raw = [pin_sha256] if isinstance(pin_sha256, str) else list(pin_sha256)
        pins = frozenset(_validated_fp(p) for p in raw)
        if not pins:
            raise ValueError("pin_sha256 is empty — pass at least one sha256 fingerprint, or None")
        https: urllib.request.HTTPSHandler = _pinning_https_handler(ssl_context, pins)
    else:
        https = urllib.request.HTTPSHandler(context=ssl_context)
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _SecureRedirectHandler, https)


def client_opener(cafile: str | Path | None = None, ssl_context: ssl.SSLContext | None = None, *,
                  client_cert: str | Path | None = None, client_key: str | Path | None = None,
                  pin_sha256: str | list | set | frozenset | None = None
                  ) -> urllib.request.OpenerDirector:
    """The one opener every remote client builds: redirect-safe + proxy-ignoring, with the client TLS
    context (`cafile` server-CA / `client_cert`+`client_key` for mTLS) and optional `pin_sha256`."""
    ctx = make_client_context(cafile, ssl_context, client_cert=client_cert, client_key=client_key)
    return build_opener(ctx, pin_sha256=pin_sha256)


def send(opener: urllib.request.OpenerDirector, req: urllib.request.Request, *, base_url: str,
         has_secret: bool, insecure: bool, timeout: float):
    """Guard then open: re-checks the cleartext-secret policy on the LIVE token at request time (so a
    token set after construction can't skip it), then sends via the secure-redirect opener."""
    guard_cleartext_secret(base_url, has_secret=has_secret, insecure=insecure)
    return opener.open(req, timeout=timeout)
