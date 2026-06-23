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
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

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

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is None:
            return None
        carried = {k for k in req.headers if k.lower() in _SENSITIVE_HEADERS}
        if carried:
            guard_cleartext_secret(newurl, has_secret=True, insecure=False)  # raises on http-routable
        old, dst = urlparse(req.full_url), urlparse(newurl)
        if (old.scheme, old.hostname, old.port) != (dst.scheme, dst.hostname, dst.port):
            for k in carried:                       # cross-origin → never forward the secret
                new.headers.pop(k, None)
        return new


def build_opener(ssl_context: ssl.SSLContext | None) -> urllib.request.OpenerDirector:
    """A urllib opener that verifies TLS with `ssl_context` (None → system roots, verification ON) and
    applies the secure-redirect policy above. Use this instead of the module-level `urlopen` so the
    redirect path can't leak a token."""
    return urllib.request.build_opener(_SecureRedirectHandler,
                                       urllib.request.HTTPSHandler(context=ssl_context))


def send(opener: urllib.request.OpenerDirector, req: urllib.request.Request, *, base_url: str,
         has_secret: bool, insecure: bool, timeout: float):
    """Guard then open: re-checks the cleartext-secret policy on the LIVE token at request time (so a
    token set after construction can't skip it), then sends via the secure-redirect opener."""
    guard_cleartext_secret(base_url, has_secret=has_secret, insecure=insecure)
    return opener.open(req, timeout=timeout)
