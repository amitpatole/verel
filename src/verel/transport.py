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
from pathlib import Path
from urllib.parse import urlparse

# Hosts that never leave the machine — plain HTTP and no token are fine (the zero-config dev roundtrip).
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", ""})


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
