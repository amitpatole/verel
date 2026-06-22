"""Signing-secret resolution — NEVER ship a public default secret.

A hardcoded in-source default secret (the old `"verel-dev-*-secret"`) lets anyone who reads the
source forge a signature — collapsing every HMAC integrity guarantee (attested verdicts, signed
tools, signed registry artifacts). Instead:

* if the env var is set, use it (the way to share a key across machines / a trust domain);
* otherwise fall back to a **persistent, per-installation random key** under the user's config dir
  — zero-config, machine-local, and secret (an attacker can't read it from the source). This keeps
  single-machine sign→verify (incl. cross-process tool reuse) working out of the box;
* if the key can't be persisted (read-only fs), use an ephemeral per-process key — cross-process
  verification then fails closed, which is correct (you must configure a shared secret for that).

There is no code path that signs/verifies with a publicly-known value.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path


def _config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "verel"


def load_secret(env_var: str, name: str) -> bytes:
    """Resolve a signing secret: env var > persisted per-installation key > ephemeral key."""
    configured = os.environ.get(env_var)
    if configured:
        return configured.encode()
    path = _config_dir() / f"{name}.key"
    try:
        if path.exists():
            return path.read_bytes()
        path.parent.mkdir(parents=True, exist_ok=True)
        key = secrets.token_bytes(32)
        path.write_bytes(key)
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return key
    except OSError:
        return secrets.token_bytes(32)  # can't persist → ephemeral (cross-process verify fails closed)
