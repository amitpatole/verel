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


def _read_existing_key(path: Path) -> bytes:
    """Read an existing key file SAFELY: never follow a symlink (O_NOFOLLOW) and refuse a file not
    owned by us or accessible to group/other. A planted key would fail OPEN (an attacker who knows
    the key forges signatures), so on any of these we raise → the caller falls back to an ephemeral
    key (which fails CLOSED). The key path is predictable, so trusting its contents blindly is unsafe."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        st = os.fstat(fd)
        if hasattr(os, "getuid") and (st.st_uid != os.getuid() or (st.st_mode & 0o077)):
            raise OSError(f"insecure signing-key file {path}: foreign owner or group/other-accessible")
        data = b""
        while chunk := os.read(fd, 4096):
            data += chunk
        return data
    finally:
        os.close(fd)


def load_or_create_keyfile(name: str, nbytes: int = 32) -> bytes:
    """Persist-or-read a random key of `nbytes` at `<config>/<name>.key`, hardened against symlink /
    chmod / planted-key attacks. Falls back to an ephemeral key (verify then fails CLOSED) if it can't
    be persisted securely. Shared by the HMAC signing secret and the ed25519 runner seed (§11)."""
    path = _config_dir() / f"{name}.key"
    try:
        if path.exists():
            return _read_existing_key(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        key = secrets.token_bytes(nbytes)
        try:
            # Atomic create-or-fail at mode 0600 from the start: O_EXCL refuses to follow/overwrite a
            # pre-existing file or symlink (no symlink attack, no chmod race), and a concurrent
            # first-run loser re-reads the winner's key instead of clobbering it.
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return _read_existing_key(path)
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
        return key
    except OSError:
        return secrets.token_bytes(nbytes)  # can't persist / insecure key → ephemeral (fails closed)


def load_secret(env_var: str, name: str) -> bytes:
    """Resolve a signing secret: env var > persisted per-installation key > ephemeral key."""
    configured = os.environ.get(env_var)
    if configured:
        return configured.encode()
    return load_or_create_keyfile(name)
