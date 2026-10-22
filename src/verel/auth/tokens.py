"""Hashed bearer tokens. The server stores only SHA-256 digests of high-entropy random tokens (never the
token), compares in constant time across ALL entries, honours expiry, and hot-reloads the file so a
revocation takes effect on the next request."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from .rbac import Principal, parse_role, valid_tenant

PREFIX = "vrl_"
MAX_TOKEN_LEN = 128
MAX_ENTRIES = 10_000
_ID_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-@")


def generate_token() -> str:
    return PREFIX + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass(frozen=True)
class Entry:
    id: str
    role: str
    tenant: str
    sha256: str
    expires: dt.date | None = None


def _check_mode(path: Path) -> None:
    st = path.stat()
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError(f"{path}: token file must not be group/world writable")


def _parse(data: object) -> list[Entry]:
    if not isinstance(data, dict) or data.get("version") != 1 \
            or not isinstance(data.get("tokens"), list):
        raise ValueError('token file must be {"version": 1, "tokens": [...]}')
    toks = data["tokens"]
    if len(toks) > MAX_ENTRIES:
        raise ValueError("too many token entries")
    out: list[Entry] = []
    seen: set[str] = set()
    for t in toks:
        if not isinstance(t, dict):
            raise ValueError("each token entry must be an object")
        tid = str(t.get("id", ""))
        if not tid or len(tid) > 128 or not set(tid) <= _ID_OK:
            raise ValueError(f"bad token id {tid!r}")
        if tid in seen:
            raise ValueError(f"duplicate token id {tid!r}")
        seen.add(tid)
        digest = str(t.get("sha256", "")).lower()
        if len(digest) != 64 or set(digest) - set("0123456789abcdef"):
            raise ValueError(f"{tid}: sha256 must be 64 hex chars")
        exp = t.get("expires")
        try:
            expires = None if exp is None else dt.date.fromisoformat(str(exp))
        except ValueError:
            raise ValueError(f"{tid}: expires must be an ISO date") from None
        role, tenant = parse_role(t.get("role")).value, valid_tenant(t.get("tenant"))
        out.append(Entry(tid, role, tenant, digest, expires))
    return out


class TokenStore:
    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self._sig: tuple[int, ...] | None = None
        self._entries: list[Entry] = []
        self._load()

    def _load(self) -> None:
        _check_mode(self.path)
        st = self.path.stat()
        self._entries = _parse(json.loads(self.path.read_text(encoding="utf-8")))
        self._sig = self._signature(st)

    @staticmethod
    def _signature(st: os.stat_result) -> tuple[int, ...]:
        # ino and mode too: a file swapped in place or chmod'ed after startup must be noticed
        return (st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns)

    def _refresh(self) -> None:
        try:
            st = self.path.stat()
            if self._signature(st) != self._sig:
                self._load()
        except (OSError, ValueError):
            # unreadable/invalid file: deny everyone (fail closed), keep no stale grants, and forget the
            # signature so the NEXT request retries (a restored file with identical metadata must recover)
            self._entries = []
            self._sig = None

    def authenticate(self, token: str, today: dt.date | None = None) -> Principal | None:
        if not isinstance(token, str) or not token.startswith(PREFIX) or len(token) > MAX_TOKEN_LEN:
            return None
        self._refresh()
        digest = hash_token(token)
        today = today or dt.datetime.now(dt.timezone.utc).date()
        hit: Entry | None = None
        for e in self._entries:  # no early exit: timing doesn't reveal which entry matched
            if hmac.compare_digest(e.sha256, digest):
                hit = e
        if hit is None or (hit.expires is not None and hit.expires < today):
            return None
        return Principal(hit.id, parse_role(hit.role), hit.tenant, "token")


# -- management (CLI) ---------------------------------------------------------------------------------
def _read_raw(path: Path) -> dict:
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        _parse(data)
        return data
    return {"version": 1, "tokens": []}


def _write(path: Path, data: dict) -> None:
    from .._chainlog import _write_atomic

    _write_atomic(path, json.dumps(data, indent=2))  # exclusive unique temp file


def add_token(path: str | os.PathLike[str], *, id: str, role: str, tenant: str,
              expires: str | None = None) -> str:
    """Create a token entry and return the SECRET (shown once; only its hash is stored)."""
    p = Path(path)
    data = _read_raw(p)
    token = generate_token()
    entry = {"id": id, "role": parse_role(role).value, "tenant": valid_tenant(tenant),
             "sha256": hash_token(token), **({"expires": expires} if expires else {})}
    data["tokens"].append(entry)
    _parse(data)  # re-validate (duplicate id, bad expiry…) before writing
    _write(p, data)
    return token


def revoke_token(path: str | os.PathLike[str], id: str) -> bool:
    p = Path(path)
    data = _read_raw(p)
    before = len(data["tokens"])
    data["tokens"] = [t for t in data["tokens"] if t.get("id") != id]
    if len(data["tokens"]) == before:
        return False
    _write(p, data)
    return True


def list_tokens(path: str | os.PathLike[str]) -> list[dict]:
    return [{k: v for k, v in t.items() if k != "sha256"} for t in _read_raw(Path(path))["tokens"]]
