"""Fencing leases (§6.3 v3) — make CONCURRENT managers safe.

The v1 scheduler is single-writer, so split-brain can't happen. The moment more than one
scheduler can run over a shared task store, it can: a paused leader resumes and writes a verdict
for a task another leader already took over. The fix is the classic fencing token (Kleppmann):

- A lease on a `key` carries a **monotonic token**. Taking over an expired lease BUMPS the token;
  renewing by the same owner KEEPS it. The token therefore only ever increases per key.
- Every terminal write is **fenced**: the store accepts it only if the writer's token is the
  current (highest) one. A stale leader's write — token below the current — is rejected
  (`FencingError`), so it cannot corrupt shared state even if it believes it still leads.

`LeaseStore` is a Protocol with two backends: `InMemoryLeaseStore` (one process, many schedulers
— and the test vehicle) and `SqliteLeaseStore` (cross-process, real distribution; acquisition is
one atomic `BEGIN IMMEDIATE` transaction). Verel's value is the fencing discipline, not the store.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable


class FencingError(RuntimeError):
    """A write was attempted with a stale (non-current) fencing token."""


@dataclass(frozen=True)
class Lease:
    key: str
    owner: str
    token: int  # monotonic per key; the fencing token
    expires_at: float


@runtime_checkable
class LeaseStore(Protocol):
    def acquire(self, key: str, owner: str, *, now: float, ttl: float) -> Lease | None: ...
    def renew(self, lease: Lease, *, now: float, ttl: float) -> Lease | None: ...
    def release(self, lease: Lease) -> None: ...
    def current_token(self, key: str) -> int: ...
    def is_current(self, lease: Lease, *, now: float) -> bool: ...
    def complete(self, lease: Lease, state: str) -> None: ...
    def outcome(self, key: str) -> str | None: ...


class InMemoryLeaseStore:
    """Single-process fencing store — correct for many schedulers in one process, and the test
    vehicle. Per-key: the highest token ever issued, the active lease, and any terminal outcome."""

    def __init__(self) -> None:
        self._tokens: dict[str, int] = {}     # highest token issued per key (the fence line)
        self._held: dict[str, Lease] = {}      # active lease per key
        self._outcome: dict[str, str] = {}     # recorded terminal state per key

    def acquire(self, key: str, owner: str, *, now: float, ttl: float) -> Lease | None:
        cur = self._held.get(key)
        if cur is not None and now < cur.expires_at and cur.owner != owner:
            return None  # held by a live, different owner
        if cur is not None and cur.owner == owner and now < cur.expires_at:
            token = cur.token  # same owner re-acquiring its live lease keeps the token
        else:
            token = self._tokens.get(key, 0) + 1  # free / expired / takeover bumps the token
            self._tokens[key] = token
        lease = Lease(key, owner, token, now + ttl)
        self._held[key] = lease
        return lease

    def renew(self, lease: Lease, *, now: float, ttl: float) -> Lease | None:
        cur = self._held.get(lease.key)
        if cur is None or cur.token != lease.token:
            return None  # superseded — someone took over
        renewed = Lease(lease.key, lease.owner, lease.token, now + ttl)
        self._held[lease.key] = renewed
        return renewed

    def release(self, lease: Lease) -> None:
        cur = self._held.get(lease.key)
        if cur is not None and cur.token == lease.token:
            del self._held[lease.key]

    def current_token(self, key: str) -> int:
        return self._tokens.get(key, 0)

    def is_current(self, lease: Lease, *, now: float) -> bool:
        return lease.token == self._tokens.get(lease.key, 0)

    def complete(self, lease: Lease, state: str) -> None:
        if lease.token != self._tokens.get(lease.key, 0):
            raise FencingError(
                f"stale token for {lease.key!r}: {lease.token} < current "
                f"{self._tokens.get(lease.key, 0)} — write rejected")
        self._outcome[lease.key] = state
        self._held.pop(lease.key, None)

    def outcome(self, key: str) -> str | None:
        return self._outcome.get(key)


class SqliteLeaseStore:
    """Cross-process fencing store. Acquisition is a single `BEGIN IMMEDIATE` transaction so two
    processes cannot both take the same expired lease. Same fencing semantics as the in-memory
    store; pass a file path shared by every manager."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        with self._conn() as c:
            c.execute("""CREATE TABLE IF NOT EXISTS leases(
                key TEXT PRIMARY KEY, owner TEXT, token INTEGER, expires_at REAL,
                max_token INTEGER NOT NULL DEFAULT 0, outcome TEXT)""")

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        c.execute("PRAGMA busy_timeout=30000")
        return c

    def acquire(self, key: str, owner: str, *, now: float, ttl: float) -> Lease | None:
        with self._conn() as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute("SELECT owner, token, expires_at, max_token FROM leases WHERE key=?",
                            (key,)).fetchone()
            max_token = row[3] if row else 0
            if row is not None and now < row[2] and row[0] != owner:
                c.execute("COMMIT")
                return None  # live, different owner
            # same owner re-acquiring its live lease keeps the token; otherwise take a fresh one.
            renewing = row is not None and row[0] == owner and now < row[2]
            token = row[1] if renewing else max_token + 1
            c.execute("""INSERT INTO leases(key, owner, token, expires_at, max_token, outcome)
                         VALUES(?,?,?,?,?, (SELECT outcome FROM leases WHERE key=?))
                         ON CONFLICT(key) DO UPDATE SET
                           owner=excluded.owner, token=excluded.token,
                           expires_at=excluded.expires_at, max_token=excluded.max_token""",
                      (key, owner, token, now + ttl, max(max_token, token), key))
            c.execute("COMMIT")
            return Lease(key, owner, token, now + ttl)

    def renew(self, lease: Lease, *, now: float, ttl: float) -> Lease | None:
        with self._conn() as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute("SELECT token FROM leases WHERE key=?", (lease.key,)).fetchone()
            if row is None or row[0] != lease.token:
                c.execute("COMMIT")
                return None
            c.execute("UPDATE leases SET expires_at=? WHERE key=?", (now + ttl, lease.key))
            c.execute("COMMIT")
            return Lease(lease.key, lease.owner, lease.token, now + ttl)

    def release(self, lease: Lease) -> None:
        with self._conn() as c:
            c.execute("UPDATE leases SET expires_at=0 WHERE key=? AND token=?",
                      (lease.key, lease.token))

    def current_token(self, key: str) -> int:
        with self._conn() as c:
            row = c.execute("SELECT max_token FROM leases WHERE key=?", (key,)).fetchone()
            return row[0] if row else 0

    def is_current(self, lease: Lease, *, now: float) -> bool:
        return lease.token == self.current_token(lease.key)

    def complete(self, lease: Lease, state: str) -> None:
        with self._conn() as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute("SELECT max_token FROM leases WHERE key=?", (lease.key,)).fetchone()
            if row is None or lease.token != row[0]:
                c.execute("COMMIT")
                raise FencingError(f"stale token for {lease.key!r}: write rejected")
            c.execute("UPDATE leases SET outcome=? WHERE key=?", (state, lease.key))
            c.execute("COMMIT")

    def outcome(self, key: str) -> str | None:
        with self._conn() as c:
            row = c.execute("SELECT outcome FROM leases WHERE key=?", (key,)).fetchone()
            return row[0] if row and row[0] else None


def monotonic_now() -> float:
    return time.monotonic()
