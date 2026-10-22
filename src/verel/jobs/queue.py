"""Durable job queue on SQLite (WAL). One file, many worker processes, crash-safe.

Delivery is AT LEAST ONCE with fencing: every claim bumps `attempts`, and `complete` / `fail` /
`heartbeat` only succeed for the exact (owner, attempts) that holds the lease, so a worker that stalled
past its lease and woke up after another worker took over cannot overwrite the newer attempt's result.
Handlers must therefore be idempotent (`dedupe_key` makes ENQUEUE idempotent per tenant).

Failure policy: a failed job is retried with capped exponential backoff until `max_attempts`, then moves
to `dead` (kept for inspection, never silently dropped). A job whose lease expires (worker crash) is
re-queued by the next claim and counts as an attempt.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_PAYLOAD = 256 * 1024
MAX_ERROR = 500
MAX_ATTEMPTS_CAP = 20
BACKOFF_BASE_S = 5.0
BACKOFF_CAP_S = 3600.0
STATES = ("queued", "running", "done", "dead")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs(
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL,
  state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL,
  run_after REAL NOT NULL, lease_owner TEXT, lease_expires REAL, result TEXT, error TEXT,
  dedupe_key TEXT, created REAL NOT NULL, updated REAL NOT NULL, by_principal TEXT NOT NULL DEFAULT '');
CREATE UNIQUE INDEX IF NOT EXISTS jobs_dedupe ON jobs(tenant, dedupe_key) WHERE dedupe_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS jobs_claim ON jobs(state, run_after);
CREATE INDEX IF NOT EXISTS jobs_tenant ON jobs(tenant, state);
"""


@dataclass(frozen=True)
class Job:
    id: str
    tenant: str
    kind: str
    payload: dict[str, Any]
    attempts: int
    max_attempts: int
    lease_owner: str = ""
    lease_expires: float = 0.0
    by: str = (
        ""  # the principal that enqueued it ("" for internal/CLI jobs); decisions are attributed to them
    )


class QuotaExceeded(RuntimeError):
    """The tenant already has too many pending jobs (queued or running)."""


DEFAULT_MAX_PENDING = 5000
DEFAULT_MAX_ROWS = 20_000  # stored rows (every state) per TENANT; bounds each tenant's share of the file
INTERNAL_KEY_PREFIX = "internal:"  # reserved for keys the workers create; a requester cannot squat them
MAX_PAYLOAD_DEPTH = 16


def _too_deep(o: Any) -> bool:
    stack = [(o, 0)]
    while stack:
        cur, d = stack.pop()
        if d > MAX_PAYLOAD_DEPTH:
            return True
        if isinstance(cur, dict):
            stack.extend((v, d + 1) for v in cur.values())
        elif isinstance(cur, list):
            stack.extend((v, d + 1) for v in cur)
    return False


class LeaseLost(RuntimeError):
    """The caller no longer holds this job's lease (it expired and another worker took over)."""


def backoff(attempts: int) -> float:
    return min(BACKOFF_CAP_S, BACKOFF_BASE_S * (2 ** max(0, attempts - 1)))


class JobQueue:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._local = threading.local()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        c = sqlite3.connect(self.path, timeout=30)
        try:
            c.execute("PRAGMA journal_mode=WAL")
            c.executescript(_SCHEMA)
            cols = {row[1] for row in c.execute("PRAGMA table_info(jobs)")}
            if "by_principal" not in cols:  # a queue file created before decisions were attributed
                c.execute("ALTER TABLE jobs ADD COLUMN by_principal TEXT NOT NULL DEFAULT ''")
        finally:
            c.close()
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def _conn(self) -> sqlite3.Connection:
        """One long-lived connection per thread. Opening and closing a connection per operation made every
        close() checkpoint the WAL (a disk sync, ~30 ms), which dominated the cost of a queue operation."""
        c = getattr(self._local, "c", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            # WAL is a persistent database property set once in __init__. synchronous=NORMAL is crash-safe
            # for the application (the database never corrupts); only a power loss can drop the last few
            # commits, and handlers are idempotent. VEREL_JOBS_SYNC=full restores a sync per commit.
            full = os.environ.get("VEREL_JOBS_SYNC") == "full"
            c.execute("PRAGMA synchronous=" + ("FULL" if full else "NORMAL"))
            c.execute("PRAGMA busy_timeout=30000")
            self._local.c = c
        return c

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        c = self._conn()
        try:
            c.execute("BEGIN IMMEDIATE")
            yield c
            c.execute("COMMIT")
        except BaseException:
            try:
                c.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise

    def close(self) -> None:
        c = getattr(self._local, "c", None)
        if c is not None:
            c.close()
            self._local.c = None

    # -- producers --------------------------------------------------------------------------------
    def enqueue(
        self,
        tenant: str,
        kind: str,
        payload: dict[str, Any],
        *,
        dedupe_key: str | None = None,
        max_attempts: int = 3,
        delay_s: float = 0.0,
        now: float | None = None,
        internal: bool = False,
        by: str = "",
    ) -> str:
        """Add a job; returns its id. Re-enqueueing the same `dedupe_key` returns the ORIGINAL id.
        Raises `QuotaExceeded` when the tenant has `VEREL_JOBS_MAX_PENDING` (default 5000) jobs pending;
        `internal=True` (worker-created follow-up jobs) is exempt, so a full queue can still emit webhooks."""
        if not kind or len(kind) > 64 or not kind.replace("_", "").replace("-", "").isalnum():
            raise ValueError("bad job kind")
        if dedupe_key is not None and (not dedupe_key or len(dedupe_key) > 256):
            raise ValueError("bad dedupe_key")
        if dedupe_key is not None and dedupe_key.startswith(INTERNAL_KEY_PREFIX) and not internal:
            raise ValueError(f"dedupe keys starting with {INTERNAL_KEY_PREFIX!r} are reserved")
        if _too_deep(payload):
            raise ValueError("payload nested too deeply")
        body = json.dumps(payload, separators=(",", ":"))
        if len(body) > MAX_PAYLOAD:
            raise ValueError(f"payload exceeds {MAX_PAYLOAD} bytes")
        max_attempts = max(1, min(int(max_attempts), MAX_ATTEMPTS_CAP))
        t = time.time() if now is None else now
        jid = uuid.uuid4().hex
        with self._tx() as c:
            if dedupe_key is not None:
                row = c.execute(
                    "SELECT id FROM jobs WHERE tenant=? AND dedupe_key=?", (tenant, dedupe_key)
                ).fetchone()
                if row:
                    return str(row[0])
            if not internal:
                limit = int(os.environ.get("VEREL_JOBS_MAX_PENDING", DEFAULT_MAX_PENDING))
                pending = c.execute(
                    "SELECT COUNT(*) FROM jobs WHERE tenant=? AND state IN ('queued','running')", (tenant,)
                ).fetchone()[0]
                if pending >= limit:
                    raise QuotaExceeded(f"tenant has {pending} pending jobs (limit {limit})")
                cap = int(os.environ.get("VEREL_JOBS_MAX_ROWS", DEFAULT_MAX_ROWS))
                rows = c.execute("SELECT COUNT(*) FROM jobs WHERE tenant=?", (tenant,)).fetchone()[0]
                if rows >= cap:
                    # Finished history is what fills the cap. Drop this tenant's oldest FINISHED jobs (never
                    # queued or running ones) before refusing, so a busy tenant cannot lock itself out.
                    c.execute(
                        "DELETE FROM jobs WHERE id IN (SELECT id FROM jobs WHERE tenant=? AND state IN "
                        "('done','dead') AND updated<? ORDER BY updated LIMIT ?)",
                        (tenant, t - 60, max(1, cap // 10)),
                    )
                    rows = c.execute("SELECT COUNT(*) FROM jobs WHERE tenant=?", (tenant,)).fetchone()[0]
                if rows >= cap:
                    # per TENANT: one tenant filling its own history must not lock the others out
                    raise QuotaExceeded(
                        f"this tenant has {rows} stored jobs; finished jobs are purged over time"
                    )
            c.execute(
                "INSERT INTO jobs(id,tenant,kind,payload,state,max_attempts,run_after,dedupe_key,"
                "created,updated,by_principal)"
                " VALUES(?,?,?,?, 'queued',?,?,?,?,?,?)",
                (jid, tenant, kind, body, max_attempts, t + max(0.0, delay_s), dedupe_key, t, t, by[:128]),
            )
        return jid

    # -- consumers --------------------------------------------------------------------------------
    def claim(
        self, worker: str, kinds: list[str], *, lease_s: float = 60.0, now: float | None = None
    ) -> Job | None:
        """Atomically take the oldest runnable job of one of `kinds`. Expired leases are reaped first: a
        crashed worker's job is re-queued (or moved to `dead` once its attempts are used up)."""
        if not kinds:
            return None
        t = time.time() if now is None else now
        marks = ",".join("?" for _ in kinds)
        with self._tx() as c:
            c.execute(
                "UPDATE jobs SET state='dead', error='lease expired; attempts exhausted', updated=?, "
                "lease_owner=NULL WHERE state='running' AND lease_expires<? AND attempts>=max_attempts",
                (t, t),
            )
            c.execute(
                "UPDATE jobs SET state='queued', lease_owner=NULL, updated=? "
                "WHERE state='running' AND lease_expires<? AND attempts<max_attempts",
                (t, t),
            )
            row = c.execute(
                "SELECT id,tenant,kind,payload,attempts,max_attempts,by_principal FROM jobs "  # nosec B608
                f"WHERE state='queued' "
                f"AND run_after<=? AND kind IN ({marks}) "
                "ORDER BY (SELECT COUNT(*) FROM jobs r WHERE r.tenant=jobs.tenant AND r.state='running'), "
                "run_after, created LIMIT 1",
                (t, *kinds),
            ).fetchone()
            if row is None:
                return None
            attempts = int(row[4]) + 1
            c.execute(
                "UPDATE jobs SET state='running', attempts=?, lease_owner=?, lease_expires=?, "
                "updated=? WHERE id=?",
                (attempts, worker, t + lease_s, t, row[0]),
            )
            return Job(
                row[0],
                row[1],
                row[2],
                json.loads(row[3]),
                attempts,
                int(row[5]),
                worker,
                t + lease_s,
                str(row[6]),
            )

    def _fenced(self, c: sqlite3.Connection, job: Job) -> None:
        r = c.execute("SELECT state,lease_owner,attempts FROM jobs WHERE id=?", (job.id,)).fetchone()
        if r is None or r[0] != "running" or r[1] != job.lease_owner or int(r[2]) != job.attempts:
            raise LeaseLost(job.id)

    def heartbeat(self, job: Job, *, lease_s: float = 60.0, now: float | None = None) -> None:
        t = time.time() if now is None else now
        with self._tx() as c:
            self._fenced(c, job)
            c.execute("UPDATE jobs SET lease_expires=?, updated=? WHERE id=?", (t + lease_s, t, job.id))

    def complete(self, job: Job, result: dict[str, Any] | None = None, *, now: float | None = None) -> None:
        t = time.time() if now is None else now
        with self._tx() as c:
            self._fenced(c, job)
            c.execute(
                "UPDATE jobs SET state='done', payload='{}', result=?, error=NULL, "
                "lease_owner=NULL, updated=? WHERE id=?",
                (json.dumps(result or {})[:MAX_PAYLOAD], t, job.id),
            )

    def fail(self, job: Job, error: str, *, permanent: bool = False, now: float | None = None) -> str:
        """Record a failure. Returns the new state: `queued` (will retry) or `dead`."""
        t = time.time() if now is None else now
        dead = permanent or job.attempts >= job.max_attempts
        with self._tx() as c:
            self._fenced(c, job)
            c.execute(
                "UPDATE jobs SET state=?, error=?, lease_owner=NULL, run_after=?, updated=?, "
                "payload=CASE WHEN ?=1 THEN '{}' ELSE payload END WHERE id=?",
                (
                    "dead" if dead else "queued",
                    error[:MAX_ERROR],
                    t + backoff(job.attempts),
                    t,
                    1 if dead else 0,
                    job.id,
                ),
            )  # a dead job keeps its error but not its (up to 256 KB) payload
        return "dead" if dead else "queued"

    # -- inspection -------------------------------------------------------------------------------
    def get(self, tenant: str, job_id: str) -> dict[str, Any] | None:
        """One job, scoped to its tenant (another tenant's id looks like a missing id)."""
        with self._tx() as c:
            r = c.execute(
                "SELECT id,kind,state,attempts,max_attempts,result,error,created,updated FROM jobs "
                "WHERE id=? AND tenant=?",
                (job_id, tenant),
            ).fetchone()
        if r is None:
            return None
        return {
            "id": r[0],
            "kind": r[1],
            "state": r[2],
            "attempts": r[3],
            "max_attempts": r[4],
            "result": json.loads(r[5]) if r[5] else None,
            "error": r[6],
            "created": r[7],
            "updated": r[8],
        }

    def purge(self, older_than_s: float, *, now: float | None = None) -> int:
        """Delete done and dead jobs untouched for older_than_s seconds (retention); returns the count."""
        t = time.time() if now is None else now
        with self._tx() as c:
            cur = c.execute(
                "DELETE FROM jobs WHERE state IN ('done','dead') AND updated<?", (t - max(0.0, older_than_s),)
            )
            return int(cur.rowcount)

    def stats(self, tenant: str | None = None) -> dict[str, int]:
        with self._tx() as c:
            rows = (
                c.execute("SELECT state,COUNT(*) FROM jobs WHERE tenant=? GROUP BY state", (tenant,))
                if tenant is not None
                else c.execute("SELECT state,COUNT(*) FROM jobs GROUP BY state")
            ).fetchall()
        out = dict.fromkeys(STATES, 0)
        out.update({s: int(n) for s, n in rows})
        return out
