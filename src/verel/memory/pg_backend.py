"""PostgresMemory — a Postgres/pgvector `MemoryView` (the external multi-machine brain backend).

The flagship external store: many agents on different machines write directly to ONE Postgres, so —
unlike the single-process `LocalMemory` — the trust-layer's read-modify-write rules must stay correct
under concurrent writers. Every mutator runs inside a transaction under a **per-key advisory lock**
(`pg_advisory_xact_lock`), so two agents asserting the same `(subject,predicate,scope)` serialize and
the interference rule (corroborate / supersede) never loses an update. `decay()` is **set-based** SQL
(atomic per-row decay + a predicate-re-checked prune) so the librarian pass can't clobber a concurrent
write. Recall pushes the scope/kind/trust filter into SQL and (with an embedder) orders by the pgvector
`<=>` distance, then applies Verel's documented `rank()` in Python — the store provides relevance,
Verel owns the ranking.

Security (a networked store with credentials):
- parameterized queries only (constant column list, all values bound);
- the DSN/password is **scrubbed from every error** (URL-userinfo *and* keyword forms), and EVERY db
  method rolls back + scrubs on failure so one error can't strand the shared connection in an aborted
  transaction;
- a **routable host requires validating TLS** — the effective target is resolved the way libpq will
  actually connect (`host`/`hostaddr`, comma-lists, and `PGHOST`/`PGHOSTADDR`/`PGSSLMODE` env), so the
  guard cannot be bypassed by a conninfo shape or an env override (fail closed);
- a statement timeout bounds every query, and recall's candidate scan is capped.

Requires **Postgres 16+** (the set-based decay uses the `IS JSON` predicate for a total, abort-proof
read of lifecycle flags) with the **pgvector** extension. `pip install verel[postgres]`. Config:
`VEREL_POSTGRES_URL`/`VEREL_POSTGRES_DSN`, `VEREL_PG_SSLMODE`, `VEREL_PG_CACERT`, `VEREL_EMBEDDER`.
"""

from __future__ import annotations

import json
import logging
import os
import re
from contextlib import contextmanager

from ..transport import is_loopback
from .view import (
    PRUNE_EC,
    PRUNE_RS,
    PRUNE_SUPPORT,
    STALE_AFTER_S,
    VOLATILE_TTL_S,
    MemoryKind,
    MemoryRecord,
    MemoryView,
    Trust,
    make_id,
    make_key,
    rank,
)
from .view import (
    relevance as _relevance,
)

_log = logging.getLogger("verel.memory.pg")

_COLS = ("id", "kind", "subject", "predicate", "text", "scope", "subj_pred_key", "source",
         "provenance", "trust", "epistemic_confidence", "retrieval_strength", "support_count",
         "created_ts", "last_recall_ts", "detail_json")
_COLS_SQL = ", ".join(_COLS)  # constant column list — never built from user input (keeps bandit B608 green)

_RECALL_SCAN_CAP = 5000   # bound the no-embedder candidate scan so a huge brain can't OOM the client
_MAX_RECALL_K = 1000      # clamp caller-supplied k so an unbounded LIMIT can't OOM the client
_MAX_CHAIN = 50           # bound the supersession correction-chain so a hot key can't inflate one row
_VALIDATING_TLS = ("verify-full", "verify-ca")

# jsonb views of the opaque detail_json TEXT, for the set-based decay. Every expression is TOTAL —
# it can NEVER raise on a malformed/non-canonical value (which would abort the whole librarian pass
# on one poisoned replicated row). Defense in depth with ingress canonicalization (_canonical_detail):
#  - _DETAIL is '{}' unless detail_json IS a JSON OBJECT (so a scalar/array/garbage row degrades, never
#    casts-and-aborts; pg16 `IS JSON OBJECT`);
#  - flags use exact jsonb equality (no `::boolean` cast on free-form text);
#  - ttl is read only when it is genuinely a JSON number (no `::float` cast on a non-numeric value).
_RAW = "COALESCE(NULLIF(detail_json, ''), '{}')"
_DETAIL = f"(CASE WHEN {_RAW} IS JSON OBJECT THEN {_RAW} ELSE '{{}}' END)::jsonb"
_PINNED = f"COALESCE({_DETAIL}->'pinned' = 'true'::jsonb, false)"
_VOLATILE = f"COALESCE({_DETAIL}->'volatile' = 'true'::jsonb, false)"
_TTL = (f"(CASE WHEN jsonb_typeof({_DETAIL}->'ttl_s') = 'number' "
        f"THEN ({_DETAIL}->>'ttl_s')::float ELSE NULL END)")
_REF = "(CASE WHEN last_recall_ts > 0 THEN last_recall_ts ELSE created_ts END)"


def _scrub(exc: Exception, dsn: str) -> str:
    """An error message with the DSN and ANY password removed — psycopg/libpq errors echo the
    connection string verbatim. Redacts the whole DSN if present, plus URL-userinfo (`://u:PASS@`)
    and keyword (`password=…`, quoted or not) forms, so a credential never reaches a log or caller."""
    msg = str(exc)
    if dsn and dsn in msg:
        msg = msg.replace(dsn, "<dsn>")
    msg = re.sub(r"(://[^:/@\s]+:)[^@\s]+(@)", r"\1<redacted>\2", msg)       # URL userinfo password
    msg = re.sub(r"(password\s*=\s*)('(?:[^']|'')*'|\S+)", r"\1<redacted>", msg)  # keyword, quoted/not
    return msg


def _routable_hosts(dsn: str) -> list[str]:
    """Every host the connection could actually target — resolved the way libpq will, NOT by regex.

    Covers `host`/`hostaddr`, comma-separated host lists, AND the `PGHOST`/`PGHOSTADDR` env defaults
    libpq applies when the DSN omits them. Returns [] only for a genuinely local target (unix socket /
    no host), where skipping the TLS guard is correct. Fail-closed: an unparseable DSN yields [] and
    the connection then fails (and is scrubbed) at connect time rather than connecting in cleartext."""
    from psycopg.conninfo import conninfo_to_dict

    try:
        d = conninfo_to_dict(dsn)
    except Exception:
        return []
    out: list[str] = []
    for key, env in (("hostaddr", "PGHOSTADDR"), ("host", "PGHOST")):
        val = d.get(key) or os.environ.get(env)
        if val:
            out.extend(part.strip().strip("[]") for part in str(val).split(",") if part.strip())
    return out


def _effective_sslmode(dsn: str) -> str:
    from psycopg.conninfo import conninfo_to_dict

    try:
        sm = conninfo_to_dict(dsn).get("sslmode")
    except Exception:
        sm = None
    return str(sm or os.environ.get("PGSSLMODE") or "")


def _verify_transport(conn) -> None:
    """Fail closed if the LIVE connection's real peer is routable but TLS is not *validating*.

    Authoritative — reads the EFFECTIVE sslmode libpq actually used (`get_parameters()` reports it even
    when it came from a service file or PG* env), so it requires verify-full/verify-ca for a routable
    peer. Checking `ssl_in_use` alone was insufficient: sslmode=require/prefer encrypts but does NO cert
    validation → MITM-able. Loopback stays zero-config (TLS not required)."""
    real_host = conn.info.hostaddr or conn.info.host or ""
    if not real_host or is_loopback(real_host):
        return
    sslmode = (conn.info.get_parameters().get("sslmode") or "").lower()
    if sslmode not in _VALIDATING_TLS:
        conn.close()
        raise ValueError(
            f"refusing the connection to routable Postgres host {real_host!r}: effective "
            f"sslmode={sslmode or 'default'} is not validating TLS — require sslmode=verify-full "
            "(with VEREL_PG_CACERT) or use a loopback host")


_FLAG_KEYS = ("pinned", "volatile", "stale")


def _canonical_detail(detail_json: str) -> str:
    """detail_json normalized so the set-based decay's jsonb access is always safe AND matches Python
    truthiness. Non-JSON / non-object → '{}'. The lifecycle flags are coerced to their canonical types
    at this single ingress so a value from `annotate`/`apply_replica` (an unvalidated string from
    another node) can never (a) abort a jsonb cast in decay or (b) diverge from `view.is_pinned`'s
    `bool(...)` semantics: pinned/volatile/stale → real JSON booleans (Python truthiness), ttl_s → a
    real number or dropped. All other keys (corrections, superseded, …) pass through untouched."""
    try:
        obj = json.loads(detail_json or "{}")
    except (ValueError, TypeError):
        return "{}"
    if not isinstance(obj, dict):
        return "{}"
    for key in _FLAG_KEYS:
        if key in obj:
            obj[key] = bool(obj[key])  # matches view.is_pinned/is_volatile: bool(detail.get(key))
    if "ttl_s" in obj:
        try:
            obj["ttl_s"] = float(obj["ttl_s"])
        except (ValueError, TypeError):
            del obj["ttl_s"]  # a non-numeric ttl can't be honored; drop it (no TTL) rather than store garbage
    return json.dumps(obj)


class PostgresMemory(MemoryView):
    def __init__(self, dsn: str, *, embedder=None, statement_timeout_ms: int = 30000):
        import psycopg

        self._dsn = dsn
        self.embedder = embedder
        # Fail closed: if ANY effective target host is routable, require a cert-validating TLS mode —
        # resolved from the DSN *and* PG* env so neither hostaddr=, a comma-list, nor an env override
        # can sneak a cleartext credential onto the wire.
        routable = [h for h in _routable_hosts(dsn) if h and not is_loopback(h)]
        if routable and _effective_sslmode(dsn) not in _VALIDATING_TLS:
            raise ValueError(
                f"refusing to connect to routable Postgres host(s) {routable} without a validating TLS "
                "mode — set sslmode=verify-full (with VEREL_PG_CACERT) or use a loopback host")
        try:
            self._conn = psycopg.connect(dsn, autocommit=False)
        except Exception as e:  # connection errors must not leak the DSN
            raise RuntimeError(f"PostgresMemory connect failed: {_scrub(e, dsn)}") from None
        # Authoritative post-connect check: ask the LIVE connection what it ACTUALLY did. The
        # pre-connect guard can't see `service=`/`PGSERVICE` (libpq expands pg_service.conf at connect
        # time) or other PG* indirection — but `conn.info` reveals the real peer, and `ssl_in_use` the
        # real transport. If the real peer is routable and the wire isn't TLS, refuse (fail closed).
        _verify_transport(self._conn)
        try:
            with self._conn.cursor() as cur:
                # SET takes no bind params; int() makes the value injection-proof (numeric only).
                cur.execute(f"SET statement_timeout = {int(statement_timeout_ms)}")  # nosec B608 — int-coerced
            self._conn.commit()
            self._has_vector = self._init_schema()
            if self._has_vector:
                from pgvector.psycopg import register_vector
                register_vector(self._conn)
        except Exception as e:  # setup errors must not leak the DSN
            raise RuntimeError(f"PostgresMemory connect failed: {_scrub(e, dsn)}") from None

    @classmethod
    def from_env(cls) -> PostgresMemory:
        """Build from operator env (`VEREL_MEMORY_BACKEND=postgres`). Fails closed without a DSN."""
        try:
            import psycopg  # noqa: F401
            from psycopg.conninfo import make_conninfo
        except ImportError as e:
            raise RuntimeError("postgres backend needs `pip install verel[postgres]`") from e
        from .embed import embedder_from_env

        dsn = os.environ.get("VEREL_POSTGRES_URL") or os.environ.get("VEREL_POSTGRES_DSN")
        if not dsn:
            raise RuntimeError("postgres backend requires VEREL_POSTGRES_URL (or VEREL_POSTGRES_DSN)")
        sslmode = os.environ.get("VEREL_PG_SSLMODE")
        cacert = os.environ.get("VEREL_PG_CACERT")
        # Merge TLS params via make_conninfo (normalizes URL↔keyword) — NOT string concatenation, which
        # silently dropped sslrootcert for URL DSNs. Wrapped + scrubbed: a malformed credentialed DSN
        # makes make_conninfo raise with the password echoed, so it must never propagate raw.
        extra = {k: v for k, v in (("sslmode", sslmode), ("sslrootcert", cacert)) if v}
        if extra:
            try:
                dsn = make_conninfo(dsn, **extra)
            except Exception as e:
                raise RuntimeError(f"invalid VEREL_POSTGRES_URL/DSN: {_scrub(e, dsn)}") from None
        return cls(dsn, embedder=embedder_from_env())

    # ---- schema ----
    def _init_schema(self) -> bool:
        with self._conn.cursor() as cur:
            cur.execute(
                "CREATE TABLE IF NOT EXISTS memory ("
                "id TEXT PRIMARY KEY, kind TEXT, subject TEXT, predicate TEXT, text TEXT, scope TEXT, "
                "subj_pred_key TEXT, source TEXT, provenance TEXT, trust TEXT, "
                "epistemic_confidence DOUBLE PRECISION, retrieval_strength DOUBLE PRECISION, "
                "support_count INTEGER, created_ts DOUBLE PRECISION, last_recall_ts DOUBLE PRECISION, "
                "detail_json TEXT)")
            has_vector = False
            try:
                cur.execute("SELECT 1 FROM pg_extension WHERE extname = 'vector'")
                has_vector = cur.fetchone() is not None
                if has_vector:
                    cur.execute("ALTER TABLE memory ADD COLUMN IF NOT EXISTS embedding vector")
            except Exception:
                has_vector = False
        self._conn.commit()
        return has_vector

    # ---- transaction helper: commit on success, ALWAYS rollback + scrub on error ----
    @contextmanager
    def _txn(self, *, dict_rows: bool = True):
        """Every db method runs through this. On any exception it rolls back (so a failed statement
        can't leave the single shared connection in an aborted-transaction state that bricks every
        later call) and re-raises a scrubbed RuntimeError (so the DSN never leaks)."""
        cur = self._conn.cursor(row_factory=_dict_row()) if dict_rows else self._conn.cursor()
        try:
            yield cur
            self._conn.commit()
        except Exception as e:
            self._conn.rollback()
            raise RuntimeError(f"postgres op failed: {_scrub(e, self._dsn)}") from None
        finally:
            cur.close()

    # ---- (de)serialization ----
    def _row_to_record(self, row: dict) -> MemoryRecord:
        d = dict(row)
        d.pop("embedding", None)
        d["provenance"] = d["provenance"].split("\x1f") if d["provenance"] else []
        d["trust"] = Trust(d["trust"])
        d["kind"] = MemoryKind(d["kind"])
        return MemoryRecord(**d)

    def _vector(self, r: MemoryRecord):
        if not self.embedder:
            return None
        from pgvector import Vector

        return Vector(self.embedder.embed([f"{r.subject} {r.predicate} {r.text}".strip()])[0])

    def _upsert(self, cur, r: MemoryRecord) -> None:
        vals = [r.id, r.kind.value, r.subject, r.predicate, r.text, r.scope, r.subj_pred_key,
                r.source, "\x1f".join(r.provenance), r.trust.value, r.epistemic_confidence,
                r.retrieval_strength, r.support_count, r.created_ts, r.last_recall_ts,
                _canonical_detail(r.detail_json)]  # canonical flags; never persist non-object JSON
        cols, ph = _COLS_SQL, ", ".join(["%s"] * len(_COLS))
        update = ", ".join(f"{c}=EXCLUDED.{c}" for c in _COLS if c != "id")
        if self._has_vector:
            vec = self._vector(r)
            cur.execute(
                f"INSERT INTO memory ({cols}, embedding) VALUES ({ph}, %s) "  # nosec B608 — const cols; bound
                f"ON CONFLICT (id) DO UPDATE SET {update}, embedding=EXCLUDED.embedding",
                [*vals, vec])
        else:
            cur.execute(
                f"INSERT INTO memory ({cols}) VALUES ({ph}) ON CONFLICT (id) DO UPDATE SET {update}",  # nosec B608 — const cols; bound
                vals)

    def _lock(self, cur, record_id: str) -> None:
        # Serialize all writers for THIS key for the rest of the txn — so concurrent corroborate /
        # supersede on the same (subject,predicate,scope) can't lose an update or race the insert.
        cur.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (record_id,))

    def _get(self, cur, record_id: str) -> MemoryRecord | None:
        cur.execute(f"SELECT {_COLS_SQL} FROM memory WHERE id=%s", (record_id,))  # nosec B608 — constant cols
        row = cur.fetchone()
        return self._row_to_record(row) if row else None

    # ---- MemoryView API ----
    def write(self, record: MemoryRecord, *, ts: float = 0.0) -> MemoryRecord:
        if not record.subj_pred_key:
            record.subj_pred_key = make_key(record.subject, record.predicate, record.scope)
        record.id = record.id or make_id(record.subj_pred_key)
        record.created_ts = record.created_ts or ts
        with self._txn() as cur:
            self._lock(cur, record.id)
            existing = self._get(cur, record.id)
            if existing is not None:
                if existing.text.strip().lower() == record.text.strip().lower():
                    existing.support_count += 1
                    existing.epistemic_confidence = min(1.0, existing.epistemic_confidence + 0.1)
                    existing.retrieval_strength = 1.0
                    for p in record.provenance:
                        if p not in existing.provenance:
                            existing.provenance.append(p)
                    if record.detail:
                        existing.with_detail(**record.detail)
                    existing.with_detail(volatile=False)
                    self._upsert(cur, existing)
                    return existing
                # different value → supersede, keeping a BOUNDED correction chain (newest last).
                chain = [*existing.detail.get("corrections", []),
                         {"text": existing.text, "ec": existing.epistemic_confidence,
                          "ts": existing.created_ts, "superseded_at": ts}][-_MAX_CHAIN:]
                record.support_count = 1
                record.retrieval_strength = 1.0
                record.with_detail(corrections=chain, superseded=existing.text)
            self._upsert(cur, record)
            return record

    def apply_replica(self, record: MemoryRecord) -> MemoryRecord:
        if not record.subj_pred_key:
            record.subj_pred_key = make_key(record.subject, record.predicate, record.scope)
        record.id = record.id or make_id(record.subj_pred_key)
        with self._txn(dict_rows=False) as cur:
            self._lock(cur, record.id)
            self._upsert(cur, record)
        return record

    def get(self, record_id: str) -> MemoryRecord | None:
        with self._txn() as cur:
            return self._get(cur, record_id)

    def recall(self, query: str, *, scope=None, kind=None, k: int = 5, ts: float = 0.0):
        # Clamp caller-supplied k at the backend boundary — an unbounded k would scale the ANN LIMIT
        # (max(k*4,20)) into a whole-table fetch + per-row cosine, OOMing the client.
        try:
            k = max(1, min(int(k), _MAX_RECALL_K))
        except (TypeError, ValueError, OverflowError):  # OverflowError: int(float('inf')) from k=1e999
            k = 5
        where = ["trust <> 'rejected'"]
        params: list = []
        if scope is not None:
            where.append("(scope = %s OR scope = 'global')")
            params.append(scope)
        if kind is not None:
            where.append("kind = %s")
            params.append(kind.value)
        clause = " AND ".join(where)
        with self._txn() as cur:
            if self.embedder is not None and self._has_vector:
                from pgvector import Vector

                from .embed import cosine

                qv = self.embedder.embed([query])[0]
                cur.execute(
                    f"SELECT {_COLS_SQL}, embedding FROM memory WHERE {clause} AND embedding IS NOT NULL "  # nosec B608
                    f"ORDER BY embedding <=> %s LIMIT %s",
                    [*params, Vector(qv), min(max(k * 4, 20), _RECALL_SCAN_CAP)])
                rows = cur.fetchall()
                cands = [self._row_to_record(r) for r in rows]
                rel = {c.id: cosine(qv, list(rows[i]["embedding"]) if rows[i]["embedding"] is not None
                                    else []) for i, c in enumerate(cands)}
                relevance_of = lambda c: rel.get(c.id, 0.0)  # noqa: E731
            else:
                # No ANN signal → lexical rank in Python over a BOUNDED candidate scan (a giant brain
                # can't OOM the client). Documented-lossy beyond the cap; warn so it isn't silent.
                cur.execute(
                    f"SELECT {_COLS_SQL} FROM memory WHERE {clause} LIMIT %s",  # nosec B608 — const cols; bound
                    [*params, _RECALL_SCAN_CAP])
                rows = cur.fetchall()
                if len(rows) >= _RECALL_SCAN_CAP:
                    _log.warning("recall scan hit the %d-row cap; lexical recall may be incomplete — "
                                 "configure an embedder (VEREL_EMBEDDER) for bounded ANN recall",
                                 _RECALL_SCAN_CAP)
                cands = [self._row_to_record(r) for r in rows]
                relevance_of = lambda c: _relevance(query, c)  # noqa: E731
            scored = sorted(cands, key=lambda c: rank(c, relevance_of(c)), reverse=True)
            top = [c for c in scored if relevance_of(c) > 0.0][:k]
            # Reinforce retrieval_strength ONLY (testing effect) as one atomic, lock-free bulk UPDATE —
            # never touches confidence; the LEAST(...) is correct even under a concurrent writer.
            if top:
                cur.execute(
                    "UPDATE memory SET retrieval_strength = LEAST(1.0, retrieval_strength + 0.3), "
                    "last_recall_ts = COALESCE(%s, last_recall_ts) WHERE id = ANY(%s)",
                    (ts or None, [c.id for c in top]))
                for c in top:  # mirror the persisted change onto the returned objects
                    c.retrieval_strength = min(1.0, c.retrieval_strength + 0.3)
                    c.last_recall_ts = ts or c.last_recall_ts
            return top

    # ---- trust mutators (advisory-locked read-modify-write = atomic per key) ----
    def _adjust(self, record_id: str, *, ec: float = 0.0, support: int = 0,
                trust: Trust | None = None, confirm: bool = False) -> MemoryRecord | None:
        with self._txn() as cur:
            self._lock(cur, record_id)
            r = self._get(cur, record_id)
            if r is None:
                return None
            r.epistemic_confidence = max(0.0, min(1.0, r.epistemic_confidence + ec))
            r.support_count += support
            if trust is not None:
                r.trust = trust
            if confirm:
                r.with_detail(volatile=False)
            self._upsert(cur, r)
            return r

    def corroborate(self, record_id, *, delta: float = 0.15):
        return self._adjust(record_id, ec=delta, support=1, confirm=True)

    def contradict(self, record_id, *, delta: float = 0.25):
        r = self._adjust(record_id, ec=-delta)
        if r is not None and r.epistemic_confidence < 0.2:
            r = self._adjust(record_id, trust=Trust.REJECTED)
        return r

    def promote(self, record_id):
        return self._adjust(record_id, trust=Trust.VERIFIED, confirm=True)

    def demote(self, record_id):
        return self._adjust(record_id, trust=Trust.CANDIDATE)

    def annotate(self, record_id: str, **detail) -> MemoryRecord | None:
        with self._txn() as cur:
            self._lock(cur, record_id)
            r = self._get(cur, record_id)
            if r is None:
                return None
            r.with_detail(**detail)
            self._upsert(cur, r)
            return r

    def set_flags(self, record_id: str, *, pinned=None, volatile=None, ttl_s=None):
        upd: dict = {}
        if pinned is not None:
            upd["pinned"] = bool(pinned)
        if volatile is not None:
            upd["volatile"] = bool(volatile)
        if ttl_s is not None:
            upd["ttl_s"] = float(ttl_s)  # coerce at ingress → a clear error here, never a silent drop later
        with self._txn() as cur:
            self._lock(cur, record_id)
            r = self._get(cur, record_id)
            if r is None:
                return None
            r.with_detail(**upd)
            self._upsert(cur, r)
            return r

    def pin(self, record_id):
        return self.set_flags(record_id, pinned=True)

    def unpin(self, record_id):
        return self.set_flags(record_id, pinned=False)

    def decay(self, *, half_life_s: float = 604800.0, now: float = 0.0,
              stale_after_s: float = STALE_AFTER_S, volatile_ttl_s: float = VOLATILE_TTL_S) -> int:
        """Librarian pass, **set-based and concurrency-safe**: each statement reads+writes atomically
        under row locks, so it never clobbers a concurrent corroborate/supersede, and the prune DELETE
        re-evaluates its predicate at delete time (Postgres re-checks the WHERE under READ COMMITTED),
        so a row reinforced above the threshold by a racing writer is NOT pruned. Pinned rows are
        exempt; confidence is never touched. Returns #pruned. Mirrors `view.apply_decay` exactly."""
        # adaptive half-life in SQL: base * min(6, 1 + 0.6*log2(1+support) + 2*max(0, ec-0.5)).
        hl = ("(%s * LEAST(6.0, 1.0 + 0.6 * log(2.0, 1.0 + GREATEST(support_count, 0)) "
              "+ 2.0 * GREATEST(0.0, epistemic_confidence - 0.5)))")
        with self._txn(dict_rows=False) as cur:
            if now and now > 0:
                cur.execute(
                    f"UPDATE memory SET retrieval_strength = retrieval_strength * "  # nosec B608 — const exprs; scalars bound
                    f"power(0.5, GREATEST(0.0, %s - {_REF}) / {hl}) WHERE NOT {_PINNED}",
                    (now, half_life_s))
                cur.execute(
                    f"UPDATE memory SET detail_json = jsonb_set({_DETAIL}, '{{stale}}', 'true')::text "  # nosec B608 — const exprs; scalars bound
                    f"WHERE NOT {_PINNED} AND (%s - {_REF}) > %s", (now, stale_after_s))
            cur.execute(
                f"DELETE FROM memory WHERE NOT {_PINNED} AND ("  # nosec B608 — const exprs/thresholds; scalars bound
                f"  ({_TTL} IS NOT NULL AND %s > 0 AND (%s - created_ts) > {_TTL}) "
                f"  OR ({_VOLATILE} AND %s > 0 AND (%s - created_ts) > %s) "
                f"  OR (retrieval_strength < {PRUNE_RS} AND epistemic_confidence < {PRUNE_EC} "
                f"      AND support_count < {PRUNE_SUPPORT} AND trust <> 'verified'))",
                (now, now, now, now, volatile_ttl_s))
            return cur.rowcount

    def all(self, *, scope=None, kind=None):
        """Full materialization — an admin/diagnostic method (consolidation, tests). Not an
        agent-facing hot path; recall (which IS) is the bounded one."""
        where, params = [], []
        if scope is not None:
            where.append("scope = %s")
            params.append(scope)
        if kind is not None:
            where.append("kind = %s")
            params.append(kind.value)
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        with self._txn() as cur:
            cur.execute(f"SELECT {_COLS_SQL} FROM memory{clause}", params)  # nosec B608 — constant cols + bound params
            return [self._row_to_record(r) for r in cur.fetchall()]

    def close(self) -> None:
        self._conn.close()


def _dict_row():
    from psycopg.rows import dict_row
    return dict_row
