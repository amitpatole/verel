"""LanceMemory — an embedded LanceDB `MemoryView` (a vector-native upgrade over the SQLite default).

LanceDB is an **embedded** columnar/vector store (a directory on disk, no server) — so this is the
zero-infrastructure way to get real ANN recall: `pip install verel[lancedb]`, point
`VEREL_LANCEDB_PATH` at a directory, no service to run. With an embedder, recall is pgvector-style
approximate-nearest-neighbour over a Lance index; without one it falls back to the same lexical
token-overlap as `LocalMemory`. The whole trust layer (interference rule, decay, the documented
`rank()`) is unchanged — Lance just provides the relevance signal and the storage.

**Single-writer**, like `LocalMemory`: one embedded dataset is owned by one process. An instance
serializes its own read-modify-write under a lock, but **concurrent multi-process writers to one Lance
dataset are NOT interference-rule-safe** — front it with a `MemoryServer` (which already wraps any
`MemoryView` behind its lock) for shared/multi-writer use, exactly as you would `LocalMemory`.

Security (embedded — no network, no credentials): LanceDB's `.where(...)` takes a **SQL-like filter
string**, so any value interpolated into one is an injection sink. This backend keeps that surface
tiny — scope/kind/trust are filtered in Python (never in a predicate), and the only values that reach
`.where()` are record ids, every one escaped through `_lit` (doubled single-quotes). The dataset path
comes from operator env only and is path-normalized.
"""

from __future__ import annotations

import os
import threading

from .view import (
    STALE_AFTER_S,
    VOLATILE_TTL_S,
    MemoryKind,
    MemoryRecord,
    MemoryView,
    Trust,
    apply_decay,
    make_id,
    make_key,
    rank,
)
from .view import (
    relevance as _relevance,
)

_TABLE = "memory"
_MAX_RECALL_K = 1000   # clamp caller-supplied k so an unbounded fetch can't OOM the client
_SCAN_CAP = 5000       # bound the no-embedder full scan
_SCALAR_FIELDS = ("id", "kind", "subject", "predicate", "text", "scope", "subj_pred_key", "source",
                  "provenance", "trust", "epistemic_confidence", "retrieval_strength",
                  "support_count", "created_ts", "last_recall_ts", "detail_json")


def _lit(value: str) -> str:
    """A SQL string literal for a LanceDB `.where(...)` predicate — single-quotes doubled (the
    DataFusion/SQL escape), control chars rejected. The ONLY values we ever put in a predicate are
    record ids; everything else (scope/kind/trust) is filtered in Python, off the SQL surface."""
    if not isinstance(value, str):
        raise TypeError("filter literal must be a str")
    if any(ord(c) < 0x20 for c in value):
        raise ValueError("control character in filter literal")
    return "'" + value.replace("'", "''") + "'"


class LanceMemory(MemoryView):
    def __init__(self, path: str, *, embedder=None, table: str = _TABLE):
        import lancedb

        self.path = path
        self.embedder = embedder
        if embedder is not None and not (isinstance(getattr(embedder, "dim", None), int)
                                         and embedder.dim > 0):
            raise RuntimeError(
                f"embedder.dim must be a positive int (the fixed vector width), got "
                f"{getattr(embedder, 'dim', None)!r}")
        self._dim = int(embedder.dim) if embedder is not None else 0
        self._table_name = table
        self._lock = threading.RLock()
        self._closed = False
        self._db = lancedb.connect(path)
        self._tbl = self._open_or_create()

    def _open_or_create(self):
        import pyarrow as pa

        # Open if it already exists, else create. We try-open-then-create rather than a membership
        # check because the existence-check API has drifted across lancedb versions (`table_names()`
        # is deprecated; `list_tables()` returns a ListTablesResponse wrapper whose `in` check is
        # always False) — getting that wrong silently re-creates and crashes ("table already exists")
        # on EVERY reopen of a persisted dataset, breaking persistence across restarts.
        try:
            tbl = self._db.open_table(self._table_name)
        except Exception:  # not present yet → create it below
            tbl = None
        if tbl is not None:
            self._reconcile_schema(tbl)
            return tbl
        fields = [
            ("id", pa.string()), ("kind", pa.string()), ("subject", pa.string()),
            ("predicate", pa.string()), ("text", pa.string()), ("scope", pa.string()),
            ("subj_pred_key", pa.string()), ("source", pa.string()), ("provenance", pa.string()),
            ("trust", pa.string()), ("epistemic_confidence", pa.float64()),
            ("retrieval_strength", pa.float64()), ("support_count", pa.int64()),
            ("created_ts", pa.float64()), ("last_recall_ts", pa.float64()),
            ("detail_json", pa.string()),
        ]
        if self._dim:  # a fixed-dim vector column only when an embedder is configured
            fields.append(("vector", pa.list_(pa.float32(), self._dim)))
        return self._db.create_table(self._table_name, schema=pa.schema(fields))

    def _reconcile_schema(self, tbl) -> None:
        """Fail CLOSED if the current embedder config disagrees with the persisted dataset's vector
        column. The vector dim is baked into the schema at create time; reopening the same
        `VEREL_LANCEDB_PATH` with a different `VEREL_EMBEDDER`/model (dim change, or adding/removing an
        embedder) otherwise crashes opaquely on the first write/recall (or silently drops to lexical).
        Raise a clear, actionable error instead — exactly the cross-restart blind spot a single-process
        test misses."""
        import pyarrow as pa

        schema = tbl.schema
        persisted = (schema.field("vector").type.list_size
                     if "vector" in schema.names
                     and pa.types.is_fixed_size_list(schema.field("vector").type) else 0)
        if persisted != self._dim:
            how = (f"persisted vector dim {persisted}" if persisted else "no embedder (lexical)")
            now = (f"current embedder dim {self._dim}" if self._dim else "no embedder (lexical)")
            raise RuntimeError(
                f"LanceDB dataset at {self.path!r} table {self._table_name!r} was created with {how}, "
                f"but is being reopened with {now}. The vector dimension is fixed at create time — set "
                "VEREL_EMBEDDER to match the original, or use a fresh VEREL_LANCEDB_PATH / "
                "VEREL_LANCEDB_TABLE for the new embedding configuration.")

    @classmethod
    def from_env(cls) -> LanceMemory:
        """Build from operator env (`VEREL_MEMORY_BACKEND=lancedb`). Fails closed without lancedb."""
        try:
            import lancedb  # noqa: F401
        except ImportError as e:
            raise RuntimeError("lancedb backend needs `pip install verel[lancedb]`") from e
        from .embed import embedder_from_env

        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
        raw = os.environ.get("VEREL_LANCEDB_PATH") or os.path.join(base, "verel", "lance")
        # operator-controlled path; normalize (expanduser/abspath) and ensure it exists.
        path = os.path.abspath(os.path.expanduser(raw))
        os.makedirs(path, exist_ok=True)
        table = os.environ.get("VEREL_LANCEDB_TABLE", _TABLE)
        return cls(path, embedder=embedder_from_env(), table=table)

    # ---- (de)serialization ----
    def _row_to_record(self, row: dict) -> MemoryRecord:
        d = {k: row[k] for k in _SCALAR_FIELDS}
        d["provenance"] = d["provenance"].split("\x1f") if d["provenance"] else []
        d["trust"] = Trust(d["trust"])
        d["kind"] = MemoryKind(d["kind"])
        return MemoryRecord(**d)

    def _record_to_row(self, r: MemoryRecord) -> dict:
        row: dict = {
            "id": r.id, "kind": r.kind.value, "subject": r.subject, "predicate": r.predicate,
            "text": r.text, "scope": r.scope, "subj_pred_key": r.subj_pred_key, "source": r.source,
            "provenance": "\x1f".join(r.provenance), "trust": r.trust.value,
            "epistemic_confidence": float(r.epistemic_confidence),
            "retrieval_strength": float(r.retrieval_strength), "support_count": int(r.support_count),
            "created_ts": float(r.created_ts), "last_recall_ts": float(r.last_recall_ts),
            "detail_json": r.detail_json,
        }
        if self._dim:
            vec = [float(x) for x in self._embed(r)]
            if len(vec) != self._dim:
                # the embedder's reported .dim lied vs what embed() returned — catch it here with a
                # clear message instead of an opaque pyarrow length-mismatch deep in merge_insert.
                raise RuntimeError(
                    f"embedder produced a {len(vec)}-dim vector but the dataset's column is "
                    f"{self._dim}-dim — the embedder/model does not match its reported .dim "
                    f"({self.embedder.__class__.__name__}); set VEREL_EMBED_DIM or use a matching model")
            row["vector"] = vec
        return row

    def _embed(self, r: MemoryRecord):
        return self.embedder.embed([f"{r.subject} {r.predicate} {r.text}".strip()])[0]

    def _upsert(self, r: MemoryRecord) -> None:
        # merge_insert keyed on the id COLUMN value (data-driven, never a SQL string) → no injection.
        (self._tbl.merge_insert("id").when_matched_update_all().when_not_matched_insert_all()
         .execute([self._record_to_row(r)]))

    def _get(self, record_id: str) -> MemoryRecord | None:
        rows = self._tbl.search().where(f"id = {_lit(record_id)}").limit(1).to_list()
        return self._row_to_record(rows[0]) if rows else None

    def _scan(self, limit: int) -> list[MemoryRecord]:
        return [self._row_to_record(x) for x in self._tbl.search().limit(limit).to_list()]

    def _check_open(self) -> None:
        # Called under the lock at the top of every public method, so a use-after-close raises a clear
        # error (not an opaque AttributeError from a nulled handle) and can't race close().
        if self._closed:
            raise RuntimeError("LanceMemory is closed")

    def _filter_sql(self, scope, kind) -> str:
        """The scope/kind/trust predicate for an ANN prefilter — every literal escaped via _lit
        (scope is arbitrary; kind/trust are enum-constant but escaped uniformly)."""
        preds = ["trust <> 'rejected'"]
        if scope is not None:
            preds.append(f"(scope = {_lit(scope)} OR scope = 'global')")
        if kind is not None:
            preds.append(f"kind = {_lit(kind.value)}")
        return " AND ".join(preds)

    # ---- MemoryView API ----
    def write(self, record: MemoryRecord, *, ts: float = 0.0) -> MemoryRecord:
        if not record.subj_pred_key:
            record.subj_pred_key = make_key(record.subject, record.predicate, record.scope)
        record.id = record.id or make_id(record.subj_pred_key)
        record.created_ts = record.created_ts or ts
        with self._lock:
            self._check_open()
            existing = self._get(record.id)
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
                    self._upsert(existing)
                    return existing
                chain = [*existing.detail.get("corrections", []),
                         {"text": existing.text, "ec": existing.epistemic_confidence,
                          "ts": existing.created_ts, "superseded_at": ts}]
                record.support_count = 1
                record.retrieval_strength = 1.0
                record.with_detail(corrections=chain, superseded=existing.text)
            self._upsert(record)
            return record

    def apply_replica(self, record: MemoryRecord) -> MemoryRecord:
        if not record.subj_pred_key:
            record.subj_pred_key = make_key(record.subject, record.predicate, record.scope)
        record.id = record.id or make_id(record.subj_pred_key)
        with self._lock:
            self._check_open()
            self._upsert(record)
        return record

    def get(self, record_id: str) -> MemoryRecord | None:
        with self._lock:
            self._check_open()
            return self._get(record_id)

    def recall(self, query: str, *, scope=None, kind=None, k: int = 5, ts: float = 0.0):
        try:
            k = max(1, min(int(k), _MAX_RECALL_K))
        except (TypeError, ValueError, OverflowError):
            k = 5
        with self._lock:
            self._check_open()
            if self.embedder is not None and self._dim:
                from .embed import cosine

                qv = self.embedder.embed([query])[0]
                # PREFILTER scope/kind/trust BEFORE the ANN limit (prefilter=True) so filtered-out
                # neighbours can't saturate the window and crowd out a valid record — this is what
                # keeps recall correctness identical to LocalMemory's scan-then-filter. The predicate
                # is built from escaped literals (scope via _lit; kind/trust are enum constants).
                rows = (self._tbl.search(qv).where(self._filter_sql(scope, kind), prefilter=True)
                        .limit(max(k * 4, 20)).to_list())
                cands = [(self._row_to_record(x), x.get("vector")) for x in rows]
                rel = {r.id: cosine(qv, list(v) if v is not None else []) for r, v in cands}
                pool = [r for r, _ in cands]
                relevance_of = lambda c: rel.get(c.id, 0.0)  # noqa: E731
            else:
                pool = self._scan(_SCAN_CAP)
                relevance_of = lambda c: _relevance(query, c)  # noqa: E731
            # Filter in Python too — authoritative for the no-embedder full scan, and a harmless
            # belt-and-suspenders for the embedder path (already prefiltered in SQL).
            if scope is not None:
                pool = [c for c in pool if c.scope == scope or c.scope == "global"]
            if kind is not None:
                pool = [c for c in pool if c.kind == kind]
            pool = [c for c in pool if c.trust != Trust.REJECTED]
            scored = sorted(pool, key=lambda c: rank(c, relevance_of(c)), reverse=True)
            top = [c for c in scored if relevance_of(c) > 0.0][:k]
            for c in top:  # recall reinforces retrieval_strength ONLY (testing effect)
                c.retrieval_strength = min(1.0, c.retrieval_strength + 0.3)
                c.last_recall_ts = ts or c.last_recall_ts
                self._upsert(c)
            return top

    # ---- trust mutators ----
    def _adjust(self, record_id: str, *, ec: float = 0.0, support: int = 0,
                trust: Trust | None = None, confirm: bool = False) -> MemoryRecord | None:
        with self._lock:
            self._check_open()
            r = self._get(record_id)
            if r is None:
                return None
            r.epistemic_confidence = max(0.0, min(1.0, r.epistemic_confidence + ec))
            r.support_count += support
            if trust is not None:
                r.trust = trust
            if confirm:
                r.with_detail(volatile=False)
            self._upsert(r)
            return r

    def corroborate(self, record_id, *, delta: float = 0.15):
        return self._adjust(record_id, ec=delta, support=1, confirm=True)

    def contradict(self, record_id, *, delta: float = 0.25):
        # ONE critical section (RLock is re-entrant): the lower-EC and the maybe-reject must not be
        # split by a concurrent corroborate/promote that would make the stale rejection wrong.
        with self._lock:
            r = self._adjust(record_id, ec=-delta)
            if r is not None and r.epistemic_confidence < 0.2:
                r = self._adjust(record_id, trust=Trust.REJECTED)
            return r

    def promote(self, record_id):
        return self._adjust(record_id, trust=Trust.VERIFIED, confirm=True)

    def demote(self, record_id):
        return self._adjust(record_id, trust=Trust.CANDIDATE)

    def annotate(self, record_id: str, **detail) -> MemoryRecord | None:
        with self._lock:
            self._check_open()
            r = self._get(record_id)
            if r is None:
                return None
            r.with_detail(**detail)
            self._upsert(r)
            return r

    def set_flags(self, record_id: str, *, pinned=None, volatile=None, ttl_s=None):
        with self._lock:
            self._check_open()
            r = self._get(record_id)
            if r is None:
                return None
            if pinned is not None:
                r.with_detail(pinned=bool(pinned))
            if volatile is not None:
                r.with_detail(volatile=bool(volatile))
            if ttl_s is not None:
                r.with_detail(ttl_s=float(ttl_s))
            self._upsert(r)
            return r

    def pin(self, record_id):
        return self.set_flags(record_id, pinned=True)

    def unpin(self, record_id):
        return self.set_flags(record_id, pinned=False)

    def decay(self, *, half_life_s: float = 604800.0, now: float = 0.0,
              stale_after_s: float = STALE_AFTER_S, volatile_ttl_s: float = VOLATILE_TTL_S) -> int:
        with self._lock:
            self._check_open()
            recs = self._scan(10**9)
            prune: list[MemoryRecord] = []
            survivors: list[MemoryRecord] = []
            for r in recs:
                (prune if apply_decay(r, now=now, half_life_s=half_life_s,
                                      stale_after_s=stale_after_s, volatile_ttl_s=volatile_ttl_s)
                 else survivors).append(r)
            if prune:  # ids are escaped via _lit (defense even though make_id ids are hex)
                ids = ", ".join(_lit(r.id) for r in prune)
                self._tbl.delete(f"id IN ({ids})")
            for r in survivors:
                self._upsert(r)
            return len(prune)

    def all(self, *, scope=None, kind=None):
        with self._lock:
            self._check_open()
            recs = self._scan(10**9)
        if scope is not None:
            recs = [r for r in recs if r.scope == scope]
        if kind is not None:
            recs = [r for r in recs if r.kind == kind]
        return recs

    def close(self) -> None:
        # Drop native handles before the process / a test's tmp dir is torn down (Lance can segfault
        # if its dataset directory is removed while still open). Hold the lock so it can't run while
        # another thread is mid-operation (which would null self._tbl out from under it). LanceDB
        # exposes no explicit close(), so release is by dropping the last references.
        with self._lock:
            self._closed = True
            self._tbl = None
            self._db = None
