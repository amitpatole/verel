"""LocalMemory — a zero-dependency SQLite MemoryView (default backend).

Implements the full trust layer (§5): split epistemic_confidence vs retrieval_strength,
the interference rule (subj_pred_key supersede), the documented ranking, power-law decay,
and the exact prune rule. Recall is lexical (token overlap) — embeddings are the v2 upgrade
behind the same interface; the design explicitly defers the weighted MMR assembler to v2.

mem0 is the rentable alternative behind the SAME `MemoryView` Protocol (see view.py); swap
it in without touching the failure-ledger, consolidation, or the loop.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

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

_COLS = (
    "id, kind, subject, predicate, text, scope, subj_pred_key, source, provenance, trust, "
    "epistemic_confidence, retrieval_strength, support_count, created_ts, last_recall_ts, detail_json"
)


class LocalMemory(MemoryView):
    def __init__(self, path: str | Path = ":memory:", *, embedder=None,
                 check_same_thread: bool = True, durable: bool = True):
        self.path = str(path)
        self.embedder = embedder  # optional: enables semantic (cosine) recall (§5.6)
        self.durable = durable
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False lets a hosted MemoryServer serve this store from its HTTP thread;
        # it is safe ONLY because the server serializes every access behind a lock.
        self._db = sqlite3.connect(self.path, check_same_thread=check_same_thread)
        self._db.row_factory = sqlite3.Row
        if self.path != ":memory:":
            # Crash safety (§5/§6.3): WAL for atomic, recoverable commits; synchronous=FULL fsyncs on
            # every commit so a write that returned is durable BEFORE its replica is acked — it
            # survives a leader crash. `durable=False` trades that fsync for speed where it's ok.
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute(f"PRAGMA synchronous={'FULL' if durable else 'NORMAL'}")
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS memory (
                id TEXT PRIMARY KEY, kind TEXT, subject TEXT, predicate TEXT, text TEXT,
                scope TEXT, subj_pred_key TEXT, source TEXT, provenance TEXT, trust TEXT,
                epistemic_confidence REAL, retrieval_strength REAL, support_count INTEGER,
                created_ts REAL, last_recall_ts REAL, detail_json TEXT, vector TEXT DEFAULT '')"""
        )
        # migrate older dbs that predate the vector column
        cols = {r[1] for r in self._db.execute("PRAGMA table_info(memory)")}
        if "vector" not in cols:
            self._db.execute("ALTER TABLE memory ADD COLUMN vector TEXT DEFAULT ''")
        self._db.commit()

    @classmethod
    def from_env(cls) -> LocalMemory:
        """Construct from operator env (the registry entry point for `VEREL_MEMORY_BACKEND=local`).

        Path: `VEREL_MEMORY_STORE` else `$XDG_CONFIG_HOME/verel/brain.db` (default `~/.config`).
        Embedder: the shared `embedder_from_env()` (None by default → lexical recall, unchanged).
        """
        import os

        from .embed import embedder_from_env

        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
        path = os.environ.get("VEREL_MEMORY_STORE") or os.path.join(base, "verel", "brain.db")
        if path != ":memory:":
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        return cls(path, embedder=embedder_from_env())

    # ---- embeddings ----
    def _embed_text(self, r: MemoryRecord) -> str:
        return f"{r.subject} {r.predicate} {r.text}".strip()

    def _set_vector(self, record_id: str, text: str) -> None:
        if not self.embedder:
            return
        import json as _json

        vec = self.embedder.embed([text])[0]
        self._db.execute("UPDATE memory SET vector=? WHERE id=?", (_json.dumps(vec), record_id))
        self._db.commit()

    def _get_vector(self, record_id: str) -> list[float] | None:
        import json as _json

        row = self._db.execute("SELECT vector FROM memory WHERE id=?", (record_id,)).fetchone()
        if row and row[0]:
            return _json.loads(row[0])
        return None

    # ---- serialization ----
    def _row_to_record(self, row: sqlite3.Row) -> MemoryRecord:
        d = dict(row)
        d["provenance"] = d["provenance"].split("\x1f") if d["provenance"] else []
        d["trust"] = Trust(d["trust"])
        d["kind"] = MemoryKind(d["kind"])
        return MemoryRecord(**d)

    def _upsert(self, r: MemoryRecord) -> None:
        # preserve any existing vector — INSERT OR REPLACE rewrites the whole row
        row = self._db.execute("SELECT vector FROM memory WHERE id=?", (r.id,)).fetchone()
        vector = (row[0] if row else "") or ""
        self._db.execute(
            f"INSERT OR REPLACE INTO memory ({_COLS}, vector) VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                r.id, r.kind.value, r.subject, r.predicate, r.text, r.scope, r.subj_pred_key,
                r.source, "\x1f".join(r.provenance), r.trust.value, r.epistemic_confidence,
                r.retrieval_strength, r.support_count, r.created_ts, r.last_recall_ts, r.detail_json,
                vector,
            ),
        )
        self._db.commit()

    # ---- MemoryView API ----
    def write(self, record: MemoryRecord, *, ts: float = 0.0) -> MemoryRecord:
        """Write with the interference rule: same (subject, predicate, scope) supersedes,
        accumulating support_count and corroboration rather than duplicating."""
        if not record.subj_pred_key:
            record.subj_pred_key = make_key(record.subject, record.predicate, record.scope)
        record.id = record.id or make_id(record.subj_pred_key)
        record.created_ts = record.created_ts or ts

        existing = self.get(record.id)
        if existing is not None:
            if existing.text.strip().lower() == record.text.strip().lower():
                if existing.trust == Trust.REJECTED:
                    # a REJECTED claim re-asserted is STILL rejected — re-stating a lie must not raise
                    # its confidence/support or reset its decay (that would pin it un-prunable and prime
                    # a resurrection). Refresh metadata only, never belief (round-6 M2).
                    self._upsert(existing)
                    return existing
                # same claim again -> corroboration (raises confidence + support, resets strength)
                existing.support_count += 1
                existing.epistemic_confidence = min(1.0, existing.epistemic_confidence + 0.1)
                existing.retrieval_strength = 1.0
                for p in record.provenance:
                    if p not in existing.provenance:
                        existing.provenance.append(p)
                # metadata (status transitions, times_seen, ...) updates to the latest write —
                # corroboration is about the CLAIM text, not its bookkeeping.
                incoming = record.detail
                if incoming:
                    existing.with_detail(**incoming)
                existing.with_detail(volatile=False)  # re-assertion confirms a volatile memory
                self._upsert(existing)
                return existing
            # different value for the same key -> supersede (interference): keep a correction
            # chain so the history is queryable, not just overwritten.
            chain = [*existing.detail.get("corrections", []),
                     {"text": existing.text, "ec": existing.epistemic_confidence,
                      "ts": existing.created_ts, "superseded_at": ts}]
            record.support_count = 1
            record.retrieval_strength = 1.0
            record.with_detail(corrections=chain, superseded=existing.text)
        self._upsert(record)
        self._set_vector(record.id, self._embed_text(record))  # no-op without an embedder
        return record

    def apply_replica(self, record: MemoryRecord) -> MemoryRecord:
        """Upsert a record VERBATIM (id + every field), with NO corroboration/supersede — for
        replication and catch-up sync, so a follower mirrors the leader's state exactly and
        re-delivery is idempotent."""
        if not record.subj_pred_key:
            record.subj_pred_key = make_key(record.subject, record.predicate, record.scope)
        record.id = record.id or make_id(record.subj_pred_key)
        self._upsert(record)
        self._set_vector(record.id, self._embed_text(record))
        return record

    def get(self, record_id: str) -> MemoryRecord | None:
        row = self._db.execute(f"SELECT {_COLS} FROM memory WHERE id=?", (record_id,)).fetchone()  # nosec B608 — _COLS is a constant column list; values bind as ?
        return self._row_to_record(row) if row else None

    def recall(self, query: str, *, scope=None, kind=None, k: int = 5, ts: float = 0.0):
        rows = self._db.execute(f"SELECT {_COLS} FROM memory").fetchall()  # nosec B608 — _COLS is a constant column list (no user input in SQL)
        cands = [self._row_to_record(r) for r in rows]
        if scope is not None:
            cands = [c for c in cands if c.scope == scope or c.scope == "global"]
        if kind is not None:
            cands = [c for c in cands if c.kind == kind]
        cands = [c for c in cands if c.trust != Trust.REJECTED]

        # Relevance signal: semantic cosine when an embedder is configured, else lexical.
        if self.embedder is not None and cands:
            from .embed import cosine

            qv = self.embedder.embed([query])[0]
            rel = {c.id: cosine(qv, self._get_vector(c.id) or []) for c in cands}
            relevance_of = lambda c: rel.get(c.id, 0.0)  # noqa: E731
            threshold = 0.0
        else:
            relevance_of = lambda c: _relevance(query, c)  # noqa: E731
            threshold = 0.0
        scored = sorted(cands, key=lambda c: rank(c, relevance_of(c)), reverse=True)
        top = [c for c in scored if relevance_of(c) > threshold][:k]
        # recall reinforces retrieval_strength ONLY (testing effect) — never confidence.
        for c in top:
            c.retrieval_strength = min(1.0, c.retrieval_strength + 0.3)
            c.last_recall_ts = ts or c.last_recall_ts
            self._upsert(c)
        return top

    def _adjust(self, record_id: str, *, ec: float = 0.0, support: int = 0,
                trust: Trust | None = None, confirm: bool = False) -> MemoryRecord | None:
        r = self.get(record_id)
        if r is None:
            return None
        r.epistemic_confidence = max(0.0, min(1.0, r.epistemic_confidence + ec))
        r.support_count += support
        if trust is not None:
            r.trust = trust
        if confirm:
            r.with_detail(volatile=False)  # corroboration / verification confirms a volatile memory
        self._upsert(r)
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
        """Merge `detail` into a record WITHOUT touching trust/confidence/support — audit
        metadata (e.g. a counterexample list), never a corroboration."""
        r = self.get(record_id)
        if r is None:
            return None
        r.with_detail(**detail)
        self._upsert(r)
        return r

    # ---- lifecycle flags (pin / volatile / TTL) ----
    def set_flags(self, record_id: str, *, pinned=None, volatile=None, ttl_s=None):
        """Set lifecycle flags directly (no corroboration side effect)."""
        r = self.get(record_id)
        if r is None:
            return None
        upd = {}
        if pinned is not None:
            upd["pinned"] = bool(pinned)
        if volatile is not None:
            upd["volatile"] = bool(volatile)
        if ttl_s is not None:
            upd["ttl_s"] = ttl_s
        r.with_detail(**upd)
        self._upsert(r)
        return r

    def pin(self, record_id):
        return self.set_flags(record_id, pinned=True)

    def unpin(self, record_id):
        return self.set_flags(record_id, pinned=False)

    def decay(self, *, half_life_s: float = 604800.0, now: float = 0.0,
              stale_after_s: float = STALE_AFTER_S, volatile_ttl_s: float = VOLATILE_TTL_S) -> int:
        """Decay retrieval_strength, expire TTL/volatile/stale records, then prune per §5.
        Pinned memories are exempt. Confidence is never touched. Returns #pruned."""
        rows = self._db.execute(f"SELECT {_COLS} FROM memory").fetchall()  # nosec B608 — _COLS is a constant column list (no user input in SQL)
        pruned = 0
        for row in rows:
            r = self._row_to_record(row)
            if apply_decay(r, now=now, half_life_s=half_life_s,
                           stale_after_s=stale_after_s, volatile_ttl_s=volatile_ttl_s):
                self._db.execute("DELETE FROM memory WHERE id=?", (r.id,))
                pruned += 1
            else:
                self._upsert(r)
        self._db.commit()
        return pruned

    def all(self, *, scope=None, kind=None):
        rows = self._db.execute(f"SELECT {_COLS} FROM memory").fetchall()  # nosec B608 — _COLS is a constant column list (no user input in SQL)
        recs = [self._row_to_record(r) for r in rows]
        if scope is not None:
            recs = [r for r in recs if r.scope == scope]
        if kind is not None:
            recs = [r for r in recs if r.kind == kind]
        return recs
