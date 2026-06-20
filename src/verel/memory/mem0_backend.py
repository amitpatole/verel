"""mem0 backend for MemoryView (§5.3) — the rented store behind the SAME Protocol.

The whole point of the `MemoryView` Protocol is that the trust layer (failure ledger,
consolidation, promotion gate) is backend-agnostic. `Mem0Memory` maps Verel records onto
mem0 memories (text -> `memory`, everything else -> `metadata`) so swapping LocalMemory for
mem0 changes one line and nothing in §5.5/§5.7/§7.5 changes.

Design-faithful choices:
- We do NOT use mem0's LLM auto-extraction (`infer=False`): Verel does its own gated
  consolidation (§5.5), so mem0 is pure storage + vector recall. That means mem0 needs no
  LLM key for our use — only an embedder for search.
- Verel's identity is content-addressed (`make_id`); we store it in metadata `verel_id` and
  reconcile on it, so the interference rule (subj_pred_key supersede) holds across backends.
- Ranking stays Verel's documented `rank()` over lexical relevance, so recall semantics are
  identical to LocalMemory and don't silently depend on mem0's similarity tuning.

`mem0` is the optional `verel[mem0]` extra; import is lazy. The adapter is written against a
tiny client surface (add/get_all/search/update/delete/get) that both real `mem0.Memory` and
the test fake implement.
"""

from __future__ import annotations

from typing import Protocol

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

_META_FIELDS = (
    "kind", "subject", "predicate", "scope", "subj_pred_key", "source", "trust",
    "epistemic_confidence", "retrieval_strength", "support_count", "created_ts",
    "last_recall_ts", "detail_json", "provenance", "verel_id",
)


class Mem0Client(Protocol):
    # Matches mem0 >= 2.0 (filters= on get_all/search; update(id, data, metadata=)).
    def add(self, messages, *, user_id: str, metadata: dict, infer: bool) -> dict: ...
    def get_all(self, *, filters: dict) -> dict: ...
    def search(self, query: str, *, filters: dict, limit: int) -> dict: ...
    def update(self, memory_id: str, data, metadata: dict | None = None) -> dict: ...
    def delete(self, memory_id: str) -> dict: ...
    def get(self, memory_id: str) -> dict | None: ...


def _to_metadata(r: MemoryRecord) -> dict:
    return {
        "kind": r.kind.value, "subject": r.subject, "predicate": r.predicate, "scope": r.scope,
        "subj_pred_key": r.subj_pred_key, "source": r.source, "trust": r.trust.value,
        "epistemic_confidence": r.epistemic_confidence, "retrieval_strength": r.retrieval_strength,
        "support_count": r.support_count, "created_ts": r.created_ts,
        "last_recall_ts": r.last_recall_ts, "detail_json": r.detail_json,
        "provenance": "\x1f".join(r.provenance), "verel_id": r.id,
    }


def _from_mem0(row: dict) -> MemoryRecord:
    md = dict(row.get("metadata") or {})
    return MemoryRecord(
        id=md.get("verel_id", ""),
        kind=MemoryKind(md.get("kind", "fact")),
        subject=md.get("subject", ""),
        predicate=md.get("predicate", ""),
        text=row.get("memory", ""),
        scope=md.get("scope", "repo:default"),
        subj_pred_key=md.get("subj_pred_key", ""),
        source=md.get("source", "other"),
        provenance=md["provenance"].split("\x1f") if md.get("provenance") else [],
        trust=Trust(md.get("trust", "candidate")),
        epistemic_confidence=float(md.get("epistemic_confidence", 0.5)),
        retrieval_strength=float(md.get("retrieval_strength", 1.0)),
        support_count=int(md.get("support_count", 1)),
        created_ts=float(md.get("created_ts", 0.0)),
        last_recall_ts=float(md.get("last_recall_ts", 0.0)),
        detail_json=md.get("detail_json", "{}"),
    )


class Mem0Memory(MemoryView):
    def __init__(self, client: Mem0Client, *, user_id: str = "verel"):
        self.client = client
        self.user_id = user_id

    # ---- internal: find the mem0 row id backing a verel record id ----
    def _rows(self) -> list[dict]:
        return (self.client.get_all(filters={"user_id": self.user_id}) or {}).get("results", [])

    def _mem0_id_for(self, verel_id: str) -> str | None:
        for row in self._rows():
            if (row.get("metadata") or {}).get("verel_id") == verel_id:
                return row.get("id")
        return None

    def _persist(self, r: MemoryRecord, mem0_id: str | None) -> None:
        if mem0_id is None:
            self.client.add([{"role": "user", "content": r.text}], user_id=self.user_id,
                            metadata=_to_metadata(r), infer=False)
        else:
            self.client.update(mem0_id, data=r.text, metadata=_to_metadata(r))

    # ---- MemoryView ----
    def write(self, record: MemoryRecord, *, ts: float = 0.0) -> MemoryRecord:
        if not record.subj_pred_key:
            record.subj_pred_key = make_key(record.subject, record.predicate, record.scope)
        record.id = record.id or make_id(record.subj_pred_key)
        record.created_ts = record.created_ts or ts

        existing = self.get(record.id)
        mem0_id = self._mem0_id_for(record.id)
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
                existing.with_detail(volatile=False)  # re-assertion confirms a volatile memory
                self._persist(existing, mem0_id)
                return existing
            chain = [*existing.detail.get("corrections", []),
                     {"text": existing.text, "ec": existing.epistemic_confidence,
                      "ts": existing.created_ts, "superseded_at": ts}]
            record.support_count = 1
            record.retrieval_strength = 1.0
            record.with_detail(corrections=chain, superseded=existing.text)
        self._persist(record, mem0_id)
        return record

    def get(self, record_id: str) -> MemoryRecord | None:
        for row in self._rows():
            if (row.get("metadata") or {}).get("verel_id") == record_id:
                return _from_mem0(row)
        return None

    def recall(self, query: str, *, scope=None, kind=None, k: int = 5, ts: float = 0.0):
        res = self.client.search(query, filters={"user_id": self.user_id}, limit=max(k * 4, 20)) or {}
        rows = res.get("results", [])
        # mem0 returns rows already ranked by SEMANTIC similarity (vector search). Use that
        # order as the relevance signal feeding Verel's documented rank() — do NOT re-filter
        # by lexical overlap, which would discard semantically-relevant-but-different-worded
        # hits (the whole point of using a vector store).
        n = max(1, len(rows))
        cands = [(_from_mem0(r), 1.0 - i / n) for i, r in enumerate(rows)]
        if scope is not None:
            cands = [(c, s) for c, s in cands if c.scope == scope or c.scope == "global"]
        if kind is not None:
            cands = [(c, s) for c, s in cands if c.kind == kind]
        cands = [(c, s) for c, s in cands if c.trust != Trust.REJECTED]
        scored = sorted(cands, key=lambda cs: rank(cs[0], cs[1]), reverse=True)
        top = [c for c, _ in scored][:k]
        for c in top:  # recall reinforces retrieval_strength only (testing effect)
            c.retrieval_strength = min(1.0, c.retrieval_strength + 0.3)
            c.last_recall_ts = ts or c.last_recall_ts
            self._persist(c, self._mem0_id_for(c.id))
        return top

    def _adjust(self, record_id, *, ec=0.0, support=0, trust=None, confirm=False):
        r = self.get(record_id)
        if r is None:
            return None
        r.epistemic_confidence = max(0.0, min(1.0, r.epistemic_confidence + ec))
        r.support_count += support
        if trust is not None:
            r.trust = trust
        if confirm:
            r.with_detail(volatile=False)
        self._persist(r, self._mem0_id_for(record_id))
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

    def annotate(self, record_id, **detail):
        """Merge `detail` into a record WITHOUT touching trust/confidence/support."""
        r = self.get(record_id)
        if r is None:
            return None
        r.with_detail(**detail)
        self._persist(r, self._mem0_id_for(record_id))
        return r

    def set_flags(self, record_id, *, pinned=None, volatile=None, ttl_s=None):
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
        self._persist(r, self._mem0_id_for(record_id))
        return r

    def pin(self, record_id):
        return self.set_flags(record_id, pinned=True)

    def unpin(self, record_id):
        return self.set_flags(record_id, pinned=False)

    def decay(self, *, half_life_s: float = 604800.0, now: float = 0.0,
              stale_after_s: float = STALE_AFTER_S, volatile_ttl_s: float = VOLATILE_TTL_S) -> int:
        pruned = 0
        for row in self._rows():
            r = _from_mem0(row)
            if apply_decay(r, now=now, half_life_s=half_life_s,
                           stale_after_s=stale_after_s, volatile_ttl_s=volatile_ttl_s):
                self.client.delete(row["id"])
                pruned += 1
            else:
                self._persist(r, row["id"])
        return pruned

    def all(self, *, scope=None, kind=None):
        recs = [_from_mem0(r) for r in self._rows()]
        if scope is not None:
            recs = [r for r in recs if r.scope == scope]
        if kind is not None:
            recs = [r for r in recs if r.kind == kind]
        return recs


def make_ollama_mem0(*, user_id: str = "verel", store_path: str | None = None,
                     vector_store: dict | None = None) -> Mem0Memory:
    """Build a real mem0 (>=2.0) MemoryView. LLM auto-extraction is OFF (`infer=False`), so
    the LLM is essentially unused; an OpenAI embedder powers vector recall (Ollama Cloud has
    no embeddings endpoint). Defaults to a local Chroma store. Requires `verel[mem0]`.
    """
    import tempfile
    from pathlib import Path

    from mem0 import Memory  # lazy: optional dependency

    ol_key = (Path.home() / ".config" / "ollama" / "key")
    cfg = {
        "llm": {"provider": "openai", "config": {
            "model": "qwen3-coder:480b", "openai_base_url": "https://ollama.com/v1",
            "api_key": ol_key.read_text().strip() if ol_key.exists() else "ollama"}},
        "embedder": {"provider": "openai", "config": {"model": "text-embedding-3-small"}},
        "vector_store": vector_store or {"provider": "chroma", "config": {
            "path": store_path or tempfile.mkdtemp(prefix="verel-mem0-"),
            "collection_name": "verel_memory"}},
    }
    return Mem0Memory(Memory.from_config(cfg), user_id=user_id)
