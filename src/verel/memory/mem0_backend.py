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
    MemoryKind,
    MemoryRecord,
    MemoryView,
    Trust,
    make_id,
    make_key,
    rank,
    relevance,
    should_prune,
)

_META_FIELDS = (
    "kind", "subject", "predicate", "scope", "subj_pred_key", "source", "trust",
    "epistemic_confidence", "retrieval_strength", "support_count", "created_ts",
    "last_recall_ts", "detail_json", "provenance", "verel_id",
)


class Mem0Client(Protocol):
    def add(self, messages, *, user_id: str, metadata: dict, infer: bool) -> dict: ...
    def get_all(self, *, user_id: str) -> dict: ...
    def search(self, query: str, *, user_id: str, limit: int) -> dict: ...
    def update(self, memory_id: str, data) -> dict: ...
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
        return (self.client.get_all(user_id=self.user_id) or {}).get("results", [])

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
            self.client.update(mem0_id, {"memory": r.text, "metadata": _to_metadata(r)})

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
                self._persist(existing, mem0_id)
                return existing
            record.support_count = 1
            record.retrieval_strength = 1.0
            record.with_detail(superseded=existing.text)
        self._persist(record, mem0_id)
        return record

    def get(self, record_id: str) -> MemoryRecord | None:
        for row in self._rows():
            if (row.get("metadata") or {}).get("verel_id") == record_id:
                return _from_mem0(row)
        return None

    def recall(self, query: str, *, scope=None, kind=None, k: int = 5, ts: float = 0.0):
        res = self.client.search(query, user_id=self.user_id, limit=max(k * 4, 20)) or {}
        cands = [_from_mem0(r) for r in res.get("results", [])]
        if scope is not None:
            cands = [c for c in cands if c.scope == scope or c.scope == "global"]
        if kind is not None:
            cands = [c for c in cands if c.kind == kind]
        cands = [c for c in cands if c.trust != Trust.REJECTED]
        scored = sorted(cands, key=lambda c: rank(c, relevance(query, c)), reverse=True)
        top = [c for c in scored if relevance(query, c) > 0][:k]
        for c in top:  # recall reinforces retrieval_strength only (testing effect)
            c.retrieval_strength = min(1.0, c.retrieval_strength + 0.3)
            c.last_recall_ts = ts or c.last_recall_ts
            self._persist(c, self._mem0_id_for(c.id))
        return top

    def _adjust(self, record_id, *, ec=0.0, support=0, trust=None):
        r = self.get(record_id)
        if r is None:
            return None
        r.epistemic_confidence = max(0.0, min(1.0, r.epistemic_confidence + ec))
        r.support_count += support
        if trust is not None:
            r.trust = trust
        self._persist(r, self._mem0_id_for(record_id))
        return r

    def corroborate(self, record_id, *, delta: float = 0.15):
        return self._adjust(record_id, ec=delta, support=1)

    def contradict(self, record_id, *, delta: float = 0.25):
        r = self._adjust(record_id, ec=-delta)
        if r is not None and r.epistemic_confidence < 0.2:
            r = self._adjust(record_id, trust=Trust.REJECTED)
        return r

    def promote(self, record_id):
        return self._adjust(record_id, trust=Trust.VERIFIED)

    def demote(self, record_id):
        return self._adjust(record_id, trust=Trust.CANDIDATE)

    def decay(self, *, half_life_s: float = 604800.0, now: float = 0.0) -> int:
        import math

        pruned = 0
        for row in self._rows():
            r = _from_mem0(row)
            ref = r.last_recall_ts or r.created_ts
            if now and ref:
                r.retrieval_strength *= math.pow(0.5, max(0.0, now - ref) / half_life_s)
            if should_prune(r):
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


def make_ollama_mem0(*, user_id: str = "verel", embedder: str = "openai",
                     vector_store: dict | None = None) -> Mem0Memory:
    """Build a real mem0-backed MemoryView wired to Ollama Cloud for any LLM use.

    LLM auto-extraction is OFF (`infer=False` on writes), so the LLM is essentially unused;
    an embedder is still required for vector recall (`openai` by default — uses ~/.config
    keys via env). Requires the `verel[mem0]` extra.
    """
    from pathlib import Path

    from mem0 import Memory  # lazy: optional dependency

    ol_key = (Path.home() / ".config" / "ollama" / "key")
    cfg = {
        "llm": {
            "provider": "openai",
            "config": {
                "model": "qwen3-coder:480b",
                "openai_base_url": "https://ollama.com/v1",
                "api_key": ol_key.read_text().strip() if ol_key.exists() else "ollama",
            },
        },
        "embedder": {"provider": embedder},
    }
    if vector_store:
        cfg["vector_store"] = vector_store
    return Mem0Memory(Memory.from_config(cfg), user_id=user_id)
