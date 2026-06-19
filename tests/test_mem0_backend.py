"""mem0 backend adapter (§5.3) — tested against a fake mem0 client so the FULL MemoryView
contract is verified offline. The same adapter drives real mem0 (verel[mem0])."""

import itertools

from verel.memory import MemoryKind, MemoryRecord, Trust
from verel.memory.mem0_backend import Mem0Memory


class FakeMem0:
    """In-memory stand-in for mem0.Memory >= 2.0 (filters=; update(id, data, metadata=))."""

    def __init__(self):
        self.rows: dict[str, dict] = {}
        self._ids = itertools.count(1)

    def add(self, messages, *, user_id, metadata, infer):
        mid = f"m{next(self._ids)}"
        self.rows[mid] = {"id": mid, "memory": messages[0]["content"], "metadata": dict(metadata)}
        return {"results": [{"id": mid}]}

    def get_all(self, *, filters):
        return {"results": list(self.rows.values())}

    def search(self, query, *, filters, limit):
        return {"results": list(self.rows.values())[:limit]}  # adapter re-ranks anyway

    def update(self, memory_id, data, metadata=None):
        if memory_id in self.rows:
            self.rows[memory_id]["memory"] = data
            if metadata is not None:
                self.rows[memory_id]["metadata"] = metadata
        return {"id": memory_id}

    def delete(self, memory_id):
        self.rows.pop(memory_id, None)
        return {}

    def get(self, memory_id):
        return self.rows.get(memory_id)


def _mem():
    return Mem0Memory(FakeMem0(), user_id="t")


def _fact(text="use max-width:100%", subject="card", predicate="width", scope="repo:x"):
    return MemoryRecord(kind=MemoryKind.FACT, subject=subject, predicate=predicate, text=text, scope=scope)


def test_write_get_roundtrip_preserves_trust_fields():
    m = _mem()
    r = m.write(_fact())
    got = m.get(r.id)
    assert got is not None and got.text == "use max-width:100%"
    assert got.trust == Trust.CANDIDATE and got.epistemic_confidence == 0.5


def test_interference_supersede_does_not_duplicate():
    m = _mem()
    a = m.write(_fact(text="use width:100%"))
    b = m.write(_fact(text="use max-width:100%"))  # same subject+predicate+scope
    assert a.id == b.id
    assert len([r for r in m.all() if r.id == a.id]) == 1
    assert m.get(a.id).text == "use max-width:100%"


def test_corroborate_and_contradict():
    m = _mem()
    r = m.write(_fact())
    assert m.corroborate(r.id).epistemic_confidence > 0.5
    for _ in range(5):
        last = m.contradict(r.id)
    assert last.trust == Trust.REJECTED


def test_recall_ranks_and_reinforces_strength():
    m = _mem()
    r = m.write(_fact())
    r.retrieval_strength = 0.2
    m._persist(r, m._mem0_id_for(r.id))
    hits = m.recall("max-width card", scope="repo:x")
    assert hits and hits[0].id == r.id
    assert m.get(r.id).retrieval_strength > 0.2  # reinforced by recall


def test_promote_and_decay_prune():
    m = _mem()
    r = m.write(_fact())
    assert m.promote(r.id).trust == Trust.VERIFIED
    # verified is never pruned even when weak
    weak = m.write(_fact(text="weak claim", subject="z", predicate="q"))
    weak.retrieval_strength, weak.epistemic_confidence, weak.support_count = 0.1, 0.3, 1
    m._persist(weak, m._mem0_id_for(weak.id))
    pruned = m.decay(now=10_000_000.0)
    assert pruned == 1 and m.get(weak.id) is None and m.get(r.id) is not None


def test_is_memoryview_compatible():
    from verel.memory.view import MemoryView

    assert isinstance(_mem(), MemoryView)


# ---- real mem0 live smoke (gated; needs verel[mem0] + OpenAI key + VEREL_MEM0_SMOKE=1) ----
def test_real_mem0_roundtrip():
    import os

    if os.environ.get("VEREL_MEM0_SMOKE") != "1":
        import pytest

        pytest.skip("set VEREL_MEM0_SMOKE=1 (and OPENAI_API_KEY) to run the live mem0 smoke")
    import tempfile

    from mem0 import Memory  # noqa: F401

    from verel.memory import MemoryKind, MemoryRecord, Trust, make_ollama_mem0

    mem = make_ollama_mem0(user_id="smoke", store_path=tempfile.mkdtemp())
    r = mem.write(MemoryRecord(kind=MemoryKind.DESIGN_RULE, subject="overflow",
                               predicate="rule", text="use max-width:100% not fixed px",
                               scope="repo:x"))
    assert mem.get(r.id) is not None and mem.get(r.id).trust == Trust.CANDIDATE
    mem.promote(r.id)
    assert mem.get(r.id).trust == Trust.VERIFIED
    hits = mem.recall("element overflows the viewport", scope="repo:x", k=3)
    assert any("max-width" in h.text for h in hits)  # semantic recall via real vectors
