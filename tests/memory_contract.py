"""The reusable MemoryView contract — the trust-layer invariants EVERY backend must satisfy.

These are the load-bearing rules from `view.py`'s module docstring, written as backend-agnostic
checks so a new store (Postgres, LanceDB, Redis, a third-party plugin) is proven correct by
reusing this harness instead of copy-pasting assertions. Each check:

- takes a FRESH, empty `mem` (a `MemoryView`),
- sets up state through the PUBLIC Protocol only — in particular `apply_replica()` is the portable
  way to force exact field values (it upserts a record verbatim, no corroboration), so no backend
  needs a private test hook,
- asserts ONE invariant.

`CONTRACT_CHECKS` lists every check; `tests/test_memory_contract.py` parametrizes it over the
in-tree backends, and each external-backend test module reuses it against a live instance.
"""

from __future__ import annotations

from verel.memory import MemoryKind, MemoryRecord, Trust
from verel.memory.view import MemoryView


def make_fact(text="use max-width:100%", subject="card", predicate="width", scope="repo:x"):
    return MemoryRecord(kind=MemoryKind.FACT, subject=subject, predicate=predicate, text=text,
                        scope=scope)


def _seed(mem: MemoryView, rec: MemoryRecord) -> MemoryRecord:
    """Persist `rec` verbatim (exact field values) via the public `apply_replica` — the portable
    way to force state (e.g. a low retrieval_strength) without poking a backend's internals."""
    return mem.apply_replica(rec)


# ---- the two orthogonal signals, never collapsed ---------------------------
def check_corroborate_raises_confidence_and_support(mem: MemoryView) -> None:
    r = mem.write(make_fact())
    assert r.epistemic_confidence == 0.5
    r2 = mem.corroborate(r.id)
    assert r2 is not None
    assert r2.epistemic_confidence > 0.5 and r2.support_count == 2


def check_contradict_lowers_and_eventually_rejects(mem: MemoryView) -> None:
    r = mem.write(make_fact())
    last = r
    for _ in range(5):
        last = mem.contradict(r.id)
    assert last is not None and last.trust == Trust.REJECTED


def check_recall_reinforces_strength_not_confidence(mem: MemoryView) -> None:
    r = mem.write(make_fact())
    r.retrieval_strength = 0.3
    _seed(mem, r)
    before_conf = mem.get(r.id).epistemic_confidence
    hits = mem.recall("max-width card width", scope="repo:x")
    assert hits and hits[0].retrieval_strength > 0.3  # testing effect
    assert hits[0].epistemic_confidence == before_conf  # truth untouched by retrieval


# ---- the interference rule -------------------------------------------------
def check_same_text_corroborates_one_row(mem: MemoryView) -> None:
    a = mem.write(make_fact())
    b = mem.write(make_fact())  # identical claim again
    assert a.id == b.id
    assert len([r for r in mem.all() if r.id == a.id]) == 1
    assert mem.get(a.id).support_count == 2


def check_different_text_supersedes_with_correction_chain(mem: MemoryView) -> None:
    a = mem.write(make_fact(text="use width:100%"))
    b = mem.write(make_fact(text="use max-width:100%"))  # same subject+predicate+scope
    assert a.id == b.id  # same interference key
    assert len([r for r in mem.all() if r.id == a.id]) == 1  # superseded, not duplicated
    got = mem.get(a.id)
    assert got.text == "use max-width:100%"
    assert got.detail.get("superseded") == "use width:100%"
    assert any(c.get("text") == "use width:100%" for c in got.detail.get("corrections", []))


# ---- replication ------------------------------------------------------------
def check_apply_replica_verbatim_and_idempotent(mem: MemoryView) -> None:
    rec = make_fact(text="canonical", subject="leader", predicate="state")
    rec.epistemic_confidence = 0.83
    rec.support_count = 7
    rec.retrieval_strength = 0.41
    first = mem.apply_replica(rec)
    snap1 = mem.get(first.id).model_dump()
    mem.apply_replica(rec)  # re-deliver
    snap2 = mem.get(first.id).model_dump()
    assert snap1 == snap2  # idempotent
    assert snap2["epistemic_confidence"] == 0.83 and snap2["support_count"] == 7  # verbatim, no merge
    assert len([r for r in mem.all() if r.id == first.id]) == 1


# ---- recall filtering -------------------------------------------------------
def check_recall_excludes_rejected(mem: MemoryView) -> None:
    r = mem.write(make_fact())
    for _ in range(5):
        mem.contradict(r.id)  # drive trust to REJECTED
    assert mem.get(r.id).trust == Trust.REJECTED
    assert all(h.id != r.id for h in mem.recall("max-width card width", scope="repo:x"))


# ---- decay / prune ----------------------------------------------------------
def _weak(subject, predicate, *, trust=Trust.CANDIDATE, support=1, ec=0.3, rs=0.1):
    rec = make_fact(text="weak", subject=subject, predicate=predicate)
    rec.trust, rec.support_count, rec.epistemic_confidence, rec.retrieval_strength = (
        trust, support, ec, rs)
    return rec


def check_decay_prunes_only_on_exact_conjunction(mem: MemoryView) -> None:
    _seed(mem, _weak("a", "p"))                                   # all four hold → pruned
    _seed(mem, _weak("b", "p", trust=Trust.VERIFIED))            # verified saves it
    _seed(mem, _weak("c", "p", support=2))                       # support_count>=2 saves it
    pruned = mem.decay(now=10_000_000.0)
    ids = {r.subject for r in mem.all()}
    assert pruned == 1
    assert "a" not in ids and "b" in ids and "c" in ids


def check_decay_leaves_confidence_invariant(mem: MemoryView) -> None:
    r = mem.write(make_fact())
    mem.promote(r.id)  # verified → never pruned, so it survives decay
    before = mem.get(r.id).epistemic_confidence
    mem.decay(now=10_000_000.0)
    after = mem.get(r.id)
    assert after is not None and after.epistemic_confidence == before  # decay never moves truth


def check_pinned_exempt_from_decay(mem: MemoryView) -> None:
    rec = _weak("pinme", "p")
    _seed(mem, rec)
    mem.pin(rec.id)
    mem.decay(now=10_000_000.0)
    assert mem.get(rec.id) is not None  # pinned ignores decay entirely


# ---- protocol conformance ---------------------------------------------------
def check_is_memoryview(mem: MemoryView) -> None:
    assert isinstance(mem, MemoryView)


CONTRACT_CHECKS = [
    check_corroborate_raises_confidence_and_support,
    check_contradict_lowers_and_eventually_rejects,
    check_recall_reinforces_strength_not_confidence,
    check_same_text_corroborates_one_row,
    check_different_text_supersedes_with_correction_chain,
    check_apply_replica_verbatim_and_idempotent,
    check_recall_excludes_rejected,
    check_decay_prunes_only_on_exact_conjunction,
    check_decay_leaves_confidence_invariant,
    check_pinned_exempt_from_decay,
    check_is_memoryview,
]
