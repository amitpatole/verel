"""Negative evals — regression suite asserting what memory must NOT surface or allow.

The positive path (what recall returns) is tested elsewhere; this suite pins the negative space:
a REJECTED fact is invisible to EVERY recall path, un-resurrectable by re-assertion, un-launderable
by supersede-then-restate, and its tombstone survives decay. The same checks also run inside the
cross-backend contract (tests/memory_contract.py CONTRACT_CHECKS → local/fakemem0 here,
postgres/lancedb/redis in their live-instance modules); this module additionally covers every
LocalMemory recall variant (FTS5 BM25, token-overlap fallback, embedder/cosine) and the budgeted
prompt renderer.
"""

import pytest
from memory_contract import (
    check_correction_chain_is_bounded,
    check_recall_excludes_rejected,
    check_rejected_reassert_does_not_resurrect,
    check_rejected_tombstone_survives_decay_and_stays_hidden,
    check_rejection_populates_durable_ledger,
    check_supersede_carries_rejected_ledger,
    make_fact,
)
from test_mem0_backend import FakeMem0

from verel.memory import LocalMemory, Mem0Memory, recall_budgeted
from verel.memory.embed import HashEmbedder
from verel.memory.view import Trust

NEGATIVE_CHECKS = [
    check_recall_excludes_rejected,
    check_rejected_reassert_does_not_resurrect,
    check_rejection_populates_durable_ledger,
    check_supersede_carries_rejected_ledger,
    check_rejected_tombstone_survives_decay_and_stays_hidden,
    check_correction_chain_is_bounded,
]


def _local_fts():
    return LocalMemory(":memory:")


def _local_fallback():
    m = LocalMemory(":memory:")
    m._fts = False  # force the pre-1.3.0 token-overlap recall path
    return m


def _local_embedder():
    return LocalMemory(":memory:", embedder=HashEmbedder())


def _fakemem0():
    return Mem0Memory(FakeMem0(), user_id="negeval")


BACKENDS = {
    "local-fts": _local_fts,
    "local-fallback": _local_fallback,
    "local-embedder": _local_embedder,
    "fakemem0": _fakemem0,
}


@pytest.mark.parametrize("backend", BACKENDS.values(), ids=list(BACKENDS))
@pytest.mark.parametrize("check", NEGATIVE_CHECKS, ids=lambda c: c.__name__)
def test_negative_eval(check, backend):
    check(backend())


def _rejected_store():
    mem = LocalMemory(":memory:")
    r = mem.write(make_fact(text="the paris office closed"))
    for _ in range(5):
        mem.contradict(r.id)
    assert mem.get(r.id).trust == Trust.REJECTED
    return mem, r


def test_budgeted_recall_never_renders_rejected_content():
    """The prompt-facing surface: a rejected fact must not appear in the fenced context block."""
    mem, r = _rejected_store()
    out = recall_budgeted(mem, "paris office closed", token_budget=500, scope="repo:x")
    assert all(rec.id != r.id for rec in out.records)
    assert "paris office" not in out.text


def test_rejected_invisible_even_with_exact_verbatim_query():
    """An attacker who knows the rejected text verbatim still can't recall it."""
    mem, r = _rejected_store()
    assert all(h.id != r.id for h in mem.recall("the paris office closed", scope="repo:x", k=100))


def test_rejected_excluded_without_scope_filter():
    """The rejected filter must not depend on the caller passing a scope."""
    mem, r = _rejected_store()
    assert all(h.id != r.id for h in mem.recall("the paris office closed", k=100))
