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
from verel.memory.view import MAX_CORRECTIONS, MemoryView, rejected_key


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


# ---- negative evals: what memory must NOT do (rejected = durable, un-launderable) ----
def _reject(mem: MemoryView, record_id: str) -> None:
    for _ in range(5):
        mem.contradict(record_id)  # drive trust to REJECTED via the backend's own path
    assert mem.get(record_id).trust == Trust.REJECTED


def check_rejected_reassert_does_not_resurrect(mem: MemoryView) -> None:
    """Re-stating a REJECTED value must not raise its confidence/support or reset its decay
    (round-6 M2) — and it must stay invisible to recall."""
    r = mem.write(make_fact())
    _reject(mem, r.id)
    before = mem.get(r.id)
    again = mem.write(make_fact())  # the same rejected claim, re-asserted
    assert again.trust == Trust.REJECTED
    after = mem.get(r.id)
    assert after.trust == Trust.REJECTED
    assert after.epistemic_confidence <= before.epistemic_confidence
    assert after.support_count == before.support_count
    assert all(h.id != r.id for h in mem.recall("max-width card width", scope="repo:x"))


def check_rejection_populates_durable_ledger(mem: MemoryView) -> None:
    """The contradict → REJECTED transition must brand the VALUE in `rejected_values`, on every
    backend — the ledger the promotion gate and operator review consult (round-7 C1)."""
    r = mem.write(make_fact())
    _reject(mem, r.id)
    ledger = mem.get(r.id).detail.get("rejected_values", [])
    assert rejected_key(make_fact().text) in ledger


def check_supersede_carries_rejected_ledger(mem: MemoryView) -> None:
    """Supersede-then-restate must not launder a rejected value: the ledger travels across
    supersessions, so the restated value arrives already branded (round-7 C1)."""
    r = mem.write(make_fact(text="the lie"))
    _reject(mem, r.id)
    mem.write(make_fact(text="a throwaway value"))       # supersede the rejected record
    assert rejected_key("the lie") in mem.get(r.id).detail.get("rejected_values", [])
    mem.write(make_fact(text="the lie"))                 # restate the once-rejected value
    fresh = mem.get(r.id)
    assert rejected_key("the lie") in fresh.detail.get("rejected_values", [])


def check_rejected_tombstone_survives_decay_and_stays_hidden(mem: MemoryView) -> None:
    """A REJECTED record is a durable tombstone: decay/prune must not erase it (that would reopen
    the launder, round-8), and it must remain invisible to recall afterwards."""
    r = mem.write(make_fact())
    _reject(mem, r.id)
    mem.decay(now=10_000_000.0)
    tomb = mem.get(r.id)
    assert tomb is not None and tomb.trust == Trust.REJECTED
    assert all(h.id != r.id for h in mem.recall("max-width card width", scope="repo:x"))


def check_promote_refuses_rejected_value(mem: MemoryView) -> None:
    """The primitive `promote()` must refuse a REJECTED value directly — the guard lives in the
    primitive so every caller (CLI review, MCP remember, PromotionGate) inherits it (round-13/C1)."""
    r = mem.write(make_fact())
    _reject(mem, r.id)
    mem.promote(r.id)  # attempt to launder straight through the primitive
    assert mem.get(r.id).trust == Trust.REJECTED  # refused — never VERIFIED
    assert all(h.id != r.id for h in mem.recall("max-width card width", scope="repo:x"))


def check_promote_refuses_restated_once_rejected_value(mem: MemoryView) -> None:
    """A once-rejected value, superseded then restated back to CANDIDATE, is still un-promotable via
    the primitive because the durable ledger is consulted (round-13/C1)."""
    r = mem.write(make_fact(text="the lie"))
    _reject(mem, r.id)
    mem.write(make_fact(text="throwaway"))     # supersede -> CANDIDATE, ledger carried
    mem.write(make_fact(text="the lie"))       # restate the once-rejected value
    assert mem.get(r.id).trust == Trust.CANDIDATE
    mem.promote(r.id)
    assert mem.get(r.id).trust != Trust.VERIFIED  # ledger blocks the restated value


def check_ledger_saturation_blocks_promotion(mem: MemoryView) -> None:
    """Rejecting more distinct values than the ledger can hold must NOT evict the target off the
    front and let it launder — the key SATURATES and all promotions are blocked (round-13/C3)."""
    from verel.memory.view import MAX_REJECTED_VALUES
    target = mem.write(make_fact(text="the target lie"))
    _reject(mem, target.id)
    for i in range(MAX_REJECTED_VALUES + 5):   # supersede-reject enough distinct values to overflow
        mem.write(make_fact(text=f"decoy value {i}"))
        _reject(mem, target.id)
    mem.write(make_fact(text="the target lie"))  # restate the (now evicted from the list) target
    assert mem.get(target.id).detail.get("rejected_saturated") is True
    mem.promote(target.id)
    assert mem.get(target.id).trust != Trust.VERIFIED  # saturated key can't be promoted


def check_legit_candidate_still_promotes(mem: MemoryView) -> None:
    """The guard must not over-block: a never-rejected CANDIDATE promotes normally."""
    r = mem.write(make_fact(text="genuinely fine"))
    assert mem.get(r.id).trust == Trust.CANDIDATE
    mem.promote(r.id)
    assert mem.get(r.id).trust == Trust.VERIFIED


def check_apply_replica_cannot_launder_rejected(mem: MemoryView) -> None:
    """The verbatim-upsert replication primitive must not let a peer resurrect a rejected value:
    a replica of a once-rejected value (even trust=VERIFIED, empty detail) is forced back to a
    REJECTED tombstone — not recallable, not promotable (round-14/A)."""
    r = mem.write(make_fact())
    _reject(mem, r.id)
    laundered = make_fact()
    laundered.id = r.id
    laundered.trust = Trust.VERIFIED  # hostile peer claims verified, drops the ledger
    mem.apply_replica(laundered)
    after = mem.get(r.id)
    assert after.trust == Trust.REJECTED  # forced back to tombstone, not VERIFIED/CANDIDATE
    assert after.detail.get("rejected_values")  # local ledger preserved, not dropped
    assert all(h.id != r.id for h in mem.recall("max-width card width", scope="repo:x"))


def check_apply_replica_preserves_local_ledger(mem: MemoryView) -> None:
    """A replica carrying a DIFFERENT (never-rejected) value at a rejected key keeps the local
    ledger, so the once-rejected value stays un-promotable afterwards (round-14/A)."""
    r = mem.write(make_fact(text="old lie"))
    _reject(mem, r.id)
    newval = make_fact(text="a fresh distinct value")
    newval.id = r.id
    newval.trust = Trust.VERIFIED
    mem.apply_replica(newval)
    after = mem.get(r.id)
    assert after.trust == Trust.VERIFIED           # a genuinely new value may be verified
    assert rejected_key("old lie") in after.detail.get("rejected_values", [])  # ledger preserved


def check_demote_cannot_unreject(mem: MemoryView) -> None:
    """Rejection is durable: demote must not move a REJECTED tombstone back to a recallable
    candidate (round-14/C-2). Walking back a VERIFIED promotion is still allowed."""
    r = mem.write(make_fact())
    _reject(mem, r.id)
    mem.demote(r.id)
    assert mem.get(r.id).trust == Trust.REJECTED
    assert all(h.id != r.id for h in mem.recall("max-width card width", scope="repo:x"))
    # sanity: demote still works on a legitimately VERIFIED record
    g = mem.write(make_fact(text="fine", subject="ok", predicate="q"))
    mem.promote(g.id)
    mem.demote(g.id)
    assert mem.get(g.id).trust == Trust.CANDIDATE


def check_correction_chain_is_bounded(mem: MemoryView) -> None:
    """Repeated supersessions must not grow one record's detail without bound (round-11 B) —
    the chain is capped at the shared MAX_CORRECTIONS on every backend."""
    r = mem.write(make_fact(text="v0"))
    for i in range(1, MAX_CORRECTIONS + 10):
        mem.write(make_fact(text=f"v{i}"))
    chain = mem.get(r.id).detail.get("corrections", [])
    assert 0 < len(chain) <= MAX_CORRECTIONS


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
    check_rejected_reassert_does_not_resurrect,
    check_rejection_populates_durable_ledger,
    check_supersede_carries_rejected_ledger,
    check_rejected_tombstone_survives_decay_and_stays_hidden,
    check_promote_refuses_rejected_value,
    check_promote_refuses_restated_once_rejected_value,
    check_ledger_saturation_blocks_promotion,
    check_legit_candidate_still_promotes,
    check_apply_replica_cannot_launder_rejected,
    check_apply_replica_preserves_local_ledger,
    check_demote_cannot_unreject,
    check_correction_chain_is_bounded,
    check_decay_prunes_only_on_exact_conjunction,
    check_decay_leaves_confidence_invariant,
    check_pinned_exempt_from_decay,
    check_is_memoryview,
]
