"""Operator review — the human-in-the-loop path that resolves CANDIDATE facts.

Pins: the pending queue lists candidates only; approve promotes + records the reviewer; approve
FAILS CLOSED on rejected records AND on restated once-rejected values (anti-laundering); reject is
a durable tombstone invisible to recall; terminal rendering is ANSI/control-safe.
"""

import pytest
from memory_contract import make_fact

from verel.memory import LocalMemory
from verel.memory.review import (
    RejectedApprovalError,
    approve,
    pending,
    reject,
    render_line,
    render_record,
)
from verel.memory.view import Trust


def _mem_with_candidates(n=3):
    mem = LocalMemory(":memory:")
    recs = [mem.write(make_fact(text=f"value {i}", subject=f"s{i}", predicate="p"))
            for i in range(n)]
    return mem, recs


def test_pending_lists_only_candidates():
    mem, recs = _mem_with_candidates()
    mem.promote(recs[0].id)
    for _ in range(5):
        mem.contradict(recs[1].id)
    ids = {r.id for r in pending(mem)}
    assert recs[0].id not in ids and recs[1].id not in ids and recs[2].id in ids


def test_pending_orders_most_supported_first_then_oldest():
    mem = LocalMemory(":memory:")
    a = mem.write(make_fact(text="a", subject="a", predicate="p"), ts=100.0)
    b = mem.write(make_fact(text="b", subject="b", predicate="p"), ts=50.0)
    mem.write(make_fact(text="b", subject="b", predicate="p"))  # corroborate b -> support 2
    out = pending(mem)
    assert out[0].id == b.id and out[1].id == a.id


def test_approve_promotes_and_records_reviewer():
    mem, recs = _mem_with_candidates(1)
    r = approve(mem, recs[0].id, reviewed_by="alice")
    assert r is not None and r.trust == Trust.VERIFIED
    assert r.detail["review"] == "approved" and r.detail["reviewed_by"] == "alice"
    assert r.detail["reviewed_ts"] > 0


def test_approve_refuses_rejected_record():
    mem, recs = _mem_with_candidates(1)
    for _ in range(5):
        mem.contradict(recs[0].id)
    with pytest.raises(RejectedApprovalError):
        approve(mem, recs[0].id, reviewed_by="alice")
    assert mem.get(recs[0].id).trust == Trust.REJECTED  # unchanged


def test_approve_refuses_restated_once_rejected_value():
    """Supersede-then-restate leaves the value branded in the carried ledger; human approval must
    not launder it (round-7 C1 for the review path)."""
    mem = LocalMemory(":memory:")
    r = mem.write(make_fact(text="the lie"))
    for _ in range(5):
        mem.contradict(r.id)
    mem.write(make_fact(text="a throwaway"))
    mem.write(make_fact(text="the lie"))  # restated — CANDIDATE again, but ledger-branded
    assert mem.get(r.id).trust == Trust.CANDIDATE
    with pytest.raises(RejectedApprovalError):
        approve(mem, r.id, reviewed_by="alice")


def test_reject_is_durable_tombstone_and_unrecallable():
    mem, recs = _mem_with_candidates(1)
    r = reject(mem, recs[0].id, reviewed_by="alice", reason="wrong")
    assert r is not None and r.trust == Trust.REJECTED
    assert r.detail["review"] == "rejected" and r.detail["review_reason"] == "wrong"
    assert r.detail.get("rejected_values")  # anti-laundering ledger populated
    assert all(h.id != r.id for h in mem.recall("value 0 s0 p", k=100))


def test_missing_record_returns_none():
    mem = LocalMemory(":memory:")
    assert approve(mem, "nope", reviewed_by="a") is None
    assert reject(mem, "nope", reviewed_by="a") is None


def test_render_is_terminal_safe():
    """Stored content must not smuggle ANSI escapes / control chars / zero-width into the review
    terminal — an attacker could otherwise spoof what the operator approves."""
    mem = LocalMemory(":memory:")
    hostile = "ok\x1b[2J\x1b[1;31mAPPROVED\x07​‮ evil"
    r = mem.write(make_fact(text=hostile))
    for out in (render_line(mem.get(r.id)), render_record(mem.get(r.id))):
        assert "\x1b" not in out and "\x07" not in out
        assert "​" not in out and "‮" not in out


def test_reviewer_and_reason_are_bounded():
    mem, recs = _mem_with_candidates(1)
    r = reject(mem, recs[0].id, reviewed_by="x" * 10_000, reason="y" * 10_000)
    assert len(r.detail["reviewed_by"]) <= 120 and len(r.detail["review_reason"]) <= 200
