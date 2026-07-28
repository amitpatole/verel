"""Mutation audit — MemoryAudit hash-chained log + AuditedMemory wrapper.

Pins: every trust-layer mutation lands in the log with actor/action/before/after; the chain is
tamper-evident; entries are bounded; recall (reachability bookkeeping) is deliberately NOT logged.
"""

import json

from memory_contract import make_fact

from verel.memory import AuditedMemory, LocalMemory, MemoryAudit
from verel.memory.view import Trust


def _audited(tmp_path, actor="cli:tester"):
    audit = MemoryAudit(tmp_path / "audit.jsonl")
    return AuditedMemory(LocalMemory(":memory:"), audit, actor=actor), audit


def test_write_is_logged_with_actor_and_snapshots(tmp_path):
    mem, audit = _audited(tmp_path)
    r = mem.write(make_fact())
    entries = audit.entries()
    assert len(entries) == 1
    e = entries[0]
    assert e["actor"] == "cli:tester"
    assert e["action"] == "write"
    assert e["record_id"] == r.id
    assert e["before"] is None
    assert e["after"]["trust"] == "candidate"


def test_trust_transitions_are_logged_before_and_after(tmp_path):
    mem, audit = _audited(tmp_path)
    r = mem.write(make_fact())
    mem.promote(r.id)
    e = audit.entries(r.id)[-1]
    assert e["action"] == "promote"
    assert e["before"]["trust"] == "candidate" and e["after"]["trust"] == "verified"


def test_contradict_to_rejection_is_traceable(tmp_path):
    mem, audit = _audited(tmp_path)
    r = mem.write(make_fact())
    for _ in range(5):
        mem.contradict(r.id)
    assert mem.get(r.id).trust == Trust.REJECTED
    actions = [e["action"] for e in audit.entries(r.id)]
    assert actions.count("contradict") == 5
    assert audit.entries(r.id)[-1]["after"]["trust"] == "rejected"


def test_chain_verifies_clean_and_detects_tamper(tmp_path):
    mem, audit = _audited(tmp_path)
    r = mem.write(make_fact())
    mem.promote(r.id)
    ok, reason = audit.verify()
    assert ok, reason
    # tamper: flip the recorded actor on the first line
    lines = audit.path.read_text().splitlines()
    e = json.loads(lines[0])
    e["actor"] = "cli:mallory"
    lines[0] = json.dumps(e, sort_keys=True, separators=(",", ":"))
    audit.path.write_text("\n".join(lines) + "\n")
    ok, reason = MemoryAudit(audit.path).verify()
    assert not ok and ("hash mismatch" in reason or "chain break" in reason)


def test_torn_tail_line_is_fail_visible(tmp_path):
    mem, audit = _audited(tmp_path)
    mem.write(make_fact())
    with audit.path.open("a", encoding="utf-8") as f:
        f.write('{"actor": "torn')  # simulated crash mid-append
    ok, reason = MemoryAudit(audit.path).verify()
    assert not ok and "unparseable" in reason


def test_entries_are_bounded_against_attacker_length_values(tmp_path):
    mem, audit = _audited(tmp_path, actor="x" * 10_000)
    mem.write(make_fact(text="A" * 100_000))
    e = audit.entries()[0]
    assert len(e["actor"]) <= 120
    assert len(e["after"]["text"]) <= 120


def test_recall_is_not_logged(tmp_path):
    mem, audit = _audited(tmp_path)
    mem.write(make_fact())
    n = len(audit.entries())
    mem.recall("max-width card width", scope="repo:x")
    assert len(audit.entries()) == n  # reachability bookkeeping, not a belief mutation


def test_wrapper_is_a_memoryview_dropin(tmp_path):
    from verel.memory.view import MemoryView
    mem, _ = _audited(tmp_path)
    assert isinstance(mem, MemoryView)


def test_decay_prunes_are_logged_as_summary(tmp_path):
    mem, audit = _audited(tmp_path)
    rec = make_fact(subject="weak", predicate="p")
    rec.retrieval_strength, rec.epistemic_confidence = 0.1, 0.3
    mem.inner.apply_replica(rec)  # seed via inner: exact field values, not part of this audit test
    pruned = mem.decay(now=10_000_000.0)
    assert pruned == 1
    e = audit.entries()[-1]
    assert e["action"] == "decay" and "pruned" in (e.get("extra") or "")
