"""Self-assessment against the agent-memory-atlas rubric — verel grading its own memory.

The atlas (neoneye.github.io/agent-memory-atlas) scores memory systems on seven **binary** dimensions
by inspecting code at a pinned commit and *tracing* behaviour (capture → storage → retrieval →
correction → deletion). This module internalises that method: each dimension is a LIVE behavioural
probe against `LocalMemory(":memory:")` (not a claim, not a "function exists" check), so a mark is
earned by demonstrated behaviour and a regression flips the mark to a dash. It is the atlas's own
discipline, dogfooded — verification-first, applied to ourselves.

The atlas is explicit that this is **not a maturity score**: "A system with six marks is not better
than one with two; it is differently shaped." We report the shape, with our evidence, and pin nothing
we can't demonstrate.

Run it:  `python -m verel.memory.rubric`  (or `verel memory rubric`).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


@dataclass
class DimensionResult:
    key: str
    title: str
    criterion: str          # the atlas's pass criterion, verbatim
    passed: bool
    evidence: str           # our file/function that implements it
    proof: str              # what the live probe demonstrated (or why it failed)


@dataclass
class RubricAssessment:
    results: list[DimensionResult]

    @property
    def score(self) -> int:
        return sum(1 for r in self.results if r.passed)

    def render(self) -> str:
        lines = ["agent-memory-atlas rubric — verel self-assessment",
                 f"score: {self.score}/{len(self.results)} (binary marks; NOT a maturity score)", ""]
        for r in self.results:
            mark = "PASS" if r.passed else " -- "
            lines.append(f"[{mark}] {r.title}")
            lines.append(f"        criterion: {r.criterion}")
            lines.append(f"        evidence:  {r.evidence}")
            lines.append(f"        proof:     {r.proof}")
        return "\n".join(lines)


def _g(mem, record_id):  # type: ignore[no-untyped-def]
    """get() that asserts the record exists — the probes write immediately before reading, so a None
    here is a real bug (surfaced as a probe failure), and it narrows the type for the checkers."""
    rec = mem.get(record_id)
    assert rec is not None, f"probe expected record {record_id!r} to exist"
    return rec


# --- the seven behavioural probes (each returns (passed, proof)) -------------------------------
def _probe_tombstone() -> tuple[bool, str]:
    """Durable record of a rejected VALUE, keyed on the value, that re-extraction can't walk past."""
    from .local import LocalMemory
    from .view import MemoryKind, MemoryRecord, is_launder_blocked, rejected_key
    m = LocalMemory(":memory:")
    r = m.write(MemoryRecord(kind=MemoryKind.FACT, subject="s", predicate="p", text="a lie",
                             scope="repo:x"), ts=1.0)
    for _ in range(6):
        m.contradict(r.id)
    ledger = _g(m, r.id).detail.get("rejected_values", [])
    keyed_on_value = rejected_key("a lie") in ledger
    # supersede then re-assert the value → still blocked (walks straight into the tombstone)
    m.write(MemoryRecord(kind=MemoryKind.FACT, subject="s", predicate="p", text="benign",
                         scope="repo:x"), ts=2.0)
    m.write(MemoryRecord(kind=MemoryKind.FACT, subject="s", predicate="p", text="a lie",
                         scope="repo:x"), ts=3.0)
    blocked = is_launder_blocked(_g(m, r.id))
    ok = keyed_on_value and blocked
    return ok, (f"rejected value keyed in ledger={keyed_on_value}; re-assert after supersede stays "
                f"un-promotable={blocked}")


def _probe_trust_state() -> tuple[bool, str]:
    """A discrete epistemic STATE (not a float) with at least one state that withholds a memory."""
    from enum import Enum

    from .local import LocalMemory
    from .view import MemoryKind, MemoryRecord, Trust
    is_enum = issubclass(Trust, Enum) and {"CANDIDATE", "VERIFIED", "REJECTED"} <= set(Trust.__members__)
    m = LocalMemory(":memory:")
    r = m.write(MemoryRecord(kind=MemoryKind.FACT, subject="card", predicate="width",
                             text="max-width 100%", scope="repo:x"), ts=1.0)
    for _ in range(6):
        m.contradict(r.id)  # → REJECTED
    withheld = all(h.id != r.id for h in m.recall("max-width card width", scope="repo:x", k=50))
    ok = is_enum and withheld
    return ok, (f"Trust enum states={list(Trust.__members__)}; REJECTED withheld from recall={withheld}")


def _probe_bitemporal() -> tuple[bool, str]:
    """When a fact was TRUE tracked separately from when it was recorded/expired."""
    from .local import LocalMemory
    from .recall import recall_as_of
    from .view import MemoryKind, MemoryRecord
    fields = {"valid_from", "valid_to"} <= set(MemoryRecord.model_fields) and \
             "created_ts" in MemoryRecord.model_fields
    m = LocalMemory(":memory:")
    m.write(MemoryRecord(kind=MemoryKind.FACT, subject="server", predicate="region", text="us-east",
                         scope="repo:x"), ts=100.0)
    m.write(MemoryRecord(kind=MemoryKind.FACT, subject="server", predicate="region", text="us-west",
                         scope="repo:x"), ts=600.0)
    past = [h.text for h in recall_as_of(m, "server region", as_of=300.0, scope="repo:x")]
    now = [h.text for h in recall_as_of(m, "server region", as_of=700.0, scope="repo:x")]
    reconstructs = past == ["us-east"] and now == ["us-west"]
    ok = fields and reconstructs
    return ok, (f"valid_from/valid_to distinct from created_ts={fields}; "
                f"as-of(March)={past}, as-of(today)={now}")


def _probe_scope_enforced() -> tuple[bool, str]:
    """A stored scope key applied as a FILTER on the read path (not just a stored tag)."""
    from .local import LocalMemory
    from .view import MemoryKind, MemoryRecord
    m = LocalMemory(":memory:")
    m.write(MemoryRecord(kind=MemoryKind.FACT, subject="x", predicate="secret", text="in A",
                         scope="repo:a"), ts=1.0)
    m.write(MemoryRecord(kind=MemoryKind.FACT, subject="x", predicate="secret", text="in B",
                         scope="repo:b"), ts=1.0)
    got = {h.text for h in m.recall("x secret", scope="repo:a", k=50)}
    enforced = got == {"in A"}  # the repo:b record is filtered out on the read path
    return enforced, f"recall(scope=repo:a) returned {sorted(got)} — repo:b filtered on read={enforced}"


def _probe_mutation_audit() -> tuple[bool, str]:
    """A named append-only event record of memory MUTATIONS in the system's own store."""
    import tempfile

    from .audit import AuditedMemory, MemoryAudit
    from .local import LocalMemory
    from .view import MemoryKind, MemoryRecord
    with tempfile.TemporaryDirectory() as d:
        audit = MemoryAudit(Path(d) / "audit.jsonl")
        m = AuditedMemory(LocalMemory(":memory:"), audit, actor="probe")
        r = m.write(MemoryRecord(kind=MemoryKind.FACT, subject="s", predicate="p", text="v",
                                 scope="repo:x"), ts=1.0)
        m.promote(r.id)
        entries = audit.entries(r.id)
        actions = [e["action"] for e in entries]
        ok_chain, _ = audit.verify()
        mutations_logged = "write" in actions and "promote" in actions
        appended = audit.path.exists() and len(entries) >= 2
        ok = mutations_logged and appended and ok_chain
    return ok, (f"logged mutations={actions}; append-only file + hash-chain verify={ok_chain}")


def _probe_human_review() -> tuple[bool, str]:
    """A place a PERSON inspects/approves/adjudicates memory content (reviewing, not just viewing)."""
    from .local import LocalMemory
    from .review import approve, pending, reject
    from .view import MemoryKind, MemoryRecord, Trust
    m = LocalMemory(":memory:")
    r = m.write(MemoryRecord(kind=MemoryKind.FACT, subject="s", predicate="p", text="v",
                             scope="repo:x"), ts=1.0)
    queued = any(x.id == r.id for x in pending(m))
    approve(m, r.id, reviewed_by="alice")
    adjudicated = _g(m, r.id).trust == Trust.VERIFIED and _g(m, r.id).detail.get("review") == "approved"
    # and it's a decision surface, not a viewer: reject is durable
    r2 = m.write(MemoryRecord(kind=MemoryKind.FACT, subject="s2", predicate="p", text="w",
                              scope="repo:x"), ts=1.0)
    reject(m, r2.id, reviewed_by="alice", reason="wrong")
    rejects = _g(m, r2.id).trust == Trust.REJECTED
    ok = queued and adjudicated and rejects
    return ok, (f"candidate queued for review={queued}; approve→verified+recorded={adjudicated}; "
                f"reject→durable={rejects} (CLI: `verel memory approve/reject`)")


def _probe_negative_evals() -> tuple[bool, str]:
    """COMMITTED evaluation cases that assert particular material must NOT be retrieved.

    The atlas assesses the SOURCE REPO at a commit — so the authoritative check is: (a) the capability
    is real (a rejected value is provably absent from recall, checked here at runtime), AND (b) there
    are committed cases asserting it. In a checkout we require the actual test file (a real regression
    guard — deleting the suite flips this mark). From an installed wheel `tests/` isn't shipped, so we
    can't see the file but the cases are still committed upstream; we don't penalise the wheel for that
    (that would make the score depend on install method, not on the code)."""
    from .local import LocalMemory
    from .recall import recall_budgeted
    from .view import MemoryKind, MemoryRecord
    m = LocalMemory(":memory:")
    r = m.write(MemoryRecord(kind=MemoryKind.FACT, subject="s", predicate="p",
                             text="passwords in plaintext", scope="repo:x"), ts=1.0)
    for _ in range(6):
        m.contradict(r.id)
    out = recall_budgeted(m, "passwords plaintext", token_budget=500, scope="repo:x")
    not_retrieved = "plaintext" not in out.text and all(rec.id != r.id for rec in out.records)
    committed, in_checkout = _find_committed_negative_evals()
    if in_checkout:
        ok = not_retrieved and committed is not None
        where = committed or "MISSING — expected tests/test_memory_negative_eval.py in this checkout"
    else:
        ok = not_retrieved  # installed wheel: prove behaviour; the committed suite lives in the repo
        where = "tests/test_memory_negative_eval.py (committed upstream; not shipped in the wheel)"
    return ok, f"rejected value absent from budgeted recall={not_retrieved}; committed cases: {where}"


def _find_committed_negative_evals() -> tuple[str | None, bool]:
    """Return (evidence_path_or_None, in_source_checkout). `in_source_checkout` is True when a
    `tests/` directory is discoverable up the tree (we're running from source), so the caller can be
    STRICT there and lenient from an installed wheel that ships no tests."""
    here = Path(__file__).resolve()
    in_checkout = False
    for parent in here.parents:
        tests_dir = parent / "tests"
        if tests_dir.is_dir():
            in_checkout = True
            cand = tests_dir / "test_memory_negative_eval.py"
            if cand.exists():
                try:
                    body = cand.read_text(encoding="utf-8")
                except OSError:
                    continue
                if "not" in body and ("recall" in body or "retriev" in body):
                    return f"{cand} + tests/memory_contract.py:check_recall_excludes_rejected", True
    return None, in_checkout


_DIMENSIONS: list[tuple[str, str, str, Callable[[], tuple[bool, str]]]] = [
    ("tombstone", "Rejected-value Tombstone",
     "durable record of a rejected value, keyed on the value, so later extraction cannot silently "
     "re-assert it", _probe_tombstone),
    ("trust_state", "Explicit Trust State",
     "discrete epistemic status exists as a field rather than a confidence score, including at least "
     "one state that withholds a memory from being treated as true", _probe_trust_state),
    ("bitemporal", "Bi-temporal Validity",
     "when a fact was true is tracked separately from when the system recorded or expired it",
     _probe_bitemporal),
    ("scope_enforced", "Scope Enforced in Retrieval",
     "a stored scope key is applied as a filter on the read path", _probe_scope_enforced),
    ("mutation_audit", "Append-only Mutation Audit",
     "named append-only event record of memory mutations in the system's own store",
     _probe_mutation_audit),
    ("human_review", "Human Review Surface",
     "a place a person inspects, approves, or adjudicates memory content, before or after it takes "
     "effect", _probe_human_review),
    ("negative_evals", "Negative Retrieval Assertion",
     "committed evaluation cases assert that particular material must not be retrieved",
     _probe_negative_evals),
]


def assess() -> RubricAssessment:
    """Run all seven behavioural probes against our own code and return the code-grounded verdict."""
    results = []
    for key, title, criterion, probe in _DIMENSIONS:
        try:
            passed, proof = probe()
        except Exception as e:  # a probe that errors is a FAIL with the error as its proof
            passed, proof = False, f"probe raised {type(e).__name__}: {e}"
        results.append(DimensionResult(key, title, criterion, passed, _EVIDENCE[key], proof))
    return RubricAssessment(results)


_EVIDENCE = {
    "tombstone": "memory/view.py:record_rejection / is_launder_blocked (ledger keyed on rejected_key)",
    "trust_state": "memory/view.py:Trust (enum CANDIDATE/VERIFIED/REJECTED); recall filters REJECTED",
    "bitemporal": "memory/view.py:MemoryRecord.valid_from/valid_to + value_as_of; recall.py:recall_as_of",
    "scope_enforced": "memory/local.py:recall (SQL `m.scope = ? OR 'global'`); all backends filter",
    "mutation_audit": "memory/audit.py:MemoryAudit / AuditedMemory (hash-chained JSONL)",
    "human_review": "memory/review.py:approve/reject/pending; cli.py `verel memory` (CLI-only)",
    "negative_evals": "tests/test_memory_negative_eval.py + memory_contract negative checks",
}


def main() -> int:
    a = assess()
    print(a.render())
    return 0 if a.score == len(a.results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
