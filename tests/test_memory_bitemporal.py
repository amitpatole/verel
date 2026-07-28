"""Bi-temporal memory — valid-time (valid_from/valid_to) distinct from transaction-time, and the
as-of reconstruction query. Closes the atlas "bi-temporal" gap.
"""

from memory_contract import make_fact

from verel.memory import LocalMemory, recall_as_of, value_as_of
from verel.memory.view import MemoryKind, MemoryRecord, Trust


def _changed_over_time():
    """region = us-east (valid 100..600) then us-west (valid 600..open)."""
    m = LocalMemory(":memory:")
    m.write(make_fact(text="us-east", subject="server", predicate="region"), ts=100.0)
    m.write(make_fact(text="us-west", subject="server", predicate="region"), ts=600.0)
    return m, m.all()[0]


def test_valid_time_is_distinct_from_transaction_time():
    m = LocalMemory(":memory:")
    f = make_fact()
    f.valid_from = 42.0  # true since t=42, but written (learned) at ts=999
    r = m.write(f, ts=999.0)
    got = m.get(r.id)
    assert got.valid_from == 42.0
    assert got.created_ts == 999.0  # transaction-time unaffected by the backdated valid-time


def test_value_as_of_reconstructs_from_chain():
    m, r = _changed_over_time()
    cur = m.get(r.id)
    assert value_as_of(cur, 300.0).text == "us-east"   # historical, from the correction chain
    assert value_as_of(cur, 700.0).text == "us-west"   # current
    assert value_as_of(cur, 50.0) is None              # before the key existed


def test_value_as_of_boundaries_are_half_open():
    m, r = _changed_over_time()
    cur = m.get(r.id)
    # [valid_from, valid_to): valid_from inclusive, valid_to exclusive
    assert value_as_of(cur, 100.0).text == "us-east"   # exactly valid_from of the old value
    assert value_as_of(cur, 600.0).text == "us-west"   # exactly the boundary → the NEW value
    assert value_as_of(cur, 599.999).text == "us-east"


def test_recall_as_of_ranks_reconstructed_values():
    m, _ = _changed_over_time()
    assert [h.text for h in recall_as_of(m, "server region", as_of=300.0, scope="repo:x")] == ["us-east"]
    assert [h.text for h in recall_as_of(m, "server region", as_of=700.0, scope="repo:x")] == ["us-west"]


def test_recall_as_of_does_not_reinforce():
    """A historical read must not bump retrieval_strength (it isn't 'using' the memory now)."""
    m, r = _changed_over_time()
    before = m.get(r.id).retrieval_strength
    recall_as_of(m, "server region", as_of=700.0, scope="repo:x")
    assert m.get(r.id).retrieval_strength == before


def test_recall_as_of_excludes_rejected_keys():
    """A key whose current value is REJECTED is not surfaced even by a historical query — a value
    graded false can't be resurfaced into a prompt through time travel."""
    m = LocalMemory(":memory:")
    r = m.write(make_fact(text="a claim", subject="x", predicate="y"), ts=100.0)
    for _ in range(6):
        m.contradict(r.id)
    assert m.get(r.id).trust == Trust.REJECTED
    assert recall_as_of(m, "x y claim", as_of=200.0, scope="repo:x") == []


def test_recall_as_of_ignores_non_finite_timestamps():
    m, _ = _changed_over_time()
    for bad in (float("nan"), float("inf"), float("-inf")):
        assert recall_as_of(m, "server region", as_of=bad, scope="repo:x") == []


def test_recall_as_of_excludes_ledgered_value_after_supersede():
    """round-15/F1: a value graded false then superseded by a benign correction must NOT be
    resurrected from the chain by a historical query — recall_as_of is ledger-aware, not just
    current-trust-aware."""
    m = LocalMemory(":memory:")
    r = m.write(make_fact(text="passwords in plaintext", subject="s", predicate="p"), ts=100.0)
    for _ in range(6):
        m.contradict(r.id)
    m.write(make_fact(text="passwords are hashed", subject="s", predicate="p"), ts=600.0)  # correction
    assert m.get(r.id).trust == Trust.CANDIDATE  # current record is a benign candidate
    hits = recall_as_of(m, "passwords plaintext", as_of=200.0, scope="repo:x")
    assert all("plaintext" not in h.text for h in hits)


def test_value_as_of_tolerates_malformed_corrections():
    """round-15/F2: a hostile replica plants a non-list / non-dict / non-numeric corrections blob;
    value_as_of must skip it, not crash."""
    for bad in ("notalist", [None], [123], [{"valid_from": "nan", "valid_to": "x", "ec": "z"}], [{}]):
        m = LocalMemory(":memory:")
        m.apply_replica(MemoryRecord(id="e", kind=MemoryKind.FACT, subject="server", predicate="region",
                                     text="cur", scope="repo:x", trust=Trust.VERIFIED,
                                     valid_from=1000.0, valid_to=2000.0, created_ts=1000.0,
                                     detail_json=__import__("json").dumps({"corrections": bad})))
        assert recall_as_of(m, "server region", as_of=500.0, scope="repo:x") == []  # no crash


def test_non_finite_interval_bounds_never_match():
    """round-15/F3: a valid_to of +inf (or a NaN bound) must not make a value 'valid forever'."""
    m = LocalMemory(":memory:")
    m.apply_replica(MemoryRecord(id="p", kind=MemoryKind.FACT, subject="server", predicate="region",
                                 text="poison forever", scope="repo:x", trust=Trust.VERIFIED,
                                 valid_from=1.0, valid_to=float("inf"), created_ts=1.0))
    assert recall_as_of(m, "server region", as_of=9e9, scope="repo:x") == []
    assert value_as_of(m.get("p"), 500.0) is None


def test_recall_as_of_includes_global_scope():
    """Scope semantics match recall(): a scoped as-of query also surfaces global facts (round-15
    round-2/E1 — as-of previously omitted global). No double-count when the scope IS global."""
    m = LocalMemory(":memory:")
    m.write(MemoryRecord(kind=MemoryKind.FACT, subject="policy", predicate="retention",
                         text="90 days", scope="global"), ts=100.0)
    hits = recall_as_of(m, "policy retention", as_of=200.0, scope="repo:x")
    assert [h.text for h in hits] == ["90 days"]
    assert len(recall_as_of(m, "policy retention", as_of=200.0, scope="global")) == 1  # no dup


def test_apply_replica_preserves_explicit_valid_time():
    """Replication mirrors a leader's valid-time verbatim (a follower must not rewrite history)."""
    m = LocalMemory(":memory:")
    m.apply_replica(MemoryRecord(id="rep1", kind=MemoryKind.FACT, subject="a", predicate="b",
                                 text="v", scope="repo:x", trust=Trust.VERIFIED,
                                 valid_from=11.0, valid_to=22.0))
    got = m.get("rep1")
    assert got.valid_from == 11.0 and got.valid_to == 22.0
