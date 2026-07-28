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


def test_apply_replica_preserves_explicit_valid_time():
    """Replication mirrors a leader's valid-time verbatim (a follower must not rewrite history)."""
    m = LocalMemory(":memory:")
    m.apply_replica(MemoryRecord(id="rep1", kind=MemoryKind.FACT, subject="a", predicate="b",
                                 text="v", scope="repo:x", trust=Trust.VERIFIED,
                                 valid_from=11.0, valid_to=22.0))
    got = m.get("rep1")
    assert got.valid_from == 11.0 and got.valid_to == 22.0
