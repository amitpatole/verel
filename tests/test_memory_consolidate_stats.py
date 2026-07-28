"""Consolidation observability — the induction pass exposes WHY it yielded N rules (clusters too
small vs LLM replies that wouldn't parse), instead of silently dropping both.
"""

from verel.memory import ConsolidationStats, LocalMemory, consolidate_failures
from verel.memory.view import MemoryKind, MemoryRecord


def _seed_failures(mem, n, *, kind="overflow", scope="repo:x"):
    for i in range(n):
        mem.write(MemoryRecord(kind=MemoryKind.FAILURE, subject=f"f{i}", predicate="fail",
                               text="panel overflow", scope=scope).with_detail(kind=kind), ts=1.0)


def test_stats_count_parse_failures():
    """An LLM that returns junk → the cluster is counted as a parse_failure, not silently gone."""
    mem = LocalMemory(":memory:")
    _seed_failures(mem, 3)
    st = ConsolidationStats()
    out = consolidate_failures(mem, scope="repo:x", chat=lambda _m: "not json", stats=st)
    assert out == []
    assert st.inputs_seen == 3 and st.clusters_found == 1
    assert st.llm_calls == 1 and st.parse_failures == 1 and st.written == 0


def test_stats_count_clusters_too_small():
    """A single failure can't form a cluster of >= min_cluster → counted as too_small, no LLM call."""
    mem = LocalMemory(":memory:")
    _seed_failures(mem, 1)
    st = ConsolidationStats()
    consolidate_failures(mem, scope="repo:x", min_cluster=2, chat=lambda _m: "{}", stats=st)
    assert st.clusters_too_small == 1 and st.llm_calls == 0 and st.parse_failures == 0


def test_stats_count_written_on_success():
    mem = LocalMemory(":memory:")
    _seed_failures(mem, 3)
    good = '{"subject":"panel","condition":"overflow","action":"clamp width","applies_to":"cards"}'
    st = ConsolidationStats()
    out = consolidate_failures(mem, scope="repo:x", chat=lambda _m: good, stats=st)
    assert len(out) == 1 and st.written == 1 and st.parse_failures == 0


def test_stats_reconcile():
    """The ledger reconciles: written == clusters_found - too_small - parse_failures."""
    mem = LocalMemory(":memory:")
    _seed_failures(mem, 3)
    st = ConsolidationStats()
    consolidate_failures(mem, scope="repo:x", chat=lambda _m: "junk", stats=st)
    assert st.written == st.clusters_found - st.clusters_too_small - st.parse_failures


def test_stats_optional_backcompat():
    """Without a stats object the function behaves exactly as before (returns the rules)."""
    mem = LocalMemory(":memory:")
    _seed_failures(mem, 2)
    good = '{"subject":"p","condition":"c","action":"a","applies_to":"x"}'
    out = consolidate_failures(mem, scope="repo:x", chat=lambda _m: good)
    assert len(out) == 1
