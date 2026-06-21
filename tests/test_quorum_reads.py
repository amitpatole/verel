"""Quorum reads + versioned records (§6.3) — a point read survives the leader being down.

`read_consistency="strong"` routes reads to the leader, so a read FAILS when the leader is
unavailable. Quorum reads instead poll up to `read_quorum` replicas and return the FRESHEST copy by
version — so a read tolerates leader downtime as long as a quorum of replicas hold the record. The
leader stamps a monotonic version (`token * STRIDE + seq`) on every mutation, which also makes
replication reorder-/duplicate-safe: an older-version copy never clobbers a newer one.
"""

from __future__ import annotations

from verel.fleet import InMemoryLeaseStore
from verel.memory import (
    LocalMemory,
    MemoryKind,
    MemoryRecord,
    ReplicatedMemory,
    Trust,
    version_of,
)
from verel.memory.view import make_key


def _fact(subj: str, text: str) -> MemoryRecord:
    return MemoryRecord(kind=MemoryKind.FACT, subject=subj, predicate="r", text=text,
                        scope="team", trust=Trust.VERIFIED,
                        subj_pred_key=make_key(subj, "r", "team"))


def _cluster(clk):
    leases = InMemoryLeaseStore()
    a = ReplicatedMemory(LocalMemory(), leases=leases, cluster_key="b", owner="A",
                         clock=lambda: clk["t"])
    b = ReplicatedMemory(LocalMemory(), leases=leases, cluster_key="b", owner="B",
                         clock=lambda: clk["t"])
    a.peers = [b]
    return leases, a, b


def test_records_are_versioned_monotonically():
    clk = {"t": 0.0}
    _, a, _ = _cluster(clk)
    r1 = a.write(_fact("deploy", "v1"))
    r2 = a.write(_fact("oncall", "page"))
    assert version_of(a.get(r1.id)) > 0
    assert version_of(a.get(r2.id)) > version_of(a.get(r1.id))


def test_version_jumps_across_failover():
    """A new leader has a higher fencing token, so its versions strictly exceed the old leader's."""
    clk = {"t": 0.0}
    leases, a, b = _cluster(clk)
    r1 = a.write(_fact("deploy", "v1"))
    v_a = version_of(a.get(r1.id))

    clk["t"] = 100.0          # A's lease lapses → B takes over with a higher token
    b.peers = [a]
    r2 = b.write(_fact("rollback", "v2"))
    assert version_of(b.get(r2.id)) > v_a


def test_quorum_read_survives_leader_down():
    clk = {"t": 0.0}
    leases, a, b = _cluster(clk)
    r = a.write(_fact("deploy", "v1"))

    class Down:               # the leader, now unreachable
        def get(self, _rid):
            raise ConnectionError("leader down")

    clk["t"] = 100.0          # A's lease lapses and (pretend) A is unreachable
    reader = ReplicatedMemory(LocalMemory(), leases=leases, cluster_key="b", owner="R",
                              read_consistency="quorum", read_quorum=2,
                              sources={"A": Down(), "B": b}, clock=lambda: clk["t"])
    got = reader.get(r.id)
    assert got is not None and got.text == "v1"   # served from follower B despite the dead leader


def test_quorum_read_returns_freshest_copy():
    """When replicas disagree, quorum read returns the highest-version copy, not just the first."""
    clk = {"t": 0.0}
    leases, a, b = _cluster(clk)
    r = a.write(_fact("deploy", "v1"))
    fresh = a.write(_fact("deploy", "v2"))        # supersedes v1 (same subject/predicate/scope)
    assert fresh.id == r.id

    # a stale replica still holding the OLD version
    stale = LocalMemory()
    old = a.get(r.id).model_copy(deep=True).with_detail(_v=1)
    old.text = "v1-stale"
    stale.apply_replica(old)

    reader = ReplicatedMemory(LocalMemory(), leases=leases, cluster_key="b", owner="R",
                              read_consistency="quorum", read_quorum=3,
                              sources={"A": a, "stale": stale}, clock=lambda: clk["t"])
    assert reader.get(r.id).text == "v2"          # freshest wins over the stale replica


def test_older_replicate_does_not_regress_newer():
    clk = {"t": 0.0}
    leases, a, b = _cluster(clk)
    r = a.write(_fact("deploy", "v2"))            # already replicated to b at its current version
    newer = b.get(r.id)
    assert newer.text == "v2"

    older = newer.model_copy(deep=True).with_detail(_v=version_of(newer) - 5)
    older.text = "v1-stale"
    b.apply_replica_fenced(older.model_dump(), leases.current_token("b"))
    assert b.get(r.id).text == "v2"               # the reordered/duplicate older copy was ignored


def test_eventual_read_is_unaffected():
    """Default eventual reads still serve from the local replica (no quorum overhead)."""
    clk = {"t": 0.0}
    leases, a, b = _cluster(clk)
    r = a.write(_fact("deploy", "v1"))
    assert b.get(r.id).text == "v1"               # b read its own local replica
