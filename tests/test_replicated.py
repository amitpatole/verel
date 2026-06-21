"""Replicated memory (§6.3) — leader fencing, replication, failover, no split-brain. Offline."""

import pytest

from verel.fleet import FencingError, InMemoryLeaseStore
from verel.memory import (
    LocalMemory,
    MemoryKind,
    MemoryRecord,
    NotLeaderError,
    ReplicatedMemory,
    Trust,
)
from verel.memory.view import make_key


def _fact(subj, text):
    return MemoryRecord(kind=MemoryKind.FACT, subject=subj, predicate="r", text=text, scope="team",
                        trust=Trust.VERIFIED, subj_pred_key=make_key(subj, "r", "team"))


def _cluster():
    clk = {"t": 0.0}
    leases = InMemoryLeaseStore()
    a = ReplicatedMemory(LocalMemory(), leases=leases, cluster_key="brain", owner="A",
                         ttl=10, clock=lambda: clk["t"])
    b = ReplicatedMemory(LocalMemory(), leases=leases, cluster_key="brain", owner="B",
                         ttl=10, clock=lambda: clk["t"])
    a.peers, b.peers = [b], [a]
    return a, b, leases, clk


def test_leader_write_replicates_to_followers():
    a, b, _, _ = _cluster()
    a.write(_fact("deploy", "via pipeline"))
    assert a.is_leader() and not b.is_leader()
    assert [r.text for r in b.all(scope="team")] == ["via pipeline"]   # follower has the replica


def test_non_leader_cannot_write():
    a, b, _, _ = _cluster()
    a.write(_fact("x", "1"))                       # A is leader
    with pytest.raises(NotLeaderError):
        b.write(_fact("y", "2"))                    # B is not — refused


def test_failover_promotes_a_follower_with_a_higher_token():
    a, b, leases, clk = _cluster()
    a.write(_fact("a", "1"))
    assert leases.current_token("brain") == 1
    clk["t"] = 100.0                                # A's lease lapses
    b.write(_fact("b", "2"))                         # B takes over
    assert b.is_leader() and leases.current_token("brain") == 2
    assert [r.text for r in a.all(scope="team") if r.subject == "b"] == ["2"]  # replicated back to A


def test_deposed_leader_is_fenced_no_split_brain():
    a, b, leases, clk = _cluster()
    a.write(_fact("a", "1"))
    clk["t"] = 100.0
    b.write(_fact("b", "2"))                          # B is now leader (token 2)
    with pytest.raises(NotLeaderError):
        a.write(_fact("c", "stale"))                  # A is deposed — fenced out


def test_replicate_rejects_a_stale_token_directly():
    a, b, leases, _ = _cluster()
    a.write(_fact("a", "1"))                           # current token = 1
    leases.acquire("brain", "C", now=1000.0, ttl=10)  # a takeover bumps the cluster token to 2
    with pytest.raises(FencingError):                 # a stale leader's replicate (token 1) is refused
        b.apply_replica_fenced(_fact("z", "stale").model_dump(), 1)


def test_reads_served_from_any_node():
    a, b, _, _ = _cluster()
    a.write(_fact("k", "v"))
    assert a.get(a.all(scope="team")[0].id) is not None
    assert b.recall("v", scope="team")               # follower can read


def test_cross_machine_cluster_over_http(tmp_path):
    from verel.memory import MemoryServer, RemoteMemory, ReplicaClient
    clk = {"t": 0.0}
    leases = InMemoryLeaseStore()
    a_local = LocalMemory(tmp_path / "a.db", check_same_thread=False)
    b_local = LocalMemory(tmp_path / "b.db", check_same_thread=False)
    a = ReplicatedMemory(a_local, leases=leases, cluster_key="brain", owner="A", ttl=10, clock=lambda: clk["t"])
    b = ReplicatedMemory(b_local, leases=leases, cluster_key="brain", owner="B", ttl=10, clock=lambda: clk["t"])
    sa, sb = MemoryServer(store=a).start(), MemoryServer(store=b).start()
    a.peers = [ReplicaClient(sb.url)]
    b.peers = [ReplicaClient(sa.url)]
    try:
        RemoteMemory(sa.url).write(_fact("deploy", "via pipeline"))      # write to leader over HTTP
        assert [r.text for r in RemoteMemory(sb.url).all(scope="team")] == ["via pipeline"]  # replicated
        with pytest.raises(Exception):
            RemoteMemory(sb.url).write(_fact("x", "1"))                  # non-leader → 421
        clk["t"] = 100.0
        RemoteMemory(sb.url).write(_fact("oncall", "page"))             # failover to B
        assert any(r.subject == "oncall" for r in RemoteMemory(sa.url).all(scope="team"))  # replicated to A
    finally:
        sa.stop()
        sb.stop()


# ---- fault tolerance (v0.24.0 hardening) ----
class _DeadPeer:
    def apply_replica_fenced(self, record, token):
        raise ConnectionError("follower unreachable")


def test_write_survives_an_unreachable_follower():
    a, b, _, _ = _cluster()
    a.peers = [b, _DeadPeer()]                       # one healthy, one down
    a.write(_fact("deploy", "via pipeline"))         # must NOT fail
    assert [r.text for r in a.all(scope="team")] == ["via pipeline"]
    assert [r.text for r in b.all(scope="team")] == ["via pipeline"]   # healthy follower still got it
    st = a.replication_status()
    assert st.acks == 2 and st.lagging == 1


def test_write_quorum_is_enforced():
    leases = InMemoryLeaseStore()
    healthy = ReplicatedMemory(LocalMemory(), leases=leases, cluster_key="q", owner="H")
    a = ReplicatedMemory(LocalMemory(), leases=leases, cluster_key="q", owner="A",
                         peers=[healthy, _DeadPeer()], write_quorum=3)
    from verel.memory import ReplicationError
    with pytest.raises(ReplicationError):            # leader + 1 healthy = 2 < quorum 3
        a.write(_fact("x", "y"))


def test_write_quorum_met_succeeds():
    leases = InMemoryLeaseStore()
    healthy = ReplicatedMemory(LocalMemory(), leases=leases, cluster_key="q2", owner="H")
    a = ReplicatedMemory(LocalMemory(), leases=leases, cluster_key="q2", owner="A",
                         peers=[healthy], write_quorum=2)
    a.write(_fact("x", "y"))                          # leader + 1 healthy = 2 == quorum
    assert a.replication_status().acks == 2


def test_apply_replica_is_idempotent_no_confidence_drift():
    a, _, _, _ = _cluster()
    rec = a.write(_fact("ci", "run suite"))
    before = a.get(rec.id).epistemic_confidence
    a.apply_replica(rec)
    a.apply_replica(rec)                              # re-deliver the same record twice
    assert a.get(rec.id).epistemic_confidence == before   # verbatim, not corroboration


def test_sync_from_catches_a_lagging_node_up():
    a, _, leases, _ = _cluster()
    a.write(_fact("deploy", "v1"))
    a.write(_fact("oncall", "page"))
    late = ReplicatedMemory(LocalMemory(), leases=leases, cluster_key="brain", owner="LATE")
    n = late.sync_from(a)
    assert n == 2 and {r.subject for r in late.all(scope="team")} == {"deploy", "oncall"}
