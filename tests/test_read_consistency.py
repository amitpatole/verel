"""Read consistency (§6.3) — eventual (local) vs strong (read-from-leader / read-your-writes)."""

from verel.fleet import InMemoryLeaseStore
from verel.memory import (
    LocalMemory,
    MemoryKind,
    MemoryRecord,
    ReplicatedMemory,
    Trust,
)
from verel.memory.view import make_key


def _fact(subj, text):
    return MemoryRecord(kind=MemoryKind.FACT, subject=subj, predicate="r", text=text, scope="team",
                        trust=Trust.VERIFIED, subj_pred_key=make_key(subj, "r", "team"))


def _setup():
    leases = InMemoryLeaseStore()
    a = ReplicatedMemory(LocalMemory(), leases=leases, cluster_key="brain", owner="A")  # leader
    a.write(_fact("deploy", "via pipeline"))   # written to the leader only (the follower lags)
    return leases, a


def test_eventual_follower_may_miss_a_recent_write():
    leases, a = _setup()
    follower = ReplicatedMemory(LocalMemory(), leases=leases, cluster_key="brain", owner="F",
                               read_consistency="eventual")   # default
    assert follower.all(scope="team") == []                    # never received the replica


def test_strong_follower_reads_from_the_leader():
    leases, a = _setup()
    follower = ReplicatedMemory(LocalMemory(), leases=leases, cluster_key="brain", owner="F",
                               read_consistency="strong", sources={"A": a})
    assert [r.text for r in follower.all(scope="team")] == ["via pipeline"]
    assert follower.recall("deploy", scope="team")             # recall routes to the leader too
    rid = a.all(scope="team")[0].id
    assert follower.get(rid) is not None                        # get routes to the leader


def test_read_your_writes_under_strong():
    leases, a = _setup()
    reader = ReplicatedMemory(LocalMemory(), leases=leases, cluster_key="brain", owner="R",
                             read_consistency="strong", sources={"A": a})
    a.write(_fact("oncall", "page owner"))                      # a fresh write to the leader
    assert any(r.subject == "oncall" for r in reader.all(scope="team"))


def test_leader_reads_locally_under_strong():
    leases, a = _setup()
    a.read_consistency = "strong"
    a.sources = {"A": a}
    assert a.leader_view() is a.local                           # the leader is authoritative — no hop


def test_strong_falls_back_to_local_when_no_leader(monkeypatch):
    leases = InMemoryLeaseStore()
    clk = {"t": 0.0}
    a = ReplicatedMemory(LocalMemory(), leases=leases, cluster_key="brain", owner="A", clock=lambda: clk["t"])
    a.write(_fact("x", "1"))
    clk["t"] = 100.0                                            # A's lease lapsed → no leader
    follower = ReplicatedMemory(LocalMemory(), leases=leases, cluster_key="brain", owner="F",
                               read_consistency="strong", sources={"A": a}, clock=lambda: clk["t"])
    assert follower.leader_view() is follower.local            # no leader → read local (best effort)


def test_strong_reads_over_http(tmp_path):
    from verel.memory import MemoryServer, RemoteMemory
    leases = InMemoryLeaseStore()
    a = ReplicatedMemory(LocalMemory(tmp_path / "a.db", check_same_thread=False),
                         leases=leases, cluster_key="brain", owner="A")
    sa = MemoryServer(store=a).start()
    try:
        a.write(_fact("deploy", "v1"))                          # leader's write (follower lags)
        follower = ReplicatedMemory(LocalMemory(), leases=leases, cluster_key="brain", owner="F",
                                   read_consistency="strong", sources={"A": RemoteMemory(sa.url)})
        assert [r.text for r in follower.all(scope="team")] == ["v1"]   # read routes to leader over HTTP
    finally:
        sa.stop()
