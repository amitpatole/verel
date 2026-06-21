"""Background anti-entropy (§6.3) — followers self-heal by syncing from the current leader. Offline."""

import time

from verel.fleet import InMemoryLeaseStore
from verel.memory import (
    AntiEntropy,
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


def _node(leases, owner, clk, *, threadsafe=False):
    return ReplicatedMemory(LocalMemory(check_same_thread=not threadsafe), leases=leases,
                            cluster_key="brain", owner=owner, ttl=30, clock=lambda: clk["t"])


# ---- lease store: who's the leader ----
def test_lease_holder_reports_the_live_owner():
    leases = InMemoryLeaseStore()
    leases.acquire("brain", "A", now=0.0, ttl=10.0)
    assert leases.holder("brain", now=5.0) == "A"
    assert leases.holder("brain", now=20.0) is None      # lease expired → no holder
    assert leases.holder("other", now=0.0) is None       # never held


def test_sqlite_lease_holder(tmp_path):
    from verel.fleet import SqliteLeaseStore
    s = SqliteLeaseStore(tmp_path / "l.db")
    s.acquire("brain", "A", now=0.0, ttl=10.0)
    assert s.holder("brain", now=5.0) == "A" and s.holder("brain", now=20.0) is None


# ---- anti-entropy tick ----
def test_tick_syncs_a_lagging_follower_from_the_leader():
    leases = InMemoryLeaseStore()
    clk = {"t": 0.0}
    a = _node(leases, "A", clk)
    late = _node(leases, "LATE", clk)
    a.write(_fact("deploy", "v1"))
    a.write(_fact("oncall", "page"))          # LATE never received these
    assert late.all(scope="team") == []
    synced = AntiEntropy(late, sources={"A": a}).tick()
    assert synced == 2 and {r.subject for r in late.all(scope="team")} == {"deploy", "oncall"}


def test_leader_does_not_sync_from_itself():
    leases = InMemoryLeaseStore()
    clk = {"t": 0.0}
    a = _node(leases, "A", clk)
    a.write(_fact("x", "1"))                   # A becomes the leader
    assert AntiEntropy(a, sources={"A": a}).tick() == 0   # the leader is the source of truth


def test_no_op_when_no_leader_holds_the_lease():
    leases = InMemoryLeaseStore()
    clk = {"t": 0.0}
    a = _node(leases, "A", clk)
    a.write(_fact("x", "1"))
    clk["t"] = 100.0                           # A's lease has lapsed; nobody holds it
    late = _node(leases, "LATE", clk)
    assert AntiEntropy(late, sources={"A": a}).tick() == 0


def test_leader_source_resolution():
    leases = InMemoryLeaseStore()
    clk = {"t": 0.0}
    a = _node(leases, "A", clk)
    b = _node(leases, "B", clk)
    a.write(_fact("x", "1"))                   # A is leader
    ae = AntiEntropy(b, sources={"A": a})
    assert ae.leader_source() is a             # B resolves the leader to A's source


# ---- background loop ----
def test_background_reconciler_self_heals():
    leases = InMemoryLeaseStore()
    clk = {"t": 0.0}
    a = _node(leases, "A", clk, threadsafe=True)
    late = _node(leases, "LATE", clk, threadsafe=True)
    a.write(_fact("deploy", "v1"))
    ae = AntiEntropy(late, sources={"A": a}, interval=0.01).start()
    try:
        a.write(_fact("policy", "new rule"))   # written AFTER the reconciler is running
        deadline = time.time() + 2
        while time.time() < deadline:
            if any(r.subject == "policy" for r in late.all(scope="team")):
                break
            time.sleep(0.02)
    finally:
        ae.stop()
    assert {r.subject for r in late.all(scope="team")} == {"deploy", "policy"}
