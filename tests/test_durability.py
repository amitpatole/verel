"""Write durability (§5/§6.3) — WAL + fsync so an acked write survives a crash. Offline."""

from verel.fleet import InMemoryLeaseStore
from verel.memory import LocalMemory, MemoryKind, MemoryRecord, ReplicatedMemory, Trust
from verel.memory.view import make_key

# PRAGMA synchronous integer values: 0=OFF, 1=NORMAL, 2=FULL.
SYNC_FULL, SYNC_NORMAL = 2, 1


def _fact(subj, text, scope="team"):
    return MemoryRecord(kind=MemoryKind.FACT, subject=subj, predicate="r", text=text, scope=scope,
                        trust=Trust.VERIFIED, subj_pred_key=make_key(subj, "r", scope))


def test_on_disk_store_is_wal_and_fsynced_by_default(tmp_path):
    m = LocalMemory(tmp_path / "m.db")
    assert m._db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert m._db.execute("PRAGMA synchronous").fetchone()[0] == SYNC_FULL


def test_durable_false_relaxes_to_normal(tmp_path):
    m = LocalMemory(tmp_path / "m.db", durable=False)
    assert m._db.execute("PRAGMA synchronous").fetchone()[0] == SYNC_NORMAL


def test_in_memory_store_unaffected():
    m = LocalMemory()                               # ":memory:" — no WAL/fsync to apply
    m.write(_fact("a", "1"))                         # still works
    assert m.all(scope="team")


def test_write_survives_a_reopen(tmp_path):
    p = tmp_path / "m.db"
    m = LocalMemory(p)
    rec = m.write(_fact("auth", "sessions are JWT"))
    m._db.close()                                    # simulate process exit (no clean shutdown)
    del m
    reopened = LocalMemory(p)                          # restart after the "crash"
    got = reopened.get(rec.id)
    assert got is not None and got.text == "sessions are JWT"


def test_replicated_leader_write_is_durable_before_ack(tmp_path):
    p = tmp_path / "leader.db"
    leader = ReplicatedMemory(LocalMemory(p), leases=InMemoryLeaseStore(), cluster_key="c", owner="L")
    w = leader.write(_fact("x", "committed"))         # returned == acked == fsynced
    leader.local._db.close()                          # crash the leader
    assert LocalMemory(p).get(w.id) is not None        # the acked write is on disk
