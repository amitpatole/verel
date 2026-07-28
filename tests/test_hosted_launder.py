"""Regression: the HTTP brain must not let a bearer/cluster client launder a rejected value
(round-14/A + C-2). Real in-process MemoryServer over HTTP.

Threat: an /apply verbatim-upsert or an /annotate+/demote sequence resurrects a value a grader
previously REJECTED. Both are closed at the store primitive (guard_replica / durable demote) and,
for /annotate, additionally at the wire boundary (ledger keys stripped)."""

from verel.memory import MemoryKind, MemoryRecord, MemoryServer, RemoteMemory, Trust
from verel.memory.view import make_key, rejected_key


def _server(tmp_path, token=None):
    return MemoryServer(tmp_path / "brain.db", auth_token=token).start()


def _rejected(client, subj="sys", pred="backup", text="backups off", scope="team:web"):
    k = make_key(subj, pred, scope)
    r = client.write(MemoryRecord(kind=MemoryKind.FACT, subject=subj, predicate=pred, text=text,
                                  scope=scope, subj_pred_key=k))
    for _ in range(6):
        client.contradict(r.id)
    assert client.get(r.id).trust == Trust.REJECTED
    return r


def test_apply_over_http_cannot_launder_rejected(tmp_path):
    srv = _server(tmp_path)
    try:
        c = RemoteMemory(srv.url)
        r = _rejected(c)
        # hostile verbatim upsert: claim VERIFIED, drop the ledger
        c.apply_replica(MemoryRecord(id=r.id, kind=MemoryKind.FACT, subject="sys", predicate="backup",
                                     text="backups off", scope="team:web", trust=Trust.VERIFIED))
        after = c.get(r.id)
        assert after.trust == Trust.REJECTED  # forced back to tombstone over the wire
        assert all(h.id != r.id for h in c.recall("backups off sys backup", scope="team:web", k=50))
    finally:
        srv.stop()


def test_annotate_over_http_cannot_strip_ledger(tmp_path):
    srv = _server(tmp_path)
    try:
        c = RemoteMemory(srv.url)
        r = _rejected(c)
        # try to clear the ledger via a metadata write, then un-reject and promote
        c.annotate(r.id, rejected_values=[], rejected_saturated=False)
        after = c.get(r.id)
        assert rejected_key("backups off") in after.detail.get("rejected_values", [])  # not stripped
        c.demote(r.id)
        assert c.get(r.id).trust == Trust.REJECTED  # demote can't un-reject
        c.promote(r.id)
        assert c.get(r.id).trust != Trust.VERIFIED  # ledger still blocks promotion
    finally:
        srv.stop()
