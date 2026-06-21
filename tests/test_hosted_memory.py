"""Hosted shared memory (§5) — a MemoryView over HTTP so a fleet shares one brain.
Real in-process HTTP server; the lattice/graduate work through the remote client unchanged."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from verel.memory import (
    MemoryKind,
    MemoryRecord,
    MemoryServer,
    RemoteMemory,
    ScopeLattice,
    Trust,
    graduate,
    lattice_recall,
)
from verel.memory.view import make_key


def _fact(subj, text, scope, *, trust=Trust.VERIFIED, ec=0.8):
    return MemoryRecord(kind=MemoryKind.FACT, subject=subj, predicate="rule", text=text,
                        scope=scope, trust=trust, epistemic_confidence=ec,
                        subj_pred_key=make_key(subj, "rule", scope))


def _server(tmp_path, token=None):
    return MemoryServer(tmp_path / "brain.db", auth_token=token).start()


def test_two_agents_share_one_brain(tmp_path):
    srv = _server(tmp_path)
    try:
        a, b = RemoteMemory(srv.url), RemoteMemory(srv.url)
        rec = a.write(_fact("deploy", "deploy via the pipeline", "team:web"))
        assert rec.id  # server assigned/returned the record
        # B sees A's write
        assert [r.text for r in b.recall("how do we deploy", scope="team:web")] == ["deploy via the pipeline"]
        assert b.get(rec.id).text == "deploy via the pipeline"
        assert {r.scope for r in b.all(scope="team:web")} == {"team:web"}
    finally:
        srv.stop()


def test_trust_ops_round_trip_and_are_shared(tmp_path):
    srv = _server(tmp_path)
    try:
        a, b = RemoteMemory(srv.url), RemoteMemory(srv.url)
        rec = a.write(_fact("ci", "run the full suite", "team:web", ec=0.5))
        b.corroborate(rec.id)
        b.corroborate(rec.id)
        assert a.get(rec.id).epistemic_confidence > 0.5            # corroboration is shared
        a.promote(rec.id)
        assert b.get(rec.id).trust == Trust.VERIFIED
        a.annotate(rec.id, note="seen in prod")
        assert b.get(rec.id).detail["note"] == "seen in prod"
        a.pin(rec.id)
        assert b.get(rec.id).detail["pinned"] is True
    finally:
        srv.stop()


def test_lattice_and_graduate_work_through_the_remote_client(tmp_path):
    srv = _server(tmp_path)
    try:
        a, b = RemoteMemory(srv.url), RemoteMemory(srv.url)
        a.write(_fact("logging", "emit JSON logs", "repo:app"))
        b.write(_fact("logging", "emit JSON logs", "repo:billing"))
        a.write(_fact("deploy", "use the pipeline", "team:web"))
        lat = ScopeLattice({"repo:app": "team:web", "repo:billing": "team:web", "team:web": "global"})
        # resolve down works over HTTP
        down = lattice_recall(b, "deploy logging", scope="repo:billing", lattice=lat, k=5)
        assert {r.scope for r in down} == {"repo:billing", "team:web"}
        # graduate up works over HTTP
        grad = graduate(a, parent="team:web", children=["repo:app", "repo:billing"], min_scopes=2)
        assert len(grad) == 1 and grad[0].scope == "team:web" and grad[0].trust == Trust.CANDIDATE
    finally:
        srv.stop()


def test_concurrent_writes_are_serialized(tmp_path):
    # the server is the single writer; N agents writing at once must all land, no sqlite errors
    srv = _server(tmp_path)
    try:
        def writer(i):
            RemoteMemory(srv.url).write(_fact(f"k{i}", f"value {i}", "team:web"))
            return i

        with ThreadPoolExecutor(max_workers=8) as ex:
            done = list(ex.map(writer, range(40)))
        assert sorted(done) == list(range(40))
        assert len(RemoteMemory(srv.url).all(scope="team:web")) == 40   # every write persisted
    finally:
        srv.stop()


def test_interference_rule_holds_over_http(tmp_path):
    srv = _server(tmp_path)
    try:
        a = RemoteMemory(srv.url)
        r1 = a.write(_fact("auth", "sessions are JWT", "team:web", ec=0.5))
        # same (subject, predicate, scope), same text -> corroboration (one record, higher belief)
        a.write(_fact("auth", "sessions are JWT", "team:web", ec=0.5))
        same_key = [r for r in a.all(scope="team:web") if r.subject == "auth"]
        assert len(same_key) == 1 and same_key[0].epistemic_confidence > 0.5
        # a different value for the same key supersedes (keeps a correction chain)
        a.write(_fact("auth", "sessions are opaque tokens now", "team:web"))
        cur = a.get(r1.id)
        assert cur.text == "sessions are opaque tokens now" and cur.detail.get("corrections")
    finally:
        srv.stop()


def test_auth_token_gates_access(tmp_path):
    srv = _server(tmp_path, token="secret")
    try:
        RemoteMemory(srv.url, auth_token="secret").write(_fact("x", "ok", "team:web"))  # ok
        with pytest.raises(Exception):
            RemoteMemory(srv.url, auth_token="wrong").all(scope="team:web")
    finally:
        srv.stop()
