"""CLI surface for bi-temporal memory: `verel memory recall --as-of` and `verel memory members`.
Point-in-time recall reachable from the operator CLI, sharing the same on-disk brain."""

from __future__ import annotations

import io
from contextlib import redirect_stdout

import pytest

from verel.cli import main
from verel.memory import LocalMemory
from verel.memory.view import MemoryKind, MemoryRecord, make_id, make_key

T0, T1, T2 = 1_000_000.0, 2_000_000.0, 3_000_000.0


@pytest.fixture(autouse=True)
def _store(tmp_path, monkeypatch):
    monkeypatch.setenv("VEREL_MEMORY_STORE", str(tmp_path / "brain.db"))
    monkeypatch.setenv("VEREL_MEMORY_BACKEND", "local")
    monkeypatch.setenv("VEREL_MEMORY_AUDIT", str(tmp_path / "audit.jsonl"))
    return tmp_path


def _seed(store):
    """Roles with valid-time: alice admin [T0,T1) then member; bob owner throughout."""
    m = LocalMemory(str(store / "brain.db"))
    for subj, pred, text, ts in [("alice", "role", "admin", T0), ("alice", "role", "member", T1),
                                 ("bob", "role", "owner", T0)]:
        key = make_key(subj, pred, "repo:x")
        m.write(MemoryRecord(id=make_id(key), kind=MemoryKind.FACT, subject=subj, predicate=pred,
                             text=text, scope="repo:x", subj_pred_key=key), ts=ts)


def _run(argv) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(argv)
    return rc, buf.getvalue()


def test_cli_recall_as_of_then_vs_now(_store):
    _seed(_store)
    rc_then, then = _run(["memory", "recall", "alice role", "--as-of",
                          str((T0 + T1) / 2), "--scope", "repo:x"])
    rc_now, now = _run(["memory", "recall", "alice role", "--as-of", str(T2), "--scope", "repo:x"])
    assert rc_then == 0 and "admin" in then       # alice WAS admin then
    assert rc_now == 0 and "member" in now         # ...is a member now


def test_cli_members_who_was_admin_then(_store):
    _seed(_store)
    rc, out = _run(["memory", "members", "--predicate", "role", "--value", "admin",
                    "--as-of", str((T0 + T1) / 2), "--scope", "repo:x"])
    assert rc == 0 and "alice" in out and "1 holder" in out


def test_cli_members_nobody_admin_now(_store):
    _seed(_store)
    rc, out = _run(["memory", "members", "--predicate", "role", "--value", "admin",
                    "--as-of", str(T2), "--scope", "repo:x"])
    assert rc == 0 and "0 holder" in out and "alice" not in out


def test_cli_recall_rejects_bad_as_of(_store):
    rc, out = _run(["memory", "recall", "x", "--as-of", "not-a-date"])
    assert rc == 2 and "could not parse" in out
