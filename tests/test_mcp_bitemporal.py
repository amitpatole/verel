"""MCP surface for bi-temporal recall: `verel_recall` with `as_of`, and the new `verel_members_as_of`
set-membership tool. Point-in-time recall reachable by an agent host, not just the Python API."""

import pytest

from verel.mcp_server import TOOLS, dispatch


@pytest.fixture(autouse=True)
def _brain(tmp_path, monkeypatch):
    monkeypatch.setenv("VEREL_MEMORY_STORE", str(tmp_path / "brain.db"))
    monkeypatch.delenv("VEREL_BRAIN_URL", raising=False)


def _remember(subject, predicate, text, scope="team"):
    return dispatch("verel_remember", {"fact": {"subject": subject, "predicate": predicate,
                                                 "text": text}, "scope": scope})


def test_members_tool_registered():
    assert "verel_members_as_of" in TOOLS
    assert "as_of" in TOOLS["verel_recall"]["schema"]["properties"]


def test_recall_as_of_reachable_over_mcp():
    """as_of routes to recall_as_of and echoes the parsed instant (the then/now boundary itself is
    a write-time concern pinned at the Python level with explicit ts)."""
    from verel.memory import parse_when
    _remember("svc", "region", "us-west")
    out = dispatch("verel_recall", {"query": "svc region", "as_of": "2099-01-01"})
    assert out["as_of"] == parse_when("2099-01-01")
    assert any(r["text"] == "us-west" for r in out["records"])


def test_recall_brief_carries_valid_interval():
    _remember("svc", "region", "us-west")
    rec = dispatch("verel_recall", {"query": "svc region", "as_of": "2099-01-01"})["records"][0]
    assert "valid_from" in rec and "valid_to" in rec


def test_recall_rejects_bad_as_of():
    out = dispatch("verel_recall", {"query": "x", "as_of": "not-a-date"})
    assert "error" in out


def test_members_as_of_reachable_over_mcp():
    _remember("alice", "role", "admin")
    out = dispatch("verel_members_as_of", {"predicate": "role", "value": "admin",
                                           "as_of": "2099-01-01"})
    assert [m["subject"] for m in out["members"]] == ["alice"]
    assert out["predicate"] == "role" and out["value"] == "admin"


def test_members_requires_predicate_and_as_of():
    assert "error" in dispatch("verel_members_as_of", {"predicate": "role"})       # no as_of
    assert "error" in dispatch("verel_members_as_of", {"as_of": "2099-01-01"})      # no predicate
    assert "error" in dispatch("verel_members_as_of", {"predicate": "role", "as_of": "bad"})
