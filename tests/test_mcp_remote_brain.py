"""Roadmap item 2 — MCP recall/remember over a REMOTE authenticated brain. With VEREL_BRAIN_URL set,
the MCP tools talk to a hosted MemoryServer; verel_remember authors as an authenticated principal
(VEREL_PRINCIPAL_SEED); recall reads the shared remote brain. Local brain stays the default.
"""

import pytest

pytest.importorskip("nacl", reason="remote principal auth needs verel[attest] (pynacl)")


from verel.mcp_server import dispatch  # noqa: E402
from verel.memory import MemoryServer, Principal  # noqa: E402
from verel.verdict import Verdict, attest_fact  # noqa: E402

_SEED = "77" * 32


@pytest.fixture
def remote(tmp_path, monkeypatch):
    """An in-process remote brain with the MCP principal enrolled, wired via env."""
    alice = Principal(bytes.fromhex(_SEED))
    srv = MemoryServer(db_path=str(tmp_path / "brain.db"),
                       trusted_principals=dict([alice.enroll()])).start()
    monkeypatch.setenv("VEREL_BRAIN_URL", srv.url)
    monkeypatch.setenv("VEREL_PRINCIPAL_SEED", _SEED)
    monkeypatch.delenv("VEREL_BRAIN_TOKEN", raising=False)
    try:
        yield srv, alice
    finally:
        srv.stop()


def test_remote_remember_authenticates_as_principal(remote):
    _srv, alice = remote
    r = dispatch("verel_remember", {"fact": {"subject": "deploy", "predicate": "how",
                                             "text": "page oncall"}, "scope": "team"})
    assert r["remote"] is True and r["author"] == alice.key_id and r["trust"] == "candidate"


def test_remote_recall_reads_the_remote_brain(remote):
    dispatch("verel_remember", {"fact": {"subject": "x", "predicate": "y", "text": "shared fact"},
                                "scope": "team"})
    out = dispatch("verel_recall", {"query": "shared fact", "scope": "team"})
    assert [r["text"] for r in out["records"]] == ["shared fact"]


def test_remote_verified_via_fact_attestation(remote):
    att = attest_fact(Verdict.PASS, [], subject="ci", predicate="status", text="green",
                      attest="ed25519").model_dump()
    r = dispatch("verel_remember", {"fact": {"subject": "ci", "predicate": "status", "text": "green"},
                                    "scope": "team", "evidence": att})
    assert r["reverified"] is True and r["trust"] == "verified"


def test_remote_brain_requires_a_principal_seed(tmp_path, monkeypatch):
    """VEREL_BRAIN_URL set but no/invalid principal seed → fail closed (can read, can't author)."""
    srv = MemoryServer(db_path=str(tmp_path / "b.db")).start()
    try:
        monkeypatch.setenv("VEREL_BRAIN_URL", srv.url)
        monkeypatch.delenv("VEREL_PRINCIPAL_SEED", raising=False)
        out = dispatch("verel_remember", {"fact": {"text": "x"}})
        assert "error" in out and "PRINCIPAL_SEED" in out["error"]
        monkeypatch.setenv("VEREL_PRINCIPAL_SEED", "nothex")
        assert "error" in dispatch("verel_remember", {"fact": {"text": "x"}})
    finally:
        srv.stop()


def test_remote_unenrolled_principal_is_not_authenticated(tmp_path, monkeypatch):
    """If the configured principal isn't enrolled on the server, the signed write is rejected."""
    srv = MemoryServer(db_path=str(tmp_path / "b.db"),
                       trusted_principals={}).start()   # nobody enrolled
    try:
        monkeypatch.setenv("VEREL_BRAIN_URL", srv.url)
        monkeypatch.setenv("VEREL_PRINCIPAL_SEED", _SEED)
        r = dispatch("verel_remember", {"fact": {"subject": "a", "predicate": "b", "text": "x"},
                                        "scope": "team"})
        assert r["remote"] is True and r["conflict"] is False and r["trust"] == "candidate"
        # nothing was written (unauthenticated) — recall finds it absent
        assert dispatch("verel_recall", {"query": "x", "scope": "team"})["records"] == []
    finally:
        srv.stop()


def test_remote_wrong_bearer_token_surfaces_http_status(tmp_path, monkeypatch):
    """A bad bearer token (401) is an HTTPError (⊂URLError) — surface it as an HTTP status, not as
    'unreachable', and never leak the token."""
    alice = Principal(bytes.fromhex(_SEED))
    srv = MemoryServer(db_path=str(tmp_path / "b.db"), auth_token="right-token",
                       trusted_principals=dict([alice.enroll()])).start()
    try:
        monkeypatch.setenv("VEREL_BRAIN_URL", srv.url)
        monkeypatch.setenv("VEREL_PRINCIPAL_SEED", _SEED)
        monkeypatch.setenv("VEREL_BRAIN_TOKEN", "WRONG-token")
        out = dispatch("verel_remember", {"fact": {"subject": "a", "predicate": "b", "text": "x"}})
        assert "error" in out and "HTTP 401" in out["error"] and "WRONG-token" not in str(out)
    finally:
        srv.stop()


def test_remote_recall_wrong_bearer_surfaces_http_status(tmp_path, monkeypatch):
    """A bad bearer on RECALL (read path) gets the same friendly HTTP-status wording as remember —
    not the generic dispatch backstop ('verel_recall failed: HTTPError') — and never leaks the token."""
    srv = MemoryServer(db_path=str(tmp_path / "b.db"), auth_token="right-token").start()
    try:
        monkeypatch.setenv("VEREL_BRAIN_URL", srv.url)
        monkeypatch.setenv("VEREL_BRAIN_TOKEN", "WRONG-token")
        out = dispatch("verel_recall", {"query": "anything", "scope": "team"})
        assert "error" in out and "HTTP 401" in out["error"] and "WRONG-token" not in str(out)
    finally:
        srv.stop()


def test_remote_recall_unreachable_is_a_clean_error(monkeypatch):
    monkeypatch.setenv("VEREL_BRAIN_URL", "http://127.0.0.1:9")   # nothing listening
    out = dispatch("verel_recall", {"query": "anything", "scope": "team"})
    assert "error" in out and "unreachable" in out["error"]


def test_remote_unreachable_is_a_clean_error(monkeypatch):
    monkeypatch.setenv("VEREL_BRAIN_URL", "http://127.0.0.1:9")   # nothing listening
    monkeypatch.setenv("VEREL_PRINCIPAL_SEED", _SEED)
    out = dispatch("verel_remember", {"fact": {"subject": "a", "predicate": "b", "text": "x"}})
    assert "error" in out and "unreachable" in out["error"]


def test_no_brain_url_uses_local_brain(tmp_path, monkeypatch):
    """Backward compat: without VEREL_BRAIN_URL, remember stays local (no `remote` flag)."""
    monkeypatch.delenv("VEREL_BRAIN_URL", raising=False)
    monkeypatch.setenv("VEREL_MEMORY_STORE", str(tmp_path / "local.db"))
    out = dispatch("verel_remember", {"fact": {"subject": "a", "predicate": "b", "text": "x"},
                                      "scope": "team"})
    assert out.get("remote") is None and out["trust"] == "candidate"
