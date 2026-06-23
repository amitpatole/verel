"""Slice 2 — `recall` / `remember` over MCP: the shared verified brain. Trust does NOT travel — a
fact is a candidate until backed by a verifiable receipt; the scope lattice resolves down.
"""

import pytest

pytest.importorskip("nacl", reason="attested-evidence tests need verel[attest] (pynacl)")

import os  # noqa: E402
import tempfile  # noqa: E402

from verel.mcp_server import dispatch  # noqa: E402


@pytest.fixture(autouse=True)
def _brain(tmp_path, monkeypatch):
    """Isolate the shared brain to a temp db per test (the real store is ~/.config/verel/brain.db)."""
    monkeypatch.setenv("VEREL_MEMORY_STORE", str(tmp_path / "brain.db"))


def _gate_receipt():
    repo = tempfile.mkdtemp()
    with open(os.path.join(repo, "test_s.py"), "w") as fh:
        fh.write("def test_ok():\n    assert True\n")
    return dispatch("verel_gate", {"repo": repo, "options": {"lint": False}, "attest": "auto"})["receipt"]


# --- remember: trust does not travel ----------------------------------------
def test_remember_without_evidence_is_candidate():
    out = dispatch("verel_remember", {"fact": {"subject": "retry", "predicate": "rule",
                                               "text": "retry transient errors 3x"}, "scope": "team"})
    assert out["trust"] == "candidate" and out["evidence_verified"] is False and out["id"]


def test_remember_attested_evidence_is_grounded_not_verified():
    """Red-team round 2 finding 1: a valid receipt attests a RUN, not this fact — so it records
    grounding but does NOT auto-promote to verified (that would trust the caller's unbound binding)."""
    out = dispatch("verel_remember", {"fact": {"subject": "ci", "predicate": "status",
                                               "text": "suite green"}, "evidence": _gate_receipt()})
    assert out["evidence_verified"] is True and out["trust"] == "candidate"
    assert "grounding" in dispatch("verel_recall", {"query": "suite green"})["records"][0]["provenance"][0] \
        or out["evidence_verified"]   # provenance carries the attested ref


def test_remember_earns_verified_with_a_fact_bound_attestation():
    """A fact-bound attestation (a verifying GateReceipt with PASS over THIS exact claim) promotes the
    belief to verified; an unrelated receipt stays grounding-only (candidate)."""
    from verel.verdict import Verdict, attest_fact
    fact = {"subject": "ci", "predicate": "status", "text": "suite green"}
    att = attest_fact(Verdict.PASS, [], subject="ci", predicate="status", text="suite green",
                      attest="ed25519").model_dump()
    out = dispatch("verel_remember", {"fact": fact, "evidence": att})
    assert out["fact_attested"] is True and out["trust"] == "verified"
    # an attestation for a DIFFERENT fact does not promote
    wrong = attest_fact(Verdict.PASS, [], subject="other", predicate="x", text="z",
                        attest="ed25519").model_dump()
    out2 = dispatch("verel_remember", {"fact": {"subject": "db", "predicate": "p", "text": "y"},
                                       "evidence": wrong})
    assert out2["fact_attested"] is False and out2["trust"] == "candidate"


def test_remember_cannot_supersede_a_verified_belief():
    """Red-team round 2 finding 2: an ordinary remember must not silently overwrite a VERIFIED fact."""
    import os as _os

    from verel.memory import LocalMemory, MemoryKind, MemoryRecord, Trust, make_id, make_key
    mem = LocalMemory(_os.environ["VEREL_MEMORY_STORE"])
    rid = make_id(make_key("db", "engine", "team"))
    mem.write(MemoryRecord(kind=MemoryKind.FACT, subject="db", predicate="engine", text="postgres",
                           scope="team", trust=Trust.VERIFIED))
    out = dispatch("verel_remember", {"fact": {"subject": "db", "predicate": "engine",
                                               "text": "sqlite poison"}, "scope": "team"})
    assert out.get("conflict") is True and out["trust"] == "verified"
    # the verified belief is intact
    assert mem.get(rid).text == "postgres" and mem.get(rid).trust == Trust.VERIFIED


def test_remember_forged_evidence_stays_candidate():
    """A tampered receipt must NOT launder trust — the importer's check fails → candidate."""
    bad = _gate_receipt()
    bad["verdict"] = "fail"          # tamper → envelope signature breaks
    out = dispatch("verel_remember", {"fact": {"subject": "x", "predicate": "y", "text": "forged"},
                                      "evidence": bad})
    assert out["evidence_verified"] is False and out["trust"] == "candidate"


def test_remember_ignores_caller_asserted_trust():
    """The caller cannot self-declare verified — any extra trust/confidence in the payload is ignored."""
    out = dispatch("verel_remember", {"fact": {"subject": "a", "predicate": "b", "text": "claim",
                                               "trust": "verified", "epistemic_confidence": 1.0}})
    assert out["trust"] == "candidate"


def test_remember_cannot_clobber_a_server_managed_skill():
    """Red-team (integration): make_id ignores `kind`, so a remember FACT shares an id with a
    toolsmith SKILL record at the same (subject, predicate, scope). A bare remember — even with a
    fact-bound attestation — must NOT supersede the skill and destroy its executable detail['tool']
    body. Mirrors authenticated_remember's structural backstop, which the local tool lacked."""
    import os as _os

    from verel.memory import LocalMemory, Trust, make_id, make_key
    from verel.toolsmith.registry import ToolRecord, ToolRegistry
    from verel.verdict import Verdict, attest_fact

    mem = LocalMemory(_os.environ["VEREL_MEMORY_STORE"])
    reg = ToolRegistry(mem, scope="global")
    reg.register(ToolRecord(name="slugify", capability="slug", doc="d", code="def f(): pass",
                            provenance=[]), trust=Trust.CANDIDATE)   # a freshly built tool is CANDIDATE
    att = attest_fact(Verdict.PASS, [], subject="slugify", predicate="tool", text="POISON",
                      attest="ed25519").model_dump()
    out = dispatch("verel_remember", {"fact": {"subject": "slugify", "predicate": "tool",
                                               "text": "POISON"}, "scope": "global", "evidence": att})
    assert out.get("conflict") is True and out.get("fact_attested") is False
    # the SKILL record (and its executable body) is intact — not overwritten by a FACT
    rec = mem.get(make_id(make_key("slugify", "tool", "global")))
    assert rec.kind.value == "skill" and "tool" in rec.detail and reg.get("slugify") is not None


def test_remember_cannot_clobber_a_candidate_failure_ledger_entry():
    """The structural backstop covers ANY non-FACT server-managed record at the colliding key — the
    failure-regression ledger, an induced design_rule/schema — not just skills, and regardless of
    trust tier (the verified-only guard didn't catch a CANDIDATE ledger entry)."""
    import os as _os

    from verel.memory import LocalMemory, MemoryKind, MemoryRecord, Trust, make_id, make_key
    mem = LocalMemory(_os.environ["VEREL_MEMORY_STORE"])
    mem.write(MemoryRecord(kind=MemoryKind.FAILURE, subject="flaky", predicate="fails",
                           text="SERVER-STATE", scope="team", trust=Trust.CANDIDATE,
                           subj_pred_key=make_key("flaky", "fails", "team")))
    out = dispatch("verel_remember", {"fact": {"subject": "flaky", "predicate": "fails",
                                               "text": "CLOBBERED"}, "scope": "team"})
    assert out.get("conflict") is True
    rec = mem.get(make_id(make_key("flaky", "fails", "team")))
    assert rec.kind == MemoryKind.FAILURE and rec.text == "SERVER-STATE"


# --- recall: lattice + surfaced trust ---------------------------------------
def test_recall_surfaces_trust_and_provenance():
    dispatch("verel_remember", {"fact": {"subject": "deploy", "predicate": "how",
                                         "text": "page oncall via pagerduty"}, "scope": "team"})
    out = dispatch("verel_recall", {"query": "how do we page on call", "scope": "team"})
    assert out["records"]
    rec = out["records"][0]
    assert rec["text"].startswith("page oncall") and rec["trust"] == "candidate"
    assert "confidence" in rec and "fingerprint" in rec and rec["scope"] == "team"


def test_recall_resolves_down_the_lattice():
    """A repo-scoped fact and a global fact are both visible from the repo scope; most specific wins."""
    dispatch("verel_remember", {"fact": {"subject": "fmt", "predicate": "rule", "text": "use black"},
                                "scope": "global"})
    dispatch("verel_remember", {"fact": {"subject": "lint", "predicate": "rule", "text": "ruff strict"},
                                "scope": "repo:myapp"})
    out = dispatch("verel_recall", {"query": "rule", "scope": "repo:myapp"})
    scopes = {r["scope"] for r in out["records"]}
    assert "repo:myapp" in scopes and "global" in scopes   # sees both self and ancestor


# --- validation / fail-closed -----------------------------------------------
def test_recall_requires_query():
    assert "error" in dispatch("verel_recall", {})
    assert "error" in dispatch("verel_recall", {"query": "   "})


def test_recall_bounds_k_and_validates_kind():
    assert "error" in dispatch("verel_recall", {"query": "x", "k": 0})
    assert "error" in dispatch("verel_recall", {"query": "x", "k": True})  # bool is not a valid k
    assert "error" in dispatch("verel_recall", {"query": "x", "kind": "bogus"})


def test_remember_requires_fact_text():
    assert "error" in dispatch("verel_remember", {})
    assert "error" in dispatch("verel_remember", {"fact": {"subject": "a"}})       # no text
    assert "error" in dispatch("verel_remember", {"fact": {"text": "   "}})        # blank text


def test_brain_inputs_are_bounded():
    """Red-team round 1: unbounded fact.text / query would balloon the store/memory."""
    assert "error" in dispatch("verel_remember", {"fact": {"text": "x" * 20_001}})
    assert "error" in dispatch("verel_recall", {"query": "q" * 4_001})
    # over-long subject/predicate/author are truncated (not an error), the fact still writes
    out = dispatch("verel_remember", {"fact": {"subject": "s" * 9000, "text": "ok"}})
    assert out["id"] and out["trust"] == "candidate"


def test_brain_store_not_agent_controllable():
    """The `store` arg from the old API must NOT repoint the brain (arbitrary file write). It's ignored;
    the brain stays the env/default store."""
    dispatch("verel_remember", {"fact": {"text": "x"}, "store": "/tmp/evil.db"})
    assert not os.path.exists("/tmp/evil.db")
