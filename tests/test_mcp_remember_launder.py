"""Regression: MCP verel_remember must not launder a once-rejected value to VERIFIED (round-13/C2).

The fact-attestation path in _tool_remember calls mem.promote(); a fact a human/grader previously
REJECTED must not be resurrectable by minting a passing attestation over it. The guard lives in the
promote() primitive, so this MCP caller inherits it.
"""

import verel.mcp_server as M
from verel.memory.view import MemoryKind, MemoryRecord, Trust, make_id, make_key
from verel.verdict import Verdict, attest_fact


def test_mcp_remember_cannot_relaunder_rejected_value(tmp_path, monkeypatch):
    monkeypatch.setenv("VEREL_MEMORY_BACKEND", "local")
    monkeypatch.setenv("VEREL_MEMORY_STORE", str(tmp_path / "brain.db"))
    monkeypatch.delenv("VEREL_BRAIN_URL", raising=False)

    subject, predicate, scope = "sys", "backup", "team"
    text = "backups are disabled"

    # Reject the value in the shared brain (drive trust to REJECTED, populating the ledger).
    brain = M._brain()
    rid = make_id(make_key(subject, predicate, scope))
    brain.write(MemoryRecord(id=rid, kind=MemoryKind.FACT, subject=subject, predicate=predicate,
                             text=text, scope=scope, subj_pred_key=make_key(subject, predicate, scope)))
    for _ in range(6):
        brain.contradict(rid)
    assert brain.get(rid).trust == Trust.REJECTED

    # Mint a VALID fact-bound attestation over the exact rejected claim (PASS verdict) and remember it.
    att = attest_fact(Verdict.PASS, [], subject=subject, predicate=predicate, text=text).model_dump()
    out = M._tool_remember({"fact": {"subject": subject, "predicate": predicate, "text": text},
                            "scope": scope, "evidence": att})

    # The attestation must NOT resurrect the rejected value.
    assert out["trust"] != "verified"
    assert "previously rejected" in out["reason"]
    assert M._brain().get(rid).trust != Trust.VERIFIED
