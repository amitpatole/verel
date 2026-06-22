"""Slice 0 — `gate` over MCP returns an attested verdict + a verifiable gate-level receipt (§3/§4),
and `verify` checks it with no trust in the producer.
"""

import json

from verel.mcp_server import dispatch
from verel.verdict import (
    GraderKind,
    Report,
    RunReceipt,
    Verdict,
    assign,
    attest_self,
    build_gate_receipt,
    keys,
    sign_receipt,
    verify_gate_receipt,
)
from verel.verdict.models import Issue, IssueKind, Severity, report_result_digest


# --- helpers ----------------------------------------------------------------
def _attested_report(grader=GraderKind.TEST, issues=None, *, attest="hmac", verdict=None):
    r = assign(Report(verdict=verdict or (Verdict.FAIL if issues else Verdict.PASS),
                      summary="", grader=grader, issues=issues or []))
    rr = RunReceipt(suite_sha="s", inputs_digest="i", coverage_assertion="scanned files: a.py",
                    runner_identity="", result_digest=report_result_digest(r), signature="")
    if attest == "ed25519":
        attest_self(rr)
    else:
        rr.signature = sign_receipt(rr)
    r.run_receipt = rr
    return r


# --- gate-receipt build/verify ----------------------------------------------
def test_gate_receipt_roundtrip_hmac():
    rep = _attested_report()
    gr = build_gate_receipt(Verdict.PASS, [rep])
    assert gr.issued_by.startswith("verel@") and gr.verdict == Verdict.PASS
    res = verify_gate_receipt(gr)
    assert res.valid and res.graders_checked == 1 and not res.public_verifiable  # hmac ≠ public


def test_gate_receipt_roundtrip_ed25519_is_public():
    rep = _attested_report(attest="ed25519")
    gr = build_gate_receipt(Verdict.PASS, [rep])
    res = verify_gate_receipt(gr)
    assert res.valid and res.public_verifiable
    assert verify_gate_receipt(gr, allowed_algs={"ed25519"}).valid  # require-public passes


def test_gate_receipt_fingerprint_tamper_rejected():
    gr = build_gate_receipt(Verdict.PASS, [_attested_report(attest="ed25519")])
    gr.verdict = Verdict.FAIL  # flip the headline verdict; fingerprint must no longer recompute
    res = verify_gate_receipt(gr)
    assert res.valid is False and "fingerprint" in res.reason


def test_gate_receipt_precise_grader_missing_receipt_fails():
    rep = _attested_report()
    rep.run_receipt = None
    gr = build_gate_receipt(Verdict.PASS, [rep])
    res = verify_gate_receipt(gr)
    assert res.valid is False and "missing receipt" in res.reason


def test_gate_receipt_forged_grader_receipt_rejected():
    rep = _attested_report(attest="ed25519")
    gr = build_gate_receipt(Verdict.PASS, [rep])
    gr.graders[0].run_receipt.signature = keys._b64e(b"\x00" * 64)  # wrong signature
    # fingerprint binds the signature, so this trips the fingerprint check first — either way invalid
    assert verify_gate_receipt(gr).valid is False


def test_gate_receipt_advisory_grader_needs_no_receipt():
    """A vision (advisory) report with no receipt must NOT block verification — advisory never gates."""
    adv = assign(Report(verdict=Verdict.WARN, summary="", grader=GraderKind.VISION,
                        issues=[Issue(kind=IssueKind.CONTRAST, severity=Severity.WARNING,
                                      message="low contrast", source=GraderKind.VISION)]))
    precise = _attested_report(attest="ed25519")
    gr = build_gate_receipt(Verdict.WARN, [precise, adv])
    assert verify_gate_receipt(gr).valid


def test_gate_receipt_ceiling_clamped_flag():
    """A CRITICAL advisory (vision) finding is clamped below gating — the receipt records it."""
    adv = assign(Report(verdict=Verdict.WARN, summary="", grader=GraderKind.VISION,
                        issues=[Issue(kind=IssueKind.LAYOUT, severity=Severity.CRITICAL,
                                      message="x", source=GraderKind.VISION)]))
    gr = build_gate_receipt(Verdict.WARN, [_attested_report(attest="ed25519"), adv])
    assert gr.ceiling_clamped is True


# --- MCP dispatch: validation / fail-closed ---------------------------------
def test_mcp_gate_requires_repo():
    assert "error" in dispatch("verel_gate", {})
    assert "error" in dispatch("verel_gate", {"repo": "/no/such/dir/xyz"})


def test_mcp_gate_rejects_bad_stage_and_attest(tmp_path):
    assert "error" in dispatch("verel_gate", {"repo": str(tmp_path), "stage": "nope"})
    assert "error" in dispatch("verel_gate", {"repo": str(tmp_path), "attest": "rot13"})


def test_mcp_gate_ed25519_unavailable_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(keys, "_NACL", False)
    out = dispatch("verel_gate", {"repo": str(tmp_path), "attest": "ed25519"})
    assert "error" in out and "verel[attest]" in out["error"]   # never silently downgrade


def test_mcp_gate_unknown_language_fails_closed(tmp_path):
    out = dispatch("verel_gate", {"repo": str(tmp_path), "language": "cobol"})
    assert "error" in out and "cobol" in out["error"]


# --- MCP dispatch: real repo dogfood + JSON-serializable + verify ------------
def test_mcp_gate_real_repo_dogfood(tmp_path):
    (tmp_path / "test_smoke.py").write_text("def test_ok():\n    assert 1 + 1 == 2\n")
    out = dispatch("verel_gate", {"repo": str(tmp_path), "options": {"lint": False}, "attest": "auto"})
    assert out["verdict"] == "pass"
    assert out["attest"] == "ed25519" and out["receipt_public_verifiable"] is True
    json.dumps(out)  # MUST be JSON-serializable for the MCP transport (no raw enums)
    v = dispatch("verel_verify", {"receipt": out["receipt"]})
    assert v["valid"] and v["public_verifiable"]
    vp = dispatch("verel_verify", {"receipt": out["receipt"], "require_public": True})
    assert vp["valid"] is True


def test_mcp_verify_single_run_receipt():
    rep = _attested_report(attest="ed25519")
    out = dispatch("verel_verify", {"receipt": rep.run_receipt.model_dump(mode="json")})
    assert out["valid"] and out["alg"] == "ed25519" and out["public_verifiable"]


def test_mcp_verify_malformed_receipt():
    assert "error" in dispatch("verel_verify", {})
    assert "error" in dispatch("verel_verify", {"receipt": {"suite_sha": 123}})  # wrong type
