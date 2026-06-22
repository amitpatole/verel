"""Slice 0 — `gate` over MCP returns an attested verdict + a verifiable gate-level receipt (§3/§4),
and `verify` checks it with no trust in the producer.
"""

import json

import pytest

pytest.importorskip("nacl", reason="ed25519 gate-receipt tests need verel[attest] (pynacl)")

from verel.mcp_server import dispatch  # noqa: E402 - after importorskip guard
from verel.verdict import (  # noqa: E402
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
from verel.verdict.models import Issue, IssueKind, Severity, report_result_digest  # noqa: E402


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
    gr = build_gate_receipt(Verdict.PASS, [rep], attest="ed25519")
    res = verify_gate_receipt(gr)
    assert res.valid and res.public_verifiable
    assert verify_gate_receipt(gr, allowed_algs={"ed25519"}).valid  # require-public passes


def test_gate_receipt_verdict_flip_breaks_envelope_signature():
    """Round-1 finding: the aggregate verdict must be SIGNED, not just fingerprinted. Flipping it
    must break the envelope signature (an attacker can recompute a fingerprint, never a signature)."""
    gr = build_gate_receipt(Verdict.PASS, [_attested_report(attest="ed25519")], attest="ed25519")
    gr.verdict = Verdict.FAIL
    res = verify_gate_receipt(gr)
    assert res.valid is False and "envelope signature" in res.reason


def test_gate_receipt_grader_tamper_trips_fingerprint():
    gr = build_gate_receipt(Verdict.PASS, [_attested_report(attest="ed25519")], attest="ed25519")
    gr.graders[0].verdict = Verdict.FAIL  # tamper a grader line without touching the signed verdict
    res = verify_gate_receipt(gr)
    assert res.valid is False and "fingerprint" in res.reason


def test_gate_receipt_precise_relabel_attack_blocked():
    """Round-1 finding: `precise` is attacker-controlled in the verify path. Relabeling a TEST grader
    advisory to skip its signature check must NOT yield valid=True — precise is derived from KIND, and
    the envelope binds the fingerprint either way."""
    gr = build_gate_receipt(Verdict.PASS, [_attested_report(attest="ed25519")], attest="ed25519")
    gr.graders[0].precise = False          # lie: claim the TEST grader is advisory
    gr.graders[0].run_receipt = None       # and drop its receipt
    assert verify_gate_receipt(gr).valid is False
    # even if the attacker recomputes the (unsigned) fingerprint, the envelope signature still fails
    from verel.verdict.attest import _fingerprint
    gr.fingerprint = _fingerprint(gr.verdict, gr.graders)
    assert verify_gate_receipt(gr).valid is False


def test_gate_receipt_ceiling_clamped_is_signed():
    """Red-team round 2: ceiling_clamped is a safety signal — flipping it on a relayed receipt must
    break the envelope signature, not pass undetected."""
    gr = build_gate_receipt(Verdict.PASS, [_attested_report(attest="ed25519")], attest="ed25519")
    assert verify_gate_receipt(gr).valid
    gr.ceiling_clamped = not gr.ceiling_clamped
    assert verify_gate_receipt(gr).valid is False


def test_gate_receipt_precise_grader_missing_receipt_fails():
    rep = _attested_report()
    rep.run_receipt = None
    gr = build_gate_receipt(Verdict.PASS, [rep])
    res = verify_gate_receipt(gr)
    assert res.valid is False and "missing receipt" in res.reason


def test_gate_receipt_forged_grader_receipt_rejected():
    rep = _attested_report(attest="ed25519")
    gr = build_gate_receipt(Verdict.PASS, [rep], attest="ed25519")
    gr.graders[0].run_receipt.signature = keys._b64e(b"\x00" * 64)  # wrong signature
    # fingerprint binds the signature, so this trips the fingerprint check — either way invalid
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


# --- coverage pins recommended by the round-3 blast-radius sweep -------------
def test_run_stage_ed25519_thread_through(tmp_path):
    """The MCP `attest` value threads run_stage → run_grader → _receipt; the per-grader receipts come
    out ed25519 and the stage's own internal hollow-gate still passes (own-key auto-trust)."""
    from verel.ci import Stage, pytest_spec, run_stage

    stage = Stage("t", [pytest_spec(str(tmp_path))], required={GraderKind.TEST})
    res = run_stage(stage, runner=lambda cmd, cwd=None: (0, "", ""), attest="ed25519")
    assert res.verdict == Verdict.PASS
    assert res.reports[0].run_receipt.alg == "ed25519"
    gr = build_gate_receipt(res.verdict, res.reports, attest="ed25519")
    assert verify_gate_receipt(gr, allowed_algs={"ed25519"}).valid


def test_untagged_payload_signature_rejected():
    """Pins the domain-separation guarantee: a signature over the OLD untagged payload (no
    "runreceipt" tag) must be rejected, so a future refactor that drops the tag can't silently pass."""
    import hashlib
    import hmac

    from verel._sign import canonical_payload
    from verel.verdict.gate import _RUNNER_SECRET
    from verel.verdict.keys import _NACL  # noqa: F401 - ensure module import side-effects

    rr = RunReceipt(suite_sha="s", inputs_digest="i", coverage_assertion="c",
                    runner_identity="r", result_digest="d", signature="")
    old = canonical_payload(rr.alg, rr.suite_sha, rr.inputs_digest, rr.coverage_assertion,
                            rr.runner_identity, rr.result_digest)  # no "runreceipt" domain tag
    rr.signature = hmac.new(_RUNNER_SECRET, old.encode(), hashlib.sha256).hexdigest()
    from verel.verdict import verify_signature
    assert verify_signature(rr) is False


# --- host-boundary: no agent input may crash the connection (red-team round 2) ----
def test_mcp_gate_non_string_language_does_not_crash():
    """A JSON array/object `language` hits `language not in LANGS` (a dict membership test) and would
    raise TypeError past the ValueError guard — must return an error, not crash the host."""
    for bad in ([["python"]], {"a": 1}, 5, None):
        out = dispatch("verel_gate", {"repo": "/tmp", "language": bad})
        assert "error" in out


def test_mcp_dispatch_never_raises():
    assert "error" in dispatch("verel_nope", {})           # unknown tool → error, not KeyError
    assert "error" in dispatch("verel_recall", {})         # missing required arg → error
    assert "error" in dispatch("verel_build_tool", {})     # missing required arg → error


def test_mcp_dispatch_backstop_does_not_leak(monkeypatch):
    """The host-boundary backstop names only the tool + exception type, never str(e)."""
    import verel.mcp_server as m

    def boom(_args):
        raise RuntimeError("/secret/path/leak")
    monkeypatch.setitem(m.TOOLS, "verel_gate", {**m.TOOLS["verel_gate"], "fn": boom})
    out = dispatch("verel_gate", {"repo": "/tmp"})
    assert "error" in out and "/secret/path/leak" not in out["error"]
    assert "RuntimeError" in out["error"]
