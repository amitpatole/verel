"""Tests for DC-03: attest='auto' default — ed25519 when available, HMAC fallback."""

import pytest

from verel.verdict import keys
from verel.verdict.attest import build_gate_receipt, mint_report_receipt
from verel.verdict.gate import verify_receipt
from verel.verdict.models import Report, Verdict


def _report(verdict: Verdict = Verdict.PASS) -> Report:
    return Report(verdict=verdict, summary="test")


def test_build_gate_receipt_default_is_auto():
    """build_gate_receipt with no attest arg must use 'auto' — not hard-coded 'hmac'."""
    import inspect
    sig = inspect.signature(build_gate_receipt)
    assert sig.parameters["attest"].default == "auto"


def test_mint_report_receipt_default_is_auto():
    import inspect
    sig = inspect.signature(mint_report_receipt)
    assert sig.parameters["attest"].default == "auto"


def test_auto_produces_hmac_when_nacl_absent(monkeypatch):
    """When keys.available() is False (no PyNaCl), auto must fall back to HMAC — not raise."""
    monkeypatch.setattr(keys, "available", lambda: False)
    r = build_gate_receipt(Verdict.PASS, [])
    assert r.alg in ("hmac-sha256", "hmac")
    assert verify_receipt(r).valid


def test_auto_produces_ed25519_when_nacl_present(monkeypatch):
    """When PyNaCl is available, auto must produce an ed25519 receipt."""
    try:
        import nacl  # noqa: F401
    except ImportError:
        pytest.skip("PyNaCl not installed — ed25519 path untestable")
    # If nacl is present, keys.available() should return True; proceed.
    if not keys.available():
        pytest.skip("keys.available() is False even though nacl is importable — environment issue")
    r = build_gate_receipt(Verdict.PASS, [])
    assert r.alg == "ed25519"


def test_explicit_hmac_still_works():
    r = build_gate_receipt(Verdict.PASS, [], attest="hmac")
    assert r.alg in ("hmac-sha256", "hmac")
    assert verify_receipt(r).valid


def test_explicit_ed25519_fails_closed_when_nacl_absent(monkeypatch):
    """attest='ed25519' with no PyNaCl must fail closed, not silently downgrade to HMAC."""
    monkeypatch.setattr(keys, "available", lambda: False)
    with pytest.raises(Exception):
        # keys.attest_self should raise MissingAttestationDep when nacl is absent
        build_gate_receipt(Verdict.PASS, [], attest="ed25519")


def test_auto_receipt_verifies(monkeypatch):
    monkeypatch.setattr(keys, "available", lambda: False)
    r = build_gate_receipt(Verdict.PASS, [])
    from verel.verdict.attest import verify_gate_receipt
    v = verify_gate_receipt(r)
    assert v.valid


def test_auto_run_receipt_verifies(monkeypatch):
    monkeypatch.setattr(keys, "available", lambda: False)
    rep = _report()
    mint_report_receipt(rep, suite_sha="abc", inputs_digest="def",
                        coverage_assertion="scanned: x.py")
    assert rep.run_receipt is not None
    assert verify_receipt(rep.run_receipt).valid
