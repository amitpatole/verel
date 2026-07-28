"""Tests for DC-04: ReceiptKind — two-tier receipt model, bound in signing_payload."""


from verel.verdict.attest import build_gate_receipt
from verel.verdict.gate import sign_receipt, verify_receipt
from verel.verdict.models import GateReceipt, ReceiptKind, Verdict


def _gate_receipt(**kwargs) -> GateReceipt:
    return build_gate_receipt(Verdict.PASS, [], **kwargs)


def test_default_receipt_kind_is_committed():
    r = _gate_receipt()
    assert r.receipt_kind == ReceiptKind.COMMITTED


def test_explicit_optimistic_receipt_kind():
    r = build_gate_receipt(Verdict.PASS, [])
    r.receipt_kind = ReceiptKind.OPTIMISTIC
    # re-sign (simulating a caller that explicitly creates an OPTIMISTIC receipt)
    r.signature = sign_receipt(r)
    assert r.receipt_kind == ReceiptKind.OPTIMISTIC


def test_receipt_kind_bound_in_signing_payload():
    """The signing payload for COMMITTED and OPTIMISTIC must differ — so a flip invalidates the sig."""
    import copy
    r_committed = _gate_receipt()
    assert r_committed.receipt_kind == ReceiptKind.COMMITTED

    # Flip receipt_kind WITHOUT re-signing — the payload changes but the signature stays.
    r_flipped = copy.deepcopy(r_committed)
    r_flipped.receipt_kind = ReceiptKind.OPTIMISTIC

    p_committed = r_committed.signing_payload()
    p_optimistic = r_flipped.signing_payload()
    assert p_committed != p_optimistic, "receipt_kind must be bound into the signing payload"


def test_flipping_receipt_kind_invalidates_hmac_signature():
    """An attacker who flips COMMITTED→OPTIMISTIC on a signed receipt must not pass verify_receipt."""
    import copy
    r = _gate_receipt()
    assert verify_receipt(r).valid

    r_flipped = copy.deepcopy(r)
    r_flipped.receipt_kind = ReceiptKind.OPTIMISTIC
    result = verify_receipt(r_flipped)
    assert not result.valid, "flipping receipt_kind must invalidate the HMAC signature"


def test_receipt_kind_values():
    assert ReceiptKind.COMMITTED.value == "committed"
    assert ReceiptKind.OPTIMISTIC.value == "optimistic"


def test_gate_receipt_model_serializes_receipt_kind():
    r = _gate_receipt()
    d = r.model_dump(mode="json")
    assert d["receipt_kind"] == "committed"


def test_gate_receipt_model_round_trips_receipt_kind():
    r = _gate_receipt()
    d = r.model_dump(mode="json")
    r2 = GateReceipt.model_validate(d)
    assert r2.receipt_kind == ReceiptKind.COMMITTED
