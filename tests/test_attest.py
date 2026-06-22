"""ed25519 publicly-verifiable receipts (substrate §11) — the attack table, regression-pinned.

Every row of SUBSTRATE_DESIGN §11.4 gets at least one test. The cardinal property: a valid ed25519
signature is necessary but NOT sufficient — the key_id must be TRUSTED (pinning, never TOFU).
"""

import json

import pytest

pytest.importorskip("nacl", reason="ed25519 receipt tests need verel[attest] (pynacl)")
from nacl.signing import SigningKey  # noqa: E402 - after importorskip guard

from verel.verdict import (
    Confidence,
    GraderKind,
    Issue,
    IssueKind,
    ReceiptVerification,
    Report,
    RunReceipt,
    Severity,
    Verdict,
    assign,
    attest_self,
    gate,
    keys,
    verify_receipt,
    verify_signature,
)
from verel.verdict.models import report_result_digest

ED = "ed25519"


# --- helpers ----------------------------------------------------------------
def _report(grader=GraderKind.SECURITY, issues=None, errored=False):
    r = Report(verdict=Verdict.FAIL if issues else Verdict.PASS, summary="", grader=grader,
               issues=issues or [], errored=errored)
    return assign(r)


def _base_receipt(report, suite_sha="abc", files=("src/a.py",)):
    return RunReceipt(
        suite_sha=suite_sha, inputs_digest="d",
        coverage_assertion=f"scanned files: {','.join(files)}",
        runner_identity="", result_digest=report_result_digest(report), signature="")


def _self_signed(report, suite_sha="abc", files=("src/a.py",)):
    rr = _base_receipt(report, suite_sha, files)
    attest_self(rr)  # stamps alg=ed25519 + own identity + inline pubkey, signs with the own key
    return rr


def _foreign_keypair(seed_byte=0x99):
    sk = SigningKey(bytes([seed_byte]) * 32)
    return sk, keys.key_id_for(bytes(sk.verify_key))


def _foreign_signed(report, sk, key_id, *, suite_sha="abc", files=("src/a.py",), inline=True):
    rr = _base_receipt(report, suite_sha, files)
    rr.alg = ED
    rr.runner_identity = f"ed25519:{key_id}"
    if inline:
        rr.public_key = keys._b64e(bytes(sk.verify_key))
    rr.signature = keys._b64e(sk.sign(rr.signing_payload().encode()).signature)
    return rr


@pytest.fixture
def trusted_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("VEREL_TRUSTED_KEYS", str(tmp_path))
    return tmp_path


def _publish(trusted_dir, sk, key_id):
    (trusted_dir / f"{key_id}.pub").write_text(keys._b64e(bytes(sk.verify_key)))


# --- happy path -------------------------------------------------------------
def test_own_key_roundtrip_is_public_verifiable():
    rr = _self_signed(_report())
    assert rr.alg == ED and rr.runner_identity.startswith("ed25519:")
    assert verify_signature(rr) is True
    res = verify_receipt(rr)
    assert isinstance(res, ReceiptVerification)
    assert res.valid and res.public_verifiable


def test_published_foreign_key_is_trusted(trusted_dir):
    """The substrate DoD: a SECOND party verifies with only the producer's PUBLIC key."""
    sk, kid = _foreign_keypair()
    rr = _foreign_signed(_report(), sk, kid)
    assert verify_signature(rr) is False          # not published yet → untrusted
    _publish(trusted_dir, sk, kid)
    assert verify_signature(rr) is True            # now trusted → verifies offline, no secret
    assert verify_receipt(rr).public_verifiable


# --- the TOFU trap (the cardinal property) ----------------------------------
def test_untrusted_key_rejected_even_with_valid_signature():
    sk, kid = _foreign_keypair()
    rr = _foreign_signed(_report(), sk, kid)       # cryptographically self-consistent...
    assert verify_signature(rr) is False           # ...but the key is not trusted → REJECTED
    assert "not trusted" in verify_receipt(rr).reason


# --- algorithm confusion / downgrade ----------------------------------------
def test_downgrade_ed25519_to_hmac_rejected():
    rr = _self_signed(_report())
    rr.alg = "hmac-sha256"                          # claim a different scheme over the same bytes
    assert verify_signature(rr) is False


def test_confusion_hmac_to_ed25519_rejected():
    from verel.verdict.gate import sign_receipt
    rr = _base_receipt(_report())
    rr.runner_identity = "ci-runner"
    rr.signature = sign_receipt(rr)                 # a genuine HMAC receipt
    assert verify_signature(rr) is True
    rr.alg = ED                                     # now masquerade as ed25519
    assert verify_signature(rr) is False


def test_unknown_alg_fails_closed():
    rr = _self_signed(_report())
    rr.alg = "rot13"
    assert verify_signature(rr) is False
    assert "unknown alg" in verify_receipt(rr).reason


# --- inline pubkey pinning --------------------------------------------------
def test_inline_pubkey_swap_rejected(trusted_dir):
    sk, kid = _foreign_keypair()
    rr = _foreign_signed(_report(), sk, kid)
    _publish(trusted_dir, sk, kid)
    assert verify_signature(rr) is True
    # swap the inline pubkey to an unrelated key while keeping the trusted key_id
    other, _ = _foreign_keypair(0x42)
    rr.public_key = keys._b64e(bytes(other.verify_key))
    assert verify_signature(rr) is False           # inline pubkey no longer hashes to key_id


def test_inline_pubkey_not_matching_keyid_rejected(trusted_dir):
    sk, kid = _foreign_keypair()
    other, okid = _foreign_keypair(0x42)
    _publish(trusted_dir, sk, kid)
    _publish(trusted_dir, other, okid)
    rr = _foreign_signed(_report(), sk, kid)
    rr.public_key = keys._b64e(bytes(other.verify_key))  # a real, trusted, but WRONG key
    assert verify_signature(rr) is False


# --- tampering (binding inherited from the base receipt, re-pinned under ed25519) ----
def test_tampered_payload_field_rejected():
    rr = _self_signed(_report())
    rr.suite_sha = "DIFFERENT"
    assert verify_signature(rr) is False


def test_signing_payload_is_injective_across_field_boundary():
    """Red-team round 2: the old bare-'|' join let a delimiter inside a field shift the partition,
    so distinct field tuples produced identical signed bytes. Length-prefixing must keep them
    distinct — moving a '|' across the suite/inputs boundary changes the payload."""
    a = RunReceipt(suite_sha="a|", inputs_digest="b", coverage_assertion="c",
                   runner_identity="r", result_digest="d", signature="x")
    b = RunReceipt(suite_sha="a", inputs_digest="|b", coverage_assertion="c",
                   runner_identity="r", result_digest="d", signature="x")
    assert a.signing_payload() != b.signing_payload()


def test_delimiter_injection_signature_does_not_transfer(monkeypatch):
    """A signature minted over one field partition must NOT verify under a shifted partition — on
    BOTH tiers. Pins the canonicalization fix end to end."""
    from verel.verdict.gate import sign_receipt
    # ed25519 tier
    rr = _base_receipt(_report())
    rr.suite_sha, rr.inputs_digest = "a|", "b"
    attest_self(rr)
    assert verify_signature(rr) is True
    shifted = rr.model_copy()
    shifted.suite_sha, shifted.inputs_digest = "a", "|b"
    assert verify_signature(shifted) is False
    # hmac tier (shares signing_payload)
    hr = _base_receipt(_report())
    hr.suite_sha, hr.inputs_digest, hr.runner_identity = "a|", "b", "ci-runner"
    hr.signature = sign_receipt(hr)
    assert verify_signature(hr) is True
    hshift = hr.model_copy()
    hshift.suite_sha, hshift.inputs_digest = "a", "|b"
    assert verify_signature(hshift) is False


def test_unicode_keyid_charset_rejected():
    """Red-team round 2: key_id charset must be strict ASCII, not Unicode-aware isalnum()."""
    rr = _self_signed(_report())
    rr.runner_identity = "ed25519:aaaaaaaaaaaaaa²²"  # superscript-2 passes str.isalnum()
    assert verify_signature(rr) is False


# --- same-class injection on the adjacent HMAC signers (red-team round 3) ----
def test_toolsmith_signature_injection_blocked():
    """A bare '|'.join let a '|' in the untrusted code / name reuse-key shift the partition, so one
    signature validated a DIFFERENT (name, code) pair. The injective payload must block it."""
    from verel.toolsmith.registry import ToolRecord
    a = ToolRecord(name="a", version=1, code="b|2|c")
    a.sign()
    forged = ToolRecord(name="a|1|b", version=2, code="c")  # different name AND code
    forged.signature = a.signature
    assert a.verify() is True
    assert forged.verify() is False


def test_artifact_signature_injection_blocked():
    from verel.registry.artifact import SkillArtifact
    a = SkillArtifact(name="n", origin="o|x", code="def f():\n    return 1").finalize()
    assert a.verify() is True
    forged = SkillArtifact(name="n|o", origin="x", code=a.code)
    forged.content_hash = a.content_hash
    forged.signature = a.signature
    assert forged.verify() is False


# --- coverage gaps named by the round-3 holistic sweep -----------------------
def test_seed_validation_rejects_bad_input_without_leaking(monkeypatch):
    from verel.verdict.keys import MissingAttestationDep, _seed
    monkeypatch.setenv("VEREL_RUNNER_ED25519_SEED", "nothex" * 4)
    with pytest.raises(MissingAttestationDep) as e:
        _seed()
    assert "nothex" not in str(e.value)               # never echo the seed material
    monkeypatch.setenv("VEREL_RUNNER_ED25519_SEED", "ab")  # valid hex, wrong length
    with pytest.raises(MissingAttestationDep) as e2:
        _seed()
    assert "ab" not in str(e2.value).replace("32", "")


def test_verify_receipt_allowed_algs_policy_at_verb_level():
    rr = _self_signed(_report())
    res = verify_receipt(rr, allowed_algs={"hmac-sha256"})  # reject ed25519 by policy
    assert res.valid is False and "not permitted" in res.reason


def test_resolve_trusted_key_rejects_mismatched_pub(trusted_dir):
    """A .pub whose contents do NOT hash to its filename key_id must not grant trust."""
    sk, kid = _foreign_keypair()
    other, _ = _foreign_keypair(0x42)
    (trusted_dir / f"{kid}.pub").write_text(keys._b64e(bytes(other.verify_key)))  # wrong key under kid
    rr = _foreign_signed(_report(), sk, kid, inline=False)
    assert verify_signature(rr) is False


def test_cli_require_public_rejects_hmac(tmp_path, capsys):
    from verel.cli import main
    from verel.verdict.gate import sign_receipt
    rr = _base_receipt(_report())
    rr.runner_identity = "ci-runner"
    rr.signature = sign_receipt(rr)                   # HMAC receipt
    path = tmp_path / "r.json"
    path.write_text(json.dumps(rr.model_dump()))
    assert main(["verify", str(path)]) == 0           # accepted by default
    assert main(["verify", str(path), "--require-public"]) == 1  # rejected by policy


def test_cli_unreadable_receipt_exits_2(tmp_path):
    from verel.cli import main
    assert main(["verify", str(tmp_path / "nope.json")]) == 2


def test_result_binding_under_ed25519_via_gate():
    issue = Issue(kind=IssueKind.OVERFLOW, severity=Severity.ERROR, message="x",
                  source=GraderKind.SECURITY, confidence=Confidence.HIGH)
    rep = _report(issues=[issue])
    rep.run_receipt = _self_signed(rep)
    rep.issues = []                                 # strip the gating issue to force a recomputed PASS
    res = gate([rep], required={GraderKind.SECURITY}, frozen_suites={GraderKind.SECURITY: "abc"},
               diff_files={"src/a.py"})
    assert res.verdict == Verdict.FAIL and "tampered" in res.reason


# --- malformed / empty ------------------------------------------------------
def test_empty_signature_fails_closed():
    rr = _self_signed(_report())
    rr.signature = ""
    assert verify_signature(rr) is False


def test_malformed_signature_b64_fails_closed():
    rr = _self_signed(_report())
    rr.signature = "!!!not-base64!!!"
    assert verify_signature(rr) is False


def test_signature_with_embedded_garbage_rejected():
    """Strict base64 (validate=True): a stray non-alphabet byte must RAISE, not be silently
    discarded into a shorter-but-valid decode. Pins the _b64d hardening from red-team round 1."""
    rr = _self_signed(_report())
    sig = rr.signature
    rr.signature = sig[:8] + "*" + sig[8:]          # inject a non-alphabet char mid-signature
    assert verify_signature(rr) is False


def test_short_signature_fails_closed():
    rr = _self_signed(_report())
    rr.signature = keys._b64e(b"tooshort")
    assert verify_signature(rr) is False


def test_key_id_path_traversal_rejected():
    rr = _self_signed(_report())
    rr.runner_identity = "ed25519:aaaa/aaaa/aaaa12"  # 16 chars but illegal charset → no fs touch
    assert verify_signature(rr) is False


# --- missing dependency fails CLOSED ----------------------------------------
def test_missing_pynacl_fails_closed(monkeypatch):
    rr = _self_signed(_report())                    # built while pynacl present
    monkeypatch.setattr(keys, "_NACL", False)
    assert verify_signature(rr) is False            # gate path: silent fail-closed
    res = verify_receipt(rr)                         # verify verb: explicit, actionable
    assert res.valid is False and "verel[attest]" in res.reason


# --- gate policy: require public verifiability -------------------------------
def test_gate_accepts_attested_ed25519_grader():
    rep = _report()
    rep.run_receipt = _self_signed(rep)
    res = gate([rep], required={GraderKind.SECURITY}, frozen_suites={GraderKind.SECURITY: "abc"},
               diff_files={"src/a.py"})
    assert res.verdict == Verdict.PASS


def test_gate_require_public_rejects_hmac():
    from verel.verdict.gate import sign_receipt
    rep = _report()
    rr = _base_receipt(rep)
    rr.runner_identity = "ci-runner"
    rr.signature = sign_receipt(rr)                 # HMAC receipt
    rep.run_receipt = rr
    # default policy accepts HMAC...
    assert gate([rep], required={GraderKind.SECURITY}, frozen_suites={GraderKind.SECURITY: "abc"},
                diff_files={"src/a.py"}).verdict == Verdict.PASS
    # ...but a public-verifiability policy rejects it
    res = gate([rep], required={GraderKind.SECURITY}, frozen_suites={GraderKind.SECURITY: "abc"},
               diff_files={"src/a.py"}, allowed_algs={ED})
    assert res.verdict == Verdict.FAIL and "receipt" in res.reason


def test_hmac_receipt_is_not_public_verifiable():
    from verel.verdict.gate import sign_receipt
    rr = _base_receipt(_report())
    rr.runner_identity = "ci-runner"
    rr.signature = sign_receipt(rr)
    res = verify_receipt(rr)
    assert res.valid and not res.public_verifiable


# --- CLI smoke --------------------------------------------------------------
def test_cli_verify_roundtrip(tmp_path, capsys):
    from verel.cli import main
    rr = _self_signed(_report())
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(rr.model_dump()))
    assert main(["verify", str(path)]) == 0
    assert "public-verifiable" in capsys.readouterr().out
