"""Slice 1 — `sight` over MCP: render a URL → attested percept (bbox + image_ref + verifiable
receipt). Live rendering needs verel[sight] + a browser; here `perceive` is monkeypatched with a
synthetic SightResult so the attestation, mapping, and fail-closed paths are exercised hermetically.
"""

import json

from verel.mcp_server import _bbox, dispatch
from verel.senses.sight import SightResult
from verel.verdict import (
    GraderKind,
    Observation,
    Percept,
    Report,
    Verdict,
    assign,
    verify_gate_receipt,
)
from verel.verdict.models import Confidence, GateReceipt, IssueKind, Severity


def _fake_result(image_path=None):
    """A synthetic SightResult: one precise DOM grader (a real contrast finding with a bbox) plus a
    clean envelope — what perceive() would return for a rendered page."""
    obs = Observation(kind=IssueKind.CONTRAST, severity=Severity.WARNING, source=GraderKind.DOM,
                      message="contrast 3.1:1 < 4.5:1", confidence=Confidence.HIGH,
                      locator=json.dumps({"x": 10, "y": 20, "width": 100, "height": 30}),
                      locator_precise=True, fingerprint="fp-contrast")
    report = assign(Report(verdict=Verdict.WARN, summary="rendered", grader=GraderKind.DOM,
                           issues=[]))
    percept = Percept(sense="sight", verdict=Verdict.WARN, summary="a login card",
                      observations=[obs], image_path=image_path,
                      matches_intent=True, intent_satisfied=7, intent_total=8)
    return SightResult(reports=[report], percept=percept, raw=None)


def _patch_perceive(monkeypatch, result, capture=None):
    import verel.senses.sight as sight

    async def fake_perceive(url, **kwargs):
        if capture is not None:
            capture.update({"url": url, **kwargs})
        return result
    monkeypatch.setattr(sight, "perceive", fake_perceive)


# --- happy path: attested percept --------------------------------------------
def test_sight_returns_attested_percept(monkeypatch, tmp_path):
    img = tmp_path / "shot.png"
    img.write_bytes(b"\x89PNG fake bytes")
    _patch_perceive(monkeypatch, _fake_result(str(img)))
    out = dispatch("verel_sight", {"url": "https://example.com", "intent": "a centered login card",
                                   "attest": "auto"})
    assert out["verdict"] == "warn"
    assert out["image_ref"].startswith("percept://")
    assert out["matches_intent"] is True and out["intent_satisfied"] == 7
    assert out["observations"][0]["bbox"] == {"x": 10, "y": 20, "w": 100, "h": 30}
    assert out["observations"][0]["source"] == "dom" and out["observations"][0]["precise"]
    json.dumps(out)  # MCP transport must serialize cleanly
    # the receipt verifies with no producer trust, and is publicly verifiable (ed25519 available)
    assert out["attest"] == "ed25519" and out["receipt_public_verifiable"] is True
    v = dispatch("verel_verify", {"receipt": out["receipt"]})
    assert v["valid"] and v["public_verifiable"]


def test_sight_receipt_binds_to_the_image(monkeypatch, tmp_path):
    """The percept receipt's inputs_digest is bound to the screenshot bytes — verify() confirms it,
    and the gate receipt's DOM grader (precise) carries a real signed RunReceipt."""
    img = tmp_path / "a.png"
    img.write_bytes(b"image-A")
    _patch_perceive(monkeypatch, _fake_result(str(img)))
    out = dispatch("verel_sight", {"url": "https://x.io", "attest": "ed25519"})
    receipt = GateReceipt.model_validate(out["receipt"])
    res = verify_gate_receipt(receipt, allowed_algs={"ed25519"})
    assert res.valid and res.graders_checked == 1   # the DOM grader is precise → its receipt checked


def test_sight_tamper_breaks_receipt(monkeypatch, tmp_path):
    img = tmp_path / "a.png"
    img.write_bytes(b"image-A")
    _patch_perceive(monkeypatch, _fake_result(str(img)))
    out = dispatch("verel_sight", {"url": "https://x.io", "attest": "ed25519"})
    tampered = out["receipt"]
    tampered["verdict"] = "pass"   # claim a clean render
    assert dispatch("verel_verify", {"receipt": tampered})["valid"] is False


# --- SSRF / input validation (fail closed) -----------------------------------
def test_sight_requires_http_url():
    assert "error" in dispatch("verel_sight", {})
    assert "error" in dispatch("verel_sight", {"url": "file:///etc/passwd"})
    assert "error" in dispatch("verel_sight", {"url": "gopher://169.254.169.254/"})
    assert "error" in dispatch("verel_sight", {"url": 12345})


def test_sight_allow_local_defaults_off(monkeypatch, tmp_path):
    """allow_local must default to False and be forwarded explicitly only when set — the SSRF guard
    stays on unless the agent opts in."""
    cap: dict = {}
    _patch_perceive(monkeypatch, _fake_result(str(tmp_path / "x")), capture=cap)
    dispatch("verel_sight", {"url": "https://x.io"})
    assert cap["allow_local"] is False
    cap.clear()
    _patch_perceive(monkeypatch, _fake_result(str(tmp_path / "x")), capture=cap)
    dispatch("verel_sight", {"url": "https://x.io", "allow_local": True})
    assert cap["allow_local"] is True


def test_sight_viewport_parsed_into_overrides(monkeypatch, tmp_path):
    cap: dict = {}
    _patch_perceive(monkeypatch, _fake_result(str(tmp_path / "x")), capture=cap)
    dispatch("verel_sight", {"url": "https://x.io", "viewport": "1280x800"})
    assert cap["settings_overrides"] == {"default_viewport_width": 1280, "default_viewport_height": 800}
    assert "error" in dispatch("verel_sight", {"url": "https://x.io", "viewport": "wide"})


def test_sight_agentvision_absent_fails_closed(monkeypatch):
    import verel.senses.sight as sight

    async def boom(url, **kwargs):
        raise ImportError("No module named 'agentvision'")
    monkeypatch.setattr(sight, "perceive", boom)
    out = dispatch("verel_sight", {"url": "https://x.io"})
    assert "error" in out and "verel[sight]" in out["error"]


def test_sight_ed25519_unavailable_fails_closed(monkeypatch):
    from verel.verdict import keys
    monkeypatch.setattr(keys, "_NACL", False)
    out = dispatch("verel_sight", {"url": "https://x.io", "attest": "ed25519"})
    assert "error" in out and "verel[attest]" in out["error"]


# --- _bbox helper ------------------------------------------------------------
def test_bbox_parsing():
    assert _bbox(None) is None
    assert _bbox("not json") is None
    assert _bbox(json.dumps([1, 2])) is None
    assert _bbox(json.dumps({"x": 1, "y": 2, "width": 3, "height": 4})) == {"x": 1, "y": 2, "w": 3, "h": 4}
