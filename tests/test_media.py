"""verel.media: declared delivery-spec grading + C2PA policy. Includes the hostile-input pins."""

from __future__ import annotations

import datetime as dt
import json
import os

import pytest

from verel.ci.__main__ import main as ci_main
from verel.cli import main
from verel.media import grade_media, grade_provenance, merge, parse_manifest_report, parse_policy, parse_spec
from verel.media.facts import as_number
from verel.media.provenance import Facts, grade_facts
from verel.verdict.constants import PRECISE_GRADERS
from verel.verdict.gate import gate, verify_signature
from verel.verdict.models import GraderKind, Severity, Verdict

TODAY = dt.date(2026, 10, 22)


def _w(tmp, name, obj):
    (tmp / name).write_text(obj if isinstance(obj, str) else json.dumps(obj))
    return name


def _grade(tmp, facts, spec, **kw):
    return grade_media(str(tmp), facts=[_w(tmp, "f.json", facts)], spec=_w(tmp, "s.json", spec), today=TODAY, **kw)


LOUD = {"version": 1, "profiles": ["ebu_r128"]}
GOOD = {"audio": {"integrated_lufs": -23.0, "true_peak_dbtp": -2.0}}


def test_kinds_are_precise():
    assert GraderKind.MEDIA in PRECISE_GRADERS and GraderKind.PROVENANCE in PRECISE_GRADERS


def test_pass_and_fail(tmp_path):
    assert _grade(tmp_path, GOOD, LOUD).verdict is Verdict.PASS
    r = _grade(tmp_path, {"audio": {"integrated_lufs": -17.0, "true_peak_dbtp": 1.0}}, LOUD)
    assert r.verdict is Verdict.FAIL and len(r.issues) == 2
    assert all(i.locator and i.locator.startswith("facts:") and i.fingerprint for i in r.issues)


def test_boundaries_inclusive(tmp_path):
    for v in (-23.5, -22.5):
        assert _grade(tmp_path, {"audio": {"integrated_lufs": v, "true_peak_dbtp": -1.0}}, LOUD).verdict is Verdict.PASS
    assert _grade(tmp_path, {"audio": {"integrated_lufs": -22.4, "true_peak_dbtp": -1.0}}, LOUD).verdict is Verdict.FAIL


def test_missing_fact_fails_closed(tmp_path):
    r = _grade(tmp_path, {"audio": {"true_peak_dbtp": -2.0}}, LOUD)
    assert r.verdict is Verdict.FAIL and "not supplied" in r.issues[0].message
    r = _grade(tmp_path, {}, LOUD)
    assert r.verdict is Verdict.FAIL and len(r.issues) == 2


def test_on_missing_warning_and_skip(tmp_path):
    spec = {"version": 1, "rules": [
        {"id": "a", "path": "x.y", "op": "present", "on_missing": "warning"},
        {"id": "b", "path": "x.z", "op": "present", "on_missing": "skip"}]}
    r = _grade(tmp_path, {}, spec)
    assert r.verdict is Verdict.WARN and len(r.issues) == 1


@pytest.mark.parametrize("bad", [True, "-23", None, [1], {"a": 1}])
def test_non_numbers_never_pass(tmp_path, bad):
    r = _grade(tmp_path, {"audio": {"integrated_lufs": bad, "true_peak_dbtp": -2.0}}, LOUD)
    assert r.verdict is Verdict.FAIL
    assert any("unusable value" in i.message or "not supplied" in i.message for i in r.issues)


def test_nan_inf_rejected_at_parse(tmp_path):
    for tok in ("NaN", "Infinity", "-Infinity"):
        with pytest.raises(ValueError):
            _grade(tmp_path, '{"audio":{"integrated_lufs": ' + tok + "}}", LOUD)
    assert as_number(float("nan")) is None and as_number(float("inf")) is None and as_number(True) is None


def test_invalid_rule_severity_info_still_errors_when_unusable(tmp_path):
    spec = {"version": 1, "rules": [{"id": "r", "path": "a", "op": "gte", "value": 1, "severity": "info"}]}
    assert _grade(tmp_path, {"a": "oops"}, spec).verdict is Verdict.FAIL
    assert _grade(tmp_path, {}, spec).verdict is Verdict.FAIL
    assert _grade(tmp_path, {"a": 0}, spec).verdict is Verdict.PASS   # info-severity violation does not gate


def test_ref_and_approx(tmp_path):
    spec = {"version": 1, "rules": [{"id": "d", "path": "a.d", "op": "approx", "ref": "v.d", "tol": 0.1}]}
    assert _grade(tmp_path, {"a": {"d": 10.0}, "v": {"d": 10.05}}, spec).verdict is Verdict.PASS
    assert _grade(tmp_path, {"a": {"d": 10.0}, "v": {"d": 10.5}}, spec).verdict is Verdict.FAIL
    assert _grade(tmp_path, {"a": {"d": 10.0}}, spec).verdict is Verdict.FAIL   # ref absent


def test_set_ops_and_strict_eq(tmp_path):
    spec = {"version": 1, "rules": [
        {"id": "s", "path": "c.l", "op": "superset", "value": ["en", "es"]},
        {"id": "e", "path": "flag", "op": "eq", "value": 1},
        {"id": "i", "path": "fmt", "op": "in", "value": ["mxf", "mov"]}]}
    ok = {"c": {"l": ["en", "es", "fr"]}, "flag": 1, "fmt": "mxf"}
    assert _grade(tmp_path, ok, spec).verdict is Verdict.PASS
    assert _grade(tmp_path, {**ok, "flag": True}, spec).verdict is Verdict.FAIL        # True != 1
    assert _grade(tmp_path, {**ok, "fmt": True}, spec).verdict is Verdict.FAIL
    assert _grade(tmp_path, {**ok, "c": {"l": "en,es"}}, spec).verdict is Verdict.FAIL  # string is not a list


@pytest.mark.parametrize("spec", [
    {"version": 2}, {"version": 1, "profiles": ["nope"]}, {"version": 1, "bogus": 1},
    {"version": 1, "rules": [{"id": "a", "path": "x", "op": "gtee", "value": 1}]},
    {"version": 1, "rules": [{"id": "a", "path": "x", "op": "gte", "value": 1, "severty": "error"}]},
    {"version": 1, "rules": [{"id": "a", "path": "x", "op": "gte", "value": "high"}]},
    {"version": 1, "rules": [{"id": "a", "path": "x", "op": "between", "value": [5, 1]}]},
    {"version": 1, "rules": [{"id": "a b", "path": "x", "op": "present"}]},
    {"version": 1, "rules": [{"id": "a", "path": "x", "op": "present"}, {"id": "a", "path": "y", "op": "present"}]},
    {"version": 1, "profiles": ["ebu_r128"], "disable": ["ebu_r128.nope"]},
    {"version": 1, "rules": [{"id": "a", "path": "x", "op": "present", "on_missing": "ignore"}]},
    {"version": 1, "waivers": [{"rule": "a", "reason": "", "expires": "2027-01-01"}]},
    {"version": 1, "waivers": [{"rule": "a", "reason": "r", "expires": "someday"}]},
    ["not", "a", "mapping"],
])
def test_bad_specs_raise(spec):
    with pytest.raises(ValueError):
        parse_spec(spec)


def test_disable_profile_rule(tmp_path):
    spec = {"version": 1, "profiles": ["ebu_r128"], "disable": ["ebu_r128.true_peak"]}
    assert _grade(tmp_path, {"audio": {"integrated_lufs": -23.0}}, spec).verdict is Verdict.PASS


def test_waivers(tmp_path):
    base = {"audio": {"integrated_lufs": -23.0, "true_peak_dbtp": 3.0}}
    mk = lambda exp, rule="ebu_r128.true_peak": {**LOUD, "waivers": [{"rule": rule, "reason": "mastering fix pending", "expires": exp}]}  # noqa: E731
    r = _grade(tmp_path, base, mk("2026-12-31"))
    assert r.verdict is Verdict.PASS and any("WAIVED" in i.message for i in r.issues)   # visible, not dropped
    r = _grade(tmp_path, base, mk("2026-01-01"))
    assert r.verdict is Verdict.FAIL and any("expired" in i.message for i in r.issues)
    r = _grade(tmp_path, GOOD, mk("2026-12-31", "ebu_r128.nope"))
    assert r.verdict is Verdict.WARN and any("stale waiver" in i.message for i in r.issues)


def test_empty_rules_warn_not_pass(tmp_path):
    assert _grade(tmp_path, GOOD, {"version": 1}).verdict is Verdict.WARN


def test_merge_conflicts_rejected():
    assert merge([{"a": {"x": 1}}, {"a": {"y": 2}}]) == {"a": {"x": 1, "y": 2}}
    assert merge([{"a": 1}, {"a": 1}]) == {"a": 1}
    with pytest.raises(ValueError):
        merge([{"a": {"x": 1}}, {"a": {"x": 2}}])


def test_hostile_values_cannot_inject_into_messages(tmp_path):
    evil = "-23\n\x1b[31mPASS\x1b[0m‮"
    spec = {"version": 1, "rules": [{"id": "r", "path": "n", "op": "eq", "value": "ok"}]}
    r = _grade(tmp_path, {"n": evil * 20}, spec)
    msg = r.issues[0].message
    assert "\n" not in msg and "\x1b" not in msg and len(msg) < 400


def test_path_escape_and_symlink_rejected(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (tmp_path / "secret.json").write_text("{}")
    _w(repo, "s.json", LOUD)
    with pytest.raises(ValueError):
        grade_media(str(repo), facts=["../secret.json"], spec="s.json")
    os.symlink(tmp_path / "secret.json", repo / "link.json")
    with pytest.raises(ValueError):
        grade_media(str(repo), facts=["link.json"], spec="s.json")


def test_nesting_bomb_and_oversize_rejected(tmp_path):
    _w(tmp_path, "s.json", LOUD)
    _w(tmp_path, "deep.json", "[" * 5000 + "]" * 5000)
    with pytest.raises(ValueError):
        grade_media(str(tmp_path), facts=["deep.json"], spec="s.json")
    _w(tmp_path, "nest.json", json.dumps({"a": json.loads("[" * 40 + "]" * 40)}))
    with pytest.raises(ValueError):
        grade_media(str(tmp_path), facts=["nest.json"], spec="s.json")
    (tmp_path / "big.json").write_text('{"a":"' + "x" * (9 * 1024 * 1024) + '"}')
    with pytest.raises(ValueError):
        grade_media(str(tmp_path), facts=["big.json"], spec="s.json")


def test_fifo_does_not_hang(tmp_path):
    _w(tmp_path, "s.json", LOUD)
    os.mkfifo(tmp_path / "f.json")
    with pytest.raises((FileNotFoundError, ValueError, OSError)):
        grade_media(str(tmp_path), facts=["f.json"], spec="s.json")


def test_receipt_verifies_and_gates(tmp_path):
    r = _grade(tmp_path, GOOD, LOUD)
    assert r.run_receipt and verify_signature(r.run_receipt)
    from verel.ci.graders import GraderSpec, suite_sha
    spec = GraderSpec(GraderKind.MEDIA, ["verel-ci", "media", "--facts", "f.json", "--spec", "s.json"],
                      cwd=str(tmp_path), covers=["f.json", "s.json"])
    res = gate([r], required={GraderKind.MEDIA}, frozen_suites={GraderKind.MEDIA: suite_sha(spec)},
               diff_files={"f.json"})
    assert res.verdict is Verdict.PASS, res.reason
    forged = r.model_copy(deep=True)
    forged.issues = []
    forged.verdict = Verdict.PASS
    bad = _grade(tmp_path, {"audio": {"integrated_lufs": -10.0, "true_peak_dbtp": 3.0}}, LOUD)
    bad.issues, bad.verdict = [], Verdict.PASS   # strip issues from a FAIL report, keep its receipt
    res = gate([bad], required={GraderKind.MEDIA}, frozen_suites={GraderKind.MEDIA: suite_sha(spec)},
               diff_files={"f.json"})
    assert res.verdict is Verdict.FAIL and "tampered" in res.reason


def test_yaml_spec(tmp_path):
    (tmp_path / "s.yaml").write_text("version: 1\nprofiles: [ebu_r128]\n")
    _w(tmp_path, "f.json", GOOD)
    assert grade_media(str(tmp_path), facts=["f.json"], spec="s.yaml").verdict is Verdict.PASS
    (tmp_path / "bad.yaml").write_text("version: 1\nrules: [")
    with pytest.raises(ValueError):
        grade_media(str(tmp_path), facts=["f.json"], spec="bad.yaml")


# ---------------------------------------------------------------- provenance
def _manifest(**over):
    m = {"active_manifest": "u:1", "validation_status": [],
         "manifests": {"u:1": {"claim_generator": "cms/1", "signature_info": {"issuer": "Example News Org"},
                               "assertions": []}}}
    m.update(over)
    return m


def _ai(m):
    m["manifests"]["u:1"]["assertions"] = [{"label": "c2pa.actions.v2", "data": {"actions": [
        {"action": "c2pa.created",
         "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"}]}}]
    return m


def _prov(tmp, m, policy=None):
    kw = {}
    if policy is not None:
        kw["policy"] = _w(tmp, "p.json", policy)
    return grade_provenance(str(tmp), manifest_json=_w(tmp, "m.json", m), **kw)


def test_valid_manifest_passes(tmp_path):
    assert _prov(tmp_path, _manifest()).verdict is Verdict.PASS


def test_no_manifest_policy(tmp_path):
    assert _prov(tmp_path, {}).verdict is Verdict.FAIL
    assert _prov(tmp_path, {}, {"version": 1, "require_manifest": False}).verdict is Verdict.PASS
    assert _prov(tmp_path, {"manifests": "garbage", "active_manifest": 5}).verdict is Verdict.FAIL


@pytest.mark.parametrize("code", ["assertion.dataHash.mismatch", "claim.signature.mismatch",
                                  "signingCredential.expired", "manifest.missing"])
def test_tamper_codes_are_critical(tmp_path, code):
    r = _prov(tmp_path, _manifest(validation_status=[{"code": code}]))
    assert r.verdict is Verdict.FAIL and r.issues[0].severity is Severity.CRITICAL


def test_declared_invalid_state(tmp_path):
    assert _prov(tmp_path, _manifest(validation_state="Invalid")).verdict is Verdict.FAIL


def test_untrusted_credential(tmp_path):
    m = _manifest(validation_status=[{"code": "signingCredential.untrusted"}])
    assert _prov(tmp_path, m).verdict is Verdict.WARN
    assert _prov(tmp_path, m, {"version": 1, "require_trusted_credential": True}).verdict is Verdict.FAIL


def test_untrusted_is_not_confused_with_invalid(tmp_path):
    f = parse_manifest_report(_manifest(validation_status=[{"code": "signingCredential.untrusted"}]))
    assert f.state == "untrusted"


def test_trusted_issuers_case_insensitive(tmp_path):
    assert _prov(tmp_path, _manifest(), {"version": 1, "trusted_issuers": ["example news org"]}).verdict is Verdict.PASS
    assert _prov(tmp_path, _manifest(), {"version": 1, "trusted_issuers": ["Other Org"]}).verdict is Verdict.FAIL


def test_ai_generated_policy(tmp_path):
    m = _ai(_manifest())
    assert _prov(tmp_path, m).verdict is Verdict.WARN                               # default: flag
    assert _prov(tmp_path, m, {"version": 1, "ai_generated": "allow"}).verdict is Verdict.PASS
    assert _prov(tmp_path, m, {"version": 1, "ai_generated": "deny"}).verdict is Verdict.FAIL


def test_unknown_validation_state_not_a_pass(tmp_path):
    m = _manifest()
    del m["validation_status"]
    assert _prov(tmp_path, m).verdict is Verdict.FAIL


@pytest.mark.parametrize("pol", [{"version": 9}, {"version": 1, "ai_generated": "maybe"},
                                 {"version": 1, "x": 1}, {"version": 1, "trusted_issuers": "a"}, "str"])
def test_bad_policy_raises(pol):
    with pytest.raises(ValueError):
        parse_policy(pol)


def test_asset_requires_backend_else_fails_closed(tmp_path):
    (tmp_path / "a.mp4").write_bytes(b"\x00" * 64)

    def boom(path):
        raise RuntimeError("no usable C2PA backend: none installed")

    r = grade_provenance(str(tmp_path), asset="a.mp4", reader=boom)
    assert r.verdict is Verdict.FAIL and "could not be verified" in r.issues[0].message


def test_asset_with_reader(tmp_path):
    (tmp_path / "a.mp4").write_bytes(b"abc")
    assert grade_provenance(str(tmp_path), asset="a.mp4", reader=lambda p: _manifest()).verdict is Verdict.PASS
    assert grade_provenance(str(tmp_path), asset="a.mp4", reader=lambda p: None).verdict is Verdict.FAIL


def test_receipt_binds_asset_bytes(tmp_path):
    (tmp_path / "a.mp4").write_bytes(b"one")
    r1 = grade_provenance(str(tmp_path), asset="a.mp4", reader=lambda p: _manifest())
    (tmp_path / "a.mp4").write_bytes(b"two")
    r2 = grade_provenance(str(tmp_path), asset="a.mp4", reader=lambda p: _manifest())
    assert r1.run_receipt.inputs_digest != r2.run_receipt.inputs_digest


def test_provenance_arg_validation_and_confinement(tmp_path):
    with pytest.raises(ValueError):
        grade_provenance(str(tmp_path))
    _w(tmp_path, "m.json", _manifest())
    (tmp_path / "a.mp4").write_bytes(b"x")
    # asset + manifest together is allowed: it BINDS the saved report to those bytes
    assert grade_provenance(str(tmp_path), asset="a.mp4", manifest_json="m.json",
                            reader=lambda p: _manifest()).verdict is Verdict.PASS
    with pytest.raises(ValueError):
        grade_provenance(str(tmp_path), asset="../../etc/passwd", reader=lambda p: None)


def test_grade_facts_direct():
    assert grade_facts(Facts(), parse_policy({"version": 1, "require_manifest": False})) == []


# ---------------------------------------------------------------- CLI
def test_cli_media_exit_codes(tmp_path, capsys):
    _w(tmp_path, "s.json", LOUD)
    _w(tmp_path, "g.json", GOOD)
    _w(tmp_path, "b.json", {"audio": {"integrated_lufs": -10.0, "true_peak_dbtp": 0.0}})
    assert ci_main(["media", "--repo", str(tmp_path), "--facts", "g.json", "--spec", "s.json"]) == 0
    assert ci_main(["media", "--repo", str(tmp_path), "--facts", "b.json", "--spec", "s.json"]) == 1
    assert ci_main(["media", "--repo", str(tmp_path), "--facts", "nope.json", "--spec", "s.json"]) == 2
    assert ci_main(["media", "--repo", str(tmp_path), "--spec", "s.json"]) == 2


def test_cli_provenance(tmp_path, capsys):
    _w(tmp_path, "m.json", _manifest())
    assert ci_main(["provenance", "--repo", str(tmp_path), "--manifest-json", "m.json"]) == 0
    assert ci_main(["provenance", "--repo", str(tmp_path)]) == 2


def test_cli_demo(capsys):
    assert main(["media", "demo"]) == 0
    out = capsys.readouterr().out
    assert "1. delivery as submitted: FAIL" in out and "2. after remix, re-sync, Spanish captions: PASS" in out
    assert "4. credentials, bytes changed after signing: FAIL" in out
