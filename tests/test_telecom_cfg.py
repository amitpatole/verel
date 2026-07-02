"""Phase 2 — telecom declared config-invariant grader (deterministic 5G-Core invariants)."""
from __future__ import annotations

from datetime import date

import pytest

pytest.importorskip("yaml", reason="telecom grader tests need verel[telecom] (pyyaml)")

from verel.ci.telecom_cfg import (
    BUILTIN_RULES,
    apply_waivers,
    grade_cfg,
    load_cfg_rules,
    normalize_helm_values,
    rule_mtu_coherence,
    rule_redundancy_floor,
    rule_sbi_tls,
    rule_snssai_consistency,
    rule_suci_security_posture,
    rule_ue_pool_sanity,
    rule_upf_interface_separation,
)
from verel.ci.telecom_model import NF, Endpoint, TelecomConfigModel
from verel.verdict.constants import PRECISE_GRADERS
from verel.verdict.gate import verify_signature
from verel.verdict.models import GraderKind, IssueKind, Severity, Verdict


def _tcm(*nfs: NF) -> TelecomConfigModel:
    return TelecomConfigModel(nfs=list(nfs))


def _errs(issues) -> list:
    return [i for i in issues if i.severity == Severity.ERROR]


def test_telecom_cfg_kind_is_precise():
    assert GraderKind.TELECOM_CFG in PRECISE_GRADERS


# --------------------------------------------------------------------------- adapter
def test_adapter_projects_open5gs_values():
    tcm = normalize_helm_values("""
amf: {replicaCount: 2, configmap: {amf: {plmn_support: [{plmn_id: {mcc: 1, mnc: 1}, s_nssai: [{sst: 1}]}]}}}
smf: {configmap: {smf: {info: [{s_nssai: [{sst: 1, dnn: [internet]}]}], session: [{subnet: 10.45.0.0/16, dnn: internet}]}}}
""")
    amf = tcm.of_kind("AMF")[0]
    assert amf.replicas == 2 and amf.plmns == ["1-1"]
    assert amf.attrs["plmn_slices"]["1-1"] == ["1"]
    assert tcm.of_kind("SMF")[0].attrs["slice_dnns"] == {"1": ["internet"]}


# --------------------------------------------------------------------------- rule 1: snssai-consistency
def _p(rid):  # default params + gating severity for a built-in
    return {**BUILTIN_RULES[rid].params, "_severity": BUILTIN_RULES[rid].severity}


def test_snssai_smf_missing_from_nssf_fails():
    smf = NF("SMF", "smf", snssais=["1-000002"], attrs={"slice_dnns": {"1-000002": ["ims"]}, "upf_pool": [{"dnns": []}]})
    nssf = NF("NSSF", "nssf", snssais=["1-000001"])
    issues = rule_snssai_consistency(_tcm(smf, nssf), _p("snssai-consistency"))
    errs = _errs(issues)
    assert errs and errs[0].kind == IssueKind.CROSS_NF_MISMATCH
    assert "1-000002" in errs[0].message


def test_snssai_consistent_passes():
    smf = NF("SMF", "smf", snssais=["1-000001"], attrs={"slice_dnns": {"1-000001": ["internet"]}, "upf_pool": [{"dnns": []}]})
    nssf = NF("NSSF", "nssf", snssais=["1-000001"])
    amf = NF("AMF", "amf", plmns=["1-1"], attrs={"plmn_slices": {"1-1": ["1-000001"]}})
    assert _errs(rule_snssai_consistency(_tcm(smf, nssf, amf), _p("snssai-consistency"))) == []


def test_snssai_slice_without_upf_fails():
    smf = NF("SMF", "smf", snssais=["1"], attrs={"slice_dnns": {"1": ["ims"]},
                                                 "upf_pool": [{"dnns": ["internet"]}]})  # ims not covered
    nssf = NF("NSSF", "nssf", snssais=["1"])
    errs = _errs(rule_snssai_consistency(_tcm(smf, nssf), _p("snssai-consistency")))
    assert any("via DNN ims" in e.message for e in errs)


# --------------------------------------------------------------------------- rule 2: ue-pool-sanity
def test_pool_overlap_fails():
    smf = NF("SMF", "smf", attrs={"sessions": [
        {"dnn": "internet", "subnet": "10.45.0.0/16", "loc": "a"},
        {"dnn": "ims", "subnet": "10.45.1.0/24", "loc": "b"}], "slice_dnns": {}, "upf_pool": []})
    errs = _errs(rule_ue_pool_sanity(_tcm(smf), _p("ue-pool-sanity")))
    assert any(e.kind == IssueKind.CROSS_NF_MISMATCH for e in errs)


def test_pool_same_dnn_identical_ok():
    smf = NF("SMF", "smf", attrs={"sessions": [{"dnn": "internet", "subnet": "10.45.0.0/16", "loc": "a"}],
                                  "slice_dnns": {}, "upf_pool": []})
    upf = NF("UPF", "upf", attrs={"sessions": [{"dnn": "internet", "subnet": "10.45.0.0/16", "loc": "b"}]})
    assert _errs(rule_ue_pool_sanity(_tcm(smf, upf), _p("ue-pool-sanity"))) == []


# --------------------------------------------------------------------------- rule 3: interface separation
def test_upf_n3_n6_overlap_fails():
    upf = NF("UPF", "upf", endpoints=[Endpoint("N3", "192.168.100.0/24", "n3"),
                                      Endpoint("N6", "192.168.100.0/24", "n6")])
    assert _errs(rule_upf_interface_separation(_tcm(upf), _p("upf-interface-separation")))


def test_upf_insufficient_evidence_is_info_not_fail():
    upf = NF("UPF", "upf", endpoints=[Endpoint("N3", "10.0.0.5/32", "n3")])  # bare host, no N6
    issues = rule_upf_interface_separation(_tcm(upf), _p("upf-interface-separation"))
    assert _errs(issues) == [] and any(i.severity == Severity.INFO for i in issues)


# --------------------------------------------------------------------------- rule 4: redundancy
def test_redundancy_floor_fails_and_passes():
    assert _errs(rule_redundancy_floor(_tcm(NF("AMF", "amf", replicas=1)),
                                       {"floors": {"AMF": 2}, "_severity": "error"}))
    assert _errs(rule_redundancy_floor(_tcm(NF("AMF", "amf", replicas=2)),
                                       {"floors": {"AMF": 2}, "_severity": "error"})) == []


# --------------------------------------------------------------------------- rule 5: SUCI
def test_suci_null_scheme_and_nia0_fail():
    udm = NF("UDM", "udm", attrs={"hnet": [{"scheme": 0, "key_present": True, "loc": "h"}]})
    amf = NF("AMF", "amf", attrs={"integrity_order": ["NIA0", "NIA2"], "ciphering_order": ["NEA0"]})
    errs = _errs(rule_suci_security_posture(_tcm(udm, amf), _p("suci-security-posture")))
    msgs = " ".join(e.message for e in errs)
    assert "null protection scheme" in msgs and "NIA0" in msgs and "NEA0" in msgs


def test_suci_good_posture_passes():
    udm = NF("UDM", "udm", attrs={"hnet": [{"scheme": 1, "key_present": True, "loc": "h"}]})
    amf = NF("AMF", "amf", attrs={"integrity_order": ["NIA2"], "ciphering_order": ["NEA2", "NEA0"]})
    assert _errs(rule_suci_security_posture(_tcm(udm, amf), _p("suci-security-posture"))) == []


# --------------------------------------------------------------------------- rule 6: SBI TLS
def test_sbi_http_fails():
    nf = NF("SMF", "smf", attrs={"sbi_client_uris": [{"uri": "http://nrf:7777", "loc": "u"}], "sbi_scheme": "https"})
    assert _errs(rule_sbi_tls(_tcm(nf), _p("sbi-tls")))


# --------------------------------------------------------------------------- rule 7: MTU
def test_mtu_too_large_fails():
    smf = NF("SMF", "smf", attrs={"mtu": 1500})
    assert _errs(rule_mtu_coherence(_tcm(smf), {"encap_overhead": 60, "n3_transport_mtu": 1500, "_severity": "error"}))
    smf_ok = NF("SMF", "smf", attrs={"mtu": 1400})
    assert _errs(rule_mtu_coherence(_tcm(smf_ok), {"encap_overhead": 60, "n3_transport_mtu": 1500, "_severity": "error"})) == []


# --------------------------------------------------------------------------- loader (fail-closed)
def test_loader_none_runs_all_builtins():
    assert len(load_cfg_rules(None)) == len(BUILTIN_RULES)


def test_loader_unknown_rule_raises():
    with pytest.raises(ValueError, match="unknown telecom rule"):
        load_cfg_rules({"version": 1, "rules": [{"id": "no-such-rule"}]})


def test_loader_bad_version_and_severity_raise():
    with pytest.raises(ValueError, match="version"):
        load_cfg_rules({"version": 2, "rules": []})
    with pytest.raises(ValueError, match="severity"):
        load_cfg_rules({"version": 1, "rules": [{"id": "mtu-coherence", "severity": "critical"}]})


def test_loader_waiver_requires_expiry_and_reason():
    with pytest.raises(ValueError):
        load_cfg_rules({"version": 1, "rules": [{"id": "sbi-tls", "waivers": [{"id": "W1"}]}]})


# --------------------------------------------------------------------------- waivers
def _sbi_http_rules(waiver_expiry: str):
    return load_cfg_rules({"version": 1, "defaults": {"enabled": False}, "rules": [
        {"id": "sbi-tls", "waivers": [{"id": "W1", "expiry": waiver_expiry, "reason": "mesh mTLS tracked"}]}]})


def test_active_waiver_downgrades_to_info_non_gating():
    nf = NF("SMF", "smf", attrs={"sbi_client_uris": [{"uri": "http://nrf:7777", "loc": "u"}], "sbi_scheme": "https"})
    rules = _sbi_http_rules("2099-01-01")
    issues = rule_sbi_tls(_tcm(nf), {**BUILTIN_RULES["sbi-tls"].params, "_severity": "error"})
    waived = apply_waivers(issues, rules, date(2026, 7, 1))
    assert _errs(waived) == []  # no longer gates
    assert any(i.severity == Severity.INFO and "WAIVED" in i.message for i in waived)


def test_expired_waiver_does_not_suppress():
    nf = NF("SMF", "smf", attrs={"sbi_client_uris": [{"uri": "http://nrf:7777", "loc": "u"}], "sbi_scheme": "https"})
    rules = _sbi_http_rules("2020-01-01")  # expired
    issues = rule_sbi_tls(_tcm(nf), {**BUILTIN_RULES["sbi-tls"].params, "_severity": "error"})
    waived = apply_waivers(issues, rules, date(2026, 7, 1))
    assert _errs(waived)  # still gates
    assert any("expired" in i.message for i in waived)


# --------------------------------------------------------------------------- end-to-end
_BROKEN = """
smf:
  configmap:
    smf:
      info: [{s_nssai: [{sst: 1, sd: "000002", dnn: [ims]}]}]
      session: [{subnet: 10.46.0.0/16, dnn: ims}]
      pfcp: {client: {upf: [{address: upf}]}}
nssf:
  configmap:
    nssf:
      sbi:
        client:
          nsi:
            - {uri: "https://nrf:7777", s_nssai: {sst: 1, sd: "000001"}}
"""
_FIXED = _BROKEN.rstrip() + '\n            - {uri: "https://nrf:7777", s_nssai: {sst: 1, sd: "000002"}}\n'
_ONLY_SNSSAI = {"version": 1, "defaults": {"enabled": False}, "rules": [{"id": "snssai-consistency"}]}


def test_grade_cfg_fail_then_pass_with_receipt(tmp_path):
    (tmp_path / "broken.yaml").write_text(_BROKEN)
    rep = grade_cfg(str(tmp_path), values="broken.yaml", rules=_ONLY_SNSSAI)
    assert rep.verdict == Verdict.FAIL
    assert rep.run_receipt and verify_signature(rep.run_receipt)
    assert any("1-000002" in (i.locator or "") + i.message for i in rep.issues)

    (tmp_path / "fixed.yaml").write_text(_FIXED)
    rep2 = grade_cfg(str(tmp_path), values="fixed.yaml", rules=_ONLY_SNSSAI)
    assert rep2.verdict == Verdict.PASS


def test_grade_cfg_path_traversal_refused(tmp_path):
    with pytest.raises(ValueError, match="escapes the repo"):
        grade_cfg(str(tmp_path), values="../../../etc/hosts")


# --------------------------------------------------------------------------- red-team R1 regressions
def test_suci_null_scheme_string_typed_still_flagged():
    # R1 F1: a quoted "0"/"0x0" scheme must not evade the null-scheme gate
    for bad in ("0", "0x0", 0):
        udm = NF("UDM", "udm", attrs={"hnet": [{"scheme": bad, "key_present": True, "loc": "h"}]})
        errs = _errs(rule_suci_security_posture(_tcm(udm), _p("suci-security-posture")))
        assert any("null protection scheme" in e.message for e in errs), bad


def test_mtu_string_and_float_still_flagged():
    # R1 F2: a present string/float mtu must not silently default to 1400
    for bad in ("9000", 9000.0):
        smf = NF("SMF", "smf", attrs={"mtu": bad})
        assert _errs(rule_mtu_coherence(_tcm(smf), {"encap_overhead": 60, "n3_transport_mtu": 1500, "_severity": "error"}))


def test_pool_overlap_detection_and_perf():
    # R1 F3: overlap still detected, and a large flat session list is O(n log n) (no O(n²) hang)
    import time
    smf = NF("SMF", "smf", attrs={"sessions": [
        {"dnn": "a", "subnet": "10.45.0.0/16", "loc": "a"},
        {"dnn": "b", "subnet": "10.45.1.0/24", "loc": "b"}], "slice_dnns": {}, "upf_pool": []})
    assert _errs(rule_ue_pool_sanity(_tcm(smf), _p("ue-pool-sanity")))
    big = NF("SMF", "smf", attrs={"sessions": [
        {"dnn": f"d{i}", "subnet": f"10.{i // 256}.{i % 256}.0/24", "loc": str(i)} for i in range(8000)],
        "slice_dnns": {}, "upf_pool": []})
    t0 = time.monotonic()
    rule_ue_pool_sanity(_tcm(big), _p("ue-pool-sanity"))
    assert time.monotonic() - t0 < 5.0  # was ~39s at n=8000 with the O(n²) scan


def test_disabling_all_rules_is_not_a_silent_pass(tmp_path):
    # R1 F4: defaults.enabled:false with no rules must WARN, not grade a clean PASS
    (tmp_path / "v.yaml").write_text("amf: {configmap: {amf: {security: {integrity_order: [NIA0]}}}}")
    rep = grade_cfg(str(tmp_path), values="v.yaml", rules={"version": 1, "defaults": {"enabled": False}})
    assert rep.verdict == Verdict.WARN
    assert any("no telecom invariants are active" in i.message for i in rep.issues)


def test_enabled_null_treated_as_default():
    rules = load_cfg_rules({"version": 1, "defaults": {"enabled": False},
                            "rules": [{"id": "sbi-tls", "enabled": None}]})
    assert [r.id for r in rules] == ["sbi-tls"]


def test_nssf_absent_with_smf_slices_warns():
    # R1 F5: omitting NSSF must surface (WARNING), not silently pass
    smf = NF("SMF", "smf", snssais=["1"], attrs={"slice_dnns": {"1": ["internet"]}, "upf_pool": [{"dnns": []}]})
    issues = rule_snssai_consistency(_tcm(smf), _p("snssai-consistency"))
    assert any(i.severity == Severity.WARNING and "no NSSF" in i.message for i in issues)
    assert _errs(issues) == []


def test_upf_n3_n6_identical_host_flagged():
    # R1 F6: an exact N3==N6 /32 host collision is a violation, not "insufficient evidence"
    upf = NF("UPF", "upf", endpoints=[Endpoint("N3", "10.0.0.5/32", "n3"), Endpoint("N6", "10.0.0.5/32", "n6")])
    assert _errs(rule_upf_interface_separation(_tcm(upf), _p("upf-interface-separation")))


def test_deeply_nested_yaml_fails_closed(tmp_path):
    (tmp_path / "deep.yaml").write_text("a: " + "[" * 60000)
    with pytest.raises(ValueError, match="invalid YAML"):
        grade_cfg(str(tmp_path), values="deep.yaml")


def test_snssai_sd_normalization():
    # R1 F8: SD forms that mean the same slice canonicalize identically (no false FAIL / no fail-open)
    from verel.ci.telecom_model import canonical_snssai
    same = {canonical_snssai(1, "000001"), canonical_snssai(1, 1), canonical_snssai(1, "1"),
            canonical_snssai(1, "0x1"), canonical_snssai("1-000001")}
    assert same == {"1-000001"}
    assert canonical_snssai(1, "ffffff") == "1"  # "no SD" collapses to SST-only
    assert canonical_snssai(1, "000002") != canonical_snssai(1, "000001")  # distinct stays distinct


# --------------------------------------------------------------------------- red-team R2 regressions
def test_suci_invalid_scheme_warns():
    # R2 #1: a scheme outside {0,1,2} is not silently accepted
    for bad in (3, 99, "abc"):
        udm = NF("UDM", "udm", attrs={"hnet": [{"scheme": bad, "key_present": True, "loc": "h"}]})
        issues = rule_suci_security_posture(_tcm(udm), _p("suci-security-posture"))
        assert any("unrecognized SUCI protection scheme" in i.message for i in issues), bad


def test_sd_int_and_string_consistent():
    # R2 #2: an int and the string of the SAME text canonicalize identically (both parsed as hex, the
    # way a chart renders the value into the NF config) — no int-vs-string interpretation split.
    from verel.ci.telecom_model import canonical_snssai
    assert canonical_snssai(1, 10) == canonical_snssai(1, "10") == "1-000010"  # text "10" → 0x10
    assert canonical_snssai(1, 1) == canonical_snssai(1, "1") == "1-000001"
    # R3: underscore digit-grouping must NOT be accepted (would let "1_0" collide with "10")
    assert canonical_snssai(1, "1_0") == "1-1_0"  # unparseable → kept verbatim, distinct from "1-000010"


def test_duplicate_rule_id_rejected():
    # R2 #3: a duplicate id (later enabled:false) is a silent-disable / review-evasion path → reject
    with pytest.raises(ValueError, match="duplicate telecom rule"):
        load_cfg_rules({"version": 1, "rules": [
            {"id": "suci-security-posture", "severity": "error"},
            {"id": "suci-security-posture", "enabled": False}]})
