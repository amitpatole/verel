"""Phase 3 — classic/appliance path (PM-XML + NETCONF-NRM adapters), RAN rules, one-machinery, XXE."""
from __future__ import annotations

import pytest

from verel.ci.telecom_cfg import grade_cfg, normalize_helm_values
from verel.ci.telecom_kpi import evaluate_kpis, parse_frame
from verel.ci.telecom_model import NF, Cell, KpiThreshold, TelecomConfigModel, xml_root
from verel.ci.telecom_nrm import normalize_nrm_xml
from verel.ci.telecom_ran import (
    rule_eirp_cap,
    rule_neighbor_symmetry,
    rule_pci_collision_confusion,
    rule_tac_plmn_consistency,
)
from verel.verdict.constants import PRECISE_GRADERS
from verel.verdict.models import GraderKind, IssueKind, Severity, Verdict


def _errs(issues):
    return [i for i in issues if i.severity == Severity.ERROR]


def _tcm(*, cells=(), nfs=()):
    return TelecomConfigModel(nfs=list(nfs), cells=list(cells))


# --------------------------------------------------------------------------- XXE safety
def test_xml_root_blocks_xxe_and_billion_laughs():
    with pytest.raises(ValueError, match="invalid XML"):  # external-entity XXE
        xml_root('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>')
    with pytest.raises(ValueError, match="invalid XML"):  # DTD/entity-expansion bomb
        xml_root('<!DOCTYPE lolz [<!ENTITY a "AAAA"><!ENTITY b "&a;&a;&a;">]><lolz>&b;</lolz>')


def test_grade_cfg_dispatches_xml_and_fails_closed_on_bad_xml(tmp_path):
    (tmp_path / "bad.xml").write_text("<data><unclosed>")
    with pytest.raises(ValueError, match="invalid XML"):
        grade_cfg(str(tmp_path), values="bad.xml")


# --------------------------------------------------------------------------- NRM adapter
_NRM = """<data><ManagedElement><id>gnb-1</id>
<GNBDUFunction><id>1</id><NRCellDU><id>3</id><attributes>
<nRPCI>17</nRPCI><nRTAC>7002</nRTAC><arfcnDL>632628</arfcnDL>
<pLMNInfoList><pLMNInfo><plmnId><mcc>001</mcc><mnc>01</mnc></plmnId>
<sNssai><sst>1</sst><sd>000001</sd></sNssai></pLMNInfo></pLMNInfoList>
<cellLocalId>3</cellLocalId></attributes></NRCellDU></GNBDUFunction>
<AMFFunction><id>1</id><attributes><taiList><tai>
<plmnId><mcc>001</mcc><mnc>01</mnc></plmnId><tac>7001</tac></tai></taiList></attributes></AMFFunction>
</ManagedElement></data>"""


def test_nrm_adapter_projects_cells_and_amf():
    m = normalize_nrm_xml(_NRM)
    c = m.cells[0]
    assert c.pci == 17 and c.tac == 7002 and c.plmns == ["001-01"] and c.snssais == ["1-000001"]
    tais = m.of_kind("AMF")[0].attrs["served_tais"]
    assert tais[0]["plmn"] == "001-01" and tais[0]["tac"] == 7001


# --------------------------------------------------------------------------- tac-plmn (flagship)
def test_tac_plmn_fail_and_pass():
    cell = Cell(name="c1", pci=1, tac=7002, plmns=["001-01"], loc="x")
    amf = NF("AMF", "amf", attrs={"served_tais": [{"plmn": "001-01", "tac": 7001}]})
    assert _errs(rule_tac_plmn_consistency(_tcm(cells=[cell], nfs=[amf]), {"_severity": "error"}))
    cell.tac = 7001
    assert _errs(rule_tac_plmn_consistency(_tcm(cells=[cell], nfs=[amf]), {"_severity": "error"})) == []


def test_tac_plmn_no_amf_tai_warns_not_silent():
    cell = Cell(name="c1", tac=7001, plmns=["001-01"], loc="x")
    issues = rule_tac_plmn_consistency(_tcm(cells=[cell]), {"_severity": "error", "require_amf_tai": False})
    assert issues and issues[0].severity == Severity.WARNING and "no AMF served-TAI" in issues[0].message


def test_tac_plmn_no_cells_is_inert():
    amf = NF("AMF", "amf", attrs={"served_tais": [{"plmn": "001-01", "tac": 7001}]})
    assert rule_tac_plmn_consistency(_tcm(nfs=[amf]), {"_severity": "error"}) == []


# --------------------------------------------------------------------------- ONE MACHINERY
def test_one_machinery_helm_vs_nrm():
    """The same rule body must fire identically on a Helm and an NRM artifact (same rule_id + PLMN/TAC),
    differing ONLY in the source locator. This is the Phase-3 thesis."""
    helm = normalize_helm_values(
        'ueransim: {gnb: {plmn_id: {mcc: "001", mnc: "01"}, tac: 7002}}\n'
        'amf: {configmap: {amf: {tai: [{plmn_id: {mcc: "001", mnc: "01"}, tac: 7001}]}}}')
    nrm = normalize_nrm_xml(_NRM)
    p = {"_severity": "error"}
    hi = _errs(rule_tac_plmn_consistency(helm, p))[0]
    ni = _errs(rule_tac_plmn_consistency(nrm, p))[0]
    assert hi.detail["rule_id"] == ni.detail["rule_id"] == "tac-plmn-consistency"
    assert (hi.detail["plmn"], hi.detail["tac"]) == (ni.detail["plmn"], ni.detail["tac"]) == ("001-01", 7002)
    assert hi.locator != ni.locator  # different source paths, same finding


# --------------------------------------------------------------------------- PCI collision/confusion
def test_pci_collision_and_range():
    a = Cell(name="A", pci=17, neighbors=[{"target": "B"}], loc="a")
    b = Cell(name="B", pci=17, loc="b")
    assert any("collision" in e.message for e in _errs(rule_pci_collision_confusion(_tcm(cells=[a, b]), {"_severity": "error"})))
    bad = Cell(name="X", pci=2000, loc="x")
    assert any("out of range" in e.message for e in _errs(rule_pci_collision_confusion(_tcm(cells=[bad]), {"_severity": "error"})))


def test_pci_confusion():
    a = Cell(name="A", pci=1, neighbors=[{"target": "B"}, {"target": "C"}], loc="a")
    b = Cell(name="B", pci=5, loc="b")
    c = Cell(name="C", pci=5, loc="c")  # two neighbors share PCI 5 → confusion
    assert any("confusion" in e.message for e in _errs(rule_pci_collision_confusion(_tcm(cells=[a, b, c]), {"_severity": "error"})))


# --------------------------------------------------------------------------- neighbor symmetry
def test_neighbor_asymmetry_warns():
    a = Cell(name="A", neighbors=[{"target": "B"}], loc="a")
    b = Cell(name="B", loc="b")  # no B→A
    issues = rule_neighbor_symmetry(_tcm(cells=[a, b]), {"_severity": "warning"})
    assert any(i.severity == Severity.WARNING and "asymmetric" in i.message for i in issues)


# --------------------------------------------------------------------------- EIRP
def test_eirp_cap_fail_and_no_license_info():
    cell = Cell(name="c1", max_tx_power_dbm=50.0, attrs={"band": "n78"}, loc="x")
    lic = {"licenses": [{"band": "n78", "max_eirp_dbm": 58.0, "antenna_gain_dbi": 15}], "_severity": "error"}
    assert _errs(rule_eirp_cap(_tcm(cells=[cell]), lic))  # 50+15=65 > 58
    info = rule_eirp_cap(_tcm(cells=[cell]), {"licenses": [], "_severity": "error"})
    assert info and info[0].severity == Severity.INFO


# --------------------------------------------------------------------------- PM-XML
_PMXML = """<measCollecFile><measData><managedElement localDn="gnb1"/>
<measInfo measInfoId="rrc"><granPeriod duration="PT900S" endTime="2026-06-30T10:15:00Z"/>
<measType p="1">RRC.ConnEstabAtt</measType><measType p="2">RRC.ConnEstabSucc</measType>
<measValue measObjLdn="ManagedElement=1,GNBDUFunction=1,NRCellDU=3"><r p="1">1000</r><r p="2">912</r></measValue>
</measInfo></measData></measCollecFile>"""


def test_pmxml_derives_ratio_kpi_and_gates():
    frame = parse_frame(_PMXML)  # auto → pmxml → derive
    rate = [s for s in frame.samples if s.kpi == "RRC.ConnEstabSuccRate"][0]
    assert round(rate.value, 1) == 91.2 and rate.samples == 1000 and rate.dims["cell"] == "3"
    issues = evaluate_kpis(frame, [KpiThreshold("RRC.ConnEstabSuccRate", min=99.0, min_samples=200)])
    assert issues and issues[0].severity == Severity.ERROR


def test_pmxml_form_mismatch_fails_closed():
    bad = ('<measCollecFile><measData><measInfo><measTypes>A B</measTypes>'
           '<measValue measObjLdn="x"><measResults>1 2 3</measResults></measValue></measInfo></measData></measCollecFile>')
    with pytest.raises(ValueError, match="mismatch"):
        parse_frame(bad, fmt="pmxml")


def test_pmxml_zero_denominator_is_insufficient_not_100pct():
    z = ('<measCollecFile><measData><measInfo><granPeriod duration="PT900S" endTime="t"/>'
         '<measType p="1">RRC.ConnEstabAtt</measType><measType p="2">RRC.ConnEstabSucc</measType>'
         '<measValue measObjLdn="NRCellDU=3"><r p="1">0</r><r p="2">0</r></measValue></measInfo></measData></measCollecFile>')
    frame = parse_frame(z, fmt="pmxml")
    rate = [s for s in frame.samples if s.kpi == "RRC.ConnEstabSuccRate"][0]
    assert rate.value == 0.0 and rate.samples == 0  # insufficient → clamps to WARNING, never a fake 100%


# --------------------------------------------------------------------------- registry + end-to-end
def test_ran_rules_registered_and_precise():
    from verel.ci.telecom_cfg import BUILTIN_RULES
    assert {"tac-plmn-consistency", "pci-collision-confusion", "neighbor-symmetry", "eirp-cap"} <= set(BUILTIN_RULES)
    assert GraderKind.TELECOM_CFG in PRECISE_GRADERS


# --------------------------------------------------------------------------- red-team R1 regressions
def test_xml_element_bomb_rejected_pre_parse():
    # R1 F1: a huge flat element count must be rejected BEFORE the tree is materialized (fast, bounded)
    import time
    bomb = "<r>" + "<c/>" * 6_000_000 + "</r>"
    t0 = time.monotonic()
    with pytest.raises(ValueError, match="element/attribute count"):
        xml_root(bomb)
    assert time.monotonic() - t0 < 3.0  # was ~11s (post-parse); pre-count is ~tens of ms


def test_xml_attribute_bomb_rejected_pre_parse():
    # R2: a single element with millions of attributes must be rejected fast (pre-parse '=' proxy),
    # not parsed into a 590MB dict
    import time
    bomb = "<r " + " ".join(f'a{i}="1"' for i in range(2_000_000)) + "/>"
    t0 = time.monotonic()
    with pytest.raises(ValueError, match="element/attribute count"):
        xml_root(bomb)
    assert time.monotonic() - t0 < 3.0


def test_pci_float_and_invalid_flagged():
    # R1 F3: an integral float is range-checked; a non-integer PCI is flagged, not silently skipped
    from verel.ci.telecom_cfg import normalize_helm_values
    m = normalize_helm_values('gnb: [{pci: 1500.0, tac: 1, plmn_id: {mcc: "1", mnc: "1"}}]')
    assert any("out of range" in e.message for e in _errs(rule_pci_collision_confusion(m, {"_severity": "error"})))
    m2 = normalize_helm_values('gnb: [{pci: 1500.5, tac: 1, plmn_id: {mcc: "1", mnc: "1"}}]')
    assert any("not an integer" in e.message for e in _errs(rule_pci_collision_confusion(m2, {"_severity": "error"})))


def test_pmxml_impossible_ratio_is_unmeasurable_not_pass():
    # R1 F4: numerator > denominator (corrupt) must NOT emit a >100% value that satisfies a floor
    corrupt = ('<measCollecFile><measData><measInfo><granPeriod duration="PT900S" endTime="t"/>'
               '<measType p="1">RRC.ConnEstabAtt</measType><measType p="2">RRC.ConnEstabSucc</measType>'
               '<measValue measObjLdn="NRCellDU=3"><r p="1">100</r><r p="2">150</r></measValue>'
               '</measInfo></measData></measCollecFile>')
    frame = parse_frame(corrupt, fmt="pmxml")
    rates = [s for s in frame.samples if s.kpi == "RRC.ConnEstabSuccRate"]
    assert rates == []  # dropped → threshold sees it absent → "unmeasurable" WARNING, never a fake pass
    issues = evaluate_kpis(frame, [KpiThreshold("RRC.ConnEstabSuccRate", min=95.0)])
    assert issues and issues[0].severity == Severity.WARNING


def test_pmxml_suspect_cannot_gate():
    # R1 F5: a suspect-flagged group yields samples=0 → a breach clamps to a non-gating WARNING
    susp = ('<measCollecFile><measData><measInfo><granPeriod duration="PT900S" endTime="t"/>'
            '<measType p="1">RM.RegInitReq</measType><measType p="2">RM.RegInitSucc</measType>'
            '<measValue measObjLdn="AMFFunction=1"><r p="1">1000</r><r p="2">100</r>'
            '<suspect>true</suspect></measValue></measInfo></measData></measCollecFile>')
    frame = parse_frame(susp, fmt="pmxml")
    rate = [s for s in frame.samples if s.kpi == "RM.RegInitSuccRate"][0]
    assert rate.samples == 0  # suspect → insufficient
    issues = evaluate_kpis(frame, [KpiThreshold("RM.RegInitSuccRate", min=99.0, min_samples=200)])
    assert issues and issues[0].severity == Severity.WARNING  # 10% would gate, but suspect → WARNING


def test_nrcellrelation_under_nrcelldu_not_dropped():
    # R3: a neighbor relation NESTED under NRCellDU must be walked (was silently dropped → PCI collision
    # graded PASS). Two neighbor cells sharing PCI 5, relation under the DU → collision must FAIL.
    nrm = normalize_nrm_xml("""<data><ManagedElement><id>g1</id><GNBDUFunction><id>1</id>
<NRCellDU><id>1</id><attributes><nRPCI>5</nRPCI><cellLocalId>1</cellLocalId></attributes>
<NRCellRelation><id>r</id><attributes><adjacentNRCellRef>g1/1/NRCellDU=2</adjacentNRCellRef></attributes></NRCellRelation>
</NRCellDU>
<NRCellDU><id>2</id><attributes><nRPCI>5</nRPCI><cellLocalId>2</cellLocalId></attributes></NRCellDU>
</GNBDUFunction></ManagedElement></data>""")
    assert len(nrm.cells) == 2
    assert any(nb for c in nrm.cells for nb in c.neighbors)  # the nested relation was captured
    assert any("collision" in e.message
               for e in _errs(rule_pci_collision_confusion(nrm, {"_severity": "error"})))


def test_relation_join_independent_of_rdn_id_vs_celllocalid():
    # R4: RDN id ('cellA') ≠ cellLocalId ('7') is legal per TS 28.541. A DU-nested relation must still
    # attach (direct, no id matching) so a PCI collision gates; and a CU-nested relation must join by
    # cellLocalId, not the RDN id.
    du_nested = normalize_nrm_xml("""<data><ManagedElement><id>g1</id><GNBDUFunction><id>1</id>
<NRCellDU><id>cellA</id><attributes><nRPCI>5</nRPCI><cellLocalId>7</cellLocalId></attributes>
<NRCellRelation><id>r</id><attributes><adjacentNRCellRef>g1/1/NRCellDU=cellB</adjacentNRCellRef></attributes></NRCellRelation>
</NRCellDU><NRCellDU><id>cellB</id><attributes><nRPCI>5</nRPCI><cellLocalId>8</cellLocalId></attributes></NRCellDU>
</GNBDUFunction></ManagedElement></data>""")
    assert any("collision" in e.message for e in _errs(rule_pci_collision_confusion(du_nested, {"_severity": "error"})))

    cu_nested = normalize_nrm_xml("""<data><ManagedElement><id>g1</id>
<GNBDUFunction><id>1</id>
<NRCellDU><id>cellA</id><attributes><nRPCI>5</nRPCI><cellLocalId>7</cellLocalId></attributes></NRCellDU>
<NRCellDU><id>cellB</id><attributes><nRPCI>5</nRPCI><cellLocalId>8</cellLocalId></attributes></NRCellDU></GNBDUFunction>
<GNBCUCPFunction><id>1</id><NRCellCU><id>99</id><attributes><cellLocalId>7</cellLocalId></attributes>
<NRCellRelation><id>r</id><attributes><adjacentNRCellRef>g1/1/NRCellDU=cellB</adjacentNRCellRef></attributes></NRCellRelation>
</NRCellCU></GNBCUCPFunction></ManagedElement></data>""")
    # the CU relation (cellLocalId 7) must land on cellA (cellLocalId 7) → collision with cellB (PCI 5)
    assert any("collision" in e.message for e in _errs(rule_pci_collision_confusion(cu_nested, {"_severity": "error"})))


def test_cu_relation_join_is_gnb_scoped():
    # R5: cellLocalId is only gNB-unique (TS 28.541). Two gNBs reusing cellLocalId=5 must NOT let a CU
    # relation misroute to the wrong gNB's cell — the collision must gate regardless of parse order.
    def build(order):
        du_a = ("""<GNBDUFunction><id>1</id><attributes><gNBId>10</gNBId></attributes>
<NRCellDU><id>a5</id><attributes><nRPCI>100</nRPCI><cellLocalId>5</cellLocalId></attributes></NRCellDU>
<NRCellDU><id>a7</id><attributes><nRPCI>100</nRPCI><cellLocalId>7</cellLocalId></attributes></NRCellDU></GNBDUFunction>
<GNBCUCPFunction><id>1</id><attributes><gNBId>10</gNBId></attributes>
<NRCellCU><id>c</id><attributes><cellLocalId>5</cellLocalId></attributes>
<NRCellRelation><id>r</id><attributes><adjacentNRCellRef>g/1/NRCellDU=a7</adjacentNRCellRef></attributes></NRCellRelation>
</NRCellCU></GNBCUCPFunction>""")
        du_b = ("""<GNBDUFunction><id>2</id><attributes><gNBId>20</gNBId></attributes>
<NRCellDU><id>b5</id><attributes><nRPCI>200</nRPCI><cellLocalId>5</cellLocalId></attributes></NRCellDU></GNBDUFunction>""")
        inner = du_a + du_b if order == "AB" else du_b + du_a
        return f"<data><ManagedElement><id>g</id>{inner}</ManagedElement></data>"
    for order in ("AB", "BA"):
        m = normalize_nrm_xml(build(order))
        assert any("collision" in e.message
                   for e in _errs(rule_pci_collision_confusion(m, {"_severity": "error"}))), order


def test_pmxml_negative_subcounter_not_laundered():
    # R3: a negative sub-counter (−5) offset by a larger positive (105) must NOT be summed to a clean
    # 100% — the ratio is corrupt → dropped → unmeasurable
    corrupt = ('<measCollecFile><measData><measInfo><granPeriod duration="PT900S" endTime="t"/>'
               '<measType p="1">RRC.ConnEstabAtt</measType>'
               '<measType p="2">RRC.ConnEstabSucc.a</measType><measType p="3">RRC.ConnEstabSucc.b</measType>'
               '<measValue measObjLdn="NRCellDU=3"><r p="1">100</r><r p="2">-5</r><r p="3">105</r>'
               '</measValue></measInfo></measData></measCollecFile>')
    frame = parse_frame(corrupt, fmt="pmxml")
    assert [s for s in frame.samples if s.kpi == "RRC.ConnEstabSuccRate"] == []


def test_eirp_band_not_derivable_is_info_not_silent():
    # R1 F2: a band-scoped license against a cell with no band → INFO, never a silent skip
    cell = Cell(name="c1", max_tx_power_dbm=100.0, loc="x")  # no band attr
    issues = rule_eirp_cap(_tcm(cells=[cell]),
                           {"licenses": [{"band": "n78", "max_eirp_dbm": 40}], "_severity": "error"})
    assert issues and issues[0].severity == Severity.INFO and "no band" in issues[0].message


def test_grade_cfg_on_nrm_xml_end_to_end(tmp_path):
    (tmp_path / "nrm.xml").write_text(_NRM)
    rep = grade_cfg(str(tmp_path), values="nrm.xml",
                    rules={"version": 1, "defaults": {"enabled": False}, "rules": [{"id": "tac-plmn-consistency"}]})
    assert rep.verdict == Verdict.FAIL
    assert any(i.kind == IssueKind.CROSS_NF_MISMATCH for i in rep.issues)
    assert rep.run_receipt is not None
