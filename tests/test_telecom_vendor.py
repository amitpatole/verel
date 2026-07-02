"""Phase 5 item 2 — vendor CM-export adapters: 3GPP bulk-CM (VsDataContainer) config + vendor PM mapping.

Proves "one machinery" extends to a THIRD input form (Helm ≡ NETCONF-NRM ≡ bulk-CM) and that a vendor
PM-counter dialect maps into the canonical vocabulary.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("yaml", reason="telecom grader tests need verel[telecom]")
pytest.importorskip("defusedxml", reason="telecom XML tests need verel[telecom]")

from verel.ci.telecom_kpi import grade_kpi, load_pm_mapping, parse_frame
from verel.ci.telecom_nrm import normalize_nrm_xml
from verel.ci.telecom_ran import rule_tac_plmn_consistency
from verel.verdict.models import Severity

_BULK = """<bulkCmConfigDataFile xmlns:xn="http://3gpp/xn">
 <xn:VsDataContainer id="ME1">
  <xn:attributes><xn:vsDataType>vsDataManagedElement</xn:vsDataType><xn:vsData></xn:vsData></xn:attributes>
  <xn:VsDataContainer id="GNB1">
   <xn:attributes><xn:vsDataType>vsDataGNBDUFunction</xn:vsDataType><xn:vsData><gNBId>7</gNBId></xn:vsData></xn:attributes>
   <xn:VsDataContainer id="CELL1">
    <xn:attributes><xn:vsDataType>vsDataNRCellDU</xn:vsDataType>
     <xn:vsData><nRPCI>1</nRPCI><nRTAC>{tac}</nRTAC><cellLocalId>1</cellLocalId>
       <pLMNInfoList><pLMNInfo><plmnId><mcc>001</mcc><mnc>01</mnc></plmnId></pLMNInfo></pLMNInfoList>
     </xn:vsData></xn:attributes>
   </xn:VsDataContainer>
  </xn:VsDataContainer>
  <xn:VsDataContainer id="AMF1">
   <xn:attributes><xn:vsDataType>vsDataAMFFunction</xn:vsDataType>
    <xn:vsData><taiList><tai><plmnId><mcc>001</mcc><mnc>01</mnc></plmnId><tac>7001</tac></tai></taiList></xn:vsData>
   </xn:attributes>
  </xn:VsDataContainer>
 </xn:VsDataContainer>
</bulkCmConfigDataFile>"""


def _errs(issues):
    return [i for i in issues if i.severity == Severity.ERROR]


def test_bulk_cm_vsdata_populates_model():
    m = normalize_nrm_xml(_BULK.format(tac=7002))
    assert len(m.cells) == 1 and [nf.kind for nf in m.nfs] == ["AMF"]
    c = m.cells[0]
    assert c.pci == 1 and c.tac == 7002 and c.plmns == ["001-01"] and c.attrs.get("gnb_id") == "7"
    amf = next(nf for nf in m.nfs if nf.kind == "AMF")
    assert amf.attrs.get("served_tais") == [
        {"plmn": "001-01", "tac": 7001, "loc": "ManagedElement=ME1/AMFFunction=AMF1/attributes/taiList"}]


def test_bulk_cm_flagship_rule_fires_same_machinery():
    # cell broadcasts TAC 7002 that no AMF serves → the SAME tac-plmn rule fires on bulk-CM
    bad = normalize_nrm_xml(_BULK.format(tac=7002))
    assert any("tac-plmn" in e.detail.get("rule", "") or "broadcasts" in e.message
               for e in _errs(rule_tac_plmn_consistency(bad, {"_severity": "error"})))
    # consistent TAC 7001 → PASS
    good = normalize_nrm_xml(_BULK.format(tac=7001))
    assert _errs(rule_tac_plmn_consistency(good, {"_severity": "error"})) == []


def test_bulk_cm_unknown_vsdatatype_recurses_no_crash():
    x = """<f xmlns:xn="x"><xn:VsDataContainer id="U">
      <xn:attributes><xn:vsDataType>vsDataSomethingUnknown</xn:vsDataType><xn:vsData><foo>1</foo></xn:vsData></xn:attributes>
      <xn:VsDataContainer id="C"><xn:attributes><xn:vsDataType>vsDataNRCellDU</xn:vsDataType>
        <xn:vsData><nRPCI>3</nRPCI><cellLocalId>3</cellLocalId></xn:vsData></xn:attributes></xn:VsDataContainer>
    </xn:VsDataContainer></f>"""
    m = normalize_nrm_xml(x)  # unknown container recursed into; the nested known cell still found
    assert any(c.pci == 3 for c in m.cells)


def test_builtin_open5gs_mapping_loads():
    mp = load_pm_mapping("open5gs")
    assert mp["fivegs_amffunction_rm_reginitsucc"] == "RM.RegInitSucc"


def test_vendor_mapping_remaps_counters():
    # a vendor scrape uses vendor counter names; the mapping remaps them into the canonical vocabulary.
    scrape = "vendor_reg_att 1000\nvendor_reg_ok 410\n"
    mapping = {"vendor_reg_att": "RM.RegInitReq", "vendor_reg_ok": "RM.RegInitSucc"}
    with_map = {s.kpi for s in parse_frame(scrape, "openmetrics", mapping).samples}
    without = {s.kpi for s in parse_frame(scrape, "openmetrics").samples}
    assert {"RM.RegInitReq", "RM.RegInitSucc"} <= with_map   # vendor names → canonical
    assert "RM.RegInitReq" not in without                     # unmapped → dropped, never mis-mapped
    # end-to-end via a repo-relative mapping FILE: the canonical rate is now computed and breaches
    with tempfile.TemporaryDirectory() as repo:
        Path(repo, "scrape.txt").write_text(scrape)
        Path(repo, "map.yaml").write_text(json.dumps({"version": 1, "map": mapping}))  # YAML ⊇ JSON
        rep = grade_kpi(repo, metrics="scrape.txt", fmt="openmetrics", mapping="map.yaml",
                        thresholds={"RM.RegInitSuccRate": {"min": 0.99, "min_samples": 1}})
        assert any(i.kind.value == "threshold_breach" and "RegInitSucc" in i.message for i in rep.issues)


def test_mapping_loader_rejects_bad_shapes():
    with tempfile.TemporaryDirectory() as repo:
        Path(repo, "nomap.yaml").write_text("version: 1\n")  # no map:
        with pytest.raises(ValueError, match="no 'map:'"):
            load_pm_mapping("nomap.yaml", repo)
    with pytest.raises(ValueError, match="unknown built-in"):
        load_pm_mapping("nonexistent-vendor")  # no repo → can't be a path either


def test_vendor_mapping_partial_leaves_unmapped_verbatim():
    # an unmapped vendor counter is NOT force-mapped; a threshold on an absent canonical name → not PASS
    mp = load_pm_mapping("open5gs")
    frame = parse_frame("some_unmapped_counter 5\n", "openmetrics", mp)
    assert "some_unmapped_counter" not in {s.kpi for s in frame.samples}  # dropped, not mis-mapped
