"""Telecom RAN↔Core cross-check — ONE rule body grades a cloud-native (Helm) AND a classic (NETCONF/NRM)
artifact. Offline, no network. This is the "one machinery" proof for the telecom track.

Scenario: a gNB broadcasts TAC 7002, but the AMF only serves TAC 7001 → UEs get Registration Reject
'tracking area not allowed' (5GMM cause #12). The SAME `tac-plmn-consistency` rule FAILs both forms with
the identical (PLMN, TAC) finding; only the source `locator` differs (Helm values path vs NRM XML path).

    python examples/demo_telecom_ran.py        # needs verel[telecom] (PyYAML + defusedxml); no network
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from verel.ci.telecom_cfg import grade_cfg
from verel.verdict.gate import verify_signature

_RULES = {"version": 1, "defaults": {"enabled": False}, "rules": [{"id": "tac-plmn-consistency"}]}

HELM_BROKEN = """
ueransim: {gnb: {plmn_id: {mcc: "001", mnc: "01"}, tac: 7002, pci: 17}}
amf: {configmap: {amf: {tai: [{plmn_id: {mcc: "001", mnc: "01"}, tac: 7001}]}}}
"""
HELM_FIXED = HELM_BROKEN.replace("tac: 7002", "tac: 7001")

NRM_BROKEN = """<data><ManagedElement><id>gnb-001</id>
<GNBDUFunction><id>1</id><NRCellDU><id>3</id><attributes>
<nRPCI>17</nRPCI><nRTAC>7002</nRTAC>
<pLMNInfoList><pLMNInfo><plmnId><mcc>001</mcc><mnc>01</mnc></plmnId></pLMNInfo></pLMNInfoList>
<cellLocalId>3</cellLocalId></attributes></NRCellDU></GNBDUFunction>
<AMFFunction><id>1</id><attributes><taiList><tai>
<plmnId><mcc>001</mcc><mnc>01</mnc></plmnId><tac>7001</tac></tai></taiList></attributes></AMFFunction>
</ManagedElement></data>"""
NRM_FIXED = NRM_BROKEN.replace("<nRTAC>7002</nRTAC>", "<nRTAC>7001</nRTAC>")


def _run(repo: str, label: str, artifact: str, fname: str) -> None:
    Path(repo, fname).write_text(artifact)
    rep = grade_cfg(repo, values=fname, rules=_RULES)
    print(f"\n=== {label}: verdict={rep.verdict.value} ===")
    for i in rep.issues:
        if i.severity.value == "error":
            d = i.detail
            print(f"  rule={d['rule_id']}  (PLMN {d.get('plmn')}, TAC {d.get('tac')})")
            print(f"  locator: {i.locator}")
    assert rep.run_receipt is not None
    print(f"  receipt: alg={rep.run_receipt.alg}  valid={verify_signature(rep.run_receipt)}")


def main() -> None:
    print("Telecom RAN↔Core cross-check — ONE rule grades Helm (cloud-native) AND NETCONF/NRM (classic)")
    with tempfile.TemporaryDirectory() as repo:
        _run(repo, "HELM  BROKEN (gNB TAC 7002 ∉ AMF served {7001})", HELM_BROKEN, "values.yaml")
        _run(repo, "NRM   BROKEN (same misconfig, NETCONF form)", NRM_BROKEN, "nrm.xml")
        print("\n  ↑ same rule_id + same (PLMN, TAC), different locators = one machinery, two worlds\n")
        _run(repo, "HELM  FIXED", HELM_FIXED, "values.yaml")
        _run(repo, "NRM   FIXED", NRM_FIXED, "nrm.xml")
    print("\nNote: grades DECLARED config, not the running network.")


if __name__ == "__main__":
    main()
