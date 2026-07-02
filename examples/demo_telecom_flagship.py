"""Telecom flagship — ONE change, TWO grounded verdicts. Offline, no network.

An operator changes a gNB's TAC to one the AMF doesn't serve. Verel catches it two ways on one gate:
  1. the CONFIG grader (telecom-cfg) FAILs the declared change — the gNB broadcasts a TAI no AMF serves;
  2. the KPI grader (telecom --kpi) FAILs the synthetic "post-change" window — AMF registration success
     collapses (UEs get Registration Reject 'tracking area not allowed').

Two graders, two signed receipts, both grounded in 3GPP — the config cause AND the KPI effect.

    python examples/demo_telecom_flagship.py     # needs verel[telecom]; no network

Honest scope: the config grader grades DECLARED config; the KPI grader is a threshold gate over SUPPLIED
PM data (it does not observe the network or prove causation — the "post" window here is synthetic).
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from verel.ci.telecom_cfg import grade_cfg
from verel.ci.telecom_kpi import grade_kpi
from verel.verdict.gate import verify_signature

# The broken change: gNB broadcasts TAC 7002, but the AMF serves only 7001.
VALUES = """
ueransim: {gnb: {plmn_id: {mcc: "001", mnc: "01"}, tac: 7002}}
amf: {configmap: {amf: {tai: [{plmn_id: {mcc: "001", mnc: "01"}, tac: 7001}]}}}
"""
# The synthetic "post-change" PM window — registration success rate collapses.
POST = {"samples": [{"kpi": "RM.RegInitSuccRate", "value": 0.41, "samples": 9000, "dims": {"nf": "amf-1"}}]}
THRESHOLDS = {"RM.RegInitSuccRate": {"min": 0.99, "min_samples": 200}}
_CFG_RULES = {"version": 1, "defaults": {"enabled": False}, "rules": [{"id": "tac-plmn-consistency"}]}


def main() -> None:
    print("Telecom flagship — one gNB TAC change, caught by config AND KPI (offline, no network)\n")
    with tempfile.TemporaryDirectory() as repo:
        Path(repo, "values.yaml").write_text(VALUES)
        Path(repo, "post.json").write_text(json.dumps(POST))

        cfg = grade_cfg(repo, values="values.yaml", rules=_CFG_RULES)
        print(f"1) CONFIG grader (telecom-cfg): verdict={cfg.verdict.value}")
        for i in cfg.issues:
            if i.severity.value == "error":
                d = i.detail
                print(f"   {i.source.value}:{i.kind.value}  (PLMN {d.get('plmn')}, TAC {d.get('tac')})")
                print(f"     {i.message}")
                print(f"     locator: {i.locator}")

        kpi = grade_kpi(repo, metrics="post.json", thresholds=THRESHOLDS)
        print(f"\n2) KPI grader (telecom --kpi): verdict={kpi.verdict.value}")
        for i in kpi.issues:
            if i.severity.value == "error":
                print(f"   {i.source.value}:{i.kind.value}  {i.locator}")
                print(f"     {i.message}")

        assert cfg.run_receipt and kpi.run_receipt
        print("\n  two signed receipts, both verify:",
              verify_signature(cfg.run_receipt) and verify_signature(kpi.run_receipt))
        print("  the config CAUSE and the KPI EFFECT of one change — one gate, two grounded reports.")


if __name__ == "__main__":
    main()
