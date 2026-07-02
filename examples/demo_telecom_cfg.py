"""Telecom config-invariant grader — a slice mismatch → grounded FAIL → one-line fix → PASS. Offline.

Verel normalizes an Open5GS-shaped Helm-values document into a canonical 5G-Core model and runs
DETERMINISTIC declared invariants (no LLM). Here the SMF serves S-NSSAI 1-000002 (DNN ims) but the NSSF
does not list it — UEs on that slice would fail NSSF slice selection. The grader FAILs with a locator
into the exact values path; adding the missing NSI entry makes it PASS.

    python examples/demo_telecom_cfg.py        # needs verel[telecom] (PyYAML); no network

Honest scope: this grades DECLARED config, not the running network.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from verel.ci.telecom_cfg import grade_cfg
from verel.verdict.gate import verify_signature

BROKEN = """
amf:
  replicaCount: 2
  configmap:
    amf:
      plmn_support:
        - plmn_id: {mcc: 999, mnc: 70}
          s_nssai:
            - {sst: 1, sd: "000001"}
            - {sst: 1, sd: "000002"}
smf:
  replicaCount: 2
  configmap:
    smf:
      info:
        - s_nssai:
            - {sst: 1, sd: "000001", dnn: [internet]}
            - {sst: 1, sd: "000002", dnn: [ims]}
      session:
        - {subnet: 10.45.0.0/16, dnn: internet}
        - {subnet: 10.46.0.0/16, dnn: ims}
      pfcp:
        client:
          upf:
            - {address: upf.open5gs.svc}
nssf:
  configmap:
    nssf:
      sbi:
        client:
          nsi:
            - uri: https://nrf.open5gs.svc:7777
              s_nssai: {sst: 1, sd: "000001"}
"""

FIX = """            - uri: https://nrf.open5gs.svc:7777
              s_nssai: {sst: 1, sd: "000002"}
"""


def _run(repo: str, name: str, values: str) -> None:
    Path(repo, "values.yaml").write_text(values)
    rep = grade_cfg(repo, values="values.yaml")  # all built-in invariants, defaults
    print(f"\n=== {name}: verdict={rep.verdict.value} ===")
    for i in rep.issues:
        if i.severity.value in ("error", "warning"):
            print(f"  {i.severity.value:7} {i.source.value}:{i.kind.value}  {i.locator}")
            print(f"          {i.message}")
    assert rep.run_receipt is not None
    print(f"  receipt: alg={rep.run_receipt.alg}  signature-valid={verify_signature(rep.run_receipt)}")


def main() -> None:
    print("Telecom config-invariant grader — Open5GS-shaped Helm values (offline, no network)")
    with tempfile.TemporaryDirectory() as repo:
        _run(repo, "BROKEN (slice 1-000002 in SMF, missing from NSSF)", BROKEN)
        _run(repo, "FIXED (added the missing NSI entry to NSSF)", BROKEN.rstrip() + "\n" + FIX)
    print("\nNote: grades DECLARED config, not the running network.")


if __name__ == "__main__":
    main()
