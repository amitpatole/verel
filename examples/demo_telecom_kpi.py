"""Telecom KPI vitals grader — broken → grounded FAIL → fixed → PASS, fully offline, no network.

Verel grades a 5G PM-counter snapshot against DECLARED thresholds and returns a signed verdict. This
demo uses a synthetic Open5GS-style metrics file (labelled synthetic — never implies vendor validation)
where the AMF initial-registration success rate has collapsed, then a corrected snapshot.

    python examples/demo_telecom_kpi.py        # needs verel[telecom] (PyYAML) for the built-in profile

What it shows: the FAIL names the exact 3GPP counter (RM.RegInitSucc/RM.RegInitReq) and cites the
clause; the receipt is signed and bound to the input bytes; a small-denominator sample is clamped to a
non-gating WARNING (statistical insufficiency cannot fail a build).
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from verel.ci.telecom_kpi import grade_kpi
from verel.verdict.gate import verify_signature

# Operator-declared thresholds (never inferred). Registration SR must be ≥ 99% over ≥ 200 attempts.
THRESHOLDS = {
    "RM.RegInitSuccRate": {"min": 0.99, "min_samples": 200, "direction": "higher_is_better"},
    "RRU.PrbTotDl": {"max": 85.0, "min_samples": 200, "direction": "lower_is_better"},
}

BROKEN = {"samples": [  # SYNTHETIC data (open-source-core shaped) — not vendor-validated
    {"kpi": "RM.RegInitSuccRate", "value": 0.912, "samples": 8421, "window": "15m", "dims": {"nf": "amf-1"}},
    {"kpi": "RRU.PrbTotDl", "value": 61.0, "samples": 8421, "dims": {"cell": "cell-1"}},
]}
FIXED = {"samples": [
    {"kpi": "RM.RegInitSuccRate", "value": 0.994, "samples": 8730, "window": "15m", "dims": {"nf": "amf-1"}},
    {"kpi": "RRU.PrbTotDl", "value": 62.0, "samples": 8730, "dims": {"cell": "cell-1"}},
]}


def _run(repo: str, name: str, snapshot: dict) -> None:
    Path(repo, "metrics.json").write_text(json.dumps(snapshot, indent=2))
    rep = grade_kpi(repo, metrics="metrics.json", thresholds=THRESHOLDS)
    print(f"\n=== {name}: verdict={rep.verdict.value} ===")
    for i in rep.issues:
        print(f"  {i.severity.value:7} {i.source.value}:{i.kind.value}  {i.locator}")
        print(f"          {i.message}")
    assert rep.run_receipt is not None
    print(f"  receipt: alg={rep.run_receipt.alg}  signature-valid={verify_signature(rep.run_receipt)}"
          f"  inputs_digest={rep.run_receipt.inputs_digest}")


def main() -> None:
    print("Telecom KPI vitals grader — synthetic Open5GS-style PM snapshot (offline, no network)")
    with tempfile.TemporaryDirectory() as repo:
        _run(repo, "BROKEN snapshot (registration SR 91.2% < 99%)", BROKEN)
        _run(repo, "FIXED snapshot (registration SR 99.4%)", FIXED)
    print("\nNote: this is a threshold gate over supplied PM data — not a service-assurance system.")
    print("It does not observe the network and cannot attribute a regression to a cause.")


if __name__ == "__main__":
    main()
