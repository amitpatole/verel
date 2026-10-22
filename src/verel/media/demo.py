"""`verel media demo` — no key, no media files: a delivery with a loud mix and a late audio track fails
with grounded findings, the corrected facts pass, and a tampered content-credentials report is caught.
Everything printed is the real output of the real graders over the synthetic facts below."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from .grade import grade_media
from .provenance import grade_provenance

SPEC = {"version": 1, "profiles": ["ebu_r128", "ebu_r37_av_sync"],
        "rules": [{"id": "tracks_match", "path": "audio.duration_s", "op": "approx",
                   "ref": "video.duration_s", "tol": 0.1, "severity": "error"},
                  {"id": "captions", "path": "captions.languages", "op": "superset",
                   "value": ["en", "es"], "severity": "error"}]}
BROKEN = {"audio": {"integrated_lufs": -17.4, "true_peak_dbtp": 0.8, "duration_s": 1800.0},
          "video": {"duration_s": 1802.5}, "av": {"offset_ms": 95.0}, "captions": {"languages": ["en"]}}
FIXED = {"audio": {"integrated_lufs": -23.1, "true_peak_dbtp": -1.6, "duration_s": 1800.0},
         "video": {"duration_s": 1800.0}, "av": {"offset_ms": 12.0}, "captions": {"languages": ["en", "es"]}}
MANIFEST = {"active_manifest": "urn:uuid:1", "validation_status": [],
            "manifests": {"urn:uuid:1": {"claim_generator": "Newsroom CMS/3.2",
                                         "signature_info": {"issuer": "Example News Org"}, "assertions": []}}}


def _show(title: str, rep) -> None:
    print(f"{title}: {rep.verdict.value.upper()}")
    for i in rep.issues:
        print(f"    {i.severity.value:<8} {i.message[:118]}")


def run_demo() -> int:
    with tempfile.TemporaryDirectory() as d:
        repo = Path(d)
        (repo / "spec.json").write_text(json.dumps(SPEC))
        (repo / "broken.json").write_text(json.dumps(BROKEN))
        (repo / "fixed.json").write_text(json.dumps(FIXED))
        _show("1. delivery as submitted", grade_media(d, facts=["broken.json"], spec="spec.json"))
        _show("2. after remix, re-sync, Spanish captions",
              grade_media(d, facts=["fixed.json"], spec="spec.json"))
        (repo / "ok.json").write_text(json.dumps(MANIFEST))
        bad = json.loads(json.dumps(MANIFEST))
        bad["validation_status"] = [{"code": "assertion.dataHash.mismatch"}]
        (repo / "tampered.json").write_text(json.dumps(bad))
        (repo / "policy.json").write_text(json.dumps({"version": 1, "trusted_issuers": ["Example News Org"]}))
        _show("3. credentials, untouched", grade_provenance(d, manifest_json="ok.json", policy="policy.json"))
        _show("4. credentials, bytes changed after signing",
              grade_provenance(d, manifest_json="tampered.json", policy="policy.json"))
    return 0
