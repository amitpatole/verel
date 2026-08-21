"""Anti-worm egress check — catch a known hidden payload reappearing in a generated artifact.

The worm's replication step: a hidden instruction, once ingested, is copied verbatim into a file
the assistant generates, which then infects the next reader. `taint_keys` pulls the canonical span
keys of a source scan's FAILing findings; `check_propagation` scans a generated artifact for any of
them. Matching is on the shared `canon_value` canonical form — the same 200-char canonical key the
memory tombstone ledger uses — so it is exactly as paraphrase-resistant as `rejected_key`, by
construction, and never re-carries a live payload in its own Report.
"""

from __future__ import annotations

import json
from collections.abc import Collection
from pathlib import Path

from ..verdict.fingerprint import assign
from ..verdict.models import (
    Confidence,
    GraderKind,
    Issue,
    IssueKind,
    Report,
    Severity,
    Verdict,
)
from .model import MAX_DOC_BYTES


def taint_keys(report: Report) -> list[str]:
    """The canonical span keys of a scan's gating findings — the payloads to watch for downstream."""
    keys: list[str] = []
    for i in report.issues:
        if i.severity in (Severity.ERROR, Severity.CRITICAL):
            k = i.detail.get("span_key")
            if isinstance(k, str) and k:
                keys.append(k)
    return sorted(set(keys))


def check_propagation(artifact_path: str | Path, *, prior: Report | None = None,
                      tainted_keys: Collection[str] | None = None,
                      runner_identity: str = "guard-runner", nonce: str = "",
                      attest: str = "hmac") -> Report:
    """Scan a generated artifact for any tainted payload from `prior` (or an explicit key set).
    A match is CRITICAL/FAIL — the worm's replication step, caught before the file propagates."""
    from ..ci.graders import GraderSpec, _receipt
    from ..memory.view import canon_value

    keys = set(tainted_keys or ())
    if prior is not None:
        keys |= set(taint_keys(prior))
    keys = {k for k in keys if k}

    p = Path(artifact_path)
    issues: list[Issue] = []
    errored = False
    try:
        raw = p.read_bytes()[: MAX_DOC_BYTES + 1]
        if len(raw) > MAX_DOC_BYTES:
            raise ValueError("artifact exceeds size cap")
        hay = canon_value(raw.decode("utf-8", "replace"))
        for k in sorted(keys):
            if k in hay:
                issues.append(Issue(
                    kind=IssueKind.INJECTION, severity=Severity.CRITICAL,
                    message="a hidden payload from the source document reappeared in this artifact "
                            "(worm replication)",
                    locator=f"{p.name}!propagation", locator_precise=True,
                    confidence=Confidence.HIGH, source=GraderKind.INJECTION,
                    detail_json=json.dumps({"detection_id": "PROP-001", "span_key": k}),
                ))
    except (ValueError, OSError) as e:
        errored = True
        issues.append(Issue(
            kind=IssueKind.INJECTION, severity=Severity.ERROR,
            message=f"artifact could not be scanned for propagation ({e})",
            locator=f"{p.name}!propagation", confidence=Confidence.HIGH,
            source=GraderKind.INJECTION,
            detail_json='{"detection_id": "PROP-ERR", "errored": true}'))

    verdict = Verdict.FAIL if (errored or issues) else Verdict.PASS
    summary = (f"propagation: {'FAIL' if verdict == Verdict.FAIL else 'PASS'} — "
               f"{len(keys)} tainted key(s) checked, {len([i for i in issues if not errored])} match(es)")
    report = Report(verdict=verdict, summary=summary, issues=issues,
                    grader=GraderKind.INJECTION, errored=errored)
    assign(report)
    spec = GraderSpec(grader=GraderKind.INJECTION, command=["verel-guard-propagation"],
                      covers=[str(p)])
    report.run_receipt = _receipt(spec, report, runner_identity=runner_identity,
                                  nonce=nonce, attest=attest)
    return report
