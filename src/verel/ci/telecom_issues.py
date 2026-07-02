"""Shared Issue helpers for the telecom graders (config invariants + RAN rules).

Kept in its own module so `telecom_cfg` (Core rules) and `telecom_ran` (RAN rules) both use one
`_mk`/`_info` without a circular import. Every telecom Issue carries `detail_json["rule_id"]` (the
`iam_risk_issues` convention) and a source-path `locator`.
"""

from __future__ import annotations

import json

from ..verdict.models import Confidence, GraderKind, Issue, IssueKind, Severity

_SEV = {"error": Severity.ERROR, "warning": Severity.WARNING, "info": Severity.INFO}


def _mk(rule_id: str, check: str, sev: Severity, kind: IssueKind, msg: str,
        loc: str = "", **detail: object) -> Issue:
    body = {"rule_id": rule_id, "check": check, **detail}
    conf = Confidence.HIGH if sev in (Severity.ERROR, Severity.CRITICAL) else Confidence.MEDIUM
    return Issue(kind=kind, severity=sev, source=GraderKind.TELECOM_CFG, confidence=conf,
                 message=msg, locator=loc or None, locator_precise=bool(loc),
                 detail_json=json.dumps(body))


def _info(rule_id: str, check: str, msg: str, loc: str = "") -> Issue:
    return _mk(rule_id, check, Severity.INFO, IssueKind.OTHER, f"insufficient evidence: {msg}", loc)
