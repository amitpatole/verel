"""Run the real gate, record what it WOULD have decided, and return what the mode lets through."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel

from ..verdict.gate import gate
from ..verdict.models import Report, Verdict
from .log import ShadowLog, ShadowRecord, valid_artifact_id
from .mode import Mode, apply_mode, parse_mode


class PilotDecision(BaseModel):
    artifact_id: str
    mode: Mode
    would_be: Verdict
    enforced: Verdict
    reason: str = ""
    gate_error: bool = False

    @property
    def blocked(self) -> bool:
        return self.enforced is Verdict.FAIL


_RANK = {"pass": 0, "warn": 1, "fail": 2, "errored": 3}


def _per_grader(reports: list[Report]) -> dict[str, str]:
    """grader -> worst outcome across its reports (so two reports from one grader can't mask a FAIL)."""
    out: dict[str, str] = {}
    for r in reports:
        v = "errored" if r.errored else r.verdict.value
        k = r.grader.value
        if k not in out or _RANK[v] > _RANK[out[k]]:
            out[k] = v
    return out


def run_pilot(
    reports: list[Report],
    *,
    artifact_id: str,
    mode: str | Mode = Mode.SHADOW,
    log: ShadowLog | None = None,
    **gate_kwargs: Any,
) -> PilotDecision:
    """Gate `reports`, log the would-be verdict, return the mode-adjusted one.

    A gate crash is treated as FAIL (fail closed): in ENFORCE it blocks; in SHADOW/ADVISORY it is
    still recorded as `gate_error` so a broken grader is visible in the pilot evidence, not hidden."""
    m = parse_mode(mode)
    valid_artifact_id(artifact_id)
    err = False
    try:
        res = gate(reports, **gate_kwargs)
        would_be, reason = res.verdict, res.reason
    except Exception as e:  # noqa: BLE001 - fail closed on ANY gate failure
        would_be, reason, err = Verdict.FAIL, f"gate error: {type(e).__name__}", True
    enforced = apply_mode(would_be, m)
    if err and m is Mode.ENFORCE:
        enforced = Verdict.FAIL
    dec = PilotDecision(artifact_id=artifact_id, mode=m, would_be=would_be, enforced=enforced,
                        reason=reason, gate_error=err)
    if log is not None:
        log.append(ShadowRecord(
            artifact_id=artifact_id, ts=datetime.now(timezone.utc).isoformat(), mode=m,
            would_be=would_be, enforced=enforced, reason=reason, gate_error=err,
            graders=_per_grader(reports),
            fingerprints=sorted({i.fingerprint for r in reports for i in r.issues if i.fingerprint}),
        ))
    return dec
