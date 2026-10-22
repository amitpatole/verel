"""Run the real gate, record what it WOULD have decided, and return what the mode lets through."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel

from ..verdict.gate import gate
from ..verdict.models import Report, Verdict
from .log import ShadowLog, ShadowRecord, valid_artifact_id
from .mode import Mode, apply_mode, parse_mode
from .policy import Policy, enforced_verdict, kill_switch

_FP_OK = re.compile(r"[A-Za-z0-9]{1,64}")
MAX_FINGERPRINTS = 500


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


def _content(reports: list[Report]) -> str:
    """sha256 of the asset the graders looked at, if one of them bound it (media/provenance do)."""
    for r in reports:
        v = r.artifacts.get("asset_sha256", "")
        if len(v) == 64 and all(c in "0123456789abcdef" for c in v):
            return v
    return ""


def run_pilot(
    reports: list[Report],
    *,
    artifact_id: str,
    mode: str | Mode = Mode.SHADOW,
    log: ShadowLog | None = None,
    tenant: str = "",
    policy: Policy | None = None,
    unique: bool = False,
    ref: str = "",
    recorded_by: str = "",
    **gate_kwargs: Any,
) -> PilotDecision:
    """Gate `reports`, log the would-be verdict, return the mode-adjusted one.

    A gate crash is treated as FAIL (fail closed): in ENFORCE it blocks; in SHADOW/ADVISORY it is
    still recorded as `gate_error` so a broken grader is visible in the pilot evidence, not hidden."""
    m = Mode.POLICY if policy is not None else parse_mode(mode)
    valid_artifact_id(artifact_id)
    err = False
    try:
        res = gate(reports, **gate_kwargs)
        would_be, reason = res.verdict, res.reason
    except Exception as e:  # noqa: BLE001 - fail closed on ANY gate failure
        would_be, reason, err = Verdict.FAIL, f"gate error: {type(e).__name__}", True
    if policy is not None:
        enforcing = any(policy.mode_for(r.grader.value) is Mode.ENFORCE for r in reports)
        try:
            enforced = enforced_verdict(reports, policy, **gate_kwargs)
        except Exception as e:  # noqa: BLE001 - fail closed, but only where something actually enforces
            enforced, err = (Verdict.FAIL if enforcing else Verdict.PASS), True
            if would_be is not Verdict.FAIL:
                would_be, reason = Verdict.FAIL, f"gate error: {type(e).__name__}"
        if err and enforcing:
            enforced = Verdict.FAIL
    else:
        enforced = apply_mode(would_be, m)
        if err and m is Mode.ENFORCE:
            enforced = Verdict.FAIL
    if kill_switch():
        if enforced is not Verdict.PASS or would_be is not Verdict.PASS:
            reason = (reason + " [kill switch active]").strip()
        enforced = Verdict.PASS
    dec = PilotDecision(
        artifact_id=artifact_id, mode=m, would_be=would_be, enforced=enforced, reason=reason, gate_error=err
    )
    graders = _per_grader(reports)
    from ..telemetry import emit_decision  # no-op unless the host app configured OpenTelemetry

    emit_decision(dec, tenant=tenant, graders=graders)
    if log is not None:
        (log.append_unique if unique else log.append)(
            ShadowRecord(
                artifact_id=artifact_id,
                ts=datetime.now(timezone.utc).isoformat(),
                mode=m,
                would_be=would_be,
                enforced=enforced,
                reason=reason,
                gate_error=err,
                ref=ref[:128],
                recorded_by=recorded_by[:128],
                content=_content(reports),
                bound=any(r.artifacts.get("facts_bound") == "1" for r in reports),
                graders=graders,
                # fingerprints come from caller-supplied reports: keep only well-formed short tokens, bounded
                fingerprints=sorted(
                    {
                        i.fingerprint
                        for r in reports
                        for i in r.issues
                        if _FP_OK.fullmatch(i.fingerprint or "")
                    }
                )[:MAX_FINGERPRINTS],
            )
        )
    return dec
