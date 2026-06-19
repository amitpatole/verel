"""Failure ledger + regression guard (§7.5) — "the fleet stops repeating mistakes".

Every gating failure the verdict bus sees is written to long-term memory keyed by its
scrubbed fingerprint. When the loop reaches PASS, those fingerprints are marked `fixed`. If
a *previously fixed* fingerprint ever reappears, the regression guard recalls it from memory
and emits a gating Report — so a reintroduced bug FAILS the gate on the strength of memory
alone, not because someone remembered to re-add a test.
"""

from __future__ import annotations

from ..verdict.constants import GATING_SEVERITY, SEV_ORDER
from ..verdict.models import (
    Confidence,
    GraderKind,
    Issue,
    IssueKind,
    Report,
    Severity,
    Verdict,
)
from .view import MemoryKind, MemoryRecord, MemoryView, make_key


def _gating_issues(report: Report) -> list[Issue]:
    g = SEV_ORDER.index(GATING_SEVERITY)
    return [i for i in report.issues if SEV_ORDER.index(i.severity) >= g]


class FailureLedger:
    def __init__(self, mem: MemoryView, *, scope: str = "repo:default"):
        self.mem = mem
        self.scope = scope

    def _key(self, fingerprint: str) -> str:
        return make_key(fingerprint, "fails", self.scope)

    def record(self, report: Report, *, ts: float = 0.0,
               volatile_fingerprints: set[str] | None = None) -> list[str]:
        """Persist every gating failure; reappearance of a fixed one flips it back to open.

        `volatile_fingerprints` (e.g. ci-medic's transient/flaky classifications) are written
        `volatile` so they self-clean from failure-memory unless they RECUR — a recurrence
        re-asserts the same record, which confirms it (clears volatile) and keeps it. This is
        the anti-"junk drawer" behaviour the design's interference rule aims at."""
        volatile_fingerprints = volatile_fingerprints or set()
        recorded = []
        for i in _gating_issues(report):
            existing = self.mem.get(self.mem_id(i.fingerprint))
            times = (existing.detail.get("times_seen", 0) + 1) if existing else 1
            status = "open"
            if existing and existing.detail.get("status") == "fixed":
                status = "reintroduced"  # was fixed, now back — a regression event
            rec = MemoryRecord(
                kind=MemoryKind.FAILURE,
                subject=i.fingerprint,
                predicate="fails",
                text=i.message,
                scope=self.scope,
                subj_pred_key=self._key(i.fingerprint),
                source=i.source.value if hasattr(i.source, "value") else str(i.source),
                provenance=[f"percept:{i.fingerprint}"],
            ).with_detail(
                fingerprint=i.fingerprint, kind=i.kind.value, locator=i.locator,
                status=status, times_seen=times,
            )
            if i.fingerprint in volatile_fingerprints:
                rec.with_detail(volatile=True)  # transient/flaky → expires unless it recurs
            self.mem.write(rec, ts=ts)
            recorded.append(i.fingerprint)
        return recorded

    def mem_id(self, fingerprint: str):
        from .view import make_id

        return make_id(self._key(fingerprint))

    def mark_fixed(self, fingerprints: list[str], *, ts: float = 0.0) -> int:
        n = 0
        for fp in fingerprints:
            rec = self.mem.get(self.mem_id(fp))
            if rec is None:
                continue
            rec.with_detail(status="fixed", fixed_ts=ts)
            self.mem.write(rec, ts=ts)  # same key -> corroborates; status now fixed
            # a confirmed fix is verified, PERMANENT knowledge — promote and PIN it so the
            # regression guard can catch a reintroduction however long later (no decay/prune).
            self.mem.promote(rec.id)
            if hasattr(self.mem, "pin"):
                self.mem.pin(rec.id)
            n += 1
        return n

    def check_regressions(self, report: Report) -> list[MemoryRecord]:
        """Which gating fingerprints in `report` were previously marked `fixed`?"""
        out = []
        for i in _gating_issues(report):
            rec = self.mem.get(self.mem_id(i.fingerprint))
            if rec is not None and rec.detail.get("status") in {"fixed"}:
                out.append(rec)
        return out


def regression_report(records: list[MemoryRecord]) -> Report:
    """Turn recalled regressions into a CONTRACT-grader Report so memory gates the build."""
    issues = [
        Issue(
            kind=IssueKind(r.detail.get("kind", "other")),
            severity=Severity.ERROR,
            message=f"Reintroduced a previously-fixed failure: {r.text}",
            locator=r.detail.get("locator"),
            confidence=Confidence.HIGH,
            source=GraderKind.CONTRACT,
            fingerprint=r.detail.get("fingerprint", ""),
            detail_json=r.detail_json,
        )
        for r in records
    ]
    return Report(
        verdict=Verdict.FAIL if issues else Verdict.PASS,
        summary=f"regression-guard: {len(issues)} previously-fixed failure(s) reintroduced",
        issues=issues,
        grader=GraderKind.CONTRACT,
    )
