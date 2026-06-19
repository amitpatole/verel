"""ci-medic — classify failing graders into safe, gated remediations (§7.4).

The medic only *proposes*; every action it suggests is re-gated by the verdict bus before it
counts (and destructive ones go through the rollback policy engine, rollback.py). Classes:

- INFRA/TRANSIENT  → RETRY            (network/timeout/connection — re-run, don't "fix")
- DEP_DRIFT        → REGEN_LOCKFILE   (ModuleNotFound / version solver errors)
- FLAKY            → QUARANTINE_FLAKY  (a signature seen flipping pass/fail — ERROR→WARNING,
                                        never silently deleted; file a ticket; record in memory)
- GENUINE          → FIX_BRANCH        (a real regression → spin an ultracode fix loop)

Classification is DETERMINISTIC (keyword/signature heuristics), so the medic itself can't be
gamed by an LLM and is fully testable. An LLM may later *enrich* a FIX_BRANCH diagnosis, but
never decides RETRY vs FIX on its own word.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from ..verdict.models import Issue, Report, Severity


class Action(str, Enum):
    RETRY = "retry"
    REGEN_LOCKFILE = "regen_lockfile"
    QUARANTINE_FLAKY = "quarantine_flaky"
    FIX_BRANCH = "fix_branch"


_INFRA = re.compile(
    r"connection (reset|refused)|timed? ?out|temporarily unavailable|network|"
    r"503|502|429|ETIMEDOUT|ECONNRESET|read timed out|rate limit",
    re.I,
)
_DEP = re.compile(
    r"ModuleNotFoundError|No module named|could not find a version|"
    r"ResolutionImpossible|incompatible|lockfile|unresolved import",
    re.I,
)


@dataclass
class Diagnosis:
    issue: Issue
    action: Action
    rationale: str
    hint: str = ""  # optional LLM root-cause enrichment (FIX_BRANCH only); never changes `action`


def classify_issue(issue: Issue, *, flaky_signatures: set[str] | None = None) -> Diagnosis:
    flaky_signatures = flaky_signatures or set()
    msg = issue.message or ""
    if issue.fingerprint in flaky_signatures:
        return Diagnosis(issue, Action.QUARANTINE_FLAKY,
                         "fingerprint seen flipping pass/fail across runs")
    if _DEP.search(msg):
        return Diagnosis(issue, Action.REGEN_LOCKFILE, "dependency drift / missing module")
    if _INFRA.search(msg):
        return Diagnosis(issue, Action.RETRY, "infrastructure/transient signal")
    return Diagnosis(issue, Action.FIX_BRANCH, "genuine regression — needs a code fix")


def triage(report: Report, *, flaky_signatures: set[str] | None = None) -> list[Diagnosis]:
    return [classify_issue(i, flaky_signatures=flaky_signatures) for i in report.issues]


_ENRICH_SYSTEM = (
    "You are a CI triage assistant. Given a single failing test/lint/type message, give a "
    "ONE-LINE root-cause hypothesis and the likely file/area to fix. You do NOT decide "
    "whether to retry or fix — that is already decided. Respond with one short line, no JSON."
)


def enrich_diagnoses(diagnoses: list[Diagnosis], *, chat=None) -> list[Diagnosis]:
    """LLM-enrich ONLY the FIX_BRANCH diagnoses with a root-cause hint. The deterministic
    classification (`action`) is authoritative and never changed by the model (§7.4)."""
    if chat is None:
        from ..agents import llm

        chat = lambda msgs: llm.chat(msgs).content  # noqa: E731
    for d in diagnoses:
        if d.action != Action.FIX_BRANCH:
            continue
        loc = f" @ {d.issue.locator}" if d.issue.locator else ""
        try:
            d.hint = chat([{"role": "system", "content": _ENRICH_SYSTEM},
                           {"role": "user", "content": f"[{d.issue.source.value}]{loc}: {d.issue.message}"}]
                          ).strip().splitlines()[0][:200]
        except Exception:  # noqa: BLE001 — enrichment is best-effort, never fatal
            d.hint = ""
    return diagnoses


def quarantine_severity(issue: Issue) -> Severity:
    """Flaky quarantine downgrades ERROR→WARNING — visible, ticketed, never silently dropped."""
    return Severity.WARNING if issue.severity == Severity.ERROR else issue.severity
