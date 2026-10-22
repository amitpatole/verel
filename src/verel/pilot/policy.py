"""Gated rollout: per-grader enforcement, promoted on evidence and demoted on regressions.

A tenant's policy is an append-only, keyed, hash-chained history of changes (who, when, why, and the
evidence), so "why was this grader blocking releases on Tuesday?" always has an answer. The CURRENT policy
is the fold of that history.

Rules (fail closed, human-authorized):
- Every grader starts in the policy default (SHADOW). Nothing enforces until someone promotes it.
- Promotion to ENFORCE re-evaluates the tenant's OWN log and labels at promotion time and requires the
  grader to have `ready_to_enforce`. Evidence is computed here, never accepted from the caller. The
  grader must already be ADVISORY (shadow -> advisory -> enforce), unless an admin gives an explicit
  override reason, which is recorded and flagged.
- Demotion is always allowed. `autodemote` demotes an enforcing grader to ADVISORY when its recent
  precision (Wilson lower bound) or reliability regresses. Re-promotion is manual.
- A global KILL SWITCH (`VEREL_PILOT_KILL_SWITCH=1`) forces every decision to PASS (shadow) without
  touching the policy.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .._chainlog import ChainLog, ChainRecord
from ..verdict.gate import gate
from ..verdict.models import GraderKind, Report, Verdict
from .evaluate import Evaluation, GraderStats, Label, Stats, evaluate, wilson_lower
from .log import ShadowRecord
from .mode import Mode, parse_mode

MIN_OVERRIDE_REASON = 10


class PolicyError(ValueError):
    """A policy change was refused (insufficient evidence, bad transition, bad input)."""


def kill_switch() -> bool:
    return os.environ.get("VEREL_PILOT_KILL_SWITCH", "").strip().lower() in ("1", "true", "yes", "on")


class PolicyRecord(ChainRecord):
    ts: str
    by: str
    grader: str  # a GraderKind value, or "*" for the default
    mode: str
    action: str  # set | promote | demote | autodemote
    reason: str = ""
    overridden: bool = False
    evidence: dict[str, Any] = {}


@dataclass
class Policy:
    default: Mode = Mode.SHADOW
    graders: dict[str, Mode] = field(default_factory=dict)

    def mode_for(self, grader: str) -> Mode:
        return self.graders.get(grader, self.default)


def _settable(mode: str) -> Mode:
    """A policy entry is a real enforcement level. `policy` (the per-grader meta-mode) is not one."""
    m = parse_mode(mode)
    if m is Mode.POLICY:
        raise PolicyError("'policy' is not a mode a grader can be set to")
    return m


def _valid_grader(name: str) -> str:
    if name != "*" and name not in {g.value for g in GraderKind}:
        raise PolicyError(f"unknown grader {name!r}")
    return name


class PolicyStore(ChainLog[PolicyRecord]):
    def __init__(self, path, *, domain: str = ""):
        super().__init__(path, PolicyRecord, domain=domain)

    def current(self) -> Policy:
        pol = Policy()
        for r in self.records():
            m = parse_mode(r.mode)
            if r.grader == "*":
                pol.default = m
            else:
                pol.graders[r.grader] = m
        return pol

    def _add(self, **kw: Any) -> PolicyRecord:
        return self.append(PolicyRecord(ts=datetime.now(timezone.utc).isoformat(), **kw))

    def set_default(self, mode: str, by: str, reason: str = "") -> PolicyRecord:
        m = _settable(mode)
        if m is Mode.ENFORCE:
            raise PolicyError("the default mode cannot be enforce; promote graders individually")
        return self._add(by=by, grader="*", mode=m.value, action="set", reason=reason[:200])

    def demote(self, grader: str, to: str, by: str, reason: str) -> PolicyRecord:
        _valid_grader(grader)
        m = _settable(to)
        if m is Mode.ENFORCE:
            raise PolicyError("demote() cannot move a grader to enforce")
        if not reason.strip():
            raise PolicyError("a demotion needs a reason")
        return self._add(by=by, grader=grader, mode=m.value, action="demote", reason=reason[:200])

    def promote(
        self,
        grader: str,
        to: str,
        by: str,
        ev: Evaluation | None = None,
        *,
        reason: str = "",
        override_reason: str | None = None,
        label_authors: int = 0,
        require_label_authors: int = 0,
    ) -> PolicyRecord:
        """Move `grader` up. To ENFORCE this needs fresh evidence in `ev` (computed by the caller from the
        tenant's own log and labels) showing it is ready, or an explicit, recorded override."""
        _valid_grader(grader)
        if grader == "*":
            raise PolicyError("promote a specific grader")
        target = _settable(to)
        current = self.current().mode_for(grader)
        if _rank(target) <= _rank(current):
            raise PolicyError(f"{grader} is already {current.value}; use demote() to go down")
        evidence: dict[str, Any] = {}
        overridden = False
        if target is Mode.ENFORCE:
            gs = next((g for g in (ev.graders if ev else []) if g.grader == grader), None)
            evidence = _evidence(ev, gs)
            skip = current is not Mode.ADVISORY
            ready = gs is not None and gs.ready_to_enforce
            evidence["label_authors"] = label_authors
            thin = label_authors < require_label_authors
            if not ready or skip or thin:
                if override_reason is None or len(override_reason.strip()) < MIN_OVERRIDE_REASON:
                    why = (
                        "has not earned enforcement"
                        if not ready
                        else "must be advisory first"
                        if skip
                        else f"has labels from {label_authors} reviewer(s), needs {require_label_authors}"
                    )
                    raise PolicyError(
                        f"{grader} {why}: {gs.reason if gs else 'no evidence'}. "
                        f"An admin may override with a reason of >= {MIN_OVERRIDE_REASON} chars."
                    )
                overridden = True
        return self._add(
            by=by,
            grader=grader,
            mode=target.value,
            action="promote",
            reason=((override_reason if overridden else reason) or "")[:200],
            overridden=overridden,
            evidence=evidence,
        )


def _rank(m: Mode) -> int:
    return {Mode.SHADOW: 0, Mode.ADVISORY: 1, Mode.ENFORCE: 2}[m]


def _evidence(ev: Evaluation | None, gs: GraderStats | None) -> dict[str, Any]:
    if ev is None or gs is None:
        return {"note": "no evaluation evidence"}
    s = gs.stats
    return {
        "tp": s.tp,
        "fp": s.fp,
        "tn": s.tn,
        "fn": s.fn,
        "precision_lb": round(s.precision_lb, 4),
        "recall": None if s.recall is None else round(s.recall, 4),
        "errored": gs.errored,
        "ready_to_enforce": gs.ready_to_enforce,
        "reason": gs.reason[:200],
        "thresholds": {
            "min_samples": ev.min_samples,
            "min_precision": ev.min_precision,
            "min_recall": ev.min_recall,
            "max_errored_rate": ev.max_errored_rate,
        },
    }


# ---------------------------------------------------------------------------------------------------
# Applying a policy to one artifact's reports.
# ---------------------------------------------------------------------------------------------------
def enforced_verdict(reports: list[Report], policy: Policy, **gate_kwargs: Any) -> Verdict:
    """The verdict the pipeline acts on: enforcing graders count fully, advisory graders can raise at most a
    WARN, shadow graders do not count. `required` (if given) only constrains the enforcing subset."""
    if kill_switch():
        return Verdict.PASS
    by_mode: dict[Mode, list[Report]] = {Mode.ENFORCE: [], Mode.ADVISORY: [], Mode.SHADOW: []}
    for r in reports:
        by_mode[policy.mode_for(r.grader.value)].append(r)
    verdict = Verdict.PASS
    if by_mode[Mode.ENFORCE]:
        kw = dict(gate_kwargs)
        if "required" in kw and kw["required"]:
            kw["required"] = {g for g in kw["required"] if policy.mode_for(g.value) is Mode.ENFORCE}
        verdict = gate(by_mode[Mode.ENFORCE], **kw).verdict
    if verdict is Verdict.PASS and by_mode[Mode.ADVISORY]:
        adv = gate(by_mode[Mode.ADVISORY]).verdict
        if adv is not Verdict.PASS:
            verdict = Verdict.WARN
    return verdict


# ---------------------------------------------------------------------------------------------------
# Regression watch.
# ---------------------------------------------------------------------------------------------------
@dataclass
class Health:
    grader: str
    healthy: bool
    reason: str


def health(
    records: list[ShadowRecord],
    labels: list[Label],
    policy: Policy,
    *,
    window: int = 200,
    min_flagged: int = 20,
    precision_floor: float = 0.9,
    max_errored_rate: float = 0.1,
) -> list[Health]:
    """Rolling check of every ENFORCING grader over its most recent `window` labeled artifacts."""
    truth = {lab.artifact_id: lab.defect for lab in labels}
    # Order artifacts by where their FIRST record sits in the log (re-recording changes nothing).
    last_pos: dict[str, int] = {}
    seen_content: set[str] = set()
    for i, r in enumerate(records):
        if r.artifact_id in last_pos:
            continue
        if r.content:
            if r.content in seen_content:
                continue  # the same file under another id is the same evidence
            seen_content.add(r.content)
        last_pos[r.artifact_id] = i  # FIRST decision per artifact, as in evaluate()
    ordered = [records[i] for i in sorted(last_pos.values()) if records[i].artifact_id in truth]
    out: list[Health] = []
    for g, m in sorted(policy.graders.items()):
        if m is not Mode.ENFORCE:
            continue
        # Judge precision over the grader's most recent FLAGS, not recent artifacts: padding the log with
        # clean passes must not be able to push bad flags out of the window.
        flags = [r for r in ordered if r.graders.get(g) == "fail"][-window:]
        st = Stats()
        for r in flags:
            st.add(True, truth[r.artifact_id])
        recent = ordered[-window:]
        seen = sum(1 for r in recent if g in r.graders)
        errs = sum(1 for r in recent if r.graders.get(g) == "errored")
        flagged = st.tp + st.fp
        if seen and errs / seen > max_errored_rate:
            out.append(Health(g, False, f"errored on {errs}/{seen} recent artifacts"))
        elif flagged >= min_flagged and wilson_lower(st.tp, flagged) < precision_floor:
            out.append(
                Health(
                    g,
                    False,
                    f"recent precision lower bound {wilson_lower(st.tp, flagged):.2f} "
                    f"< {precision_floor:.2f} over its last {flagged} flags",
                )
            )
        else:
            out.append(Health(g, True, f"{flagged} recent flags, {errs} errors"))
    return out


def autodemote(
    store: PolicyStore, records: list[ShadowRecord], labels: list[Label], **kw: Any
) -> list[Health]:
    """Demote every unhealthy ENFORCING grader to ADVISORY. Returns the demoted graders' health."""
    demoted = [h for h in health(records, labels, store.current(), **kw) if not h.healthy]
    for h in demoted:
        store.append(
            PolicyRecord(
                ts=datetime.now(timezone.utc).isoformat(),
                by="auto",
                grader=h.grader,
                mode=Mode.ADVISORY.value,
                action="autodemote",
                reason=h.reason[:200],
            )
        )
    return demoted


def evaluate_for_promotion(records: list[ShadowRecord], labels: list[Label], **kw: Any) -> Evaluation:
    return evaluate(records, labels, **kw)
