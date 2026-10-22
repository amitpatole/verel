"""Score recorded pilot verdicts against human labels and say — honestly — whether a grader has
earned enforcement. Graduation is a RECOMMENDATION from evidence; a human flips the switch.

The FIRST decision recorded for an artifact id is the one scored. A later re-record of the same id is kept
in the log but not scored, so nobody can re-grade a labeled artifact to manufacture (or erase) evidence; a new
version of an asset gets a new artifact id."""

from __future__ import annotations

import json
import math
from pathlib import Path

from pydantic import BaseModel, Field, computed_field, field_validator

from .._safeio import read_regular
from .log import ShadowRecord, valid_artifact_id

MAX_LABEL_BYTES = 10_000_000
Z95 = 1.959963984540054


class Label(BaseModel):
    artifact_id: str
    defect: bool  # ground truth from a human reviewer: does this artifact have a real problem?

    @field_validator("artifact_id")
    @classmethod
    def _id(cls, v: str) -> str:
        return valid_artifact_id(v)


def load_labels(path: str | Path) -> list[Label]:
    """JSON list or JSONL of `{"artifact_id": ..., "defect": true|false}`. Duplicate ids with
    conflicting labels are rejected — ambiguous ground truth would silently skew every metric."""
    text = read_regular(path, MAX_LABEL_BYTES).decode("utf-8")
    try:
        rows = json.loads(text)
    except json.JSONDecodeError:
        rows = [json.loads(ln) for ln in text.splitlines() if ln.strip()]
    if not isinstance(rows, list):
        raise ValueError("labels must be a JSON list or JSONL")
    seen: dict[str, bool] = {}
    out: list[Label] = []
    for r in rows:
        lab = Label.model_validate(r)
        valid_artifact_id(lab.artifact_id)
        if lab.artifact_id in seen:
            if seen[lab.artifact_id] != lab.defect:
                raise ValueError(f"conflicting labels for {lab.artifact_id!r}")
            continue
        seen[lab.artifact_id] = lab.defect
        out.append(lab)
    return out


def wilson_lower(successes: int, n: int, z: float = Z95) -> float:
    """Lower bound of the Wilson score interval — a small, lucky sample can't look 'precise'."""
    if n <= 0:
        return 0.0
    p = successes / n
    d = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (centre - margin) / d)


class Stats(BaseModel):
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def n(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @computed_field  # type: ignore[prop-decorator]
    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fpr(self) -> float | None:
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) else None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def precision_lb(self) -> float:
        return wilson_lower(self.tp, self.tp + self.fp)

    def add(self, predicted_bad: bool, defect: bool) -> None:
        if predicted_bad and defect:
            self.tp += 1
        elif predicted_bad:
            self.fp += 1
        elif defect:
            self.fn += 1
        else:
            self.tn += 1


class GraderStats(BaseModel):
    grader: str
    stats: Stats
    errored: int = 0
    ready_to_enforce: bool = False
    reason: str = ""


class Evaluation(BaseModel):
    labeled: int
    unlabeled_records: int
    labels_without_record: int  # coverage hole: labeled artifacts the pipeline never graded
    errored_gates: int
    overall: Stats
    graders: list[GraderStats] = Field(default_factory=list)
    min_samples: int
    min_precision: float
    min_recall: float = 0.5
    max_errored_rate: float = 0.05
    duplicate_content: int = 0  # decisions ignored because the same file was already scored under another id


def _ready(
    stats: Stats,
    errored: int,
    min_samples: int,
    min_precision: float,
    min_recall: float,
    max_errored_rate: float,
) -> tuple[bool, str]:
    """Precision alone can be gamed by a grader that flags almost nothing, or that keeps crashing:
    enforcement also needs real recall and a low outage rate."""
    flagged = stats.tp + stats.fp
    if flagged < min_samples:
        return False, f"only {flagged} flagged artifacts (need >= {min_samples})"
    lb = stats.precision_lb
    if lb < min_precision:
        return False, f"precision lower bound {lb:.2f} < {min_precision:.2f}"
    rec = stats.recall
    if rec is None or rec < min_recall:
        shown = "n/a" if rec is None else f"{rec:.2f}"
        return False, f"recall {shown} < {min_recall:.2f} (it misses too many real defects)"
    seen = stats.n + errored
    err_rate = errored / seen if seen else 0.0
    if err_rate > max_errored_rate:
        return False, f"errored on {err_rate:.0%} of artifacts (> {max_errored_rate:.0%}); it is not reliable"
    return True, (
        f"precision lower bound {lb:.2f} >= {min_precision:.2f}, recall {rec:.2f}, "
        f"errored {err_rate:.0%}, over {flagged} flags"
    )


def evaluate(
    records: list[ShadowRecord],
    labels: list[Label],
    *,
    warn_is_positive: bool = False,
    min_samples: int = 30,
    min_precision: float = 0.95,
    min_recall: float = 0.5,
    max_errored_rate: float = 0.05,
) -> Evaluation:
    """Latest record per artifact is scored against its label. A grader whose report ERRORED is
    excluded from its own stats (and counted) — an outage must not read as a clean PASS."""
    truth = {lab.artifact_id: lab.defect for lab in labels}
    latest: dict[str, ShadowRecord] = {}  # FIRST decision per artifact: re-recording cannot rewrite evidence
    seen_content: set[str] = set()
    duplicate_content = 0
    for r in records:
        if r.artifact_id in latest:
            continue
        if r.content:  # the same FILE under another id is the same evidence, counted once
            if r.content in seen_content:
                duplicate_content += 1
                continue
            seen_content.add(r.content)
        latest[r.artifact_id] = r
    bad = {"fail", "warn"} if warn_is_positive else {"fail"}

    overall = Stats()
    per: dict[str, Stats] = {}
    errs: dict[str, int] = {}
    unlabeled = 0
    for aid, rec in latest.items():
        if aid not in truth:
            unlabeled += 1
            continue
        overall.add(rec.would_be.value in bad, truth[aid])
        for g, v in rec.graders.items():
            if v == "errored":
                errs[g] = errs.get(g, 0) + 1
                continue
            per.setdefault(g, Stats()).add(v in bad, truth[aid])

    gs = []
    for g in sorted(set(per) | set(errs)):
        st = per.get(g, Stats())
        ok, why = _ready(st, errs.get(g, 0), min_samples, min_precision, min_recall, max_errored_rate)
        gs.append(GraderStats(grader=g, stats=st, errored=errs.get(g, 0), ready_to_enforce=ok, reason=why))
    return Evaluation(
        labeled=overall.n,
        unlabeled_records=unlabeled,
        labels_without_record=len(set(truth) - set(latest)),
        errored_gates=sum(1 for r in latest.values() if r.gate_error),
        overall=overall,
        graders=gs,
        min_samples=min_samples,
        min_precision=min_precision,
        min_recall=min_recall,
        max_errored_rate=max_errored_rate,
        duplicate_content=duplicate_content,
    )
