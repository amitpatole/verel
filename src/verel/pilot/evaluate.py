"""Score recorded pilot verdicts against human labels and say — honestly — whether a grader has
earned enforcement. Graduation is a RECOMMENDATION from evidence; a human flips the switch."""

from __future__ import annotations

import json
import math
from pathlib import Path

from pydantic import BaseModel, Field, computed_field

from .log import ShadowRecord, valid_artifact_id

MAX_LABEL_BYTES = 10_000_000
Z95 = 1.959963984540054


class Label(BaseModel):
    artifact_id: str
    defect: bool  # ground truth from a human reviewer: does this artifact have a real problem?


def load_labels(path: str | Path) -> list[Label]:
    """JSON list or JSONL of `{"artifact_id": ..., "defect": true|false}`. Duplicate ids with
    conflicting labels are rejected — ambiguous ground truth would silently skew every metric."""
    p = Path(path)
    if p.stat().st_size > MAX_LABEL_BYTES:
        raise ValueError(f"labels file exceeds {MAX_LABEL_BYTES} bytes")
    text = p.read_text(encoding="utf-8")
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


def _ready(stats: Stats, min_samples: int, min_precision: float) -> tuple[bool, str]:
    flagged = stats.tp + stats.fp
    if flagged < min_samples:
        return False, f"only {flagged} flagged artifacts (need >= {min_samples})"
    lb = stats.precision_lb
    if lb < min_precision:
        return False, f"precision lower bound {lb:.2f} < {min_precision:.2f}"
    return True, f"precision lower bound {lb:.2f} >= {min_precision:.2f} over {flagged} flags"


def evaluate(
    records: list[ShadowRecord],
    labels: list[Label],
    *,
    warn_is_positive: bool = False,
    min_samples: int = 30,
    min_precision: float = 0.95,
) -> Evaluation:
    """Latest record per artifact is scored against its label. A grader whose report ERRORED is
    excluded from its own stats (and counted) — an outage must not read as a clean PASS."""
    truth = {lab.artifact_id: lab.defect for lab in labels}
    latest: dict[str, ShadowRecord] = {}
    for r in records:
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
        ok, why = _ready(st, min_samples, min_precision)
        gs.append(GraderStats(grader=g, stats=st, errored=errs.get(g, 0), ready_to_enforce=ok, reason=why))
    return Evaluation(
        labeled=overall.n, unlabeled_records=unlabeled,
        labels_without_record=len(set(truth) - set(latest)),
        errored_gates=sum(1 for r in latest.values() if r.gate_error),
        overall=overall, graders=gs, min_samples=min_samples, min_precision=min_precision,
    )
