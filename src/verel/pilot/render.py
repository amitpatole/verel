"""Terminal rendering of an Evaluation (kept out of evaluate.py so the model stays pure)."""

from __future__ import annotations

from .._safeio import printable
from .evaluate import Evaluation, Stats


def _pct(x: float | None) -> str:
    return "  n/a" if x is None else f"{x * 100:5.1f}%"


def _row(name: str, s: Stats, tail: str) -> str:
    return (f"  {name:<12} tp={s.tp:<3} fp={s.fp:<3} tn={s.tn:<3} fn={s.fn:<3} "
            f"precision={_pct(s.precision)} (lb {s.precision_lb * 100:4.1f}%) "
            f"recall={_pct(s.recall)} fpr={_pct(s.fpr)}  {tail}")


def render(ev: Evaluation) -> str:
    lines = [
        f"labeled={ev.labeled}  unlabeled_records={ev.unlabeled_records}  "
        f"labels_without_record={ev.labels_without_record}  gate_errors={ev.errored_gates}",
        _row("GATE", ev.overall, ""),
    ]
    for g in ev.graders:
        verdict = "READY to enforce" if g.ready_to_enforce else "keep in shadow/advisory"
        err = f" errored={g.errored}" if g.errored else ""
        lines.append(_row(printable(g.grader, 24), g.stats, f"-> {verdict}: {g.reason}{err}"))
    return "\n".join(lines)
