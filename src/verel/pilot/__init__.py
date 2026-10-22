"""`verel.pilot` — run Verel in a real pipeline *without* risking it, then prove it earned enforcement.

Three enforcement modes (SHADOW → ADVISORY → ENFORCE), a tamper-evident hash-chained decision log,
and an evaluation harness that scores recorded verdicts against human labels (precision / recall /
false-positive rate with a Wilson lower bound) and recommends — never auto-applies — graduation.
"""

from __future__ import annotations

from .evaluate import Evaluation, GraderStats, Label, Stats, evaluate, load_labels, wilson_lower
from .log import LogCorrupt, ShadowLog, ShadowRecord
from .mode import Mode, apply_mode, parse_mode
from .shadow import PilotDecision, run_pilot

__all__ = [
    "Evaluation", "GraderStats", "Label", "LogCorrupt", "Mode", "PilotDecision", "ShadowLog",
    "ShadowRecord", "Stats", "apply_mode", "evaluate", "load_labels", "parse_mode", "run_pilot",
    "wilson_lower",
]
