"""Episodic percept log + Verel-owned progressed/stuck (§7.2, §8.5).

Binding rule from the design: Verel does NOT rely on AgentVision `LoopSession`'s in-process
message-based progressed/stuck (it is lost on a worker crash and uses a brittle identity).
Verel persists `PerceptEvent`s itself and recomputes progressed/stuck from its OWN scrubbed
fingerprints — both every iteration AND on resume. This module is that single source of
stuck-timing truth.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..verdict.models import Percept


def _gating_set(percept: Percept) -> frozenset[str]:
    from ..verdict.constants import GATING_SEVERITY, SEV_ORDER

    gate_idx = SEV_ORDER.index(GATING_SEVERITY)
    return frozenset(
        o.fingerprint for o in percept.observations if SEV_ORDER.index(o.severity) >= gate_idx
    )


class PerceptLog:
    """Append-only JSONL log of percepts for one artifact, with crash-safe replay."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, percept: Percept, *, ts: str = "", model: str = "", backend: str = "",
               ssim: float | None = None, changed_ratio: float | None = None) -> None:
        prev = self._last()
        progressed = bool(prev is not None and _gating_set(percept) < prev)
        record = {
            "ts": ts,
            "agent_id": percept.agent_id,
            "artifact_id": percept.artifact_id,
            "verdict": percept.verdict.value,
            "signature": percept.signature,
            "gating": sorted(_gating_set(percept)),
            "progressed": progressed,
            "stuck": self._would_be_stuck(percept),
            "model": model,
            "backend": backend,
            "ssim": ssim,
            "changed_ratio": changed_ratio,
            "image_path": percept.image_path,
            "matches_intent": percept.matches_intent,
            "intent_satisfied": percept.intent_satisfied,
            "intent_total": percept.intent_total,
            "playing": percept.playing,
            "live": percept.live,
            "stabilized": percept.stabilized,
        }
        with self.path.open("a") as f:
            f.write(json.dumps(record) + "\n")

    def history(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]

    def _gating_sets(self) -> list[frozenset[str]]:
        return [frozenset(r["gating"]) for r in self.history()]

    def _last(self) -> frozenset[str] | None:
        sets = self._gating_sets()
        return sets[-1] if sets else None

    def progressed(self) -> bool:
        """Did the most recent appended percept strictly shrink the gating set?"""
        sets = self._gating_sets()
        if len(sets) < 2:
            return True  # first observation can't be stuck
        return sets[-1] < sets[-2]

    def _would_be_stuck(self, candidate: Percept) -> bool:
        prev = self._last()
        if prev is None:
            return False
        cand = _gating_set(candidate)
        # stuck = still failing AND not a strict shrink vs the previous gating set.
        return bool(cand) and not (cand < prev)

    def stuck(self, window: int | None = None) -> bool:
        """Stuck = the gating set is non-empty and has not strictly shrunk across the last
        `window` observations (default = constants.W)."""
        from ..verdict.constants import W

        window = window or W
        sets = self._gating_sets()
        if not sets or not sets[-1]:
            return False  # passing or empty -> not stuck
        recent = sets[-window:]
        if len(recent) < 2:
            return False
        # strict monotone shrink somewhere in the window means we are still making progress
        shrank = any(recent[i] < recent[i - 1] for i in range(1, len(recent)))
        return not shrank
