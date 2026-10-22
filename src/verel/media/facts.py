"""Media facts: a flat-ish JSON document of MEASUREMENTS about an asset, produced by the senses
(Audel loudness/true-peak, AgentVision frame/caption state, ffprobe container facts…) and graded by
declared rules. Verel never measures here and never infers a missing value.

Contract ("MediaFacts v1"): a JSON object; keys are dotted paths into nested objects, e.g.
`audio.integrated_lufs`, `audio.true_peak_dbtp`, `av.offset_ms` (positive = audio late),
`video.duration_s`, `captions.languages`. Numbers must be finite; booleans are not numbers.
"""

from __future__ import annotations

import math
from typing import Any

from .._safeio import printable
from ._io import confine, load_json, read_text

MAX_FACT_FILES = 8
MAX_FACT_BYTES = 16 * 1024 * 1024

MISSING = object()


def get_path(facts: dict[str, Any], path: str) -> Any:
    cur: Any = facts
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return MISSING
        cur = cur[part]
    return cur


def as_number(v: Any) -> float | None:
    """A finite real number, else None. bool is deliberately NOT a number (True must not pass `>= 0.5`)."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    try:
        f = float(v)
    except OverflowError:  # an absurdly large integer fact
        return None
    return f if math.isfinite(f) else None


def merge(docs: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge facts from several senses. The same leaf with two DIFFERENT values is an error — silently
    picking one would let a stale measurement override a fresh one."""
    out: dict[str, Any] = {}

    def put(dst: dict[str, Any], src: dict[str, Any], trail: str) -> None:
        for k, v in src.items():
            here = f"{trail}.{k}" if trail else k
            if k not in dst:
                dst[k] = v
            elif isinstance(dst[k], dict) and isinstance(v, dict):
                put(dst[k], v, here)
            elif type(dst[k]) is not type(v) or dst[k] != v:  # True vs 1 IS a conflict
                raise ValueError(f"conflicting facts for {here!r}: {dst[k]!r} vs {v!r}")

    for d in docs:
        put(out, d, "")
    return out


def load_facts(repo: str, rels: list[str]) -> tuple[dict[str, Any], str]:
    """Load + merge repo-confined facts files. Returns (facts, concatenated raw text for hashing)."""
    if len(rels) > MAX_FACT_FILES:
        raise ValueError(f"at most {MAX_FACT_FILES} facts files")
    seen: set[str] = set()
    total = 0
    docs, raws = [], []
    for rel in rels:
        real = confine(repo, rel)
        if real in seen:
            raise ValueError(
                f"facts file listed twice: {printable(rel, 80)!r}"
            )
        seen.add(real)
        raw = read_text(repo, rel)
        total += len(raw)
        if total > MAX_FACT_BYTES:
            raise ValueError("facts files exceed the total size limit")
        data = load_json(raw, rel)
        if not isinstance(data, dict):
            raise ValueError(f"{rel}: facts must be a JSON object")
        docs.append(data)
        raws.append(raw)
    return merge(docs), "\n".join(raws)
