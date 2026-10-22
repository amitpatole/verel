"""Enforcement modes. Unknown input RAISES — a typo must never silently weaken or strengthen a gate."""

from __future__ import annotations

from enum import Enum

from ..verdict.models import Verdict


class Mode(str, Enum):
    SHADOW = "shadow"      # observe only: the pipeline always proceeds; the would-be verdict is logged
    ADVISORY = "advisory"  # surface problems but never block: FAIL is downgraded to WARN
    ENFORCE = "enforce"    # the real verdict is the enforced verdict


def parse_mode(value: str | Mode) -> Mode:
    if isinstance(value, Mode):
        return value
    try:
        return Mode(str(value).strip().lower())
    except ValueError:
        raise ValueError(
            f"unknown pilot mode {value!r}; expected one of: {', '.join(m.value for m in Mode)}"
        ) from None


def apply_mode(would_be: Verdict, mode: Mode) -> Verdict:
    """The verdict the pipeline should ACT on, given the real (would-be) verdict and the mode."""
    if mode is Mode.ENFORCE:
        return would_be
    if mode is Mode.ADVISORY:
        return Verdict.WARN if would_be is Verdict.FAIL else would_be
    return Verdict.PASS  # SHADOW
