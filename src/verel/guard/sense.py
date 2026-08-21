"""`DocumentGuard` — the guard as a duck-typed agentsensory `Sense`.

The document-ingress scanner is architecturally a boundary/immune capability: in the organism it
will live in `immel`. It ships in `verel` now (fastest path to a tested defense) behind this
`Sense`-shaped surface so `immel` can adopt it without a rewrite — `immel.document` lazy-imports
this class and re-exports it. The shape matches the agentsensory `Sense` protocol
(`name` / `available()` / async `analyze()`), verified structurally rather than by importing
agentsensory (which the base wheel does not depend on).
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from ..verdict.models import Report


class DocumentGuard:
    """A `Sense` over untrusted documents: perceives hidden content / injection and grades it."""

    name = "immel.document"

    def available(self) -> bool:
        return True

    async def analyze(self, source: str | Path | Sequence[str | Path], **kwargs: object) -> Report:
        from .report import grade_docs
        if isinstance(source, (str, Path)):
            paths: Sequence[str | Path] = [source]
        else:
            paths = list(source)
        return grade_docs(paths, **kwargs)  # type: ignore[arg-type]
