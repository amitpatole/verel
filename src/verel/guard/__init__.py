"""`verel.guard` — static document-ingress grader (hidden-content / prompt-injection scanner).

Grades untrusted documents BEFORE any LLM sees them: the document is data, never instructions, and
no model runs in the detection path. The load-bearing signal is the visible-vs-extracted mismatch
(text a human reader can't see but an extractor ingests) combined with a lexical catalogue of
injection/exfil/propagation imperatives and invisible-Unicode carriers. Structural hiding alone is
advisory (WARNING); hiding plus an imperative is the worm conjunction (CRITICAL).

The engine lives here (fastest path to a shipped, tested defense) behind a `Sense`-shaped surface
(`DocumentGuard`) so the future `immel` boundary organ can adopt it without a rewrite.
"""

from __future__ import annotations

from .model import CATALOG_VERSION, Finding, MissingGuardDep
from .report import grade_docs
from .sense import DocumentGuard

__all__ = [
    "CATALOG_VERSION",
    "DocumentGuard",
    "Finding",
    "MissingGuardDep",
    "grade_docs",
    "scan_text",
]


def scan_text(text: str) -> list[Finding]:
    """Scan a raw string (no file) for injection patterns and invisible-Unicode carriers."""
    from .invisible import scan_invisible
    from .lexical import scan_text as _scan
    return _scan(text) + scan_invisible(text)
