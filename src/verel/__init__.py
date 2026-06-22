"""Verel — the agent framework where nothing is "done" until a grader returns a verdict,
checked by real senses including eyes (AgentVision), and only verified work compounds.

Phase 0 (walking skeleton) ships the verdict bus + the AgentVision sight adapter + the
single-worker ultracode loop. See docs/VEREL_DESIGN.md.
"""

from __future__ import annotations

__version__ = "0.29.2"

from .verdict import (
    GateResult,
    GraderKind,
    Issue,
    IssueKind,
    Percept,
    Report,
    Verdict,
    gate,
    issue_signature,
    progressed,
)

__all__ = [
    "__version__",
    "GateResult",
    "GraderKind",
    "Issue",
    "IssueKind",
    "Percept",
    "Report",
    "Verdict",
    "gate",
    "issue_signature",
    "progressed",
]
