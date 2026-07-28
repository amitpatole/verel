"""Verel — the agent framework where nothing is "done" until a grader returns a verdict,
checked by real senses including eyes (AgentVision), and only verified work compounds.

The verdict bus grades work (`pass`/`warn`/`fail`) with signed receipts; graders span code (tests,
types, lint, security, mutation), infrastructure (IaC/IAM/K8s), telecom (5G RAN/Core config + KPIs),
and perception (eyes/ears). Docs: https://amitpatole.github.io/verel/
"""

from __future__ import annotations

__version__ = "1.9.1"

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
