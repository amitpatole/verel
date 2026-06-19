"""Verel public Skill Registry + the H2 corpus-transfer experiment (§2.2, §8.7).

The distribution layer of the data flywheel — content-addressed, signed skill artifacts that
re-earn trust on import — plus the harness that MEASURES whether skills transfer across
tenants (the gate on whether this layer is a real moat).
"""

from __future__ import annotations

from .artifact import SkillArtifact, content_hash
from .h2 import KILL_LINE, TransferOutcome, TransferReport, measure_transfer
from .store import PublicRegistry
from .transfer import ImportResult, export_skill, import_skill

__all__ = [
    "SkillArtifact",
    "content_hash",
    "PublicRegistry",
    "export_skill",
    "import_skill",
    "ImportResult",
    "measure_transfer",
    "TransferReport",
    "TransferOutcome",
    "KILL_LINE",
]
