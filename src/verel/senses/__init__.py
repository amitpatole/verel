"""Verel senses — perception that feeds the verdict bus and (later) the brain.

`sight` is the AgentVision-backed sense and the only one implemented in Phase 0. Other
senses (logs/tests/metrics/types) share the same `Percept` envelope (§8.3).
"""

from __future__ import annotations

from .percept_log import PerceptLog
from .sight import SightResult, classic_capabilities, from_agentvision, perceive, watch

__all__ = ["PerceptLog", "SightResult", "classic_capabilities", "from_agentvision",
           "perceive", "watch"]
