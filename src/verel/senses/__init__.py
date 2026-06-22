"""Verel senses — perception that feeds the verdict bus and (later) the brain.

`sight` (AgentVision-backed eyes) and `audio` (Audel-backed ears) share the same `Percept`
envelope (§8.3); other senses (logs/tests/metrics/types) follow the same shape. `sight.perceive`/
`sight.watch` and `audio.perceive`/`audio.watch` have the same names by design — call them through
their module (`from verel.senses import audio; audio.perceive(...)`) so neither shadows the other.
"""

from __future__ import annotations

from . import audio
from .audio import AudioResult, from_audel
from .percept_log import PerceptLog
from .sight import SightResult, classic_capabilities, from_agentvision, perceive, watch

__all__ = ["PerceptLog", "SightResult", "classic_capabilities", "from_agentvision",
           "perceive", "watch", "audio", "AudioResult", "from_audel"]
