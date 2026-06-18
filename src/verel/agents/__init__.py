"""Verel agents — the seam where models author work the verdict bus then gates.

Phase 0 ships the coding agent (`FixHook`). The orchestration/fleet layer (agents managing
agents) is v2 per docs/VEREL_DESIGN.md §6.
"""

from __future__ import annotations

from .coder import Coder, LLMCoder, make_fix_hook

__all__ = ["Coder", "LLMCoder", "make_fix_hook"]
