"""Verel agents — the seam where models author work the verdict bus then gates.

The coding agent heals a red build (`verel heal`); the fleet/loop layer runs many managers over one
shared, trust-gated brain. Agentic features need an LLM; grading itself does not.
"""

from __future__ import annotations

from .code_fixer import fix_code
from .coder import Coder, LLMCoder, make_fix_hook

__all__ = ["Coder", "LLMCoder", "make_fix_hook", "fix_code"]
