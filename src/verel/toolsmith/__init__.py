"""Verel tool-smith — agents building their own tools (§7.6).

detect → scaffold → test → register → reuse. Tools live in procedural memory (SKILL records)
behind the same MemoryView, gated by the same attested eval discipline as facts/skills:
verified-and-auto for read-only/idempotent tools, human-review-gated for destructive ones.
"""

from __future__ import annotations

from .container import best_runner, bwrap_available, run_container
from .registry import SideEffect, ToolRecord, ToolRegistry, load_callable
from .sandbox import SandboxError, run_sandboxed
from .seccomp import (
    ALLOWED_SYSCALLS,
    DENIED_SYSCALLS,
    PROFILE_ALLOWLIST,
    PROFILE_DENYLIST,
    build_bpf,
    seccomp_available,
)
from .smith import BuildResult, ToolCase, ToolSmith, ToolSpec, eval_tool_cases

__all__ = [
    "SideEffect",
    "ToolRecord",
    "ToolRegistry",
    "load_callable",
    "run_sandboxed",
    "run_container",
    "best_runner",
    "bwrap_available",
    "seccomp_available",
    "build_bpf",
    "DENIED_SYSCALLS",
    "ALLOWED_SYSCALLS",
    "PROFILE_DENYLIST",
    "PROFILE_ALLOWLIST",
    "SandboxError",
    "BuildResult",
    "ToolCase",
    "ToolSmith",
    "ToolSpec",
    "eval_tool_cases",
]
