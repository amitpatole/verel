"""The coding agent that authors fixes — the real `FixHook` (design §11.1 item 5).

Replaces the deterministic stand-in from Phase 0: given the artifact source and the
verdict-bus issues, an LLM proposes the corrected file, scoped to ONLY the reported issues.
The loop still owns truth — it re-perceives and re-gates; if the agent's edit doesn't shrink
the gating set, Verel's own stuck-detection halts the loop (the agent can't declare success).

`Coder` is a protocol, so a Claude-backed coder, a local-model coder, or a test fake all
plug into `make_fix_hook(...)` identically.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Protocol

from ..verdict.models import GateResult, Report
from . import llm

_FENCE = re.compile(r"```(?:[a-zA-Z0-9_+-]*)?\n(.*?)```", re.DOTALL)

_SYSTEM = (
    "You are a precise coding agent operating inside an eval-gated loop. You are given the "
    "FULL contents of a single source file and a list of verified issues found by graders "
    "(DOM geometry, contrast, OCR, vision). Fix ONLY those issues. Do not refactor, rename, "
    "add features, or change unrelated styling. Preserve the file's structure and intent. "
    "Return the COMPLETE corrected file inside a single fenced code block and nothing else."
)


def _issues_block(reports: list[Report]) -> str:
    lines = []
    for r in reports:
        for i in r.issues:
            loc = f" @ {i.locator}" if i.locator else ""
            lines.append(f"- [{r.grader.value}/{i.severity.value}] {i.kind.value}{loc}: {i.message}")
    return "\n".join(lines) or "- (no machine-graded issues listed; infer from the verdict)"


def _extract_file(reply: str) -> str:
    m = _FENCE.search(reply)
    return (m.group(1) if m else reply).strip("\n")


class Coder(Protocol):
    def fix(self, source: str, issues_text: str, *, filename: str) -> str:
        """Return the corrected file contents (full file)."""
        ...


class LLMCoder:
    """Provider-agnostic LLM coder (OpenAI backend in Phase 0; Claude is the prod default)."""

    def __init__(self, model: str | None = None):
        self.model = model
        self.last_cost_tokens = 0

    def fix(self, source: str, issues_text: str, *, filename: str) -> str:
        user = (
            f"File: {filename}\n\nIssues to fix:\n{issues_text}\n\n"
            f"Current contents:\n```\n{source}\n```\n\n"
            "Return the complete corrected file in one fenced code block."
        )
        res = llm.chat(
            [{"role": "system", "content": _SYSTEM}, {"role": "user", "content": user}],
            model=self.model,
        )
        self.last_cost_tokens = res.prompt_tokens + res.completion_tokens
        return _extract_file(res.content)


def make_fix_hook(coder: Coder | None = None, *, verbose: bool = True):
    """Build a `FixHook` for `verel.loop.ultracode_loop` backed by a coding agent."""
    coder = coder or LLMCoder()

    async def fix(artifact: str, gate_result: GateResult, reports: list[Report]) -> bool:
        path = Path(artifact)
        source = path.read_text()
        issues_text = _issues_block(reports)
        try:
            new_source = coder.fix(source, issues_text, filename=path.name)
        except Exception as e:  # noqa: BLE001 — a failed agent call is a give-up, not a crash
            if verbose:
                print(f"  coder: error ({e}); giving up")
            return False
        if not new_source or new_source.strip() == source.strip():
            if verbose:
                print("  coder: no change proposed; giving up")
            return False
        path.write_text(new_source if new_source.endswith("\n") else new_source + "\n")
        if verbose:
            print(f"  coder: rewrote {path.name} ({len(source)} -> {len(new_source)} chars)")
        return True

    return fix
