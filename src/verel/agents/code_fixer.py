"""Code-fixer agent — patches source to make failing graders pass (§7.4 self-healing).

Given a repo and the failing verdict-bus issues (test/lint/type messages), an LLM proposes
edits to the implicated source files. The loop owns truth: the CI stage re-runs after every
patch, so the agent can never declare success — only the graders can. Returns the set of
files it changed (empty => gave up).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable

from . import llm
from ..verdict.models import Report

ChatFn = Callable[[list[dict]], str]

_SYSTEM = (
    "You are a code-fixer in an eval-gated CI loop. You are given failing test/lint/type "
    "output and the current source files. Edit ONLY what is needed to make them pass; do not "
    "change tests, rename things, or add features. Respond as STRICT JSON: "
    '{"files": {"<relpath>": "<full new file contents>"}}. Include every file you change, in '
    "full. No prose outside the JSON."
)

_SKIP = {".git", ".venv", "venv", "__pycache__", ".verel", "node_modules", ".pytest_cache"}


def _source_files(repo: Path, *, max_files: int = 25, max_bytes: int = 60_000) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in sorted(repo.rglob("*.py")):
        if any(part in _SKIP for part in p.parts):
            continue
        if p.name.startswith("test_") or p.name.endswith("_test.py"):
            continue  # never edit tests
        try:
            text = p.read_text()
        except (OSError, UnicodeDecodeError):
            continue
        if len(text) > max_bytes:
            continue
        out[str(p.relative_to(repo))] = text
        if len(out) >= max_files:
            break
    return out


def _issues_text(reports: list[Report]) -> str:
    lines = []
    for r in reports:
        for i in r.issues:
            loc = f" @ {i.locator}" if i.locator else ""
            lines.append(f"- [{i.source.value}/{i.severity.value}]{loc}: {i.message}")
    return "\n".join(lines) or "- (no machine-graded issues)"


def _parse_files(reply: str) -> dict[str, str]:
    s, e = reply.find("{"), reply.rfind("}")
    if s == -1 or e == -1:
        return {}
    try:
        obj = json.loads(reply[s : e + 1])
    except json.JSONDecodeError:
        return {}
    files = obj.get("files", {})
    return {k: v for k, v in files.items() if isinstance(k, str) and isinstance(v, str)}


def fix_code(repo: str | Path, reports: list[Report], *, chat: ChatFn | None = None,
             hints: list[str] | None = None) -> set[str]:
    """Ask the agent to patch source so the failing graders pass. Returns changed file paths.
    `hints` are optional ci-medic root-cause hypotheses (LLM-enriched) to focus the fix."""
    repo = Path(repo)
    chat = chat or (lambda msgs: llm.chat(msgs).content)
    sources = _source_files(repo)
    if not sources:
        return set()

    blob = "\n\n".join(f"=== {path} ===\n{content}" for path, content in sources.items())
    hint_text = ("\nRoot-cause hints:\n" + "\n".join(f"- {h}" for h in hints) if hints else "")
    user = f"Failing graders:\n{_issues_text(reports)}{hint_text}\n\nSource files:\n{blob}"
    proposed = _parse_files(chat([{"role": "system", "content": _SYSTEM},
                                  {"role": "user", "content": user}]))

    changed: set[str] = set()
    for rel, content in proposed.items():
        target = (repo / rel).resolve()
        if repo.resolve() not in target.parents and target != repo.resolve():
            continue  # path escape guard
        if Path(rel).name.startswith("test_"):
            continue  # never edit tests
        if sources.get(rel, None) == content:
            continue  # no-op
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content if content.endswith("\n") else content + "\n")
        changed.add(rel)
    return changed
