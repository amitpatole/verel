"""Pre-commit hook installer (§7.4) — makes "agents run CI/CD" concrete at the git boundary.

Installs a `.git/hooks/pre-commit` that runs Verel's pre-commit stage; a FAIL verdict aborts
the commit. This is the local safety gate every worker (human or agent) passes through.
"""

from __future__ import annotations

import stat
from pathlib import Path

_HOOK = """#!/usr/bin/env bash
# Installed by verel.ci — runs the pre-commit verdict gate; FAIL aborts the commit.
exec python -m verel.ci precommit --repo "$(git rev-parse --show-toplevel)"
"""


def install_precommit(repo: str | Path) -> Path:
    repo = Path(repo).resolve()
    hooks = repo / ".git" / "hooks"
    if not hooks.exists():
        raise FileNotFoundError(f"{repo} has no .git/hooks (not a git repo?)")
    hook = hooks / "pre-commit"
    hook.write_text(_HOOK)
    hook.chmod(hook.stat().st_mode | stat.S_IEXEC | stat.S_IRWXU)
    return hook


def is_installed(repo: str | Path) -> bool:
    hook = Path(repo).resolve() / ".git" / "hooks" / "pre-commit"
    return hook.exists() and "verel.ci" in hook.read_text()
