"""Integration adapters — plug Verel into a team's EXISTING agent stack (the "Reach" track).

Verel grades artifacts, not agent internals, so it is host/model-agnostic: the same verdict gate
inserts into whatever a team already uses to instruct agents. This package is the seam for every
non-CLI adapter (rules-file snippets, `verel mcp install`, and — later — the MCP client/gateway,
REST/webhook, and agent-SDK shims). Keep adapters thin: they only marshal to `dispatch()`/`gate()`.

R0 (shipped here): `snippets` — the universal "call verel_gate before done" instruction for any
agent host, plus the verel-mcp server config, as pure, testable strings.
"""

from __future__ import annotations

from .snippets import (
    RULES_TARGETS,
    mcp_config_json,
    mcp_install_hint,
    rules_snippet,
)

__all__ = [
    "RULES_TARGETS",
    "mcp_config_json",
    "mcp_install_hint",
    "rules_snippet",
    # R1 — REST gate server + GitHub webhook (lazy: imported on demand so the base import stays light)
    "GateServer",
    "verify_github_signature",
    "parse_pr_event",
    "post_commit_status",
]


def __getattr__(name: str):
    # Lazy re-export of the REST surface (keeps `import verel.integrations` from pulling http.server
    # until something actually needs the server).
    if name in ("GateServer", "verify_github_signature", "parse_pr_event", "post_commit_status"):
        from . import rest
        return getattr(rest, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
