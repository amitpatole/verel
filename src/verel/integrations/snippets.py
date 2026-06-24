"""Drop-in adoption snippets — make ANY agent call the Verel gate before it declares "done".

All functions are pure (return strings/dicts) so they're trivially testable and the CLI just
prints or writes them. Nothing here imports the heavy framework — `verel mcp install` / `verel
rules` work on a minimal install.
"""

from __future__ import annotations

import json

# The verel-mcp server, in the standard MCP `mcpServers` shape every host understands.
_MCP_SERVER = {"command": "verel-mcp"}


def mcp_config_json(*, server_name: str = "verel") -> str:
    """The MCP server config block to add to a host's MCP settings (Claude Desktop, Cursor, …)."""
    return json.dumps({"mcpServers": {server_name: _MCP_SERVER}}, indent=2)


# Where each known host keeps its MCP config (relative to the noted base). Print-only guidance —
# we never guess-write a global host file without the user naming the host.
_MCP_HOSTS = {
    "claude-desktop": "~/.config/Claude/claude_desktop_config.json (Linux) · "
                      "~/Library/Application Support/Claude/claude_desktop_config.json (macOS)",
    "cursor": ".cursor/mcp.json (project) or ~/.cursor/mcp.json (global)",
    "cline": "VS Code settings → Cline MCP servers (cline_mcp_settings.json)",
    "continue": "~/.continue/config.json (under \"mcpServers\")",
    "windsurf": "~/.codeium/windsurf/mcp_config.json",
}


def mcp_install_hint() -> str:
    """Human-readable: the config block + where each host expects it."""
    lines = ["Add this MCP server to your agent host:", "", mcp_config_json(), "",
             "Then point your host at it:"]
    for host, where in _MCP_HOSTS.items():
        lines.append(f"  - {host}: {where}")
    lines += ["", "Install the binary first if needed:  pipx install verel  (or pip install verel)"]
    return "\n".join(lines)


# The universal instruction — host-agnostic. This is the whole point of R0: any agent that reads
# its rules file will gate its own work through Verel and stop self-declaring "done".
_RULES_BODY = """\
## Verification gate (Verel) — do not declare work "done" on your own say-so

Before you treat ANY coding task as complete, verify it with Verel. Your own judgment that the work
is finished is not sufficient — a grader decides "done", not you.

1. Call the `verel_gate` MCP tool with the repo path, e.g. `{"repo": "."}`.
2. Consider the task complete ONLY when it returns `verdict: pass`.
3. If it returns `verdict: fail`, read the grounded issues (each has a `file:line` locator), fix the
   root cause in the SOURCE, then call `verel_gate` again. Repeat until it passes.
4. Never edit or weaken tests to make the gate pass — fix the code under test.

If `verel_gate` is not available, add the Verel MCP server to this host's config:

```json
{MCP_CONFIG}
```

and install it with `pipx install verel` (or `pip install verel`). See https://github.com/amitpatole/verel
"""


def _rules_body() -> str:
    return _RULES_BODY.replace("{MCP_CONFIG}", mcp_config_json())


# target -> filename the host reads. The BODY is identical everywhere (the instruction is universal);
# only the destination file differs per host.
RULES_TARGETS = {
    "cursor": ".cursorrules",
    "claude": "CLAUDE.md",
    "agents": "AGENTS.md",
    "copilot": ".github/copilot-instructions.md",
    "windsurf": ".windsurfrules",
}


def rules_snippet(target: str) -> tuple[str, str]:
    """Return `(filename, content)` for a host target. Content is the universal gate instruction;
    for `claude`/`agents` (full markdown docs) it carries an H1, else just the section body."""
    if target not in RULES_TARGETS:
        raise ValueError(f"unknown rules target {target!r}; known: {sorted(RULES_TARGETS)}")
    filename = RULES_TARGETS[target]
    body = _rules_body()
    if target in ("claude", "agents"):
        body = f"# Agent instructions\n\n{body}"
    return filename, body
