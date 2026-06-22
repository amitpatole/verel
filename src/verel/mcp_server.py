"""Verel MCP server — exposes the framework to any MCP host (Cursor/Claude/etc.), mirroring
AgentVision's surface strategy: the same capabilities, reachable cross-host.

The tool DISPATCH layer (`TOOLS`, `dispatch`) is pure and testable without the `mcp` package;
`serve()` binds it to a real MCP stdio server (the optional `verel[mcp]` extra). Tools:

  verel_gate         gate a list of Reports (JSON) → verdict
  verel_ci_check     run the inner-loop CI stage on a repo → verdict + issues
  verel_recall       recall from a memory store → records
  verel_build_tool   detect→scaffold→test→register a tool (needs an LLM key)

Every tool returns the same verdict-shaped truth the rest of Verel speaks.
"""

from __future__ import annotations

import json
from typing import Any

# ---- tool implementations (pure-ish; importable without `mcp`) ----


def _tool_gate(args: dict) -> dict:
    from .verdict.gate import gate
    from .verdict.models import Report

    reports = [Report(**r) for r in args.get("reports", [])]
    gr = gate(reports)
    return {"verdict": gr.verdict.value, "reason": gr.reason,
            "attributions": {k: v.value for k, v in gr.attributions.items()}}


def _tool_ci_check(args: dict) -> dict:
    from .ci import inner_loop_stage, run_stage

    stage = inner_loop_stage(args["repo"], with_lint=args.get("lint", False))
    res = run_stage(stage)
    return {
        "verdict": res.verdict.value,
        "issues": [
            {"grader": i.source.value, "severity": i.severity.value,
             "locator": i.locator, "message": i.message}
            for r in res.reports for i in r.issues
        ],
    }


def _tool_recall(args: dict) -> dict:
    from .memory import LocalMemory

    mem = LocalMemory(args.get("store", ":memory:"))
    hits = mem.recall(args["query"], scope=args.get("scope"), k=args.get("k", 5))
    return {"records": [{"subject": h.subject, "text": h.text, "trust": h.trust.value,
                         "scope": h.scope} for h in hits]}


def _tool_build_tool(args: dict) -> dict:
    from .memory import LocalMemory
    from .toolsmith import SideEffect, ToolCase, ToolRegistry, ToolSmith, ToolSpec

    spec = ToolSpec(
        name=args["name"], capability=args["capability"],
        signature_hint=args.get("signature_hint", ""),
        side_effect=SideEffect(args.get("side_effect", "read_only")),
        cases=[ToolCase(**c) for c in args.get("cases", [])],
    )
    # SECURITY: this path builds and runs LLM/remote-supplied code. Require the CONTAINER tier
    # (bwrap netns + read-only fs + seccomp). Do NOT fall back to "best"/subprocess — the rlimit
    # subprocess tier has no network/seccomp isolation, so a bwrap-less host would otherwise become
    # remote-code-execution-with-network. Without bwrap the build fails closed (code never runs).
    res = ToolSmith(ToolRegistry(LocalMemory(), scope="global"), isolation="container").build(spec)
    return {"registered": res.registered, "trust": res.trust.value if res.trust else None,
            "score": res.score, "reason": res.reason}


TOOLS: dict[str, dict[str, Any]] = {
    "verel_gate": {"fn": _tool_gate, "description": "Gate a list of verdict-bus Reports → verdict."},
    "verel_ci_check": {"fn": _tool_ci_check, "description": "Run the inner-loop CI stage on a repo."},
    "verel_recall": {"fn": _tool_recall, "description": "Recall records from a memory store."},
    "verel_build_tool": {"fn": _tool_build_tool,
                         "description": "Build+verify+register a tool (needs LLM key)."},
}


def dispatch(name: str, args: dict) -> dict:
    """Call a tool by name. Pure entry point used by both tests and the MCP binding."""
    if name not in TOOLS:
        raise KeyError(f"unknown tool {name!r}; known: {sorted(TOOLS)}")
    return TOOLS[name]["fn"](args or {})


def serve() -> None:  # pragma: no cover - requires the optional `mcp` extra + a host
    """Bind the dispatch layer to a real MCP stdio server (`pip install verel[mcp]`)."""
    import anyio
    import mcp.types as types
    from mcp.server import Server
    from mcp.server.stdio import stdio_server

    server = Server("verel")

    @server.list_tools()
    async def _list() -> list[types.Tool]:
        return [types.Tool(name=n, description=t["description"],
                           inputSchema={"type": "object"}) for n, t in TOOLS.items()]

    @server.call_tool()
    async def _call(name: str, arguments: dict) -> list[types.TextContent]:
        result = dispatch(name, arguments or {})
        return [types.TextContent(type="text", text=json.dumps(result))]

    async def _run():
        async with stdio_server() as (r, w):
            await server.run(r, w, server.create_initialization_options())

    anyio.run(_run)


def main() -> int:  # console entry point
    serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
