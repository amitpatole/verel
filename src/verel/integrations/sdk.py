"""Agent-SDK shims (the "Reach" track, R3) — one hook into any framework's done-step.

Verel grades artifacts, so the integration is the same everywhere: give the agent a *tool* that runs
the gate and reads the verdict before it declares "done". This module ships the framework-agnostic
pieces — a plain `gate()` callable, the function-calling tool *schemas* in OpenAI and Anthropic shape,
and a dispatcher — so it works with **OpenAI Assistants / function calling, the Anthropic SDK, the
Claude Agent SDK, LangGraph/LangChain, CrewAI, AutoGen** and anything that accepts a Python callable
or a tool schema. No heavy SDK is imported here (zero new deps); the docs show the 1-line wiring per
framework, and `langchain_tools()` lazily adapts to LangChain when it's installed.
"""

from __future__ import annotations

import json


def gate(repo: str = ".", *, criteria: str | None = None, files: list[str] | None = None,
         lint: bool = True) -> dict:
    """Run the Verel gate on `repo` and return the verdict the agent should read before "done".

    Runs the CI gate (tests + lint + types). If `criteria` (the ticket / acceptance text) is given,
    ALSO runs the spec/intent grader and folds it in. Returns
    `{"verdict": pass|warn|fail, "issues": [...], ...}` — treat the work as done only on `pass`.
    """
    from ..mcp_server import dispatch
    ci = dispatch("verel_ci_check", {"repo": repo, "lint": lint})
    out: dict = {"verdict": ci.get("verdict", "fail"), "issues": ci.get("issues", []), "ci": ci}
    if criteria:
        spec = dispatch("verel_spec", {"repo": repo, "criteria": criteria, "files": files or []})
        out["spec"] = spec
        # The combined verdict is the worst of the two (fail > warn > pass).
        order = {"pass": 0, "warn": 1, "fail": 2}
        worst = max(out["verdict"], spec.get("verdict", "pass"), key=lambda v: order.get(v, 2))
        out["verdict"] = worst
        out["issues"] = out["issues"] + spec.get("issues", [])
    return out


# The function-calling schema for the gate tool — parameters as JSON Schema, shared by both shapes.
_GATE_PARAMS = {
    "type": "object",
    "properties": {
        "repo": {"type": "string", "description": "path to the repo to gate (default '.')"},
        "criteria": {"type": "string",
                     "description": "optional: ticket / acceptance-criteria text to check the diff against"},
        "files": {"type": "array", "items": {"type": "string"},
                  "description": "optional: changed source files (for the spec check)"},
    },
    "required": [],
}
_GATE_DESC = ("Verify the work with Verel before declaring it done: runs tests + lint + types (and, "
              "with `criteria`, checks the diff against the ticket's intent). Treat the task complete "
              "ONLY when verdict == 'pass'; on 'fail', fix the root cause and call again.")


def openai_tools() -> list[dict]:
    """The gate as an OpenAI function-calling tool (also works with most OpenAI-compatible APIs)."""
    return [{"type": "function", "function": {
        "name": "verel_gate", "description": _GATE_DESC, "parameters": _GATE_PARAMS}}]


def anthropic_tools() -> list[dict]:
    """The gate as an Anthropic (Claude) tool-use definition."""
    return [{"name": "verel_gate", "description": _GATE_DESC, "input_schema": _GATE_PARAMS}]


def run_tool_call(name: str, arguments: str | dict) -> dict:
    """Execute a tool call emitted by any of the schemas above. `arguments` is the model's JSON (str
    or already-parsed dict). Unknown tools return an error dict rather than raising."""
    if name != "verel_gate":
        return {"error": f"unknown tool {name!r}"}
    args = json.loads(arguments) if isinstance(arguments, str) else (arguments or {})
    if not isinstance(args, dict):
        return {"error": "arguments must be a JSON object"}
    return gate(args.get("repo", "."), criteria=args.get("criteria"), files=args.get("files"),
                lint=bool(args.get("lint", True)))


def langchain_tools() -> list:
    """The gate as a LangChain/LangGraph `StructuredTool` (lazy — needs `langchain_core`)."""
    try:
        from langchain_core.tools import StructuredTool
    except ImportError as e:  # pragma: no cover - optional dep
        raise ImportError("langchain_tools() needs langchain — `pip install langchain-core`") from e
    return [StructuredTool.from_function(
        func=gate, name="verel_gate", description=_GATE_DESC)]  # pragma: no cover - needs the dep
