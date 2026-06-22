"""Verel MCP server — exposes the framework to any MCP host (Cursor/Claude Code/etc.), mirroring
AgentVision's surface strategy: the same capabilities, reachable cross-host.

The tool DISPATCH layer (`TOOLS`, `dispatch`) is pure and testable without the `mcp` package;
`serve()` binds it to a real MCP stdio server (the optional `verel[mcp]` extra). Hero verbs:

  verel_gate         RUN the graders on a repo → attested verdict + a verifiable receipt (§3/§4)
  verel_verify       verify a receipt with NO trust in its producer (ed25519 = public; §11)
  verel_ci_check     run the inner-loop CI stage on a repo → verdict + issues
  verel_recall       recall from a memory store → records
  verel_build_tool   detect→scaffold→test→register a tool (needs an LLM key)

`gate` is the conscience: the agent can no longer self-declare "done" — it gets a real verdict with
grounded file:line issues AND a receipt a different party can check. That receipt is the wedge.
"""

from __future__ import annotations

import json
import os
from typing import Any

_STAGES = ("inner_loop", "pre_merge")
_ATTEST = ("auto", "ed25519", "hmac")


def _err(msg: str) -> dict:
    return {"error": msg}


def _resolve_attest(choice: str) -> tuple[str, str | None]:
    """Map the requested attest mode to a concrete scheme. 'auto' → ed25519 when verel[attest] is
    installed, else hmac. Explicit 'ed25519' FAILS CLOSED (returns an error) when unavailable rather
    than silently downgrading the public-verifiability guarantee."""
    from .verdict import keys

    if choice not in _ATTEST:
        return "", f"attest must be one of {_ATTEST}, got {choice!r}"
    if choice == "ed25519" and not keys.available():
        return "", "attest='ed25519' requested but PyNaCl is not installed (pip install verel[attest])"
    if choice == "hmac":
        return "hmac", None
    return ("ed25519" if keys.available() else "hmac"), None


def _issue_dict(i) -> dict:
    file, _, line = (i.locator or "").rpartition(":")
    return {"message": i.message, "file": file or (i.locator or ""), "line": line,
            "severity": i.severity.value, "source": i.source.value, "fingerprint": i.fingerprint}


def _tool_gate(args: dict) -> dict:
    """Give an agent a conscience: run the real graders on its repo and return an ATTESTED verdict.
    The agent cannot fake green — the receipt commits to what actually ran."""
    from .ci import inner_loop_stage, premerge_stage, run_stage
    from .verdict import build_gate_receipt, verify_gate_receipt

    repo = args.get("repo")
    if not repo or not isinstance(repo, str):
        return _err("repo (absolute path) is required")
    repo = os.path.abspath(repo)
    if not os.path.isdir(repo):
        return _err(f"repo is not a directory: {repo}")

    stage_name = args.get("stage", "inner_loop")
    if stage_name not in _STAGES:
        return _err(f"stage must be one of {_STAGES}, got {stage_name!r}")
    language = args.get("language", "python")
    if not isinstance(language, str):
        return _err("language must be a string")   # else `language not in LANGS` raises TypeError
    opts = args.get("options") or {}
    if not isinstance(opts, dict):
        return _err("options must be an object")
    attest, aerr = _resolve_attest(args.get("attest", "auto"))
    if aerr:
        return _err(aerr)
    diff_files = {f for f in (args.get("diff_files") or []) if isinstance(f, str)}

    try:
        if stage_name == "pre_merge":
            stage = premerge_stage(repo, language=language, with_types=opts.get("types", True),
                                   security=opts.get("security", False))
        else:
            stage = inner_loop_stage(repo, language=language, with_lint=opts.get("lint", True),
                                     with_types=opts.get("types", False))
    except ValueError as e:
        return _err(str(e))   # unknown language → fail closed with a clear message

    res = run_stage(stage, diff_files=diff_files, attest=attest)
    receipt = build_gate_receipt(res.verdict, res.reports, attest=attest)
    checked = verify_gate_receipt(receipt)   # dogfood: confirm the receipt we hand back verifies

    return {
        "verdict": res.verdict.value,
        "stage": stage.name,
        "reason": res.gate.reason,
        "reports": [
            {"grader": r.grader.value, "verdict": r.verdict.value,
             "issues": [_issue_dict(i) for i in r.issues]}
            for r in res.reports
        ],
        "ceiling_clamped": receipt.ceiling_clamped,
        "attest": attest,
        "receipt_public_verifiable": checked.public_verifiable,
        "receipt": receipt.model_dump(mode="json"),  # enums → strings, so json.dumps over MCP is safe
    }


def _tool_verify(args: dict) -> dict:
    """Verify a receipt with no trust in its producer. Accepts a gate-level receipt (has `graders`)
    or a single RunReceipt (has `suite_sha`). `require_public` rejects HMAC (demands ed25519)."""
    from .verdict import GateReceipt, RunReceipt, verify_gate_receipt, verify_receipt

    receipt = args.get("receipt")
    if not isinstance(receipt, dict):
        return _err("receipt (object) is required")
    allowed = {"ed25519"} if args.get("require_public") else None
    try:
        if "graders" in receipt:
            res = verify_gate_receipt(GateReceipt.model_validate(receipt), allowed_algs=allowed)
            return {"valid": res.valid, "verdict": res.verdict.value if res.verdict else None,
                    "graders_checked": res.graders_checked,
                    "public_verifiable": res.public_verifiable, "reason": res.reason}
        rv = verify_receipt(RunReceipt.model_validate(receipt), allowed_algs=allowed)
        return {"valid": rv.valid, "alg": rv.alg, "runner_identity": rv.runner_identity,
                "public_verifiable": rv.public_verifiable, "reason": rv.reason}
    except ValueError as e:
        return _err(f"malformed receipt: {e}")


def _tool_ci_check(args: dict) -> dict:
    from .ci import inner_loop_stage, run_stage

    repo = args.get("repo")
    if not repo or not isinstance(repo, str) or not os.path.isdir(os.path.abspath(repo)):
        return _err("repo (existing directory) is required")
    stage = inner_loop_stage(os.path.abspath(repo), with_lint=args.get("lint", False))
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

    query = args.get("query")
    if not isinstance(query, str):
        return _err("query (string) is required")
    mem = LocalMemory(args.get("store", ":memory:"))
    hits = mem.recall(query, scope=args.get("scope"), k=args.get("k", 5))
    return {"records": [{"subject": h.subject, "text": h.text, "trust": h.trust.value,
                         "scope": h.scope} for h in hits]}


def _tool_build_tool(args: dict) -> dict:
    from .memory import LocalMemory
    from .toolsmith import SideEffect, ToolCase, ToolRegistry, ToolSmith, ToolSpec

    if not isinstance(args.get("name"), str) or not isinstance(args.get("capability"), str):
        return _err("name and capability (strings) are required")
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


# ---- JSON Schemas so MCP hosts present real arguments to agents ----
_REPO = {"type": "string", "description": "absolute path to the repo"}
_GATE_SCHEMA = {
    "type": "object",
    "properties": {
        "repo": _REPO,
        "stage": {"type": "string", "enum": list(_STAGES), "default": "inner_loop"},
        "language": {"type": "string", "enum": ["python", "js", "go"], "default": "python"},
        "diff_files": {"type": "array", "items": {"type": "string"},
                       "description": "changed files; a grader must cover at least one"},
        "options": {"type": "object", "description": "lint/types/security toggles"},
        "attest": {"type": "string", "enum": list(_ATTEST), "default": "auto",
                   "description": "auto: ed25519 if available else hmac; ed25519 fails closed if absent"},
    },
    "required": ["repo"],
}
_VERIFY_SCHEMA = {
    "type": "object",
    "properties": {
        "receipt": {"type": "object", "description": "a gate receipt (has 'graders') or a RunReceipt"},
        "require_public": {"type": "boolean", "default": False,
                           "description": "reject HMAC; require ed25519 public verifiability"},
    },
    "required": ["receipt"],
}
_OBJ = {"type": "object"}

TOOLS: dict[str, dict[str, Any]] = {
    "verel_gate": {"fn": _tool_gate, "schema": _GATE_SCHEMA,
                   "description": "Run graders on a repo → attested verdict + a verifiable receipt. "
                                  "The agent cannot self-declare done."},
    "verel_verify": {"fn": _tool_verify, "schema": _VERIFY_SCHEMA,
                     "description": "Verify a receipt with no trust in its producer "
                                    "(ed25519 = publicly verifiable)."},
    "verel_ci_check": {"fn": _tool_ci_check, "schema": {"type": "object", "properties": {"repo": _REPO},
                       "required": ["repo"]}, "description": "Run the inner-loop CI stage on a repo."},
    "verel_recall": {"fn": _tool_recall, "schema": _OBJ,
                     "description": "Recall records from a memory store."},
    "verel_build_tool": {"fn": _tool_build_tool, "schema": _OBJ,
                         "description": "Build+verify+register a tool (needs LLM key)."},
}


def dispatch(name: str, args: dict) -> dict:
    """Call a tool by name. Pure entry point used by both tests and the MCP binding. NEVER raises:
    the dispatch boundary is the MCP host connection, so an unknown tool or any unhandled tool
    exception becomes a structured {"error": ...} rather than a crash. The error names only the tool
    and the exception TYPE — never str(e) — so a stray exception can't leak a path/secret."""
    if name not in TOOLS:
        return _err(f"unknown tool {name!r}; known: {sorted(TOOLS)}")
    try:
        return TOOLS[name]["fn"](args or {})
    except Exception as e:  # host-boundary backstop — a tool bug must not kill the connection
        return _err(f"{name} failed: {type(e).__name__}")


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
                           inputSchema=t.get("schema", _OBJ)) for n, t in TOOLS.items()]

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
