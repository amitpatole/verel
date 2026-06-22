"""Verel MCP server — exposes the framework to any MCP host (Cursor/Claude Code/etc.), mirroring
AgentVision's surface strategy: the same capabilities, reachable cross-host.

The tool DISPATCH layer (`TOOLS`, `dispatch`) is pure and testable without the `mcp` package;
`serve()` binds it to a real MCP stdio server (the optional `verel[mcp]` extra). Hero verbs:

  verel_gate         RUN the graders on a repo → attested verdict + a verifiable receipt (§3/§4)
  verel_sight        render a URL → attested percept (bboxes + image_ref + receipt) — the eyes
  verel_verify       verify a receipt with NO trust in its producer (ed25519 = public; §11)
  verel_recall       read the shared verified brain (resolves DOWN the scope lattice)
  verel_remember     write to the shared brain — trust does NOT travel (candidate until attested)
  verel_ci_check     run the inner-loop CI stage on a repo → verdict + issues
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
# Bound attacker-controlled brain inputs so a single `remember`/`recall` can't balloon the store/memory.
_MAX_QUERY = 4_000
_MAX_TEXT = 20_000
_MAX_FIELD = 512


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


def _run_async(coro):
    """Run an async coroutine from the sync dispatch layer, whether or not a loop is already running
    (the MCP server binds an anyio loop; tests call dispatch directly)."""
    import asyncio

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)          # no loop in this thread → safe
    import concurrent.futures  # inside a running loop → run in a fresh worker thread
    with concurrent.futures.ThreadPoolExecutor(1) as ex:
        return ex.submit(lambda: asyncio.run(coro)).result()


def _bbox(locator: str | None) -> dict | None:
    """AgentVision serializes its pixel BBox into Issue.locator as JSON {x,y,width,height}."""
    if not locator:
        return None
    try:
        d = json.loads(locator)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(d, dict):
        return None
    return {"x": d.get("x"), "y": d.get("y"),
            "w": d.get("width", d.get("w")), "h": d.get("height", d.get("h"))}


def _tool_sight(args: dict) -> dict:
    """Give an agent EYES: render a URL and return an ATTESTED percept — grounded observations with
    pixel bboxes, an image_ref, intent conformance, and a verifiable receipt (§3/§4). Most agents are
    blind; this answers 'does it actually render / match what we set out to build?' — verifiably."""
    import hashlib

    url = args.get("url")
    if not url or not isinstance(url, str):
        return _err("url (string) is required")
    # STRICT: only a JSON boolean `true` disables the SSRF guard. `bool("false")` is True, so a
    # truthy non-bool (the string "false", 1, []) must NOT silently open localhost/LAN. Fail closed.
    allow_local = args.get("allow_local") is True
    scheme = url.split("://", 1)[0].lower() if "://" in url else ""
    if scheme not in ("http", "https"):
        # file://, gopher://, etc. are SSRF/LFI vectors — refuse at our layer too (defense in depth;
        # AgentVision also blocks file scheme + private networks by default).
        return _err("url must be http(s)")

    intent = args.get("intent")
    if intent is not None and not isinstance(intent, str):
        return _err("intent must be a string")
    backend = args.get("backend", "local")
    if not isinstance(backend, str):
        return _err("backend must be a string")
    attest, aerr = _resolve_attest(args.get("attest", "auto"))
    if aerr:
        return _err(aerr)

    overrides: dict = {}
    vp = args.get("viewport")
    if vp is not None:
        if not isinstance(vp, str) or "x" not in vp.lower():
            return _err("viewport must be like '1280x800'")
        try:
            w, h = (int(x) for x in vp.lower().split("x", 1))
        except ValueError:
            return _err("viewport must be like '1280x800'")
        overrides["default_viewport_width"], overrides["default_viewport_height"] = w, h

    from .senses.sight import perceive  # lazy module; AgentVision itself is imported at render time

    kwargs: dict = {}
    if intent:
        try:
            from agentvision import Brief
            kwargs["brief"] = Brief(text=intent)   # drives intent-conformance grading
        except ImportError:
            pass   # AgentVision absent → no conformance; the render below fails closed if it's real
    try:
        result = _run_async(perceive(url, backend=backend, allow_local=allow_local,
                                     settings_overrides=overrides, **kwargs))
    except ImportError:
        return _err("sight requires AgentVision — install it with `pip install verel[sight]`")

    from .verdict import build_gate_receipt, mint_report_receipt, verify_gate_receipt

    p = result.percept
    img = p.image_path
    img_bytes = b""
    if img and os.path.isfile(img):
        with open(img, "rb") as fh:
            img_bytes = fh.read()
    image_ref = "percept://" + hashlib.blake2s(img_bytes or url.encode()).hexdigest()[:16]
    # Bind the receipt to WHAT WAS SEEN: the screenshot bytes (falling back to the url) — so a percept
    # receipt can't be replayed onto a different render.
    suite_sha = hashlib.blake2s(f"sight:{url}:{backend}:{vp}".encode()).hexdigest()[:16]
    inputs_digest = hashlib.blake2s(img_bytes or url.encode()).hexdigest()[:16]
    for rep in result.reports:
        mint_report_receipt(rep, suite_sha=suite_sha, inputs_digest=inputs_digest,
                            coverage_assertion=f"rendered: {url}", attest=attest)
    # Bind the trust-implying percept facts (image_ref + intent conformance) INTO the signature, so a
    # relayed percept can't pair a valid receipt with a different image_ref or a flipped matches_intent.
    subject = (f"sight image_ref={image_ref} matches_intent={p.matches_intent} "
               f"intent={p.intent_satisfied}/{p.intent_total}")
    receipt = build_gate_receipt(p.verdict, result.reports, attest=attest, subject=subject)
    checked = verify_gate_receipt(receipt)

    return {
        "verdict": p.verdict.value,
        "summary": p.summary,
        "image_ref": image_ref,
        "image_path": img,
        "observations": [
            {"message": o.message, "bbox": _bbox(o.locator), "severity": o.severity.value,
             "source": o.source.value, "confidence": o.confidence.value,
             "precise": o.locator_precise, "fingerprint": o.fingerprint}
            for o in p.observations
        ],
        "matches_intent": p.matches_intent,
        "intent_satisfied": p.intent_satisfied,
        "intent_total": p.intent_total,
        "ceiling_clamped": receipt.ceiling_clamped,
        "attest": attest,
        "receipt_public_verifiable": checked.public_verifiable,
        "receipt": receipt.model_dump(mode="json"),
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
            # graders_checked==0 means VALID but advisory-only (nothing precise attested) — a consumer
            # wanting gated assurance must check it. `subject` carries the attested percept facts.
            return {"valid": res.valid, "verdict": res.verdict.value if res.verdict else None,
                    "graders_checked": res.graders_checked,
                    "public_verifiable": res.public_verifiable, "subject": res.subject,
                    "reason": res.reason}
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


def _config_dir() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "verel")


def _brain():
    """The shared verified brain — ONE persistent store per server (env VEREL_MEMORY_STORE, else
    ~/.config/verel/brain.db). Deliberately NOT agent-controllable: a tool arg can't repoint it at an
    arbitrary path (that would be arbitrary file read/write), and a fixed store is what lets a Cursor
    session, a Claude Code session, and a CI agent draw from the SAME brain."""
    from .memory import LocalMemory

    path = os.environ.get("VEREL_MEMORY_STORE") or os.path.join(_config_dir(), "brain.db")
    if path != ":memory:":
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    return LocalMemory(path)


def _evidence_verifies(evidence) -> tuple[bool, str]:
    """The importer's OWN check for `remember`: a fact becomes verified only if the caller attaches a
    receipt that actually VERIFIES (gate receipt or RunReceipt) — never on the caller's say-so. Returns
    (verified, reference). Reuses the hardened verify_receipt/verify_gate_receipt."""
    if not isinstance(evidence, dict):
        return False, ""
    from .verdict import GateReceipt, RunReceipt, verify_gate_receipt, verify_receipt

    try:
        if "graders" in evidence:
            r = verify_gate_receipt(GateReceipt.model_validate(evidence))
            return r.valid, (r.subject or "gate-receipt")
        v = verify_receipt(RunReceipt.model_validate(evidence))
        return v.valid, (v.runner_identity or "run-receipt")
    except (ValueError, TypeError):
        return False, ""


def _tool_recall(args: dict) -> dict:
    """Read the shared verified memory. Resolves DOWN the scope lattice (self < team < org < global;
    most specific wins) and surfaces trust/confidence/provenance so a caller can weight what it gets."""
    from .memory import MemoryKind, lattice_recall

    query = args.get("query")
    if not isinstance(query, str) or not query.strip():
        return _err("query (string) is required")
    if len(query) > _MAX_QUERY:
        return _err(f"query too long (max {_MAX_QUERY} chars)")
    scope = args.get("scope") if isinstance(args.get("scope"), str) else None
    k = args.get("k", 5)
    if not isinstance(k, int) or isinstance(k, bool) or k <= 0:
        return _err("k must be a positive integer")
    k = min(k, 100)   # bound the result set
    kind = None
    kraw = args.get("kind")
    if kraw is not None:
        if not isinstance(kraw, str):
            return _err("kind must be a string")
        try:
            kind = MemoryKind(kraw)
        except ValueError:
            return _err(f"unknown kind {kraw!r}")

    mem = _brain()
    hits = (lattice_recall(mem, query, scope=scope, kind=kind, k=k) if scope
            else mem.recall(query, kind=kind, k=k))
    return {"records": [
        {"text": h.text, "subject": h.subject, "predicate": h.predicate, "scope": h.scope,
         "trust": h.trust.value, "confidence": round(h.epistemic_confidence, 3),
         "support_count": h.support_count, "provenance": h.provenance, "fingerprint": h.id}
        for h in hits]}


def _tool_remember(args: dict) -> dict:
    """Write to the shared brain — trust does NOT travel. A claim enters as a CANDIDATE and only
    becomes VERIFIED by passing the importer's own check (a verifiable `evidence` receipt); the
    caller's self-asserted confidence is ignored, and AuthorTrust weights repeat contributors so one
    noisy agent can't poison the swarm."""
    from .memory import (
        AuthorTrust,
        MemoryKind,
        MemoryRecord,
        import_belief,
        make_id,
        make_key,
    )

    fact = args.get("fact")
    if not isinstance(fact, dict) or not isinstance(fact.get("text"), str) or not fact["text"].strip():
        return _err("fact.text (non-empty string) is required")
    if len(fact["text"]) > _MAX_TEXT:
        return _err(f"fact.text too long (max {_MAX_TEXT} chars)")
    scope = args.get("scope") or "team"
    if not isinstance(scope, str) or len(scope) > _MAX_FIELD:
        return _err("scope must be a string")
    author_raw = args.get("author")
    author = author_raw[:_MAX_FIELD] if isinstance(author_raw, str) else ""
    subject = str(fact.get("subject", ""))[:_MAX_FIELD]
    predicate = str(fact.get("predicate", ""))[:_MAX_FIELD]
    evidence = args.get("evidence")
    ev_ok, ev_ref = _evidence_verifies(evidence)

    provenance: list[str] = []
    if ev_ok:
        provenance.append(f"attested:{ev_ref}")
    elif isinstance(evidence, str) and evidence.strip():
        provenance.append(f"evidence:{evidence[:200]}")

    mem = _brain()
    claim = MemoryRecord(kind=MemoryKind.FACT, subject=subject, predicate=predicate,
                         text=fact["text"], scope=scope, provenance=provenance)
    # the importer's check IS the attestation check — trust does not travel.
    result = import_belief(mem, claim, verify=lambda _rec: ev_ok, author=author,
                           author_trust=AuthorTrust(mem))
    rec = mem.get(make_id(make_key(subject, predicate, scope)))
    return {"id": rec.id if rec else "", "trust": rec.trust.value if rec else "candidate",
            "reverified": result.reverified, "evidence_verified": ev_ok, "scope": scope,
            "author_prior": round(result.prior, 3), "reason": result.reason}


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
_SIGHT_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "http(s) URL to render and grade"},
        "intent": {"type": "string", "description": "what the UI should be — graded for conformance"},
        "viewport": {"type": "string", "description": "WxH, e.g. '1280x800'"},
        "backend": {"type": "string", "default": "local",
                    "description": "vision backend; 'local' = no-LLM structural checks (default)"},
        "allow_local": {"type": "boolean", "default": False,
                        "description": "EXPLICIT opt-in to render localhost/LAN (SSRF guard off)"},
        "attest": {"type": "string", "enum": list(_ATTEST), "default": "auto"},
    },
    "required": ["url"],
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
_RECALL_SCHEMA = {
    "type": "object",
    "properties": {
        "query": {"type": "string"},
        "scope": {"type": "string", "description": "resolve down from this scope (repo:x, team, global)"},
        "kind": {"type": "string", "enum": ["fact", "design_rule", "schema", "failure", "skill"]},
        "k": {"type": "integer", "default": 5},
    },
    "required": ["query"],
}
_REMEMBER_SCHEMA = {
    "type": "object",
    "properties": {
        "fact": {"type": "object", "description": "{subject, predicate, text} — text required",
                 "properties": {"subject": {"type": "string"}, "predicate": {"type": "string"},
                                "text": {"type": "string"}}, "required": ["text"]},
        "scope": {"type": "string", "default": "team"},
        "author": {"type": "string", "description": "contributing agent id — weights AuthorTrust"},
        "evidence": {"description": "a verifiable receipt (gate/run) that promotes the fact to "
                                    "verified, or a textual note (kept as provenance)"},
    },
    "required": ["fact"],
}
_OBJ = {"type": "object"}

TOOLS: dict[str, dict[str, Any]] = {
    "verel_gate": {"fn": _tool_gate, "schema": _GATE_SCHEMA,
                   "description": "Run graders on a repo → attested verdict + a verifiable receipt. "
                                  "The agent cannot self-declare done."},
    "verel_sight": {"fn": _tool_sight, "schema": _SIGHT_SCHEMA,
                    "description": "Render a URL and return an attested percept: grounded observations "
                                   "with pixel bboxes + an image_ref + a verifiable receipt."},
    "verel_verify": {"fn": _tool_verify, "schema": _VERIFY_SCHEMA,
                     "description": "Verify a receipt with no trust in its producer "
                                    "(ed25519 = publicly verifiable)."},
    "verel_ci_check": {"fn": _tool_ci_check, "schema": {"type": "object", "properties": {"repo": _REPO},
                       "required": ["repo"]}, "description": "Run the inner-loop CI stage on a repo."},
    "verel_recall": {"fn": _tool_recall, "schema": _RECALL_SCHEMA,
                     "description": "Read the shared verified brain (resolves down the scope lattice)."},
    "verel_remember": {"fn": _tool_remember, "schema": _REMEMBER_SCHEMA,
                       "description": "Write to the shared brain — trust does not travel; a fact is "
                                      "candidate until backed by a verifiable receipt."},
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
