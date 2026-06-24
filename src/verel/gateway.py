"""Action gateway — gate the boundary, not just the loop (the "Reach" capstone, G).

The agent calls its normal tools (`write_file`, `create_pr`, `deploy`, `delete_*`); this sits in
front and **gates the consequential ones**: a verdict decides whether an action forwards, and an
irreversible action is dry-run by default and requires explicit human approval. The agent needn't
know the gateway exists.

This is enforcement that will eventually be `immel` (boundary/policy) and `actel` (act-then-verify).
It is built here now, but behind a **clean three-layer seam** so it lifts out later as a package move,
not a rewrite:

  * **verdict**  — *decide*: classify the action and (for consequential ones) gate the artifact.
  * **enforce**  — *forward / block / dry-run / require-approval / rollback*: the policy decision.
  * **adapters** — the actual tool invocation (`invoke`) and approval channel (`approve`), injected.

Non-negotiables (the actel/immel rules), honored from day one:
  * **Fail closed** — an unclassifiable action, a missing gate, or a denied tool does NOT forward.
  * **Dry-run by default** for irreversible/destructive actions; **human approval** required to apply.
  * Never auto-apply a destructive op on advisory evidence.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum


class ActionClass(str, Enum):
    SAFE = "safe"                  # read-only — forward immediately
    CONSEQUENTIAL = "consequential"  # writes an artifact — gate it before forwarding
    IRREVERSIBLE = "irreversible"  # destructive / outward-facing — dry-run + human approval


class Decision(str, Enum):
    FORWARD = "forward"
    BLOCKED = "blocked"          # gate FAIL or denied → not performed
    DRY_RUN = "dry_run"          # irreversible, no approval → planned but not performed
    NEEDS_APPROVAL = "needs_approval"


# Verb sets matched against the tool name's WORD TOKENS (snake_case / kebab / camelCase split), so
# `delete_branch` → {delete, branch} hits `delete`, but `get_information` → {get, information} does NOT
# falsely hit `format`. Irreversible wins over consequential wins over safe. Operators extend via Policy.
_IRREVERSIBLE_VERBS = {"delete", "destroy", "drop", "deploy", "release", "publish", "push", "rm",
                       "remove", "revoke", "terminate", "shutdown", "wipe", "truncate", "merge",
                       "force", "purge", "evict", "flush", "format", "unlink", "reset", "disable",
                       "expire", "clear", "kill", "prune", "overwrite", "rollback"}
_CONSEQUENTIAL_VERBS = {"write", "create", "update", "edit", "commit", "set", "put", "patch", "apply",
                        "insert", "upsert", "rename", "move", "mkdir", "save", "add", "modify"}
_SAFE_VERBS = {"read", "list", "get", "search", "fetch", "view", "show", "query", "status",
               "describe", "inspect", "diff", "find", "count", "head"}


def _tokens(name: str) -> set[str]:
    """Word tokens of a tool name, lowercased — splits snake_case, kebab-case, dots, and camelCase
    (`deployToProd` → {deploy, to, prod}; `delete_branch` → {delete, branch})."""
    return {m.group(0).lower() for m in re.finditer(r"[A-Z]+(?![a-z])|[A-Za-z][a-z0-9]*", name)}


@dataclass
class Policy:
    """What the gateway allows. `deny` always wins (fail closed); `allow` (if non-empty) is an
    allowlist. `dry_run` (default True) means irreversible actions are never applied without explicit
    `approve`. `auto_consequential` lets safe-classified writes through without an artifact gate."""
    allow: set[str] = field(default_factory=set)        # if non-empty: only these tools may run
    deny: set[str] = field(default_factory=set)         # never run these (wins over allow)
    dry_run: bool = True                                # irreversible → planned, not applied
    overrides: dict[str, ActionClass] = field(default_factory=dict)  # force a tool's class

    def classify(self, tool: str) -> ActionClass:
        # SAFE is the only class that forwards UNGATED, and it's a name HEURISTIC — for an untrusted
        # tool set, set `allow` so an unexpected name can't auto-forward, and/or add `overrides`.
        if tool in self.overrides:
            return self.overrides[tool]
        toks = _tokens(tool)
        if toks & _IRREVERSIBLE_VERBS:
            return ActionClass.IRREVERSIBLE
        if toks & _CONSEQUENTIAL_VERBS:
            return ActionClass.CONSEQUENTIAL
        if toks & _SAFE_VERBS:
            return ActionClass.SAFE
        # Unknown shape → treat as consequential (fail closed: don't assume read-only).
        return ActionClass.CONSEQUENTIAL

    def permitted(self, tool: str) -> bool:
        if tool in self.deny:
            return False
        return not self.allow or tool in self.allow


@dataclass
class GatewayResult:
    decision: Decision
    tool: str
    action_class: ActionClass
    reason: str
    result: object = None          # the downstream tool's result, when forwarded
    verdict: dict | None = None    # the gate verdict, when an artifact was gated


# Injected adapters (the seam): `invoke(tool, args)->result`; `gate(tool, args)->verdict-dict` (a
# verdict has a "verdict" key in {"pass","warn","fail"}); `approve(tool, args)->bool` for irreversible.
InvokeFn = Callable[[str, dict], object]
GateFn = Callable[[str, dict], dict]
ApproveFn = Callable[[str, dict], bool]


class Gateway:
    """Front a set of tools with the gate. `invoke` performs the real action; `gate` (optional)
    returns a verdict for a consequential action's artifact; `approve` (optional) is the human channel
    for irreversible actions. With neither gate nor approve, the gateway still fails closed."""

    def __init__(self, invoke: InvokeFn, *, policy: Policy | None = None,
                 gate: GateFn | None = None, approve: ApproveFn | None = None):
        self._invoke = invoke
        self.policy = policy or Policy()
        self._gate = gate
        self._approve = approve

    def handle(self, tool: str, args: dict | None = None) -> GatewayResult:
        args = args or {}
        cls = self.policy.classify(tool)
        if not self.policy.permitted(tool):
            return GatewayResult(Decision.BLOCKED, tool, cls, "tool denied by policy")

        if cls is ActionClass.SAFE:
            return GatewayResult(Decision.FORWARD, tool, cls, "safe (read-only)",
                                 result=self._invoke(tool, args))

        if cls is ActionClass.CONSEQUENTIAL:
            if self._gate is None:
                # No way to verify the artifact → fail closed (don't forward an unverified write).
                return GatewayResult(Decision.BLOCKED, tool, cls,
                                     "no gate configured to verify this consequential action")
            try:
                verdict = self._gate(tool, args)
            except Exception as e:  # a crashing gate is missing evidence → fail closed, don't crash
                return GatewayResult(Decision.BLOCKED, tool, cls,
                                     f"gate errored ({type(e).__name__}) — action refused")
            v = verdict.get("verdict") if isinstance(verdict, dict) else None
            # PASS is the ONLY token that forwards. warn/error/missing/None/malformed are NOT a pass —
            # they're advisory or missing evidence, and the house rule is fail-closed on both.
            if not isinstance(v, str) or v.strip().lower() != "pass":
                return GatewayResult(Decision.BLOCKED, tool, cls,
                                     f"gate did not PASS ({v!r}) — action refused",
                                     verdict=verdict if isinstance(verdict, dict) else None)
            return GatewayResult(Decision.FORWARD, tool, cls, "gate passed",
                                 result=self._invoke(tool, args), verdict=verdict)

        # IRREVERSIBLE: dry-run by default; apply only on explicit human approval. Never auto-apply.
        approved = bool(self._approve and self._approve(tool, args))
        if self.policy.dry_run and not approved:
            return GatewayResult(Decision.DRY_RUN, tool, cls,
                                 "irreversible — dry-run; requires human approval to apply")
        if not approved:
            return GatewayResult(Decision.NEEDS_APPROVAL, tool, cls,
                                 "irreversible — human approval required")
        return GatewayResult(Decision.FORWARD, tool, cls, "irreversible — approved by human",
                             result=self._invoke(tool, args))


def repo_gate(repo: str = ".") -> GateFn:
    """A ready-made `gate` adapter that runs the Verel CI gate on `repo` and returns its verdict — so
    a consequential action only forwards when the repo currently passes. NOTE: this is a
    *pre-condition* gate (is the repo green BEFORE the action?), not an artifact-level check of what
    the action produces — verifying the post-action world is `actel`'s act-then-verify job."""
    def _gate(_tool: str, _args: dict) -> dict:
        from .mcp_server import dispatch
        return dispatch("verel_ci_check", {"repo": repo, "lint": True})
    return _gate
