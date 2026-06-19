"""Cross-episode consolidation (§5.5 step 2b) — episodic failures -> a semantic DesignRule.

This is the genuine "episodic -> semantic" step: cluster recurring failures of the same
kind and ask an LLM (Ollama Cloud by default) to synthesize ONE reusable, generalized
DesignRule (e.g. "fixed-px widths on cards overflow narrow viewports; use max-width:100%").

Honesty (§5.5): the rule is written as `trust=candidate`. It earns `verified` ONLY through
corroboration or the held-out eval gate — never because an LLM asserted it. Consolidation is
offline for a mundane reason (batching cost/latency), NOT the neural replay rationale.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Callable

from ..agents import llm
from .view import MemoryKind, MemoryRecord, MemoryView, Trust

_WORD = re.compile(r"[a-z0-9-]+")

# A chat function: (messages) -> text. Injectable so tests run offline.
ChatFn = Callable[[list[dict]], str]

_SYSTEM = (
    "You are a memory-consolidation function. Given several episodic UI/eval failures of the "
    "same kind, output ONE generalized, reusable design rule that would prevent the whole "
    "cluster. Be specific and actionable. Respond as strict JSON: "
    '{"subject": "<component/pattern>", "rule": "<imperative one-liner>"}. No prose.'
)


def _default_chat(messages: list[dict]) -> str:
    return llm.chat(messages).content


def consolidate_failures(
    mem: MemoryView,
    *,
    scope: str = "repo:default",
    min_cluster: int = 2,
    chat: ChatFn | None = None,
    ts: float = 0.0,
) -> list[MemoryRecord]:
    """Cluster FAILURE records by kind within `scope`; synthesize a candidate DesignRule per
    cluster of size >= `min_cluster`. Returns the written DesignRule records."""
    chat = chat or _default_chat
    failures = list(mem.all(scope=scope, kind=MemoryKind.FAILURE))
    clusters: dict[str, list[MemoryRecord]] = defaultdict(list)
    for r in failures:
        clusters[r.detail.get("kind", "other")].append(r)

    written: list[MemoryRecord] = []
    for kind, group in clusters.items():
        if len(group) < min_cluster:
            continue
        examples = "\n".join(f"- {r.text}" for r in group[:8])
        reply = chat(
            [
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": f"Failure kind: {kind}\nExamples:\n{examples}"},
            ]
        )
        parsed = _parse(reply)
        if parsed is None:
            continue
        # keywords ground the rule's matcher for the held-out promotion eval (§7.7) — derived
        # from the induced rule text, not hand-set, so the gate tests what was actually induced.
        keywords = sorted({w for w in _WORD.findall(parsed["rule"].lower()) if len(w) > 3})[:12]
        rule = MemoryRecord(
            kind=MemoryKind.DESIGN_RULE,
            subject=parsed["subject"],
            predicate="design_rule",
            text=parsed["rule"],
            scope=scope,
            source="consolidation",
            provenance=[r.id for r in group],
            trust=Trust.CANDIDATE,  # NEVER auto-verified
            epistemic_confidence=0.5,
            support_count=len(group),
        ).with_detail(
            # §5.5: an induced rule starts `inferred` — its evidence is the CLUSTER, and it
            # cannot reach `corroborated`/`verified` without a held-out graded eval (§7.7).
            grounding="inferred",
            covers_kind=kind,
            keywords=keywords,
            from_kind=kind,
            cluster_size=len(group),
        )
        written.append(mem.write(rule, ts=ts))
    return written


def _parse(reply: str) -> dict | None:
    reply = reply.strip()
    start, end = reply.find("{"), reply.rfind("}")
    if start == -1 or end == -1:
        return None
    try:
        obj = json.loads(reply[start : end + 1])
    except json.JSONDecodeError:
        return None
    if "subject" in obj and "rule" in obj:
        return {"subject": str(obj["subject"]), "rule": str(obj["rule"])}
    return None
