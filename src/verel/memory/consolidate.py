"""Cross-episode consolidation (§5.5 step 2b) — episodic failures -> semantic rules -> schemas.

Three layers, each writing `trust=candidate` (NEVER auto-verified — a rule earns `verified` only
through corroboration or the held-out eval gate, §7.7):

1. **Cluster** recurring failures. Semantically when the memory has an embedder (so "panel runs
   off screen" and "card overflows viewport" land together despite no shared words); otherwise by
   the coarse `detail['kind']` label.
2. **Induce a structured DesignRule** per cluster: not just a one-liner but `{condition, action,
   applies_to}` slots, so the rule's matcher and the held-out gate test something specific.
3. **Induce a SCHEMA** (2nd order): cluster the DesignRules themselves and synthesize a higher
   level principle that subsumes a family of rules.

Consolidation is offline for a mundane reason (batching cost/latency), NOT a neural-replay story.
The LLM is Ollama Cloud by default (OpenAI fallback via `verel.agents.llm`); the chat fn is
injectable so the whole module is tested offline.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from collections.abc import Callable

from ..agents import llm
from .embed import cosine
from .view import MemoryKind, MemoryRecord, MemoryView, Trust

_WORD = re.compile(r"[a-z0-9-]+")

# A chat function: (messages) -> text. Injectable so tests run offline.
ChatFn = Callable[[list[dict]], str]
# A vector lookup for a record (returns its dense embedding or None). Enables semantic clustering.
VectorOf = Callable[[MemoryRecord], "list[float] | None"]

_RULE_SYSTEM = (
    "You are a memory-consolidation function. Given several episodic UI/eval failures of the "
    "same kind, induce ONE generalized, reusable design rule that would prevent the whole "
    "cluster. Respond as strict JSON with exactly these fields: "
    '{"subject": "<component/pattern>", "condition": "<when this happens>", '
    '"action": "<do this to prevent it>", "applies_to": "<where it applies>"}. '
    "Be specific and imperative. No prose, no markdown."
)
_SCHEMA_SYSTEM = (
    "You are a schema-induction function. Given several specific design rules that seem related, "
    "induce ONE higher-level principle that subsumes them — the general schema they are all "
    "instances of. Respond as strict JSON: "
    '{"subject": "<the general pattern>", "principle": "<one imperative sentence>"}. No prose.'
)


def _default_chat(messages: list[dict]) -> str:
    return llm.chat(messages).content


# ---------------------------------------------------------------------------
# Clustering.
# ---------------------------------------------------------------------------
def _subcluster(members: list[MemoryRecord], vector_of: VectorOf,
                threshold: float) -> list[list[MemoryRecord]]:
    """Greedy single-link agglomeration by cosine ≥ threshold (a record joins the first cluster
    it's close enough to, else starts its own). Order-stable."""
    clusters: list[tuple[list[list[float]], list[MemoryRecord]]] = []
    for r in members:
        v = vector_of(r)
        if not v:
            clusters.append(([], [r]))
            continue
        best: tuple[list[list[float]], list[MemoryRecord]] | None = None
        best_sim = threshold
        for c in clusters:
            sim = max((cosine(v, cv) for cv in c[0] if cv), default=0.0)
            if sim >= best_sim:
                best, best_sim = c, sim
        if best is None:
            clusters.append(([v], [r]))
        else:
            best[0].append(v)
            best[1].append(r)
    return [members for _, members in clusters]


def cluster_records(records: list[MemoryRecord], *, vector_of: VectorOf | None = None,
                    threshold: float = 0.6) -> list[list[MemoryRecord]]:
    """Group related records. ALWAYS buckets by the coarse `detail['kind']` label first (a strong
    prior the failure-ledger already provides) so distinct kinds never merge; then, when
    `vector_of` is given, refines each bucket by MEANING (cosine ≥ threshold) — so a kind can split
    into finer sub-patterns but two kinds never collapse together. Order-stable."""
    buckets: dict[str, list[MemoryRecord]] = defaultdict(list)
    for r in records:
        buckets[str(r.detail.get("kind", r.kind.value))].append(r)
    if vector_of is None:
        return list(buckets.values())
    out: list[list[MemoryRecord]] = []
    for members in buckets.values():
        out.extend(_subcluster(members, vector_of, threshold))
    return out


def _vector_of(mem: MemoryView) -> VectorOf | None:
    """Build a vector lookup from a backend that stores embeddings, else None (lexical fallback)."""
    emb = getattr(mem, "embedder", None)
    getv = getattr(mem, "_get_vector", None)
    if emb is None or getv is None:
        return None
    return lambda r: getv(r.id)


def _keywords(*texts: str) -> list[str]:
    blob = " ".join(texts).lower()
    return sorted({w for w in _WORD.findall(blob) if len(w) > 3})[:12]


# ---------------------------------------------------------------------------
# Layer 1+2: failures -> structured DesignRules.
# ---------------------------------------------------------------------------
def consolidate_failures(
    mem: MemoryView,
    *,
    scope: str = "repo:default",
    min_cluster: int = 2,
    chat: ChatFn | None = None,
    semantic: bool = False,
    cluster_threshold: float = 0.6,
    ts: float = 0.0,
) -> list[MemoryRecord]:
    """Cluster FAILURE records within `scope` and synthesize a candidate, structured DesignRule
    per cluster of size >= `min_cluster`. `semantic=True` refines each failure-kind bucket by
    meaning (needs a backend with a real embedder); the default clusters by kind, deterministically."""
    chat = chat or _default_chat
    failures = list(mem.all(scope=scope, kind=MemoryKind.FAILURE))
    vof = _vector_of(mem) if semantic else None
    clusters = cluster_records(failures, vector_of=vof, threshold=cluster_threshold)

    written: list[MemoryRecord] = []
    for group in clusters:
        if len(group) < min_cluster:
            continue
        # the cluster's dominant failure kind labels the rule (covers_kind), even if mixed.
        covers_kind = Counter(r.detail.get("kind", "other") for r in group).most_common(1)[0][0]
        examples = "\n".join(f"- {r.text}" for r in group[:8])
        parsed = _parse_rule(chat([
            {"role": "system", "content": _RULE_SYSTEM},
            {"role": "user", "content": f"Failure kind: {covers_kind}\nExamples:\n{examples}"},
        ]))
        if parsed is None:
            continue
        text = (f"{parsed['condition']} → {parsed['action']}"
                if parsed["condition"] else parsed["action"])
        rule = MemoryRecord(
            kind=MemoryKind.DESIGN_RULE,
            subject=parsed["subject"],
            predicate="design_rule",
            text=text,
            scope=scope,
            source="consolidation",
            provenance=[r.id for r in group],
            trust=Trust.CANDIDATE,  # NEVER auto-verified
            epistemic_confidence=0.5,
            support_count=len(group),
        ).with_detail(
            grounding="inferred",  # evidence is the CLUSTER; needs a held-out graded eval (§7.7)
            covers_kind=covers_kind,
            keywords=_keywords(parsed["condition"], parsed["action"]),
            condition=parsed["condition"],
            action=parsed["action"],
            applies_to=parsed["applies_to"],
            from_kind=covers_kind,
            cluster_size=len(group),
        )
        written.append(mem.write(rule, ts=ts))
    return written


# ---------------------------------------------------------------------------
# Layer 3: DesignRules -> SCHEMA (2nd-order induction).
# ---------------------------------------------------------------------------
def induce_schemas(
    mem: MemoryView,
    *,
    scope: str = "repo:default",
    min_rules: int = 3,
    chat: ChatFn | None = None,
    semantic: bool = False,
    cluster_threshold: float = 0.55,
    ts: float = 0.0,
) -> list[MemoryRecord]:
    """Cluster existing DesignRules and induce a higher-level SCHEMA (principle) per cluster of
    size >= `min_rules`. Schemas are candidate + inferred — they earn trust the same way.
    `semantic=True` splits the rules into themes (needs a real embedder); the default treats all
    of a scope's rules as one cluster and induces one overarching principle."""
    chat = chat or _default_chat
    rules = [r for r in mem.all(scope=scope, kind=MemoryKind.DESIGN_RULE)
             if r.detail.get("grounding") != "schema"]  # never re-consolidate a schema
    vof = _vector_of(mem) if semantic else None
    clusters = cluster_records(rules, vector_of=vof, threshold=cluster_threshold)

    written: list[MemoryRecord] = []
    for group in clusters:
        if len(group) < min_rules:
            continue
        listing = "\n".join(f"- {r.subject}: {r.text}" for r in group[:10])
        parsed = _parse_schema(chat([
            {"role": "system", "content": _SCHEMA_SYSTEM},
            {"role": "user", "content": f"Related design rules:\n{listing}"},
        ]))
        if parsed is None:
            continue
        schema = MemoryRecord(
            kind=MemoryKind.SCHEMA,
            subject=parsed["subject"],
            predicate="schema",
            text=parsed["principle"],
            scope=scope,
            source="consolidation",
            provenance=[r.id for r in group],
            trust=Trust.CANDIDATE,
            epistemic_confidence=0.5,
            support_count=len(group),
        ).with_detail(
            grounding="schema",  # 2nd-order; guards against re-consolidating schemas
            order=2,
            keywords=_keywords(parsed["subject"], parsed["principle"]),
            subsumes=[r.id for r in group],
            cluster_size=len(group),
        )
        written.append(mem.write(schema, ts=ts))
    return written


# ---------------------------------------------------------------------------
# Parsers (tolerant: accept the structured schema, fall back to the old {subject, rule}).
# ---------------------------------------------------------------------------
def _loads(reply: str) -> dict | None:
    reply = reply.strip()
    start, end = reply.find("{"), reply.rfind("}")
    if start == -1 or end == -1:
        return None
    try:
        obj = json.loads(reply[start:end + 1])
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def _parse_rule(reply: str) -> dict | None:
    obj = _loads(reply)
    if obj is None or "subject" not in obj:
        return None
    if "action" in obj:  # structured form
        return {"subject": str(obj["subject"]), "condition": str(obj.get("condition", "")),
                "action": str(obj["action"]), "applies_to": str(obj.get("applies_to", ""))}
    if "rule" in obj:  # back-compat flat form
        return {"subject": str(obj["subject"]), "condition": "",
                "action": str(obj["rule"]), "applies_to": ""}
    return None


def _parse_schema(reply: str) -> dict | None:
    obj = _loads(reply)
    if obj is None or "subject" not in obj or "principle" not in obj:
        return None
    return {"subject": str(obj["subject"]), "principle": str(obj["principle"])}
