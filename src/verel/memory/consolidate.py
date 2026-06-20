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
        # a record's natural category: a failure's `kind`, a design rule's `covers_kind`, else
        # the MemoryKind. This lets rules cluster by the failure family they cover, which is what
        # lets a higher level of schema induction find more than one cluster.
        cat = r.detail.get("kind") or r.detail.get("covers_kind") or r.kind.value
        buckets[str(cat)].append(r)
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
# Layer 3: DesignRules -> SCHEMA, and SCHEMA -> SCHEMA (multi-hop hierarchy).
# ---------------------------------------------------------------------------
def _sources_at(mem: MemoryView, scope: str, source_order: int) -> list[MemoryRecord]:
    """The records a schema of order `source_order + 1` is induced from: design rules for the
    first hop (source_order 1), else schemas of exactly `source_order`."""
    if source_order <= 1:
        return [r for r in mem.all(scope=scope, kind=MemoryKind.DESIGN_RULE)
                if r.detail.get("grounding") != "schema"]
    return [r for r in mem.all(scope=scope, kind=MemoryKind.SCHEMA)
            if int(r.detail.get("order", 2)) == source_order]


def _induce_level(mem: MemoryView, scope: str, *, source_order: int, min_size: int,
                  chat: ChatFn, semantic: bool, threshold: float, ts: float) -> list[MemoryRecord]:
    """Induce one schema level: cluster the order-`source_order` records and synthesize an
    order-`source_order+1` SCHEMA per cluster of size >= `min_size`."""
    sources = _sources_at(mem, scope, source_order)
    vof = _vector_of(mem) if semantic else None
    clusters = cluster_records(sources, vector_of=vof, threshold=threshold)
    target_order = source_order + 1

    written: list[MemoryRecord] = []
    for group in clusters:
        if len(group) < min_size:
            continue
        listing = "\n".join(f"- {r.subject}: {r.text}" for r in group[:10])
        parsed = _parse_schema(chat([
            {"role": "system", "content": _SCHEMA_SYSTEM},
            {"role": "user", "content": f"Related {'rules' if source_order <= 1 else 'principles'}:"
                                        f"\n{listing}"},
        ]))
        if parsed is None:
            continue
        schema = MemoryRecord(
            kind=MemoryKind.SCHEMA, subject=parsed["subject"], predicate="schema",
            text=parsed["principle"], scope=scope, source="consolidation",
            provenance=[r.id for r in group], trust=Trust.CANDIDATE,
            epistemic_confidence=0.5, support_count=len(group),
        ).with_detail(
            grounding="schema", order=target_order,
            keywords=_keywords(parsed["subject"], parsed["principle"]),
            subsumes=[r.id for r in group], cluster_size=len(group),
        )
        written.append(mem.write(schema, ts=ts))
    return written


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
    """Cluster DesignRules and induce one level of order-2 SCHEMAs (principles). Candidate +
    inferred — they earn trust the same way. `semantic=True` splits rules into themes."""
    return _induce_level(mem, scope, source_order=1, min_size=min_rules,
                         chat=chat or _default_chat, semantic=semantic,
                         threshold=cluster_threshold, ts=ts)


def induce_hierarchy(
    mem: MemoryView,
    *,
    scope: str = "repo:default",
    min_size: int = 2,
    max_order: int = 4,
    chat: ChatFn | None = None,
    semantic: bool = False,
    cluster_threshold: float = 0.55,
    ts: float = 0.0,
) -> dict[int, list[MemoryRecord]]:
    """Build a multi-hop schema hierarchy: rules → order-2 schemas → order-3 … until a level
    yields nothing new or `max_order` is reached. Returns {order: [schemas induced at that order]}.
    Each level consolidates the level below it, so the top is the most general principle the
    corpus supports. Every node stays `candidate` — height never confers trust."""
    chat = chat or _default_chat
    levels: dict[int, list[MemoryRecord]] = {}
    for order in range(2, max_order + 1):
        induced = _induce_level(mem, scope, source_order=order - 1, min_size=min_size,
                                chat=chat, semantic=semantic, threshold=cluster_threshold, ts=ts)
        if not induced:
            break  # the corpus doesn't support a higher level
        levels[order] = induced
    return levels


# ---------------------------------------------------------------------------
# Cross-scope consolidation — a pattern that recurs across repos becomes a global rule.
# ---------------------------------------------------------------------------
def consolidate_across_scopes(
    mem: MemoryView,
    scopes: list[str],
    *,
    target_scope: str = "global",
    min_scopes: int = 2,
    min_cluster: int = 2,
    chat: ChatFn | None = None,
    semantic: bool = False,
    cluster_threshold: float = 0.6,
    ts: float = 0.0,
) -> list[MemoryRecord]:
    """Gather FAILUREs across several `scopes`, cluster them, and induce a DesignRule in
    `target_scope` ONLY for clusters whose evidence spans >= `min_scopes` distinct scopes — a
    cross-cutting pattern (e.g. the same overflow bug in three repos), not a repo-local quirk. The
    rule records which scopes it generalizes (`detail['spans']`)."""
    chat = chat or _default_chat
    failures = [r for s in scopes for r in mem.all(scope=s, kind=MemoryKind.FAILURE)]
    clusters = cluster_records(failures, vector_of=_vector_of(mem) if semantic else None,
                               threshold=cluster_threshold)

    written: list[MemoryRecord] = []
    for group in clusters:
        spans = sorted({r.scope for r in group})
        if len(group) < min_cluster or len(spans) < min_scopes:
            continue  # not cross-cutting enough to generalize
        covers_kind = Counter(r.detail.get("kind", "other") for r in group).most_common(1)[0][0]
        examples = "\n".join(f"- ({r.scope}) {r.text}" for r in group[:8])
        parsed = _parse_rule(chat([
            {"role": "system", "content": _RULE_SYSTEM},
            {"role": "user", "content": f"Failure kind: {covers_kind} (seen across "
                                        f"{len(spans)} repos)\nExamples:\n{examples}"},
        ]))
        if parsed is None:
            continue
        text = (f"{parsed['condition']} → {parsed['action']}"
                if parsed["condition"] else parsed["action"])
        rule = MemoryRecord(
            kind=MemoryKind.DESIGN_RULE, subject=parsed["subject"], predicate="design_rule",
            text=text, scope=target_scope, source="consolidation",
            provenance=[r.id for r in group], trust=Trust.CANDIDATE,
            epistemic_confidence=0.5, support_count=len(group),
        ).with_detail(
            grounding="inferred", covers_kind=covers_kind,
            keywords=_keywords(parsed["condition"], parsed["action"]),
            condition=parsed["condition"], action=parsed["action"], applies_to=parsed["applies_to"],
            from_kind=covers_kind, cluster_size=len(group),
            spans=spans, cross_scope=True,  # generalizes across these scopes
        )
        written.append(mem.write(rule, ts=ts))
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
