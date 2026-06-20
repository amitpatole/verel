"""Contradiction-driven schema revision (§5.5) — consolidation that can be WRONG, and recovers.

Consolidation only ever GREW: corroborate a rule, climb it into a schema. But a generalization can
be falsified — a new failure lands squarely in a rule's domain that the rule was supposed to
prevent. That's a counterexample, and a memory that only grows is a memory that lies. This is the
contraction half:

  1. record the counterexample on the rule (`annotate`, no corroboration) and `contradict` it so
     its confidence falls;
  2. once enough counterexamples accumulate, ask the LLM to SPLIT the over-broad rule into a
     NARROWED general rule (which supersedes the original via the interference key) plus a specific
     EXCEPTION rule — both candidate + inferred, both earning trust the normal way;
  3. if confidence collapses (`contradict` drops it below the reject floor) the rule is REJECTED.

Revision only ever lowers trust or narrows scope — it never auto-verifies. The chat fn is
injectable so the whole module is tested offline.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

from ..agents import llm
from .view import MemoryKind, MemoryRecord, MemoryView, Trust, make_key

ChatFn = Callable[[list[dict]], str]

_REVISE_SYSTEM = (
    "A general design rule has met counterexamples — failures in its domain it did NOT prevent. "
    "Revise it: produce a NARROWED version of the rule that no longer over-claims, plus a specific "
    "EXCEPTION rule covering the counterexample case. Respond as strict JSON: "
    '{"narrowed": {"condition": "..", "action": "..", "applies_to": ".."}, '
    '"exception": {"subject": "..", "condition": "..", "action": "..", "applies_to": ".."}}. '
    "No prose."
)


def _default_chat(messages: list[dict]) -> str:
    return llm.chat(messages).content


@dataclass
class Revision:
    action: str  # "weakened" | "split" | "rejected"
    rule_id: str
    confidence: float
    trust: str
    narrowed: MemoryRecord | None = None
    exception: MemoryRecord | None = None


def contradicts(rule: MemoryRecord, failure: MemoryRecord) -> bool:
    """A failure is a counterexample to `rule` iff it falls in the rule's domain — same covered
    failure kind. The rule claimed to prevent this class of failure and didn't. Conservative: only
    a same-domain recurrence counts, never an unrelated failure."""
    rk = rule.detail.get("covers_kind") or rule.detail.get("from_kind")
    fk = failure.detail.get("kind")
    return rk is not None and fk is not None and rk == fk


def revise_with_counterexample(
    mem: MemoryView,
    rule: MemoryRecord,
    counterexample: MemoryRecord,
    *,
    chat: ChatFn | None = None,
    contradiction_delta: float = 0.2,
    split_after: int = 2,
    ts: float = 0.0,
) -> Revision:
    """Apply one counterexample to `rule`: record it, contradict the rule, and — once `split_after`
    counterexamples have accumulated — split the rule into a narrowed rule + an exception rule. The
    narrowed rule SUPERSEDES the original (same subject/predicate/scope key)."""
    chat = chat or _default_chat

    # 1) record the counterexample (audit, not corroboration) and weaken belief.
    seen = [*rule.detail.get("counterexamples", []),
            {"id": counterexample.id, "text": counterexample.text}]
    mem.annotate(rule.id, counterexamples=seen)
    weakened = mem.contradict(rule.id, delta=contradiction_delta)
    cur = weakened or mem.get(rule.id) or rule

    # 2) collapsed -> rejected (contradict already flips trust below its floor).
    if cur.trust == Trust.REJECTED:
        return Revision("rejected", rule.id, cur.epistemic_confidence, cur.trust.value)

    # 3) enough counterexamples -> split into narrowed + exception.
    if len(seen) >= split_after:
        parsed = _parse_split(chat([
            {"role": "system", "content": _REVISE_SYSTEM},
            {"role": "user", "content": _split_prompt(rule, seen)},
        ]))
        if parsed is not None:
            narrowed = _write_narrowed(mem, rule, parsed["narrowed"], counterexample, ts)
            exception = _write_exception(mem, rule, parsed["exception"], counterexample, ts)
            return Revision("split", rule.id, narrowed.epistemic_confidence,
                            narrowed.trust.value, narrowed=narrowed, exception=exception)

    return Revision("weakened", rule.id, cur.epistemic_confidence, cur.trust.value)


# ---------------------------------------------------------------------------
def _split_prompt(rule: MemoryRecord, seen: list[dict]) -> str:
    examples = "\n".join(f"- {c['text']}" for c in seen)
    return (f"Rule subject: {rule.subject}\n"
            f"Rule: when {rule.detail.get('condition', '')} → {rule.detail.get('action', rule.text)} "
            f"(applies to {rule.detail.get('applies_to', '')})\n"
            f"Counterexamples it failed to prevent:\n{examples}")


def _write_narrowed(mem: MemoryView, rule: MemoryRecord, n: dict, cx: MemoryRecord,
                    ts: float) -> MemoryRecord:
    text = f"{n['condition']} → {n['action']}" if n.get("condition") else n["action"]
    rec = MemoryRecord(
        kind=MemoryKind.DESIGN_RULE, subject=rule.subject, predicate="design_rule", text=text,
        scope=rule.scope, source="revision", provenance=[*rule.provenance, f"counterexample:{cx.id}"],
        trust=Trust.CANDIDATE, epistemic_confidence=0.5,
        subj_pred_key=rule.subj_pred_key,  # SUPERSEDE the over-broad original
    ).with_detail(
        grounding="inferred", covers_kind=rule.detail.get("covers_kind"),
        condition=n.get("condition", ""), action=n["action"], applies_to=n.get("applies_to", ""),
        revised_from=rule.id, revision="narrowed",
    )
    return mem.write(rec, ts=ts)


def _write_exception(mem: MemoryView, rule: MemoryRecord, e: dict, cx: MemoryRecord,
                     ts: float) -> MemoryRecord:
    subject = e.get("subject") or f"{rule.subject} (exception)"
    text = f"{e['condition']} → {e['action']}" if e.get("condition") else e["action"]
    scope = rule.scope
    rec = MemoryRecord(
        kind=MemoryKind.DESIGN_RULE, subject=subject, predicate="design_rule", text=text,
        scope=scope, source="revision", provenance=[f"counterexample:{cx.id}", f"exception_of:{rule.id}"],
        trust=Trust.CANDIDATE, epistemic_confidence=0.5,
        subj_pred_key=make_key(subject, "design_rule", scope),  # NEW record, not a supersede
    ).with_detail(
        grounding="inferred", covers_kind=rule.detail.get("covers_kind"),
        condition=e.get("condition", ""), action=e["action"], applies_to=e.get("applies_to", ""),
        exception_of=rule.id, revision="exception",
    )
    return mem.write(rec, ts=ts)


def _parse_split(reply: str) -> dict | None:
    reply = reply.strip()
    start, end = reply.find("{"), reply.rfind("}")
    if start == -1 or end == -1:
        return None
    try:
        obj = json.loads(reply[start:end + 1])
    except json.JSONDecodeError:
        return None
    n, e = obj.get("narrowed"), obj.get("exception")
    if not isinstance(n, dict) or not isinstance(e, dict) or "action" not in n or "action" not in e:
        return None
    return {"narrowed": n, "exception": e}
