"""Operator review — the human-in-the-loop workflow that resolves CANDIDATE facts.

A fact enters memory as CANDIDATE and normally earns VERIFIED through the attested promotion gate
(promotion.py) or multi-principal corroboration (remember.py). This module adds the third path the
trust model names but never surfaced: a HUMAN reviews the pending candidates and decides.

Deliberate security posture:
- **CLI-only by design.** Review is exposed via `verel memory ...` (a human at a terminal), NOT over
  MCP — an agent must never be able to approve its own candidate facts. The agent-facing surface
  (`verel_remember`/`verel_recall`) stays read/write of candidates only.
- **Approve never launders.** `approve()` refuses a REJECTED record: the rejected-value ledger exists
  precisely so a once-rejected value can't come back; a human wanting to resurrect one must write it
  as a NEW fact and let the gate see the ledger.
- **Reject rides the existing tombstone path.** `reject()` drives the backend's own contradict →
  REJECTED transition (ec floor + `rejected_values` ledger), so the durable anti-laundering behaviour
  is identical across every backend — no second rejection mechanism to drift.
- **Terminal-safe rendering.** Everything shown to the operator passes `view.canonical_text`, so a
  stored fact can't smuggle ANSI/control/zero-width sequences into the review terminal and spoof
  what is being approved.
"""

from __future__ import annotations

import time

from .view import MemoryKind, MemoryRecord, MemoryView, Trust, canonical_text, rejected_key

_MAX_LIMIT = 500
_MAX_REASON = 200
_MAX_REVIEWER = 120


class RejectedApprovalError(ValueError):
    """Raised when approve() is asked to promote a REJECTED record (anti-laundering, round-7 C1)."""


def pending(mem: MemoryView, *, scope: str | None = None, kind: MemoryKind | None = None,
            limit: int = 50) -> list[MemoryRecord]:
    """CANDIDATE facts awaiting review — most-corroborated first, then oldest first.

    Ordering is a review queue, not a ranking: high-support candidates are the ones agents keep
    re-asserting (decide them first); ties go to the oldest so nothing starves at the tail."""
    limit = max(1, min(int(limit), _MAX_LIMIT))
    recs = [r for r in mem.all(scope=scope, kind=kind) if r.trust == Trust.CANDIDATE]
    recs.sort(key=lambda r: (-r.support_count, r.created_ts))
    return recs[:limit]


def approve(mem: MemoryView, record_id: str, *, reviewed_by: str) -> MemoryRecord | None:
    """Promote a CANDIDATE to VERIFIED on human authority, recording who and when.

    Returns the updated record, or None when `record_id` doesn't exist. Raises
    `RejectedApprovalError` for a REJECTED record — approval must not bypass the rejected-value
    ledger (write the value as a new fact instead; the promotion gate consults the ledger)."""
    r = mem.get(record_id)
    if r is None:
        return None
    if r.trust == Trust.REJECTED:
        raise RejectedApprovalError(
            f"record {record_id} is REJECTED — approving it would launder a rejected value past "
            "the tombstone ledger. If it is genuinely correct now, write it as a new fact.")
    if rejected_key(r.text) in r.detail.get("rejected_values", []):
        # supersede-then-restate left this VALUE branded in the carried ledger even though the
        # record is CANDIDATE again — human approval must not launder it either (round-7 C1).
        raise RejectedApprovalError(
            f"record {record_id}'s value was previously REJECTED (rejected_values ledger) — "
            "approving the restated value would launder it. Review the correction chain first.")
    mem.promote(record_id)
    mem.annotate(record_id, review="approved",
                 reviewed_by=canonical_text(reviewed_by)[:_MAX_REVIEWER],
                 reviewed_ts=time.time())
    return mem.get(record_id)


def reject(mem: MemoryView, record_id: str, *, reviewed_by: str,
           reason: str = "") -> MemoryRecord | None:
    """Reject a fact on human authority — a durable tombstone, invisible to recall from now on.

    Uses the backend's own contradict → REJECTED path (delta=1.0 floors epistemic_confidence), so
    the `rejected_values` anti-laundering ledger is populated exactly as an evidence-driven
    rejection would. Returns the updated record, or None when it doesn't exist."""
    r = mem.get(record_id)
    if r is None:
        return None
    mem.contradict(record_id, delta=1.0)
    mem.annotate(record_id, review="rejected",
                 reviewed_by=canonical_text(reviewed_by)[:_MAX_REVIEWER],
                 reviewed_ts=time.time(),
                 review_reason=canonical_text(reason)[:_MAX_REASON])
    return mem.get(record_id)


def render_line(r: MemoryRecord, *, width: int = 100) -> str:
    """One terminal-safe line per record for the review listing. All record-derived fields pass
    `canonical_text` (ANSI/control/zero-width stripped) so stored content can't forge terminal
    output; the line is truncated to `width`."""
    head = canonical_text(f"{r.subject} {r.predicate}".strip())
    body = canonical_text(r.text)
    label = f"{head}: {body}" if head else body
    line = (f"{r.id}  {r.trust.value:<9}  ec={r.epistemic_confidence:.2f} "
            f"sup={r.support_count}  [{canonical_text(r.scope)}]  {label}")
    return line[: max(40, width)]


def render_record(r: MemoryRecord) -> str:
    """Multi-line terminal-safe detail view: the record, its correction chain, review metadata and
    the rejected-value ledger — what an operator needs to decide, nothing raw."""
    d = r.detail
    lines = [
        f"id:         {r.id}",
        f"kind:       {r.kind.value}",
        f"trust:      {r.trust.value}",
        f"scope:      {canonical_text(r.scope)}",
        f"subject:    {canonical_text(r.subject)}",
        f"predicate:  {canonical_text(r.predicate)}",
        f"text:       {canonical_text(r.text)}",
        f"confidence: {r.epistemic_confidence:.3f}   support: {r.support_count}   "
        f"strength: {r.retrieval_strength:.3f}",
        f"source:     {canonical_text(r.source)}   created_ts: {r.created_ts}",
    ]
    if r.provenance:
        lines.append("provenance: " + ", ".join(canonical_text(p)[:80] for p in r.provenance[:10]))
    for c in d.get("corrections", []):
        lines.append(f"superseded: {canonical_text(str(c.get('text', '')))[:120]} "
                     f"(ec={c.get('ec')}, at={c.get('superseded_at')})")
    if d.get("rejected_values"):
        lines.append(f"rejected ledger: {len(d['rejected_values'])} value(s) permanently blocked")
    if d.get("review"):
        lines.append(f"review:     {canonical_text(str(d.get('review')))} "
                     f"by {canonical_text(str(d.get('reviewed_by', '?')))} "
                     f"at {d.get('reviewed_ts')}")
        if d.get("review_reason"):
            lines.append(f"reason:     {canonical_text(str(d['review_reason']))}")
    return "\n".join(lines)
