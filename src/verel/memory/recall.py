"""Token-budgeted recall (MEMORY-EXTRACTION-KICKOFF.md, Phase 3).

Closes the "keep the prompt small" gap (the Engram-style win) — and does it **graded-first**. Returns
the highest-value scoped memories that fit a token budget, ranked by the documented `view.rank`
(relevance + retrieval strength + confidence + a small trust term), so under pressure a `VERIFIED`
fact beats an equally-relevant `CANDIDATE` and a poisoned candidate can't crowd out a verified one.

Pure + dependency-free: the token estimator is injectable (`token_count`), defaulting to a ~4-chars/
token heuristic so it works with zero deps; pass `tiktoken`-backed counting for exactness.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .view import MemoryKind, MemoryRecord, MemoryView, rank, relevance

TokenCount = Callable[[str], int]


def _est_tokens(s: str) -> int:
    """Dependency-free ~GPT token estimate (≈4 chars/token), at least 1 for a non-empty line."""
    return max(1, round(len(s) / 4)) if s else 0


def _render(r: MemoryRecord) -> str:
    """A compact, prompt-ready line for one memory (SPO is already terse)."""
    head = f"{r.subject.strip()} {r.predicate.strip()}".strip()
    return f"- {head}: {r.text.strip()}" if head else f"- {r.text.strip()}"


@dataclass
class BudgetedRecall:
    records: list[MemoryRecord] = field(default_factory=list)
    used_tokens: int = 0
    dropped: int = 0  # relevant memories that didn't fit the budget

    @property
    def text(self) -> str:
        """The minimal context block, ready to drop into a prompt. Appends a one-line tail note when
        memories were dropped, so the agent knows the recall was budget-limited (not exhaustive)."""
        lines = [_render(r) for r in self.records]
        if self.dropped:
            lines.append(f"- (+{self.dropped} more lower-ranked memories omitted for budget)")
        return "\n".join(lines)


def recall_budgeted(mem: MemoryView, query: str, *, scope: str, token_budget: int,
                    kind: MemoryKind | None = None, k: int = 50,
                    token_count: TokenCount | None = None, now: float = 0.0) -> BudgetedRecall:
    """Return the best scoped memories for `query` that fit `token_budget`, verified-first, plus the
    tokens used and the number dropped.

    Fills greedily in `view.rank` order and **never exceeds the budget** — except it always returns at
    least the single highest-ranked memory, so recall is never empty when a relevant memory exists
    (a one-line fact is worth more than an empty context, even under a sub-fact budget)."""
    tc = token_count or _est_tokens
    pool = mem.recall(query, scope=scope, kind=kind, k=k, ts=now)
    ranked = sorted(pool, key=lambda r: rank(r, relevance(query, r)), reverse=True)
    chosen: list[MemoryRecord] = []
    used = dropped = 0
    for r in ranked:
        cost = tc(_render(r))
        # `not chosen` guarantees the single most load-bearing memory even on a sub-fact budget;
        # after that, add only while it fits — never exceeding the budget.
        if not chosen or used + cost <= token_budget:
            chosen.append(r)
            used += cost
        else:
            dropped += 1
    return BudgetedRecall(records=chosen, used_tokens=used, dropped=dropped)
