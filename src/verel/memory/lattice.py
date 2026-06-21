"""Scope lattice (§5) — the spine of a shared team brain.

A memory's `scope` places it in a hierarchy: a private agent scope sits under a team scope, under
an org scope, under `global`. The lattice gives two cognitive moves a flat scope can't:

* **RESOLVE DOWN** — recall sees what *self*, *team*, and *org* know at once, ranked so the most
  specific scope wins ties (your repo's rule beats the team's, but the team's is still visible). An
  agent thinks with the whole society's verified knowledge behind it.
* **GRADUATE UP** — a belief independently VERIFIED in several sibling child scopes is promoted to
  the parent as a CANDIDATE: collective knowledge no single agent decreed, which still has to
  re-earn `verified` at the higher level. Individual experience compounds into team wisdom.

Backward compatible: the default lattice makes every scope a child of `global`, which is exactly
the existing "your scope + global" recall behaviour. Pure logic over any `MemoryView` — works the
same on `LocalMemory`, `mem0`, or (later) a hosted shared store.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .view import (
    MemoryKind,
    MemoryRecord,
    MemoryView,
    Trust,
    make_key,
)
from .view import rank as _rank
from .view import relevance as _relevance

GLOBAL = "global"

# A more-specific scope ranks above an equally-relevant memory from a broader one. Small, so
# relevance and belief still dominate — it only breaks ties between scopes.
SPECIFICITY_BONUS = 0.15


@dataclass
class ScopeLattice:
    """A child→parent map over scope strings. A scope with no explicit parent rolls up to `global`,
    so a flat set of scopes behaves exactly as before."""

    parents: dict[str, str] = field(default_factory=dict)

    def parent(self, scope: str) -> str | None:
        if scope == GLOBAL:
            return None
        return self.parents.get(scope, GLOBAL)

    def ancestors(self, scope: str) -> list[str]:
        """`[scope, parent, …, global]` — most specific first; cycle-guarded."""
        chain: list[str] = []
        seen: set[str] = set()
        cur: str | None = scope
        while cur is not None and cur not in seen:
            chain.append(cur)
            seen.add(cur)
            cur = self.parent(cur)
        if GLOBAL not in chain:
            chain.append(GLOBAL)
        return chain

    def children(self, parent: str, scopes) -> list[str]:
        """Which of `scopes` are direct children of `parent`."""
        return [s for s in scopes if s != parent and self.parent(s) == parent]


def lattice_recall(mem: MemoryView, query: str, *, scope: str,
                   lattice: ScopeLattice | None = None,
                   kind: MemoryKind | None = None, k: int = 5) -> list[MemoryRecord]:
    """Recall across `scope` and all its ancestors at once, ranked by the documented `rank()` plus a
    specificity bonus for closer scopes. A pure read — no recall reinforcement side effect, so it's
    safe to call across many scopes."""
    lattice = lattice or ScopeLattice()
    chain = lattice.ancestors(scope)
    span = max(1, len(chain) - 1)
    scored: list[tuple[float, int, MemoryRecord]] = []
    for depth, a in enumerate(chain):
        for r in mem.all(scope=a, kind=kind):
            if r.trust == Trust.REJECTED:
                continue
            rel = _relevance(query, r)
            if rel <= 0.0:
                continue  # match recall(): don't surface irrelevant memories
            bonus = SPECIFICITY_BONUS * (span - depth) / span  # depth 0 (most specific) → max
            scored.append((_rank(r, rel) + bonus, depth, r))
    scored.sort(key=lambda t: (t[0], -t[1]), reverse=True)  # higher score, then more specific
    return [r for _, _, r in scored[:k]]


def graduate(mem: MemoryView, *, parent: str, children: list[str],
             min_scopes: int = 2, kind: MemoryKind | None = None,
             ts: float = 0.0) -> list[MemoryRecord]:
    """Promote a belief that is independently VERIFIED in >= `min_scopes` of the `children` scopes up
    to `parent` as a CANDIDATE — collective knowledge that must re-earn `verified` at the higher
    level (records `detail['graduated_from']`). A claim is `(subject, predicate, text)`; the same
    claim verified across siblings is the evidence it generalizes. Returns the graduated records."""
    by_claim: dict[tuple[str, str, str], list[MemoryRecord]] = defaultdict(list)
    for c in children:
        for r in mem.all(scope=c, kind=kind):
            if r.trust == Trust.VERIFIED:
                by_claim[(r.subject, r.predicate, r.text.strip().lower())].append(r)

    written: list[MemoryRecord] = []
    for (subject, predicate, _text), recs in by_claim.items():
        spans = sorted({r.scope for r in recs})
        if len(spans) < min_scopes:
            continue  # not corroborated across enough siblings to generalize
        proto = recs[0]
        rec = MemoryRecord(
            kind=proto.kind, subject=subject, predicate=predicate, text=proto.text,
            scope=parent, source="graduation", provenance=[r.id for r in recs],
            trust=Trust.CANDIDATE, epistemic_confidence=0.5, support_count=len(recs),
            subj_pred_key=make_key(subject, predicate, parent),
        ).with_detail(grounding="graduated", graduated_from=spans, graduated_count=len(spans))
        written.append(mem.write(rec, ts=ts))
    return written
