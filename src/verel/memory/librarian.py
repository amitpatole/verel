"""The librarian (§5) — the maintenance cycle that keeps the brain compounding, not rotting.

A brain that only ever *writes* becomes a junk drawer: duplicate episodes pile up, stale beliefs
linger, individual lessons never become team knowledge. The librarian is the periodic, **gated**
upkeep pass — the "sleep" that consolidates the day's experience. It only orchestrates primitives
that already earn their own trust, so it never decrees anything:

  1. **consolidate** recurring failures into candidate, structured `DesignRule`s;
  2. **induce** the multi-hop schema hierarchy over those rules;
  3. **graduate** beliefs verified across sibling scopes up the lattice (as candidates);
  4. **prune & decay** — drop what the §5 rule allows (never `verified`, never `pinned`).

Steps 1–3 produce only `candidate`/`inferred` records — they still face the promotion gate before
they're trusted. Step 4 prunes strictly per the documented rule. So the librarian *proposes and
tidies*; it never mints trust. Runs against any `MemoryView`, including `RemoteMemory` — so it
maintains the *shared* team brain. The LLM (consolidation/induction) is injectable for offline runs.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .consolidate import consolidate_failures, induce_hierarchy
from .lattice import graduate
from .view import MemoryView

ChatFn = Callable[[list[dict]], str]


@dataclass
class LibrarianReport:
    scope: str
    rules_induced: int = 0
    schemas_induced: int = 0   # summed across every hierarchy level
    graduated: int = 0
    pruned: int = 0

    @property
    def changed(self) -> int:
        return self.rules_induced + self.schemas_induced + self.graduated + self.pruned

    def summary(self) -> str:
        return (f"librarian[{self.scope}]: +{self.rules_induced} rules, +{self.schemas_induced} "
                f"schemas, +{self.graduated} graduated, -{self.pruned} pruned")


def librarian_pass(
    mem: MemoryView,
    *,
    scope: str,
    children: list[str] | None = None,
    chat: ChatFn | None = None,
    min_cluster: int = 2,
    min_size: int = 2,
    graduate_min_scopes: int = 2,
    half_life_s: float = 604800.0,
    now: float = 0.0,
    ts: float = 0.0,
    consolidate: bool = True,
    induce: bool = True,
    promote_up: bool = True,
    prune: bool = True,
) -> LibrarianReport:
    """Run one maintenance cycle over `scope` and report what it did. With `children`, also graduate
    beliefs verified across those sibling scopes up to `scope`. Each step is independently
    toggleable. Nothing here mints trust — consolidation/graduation write candidates; prune only
    drops what §5 allows."""
    rep = LibrarianReport(scope=scope)

    if consolidate:
        rep.rules_induced = len(consolidate_failures(mem, scope=scope, min_cluster=min_cluster,
                                                     chat=chat, ts=ts))
    if induce:
        levels = induce_hierarchy(mem, scope=scope, min_size=min_size, chat=chat, ts=ts)
        rep.schemas_induced = sum(len(v) for v in levels.values())
    if promote_up and children:
        rep.graduated = len(graduate(mem, parent=scope, children=children,
                                     min_scopes=graduate_min_scopes, ts=ts))
    if prune:
        rep.pruned = mem.decay(half_life_s=half_life_s, now=now)

    return rep
