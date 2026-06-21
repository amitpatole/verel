"""Cross-agent trust (§5, §8.7) — sharing a brain *safely*.

A hosted shared brain (hosted.py) lets many agents read and write one store. The danger is obvious:
one sloppy or adversarial agent can poison everyone. Two rules keep it honest, both lifted from the
skill registry's "trust does not travel" discipline and applied to *beliefs*:

* **`import_belief`** — a peer's belief is never trusted on its say-so. It enters the importer as a
  CANDIDATE and only becomes VERIFIED by passing the importer's OWN check in its OWN context. The
  peer's self-asserted confidence is ignored entirely.
* **`AuthorTrust`** — a per-author reputation, *shared in the brain itself*. A contributor whose
  beliefs keep re-verifying earns a higher prior (their claims start more believed and surface
  sooner); a noisy one's prior falls (their claims need more corroboration before they're trusted).
  So a single bad actor can't move the collective — the system literally learns who to trust.

Pure logic over any `MemoryView` (incl. `RemoteMemory`), with the verifier injected — so it's tested
offline and works the same on a private store or the shared team brain.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .view import MemoryKind, MemoryRecord, MemoryView, Trust, make_id, make_key

# A verifier checks a belief in the importer's own context (held-out eval, a grader run, the
# promotion gate). Returns True iff the belief holds locally.
Verifier = Callable[[MemoryRecord], bool]

NEUTRAL_PRIOR = 0.5  # an unknown author is neither trusted nor distrusted


def author_of(record: MemoryRecord) -> str:
    """Who contributed this belief (stored in detail so it round-trips across backends)."""
    return str(record.detail.get("author", ""))


@dataclass
class AuthorTrust:
    """Per-author reputation, persisted in the brain so every agent shares the same view of who's
    reliable. `prior(author)` is a Laplace-smoothed re-verification rate in (0, 1)."""

    mem: MemoryView
    scope: str = "meta:authors"

    def _key(self, author: str) -> str:
        return make_key(author, "author_trust", self.scope)

    def _get(self, author: str) -> MemoryRecord | None:
        return self.mem.get(make_id(self._key(author)))

    def record(self, author: str, *, ok: bool, ts: float = 0.0) -> None:
        """Log one outcome for `author` — their imported belief re-verified (ok) or didn't."""
        if not author:
            return
        rec = self._get(author)
        if rec is None:
            rec = self.mem.write(MemoryRecord(
                kind=MemoryKind.FACT, subject=author, predicate="author_trust",
                text=f"reputation of {author}", scope=self.scope,
                subj_pred_key=self._key(author),
            ).with_detail(verified=0, total=0), ts=ts)
        d = rec.detail
        # read-modify-write — approximate under heavy concurrency, which is fine for reputation.
        self.mem.annotate(rec.id, verified=int(d.get("verified", 0)) + (1 if ok else 0),
                          total=int(d.get("total", 0)) + 1)

    def prior(self, author: str) -> float:
        if not author:
            return NEUTRAL_PRIOR
        rec = self._get(author)
        if rec is None:
            return NEUTRAL_PRIOR
        d = rec.detail
        v, t = int(d.get("verified", 0)), int(d.get("total", 0))
        return (v + 1) / (t + 2)  # Laplace smoothing → neutral at 0 evidence, converges to the rate

    def standing(self, author: str) -> tuple[int, int]:
        """(verified, total) outcomes recorded for `author`."""
        rec = self._get(author)
        if rec is None:
            return (0, 0)
        d = rec.detail
        return (int(d.get("verified", 0)), int(d.get("total", 0)))


@dataclass
class BeliefImport:
    subject: str
    installed: bool   # entered the store (as a candidate at least)
    reverified: bool  # passed the importer's check → verified locally
    prior: float      # the author's reputation at import time
    reason: str


def import_belief(into: MemoryView, claim: MemoryRecord, *, verify: Verifier,
                  author: str | None = None, author_trust: AuthorTrust | None = None,
                  ts: float = 0.0) -> BeliefImport:
    """Install a peer's `claim` as a CANDIDATE and re-verify it in the importer's context with
    `verify`. Trust does NOT travel: the claim's own trust/confidence are ignored; the candidate's
    starting confidence is anchored to the AUTHOR's reputation (not the peer's assertion). Only a
    belief that re-verifies becomes VERIFIED locally; either way the author's standing is updated."""
    author = author if author is not None else author_of(claim)
    prior = author_trust.prior(author) if author_trust is not None else NEUTRAL_PRIOR

    rec = into.write(MemoryRecord(
        kind=claim.kind, subject=claim.subject, predicate=claim.predicate, text=claim.text,
        scope=claim.scope, source="import",
        provenance=[*claim.provenance, f"imported:{author or 'unknown'}"],
        trust=Trust.CANDIDATE,
        epistemic_confidence=0.3 + 0.4 * prior,  # 0.3 (unknown/poor) … 0.7 (well-trusted author)
        subj_pred_key=make_key(claim.subject, claim.predicate, claim.scope),
    ).with_detail(author=author, imported=True, grounding="imported"), ts=ts)

    ok = bool(verify(rec))
    if author_trust is not None:
        author_trust.record(author, ok=ok, ts=ts)
    if ok:
        into.promote(rec.id)  # re-verified in MY context → it's mine now, verified
        return BeliefImport(claim.subject, True, True, prior, "re-verified locally → verified")
    return BeliefImport(claim.subject, True, False, prior,
                        "installed as candidate — did not re-verify; trust did not travel")
