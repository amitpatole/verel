"""The grade gate for conversational memory (MEMORY-EXTRACTION-KICKOFF.md, Phase 2).

This is where the moat lives. Extraction (Phase 1) only *proposes* `Trust.CANDIDATE` facts;
`remember_conversation` decides which ones actually compound:

  * a re-stated fact is **corroborated** (`MemoryView.write` raises belief + support),
  * a changed value **supersedes** the old one (a queryable correction chain, not a silent overwrite),
  * a fact graduates `CANDIDATE → VERIFIED` only when it is **corroborated past a threshold** OR a
    supplied **attestation** verifies it.

So a one-off, uncorroborated, unattested fact stays `CANDIDATE` forever — it never silently becomes
trusted. That's the difference from extract-and-believe memory: extracted, but **verified before
trusted**.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .extract import ChatFn, extract_facts
from .view import MemoryRecord, MemoryView, Trust

# Belief starts at the 0.5 prior and rises +0.1 per corroboration. 0.7 ⇒ confirmed ~twice (≈3 mentions
# across turns/sessions/sources) before a fact is trusted. Configurable; a stricter deployment can
# raise it or require an attestation via `attest`.
PROMOTE_EC = 0.7

# Returns True if a fact carries valid out-of-band attestation (e.g. verify_fact_attestation over a
# signed GateReceipt). Lets a deployment demand cryptographic proof, not just repetition.
Attestor = Callable[[MemoryRecord], bool]


@dataclass
class RememberResult:
    promoted: list[MemoryRecord] = field(default_factory=list)   # CANDIDATE → VERIFIED on this pass
    candidate: list[MemoryRecord] = field(default_factory=list)  # written, not yet trusted
    superseded: list[MemoryRecord] = field(default_factory=list)  # an old value a correction replaced

    @property
    def summary(self) -> str:
        return (f"remember: {len(self.promoted)} verified, {len(self.candidate)} candidate, "
                f"{len(self.superseded)} superseded")


def remember_conversation(mem: MemoryView, transcript: object, *, scope: str, chat: ChatFn,
                          now: float = 0.0, promote_at: float = PROMOTE_EC,
                          attest: Attestor | None = None) -> RememberResult:
    """Extract candidate facts from a conversation and let only GRADED facts compound into `mem`.

    Each extracted fact is written (which corroborates a re-statement or supersedes a changed value),
    then graduates `CANDIDATE → VERIFIED` iff it is corroborated to `promote_at` OR `attest` verifies
    it. Returns what was promoted, what stays candidate, and what was superseded — never trusting a
    fact on a single say-so."""
    res = RememberResult()
    for fact in extract_facts(transcript, scope=scope, chat=chat, now=now):
        before = mem.get(fact.id)
        if before is not None and before.text.strip().lower() != fact.text.strip().lower():
            res.superseded.append(before)  # the new value will supersede this one (write keeps the chain)
        rec = mem.write(fact, ts=now)
        if rec.trust == Trust.VERIFIED:
            continue  # already trusted from earlier corroboration — don't double-count
        attested = bool(attest and attest(rec))
        if attested or rec.epistemic_confidence >= promote_at:
            res.promoted.append(mem.promote(rec.id) or rec)
        else:
            res.candidate.append(rec)  # not enough evidence yet — stays a candidate, uncompounded
    return res
