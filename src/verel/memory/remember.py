"""The grade gate for conversational memory (MEMORY-EXTRACTION-KICKOFF.md, Phase 2).

This is where the moat lives. Extraction (Phase 1) only *proposes* `Trust.CANDIDATE` facts;
`remember_conversation` decides which ones actually compound:

  * a re-stated fact is **corroborated** (`MemoryView.write` raises belief + support),
  * a changed value **supersedes** the old one (a queryable correction chain, not a silent overwrite),
  * a fact graduates `CANDIDATE → VERIFIED` only when **independent sources** corroborate it (≥
    `min_sources` distinct provenance) OR a supplied **attestation** verifies it.

So a one-off fact — and, crucially, a fact a single attacker *repeats* — stays `CANDIDATE`: trust
requires INDEPENDENT corroboration, not raw confidence, so one author can't promote a lie by saying it
N times (round-5 security cadence, finding F1). That's the difference from extract-and-believe memory:
extracted, but **verified before trusted**.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .extract import ChatFn, extract_facts
from .principal import is_reserved_key
from .view import MemoryKind, MemoryRecord, MemoryView, Trust, rejected_key

# Distinct AUTHENTICATED principals required to promote a fact by corroboration. ≥2 means one principal
# repeating a claim never reaches VERIFIED. Configurable upward; never below 2 for the corroboration path.
MIN_SOURCES = 2

# True if a fact carries valid out-of-band attestation (e.g. verify_fact_attestation over a signed
# GateReceipt). The PRIMARY promotion path — a deployment proves a fact cryptographically.
Attestor = Callable[[MemoryRecord], bool]

# Maps a `source` to an AUTHENTICATED principal id (or None if it can't be verified). The corroboration
# path counts only DISTINCT authenticated principals — because raw `source` strings are self-asserted by
# the caller, two of them are NOT independent corroboration (round-5 F1, CRITICAL). Without an
# authenticator, corroboration NEVER promotes the trust tier (only `attest` does).
#
# CONTRACT (round-6 C2): the authenticator MUST validate an UNFORGEABLE credential — verify a signature,
# introspect a session token, read an mTLS identity — and return the resolved principal id. It must
# NEVER echo its input (`lambda s: s` is INSECURE: `source` is attacker-chosen, so an echo lets one
# caller forge N "distinct principals" by passing N labels). The gate counts only non-empty *string*
# returns, but it cannot tell a real id from an echoed one — that guarantee is the authenticator's job.
Authenticator = Callable[[str], "str | None"]


def _distinct_principals(provenance: list[str], authenticate: Authenticator) -> int:
    # Count ONLY non-empty *string* ids, deduped on the NORMALIZED (strip+casefold) id. A buggy
    # authenticator returning a truthy non-string (True, an object) must not inflate the count
    # (`{True,"bob"}` is one principal, round-6 M1); and one human under case/whitespace id variants
    # ("Alice"/"alice "/"alice") is ONE principal, not N (round-7 M1 residual) — so dedup canonically.
    ids = {pid.strip().casefold() for p in provenance
           if isinstance((pid := authenticate(p)), str) and pid.strip()}
    return len(ids)


@dataclass
class RememberResult:
    promoted: list[MemoryRecord] = field(default_factory=list)   # CANDIDATE → VERIFIED on this pass
    candidate: list[MemoryRecord] = field(default_factory=list)  # written, not yet trusted
    superseded: list[MemoryRecord] = field(default_factory=list)  # an old value a correction replaced
    refused: list[str] = field(default_factory=list)  # dropped — reserved key / would clobber non-FACT

    @property
    def summary(self) -> str:
        return (f"remember: {len(self.promoted)} verified, {len(self.candidate)} candidate, "
                f"{len(self.superseded)} superseded, {len(self.refused)} refused")


def remember_conversation(mem: MemoryView, transcript: object, *, scope: str, chat: ChatFn,
                          source: str = "", now: float = 0.0, min_sources: int = MIN_SOURCES,
                          attest: Attestor | None = None,
                          authenticate: Authenticator | None = None) -> RememberResult:
    """Extract candidate facts from a conversation and let only GRADED facts compound into `mem`.

    A fact graduates `CANDIDATE → VERIFIED` ONLY when:
      * `attest` verifies it (a signed receipt / held-out eval — the primary path), OR
      * `authenticate` is supplied AND ≥ `min_sources` **distinct authenticated principals** corroborate
        it. Raw `source` strings are self-asserted, so without an authenticator corroboration NEVER
        promotes — a single caller can't forge `VERIFIED` by minting two source labels (round-5 F1).

    Corroboration still raises *confidence* (a ranking signal) via `write`; it just doesn't grant the
    trust tier on its own. A reserved key (`is_reserved_key`) or a collision with a server-managed
    non-FACT record (a SKILL/AuthorTrust/rule) is **refused** — an untrusted transcript can't touch
    control state (round-5 lens-3 F1). A `REJECTED` fact is not re-promotable by corroboration."""
    res = RememberResult()
    for fact in extract_facts(transcript, scope=scope, chat=chat, now=now, source=source):
        if is_reserved_key(fact.predicate, fact.scope):
            res.refused.append(fact.text)
            continue
        before = mem.get(fact.id)
        if before is not None and before.kind != MemoryKind.FACT:
            res.refused.append(fact.text)   # would clobber a server-managed non-FACT record
            continue
        # Capture the trust tier BEFORE write. A different value SUPERSEDES (write rebuilds the record as
        # CANDIDATE), which would silently erase a prior REJECTED verdict — so a one-char value change
        # could launder a rejected lie back to promotable. Bind to the pre-write tier instead (round-6
        # C1): a key that was REJECTED is not re-promotable in this pass, value-change or not.
        was_rejected = before is not None and before.trust == Trust.REJECTED
        if before is not None and before.text.strip().lower() != fact.text.strip().lower():
            res.superseded.append(before)  # the new value will supersede this one (write keeps the chain)
        rec = mem.write(fact, ts=now)
        if rec.trust == Trust.VERIFIED:
            continue  # already trusted — don't double-count
        # A value that was EVER rejected for this key is not promotable, even after a supersede-then-
        # restate laundering chain (round-7 C1): `write` carries a durable `rejected_values` set forward
        # across supersessions, so a once-rejected value can't be re-minted as a fresh promotable CANDIDATE.
        value_rejected = rejected_key(fact.text) in set(rec.detail.get("rejected_values", ()))
        blocked = was_rejected or value_rejected
        attested = (not blocked) and bool(attest and attest(rec))
        independent = (not blocked and rec.trust != Trust.REJECTED and authenticate is not None
                       and _distinct_principals(rec.provenance, authenticate) >= max(2, min_sources))
        if attested or independent:
            res.promoted.append(mem.promote(rec.id) or rec)
        else:
            res.candidate.append(rec)  # confidence may rise, but not the trust tier — stays candidate
    return res
