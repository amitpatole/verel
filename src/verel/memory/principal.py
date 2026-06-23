"""Authenticated principals for the shared brain (§5, §8.7 — the multi-principal hardening).

The local brain trusts one operator, so `author` could be a free string. The moment the brain is
shared across principals (the hosted `MemoryServer`/`RemoteMemory` direction), that string is
forgeable — and `AuthorTrust`, the very thing meant to stop one bad actor poisoning the swarm, can
itself be forged or used to impersonate/tank another author (brain-audit finding 3).

The fix: a **principal is an ed25519 keypair whose `key_id` IS its identity**. A write is SIGNED; the
verifier derives `author` from the VERIFIED key — never from a caller-supplied string. Authoring a
belief as "alice" now requires alice's private key, and `AuthorTrust` keys on the authenticated id.

Trust is pinning (same model as the receipts): a principal must be ENROLLED — its public key present
in the verifier's `trusted` set — or its writes are rejected. Reuses `verel.verdict.keys` (PyNaCl).
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from .._sign import canonical_payload
from ..verdict import keys
from .share import AuthorTrust, author_of, import_belief
from .view import MemoryKind, MemoryRecord, MemoryView, Trust, make_id, make_key

# Bound a signed write's fields so a verbatim-stored record can't bloat the brain (server-side DoS).
_MAX_TEXT = 20_000
_MAX_FIELD = 512

# A client signed-write may only AUTHOR a plain belief. Server-side pipelines key CONTROL-BEARING
# state on specific (predicate, scope) conventions in the SAME store: the AuthorTrust reputation
# ledger (author_trust / meta:authors), the failure-regression ledger (predicate "fails"), the
# induced design-rules/schemas (design_rule / schema), and the toolsmith's procedural SKILL registry
# (predicate "tool" — the executable tool body lives in detail['tool']). A client write that collides
# with one of those keys would clobber or forge that state via the interference rule (make_id ignores
# `kind`, so the collision is purely on the normalized subject|predicate|scope — a FACT and a SKILL
# with the same subj_pred_key share an id). And FAILURE/DESIGN_RULE/SCHEMA/SKILL are EARNED or INDUCED,
# never directly authored. So a signed write is constrained to kind=FACT with a non-reserved
# predicate/scope; everything else is server-managed and refused. (Compare on the same strip().lower()
# normalization `make_key` applies, so a case/whitespace variant can't dodge it.)
_CLIENT_KIND = MemoryKind.FACT
_RESERVED_SCOPES = frozenset({"meta:authors"})
_RESERVED_PREDICATES = frozenset({"author_trust", "fails", "design_rule", "schema", "tool"})


def is_reserved_key(predicate: str, scope: str) -> bool:
    """True if (predicate, scope) names server-managed control state a client write must never touch
    (the reputation ledger, failure ledger, induced rules/schemas, the skill registry). The one
    FACT-kind control record (AuthorTrust) needs this predicate/scope check because the kind-based
    structural backstop can't catch a FACT-vs-FACT collision. Normalized exactly as make_key, so a
    case/whitespace variant can't dodge it while still colliding with the target's subj_pred_key.
    Shared by BOTH the remote (`authenticated_remember`) and local (`verel_remember`) write paths."""
    return scope.strip().lower() in _RESERVED_SCOPES or predicate.strip().lower() in _RESERVED_PREDICATES


def _write_payload(key_id: str, subject: str, predicate: str, scope: str, text: str) -> str:
    """The bytes a principal signs to author a belief — binds the identity to the exact claim, so a
    signature can't be lifted onto a different fact (domain-tagged, injective; see verel._sign)."""
    return canonical_payload("memwrite", key_id, subject, predicate, scope, text)


class Principal:
    """An authenticated writer: an ed25519 keypair; `key_id` is its identity in the brain."""

    def __init__(self, seed: bytes):
        keys._require_nacl()
        from nacl.signing import SigningKey

        if len(seed) != 32:
            raise ValueError("principal seed must be exactly 32 bytes")
        self._sk = SigningKey(seed)
        self.key_id = keys.key_id_for(bytes(self._sk.verify_key))

    @classmethod
    def generate(cls) -> Principal:
        return cls(secrets.token_bytes(32))

    def public_key_b64(self) -> str:
        return keys._b64e(bytes(self._sk.verify_key))

    def sign_write(self, *, subject: str, predicate: str, scope: str, text: str) -> str:
        payload = _write_payload(self.key_id, subject, predicate, scope, text)
        return keys._b64e(self._sk.sign(payload.encode()).signature)

    def enroll(self) -> tuple[str, str]:
        """`(key_id, public_key_b64)` — what an operator adds to a server's trusted-principals set."""
        return self.key_id, self.public_key_b64()


def verify_write(*, key_id: str, subject: str, predicate: str, scope: str, text: str,
                 signature: str, trusted: dict[str, str]) -> bool:
    """True iff `signature` is a valid ed25519 signature over the claim by an ENROLLED principal.
    Fails CLOSED: unknown/unenrolled key_id, a stored pubkey that doesn't hash to its key_id, a bad
    signature, or PyNaCl absent. Pinning, never TOFU — the key must already be trusted."""
    if not keys.available():
        return False
    pub_b64 = trusted.get(key_id)
    if not pub_b64:
        return False  # principal not enrolled
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    try:
        pub = keys._b64d(pub_b64)
        if len(pub) != 32 or keys.key_id_for(pub) != key_id:
            return False  # the enrolled pubkey must match its claimed id
        VerifyKey(pub).verify(_write_payload(key_id, subject, predicate, scope, text).encode(),
                              keys._b64d(signature))
        return True
    except BadSignatureError:
        return False
    except Exception:  # malformed base64 / wrong-length sig / etc. → fail closed
        return False


@dataclass
class AuthnWrite:
    authenticated: bool   # the signature verified against an enrolled principal
    written: bool         # entered the store
    author: str           # the AUTHENTICATED key_id (empty if not authenticated)
    reverified: bool
    conflict: bool        # refused: would overwrite ANOTHER principal's verified belief
    reason: str


def authenticated_remember(into: MemoryView, *, subject: str, predicate: str, scope: str, text: str,
                           signature: str, key_id: str, trusted: dict[str, str],
                           kind: MemoryKind = MemoryKind.FACT, evidence: dict | None = None,
                           author_trust: AuthorTrust | None = None, ts: float = 0.0) -> AuthnWrite:
    """Write a belief on behalf of an AUTHENTICATED principal. The signature must verify against an
    enrolled key (else rejected); `author` is the verified key_id (forge-proof); AuthorTrust keys on
    it. A principal may NOT silently supersede another principal's VERIFIED belief (cross-principal
    protection) — that needs a revision/contradiction flow, not a bare write.

    Trust does not travel by say-so — a write enters as a CANDIDATE. It earns the cross-principal
    `verified` tier ONLY when `evidence` is a **fact-bound attestation**: a publicly-verifiable
    (ed25519) GateReceipt that attests a PASS verdict AND whose signed subject commits to THIS exact
    claim. A trusted grader signed over this specific fact — so it's verified, not laundered."""
    if not verify_write(key_id=key_id, subject=subject, predicate=predicate, scope=scope, text=text,
                        signature=signature, trusted=trusted):
        return AuthnWrite(False, False, "", False, False, "unauthenticated — signature invalid or "
                          "principal not enrolled")
    if len(text) > _MAX_TEXT or len(subject) > _MAX_FIELD or len(predicate) > _MAX_FIELD \
            or len(scope) > _MAX_FIELD:
        return AuthnWrite(True, False, key_id, False, False, "field too long")
    # A client may only author plain FACTs — control-bearing kinds are earned/induced, not authored.
    if kind != _CLIENT_KIND:
        return AuthnWrite(True, False, key_id, False, False,
                          f"signed writes may only author facts, not {kind.value} (server-managed)")
    # Refuse keys that collide with server-managed control state (reputation ledger, failure ledger,
    # induced rules/schemas). See is_reserved_key — shared with the local write path.
    if is_reserved_key(predicate, scope):
        return AuthnWrite(True, False, key_id, False, False,
                          "reserved key — that predicate/scope is server-managed, not client-writable")
    author = key_id
    rid = make_id(make_key(subject, predicate, scope))
    existing = into.get(rid)
    # STRUCTURAL backstop (root cause, predicate-independent): make_id ignores `kind`, so a client FACT
    # shares an id with a server-managed record at the same subject|predicate|scope. A client must never
    # supersede a NON-FACT record (the failure ledger, a SKILL, an induced rule/schema) — this catches
    # ANY such record regardless of its predicate, so a future server-managed kind can't reopen the
    # collision class the reserved-predicate denylist chases one entry at a time. (FACT-kind control
    # state — only the AuthorTrust ledger — is covered by the reserved predicate/scope check above.)
    if existing is not None and existing.kind != MemoryKind.FACT:
        return AuthnWrite(True, False, author, False, True,
                          f"collides with a server-managed {existing.kind.value} record — refused")
    # A principal may neither overwrite NOR corroborate-and-reattribute ANOTHER principal's VERIFIED
    # belief — the author check fires regardless of text equivalence (a case/whitespace variant would
    # otherwise hit the corroboration merge and silently rewrite the stored `author`). Cross-principal
    # agreement on a verified belief needs a dedicated signed-corroborate flow, not a bare write.
    if (existing is not None and existing.trust == Trust.VERIFIED
            and author_of(existing) != author):
        return AuthnWrite(True, False, author, False, True,
                          "conflicts with another principal's verified belief — not overwritten")

    claim = MemoryRecord(kind=kind, subject=subject, predicate=predicate, text=text, scope=scope,
                         subj_pred_key=make_key(subject, predicate, scope))
    # The importer's own check: trust does not travel by say-so. It re-verifies (→ verified) ONLY when
    # `evidence` is a publicly-verifiable, fact-BOUND attestation of a PASS over THIS exact claim;
    # otherwise the write stays a CANDIDATE. author is the authenticated principal (AuthorTrust safe).
    from ..verdict import verify_fact_attestation
    attested = evidence is not None and verify_fact_attestation(
        evidence, subject, predicate, text, allowed_algs={"ed25519"})
    res = import_belief(into, claim, verify=lambda _r: attested, author=author,
                        author_trust=author_trust, ts=ts)
    reason = ("verified by a fact-bound attestation" if res.reverified
              else "written as candidate (authenticated)")
    return AuthnWrite(True, True, author, res.reverified, False, reason)
