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
                           kind: MemoryKind = MemoryKind.FACT,
                           author_trust: AuthorTrust | None = None, ts: float = 0.0) -> AuthnWrite:
    """Write a belief on behalf of an AUTHENTICATED principal. The signature must verify against an
    enrolled key (else rejected); `author` is the verified key_id (forge-proof); AuthorTrust keys on
    it. A principal may NOT silently supersede another principal's VERIFIED belief (cross-principal
    protection) — that needs a revision/contradiction flow, not a bare write."""
    if not verify_write(key_id=key_id, subject=subject, predicate=predicate, scope=scope, text=text,
                        signature=signature, trusted=trusted):
        return AuthnWrite(False, False, "", False, False, "unauthenticated — signature invalid or "
                          "principal not enrolled")
    author = key_id
    rid = make_id(make_key(subject, predicate, scope))
    existing = into.get(rid)
    if (existing is not None and existing.trust == Trust.VERIFIED
            and existing.text.strip().lower() != text.strip().lower()
            and author_of(existing) != author):
        return AuthnWrite(True, False, author, False, True,
                          "conflicts with another principal's verified belief — not overwritten")

    claim = MemoryRecord(kind=kind, subject=subject, predicate=predicate, text=text, scope=scope,
                         subj_pred_key=make_key(subject, predicate, scope))
    # trust does not travel: the candidate re-verifies only via the importer's own check (none here →
    # stays candidate). author is the authenticated principal; AuthorTrust can no longer be forged.
    res = import_belief(into, claim, verify=lambda _r: False, author=author,
                        author_trust=author_trust, ts=ts)
    return AuthnWrite(True, True, author, res.reverified, False, "written as candidate (authenticated)")
