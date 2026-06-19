"""Skill artifact — the content-addressed, signed, provenance-tagged unit of the public
Skill Registry (§2.2, §8.7).

A skill leaves a tenant ONLY as a verified artifact: its id is the hash of its code (content-
addressed, so identical skills dedupe and tampering is detectable), it carries provenance and
the origin's eval score, and it is signed. Crucially, importing an artifact does NOT import
its trust — it must re-earn `verified` against the importing tenant's own held-out eval
(transfer.py). That re-verification rate is exactly what the moat hypothesis (H2) measures.
"""

from __future__ import annotations

import hashlib
import hmac
import os

from pydantic import BaseModel, Field

_SECRET = os.environ.get("VEREL_REGISTRY_SECRET", "verel-dev-registry-secret").encode()


def content_hash(code: str) -> str:
    return hashlib.blake2s(code.encode()).hexdigest()[:24]


class SkillArtifact(BaseModel):
    content_hash: str = ""  # = content_hash(code); the registry key
    name: str
    capability: str = ""
    code: str = ""
    side_effect: str = "read_only"
    origin: str = ""  # origin tenant/scope (provenance, never trust)
    eval_score: float = 0.0  # origin's score (provenance, never trust)
    provenance: list[str] = Field(default_factory=list)
    signature: str = ""

    def _payload(self) -> str:
        return f"{self.content_hash}|{self.name}|{self.origin}"

    def finalize(self) -> "SkillArtifact":
        self.content_hash = content_hash(self.code)
        self.signature = hmac.new(_SECRET, self._payload().encode(), hashlib.sha256).hexdigest()
        return self

    def verify(self) -> bool:
        if not self.signature or self.content_hash != content_hash(self.code):
            return False  # tampered code or missing signature
        expected = hmac.new(_SECRET, self._payload().encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)
