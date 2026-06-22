"""PublicRegistry — a content-addressed store of signed skill artifacts (§2.2).

The "public" registry is a directory of `<content_hash>.json` artifacts (a stand-in for a
hosted, signed registry). Publishing verifies the signature; lookup is by content hash or a
lexical capability search. This is the distribution layer of the data flywheel — only as
valuable as skills that actually transfer (which §8.7 / h2.py measures before we invest).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .artifact import SkillArtifact

# Content hashes are blake2s hex digests; anything else (esp. '../' path traversal) is rejected
# before it ever reaches the filesystem.
_HASH_RE = re.compile(r"[0-9a-f]{1,64}\Z")


class PublicRegistry:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def publish(self, artifact: SkillArtifact) -> SkillArtifact:
        if not artifact.content_hash or not artifact.signature:
            artifact.finalize()
        if not artifact.verify():
            raise ValueError(f"refusing to publish unsigned/tampered artifact {artifact.name!r}")
        (self.root / f"{artifact.content_hash}.json").write_text(artifact.model_dump_json(indent=2))
        return artifact

    def get(self, content_hash: str) -> SkillArtifact | None:
        if not _HASH_RE.match(content_hash):  # reject path traversal / non-hash lookups
            return None
        p = self.root / f"{content_hash}.json"
        return SkillArtifact(**json.loads(p.read_text())) if p.exists() else None

    def all(self) -> list[SkillArtifact]:
        return [SkillArtifact(**json.loads(p.read_text())) for p in sorted(self.root.glob("*.json"))]

    def search(self, capability: str) -> list[SkillArtifact]:
        q = set(capability.lower().split())
        scored = []
        for a in self.all():
            hay = set(f"{a.name} {a.capability}".lower().split())
            overlap = len(q & hay)
            if overlap:
                scored.append((overlap, a))
        return [a for _, a in sorted(scored, key=lambda t: t[0], reverse=True)]
