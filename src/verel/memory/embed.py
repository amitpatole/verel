"""Embedders for semantic recall (§5.6 — the v2 upgrade behind the same MemoryView).

Recall was lexical token-overlap (v1). With an `Embedder`, recall ranks by cosine similarity
of dense vectors, so "the panel runs off the screen" matches a rule about "overflow" even
with zero shared words. The ranking rule (`rank()`) is unchanged — only the relevance signal
gets smarter.

- `HashEmbedder`: deterministic, dependency-free, offline. Char n-gram hashing — captures
  surface overlap, NOT meaning. The zero-dep default and the test embedder; honest about its
  limits.
- `OpenAIEmbedder`: real semantic vectors (text-embedding-3-small). Ollama Cloud does not
  serve embeddings, so the real embedder uses the OpenAI key; swap the endpoint for any
  OpenAI-compatible embeddings API.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import urllib.request
from pathlib import Path
from typing import Protocol, runtime_checkable

_WORD = re.compile(r"[a-z0-9]+")


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


@runtime_checkable
class Embedder(Protocol):
    dim: int

    def embed(self, texts: list[str]) -> list[list[float]]: ...


class HashEmbedder:
    """Deterministic char-trigram hashing into a fixed-dim, L2-normalized vector. Offline and
    dependency-free — proves the vector machinery and gives stable tests. NOT semantic."""

    def __init__(self, dim: int = 256):
        self.dim = dim

    def _vec(self, text: str) -> list[float]:
        v = [0.0] * self.dim
        toks = _WORD.findall(text.lower())
        grams = [text[i : i + 3] for i in range(max(0, len(text) - 2))] + toks
        for g in grams:
            h = int(hashlib.blake2s(g.encode()).hexdigest()[:8], 16)
            v[h % self.dim] += 1.0
        n = math.sqrt(sum(x * x for x in v))
        return [x / n for x in v] if n else v

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._vec(t) for t in texts]


class OpenAIEmbedder:
    """Real semantic embeddings via an OpenAI-compatible /v1/embeddings endpoint."""

    def __init__(self, model: str = "text-embedding-3-small",
                 base_url: str = "https://api.openai.com/v1", dim: int = 1536):
        self.model = model
        self.base_url = base_url
        self.dim = dim

    def _key(self) -> str:
        if k := os.environ.get("OPENAI_API_KEY"):
            return k.strip()
        p = Path.home() / ".config" / "OpenAI" / "key"
        if p.exists():
            return p.read_text().strip()
        raise RuntimeError("no OpenAI key for embeddings (OPENAI_API_KEY or ~/.config/OpenAI/key)")

    def embed(self, texts: list[str]) -> list[list[float]]:
        payload = json.dumps({"model": self.model, "input": texts}).encode()
        if not str(self.base_url).lower().startswith(("http://", "https://")):
            # never ship the bearer key to a file:/ or custom-scheme target via a misconfigured base_url
            raise RuntimeError(f"embeddings base_url must be http(s), got {self.base_url!r}")
        req = urllib.request.Request(f"{self.base_url}/embeddings", data=payload,
                                     headers={"Authorization": f"Bearer {self._key()}",
                                              "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as r:  # nosec B310 — scheme guarded http(s) above
            data = json.load(r)
        return [e["embedding"] for e in data["data"]]
