"""Tool Registry — versioned, signed, provenance-tagged procedural memory (§7.6).

Tools/skills are stored as `MemoryKind.SKILL` records behind the SAME `MemoryView`, so the
trust model, decay, and the held-out promotion gate (§7.7) apply to skills exactly as to
facts: a skill enters shared memory only `verified`, and is reusable via the memory's
semantic recall. Each tool's code is content-signed; tampering breaks the signature.

SECURITY NOTE (honest): `load_callable` executes stored code in a restricted namespace with
a wall-clock timeout. This is a guardrail, NOT a real sandbox — a determined escape is
possible. Production runs untrusted tool code in the separate-trust-domain runner (§7.7:
subprocess/container), never in-process. `destructive` tools require a human-review verdict
before they can be registered `verified` (see smith.py).
"""

from __future__ import annotations

import hashlib
import hmac
import signal
from enum import Enum

from pydantic import BaseModel, Field

from .._secrets import load_secret
from ..memory.view import MemoryKind, MemoryRecord, MemoryView, Trust, make_key

# Tool-code signing key — a SEPARATE trust domain from the gate's runner secret (a leak of one must
# not forge the other). No public default; see _secrets.load_secret.
_SECRET = load_secret("VEREL_TOOL_SECRET", "tool_secret")


class SideEffect(str, Enum):
    READ_ONLY = "read_only"  # pure / no side effects -> auto-promote on eval pass
    IDEMPOTENT = "idempotent"  # repeatable side effects -> auto-promote on eval pass
    DESTRUCTIVE = "destructive"  # needs a human-review verdict before verified


AUTO_PROMOTABLE = {SideEffect.READ_ONLY, SideEffect.IDEMPOTENT}


class ToolRecord(BaseModel):
    name: str
    version: int = 1
    capability: str = ""  # natural-language description -> semantic reuse key
    code: str = ""  # a self-contained python module defining `def {name}(...)`
    doc: str = ""
    side_effect: SideEffect = SideEffect.READ_ONLY
    provenance: list[str] = Field(default_factory=list)
    eval_score: float = 0.0
    # The syscalls this tool exercised while passing its held-out eval (learned, see
    # seccomp_learn.py). Operator-set containment metadata for the capability seccomp profile —
    # deliberately NOT in the HMAC signature: the signature attests untrusted *code* integrity,
    # while the policy is the operator's enforcement choice applied at run time (an attacker who
    # could rewrite it could equally run with no seccomp at all, so signing it buys nothing).
    syscall_policy: list[str] | None = None
    signature: str = ""

    def signing_payload(self) -> str:
        return f"{self.name}|{self.version}|{self.code}"

    def sign(self) -> ToolRecord:
        self.signature = hmac.new(_SECRET, self.signing_payload().encode(), hashlib.sha256).hexdigest()
        return self

    def verify(self) -> bool:
        if not self.signature:
            return False
        expected = hmac.new(_SECRET, self.signing_payload().encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)


class _Timeout(Exception):
    pass


def load_callable(tool: ToolRecord, *, timeout_s: int = 2):
    """Materialize the tool's function. Verifies the signature first; execs in a restricted
    namespace with a wall-clock timeout. NOT a production sandbox (see module docstring)."""
    if not tool.verify():
        raise ValueError(f"tool {tool.name!r} failed signature verification — refusing to load")

    bi = __builtins__ if isinstance(__builtins__, dict) else vars(__builtins__)
    safe_builtins = {
        k: bi[k]
        for k in ("range", "len", "min", "max", "abs", "sum", "sorted", "enumerate", "zip",
                  "map", "filter", "round", "int", "float", "str", "bool", "list", "dict",
                  "set", "tuple", "isinstance", "any", "all", "ord", "chr", "repr",
                  "ValueError", "TypeError", "KeyError", "IndexError", "Exception")
        if k in bi
    }
    # Whitelisted imports only — pure stdlib helpers. `os`, `sys`, `open`, sockets stay blocked,
    # so the guard remains meaningful even though this is NOT a real sandbox (see docstring).
    allowed_modules = {"re", "math", "string", "json", "datetime", "itertools",
                       "functools", "collections", "decimal", "fractions", "textwrap"}

    def _safe_import(name, *args, **kwargs):
        if name.split(".")[0] not in allowed_modules:
            raise ImportError(f"import of {name!r} is not allowed in the tool sandbox")
        return bi["__import__"](name, *args, **kwargs)

    safe_builtins["__import__"] = _safe_import
    ns: dict = {"__builtins__": safe_builtins}
    exec(compile(tool.code, f"<tool:{tool.name}>", "exec"), ns)  # noqa: S102 — guarded; see docstring
    fn = ns.get(tool.name)
    if not callable(fn):
        raise ValueError(f"tool code does not define a callable named {tool.name!r}")

    def guarded(*args, **kwargs):
        had_alarm = hasattr(signal, "SIGALRM")
        if had_alarm:
            def _raise(*_a):
                raise _Timeout(f"tool {tool.name!r} exceeded {timeout_s}s")

            old = signal.signal(signal.SIGALRM, _raise)
            signal.alarm(timeout_s)
        try:
            return fn(*args, **kwargs)
        finally:
            if had_alarm:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old)

    return guarded


class ToolRegistry:
    """Procedural memory over a MemoryView. Tools are SKILL records; reuse via recall."""

    def __init__(self, mem: MemoryView, *, scope: str = "global"):
        self.mem = mem
        self.scope = scope

    def _id_key(self, name: str) -> str:
        return make_key(name, "tool", self.scope)

    def register(self, tool: ToolRecord, *, trust: Trust, ts: float = 0.0) -> MemoryRecord:
        tool.sign()
        rec = MemoryRecord(
            kind=MemoryKind.SKILL,
            subject=tool.name,
            predicate="tool",
            text=tool.capability or tool.doc or tool.name,
            scope=self.scope,
            subj_pred_key=self._id_key(tool.name),
            source="toolsmith",
            provenance=tool.provenance,
            trust=trust,
            epistemic_confidence=0.7 if trust == Trust.VERIFIED else 0.5,
        ).with_detail(tool=tool.model_dump())
        return self.mem.write(rec, ts=ts)

    def get(self, name: str) -> ToolRecord | None:
        rec = self.mem.get(make_idfromkey(self._id_key(name)))
        return ToolRecord(**rec.detail["tool"]) if rec and "tool" in rec.detail else None

    def find(self, capability: str, *, verified_only: bool = True, k: int = 3,
             min_relevance: float = 0.0) -> list[ToolRecord]:
        from ..memory.view import relevance

        hits = self.mem.recall(capability, scope=self.scope, kind=MemoryKind.SKILL, k=k)

        # Semantic reuse when the memory has an embedder (cosine of capability vs skill
        # vector); lexical token-overlap otherwise. So "make a url-friendly string" can reuse
        # "slugify" even with no shared words.
        embedder = getattr(self.mem, "embedder", None)
        qv = embedder.embed([capability])[0] if embedder else None

        def rel(h) -> float:
            if qv is not None and hasattr(self.mem, "_get_vector"):
                from ..memory.embed import cosine

                v = self.mem._get_vector(h.id)
                return cosine(qv, v) if v else 0.0
            return relevance(capability, h)

        tools = []
        for h in hits:
            if verified_only and h.trust != Trust.VERIFIED:
                continue
            if min_relevance and rel(h) < min_relevance:  # guard against weak matches
                continue
            t = h.detail.get("tool")
            if t:
                tools.append(ToolRecord(**t))
        return tools


def make_idfromkey(key: str) -> str:
    from ..memory.view import make_id

    return make_id(key)
