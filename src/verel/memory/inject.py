"""Deterministic memory-injection harness — fold graded, fenced memory into an LLM's context at
runtime WITHOUT the model deciding to retrieve.

The MCP recall tool is *agent-driven*: the model must choose to call it, so whether prior context is
present depends on the model's judgement. This is the other path — a **developer-designed runtime
hook**: a pure function over the message list that always runs, so relevant memory from earlier
conversations is deterministically present at a position the developer picks (system / user /
assistant). No tool call, no model choice — the friction of a user re-supplying context they already
gave is removed by construction.

What makes this safe (and different from "just stuff recall into the system prompt"): the injected
block is `recall_budgeted`'s fenced `<recalled_memory>` DATA — **graded-first** (a VERIFIED fact beats
an equally-relevant CANDIDATE; a poisoned candidate can't crowd it out), **token-budgeted** (it never
blows the context), and **neutralized** via the shared `canonical_text` transform (zero-width/bidi
stripped, every newline/control collapsed, angle brackets defanged) so a stored memory can't forge the
fence tags or smuggle a new instruction line into the very prompt it is injected into. The harness
inherits all of that; it must only ever inject `BudgetedRecall.text`, never raw record text.

Pure + dependency-free + offline-testable: `inject_memory` takes a message list and returns a new one;
`MemoryInjector` wraps any `ChatFn` (`Callable[[list[dict]], str]`, the universal seam Verel already
uses everywhere) so a single wrap turns retrieval deterministic for a whole app.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from .recall import recall_budgeted
from .view import MemoryKind, MemoryView

ChatFn = Callable[[list[dict]], str]
QueryFn = Callable[[list[dict]], str]
CaptureFn = Callable[[list[dict], str], None]
Position = Literal["system", "user", "assistant"]

# A modest default so a wrap is safe out of the box (a few facts, never a context blowup). Tune per app.
DEFAULT_BUDGET = 400


def last_user_query(messages: list[dict]) -> str:
    """The deterministic default recall query: the content of the LATEST user turn — what the user is
    asking about right now, which is what prior context should be relevant to. Falls back to the last
    message's content, then to empty (which suppresses injection)."""
    for m in reversed(messages):
        if isinstance(m, dict) and m.get("role") == "user":
            return str(m.get("content", ""))
    if messages and isinstance(messages[-1], dict):
        return str(messages[-1].get("content", ""))
    return ""


def inject_memory(mem: MemoryView, messages: list[dict], *, scope: str | None = None,
                  position: Position = "system", token_budget: int = DEFAULT_BUDGET,
                  kind: MemoryKind | None = None, query: str | None = None,
                  query_fn: QueryFn | None = None, now: float = 0.0) -> list[dict]:
    """Return a NEW message list with relevant graded memory injected at `position`.

    Pure + deterministic — no LLM, no model choice: the same messages + memory state always yield the
    same output, and the caller's list (and its dicts) are never mutated. If no relevant memory is
    recalled (empty query or empty result), the messages are returned unchanged (a shallow copy).

    - `query` / `query_fn`: the recall query is `query` if given, else `query_fn(messages)`, else the
      latest user turn (`last_user_query`). The query is used only as a lexical recall key, never a sink.
    - `position`:
        * `system`   — append the fenced block to the system message (create one at the front if none),
          so the developer's OWN system instructions stay first and authoritative.
        * `user`     — prepend the block inside the latest user turn (the context precedes their words).
        * `assistant`— insert a synthetic assistant turn carrying the block just before the latest user
          turn (the assistant "recalls" it), for setups that prefer memory as prior model context.
    - `token_budget`: bounds the injected block; recall is graded-first and fenced as untrusted DATA.
    """
    if not isinstance(messages, list):
        raise TypeError("messages must be a list of {role, content} dicts")
    if position not in ("system", "user", "assistant"):
        raise ValueError(f"unknown position {position!r}; use 'system' | 'user' | 'assistant'")
    q = query if query is not None else (query_fn or last_user_query)(messages)
    if not (isinstance(q, str) and q.strip()):
        return list(messages)
    block = recall_budgeted(mem, q, token_budget=token_budget, scope=scope, kind=kind, now=now).text
    if not block:
        return list(messages)
    return _inject_at(messages, block, position)


def _inject_at(messages: list[dict], block: str, position: Position) -> list[dict]:
    """Place `block` at `position`, returning a new list; only the touched dict is copied."""
    out: list[dict] = [dict(m) if isinstance(m, dict) else m for m in messages]
    if position == "system":
        for m in out:
            if isinstance(m, dict) and m.get("role") == "system":
                m["content"] = f"{m.get('content') or ''}\n\n{block}".strip()
                return out
        return [{"role": "system", "content": block}, *out]
    if position == "user":
        for i in range(len(out) - 1, -1, -1):
            m = out[i]
            if isinstance(m, dict) and m.get("role") == "user":
                m["content"] = f"{block}\n\n{m.get('content') or ''}".strip()
                return out
        return [*out, {"role": "user", "content": block}]
    # position == "assistant"
    for i in range(len(out) - 1, -1, -1):
        if isinstance(out[i], dict) and out[i].get("role") == "user":
            out.insert(i, {"role": "assistant", "content": block})
            return out
    return [*out, {"role": "assistant", "content": block}]


class MemoryInjector:
    """Wrap any `ChatFn` so every call deterministically gets relevant graded memory injected first — a
    runtime hook, NOT an agent tool. Drop-in: `chat = MemoryInjector(mem, chat, scope=...)` and every
    downstream call to `chat(messages)` now carries fenced, graded, budgeted context with no change to
    the caller and no dependence on the model choosing to retrieve.

    Optional `capture` closes the loop: a `Callable[[messages, reply], None]` run AFTER the reply (e.g.
    `capture_conversation(...)`), so the turn can be written back to memory deterministically too. A
    capture error never breaks the chat call (best-effort, logged by the callable if it wants)."""

    def __init__(self, mem: MemoryView, chat: ChatFn, *, scope: str | None = None,
                 position: Position = "system", token_budget: int = DEFAULT_BUDGET,
                 kind: MemoryKind | None = None, query_fn: QueryFn | None = None,
                 now: float = 0.0, capture: CaptureFn | None = None) -> None:
        self._mem = mem
        self._chat = chat
        self._scope = scope
        self._position = position
        self._budget = token_budget
        self._kind = kind
        self._query_fn = query_fn
        self._now = now
        self._capture = capture

    def __call__(self, messages: list[dict]) -> str:
        augmented = inject_memory(self._mem, messages, scope=self._scope, position=self._position,
                                  token_budget=self._budget, kind=self._kind, query_fn=self._query_fn,
                                  now=self._now)
        reply = self._chat(augmented)
        if self._capture is not None:
            try:
                self._capture(messages, reply)
            except Exception:  # noqa: BLE001 — a write-back failure must never break the chat turn
                pass
        return reply


def capture_conversation(mem: MemoryView, chat: ChatFn, *, scope: str, **remember_kw: object) -> CaptureFn:
    """Build a `capture` hook that writes a turn back to memory via `remember_conversation` — so a
    `MemoryInjector` becomes a full read+write harness. Renders the latest user turn + the assistant
    reply into a transcript and grades it exactly like any conversation (candidate until corroborated /
    attested — trust does not travel). `chat` is the EXTRACTOR LLM (may differ from the reply model)."""
    from .remember import remember_conversation

    def capture(messages: list[dict], reply: str) -> None:
        user = last_user_query(messages)
        transcript = f"user: {user}\nassistant: {reply}"
        remember_conversation(mem, transcript, scope=scope, chat=chat, **remember_kw)  # type: ignore[arg-type]

    return capture
