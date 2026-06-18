"""LLM-driven manager — the manager IS an agent now (§6.1).

A manager agent is given a goal (and optional context/artifacts) and emits a structured
fan-out decision. The control plane remains the authority: whatever the model returns is
parsed, then **validated and clamped** by `validate_fanout`/`clamp` before any task is
admitted. If the model's output is unusable, we fall back to the deterministic planner —
the fleet degrades safely, never crashes on a bad decision.
"""

from __future__ import annotations

import json
from typing import Callable

from ..agents import llm
from .manager import FanOut, Subtask, clamp, plan_over_artifacts, validate_fanout

ChatFn = Callable[[list[dict]], str]

_SYSTEM = (
    "You are a MANAGER agent in an eval-gated build fleet. Given a goal and a list of "
    "artifacts (files), decide whether to fan out to independent parallel workers or do it "
    "yourself. Fan out ONLY when subtasks are mutually INDEPENDENT (no inter-subtask deps), "
    "each individually verifiable, and worth parallelizing. Respond as STRICT JSON only:\n"
    '{"decision":"fan_out"|"self","rationale":"...","concurrency_cap":N,'
    '"subtasks":[{"id":"...","goal":"...","artifact":"<path or null>","verifier":"sight"}]}\n'
    "Each subtask must own exactly one artifact. No prose outside the JSON."
)


def _default_chat(messages: list[dict]) -> str:
    return llm.chat(messages).content


def _parse(reply: str) -> dict | None:
    s, e = reply.find("{"), reply.rfind("}")
    if s == -1 or e == -1:
        return None
    try:
        return json.loads(reply[s : e + 1])
    except json.JSONDecodeError:
        return None


def decide_fanout(goal: str, *, artifacts: list[str] | None = None, context: str = "",
                  chat: ChatFn | None = None, max_subtasks: int = 8) -> FanOut:
    """Ask the manager agent to decompose `goal`. Always returns a VALID, clamped FanOut:
    the model proposes, the plane disposes; invalid output falls back to the deterministic
    one-worker-per-artifact plan."""
    chat = chat or _default_chat
    artifacts = artifacts or []
    user = (
        f"Goal: {goal}\nContext: {context or '(none)'}\n"
        f"Artifacts ({len(artifacts)}):\n" + "\n".join(f"- {a}" for a in artifacts)
    )
    fallback = (plan_over_artifacts(goal, artifacts) if artifacts
                else FanOut(decision="self", rationale="no artifacts to fan out over"))

    parsed = _parse(chat([{"role": "system", "content": _SYSTEM}, {"role": "user", "content": user}]))
    if not parsed:
        return fallback
    try:
        subs = [
            Subtask(id=str(s["id"]), goal=s.get("goal", ""), artifact=s.get("artifact"),
                    verifier=s.get("verifier", "sight"))
            for s in parsed.get("subtasks", [])
        ][:max_subtasks]
        fo = FanOut(decision=parsed.get("decision", "fan_out"),
                    rationale=parsed.get("rationale", goal),
                    subtasks=subs, concurrency_cap=int(parsed.get("concurrency_cap", 4)))
    except (KeyError, TypeError, ValueError):
        return fallback

    fo = clamp(fo)
    ok, _ = validate_fanout(fo)
    if not ok:
        return fallback
    # Don't trust the model to have covered every artifact: if it dropped some, fall back so
    # nothing goes unverified (silent under-coverage is the failure mode we refuse).
    if artifacts and {s.artifact for s in fo.subtasks if s.artifact} != set(artifacts):
        return fallback
    return fo
