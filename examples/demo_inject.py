#!/usr/bin/env python3
"""Deterministic memory injection — give an LLM prior context WITHOUT it choosing to retrieve.

The usual RAG/agent pattern makes memory a TOOL the model must decide to call; if it doesn't, the user
re-supplies context they already gave. This is the other path: a developer-designed runtime HOOK that
always folds relevant, graded, fenced memory into the prompt at a position you pick (system / user /
assistant). No tool call, no model judgement — deterministic by construction.

The injected block is graded-first (a VERIFIED fact beats a candidate), token-budgeted, and fenced as
untrusted DATA so a poisoned memory can't smuggle an instruction into the prompt it lands in.

Runs offline, no API key:

    python examples/demo_inject.py
"""
from __future__ import annotations

from verel.memory import LocalMemory, MemoryInjector, inject_memory
from verel.memory.view import MemoryKind, MemoryRecord, make_id, make_key


def remember(mem: LocalMemory, subject: str, predicate: str, text: str, scope: str) -> None:
    key = make_key(subject, predicate, scope)
    mem.write(MemoryRecord(id=make_id(key), kind=MemoryKind.FACT, subject=subject, predicate=predicate,
                           text=text, scope=scope, subj_pred_key=key), ts=1.0)


def main() -> None:
    mem = LocalMemory(":memory:")
    scope = "user:dana"
    # Facts Dana established in EARLIER conversations — she should never have to repeat them.
    remember(mem, "dana", "prefers", "dark mode", scope)
    remember(mem, "dana", "timezone", "US/Pacific", scope)
    remember(mem, "dana", "stack", "python and rust", scope)

    # A brand-new turn. Dana never restates her settings — the hook recalls them by subject overlap.
    # (Lexical recall matches shared tokens like "dana"; an embedder backend matches semantically.)
    messages = [{"role": "system", "content": "You are Dana's coding assistant."},
                {"role": "user", "content": "Set up dana's workspace: timezone, stack, and theme."}]

    print("=== position='system' (memory appended AFTER the developer's system prompt) ===")
    out = inject_memory(mem, messages, scope=scope, position="system", token_budget=200)
    print(out[0]["content"])

    print("\n=== the same, as a drop-in ChatFn wrapper (one wrap = every call gets context) ===")

    def fake_llm(msgs: list[dict]) -> str:
        # A real model would READ the fenced memory and act on it. We just prove it arrived.
        ctx = next((m["content"] for m in msgs if m["role"] == "system"), "")
        knows = [w for w in ("dark mode", "US/Pacific", "python and rust") if w in ctx]
        return f"(model saw {len(knows)} recalled facts: {knows})"

    chat = MemoryInjector(mem, fake_llm, scope=scope, position="system", token_budget=200)
    print(chat(messages))

    print("\n=== position='user' vs 'assistant' — the developer picks where the hook injects ===")
    for pos in ("user", "assistant"):
        out = inject_memory(mem, messages, scope=scope, position=pos, token_budget=120)
        print(f"  {pos:<9} -> roles now: {[m['role'] for m in out]}")

    print("\nDeterministic: no tool call, no model choice — the context is ALWAYS there, and fenced so a"
          "\npoisoned memory can't hijack the prompt it's injected into.")


if __name__ == "__main__":
    main()
