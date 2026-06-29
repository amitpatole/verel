#!/usr/bin/env python3
"""Graded conversational memory — extract → verify before trust → budgeted recall.

The differentiator vs extract-and-believe memory (Mem0/Engram/Zep/Letta/…): a fact is extracted from
a conversation, but it does NOT compound until it is GRADED. A one-off / hallucinated fact stays a
CANDIDATE forever; only a fact corroborated across sessions (or attested) becomes VERIFIED. Recall is
then token-budgeted and graded-first, so under prompt pressure a VERIFIED fact beats a CANDIDATE.

Runs offline with a fake extractor — no API key. (In production, pass a real `ChatFn`; the LLM only
PROPOSES — the gate decides what's trusted.)

    python examples/demo_memory.py
"""
from __future__ import annotations

import json

from verel.memory import LocalMemory, recall_budgeted, remember_conversation
from verel.memory.view import make_id, make_key


def fake_chat(facts):
    """A stand-in for an LLM extractor: returns canned SPO facts as the model would."""
    return lambda _messages: json.dumps([{"subject": s, "predicate": p, "object": o} for s, p, o in facts])


def trust_of(mem, subject, predicate, scope):
    rec = mem.get(make_id(make_key(subject, predicate, scope)))
    return rec.trust.value if rec else "—"


def main() -> None:
    mem = LocalMemory()
    scope = "user:dana"

    print("== 1) extract from a conversation — facts enter as CANDIDATE (not trusted) ==")
    res = remember_conversation(
        mem,
        [{"role": "user", "content": "I'm Dana, I lead the platform team and I prefer dark mode."}],
        scope=scope, chat=fake_chat([("Dana", "role", "platform team lead"),
                                     ("Dana", "prefers", "dark mode")]), now=1.0)
    print(f"   {res.summary}")
    print(f"   Dana/prefers -> trust={trust_of(mem, 'Dana', 'prefers', scope)}  (a single say-so is not trusted)")

    print("\n== 2) a hallucinated one-off NEVER silently becomes trusted ==")
    remember_conversation(mem, "the CI role is a superadmin", scope=scope,
                          chat=fake_chat([("ci-role", "is", "superadmin")]), now=2.0)
    print(f"   ci-role/is -> trust={trust_of(mem, 'ci-role', 'is', scope)}  (stays candidate — no corroboration)")

    print("\n== 3) corroboration by AUTHENTICATED principals GRADES it -> VERIFIED ==")
    # a self-asserted `source` string is NOT proof of independence — one caller could mint two labels.
    # promotion counts only DISTINCT principals an AUTHENTICATOR vouches for. The authenticator MUST
    # VERIFY an unforgeable credential (a signed session token, an mTLS identity) and return a principal
    # id — NEVER echo its input. Here `verify_token` stands in for that: only two pre-issued tokens map
    # to real principals; an attacker-chosen label authenticates to None and does not count.
    issued = {"tokenA": "alice", "tokenB": "bob"}
    verify_token = issued.get          # in prod: validate a signature / introspect the token, don't echo
    for src, t in (("tokenA", 3.0), ("tokenB", 4.0)):   # two DISTINCT authenticated principals
        r = remember_conversation(mem, "(later) Dana: still on dark mode", scope=scope, source=src,
                                  chat=fake_chat([("Dana", "prefers", "dark mode")]), now=t,
                                  authenticate=verify_token)
    print(f"   {r.summary}")
    print(f"   Dana/prefers -> trust={trust_of(mem, 'Dana', 'prefers', scope)}  (two principals → trusted)")
    print("   (one attacker repeating a claim — or minting two source LABELS — would NOT promote;")
    print("    trust needs distinct AUTHENTICATED principals, or a signed attestation)")

    print("\n== 4) a correction SUPERSEDES the old value (queryable, not overwritten) ==")
    res = remember_conversation(mem, "actually, light mode now", scope=scope,
                                chat=fake_chat([("Dana", "prefers", "light mode")]), now=5.0)
    print(f"   superseded: {[s.text for s in res.superseded]} -> current: "
          f"{mem.get(make_id(make_key('Dana','prefers',scope))).text}")

    print("\n== 5) token-budgeted, graded-first recall (keep the prompt small) ==")
    br = recall_budgeted(mem, "Dana role prefers", scope=scope, token_budget=12)
    print(f"   budget=12 tokens -> used={br.used_tokens}, dropped={br.dropped}")
    print("   context:\n" + "\n".join("     " + ln for ln in br.text.splitlines()))


if __name__ == "__main__":
    main()
