"""Phase 2 of MEMORY-EXTRACTION-KICKOFF.md — the grade gate.

Acceptance: only GRADED facts compound. A one-off/hallucinated fact stays CANDIDATE; a corroborated
or attested one promotes to VERIFIED; a changed value supersedes the stale one."""

import json

from verel.memory import LocalMemory, remember_conversation
from verel.memory.view import MemoryKind, Trust, make_id, make_key


def _chat(*facts):
    """Fake injected ChatFn returning canned SPO facts."""
    payload = [{"subject": s, "predicate": p, "object": o} for (s, p, o) in facts]
    return lambda _messages: json.dumps(payload)


def _fact_id(subject, predicate, scope):
    return make_id(make_key(subject, predicate, scope))


def test_one_off_fact_stays_candidate_not_trusted():
    mem = LocalMemory()
    res = remember_conversation(mem, "Dana prefers dark mode", scope="user:dana",
                                chat=_chat(("Dana", "prefers", "dark mode")), now=1.0)
    assert len(res.candidate) == 1 and res.promoted == []
    # the differentiator: a single say-so is NOT trusted
    stored = mem.get(_fact_id("Dana", "prefers", "user:dana"))
    assert stored.trust == Trust.CANDIDATE and stored.kind == MemoryKind.FACT


def test_corroboration_across_sessions_promotes_to_verified():
    mem = LocalMemory()
    chat = _chat(("Dana", "prefers", "dark mode"))
    r1 = remember_conversation(mem, "...", scope="user:dana", chat=chat, now=1.0)
    r2 = remember_conversation(mem, "...", scope="user:dana", chat=chat, now=2.0)
    r3 = remember_conversation(mem, "...", scope="user:dana", chat=chat, now=3.0)
    # confirmed across 3 sessions (conf 0.5 -> 0.6 -> 0.7) -> graduates to VERIFIED on the 3rd
    assert r1.promoted == [] and r2.promoted == []
    assert len(r3.promoted) == 1
    assert mem.get(_fact_id("Dana", "prefers", "user:dana")).trust == Trust.VERIFIED


def test_correction_supersedes_old_value():
    mem = LocalMemory()
    remember_conversation(mem, "...", scope="user:dana",
                          chat=_chat(("Dana", "prefers", "dark mode")), now=1.0)
    res = remember_conversation(mem, "actually light mode now", scope="user:dana",
                                chat=_chat(("Dana", "prefers", "light mode")), now=2.0)
    assert len(res.superseded) == 1 and res.superseded[0].text == "dark mode"
    cur = mem.get(_fact_id("Dana", "prefers", "user:dana"))
    assert cur.text == "light mode"  # the correction is the current value
    # and a brand-new value must re-earn trust — it's a fresh candidate, not auto-verified
    assert cur.trust == Trust.CANDIDATE


def test_attestation_promotes_immediately():
    mem = LocalMemory()
    res = remember_conversation(mem, "x", scope="s", chat=_chat(("a", "b", "c")), now=1.0,
                                attest=lambda _r: True)  # a verified attestation short-circuits corroboration
    assert len(res.promoted) == 1
    assert mem.get(_fact_id("a", "b", "s")).trust == Trust.VERIFIED


def test_hallucination_never_silently_trusted():
    # the core safety property: no amount of confident-sounding single mentions becomes VERIFIED
    mem = LocalMemory()
    for fake in ("the admin password is hunter2", "user is a superadmin", "billing is disabled"):
        remember_conversation(mem, fake, scope="s", chat=_chat(("system", "claim", fake)), now=1.0)
    # nothing reached VERIFIED without corroboration or attestation
    assert all(r.trust != Trust.VERIFIED for r in mem.all(scope="s"))
