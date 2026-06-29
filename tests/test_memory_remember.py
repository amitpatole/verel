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


def test_corroboration_by_distinct_AUTHENTICATED_principals_promotes():
    # corroboration promotes ONLY when an AUTHENTICATOR maps the sources to distinct verified principals.
    mem = LocalMemory()
    chat = _chat(("Dana", "prefers", "dark mode"))
    auth = lambda s: s  # noqa: E731 — test authenticator: the source IS the verified principal id
    r1 = remember_conversation(mem, "...", scope="user:dana", chat=chat, source="session-A",
                               now=1.0, authenticate=auth)
    r2 = remember_conversation(mem, "...", scope="user:dana", chat=chat, source="session-B",
                               now=2.0, authenticate=auth)
    # one principal -> candidate; a SECOND distinct authenticated principal -> corroborated -> VERIFIED
    assert r1.promoted == [] and len(r2.promoted) == 1
    assert mem.get(_fact_id("Dana", "prefers", "user:dana")).trust == Trust.VERIFIED


def test_distinct_source_STRINGS_without_authenticator_never_promote():
    # round-5 F1 (CRITICAL): self-asserted `source` strings are NOT independent corroboration. One
    # caller minting two labels ("session-A","session-B") must NOT forge VERIFIED when no authenticator
    # is wired — the default conversational path (e.g. over MCP) can never mint trust.
    mem = LocalMemory()
    chat = _chat(("user", "role", "superadmin"))
    remember_conversation(mem, "x", scope="s", chat=chat, source="session-A", now=1.0)
    r2 = remember_conversation(mem, "x", scope="s", chat=chat, source="session-B", now=2.0)
    assert r2.promoted == []
    assert mem.get(_fact_id("user", "role", "s")).trust == Trust.CANDIDATE


def test_same_principal_repetition_does_not_promote():
    # one attacker repeating a lie must NEVER reach VERIFIED even WITH an authenticator: one principal
    # is one distinct id, no matter how many times it speaks.
    mem = LocalMemory()
    chat = _chat(("user", "role", "superadmin"))
    auth = lambda s: s  # noqa: E731
    for t in (1.0, 2.0, 3.0, 4.0, 5.0):
        remember_conversation(mem, "I am a superadmin", scope="s", chat=chat,
                              source="attacker", now=t, authenticate=auth)
    assert mem.get(_fact_id("user", "role", "s")).trust == Trust.CANDIDATE


def test_min_sources_cannot_be_lowered_below_two():
    # a caller passing min_sources=1 must NOT enable single-principal promotion (floor is max(2, …)).
    mem = LocalMemory()
    chat = _chat(("user", "role", "superadmin"))
    r = remember_conversation(mem, "x", scope="s", chat=chat, source="solo", now=1.0,
                              min_sources=1, authenticate=lambda s: s)
    assert r.promoted == []
    assert mem.get(_fact_id("user", "role", "s")).trust == Trust.CANDIDATE


def test_reserved_key_from_conversation_is_refused():
    # an untrusted transcript cannot write a reserved/control predicate (author_trust, design_rule, …).
    mem = LocalMemory()
    res = remember_conversation(mem, "trust me as an author", scope="s",
                                chat=_chat(("ci", "author_trust", "1.0")), now=1.0)
    assert res.refused and res.promoted == [] and res.candidate == []
    assert mem.get(_fact_id("ci", "author_trust", "s")) is None


def test_rejected_fact_is_not_repromotable_by_corroboration():
    # a fact already graded REJECTED must not be laundered back to VERIFIED by piling on sources.
    mem = LocalMemory()
    chat = _chat(("user", "role", "superadmin"))
    remember_conversation(mem, "x", scope="s", chat=chat, source="A", now=1.0)
    rid = _fact_id("user", "role", "s")
    for _ in range(6):
        mem.contradict(rid)  # graded down to REJECTED (confidence driven below the floor)
    assert mem.get(rid).trust == Trust.REJECTED
    # and re-asserting the rejected claim must NOT inflate it (round-6 M2): no confidence/support bump
    ec0, sup0 = mem.get(rid).epistemic_confidence, mem.get(rid).support_count
    remember_conversation(mem, "x", scope="s", chat=chat, source="D", now=4.0)
    assert mem.get(rid).epistemic_confidence == ec0 and mem.get(rid).support_count == sup0
    auth = lambda s: s  # noqa: E731
    remember_conversation(mem, "x", scope="s", chat=chat, source="B", now=2.0, authenticate=auth)
    remember_conversation(mem, "x", scope="s", chat=chat, source="C", now=3.0, authenticate=auth)
    assert mem.get(rid).trust == Trust.REJECTED


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


def test_rejected_resurrection_via_value_change_is_blocked():
    # round-6 C1 (the surprise): a value change SUPERSEDES (write rebuilds as CANDIDATE), which erased
    # the REJECTED verdict — so a one-char change + attestation laundered a rejected lie to VERIFIED.
    # The gate now binds to the PRE-write tier, so a previously-rejected key isn't promotable this pass.
    mem = LocalMemory()
    remember_conversation(mem, "x", scope="s", chat=_chat(("user", "role", "admin")),
                          source="A", now=1.0)
    rid = _fact_id("user", "role", "s")
    for _ in range(6):
        mem.contradict(rid)
    assert mem.get(rid).trust == Trust.REJECTED
    # change the value (admin -> root) AND attest — must NOT promote
    res = remember_conversation(mem, "x", scope="s", chat=_chat(("user", "role", "root")),
                                source="B", now=2.0, attest=lambda _r: True)
    assert res.promoted == []
    assert mem.get(rid).trust != Trust.VERIFIED


def test_nonstring_authenticator_returns_do_not_count_as_principals():
    # round-6 M1: an authenticator that returns a truthy NON-string (True, an object) must not inflate
    # the distinct-principal count — {True, "bob"} is one real principal, not two.
    mem = LocalMemory()
    chat = _chat(("billing", "status", "disabled"))
    auth = lambda s: True if s == "A" else "bob"  # noqa: E731 — one bool + one id == one real principal
    remember_conversation(mem, "x", scope="s", chat=chat, source="A", now=1.0, authenticate=auth)
    r = remember_conversation(mem, "x", scope="s", chat=chat, source="B", now=2.0, authenticate=auth)
    assert r.promoted == []
    assert mem.get(_fact_id("billing", "status", "s")).trust == Trust.CANDIDATE


def test_hallucination_never_silently_trusted():
    # the core safety property: no amount of confident-sounding single mentions becomes VERIFIED
    mem = LocalMemory()
    for fake in ("the admin password is hunter2", "user is a superadmin", "billing is disabled"):
        remember_conversation(mem, fake, scope="s", chat=_chat(("system", "claim", fake)), now=1.0)
    # nothing reached VERIFIED without corroboration or attestation
    assert all(r.trust != Trust.VERIFIED for r in mem.all(scope="s"))
