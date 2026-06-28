"""Conversational fact extraction (MEMORY-EXTRACTION-KICKOFF.md, Phase 1).

Turn a conversation into **candidate** SPO facts. The novel part is small on purpose: extraction
itself is what Mem0/Engram/Honcho do; the moat is that every extracted fact is written as
`Trust.CANDIDATE` and only compounds after the *existing* held-out / attested promotion gate
(`promotion`/`principal.import_belief`) makes it `Trust.VERIFIED`. This module does NOT promote —
it only proposes. Phase 2 wires the gate.

House rules honored:
  * `ChatFn` is INJECTED, so the whole module is unit-tested offline with a fake chat (no API key).
  * `parse_extracted_facts` is PURE over the model's output and **fails closed** on hostile/garbage
    JSON — the transcript is untrusted input (a chat turn can try to smuggle a fact), so a bad/oversized
    payload yields `[]`, never a crash or a partial trusted write.
  * Records are content-addressed (`make_key`/`make_id`) and deduped by `subj_pred_key`, so the same
    fact across turns collapses to one identity instead of N duplicates.
  * Extracted confidence is NOT trusted: every fact is the prior (`epistemic_confidence` default), moved
    only later by corroborate/contradict — a self-reported LLM "confidence" is kept as a hint, not belief.
"""

from __future__ import annotations

import json
from collections.abc import Callable

from .view import MemoryKind, MemoryRecord, Trust, make_id, make_key

ChatFn = Callable[[list[dict]], str]

# DoS / poisoning guards on untrusted extractor output.
_MAX_FACTS = 200          # a single conversation can't mint an unbounded number of memories
_MAX_FIELD = 2000         # cap any one SPO field (subject/predicate/object) length

_SYSTEM = (
    "You extract DURABLE, reusable facts from a conversation — preferences, decisions, identities, "
    "stable attributes — NOT transient chatter or one-off requests. Return ONLY a JSON array; each "
    'item is {"subject","predicate","object"} (short noun phrases; subject is who/what the fact is '
    'about, object is the value). Omit anything you are not confident is durably true. No prose, no '
    "code fences — just the JSON array."
)


def _normalize(transcript: object) -> str:
    """Accept a plain string OR a list of {role, content} turns; render to a readable transcript."""
    if isinstance(transcript, str):
        return transcript
    if isinstance(transcript, list):
        lines = []
        for turn in transcript:
            if isinstance(turn, dict):
                role = str(turn.get("role", "user"))
                content = str(turn.get("content", ""))
                lines.append(f"{role}: {content}")
        return "\n".join(lines)
    return str(transcript)


def _clean(v: object) -> str:
    return "" if v is None else str(v).strip()[:_MAX_FIELD]


def parse_extracted_facts(out: str, *, scope: str, now: float = 0.0) -> list[MemoryRecord]:
    """Pure: parse the model's JSON array of {subject,predicate,object} into **candidate** FACT
    records, deduped by `subj_pred_key`. Fails closed (returns []) on non-JSON, a non-array, or
    deeply-nested/oversized hostile input — never a crash, never a partial trusted write."""
    try:
        data = json.loads(out or "[]")
    except (json.JSONDecodeError, RecursionError, ValueError, MemoryError):
        return []
    if not isinstance(data, list):
        return []
    out_records: dict[str, MemoryRecord] = {}  # subj_pred_key -> record (dedup, first wins)
    for item in data[:_MAX_FACTS]:
        if not isinstance(item, dict):
            continue
        subject = _clean(item.get("subject"))
        predicate = _clean(item.get("predicate"))
        obj = _clean(item.get("object"))
        if not (subject and predicate and obj):
            continue
        key = make_key(subject, predicate, scope)
        # LAST statement wins on a (subject,predicate,scope) collision — an in-conversation correction
        # ("actually, light mode") must supersede the earlier value, not be dropped. Cross-conversation
        # supersession against the STORE is Phase 2's job (revise.contradicts); this is within-batch.
        # keep a self-reported salience hint, but NEVER let it move belief (epistemic_confidence)
        hint = item.get("confidence")
        detail: dict[str, object] = {"extracted": True}
        if isinstance(hint, (int, float)):
            detail["salience_hint"] = max(0.0, min(1.0, float(hint)))
        out_records[key] = MemoryRecord(
            id=make_id(key), kind=MemoryKind.FACT, subject=subject, predicate=predicate,
            text=obj, scope=scope, subj_pred_key=key, source="extraction",
            trust=Trust.CANDIDATE, created_ts=now, detail_json=json.dumps(detail),
        )
    return list(out_records.values())


def extract_facts(transcript: object, *, scope: str, chat: ChatFn, now: float = 0.0) -> list[MemoryRecord]:
    """Extract candidate FACT records from a conversation (string or [{role,content}] turns). The
    `chat` callable is injected; offline tests pass a fake one. Returns `Trust.CANDIDATE` records — the
    promotion gate (Phase 2) is what decides which ones become `VERIFIED` and compound."""
    messages = [{"role": "system", "content": _SYSTEM},
                {"role": "user", "content": _normalize(transcript)}]
    try:
        out = chat(messages)
    except Exception:  # a flaky/failing extractor must not crash the caller — just yield nothing
        return []
    return parse_extracted_facts(out if isinstance(out, str) else "", scope=scope, now=now)
