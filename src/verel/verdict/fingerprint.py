"""Scrubbed, Nirvana-computed fingerprints + issue-set signature (§7.2).

AgentVision's `issue_signature` is message-based (`message.strip().lower()`), which is too
brittle to be the fleet-wide identity: any line number / seed / timestamp / float yields a
new signature -> progressed=true forever -> stuck never fires. Verel computes a *scrubbed*
fingerprint per GraderKind and recomputes progressed/stuck from its own log.
"""

from __future__ import annotations

import re
from hashlib import blake2s

from .models import GraderKind, Issue, Report

_ADDR = re.compile(r"0x[0-9a-f]+")
_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
_TS = re.compile(r"\b\d{4}-\d{2}-\d{2}t[\d:.]+z?\b")
_PATH = re.compile(r"[/\\][\w./\\-]+")
_FLOAT = re.compile(r"-?\d+\.\d+")
# Boundary-free so digits glued to units are scrubbed too ("12px" -> "<num>px"); floats are
# already replaced above, so this never bites into a "<float>" token.
_INT = re.compile(r"\d+")


def canonicalize(msg: str) -> str:
    """Scrub volatile tokens so the same logical failure hashes stably across reruns."""
    s = msg.strip().lower()
    s = _ADDR.sub("<addr>", s)
    s = _UUID.sub("<uuid>", s)
    s = _TS.sub("<ts>", s)
    s = _PATH.sub("<path>", s)
    s = _FLOAT.sub("<float>", s)
    s = _INT.sub("<num>", s)
    return s


def fingerprint(i: Issue) -> str:
    """Per-GraderKind stable identity for one issue. NIRVANA-computed."""
    d = i.detail
    if i.source == GraderKind.TEST:
        key = f"{d.get('test_id', '')}|{canonicalize(i.message)}"
    elif i.source == GraderKind.TYPECHECK:
        key = f"{d.get('rule_code', '')}|{i.locator}|{d.get('symbol', '')}"
    elif i.source == GraderKind.LINT:
        key = f"{d.get('rule_id', '')}|{i.locator}"
    elif i.source == GraderKind.SECURITY:
        key = f"{d.get('cwe', '')}|{i.locator}|{canonicalize(i.message)}"
    else:
        key = f"{i.kind.value}|{i.locator}|{canonicalize(i.message)}"
    return blake2s(key.encode()).hexdigest()[:16]


def assign(report: Report) -> Report:
    """Populate `fingerprint` on every issue in place; returns the same report."""
    for i in report.issues:
        i.fingerprint = fingerprint(i)
    return report


def issue_signature(report: Report) -> frozenset[tuple[str, str]]:
    """Identity of the issue *set* — used for progress/stuck detection."""
    return frozenset((i.kind.value, i.fingerprint or fingerprint(i)) for i in report.issues)
