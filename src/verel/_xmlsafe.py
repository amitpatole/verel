"""Hardened XML parsing for UNTRUSTED artifacts, shared by the telecom graders and the document guard.

Factored out of `verel.ci.telecom_model` (which re-exports it with its telecom-specific missing-dep
hint preserved) so `verel.guard` parses hostile OOXML/ODF parts with the identical XXE /
billion-laughs / resource-bound hardening. defusedxml stays a lazy import behind an extra; when it
is absent the caller's named extra is surfaced and parsing FAILS CLOSED — untrusted XML is never
parsed with the stdlib parser as a fallback.
"""

from __future__ import annotations

from typing import Any


class MissingXmlDep(RuntimeError):
    """Safe XML parsing needs defusedxml (behind an extra) but it is not installed."""


_MAX_XML_ELEMENTS = 1_000_000
_MAX_XML_DEPTH = 64
_MAX_XML_TEXT = 4096
_MAX_XML_ATTRS = 4096  # per-element attribute count (defense-in-depth, post-parse)


def xml_root(raw: str, *, dep_hint: str = "safe XML parsing needs defusedxml",
             max_text: int = _MAX_XML_TEXT) -> Any:
    """Parse an UNTRUSTED XML artifact SAFELY. Uses defusedxml with DTD, external entities, and
    entity expansion ALL forbidden (kills XXE + billion-laughs at the door), then walks once to
    bound element count/depth/text (defusedxml does not bound those). Fails closed to a clean
    ValueError — never a raw parser traceback on attacker input. `dep_hint` names the extra the
    caller ships defusedxml behind (telecom vs guard), raised as `MissingXmlDep` when absent;
    `max_text` is the per-text-node bound (a prose document legitimately carries longer runs than
    a PM-XML counter file, so the guard raises it — the total is still bounded upstream by the
    caller's member-size cap)."""
    try:
        from defusedxml import DefusedXmlException  # type: ignore[import-untyped]
        from defusedxml.ElementTree import fromstring  # type: ignore[import-untyped]
    except ModuleNotFoundError as e:  # pragma: no cover - exercised via the install-hint tests
        raise MissingXmlDep(dep_hint) from e
    from xml.etree.ElementTree import ParseError
    # Cheap PRE-parse bound: `fromstring` materializes the WHOLE tree before any post-walk guard runs,
    # so a 24 MB artifact would balloon to ~GBs of RSS before we could reject it (red-team R1 F1 / R2 —
    # the "guard after the expensive op" shape). The parse cost scales with elements AND attributes;
    # '<' bounds elements and '=' bounds attribute assignments (both over-count, i.e. conservative), so
    # their sum is a cheap (~tens of ms) upper bound on parse work — reject here, before parsing.
    s = raw or ""
    if s.count("<") + s.count("=") > _MAX_XML_ELEMENTS:
        raise ValueError("oversized XML artifact (element/attribute count)")
    try:
        root = fromstring(raw or "", forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except (ParseError, DefusedXmlException, RecursionError, ValueError) as e:
        raise ValueError(f"invalid XML artifact: {type(e).__name__}") from e
    n = 0
    stack = [(root, 1)]
    while stack:
        el, depth = stack.pop()
        n += 1
        if n > _MAX_XML_ELEMENTS:
            raise ValueError("oversized XML artifact (element count)")
        if depth > _MAX_XML_DEPTH:
            raise ValueError("over-deep XML artifact")
        if el.text and len(el.text) > max_text:
            raise ValueError("oversized XML text node")
        if len(el.attrib) > _MAX_XML_ATTRS:
            raise ValueError("over-attributed XML element")
        for child in el:
            stack.append((child, depth + 1))
    return root


def local_name(tag: object) -> str:
    """The namespace-stripped local element name (producers mangle namespaces; match locally)."""
    t = str(tag)
    return t.rsplit("}", 1)[-1] if "}" in t else t
