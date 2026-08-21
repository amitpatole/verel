"""Lexical injection patterns over untrusted document text (dependency-free, no LLM).

Detects instructions aimed at the CONSUMING model: override/role/concealment/tool-inducement/
propagation imperatives, rendered-fetch exfil vectors, and the encoded-payload machinery reused
from `verel._hostile` (encoded runs, decode-and-execute lures, decode-and-rescan).

Severity policy: an imperative in VISIBLE text is WARNING at most (documents *about* prompt
injection must surface, not gate) except concealment/propagation/exfil, which have near-zero
legitimate use. The same imperative in a HIDDEN span (`hidden=True`, set by the structural
scanners) escalates to CRITICAL — the conjunction of hiding and instruction is the attack.

All quantifiers are BOUNDED (the house ReDoS rule); scanning runs over `_hostile.fold(text)`
(zero-width stripped, NFKC, homoglyphs folded) so invisible-character splitting or lookalike
codepoints can't dodge a pattern the model would still read through. Span offsets ground into
the folded stream.
"""

from __future__ import annotations

import re

from .. import _hostile
from ..verdict.models import Confidence, IssueKind, Severity
from .model import Finding

# Each family: (detection_id, kind, visible severity, pattern). Hidden-context escalation below.
_W = r"[ \t]{0,8}"        # bounded intra-phrase whitespace
_ART = r"(?:the|your|all|any|every|previous|prior|above|earlier|initial|original|these|this){0,1}"

_OVERRIDE = re.compile(
    rf"\b(?:ignore|disregard|forget|override|bypass){_W}(?:{_ART}{_W}){{0,3}}"
    rf"(?:instructions?|prompts?|rules?|context|guidelines?|directives?|training)\b"
    rf"|\bnew{_W}(?:system{_W})?(?:prompt|instructions?){_W}:"
    rf"|\byour{_W}(?:real|true|actual){_W}(?:instructions?|task|goal){_W}(?:is|are)\b",
    re.IGNORECASE,
)
_ROLE = re.compile(
    rf"\byou{_W}are{_W}(?:now|no{_W}longer)\b"
    rf"|\bfrom{_W}now{_W}on{_W}you\b"
    rf"|\bact{_W}as{_W}(?:a|an|the|if)\b"
    rf"|\bpretend{_W}(?:to{_W}be|you{_W}are)\b"
    rf"|\bassume{_W}the{_W}role\b"
    rf"|\byour{_W}new{_W}(?:role|persona|identity)\b",
    re.IGNORECASE,
)
_CONCEAL = re.compile(
    rf"\b(?:do{_W}not|don'?t|never){_W}(?:tell|reveal|inform|mention|show|disclose|alert|notify)\b"
    rf"[^.\n]{{0,60}}\b(?:user|human|anyone|reader|operator)\b"
    rf"|\bwithout{_W}(?:informing|telling|alerting|notifying)\b"
    rf"|\bkeep{_W}(?:this|it){_W}(?:hidden|secret|confidential|between{_W}us)\b"
    rf"|\bdo{_W}not{_W}(?:mention|acknowledge|reference){_W}(?:this|these)\b",
    re.IGNORECASE,
)
_TOOL_INDUCE = re.compile(
    rf"\b(?:call|invoke|use|run|execute|trigger){_W}(?:the{_W})?[\w.-]{{1,40}}{_W}"
    rf"(?:tool|function|command|plugin|action)\b"
    rf"|\brun{_W}the{_W}following\b"
    rf"|\bexecute{_W}(?:the{_W}following|this)\b"
    rf"|\bsend{_W}(?:an?{_W})?(?:email|message|request)\b[^.\n]{{0,80}}\bto\b"
    rf"|\b(?:fetch|browse|navigate|go){_W}to{_W}https?://",
    re.IGNORECASE,
)
# A rendered markdown image auto-fetches on display: an image URL with a query string is a data
# sink the model can be induced to fill (the classic exfil channel). A plain link needs a click,
# so only the image form and explicit "post/send … to http" count here.
_EXFIL_MD = re.compile(
    r"!\[[^\]\n]{0,200}\]\(\s*https?://[^)\s]{1,300}[?&][^)\s]{1,300}\)"
    r"|\b(?:post|send|upload|exfiltrate|transmit)\b[^.\n]{0,60}\bto\s+https?://",
    re.IGNORECASE,
)
_PROPAGATE = re.compile(
    rf"\b(?:include|insert|copy|add|embed|append|place){_W}(?:this|these|the{_W}following)\b"
    rf"[^.\n]{{0,80}}\b(?:in|into|to|at){_W}(?:every|all|each|any|future)\b"
    rf"[^.\n]{{0,40}}\b(?:files?|documents?|outputs?|responses?|replies|messages?|artifacts?)\b"
    rf"|\bwhen{_W}(?:you{_W})?(?:generat|creat|writ|produc)\w{{0,4}}{_W}[^.\n]{{0,60}}"
    rf"\b(?:include|insert|copy|embed)\b",
    re.IGNORECASE,
)

# (id, kind, visible-context severity, escalates-when-hidden, pattern)
_FAMILIES: list[tuple[str, IssueKind, Severity, bool, re.Pattern[str]]] = [
    ("LEX-001", IssueKind.INJECTION, Severity.WARNING, True, _OVERRIDE),
    ("LEX-002", IssueKind.INJECTION, Severity.WARNING, True, _ROLE),
    ("LEX-003", IssueKind.INJECTION, Severity.ERROR, True, _CONCEAL),
    ("LEX-004", IssueKind.INJECTION, Severity.WARNING, True, _TOOL_INDUCE),
    ("LEX-005", IssueKind.EXFIL_VECTOR, Severity.ERROR, True, _EXFIL_MD),
    ("LEX-006", IssueKind.INJECTION, Severity.ERROR, True, _PROPAGATE),
]

_MESSAGES = {
    "LEX-001": "instruction-override directive",
    "LEX-002": "role/persona reassignment directive",
    "LEX-003": "concealment directive (hide activity from the user)",
    "LEX-004": "tool/command invocation inducement",
    "LEX-005": "rendered-fetch exfiltration vector",
    "LEX-006": "propagation directive (replicate into generated output)",
    "LEX-007": "encoded payload run",
    "LEX-008": "decode-and-execute / shell-command lure",
    "LEX-009": "encoded token decodes to a hostile payload",
}

# Cap the number of expensive decode-and-rescan candidates per scanned unit — a 2 MiB text with
# hundreds of thousands of tokens must not turn LEX-009 into a DoS on the scanner itself.
_MAX_DECODE_TOKENS = 2000


def _snippet(s: str) -> str:
    """A defanged, bounded excerpt safe to carry inside a Report (never a live payload)."""
    from ..memory.view import canonical_text
    return canonical_text(s)[:120]


def _mk(det: str, kind: IssueKind, sev: Severity, m: re.Match[str], *, hidden: bool,
        confidence: Confidence = Confidence.HIGH) -> Finding:
    text = m.group(0)
    from ..memory.view import rejected_key
    return Finding(
        detection_id=det, kind=kind, severity=sev, confidence=confidence,
        message=f"{_MESSAGES[det]}: “{_snippet(text)}”",
        locator=f"text@{m.start()}-{m.end()}", hidden=hidden,
        detail={"detection_id": det, "span_key": rejected_key(text), "snippet": _snippet(text)},
    )


def scan_text(text: str, *, origin: str = "", hidden: bool = False) -> list[Finding]:
    """Scan one unit of untrusted text. `hidden=True` (the caller found the text in a channel a
    human reader does not see) escalates imperative families to CRITICAL — the worm conjunction."""
    folded = _hostile.fold(text)[: 2 * 1024 * 1024]
    findings: list[Finding] = []
    for det, kind, sev, escalates, pat in _FAMILIES:
        for m in pat.finditer(folded):
            eff = Severity.CRITICAL if (hidden and escalates) else sev
            findings.append(_mk(det, kind, eff, m, hidden=hidden))
    for m in _hostile.ENCODED_RUN.finditer(folded):
        # a visible encoded run is advisory (hashes/UUIDs exist); a HIDDEN encoded blob is the
        # smuggling shape itself — text a reader can't see AND can't read is not legitimate content,
        # so it gates (security round 4, R4-1: catches multi-layer encodings a decode pass can't peel).
        enc_sev = Severity.ERROR if hidden else Severity.WARNING
        findings.append(_mk("LEX-007", IssueKind.INJECTION, enc_sev, m,
                            hidden=hidden, confidence=Confidence.MEDIUM))
    # entity/charcode-encoded imperative (e.g. &#105;&#103;… → "ig…"): decode one layer and re-scan
    entity_decoded = _decode_entities(folded)
    if entity_decoded and entity_decoded != folded and _families_hit(entity_decoded):
        from ..memory.view import rejected_key
        eff = Severity.CRITICAL if hidden else Severity.ERROR
        findings.append(Finding(
            detection_id="LEX-009", kind=IssueKind.INJECTION, severity=eff,
            confidence=Confidence.HIGH,
            message=f"{_MESSAGES['LEX-009']}: “{_snippet(entity_decoded)}”",
            locator="text@entity", hidden=hidden,
            detail={"detection_id": "LEX-009", "span_key": rejected_key(entity_decoded),
                    "snippet": _snippet(entity_decoded)}))
    for pat in (_hostile.DECODE_EXEC, _hostile.SHELL_CMD):
        for m in pat.finditer(folded):
            eff = Severity.CRITICAL if hidden else Severity.ERROR
            findings.append(_mk("LEX-008", IssueKind.INJECTION, eff, m, hidden=hidden))
    # Decode-and-rescan (the robust catch for the encoding class), bounded to plausible tokens.
    checked = 0
    pos = 0
    for tok in folded.split():
        start = folded.find(tok, pos)
        pos = start + len(tok) if start >= 0 else pos
        if checked >= _MAX_DECODE_TOKENS:
            break
        if len(tok) < 12 or _hostile.b64ish(tok) is None:
            continue
        checked += 1
        # decoded_unsafe catches secrets/shell in the plaintext; the guard ALSO decodes and re-scans
        # for INJECTION imperatives — a base64-wrapped "ignore previous instructions" is a second-order
        # injection the model decodes downstream, which the secret/shell denylist alone would miss.
        decoded_imperative = any(has_imperative(dec) for dec in _hostile.decode_candidates(tok))
        if _hostile.decoded_unsafe(tok) or decoded_imperative:
            eff = Severity.CRITICAL if hidden else Severity.ERROR
            from ..memory.view import rejected_key
            findings.append(Finding(
                detection_id="LEX-009", kind=IssueKind.INJECTION, severity=eff,
                confidence=Confidence.HIGH,
                message=f"{_MESSAGES['LEX-009']}: “{_snippet(tok)}”",
                locator=f"text@{start}-{start + len(tok)}", hidden=hidden,
                detail={"detection_id": "LEX-009", "span_key": rejected_key(tok),
                        "snippet": _snippet(tok)},
            ))
    return findings


_ENTITY = re.compile(r"&#x([0-9a-fA-F]{1,6});|&#([0-9]{1,7});")
_DECIMAL_CHARCODES = re.compile(r"(?:\b\d{1,3}[,\s]+){5,}\d{1,3}\b")


def _decode_entities(text: str) -> str | None:
    """Decode HTML numeric entities (&#105; / &#x69;) and decimal char-code runs to plaintext, so an
    entity- or charcode-encoded imperative in a comment/body is revealed (security round 3, R3-1)."""
    if _ENTITY.search(text):
        def sub(m: re.Match[str]) -> str:
            code = int(m.group(1), 16) if m.group(1) else int(m.group(2))
            return chr(code) if 0 <= code <= 0x10FFFF else ""
        return _ENTITY.sub(sub, text)
    m = _DECIMAL_CHARCODES.search(text)
    if m:
        try:
            return "".join(chr(int(n)) for n in re.split(r"[,\s]+", m.group(0)) if n and int(n) < 0x110000)
        except (ValueError, OverflowError):
            return None
    return None


def _families_hit(folded: str) -> bool:
    return any(pat.search(folded) for _, _, _, _, pat in _FAMILIES) or bool(
        _hostile.DECODE_EXEC.search(folded) or _hostile.SHELL_CMD.search(folded))


def has_imperative(text: str) -> bool:
    """True when any imperative family matches — used by structural scanners to decide whether a
    hidden span is the worm conjunction (→ CRITICAL) or bare hidden text (→ WARNING). Also decodes
    one entity/charcode layer so an encoded imperative is revealed."""
    folded = _hostile.fold(text)[: 2 * 1024 * 1024]
    if _families_hit(folded):
        return True
    decoded = _decode_entities(folded)
    return bool(decoded and decoded != folded and _families_hit(decoded))
