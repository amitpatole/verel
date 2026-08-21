"""Hostile-content scanning primitives shared by memory extraction and the document guard.

Factored out of `verel.memory.extract` (which re-imports these under its original underscore
aliases, so every extraction-side security pin keeps passing) so `verel.guard` can scan
untrusted *documents* with the same machinery that already survived the memory security
cadence: encoded-payload decode-and-rescan, decode-and-execute lures, bare shell-command
payloads, zero-width/homoglyph evasion folding, and opaque high-entropy blob detection.

Everything here is pure and dependency-free. The scanning philosophy (rounds 6–10 of the
memory security cadence): a denylist scans the LITERAL surface form, but the dangerous
payload is often the DECODED form — so invert one layer and re-scan, and prefer a POSITIVE
model (durable text is short and readable; an opaque blob is hostile) over a longer denylist.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import unicodedata
from collections import Counter

SECRET_TEXT = re.compile(
    r"AKIA[0-9A-Z]{12,}"                          # AWS access key id
    r"|AIza[0-9A-Za-z_-]{30,}"                    # Google API key
    r"|ya29\.[0-9A-Za-z_-]{20,}"                  # Google OAuth access token
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"        # PEM private key
    r"|\bsk-[A-Za-z0-9]{20,}\b"                   # OpenAI-style secret key
    r"|\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"    # Stripe secret key (round-6 F4)
    r"|\brk_(?:live|test)_[A-Za-z0-9]{16,}\b"    # Stripe restricted key
    r"|\bgh[pousr]_[A-Za-z0-9]{20,}\b"           # GitHub token
    r"|\bglpat-[A-Za-z0-9_-]{16,}\b"             # GitLab PAT (round-6 F4)
    r"|\bshpat_[A-Za-z0-9]{16,}\b"               # Shopify token
    r"|\bSG\.[\w-]{16,}\.[\w-]{16,}\b"           # SendGrid key (round-6 F4)
    r"|AGE-SECRET-KEY-1[A-Z0-9]{20,}"            # age secret key (round-6 F4)
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}\b"         # Slack token
    r"|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.",  # JWT
    re.IGNORECASE,   # round-6 F7: a fullwidth/uppercased key (NFKC→'SK-…') must match too
)
SECRET_TEXT_I = re.compile(
    # URI with user:pass@ (postgres://u:p@host, …). All quantifiers are BOUNDED so a long alnum run
    # (the blob shape this module receives) can't trigger O(n²) backtracking on the `://`/`@` anchors
    # (round-10 ReDoS): a real scheme is short and userinfo is not megabytes.
    r"[a-z][a-z0-9+.\-]{0,30}://[^/\s:@]{1,256}:[^/\s@]{1,256}@"
    r"|bearer\s+[A-Za-z0-9._\-]{16,256}"         # bearer token
    r"|\b[0-9a-f]{32,64}\b",                     # generic hex API key / token (best-effort)
    re.IGNORECASE,
)
# PII that must not be retained durably (email + E.164-ish phone). Best-effort. Quantifiers are
# BOUNDED (local-part ≤64, domain ≤255 per RFC; phone ≤32) so a long alnum run can't backtrack the `@`
# anchor into O(n²) (round-10 ReDoS — the email alt was the dominant cost on a blob-shaped field).
PII_TEXT = re.compile(r"[\w.+\-]{1,64}@[\w\-]{1,255}\.[\w.\-]{1,255}"   # email
                      r"|\+\d[\d\s().\-]{7,32}\d")                     # international phone

ZERO_WIDTH = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")  # zero-width/bidi
ENCODED_RUN = re.compile(
    r"[A-Za-z0-9+/]{40,}={0,2}"          # base64 / base64url run (legit facts don't have 40-char blobs)
    r"|[A-Za-z0-9_-]{40,}"               # base64url (- _ alphabet)
    r"|\b[0-9a-fA-F]{32,}\b"             # long hex blob
    r"|(?:%[0-9a-fA-F]{2}){6,}"          # percent-encoding run
    r"|(?:\\x[0-9a-fA-F]{2}){6,}"        # \xNN escape run
    r"|(?:\\u[0-9a-fA-F]{4}){4,}"        # \uNNNN escape run
    r"|&#x?[0-9a-fA-F]+;(?:&#x?[0-9a-fA-F]+;){4,}"  # HTML entity run
    r"|(?:\b\d{1,3}[,\s]+){6,}\d{1,3}\b"  # decimal char-code run, e.g. 114,109,32,45 → 'rm -' (round-6 F8)
)
# A payload that ships its own decode-and-execute recipe is hostile on its face — drop regardless of
# length. round-6 F9: cover the long-form / language-specific decode-and-run idioms the short list missed.
DECODE_EXEC = re.compile(
    r"base(?:64|32)\s+--?d(?:ecode)?|b64decode|base64_decode|Base64\.decode64|bytes\.fromhex"
    r"|atob\s*\(|fromCharCode|certutil\s+-decode|uudecode|wscript|cscript"
    r"|\beval\s*\(|\bexec(?:Sync|File)?\s*\(|\bsystem\s*[(\"']|os\.(?:system|popen|exec)"
    r"|\bpopen\s*\(|subprocess|child_process|pty\.spawn|spawn\w*\s*\(|openssl\s+enc\s+-d"
    r"|Invoke-Expression|\biex\b|-enc(?:odedcommand)?\b|\bperl\s+-e\b|\bnode\s+-e\b|\bpython3?\s+-c\b"
    r"|\|\s*(?:ba)?sh\b|\$\(.*\)|\$'[^']*\\x|`[^`]+`",
    re.IGNORECASE,
)
# Common homoglyphs (Cyrillic / Greek lookalikes) folded to ASCII before scanning, so 'АKIA…' (Cyrillic
# А) can't dodge the denylist while a downstream LLM still reads it as 'AKIA…' (round-6 F6). NFKC handles
# fullwidth/compatibility forms (F7); homoglyphs are DISTINCT codepoints NFKC won't touch, hence this map.
HOMOGLYPHS = str.maketrans({
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
    "Т": "T", "Х": "X", "У": "Y", "І": "I", "Ј": "J", "Ѕ": "S", "а": "a", "е": "e", "о": "o",
    "р": "p", "с": "c", "у": "y", "х": "x", "к": "k", "м": "m", "ѕ": "s", "і": "i", "ј": "j",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X", "ο": "o", "ν": "v",
})
# A durable FACT value is short readable text; an opaque, high-entropy, mixed-class token is an encoded
# blob (base64/base32/base85/…) regardless of how it's chunked — entropy survives whitespace-splitting,
# so this catches what the contiguous-run regex misses (round-6 F1/F2/F3). All-lowercase prose stays
# single-class and is spared; the class+entropy gate is what separates a blob from a long word/sentence.
BLOB_MIN = 24            # below this, a short blob is a documented residual (R-020)
BLOB_ENTROPY = 4.0       # bits/char; base32≈4.5, base64≈5, base85≈5.5, English-no-spaces≈3.5–4.0


def strip_zero_width(s: str) -> str:
    """Remove zero-width / bidi controls so 'A​KIA…' can't split a token past the denylist."""
    return ZERO_WIDTH.sub("", s)


def fold(s: str) -> str:
    """Normalize for SCANNING ONLY (the stored value keeps its original bytes): strip zero-width, NFKC
    (fullwidth→ASCII), then fold common homoglyphs — so a token can't hide from the denylist behind a
    visually-identical codepoint that an LLM still reads as the ASCII form."""
    return unicodedata.normalize("NFKC", strip_zero_width(s)).translate(HOMOGLYPHS)


def shannon(s: str) -> float:
    n = len(s)
    if n <= 1:
        return 0.0
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def decode_candidates(token: str) -> list[str]:
    """Best-effort: DECODE a token as base64/base64url/base32/hex and return any printable plaintext.
    This is the principled answer to the encoding class — instead of guessing at the surface form
    (an arms race short base64 wins, since it's statistically ~prose), we INVERT one layer and re-scan
    the result. Attacker `.`/whitespace separators are stripped; a leading base64 run (before a trailing
    noise word) and each long base64-ish substring are tried, so dot-chunking can't dodge it."""
    raws: list[bytes] = []
    strip = re.sub(r"[.\s]", "", token)
    runs = {strip}
    m = re.match(r"[A-Za-z0-9+/_-]+={0,2}", strip)
    if m:
        runs.add(m.group())
    for r in re.findall(r"[A-Za-z0-9+/=_-]{12,}", token):
        runs.add(re.sub(r"[.\s]", "", r))
    for t in runs:
        body = t.rstrip("=")
        if len(body) < 4:   # a tiny command (`:|sh`) base64s to a ~6-char body — decode it too (round-9)
            continue
        for alt in (None, b"-_"):
            try:
                raws.append(base64.b64decode(body + "=" * (-len(body) % 4), altchars=alt, validate=True))
            except (binascii.Error, ValueError):
                pass
        try:
            raws.append(base64.b32decode(body.upper() + "=" * (-len(body) % 8), casefold=True))
        except (binascii.Error, ValueError):
            pass
        for b85 in (base64.b85decode, base64.a85decode):   # base85 / ascii85 (round-9: short b85 secret)
            try:
                raws.append(b85(t))
            except (binascii.Error, ValueError):
                pass
        if re.fullmatch(r"[0-9a-fA-F]+", t) and len(t) % 2 == 0:
            try:
                raws.append(bytes.fromhex(t))
            except ValueError:
                pass
    out: list[str] = []
    for raw in raws:
        s = raw.decode("utf-8", "ignore")
        if s and sum(c.isprintable() for c in s) >= 0.8 * len(s):
            out.append(s)
    return out


# A decoded blob that IS a shell command is a decode-and-run payload even with no decode-keyword
# (round-8: `rm -rf ~`, a fork bomb, `shutdown now` decoded cleanly but matched nothing). This scans
# DECODED plaintext only (never raw fact text), so it can't false-positive on a natural-language fact —
# a benign value that base64-decodes to an English shell-verb sentence is itself an opaque blob already.
SHELL_CMD = re.compile(
    r"^\s*(?:sudo\s+|doas\s+|command\s+|/\w[\w/]*/)?(?:rm|rmdir|kill(?:all)?|chmod|chown|dd|mkfs\w*"
    r"|shutdown|halt|reboot|poweroff|curl|wget|nc|ncat|telnet|bash|sh|zsh|ksh|eval|exec|mv|cp|truncate"
    r"|shred|history|crontab|systemctl|service|iptables|ufw|userdel|useradd|passwd|chpasswd|insmod"
    r"|modprobe|git\s+clean|npm|npx|yarn|pnpm|docker|kubectl|make|source|env|ssh|scp|rsync|tar|chattr"
    r"|setfacl|mount|umount|ln|del|erase|format|rd|Remove-Item|Stop-Computer|Stop-Service"
    r"|Invoke-WebRequest|Start-Process|reg\s+(?:delete|add))\b"
    r"|:\(\)\s*\{|>\s*[~/]|>>\s*[~/]|/dev/(?:sd|nvme|null|zero|random|urandom)|\bmkfs\b|\$\(|`[^`]+`",
    re.IGNORECASE | re.MULTILINE,
)
# Strip shell-quoting / escape noise BEFORE the verb scan so an obfuscated leading verb the shell would
# re-expand (`r''m`, `r$@m`, `\x72m`, `\162m`) can't dodge the `^verb` anchor (round-9). Best-effort.
SHELL_NOISE = re.compile(r"""['"`]|\$[@*]|\$\{[^}]*\}|\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}|\\""")


def deobfuscate(text: str) -> str:
    # decode \xNN / \NNN escapes to the char they denote (so `\x72m`→`rm`), then drop quoting noise
    def _esc(m: re.Match[str]) -> str:
        g = m.group(0)
        try:
            if g[:2] == "\\x":
                return chr(int(g[2:], 16))
            if g[1:].isdigit():
                return chr(int(g[1:], 8))
        except ValueError:
            return ""
        return ""
    decoded = re.sub(r"\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}", _esc, text)
    return SHELL_NOISE.sub("", decoded)


def text_unsafe(text: str) -> bool:
    """A decoded string is unsafe if it reveals a credential/PII, a decode-and-run lure, or IS a shell
    command (round-8: a bare destructive one-liner matches no secret/lure pattern but is still a payload).
    The command check also runs on a de-obfuscated copy so shell-quoting can't hide the leading verb."""
    if (SECRET_TEXT.search(text) or SECRET_TEXT_I.search(text)
            or PII_TEXT.search(text) or DECODE_EXEC.search(text) or SHELL_CMD.search(text)):
        return True
    return bool(SHELL_CMD.search(deobfuscate(text)))


def decoded_unsafe(token: str, depth: int = 2) -> bool:
    """Decode `token` (recursing once for base64-of-base64) and re-scan the plaintext for a secret or an
    exec lure — closes the 'encode a secret/instruction, decode it later' class regardless of entropy or
    chunking (round-7 F-NEW-1/F-NEW-2), without the false-positives a lowered entropy threshold causes."""
    for d in decode_candidates(token):
        if text_unsafe(d):
            return True
        if depth > 1:
            for t2 in d.split():
                if decoded_unsafe(t2, depth - 1):
                    return True
    return False


def case_mixed(t: str) -> bool:
    """INTRA-token case-mixing: a lowercase plus an uppercase that is NOT just a leading capital. This
    is the STRONG 'random encoded token' tell ('QUtJQUlP'); a Capitalized word ('Python') lacks it."""
    return bool(re.search(r"[a-z]", t) and re.search(r"(?<=.)[A-Z]", t))


def b64ish(tok: str) -> str | None:
    """If `tok` is a random-looking encoded chunk (pure base64/base64url alphabet with a 'not-a-word'
    tell — a digit, a base64 special, or intra-token case-mixing), return its stripped core, else None.
    A normal word ('Python','and') has no such tell; 'QUtJQUlP'/'U0ZPRE5O' do."""
    t = tok.strip("\"'`.,;:()[]{}<>")
    if len(t) < 4 or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", t):
        return None
    if re.search(r"\d", t) or re.search(r"[+/=]", t) or case_mixed(t):
        return t
    return None


def url_like(tok: str) -> bool:
    """A URL/path/dotted-identifier — structured, not an opaque blob (any embedded credential is caught
    separately by `SECRET_TEXT_I`). Excluding these is what keeps the single-token blob test from
    false-positiving on a legitimate `https://…` or `/usr/local/…` value."""
    return "://" in tok or bool(re.search(r"/[^/]+/", tok)) or tok.count(".") >= 2


def is_opaque_blob(field: str) -> bool:
    """True if a field is an encoded blob: either ≥3 consecutive random-looking base64 chunks (chunked
    encoding, round-6 F1), or a single long high-entropy multi-class token that isn't a URL/path. Works
    on the ORIGINAL tokens — never the whitespace-compacted string — so a sentence with proper nouns
    can't fabricate the mixed-class signal."""
    toks = field.split()
    run = acc = 0
    strong = False
    for t in toks:
        core = b64ish(t)
        if core is not None:
            run += 1
            acc += len(core)
            strong = strong or case_mixed(core)
            # ≥3 chunks in a row is unmistakable chunked encoding; ≥2 also counts when the run is
            # blob-sized AND includes a case-mixed (random-looking) chunk, catching a newline-split
            # base64 of a secret (round-6 F3) without flagging legit 'word2024 word5678' pairs.
            if run >= 3 or (run >= 2 and acc >= BLOB_MIN and strong):
                return True
        else:
            run = acc = 0
            strong = False
    for t in toks:
        core = t.strip("\"'`.,;:()[]{}<>")
        # A URL/path/dotted token is excluded here (it would false-positive); a dotted blob that hides a
        # SECRET is caught instead by `decoded_unsafe` (decode-and-rescan), which a real path survives.
        if len(core) >= BLOB_MIN and not url_like(core):
            classes = sum(bool(re.search(p, core)) for p in
                          (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))
            if classes >= 2 and shannon(core) >= BLOB_ENTROPY:
                return True
    return False
