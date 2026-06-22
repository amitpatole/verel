"""Canonical signing payload — an INJECTIVE encoding of a field tuple.

A naive `"|".join(fields)` (or any single-delimiter join) is NOT injective: a delimiter byte inside
any field shifts the partition, so one signature becomes valid for multiple distinct field tuples
(e.g. `("a|","b")` and `("a","|b")` both render `a|b`). That silently defeats the binding a signature
is supposed to provide — the signature commits to the byte string, not to the tuple the signer meant.

Length-prefixing each field (netstring `len:data,`) makes the encoding a one-to-one function of the
tuple: the length is consumed before the data and the terminator is never content-searched, so no
field's content can forge a boundary. UTF-8 is itself a bijection str↔bytes, so the property survives
`.encode()`. Shared by every HMAC/ed25519 signer in the package so the guarantee can't drift per-site.
"""

from __future__ import annotations


def canonical_payload(*parts: str) -> str:
    """Injective length-prefixed (netstring) encoding of a fixed field tuple."""
    return "".join(f"{len(p)}:{p}," for p in parts)
