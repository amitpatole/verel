"""Bounded reads of untrusted local files: regular files only (a FIFO/device can't hang or exhaust us),
size checked on the OPEN descriptor, never trusting `st_size` alone for devices."""

from __future__ import annotations

import os
import stat


def read_regular(path: str | os.PathLike[str], limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"{os.fspath(path)!r} is not a regular file")
        if st.st_size > limit:
            raise ValueError(f"file exceeds {limit} bytes")
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(limit + 1)
        if len(data) > limit:
            raise ValueError(f"file exceeds {limit} bytes")
        return data
    finally:
        os.close(fd)


def _clip(x: object, depth: int = 0) -> object:
    """A small, bounded copy of an untrusted structure (never walks more than ~20 items per level)."""
    if isinstance(x, (str, int, float, bool)) or x is None:
        return x[:60] if isinstance(x, str) else x
    if depth >= 3:
        return "..."
    if isinstance(x, dict):
        return {str(k)[:40]: _clip(v, depth + 1) for k, v in list(x.items())[:20]}
    if isinstance(x, (list, tuple)):
        return [_clip(v, depth + 1) for v in list(x)[:20]]
    return str(type(x).__name__)


def printable(x: object, n: int = 80) -> str:
    """Terminal-safe, bounded rendering of an untrusted value (never str()s an unbounded structure)."""
    if isinstance(x, (str, int, float, bool, BaseException)) or x is None:
        s = str(x)[:n]
    else:
        import json

        s = json.dumps(_clip(x), separators=(", ", ": "), default=str)[:n]
    return "".join(ch if ch.isprintable() else "?" for ch in s)
