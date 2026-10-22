"""Confined, bounded file access shared by the media graders (no traversal, no FIFOs, size-capped)."""

from __future__ import annotations

import hashlib
import json
import os
import stat

from .._safeio import printable

MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 32


def confine(repo: str, rel: str) -> str:
    """Resolve `rel` inside `repo` or raise. realpath-contained so `..` and symlinks can't escape."""
    root = os.path.realpath(repo)
    rp = os.path.realpath(rel if os.path.isabs(rel) else os.path.join(repo, rel))
    if rp != root and not rp.startswith(root + os.sep):
        raise ValueError(f"path escapes the repo: {printable(rel, 120)!r}")
    return rp


def _open_regular(path: str) -> int:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))  # a planted FIFO can't hang us
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise FileNotFoundError(path)
    return fd


def read_text(repo: str, rel: str, limit: int = MAX_JSON_BYTES) -> str:
    fd = _open_regular(confine(repo, rel))
    with os.fdopen(fd, "rb") as f:
        if os.fstat(f.fileno()).st_size > limit:
            raise ValueError(f"file too large (> {limit} bytes): {rel!r}")
        return f.read(limit + 1).decode("utf-8")


def sha256_file(repo: str, rel: str) -> str:
    """Streaming digest of a (possibly multi-GB) asset, bound into the receipt."""
    fd = _open_regular(confine(repo, rel))
    h = hashlib.sha256()
    with os.fdopen(fd, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _depth(o: object, d: int = 0) -> int:
    if d > MAX_DEPTH:
        return d
    if isinstance(o, dict):
        return max([_depth(v, d + 1) for v in o.values()] or [d])
    if isinstance(o, list):
        return max([_depth(v, d + 1) for v in o] or [d])
    return d


def load_json(text: str, what: str) -> object:
    try:
        data = json.loads(text, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
    except RecursionError:
        raise ValueError(f"{what}: nesting too deep") from None
    except ValueError as e:
        raise ValueError(f"{what}: invalid JSON ({e})") from None
    if _depth(data) > MAX_DEPTH:
        raise ValueError(f"{what}: nesting deeper than {MAX_DEPTH}")
    return data


def clean(x: object, n: int = 80) -> str:
    """Terminal-safe, bounded rendering of an untrusted value for messages (never str()s a huge object)."""
    return printable(x, n)
