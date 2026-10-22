"""Append-only, hash-chained decision log. Pilot evidence is only worth something if it can't be
quietly edited after the fact, so each record commits to its predecessor (same idea as the memory
audit chain). Verification is fail-closed: any break raises `LogCorrupt`."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
from pathlib import Path

from pydantic import BaseModel, Field

from ..verdict.models import Verdict
from .mode import Mode

GENESIS = "0" * 64
_ID_RE = re.compile(r"^[A-Za-z0-9._:/@+=-]{1,256}$")
MAX_RECORDS = 1_000_000


class LogCorrupt(Exception):
    """The decision log failed integrity verification (edit, deletion, reorder, or truncation)."""


def valid_artifact_id(artifact_id: str) -> str:
    if not isinstance(artifact_id, str) or not _ID_RE.match(artifact_id):
        raise ValueError("artifact_id must be 1-256 chars of [A-Za-z0-9._:/@+=-]")
    return artifact_id


class ShadowRecord(BaseModel):
    artifact_id: str
    ts: str
    mode: Mode
    would_be: Verdict
    enforced: Verdict
    reason: str = ""
    graders: dict[str, str] = Field(default_factory=dict)   # grader -> verdict | "errored"
    fingerprints: list[str] = Field(default_factory=list)
    gate_error: bool = False
    prev_hash: str = GENESIS
    hash: str = ""

    def compute_hash(self) -> str:
        body = self.model_dump(mode="json", exclude={"hash"})
        return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class ShadowLog:
    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)

    def _read(self) -> list[ShadowRecord]:
        if not self.path.exists():
            return []
        out: list[ShadowRecord] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                if n > MAX_RECORDS:
                    raise LogCorrupt(f"log exceeds {MAX_RECORDS} records")
                if not line.strip():
                    continue
                try:
                    out.append(ShadowRecord.model_validate_json(line))
                except Exception as e:  # noqa: BLE001 - any parse failure is corruption
                    raise LogCorrupt(f"line {n}: unparseable record ({type(e).__name__})") from None
        return out

    def records(self) -> list[ShadowRecord]:
        """All records, chain-verified. Raises `LogCorrupt` on any integrity failure."""
        recs = self._read()
        prev = GENESIS
        for i, r in enumerate(recs, 1):
            if r.prev_hash != prev:
                raise LogCorrupt(f"record {i}: chain broken (deleted, reordered or inserted record)")
            if r.hash != r.compute_hash():
                raise LogCorrupt(f"record {i}: hash mismatch (record was edited)")
            prev = r.hash
        return recs

    def verify(self, expect_head: str | None = None) -> int:
        """Verify the chain; with `expect_head` (a head hash recorded elsewhere) also detect tail
        truncation, which a self-contained hash chain cannot see on its own."""
        recs = self.records()
        if expect_head is not None:
            head = recs[-1].hash if recs else GENESIS
            if head != expect_head:
                raise LogCorrupt("head hash mismatch (log truncated, extended or replaced)")
        return len(recs)

    def head(self) -> str:
        recs = self.records()
        return recs[-1].hash if recs else GENESIS

    def append(self, rec: ShadowRecord) -> ShadowRecord:
        """Verify-then-append under an exclusive file lock, so concurrent pipeline workers extend ONE
        chain instead of forking it. Refuses to extend a corrupt chain. Cost is O(n) per append
        (full verification); fine for pilot volumes, revisit for millions of records."""
        valid_artifact_id(rec.artifact_id)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a+", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)  # released on close
            recs = self.records()
            rec.prev_hash = recs[-1].hash if recs else GENESIS
            rec.hash = rec.compute_hash()
            fh.write(rec.model_dump_json() + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return rec
