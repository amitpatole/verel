"""Pilot decision log: a keyed, hash-chained, tamper-evident record of every would-be verdict.
The integrity machinery lives in `verel._chainlog` (shared with the label ledger and audit log)."""

from __future__ import annotations

import re

from .._chainlog import GENESIS, ChainLog, ChainRecord, LogCorrupt
from ..verdict.models import Verdict
from .mode import Mode

__all__ = ["GENESIS", "DuplicateArtifact", "LogCorrupt", "ShadowLog", "ShadowRecord", "valid_artifact_id"]

_ID_RE = re.compile(r"[A-Za-z0-9._:/@+=-]{1,256}")


def valid_artifact_id(artifact_id: str) -> str:
    # fullmatch, not match+`$`: `$` would admit a trailing newline
    if not isinstance(artifact_id, str) or not _ID_RE.fullmatch(artifact_id):
        raise ValueError("artifact_id must be 1-256 chars of [A-Za-z0-9._:/@+=-]")
    return artifact_id


class DuplicateArtifact(ValueError):
    """A decision for this artifact id already exists; record a new version under a new id."""

    def __init__(self, artifact_id: str, existing: object = None):
        super().__init__(artifact_id)
        self.existing = existing


class ShadowRecord(ChainRecord):
    artifact_id: str
    ts: str
    mode: Mode
    would_be: Verdict
    enforced: Verdict
    reason: str = ""
    graders: dict[str, str] = {}
    fingerprints: list[str] = []
    gate_error: bool = False
    ref: str = ""  # who/what recorded it (principal, job id): a retried job recognises its own record
    recorded_by: str = ""  # the PRINCIPAL accountable for the decision (HTTP caller, or who enqueued the job)
    content: str = ""  # sha256 of the asset the decision is about, when known: evidence counts files, not ids
    bound: bool = False  # the facts named this exact file (asset.sha256 matched)


class ShadowLog(ChainLog[ShadowRecord]):
    def __init__(self, path, *, domain: str = ""):
        super().__init__(path, ShadowRecord, domain=domain, id_field="artifact_id")

    def append(self, rec: ShadowRecord) -> ShadowRecord:
        valid_artifact_id(rec.artifact_id)
        return super().append(rec)

    def append_unique(self, rec: ShadowRecord) -> ShadowRecord:
        """Append only if this artifact id has no decision yet (checked under the log's lock). Raises
        `DuplicateArtifact` otherwise."""
        aid = valid_artifact_id(rec.artifact_id)
        return self.append_unique_record(rec, aid)

    def append_unique_record(self, rec: ShadowRecord, aid: str) -> ShadowRecord:
        return self.append_if_absent(
            rec,
            b'"artifact_id":"' + aid.encode() + b'"',
            lambda r: r.artifact_id == aid,
            lambda r: DuplicateArtifact(aid, r if r is not rec else None),
            lambda: self.archived_has(aid),
        )
