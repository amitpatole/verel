"""`verel.media` — deterministic delivery-spec and content-credentials grading for media & communications.

Two graders on the one verdict bus: MEDIA (declared rules over supplied measurement facts) and
PROVENANCE (C2PA policy over a validated manifest). Verel does not measure or run the cryptography:
the senses (Audel, AgentVision, ffprobe) supply facts; a C2PA implementation validates manifests.
"""

from __future__ import annotations

from .facts import load_facts, merge
from .grade import grade_media, grade_spec
from .profiles import PROFILES
from .provenance import Policy, grade_provenance, parse_manifest_report, parse_policy
from .rules import Spec, parse_spec

__all__ = ["PROFILES", "Policy", "Spec", "grade_media", "grade_provenance", "grade_spec", "load_facts",
           "merge", "parse_manifest_report", "parse_policy", "parse_spec"]
