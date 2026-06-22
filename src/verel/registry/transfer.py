"""Cross-tenant transfer — export verified skills, import + RE-VERIFY (§8.7).

The one rule that makes the flywheel honest: **trust does not travel with the artifact.**
A skill exported from tenant A enters tenant B as a `candidate` and only becomes `verified`
in B if it passes B's OWN held-out eval. The fraction of imports that re-verify against a
different tenant is the corpus-fungibility hypothesis H2 — the gate on whether the public
registry is a real moat or just per-tenant lock-in.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..memory.view import Trust
from ..toolsmith import SideEffect, ToolCase, ToolRecord, ToolRegistry, eval_tool_cases
from .artifact import SkillArtifact


def export_skill(tool: ToolRecord, *, origin: str) -> SkillArtifact:
    """Package a (verified) tool as a signed, content-addressed artifact for publication."""
    return SkillArtifact(
        name=tool.name, capability=tool.capability, code=tool.code,
        side_effect=tool.side_effect.value, origin=origin, eval_score=tool.eval_score,
        provenance=list(tool.provenance),
    ).finalize()


@dataclass
class ImportResult:
    name: str
    transferred: bool  # signature verified + code installed (as candidate at least)
    reverified: bool  # passed the TARGET tenant's held-out eval -> verified locally
    score: float
    reason: str


def import_skill(artifact: SkillArtifact, into: ToolRegistry, *, target_cases: list[ToolCase],
                 target_name: str | None = None, isolation: str = "container",
                 sandbox: bool | None = None) -> ImportResult:
    """Install an artifact into `into`, then re-verify against the target tenant's cases.

    SECURITY: the artifact's code is FOREIGN/untrusted ("trust does not travel" — its signature only
    proves a secret-holder packaged it). So re-verification runs in the CONTAINER tier by default
    (bwrap netns + read-only fs + seccomp), fail-closed without bwrap — exactly like the MCP build
    path. `sandbox` is a back-compat override for TRUSTED local code only (e.g. fast tests)."""
    if not artifact.verify():
        return ImportResult(artifact.name, False, False, 0.0, "signature/content verification failed")

    name = target_name or artifact.name
    mode = isolation if sandbox is None else ("subprocess" if sandbox else "none")
    passed, score, detail = eval_tool_cases(artifact.code, name, target_cases,
                                            side_effect=SideEffect(artifact.side_effect),
                                            isolation=mode)
    tool = ToolRecord(name=name, capability=artifact.capability, code=artifact.code,
                      side_effect=SideEffect(artifact.side_effect), eval_score=score,
                      provenance=[*artifact.provenance, f"imported:{artifact.content_hash}"])
    into.register(tool, trust=Trust.VERIFIED if passed else Trust.CANDIDATE)
    return ImportResult(name, True, passed, score,
                        "re-verified against target corpus" if passed
                        else f"installed as candidate ({detail}) — did not transfer")
