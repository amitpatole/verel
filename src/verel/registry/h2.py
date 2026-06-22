"""H2 — the corpus-fungibility experiment (§8.7), the moat's gating decision.

The design is blunt: the data-network-effect that is the ENTIRE moat *may not exist*, because
a skill may not be fungible across tenants. So we don't assume it — we measure it. For each
verified skill from a source tenant, attempt to re-verify it against every OTHER tenant's
held-out eval. The transfer rate decides:

    rate >= KILL_LINE  → build the public Skill Registry (the moat is real)
    rate <  KILL_LINE  → do NOT build it; pivot the moat story to per-tenant lock-in

This harness reports the measured rate honestly and logs exactly what was attempted — no
silent caps, no optimistic rounding. Pure utility skills will transfer near-100%; repo/
design-system-specific skills will transfer poorly. The mix is the real answer.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..memory import LocalMemory
from ..toolsmith import ToolCase, ToolRegistry
from .artifact import SkillArtifact
from .transfer import import_skill

KILL_LINE = 0.20  # §8.7: <20% cross-repo verified-skill transfer => no public registry


@dataclass
class TransferOutcome:
    skill: str
    target: str
    reverified: bool
    score: float


@dataclass
class TransferReport:
    outcomes: list[TransferOutcome] = field(default_factory=list)

    @property
    def attempts(self) -> int:
        return len(self.outcomes)

    @property
    def transferred(self) -> int:
        return sum(o.reverified for o in self.outcomes)

    @property
    def rate(self) -> float:
        return self.transferred / self.attempts if self.attempts else 0.0

    @property
    def decision(self) -> str:
        if self.attempts == 0:
            return "no data"
        return ("BUILD public Skill Registry — corpus is fungible"
                if self.rate >= KILL_LINE
                else "DO NOT build registry — pivot moat to per-tenant lock-in")

    def per_skill_rate(self) -> dict[str, float]:
        by: dict[str, list[bool]] = {}
        for o in self.outcomes:
            by.setdefault(o.skill, []).append(o.reverified)
        return {k: sum(v) / len(v) for k, v in by.items()}


def measure_transfer(skills: list[SkillArtifact],
                     targets: dict[str, dict[str, list[ToolCase]]],
                     *, isolation: str = "container", sandbox: bool | None = None,
                     log=lambda m: None) -> TransferReport:
    """skills: verified artifacts from source tenant(s).
    targets: {tenant_name: {capability_or_name: [target held-out cases]}}.

    For each skill, attempt re-verification against each target tenant that has held-out
    cases for that skill's capability. Skills a target can't evaluate are NOT counted as
    transfers (and that omission is logged — silence would inflate the rate)."""
    report = TransferReport()
    for skill in skills:
        for tenant, specs in targets.items():
            cases = specs.get(skill.name) or specs.get(skill.capability)
            if not cases:
                log(f"  skip: {tenant} has no held-out cases for {skill.name!r} (not counted)")
                continue
            reg = ToolRegistry(LocalMemory(), scope=f"tenant:{tenant}")
            res = import_skill(skill, reg, target_cases=cases, isolation=isolation, sandbox=sandbox)
            report.outcomes.append(TransferOutcome(skill.name, tenant, res.reverified, res.score))
            log(f"  {skill.name} -> {tenant}: {'TRANSFER' if res.reverified else 'no'} ({res.score:.0%})")
    return report
