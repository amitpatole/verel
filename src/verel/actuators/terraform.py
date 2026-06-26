"""Terraform/OpenTofu actuator — act-then-verify (IAC-KICKOFF.md Phase 4).

The agent calls its normal tools; the gateway (verel.gateway) gates the consequential ones. This
actuator is what runs *behind* a forwarded terraform action — and it enforces the IaC-specific
non-negotiables the generic gateway can't:

  * plan   — produce a BOUND binary plan (`plan -out`), its digest, and an IAC verdict (drift + the
             IAM sensor). The digest binds the exact bytes that were graded.
  * act    — apply EXACTLY the approved plan file. A digest mismatch (a re-plan or file substitution
             between approval and apply) is REFUSED, never applied — the plan-binding / TOCTOU defense.
  * watch  — re-plan after apply; PASS only when the world converged (no remaining drift).

Honored from day one (the actel/immel rules):
  * Dynamic escalation — destroy/replace OR IAM widening in the bound plan ⇒ IRREVERSIBLE (dry-run +
    human approval); pure create/no-op ⇒ CONSEQUENTIAL (verdict-gated). Fed to the gateway via the
    documented `Policy.overrides` hook (`escalation_override`).
  * Fail closed — a failed/unparseable plan, a missing planfile, a digest mismatch, or an
    un-approved irreversible action does NOT apply.
  * Argv only — every command is argv (no shell); operator-influenced args (binary, planfile) are
    charset-validated so a value like `-rf` or `; rm` can't smuggle an option / shell metachar.

The command runner and the planfile reader are injected, so the whole module is unit-tested offline
with no terraform installed.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from hashlib import blake2s
from pathlib import Path

from ..ci.graders import Runner, run_grader, subprocess_runner
from ..ci.iac import (
    destructive_changes,
    extract_iam_changes,
    terraform_plan_spec,
)
from ..gateway import ActionClass
from ..verdict.models import GraderKind, Report, Verdict

ReadBytes = Callable[[str], bytes]

# Args we build into a terraform argv that an operator can influence (binary name, planfile path).
# Reject anything that could become an option (leading '-') or carry a shell/space metachar. This is
# argv (no shell) so injection is already mostly closed; this keeps option-injection closed too.
_SAFE_ARG = re.compile(r"^[A-Za-z0-9_./@][A-Za-z0-9_./@=:+-]*$")


def _validate_arg(value: str, what: str) -> str:
    if not isinstance(value, str) or not _SAFE_ARG.match(value):
        raise ValueError(f"unsafe {what}: {value!r}")
    return value


def _default_read_bytes(path: str) -> bytes:
    return Path(path).read_bytes()


def plan_digest(data: bytes) -> str:
    """Identity of a binary plan file — the bound digest the gate approves and `act` re-checks."""
    return blake2s(data).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Dynamic escalation (pure) — class an apply by what the BOUND plan actually does.
# ---------------------------------------------------------------------------
def escalate(plan_json: dict, *, base: ActionClass = ActionClass.CONSEQUENTIAL
             ) -> tuple[ActionClass, list[str]]:
    """Destroy/replace OR IAM widening ⇒ IRREVERSIBLE (dry-run + human approval); else `base`
    (CONSEQUENTIAL, verdict-gated). Returns (class, human-readable reasons)."""
    reasons: list[str] = []
    dz = destructive_changes(plan_json)
    if dz:
        reasons.append(f"{len(dz)} destroy/replace ({', '.join(dz[:5])})")
    widenings = [c.address for c in extract_iam_changes(plan_json)
                 if c.change_type in ("grant", "widen", "replace")]
    if widenings:
        reasons.append(f"{len(widenings)} IAM widening ({', '.join(widenings[:5])})")
    return (ActionClass.IRREVERSIBLE if reasons else base), reasons


def escalation_override(plan_json: dict) -> dict[str, ActionClass]:
    """Plan-aware `Policy.overrides` for the gateway: classify `terraform/tofu apply` from the bound
    plan, and always treat `destroy` as IRREVERSIBLE."""
    cls, _ = escalate(plan_json)
    return {"terraform apply": cls, "tofu apply": cls,
            "terraform destroy": ActionClass.IRREVERSIBLE, "tofu destroy": ActionClass.IRREVERSIBLE}


# ---------------------------------------------------------------------------
# Capture C — classify direct IAM-mutating tool calls (code/agents), not just IaC.
# ---------------------------------------------------------------------------
# Substrings (normalized: '-' → '_') that mark an IAM *widening* action across AWS/GCP/Azure/K8s SDKs
# and CLIs. Any match ⇒ IRREVERSIBLE so a one-off grant routed through the gateway gets human approval.
_IAM_MUTATING = (
    "attach_role_policy", "attach_user_policy", "attach_group_policy", "put_role_policy",
    "put_user_policy", "put_group_policy", "create_policy", "create_policy_version",
    "set_default_policy_version", "create_access_key", "update_assume_role_policy", "create_role",
    "add_iam_policy_binding", "set_iam_policy", "add_user_to_group",
    "role_assignment_create", "create_role_assignment",
    "create_rolebinding", "create_clusterrolebinding", "create_role_binding",
    "create_cluster_role_binding",
)


def iam_action_class(tool: str) -> ActionClass | None:
    """IRREVERSIBLE for an IAM-widening tool name (Capture C), else None (defer to verb heuristics)."""
    t = (tool or "").lower().replace("-", "_")
    return ActionClass.IRREVERSIBLE if any(p in t for p in _IAM_MUTATING) else None


def iam_tool_overrides(tools: list[str]) -> dict[str, ActionClass]:
    """Build `Policy.overrides` forcing every IAM-mutating tool in `tools` to IRREVERSIBLE."""
    return {t: cls for t in tools if (cls := iam_action_class(t)) is not None}


# ---------------------------------------------------------------------------
# The actuator.
# ---------------------------------------------------------------------------
@dataclass
class PlanResult:
    planfile: str
    plan_digest: str  # "" ⇒ unbound (plan failed) — act() will refuse
    report: Report
    action_class: ActionClass
    escalation_reasons: list[str] = field(default_factory=list)
    plan_json: dict = field(default_factory=dict)


@dataclass
class ActResult:
    applied: bool
    reason: str
    rc: int | None = None


def _errored_report(summary: str) -> Report:
    return Report(verdict=Verdict.FAIL, summary=summary, grader=GraderKind.IAC, errored=True)


class TerraformActuator:
    """Plan/act/watch for a terraform/tofu working directory. Inject `runner`/`read_bytes` for tests."""

    def __init__(self, repo: str, *, runner: Runner = subprocess_runner,
                 read_bytes: ReadBytes = _default_read_bytes, binary: str = "terraform",
                 planfile: str = "tfplan.bin"):
        self.repo = repo
        self._run = runner
        self._read = read_bytes
        self.binary = _validate_arg(binary, "binary")
        self.planfile = _validate_arg(planfile, "planfile")

    def _planpath(self) -> str:
        return str(Path(self.repo) / self.planfile)

    def plan(self) -> PlanResult:
        """Produce a bound binary plan, grade it (drift + IAM), and classify the apply."""
        rc, _out, err = self._run(
            [self.binary, "plan", "-input=false", "-lock-timeout=60s", "-out", self.planfile], self.repo)
        if rc != 0:
            return PlanResult(self.planfile, "", _errored_report(f"plan failed: {err[:200]}"),
                              ActionClass.IRREVERSIBLE, ["plan errored — fail closed"], {})

        # Machine-readable plan, captured once and reused for BOTH the verdict and escalation.
        rc2, show_out, err2 = self._run([self.binary, "show", "-json", self.planfile], self.repo)
        plan_json: dict = {}
        if rc2 == 0:
            try:
                loaded = json.loads(show_out)
                plan_json = loaded if isinstance(loaded, dict) else {}
            except json.JSONDecodeError:
                plan_json = {}
        # Reuse run_grader (attestation + signed receipt) by feeding it the already-captured output.
        def _replay(_cmd: list[str], _cwd: str | None = None) -> tuple[int, str, str]:
            return (rc2, show_out, err2)

        report = run_grader(terraform_plan_spec(self.repo, self.planfile, binary=self.binary),
                            runner=_replay)

        # Bind the digest to the actual plan-file bytes; no digest ⇒ cannot bind ⇒ fail closed.
        try:
            digest = plan_digest(self._read(self._planpath()))
        except OSError as e:
            return PlanResult(self.planfile, "", _errored_report(f"planfile unreadable: {e}"),
                              ActionClass.IRREVERSIBLE, ["unbound plan — fail closed"], plan_json)

        # If `show -json` failed we cannot read what the plan DOES — we must not classify it as the
        # less-restrictive CONSEQUENTIAL. Fail closed to IRREVERSIBLE (red-team round 2).
        if rc2 != 0:
            return PlanResult(self.planfile, digest, _errored_report(f"plan unreadable: {err2[:200]}"),
                              ActionClass.IRREVERSIBLE, ["plan JSON unreadable — fail closed"], plan_json)

        cls, reasons = escalate(plan_json)
        return PlanResult(self.planfile, digest, report, cls, reasons, plan_json)

    def act(self, approved_digest: str) -> ActResult:
        """Apply EXACTLY the bound plan. Refuses unless the planfile's CURRENT digest equals the
        approved digest — a re-plan or file swap between approval and apply is rejected, not applied.
        (Human-approval gating for IRREVERSIBLE actions is the gateway's job, upstream of this.)"""
        try:
            current = plan_digest(self._read(self._planpath()))
        except OSError:
            return ActResult(False, "planfile missing — refused (fail closed)")
        if not approved_digest:
            return ActResult(False, "no approved plan digest — refused (fail closed)")
        if current != approved_digest:
            return ActResult(False, "plan-binding mismatch — plan changed since approval; refused")
        # Applying a SAVED plan file does not prompt and ignores config drift — it applies precisely
        # what was graded + approved. That is the whole point of plan-binding.
        rc, _out, err = self._run([self.binary, "apply", "-input=false", self.planfile], self.repo)
        return ActResult(rc == 0, "applied" if rc == 0 else f"apply failed: {err[:200]}", rc=rc)

    def destroy(self, *, approved: bool = False) -> ActResult:
        """Destroy is inherently IRREVERSIBLE — refuses unless the caller (the gateway, post human
        approval) passes approved=True."""
        if not approved:
            return ActResult(False, "destroy not approved — refused (fail closed)")
        rc, _out, err = self._run([self.binary, "destroy", "-input=false", "-auto-approve"], self.repo)
        return ActResult(rc == 0, "destroyed" if rc == 0 else f"destroy failed: {err[:200]}", rc=rc)

    def watch(self) -> Report:
        """Act-then-verify: re-plan after apply. `-detailed-exitcode` → 0 no changes (converged),
        2 changes remain (drift), 1 error."""
        rc, _out, err = self._run(
            [self.binary, "plan", "-input=false", "-detailed-exitcode", "-lock-timeout=60s"], self.repo)
        if rc == 0:
            return Report(verdict=Verdict.PASS, summary="post-apply: converged (no drift)",
                          grader=GraderKind.IAC)
        if rc == 2:
            return Report(verdict=Verdict.FAIL, summary="post-apply: drift remains — world did not converge",
                          grader=GraderKind.IAC)
        return _errored_report(f"post-apply plan errored: {err[:200]}")
