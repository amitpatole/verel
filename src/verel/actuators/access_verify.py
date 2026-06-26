"""Effective-access verification — the act-then-verify capstone for IAM (IAC-KICKOFF.md Phase 5).

Pre-apply graders (Captures A/B) read what a change *intends*. This reads what the cloud *actually*
grants — closing the gap that makes IAM problems surface "only when something goes wrong". It shells
out to the cloud's own analyzers (AWS IAM Access Analyzer + policy simulator, GCP Policy/asset IAM
analysis, Azure role assignments) with creds resolved from ~/.config (see cloudcreds), and maps their
findings onto the verdict bus as `GraderKind.IAM` issues.

NOTE — this is NOT a pure offline gate: it needs cloud READ credentials, and provider calls can't be
sandboxed. The parsers are pure (offline-tested); the verifier's runner is injected. Fail closed: no
creds, or a CLI error, ⇒ an errored Report, never a silent pass.
"""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable

from ..ci.iac import (
    _ADMIN_AZURE_GUIDS,
    _ADMIN_AZURE_ROLES,
    _ADMIN_GCP_ROLES,
    _PRIVESC_ACTIONS,
    _PRIVESC_AZURE_GUIDS,
    _PRIVESC_GCP_ROLES,
    safe_arg,
    safe_args,
)
from ..verdict.models import Confidence, GraderKind, Issue, IssueKind, Report, Severity, Verdict
from .cloudcreds import CloudCreds

# Env-aware runner (cloud creds must reach the subprocess). Distinct from ci.graders.Runner (no env).
EnvRunner = Callable[[list[str], "dict[str, str] | None"], "tuple[int, str, str]"]


def subprocess_env_runner(cmd: list[str], env: dict[str, str] | None = None, *,
                          timeout: int = 120) -> tuple[int, str, str]:
    full = {**os.environ, **(env or {})}
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=full)  # noqa: S603
    return r.returncode, r.stdout, r.stderr


# Actions that, if EFFECTIVELY allowed, indicate privilege-escalation / admin reach. This MUST be a
# superset of the pre-apply sensor's privesc set — a live check that is BLINDER than the plan grader
# would silently pass grants the plan grader catches (round-6 finding E1, thesis-breaking). So we
# reuse the canonical `_PRIVESC_ACTIONS` from the offline sensor as the single source of truth.
_SENSITIVE_ACTIONS = _PRIVESC_ACTIONS | {"*"}
# GCP admin OR privilege-escalation roles, reusing the offline sensor's canonical sets (E1).
_GCP_GATING_ROLES = _ADMIN_GCP_ROLES | _PRIVESC_GCP_ROLES
# Azure built-in admin/privesc role GUIDs (an assignment may carry only roleDefinitionId) (E1/E4).
_AZURE_GATING_GUIDS = _ADMIN_AZURE_GUIDS | _PRIVESC_AZURE_GUIDS
_PUBLIC = {"allusers", "allauthenticatedusers"}


def _iam_issue(rule_id: str, sev: Severity, msg: str, locus: str | None) -> Issue:
    return Issue(kind=IssueKind.IAM_RISK, severity=sev, source=GraderKind.IAM, message=msg,
                 locator=locus, locator_precise=bool(locus), confidence=Confidence.HIGH,
                 detail_json=json.dumps({"rule_id": rule_id, "effective": True}))


def _report(issues: list[Issue], summary: str) -> Report:
    worst_gates = any(i.severity in (Severity.ERROR, Severity.CRITICAL) for i in issues)
    return Report(verdict=Verdict.FAIL if worst_gates else (Verdict.WARN if issues else Verdict.PASS),
                  summary=summary, issues=issues, grader=GraderKind.IAM)


def _errored(summary: str) -> Report:
    return Report(verdict=Verdict.FAIL, summary=summary, grader=GraderKind.IAM, errored=True)


# ---------------------------------------------------------------------------
# Pure parsers over the cloud analyzers' JSON.
# ---------------------------------------------------------------------------
_AWS_VALIDATE_SEV = {
    "ERROR": Severity.ERROR, "SECURITY_WARNING": Severity.ERROR,
    "WARNING": Severity.WARNING, "SUGGESTION": Severity.INFO,
}


def parse_aws_validate_policy(out: str, err: str = "") -> list[Issue]:
    """`aws accessanalyzer validate-policy`: {"findings":[{findingType,issueCode,findingDetails}]}.
    ERROR + SECURITY_WARNING gate; WARNING advises; SUGGESTION informs."""
    try:
        data = json.loads(out or "{}")
    except (json.JSONDecodeError, RecursionError, ValueError):
        return []
    issues = []
    for f in data.get("findings", []) if isinstance(data, dict) else []:
        if not isinstance(f, dict):  # a non-dict element must not crash the parser (round-15 R15-1)
            continue
        ft = f.get("findingType", "WARNING")
        issues.append(_iam_issue(f.get("issueCode", "VALIDATE"),
                                 _AWS_VALIDATE_SEV.get(ft, Severity.WARNING),
                                 f"{f.get('issueCode', '')}: {f.get('findingDetails', '')}".strip(),
                                 None))
    return issues


def parse_aws_simulate(out: str, err: str = "", sensitive: set[str] | None = None) -> list[Issue]:
    """`aws iam simulate-principal-policy`: {"EvaluationResults":[{EvalActionName,EvalDecision,
    EvalResourceName}]}. An effectively-ALLOWED sensitive action is a gating finding."""
    sensitive = sensitive or _SENSITIVE_ACTIONS
    try:
        data = json.loads(out or "{}")
    except (json.JSONDecodeError, RecursionError, ValueError):
        return []
    issues = []
    for r in data.get("EvaluationResults", []) if isinstance(data, dict) else []:
        if not isinstance(r, dict):  # round-15 R15-1
            continue
        action = str(r.get("EvalActionName", ""))
        if action.lower() not in sensitive:
            continue
        if r.get("EvalDecision") == "allowed":
            res = r.get("EvalResourceName", "*")
            issues.append(_iam_issue("EFFECTIVE_ALLOW", Severity.ERROR,
                                     f"principal is effectively allowed {action} on {res}", action))
        # Per-resource results can ALLOW a specific resource even when the top-level decision is a
        # generic implicitDeny — that allow is the real grant and must not be missed (E2).
        for rsr in r.get("ResourceSpecificResults", []) if isinstance(r, dict) else []:
            if isinstance(rsr, dict) and rsr.get("EvalResourceDecision") == "allowed":
                res = rsr.get("EvalResourceName", "*")
                issues.append(_iam_issue("EFFECTIVE_ALLOW", Severity.ERROR,
                                         f"principal is effectively allowed {action} on {res}", action))
    return issues


def parse_gcp_analyze_iam(out: str, err: str = "") -> list[Issue]:
    """`gcloud asset analyze-iam-policy --format=json`: {"mainAnalysis":{"analysisResults":[{"iamBinding":
    {"role","members":[...]}}]}} (also tolerates a top-level analysisResults). Admin roles or public
    members gate."""
    try:
        data = json.loads(out or "{}")
    except (json.JSONDecodeError, RecursionError, ValueError):
        return []
    main = data.get("mainAnalysis", data) if isinstance(data, dict) else {}
    results = main.get("analysisResults", []) if isinstance(main, dict) else []
    issues = []
    for r in results:
        b = (r or {}).get("iamBinding", {}) if isinstance(r, dict) else {}
        role = str(b.get("role", "")).lower()
        members = [str(m).lower() for m in b.get("members", []) or []]
        if role in _GCP_GATING_ROLES:
            issues.append(_iam_issue("ADMIN_GRANT", Severity.ERROR,
                                     f"effective admin/privesc role {role}", role))
        if any(m.split(":")[-1] in _PUBLIC for m in members):
            issues.append(_iam_issue("PUBLIC_PRINCIPAL", Severity.CRITICAL,
                                     f"effective public member on {role}", role))
    return issues


def parse_az_role_assignments(out: str, err: str = "") -> list[Issue]:
    """`az role assignment list --all -o json`: [{principalName,roleDefinitionName,scope}]. Admin
    roles at a subscription/management-group scope gate."""
    try:
        data = json.loads(out or "[]")
    except (json.JSONDecodeError, RecursionError, ValueError):
        return []
    issues = []
    for a in data if isinstance(data, list) else []:
        if not isinstance(a, dict):  # round-15 R15-1
            continue
        role = str(a.get("roleDefinitionName", "")).lower()
        # An assignment can surface only a roleDefinitionId GUID (empty/renamed name) — match the GUID
        # tail against the offline sensor's built-in admin/privesc GUIDs so it can't slip through (E4).
        guid = str(a.get("roleDefinitionId", "")).rstrip("/").split("/")[-1].lower()
        scope = str(a.get("scope", ""))
        broad = scope.count("/") <= 2 or "/managementGroups/" in scope  # /subscriptions/<id> or higher
        if (role in _ADMIN_AZURE_ROLES or guid in _AZURE_GATING_GUIDS) and broad:
            issues.append(_iam_issue("ADMIN_GRANT", Severity.ERROR,
                                     f"effective {role or guid} at {scope}", scope))
    return issues


def _bad_output(out: str) -> bool:
    """rc==0 but EMPTY or non-JSON output ⇒ the analyzer didn't return a result we can trust → errored,
    NOT a silent PASS. These analyzers always emit a JSON envelope on success, so empty stdout on rc==0
    is a soft-failure that must not read as 'no findings' (red-team R3-F5)."""
    if not out.strip():
        return True
    try:
        json.loads(out)
    except (json.JSONDecodeError, RecursionError, ValueError):
        return True
    return False


class EffectiveAccessVerifier:
    def __init__(self, *, runner: EnvRunner = subprocess_env_runner):
        self._run = runner

    def _exec(self, cmd: list[str], env: dict[str, str]) -> tuple[int, str, str]:
        """Never let a hang/exec-error escape — it becomes a non-zero rc the callers treat as errored."""
        try:
            return self._run(cmd, env)
        except subprocess.TimeoutExpired:
            return (124, "", "timed out")
        except OSError as e:
            return (127, "", f"exec error: {type(e).__name__}: {e}")

    def aws_validate_policy(self, policy_file: str, creds: CloudCreds) -> Report:
        if not creds.available:
            return _errored(f"aws: no credentials ({creds.source})")
        safe_arg(policy_file, "policy file")  # no option/metachar injection into the aws CLI
        rc, out, err = self._exec(
            ["aws", "accessanalyzer", "validate-policy", "--policy-type", "IDENTITY_POLICY",
             "--policy-document", f"file://{policy_file}", "--output", "json"], creds.env)
        if rc != 0:
            return _errored(f"aws validate-policy failed: {err[:200]}")
        if _bad_output(out):
            return _errored("aws validate-policy: empty/unparseable output")
        return _report(parse_aws_validate_policy(out), "aws: policy validated")

    def aws_simulate_principal(self, principal_arn: str, actions: list[str], creds: CloudCreds) -> Report:
        """The TRUE effective-access check for AWS — `aws iam simulate-principal-policy` asks the
        account what `principal_arn` is ACTUALLY allowed to do (across all attached/inline/boundary/SCP
        policies), not what one document says. This is the "verify against reality" path; `validate-
        policy` (above) is only a static lint of a local document (round-7 R7-1). Fail closed on no
        creds / CLI error / empty output."""
        if not creds.available:
            return _errored(f"aws: no credentials ({creds.source})")
        safe_arg(principal_arn, "principal arn")
        acts = safe_args(actions, "action name")  # no option/metachar injection into the aws CLI
        if not acts:
            return _errored("aws simulate: no action names supplied")
        rc, out, err = self._exec(
            ["aws", "iam", "simulate-principal-policy", "--policy-source-arn", principal_arn,
             "--action-names", *acts, "--output", "json"], creds.env)
        if rc != 0:
            return _errored(f"aws simulate-principal-policy failed: {err[:200]}")
        if _bad_output(out):
            return _errored("aws simulate-principal-policy: empty/unparseable output")
        return _report(parse_aws_simulate(out),
                       f"aws: simulated {len(acts)} action(s) for {principal_arn}")

    def gcp_analyze_iam(self, scope: str, creds: CloudCreds) -> Report:
        if not creds.available:
            return _errored(f"gcp: no credentials ({creds.source})")
        safe_arg(scope, "gcp scope")  # e.g. projects/<id> — no flag/metachar injection into gcloud
        # Bind cred identity to the audited target: if the SA key names a project AND the scope names a
        # DIFFERENT project, we'd be analyzing the wrong reality and reporting it as the target's —
        # fail closed instead of presenting a falsely-scoped green (round-6 finding E3).
        scope_proj = scope.split("projects/", 1)[1].split("/")[0] if "projects/" in scope else ""
        if creds.project and scope_proj and creds.project != scope_proj:
            return _errored(f"gcp: credential project {creds.project!r} does not match audited scope "
                            f"project {scope_proj!r} — refusing to report a mismatched reality")
        rc, out, err = self._exec(
            ["gcloud", "asset", "analyze-iam-policy", "--scope", scope, "--format", "json"], creds.env)
        if rc != 0:
            return _errored(f"gcloud analyze-iam-policy failed: {err[:200]}")
        if _bad_output(out):
            return _errored("gcloud analyze-iam-policy: empty/unparseable output")
        return _report(parse_gcp_analyze_iam(out), "gcp: effective IAM analyzed")

    def azure_role_assignments(self, creds: CloudCreds) -> Report:
        if not creds.available:
            return _errored(f"azure: no credentials ({creds.source})")
        rc, out, err = self._exec(["az", "role", "assignment", "list", "--all", "-o", "json"], creds.env)
        if rc != 0:
            return _errored(f"az role assignment list failed: {err[:200]}")
        if _bad_output(out):
            return _errored("az role assignment list: empty/unparseable output")
        return _report(parse_az_role_assignments(out), "azure: role assignments analyzed")
