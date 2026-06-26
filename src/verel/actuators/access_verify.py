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

from ..ci.iac import safe_arg
from ..verdict.models import Confidence, GraderKind, Issue, IssueKind, Report, Severity, Verdict
from .cloudcreds import CloudCreds

# Env-aware runner (cloud creds must reach the subprocess). Distinct from ci.graders.Runner (no env).
EnvRunner = Callable[[list[str], "dict[str, str] | None"], "tuple[int, str, str]"]


def subprocess_env_runner(cmd: list[str], env: dict[str, str] | None = None, *,
                          timeout: int = 120) -> tuple[int, str, str]:
    full = {**os.environ, **(env or {})}
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=full)  # noqa: S603
    return r.returncode, r.stdout, r.stderr


# Actions that, if EFFECTIVELY allowed on a broad resource, indicate a privilege-escalation / admin
# reach worth flagging in a simulate result (the same primitives the pre-apply sensor watches).
_SENSITIVE_ACTIONS = {
    "iam:passrole", "iam:createpolicyversion", "iam:attachrolepolicy", "iam:attachuserpolicy",
    "iam:createaccesskey", "iam:putrolepolicy", "sts:assumerole", "*",
}
_ADMIN_GCP_ROLES = {"roles/owner", "roles/editor"}
_ADMIN_AZURE_ROLES = {"owner", "contributor", "user access administrator"}
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
        action = str(r.get("EvalActionName", ""))
        if r.get("EvalDecision") == "allowed" and action.lower() in sensitive:
            res = r.get("EvalResourceName", "*")
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
        if role in _ADMIN_GCP_ROLES:
            issues.append(_iam_issue("ADMIN_GRANT", Severity.ERROR,
                                     f"effective admin role {role}", role))
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
        role = str(a.get("roleDefinitionName", "")).lower()
        scope = str(a.get("scope", ""))
        broad = scope.count("/") <= 2 or "/managementGroups/" in scope  # /subscriptions/<id> or higher
        if role in _ADMIN_AZURE_ROLES and broad:
            issues.append(_iam_issue("ADMIN_GRANT", Severity.ERROR,
                                     f"effective {role} at {scope}", scope))
    return issues


def _unparseable(out: str) -> bool:
    """rc==0 but non-empty output that isn't valid JSON ⇒ the analyzer didn't return a result we can
    trust → errored, NOT a silent PASS (a tool that exits 0 with garbage must not read as 'no findings')."""
    if not out.strip():
        return False
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
        if _unparseable(out):
            return _errored("aws validate-policy: unparseable output")
        return _report(parse_aws_validate_policy(out), "aws: policy validated")

    def gcp_analyze_iam(self, scope: str, creds: CloudCreds) -> Report:
        if not creds.available:
            return _errored(f"gcp: no credentials ({creds.source})")
        safe_arg(scope, "gcp scope")  # e.g. projects/<id> — no flag/metachar injection into gcloud
        rc, out, err = self._exec(
            ["gcloud", "asset", "analyze-iam-policy", "--scope", scope, "--format", "json"], creds.env)
        if rc != 0:
            return _errored(f"gcloud analyze-iam-policy failed: {err[:200]}")
        if _unparseable(out):
            return _errored("gcloud analyze-iam-policy: unparseable output")
        return _report(parse_gcp_analyze_iam(out), "gcp: effective IAM analyzed")

    def azure_role_assignments(self, creds: CloudCreds) -> Report:
        if not creds.available:
            return _errored(f"azure: no credentials ({creds.source})")
        rc, out, err = self._exec(["az", "role", "assignment", "list", "--all", "-o", "json"], creds.env)
        if rc != 0:
            return _errored(f"az role assignment list failed: {err[:200]}")
        if _unparseable(out):
            return _errored("az role assignment list: unparseable output")
        return _report(parse_az_role_assignments(out), "azure: role assignments analyzed")
