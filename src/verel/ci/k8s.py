"""Kubernetes graders + the native RBAC sensor (IAC-KICKOFF.md, Phase 3).

Renders/validates manifests and grades them on the verdict bus, and — Capture B of the IAM change
sensor — extracts dangerous RBAC out of native Kubernetes manifests *before* they apply:

  * `extract_rbac_risks` — pure over parsed manifest dicts: wildcard rules, escalate/bind/impersonate,
    cluster-wide secret read, cluster-admin / system:masters bindings, anonymous subjects (IAM).
  * `parse_kube_objects`  — JSON manifests (a List object / array / single / NDJSON, e.g.
    `kubectl ... -o json`) → the RBAC sensor. No YAML dependency.
  * `parse_helm_template` — `helm template` YAML output → the RBAC sensor (lazy `pyyaml`, in `verel[iac]`).
  * `parse_kube_score` / `parse_kube_linter` / `parse_polaris` — config posture scanners (SECURITY).

All parsers are pure over canned tool output (the Runner is injected), so the matrix runs offline.
The terraform-provider RBAC path (snake_case) lives in `iac.py::_k8s_rbac`; this module handles native
camelCase manifests — same risk vocabulary, different surface.
"""

from __future__ import annotations

import json
import os

from ..verdict.models import Confidence, GraderKind, Issue, IssueKind, Report, Severity, Verdict
from .graders import GraderSpec
from .iac import _as_list, _load_json, parse_terraform_plan, safe_arg, safe_args

# Cap on a single IaC artifact we read off disk (plan / manifests) before parsing — a hostile repo
# can't OOM us with a multi-GB file. 25 MiB is far above any real terraform plan / manifest set.
_MAX_ARTIFACT_BYTES = 25 * 1024 * 1024

# ---------------------------------------------------------------------------
# The native-manifest RBAC sensor (Capture B).
# ---------------------------------------------------------------------------
_RBAC_KINDS = {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"}
_PRIVESC_VERBS = {"escalate", "bind", "impersonate"}  # k8s RBAC privilege-escalation primitives
_SECRET_READ_VERBS = {"get", "list", "watch", "*"}
_ANON_SUBJECTS = {"system:anonymous", "system:unauthenticated"}
_ANON_GROUPS = {"system:unauthenticated", "system:authenticated"}  # binding to these = effectively public


def _locus(obj: dict) -> str:
    md = obj.get("metadata") or {}
    ns = md.get("namespace")
    kind = obj.get("kind", "")
    name = md.get("name", "")
    return f"{kind}/{ns}/{name}" if ns else f"{kind}/{name}"


def _rbac_issue(rule_id: str, sev: Severity, msg: str, locus: str, kind: str) -> Issue:
    return Issue(
        kind=IssueKind.IAM_RISK, severity=sev, source=GraderKind.IAM, message=msg,
        locator=locus, locator_precise=True, confidence=Confidence.HIGH,
        detail_json=json.dumps({"rule_id": rule_id, "address": locus, "cloud": "k8s",
                                "resource_type": kind}),
    )


def _role_risks(obj: dict, locus: str, cluster: bool) -> list[Issue]:
    kind = obj.get("kind", "")
    out: list[Issue] = []
    for rule in _as_list(obj.get("rules")):
        if not isinstance(rule, dict):
            continue
        verbs = {str(v).lower() for v in _as_list(rule.get("verbs"))}
        res = {str(r).lower() for r in _as_list(rule.get("resources"))}
        if "*" in verbs and "*" in res:
            out.append(_rbac_issue("WILDCARD_RBAC", Severity.ERROR,
                                   f"RBAC rule grants */* at {locus}", locus, kind))
        if verbs & _PRIVESC_VERBS:
            out.append(_rbac_issue("PRIVILEGE_ESCALATION", Severity.CRITICAL,
                                   f"RBAC grants {sorted(verbs & _PRIVESC_VERBS)} at {locus}", locus, kind))
        if "secrets" in res and (verbs & _SECRET_READ_VERBS):
            sev = Severity.ERROR if cluster else Severity.WARNING
            scope = "cluster-wide " if cluster else ""
            out.append(_rbac_issue("SECRETS_ACCESS", sev,
                                   f"grants {scope}read of secrets at {locus}", locus, kind))
    return out


def _binding_risks(obj: dict, locus: str) -> list[Issue]:
    kind = obj.get("kind", "")
    out: list[Issue] = []
    ref = obj.get("roleRef") or {}
    if str(ref.get("name", "")).lower() == "cluster-admin":
        out.append(_rbac_issue("ADMIN_GRANT", Severity.ERROR,
                               f"binding to cluster-admin at {locus}", locus, kind))
    for s in _as_list(obj.get("subjects")):
        if not isinstance(s, dict):
            continue
        nm = str(s.get("name", "")).lower()
        skind = str(s.get("kind", ""))
        if nm == "system:masters":
            out.append(_rbac_issue("ADMIN_GRANT", Severity.ERROR,
                                   f"binding to system:masters at {locus}", locus, kind))
        elif nm in _ANON_SUBJECTS or (skind == "Group" and nm in _ANON_GROUPS):
            out.append(_rbac_issue("PUBLIC_PRINCIPAL", Severity.CRITICAL,
                                   f"binding to an anonymous/unauthenticated subject at {locus}",
                                   locus, kind))
    return out


def extract_rbac_risks(manifests: list) -> list[Issue]:
    """Run the deterministic RBAC risk rules over native Kubernetes manifest dicts → IAM issues."""
    out: list[Issue] = []
    for obj in manifests:
        if not isinstance(obj, dict):
            continue
        kind = obj.get("kind", "")
        if kind not in _RBAC_KINDS:
            continue
        locus = _locus(obj)
        if kind in ("Role", "ClusterRole"):
            out.extend(_role_risks(obj, locus, cluster=kind.startswith("Cluster")))
        else:
            out.extend(_binding_risks(obj, locus))
    return out


# ---------------------------------------------------------------------------
# Manifest loaders → the RBAC sensor (GraderKind.IAC).
# ---------------------------------------------------------------------------
def _load_manifests(out: str) -> list:
    """Parse a stream of Kubernetes objects: a List object ({"items":[...]}), a single object, a JSON
    array, or NDJSON (one object per line, e.g. `kubectl get -o json` / `--dry-run -o json`)."""
    text = out or ""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError, ValueError):
        objs: list = []
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    objs.append(json.loads(line))
                except (json.JSONDecodeError, RecursionError, ValueError):
                    continue
        return objs
    if isinstance(data, dict):
        if isinstance(data.get("items"), list):
            return data["items"]
        return [data] if data.get("kind") else []
    return data if isinstance(data, list) else []


def parse_kube_objects(out: str, err: str = "") -> list[Issue]:
    """JSON Kubernetes manifests → RBAC risk sensor (no YAML dependency)."""
    return extract_rbac_risks(_load_manifests(out))


def parse_helm_template(out: str, err: str = "") -> list[Issue]:
    """`helm template` YAML (multi-doc) → RBAC risk sensor. YAML support is lazy (`pyyaml`, in
    `verel[iac]`); without it the RBAC scan is skipped with a visible WARNING (not a silent green)."""
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        return [Issue(kind=IssueKind.OTHER, severity=Severity.WARNING, source=GraderKind.IAC,
                      message="helm RBAC scan skipped: pyyaml not installed (`pip install verel[iac]`)",
                      detail_json=json.dumps({"rule_id": "pyyaml-missing"}))]
    try:
        docs = [d for d in yaml.safe_load_all(out or "") if isinstance(d, dict)]
    except yaml.YAMLError:
        return [Issue(kind=IssueKind.OTHER, severity=Severity.ERROR, source=GraderKind.IAC,
                      message="helm template output is not valid YAML",
                      detail_json=json.dumps({"rule_id": "helm-yaml-error"}))]
    return extract_rbac_risks(docs)


# ---------------------------------------------------------------------------
# Config posture scanners (GraderKind.SECURITY).
# ---------------------------------------------------------------------------
def parse_kube_score(out: str, err: str = "") -> list[Issue]:
    """kube-score `--output-format json`: a list of {object_name, checks:[{check:{id,name},grade,
    comments:[{summary}]}]}. grade 1=critical, 5/7=warning, 10=ok. <=1 gates, <10 advises."""
    try:
        data = json.loads(out or "[]")
    except (json.JSONDecodeError, RecursionError, ValueError):
        return []
    issues: list[Issue] = []
    for obj in data if isinstance(data, list) else []:
        name = obj.get("object_name", "")
        for chk in obj.get("checks", []) or []:
            grade = chk.get("grade", 10)
            if isinstance(grade, (int, float)) and grade >= 10:
                continue
            sev = Severity.ERROR if (isinstance(grade, (int, float)) and grade <= 1) else Severity.WARNING
            c = chk.get("check") or {}
            comments = chk.get("comments") or []
            summ = comments[0].get("summary", "") if comments and isinstance(comments[0], dict) else ""
            issues.append(Issue(
                kind=IssueKind.MISCONFIG, severity=sev, source=GraderKind.SECURITY,
                message=f"{c.get('name', 'kube-score')} {summ}".strip(), locator=name or None,
                detail_json=json.dumps({"rule_id": c.get("id", "kube-score")}),
            ))
    return issues


def parse_kube_linter(out: str, err: str = "") -> list[Issue]:
    """kube-linter `lint --format json`: {"Reports":[{Check,Diagnostic:{Message},
    Object:{K8sObject:{Namespace,Name,GroupVersionKind:{Kind}}}}]}. No severity → WARNING."""
    data = _load_json(out)
    issues: list[Issue] = []
    for r in data.get("Reports", []) if isinstance(data, dict) else []:
        diag = r.get("Diagnostic") or {}
        o = (r.get("Object") or {}).get("K8sObject") or {}
        gvk = o.get("GroupVersionKind") or {}
        locus = f"{gvk.get('Kind', '')}/{o.get('Namespace', '')}/{o.get('Name', '')}"
        check = r.get("Check", "kube-linter")
        issues.append(Issue(
            kind=IssueKind.MISCONFIG, severity=Severity.WARNING, source=GraderKind.SECURITY,
            message=f"{check} {diag.get('Message', '')}".strip(), locator=locus,
            detail_json=json.dumps({"rule_id": check}),
        ))
    return issues


def _polaris_failed(node: object) -> list[dict]:
    """Walk a polaris result tree, collecting failed ResultMessage dicts (Success is False).
    Iterative (explicit stack) + depth-bounded so a deeply-nested hostile tree can't overflow."""
    found: list[dict] = []
    stack: list[tuple[object, int]] = [(node, 0)]
    while stack:
        cur, depth = stack.pop()
        if depth > 200:
            continue
        if isinstance(cur, dict):
            if "Success" in cur and "Severity" in cur:
                if cur.get("Success") is False:
                    found.append(cur)
                continue
            for v in cur.values():
                stack.append((v, depth + 1))
        elif isinstance(cur, list):
            for v in cur:
                stack.append((v, depth + 1))
    return found


def parse_polaris(out: str, err: str = "") -> list[Issue]:
    """polaris `audit --format json`: {"Results":[{Name,Namespace,Kind, ...nested checks...}]}. Each
    failed check carries a Severity (danger→ERROR, warning→WARNING) and a Message."""
    data = _load_json(out)
    issues: list[Issue] = []
    for res in data.get("Results", []) if isinstance(data, dict) else []:
        locus = f"{res.get('Kind', '')}/{res.get('Namespace', '')}/{res.get('Name', '')}"
        for chk in _polaris_failed(res):
            sev = Severity.ERROR if str(chk.get("Severity", "")).lower() == "danger" else Severity.WARNING
            cid = chk.get("ID", "polaris")
            issues.append(Issue(
                kind=IssueKind.MISCONFIG, severity=sev, source=GraderKind.SECURITY,
                message=f"{cid} {chk.get('Message', '')}".strip(), locator=locus,
                detail_json=json.dumps({"rule_id": cid}),
            ))
    return issues


# ---------------------------------------------------------------------------
# Spec constructors.
# ---------------------------------------------------------------------------
def kubectl_dryrun_spec(repo: str, path: str = ".", covers: list[str] | None = None):
    """Validate + RBAC-scan manifests via client-side dry-run (no cluster needed)."""
    return GraderSpec(GraderKind.IAC,
                      ["kubectl", "apply", "-f", safe_arg(path, "manifest path"),
                       "--dry-run=client", "-o", "json"],
                      cwd=repo, covers=covers or [], parser=parse_kube_objects, lang="yaml")


def helm_template_spec(repo: str, chart: str, *, values: list[str] | None = None,
                       covers: list[str] | None = None):
    # safe_arg on chart + values closes helm option-injection — notably `--post-renderer=<prog>`
    # (arbitrary code execution) and `--set`/`-f` smuggling — since a leading `-` is rejected.
    cmd = ["helm", "template", safe_arg(chart, "helm chart")]
    for v in safe_args(values or [], "helm values"):
        cmd += ["-f", v]
    return GraderSpec(GraderKind.IAC, cmd, cwd=repo, covers=covers or [],
                      parser=parse_helm_template, lang="yaml")


def kube_score_spec(repo: str, paths: list[str], covers: list[str] | None = None):
    return GraderSpec(GraderKind.SECURITY,
                      ["kube-score", "score", "--output-format", "json",
                       *safe_args(paths, "kube-score path")],
                      cwd=repo, covers=covers or [], parser=parse_kube_score, lang="yaml")


def kube_linter_spec(repo: str, paths: list[str] | None = None, covers: list[str] | None = None):
    return GraderSpec(GraderKind.SECURITY,
                      ["kube-linter", "lint", "--format", "json",
                       *safe_args(paths or ["."], "kube-linter path")],
                      cwd=repo, covers=covers or [], parser=parse_kube_linter, lang="yaml")


def polaris_spec(repo: str, audit_path: str = ".", covers: list[str] | None = None):
    return GraderSpec(GraderKind.SECURITY,
                      ["polaris", "audit", "--audit-path", safe_arg(audit_path, "audit path"),
                       "--format", "json"],
                      cwd=repo, covers=covers or [], parser=parse_polaris, lang="yaml")


# ---------------------------------------------------------------------------
# One offline entry point for the MCP tool + the `verel-ci iac` CLI.
# ---------------------------------------------------------------------------
def _read_in_repo(repo: str, rel: str) -> str:
    """Read a file that MUST live inside `repo` (charset-validate the path against traversal)."""
    path = rel if os.path.isabs(rel) else os.path.join(repo, rel)
    rp = os.path.realpath(path)
    if rp != os.path.realpath(repo) and not rp.startswith(os.path.realpath(repo) + os.sep):
        raise ValueError(f"path escapes the repo: {rel!r}")
    if not os.path.isfile(rp):
        raise FileNotFoundError(rel)
    if os.path.getsize(rp) > _MAX_ARTIFACT_BYTES:
        raise ValueError(f"artifact too large (> {_MAX_ARTIFACT_BYTES} bytes): {rel!r}")
    with open(rp, encoding="utf-8") as f:
        return f.read(_MAX_ARTIFACT_BYTES + 1)


def grade_iac(repo: str, *, plan: str | None = None, manifests: str | None = None) -> Report:
    """Grade IaC artifacts OFFLINE into one IAC Report (no cloud creds, nothing applied): a
    `terraform show -json` plan (drift + the cloud-IAM change sensor) and/or Kubernetes manifests as
    JSON (the RBAC sensor). Verdict reduces by gating severity — a wildcard/privesc/public/admin grant
    (`ERROR`/`CRITICAL`) FAILs; a planned destroy/replace is surfaced (`INFO`, does not gate."""
    issues: list[Issue] = []
    if plan:
        issues.extend(parse_terraform_plan(_read_in_repo(repo, plan)))
    if manifests:
        issues.extend(parse_kube_objects(_read_in_repo(repo, manifests)))
    gating = any(i.severity in (Severity.ERROR, Severity.CRITICAL) for i in issues)
    verdict = Verdict.FAIL if gating else (Verdict.WARN if issues else Verdict.PASS)
    return Report(verdict=verdict, summary=f"iac: {len(issues)} issue(s)", issues=issues,
                  grader=GraderKind.IAC)
