"""Per-tenant storage layout shared by the HTTP service, the job worker and the hot-folder connector."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from ..auth.rbac import valid_tenant


def require_private_dir(d: Path) -> None:
    """The data directories hold evidence and keys-adjacent state: refuse one that another user could
    write into (a planted symlink or file there is how a local attacker redirects our writes)."""
    st = d.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise ValueError(f"{d} must be a real directory, not a symlink")
    if hasattr(os, "getuid") and (st.st_uid != os.getuid() or st.st_mode & 0o022):
        raise ValueError(f"{d} must be owned by this user and not group/world writable")


def tenant_dir(root: Path, tenant: str) -> Path:
    """`<root>/tenants/<tenant>/`, created 0700. The tenant id is charset-validated AND the resolved path is
    re-checked to sit under `<root>/tenants`, so no id can name a path outside it."""
    valid_tenant(tenant)
    base = root / "tenants"
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    require_private_dir(base)
    d = base.resolve() / tenant
    if d.parent != base.resolve():
        raise ValueError("bad tenant")
    d.mkdir(exist_ok=True, mode=0o700)
    require_private_dir(d)
    return d


def log_domain(tenant: str, kind: str) -> str:
    """MAC domain for a tenant's log, so evidence cannot be moved between tenants or log kinds."""
    return f"{tenant}/{kind}"


# -- the tenant's logs (one place, so the service, worker and hot folder agree on paths and MAC domains) --
from .._chainlog import ChainLog, ChainRecord  # noqa: E402
from .log import ShadowLog  # noqa: E402
from .policy import PolicyStore  # noqa: E402


class LabelRecord(ChainRecord):
    ts: str
    by: str
    artifact_id: str
    defect: bool
    amend: bool = False  # an admin correction; the LATEST label for an artifact wins


def current_labels(records: list[LabelRecord]) -> dict[str, LabelRecord]:
    """Latest label per artifact (amendments supersede earlier labels)."""
    out: dict[str, LabelRecord] = {}
    for r in records:
        out[r.artifact_id] = r
    return out


def pilot_log(root: Path, tenant: str) -> ShadowLog:
    return ShadowLog(tenant_dir(root, tenant) / "pilot.jsonl", domain=log_domain(tenant, "pilot"))


def label_log(root: Path, tenant: str) -> ChainLog[LabelRecord]:
    path = tenant_dir(root, tenant) / "labels.jsonl"
    return ChainLog(path, LabelRecord, domain=log_domain(tenant, "labels"), id_field="artifact_id")


def policy_store(root: Path, tenant: str) -> PolicyStore:
    return PolicyStore(tenant_dir(root, tenant) / "policy.jsonl", domain=log_domain(tenant, "policy"))


def audit_log(root: Path, tenant: str):
    from ..auth.audit import AuditLog

    return AuditLog(tenant_dir(root, tenant) / "audit.jsonl", domain=log_domain(tenant, "audit"))


def current_policy(root: Path, tenant: str):
    """The tenant's promotion policy, or None if it has never set one (then plain modes apply)."""
    store = policy_store(root, tenant)
    return store.current() if store.records() else None
