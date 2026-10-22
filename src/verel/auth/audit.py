"""Authorization audit trail: every allow/deny decision, hash-chained and tamper-evident. Never records
a token or claim body — only who (principal id), where (tenant), what (action) and the outcome."""

from __future__ import annotations

from datetime import datetime, timezone

from .._chainlog import ChainLog, ChainRecord
from .rbac import Principal


class AuditRecord(ChainRecord):
    ts: str
    principal: str
    tenant: str
    action: str
    allowed: bool
    reason: str = ""


class AuditLog(ChainLog[AuditRecord]):
    def __init__(self, path, *, domain: str = ""):
        super().__init__(path, AuditRecord, domain=domain)

    def log(self, principal: Principal | None, action: str, allowed: bool, reason: str = "",
            *, tenant: str = "") -> None:
        self.append(AuditRecord(
            ts=datetime.now(timezone.utc).isoformat(),
            principal=principal.id if principal else "anonymous",
            tenant=principal.tenant if principal else tenant,
            action=action[:128], allowed=allowed, reason=reason[:200]))
