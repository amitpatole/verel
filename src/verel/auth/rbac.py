"""Roles, permissions and tenants. The role→permission table is fixed in code on purpose: nothing a
config file or a token claim says can mint a permission that is not defined here."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

TENANT_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")  # used with fullmatch: `$` would admit a trailing \n


class Role(str, Enum):
    VIEWER = "viewer"      # read evaluations and verify logs
    OPERATOR = "operator"  # + record decisions, add labels, enqueue jobs
    ADMIN = "admin"        # + promote/demote graders, archive logs


_VIEWER = frozenset({"pilot:read"})
_OPERATOR = _VIEWER | {"pilot:record", "pilot:label", "jobs:enqueue", "jobs:read"}
_ADMIN = _OPERATOR | {"pilot:promote", "pilot:archive"}
PERMISSIONS: dict[Role, frozenset[str]] = {Role.VIEWER: _VIEWER, Role.OPERATOR: frozenset(_OPERATOR),
                                           Role.ADMIN: frozenset(_ADMIN)}


def parse_role(value: object, *, strict: bool = False) -> Role:
    """`strict=True` (used for IdP claims) accepts only the exact lowercase role name: no trimming, no
    case folding, no non-string values."""
    try:
        if strict:
            if not isinstance(value, str):
                raise ValueError
            return Role(value)
        return Role(str(value).strip().lower())
    except ValueError:
        known = ", ".join(r.value for r in Role)
        raise ValueError(f"unknown role {value!r}; expected one of: {known}") from None


def valid_tenant(value: object) -> str:
    if not isinstance(value, str) or not TENANT_RE.fullmatch(value):
        raise ValueError("tenant must match [a-z0-9][a-z0-9_-]{0,62}")
    return value


@dataclass(frozen=True)
class Principal:
    id: str
    role: Role
    tenant: str
    source: str = "token"  # token | oidc

    def can(self, permission: str) -> bool:
        return permission in PERMISSIONS[self.role]
