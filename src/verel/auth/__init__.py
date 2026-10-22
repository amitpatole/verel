"""`verel.auth` — roles, tenants, hashed bearer tokens, optional OIDC SSO, and an audit trail."""

from __future__ import annotations

from .audit import AuditLog
from .oidc import OIDCConfig, OIDCVerifier
from .rbac import PERMISSIONS, Principal, Role, parse_role, valid_tenant
from .tokens import TokenStore, add_token, generate_token, list_tokens, revoke_token


class Authenticator:
    """Bearer-token first, then OIDC. Returns a `Principal` or None (deny)."""

    def __init__(self, tokens: TokenStore | None = None, oidc: OIDCVerifier | None = None):
        if tokens is None and oidc is None:
            raise ValueError("an Authenticator needs a token store or an OIDC verifier")
        self.tokens, self.oidc = tokens, oidc

    def authenticate(self, authorization: str | None) -> Principal | None:
        if not authorization or not authorization.startswith("Bearer "):
            return None
        tok = authorization[7:].strip()
        if self.tokens is not None:
            p = self.tokens.authenticate(tok)
            if p is not None:
                return p
        return self.oidc.authenticate(tok) if self.oidc is not None else None


__all__ = ["AuditLog", "Authenticator", "OIDCConfig", "OIDCVerifier", "PERMISSIONS", "Principal", "Role",
           "TokenStore", "add_token", "generate_token", "list_tokens", "parse_role", "revoke_token",
           "valid_tenant"]
