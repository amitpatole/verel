"""OIDC / SSO bearer-JWT verification (needs `pip install "verel[sso]"`).

Hardening choices: an explicit algorithm allowlist (asymmetric only; `none` and HS* are never accepted,
which closes the classic alg-confusion attacks); `exp`, `iss` and `aud` are REQUIRED; the role and
tenant come from claims and an unknown or missing one DENIES (it never defaults to a role); keys come
from a local JWKS file or an https URL fetched through the same SSRF guard as the telecom scraper.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .rbac import Principal, parse_role, valid_tenant

ALLOWED_ALGS = ("RS256", "RS384", "RS512", "ES256", "ES384", "PS256")
MAX_JWKS_BYTES = 1_000_000
MAX_JWT_LEN = 16_384


class MissingSSODep(RuntimeError):
    pass


@dataclass
class OIDCConfig:
    issuer: str
    audience: str
    jwks_file: str | None = None
    jwks_url: str | None = None
    algorithms: tuple[str, ...] = ("RS256", "ES256")
    role_claim: str = "verel_role"
    tenant_claim: str = "verel_tenant"
    leeway_s: int = 30
    jwks_ttl_s: int = 300

    def __post_init__(self) -> None:
        if not self.issuer or not self.audience:
            raise ValueError("OIDC needs both issuer and audience")
        if bool(self.jwks_file) == bool(self.jwks_url):
            raise ValueError("provide exactly one of jwks_file or jwks_url")
        bad = [a for a in self.algorithms if a not in ALLOWED_ALGS]
        if bad or not self.algorithms:
            raise ValueError(f"algorithms must be a non-empty subset of {ALLOWED_ALGS}; got {bad or 'none'}")
        if not 0 <= self.leeway_s <= 120:
            raise ValueError("leeway_s must be within 0..120")
        if self.jwks_url and not self.jwks_url.startswith("https://"):
            raise ValueError("jwks_url must be https")


class OIDCVerifier:
    def __init__(self, cfg: OIDCConfig):
        try:
            import jwt  # noqa: F401
        except ImportError as e:
            raise MissingSSODep('SSO needs PyJWT: pip install "verel[sso]"') from e
        self.cfg = cfg
        self._jwks: dict[str, Any] | None = None
        self._loaded_at = 0.0
        self._last_refresh = 0.0

    def _fetch(self) -> dict[str, Any]:
        c = self.cfg
        if c.jwks_file:
            p = Path(c.jwks_file)
            if p.stat().st_size > MAX_JWKS_BYTES:
                raise ValueError("JWKS file too large")
            raw = p.read_bytes()
        else:
            from ..ci.telecom_fetch import _get
            assert c.jwks_url
            raw = _get(c.jwks_url, timeout=10.0, max_bytes=MAX_JWKS_BYTES, verify_tls=True,
                       allow_link_local=False)
        doc = json.loads(raw)
        if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
            raise ValueError("JWKS must be an object with a `keys` list")
        return doc

    def _keyset(self, force: bool = False):
        import jwt
        now = time.monotonic()
        stale = self._jwks is None or now - self._loaded_at > self.cfg.jwks_ttl_s
        if force and now - self._last_refresh < 60:  # unknown-kid refresh is rate limited
            force = False
        if stale or force:
            self._last_refresh = now
            self._jwks = self._fetch()
            self._loaded_at = now
        assert self._jwks is not None
        return jwt.PyJWKSet.from_dict(self._jwks)

    def authenticate(self, token: str) -> Principal | None:
        """Return a Principal for a valid token, else None. Never raises on hostile input."""
        import jwt
        if not isinstance(token, str) or not token or len(token) > MAX_JWT_LEN or token.count(".") != 2:
            return None
        try:
            header = jwt.get_unverified_header(token)
            alg, kid = header.get("alg"), header.get("kid")
            if alg not in self.cfg.algorithms:
                return None
            ks = self._keyset()
            key = next((k for k in ks.keys if kid is not None and k.key_id == kid), None)
            if key is None:
                fresh = self._keyset(force=True)
                key = next((k for k in fresh.keys if kid is not None and k.key_id == kid), None)
            if key is None:
                return None  # no kid fallback: guessing a key is how key-confusion starts
            claims = jwt.decode(token, key.key, algorithms=list(self.cfg.algorithms),
                                audience=self.cfg.audience, issuer=self.cfg.issuer, leeway=self.cfg.leeway_s,
                                options={"require": ["exp", "iss", "aud", "sub"]})
            role = parse_role(claims.get(self.cfg.role_claim), strict=True)
            tenant = valid_tenant(claims.get(self.cfg.tenant_claim))
            return Principal(f"oidc:{claims['sub']}"[:128], role, tenant, "oidc")
        except Exception:  # noqa: BLE001 - any failure is a denial, never a crash or an oracle
            return None
