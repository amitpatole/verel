"""Cloud credential resolution for the effective-access verifier (IAC-KICKOFF.md Phase 5).

House rule: secrets are external-service creds under `~/.config/`, never in a repo. This resolves
AWS / GCP / Azure credentials from that layout into the environment a cloud CLI subprocess needs.

Credential VALUES are never logged — `CloudCreds.__repr__` shows only env *key names* and the
provenance PATH (safe to put in a receipt). Fail closed: absent/unreadable creds ⇒ `available=False`
⇒ the verifier returns an errored Report, never a silent pass.

Layout resolved (matches this machine; falls back gracefully elsewhere):
  AWS    ~/.config/AWS/rootkey.csv     cols "Access key ID","Secret access key"
  GCP    ~/.config/gcp/<sa>.json       service_account key  (+ ~/.config/gcloud as CLOUDSDK_CONFIG)
  Azure  ~/.azure/                     az CLI config dir (AZURE_CONFIG_DIR)  (+ ~/.config/Azure/key)
"""

from __future__ import annotations

import csv
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

_MAX_CRED_BYTES = 1 * 1024 * 1024  # a credential file is small; cap the read


def _secure_cred_read(path: Path) -> str | None:
    """Read a credential file ONLY if it is a regular file owned by us — reject a symlink (swap
    attack) or a foreign-owned file (substitution attack), mirroring the signing-key hardening in
    verel._secrets. Returns the text, or None (⇒ caller treats creds as absent / fail closed).
    NOTE: file *mode* (group/world-readable) is surfaced as a warning by the caller, not hard-failed,
    so a pre-existing 0644 cred file keeps working — the symlink/owner checks are the real defense."""
    # O_NOFOLLOW rejects a symlinked FINAL component (→ ELOOP); then fstat the OPEN fd (not a prior
    # lstat) so the regular-file + owner checks apply to the exact bytes we'll read — no lstat→open race.
    # O_NONBLOCK so opening a planted FIFO/device doesn't BLOCK before the S_ISREG check (DoS) — it's a
    # no-op for read() on a regular file.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError:
        return None
    try:
        with os.fdopen(fd, encoding="utf-8-sig") as f:  # closes fd on every exit, incl. early return
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode):
                return None
            if hasattr(os, "getuid") and st.st_uid != os.getuid():
                return None
            return f.read(_MAX_CRED_BYTES)
    except OSError:
        return None


def _world_or_group_readable(path: Path) -> bool:
    try:
        return bool(path.lstat().st_mode & 0o077)
    except OSError:
        return False


_AWS_KEY_ID = re.compile(r"^[A-Z0-9]{16,128}$")
_GCP_SA_REQUIRED = ("private_key", "client_email", "token_uri", "private_key_id")


@dataclass
class CloudCreds:
    cloud: str
    available: bool
    source: str = ""  # provenance PATH only — safe to log / put in a receipt
    project: str = ""  # gcp project_id / non-secret account hint
    warning: str = ""  # non-fatal advisory (e.g. loose file mode) — safe to surface
    env: dict[str, str] = field(default_factory=dict, repr=False)  # secret values — kept out of repr

    def __repr__(self) -> str:  # never leak secret values
        return (f"CloudCreds(cloud={self.cloud!r}, available={self.available}, "
                f"source={self.source!r}, warning={self.warning!r}, env_keys={sorted(self.env)})")


def _config_home() -> Path:
    return Path.home() / ".config"


def _col(row: dict, *names: str) -> str:
    """Case-insensitive column lookup tolerant of header whitespace/BOM."""
    for n in names:
        for k, v in row.items():
            if k and k.strip().lower() == n.lower():
                return (v or "").strip()
    return ""


def resolve_aws(config_home: Path | None = None) -> CloudCreds:
    base = config_home or _config_home()
    p = base / "AWS" / "rootkey.csv"
    text = _secure_cred_read(p)
    if text is None:
        return CloudCreds("aws", False, str(p))
    rows = list(csv.DictReader(text.splitlines()))
    if not rows:
        return CloudCreds("aws", False, str(p))
    kid = _col(rows[0], "Access key ID", "AccessKeyId", "aws_access_key_id")
    sec = _col(rows[0], "Secret access key", "SecretAccessKey", "aws_secret_access_key")
    # Shape-validate so garbage/partial rows don't report a confusing "creds present".
    if not _AWS_KEY_ID.match(kid) or len(sec) < 30:
        return CloudCreds("aws", False, str(p))
    warn = "rootkey.csv is group/world-readable — `chmod 600`" if _world_or_group_readable(p) else ""
    return CloudCreds("aws", True, str(p), warning=warn,
                      env={"AWS_ACCESS_KEY_ID": kid, "AWS_SECRET_ACCESS_KEY": sec})


def resolve_gcp(config_home: Path | None = None) -> CloudCreds:
    base = config_home or _config_home()
    gcp_dir = base / "gcp"
    sa_path: Path | None = None
    project = ""
    warn = ""
    if gcp_dir.exists():
        for f in sorted(gcp_dir.glob("*.json")):
            text = _secure_cred_read(f)  # reject symlink / foreign-owned SA-key files
            if text is None:
                continue
            try:
                d = json.loads(text)
            except (json.JSONDecodeError, ValueError):
                continue
            # Require a FULL service-account key (type alone is plant-able / a stub auths nowhere).
            if isinstance(d, dict) and d.get("type") == "service_account" \
                    and all(d.get(k) for k in _GCP_SA_REQUIRED):
                sa_path = f
                project = str(d.get("project_id", ""))
                # A valid SA key may omit project_id; derive it from the client_email
                # (svc@<project>.iam.gserviceaccount.com) so the verifier's cred↔scope binding stays
                # active rather than silently disabling itself (round-7 R7-2).
                if not project:
                    # Derive the project id from the SA email so the cred↔scope binding stays active
                    # when the key omits project_id (round-7 R7-2, round-8 F1). Two forms:
                    #   user-managed  name@<project>.iam.gserviceaccount.com  (project AFTER @)
                    #   App Engine    <project>@appspot.gserviceaccount.com    (project is local-part)
                    # NOT `<num>-compute@developer.gserviceaccount.com` — its local-part is the project
                    # NUMBER, which would cause a FALSE mismatch, so it is deliberately left unmatched.
                    email = str(d.get("client_email", ""))
                    m = re.search(r"@([a-z0-9-]+)\.iam\.gserviceaccount\.com", email) \
                        or re.match(r"([a-z0-9-]+)@appspot\.gserviceaccount\.com", email)
                    if m:
                        project = m.group(1)
                if _world_or_group_readable(f):
                    warn = f"{f.name} is group/world-readable — `chmod 600`"
                break
    env: dict[str, str] = {}
    if sa_path:
        env["GOOGLE_APPLICATION_CREDENTIALS"] = str(sa_path)
    gcloud_dir = base / "gcloud"
    if gcloud_dir.exists():
        env["CLOUDSDK_CONFIG"] = str(gcloud_dir)
    # Need a valid service-account key to authenticate non-interactively; gcloud dir alone is not enough.
    return CloudCreds("gcp", bool(sa_path), str(sa_path) if sa_path else str(gcp_dir),
                      project=project, warning=warn, env=env)


# Only actual TOKEN material — NOT azureProfile.json, which is a subscription list that PERSISTS
# after `az logout` and would falsely report creds-present when logged out (round-7 R7-5).
_AZURE_TOKEN_FILES = ("msal_token_cache.json", "msal_token_cache.bin", "accessTokens.json")


def resolve_azure(config_home: Path | None = None, home: Path | None = None) -> CloudCreds:
    base = config_home or _config_home()
    h = home or Path.home()
    az_dir = h / ".azure"
    is_dir = az_dir.is_dir() and not az_dir.is_symlink()  # reject a swapped-in symlinked config dir
    env: dict[str, str] = {}
    if is_dir:
        env["AZURE_CONFIG_DIR"] = str(az_dir)
    # The dir EXISTING is not credentials (it persists after `az logout`); require token material.
    has_creds = is_dir and any((az_dir / f).exists() for f in _AZURE_TOKEN_FILES)
    return CloudCreds("azure", has_creds,
                      str(az_dir) if is_dir else str(base / "Azure" / "key"), env=env)


def resolve(cloud: str, config_home: Path | None = None) -> CloudCreds:
    if cloud == "aws":
        return resolve_aws(config_home)
    if cloud == "gcp":
        return resolve_gcp(config_home)
    if cloud == "azure":
        return resolve_azure(config_home)
    return CloudCreds(cloud, False, "")
