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
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CloudCreds:
    cloud: str
    available: bool
    source: str = ""  # provenance PATH only — safe to log / put in a receipt
    project: str = ""  # gcp project_id / non-secret account hint
    env: dict[str, str] = field(default_factory=dict, repr=False)  # secret values — kept out of repr

    def __repr__(self) -> str:  # never leak secret values
        return (f"CloudCreds(cloud={self.cloud!r}, available={self.available}, "
                f"source={self.source!r}, env_keys={sorted(self.env)})")


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
    if not p.exists():
        return CloudCreds("aws", False, str(p))
    try:
        text = p.read_text(encoding="utf-8-sig")  # utf-8-sig strips the BOM seen in the export
    except OSError:
        return CloudCreds("aws", False, str(p))
    rows = list(csv.DictReader(text.splitlines()))
    if not rows:
        return CloudCreds("aws", False, str(p))
    kid = _col(rows[0], "Access key ID", "AccessKeyId", "aws_access_key_id")
    sec = _col(rows[0], "Secret access key", "SecretAccessKey", "aws_secret_access_key")
    if not kid or not sec:
        return CloudCreds("aws", False, str(p))
    return CloudCreds("aws", True, str(p),
                      env={"AWS_ACCESS_KEY_ID": kid, "AWS_SECRET_ACCESS_KEY": sec})


def resolve_gcp(config_home: Path | None = None) -> CloudCreds:
    base = config_home or _config_home()
    gcp_dir = base / "gcp"
    sa_path: Path | None = None
    project = ""
    if gcp_dir.exists():
        for f in sorted(gcp_dir.glob("*.json")):
            try:
                d = json.loads(f.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(d, dict) and d.get("type") == "service_account":
                sa_path = f
                project = str(d.get("project_id", ""))
                break
    env: dict[str, str] = {}
    if sa_path:
        env["GOOGLE_APPLICATION_CREDENTIALS"] = str(sa_path)
    gcloud_dir = base / "gcloud"
    if gcloud_dir.exists():
        env["CLOUDSDK_CONFIG"] = str(gcloud_dir)
    # Need a service-account key to authenticate non-interactively; gcloud dir alone is not enough.
    return CloudCreds("gcp", bool(sa_path), str(sa_path) if sa_path else str(gcp_dir),
                      project=project, env=env)


def resolve_azure(config_home: Path | None = None, home: Path | None = None) -> CloudCreds:
    base = config_home or _config_home()
    h = home or Path.home()
    az_dir = h / ".azure"
    env: dict[str, str] = {}
    if az_dir.exists():
        env["AZURE_CONFIG_DIR"] = str(az_dir)
    keyfile = base / "Azure" / "key"
    return CloudCreds("azure", az_dir.exists(),
                      str(az_dir) if az_dir.exists() else str(keyfile), env=env)


def resolve(cloud: str, config_home: Path | None = None) -> CloudCreds:
    if cloud == "aws":
        return resolve_aws(config_home)
    if cloud == "gcp":
        return resolve_gcp(config_home)
    if cloud == "azure":
        return resolve_azure(config_home)
    return CloudCreds(cloud, False, "")
