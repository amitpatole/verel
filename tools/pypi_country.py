#!/usr/bin/env python3
"""Per-country PyPI downloads for Verel + AgentVision, from the BigQuery public dataset.

`bigquery-public-data.pypi.file_downloads` is the ONLY source of country-level PyPI geography.
The table is clustered by project, so filtering to our two packages prunes the scan to a few GB —
a 30-day query is ~6.6 GB (~$0.03, well within the 1 TB/month free tier). Run once a day on a timer;
it writes tools/country_cache.json, which the dashboard reads (the dashboard never queries BQ itself).

Auth uses the service-account key in an ISOLATED gcloud config dir, so it does not disturb your
normal `gcloud`/`bq` login. Configure via env if your paths differ:
  GCP_KEY (service-account json) · GCP_PROJECT · COUNTRY_WINDOW_DAYS (default 30)

Run:  python tools/pypi_country.py
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

SDK = Path.home() / "google-cloud-sdk" / "bin"
KEY = os.environ.get("GCP_KEY", str(Path.home() / ".config/gcp/gen-lang-client-0663036021-07e5f8af360d.json"))
PROJECT = os.environ.get("GCP_PROJECT", "gen-lang-client-0663036021")
WINDOW = int(os.environ.get("COUNTRY_WINDOW_DAYS", "30"))
PACKAGES = ("verel", "agentvision")
SDK_CONFIG = str(Path.home() / ".config/gcp/sdk-metrics")  # isolated gcloud config (won't touch your login)
CACHE = Path(__file__).resolve().parent / "country_cache.json"

_QUERY = (
    "SELECT file.project AS project, IFNULL(country_code,'??') AS country, COUNT(*) AS downloads "
    "FROM `bigquery-public-data.pypi.file_downloads` "
    "WHERE DATE(timestamp) BETWEEN DATE_SUB(CURRENT_DATE(), INTERVAL {win} DAY) AND CURRENT_DATE() "
    "AND file.project IN ({pkgs}) GROUP BY project, country ORDER BY downloads DESC"
)


def _env() -> dict:
    env = dict(os.environ)
    env["CLOUDSDK_CONFIG"] = SDK_CONFIG
    env["PATH"] = f"{SDK}:{env.get('PATH', '')}"
    return env


def main() -> None:
    env = _env()
    # activate the service account inside the isolated config (idempotent)
    subprocess.run([str(SDK / "gcloud"), "auth", "activate-service-account", "--key-file", KEY, "--quiet"],
                   env=env, check=True, capture_output=True, text=True)
    pkgs = ",".join(f"'{p}'" for p in PACKAGES)
    q = _QUERY.format(win=WINDOW, pkgs=pkgs)
    out = subprocess.run([str(SDK / "bq"), f"--project_id={PROJECT}", "query", "--format=json",
                          "--use_legacy_sql=false", "--quiet", q],
                         env=env, capture_output=True, text=True, timeout=180)
    if out.returncode != 0:
        raise SystemExit(f"bq query failed:\n{out.stderr.strip()[:500]}")
    rows = json.loads(out.stdout or "[]")
    by: dict[str, list] = {}
    for r in rows:
        by.setdefault(r["project"], []).append([r["country"], int(r["downloads"])])
    result = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "window_days": WINDOW,
        "countries": by,
    }
    CACHE.write_text(json.dumps(result, indent=2))
    tot = {p: sum(n for _, n in lst) for p, lst in by.items()}
    print(f"wrote {CACHE} · {WINDOW}d · " + " · ".join(f"{p}:{n:,}" for p, n in tot.items()))


if __name__ == "__main__":
    main()
