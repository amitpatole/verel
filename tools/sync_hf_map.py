#!/usr/bin/env python3
"""Refresh the HF Space landing-page country map from the latest BigQuery snapshot.

Reads tools/country_cache.json (written daily by pypi_country.py) and surgically updates ONLY the
embedded country data + totals + snapshot date in the LIVE Space index.html, then re-uploads.

Working from the LIVE file (not the repo) means it never clobbers other manual edits to the Space,
and it touches nothing in git. Run after pypi_country.py — the daily timer does both. Idempotent:
if the live snapshot already matches, it uploads nothing.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from huggingface_hub import HfApi, hf_hub_download

REPO = "amitpatole/verel"
CACHE = Path(__file__).resolve().parent / "country_cache.json"
TOKEN = (Path.home() / ".cache/huggingface/token").read_text().strip()


def build_embed() -> tuple[dict, dict[str, int], str]:
    cc = json.loads(CACHE.read_text())
    projects: dict[str, dict] = {}
    totals: dict[str, int] = {}
    for pkg, lst in cc["countries"].items():
        v: dict[str, int] = {}
        tot = 0
        for c, n in lst:
            if c == "??":
                continue
            v[c] = n
            v[c.lower()] = n
            tot += n
        projects[pkg] = v
        totals[pkg] = tot
    embed = {"projects": projects, "labels": {"verel": "Verel", "agentvision": "AgentVision"}}
    return embed, totals, cc["generated"][:10]


def main() -> None:
    embed, totals, date = build_embed()
    vk = f"{totals.get('verel', 0) / 1000:.1f}k"
    ak = f"{totals.get('agentvision', 0) / 1000:.1f}k"
    api = HfApi(token=TOKEN)
    live = Path(hf_hub_download(REPO, "index.html", repo_type="space", token=TOKEN,
                                force_download=True)).read_text()

    new, n_data = re.subn(r"window\.HFCOUNTRY=\{.*?\};",
                          lambda _m: "window.HFCOUNTRY=" + json.dumps(embed) + ";", live, flags=re.S)
    new, n_tot = re.subn(r"<b>Verel ~[0-9.]+k</b> &middot; <b>AgentVision ~[0-9.]+k</b>",
                         lambda _m: f"<b>Verel ~{vk}</b> &middot; <b>AgentVision ~{ak}</b>", new)
    new, n_date = re.subn(r"snapshot \d{4}-\d{2}-\d{2}", lambda _m: f"snapshot {date}", new)

    if not n_data:  # the map markers aren't on the live page — bail rather than corrupt it
        raise SystemExit("HFCOUNTRY marker not found on the live Space — skipping (re-add the map first)")
    if n_tot == 0:
        print("warning: totals headline not matched (page edited?) — data+date updated only")
    if new == live:
        print(f"HF country map already current ({date}) — nothing to upload")
        return
    api.upload_file(path_or_fileobj=new.encode(), path_in_repo="index.html", repo_id=REPO,
                    repo_type="space", commit_message=f"Landing: refresh country map snapshot ({date})")
    print(f"synced HF country map · {date} · verel {totals.get('verel', 0):,} · "
          f"agentvision {totals.get('agentvision', 0):,}")


if __name__ == "__main__":
    main()
