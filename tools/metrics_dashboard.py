#!/usr/bin/env python3
"""Live metrics dashboard for Verel + AgentVision — self-hosted on your network.

Aggregates public adoption metrics and serves an auto-refreshing dashboard:
  * PyPI downloads — lifetime total (pepy.tech), last day/week/month + OS & Python
    breakdown (pypistats), current version (PyPI).
  * GitHub — stars / forks / watchers / open issues, clone & view traffic, and the
    referring sites ("where" repo traffic comes from) via the traffic API.

Run:  python tools/metrics_dashboard.py            # serves on 0.0.0.0:8042
      PORT=9123 REFRESH=300 python tools/metrics_dashboard.py

Open  http://<your-LAN-ip>:8042  from any device on the network.
(Default 8042 avoids the LMDS docker-compose port range; override with PORT=.)

Notes
  * GitHub data uses your local `gh` auth (gh CLI must be logged in). Traffic
    (clones/views/referrers) needs push access to the repos — which you have.
  * Country-level PyPI geography is NOT available from any free API (it lives in
    the Google BigQuery `pypi.file_downloads` dataset). The OS/Python split is the
    client breakdown; GitHub referrers are the closest "from where" signal.
  * Stdlib only. No secrets are served — only aggregate public counts.
"""

# ruff: noqa: E501 — the embedded HTML/CSS dashboard template has intentionally long lines
from __future__ import annotations

import json
import os
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# (PyPI package name, GitHub owner/repo, display label)
PROJECTS = [
    ("verel", "amitpatole/verel", "Verel 🧠"),
    ("agentvision", "amitpatole/agent-vision", "AgentVision 👁️"),
]
REFRESH = int(os.environ.get("REFRESH", "600"))  # seconds between live re-fetches
PORT = int(os.environ.get("PORT", "8042"))  # 8042 dodges the LMDS docker-compose port range


_UA = "verel-metrics-dashboard (+https://github.com/amitpatole/verel)"
_PS_LAST = [0.0]  # last pypistats request time — pypistats rate-limits hard, so we space + retry


def _get(url: str, timeout: float = 15.0, retries: int = 2) -> dict | None:
    is_ps = "pypistats.org" in url
    for attempt in range(retries + 1):
        if is_ps:  # keep ≥1.5s between pypistats hits to stay under its rate limit
            gap = 1.5 - (time.time() - _PS_LAST[0])
            if gap > 0:
                time.sleep(gap)
            _PS_LAST[0] = time.time()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < retries:
                time.sleep(3 * (attempt + 1))  # backoff and retry on rate-limit
                continue
            return None
        except Exception:  # noqa: BLE001 — a dead source degrades to None, never crashes the board
            return None
    return None


def _gh(path: str) -> dict | list | None:
    try:
        out = subprocess.run(["gh", "api", path], capture_output=True, text=True, timeout=20)
        return json.loads(out.stdout) if out.returncode == 0 and out.stdout.strip() else None
    except Exception:  # noqa: BLE001
        return None


def _as_dict(v: object) -> dict:
    return v if isinstance(v, dict) else {}


def _as_list(v: object) -> list:
    return v if isinstance(v, list) else []


def _agg(rows: list[dict] | None) -> dict[str, int]:
    """Sum a pypistats category series into {category: downloads}, biggest first."""
    agg: dict[str, int] = {}
    for r in rows or []:
        agg[r["category"]] = agg.get(r["category"], 0) + r["downloads"]
    return dict(sorted(agg.items(), key=lambda kv: -kv[1]))


_LAST_PYPI: dict[str, dict] = {}  # last good per-package metrics — survive transient rate-limits


def pypi_metrics(pkg: str) -> dict:
    pepy = _get(f"https://pepy.tech/api/v2/projects/{pkg}") or {}
    recent = (_get(f"https://pypistats.org/api/packages/{pkg}/recent") or {}).get("data", {})
    systems = _agg((_get(f"https://pypistats.org/api/packages/{pkg}/system") or {}).get("data"))
    pys = _agg((_get(f"https://pypistats.org/api/packages/{pkg}/python_minor") or {}).get("data"))
    info = (_get(f"https://pypi.org/pypi/{pkg}/json") or {}).get("info", {})
    new = {
        "total": pepy.get("total_downloads"),
        "versions": len(pepy.get("versions", []) or []) or None,
        "version": info.get("version"),
        "day": recent.get("last_day"), "week": recent.get("last_week"), "month": recent.get("last_month"),
        "systems": {k: v for k, v in systems.items() if k != "null"},
        "python": {k: v for k, v in pys.items() if k != "null"},
    }
    # a 429 yields None/{} for some fields — keep the last good value instead of blanking the card
    prev = _LAST_PYPI.get(pkg, {})
    out = {k: (prev.get(k) if (v is None or v == {}) else v) for k, v in new.items()}
    _LAST_PYPI[pkg] = out
    return out


def github_metrics(repo: str) -> dict:
    r = _as_dict(_gh(f"repos/{repo}"))
    clones = _as_dict(_gh(f"repos/{repo}/traffic/clones"))
    views = _as_dict(_gh(f"repos/{repo}/traffic/views"))
    refs = _as_list(_gh(f"repos/{repo}/traffic/popular/referrers"))
    return {
        "stars": r.get("stargazers_count"), "forks": r.get("forks_count"),
        "watchers": r.get("subscribers_count"), "issues": r.get("open_issues_count"),
        "clones": clones.get("count"), "clones_uniq": clones.get("uniques"),
        "views": views.get("count"), "views_uniq": views.get("uniques"),
        "referrers": [(x.get("referrer"), x.get("count")) for x in refs][:8],
    }


def collect() -> dict:
    data: dict = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "projects": []}
    for pkg, repo, label in PROJECTS:
        data["projects"].append({
            "label": label, "pkg": pkg, "repo": repo,
            "pypi": pypi_metrics(pkg), "github": github_metrics(repo),
        })
    return data


_CACHE: dict = {"data": None, "at": 0.0}
_LOCK = threading.Lock()


def cached() -> dict:
    with _LOCK:
        if _CACHE["data"] is None or (time.time() - _CACHE["at"]) > REFRESH:
            _CACHE["data"] = collect()
            _CACHE["at"] = time.time()
        return _CACHE["data"]


# --------------------------------------------------------------------------- UI
def _n(v) -> str:
    return f"{v:,}" if isinstance(v, int) else "—"


def _bars(d: dict[str, int], limit: int = 5) -> str:
    items = list(d.items())[:limit]
    top = max((v for _, v in items), default=1) or 1
    rows = ""
    for k, v in items:
        pct = int(100 * v / top)
        rows += (f'<div class="bar"><span class="bk">{k}</span>'
                 f'<span class="bt"><i style="width:{pct}%"></i></span>'
                 f'<span class="bv">{_n(v)}</span></div>')
    return rows or '<div class="muted">no data</div>'


def render(d: dict) -> str:
    cards = ""
    for p in d["projects"]:
        py, gh = p["pypi"], p["github"]
        refs = "".join(f'<li>{(r or "direct")} · <b>{_n(c)}</b></li>' for r, c in gh["referrers"]) \
            or '<li class="muted">no referrers in the last 14 days</li>'
        cards += f"""
        <section class="card">
          <h2>{p['label']} <span class="v">v{py['version'] or '?'}</span></h2>
          <div class="hero"><div class="big">{_n(py['total'])}</div>
            <div class="sub">lifetime PyPI downloads · across {py['versions']} releases</div></div>
          <div class="grid3">
            <div class="stat"><b>{_n(py['day'])}</b><span>last day</span></div>
            <div class="stat"><b>{_n(py['week'])}</b><span>last week</span></div>
            <div class="stat"><b>{_n(py['month'])}</b><span>last month</span></div>
          </div>
          <div class="cols">
            <div><h3>By OS (PyPI client)</h3>{_bars(py['systems'])}</div>
            <div><h3>By Python</h3>{_bars(py['python'])}</div>
          </div>
          <h3>GitHub <a href="https://github.com/{p['repo']}" target="_blank">{p['repo']}</a></h3>
          <div class="grid4">
            <div class="stat"><b>{_n(gh['stars'])}</b><span>★ stars</span></div>
            <div class="stat"><b>{_n(gh['forks'])}</b><span>forks</span></div>
            <div class="stat"><b>{_n(gh['clones'])}</b><span>clones · {_n(gh['clones_uniq'])}u</span></div>
            <div class="stat"><b>{_n(gh['views'])}</b><span>views · {_n(gh['views_uniq'])}u</span></div>
          </div>
          <h3>Where (repo traffic referrers, 14d)</h3><ul class="refs">{refs}</ul>
        </section>"""
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="refresh" content="60"><title>Verel × AgentVision — live metrics</title>
<style>
:root{{--bg:#0a0a11;--card:#14141f;--line:#262633;--fg:#eceaf7;--mut:#a6a6c4;--acc:#8b7cff;--acc2:#5ad1e6;--good:#46d39a}}
*{{box-sizing:border-box;margin:0;padding:0}}body{{background:var(--bg);color:var(--fg);font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.5}}
.wrap{{max-width:1100px;margin:0 auto;padding:28px 20px}}h1{{font-size:30px;letter-spacing:-1px}}
.ts{{color:var(--mut);font-size:13px;margin-top:4px}}
.cards{{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:22px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:22px}}
.card h2{{font-size:21px}}.v{{color:var(--acc2);font-size:13px;font-weight:600}}
.hero{{margin:14px 0}}.big{{font-size:46px;font-weight:850;background:linear-gradient(90deg,#cfc8ff,#8b7cff);-webkit-background-clip:text;background-clip:text;color:transparent}}
.sub{{color:var(--mut);font-size:13px}}
.grid3,.grid4{{display:grid;gap:10px;margin:12px 0}}.grid3{{grid-template-columns:repeat(3,1fr)}}.grid4{{grid-template-columns:repeat(4,1fr)}}
.stat{{background:#0e0e18;border:1px solid var(--line);border-radius:10px;padding:10px;text-align:center}}
.stat b{{font-size:19px}}.stat span{{display:block;color:var(--mut);font-size:11px}}
.cols{{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin:8px 0 4px}}h3{{font-size:13px;color:var(--mut);margin:14px 0 8px;text-transform:uppercase;letter-spacing:.06em}}
h3 a{{color:var(--acc2);text-transform:none;letter-spacing:0}}
.bar{{display:flex;align-items:center;gap:8px;margin:5px 0;font-size:13px}}.bk{{width:62px;color:var(--mut)}}.bt{{flex:1;background:#0e0e18;border-radius:6px;height:9px;overflow:hidden}}.bt i{{display:block;height:100%;background:linear-gradient(90deg,var(--acc),var(--acc2))}}.bv{{width:60px;text-align:right}}
.refs{{list-style:none;font-size:14px}}.refs li{{padding:4px 0;border-bottom:1px solid var(--line)}}
.muted{{color:var(--mut);font-size:13px}}
@media(max-width:820px){{.cards{{grid-template-columns:1fr}}}}
</style></head><body><div class="wrap">
<h1>Verel × AgentVision — live adoption</h1>
<div class="ts">updated {d['ts']} · auto-refresh 60s · cache {REFRESH}s · <a href="/api/metrics" style="color:var(--acc2)">JSON</a></div>
<div class="cards">{cards}</div>
<p class="ts" style="margin-top:18px">PyPI downloads via pepy.tech + pypistats · GitHub via the traffic API.
Country-level PyPI geography needs the BigQuery <code>pypi.file_downloads</code> dataset (not a free API).</p>
</div></body></html>"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_a):  # quiet
        pass

    def do_GET(self):  # noqa: N802
        d = cached()
        if self.path.startswith("/api/metrics"):
            body = json.dumps(d, indent=2).encode()
            ctype = "application/json"
        else:
            body = render(d).encode()
            ctype = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _lan_ip() -> str:
    try:
        out = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5).stdout
        for tok in out.split():
            if tok.count(".") == 3 and not tok.startswith(("127.", "172.")):
                return tok
    except Exception:  # noqa: BLE001
        pass
    return "0.0.0.0"


def main() -> None:
    print("Fetching first snapshot (PyPI + GitHub)…")
    cached()  # warm the cache so the first page load is instant
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"\n  Live metrics dashboard:  http://{_lan_ip()}:{PORT}")
    print(f"  (also http://localhost:{PORT})  ·  JSON at /api/metrics  ·  Ctrl-C to stop\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()
