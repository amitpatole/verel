#!/usr/bin/env python3
"""Generate a self-contained 'Adoption' mkdocs page (downloads trend + country map) for the
GitHub Pages docs of either verel or agent-vision.

Snapshot data: the country map from tools/country_cache.json (BigQuery, written daily by
pypi_country.py); the daily trend from pypistats /overall (live, no mirrors). The page embeds the
data + the jsVectorMap / Chart.js CDN libs so it renders client-side on the static Pages site.

Usage:  python tools/build_adoption.py <output.md>
e.g.    python tools/build_adoption.py docs/adoption.md
        python tools/build_adoption.py ~/Eyes_For_AI_Agents/docs/adoption.md
"""

# ruff: noqa: E501 — the embedded HTML/JS adoption template has intentionally long lines
from __future__ import annotations

import json
import sys
import time
import urllib.request
from pathlib import Path

CACHE = Path(__file__).resolve().parent / "country_cache.json"
PKGS = ("verel", "agentvision")
LABELS = {"verel": "Verel", "agentvision": "AgentVision"}


def _get(url: str) -> dict:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "verel-adoption"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except Exception:  # noqa: BLE001
        return {}


def trend() -> dict | None:
    series = {}
    for pkg in PKGS:
        raw = _get(f"https://pypistats.org/api/packages/{pkg}/overall?mirrors=false").get("data", [])
        agg: dict[str, int] = {}
        for row in raw:
            agg[row["date"]] = agg.get(row["date"], 0) + row["downloads"]
        series[pkg] = agg
        time.sleep(1.5)  # pypistats rate-limit courtesy
    dates = sorted({d for s in series.values() for d in s})
    if len(dates) < 2:
        return None
    return {"labels": [d[5:] for d in dates],
            "datasets": {p: [series[p].get(d, 0) for d in dates] for p in PKGS},
            "labelmap": LABELS}


def countries() -> dict | None:
    try:
        cc = json.loads(CACHE.read_text())
    except Exception:  # noqa: BLE001
        return None
    projects, totals = {}, {}
    for pkg, lst in cc.get("countries", {}).items():
        v, tot = {}, 0
        for c, n in lst:
            if c == "??":
                continue
            v[c] = n
            v[c.lower()] = n
            tot += n
        projects[pkg] = v
        totals[pkg] = tot
    return {"projects": projects, "labels": LABELS, "totals": totals,
            "window": cc.get("window_days"), "generated": cc.get("generated", "")[:10]}


_HTML = """
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/css/jsvectormap.min.css">
<style>
.adopt{{--l:#262633;--m:#a6a6c4;--ac:#8b7cff;--ac2:#5ad1e6}}
.adopt .box{{background:#0b0b12;border:1px solid var(--l);border-radius:14px;padding:16px;margin:14px 0}}
.adopt h3{{margin:0 0 8px;font-size:16px}}
.adopt .sub{{color:var(--m);font-size:13px;margin:-2px 0 10px}}
.adopt #aTrend{{height:300px}}
.adopt #aMap{{height:460px}}
.adopt .tabs{{display:flex;gap:8px;justify-content:center;margin-bottom:10px}}
.adopt .tab{{background:#15151f;border:1px solid var(--l);color:var(--m);border-radius:9px;padding:6px 16px;font-weight:600;font-size:13px;cursor:pointer}}
.adopt .tab.on{{border-color:var(--ac);color:#fff}}
.adopt .jvm-tooltip{{background:#14141f!important;border:1px solid var(--l)!important;color:#eceaf7!important;border-radius:8px!important;padding:6px 10px!important}}
</style>
<div class="adopt">
  <div class="box"><h3>📈 Downloads over time</h3><div class="sub">Daily PyPI downloads (no mirrors){trendnote}</div>
    <div id="aTrend"></div></div>
  <div class="box"><h3>🌍 Where it's installed</h3><div class="sub">{mapnote}</div>
    <div class="tabs">{tabs}</div><div id="aMap"></div></div>
</div>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/js/jsvectormap.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/maps/world.js"></script>
<script>window.ADOPT={data};</script>
<script>
(function(){{
  var D=window.ADOPT; var col={{verel:'#8b7cff',agentvision:'#5ad1e6'}};
  if(D.trend && window.Chart){{
    var T=D.trend, ds=Object.keys(T.datasets).map(function(p){{return {{label:T.labelmap[p]||p,data:T.datasets[p],
      borderColor:col[p]||'#8b7cff',backgroundColor:(col[p]||'#8b7cff')+'22',fill:true,tension:.3,pointRadius:2,borderWidth:2}};}});
    var c=document.createElement('canvas'); document.getElementById('aTrend').appendChild(c);
    new Chart(c,{{type:'line',data:{{labels:T.labels,datasets:ds}},options:{{responsive:true,maintainAspectRatio:false,animation:false,
      interaction:{{mode:'index',intersect:false}},plugins:{{legend:{{labels:{{color:'#cfc8ff',usePointStyle:true}}}}}},
      scales:{{x:{{ticks:{{color:'#8a8aa6'}},grid:{{color:'#1b1b28'}}}},y:{{beginAtZero:true,ticks:{{color:'#8a8aa6'}},grid:{{color:'#1b1b28'}}}}}}}}}});
  }}
  if(D.countries && window.jsVectorMap){{
    var C=D.countries, cur=Object.keys(C.projects)[0], map=null;
    function vals(p){{return C.projects[p]||{{}};}}
    function build(p){{cur=p; var h=document.getElementById('aMap'); if(map){{try{{map.destroy();}}catch(e){{}}}} h.innerHTML='';
      map=new jsVectorMap({{selector:'#aMap',map:'world',zoomButtons:true,backgroundColor:'transparent',
        regionStyle:{{initial:{{fill:'#1c1c2b',stroke:'#0a0a11',strokeWidth:0.4}},hover:{{fill:'#5ad1e6'}}}},
        series:{{regions:[{{attribute:'fill',scale:['#241f45','#6a5acd','#8b7cff','#5ad1e6'],normalizeFunction:'polynomial',values:vals(p)}}]}},
        onRegionTooltipShow:function(e,tt,code){{var v=vals(cur)[code]||vals(cur)[code&&code.toUpperCase()]||0;
          tt.text('<b>'+tt.text()+'</b><br>'+v.toLocaleString()+' downloads',true);}}}});
      document.querySelectorAll('.adopt .tab').forEach(function(b){{b.classList.toggle('on',b.dataset.p===cur);}});}}
    document.querySelectorAll('.adopt .tab').forEach(function(b){{b.addEventListener('click',function(){{build(b.dataset.p);}});}});
    build(cur);
  }}
}})();
</script>
"""


def main() -> None:
    out = Path(sys.argv[1]).expanduser() if len(sys.argv) > 1 else Path("docs/adoption.md")
    tr = trend()
    co = countries()
    data = {"trend": tr, "countries": (co and {"projects": co["projects"], "labels": co["labels"]})}
    tabs = ("".join(f'<button class="tab{" on" if i == 0 else ""}" data-p="{p}">{LABELS[p]}</button>'
                    for i, p in enumerate(co["projects"])) if co else "")
    mapnote = (f"Real PyPI downloads by country &mdash; last {co['window']} days via BigQuery "
               f"(snapshot {co['generated']}). Hover a country for its count.") if co else "no data yet"
    trendnote = f" &middot; verel ~{(tr['datasets']['verel'] and sum(tr['datasets']['verel'])) or 0:,} in-window" if tr else ""
    body = _HTML.format(data=json.dumps(data), tabs=tabs, mapnote=mapnote, trendnote=trendnote)
    page = ("# Adoption\n\n"
            "Verel and AgentVision ship and version independently, but grow together. Live-ish snapshot of "
            "real PyPI download adoption (the trend is from pypistats; the country map from the BigQuery "
            "public dataset).\n" + body + "\n")
    out.write_text(page)
    print(f"wrote {out}" + (f" · trend {len(tr['labels'])} days" if tr else " · no trend")
          + (f" · {sum(len(v) // 2 for v in co['projects'].values())} country points" if co else " · no map"))


if __name__ == "__main__":
    main()
