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
<style>
.adopt .box{{background:var(--md-default-bg-color);border:1px solid var(--md-default-fg-color--lightest);border-radius:12px;padding:18px 20px;margin:16px 0}}
.adopt h3{{margin:0 0 2px;font-size:16px}}
.adopt .sub{{color:var(--md-default-fg-color--light);font-size:13px;margin:0 0 12px}}
.adopt .tabs{{display:flex;gap:8px;margin:0 0 12px}}
.adopt .tab{{background:transparent;border:1px solid var(--md-default-fg-color--lighter);color:var(--md-default-fg-color--light);border-radius:8px;padding:5px 14px;font-weight:600;font-size:13px;cursor:pointer}}
.adopt .tab.on{{border-color:#7a72b5;color:#564f8c;background:rgba(122,114,181,.08)}}
.adopt .spark{{width:100%;height:118px;display:block}}
.adopt table.ctab{{width:100%;border-collapse:collapse;font-size:14px}}
.adopt .ctab td{{padding:6px 6px;border-bottom:1px solid var(--md-default-fg-color--lightest);vertical-align:middle}}
.adopt .ctab tr:last-child td{{border-bottom:none}}
.adopt .cflag{{width:24px;font-size:17px;line-height:1}}
.adopt .cname{{white-space:nowrap;max-width:180px;overflow:hidden;text-overflow:ellipsis}}
.adopt .cbar{{width:50%}}
.adopt .cbar span{{display:block;height:9px;border-radius:5px;background:linear-gradient(90deg,#7a72b5,#564f8c);min-width:3px}}
.adopt .cnum{{text-align:right;font-family:var(--md-code-font,monospace);color:var(--md-default-fg-color--light);width:62px;white-space:nowrap}}
.adopt .more{{color:var(--md-default-fg-color--light);font-size:12.5px;margin:10px 2px 0}}
</style>
<div class="adopt">
  <div class="box"><h3>📈 Downloads over time</h3><div class="sub">Daily PyPI downloads (no mirrors){trendnote}</div>
    <div id="aTrend"></div></div>
  <div class="box"><h3>🌍 Where it's installed</h3><div class="sub">{mapnote}</div>
    <div class="tabs">{tabs}</div><div id="aMap"></div></div>
</div>
<script>window.ADOPT={data};</script>
<script>
(function(){{
  var D=window.ADOPT; if(!D) return;
  var rn=null; try{{rn=new Intl.DisplayNames(['en'],{{type:'region'}});}}catch(e){{}}
  function nm(cc){{try{{return (rn&&rn.of(cc))||cc;}}catch(e){{return cc;}}}}
  function flag(cc){{return cc.replace(/./g,function(c){{return String.fromCodePoint(127397+c.charCodeAt(0));}});}}
  if(D.trend){{
    var T=D.trend, el=document.getElementById('aTrend'), W=680,H=118,P=10;
    var S=[['verel','#7a72b5'],['agentvision','#3a8a99']], all=[1];
    S.forEach(function(s){{(T.datasets[s[0]]||[]).forEach(function(v){{all.push(v);}});}});
    var mx=Math.max.apply(null,all);
    function pth(a){{var n=a.length; return a.map(function(v,i){{var x=P+i*(W-2*P)/Math.max(1,n-1),y=H-P-(v/mx)*(H-2*P); return (i?'L':'M')+x.toFixed(1)+' '+y.toFixed(1);}}).join(' ');}}
    var svg='<svg class="spark" viewBox="0 0 '+W+' '+H+'" preserveAspectRatio="none">';
    S.forEach(function(s){{var d=T.datasets[s[0]]||[]; if(d.length) svg+='<path d="'+pth(d)+'" fill="none" stroke="'+s[1]+'" stroke-width="2" stroke-linejoin="round"/>';}});
    svg+='</svg>';
    var leg=S.map(function(s){{return '<span style="color:'+s[1]+'">\\u25cf</span> '+((T.labelmap||{{}})[s[0]]||s[0]);}}).join(' &nbsp; ');
    el.innerHTML=svg+'<div class="sub" style="margin:6px 0 0">'+leg+' &nbsp;\\u00b7&nbsp; '+T.labels[0]+' \\u2192 '+T.labels[T.labels.length-1]+'</div>';
  }}
  if(D.countries){{
    var C=D.countries, cur=Object.keys(C.projects)[0];
    function rows(p){{var raw=C.projects[p]||{{}},seen={{}},out=[];Object.keys(raw).forEach(function(k){{var u=k.toUpperCase();if(/^[A-Z]{{2}}$/.test(u)&&!seen[u]){{seen[u]=1;out.push([u,raw[k]]);}}}});return out.sort(function(a,b){{return b[1]-a[1];}});}}
    function build(p){{cur=p;var r=rows(p),mx=r.length?r[0][1]:1,top=r.slice(0,16),rest=r.slice(16),h=document.getElementById('aMap');
      var html='<table class="ctab"><tbody>';
      top.forEach(function(x){{var pct=Math.max(2,Math.round(x[1]/mx*100));
        html+='<tr><td class="cflag">'+flag(x[0])+'</td><td class="cname">'+nm(x[0])+'</td><td class="cbar"><span style="width:'+pct+'%"></span></td><td class="cnum">'+x[1].toLocaleString()+'</td></tr>';}});
      h.innerHTML=html+'</tbody></table>';
      if(rest.length){{var s=rest.reduce(function(a,x){{return a+x[1];}},0);h.innerHTML+='<p class="more">+ '+rest.length+' more countries \\u00b7 '+s.toLocaleString()+' downloads</p>';}}
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
    mapnote = (f"Top countries by PyPI downloads &mdash; last {co['window']} days via BigQuery "
               f"(snapshot {co['generated']})") if co else "no data yet"
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
