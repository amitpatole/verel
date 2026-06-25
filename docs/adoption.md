# Adoption

Verel and AgentVision ship and version independently, but grow together. Live-ish snapshot of real PyPI download adoption (the trend is from pypistats; the country map from the BigQuery public dataset).

<style>
.adopt .box{background:var(--md-default-bg-color);border:1px solid var(--md-default-fg-color--lightest);border-radius:12px;padding:18px 20px;margin:16px 0}
.adopt h3{margin:0 0 2px;font-size:16px}
.adopt .sub{color:var(--md-default-fg-color--light);font-size:13px;margin:0 0 12px}
.adopt .tabs{display:flex;gap:8px;margin:0 0 12px}
.adopt .tab{background:transparent;border:1px solid var(--md-default-fg-color--lighter);color:var(--md-default-fg-color--light);border-radius:8px;padding:5px 14px;font-weight:600;font-size:13px;cursor:pointer}
.adopt .tab.on{border-color:#7a72b5;color:#564f8c;background:rgba(122,114,181,.08)}
.adopt .spark{width:100%;height:118px;display:block}
.adopt table.ctab{width:100%;border-collapse:collapse;font-size:14px}
.adopt .ctab td{padding:6px 6px;border-bottom:1px solid var(--md-default-fg-color--lightest);vertical-align:middle}
.adopt .ctab tr:last-child td{border-bottom:none}
.adopt .cflag{width:24px;font-size:17px;line-height:1}
.adopt .cname{white-space:nowrap;max-width:180px;overflow:hidden;text-overflow:ellipsis}
.adopt .cbar{width:50%}
.adopt .cbar span{display:block;height:9px;border-radius:5px;background:linear-gradient(90deg,#7a72b5,#564f8c);min-width:3px}
.adopt .cnum{text-align:right;font-family:var(--md-code-font,monospace);color:var(--md-default-fg-color--light);width:62px;white-space:nowrap}
.adopt .more{color:var(--md-default-fg-color--light);font-size:12.5px;margin:10px 2px 0}
</style>
<div class="adopt">
  <div class="box"><h3>📈 Downloads over time</h3><div class="sub">Daily PyPI downloads (no mirrors) &middot; verel ~5,184 in-window</div>
    <div id="aTrend"></div></div>
  <div class="box"><h3>🌍 Where it's installed</h3><div class="sub">Top countries by PyPI downloads &mdash; last 30 days via BigQuery (snapshot 2026-06-25)</div>
    <div class="tabs"><button class="tab on" data-p="verel">Verel</button><button class="tab" data-p="agentvision">AgentVision</button></div><div id="aMap"></div></div>
</div>
<script>window.ADOPT={"trend": {"labels": ["06-18", "06-19", "06-20", "06-21", "06-22", "06-23", "06-24"], "datasets": {"verel": [222, 1347, 112, 744, 682, 1036, 1041], "agentvision": [228, 716, 89, 48, 567, 341, 41]}, "labelmap": {"verel": "Verel", "agentvision": "AgentVision"}}, "countries": {"projects": {"verel": {"US": 9066, "us": 9066, "DE": 1153, "de": 1153, "HK": 701, "hk": 701, "JP": 678, "jp": 678, "CN": 610, "cn": 610, "GB": 439, "gb": 439, "FR": 436, "fr": 436, "NO": 392, "no": 392, "IN": 364, "in": 364, "SG": 337, "sg": 337, "FI": 279, "fi": 279, "NL": 167, "nl": 167, "DK": 163, "dk": 163, "KR": 159, "kr": 159, "RU": 148, "ru": 148, "IT": 122, "it": 122, "SE": 118, "se": 118, "IE": 103, "ie": 103, "CA": 65, "ca": 65, "CL": 41, "cl": 41, "AU": 41, "au": 41, "LT": 35, "lt": 35, "NP": 19, "np": 19, "MD": 18, "md": 18, "TH": 16, "th": 16, "AT": 16, "at": 16, "BE": 16, "be": 16, "PL": 15, "pl": 15, "TW": 11, "tw": 11, "VG": 6, "vg": 6, "QA": 4, "qa": 4, "SA": 4, "sa": 4, "EE": 4, "ee": 4, "ZA": 3, "za": 3, "PT": 3, "pt": 3, "IL": 3, "il": 3, "VN": 2, "vn": 2, "PK": 2, "pk": 2, "IM": 2, "im": 2, "AD": 2, "ad": 2, "MO": 2, "mo": 2, "BG": 2, "bg": 2, "BR": 2, "br": 2, "ES": 2, "es": 2, "GR": 2, "gr": 2, "KH": 2, "kh": 2, "GE": 2, "ge": 2, "TR": 2, "tr": 2, "LK": 2, "lk": 2, "PA": 2, "pa": 2, "NZ": 2, "nz": 2, "UA": 2, "ua": 2, "RO": 2, "ro": 2, "IS": 1, "is": 1, "AM": 1, "am": 1, "CY": 1, "cy": 1, "GL": 1, "gl": 1, "MT": 1, "mt": 1, "LV": 1, "lv": 1, "RS": 1, "rs": 1, "EG": 1, "eg": 1, "AL": 1, "al": 1}, "agentvision": {"US": 3355, "us": 3355, "DE": 873, "de": 873, "CN": 245, "cn": 245, "JP": 239, "jp": 239, "FR": 209, "fr": 209, "HK": 206, "hk": 206, "SG": 160, "sg": 160, "GB": 135, "gb": 135, "NO": 106, "no": 106, "NL": 101, "nl": 101, "FI": 81, "fi": 81, "KR": 68, "kr": 68, "DK": 64, "dk": 64, "RU": 49, "ru": 49, "SE": 43, "se": 43, "IE": 38, "ie": 38, "CA": 27, "ca": 27, "IN": 16, "in": 16, "CL": 16, "cl": 16, "AU": 15, "au": 15, "BE": 12, "be": 12, "NP": 11, "np": 11, "LT": 8, "lt": 8, "TW": 7, "tw": 7, "CH": 5, "ch": 5, "MY": 4, "my": 4, "AT": 3, "at": 3, "EE": 3, "ee": 3, "MD": 3, "md": 3, "VN": 2, "vn": 2, "RO": 2, "ro": 2, "VG": 2, "vg": 2, "TH": 2, "th": 2, "LV": 1, "lv": 1, "TR": 1, "tr": 1, "BG": 1, "bg": 1, "RS": 1, "rs": 1, "IT": 1, "it": 1}}, "labels": {"verel": "Verel", "agentvision": "AgentVision"}}};</script>
<script>
(function(){
  var D=window.ADOPT; if(!D) return;
  var rn=null; try{rn=new Intl.DisplayNames(['en'],{type:'region'});}catch(e){}
  function nm(cc){try{return (rn&&rn.of(cc))||cc;}catch(e){return cc;}}
  function flag(cc){return cc.replace(/./g,function(c){return String.fromCodePoint(127397+c.charCodeAt(0));});}
  if(D.trend){
    var T=D.trend, el=document.getElementById('aTrend'), W=680,H=118,P=10;
    var S=[['verel','#7a72b5'],['agentvision','#3a8a99']], all=[1];
    S.forEach(function(s){(T.datasets[s[0]]||[]).forEach(function(v){all.push(v);});});
    var mx=Math.max.apply(null,all);
    function pth(a){var n=a.length; return a.map(function(v,i){var x=P+i*(W-2*P)/Math.max(1,n-1),y=H-P-(v/mx)*(H-2*P); return (i?'L':'M')+x.toFixed(1)+' '+y.toFixed(1);}).join(' ');}
    var svg='<svg class="spark" viewBox="0 0 '+W+' '+H+'" preserveAspectRatio="none">';
    S.forEach(function(s){var d=T.datasets[s[0]]||[]; if(d.length) svg+='<path d="'+pth(d)+'" fill="none" stroke="'+s[1]+'" stroke-width="2" stroke-linejoin="round"/>';});
    svg+='</svg>';
    var leg=S.map(function(s){return '<span style="color:'+s[1]+'">\u25cf</span> '+((T.labelmap||{})[s[0]]||s[0]);}).join(' &nbsp; ');
    el.innerHTML=svg+'<div class="sub" style="margin:6px 0 0">'+leg+' &nbsp;\u00b7&nbsp; '+T.labels[0]+' \u2192 '+T.labels[T.labels.length-1]+'</div>';
  }
  if(D.countries){
    var C=D.countries, cur=Object.keys(C.projects)[0];
    function rows(p){var raw=C.projects[p]||{},seen={},out=[];Object.keys(raw).forEach(function(k){var u=k.toUpperCase();if(/^[A-Z]{2}$/.test(u)&&!seen[u]){seen[u]=1;out.push([u,raw[k]]);}});return out.sort(function(a,b){return b[1]-a[1];});}
    function build(p){cur=p;var r=rows(p),mx=r.length?r[0][1]:1,top=r.slice(0,16),rest=r.slice(16),h=document.getElementById('aMap');
      var html='<table class="ctab"><tbody>';
      top.forEach(function(x){var pct=Math.max(2,Math.round(x[1]/mx*100));
        html+='<tr><td class="cflag">'+flag(x[0])+'</td><td class="cname">'+nm(x[0])+'</td><td class="cbar"><span style="width:'+pct+'%"></span></td><td class="cnum">'+x[1].toLocaleString()+'</td></tr>';});
      h.innerHTML=html+'</tbody></table>';
      if(rest.length){var s=rest.reduce(function(a,x){return a+x[1];},0);h.innerHTML+='<p class="more">+ '+rest.length+' more countries \u00b7 '+s.toLocaleString()+' downloads</p>';}
      document.querySelectorAll('.adopt .tab').forEach(function(b){b.classList.toggle('on',b.dataset.p===cur);});}
    document.querySelectorAll('.adopt .tab').forEach(function(b){b.addEventListener('click',function(){build(b.dataset.p);});});
    build(cur);
  }
})();
</script>

