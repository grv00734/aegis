/** The single-page Aegis control panel (iOS Control Center style), served by src/gui.ts. */
export function dashboardHtml(): string {
  return PAGE;
}

const SHIELD =
  '<svg viewBox="0 0 24 24" width="26" height="26" aria-hidden="true"><path d="M12 2l8 3v6c0 5-3.4 9-8 11-4.6-2-8-6-8-11V5l8-3z" fill="currentColor"/></svg>';

const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"/>
<title>Aegis</title>
<style>
  :root{
    --green:#34c759; --blue:#0a84ff; --red:#ff453a; --amber:#ff9f0a; --purple:#bf5af2;
    --txt:#f5f5f7; --sub:rgba(235,235,245,.6); --glass:rgba(40,40,52,.55);
    --glass2:rgba(70,70,84,.45); --stroke:rgba(255,255,255,.14);
    /* glass edge: hairline border + top highlight + soft depth */
    --edge:inset 0 1px 0 rgba(255,255,255,.18), inset 0 0 0 1px rgba(255,255,255,.05);
    --depth:0 12px 38px rgba(0,0,0,.36);
    --ring:0 0 0 3px rgba(10,132,255,.28);
  }
  *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
  html,body{height:100%}
  body{margin:0;color:var(--txt);
    font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    font-size:15px;line-height:1.4;
    background:
      radial-gradient(circle at 12% 18%, #7b2ff7 0%, transparent 42%),
      radial-gradient(circle at 88% 12%, #0a84ff 0%, transparent 46%),
      radial-gradient(circle at 82% 88%, #16c2a3 0%, transparent 42%),
      radial-gradient(circle at 18% 92%, #ff2d75 0%, transparent 44%),
      #0a0a12;
    background-attachment:fixed;}
  .wrap{max-width:1000px;margin:0 auto;padding:22px 16px 48px}
  .titlebar{display:flex;align-items:center;justify-content:space-between;margin:6px 4px 18px;gap:12px;flex-wrap:wrap}
  .titlebar h1{font-size:22px;font-weight:700;letter-spacing:.3px;margin:0}
  .titlebar h1 small{display:block;font-size:12px;font-weight:500;color:var(--sub)}
  .pills{display:flex;gap:7px;flex-wrap:wrap}
  .pill{font-size:11px;color:var(--sub);background:var(--glass);border:1px solid var(--stroke);
    border-radius:999px;padding:4px 9px;backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px)}

  .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:14px}
  .stat{background:var(--glass);border:1px solid var(--stroke);border-radius:16px;padding:14px 16px;
    backdrop-filter:blur(22px);-webkit-backdrop-filter:blur(22px);box-shadow:var(--edge)}
  .stat .n{font-size:30px;font-weight:800;line-height:1}
  .stat .l{font-size:11px;color:var(--sub);text-transform:uppercase;letter-spacing:.5px;margin-top:6px}
  .stat.b .n{color:var(--blue)} .stat.r .n{color:var(--red)} .stat.g .n{color:var(--green)}

  .grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
  .module{background:var(--glass);border:1px solid var(--stroke);border-radius:22px;padding:16px;
    backdrop-filter:blur(26px) saturate(150%);-webkit-backdrop-filter:blur(26px) saturate(150%);
    box-shadow:var(--depth), var(--edge);animation:rise .4s ease both;transition:border-color .2s}
  .module:hover{border-color:rgba(255,255,255,.22)}
  @keyframes rise{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
  .module h2{margin:0 0 12px;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.7px;color:var(--sub);
    display:flex;justify-content:space-between;align-items:center}
  .span2{grid-column:1 / -1}
  .linkbtn{background:none;border:0;color:var(--blue);font-size:12px;cursor:pointer;padding:0}

  .conn{display:flex;gap:14px}
  .conn .item{display:flex;align-items:center;gap:12px;flex:1;min-width:0}
  .round{width:54px;height:54px;border-radius:50%;border:0;cursor:pointer;flex:0 0 auto;
    display:flex;align-items:center;justify-content:center;color:var(--sub);background:var(--glass2);transition:all .18s ease}
  .round.on{color:#fff;background:var(--green);box-shadow:0 0 0 4px rgba(52,199,89,.25),0 6px 18px rgba(52,199,89,.4)}
  .round.blue.on{background:var(--blue);box-shadow:0 0 0 4px rgba(10,132,255,.25),0 6px 18px rgba(10,132,255,.4)}
  .conn .txt{min-width:0}
  .conn .txt b{font-weight:600;font-size:15px}
  .conn .txt small{display:block;color:var(--sub);font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

  .segmented{display:flex;background:rgba(0,0,0,.28);border-radius:12px;padding:3px;gap:3px;box-shadow:inset 0 1px 2px rgba(0,0,0,.3)}
  .segmented button.on{box-shadow:var(--edge)}
  .segmented button{flex:1;border:0;background:transparent;color:var(--txt);font-size:13px;font-weight:600;padding:8px 4px;border-radius:9px;cursor:pointer;transition:.15s}
  .segmented button.on{background:rgba(255,255,255,.22)}

  .srow{display:flex;align-items:center;justify-content:space-between;padding:9px 2px;border-bottom:1px solid rgba(255,255,255,.08)}
  .srow:last-child{border-bottom:0}
  .switch{position:relative;width:50px;height:30px;flex:0 0 auto}
  .switch input{opacity:0;width:0;height:0;position:absolute}
  .switch .sl{position:absolute;inset:0;background:rgba(120,120,128,.4);border-radius:999px;transition:.2s}
  .switch .sl:before{content:"";position:absolute;width:26px;height:26px;left:2px;top:2px;background:#fff;border-radius:50%;transition:.2s;box-shadow:0 2px 5px rgba(0,0,0,.35)}
  .switch input:checked + .sl{background:var(--green)}
  .switch input:checked + .sl:before{transform:translateX(20px)}

  textarea{width:100%;background:rgba(0,0,0,.28);color:var(--txt);border:1px solid var(--stroke);border-radius:14px;
    padding:11px 13px;font-size:13px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;resize:vertical;transition:border-color .15s, box-shadow .15s}
  textarea:focus,select:focus{outline:none;border-color:var(--blue);box-shadow:var(--ring)}
  .btn{background:var(--blue);color:#fff;border:0;border-radius:12px;padding:9px 16px;font-size:14px;font-weight:600;cursor:pointer}
  .btn.sub{background:rgba(255,255,255,.16)}
  .btn.tiny{padding:5px 11px;font-size:12px;border-radius:9px}
  .hint{color:var(--sub);font-size:12px;margin:2px 2px 12px}
  .samples{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}

  .panes{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px}
  .pane{background:rgba(0,0,0,.3);border:1px solid var(--stroke);border-radius:14px;padding:12px;box-shadow:inset 0 1px 0 rgba(255,255,255,.06);
    white-space:pre-wrap;word-break:break-word;font-size:12.5px;max-height:210px;overflow:auto;
    font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  .pane .ttl{font-family:inherit;color:var(--sub);font-size:11px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px;display:block}
  mark.hl{padding:1px 2px;border-radius:4px;color:#fff}
  mark.hl.critical{background:rgba(255,69,58,.55)} mark.hl.high{background:rgba(255,159,10,.55)}
  mark.hl.medium{background:rgba(10,132,255,.5)} mark.hl.low{background:rgba(120,120,128,.5)}
  .ph{color:var(--green)}
  .chips{display:flex;flex-wrap:wrap;gap:7px;margin-top:12px;align-items:center}
  .chip{font-size:11px;border:1px solid var(--stroke);border-radius:999px;padding:4px 10px;color:var(--sub)}
  .chip b{color:#fff}

  .bars{display:flex;flex-direction:column;gap:10px}
  .bar{display:grid;grid-template-columns:120px 1fr 40px;align-items:center;gap:10px;font-size:12.5px}
  .bar .track{height:10px;background:rgba(0,0,0,.3);border-radius:999px;overflow:hidden}
  .bar .fill{height:100%;border-radius:999px;background:var(--blue);transition:width .4s}
  .bar.pci .fill{background:var(--amber)} .bar.hipaa .fill{background:var(--purple)}
  .bar.gdpr .fill{background:var(--blue)} .bar.soc2 .fill{background:var(--red)}
  .bar .v{text-align:right;color:var(--sub)}

  .activity{list-style:none;margin:0;padding:0;max-height:280px;overflow:auto}
  .activity li{display:flex;gap:9px;align-items:center;padding:9px 4px;border-bottom:1px solid rgba(255,255,255,.07);font-size:12.5px;animation:rise .25s ease both}
  .tag{font-size:10px;font-weight:800;padding:2px 8px;border-radius:999px;flex:0 0 auto}
  .tag.REDACT{background:rgba(10,132,255,.22);color:#7fbcff}
  .tag.BLOCK{background:rgba(255,69,58,.22);color:#ff8a80}
  .tag.WARN{background:rgba(255,159,10,.22);color:#ffcf70}
  .tag.CLEAN{background:rgba(52,199,89,.22);color:#7ee29a}
  .grow{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:var(--sub)}
  .empty{color:var(--sub);font-style:italic;padding:6px 2px}
  .saved{color:var(--green);font-size:12px;margin-left:10px}
  .polgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px}
  .polrow{display:flex;align-items:center;justify-content:space-between;background:rgba(0,0,0,.22);
    border:1px solid var(--stroke);border-radius:12px;padding:8px 12px;font-size:13px;box-shadow:var(--edge)}
  .polrow select{background:rgba(0,0,0,.32);color:var(--txt);border:1px solid var(--stroke);
    border-radius:8px;padding:5px 8px;font-size:12px}
  #toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%) translateY(20px);background:rgba(20,20,28,.92);
    border:1px solid var(--stroke);border-radius:12px;padding:10px 18px;font-size:13px;opacity:0;transition:.25s;
    backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);pointer-events:none;z-index:20}
  #toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
  @media(max-width:720px){.grid,.panes{grid-template-columns:1fr}.stats{grid-template-columns:1fr 1fr}}
</style>
</head>
<body>
<div class="wrap">
  <div class="titlebar">
    <h1>Aegis<small>Confidential Data Guard</small></h1>
    <div class="pills" id="pills"></div>
  </div>

  <div class="stats">
    <div class="stat r"><div class="n" id="m_findings">0</div><div class="l">Findings caught</div></div>
    <div class="stat b"><div class="n" id="m_events">0</div><div class="l">Requests guarded</div></div>
    <div class="stat"><div class="n" id="m_blocked">0</div><div class="l">Blocked</div></div>
    <div class="stat g"><div class="n" id="m_topcat">—</div><div class="l">Top category</div></div>
  </div>

  <div class="grid">
    <section class="module">
      <h2>Guard</h2>
      <div class="conn">
        <div class="item">
          <button class="round" id="toggleBase">${SHIELD}</button>
          <div class="txt"><b>Base-URL</b><small id="urlBase">Off</small></div>
        </div>
        <div class="item">
          <button class="round blue" id="toggleSystem">${SHIELD}</button>
          <div class="txt"><b>System</b><small id="urlSystem">Off</small></div>
        </div>
      </div>
    </section>

    <section class="module">
      <h2>Action on detection</h2>
      <div class="segmented" id="segMode">
        <button data-mode="redact">Redact</button>
        <button data-mode="block">Block</button>
        <button data-mode="warn">Warn</button>
      </div>
      <p class="hint" style="margin-top:12px;margin-bottom:6px">Redact swaps secrets for placeholders and restores them in the reply. Block refuses the request.</p>
      <label class="srow"><span>Optimize prompts (reduce tokens)</span><span class="switch"><input type="checkbox" id="optToggle"/><span class="sl"></span></span></label>
    </section>

    <section class="module span2">
      <h2>Live redaction tester</h2>
      <p class="hint">Paste anything an employee might send to an AI. Detection runs locally — nothing leaves this machine.</p>
      <textarea id="input" rows="5" placeholder="Paste a .env, config, code, or notes here..."></textarea>
      <div class="samples">
        <button class="btn sub tiny" data-sample="env">Load .env</button>
        <button class="btn sub tiny" data-sample="code">Load code</button>
        <button class="btn sub tiny" data-sample="pii">Load customer data</button>
      </div>
      <div class="panes">
        <div class="pane" id="detected"><span class="ttl">Detected (highlighted)</span><span class="empty">No findings yet.</span></div>
        <div class="pane" id="redacted"><span class="ttl">Sent to the AI (scrubbed)</span><span class="empty">—</span></div>
      </div>
      <div class="chips" id="chips">
        <span class="chip"><b id="count">0</b> findings</span>
        <span class="chip" id="savedChip" style="display:none"></span>
        <button class="btn sub tiny" id="copyBtn" style="margin-left:auto" disabled>Copy scrubbed</button>
      </div>
    </section>

    <section class="module">
      <h2>Detectors</h2>
      <div id="detectors"></div>
    </section>

    <section class="module">
      <h2>Company dictionary</h2>
      <textarea id="dictionary" rows="4" placeholder="Project Phoenix&#10;acme-internal.com"></textarea>
      <div style="display:flex;align-items:center;margin-top:10px">
        <button class="btn sub" id="btnDict">Apply</button><span class="saved" id="savedMsg"></span>
      </div>
    </section>

    <section class="module span2">
      <h2>Policy &amp; allowlist</h2>
      <p class="hint" style="margin-top:0">Per-category action (strictest wins). Allowlist values are never flagged.</p>
      <div class="polgrid" id="catActions"></div>
      <div class="hint" style="margin:14px 2px 6px">Allowlist — one literal value or /regex/ per line</div>
      <textarea id="allowlist" rows="3" placeholder="AKIAIOSFODNN7EXAMPLE&#10;/@example\\.com$/"></textarea>
      <div style="display:flex;align-items:center;margin-top:10px">
        <button class="btn sub" id="btnAllow">Apply allowlist</button><span class="saved" id="savedAllow"></span>
      </div>
    </section>

    <section class="module span2">
      <h2>Token spend</h2>
      <div id="budget"><div class="empty">Budget control is off (set budget.enabled in config).</div></div>
    </section>

    <section class="module span2">
      <h2>Compliance exposure <button class="linkbtn" id="refreshCompliance">refresh</button></h2>
      <div class="bars" id="compliance"><div class="empty">No exposure recorded yet.</div></div>
    </section>

    <section class="module span2">
      <h2>Activity <button class="linkbtn" id="clearActivity">clear</button></h2>
      <ul class="activity" id="activity"><li class="empty">Waiting for traffic — start a guard and send a request.</li></ul>
    </section>
  </div>
</div>
<div id="toast"></div>

<script>
  var DETECTORS=["secrets","pii","identity","network","dictionary","code","entropy"];
  var CATS=["secret","pii","network","dictionary","code"];
  var SAMPLES={
    env:"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\\nDATABASE_URL=postgres://admin:S3cr3t@db.acme-internal.com:5432/prod\\nANTHROPIC_API_KEY=sk-ant-abcd1234EFGH5678ijklMNOP",
    code:"// CONFIDENTIAL - internal\\nconst key = 'sk-ant-abcd1234EFGH5678ijklMNOP';\\n// ask James Wilson about the com.acme.internal module",
    pii:"Customer James Wilson, james.wilson@example.com, card 4242 4242 4242 4242, DOB: 04/12/1980, 1600 Pennsylvania Avenue"
  };
  function $(id){return document.getElementById(id)}
  function api(p,m,b){return fetch(p,{method:m||"GET",headers:{"content-type":"application/json"},body:b?JSON.stringify(b):undefined}).then(function(r){return r.json()})}
  function esc(s){return String(s).replace(/[&<>]/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;"}[c]})}
  function setConfig(part){return api("/api/config","POST",part).then(renderStatus)}
  var toastT;
  function toast(msg){var t=$("toast");t.textContent=msg;t.classList.add("show");clearTimeout(toastT);toastT=setTimeout(function(){t.classList.remove("show")},1800)}

  var current={};
  function renderStatus(s){
    current=s;
    $("toggleBase").classList.toggle("on",!!s.base);
    $("toggleSystem").classList.toggle("on",!!s.system);
    $("urlBase").textContent=s.base?s.baseUrl.replace("http://",""):"Off";
    $("urlSystem").textContent=s.system?s.systemUrl.replace("http://",""):"Off";
    $("pills").innerHTML=
      '<span class="pill">'+(s.base?"Base-URL on":"Base-URL off")+'</span>'+
      '<span class="pill">'+(s.system?"System on":"System off")+'</span>'+
      '<span class="pill">mode '+esc(s.mode)+'</span>';
    Array.prototype.forEach.call($("segMode").children,function(b){b.classList.toggle("on",b.dataset.mode===s.mode)});
    renderDetectors(s.detectors);
    renderPolicy(s);
    if(document.activeElement!==$("optToggle")) $("optToggle").checked=!!(s.optimize&&s.optimize.enabled);
    renderBudget(s);
    if(document.activeElement!==$("dictionary")) $("dictionary").value=(s.dictionary||[]).join("\\n");
  }
  function pbar(label,pct){return '<div class="bar"><span>'+esc(label)+'</span><span class="track"><span class="fill" style="width:'+pct+'%"></span></span><span class="v">'+pct+'%</span></div>'}
  function renderBudget(s){
    var b=s.budget;
    if(!b){$("budget").innerHTML='<div class="empty">Budget control is off (set budget.enabled in config).</div>';return}
    var lim=b.limits||{}; var h='';
    h+='<div class="hint" style="margin:0 0 8px">window '+b.windowHours+'h · action '+esc(b.action)+' · resets '+esc((b.resetAt||"").replace("T"," ").replace(/\\..*/,""))+'</div>';
    h+='<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:8px">';
    h+='<div class="stat b" style="flex:1"><div class="n">'+b.total.tokens+'</div><div class="l">tokens'+(lim.maxTokens?" / "+lim.maxTokens:"")+'</div></div>';
    h+='<div class="stat g" style="flex:1"><div class="n">$'+b.total.costUsd.toFixed(4)+'</div><div class="l">cost'+(lim.maxCostUsd?" / $"+lim.maxCostUsd:"")+'</div></div>';
    h+='<div class="stat" style="flex:1"><div class="n">'+b.total.requests+'</div><div class="l">requests</div></div>';
    h+='</div>';
    if(lim.maxTokens) h+=pbar("tokens",Math.min(100,Math.round(b.total.tokens/lim.maxTokens*100)));
    if(lim.maxCostUsd) h+=pbar("cost",Math.min(100,Math.round(b.total.costUsd/lim.maxCostUsd*100)));
    if(b.services&&b.services.length){h+='<div class="hint" style="margin-top:10px">by service</div>';
      b.services.forEach(function(x){h+='<div class="bar"><span>'+esc(x.service)+'</span><span class="track"></span><span class="v">'+x.tokens+' tok · $'+x.costUsd.toFixed(4)+'</span></div>'})}
    if(b.users&&b.users.length){h+='<div class="hint" style="margin-top:10px">by employee</div>';
      b.users.forEach(function(x){h+='<div class="bar"><span>'+esc(x.user)+'</span><span class="track"></span><span class="v">'+x.tokens+' tok · $'+x.costUsd.toFixed(4)+' · '+x.requests+' req</span></div>'})}
    $("budget").innerHTML=h;
  }
  function renderPolicy(s){
    if(!$("catActions").dataset.built){
      $("catActions").innerHTML=CATS.map(function(c){
        return '<div class="polrow"><span>'+c+'</span><select id="ca_'+c+'">'+
          '<option value="">default</option><option value="warn">warn</option>'+
          '<option value="redact">redact</option><option value="block">block</option></select></div>'}).join("");
      $("catActions").dataset.built="1";
      CATS.forEach(function(c){$("ca_"+c).addEventListener("change",saveCatActions)});
    }
    var ca=s.categoryActions||{}, blk=s.blockOn||[];
    CATS.forEach(function(c){var el=$("ca_"+c);var v=ca[c]||(blk.indexOf(c)>=0?"block":"");if(document.activeElement!==el)el.value=v});
    if(document.activeElement!==$("allowlist")) $("allowlist").value=(s.allowlist||[]).join("\\n");
  }
  function saveCatActions(){
    var ca={};CATS.forEach(function(c){var v=$("ca_"+c).value;if(v)ca[c]=v});
    // GUI becomes the single source: fold blockOn into categoryActions.
    setConfig({categoryActions:ca,blockOn:[]}).then(function(){scan();toast("Policy updated")});
  }
  function renderDetectors(d){
    if(!$("detectors").dataset.built){
      $("detectors").innerHTML=DETECTORS.map(function(k){
        return '<label class="srow"><span>'+k+'</span><span class="switch"><input type="checkbox" id="det_'+k+'"/><span class="sl"></span></span></label>'}).join("");
      $("detectors").dataset.built="1";
      DETECTORS.forEach(function(k){$("det_"+k).addEventListener("change",saveDetectors)});
    }
    DETECTORS.forEach(function(k){var c=$("det_"+k);if(c&&document.activeElement!==c)c.checked=!!d[k]});
  }
  function saveDetectors(){var det={};DETECTORS.forEach(function(k){det[k]=$("det_"+k).checked});setConfig({detectors:det}).then(function(){scan();toast("Detectors updated")})}

  $("optToggle").addEventListener("change",function(){setConfig({optimize:{enabled:$("optToggle").checked}}).then(function(){toast("Optimize prompts "+($("optToggle").checked?"on":"off"))})});
  $("toggleBase").addEventListener("click",function(){api(current.base?"/api/proxy/stop":"/api/proxy/start","POST",{kind:"base"}).then(function(s){renderStatus(s);toast(s.base?"Base-URL guard on":"Base-URL guard off")})});
  $("toggleSystem").addEventListener("click",function(){api(current.system?"/api/proxy/stop":"/api/proxy/start","POST",{kind:"system"}).then(function(s){renderStatus(s);toast(s.system?"System guard on":"System guard off")})});
  Array.prototype.forEach.call($("segMode").children,function(b){b.addEventListener("click",function(){setConfig({mode:b.dataset.mode}).then(function(){scan();toast("Mode: "+b.dataset.mode)})})});
  $("btnDict").addEventListener("click",function(){
    var dict=$("dictionary").value.split("\\n").map(function(x){return x.trim()}).filter(Boolean);
    setConfig({dictionary:dict}).then(function(){$("savedMsg").textContent="Saved";setTimeout(function(){$("savedMsg").textContent=""},1400);scan();toast("Dictionary applied")})});
  Array.prototype.forEach.call(document.querySelectorAll("[data-sample]"),function(b){
    b.addEventListener("click",function(){$("input").value=SAMPLES[b.dataset.sample].replace(/\\\\n/g,"\\n");scan()})});
  $("btnAllow").addEventListener("click",function(){
    var list=$("allowlist").value.split("\\n").map(function(x){return x.trim()}).filter(Boolean);
    setConfig({allowlist:list}).then(function(){$("savedAllow").textContent="Saved";setTimeout(function(){$("savedAllow").textContent=""},1400);scan();toast("Allowlist applied")})});

  function highlight(text,fs){
    if(!fs.length) return esc(text);
    var out="",pos=0;
    fs.slice().sort(function(a,b){return a.start-b.start}).forEach(function(f){
      if(f.start<pos) return;
      out+=esc(text.slice(pos,f.start));
      out+='<mark class="hl '+f.severity+'" title="'+esc(f.category+"/"+f.type)+'">'+esc(text.slice(f.start,f.end))+'</mark>';
      pos=f.end;
    });
    out+=esc(text.slice(pos));
    return out;
  }
  function colorPlaceholders(s){return esc(s).replace(/\\[\\[REDACTED:[A-Z0-9_]+:\\d+\\]\\]/g,function(m){return '<span class="ph">'+m+'</span>'})}

  var lastRedacted="";
  var st;
  function scan(){
    var text=$("input").value;
    if(!text){$("detected").innerHTML='<span class="ttl">Detected (highlighted)</span><span class="empty">No findings yet.</span>';
      $("redacted").innerHTML='<span class="ttl">Sent to the AI (scrubbed)</span><span class="empty">—</span>';
      $("count").textContent="0";$("copyBtn").disabled=true;return}
    api("/api/scan","POST",{text:text}).then(function(r){
      lastRedacted=r.redacted;
      $("detected").innerHTML='<span class="ttl">Detected (highlighted)</span>'+highlight(text,r.findings);
      $("redacted").innerHTML='<span class="ttl">Sent to the AI (scrubbed)</span>'+colorPlaceholders(r.redacted);
      $("count").textContent=r.findings.length;
      if(r.savedTokens){$("savedChip").textContent="saved "+r.savedTokens+" tok";$("savedChip").style.display=""}else{$("savedChip").style.display="none"}
      $("copyBtn").disabled=r.findings.length===0;
    });
  }
  $("input").addEventListener("input",function(){clearTimeout(st);st=setTimeout(scan,250)});
  $("copyBtn").addEventListener("click",function(){
    (navigator.clipboard?navigator.clipboard.writeText(lastRedacted):Promise.resolve()).then(function(){toast("Scrubbed text copied")})});

  // ---- metrics + activity ----
  var stats={findings:0,events:0,blocked:0,cat:{}};
  function renderStats(){
    $("m_findings").textContent=stats.findings;
    $("m_events").textContent=stats.events;
    $("m_blocked").textContent=stats.blocked;
    var top="—",max=0;for(var k in stats.cat){if(stats.cat[k]>max){max=stats.cat[k];top=k}}
    $("m_topcat").textContent=top;
  }
  function fold(e){
    stats.events++; stats.findings+=(e.summary&&e.summary.total)||0;
    if(e.action==="blocked")stats.blocked++;
    var bc=(e.summary&&e.summary.byCategory)||{};for(var k in bc)stats.cat[k]=(stats.cat[k]||0)+bc[k];
    renderStats();
  }
  function addActivity(e){
    var ul=$("activity");var em=ul.querySelector(".empty");if(em)em.remove();
    var types=Object.keys((e.summary&&e.summary.byType)||{}).map(function(k){return k+"×"+e.summary.byType[k]}).join(", ");
    if(e.savedTokens)types=(types?types+" · ":"")+"opt -"+e.savedTokens+" tok";
    var tag=e.action==="blocked"?"BLOCK":e.action==="redacted"?"REDACT":e.action==="warned"?"WARN":"CLEAN";
    var li=document.createElement("li");
    li.innerHTML='<span class="tag '+tag+'">'+tag+'</span>'+
      '<span class="mono">'+esc((e.ts||"").replace("T"," ").replace(/\\..*/,""))+'</span>'+
      '<span class="grow">'+esc(e.route||"")+(e.direction==="response"?" - response":"")+'</span>'+
      '<span class="mono">'+esc(types)+'</span>';
    ul.insertBefore(li,ul.firstChild);
    while(ul.children.length>60)ul.removeChild(ul.lastChild);
  }
  $("clearActivity").addEventListener("click",function(){$("activity").innerHTML='<li class="empty">Cleared.</li>'});

  // ---- compliance ----
  var FW=[["PCI_DSS","PCI DSS","pci"],["HIPAA","HIPAA","hipaa"],["GDPR","GDPR","gdpr"],["SECRETS_SOC2","Secrets / SOC2","soc2"]];
  function renderCompliance(rep){
    var fr=rep.frameworks||{};var max=1;FW.forEach(function(f){max=Math.max(max,(fr[f[0]]||{}).total||0)});
    var any=FW.some(function(f){return ((fr[f[0]]||{}).total||0)>0});
    if(!any){$("compliance").innerHTML='<div class="empty">No exposure recorded yet.</div>';return}
    $("compliance").innerHTML=FW.map(function(f){
      var t=(fr[f[0]]||{}).total||0;var w=Math.round(t/max*100);
      return '<div class="bar '+f[2]+'"><span>'+f[1]+'</span><span class="track"><span class="fill" style="width:'+w+'%"></span></span><span class="v">'+t+'</span></div>';
    }).join("");
  }
  var cT;
  function refreshCompliance(){clearTimeout(cT);cT=setTimeout(function(){api("/api/report").then(renderCompliance)},400)}
  $("refreshCompliance").addEventListener("click",function(){api("/api/report").then(renderCompliance)});

  var ev=new EventSource("/api/events");
  ev.onmessage=function(m){var e=JSON.parse(m.data);
    if(e.type==="status")renderStatus(e.status);
    else if(e.type==="audit"){addActivity(e.entry);fold(e.entry);refreshCompliance()}};
  api("/api/status").then(renderStatus);
  api("/api/audit").then(function(r){(r.entries||[]).slice().reverse().forEach(function(e){addActivity(e);fold(e)})});
  api("/api/report").then(renderCompliance);
</script>
</body>
</html>`;
