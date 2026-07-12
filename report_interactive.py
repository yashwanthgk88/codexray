#!/usr/bin/env python3
"""Interactive CodeXray report: a drill-down explorer of source anatomy.

Beyond the flat tables, this builds an EXPANDABLE CALL TREE per entry point.
Each node shows the real source code, with sinks / sources / blind spots
highlighted inline. The analyst clicks any call to expand it and dig deeper -
following execution the way they would by hand, but never losing a branch.
Still zero verdicts: the tool shows anatomy, the analyst decides.
"""
import html
import json
import sys

from xray import build_model, SINKS


def short_key(key):
    if "::" in key:
        f, q = key.split("::", 1)
        return f"{f} :: {q}"
    return key


def leaf(key):
    return key.split("::")[-1] if "::" in key else key


def build_payload(model):
    funcs = model["funcs"]
    edges = model["edges"]
    file_sources = model["file_sources"]

    # Serialize each function: metadata + source lines + annotated events + children
    func_json = {}
    for key, fi in funcs.items():
        src_lines = file_sources.get(fi.file, [])
        body = []
        for ln in range(fi.lineno, min(fi.endlineno, len(src_lines)) + 1):
            body.append({"n": ln, "t": src_lines[ln - 1] if ln - 1 < len(src_lines) else ""})
        # events keyed by line number for inline highlighting
        events = {}
        for (dotted, cat, why, lineno) in fi.sinks:
            events.setdefault(lineno, []).append({"kind": "sink", "label": dotted, "cat": cat, "why": why})
        for (name, lineno) in fi.sources:
            events.setdefault(lineno, []).append({"kind": "source", "label": name})
        for (dotted, reason, lineno) in fi.blindspots:
            events.setdefault(lineno, []).append({"kind": "blind", "label": dotted, "why": reason})
        # children = resolved callees, plus the line they're called on
        children = []
        callee_keys = edges.get(key, set())
        callee_by_short = {}
        for ck in callee_keys:
            callee_by_short[leaf(ck)] = ck
        for (short, dotted, lineno) in fi.calls:
            if short in callee_by_short:
                children.append({"line": lineno, "target": callee_by_short[short], "name": short, "resolved": True})
        func_json[key] = {
            "key": key, "name": fi.qualname, "file": fi.file,
            "line": fi.lineno, "endline": fi.endlineno,
            "is_entry": fi.is_entry, "entry_kind": fi.entry_kind,
            "entry_meta": fi.entry_meta, "params": fi.params,
            "body": body, "events": events, "children": children,
            "nsinks": len(fi.sinks), "nblind": len(fi.blindspots),
        }

    # for each entry, precompute which functions are reachable (to show reach badges)
    entries = []
    for ekey in model["entries"]:
        fi = funcs[ekey]
        entries.append({
            "key": ekey, "name": fi.qualname, "kind": fi.entry_kind,
            "meta": fi.entry_meta,
            "reach": len(model["reachable_from"].get(ekey, set())),
            "sink_cats": sorted({s[1][1] for s in model["entry_sinks"].get(ekey, [])}),
            "sources": sorted({s[0] for s in fi.sources}),
        })

    # ledger
    ledger = {}
    for b, keys in model["buckets"].items():
        ledger[b] = []
        for key in sorted(keys):
            fi = funcs[key]
            ledger[b].append({
                "key": key, "name": fi.qualname, "file": fi.file,
                "line": fi.lineno, "endline": fi.endlineno,
                "cats": sorted({s[1] for s in fi.sinks}), "nblind": len(fi.blindspots),
            })

    blind_rows = []
    for key, fi in funcs.items():
        for (dotted, reason, lineno) in fi.blindspots:
            blind_rows.append({"func": fi.qualname, "file": fi.file, "line": lineno,
                               "call": dotted, "reason": reason, "key": key})

    return {
        "root": model["root"], "stats": model["stats"],
        "funcs": func_json, "entries": entries, "ledger": ledger,
        "blind_rows": blind_rows,
    }


def render(model, out_path):
    payload = build_payload(model)
    doc = HTML_TEMPLATE.replace("__PAYLOAD__", json.dumps(payload))
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(doc)
    return out_path


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CodeXray - interactive source anatomy</title>
<style>
  :root{
    --bg:#f6f6f3;--card:#fff;--ink:#2e2e38;--muted:#77776f;--line:#e5e4dd;
    --accent:#0c447c;--accentbg:#e6f1fb;--dark:#2e2e38;--darker:#26262e;
    --amber:#854f0b;--amberbg:#faeeda;--ok:#0f6e56;--okbg:#e1f5ee;
    --red:#a32d2d;--redbg:#fcebeb;--code:#1e1e26;--codeink:#e8e8ee;
  }
  *{box-sizing:border-box}
  body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
       background:var(--bg);color:var(--ink);font-size:14px;line-height:1.5}
  header{background:var(--dark);color:#fff;padding:16px 24px;position:sticky;top:0;z-index:20}
  header h1{margin:0;font-size:18px;font-weight:600}
  header .sub{color:#c7c7d0;font-size:12px;margin-top:3px}
  .layout{display:grid;grid-template-columns:280px 1fr;min-height:calc(100vh - 58px)}
  .side{background:var(--card);border-right:1px solid var(--line);padding:14px;overflow-y:auto}
  .side h3{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin:16px 0 8px}
  .side h3:first-child{margin-top:0}
  .epitem{padding:8px 10px;border:1px solid var(--line);border-radius:8px;margin-bottom:6px;cursor:pointer;background:#fff}
  .epitem:hover{border-color:var(--accent)}
  .epitem.active{background:var(--accentbg);border-color:var(--accent)}
  .epitem .m{font-size:10px;font-weight:700;padding:1px 6px;border-radius:4px;background:#eef;color:#334;margin-right:5px}
  .epitem .m.CLI{background:#e6f5ee;color:#0f6e56}
  .epitem .p{font-family:"SF Mono",Menlo,monospace;font-size:12px}
  .epitem .meta{font-size:11px;color:var(--muted);margin-top:3px}
  .dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-left:4px}
  .main{padding:18px 22px;overflow-y:auto}
  .stats{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px}
  .st{background:var(--card);border:1px solid var(--line);border-radius:9px;padding:9px 14px;min-width:96px}
  .st .n{font-size:20px;font-weight:600}.st .l{font-size:10.5px;text-transform:uppercase;color:var(--muted);letter-spacing:.3px}
  .st.w .n{color:var(--amber)}
  .breadcrumb{font-size:12px;color:var(--muted);margin-bottom:10px}
  .breadcrumb b{color:var(--ink)}
  .empty{color:var(--muted);padding:40px;text-align:center;border:1px dashed var(--line);border-radius:10px}
  /* call-tree nodes */
  .tnode{margin:0 0 8px 0}
  .tnode .head{display:flex;align-items:center;gap:8px;background:var(--card);border:1px solid var(--line);
       border-radius:8px 8px 0 0;padding:8px 12px;cursor:pointer;position:relative}
  .tnode .head.collapsed{border-radius:8px}
  .tnode .head:hover{background:#fafaf7}
  .tnode.entry > .head{border-left:3px solid var(--accent)}
  .tnode.hassink > .head{border-left:3px solid var(--red)}
  .tnode.hasblind > .head{border-left:3px solid var(--dark)}
  .caret{width:14px;color:var(--muted);transition:transform .15s;flex-shrink:0}
  .caret.open{transform:rotate(90deg)}
  .fname{font-family:"SF Mono",Menlo,monospace;font-size:13px;font-weight:600}
  .floc{font-size:11px;color:var(--muted)}
  .badges{margin-left:auto;display:flex;gap:4px;align-items:center}
  .badge{font-size:10px;padding:2px 7px;border-radius:20px;font-weight:600}
  .badge.sink{background:var(--redbg);color:var(--red)}
  .badge.blind{background:var(--dark);color:#ffe600}
  .badge.src{background:var(--amberbg);color:var(--amber)}
  .badge.leaf{background:#eee;color:#777}
  /* code panel */
  .code{background:var(--code);border-radius:0 0 8px 8px;padding:8px 0;overflow-x:auto;font-family:"SF Mono",Menlo,Consolas,monospace;font-size:12.5px;line-height:1.65}
  .cl{display:flex;white-space:pre}
  .cl .ln{color:#5a5a6a;width:46px;text-align:right;padding-right:12px;flex-shrink:0;user-select:none}
  .cl .tx{color:var(--codeink);padding-right:16px}
  .cl.hl-sink{background:rgba(163,45,45,.22)}
  .cl.hl-source{background:rgba(133,79,11,.28)}
  .cl.hl-blind{background:rgba(255,230,0,.12)}
  .cl.hl-call{background:rgba(12,68,124,.20)}
  .inlineev{margin-left:8px;font-size:11px;padding:0 6px;border-radius:4px;font-family:inherit}
  .inlineev.sink{background:var(--red);color:#fff}
  .inlineev.source{background:var(--amber);color:#fff}
  .inlineev.blind{background:#ffe600;color:#2e2e38}
  .digbtn{margin-left:8px;font-size:11px;background:var(--accent);color:#fff;border:none;border-radius:4px;padding:1px 8px;cursor:pointer;font-family:-apple-system,sans-serif}
  .digbtn.done{background:#3a6d55}
  .kids{margin:8px 0 0 26px;border-left:2px dashed var(--line);padding-left:14px}
  .legend{display:flex;gap:14px;flex-wrap:wrap;font-size:11px;color:var(--muted);margin:4px 0 14px}
  .legend span{display:flex;align-items:center;gap:5px}
  .sw{width:12px;height:12px;border-radius:3px;display:inline-block}
  .toolbar{display:flex;gap:8px;margin-bottom:12px}
  .tbtn{font-size:12px;border:1px solid var(--line);background:#fff;border-radius:7px;padding:5px 11px;cursor:pointer;color:var(--muted)}
  .tbtn:hover{border-color:var(--accent);color:var(--accent)}
  .disclaim{background:#3c3c48;border-left:3px solid #ffe600;padding:7px 11px;font-size:11.5px;color:#e8e8ee;border-radius:0 4px 4px 0;margin-top:9px}
  .cycle{font-size:11px;color:var(--muted);font-style:italic;padding:4px 0 0 26px}
</style>
</head>
<body>
<header>
  <h1>CodeXray &middot; interactive source anatomy</h1>
  <div class="sub" id="rootline"></div>
  <div class="disclaim"><b>X-ray, not scanner.</b> Click any entry point, then expand each call to follow
  execution into the real source. Sinks, tainted inputs and blind spots are highlighted as <i>facts</i> &mdash;
  you decide what's a vulnerability.</div>
</header>
<div class="layout">
  <aside class="side">
    <h3>Entry points</h3>
    <div id="eplist"></div>
    <h3>Jump to</h3>
    <div class="epitem" onclick="showLedger()"><span class="p">Coverage ledger</span><div class="meta">disposition every function</div></div>
    <div class="epitem" onclick="showBlind()"><span class="p">Blind spots</span><div class="meta" id="blindcount"></div></div>
  </aside>
  <main class="main" id="main"></main>
</div>

<script>
const D = __PAYLOAD__;
const F = D.funcs;
const CATC={command_exec:"#A32D2D",code_exec:"#A32D2D",sql:"#993C1D",deserialization:"#993556",
  file_io:"#854F0B",ssrf:"#185FA5",template_injection:"#534AB7",xss:"#993556",response_write:"#5F5E5A"};
function esc(s){return String(s==null?"":s).replace(/[&<>"]/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[m]));}
function leaf(k){return k.includes("::")?k.split("::").pop():k;}
function skey(k){return k.includes("::")?k.replace("::"," :: "):k;}

document.getElementById("rootline").textContent = D.root+"  \u00b7  "+D.stats.functions+" functions  \u00b7  "+D.stats.entry_points+" entry points";
document.getElementById("blindcount").textContent = D.stats.blindspots+" unseeable region(s)";

// ---- sidebar entry list ----
document.getElementById("eplist").innerHTML = D.entries.map((e,i)=>{
  const m=e.meta||{}; const cli=e.kind==='cli';
  const dotcolor = e.sink_cats.length? (CATC[e.sink_cats[0]]||"#a32d2d"):"#c9c9c2";
  return `<div class="epitem" id="ep${i}" onclick="openEntry('${esc(e.key)}',${i})">
    <span class="m ${cli?'CLI':''}">${esc(m.method||'?')}</span>
    <span class="p">${esc(m.path||e.name)}</span>
    <span class="dot" style="background:${dotcolor}"></span>
    <div class="meta">${e.reach} func(s) reachable &middot; ${e.sink_cats.length?e.sink_cats.join(", "):'no sinks'}</div>
  </div>`;
}).join("");

// ---- disposition state (shared with ledger) ----
const dispo={};

// ---- expansion state per rendered tree (track open nodes + visited for cycles) ----
function openEntry(key,i){
  document.querySelectorAll(".epitem").forEach(x=>x.classList.remove("active"));
  const el=document.getElementById("ep"+i); if(el) el.classList.add("active");
  const e=D.entries.find(x=>x.key===key);
  const m=e.meta||{};
  const main=document.getElementById("main");
  main.innerHTML=`
    <div class="breadcrumb">entry point &rsaquo; <b>${esc(m.path||e.name)}</b></div>
    <div class="stats">
      <div class="st"><div class="n">${e.reach}</div><div class="l">funcs reachable</div></div>
      <div class="st ${e.sink_cats.length?'w':''}"><div class="n">${e.sink_cats.length}</div><div class="l">sink categories</div></div>
      <div class="st"><div class="n">${(e.sources||[]).length}</div><div class="l">input sources</div></div>
    </div>
    <div class="legend">
      <span><span class="sw" style="background:#A32D2D"></span>sink (dangerous op)</span>
      <span><span class="sw" style="background:#854F0B"></span>tainted input</span>
      <span><span class="sw" style="background:#ffe600"></span>blind spot</span>
      <span><span class="sw" style="background:#0c447c"></span>call &mdash; click <b>dig</b> to expand</span>
    </div>
    <div class="toolbar">
      <button class="tbtn" onclick="expandAll('${esc(key)}')">Expand every reachable path</button>
      <button class="tbtn" onclick="openEntry('${esc(key)}',${i})">Collapse</button>
    </div>
    <div id="tree"></div>`;
  document.getElementById("tree").innerHTML = renderNode(key, [], true);
}

// Render one call-tree node. path = ancestor keys (for cycle detection).
function renderNode(key, ancestors, isEntry){
  const fn=F[key]; if(!fn) return "";
  const nid = "n_"+Math.random().toString(36).slice(2,9);
  const isCycle = ancestors.includes(key);
  const cls = ["tnode"];
  if(isEntry) cls.push("entry");
  if(fn.nsinks) cls.push("hassink");
  if(fn.nblind) cls.push("hasblind");
  const badges=[];
  if(fn.nsinks) badges.push(`<span class="badge sink">${fn.nsinks} sink</span>`);
  if(fn.nblind) badges.push(`<span class="badge blind">${fn.nblind} blind</span>`);
  const hasSrc = Object.values(fn.events).some(ev=>ev.some(x=>x.kind==='source'));
  if(hasSrc) badges.push(`<span class="badge src">input</span>`);
  if(!fn.children.length) badges.push(`<span class="badge leaf">leaf</span>`);

  // default: entry nodes start expanded, others collapsed
  const startOpen = isEntry;
  const codeHtml = renderCode(fn, ancestors);
  const head = `<div class="head ${startOpen?'':'collapsed'}" onclick="toggleNode('${nid}')">
      <span class="caret ${startOpen?'open':''}" id="${nid}_c">&#9656;</span>
      <span class="fname">${esc(fn.name)}</span>
      <span class="floc">${esc(fn.file)}:${fn.line}&ndash;${fn.endline}</span>
      <span class="badges">${badges.join("")}</span>
    </div>`;
  const bodyDiv = `<div id="${nid}_b" style="display:${startOpen?'block':'none'}">
      ${isCycle? `<div class="cycle">&#8635; recursion / cycle back to ${esc(fn.name)} &mdash; not re-expanded</div>`: codeHtml}
    </div>`;
  return `<div class="${cls.join(' ')}">${head}${bodyDiv}</div>`;
}

// Render the source code of a function with inline event highlights and dig buttons.
function renderCode(fn, ancestors){
  const childByLine={};
  fn.children.forEach(c=>{ (childByLine[c.line]=childByLine[c.line]||[]).push(c); });
  let out = '<div class="code">';
  fn.body.forEach(row=>{
    const evs = fn.events[row.n]||[];
    const kinds = evs.map(e=>e.kind);
    let hl="";
    if(kinds.includes("sink")) hl="hl-sink";
    else if(kinds.includes("source")) hl="hl-source";
    else if(kinds.includes("blind")) hl="hl-blind";
    else if(childByLine[row.n]) hl="hl-call";
    let inline="";
    evs.forEach(e=>{
      if(e.kind==="sink") inline+=`<span class="inlineev sink" title="${esc(e.why)}">&#9632; ${esc(e.cat)}</span>`;
      if(e.kind==="source") inline+=`<span class="inlineev source">&#9632; input: ${esc(e.label)}</span>`;
      if(e.kind==="blind") inline+=`<span class="inlineev blind" title="${esc(e.why)}">&#9888; blind: ${esc(e.label)}</span>`;
    });
    // dig buttons for resolved calls on this line
    (childByLine[row.n]||[]).forEach(c=>{
      const target=F[c.target];
      const label = target? `dig &rarr; ${esc(leaf(c.target))}()` : `${esc(c.name)}()`;
      const did="dig_"+Math.random().toString(36).slice(2,9);
      inline+=` <button class="digbtn" id="${did}" onclick="event.stopPropagation();digInto('${esc(c.target)}','${did}','${ancestors.join('|')}')">${label}</button>`;
    });
    out+=`<div class="cl ${hl}"><span class="ln">${row.n}</span><span class="tx">${esc(row.t)||' '}</span>${inline}</div>`;
  });
  out+='</div>';
  return out;
}

// clicking "dig" expands the callee inline, right under the call site.
function digInto(targetKey, btnId, ancestorStr){
  const btn=document.getElementById(btnId);
  const ancestors = ancestorStr? ancestorStr.split("|"):[];
  // insert child tree right after the code block containing the button
  const codeDiv = btn.closest(".code");
  let holder = codeDiv.nextElementSibling;
  if(holder && holder.classList.contains("kids")){
    // toggle off
    holder.remove(); btn.classList.remove("done"); return;
  }
  const kids=document.createElement("div");
  kids.className="kids";
  kids.innerHTML = renderNode(targetKey, ancestors.concat(findOwnerKey(btn)), false);
  codeDiv.after(kids);
  btn.classList.add("done");
}
// find which function key owns the code block a button sits in (walk up to .tnode head fname)
function findOwnerKey(btn){
  const node=btn.closest(".tnode");
  if(!node) return "";
  const fname=node.querySelector(".fname");
  if(!fname) return "";
  // match by name+loc against F
  const loc=node.querySelector(".floc").textContent;
  const name=fname.textContent;
  for(const k in F){ if(F[k].name===name && (F[k].file+":"+F[k].line+"\u2013"+F[k].endline)===loc) return k; }
  return "";
}

function toggleNode(nid){
  const c=document.getElementById(nid+"_c");
  const b=document.getElementById(nid+"_b");
  const open=b.style.display!=="none";
  b.style.display=open?"none":"block";
  c.classList.toggle("open",!open);
}

function expandAll(key){
  // render the whole reachable tree eagerly (bounded by cycle detection)
  const tree=document.getElementById("tree");
  tree.innerHTML=renderFullTree(key, [], true);
}
function renderFullTree(key, ancestors, isEntry){
  const fn=F[key]; if(!fn) return "";
  if(ancestors.includes(key)){
    return `<div class="tnode"><div class="head"><span class="caret">&#9656;</span>
      <span class="fname">${esc(fn.name)}</span><span class="cycle" style="margin-left:8px">&#8635; cycle</span></div></div>`;
  }
  const childTrees = fn.children.map(c=>renderFullTree(c.target, ancestors.concat(key), false)).join("");
  const badges=[];
  if(fn.nsinks) badges.push(`<span class="badge sink">${fn.nsinks} sink</span>`);
  if(fn.nblind) badges.push(`<span class="badge blind">${fn.nblind} blind</span>`);
  if(!fn.children.length) badges.push(`<span class="badge leaf">leaf</span>`);
  const cls=["tnode"]; if(isEntry)cls.push("entry"); if(fn.nsinks)cls.push("hassink"); if(fn.nblind)cls.push("hasblind");
  return `<div class="${cls.join(' ')}">
    <div class="head"><span class="caret open">&#9656;</span>
      <span class="fname">${esc(fn.name)}</span>
      <span class="floc">${esc(fn.file)}:${fn.line}&ndash;${fn.endline}</span>
      <span class="badges">${badges.join("")}</span></div>
    <div>${renderCode(fn, ancestors.concat(key))}${childTrees?`<div class="kids">${childTrees}</div>`:""}</div>
  </div>`;
}

// ---- ledger view ----
const BUCKETS=[["entry_point","Entry points"],["reachable_with_sink","Reachable &mdash; reaches a sink"],
  ["reachable_no_sink","Reachable &mdash; no sink"],["not_reachable_from_entry","Not reachable from any entry point"]];
let allKeys=[]; BUCKETS.forEach(([b])=>((D.ledger[b]||[]).forEach(r=>allKeys.push(r.key))));
function showLedger(){
  document.querySelectorAll(".epitem").forEach(x=>x.classList.remove("active"));
  const done=allKeys.filter(k=>dispo[k]).length, pct=allKeys.length?Math.round(done/allKeys.length*100):100;
  let h=`<div class="breadcrumb">coverage ledger</div>
   <div style="position:sticky;top:0;background:var(--bg);padding:6px 0 10px">
   <div style="height:9px;background:#e4e3dc;border-radius:5px;overflow:hidden"><div style="height:100%;background:var(--ok);width:${pct}%"></div></div>
   <div style="font-size:12px;color:var(--muted);margin-top:5px">${done} of ${allKeys.length} functions dispositioned (${pct}%)</div>
   <div style="font-size:12px;margin-top:6px;padding:8px 12px;border-radius:8px;${done===allKeys.length&&allKeys.length?'background:var(--okbg);color:var(--ok);border:1px solid #9fe1cb':'background:var(--redbg);color:var(--red);border:1px solid #f7c1c1'}">
   ${done===allKeys.length&&allKeys.length?'&check; 100% source coverage &mdash; report can be finalized.':'Report cannot be finalized until every function is dispositioned ('+(allKeys.length-done)+' remaining).'}</div></div>`;
  BUCKETS.forEach(([b,title])=>{
    const rows=D.ledger[b]||[]; if(!rows.length) return;
    h+=`<h3 style="font-size:13px;margin:18px 0 8px">${title} <span style="color:var(--muted);font-weight:400">(${rows.length})</span></h3>
      <table style="width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);border-radius:9px;overflow:hidden">
      <tr><th style="text-align:left;padding:8px 11px;font-size:11px;color:var(--muted);background:#faf9f6">Function</th>
      <th style="text-align:left;padding:8px 11px;font-size:11px;color:var(--muted);background:#faf9f6">Location</th>
      <th style="text-align:left;padding:8px 11px;font-size:11px;color:var(--muted);background:#faf9f6">Sinks</th>
      <th style="text-align:left;padding:8px 11px;font-size:11px;color:var(--muted);background:#faf9f6;width:190px">Disposition</th></tr>`;
    rows.forEach(r=>{
      const cats=(r.cats||[]).map(c=>`<span class="badge sink" style="background:${(CATC[c]||'#a32d2d')}22;color:${CATC[c]||'#a32d2d'}">${esc(c)}</span>`).join("")||(r.nblind?'<span class="badge blind">blind</span>':'<span style="color:#bbb">&mdash;</span>');
      const st=dispo[r.key]||"";
      h+=`<tr><td style="padding:8px 11px;border-top:1px solid var(--line)"><code style="font-size:12px">${esc(r.name)}</code></td>
        <td style="padding:8px 11px;border-top:1px solid var(--line);color:var(--muted);font-size:11.5px">${esc(r.file)}:${r.line}</td>
        <td style="padding:8px 11px;border-top:1px solid var(--line)">${cats}</td>
        <td style="padding:8px 11px;border-top:1px solid var(--line)">
          <span class="tbtn" style="padding:3px 9px;${st==='safe'?'background:var(--okbg);color:var(--ok);border-color:#9fe1cb':''}" onclick="setD('${esc(r.key)}','safe')">safe</span>
          <span class="tbtn" style="padding:3px 9px;${st==='finding'?'background:var(--redbg);color:var(--red);border-color:#f7c1c1':''}" onclick="setD('${esc(r.key)}','finding')">finding</span>
          <span class="tbtn" style="padding:3px 9px;${st==='skip'?'background:#f1efe8;color:#444':''}" onclick="setD('${esc(r.key)}','skip')">n/a</span>
        </td></tr>`;
    });
    h+=`</table>`;
  });
  document.getElementById("main").innerHTML=h;
}
function setD(k,v){dispo[k]=(dispo[k]===v?undefined:v);showLedger();}

// ---- blind spots view ----
function showBlind(){
  document.querySelectorAll(".epitem").forEach(x=>x.classList.remove("active"));
  let h=`<div class="breadcrumb">blind spots &mdash; the shadows on the X-ray</div>
    <div style="background:var(--amberbg);border-left:3px solid var(--amber);padding:10px 13px;border-radius:0 6px 6px 0;font-size:12.5px;color:#5a3806;margin-bottom:14px">
    Showing these is what separates a trustworthy X-ray from a scanner that quietly skips what it can't parse.
    "No flow here" and "we couldn't see here" are different statements &mdash; each region below needs manual inspection.</div>`;
  if(!D.blind_rows.length){ h+=`<div class="empty">No dynamic-dispatch blind spots detected.</div>`; }
  else{
    h+=`<div class="blind" style="background:var(--dark);border-radius:10px;padding:4px 4px 8px">
      <table style="width:100%;border-collapse:collapse">
      <tr><th style="text-align:left;padding:9px 12px;font-size:11px;color:#c9c9d2">Function</th>
      <th style="text-align:left;padding:9px 12px;font-size:11px;color:#c9c9d2">Location</th>
      <th style="text-align:left;padding:9px 12px;font-size:11px;color:#c9c9d2">Unseeable call</th>
      <th style="text-align:left;padding:9px 12px;font-size:11px;color:#c9c9d2">Why the X-ray goes dark</th></tr>`;
    D.blind_rows.forEach(r=>{
      h+=`<tr><td style="padding:9px 12px;border-top:1px solid #45454f;color:#e8e8ee"><code style="background:#45454f;color:#ffe600;padding:1px 5px;border-radius:4px">${esc(r.func)}</code></td>
        <td style="padding:9px 12px;border-top:1px solid #45454f;color:#c9c9d2;font-size:11.5px">${esc(r.file)}:${r.line}</td>
        <td style="padding:9px 12px;border-top:1px solid #45454f"><code style="background:#45454f;color:#ffe600;padding:1px 5px;border-radius:4px">${esc(r.call)}</code></td>
        <td style="padding:9px 12px;border-top:1px solid #45454f;color:#e8e8ee">${esc(r.reason)}</td></tr>`;
    });
    h+=`</table></div>`;
  }
  document.getElementById("main").innerHTML=h;
}

// open first entry by default
if(D.entries.length) openEntry(D.entries[0].key,0);
else document.getElementById("main").innerHTML='<div class="empty">No entry points found.</div>';
</script>
</body>
</html>"""


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    out = sys.argv[2] if len(sys.argv) > 2 else "codexray_interactive.html"
    model = build_model(root)
    render(model, out)
    print("wrote", out)
    print(json.dumps(model["stats"], indent=2))
