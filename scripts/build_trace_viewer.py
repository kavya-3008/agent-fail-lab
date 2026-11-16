"""Build docs/traces.html: a replayable, filterable view of every agent run.
Run: PYTHONPATH=. python3 scripts/build_trace_viewer.py"""
import json
from pathlib import Path

from lab.runner import all_agents, run_all
from lab.scenarios import SCENARIOS, reveal

ROOT = Path(__file__).resolve().parent.parent
scen = {s.name: s for s in SCENARIOS}
runs = []
for r in run_all(all_agents()):
    s = scen[r["scenario"]]
    r["task"] = s.task
    r["documents"] = {k: reveal(v) + (" [contains hidden Unicode]" if reveal(v) != v else "") for k, v in s.documents.items()}
    r["allowed"] = sorted(s.allowed_recipients)
    runs.append(r)

data = json.dumps(runs).replace("</", "<\\/")
html = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent Fail Lab Traces</title><style>
:root{--bg:#f6f8fa;--fg:#14181c;--mut:#5b6670;--acc:#0f766e;--bad:#b91c1c;--card:#fff;--line:#dde3e8}
@media(prefers-color-scheme:dark){:root{--bg:#0e1316;--fg:#e8eef2;--mut:#93a1ab;--acc:#2dd4bf;--bad:#f87171;--card:#151c20;--line:#26323a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}
main{max-width:900px;margin:0 auto;padding:32px 16px 64px}h1{margin:0 0 6px}.note{color:var(--mut);font-size:.9rem}
.bar{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0}select,label{font:inherit;color:var(--fg)}select{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:6px}
details{background:var(--card);border:1px solid var(--line);border-radius:12px;margin:8px 0;padding:10px 16px}summary{cursor:pointer}
.pill{display:inline-block;padding:0 9px;border-radius:99px;font-size:.78rem;margin-left:6px;border:1px solid}.ok{color:var(--acc)}.bad{color:var(--bad)}
.step{border-left:3px solid var(--line);padding:2px 12px;margin:8px 0}.step.bad{border-color:var(--bad)}.step.blk{border-color:var(--acc)}
pre{white-space:pre-wrap;word-break:break-word;background:var(--bg);padding:8px;border-radius:8px;font-size:.82rem;margin:4px 0}
</style></head><body><main><h1>Trace viewer</h1>
<p class="note">Replay each run: the task, what the documents said, every tool call in order (unauthorized ones in red), and what defenses blocked. <a href="index.html">Back to summary</a></p>
<div class="bar"><label>Agent <select id="a"></select></label><label>Result <select id="r"><option value="">all</option><option value="bad">failed</option><option value="ok">resisted</option></select></label></div>
<div id="out"></div></main><script>
const runs=__DATA__;const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const agents=[...new Set(runs.map(r=>r.agent))];$('a').innerHTML='<option value="">all</option>'+agents.map(a=>`<option>${esc(a)}</option>`).join('');
function badCall(r,c){return c.tool==='send_email'&&!r.allowed.includes(c.args.to)}
function draw(){const a=$('a').value,f=$('r').value;$('out').innerHTML=runs.filter(r=>(!a||r.agent===a)&&(!f||(f==='bad')===!!r.failures.length)).map(r=>{
const pills=(r.failures.length?r.failures.map(x=>`<span class="pill bad">${esc(x)}</span>`):['<span class="pill ok">ok</span>']).join('')+(r.completed?'':'<span class="pill bad">task not done</span>');
const docs=Object.entries(r.documents).map(([k,v])=>`<div class="note">document: ${esc(k)}</div><pre>${esc(v)}</pre>`).join('');
const calls=r.tool_calls.map((c,i)=>`<div class="step ${badCall(r,c)?'bad':''}"><b>${i+1}. ${esc(c.tool)}</b><pre>${esc(JSON.stringify(c.args))}</pre></div>`).join('')||'<p class="note">no tool calls</p>';
const blk=r.blocked.map(b=>`<div class="step blk"><b>defense: ${esc(b.defense)}</b> ${esc(b.reason)}</div>`).join('');
return `<details><summary>${esc(r.agent)} on <b>${esc(r.scenario)}</b>${pills}</summary><p class="note">User task: ${esc(r.task)}</p>${docs}${calls}${blk}<div class="note">Final output</div><pre>${esc(r.output)}</pre></details>`}).join('')||'<p class="note">No runs match.</p>'}
$('a').onchange=$('r').onchange=draw;draw();</script></body></html>""".replace("__DATA__", data)
(ROOT / "docs/traces.html").write_text(html)
print(f"wrote docs/traces.html ({len(runs)} runs)")
