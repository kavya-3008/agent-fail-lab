"""Static HTML trace viewer: replays each run step by step and marks the first tool call that went wrong."""
from __future__ import annotations

from html import escape

from .detectors import detect_failures
from .scenarios import SCENARIOS, Scenario, reveal
from .tools import Sandbox

_BY_NAME = {s.name: s for s in SCENARIOS}


def flag_calls(scenario: Scenario, calls: list[dict]) -> list[list[str]]:
    """Failures attributable to each individual call (detectors run on that call alone)."""
    out = []
    for c in calls:
        sb = Sandbox(documents={})
        sb.calls.append(c)
        out.append(detect_failures(scenario, sb))
    return out


def first_bad_step(scenario: Scenario, calls: list[dict]) -> int | None:
    for i, f in enumerate(flag_calls(scenario, calls)):
        if f:
            return i
    return None


def _visible(text: str) -> str:
    """Show hidden tag-character text explicitly instead of letting it vanish."""
    shown = reveal(text)
    if shown == text:
        return escape(text)
    hidden = "".join(ch for ch in text if not (0xE0020 <= ord(ch) <= 0xE007E))
    decoded = "".join(chr(ord(ch) - 0xE0000) for ch in text if 0xE0020 <= ord(ch) <= 0xE007E)
    return escape(hidden) + f'<mark title="invisible in a normal viewer">[hidden: {escape(decoded)}]</mark>'


def render_run(r: dict) -> str:
    sc = _BY_NAME[r["scenario"]]
    flags = flag_calls(sc, r["tool_calls"])
    bad = first_bad_step(sc, r["tool_calls"])
    status = ", ".join(r["failures"]) or "ok"
    steps = [f"<li class='step'><b>User task</b><div>{escape(sc.task)}</div></li>"]
    for i, (c, f) in enumerate(zip(r["tool_calls"], flags)):
        args = "; ".join(f"{k}={escape(str(v))}" for k, v in c["args"].items())
        cls = "step bad" if f else "step"
        note = f"<div class='flag'>{'first deviation: ' if i == bad else ''}{escape(', '.join(f))}</div>" if f else ""
        extra = ""
        if c["tool"] == "read_document" and c["args"]["name"] in sc.documents:
            extra = f"<pre>{_visible(sc.documents[c['args']['name']])}</pre>"
        steps.append(f"<li class='{cls}'><b>{i + 1}. {escape(c['tool'])}</b> <code>{args}</code>{note}{extra}</li>")
    for b in r["blocked"]:
        steps.append(f"<li class='step def'><b>defense: {escape(b['defense'])}</b> {escape(b['tool'])}: {escape(b['reason'])}</li>")
    if not r["tool_calls"]:
        steps.append("<li class='step'><i>no tool calls</i></li>")
    done = "task done" if r["completed"] else "task not completed"
    pill = "bad" if r["failures"] else "ok"
    return (f"<details data-status='{pill}'><summary><span class='pill {pill}'>{escape(status)}</span> "
            f"{escape(r['agent'])} &middot; {escape(r['scenario'])} <span class='note'>({done})</span></summary>"
            f"<ol>{''.join(steps)}</ol></details>")


CSS = """:root{--bg:#f6f8fa;--fg:#14181c;--mut:#5b6670;--acc:#0f766e;--bad:#b91c1c;--card:#fff;--line:#dde3e8}
@media(prefers-color-scheme:dark){:root{--bg:#0e1316;--fg:#e8eef2;--mut:#93a1ab;--acc:#2dd4bf;--bad:#f87171;--card:#151c20;--line:#26323a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,sans-serif}
main{max-width:900px;margin:0 auto;padding:32px 16px 64px}details{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:8px 0;padding:8px 14px}
summary{cursor:pointer}ol{list-style:none;padding:0}.step{border-left:3px solid var(--line);padding:4px 10px;margin:8px 0}.step.bad{border-color:var(--bad)}.step.def{border-color:var(--acc)}
.flag{color:var(--bad);font-size:.88rem}pre{white-space:pre-wrap;background:var(--bg);padding:8px;border-radius:6px;overflow-x:auto}mark{background:transparent;color:var(--bad);font-weight:600}
.pill{display:inline-block;padding:1px 9px;border-radius:99px;font-size:.78rem;border:1px solid}.ok{color:var(--acc);border-color:var(--acc)}.bad{color:var(--bad);border-color:var(--bad)}
.note{color:var(--mut);font-size:.88rem}a{color:var(--acc)}code{word-break:break-all}label{margin-right:12px}"""

JS = """const f=document.getElementById('f');function u(){const v=f.value;document.querySelectorAll('details').forEach(d=>{
const a=d.textContent.toLowerCase().includes(document.getElementById('q').value.toLowerCase());
const s=v==='all'||d.dataset.status===v;d.style.display=a&&s?'':'none'})}
f.onchange=u;document.getElementById('q').oninput=u"""


def render_trace_page(results: list[dict]) -> str:
    runs = "".join(render_run(r) for r in results)
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>Agent Fail Lab: trace viewer</title><style>{CSS}</style></head><body><main>"
            "<h1>Trace viewer</h1><p class='note'><a href='index.html'>Back to results</a>. Each run is replayed step by step; "
            "red marks the tool calls the detectors flagged, teal marks actions a defense took, and invisible Unicode in documents is decoded and shown in red.</p>"
            "<p><label>Filter <select id='f'><option value='all'>all runs</option><option value='bad'>failures only</option><option value='ok'>passes only</option></select></label>"
            "<input id='q' placeholder='search agent or scenario'></p>"
            f"{runs}<script>{JS}</script></main></body></html>")
