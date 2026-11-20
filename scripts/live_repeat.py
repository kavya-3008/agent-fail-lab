"""Repeat live Gemini runs and append each to results/live_runs.jsonl (resumable, spend-capped).
Usage: PYTHONPATH=. python3 scripts/live_repeat.py --runs 10 [--scenarios a,b] [--budget 2.00]
Skips (scenario, run index) pairs already recorded, so you can run it again on later days to top up.
Cost is estimated from reported token usage at Flash rates (edit RATES if pricing changed)."""
import argparse
import json
from pathlib import Path

from lab.detectors import detect_failures
from lab.gemini_agent import GeminiAgent
from lab.runner import task_completed
from lab.scenarios import SCENARIOS
from lab.tools import Sandbox

RATES = {"input": 0.30 / 1e6, "output": 2.50 / 1e6}  # USD per token, gemini-2.5-flash (verify against current pricing)
OUT = Path("results/live_runs.jsonl")

ap = argparse.ArgumentParser()
ap.add_argument("--runs", type=int, default=10, help="target runs per scenario")
ap.add_argument("--scenarios", default="", help="comma-separated names (default all)")
ap.add_argument("--budget", type=float, default=2.0, help="stop when this session's estimated spend hits this many USD")
ap.add_argument("--max-new", type=int, default=10**9, help="stop after this many new runs this session")
args = ap.parse_args()

done = {}
if OUT.exists():
    for line in OUT.read_text().splitlines():
        r = json.loads(line)
        done.setdefault(r["scenario"], set()).add(r["run"])
names = set(filter(None, args.scenarios.split(",")))
scs = [s for s in SCENARIOS if not names or s.name in names]

agent = GeminiAgent()
agent.max_calls = 10**6  # spend is governed by --budget / --max-new here
OUT.parent.mkdir(exist_ok=True)
spent = new = 0
for i in range(args.runs):  # round-robin so partial sessions stay balanced across scenarios
    for sc in scs:
        if i in done.get(sc.name, set()):
            continue
        if spent >= args.budget or new >= args.max_new:
            print(f"stopping: new={new} est_spend=${spent:.3f}")
            raise SystemExit
        sb = Sandbox(documents=dict(sc.documents))
        try:
            out = agent.run(sc, sb)
            err = None
        except Exception as e:  # keep going; record the error so it is not silently lost
            out, err = "", f"{type(e).__name__}: {e}"[:300]
        u = agent.last_usage if not err else {"input": 0, "output": 0}
        cost = u["input"] * RATES["input"] + u["output"] * RATES["output"]
        spent += cost
        new += 1
        rec = {"model": agent.model, "scenario": sc.name, "family": sc.family, "run": i,
               "failures": detect_failures(sc, sb), "completed": task_completed(sc, sb),
               "tools": [c["tool"] for c in sb.calls], "tool_calls": sb.calls, "output": out[:600],
               "tokens": u, "est_cost_usd": round(cost, 5), "error": err}
        with OUT.open("a") as f:
            f.write(json.dumps(rec) + "\n")
        print(f"{sc.name:<26} run {i:<2} {', '.join(rec['failures']) or 'ok':<40} tools={rec['tools']} ${cost:.4f}" + (f" ERROR {err}" if err else ""))
print(f"done: new={new} est_spend=${spent:.3f}")
