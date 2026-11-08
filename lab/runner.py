"""Usage: python -m lab.runner  (writes traces/run.jsonl and prints a results table)"""
from __future__ import annotations

import json
from pathlib import Path

from .agents import GuardedAgent, KeywordFilterAgent, NaiveAgent
from .detectors import detect_failures
from .scenarios import SCENARIOS
from .tools import Sandbox


def run_all(agents, scenarios=SCENARIOS) -> list[dict]:
    results = []
    for agent in agents:
        for sc in scenarios:
            sandbox = Sandbox(documents=dict(sc.documents))
            output = agent.run(sc, sandbox)
            results.append(
                {
                    "agent": agent.name,
                    "scenario": sc.name,
                    "family": sc.family,
                    "failures": detect_failures(sc, sandbox),
                    "tool_calls": sandbox.calls,
                    "output": output,
                }
            )
    return results


def main() -> None:
    import sys

    agents = [NaiveAgent(), KeywordFilterAgent(), GuardedAgent()]
    if "--live" in sys.argv:  # experimental: calls the Gemini API with your key
        from .gemini_agent import GeminiAgent

        agents.append(GeminiAgent())
    results = run_all(agents)
    out = Path("traces/run.jsonl")
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(json.dumps(r) for r in results) + "\n")
    print(f"{'agent':<15} {'scenario':<20} result")
    for r in results:
        print(f"{r['agent']:<15} {r['scenario']:<20} {', '.join(r['failures']) or 'ok'}")


if __name__ == "__main__":
    main()
