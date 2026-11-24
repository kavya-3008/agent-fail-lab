"""Defense-stack scorecard: every combination of up to three defenses, scored on every suite at once.

Each README table scores a hand-picked list of agents on one suite. This module asks the question the tables cannot:
across *all* suites (the 11 attacks, the effective mutants, the adaptive and the reworded attacks) and the benign
tasks, which stacks of defenses are worth using, and which are strictly worse than another stack?

Security = share of attack runs resisted, pooled over the four attack suites. Utility = share of benign tasks served.
A stack is on the Pareto front when no other stack is at least as good on both and better on one.
Run: python3 -m lab.scorecard
"""
from __future__ import annotations

import itertools

from .adaptive import ADAPTIVE_SCENARIOS
from .agents import NaiveAgent
from .benign import BENIGN_CASES, served
from .defenses import (AddresseeQuarantine, DefendedAgent, EgressProvenanceGuard, InputQuarantine, InputQuarantineV2,
                       NormalizingEgressGuard, OutputDLP, ReadScopeGuard, RecipientAllowlist)
from .detectors import detect_failures
from .mutations import mutants
from .paraphrase import PARAPHRASE_SCENARIOS, ParaphraseNaiveAgent
from .scenarios import SCENARIOS
from .tools import Sandbox

DEFENSES = {
    "allowlist": RecipientAllowlist, "dlp": OutputDLP, "q1": InputQuarantine, "q2": InputQuarantineV2,
    "q3": AddresseeQuarantine, "egress": EgressProvenanceGuard, "egress2": NormalizingEgressGuard,
    "read_scope": ReadScopeGuard,
}
SUITES = ("attacks", "mutants", "adaptive", "reworded")


def stacks(max_size: int = 3) -> list[tuple[str, ...]]:
    """The empty stack (plain naive agent) plus every combination of up to max_size defenses."""
    out: list[tuple[str, ...]] = [()]
    for n in range(1, max_size + 1):
        out += list(itertools.combinations(DEFENSES, n))
    return out


def _agent(inner, stack: tuple[str, ...]):
    return DefendedAgent(inner, [DEFENSES[n]() for n in stack], "+".join(stack) or "naive")


def _fails(agent, sc) -> bool:
    sb = Sandbox(documents=dict(sc.documents))
    agent.run(sc, sb)
    return bool(detect_failures(sc, sb))


def _effective_mutants():
    naive = NaiveAgent()
    return [m for m in mutants(SCENARIOS) if _fails(naive, m)]


def score_stack(stack: tuple[str, ...], effective=None) -> dict:
    effective = _effective_mutants() if effective is None else effective
    attacks = [s for s in SCENARIOS if s.family != "control"]
    suites = {"attacks": attacks, "mutants": effective, "adaptive": ADAPTIVE_SCENARIOS, "reworded": PARAPHRASE_SCENARIOS}
    row = {"stack": "+".join(stack) or "naive", "size": len(stack), "suites": {}}
    for suite, scenarios in suites.items():
        inner = ParaphraseNaiveAgent() if suite == "reworded" else NaiveAgent()
        agent = _agent(inner, stack)
        row["suites"][suite] = [len(scenarios) - sum(_fails(agent, sc) for sc in scenarios), len(scenarios)]
    agent = _agent(NaiveAgent(), stack)
    ok = 0
    for sc, markers, _ in BENIGN_CASES:
        sb = Sandbox(documents=dict(sc.documents))
        ok += served(sc, markers, sb, agent.run(sc, sb))
    row["benign"] = [ok, len(BENIGN_CASES)]
    held = sum(v[0] for v in row["suites"].values())
    total = sum(v[1] for v in row["suites"].values())
    row["security"] = held / total
    row["utility"] = ok / len(BENIGN_CASES)
    return row


def pareto_front(rows: list[dict]) -> list[dict]:
    def dominated(r):
        return any(o["security"] >= r["security"] and o["utility"] >= r["utility"]
                   and (o["security"] > r["security"] or o["utility"] > r["utility"]) for o in rows)
    return [r for r in rows if not dominated(r)]


def scorecard(max_size: int = 3) -> dict:
    effective = _effective_mutants()
    rows = [score_stack(s, effective) for s in stacks(max_size)]
    front = {r["stack"] for r in pareto_front(rows)}
    for r in rows:
        r["pareto"] = r["stack"] in front
    rows.sort(key=lambda r: (-r["security"], -r["utility"], r["size"]))
    return {"effective_mutants": len(effective), "rows": rows}


def main() -> None:
    card = scorecard()
    print(f"{'stack':<34}{'sec':>6}{'util':>6}  " + "  ".join(f"{s:>9}" for s in SUITES) + "  benign")
    for r in card["rows"]:
        suites = "  ".join(f"{r['suites'][s][0]:>4}/{r['suites'][s][1]:<4}" for s in SUITES)
        print(f"{r['stack']:<34}{r['security']:>6.1%}{r['utility']:>6.0%}  {suites}  {r['benign'][0]}/{r['benign'][1]}"
              f"{'  *pareto' if r['pareto'] else ''}")


if __name__ == "__main__":
    main()
