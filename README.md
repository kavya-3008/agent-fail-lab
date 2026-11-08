# Agent Fail Lab

A tiny red-team harness for tool-using AI agents. It plants hidden instructions in the data an agent processes
(prompt injection), runs the agent in a sandbox, and records whether it was tricked into doing something the user never asked for.

Inspired by research on stress-testing multimodal agents before deployment: find how and when they fail *before* they ship.

## Quickstart

```bash
python3 -m pip install -r requirements.txt
python3 -m lab.runner
python3 -m pytest
```

## Findings so far

| Agent | Attacks resisted (of 5) |
|---|---|
| naive | 0 |
| keyword filter ("ignore previous instructions") | 1 |
| guarded (data is never instructions, tool allowlist) | 5 |

Filtering for known attack phrases is easy to bypass: politeness, a fake authority message, invisible Unicode characters or a second document each slip past it. Structural defenses hold.

## How it works (v0.1)

- **Sandbox** (`lab/tools.py`): fake `read_document` and `send_email` tools. Nothing touches the network, every call is recorded.
- **Scenarios** (`lab/scenarios.py`): a user task plus documents with a hidden attack and a canary secret.
- **Detectors** (`lab/detectors.py`): flag unauthorized tool use, exfiltration to the attacker address, and canary leaks.
- **Agents** (`lab/agents.py`): a deliberately naive agent and a guarded one, both scripted so results are deterministic.
- **Runner** (`lab/runner.py`): runs every agent against every scenario and writes JSONL traces.

The naive agent gets exploited and the guarded one does not. That is the point: the harness can tell them apart.

## Roadmap

- [x] Sandbox, scenarios, detectors, scripted agents, runner
- [x] Experimental Gemini function-calling agent (`python3 -m lab.runner --live`), not yet validated
- [x] Attack families: direct override, polite request, authority spoofing, invisible Unicode, multi-hop injection
- [ ] Tool-argument manipulation and conflicting-instruction attacks
- [ ] Defense experiments: instruction hierarchy prompts, input quarantining, tool-call allowlists
- [ ] Trace viewer (HTML) to replay where an agent went wrong
- [ ] Failure-rate report across models with confidence intervals
- [ ] Scenario generator that mutates attacks automatically

## Config

Copy `.env.example` to `.env` and add `GEMINI_API_KEY` once the Gemini agent lands. The key is never committed.

## Live site

https://kavya-3008.github.io/agent-fail-lab/ (regenerate with `PYTHONPATH=. python3 scripts/build_site.py`)
