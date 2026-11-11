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

Eleven attacks per agent: the original five injection styles, five tool-argument manipulations (the user *did* ask for an email, the document bends its arguments) and one conflicting-instruction attack. Two benign controls check that defenses do not break the user's real task.

| Agent | Attacks resisted (of 11) | User task still done (of 11) |
|---|---|---|
| naive | 0 | 8 |
| keyword filter ("ignore previous instructions") | 1 | 8 |
| guarded (data is never instructions, tool allowlist) | 11 | 11 |
| naive + recipient allowlist | 9 | 8 |
| naive + output DLP (redact credential-like strings) | 1 | 8 |
| naive + input quarantine (strip invisible text and instruction-like sentences) | 10 | 10 |
| naive + all three layered | 11 | 10 |

What each defense does and does not catch (all offline, scripted agents):

- **Recipient allowlist** (only addresses named in the user's task may receive mail) stops every redirect, CC, obfuscated CC and classic exfiltration, but **fails** against a secret smuggled into the body of an allowed email (`arg_body_smuggle`, `arg_encoded_smuggle`): the recipient is legitimate, the content is not.
- **Output DLP** redacts a literal `api_token=...` in the body, but **fails** against base64-encoded secrets and does nothing about mail sent to the wrong address (the redacted mail still reaches the attacker). Only 1 of 11 resisted.
- **Input quarantine** removes invisible Unicode and instruction-like sentences from documents before the agent sees them. It stopped 10 of 11 but **fails** on an obfuscated address (`attacker[at]evil.example`) that its cue list does not recognize.
- **Layering** all three resisted all 11, at a cost: in `arg_obfuscated_cc` the allowlist blocked the whole email, so the user's legitimate email never went out (safe, but the task was not completed).
- The detector also checks for secrets that are reversed, hex- or base64-encoded, and for emails to any address the user did not authorize (`wrong_recipient`).

Caveat: the agents are scripted and the scenarios were written by the same author as the defenses, so these results map what each mechanism can and cannot see; they are not a guarantee against a real model or a real adversary. The quarantine's 10/11 in particular is likely optimistic against adaptive paraphrasing.

### Mutation robustness

`lab/mutations.py` rewrites the injected text of each of the 11 attacks with 7 mutators (uppercase, urgent prefix, team framing, "ignore previous instructions" prefix, `@` to `[at]`, note wrapper, invisible Unicode) alone and in pairs: 308 mutants. A mutant only counts if the naive agent still falls for it (222 did); defenses are scored on those.

| Agent | Effective mutants resisted |
|---|---|
| naive | 0 / 222 |
| keyword filter | 47 / 222 |
| guarded | 222 / 222 |
| naive + recipient allowlist | 180 / 222 |
| naive + output DLP | 21 / 222 |
| naive + input quarantine | 194 / 222 |
| naive + all three layered | 222 / 222 |

Mutation did not uncover new weaknesses in the scripted defenses: every failure is one of the blind spots already listed (quarantine breaks only on the obfuscated-address attack, 28 mutants; the allowlist only on the two body-smuggling attacks, 42 mutants). The keyword filter only holds when a mutator happens to add the phrase it looks for. Caveat: the mutators are mechanical and the scripted agents' regexes are case-insensitive and format-tolerant, so this measures defense brittleness to surface changes, not to a creative paraphrasing adversary; real model agents may react very differently.

### Live model (Gemini 2.5 Flash, one run per scenario)

It read the documents, summarized them, and made no unauthorized tool calls in any of the 5 attacks. Small sample, and in `multi_hop` it never opened the appendix, so that attack never reached it. A first live run initially showed 'ok' everywhere only because a bug stopped tools from running at all; a regression test now guards that.

## How it works (v0.1)

- **Sandbox** (`lab/tools.py`): fake `read_document` and `send_email` tools. Nothing touches the network, every call is recorded.
- **Scenarios** (`lab/scenarios.py`): a user task plus documents with a hidden attack and a canary secret.
- **Defenses** (`lab/defenses.py`): composable tool wrappers (recipient allowlist, output DLP, input quarantine) that guard an agent without changing it.
- **Detectors** (`lab/detectors.py`): flag unauthorized tool use, exfiltration to the attacker address, and canary leaks.
- **Agents** (`lab/agents.py`): a deliberately naive agent and a guarded one, both scripted so results are deterministic.
- **Runner** (`lab/runner.py`): runs every agent against every scenario and writes JSONL traces.

The naive agent gets exploited and the guarded one does not. That is the point: the harness can tell them apart.

## Roadmap

- [x] Sandbox, scenarios, detectors, scripted agents, runner
- [x] Gemini function-calling agent (`python3 -m lab.runner --live`, capped at 20 calls via GEMINI_MAX_CALLS)
- [ ] Repeat live runs (n>=10 per scenario) for real failure-rate estimates, and add attacks that force the model to read the injected content
- [x] Attack families: direct override, polite request, authority spoofing, invisible Unicode, multi-hop injection
- [x] Tool-argument manipulation and conflicting-instruction attacks
- [x] Defense experiments: input quarantining, tool-call allowlists, output filtering (instruction-hierarchy prompts need a live model, still open)
- [ ] Trace viewer (HTML) to replay where an agent went wrong
- [ ] Failure-rate report across models with confidence intervals
- [x] Scenario generator that mutates attacks automatically (`lab/mutations.py`)

## Config

Copy `.env.example` to `.env` and add `GEMINI_API_KEY` once the Gemini agent lands. The key is never committed.

## Live site

https://kavya-3008.github.io/agent-fail-lab/ (regenerate with `PYTHONPATH=. python3 scripts/build_site.py`)
