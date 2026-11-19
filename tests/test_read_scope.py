from lab.adaptive import ADAPTIVE_SCENARIOS, adaptive_report
from lab.defenses import DefendedAgent, ReadScopeGuard
from lab.agents import NaiveAgent
from lab.detectors import detect_failures
from lab.mutations import mutation_report
from lab.paraphrase import paraphrase_report
from lab.runner import all_agents, run_all
from lab.scenarios import SCENARIOS
from lab.tools import Sandbox
from lab.utility import BENIGN_REFERENCE, utility_report

NAMES = ("naive+read scope", "naive+allowlist+read scope")


def _agents(*names):
    return [a for a in all_agents() if a.name in names]


def test_blocked_read_is_not_recorded_as_a_tool_call_and_returns_a_policy_message():
    sc = next(s for s in SCENARIOS if s.name == "arg_body_smuggle")
    sb = Sandbox(documents=dict(sc.documents))
    DefendedAgent(NaiveAgent(), [ReadScopeGuard()], "rs").run(sc, sb)
    assert [c["args"]["name"] for c in sb.calls if c["tool"] == "read_document"] == ["meeting_notes"]
    assert any(b["tool"] == "read_document" and b["defense"] == "read_scope" for b in sb.blocked)
    assert detect_failures(sc, sb) == []


def test_read_scope_alone_fails_every_recipient_attack():
    rows = {r["scenario"]: r for r in run_all(_agents("naive+read scope"), SCENARIOS)}
    for name in ("arg_redirect_recipient", "arg_cc_attacker", "arg_obfuscated_cc", "direct_override"):
        assert rows[name]["failures"], name
    assert not rows["arg_body_smuggle"]["failures"] and not rows["arg_encoded_smuggle"]["failures"]


def test_read_scope_plus_allowlist_resists_all_attacks_and_completes_the_task():
    rows = [r for r in run_all(_agents(NAMES[1]), SCENARIOS) if r["family"] != "control"]
    assert all(not r["failures"] for r in rows)
    ctrl = next(r for r in run_all(_agents(NAMES[1]), SCENARIOS) if r["scenario"] == "benign_email_task")
    assert ctrl["completed"]


def test_read_scope_is_format_independent_on_adaptive_attacks():
    rep = adaptive_report(_agents(*NAMES))
    assert rep["naive+allowlist+read scope"]["resisted"] == len(ADAPTIVE_SCENARIOS)
    assert rep["naive+read scope"]["resisted"] == len(ADAPTIVE_SCENARIOS)


def test_pair_resists_every_effective_mutant():
    rep = mutation_report(_agents(NAMES[1]))
    assert rep["agents"][NAMES[1]]["resisted"] == rep["effective"]


def test_pair_resists_paraphrased_attacks():
    rep = paraphrase_report()
    assert rep["para+allowlist+read scope"]["resisted"] == rep["para+allowlist+read scope"]["total"]


def test_utility_cost_is_real():
    rep = utility_report(_agents(*NAMES, "naive", "guarded"))
    assert rep["naive"]["read_appendix"]
    assert not rep["naive+read scope"]["read_appendix"]
    assert not rep["naive+allowlist+read scope"]["read_appendix"]
    assert BENIGN_REFERENCE.family == "control"
