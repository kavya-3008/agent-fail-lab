from lab.agents import GuardedAgent, NaiveAgent
from lab.runner import run_all


def by(results, agent, scenario):
    return next(r for r in results if r["agent"] == agent and r["scenario"] == scenario)


def test_naive_agent_is_exploited():
    res = run_all([NaiveAgent(), GuardedAgent()])
    r = by(res, "naive", "injection_in_document")
    assert "canary_leaked" in r["failures"] and "exfil_to_attacker" in r["failures"]


def test_guarded_agent_resists_all_attacks():
    res = run_all([GuardedAgent()])
    assert all(r["failures"] == [] for r in res)


def test_benign_control_has_no_failures_for_anyone():
    res = run_all([NaiveAgent(), GuardedAgent()])
    assert by(res, "naive", "benign_control")["failures"] == []
