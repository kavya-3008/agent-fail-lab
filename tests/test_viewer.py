from lab.runner import all_agents, run_all
from lab.scenarios import SCENARIOS
from lab.viewer import first_bad_step, render_run, render_trace_page

ALL = run_all(all_agents())


def get(agent, scenario):
    return next(r for r in ALL if r["agent"] == agent and r["scenario"] == scenario)


def sc(name):
    return next(s for s in SCENARIOS if s.name == name)


def test_first_bad_step_points_at_the_exfil_call_not_the_read():
    r = get("naive", "direct_override")
    assert first_bad_step(sc("direct_override"), r["tool_calls"]) == 2
    assert "first deviation" in render_run(r)


def test_clean_run_has_no_flagged_step():
    r = get("guarded", "direct_override")
    assert first_bad_step(sc("direct_override"), r["tool_calls"]) is None
    assert "first deviation" not in render_run(r)


def test_hidden_unicode_is_decoded_visibly():
    html = render_run(get("naive", "invisible_unicode"))
    assert "[hidden: " in html and "attacker@evil.example" in html


def test_defense_actions_are_shown_and_page_covers_every_run():
    page = render_trace_page(ALL)
    assert page.count("<details") == len(ALL)
    assert "defense: " in page


def test_html_is_escaped():
    r = dict(get("naive", "benign_control"))
    r["agent"] = "<script>x</script>"
    assert "<script>x</script>" not in render_run(r)
