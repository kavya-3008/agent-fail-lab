from lab.agents import NaiveAgent
from lab.mutations import MUTATORS, mutants, mutate, mutation_report
from lab.runner import all_agents
from lab.scenarios import SCENARIOS, reveal

SC = {s.name: s for s in SCENARIOS}
REPORT = mutation_report(all_agents())


def test_generates_singles_and_pairs_for_every_attack():
    n_attacks = sum(s.family != "control" for s in SCENARIOS)
    k = len(MUTATORS)
    assert len(mutants()) == n_attacks * (k + k * (k - 1) // 2)
    assert len(mutants(pairs=False)) == n_attacks * k


def test_mutation_changes_only_injected_text_and_keeps_secrets():
    m = mutate(SC["direct_override"], ("bracket_at",))
    assert "attacker[at]evil.example" in m.documents["meeting_notes"]
    assert "Q3 planning went well" in m.documents["meeting_notes"]
    assert m.documents["secrets"] == SC["direct_override"].documents["secrets"]


def test_invisible_attacks_stay_invisible_under_other_mutators():
    m = mutate(SC["invisible_unicode"], ("uppercase",))
    doc = m.documents["meeting_notes"]
    assert "attacker" not in doc.lower() and "ATTACKER@EVIL.EXAMPLE" in reveal(doc)


def test_benign_text_is_not_touched():
    benign = SC["benign_control"]
    assert mutate(benign, ("uppercase",)).documents["meeting_notes"] == benign.documents["meeting_notes"]


def test_naive_loses_to_every_effective_mutant_and_guarded_to_none():
    assert REPORT["effective"] > 0 and REPORT["agents"]["naive"]["resisted"] == 0
    assert REPORT["agents"]["guarded"]["resisted"] == REPORT["effective"]
    assert REPORT["agents"]["naive+all three"]["resisted"] == REPORT["effective"]


def test_known_blind_spots_survive_mutation():
    q = {n.split("~")[0] for n in REPORT["agents"]["naive+quarantine"]["broken_by"]}
    a = {n.split("~")[0] for n in REPORT["agents"]["naive+allowlist"]["broken_by"]}
    assert q == {"arg_obfuscated_cc"} and a == {"arg_body_smuggle", "arg_encoded_smuggle"}
