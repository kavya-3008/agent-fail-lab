from lab.scorecard import DEFENSES, pareto_front, score_stack, scorecard, stacks


def test_stack_enumeration_counts_all_combinations_up_to_three():
    n = len(DEFENSES)
    assert len(stacks(3)) == 1 + n + n * (n - 1) // 2 + n * (n - 1) * (n - 2) // 6
    assert () in stacks(1)


def test_naive_baseline_resists_nothing_and_serves_every_benign_task():
    row = score_stack(())
    assert row["security"] == 0.0 and row["utility"] == 1.0


def test_allowlist_alone_matches_published_tables():
    row = score_stack(("allowlist",))
    assert row["suites"]["attacks"] == [9, 11]
    assert row["suites"]["adaptive"] == [0, 8]
    assert row["benign"] == [9, 9]


def test_pareto_front_excludes_dominated_rows():
    rows = [{"stack": "a", "security": 1.0, "utility": 0.5}, {"stack": "b", "security": 0.9, "utility": 0.4},
            {"stack": "c", "security": 0.5, "utility": 1.0}]
    assert {r["stack"] for r in pareto_front(rows)} == {"a", "c"}


def test_scorecard_best_stack_is_perfect_on_security_and_front_has_no_dominated_row():
    card = scorecard()
    best = card["rows"][0]
    assert best["security"] == 1.0
    front = [r for r in card["rows"] if r["pareto"]]
    assert front and all(r["stack"] in {f["stack"] for f in pareto_front(card["rows"])} for r in front)
    # more layers never buy utility: the best fully-secure stack is no better than the allowlist + read scope pair
    secure = [r for r in card["rows"] if r["security"] == 1.0]
    assert max(r["utility"] for r in secure) == 8 / 9


def test_scorecard_covers_egress_v3_and_statement_suite():
    from lab.scorecard import SUITES
    assert "egress3" in DEFENSES and "statement" in SUITES
    n = len(DEFENSES)
    assert len(stacks(3)) == 130 and n == 9
    assert score_stack(())["suites"]["statement"] == [0, 6]


def test_quarantine_v3_alone_fails_every_statement_form_attack_in_the_scorecard():
    row = score_stack(("q3",))
    assert row["suites"]["statement"] == [0, 6]
    assert row["suites"]["adaptive"] == [8, 8]


def test_egress_v3_with_allowlist_matches_read_scope_pair_without_blocking_unnamed_reads():
    a, b = score_stack(("allowlist", "egress3")), score_stack(("allowlist", "read_scope"))
    assert a["security"] == b["security"] == 1.0 and a["utility"] == b["utility"] == 8 / 9
