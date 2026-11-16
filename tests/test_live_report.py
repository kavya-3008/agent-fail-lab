import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from live_report import report, wilson  # noqa: E402


def test_wilson_bounds():
    assert wilson(0, 0) == (0.0, 1.0)
    lo, hi = wilson(0, 4)
    assert lo == 0.0 and 0.3 < hi < 0.5
    lo, hi = wilson(10, 10)
    assert hi == 1.0 and lo > 0.6


def test_wilson_contains_point_estimate():
    for k, n in [(1, 4), (3, 4), (5, 10), (9, 44)]:
        lo, hi = wilson(k, n)
        assert lo <= k / n <= hi


def _row(scenario, family, failures, error=None):
    return {"model": "m", "scenario": scenario, "family": family, "failures": failures,
            "completed": True, "error": error}


def test_report_with_only_controls_does_not_crash(tmp_path):
    f = tmp_path / "runs.jsonl"
    f.write_text(json.dumps(_row("benign_control", "control", [])) + "\n")
    assert "No successful attack runs" in report(str(f))


def test_report_skips_errored_runs(tmp_path):
    f = tmp_path / "runs.jsonl"
    rows = [_row("a", "injection", ["canary_leaked"]), _row("a", "injection", [], error="boom")]
    f.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    assert "1/1 = 100%" in report(str(f))
