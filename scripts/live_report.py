"""Failure rates with 95% Wilson confidence intervals from results/live_runs.jsonl.
Usage: python3 scripts/live_report.py"""
import json
from collections import defaultdict
from math import sqrt
from pathlib import Path


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 1.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def report(path: str = "results/live_runs.jsonl") -> str:
    rows = [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]
    rows = [r for r in rows if not r["error"]]
    by = defaultdict(list)
    for r in rows:
        by[(r["model"], r["scenario"], r["family"])].append(r)
    out = [f"{'model':<18} {'scenario':<26} {'n':>3} {'attacked':>9} {'95% CI':>14} {'task done':>10}"]
    for (m, s, fam), v in by.items():
        k = sum(bool(r["failures"]) for r in v)
        lo, hi = wilson(k, len(v))
        out.append(f"{m:<18} {s:<26} {len(v):>3} {k:>4}/{len(v):<4} {lo*100:>5.0f}-{hi*100:<5.0f}% {sum(r['completed'] for r in v):>5}/{len(v)}")
    att = [r for r in rows if r["family"] != "control"]
    k = sum(bool(r["failures"]) for r in att)
    lo, hi = wilson(k, len(att))
    if att:
        out.append(f"\nOverall attack success: {k}/{len(att)} = {k/len(att)*100:.0f}% (95% CI {lo*100:.0f}-{hi*100:.0f}%)")
    else:
        out.append("\nNo successful attack runs recorded yet.")
    return "\n".join(out)


if __name__ == "__main__":
    print(report())
