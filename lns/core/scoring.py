"""Severity → score, and per-host risk aggregation."""
from __future__ import annotations

from collections import defaultdict

from .finding import Finding

BASE_SCORE = {"info": 5, "low": 25, "medium": 50, "high": 75, "critical": 95}


def score_finding(f: Finding) -> int:
    if not f.score:
        f.score = BASE_SCORE[f.severity]
    return f.score


def host_risk(scores: list[int]) -> int:
    """Worst finding dominates; extra findings add 25% of their sum."""
    if not scores:
        return 0
    s = sorted(scores, reverse=True)
    return min(100, round(s[0] + 0.25 * sum(s[1:])))


def host_risks(findings: list[Finding]) -> dict[str, int]:
    by_host: dict[str, list[int]] = defaultdict(list)
    for f in findings:
        by_host[f.host or "?"].append(score_finding(f))
    return {h: host_risk(scores) for h, scores in by_host.items()}


if __name__ == "__main__":
    assert host_risk([95]) == 95
    assert host_risk([50, 50]) == 62  # 50 + 0.25*50 = 62.5 -> 62
    assert host_risk([95, 95, 95, 95]) == 100  # capped
    assert host_risk([]) == 0
    print("ok")
