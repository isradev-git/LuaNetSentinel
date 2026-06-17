"""Multi-source correlation: a host seen by 2+ collectors is more dangerous."""
from __future__ import annotations

from collections import defaultdict

from .finding import Finding
from .scoring import host_risks

BOOST = 15


def correlate(findings: list[Finding]) -> dict[str, int]:
    """Per-host risk with +15 boost when a host appears in 2+ sources."""
    risks = host_risks(findings)
    sources: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        sources[f.host or "?"].add(f.source)
    return {
        host: min(100, risk + (BOOST if len(sources[host]) >= 2 else 0))
        for host, risk in risks.items()
    }


if __name__ == "__main__":
    def mk(host, source, sev="medium"):
        return Finding(rule_id="r", source=source, severity=sev,
                       category="c", title="t", target={"host": host})

    single = [mk("a", "scanner")]
    assert correlate(single)["a"] == 50  # no boost

    multi = [mk("b", "scanner"), mk("b", "traffic")]
    # risk = 50 + 0.25*50 = 62, +15 boost = 77
    assert correlate(multi)["b"] == 77
    print("ok")
