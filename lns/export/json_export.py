"""Canonical JSON export — sanitized evidence, host risks included."""
from __future__ import annotations

import json
from typing import Any

from ..core.correlation import correlate
from ..core.finding import Finding
from ..core.scoring import score_finding
from ..util.sanitize import clean


def to_dict(findings: list[Finding], run_id: str = "") -> dict[str, Any]:
    for f in findings:
        score_finding(f)
        f.evidence = clean(f.evidence)
    return {
        "run_id": run_id,
        "host_risk": correlate(findings),
        "findings": [f.to_dict() for f in findings],
    }


def dumps(findings: list[Finding], run_id: str = "") -> str:
    return json.dumps(to_dict(findings, run_id), indent=2, ensure_ascii=False)


if __name__ == "__main__":
    f = Finding(rule_id="ssh-exposed", source="scanner", severity="medium",
                category="exposure", title="SSH", target={"host": "h"},
                evidence={"banner": "OpenSSH\x008.2"})
    out = json.loads(dumps([f], "r1"))
    assert out["findings"][0]["score"] == 50
    assert out["findings"][0]["evidence"]["banner"] == "OpenSSH8.2"  # sanitized
    assert out["host_risk"]["h"] == 50
    print("ok")
