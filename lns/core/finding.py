"""Finding: the shared contract spoken by all three collectors."""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, asdict
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class Finding:
    rule_id: str
    source: str  # scanner | traffic | weblog
    severity: str  # info | low | medium | high | critical
    category: str
    title: str
    target: dict[str, Any] = field(default_factory=dict)  # {host, port, proto}
    evidence: dict[str, Any] = field(default_factory=dict)
    description: str = ""
    remediation: str = ""
    score: int = 0
    run_id: str = ""
    ts: float = field(default_factory=time.time)
    id: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity {self.severity!r}")
        if not self.id:
            self.id = self._gen_id()

    def _gen_id(self) -> str:
        # ponytail: stable id from rule+target+ts, enough to dedupe a run
        raw = f"{self.rule_id}|{self.target}|{self.ts}"
        return "f_" + hashlib.sha1(raw.encode()).hexdigest()[:8]

    @property
    def host(self) -> str | None:
        return self.target.get("host")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


if __name__ == "__main__":
    f = Finding(rule_id="ssh-exposed", source="scanner", severity="medium",
                category="exposure", title="SSH expuesto",
                target={"host": "192.168.1.10", "port": 22, "proto": "tcp"})
    assert f.id.startswith("f_")
    assert f.host == "192.168.1.10"
    try:
        Finding(rule_id="x", source="scanner", severity="boom",
                category="c", title="t")
        assert False, "bad severity should raise"
    except ValueError:
        pass
    print("ok", f.to_dict())
