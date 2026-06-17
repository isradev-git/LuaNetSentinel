"""Alert dispatcher: severity threshold + anti-spam (dedup + digest)."""
from __future__ import annotations

from typing import Callable

from ..core.finding import SEVERITIES, Finding
from . import email_smtp, telegram


def _rank(sev: str) -> int:
    return SEVERITIES.index(sev)


def default_channels() -> list[Callable[[str], bool]]:
    """Only channels with secrets configured in the environment."""
    chans: list[Callable[[str], bool]] = []
    if telegram.configured():
        chans.append(telegram.send)
    if email_smtp.configured():
        chans.append(email_smtp.send)
    return chans


def digest(findings: list[Finding]) -> str:
    """One message for the whole batch — anti-spam, not one msg per finding."""
    lines = [f"🛡️ LuaNetSentinel: {len(findings)} hallazgo(s) sobre umbral", ""]
    for f in sorted(findings, key=lambda x: -_rank(x.severity)):
        lines.append(f"[{f.severity.upper()}] {f.title} — {f.host or '?'} "
                     f"(score {f.score}, regla {f.rule_id})")
    return "\n".join(lines)


class Notifier:
    def __init__(self, min_severity: str = "high",
                 channels: list[Callable[[str], bool]] | None = None):
        self.min = _rank(min_severity)
        self.channels = default_channels() if channels is None else channels
        self._sent: set[str] = set()  # content keys already alerted (dedup)

    def select(self, findings: list[Finding]) -> list[Finding]:
        return [f for f in findings
                if _rank(f.severity) >= self.min and f.key not in self._sent]

    def notify(self, findings: list[Finding]) -> int:
        """Send a single digest of new, above-threshold findings. Returns count."""
        new = self.select(findings)
        if not new:
            return 0
        text = digest(new)
        for send in self.channels:
            try:
                send(text)
            except Exception:  # a dead channel must not crash the watch loop
                pass
        self._sent.update(f.key for f in new)
        return len(new)


if __name__ == "__main__":
    rec: list[str] = []
    n = Notifier(min_severity="high", channels=[rec.append])

    def mk(sev, rid):
        return Finding(rule_id=rid, source="scanner", severity=sev,
                       category="c", title=f"{rid}", score=0,
                       target={"host": "h"})

    batch = [mk("low", "a"), mk("high", "b"), mk("critical", "c")]
    assert n.notify(batch) == 2          # low filtered out
    assert len(rec) == 1                 # one digest, not two messages
    assert "[CRITICAL]" in rec[0]
    assert n.notify(batch) == 0          # dedup: same findings don't re-alert
    print("ok")
