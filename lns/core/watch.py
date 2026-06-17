"""Watch loop — periodic collect → store → alert on new findings.

Collector-agnostic: takes a `collect(run_id) -> list[Finding]` callable so the
loop logic (dedup across cycles, alerting, cadence) is testable without nmap.
"""
from __future__ import annotations

import time
from typing import Callable

from ..alerting.notify import Notifier
from .finding import Finding
from .store import Store


def watch(collect: Callable[[str], list[Finding]], store: Store,
          notifier: Notifier, interval: float = 60.0,
          cycles: int | None = None, scope: str = "",
          on_cycle: Callable[[dict], None] | None = None,
          sleep: Callable[[float], None] = time.sleep) -> None:
    seen: set[str] = set()
    n = 0
    while cycles is None or n < cycles:
        run_id = store.new_run(scope=scope)
        findings = collect(run_id)
        store.save(findings)
        fresh = [f for f in findings if f.key not in seen]
        seen.update(f.key for f in findings)
        alerted = notifier.notify(fresh)
        if on_cycle:
            on_cycle({"run_id": run_id, "cycle": n, "total": len(findings),
                      "new": len(fresh), "alerted": alerted})
        n += 1
        if cycles is not None and n >= cycles:
            break
        sleep(interval)


if __name__ == "__main__":
    from ..alerting.notify import Notifier as N

    store = Store(":memory:")
    rec: list[str] = []
    notifier = N(min_severity="high", channels=[rec.append])

    calls = {"n": 0}

    def collect(run_id):
        calls["n"] += 1
        # same logical finding every cycle, but default ts -> DIFFERENT id each
        # time. Dedup must hold via content key, proving anti-spam survives rescans.
        return [Finding(rule_id="ssh-exposed", source="scanner", severity="high",
                        category="exposure", title="SSH", score=75, run_id=run_id,
                        target={"host": "h", "port": 22})]

    events: list[dict] = []
    watch(collect, store, notifier, interval=0, cycles=3,
          on_cycle=events.append, sleep=lambda _: None)
    assert calls["n"] == 3
    assert events[0]["new"] == 1 and events[0]["alerted"] == 1
    assert events[1]["new"] == 0 and events[1]["alerted"] == 0  # dedup
    assert len(rec) == 1  # alerted exactly once across 3 cycles
    print("ok", events)
