"""SQLite store — source of truth for runs, findings, baseline."""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from .finding import Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY, ts REAL, scope TEXT, summary TEXT
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, run_id TEXT, rule_id TEXT, source TEXT,
  severity TEXT, score INTEGER, category TEXT, title TEXT,
  description TEXT, target TEXT, evidence TEXT, remediation TEXT, ts REAL
);
CREATE TABLE IF NOT EXISTS baseline (
  host TEXT PRIMARY KEY, ports TEXT, services TEXT, ts REAL
);
CREATE INDEX IF NOT EXISTS ix_findings_run ON findings(run_id);
"""


class Store:
    def __init__(self, path: str | Path = "lns.db"):
        self.db = sqlite3.connect(str(path))
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def new_run(self, scope: str = "", summary: str = "") -> str:
        run_id = time.strftime("run_%Y%m%d_%H%M%S")
        self.db.execute("INSERT OR REPLACE INTO runs VALUES (?,?,?,?)",
                        (run_id, time.time(), scope, summary))
        self.db.commit()
        return run_id

    def save(self, findings: list[Finding]) -> None:
        self.db.executemany(
            "INSERT OR REPLACE INTO findings VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [(f.id, f.run_id, f.rule_id, f.source, f.severity, f.score,
              f.category, f.title, f.description, json.dumps(f.target),
              json.dumps(f.evidence), f.remediation, f.ts) for f in findings])
        self.db.commit()

    def findings(self, run_id: str) -> list[dict]:
        rows = self.db.execute(
            "SELECT * FROM findings WHERE run_id=? ORDER BY score DESC",
            (run_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["target"] = json.loads(d["target"])
            d["evidence"] = json.loads(d["evidence"])
            out.append(d)
        return out

    def latest_run(self) -> str | None:
        row = self.db.execute(
            "SELECT run_id FROM runs ORDER BY ts DESC LIMIT 1").fetchone()
        return row["run_id"] if row else None

    # --- baseline ---
    def set_baseline(self, host: str, ports: list[int],
                     services: dict | None = None) -> None:
        self.db.execute("INSERT OR REPLACE INTO baseline VALUES (?,?,?,?)",
                        (host, json.dumps(sorted(ports)),
                         json.dumps(services or {}), time.time()))
        self.db.commit()

    def get_baseline(self, host: str) -> dict | None:
        row = self.db.execute("SELECT * FROM baseline WHERE host=?",
                              (host,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["ports"] = json.loads(d["ports"])
        d["services"] = json.loads(d["services"])
        return d

    def all_baseline(self) -> list[dict]:
        return [self.get_baseline(r["host"])
                for r in self.db.execute("SELECT host FROM baseline").fetchall()]

    def close(self) -> None:
        self.db.close()


if __name__ == "__main__":
    s = Store(":memory:")
    rid = s.new_run(scope="home")
    f = Finding(rule_id="ssh-exposed", source="scanner", severity="medium",
                category="exposure", title="SSH", score=50, run_id=rid,
                target={"host": "h", "port": 22}, evidence={"state": "open"})
    s.save([f])
    got = s.findings(rid)
    assert len(got) == 1
    assert got[0]["target"]["port"] == 22
    assert got[0]["evidence"]["state"] == "open"
    print("ok", rid)
