"""Web log collector — parse combined logs, run attack-signature rules.

Combined Log Format (Nginx/Apache/Caddy default):
  IP - - [ts] "METHOD path PROTO" status size "referer" "user-agent"

Two layers, like the traffic collector:
  - stateless signature rules (rules/weblog/*.py): SQLi, XSS, traversal, scanner UA
  - stateful anomaly analyzer here: per-IP error rate (4xx/5xx)
"""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from urllib.parse import unquote

from ..core import rules
from ..core.finding import Finding

LINE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<ref>[^"]*)" "(?P<ua>[^"]*)"')

# ponytail: fixed threshold, no time window — add windowing if it misses slow scans
ERROR_THRESHOLD = 10


def parse_line(line: str) -> rules.Context | None:
    m = LINE.match(line)
    if not m:
        return None
    return rules.Context(
        proto="http", host=m["ip"], method=m["method"],
        path=unquote(m["path"]),        # decode %27 etc. before matching
        raw_path=m["path"], status=int(m["status"]), ua=m["ua"])


def analyze_lines(lines, run_id: str = "") -> list[Finding]:
    rules.load_rules()
    out: list[Finding] = []
    errors: dict[str, int] = defaultdict(int)
    for line in lines:
        ctx = parse_line(line.rstrip("\n"))
        if ctx is None:
            continue
        out += rules.apply(ctx, "weblog", run_id=run_id)
        if ctx.status >= 400:
            errors[ctx.host] += 1
    out += _error_spikes(errors, run_id)
    return out


def _error_spikes(errors: dict[str, int], run_id: str) -> list[Finding]:
    out = []
    for ip, n in errors.items():
        if n >= ERROR_THRESHOLD:
            out.append(Finding(
                rule_id="error-spike", source="weblog", severity="medium",
                category="suspicious-traffic", title="Pico de errores 4xx/5xx por IP",
                description="Una IP genera muchos errores: posible fuzzing/escaneo.",
                remediation="Revisa la IP; considera rate-limit o bloqueo temporal.",
                target={"host": ip, "proto": "http"},
                evidence={"errors": n}, run_id=run_id))
    return out


def analyze(path: str, run_id: str = "") -> list[Finding]:
    return analyze_lines(Path(path).read_text().splitlines(), run_id=run_id)


if __name__ == "__main__":
    lines = [
        '1.2.3.4 - - [17/Jun/2026:10:00:00 +0000] '
        '"GET /p?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 200 10 "-" "Mozilla"',
        '5.6.7.8 - - [17/Jun/2026:10:00:01 +0000] '
        '"GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 10 "-" "curl"',
        '9.9.9.9 - - [17/Jun/2026:10:00:02 +0000] '
        '"GET /../../etc/passwd HTTP/1.1" 404 10 "-" "sqlmap/1.7"',
    ]
    fs = analyze_lines(lines)
    ids = {f.rule_id for f in fs}
    print("fired:", ids)
    assert "sqli" in ids and "xss" in ids and "path-traversal" in ids
    assert "scanner-ua" in ids
    print("ok")
