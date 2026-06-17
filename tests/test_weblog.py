from pathlib import Path

from lns.collectors import weblog

FIXTURE = Path(__file__).parent / "fixtures" / "access.log"


def test_signatures_fire_on_fixture():
    fs = weblog.analyze(str(FIXTURE))
    ids = {f.rule_id for f in fs}
    assert {"sqli", "xss", "path-traversal", "scanner-ua"} <= ids


def test_attacker_ip_is_target_host():
    fs = weblog.analyze(str(FIXTURE))
    sqli = next(f for f in fs if f.rule_id == "sqli")
    assert sqli.target["host"] == "1.2.3.4"  # client IP, for correlation


def test_malformed_lines_ignored():
    fs = weblog.analyze_lines(["garbage", "", "not a log line"])
    assert fs == []


def test_error_spike_threshold():
    lines = ['7.7.7.7 - - [17/Jun/2026:10:00:00 +0000] '
             '"GET /x HTTP/1.1" 404 1 "-" "ua"'] * 12
    fs = weblog.analyze_lines(lines)
    assert any(f.rule_id == "error-spike" for f in fs)
