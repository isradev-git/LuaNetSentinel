import json

from lns.core.finding import Finding
from lns.export import html, json_export


def _malicious():
    return Finding(rule_id="ssh-exposed", source="scanner", severity="medium",
                   category="exposure", title="SSH expuesto", target={"host": "h"},
                   evidence={"banner": "<script>alert(1)</script>"})


def test_json_sanitizes_and_scores():
    out = json.loads(json_export.dumps([_malicious()], "r1"))
    f = out["findings"][0]
    assert f["score"] == 50
    assert out["host_risk"]["h"] == 50


def test_html_escapes_evidence():
    page = html.to_html([_malicious()], run_id="r1", scope="home")
    assert "SSH expuesto" in page
    assert "<script>alert(1)" not in page   # not live markup
    assert "&lt;script&gt;" in page          # escaped
