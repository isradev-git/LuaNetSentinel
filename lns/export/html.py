"""HTML report (jinja2, autoescape on) — entregable a cliente. Dark theme."""
from __future__ import annotations

import time
from collections import defaultdict
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..core import i18n
from ..core.correlation import correlate
from ..core.finding import Finding
from ..core.scoring import score_finding
from ..util.sanitize import clean

TEMPLATES = Path(__file__).resolve().parents[2] / "templates"


def to_html(findings: list[Finding], run_id: str = "", scope: str = "",
            generated_at: str | None = None) -> str:
    for f in findings:
        score_finding(f)
        f.evidence = clean(f.evidence)  # defense in depth; autoescape also on
        i18n.translate(f)  # title/description/remediation al idioma activo

    risks = sorted(correlate(findings).items(), key=lambda x: -x[1])
    by_host: dict[str, list[Finding]] = defaultdict(list)
    for f in sorted(findings, key=lambda x: -x.score):
        by_host[f.host or "—"].append(f)

    env = Environment(loader=FileSystemLoader(str(TEMPLATES)),
                      autoescape=select_autoescape(["html", "j2"]))
    return env.get_template("report.html.j2").render(
        run_id=run_id, scope=scope,
        generated_at=generated_at or time.strftime("%Y-%m-%d %H:%M:%S"),
        findings=findings, risks=risks, by_host=sorted(by_host.items()))


if __name__ == "__main__":
    f = Finding(rule_id="ssh-exposed", source="scanner", severity="medium",
                category="exposure", title="SSH expuesto", target={"host": "h"},
                evidence={"banner": "<script>alert(1)</script>"})
    html = to_html([f], run_id="r1", scope="home")
    assert "LuaNetSentinel" in html
    assert "SSH expuesto" in html
    # the malicious banner must be escaped, not live markup
    assert "<script>alert(1)" not in html
    assert "&lt;script&gt;" in html
    print("ok", len(html), "bytes")
