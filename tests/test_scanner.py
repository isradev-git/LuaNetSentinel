from pathlib import Path

import pytest

from lns.collectors import scanner
from lns.core import rules
from lns.core.correlation import correlate
from lns.core.finding import Finding
from lns.core.scope import OutOfScope, Scope

FIXTURE = Path(__file__).parent / "fixtures" / "nmap.xml"


@pytest.fixture(autouse=True)
def _load():
    rules.load_rules()


def test_parse_fires_expected_rules():
    findings = scanner.parse_xml(FIXTURE.read_text(), run_id="r1")
    ids = {f.rule_id for f in findings}
    assert "ssh-exposed" in ids       # port 22 open
    assert "legacy-service" in ids    # telnet 23 open
    # port 80 http triggers nothing here
    assert all(f.target["host"] == "192.168.1.10" for f in findings)


def test_tls_weak_from_script_output():
    xml = """<nmaprun><host><address addr="192.168.1.10"/>
      <ports><port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
        <script id="ssl-enum-ciphers" output="TLSv1.0: ... RC4 ... least strength: C"/>
      </port></ports></host></nmaprun>"""
    findings = scanner.parse_xml(xml, run_id="r1")
    assert any(f.rule_id == "tls-weak" for f in findings)


def test_observed_ports_only_open():
    findings_xml = FIXTURE.read_text()
    observed = scanner.observed_ports(findings_xml)
    assert observed["192.168.1.10"] == {22, 23, 80}


def test_scope_blocks_out_of_range():
    scope = Scope("home", ["192.168.1.0/24"])
    with pytest.raises(OutOfScope):
        scope.guard("8.8.8.8")


def test_correlation_boost():
    fs = [Finding(rule_id="a", source="scanner", severity="medium",
                  category="c", title="t", target={"host": "x"}),
          Finding(rule_id="b", source="traffic", severity="medium",
                  category="c", title="t", target={"host": "x"})]
    assert correlate(fs)["x"] == 77  # 62 risk + 15 boost
