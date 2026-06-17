"""Scanner collector: scope guard → nmap → XML parse → rules → Findings."""
from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from ..core import rules
from ..core.finding import Finding
from ..core.scope import Scope

NSE = Path(__file__).resolve().parents[2] / "nse" / "suspicious-services.nse"


def run_nmap(target: str) -> str:
    """Launch nmap, return XML on stdout. Uses our NSE script if present."""
    cmd = ["nmap", "-oX", "-", "-sV", "-sC"]
    if NSE.exists():
        cmd += ["--script", str(NSE)]
    cmd.append(target)
    return subprocess.run(cmd, capture_output=True, text=True,
                          check=True).stdout


def parse_xml(xml: str, run_id: str = "") -> list[Finding]:
    """Parse nmap XML → one rule-evaluation per open port. Offline-testable."""
    root = ET.fromstring(xml)
    out: list[Finding] = []
    for host in root.findall("host"):
        addr_el = host.find("address")
        host_ip = addr_el.get("addr") if addr_el is not None else None
        for port in host.findall("./ports/port"):
            state_el = port.find("state")
            svc_el = port.find("service")
            scripts = {s.get("id"): s.get("output", "")
                       for s in port.findall("script")}
            ctx = rules.Context(
                scripts=scripts,
                host=host_ip,
                port=int(port.get("portid")),
                proto=port.get("protocol"),
                state=state_el.get("state") if state_el is not None else None,
                service=svc_el.get("name") if svc_el is not None else None,
                product=svc_el.get("product") if svc_el is not None else None,
                version=svc_el.get("version") if svc_el is not None else None,
                banner=(svc_el.get("product", "") + " "
                        + svc_el.get("version", "")).strip()
                if svc_el is not None else "",
            )
            out += rules.apply(ctx, "scanner", run_id=run_id)
    return out


def observed_ports(xml: str) -> dict[str, set[int]]:
    """Map host -> set of open ports, for baseline drift comparison."""
    root = ET.fromstring(xml)
    out: dict[str, set[int]] = {}
    for host in root.findall("host"):
        addr_el = host.find("address")
        ip = addr_el.get("addr") if addr_el is not None else None
        if not ip:
            continue
        ports = {int(p.get("portid")) for p in host.findall("./ports/port")
                 if (st := p.find("state")) is not None and st.get("state") == "open"}
        out[ip] = ports
    return out


def scan(target: str, scope: Scope, run_id: str = "") -> list[Finding]:
    scope.guard(target)  # raises OutOfScope before anything launches
    return parse_xml(run_nmap(target), run_id=run_id)


if __name__ == "__main__":
    rules.load_rules()
    sample = """<nmaprun><host><address addr="192.168.1.10"/>
      <ports><port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2"/>
      </port></ports></host></nmaprun>"""
    fs = parse_xml(sample, run_id="r1")
    print("findings:", [(f.rule_id, f.target) for f in fs])
