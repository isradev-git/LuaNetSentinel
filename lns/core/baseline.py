"""Baseline + drift — known-good state per host, deviations become Findings.

Blue-team asset inventory: a new port, a new host, or a changed service vs
the reference state is drift (category=drift).
"""
from __future__ import annotations

from .finding import Finding
from .store import Store


def drift(store: Store, observed: dict[str, set[int]],
          run_id: str = "") -> list[Finding]:
    """Compare observed open ports per host against the stored baseline."""
    out: list[Finding] = []
    for host, ports in observed.items():
        base = store.get_baseline(host)
        if base is None:
            out.append(_finding(host, "Host nuevo (sin baseline)",
                                {"ports": sorted(ports)},
                                "Confirma el host y fija baseline si es legítimo.",
                                "high", run_id))
            continue
        new_ports = sorted(set(ports) - set(base["ports"]))
        for p in new_ports:
            out.append(_finding(host, f"Puerto nuevo {p} respecto al baseline",
                                {"port": p, "baseline": base["ports"]},
                                "Verifica el servicio; actualiza baseline o cierra el puerto.",
                                "medium", run_id, port=p))
    return out


def _finding(host, title, evidence, remediation, severity, run_id, port=None):
    return Finding(
        rule_id="drift", source="scanner", severity=severity, category="drift",
        title=title, description="Desviación respecto al estado de referencia.",
        remediation=remediation, target={"host": host, "port": port},
        evidence=evidence, run_id=run_id)


if __name__ == "__main__":
    s = Store(":memory:")
    s.set_baseline("192.168.1.10", [22, 80])
    # observed has a new port 23 + an unknown host
    fs = drift(s, {"192.168.1.10": {22, 80, 23}, "192.168.1.99": {445}})
    titles = sorted(f.title for f in fs)
    assert any("Puerto nuevo 23" in t for t in titles), titles
    assert any("Host nuevo" in t for t in titles), titles
    assert all(f.category == "drift" for f in fs)
    print("ok", titles)
