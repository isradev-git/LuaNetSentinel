"""CVE enrichment: detected (product, version) -> known CVEs.

Queries NVD 2.0 (no API key) once per (product, version) and caches the result
in SQLite, so later runs and the report keep working OFFLINE. Network down /
offline => cache-only, silent degrade (never raises for network reasons). NVD
CVSS bands map straight onto our Finding severities.

ponytail: keyword match against NVD, not CPE/version-range — noisy by design
(may over-match). Upgrade path: use nmap's <cpe> + NVD cpeName + version-range
filtering when precision matters. Evidence stays honest about the limitation.
"""
from __future__ import annotations

from typing import Any, Callable

import requests  # already a dep (alerting/telegram)

from .finding import Finding

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
Fetch = Callable[[str], list[dict[str, Any]]]


def band(cvss: float) -> str:
    """NVD CVSS v3 base-score bands -> our Finding severities."""
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


def _cvss(metrics: dict) -> float:
    """Best available base score across CVSS v3.1 / v3.0 / v2 metric blocks."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []):
            score = m.get("cvssData", {}).get("baseScore")
            if score is not None:
                return float(score)
    return 0.0


def nvd_fetch(query: str) -> list[dict[str, Any]]:
    """NVD keyword search -> [{id, cvss}]. Raises on network / HTTP error."""
    r = requests.get(NVD, params={"keywordSearch": query, "resultsPerPage": 20},
                     timeout=15)
    r.raise_for_status()
    out: list[dict[str, Any]] = []
    for item in r.json().get("vulnerabilities", []):
        c = item.get("cve", {})
        out.append({"id": c.get("id"), "cvss": _cvss(c.get("metrics", {}))})
    return out


def lookup(product: str, version: str, store: Any,
           fetch: Fetch = nvd_fetch) -> list[dict[str, Any]]:
    """CVEs for one product/version, sorted by CVSS desc. Cache-first; fetch +
    cache on miss; [] on offline miss. Never raises for network reasons.

    A cached empty list is a real answer (clean service), distinct from a miss
    (None), so clean services are not re-queried every run."""
    query = f"{product} {version}".strip()
    if not query:
        return []
    cached = store.cve_get(query) if store else None
    if cached is not None:
        return cached
    try:
        cves = fetch(query)
    except Exception:  # offline / HTTP / parse -> degrade to nothing
        return []
    cves = [c for c in cves if c.get("id")]
    cves.sort(key=lambda c: c.get("cvss") or 0, reverse=True)
    if store:
        store.cve_put(query, cves)
    return cves


def enrich(services: list[dict[str, Any]], store: Any, fetch: Fetch = nvd_fetch,
           min_cvss: float = 7.0, top: int = 5) -> list[Finding]:
    """One 'vulnerability' Finding per service with CVEs at/above min_cvss."""
    out: list[Finding] = []
    for svc in services:
        product, version = svc.get("product"), svc.get("version")
        if not product or not version:
            continue
        cves = [c for c in lookup(product, version, store, fetch)
                if (c.get("cvss") or 0) >= min_cvss][:top]
        if not cves:
            continue
        top_cvss = cves[0]["cvss"]
        out.append(Finding(
            rule_id="cve-known", source="scanner", severity=band(top_cvss),
            category="vulnerability",
            title=f"CVEs conocidos en {product} {version}",
            description=f"{len(cves)} CVE de CVSS>={min_cvss} (coincidencia por "
                        f"keyword NVD; verificar versión exacta).",
            remediation=f"Actualizar {product} a una versión sin estos CVE.",
            evidence={"product": product, "version": version,
                      "max_cvss": top_cvss,
                      "cves": [f"{c['id']} ({c['cvss']})" for c in cves]},
            target={"host": svc.get("host"), "port": svc.get("port"),
                    "proto": svc.get("proto")}))
    return out


if __name__ == "__main__":
    from .store import Store

    assert band(9.8) == "critical" and band(7.0) == "high"
    assert band(4.0) == "medium" and band(0.1) == "low" and band(0) == "info"

    fake = {"openssh 7.4": [{"id": "CVE-2016-10009", "cvss": 7.5},
                            {"id": "CVE-2018-15473", "cvss": 5.3}]}
    calls: list[str] = []

    def fetch(q):
        calls.append(q)
        return fake.get(q.lower(), [])

    s = Store(":memory:")
    a = lookup("OpenSSH", "7.4", s, fetch=fetch)
    assert a[0]["cvss"] == 7.5            # sorted desc
    assert lookup("OpenSSH", "7.4", s, fetch=fetch) == a
    assert len(calls) == 1                # 2nd call from cache, no re-fetch

    def boom(q):
        raise OSError("offline")
    assert lookup("nginx", "1.0", s, fetch=boom) == []   # offline miss -> []

    fs = enrich([{"host": "h", "port": 22, "proto": "tcp",
                  "product": "OpenSSH", "version": "7.4"}], s, fetch=fetch)
    assert len(fs) == 1 and fs[0].severity == "high"
    assert fs[0].category == "vulnerability"
    print("ok", fs[0].evidence["cves"])
