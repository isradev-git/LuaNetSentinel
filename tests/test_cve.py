from lns.core import cve
from lns.core.store import Store

FAKE = {"openssh 7.4": [{"id": "CVE-2016-10009", "cvss": 7.5},
                        {"id": "CVE-2018-15473", "cvss": 5.3}]}


def fake_fetch(q):
    return FAKE.get(q.lower(), [])


def test_band_mapping():
    assert cve.band(9.8) == "critical"
    assert cve.band(7.0) == "high"
    assert cve.band(4.0) == "medium"
    assert cve.band(0.1) == "low"
    assert cve.band(0) == "info"


def test_lookup_caches_and_sorts():
    store = Store(":memory:")
    calls = []

    def counting(q):
        calls.append(q)
        return fake_fetch(q)

    a = cve.lookup("OpenSSH", "7.4", store, fetch=counting)
    assert [c["cvss"] for c in a] == [7.5, 5.3]   # sorted desc
    b = cve.lookup("OpenSSH", "7.4", store, fetch=counting)
    assert b == a
    assert len(calls) == 1                          # 2nd call served from cache


def test_offline_miss_degrades_to_empty():
    store = Store(":memory:")

    def boom(q):
        raise OSError("offline")

    assert cve.lookup("Nginx", "1.0", store, fetch=boom) == []


def test_enrich_emits_vuln_finding():
    store = Store(":memory:")
    svcs = [{"host": "h", "port": 22, "proto": "tcp",
             "product": "OpenSSH", "version": "7.4"}]
    fs = cve.enrich(svcs, store, fetch=fake_fetch, min_cvss=7.0)
    assert len(fs) == 1
    f = fs[0]
    assert f.category == "vulnerability"
    assert f.severity == "high"                     # max cvss 7.5
    assert f.target["host"] == "h"
    assert any("CVE-2016-10009" in c for c in f.evidence["cves"])


def test_enrich_skips_below_threshold_and_missing_version():
    store = Store(":memory:")
    drop = [{"host": "h", "port": 22, "proto": "tcp",
             "product": "OpenSSH", "version": "7.4"}]
    assert cve.enrich(drop, store, fetch=fake_fetch, min_cvss=9.9) == []
    nover = [{"host": "h", "port": 80, "proto": "tcp",
              "product": "X", "version": ""}]
    assert cve.enrich(nover, store, fetch=fake_fetch) == []
