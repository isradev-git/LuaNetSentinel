from lns.core import baseline
from lns.core.store import Store


def test_drift_detects_new_port_and_new_host():
    s = Store(":memory:")
    s.set_baseline("192.168.1.10", [22, 80])
    fs = baseline.drift(s, {"192.168.1.10": {22, 80, 23}, "192.168.1.99": {445}})
    titles = [f.title for f in fs]
    assert any("Puerto nuevo 23" in t for t in titles)
    assert any("Host nuevo" in t for t in titles)
    assert all(f.category == "drift" for f in fs)


def test_no_drift_when_matches_baseline():
    s = Store(":memory:")
    s.set_baseline("192.168.1.10", [22, 80])
    fs = baseline.drift(s, {"192.168.1.10": {22, 80}})
    assert fs == []
