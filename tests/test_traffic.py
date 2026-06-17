from scapy.all import ARP, DNS, DNSQR, Ether, IP, TCP, UDP, Raw

from lns.collectors import traffic


def test_dns_tunneling_fires():
    pkt = (IP(src="192.168.1.5", dst="8.8.8.8") / UDP() /
           DNS(rd=1, qd=DNSQR(qname="aGVsbG8gd29ybGQgZXhmaWw.x7f9q2.evil.com")))
    fs = traffic.analyze([pkt])
    assert any(f.rule_id == "dns-tunneling" for f in fs)


def test_cleartext_http_basic():
    payload = b"GET / HTTP/1.1\r\nAuthorization: Basic YWRtaW46czNjcmV0\r\n\r\n"
    pkt = IP(src="192.168.1.5", dst="192.168.1.9") / TCP(dport=80) / Raw(load=payload)
    fs = traffic.analyze([pkt])
    cred = [f for f in fs if f.rule_id == "cleartext-credentials"]
    assert cred and "admin" in cred[0].evidence["detail"]


def test_beaconing_regular_interval():
    pkts = []
    for i in range(5):
        p = IP(src="192.168.1.5", dst="10.0.0.9") / TCP(dport=443)
        p.time = 1000.0 + i * 10.0  # perfectly regular -> beacon
        pkts.append(p)
    fs = traffic.analyze(pkts)
    assert any(f.rule_id == "beaconing" for f in fs)


def test_no_beaconing_when_irregular():
    pkts = []
    for i, t in enumerate([0, 3, 17, 18, 40]):  # jittery
        p = IP(src="192.168.1.5", dst="10.0.0.9") / TCP(dport=8443)
        p.time = 1000.0 + t
        pkts.append(p)
    fs = traffic.analyze(pkts)
    assert not any(f.rule_id == "beaconing" for f in fs)


def test_arp_spoof_two_macs():
    arp = [Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:01"),
           Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:02")]
    fs = traffic.analyze(arp)
    assert any(f.rule_id == "arp-spoofing" for f in fs)
