"""Traffic collector (scapy): pcap offline or live sniff → Findings.

Two detection layers:
  - stateless per-packet rules (rules/traffic/*.py): DNS tunneling, cleartext creds
  - stateful analyzers here: beaconing (C2) and ARP spoofing need cross-packet state
"""
from __future__ import annotations

import base64
import statistics
from collections import defaultdict
from typing import Any, Iterable

from scapy.all import ARP, DNS, DNSQR, IP, TCP, UDP, Raw, rdpcap, sniff

from ..core import rules
from ..core.finding import Finding

# ponytail: fixed thresholds; expose as config if false-positive rate bites
BEACON_MIN_HITS = 4
BEACON_MAX_CV = 0.15  # coefficient of variation: low = suspiciously regular


def read_pcap(path: str) -> list:
    return list(rdpcap(path))


def live(iface: str, count: int = 0, timeout: int | None = None) -> list:
    return list(sniff(iface=iface, count=count, timeout=timeout))


def _contexts(pkt: Any) -> list[rules.Context]:
    """Derive zero+ rule Contexts from one packet (stateless features)."""
    out: list[rules.Context] = []
    src = pkt[IP].src if pkt.haslayer(IP) else None

    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
        qname = pkt[DNSQR].qname
        qname = qname.decode(errors="replace") if isinstance(qname, bytes) else str(qname)
        out.append(rules.Context(proto="dns", host=src, qname=qname.rstrip(".")))

    if pkt.haslayer(Raw):
        payload = bytes(pkt[Raw].load)
        proto, detail = _creds(payload)
        if proto:
            dst = pkt[IP].dst if pkt.haslayer(IP) else None
            out.append(rules.Context(proto=proto, host=dst,
                                     has_credentials=True, cred_detail=detail))
    return out


def _creds(payload: bytes) -> tuple[str | None, str | None]:
    """Spot cleartext auth in a raw payload. Returns (proto, detail)."""
    low = payload.lower()
    marker = b"authorization: basic "
    idx = low.find(marker)
    if idx != -1:
        # slice token from ORIGINAL bytes — base64 is case-sensitive
        token = payload[idx + len(marker):].split(b"\r\n", 1)[0].strip()
        try:
            user = base64.b64decode(token).split(b":", 1)[0].decode(errors="replace")
        except Exception:
            user = "?"
        return "http", f"HTTP Basic user={user}"
    if low.startswith(b"user ") or b"\r\nuser " in low:
        return "ftp", "FTP USER/PASS"
    return None, None


def _beaconing(packets: Iterable, run_id: str) -> list[Finding]:
    """Periodic connections to the same dst:port = possible C2 beacon."""
    times: dict[tuple, list[float]] = defaultdict(list)
    for pkt in packets:
        if pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
            l4 = pkt[TCP] if pkt.haslayer(TCP) else pkt[UDP]
            key = (pkt[IP].src, pkt[IP].dst, int(l4.dport))
            times[key].append(float(pkt.time))

    out: list[Finding] = []
    for (src, dst, dport), ts in times.items():
        if len(ts) < BEACON_MIN_HITS:
            continue
        deltas = [b - a for a, b in zip(sorted(ts), sorted(ts)[1:])]
        mean = statistics.fmean(deltas)
        if mean <= 0:
            continue
        cv = statistics.pstdev(deltas) / mean
        if cv < BEACON_MAX_CV:
            out.append(Finding(
                rule_id="beaconing", source="traffic", severity="high",
                category="suspicious-traffic", title="Beaconing periódico (posible C2)",
                description="Conexiones regulares al mismo destino: patrón de C2.",
                remediation="Aísla el host origen e investiga el destino.",
                target={"host": src, "port": dport, "proto": "tcp"},
                evidence={"dst": dst, "hits": len(ts),
                          "period_s": round(mean, 2), "cv": round(cv, 3)},
                run_id=run_id))
    return out


def _arp_spoof(packets: Iterable, run_id: str) -> list[Finding]:
    """One IP claimed by 2+ MACs = ARP spoofing on the LAN."""
    macs: dict[str, set[str]] = defaultdict(set)
    for pkt in packets:
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # is-at (reply)
            macs[pkt[ARP].psrc].add(pkt[ARP].hwsrc)

    out: list[Finding] = []
    for ip, hw in macs.items():
        if len(hw) >= 2:
            out.append(Finding(
                rule_id="arp-spoofing", source="traffic", severity="critical",
                category="suspicious-traffic", title="ARP spoofing detectado",
                description="Una IP responde con varias MAC: envenenamiento ARP.",
                remediation="Revisa la LAN; fija entradas ARP estáticas en hosts críticos.",
                target={"host": ip, "proto": "arp"},
                evidence={"macs": sorted(hw)}, run_id=run_id))
    return out


def analyze(packets: list, run_id: str = "") -> list[Finding]:
    rules.load_rules()
    out: list[Finding] = []
    for pkt in packets:
        for ctx in _contexts(pkt):
            out += rules.apply(ctx, "traffic", run_id=run_id)
    out += _beaconing(packets, run_id)
    out += _arp_spoof(packets, run_id)
    return out


if __name__ == "__main__":
    from scapy.all import Ether
    dns = (IP(src="192.168.1.5", dst="8.8.8.8") / UDP() /
           DNS(rd=1, qd=DNSQR(qname="aGVsbG8gd29ybGQgZXhmaWw.x7f9q2.evil.com")))
    beacons = []  # 5 regular beacons 10s apart
    for i in range(5):
        p = IP(src="192.168.1.5", dst="10.0.0.9") / TCP(dport=443)
        p.time = 1000.0 + i * 10.0
        beacons.append(p)
    arp = [Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:01"),
           Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:02")]
    fs = analyze([dns] + beacons + arp)
    ids = {f.rule_id for f in fs}
    print("fired:", ids)
    assert "dns-tunneling" in ids
    assert "beaconing" in ids
    assert "arp-spoofing" in ids
    print("ok")
