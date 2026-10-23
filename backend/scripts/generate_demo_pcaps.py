"""
generate_demo_pcaps.py — Create synthetic PCAP files for demonstration.

Run from the ``backend/`` directory:

    python -m scripts.generate_demo_pcaps

Produces two files in ``backend/data/``:

  - normal_traffic.pcap      — benign browsing-like traffic; must produce
                               NO alerts.
  - suspicious_traffic.pcap  — contains a simulated port scan and a
                               high-rate burst; must produce alerts.

All traffic is synthetic and generated locally with Scapy.  No real
network traffic is captured, and no live host is contacted.
"""

from __future__ import annotations

import os
import sys

# Make the ``app`` package importable when run as ``python -m scripts...``
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scapy.all import DNS, DNSQR, Ether, ICMP, IP, IPv6, Raw, TCP, UDP, wrpcap
from scapy.config import conf


# ---------------------------------------------------------------------------
# Offline guard
# ---------------------------------------------------------------------------
# A bare ``Ether()`` leaves ``dst`` unset, which makes Scapy fill it in by
# issuing a *real* ARP request (IPv4) or neighbour-solicitation (IPv6) on
# the live interface.  That would turn a pure data-generation script into
# something that touches the network and fails on machines without a packet
# socket (winpcap/Npcap).  Register a resolver that returns a fixed dummy
# MAC instead, so generation is hermetic regardless of the host.
_DUMMY_MAC = "02:00:00:00:00:01"
conf.neighbor.register_l3(Ether, IP, lambda l2, l3: _DUMMY_MAC)
conf.neighbor.register_l3(Ether, IPv6, lambda l2, l3: _DUMMY_MAC)


def _eth(src="02:00:00:00:00:01", dst="02:00:00:00:00:02"):
    """Ethernet header with explicit addresses (never resolves live)."""
    return Ether(src=src, dst=dst)

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

# Fixed epoch base so the generated captures (and therefore the
# demonstration output) are byte-for-byte reproducible.
BASE_TIME = 1_700_000_000.0


def generate_normal_traffic() -> str:
    """Generate benign traffic: web browsing, DNS lookups and pings."""
    pkts = []

    # HTTP browsing from one client to one web server.
    for i in range(15):
        pkt = (
            _eth()
            / IP(src="192.168.1.10", dst="93.184.216.34")
            / TCP(sport=50000 + i, dport=80)
            / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        )
        pkt.time = BASE_TIME + i * 2.0
        pkts.append(pkt)

    # HTTPS sessions to a second server.
    for i in range(10):
        pkt = (
            _eth()
            / IP(src="192.168.1.10", dst="142.250.80.46")
            / TCP(sport=51000 + i, dport=443)
        )
        pkt.time = BASE_TIME + 30 + i * 1.5
        pkts.append(pkt)

    # DNS queries.
    for i, domain in enumerate(["google.com", "github.com", "python.org"]):
        pkt = (
            _eth()
            / IP(src="192.168.1.10", dst="8.8.8.8")
            / UDP(sport=60000 + i, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=domain))
        )
        pkt.time = BASE_TIME + 50 + i * 5.0
        pkts.append(pkt)

    # ICMP echo requests to the gateway.
    for i in range(3):
        pkt = _eth() / IP(src="192.168.1.10", dst="192.168.1.1") / ICMP()
        pkt.time = BASE_TIME + 70 + i * 10.0
        pkts.append(pkt)

    path = os.path.join(DATA_DIR, "normal_traffic.pcap")
    wrpcap(path, pkts)
    print(f"[OK] Wrote {len(pkts)} packets -> {path}")
    return path


def generate_suspicious_traffic() -> str:
    """Generate traffic with a simulated port scan and a high-rate burst."""
    pkts = []

    # --- Simulated port scan: 40 distinct ports probed in 16 s ---------
    # src 192.168.1.100 -> dst 10.0.0.5, destination ports 20..59.
    # Rule A (>=20 distinct ports in 60 s) fires here.
    for i in range(40):
        pkt = (
            _eth()
            / IP(src="192.168.1.100", dst="10.0.0.5")
            / TCP(sport=40000, dport=20 + i, flags="S")
        )
        pkt.time = BASE_TIME + i * 0.4
        pkts.append(pkt)

    # --- Simulated high-rate burst: 300 packets in ~1.5 s --------------
    # src 192.168.1.200 -> dst 10.0.0.5:80.
    # Rule B (>=100 pkt/s over a 10 s window, >=20 packets) fires here.
    burst_start = BASE_TIME + 60.0
    for i in range(300):
        pkt = (
            _eth()
            / IP(src="192.168.1.200", dst="10.0.0.5")
            / TCP(sport=55000, dport=80)
            / Raw(b"X" * 100)
        )
        pkt.time = burst_start + i * 0.005
        pkts.append(pkt)

    # --- Background traffic from an innocent host ----------------------
    # This host must NOT be flagged.
    for i in range(5):
        pkt = (
            _eth()
            / IP(src="192.168.1.10", dst="8.8.8.8")
            / UDP(sport=60000 + i, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.com"))
        )
        pkt.time = BASE_TIME + 100 + i * 3.0
        pkts.append(pkt)

    path = os.path.join(DATA_DIR, "suspicious_traffic.pcap")
    wrpcap(path, pkts)
    print(f"[OK] Wrote {len(pkts)} packets -> {path}")
    return path


def main() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    generate_normal_traffic()
    generate_suspicious_traffic()
    print("\nDone. Use these files with POST /analyze to demonstrate NetSentinel.")


if __name__ == "__main__":
    main()
