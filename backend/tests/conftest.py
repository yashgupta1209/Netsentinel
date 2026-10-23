"""
conftest.py — Shared fixtures for NetSentinel tests.

Generates synthetic PCAP files in-memory using Scapy and provides them
as reusable pytest fixtures so that every test module does not need to
duplicate the packet-construction logic.
"""

from __future__ import annotations

import os
import tempfile
from typing import Generator

import pytest
from scapy.all import (
    Ether,
    ICMP,
    ICMPv6EchoRequest,
    ICMPv6ND_NS,
    IP,
    IPv6,
    DNS,
    DNSQR,
    Raw,
    TCP,
    UDP,
    wrpcap,
)
from scapy.config import conf
from scapy.utils import PcapNgWriter, PcapWriter


# ---------------------------------------------------------------------------
# Offline guard
# ---------------------------------------------------------------------------
# Scapy fills an unspecified ``Ether.dst`` by calling ``conf.neighbor.resolve``,
# which for IPv6 performs a *real* neighbour-solicitation on the live interface
# and for IPv4 issues a real ARP request.  That makes merely *building* a
# fixture depend on a working packet socket (winpcap/Npcap on Windows), which
# is exactly the kind of hidden network dependency these tests must not have.
#
# ``_eth()`` below removes the trigger by always setting explicit addresses.
# This resolver is a second line of defence so that a future fixture which
# forgets to use ``_eth()`` fails loudly here instead of reaching the network.
_DUMMY_MAC = "02:00:00:00:00:01"


def _offline_mac_resolver(l2inst, l3inst):
    """Return a fixed MAC instead of probing the live network."""
    return _DUMMY_MAC


conf.neighbor.register_l3(Ether, IPv6, _offline_mac_resolver)
conf.neighbor.register_l3(Ether, IP, _offline_mac_resolver)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _eth(src="02:00:00:00:00:01", dst="02:00:00:00:00:02"):
    """An Ethernet header with explicit addresses (never resolves live)."""
    return Ether(src=src, dst=dst)


def _write_tmp_pcap(packets, suffix=".pcap") -> str:
    """Write *packets* to a temp file and return the path."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    wrpcap(path, packets)
    return path


def _pcap_bytes(packets) -> bytes:
    """Return raw PCAP bytes for a list of Scapy packets."""
    path = _write_tmp_pcap(packets)
    try:
        with open(path, "rb") as f:
            return f.read()
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Fixtures — PCAP file paths (cleaned up after the test)
# ---------------------------------------------------------------------------

@pytest.fixture
def tcp_pcap(tmp_path) -> str:
    """PCAP containing 5 TCP packets."""
    pkts = [
        _eth() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b"GET / HTTP/1.1"),
        _eth() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=12345) / Raw(b"HTTP/1.1 200 OK"),
        _eth() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=443),
        _eth() / IP(src="10.0.0.3", dst="10.0.0.4") / TCP(sport=54321, dport=22),
        _eth() / IP(src="10.0.0.4", dst="10.0.0.3") / TCP(sport=22, dport=54321),
    ]
    path = str(tmp_path / "tcp.pcap")
    wrpcap(path, pkts)
    return path


@pytest.fixture
def udp_pcap(tmp_path) -> str:
    """PCAP containing 3 UDP packets."""
    pkts = [
        _eth() / IP(src="10.0.0.1", dst="10.0.0.5") / UDP(sport=5000, dport=53) / Raw(b"\x00"),
        _eth() / IP(src="10.0.0.5", dst="10.0.0.1") / UDP(sport=53, dport=5000) / Raw(b"\x00"),
        _eth() / IP(src="10.0.0.1", dst="10.0.0.6") / UDP(sport=6000, dport=8080),
    ]
    path = str(tmp_path / "udp.pcap")
    wrpcap(path, pkts)
    return path


@pytest.fixture
def icmp_pcap(tmp_path) -> str:
    """PCAP containing 2 ICMP packets."""
    pkts = [
        _eth() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(),
        _eth() / IP(src="10.0.0.2", dst="10.0.0.1") / ICMP(type=0),
    ]
    path = str(tmp_path / "icmp.pcap")
    wrpcap(path, pkts)
    return path


@pytest.fixture
def dns_pcap(tmp_path) -> str:
    """PCAP containing a DNS query over UDP."""
    pkts = [
        _eth() / IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=12345, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")),
    ]
    path = str(tmp_path / "dns.pcap")
    wrpcap(path, pkts)
    return path


@pytest.fixture
def non_ip_pcap(tmp_path) -> str:
    """PCAP containing a packet with no IP layer."""
    pkts = [
        Ether(dst="ff:ff:ff:ff:ff:ff") / Raw(b"\x00\x01\x02\x03"),
    ]
    path = str(tmp_path / "non_ip.pcap")
    wrpcap(path, pkts)
    return path


@pytest.fixture
def empty_pcap(tmp_path) -> str:
    """PCAP with zero packets."""
    path = str(tmp_path / "empty.pcap")
    wrpcap(path, [])
    return path


@pytest.fixture
def mixed_pcap(tmp_path) -> str:
    """PCAP with TCP + UDP + ICMP + non-IP packets."""
    pkts = [
        _eth() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1111, dport=80),
        _eth() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=2222, dport=53),
        _eth() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(),
        Ether(dst="ff:ff:ff:ff:ff:ff") / Raw(b"\xaa\xbb"),
    ]
    path = str(tmp_path / "mixed.pcap")
    wrpcap(path, pkts)
    return path


# ---------------------------------------------------------------------------
# Fixtures — port-scan and high-rate traffic for detection tests
# ---------------------------------------------------------------------------

@pytest.fixture
def port_scan_pcap(tmp_path) -> str:
    """PCAP simulating a port scan: one source → 30 distinct dst ports."""
    base_time = 1000000000.0
    pkts = []
    for i in range(30):
        pkt = _eth() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=40000, dport=1 + i)
        pkt.time = base_time + i * 0.5  # 30 ports in 15 seconds
        pkts.append(pkt)
    path = str(tmp_path / "port_scan.pcap")
    wrpcap(path, pkts)
    return path


@pytest.fixture
def normal_traffic_pcap(tmp_path) -> str:
    """PCAP with normal traffic — few distinct destination ports."""
    base_time = 1000000000.0
    pkts = []
    for i in range(10):
        pkt = _eth() / IP(src="192.168.1.50", dst="10.0.0.1") / TCP(sport=40000 + i, dport=80)
        pkt.time = base_time + i * 1.0
        pkts.append(pkt)
    path = str(tmp_path / "normal.pcap")
    wrpcap(path, pkts)
    return path


@pytest.fixture
def high_rate_pcap(tmp_path) -> str:
    """PCAP simulating high traffic rate: 200 packets in ~1 second."""
    base_time = 1000000000.0
    pkts = []
    for i in range(200):
        pkt = _eth() / IP(src="192.168.1.200", dst="10.0.0.1") / TCP(sport=50000, dport=80)
        pkt.time = base_time + i * 0.005  # 200 pkt/s
        pkts.append(pkt)
    path = str(tmp_path / "high_rate.pcap")
    wrpcap(path, pkts)
    return path


@pytest.fixture
def low_rate_pcap(tmp_path) -> str:
    """PCAP with low traffic rate."""
    base_time = 1000000000.0
    pkts = []
    for i in range(5):
        pkt = _eth() / IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=50000, dport=80)
        pkt.time = base_time + i * 10.0  # 0.1 pkt/s
        pkts.append(pkt)
    path = str(tmp_path / "low_rate.pcap")
    wrpcap(path, pkts)
    return path


# ---------------------------------------------------------------------------
# Fixtures — IPv6, ICMPv6 and edge-case timestamps
# ---------------------------------------------------------------------------

@pytest.fixture
def ipv6_pcap(tmp_path) -> str:
    """PCAP containing IPv6 TCP and UDP packets."""
    pkts = [
        _eth() / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / TCP(sport=1234, dport=443),
        _eth() / IPv6(src="2001:db8::3", dst="2001:db8::4")
        / UDP(sport=53, dport=5353),
        _eth() / IPv6(src="2001:db8::5", dst="2001:db8::6") / Raw(b"\x00"),
    ]
    path = str(tmp_path / "ipv6.pcap")
    wrpcap(path, pkts)
    return path


@pytest.fixture
def icmpv6_pcap(tmp_path) -> str:
    """PCAP containing ICMPv6 echo and neighbour-solicitation packets."""
    pkts = [
        _eth() / IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest(),
        _eth() / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / ICMPv6ND_NS(tgt="2001:db8::9"),
    ]
    path = str(tmp_path / "icmpv6.pcap")
    wrpcap(path, pkts)
    return path


@pytest.fixture
def zero_timestamp_pcap(tmp_path) -> str:
    """PCAP whose only packet has timestamp exactly 0.0.

    Guards against the truthiness bug that turned a valid 0.0 epoch
    timestamp into None.
    """
    pkt = _eth() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1, dport=2)
    pkt.time = 0
    path = str(tmp_path / "zero_time.pcap")
    with PcapWriter(path) as writer:
        writer.write(pkt)
    return path


@pytest.fixture
def pcapng_bytes() -> bytes:
    """Raw bytes of a PCAPNG (rather than classic PCAP) capture."""
    pkts = [
        _eth() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=80),
        _eth() / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=2, dport=443),
    ]
    fd, path = tempfile.mkstemp(suffix=".pcapng")
    os.close(fd)
    try:
        PcapNgWriter(path).write(pkts)
        with open(path, "rb") as fh:
            return fh.read()
    finally:
        os.unlink(path)


@pytest.fixture
def two_packet_pcap_bytes() -> bytes:
    """A minimal session: two packets microseconds apart.

    This is the shape of an ordinary TCP handshake / request-response
    exchange.  It must NOT raise a high-traffic-rate alert despite the
    instantaneous rate being very high.
    """
    base_time = 1000000000.0
    pkts = []
    for i in range(2):
        pkt = _eth() / IP(src="172.16.0.9", dst="10.0.0.1") / TCP(sport=5000, dport=443)
        pkt.time = base_time + i * 0.001
        pkts.append(pkt)
    return _pcap_bytes(pkts)


# ---------------------------------------------------------------------------
# Fixture — raw PCAP bytes for API upload tests
# ---------------------------------------------------------------------------

@pytest.fixture
def tcp_pcap_bytes() -> bytes:
    """Return raw bytes of a small TCP PCAP."""
    pkts = [
        _eth() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b"GET /"),
        _eth() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=12345) / Raw(b"HTTP 200"),
    ]
    return _pcap_bytes(pkts)


@pytest.fixture
def port_scan_pcap_bytes() -> bytes:
    """Raw bytes of the port-scan PCAP for upload tests."""
    base_time = 1000000000.0
    pkts = []
    for i in range(30):
        pkt = _eth() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=40000, dport=1 + i)
        pkt.time = base_time + i * 0.5
        pkts.append(pkt)
    return _pcap_bytes(pkts)
