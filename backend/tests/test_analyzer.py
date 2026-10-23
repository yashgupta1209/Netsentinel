"""
test_analyzer.py — Tests for the packet reader and statistics modules.

All PCAP data is generated synthetically using Scapy fixtures defined
in conftest.py.  No network access or admin privileges are required.
"""

from __future__ import annotations

import os
import tempfile

import pytest
from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw, wrpcap

from app.analyzer.packet_reader import read_pcap, read_pcap_bytes
from app.analyzer.statistics import compute_statistics


# ===================================================================
# Packet Reader Tests
# ===================================================================

class TestPacketReaderTCP:
    """Test reading TCP packets."""

    def test_tcp_packets_count(self, tcp_pcap):
        records = read_pcap(tcp_pcap)
        assert len(records) == 5

    def test_tcp_fields_present(self, tcp_pcap):
        records = read_pcap(tcp_pcap)
        r = records[0]
        assert r["src_ip"] == "10.0.0.1"
        assert r["dst_ip"] == "10.0.0.2"
        assert r["protocol"] == "TCP"
        assert r["src_port"] == 12345
        assert r["dst_port"] == 80
        assert r["length"] > 0
        assert r["timestamp"] is not None


class TestPacketReaderUDP:
    """Test reading UDP packets."""

    def test_udp_packets_count(self, udp_pcap):
        records = read_pcap(udp_pcap)
        assert len(records) == 3

    def test_udp_fields(self, udp_pcap):
        records = read_pcap(udp_pcap)
        r = records[0]
        assert r["protocol"] in ("UDP", "DNS")
        assert r["src_port"] == 5000
        assert r["dst_port"] == 53


class TestPacketReaderICMP:
    """Test reading ICMP packets."""

    def test_icmp_packets_count(self, icmp_pcap):
        records = read_pcap(icmp_pcap)
        assert len(records) == 2

    def test_icmp_no_ports(self, icmp_pcap):
        records = read_pcap(icmp_pcap)
        for r in records:
            assert r["protocol"] == "ICMP"
            assert r["src_port"] is None
            assert r["dst_port"] is None


class TestPacketReaderNonIP:
    """Test packets that lack an IP layer."""

    def test_non_ip_packet(self, non_ip_pcap):
        records = read_pcap(non_ip_pcap)
        assert len(records) == 1
        r = records[0]
        assert r["src_ip"] is None
        assert r["dst_ip"] is None
        assert r["protocol"] == "Non-IP"
        assert r["src_port"] is None
        assert r["dst_port"] is None


class TestPacketReaderEmpty:
    """Test empty captures."""

    def test_empty_pcap_returns_empty_list(self, empty_pcap):
        records = read_pcap(empty_pcap)
        assert records == []


class TestPacketReaderInvalid:
    """Test malformed and missing input."""

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            read_pcap("/nonexistent/path/fake.pcap")

    def test_invalid_content(self, tmp_path):
        bad = tmp_path / "bad.pcap"
        bad.write_text("this is not a pcap file")
        with pytest.raises(ValueError):
            read_pcap(str(bad))

    def test_read_pcap_bytes_empty(self):
        with pytest.raises(ValueError):
            read_pcap_bytes(b"")


class TestPacketReaderMixed:
    """Test correct extraction across mixed protocols."""

    def test_mixed_protocols(self, mixed_pcap):
        records = read_pcap(mixed_pcap)
        assert len(records) == 4
        protocols = {r["protocol"] for r in records}
        assert "TCP" in protocols
        assert "UDP" in protocols
        assert "ICMP" in protocols
        assert "Non-IP" in protocols

    def test_all_records_have_length(self, mixed_pcap):
        records = read_pcap(mixed_pcap)
        for r in records:
            assert r["length"] > 0


# ===================================================================
# Statistics Tests
# ===================================================================

class TestStatistics:
    """Test traffic statistics computations."""

    def test_total_packet_count(self, tcp_pcap):
        records = read_pcap(tcp_pcap)
        stats = compute_statistics(records)
        assert stats["total_packets"] == 5

    def test_total_bytes(self, tcp_pcap):
        records = read_pcap(tcp_pcap)
        stats = compute_statistics(records)
        assert stats["total_bytes"] > 0

    def test_protocol_distribution(self, mixed_pcap):
        records = read_pcap(mixed_pcap)
        stats = compute_statistics(records)
        pc = stats["protocol_counts"]
        assert pc.get("TCP", 0) == 1
        assert pc.get("UDP", 0) == 1
        assert pc.get("ICMP", 0) == 1
        assert pc.get("Non-IP", 0) == 1

    def test_src_ip_counts(self, tcp_pcap):
        records = read_pcap(tcp_pcap)
        stats = compute_statistics(records)
        src_map = dict(stats["top_src_ips"])
        # 10.0.0.1 sends packets 1 and 3 → count = 2
        assert src_map["10.0.0.1"] == 2

    def test_dst_ip_counts(self, tcp_pcap):
        records = read_pcap(tcp_pcap)
        stats = compute_statistics(records)
        dst_map = dict(stats["top_dst_ips"])
        # 10.0.0.2 is dst in packets 1 and 3 → count = 2
        assert dst_map["10.0.0.2"] == 2

    def test_dst_port_counts(self, tcp_pcap):
        records = read_pcap(tcp_pcap)
        stats = compute_statistics(records)
        dpc = stats["dst_port_counts"]
        # Ports used: 80 (×2 from 10.0.0.1→10.0.0.2), 443 (×1),
        # 12345 (×1), 22 (×1), 54321 (×1)
        assert "80" in dpc

    def test_empty_input(self):
        stats = compute_statistics([])
        assert stats["total_packets"] == 0
        assert stats["total_bytes"] == 0
        assert stats["protocol_counts"] == {}
        assert stats["top_src_ips"] == []
        assert stats["top_dst_ips"] == []
        assert stats["dst_port_counts"] == {}

    def test_missing_fields(self):
        """Packets with None for optional fields should not crash."""
        records = [
            {"timestamp": None, "src_ip": None, "dst_ip": None,
             "protocol": "Non-IP", "src_port": None, "dst_port": None,
             "length": 42},
        ]
        stats = compute_statistics(records)
        assert stats["total_packets"] == 1
        assert stats["total_bytes"] == 42
        assert stats["top_src_ips"] == []

    def test_deterministic(self, tcp_pcap):
        """Same input ⇒ same output."""
        records = read_pcap(tcp_pcap)
        s1 = compute_statistics(records)
        s2 = compute_statistics(records)
        assert s1 == s2


# ===================================================================
# Regression tests — IPv6, ICMPv6, PCAPNG and timestamp edge cases
# ===================================================================

class TestPacketReaderIPv6:
    """IPv6 addresses, ports and protocol classification."""

    def test_ipv6_packet_count(self, ipv6_pcap):
        assert len(read_pcap(ipv6_pcap)) == 3

    def test_ipv6_tcp_addresses_and_ports(self, ipv6_pcap):
        records = read_pcap(ipv6_pcap)
        r = records[0]
        assert r["src_ip"] == "2001:db8::1"
        assert r["dst_ip"] == "2001:db8::2"
        assert r["protocol"] == "TCP"
        assert r["src_port"] == 1234
        assert r["dst_port"] == 443

    def test_ipv6_udp_ports(self, ipv6_pcap):
        records = read_pcap(ipv6_pcap)
        r = records[1]
        assert r["protocol"] == "UDP"
        assert r["src_port"] == 53
        assert r["dst_port"] == 5353

    def test_ipv6_without_transport_has_no_ports(self, ipv6_pcap):
        """An IPv6 packet with no transport layer yields null ports."""
        records = read_pcap(ipv6_pcap)
        r = records[2]
        assert r["src_ip"] == "2001:db8::5"
        assert r["src_port"] is None
        assert r["dst_port"] is None


class TestPacketReaderICMPv6:
    """ICMPv6 must not be mislabelled as generic 'Other-IP'."""

    def test_icmpv6_echo_classified(self, icmpv6_pcap):
        records = read_pcap(icmpv6_pcap)
        assert records[0]["protocol"] == "ICMPv6"

    def test_icmpv6_neighbour_solicitation_classified(self, icmpv6_pcap):
        records = read_pcap(icmpv6_pcap)
        assert records[1]["protocol"] == "ICMPv6"

    def test_icmpv6_has_no_ports_but_has_addresses(self, icmpv6_pcap):
        for r in read_pcap(icmpv6_pcap):
            assert r["src_port"] is None
            assert r["dst_port"] is None
            assert r["src_ip"] == "2001:db8::1"


class TestPacketReaderTimestamps:
    """A timestamp of exactly 0 is valid and must be preserved."""

    def test_zero_timestamp_is_not_none(self, zero_timestamp_pcap):
        records = read_pcap(zero_timestamp_pcap)
        assert len(records) == 1
        assert records[0]["timestamp"] == 0.0

    def test_timestamps_are_numeric(self, tcp_pcap):
        for r in read_pcap(tcp_pcap):
            assert isinstance(r["timestamp"], float)


class TestPacketReaderPCAPNG:
    """PCAPNG captures are accepted alongside classic PCAP."""

    def test_pcapng_parses(self, pcapng_bytes):
        assert pcapng_bytes[:4] == b"\x0a\x0d\x0d\x0a"
        records = read_pcap_bytes(pcapng_bytes)
        assert len(records) == 2

    def test_pcapng_protocols(self, pcapng_bytes):
        protocols = [r["protocol"] for r in read_pcap_bytes(pcapng_bytes)]
        assert protocols == ["TCP", "TCP"]


class TestReadPcapBytesInputTypes:
    """Byte-like inputs are accepted; non-bytes input fails cleanly."""

    def test_bytearray_accepted(self, tcp_pcap):
        with open(tcp_pcap, "rb") as fh:
            assert len(read_pcap_bytes(bytearray(fh.read()))) == 5

    def test_non_bytes_input_raises_valueerror(self):
        with pytest.raises(ValueError):
            read_pcap_bytes("not bytes")  # type: ignore[arg-type]


# ===================================================================
# Regression tests — statistics robustness
# ===================================================================

class TestStatisticsRobustness:
    """Malformed records must not corrupt totals."""

    def test_negative_length_does_not_reduce_total_bytes(self):
        records = [
            {"timestamp": 1.0, "src_ip": "1.1.1.1", "dst_ip": None,
             "protocol": "TCP", "src_port": 1, "dst_port": 2, "length": -5},
            {"timestamp": 2.0, "src_ip": "1.1.1.1", "dst_ip": None,
             "protocol": "TCP", "src_port": 1, "dst_port": 2, "length": 60},
        ]
        stats = compute_statistics(records)
        assert stats["total_bytes"] == 60

    def test_missing_length_counts_as_zero(self):
        stats = compute_statistics([
            {"timestamp": 1.0, "src_ip": "1.1.1.1", "dst_ip": None,
             "protocol": "TCP", "src_port": 1, "dst_port": 2},
        ])
        assert stats["total_bytes"] == 0

    def test_packets_without_ip_reported(self):
        records = [
            {"timestamp": 1.0, "src_ip": None, "dst_ip": None,
             "protocol": "Non-IP", "src_port": None, "dst_port": None,
             "length": 42},
            {"timestamp": 2.0, "src_ip": "1.1.1.1", "dst_ip": None,
             "protocol": "TCP", "src_port": 1, "dst_port": 80, "length": 54},
        ]
        stats = compute_statistics(records)
        assert stats["packets_without_ip"] == 1
        assert stats["packets_without_ports"] == 1
        assert dict(stats["top_src_ips"]) == {"1.1.1.1": 1}

    def test_top_ip_ordering_is_deterministic(self):
        """Equal counts are ordered by IP so output never jitters."""
        records = [
            {"timestamp": float(i), "src_ip": ip, "dst_ip": None,
             "protocol": "TCP", "src_port": 1, "dst_port": 80, "length": 54}
            for i, ip in enumerate(["10.0.0.9", "10.0.0.1", "10.0.0.5"])
        ]
        stats = compute_statistics(records)
        assert [ip for ip, _ in stats["top_src_ips"]] == [
            "10.0.0.1", "10.0.0.5", "10.0.0.9",
        ]

    def test_icmp_protocol_counted(self, icmp_pcap):
        stats = compute_statistics(read_pcap(icmp_pcap))
        assert stats["protocol_counts"] == {"ICMP": 2}
