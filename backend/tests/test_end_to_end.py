"""
test_end_to_end.py — Full-pipeline tests over the committed demo captures.

These exercise the same code path the API's ``POST /analyze`` uses
(``read_pcap`` -> ``compute_statistics`` -> ``run_all_rules``) but call
the functions directly, so they do not require a web server.

They also pin down the behaviour the demonstration relies on:

* ``data/normal_traffic.pcap``      must produce ZERO alerts
* ``data/suspicious_traffic.pcap``  must produce BOTH alert types
"""

from __future__ import annotations

import os

import pytest

from app.analyzer.packet_reader import read_pcap
from app.analyzer.statistics import compute_statistics
from app.detection.rules import run_all_rules

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
NORMAL = os.path.join(DATA_DIR, "normal_traffic.pcap")
SUSPICIOUS = os.path.join(DATA_DIR, "suspicious_traffic.pcap")


def _analyse(path):
    packets = read_pcap(path)
    return packets, compute_statistics(packets), run_all_rules(packets)


requires_demo_files = pytest.mark.skipif(
    not (os.path.isfile(NORMAL) and os.path.isfile(SUSPICIOUS)),
    reason="demo captures not generated; run python -m scripts.generate_demo_pcaps",
)


@requires_demo_files
class TestNormalCaptureIsClean:
    """Benign traffic must not trip either rule."""

    def test_parses(self):
        packets, _, _ = _analyse(NORMAL)
        assert len(packets) == 31

    def test_statistics_are_sane(self):
        _, stats, _ = _analyse(NORMAL)
        assert stats["total_packets"] == 31
        assert stats["total_bytes"] > 0
        assert set(stats["protocol_counts"]) == {"TCP", "DNS", "ICMP"}
        assert stats["packets_without_ip"] == 0

    def test_no_alerts(self):
        _, _, alerts = _analyse(NORMAL)
        assert alerts == [], f"benign traffic raised alerts: {alerts}"


@requires_demo_files
class TestSuspiciousCaptureTriggersBothRules:
    """Simulated scan + flood must raise exactly one alert per rule."""

    def test_parses(self):
        packets, _, _ = _analyse(SUSPICIOUS)
        assert len(packets) == 345

    def test_both_alert_types_present(self):
        _, _, alerts = _analyse(SUSPICIOUS)
        types = {a["alert_type"] for a in alerts}
        assert types == {"port_scan", "high_traffic_rate"}

    def test_one_alert_per_source(self):
        _, _, alerts = _analyse(SUSPICIOUS)
        ips = [a["src_ip"] for a in alerts]
        assert len(ips) == len(set(ips))

    def test_port_scan_attributes_correct_source(self):
        _, _, alerts = _analyse(SUSPICIOUS)
        scan = [a for a in alerts if a["alert_type"] == "port_scan"]
        assert len(scan) == 1
        assert scan[0]["src_ip"] == "192.168.1.100"
        assert scan[0]["evidence"]["distinct_ports"] >= 20

    def test_rate_alert_attributes_correct_source(self):
        _, _, alerts = _analyse(SUSPICIOUS)
        rate = [a for a in alerts if a["alert_type"] == "high_traffic_rate"]
        assert len(rate) == 1
        assert rate[0]["src_ip"] == "192.168.1.200"
        assert rate[0]["evidence"]["observed_rate"] >= 100

    def test_innocent_background_host_not_flagged(self):
        """The bystander host in the capture must stay clean."""
        _, _, alerts = _analyse(SUSPICIOUS)
        assert "192.168.1.10" not in {a["src_ip"] for a in alerts}


@requires_demo_files
class TestPipelineDeterminism:
    """The whole pipeline is deterministic for the same file."""

    def test_repeated_runs_are_identical(self):
        _, stats1, alerts1 = _analyse(SUSPICIOUS)
        _, stats2, alerts2 = _analyse(SUSPICIOUS)
        assert stats1 == stats2
        assert alerts1 == alerts2
