"""
test_detection.py — Tests for the intrusion detection rules.

Synthetic PCAP fixtures are defined in conftest.py.
"""

from __future__ import annotations

import pytest

from app.analyzer.packet_reader import read_pcap
from app.detection.rules import (
    detect_port_scan,
    detect_high_traffic_rate,
    run_all_rules,
    Alert,
)


# ===================================================================
# Port-Scan Detection
# ===================================================================

class TestPortScanDetection:
    """Rule A: port-scan detection."""

    def test_port_scan_triggers(self, port_scan_pcap):
        """30 distinct ports in 15 s should trigger (threshold=20)."""
        records = read_pcap(port_scan_pcap)
        alerts = detect_port_scan(records, port_threshold=20, window_seconds=60)
        assert len(alerts) == 1
        a = alerts[0]
        assert a.alert_type == "port_scan"
        assert a.src_ip == "192.168.1.100"
        assert a.evidence["distinct_ports"] >= 20

    def test_normal_traffic_no_port_scan(self, normal_traffic_pcap):
        """10 packets all to port 80 — should NOT trigger."""
        records = read_pcap(normal_traffic_pcap)
        alerts = detect_port_scan(records, port_threshold=20, window_seconds=60)
        assert len(alerts) == 0

    def test_no_duplicate_alerts(self, port_scan_pcap):
        """Only one alert per source IP per run."""
        records = read_pcap(port_scan_pcap)
        alerts = detect_port_scan(records, port_threshold=5, window_seconds=60)
        src_ips = [a.src_ip for a in alerts]
        assert len(src_ips) == len(set(src_ips))

    def test_missing_fields_safe(self):
        """Packets with missing IPs/ports/timestamps don't crash."""
        records = [
            {"timestamp": None, "src_ip": None, "dst_ip": None,
             "protocol": "TCP", "src_port": None, "dst_port": None,
             "length": 60},
        ]
        alerts = detect_port_scan(records, port_threshold=1, window_seconds=60)
        assert alerts == []

    def test_alert_evidence(self, port_scan_pcap):
        """Alert evidence should contain helpful details."""
        records = read_pcap(port_scan_pcap)
        alerts = detect_port_scan(records, port_threshold=20, window_seconds=60)
        assert len(alerts) == 1
        ev = alerts[0].evidence
        assert "distinct_ports" in ev
        assert "window_seconds" in ev
        assert "sample_ports" in ev


# ===================================================================
# High-Traffic-Rate Detection
# ===================================================================

class TestHighTrafficRateDetection:
    """Rule B: high-traffic-rate detection."""

    def test_high_rate_triggers(self, high_rate_pcap):
        """200 packets in ~1 s ⇒ ~200 pkt/s, threshold=100."""
        records = read_pcap(high_rate_pcap)
        alerts = detect_high_traffic_rate(
            records, rate_threshold=100, window_seconds=10
        )
        assert len(alerts) == 1
        a = alerts[0]
        assert a.alert_type == "high_traffic_rate"
        assert a.src_ip == "192.168.1.200"

    def test_low_rate_no_alert(self, low_rate_pcap):
        """5 packets over 40 s → 0.125 pkt/s → no alert."""
        records = read_pcap(low_rate_pcap)
        alerts = detect_high_traffic_rate(
            records, rate_threshold=100, window_seconds=10
        )
        assert len(alerts) == 0

    def test_missing_timestamps_safe(self):
        """Packets without timestamps are skipped, not crashed."""
        records = [
            {"timestamp": None, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
             "protocol": "TCP", "src_port": 1234, "dst_port": 80,
             "length": 60},
        ]
        alerts = detect_high_traffic_rate(
            records, rate_threshold=1, window_seconds=10
        )
        assert alerts == []

    def test_no_duplicate_alerts_for_same_ip(self, high_rate_pcap):
        records = read_pcap(high_rate_pcap)
        alerts = detect_high_traffic_rate(
            records, rate_threshold=50, window_seconds=10
        )
        src_ips = [a.src_ip for a in alerts]
        assert len(src_ips) == len(set(src_ips))


# ===================================================================
# Combined rules
# ===================================================================

class TestRunAllRules:
    """Test the convenience wrapper."""

    def test_combined_returns_dicts(self, port_scan_pcap):
        records = read_pcap(port_scan_pcap)
        alerts = run_all_rules(records, port_scan_threshold=20, port_scan_window=60)
        assert isinstance(alerts, list)
        for a in alerts:
            assert isinstance(a, dict)
            assert "alert_type" in a

    def test_empty_packets_no_alerts(self):
        alerts = run_all_rules([])
        assert alerts == []


# ===================================================================
# Regression tests — false positives, window maths and safety
# ===================================================================

def _records(packets, src="172.16.0.9", dst="10.0.0.1"):
    """Build packet records directly, bypassing PCAP I/O for pure logic tests."""
    out = []
    for ts, port in packets:
        out.append({
            "timestamp": ts,
            "src_ip": src,
            "dst_ip": dst,
            "protocol": "TCP",
            "src_port": 5000,
            "dst_port": port,
            "length": 60,
        })
    return out


class TestHighRateNoFalsePositives:
    """A brief burst of very few packets is not a high-traffic-rate event.

    Two packets a millisecond apart produce a mathematically enormous
    rate, but with no traffic volume behind it.  The rule therefore
    requires a minimum sample size before estimating a rate.
    """

    def test_two_packet_burst_does_not_alert(self):
        """Ordinary TCP handshake / request-response shape."""
        alerts = detect_high_traffic_rate(
            _records([(1000.0, 443), (1000.001, 443)]),
            rate_threshold=100, window_seconds=10,
        )
        assert alerts == []

    def test_three_packet_burst_does_not_alert(self):
        alerts = detect_high_traffic_rate(
            _records([(1000.0, 443), (1000.01, 443), (1000.02, 443)]),
            rate_threshold=100, window_seconds=10,
        )
        assert alerts == []

    def test_small_sample_size_can_be_required(self):
        """min_packets controls the guard and is honoured."""
        packets = _records([(1000.0 + i * 0.001, 443) for i in range(200)])
        assert len(detect_high_traffic_rate(
            packets, rate_threshold=100, window_seconds=10, min_packets=200,
        )) == 1
        assert detect_high_traffic_rate(
            packets, rate_threshold=100, window_seconds=10, min_packets=201,
        ) == []

    def test_min_packets_below_two_is_rejected(self):
        with pytest.raises(ValueError):
            detect_high_traffic_rate([], rate_threshold=1, min_packets=1)

    def test_sustained_moderate_rate_does_not_alert(self):
        """25 packets over 24 s is ~1 pkt/s — well under the threshold."""
        alerts = detect_high_traffic_rate(
            _records([(1000.0 + i * 1.0, 443) for i in range(25)]),
            rate_threshold=100, window_seconds=10,
        )
        assert alerts == []


class TestHighRatePositiveStillFires:
    """The rule must still detect a genuine high-rate burst."""

    def test_dense_burst_fires(self):
        """200 packets in ~1 s."""
        alerts = detect_high_traffic_rate(
            _records([(1000.0 + i * 0.005, 443) for i in range(200)]),
            rate_threshold=100, window_seconds=10,
        )
        assert len(alerts) == 1
        a = alerts[0]
        assert a.alert_type == "high_traffic_rate"
        assert a.evidence["observed_rate"] >= 100

    def test_rate_reported_matches_span(self):
        """Evidence reports the measured span, not the window width."""
        alerts = detect_high_traffic_rate(
            _records([(1000.0 + i * 0.005, 443) for i in range(200)]),
            rate_threshold=100, window_seconds=10,
        )
        a = alerts[0]
        assert 0 < a.evidence["measured_span_seconds"] < 10

    def test_burst_outside_window_does_not_alert(self):
        """200 packets spread over 99 s is ~2 pkt/s, not a flood."""
        alerts = detect_high_traffic_rate(
            _records([(1000.0 + i * 0.5, 443) for i in range(200)]),
            rate_threshold=100, window_seconds=10,
        )
        assert alerts == []


class TestDetectionSafety:
    """Malformed or unusual inputs are handled without crashing."""

    def test_unsorted_timestamps_still_detected(self):
        """Rule A sorts internally, so capture order does not matter."""
        scrambled = [
            (1000.0 + (30 - i) * 0.5, 1 + i) for i in range(30)
        ]
        alerts = detect_port_scan(
            _records(scrambled), port_threshold=20, window_seconds=60,
        )
        assert len(alerts) == 1

    def test_non_numeric_ports_are_skipped(self):
        records = [
            {"timestamp": 1.0, "src_ip": "1.1.1.1", "dst_ip": None,
             "protocol": "TCP", "src_port": 1, "dst_port": "not-a-port",
             "length": 60},
        ]
        assert detect_port_scan(records, port_threshold=1) == []
        assert detect_high_traffic_rate(records, rate_threshold=1) == []

    def test_bool_and_none_ports_are_skipped(self):
        records = _records([(1.0, 80)])
        records[0]["dst_port"] = None
        assert detect_port_scan(records, port_threshold=1) == []

    def test_two_source_ips_independently_alerted(self):
        """Each offending source gets its own alert."""
        records = []
        for i in range(25):
            records.append({
                "timestamp": 1000.0 + i * 0.5,
                "src_ip": "10.0.0.50", "dst_ip": "10.0.0.1",
                "protocol": "TCP", "src_port": 1, "dst_port": 1 + i,
                "length": 60,
            })
        alerts = detect_port_scan(records, port_threshold=20, window_seconds=60)
        assert [a.src_ip for a in alerts] == ["10.0.0.50"]

    def test_empty_input_returns_empty_list(self):
        assert detect_port_scan([]) == []
        assert detect_high_traffic_rate([]) == []


class TestAlertContract:
    """Alerts carry the fields the brief requires."""

    def test_alert_contains_required_fields(self, port_scan_pcap):
        alerts = detect_port_scan(
            read_pcap(port_scan_pcap), port_threshold=20, window_seconds=60
        )
        a = alerts[0].to_dict()
        for key in (
            "timestamp", "alert_type", "src_ip", "severity",
            "description", "evidence", "rule", "threshold",
        ):
            assert key in a, f"missing alert field: {key}"

    def test_alert_describes_suspicion_not_certainty(self, port_scan_pcap):
        """Alerts must describe a suspicious pattern, not assert an attack."""
        alerts = detect_port_scan(
            read_pcap(port_scan_pcap), port_threshold=20, window_seconds=60
        )
        text = " ".join(a.description.lower() for a in alerts)
        assert "possible" in text or "suspicious" in text
        # No overreaching certainty language.
        assert "confirmed attack" not in text.replace("not a confirmed", "")
        assert "successful connection" not in text
        assert "open ports found" not in text

    def test_evidence_reports_distinct_ports_not_packets(self, port_scan_pcap):
        """Rule A counts *distinct* ports."""
        alerts = detect_port_scan(
            read_pcap(port_scan_pcap), port_threshold=20, window_seconds=60
        )
        a = alerts[0]
        assert a.evidence["distinct_ports"] >= 20
        assert a.evidence["packets_in_window"] >= a.evidence["distinct_ports"]


class TestRuleConfigurationValidation:
    """Invalid rule configuration is a programming error and must be reported."""

    def test_port_scan_rejects_zero_threshold(self):
        with pytest.raises(ValueError):
            detect_port_scan([], port_threshold=0)

    def test_port_scan_rejects_nonpositive_window(self):
        with pytest.raises(ValueError):
            detect_port_scan([], window_seconds=0)

    def test_rate_rule_rejects_nonpositive_window(self):
        with pytest.raises(ValueError):
            detect_high_traffic_rate([], window_seconds=0)

    def test_rate_rule_rejects_small_min_packets(self):
        with pytest.raises(ValueError):
            detect_high_traffic_rate([], min_packets=1)

    def test_valid_configuration_is_accepted(self):
        assert detect_port_scan([], port_threshold=1, window_seconds=1) == []
        assert detect_high_traffic_rate(
            [], rate_threshold=1, window_seconds=1, min_packets=2
        ) == []
