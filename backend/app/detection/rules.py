"""
rules.py — Rule-based intrusion detection engine.

Two configurable rules:

  A. **Port-scan detection** — flags a source IP that contacts an
     unusually large number of *distinct* destination ports within a
     time window.
  B. **High-traffic-rate detection** — flags a source IP whose packet
     rate (packets per second) within a window exceeds a threshold.

Alerts describe *suspicious patterns*; they do NOT assert that an
attack definitively occurred.

Design notes
------------
Both rules use a **sliding window** over packets sorted by timestamp,
so out-of-order timestamps in the capture are handled correctly.

To avoid flooding the operator, each rule emits **at most one alert
per source IP per analysis run** — the first window in which that
source crosses the threshold.

Rule B requires a **minimum sample size** (``min_packets``) inside the
window before it will estimate a rate.  Without this guard, two packets
a few milliseconds apart (a normal TCP handshake) produce a
mathematically correct but meaningless "hundreds of packets per second"
reading and raise a spurious alert.

Limitations
-----------
- Detection operates on packet metadata only (IPs, ports, timestamps).
- Connection success/failure cannot be determined from a raw PCAP
  without reconstructing TCP flag sequences (SYN/SYN-ACK/ACK), which
  this rule set does not attempt.  A port-scan alert therefore means
  "many distinct ports were *contacted*", not "open ports were found".
- Packets lacking a timestamp, source IP, or (for Rule A) a
  destination port are skipped by the respective rule rather than
  guessed at.
- Rule B measures the rate across the span actually covered by the
  packets in the window, so a short dense burst is still reported as a
  high rate even though it is brief.  Sustained-vs-bursty
  classification is left to a future rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

# Defaults — exposed as keyword arguments on every rule function so the
# caller (and the API layer) can tune them without editing this module.
DEFAULT_PORT_SCAN_THRESHOLD = 20
DEFAULT_PORT_SCAN_WINDOW = 60.0
# Backwards-compatible alias (same value, shorter name).
DEFAULT_PORT_THRESHOLD = DEFAULT_PORT_SCAN_THRESHOLD
DEFAULT_RATE_THRESHOLD = 100.0
DEFAULT_RATE_WINDOW = 10.0
DEFAULT_MIN_PACKETS = 20


# ---------------------------------------------------------------------------
# Alert data class
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    """A single detection alert."""

    timestamp: float
    alert_type: str
    src_ip: str | None
    severity: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    rule: str = ""
    threshold: Any = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _coerce_port(value: Any) -> int | None:
    """Return *value* as an int port number, or ``None`` if unusable."""
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_timestamp(value: Any) -> float | None:
    """Return *value* as a float timestamp, or ``None`` if unusable."""
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Rule A — Port-Scan Detection
# ---------------------------------------------------------------------------

def detect_port_scan(
    packets: list[dict[str, Any]],
    *,
    port_threshold: int = DEFAULT_PORT_SCAN_THRESHOLD,
    window_seconds: float = DEFAULT_PORT_SCAN_WINDOW,
) -> list[Alert]:
    """Detect source IPs contacting many distinct destination ports.

    Parameters
    ----------
    packets : list[dict]
        Parsed packet records.
    port_threshold : int
        Minimum number of *distinct* destination ports within
        *window_seconds* to trigger an alert.
    window_seconds : float
        Sliding time window in seconds.

    Returns
    -------
    list[Alert]
        At most one alert per offending source IP (the first episode).
    """
    if port_threshold < 1:
        raise ValueError("port_threshold must be >= 1")
    if window_seconds <= 0:
        raise ValueError("window_seconds must be > 0")

    if not packets:
        return []

    # Group packets by source IP, keeping only those that carry both a
    # source IP and a destination port.
    per_src: dict[str, list[tuple[float, int]]] = {}
    for p in packets:
        src = p.get("src_ip")
        if src is None:
            continue
        port = _coerce_port(p.get("dst_port"))
        ts = _coerce_timestamp(p.get("timestamp"))
        if port is None or ts is None:
            continue
        per_src.setdefault(str(src), []).append((ts, port))

    alerts: list[Alert] = []

    for src_ip in sorted(per_src):
        # Sort by timestamp so out-of-order captures are handled.
        entries = sorted(per_src[src_ip], key=lambda e: e[0])

        n = len(entries)
        left = 0
        # Reference count of distinct ports currently inside the window.
        window_ports: dict[int, int] = {}

        for i in range(n):
            ts_i, port_i = entries[i]
            window_ports[port_i] = window_ports.get(port_i, 0) + 1

            # Drop packets that have fallen out of the trailing edge.
            cutoff = ts_i - window_seconds
            while left < i and entries[left][0] < cutoff:
                _, old_port = entries[left]
                window_ports[old_port] -= 1
                if window_ports[old_port] == 0:
                    del window_ports[old_port]
                left += 1

            distinct = len(window_ports)
            if distinct >= port_threshold:
                alerts.append(Alert(
                    timestamp=ts_i,
                    alert_type="port_scan",
                    src_ip=src_ip,
                    severity="high",
                    description=(
                        f"Possible port scan: source {src_ip} contacted "
                        f"{distinct} distinct destination ports within "
                        f"{window_seconds:g}s (threshold: {port_threshold}). "
                        f"This indicates a suspicious pattern, not a "
                        f"confirmed attack."
                    ),
                    evidence={
                        "distinct_ports": distinct,
                        "packets_in_window": i - left + 1,
                        "window_seconds": window_seconds,
                        "sample_ports": sorted(window_ports.keys())[:10],
                    },
                    rule="port_scan",
                    threshold=port_threshold,
                ))
                break  # one alert per source IP per run

    return alerts


# ---------------------------------------------------------------------------
# Rule B — High-Traffic-Rate Detection
# ---------------------------------------------------------------------------

def detect_high_traffic_rate(
    packets: list[dict[str, Any]],
    *,
    rate_threshold: float = DEFAULT_RATE_THRESHOLD,
    window_seconds: float = DEFAULT_RATE_WINDOW,
    min_packets: int = DEFAULT_MIN_PACKETS,
) -> list[Alert]:
    """Detect source IPs sending packets at an unusually high rate.

    Parameters
    ----------
    packets : list[dict]
        Parsed packet records.
    rate_threshold : float
        Packets-per-second threshold.  A source whose observed rate
        within *window_seconds* reaches this value is flagged.
    window_seconds : float
        Sliding time window in seconds.
    min_packets : int
        Minimum number of packets that must fall inside the window
        before a rate is estimated.  This suppresses spurious alerts
        from very small samples (e.g. a two-packet TCP handshake).
        Must be >= 2.

    Returns
    -------
    list[Alert]
        At most one alert per offending source IP (the first episode).
    """
    # Validate configuration first: a bad argument is a programming
    # error and must be reported even when there is no input to process.
    if min_packets < 2:
        raise ValueError("min_packets must be >= 2")
    if window_seconds <= 0:
        raise ValueError("window_seconds must be > 0")

    if not packets:
        return []

    per_src: dict[str, list[float]] = {}
    for p in packets:
        src = p.get("src_ip")
        if src is None:
            continue
        ts = _coerce_timestamp(p.get("timestamp"))
        if ts is None:
            continue
        per_src.setdefault(str(src), []).append(ts)

    alerts: list[Alert] = []

    for src_ip in sorted(per_src):
        timestamps = sorted(per_src[src_ip])

        n = len(timestamps)
        left = 0

        for i in range(n):
            cutoff = timestamps[i] - window_seconds
            while left < i and timestamps[left] < cutoff:
                left += 1

            count_in_window = i - left + 1

            # Not enough evidence to estimate a rate yet.
            if count_in_window < min_packets:
                continue

            span = timestamps[i] - timestamps[left]
            # `span` is the time actually covered by the packets in the
            # window.  It is > 0 because count_in_window >= 2 and the
            # timestamps are sorted (duplicates give span == 0).
            elapsed = span if span > 0 else window_seconds

            rate = count_in_window / elapsed

            if rate >= rate_threshold:
                alerts.append(Alert(
                    timestamp=timestamps[i],
                    alert_type="high_traffic_rate",
                    src_ip=src_ip,
                    severity="medium",
                    description=(
                        f"High traffic rate: source {src_ip} sent "
                        f"{count_in_window} packets in {elapsed:.3f}s "
                        f"({rate:.1f} pkt/s), at or above the configured "
                        f"threshold of {rate_threshold:g} pkt/s. This is a "
                        f"traffic-volume observation, not a confirmed attack."
                    ),
                    evidence={
                        "packets_in_window": count_in_window,
                        "window_seconds": window_seconds,
                        "measured_span_seconds": round(elapsed, 6),
                        "observed_rate": round(rate, 2),
                        "min_packets": min_packets,
                    },
                    rule="high_traffic_rate",
                    threshold=rate_threshold,
                ))
                break  # one alert per source IP per run

    return alerts


# ---------------------------------------------------------------------------
# Convenience wrapper
# ---------------------------------------------------------------------------

def run_all_rules(
    packets: list[dict[str, Any]],
    *,
    port_scan_threshold: int = DEFAULT_PORT_SCAN_THRESHOLD,
    port_scan_window: float = DEFAULT_PORT_SCAN_WINDOW,
    rate_threshold: float = DEFAULT_RATE_THRESHOLD,
    rate_window: float = DEFAULT_RATE_WINDOW,
    rate_min_packets: int = DEFAULT_MIN_PACKETS,
) -> list[dict[str, Any]]:
    """Run every detection rule and return a combined alert list."""
    alerts: list[Alert] = []
    alerts.extend(detect_port_scan(
        packets,
        port_threshold=port_scan_threshold,
        window_seconds=port_scan_window,
    ))
    alerts.extend(detect_high_traffic_rate(
        packets,
        rate_threshold=rate_threshold,
        window_seconds=rate_window,
        min_packets=rate_min_packets,
    ))
    return [a.to_dict() for a in alerts]
