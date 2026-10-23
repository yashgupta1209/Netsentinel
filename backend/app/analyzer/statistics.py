"""
statistics.py — Compute traffic statistics from parsed packet records.

All functions accept a list of packet-record dicts (as produced by
``packet_reader.read_pcap``) and return deterministic results.

Counting rules
--------------
- ``total_packets`` counts every record, regardless of protocol.
- ``total_bytes`` sums each record's ``length``; missing/invalid
  lengths count as 0 so that a malformed record cannot corrupt the
  total (e.g. a negative length is clamped to 0).
- IP- and port-based counters ignore records where the relevant field
  is ``None``; those records are never attributed to an invented value.
- Ties in the "top N" lists are broken by the underlying value so the
  output is stable for the same input.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

TOP_N_IPS = 10
TOP_N_PORTS = 20


def compute_statistics(packets: list[dict[str, Any]]) -> dict[str, Any]:
    """Return aggregate statistics for a list of parsed packet records.

    Parameters
    ----------
    packets : list[dict]
        Output of :func:`packet_reader.read_pcap`.

    Returns
    -------
    dict
        Keys:
        - ``total_packets``   – int
        - ``total_bytes``     – int
        - ``protocol_counts`` – dict[str, int]
        - ``top_src_ips``     – list of ``[ip, count]`` (top 10)
        - ``top_dst_ips``     – list of ``[ip, count]`` (top 10)
        - ``dst_port_counts`` – dict[str, int]  (port → count, top 20)
        - ``packets_without_ip`` – int
        - ``packets_without_ports`` – int
    """
    if not packets:
        return _empty_stats()

    total_packets = len(packets)
    total_bytes = 0

    protocol_counter: Counter[str] = Counter()
    src_ip_counter: Counter[str] = Counter()
    dst_ip_counter: Counter[str] = Counter()
    dst_port_counter: Counter[int] = Counter()

    packets_without_ip = 0
    packets_without_ports = 0

    for p in packets:
        protocol_counter[p.get("protocol") or "Unknown"] += 1

        length = p.get("length")
        if isinstance(length, (int, float)) and length > 0:
            total_bytes += int(length)

        src = p.get("src_ip")
        dst = p.get("dst_ip")
        if src is None and dst is None:
            packets_without_ip += 1
        else:
            if src is not None:
                src_ip_counter[src] += 1
            if dst is not None:
                dst_ip_counter[dst] += 1

        dp = p.get("dst_port")
        if dp is None:
            packets_without_ports += 1
        else:
            dst_port_counter[dp] += 1

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "protocol_counts": dict(protocol_counter.most_common()),
        "top_src_ips": _sorted_top(src_ip_counter, TOP_N_IPS),
        "top_dst_ips": _sorted_top(dst_ip_counter, TOP_N_IPS),
        "dst_port_counts": {
            str(port): count
            for port, count in dst_port_counter.most_common(TOP_N_PORTS)
        },
        "packets_without_ip": packets_without_ip,
        "packets_without_ports": packets_without_ports,
    }


def _sorted_top(counter: Counter, limit: int) -> list[list[Any]]:
    """Return ``[[value, count], ...]`` sorted by count desc then value asc."""
    ordered = sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0])))
    return [[value, count] for value, count in ordered[:limit]]


def _empty_stats() -> dict[str, Any]:
    """Return a zeroed-out statistics dict for empty input."""
    return {
        "total_packets": 0,
        "total_bytes": 0,
        "protocol_counts": {},
        "top_src_ips": [],
        "top_dst_ips": [],
        "dst_port_counts": {},
        "packets_without_ip": 0,
        "packets_without_ports": 0,
    }
