"""
packet_reader.py — Read PCAP files and extract structured packet records.

Uses Scapy to parse PCAP/PCAPNG files and extracts:
  - Timestamp, source/destination IP (v4 and v6), protocol,
    source/destination port, and packet length.

Unavailable fields are represented as None.
"""

from __future__ import annotations

import os
import tempfile
from typing import Any

from scapy.all import (
    rdpcap,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    DNS,
    Packet,
)

# Scapy's generic ICMPv6 base class.  All ICMPv6 message types
# (echo, neighbour discovery, ...) inherit from it.
try:  # pragma: no cover - import location differs across Scapy versions
    from scapy.layers.inet6 import _ICMPv6 as _ICMPv6Base
except ImportError:
    _ICMPv6Base = None  # type: ignore[assignment]

# Scapy classes that carry a transport-layer *port* pair.
_PORT_LAYERS = (TCP, UDP)


def _iter_layers(pkt: Packet):
    """Yield each Scapy layer in *pkt* from outermost to innermost.

    Scapy's own ``haslayer()`` relies on a type-dispatch table that does
    not resolve some base classes (notably the private ``_ICMPv6``), so
    we walk the ``payload`` chain and test with ``isinstance`` instead.
    """
    seen: set[int] = set()
    layer: Any = pkt
    while isinstance(layer, Packet) and id(layer) not in seen:
        seen.add(id(layer))
        yield layer
        layer = layer.payload


def _identify_protocol(pkt: Packet) -> str:
    """Return a human-readable protocol name for *pkt*.

    Checks layers from most-specific to least-specific so that, e.g.,
    a DNS-over-UDP packet is labelled ``"DNS"`` rather than ``"UDP"``.
    ICMPv6 (including NDP and echo) is labelled ``"ICMPv6"``.
    """
    layers = list(_iter_layers(pkt))

    if any(isinstance(layer, DNS) for layer in layers):
        return "DNS"
    if any(isinstance(layer, TCP) for layer in layers):
        return "TCP"
    if any(isinstance(layer, UDP) for layer in layers):
        return "UDP"
    if any(isinstance(layer, ICMP) for layer in layers):
        return "ICMP"
    if _ICMPv6Base is not None and any(
        isinstance(layer, _ICMPv6Base) for layer in layers
    ):
        return "ICMPv6"
    if any(isinstance(layer, (IP, IPv6)) for layer in layers):
        return "Other-IP"
    return "Non-IP"


def _extract_timestamp(pkt: Packet) -> float | None:
    """Return the packet timestamp as a float, or ``None`` if unavailable.

    ``pkt.time`` may be ``None`` (no timestamp) or a Scapy ``EDecimal``
    (including a legitimate ``0``).  A truthiness check is therefore
    wrong: it would discard the valid timestamp ``0``.
    """
    raw_time = getattr(pkt, "time", None)
    if raw_time is None:
        return None
    try:
        return float(raw_time)
    except (TypeError, ValueError):
        return None


def _extract_record(pkt: Packet) -> dict[str, Any]:
    """Convert a single Scapy packet into a flat dictionary."""
    record: dict[str, Any] = {
        "timestamp": _extract_timestamp(pkt),
        "src_ip": None,
        "dst_ip": None,
        "protocol": _identify_protocol(pkt),
        "src_port": None,
        "dst_port": None,
        "length": len(pkt),
    }

    layers = list(_iter_layers(pkt))

    # IPv4 / IPv6 addresses
    for layer in layers:
        if isinstance(layer, IP):
            record["src_ip"] = layer.src
            record["dst_ip"] = layer.dst
            break
        if isinstance(layer, IPv6):
            record["src_ip"] = layer.src
            record["dst_ip"] = layer.dst
            break

    # Transport-layer ports (TCP/UDP only; ICMP has no ports)
    for layer in layers:
        if isinstance(layer, _PORT_LAYERS):
            record["src_port"] = int(layer.sport)
            record["dst_port"] = int(layer.dport)
            break

    return record


def read_pcap(file_path: str) -> list[dict[str, Any]]:
    """Read a PCAP/PCAPNG file and return a list of packet records.

    Parameters
    ----------
    file_path : str
        Path to a ``.pcap`` or ``.pcapng`` file.

    Returns
    -------
    list[dict]
        One dictionary per packet.  Missing fields are ``None``.

    Raises
    ------
    FileNotFoundError
        If *file_path* does not exist or is not a regular file.
    ValueError
        If the file cannot be parsed as a PCAP.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    try:
        packets = rdpcap(file_path)
    except Exception as exc:
        raise ValueError(f"Failed to read PCAP file: {exc}") from exc

    if len(packets) == 0:
        return []

    return [_extract_record(pkt) for pkt in packets]


def _write_all(fd: int, data: bytes) -> None:
    """Write *data* to file descriptor *fd*, handling partial writes."""
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written == 0:  # pragma: no cover - defensive
            raise OSError("os.write returned 0; disk may be full")
        view = view[written:]


def read_pcap_bytes(raw: bytes | bytearray | memoryview) -> list[dict[str, Any]]:
    """Parse PCAP content supplied as raw bytes (e.g. from an upload).

    Writes *raw* to a temporary file, parses it, then deletes the file.
    The temporary file is always removed, even on parse failure.

    Returns
    -------
    list[dict]
        Same format as :func:`read_pcap`.

    Raises
    ------
    ValueError
        If *raw* is empty or is not valid PCAP content.
    """
    if not raw:
        raise ValueError("Empty PCAP data")

    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise ValueError(
            f"Expected bytes-like PCAP data, got {type(raw).__name__}"
        )

    raw = bytes(raw)

    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".pcap")
    try:
        _write_all(tmp_fd, raw)
        os.close(tmp_fd)
        tmp_fd = -1
        return read_pcap(tmp_path)
    finally:
        if tmp_fd != -1:
            try:
                os.close(tmp_fd)
            except OSError:
                pass
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
