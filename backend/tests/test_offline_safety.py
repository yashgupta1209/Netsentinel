"""
test_offline_safety.py — Guards that the test suite stays hermetic.

These tests exist because of a real bug: fixtures built with ``Ether() /
IPv6(...)`` and an unset destination MAC caused Scapy to perform a *live*
neighbour-solicitation while merely constructing a packet.  On a Windows
host without Npcap that raised
``RuntimeError: ... winpcap is not installed`` from inside a fixture, which
made the whole suite fail for a reason that had nothing to do with the code
under test.

Requirement they protect: the test suite must not need a network interface,
a packet socket, or administrator rights.
"""

from __future__ import annotations

import pathlib
import re

from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6

from tests.conftest import _eth


def test_fixtures_never_touch_the_live_network():
    """Building an IPv6 fixture must not trigger live neighbour discovery.

    Regression guard: ``Ether() / IPv6(...)`` with an unset destination MAC
    makes Scapy issue a real neighbour-solicitation, which raises
    ``RuntimeError: ... winpcap is not installed`` on a Windows host without
    Npcap.  That turned a pure data-construction step into a network
    dependency.  If this test fails, a fixture has reintroduced a bare
    ``Ether()``.
    """
    from scapy.layers.inet6 import IPv6 as _IPv6, ICMPv6EchoRequest as _Echo

    pkt = _eth() / _IPv6(src="2001:db8::1", dst="2001:db8::2") / _Echo()
    raw = bytes(pkt)          # this is the call that used to hit the network
    assert raw, "packet failed to serialise"
    assert pkt[_IPv6].dst == "2001:db8::2"


def test_no_source_file_builds_a_bare_ether():
    """No module may construct ``Ether()`` without explicit addresses."""
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parent.parent
    offenders = []
    for path in list(root.glob("app/**/*.py")) + list(root.glob("scripts/**/*.py")):
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), 1):
            if re.search(r"\bEther\(\s*\)", line) and not line.strip().startswith("#"):
                offenders.append(f"{path.relative_to(root)}:{lineno}")
    assert not offenders, (
        "Bare Ether() would resolve MACs over the live network: " + ", ".join(offenders)
    )
