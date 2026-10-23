# NetSentinel — Project Notes

Internal record of the first milestone: what was built, why, what is
known to be wrong, and what comes next.

---

## 1. Summary of this milestone

A working prototype that reads a PCAP/PCAPNG file, computes traffic
statistics, runs two rule-based intrusion-detection rules, and exposes all
of it over a FastAPI REST API. Everything is covered by an offline pytest
suite.

The architecture is deliberately layered so that each stage can be tested
in isolation:

```
PCAP file
   |
   v
packet_reader.read_pcap / read_pcap_bytes      -> list[dict]
   |
   v
statistics.compute_statistics                  -> dict
   |
   v
detection.run_all_rules                        -> list[dict]
   |
   v
schemas (Pydantic)  ---------------->  FastAPI endpoints
```

Nothing below the API layer imports FastAPI or Pydantic. That matters in
practice: the analyzer, the statistics engine and the detection rules can
all be exercised with a bare `python` interpreter.

## 2. Design decisions

### 2.1 Packet records are plain dicts

A packet record is a flat dictionary:

```python
{
    "timestamp": 1700000007.6,
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.5",
    "protocol": "TCP",
    "src_port": 40000,
    "dst_port": 20,
    "length": 54,
}
```

Unavailable fields are `None`. The brief explicitly said not to invent
fields that are absent from the capture, so a DNS-over-UDP packet reports
`src_port`/`dst_port` (they really are present at the UDP layer) while an
ICMP packet reports `None` for both.

### 2.2 Protocol naming

Chosen order of precedence: DNS, TCP, UDP, ICMP, ICMPv6, Other-IP,
Non-IP. DNS wins over UDP so that a DNS query does not get double-counted
as generic UDP traffic.

`Other-IP` means "an IP packet with a transport layer we do not name"
(GRE/ESP/IP-in-IP, etc.), and `Non-IP` means no IP layer at all (ARP, a raw
Ethernet frame).

### 2.3 Layer inspection uses `isinstance`, not `haslayer`

This was a real bug worth recording. `Scapy.packet.Packet.haslayer()`
resolves classes through a type-dispatch table, and that mechanism does
**not** resolve the private `_ICMPv6` base class. The result was that every
ICMPv6 packet — echo requests, neighbour solicitations — was classified
as `"Other-IP"`.

`packet_reader._iter_layers()` now walks the `payload` chain and tests
each layer with `isinstance()`, which does work for private base classes.
Covered by `TestPacketReaderICMPv6`.

### 2.4 Timestamps

Scapy stores timestamps as `EDecimal`. A truthiness test
(`if pkt.time else None`) silently converts the valid timestamp `0.0`
into `None`, so `_extract_timestamp()` uses an explicit
`is None` check plus `float()`. Covering that costs a fixture
(`zero_timestamp_pcap`) and two assertions.

### 2.5 Detection rules

Both rules sort packets by timestamp and then use a two-pointer sliding
window, which is O(n) per source IP and handles out-of-order captures.

Each rule emits **at most one alert per source IP per analysis**. Without
this, a 300-packet burst produces several hundred identical alerts, which
is unusable. The consequence is that a second, later episode by the same
host is not reported; that is an accepted trade-off for this milestone.

#### The false positive that mattered

The first version of Rule B estimated rate as
`packets_in_window / max(span, window_seconds)`. Two packets a
millisecond apart — a completely ordinary TCP handshake — therefore
produced 2000 pkt/s and raised a "high traffic rate" alert.

Rule B now has a `min_packets` parameter (default 20): the rate is only
estimated once at least that many packets fall inside the window. The
evidence block reports `measured_span_seconds` so the reader can see that
the window was *not* a full 10 seconds.

This is documented in the module docstring because it is exactly the kind
of thing a reviewer would otherwise assume is intended behaviour.

### 2.6 Upload validation

Validation lives in `app/validation.py`, which deliberately imports
**neither** FastAPI **nor** Pydantic. Reasons:

1. The policy is then directly testable without a web framework, in any
   Python environment.
2. `app.main` and the tests share one implementation instead of each
   re-implementing the rules.

`validate_filename` strips any client-supplied path down to the basename
first, so `..\..\..\shadow` cannot smuggle a valid extension past the
check, and a supplied path is never used to build a filesystem path.

#### The size-limit bug

The first version did:

```python
raw = await file.read()
if len(raw) > MAX_UPLOAD_BYTES:
    raise HTTPException(413, ...)
```

That reads the whole body *before* enforcing the cap, so a client can pin
far more than 10 MiB of process memory. `read_upload_bounded()` in
`app/main.py` now reads in 256 KiB chunks and aborts as soon as the
accumulated size passes the limit, bounding memory to roughly the limit
plus one chunk regardless of request size. It also short-circuits on the
declared `Content-Length`.

### 2.7 API state

`_latest` is a module-level dict holding the most recent successful
analysis. A new analysis replaces it in one assignment, so results from
different captures cannot be mixed.

Before the first successful analysis, `/stats` and `/alerts` return 404.
After it, an analysis of clean traffic returns an **empty list** — that is
the expected "nothing suspicious" answer, not an error. This distinction
is easy to get wrong and worth explaining when someone asks why one case
is 404 and the other is 200.

## 3. Verification

Result: **105 passed, 1 skipped** (one skipped module), stable across
three consecutive full runs of the suite.

The suite defines 124 test cases in total. The 19 in `tests/test_api.py`
are the ones that do not execute here — see below. Component counts:
`test_analyzer.py` 40, `test_detection.py` 32, `test_validation.py` 21,
`test_end_to_end.py` 10, `test_offline_safety.py` 2, `test_api.py` 19.

Executed and passing:

- `tests/test_analyzer.py` — packet reader (PCAP and PCAPNG, IPv4 and
  IPv6, TCP / UDP / ICMP / ICMPv6 / DNS, packets with no IP layer,
  empty captures, malformed input) and the statistics engine.
- `tests/test_detection.py` — both rules, positive and negative cases,
  missing timestamps / IPs / ports, out-of-order timestamps, and alert
  deduplication per source IP.
- `tests/test_validation.py` — filename, size and magic-byte checks,
  including `..\..\shadow`-style path-traversal input.
- `tests/test_end_to_end.py` — full pipeline over the two demo captures,
  asserting 0 alerts on the benign one, 2 on the suspicious one, and
  that `192.168.1.10` (the innocent host in the suspicious capture) is
  never flagged.

Also verified:

- Every `.py` file passes `python -m py_compile` and an `ast.parse`
  check.
- All expected public names resolve from each module.
- The pipeline runs under `-W error`, so no warnings are being hidden.

**Not executed: `tests/test_api.py`** (19 test cases covering `/health`,
`/analyze`, `/stats`, `/alerts`, invalid and empty uploads, and the
404-before-first-analysis behaviour). Importing FastAPI requires
`pydantic_core`, a compiled extension. The venv's copy is a Windows
`.pyd` that cannot be loaded in the Linux environment this milestone was
developed in, and no package index was reachable to install a Linux
build. The module skips itself at collection with that exact reason, so
the rest of the suite still runs cleanly.

`app/main.py`, `app/schemas.py` and `tests/test_api.py` compile and parse
cleanly and were reviewed statically. **The API is not yet verified.** Run
`python -m pytest -v` on Windows first — if anything in `test_api.py`
fails, fix it before claiming the API works. Do not paste test results for
this module until you have actually seen them pass.

### Bugs found and fixed after the first Windows test run

1. **IPv6 fixtures required a live network stack.** `conftest.py` built
   packets with `Ether() / IPv6(...)` and no destination MAC. Scapy fills an
   unset `Ether.dst` by calling `conf.neighbor.resolve`, which for IPv6
   issues a real neighbour-solicitation on the live interface. Without Npcap
   this raised `RuntimeError: ... winpcap is not installed` from *inside the
   fixture*, failing 7 IPv6/ICMPv6 tests and the PCAPNG test with a
   collection error that had nothing to do with the parser. Fixed by giving
   every fixture explicit MACs via a `_eth()` helper, plus an
   `offline_mac_resolver` registered on `conf.neighbor` as a second line of
   defence. `tests/test_offline_safety.py` guards against regression — it was
   verified to fail when a bare `Ether()` is deliberately reintroduced.
   `scripts/generate_demo_pcaps.py` had the same latent bug and was fixed
   identically; the regenerated captures are byte-identical in size and
   statistically identical to the previous ones, and reproduce exactly.

2. **`_SlowUpload` test double was missing its `total` attribute.**
   `test_bounded_read_rejects_declared_oversize_without_reading` asserted
   `body.left == body.total`, but the helper only stored `size`, `chunk`,
   `left` and `payload`. The assertion raised `AttributeError` and the test
   failed. The *implementation* was correct — replaying the real
   `read_upload_bounded` source confirmed it raises 413 for both an
   over-limit and a 4x-over-limit body without reading a single byte. The
   fix was to record `total` on the test double so the assertion can actually
   check what it claims to check. The assertion was **not** weakened.

Both were environment-dependent: they passed in the Linux development
environment and failed on Windows. This is exactly why the API test results
must be confirmed on the target platform rather than assumed.

## 4. Known issues

1. **API not yet executed.** See section 3.
2. **Malformed captures may parse silently.** Scapy is lenient: a file
   with a valid magic but a corrupt body can yield a small number of
   garbage `"Non-IP"` records instead of raising. We surface Scapy's
   errors but do not additionally validate the file header ourselves.
3. **`length` is the reconstructed packet size**, from `len(pkt)` on the
   Scapy packet, not the `wirelen` field in the capture header. For
   truncated captures these differ. `wirelen` would be more accurate for
   the byte total but is only populated reliably in the raw-header case.
4. **No IPv4-in-IPv6 normalisation.** `::ffff:10.0.0.1` and `10.0.0.1`
   count as different hosts.
5. **One alert per source IP per analysis** means later episodes by the
   same host are invisible.
6. **No payload inspection**, so no signature-based detection is possible.
7. **Whole file in memory**, which limits useful capture size.

## 5. Next development steps

In rough order of value:

1. **Run `tests/test_api.py` on Windows and fix whatever breaks.** This is
   the single highest-value next action, because the API is the only part
   of the system that has not been executed.
2. **Connection-state tracking.** Reconstruct TCP SYN/SYN-ACK/ACK per
   5-tuple so Rule A can distinguish a completed connection from a bare
   probe. This is the cheapest upgrade that materially improves
   accuracy.
3. **A second, independent rule.** Something like "many distinct
   destination *hosts* in a short window" (horizontal scan) would broaden
   coverage without much code.
4. **Per-analysis configuration.** Expose thresholds as request
   parameters or a config file so a reviewer can see the rules fire at
   different settings.
5. **Streaming analysis.** `Scapy` can parse a capture incrementally
   (`PcapReader`) instead of loading it whole, which removes the 10 MiB
   limit and the in-memory cap.
6. **Persistence.** PostgreSQL with an `analyses` table and a foreign key
   to `alerts`; replace `_latest` with a query for the most recent row.
7. **WebSocket alert streaming**, then a small frontend.
8. **Calibration.** Measure false-positive rate on a corpus of normal
   captures and tune the defaults. No accuracy number should be
   published before this exists.
