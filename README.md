# NetSentinel

**Network Traffic Analyzer and Intrusion Detection System**

A prototype for **BCSE308P — Computer Networks Lab**.

| Team member | Roll number |
| --- | --- |
| Yash Gupta | 24BCE0759 |
| Sapandeep Kour | 24BCE0960 |
| Ritesh Yadav | 24BCE0892 |
| Shaunak Dutta | 24BCE2058 |

> **Status: prototype / first milestone.** This is a teaching project, not a
> production IDS. It runs two transparent, rule-based detectors over a static
> PCAP file. It is not a live monitor, does not use machine learning, and has
> no database or web frontend. See [Limitations](#current-limitations).

---

## 1. Introduction

NetSentinel reads a saved PCAP capture, reports what is in it, and flags
traffic patterns that look like reconnaissance or flooding. The idea is to
demonstrate, through a small working system, the packet and transport
layers that a computer-networks course covers: Ethernet framing, IPv4 and
IPv6 addressing, the TCP/UDP/ICMP/DNS protocols, and how a network
intrusion detection system actually decides that something is unusual.

The important design constraint is **transparency**. Every alert points at
the concrete numbers behind it — which source IP, how many distinct
destination ports, over what time span, against which threshold. There is
no black-box classifier and no invented labels: an alert always means the
traffic matched a rule we can show you, and it never claims an attack was
confirmed.

## 2. Problem statement

Real intrusion detection is often presented as a magic box: data goes in,
"attack detected" comes out. For a Computer Networks course we wanted a
system that instead makes the reasoning visible:

- Which fields of a real packet are actually available, and which are
  absent?
- How do you count packets, bytes, protocols and ports in a consistent way?
- What does "this host is scanning ports" mean precisely, and what would it
  *not* be fair to conclude from a capture alone?
- How do you avoid alarming on ordinary traffic?

NetSentinel answers these questions with a small, fully testable codebase.

## 3. Objectives

1. Parse PCAP and PCAPNG captures with Scapy and extract only fields that
   are genuinely present.
2. Compute traffic statistics that are deterministic and correct for known
   fixtures.
3. Implement two rule-based detectors whose thresholds are configurable and
   whose alerts carry supporting evidence.
4. Expose the pipeline over a FastAPI REST API with strict upload
   validation.
5. Prove the behaviour with a repeatable pytest suite that needs no network
   access and no administrator rights.

## 4. Implemented features

| Area | What exists |
| --- | --- |
| Packet reading | PCAP and PCAPNG, IPv4 + IPv6, TCP / UDP / ICMP / ICMPv6 / DNS classification, source & destination ports, timestamps, packet length. Missing fields come back as `null`. |
| Statistics | Packet count, byte total, per-protocol counts, top source/destination IPs, destination-port distribution, and counts of packets lacking an IP address or a port. |
| Detection | Rule A — possible port scan (distinct destination ports in a window). Rule B — high traffic rate (packets per second in a window, with a minimum sample size). At most one alert per source IP per analysis. |
| API | `GET /health`, `POST /analyze`, `GET /stats`, `GET /alerts`, plus FastAPI's `/docs`, `/redoc` and `/openapi.json`. |
| Upload safety | Filename check, content magic-byte check, 10 MiB cap enforced *before* the body is fully buffered, temp files always cleaned up, no client-supplied paths honoured. |
| Tests | 124 test cases across 6 modules; 105 executed and passing here, 19 API tests pending a Windows run. |
| Demo data | A generator that produces a benign capture and a suspicious one. |

## 5. Technology stack

- **Python 3.10+** (developed against 3.14)
- **Scapy** — PCAP/PCAPNG parsing and synthetic packet generation
- **FastAPI** — REST API and automatic OpenAPI documentation
- **Uvicorn** — ASGI server
- **Pydantic** — response schema validation
- **pytest** — automated tests

## 6. Project structure

```
.
├── README.md
├── .gitignore
├── docs/
│   └── project_notes.md          # design decisions, known issues, roadmap
└── backend/
    ├── requirements.txt
    ├── app/
    │   ├── main.py               # FastAPI app, endpoints, bounded upload read
    │   ├── schemas.py            # Pydantic response models
    │   ├── validation.py         # upload policy (filename/size/magic bytes)
    │   ├── analyzer/
    │   │   ├── packet_reader.py  # PCAP -> packet records
    │   │   └── statistics.py     # packet records -> statistics
    │   └── detection/
    │       └── rules.py          # Rule A and Rule B
    ├── data/
    │   ├── README.md
    │   ├── normal_traffic.pcap           # generated, benign
    │   └── suspicious_traffic.pcap       # generated, simulated attack
    ├── scripts/
    │   └── generate_demo_pcaps.py        # writes the two captures above
    └── tests/
        ├── conftest.py                  # synthetic PCAP fixtures
        ├── test_analyzer.py             # packet reader + statistics
        ├── test_detection.py            # both detection rules
        ├── test_validation.py           # upload policy
        ├── test_api.py                  # endpoints (FastAPI TestClient)
        └── test_end_to_end.py           # full pipeline over demo captures
```

## 7. Setup (Windows / PowerShell)

A virtual environment already exists at `venv\` in the project root,
created with Python 3.14. To reuse it:

```powershell
cd "C:\Users\Yash Gupta\OneDrive\Desktop\CLG ACAD\SEM-5\F1 - computer network\CN project"
.\venv\Scripts\Activate.ps1
python --version
```

If the environment does not exist or you are starting fresh:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
cd backend
python -m pip install -r requirements.txt
```

Verify the imports:

```powershell
python -c "import scapy, fastapi, uvicorn, pytest, httpx, multipart; print('all imports OK')"
```

Regenerate the demonstration captures (optional — they are already present):

```powershell
python -m scripts.generate_demo_pcaps
```

## 8. Running the API

From the `backend\` directory, with the environment activated:

```powershell
python -m uvicorn app.main:app --reload --port 8000
```

The server prints `Application startup complete.` and:

- **Interactive docs (Swagger UI):** http://127.0.0.1:8000/docs
- **Alternative docs (ReDoc):** http://127.0.0.1:8000/redoc
- **OpenAPI spec:** http://127.0.0.1:8000/openapi.json

## 9. Running the tests

From the `backend\` directory:

```powershell
python -m pytest -v
```

The suite is fully offline: all PCAP data is synthesised in memory with
Scapy during the test run, so no internet connection, network interface or
administrator privilege is required.

## 10. API endpoints

### `GET /health`

Returns `{"status": "ok", "version": "0.1.0"}`.

### `POST /analyze`

Uploads a capture file as multipart form data under the field name
`file`.

| Check | Failure status |
| --- | --- |
| Filename must end in `.pcap` or `.pcapng` | 400 |
| Body must not be empty | 400 |
| Body must not exceed 10 MiB | 413 |
| First 4 bytes must be a PCAP or PCAPNG magic | 400 |
| Content must parse as a capture | 400 |

A successful response contains `packets_parsed`, `statistics` and `alerts`,
and it becomes the value served by `/stats` and `/alerts`.

> **State model.** A new successful analysis **replaces** the previous
> result in its entirety — results from different captures are never
> merged. The store is single-process and in-memory, so restarting the
> server clears it. That is acceptable for a local single-user demo and
> would not be acceptable for real deployment.

Before the first successful analysis, `GET /stats` and `GET /alerts`
return **404** with an explanatory message. After the first analysis, an
analysis of clean traffic returns an **empty list** for `/alerts` — that is
the expected "nothing suspicious" answer, not an error.

### `GET /stats`

Statistics from the most recent successful analysis. **404** before the
first analysis.

### `GET /alerts`

Alerts from the most recent successful analysis. **404** before the first
analysis; an empty array when traffic was clean.

## 11. Synthetic test data

`backend/scripts/generate_demo_pcaps.py` builds two captures with Scapy and
writes them to `backend/data/`. It uses a fixed epoch base (`1700000000.0`)
so the output is reproducible.

`normal_traffic.pcap` — 31 packets from a single client: HTTP requests to
port 80, HTTPS sessions to port 443, three DNS lookups, and three ICMP
echoes to the gateway. Spread over several tens of seconds at a low rate.

`suspicious_traffic.pcap` — 345 packets:

- a **simulated port scan**: `192.168.1.100` → `10.0.0.5`, 40 distinct
  destination ports (20–59) probed at 2.5 packets/second;
- a **simulated flood**: `192.168.1.200` → `10.0.0.5:80`, 300 packets in
  about 1.5 seconds;
- **innocent background traffic**: `192.168.1.10` sending five DNS queries.

The tests assert that the innocent host is never flagged, which is the
property that matters in a real detector.

## 12. Detection rules

Both rules use a **sliding window** over packets sorted by timestamp, so
out-of-order captures are handled, and each emits **at most one alert per
source IP per analysis** so the operator is not flooded.

### Rule A — possible port scan

| Parameter | Default |
| --- | --- |
| `port_threshold` | 20 distinct destination ports |
| `window_seconds` | 60 |

Counts **distinct destination ports** rather than packets, so one host
transmitting a large file on a single port is not flagged.

The capture does not record whether a connection succeeded. The rule
therefore reports that ports were *contacted*, and never that any of them
were open.

### Rule B — high traffic rate

| Parameter | Default |
| --- | --- |
| `rate_threshold` | 100 packets/second |
| `window_seconds` | 10 |
| `min_packets` | 20 |

The rate is measured across the span actually covered by the packets inside
the window. `min_packets` suppresses alerts from very small samples: two
packets a millisecond apart is a mathematically enormous rate but is just an
ordinary TCP handshake, so it must not raise an alert. The evidence block
reports both the measured span and the configured window width.

### Alerts

Every alert carries: `timestamp`, `alert_type`, `src_ip`, `severity`,
`description`, `evidence`, `rule` and `threshold`.

Alert text describes a **suspicious pattern**, never a confirmed attack.

## 13. Demonstration procedure

Prepare once:

```powershell
cd "C:\Users\Yash Gupta\OneDrive\Desktop\CLG ACAD\SEM-5\F1 - computer network\CN project\backend"
..\venv\Scripts\Activate.ps1
python -m scripts.generate_demo_pcaps
```

**Step 1 — start the backend** (terminal 1):

```powershell
python -m uvicorn app.main:app --reload --port 8000
```

**Step 2 — open the documentation** in a browser:
http://127.0.0.1:8000/docs

**Step 3 — confirm the service is up** (terminal 2):

```powershell
python -c "import urllib.request,json; print(json.load(urllib.request.urlopen('http://127.0.0.1:8000/health')))"
```

Expect: `{'status': 'ok', 'version': '0.1.0'}`

**Steps 4–7 — the upload part is easiest in Swagger UI.**

On http://127.0.0.1:8000/docs choose `POST /analyze`, click **Try it out**,
select the file, then **Execute**. The response is right there, and the
`/stats` and `/alerts` calls can be run with **Try it out** too.

Recommended sequence:

1. Upload `data\normal_traffic.pcap` — note the statistics and that
   `alerts` is `[]`.
2. Upload `data\suspicious_traffic.pcap` — show the two alerts.
3. Call `GET /alerts` — the same two alerts come back.
4. Re-upload `data\normal_traffic.pcap` — `/alerts` is `[]` again.
5. Try uploading a text file renamed to `.pcap` — you get a controlled
   `400` response.

If you prefer the command line, `docs\demo_commands.md` has copy-pasteable
commands for every step.

**Expected results from the bundled captures.**

`normal_traffic.pcap` — 31 packets, 2241 bytes, protocols
`{"TCP": 25, "DNS": 3, "ICMP": 3}`, **0 alerts**.

`suspicious_traffic.pcap` — 345 packets, 48715 bytes, **2 alerts**:

- `port_scan`, severity `high`, source `192.168.1.100` — 20 distinct
  destination ports within 60 s, sample ports `[20, 21, 22, ...]`
- `high_traffic_rate`, severity `medium`, source `192.168.1.200` —
  20 packets in 0.095 s ≈ 210.5 pkt/s against a 100 pkt/s threshold

In the suspicious capture, `192.168.1.10` also sends five DNS queries. It is
**not** flagged, which is the property worth pointing out to the faculty.

**Step 8 — run the tests:**

```powershell
python -m pytest -v
```

## 14. Current limitations

Honest list of what this prototype does **not** do.

1. **No live monitoring.** Traffic is only ever read from a saved file.
2. **No connection state.** TCP flag sequences are not reconstructed, so
   Rule A cannot tell a completed connection from a probe.
3. **Heuristic, threshold-based detection.** Expect false positives on
   unusual but legitimate traffic (a build server running a large port
   scan, a backup job). Thresholds are defaults, not calibrated values.
4. **No false-positive rate measurement.** No accuracy percentage is
   claimed anywhere. The tests prove the rules behave as specified on
   synthetic fixtures; they do not measure detection accuracy against real
   attacks.
5. **In-memory single-process state.** Restarting the server or running
   multiple workers loses or fragments the stored analysis.
6. **No authentication, no database, no history.**
7. **No frontend.** API documentation only.
8. **Two rules only.** No signature database, no anomaly baseline.
9. **Small captures only** (10 MiB upload cap, whole file held in memory).
10. **IPv4-mapped and tunneled IPv6 addresses are not normalised**, so
    `::ffff:10.0.0.1` and `10.0.0.1` would count as different hosts.

## 15. Planned, not implemented

For reference — none of these exist in this milestone:

- live packet capture via Scapy / `np.cap`
- PostgreSQL persistence and analysis history
- WebSocket streaming of alerts to a dashboard
- a Next.js frontend
- signature-based detection with a rule database
- anomaly detection or machine-learning classification
- multi-process-safe state (Redis or a database)
- packet payload inspection and protocol-specific parsers
- authentication and role-based access

## 16. Verification status

The suite defines **124 test cases** across six modules. In the Linux
environment used to develop this milestone, **105 executed and passed**;
the remaining 19 are in `tests/test_api.py`, which skips itself at
collection (reason below). On a Windows machine with the requirements
installed, all 124 should run.

Measured in this environment: 105 passed, 1 skipped (the module-level
skip), stable across three consecutive full runs.

**Executed and passing** (stable across three consecutive full runs):

- `tests/test_analyzer.py` — packet reader (PCAP + PCAPNG, IPv4 + IPv6,
  TCP/UDP/ICMP/ICMPv6/DNS, missing layers, empty and malformed input) and
  the statistics engine.
- `tests/test_detection.py` — both detection rules, positive and negative,
  missing fields, out-of-order timestamps, alert deduplication.
- `tests/test_validation.py` — filename, size, and magic-byte validation
  including path-traversal inputs.
- `tests/test_end_to_end.py` — the whole pipeline over the demo captures,
  asserting the alert count and that the innocent host is never flagged.
- `tests/test_offline_safety.py` — guards that the suite stays hermetic
  (no fixture may trigger live MAC resolution).

**Not executed here** — `tests/test_api.py` (19 test cases) covers
`/health`, `/analyze`, `/stats`, `/alerts`, invalid uploads, empty
uploads, and the 404-before-first-analysis behaviour. Importing FastAPI
requires `pydantic_core`, a compiled extension module. The virtual
environment's copy is a Windows `.pyd` and cannot be loaded in the Linux
authoring environment used to develop this milestone, and no package
index was reachable to install a Linux build. The module therefore skips
itself with that reason rather than erroring at collection.

`app/main.py` and `app/schemas.py` additionally passed a syntax
(`py_compile`) and AST check, and their endpoint logic was reviewed
statically. **Run `python -m pytest -v` on Windows to confirm the API
tests pass before treating the API as verified.**

Every test is deterministic and offline: all PCAP fixtures are built with
Scapy in memory at run time.
