# Demonstration Commands

A scripted demonstration for NetSentinel. Using `scripts/demo_client.py`
rather than raw PowerShell one-liners keeps the output readable and makes
every step reproducible.

Run everything from the `backend\` directory with the virtual environment
activated:

```powershell
cd "C:\Users\Yash Gupta\OneDrive\Desktop\CLG ACAD\SEM-5\F1 - computer network\CN project\backend"
..\venv\Scripts\Activate.ps1
```

## 0. Prepare

Regenerate the demonstration captures and confirm the dependencies import:

```powershell
python -m scripts.generate_demo_pcaps
```

```powershell
python -c "import scapy, fastapi, uvicorn, pytest, httpx, multipart; print('imports OK')"
```

## 1. Start the backend (terminal 1 — leave this running)

```powershell
python -m uvicorn app.main:app --reload --port 8000
```

Interactive API documentation: **http://127.0.0.1:8000/docs**

## 2. The demonstration sequence (terminal 2)

Every command below prints the HTTP status code and the raw JSON response
body from the server.

```powershell
python -m scripts.demo_client health
```

```powershell
python -m scripts.demo_client analyze data/normal_traffic.pcap
```

```powershell
python -m scripts.demo_client stats
```

```powershell
python -m scripts.demo_client alerts
```

Then the suspicious capture:

```powershell
python -m scripts.demo_client analyze data/suspicious_traffic.pcap
```

```powershell
python -m scripts.demo_client alerts
```

Clean traffic again, to show the alert list empties out:

```powershell
python -m scripts.demo_client analyze data/normal_traffic.pcap
```

```powershell
python -m scripts.demo_client alerts
```

Invalid input handling:

```powershell
python -m scripts.demo_client reject-extension
```

```powershell
python -m scripts.demo_client reject-content
```

## 3. The "before any analysis" case

`GET /stats` and `GET /alerts` return **404** until a successful analysis
has run. Restart the server (terminal 1: `Ctrl+C`, then step 1 again) so the
in-memory store is empty, then in terminal 2:

```powershell
python -m scripts.demo_client stats
```

Expected: `HTTP 404` with `"No analysis has been performed yet. ..."`

## 4. Run the automated tests

```powershell
python -m pytest -v
```

Quiet summary:

```powershell
python -m pytest -q
```

## Notes

- `demo_client.py` uses only the Python standard library, so it needs no
  extra dependency beyond what the project already requires.
- Point it at a different port with `--base-url`, e.g.
  `python -m scripts.demo_client --base-url http://127.0.0.1:9000 health`.
- All traffic used here is synthetic and generated locally. No live
  network interface is used and no external host is contacted.
