"""
main.py — FastAPI application for NetSentinel.

Endpoints
---------
GET  /health   — service health check
POST /analyze  — upload a PCAP, get packets + stats + alerts
GET  /stats    — most recent analysis statistics
GET  /alerts   — most recent analysis alerts

State
-----
A simple in-memory store holds the most recent analysis result.
Before any analysis has been run, ``/stats`` and ``/alerts``
return HTTP 404 with an explanatory message.  A new successful
analysis replaces the previous result entirely, so results from
different captures are never merged.

This store is single-process and in-memory: restarting the server,
or running the app with more than one worker, clears or fragments it.
That is acceptable for a single-user local demonstration but would
not be sufficient for real deployment.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import FastAPI, File, HTTPException, UploadFile

from .analyzer.packet_reader import read_pcap_bytes
from .analyzer.statistics import compute_statistics
from .detection.rules import run_all_rules
from .schemas import (
    AlertModel,
    AnalysisResponse,
    HealthResponse,
    StatsResponse,
)
from .validation import (
    MAX_UPLOAD_BYTES,
    UPLOAD_CHUNK_BYTES,
    UploadValidationError,
    validate_filename,
    validate_magic,
    validate_size,
)

if TYPE_CHECKING:  # pragma: no cover
    from typing import Any

app = FastAPI(
    title="NetSentinel",
    description=(
        "Network Traffic Analyzer and Intrusion Detection System — "
        "BCSE308P Computer Networks Lab project (prototype)."
    ),
    version="0.1.0",
)

# ---------------------------------------------------------------------------
# In-memory store for the most recent analysis
# ---------------------------------------------------------------------------
_latest: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _handle_validation_error(exc: UploadValidationError) -> HTTPException:
    """Convert a validation policy error into an HTTP response.

    Only the operator-facing message is returned; internal paths and
    tracebacks are never exposed.
    """
    return HTTPException(status_code=exc.status_code, detail=exc.detail)


async def read_upload_bounded(file: UploadFile) -> bytes:
    """Read an upload in chunks, rejecting it before it is fully buffered.

    Reading the body first and *then* checking its length (the naive
    approach) lets a client pin 10 MiB — or far more, before the server
    can react — of process memory.  Instead we accumulate chunks and
    abort as soon as the limit is exceeded, so memory use is bounded to
    roughly the limit plus one chunk regardless of the request size.
    """
    declared = getattr(file, "size", None)

    if declared == 0:
        raise UploadValidationError(400, "Uploaded file is empty.")
    if declared is not None and declared > MAX_UPLOAD_BYTES:
        raise UploadValidationError(
            413,
            f"File exceeds the maximum allowed size of "
            f"{MAX_UPLOAD_BYTES // (1024 * 1024)} MiB "
            f"({MAX_UPLOAD_BYTES} bytes).",
        )

    body = bytearray()
    while True:
        chunk = await file.read(UPLOAD_CHUNK_BYTES)
        if not chunk:
            break
        body.extend(chunk)
        if len(body) > MAX_UPLOAD_BYTES:
            raise UploadValidationError(
                413,
                f"File exceeds the maximum allowed size of "
                f"{MAX_UPLOAD_BYTES // (1024 * 1024)} MiB "
                f"({MAX_UPLOAD_BYTES} bytes).",
            )
    return bytes(body)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health", response_model=HealthResponse)
def health():
    """Return service health status."""
    return HealthResponse(status="ok", version="0.1.0")


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze(file: UploadFile = File(...)):
    """Accept a PCAP upload, parse it, compute statistics, run rules.

    Returns the full analysis and also stores it so that ``/stats`` and
    ``/alerts`` can serve the most recent result.
    """
    global _latest  # noqa: PLW0603

    # --- 1. filename extension (weak, fast filter only) ---
    try:
        validate_filename(file.filename)
    except UploadValidationError as exc:
        raise _handle_validation_error(exc)

    # --- 2. read with a bounded buffer, then check size and magic ---
    try:
        raw = await read_upload_bounded(file)
        validate_size(len(raw))
        validate_magic(raw)
    except UploadValidationError as exc:
        raise _handle_validation_error(exc)

    # --- 3. parse ---
    # read_pcap_bytes writes to a temp file and deletes it on exit, so the
    # upload is not retained on disk.
    try:
        packets = read_pcap_bytes(raw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # --- 4. analyse ---
    stats = compute_statistics(packets)
    alerts = run_all_rules(packets)

    # A single assignment replaces the whole previous result.
    _latest = {
        "packets_parsed": len(packets),
        "statistics": stats,
        "alerts": alerts,
    }

    return AnalysisResponse(
        packets_parsed=len(packets),
        statistics=StatsResponse(**stats),
        alerts=[AlertModel(**a) for a in alerts],
    )


@app.get("/stats", response_model=StatsResponse)
def get_stats():
    """Return statistics from the most recent successful analysis.

    Before the first successful analysis this returns HTTP 404.
    """
    if _latest is None:
        raise HTTPException(
            status_code=404,
            detail="No analysis has been performed yet. "
            "Upload a PCAP to /analyze first.",
        )
    return StatsResponse(**_latest["statistics"])


@app.get("/alerts", response_model=list[AlertModel])
def get_alerts():
    """Return alerts from the most recent successful analysis.

    Before the first successful analysis this returns HTTP 404.  A
    capture with no suspicious traffic returns an empty list, which is
    the expected (clean) answer rather than a 404.
    """
    if _latest is None:
        raise HTTPException(
            status_code=404,
            detail="No analysis has been performed yet. "
            "Upload a PCAP to /analyze first.",
        )
    return [AlertModel(**a) for a in _latest["alerts"]]
