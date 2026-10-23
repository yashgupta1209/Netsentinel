"""
test_api.py — Tests for the FastAPI endpoints.

Uses FastAPI's TestClient (backed by httpx) to exercise the API
without starting a real server.
"""

from __future__ import annotations

import asyncio
import io

import pytest

# FastAPI imports Pydantic, whose core (``pydantic_core``) is a *compiled*
# extension module.  On a machine where the wheel for this platform is not
# installed, importing FastAPI raises ImportError before a single test can
# run.  Rather than let that abort collection for the whole suite, skip this
# module with a reason that names the actual cause.
#
# NOTE: this is an environment limitation, not a reason to weaken coverage.
# On a correctly provisioned environment (see README section 7) this module
# imports normally and all of its tests run.
try:
    from fastapi.testclient import TestClient
    import app.main as _main_module
    from app.main import app, read_upload_bounded
except ImportError as exc:  # pragma: no cover - environment dependent
    pytest.skip(
        f"FastAPI/Pydantic not importable in this environment ({exc}). "
        "Install the backend requirements to run the API tests — see "
        "README section 7.",
        allow_module_level=True,
    )
from app.validation import (
    MAX_UPLOAD_BYTES,
    UPLOAD_CHUNK_BYTES,
    UploadValidationError,
)


class _SlowUpload:
    """A minimal stand-in for FastAPI's UploadFile.

    Reports a ``size`` like the real object and hands back one small
    chunk per ``read()`` call, so tests can observe how much of an
    oversized body actually gets buffered.
    """

    def __init__(self, total, chunk=4096, payload=None):
        self.size = total
        self.chunk = chunk
        self.total = total      # kept so tests can assert "nothing was read"
        self.left = total
        self.payload = payload

    async def read(self, n):
        if self.left <= 0:
            return b""
        size = min(n, self.chunk, self.left)
        start = self.size - self.left
        self.left -= size
        if self.payload is not None:
            return self.payload[start:start + size]
        return b"\x00" * size


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset the in-memory latest-analysis store between tests."""
    _main_module._latest = None
    yield
    _main_module._latest = None


@pytest.fixture
def client():
    return TestClient(app)


# ===================================================================
# Health endpoint
# ===================================================================

class TestHealthEndpoint:
    def test_health_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "version" in data


# ===================================================================
# Analyze endpoint
# ===================================================================

class TestAnalyzeEndpoint:
    def test_valid_pcap_upload(self, client, tcp_pcap_bytes):
        resp = client.post(
            "/analyze",
            files={"file": ("test.pcap", io.BytesIO(tcp_pcap_bytes), "application/octet-stream")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["packets_parsed"] == 2
        assert "statistics" in data
        assert "alerts" in data

    def test_invalid_extension(self, client):
        resp = client.post(
            "/analyze",
            files={"file": ("test.txt", io.BytesIO(b"\x00" * 100), "text/plain")},
        )
        assert resp.status_code == 400

    def test_empty_upload(self, client):
        resp = client.post(
            "/analyze",
            files={"file": ("test.pcap", io.BytesIO(b""), "application/octet-stream")},
        )
        assert resp.status_code == 400

    def test_invalid_content(self, client):
        resp = client.post(
            "/analyze",
            files={"file": ("test.pcap", io.BytesIO(b"not a pcap file content!!"), "application/octet-stream")},
        )
        assert resp.status_code == 400


# ===================================================================
# Stats endpoint
# ===================================================================

class TestStatsEndpoint:
    def test_stats_before_analysis(self, client):
        resp = client.get("/stats")
        assert resp.status_code == 404

    def test_stats_after_analysis(self, client, tcp_pcap_bytes):
        client.post(
            "/analyze",
            files={"file": ("test.pcap", io.BytesIO(tcp_pcap_bytes), "application/octet-stream")},
        )
        resp = client.get("/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_packets"] == 2
        assert data["total_bytes"] > 0


# ===================================================================
# Alerts endpoint
# ===================================================================

class TestAlertsEndpoint:
    def test_alerts_before_analysis(self, client):
        resp = client.get("/alerts")
        assert resp.status_code == 404

    def test_alerts_after_analysis(self, client, tcp_pcap_bytes):
        client.post(
            "/analyze",
            files={"file": ("test.pcap", io.BytesIO(tcp_pcap_bytes), "application/octet-stream")},
        )
        resp = client.get("/alerts")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_alerts_with_detection(self, client, port_scan_pcap_bytes):
        """Upload port-scan traffic and verify an alert is returned."""
        client.post(
            "/analyze",
            files={"file": ("scan.pcap", io.BytesIO(port_scan_pcap_bytes), "application/octet-stream")},
        )
        resp = client.get("/alerts")
        assert resp.status_code == 200
        alerts = resp.json()
        assert len(alerts) >= 1
        assert alerts[0]["alert_type"] == "port_scan"


# ===================================================================
# Upload size policy
# ===================================================================

class TestUploadSizePolicy:
    """An oversized upload must be rejected, not buffered into memory."""

    def test_oversized_upload_returns_413(self, client, tcp_pcap_bytes):
        """Padding the (valid) PCAP makes the body exceed the limit."""
        oversized = tcp_pcap_bytes + b"\x00" * (MAX_UPLOAD_BYTES + 1)
        resp = client.post(
            "/analyze",
            files={"file": ("big.pcap", io.BytesIO(oversized),
                            "application/octet-stream")},
        )
        assert resp.status_code == 413

    def test_bounded_read_does_not_buffer_whole_upload(self):
        """read_upload_bounded must stop at ~limit + one chunk."""
        body = _SlowUpload(total=MAX_UPLOAD_BYTES + 1)
        with pytest.raises(UploadValidationError) as exc:
            asyncio.run(read_upload_bounded(body))
        # Only the bytes actually consumed are buffered before aborting.
        consumed = MAX_UPLOAD_BYTES + 1 - body.left
        assert consumed < MAX_UPLOAD_BYTES + UPLOAD_CHUNK_BYTES
        assert "maximum allowed size" in exc.value.detail

    def test_bounded_read_rejects_declared_oversize_without_reading(self):
        """A declared Content-Length over the limit short-circuits."""
        body = _SlowUpload(total=MAX_UPLOAD_BYTES * 4)
        with pytest.raises(UploadValidationError) as exc:
            asyncio.run(read_upload_bounded(body))
        assert exc.value.status_code == 413
        assert body.left == body.total, "no body should have been read"

    def test_bounded_read_rejects_declared_empty(self):
        body = _SlowUpload(total=0)
        with pytest.raises(UploadValidationError) as exc:
            asyncio.run(read_upload_bounded(body))
        assert exc.value.status_code == 400

    def test_valid_upload_passes_through_intact(self, tcp_pcap_bytes):
        body = _SlowUpload(total=len(tcp_pcap_bytes), payload=tcp_pcap_bytes)
        assert asyncio.run(read_upload_bounded(body)) == tcp_pcap_bytes

    def test_file_with_wrong_extension_rejected(self, client, tcp_pcap_bytes):
        resp = client.post(
            "/analyze",
            files={"file": ("capture.zip", io.BytesIO(tcp_pcap_bytes),
                            "application/octet-stream")},
        )
        assert resp.status_code == 400


# ===================================================================
# API response consistency
# ===================================================================

class TestResponseConsistency:
    """The store, /analyze body, /stats and /alerts must agree."""

    def test_stats_and_alerts_match_analysis_body(self, client, tcp_pcap_bytes):
        analysis = client.post(
            "/analyze",
            files={"file": ("test.pcap", io.BytesIO(tcp_pcap_bytes),
                            "application/octet-stream")},
        )
        assert analysis.status_code == 200
        body = analysis.json()

        stats = client.get("/stats").json()
        alerts = client.get("/alerts").json()

        assert stats == body["statistics"]
        assert alerts == body["alerts"]

    def test_new_analysis_replaces_previous(self, client, tcp_pcap_bytes):
        """A second analysis replaces the first rather than merging."""
        first = client.post(
            "/analyze",
            files={"file": ("a.pcap", io.BytesIO(tcp_pcap_bytes),
                            "application/octet-stream")},
        )
        client.post(
            "/analyze",
            files={"file": ("b.pcap", io.BytesIO(tcp_pcap_bytes),
                            "application/octet-stream")},
        )
        assert client.get("/stats").json() == first.json()["statistics"]

    def test_health_and_docs_available(self, client):
        assert client.get("/health").status_code == 200
        assert client.get("/openapi.json").status_code == 200
        assert client.get("/docs").status_code == 200
        assert client.get("/redoc").status_code == 200
