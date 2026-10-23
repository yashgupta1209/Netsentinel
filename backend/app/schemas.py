"""
schemas.py — Pydantic response models for the FastAPI endpoints.

These models define the public JSON contract of the API.  They are
also used to validate that the values produced by the analyzer and
detection modules have the expected shape before they are returned.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Response body for ``GET /health``."""

    status: str
    version: str


class AlertModel(BaseModel):
    """A single detection alert."""

    timestamp: float
    alert_type: str
    src_ip: str | None = None
    severity: str
    description: str
    # default_factory avoids the shared-mutable-default pitfall.
    evidence: dict[str, Any] = Field(default_factory=dict)
    rule: str = ""
    threshold: Any = None


class StatsResponse(BaseModel):
    """Traffic statistics for a single analysis."""

    total_packets: int
    total_bytes: int
    protocol_counts: dict[str, int]
    top_src_ips: list[list[Any]]
    top_dst_ips: list[list[Any]]
    dst_port_counts: dict[str, int]
    packets_without_ip: int = 0
    packets_without_ports: int = 0


class AnalysisResponse(BaseModel):
    """Response body for ``POST /analyze``."""

    packets_parsed: int
    statistics: StatsResponse
    alerts: list[AlertModel]


class ErrorResponse(BaseModel):
    """Generic error body (FastAPI's default ``{"detail": ...}`` shape)."""

    detail: str
