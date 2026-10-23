"""
validation.py — Upload validation rules for the /analyze endpoint.

This module is deliberately free of any FastAPI or Pydantic import so
that the validation policy can be unit-tested without starting a web
server, and so that the API layer and the tests share one implementation.

The functions here *raise* :class:`UploadValidationError` (a plain
exception carrying the intended HTTP status code) rather than returning
FastAPI ``HTTPException`` objects; ``app.main`` translates them.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Policy constants
# ---------------------------------------------------------------------------

#: Maximum accepted upload size in bytes (10 MiB).
MAX_UPLOAD_BYTES = 10 * 1024 * 1024

#: Read the request body in chunks of this size so that an oversized
#: upload is rejected *before* it is fully buffered in memory.
UPLOAD_CHUNK_BYTES = 256 * 1024

#: Accepted filename extensions.
ALLOWED_EXTENSIONS = (".pcap", ".pcapng")

#: Magic byte prefixes for the capture formats we accept.
#:   d4c3b2a1 - classic PCAP, little-endian
#:   a1b2c3d4 - classic PCAP, big-endian
#:   0a0d0d0a - PCAPNG section header block
PCAP_MAGICS = (
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x0a\x0d\x0d\x0a",
)


class UploadValidationError(Exception):
    """A rejected upload, carrying the HTTP status code to return."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


# ---------------------------------------------------------------------------
# Validation steps
# ---------------------------------------------------------------------------

def validate_filename(filename: str | None) -> None:
    """Reject filenames without a recognised capture extension.

    The extension is only a first, cheap filter; :func:`validate_magic`
    is what actually establishes that the content is a capture file.
    Only the basename is inspected so that any client-supplied path
    separators are ignored and never used to build a filesystem path.
    """
    if not filename:
        raise UploadValidationError(400, "No filename supplied.")

    # Strip any directory component: path separators supplied by the
    # client must never be honoured.
    basename = filename.replace("\\", "/").rsplit("/", 1)[-1].lower()

    if not basename.endswith(ALLOWED_EXTENSIONS):
        allowed = " or ".join(ALLOWED_EXTENSIONS)
        raise UploadValidationError(
            400, f"File must have a {allowed} extension."
        )


def validate_size(total_bytes: int, max_bytes: int = MAX_UPLOAD_BYTES) -> None:
    """Reject an upload that is empty or exceeds *max_bytes*."""
    if total_bytes == 0:
        raise UploadValidationError(400, "Uploaded file is empty.")
    if total_bytes > max_bytes:
        raise UploadValidationError(
            413,
            f"File exceeds the maximum allowed size of "
            f"{max_bytes // (1024 * 1024)} MiB ({max_bytes} bytes).",
        )


def validate_magic(raw: Any) -> None:
    """Reject content that does not begin with a known capture magic.

    This validates *content*, not the filename, so a text file that has
    been renamed to ``.pcap`` is rejected.
    """
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise UploadValidationError(400, "Uploaded content is not binary data.")

    header = bytes(raw[:4])
    if len(header) < 4 or not any(
        header == magic for magic in PCAP_MAGICS
    ):
        raise UploadValidationError(
            400, "File content is not a valid PCAP or PCAPNG capture."
        )
