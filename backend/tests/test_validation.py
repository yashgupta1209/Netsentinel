"""
test_validation.py — Tests for the /analyze upload validation policy.

These cover the policy layer directly (no FastAPI, no Pydantic), so they
run in any environment that has the project's own code available.
"""

from __future__ import annotations

import pytest

from app.validation import (
    MAX_UPLOAD_BYTES,
    UploadValidationError,
    validate_filename,
    validate_magic,
    validate_size,
)


class TestValidateFilename:
    def test_accepts_pcap(self):
        validate_filename("capture.pcap")

    def test_accepts_pcapng(self):
        validate_filename("capture.pcapng")

    def test_accepts_uppercase(self):
        validate_filename("CAPTURE.PCAP")

    def test_rejects_txt(self):
        with pytest.raises(UploadValidationError) as exc:
            validate_filename("notes.txt")
        assert exc.value.status_code == 400

    def test_rejects_no_extension(self):
        with pytest.raises(UploadValidationError) as exc:
            validate_filename("capture")
        assert exc.value.status_code == 400

    def test_rejects_empty(self):
        with pytest.raises(UploadValidationError):
            validate_filename("")

    def test_rejects_none(self):
        with pytest.raises(UploadValidationError):
            validate_filename(None)

    def test_strips_client_supplied_path(self):
        """A client-supplied path must be reduced to its basename."""
        validate_filename("C:\\Users\\victim\\secret.pcap")
        validate_filename("/etc/passwd.pcapng")

    def test_path_traversal_does_not_bypass(self):
        """'..' or absolute paths cannot sneak a valid extension past."""
        with pytest.raises(UploadValidationError):
            validate_filename("../../../etc/shadow")


class TestValidateSize:
    def test_accepts_normal_size(self):
        validate_size(1024)

    def test_rejects_empty(self):
        with pytest.raises(UploadValidationError) as exc:
            validate_size(0)
        assert exc.value.status_code == 400

    def test_rejects_oversized(self):
        with pytest.raises(UploadValidationError) as exc:
            validate_size(MAX_UPLOAD_BYTES + 1)
        assert exc.value.status_code == 413

    def test_accepts_exactly_at_limit(self):
        validate_size(MAX_UPLOAD_BYTES)

    def test_message_mentions_megabytes(self):
        with pytest.raises(UploadValidationError) as exc:
            validate_size(MAX_UPLOAD_BYTES + 1)
        assert "MiB" in exc.value.detail


class TestValidateMagic:
    def test_accepts_little_endian_pcap(self):
        validate_magic(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    def test_accepts_big_endian_pcap(self):
        validate_magic(b"\xa1\xb2\xa3\xd4"[:0] + b"\xa1\xb2\xc3\xd4" + b"\x00" * 20)

    def test_accepts_pcapng(self):
        validate_magic(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20)

    def test_rejects_text_renamed_to_pcap(self):
        """Content is validated, not just the filename."""
        with pytest.raises(UploadValidationError) as exc:
            validate_magic(b"this is plain text, definitely not a capture")
        assert exc.value.status_code == 400

    def test_rejects_too_short(self):
        with pytest.raises(UploadValidationError):
            validate_magic(b"\xd4\xc3")

    def test_rejects_non_bytes(self):
        with pytest.raises(UploadValidationError) as exc:
            validate_magic("d4c3b2a1")  # type: ignore[arg-type]
        assert exc.value.status_code == 400

    def test_checks_only_header(self):
        """Body bytes are irrelevant once the header matches."""
        validate_magic(b"\xd4\xc3\xb2\xa1" + b"\xff" * 32)
