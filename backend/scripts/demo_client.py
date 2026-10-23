"""
demo_client.py — Tiny command-line client for demonstrating the API.

Why this exists: the demonstration needs to upload a file to
``POST /analyze`` and print the JSON reply.  Doing that as a PowerShell
one-liner is fragile and hides the mechanics; this script does it in
plain Python with the standard library only (no extra dependency), and
prints real server responses rather than a hand-made summary.

Usage (from the ``backend/`` directory, with the API running):

    python -m scripts.demo_client health
    python -m scripts.demo_client analyze data/normal_traffic.pcap
    python -m scripts.demo_client stats
    python -m scripts.demo_client alerts
    python -m scripts.demo_client reject-extension
    python -m scripts.demo_client reject-content

Every command prints the HTTP status code and the response body, so the
output can be used directly as evidence during a demonstration.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

DEFAULT_BASE_URL = "http://127.0.0.1:8000"


def _request(url: str, *, data: bytes | None = None, headers=None):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except urllib.error.URLError as exc:
        print(f"Could not reach {url}: {exc.reason}", file=sys.stderr)
        print("Is the server running? Start it with:", file=sys.stderr)
        print("    python -m uvicorn app.main:app --port 8000", file=sys.stderr)
        raise SystemExit(2)


def _show(status: int, body: bytes) -> None:
    print(f"HTTP {status}")
    text = body.decode("utf-8", errors="replace")
    try:
        print(json.dumps(json.loads(text), indent=2))
    except json.JSONDecodeError:
        print(text)


def _multipart(field: str, filename: str, content: bytes):
    """Build a minimal multipart/form-data body by hand."""
    boundary = "----NetSentinelBoundary"
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"; '
        f'filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    body = head + content + tail
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    return body, headers


def cmd_health(base: str) -> None:
    _show(*_request(f"{base}/health"))


def cmd_stats(base: str) -> None:
    _show(*_request(f"{base}/stats"))


def cmd_alerts(base: str) -> None:
    _show(*_request(f"{base}/alerts"))


def cmd_analyze(base: str, path: str) -> None:
    with open(path, "rb") as fh:
        content = fh.read()
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    body, headers = _multipart("file", name, content)
    print(f"Uploading {name} ({len(content)} bytes) ...")
    _show(*_request(f"{base}/analyze", data=body, headers=headers))


def cmd_reject_extension(base: str) -> None:
    """A .txt upload must be refused on the extension check."""
    body, headers = _multipart("file", "notes.txt", b"not a capture file")
    _show(*_request(f"{base}/analyze", data=body, headers=headers))


def cmd_reject_content(base: str) -> None:
    """A file named .pcap but containing text must be refused on content."""
    body, headers = _multipart("file", "fake.pcap", b"not a capture file")
    _show(*_request(f"{base}/analyze", data=body, headers=headers))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="NetSentinel demonstration client",
    )
    parser.add_argument(
        "--base-url", default=DEFAULT_BASE_URL,
        help=f"API base URL (default: {DEFAULT_BASE_URL})",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("health", help="GET /health")
    sub.add_parser("stats", help="GET /stats")
    sub.add_parser("alerts", help="GET /alerts")

    analyze = sub.add_parser("analyze", help="POST /analyze with a PCAP file")
    analyze.add_argument("path", help="path to a .pcap/.pcapng file")

    sub.add_parser(
        "reject-extension", help="POST /analyze with a .txt file (expect 400)"
    )
    sub.add_parser(
        "reject-content", help="POST /analyze with fake .pcap content (expect 400)"
    )

    args = parser.parse_args(argv)
    base = args.base_url.rstrip("/")

    if args.command == "health":
        cmd_health(base)
    elif args.command == "stats":
        cmd_stats(base)
    elif args.command == "alerts":
        cmd_alerts(base)
    elif args.command == "analyze":
        cmd_analyze(base, args.path)
    elif args.command == "reject-extension":
        cmd_reject_extension(base)
    elif args.command == "reject-content":
        cmd_reject_content(base)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
