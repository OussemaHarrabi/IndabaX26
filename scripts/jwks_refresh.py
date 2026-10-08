#!/usr/bin/env python3
"""Materialise an issuer JWKS URL into the mounted file the service reads (D7).

The decision process deliberately holds no network capability: it reads a mounted
JWKS file. This operator-side helper performs the one fetch, writes the document
atomically and records the issuer URL it came from, so the service itself never
opens a socket.

Usage::

    python scripts/jwks_refresh.py --url "$AEGISGRAPH_JWKS_URL" --output /run/secrets/jwks.json
    python scripts/jwks_refresh.py --check --output /run/secrets/jwks.json

Run it from an init container, a sidecar, or a cron job; the service only needs
the file to exist and be readable.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_DOCUMENT_BYTES = 1_048_576


def fetch(url: str, *, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Fetch and parse one JWKS document, refusing anything that is not a key set."""

    request = urllib.request.Request(url, headers={"accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read(MAX_DOCUMENT_BYTES + 1)
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise SystemExit(f"jwks_refresh: {url} returned more than {MAX_DOCUMENT_BYTES} bytes")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise SystemExit(f"jwks_refresh: {url} did not return JSON: {error}") from error
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise SystemExit(f"jwks_refresh: {url} is not a JWKS document (no 'keys' list)")
    return document


def write_atomic(document: dict[str, Any], output: Path) -> None:
    """Write the document so a reader never observes a half-written key set."""

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)


def check(output: Path) -> dict[str, Any]:
    """Report the state of the mounted JWKS file without fetching anything."""

    if not output.is_file():
        return {"output": str(output), "exists": False, "key_count": 0}
    try:
        document = json.loads(output.read_text(encoding="utf-8"))
    except ValueError:
        return {"output": str(output), "exists": True, "key_count": 0, "valid": False}
    keys = document.get("keys") if isinstance(document, dict) else None
    return {
        "output": str(output),
        "exists": True,
        "valid": isinstance(keys, list),
        "key_count": len(keys) if isinstance(keys, list) else 0,
    }


def main(argv: list[str] | None = None) -> int:
    """Fetch (or check) the JWKS file and print a short JSON report."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.environ.get("AEGISGRAPH_JWKS_URL"))
    parser.add_argument("--output", default=os.environ.get("AEGISGRAPH_JWKS"))
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    if not args.output:
        print("jwks_refresh: --output (or AEGISGRAPH_JWKS) is required", file=sys.stderr)
        return 2
    output = Path(args.output)
    if args.check:
        print(json.dumps(check(output), sort_keys=True))
        return 0
    if not args.url:
        print("jwks_refresh: --url (or AEGISGRAPH_JWKS_URL) is required", file=sys.stderr)
        return 2
    try:
        document = fetch(args.url, timeout=args.timeout)
    except (OSError, urllib.error.URLError) as error:
        print(f"jwks_refresh: could not fetch {args.url}: {error}", file=sys.stderr)
        return 1
    write_atomic(document, output)
    print(json.dumps({**check(output), "source": args.url}, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    sys.exit(main())
