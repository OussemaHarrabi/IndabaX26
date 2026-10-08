#!/usr/bin/env python3
"""Apply the retention window to payload-adjacent metadata (D6).

Digests, verdicts, reason codes, policy identity and actor identity are the audit
trail and are retained indefinitely. The payload-adjacent half of a receipt — the
``metadata`` a request produced, stored only when
``AEGISGRAPH_STORE_PAYLOAD_METADATA=true`` — is redacted once it is older than
``AEGISGRAPH_RETENTION_DAYS`` (default 90), and each pass writes one audit event
per affected tenant recording the cutoff and the counts.

Usage::

    DATABASE_URL=postgresql+psycopg://... python scripts/retention.py
    DATABASE_URL=postgresql+psycopg://... python scripts/retention.py --days 30
    DATABASE_URL=postgresql+psycopg://... python scripts/retention.py --now 2026-10-08T00:00:00Z

The command is idempotent: a second run with the same cutoff redacts nothing.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from aegisgraph.settings import (
    DATABASE_URL_ENV,
    RETENTION_DAYS_ENV,
    load_settings,
)
from aegisgraph.store import apply_retention, open_store, reset_store_cache


def parse_moment(value: str) -> datetime:
    """Parse an ISO-8601 instant, requiring an explicit offset."""

    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"not an ISO-8601 instant: {value!r}") from error
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("the instant must carry an offset (e.g. ...Z)")
    return parsed.astimezone(UTC)


def main(argv: list[str] | None = None) -> int:
    """Run one retention pass against the configured durable store."""

    settings = load_settings()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--days",
        type=int,
        default=settings.retention_days,
        help=f"retention window in days (default {settings.retention_days})",
    )
    parser.add_argument("--now", type=parse_moment, default=None, help="cutoff instant, ISO-8601")
    args = parser.parse_args(argv)

    if not settings.database_url:
        print(
            f"retention: {DATABASE_URL_ENV} is required; there is nothing durable to retain",
            file=sys.stderr,
        )
        return 2
    if args.days < 0:
        print("retention: --days must not be negative", file=sys.stderr)
        return 2

    reset_store_cache()
    store = open_store(settings)
    report = apply_retention(store, now=args.now, days=args.days)
    print(
        json.dumps(
            {
                "cutoff": report.cutoff.isoformat(),
                "retention_days": args.days,
                "payloads_redacted": report.payloads_redacted,
                "runs_redacted": report.runs_redacted,
                "tenants": list(report.tenants),
                "source": RETENTION_DAYS_ENV,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    sys.exit(main())
