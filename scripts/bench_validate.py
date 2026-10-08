#!/usr/bin/env python3
"""Validate the native benchmark. Exit code 0 means every check passed."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from benchmark.dataset import DatasetError  # noqa: E402
from benchmark.validators import validate_dataset  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        default=str(REPO_ROOT / "benchmark" / "data"),
        help="dataset root (default: benchmark/data)",
    )
    parser.add_argument("--json", action="store_true", help="also print the machine-readable view")
    args = parser.parse_args(argv)
    try:
        report = validate_dataset(Path(args.root))
    except DatasetError as error:
        print(f"RESULT: FAIL\n  DATASET: {error}")
        return 1
    print(report.render())
    if args.json:
        import json

        payload = {
            "ok": report.ok,
            "scenario_count": report.scenario_count,
            "by_split": report.by_split,
            "by_domain": report.by_domain,
            "by_family": report.by_family,
            "dataset_hash": report.dataset_hash,
            "max_request_bytes": report.max_request_bytes,
            "holdout": report.holdout,
            "findings": [
                {
                    "severity": finding.severity,
                    "code": finding.code,
                    "message": finding.message,
                    "where": list(finding.where),
                }
                for finding in report.findings
            ],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
