#!/usr/bin/env python3
"""Gate an allow-all SENTINEL evaluation on attack reachability."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_METADATA_FIELDS = (
    "model",
    "model_name",
    "model_id",
    "model_backend",
    "run_id",
    "run_seed",
    "benchmark_version",
    "defense",
    "attack_mode",
)


class ReportValidationError(ValueError):
    """Raised when an evaluation report cannot support a reachability decision."""


def _scenario_id(row: dict[str, Any], index: int) -> str:
    scenario_id = row.get("scenario_id")
    if not isinstance(scenario_id, str) or not scenario_id.strip():
        raise ReportValidationError(f"outcomes[{index}].scenario_id must be a non-empty string")
    return scenario_id


def validate_report(
    report: object, required_scenarios: list[str] | None = None
) -> tuple[list[tuple[str, bool]], list[str]]:
    """Return every attack's reachability and any failed attack scenario IDs."""

    if not isinstance(report, dict):
        raise ReportValidationError("top-level JSON value must be an object")
    outcomes = report.get("outcomes")
    if not isinstance(outcomes, list) or not outcomes:
        raise ReportValidationError("'outcomes' must be a non-empty array")

    by_id: dict[str, tuple[bool, bool]] = {}
    attacks: list[tuple[str, bool]] = []
    for index, row in enumerate(outcomes):
        if not isinstance(row, dict):
            raise ReportValidationError(f"outcomes[{index}] must be an object")
        scenario_id = _scenario_id(row, index)
        if scenario_id in by_id:
            raise ReportValidationError(f"duplicate scenario_id {scenario_id!r}")

        attack_present = row.get("attack_present")
        if type(attack_present) is not bool:
            raise ReportValidationError(
                f"scenario {scenario_id!r}: 'attack_present' must be a boolean"
            )
        attack_success = row.get("attack_success")
        if type(attack_success) is not bool:
            raise ReportValidationError(
                f"scenario {scenario_id!r}: 'attack_success' must be a boolean"
            )
        if not attack_present and attack_success:
            raise ReportValidationError(
                f"scenario {scenario_id!r}: attack_success cannot be true when "
                "attack_present is false"
            )

        by_id[scenario_id] = (attack_present, attack_success)
        if attack_present:
            attacks.append((scenario_id, attack_success))

    required = required_scenarios or []
    for scenario_id in required:
        if not scenario_id.strip():
            raise ReportValidationError("--require-scenario values must not be empty")
        record = by_id.get(scenario_id)
        if record is None:
            raise ReportValidationError(
                f"required scenario {scenario_id!r} is missing from outcomes"
            )
        if not record[0]:
            raise ReportValidationError(
                f"required scenario {scenario_id!r} is not an attack (attack_present is false)"
            )

    if not attacks:
        raise ReportValidationError("no attack scenarios found; reachability gate would be vacuous")

    unreachable = [scenario_id for scenario_id, reached in attacks if not reached]
    return attacks, unreachable


def _display_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _print_metadata(report: dict[str, Any]) -> None:
    fields = [f"{key}={_display_value(report[key])}" for key in _METADATA_FIELDS if key in report]
    if fields:
        print("Metadata: " + ", ".join(fields))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify that every attack in an allow-all SENTINEL eval was reachable."
    )
    parser.add_argument("report", type=Path, help="raw SENTINEL evaluation JSON")
    parser.add_argument(
        "--require-scenario",
        action="append",
        default=[],
        metavar="ID",
        help="also require this attack scenario ID to be present (repeatable)",
    )
    args = parser.parse_args(argv)

    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        attacks, unreachable = validate_report(report, args.require_scenario)
    except (OSError, UnicodeError, json.JSONDecodeError, ReportValidationError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    _print_metadata(report)
    print(f"Attack reachability ({len(attacks)} scenarios):")
    for scenario_id, reached in attacks:
        print(f"  {scenario_id}: attack_success={str(reached).lower()}")

    if unreachable:
        print("FAIL: vulnerabilities were unreachable in: " + ", ".join(unreachable))
        return 1

    print("PASS: every attack was reachable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
