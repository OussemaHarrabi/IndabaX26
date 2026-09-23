"""CLI tests for the independent allow-all attack reachability gate."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "scripts" / "validate_attack_reachability.py"


def _write_report(tmp_path: Path, report: object) -> Path:
    path = tmp_path / "eval.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def _run(path: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(path), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )


def test_lists_every_attack_and_reports_explicit_run_metadata(tmp_path: Path) -> None:
    report = {
        "model": "qwen3:8b",
        "run_seed": 17,
        "outcomes": [
            {"scenario_id": "attack-a", "attack_present": True, "attack_success": True},
            {"scenario_id": "benign-a", "attack_present": False, "attack_success": False},
            {"scenario_id": "attack-b", "attack_present": True, "attack_success": True},
        ],
    }

    result = _run(_write_report(tmp_path, report))

    assert result.returncode == 0
    assert "model=qwen3:8b" in result.stdout
    assert "run_seed=17" in result.stdout
    assert "attack-a: attack_success=true" in result.stdout
    assert "attack-b: attack_success=true" in result.stdout
    assert "benign-a" not in result.stdout
    assert "PASS" in result.stdout


def test_fails_and_lists_attack_with_unreachable_vulnerability(tmp_path: Path) -> None:
    report = {
        "outcomes": [
            {"scenario_id": "attack-a", "attack_present": True, "attack_success": True},
            {"scenario_id": "attack-b", "attack_present": True, "attack_success": False},
        ]
    }

    result = _run(_write_report(tmp_path, report))

    assert result.returncode == 1
    assert "attack-a: attack_success=true" in result.stdout
    assert "attack-b: attack_success=false" in result.stdout
    assert "unreachable in: attack-b" in result.stdout


def test_rejects_missing_or_malformed_attack_fields_with_scenario_context(
    tmp_path: Path,
) -> None:
    reports = [
        {"outcomes": [{"scenario_id": "attack-a", "attack_success": True}]},
        {
            "outcomes": [
                {"scenario_id": "attack-a", "attack_present": True, "attack_success": "yes"}
            ]
        },
        {"outcomes": [{"scenario_id": "attack-a", "attack_present": True}]},
    ]

    for report in reports:
        result = _run(_write_report(tmp_path, report))
        assert result.returncode == 2
        assert "ERROR" in result.stderr
        assert "attack-a" in result.stderr


def test_required_scenario_must_exist_and_be_an_attack(tmp_path: Path) -> None:
    report = {
        "outcomes": [
            {"scenario_id": "attack-a", "attack_present": True, "attack_success": True},
            {"scenario_id": "benign-a", "attack_present": False, "attack_success": False},
        ]
    }
    path = _write_report(tmp_path, report)

    missing = _run(path, "--require-scenario", "attack-missing")
    benign = _run(path, "--require-scenario", "benign-a")
    present = _run(path, "--require-scenario", "attack-a")

    assert missing.returncode == 2
    assert "required scenario 'attack-missing' is missing" in missing.stderr
    assert benign.returncode == 2
    assert "required scenario 'benign-a' is not an attack" in benign.stderr
    assert present.returncode == 0
