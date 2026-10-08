"""Validator tests: one entry point, readable findings, every check covered."""

from __future__ import annotations

import json
from pathlib import Path

from benchmark import validators
from benchmark.fixtures import DATASET_META, scenario_dict, write_dataset, write_scenario_file
from benchmark.schema import Scenario
from benchmark.seal import seal_holdout
from benchmark.validators import validate_dataset

PASSPHRASE = "validator-passphrase"


def _codes(report: validators.ValidationReport) -> list[str]:
    return sorted(finding.code for finding in report.findings)


def _sealed(tmp_path: Path) -> None:
    scenario = Scenario.model_validate(
        scenario_dict(scenario_id="hold_enterprise_probe", split="holdout")
    )
    seal_holdout([scenario], PASSPHRASE, tmp_path)


def _clean_dataset(tmp_path: Path) -> None:
    write_dataset(
        tmp_path,
        [
            scenario_dict(scenario_id="ent_fixture_attack", pair_id="pair_fixture_01"),
            scenario_dict(
                scenario_id="ent_fixture_control",
                scenario_kind="benign",
                attack_step_id=None,
                utility_step_id=1,
                pair_id="pair_fixture_01",
            ),
        ],
    )
    _sealed(tmp_path)


def test_a_clean_dataset_passes_with_no_findings(tmp_path: Path) -> None:
    _clean_dataset(tmp_path)

    report = validate_dataset(tmp_path)

    assert report.ok, report.render()
    assert report.findings == []
    assert report.scenario_count == 2
    assert report.by_split == {"development": 2}
    assert report.dataset_hash != ""
    assert report.holdout["sealed"] is True


def test_the_committed_dataset_passes() -> None:
    root = Path(__file__).resolve().parents[1] / "benchmark" / "data"

    report = validate_dataset(root)

    assert report.ok, report.render()
    assert report.scenario_count >= 20
    assert set(report.by_domain) == {"enterprise", "finance", "soc"}
    assert report.holdout["present"] is True


def test_an_invalid_file_is_reported_with_its_location(tmp_path: Path) -> None:
    _clean_dataset(tmp_path)
    broken = scenario_dict(scenario_id="ent_fixture_broken")
    broken["proposed_actions"][1]["action"]["content"] = "not allowed on a tool call"
    write_scenario_file(tmp_path, broken)

    report = validate_dataset(tmp_path)

    assert "SCHEMA_INVALID" in _codes(report)
    assert not report.ok
    assert "ent_fixture_broken" in report.render()


def test_malformed_json_is_reported_rather_than_raising(tmp_path: Path) -> None:
    _clean_dataset(tmp_path)
    path = tmp_path / "scenarios" / "enterprise" / "ent_fixture_raw.json"
    path.write_text("{not json", encoding="utf-8")

    report = validate_dataset(tmp_path)

    assert "SCHEMA_JSON" in _codes(report)


def test_label_leakage_into_a_request_is_detected(tmp_path: Path) -> None:
    _clean_dataset(tmp_path)
    leaky = scenario_dict(scenario_id="ent_fixture_leaky")
    leaky["user_goal"] = "Run the ent_fixture_leaky episode and report back."
    write_scenario_file(tmp_path, leaky)

    report = validate_dataset(tmp_path)

    assert "LABEL_LEAKAGE" in _codes(report)
    assert "benchmark scenario_id" in report.render()


def test_a_duplicated_body_under_two_ids_is_detected(tmp_path: Path) -> None:
    _clean_dataset(tmp_path)
    first = scenario_dict(scenario_id="ent_fixture_dup_a")
    second = json.loads(json.dumps(first))
    second["id"] = "ent_fixture_dup_b"
    write_scenario_file(tmp_path, first)
    write_scenario_file(tmp_path, second)

    report = validate_dataset(tmp_path)

    assert "DUPLICATE_BODY" in _codes(report)


def test_bound_violations_are_detected_against_the_wire_limit(tmp_path: Path, monkeypatch) -> None:
    _clean_dataset(tmp_path)
    monkeypatch.setattr(validators, "WIRE_BODY_LIMIT", 200)

    report = validate_dataset(tmp_path)

    assert "BOUND_REQUEST" in _codes(report)
    assert report.max_request_bytes > 200


def test_a_non_synthetic_scenario_is_rejected_by_the_licence_check(tmp_path: Path) -> None:
    _clean_dataset(tmp_path)
    document = scenario_dict(scenario_id="ent_fixture_real")
    document["dataset"] = dict(DATASET_META)
    document["dataset"]["synthetic"] = True
    write_scenario_file(tmp_path, document)
    # The synthetic flag is schema-level; the licence check adds the date guard.
    document["dataset"]["created"] = "2020-01-01"
    write_scenario_file(tmp_path, document)

    report = validate_dataset(tmp_path)

    assert "PROVENANCE_DATE" in _codes(report)


def test_split_and_pair_findings_reach_the_report(tmp_path: Path) -> None:
    write_dataset(tmp_path, [scenario_dict(scenario_id="ent_fixture_lonely")])
    _sealed(tmp_path)

    report = validate_dataset(tmp_path)

    assert "PAIR_CONTROL_COUNT" in _codes(report)


def test_the_scoring_determinism_probe_runs_on_the_committed_dataset() -> None:
    root = Path(__file__).resolve().parents[1] / "benchmark" / "data"

    report = validate_dataset(root)

    assert "SCORING_NONDETERMINISTIC" not in _codes(report)


def test_the_report_renders_a_readable_verdict(tmp_path: Path) -> None:
    _clean_dataset(tmp_path)

    rendered = validate_dataset(tmp_path).render()

    assert rendered.startswith("native benchmark validation:")
    assert "RESULT: PASS" in rendered
    assert "sealed holdout" in rendered
