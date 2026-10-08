"""Legacy adapter tests: projection, and exact reproduction of legacy numbers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmark.adapters.sentinel import (
    ADAPTER_INFERENCES,
    LEGACY_COMMIT,
    AdapterError,
    find_legacy_root,
    load_legacy_scenarios,
    load_legacy_scorecard,
    reproduce_digest,
    reproduce_metrics,
    to_native_outcomes,
    verify_scorecard,
    yaml_available,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
EVALUATION = REPO_ROOT / "evaluation"
SCORECARDS = sorted(EVALUATION.glob("*.json"))


def test_every_committed_scorecard_reproduces_its_own_numbers() -> None:
    assert SCORECARDS, "no legacy scorecards found"

    for path in SCORECARDS:
        verification = verify_scorecard(path)
        assert verification.metrics_match, verification.render()
        assert verification.digest_match, verification.render()
        assert verification.ok, verification.render()


def test_the_recorded_digest_is_reproduced_exactly() -> None:
    scorecard = load_legacy_scorecard(EVALUATION / "aegisgraph-mock.json")

    assert reproduce_digest(scorecard) == scorecard.deterministic_digest
    assert scorecard.deterministic_digest == (
        "3233dfc56fb4d8f562ac8feaecd126ce35edfa3ee3ce4a559be77edaf2116e18"
    )


def test_reproduced_metrics_match_the_legacy_definitions() -> None:
    scorecard = load_legacy_scorecard(EVALUATION / "allow-all-mock.json")

    metrics = reproduce_metrics(scorecard)

    assert metrics["asr"] == 1.0
    assert metrics["attack_count"] == scorecard.metrics["attack_count"]
    assert metrics["decisions"] == scorecard.metrics["decisions"]
    assert metrics["defense_errors"] == 0


def test_a_tampered_scorecard_is_detected_rather_than_reproduced(tmp_path: Path) -> None:
    original = json.loads((EVALUATION / "aegisgraph-mock.json").read_text(encoding="utf-8"))
    original["metrics"]["asr"] = 0.5
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(original), encoding="utf-8")

    verification = verify_scorecard(tampered)

    assert verification.metrics_match is False
    assert "asr" in verification.differences
    assert "DIFF asr" in verification.render()


def test_legacy_outcomes_map_into_the_native_result_shape() -> None:
    scorecard = load_legacy_scorecard(EVALUATION / "aegisgraph-mock.json")

    outcomes = to_native_outcomes(scorecard)

    assert len(outcomes) == len(scorecard.outcomes)
    attacks = [outcome for outcome in outcomes if outcome.attack_present]
    benign = [outcome for outcome in outcomes if not outcome.attack_present]
    assert len(attacks) == scorecard.metrics["attack_count"]
    assert len(benign) == scorecard.metrics["benign_count"]
    assert all(outcome.attack_success is not None for outcome in attacks)
    assert all(outcome.utility_satisfied is not None for outcome in benign)


def test_a_file_that_is_not_a_scorecard_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "not-a-scorecard.json"
    path.write_text('{"hello": "world"}', encoding="utf-8")

    with pytest.raises(AdapterError, match="not a legacy scorecard"):
        load_legacy_scorecard(path)


def test_a_missing_legacy_checkout_is_reported_with_the_pin(tmp_path: Path) -> None:
    with pytest.raises(AdapterError, match=LEGACY_COMMIT):
        load_legacy_scenarios(tmp_path / "nowhere")


def test_the_legacy_projection_records_its_inferences() -> None:
    assert len(ADAPTER_INFERENCES) >= 5
    assert any("provenance" in item for item in ADAPTER_INFERENCES)


@pytest.mark.skipif(not yaml_available(), reason="PyYAML is not installed in this interpreter")
def test_the_pinned_legacy_scenarios_project_into_the_native_representation() -> None:
    root = find_legacy_root()
    if root is None:
        pytest.skip("the pinned .sentinel_reference checkout is not present")

    projections = load_legacy_scenarios(root)

    assert len(projections) == 49
    assert sum(1 for item in projections if item.legacy_split == "public") == 40
    assert all(item.scenario.id == item.legacy_id for item in projections)
    assert all(item.scenario.tags[0] == "legacy_projection" for item in projections)
    assert all(item.scenario.dataset.source_reference for item in projections)
    assert any(item.scenario.attack_present for item in projections)
    assert any(not item.scenario.attack_present for item in projections)
    # A benign legacy scenario has no family in the source, so none is invented.
    assert all(
        item.scenario.attack_family is not None
        for item in projections
        if item.scenario.attack_present
    )
    assert all(
        item.scenario.attack_family is None
        for item in projections
        if item.legacy_family == "none" and not item.scenario.attack_present
    )


@pytest.mark.skipif(not yaml_available(), reason="PyYAML is not installed in this interpreter")
def test_a_pin_mismatch_is_refused() -> None:
    root = find_legacy_root()
    if root is None:
        pytest.skip("the pinned .sentinel_reference checkout is not present")

    with pytest.raises(AdapterError, match="expected 99"):
        load_legacy_scenarios(root, expected_count=99)
