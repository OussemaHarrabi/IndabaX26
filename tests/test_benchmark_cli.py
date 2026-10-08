"""CLI-level tests: the refusals that must happen before a table is printed."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

from benchmark.fixtures import scenario_dict
from benchmark.policies import collect_policy_sets
from benchmark.schema import Scenario
from benchmark.scoring import StepVerdict, derive_outcome

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"bench_cli_{name}", SCRIPTS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _attack_outcome_line() -> str:
    scenario = Scenario.model_validate(scenario_dict(scenario_id="ent_fixture_attack"))
    outcome = derive_outcome(
        scenario,
        (
            StepVerdict(step_id=0, http_status=200, decision="allow"),
            StepVerdict(step_id=1, http_status=200, decision="block"),
        ),
    )
    return json.dumps(outcome.to_json(), sort_keys=True) + "\n"


def test_raw_outcomes_without_a_control_are_refused(tmp_path: Path) -> None:
    """An attack-evidence-free table must not look like a result."""

    module = _load("bench_score")
    outcomes = tmp_path / "outcomes.jsonl"
    outcomes.write_text(_attack_outcome_line(), encoding="utf-8")

    assert module.main(["--outcomes", str(outcomes)]) == 1


def test_raw_outcomes_with_a_control_are_scored(tmp_path: Path) -> None:
    module = _load("bench_score")
    outcomes = tmp_path / "outcomes.jsonl"
    outcomes.write_text(_attack_outcome_line(), encoding="utf-8")
    control = tmp_path / "control.jsonl"
    control.write_text(_attack_outcome_line(), encoding="utf-8")

    assert module.main(["--outcomes", str(outcomes), "--control", str(control)]) == 0


def test_benign_only_outcomes_without_a_control_are_scored(tmp_path: Path) -> None:
    module = _load("bench_score")
    scenario = Scenario.model_validate(
        scenario_dict(
            scenario_id="ent_fixture_control",
            scenario_kind="benign",
            attack_step_id=None,
            utility_step_id=1,
        )
    )
    outcome = derive_outcome(
        scenario,
        (
            StepVerdict(step_id=0, http_status=200, decision="allow"),
            StepVerdict(step_id=1, http_status=200, decision="allow"),
        ),
    )
    outcomes = tmp_path / "outcomes.jsonl"
    outcomes.write_text(json.dumps(outcome.to_json(), sort_keys=True) + "\n", encoding="utf-8")

    assert module.main(["--outcomes", str(outcomes)]) == 0


def test_the_run_cli_refuses_the_sealed_holdout_split() -> None:
    module = _load("bench_run")

    assert module.main(["--defense-url", "http://127.0.0.1:1", "--splits", "holdout"]) == 2


def test_the_policies_cli_requires_a_credential() -> None:
    module = _load("bench_policies")

    with pytest.raises(SystemExit) as caught:
        module.main(["--defense-url", "http://127.0.0.1:1"])

    assert caught.value.code == 2


def test_the_policies_cli_reports_an_absent_token_file(tmp_path: Path) -> None:
    module = _load("bench_policies")

    code = module.main(
        [
            "--defense-url",
            "http://127.0.0.1:1",
            "--token-file",
            str(tmp_path / "absent"),
        ]
    )

    assert code == 1


def test_the_policies_cli_derives_one_set_per_distinct_document() -> None:
    _load("bench_policies")  # the CLI module must import cleanly
    plan = collect_policy_sets(REPO_ROOT / "benchmark" / "data", ("development", "validation"))

    assert len(plan.documents) == 26
    assert len(plan.blob_sha256) == 64
    assert all(key.startswith("bench-") and key.endswith(":1") for key in plan.documents)
