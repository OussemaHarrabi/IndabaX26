"""Schema round-trip and rejection tests for the native benchmark scenario."""

from __future__ import annotations

import copy
import json

import pytest
from pydantic import ValidationError

from benchmark.fixtures import scenario_dict
from benchmark.schema import (
    Scenario,
    canonical_json,
    canonical_scenario_text,
    load_scenario_text,
    parse_scenario,
    scenario_hash,
    scenario_json_schema,
)


def _attack() -> dict:
    return scenario_dict(scenario_id="ent_fixture_attack", pair_id="pair_fixture_01")


def _control() -> dict:
    return scenario_dict(
        scenario_id="ent_fixture_control",
        scenario_kind="benign",
        attack_step_id=None,
        utility_step_id=1,
    )


def test_scenario_round_trips_through_canonical_text_unchanged() -> None:
    scenario = Scenario.model_validate(_attack())

    reloaded = load_scenario_text(canonical_scenario_text(scenario))

    assert reloaded == scenario
    assert scenario_hash(reloaded) == scenario_hash(scenario)
    assert json.loads(canonical_scenario_text(scenario))["id"] == scenario.id


def test_canonical_text_is_stable_and_sorted() -> None:
    scenario = Scenario.model_validate(_attack())

    text = canonical_scenario_text(scenario)

    assert text.endswith("\n")
    keys = [line.split(":")[0] for line in text.splitlines() if line.startswith('  "')]
    assert keys == sorted(keys)


def test_parse_scenario_rejects_a_non_mapping() -> None:
    with pytest.raises(ValidationError):
        parse_scenario(["not", "a", "mapping"])


def test_attack_requires_a_family_and_a_step() -> None:
    document = _attack()
    document["attack_family"] = None
    with pytest.raises(ValidationError, match="attack_family"):
        Scenario.model_validate(document)

    document = _attack()
    document["scoring"] = {"method": "action_authorization", "attack_step_id": None}
    with pytest.raises(ValidationError, match="attack_step_id"):
        Scenario.model_validate(document)


def test_benign_control_must_not_declare_an_attack_step_or_vague_expectation() -> None:
    document = _control()
    document["scoring"] = {"method": "action_authorization", "attack_step_id": 0}
    with pytest.raises(ValidationError, match="benign control"):
        Scenario.model_validate(document)

    document = _control()
    document["utility_criterion"]["expectation"] = "not_allowed"
    with pytest.raises(ValidationError, match="concrete utility expectation"):
        Scenario.model_validate(document)


def test_family_label_falls_back_for_an_unlabelled_control() -> None:
    document = _control()
    document["attack_family"] = None

    scenario = Scenario.model_validate(document)

    assert scenario.family_label == "unlabelled"


def test_provenance_references_are_checked() -> None:
    document = _attack()
    document["observations"][0]["provenance_id"] = "ghost"
    with pytest.raises(ValidationError, match="unknown provenance"):
        Scenario.model_validate(document)

    document = _attack()
    document["provenance"].append(
        {
            "id": "derived",
            "source_type": "document",
            "source_id": "doc-1",
            "trust_level": "trusted_internal",
            "sensitivity": "internal",
            "origin_actor": "ops",
            "retrieved_via": "wiki.read",
            "observed_at": "2026-03-02T08:15:00Z",
            "parents": ["missing"],
        }
    )
    with pytest.raises(ValidationError, match="unknown parents"):
        Scenario.model_validate(document)

    document = _attack()
    document["provenance"][0]["parents"] = ["src"]
    with pytest.raises(ValidationError, match="own parent"):
        Scenario.model_validate(document)


def test_duplicate_identifiers_are_rejected() -> None:
    document = _attack()
    document["proposed_actions"].append(copy.deepcopy(document["proposed_actions"][0]))
    with pytest.raises(ValidationError, match="step ids must be unique"):
        Scenario.model_validate(document)

    document = _attack()
    document["observations"].append(copy.deepcopy(document["observations"][0]))
    with pytest.raises(ValidationError, match="observation ids must be unique"):
        Scenario.model_validate(document)

    document = _attack()
    document["provenance"].append(copy.deepcopy(document["provenance"][0]))
    with pytest.raises(ValidationError, match="node ids must be unique"):
        Scenario.model_validate(document)


def test_action_shape_rules_are_enforced() -> None:
    document = _attack()
    document["proposed_actions"][1]["action"]["content"] = "extra"
    with pytest.raises(ValidationError, match="tool_call actions take 'arguments' only"):
        Scenario.model_validate(document)

    document = _attack()
    document["proposed_actions"] = [
        {"step_id": 0, "description": "say it", "action": {"type": "respond", "final": True}}
    ]
    document["scoring"] = {"method": "action_authorization", "attack_step_id": 0}
    with pytest.raises(ValidationError, match="require 'content'"):
        Scenario.model_validate(document)

    document = _attack()
    document["proposed_actions"] = [
        {
            "step_id": 0,
            "description": "read",
            "action": {"type": "tool_call", "tool": "email_read", "final": True},
        }
    ]
    document["scoring"] = {"method": "action_authorization", "attack_step_id": 0}
    with pytest.raises(ValidationError, match="only respond actions can be final"):
        Scenario.model_validate(document)


def test_confirmation_requests_need_a_tool_call_target() -> None:
    document = _attack()
    document["proposed_actions"].append(
        {
            "step_id": 2,
            "description": "ask",
            "action": {
                "type": "request_confirmation",
                "content": "approve?",
                "confirmation_for": None,
            },
        }
    )
    with pytest.raises(ValidationError, match="confirmation_for"):
        Scenario.model_validate(document)


def test_bounds_and_placeholders_are_rejected() -> None:
    document = _attack()
    document["id"] = "X"
    with pytest.raises(ValidationError):
        Scenario.model_validate(document)

    document = _attack()
    document["observations"][0]["content"] = "a" * 4001
    with pytest.raises(ValidationError):
        Scenario.model_validate(document)

    document = _attack()
    document["dataset"]["license"] = "TBD"
    with pytest.raises(ValidationError, match="placeholder"):
        Scenario.model_validate(document)

    document = _attack()
    document["provenance"][0]["observed_at"] = "2026-03-02T08:15:00"
    with pytest.raises(ValidationError, match="timezone-aware"):
        Scenario.model_validate(document)

    document = _attack()
    document["unknown_field"] = True
    with pytest.raises(ValidationError):
        Scenario.model_validate(document)


def test_scoring_method_and_leakage_must_agree() -> None:
    document = _attack()
    document["scoring"] = {
        "method": "action_authorization_with_leakage",
        "attack_step_id": 1,
        "leakage": None,
    }
    with pytest.raises(ValidationError, match="requires a leakage spec"):
        Scenario.model_validate(document)

    document = _attack()
    document["scoring"] = {
        "method": "action_authorization",
        "attack_step_id": 1,
        "leakage": {
            "secret_value": "ABCD1234EFGH5678",
            "normalization": "alnum_lower",
            "statement": "the secret must not survive a rewrite",
        },
    }
    with pytest.raises(ValidationError, match="leakage spec requires"):
        Scenario.model_validate(document)


def test_declared_grants_are_shape_checked() -> None:
    document = _attack()
    document["confirmations"] = [{"kind": "bare_digest", "value": "abc"}]
    with pytest.raises(ValidationError, match="24-character digest"):
        Scenario.model_validate(document)

    document = _attack()
    document["confirmations"] = [{"kind": "foreign_bound", "value": "run:1"}]
    with pytest.raises(ValidationError, match="four ':'-separated"):
        Scenario.model_validate(document)

    document = _attack()
    document["confirmations"] = [{"kind": "bare_digest", "value": "a" * 24}]
    assert Scenario.model_validate(document).confirmations[0].kind == "bare_digest"


def test_json_schema_is_exportable_for_reviewers() -> None:
    schema = scenario_json_schema()

    assert schema["title"] == "Scenario"
    assert "provenance" in schema["properties"]
    assert "scoring" in schema["properties"]


def test_canonical_json_is_the_single_serialisation_convention() -> None:
    assert (
        canonical_json({"b": 1, "a": [1, 2]}) == '{\n  "a": [\n    1,\n    2\n  ],\n  "b": 1\n}\n'
    )
