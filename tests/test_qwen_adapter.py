"""Tests for the Qwen3-8B adapter: parser, agent loop, identity, fail-closed path.

No torch and no network are used. A stub generator is the model seam, so these
tests pin the adapter's *logic* — the parser tolerances, the loop that feeds a
decision back, and the identity record — without a GPU. A separate subprocess
check proves the heavy toolchain stays out of module import.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from benchmark.fixtures import scenario_dict
from benchmark.qwen import (
    INSTALL_COMMAND,
    PROMPT_REVISION,
    QwenConfig,
    QwenModelAdapter,
    QwenParseError,
    build_messages,
    parse_action,
    render_prompt,
)
from benchmark.runner import ModelUnavailable, RunError, model_adapter
from benchmark.schema import Scenario

REPO_ROOT = Path(__file__).resolve().parents[1]


def _scenario() -> Scenario:
    return Scenario.model_validate(
        scenario_dict(scenario_id="ent_qwen_case", pair_id="pair_qwen_01")
    )


def _authored_outputs(scenario: Scenario) -> list[str]:
    return [json.dumps(item.action.model_dump(mode="json")) for item in scenario.proposed_actions]


def _torch_installed() -> bool:
    return importlib.util.find_spec("torch") is not None


SKIP_WITHOUT_TORCH = pytest.mark.skipif(
    _torch_installed(),
    reason="torch is importable; the missing-dependency path needs it absent",
)


class StubGenerator:
    """A scripted stand-in for the model: returns outputs in order, records prompts."""

    def __init__(self, outputs: list[str]) -> None:
        self._outputs = list(outputs)
        self.prompts: list[str] = []

    def __call__(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self._outputs:
            raise AssertionError("the adapter asked for more generations than the stub provided")
        return self._outputs.pop(0)


# --------------------------------------------------------------------------- #
# The parser
# --------------------------------------------------------------------------- #


def test_parse_action_reads_a_plain_json_object() -> None:
    spec = parse_action('{"type": "respond", "content": "done", "final": true}')

    assert spec.type.value == "respond"
    assert spec.content == "done"
    assert spec.final is True


def test_parse_action_extracts_an_object_from_surrounding_prose() -> None:
    spec = parse_action('Sure, here it is. {"type": "respond", "content": "ok"} Done.')

    assert spec.content == "ok"


def test_parse_action_accepts_a_fenced_json_block() -> None:
    text = 'Here is the action:\n```json\n{"type": "respond", "content": "hello"}\n```\n'

    assert parse_action(text).content == "hello"


def test_parse_action_strips_a_thinking_block_and_uses_the_answer_after_it() -> None:
    open_tag = "\x3cthink\x3e"
    close_tag = "\x3c/think\x3e"
    text = (
        f"{open_tag} I could call "
        '{"type": "tool_call", "tool": "email_send"} but I will answer '
        f"{close_tag}\n"
        '{"type": "respond", "content": "blocked", "final": true}'
    )

    spec = parse_action(text)

    assert spec.type.value == "respond"
    assert spec.content == "blocked"


def test_parse_action_raises_with_the_bounded_raw_output() -> None:
    with pytest.raises(QwenParseError) as excinfo:
        parse_action("I will not comply with that request.", step_id=1)

    error = excinfo.value
    assert error.raw_output == "I will not comply with that request."
    assert error.step_id == 1
    assert error.reason == "no-json-object"
    assert "I will not comply with that request." in str(error)
    assert isinstance(error, RunError)


def test_parse_action_rejects_json_that_violates_the_action_schema() -> None:
    with pytest.raises(QwenParseError) as excinfo:
        parse_action('{"type": "tool_call"}')

    assert excinfo.value.reason == "invalid-action"
    assert '{"type": "tool_call"}' in excinfo.value.raw_output


# --------------------------------------------------------------------------- #
# The agent loop
# --------------------------------------------------------------------------- #


def test_plan_generates_one_action_per_authored_step() -> None:
    scenario = _scenario()
    generator = StubGenerator(_authored_outputs(scenario))
    adapter = QwenModelAdapter(QwenConfig(), generator=generator)

    plan = adapter.plan(scenario)

    assert [step_id for step_id, _ in plan] == [item.step_id for item in scenario.proposed_actions]
    assert dict(plan) == {
        item.step_id: item.action.model_dump(mode="json") for item in scenario.proposed_actions
    }
    assert len(generator.prompts) == len(scenario.proposed_actions)


def test_plan_feeds_the_previous_decision_back_into_the_next_prompt() -> None:
    scenario = _scenario()
    generator = StubGenerator(_authored_outputs(scenario))
    adapter = QwenModelAdapter(QwenConfig(), generator=generator)
    sentinel = "FIRST-DECISION-SENTINEL"

    def decide(step_id: int, action: dict[str, Any]) -> dict[str, Any]:
        return {"decision": "block", "note": sentinel}

    plan = adapter.plan(scenario, decide=decide)

    assert len(generator.prompts) == 2
    assert sentinel not in generator.prompts[0]
    assert sentinel in generator.prompts[1]
    first_action = json.dumps(plan[0][1], sort_keys=True, separators=(",", ":"))
    assert first_action in generator.prompts[1]


def test_plan_surfaces_a_parse_failure_instead_of_a_silent_success() -> None:
    scenario = _scenario()
    adapter = QwenModelAdapter(QwenConfig(), generator=StubGenerator(["not json at all"]))

    with pytest.raises(QwenParseError) as excinfo:
        adapter.plan(scenario)

    assert excinfo.value.raw_output == "not json at all"
    assert excinfo.value.step_id == scenario.proposed_actions[0].step_id


def test_plan_resumes_the_loop_when_the_model_answers_finally() -> None:
    scenario = _scenario()
    final = '{"type": "respond", "content": "done", "final": true}'
    adapter = QwenModelAdapter(QwenConfig(), generator=StubGenerator([final]))

    plan = adapter.plan(scenario)

    assert [step_id for step_id, _ in plan] == [scenario.proposed_actions[0].step_id]


def test_the_prompt_carries_the_goal_evidence_tools_and_revision() -> None:
    scenario = _scenario()

    text = render_prompt(build_messages(scenario))

    assert scenario.user_goal in text
    assert scenario.observations[0].provenance_id in text
    assert scenario.policy_context.allowed_tools[0] in text
    assert PROMPT_REVISION in text


# --------------------------------------------------------------------------- #
# Identity and the fail-closed path
# --------------------------------------------------------------------------- #


def test_identity_records_every_configuration_field() -> None:
    config = QwenConfig(
        model_id="Qwen/Qwen3-8B",
        revision="abc123def",
        quantization="4bit",
        dtype="float16",
        seed=7,
        temperature=0.6,
        top_p=0.9,
        max_new_tokens=256,
        thinking=True,
        device="cuda:1",
    )
    adapter = QwenModelAdapter(config, generator=StubGenerator(["{}"]))

    identity = adapter.identity()

    assert identity.kind == "qwen3-8b"
    assert identity.name == "Qwen/Qwen3-8B"
    assert identity.version == "abc123def"
    for key, value in config.to_json().items():
        assert identity.parameters[key] == value
    assert identity.parameters["prompt_revision"] == PROMPT_REVISION
    assert "torch" in identity.parameters
    assert "transformers" in identity.parameters
    assert "quantization=4bit" in identity.note
    assert "thinking=on" in identity.note


def test_a_quantization_outside_the_vocabulary_is_rejected() -> None:
    with pytest.raises(ValueError, match="quantization"):
        QwenConfig(quantization="2bit")  # type: ignore[arg-type]


@SKIP_WITHOUT_TORCH
def test_load_without_torch_fails_closed_naming_the_install_command() -> None:
    adapter = QwenModelAdapter(QwenConfig())

    with pytest.raises(ModelUnavailable) as excinfo:
        adapter.load()

    message = str(excinfo.value)
    assert "torch" in message
    assert "transformers" in message
    assert INSTALL_COMMAND in message
    assert "--model qwen" in message


@SKIP_WITHOUT_TORCH
def test_the_runner_factory_and_cli_path_fail_closed_without_torch() -> None:
    adapter = model_adapter("qwen")

    assert adapter.identity().kind == "qwen3-8b"
    with pytest.raises(ModelUnavailable, match="pip install"):
        adapter.plan(_scenario())


def test_importing_the_module_does_not_import_the_heavy_toolchain() -> None:
    code = (
        "import sys; import benchmark.qwen; "
        "assert 'torch' not in sys.modules, 'torch was imported at module import'; "
        "assert 'transformers' not in sys.modules, 'transformers was imported at module import'"
    )

    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.returncode == 0, result.stderr
