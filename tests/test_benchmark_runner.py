"""Runner tests: a live gateway, an immutable run directory, a full manifest."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from benchmark.runner import (
    RunConfig,
    RunError,
    ScriptedAdapter,
    UnavailableModelAdapter,
    execute_run,
    load_run,
    model_adapter,
)
from benchmark.scoring import score

DATA_ROOT = Path(__file__).resolve().parents[1] / "benchmark" / "data"
VALIDATION_SPLITS = ("validation",)


@contextmanager
def running_gateway() -> Iterator[str]:
    """Start the real gateway on an ephemeral port and yield its base URL."""

    import uvicorn
    from aegisgraph.app import app

    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 30
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    if not server.started:
        raise RuntimeError("the gateway did not start")
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=15)


def _config(url: str, runs_dir: Path, **overrides: object) -> RunConfig:
    kwargs: dict[str, object] = {
        "defense_url": url,
        "dataset_root": DATA_ROOT,
        "runs_dir": runs_dir,
        "model": ScriptedAdapter(),
        "splits": VALIDATION_SPLITS,
        "timestamp": "20260101T000000Z",
        "config_slug": "pytest",
        "hardware_note": "pytest host",
        "lock_path": Path(__file__).resolve().parents[1] / "requirements.lock",
    }
    kwargs.update(overrides)
    return RunConfig(**kwargs)  # type: ignore[arg-type]


def test_dry_run_against_a_local_gateway_writes_an_immutable_run(tmp_path: Path) -> None:
    with running_gateway() as url:
        result = execute_run(_config(url, tmp_path))

    run_dir = result.run_dir
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    outcomes = [
        json.loads(line)
        for line in (run_dir / "outcomes.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    assert run_dir.name == "20260101T000000Z-pytest"
    assert len(outcomes) == len(result.outcomes) > 0
    assert manifest["run"]["immutable"] is True
    assert manifest["run"]["created_with"] == "mkdir(exist_ok=False)"
    assert manifest["code"]["commit"] != ""
    assert manifest["dataset"]["sha256"] != ""
    assert manifest["scenario_set"]["sha256"] != ""
    assert manifest["scenario_set"]["splits"] == list(VALIDATION_SPLITS)
    assert manifest["model"]["kind"] == "scripted"
    assert manifest["seed"] == 1729
    assert manifest["temperature"] is None
    assert manifest["max_tokens"] is None
    assert manifest["hardware"]["note"] == "pytest host"
    assert manifest["dependency_lock"]["present"] is True
    assert manifest["control"]["kind"] == "internal-allow-all"
    assert manifest["defense"]["health"]["status"] == 200
    assert manifest["limitations"]

    report = score(result.outcomes, control_outcomes=result.control_outcomes)
    assert report.control.asr == 1.0
    assert report.overall.attack_count == report.overall.benign_count
    assert report.overall.asr is not None
    assert report.overall.benign_task_success is not None


def test_a_second_run_into_the_same_directory_fails(tmp_path: Path) -> None:
    with running_gateway() as url:
        first = execute_run(_config(url, tmp_path))
        with pytest.raises(RunError, match="refusing to overwrite"):
            execute_run(_config(url, tmp_path))

    assert (first.run_dir / "manifest.json").is_file()


def test_load_run_verifies_the_recorded_artifact_hashes(tmp_path: Path) -> None:
    with running_gateway() as url:
        result = execute_run(_config(url, tmp_path))

    manifest, outcomes, control = load_run(result.run_dir)
    assert manifest["run"]["name"] == result.run_dir.name
    assert len(outcomes) == len(control)

    (result.run_dir / "outcomes.jsonl").write_text("{}\n", encoding="utf-8")
    with pytest.raises(RunError, match="does not match the manifest hash"):
        load_run(result.run_dir)


def test_an_unhealthy_gateway_fails_before_any_directory_is_created(tmp_path: Path) -> None:
    config = _config("http://127.0.0.1:1", tmp_path)

    with pytest.raises(RunError, match="not healthy"):
        execute_run(config)

    assert list(tmp_path.iterdir()) == []


def test_the_derived_run_slug_depends_on_the_configuration(tmp_path: Path) -> None:
    base = _config("http://127.0.0.1:1", tmp_path, config_slug=None)
    other = _config("http://127.0.0.1:1", tmp_path, config_slug=None, seed=99)

    assert base.slug() != other.slug()
    assert base.run_name() != other.run_name()
    assert base.slug().isascii()


def test_the_unavailable_model_adapter_fails_closed_with_the_exact_command() -> None:
    adapter = model_adapter("ollama")
    assert isinstance(adapter, UnavailableModelAdapter)

    with pytest.raises(RunError, match="install Ollama"):
        adapter.plan(None)  # type: ignore[arg-type]


def test_an_unknown_model_adapter_is_rejected() -> None:
    with pytest.raises(RunError, match="unknown model adapter"):
        model_adapter("gpt-9")
