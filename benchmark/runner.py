"""Drive the gateway over HTTP and write immutable run directories.

A *run* is the pair (configuration, outcome set) written into
``runs/<timestamp>-<config-slug>/``. A run directory is created exactly once:
``mkdir(exist_ok=False)`` is the only way it is created, so a second run into the
same name fails loudly rather than silently merging two different measurements.

What goes into a run
--------------------
``manifest.json``
    everything needed to reproduce the run: code commit, the gateway's declared
    policy set, the dataset hash, the evaluated scenario-set hash, model identity
    and parameters, seed, temperature, token limits, hardware note, dependency
    lock hash, the wire contract used, and the hashes of the outcome files.
``outcomes.jsonl``
    one judged outcome per scenario against the defence, with every raw verdict.
``control.jsonl``
    the same scenarios against the allow-all control. An attack claim is licensed
    only when the control authorizes the attack action.

The runner is the *only* place that performs I/O. Judgement lives in
:mod:`benchmark.scoring`; request assembly lives in :mod:`benchmark.wire`.
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from benchmark.control import ControlServer
from benchmark.dataset import Dataset, load_dataset, scenario_set_hash
from benchmark.schema import Scenario
from benchmark.scoring import Outcome, StepVerdict, derive_outcome
from benchmark.wire import build_plan_episode

MANIFEST_SCHEMA_VERSION = "aegisgraph-benchmark-run/v1"
DEFAULT_RUNS_DIR = "benchmark/runs"
DEFAULT_TIMEOUT_SECONDS = 10.0
GENERIC_PATH = "/api/v1/decisions"
VERSION_PATH = "/api/v1/version"
HEALTH_PATH = "/healthz"


class RunError(RuntimeError):
    """Raised when a run cannot start or cannot be written immutably."""


class ModelUnavailable(RunError):
    """Raised by a model adapter that has no reachable model behind it."""


# --------------------------------------------------------------------------- #
# Model adapters
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ModelIdentity:
    """Who proposed the actions, and with what settings.

    ``kind`` is one of ``scripted``, ``unavailable``. It is never ``real``: this
    environment has no model, and a run that could not call one must say so.
    """

    kind: str
    name: str
    version: str
    parameters: dict[str, Any] = field(default_factory=dict)
    note: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "version": self.version,
            "parameters": dict(sorted(self.parameters.items())),
            "note": self.note,
        }


class ModelAdapter(Protocol):
    """The injectable seam between the benchmark and whatever proposes actions."""

    def identity(self) -> ModelIdentity: ...

    def plan(self, scenario: Scenario) -> tuple[tuple[int, dict[str, Any]], ...]:
        """Return ``(step_id, action payload)`` pairs to send to the gateway."""


class ScriptedAdapter:
    """The deterministic no-model path: replay the scenario's authored script.

    This is the adapter every committed native run uses. It is a *harness*, not a
    claim about model behaviour: it asks "given this exact proposal, what does the
    defence decide?", which is the question the gateway can answer.
    """

    def identity(self) -> ModelIdentity:
        return ModelIdentity(
            kind="scripted",
            name="scripted-scenario-plan",
            version="1",
            parameters={"seed": None, "temperature": None, "max_tokens": None},
            note=(
                "no model is available in this environment; the scenario's authored "
                "action script is replayed verbatim, so the defence is measured, not the model"
            ),
        )

    def plan(self, scenario: Scenario) -> tuple[tuple[int, dict[str, Any]], ...]:
        return tuple(
            (proposed.step_id, proposed.action.model_dump(mode="json"))
            for proposed in scenario.proposed_actions
        )


class UnavailableModelAdapter:
    """A declared model adapter with no model behind it. Fails closed.

    The exact command that would make it real is recorded in the raised error and
    in the manifest, so a reviewer knows precisely what is missing rather than
    reading a plausible-looking fake.
    """

    def __init__(self, name: str, command: str) -> None:
        self._name = name
        self._command = command

    def identity(self) -> ModelIdentity:
        return ModelIdentity(
            kind="unavailable",
            name=self._name,
            version="0",
            parameters={"seed": None, "temperature": None, "max_tokens": None},
            note=f"blocked: {self._command}",
        )

    def plan(self, scenario: Scenario) -> tuple[tuple[int, dict[str, Any]], ...]:
        raise ModelUnavailable(
            f"model adapter {self._name!r} has no model behind it; to run it, "
            f"execute: {self._command}"
        )


def model_adapter(name: str) -> ModelAdapter:
    """Return the adapter for ``--model``. Only ``scripted`` runs here."""

    if name == "scripted":
        return ScriptedAdapter()
    if name == "ollama":
        return UnavailableModelAdapter(
            "ollama",
            "install Ollama, serve the reference model, then re-run with "
            "--model ollama (see docs/benchmark/evaluation-card.md)",
        )
    raise RunError(f"unknown model adapter {name!r}; available: scripted, ollama")


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RunConfig:
    defense_url: str
    dataset_root: Path
    runs_dir: Path
    model: ModelAdapter
    control_url: str | None = None
    splits: tuple[str, ...] = ("development", "validation")
    config_slug: str | None = None
    timestamp: str | None = None
    timeout: float = DEFAULT_TIMEOUT_SECONDS
    seed: int = 1729
    temperature: float | None = None
    max_tokens: int | None = None
    hardware_note: str = "unspecified host"
    lock_path: Path | None = None

    def slug(self) -> str:
        if self.config_slug:
            return _slugify(self.config_slug)
        split_slug = "-".join(self.splits)
        identity = self.model.identity()
        raw = f"{identity.kind}-{split_slug}"
        digest = hashlib.sha256(
            json.dumps(
                {
                    "defense_url": self.defense_url,
                    "splits": self.splits,
                    "model": identity.to_json(),
                    "seed": self.seed,
                    "temperature": self.temperature,
                    "max_tokens": self.max_tokens,
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()[:8]
        return _slugify(f"{raw}-{digest}")

    def run_name(self) -> str:
        stamp = self.timestamp or datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        return f"{stamp}-{self.slug()}"


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:64] or "run"


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class HttpResponse:
    status: int | None
    payload: dict[str, Any] | None
    error: str | None
    latency_ms: float | None


class HttpClient:
    """Minimal JSON-over-HTTP client. Standard library only, no hidden state."""

    def __init__(self, base_url: str, timeout: float) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def get(self, path: str) -> HttpResponse:
        return self._call("GET", path, None)

    def post(self, path: str, body: dict[str, Any]) -> HttpResponse:
        return self._call("POST", path, json.dumps(body, separators=(",", ":")).encode("utf-8"))

    def _call(self, method: str, path: str, body: bytes | None) -> HttpResponse:
        import time

        url = f"{self.base_url}{path}"
        request = Request(url, data=body, method=method)
        if body is not None:
            request.add_header("Content-Type", "application/json")
        started = time.perf_counter()
        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
                status = response.status
        except HTTPError as error:
            elapsed = (time.perf_counter() - started) * 1000
            try:
                detail = error.read().decode("utf-8")[:400]
            except Exception:  # pragma: no cover - defensive
                detail = ""
            return HttpResponse(
                status=error.code,
                payload=None,
                error=f"HTTP {error.code}: {detail}",
                latency_ms=elapsed,
            )
        except (URLError, TimeoutError, ConnectionError) as error:
            elapsed = (time.perf_counter() - started) * 1000
            return HttpResponse(
                status=None,
                payload=None,
                error=f"{type(error).__name__}: {error}",
                latency_ms=elapsed,
            )
        elapsed = (time.perf_counter() - started) * 1000
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            return HttpResponse(
                status=status,
                payload=None,
                error=f"invalid JSON response: {error}",
                latency_ms=elapsed,
            )
        if not isinstance(payload, dict):
            return HttpResponse(
                status=status,
                payload=None,
                error="response is not a JSON object",
                latency_ms=elapsed,
            )
        return HttpResponse(status=status, payload=payload, error=None, latency_ms=elapsed)


# --------------------------------------------------------------------------- #
# The run
# --------------------------------------------------------------------------- #


def _verdict_from(response: HttpResponse, step_id: int) -> StepVerdict:
    if response.error is not None or response.payload is None:
        return StepVerdict(
            step_id=step_id,
            http_status=response.status,
            decision=None,
            latency_ms=response.latency_ms,
            error=response.error or "no response payload",
        )
    payload = response.payload
    decision = payload.get("decision")
    if not isinstance(decision, str):
        return StepVerdict(
            step_id=step_id,
            http_status=response.status,
            decision=None,
            latency_ms=response.latency_ms,
            error="response has no decision field",
        )
    rewritten = payload.get("rewritten_action")
    return StepVerdict(
        step_id=step_id,
        http_status=response.status,
        decision=decision,
        reason_codes=tuple(str(code) for code in payload.get("reason_codes") or ()),
        risk_score=payload.get("risk_score"),
        latency_ms=response.latency_ms,
        execution_digest=payload.get("execution_digest"),
        rewritten_action=rewritten if isinstance(rewritten, dict) else None,
    )


def _git_commit() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).resolve().parent,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - environment dependent
        return "unknown"
    commit = result.stdout.strip()
    return commit if result.returncode == 0 and commit else "unknown"


def _git_branch() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).resolve().parent,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - environment dependent
        return "unknown"
    branch = result.stdout.strip()
    return branch if result.returncode == 0 and branch else "unknown"


def _file_sha256(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {"path": None, "sha256": None, "present": False}
    return {
        "path": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "present": True,
    }


def _jsonl(records: Sequence[dict[str, Any]]) -> bytes:
    return "".join(json.dumps(record, sort_keys=True) + "\n" for record in records).encode("utf-8")


@dataclass(frozen=True)
class RunResult:
    run_dir: Path
    manifest: dict[str, Any]
    outcomes: tuple[Outcome, ...]
    control_outcomes: tuple[Outcome, ...]


def execute_run(config: RunConfig, dataset: Dataset | None = None) -> RunResult:
    """Run the dataset against the defence and the control, then write the run."""

    loaded = dataset if dataset is not None else load_dataset(config.dataset_root)
    selected = tuple(
        entry.scenario for entry in loaded.entries if entry.scenario.split.value in config.splits
    )
    if not selected:
        raise RunError(f"no scenarios match splits {config.splits} in {config.dataset_root}")

    defense = HttpClient(config.defense_url, config.timeout)
    health = defense.get(HEALTH_PATH)
    if health.error is not None or health.status != 200:
        raise RunError(
            f"defence at {config.defense_url} is not healthy: "
            f"status={health.status} error={health.error}"
        )
    version = defense.get(VERSION_PATH)

    internal_control: ControlServer | None = None
    control_url = config.control_url
    if control_url is None:
        internal_control = ControlServer().start()
        control_url = internal_control.url
        control_kind = "internal-allow-all"
    else:
        control_kind = "external-allow-all"
    control = HttpClient(control_url, config.timeout)

    outcomes: list[Outcome] = []
    control_outcomes: list[Outcome] = []
    try:
        for index, scenario in enumerate(selected):
            from benchmark.wire import run_id_for

            run_id = run_id_for(index)
            plan = config.model.plan(scenario)
            original = {step_id: action for step_id, action in plan}

            defense_steps: list[StepVerdict] = []
            for request in build_plan_episode(scenario, run_id=run_id, plan=plan):
                response = defense.post(GENERIC_PATH, request)
                defense_steps.append(_verdict_from(response, int(request["step_id"])))
            outcomes.append(
                derive_outcome(scenario, tuple(defense_steps), original_actions=original)
            )

            control_steps: list[StepVerdict] = []
            for request in build_plan_episode(scenario, run_id=run_id, plan=plan):
                response = control.post(GENERIC_PATH, request)
                control_steps.append(_verdict_from(response, int(request["step_id"])))
            control_outcomes.append(
                derive_outcome(scenario, tuple(control_steps), original_actions=original)
            )
    finally:
        if internal_control is not None:
            internal_control.stop()

    run_dir = config.runs_dir / config.run_name()
    try:
        run_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError as error:
        raise RunError(f"refusing to overwrite an existing run directory: {run_dir}") from error

    outcome_bytes = _jsonl([outcome.to_json() for outcome in outcomes])
    control_bytes = _jsonl([outcome.to_json() for outcome in control_outcomes])
    (run_dir / "outcomes.jsonl").write_bytes(outcome_bytes)
    (run_dir / "control.jsonl").write_bytes(control_bytes)

    identity = config.model.identity()
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "run": {
            "name": run_dir.name,
            "created": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "immutable": True,
            "created_with": "mkdir(exist_ok=False)",
        },
        "code": {"commit": _git_commit(), "branch": _git_branch()},
        "defense": {
            "url": config.defense_url,
            "health": {"status": health.status},
            "version": version.payload,
            "version_error": version.error,
            "endpoint": GENERIC_PATH,
        },
        "control": {"url": control_url, "kind": control_kind},
        "policy_set": (version.payload or {}).get("policy_set"),
        "scenario_policy_sets": sorted(
            {
                f"{scenario.policy_context.policy_id}/{scenario.policy_context.policy_version}"
                for scenario in selected
            }
        ),
        "dataset": {
            "root": str(config.dataset_root),
            "sha256": loaded.dataset_hash(),
            "scenario_count": len(loaded.entries),
            "file_hashes": {entry.relative_path: entry.sha256 for entry in loaded.entries},
        },
        "scenario_set": {
            "sha256": scenario_set_hash(selected),
            "splits": list(config.splits),
            "scenario_count": len(selected),
            "scenario_ids": [scenario.id for scenario in selected],
        },
        "model": identity.to_json(),
        "seed": config.seed,
        "temperature": config.temperature,
        "max_tokens": config.max_tokens,
        "hardware": {
            "note": config.hardware_note,
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "machine": platform.machine(),
        },
        "dependency_lock": _file_sha256(config.lock_path),
        "artifacts": {
            "outcomes.jsonl": hashlib.sha256(outcome_bytes).hexdigest(),
            "control.jsonl": hashlib.sha256(control_bytes).hexdigest(),
        },
        "limitations": [
            "no model is available in this environment; the result measures the gateway "
            "under a scripted plan, not model behaviour",
            "the reachability control is a harness-liveness check for scripted plans: it "
            "licenses a scenario, it does not show a model falls for the payload",
        ],
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    (run_dir / "manifest.json").write_bytes(manifest_bytes)

    return RunResult(
        run_dir=run_dir,
        manifest=manifest,
        outcomes=tuple(outcomes),
        control_outcomes=tuple(control_outcomes),
    )


def load_run(run_dir: Path | str) -> tuple[dict[str, Any], list[Outcome], list[Outcome]]:
    """Read a written run back. Verifies the manifest hashes first."""

    base = Path(run_dir)
    manifest_path = base / "manifest.json"
    if not manifest_path.is_file():
        raise RunError(f"no manifest at {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    outcomes: list[Outcome] = []
    control: list[Outcome] = []
    for name, target in (("outcomes.jsonl", outcomes), ("control.jsonl", control)):
        path = base / name
        raw = path.read_bytes()
        recorded = (manifest.get("artifacts") or {}).get(name)
        actual = hashlib.sha256(raw).hexdigest()
        if recorded and recorded != actual:
            raise RunError(f"{path} does not match the manifest hash ({recorded} != {actual})")
        for line in raw.decode("utf-8").splitlines():
            if line.strip():
                target.append(Outcome.from_json(json.loads(line)))
    return manifest, outcomes, control


__all__ = [
    "MANIFEST_SCHEMA_VERSION",
    "ModelAdapter",
    "ModelIdentity",
    "ModelUnavailable",
    "RunConfig",
    "RunError",
    "RunResult",
    "ScriptedAdapter",
    "UnavailableModelAdapter",
    "execute_run",
    "load_run",
    "model_adapter",
]
