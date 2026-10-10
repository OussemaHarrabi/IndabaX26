"""Drive the multi-stage Qwen3-8B campaign, resumably, on a hosted runtime.

A *campaign run* is one ``(stage, condition, seed)`` measured over the stage's
scenario set, with the model in the loop: for every step the adapter generates an
action, the driver posts it to the decision surface, records the verdict and feeds
that verdict back into the next generation. It writes one run directory and
**never rewrites a completed one**.

What this module is responsible for, and what it deliberately is not
--------------------------------------------------------------------
*It is* the executor: the per-scenario loop, the per-scenario atomic checkpoint,
the artifact writer, the resume rule, the failure record and the bundle. *It is
not* the judge (``benchmark.scoring``), the request builder (``benchmark.wire``),
the manifest schema (``benchmark.runner``), the model (``benchmark.qwen``) or the
scorer (``scripts/bench_score.py``). Every one of those is imported, so a
notebook cell and this driver cannot disagree about what was measured.

Failure discipline
------------------
The frozen runner aborts a run on a non-2xx decision response, which is right for
a scripted benchmark: a refusal must never become a verdict. A campaign run
cannot afford that — a Colab session that dies at scenario 39 of 42 must keep the
38 it measured — so here a parse failure, a gateway non-2xx, a timeout and an
interruption each become an **errored outcome** plus a row in ``failures.jsonl``,
and the campaign moves to the next scenario. An errored outcome can never be read
as "the attack was stopped": it carries ``attack_success = null``, the scorer
counts it in ``errored_attacks`` and, intention-to-treat, as a failure.

Immutability and resume
-----------------------
One run directory per ``(stage, condition, seed)``, created with
``mkdir(exist_ok=False)``. Each completed scenario is written to
``checkpoints/<scenario_id>.json`` through a temporary file and an atomic rename,
then the derived artifacts and ``hashes.sha256`` are rewritten atomically. On
resume the recorded hash of every checkpoint is verified against
``hashes.sha256``; a verified entry is skipped, a missing or mismatching one is
re-run, and a mismatching checkpoint is moved to ``checkpoints/rejected/`` rather
than deleted, with the mismatch itself recorded as a failure.
"""

from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import os
import platform
import re
import subprocess
import sys
import time
import zipfile
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any
from uuid import uuid4

from benchmark.control import ControlServer
from benchmark.dataset import Dataset, DatasetEntry, load_dataset, scenario_set_hash
from benchmark.qwen import (
    PROMPT_REVISION,
    QwenConfig,
    QwenModelAdapter,
    QwenParseError,
    StepTrace,
    build_messages,
    render_prompt,
)
from benchmark.runner import (
    DEFAULT_TIMEOUT_SECONDS,
    GENERIC_PATH,
    HASH_CONVENTION,
    HEALTH_PATH,
    VERSION_PATH,
    AuthConfig,
    HttpClient,
    ModelAdapter,
    ModelIdentity,
    ModelUnavailable,
    RunError,
    _git_branch,
    _git_commit,
    _git_dirty,
    _jsonl,
    build_run_manifest,
    content_sha256,
    decision_verdict,
    model_adapter,
)
from benchmark.runner import _git_root as _repo_root
from benchmark.schema import Scenario
from benchmark.scoring import StepVerdict, derive_outcome
from benchmark.wire import build_request, run_id_for

CAMPAIGN_SCHEMA_VERSION = "aegisgraph-campaign/v1"
CHECKPOINT_SCHEMA_VERSION = "aegisgraph-campaign-checkpoint/v1"
ENVIRONMENT_SCHEMA_VERSION = "aegisgraph-campaign-environment/v1"
CONFIGURATION_SCHEMA_VERSION = "aegisgraph-campaign-configuration/v1"
FAILURE_SCHEMA_VERSION = "aegisgraph-campaign-failure/v1"

FREEZE_BLOCK = "docs/evidence/qwen-campaign-freeze.md (block 4)"
PROTOCOL = "docs/research/qwen3-8b-campaign.md"

STAGES: tuple[str, ...] = ("A", "B", "C", "D")
CONDITION_CONTROL = "control"
CONDITION_DEFENCE = "defence"
CONDITION_ABLATION = "ablation"

#: The anchor seed. Stage A runs exactly this seed (freeze block 1 §3); stages
#: B-D use the preregistered list the operator declares before Stage A.
ANCHOR_SEED = 1729

#: Stage → (required seeds, preferred seeds). The floor is the freeze block's:
#: B and C need at least three preregistered seeds (five preferred); A and D run
#: exactly once.
STAGE_SEED_RULES: dict[str, tuple[int, int]] = {
    "A": (1, 1),
    "B": (3, 5),
    "C": (3, 5),
    "D": (1, 1),
}

STAGE_SPLITS: dict[str, tuple[str, ...]] = {
    "A": ("development", "validation"),
    "B": ("development",),
    "C": ("validation",),
    "D": ("holdout",),
}

#: Stage A's fixed smoke set (freeze block 1 §2.1): one matched pair per domain,
#: spanning both open splits. Fixed here because the freeze fixed it.
SMOKE_SCENARIOS: tuple[str, ...] = (
    "ent_direct_injection_vendor_note_attack",
    "ent_direct_injection_vendor_note_control",
    "fin_memory_poisoning_standing_release_attack",
    "fin_memory_poisoning_standing_release_control",
    "soc_replay_tampering_grant_attack",
    "soc_replay_tampering_grant_control",
)

#: The artifacts the protocol requires in every run directory. ``score.json``,
#: ``score.txt`` and ``statistics.json`` are written by other tools (protocol §8)
#: and are hashed by the bundle step when they are present; this driver never
#: writes them.
RUN_ARTIFACTS: tuple[str, ...] = (
    "manifest.json",
    "environment.json",
    "configuration.json",
    "raw_generations.jsonl",
    "proposed_actions.jsonl",
    "decisions.jsonl",
    "outcomes.jsonl",
    "control.jsonl",
    "failures.jsonl",
    "hashes.sha256",
    "pip-freeze.txt",
)

CHECKPOINT_DIR = "checkpoints"
REJECTED_DIR = "rejected"
HASHES_FILE = "hashes.sha256"
MANIFEST_FILE = "manifest.json"
CONFIGURATION_FILE = "configuration.json"
ENVIRONMENT_FILE = "environment.json"
PIP_FREEZE_FILE = "pip-freeze.txt"

#: ``--model`` name → the run-directory prefix. Keeping the prefix in the
#: directory name makes a scripted proof read as one, next to a real run.
MODEL_PREFIX: dict[str, str] = {"qwen": "qwen3-8b", "scripted": "scripted", "ollama": "ollama"}

#: Failure causes, so a reader can count them without parsing free text.
CAUSE_MODEL_PARSE = "model-parse-failure"
CAUSE_GATEWAY = "gateway-error"
CAUSE_TIMEOUT = "gateway-timeout"
CAUSE_CONNECTION = "connection-error"
CAUSE_CONTROL = "control-error"
CAUSE_INTERRUPTION = "interruption"
CAUSE_ADAPTER = "adapter-error"
CAUSE_UNEXPECTED = "unexpected-error"
CAUSE_CHECKPOINT = "checkpoint-hash-mismatch"

#: How many characters of a raw model output a failure row carries.
MAX_FAILURE_RAW_OUTPUT = 2000

_PIP_FREEZE_CACHE: bytes | None = None


class CampaignError(RunError):
    """A campaign run cannot start, or cannot be resumed, as configured."""


class _StepFailure(RunError):
    """One step failed in a way the campaign records rather than aborts on."""

    def __init__(
        self,
        cause: str,
        detail: str,
        *,
        step_id: int | None,
        phase: str,
        http_status: int | None = None,
        raw_output: str | None = None,
    ) -> None:
        super().__init__(detail)
        self.cause = cause
        self.detail = detail
        self.step_id = step_id
        self.phase = phase
        self.http_status = http_status
        self.raw_output = raw_output


# --------------------------------------------------------------------------- #
# Condition
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Condition:
    """The preregistered condition: which arm the run measures as its treatment."""

    name: str
    ablation: str | None = None

    @property
    def slug(self) -> str:
        if self.name == CONDITION_ABLATION:
            return f"ablation-{self.ablation}"
        return self.name

    @property
    def treatment_is_control(self) -> bool:
        """Whether the treatment endpoint is the harness allow-all control."""

        return self.name == CONDITION_CONTROL

    def to_json(self) -> dict[str, Any]:
        return {"name": self.name, "ablation": self.ablation, "slug": self.slug}


def parse_condition(value: str) -> Condition:
    """Parse ``control`` | ``defence`` | ``ablation:<name>``."""

    if value in (CONDITION_CONTROL, CONDITION_DEFENCE):
        return Condition(name=value)
    prefix = f"{CONDITION_ABLATION}:"
    if value.startswith(prefix):
        name = value[len(prefix) :].strip()
        if not name:
            raise CampaignError(
                "--condition ablation:<name> needs a component name, e.g. ablation:kernel"
            )
        return Condition(name=CONDITION_ABLATION, ablation=name)
    raise CampaignError(
        f"unknown condition {value!r}; expected control, defence, or ablation:<name>"
    )


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CampaignConfig:
    """Everything one campaign invocation needs. Frozen once the run starts.

    ``adapter`` wins over ``model_name`` when it is set: the notebooks pass a
    ``QwenModelAdapter`` they configured, the tests pass one with a stub
    generator, and the CLI builds one from ``--model`` and ``--adapter-json``.
    ``declared_seeds`` is the full preregistered seed list the invocation belongs
    to (recorded, and used to enforce the stage's seed floor); one invocation
    still runs exactly ``seed``.
    """

    stage: str
    dataset_root: Path
    runs_dir: Path
    seed: int = ANCHOR_SEED
    declared_seeds: tuple[int, ...] = ()
    condition: str = CONDITION_DEFENCE
    model_name: str = "qwen"
    adapter_config: dict[str, Any] = field(default_factory=dict)
    adapter: ModelAdapter | None = None
    gateway_url: str = "http://127.0.0.1:8091"
    control_url: str | None = None
    auth: AuthConfig | None = None
    timeout: float = DEFAULT_TIMEOUT_SECONDS
    hardware_note: str = "unspecified host"
    lock_path: Path | None = None
    resume: bool = False
    bundle: bool = False
    authorize_holdout: bool = False
    holdout_dir: Path | None = None
    splits: tuple[str, ...] | None = None
    scenario_ids: tuple[str, ...] | None = None
    timestamp: str | None = None
    max_scenarios: int | None = None
    tbd: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.stage not in STAGES:
            raise CampaignError(
                f"unknown stage {self.stage!r}; expected one of {', '.join(STAGES)}"
            )
        parse_condition(self.condition)
        if self.seed < 0:
            raise CampaignError(f"seed must be >= 0, got {self.seed}")
        if self.max_scenarios is not None and self.max_scenarios < 1:
            raise CampaignError(f"--max-scenarios must be >= 1, got {self.max_scenarios}")

    @property
    def condition_obj(self) -> Condition:
        return parse_condition(self.condition)

    @property
    def seeds(self) -> tuple[int, ...]:
        return tuple(self.declared_seeds) if self.declared_seeds else (self.seed,)

    def split_selection(self) -> tuple[str, ...]:
        return tuple(self.splits) if self.splits is not None else STAGE_SPLITS[self.stage]

    def id_selection(self) -> tuple[str, ...] | None:
        if self.scenario_ids is not None:
            return tuple(self.scenario_ids)
        if self.stage == "A":
            return SMOKE_SCENARIOS
        return None

    def run_slug(self) -> str:
        """``<model>-<stage>-<condition>-s<seed>``; the condition is omitted for defence."""

        prefix = MODEL_PREFIX.get(self.model_name, _slugify(self.model_name))
        parts = [prefix, self.stage.lower()]
        if self.condition != CONDITION_DEFENCE:
            parts.append(self.condition_obj.slug)
        parts.append(f"s{self.seed}")
        return _slugify("-".join(parts))

    def run_name(self, timestamp: str | None = None) -> str:
        stamp = timestamp or self.timestamp or _utc_stamp()
        return f"{stamp}-{self.run_slug()}"

    def resolve_model(self) -> ModelAdapter:
        if self.adapter is not None:
            return self.adapter
        if self.model_name == "qwen":
            payload = dict(self.adapter_config)
            # The campaign seed is the experimental unit.  A stale seed in a
            # reusable adapter JSON must never collapse a multi-seed campaign
            # into repeated copies of the same model stream.
            payload["seed"] = self.seed
            return QwenModelAdapter(_qwen_config(payload))
        return model_adapter(self.model_name)


def _slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:64] or "run"


def _qwen_config(adapter_config: Mapping[str, Any]) -> QwenConfig:
    """Build the frozen inference configuration, failing closed on a typo."""

    try:
        return QwenConfig(**dict(adapter_config))
    except TypeError as error:
        known = sorted(QwenConfig.__dataclass_fields__)
        raise CampaignError(
            f"adapter configuration has an unknown field ({error}); known fields: {known}"
        ) from error
    except ValueError as error:
        raise CampaignError(f"adapter configuration is invalid: {error}") from error


def validate_adapter_config(config: CampaignConfig) -> None:
    """Fail closed on an adapter configuration with an unknown or invalid field.

    Checked before anything is touched, including in the dry run: a typo in
    ``--adapter-json`` must not be discovered halfway through a GPU session.
    """

    if config.adapter_config:
        _qwen_config(config.adapter_config)


def validate_seed_count(stage: str, seeds: Sequence[int]) -> dict[str, Any]:
    """Enforce the freeze block's seed counts for an invocation given ``seeds``.

    The floor is what the freeze block licenses: three seeds for B and C, one for
    A and D. Fewer than the preferred count is allowed only where the freeze
    allows it (C is three-floor/five-preferred) and is reported, never silently
    accepted. Seeds are never chosen after seeing outcomes.
    """

    if stage not in STAGE_SEED_RULES:
        raise CampaignError(f"unknown stage {stage!r}")
    required, preferred = STAGE_SEED_RULES[stage]
    if not seeds:
        raise CampaignError(f"stage {stage} needs at least {required} preregistered seed(s)")
    if len(set(seeds)) != len(seeds):
        raise CampaignError(f"stage {stage} was given duplicate seeds: {list(seeds)}")
    if len(seeds) < required:
        raise CampaignError(
            f"stage {stage} needs at least {required} preregistered seed(s), got {len(seeds)}; "
            "the seed list is declared before Stage A and is never chosen after seeing outcomes"
        )
    if stage in ("A", "D") and len(seeds) > required:
        raise CampaignError(f"stage {stage} runs exactly {required} seed(s), got {len(seeds)}")
    return {
        "seeds": list(seeds),
        "count": len(seeds),
        "required": required,
        "preferred": preferred,
        "below_required": len(seeds) < required,
        "below_preferred": len(seeds) < preferred,
    }


# --------------------------------------------------------------------------- #
# Stage plan (pure: no network, no directory, no model load)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class StagePlan:
    """What one invocation would run, resolved before anything is touched."""

    stage: str
    condition: Condition
    seed: int
    splits: tuple[str, ...]
    scenarios: tuple[Scenario, ...]
    dataset: Dataset
    dataset_source: str
    dataset_root: Path
    run_slug: str
    model_name: str

    @property
    def scenario_ids(self) -> tuple[str, ...]:
        return tuple(scenario.id for scenario in self.scenarios)

    def to_json(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "condition": self.condition.to_json(),
            "seed": self.seed,
            "splits": list(self.splits),
            "dataset_source": self.dataset_source,
            "dataset_root": str(self.dataset_root),
            "dataset_sha256": self.dataset.dataset_hash(),
            "scenario_set_sha256": scenario_set_hash(self.scenarios),
            "scenario_count": len(self.scenarios),
            "scenario_ids": list(self.scenario_ids),
            "run_slug": self.run_slug,
            "model": self.model_name,
        }


def _holdout_dataset(root: Path) -> Dataset:
    """Load the unsealed holdout plaintext, written flat as ``<id>.json``.

    ``benchmark.dataset.load_dataset`` never reads the holdout, by design; the
    plaintext only exists after ``scripts/bench_seal.py open --out <dir>``, which
    is why Stage D needs this separate, explicit loader.
    """

    if not root.is_dir():
        raise CampaignError(
            f"the holdout plaintext directory {root} does not exist; open the seal first "
            "(scripts/bench_seal.py open --out <dir>) — Stage D refuses to run otherwise"
        )
    files = sorted(root.glob("*.json"))
    if not files:
        raise CampaignError(f"no plaintext holdout scenarios under {root}")
    entries: list[DatasetEntry] = []
    for path in files:
        raw = path.read_bytes()
        try:
            scenario = Scenario.model_validate(json.loads(raw.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise CampaignError(f"{path}: not a valid holdout scenario: {error}") from error
        if scenario.split.value != "holdout":
            raise CampaignError(
                f"{path}: split is {scenario.split.value!r}, not 'holdout'; refusing to run "
                "Stage D over a non-holdout scenario"
            )
        entries.append(
            DatasetEntry(
                relative_path=path.name,
                sha256=hashlib.sha256(raw).hexdigest(),
                scenario=scenario,
            )
        )
    entries.sort(key=lambda entry: entry.scenario.id)
    return Dataset(root=root, entries=tuple(entries))


def plan_stage(config: CampaignConfig) -> StagePlan:
    """Resolve the stage's scenarios without touching a socket or a directory."""

    condition = config.condition_obj
    splits = config.split_selection()
    if config.stage == "D":
        if config.holdout_dir is None:
            raise CampaignError("Stage D needs --holdout-dir (the unsealed plaintext directory)")
        dataset = _holdout_dataset(config.holdout_dir)
        dataset_root = config.holdout_dir
        source = "holdout-plaintext"
        selected = dataset.scenarios
    else:
        if "holdout" in splits:
            raise CampaignError(
                "the sealed holdout is Stage D only; it cannot be run through --splits"
            )
        dataset = load_dataset(config.dataset_root)
        dataset_root = config.dataset_root
        source = "dataset"
        wanted = config.id_selection()
        if wanted is not None:
            by_id = dataset.by_id
            missing = [scenario_id for scenario_id in wanted if scenario_id not in by_id]
            if missing:
                raise CampaignError(
                    f"the stage's fixed scenario set is not in {dataset_root}: missing {missing}"
                )
            selected = tuple(by_id[scenario_id] for scenario_id in wanted)
            outside = sorted(
                {
                    scenario.split.value
                    for scenario in selected
                    if scenario.split.value not in splits
                }
            )
            if outside:
                raise CampaignError(
                    f"the fixed scenario set declares splits {outside} outside {splits}"
                )
        else:
            selected = tuple(
                entry.scenario for entry in dataset.entries if entry.scenario.split.value in splits
            )
    if not selected:
        raise CampaignError(f"no scenarios selected for stage {config.stage} in {dataset_root}")

    return StagePlan(
        stage=config.stage,
        condition=condition,
        seed=config.seed,
        splits=splits,
        scenarios=selected,
        dataset=dataset,
        dataset_source=source,
        dataset_root=dataset_root,
        run_slug=config.run_slug(),
        model_name=config.model_name,
    )


# --------------------------------------------------------------------------- #
# Atomic writes, checkpoints and hashes
# --------------------------------------------------------------------------- #


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` through a temporary file and an atomic rename."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid4().hex[:8]}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    handle = os.open(temporary, flags, 0o644)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        with suppress(OSError):
            temporary.unlink()
        raise


def _atomic_write_text(path: Path, text: str) -> None:
    _atomic_write_bytes(path, text.encode("utf-8"))


def _atomic_write_json(path: Path, payload: Any) -> None:
    _atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _raw_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_temporary(name: str) -> bool:
    return name.startswith(".") or ".tmp" in name


def _hashed_paths(run_dir: Path) -> list[Path]:
    """Every file the run directory hashes, in a deterministic order.

    Everything present is covered, not just the named artifacts: a ``score.json``
    written after the run is part of the bundle's integrity claim, so the hash
    manifest is extended to it at bundle time rather than leaving it uncovered.
    """

    paths: list[Path] = []
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file() or _is_temporary(path.name):
            continue
        if path == run_dir / HASHES_FILE:
            continue
        paths.append(path)
    return paths


def read_hashes(run_dir: Path) -> dict[str, str]:
    """Parse ``hashes.sha256`` into ``{relative posix path: digest}``."""

    path = run_dir / HASHES_FILE
    if not path.is_file():
        return {}
    recorded: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split("  ", 1)
        if len(parts) != 2:
            continue
        recorded[parts[1].strip()] = parts[0].strip()
    return recorded


#: The declaration line ``hashes.sha256`` opens with. It is a fixed token, not a
#: sentence, because a reader has to be able to select the hashing function from
#: it; the explanation follows on the next comment line.
CONVENTION_NAME = "content-sha256-lf"
HASH_DECLARATION = f"# convention: {CONVENTION_NAME}"


def write_hashes(run_dir: Path) -> dict[str, str]:
    """Recompute ``hashes.sha256`` over every artifact of the run directory.

    The file opens with ``# convention: content-sha256-lf`` and then one
    ``sha256sum``-format line per artifact (``<digest>  <relative-path>``, paths
    relative to the run directory). **Every** entry is taken under that one
    declared convention — ``sha256(bytes)`` with CRLF normalised to LF — including
    artifacts another tool wrote through the platform's text mode (``score.json``
    on a Windows host): no entry is hashed raw, so the file never mixes
    conventions. ``sha256sum -c hashes.sha256`` verifies it as written because
    every file this driver writes uses LF, and a reader that honours the
    declaration verifies the rest on any platform.
    """

    lines = [HASH_DECLARATION, f"# {HASH_CONVENTION}"]
    recorded: dict[str, str] = {}
    for path in _hashed_paths(run_dir):
        relative = path.relative_to(run_dir).as_posix()
        digest = content_sha256(path.read_bytes())
        recorded[relative] = digest
        lines.append(f"{digest}  {relative}")
    _atomic_write_text(run_dir / HASHES_FILE, "\n".join(lines) + "\n")
    return recorded


def count_failures(run_dir: Path) -> int:
    """How many rows ``failures.jsonl`` holds (0 when the file is absent)."""

    path = run_dir / "failures.jsonl"
    if not path.is_file():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def verify_hashes(run_dir: Path) -> dict[str, Any]:
    """Verify every entry of ``hashes.sha256``; report what is missing or wrong."""

    recorded = read_hashes(run_dir)
    missing: list[str] = []
    mismatched: list[dict[str, str]] = []
    for relative, digest in sorted(recorded.items()):
        path = run_dir / relative
        if not path.is_file():
            missing.append(relative)
            continue
        actual = content_sha256(path.read_bytes())
        if actual != digest:
            mismatched.append({"path": relative, "recorded": digest, "actual": actual})
    return {
        "hash_convention": CONVENTION_NAME,
        "hash_convention_note": HASH_CONVENTION,
        "recorded": len(recorded),
        "missing": missing,
        "mismatched": mismatched,
        "ok": bool(recorded) and not missing and not mismatched,
    }


# --------------------------------------------------------------------------- #
# The per-scenario record
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ScenarioRecord:
    """One completed scenario: the checkpoint, and the unit of resume."""

    scenario_id: str
    attempt: int
    status: str
    outcome: dict[str, Any]
    control_outcome: dict[str, Any]
    generations: tuple[dict[str, Any], ...]
    proposals: tuple[dict[str, Any], ...]
    decisions: tuple[dict[str, Any], ...]
    failures: tuple[dict[str, Any], ...]
    recorded_at: str
    duration_ms: float | None

    def to_json(self) -> dict[str, Any]:
        return {
            "checkpoint_version": CHECKPOINT_SCHEMA_VERSION,
            "scenario_id": self.scenario_id,
            "attempt": self.attempt,
            "status": self.status,
            "recorded_at": self.recorded_at,
            "duration_ms": self.duration_ms,
            "outcome": self.outcome,
            "control_outcome": self.control_outcome,
            "generations": list(self.generations),
            "proposals": list(self.proposals),
            "decisions": list(self.decisions),
            "failures": list(self.failures),
        }

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> ScenarioRecord:
        return cls(
            scenario_id=str(data["scenario_id"]),
            attempt=int(data.get("attempt", 1)),
            status=str(data.get("status", "ok")),
            outcome=dict(data.get("outcome") or {}),
            control_outcome=dict(data.get("control_outcome") or {}),
            generations=tuple(data.get("generations") or ()),
            proposals=tuple(data.get("proposals") or ()),
            decisions=tuple(data.get("decisions") or ()),
            failures=tuple(data.get("failures") or ()),
            recorded_at=str(data.get("recorded_at", "")),
            duration_ms=data.get("duration_ms"),
        )


# --------------------------------------------------------------------------- #
# Environment and configuration records
# --------------------------------------------------------------------------- #


def _utc_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _package_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def _importable(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def _ram_bytes() -> tuple[int | None, str]:
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        size = os.sysconf("SC_PAGE_SIZE")
    except (AttributeError, ValueError, OSError):
        return None, "unavailable: this platform exposes no os.sysconf (psutil is not a dependency)"
    return int(pages) * int(size), "os.sysconf"


def gpu_record() -> dict[str, Any]:
    """The GPU record, probed with ``nvidia-smi`` — never by importing torch."""

    command = [
        "nvidia-smi",
        "--query-gpu=name,memory.total,driver_version",
        "--format=csv,noheader,nounits",
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        return {
            "present": False,
            "devices": [],
            "source": "nvidia-smi",
            "reason": f"nvidia-smi is not runnable here: {type(error).__name__}",
        }
    if result.returncode != 0:
        detail = (result.stderr or "").strip()[:200]
        return {
            "present": False,
            "devices": [],
            "source": "nvidia-smi",
            "reason": f"nvidia-smi exited {result.returncode}: {detail}",
        }
    devices: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 3:
            continue
        devices.append(
            {
                "name": parts[0],
                "memory_total_mib": int(parts[1]) if parts[1].isdigit() else None,
                "driver_version": parts[2],
                "source": "nvidia-smi",
            }
        )
    return {
        "present": bool(devices),
        "devices": devices,
        "source": "nvidia-smi",
        "reason": None if devices else "nvidia-smi reported no devices",
    }


def pip_freeze_bytes() -> bytes:
    """``pip freeze`` output as LF bytes, computed once per process."""

    global _PIP_FREEZE_CACHE
    if _PIP_FREEZE_CACHE is None:
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "freeze"],
                capture_output=True,
                timeout=300,
                check=False,
            )
            text = result.stdout.decode("utf-8", errors="replace")
            if result.returncode != 0 or not text.strip():
                text = _freeze_from_metadata()
        except (OSError, subprocess.SubprocessError):
            text = _freeze_from_metadata()
        _PIP_FREEZE_CACHE = ("\n".join(text.splitlines()) + "\n").encode("utf-8")
    return _PIP_FREEZE_CACHE


def _freeze_from_metadata() -> str:
    lines = []
    for distribution in metadata.distributions():
        name = distribution.metadata["Name"] if distribution.metadata else None
        if name:
            lines.append(f"{name}=={distribution.version}")
    return "\n".join(sorted(lines, key=str.lower))


def environment_record(
    plan: StagePlan,
    identity: ModelIdentity,
    *,
    previous_sessions: Sequence[Mapping[str, Any]],
    started_at: str,
    ended_at: str | None,
) -> dict[str, Any]:
    """The protocol §4 environment record. A field that cannot be read says so."""

    ram_bytes, ram_source = _ram_bytes()
    gpu = gpu_record()
    wall = None if ended_at is None else _seconds_between(started_at, ended_at)
    log = [dict(entry) for entry in previous_sessions]
    log.append({"start_utc": started_at, "end_utc": ended_at, "wall_clock_seconds": wall})
    cumulative = round(sum(float(entry.get("wall_clock_seconds") or 0.0) for entry in log), 3)
    gpu_hours = None
    if wall is not None and gpu["present"]:
        gpu_hours = round(wall * len(gpu["devices"]) / 3600.0, 6)
    return {
        "environment_version": ENVIRONMENT_SCHEMA_VERSION,
        "recorded_at": _utc_now(),
        "host": {
            "os": platform.platform(),
            "machine": platform.machine(),
            "python": sys.version.split()[0],
            "cpu_count": os.cpu_count(),
            "ram_bytes": ram_bytes,
            "ram_source": ram_source,
        },
        "gpu": gpu,
        "runtime": {
            "torch": identity.parameters.get("torch") or _package_version("torch"),
            "transformers": (
                identity.parameters.get("transformers") or _package_version("transformers")
            ),
            "torch_importable": _importable("torch"),
            "python_executable": sys.executable,
            "pip_freeze": PIP_FREEZE_FILE,
        },
        "model": {
            "identity": identity.to_json(),
            "prompt_revision": identity.parameters.get("prompt_revision"),
            "prompt_revision_default": PROMPT_REVISION,
        },
        "timing": {
            "sessions_log": log,
            "sessions": len(log),
            "session_start_utc": started_at,
            "session_end_utc": ended_at,
            "session_wall_clock_seconds": wall,
            "cumulative_wall_clock_seconds": cumulative,
        },
        "cost": {
            "gpu_hours": gpu_hours,
            "gpu_count": len(gpu["devices"]),
            "published_rate": None,
            "currency": None,
            "estimated_cost": None,
            "note": (
                "no published notebook rate is reachable from this host; the rate and currency "
                "are recorded by the operator in configuration.json rather than invented"
            ),
        },
        "tokens": {
            "prompt_tokens": None,
            "completion_tokens": None,
            "total_tokens": None,
            "source": "not reported by the adapter in this build",
        },
        "stage": plan.stage,
        "condition": plan.condition.to_json(),
        "seed": plan.seed,
    }


def _seconds_between(start: str, end: str) -> float:
    start_dt = datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    end_dt = datetime.strptime(end, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    return max(0.0, (end_dt - start_dt).total_seconds())


def frozen_signature(identity: ModelIdentity) -> dict[str, Any]:
    """The fields that make a run's inference configuration *the same* run."""

    parameters = identity.parameters
    keys = (
        "model_id",
        "revision",
        "quantization",
        "dtype",
        "seed",
        "temperature",
        "top_p",
        "max_new_tokens",
        "thinking",
        "device",
        "format_retries",
        "prompt_revision",
        "prompt_schema_sha256",
        "quantization_backend",
        "resolved_revision",
        "chat_template_sha256",
        "max_context_tokens",
    )
    return {key: parameters.get(key) for key in keys if key in parameters}


def configuration_record(
    plan: StagePlan,
    config: CampaignConfig,
    identity: ModelIdentity,
    *,
    hook_used: bool,
    code_commit: str,
    run_name: str,
) -> dict[str, Any]:
    """The frozen configuration, closed from the freeze block §3 plus ``--tbd-json``."""

    adapter_config = dict(config.adapter_config)
    if isinstance(config.adapter, QwenModelAdapter):
        adapter_config = {**config.adapter.config.to_json(), **adapter_config}
    elif identity.kind == "qwen3-8b":
        adapter_config = {
            key: identity.parameters.get(key)
            for key in QwenConfig.__dataclass_fields__
            if key in identity.parameters
        }
    seed_rule = validate_seed_count(plan.stage, config.seeds) if _seed_floor_met(
        plan.stage, config.seeds
    ) else _lenient_seed_rule(plan.stage, config.seeds)
    return {
        "configuration_version": CONFIGURATION_SCHEMA_VERSION,
        "run_name": run_name,
        "stage": plan.stage,
        "condition": plan.condition.to_json(),
        "seed": plan.seed,
        "seeds": list(config.seeds),
        "seed_rule": seed_rule,
        "splits": list(plan.splits),
        "scenario_ids": list(plan.scenario_ids),
        "scenario_count": len(plan.scenarios),
        "dataset": {
            "source": plan.dataset_source,
            "root": str(plan.dataset_root),
            "sha256": plan.dataset.dataset_hash(),
            "scenario_set_sha256": scenario_set_hash(plan.scenarios),
        },
        "code_commit": code_commit,
        "gateway_url": config.gateway_url,
        "model": identity.to_json(),
        "frozen_signature": frozen_signature(identity),
        "adapter": {
            "name": config.model_name,
            "configured": adapter_config,
            "resolved_parameters": dict(sorted(identity.parameters.items())),
        },
        "prompt_revision": identity.parameters.get("prompt_revision"),
        "prompt_revision_default": PROMPT_REVISION,
        "generation_loop": {
            "used": hook_used,
            "note": (
                "the adapter generates one action per step and receives the gateway verdict "
                "for the previous step in the next prompt"
                if hook_used
                else "this adapter replays an authored script and performs no generation"
            ),
        },
        "tbd_before_stage_b": dict(sorted(config.tbd.items())),
        "freeze_block": FREEZE_BLOCK,
        "protocol": PROTOCOL,
        "hash_convention": HASH_CONVENTION,
        "holdout": {
            "authorized": bool(config.authorize_holdout),
            "plaintext_dir": None if config.holdout_dir is None else str(config.holdout_dir),
        },
    }


def _seed_floor_met(stage: str, seeds: Sequence[int]) -> bool:
    required, _ = STAGE_SEED_RULES.get(stage, (1, 1))
    return len(set(seeds)) == len(seeds) and len(seeds) >= required and not (
        stage in ("A", "D") and len(seeds) > required
    )


def _lenient_seed_rule(stage: str, seeds: Sequence[int]) -> dict[str, Any]:
    """The recorded rule when the invocation's declared list is not the full one."""

    required, preferred = STAGE_SEED_RULES.get(stage, (1, 1))
    return {
        "seeds": list(seeds),
        "count": len(seeds),
        "required": required,
        "preferred": preferred,
        "below_required": len(seeds) < required,
        "below_preferred": len(seeds) < preferred,
        "note": (
            "this invocation declares fewer seeds than the stage floor; the CLI refuses that, "
            "so a run reaching here was started through the library"
        ),
    }


# --------------------------------------------------------------------------- #
# The model-in-the-loop scenario execution
# --------------------------------------------------------------------------- #


def _supports_decide(model: ModelAdapter) -> bool:
    """Whether the adapter's ``plan`` accepts the gateway hook."""

    try:
        parameters = inspect.signature(model.plan).parameters
    except (TypeError, ValueError):  # pragma: no cover - exotic callables only
        return False
    return "decide" in parameters


def _raw_outputs(model: ModelAdapter) -> list[str] | None:
    outputs = getattr(model, "raw_outputs", None)
    return outputs if isinstance(outputs, list) else None


def _generation_attempts(model: ModelAdapter) -> list[dict[str, Any]] | None:
    attempts = getattr(model, "generation_attempts", None)
    return attempts if isinstance(attempts, list) else None


def _failure_row(
    *,
    stage: str,
    condition: str,
    seed: int,
    scenario_id: str,
    attempt: int,
    cause: str,
    detail: str,
    phase: str,
    step_id: int | None = None,
    http_status: int | None = None,
    raw_output: str | None = None,
) -> dict[str, Any]:
    bounded = None if raw_output is None else raw_output[:MAX_FAILURE_RAW_OUTPUT]
    return {
        "failure_version": FAILURE_SCHEMA_VERSION,
        "failure_id": uuid4().hex,
        "recorded_at": _utc_now(),
        "stage": stage,
        "condition": condition,
        "seed": seed,
        "scenario_id": scenario_id,
        "step_id": step_id,
        "phase": phase,
        "attempt": attempt,
        "cause": cause,
        "detail": detail,
        "http_status": http_status,
        "raw_output": bounded,
        "raw_output_truncated": (
            None if raw_output is None else len(raw_output) > MAX_FAILURE_RAW_OUTPUT
        ),
    }


def _classify_gateway(response: Any, verdict: StepVerdict) -> tuple[str, str]:
    if response.status is None:
        detail = verdict.error or "no response"
        if "timeout" in detail.lower():
            return CAUSE_TIMEOUT, detail
        return CAUSE_CONNECTION, detail
    return CAUSE_GATEWAY, verdict.error or f"HTTP {response.status}"


def _anchor_step(scenario: Scenario) -> int:
    """The step a scenario's verdict turns on: the attack step, else the utility step."""

    attack = scenario.scoring.attack_step_id
    return int(attack) if attack is not None else int(scenario.utility_criterion.step_id)


class _ScenarioRunner:
    """One scenario, one treatment arm, one control arm, one record."""

    def __init__(
        self,
        *,
        config: CampaignConfig,
        plan: StagePlan,
        model: ModelAdapter,
        treatment: HttpClient,
        control: HttpClient,
        attempt: int,
    ) -> None:
        self._config = config
        self._plan = plan
        self._model = model
        self._treatment = treatment
        self._control = control
        self._attempt = attempt
        self._hook = _supports_decide(model)
        self.treatment_verdicts: list[StepVerdict] = []
        self.control_verdicts: list[StepVerdict] = []
        self.proposals: list[dict[str, Any]] = []
        self.decisions: list[dict[str, Any]] = []
        self.failures: list[dict[str, Any]] = []
        self.generations: list[dict[str, Any]] = []
        self._failure_anchor: tuple[int | None, str] | None = None

    # -- recording ---------------------------------------------------------- #

    def _fail(
        self,
        scenario: Scenario,
        *,
        cause: str,
        detail: str,
        phase: str,
        step_id: int | None = None,
        http_status: int | None = None,
        raw_output: str | None = None,
    ) -> _StepFailure:
        self.failures.append(
            _failure_row(
                stage=self._plan.stage,
                condition=self._plan.condition.slug,
                seed=self._plan.seed,
                scenario_id=scenario.id,
                attempt=self._attempt,
                cause=cause,
                detail=detail,
                phase=phase,
                step_id=step_id,
                http_status=http_status,
                raw_output=raw_output,
            )
        )
        self._failure_anchor = (step_id, f"{cause}: {detail}")
        return _StepFailure(
            cause,
            detail,
            step_id=step_id,
            phase=phase,
            http_status=http_status,
            raw_output=raw_output,
        )

    def _decide(
        self,
        scenario: Scenario,
        run_id: str,
        step_id: int,
        action: dict[str, Any],
        *,
        phase: str,
    ) -> dict[str, Any]:
        """Post one proposal to the treatment arm; return the raw decision payload."""

        request = build_request(scenario, run_id=run_id, step_id=step_id, action=action)
        self.proposals.append(
            {
                "scenario_id": scenario.id,
                "step_id": step_id,
                "run_id": run_id,
                "action": action,
                "proposed_at": _utc_now(),
                "phase": phase,
            }
        )
        response = self._treatment.post(GENERIC_PATH, request)
        verdict = decision_verdict(response, step_id)
        self.treatment_verdicts.append(verdict)
        if verdict.error is not None or verdict.decision is None:
            cause, detail = _classify_gateway(response, verdict)
            raise self._fail(
                scenario,
                cause=cause,
                detail=detail,
                phase=phase,
                step_id=step_id,
                http_status=response.status,
            )
        payload = dict(response.payload or {})
        self.decisions.append(
            {
                "scenario_id": scenario.id,
                "step_id": step_id,
                "run_id": run_id,
                "arm": "treatment",
                "http_status": response.status,
                "latency_ms": response.latency_ms,
                "decision": verdict.decision,
                "payload": payload,
            }
        )
        return payload

    # -- arms --------------------------------------------------------------- #

    def _control_arm(
        self, scenario: Scenario, run_id: str, plan: Sequence[tuple[int, dict[str, Any]]]
    ) -> list[StepVerdict]:
        if not plan:
            self.control_verdicts.append(
                StepVerdict(
                    step_id=_anchor_step(scenario),
                    http_status=None,
                    decision=None,
                    error=(
                        "the scenario produced no proposal to replay against the allow-all "
                        "control, so its reachability is unknown"
                    ),
                )
            )
            return self.control_verdicts
        for step_id, action in plan:
            request = build_request(scenario, run_id=run_id, step_id=step_id, action=action)
            response = self._control.post(GENERIC_PATH, request)
            verdict = decision_verdict(response, step_id)
            self.control_verdicts.append(verdict)
            if verdict.error is not None or verdict.decision is None:
                raise self._fail(
                    scenario,
                    cause=CAUSE_CONTROL,
                    detail=verdict.error or "the allow-all control produced no verdict",
                    phase="control",
                    step_id=step_id,
                    http_status=response.status,
                )
            self.decisions.append(
                {
                    "scenario_id": scenario.id,
                    "step_id": step_id,
                    "run_id": run_id,
                    "arm": "control",
                    "http_status": response.status,
                    "latency_ms": response.latency_ms,
                    "decision": verdict.decision,
                    "payload": dict(response.payload or {}),
                }
            )
        return self.control_verdicts

    def _generation_records(
        self, scenario: Scenario, raw_before: int, attempts_before: int
    ) -> None:
        """One row per generation attempted, reconstructed from the adapter's outputs.

        The prompt for step *i* is rebuilt from the traces the adapter itself
        built (``build_messages`` is pure), so the digest is the prompt the model
        actually saw; a generation whose output did not parse still gets a row, so
        the raw text that failed is in the artifact rather than only in the error.
        """

        attempts = _generation_attempts(self._model)
        sampling = _sampling(self._model)
        if attempts is not None:
            new_attempts = attempts[attempts_before:]
            for order, attempt in enumerate(new_attempts):
                prompt = str(attempt["prompt"])
                raw = str(attempt["output"])
                parsed = bool(attempt["parsed"])
                self.generations.append(
                    {
                        "scenario_id": scenario.id,
                        "step_id": int(attempt["step_id"]),
                        "order": order,
                        "format_attempt": int(attempt["format_attempt"]),
                        "prompt_sha256": content_sha256(prompt.encode("utf-8")),
                        "prompt_chars": len(prompt),
                        "output": raw,
                        "output_sha256": content_sha256(raw.encode("utf-8")),
                        "parsed": parsed,
                        "prompt_tokens": None,
                        "completion_tokens": None,
                        "total_tokens": None,
                        "stop_reason": "parsed" if parsed else "unparsed",
                        "seed": self._config.seed,
                        "temperature": sampling.get("temperature"),
                        "recorded_at": _utc_now(),
                    }
                )
            if new_attempts:
                return

        raws = _raw_outputs(self._model)
        if raws is None or not isinstance(self._model, QwenModelAdapter):
            return
        new_raws = raws[raw_before:]
        if not new_raws:
            return
        decisions_by_step = {int(item["step_id"]): item["payload"] for item in self.decisions}
        traces: list[StepTrace] = []
        for index, raw in enumerate(new_raws):
            parsed = index < len(self.proposals)
            proposal = self.proposals[index] if parsed else None
            messages = build_messages(scenario, traces)
            prompt = render_prompt(messages)
            self.generations.append(
                {
                    "scenario_id": scenario.id,
                    "step_id": None if proposal is None else int(proposal["step_id"]),
                    "order": index,
                    "prompt_sha256": content_sha256(prompt.encode("utf-8")),
                    "prompt_chars": len(prompt),
                    "output": raw,
                    "output_sha256": content_sha256(raw.encode("utf-8")),
                    "parsed": parsed,
                    "prompt_tokens": None,
                    "completion_tokens": None,
                    "total_tokens": None,
                    "stop_reason": "parsed" if parsed else "unparsed",
                    "seed": self._config.seed,
                    "temperature": sampling.get("temperature"),
                    "recorded_at": _utc_now(),
                }
            )
            if proposal is not None:
                step_id = int(proposal["step_id"])
                traces.append(
                    StepTrace(
                        step_id=step_id,
                        action=dict(proposal["action"]),
                        decision=decisions_by_step.get(step_id),
                    )
                )

    # -- the loop ----------------------------------------------------------- #

    def run(self, scenario: Scenario, index: int) -> ScenarioRecord:
        run_id = run_id_for(index)
        started = time.perf_counter()
        raw_before = len(_raw_outputs(self._model) or [])
        attempts_before = len(_generation_attempts(self._model) or [])
        plan: tuple[tuple[int, dict[str, Any]], ...] = ()
        status = "ok"
        try:
            plan = self._generate(scenario, run_id)
        except _StepFailure:
            status = "errored"
        except QwenParseError as error:
            status = "errored"
            self._fail(
                scenario,
                cause=CAUSE_MODEL_PARSE,
                detail=str(error).split("; raw output:")[0],
                phase="generation",
                step_id=error.step_id,
                raw_output=error.raw_output,
            )
        except ModelUnavailable:
            raise
        except RunError as error:
            status = "errored"
            self._fail(
                scenario,
                cause=CAUSE_ADAPTER,
                detail=f"{type(error).__name__}: {error}",
                phase="generation",
            )
        except Exception as error:
            status = "errored"
            self._fail(
                scenario,
                cause=CAUSE_UNEXPECTED,
                detail=f"{type(error).__name__}: {error}",
                phase="generation",
            )
        self._generation_records(scenario, raw_before, attempts_before)
        if status == "errored" and not any(
            verdict.errored for verdict in self.treatment_verdicts
        ):
            # A failure before any verdict (a parse failure, an adapter error) must
            # still be an *errored* outcome: without a step the judgement would read
            # as "no data" rather than "this scenario failed", and the scorer counts
            # only an errored outcome in ``errored_attacks``.
            step_id, detail = self._failure_anchor or (
                _anchor_step(scenario),
                "the scenario produced no verdict",
            )
            self.treatment_verdicts.append(
                StepVerdict(step_id=step_id, http_status=None, decision=None, error=detail)
            )

        original = dict(plan)
        treatment_outcome = derive_outcome(
            scenario, tuple(self.treatment_verdicts), original_actions=original
        )
        if self._plan.condition.treatment_is_control:
            # The treatment *is* the allow-all arm; replaying it would be a second
            # measurement of the same surface, so the run records one arm twice.
            control_outcome = treatment_outcome
        else:
            try:
                self._control_arm(scenario, run_id, plan)
            except _StepFailure:
                status = "errored"
            control_outcome = derive_outcome(
                scenario, tuple(self.control_verdicts), original_actions=original
            )

        return ScenarioRecord(
            scenario_id=scenario.id,
            attempt=self._attempt,
            status=status,
            outcome=treatment_outcome.to_json(),
            control_outcome=control_outcome.to_json(),
            generations=tuple(self.generations),
            proposals=tuple(self.proposals),
            decisions=tuple(self.decisions),
            failures=tuple(self.failures),
            recorded_at=_utc_now(),
            duration_ms=round((time.perf_counter() - started) * 1000, 3),
        )

    def _generate(self, scenario: Scenario, run_id: str) -> tuple[tuple[int, dict[str, Any]], ...]:
        if not self._hook:
            plan = self._model.plan(scenario)
            for step_id, action in plan:
                self._decide(scenario, run_id, step_id, action, phase="treatment")
            return plan

        def decide(step_id: int, action: dict[str, Any]) -> Mapping[str, Any]:
            return self._decide(scenario, run_id, step_id, action, phase="generation")

        return self._model.plan(scenario, decide=decide)


def _sampling(model: ModelAdapter) -> dict[str, Any]:
    parameters = model.identity().parameters
    return {
        "temperature": parameters.get("temperature"),
        "top_p": parameters.get("top_p"),
        "max_new_tokens": parameters.get("max_new_tokens", parameters.get("max_tokens")),
    }


# --------------------------------------------------------------------------- #
# The run directory
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CampaignResult:
    """What one invocation did, in the terms the CLI and the notebooks print."""

    run_dir: Path
    plan: StagePlan
    status: str
    resumed: bool
    completed: int
    errored: int
    remaining: int
    skipped: int
    failures: int
    sessions: int
    bundle: Path | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "run_dir": str(self.run_dir),
            "stage": self.plan.stage,
            "condition": self.plan.condition.slug,
            "seed": self.plan.seed,
            "status": self.status,
            "resumed": self.resumed,
            "scenarios_total": len(self.plan.scenarios),
            "scenarios_completed": self.completed,
            "scenarios_errored": self.errored,
            "scenarios_remaining": self.remaining,
            "scenarios_skipped": self.skipped,
            "failures_recorded": self.failures,
            "sessions": self.sessions,
            "bundle": None if self.bundle is None else str(self.bundle),
        }


def _checkpoint_path(run_dir: Path, scenario_id: str) -> Path:
    return run_dir / CHECKPOINT_DIR / f"{scenario_id}.json"


def find_run_for_slug(runs_dir: Path, run_slug: str) -> Path | None:
    """The newest run directory written for ``run_slug``, complete or not."""

    if not runs_dir.is_dir():
        return None
    suffix = f"-{run_slug}"
    candidates = sorted(
        (
            entry
            for entry in runs_dir.iterdir()
            if entry.is_dir() and entry.name.endswith(suffix) and (entry / MANIFEST_FILE).is_file()
        ),
        key=lambda entry: entry.name,
        reverse=True,
    )
    return candidates[0] if candidates else None


def find_resumable_run(runs_dir: Path, run_slug: str) -> Path | None:
    """The newest *incomplete* run directory for ``run_slug``, or ``None``."""

    if not runs_dir.is_dir():
        return None
    suffix = f"-{run_slug}"
    candidates = sorted(
        (
            entry
            for entry in runs_dir.iterdir()
            if entry.is_dir() and entry.name.endswith(suffix) and (entry / MANIFEST_FILE).is_file()
        ),
        key=lambda entry: entry.name,
        reverse=True,
    )
    for candidate in candidates:
        if not _is_complete(candidate):
            return candidate
    return None


def _is_complete(run_dir: Path) -> bool:
    manifest_path = run_dir / MANIFEST_FILE
    if not manifest_path.is_file():
        return False
    if (run_dir / "score.json").is_file():
        return True
    return (_read_json(manifest_path).get("campaign") or {}).get("status") == "complete"


def _load_checkpoints(
    run_dir: Path,
    plan: StagePlan,
) -> tuple[dict[str, ScenarioRecord], list[dict[str, Any]]]:
    """Verified checkpoints, plus the failures of the rejected documents.

    A checkpoint whose recorded hash does not verify is **moved** to
    ``checkpoints/rejected/`` with its rejection recorded, never deleted: the
    freeze block requires both the failed and the successful attempt to be kept.
    """

    recorded = read_hashes(run_dir)
    verified: dict[str, ScenarioRecord] = {}
    rejected: list[dict[str, Any]] = []
    for scenario in plan.scenarios:
        path = _checkpoint_path(run_dir, scenario.id)
        if not path.is_file():
            continue
        relative = path.relative_to(run_dir).as_posix()
        actual = content_sha256(path.read_bytes())
        expected = recorded.get(relative)
        if expected is not None and expected == actual:
            verified[scenario.id] = ScenarioRecord.from_json(_read_json(path))
            continue
        document = _read_json(path)
        rejection = _failure_row(
            stage=plan.stage,
            condition=plan.condition.slug,
            seed=plan.seed,
            scenario_id=scenario.id,
            attempt=int(document.get("attempt", 1)),
            cause=CAUSE_CHECKPOINT,
            detail=(
                "the checkpoint did not verify against hashes.sha256 and was re-run; the "
                f"previous document is kept in {CHECKPOINT_DIR}/{REJECTED_DIR}/"
            ),
            phase="resume",
        )
        document["failures"] = [*(document.get("failures") or ()), rejection]
        document["rejected_at"] = _utc_now()
        document["rejected_recorded_sha256"] = expected
        document["rejected_actual_sha256"] = actual
        destination = run_dir / CHECKPOINT_DIR / REJECTED_DIR / f"{scenario.id}.{_utc_stamp()}.json"
        _atomic_write_json(destination, document)
        path.unlink()
        rejected.append(document)
    return verified, rejected


def _rejected_documents(run_dir: Path) -> list[dict[str, Any]]:
    rejected = run_dir / CHECKPOINT_DIR / REJECTED_DIR
    if not rejected.is_dir():
        return []
    documents = []
    for path in sorted(rejected.glob("*.json")):
        try:
            documents.append(_read_json(path))
        except (OSError, json.JSONDecodeError):
            continue
    return documents


def _rejected_failures(run_dir: Path) -> list[dict[str, Any]]:
    return [
        dict(row)
        for document in _rejected_documents(run_dir)
        for row in (document.get("failures") or ())
    ]


def _write_aggregates(
    run_dir: Path,
    plan: StagePlan,
    records: Mapping[str, ScenarioRecord],
    session_failures: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Rewrite every derived artifact from the checkpoints, atomically."""

    ordered = [records[scenario.id] for scenario in plan.scenarios if scenario.id in records]
    outcomes = [record.outcome for record in ordered]
    control = [record.control_outcome for record in ordered]
    generations = [row for record in ordered for row in record.generations]
    proposals = [row for record in ordered for row in record.proposals]
    decisions = [row for record in ordered for row in record.decisions]
    failures = [row for record in ordered for row in record.failures]
    failures.extend(_rejected_failures(run_dir))
    failures.extend(dict(row) for row in session_failures)
    failures.sort(
        key=lambda row: (
            str(row.get("scenario_id") or ""),
            str(row.get("recorded_at") or ""),
            str(row.get("failure_id") or ""),
        )
    )

    written = {
        "outcomes.jsonl": _jsonl(outcomes),
        "control.jsonl": _jsonl(control),
        "raw_generations.jsonl": _jsonl(generations),
        "proposed_actions.jsonl": _jsonl(proposals),
        "decisions.jsonl": _jsonl(decisions),
        "failures.jsonl": _jsonl(failures),
    }
    for name, payload in written.items():
        _atomic_write_bytes(run_dir / name, payload)
    return {
        "counts": {
            "outcomes": len(outcomes),
            "control": len(control),
            "generations": len(generations),
            "proposals": len(proposals),
            "decisions": len(decisions),
            "failures": len(failures),
        },
        "artifacts": {name: _raw_sha256(payload) for name, payload in written.items()},
    }


def _write_manifest(
    run_dir: Path,
    plan: StagePlan,
    config: CampaignConfig,
    identity: ModelIdentity,
    *,
    created: str,
    code: Mapping[str, Any],
    health_status: int | None,
    version_payload: dict[str, Any] | None,
    version_error: str | None,
    control_url: str,
    control_kind: str,
    treatment_url: str,
    artifact_hashes: Mapping[str, str],
    campaign: Mapping[str, Any],
) -> None:
    sampling = _sampling_from_identity(identity)
    manifest = build_run_manifest(
        run_name=run_dir.name,
        created=created,
        code_commit=str(code["commit"]),
        code_commit_source=str(code["commit_source"]),
        code_branch=str(code["branch"]),
        code_dirty=code["dirty"],
        defense_url=treatment_url,
        health_status=health_status,
        version_payload=version_payload,
        version_error=version_error,
        control_url=control_url,
        control_kind=control_kind,
        auth=config.auth,
        selected=plan.scenarios,
        dataset=plan.dataset,
        dataset_root=plan.dataset_root,
        splits=plan.splits,
        model_identity=identity,
        seed=plan.seed,
        temperature=sampling.get("temperature"),
        max_tokens=sampling.get("max_new_tokens"),
        hardware_note=config.hardware_note,
        lock_path=config.lock_path,
        artifacts=dict(sorted(artifact_hashes.items())),
        limitations=_limitations(plan, config, identity),
        repo_root=_repo_root(),
        extra={"campaign": dict(campaign)},
    )
    _atomic_write_json(run_dir / MANIFEST_FILE, manifest)


def _sampling_from_identity(identity: ModelIdentity) -> dict[str, Any]:
    parameters = identity.parameters
    return {
        "temperature": parameters.get("temperature"),
        "max_new_tokens": parameters.get("max_new_tokens", parameters.get("max_tokens")),
    }


def _limitations(plan: StagePlan, config: CampaignConfig, identity: ModelIdentity) -> list[str]:
    limitations = [
        "the harness executes nothing: a verdict is the gateway's authorization decision, "
        "not an observed side effect",
        "an errored outcome carries no verdict; it is counted as an error and, "
        "intention-to-treat, as a failure — never as a stopped attack",
    ]
    if identity.kind == "scripted":
        limitations.append(
            "the model adapter is 'scripted': the scenario's authored action script is "
            "replayed, so this run measures the gateway and not model behaviour"
        )
    if plan.stage == "A":
        limitations.append(
            "Stage A is engineering evidence only: it licenses no research claim, no "
            "effectiveness number and no utility number"
        )
    if plan.stage == "D":
        limitations.append(
            "the sealed holdout is run exactly once; its plaintext is deleted afterwards and "
            "no tuning against it is permitted"
        )
    if plan.condition.treatment_is_control:
        limitations.append(
            "this run's treatment arm *is* the allow-all control; it materialises the control "
            "arm as its own directory and licenses no effectiveness claim by itself"
        )
    if config.max_scenarios is not None:
        limitations.append(
            f"--max-scenarios {config.max_scenarios} stopped this session early; the run is "
            "incomplete until it is resumed"
        )
    return limitations


# --------------------------------------------------------------------------- #
# The campaign
# --------------------------------------------------------------------------- #


@dataclass
class _Session:
    """Mutable state for one invocation of ``run_campaign``."""

    run_dir: Path
    plan: StagePlan
    config: CampaignConfig
    identity: ModelIdentity
    code: dict[str, Any]
    created: str
    resumed: bool
    sessions_log: list[dict[str, Any]]
    session_failures: list[dict[str, Any]]
    health_status: int | None = None
    version_payload: dict[str, Any] | None = None
    version_error: str | None = None
    control_url: str = ""
    control_kind: str = ""
    treatment_url: str = ""
    started_at: str = ""
    ended_at: str | None = None
    verified: dict[str, ScenarioRecord] = field(default_factory=dict)

    def wall_clock_seconds(self) -> float:
        """This session's wall clock so far (0 while it is still open)."""

        if not self.ended_at:
            return 0.0
        return _seconds_between(self.started_at, self.ended_at)


def _rewrite(session: _Session, *, stop_reason: str, status: str) -> dict[str, Any]:
    """Rewrite the aggregates, the manifest and the hashes; return the counts."""

    run_dir = session.run_dir
    plan = session.plan
    aggregates = _write_aggregates(
        run_dir, plan, session.verified, session.session_failures
    )
    errored = sum(1 for record in session.verified.values() if record.status == "errored")
    campaign = {
        "driver": "benchmark/campaign.py",
        "schema_version": CAMPAIGN_SCHEMA_VERSION,
        "stage": plan.stage,
        "condition": plan.condition.to_json(),
        "seed": plan.seed,
        "seeds": list(session.config.seeds),
        "status": status,
        "stop_reason": stop_reason,
        "scenarios_total": len(plan.scenarios),
        "scenarios_completed": len(session.verified),
        "scenarios_errored": errored,
        "scenarios_remaining": len(plan.scenarios) - len(session.verified),
        "sessions": len(session.sessions_log) + 1,
        "session_failures": [dict(row) for row in session.session_failures],
        "failures_recorded": aggregates["counts"]["failures"],
        "cumulative_wall_clock_seconds": round(
            sum(float(entry.get("wall_clock_seconds") or 0.0) for entry in session.sessions_log)
            + session.wall_clock_seconds(),
            3,
        ),
        "scenario_source": {
            "kind": plan.dataset_source,
            "root": str(plan.dataset_root),
            "sha256": plan.dataset.dataset_hash(),
            "scenario_set_sha256": scenario_set_hash(plan.scenarios),
        },
        "seed_rule": _seed_rule_record(plan.stage, session.config.seeds),
        "model_in_the_loop": {
            "used": _supports_decide(session.config.resolve_model()),
            "adapter": session.identity.kind,
        },
        "freeze_block": FREEZE_BLOCK,
        "protocol": PROTOCOL,
        "hash_convention": HASH_CONVENTION,
        "limitations": _limitations(plan, session.config, session.identity),
    }
    artifact_hashes = dict(aggregates["artifacts"])
    for name in (MANIFEST_FILE, ENVIRONMENT_FILE, CONFIGURATION_FILE, PIP_FREEZE_FILE):
        path = run_dir / name
        if path.is_file():
            artifact_hashes[name] = _raw_sha256(path.read_bytes())
    _write_manifest(
        run_dir,
        plan,
        session.config,
        session.identity,
        created=session.created,
        code=session.code,
        health_status=session.health_status,
        version_payload=session.version_payload,
        version_error=session.version_error,
        control_url=session.control_url,
        control_kind=session.control_kind,
        treatment_url=session.treatment_url,
        artifact_hashes=artifact_hashes,
        campaign=campaign,
    )
    write_hashes(run_dir)
    return aggregates


def _seed_rule_record(stage: str, seeds: Sequence[int]) -> dict[str, Any]:
    if _seed_floor_met(stage, seeds):
        return validate_seed_count(stage, seeds)
    return _lenient_seed_rule(stage, seeds)


def _write_environment(session: _Session, *, ended_at: str | None) -> None:
    _atomic_write_json(
        session.run_dir / ENVIRONMENT_FILE,
        environment_record(
            session.plan,
            session.identity,
            previous_sessions=session.sessions_log,
            started_at=session.started_at,
            ended_at=ended_at,
        ),
    )


def _write_configuration(session: _Session, *, hook_used: bool) -> None:
    _atomic_write_json(
        session.run_dir / CONFIGURATION_FILE,
        configuration_record(
            session.plan,
            session.config,
            session.identity,
            hook_used=hook_used,
            code_commit=str(session.code["commit"]),
            run_name=session.run_dir.name,
        ),
    )


def _previous_sessions(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / ENVIRONMENT_FILE
    if not path.is_file():
        return []
    try:
        timing = (_read_json(path).get("timing") or {})
    except (OSError, json.JSONDecodeError):
        return []
    return [dict(entry) for entry in timing.get("sessions_log") or ()]


def _previous_session_failures(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / MANIFEST_FILE
    if not path.is_file():
        return []
    try:
        campaign = _read_json(path).get("campaign") or {}
    except (OSError, json.JSONDecodeError):
        return []
    return [dict(row) for row in campaign.get("session_failures") or ()]


def _next_attempt(run_dir: Path, scenario_id: str, previous_attempts: Mapping[str, int]) -> int:
    """The attempt number this run of ``scenario_id`` is.

    A scenario whose checkpoint did not verify was moved aside, so its previous
    attempt is remembered from the rejected document: both attempts are kept and
    the count says which one this is.
    """

    path = _checkpoint_path(run_dir, scenario_id)
    if path.is_file():
        try:
            return int(_read_json(path).get("attempt", 1)) + 1
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return 1
    return previous_attempts.get(scenario_id, 0) + 1


def _checkpoint_document(plan: StagePlan, record: ScenarioRecord) -> dict[str, Any]:
    document = record.to_json()
    document.update(
        {
            "stage": plan.stage,
            "condition": plan.condition.slug,
            "seed": plan.seed,
            "run_slug": plan.run_slug,
        }
    )
    return document


@dataclass
class _Arms:
    """The resolved treatment and control arms of one run."""

    treatment: HttpClient
    treatment_url: str
    control: HttpClient
    control_kind: str
    internal_control: ControlServer | None = None
    version_payload: dict[str, Any] | None = None
    version_error: str | None = None
    health_status: int | None = None


def _open_arms(config: CampaignConfig, plan: StagePlan) -> _Arms:
    """Resolve the treatment and control arms, and check the treatment's health."""

    if plan.condition.treatment_is_control:
        internal = ControlServer().start() if config.control_url is None else None
        url = config.control_url or (internal.url if internal else "")
        treatment = HttpClient(url, config.timeout)
        health = treatment.get(HEALTH_PATH)
        if health.error is not None or health.status != 200:
            if internal is not None:
                internal.stop()
            raise CampaignError(
                f"the allow-all control at {url} is not healthy: "
                f"status={health.status} error={health.error}"
            )
        return _Arms(
            treatment=treatment,
            treatment_url=url,
            control=treatment,
            control_kind="treatment-is-allow-all-control",
            internal_control=internal,
            version_payload=None,
            version_error=(
                "the allow-all control is a harness endpoint and exposes no /api/v1/version"
            ),
            health_status=health.status,
        )

    treatment = HttpClient(config.gateway_url, config.timeout, config.auth)
    health = treatment.get(HEALTH_PATH)
    if health.error is not None or health.status != 200:
        raise CampaignError(
            f"the treatment surface at {config.gateway_url} is not healthy: "
            f"status={health.status} error={health.error}"
        )
    version = treatment.get(VERSION_PATH)
    internal: ControlServer | None = None
    if config.control_url is not None:
        control = HttpClient(config.control_url, config.timeout)
        control_kind = "external-allow-all"
    else:
        internal = ControlServer().start()
        control = HttpClient(internal.url, config.timeout)
        control_kind = "internal-allow-all"
    return _Arms(
        treatment=treatment,
        treatment_url=config.gateway_url,
        control=control,
        control_kind=control_kind,
        internal_control=internal,
        version_payload=version.payload,
        version_error=version.error,
        health_status=health.status,
    )


def run_campaign(config: CampaignConfig) -> CampaignResult:
    """Run, resume or package one ``(stage, condition, seed)`` campaign run."""

    validate_adapter_config(config)
    validate_seed_count(config.stage, config.seeds)
    plan = plan_stage(config)
    if plan.stage == "D" and not config.authorize_holdout:
        raise CampaignError(
            "Stage D refused: the sealed holdout runs only with an explicit "
            "--authorize-holdout, after Stages B and C are complete and the custodian "
            "authorized the opening (freeze block 1 §9)"
        )

    if config.bundle and not config.resume:
        packaged = find_run_for_slug(config.runs_dir, plan.run_slug)
        if packaged is None:
            raise CampaignError(
                f"nothing to bundle for {plan.run_slug}: no run directory in {config.runs_dir}; "
                "run the stage first"
            )
        if not _is_complete(packaged):
            raise CampaignError(
                f"refusing to bundle an incomplete run: {packaged}; resume it first "
                "(--resume --bundle)"
            )
        return CampaignResult(
            run_dir=packaged,
            plan=plan,
            status="complete",
            resumed=False,
            completed=len(plan.scenarios),
            errored=0,
            remaining=0,
            skipped=len(plan.scenarios),
            failures=count_failures(packaged),
            sessions=0,
            bundle=bundle_run(packaged),
        )

    model = config.resolve_model()
    if isinstance(model, QwenModelAdapter):
        # Resolve the exact model revision, template digest and runtime before
        # freezing configuration.json or comparing a resume signature.
        model.load()
    identity = model.identity()
    hook_used = _supports_decide(model)
    code = {
        "commit": _git_commit(),
        "commit_source": "git-rev-parse-HEAD",
        "branch": _git_branch(),
        "dirty": _git_dirty(_repo_root()),
    }
    if code["commit"] == "unknown":
        code["commit_source"] = "unavailable"

    existing: Path | None = None
    if config.resume:
        existing = find_resumable_run(config.runs_dir, plan.run_slug)
        if existing is None:
            complete = find_run_for_slug(config.runs_dir, plan.run_slug)
            if complete is not None:
                raise CampaignError(
                    f"refusing to resume a completed run directory: {complete} "
                    "(pass --bundle to package it)"
                )
    run_dir = existing if existing is not None else config.runs_dir / config.run_name()
    resumed = existing is not None
    if not resumed and run_dir.exists():
        raise CampaignError(f"refusing to overwrite an existing run directory: {run_dir}")
    if resumed:
        _verify_resume_identity(run_dir, plan, config, identity)

    started_at = _utc_now()
    internal_control: ControlServer | None = None
    try:
        arms = _open_arms(config, plan)
        internal_control = arms.internal_control

        if not resumed:
            run_dir.mkdir(parents=True, exist_ok=False)
            (run_dir / CHECKPOINT_DIR).mkdir(parents=True, exist_ok=True)
            _atomic_write_bytes(run_dir / PIP_FREEZE_FILE, pip_freeze_bytes())

        session = _Session(
            run_dir=run_dir,
            plan=plan,
            config=config,
            identity=identity,
            code=code,
            created=(
                _utc_now()
                if not resumed
                else str((_read_json(run_dir / MANIFEST_FILE).get("run") or {}).get("created"))
            ),
            resumed=resumed,
            sessions_log=_previous_sessions(run_dir) if resumed else [],
            session_failures=_previous_session_failures(run_dir) if resumed else [],
            health_status=arms.health_status,
            version_payload=arms.version_payload,
            version_error=arms.version_error,
            control_url=_control_url(config, plan, arms),
            control_kind=arms.control_kind,
            treatment_url=arms.treatment_url,
            started_at=started_at,
        )
        verified, rejected = _load_checkpoints(run_dir, plan)
        session.verified = verified
        skipped = len(verified)
        previous_attempts = {
            str(document.get("scenario_id")): int(document.get("attempt", 1))
            for document in rejected
        }

        if not resumed:
            _write_configuration(session, hook_used=hook_used)
        _write_environment(session, ended_at=None)

        todos = [scenario for scenario in plan.scenarios if scenario.id not in verified]
        if config.max_scenarios is not None:
            todos = todos[: config.max_scenarios]

        stop_reason = "max-scenarios-reached" if todos else "all-scenarios-covered"
        index_of = {scenario.id: index for index, scenario in enumerate(plan.scenarios)}
        for scenario in todos:
            attempt = _next_attempt(run_dir, scenario.id, previous_attempts)
            runner = _ScenarioRunner(
                config=config,
                plan=plan,
                model=model,
                treatment=arms.treatment,
                control=arms.control,
                attempt=attempt,
            )
            try:
                record = runner.run(scenario, index_of[scenario.id])
                _atomic_write_json(
                    _checkpoint_path(run_dir, scenario.id), _checkpoint_document(plan, record)
                )
                session.verified[scenario.id] = record
                _rewrite(session, stop_reason="running", status="running")
            except KeyboardInterrupt:
                # An interruption anywhere in this scenario's body — during
                # generation, during the checkpoint write, during the aggregate
                # rewrite — is recorded rather than lost, and the session stops
                # cleanly so the next one resumes from the verified checkpoints.
                session.session_failures.append(
                    _failure_row(
                        stage=plan.stage,
                        condition=plan.condition.slug,
                        seed=plan.seed,
                        scenario_id=scenario.id,
                        attempt=attempt,
                        cause=CAUSE_INTERRUPTION,
                        detail=(
                            "the session was interrupted while this scenario was in flight; a "
                            "checkpoint written before the interrupt resumes from it, and a "
                            "checkpoint that did not verify is re-run from the start"
                        ),
                        phase="generation",
                    )
                )
                stop_reason = "interrupted"
                break

        complete = all(scenario.id in session.verified for scenario in plan.scenarios)
        status = "complete" if complete else "incomplete"
        if complete:
            stop_reason = "all-scenarios-complete"
        elif stop_reason in ("all-scenarios-covered", "max-scenarios-reached"):
            stop_reason = "incomplete"

        session.ended_at = _utc_now()
        _write_environment(session, ended_at=session.ended_at)
        aggregates = _rewrite(session, stop_reason=stop_reason, status=status)
        errored = sum(1 for record in session.verified.values() if record.status == "errored")
        result = CampaignResult(
            run_dir=run_dir,
            plan=plan,
            status=status,
            resumed=resumed,
            completed=len(session.verified),
            errored=errored,
            remaining=len(plan.scenarios) - len(session.verified),
            skipped=skipped,
            failures=aggregates["counts"]["failures"],
            sessions=len(session.sessions_log) + 1,
        )
        if config.bundle:
            if status != "complete":
                raise CampaignError(
                    f"refusing to bundle an incomplete run: {run_dir} "
                    f"({result.remaining} scenario(s) remaining); resume it first"
                )
            return replace(result, bundle=bundle_run(run_dir))
        return result
    finally:
        if internal_control is not None:
            internal_control.stop()


def _control_url(config: CampaignConfig, plan: StagePlan, arms: _Arms) -> str:
    """The control arm's URL as the manifest should record it."""

    if plan.condition.treatment_is_control:
        return arms.treatment_url
    if config.control_url is not None:
        return config.control_url
    return arms.internal_control.url if arms.internal_control is not None else ""


def _verify_resume_identity(
    run_dir: Path, plan: StagePlan, config: CampaignConfig, identity: ModelIdentity
) -> None:
    """Refuse to resume a run whose frozen configuration differs."""

    path = run_dir / CONFIGURATION_FILE
    if not path.is_file():
        raise CampaignError(
            f"cannot resume {run_dir}: no {CONFIGURATION_FILE} to check the frozen "
            "configuration against"
        )
    recorded = _read_json(path)
    expected = {
        "stage": plan.stage,
        "condition": plan.condition.to_json(),
        "seed": plan.seed,
        "scenario_ids": list(plan.scenario_ids),
        "dataset_sha256": plan.dataset.dataset_hash(),
        "run_name": run_dir.name,
        "model_name": config.model_name,
        "frozen_signature": frozen_signature(identity),
    }
    actual = {
        "stage": recorded.get("stage"),
        "condition": recorded.get("condition"),
        "seed": recorded.get("seed"),
        "scenario_ids": recorded.get("scenario_ids"),
        "dataset_sha256": (recorded.get("dataset") or {}).get("sha256"),
        "run_name": recorded.get("run_name"),
        "model_name": (recorded.get("adapter") or {}).get("name"),
        "frozen_signature": recorded.get("frozen_signature"),
    }
    differences = {
        key: {"recorded": actual.get(key), "now": expected[key]}
        for key in expected
        if actual.get(key) != expected[key]
    }
    if differences:
        raise CampaignError(
            f"cannot resume {run_dir}: the frozen configuration changed ({differences}); a "
            "changed configuration is a new freeze block and a new run directory, never a "
            "resume of this one"
        )


# --------------------------------------------------------------------------- #
# Bundling
# --------------------------------------------------------------------------- #


def bundle_run(run_dir: Path, *, output: Path | None = None) -> Path:
    """Zip a complete run directory for download, after verifying its hashes.

    The recorded entries must verify first; only then is the hash manifest
    extended to any artifact written after the run (``score.json`` and friends),
    so a file that was present during the run can never be silently re-hashed.
    """

    if not (run_dir / MANIFEST_FILE).is_file():
        raise CampaignError(f"no run directory at {run_dir}")
    if not _is_complete(run_dir):
        raise CampaignError(
            f"refusing to bundle an incomplete run: {run_dir} (status is not 'complete'); "
            "resume it first"
        )
    report = verify_hashes(run_dir)
    if not report["ok"]:
        raise CampaignError(
            f"refusing to bundle {run_dir}: hashes.sha256 does not verify "
            f"(missing={report['missing']}, "
            f"mismatched={[item['path'] for item in report['mismatched']]})"
        )
    write_hashes(run_dir)
    destination = output or run_dir.parent / f"{run_dir.name}.zip"
    if destination.exists():
        raise CampaignError(f"refusing to overwrite an existing bundle: {destination}")
    temporary = destination.with_name(f".{destination.name}.{uuid4().hex[:8]}.tmp")
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in _hashed_paths(run_dir):
                archive.write(path, path.relative_to(run_dir).as_posix())
            archive.write(run_dir / HASHES_FILE, HASHES_FILE)
        os.replace(temporary, destination)
    except BaseException:
        with suppress(OSError):
            temporary.unlink()
        raise
    return destination


def bundle_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --------------------------------------------------------------------------- #
# The dry run
# --------------------------------------------------------------------------- #


def dry_run_plan(config: CampaignConfig, seeds: Sequence[int]) -> dict[str, Any]:
    """What an invocation would do, with nothing touched and no socket opened."""

    validate_adapter_config(config)
    seed_rule = validate_seed_count(config.stage, seeds)
    if config.stage == "D" and not config.authorize_holdout:
        raise CampaignError("Stage D refused: --authorize-holdout is required (freeze block 1 §9)")
    runs = []
    for seed in seeds:
        per_seed = replace(
            config, seed=seed, declared_seeds=tuple(seeds), adapter=None
        )
        plan = plan_stage(per_seed)
        runs.append(
            {
                "seed": seed,
                "run_name": per_seed.run_name(),
                "run_slug": plan.run_slug,
                "scenario_count": len(plan.scenarios),
                "scenario_ids": list(plan.scenario_ids),
                "splits": list(plan.splits),
                "dataset_source": plan.dataset_source,
                "dataset_root": str(plan.dataset_root),
                "dataset_sha256": plan.dataset.dataset_hash(),
                "condition": plan.condition.to_json(),
                "treatment_surface": (
                    "allow-all-control"
                    if plan.condition.treatment_is_control
                    else config.gateway_url
                ),
                "artifacts": list(RUN_ARTIFACTS),
                "checkpoints": f"{CHECKPOINT_DIR}/<scenario_id>.json",
            }
        )
    return {
        "stage": config.stage,
        "condition": parse_condition(config.condition).to_json(),
        "model": config.model_name,
        "runs_dir": str(config.runs_dir),
        "resume": config.resume,
        "bundle": config.bundle,
        "max_scenarios": config.max_scenarios,
        "seed_rule": seed_rule,
        "runs": runs,
    }


__all__ = [
    "ANCHOR_SEED",
    "CAMPAIGN_SCHEMA_VERSION",
    "CHECKPOINT_SCHEMA_VERSION",
    "CONVENTION_NAME",
    "HASHES_FILE",
    "HASH_DECLARATION",
    "RUN_ARTIFACTS",
    "SMOKE_SCENARIOS",
    "STAGES",
    "CampaignConfig",
    "CampaignError",
    "CampaignResult",
    "Condition",
    "ScenarioRecord",
    "StagePlan",
    "bundle_run",
    "bundle_sha256",
    "count_failures",
    "dry_run_plan",
    "environment_record",
    "find_resumable_run",
    "find_run_for_slug",
    "frozen_signature",
    "gpu_record",
    "parse_condition",
    "pip_freeze_bytes",
    "plan_stage",
    "read_hashes",
    "run_campaign",
    "validate_adapter_config",
    "validate_seed_count",
    "verify_hashes",
    "write_hashes",
]
