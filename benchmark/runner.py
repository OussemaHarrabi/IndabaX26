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
from benchmark.wire import policy_document as wire_policy_document
from benchmark.wire import policy_document_digest as wire_policy_document_digest
from benchmark.wire import policy_set_for as wire_policy_set_for

MANIFEST_SCHEMA_VERSION = "aegisgraph-benchmark-run/v1"

#: The committed files whose content turns a policy document into a decision. The
#: H5.2 gate compares these between the freeze commit and the unseal commit: a
#: policy *document* can be unchanged while the code that applies it is not.
POLICY_SOURCE_BLOBS: tuple[str, ...] = (
    "backend/aegisgraph/policy.py",
    "backend/aegisgraph/engine.py",
    "backend/aegisgraph/adapter.py",
)

#: The hashing convention for **every** file and document hash this runner
#: records: SHA-256 of the content bytes with CRLF normalised to LF, and no git
#: object header. This is the convention ``scripts/generate_sbom.py`` uses for
#: ``source.requirements_lock_sha256``, so the run manifest and the release SBOM
#: agree about the same file on any platform: a Windows checkout and a Linux
#: checkout produce the same value. A git *object* header would not — it is a
#: different function of the same bytes.
HASH_CONVENTION = "content-sha256-lf: sha256(bytes) with CRLF normalised to LF, no object header"
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
    auth: AuthConfig | None = None

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


def _b64url_decode(value: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def unverified_jwt_subject(token: str) -> str | None:
    """Read the ``sub`` claim of a JWT **without verifying it**.

    This exists only so the run manifest can name the principal. It is never an
    authorization decision — the gateway verifies the token — and an opaque
    service token has no readable subject, so ``None`` is returned.
    """

    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        claims = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
    except Exception:
        return None
    if not isinstance(claims, dict):
        return None
    subject = claims.get("sub")
    if isinstance(subject, str) and 0 < len(subject) <= 256:
        return subject
    return None


def read_token(token: str | None, token_file: str | None) -> str:
    """Resolve a bearer token from a literal or a file, without ever echoing it.

    The file form is preferred because a literal token ends up in a shell history.
    Whitespace is rejected rather than trimmed silently, so a wrapped or
    multi-line file is reported instead of producing an unauthenticated run.
    """

    if token is not None and token_file is not None:
        raise RunError("pass --auth-token or --auth-token-file, not both")
    if token_file is not None:
        path = Path(token_file)
        if not path.is_file():
            raise RunError(f"auth token file not found: {path}")
        raw = path.read_bytes()
        if b"\x00" in raw:
            raise RunError(
                f"{path} looks like UTF-16 (a shell redirect on Windows writes UTF-16); "
                "write the token file as UTF-8 without a BOM"
            )
        try:
            value = raw.decode("utf-8-sig")
        except UnicodeDecodeError as error:
            raise RunError(f"{path} is not valid UTF-8: {error}") from error
    elif token is not None:
        value = token
    else:
        raise RunError("no credential: pass --auth-token-file (preferred) or --auth-token")
    value = value.strip()
    if not value:
        raise RunError("the auth token is empty")
    if any(character.isspace() for character in value):
        raise RunError("the auth token contains whitespace; is the file wrapped or multi-line?")
    return value


@dataclass(frozen=True)
class AuthConfig:
    """A bearer credential for the decision surface.

    The token is a secret: it is never logged, never written to a manifest and
    never reproduced by ``repr`` (the field is excluded and ``__repr__`` is
    overridden), so neither a traceback nor a debug print can leak it.
    """

    token: str = field(repr=False)
    header: str = "Authorization"
    scheme: str = "Bearer"

    def header_value(self) -> str:
        return f"{self.scheme} {self.token}" if self.scheme else self.token

    def metadata(self) -> dict[str, Any]:
        """Non-secret metadata for the manifest: never the token, never its digest."""

        return {
            "mode": "bearer",
            "header": self.header,
            "scheme": self.scheme,
            "principal": unverified_jwt_subject(self.token),
            "principal_source": "unverified-jwt-sub-or-null",
        }

    def __repr__(self) -> str:
        return (
            f"AuthConfig(header={self.header!r}, scheme={self.scheme!r}, "
            f"principal={unverified_jwt_subject(self.token)!r})"
        )


class HttpClient:
    """Minimal JSON-over-HTTP client. Standard library only, no hidden state."""

    def __init__(self, base_url: str, timeout: float, auth: AuthConfig | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.auth = auth

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
        if self.auth is not None:
            request.add_header(self.auth.header, self.auth.header_value())
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


def _git_root() -> Path:
    """The repository root this module lives in."""

    return Path(__file__).resolve().parents[1]


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


def content_sha256(data: bytes) -> str:
    """SHA-256 of content bytes with CRLF normalised to LF (see ``HASH_CONVENTION``)."""

    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def _committed_bytes(path: Path, repo_root: Path | None) -> bytes | None:
    """The bytes git stores for ``path``, or the working copy when that is impossible."""

    if repo_root is not None:
        try:
            relative = path.resolve().relative_to(repo_root.resolve()).as_posix()
        except ValueError:
            relative = None
        if relative is not None:
            import subprocess

            result = subprocess.run(
                ["git", "show", f"HEAD:{relative}"],
                capture_output=True,
                cwd=repo_root,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                return result.stdout
    try:
        return path.read_bytes()
    except OSError:
        return None


def content_sha256_file(path: Path, repo_root: Path | None = None) -> str | None:
    """The portable content hash of a file, or ``None`` when it cannot be read.

    Reading the committed bytes when git can supply them makes the value
    independent of the checkout's line-ending configuration, which is what the
    release SBOM records.
    """

    data = _committed_bytes(path, repo_root)
    if data is None:
        return None
    return content_sha256(data)


def _git_dirty(repo_root: Path) -> bool | None:
    """Whether the working tree has uncommitted changes, or ``None`` if unknown."""

    import subprocess

    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True,
            text=True,
            cwd=repo_root,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - environment dependent
        return None
    if result.returncode != 0:
        return None
    return bool(result.stdout.strip())


def _policy_source_blobs(repo_root: Path) -> dict[str, Any]:
    """Content hashes of the committed policy-implementing files."""

    blobs: dict[str, Any] = {}
    for relative in POLICY_SOURCE_BLOBS:
        blobs[relative] = content_sha256_file(repo_root / relative, repo_root)
    missing = sorted(name for name, value in blobs.items() if value is None)
    return {
        "convention": HASH_CONVENTION,
        "blobs": blobs,
        "missing": missing,
        "missing_reason": (f"not present in this checkout: {missing}" if missing else None),
    }


def _file_sha256(path: Path | None, repo_root: Path | None = None) -> dict[str, Any]:
    """A file's portable content hash, with the convention recorded beside it."""

    if path is None or not path.is_file():
        return {"path": None, "sha256": None, "present": False, "hash_convention": HASH_CONVENTION}
    return {
        "path": path.name,
        "sha256": content_sha256_file(path, repo_root),
        "present": True,
        "hash_convention": HASH_CONVENTION,
    }


def _jsonl(records: Sequence[dict[str, Any]]) -> bytes:
    return "".join(json.dumps(record, sort_keys=True) + "\n" for record in records).encode("utf-8")


@dataclass(frozen=True)
class RunResult:
    run_dir: Path
    manifest: dict[str, Any]
    outcomes: tuple[Outcome, ...]
    control_outcomes: tuple[Outcome, ...]


def _policy_blob_sha256(documents: dict[str, dict[str, Any]]) -> tuple[str | None, str | None]:
    """The H5.2 gate value: a git blob hash over the documents the run decided under.

    The documents are derived from the committed scenario files, so the *committed*
    artifact that pins them is ``dataset.sha256``; this value pins the exact
    mapping from policy-set identity to document that the requests named. It is
    hashed with git's blob convention so it is comparable with a freeze record.
    Returns ``(null, reason)`` rather than omitting the field when it cannot be
    computed.
    """

    if not documents:
        return None, "the run pinned no policy set"
    try:
        canonical = json.dumps(
            {key: documents[key] for key in sorted(documents)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:  # pragma: no cover - defensive
        return None, f"the policy documents are not JSON-serialisable: {error}"
    return content_sha256(canonical), None


def _require_decision_status(
    response: HttpResponse,
    *,
    surface: str,
    path: str,
    scenario_id: str,
    step_id: int,
    url: str,
) -> None:
    """Refuse to continue when a decision request did not answer 200.

    A non-200 is never a verdict. Without this guard a deployment that required
    authentication would answer ``401`` to every request, and a run full of
    refusals would be scored as *attacks stopped* — the single most dangerous
    possible failure mode for this project. The run aborts before the run
    directory is created, so nothing is recorded.
    """

    if response.status == 200 and response.error is None:
        return
    detail = (response.error or "no response").strip()
    raise RunError(
        f"the {surface} did not answer 200: HTTP {response.status} on {path} at {url} "
        f"for scenario {scenario_id!r} step {step_id} [{detail}]. "
        "A non-2xx response is never recorded as a decision; the run was aborted before "
        "any run directory was written. If the surface requires authentication, pass "
        "--auth-token-file; if it refuses the policy set, publish it first with "
        "scripts/bench_policies.py."
    )


def execute_run(config: RunConfig, dataset: Dataset | None = None) -> RunResult:
    """Run the dataset against the defence and the control, then write the run."""

    loaded = dataset if dataset is not None else load_dataset(config.dataset_root)
    selected = tuple(
        entry.scenario for entry in loaded.entries if entry.scenario.split.value in config.splits
    )
    if not selected:
        raise RunError(f"no scenarios match splits {config.splits} in {config.dataset_root}")

    # The code identity is captured *before* the run directory exists, so the
    # directory this run creates cannot make the tree look dirty, and a run taken
    # with uncommitted changes says so instead of claiming a commit it did not use.
    code_commit = _git_commit()
    code_commit_source = "git-rev-parse-HEAD" if code_commit != "unknown" else "unavailable"
    code_dirty = _git_dirty(_git_root())

    # Fail fast on a name collision, before a single request is sent: a repeated
    # invocation must not pay a full gateway pass or perturb the host's latency
    # baseline for a concurrent measurement. The exclusive mkdir below remains the
    # authoritative guard.
    run_dir = config.runs_dir / config.run_name()
    if run_dir.exists():
        raise RunError(
            f"refusing to overwrite an existing run directory: {run_dir} "
            "(detected before any request was sent)"
        )

    # Every request pins the policy set its scenario needs, so the run records
    # exactly which stored policy documents it depends on. Publishing them is a
    # separate, auditable step (scripts/bench_policies.py).
    policy_sets_used: set[str] = set()
    policy_digests: dict[str, str] = {}
    policy_bodies: dict[str, dict[str, Any]] = {}
    for scenario in selected:
        identity = wire_policy_set_for(scenario)
        key = f"{identity['id']}:{identity['version']}"
        policy_sets_used.add(key)
        policy_digests[key] = wire_policy_document_digest(wire_policy_document(scenario))
        policy_bodies[key] = wire_policy_document(scenario)
    policy_blob_sha256, policy_blob_reason = _policy_blob_sha256(policy_bodies)
    policy_source_blobs = _policy_source_blobs(Path(__file__).resolve().parents[1])

    defense = HttpClient(config.defense_url, config.timeout, config.auth)
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
                _require_decision_status(
                    response,
                    surface="defence",
                    path=GENERIC_PATH,
                    scenario_id=scenario.id,
                    step_id=int(request["step_id"]),
                    url=config.defense_url,
                )
                defense_steps.append(_verdict_from(response, int(request["step_id"])))
            outcomes.append(
                derive_outcome(scenario, tuple(defense_steps), original_actions=original)
            )

            control_steps: list[StepVerdict] = []
            for request in build_plan_episode(scenario, run_id=run_id, plan=plan):
                response = control.post(GENERIC_PATH, request)
                _require_decision_status(
                    response,
                    surface="control",
                    path=GENERIC_PATH,
                    scenario_id=scenario.id,
                    step_id=int(request["step_id"]),
                    url=control_url,
                )
                control_steps.append(_verdict_from(response, int(request["step_id"])))
            control_outcomes.append(
                derive_outcome(scenario, tuple(control_steps), original_actions=original)
            )
    finally:
        if internal_control is not None:
            internal_control.stop()

    try:
        run_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError as error:  # pragma: no cover - the pre-flight check wins the race
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
        "code": {
            "commit": code_commit,
            "commit_source": code_commit_source,
            "branch": _git_branch(),
            "dirty": code_dirty,
        },
        "defense": {
            "url": config.defense_url,
            "health": {"status": health.status},
            "version": version.payload,
            "version_error": version.error,
            "endpoint": GENERIC_PATH,
        },
        "control": {"url": control_url, "kind": control_kind},
        "auth": (
            config.auth.metadata()
            if config.auth is not None
            else {
                "mode": "none",
                "header": None,
                "scheme": None,
                "principal": None,
                "principal_source": "no credential supplied",
            }
        ),
        "policy_set": (version.payload or {}).get("policy_set"),
        "policy": {
            "gate": "H5.2",
            "blob_sha256": policy_blob_sha256,
            "blob_sha256_reason": policy_blob_reason,
            "blob_sha256_source": (
                "the policy documents the requests pinned, hashed as one git blob over the "
                "canonical {policy-set-id:version -> document} map, computed by the "
                "benchmark before any gateway call"
            ),
            "hash_convention": HASH_CONVENTION,
            "source_blobs": policy_source_blobs,
            "source": "scenario-derived, published to the tenant and pinned per request",
            "publish_command": (
                "python scripts/bench_policies.py publish --defense-url <url> --token-file <path>"
            ),
            "policy_set_count": len(policy_sets_used),
            "policy_sets": sorted(policy_sets_used),
            "document_digests": {key: value for key, value in sorted(policy_digests.items())},
            "server_default": (version.payload or {}).get("policy_set"),
        },
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
        "dependency_lock": _file_sha256(config.lock_path, _git_root()),
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
    "read_token",
]
