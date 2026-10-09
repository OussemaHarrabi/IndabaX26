"""Campaign-driver tests: the model in the loop, failures, resume, immutability.

No torch, no GPU, no model download and no cloud run are used. The model seam is
a stub generator behind the real ``QwenModelAdapter`` (so the prompt the driver
feeds a verdict into is the real one), and the decision surface is either the real
gateway started in-process or a stub that refuses every decision. Every assertion
is against an artifact the driver actually wrote.
"""

from __future__ import annotations

import json
import threading
import time
import zipfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from benchmark.campaign import (
    ANCHOR_SEED,
    CONVENTION_NAME,
    HASH_DECLARATION,
    RUN_ARTIFACTS,
    CampaignConfig,
    CampaignError,
    bundle_run,
    count_failures,
    dry_run_plan,
    find_run_for_slug,
    parse_condition,
    plan_stage,
    read_hashes,
    run_campaign,
    validate_seed_count,
    verify_hashes,
    write_hashes,
)
from benchmark.dataset import write_scenario
from benchmark.fixtures import scenario_dict, write_dataset
from benchmark.policies import collect_policy_sets, publish_plan
from benchmark.qwen import PROMPT_REVISION, QwenConfig, QwenModelAdapter
from benchmark.runner import AuthConfig, HttpClient, ScriptedAdapter
from benchmark.schema import Scenario
from scripts.bench_campaign import _print_summary
from scripts.bench_campaign import main as campaign_main

# --------------------------------------------------------------------------- #
# Fixtures and helpers
# --------------------------------------------------------------------------- #


class StubGenerator:
    """A scripted stand-in for the model: returns outputs in order, records prompts."""

    def __init__(self, outputs: Sequence[str]) -> None:
        self._outputs = list(outputs)
        self.prompts: list[str] = []

    def __call__(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self._outputs:
            raise AssertionError("the adapter asked for more generations than the stub provided")
        return self._outputs.pop(0)


def _dataset(root: Path, *, pairs: int = 1, split: str = "development") -> Path:
    """A tiny synthetic dataset: ``pairs`` attack/control pairs, two steps each."""

    documents: list[dict[str, Any]] = []
    for index in range(pairs):
        documents.append(
            scenario_dict(
                scenario_id=f"ent_case_{index}_attack",
                pair_id=f"pair_case_{index}",
                split=split,
                attack_step_id=1,
            )
        )
        documents.append(
            scenario_dict(
                scenario_id=f"ent_case_{index}_control",
                pair_id=f"pair_case_{index}",
                scenario_kind="benign",
                attack_family=None,
                attack_step_id=None,
                split=split,
                expectation="allowed",
            )
        )
    write_dataset(root, documents)
    return root


def _authored_outputs(root: Path, scenario_id: str) -> list[str]:
    scenario = _scenario(root, scenario_id)
    return [json.dumps(item.action.model_dump(mode="json")) for item in scenario.proposed_actions]


def _scenario(root: Path, scenario_id: str) -> Scenario:
    from benchmark.dataset import load_dataset

    return load_dataset(root).by_id[scenario_id]


@contextmanager
def running_gateway(dataset_root: Path) -> Iterator[str]:
    """The real gateway on an ephemeral port, with the dataset's policy sets published."""

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
    url = f"http://127.0.0.1:{port}"
    plan = collect_policy_sets(dataset_root, ("development", "validation"))
    publish_plan(HttpClient(url, 10.0), plan)
    try:
        yield url
    finally:
        server.should_exit = True
        thread.join(timeout=15)


class StubGateway:
    """An origin that answers every decision request with one non-200 status.

    It answers health and version normally, so the campaign's pre-flight passes
    and the failure happens where the test wants it: at the decision surface.
    """

    def __init__(self, decision_status: int = 503, detail: str = "stub") -> None:
        self.decision_status = decision_status
        self.detail = detail
        self.requests: list[str] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: object) -> None:
                """Silence the access log."""

            def _send(self, status: int, payload: dict[str, object]) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                outer.requests.append(self.path)
                if self.path == "/healthz":
                    self._send(200, {"status": "ok"})
                elif self.path == "/api/v1/version":
                    self._send(
                        200,
                        {
                            "api_version": "aegisgraph/v1",
                            "policy_set": {"id": "stub-default", "version": "1"},
                            "build": {"service": "stub", "version": "0", "commit": "stub"},
                        },
                    )
                else:
                    self._send(404, {"detail": "Not found"})

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                outer.requests.append(self.path)
                self._send(outer.decision_status, {"detail": outer.detail})

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._httpd.server_address[1]}"

    def decision_requests(self) -> list[str]:
        return [path for path in self.requests if path == "/api/v1/decisions"]

    def __enter__(self) -> StubGateway:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


def _config(
    dataset_root: Path,
    runs_dir: Path,
    *,
    scenario_ids: Sequence[str] | None = None,
    model_name: str = "scripted",
    adapter: Any = None,
    gateway_url: str = "http://127.0.0.1:1",
    **overrides: Any,
) -> CampaignConfig:
    kwargs: dict[str, Any] = {
        "stage": "A",
        "dataset_root": dataset_root,
        "runs_dir": runs_dir,
        "seed": ANCHOR_SEED,
        "condition": "defence",
        "model_name": model_name,
        "adapter": adapter if adapter is not None else ScriptedAdapter(),
        "gateway_url": gateway_url,
        "splits": ("development",),
        "scenario_ids": tuple(scenario_ids) if scenario_ids is not None else None,
        "hardware_note": "pytest host",
        "lock_path": Path(__file__).resolve().parents[1] / "requirements.lock",
    }
    kwargs.update(overrides)
    return CampaignConfig(**kwargs)


def _rows(run_dir: Path, name: str) -> list[dict[str, Any]]:
    path = run_dir / name
    if not path.is_file():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


# --------------------------------------------------------------------------- #
# The model in the loop
# --------------------------------------------------------------------------- #


def test_the_decision_is_fed_back_into_the_next_generation(tmp_path: Path) -> None:
    root = _dataset(tmp_path / "data")
    generator = StubGenerator(_authored_outputs(root, "ent_case_0_attack"))
    adapter = QwenModelAdapter(QwenConfig(), generator=generator)

    with running_gateway(root) as url:
        result = run_campaign(
            _config(
                root,
                tmp_path / "runs",
                scenario_ids=("ent_case_0_attack",),
                model_name="qwen",
                adapter=adapter,
                gateway_url=url,
            )
        )

    assert result.status == "complete"
    assert len(generator.prompts) == 2, "one generation per authored step"

    decisions = [
        row for row in _rows(result.run_dir, "decisions.jsonl") if row["arm"] == "treatment"
    ]
    assert decisions, "the gateway decided the proposal"
    first = decisions[0]["payload"]
    assert first["decision"] in {"allow", "block", "escalate", "rewrite"}
    rendered = json.dumps(first, sort_keys=True, separators=(",", ":"))

    assert rendered not in generator.prompts[0], "step 0 has no verdict to feed back yet"
    assert rendered in generator.prompts[1], "step 1's prompt carries step 0's verdict"

    generations = _rows(result.run_dir, "raw_generations.jsonl")
    assert [row["order"] for row in generations] == [0, 1]
    assert all(row["parsed"] for row in generations)
    assert all(len(row["prompt_sha256"]) == 64 for row in generations)
    assert generations[1]["prompt_sha256"] != generations[0]["prompt_sha256"]

    configuration = json.loads((result.run_dir / "configuration.json").read_text(encoding="utf-8"))
    assert configuration["generation_loop"]["used"] is True
    assert configuration["prompt_revision"] == PROMPT_REVISION


def test_the_loop_stops_when_the_model_answers_finally(tmp_path: Path) -> None:
    root = _dataset(tmp_path / "data")
    final = '{"type": "respond", "content": "done", "final": true}'
    adapter = QwenModelAdapter(QwenConfig(), generator=StubGenerator([final]))

    with running_gateway(root) as url:
        result = run_campaign(
            _config(
                root,
                tmp_path / "runs",
                scenario_ids=("ent_case_0_attack",),
                model_name="qwen",
                adapter=adapter,
                gateway_url=url,
            )
        )

    generations = _rows(result.run_dir, "raw_generations.jsonl")
    proposals = _rows(result.run_dir, "proposed_actions.jsonl")
    assert len(generations) == 1
    assert len(proposals) == 1
    assert generations[0]["stop_reason"] == "parsed"


def test_the_scripted_adapter_records_no_generations(tmp_path: Path) -> None:
    root = _dataset(tmp_path / "data")
    with running_gateway(root) as url:
        result = run_campaign(
            _config(
                root,
                tmp_path / "runs",
                scenario_ids=("ent_case_0_attack",),
                gateway_url=url,
            )
        )

    assert (result.run_dir / "raw_generations.jsonl").read_bytes() == b""
    configuration = json.loads((result.run_dir / "configuration.json").read_text(encoding="utf-8"))
    assert configuration["generation_loop"]["used"] is False
    assert configuration["prompt_revision"] is None


# --------------------------------------------------------------------------- #
# Failures are recorded, never fatal
# --------------------------------------------------------------------------- #


def test_a_parse_failure_becomes_an_errored_outcome_and_the_campaign_continues(
    tmp_path: Path,
) -> None:
    root = _dataset(tmp_path / "data")
    adapter = QwenModelAdapter(
        QwenConfig(format_retries=0),
        generator=StubGenerator(["not json at all", "still not json"]),
    )

    with running_gateway(root) as url:
        result = run_campaign(
            _config(
                root,
                tmp_path / "runs",
                scenario_ids=("ent_case_0_attack", "ent_case_0_control"),
                model_name="qwen",
                adapter=adapter,
                gateway_url=url,
            )
        )

    outcomes = _rows(result.run_dir, "outcomes.jsonl")
    assert len(outcomes) == 2, "the campaign continued to the second scenario"
    assert all(outcome["errored"] for outcome in outcomes)
    assert all(outcome["attack_success"] is None for outcome in outcomes)
    assert result.status == "complete"
    assert result.errored == 2

    failures = _rows(result.run_dir, "failures.jsonl")
    parse_failures = [row for row in failures if row["cause"] == "model-parse-failure"]
    assert len(parse_failures) == 2
    assert parse_failures[0]["raw_output"] == "not json at all"
    assert parse_failures[0]["raw_output_truncated"] is False
    assert parse_failures[0]["stage"] == "A"
    assert parse_failures[0]["seed"] == ANCHOR_SEED
    assert parse_failures[0]["attempt"] == 1
    assert parse_failures[0]["phase"] == "generation"

    generations = _rows(result.run_dir, "raw_generations.jsonl")
    assert [row["parsed"] for row in generations] == [False, False]


def test_a_repaired_generation_keeps_both_raw_attempts(tmp_path: Path) -> None:
    root = _dataset(tmp_path / "data")
    scenario = _scenario(root, "ent_case_0_attack")
    valid = _authored_outputs(root, scenario.id)
    invalid = '{"type":"tool_call","tool":"document_read","arguments":{},"content":"reading"}'
    adapter = QwenModelAdapter(
        QwenConfig(format_retries=1), generator=StubGenerator([invalid, *valid])
    )

    with running_gateway(root) as url:
        result = run_campaign(
            _config(
                root,
                tmp_path / "runs",
                scenario_ids=(scenario.id,),
                model_name="qwen",
                adapter=adapter,
                gateway_url=url,
            )
        )

    generations = _rows(result.run_dir, "raw_generations.jsonl")
    assert [row["parsed"] for row in generations[:2]] == [False, True]
    assert [row["format_attempt"] for row in generations[:2]] == [0, 1]
    assert generations[0]["output"] == invalid
    assert result.errored == 0


def test_campaign_qwen_adapter_uses_the_per_run_campaign_seed(tmp_path: Path) -> None:
    config = CampaignConfig(
        stage="A",
        dataset_root=tmp_path,
        runs_dir=tmp_path / "runs",
        seed=2741,
        model_name="qwen",
        adapter_config={"seed": 0, "quantization": "4bit"},
    )

    adapter = config.resolve_model()

    assert isinstance(adapter, QwenModelAdapter)
    assert adapter.config.seed == 2741


def test_cli_summary_marks_completed_attempts_with_errors_as_failed(capsys: Any) -> None:
    result = type(
        "Result",
        (),
        {"status": "complete", "errored": 2, "failures": 2, "bundle": None},
    )()

    succeeded = _print_summary([result])

    assert succeeded is False
    assert "RESULT: CAMPAIGN COMPLETED WITH ERRORS" in capsys.readouterr().out


def test_cli_summary_allows_a_recovered_run_to_complete(capsys: Any) -> None:
    result = type(
        "Result",
        (),
        {"status": "complete", "errored": 0, "failures": 2, "bundle": None},
    )()

    succeeded = _print_summary([result])

    assert succeeded is True
    output = capsys.readouterr().out
    assert "retained failure records: 2" in output
    assert "RESULT: CAMPAIGN COMPLETE" in output


def test_a_gateway_error_is_recorded_not_fatal(tmp_path: Path) -> None:
    root = _dataset(tmp_path / "data")
    with StubGateway(decision_status=503, detail="no verifier") as stub:
        result = run_campaign(
            _config(
                root,
                tmp_path / "runs",
                scenario_ids=("ent_case_0_attack", "ent_case_0_control"),
                gateway_url=stub.url,
            )
        )

    assert result.status == "complete", "a refused decision is recorded, not fatal"
    outcomes = _rows(result.run_dir, "outcomes.jsonl")
    assert len(outcomes) == 2
    assert all(outcome["errored"] for outcome in outcomes)

    failures = _rows(result.run_dir, "failures.jsonl")
    gateway = [row for row in failures if row["cause"] == "gateway-error"]
    assert gateway, failures
    assert gateway[0]["http_status"] == 503
    assert stub.decision_requests(), "the driver really did call the surface"
    assert "503" in gateway[0]["detail"]


def test_a_non_200_can_never_be_read_as_a_stopped_attack(tmp_path: Path) -> None:
    """The whole point of the failure path: a refusal must not look like a block."""

    root = _dataset(tmp_path / "data")
    with StubGateway(decision_status=401, detail="an Authorization header is required") as stub:
        result = run_campaign(
            _config(
                root,
                tmp_path / "runs",
                scenario_ids=("ent_case_0_attack",),
                gateway_url=stub.url,
            )
        )

    outcome = _rows(result.run_dir, "outcomes.jsonl")[0]
    assert outcome["attack_success"] is None
    assert outcome["errored"] is True
    assert all(step["decision"] is None for step in outcome["steps"])


# --------------------------------------------------------------------------- #
# Checkpoints, resume and immutability
# --------------------------------------------------------------------------- #


def test_a_clean_stop_leaves_the_run_resumable_and_resume_skips_verified(
    tmp_path: Path,
) -> None:
    root = _dataset(tmp_path / "data", pairs=2)
    ids = ("ent_case_0_attack", "ent_case_0_control", "ent_case_1_attack", "ent_case_1_control")

    with running_gateway(root) as url:
        first = run_campaign(
            _config(root, tmp_path / "runs", scenario_ids=ids, gateway_url=url, max_scenarios=2)
        )
        assert first.status == "incomplete"
        assert first.completed == 2
        assert first.remaining == 2

        second = run_campaign(
            _config(root, tmp_path / "runs", scenario_ids=ids, gateway_url=url, resume=True)
        )

    assert second.resumed is True
    assert second.skipped == 2
    assert second.completed == 4
    assert second.status == "complete"
    assert second.run_dir == first.run_dir
    assert sorted(path.name for path in (second.run_dir / "checkpoints").glob("*.json")) == [
        f"{scenario_id}.json" for scenario_id in sorted(ids)
    ]


def test_resume_re_runs_a_scenario_whose_checkpoint_hash_fails(tmp_path: Path) -> None:
    root = _dataset(tmp_path / "data", pairs=2)
    ids = ("ent_case_0_attack", "ent_case_0_control", "ent_case_1_attack", "ent_case_1_control")

    with running_gateway(root) as url:
        first = run_campaign(
            _config(root, tmp_path / "runs", scenario_ids=ids, gateway_url=url, max_scenarios=2)
        )
        checkpoint = first.run_dir / "checkpoints" / "ent_case_0_attack.json"
        document = json.loads(checkpoint.read_text(encoding="utf-8"))
        document["status"] = "tampered"
        checkpoint.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        second = run_campaign(
            _config(root, tmp_path / "runs", scenario_ids=ids, gateway_url=url, resume=True)
        )

    assert second.skipped == 1, "only the untouched checkpoint was skipped"
    rejected = sorted((second.run_dir / "checkpoints" / "rejected").glob("*.json"))
    assert len(rejected) == 1
    assert "ent_case_0_attack" in rejected[0].name

    failures = _rows(second.run_dir, "failures.jsonl")
    mismatches = [row for row in failures if row["cause"] == "checkpoint-hash-mismatch"]
    assert len(mismatches) == 1
    assert mismatches[0]["phase"] == "resume"

    rewritten = json.loads(
        (second.run_dir / "checkpoints" / "ent_case_0_attack.json").read_text(encoding="utf-8")
    )
    assert rewritten["status"] in {"ok", "errored"}
    assert rewritten["attempt"] == 2
    assert verify_hashes(second.run_dir)["ok"] is True
    assert second.status == "complete"


def test_a_completed_run_is_never_overwritten(tmp_path: Path) -> None:
    root = _dataset(tmp_path / "data")
    ids = ("ent_case_0_attack", "ent_case_0_control")

    with running_gateway(root) as url:
        first = run_campaign(_config(root, tmp_path / "runs", scenario_ids=ids, gateway_url=url))
        manifest_before = (first.run_dir / "manifest.json").read_bytes()
        hashes_before = (first.run_dir / "hashes.sha256").read_bytes()

        with pytest.raises(CampaignError, match="refusing to overwrite an existing run"):
            run_campaign(
                _config(
                    root,
                    tmp_path / "runs",
                    scenario_ids=ids,
                    gateway_url=url,
                    timestamp=first.run_dir.name.split("-")[0],
                )
            )
        with pytest.raises(CampaignError, match="refusing to resume a completed run"):
            run_campaign(
                _config(root, tmp_path / "runs", scenario_ids=ids, gateway_url=url, resume=True)
            )

    assert (first.run_dir / "manifest.json").read_bytes() == manifest_before
    assert (first.run_dir / "hashes.sha256").read_bytes() == hashes_before


def test_a_resume_with_a_changed_configuration_is_refused(tmp_path: Path) -> None:
    root = _dataset(tmp_path / "data", pairs=2)
    ids = ("ent_case_0_attack", "ent_case_0_control", "ent_case_1_attack", "ent_case_1_control")

    with running_gateway(root) as url:
        run_campaign(
            _config(root, tmp_path / "runs", scenario_ids=ids, gateway_url=url, max_scenarios=1)
        )
        with pytest.raises(CampaignError, match="the frozen configuration changed"):
            run_campaign(
                _config(
                    root,
                    tmp_path / "runs",
                    scenario_ids=ids[:2],
                    gateway_url=url,
                    resume=True,
                )
            )


# --------------------------------------------------------------------------- #
# The artifact set
# --------------------------------------------------------------------------- #


def test_the_artifact_set_is_complete_and_hashes_verify(tmp_path: Path) -> None:
    root = _dataset(tmp_path / "data")
    ids = ("ent_case_0_attack", "ent_case_0_control")

    with running_gateway(root) as url:
        result = run_campaign(_config(root, tmp_path / "runs", scenario_ids=ids, gateway_url=url))

    for name in RUN_ARTIFACTS:
        assert (result.run_dir / name).is_file(), f"missing artifact {name}"

    report = verify_hashes(result.run_dir)
    assert report["ok"] is True, report
    recorded = read_hashes(result.run_dir)
    for name in RUN_ARTIFACTS:
        if name == "hashes.sha256":
            continue
        assert name in recorded
    assert "checkpoints/ent_case_0_attack.json" in recorded
    assert read_hashes(result.run_dir) == recorded

    manifest = json.loads((result.run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["campaign"]["status"] == "complete"
    assert manifest["campaign"]["sessions"] == 1
    assert manifest["run"]["immutable"] is True
    assert manifest["model"]["kind"] == "scripted"
    assert manifest["dataset"]["sha256"] != ""
    assert manifest["scenario_set"]["scenario_ids"] == list(ids)
    assert manifest["policy"]["blob_sha256"] is not None
    assert manifest["artifacts"]["outcomes.jsonl"] != ""
    assert manifest["seed"] == ANCHOR_SEED

    configuration = json.loads((result.run_dir / "configuration.json").read_text(encoding="utf-8"))
    assert configuration["scenario_ids"] == list(ids)
    assert configuration["seed_rule"]["count"] == 1
    assert configuration["freeze_block"].startswith("docs/evidence/qwen-campaign-freeze.md")

    environment = json.loads((result.run_dir / "environment.json").read_text(encoding="utf-8"))
    assert environment["timing"]["sessions"] == 1
    assert environment["timing"]["cumulative_wall_clock_seconds"] >= 0
    assert environment["gpu"]["present"] in (True, False)
    assert environment["host"]["python"]


def test_the_hash_manifest_declares_its_convention(tmp_path: Path) -> None:
    """The declaration is a fixed token, and every entry is taken under it.

    A CRLF file dropped into the run directory (a ``score.json`` written through
    the platform's text mode on Windows) must still verify under the declared
    convention, and must *not* verify raw — which is exactly why the declaration
    has to be in the file.
    """

    import hashlib

    root = _dataset(tmp_path / "data")
    ids = ("ent_case_0_attack", "ent_case_0_control")

    with running_gateway(root) as url:
        result = run_campaign(_config(root, tmp_path / "runs", scenario_ids=ids, gateway_url=url))

    text = (result.run_dir / "hashes.sha256").read_text(encoding="utf-8")
    lines = text.splitlines()
    assert lines[0] == "# convention: content-sha256-lf"
    assert lines[0] == HASH_DECLARATION
    assert CONVENTION_NAME == "content-sha256-lf"
    assert all(line.startswith("#") or "  " in line for line in lines)

    entries = {}
    for line in lines[1:]:
        if line.startswith("#"):
            continue
        digest, relative = line.split("  ", 1)
        entries[relative] = digest
    assert "manifest.json" in entries
    assert not any(relative.startswith("/") or ":" in relative for relative in entries)
    for relative, digest in entries.items():
        raw = (result.run_dir / relative).read_bytes()
        assert digest == hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest(), relative

    crlf = result.run_dir / "score.json"
    crlf.write_bytes(b'{\r\n  "asr": null\r\n}\r\n')
    written = write_hashes(result.run_dir)
    assert written["score.json"] == hashlib.sha256(b'{\n  "asr": null\n}\n').hexdigest()
    assert written["score.json"] != hashlib.sha256(crlf.read_bytes()).hexdigest()
    assert verify_hashes(result.run_dir)["ok"] is True
    assert verify_hashes(result.run_dir)["hash_convention"] == "content-sha256-lf"


def test_the_committed_scorer_reads_the_campaign_run(tmp_path: Path) -> None:
    """A campaign run directory must be scorable by the committed scorer, unmodified."""

    from benchmark.runner import load_run

    root = _dataset(tmp_path / "data")
    ids = ("ent_case_0_attack", "ent_case_0_control")

    with running_gateway(root) as url:
        result = run_campaign(_config(root, tmp_path / "runs", scenario_ids=ids, gateway_url=url))

    manifest, outcomes, control = load_run(result.run_dir)
    assert manifest["run"]["name"] == result.run_dir.name
    assert len(outcomes) == len(control) == 2


# --------------------------------------------------------------------------- #
# Conditions
# --------------------------------------------------------------------------- #


def test_the_control_condition_measures_the_allow_all_arm(tmp_path: Path) -> None:
    root = _dataset(tmp_path / "data")
    ids = ("ent_case_0_attack",)

    result = run_campaign(
        _config(root, tmp_path / "runs", scenario_ids=ids, condition="control")
    )

    manifest = json.loads((result.run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["control"]["kind"] == "treatment-is-allow-all-control"
    assert manifest["defense"]["url"] == manifest["control"]["url"]
    outcomes = _rows(result.run_dir, "outcomes.jsonl")
    control = _rows(result.run_dir, "control.jsonl")
    assert outcomes == control
    assert all(step["decision"] == "allow" for step in outcomes[0]["steps"])
    assert result.run_dir.name.endswith("-a-control-s1729")


def test_an_ablation_condition_is_recorded_in_the_slug_and_configuration(
    tmp_path: Path,
) -> None:
    root = _dataset(tmp_path / "data")
    with running_gateway(root) as url:
        result = run_campaign(
            _config(
                root,
                tmp_path / "runs",
                scenario_ids=("ent_case_0_attack",),
                condition="ablation:kernel",
                gateway_url=url,
            )
        )

    assert result.run_dir.name.endswith("-a-ablation-kernel-s1729")
    configuration = json.loads((result.run_dir / "configuration.json").read_text(encoding="utf-8"))
    assert configuration["condition"] == {
        "name": "ablation",
        "ablation": "kernel",
        "slug": "ablation-kernel",
    }


def test_an_unknown_condition_is_rejected() -> None:
    with pytest.raises(CampaignError, match="needs a component name"):
        parse_condition("ablation:")
    with pytest.raises(CampaignError, match="unknown condition"):
        parse_condition("nonsense")


# --------------------------------------------------------------------------- #
# Stage D, the seed rules and the dry run
# --------------------------------------------------------------------------- #


def _holdout_dir(tmp_path: Path) -> Path:
    holdout = tmp_path / "holdout"
    holdout.mkdir(parents=True, exist_ok=True)
    scenario = Scenario.model_validate(
        scenario_dict(scenario_id="hold_case_attack", pair_id="pair_hold", split="holdout")
    )
    write_scenario(holdout / f"{scenario.id}.json", scenario)
    return holdout


def test_stage_d_refuses_without_the_authorization_flag(tmp_path: Path) -> None:
    root = _dataset(tmp_path / "data")
    holdout = _holdout_dir(tmp_path)
    runs = tmp_path / "runs"

    with pytest.raises(CampaignError, match="authorize-holdout"):
        run_campaign(
            CampaignConfig(
                stage="D",
                dataset_root=root,
                runs_dir=runs,
                holdout_dir=holdout,
                model_name="scripted",
                adapter=ScriptedAdapter(),
            )
        )
    assert not runs.exists(), "nothing was touched"


def test_stage_d_refuses_a_missing_plaintext_holdout(tmp_path: Path) -> None:
    root = _dataset(tmp_path / "data")
    with pytest.raises(CampaignError, match="does not exist"):
        plan_stage(
            CampaignConfig(
                stage="D",
                dataset_root=root,
                runs_dir=tmp_path / "runs",
                holdout_dir=tmp_path / "not-there",
                authorize_holdout=True,
            )
        )


def test_stage_d_with_authorization_runs_the_holdout_once(tmp_path: Path) -> None:
    root = _dataset(tmp_path / "data")
    holdout = _holdout_dir(tmp_path)
    result = run_campaign(
        CampaignConfig(
            stage="D",
            dataset_root=root,
            runs_dir=tmp_path / "runs",
            holdout_dir=holdout,
            authorize_holdout=True,
            model_name="scripted",
            adapter=ScriptedAdapter(),
            condition="control",
        )
    )

    assert result.plan.scenario_ids == ("hold_case_attack",)
    assert result.run_dir.name.endswith("-d-control-s1729")
    manifest = json.loads((result.run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["dataset"]["root"] == str(holdout)
    assert manifest["scenario_set"]["splits"] == ["holdout"]


def test_the_stage_seed_rules_are_enforced() -> None:
    assert validate_seed_count("A", (1729,))["count"] == 1
    with pytest.raises(CampaignError, match="at least 3 preregistered seed"):
        validate_seed_count("B", (1729, 42))
    with pytest.raises(CampaignError, match="at least 3 preregistered seed"):
        validate_seed_count("C", (1729,))
    assert validate_seed_count("C", (1, 2, 3))["below_preferred"] is True
    assert validate_seed_count("C", (1, 2, 3, 4, 5))["below_preferred"] is False
    with pytest.raises(CampaignError, match="exactly 1 seed"):
        validate_seed_count("A", (1, 2))
    with pytest.raises(CampaignError, match="exactly 1 seed"):
        validate_seed_count("D", (1, 2))
    with pytest.raises(CampaignError, match="duplicate seeds"):
        validate_seed_count("C", (1, 1, 2))


def test_the_dry_run_calls_nothing_and_writes_nothing(tmp_path: Path) -> None:
    root = _dataset(tmp_path / "data")
    runs = tmp_path / "runs"
    with StubGateway() as stub:
        code = campaign_main(
            [
                "--stage",
                "A",
                "--model",
                "scripted",
                "--dataset",
                str(root),
                "--defense-url",
                stub.url,
                "--runs-dir",
                str(runs),
                "--scenario-ids",
                "ent_case_0_attack",
                "--dry-run",
            ]
        )

    assert code == 0
    assert stub.requests == [], "the dry run opened no connection"
    assert not runs.exists()


def test_the_dry_run_refuses_a_stage_below_the_seed_floor(tmp_path: Path, capsys: Any) -> None:
    root = _dataset(tmp_path / "data")
    runs = tmp_path / "runs"
    code = campaign_main(
        [
            "--stage",
            "B",
            "--seed",
            "1729",
            "--model",
            "scripted",
            "--dataset",
            str(root),
            "--runs-dir",
            str(runs),
            "--dry-run",
        ]
    )

    assert code == 2
    assert "RESULT: DRY-RUN FAILED" in capsys.readouterr().err
    assert not runs.exists()


def test_the_dry_run_lists_one_run_per_seed(tmp_path: Path) -> None:
    root = _dataset(tmp_path / "data")
    plan = dry_run_plan(
        _config(root, tmp_path / "runs", scenario_ids=("ent_case_0_attack",), stage="A"),
        (1729,),
    )

    assert plan["stage"] == "A"
    assert plan["seed_rule"]["count"] == 1
    assert [run["seed"] for run in plan["runs"]] == [1729]
    assert plan["runs"][0]["scenario_ids"] == ["ent_case_0_attack"]
    assert plan["runs"][0]["treatment_surface"] == "http://127.0.0.1:1"
    assert set(RUN_ARTIFACTS).issubset(set(plan["runs"][0]["artifacts"]))


# --------------------------------------------------------------------------- #
# Bundling
# --------------------------------------------------------------------------- #


def test_the_bundle_is_a_zip_whose_hashes_verify(tmp_path: Path) -> None:
    root = _dataset(tmp_path / "data")
    ids = ("ent_case_0_attack", "ent_case_0_control")

    with running_gateway(root) as url:
        result = run_campaign(_config(root, tmp_path / "runs", scenario_ids=ids, gateway_url=url))

    bundle = bundle_run(result.run_dir)
    assert bundle.is_file()
    assert bundle.name == f"{result.run_dir.name}.zip"

    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(bundle) as archive:
        archive.extractall(extracted)
        names = archive.namelist()
    assert "hashes.sha256" in names
    assert "manifest.json" in names
    assert "checkpoints/ent_case_0_attack.json" in names
    assert verify_hashes(extracted)["ok"] is True

    with pytest.raises(CampaignError, match="refusing to overwrite an existing bundle"):
        bundle_run(result.run_dir)


def test_bundling_an_incomplete_run_is_refused(tmp_path: Path) -> None:
    root = _dataset(tmp_path / "data", pairs=2)
    ids = ("ent_case_0_attack", "ent_case_0_control", "ent_case_1_attack", "ent_case_1_control")

    with running_gateway(root) as url:
        result = run_campaign(
            _config(root, tmp_path / "runs", scenario_ids=ids, gateway_url=url, max_scenarios=1)
        )

    with pytest.raises(CampaignError, match="incomplete run"):
        bundle_run(result.run_dir)


def test_bundling_is_a_standalone_packaging_step(tmp_path: Path) -> None:
    root = _dataset(tmp_path / "data")
    ids = ("ent_case_0_attack", "ent_case_0_control")

    with running_gateway(root) as url:
        first = run_campaign(_config(root, tmp_path / "runs", scenario_ids=ids, gateway_url=url))

    with StubGateway() as stub:
        code = campaign_main(
            [
                "--stage",
                "A",
                "--model",
                "scripted",
                "--dataset",
                str(root),
                "--defense-url",
                stub.url,
                "--runs-dir",
                str(tmp_path / "runs"),
                "--scenario-ids",
                "ent_case_0_attack,ent_case_0_control",
                "--bundle",
            ]
        )

    assert code == 0
    assert stub.requests == [], "packaging must not call anything"
    assert (first.run_dir.parent / f"{first.run_dir.name}.zip").is_file()


def test_bundle_only_refuses_when_nothing_was_run(tmp_path: Path, capsys: Any) -> None:
    root = _dataset(tmp_path / "data")
    code = campaign_main(
        [
            "--stage",
            "A",
            "--model",
            "scripted",
            "--dataset",
            str(root),
            "--runs-dir",
            str(tmp_path / "runs"),
            "--scenario-ids",
            "ent_case_0_attack",
            "--bundle",
        ]
    )

    assert code == 2
    assert "nothing to bundle" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# The CLI surface
# --------------------------------------------------------------------------- #


def test_the_cli_requires_a_seed_for_the_later_stages(tmp_path: Path, capsys: Any) -> None:
    root = _dataset(tmp_path / "data")
    code = campaign_main(
        [
            "--stage",
            "C",
            "--model",
            "scripted",
            "--dataset",
            str(root),
            "--runs-dir",
            str(tmp_path / "runs"),
            "--dry-run",
        ]
    )

    assert code == 2
    assert "RESULT: DRY-RUN FAILED" in capsys.readouterr().err


def test_the_cli_rejects_a_bad_adapter_configuration(tmp_path: Path, capsys: Any) -> None:
    root = _dataset(tmp_path / "data")
    code = campaign_main(
        [
            "--stage",
            "A",
            "--model",
            "qwen",
            "--dataset",
            str(root),
            "--runs-dir",
            str(tmp_path / "runs"),
            "--adapter-json",
            '{"not_a_field": 1}',
            "--dry-run",
        ]
    )

    assert code == 2
    assert "RESULT: DRY-RUN FAILED" in capsys.readouterr().err


def test_the_cli_runs_a_stage_and_reports_the_run_directory(tmp_path: Path, capsys: Any) -> None:
    root = _dataset(tmp_path / "data")
    with running_gateway(root) as url:
        code = campaign_main(
            [
                "--stage",
                "A",
                "--model",
                "scripted",
                "--dataset",
                str(root),
                "--defense-url",
                url,
                "--runs-dir",
                str(tmp_path / "runs"),
                "--scenario-ids",
                "ent_case_0_attack",
            ]
        )

    out = capsys.readouterr().out
    assert code == 0, out
    assert "RESULT: CAMPAIGN COMPLETE" in out
    assert "run directory: " in out


def test_a_failed_run_exits_one(tmp_path: Path, capsys: Any) -> None:
    """A model that cannot load is a failure, not a refusal."""

    root = _dataset(tmp_path / "data")
    with running_gateway(root) as url:
        code = campaign_main(
            [
                "--stage",
                "A",
                "--model",
                "ollama",
                "--dataset",
                str(root),
                "--runs-dir",
                str(tmp_path / "runs"),
                "--scenario-ids",
                "ent_case_0_attack",
                "--defense-url",
                url,
            ]
        )

    assert code == 1
    assert "run failed:" in capsys.readouterr().err


def test_find_run_for_slug_ignores_other_slugs(tmp_path: Path) -> None:
    root = _dataset(tmp_path / "data")
    with running_gateway(root) as url:
        result = run_campaign(
            _config(root, tmp_path / "runs", scenario_ids=("ent_case_0_attack",), gateway_url=url)
        )

    assert find_run_for_slug(tmp_path / "runs", "scripted-a-s1729") == result.run_dir
    assert find_run_for_slug(tmp_path / "runs", "scripted-a-s42") is None
    assert count_failures(result.run_dir) == 0


def test_the_token_is_never_written_into_the_run(tmp_path: Path) -> None:
    root = _dataset(tmp_path / "data")
    token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiZW5jaC1jbGllbnQifQ.signature"

    with running_gateway(root) as url:
        result = run_campaign(
            _config(
                root,
                tmp_path / "runs",
                scenario_ids=("ent_case_0_attack",),
                gateway_url=url,
                auth=AuthConfig(token=token),
            )
        )

    for name in RUN_ARTIFACTS:
        assert token not in (result.run_dir / name).read_text(encoding="utf-8", errors="replace")
    manifest = json.loads((result.run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["auth"]["mode"] == "bearer"
    assert manifest["auth"]["principal"] == "bench-client"
