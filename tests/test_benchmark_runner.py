"""Runner tests: a live gateway, an immutable run directory, a full manifest.

The stub gateway at the bottom of this file exists for one purpose: to prove that
a non-2xx response can never become a verdict. A run full of ``401``s must fail
loudly and write nothing, because the alternative — a table that looks like
*attacks stopped* — is the most dangerous failure this project can have.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from benchmark.policies import collect_policy_sets, publish_plan
from benchmark.runner import (
    AuthConfig,
    HttpClient,
    RunConfig,
    RunError,
    ScriptedAdapter,
    UnavailableModelAdapter,
    execute_run,
    load_run,
    model_adapter,
    read_token,
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
    url = f"http://127.0.0.1:{port}"
    # The gateway resolves the policy identity server-side (M2), so the policy
    # sets the selection pins must exist for the tenant before the run. In
    # development the principal holds every scope, so the test publishes them the
    # same way the documented flow does.
    plan = collect_policy_sets(DATA_ROOT, VALIDATION_SPLITS)
    publish_plan(HttpClient(url, 10.0), plan)
    try:
        yield url
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


class StubGateway:
    """A minimal origin server that answers every decision request with one status.

    It exists to test the failure path: what the runner does when the surface
    refuses to decide. Every request is recorded, so a test can assert that
    nothing was sent when it should not have been.
    """

    def __init__(self, decision_status: int = 200, detail: str = "stub") -> None:
        self.decision_status = decision_status
        self.detail = detail
        self.requests: list[tuple[str, dict[str, str]]] = []
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
                outer.requests.append((self.path, dict(self.headers)))
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
                outer.requests.append((self.path, dict(self.headers)))
                if outer.decision_status != 200:
                    self._send(
                        outer.decision_status,
                        {"detail": outer.detail, "code": f"STUB_{outer.decision_status}"},
                    )
                    return
                self._send(
                    200,
                    {
                        "decision": "allow",
                        "risk_score": 0.0,
                        "confidence": 1.0,
                        "reason_codes": ["STUB_ALLOW"],
                        "explanation": None,
                        "rewritten_action": None,
                        "metadata": {},
                        "api_version": "aegisgraph/v1",
                        "request_id": "0" * 32,
                        "receipt_id": "0" * 32,
                        "policy_set": {"id": "stub-default", "version": "1"},
                        "action_digest": "0" * 24,
                        "execution_digest": "0" * 24,
                        "decided_at": "2026-01-01T00:00:00Z",
                        "valid_until": "2026-01-01T00:01:00Z",
                    },
                )

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._httpd.server_address[1]}"

    def decision_requests(self) -> list[tuple[str, dict[str, str]]]:
        return [item for item in self.requests if item[0] == "/api/v1/decisions"]

    def __enter__(self) -> StubGateway:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


def test_a_401_is_never_recorded_as_a_verdict(tmp_path: Path) -> None:
    with (
        StubGateway(decision_status=401, detail="an Authorization header is required") as stub,
        pytest.raises(RunError) as caught,
    ):
        execute_run(_config(stub.url, tmp_path))

    message = str(caught.value)
    assert "HTTP 401" in message
    assert "/api/v1/decisions" in message
    assert "never recorded as a decision" in message
    assert "--auth-token-file" in message
    assert list(tmp_path.iterdir()) == []


def test_a_503_is_never_recorded_as_a_verdict(tmp_path: Path) -> None:
    with (
        StubGateway(decision_status=503, detail="no verifier") as stub,
        pytest.raises(RunError, match="HTTP 503"),
    ):
        execute_run(_config(stub.url, tmp_path))

    assert list(tmp_path.iterdir()) == []


def test_a_refused_request_names_the_scenario_and_the_step(tmp_path: Path) -> None:
    with (
        StubGateway(decision_status=422, detail="policy set is not stored") as stub,
        pytest.raises(RunError) as caught,
    ):
        execute_run(_config(stub.url, tmp_path))

    message = str(caught.value)
    assert "for scenario '" in message
    assert "step 0" in message
    assert "bench_policies.py" in message


def test_the_auth_header_is_sent_and_the_token_is_never_recorded(tmp_path: Path) -> None:
    token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiZW5jaC1jbGllbnQifQ.signature"
    auth = AuthConfig(token=token, header="X-Service-Token", scheme="")
    with StubGateway() as stub:
        result = execute_run(_config(stub.url, tmp_path, auth=auth))

    sent = [headers.get("X-Service-Token") for _, headers in stub.decision_requests()]
    assert sent and all(value == token for value in sent)

    manifest_text = (result.run_dir / "manifest.json").read_text(encoding="utf-8")
    assert token not in manifest_text
    assert result.manifest["auth"] == {
        "mode": "bearer",
        "header": "X-Service-Token",
        "scheme": "",
        "principal": "bench-client",
        "principal_source": "unverified-jwt-sub-or-null",
    }


def test_a_run_without_a_credential_records_that_it_had_none(tmp_path: Path) -> None:
    with StubGateway() as stub:
        result = execute_run(_config(stub.url, tmp_path))

    assert result.manifest["auth"]["mode"] == "none"
    assert result.manifest["auth"]["principal"] is None
    assert result.manifest["policy"]["gate"] == "H5.2"
    assert len(result.manifest["policy"]["blob_sha256"]) == 64
    assert result.manifest["policy"]["policy_set_count"] >= 1


def test_a_run_directory_collision_is_detected_before_any_request(tmp_path: Path) -> None:
    (tmp_path / "20260101T000000Z-pytest").mkdir()
    with StubGateway() as stub:
        with pytest.raises(RunError, match="detected before any request was sent"):
            execute_run(_config(stub.url, tmp_path))
        assert stub.decision_requests() == []


def test_the_token_reader_refuses_blank_and_wrapped_values(tmp_path: Path) -> None:
    path = tmp_path / "token"
    path.write_text("wrapped\nvalue\n", encoding="utf-8")
    with pytest.raises(RunError, match="whitespace"):
        read_token(None, str(path))

    empty = tmp_path / "empty"
    empty.write_text("   \n", encoding="utf-8")
    with pytest.raises(RunError, match="empty"):
        read_token(None, str(empty))

    with pytest.raises(RunError, match="not both"):
        read_token("a", str(path))

    with pytest.raises(RunError, match="not found"):
        read_token(None, str(tmp_path / "absent"))

    good = tmp_path / "good"
    good.write_text("abc.def.ghi\n", encoding="utf-8")
    assert read_token(None, str(good)) == "abc.def.ghi"
