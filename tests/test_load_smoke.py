"""Smoke test for the load harness against a real server (M3).

The harness is exercised end to end: a uvicorn subprocess serving the real
application with the M2 authentication surface, an opaque service token on disk, the
policy set published over HTTP, and an immutable report written to a temporary
directory. A short budget keeps the test inside a few seconds.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import secrets
import socket
import stat
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BACKEND = REPOSITORY_ROOT / "backend"
SCRIPT = REPOSITORY_ROOT / "scripts" / "load_test.py"
STARTUP_TIMEOUT_SECONDS = 40.0


def _load_harness() -> ModuleType:
    spec = importlib.util.spec_from_file_location("aegisgraph_load_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


harness = _load_harness()


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@dataclass(frozen=True)
class LiveServer:
    base_url: str
    token_file: Path
    output_directory: Path
    log_path: Path


@pytest.fixture(scope="module")
def server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[LiveServer]:
    directory = tmp_path_factory.mktemp("load-smoke")
    token = secrets.token_urlsafe(32)
    token_file = directory / "service-token"
    token_file.write_text(token + "\n", encoding="utf-8")
    tokens_file = directory / "service-tokens.json"
    tokens_file.write_text(
        json.dumps(
            [
                {
                    "id": "load-smoke-client",
                    "tenant_id": "tenant-smoke",
                    "sha256": hashlib.sha256(token.encode()).hexdigest(),
                    "scopes": [
                        "decision:submit",
                        "receipt:read",
                        "policy:read",
                        "policy:write",
                    ],
                    "trust_ceiling": "trusted_internal",
                }
            ]
        ),
        encoding="utf-8",
    )
    port = _free_port()
    log_path = directory / "api.log"
    environment = {
        **os.environ,
        "PYTHONPATH": str(BACKEND),
        "AEGISGRAPH_AUTH_MODE": "required",
        "AEGISGRAPH_SERVICE_TOKEN_FILE": str(tokens_file),
        "AEGISGRAPH_LOG_LEVEL": "info",
        "AEGISGRAPH_LEGACY_UNAUTHENTICATED": "false",
    }
    environment.pop("DATABASE_URL", None)
    environment.pop("OTEL_EXPORTER_OTLP_ENDPOINT", None)
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "aegisgraph.app:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--log-level",
                "warning",
            ],
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    base_url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"the server exited early:\n{log_path.read_text()[-2000:]}")
            try:
                if httpx.get(f"{base_url}/healthz", timeout=1.0).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.2)
        else:
            raise RuntimeError(f"the server did not become ready:\n{log_path.read_text()[-2000:]}")
        yield LiveServer(base_url, token_file, directory, log_path)
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:  # pragma: no cover - a server that ignores SIGTERM
            process.kill()
            process.wait(timeout=15)


def _run_harness(server: LiveServer, *extra: str) -> int:
    return harness.main(
        [
            "--token-file",
            str(server.token_file),
            "--base-url",
            server.base_url,
            "--out-dir",
            str(server.output_directory),
            *extra,
        ]
    )


def test_the_harness_reports_a_clean_run_and_writes_an_immutable_report(
    server: LiveServer,
) -> None:
    exit_code = _run_harness(
        server,
        "--concurrency",
        "4",
        "--duration",
        "2",
        "--warm-up",
        "5",
        "--requests",
        "40",
        "--server-log",
        str(server.log_path),
        "--label",
        "load smoke",
    )

    assert exit_code == 0
    reports = sorted(server.output_directory.glob("m3-load-*.json"))
    assert len(reports) == 1
    report_path = reports[0]
    body = report_path.read_text(encoding="utf-8")
    report = json.loads(body)
    results = report["results"]

    assert report["schema"] == "aegisgraph.load-test/1"
    assert report["label"] == "load smoke"
    assert report["api_version"] == "aegisgraph/v1"
    assert results["measured_requests"] == 40
    assert results["status_counts"] == {"200": 40}
    assert results["error_rate"] == 0.0
    assert results["server_error_rate"] == 0.0
    assert results["throughput_rps"] > 0.0
    latency = results["latency_seconds"]
    assert 0.0 < latency["p50"] <= latency["p95"] <= latency["p99"] <= latency["max"]
    assert sum(results["verdict_counts"].values()) == 40
    assert set(results["verdict_counts"]) <= {"allow", "block", "escalate"}
    assert sum(results["shape_counts"].values()) == 40
    assert report["environment"]["observed_on"].startswith("local developer hardware")
    assert report["environment"]["base_url"] == server.base_url
    assert report["policy_set"]["id"] == "load-test-policy"
    assert report["policy_set"]["source"]
    assert report["service_side"]["decisions_observed"] >= 40
    assert report["service_side"]["latency_seconds"]["p95"] > 0.0

    # The digest covers the payload, and the sidecar covers the bytes on disk.
    payload = {key: value for key, value in report.items() if key != "report_digest_sha256"}
    assert report["report_digest_sha256"] == harness.digest_of(payload)
    sidecar = report_path.with_suffix(".sha256").read_text(encoding="utf-8").split()
    assert sidecar[0] == hashlib.sha256(body.encode("utf-8")).hexdigest()
    assert sidecar[1] == report_path.name
    assert stat.S_IMODE(report_path.stat().st_mode) & 0o222 == 0


def test_an_existing_report_is_never_overwritten(tmp_path: Path) -> None:
    stamp = datetime(2026, 10, 8, 12, 0, 0, tzinfo=UTC)
    report: dict[str, Any] = {"schema": "aegisgraph.load-test/1", "results": {}}

    path, digest = harness.write_report(report, tmp_path, stamp=stamp)

    assert path.exists()
    assert path.with_suffix(".sha256").read_text(encoding="utf-8").startswith(digest)
    with pytest.raises(FileExistsError):
        harness.write_report(report, tmp_path, stamp=stamp)


def test_the_harness_refuses_a_missing_or_multi_line_token_file(tmp_path: Path) -> None:
    missing = tmp_path / "absent"
    assert harness.main(["--token-file", str(missing), "--base-url", "http://127.0.0.1:1"]) == 2

    multi = tmp_path / "multi"
    multi.write_text("one\ntwo\n", encoding="utf-8")
    assert harness.main(["--token-file", str(multi), "--base-url", "http://127.0.0.1:1"]) == 2


def test_the_harness_reports_an_unreachable_api_instead_of_crashing(tmp_path: Path) -> None:
    token = tmp_path / "token"
    token.write_text("not-a-real-token\n", encoding="utf-8")
    port = _free_port()

    exit_code = harness.main(
        [
            "--token-file",
            str(token),
            "--base-url",
            f"http://127.0.0.1:{port}",
            "--duration",
            "1",
            "--warm-up",
            "0",
        ]
    )

    assert exit_code == 2


def test_percentiles_interpolate_and_stay_monotone() -> None:
    samples = [1.0, 2.0, 3.0, 4.0]

    assert harness.percentile(samples, 0.0) == 1.0
    assert harness.percentile(samples, 1.0) == 4.0
    assert harness.percentile(samples, 0.5) == 2.5
    assert harness.percentile([], 0.95) == 0.0
    assert harness.percentile([7.0], 0.99) == 7.0


def test_the_request_mix_is_a_weighted_valid_set() -> None:
    weights = [weight for weight, _name, _action in harness.REQUEST_MIX]

    assert sum(weights) == 100
    assert all(weight > 0 for weight in weights)
    assert len({name for _weight, name, _action in harness.REQUEST_MIX}) == len(
        harness.REQUEST_MIX
    )
    for _weight, _name, action in harness.REQUEST_MIX:
        assert action["type"] in {"respond", "tool_call"}
