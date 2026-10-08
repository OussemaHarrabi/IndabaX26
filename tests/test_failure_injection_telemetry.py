"""Failure injection for telemetry and health semantics (M3).

The two invariants under test:

* a missing or unreachable collector changes neither the decision nor its latency;
* ``/healthz`` stays liveness and ``/readyz`` stays dependency readiness when the
  database or the collector is unavailable.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from importlib import import_module
from typing import Any

import pytest
from aegisgraph import telemetry
from aegisgraph.settings import load_settings
from fastapi.testclient import TestClient

app_module = import_module("aegisgraph.app")
client = TestClient(app_module.app)

REFUSED_ENDPOINT = "http://127.0.0.1:1"
BLACK_HOLE_ENDPOINT = "http://10.255.255.1:4318"
UNREACHABLE_DATABASE = (
    "postgresql+psycopg://nobody:nothing@127.0.0.1:1/aegisgraph?connect_timeout=1"
)


def _body(action: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "api_version": "aegisgraph/v1",
        "run_id": "telemetry-failure-injection",
        "step_id": 1,
        "user_goal": "Perform the requested safe task",
        "conversation": [],
        "candidate_action": action,
        "policy_context": {
            "policy_id": "test-policy",
            "policy_version": "1",
            "allowed_tools": ["document_search"],
            "confirmation_required_tools": [],
            "consequential_tools": [],
        },
        "history_digest": {"confirmations_granted": []},
    }
    payload.update(overrides)
    return payload


SAFE = {"type": "respond", "content": "Done"}


@pytest.fixture(autouse=True)
def _isolated_facade() -> Iterator[None]:
    yield
    telemetry.reset_telemetry()


def _decide(instance: telemetry.Telemetry, **overrides: Any) -> dict[str, Any]:
    telemetry.install_telemetry(instance)
    response = client.post("/api/v1/decisions", json=_body(SAFE, **overrides))
    assert response.status_code == 200
    return response.json()


def test_no_provider_or_export_thread_exists_without_a_configured_endpoint() -> None:
    instance = telemetry.build_telemetry(load_settings({}))

    assert instance.telemetry_enabled is False
    assert instance.tracer is None
    assert instance.export_failure_count() == 0.0


def test_an_unreachable_collector_neither_changes_nor_slows_a_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = _decide(telemetry.build_telemetry(load_settings({})), run_id="baseline")

    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", BLACK_HOLE_ENDPOINT)
    monkeypatch.setenv("AEGISGRAPH_OTEL_EXPORT_TIMEOUT_SECONDS", "0.5")
    instance = telemetry.build_telemetry(load_settings())

    telemetry.install_telemetry(instance)
    warm_up = client.post("/api/v1/decisions", json=_body(SAFE, run_id="warm-up"))

    started = time.perf_counter()
    response = client.post("/api/v1/decisions", json=_body(SAFE, run_id="under-test"))
    elapsed = time.perf_counter() - started

    assert warm_up.status_code == response.status_code == 200
    assert elapsed < 0.25, f"the decision waited on the exporter for {elapsed:.3f}s"
    decided = response.json()
    for field in ("decision", "risk_score", "confidence", "reason_codes", "explanation"):
        assert decided[field] == baseline[field]

    assert instance.flush(timeout_millis=2_000)
    assert instance.export_failure_count() >= 1.0

    assert client.get("/healthz").status_code == 200
    assert client.post("/api/v1/decisions", json=_body(SAFE, run_id="after")).status_code == 200


def test_a_refused_collector_is_counted_and_survivable() -> None:
    instance = telemetry.build_telemetry(
        load_settings(
            {
                "AEGISGRAPH_OTEL_ENDPOINT": REFUSED_ENDPOINT,
                "AEGISGRAPH_OTEL_EXPORT_TIMEOUT_SECONDS": "0.5",
            }
        )
    )
    telemetry.install_telemetry(instance)

    assert client.post("/api/v1/decisions", json=_body(SAFE)).status_code == 200
    assert instance.flush(timeout_millis=2_000)

    assert instance.export_failure_count() >= 1.0
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 200


def test_readiness_is_liveness_plus_the_receipt_store_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    healthy = client.get("/readyz")
    assert healthy.status_code == 200
    assert healthy.json()["dependencies"]["receipt_store"]["reachable"] is True
    # Readiness is about serving traffic: the insecurity warnings (authentication is
    # off in this configuration) must not make a working process unready (H4-09).
    assert healthy.json()["ready"] is True
    assert healthy.json()["insecure"] is True

    # Collector down: no effect on either probe; telemetry is not a dependency.
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", REFUSED_ENDPOINT)
    monkeypatch.setenv("AEGISGRAPH_OTEL_EXPORT_TIMEOUT_SECONDS", "0.25")
    collector_down = client.get("/readyz")
    assert collector_down.status_code == 200
    assert client.get("/healthz").status_code == 200

    # Database down: readiness degrades (`503`), liveness stays `200`.
    monkeypatch.setenv("DATABASE_URL", UNREACHABLE_DATABASE)
    database_down = client.get("/readyz")
    assert database_down.status_code == 503
    assert database_down.json()["status"] == "degraded"
    assert database_down.json()["dependencies"]["receipt_store"]["reachable"] is False
    assert database_down.json()["dependencies"]["receipt_store"]["durable"] is True
    assert client.get("/healthz").status_code == 200

    # Both down: the database is the dependency that matters, liveness unchanged.
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", BLACK_HOLE_ENDPOINT)
    both_down = client.get("/readyz")
    assert both_down.status_code == 503
    assert client.get("/healthz").status_code == 200
