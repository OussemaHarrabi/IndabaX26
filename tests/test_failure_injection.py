"""Failure injection: a broken dependency must not become a broken decision (M3).

Each test asserts the documented behaviour and then that the process is still
healthy: a following request succeeds, ``/healthz`` answers, and nothing the
boundary promised (fail-closed, no partial receipt) is silently relaxed.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from importlib import import_module
from typing import Any

import pytest
from aegisgraph import telemetry
from aegisgraph.access import store_dependency
from aegisgraph.auth import AUTHENTICATION_REQUIRED
from aegisgraph.settings import load_settings
from aegisgraph.store import MemoryStore
from fastapi.testclient import TestClient
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

app_module = import_module("aegisgraph.app")
client = TestClient(app_module.app)

TENANT = "development"


def _body(action: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "api_version": "aegisgraph/v1",
        "run_id": "failure-injection",
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


class _ReceiptStoreDown(MemoryStore):
    """A durable store that refuses every write, like a database that went away."""

    durable = True

    def store_receipt(self, record: Any) -> Any:
        raise RuntimeError("the connection to the receipt store was refused")


class _SlowStore(MemoryStore):
    """A store that pauses inside a write, so a burst overlaps in flight."""

    def store_receipt(self, record: Any) -> Any:
        time.sleep(0.002)
        return super().store_receipt(record)


@pytest.fixture(autouse=True)
def _isolated_facade() -> Iterator[None]:
    yield
    telemetry.reset_telemetry()


@pytest.fixture
def captured() -> Iterator[telemetry.Telemetry]:
    exporter = InMemorySpanExporter()
    instance = telemetry.build_telemetry(
        load_settings({"AEGISGRAPH_TELEMETRY_ENABLED": "true", "AEGISGRAPH_OTEL_ENDPOINT": "http://c:4318"}),
        exporter=exporter,
    )
    telemetry.install_telemetry(instance)
    yield instance


@pytest.fixture
def overridden() -> Iterator[Any]:
    """Override the store dependency and restore the app afterwards."""

    def install(store: Any) -> Any:
        app_module.app.dependency_overrides[store_dependency] = lambda: store
        return store

    try:
        yield install
    finally:
        app_module.app.dependency_overrides.pop(store_dependency, None)


def test_a_decision_is_not_returned_as_if_persisted_when_the_store_is_down(
    overridden: Any, captured: telemetry.Telemetry
) -> None:
    store = overridden(_ReceiptStoreDown())

    response = client.post("/api/v1/decisions", json=_body(SAFE))

    assert response.status_code == 503
    assert response.json() == {
        "detail": "the durable receipt store is unavailable",
        "code": "RECEIPT_STORE_UNAVAILABLE",
    }
    # Fail-closed: no verdict, no receipt identity, nothing a client could act on.
    assert "decision" not in response.json()
    assert "receipt_id" not in response.json()
    assert store.list_receipts(TENANT, limit=10)[0] == []
    assert captured.sample(
        telemetry.RECEIPT_FAILURE_COUNTER, reason="RECEIPT_STORE_UNAVAILABLE"
    ) == 1.0

    # The process is healthy afterwards and the same request still decides normally.
    assert client.get("/healthz").status_code == 200
    app_module.app.dependency_overrides.pop(store_dependency, None)
    recovered = client.post("/api/v1/decisions", json=_body(SAFE))
    assert recovered.status_code == 200
    assert recovered.json()["decision"] == "allow"
    assert recovered.json()["reason_codes"] == ["BENIGN_ACTION"]


def test_a_duplicate_request_id_for_another_action_is_refused_and_counted(
    overridden: Any, captured: telemetry.Telemetry
) -> None:
    overridden(MemoryStore())
    first = client.post(
        "/api/v1/decisions", json=_body(SAFE, request_id="conflicting-request")
    )
    second = client.post(
        "/api/v1/decisions",
        json=_body({"type": "respond", "content": "Different"}, request_id="conflicting-request"),
    )

    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["code"] == "REQUEST_ID_CONFLICT"
    assert captured.sample(telemetry.RECEIPT_FAILURE_COUNTER, reason="REQUEST_ID_CONFLICT") == 1.0
    assert client.get("/healthz").status_code == 200


def test_a_client_cancellation_mid_request_is_not_converted_into_a_decision(
    overridden: Any, caplog: pytest.LogCaptureFixture
) -> None:
    class _Cancelled(MemoryStore):
        """Cancellation delivered at the persistence await point, as uvicorn does."""

        def store_receipt(self, record: Any) -> Any:
            raise asyncio.CancelledError

    store = overridden(_Cancelled())

    # A cancelled request is abandoned: the transport sees no decision at all.
    # The framework reports the missing response as ``No response returned``
    # rather than surfacing the cancellation, and the boundary logs the exception
    # type without any request content.
    with (
        caplog.at_level("INFO", logger="aegisgraph.decision"),
        pytest.raises(RuntimeError, match="No response returned"),
    ):
        client.post("/api/v1/decisions", json=_body(SAFE))

    # Nothing half-written, nothing fabricated, nothing logged as a decision.
    assert store.list_receipts(TENANT, limit=10)[0] == []
    assert [record for record in caplog.records if record.name == "aegisgraph.decision"] == []
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 200
    app_module.app.dependency_overrides.pop(store_dependency, None)
    assert client.post("/api/v1/decisions", json=_body(SAFE)).status_code == 200


def test_an_overload_spike_is_served_without_an_error_and_leaves_the_service_healthy(
    overridden: Any,
) -> None:
    overridden(_SlowStore())
    workers, per_worker = 4, 16

    def hammer(index: int) -> list[int]:
        local = TestClient(app_module.app)
        action = SAFE if index % 2 == 0 else {
            "type": "tool_call",
            "tool": "email_send",
            "arguments": {"to": "a@b.test"},
        }
        return [
            local.post(
                "/api/v1/decisions", json=_body(action, run_id=f"spike-{index}-{n}")
            ).status_code
            for n in range(per_worker)
        ]

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        statuses = [status for batch in pool.map(hammer, range(workers)) for status in batch]
    elapsed = time.perf_counter() - started

    assert len(statuses) == workers * per_worker
    assert set(statuses) == {200}, f"spike produced non-200 responses: {sorted(set(statuses))}"
    assert elapsed < 30.0
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 200
    app_module.app.dependency_overrides.pop(store_dependency, None)
    assert client.post("/api/v1/decisions", json=_body(SAFE)).status_code == 200


def test_the_body_bound_still_holds_while_the_store_is_slow(overridden: Any) -> None:
    overridden(_SlowStore())

    response = client.post(
        "/api/v1/decisions",
        content=b"{" + b"a" * (1_048_576 + 16),
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert client.get("/healthz").status_code == 200


def test_a_burst_of_authentication_refusals_leaves_the_service_healthy(
    monkeypatch: pytest.MonkeyPatch, auth: Any, captured: telemetry.Telemetry
) -> None:
    def refuse(_index: int) -> int:
        with TestClient(app_module.app) as local:
            return local.post("/api/v1/decisions", json=_body(SAFE)).status_code

    with ThreadPoolExecutor(max_workers=4) as pool:
        statuses = list(pool.map(refuse, range(12)))

    assert set(statuses) == {401}
    assert captured.sample(telemetry.AUTH_FAILURE_COUNTER, reason=AUTHENTICATION_REQUIRED) == 12.0
    assert client.get("/healthz").status_code == 200


def test_the_failure_injection_harness_does_not_leak_a_thread() -> None:
    before = threading.active_count()
    with TestClient(app_module.app) as local:
        assert local.get("/healthz").status_code == 200
    assert threading.active_count() <= before
