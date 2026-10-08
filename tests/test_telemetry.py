"""Telemetry tests: the spans, the metric vocabulary and the label discipline (M3).

The spans are observed through an in-memory exporter injected into the same
batching provider the real OTLP exporter uses, so what these tests assert is what a
collector would receive. The metric vocabulary is asserted against the exposition
payload, so a label can only exist if it is declared and bounded.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from importlib import import_module
from typing import Any

import pytest
from aegisgraph import telemetry
from aegisgraph.settings import ConfigurationError, load_settings, safe_summary, validate_settings
from fastapi.testclient import TestClient
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

app_module = import_module("aegisgraph.app")
client = TestClient(app_module.app)

TELEMETRY_ENV = {
    "AEGISGRAPH_TELEMETRY_ENABLED": "true",
    "AEGISGRAPH_OTEL_ENDPOINT": "http://collector:4318",
}
CANARY = "CANARY-telemetry-must-not-carry-this"

_FAMILY_SUFFIXES = ("_total", "_created", "_bucket", "_count", "_sum", "_gauge")
_EXPOSITION_LINE = re.compile(r"^(?P<name>[a-z][a-z0-9_]*)(?P<labels>\{[^}]*\})?\s")


def _body(action: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "api_version": "aegisgraph/v1",
        "run_id": "telemetry-run",
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


@pytest.fixture(autouse=True)
def _isolated_facade() -> Iterator[None]:
    """Never leak an installed facade or its export thread into another test."""

    yield
    telemetry.reset_telemetry()


@pytest.fixture
def captured() -> Iterator[tuple[telemetry.Telemetry, InMemorySpanExporter]]:
    """Install a facade whose spans are collected in memory."""

    exporter = InMemorySpanExporter()
    instance = telemetry.build_telemetry(load_settings(TELEMETRY_ENV), exporter=exporter)
    telemetry.install_telemetry(instance)
    yield instance, exporter


def _exposition(instance: telemetry.Telemetry) -> str:
    return instance.render_metrics().decode("utf-8")


def _label_names(labels: str) -> set[str]:
    return set(re.findall(r"([a-zA-Z_][a-zA-Z0-9_]*)=", labels))


def _family(name: str) -> str:
    for suffix in _FAMILY_SUFFIXES:
        if not name.endswith(suffix):
            continue
        base = name[: -len(suffix)]
        if base in telemetry.METRIC_LABELS:
            return base
        if f"{base}_total" in telemetry.METRIC_LABELS:
            return f"{base}_total"
    return name


def test_a_decision_emits_the_four_phase_spans_and_the_root_span(
    captured: tuple[telemetry.Telemetry, InMemorySpanExporter],
) -> None:
    instance, exporter = captured

    response = client.post(
        "/api/v1/decisions", json=_body({"type": "respond", "content": "Done"})
    )

    assert response.status_code == 200
    assert instance.flush()
    spans = {span.name: span for span in exporter.get_finished_spans()}
    assert set(spans) == {
        telemetry.SPAN_DECISION,
        telemetry.SPAN_NORMALISE,
        telemetry.SPAN_EVALUATE,
        telemetry.SPAN_PERSIST,
        telemetry.SPAN_RESPOND,
    }
    root = spans[telemetry.SPAN_DECISION]
    assert root.attributes is not None
    assert root.attributes[telemetry.ATTR_ROUTE] == "/api/v1/decisions"
    assert root.attributes[telemetry.ATTR_VERDICT] == "allow"
    # The policy identity is resolved server-side (H2-02, H3-04), so telemetry must
    # mirror whatever identity the decision actually carried.
    identity = response.json()["policy_set"]
    assert root.attributes[telemetry.ATTR_POLICY_SET_ID] == identity["id"]
    assert root.attributes[telemetry.ATTR_POLICY_SET_VERSION] == identity["version"]
    assert root.attributes[telemetry.ATTR_RECEIPT_STORE_OUTCOME] == telemetry.OUTCOME_STORED
    assert float(root.attributes[telemetry.ATTR_LATENCY_MS]) > 0.0
    persisted = spans[telemetry.SPAN_PERSIST].attributes
    assert persisted is not None
    assert persisted[telemetry.ATTR_RECEIPT_STORE_OUTCOME] == telemetry.OUTCOME_STORED


def test_every_span_attribute_is_declared_for_that_span(
    captured: tuple[telemetry.Telemetry, InMemorySpanExporter],
) -> None:
    instance, exporter = captured

    client.post("/api/v1/decisions", json=_body({"type": "respond", "content": "Done"}))
    client.post(
        "/api/v1/decisions",
        json=_body({"type": "tool_call", "tool": "email_send", "arguments": {"to": "a@b.test"}}),
    )

    instance.flush()
    spans = exporter.get_finished_spans()
    assert spans
    for span in spans:
        declared = telemetry.SPAN_ATTRIBUTES[span.name]
        assert set(span.attributes or {}) <= declared
        assert set(span.attributes or {}) & telemetry.CONTENT_NAMES == set()


def test_duplicate_request_id_reports_the_duplicate_receipt_outcome(
    captured: tuple[telemetry.Telemetry, InMemorySpanExporter],
) -> None:
    instance, exporter = captured
    body = _body({"type": "respond", "content": "Done"}, request_id="fixed-request-id")

    first = client.post("/api/v1/decisions", json=body)
    second = client.post("/api/v1/decisions", json=body)

    assert first.status_code == second.status_code == 200
    assert second.json()["receipt_id"] == first.json()["receipt_id"]
    instance.flush()
    outcomes = [
        span.attributes[telemetry.ATTR_RECEIPT_STORE_OUTCOME]
        for span in exporter.get_finished_spans()
        if span.name == telemetry.SPAN_PERSIST
    ]
    assert outcomes == [telemetry.OUTCOME_STORED, telemetry.OUTCOME_DUPLICATE]


def test_content_never_reaches_a_span_attribute_or_a_metric_label(
    captured: tuple[telemetry.Telemetry, InMemorySpanExporter],
) -> None:
    instance, exporter = captured

    response = client.post(
        "/api/v1/decisions",
        json=_body(
            {"type": "respond", "content": CANARY},
            run_id=CANARY,
            user_goal=CANARY,
            request_id="canary-request",
        ),
    )

    assert response.status_code == 200
    assert CANARY not in response.text
    instance.flush()
    for span in exporter.get_finished_spans():
        assert CANARY not in span.name
        for key, value in (span.attributes or {}).items():
            assert CANARY not in f"{key}={value}"
        assert CANARY not in repr([(event.name, event.attributes) for event in span.events])
    assert CANARY not in _exposition(instance)
    for name, labels in telemetry.METRIC_LABELS.items():
        assert name not in telemetry.CONTENT_NAMES
        assert labels & telemetry.CONTENT_NAMES == set()
    for span_name, attributes in telemetry.SPAN_ATTRIBUTES.items():
        assert span_name not in telemetry.CONTENT_NAMES
        assert attributes & telemetry.CONTENT_NAMES == set()


def test_the_exposition_carries_only_declared_bounded_label_names(
    captured: tuple[telemetry.Telemetry, InMemorySpanExporter],
) -> None:
    instance, _exporter = captured

    client.post("/api/v1/decisions", json=_body({"type": "respond", "content": "Done"}))
    client.get("/healthz")
    client.get("/no/such/route")

    seen_families: set[str] = set()
    for line in _exposition(instance).splitlines():
        if line.startswith("# TYPE "):
            seen_families.add(_family(line.split()[2]))
            continue
        if line.startswith("#"):
            continue
        match = _EXPOSITION_LINE.match(line)
        if match is None:
            continue
        name = match.group("name")
        if not name.startswith(telemetry.METRIC_PREFIX):
            continue
        family = _family(name)
        seen_families.add(family)
        assert family in telemetry.METRIC_LABELS, f"undeclared metric {family}"
        labels = _label_names(match.group("labels") or "")
        labels.discard("le")  # synthetic histogram bucket bound, not a label we choose
        assert labels <= telemetry.METRIC_LABELS[family], f"{family} grew labels {labels}"
        assert labels & telemetry.CONTENT_NAMES == set()
    assert seen_families == set(telemetry.METRIC_LABELS)


def test_an_unmatched_route_becomes_one_bounded_label(
    captured: tuple[telemetry.Telemetry, InMemorySpanExporter],
) -> None:
    instance, _exporter = captured

    client.get("/no/such/route/1")
    client.get("/no/such/route/2")

    assert instance.sample(
        telemetry.REQUEST_COUNTER, route=telemetry.ROUTE_UNMATCHED, method="GET", status="404"
    ) == 2.0


def test_a_decision_records_the_verdict_and_the_latency_histogram(
    captured: tuple[telemetry.Telemetry, InMemorySpanExporter],
) -> None:
    instance, _exporter = captured

    allowed = client.post("/api/v1/decisions", json=_body({"type": "respond", "content": "Done"}))
    blocked = client.post(
        "/api/v1/decisions",
        json=_body({"type": "tool_call", "tool": "email_send", "arguments": {"to": "a@b.test"}}),
    )

    assert instance.sample(
        telemetry.DECISION_COUNTER,
        verdict="allow",
        policy_id=allowed.json()["policy_set"]["id"],
    ) == 1.0
    assert instance.sample(
        telemetry.DECISION_COUNTER,
        verdict="block",
        policy_id=blocked.json()["policy_set"]["id"],
    ) == 1.0
    assert instance.sample(f"{telemetry.DECISION_LATENCY}_count") == 2.0
    assert instance.sample(f"{telemetry.DECISION_LATENCY}_sum") > 0.0


def test_an_authentication_refusal_is_counted_by_bounded_reason(
    captured: tuple[telemetry.Telemetry, InMemorySpanExporter], auth: Any
) -> None:
    instance, _exporter = captured

    missing = client.post("/api/v1/decisions", json=_body({"type": "respond", "content": "Done"}))
    invalid = client.post(
        "/api/v1/decisions",
        json=_body({"type": "respond", "content": "Done"}),
        headers={"Authorization": f"Bearer {CANARY}"},
    )

    assert missing.status_code == 401
    assert invalid.status_code == 401
    assert instance.sample(
        telemetry.AUTH_FAILURE_COUNTER, reason="AUTHENTICATION_REQUIRED"
    ) == 1.0
    assert instance.sample(telemetry.AUTH_FAILURE_COUNTER, reason="INVALID_TOKEN") == 1.0
    assert CANARY not in _exposition(instance)


def test_metrics_are_enabled_in_development_and_opt_in_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AEGISGRAPH_ENV", raising=False)
    monkeypatch.delenv("AEGISGRAPH_METRICS_ENABLED", raising=False)
    assert client.get("/metrics").status_code == 200

    monkeypatch.setenv("AEGISGRAPH_ENV", "production")
    refused = client.get("/metrics")
    assert refused.status_code == 404
    assert refused.json()["detail"] == "Request could not be safely processed"

    monkeypatch.setenv("AEGISGRAPH_METRICS_ENABLED", "true")
    assert client.get("/metrics").status_code == 200
    assert client.get("/metrics").headers["content-type"].startswith("text/plain")


def test_the_metrics_scrape_does_not_count_itself(
    captured: tuple[telemetry.Telemetry, InMemorySpanExporter],
) -> None:
    instance, _exporter = captured

    for _ in range(3):
        assert client.get("/metrics").status_code == 200

    assert (
        instance.sample(
            telemetry.REQUEST_COUNTER, route="/metrics", method="GET", status="200"
        )
        == 0.0
    )


def test_settings_resolve_metrics_and_telemetry_without_leaking_the_endpoint() -> None:
    development = load_settings({})
    assert development.metrics_enabled is True
    assert development.telemetry_enabled is False
    assert development.telemetry_endpoint is None
    assert development.telemetry_service_name == "aegisgraph-api"
    assert development.telemetry_export_timeout_seconds == 2.0

    production = load_settings({"AEGISGRAPH_ENV": "production"})
    assert production.metrics_enabled is False
    assert load_settings(
        {"AEGISGRAPH_ENV": "production", "AEGISGRAPH_METRICS_ENABLED": "true"}
    ).metrics_enabled is True

    conventional = load_settings({"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4317"})
    assert conventional.telemetry_enabled is True
    assert conventional.telemetry_endpoint == "http://collector:4317"

    explicit = load_settings(
        {
            "AEGISGRAPH_OTEL_ENDPOINT": "https://otlp.example/",
            "AEGISGRAPH_OTEL_EXPORT_TIMEOUT_SECONDS": "0.25",
        }
    )
    assert explicit.telemetry_endpoint == "https://otlp.example"
    assert explicit.telemetry_export_timeout_seconds == 0.25

    disabled = load_settings(
        {
            "OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4318",
            "AEGISGRAPH_TELEMETRY_ENABLED": "false",
        }
    )
    assert disabled.telemetry_enabled is False

    summary = safe_summary(explicit)
    assert summary["telemetry_endpoint_configured"] is True
    assert "https://otlp.example" not in str(summary)


def test_a_non_http_telemetry_endpoint_is_refused() -> None:
    settings = load_settings({"OTEL_EXPORTER_OTLP_ENDPOINT": "grpc://collector:4317"})

    assert settings.telemetry_endpoint is None
    with pytest.raises(ConfigurationError) as error:
        validate_settings(settings)

    assert "OTLP/HTTP" in str(error.value)


def test_the_otlp_http_endpoint_is_derived_deterministically() -> None:
    assert (
        telemetry.otlp_http_trace_endpoint("http://otel-collector:4317")
        == "http://otel-collector:4318/v1/traces"
    )
    assert (
        telemetry.otlp_http_trace_endpoint("http://collector:4318/v1/traces")
        == "http://collector:4318/v1/traces"
    )
    assert (
        telemetry.otlp_http_trace_endpoint("https://otlp.example/base/")
        == "https://otlp.example/base/v1/traces"
    )


def test_the_process_facade_is_rebuilt_only_when_the_configuration_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AEGISGRAPH_METRICS_ENABLED", raising=False)
    first = telemetry.get_telemetry()
    assert telemetry.get_telemetry() is first

    monkeypatch.setenv("AEGISGRAPH_METRICS_ENABLED", "false")
    second = telemetry.get_telemetry()

    assert second is not first
    assert second.metrics_enabled is False


def test_a_broken_metric_or_span_never_reaches_the_caller(
    captured: tuple[telemetry.Telemetry, InMemorySpanExporter],
) -> None:
    instance, _exporter = captured

    class _Exploding:
        def labels(self, **_labels: str) -> Any:
            raise RuntimeError("registry is broken")

    instance.requests = _Exploding()  # type: ignore[assignment]
    instance.registry = _Exploding()  # type: ignore[assignment]

    instance.record_request("/api/v1/decisions", "POST", 200)
    instance.record_decision(verdict="allow", policy_id="p", latency_seconds=0.001)
    instance.record_auth_failure("INVALID_TOKEN")
    instance.record_receipt_failure("RECEIPT_STORE_UNAVAILABLE")
    instance.record_export_failure("traces")
    assert instance.render_metrics() == b""
    assert instance.sample(telemetry.REQUEST_COUNTER) == 0.0

    ran = False
    with instance.span(telemetry.SPAN_DECISION) as span:
        ran = True
        span.set_attribute(telemetry.ATTR_VERDICT, "allow")
    assert ran is True


def test_a_failing_span_body_propagates_without_recording_its_message(
    captured: tuple[telemetry.Telemetry, InMemorySpanExporter],
) -> None:
    instance, exporter = captured

    with pytest.raises(ValueError, match=CANARY), telemetry.span(telemetry.SPAN_EVALUATE):
        raise ValueError(CANARY)

    instance.flush()
    (span,) = exporter.get_finished_spans()
    assert span.events == ()
    assert CANARY not in repr(span.status)
    assert span.status.status_code.name == "ERROR"
