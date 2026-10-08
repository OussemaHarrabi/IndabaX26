"""Traces, metrics and export-failure accounting for the AegisGraph service (M3).

Three rules shape this module, and all of them are enforced here rather than at the
call sites:

1. **Telemetry is never a dependency of a decision.** Every span, metric write and
   exporter call is wrapped: a missing collector, an unreachable exporter or a
   broken registry cannot change a verdict, raise into a request, or delay one
   beyond the configured export timeout. Spans are queued by the SDK's
   :class:`~opentelemetry.sdk.trace.export.BatchSpanProcessor` and exported on a
   background thread, so the request path only appends to an in-memory queue.
2. **A batch export that fails is counted, not raised.** The OTLP exporter is
   wrapped by :class:`_CountingSpanExporter`, which turns a failure into
   ``aegisgraph_telemetry_export_failures_total{signal="traces"}``.
3. **No content in labels or attributes.** Only the attribute and label names
   declared in :data:`SPAN_ATTRIBUTES` and :data:`METRIC_LABELS` are ever emitted.
   There is no tenant, principal, request id, receipt id, URL, action content or
   credential value anywhere in the telemetry surface; :data:`CONTENT_NAMES` is the
   denylist the test suite enforces against those two declarations.

Nothing here executes a candidate action; it only observes a decision.
"""

from __future__ import annotations

import logging
import sys
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Final

from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
    OTLPSpanExporter,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SpanExporter,
    SpanExportResult,
)
from opentelemetry.trace import Tracer
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
)

from aegisgraph.settings import Settings, load_settings

_LOGGER = logging.getLogger("aegisgraph.telemetry")

METRIC_PREFIX: Final[str] = "aegisgraph"

# --- Metric and attribute names ------------------------------------------------
# These two mappings are the whole vocabulary of the telemetry surface.

REQUEST_COUNTER: Final[str] = f"{METRIC_PREFIX}_requests_total"
DECISION_COUNTER: Final[str] = f"{METRIC_PREFIX}_decisions_total"
DECISION_LATENCY: Final[str] = f"{METRIC_PREFIX}_decision_latency_seconds"
AUTH_FAILURE_COUNTER: Final[str] = f"{METRIC_PREFIX}_auth_failures_total"
RECEIPT_FAILURE_COUNTER: Final[str] = f"{METRIC_PREFIX}_receipt_store_failures_total"
EXPORT_FAILURE_COUNTER: Final[str] = f"{METRIC_PREFIX}_telemetry_export_failures_total"

SPAN_DECISION: Final[str] = f"{METRIC_PREFIX}.decision"
SPAN_NORMALISE: Final[str] = f"{METRIC_PREFIX}.decision.normalise"
SPAN_EVALUATE: Final[str] = f"{METRIC_PREFIX}.decision.evaluate"
SPAN_PERSIST: Final[str] = f"{METRIC_PREFIX}.decision.persist_receipt"
SPAN_RESPOND: Final[str] = f"{METRIC_PREFIX}.decision.respond"

ATTR_ROUTE: Final[str] = f"{METRIC_PREFIX}.route"
ATTR_VERDICT: Final[str] = f"{METRIC_PREFIX}.verdict"
ATTR_POLICY_SET_ID: Final[str] = f"{METRIC_PREFIX}.policy_set.id"
ATTR_POLICY_SET_VERSION: Final[str] = f"{METRIC_PREFIX}.policy_set.version"
ATTR_RECEIPT_STORE_OUTCOME: Final[str] = f"{METRIC_PREFIX}.receipt_store.outcome"
ATTR_LATENCY_MS: Final[str] = f"{METRIC_PREFIX}.latency_ms"

ROUTE_UNMATCHED: Final[str] = "unmatched"
"""Route label for a request that matched no route (a 404, or a body-limit refusal)."""

OUTCOME_STORED: Final[str] = "stored"
OUTCOME_DUPLICATE: Final[str] = "duplicate"
OUTCOME_UNAVAILABLE: Final[str] = "unavailable"
OUTCOME_CONFLICT: Final[str] = "conflict"

SIGNAL_TRACES: Final[str] = "traces"

SPAN_ATTRIBUTES: Final[Mapping[str, frozenset[str]]] = {
    SPAN_DECISION: frozenset(
        {
            ATTR_ROUTE,
            ATTR_VERDICT,
            ATTR_POLICY_SET_ID,
            ATTR_POLICY_SET_VERSION,
            ATTR_RECEIPT_STORE_OUTCOME,
            ATTR_LATENCY_MS,
        }
    ),
    SPAN_NORMALISE: frozenset({ATTR_ROUTE, ATTR_POLICY_SET_ID, ATTR_POLICY_SET_VERSION}),
    SPAN_EVALUATE: frozenset(
        {ATTR_ROUTE, ATTR_VERDICT, ATTR_POLICY_SET_ID, ATTR_POLICY_SET_VERSION}
    ),
    SPAN_PERSIST: frozenset({ATTR_ROUTE, ATTR_RECEIPT_STORE_OUTCOME}),
    SPAN_RESPOND: frozenset({ATTR_ROUTE, ATTR_LATENCY_MS}),
}
"""The complete set of span attribute names each span may carry (enforced by test)."""

METRIC_LABELS: Final[Mapping[str, frozenset[str]]] = {
    REQUEST_COUNTER: frozenset({"route", "method", "status"}),
    DECISION_COUNTER: frozenset({"verdict", "policy_id"}),
    DECISION_LATENCY: frozenset(),
    AUTH_FAILURE_COUNTER: frozenset({"reason"}),
    RECEIPT_FAILURE_COUNTER: frozenset({"reason"}),
    EXPORT_FAILURE_COUNTER: frozenset({"signal"}),
}
"""The complete label vocabulary; every label set is bounded (never per-request)."""

CONTENT_NAMES: Final[frozenset[str]] = frozenset(
    {
        "canary",
        "content",
        "credential",
        "email",
        "ip",
        "path",
        "payload",
        "principal",
        "principal_id",
        "query",
        "receipt_id",
        "request_id",
        "run_id",
        "secret",
        "session",
        "tenant",
        "tenant_id",
        "token",
        "trace_id",
        "span_id",
        "url",
        "user",
        "user_goal",
    }
)
"""Names that must never appear as a label or attribute name or as a value (M3)."""

DECISION_LATENCY_BUCKETS: Final[tuple[float, ...]] = (
    0.0005,
    0.001,
    0.0025,
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
)
"""Histogram buckets in seconds, centred on the latencies the local load test measured."""


def otlp_http_trace_endpoint(base_url: str) -> str:
    """Return the full OTLP/HTTP traces URL for a configured endpoint.

    ``OTEL_EXPORTER_OTLP_ENDPOINT`` conventionally names the collector's **gRPC**
    receiver (``:4317``), while the HTTP exporter must post to the collector's HTTP
    receiver (``:4318``). A well-known ``:4317`` port is therefore translated to its
    HTTP sibling; the service's own ``AEGISGRAPH_OTEL_ENDPOINT`` is an HTTP endpoint
    and passes through untouched apart from gaining the ``/v1/traces`` suffix.
    """

    endpoint = base_url.rstrip("/")
    if endpoint.endswith("/v1/traces"):
        return endpoint
    if endpoint.endswith(":4317"):
        endpoint = f"{endpoint[: -len('4317')]}4318"
    return f"{endpoint}/v1/traces"


class _SpanHandle:
    """A span that can be annotated but never raises at the caller."""

    __slots__ = ("_span",)

    def __init__(self, span: Any | None) -> None:
        self._span = span

    def set_attribute(self, key: str, value: str | bool | int | float) -> None:
        if self._span is None:
            return
        try:
            self._span.set_attribute(key, value)
        except Exception:  # pragma: no cover - telemetry must never break a decision
            _LOGGER.debug("span attribute refused", exc_info=True)


_NULL_SPAN = _SpanHandle(None)


@contextmanager
def _open_span(
    tracer: Tracer | None, name: str, attributes: Mapping[str, Any]
) -> Iterator[_SpanHandle]:
    """Yield a span handle; a broken tracer degrades to a no-op span.

    The body's exception is never swallowed: a failure in telemetry *around* the
    body falls back to :data:`_NULL_SPAN`, while an exception raised *by* the body
    propagates unchanged. ``record_exception=False`` keeps an exception message —
    which could echo request content — out of the span.
    """

    if tracer is None:
        yield _NULL_SPAN
        return
    try:
        manager = tracer.start_as_current_span(
            name,
            attributes=_safe_attributes(attributes),
            record_exception=False,
            set_status_on_exception=True,
        )
        span = manager.__enter__()
    except Exception:  # pragma: no cover - a tracer that cannot start a span
        _LOGGER.debug("span could not be started", exc_info=True)
        yield _NULL_SPAN
        return
    try:
        yield _SpanHandle(span)
    except BaseException:
        _exit_span(manager, sys.exc_info()[1])
        raise
    else:
        _exit_span(manager, None)


def _exit_span(manager: Any, error: BaseException | None) -> None:
    try:
        if error is None:
            manager.__exit__(None, None, None)
        else:
            manager.__exit__(type(error), error, error.__traceback__)
    except Exception:  # pragma: no cover - telemetry must never break a decision
        _LOGGER.debug("span could not be closed", exc_info=True)


def _safe_attributes(attributes: Mapping[str, Any]) -> dict[str, str | bool | int | float]:
    safe: dict[str, str | bool | int | float] = {}
    for key, value in attributes.items():
        if isinstance(value, (str, bool, int, float)):
            safe[key] = value
    return safe


class _CountingSpanExporter(SpanExporter):
    """Wrap the OTLP exporter so a failed export is counted instead of raised."""

    def __init__(self, inner: SpanExporter, on_failure: Callable[[], None]) -> None:
        self._inner = inner
        self._on_failure = on_failure

    def export(self, spans: Any) -> Any:
        try:
            result = self._inner.export(spans)
        except Exception:
            _LOGGER.debug("OTLP span export failed", exc_info=True)
            self._on_failure()
            return SpanExportResult.FAILURE
        if result is not SpanExportResult.SUCCESS:
            self._on_failure()
        return result

    def shutdown(self) -> None:
        try:
            self._inner.shutdown()
        except Exception:  # pragma: no cover - shutdown must never raise
            _LOGGER.debug("OTLP exporter shutdown failed", exc_info=True)

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        try:
            return bool(self._inner.force_flush(timeout_millis))
        except Exception:  # pragma: no cover - flush must never raise
            self._on_failure()
            return False


@dataclass(frozen=True)
class TelemetryState:
    """A settings-derived cache key, so a configuration change rebuilds the facade."""

    metrics_enabled: bool
    telemetry_enabled: bool
    telemetry_endpoint: str | None
    telemetry_service_name: str
    telemetry_export_timeout_seconds: float

    @classmethod
    def of(cls, settings: Settings) -> TelemetryState:
        return cls(
            metrics_enabled=settings.metrics_enabled,
            telemetry_enabled=settings.telemetry_enabled,
            telemetry_endpoint=settings.telemetry_endpoint,
            telemetry_service_name=settings.telemetry_service_name,
            telemetry_export_timeout_seconds=settings.telemetry_export_timeout_seconds,
        )


class Telemetry:
    """The process-wide telemetry facade: one private registry, one tracer.

    A fresh instance owns a fresh :class:`~prometheus_client.CollectorRegistry`, so
    two instances never collide on a metric name and a test can isolate its
    observations completely.
    """

    def __init__(
        self,
        *,
        metrics_enabled: bool,
        telemetry_enabled: bool,
        endpoint: str | None,
        service_name: str,
        export_timeout_seconds: float,
        exporter: Any | None = None,
    ) -> None:
        self.metrics_enabled = metrics_enabled
        self.telemetry_enabled = telemetry_enabled
        self.endpoint = endpoint
        self.registry = CollectorRegistry()
        self.requests = Counter(
            REQUEST_COUNTER,
            "HTTP requests handled, by route template, method and status.",
            ("route", "method", "status"),
            registry=self.registry,
        )
        self.decisions = Counter(
            DECISION_COUNTER,
            "Decisions returned, by verdict and policy set id.",
            ("verdict", "policy_id"),
            registry=self.registry,
        )
        self.decision_latency = Histogram(
            DECISION_LATENCY,
            "Wall-clock latency of a generic decision, in seconds.",
            registry=self.registry,
            buckets=DECISION_LATENCY_BUCKETS,
        )
        self.auth_failures = Counter(
            AUTH_FAILURE_COUNTER,
            "Authentication and authorization refusals, by bounded reason code.",
            ("reason",),
            registry=self.registry,
        )
        self.receipt_failures = Counter(
            RECEIPT_FAILURE_COUNTER,
            "Durable receipt-store failures, by bounded reason code.",
            ("reason",),
            registry=self.registry,
        )
        self.export_failures = Counter(
            EXPORT_FAILURE_COUNTER,
            "Telemetry exports that did not succeed, by signal.",
            ("signal",),
            registry=self.registry,
        )
        self._tracer: Tracer | None = None
        self._provider: TracerProvider | None = None
        if telemetry_enabled and (endpoint is not None or exporter is not None):
            self._tracer, self._provider = self._build_provider(
                endpoint=endpoint,
                service_name=service_name,
                export_timeout_seconds=export_timeout_seconds,
                exporter=exporter,
            )

    def _build_provider(
        self,
        *,
        endpoint: str | None,
        service_name: str,
        export_timeout_seconds: float,
        exporter: Any | None = None,
    ) -> tuple[Tracer | None, TracerProvider | None]:
        """Build the tracer provider; a provider that cannot be built is not fatal."""

        try:
            if exporter is None:
                exporter = OTLPSpanExporter(
                    endpoint=otlp_http_trace_endpoint(endpoint or ""),
                    timeout=export_timeout_seconds,
                )
            counting = _CountingSpanExporter(
                exporter, lambda: self.record_export_failure(SIGNAL_TRACES)
            )
            provider = TracerProvider(
                resource=Resource.create({"service.name": service_name})
            )
            provider.add_span_processor(
                BatchSpanProcessor(
                    counting,
                    max_queue_size=2048,
                    schedule_delay_millis=1000,
                    max_export_batch_size=256,
                )
            )
        except Exception:  # pragma: no cover - a provider that cannot be built
            _LOGGER.error("Tracing could not be configured; continuing without spans")
            return None, None
        return provider.get_tracer("aegisgraph"), provider

    @property
    def tracer(self) -> Tracer | None:
        return self._tracer

    @contextmanager
    def span(self, name: str, /, **attributes: str | bool | int | float) -> Iterator[_SpanHandle]:
        """Open a span, or a no-op handle when tracing is off or broken."""

        with _open_span(self._tracer, name, attributes) as handle:
            yield handle

    # --- Recording ------------------------------------------------------------
    # Every writer is wrapped: a broken registry must not reach a caller.

    def record_request(self, route: str, method: str, status: int) -> None:
        try:
            self.requests.labels(route=route, method=method, status=str(status)).inc()
        except Exception:  # pragma: no cover - telemetry must never break a request
            _LOGGER.debug("request metric refused", exc_info=True)

    def record_decision(self, *, verdict: str, policy_id: str, latency_seconds: float) -> None:
        try:
            self.decisions.labels(verdict=verdict, policy_id=policy_id).inc()
            self.decision_latency.observe(max(latency_seconds, 0.0))
        except Exception:  # pragma: no cover - telemetry must never break a decision
            _LOGGER.debug("decision metric refused", exc_info=True)

    def record_auth_failure(self, reason: str) -> None:
        try:
            self.auth_failures.labels(reason=reason).inc()
        except Exception:  # pragma: no cover - telemetry must never break a decision
            _LOGGER.debug("auth-failure metric refused", exc_info=True)

    def record_receipt_failure(self, reason: str) -> None:
        try:
            self.receipt_failures.labels(reason=reason).inc()
        except Exception:  # pragma: no cover - telemetry must never break a decision
            _LOGGER.debug("receipt-failure metric refused", exc_info=True)

    def record_export_failure(self, signal: str) -> None:
        try:
            self.export_failures.labels(signal=signal).inc()
        except Exception:  # pragma: no cover - telemetry must never break a decision
            _LOGGER.debug("export-failure metric refused", exc_info=True)

    # --- Reading (used by /metrics and by the tests) --------------------------

    def render_metrics(self) -> bytes:
        """Return the Prometheus exposition payload, or an empty body if it breaks."""

        try:
            return generate_latest(self.registry)
        except Exception:  # pragma: no cover - metrics must never break a scrape
            _LOGGER.error("metrics could not be rendered")
            return b""

    @property
    def content_type(self) -> str:
        return CONTENT_TYPE_LATEST

    def sample(self, name: str, **labels: str) -> float:
        """Return the current value of one series, or ``0.0`` when it is absent."""

        try:
            value = self.registry.get_sample_value(name, labels or None)
        except Exception:  # pragma: no cover - a registry that cannot be read
            return 0.0
        return float(value) if isinstance(value, (int, float)) else 0.0

    def export_failure_count(self, signal: str = SIGNAL_TRACES) -> float:
        """Return the current value of the export-failure series."""

        return self.sample(EXPORT_FAILURE_COUNTER, signal=signal)

    def flush(self, timeout_millis: int = 5_000) -> bool:
        """Flush queued spans; deliberately never called on a request path."""

        if self._provider is None:
            return True
        try:
            return bool(self._provider.force_flush(timeout_millis))
        except Exception:  # pragma: no cover - flush must never raise
            _LOGGER.debug("flush failed", exc_info=True)
            return False

    def shutdown(self, timeout_millis: int = 5_000) -> None:
        """Flush and stop the export thread (process shutdown, or a rebuilt facade)."""

        self.flush(timeout_millis)
        if self._provider is None:
            return
        try:
            self._provider.shutdown()
        except Exception:  # pragma: no cover - shutdown must never raise
            _LOGGER.debug("provider shutdown failed", exc_info=True)


def build_telemetry(settings: Settings, *, exporter: Any | None = None) -> Telemetry:
    """Build an isolated facade from a validated configuration (no global state).

    ``exporter`` is the test seam: an in-memory exporter can be injected so a test
    observes exactly the spans a decision produced, with the same batching and
    counting wrapper the real OTLP exporter goes through.
    """

    return Telemetry(
        metrics_enabled=settings.metrics_enabled,
        telemetry_enabled=settings.telemetry_enabled,
        endpoint=settings.telemetry_endpoint,
        service_name=settings.telemetry_service_name,
        export_timeout_seconds=settings.telemetry_export_timeout_seconds,
        exporter=exporter,
    )


_TELEMETRY: Telemetry | None = None
_TELEMETRY_STATE: TelemetryState | None = None
_TELEMETRY_INJECTED: Telemetry | None = None
_TELEMETRY_LOCK = threading.Lock()


def install_telemetry(instance: Telemetry) -> None:
    """Serve ``instance`` as the process facade until :func:`reset_telemetry`.

    The application boundary never calls this: it exists so a test can observe the
    spans and counters the real request path emits, without a collector.
    """

    global _TELEMETRY_INJECTED
    with _TELEMETRY_LOCK:
        _TELEMETRY_INJECTED = instance


def get_telemetry() -> Telemetry:
    """Return the process facade, rebuilding it when the configuration changed."""

    global _TELEMETRY, _TELEMETRY_STATE
    injected = _TELEMETRY_INJECTED
    if injected is not None:
        return injected
    settings = load_settings()
    state = TelemetryState.of(settings)
    with _TELEMETRY_LOCK:
        current = _TELEMETRY
        if current is not None and state == _TELEMETRY_STATE:
            return current
        _TELEMETRY = build_telemetry(settings)
        _TELEMETRY_STATE = state
        rebuilt = _TELEMETRY
    if current is not None:
        current.shutdown()
    return rebuilt


def reset_telemetry() -> None:
    """Drop the process facade, including any injected one (tests, shutdown)."""

    global _TELEMETRY, _TELEMETRY_STATE, _TELEMETRY_INJECTED
    with _TELEMETRY_LOCK:
        current = _TELEMETRY
        injected = _TELEMETRY_INJECTED
        _TELEMETRY = None
        _TELEMETRY_STATE = None
        _TELEMETRY_INJECTED = None
    if current is not None:
        current.shutdown()
    if injected is not None and injected is not current:
        injected.shutdown()


@contextmanager
def span(name: str, /, **attributes: str | bool | int | float) -> Iterator[_SpanHandle]:
    """Open a span on the process facade for the duration of a block."""

    with get_telemetry().span(name, **attributes) as handle:
        yield handle


def record_request(route: str, method: str, status: int) -> None:
    get_telemetry().record_request(route, method, status)


def record_decision(*, verdict: str, policy_id: str, latency_seconds: float) -> None:
    get_telemetry().record_decision(
        verdict=verdict, policy_id=policy_id, latency_seconds=latency_seconds
    )


def record_auth_failure(reason: str) -> None:
    get_telemetry().record_auth_failure(reason)


def record_receipt_failure(reason: str) -> None:
    get_telemetry().record_receipt_failure(reason)


def render_metrics() -> bytes:
    return get_telemetry().render_metrics()


def metrics_enabled() -> bool:
    return get_telemetry().metrics_enabled


def metrics_content_type() -> str:
    return get_telemetry().content_type


__all__ = [
    "ATTR_LATENCY_MS",
    "ATTR_POLICY_SET_ID",
    "ATTR_POLICY_SET_VERSION",
    "ATTR_RECEIPT_STORE_OUTCOME",
    "ATTR_ROUTE",
    "ATTR_VERDICT",
    "AUTH_FAILURE_COUNTER",
    "CONTENT_NAMES",
    "DECISION_COUNTER",
    "DECISION_LATENCY",
    "DECISION_LATENCY_BUCKETS",
    "EXPORT_FAILURE_COUNTER",
    "METRIC_LABELS",
    "METRIC_PREFIX",
    "OUTCOME_CONFLICT",
    "OUTCOME_DUPLICATE",
    "OUTCOME_STORED",
    "OUTCOME_UNAVAILABLE",
    "RECEIPT_FAILURE_COUNTER",
    "REQUEST_COUNTER",
    "ROUTE_UNMATCHED",
    "SIGNAL_TRACES",
    "SPAN_ATTRIBUTES",
    "SPAN_DECISION",
    "SPAN_EVALUATE",
    "SPAN_NORMALISE",
    "SPAN_PERSIST",
    "SPAN_RESPOND",
    "Telemetry",
    "TelemetryState",
    "build_telemetry",
    "get_telemetry",
    "install_telemetry",
    "metrics_content_type",
    "metrics_enabled",
    "otlp_http_trace_endpoint",
    "record_auth_failure",
    "record_decision",
    "record_receipt_failure",
    "record_request",
    "render_metrics",
    "reset_telemetry",
    "span",
]
