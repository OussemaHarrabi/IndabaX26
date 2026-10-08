# Observability: traces, metrics and health semantics

Owner: Agent D (observability, performance, reliability). Files:
`backend/aegisgraph/telemetry.py`, the instrumentation hooks in
`backend/aegisgraph/app.py` and `backend/aegisgraph/api_v1.py`, the settings in
`backend/aegisgraph/settings.py`, `deploy/observability/**`,
`scripts/load_test.py`, `tests/test_telemetry*.py`,
`tests/test_failure_injection*.py`.

The governing rule for this whole surface: **telemetry is never a dependency of a
decision**. A missing collector, an unreachable exporter, a broken metric registry
or a cancelled scrape cannot change a verdict, raise into a request, or delay a
request beyond the configured export timeout.

## What the service emits

### Traces (OTLP/HTTP)

One trace per generic decision, emitted by `aegisgraph/api_v1.py`. Span names and
the *only* attributes each span may carry:

| Span | Attributes | Set when |
| --- | --- | --- |
| `aegisgraph.decision` | route, verdict, policy set id, policy set version, receipt-store outcome, latency | root span, closed after the response is built |
| `aegisgraph.decision.normalise` | route, policy set id, policy set version | after trust-ceiling, policy resolution, confirmation authorization and identity construction |
| `aegisgraph.decision.evaluate` | route, verdict, policy set id, policy set version | around `engine.evaluate` and the response conversion, including the response-size guard |
| `aegisgraph.decision.persist_receipt` | route, receipt-store outcome | around the durable receipt write |
| `aegisgraph.decision.respond` | route, latency | around refusal recording, the structured decision record and the final encode |

Attribute names: `aegisgraph.route`, `aegisgraph.verdict`,
`aegisgraph.policy_set.id`, `aegisgraph.policy_set.version`,
`aegisgraph.receipt_store.outcome` (`stored` | `duplicate` | `unavailable` |
`conflict`), `aegisgraph.latency_ms`.

`record_exception=False` is set deliberately: an exception message can echo request
content, so a failure marks the span `ERROR` without attaching the exception. The
declared vocabulary lives in `telemetry.SPAN_ATTRIBUTES`, and
`tests/test_telemetry.py::test_every_span_attribute_is_declared_for_that_span`
asserts that no span carries anything else.

### Metrics (Prometheus, pull)

| Metric | Labels | Meaning |
| --- | --- | --- |
| `aegisgraph_requests_total` | `route`, `method`, `status` | every handled request; `route` is the matched **route template** (`unmatched` for a 404 or a body-limit refusal), never the concrete path |
| `aegisgraph_decisions_total` | `verdict`, `policy_id` | decisions returned, by verdict and policy set id |
| `aegisgraph_decision_latency_seconds` | – | histogram of the in-process decision latency |
| `aegisgraph_auth_failures_total` | `reason` | authentication/authorization refusals by bounded reason code (`AUTHENTICATION_REQUIRED`, `INVALID_TOKEN`, `TOKEN_EXPIRED`, `INSUFFICIENT_SCOPE`, `TRUST_CEILING_EXCEEDED`, `TENANT_MISMATCH`, `AUTHENTICATION_UNAVAILABLE`) |
| `aegisgraph_receipt_store_failures_total` | `reason` | `RECEIPT_STORE_UNAVAILABLE`, `REQUEST_ID_CONFLICT` |
| `aegisgraph_telemetry_export_failures_total` | `signal` | `traces`: a batch export that did not succeed |

The histogram buckets are
`0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5`
seconds — centred on the latencies the local load test measured (p50 1.6 ms,
p95 3.1 ms, p99 5.2 ms).

### No content, no identity

There is no tenant, principal, request id, receipt id, run id, URL, action content
or credential label anywhere. `telemetry.METRIC_LABELS` and
`telemetry.SPAN_ATTRIBUTES` are the complete vocabulary, and
`telemetry.CONTENT_NAMES` is the denylist the tests enforce:

* `tests/test_telemetry.py::test_the_exposition_carries_only_declared_bounded_label_names`
  parses the `/metrics` payload and fails if any family or label is undeclared;
* `tests/test_telemetry.py::test_content_never_reaches_a_span_attribute_or_a_metric_label`
  sends a canary string as the action content, the run id, the user goal and the
  request id, then asserts the canary appears in no span attribute, no span event
  and nowhere in the exposition.

Cardinality is bounded by construction: route templates, HTTP methods, status
codes, verdicts, operator-defined policy set ids and fixed reason codes. A caller
cannot inflate a series by sending different identifiers.

## Configuration

| Variable | Default | Effect |
| --- | --- | --- |
| `AEGISGRAPH_METRICS_ENABLED` | development: `true`; production: `false` | serves `GET /metrics`. In production it must be set to `true` explicitly. |
| `AEGISGRAPH_TELEMETRY_ENABLED` | on exactly when an endpoint is configured | builds the tracer provider and the export thread |
| `AEGISGRAPH_OTEL_ENDPOINT` | – | OTLP/HTTP base URL (the service's own variable, used verbatim) |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_EXPORTER_OTLP_ENDPOINT` | – | conventional fallbacks, so the Compose stack needs no duplicate configuration |
| `AEGISGRAPH_OTEL_SERVICE_NAME`, `OTEL_SERVICE_NAME` | `aegisgraph-api` | `service.name` resource attribute |
| `AEGISGRAPH_OTEL_EXPORT_TIMEOUT_SECONDS` | `2.0` | per-export timeout; a positive float, otherwise the default |

Endpoint resolution is deterministic (`telemetry.otlp_http_trace_endpoint`):
`OTEL_EXPORTER_OTLP_ENDPOINT` conventionally names the collector's **gRPC**
receiver (`:4317`), while the HTTP exporter must post to the HTTP receiver, so a
well-known `:4317` port is translated to `:4318` and `/v1/traces` is appended.
`http://otel-collector:4317` → `http://otel-collector:4318/v1/traces`;
`http://collector:4318/v1/traces` is left alone. A non-`http(s)` endpoint is a
configuration problem and `validate_settings` refuses to start.

Export is batched (`BatchSpanProcessor`, 1 s schedule, 256-span batches, 2048-span
queue) on the SDK's background thread, so a request only appends to an in-memory
queue. The exporter is wrapped by a counting adapter that turns a failed export
into `aegisgraph_telemetry_export_failures_total{signal="traces"}` instead of an
exception. Every metric write is wrapped as well; `tests/test_telemetry.py` proves
a registry that raises on every operation still lets a request through.

## `/metrics` is an internal surface

`GET /metrics` returns the Prometheus text exposition. It is **not** a public
surface: it is enabled by default in development, requires an explicit
`AEGISGRAPH_METRICS_ENABLED=true` in production, and the Kubernetes
NetworkPolicy (`deploy/k8s/networkpolicy-api.yaml`) already restricts ingress to
the pod. The scrape itself is excluded from `aegisgraph_requests_total`, so
scraping never feeds its own series.

```sh
curl -s http://127.0.0.1:8080/metrics | grep '^aegisgraph_'
# production without the flag:
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/metrics   # 404
```

## Health semantics

| Probe | Contract |
| --- | --- |
| `GET /healthz` | liveness only: the process answers. Never touches the database, the collector or the store. |
| `GET /readyz` | dependency readiness: the authentication mode, whether the receipt store is durable, and whether that store currently answers. `503` with `"status": "degraded"` when the store is unreachable. |

Telemetry is deliberately **not** part of readiness: an observability outage must
never remove a healthy API from a load balancer. The combinations below are
asserted in
`tests/test_failure_injection_telemetry.py::test_readiness_is_liveness_plus_the_receipt_store_only`
(all up, database down, collector down, and both down):

| Database | Collector | `/healthz` | `/readyz` |
| --- | --- | --- | --- |
| up | up | `200` | `200` |
| down | up | `200` | `503` (`receipt_store.reachable: false`) |
| up | down | `200` | `200` |
| down | down | `200` | `503` |

## Exact commands and what was verified locally

Run the API with tracing pointed at a collector:

```sh
PYTHONPATH=backend AEGISGRAPH_AUTH_MODE=required \
  AEGISGRAPH_SERVICE_TOKEN_FILE=.../service-tokens.json \
  AEGISGRAPH_OTEL_ENDPOINT=http://127.0.0.1:14318 \
  AEGISGRAPH_LOG_LEVEL=info \
  python -m uvicorn aegisgraph.app:app --host 127.0.0.1 --port 58833
```

Run the collector from the repository configuration (the shipped
`deploy/observability/otel-collector.yaml`, which receives OTLP on 4317/4318 and
exports to `debug`):

```sh
docker run -d --name m3-otel -p 127.0.0.1:14318:4318 \
  -v "$PWD/deploy/observability/otel-collector.yaml:/etc/otelcol/config.yaml:ro" \
  otel/opentelemetry-collector-contrib@sha256:d2da12c4336a79758826700be9e21ecf4a9f7d945b7f8a58ba55ee3fa45427c8 \
  --config=/etc/otelcol/config.yaml
docker logs m3-otel | tail -1
```

Observed (2026-10-08, local Docker 29.6.2): after one decision the collector logged

```
info  Traces  {"kind": "exporter", "data_type": "traces", "name": "debug", "resource spans": 1, "spans": 5}
```

— one trace, five spans (the root plus the four phases). A second run against a
collector configured with the `debug` exporter at `verbosity: detailed` printed the
span tree itself, e.g. `aegisgraph.decision.normalise` (attributes
`aegisgraph.policy_set.id`, `aegisgraph.policy_set.version`),
`aegisgraph.decision.evaluate` (+ `aegisgraph.verdict`),
`aegisgraph.decision.persist_receipt` (+ `aegisgraph.receipt_store.outcome`),
`aegisgraph.decision.respond` (+ `aegisgraph.latency_ms`) and the root
`aegisgraph.decision` (+ `aegisgraph.route`), all under the same trace id, and the
canary string sent as the action content and user goal appeared **zero** times in
the collector output (`docker logs … | grep -c CANARY` → `0`).

### An unreachable collector does not affect a decision

```sh
# API pointed at a closed port (nothing listens on 4319):
PYTHONPATH=backend AEGISGRAPH_AUTH_MODE=required \
  AEGISGRAPH_SERVICE_TOKEN_FILE=.../service-tokens.json \
  AEGISGRAPH_OTEL_ENDPOINT=http://127.0.0.1:4319 \
  AEGISGRAPH_OTEL_EXPORT_TIMEOUT_SECONDS=0.5 \
  python -m uvicorn aegisgraph.app:app --host 127.0.0.1 --port 58832
```

Observed (five decisions after a warm-up, plus a 2.5 s wait for the batch export):

```
decision: {"client_round_trip_ms": [6.29, 6.976, 5.69, 8.649, 7.645], "decision": "allow",
           "policy_set": {"id": "load-test-policy", "version": "1"},
           "reason_codes": ["BENIGN_ACTION"], "status": 200}
export failures: aegisgraph_telemetry_export_failures_total{signal="traces"} 1.0
readiness: 200 liveness: 200
```

The verdict, reason codes and policy identity are identical to the same request
with telemetry disabled, the round trip is single-digit milliseconds, the failed
export is counted rather than raised, and both probes stay healthy.
`tests/test_failure_injection_telemetry.py` reproduces this against a black-hole
address and asserts the decision does not wait on the exporter at all.

### Dashboards

`deploy/observability/grafana/dashboards/aegisgraph-service.json` (uid
`aegisgraph-service`) carries the panels for service health, decision latency
(p50/p95/p99 plus a p95 stat), verdict distribution, request rate by route and
status, authentication failures by reason, receipt-store failures by reason, the
5xx error rate and telemetry export failures. It uses the provisioned Prometheus
datasource (`uid: prometheus`).

Verified locally:

* the dashboard **loads**: Grafana (the digest-pinned `11.3.1` image from
  `compose.yaml`) started with the repository's provisioning directory and the
  single dashboards directory `deploy/observability/grafana/dashboards/`;
  `GET /api/search?type=dash-db` returned it in folder `AegisGraph` with uid
  `aegisgraph-service`;
* all 12 panel expressions **execute**: Prometheus (the digest-pinned `v2.55.1`
  image) scraped a live API (`job_name: aegisgraph-api`, `metrics_path: /metrics`)
  and every expression from the dashboard JSON was issued to
  `/api/v1/query`; `panels=12 failures=0`, with real values (decision request rate
  `0.154 req/s`, p50 `1.86 ms`, p95 `4.0 ms`, p99 `4.8 ms`, verdict distribution
  two series, auth failures one series).

**Closed in M4 — the shipped stack now scrapes the API.** The two provisioning
trees were consolidated onto this file set (`deploy/observability/**`): the
`aegisgraph-api` job from `api-scrape.yml` is now in the single
`deploy/observability/prometheus/prometheus.yml`, `compose.yaml` mounts
`deploy/observability/grafana/dashboards/` (so this dashboard is the only one
provisioned), and `deploy/compose/**` no longer exists. Verified by measurement on
the running stack (target `up`, real `aegisgraph_*` series, Grafana dashboard +
datasource resolving); the exact commands and outputs are in
`docs/ops/compose.md` → "The observability data path (verified)".

## What is verified and what is not

Verified locally:

* span names, attributes and the absence of content, against an in-memory exporter
  and against a real collector over OTLP/HTTP;
* metric names, label vocabulary and boundedness, against the rendered exposition;
* `/metrics` gating (development on, production opt-in), including `404` in
  production without the flag;
* the collector-down and database-down health matrix;
* the dashboard loading in Grafana and every panel expression resolving in
  Prometheus.

Not verified locally:

* a production Kubernetes deployment (the NetworkPolicy restricting `/metrics` is
  asserted by the manifest tests owned by the container workstream, not here);
* a long-running collector under load (the local collector run is a single
  short-lived container);
* tail-based sampling, span metrics or a service graph — none of them are
  configured, by design.
