# ADR-0003 — Telemetry: OpenTelemetry + Prometheus + Grafana

- **Status:** proposed
- **Date:** 2026-10-08
- **Deciders:** architecture lead (proposal), platform/telemetry engineer, orchestrator
- **Milestone:** M4

## Context

Observability today is entirely **forensic and local**: the inspector imports
traces and scorecards in the browser and never uploads them
(`backend/aegisgraph/static/index.html:36`,
`backend/aegisgraph/static/dashboard.js:412`). There are no counters, no
histograms, no distributed traces and no service-level objectives. An operator
running the platform in production cannot answer "how many decisions, of which
verdict, at what latency, and is the fail-closed rate anomalous?".

Telemetry is also the classic exfiltration channel, so its design must bound
what can leave the process.

## Decision

Instrument the platform with **OpenTelemetry** for traces and metrics, export
metrics to **Prometheus**, and visualize them in **Grafana**. Run the
Prometheus/Grafana stack in the same Compose environment as the service.

- Traces span boundary → normalization → policy → kernel → store, with the
  request id and action digest as correlation keys.
- Metrics: decision counts by verdict and reason code, decision latency
  histogram, fail-closed/error rate, receipt-store write outcomes, enforcement
  outcomes.
- **Content-free by contract:** telemetry attributes never carry observation
  content, user goals, secrets or credentials; only enumerated labels, ids and
  digests.
- The browser inspector stays local-only. Telemetry is server-side and additive.

## Alternatives

1. **Structured logs only.** Cheapest, but no aggregation, latency histograms or
   alerting; hard to correlate a request across components.
2. **StatsD / a proprietary agent.** Fewer moving parts, weaker vendor-neutral
   correlation and a proprietary dependency.
3. **OpenTelemetry → managed SaaS backend.** Externally hosted telemetry is
   unacceptable without an explicit owner decision and a data-processing review;
   rejected for now.
4. **Custom metrics endpoint without OpenTelemetry.** Loses tracing and the
   standard exporter ecosystem.

## Consequences

- **Positive:** vendor-neutral instrumentation, standard dashboards, SLOs
  expressible as alerts; traces make incidents replayable alongside receipts.
- **Negative:** two more services to run (Prometheus, Grafana) and a real risk of
  accidental content leakage into labels — mitigated by the content-free
  contract and a test that asserts attributes contain no free text.
- **Neutral:** no decision semantics change; telemetry observes, it does not
  decide.
- **Blocked:** none locally; the stack runs in Compose. A hosted backend remains
  out of scope without owner authorization.
