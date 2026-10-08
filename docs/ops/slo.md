# Service level objectives for the decision surface

Owner: Agent D (observability, performance, reliability). Files: this document,
`scripts/load_test.py`, `docs/evidence/performance/**`,
`deploy/observability/grafana/dashboards/aegisgraph-service.json`.

**Every number in this document is a local-hardware observation.** It was measured
on one developer machine (Windows 11, AMD64, 16 logical CPUs, Python 3.13.14, one
`uvicorn` process, no tuning, no CPU pinning, the load generator running on the
same host) against the local API, not on production hardware and not under
production traffic. The targets below are derived from that measurement and must be
re-derived on the deployment hardware before they are promised to anyone.

## Scope

In scope: `POST /api/v1/decisions`, the receipt-bearing generic decision surface.
Out of scope: the frozen legacy `POST /v1/decision` (its behaviour is deliberately
frozen and measured elsewhere), the administration and audit read surfaces, and the
local read-only dashboard.

## Service level indicators

| SLI | Definition | Source |
| --- | --- | --- |
| decision latency | wall-clock time inside the process from the start of `create_decision` to the response being built, recorded by the API itself | `aegisgraph.latency_ms` in the structured decision record; `aegisgraph_decision_latency_seconds` histogram |
| availability | fraction of decision requests answered with a `2xx` | `aegisgraph_requests_total{route="/api/v1/decisions",status=~"2.."}` / total |
| server error rate | fraction answered `5xx` (or dropped by the transport) | `aegisgraph_requests_total{status=~"5.."}` / total |
| end-to-end latency | what a client observes, including its own scheduling | the load harness report (`results.latency_seconds`) |

The in-process SLI is the one to alert on: it is the service's own cost, free of
client scheduling noise. The end-to-end SLI is the one a caller experiences and is
reported separately.

## Measured baseline

Artifact: `docs/evidence/performance/m3-load-20261008T193951Z.json`
(file SHA-256 `cb338d588a3bb86d4cd227d6a9ab25485aed3e3040e735bf6aad463b9fdb0f27`,
report digest `3dcd41453b28ceda017dac7cb49e1061a1b2174af822a90c48e25c58c547250d`).

Run: 16 concurrent clients, 20 s measured window after a 40-request warm-up, a
weighted mix of valid requests (60 % answer, 20 % allowed read tool, 15 % blocked
tool, 5 % confirmation-required consequential action), telemetry disabled (no OTLP
endpoint configured).

| Figure | Value |
| --- | --- |
| measured requests | 4 256 |
| throughput | 212.4 req/s |
| errors | 0 (0.0000 %) |
| statuses | `{"200": 4256}` |
| verdicts | `allow` 3 360, `block` 663, `escalate` 233 |
| in-process latency | p50 1.573 ms, p95 3.139 ms, p99 5.175 ms, mean 1.794 ms, max 14.878 ms |
| client-observed latency | p50 71.4 ms, p95 102.9 ms, p99 132.9 ms, mean 75.2 ms, max 147.2 ms |

The gap between the two latency views is the load generator itself: 16 blocking
client threads share the same 16-CPU host with the server, so the client-observed
p50 is queueing on the client side, not work inside the service. Little's law
confirms it: 16 concurrent / 212 req/s ≈ 75 ms of in-flight time. The in-process
numbers (a few milliseconds) are what the service actually costs.

## Objectives

| Objective | Target | Window | Measured baseline | Headroom |
| --- | --- | --- | --- | --- |
| decision latency (in-process) | p95 ≤ 10 ms **and** p99 ≤ 25 ms at ≥ 200 req/s with 16 concurrent callers | 30 days, rolling | p95 3.139 ms, p99 5.175 ms | 3.2× on p95, 4.8× on p99 |
| decision latency (end-to-end, client co-located) | p95 ≤ 250 ms | 30 days, rolling | p95 102.9 ms | 2.4× |
| availability | ≥ 99.9 % of decision requests answered `2xx` | 30 days, rolling | 100 % over 4 256 requests in a 20 s window | – |
| server errors | 0 `5xx` attributable to the decision path | 30 days, rolling | 0 over 4 256 requests | – |

Why these targets, and not tighter ones:

* the p95 target is 3.2× the measured p95. A tighter target (say 5 ms) would sit
  inside the observed spread of a *single* machine and would page on a garbage
  collection pause or a cold cache — the measured maximum of 14.9 ms in one run is
  exactly such an event, so a p95 of 5 ms would be a promise the evidence does not
  support;
* the p99 target leaves room for the same tail while still catching a real
  regression (a 5× slowdown of the median);
* 99.9 % availability is the conventional first target for a single-replica service
  with a manual restart; the measured 100 % over a 20 s window says nothing about a
  month, so the target is deliberately conservative rather than extrapolated;
* the error-rate objective is absolute because the decision path has no expected
  `5xx`: a `5xx` here means the boundary failed (an unhandled exception) or the
  receipt store was unreachable, and the latter is already counted separately as
  `aegisgraph_receipt_store_failures_total{reason="RECEIPT_STORE_UNAVAILABLE"}`.

### Error budget

For 99.9 % availability over a 30-day window:

* allowed failure: 0.1 % of decision requests;
* at the measured 212 req/s sustained, that is ≈ 550 000 requests/day, so the budget
  is ≈ 550 requests/day and ≈ 16 500 requests per 30-day window;
* expressed in time (the conventional view): 43 min 12 s of full outage per 30 days.

Budget policy (deliberately simple, and reviewable): if more than half the monthly
budget is consumed, the next change to the decision path requires a load-test run
and a fresh report in `docs/evidence/performance/` before it merges; if the budget
is exhausted, reliability work takes precedence over feature work until the window
rolls.

## Measurement protocol

1. **Start the API** with the M2 authentication surface and a service token holding
   `decision:submit`, `policy:read`, `policy:write` and `receipt:read`, and with
   decision logging at `info` (the structured decision record carries
   `latency_ms`). The exact commands are in `docs/ops/load-testing.md`.
2. **Run the harness** for a fixed window, and pass the server log so both latency
   views are captured in one artifact:

   ```sh
   python scripts/load_test.py \
     --token-file /run/secrets/service-token \
     --base-url http://127.0.0.1:8080 \
     --concurrency 16 --duration 20 --warm-up 40 \
     --server-log /tmp/aegisgraph-api.log \
     --label "decision-surface baseline"
   ```

   The harness exits non-zero if the error rate exceeds `--max-error-rate`
   (default `0.0`), so a failing run cannot be mistaken for a passing one.
3. **Read the artifact** in `docs/evidence/performance/`; reports are immutable
   (an existing file is never overwritten) and carry both the digest of the report
   payload and a `.sha256` sidecar of the bytes on disk.
4. **Continuously**, take the same SLIs from Prometheus (the queries the dashboard
   uses):

   ```promql
   # in-process p95 / p99
   histogram_quantile(0.95, sum by (le) (rate(aegisgraph_decision_latency_seconds_bucket[5m])))
   histogram_quantile(0.99, sum by (le) (rate(aegisgraph_decision_latency_seconds_bucket[5m])))
   # availability over the window
   sum(rate(aegisgraph_requests_total{route="/api/v1/decisions",status=~"2.."}[5m]))
     / clamp_min(sum(rate(aegisgraph_requests_total{route="/api/v1/decisions"}[5m])), 0.000001)
   # server error rate
   sum(rate(aegisgraph_requests_total{status=~"5.."}[5m]))
     / clamp_min(sum(rate(aegisgraph_requests_total[5m])), 0.000001)
   ```

   The histogram buckets are `0.0005 … 5` seconds, so the p95 target (10 ms) sits
   inside a bucket boundary (`0.01`) rather than being interpolated across a wide
   gap.

Exclusions: none. A request refused by authentication is a `401` and counts as
unavailable for the availability objective, because a caller could not obtain a
decision. Receipt-store refusals (`503`) count as unavailable as well; they are
also visible separately, so the two causes can be told apart.

## What is verified and what is not

Verified locally: the baseline above, reproduced from the committed artifact; the
`/metrics` series and histogram buckets the queries depend on; the dashboard panels
executing against a live scrape; the failure behaviour that keeps a `503` from
being counted as a served decision (`tests/test_failure_injection*.py`).

Not verified: behaviour above 212 req/s (the harness was not driven past the point
where the co-located client saturates), behaviour with more than one API replica,
behaviour under a real database (the measured run used the process-local store, so
`RECEIPT_STORE_UNAVAILABLE` never occurred), and any long-window availability
number — the 20-second window is a smoke measurement, not a month of evidence.
