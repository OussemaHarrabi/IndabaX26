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

Artifact: `docs/evidence/performance/m3-load-20261008T210436Z.json`
(file SHA-256 `a8250f2fcfe0fdcda5a3b25b8ca2e6b578054b8d6f3ef357f39bbef36eee8b62`,
report digest `e437951890bce9837eb75e751fcb04f606ce513456e359bcf81102ded780ce89`).

Run: 16 concurrent clients, 20 s measured window after a 40-request warm-up, a
weighted mix of valid requests (60 % answer, 20 % allowed read tool, 15 % blocked
tool, 5 % confirmation-required consequential action), telemetry disabled (no OTLP
endpoint configured). The service-side block covers **2 986 decisions for 2 986
measured requests** (`service_side.counts_match_measured: true`): the warm-up is
excluded, so the denominator is the measured window and nothing else.

| Figure | Value |
| --- | --- |
| measured requests | 2 986 |
| throughput | 148.9 req/s |
| errors | 0 (0.0000 %) |
| statuses | `{"200": 2986}` |
| verdicts | `allow` 2 368, `block` 455, `escalate` 163 |
| in-process latency | p50 2.302 ms, p95 5.227 ms, p99 7.283 ms, mean 2.654 ms, max 16.475 ms |
| client-observed latency | p50 98.6 ms, p95 169.4 ms, p99 201.4 ms, mean 107.2 ms, max 360.0 ms |

### The superseded first report

`docs/evidence/performance/m3-load-20261008T193951Z.json` is kept as history and
must not be quoted. Two defects in the first revision of the harness made its
numbers wrong, both found by an independent adversarial review
(`docs/evidence/reviews/M3-telemetry-load-adversarial-review.json`, findings H4-01
and H4-02) and both fixed before this baseline was taken:

* its service-side block reported **4 296 decisions for 4 256 measured requests**:
  the log offset was captured before the warm-up, so 40 cold-start requests were
  included in the percentiles (p50 1.573 / p95 3.139 / p99 5.175 ms). Those numbers
  are **warm-up-contaminated and superseded**;
* its `.sha256` sidecar used the LF digest `cb338d58…` while the file on disk had
  been written in text mode on Windows (117 CRLF pairs, raw digest `1b1f7e20…`), so
  `sha256sum` did not match the sidecar. Reports are now written in binary and the
  sidecar is the digest of the exact bytes on disk; the smoke test asserts it by
  hashing `read_bytes()`.

Why the corrected run is also slower (148.9 req/s against 212.4 req/s, p95 5.227 ms
against 3.139 ms): the second run shared the machine with concurrent work. That
spread is itself the honest picture of this class of host — the SLO targets below
are therefore justified against the **worse** of the two runs, and the run-to-run
variation (≈1.7× on p95) is treated as part of the environment, not as noise to be
averaged away.

The gap between the two latency views is the load generator itself: 16 blocking
client threads share the same 16-CPU host with the server, so the client-observed
p50 is queueing on the client side, not work inside the service. Little's law
confirms it: 16 concurrent / 149 req/s ≈ 107 ms of in-flight time. The in-process
numbers (a few milliseconds) are what the service actually costs.

The measured run used the **process-local** receipt store (no `DATABASE_URL`), so
the in-process figure excludes a durable PostgreSQL write. It is not comparable to
a durable-store latency and no objective below assumes it is.

## Objectives

| Objective | Target | Window | Measured baseline | Headroom |
| --- | --- | --- | --- | --- |
| decision latency (in-process) | p95 ≤ 10 ms **and** p99 ≤ 25 ms at ≥ 140 req/s with 16 concurrent callers | 30 days, rolling | p95 5.227 ms, p99 7.283 ms | 1.9× on p95, 3.4× on p99 |
| decision latency (end-to-end, client co-located) | p95 ≤ 500 ms | 30 days, rolling | p95 169.4 ms | 3.0× |
| availability | ≥ 99.9 % of decision requests answered `2xx` | 30 days, rolling | 100 % over 2 986 requests in a 20 s window | – |
| server errors | 0 `5xx` attributable to the decision path | 30 days, rolling | 0 over 2 986 requests | – |

Why these targets, and not tighter ones:

* the p95 target is 1.9× the measured p95 **and** 3.2× the p95 of the (superseded
  but real) faster run, so it sits above the whole observed spread of this machine
  rather than inside it. A tighter target (say 7 ms) would sit within the run-to-run
  variation and would page on a garbage collection pause or a busy host — the
  measured maximum of 16.5 ms in this run is exactly such an event;
* the p99 target leaves room for the same tail while still catching a real
  regression (a 3× slowdown of the median);
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
* at the measured 149 req/s sustained, that is ≈ 385 000 requests/day, so the budget
  is ≈ 385 requests/day and ≈ 11 500 requests per 30-day window;
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
   (default `0.0`), so a failing run cannot be mistaken for a passing one. Check
   `service_side.counts_match_measured` in the artifact: it must be `true`, which
   is what proves the service-side percentiles cover the measured window only (the
   log offset is taken after the warm-up, and the tail is sliced on raw bytes).
3. **Read the artifact** in `docs/evidence/performance/`; reports are immutable
   (an existing file is never overwritten). It carries two digests, and
   `digest_semantics` says which is which: `report_digest_sha256` over the payload's
   canonical encoding, and a `.sha256` sidecar that is the digest of the exact bytes
   on disk (written in binary, LF endings) so it equals `sha256sum` of the file.
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

Not verified: behaviour above 149 req/s (the harness was not driven past the point
where the co-located client saturates), behaviour with more than one API replica,
behaviour under a real database (the measured run used the process-local store, so
`RECEIPT_STORE_UNAVAILABLE` never occurred and the in-process figure excludes a
durable write), and any long-window availability number — the 20-second window is a
smoke measurement, not a month of evidence.
