# Load testing the decision surface

Owner: Agent D (observability, performance, reliability). Files:
`scripts/load_test.py`, `tests/test_load_smoke.py`,
`docs/evidence/performance/**`, `docs/ops/slo.md`.

`scripts/load_test.py` drives the **M2 surface** the way a real client does: it
authenticates with an opaque service token read from `--token-file`, checks
`GET /api/v1/version`, publishes or reuses an activated policy set over
`POST /api/v1/policies`, then sends a weighted mix of valid decision requests with
a fixed concurrency for a bounded budget. It reports throughput, p50/p95/p99, the
error rate, the status and verdict distributions, and the machine the numbers came
from, and it writes an **immutable** report.

## Prerequisites

The token must hold `decision:submit`; publishing a policy set additionally needs
`policy:write` (`policy:read` is enough to reuse one an operator activated
earlier). A token without `policy:write` still works if the named version is
already active — the harness reports which route it took in
`policy_set.source`.

## Run it

```sh
# 1. an API with the M2 surface on and decision logging on (the harness reads the
#    decision record for the service-side latency)
PYTHONPATH=backend \
  AEGISGRAPH_AUTH_MODE=required \
  AEGISGRAPH_SERVICE_TOKEN_FILE=/run/secrets/service-tokens.json \
  AEGISGRAPH_LOG_LEVEL=info \
  python -m uvicorn aegisgraph.app:app --host 127.0.0.1 --port 8080 \
  > /tmp/aegisgraph-api.log 2>&1 &

# 2. the load itself
python scripts/load_test.py \
  --token-file /run/secrets/service-token \
  --base-url http://127.0.0.1:8080 \
  --concurrency 16 --duration 20 --warm-up 40 \
  --server-log /tmp/aegisgraph-api.log \
  --label "decision-surface baseline"
```

Exit codes: `0` within `--max-error-rate` (default `0.0`), `1` above it, `2` for a
usage or environment problem (missing/empty/multi-line token file, unreachable API,
a policy set that could not be published or reused).

Options:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--token-file` | required | file holding exactly one service token |
| `--base-url` | `http://127.0.0.1:8080` | API base URL |
| `--concurrency` | `16` | worker threads |
| `--duration` | `10` | measured seconds |
| `--requests` | `0` | measured request cap; `0` means duration only. The cap is exact: a request slot is reserved under a lock before it is sent, so the measured count never overshoots |
| `--warm-up` | `40` | requests sent before measuring (never counted) |
| `--timeout` | `10` | per-request timeout in seconds |
| `--max-error-rate` | `0.0` | non-zero exit above this rate |
| `--policy-id` / `--policy-version` | `load-test-policy` / `1` | the policy set to publish and activate |
| `--out-dir` | `docs/evidence/performance` | where the immutable report goes |
| `--server-log` | – | the API's stdout log; when given, the service-side decision latency is read from it |
| `--label` | – | free text recorded in the report |

## The request mix

| Weight | Name | Candidate action | Expected verdict |
| --- | --- | --- | --- |
| 60 | `answer` | `respond` | `allow` |
| 20 | `read_tool` | `tool_call` `document_search` (allowed by the policy set) | `allow` |
| 15 | `blocked_tool` | `tool_call` `email_send` to an external domain (not allowed) | `block` |
| 5 | `confirmation_required` | `tool_call` `payment_execute` (allowed but consequential) | `escalate` |

Every shape is a valid request, so a non-`200` status is a real failure and not an
artifact of the mix. The policy document the harness publishes is recorded in the
report (`policy_set.document`), so the mix is reproducible.

## The report

Written to `<out-dir>/m3-load-<UTC timestamp>.json` with a `.sha256` sidecar, and
marked read-only. **An existing report is never overwritten** — a second run at the
same instant fails rather than clobbering evidence. Two digests are recorded, and
the report says which is which in `digest_semantics`:
`report_digest_sha256` covers the report's canonical (sorted, compact) encoding
without that field, and the sidecar covers the exact bytes on disk.

Schema `aegisgraph.load-test/1`:

| Key | Contents |
| --- | --- |
| `started_at`, `label`, `tool`, `api_version` | provenance |
| `environment` | `observed_on` note, base URL, platform, machine, processor, CPU count, Python version, the server's reported build and policy set |
| `policy_set` | id, version, how it was obtained, and the published document |
| `results` | measured requests, elapsed seconds, throughput, latency (`min`/`p50`/`p95`/`p99`/`max`/`mean`), error rate, server error rate, status/verdict/shape counts, error samples, parameters, the request mix, the percentile method, and `latency_kind` |
| `service_side` | decision count and latency percentiles read from the structured decision records written after the warm-up |
| `digest_semantics`, `report_digest_sha256` | how to verify the artifact |

Percentiles use linear interpolation on the sorted sample set (`latency_kind` and
`percentile_method` say so in the report itself).

## Observed run (2026-10-08)

```
$ python scripts/load_test.py --token-file ... --base-url http://127.0.0.1:58831 \
    --concurrency 16 --duration 20 --warm-up 40 --server-log .../api.log
# Load test report — 2026-10-08T19:39:51.418242+00:00
- artifact: docs/evidence/performance/m3-load-20261008T193951Z.json
- sha256: cb338d588a3bb86d4cd227d6a9ab25485aed3e3040e735bf6aad463b9fdb0f27
- policy set: load-test-policy:1 (published and activated by the harness)

| metric | value |
| --- | --- |
| measured requests | 4256 |
| throughput | 212.353 req/s |
| p50 | 71.422 ms |
| p95 | 102.870 ms |
| p99 | 132.912 ms |
| max | 147.161 ms |
| error rate | 0.0000% |
| status counts | {'200': 4256} |
| verdict counts | {'allow': 3360, 'block': 663, 'escalate': 233} |

Service-side decision latency, read from the structured decision record
(4296 decisions in the measured window):

| metric | value |
| --- | --- |
| p50 | 1.573 ms |
| p95 | 3.139 ms |
| p99 | 5.175 ms |
| max | 14.878 ms |

Observed on local developer hardware, single API process, no tuning:
Windows 11 / AMD64 / 16 CPUs / Python 3.13.14, concurrency 16.
```

The client-observed and service-side latencies differ by roughly an order of
magnitude because the 16 blocking client threads share the same 16-CPU host as the
server: 16 concurrent / 212 req/s ≈ 75 ms of in-flight time, which is client-side
queueing, not work inside the decision path. For a number that is free of that
noise, run the generator on a different host, or read the `service_side` block.
`docs/ops/slo.md` states which one each objective uses.

## Automated smoke test

`tests/test_load_smoke.py` starts a real `uvicorn` subprocess with the M2
authentication surface and an opaque service token, runs the harness with a
40-request cap, and asserts: exit code `0`, a single immutable report, 40 measured
requests, all `200`, error rate `0`, monotone percentiles, a verdict distribution
that sums to the measured count, a `service_side` block, the payload digest
matching a recomputation, the sidecar matching the bytes on disk, the file marked
read-only, and that a second write to the same path raises. It also covers a
missing token file, a multi-line token file, an unreachable API and the percentile
helper.

## What is verified and what is not

Verified locally: the harness runs end to end against a real server; the report is
immutable and digest-verified; the token, policy publication and reuse paths work;
the cap is exact; the smoke test passes.

Not verified: runs above ~212 req/s (the co-located client saturates first), runs
against the PostgreSQL-backed store (the observed run used the process-local store,
so the receipt write cost is the in-memory one), multi-replica behaviour, and any
comparison against production hardware.
