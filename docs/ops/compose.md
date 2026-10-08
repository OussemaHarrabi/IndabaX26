# Compose: the local production-like stack

Owner: Agent E (DevSecOps). Files: `compose.yaml`, `deploy/observability/**`,
`.env.example`, `Makefile`.

## Services

| Service | Image (digest-pinned) | Ports (host → container) | Healthcheck | Notes |
| --- | --- | --- | --- | --- |
| `api` | built from `Dockerfile` (`aegisgraph:local`) | `127.0.0.1:8080 → 8080` | Python `urlopen /healthz` | read-only rootfs, `cap_drop: [ALL]`, `no-new-privileges`; `DATABASE_URL` wired for durable receipts (M2) |
| `migrate` | same image as `api` | none | exit code (one-shot) | `python -m alembic upgrade head`; `restart: "no"` |
| `postgres` | `postgres@sha256:2d2b8998…` (17) | none published | `pg_isready` | M2 datastore; named volume `pgdata` |
| `otel-collector` | `otel/opentelemetry-collector-contrib@sha256:d2da12c4…` (0.115.1) | `127.0.0.1:4317/4318/8888/8889` | none (image has no shell) | OTLP in; internal metrics on `:8888`, pipeline metrics on `:8889` |
| `prometheus` | `prom/prometheus@sha256:2659f4c2…` (v2.55.1) | `127.0.0.1:9090` | `wget /-/ready` | scrapes the collector; named volume `prometheus-data` |
| `grafana` | `grafana/grafana@sha256:fa801ab6…` (11.3.1) | `127.0.0.1:3000` | `wget /api/health` | provisions the `prometheus` datasource and the M3 dashboard `aegisgraph-service.json` (uid `aegisgraph-service`); named volume `grafana-data` |

`migrate` binds the API's dependency: `api` waits for
`service_completed_successfully` with `required: false`, so the schema exists
before the service starts in the normal path, while a missing or failed migration
still leaves the API running (its `/readyz` then reports the store honestly).

Digests were resolved on 2026-10-08 with
`docker buildx imagetools inspect <ref>` and are the multi-arch manifest-list
digests. The tag is kept in this table for humans; the `compose.yaml` files
reference images **by digest only**, so a re-tagged upstream image cannot change
what runs.

## Bring-up (including the `.env` bootstrap)

`.env` is **not** committed and is required: `compose.yaml` interpolates every
secret with the `:?` form, so Compose fails closed instead of falling back to a
weak default. The exact sequence is:

```sh
cd <repo root>
cp .env.example .env                 # 1. create the file from the template
#    then edit POSTGRES_PASSWORD and GRAFANA_ADMIN_PASSWORD in .env
docker compose config                # 2. validate + interpolate (no containers)
docker compose up -d --build         # 3. build the API and start the stack
docker compose ps                    # 4. check health
```

Without step 1, step 2 already fails:

```
$ docker compose config
error while interpolating services.postgres.environment.POSTGRES_USER:
required variable POSTGRES_USER is missing a value: set POSTGRES_USER in .env
exit=1
```

(The variable named in the message depends on Compose's map iteration order; any
of `POSTGRES_USER`, `POSTGRES_PASSWORD` or `GRAFANA_ADMIN_PASSWORD` can be the
first one reported. All three are required.)

**`.env` must never be committed.** It is covered by `.gitignore`, and the
committed template is `.env.example` with placeholders only. The values the CI
`compose` job uses come from that same template (see `docs/ops/ci.md`).

The API is only reachable on loopback. Everything is reachable from the host on
`127.0.0.1` for inspection:

| Endpoint | URL |
| --- | --- |
| API dashboard | http://127.0.0.1:8080/ |
| Prometheus | http://127.0.0.1:9090/ |
| Grafana | http://127.0.0.1:3000/ (`admin` + `GRAFANA_ADMIN_PASSWORD`) |

Minimal stack (API + datastore only), valid because the API has no hard
dependency on the observability services:

```sh
docker compose up -d postgres migrate api
```

### Schema migration

`docker compose up` runs the `migrate` one-shot service before the API starts.
Verified bring-up:

```
$ docker compose up -d --build
 Container aegisgraph-postgres-1  Healthy
 Container aegisgraph-migrate-1   Started ... Exited
 Container aegisgraph-api-1       Started
$ docker inspect --format 'exit={{.State.ExitCode}}' aegisgraph-migrate-1
exit=0
$ docker compose exec -T postgres psql -U aegisgraph -d aegisgraph -c '\dt'
 alembic_version | audit_events | confirmation_grants | evaluation_runs
 policy_sets     | receipt_metadata | receipts            (7 rows)
```

Re-run it on demand (it is idempotent) with:

```sh
make migrate                 # docker compose run --rm migrate
```

Migrations are also runnable from the shipped image, which now carries
`alembic.ini`; see `docs/ops/migrations.md` and `docs/ops/container.md`.

### Readiness and one decision

```sh
curl -s http://127.0.0.1:8080/readyz
# {"status":"ready","ready":true,"dependencies":{"authentication":{"mode":"none",...},
#  "receipt_store":{"durable":true,"reachable":true}, "environment":"development"}}
```

`/healthz` is liveness only. `/readyz` is the dependency-aware signal and shows
the durable store is wired and reachable.

The unauthenticated `/v1/decision` surface is **off by default** (M2 decision
D5). To demo it, set it in `.env` and restart the API:

```sh
echo 'AEGISGRAPH_LEGACY_UNAUTHENTICATED=true' >> .env   # loopback demo only
docker compose up -d api
curl -s -X POST http://127.0.0.1:8080/v1/decision -H 'Content-Type: application/json' \
  --data-binary '{"run_id":"compose","step_id":1,"user_goal":"Perform the requested safe task","conversation":[],"candidate_action":{"type":"respond","content":"Done"},"policy_context":{"policy_id":"demo","policy_version":"1","allowed_tools":[],"confirmation_required_tools":[],"consequential_tools":[]},"history_digest":{"confirmations_granted":[]}}'
# {"decision":"allow","risk_score":0.05,...,"reason_codes":["BENIGN_ACTION"],...}
```

The supported path is the authenticated `/api/v1` API; mint a local token with
`scripts/dev_issuer.py` rather than enabling the legacy surface outside a
throwaway demo.

Tear down, keeping named volumes: `docker compose down`. Wipe them:
`docker compose down -v`.

A `Makefile` wraps the same commands (`make stack-up`, `make stack-ps`,
`make stack-down`). **`make` is not installed in the current Windows
environment**, so the raw `docker compose` commands above are the canonical
bring-up.

## Telemetry is best-effort, verified

The API has no `depends_on` on the collector, Prometheus or Grafana, so it starts
and stays healthy with any subset of them missing. Verified:

```
$ docker compose stop otel-collector prometheus grafana
$ docker compose ps
NAME                    STATUS
aegisgraph-api-1        Up 3 minutes (healthy)
aegisgraph-postgres-1   Up 3 minutes (healthy)

$ curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/healthz
200
$ curl -s -X POST http://127.0.0.1:8080/v1/decision … 
{"decision":"allow","risk_score":0.05,...,"reason_codes":["BENIGN_ACTION"],...}
```

`depends_on` for the API uses `condition: service_healthy, required: false`, so a
missing or unhealthy PostgreSQL also cannot stop the API from starting.

## Secrets

`compose.yaml` uses the `:?` interpolation form for `POSTGRES_PASSWORD` and
`GRAFANA_ADMIN_PASSWORD`, so Compose **fails closed** when they are unset rather
than defaulting. `.env.example` ships placeholders only; `.env` is gitignored and
never committed. The API itself takes no secret at this revision.

## Resource limits and isolation

Every service has CPU/memory `limits` and `reservations`, `cap_drop: [ALL]` (with
the four capabilities PostgreSQL's entrypoint genuinely needs added back),
`security_opt: [no-new-privileges:true]` and — except where an image demonstrably
requires otherwise — a read-only root filesystem. Only loopback ports are
published. The collector, Prometheus and Grafana also run read-only with `tmpfs`
for their writable scratch space.

## The observability data path (verified)

One provisioning tree, `deploy/observability/**`, is mounted by `compose.yaml`:

| Mount | Container path | File |
| --- | --- | --- |
| collector config | `/etc/otelcol/config.yaml` | `deploy/observability/otel-collector.yaml` |
| scrape config | `/etc/prometheus/prometheus.yml` | `deploy/observability/prometheus/prometheus.yml` |
| provisioning | `/etc/grafana/provisioning` | `deploy/observability/grafana/provisioning/` |
| dashboards | `/var/lib/grafana/dashboards` | `deploy/observability/grafana/dashboards/` |

There is exactly **one** Prometheus scrape config and exactly **one** provisioned
dashboards directory in the repository. The dashboard is
`aegisgraph-service.json` (uid `aegisgraph-service`), the reviewed M3 dashboard
documented in `docs/ops/observability.md`.

1. The collector exposes its internal metrics on `:8888`
   (`service.telemetry.metrics.address: 0.0.0.0:8888`).
2. Prometheus scrapes four jobs: itself, the collector's pipeline metrics
   (`otel-collector:8889`), the collector's internal `otelcol_*` metrics
   (`otel-collector:8888`) and — new in M3/M4 — the **API's own `/metrics`**
   (`job_name: aegisgraph-api`, `metrics_path: /metrics`, target `api:8080`).
3. Grafana provisions the `prometheus` datasource and the M3 dashboard.

The stack runs the API in **development** (no `AEGISGRAPH_ENV` is set), so
`GET /metrics` is served by default. In production the surface is off unless
`AEGISGRAPH_METRICS_ENABLED=true`; the scrape job is documented accordingly in
`prometheus.yml`.

Verified end to end against the running stack (2026-10-08, Docker 29.6.2):

```sh
# 1. the API job is up
curl -s 'http://127.0.0.1:9090/api/v1/targets?state=active'
#    job=aegisgraph-api  health=up  scrapeUrl=http://api:8080/metrics  lastError=""
curl -sG http://127.0.0.1:9090/api/v1/query --data-urlencode 'query=up{job="aegisgraph-api"}'
#    up = 1

# 2. real aegisgraph_* series after traffic through the API
curl -sG http://127.0.0.1:9090/api/v1/query \
  --data-urlencode 'query=count by (__name__) ({__name__=~"aegisgraph_.+"})'
#    aegisgraph_requests_total 3 series | aegisgraph_requests_created 3
#    aegisgraph_decision_latency_seconds_bucket 14 | _count 1 | _sum 1 | _created 1
curl -sG http://127.0.0.1:9090/api/v1/query \
  --data-urlencode 'query=sum by (route,status) (aegisgraph_requests_total)'
#    {route="/healthz",status="200"} = 2
#    {route="/api/v1/decisions",status="422"} = 6
#    {route="/v1/decision",status="200"} = 4

# 3. Grafana has the dashboard and a resolving datasource
curl -s http://127.0.0.1:3000/api/dashboards/uid/aegisgraph-service
#    title "AegisGraph — decision service (M3)", uid aegisgraph-service, 10 panels,
#    folder AegisGraph, datasource {"type":"prometheus","uid":"prometheus"}
curl -s http://127.0.0.1:3000/api/datasources/uid/prometheus/health
#    {"status":"OK","message":"Successfully queried the Prometheus API."}
curl -sG http://127.0.0.1:3000/api/datasources/proxy/uid/prometheus/api/v1/query \
  --data-urlencode 'query=sum(aegisgraph_requests_total)'
#    13
```

The traffic in step 2 was 6 POSTs to `/api/v1/decisions` (refused with `422` by
request validation before authentication — the refusal is instrumented, which is
the point) and 4 POSTs to the legacy `/v1/decision` with
`AEGISGRAPH_LEGACY_UNAUTHENTICATED=true` (real `allow` decisions). Both routes
appear as their own `route` label. The authenticated decision counter
`aegisgraph_decisions_total` stays empty until a caller presents a token: the
stack does not ship credentials, so the decision-rate panel needs either a token
from `scripts/dev_issuer.py` or the legacy surface.

## Notes and limitations

- **Collector healthcheck:** the collector image has no shell, so Compose cannot
  run an in-container probe. Its liveness is observed from outside via the
  Prometheus scrape. Prometheus and Grafana are probed in-container.
- **Grafana plugins:** Grafana installs a bundled plugin at startup into
  `/tmp/plugins` (tmpfs). It is lost on restart by design; no state is needed.
- **PostgreSQL is not yet used** by the API at this revision (persistence is M2).
  It is wired so the integration tests in M2 have a ready datastore and so the
  network/health wiring is exercised now.

## What is not verified here

- **Grafana dashboards rendering in a browser.** Queries were proven to return
  real series through the Prometheus API and Grafana's datasource health check,
  but no screenshot/visual assertion was made. A headless-browser check is the
  next step.
- **Resource-limit enforcement** (`deploy.resources.limits`) is declared and
  parsed by Compose; no memory-pressure or CPU-throttling test was run.
- **Two-minute-plus soak** or restart-recovery behaviour is not tested.
