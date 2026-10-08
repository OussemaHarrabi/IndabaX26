# Compose: the local production-like stack

Owner: Agent E (DevSecOps). Files: `compose.yaml`, `deploy/compose/**`,
`.env.example`, `Makefile`.

## Services

| Service | Image (digest-pinned) | Ports (host → container) | Healthcheck | Notes |
| --- | --- | --- | --- | --- |
| `api` | built from `Dockerfile` (`aegisgraph:local`) | `127.0.0.1:8080 → 8080` | Python `urlopen /healthz` | read-only rootfs, `cap_drop: [ALL]`, `no-new-privileges` |
| `postgres` | `postgres@sha256:5660c2cb…` (16.4-alpine) | none published | `pg_isready` | M2 datastore; named volume `pgdata` |
| `otel-collector` | `otel/opentelemetry-collector-contrib@sha256:d2da12c4…` (0.115.1) | `127.0.0.1:4317/4318/8888/8889` | none (image has no shell) | OTLP in; internal metrics on `:8888`, pipeline metrics on `:8889` |
| `prometheus` | `prom/prometheus@sha256:2659f4c2…` (v2.55.1) | `127.0.0.1:9090` | `wget /-/ready` | scrapes the collector; named volume `prometheus-data` |
| `grafana` | `grafana/grafana@sha256:fa801ab6…` (11.3.1) | `127.0.0.1:3000` | `wget /api/health` | provisioned datasource + dashboard; named volume `grafana-data` |

Digests were resolved on 2026-10-08 with
`docker buildx imagetools inspect <ref>` and are the multi-arch manifest-list
digests. The tag is kept in this table for humans; the `compose.yaml` files
reference images **by digest only**, so a re-tagged upstream image cannot change
what runs.

## Bring-up

```sh
cp .env.example .env      # then edit the passwords; .env is gitignored
docker compose up -d --build
docker compose ps
```

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
docker compose up -d api postgres
```

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

1. The collector exposes its internal metrics on `:8888`
   (`service.telemetry.metrics.address: 0.0.0.0:8888`).
2. Prometheus scrapes two collector jobs (`otel-collector:8889` for pipeline
   metrics, `otel-collector:8888` for internal `otelcol_*` metrics) plus itself.
3. Grafana provisions the `prometheus` datasource and the `AegisGraph — local
   stack health` dashboard from files.

Verified with live queries against the running stack:

```
$ curl -s 'http://127.0.0.1:9090/api/v1/targets?state=active'   # jobs: prometheus up,
                                                                 # otel-collector up,
                                                                 # otel-collector-internal up
$ curl -sG http://127.0.0.1:9090/api/v1/query --data-urlencode 'query=up{job=~".+"}'
  series: 3   (all = 1)
$ … 'query=otelcol_process_uptime'            → 1 series
$ … 'query=rate(otelcol_process_cpu_seconds[5m])' → 1 series
$ curl -s http://127.0.0.1:3000/api/health    → {"database":"ok","version":"11.3.1",...}
$ curl -s http://127.0.0.1:3000/api/datasources/uid/prometheus/health
  → {"status":"OK","message":"Successfully queried the Prometheus API."}
```

The API does **not** emit telemetry yet; that instrumentation is M2 (ADR-0003).
The panels above therefore prove the **collector → Prometheus → Grafana** path
with the collector's own metrics. A span-level panel lights up once the API emits
spans; the pipeline is already configured for it.

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
