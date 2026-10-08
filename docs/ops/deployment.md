# Deployment: Kubernetes manifests, image provenance, and rollback

Owner: Agent E (DevSecOps). Files: `deploy/k8s/**`, `deploy/sbom/**`,
`scripts/validate_k8s_manifests.py`, `scripts/generate_sbom.py`.

ADR-0005 makes Docker Compose the supported deployment unit and Kubernetes a
**validated-but-unverified** artifact. This document is the honest ledger of what
that means.

## Manifests

| File | Kind | Purpose |
| --- | --- | --- |
| `deploy/k8s/namespace.yaml` | Namespace | `aegisgraph`, with Pod Security Admission `restricted` enforced/audited/warned |
| `deploy/k8s/configmap.yaml` | ConfigMap | non-secret config (legacy surface off, OTLP endpoint) |
| `deploy/k8s/deployment.yaml` | Deployment | 2 replicas, full container hardening, probes, resources |
| `deploy/k8s/service.yaml` | Service | ClusterIP `80 → http(8080)` |
| `deploy/k8s/migrate-job.yaml` | Job | one-shot `alembic upgrade head` from the same image (M2 schema) |
| `deploy/k8s/networkpolicy-default-deny.yaml` | NetworkPolicy | deny all ingress+egress in the namespace |
| `deploy/k8s/networkpolicy-api.yaml` | NetworkPolicy | allow only edge→8080, DNS, DB 5432, OTLP 4317/4318 |
| `deploy/k8s/networkpolicy-migrate.yaml` | NetworkPolicy | migration Job egress limited to DNS + PostgreSQL 5432 |
| `deploy/k8s/poddisruptionbudget.yaml` | PodDisruptionBudget | `minAvailable: 1` |
| `deploy/k8s/kustomization.yaml` | Kustomization | the single place the image is resolved |

There is deliberately **no Secret manifest**: the Deployment references
`aegisgraph-secrets` by name and the values are created out-of-band, so no secret
value can ever be committed. The validator asserts that no `Secret` object in the
rendered set carries `data`/`stringData`.

### Hardening asserted by the validator

`scripts/validate_k8s_manifests.py` renders the manifests and then checks, as
failing assertions:

- pod `runAsNonRoot: true`, `seccompProfile: RuntimeDefault`;
- container `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`,
  `capabilities.drop: [ALL]`;
- `automountServiceAccountToken: false`;
- CPU/memory requests **and** limits on every container;
- `readinessProbe` on `/readyz` (dependency-aware) and `livenessProbe`/`startupProbe`
  on `/healthz` (liveness only);
- the ConfigMap keeps the production posture (`AEGISGRAPH_ENV=production`,
  `AEGISGRAPH_AUTH_MODE=required`, `AEGISGRAPH_METRICS_ENABLED=false`,
  `AEGISGRAPH_LEGACY_UNAUTHENTICATED=false`);
- the default-deny policy covers Ingress and Egress; the API policy's ingress
  ports are ⊆ {8080} and its egress ports ⊆ {53, 5432, 4317, 4318};
- a PodDisruptionBudget with `minAvailable`/`maxUnavailable`;
- the migration Job runs `python -m alembic upgrade head` from the **same image**
  as the API, reads `DATABASE_URL` from the Secret (never a ConfigMap), is
  hardened identically, and has its own egress policy limited to DNS + 5432;
- the image is not a floating `:latest` (a non-digest tag prints an explicit
  NOTE, see below).

## Validation evidence (exact commands and output)

```sh
kubectl kustomize deploy/k8s
# → 9 objects, image rewritten to ghcr.io/oussemaharrabi/aegisgraph:0.1.0

python scripts/validate_k8s_manifests.py --validator both
# 9 × schema[kubernetes-validate] PASS
# schema[kubeconform]: Summary: 9 resources found in 1 file - Valid: 9, Invalid: 0, Errors: 0, Skipped: 0
# 34 × policy PASS → "all manifest checks passed"
```

Two independent schema validators agree on all 9 objects:

- **`kubernetes-validate` 1.36.0** — pip-installable, fully offline (schemas ship
  with the package). This is the primary validator and the only one CI needs.
- **`kubeconform` 0.7.0** — strict mode, schemas fetched from the Kubernetes
  JSON-schema catalog for **1.31.0**. It is *not* on `PATH` by default; it is
  installed from a pinned, checksum-verified release asset:

  ```sh
  python scripts/install_kubeconform.py --dest artifacts/tools
  python scripts/validate_k8s_manifests.py --validator both \
      --kubeconform artifacts/tools/kubeconform.exe
  ```

  `scripts/install_kubeconform.py` pins version **0.7.0** and verifies the
  downloaded asset against the vendor's own `CHECKSUMS` before extracting
  anything. Reproducing the exact numbers from this document:

  | Item | Value |
  | --- | --- |
  | Release URL | `https://github.com/yannh/kubeconform/releases/download/v0.7.0/kubeconform-windows-amd64.zip` |
  | Asset SHA-256 | `9cb75551d81c909c2241ab383ced2be68363b5bfb15fd989badcc5a63bea5d7e` |
  | Linux asset (CI) | `kubeconform-linux-amd64.tar.gz`, SHA-256 `c31518ddd122663b3f3aa874cfe8178cb0988de944f29c74a0b9260920d115d3` |
  | Vendor `CHECKSUMS` file | SHA-256 `3b8bfbac6e662823a51292368b0c25bc04001a32b006f04aafdf348c091d243f` |
  | Temporary extraction path used for the recorded run | `artifacts/tools/` (gitignored) |

  Both assets' computed SHA-256 were cross-checked against the vendor
  `CHECKSUMS` file, and the binary reports `v0.7.0`. A mismatch aborts without
  writing anything. The CI `kubernetes` job installs it with the same script and
  runs `--validator both`, so the cross-check is reproducible in CI too.

`kubectl apply --dry-run=client` is **not** a usable gate in this environment:
kubectl performs API discovery even for client dry-run and fails with
`failed to download openapi … dial tcp [::1]:8080: connectex: … refused` when no
cluster is configured. The `kubeconform`/`kubernetes-validate` pair is the
substitute, and both run offline once `kubernetes-validate` is installed (only
kubeconform's one-time download needs the network).

## Image pinning

`deployment.yaml` carries `image: aegisgraph` untagged; `kustomization.yaml`
rewrites it once. The committed rewrite currently uses the build-identifier tag
`0.1.0`, which is a **recorded deviation**: CI records the immutable digest in
`artifacts/image-digest.txt`, and production must switch to it:

```sh
cd deploy/k8s
kustomize edit set image \
  aegisgraph=ghcr.io/oussemaharrabi/aegisgraph@sha256:<digest-from-CI>
```

The validator prints a NOTE whenever the image is tag-pinned rather than
digest-pinned, so the deviation is visible in every CI run.

**Rule: any recorded image ID must name the lock revision it was built from.**
`requirements.lock` gained the M2 persistence/auth stack and then the M3
observability stack (23 → 39 pinned entries), and the image digest moved with it.
The portable provenance triple is **(commit, `requirements.lock` content hash,
exact build command)**; the image ID is the checksum of the artifact you actually
built and is context-sensitive (see the table in `docs/ops/container.md`). At
commit `57596f3` the lock content hash is
`d0bf0f5504aa8c5da890c6913b2b4faa36f5e0476daced5ee7359eefd15730d3` (39 entries).
`scripts/check_sbom_freshness.py` enforces that the committed SBOM still names
this value, in CI.

## Deploying with the schema

**The deployment runs the API in production mode.** `deploy/k8s/configmap.yaml`
sets `AEGISGRAPH_ENV=production`, `AEGISGRAPH_AUTH_MODE=required` and
`AEGISGRAPH_METRICS_ENABLED=false` explicitly (H4-07), because the defaults are
*development*: with `AEGISGRAPH_ENV` unset the pod would serve `/metrics` by
default and accept `auth_mode=none`. In production the process validates its
configuration **at import, before the server binds**, and exits non-zero on an
unsafe one (`app.configure_configuration`). So the Secret must supply:

| Secret key | Why |
| --- | --- |
| `DATABASE_URL` | production requires a durable receipt store (`AEGISGRAPH_ENV=production` refuses to start without it) |
| a **token verifier** — `AEGISGRAPH_SERVICE_TOKENS` (JSON) or `AEGISGRAPH_JWKS` + `AEGISGRAPH_JWT_ISSUER` + `AEGISGRAPH_JWT_AUDIENCE` (the JWKS file must be mounted) | `AEGISGRAPH_AUTH_MODE=required` needs one; without it the process refuses to start |

`AEGISGRAPH_METRICS_ENABLED=false` means the Prometheus scrape job for the API
(see `deploy/observability/prometheus/prometheus.yml`) has no target in this
deployment; set it to `true` deliberately if the cluster should scrape the API.

Probes (H4-08): **readiness is `/readyz`**, which answers `503` while the receipt
store is unreachable, so a pod whose datastore is down leaves the Service
endpoints instead of staying in rotation and refusing decisions. Liveness and
startup stay on `/healthz`, which is liveness-only by design — a dependency outage
must never restart a healthy process.

Both postures were reproduced against the shipped image with exactly the
ConfigMap's environment (store deliberately unreachable):

```
$ docker run -d --read-only … \
    -e AEGISGRAPH_ENV=production -e AEGISGRAPH_AUTH_MODE=required \
    -e AEGISGRAPH_METRICS_ENABLED=false -e AEGISGRAPH_LEGACY_UNAUTHENTICATED=false \
    -e DATABASE_URL='postgresql+psycopg://u:p@127.0.0.1:1/db' \
    -e AEGISGRAPH_SERVICE_TOKENS='[{…"scopes":["decision:submit"]}]' aegisgraph:m4
$ curl -s -o /dev/null -w '%{http_code}' .../healthz     -> 200   (liveness)
$ curl -s -o /dev/null -w '%{http_code}' .../readyz      -> 503   (readiness)
$ curl -s .../readyz
  {"status":"degraded","ready":false,"dependencies":{"authentication":{"mode":"required",
   "service_tokens_configured":1,"legacy_unauthenticated":false},
   "receipt_store":{"durable":true,"reachable":false}, …}}
$ curl -s -o /dev/null -w '%{http_code}' .../metrics     -> 404   (off in production)
$ POST /v1/decision (well-formed)                        -> 404   (legacy refused)
```

Fail-closed startup is real, not aspirational: with the verifier missing the
process refuses to bind —

```
aegisgraph.settings.ConfigurationError: AEGISGRAPH_AUTH_MODE=required needs a
verifier: set AEGISGRAPH_JWT_ISSUER, AEGISGRAPH_JWT_AUDIENCE and AEGISGRAPH_JWKS,
or configure AEGISGRAPH_SERVICE_TOKENS
```

Migrations are a separate, explicit step, never an init container racing the API:

```sh
kubectl apply -k deploy/k8s
kubectl -n aegisgraph create secret generic aegisgraph-secrets \
  --from-literal=DATABASE_URL='postgresql+psycopg://user:secret@postgres:5432/aegisgraph' \
  --from-literal=AEGISGRAPH_SERVICE_TOKENS='[{"id":"client-a","tenant_id":"acme","sha256":"<lowercase sha256 of the token>","scopes":["decision:submit"]}]'
kubectl -n aegisgraph wait --for=condition=complete job/aegisgraph-migrate --timeout=180s
kubectl -n aegisgraph rollout status deploy/aegisgraph-api --timeout=120s
```

The migration Job reads only `DATABASE_URL` from the Secret; the API also reads
the verifier. `scripts/validate_k8s_manifests.py` asserts that the ConfigMap keeps
the production posture and that the probes stay split, so a later edit cannot drop
them silently.

Re-running a migration after a schema change needs the Job recreated (Jobs are
immutable in their pod template):

```sh
kubectl -n aegisgraph delete job aegisgraph-migrate --ignore-not-found
kubectl apply -k deploy/k8s
```

## Rollback

**Kubernetes**

```sh
kubectl -n aegisgraph rollout status deploy/aegisgraph-api
kubectl -n aegisgraph rollout undo deploy/aegisgraph-api      # previous ReplicaSet
# or pin a known-good digest and re-apply:
cd deploy/k8s && kustomize edit set image aegisgraph=<registry>@sha256:<known-good>
kubectl apply -k deploy/k8s
```

`maxUnavailable: 0` / `maxSurge: 1` plus the readiness probe mean a bad rollout
never takes traffic. The PodDisruptionBudget keeps one replica serving during
drains.

**Compose**

```sh
git revert <commit-that-changed-compose.yaml>   # or reset the digest in compose.yaml
docker compose up -d --no-deps --build api
```

Named volumes are preserved by `docker compose down`, so a rollback does not lose
the datastore.

## SBOM and release provenance

`scripts/generate_sbom.py` produces a hash-bearing dependency inventory because
`syft` is unavailable in this environment. It records:

- the image identity from `docker image inspect` (id, repo digests, size, user);
- the git commit and the SHA-256 of `requirements.lock`;
- every distribution installed **inside the image**, read with
  `importlib.metadata` (the hardened image has no `pip` by design, so
  `pip freeze` cannot run there — this is the equivalent), including each
  distribution's `RECORD` SHA-256;
- `--deterministic` omits the timestamp so the output is byte-reproducible.

```sh
python scripts/generate_sbom.py --image aegisgraph:m4 --deterministic \
  --output deploy/sbom/aegisgraph-image-sbom.json
```

| Artifact | SHA-256 (git blob) |
| --- | --- |
| `deploy/sbom/aegisgraph-image-sbom.json` | `142273255283014cc99214466f5bb2cf2305bac35edfeda83be0bf3ae4909572` |
| `deploy/sbom/aegisgraph-image-sbom.requirements.txt` | `e7b307190f694cda027f474ab7de7ab3ddf043de9f9f64e6ba214b84acfee8ad` |

Both are **blob** digests (`git show HEAD:<path> | sha256sum`). `.gitattributes`
marks `*.json` as `-text`, so the manifest's blob bytes are stable; the `.txt`
inventory is LF in the blob and a Windows working copy may materialize CRLF, so
hash the blob for both.

The manifest records `image.id` (the content digest of the build that produced
it — `sha256:bb373f36…` for the current revision; the image is built with
`--provenance=false --sbom=false`, see `docs/ops/container.md`),
`source.requirements_lock_sha256` (the lock revision it corresponds to) and
`source.commit`. Because the manifest is committed after the commit it describes,
`source.commit` names its parent commit; regenerating at that revision reproduces
the file byte-for-byte.

Two consecutive deterministic runs produced byte-identical output. CI emits a
fresh (timestamped) SBOM plus the image digest and uploads them as the
`container-evidence` artifact.

Tool versions used: Docker Engine 29.6.2, Compose v5.3.1, CPython 3.12.15 inside
the image; the script itself uses only the standard library and the `docker` CLI.

## What is not verified here

- **A real cluster smoke test is blocked: `kind` is not installed** (and no
  cluster is configured). Every claim above is schema- and policy-level only;
  nothing was `kubectl apply`-ed. The exact commands for the later run are:

  ```sh
  kind create cluster --name aegisgraph
  kubectl apply -k deploy/k8s
  kubectl -n aegisgraph create secret generic aegisgraph-secrets \
    --from-literal=AEGISGRAPH_BINDING_TOKEN=<value>
  kubectl -n aegisgraph rollout status deploy/aegisgraph-api --timeout=120s
  kubectl -n aegisgraph port-forward svc/aegisgraph-api 8080:80 &
  curl -fsS http://127.0.0.1:8080/healthz
  kubectl -n aegisgraph get pod -o jsonpath='{.items[*].spec.containers[*].securityContext}'
  ```

- **NetworkPolicy enforcement** (that the CNI actually drops non-allowed
  traffic). Schema-valid does not mean enforced; needs a cluster with a
  policy-capable CNI.
- **Pod Security Admission acceptance** of the namespace labels — needs the API
  server.
- **Digest-pinned production image** does not exist yet; no registry push happens
  in M4.

## Proposals for orchestrator-owned files (not applied)

1. **F8 — hash-pinned lock.** `requirements.lock` pins versions but not hashes.
   Proposal: regenerate it with a hash-bearing tool
   (`pip-compile --generate-hashes` or `pip download` + `--require-hashes`) and
   switch the image build to `pip install --require-hashes -r requirements.lock`.
   `requirements.lock` is orchestrator-owned, so this is proposed, not done.
   `pip-audit -r requirements.lock` (CI) covers CVEs but **not** integrity, so the
   two are complementary.
2. **Pin the dev/CI toolchain.** CI installs `pip-audit`, `bandit` and
   `kubernetes-validate` unpinned. A `requirements-dev.lock` (or hashes in the
   `[dev]` extra) would make the security and validation gates reproducible.
3. **Registry.** Push the image to `ghcr.io/oussemaharrabi/aegisgraph` and have CI
   record the pushed digest, so `deployment.yaml` can be digest-pinned.
