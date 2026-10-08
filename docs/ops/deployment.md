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
| `deploy/k8s/networkpolicy-default-deny.yaml` | NetworkPolicy | deny all ingress+egress in the namespace |
| `deploy/k8s/networkpolicy-api.yaml` | NetworkPolicy | allow only edge→8080, DNS, DB 5432, OTLP 4317/4318 |
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
- readiness **and** liveness probes on `/healthz`;
- the default-deny policy covers Ingress and Egress; the API policy's ingress
  ports are ⊆ {8080} and its egress ports ⊆ {53, 5432, 4317, 4318};
- a PodDisruptionBudget with `minAvailable`/`maxUnavailable`;
- the image is not a floating `:latest` (a non-digest tag prints an explicit
  NOTE, see below).

## Validation evidence (exact commands and output)

```sh
kubectl kustomize deploy/k8s
# → 7 objects, image rewritten to ghcr.io/oussemaharrabi/aegisgraph:0.1.0

python scripts/validate_k8s_manifests.py --validator both
# 7 × schema[kubernetes-validate] PASS
# schema[kubeconform]: Summary: 7 resources found in 1 file - Valid: 7, Invalid: 0, Errors: 0, Skipped: 0
# 21 × policy PASS → "all manifest checks passed"
```

Two independent schema validators agree on all 7 objects:

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

| Artifact | SHA-256 |
| --- | --- |
| `deploy/sbom/aegisgraph-image-sbom.json` | `9042dfe2358c2625bc2b70727244f8e89cfc19280d6255037349423fbcd492c7` |
| `deploy/sbom/aegisgraph-image-sbom.requirements.txt` | `ed494c891709fbfeb93fc8b23173250c306b32dbc3f9a71f8114767260881e13` |

The manifest records `image.id =
sha256:179c8913d1b4d373058048e719c553a17ae93a4dcc8b817a9c6dac36648b0c18` (the
reproducible content digest; the image is built with `--provenance=false
--sbom=false`, see `docs/ops/container.md`) and `source.commit`, the revision
whose source produced the image. Because the manifest is committed after the
commit it describes, `source.commit` names its parent commit; regenerating at
that revision reproduces the file byte-for-byte.

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
