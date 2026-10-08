# deploy/k8s — validated, not smoke-tested

These manifests are **schema- and policy-validated** but have **never been
applied to a real cluster**: `kind` is not installed and no cluster is configured
in this environment. No "works on Kubernetes" claim is made. This is ADR-0005's
"validated-but-unverified" artifact.

## Apply

The Deployment runs the API in **production** mode: `configmap.yaml` sets
`AEGISGRAPH_ENV=production`, `AEGISGRAPH_AUTH_MODE=required` and
`AEGISGRAPH_METRICS_ENABLED=false`. The process validates its configuration at
import and exits non-zero on an unsafe one, so the pod **fails closed** until the
Secret exists and supplies both a durable store and a token verifier:

```sh
kubectl apply -k deploy/k8s
kubectl -n aegisgraph create secret generic aegisgraph-secrets \
  --from-literal=DATABASE_URL='postgresql+psycopg://user:secret@postgres:5432/aegisgraph' \
  --from-literal=AEGISGRAPH_SERVICE_TOKENS='[{"id":"client-a","tenant_id":"acme","sha256":"<lowercase sha256 of the token>","scopes":["decision:submit"]}]'
kubectl -n aegisgraph wait --for=condition=complete job/aegisgraph-migrate --timeout=180s
kubectl -n aegisgraph rollout status deploy/aegisgraph-api --timeout=120s
```

`AEGISGRAPH_SERVICE_TOKENS` is one option; `AEGISGRAPH_JWKS` (+
`AEGISGRAPH_JWT_ISSUER`, `AEGISGRAPH_JWT_AUDIENCE`, with the JWKS file mounted) is
the other. Values are never committed.

Probes: `readinessProbe` is `/readyz` (dependency-aware — a pod whose receipt
store is unreachable leaves the Service endpoints), while `livenessProbe` and
`startupProbe` stay on `/healthz` (liveness only, so a dependency outage never
restarts a healthy process). `scripts/validate_k8s_manifests.py` asserts both the
production posture and the probe split.

`kustomize build` renders **9 objects**. The one-shot `aegisgraph-migrate` Job runs
`python -m alembic upgrade head` from the same image as the API (it reads only
`DATABASE_URL`); recreate it (`kubectl delete job aegisgraph-migrate`) after any
schema change.

Before applying to a real cluster, replace the `0.1.0` placeholder tag with the
digest CI recorded (`artifacts/image-digest.txt`, uploaded as `container-evidence`):

```sh
cd deploy/k8s
kustomize edit set image \
  aegisgraph=ghcr.io/oussemaharrabi/aegisgraph@sha256:<digest>
```

## Validate (offline after one pinned download, what CI runs)

```sh
python -m pip install kubernetes-validate pyyaml
python scripts/install_kubeconform.py --dest artifacts/tools   # pinned + checksum-verified
python scripts/validate_k8s_manifests.py --validator both
```

This renders with `kubectl kustomize`, schema-validates with both
`kubernetes-validate` (offline) and `kubeconform` (strict, pinned v0.7.0), and
asserts the hardening invariants (non-root, read-only rootfs, no privilege
escalation, all capabilities dropped, RuntimeDefault seccomp, probes, resources,
default-deny NetworkPolicy, PodDisruptionBudget, no literal secret values).
`--validator auto` (the default) runs `kubernetes-validate` and adds
`kubeconform` when it is available.

`kubectl apply --dry-run=client` is **not** usable here: kubectl attempts API
discovery even for client dry-run and fails without a cluster.

## Not verified

- no `kubectl apply` / pod readiness / rollout;
- no NetworkPolicy enforcement test (needs a policy-capable CNI);
- no Pod Security Admission acceptance test (needs the API server);
- `runAsNonRoot` with `fsGroup: 10001` and the `emptyDir` `sizeLimit` are declared
  but not exercised at runtime.

See `docs/ops/deployment.md` for the exact cluster command sequence and the
rollback procedure.
