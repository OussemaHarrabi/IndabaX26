# deploy/k8s — validated, not smoke-tested

These manifests are **schema- and policy-validated** but have **never been
applied to a real cluster**: `kind` is not installed and no cluster is configured
in this environment. No "works on Kubernetes" claim is made. This is ADR-0005's
"validated-but-unverified" artifact.

## Apply

```sh
# The pod fails closed until the Secret exists (values are never committed).
# DATABASE_URL is required for the M2 durable receipt store.
kubectl apply -k deploy/k8s
kubectl -n aegisgraph create secret generic aegisgraph-secrets \
  --from-literal=DATABASE_URL='postgresql+psycopg://user:secret@postgres:5432/aegisgraph'
kubectl -n aegisgraph wait --for=condition=complete job/aegisgraph-migrate --timeout=180s
kubectl -n aegisgraph rollout status deploy/aegisgraph-api --timeout=120s
```

`kustomize build` renders **9 objects**. The one-shot `aegisgraph-migrate` Job runs
`python -m alembic upgrade head` from the same image as the API; recreate it
(`kubectl delete job aegisgraph-migrate`) after any schema change.

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
