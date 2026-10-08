# Container: hardening, the read-only posture, and the F10 regression proof

Owner: Agent E (DevSecOps). Files: `Dockerfile`, `.dockerignore`.

## What the image is

- **Base:** `python:3.12-slim`, pinned by **digest**
  (`@sha256:05cda977…`, the manifest-list digest resolved 2026-10-08) for both
  stages, so a rebuild cannot silently pick up a new base.
- **Stage 1 (`builder`)** installs the exact pins from `requirements.lock` with
  `--target=/install`. Every pin is a pure-Python wheel, so no compiler is
  involved.
- **Stage 2 (`runtime`)** copies only the resolved dependency tree and
  `backend/` + `requirements.lock`. It then **removes `pip`, `setuptools`,
  `wheel` and `_distutils_hack`** and runs as **uid/gid 10001**, which owns
  nothing writable.

## Hardening properties (verified)

| Property | Evidence |
| --- | --- |
| Non-root runtime user | `id -u` → `10001` |
| `/app` owned by root, no write bit for anyone | `stat` → `root:root 555`; `touch /app/breach` → `Permission denied` |
| Works with a read-only root filesystem | `docker run --read-only ...` serves `/healthz` and a decision |
| No build toolchain / package manager in the runtime layer | `command -v pip gcc cc make` → none |
| `HEALTHCHECK` present | `docker inspect` → `healthy` |
| No secrets in the image or the Dockerfile | only `requirements.lock` and `backend/` are copied; config arrives via env |

## The F10 regression criterion

Finding **F10** is: *the application directory is owned by the runtime user, so a
foothold could rewrite the service's own code*. The regression criterion is *"the
image runs with a read-only root filesystem, **or** `/app` is root-owned and not
writable by the service user; a smoke test covers `/healthz` and one decision
under that configuration."*

Both halves are satisfied **independently**:

1. Under `--read-only` the whole filesystem is immutable:
   `touch /app/breach` → `Read-only file system`.
2. Even **without** `--read-only`, ownership alone denies the runtime user:
   `touch /app/breach` → `Permission denied` (not `EROFS`).

`--read-only` is therefore the **supported posture**, stated in the `Dockerfile`
header, not merely tolerated.

## Build and smoke (exact commands and output)

```sh
docker build --provenance=false --sbom=false -t aegisgraph:m4 .
```

```
#15 exporting manifest sha256:179c8913d1b4d373058048e719c553a17ae93a4dcc8b817a9c6dac36648b0c18 done
#15 exporting config sha256:c05aa6ce8f4e06d98348bd48c61b7e762efd271f96eb3a703bc796a7b83e8cea done
#15 naming to docker.io/library/aegisgraph:m4 done
```

`--provenance=false --sbom=false` is deliberate: BuildKit's default provenance
attestation records build metadata, so the *manifest-list* digest changes between
builds even when the content does not (an un-flagged build of this same
Dockerfile produced `sha256:9b033e3d…`). With attestations off the digest is a
content digest, verified stable across two consecutive builds
(`docker image inspect --format '{{.Id}}'` → the same `179c8913…` both times).

```sh
docker run --rm -d --name aegis-smoke \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  -p 18080:8080 aegisgraph:m4
curl -s http://127.0.0.1:18080/healthz
# {"status":"ok"}
curl -s -X POST http://127.0.0.1:18080/v1/decision -H 'Content-Type: application/json' \
  --data-binary '{"run_id":"smoke","step_id":1,"user_goal":"Perform the requested safe task","conversation":[],"candidate_action":{"type":"respond","content":"Done"},"policy_context":{"policy_id":"smoke","policy_version":"1","allowed_tools":[],"confirmation_required_tools":[],"consequential_tools":[]},"history_digest":{"confirmations_granted":[]}}'
# {"decision":"allow","risk_score":0.05,"confidence":0.99,"reason_codes":["BENIGN_ACTION"], ...}
```

Observed hardening proof inside the running container:

```
$ docker exec aegis-smoke sh -c 'id; ls -ld /app; stat -c "%U:%G %a %n" /app /app/backend/aegisgraph/app.py'
uid=10001(aegisgraph) gid=10001(aegisgraph) groups=10001(aegisgraph)
dr-xr-xr-x 1 root root 4096 /app
root:root 555 /app
root:root 555 /app/backend/aegisgraph/app.py

$ ... touch /app/breach /app/backend/aegisgraph/breach.py /usr/local/breach
touch: cannot touch '/app/breach': Read-only file system
touch: cannot touch '/app/backend/aegisgraph/breach.py': Read-only file system
touch: cannot touch '/usr/local/breach': Read-only file system

$ ... command -v pip pip3 gcc cc make
pip/gcc/cc/make: none present

$ docker inspect --format '{{.State.Health.Status}}' aegis-smoke
healthy
```

Without `--read-only`, the same write attempts fail on permissions alone:

```
$ docker run --rm --entrypoint sh aegisgraph:m4 -c 'touch /app/breach'
touch: cannot touch '/app/breach': Permission denied
```

## Registry layout and trust

The runtime layer therefore contains **no writable application code**: the process
cannot modify `aegisgraph/`, drop a `sitecustomize.py`, or reinstall a package.
`requirements.lock` is kept in the image only for provenance.

## Recorded artifacts

| Artifact | Value |
| --- | --- |
| Image reference built locally | `aegisgraph:m4` |
| **Image ID (content digest, reproducible)** | `sha256:179c8913d1b4d373058048e719c553a17ae93a4dcc8b817a9c6dac36648b0c18` |
| Config digest | `sha256:c05aa6ce8f4e06d98348bd48c61b7e762efd271f96eb3a703bc796a7b83e8cea` |
| Base image | `python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f` |
| Compressed size | 48,548,441 bytes |
| SBOM manifest (`deploy/sbom/aegisgraph-image-sbom.json`) | sha256 `9042dfe2358c2625bc2b70727244f8e89cfc19280d6255037349423fbcd492c7` |
| Dependency inventory (`deploy/sbom/aegisgraph-image-sbom.requirements.txt`) | sha256 `ed494c891709fbfeb93fc8b23173250c306b32dbc3f9a71f8114767260881e13` |

The un-flagged build of the same Dockerfile produced a *manifest-list* digest of
`sha256:9b033e3d…`; that digest is not recorded as the identity because it is not
reproducible (it carries a BuildKit attestation). Only the content digest
(`179c8913…`) is.

CI re-derives the ID with `docker image inspect --format '{{.Id}}'` and uploads it
as `artifacts/image-digest.txt`.

## Secrets

No secret is baked into the image. Runtime configuration is env-only; the Compose
stack supplies it from `.env` (gitignored, templated by `.env.example`), and the
Kubernetes deployment reads a Secret that this repository does not ship. See
`docs/ops/compose.md` and `docs/ops/deployment.md`.

## What is not verified here

- `--read-only` combined with the Compose `tmpfs`/`cap_drop` settings is verified
  through the raw `docker run` above; the Compose service is verified to start
  (`docs/ops/compose.md`).
- No image was pushed to a registry in M4, so `RepoDigests` for a remote registry
  do not exist yet; the local image ID is the pinned identity.
- The image is built for `linux/amd64` only. Multi-arch builds are out of scope.
