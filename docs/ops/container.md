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

Built at commit `57596f3` against `requirements.lock` whose content SHA-256 (LF,
git blob) is
`d0bf0f5504aa8c5da890c6913b2b4faa36f5e0476daced5ee7359eefd15730d3` — **39 pinned
entries** (`git show 57596f3:requirements.lock | sha256sum`):

```
#16 exporting manifest sha256:bb373f362f052ffa49f15a47ef5ffd72bb7665a275e0b79a9db54f1f6c5cb531 done
#16 exporting config sha256:041d91defb721324117d1e0e68dc54ed0f620f903142dff5a1cea154690fbb32 done
docker image inspect -> id=sha256:bb373f362f052ffa49f15a47ef5ffd72bb7665a275e0b79a9db54f1f6c5cb531 size=73084467
```

Two consecutive builds produced the same ID.

**Rule: any recorded image ID must name the lock revision (and the commit) it was
built from.** An image ID alone is meaningless across revisions: the lock went
23 → 39 entries (M2 added the persistence/auth stack; M3 added `opentelemetry-*`
and `prometheus-client`), and the digest moved with it. `scripts/check_sbom_freshness.py`
enforces the same rule for the SBOM in CI.

`--provenance=false --sbom=false` is deliberate: BuildKit's default provenance
attestation records build metadata, so the *manifest-list* digest changes between
builds even when the content does not. With attestations off, `docker image
inspect --format '{{.Id}}'` is a content digest.

### The digest is tied to the build context, not only to the commit

A content-addressed image digest also absorbs the bytes *and the modification
times* of whatever the context materialized. Building the same commit from a
different context gives a different ID, which is expected and not a defect:

| Context (same commit `57596f3`, same lock `d0bf0f55…`) | Image ID | Size (B) |
| --- | --- | --- |
| This Windows worktree (`backend/*.py` materialized CRLF by `core.autocrlf=true`) | `sha256:bb373f36…` | 73,084,467 |
| `git archive` context, LF line endings (`git -c core.autocrlf=false`) | `sha256:08595cbc…` | 72,738,608 |

So the *portable* provenance triple is **(commit, lock content hash, exact build
command)**; the image ID is the checksum of the artifact you actually built and
must travel with those three. Shrinking this variance is proposed in the M4
handoff: `.gitattributes` `eol=lf` rules for source files (or building from a
`git archive` context, which normalizes both bytes and mtimes to the commit).

```sh
docker run --rm -d --name aegis-smoke \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  -e AEGISGRAPH_LEGACY_UNAUTHENTICATED=true \
  -p 18080:8080 aegisgraph:m4
curl -s http://127.0.0.1:18080/healthz
# {"status":"ok"}
curl -s -X POST http://127.0.0.1:18080/v1/decision -H 'Content-Type: application/json' \
  --data-binary '{"run_id":"smoke","step_id":1,"user_goal":"Perform the requested safe task","conversation":[],"candidate_action":{"type":"respond","content":"Done"},"policy_context":{"policy_id":"smoke","policy_version":"1","allowed_tools":[],"confirmation_required_tools":[],"consequential_tools":[]},"history_digest":{"confirmations_granted":[]}}'
# {"decision":"allow","risk_score":0.05,"confidence":0.99,"reason_codes":["BENIGN_ACTION"], ...}
```

`AEGISGRAPH_LEGACY_UNAUTHENTICATED=true` is required to exercise the frozen
`/v1/decision` surface after M2 (decision D5); it is passed explicitly rather than
left to the development default, and the throwaway container still needs no
credentials and no database. `/healthz` is liveness only — the dependency-aware
signal is `/readyz`, which reports the authentication mode and whether the receipt
store is durable and reachable.

### `GET /metrics` (M3)

The image serves a Prometheus exposition endpoint at `/metrics`. It is **on by
default in development and off in production**; `AEGISGRAPH_METRICS_ENABLED`
overrides either way. Verified in the smoke container:

```
$ curl -s -o /dev/null -w '%{http_code} %{content_type}' http://127.0.0.1:18090/metrics
200 text/plain; version=1.0.0; charset=utf-8
$ curl -s http://127.0.0.1:18090/metrics | head -2
# HELP aegisgraph_requests_total HTTP requests handled, by route template, method and status.
# TYPE aegisgraph_requests_total counter
```

The CI smoke asserts `/healthz`, `/metrics` and one decision. The scrape is
excluded from its own request counters, so a `/metrics` poll does not perturb the
series.

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
| Source revision | `57596f3` (integration HEAD at build time; M3 merged) |
| Lock revision (**primary identity**) | `requirements.lock` content SHA-256 `d0bf0f5504aa8c5da890c6913b2b4faa36f5e0476daced5ee7359eefd15730d3` (39 pinned entries) |
| Image reference built locally | `aegisgraph:m4` |
| **Image ID (content digest)** at that lock revision, built in this environment | `sha256:bb373f362f052ffa49f15a47ef5ffd72bb7665a275e0b79a9db54f1f6c5cb531` |
| Config digest | `sha256:041d91defb721324117d1e0e68dc54ed0f620f903142dff5a1cea154690fbb32` |
| Base image | `python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f` |
| Size | 73,084,467 bytes |
| SBOM manifest (`deploy/sbom/aegisgraph-image-sbom.json`) | sha256 `142273255283014cc99214466f5bb2cf2305bac35edfeda83be0bf3ae4909572` |
| Dependency inventory (`deploy/sbom/aegisgraph-image-sbom.requirements.txt`) | sha256 `e7b307190f694cda027f474ab7de7ab3ddf043de9f9f64e6ba214b84acfee8ad` |

The SBOM records `source.commit = 57596f3` and
`source.requirements_lock_sha256 = d0bf0f55…`, i.e. it names exactly the revision
and lock it describes. `scripts/check_sbom_freshness.py` fails CI when that stops
being true (see `docs/ops/ci.md`).

Both SBOM digests are **git blob** digests: `git show HEAD:<path> | sha256sum`.
`.gitattributes` marks `*.json` as `-text`, so the manifest's blob bytes are
stable across checkouts. The `.requirements.txt` inventory is written with LF and
is **not** marked, so a Windows checkout with `core.autocrlf=true` would
materialize CRLF in the working copy while the blob — the recorded value — stays
LF. Hash the blob for both, never the working copy.

The image ID above is the one produced by the documented command **in this
environment**; see the context table in the build section for why another
context yields another ID, and why the lock blob hash — not the image ID alone —
is the portable identity. CI re-derives its own ID with `docker image inspect
--format '{{.Id}}'`, writes it to `artifacts/image-digest.txt`, and uploads it
together with the lock hash.

## Migrations from the shipped image

`alembic.ini` is copied into the image (root-owned, read-only), so the migration
step runs from the deployed artifact and not only from a checkout:

```sh
docker run --rm -e DATABASE_URL='postgresql+psycopg://user:secret@host:5432/aegisgraph' \
  aegisgraph:m4 python -m alembic upgrade head
```

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
