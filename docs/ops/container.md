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

Built at commit `4350af3` against `requirements.lock` whose git blob SHA-256 is
`b49b8c5d328f5823f07f5aa96bbc63572376e857a982bff2050781d57b5f93fd` (23 pinned
packages; `git show 4350af3:requirements.lock | sha256sum`):

```
#16 exporting config sha256:ab1fc8bc087cc482edefc14c350bb8966b5d19933ad39d5f476b6faa4e7f086a done
#16 naming to docker.io/library/aegisgraph:m4 done
docker image inspect -> id=sha256:f36f6e1e51ba9df381d37315224d4d0909e087c62313960153cbdfb10b97e5aa size=69404249
```

**Rule: any recorded image ID must name the lock revision (and the commit) it was
built from.** An image ID alone is meaningless across revisions — `requirements.lock`
gained the whole M2 stack (alembic, SQLAlchemy, psycopg, cryptography, PyJWT) and
the digest moved with it.

`--provenance=false --sbom=false` is deliberate: BuildKit's default provenance
attestation records build metadata, so the *manifest-list* digest changes between
builds even when the content does not (an un-flagged build of an earlier revision
produced `sha256:9b033e3d…`). With attestations off, `docker image inspect
--format '{{.Id}}'` is a content digest, verified stable across two consecutive
builds of this revision (the same `f36f6e1e…` both times).

### The digest is tied to the build context, not only to the commit

A content-addressed image digest also absorbs the bytes *and the modification
times* of whatever the context materialized. Building the same commit from a
different context gives a different ID, which is expected and not a defect:

| Context | Image ID | Size (B) |
| --- | --- | --- |
| This Windows worktree (`backend/*.py` materialized CRLF by `core.autocrlf=true`) | `sha256:f36f6e1e…` | 69,404,249 |
| Committed `Dockerfile` (no `alembic.ini`), same CRLF worktree | `sha256:bf154b87…` | 69,415,410 |
| `git archive` context, LF line endings (`git -c core.autocrlf=false`) | `sha256:a7404539…` | 69,055,315 |
| Another reviewer's build of the same commit | `sha256:77f51aca…` | 69,138,507 |

So the *portable* provenance triple is **(commit, lock blob hash, exact build
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
| Source revision | `4350af3` (integration HEAD; M2 merged) |
| Lock revision (**primary identity**) | `requirements.lock` blob SHA-256 `b49b8c5d328f5823f07f5aa96bbc63572376e857a982bff2050781d57b5f93fd` (23 packages, 1399 bytes) |
| Image reference built locally | `aegisgraph:m4` |
| **Image ID (content digest)** at that lock revision, built in this environment | `sha256:f36f6e1e51ba9df381d37315224d4d0909e087c62313960153cbdfb10b97e5aa` |
| Config digest | `sha256:ab1fc8bc087cc482edefc14c350bb8966b5d19933ad39d5f476b6faa4e7f086a` |
| Base image | `python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f` |
| Size | 69,404,249 bytes |
| SBOM manifest (`deploy/sbom/aegisgraph-image-sbom.json`) | sha256 `14949d1b921cf5dca0cd2c55b12508f84d93205371ad066addc239a0b3144143` |
| Dependency inventory (`deploy/sbom/aegisgraph-image-sbom.requirements.txt`) | sha256 `e4539d17fbcfc892e907fb83eab67c81ea025ed7de9d9a6065eb323e31dfac3e` |

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
