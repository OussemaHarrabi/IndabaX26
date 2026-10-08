# CI: gates, local reproduction, and what is not verified

Owner: Agent E (DevSecOps). Workflow: `.github/workflows/ci.yml`.

Every gate below has a locally-run equivalent. Anything that only runs on a
GitHub-hosted runner is marked **unverified** with the reason.

## Jobs

| Job | What it proves | Local equivalent |
| --- | --- | --- |
| `quality` | `ruff`, strict `mypy`, and `pytest` with the coverage gate | `make gates` |
| `security` | no known CVEs in the shipped pins; no medium+ static findings | `make audit && make bandit` |
| `container` | image builds; runs under `--read-only`; serves `/healthz` and one decision; no writable app code; digest + SBOM recorded | `make smoke && make sbom` |
| `kubernetes` | manifests render, schema-validate and satisfy the hardening invariants | `make k8s-validate` |
| `compose` | the Compose stack parses and interpolates | `make compose-config` |

A matrix is deliberately **not** used: `pyproject.toml` declares
`requires-python = ">=3.12,<3.13"`, so there is exactly one supported interpreter
minor. The single axis (`3.12`) is fixed in `env.PYTHON_VERSION`.

The container job builds with `docker buildx build --provenance=false --sbom=false
--load`. BuildKit's default provenance attestation records build metadata, which
makes the *manifest-list* digest vary between builds even for identical content;
disabling it makes the recorded digest a reproducible content digest (see
`docs/ops/deployment.md` and `docs/ops/container.md`). The equivalent local
command is `docker build --provenance=false --sbom=false -t aegisgraph:local .`.

### The `kubernetes` job's validators

`kubernetes-validate` comes from pip. `kubeconform` is **not** on `PATH` by
default, so the job installs it with `python scripts/install_kubeconform.py`,
which pins v0.7.0 and verifies the downloaded asset against the vendor's
published SHA-256 before extracting it. The job then runs
`python scripts/validate_k8s_manifests.py --validator both`, so both validators
run and must agree. The script's default `--validator auto` runs
`kubernetes-validate` and adds `kubeconform` only if it is already available,
printing a NOTE when it is not — it never silently claims a cross-check it did
not perform.

### Where the `compose` job's values come from

The `compose` job runs `cp .env.example .env` and then
`docker compose config --quiet`. The values are therefore the **placeholders in
the committed `.env.example`** — no CI secret is used, nothing is started, and
nothing is deployed. `.env` is removed afterwards (`rm -f .env`) and is never
committed or uploaded. This is exactly why `compose.yaml` uses the `:?`
interpolation form: the check would fail closed if the variable were absent.

## Coverage gate: the exact baseline and the ratchet rule

The gate is `python -m pytest -q --cov=aegisgraph --cov-report=term-missing
--cov-fail-under="${COVERAGE_FAIL_UNDER}"`.

- **Measured baseline at commit `33f96cc`** (2026-10-08): **988 / 1043 statements
  = 94.73 %** (55 missed). This is identical on the local Windows interpreter
  (CPython 3.13.14) and inside `python:3.12-slim` (CPython 3.12.15), so the F9
  environment difference does not change the ratio.
- `pytest-cov` **prints** that as `95 %` because it rounds for display. A floor of
  `95` therefore fails on the real baseline by three statements — verified:
  `--cov-fail-under=95` exits non-zero with
  `Required test coverage of 95% not reached. Total coverage: 94.73%`.
- `COVERAGE_FAIL_UNDER` is set to **94** in the workflow `env:` block. The floor is
  a **ratchet**: it may only move up. Lowering it requires a written justification
  in the same commit. The 55 missing lines are defensive `raise ValueError`
  branches in `backend/aegisgraph/{contracts,policy,engine,app}.py`; padding tests
  purely to clear the number is explicitly rejected.
- Reproduce the exact figure locally:

  ```sh
  python -m pytest -q --cov=aegisgraph --cov-report=term-missing
  ```

## Reproducing each gate locally

```sh
# quality
python -m ruff check backend tests scripts
python -m mypy
python -m pytest -q --cov=aegisgraph --cov-report=term-missing --cov-fail-under=94

# security (installs nothing into the project; tools are dev-only)
python -m pip install pip-audit bandit
python -m pip_audit -r requirements.lock --strict --progress-spinner off
python -m bandit -r backend -q --severity-level medium

# container
docker build --provenance=false --sbom=false -t aegisgraph:ci .
docker run ... --read-only ... aegisgraph:ci        # see docs/ops/container.md
python scripts/generate_sbom.py --image aegisgraph:ci

# kubernetes (kubeconform is optional but reproducible: pinned + checksum-verified)
python -m pip install kubernetes-validate pyyaml
python scripts/install_kubeconform.py --dest artifacts/tools
python scripts/validate_k8s_manifests.py --validator both \
    --kubeconform artifacts/tools/kubeconform.exe

# compose
cp .env.example .env && docker compose config --quiet && rm -f .env
```

## Pinned actions

Actions are pinned to immutable commit SHAs (resolved 2026-10-08 with
`git ls-remote https://github.com/<owner>/<repo> refs/tags/<tag>`):

| Action | Version | Commit |
| --- | --- | --- |
| `actions/checkout` | v4 | `11d5960a326750d5838078e36cf38b85af677262` |
| `actions/setup-python` | v5 | `a26af69be951a213d495a4c3e4e4022e16d87065` |
| `actions/upload-artifact` | v4 | `ea165f8d65b6e75b540449e92b4886f43607fa02` |

The container build and smoke test use the runner's stock Docker daemon
(`docker build`, `docker run`) rather than `docker/build-push-action`, to keep the
action surface minimal; no registry push happens in M4.

## Tool versions used for the local runs

| Tool | Version |
| --- | --- |
| Python (dev host) | CPython 3.13.14 |
| Python (image / CI) | CPython 3.12.15 |
| pytest / pytest-cov / coverage | 9.1.1 / 7.1.0 / 7.16.2 |
| ruff | 0.16.1 |
| mypy | 2.4.0 |
| pip-audit | 2.10.1 |
| bandit | 1.9.4 |
| kubernetes-validate | 1.36.0 |
| kubeconform (pinned installer) | 0.7.0 |
| Docker Engine / Compose | 29.6.2 / v5.3.1 |

## What is not verified here

- **GitHub-hosted execution of the workflow.** No run was executed on GitHub.
  Every step was reproduced locally on Windows and (for the test/quality jobs) in
  `python:3.12-slim`. To verify: push the branch and read the `ci` run, or run
  `act -j quality` with a Docker daemon (**unverified** — `act` is not installed).
- **`actions/upload-artifact` behaviour** (retention, compression) is unverified
  locally; the artifact contents are what `make sbom` and the digest steps emit.
- **pip-audit's live advisory database** changes over time; a green run today does
  not guarantee a green run tomorrow. The lock pins are what get audited.
