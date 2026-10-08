# CI: gates, local reproduction, and what is not verified

Owner: Agent E (DevSecOps). Workflow: `.github/workflows/ci.yml`.

Every gate below has a locally-run equivalent. Anything that only runs on a
GitHub-hosted runner is marked **unverified** with the reason.

## Jobs

| Job | What it proves | Local equivalent |
| --- | --- | --- |
| `quality` | `ruff`, strict `mypy`, and `pytest` with the coverage gate, against a PostgreSQL 17 service (so the `db` tests run) | `make gates` (see the database note below) |
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

## Coverage gate: the exact measurement and the ratchet rule

The gate is `python -m pytest -q --cov=aegisgraph --cov-report=term-missing
--cov-fail-under="${COVERAGE_FAIL_UNDER}"`, run against a PostgreSQL 17 service.

- **Measured at commit `4350af3`** (2026-10-08, `python:3.12-slim`, PostgreSQL 17,
  the `db`-marked tests enabled): **454 collected, 452 passed, 2 skipped →
  2612 / 2709 statements = 96.42 %** (97 missed). The two skips need the
  untracked `.sentinel_reference` checkout, which a clean clone does not have.
- **With no database** the 12 `db` tests skip and the ratio collapses to
  **2514 / 2709 = 92.80 %** (195 missed). That is why the floor is also the guard
  that the database tests actually ran: a silent skip cannot pass at 95.
- `COVERAGE_FAIL_UNDER` is set to **95** in the workflow `env:` block, below the
  measured 96.42 % but above the no-database ratio. The floor is a **ratchet**: it
  may only move up. Lowering it requires a written justification in the same
  commit. (Before M2 the same suite measured 94.73 % at `33f96cc`, with no
  database tests at all; the floor was 94 then and is raised, never lowered.)
- A reviewer building the same commit with the `.sentinel_reference` checkout
  present measured 96.68 % (2619/2709); the 0.26 pt difference is exactly the two
  `.sentinel_reference` tests.
- Reproduce both figures locally (see `docs/ops/compose.md` for the database):

  ```sh
  export AEGISGRAPH_TEST_DATABASE_URL='postgresql+psycopg://aegisgraph:local-only@127.0.0.1:15532/aegisgraph'
  python -m alembic upgrade head                 # DATABASE_URL, see docs/ops/migrations.md
  python -m pytest -q --cov=aegisgraph --cov-report=term-missing   # 96.42 %
  unset AEGISGRAPH_TEST_DATABASE_URL
  python -m pytest -q --cov=aegisgraph --cov-report=term           # 92.80 %, gate fails
  ```

## Reproducing each gate locally

```sh
# quality (needs PostgreSQL 17 for the `db` tests; see docs/ops/compose.md)
python -m pip install -r requirements.lock && python -m pip install -e ".[dev]"
python -m pip install pyyaml          # needed by tests/, not yet in the [dev] extra
export DATABASE_URL='postgresql+psycopg://aegisgraph:local-only@127.0.0.1:15532/aegisgraph'
export AEGISGRAPH_TEST_DATABASE_URL="$DATABASE_URL"
python -m alembic upgrade head
python -m pytest -q -m db                       # these must RUN, not skip
python -m ruff check backend tests scripts
python -m mypy
python -m pytest -q --cov=aegisgraph --cov-report=term-missing --cov-fail-under=95

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
| PyYAML (installed explicitly by CI) | unpinned — latest at install time; see the proposal below |
| PostgreSQL (CI service and Compose stack) | 17 |
| Docker Engine / Compose | 29.6.2 / v5.3.1 |

**Known gap:** `tests/test_benchmark_sentinel_adapter.py` imports PyYAML
conditionally, but PyYAML is declared in neither `[project.optional-dependencies]
dev` nor `requirements.lock`, so a developer following the README gets two skips
and one failure. The `quality` job installs it explicitly to keep CI green.
Adding `pyyaml` to the `[dev]` extra (or to the lock) is proposed in the M4
handoff — `pyproject.toml` and `requirements.lock` are outside this change's
write scope.

## What is not verified here

- **GitHub-hosted execution of the workflow.** No run was executed on GitHub.
  Every step was reproduced locally on Windows and (for the test/quality jobs) in
  `python:3.12-slim`. To verify: push the branch and read the `ci` run, or run
  `act -j quality` with a Docker daemon (**unverified** — `act` is not installed).
- **`actions/upload-artifact` behaviour** (retention, compression) is unverified
  locally; the artifact contents are what `make sbom` and the digest steps emit.
- **pip-audit's live advisory database** changes over time; a green run today does
  not guarantee a green run tomorrow. The lock pins are what get audited.
