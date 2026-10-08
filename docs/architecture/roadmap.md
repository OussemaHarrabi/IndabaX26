# Roadmap — program milestones M0–M8

The program's milestone list is **authoritative**; this roadmap maps the platform
work onto it. M0 is defined by the orchestrator's baseline report
(`docs/evidence/m0-baseline-report.md`, orchestrator-owned). The milestone
definitions below were confirmed by the orchestrator on 2026-10-08 (an earlier
draft numbering is superseded).

Status vocabulary: `implemented` / `partial` / `proposed`. Blocked cells name the
missing tool and the command that would unblock them. Dates are deliberately
omitted: each milestone gates on its exit criteria, not on a calendar.

## 1. Milestone overview

| Milestone | Program scope | Outcome | Depends on | Primary ADR | Status (2026-10-08) |
| --- | --- | --- | --- | --- | --- |
| **M0** | Charter + baseline | Intake, baseline reproduced, charter, architecture, threat model, ADRs, legacy record, ledger skeleton | — | all | `implemented` (closed) |
| **M1** | Contracts + enforcement | Native versioned contracts with a policy/code revision in every decision; legacy adapter isolated; enforcement binding and integration SDK | M0 | ADR-0006 | `implemented` — contract, enforcement SDK, bounded input and strict confirmation landed (`4013b59`, `7502df3`); legacy suite re-checked decision-identical |
| **M2** | Auth + policy + audit store | Authentication and tenancy; versioned policy; durable append-only receipt/audit store | M1 | ADR-0001, ADR-0002 | `partial` — the dependency stack is merged (`4b9eb5c`: PostgreSQL/SQLAlchemy/Alembic in `requirements.lock`); no migration, store or auth evidence yet, so F1–F3 stay open |
| **M3** | Observability + reliability | OpenTelemetry, Prometheus, Grafana, SLOs, fail-closed guarantees under load | M1, M2 | ADR-0003 | `proposed` — the Compose stack already ships collector, Prometheus and Grafana services, but no instrumentation claim is verified |
| **M4** | CI/CD + containers + deployment | Pipelines and gates; hardened Compose stack; Kubernetes manifests validated and smoke-tested | M1, M2 | ADR-0005 | `implemented` with two named gaps: **no GitHub-hosted CI run has ever executed**, and **no cluster smoke test** (`kind` absent) |
| **M5** | Evaluation framework + benchmark data | Native evaluation schema authoritative; versioned legacy adapter; benchmark data + reachability gate | M1 | ADR-0004 | `implemented` — schema, 60-scenario dataset, deterministic scoring, sealed holdout; **scripted adapter only**, no holdout run |
| **M6** | Empirical campaign | Real-model runs, multi-seed variance, component ablations, generalization | M2, M5 | ADR-0004 | `proposed` — blocked: no `ollama`, GPU or paid API |
| **M7** | Independent review | Adversarial and security review of the new surfaces; reproducibility audit | M3, M4, M6 | all | `proposed` — the M0 review covered the pre-M1 boundary only |
| **M8** | Docs + demo + release | Documentation, demo, versioned release, provenance manifest | M5, M6, M7 | all | `proposed` |

### M0 execution status (closed)

- **Entry:** legacy baseline `649f65a` reproduced in the integration worktree.
- **Exit:** `AGENTS.md`, `PRODUCT.md`, `README.md`, system context, threat model,
  six ADRs, roadmap, legacy record + evidence map, and the ledger skeleton merged;
  `python -m pytest -q` green.
- **Blocked:** nothing.

## 2. Dependency graph

```mermaid
flowchart LR
  M0 --> M1
  M1 --> M2
  M1 --> M5
  M2 --> M3
  M2 --> M4
  M2 --> M6
  M5 --> M6
  M3 --> M7
  M4 --> M7
  M6 --> M7
  M5 --> M8
  M6 --> M8
  M7 --> M8
```

Hard ordering rules:

1. **Contracts + enforcement (M1) precede everything.** Every later milestone
   imports the versioned request/response/receipt models, and every receipt must
   carry the policy version and code commit that produced it (see the M0
   reproduction finding in [`../evidence/ledger.md`](../evidence/ledger.md) row
   L14). Changing contracts after M2 forces a migration and invalidates stored
   receipts.
2. **Auth + policy + audit store (M2) precede observability and deployment.**
   Auth decisions, policy versions and telemetry exports all persist; they need a
   stable schema.
3. **Evaluation framework (M5) can run in parallel with M2–M4** — it depends only
   on M1 — but its native results are not a release gate until M8.
4. **The empirical campaign (M6) needs M5 (harness) and M2 (stored policy/code
   revision in every result).**
5. **Independent review (M7) follows the empirical campaign and a deployable
   stack**; it reviews evidence, not intentions.
6. **Release (M8) is last.**

## 3. Milestone detail

### M0 — Charter and baseline *(complete)*

Baseline reproduced (`187 passed`, Ruff and mypy clean), charter and architecture
written, ADRs proposed, legacy evidence mapped, ledger seeded. See the handoff
for the exact commits.

### M1 — Contracts + enforcement *(complete)*

- **Entry:** M0 merged. Baseline suite green.
- **Status:** landed (`4013b59`, `7502df3`). Evidence and measured numbers are in
  the ledger, section B (rows P1, P6, P11–P14): the generic surface carries
  version, policy set, request/receipt identity and both digests; eleven live
  requests emitted eleven decision records whose `receipt_id` matched the
  response; the enforcement SDK refused a tampered action with `digest_mismatch`;
  a 1.2 MB body returned 413 and the 880k-character adversarial request decided in
  37 ms on the local host. The legacy suite is decision-identical to the M0
  recheck (ledger L16).
- **Work:** extract a versioned native decision/receipt schema; carry an explicit
  **policy version and source code revision** in every decision, receipt,
  scorecard and artifact; isolate the legacy SENTINEL wire contract behind a
  `legacy/` adapter so both evolve without drift; build the enforcement adapter
  that refuses an action whose digest does not match the receipt, plus the
  integration SDK (escalation resume, rewrite re-validation).
- **Exit:** contract tests for both surfaces; no scenario/tenant id in a decision
  path; legacy wire contract byte-compatible; a digest-mismatched action is
  refused; an escalated action executes only after a matching confirmation.
- **Risk:** shared contracts have the highest blast radius — single writer only.
- **Security exit:** the F4–F7 regression criteria are covered by tests (see the
  findings map immediately below); F1–F3 stay open by design until M2.
- **ADR:** ADR-0006.

### Security findings → milestones

The M0 adversarial review produced 10 findings, `F1`–`F10`, registered with their
severities, preconditions and per-finding regression criteria in
[`../evidence/security-findings.md`](../evidence/security-findings.md). That
register is the source of record (orchestrator-owned; read-only here); this map
only assigns each finding to the milestone that closes it.

| Finding | Severity | Subject | Closed in |
| --- | --- | --- | --- |
| F1 | high (critical if internet-reachable) | Unauthenticated decision boundary; caller supplies every security-relevant input | M2 |
| F2 | high | Confirmation self-granted inside the same envelope | M2 |
| F3 | high | Attacker-declared trust/sensitivity labels and policy facts | M2 |
| F4 | high | Algorithmic-complexity DoS in claim scanning | **M1** |
| F5 | medium | Unbounded request body | **M1** |
| F6 | medium | Non-injective canonical-digest matching; unbound, unexpiring, reusable grants | **M1** (new surface only) |
| F7 | medium | No decision identity, receipt or audit record at the wire boundary | **M1** partially (identity + emitted record); M2 owns the durable store |
| F8 | low | Dependency pins carry no hashes | M4 |
| F9 | medium (evidence fidelity) | Suite environment differs from the shipped image | M3 (CI runs the suite in the image) / M4 |
| F10 | low | Application directory writable by the runtime user | M4 |

**M1 closes F4, F5, F6 on the new surface and F7 partially** (identity plus one
emitted decision record; the append-only store is M2's). **M1 leaves open**
F1, F2 and F3, which M2 closes with authenticated, tenant-scoped policy and
server-issued grants — an unauthenticated body cap or digest binding is not an
authorization control. F8 and F10 close in M4 (hashed dependency pins, read-only
root filesystem); F9 remains open until CI runs the suite inside the built image
(M3/M4). F6's **legacy** matching rule is deliberately unchanged in M1: any change
there requires a new evaluation artifact, never an edit of the frozen scorecards
in [`../evidence/ledger.md`](../evidence/ledger.md).

**Landed.** M1's four fixes have landed and are verified in the ledger
(P11–P14): F4 and F5 by the bounded scan and the 413 body cap, F6 by strict
confirmation binding on the generic surface, F7 by the decision identity and the
emitted record (the durable store remains M2's). The register's own `open`/`fixed`
statuses are the orchestrator's to update; this roadmap records only which
milestone owns each finding.

### M2 — Auth + policy + audit store

- **Entry:** M1 frozen contracts.
- **Status:** `partial` — only the dependency stack has landed
  (`4b9eb5c` adds PostgreSQL/SQLAlchemy/Alembic pins to `requirements.lock`, with
  license and vulnerability review). No migration, no store round-trip and no
  authentication evidence exists yet, so **F1–F3 stay open**. The coverage
  baseline moved with those pins, which is why every coverage number must be
  quoted with its commit (ledger P15).
- **Work:** OIDC/JWT for interactive principals plus scoped service tokens for
  machine callers (ADR-0002); per-tenant authorization on every read and write;
  an explicit policy store with versions and an audit trail; PostgreSQL +
  SQLAlchemy 2 + Alembic with an append-only `receipts` table keyed by request id
  and action digest (ADR-0001).
- **Exit:** migration from empty DB applies cleanly; a receipt round-trips and a
  mutated receipt is rejected; unauthenticated access rejected; cross-tenant
  reads denied; policy version changes are auditable and attributable.
- **Blocked locally:** no host `psql`; the intended path is containerized
  PostgreSQL via Docker. Until then the store is exercised through the container
  only — do not substitute SQLite and call it verified.
- **ADRs:** ADR-0001, ADR-0002.

### M3 — Observability + reliability

- **Entry:** M2 store and principals.
- **Work:** OpenTelemetry traces across boundary → adapter → kernel → store;
  Prometheus counters/histograms (decisions by verdict/reason, latency, failures,
  enforcement outcomes); Grafana dashboards; SLOs for decision latency and
  fail-closed rate; load and failure-injection tests proving the gateway stays
  fail-closed.
- **Exit:** a decision emits a trace and increments metrics; dashboards render
  real data; no content or secrets in telemetry attributes; the fail-closed
  invariant holds under fault injection.
- **ADR:** ADR-0003.

### M4 — CI/CD + containers + deployment *(complete, two gaps named)*

- **Entry:** M1, M2.
- **Status:** landed (`6e4f6b2`, `891483d`, `79f9e59`, `40404a0`, `3889f10`).
  Verified here: the workflow defines five jobs with SHA-pinned actions and a
  coverage floor of 94 (measured 95.03 % = 1358/1429 at `3353886`); the image
  builds reproducibly and runs non-root (uid 10001) with a read-only rootfs
  serving `/healthz` and a decision; `deploy/k8s` renders 7 objects and passes 7
  schema checks under two validators plus 22 policy assertions; the Compose
  configuration parses to five services; the SBOM digest reproduces. Numbers and
  caveats are in the ledger, section C.
- **Gaps:** **no GitHub-hosted CI run has ever executed** (blocked: the workflow
  is only reproducible locally until the branch is pushed), and **no cluster
  smoke test** — `kind` is absent. Neither gap is papered over by a local run.
- **Work:** CI pipelines running tests, Ruff, mypy and the reachability gate;
  hardened Compose stack (service + PostgreSQL + Prometheus + Grafana); container
  image build and live run verification; Kubernetes manifests validated by schema
  tooling.
- **Exit:** Compose stack starts from a clean machine and passes a smoke test;
  image runs non-root with the documented hardening; Kubernetes manifests
  validate (`kubectl apply --dry-run=server` or equivalent).
- **Blocked:** Kubernetes **cluster smoke test** needs `kind` (not installed).
  Command when available:
  `kind create cluster --name aegisgraph && kubectl apply -k deploy/k8s`.
  Report this cell as `blocked`.
- **ADR:** ADR-0005.

### M5 — Evaluation framework + benchmark data *(complete, scripted only)*

- **Entry:** M1 contracts.
- **Status:** landed (`f8e6004`, `7138aa4`, `d2856a4`, `75966b2`). Verified here:
  the dataset validates (`RESULT: PASS`, 60 open scenarios, 42/18 splits, six per
  family over ten families, dataset sha256 `7e916a11…`, largest request 2118 B);
  a scripted run against the M1 gateway reproduces the published scoring digest
  `4373896…` and two `--json` scorings are byte-identical; run directories are
  created once and refuse to be overwritten; the 20-scenario holdout is sealed
  (ciphertext `52f67318…`) and verifies without the custodian passphrase; every
  committed legacy scorecard reports `metrics reproduced: True` and
  `digest reproduced: True` through the read-only adapter. See the ledger,
  section D.
- **Caveats:** the only adapter that runs here is `scripted` — every number is a
  scripted number; the holdout is sealed and unrun; 20 holdout scenarios support
  a direction, not a confidence interval.
- **Work:** a native evaluation schema authoritative for platform claims; the
  legacy SENTINEL suite preserved behind a versioned, read-only adapter; the
  allow-all reachability control generalized into the native harness; benchmark
  data versioned with digests; optional Inspect AI integration (e.g. AgentDojo).
- **Exit:** a native run produces a scorecard with a deterministic digest and the
  policy/code revision; the legacy adapter reproduces the preserved baseline
  without editing the legacy artifacts; reachability gate mandatory in CI.
- **ADR:** ADR-0004.

### M6 — Empirical campaign

- **Entry:** M2 (stored revision), M5 (harness).
- **Work:** real-model runs on the pinned and native suites; multi-seed variance;
  component ablations; generalization to an unseen tool schema; every result
  labelled synthetic or real with its revision fingerprint.
- **Exit:** a reported campaign with variance/confidence, ablations, and a
  reproducibility package a third party can re-run.
- **Blocked:** real-model runs need `ollama` (or an authorized API). Neither is
  available; synthetic runs are labelled and cannot substitute.
- **ADR:** ADR-0004.

### M7 — Independent review

- **Entry:** M3, M4, M6.
- **Work:** adversarial and security review of the new surfaces (API boundary,
  store, auth, telemetry); reproducibility audit of every headline claim;
  independent re-run of the evaluation gates.
- **Exit:** findings triaged with severity; every "complete" claim independently
  verified or explicitly blocked; the ledger is complete.

### M8 — Docs + demo + release

- **Entry:** M5, M6, M7.
- **Work:** documentation truth pass; a demo of a decided, enforced action with a
  receipt; versioned release with a provenance manifest (paths + SHA-256);
  dependency audit; migrate the legacy evidence links.
- **Exit:** every headline claim in [`../evidence/ledger.md`](../evidence/ledger.md)
  is `verified` with an artifact, digest, command and commit, or explicitly
  `blocked` with the missing tool.

## 4. Blocked-by-tooling ledger

| Capability | Milestone | Status | Missing tool | Unblock command / condition |
| --- | --- | --- | --- | --- |
| Kubernetes cluster smoke test | M4 | blocked | `kind` | `kind create cluster --name aegisgraph` |
| PostgreSQL on the host | M2 | blocked | `psql` | containerized PostgreSQL (Docker) is the intended path |
| Real-model evaluation reruns | M6 | blocked | `ollama` | install `ollama` + `qwen3:8b`, or authorize an API |
| Paid-model benchmarking | M6 | blocked | API credentials | explicit owner authorization |
| GitHub-hosted CI execution | M4 | blocked | no run has executed on GitHub; `act` not installed | push the branch and read the `ci` run, or `act -j quality` |
| Holdout result | M5/M6 | blocked | the seal may be opened only by the custodian after the policy freeze | follow `docs/benchmark/holdout.md` §4, then open once with the recorded command |
| Docker-engine live run | M4 | verified | — | done: `docker build` + `docker run --read-only` (ledger P16) |

## 5. Single-writer map

One writer per path. Multiple agents may work in parallel only on disjoint files.
The orchestrator arbitrates conflicts and owns the shared files.

### Orchestrator-owned (nobody else edits)

| Path | Reason |
| --- | --- |
| `pyproject.toml`, `requirements.lock` | Dependency and interpreter contract |
| `benchmark.lock` | Pinned legacy benchmark identity |
| `Dockerfile`, `.dockerignore` | Build contract |
| `.github/**` | CI and gates |
| `backend/aegisgraph/contracts.py` | Shared canonical contract (highest blast radius) |
| `docs/evidence/m0-baseline-report.md` | Orchestrator baseline record |
| `AGENTS.md`, `PRODUCT.md`, `README.md` | Shared operating/product docs |
| `docs/architecture/**` | Charter (this agent, M0 only) |

### Per-milestone ownership

Landing milestones record the paths that actually carried the work; unstarted
milestones keep their proposed allocation.

| Milestone | Writer role | Owned paths |
| --- | --- | --- |
| M1 | Contracts/API implementer + integration | **landed:** `backend/aegisgraph/{api_v1,enforcement,adapter,demo_tools}.py`, `backend/aegisgraph/{app,sentinel,contracts,engine}.py`, `docs/api/**`, `examples/**`, `tests/test_{api_v1,enforcement,bounds,confirmation_strict}.py`, `evaluation/m1-recheck/**`. The originally proposed `legacy/**` and `sdk/**` packages were not created — the legacy wire stays in `sentinel.py` and the SDK in `enforcement.py`, so there is no second convention to maintain |
| M2 | Persistence engineer + security engineer | proposed: new `backend/aegisgraph/store/**`, `migrations/**`, new `backend/aegisgraph/auth/**`, new `backend/aegisgraph/policy_store/**`, `tests/test_store.py`, `tests/test_auth.py`; the pins landed early in `requirements.lock` (`4b9eb5c`, orchestrator-owned) |
| M3 | Platform/telemetry engineer | proposed: new `backend/aegisgraph/telemetry/**`, `deploy/observability/**`, `tests/test_telemetry.py` |
| M4 | Platform engineer | **landed:** `.github/workflows/ci.yml` (with orchestrator), `compose.yaml`, `.env.example`, `Makefile`, `Dockerfile`, `.dockerignore`, `deploy/**`, `docs/ops/**`, `scripts/{generate_sbom,validate_k8s_manifests,install_kubeconform}.py` |
| M5 | Evaluation engineer | **landed:** `benchmark/**` (schema, validators, dataset, splits, runner, scoring, seal, adapters), `scripts/bench_*.py`, `docs/benchmark/**`, `tests/test_benchmark_*.py`; `evaluation/**` stayed add-only (the M1 recheck added a directory, it edited nothing) |
| M6 | Evaluation engineer + research analyst | `evaluation/campaign/**`, `docs/research/**` (research docs already landed) |
| M7 | Independent reviewers | read-only findings; `docs/review/**` |
| M8 | Orchestrator + documentation writer | release manifest, `docs/evidence/ledger.md`, release notes |

### Never shared mid-flight

- The legacy evidence under `evaluation/real-qwen/**` is **add-only**. New
  artifacts get new names; existing digests are never recomputed or edited.
- `backend/aegisgraph/engine.py` is a single-writer file: policy changes are one
  writer at a time, with a component ablation and a matched evaluation rerun.
- Any change to a shared contract (`contracts.py`, `sentinel.py`) must land
  before dependent milestone work begins, not in parallel with it.

## 6. Gate for every milestone

Each milestone exit runs, in the integration worktree: `python -m pytest -q`,
`python -m ruff check backend tests`, `python -m mypy`, plus the milestone's own
smoke run. The coverage gate is the same test command plus
`--cov-fail-under=94` (the ratchet floor in CI). Every number quoted from a run —
coverage, latency, a digest — must name the commit it was measured at, because
three coverage baselines and one moved image ID were observed across M1–M5 (see
[`../evidence/ledger.md`](../evidence/ledger.md) rows P15 and P16). The
orchestrator independently verifies each "complete" claim and updates
`docs/evidence/ledger.md` before the milestone is closed.
