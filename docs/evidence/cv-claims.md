# CV claims, bounded and verifiable

## How to read this

Every bullet below is a claim you can defend in an interview by opening the
named artifact and re-running the named command. Each bullet states a **claim**,
its **evidence** (artifact + command + commit) and its **limitation** in the same
breath, so no claim travels without its boundary.

Rules this document obeys:

1. **No claim without an artifact.** Every bullet names a file in the tree and a
   command that exists. Where a digest is quoted, it is the digest verified at
   this commit, not one copied from a summary.
2. **Rows still `pending` or `blocked` in [`ledger.md`](ledger.md) are excluded**
   from the bullets and re-stated in *Not claimed (yet)*. The ledger is the
   authority for what is promoted; a bullet never promotes a row by prose.
3. **The commit is part of the claim.** Coverage, latency and image numbers are
   quoted with the commit they were measured at, because M1–M5 produced three
   different coverage baselines and two image IDs.
4. **Legacy numbers are frozen** at their measured commits and are never
   recomputed under new code.

Audience tags: `[ind-tech]` industrial technical role · `[ind-hybrid]`
industrial hybrid role (engineering + evaluation) · `[res-tech]` research
technical role · `[res-deep]` research deep role. Tags mark which bullet is worth
raising for which audience; the evidence is the same for all.

Reference revision: the integration branch `feature/aegisgraph-industrial-research`
at `c647588`. Later commits are named where a row pins one.

---

## Capability: Agent-security gateway design

**A. A four-verb, fail-closed decision gateway over inert candidate actions.** `[ind-tech]`
**Evidence.** `backend/aegisgraph/engine.py` (the policy kernel: provenance
resolution, authorization, confirmation, sensitive-flow redaction, rewrite
re-validation); `python -m pytest -q tests/test_policy_kernel.py`; commit
`ab4b30c` on the integration tip `c647588`. Ledger row **L8** (legacy core
passes its suite).
**Limitation.** Deterministic rule outputs, not a learned or calibrated detector;
the legacy headline is one seeded run, and nine of the 31 legacy attacks never
reached under allow-all, so they are not effectiveness evidence (L1).

**B. A caller-side enforcement SDK with eight ordered refusal reasons that never invokes the executor on a refusal.** `[ind-tech]`
**Evidence.** `backend/aegisgraph/enforcement.py`, `examples/enforce_decision.py`;
`python examples/enforce_decision.py` → observed
`tampered action: REFUSED [digest_mismatch] the candidate action is not the action the receipt was issued for`;
commit `3313641`, integration tip `c647588`. Ledger rows **P6**, **P12**.
**Limitation.** The executor is the inert simulated toolbox — no real side effect;
on the legacy surface receipt validity is caller-side only.

**C. Bounded request and bounded per-request CPU: an oversized body is refused before parsing, and an unbounded narrative scan fails closed instead of running.** `[ind-tech]`
**Evidence.** `backend/aegisgraph/app.py` (`AEGISGRAPH_MAX_BODY_BYTES`, default
1 MiB), `backend/aegisgraph/engine.py` (one source profile per distinct source
plus a per-pass sentence budget), `tests/test_bounds.py`;
`python -m pytest -q tests/test_bounds.py`; commits `4013b59` (P13), `5480a77`
and `36a279a` (P25, the H2-01 fix). Ledger rows **P13**, **P25**.
**Limitation.** Latency figures are host-dependent; the guard bounds *scans*, and
a source that is well-formed but genuinely non-verifiable is blocked
(`NARRATIVE_SCAN_BUDGET_EXCEEDED`) rather than verified.

**D. Strict confirmation binding — a grant must match the run, the step, the exact execution digest and an expiry, and must have been issued.** `[ind-tech]` `[ind-hybrid]`
**Evidence.** `docs/api/contracts.md` §2 (mode table), `tests/test_confirmation_strict.py`,
`tests/test_confirmation_channel.py`; live reproduction in
[`../demo/demo-script.md`](../demo/demo-script.md) step 3
(`escalate / CONFIRMATION_REQUIRED` → `allow / CONFIRMATION_VERIFIED`);
commits `4013b59` (P14), `5480a77` (P29), `540af18` (H2-03). Ledger rows **P14**,
**P27**, **P29**; findings F2 and H2-03 closed.
**Limitation.** The frozen legacy surface keeps the lossy canonical-digest
matching the pinned harness depends on (documented in `docs/api/contracts.md` §2).

**E. Adversarial review drove concrete fixes to the gateway, with a regression test each.** `[ind-hybrid]` `[res-tech]`
**Evidence.** `docs/evidence/security-findings.md` (the register),
`docs/evidence/reviews/M1-M5-adversarial-security-review.json` and
`docs/evidence/reviews/M2-surface-adversarial-security-review.json`; read the
register, then `python -m pytest -q tests/test_bounds.py tests/test_authorization_policy.py tests/test_confirmation_channel.py`;
commits `444ff4f`, `fb6e42a`, `2484b09`, merged at `29fa3ba`. Ledger rows
**P25–P29** (second review), **P54–P62** (third review; H3-01 … H3-09, all
`verified` — seven fixed, two accepted with a documented reason), and **P63**,
**P64** (the two corrective rounds, the second carrying the schema migration
`0002_receipt_decision_body` whose incremental `0001 → 0002` upgrade applied
cleanly with `alembic check` reporting no new operations).
**Limitation.** Seven of the nine third-review findings were **fixed** and two
(H3-06, H3-08) are `accepted` with a stated residual (a development-only
loopback misconfiguration; one bounded 1 MiB read per anonymous request); the
fixes were verified by the orchestrator, not re-run by this author.

## Capability: Typed, versioned API contracts

**F. A versioned `aegisgraph/v1` decision contract: seven legacy fields plus eight server-computed identity fields, with a machine-readable schema and a build-identity endpoint.** `[ind-tech]` `[ind-hybrid]`
**Evidence.** `docs/api/contracts.md`, `docs/api/decision.schema.json`,
`backend/aegisgraph/api_v1.py`, `tests/test_api_v1.py`; live
`GET /api/v1/version` → `{"api_version":"aegisgraph/v1","policy_set":{"id":"aegisgraph-default","version":"1"},...}`
and `POST /api/v1/decisions` (see [demo step 1](../demo/demo-script.md)); commits
`4013b59`, `7502df3`, `7147eb3`. Ledger rows **P1**, **P11**.
**Limitation.** The code revision is **not** inside the decision record; it
reaches an artifact only through `/api/v1/version` and the benchmark manifest.

**G. The reported policy identity is server-resolved; a version the server does not hold is refused with `422 POLICY_SET_UNKNOWN` and writes no receipt.** `[ind-tech]`
**Evidence.** `backend/aegisgraph/access.py` (`effective_policy`),
`docs/api/auth.md` §6, `tests/test_authorization_policy.py`;
`python -m pytest -q tests/test_authorization_policy.py`; commits `940ed13`,
`540af18`. Ledger row **P26**; finding H2-02 closed.
**Limitation.** The follow-up H3-04 (a `policy:context_override` holder naming an
unstored identity) was **fixed** at `2484b09` (merged `29fa3ba`): an unbacked
override is now reported as `{"id":"caller-override","version":"<32 hex of the
document digest>"}` with no caller string carried verbatim (ledger **P57**).

**H. Idempotency is explicit: the caller's `request_id` is preserved by design as the tenant-scoped idempotency key, and a conflicting reuse is refused with `409 REQUEST_ID_CONFLICT`.** `[ind-tech]`
**Evidence.** `docs/api/receipts.md` §2, `tests/test_api_v1.py`
(two pinning tests); `python -m pytest -q tests/test_api_v1.py`; commit
`940ed13`. Ledger row **P28**; finding H2-05 closed as a documented decision.
**Limitation.** The follow-up H3-02 (an idempotent replay returning a fresh
decision under the stored `receipt_id`) was **fixed** at `2484b09` (merged
`29fa3ba`): two identical requests now return the same `receipt_id` and
byte-identical bodies, a receipt whose body cannot be reconstructed returns
`409 RECEIPT_NOT_RECONSTRUCTIBLE`, and the incremental `0001 → 0002` migration
applied cleanly on an existing database (ledger **P55**).

## Capability: Authentication, authorization and tenant isolation

**I. JWT/JWKS and scoped opaque service tokens, six scopes with role expansion, a per-credential trust ceiling, tenant identity taken from the credential, and cross-tenant reads answered `404`.** `[ind-tech]` `[ind-hybrid]`
**Evidence.** `backend/aegisgraph/auth.py`, `docs/api/auth.md`,
`tests/test_authentication.py`; live reproduction (anonymous `401`, wrong-scope
`403`, cross-tenant `404`, ceiling `403 TRUST_CEILING_EXCEEDED`); commits
`7a87e8b`, `4350af3`, `940ed13`. Ledger row **P3**; finding F1 closed.
**Limitation.** Residual **accepted**: the caller is the source of truth for its
own evidence, bounded by the ceiling. The follow-up H3-01 (the ceiling did not
cover conversation-derived evidence) was **fixed** at `2484b09` (merged
`29fa3ba`): `IMPLICIT_ROLE_TRUST` is now the single source of truth for the
adapter *and* the ceiling, a `user`-role item with no provenance ids is refused
with `403 TRUST_CEILING_EXCEEDED` at the default ceiling, and the same request
succeeds with an `authenticated_user` ceiling (ledger **P54**).

**J. Startup fails closed on insecure production configuration.** `[ind-tech]`
**Evidence.** `backend/aegisgraph/settings.py` (`python -m aegisgraph.settings`),
`docs/api/auth.md` §1;
`AEGISGRAPH_ENV=production python -m aegisgraph.settings` → refusal line, exit `2`;
commit `7147eb3`. Ledger row **P3**; decision **D7**.
**Limitation.** The bundled issuer (`scripts/dev_issuer.py`) is development-only
and labels every artefact `"development-only"`; it is not a production IdP.

## Capability: Durable, append-only audit with migrations

**K. Durable, append-only receipts and audit events in PostgreSQL 17 via SQLAlchemy 2 and Alembic; `UPDATE`/`DELETE` are refused by database triggers.** `[ind-tech]` `[ind-hybrid]`
**Evidence.** `backend/migrations/versions/0001_initial.py`,
`backend/aegisgraph/models.py` (`APPEND_ONLY_STATEMENTS`), `docs/ops/migrations.md`,
`tests/test_postgres_store.py`;
`DATABASE_URL=... python -m alembic upgrade head && python -m alembic check`
(→ `No new upgrade operations detected`); commits `7a87e8b`, `4350af3`, `940ed13`.
Ledger row **P2**; ADR-0001.
**Limitation.** `TRUNCATE` is a privileged DDL operation the row triggers do not
intercept (break-glass, documented); the `db`-marked tests **skip** without a
PostgreSQL and no silent skip can pass the coverage floor (P15).

**L. Retention keeps digests, verdicts, policy and actor identity indefinitely and redacts payload-adjacent metadata after a window; the payload copy is digest-only by default.** `[ind-tech]` `[ind-hybrid]`
**Evidence.** `scripts/retention.py`, `docs/ops/retention.md`,
`tests/test_receipts_api.py`; `python scripts/retention.py` (idempotent, writes one
audit event per affected tenant); commit `7a87e8b`. Ledger row **P2**; decision
**D6**.
**Limitation.** Scheduling is external (cron/CronJob); "deletion" means the
payload-adjacent field is destroyed, not that an audit row is removed.

## Capability: Observability and SLOs

**M. The decision surface is measured on committed, immutable artifacts, and its SLOs are derived from that measurement.** `[ind-hybrid]` `[res-tech]`
**Evidence.** `docs/evidence/performance/m3-load-20261008T210436Z.json` (sidecar
`a8250f2fcfe0fdcda5a3b25b8ca2e6b578054b8d6f3ef357f39bbef36eee8b62`, equal to
`sha256sum` of the committed blob; internal canonical digest
`e437951890bce9837eb75e751fcb04f606ce513456e359bcf81102ded780ce89`),
`docs/ops/slo.md`, `docs/ops/load-testing.md`, `scripts/load_test.py`;
`python scripts/load_test.py --token-file ... --concurrency 16 --duration 20 --warm-up 40 --server-log ...`;
commits `7147eb3` (first harness), `4136382`, `fe46e7d` (corrected harness and
republished baseline).
Observed: 2 986 measured requests (40 warm-up excluded,
`service_side.counts_match_measured: true`), 148.938 req/s, 0 errors,
`{"200": 2986}`, verdict mix 2368 allow / 455 block / 163 escalate; in-process p50
2.302 ms / p95 5.227 ms / p99 7.283 ms. The earlier report
`m3-load-20261008T193951Z.json` is **superseded and must not be quoted**: its
service-side block covered 4 296 samples including the 40 warm-up requests, and its
sidecar digest did not match the committed bytes.
**Limitation.** One developer machine, one `uvicorn` process, in-process store, a
20 s window — **not** production hardware, **not** a month of availability; the
corrected run is also slower (148.9 vs 212.4 req/s) because the host was busy, and
the SLO targets are set above the worse run. The M3 telemetry row **P4** is
promoted to `verified` in the ledger, so the measurement is a ledger claim rather
than an artifact-only observation.

**N. Telemetry is instrumented with content-free, bounded labels, and a telemetry or collector outage cannot change a decision or remove a healthy service from a load balancer.** `[ind-hybrid]`
**Evidence.** `backend/aegisgraph/telemetry.py`, `tests/test_telemetry.py`
(declared label/attribute vocabulary; a canary in the content, run id, user goal
and request id appears in no span attribute, span event or exposition),
`tests/test_failure_injection_telemetry.py`, `docs/ops/observability.md`,
`deploy/observability/grafana/dashboards/aegisgraph-service.json`;
`python -m pytest -q tests/test_telemetry.py tests/test_failure_injection_telemetry.py`;
ledger row **P4** `verified`. Observed: an unreachable collector does not affect
the verdict or reason codes, the failed export increments
`aegisgraph_telemetry_export_failures_total{signal="traces"}`, and `/healthz` and
`/readyz` stay `200`.
**Limitation.** The exporter and dashboards are verified on a single short-lived
collector and a local Prometheus/Grafana, not under sustained production load;
`record_exception=False` means a failure marks a span `ERROR` without attaching
the exception, so a root cause is not in the trace. `/metrics` itself has **no
authentication dependency on the route** — the control is port-level only
(Compose publishes `127.0.0.1:8080`; the Kubernetes NetworkPolicy restricts
ingress), so a deployment that exposes the API port to an untrusted network
exposes the exposition with it (ledger **P80**, `accepted`); the shipped Compose
stack ran in development with `/metrics` on and no explicit auth mode (**P81**,
verified), and a caller-controlled span attribute is bounded in the current
exposition but unbounded in distinct values (**P84**, `accepted`).

## Capability: CI/CD and container hardening

**O. Five CI jobs with SHA-pinned actions — green on GitHub-hosted runners — and a coverage floor enforced against a PostgreSQL service.** `[ind-tech]` `[ind-hybrid]`
**Evidence.** `.github/workflows/ci.yml`, `docs/ops/ci.md`,
`requirements.lock`, `pyproject.toml`;
`python -m pytest -q --cov=aegisgraph --cov-report=term-missing --cov-fail-under=95`
(against PostgreSQL 17), `python -m ruff check backend tests`, `python -m mypy`,
`python -m pip_audit -r requirements.lock --strict`; commits `6e4f6b2`,
`bf02ddc` (floor 95 + database service), `92f6803`, `4b9eb5c`/`60eb2bf`
(dependency additions). Ledger rows **P15**, **P65** — every dependency the
platform added is declared, licence-reviewed and audit-clean (lock blob
`d0bf0f5504aa8c5da890c6913b2b4faa36f5e0476daced5ee7359eefd15730d3`, 39 pinned
entries). The workflow executes on GitHub-hosted runners and is green on the
release tag `v0.1.0-industrial` (`eb33d2c`, run `37846970280`, all five gates)
and on the branch tip at the time of writing (`cb3f82f`, run `37863688964`); the
branch's 29 runs are 10 success / 1 failure (fixed at `cc3a14f`) / 17
concurrency cancellations; the release carries a provenance manifest
(`docs/evidence/release-manifest.json`, `scripts/release_manifest.py`) and notes
— ledger rows **P85**, **P8**.
**Limitation.** `pip-audit`'s live advisory database changes over time, and
finding **F8** stays `accepted` (the lock pins versions, not hashes — the audit
covers CVEs, not integrity); **F9 stays `open`** — the suite is still not run
*inside* the built image, so the "N passed" baseline is evidence about the local
and hosted interpreters, not about the shipped artifact. The 17 cancellations are
concurrency limits, not failures.

**P. A hardened image: non-root (uid 10001), a root-owned read-only `/app`, no pip or compiler, and a read-only-rootfs smoke test that serves a decision.** `[ind-tech]`
**Evidence.** `Dockerfile`, `docs/ops/container.md`;
`docker build --provenance=false --sbom=false -t aegisgraph:local .` then
`docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop=ALL --security-opt=no-new-privileges -p 8080:8080 aegisgraph:local`;
`scripts/generate_sbom.py --deterministic` for the SBOM; commits `ce8db3c`,
`3889f10`, `92f6803`. Ledger rows **P16**, **P18**; finding F10 fixed.
**Limitation.** The image ID is context-sensitive (the portable triple is
commit + `requirements.lock` blob SHA-256 + exact build command); `linux/amd64`
only; no image was pushed to a registry.

**Q. A five-service Compose stack verified end to end — including Prometheus scraping the API's own `/metrics` and Grafana serving the dashboard — plus Kubernetes manifests that pass two independent validators and 29 policy assertions.** `[ind-tech]` `[ind-hybrid]`
**Evidence.** `compose.yaml`, `deploy/observability/prometheus/prometheus.yml`
(the single scrape config, `job_name: aegisgraph-api` → `api:8080/metrics`),
`deploy/observability/grafana/dashboards/aegisgraph-service.json`,
`deploy/k8s/**`, `scripts/validate_k8s_manifests.py`, `docs/ops/compose.md`,
`docs/ops/deployment.md`;
`python scripts/validate_k8s_manifests.py --validator both` → 9 objects, 29 policy
`[PASS]` lines; `docker compose up -d --build` → five healthy services, the
one-shot `migrate` applied `0001_initial`, `up{job="aegisgraph-api"} = 1`, real
`aegisgraph_*` series in Prometheus, and Grafana's 10-panel dashboard resolving
through a healthy datasource; commits `891483d`, `8bf76af` (P7), `79f9e59`,
`c2d99e2` (P17), `92f6803`, and the observability-tree consolidation at `4d51cde`
/ `75fa1b9`. Ledger rows **P7**, **P17**, **P4**.
**Limitation.** **The cluster smoke test is blocked** (ledger **B1**: `kind` is
not installed) — schema and policy validation only, nothing was `kubectl apply`-ed;
the Compose live run is the orchestrator's, not this agent's. The stack ships no
credentials, so `aegisgraph_decisions_total` stays empty until a caller presents a
token; the measured `/api/v1/decisions` traffic was instrumented `422` refusals,
not counted decisions.

## Capability: Evaluation design and statistics

**R. A native evaluation schema and validator are authoritative, and the legacy SENTINEL suite is a read-only adapter over them.** `[res-tech]` `[res-deep]`
**Evidence.** `benchmark/schema.py`, `benchmark/validators.py`,
`benchmark/adapters/sentinel.py`, `docs/benchmark/{scenario,data,evaluation}-card.md`;
`python scripts/bench_validate.py` → `RESULT: PASS` (`errors=0 warnings=0`), and
`from benchmark.adapters.sentinel import verify_all; verify_all("evaluation")`;
commits `f8e6004`, `b0923c6`, `2db482c`. Ledger rows **P5**, **P20**. The dataset
is 60 scenarios (42 development / 18 validation, six per family across ten
families), sha256 `7e916a11981fa6444724dc78558e51561d32a3005b182862efb52b7c5f2cf735`.
**Limitation.** `n = 3` per family supports a direction, not a per-family
confidence interval; projection inferences are tagged `legacy_projection` and
cannot license a native claim. The scorer/splitter defects the reproducibility
audit raised (**P31**, **P34**, **P35**, **P37–P49**) are now fixed and verified
against the cited artifacts.

**S. A native run is scored deterministically, reproduces a committed reference digest, and is written once and never overwritten.** `[res-tech]` `[res-deep]`
**Evidence.** `benchmark/runs/20261008T230000Z-m2-authenticated-full/` (committed;
`score.json` → `deterministic_digest 8d79f032d3018ed0618088b004094d1ba30dfe14605390f375e560b5c04aee13`,
overall asr 0.5000 (15/30), benign task success 0.9667, false-block 0.0556,
`control_licensed` 30, `control_excluded` 0), `scripts/bench_run.py`,
`scripts/bench_score.py`; two `--json` scorings are byte-identical and a
colliding run directory is refused; commits `a94ce6f8` (the run's `code.commit`,
`dirty: false`), `f2222a3`, `2db482c`. The M6 freeze-block-1 campaign run
`benchmark/runs/20261008T203656Z-m6-campaign/` (digest `b6951afb…`) reproduces
from its committed artifacts, and `docs/evidence/m6-campaign.md` records C1–C4.
Ledger rows **P21**, **P22**, **P66**, **P68**.
**Limitation.** `model.kind = scripted` — this measures the **gateway**, not a
model; the intention-to-treat denominator defect (**P31**) is fixed and verified.

**T. The evaluation plan's multiplicity correction is implemented and a confirmatory verdict is gated on it.** `[res-deep]`
**Evidence.** `docs/research/analysis.py`, `docs/research/research-plan.md` §10
(Amendment 1), `docs/research/statistics.md`;
`python docs/research/analysis.py --control evaluation/real-qwen/allow-all-qwen3-8b.json --treatment evaluation/real-qwen/aegisgraph-v5-qwen3-8b.json --by-domain`;
commit `6cbd79d`. Ledger rows **P32**, **P33** (Holm–Bonferroni families; the H3
verdict prints "NOT CONFIRMED — overturned by the Holm-Bonferroni correction").
**Limitation.** The audit's H5.2-gate, minimum-slice and control-liveness findings
(I2-12, I2-13, I2-15 → ledger **P41**, **P42**, **P44**) are now fixed and verified
at the cited benchmark artifacts, not only on the research path.

**U. The holdout is sealed, custody is recorded, and the seal verifies without the custodian key.** `[res-deep]`
**Evidence.** `benchmark/data/holdout/**`, `docs/benchmark/holdout.md`,
`docs/evidence/m5-seal-custody.md`, `scripts/bench_seal.py`;
`python scripts/bench_seal.py verify` → `RESULT: PASS`, `opened: false`; the seal
was rotated after a passphrase exposure (ciphertext `c1a32fb8…`, key outside the
repository); commits `8366e58` (defect), `2cd5926` (rotation), `8d405a8` (custody).
Ledger rows **P23**, **P36**, **P50**.
**Limitation.** The holdout has **never been opened**; its result is blocked
(ledger **B6**) and no item from it is claimed here.

## Capability: Multi-agent program management

**V. An evidence ledger with a strict status vocabulary and per-row artifact, digest, command and commit, backed by four adversarial reviews and two reproducibility audits.** `[ind-hybrid]` `[res-deep]`
**Evidence.** `docs/evidence/ledger.md` (rows L1–L16, P1–P85, B1–B6),
`docs/evidence/reviews/*.json` (six review artifacts: four adversarial security,
telemetry and load reviews, and two reproducibility audits),
`docs/evidence/security-findings.md`;
read the ledger, and hash artifacts as blobs (`git show <commit>:<path> | sha256sum`)
because a Windows checkout rewrites line endings; commits `287acf9`, `d86ac83`,
`444ff4f`, `fb6e42a`, `8d405a8`, `2484b09`. Ledger rows **L15**, **P25–P29**,
**P30–P52**, **P54–P67**, **P68–P85** — including the M6 campaign
reproducibility audit (**P69–P74**), the M3 telemetry/load adversarial review
(**P75–P84**) and the hosted-CI evidence (**P85**).
**Limitation.** Only **P9** (real-model campaign) and **P10** (M7's
reproducibility-audit exit) remain `pending`, and the blocked set is **B1–B4** and
**B6**; the review-driven fixes were verified by the orchestrator, not re-run by
this author; two findings are `accepted` by decision (**P59**, **P61**) and two
more are `accepted` residuals (**P80**, **P84**); the review artifact digests are
**blob** digests, not working-copy digests.

**W. A single-writer workstream map and milestone entry/exit criteria, with the frozen legacy evidence kept separate from the new platform.** `[ind-hybrid]`
**Evidence.** `docs/architecture/roadmap.md`, `docs/architecture/system-context.md`,
`docs/legacy/**`, `docs/evidence/ledger.md` (legacy rows L1–L16 never recomputed);
commits `287acf9` (roadmap), `ac5fcfd` (system context / threat model).
**Limitation.** The roadmap is a plan, and the legacy/industrial separation is
enforced by documentation and process, not by code.

---

## Not claimed (yet)

Deliberately absent from the bullets above. Each line names the ledger row or the
blocker that keeps it out.

- **Real-model campaign results.** Ledger **P9** `pending`; blocked rows **B3**
  (no `ollama`) and **B4** (no paid API). Every committed run — the M5 reference
  and the M6 campaign — records `model.kind = scripted` and says in its own
  `limitations` that it measures the gateway, not a model.
- **The sealed holdout result.** Ledger **B6** `blocked`: the seal may be opened
  once, after the policy freeze, by the custodian; it never has been (P66's freeze
  block left it closed).
- **A cloud deployment.** No image was pushed to a registry and no hosted
  deployment is recorded.
- **A Kubernetes cluster smoke test.** Ledger **B1** `blocked` (`kind` is not
  installed); only schema and policy validation exist (P17).
- **A PostgreSQL client on the host.** Ledger **B2** `blocked` (`psql` is not
  installed); the containerized PostgreSQL path is the intended one.
- **An independent review of the new surfaces as an M7 exit (P10).** `verified` at
  the v0.1.1 cut: six review/audit vectors landed, and two fresh-clone independent
  verifications re-ran the claimed gates against the release tree (`46cb37b`),
  closing P10 with its two findings (P86, P87). The residual is stated in the row:
  the verifier is of the same programme, not an external party, and the development
  split, the campaign's timing and the aggregate digests were not re-run.
- **Anchored ground truth for the legacy benign-utility gap.** The kit's self-test
  gate is not met (L6: 4/9 benign tasks), and no confidence interval or multi-seed
  estimate exists (L1–L3 limitations). No population-level statistical claim is
  made from the legacy single-seeded run.
- **Fully closed F3.** F3 is claimed only for its caller-authority half (P3); the
  residual — a deployment must treat the caller as the source of truth for its
  own evidence, bounded by the ceiling — is `accepted`, and the third review's
  H3-01 fix (P54) was verified by the orchestrator, not re-run by this author.
- **Hash-pinned lockfile (F8, `accepted`) and the suite running *inside* the
  shipped image (F9, `open`).**
- **Any universal security claim**, and any learned or fine-tuned detector.
