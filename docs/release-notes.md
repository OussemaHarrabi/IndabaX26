# AegisGraph release notes — v0.1.0-industrial

**Release identity.** Tag `v0.1.0-industrial`, branch
`feat/m8-release` off `feature/aegisgraph-industrial-research`. The commit, the
complete artifact list and every digest are in
[`evidence/release-manifest.json`](evidence/release-manifest.json), produced by
[`../scripts/release_manifest.py`](../scripts/release_manifest.py) with

```bash
python scripts/release_manifest.py --commit HEAD --tag v0.1.0-industrial \
  --out docs/evidence/release-manifest.json
```

The manifest is the identity of record for this release: it carries, for each of
its 39 artifacts, the SHA-256 of the bytes on disk (`sha256_raw`), the SHA-256
with CRLF normalised to LF (`sha256_lf`), the SHA-256 of the committed git blob
(`sha256_blob`) and which of the two conventions that blob matches. This release
notes file deliberately does not restate those digests; it names the artifact
each number comes from. A digest restated in prose is a digest that can go stale.

## 1. What this release is

AegisGraph is a pre-execution decision gateway for agentic systems: given one
proposed agent action and the inert facts around it, it returns one of four verbs
— `allow`, `block`, `escalate`, `rewrite` — plus a reason, and never executes the
proposed action. This release is the **industrial-research build** of that
gateway after milestones M0–M8: a versioned decision contract with a policy/code
revision in every decision, an authenticated tenant-scoped policy and receipt
store, machine telemetry and a fail-closed load posture, CI/container/Kubernetes
deployment surface, a native evaluation harness with a 60-scenario dataset and a
sealed holdout, one frozen empirical campaign, six independent review or audit
vectors, a runnable demo, and this provenance manifest. **Every measured result
in this release is `scripted` (the native benchmark replays authored action
scripts) or a legacy mock-kit number.** No real-model run exists in this
repository: the model cells are `blocked` because no open-weight runtime and no
paid API are available. The sealed holdout was not opened. Nothing here is a
statement about model behaviour, about any population of attacks, or about
security in general.

## 2. What it contains

| Milestone | What landed | Status | Authoritative pointer |
| --- | --- | --- | --- |
| M0 | Charter, baseline reproduction, architecture, six ADRs, threat model, legacy evidence map, ledger skeleton | implemented | [`evidence/m0-baseline-report.md`](evidence/m0-baseline-report.md), [`architecture/roadmap.md`](architecture/roadmap.md) |
| M1 | Versioned `aegisgraph/v1` contract; enforcement SDK that refuses a digest-mismatched action; bounded body and scan cost | implemented | [`api/contracts.md`](api/contracts.md), [`api/decision.schema.json`](api/decision.schema.json) |
| M2 | Authentication, tenancy, scoped tokens, versioned policy, durable append-only receipt store (PostgreSQL 17) | implemented | [`api/auth.md`](api/auth.md), [`api/receipts.md`](api/receipts.md) |
| M3 | OpenTelemetry, Prometheus, Grafana, SLOs, load harness, fail-closed under fault injection | implemented | [`ops/observability.md`](ops/observability.md), [`ops/slo.md`](ops/slo.md), [`ops/load-testing.md`](ops/load-testing.md) |
| M4 | CI gates with SHA-pinned actions and a coverage floor of 95; hardened image; Compose stack; validated Kubernetes manifests; drift-guarded SBOM | implemented, two gaps named — no cluster smoke test, and F9 (the suite does not run inside the built image); the hosted workflow is verified running (ledger P85) | [`ops/ci.md`](ops/ci.md), [`ops/container.md`](ops/container.md), [`ops/deployment.md`](ops/deployment.md) |
| M5 | Native evaluation schema authoritative; legacy suite behind a read-only adapter; 60-scenario dataset; sealed 20-scenario holdout | implemented, scripted only | [`docs/benchmark/data-card.md`](benchmark/data-card.md), [`docs/benchmark/evaluation-card.md`](benchmark/evaluation-card.md) |
| M6 | Freeze block 1 declared and exercised: C1/C2 native scripted, C3 legacy re-check, C4 determinism, plus the null delta | partial — model cells blocked | [`evidence/m6-freeze.md`](evidence/m6-freeze.md), [`evidence/m6-campaign.md`](evidence/m6-campaign.md) |
| M7 | Six independent review/audit vectors | partial — six vectors landed; what remains is the reproducibility audit of every headline claim and an independent re-run of the gates | [`evidence/ledger.md`](evidence/ledger.md), [`evidence/reviews/`](evidence/reviews/) |
| M8 | Runnable demo, bounded CV-claims document, this release and its provenance manifest | this release | [`demo/demo-script.md`](demo/demo-script.md), [`evidence/cv-claims.md`](evidence/cv-claims.md) |

The milestone definitions, the blocked-by-tooling ledger and the per-milestone
"blocked" cells are authoritative in
[`architecture/roadmap.md`](architecture/roadmap.md); per-claim status is
authoritative in [`evidence/ledger.md`](evidence/ledger.md).

## 3. Headline measured results

### 3.1 Native benchmark, scripted replay (C1, C2) — `scripted`

Artifacts: `benchmark/runs/20261008T203656Z-m6-campaign/` (`manifest.json`,
`outcomes.jsonl`, `control.jsonl`, `score.json`, `score.txt`, `README.md`);
configuration identity in `docs/evidence/m6-campaign.md` §1 and reproduced in the
manifest's `frozen_identity` block.

| Quantity | Value | Source field |
| --- | --- | --- |
| Gateway commit | `818cf1f29795aa5d1e92b90fe4dfd4ed13174e03`, `dirty = false` | `manifest.json` `code` |
| Dataset / scenario set | `7e916a11…` (60 scenarios) / `e4f376b2…` | `manifest.json` `dataset.sha256`, `scenario_set.sha256` |
| Policy identity | `aegisgraph-default/1`, blob `53d663b1…`, 26 derived sets pinned per request | `manifest.json` `policy` |
| Model | `model.kind = scripted` (the scenario's authored action script replayed verbatim) | `manifest.json` `model` |
| Seed / temperature / max tokens | `1729` / `null` / `null` | `manifest.json` |
| Attack success rate (intention-to-treat) | **0.5000** (15 of 30 reached attacks) | `score.json` `overall.asr`, `overall.attack_successes` |
| Benign task success | **0.9667** (29 of 30 controls) | `score.json` `overall.benign_task_success` |
| False-block rate (decision / scenario) | **0.0556** / **0.0417** | `score.json` `overall.false_block_rate`, `.false_block_rate_scenarios` |
| Escalation rate, rewrites, defense errors | 0.0714, 0 rewrites, **0 errors** | `score.json` `overall` |
| Decisions scored | 168 | `score.json` `overall.decisions` |
| Deterministic digest | `b6951afb6db8fde2dd029d1e964312094d853487ae79d1abfdde02dc08b2581d` | `score.json` `deterministic_digest` |
| Reachability control (C2) | licensed 30, excluded 0, `effectiveness_claim = true`, control `asr = 1.0000` | `score.json` `control` |

`score.json` was written through the platform's text mode, so its working copy —
and its committed blob — carry CRLF; its LF-normalised digest is recorded beside
it in the release manifest and in `docs/evidence/m6-freeze.md` §8. The three
`-text` JSON/JSONL artifacts (`manifest.json`, `outcomes.jsonl`,
`control.jsonl`) are byte-identical on disk and in the blob.

### 3.2 Legacy 40-scenario suite, mock model (frozen ladder)

Artifacts: `evaluation/allow-all-mock.json`, `evaluation/provenance-mock.json`,
`evaluation/aegisgraph-mock.json` (ladder table also in
`evaluation/README.md`). Pinned suite: starter kit
`dd2e5fe0979d0781a4bfe6d0849cd80cf69ef4a2`, model `mock` (a development
instrument, not a neural agent).

| Configuration | ASR | BTU | FBR | DFI | Self-test composite | Digest |
| --- | --- | --- | --- | --- | --- | --- |
| Allow-all control | 1.0000 | 1.0000 | 0.0000 | 0.4000 | 0.054448 | `a9aa03e1…` |
| Built-in provenance baseline | 0.0000 | 1.0000 | 0.2222 | 1.0000 | 0.939104 | `7e9ab169…` |
| AegisGraph (intent-envelope calibration) | 0.0000 | 0.8889 | 0.0683 | 1.0000 | 0.953956 | `3233dfc5…` |

Values read from each scorecard's `metrics` and `score.official_score`.
`3233dfc5…` is the committed historical scorecard's *evaluator* digest; the
committed **file** is not byte-reproducible from current code, and has not been
since M0 (one decision in `enterprise_memory_poison` step 9 differs — see §6).

### 3.3 Legacy 40-scenario suite, real Qwen3-8B (frozen, not re-run) — `legacy kit`, real model

Artifacts: `evaluation/real-qwen/allow-all-qwen3-8b.json`,
`evaluation/real-qwen/aegisgraph-v3-qwen3-8b.json`,
`evaluation/real-qwen/aegisgraph-v5-qwen3-8b.json`. These are frozen historical
artefacts under an add-only policy; they were **not** produced by this release
(let alone by the scripted runner) and are quoted, never recomputed.

| Configuration | ASR | Benign task success | FBR | p95 latency | Eligible |
| --- | --- | --- | --- | --- | --- |
| Allow-all control | 0.7097 (22 of 31) | 5/9 (`btu` 0.5556) | 0.0000 | 0.056 ms | true |
| AegisGraph v3 | 0.0000 (0 of 31) | 4/9 (`btu` 0.4444) | 0.0087 | 8.355 ms | false |
| AegisGraph v5 (final) | 0.0000 (0 of 31) | 4/9 (`btu` 0.4444) | 0.0086 | 9.284 ms | false |

The headline in this repository's permitted register: on one seeded synthetic
public-suite run, reached-attack success went from `22/22` (allow-all) to `0/22`
with 4/9 benign tasks retained; nine of the 31 attacks were unreachable under
allow-all and are not defence evidence; the kit's 0.5 self-test utility gate is
**not** met, which is why `score.eligible` is `false` with
`gate_reason = "benign task utility 0.4444 is below the utility gate 0.5"`. The
paired re-analysis and the v1→v5 ladder are in `docs/research/report.md` §6.5 and
`docs/research/statistics.md` §9.

### 3.4 Campaign cell C3/C4 — legacy re-check and determinism

Artifacts: `evaluation/m6-recheck/aegisgraph-mock-m6-818cf1f.json` (with its
`README.md`). On the pinned public suite with the mock model, this build produces
the deterministic digest `8669aadb87e94652645ae8ed1f454f6f103c21bc8960cc65bf6e051de3043dfa`,
byte-identical to the M0 and M1 re-checks, with the decision mix
150 `allow` / 57 `block` / 0 `escalate` / 1 `rewrite`. Two independent scorings of
the C1 run are byte-identical and the committed campaign `score.json`
(SHA-256 `05f22292002cbd6e0739d5d6705227a34ca275e0167da971b7d5fc68172dd447`, raw
bytes) reproduces from the committed `outcomes.jsonl`/`control.jsonl`
(`docs/evidence/m6-campaign.md` §5).

### 3.5 Delta against the previous reference run: a null result

Measured scenario by scenario against
`benchmark/runs/20261008T230000Z-m2-authenticated-full/`: 0 of 60 verdicts
changed, 0 judged outcomes changed, every aggregate metric identical; the
deterministic digest moved only because `code_commit` is part of the identity
(`a94ce6f` → `818cf1f`). Neither of the two M2 corrective fixes the freeze
predicted would move the run (H3-01's trust ceiling, H3-04's override identity)
is reachable from these 60 scenarios under the campaign credential, so this is a
limitation of the measurement, not evidence about the fixes. Recorded in
`docs/evidence/m6-campaign.md` §7 and proved by the independent campaign audit
(`docs/evidence/reviews/M6-campaign-reproducibility-audit.json`).

### 3.6 Corrected load baseline — local developer hardware

Artifacts: `docs/evidence/performance/m3-load-20261008T210436Z.json` and its
`.sha256` sidecar (`docs/ops/load-testing.md` §"Observed run").

| Metric | Value |
| --- | --- |
| Measured requests / throughput / error rate | 2986 / 148.938 req/s / 0.0000 |
| Client-observed latency p50 / p95 / p99 / max | 98.596 / 169.357 / 201.422 / 360.021 ms |
| Service-side decision latency p50 / p95 / p99 / max | 2.302 / 5.227 / 7.283 / 16.475 ms |
| Verdicts (200 only) | allow 2368, block 455, escalate 163 |
| Warm-up / window consistency | 40 warm-up requests excluded; `counts_match_measured = true` |

Client and service-side latencies differ by roughly an order of magnitude because
the 16 blocking client threads share the same 16-CPU host as the server; the
client figures are queueing, not work inside the decision path
(`docs/ops/load-testing.md`). The earlier artifact
`docs/evidence/performance/m3-load-20261008T193951Z.json` includes warm-up
requests in its service-side block and has a sidecar that disagrees with its
committed bytes; `docs/ops/load-testing.md` marks it superseded and says it must
not be quoted. **It is not quoted here**, and it is not in the release manifest.

### 3.7 Tests, coverage and tooling

| Quantity | Value | Artifact / command |
| --- | --- | --- |
| Tests collected at this revision | **598** | `python -m pytest -q --collect-only` |
| Suite with PostgreSQL 17 at `57596f3` | 569 passed, 2 skipped → **3009/3108 = 96.81 %** | `docs/ops/ci.md` ("Coverage gate") |
| Suite with no database | 2914/3108 = **93.76 %** | `docs/ops/ci.md` ("Coverage gate") |
| Coverage floor (ratchet) | **95** | `.github/workflows/ci.yml`, `docs/ops/ci.md` |
| Hosted CI (five gates) | green on the release tag `eb33d2c` (run `37846970280`, 2026-10-08T21:28:01Z) and on the tip `cb3f82f` (run `37863688964`); branch history 29 runs: 10 success / 1 failure / 17 `cancel-in-progress` cancellations, the failure being a test defect fixed in `cc3a14f` | `docs/evidence/ledger.md` row **P85**, `docs/ops/ci.md` |
| Native dataset validation | `RESULT: PASS` (`errors=0 warnings=0`), dataset `7e916a11…`, sealed holdout 20 scenarios, ciphertext `c1a32fb8…` | `python scripts/bench_validate.py` |
| Static checks | `ruff check` and strict `mypy` clean (19 source files) | `python -m ruff check scripts`, `python -m mypy` |

The two skips need the untracked `.sentinel_reference` kit checkout, which a
clean clone does not have; the floor of 95 is deliberately above the no-database
ratio, so a silent skip of the database tests cannot pass. The two coverage rows
are the CI gate's own measurement **at `57596f3`** and are quoted with their
commit, never as the current tip's ratio; the suite has grown since (598 tests
collected here).

### 3.8 Container and software bill of materials

Artifacts: `deploy/sbom/aegisgraph-image-sbom.json` and
`deploy/sbom/aegisgraph-image-sbom.requirements.txt`, guarded by
`scripts/check_sbom_freshness.py`.

| Quantity | Value |
| --- | --- |
| Image digest (committed record) | `sha256:bb373f362f052ffa49f15a47ef5ffd72bb7665a275e0b79a9db54f1f6c5cb531` |
| Image size / runtime user / runtime Python | 73,084,467 B / `10001:10001` (non-root) / 3.12.15 |
| Packages inventoried | 39 |
| SBOM source commit / lock digest | `57596f304b726bbd08b1c6cbf4e605d16237fd7f` / `d0bf0f5504aa8c5da890c6913b2b4faa36f5e0476daced5ee7359eefd15730d3` |

**The image was not rebuilt at the release commit**; the digest above is the
recorded build at the SBOM's source commit, and the manifest says so. The lock
digest appears in the campaign manifest, the SBOM and `requirements.lock`, and is
reconciled by `python scripts/check_sbom_freshness.py`.

### 3.9 Independent review vectors

Six read-only vectors are committed under `docs/evidence/reviews/`; each is in
the release manifest. Counts read from each artifact's `findings` array:

| Artifact | Findings |
| --- | --- |
| `M0-adversarial-security-review.json` | 10 (4 high, 4 medium, 2 low) |
| `M0-M5-research-reproducibility-audit.json` | 23 (7 high, 5 medium, 11 low) |
| `M1-M5-adversarial-security-review.json` | 6 (1 high, 2 medium, 3 low) |
| `M2-surface-adversarial-security-review.json` | 9 (1 high, 2 medium, 6 low) |
| `M3-telemetry-load-adversarial-review.json` | 10 (3 medium, 6 low, 1 informational) |
| `M6-campaign-reproducibility-audit.json` | 6 (2 medium, 4 low) |

Their per-finding status — fixed, accepted with a documented residual, or still
open — is authoritative in `docs/evidence/ledger.md`; this note does not restate
it. The review vectors are point-in-time evidence: they describe the tree at the
commit they name, not this release.

## 4. How to reproduce

```bash
# 0. The release identity (writes the manifest; deterministic apart from generated_at)
python scripts/release_manifest.py --commit <commit> --tag v0.1.0-industrial \
  --out docs/evidence/release-manifest.json

# 1. Re-hash every listed artifact from the working tree (files and the dataset aggregate)
python scripts/release_manifest.py --verify docs/evidence/release-manifest.json

# 2. One artifact, both conventions
sha256sum <path>                                   # sha256_raw
git show <commit>:<path> | sha256sum               # sha256_blob
git show <commit>:<path> | tr -d '\r' | sha256sum  # sha256_lf

# 3. Re-score the frozen campaign run (twice; the two files must be identical)
python scripts/bench_score.py --run benchmark/runs/20261008T203656Z-m6-campaign --json --out a.json
python scripts/bench_score.py --run benchmark/runs/20261008T203656Z-m6-campaign --json --out b.json
cmp a.json b.json

# 4. Dataset and reachability gates
python scripts/bench_validate.py

# 5. The test suite (the campaign's gateway commit for C1/C3 needs PostgreSQL 17;
#    see docs/evidence/m6-freeze.md §3 for the full C1–C3 command set)
python -m pytest -q
```

Full campaign configuration identity and the exact C1–C4 commands are in
`docs/evidence/m6-freeze.md` §3; the demo's six steps are in
`docs/demo/demo-script.md`.

## 5. What this release does **not** claim

- **No real-model result.** Every measured number in this release is `scripted`
  or a legacy mock-kit number. A real-model campaign cell (`--model ollama`)
  fails closed with `ModelUnavailable`; `model.kind = scripted` is recorded in
  every campaign manifest.
- **No result on the sealed holdout.** The 20-scenario holdout was not opened;
  no artifact in this release contains a holdout number.
- **No cluster behaviour and no in-image test run.** No Kubernetes cluster smoke
  test has run (`kind` is not installed) — the manifests are schema-validated and
  policy-asserted only — and the suite is still not executed inside the built
  image (F9). The hosted workflow itself **is** verified running on GitHub: the
  release tag and the branch tip both have green hosted runs (§3.7, ledger P85).
- **No universal protection.** The gateway's verdicts are conditional on one
  fixed synthetic case series at one frozen commit. They are not a population
  estimate, a confidence interval, or proof that any injection is detected.
- **No comparability between the scripted native run and the legacy real-Qwen
  run.** Different suites, different instruments, different numbers of reached
  attacks; the release never pairs them.
- **No causal credit for the two M2 corrective fixes.** The campaign's null delta
  shows the fixed code paths were not reachable from the frozen dataset, which is
  the opposite of evidence that the fixes work.
- **No per-component ablation matrix.** The legacy v1→v5 ladder is matched-
  configuration component evidence on one seeded run per configuration, not a
  controlled ablation.
- **No freshness beyond the recorded build.** The container digest is a recorded
  build from the SBOM's source commit, not a build of the release commit.
- **No portability claim for `sha256_raw`.** It is the bytes on disk in the
  generating checkout (`core.autocrlf = true`, git 2.55.0.windows.3, recorded in
  the manifest's `checkout` block). For git-text files it is the CRLF form;
  `sha256_lf`/`sha256_blob` are the portable values, and each manifest entry says
  which of them its blob matches.

## 6. Known limitations

- **Legacy mock scorecard not byte-reproducible.** The committed
  `evaluation/aegisgraph-mock.json` (`3233dfc5…`) is not reproduced from current
  code and has not been since M0: exactly one decision differs
  (`enterprise_memory_poison` step 9 — `rewrite/UNTRUSTED_AUTHORITY_REDACTED`
  today versus `allow/BENIGN_ACTION` in the frozen artifact), because the
  narrative-authority guard landed after it and the artifact carries no defence
  revision fingerprint. The re-checks (`8669aadb…`) are the reproducible ones.
- **Single seed, no repeats.** The native campaign is one scripted run at seed
  `1729`; the legacy ladder is one seeded run per configuration. Repeated-trial
  variance is not estimated.
- **Utility gate not met (legacy).** 4/9 benign tasks retained versus 5/9 under
  allow-all; the fifth is an `email_send` confirmation/subject mismatch in
  `enterprise_security_digest`, left unrepaired rather than weakening the
  confirmation boundary.
- **Residual output contamination (legacy).** v5 still passes a lower-trust
  tool-use prompt into one final `enterprise_memory_poison` answer; that scenario
  was unreachable under allow-all, so it is not a defence win.
- **Unreachable attacks.** Nine of 31 legacy attacks never reached the defense
  under allow-all and are excluded from the effectiveness reading.
- **Provenance gaps recorded on the campaign.** The gateway identity is
  runner-attested (`build.commit = unknown` on the service side); the campaign
  credential's scopes and ceiling are asserted in prose but recorded in no
  committed artifact; campaign latency is not comparable to the in-process run
  (durable PostgreSQL 17 receipts here). See `docs/evidence/m6-campaign.md` §1.
  All three are now recorded rather than silent: the runner writes
  `defense.build_identity` and `auth.scopes`/`trust_ceiling`/`claims_source`
  (ledger rows **P69**, **P72**) and the latency difference is stated in
  `docs/evidence/m6-campaign.md` §7.
- **Review findings at this release.** All sixteen findings of the M6 campaign
  audit and the M3 telemetry/load review (ledger rows **P69–P84**) are closed or
  explicitly `accepted`. Five residual items stay `accepted` with their reasons
  written down: dependency pins carry no hashes (F8), the legacy loopback refusal
  checks the configured bind variable rather than the actual bind (H3-06), the
  request body is buffered up to the 1 MiB cap before the credential is resolved
  (H3-08), the `/metrics` control is port-level rather than credential-level
  (P80), and a caller-controlled span attribute is unbounded in distinct values
  (P84). Statuses and residuals: `docs/evidence/ledger.md`.
- **Blocked cells** (from `docs/architecture/roadmap.md` §4, with the missing
  tool named): B1 Kubernetes cluster smoke test (`kind`); B2 host PostgreSQL
  (`psql`, containerized path intended); B3 real-model rerun (`ollama`); B4
  paid-model benchmark (no API credentials); B6 holdout result (seal may be
  opened only by the custodian after the freeze checklist in
  `docs/benchmark/holdout.md` §4). The former B5 (GitHub-hosted CI execution) is
  **verified** — green runs `37846970280` on the tag and `37863688964` on the tip
  — and the roadmap's blocked table records it as such (ledger **P85**).
- **Corrections after publication.** The §5 bullet "No GitHub-hosted CI run" was
  wrong when written and has been replaced by the verified position above: the
  hosted workflow runs on every push, the release tag `v0.1.0-industrial` (cut at
  `eb33d2c`) has a green run `37846970280` and the tip `cb3f82f` has run
  `37863688964` (ledger P85). The stale `README.md`-freshness bullet, the
  "blocked"/"unverified" labels on B5 and on the M3 and campaign review findings,
  and the milestone-table wording were corrected in the same pass against ledger
  rows P69–P85. No measured number and no release identity changed; the two
  manifest entries for `docs/architecture/roadmap.md` and `docs/evidence/ledger.md`
  were regenerated in the same commit, because those documents themselves changed
  when the hosted-CI evidence landed (ledger P85).

## 7. Pointers

- Claim-to-evidence map (one row per claim: artifact, digest, command, commit):
  [`evidence/ledger.md`](evidence/ledger.md).
- Milestones, exit criteria, blocked-by-tooling table and single-writer map:
  [`architecture/roadmap.md`](architecture/roadmap.md).
- Freeze contract and recorded results: [`evidence/m6-freeze.md`](evidence/m6-freeze.md);
  campaign report: [`evidence/m6-campaign.md`](evidence/m6-campaign.md).
- Research report and statistics: [`research/report.md`](research/report.md),
  [`research/statistics.md`](research/statistics.md);
  claim wording rules: [`research/claim-language.md`](research/claim-language.md).
- Bounded, audience-specific claim bullets: [`evidence/cv-claims.md`](evidence/cv-claims.md).
- Security findings register: [`evidence/security-findings.md`](evidence/security-findings.md).
- Provenance manifest: [`evidence/release-manifest.json`](evidence/release-manifest.json),
  generator: [`../scripts/release_manifest.py`](../scripts/release_manifest.py).
