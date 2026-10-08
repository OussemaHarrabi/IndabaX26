# Evidence ledger

One row per claim. Status vocabulary is strict: **verified** (an artifact and a
command reproduce it), **pending** (not yet demonstrated), **blocked** (cannot be
demonstrated with the available tooling — the blocker is named). Types are
**industrial** (platform engineering) or **research** (benchmark/evaluation).

Rule: no row may be promoted to `verified` without an artifact, its digest, the
exact command and the source commit. Legacy numbers are frozen at their measured
commits and are never recomputed under new code.

## A. Legacy SENTINEL results (frozen)

| # | Claim | Type | Status | Artifact | Digest | Command | Commit | Limitation |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| L1 | AegisGraph v5 stopped **0 of the 22 allow-all-reached attacks** | research | verified | `evaluation/real-qwen/aegisgraph-v5-qwen3-8b.json` | `b9b0937814f8a545b8cb1deebacb1623830a04dedbfdb6b8f297be31118027c4` | pinned kit `sentinel eval public` + read `attack_success` + `scripts/validate_attack_reachability.py` | `53472e560d6a21f197a7a0f72e537e3c7c88e756` | one seeded run; 9 of 31 attacks never reached under allow-all, so not effectiveness evidence |
| L2 | v5 false-block rate **0.0086** | research | verified | same scorecard | same | same | same | single observation; no confidence interval |
| L3 | v5 p95 decision latency **9.284 ms** | research | verified | same scorecard | same | same | same | free Colab T4 runtime; not a production latency claim |
| L4 | v5 evaluator deterministic digest | research | verified | scorecard | `57ad9925d63d735eb27bddc8e6d23338c076308e20a657e135522146482e57a5` | evaluator digest field | same | latency excluded by the evaluator's definition |
| L5 | v5 full 40-trace archive | research | verified | `evaluation/real-qwen/aegisgraph-v5-qwen3-8b-evidence-20260923.zip` | `37dbcf836108ad667c720666d27e63c8d8b1001d1ea93ab53a2e84ce7f702d76` | `Get-FileHash -Algorithm SHA256` | same | synthetic traces; credential-like strings are canaries |
| L6 | Kit self-test gate **not met** (benign 4/9 < 0.5) | research | verified | v5 scorecard `eligible=false`, `BTU=4/9` | as L1 | inspect scorecard | same | 4 failures also occur under allow-all; the 5th is an `email_send` confirmation mismatch |
| L7 | Residual output contamination persists in `enterprise_memory_poison` | research | verified | `evaluation/real-qwen/enterprise_memory_poison-v5.jsonl` | see manifest | inspect the final answer for the `document_read`/`email_draft` instruction | same | scenario unreachable under allow-all; not a defence win |
| L8 | Legacy decision core passes its test suite | industrial | verified | `tests/` | — | `python -m pytest -q` | `770e88d` | 187 passed in 1.69 s on local Python 3.13.14; package declares `>=3.12,<3.13` (discrepancy recorded, not silently changed) |
| L9 | Legacy code passes Ruff | industrial | verified | `backend/`, `tests/` | — | `python -m ruff check backend tests` | `770e88d` | ruff 0.16.1 local |
| L10 | Legacy code passes strict mypy | industrial | verified | 8 source files | — | `python -m mypy` | `770e88d` | mypy 2.4.0 locally is outside the dev pin (`>=1.13,<2`); strict mode still clean |
| L11 | Defence code byte-identical between `649f65a` and `770e88d` | industrial | verified | `backend/**`, `tests/**` | — | `git diff 649f65a 770e88d -- backend tests` (empty) | `770e88d` | the two extra commits touch only docs |
| L12 | Baseline reproduced at intake | industrial | verified | `docs/evidence/m0-baseline-report.md` | — | `python -m pytest -q` in the integration worktree | `770e88d` | recorded by the orchestrator (187 passed in 2.71 s) |
| L13 | No scenario id / expected outcome is a decision input | industrial | verified | `tests/test_contracts.py:196-205` | — | run the contract tests | `770e88d` | asserts absence from contract models; rule vocabulary remains benchmark-shaped |

## B. New platform (pending — do not promote without evidence)

| # | Claim | Type | Status | Artifact | Digest | Command | Commit | Limitation |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P1 | Native versioned contract + policy version in every decision | industrial | pending | — | — | — | — | M1; contract not yet extracted |
| P2 | Receipt persistence (append-only, digest-bound) | industrial | pending | — | — | — | — | M2; ADR-0001 |
| P3 | Authentication + per-tenant isolation | industrial | pending | — | — | — | — | M3; ADR-0002; local test issuer only |
| P4 | Telemetry (OTel/Prometheus/Grafana) with content-free attributes | industrial | pending | — | — | — | — | M4; ADR-0003 |
| P5 | Native evaluation schema (authoritative) + legacy adapter | research | pending | — | — | — | — | M5; ADR-0004 |
| P6 | Enforcement refuses digest-mismatched actions | industrial | pending | — | — | — | — | M6; ADR-0006 |
| P7 | Compose stack starts from clean and passes smoke test | industrial | pending | — | — | `docker compose up` + smoke | — | M7; ADR-0005 |
| P8 | Release provenance manifest (paths + SHA-256) | industrial | pending | — | — | — | — | M8 |

## C. Blocked (tooling unavailable)

| # | Claim | Type | Status | Blocker | Unblock condition |
| --- | --- | --- | --- | --- | --- |
| B1 | Kubernetes cluster smoke test | industrial | blocked | `kind` not installed | `kind create cluster --name aegisgraph && kubectl apply -k deploy/k8s` |
| B2 | PostgreSQL on host | industrial | blocked | `psql` not installed | containerized PostgreSQL is the intended path; host client optional |
| B3 | Real-model evaluation rerun | research | blocked | `ollama` not installed | install `ollama` + `qwen3:8b`, or authorize an API |
| B4 | Paid-model benchmark | research | blocked | no API credentials | explicit owner authorization |
| B5 | Live Docker-engine run of the hardened image | industrial | pending | Docker 29.6.2 present; run not yet performed | `docker build -t aegisgraph:local . && docker run …` |

## D. How to update this ledger

1. Add the row **before** the work, with status `pending`.
2. On completion, attach artifact path, digest, exact command and commit; only
   then set `verified`.
3. If tooling is missing, set `blocked` and name the missing tool — never fill a
   cell with mock data presented as real.
4. Never edit a legacy row's number; if a new run disagrees, add a new row and
   reference both.
