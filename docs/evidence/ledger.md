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
| L14 | Legacy mock scorecard is **not byte-reproducible** from final HEAD | research | verified | `.audit-tmp/m0-mock-recheck.json` | fresh deterministic digest `8669aadb…` vs committed `3233dfc5…` | `uv run sentinel eval public --defense-url http://127.0.0.1:8156 --model mock --json` | `770e88d` | 40/40 outcome labels identical, 14/18 metric keys identical; exactly one decision differs — `enterprise_memory_poison` step 9 returns `rewrite`/`UNTRUSTED_AUTHORITY_REDACTED` now versus `allow`/`BENIGN_ACTION` in the committed artifact (150 allow + 57 block + 1 rewrite vs 151 allow + 57 block); `brier`, `ece` and the deterministic digest differ; latency differs by wall clock; the committed artifact carries **no defence-revision fingerprint** |

| L15 | M0 independent adversarial security review of the shipped decision boundary | industrial | verified | `docs/evidence/reviews/M0-adversarial-security-review.json` (31,179 B) | `8d6c50522723e54c3bbafd24267dc56020519862ccc736cdfd8a3374effe6ecf` | `git show HEAD:docs/evidence/reviews/M0-adversarial-security-review.json \| sha256sum` + `python -c "json.load(...)['findings']"` for the finding vector | `770e88d` | reviewer Agent H, read-only, probes written outside the repo; 10 findings — **4 high** (F1–F4, F1 qualified "critical if reachable by an untrusted network"), **4 medium** (F5, F6, F7, F9), **2 low** (F8, F10); *this row verifies the review artifact* (digest and finding vector re-derived here), not Agent H's live probes, which were not re-executed; findings are tracked in the orchestrator-owned [`security-findings.md`](security-findings.md); no finding changes a legacy scorecard (trusted-caller preconditions hold) |

**Note on L14 (legacy finding F14, reproduced).** The single differing decision is
explained by the narrative-authority guard in
`backend/aegisgraph/engine.py:634-705`: the current code rewrites a forged
authority claim that the committed artifact allowed. No committed artifact
records the defence revision that produced it, so a fresh run cannot be
attributed byte-for-byte to the committed mock scorecard. This is the concrete
reproduction of legacy audit finding **F14** ("traces and scorecards are not
fingerprinted with the defense revision", `COURSE/09-audit-findings.md`) and the
reason milestones **M1, M5 and M6 must carry an explicit policy version and code
commit** in every contract, receipt, scorecard and artifact.

**Note on L15 (review artifact integrity).** The digest recorded in L15 is the
**git blob** digest (`git show HEAD:<path> | sha256sum`). A Windows checkout with
`core.autocrlf=true` materializes CRLF and hashes to
`2b5d8e1438232d4895f7e3cd472fdf6f17d94a86be6f2f738d0896b0555c0c01` (31,415 bytes on
disk vs 31,179 bytes committed), so the M8 reproducibility audit must hash the
blob, never the working copy. Re-deriving the finding vector confirmed
`F1`–`F10`: **4 high** (F1–F4; F1 carries the qualifier "critical if reachable by
an untrusted network"), **4 medium** (F5, F6, F7, F9), **2 low** (F8, F10). The
M1 dispatch summary's "3 high / 5 medium / 2 low" does not match the artifact —
**the artifact governs**.

## B. New platform (pending — do not promote without evidence)

Rows **P11–P14** register the M1 dispatch outcomes *before* they exist: status
`pending`, the artifact and command that will be required named up front. They are
promoted only by attaching a real artifact, its digest, the exact command and the
commit (section D rule 2).

| # | Claim | Type | Status | Artifact | Digest | Command | Commit | Limitation |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P1 | Native versioned contract + policy/code revision in every decision | industrial | pending | — | — | — | — | M1; contract not yet extracted |
| P2 | Receipt persistence (append-only, digest-bound) | industrial | pending | — | — | — | — | M2; ADR-0001 |
| P3 | Authentication + per-tenant isolation | industrial | pending | — | — | — | — | M2; ADR-0002; local test issuer only |
| P4 | Telemetry (OTel/Prometheus/Grafana) with content-free attributes | industrial | pending | — | — | — | — | M3; ADR-0003 |
| P5 | Native evaluation schema (authoritative) + legacy adapter | research | pending | — | — | — | — | M5; ADR-0004 |
| P6 | Enforcement refuses digest-mismatched actions | industrial | pending | — | — | — | — | M1; ADR-0006 |
| P7 | Compose stack starts from clean and passes smoke test | industrial | pending | — | — | `docker compose up` + smoke | — | M4; ADR-0005 |
| P8 | Release provenance manifest (paths + SHA-256) | industrial | pending | — | — | — | — | M8 |
| P9 | Empirical campaign (multi-seed real-model runs, ablation, variance) | research | pending | — | — | — | — | M6; blocked on `ollama`/API, see B3 |
| P10 | Independent review of new surfaces and reproducibility audit | research | pending | — | — | — | — | M7 |
| P11 | Versioned **generic** decision API + server-computed decision identity and emitted receipt | industrial | pending | expected: `tests/test_contracts.py` + the native request/response/receipt models | — | `python -m pytest -q tests/test_contracts.py` | — | M1; closes F7 at the wire (identity + one structured record per request; stable for identical inputs, different for a changed action); the durable append-only store stays M2 (P2); also the structural fix for the unpinned revision seen in L14 |
| P12 | Enforcement SDK refuses **every** failure class (digest-mismatch, escalation without a matching confirmation, rewritten action re-validated) | industrial | pending | expected: `backend/aegisgraph/enforce/**`, `sdk/**`, `tests/test_enforcement.py` | — | `python -m pytest -q tests/test_enforcement.py` | — | M1; ADR-0006; F1–F3 (unauthorised caller, self-granted confirmation, declared labels) stay open by design until M2 supplies authenticated, tenant-scoped policy — an unauthenticated refusal is not an authorization control |
| P13 | Bounded request body (**413** before parsing) and bounded scan cost (**F4**) | industrial | pending | expected: body cap + per-character scan micro-benchmark in `tests/test_enforcement.py` / `scripts/**` | — | `python -m pytest -q tests/test_enforcement.py -k "body or bound"` | — | M1; closes F4 (worst-case 2 MiB request completes or is rejected under 1 s; per-char scan cost flat 1 KB→16 KB) and F5 (over-cap Content-Length or chunked body rejected 413); acceptance criteria in [`security-findings.md`](security-findings.md) |
| P14 | Strict **confirmation binding** on the new surface (exact execution digest + request identity; grants expire, no cross-run reuse) | industrial | pending | expected: confirmation cases in `tests/test_enforcement.py` + `sdk/**` binding logic | — | `python -m pytest -q tests/test_enforcement.py -k confirmation` | — | M1; closes F6 **on the new surface only** — the legacy adapter keeps legacy matching, and any change to that matching rule requires a new evaluation artifact, never an edit of the legacy scorecard ([`security-findings.md`](security-findings.md)) |

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
