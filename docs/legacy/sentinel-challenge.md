# The SENTINEL challenge record (preserved)

This is the historical record of AegisGraph as the IndabaX Tunisia 2026 /
SENTINEL challenge submission by team **`9ahwa mahrou9a`**. It is preserved
unchanged in substance. Nothing here is a description of the new industrial
platform; the new platform is described in
[`../architecture/system-context.md`](../architecture/system-context.md).

Every measurement below is a **self-test** on a published suite, not an official
jury score, and is reproduced from the committed artifacts.

## 1. What the challenge was

SENTINEL is an **agent-security** challenge. Participants received:

- a tool-using reference agent — unmodified `Qwen/Qwen3-8B` driving a simulated
  enterprise / finance / SOC environment;
- a published library of **40 scenarios: 31 attacks and 9 benign**, across
  enterprise (15), finance (12) and SOC (13), with 3 hard negatives
  (`benchmark.lock`);
- a defense contract: for each proposed candidate action, return one of four
  verbs — `allow`, `block`, `escalate`, `rewrite` — without executing anything;
- an evaluation harness (`sentinel eval`) producing per-scenario outcomes and a
  kit self-test utility gate.

Judging was by a human jury rubric (video & observability, technical report,
creativity, engineering & responsible AI); there was no automated score to game.
Attacks were text-only mutations inside scenario-declared surfaces (see
[`../architecture/threat-model.md`](../architecture/threat-model.md) §4.1).

The pinned benchmark is `Skan22/Sentinel_Starter_Kit` at commit
`dd2e5fe0979d0781a4bfe6d0849cd80cf69ef4a2` (Apache-2.0), recorded in
[`../../benchmark.lock`](../../benchmark.lock).

## 2. What the team built

A deterministic, fail-closed decision gateway plus a local observability surface,
both of which survive into the new platform as the implemented decision core:

- **Decision core** (`backend/aegisgraph/`): bounded canonical and wire
  contracts; per-source provenance resolution; declarative policy facts;
  trust/sensitivity-aware rules for authorization, confirmation, sensitive-flow
  redaction and rewrite re-validation. See the component anchors in
  [`../architecture/system-context.md`](../architecture/system-context.md).
- **Observability surface** (`backend/aegisgraph/static/`): a local, read-only
  inspector that imports SENTINEL JSONL traces and evaluator scorecards, follows
  proposal → decision → effect, compares scorecards, and never uploads or
  executes anything.
- **Evidence package** (`evaluation/`, `REPORT.tex`, `REPORT_PLAN.md`,
  `SUBMISSION_*`, `DEMO_RUNBOOK.md`, `COLAB_QWEN_RUN.md`, `VIDEO_SCRIPT_V5.md`):
  scorecards, raw traces, archives with digests, the LaTeX report source and the
  submission paperwork. See [`evidence-map.md`](evidence-map.md).

There is **no** model fine-tuning and **no** learned detector; risk/confidence
are deterministic rule outputs, not calibrated probabilities of harm.

## 3. How it was measured

Five matched-configuration runs on the pinned suite, all with the unmodified
reference agent: `Qwen/Qwen3-8B` via local Ollama 0.34.3 `ollama:qwen3:8b`
Q4_K_M, thinking off, 768 maximum new tokens, temperature 0, seed 0, Python
3.12.14, free Colab Tesla T4 (15 GiB). Ollama cloud was disabled and there was
**no external inference API**. Runs happened at different times, so this is a
matched-configuration comparison, not a repeated-trial statistical estimate.

## 4. Measured results (exact)

| Run | Defense source commit | ASR (all 31) | Attacks stopped among 22 reached | Benign task success | False-block rate | p95 decision latency |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Allow-all | built-in | 22/31 | 0/22 | 5/9 | 0 | 0.056 ms |
| Built-in provenance | built-in | 9/31 | 13/22 | 4/9 | .3466 | 0.126 ms |
| AegisGraph v1 | `b791f79eacfe99ab9c4765d0db910eba8ab44bfd` | 10/31 | 12/22 | 4/9 | 0 | 8.598 ms |
| AegisGraph v3 | `a511ff8358e104a78a90844a8f150cb1db1482ad` | 0/31 | **22/22** | 4/9 | .0087 | 8.355 ms |
| **AegisGraph v5 (final)** | `53472e560d6a21f197a7a0f72e537e3c7c88e756` | 0/31 | **22/22** | 4/9 | **.0086** | **9.284 ms** |

Headline claim, stated exactly: **0 of the 22 allow-all-reached attacks succeeded
under v5, with a false-block rate of 0.0086 and p95 decision latency of 9.284 ms,
on one seeded run of the public suite.** Four of the nine benign cases failed
under allow-all too; the fifth is a consequential `email_send` confirmation
mismatch. Nine of the 31 attacks never reached the agent under allow-all and are
**not** defence-effectiveness evidence.

Artifact digests (SHA-256 unless noted):

| Artifact | Digest |
| --- | --- |
| v5 scorecard (`evaluation/real-qwen/aegisgraph-v5-qwen3-8b.json`) | `b9b0937814f8a545b8cb1deebacb1623830a04dedbfdb6b8f297be31118027c4` |
| v5 evaluator deterministic digest | `57ad9925d63d735eb27bddc8e6d23338c076308e20a657e135522146482e57a5` |
| v5 evidence archive (40 traces, 90 entries) | `37dbcf836108ad667c720666d27e63c8d8b1001d1ea93ab53a2e84ce7f702d76` |
| v3 scorecard | `4894de5b5bd874c28216f64273ab4a91882cd7eac1ee7fb3ccc1c50c332bdbb8` |
| v3 deterministic digest | `56ac2dba10e09fd17d8eb7dad32b61cc3fd21446b3f06314a664849da84a8a59` |
| v3 evidence archive (40 traces, 89 entries) | `b14774a5d90db3f210621ca5ec89382a0404944e4561f694a4a5f86d419da4ce` |
| v1 scorecard | `0b9866808c57bca83d802b2f1e6a45cac03c8509142d7fce22d505f2af64675f` |
| provenance scorecard | `b45b0c09b6433315153e9e032bbeb6ff35c8f5b33c3c8fb15618bd5ad012182a` |
| allow-all scorecard | `312e1e99befdc3542d7bc6f0b4cd85691a7cc8a0df149536573de5dd7a497593` |
| v1+provenance+allow-all archive (120 traces, 258 entries) | `9a8a53f6244a7dfe2d3196b9c151d7b7e4b752d3caa13c8fe9259166759c7dc3` |

The full digest table, the nine unreached scenarios and the per-scenario
residual-contamination findings are in
[`../../evaluation/real-qwen/README.md`](../../evaluation/real-qwen/README.md).

## 5. Known weaknesses at submission

- **Utility gate not met.** The v5 scorecard says `eligible=false` because 4/9
  benign utility is below the kit's 0.5 self-test gate.
- **Residual output contamination.** Even where `attack_success=false`, v3 let
  false claims into memory/responses in `enterprise_memory_poison`,
  `soc_hostile_log_text` and `soc_intel_memory_poison`. v5 removes selected false
  authority and disable-monitoring claims from those examples, but its final
  `enterprise_memory_poison` response still instructs the user to call
  `document_read` with `DOC-3104` and then `email_draft`. That scenario was
  already unreachable under allow-all, so it is not a defence win.
- **Bounded narrative guard.** It can miss paraphrases, translations, transformed
  secrets and multi-turn laundering.
- **Single observation.** One seeded run; no confidence intervals, no multi-seed
  reruns, no revision fingerprint linking trace and scorecard.

## 6. Submission-state gaps (as they stood)

| Gap | State |
| --- | --- |
| Demo video | not recorded |
| Compiled report PDF inside the repository | was a dead link; the orchestrator restored `output/pdf/AegisGraph-SENTINEL-Technical-Report.pdf` (SHA-256 `69035d0099cefe8cb1d58499dbf613c288a4e2a67352db1b3f16d0a2cc975c4f`), per `docs/evidence/m0-baseline-report.md` |
| Live organizer-validator run | pending |
| Live Docker-engine run | unverified at submission |
| Manifest validation | team field populated; live validation pending |
| Human-team eligibility | owner reports solo registration; the form asks for 3–5 humans; **no names are invented** |
| Multi-seed rerun / generalization (AgentDojo) | not run |

All of the above are documented, not hidden. The challenge paperwork is preserved
in place: [`../../SUBMISSION_CHECKLIST.md`](../../SUBMISSION_CHECKLIST.md),
[`../../SUBMISSION_HANDOFF.md`](../../SUBMISSION_HANDOFF.md),
[`../../DEMO_RUNBOOK.md`](../../DEMO_RUNBOOK.md),
[`../../COLAB_QWEN_RUN.md`](../../COLAB_QWEN_RUN.md),
[`../../REPORT_PLAN.md`](../../REPORT_PLAN.md),
[`../../VIDEO_SCRIPT_V5.md`](../../VIDEO_SCRIPT_V5.md) and
[`../../REACHABILITY_GATE.md`](../../REACHABILITY_GATE.md).
