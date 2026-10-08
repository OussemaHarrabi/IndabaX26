# Legacy evidence map

Path → purpose for the preserved SENTINEL evidence package. Links are relative to
this file. **Everything here is an artifact of record and is read-only**: nothing
in this package is edited, recomputed or reinterpreted. New platform evidence is
tracked in [`../evidence/ledger.md`](../evidence/ledger.md).

## 1. Frozen revisions

| Revision | Role |
| --- | --- |
| `649f65a1b69ecc451c5679e59d2a47357a8729c2` | Legacy baseline branch `feature/aegisgraph` (defence code + tests) |
| `770e88d` | `main`: the baseline plus two documentation commits (`COURSE/**`, one README section, one `.gitignore` line); defence code byte-identical to the baseline |
| `53472e560d6a21f197a7a0f72e537e3c7c88e756` | Measured final v5 defence source |
| `a511ff8358e104a78a90844a8f150cb1db1482ad` | Measured v3 defence source |
| `b791f79eacfe99ab9c4765d0db910eba8ab44bfd` | Measured v1 defence source |
| `dd2e5fe0979d0781a4bfe6d0849cd80cf69ef4a2` | Pinned benchmark (`Skan22/Sentinel_Starter_Kit`, Apache-2.0) |

`benchmark.lock` records the benchmark pin and the scenario counts (40 = 31
attacks + 9 benign; enterprise 15, finance 12, SOC 13; 3 hard negatives).

## 2. Real-model evidence — `evaluation/real-qwen/`

| Path | Purpose | Notes |
| --- | --- | --- |
| [`../../evaluation/real-qwen/README.md`](../../evaluation/real-qwen/README.md) | Manifest: runtime config, digest tables, unreached scenarios, residual findings | Primary index of the real-model run |
| [`aegisgraph-qwen3-8b-evidence-20260923.zip`](../../evaluation/real-qwen/aegisgraph-qwen3-8b-evidence-20260923.zip) | allow-all + provenance + v1 scorecards, metadata, logs, 120 traces (258 entries) | SHA-256 `9a8a53f6…9c7dc3` |
| [`aegisgraph-v3-qwen3-8b-evidence-20260923.zip`](../../evaluation/real-qwen/aegisgraph-v3-qwen3-8b-evidence-20260923.zip) | v3 scorecard, metadata, logs, 40 traces (89 entries) | SHA-256 `b14774a5…419da4ce` |
| [`aegisgraph-v5-qwen3-8b-evidence-20260923.zip`](../../evaluation/real-qwen/aegisgraph-v5-qwen3-8b-evidence-20260923.zip) | Final v5 scorecard, metadata, logs, 40 raw traces (90 entries) | SHA-256 `37dbcf83…7f702d76` |
| [`allow-all-qwen3-8b.json`](../../evaluation/real-qwen/allow-all-qwen3-8b.json) | Allow-all scorecard / reachability control | Importable into the inspector |
| [`provenance-qwen3-8b.json`](../../evaluation/real-qwen/provenance-qwen3-8b.json) | Built-in provenance baseline scorecard | Importable |
| [`aegisgraph-qwen3-8b.json`](../../evaluation/real-qwen/aegisgraph-qwen3-8b.json) | AegisGraph v1 scorecard | Importable |
| [`aegisgraph-v3-qwen3-8b.json`](../../evaluation/real-qwen/aegisgraph-v3-qwen3-8b.json) | AegisGraph v3 scorecard | SHA-256 `4894de5b…32bdbb8` |
| [`aegisgraph-v5-qwen3-8b.json`](../../evaluation/real-qwen/aegisgraph-v5-qwen3-8b.json) | Final v5 scorecard | SHA-256 `b9b09378…8027c4` |
| [`ent_portal_rotation_draft-v5.jsonl`](../../evaluation/real-qwen/ent_portal_rotation_draft-v5.jsonl) | v5 trace for the reached-and-stopped redaction demo | `SENSITIVE_RESPONSE_REDACTED` |
| [`ent_portal_rotation_draft-targeted-v3.jsonl`](../../evaluation/real-qwen/ent_portal_rotation_draft-targeted-v3.jsonl) | Targeted v3 rerun of the same demo | Individually rerun |
| [`soc_patch_bastion_disclosure-v5.jsonl`](../../evaluation/real-qwen/soc_patch_bastion_disclosure-v5.jsonl) | v5 trace for the SOC action+response redaction demo | `SENSITIVE_ACTION_REDACTED`, `SENSITIVE_RESPONSE_REDACTED` |
| [`soc_patch_bastion_disclosure-targeted-v3.jsonl`](../../evaluation/real-qwen/soc_patch_bastion_disclosure-targeted-v3.jsonl) | Targeted v3 rerun of the SOC demo | Individually rerun |
| [`enterprise_project_status-v5.jsonl`](../../evaluation/real-qwen/enterprise_project_status-v5.jsonl) | Benign control trace, `task_success=true` | Use with the v5 scorecard |
| [`enterprise_memory_poison-v5.jsonl`](../../evaluation/real-qwen/enterprise_memory_poison-v5.jsonl) | Trace for the residual output-contamination finding | Unreached under allow-all |
| [`soc_hostile_log_text-v5.jsonl`](../../evaluation/real-qwen/soc_hostile_log_text-v5.jsonl) | Trace for the hostile-log residual finding | Unreached under allow-all |
| [`soc_intel_memory_poison-v5.jsonl`](../../evaluation/real-qwen/soc_intel_memory_poison-v5.jsonl) | Trace for the intel memory-poison residual finding | Unreached under allow-all |

Credential-like strings inside these synthetic traces are **canaries**, not real
credentials. The owner also authorized a public-view copy of only this synthetic
folder on Google Drive; the repository files are the evidence of record.

## 3. Mock (development) evidence — `evaluation/`

Generated with the pinned kit's deterministic mock model, not a real model.

| Path | Purpose |
| --- | --- |
| [`../../evaluation/README.md`](../../evaluation/README.md) | Mock scorecard table, calibration notes, reproduction command |
| [`allow-all-mock.json`](../../evaluation/allow-all-mock.json) | Reachability / control baseline |
| [`provenance-mock.json`](../../evaluation/provenance-mock.json) | Built-in `provenance` baseline |
| [`aegisgraph-mock.pre-calibration.json`](../../evaluation/aegisgraph-mock.pre-calibration.json) | Original fail-closed defence |
| [`aegisgraph-mock.pre-intent-calibration.json`](../../evaluation/aegisgraph-mock.pre-intent-calibration.json) | Provenance-calibrated defence |
| [`aegisgraph-mock.json`](../../evaluation/aegisgraph-mock.json) | Intent-envelope-calibrated defence |

These are development diagnostics, never Qwen results and never a jury score.

## 4. Report, gate and harness

| Path | Purpose |
| --- | --- |
| [`../../REPORT.tex`](../../REPORT.tex) | Legacy technical report source (threat model, architecture, evaluation, limitations) |
| [`../../output/pdf/AegisGraph-SENTINEL-Technical-Report.pdf`](../../output/pdf/AegisGraph-SENTINEL-Technical-Report.pdf) | Compiled report PDF; restored by the orchestrator unchanged (SHA-256 `69035d00…cc975c4f`, 293,903 bytes). Compiled from `REPORT.tex` at the legacy baseline and **not regenerated** |
| [`../../REPORT_PLAN.md`](../../REPORT_PLAN.md) | Report plan / milestone snapshot |
| [`../../benchmark.lock`](../../benchmark.lock) | Pinned benchmark and scenario counts |
| [`../../scripts/validate_attack_reachability.py`](../../scripts/validate_attack_reachability.py) | Allow-all reachability gate (read-only) |
| [`../../REACHABILITY_GATE.md`](../../REACHABILITY_GATE.md) | How to run the gate |
| [`../../OBSERVABILITY_DASHBOARD_BRIEF.md`](../../OBSERVABILITY_DASHBOARD_BRIEF.md) | Approved inspector design brief |
| [`../../DEMO_RUNBOOK.md`](../../DEMO_RUNBOOK.md) | Demo script |
| [`../../COLAB_QWEN_RUN.md`](../../COLAB_QWEN_RUN.md) | Free-T4 Qwen run protocol |
| [`../../SUBMISSION_CHECKLIST.md`](../../SUBMISSION_CHECKLIST.md) | Submission readiness checklist |
| [`../../SUBMISSION_HANDOFF.md`](../../SUBMISSION_HANDOFF.md) | Submission form handoff |
| [`../../VIDEO_SCRIPT_V5.md`](../../VIDEO_SCRIPT_V5.md) | Video script |
| [`../../sentinel-submission.yaml`](../../sentinel-submission.yaml) | Legacy manifest (team `9ahwa mahrou9a`) |
| `SENTINEL_Specification_Book_IndabaX_Tunisia.pdf` | Organizer specification book (timeless reference) |
| [`../../COURSE/README.md`](../../COURSE/README.md) | Teaching material index; the single-file course is [`../../COURSE/aegisgraph-course.html`](../../COURSE/aegisgraph-course.html) |

## 5. How to read the legacy evidence without fooling yourself

1. **Run the reachability gate first.** An attack result is void unless the same
   configuration reaches it under `allow_all`
   ([`../../scripts/validate_attack_reachability.py`](../../scripts/validate_attack_reachability.py)).
2. **Check the digest, not the filename.** Scorecard SHA-256 and the evaluator
   deterministic digest are in the real-model manifest; the inspector matches
   trace to scorecard by run id and withholds ambiguous outcomes.
3. **Know the denominator.** 31 attacks, but only 22 reached — the headline uses
   22. Nine unreached attacks are not defence evidence.
4. **Separate mock from real.** Anything under `evaluation/*.json` (no
   `real-qwen/`) is a mock development run.
5. **Read the residual findings.** A `attack_success=false` does not by itself
   mean a clean output; see the contamination findings in the manifest.
