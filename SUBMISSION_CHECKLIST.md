# Submission readiness checklist

The pinned organizer guide and rubric are the source of truth. This checklist does not mark an item complete merely because a plan or starter artifact exists. Four matched real-Qwen3-8B self-test runs and 160 raw traces are now committed under `evaluation/real-qwen/`; the final video and several release gates remain pending. V3 failed the kit's benign-utility eligibility gate (4/9 below 0.5), despite zero attack successes among 22 reached attacks. Do not portray it as an official qualifying score.

## Required deliverables

- [x] **Defense prototype:** AegisGraph v3 source, exact commit and reproducible run instructions; final release freeze and validator remain below.
- [x] **Observability implementation:** read-only dashboard with trace/scorecard import, filters, event inspector and decision/effect relationships. Manual acceptance with actual Qwen artifacts and responsive/assistive-tech checks remain below.
- [ ] **5–10 minute demo video:** qualifying attack with per-scenario allow-all `attack_success=True`, defended attack blocked/stopped for the right reason, successful benign task, and live/readable explanation. Align every model/config claim with raw artifacts.
- [ ] **GitHub repository:** source, architecture, setup, evaluation, security statement, report, runbooks, raw or traceable result artifacts, license, and no secrets. Confirm correct remote/visibility and submit the URL through the organizer's process.
- [x] **Technical report source:** `REPORT.tex` contains threat model, architecture, real-model evaluation, matched component comparison, failure/utility analysis, limitations, and reproducibility. Rendering and template verification remain below.

## Official benchmark / evaluation

- [ ] Confirm `benchmark.lock` remains pinned to `dd2e5fe0979d0781a4bfe6d0849cd80cf69ef4a2` and report 40 scenarios (31 attacks, 9 benign) plus the old PDF count discrepancy.
- [x] Record `allow_all` for all 31 attack scenarios. Only 22 reached; both showcase candidates have individual `attack_success=True` and retained traces.
- [x] Run matched `allow_all`, `provenance`, AegisGraph v1 and v3 evaluations with fixed Qwen/Qwen3-8B identity, tools, and system prompt; disclose permitted runtime changes.
- [x] No external inference API for the reference Qwen run. Free Colab T4, local Ollama Q4_K_M, runtime settings, versions, seed, commands, traces, outputs and digests recorded.
- [ ] Keep development `mock` results separate and labelled. No fabricated/missing values, no cherry-picking, no scenario-ID-dependent decisions. State that evaluator metrics are evidence, not official jury scores.
- [x] Compare v1 (output guard off) with v3 (output guard on) under the same model/runtime/public suite, and document v1 leak and v3 benign-utility failure. This is one matched component comparison, not repeated-trial certainty.
- [ ] Resolve or explicitly accept the kit's `eligible=false` utility gate: v3 BTU 4/9 versus required 0.5. Do not remove consequential-action confirmation solely to pass the gate; any policy revision requires a fresh full matched evaluation.
- [ ] Address or explicitly demonstrate the residual output/memory contamination in `enterprise_memory_poison`, `soc_hostile_log_text`, and `soc_intel_memory_poison`. These three attacks are allow-all-unreached for their specific success graders, so a zero ASR must not hide the contaminated records/responses. Use generic source-attribution tests, not scenario IDs.

## Engineering / package checks

- [x] Populate `sentinel-submission.yaml` with the user-provided registered name `9ahwa mahrou9a`.
- [ ] Validate the updated manifest against the exact pinned starter kit and save the complete output; do not treat filling the team field as proof that the team-size rule is satisfied.
- [ ] Run project tests, Ruff and mypy; preserve outputs/commit. Build and run container where Docker engine is available; validate non-root user and hardened runtime settings.
- [ ] With the defense service running, run the official submission validator including live health/decision contract checks. Save complete validator output. Static or mock contract success does not equal Qwen benchmark success.
- [ ] Confirm no real credentials/secrets in release artifacts, no privileged container settings or host socket mounts, and no external side effects or real-world target access. The committed trace canaries are synthetic. Keep service local or put deployment behind authentication/network controls.
- [ ] Verify exact licenses/source declarations in manifest, lockfiles, report and repository; verify output sizes and generated artifacts are manageable.

## Registration / eligibility decision

The organizer guide says teams contain **3–5 people**. The user supplied the registered team name `9ahwa mahrou9a` and is currently doing the implementation solo. Do not state that the eligibility condition is met by the team name alone or fabricate members. Before final submission, ask the organizer whether a registered one-person team is accepted or whether the team record must be updated to include 3–5 real participants. This is an external clarification, not a software task an agent can resolve autonomously.

## Final freeze and handoff

- [ ] Freeze a release commit/tag; ensure report commands work from a clean checkout.
- [ ] Map every reported number and demo statement to a raw artifact, replay trace, or source/configuration commit.
- [ ] Render the LaTeX report, read every page, verify links and tables; check video duration and watch the exported video end-to-end.
- [ ] Produce one manifest of deliverable filenames + SHA-256 hashes; exclude private notebook credentials and accidental local logs.
- [ ] Make the final submission using the organizer's designated portal/link and retain a receipt or confirmation.
