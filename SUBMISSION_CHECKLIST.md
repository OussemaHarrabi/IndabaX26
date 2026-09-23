# Submission readiness checklist

The pinned organizer guide and rubric are the source of truth. This checklist does not mark an item complete merely because a plan or starter artifact exists. Current mock scorecards are development evidence only; Qwen3-8B results and final video are still pending.

## Required deliverables

- [ ] **Defense:** buildable AegisGraph source and reproducible run instructions; verify actual current commit and no uncommitted source changes in release snapshot.
- [ ] **Observability layer:** every candidate decision legibly relates action, decision, reason/risk/confidence, and what happened next. The jury calls for a genuinely usable layer, not a static log dump; current API response/replay is not evidence that a dedicated visualization is finished.
- [ ] **5–10 minute demo video:** qualifying attack with per-scenario allow-all `attack_success=True`, defended attack blocked/stopped for the right reason, successful benign task, and live/readable explanation. Align every model/config claim with raw artifacts.
- [ ] **GitHub repository:** source, architecture, setup, evaluation, security statement, report, runbooks, raw or traceable result artifacts, license, and no secrets. Confirm correct remote/visibility and submit the URL through the organizer's process.
- [ ] **Technical report:** threat model, falsifiable hypothesis, method/architecture, experiments, results by domain and attack family, baselines, ablation, failure analysis, Responsible AI/security, and reproducibility. Follow the pinned report template.

## Official benchmark / evaluation

- [ ] Confirm `benchmark.lock` remains pinned to `dd2e5fe0979d0781a4bfe6d0849cd80cf69ef4a2` and report 40 scenarios (31 attacks, 9 benign) plus the old PDF count discrepancy.
- [ ] Record `allow_all` on every scenario used to support an attack claim. For every showcased attack, individually retain `attack_success=True` under the same reference-agent configuration.
- [ ] Run matched `allow_all`, `provenance`, and AegisGraph evaluations with fixed Qwen/Qwen3-8B identity, tools, and system prompt; disclose only permitted runtime differences.
- [ ] No external inference API for the reference Qwen run. Colab is acceptable per organizer's definition; record GPU, model/runtime settings, versions, seed, commands, traces, outputs and digests.
- [ ] Keep development `mock` results separate and labelled. No fabricated/missing values, no cherry-picking, no scenario-ID-dependent decisions. State that evaluator metrics are evidence, not official jury scores.
- [ ] Complete at least one controlled ablation and write concrete failure analysis; do not relabel policy-tuning history as an ablation unless it isolates one component under matched conditions.

## Engineering / package checks

- [x] Populate `sentinel-submission.yaml` with the user-provided registered name `9ahwa mahrou9a`.
- [ ] Validate the updated manifest against the exact pinned starter kit and save the complete output; do not treat filling the team field as proof that the team-size rule is satisfied.
- [ ] Run project tests, Ruff and mypy; preserve outputs/commit. Build and run container where Docker engine is available; validate non-root user and hardened runtime settings.
- [ ] With the defense service running, run the official submission validator including live health/decision contract checks. Save complete validator output. Static or mock contract success does not equal Qwen benchmark success.
- [ ] Confirm no credentials/secrets, no privileged container settings, no host socket mounts, and no external side effects or real-world target access. Keep service local or put deployment behind authentication/network controls.
- [ ] Verify exact licenses/source declarations in manifest, lockfiles, report and repository; verify output sizes and generated artifacts are manageable.

## Registration / eligibility decision

The organizer guide says teams contain **3–5 people**. The user supplied the registered team name `9ahwa mahrou9a` and is currently doing the implementation solo. Do not state that the eligibility condition is met by the team name alone or fabricate members. Before final submission, ask the organizer whether a registered one-person team is accepted or whether the team record must be updated to include 3–5 real participants. This is an external clarification, not a software task an agent can resolve autonomously.

## Final freeze and handoff

- [ ] Freeze a release commit/tag; ensure report commands work from a clean checkout.
- [ ] Map every reported number and demo statement to a raw artifact, replay trace, or source/configuration commit.
- [ ] Render/read all documentation and verify links; check video duration and watch the exported video end-to-end.
- [ ] Produce one manifest of deliverable filenames + SHA-256 hashes; exclude private notebook credentials and accidental local logs.
- [ ] Make the final submission using the organizer's designated portal/link and retain a receipt or confirmation.
