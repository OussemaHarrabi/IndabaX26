# Technical report plan

This is the evidence map for the drafted [`REPORT.tex`](REPORT.tex). It follows the pinned organizer's research template and judging rubric. Historical `evaluation/README.md` values are **development mock** results; the real-model evidence is separately committed in [`evaluation/real-qwen/`](evaluation/real-qwen/README.md). Neither the mock nor real-model self-test is an official jury score.

## Evidence boundary and current gaps

- Benchmark source: `Skan22/Sentinel_Starter_Kit` commit `dd2e5fe0979d0781a4bfe6d0849cd80cf69ef4a2`, pinned in `benchmark.lock`: 40 scenarios (31 attacks, 9 benign), enterprise 15, finance 12, SOC 13. Note the PDF's older scenario count as a source discrepancy.
- Real-model measured artifact set: four matched 40-case full-suite runs, 160 JSONL traces, scorecards, metadata and logs in `evaluation/real-qwen/`. Allow-all reached 22/31 attacks; nine are excluded from defense-effectiveness claims. V3 stopped all 22 reached attacks in one seed but had BTU 4/9 and failed the kit's 0.5 utility gate. This caveat must appear beside any zero-ASR headline.
- Matched component comparison: AegisGraph v1 (`b791f79...`) with output guard absent versus v3 (`a511ff83...`) with generic exact-credential redaction/revalidation. The original v1 leak and v3 utility cost are trace-backed in the LaTeX report. A two-case block-only intermediate run is qualitative failure analysis, not a full-suite ablation.
- Remaining evidence: live organizer submission validator, Docker-engine check, final screen-captured 5–10 minute video, report PDF rendering/page QA, assistive-technology acceptance, source/license review, team eligibility and portal receipt. The dashboard has passed a headless-Chrome import of actual Qwen artifacts at desktop and 390px after fixing exact-run joining and horizontal overflow.
- The manifest has now been populated with the user-provided registered team name `9ahwa mahrou9a`; rerun the pinned validator and inspect its result before calling it submission-ready. Organizer guide requires teams of 3–5; because the user is working solo, ask the organizer how a solo participant/registered team is treated rather than implying the team-size requirement is met.

## Section-by-section outline

1. **Abstract (100–200 words).** State the deterministic provenance-aware pre-tool gateway and the completed Qwen result with both reached-attack security and the failed benign-utility gate. Do not lead with mock scores.
2. **Threat model.** Define protected asset (integrity/confidentiality of simulated tool actions), attack surfaces in candidate tool calls and untrusted observed content, attacker capabilities (indirect instructions, poisoned retrieved/memory content, exfiltration attempts, unauthorized/consequential actions), trust boundaries, and explicit scope: SENTINEL synthetic simulator only; no real-world cyber defense claim, no arbitrary multilingual prompt-injection completeness, and no host protection/auth by default.
3. **Hypothesis.** Use a falsifiable statement grounded in implemented behavior, e.g. whether evidence provenance + exact candidate-action coupling reduces successful attacks while preserving benign task utility compared with the built-in `provenance` baseline. Set numerical thresholds only before the final evaluation, and do not retrofit to mock outcomes.
4. **Method.** Diagram the reference agent → AegisGraph HTTP decision gateway → simulator tool path. Describe canonical request contracts, immutable action representation/digest, provenance resolution, deterministic policy checks, response/error behavior, observability fields, and boundary: AegisGraph does not execute tools or call an LLM. Explain why decisions use action/evidence/policy signals, not scenario IDs or expected outcomes. Include implementation commit and container constraints.
5. **Experiments.** Cite exact benchmark/source commits, 40-case inventory, Qwen/Ollama Q4_K_M runtime, Colab T4, commands and artifact hashes. Hold model, tools and prompt fixed. Compare allow-all, provenance, v1 and v3; specify the 22/31 reachability gate.
6. **Results.** Report ASR, BTU, FBR, DFI, TUI, UER, calibration and latency from raw scorecards; add domain slices and the distinct 22-reached denominator. The public suite is complete, but one seed is not a confidence interval. State `sentinel eval` is self-test, not jury score, and disclose `eligible=false`.
7. **Component comparison.** Isolate the v1-to-v3 output guard under matched configuration and report both attack and benign-utility effects. The intermediate block-only targeted check explains the choice of rewrite but is not a full-suite control.
8. **Failure analysis.** Explain v1 final-response leak, v3 exact-match coverage limits, the four benign failures already present under allow-all, and the one additional v3 consequential-email confirmation loss. Cite concrete run IDs/reason codes; no cherry-picking.
9. **Responsible AI and security.** State synthetic-only evaluation, local/no-inference-API model execution, no chain-of-thought collection, minimized/no persistent request storage (verify actual deployment/logging before asserting), expected false positives, human escalation role, lack of default authentication, deployment restrictions (loopback or protected network), incident/reporting process, and limitations/fairness across domains.
10. **Reproducibility.** Give repository commit/tag, benchmark pin, build/run/test/validator commands, model/download/runtime instructions, immutable raw scorecards and SHA-256/deterministic digests, environment capture, licenses, and exact mapping from report tables to artifacts. Include a statement that latency is nondeterministic and scorecard deterministic digest excludes latency, per organizer docs.

## Table and artifact conventions

| Field | Required record |
| --- | --- |
| Run identity | Unique run label, timestamp, command, output path |
| Code | AegisGraph commit and pinned starter-kit commit |
| Model | Exact `Qwen/Qwen3-8B` or `mock`; never abbreviate away the backend |
| Runtime | GPU/runtime, dtype/quantization, token budget, thinking mode, Python/dependency versions |
| Reachability | Per attack scenario's `attack_success` under `allow_all`; list failures/exclusions |
| Results | Raw evaluator artifact, deterministic digest, SHA-256, stderr/logs |
| Comparison | Same scenarios, tools, prompt, model and runtime across baselines/defense |

Use filenames from `COLAB_QWEN_RUN.md` and hashes from `evaluation/real-qwen/README.md`. Maintain mock results as a clearly separated iteration table; do not overwrite raw evidence. The LaTeX source contains a qualified assessment, not a claim that the utility gate, video, eligibility, or submission is complete.
