# AegisGraph research design

**Status:** preregistered · **Version:** 1.1 · **Date:** 2026-10-08
(amendment 1: the control-liveness check in §3 and the implemented families in §6)
**Companion documents:** `research-plan.md` (hypotheses), `statistics.md`
(analysis), `ablation-plan.md` (components), `claim-language.md` (wording).
Labels: `measured` / `implemented` / `proposed` / `blocked` / `[INFERENCE]` as in
`research-plan.md` §Status legend.

## 1. Unit of analysis

Two units, used for different questions and never mixed:

| Unit | Used for | Definition |
| --- | --- | --- |
| **Scenario** | RQ1 (attack effectiveness, utility), RQ2, RQ3, RQ5 | One pinned scenario evaluated once per configuration: a row of the scorecard `outcomes[]`, keyed by `scenario_id`. |
| **Decision** | RQ1 secondary metrics (FBR, escalation rate, UER, TUI), RQ4 (latency, throughput) | One `defense_decision` event returned by the gateway for one candidate action. |

A scenario contains many decisions. Decisions inside a scenario are **not**
independent observations and are never counted as such. FBR and escalation rate
are decision-level by the evaluator's definition
(`COURSE/notes/09-evidence-verification.md` §1), so they are reported as
decision-level ratios with their own denominators — never as if the scenario were
the unit.

## 2. Population versus case series (rejection of pseudo-replication)

The pinned 40 scenarios are a fixed, hand-authored case series, not a probability
sample of a population. Consequences, which the design enforces:

- No population inference. The exact McNemar p-values and exact binomial intervals
  are **conditional** on this scenario set, this model and this seed. They quantify
  how surprising the observed matched discordance would be *under the design's own
  pairing*, not a rate over a population of attacks.
- Effect sizes are reported as absolute counts and risk differences on named
  scenarios, not as estimated population rates.
- Adding repeats at temperature 0 does not add independent samples; it tests
  determinism (§6).
- A holdout (RQ5) is a **different** fixed case series, not a sample; its result is
  a generalization probe, not an unbiased estimate.

This is why every licensed claim names the suite, the model and the seed, and why
the forbidden forms in `claim-language.md` include any universal security claim.

## 3. Reachability rule

**Rule.** An attack-effectiveness claim is made only over `R`, the set of
`attack_present=true` scenarios whose `attack_success` is `true` under the
**allow-all** configuration with the same model, backend, quantization, prompt,
tools and seed as the defense run. `R` is derived once per model/backend from a
raw allow-all artifact and is committed alongside the comparison.

**The control-liveness check, stated so it can fail (amendment 1).** The rule above
is only useful if the control is checked, and the check must have a falsifiable
failure mode rather than restating the definition of `R`:

- **Check.** For every `attack_present=true` scenario, ask whether the control's
  verdict authorises the attack action (`attack_success=true` under allow-all).
- **On pass.** The scenario is *licensed* and enters `R`; the effectiveness
  denominator is the licensed set.
- **On failure.** The scenario's control verdict does **not** authorise the attack
  action. It is **excluded from the effectiveness claim and counted**, with its
  `scenario_id` listed. It is never counted as a stop and never enters any
  proportion; it neither supports nor falsifies the hypothesis.
- **Failure mode of the check itself.** If the excluded set is the *whole* attack
  set, the control authorised no attack action at all: the run measured nothing
  about the defense, no effectiveness claim is licensed, and every derived cell is
  void. This is the falsifiable form — it is a property of the artifact, not a
  restatement of the definition.
- **Instrumentation.** `docs/research/analysis.py` prints the licensed count, the
  excluded count and the excluded IDs on every run (`liveness` block in `--json`;
  a `Liveness …` line in Markdown). `measured` on the legacy control: 31 attack
  scenarios, 22 licensed, 9 excluded and counted.

The check is a harness/control check, not a claim about a real model: under a
scripted plan it shows the episode assembles and the action is one a decision
surface will authorise (`docs/benchmark/evaluation-card.md` §6).

Consequences:

- Unreached attacks are excluded from the effectiveness denominator and are never
  described as "blocked" or "defended". `measured` example: nine scenarios were
  unreachable under Qwen3-8B (`evaluation/real-qwen/README.md`), and residual
  output contamination was found in three of them — a clean `attack_success=false`
  there is not a defense win.
- `R` is model-dependent: 22/31 under Qwen3-8B (`measured`), 31/31 under the
  deterministic mock (`measured`, reproduced by `docs/research/analysis.py`).
- The validator enforces structural integrity: duplicate/missing `scenario_id`,
  non-bool `attack_present`/`attack_success`, or `attack_success=true` on a
  non-attack scenario raise (`scripts/validate_attack_reachability.py`).

**Documented caveat.** `REACHABILITY_GATE.md:14` states the gate exits non-zero if
*any* attack did not succeed — a binary contract. The real-Qwen allow-all run has
nine unreached attacks and therefore **fails** that gate; the project's comparison
therefore uses the 22-subset contract instead. `[INFERENCE]` this difference must
be stated wherever the gate is presented as the pre-comparison check, because a
reader who applies the documented gate literally would conclude the comparison
was never licensed. The design adopts the 22-subset rule explicitly rather than
silently.

## 4. Matched comparison design

**Design.** For each scenario, the same agent run is repeated under configurations
that differ **only** in the defense:

| Arm | Role |
| --- | --- |
| allow-all | undefended control; defines `R`; establishes the ceiling |
| built-in provenance | same-model baseline defense (secondary comparator for H1.1b) |
| AegisGraph full | treatment |
| one arm per ablation row | component-on/off treatments (RQ2) |

Held constant across arms: pinned starter kit commit, agent system prompt, tool
schemas, model, quantization, decode settings, temperature, seed, scenario
versions, and the scenario set. The reference agent's prompt and tools are never
modified and no safety instruction is inserted (`REPORT.tex` §"Model and
fair-comparison constraints").

**Why matched.** Between-scenario variance (difficulty, domain, attack family)
dominates between-arm variance; pairing removes it from the comparison. The
paired analysis is exact and does not need a distributional model.

**Threats and controls.**

| Threat | Control |
| --- | --- |
| Model nondeterminism | temperature 0, fixed seed; determinism verified by repeats (H3.4) |
| Defense changes the agent's context | the gateway returns only a decision; the harness feeds it back unchanged |
| Scoring changed by the treatment | the evaluator is the pinned kit and is not edited; the response schema is unchanged (see `ablation-plan.md` safety checks) |
| Reachability drift between arms | `R` re-derived from allow-all for every build; allow-all digest equality checked (H1.3, H2.3) |
| Selective reporting | fixed metric set, fixed hypotheses, fixed family-wise correction |
| Unreached attacks read as wins | the reachability rule (§3) |

## 5. Pairing, independence, exclusions, missing data

### 5.1 Pairing

Pairs are formed by exact `scenario_id` string equality. `analysis.py` refuses a
scorecard with a duplicate `scenario_id` and reports any `scenario_id` present in
one arm but not the other as `missing_reached` rather than dropping it silently.

### 5.2 Repeated-run independence

- **Temperature 0, fixed seed.** Runs of the same build and backend are expected to
  be identical. Repeats are therefore *not* independent samples; they measure
  serving/infrastructure variance. Analysis: report per-repeat counts and their
  range; agreement is the paired routine's discordant counts when repeat 1 is the
  control and repeat 2 the treatment.
- **Temperature > 0.** Each repeat is a new draw. Repeats are paired by scenario
  across repeats; between-run variance is reported separately from within-run
  scenario-level variation, and any pooled interval is labelled as a
  random-effects summary over runs, with the number of runs stated.
- The independence unit for a repeated design is **scenario × repeat**, not
  scenario alone; pooling repeats into a single denominator is prohibited.

### 5.3 Exclusions (pre-declared, exhaustive)

A scenario or run is excluded only for one of these reasons, each reported with a
count and the affected IDs:

1. The scenario is absent from the pinned suite in the other arm (schema/mismatch).
2. The run's `benchmark_version` or model/runtime metadata does not match the arm's
   declared header.
3. The scenario's row is structurally invalid (non-bool flags, duplicate id).

Never excluded: a scenario because its outcome is inconvenient. A non-null
`defense_error` is **not** an exclusion; it is handled by intention-to-treat (§5.4).

### 5.4 Missing data

- A scenario missing from a treatment arm is counted as a **failure** for that arm
  under intention-to-treat (an unavailable decision cannot execute the action
  safely), and the missingness is reported separately.
- A non-null `defense_error` on a decision counts as a failure for the
  effectiveness metric and is reported as a gateway reliability failure (RQ4).
- Sensitivity analysis: recompute the primary comparison excluding missing/errored
  rows; if the conclusion changes, the result is reported as inconclusive, not as
  the favourable version.
- Missing data is never imputed for attack or task outcomes.

## 6. Multiple comparisons

- **Confirmatory family RQ1:** four hypotheses (H1.1, H1.1b, H1.2, H1.3) tested
  with Holm–Bonferroni at family-wise α = 0.05, ordered by ascending p.
- **Confirmatory family RQ3:** H3.2, H3.3, H3.4 (H3.1 is blocked) with
  Holm–Bonferroni at α = 0.05.
- **Confirmatory family RQ4:** H4.1–H4.4 with Holm–Bonferroni at α = 0.05.
- **Confirmatory family RQ5:** H5.1–H5.3 with Holm–Bonferroni at α = 0.05.
- **Exploratory family RQ2:** the ablation matrix is exploratory; across rows use
  Benjamini–Hochberg FDR at q = 0.05 and label every RQ2 result "exploratory".
- Uncorrected p-values may be shown for transparency but must be marked
  "uncorrected".

**Implemented (amendment 1).** The families above are the ones
`docs/research/analysis.py` declares and corrects: F1 effectiveness (the
per-treatment reached-attack McNemar tests of one invocation), F2 utility (the
per-treatment benign `task_success` tests), F3 RQ3 slices (per treatment, its
reportable slice tests — a slice with no p-value is not a test and does not enter
the family), and RQ2 exploratory rows under BH. Both p-values are printed
(`exact p` raw, `Holm adj p` corrected) with the family size `m`, and a
confirmatory verdict is read off the adjusted value; when the count rule of an H3
hypothesis holds but the corrected gate does not, the script prints the overturn
rather than a bare verdict (`statistics.md` §5, `research-plan.md` §10).

## 7. Exploratory versus confirmatory boundary

**Confirmatory** = exactly the hypotheses named in `research-plan.md` with the
metric definitions and denominators fixed there, analysed with the methods in
`statistics.md`, on a frozen configuration, with the stated correction.

**Exploratory** = everything else: per-family slices not listed as hypotheses,
latency distributions beyond the stated percentiles, any metric invented after
seeing data, any subgroup discovered post hoc, and all ablation rows.

Rules:

- An exploratory finding may be reported, labelled exploratory, without a
  corrected p-value as if it were confirmed.
- An exploratory finding becomes confirmatory only after a dated amendment to
  `research-plan.md` **and** a fresh run on a configuration not used to generate
  the hypothesis. Re-analysing the same run cannot promote it.
- The exploratory/confirmatory status of each reported table is stated in its
  caption.

## 8. Design decisions recorded for the transition

`implemented` — the platform's purpose is to intercept a proposed action before
execution, apply versioned policy, bind the decision to the exact action, support
escalation/rewrite, and record auditable receipts. The research design must
therefore measure the **gateway's** decision, not a model's cooperation: the
treated unit is the candidate action, and the outcome is the harness's finding
after the gateway's decision was applied. `[INFERENCE]` a design that credited the
model for self-refusal would not test the platform, so no arm adds a safety prompt.

`measured` — the legacy evidence package (scorecards, traces, hashes) remains the
record for the challenge period; new runs under this plan are separate artifacts
with separate digests and are never merged into the legacy tables.
