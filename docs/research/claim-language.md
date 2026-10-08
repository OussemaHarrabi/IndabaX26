# AegisGraph permitted claim language

**Status:** preregistered · **Version:** 1.1 · **Date:** 2026-10-08
(amendment 1: the corrected p and the control-liveness count are required
qualifiers; the holdout template names the `policy.blob_sha256` gate input)
**Companion documents:** `research-plan.md` (hypotheses), `design.md` (case-series
boundary), `statistics.md` (reporting format). Labels as in `research-plan.md`.

This file is normative. A report, README, dashboard caption, slide or commit
message that violates it is a defect and must be corrected before release.

## 1. Universal rules

1. **Name the artifact.** Every claim names the suite, the benchmark commit, the
   model and quantization, the temperature and seed, the defense source commit and
   the denominator. A comparison missing any of these is not reportable
   (`statistics.md` §10).
2. **Reached set.** Attack-effectiveness claims are made only over `R`, the attacks
   reached under allow-all with the same model/backend/seed. Unreached attacks are
   never called blocked or defended.
3. **Case series, not population.** Use "on this suite", "in this one seeded run",
   "conditional on this fixed case series". Never a population rate.
4. **Counts before proportions.** `0/22`, then `0.0000`. Never a bare percentage.
5. **Self-test, not jury score.** The evaluator's optional `official_score` and the
   0.5 utility gate are the kit's self-test, not the human jury's rubric.
6. **Legacy integrity.** The historical evidence package is quoted exactly; its
   limitations (BTU 4/9 below the utility gate, residual output contamination,
   unreached attacks) travel with the numbers.
7. **No future tense for unbuilt work.** Label `proposed` or `blocked`; never
   describe a planned capability as present.
8. **Corrected p, not raw p.** A confirmatory claim quotes the family-corrected
   (Holm–Bonferroni) p-value with its family size `m`; a raw p may be shown only
   marked "uncorrected". A verdict the correction overturns is reported as
   "not confirmed", never as "holds" (`statistics.md` §5).
9. **Liveness count travels with the claim.** Every effectiveness claim states how
   many attack scenarios the control licensed and how many were excluded and
   counted; a claim that hides the excluded set is a defect (`design.md` §3).

## 2. Required qualifiers by result class

### 2.1 Legacy measured result (challenge period, frozen artifacts)

- **Allowed.** "On the pinned public 40-scenario suite (starter kit
  `dd2e5fe0979d0781a4bfe6d0849cd80cf69ef4a2`) with Qwen3-8B
  (`ollama:qwen3:8b`, Q4_K_M) at temperature 0 seed 0, reached-attack success went
  22/22 → 0/22 with 4/9 benign tasks retained. The 22 are the attacks reached under
  allow-all; the other nine were unreachable and are not defense evidence. This is
  one seeded synthetic public-suite run, not a population estimate and not a
  universal security claim. The kit's 0.5 self-test utility gate is **not** met
  (BTU 4/9)."
- **Allowed (component, measured).** "The v1→v3 code difference adds the generic
  exact-credential output guard with the suite, model, prompt, tools and seeds
  fixed; reached-attack success moved 10/22 → 0/22 and BTU stayed 4/9. This is a
  component-on/off comparison on one seeded run, not independent repeated trials."
- **Forbidden.** "AegisGraph stops prompt injection." · "ASR is 0." ·
  "AegisGraph blocks 100% of attacks." · "The gateway is secure." · "It passes the
  utility gate." · "It generalizes across models." · "The nine unreached attacks
  were blocked." · Any universal security claim.

### 2.2 New measured result (pinned public suite, this plan)

- **Template.** "On \<suite\> (\<n\> scenarios, benchmark commit \<c\>) with
  \<model\> \<quantization\> at temperature \<t\> seed \<s\>, among the `|R|`
  attacks reached under allow-all (of \<attacks\> attack scenarios; \<excluded\>
  excluded from the claim and counted), \<defense label\> (commit \<sha\>) stopped
  `b/|R|` (allow-all `|R|/|R|`; built-in provenance `p/|R|`), with benign task
  success `k/n_benign`. Exact McNemar p = \<p\> raw, \<p_adj\> after
  Holm–Bonferroni over the \<m\>-member family, conditional on this fixed case
  series. One seeded run on a synthetic suite."
- **Forbidden.** Dropping the reached-set sentence; dropping the liveness count;
  reporting the full-suite ASR (31-denominator) as the effect; calling the result
  "significant" without the conditional qualifier; calling a result significant on
  its raw p when the corrected p does not clear the threshold; calling a null a
  success.

### 2.3 Mock / development result

- **Allowed.** "On the deterministic mock model — a development instrument, not a
  neural reference agent — the intent-envelope configuration reached BTU 0.8889 and
  FBR 0.0683 at ASR 0.0000 on the pinned mock suite. Mock numbers do not
  demonstrate model performance."
- **Forbidden.** Presenting a mock number as a model result; mixing mock and
  real-model rows in one table without a per-row label.

### 2.4 Component / ablation result (exploratory)

- **Allowed.** "Exploratory component-on/off ablation ABL-F-cred on the same
  reached set `R` raised reached-attack success from `x/22` to `y/22`, with all
  other components fixed; the ablation build failed exactly the credential-redaction
  tests and reproduced the allow-all control digest. Exploratory; not
  family-wise corrected."
- **Forbidden.** Reporting an ablation as confirmatory; attributing an effect to a
  component whose ablation build did not actually disable it (R2); reading an FBR
  drop as an improvement.

### 2.5 Null / negative result

- **Allowed.** "ABL-G showed no change in reached-attack success on `R`; the
  memory-poisoning scenarios were unreached under allow-all, so this row is a null
  result on this suite and does not measure the mechanism's effect."
- **Forbidden.** Omitting the row; describing a null as "consistent with
  effectiveness".

### 2.6 Blocked / not-run result

- **Allowed.** "A second model backend is **blocked** in this environment (no
  Ollama, no GPU, CPU-only inference). The command to run it later is
  `ollama serve` plus the pinned evaluator with `--model ollama:qwen3:8b`."
- **Forbidden.** Filling a blocked cell with mock data, a placeholder, or an
  estimate presented as a measurement.

### 2.7 Holdout result (RQ5)

- **Allowed.** "On the sealed holdout (\<count\> scenarios, seal digest \<h\>),
  frozen at \<tag\> with `policy.blob_sha256` unchanged between freeze and unseal,
  the reached-attack success was `a/b`, a gap of `+g` against the public reached
  set. One-shot evaluation; the holdout is now retired."
- **Forbidden.** Reporting a holdout result after a second use without retiring the
  set; reporting it without the seal-integrity check (`policy.blob_sha256`, H5.2);
  reporting it at all before the freeze/unseal comparison has run — the H5.2 gate
  is instrumented but not yet exercised and the seal is closed (`research-plan.md`
  §6.4, §11); tuning on it.

### 2.8 Operational result (RQ4)

- **Allowed.** "On \<CPU\>, \<OS\>, Python \<v\>, one uvicorn worker, after 20
  warm-up requests, at concurrency 1 with N ≥ 1000 decisions, the full
  configuration's p95 decision latency was \<x\> ms (p50 \<y\>, p99 \<z\>) with zero
  non-2xx responses and zero defense errors. Gateway marginal cost is $0; model
  cost is reported separately."
- **Forbidden.** Reporting a mean latency alone; reporting latency without the
  hardware header; presenting model GPU cost as gateway cost; comparing cells
  measured on different hardware as if paired.

### 2.9 Output-integrity result

- **Allowed.** "`attack_success=false` on `enterprise_memory_poison` is not a
  defense win: that scenario was unreached under allow-all, and the v5 trace still
  contains residual prompt laundering (the response instructs the user to call
  `document_read` with `DOC-3104`). Output integrity remains incomplete."
- **Forbidden.** "No data leaked." · "Outputs are clean." · Treating
  `attack_success=false` on an unreached scenario as a stop.

### 2.10 Platform capability (implemented vs proposed)

- **Allowed.** "Implemented: a decision gateway that returns allow/block/escalate/
  rewrite for a proposed action and revalidates rewrites; a bounded provenance
  normalizer; a read-only evidence dashboard. Proposed: versioned policy lifecycle,
  durable audit store, caller authentication, deployment-grade transport security."
- **Forbidden.** "The platform enforces policy in production." · "Receipts are
  tamper-evident." · Any deployment or compliance claim.

## 3. Banned phrases (mechanical check)

The following must not appear in a claim context (a sentence describing a result):

`prevents prompt injection` · `100%` (of attacks) · `zero false positives` ·
`universally` / `in general` (for effectiveness) · `proven secure` ·
`official score` (as a jury result) · `passes the utility gate` ·
`guarantees` · `all attacks blocked` · `no data leakage` · `calibrated`
(for Brier/ECE) · `statistically significant` (without "conditional on this fixed
case series").

## 4. Reviewer checklist

- [ ] Every number names its artifact, command, denominator and commit.
- [ ] Every effectiveness claim names `R` and its size.
- [ ] Legacy limitations are present wherever legacy numbers appear.
- [ ] Mock rows are labelled mock; blocked cells say blocked.
- [ ] Exploratory rows are labelled exploratory; corrected p-values are corrected.
- [ ] No banned phrase from §3 appears in a claim context.
- [ ] The sentence is true of the commit it is attached to.
