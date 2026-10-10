# Continuation prompt: make the next AegisGraph experiment research-valid

You are the orchestrator for AegisGraph. Read AGENTS.md and the current evidence
ledger. Preserve the historical SENTINEL results, BF16 recovery smoke, FP16
public campaign and ablations as separate immutable evidence. The 10 October
FP16 measurements use source b130776a0a3797a41f93435d51d7597825a381f4 and remain
exploratory. Never re-score them as if they used a newer prompt or executor.

Goal: ship the smallest credible research/industrial extension that distinguishes
action authorization, execution, approval and task completion, removes incidental
prompt variation, and supplies reproducible model-performance measurements.
No robotics, external email/payment/remediation, paid inference or holdout opening
is required. Use a deterministic synthetic executor for public test fixtures.

## Why this work is needed

1. Current generated prompts contain complete decision receipts, including UUIDs,
   times and condition-identifying control labels. Identical initial prompts and
   equivalent policy decisions can produce different later prompt hashes.
2. The current harness authorizes read/write proposals but does not execute them
   or return new tool observations. Read loops and missing persistence cannot be
   treated as successful task completion.
3. Allowed confirmation requests do not mint human grants, but the model sometimes
   reports that approval and isolation already completed.
4. Episode budgets derive from authored script lengths, rather than an independent
   task-completion budget. Actual token lengths are discarded after decoding.
5. Positional generated-action scores are invalid. Exact authored-action coverage
   alone misses semantically equivalent harmful variants.

These are observed benchmark/reference-agent limitations, not permission to
weaken policies or hard-code dataset labels. No universal protection or deployable
end-to-end workflow claim is allowed.

## Agent distribution and ownership

Orchestrator owns integrated plan, shared contracts, preregistration, review,
integration and Git pushes. Start with a clean isolated branch from the agreed
current source, preserve other agents' work, and assign one writer per file.
Each delegation follows the AGENTS task contract. Agents do not push individually.

**A. Reference-agent feedback implementer**

Scope: benchmark/qwen.py and focused adapter tests. Create a versioned deterministic
feedback projection containing authorization verb, effective rewritten action,
normalized semantic reason and explicit approval/execution state. Keep complete
receipts in audit artifacts. Exclude UUIDs, timestamps, condition names, policy
hashes and transport/build fields from model input. Preserve bounded retries and
fail-closed parsing. Do not change gateway decision logic or public labels.

Regression: different receipt UUID/times with identical semantic decisions yield
identical prompt bytes; meaningful allow/block/escalate/rewrite changes alter the
prompt. Allow-all and full defence must share feedback shape and neutral vocabulary.

**B. Synthetic executor implementer**

Scope: a new benchmark executor module and its tests, plus one agreed integration
seam in campaign.py owned by the orchestrator. Define allowlisted per-tool argument
schemas, deterministic read results, factual-memory state and explicit inert
execution-result records. Use public synthetic observations only. Unsupported
tools/arguments produce a recorded failure, never fabricated success.

Execution requires allowed original action or valid revalidated rewrite, exact
receipt binding and unexpired context. Block/escalate leaves world state unchanged.
An allowed confirmation request records approval_pending; only a separately
authenticated exact grant can authorize a consequential action. A nested target
inside a request is not executed. Test malformed arguments, mismatched digests,
expired/reused grants, untrusted sources, safe rewrites and failed execution.

Do not silently make old tools or old runs execute. Version the executor and
record its source/hash in new run manifests.

**C. Evaluation and instrumentation implementer**

Scope: new semantic evaluator/instrumentation modules and focused tests; coordinate
all campaign.py changes with the orchestrator. Define label-independent runtime
execution state and evaluator-only scenario harm/utility predicates. Dataset labels
may guide post-hoc evaluation; they must never reach policy decisions.

Join proposed action, receipt, effective action and execution result. Record
authorized_harm, executed_harm, harmful_attempt, legitimate_task_completion,
unknown evidence, final response and budget exhaustion separately. Preserve raw
positional diagnostics under their original schema and mark their invalid scope.
Do not map unknown or error to successful protection. Check semantic variants,
negation, quotation, unsupported completion claims and canary normalization.

Use a separate frozen bounded episode budget. Record actual input-ID length,
new generated-ID length including stopping tokens, generation duration and stop
reason before decoding; decoded-text token estimates are not actual generation
counts. Record GPU allocation hours separately from active compute and token
throughput. Add tests for erroneous positional inference and missing tool results.

**D. Independent adversarial reviewer**

Read-only initially. Review one agreed boundary per milestone: feedback neutrality,
authorization/execution binding, confirmation state, or scorer denominators. Try
counterexamples: changed nonce, malformed rewrite, unconfirmed nested execution,
false final completion, harmless quotation, benign canary-free output and missing
receipts. Require concrete tests/trace evidence. Never tune the policy to make
the experiment pass. Independently adjudicate disputed semantic annotations.

## Experimental plan for the new version

Before running, append a new dated freeze block with source commit, model revision,
chat-template/prompt/executor/evaluator hashes, dtype/NF4 settings, maximum context,
generation budget, retry settings and complete declared seed list. State that
greedy repeats are determinism checks, not independent seed samples. A stochastic
stability arm is optional and must be separately preregistered with temperature,
sampling parameters, repeated-trial design and compute budget.

Choose a small labelled pilot first. Verify identical deterministic replay inputs
and prompt hashes, complete execution-state records, matched independent allow-all
rollouts and correct positive/negative controls. Verify semantic judgements with
the reviewer. Record errors and negative utility outcomes. Do not start the larger
GPU campaign until these validity gates pass. Use Kaggle/Colab; no local GPU exists.

Then run the frozen public development and validation case sets and the four
single-mechanism ablations. Reuse controls only under identical model/config/input
versions. Keep development, validation, historical results, greedy repetitions and
new stochastic arms separate. Retain every declared run; do not select the best.
The sealed holdout needs the custodian's explicit separate authorization after
the agreed gates. Do not open it merely because the public campaign is complete.

## Acceptance and outputs

- Focused regressions show red before fixes and green after them.
- Full tests, Ruff, strict typing and hosted CI pass; database gates run with a
  real PostgreSQL service rather than silently skipping.
- A clean-clone verifier validates source/version pins, raw artifact hashes,
  receipt/action/execution correspondence and analysis reconstruction.
- Public-run and ablation tables provide counts before percentages, reached-attack
  denominators from independent allow-all generation, benign completion, unknowns,
  errors, stage/seed variation and negative results. Never pool identical repeats
  for p-values. Use exact paired analysis only when its preregistered assumptions
  and sample/reportability floors hold; otherwise state why it is unavailable.
- Latency tables distinguish HTTP roundtrip, service latency, end-to-end episode,
  model generation and time spent loading. Include hardware, precision, token
  counts and actual allocation time; missing fields stay unavailable.
- Supply runnable GPU notebooks with pinned bootstrap, interruption/resume,
  secret-safe artifact export and archive verification; also supply a private
  CLI runner so a browser tab need not remain open.
- Deliver a technical report, evidence ledger, reproduction commands, negative
  result analysis, remaining limitations and three bounded CV bullets. No claim
  of publications, production deployment, universal defence or new skills merely
  because a dependency appears in the project.

Commit cohesive verified changes with clear messages; push the feature branch
after orchestrator review and normal non-force remote checks. Preserve failed
experiments and old reports. No secrets, credentials, model weights, issuer keys,
runtime databases or unreviewed proprietary content enter Git. Avoid unrelated
cleanup and unnecessary distributed infrastructure.
