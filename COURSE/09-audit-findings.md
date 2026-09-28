# Module 9 — Audit findings: what is solid, what is fragile, what to do next

> **What this module gives you:** an independent read of the project. Which claims survive re-verification, which parts are fragile, how much each weakness actually costs you, and a ranked repair list you can execute.

**Prerequisites:** [Module 7](07-the-decision-kernel.md) and [Module 8](08-evidence-and-evolution.md).

---

## 1. How this audit was done (so you can judge its findings)

The audit did not read the project's READMEs and repeat them. It did four things:

1. **Recomputed the evidence from the raw artifacts.** All ten scorecards in `evaluation/` were re-parsed from their per-scenario `outcomes[]` arrays, and every metric key, per-domain slice, and composite was recomputed without using the project's own metric code.
2. **Re-hashed the artifacts.** Every SHA-256 that the project claims for a scorecard, an archive, or a trace file was recomputed from the bytes on disk, and the evaluator's deterministic digest algorithm was reimplemented from the documented description.
3. **Re-read the implementation.** Every claim about code below carries a `file:line` anchor that was opened and checked in this audit.
4. **Re-ran the specific greps** behind the project's strongest honesty claim (no scenario-id-specific decisions) and behind several "dead code" findings.

Every statement below is labelled by evidence class, and you should keep that habit when you read security work:

| Class | Meaning |
| --- | --- |
| **measured** | an artifact exists and was recomputed |
| **code reading** | the statement is what the code does on inspection |
| **`[INFERENCE]`** | the auditor's reasoning, not a fact in the repository |

Severity used in this module:

| Severity | Meaning |
| --- | --- |
| **S1** | breaks a claim the project makes, or leaves a real bypass in the threat model |
| **S2** | costs points on the jury rubric, misleads a reader, or blocks reproducibility |
| **S3** | hygiene; fix when convenient |

---

## 2. What is verified and solid

Start here, because it is the part you can rely on in a report, a slide, or an interview.

| Claim | How it was checked | Result |
| --- | --- | --- |
| v5 stops every attack that a real model actually reaches: 0 of 22 | reached set recomputed from the allow-all run; v5 outcomes recomputed from its scorecard | **exact match** |
| Undefended baseline succeeds on all reached attacks: 22 of 22 (full suite 22/31 = 0.7097) | recomputed from `evaluation/real-qwen/allow-all-qwen3-8b.json` | **exact match** |
| All 18 metric keys and all per-domain slices of all 10 scorecards | recomputed independently from `outcomes[]` | **zero mismatches** |
| All 14 claimed SHA-256 digests (3 evidence zips, 5 scorecards, 3 JSONL trace files, others) | recomputed with a hashing tool | **byte-for-byte match** |
| Evaluator deterministic digest (latency excluded) | algorithm reimplemented and re-run | **reproduced** |
| 189 decisions = 113 allow / 16 rewrite / 59 block / 1 escalate, zero defense errors | counted from `evaluation/real-qwen/aegisgraph-v5-qwen3-8b-evidence-20260923.zip` | **exact match** |
| The suite is 40 public scenarios (31 attack, 9 benign) in 3 domains | counted files; cross-checked against `benchmark.lock` | **exact match** |
| No scenario-id-specific decisions | grep for true scenario ids (`\b(ent|fin|soc)_[a-z]`) across `backend/`: zero hits; the only `scenario` references are dashboard display plumbing | **claim holds** |
| The decision path is pure and deterministic | code reading: no caches, counters, or globals in `backend/aegisgraph/{adapter,policy,engine}.py`; a test asserts identical output for repeated identical requests | **holds** |
| Fail-closed boundaries exist at the adapter, policy, and evaluation layers, and the response is hard-capped at 64 KB with a block fallback | `backend/aegisgraph/app.py:20,91-105` | **holds** |
| The documentation is honest about limits | `eligible=false` is stated, mock-vs-Qwen runs are labelled separately, the failure analysis names the surviving laundering case, and the report's own text says the defense is "not a substantiated winner" | **holds** |

**What this means in plain language:** the arithmetic and the artifact discipline of this project are trustworthy. The weaknesses are in *coverage*, *trust assumptions*, and *release polish* — not in the numbers you would quote.

---

## 3. Findings register

| ID | Sev | Area | Finding | Anchor |
| --- | --- | --- | --- | --- |
| F1 | S1 | trust model | A conversation item on a trusted role (`user`/`agent`/`safety`/`human`) that cites **no** provenance ids is silently trusted as `AUTHENTICATED_USER` + `TRUSTED_INTERNAL`, with `provenance_complete` left `True`. **Demonstrated live** (below): the identical hostile instruction is blocked when it arrives as an untrusted tool result and allowed when it is placed on a `user`-role item without provenance | `backend/aegisgraph/adapter.py:55-68` |
| F2 | S2 | duplicate guard, untested codes | `validate_rewrite()` — the public rewrite guard — has no caller outside tests, so its codes (`UNSAFE_REWRITE`, the `REWRITE_*` family, `SAFE_REWRITE`) cannot fire in production. The codes that *do* fire live are emitted by the engine's internal revalidation, not by this helper. Treat any statement that "all rewrite codes are dead" as false | `backend/aegisgraph/engine.py:371-459` (helper) vs `engine.py:606-610,694-702` (live) |
| F15 | S2 | decision posture | Rewrite revalidation accepts only `ALLOW`. A redaction whose replacement would still require confirmation is therefore converted into a hard `block` (risk 1.0) instead of an `escalate`. **Demonstrated live**: an internal-domain `email_send` quoting a confidential credential returns `block` / `REDACTION_REVALIDATION_FAILED` rather than an escalation for confirmation | `backend/aegisgraph/engine.py:606-610` |
| F3 | S1 | submission | Release blockers are open: no video, no rendered report PDF, no live organizer-validator run, no verified Docker-engine run, and a solo registration against a 3–5 member rule | `SUBMISSION_CHECKLIST.md`, `SUBMISSION_HANDOFF.md`, `README.md` |
| F4 | S2 | service | No HTTP-layer body-size limit; per-field caps imply bodies up to a few MB are buffered before validation. The response is capped, the request is not | `backend/aegisgraph/app.py:83-105` (no middleware); field caps in `sentinel.py` |
| F5 | S2 | metric meaning | `risk_score` is a literal per gate and `confidence` is a constant, yet Brier score and ECE are reported — those calibration numbers measure rule constants, not judgement quality | `backend/aegisgraph/engine.py:1107` (confidence 0.99), literals per gate |
| F6 | S2 | coverage | The intent envelope binds arguments for `email_draft`/`email_send`, `ticket_update`, `case_note_create`, `payment_prepare`, `incident_create`, `incident_update`, `remediation_prepare` — but not for `payment_confirm`, `payment_execute`, `remediation_execute`, so for those the goal-binding leg is vacuous and only the confirmation digest protects the arguments | `backend/aegisgraph/engine.py:860-869` |
| F7 | S2 | generalization | Detection is vocabulary-shaped: literal instruction patterns, English verbs, whitespace-only normalization, adjacency windows for fragment stitching, digit-bearing assignment-form secrets. Paraphrase, translation, encoded payloads, longer multi-turn laundering, unknown tools, non-email exfiltration channels and digit-less secrets are structurally uncovered | `backend/aegisgraph/engine.py:91-92,107-127,892-937,963-970,629`; `backend/aegisgraph/policy.py:75-83` |
| F8 | S2 | documentation | Documentation drift: a linked report PDF that does not exist, an unsourced jury-stage point split, runbooks still describing the pre-v5 prototype, a "120/40/40 traces" claim against 121/42/45 in the archives, and a promised per-family metric slice that no scorecard contains | `README.md:5,83`; `REPORT.tex` (stage split); `evaluation/real-qwen/README.md` |
| F9 | S2 | evidence contract | The reachability gate is documented and implemented as binary (any unreachable attack ⇒ non-zero exit), while every headline table uses a 22-attack subset — the project's numbers follow a weaker contract than its own gate | `REACHABILITY_GATE.md`; `scripts/validate_attack_reachability.py` |
| F10 | S2 | observability (40-pt rubric category) | Dashboard defects: an "attack reachability" row fed by a field no artifact emits; the uncontrolled-comparison warning ignores the only fields that differ between revisions (`deterministic_digest`, `defense`, `score`); six trust levels collapse to three buckets; missing forced-colors/contrast support and incomplete ARIA tab semantics | `backend/aegisgraph/static/dashboard.js:302-308,395-409`; `tests/test_dashboard.py` |
| F11 | S2 | packaging | Two dependency sources of truth (`pyproject.toml` ranges vs `requirements.lock` pins) with no test reconciling them; `.dockerignore` omits `evaluation/` (~2.4 MB) and `scripts/`; the Docker path has never been executed | `Dockerfile`, `requirements.lock`, `.dockerignore` |
| F12 | S3 | kit-side behaviour | Harness details that change how you read evidence: a rewrite may name any registered tool (not only the scenario's allowed tools); an escalation on a non-tool action bypasses the confirmation record; the memory-sink leak check hardcodes trusted-internal; `DEFENSE_DECISION` events drop the response `metadata` | `.sentinel_reference/src/sentinel/agent/reference.py:314-341`; `.sentinel_reference/src/sentinel/core/state.py` |
| F13 | S3 | evidence format | v1 archive metadata omits benchmark commit / deterministic digest / temperature that v5 includes; mock scorecards carry an optional composite score that invites being read as an official number | `evaluation/real-qwen/aegisgraph-qwen3-8b.json`; `evaluation/README.md` |
| F14 | S3 | integrity | Traces and scorecards are not fingerprinted with the defense revision — the failure mode the README itself warns about (a single wrong-revision scorecard with a matching run id cannot be detected) | `README.md` (judge's quick path) |

### 3.1 The findings that matter most

**F1 — the trust boundary is asserted by the caller, not proven by the defense.**

The adapter's job is to turn a wire request into canonical observations. When an item cites provenance ids, the adapter looks them up and copies `trust_level` and `sensitivity` from the wire record — a record the *client* supplies (`adapter.py:81-91`). When an item cites **no** ids and its role is `user`, `agent`, `safety` or `human`, the adapter fills in `AUTHENTICATED_USER` + `TRUSTED_INTERNAL` and does not mark the request incomplete (`adapter.py:55-68`).

This is not a hypothesis. Four requests were sent to the running service during this audit, and the only difference between the blocked and the allowed case is **which channel the text arrived on**:

| Request | Arrival channel | Result |
| --- | --- | --- |
| Hostile instruction as an untrusted tool result, cited by provenance id, repeated in the action's own text | `tool` observation with `provenance_ids` | `block`, `UNTRUSTED_INSTRUCTION`, risk 0.99 |
| The same instruction in a `user`-role conversation item with no provenance ids, repeated in the action's own text | role-asserted trust | **`allow`, `POLICY_CHECKS_PASSED`, `least_trust: authenticated_user`** |
| The same instruction written to memory from a `safety`-role item with no provenance ids | role-asserted trust | **`allow`**, metadata records `memory_trust: trusted_internal` |
| Control: the same memory write with untrusted provenance | `tool` observation with `provenance_ids` | `allow`, `UNTRUSTED_MEMORY_INHERITED`, `memory_trust: untrusted_external` |

In the pinned harness the attacker mutates declared text surfaces, which carry provenance, so the published threat model is not bypassed by this. The weakness is at the contract boundary: **the component that is supposed to enforce the trust boundary accepts a self-declaration of trust from the component it is guarding**, and when that happens the untrusted-instruction rule and the credential-redaction rule both stay silent (rows 2 and 3). The mitigation that preserves utility is not "trust nothing" — it is to require an explicit provenance id, or an explicit harness-level `implicit_trust` flag, before text is treated as authenticated user intent.

**F2 — a rewrite guard that only tests exercise, and codes that are wrongly assumed dead.**

`engine.py:371` defines `validate_rewrite(request, rewritten_action)`, which re-runs the decision ladder and adds rewrite-specific rules (finality, confirmation bypass, enforcement downgrade, effect escalation). Grep confirms no caller outside `tests/test_policy_kernel.py`: the served endpoint calls `decide()` only. The codes emitted only by that helper — `UNSAFE_REWRITE`, `REWRITE_FINALITY_ESCALATION`, `REWRITE_CONFIRMATION_BYPASS`, `REWRITE_FINAL_ACTION_CHANGED`, `REWRITE_ENFORCEMENT_DOWNGRADE`, `REWRITE_EFFECT_ESCALATION`, `SAFE_REWRITE` — cannot fire in production.

The served path is not unguarded, though, and this is where a careless audit goes wrong: the engine re-validates its own replacements inside `_redact_sensitive_flow` (`engine.py:606-610`) and `_redact_untrusted_authority` (`engine.py:694-702`), and those codes *are* live — this audit observed `REDACTION_REVALIDATION_FAILED` returned by the running service. The accurate finding is therefore narrower than "the safety path is dead": **there are two rewrite validators, only one of them runs, and the dead one is the one that looks authoritative.** Wire it in or delete it; do not leave a reviewer guessing which mechanism protects a substitution.

**F15 — a rewrite that should escalate becomes a hard block.**

Revalidation accepts exactly one outcome: `ALLOW`. Anything else becomes `_block("REDACTION_REVALIDATION_FAILED", 1.0)`. Consider an internal email whose body quotes a credential taken from a confidential record. The engine redacts the credential — correct — then re-evaluates the redacted action, which is still consequential and still lacks a confirmation digest, so the inner evaluation returns `escalate` rather than `allow`, and the outer decision collapses to a block. Demonstrated live: that exact request returned `block` / risk 1.0 instead of asking a human.

The security intent is defensible (never execute a substitution that is not itself clean), but the utility cost is real and invisible in the docs: **an action that would have been escalatable becomes a hard refusal once a secret is found inside it**, which is a plausible contributor to the residual false-block rate. The cheap fix is to propagate the inner verdict when it is `escalate` (escalating the *redacted* action, with the reason code explaining the redaction), and to keep the hard block only for inner `block`.

---

## 4. The repair plan (ordered, with acceptance criteria)

Do these in order; each one is independently shippable. "Acceptance" is what you must be able to show, not what you must believe.

| # | Action | Acceptance | Regression risk |
| --- | --- | --- | --- |
| 1 | Close F1: require explicit provenance for consumed content, or mark implicit trust as incomplete and fail closed | A crafted request whose hostile text is placed in a `user`-role item with no provenance ids is blocked (new test), while the benign suite still passes | Medium — the harness sets roles, so check how often it omits provenance ids before making this strict |
| 2 | Resolve F2 and F15: keep one canonical rewrite-validation path, and propagate an inner `escalate` instead of collapsing it into a block | `grep -rn validate_rewrite backend/` shows the endpoint using the guard, or the symbol is gone; a redacted consequential action returns `escalate` (with the redaction reason code) instead of `block`, covered by a test; the benign set is re-measured after the change | Low mechanically, but it changes a refusal into a human gate — re-run the benign suite |
| 3 | Close F6: extend the goal-binding table to `payment_confirm`, `payment_execute`, `remediation_execute` arguments | A confirmation granted for one amount/beneficiary/asset cannot authorise a different one; benign `finance_refund_confirmed` still completes | Medium — watch the confirmation subject mismatch that already fails one benign scenario |
| 4 | Fix F9 and the port: state the subset denominator next to every table; change the Docker example to `-p 127.0.0.1:8080:8080` | Every table in the repo states `reached attacks (N=22)`; `README.md` no longer publishes the unauthenticated API on all interfaces | None |
| 5 | Add a request-size limit (F4) | A 5 MB body is rejected with a sanitized 4xx before parsing; the existing 64 KB response cap and fail-closed test still pass | Low |
| 6 | Repair the observability layer (F10) — this is a 40-point rubric category | The comparison warning fires for the real v3-vs-v5 pair; the reachability row is either populated from real data or removed; trust labels are not collapsed; axe/forced-colors checks pass | Low |
| 7 | Documentation truth pass (F8, F13) | No link in the repo 404s; the unsourced stage split is either cited or deleted; runbooks describe v5 with the exact command that produced the archived traces; promised slices exist or the promise is dropped | None |
| 8 | Evidence upgrades (F5, F7, F14) | A paraphrase/translation regression suite exists with a benign control; a multi-seed rerun is reported with variance; scorecards carry a defense-revision fingerprint | None to the defense, but expect the paraphrase suite to find real misses — that is the point |
| 9 | Release readiness (F3) | Video recorded, report rendered, validator run, Docker run verified, team composition clarified with the organizers in writing | None |

Notice the shape of this list: seven of nine items are *honesty and finish* work, not new defense logic. That is the normal shape of a hackathon project that was built by an agent under a measured-evidence discipline — the risky part is never the math, it is the gap between what the docs imply and what the code does.

---

## 5. What would falsify this project's claims

A claim that cannot be falsified is marketing. The defensible claim from this project is narrow and specific:

> On SENTINEL's published 40-scenario suite, with the pinned starter kit and Qwen3-8B at temperature 0 and seed 0, this deterministic gateway reduced attack success on the 22 attacks a real model actually reaches from 22/22 to 0/22, at a false-block rate of 0.86% and a p95 decision latency of 9.3 ms, while losing one benign task relative to the undefended baseline.

Each of the following experiments would falsify part of that, which is exactly why they belong in the backlog:

| Experiment | What it would falsify |
| --- | --- |
| Rerun the same suite across several seeds and report the spread | "0/22" as a stable property rather than one seeded observation |
| Run the paraphrase/translation/encoding suite (F7) | "The rule set generalises beyond the literal attack vocabulary" |
| Run AgentDojo | "The approach generalises beyond this benchmark" |
| Add a benign regression suite before and after any rule change | "The utility cost is 0.86% and stable" |
| Re-run with a stronger model (larger or less quantised) | "The 22/22 reachability result is a property of the attack set rather than of Qwen3-8B at this quantisation" |
| Inject a hostile instruction through a surface the suite never uses (a new tool argument, a non-email sink) | "The provenance/flow rules are family-complete" |

---

## 6. Where to take your learning next

This project is one concrete instance of a well-known pattern: **an action-level reference monitor with provenance and intent binding**. The concepts transfer:

- **AgentDojo** (NeurIPS 2024) — an independent prompt-injection benchmark for tool-using agents. Running this project's gateway against it is the single highest-value generalization experiment available.
- **OWASP Top 10 for LLM Applications** — read LLM01 (prompt injection) and LLM06 (excessive agency) with this project in mind; you will recognise the design decisions.
- **Dual-LLM / planner-executor patterns** (privileged planner, quarantined executor) — the architectural answer to "the model reads untrusted text", complementary to this project's decision-point answer.
- **Taint tracking and information-flow control** — the academic ancestor of the provenance rules in Module 7. The `provenance` baseline's failure (verbatim overlap vs paraphrase) is the classic precision problem of dynamic taint analysis.
- **Calibration** — why reporting Brier/ECE requires a score that means something (F5); read up on this before writing any "confidence" field into a security product.

Then do [Module 10](10-labs.md). The fastest way to internalise this material is to break your own gateway and measure the result.

---

## Check yourself

1. Which parts of the project were independently recomputed, and which were only read?
   - All ten scorecards' metrics and per-domain slices, all claimed hashes, the evaluator digest, the reached-attack set, and the decision counts were recomputed from artifacts. Source code claims are code reading; structural blind spots are `[INFERENCE]`.
2. Why is F1 (implicit trust for role-only items) serious even though it is not exploited on the published suite?
   - Because the defense's trust boundary accepts a self-declaration from the client it is meant to guard. Exploitability depends on deployment; the design weakness does not.
3. What exactly is dead in F2, and what is *not* dead?
   - `validate_rewrite()` and the codes only it emits (`UNSAFE_REWRITE`, the `REWRITE_*` family, `SAFE_REWRITE`) never run in production. What is live is the pipeline's own revalidation inside the two redaction functions — this audit saw `REDACTION_REVALIDATION_FAILED` come back from the running service.
4. What does F15 change about a redacted consequential action?
   - Revalidation accepts only `allow`, so an action that would have been escalated for human confirmation becomes a hard block once a secret is found inside it. The fix is to propagate the inner `escalate` verdict for the redacted action.
5. Why is the denominator 22 rather than 31 in the headline ASR claim?
   - Nine attacks never produce their harm even with no defense installed (the model refuses or the demanded tool is outside the allowed set), so their `attack_success` is not evidence about any defense. The reachability control is what identifies those nine.
6. Why do the reported Brier score and ECE deserve a warning label?
   - They are computed from a `risk_score` that is a fixed literal per gate and a `confidence` that is a constant; calibration metrics over constants look meaningful but carry no information.
7. Name three experiments that would falsify the project's central claim.
   - Multi-seed reruns, a paraphrase/translation attack suite, AgentDojo, a benign regression suite, a stronger model, or a new injection surface — any one of them can shrink the claim.

---

## Where this lives in the repo

- `evaluation/` — the ten scorecards and the JSONL traces the audit recomputed from
- `evaluation/real-qwen/README.md` — the evidence manifest with the digests that were re-verified
- `backend/aegisgraph/adapter.py:55-91` — the trust-resolution rules behind F1
- `backend/aegisgraph/engine.py:371-459` — the test-only rewrite guard behind F2
- `backend/aegisgraph/engine.py:606-610` — the live revalidation that turns a redacted escalate into a block (F15)
- `backend/aegisgraph/engine.py:860-869` — the goal-binding table behind F6
- `backend/aegisgraph/app.py:83-105` — the endpoint with no request-size limit (F4)
- `backend/aegisgraph/static/dashboard.js:302-308,395-409` — the observability defects (F10)
- `scripts/validate_attack_reachability.py`, `REACHABILITY_GATE.md` — the binary gate behind F9
- `SUBMISSION_CHECKLIST.md`, `SUBMISSION_HANDOFF.md` — the open release items (F3)
