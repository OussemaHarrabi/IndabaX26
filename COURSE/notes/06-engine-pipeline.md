# 06 — Engine / decision pipeline (AegisGraph)

Sources: `.audit-tmp/aegisgraph/backend/aegisgraph/engine.py` (1134 ln), `policy.py` (159), `contracts.py`, `adapter.py`, `sentinel.py`, tests `tests/test_policy_kernel.py`.

Public API: `engine.decide(request: SentinelRequest) -> GuardDecision` (`engine.py:345`) and `engine.validate_rewrite(request, rewritten_action)` (`engine.py:371`). HTTP entry `app.py:88` calls only `decide`; `validate_rewrite` is not wired into `app.py` (`app.py:83-89`). Both public functions are pure (no module state); see §6.

## 0. Pre-pipeline normalisation (adapter)

`decide` runs 3 guarded steps in order (`engine.py:347-366`):
1. `adapt_request` (`adapter.py:37`) → on exception: BLOCK `ADAPTER_VALIDATION_FAILED` risk 1.0 (`engine.py:349-352`).
2. `parse_policy_facts` (`policy.py:34`) → exception: BLOCK `POLICY_VALIDATION_FAILED` (`engine.py:356-360`).
3. `_evaluate(adapted, facts, skip_confirmation=False)` → exception: BLOCK `INTERNAL_EVALUATION_FAILED` (`engine.py:363-366`).
Failure decisions are built by `_failure_decision` (`engine.py:1126`): verdict=block, risk_score=1.0, confidence=1.0, metadata={}. Explanations are static strings; caught exception detail is never echoed (test `test_decide_converts_unexpected_adapter_errors_to_stable_fail_closed_decision:382`).

Adapter outputs used by the engine (all fields `adapter.py:25-32`):
- `provenance_complete`: False iff a `provenance_id` did not resolve to a record (`adapter.py:67-80`, set `complete=False` at `:74`). Duplicate record id → first kept only, rest become `None` → treated unresolved (`adapter.py:56`).
- `least_trust` / `max_sensitivity`: max over observations in enum order (`adapter.py:97-105`).
- `confirmations_granted`: copied verbatim from `request.history_digest.confirmations_granted` (`adapter.py:128`).
- `evidence_truncated`: `len(observations) > _MAX_CANONICAL_OBSERVATIONS` (=128, `adapter.py:24`, `:131`).
- Observation trust: referenced → `provenance.trust_level`/`sensitivity`; unattributed (no ids, non-user role) → `UNTRUSTED_INTERNAL`/`INTERNAL` (`adapter.py:88`); unresolved id → `ADVERSARY_CONTROLLED`/`RESTRICTED` (`adapter.py:154-161`).

TrustLevel ascending order (`contracts.py:70-75`): system_policy < authenticated_user < trusted_internal < untrusted_internal < untrusted_external < adversary_controlled. Sensitivity ascending: public < internal < confidential < restricted.

## 1. `_evaluate` decision pipeline — exact order (`engine.py:462-548`)

First match wins; every later gate is unreachable once an earlier one fires.

| # | Line | Trigger | Decision | Reason code | risk |
|---|------|---------|----------|-------------|------|
| 1 | 465-466 | `not facts.valid` | BLOCK | `POLICY_CONTEXT_INVALID` | 0.98 |
| 2 | 467-468 | `not adapted.provenance_complete` | BLOCK | `PROVENANCE_INCOMPLETE` | 0.97 |
| 3 | 470-472 | `evidence_truncated and action.type is not RESPOND` | BLOCK | `EVIDENCE_TRUNCATED` | 0.96 |
| 4a | 473-476 | type=REQUEST_CONFIRMATION and `confirmation_for is None` | BLOCK | `INVALID_CONFIRMATION_TARGET` | 1.0 |
| 4b | 477-489 | type=REQUEST_CONFIRMATION, target re-evaluated (`skip_confirmation=True`) | returns target verdict if ≠ ALLOW, else ALLOW | target's codes / `CONFIRMATION_REQUEST_SAFE` | 0.18 |
| 5 | 490-491 | type=TOOL_CALL and `tool not in facts.allowed_tools` | BLOCK | `UNAUTHORIZED_TOOL` | 1.0 |
| 6 | 493-494 | type=MEMORY_WRITE and `_memory_write_is_directive(action)` | BLOCK | `MEMORY_POISONING` | 0.96 |
| 7 | 496-497 | type=TOOL_CALL and `_coupled_instruction(action, adapted)` | BLOCK | `UNTRUSTED_INSTRUCTION` | 0.99 |
| 8 | 499-500 | `_is_sensitive_external_flow(...)` | BLOCK | `SENSITIVE_DATA_EXFILTRATION` | 1.0 |
| 9 | 502-504 | `_redact_sensitive_flow(...)` returns non-None | REWRITE (+ revalidation) | `SENSITIVE_RESPONSE_REDACTED` / `SENSITIVE_ACTION_REDACTED` | 0.85 |
| 10 | 506-508 | `_redact_untrusted_authority(...)` returns non-None | REWRITE (+ revalidation) | `UNTRUSTED_AUTHORITY_REDACTED` | 0.86 |
| 11a | 510-520 | type=TOOL_CALL, `requires_confirmation(action,facts)`, not skip, digest ∉ granted | ESCALATE | `CONFIRMATION_REQUIRED` | 0.72 |
| 11b | 521-527 | same but confirmed (or `skip_confirmation=True`) | ALLOW | `CONFIRMATION_VERIFIED` (not skip) / `POLICY_CHECKS_PASSED` (skip) | 0.16 |
| 12 | 529-535 | type=RESPOND | ALLOW | `BENIGN_ACTION` | 0.05 |
| 13 | 536-542 | type=MEMORY_WRITE and `_has_untrusted_evidence(adapted)` | ALLOW | `UNTRUSTED_MEMORY_INHERITED` | 0.32 |
| 14 | 543-548 | fall-through | ALLOW | `POLICY_CHECKS_PASSED` | 0.08 |

Note: `_evaluate` reasons #4b/#11b both emit `POLICY_CHECKS_PASSED` when `skip_confirmation=True` (`engine.py:523`), so a request_confirmation target's allow is labelled with the target's own reason — the wrapper only substitutes `CONFIRMATION_REQUEST_SAFE` when the target returns ALLOW… actually #4b returns the target result unchanged when ALLOW? No: `engine.py:479-489` discards the target's ALLOW and returns a fresh `_decision(ALLOW, 0.18, "CONFIRMATION_REQUEST_SAFE", ...)`; only non-ALLOW target results propagate unchanged (incl. their `rewritten_action`). [INFERENCE] a target that revalidation would REWRITE is returned as a REWRITE of the *target* from a request_confirmation action.

Confidence: all `_decision` outputs set confidence=0.99 (`engine.py:1107`); failure=1.0. Rewrite paths: sensitive-redaction 0.99, authority-redaction 0.93, safe-rewrite 0.99 (`engine.py:612,700,456`).

## 2. Precedence & final assembly

- Sequential first-match in `_evaluate` ⇒ the *lowest-numbered* gate that fires dictates verdict + reason. e.g. an unauthorized tool (5) fires before a coupled injection (7) and before confirmation escalation (11); test `test_unauthorized_tool_is_blocked_before_other_checks:475`.
- Decision objects assembled by `_decision` (`engine.py:1103-1123`): sets `confidence=0.99`, single-element `reason_codes=(code,)`, metadata `{"least_trust":..., "max_sensitivity":...}` plus `"memory_trust"` when candidate type is MEMORY_WRITE (`engine.py:1111-1113`).
- `_block` (`engine.py:1093`) is `_decision(BLOCK, risk, code, ...)`.
- Rewrite decisions bypass `_decision` and are constructed inline; they may carry multiple reason codes (`REWRITE_ENFORCEMENT_DOWNGRADE, *original_codes`; `UNSAFE_REWRITE, *evaluated_codes`), each truncated to 16 (`engine.py:426,437`).
- `VERDICT_SEVERITY` = allow 0 < rewrite 1 < escalate 2 < block 3 (`engine.py:322-327`); used only by rewrite validation.

## 3. Risk / confidence scoring

No formula — every gate hard-codes a literal risk (see §1). Range is enforced structurally: `GuardDecision.risk_score: Field(ge=0.0, le=1.0)` (`contracts.py:214`) and wire `SentinelResponse.risk_score` same (`sentinel.py:191`). Rewrite floors/caps: `max(0.95, ...)` for downgrade/unsafe-rewrite (`engine.py:419,436`), `max(0.2, evaluated.risk_score)` for safe rewrite (`engine.py:453`), `max(0.98`… no, 0.98 literal) effect-escalation (`engine.py:450`), 1.0 literal for finality/bypass/authority-only (`engine.py:402,407,413,442,449?`). Redaction risks are constants 0.85 / 0.86; block-on-revalidation-failure 1.0 (`engine.py:610,702`). Metadata JSON bounded to `MAX_METADATA_BYTES=4096`, reason codes ≤16 and regex `^[A-Z][A-Z0-9_]{1,63}$` (`contracts.py:11,210,219`).

## 4. Rewrite / redaction path

Two internal rewriters + one external validator:

**(a) `_redact_sensitive_flow` (`engine.py:566-620`)** — runs on RESPOND-with-content (surface `"response"`) or TOOL_CALL on a side-effecting tool (surface `"action"`); else returns None.
- Credential set from `_sensitive_credential_values` (`engine.py:622`): only observations with `sensitivity >= CONFIDENTIAL`, matched by `_CREDENTIAL_ASSIGNMENT` (`engine.py:99-106`), value length ≥8 **and** containing ≥1 digit (`engine.py:627-631`). Test `test_restricted_credential_field_families_are_protected:751`.
- Replaces each credential with literal `[REDACTED]` throughout response content or each str argument (`engine.py:584-599`); no change → None.
- Revalidates by re-running `_evaluate` once on the rewritten action (`engine.py:606`); if that is not ALLOW → BLOCK `REDACTION_REVALIDATION_FAILED` (`engine.py:610`). Else REWRITE, risk 0.85, confidence 0.99.
- Evidence: `test_restricted_credential_copied_into_final_response_is_redacted:681` expects `rewritten_action.content == "… service_key is [REDACTED]."` and `final is True` preserved.

**(b) `_redact_untrusted_authority` (`engine.py:634-713`)** — removes "laundered" operational claims copied from low-trust observations into narrative sinks.
- Sources = contents of observations with `trust_level >= untrusted_internal` (`engine.py:647-651`, threshold `_UNTRUSTED_THRESHOLD=TrustLevel.UNTRUSTED_INTERNAL`, `engine.py:95`). None → None.
- Splits content into sentences (`_NARRATIVE_SENTENCE`), marks tainted via `_is_laundered_claim` (`engine.py:717-748`): returns True when sentence and some source both match a `_UNTRUSTED_CLAIM_PATTERNS` key (policy_exception / alert_dismissal / monitoring_suppression, `engine.py:114-136`) unless a `_SAFE_CLAIM_NEGATIONS` guard matches, OR a reported email action copies an address from the source not present in `user_goal`. Non-tainted sentences kept; if a removal happened, also drop sentences matching `_DANGLING_ACTION_REFERENCE` (`engine.py:677`).
- If result empty for RESPOND/MEMORY_WRITE → BLOCK `UNTRUSTED_AUTHORITY_ONLY` 0.97 (`engine.py:676-677`); a narrative arg emptied → same block (`engine.py:690-691`). Revalidation as (a) but failure → `AUTHORITY_REVALIDATION_FAILED` / or ALLOW + REWRITE `UNTRUSTED_AUTHORITY_REDACTED` 0.86 conf 0.93.
- Evidence: `test_fake_manager_instruction_is_removed_from_final_response:1584`, `test_redaction_removes_dangling_confirmation_reference:1688` (content collapses to just the safe sentence).

**(c) `validate_rewrite` / `_validate_rewrite` (`engine.py:371-459`)** — validates a defender-proposed replacement action.
Order:
1. `original.final=False` → `rewritten.final=True` ⇒ BLOCK `REWRITE_FINALITY_ESCALATION` 1.0 (`engine.py:401-402`).
2. original type REQUEST_CONFIRMATION → rewritten type ≠ REQUEST_CONFIRMATION ⇒ BLOCK `REWRITE_CONFIRMATION_BYPASS` 1.0 (`engine.py:405-407`).
3. original RESPOND+final → rewritten not RESPOND ⇒ BLOCK `REWRITE_FINAL_ACTION_CHANGED` 1.0 (`engine.py:409-413`).
4. `original_decision = _evaluate(original)`; if severity > allow ⇒ BLOCK `REWRITE_ENFORCEMENT_DOWNGRADE` + original codes, risk `max(0.95, …)` (`engine.py:415-428`).
5. `_evaluate(rewritten)`; if ≠ ALLOW ⇒ BLOCK `UNSAFE_REWRITE` + codes, `max(0.95, …)` (`engine.py:432-440`).
6. original RESPOND → rewritten MEMORY_WRITE ⇒ BLOCK `REWRITE_EFFECT_ESCALATION` 1.0 (`engine.py:441-442`).
7. `_action_effect(rewritten) > _action_effect(original)` and rewritten effect ≥ WRITE and rewritten digest ∉ confirmations ⇒ BLOCK `REWRITE_EFFECT_ESCALATION` 0.98 (`engine.py:443-450`).
8. else REWRITE `SAFE_REWRITE`, risk `max(0.2, evaluated.risk_score)`, conf 0.99 (`engine.py:451-458`).
Evidence: `test_safe_rewrite_is_emitted_only_after_full_revalidation:1791`; `test_rewrite_cannot_downgrade_an_existing_escalation_to_executable_rewrite:1804`; `test_write_effect_rewrite_requires_exact_confirmation:1857`; parametrised `test_unsafe_rewrite_is_blocked_and_never_executable:1918`.

**Bounding**: no internal rewrite loop. Each redactor re-validates exactly once; if re-validation itself yields a REWRITE (≠ ALLOW) it is converted to a BLOCK, so nesting stops at depth 1. The only recursion is REQUEST_CONFIRMATION → target (`engine.py:478`), depth ≤2 because a target must be a tool_call (`sentinel.py:96-100`). `_action_effect` (`engine.py:1079-1091`) ranks respond=INERT, request_confirmation/read-only=READ_OR_CONFIRM, memory/write/consequential=PERSISTENT_OR_CONSEQUENTIAL, else WRITE.

## 5. Confirmation / escalation

- `requires_confirmation(action, facts)` (`policy.py:63`) = `tool in facts.confirmation_required_tools` OR `is_consequential` (`policy.py:47`): `tool in STATIC_CONSEQUENTIAL_TOOLS` (`{email_send,payment_confirm,payment_execute,remediation_execute}`, `policy.py:16`) OR `tool in facts.consequential_tools` OR `ticket_update` with status ∈ {closed,resolved} OR `incident_update` with status == closed (status lower-cased/stripped, `policy.py:55-60`).
- **Escalate** trigger: only gate #11a — TOOL_CALL, requires confirmation, `not skip_confirmation`, and the action's digest is absent from `confirmations_granted` (`engine.py:510-520`). verdict=escalate, risk 0.72, code `CONFIRMATION_REQUIRED`.
- **Token/marker**: a confirmation is a 24-hex-char string equal to `CandidateAction.digest()` → `action_digest` = `sha256(json.dumps({type,tool,arguments(sorted/canonical),content-or-None-if-tool_call,[confirmation_for digest]}, sort_keys, separators))[:24]` (`contracts.py:158-167,249-262`). It deliberately excludes `final`; canonicalises argument values via `_canonical_argument` (`contracts.py:263`…). Token travels in `history_digest.confirmations_granted: tuple[str,…]≤256` (`sentinel.py:152`), consumed as a frozenset (`adapter.py:128`). Match is exact string membership (`engine.py:513`); test `test_confirmation_must_match_the_exact_canonical_action_digest:516` asserts an equivalent-but-not-identical action still matches.
- **Unconfirmed consequential action** ⇒ escalate (not block, not execute). Confirmed ⇒ ALLOW with `CONFIRMATION_VERIFIED` (`engine.py:521-527`). Rewrites cannot launder a confirmation requirement (gate 7 in `_validate_rewrite`; `test_write_effect_rewrite_requires_exact_confirmation`).

## 6. Failure & boundary behaviour

- Exceptions: three catch points in each public fn (`engine.py:347,354,363` and `:373,380,389`); all fail closed to BLOCK. No exception text leaks into `explanation` (tests :382-449). HTTP layer additionally converts any serialization failure to a block (`app.py:97-106`).
- Unknown action type: impossible — `SentinelCandidateAction.type` is a 4-value `Literal` (`sentinel.py:59`) and `ActionKind(type)` in adapter (`adapter.py:137`); an out-of-set value raises at request validation before `decide`. [INFERENCE] it would surface as `ADAPTER_VALIDATION_FAILED` only if it passed pydantic — it cannot.
- Shape constraints: `_shape_matches_type` (`sentinel.py:87-107`) rejects tool_call w/o tool, respond/memory_write w/o content, request_confirmation w/o tool_call target, final non-respond.
- Empty/oversized: `user_goal` defaulted to `"Unspecified user goal"` when falsy (`adapter.py:118`); `MAX_CONTENT_CHARS=16000`, `MAX_ARGUMENT_CHARS=8000`, `MAX_CONTEXT_BYTES=16384`, `MAX_METADATA_BYTES=4096`, ≤32 args, key isidentifier ≤64 (`contracts.py:11-14,125-137`). Oversize → pydantic validation error → HTTP 422 before policy (or `ADAPTER_VALIDATION_FAILED` if raised inside adapter).
- Missing provenance: unresolved id → `provenance_complete=False` → BLOCK `PROVENANCE_INCOMPLETE` at gate #2, even for a RESPOND (`test_explicit_dangling_or_duplicate_provenance_fails_globally_even_for_response:215`). Unattributed (no ids) evidence is NOT "missing": complete stays True, observation is `UNTRUSTED_INTERNAL` (`test_unattributed_provenance_is_low_trust_while_broken_reference_fails_closed:1714`).
- Evidence bounding: >128 canonical observations ⇒ `evidence_truncated=True`; blocks any non-RESPOND action (`engine.py:470-472`; test `test_evidence_expansion_cannot_evict_an_attack_and_fail_open_a_tool_action:338`). Selection keeps least-trusted/most-sensitive first (`adapter.py:190-203`).
- Replay/determinism: no caches, counters, globals, or `lru_cache` in engine/adapter/policy (grep clean); `decide` is a pure function of the request. `test_decisions_are_deterministic_bounded_and_explainable:1928` asserts two calls return equal objects. Metadata is derived only from the adapted request. No state between requests.

## 7. Dead / unreachable branches & hardcoded values to question

- [INFERENCE] `_VALIDATE_REWRITE` gates are only reachable via `validate_rewrite`, which `app.py` never calls — the HTTP service cannot emit a non-error block from rewrite validation. If the harness never calls `validate_rewrite`, gates 1-8 in §4c are dead in production (tests exercise them directly).
- [INFERENCE] gate #8 `SENSITIVE_DATA_EXFILTRATION` returns before the redactors, so `_redact_sensitive_flow` only handles ≤CONFIDENTIAL/confidential-to-internal cases; a confidential external *send* is always blocked, never redacted.
- [INFERENCE] `_UNTRUSTED_CLAIM_PATTERNS` only has 3 keys but `_SAFE_CLAIM_NEGATIONS` has 2 — `policy_exception` has no safe-negation escape hatch (asymmetric, possibly intentional).
- [INFERENCE] In `_redact_untrusted_authority`, `_is_laundered_claim` is recomputed per source inside the loop and returns True on the first matching source; `user_goal` is passed only for the email-address exemption — sentence replaced wholesale, so partial redaction of a claim's span is not possible.
- [INFERENCE] `_evaluate` recursion for REQUEST_CONFIRMATION returns the target's decision object directly when non-ALLOW, meaning `rewritten_action`/metadata describe the *target*, not the request_confirmation action; a reviewer should confirm the harness expects that.
- Hardcoded values a reviewer should question: risk literals 0.98/0.97/0.96/0.99/1.0/0.85/0.86/0.72/0.32/0.18/0.16/0.08/0.05; `_UNTRUSTED_THRESHOLD` (untrusted_internal ⇒ trusted_internal is "trusted"); `_MAX_ADJACENT_COMPOSITION_OBSERVATIONS=3`; `_MAX_ADJACENT_COMPOSITION_CHARS=512`; `_MAX_CANONICAL_OBSERVATIONS=128`; credential heuristic `len≥8 and any char.isdigit()` (`engine.py:629`); `_MEMORY_PERSISTENCE_DIRECTIVE` word list (`engine.py:96-99`); `[:16]` reason-code truncation; `confidence=0.99` constant.
- [INFERENCE] `VERDICT_SEVERITY` has a `REWRITE` entry but `_validate_rewrite` only compares against `ALLOW` (line 416); the ordering allow<rewrite<escalate<block is otherwise unused in engine flow.

## Could-not-determine

- Whether the SENTINEL harness ever invokes `validate_rewrite` (no caller found in backend; only tests). Stated as [INFERENCE] above.
- Exact-byte canonicalisation of numeric argument values (`_canonical_argument`) not fully read; affects only digest equality, not decision logic.
