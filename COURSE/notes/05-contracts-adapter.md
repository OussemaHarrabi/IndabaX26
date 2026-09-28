# 05 — Canonical contracts, SENTINEL wire models, adapter

Files: `.audit-tmp/aegisgraph/backend/aegisgraph/{contracts.py,sentinel.py,adapter.py}`,
tests `.audit-tmp/aegisgraph/tests/{test_contracts.py,test_sentinel_adapter.py}`.
Line refs are relative to workspace root; `contracts.py:NN` etc. mean
`.audit-tmp/aegisgraph/backend/aegisgraph/contracts.py:NN`.

Two model families:
- `contracts.py` = **canonical, policy-neutral** domain model (what the engine sees). `_FrozenModel` = `frozen=True, extra="forbid"` (contracts.py:97-99).
- `sentinel.py` = **wire** model for the official SENTINEL v1 API. `_LenientFrozenModel` = `frozen=True, extra="ignore"` (sentinel.py:50-52); `SentinelCandidateAction` and `SentinelResponse` are strict `extra="forbid"`.
The adapter (adapter.py) is the only bridge; engine imports it at engine.py:8.

## 1. Canonical action model (contracts.py)

### Enums
- `TrustLevel` (contracts.py:67-74), ordered low→high by declaration index via `_OrderedSecurityEnum.__lt__` (contracts.py:59-64): `system_policy`, `authenticated_user`, `trusted_internal`, `untrusted_internal`, `untrusted_external`, `adversary_controlled`.
- `Sensitivity` (contracts.py:76-81): `public`, `internal`, `confidential`, `restricted`.
- `ActionKind` (contracts.py:83-88): `respond`, `tool_call`, `memory_write`, `request_confirmation`.
- `Verdict` (contracts.py:90-95): `allow`, `block`, `escalate`, `rewrite`.

### `Observation` (contracts.py:101-108)
| field | type | rule |
|---|---|---|
| `kind` | str | `min_length=1, max_length=64, pattern=^[a-z][a-z0-9_]*$` |
| `content` | str | `max_length=MAX_CONTENT_CHARS` = 16_000 |
| `source` | str | `min_length=1, max_length=256` |
| `trust_level` | `TrustLevel` | required |
| `sensitivity` | `Sensitivity` | default `INTERNAL` |

### `CandidateAction` (contracts.py:111-170)
Fields: `type: ActionKind` (114); `tool: str|None` default None, `pattern=^[a-z][a-z0-9_]{1,63}$` i.e. 2–64 chars (115); `arguments: Mapping[str,ArgumentValue]` default `FrozenDict` (116); `content: str|None` default None, max 16_000 (117); `final: bool=False` (118); `confirmation_for: CandidateAction|None` (119). `ArgumentValue = str|int|float|bool|None` (contracts.py:31) — no nested objects/lists.

Rules (measured from code):
- `arguments` validator `_bounded_arguments` (123-136): ≤32 entries; each key must satisfy `str.isidentifier()` and `len≤64`; str values `≤8_000` chars (`MAX_ARGUMENT_CHARS`); float values must be `math.isfinite`. Result re-wrapped as `FrozenDict`.
- `_shape_matches_type` (142-161):
  - `tool_call`: `tool` required; `content`/`confirmation_for` must be None ("tool_call actions take 'arguments' only").
  - `respond`/`memory_write`: `content` required; `tool`/`arguments`/`confirmation_for` must be empty ("...take 'content' only").
  - `request_confirmation`: `confirmation_for` must be present and of type `tool_call`; `tool`/`arguments` must be empty.
  - `final=True` only allowed for `respond` ("only respond actions can be final").
- Frozen: mutation raises `ValidationError` (test_contracts.py:30).
- `digest()`/`execution_digest()` (163-170) → `action_digest`/`exact_action_digest`.

### Digests (contracts.py:249-292) — two DIFFERENT fingerprints
- `action_digest` (249-262) — the **confirmation-protocol** digest. Payload keys `{type, tool, arguments, content}`; `content` forced to `None` when type is `tool_call`; argument keys **sorted**; each value passed through `_canonical_argument` (287-292): strings → `" ".join(value.split())` (whitespace collapse), integral floats → int; nested `confirmation_for` replaced by its own `action_digest`. Then `json.dumps(sort_keys=True, separators=(",",":"), allow_nan=False)` → `sha256[:24]`.
  - Golden vector (MEASURED, test_contracts.py:52): `{amount:12.0, note:"a   b\n c"}` == `{amount:12, note:"a b c"}` → `"2ce0b8de5d0b516fd176a716"`.
  - Deliberately **loses** whitespace, int/float distinction, and `final` (non_final.digest == final.digest, test_contracts.py:80).
- `exact_action_digest` (265-278) — exact execution-semantic fingerprint via `_exact_action_payload` (273-285): includes `final`, raw (un-collapsed) arguments, nested `confirmation_for` recursively; no canonicalization. So it distinguishes `12.0` from `12`, spacing, and `final`.
- `DecisionReceipt` (236-246): `request_id` (pattern `^[A-Za-z0-9][A-Za-z0-9._:-]*$`, ≤128), `action_digest` `^[0-9a-f]{24}$`, optional `execution_digest` `^[0-9a-f]{24}$`, `decision: GuardDecision`.

### `GuardRequest` (contracts.py:172-195) — canonical engine input
`request_id` (175-179, same pattern, ≤128); `user_goal` (180, `min_length=1`, ≤16_000); `observations: tuple[Observation,...]` (181, `max_length=128`); `candidate_action` (182); `policy_context: Mapping[str,JsonValue]` (183) validated by `_bounded_policy_context` → `_require_json_size(value, MAX_CONTEXT_BYTES=16_384)` then `_freeze_json_mapping` (deep-frozen `FrozenDict`/tuples).

### `GuardDecision` (contracts.py:198-233)
`verdict: Verdict`; `risk_score`/`confidence` float in `[0.0,1.0]`; `reason_codes` tuple ≤16, each must fullmatch `REASON_CODE_PATTERN = ^[A-Z][A-Z0-9_]{1,63}$` (29, 208-215); `explanation` ≤500; `rewritten_action: CandidateAction|None`; `metadata` ≤`MAX_METADATA_BYTES=4_096`. `_rewrite_consistency` (228-233): `rewrite` ⇔ `rewritten_action is not None`.

### JSON bounds helpers
`_require_json_size` (316-322): `len(json.dumps(value, allow_nan=False))` bytes; non-serializable → `ValueError`. `MAX_ARGUMENT_CHARS=8000`, `MAX_CONTENT_CHARS=16000`, `MAX_CONTEXT_BYTES=16384`, `MAX_METADATA_BYTES=4096` (25-28).

## 2. Wire provenance model (sentinel.py)

`SentinelProvenance` (111-121), lenient (`extra="ignore"`):
| wire field | type/rule | maps to canonical |
|---|---|---|
| `source_type` | str 1–128 | part of `Observation.source` |
| `source_id` | str 1–256 | part of `Observation.source` |
| `trust_level` | `TrustLevelLiteral` (exact 6 strings, sentinel.py:32-39) | `Observation.trust_level` (cast, adapter.py:86) |
| `origin_actor` | str 1–256 | **not carried into canonical** |
| `retrieved_via` | str 1–256 | **not carried into canonical** |
| `sensitivity` | `SensitivityLiteral`, default `"internal"` | `Observation.sensitivity` |
| `timestamp` | `datetime` (required) | **not carried into canonical** |
| `parent_event_ids` | tuple ≤128, each 1–256 | not carried |
| `tags` | tuple ≤128, each 1–128 | not carried |

`SentinelProvenanceRecord` (123-125): `id` (1–256) + `provenance`. The record `id` is the join key to `provenance_ids` on conversation/observation views.

`SentinelConversationItem` (128-133): `role ∈ {user,agent,tool,memory,safety,human}` (Literal, line 129), `kind` 1–64, `content` ≤16_000, `provenance_ids` tuple ≤128.
`SentinelObservationView` (135-138): `kind` 1–64, `content` ≤16_000, `provenance_ids` ≤128.
`SentinelHistoryDigest` (148-156): `steps_taken`,`turn_index`,`blocked_count`,`escalated_count` `ge=0`; `tool_calls` ≤256; `confirmations_granted: tuple[str,...]` ≤256; `least_trusted_seen`/`most_sensitive_seen` optional literals.

`SentinelRequest` (159-186), lenient: `run_id` 1–256, `step_id` ge=0, `user_goal` ≤16_000 (**no min** — empty allowed, 164), `conversation` ≤256, `observation` optional, `candidate_action` strict, `policy_context` ≤16_384 (176-181, `json.dumps`), `provenance` ≤256, `history_digest` default.
`SentinelResponse` (188-224), strict: mirrors `GuardDecision` but `decision: VerdictLiteral`; `_rewrite_needs_action` (222-226) uses XOR `(decision=="rewrite") != (rewritten_action is not None)`.

Aliases at sentinel.py (last lines): `CandidateAction=SentinelCandidateAction`, `DefenseRequest=SentinelRequest`, `DefenseDecision=SentinelResponse`, `SentinelDefenseRequest`, `SentinelDefenseResponse`.

### Provenance labels/flags in canonical form
Provenance is not a field set; it is **folded into each `Observation`** as `trust_level`+`sensitivity`+`source`. Labels actually minted by the adapter:
- `source = "implicit:<role>"` — no `provenance_ids`, role ∈ {user,agent,safety,human} (adapter.py:63) → `trust_level = AUTHENTICATED_USER` if role==user else `TRUSTED_INTERNAL`, `sensitivity = INTERNAL` (adapter.py:55-68).
- `source = "unattributed:<role>"` — no `provenance_ids`, other role → `UNTRUSTED_INTERNAL` / `INTERNAL` (adapter.py:161-169).
- `source = "<id>:<source_type>:<source_id>"` — resolved record; trust/sensitivity copied verbatim from wire (adapter.py:81-91).
- `source = "unresolved:<id>"` — `provenance_ids` cites an id absent from `provenance` → `ADVERSARY_CONTROLLED` / `RESTRICTED`, and `provenance_complete=False` (adapter.py:151-159).
- Any `source` string >256 chars → `"source:"+sha256(source)[:?]` full hex (adapter.py:183-187) — note: returns `source:<64hex>`, len 71.

## 3. Adapter algorithm (adapter.py:35-134), line by line

`adapt_request(request: SentinelRequest) -> AdaptedRequest`:

1. **Build provenance index** (43-45): `for record in request.provenance: records[record.id] = None if record.id in records else record`. Later duplicates overwrite the first value with `None`; a `None` entry is later treated the same as missing → unresolved/ADVERSARY_CONTROLLED. `[INFERENCE]` duplicate-id ⇒ fail-closed, first record loses.
2. Loop over `request.conversation` (101-102) calling `append_resolved(item.kind, item.content, item.provenance_ids, role=item.role)`; then if `request.observation` present, same with `role="observation"` (103-108).
3. `append_resolved` (54-99):
   - `identifiers = tuple(ids)`. If empty: role ∈ {user,agent,safety,human} → implicit-trust observation (see §2); else `_unattributed_observation` (UNTRUSTED_INTERNAL). **No `complete` change for either branch.**
   - Else loop ids: `records.get(id)`; `None` → `complete=False` + `_unknown_observation` (ADVERSARY_CONTROLLED/RESTRICTED); resolved → append Observation with `kind=_safe_kind(kind)`, content as-is, `source=_compact_source(f"{id}:{source_type}:{source_id}")`, trust/sensitivity from wire. First resolution of each unique id appends the record to `referenced_records` (81-84).
4. **Aggregates** (107-119): `least_trust = max(observations trust by enum index, default AUTHENTICATED_USER)`; `max_sensitivity = max(..., default INTERNAL)`. With zero observations both defaults apply.
5. `bounded_observations = _select_security_relevant_observations(observations)` (120) → if ≤128, unchanged; else rank by `(-trust_index, -sensitivity_index, original_index)` and keep the 128 most untrusted/most sensitive, re-sorted to original order (190-206).
6. Canonical build (121-127): `request_id=_canonical_request_id` = `"request:"+sha256(f"{run_id}\x00{step_id}")[:32]` (178-181, note literal NUL `\x00` separator); `user_goal = request.user_goal or "Unspecified user goal"` (fallback for empty goal); `policy_context = request.model_dump(mode="json")["policy_context"]` (round-trips through JSON then re-validated by GuardRequest bounds).
7. `AdaptedRequest` (126-134) carries: `request`, `confirmations_granted=frozenset(history_digest.confirmations_granted)`, `least_trust`, `max_sensitivity`, `provenance_complete=complete`, `referenced_provenance`, `evidence_truncated = len(observations) > 128`.

`_canonical_action` (137-148): maps wire action 1:1 into `CandidateAction`, recursing into `confirmation_for`; `ActionKind(action.type)` enum cast; arguments/content/final passed through unchanged (re-validated by canonical model). No field is dropped.
`_safe_kind` (171-176): `re.sub(r"[^a-z0-9_]+","_",kind.lower()).strip("_")`; if empty→`"event"`, if not starting with a letter→prefixed `event_`; truncated to 64. Because canonical `kind` pattern requires `^[a-z]`, this is what lets arbitrary wire `kind` (uppercase, spaces, punctuation) pass.

### Ambiguity / malformed / missing / unknown / extraneous — exact behavior
| situation | behavior |
|---|---|
| cited provenance id missing (or duplicated) | `complete=False`; observation labelled `unresolved:<id>`, `ADVERSARY_CONTROLLED`/`RESTRICTED`; engine blocks `PROVENANCE_INCOMPLETE` (engine.py:467-468) |
| no `provenance_ids` on user/agent/safety/human item | implicit `AUTHENTICATED_USER`(user)/`TRUSTED_INTERNAL`(other) — **widening default**, no completeness flag |
| no `provenance_ids` on tool/memory/observation item | `UNTRUSTED_INTERNAL`/`INTERNAL` |
| empty `user_goal` | replaced by literal `"Unspecified user goal"` |
| >128 observations | silently truncated to 128 most-suspicious; `evidence_truncated=True`; engine blocks for non-`respond` (engine.py:471-472) |
| unknown/extraneous wire fields | envelope + provenance + views **ignored** (`extra="ignore"`); `candidate_action` and `Response` **rejected** (`extra="forbid"`) |
| malformed wire payload (bad enum, wrong type, bounds) | pydantic `ValidationError` raised inside `decide`; caught (engine.py:348-352, 374-378) → `_failure_decision("ADAPTER_VALIDATION_FAILED", ...)` inside evaluate; if it escapes to endpoint, app returns **422** with generic `{"detail":"Invalid SENTINEL request"}` (app.py:65-67) |

## 4. Strict-vs-permissive parsing policy

- **Permissive (ignore unknown):** `SentinelRequest`, `SentinelProvenance`, `SentinelProvenanceRecord`, `SentinelConversationItem`, `SentinelObservationView`, `SentinelHistoryDigest`, `SentinelToolCallSummary` (`_LenientFrozenModel`). rationale = forward compatibility (test_sentinel_adapter.py:52-63 asserts `future_envelope_field` dropped).
- **Strict (`extra="forbid"`):** `SentinelCandidateAction` and `SentinelResponse` (test_sentinel_adapter.py:65-80) — an unknown key in `candidate_action` aborts the whole request.
- **Canonical side is always strict** (`_FrozenModel`).
- **Error surface (app.py):** `RequestValidationError`→422 body `_GENERIC_INVALID={"detail":"Invalid SENTINEL request"}` (app.py:22,65-67); `StarletteHTTPException` 400/413/415/422→same generic, others→`_GENERIC_FAILURE={"detail":"Request could not be safely processed"}` with original status (70-75); any unhandled exception in middleware→500 generic (51-56). `decision_endpoint` (83-108): on ANY exception while building/validating the response it logs and returns a **200 `block`** fallback (`INTERNAL_EVALUATION_FAILED`, risk 1.0, confidence 1.0) — never an allow (comment line 97). Response byte cap `_MAX_RESPONSE_BYTES=64_000` (21, 92). No validation-error details (field names, values) are ever returned to the caller.

## 5. Reason-code & decision enums (exact strings in these modules)

Decision enum `Verdict` (contracts.py:90-95) / `VerdictLiteral` (sentinel.py:43): `allow`, `block`, `escalate`, `rewrite`.
Reason codes: these modules define **only the pattern** `^[A-Z][A-Z0-9_]{1,63}$` (contracts.py:29); no enumerations. Concrete literals live in engine.py/app.py: `INTERNAL_EVALUATION_FAILED` (app.py:101), `ADAPTER_VALIDATION_FAILED` (engine.py:352,378), `POLICY_CONTEXT_INVALID` (466), `PROVENANCE_INCOMPLETE` (468), `EVIDENCE_TRUNCATED` (472), `REWRITE_ENFORCEMENT_DOWNGRADE` (422), `UNSAFE_REWRITE` (437), `SAFE_REWRITE` (455), `SENSITIVE_<SURFACE>_REDACTED` (615), `UNTRUSTED_AUTHORITY_REDACTED` (707). (Out of scope but needed for the "complete list" question.)

## 6. Risky behaviour to flag `[INFERENCE]`

1. adapter.py:55-68 + 107-119 — **trust-widening default**: a conversation item with role `user`/`agent`/`safety`/`human` and *no* `provenance_ids` is minted as `authenticated_user`/`trusted_internal` with no cryptographic binding and no `provenance_complete=False`; the wire client chooses both `role` and omission of ids, so it can self-assert high trust on attacker-influenced text.
2. adapter.py:81-91 — trust/sensitivity are copied **from the client-supplied provenance record** (`TrustLevel(provenance.trust_level)`); nothing in these modules verifies the declared label against origin. The whole trust model rests on the harness honestly labeling its own sources.
3. adapter.py:43-45 — duplicate provenance `id` silently becomes `None` → treated as *unresolved* (fail-closed) but **first record is discarded without any error**; and `records.get` cannot distinguish "id not declared" from "id duplicated".
4. adapter.py:120 + 190-206 — >128 observations are **silently dropped** (kept = most suspicious); benign-but-relevant evidence can vanish; only a coarse `evidence_truncated` flag survives, and the engine only blocks on it for non-`respond` actions (engine.py:471).
5. adapter.py:171-176 — `_safe_kind` lossy normalization/truncation to 64 chars can **collapse distinct wire kinds** into one canonical `kind`; no collision detection.
6. contracts.py:287-292 — `action_digest` canonicalization is lossy by design (whitespace, `12.0`→`12`, `final` ignored); two distinct executions share a confirmation digest. The module compensates with `exact_action_digest`, but any caller binding only `action_digest` inherits the loss (test_contracts.py:80-86 shows both non_final/final share `action_digest`).
7. sentinel.py:164 vs contracts.py:180 — wire `user_goal` has **no min length** while canonical requires ≥1; the silent `"Unspecified user goal"` substitution (adapter.py:124) means an empty goal is never rejected, it is rewritten to a benign-looking string.
8. adapter.py:126-127 — `policy_context` is passed through `model_dump(mode="json")`; JSON round-trip is lossy for values like non-string dict keys (pydantic coerces), and the re-validated size may differ from the original byte size. `[INFERENCE]` low impact.
9. No global input byte cap before parsing: `run_id`/`source_id`/`tags` are capped per-field but a `conversation` of 256 items × 16 000 chars each is accepted (sentinel.py:165, 131), i.e. ~4 MB of inbound content per request. `[INFERENCE]` unbounded-ish but bounded.

## Acceptance trace — one concrete inbound request, field by field

Source payload (verbatim, test_sentinel_adapter.py:14-43, `_request_payload()`):

```json
{"run_id":"run-1","step_id":3,"user_goal":"Review the message",
 "conversation":[{"role":"user","kind":"message","content":"Review","future":true}],
 "observation":{"kind":"email","content":"Vendor message","provenance_ids":["prov-1"],"future":true},
 "candidate_action":{"type":"respond","content":"Reviewed","final":true},
 "policy_context":{},
 "provenance":[{"id":"prov-1","provenance":{"source_type":"email","source_id":"vendor-1",
   "trust_level":"untrusted_external","origin_actor":"vendor","retrieved_via":"mailbox",
   "sensitivity":"internal","timestamp":"2026-09-21T10:30:00Z",
   "parent_event_ids":["event-parent"],"tags":["vendor","email"],"future":true}}],
 "history_digest":{"steps_taken":2,"turn_index":1,"future":true},
 "future_envelope_field":{"added":"later"}}
```

Trace through `SentinelRequest.model_validate` then `adapt_request`:

1. Envelope parse (lenient): `future_envelope_field` dropped; conversation item `future` dropped; observation `future` dropped; provenance inner `future` dropped (test asserts this at :57-63). `timestamp` → `2026-09-21T10:30:00+00:00` (aware UTC). `parent_event_ids=("event-parent",)`, `tags=("vendor","email")` — but neither is carried further.
2. `records = {"prov-1": <record>}` (adapter.py:43-45).
3. Conversation item: `role="user"`, `provenance_ids=()` → implicit branch (adapter.py:55-68): Observation `{kind="message", content="Review", source="implicit:user", trust_level=AUTHENTICATED_USER, sensitivity=INTERNAL}`.
4. Observation view: `provenance_ids=("prov-1",)` resolves (adapter.py:74-91) → Observation `{kind="email", content="Vendor message", source="prov-1:email:vendor-1" (len 21 ≤256, unchanged), trust_level=UNTRUSTED_EXTERNAL, sensitivity=INTERNAL}`. `referenced_records=[prov-1]`, `complete` stays True.
5. Aggregates: `least_trust = UNTRUSTED_EXTERNAL` (index 4 > AUTHENTICATED_USER index 1); `max_sensitivity = INTERNAL`.
6. `bounded_observations`: 2 ≤128 → unchanged, `evidence_truncated=False`.
7. `request_id = "request:cbf52acfcddeb291f283e901338b056c"` (MEASURED: sha256(b"run-1\x003")[:32]).
8. `user_goal="Review the message"` (non-empty, kept); `policy_context={}` (none) → `FrozenDict({})`.
9. `candidate_action`: `_canonical_action` → `CandidateAction(type=RESPOND, tool=None, arguments={}, content="Reviewed", final=True, confirmation_for=None)`; passes shape rule "only respond actions can be final".
10. `AdaptedRequest.request` = `GuardRequest{request_id as above, user_goal="Review the message", observations=(message/AUTHENTICATED_USER, email/UNTRUSTED_EXTERNAL), candidate_action=respond("Reviewed",final=True), policy_context={}}`; `confirmations_granted=frozenset()`, `least_trust=UNTRUSTED_EXTERNAL`, `max_sensitivity=INTERNAL`, `provenance_complete=True`, `referenced_provenance=(prov-1,)`, `evidence_truncated=False`.
11. Engine receives this `AdaptedRequest` (engine.py:349); because `provenance_complete` is True and action is `respond`, neither `PROVENANCE_INCOMPLETE` nor `EVIDENCE_TRUNCATED` fires.

Ambiguous variant — change step 4's `provenance_ids` to `["prov-x"]` (not declared): `records.get("prov-x") → None` (adapter.py:76) → `complete=False`, Observation `{source="unresolved:prov-x", trust_level=ADVERSARY_CONTROLLED, sensitivity=RESTRICTED}` (adapter.py:151-159); `least_trust` becomes `ADVERSARY_CONTROLLED`; engine returns `PROVENANCE_INCOMPLETE` block (engine.py:467-468) regardless of the candidate action. If instead the id list is emptied, role `user` yields the *opposite* outcome — `AUTHENTICATED_USER` and `complete=True` (risk #1 above).
