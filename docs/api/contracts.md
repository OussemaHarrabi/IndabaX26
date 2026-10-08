# AegisGraph decision contracts (normative)

This document is normative for the two decision surfaces served by
`backend/aegisgraph/app.py`. The machine-readable schema for the generic surface
is `docs/api/decision.schema.json`.

| Surface | Method and path | Status |
| --- | --- | --- |
| Frozen legacy SENTINEL wire | `POST /v1/decision` | byte-compatible shape, frozen |
| Generic AegisGraph contract | `POST /api/v1/decisions` | versioned, `aegisgraph/v1` |
| Identity endpoint | `GET /api/v1/version` | versioned, `aegisgraph/v1` |
| Liveness | `GET /healthz` | unchanged |
| Local dashboard | `GET /`, `/assets/*` | unchanged |

Both decision surfaces evaluate an **inert** candidate action. Neither executes a
tool, calls a model, or mutates state.

## 1. `POST /v1/decision` (frozen legacy wire)

Unchanged. Request and response models live in `backend/aegisgraph/sentinel.py`
(`SentinelRequest`, `SentinelResponse`). The response is exactly seven fields and
`extra="forbid"`:

| Field | Type | Notes |
| --- | --- | --- |
| `decision` | `allow \| block \| escalate \| rewrite` | |
| `risk_score` | number `0..1` | |
| `confidence` | number `0..1` | |
| `reason_codes` | array of `UPPER_SNAKE_CASE` codes, max 16 | |
| `explanation` | string or `null`, max 500 chars | |
| `rewritten_action` | candidate action or `null` | present iff `decision == "rewrite"` |
| `metadata` | object, max 4096 JSON bytes | |

`explanation` and `metadata` never echo request content. An unknown envelope key
in the request is ignored (forward compatible); an unknown key in a *response*
is a contract violation.

**Trusted-caller confirmation mode (legacy).** Confirmation is matched against the
bare canonical action digest (`CandidateAction.digest()`). The canonical digest
is lossy (whitespace-normalized strings and integral floats collide) and the
grant is not bound to a run, a step, or an expiry. This is the behaviour the
pinned SENTINEL starter kit and the committed scorecards depend on, so it is
preserved unchanged and documented here as *trusted-caller mode*.

## 2. `POST /api/v1/decisions` (generic contract)

### Request

The whole SENTINEL envelope (bounded exactly as above) plus:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `api_version` | `"aegisgraph/v1"` | yes | any other value, or omission, is `422` |
| `request_id` | string, 1..128, `^[A-Za-z0-9][A-Za-z0-9._:-]*$` | no | server generates a 32-hex id when absent |
| `policy_set` | `{id, version}` | no | defaults to the server policy set below |

Unknown envelope keys are still ignored, exactly as on the legacy wire.

### Response

The seven legacy fields **plus** eight identity fields; `extra="forbid"`.

| Field | Type | Notes |
| --- | --- | --- |
| `api_version` | `"aegisgraph/v1"` | |
| `request_id` | string | echoed or generated |
| `receipt_id` | 32 lowercase hex chars | `uuid4().hex`, server-generated |
| `policy_set` | `{id, version}` | effective policy identity for this decision |
| `action_digest` | 24 lowercase hex chars | existing canonical digest, **lossy** |
| `execution_digest` | 24 lowercase hex chars | exact digest (`contracts.exact_action_digest`) |
| `decided_at` | ISO-8601 UTC datetime | |
| `valid_until` | ISO-8601 UTC datetime | `decided_at + TTL` |

Both digests are always present, including on the fail-closed path.

**Receipt validity.** `valid_until = decided_at + TTL`, where `TTL` is
`AEGISGRAPH_RECEIPT_TTL_SECONDS` (default `60`, must be a positive integer;
invalid or non-positive values fall back to the default). `valid_until` is the
window the *caller-side* enforcement SDK checks. It is not a durable
authorization record: durable storage is Milestone 2.

**Strict confirmation mode (generic surface only).** A grant in
`history_digest.confirmations_granted` is accepted only when it is exactly
`"<run_id>:<step_id>:<execution_digest>:<expiry_unix>"` and all four components
match the request: same `run_id`, same `step_id`, `execution_digest` equal to the
exact digest of the evaluated action, and `expiry_unix` strictly greater than the
decision time. `run_id` may itself contain `:` (the grant is split from the
right). Bare canonical digests, malformed grants, grants for another run or step,
grants for a colliding action variant, and expired grants are all treated as *not
granted*, so the decision escalates with `CONFIRMATION_REQUIRED` instead of
allowing the action. This is what closes F6 on the new surface.

| Mode | Surface | Grant accepted | Colliding variant (same canonical digest) | Expiry |
| --- | --- | --- | --- | --- |
| legacy | `POST /v1/decision` | bare canonical digest | allowed (documented collision) | not checked |
| strict | `POST /api/v1/decisions` | `run:step:execution_digest:expiry` | rejected (escalate) | checked |

**Decision record.** Each generic decision emits exactly one structured JSON log
line on the `aegisgraph.decision` logger with these keys and no request content,
no secrets and no canary values:

`event`, `request_id`, `receipt_id`, `policy_set`, `verdict`, `reason_codes`,
`action_digest`, `execution_digest`, `latency_ms`, `caller`.

`caller` is a placeholder and is always `null` until Milestone 2 supplies the
authenticated caller identity.

## 3. `GET /api/v1/version`

| Field | Type | Notes |
| --- | --- | --- |
| `api_version` | `"aegisgraph/v1"` | |
| `policy_set` | `{id, version}` | the server's active policy set: `{"id": "aegisgraph-default", "version": "1"}` |
| `build` | object | `{service, version, commit}`; `version` is the installed distribution version, else the source `pyproject.toml` version, else `"unknown"`; `commit` comes from `AEGISGRAPH_BUILD_COMMIT`, else `"unknown"` |

## 4. Bounds and status codes

| Bound | Value | Enforced where |
| --- | --- | --- |
| Request body | `AEGISGRAPH_MAX_BODY_BYTES`, default `1_048_576` (1 MiB) | before JSON parsing, for both `Content-Length` and chunked bodies |
| Response body | 64 000 bytes | both decision endpoints |
| `user_goal`, `content` | 16 000 chars | request model |
| `policy_context` | 16 384 JSON bytes | request model |
| `metadata` | 4 096 JSON bytes | response model |
| tool arguments | 32 entries, 8 000 chars per string value | request model |

| Status | Meaning | Body |
| --- | --- | --- |
| `200` | a decision was produced (including a fail-closed `block`) | response model |
| `413` | body above the configured bound | `{"detail": "Request body exceeds the configured limit"}` |
| `422` | request validation failed (including a wrong or missing `api_version`) | `{"detail": "Invalid SENTINEL request"}` |
| `404` / `405` | unknown route or wrong method | sanitized as above |

Every response carries `Cache-Control: no-store`, `Pragma: no-cache` and
`X-Content-Type-Options: nosniff`. Error bodies are sanitized and never contain
request content or internal details. A valid request that fails *inside*
evaluation is answered `200` with `block` / `INTERNAL_EVALUATION_FAILED`: a
failure never becomes an allow.

## 5. Enforcement boundary

`backend/aegisgraph/enforcement.py` is the caller-side boundary that binds a
decision to the exact action. `enforce(receipt, action, *, expected_policy,
now=None)` returns `EnforcementOutcome {allowed, reason, detail}` with one of
these `RefusalReason` values, checked in this order:

1. `MISSING_RECEIPT` — no receipt, or no `receipt_id`.
2. `VERDICT_BLOCKED` / `UNRESOLVED_ESCALATION` / `REWRITE_NOT_REVALIDATED` — the
   recorded verdict is not `allow`.
3. `POLICY_MISMATCH` — the receipt was issued under another policy set.
4. `EXPIRED_RECEIPT` — `valid_until` is not in the future.
5. `DIGEST_MISMATCH` — either digest does not match the candidate action.
6. `MALFORMED_RECEIPT` — a structurally unusable receipt (missing or invalid
   digests, policy identity, validity window, or verdict).

`execute_guarded(executor, receipt, action, **kwargs)` calls the caller-supplied
executor **only** when enforcement allows the action; on any refusal the executor
is never invoked and `GuardedExecution.executed` is `False`.

## 6. Intentional behaviour change in Milestone 1

`tests/test_policy_kernel.py::test_confirmation_must_match_the_exact_canonical_action_digest`
previously passed a bare digest inside the request and asserted `allow` as the
only behaviour. The legacy assertion is unchanged; the test now also asserts that
the same request **escalates** in strict mode. No legacy result changes: the
pinned harness drives `POST /v1/decision`, which stays in trusted-caller mode.
