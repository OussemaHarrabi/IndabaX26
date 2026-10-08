# Receipts, confirmations, policy administration and audit

Status: Milestone 2. Closes the durable half of finding **F7** and finding **F2**;
implements decisions **D1**, **D4** and **D6**. Authentication, scopes and the
trust ceiling are documented in [auth.md](auth.md).

## 1. What a receipt is

A receipt is the durable record of one decision. It is written once per
`(tenant_id, request_id)` and is **append-only**: the database refuses to update or
delete it, so the audit trail cannot be rewritten in place.

A receipt holds:

| Retained indefinitely (D6) | Retention-scoped (D6) |
| --- | --- |
| `receipt_id`, `request_id`, `surface` | `metadata` (the payload-adjacent copy) |
| `verdict`, `risk_score`, `confidence`, `reason_codes` | |
| `action_digest`, `execution_digest`, `payload_digest` | |
| `policy_set {id, version}` | |
| `principal_id`, `auth_method`, `run_id`, `step_id` | |
| `decided_at`, `valid_until` | |

`payload_digest` is the SHA-256 of the canonical JSON of the request plus the
response metadata. By default **only the digest is stored**: payload-adjacent
content is not persisted at all. Setting `AEGISGRAPH_STORE_PAYLOAD_METADATA=true`
additionally keeps a copy that the retention procedure redacts — see
[../ops/retention.md](../ops/retention.md).

The frozen legacy `POST /v1/decision` wire is intentionally **not** receipt-bearing:
its measured behaviour is preserved byte for byte.

## 2. `request_id` versus `receipt_id` (H2-05)

| Field | Who computes it | Role |
| --- | --- | --- |
| `request_id` | the **caller**, or the server when omitted | the caller's correlation and idempotency key; preserved verbatim by design |
| `receipt_id` | the **server** (`uuid4().hex`) | the decision identity the audit trail and the enforcement SDK key on |

A caller-supplied `request_id` is preserved rather than replaced because it is the
idempotency key: a client that retries a request after a timeout must be able to
present the same value and receive the same receipt instead of a second decision.
Replacing it server-side would make a safe retry impossible.

It is safe for correlation because:

* receipts are keyed by `(tenant_id, request_id)`, so the value is tenant-scoped and
  two tenants can never collide;
* a reused `request_id` carrying a *different* action is refused with
  `409 REQUEST_ID_CONFLICT` and audited, so a value can never be re-pointed at
  another decision;
* the authoritative decision identity is the server-computed `receipt_id`, which
  appears in the decision record, in `GET /api/v1/receipts`, and in the receipt the
  SDK verifies. A client cannot choose it, and no other field is derived from
  `request_id`.

When the caller omits `request_id`, the server generates a 32-hex value, so the
response and the receipt always carry one. The behaviour is pinned by
`tests/test_receipts_api.py::test_a_caller_supplied_request_id_is_preserved_by_design`
and `::test_an_omitted_request_id_is_generated_by_the_server`.

## 3. Idempotency

* The same `request_id` with the same action returns the stored receipt — same
  `receipt_id`, `decided_at` and `valid_until` — and writes no second row. Two
  workers racing on the same `request_id` produce exactly one row (the unique key
  decides; both callers read the same receipt).
* The same `request_id` with a **different** action is refused with
  `409 REQUEST_ID_CONFLICT` and an `receipt_request_conflict` audit event. Returning
  the first decision for a different action would be a silent authorization bug.
* Omitting `request_id` generates a fresh one, so the request is a new decision.

A decision that cannot be persisted is not returned as if it had been:
`503 RECEIPT_STORE_UNAVAILABLE` is returned instead.

## 4. Endpoints

All of them are tenant-scoped from the credential. A row belonging to another tenant
is reported as `404`, not `403`, so the surface is not a cross-tenant existence
oracle.

### `GET /api/v1/receipts` — scope `receipt:read`

| Query | Bound | Default |
| --- | --- | --- |
| `limit` | 1–100 | 20 |
| `cursor` | ≤ 256 chars, opaque | — |

Newest first, ordered by `(decided_at, request_id)` descending. The response is
`{"items": [...], "next_cursor": "..."}`; `next_cursor` is `null` on the last page.
An unparseable cursor returns an empty page rather than an error.

```console
$ curl -s -H "Authorization: Bearer $AUDITOR_TOKEN" \
    'https://host/api/v1/receipts?limit=2' | jq '.items[].receipt_id, .next_cursor'
```

### `GET /api/v1/receipts/{receipt_id}` — scope `receipt:read`

One receipt, or `404 RECEIPT_NOT_FOUND`.

### `POST /api/v1/confirmations` — scope `confirmation:grant`

The **only** way a confirmation grant comes into existence (D4).

```json
{ "run_id": "run-7", "step_id": 4, "execution_digest": "9f2c…", "ttl_seconds": 300 }
```

`ttl_seconds` is 1–86400 and defaults to 300. The response is `201`:

```json
{
  "grant": "run-7:4:9f2c…:1770000000",
  "run_id": "run-7",
  "step_id": 4,
  "execution_digest": "9f2c…",
  "issued_by": "reviewer-a",
  "issued_at": "2026-10-08T09:00:00Z",
  "expires_at": "2026-10-08T09:05:00Z"
}
```

The grant is persisted as
`(tenant_id, run_id, step_id, execution_digest, issued_by, issued_at, expires_at)`.
Issuing is idempotent on the four binding components and writes an
`confirmation_grant_issued` audit event.

### How a grant is consumed

The caller presents the grant string in `history_digest.confirmations_granted` on
`POST /api/v1/decisions`. At decision time the service keeps only grants that

1. parse as `run_id:step_id:execution_digest:expiry`,
2. exist in the store for the caller's tenant, bound to the same run, step and
   exact execution digest,
3. are unexpired,

and then requires the survivor to match the request's own run, step and action.

**A syntactically perfect grant that was never issued is refused** and the action
escalates: this is what closes F2, because a caller can no longer mint a
confirmation by computing a digest offline. Dropped grants are counted in a
`confirmation_grant_refused` audit event that carries no request content.

### `GET` / `POST /api/v1/policies` — scopes `policy:read` / `policy:write`

```json
{ "id": "aegisgraph-default", "version": "2", "document": { "allowed_tools": ["document_search"] }, "activate": true }
```

* Versions are **immutable**. Re-publishing an identical document is idempotent;
  publishing a different document under an existing `(id, version)` is refused with
  `409 POLICY_SET_IMMUTABLE`. Publish a new version instead.
* The document is validated with the same parser the decision path uses, so a
  document that cannot be evaluated is refused with `422 POLICY_DOCUMENT_INVALID`.
* A document larger than 256 KiB is refused with `413 POLICY_DOCUMENT_TOO_LARGE`.
* `activate: true` publishes and activates in one call. Activating one version
  deactivates the previous one for that policy id.
* Every change writes an audit event: `policy_set_created`, `policy_set_activated`.

`POST /api/v1/policies/{policy_id}/activate` with `{"version": "2"}` activates an
already stored version, or returns `404 POLICY_SET_UNKNOWN`.

### `GET /api/v1/audit-events` — scope `receipt:read` or `policy:read`

The most recent audit events for the tenant, newest first, bounded by `limit`
(1–200, default 200).

| Event type | Written when |
| --- | --- |
| `policy_set_created` | a policy version is stored |
| `policy_set_activated` | the activation flag changes |
| `confirmation_grant_issued` | a grant is issued |
| `confirmation_grant_refused` | a presented grant was malformed, expired or never issued |
| `receipt_request_conflict` | a `request_id` was reused for a different action |
| `retention_applied` | a retention pass redacted payload-adjacent data |

`audit_events` is append-only at the database level, like `receipts`.

## 5. Readiness

`GET /healthz` stays a bare liveness probe: `{"status": "ok"}`. Dependency
readiness is reported by the separate, unauthenticated `GET /readyz`:

```json
{
  "status": "ready",
  "ready": true,
  "dependencies": {
    "authentication": {
      "mode": "required",
      "jwt_configured": true,
      "service_tokens_configured": 1,
      "legacy_unauthenticated": false
    },
    "receipt_store": { "durable": true, "reachable": true },
    "environment": "production"
  }
}
```

`ready` is `false` and the status is `503` when the receipt store does not answer,
or when a development process runs without authentication. The body contains no
secret material: no token, no digest, no key, no database URL.

## 6. Enforcement

`backend/aegisgraph/enforcement.py` is unchanged: pass the receipt mapping the
service returned to `enforce()`/`execute_guarded()` together with the exact
`CandidateAction`. A receipt read back from `GET /api/v1/receipts` carries the same
`receipt_id`, `policy_set`, `action_digest`, `execution_digest` and `valid_until`, so
a caller can re-verify an action after a restart.
