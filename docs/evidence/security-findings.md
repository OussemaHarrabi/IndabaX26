# Security findings register

Owner: orchestrator. Source: the Milestone 0 independent adversarial review.

| Field | Value |
| --- | --- |
| Reviewer | Agent H (read-only adversarial security reviewer) |
| Date | 2026-10-08 |
| Reviewed revision | `770e88d` (defence code byte-identical to `649f65a`); re-verified at `192bc64` |
| Method | code reading plus targeted live reproduction on the local stack and on the pinned container stack; temporary probes written outside the repository and deleted |
| Raw artifact | `docs/evidence/reviews/M0-adversarial-security-review.json` (31,179 bytes, SHA-256 `8d6c50522723e54c3bbafd24267dc56020519862ccc736cdfd8a3374effe6ecf`) |
| Scope note | the review covered the shipped decision boundary and its integration contract. Absence of a finding in this scope is **not** a claim that the system is secure |

**Finding vector: 4 high (F1–F4), 4 medium (F5, F6, F7, F9), 2 low (F8, F10).** An earlier commit message on this
branch (`d86ac83`) summarised this as "3 high, 5 medium, 2 low"; that summary was wrong and is corrected here. The
per-finding severities in the table below were always correct, and the review artifact is the authority.

**Hashing rule for evidence artifacts.** These artifacts are committed as *blobs* whose bytes must not be
transformed by a checkout. Hash the blob, not a Windows working copy:

```
git show <commit>:<path> | sha256sum
```

The repository's `.gitattributes` now marks `*.json` and `*.jsonl` as `-text` so a checkout cannot rewrite line
endings. Existing legacy blobs were deliberately **not** renormalised, because renormalising would change their
bytes and invalidate the frozen digests.

Status vocabulary: `open` (confirmed, not yet fixed), `fixed` (regression test present), `accepted`
(documented residual risk with an explicit decision).

| ID | Severity | Finding | Milestone | Status |
| --- | --- | --- | --- | --- |
| F1 | high (critical if internet-reachable) | Unauthenticated decision boundary: every security-relevant input (policy context, provenance labels, confirmation grants) is supplied by the caller; `Dockerfile` binds `0.0.0.0` | M2 | open |
| F2 | high | Confirmation is self-granted inside the same envelope: an offline-computed action digest placed in `history_digest.confirmations_granted` turns `escalate` into `allow / CONFIRMATION_VERIFIED` | M2 | open |
| F3 | high | Provenance trust/sensitivity labels and policy facts are attacker-declared, so the untrusted-instruction and sensitive-flow controls are switchable by relabelling evidence or editing `policy_context` | M2 | open |
| F4 | high | Algorithmic-complexity denial of service in `_is_laundered_claim` (`_EMAIL_ADDRESS.findall`): measured 163 s of event-loop blockage for one 2 MiB request; quadratic in input length and multiplicative over sources × sentences | **M1** | open |
| F5 | medium | No upper bound on request body size; per-field bounds only, and unknown keys are ignored, so bodies can be padded arbitrarily (768 MiB measured on the local stack) | **M1** | open |
| F6 | medium | Confirmation and rewrite matching use the canonical digest, which is not injective (whitespace and integral-float variants collide), and grants are unbound, unexpiring, reusable across runs | **M1** | open |
| F7 | medium | No decision identity, receipt or audit record at the wire boundary; `DecisionReceipt` exists but is never constructed outside tests | **M1** (identity + emitted record) / M2 (durable store) | open |
| F8 | low | `requirements.lock` pins versions without hashes, so installed artifacts are not integrity-checked | M4 | open |
| F9 | medium (evidence fidelity) | The environment that runs the suite differs from the shipped image, with a demonstrated behavioural difference (body-size memory amplification) | M3 (CI runs in the image) / M4 | open |
| F10 | low | The application directory is owned by the runtime user, so a foothold could rewrite the service's own code unless the filesystem is read-only | M4 | open |

## Effect on published results

None of the findings changes the legacy scorecards: those runs measure the engine under a trusted-simulator
model with a trusted caller, which remains a valid stated precondition. Two caveats must travel with the
claims:

- F6 touches the confirmation matching rule, which is exactly the mechanism behind the measured benign
  failure in `enterprise_security_digest`. Any change to matching requires a **new** evaluation run recorded
  as a new artifact; the legacy scorecard is never overwritten.
- F9 means the "187 passed" baseline is evidence about the local interpreter, not about the shipped image,
  until CI runs the suite inside the container.

## Required regression criteria (short form)

- F1: anonymous `POST` returns 401/403 and produces no decision; policy overrides and confirmation grants
  require a verified caller identity.
- F2: a correct digest presented in the same envelope still yields escalate/block; a grant issued for one run
  is rejected in another; an offline-computed digest is not accepted as proof of confirmation.
- F3: self-declared trusted labels cannot remove an untrusted-instruction block; overriding
  `internal_email_domains` / `allowed_tools` requires an authorised caller and is otherwise ignored.
- F4: a worst-case 2 MiB adversarial request completes or is rejected in under 1 s; a micro-benchmark asserts
  per-character scan cost stays flat from 1 KB to 16 KB.
- F5: a Content-Length or chunked body above the cap is rejected with 413 before JSON parsing.
- F6: confirmation matches the exact execution digest and is bound to request identity; a whitespace or float
  variant of an approved action is not allowed by the canonical twin's grant.
- F7: the response carries a server-computed decision identity and the service emits one structured decision
  record per request; identical inputs give a stable identity, a changed action gives a different one.
- F8: `pip install --require-hashes -r requirements.lock` succeeds, or the file is renamed to reflect
  version pinning only and the limitation is documented.
- F9: CI runs the test suite inside the built image and records the image digest with the result.
- F10: the image runs with a read-only root filesystem, or `/app` is root-owned and not writable by the
  service user; a smoke test covers `/healthz` and one decision under that configuration.

## Orchestrator decisions locked for M2 (F1–F3, and the durable half of F7)

These are decisions, not proposals: M2 implements them as written. ADR-0001 and ADR-0002 remain the
architectural rationale; where they were silent, the following is authoritative.

| # | Decision |
| --- | --- |
| D1 | **Principal and tenant.** Every authenticated request resolves to `principal_id`, `tenant_id` and a scope list. `tenant_id` comes from the credential, never from the body. Receipts are keyed by `(tenant_id, request_id)` and every query is tenant-scoped. |
| D2 | **Trust ceiling.** A request may assert a provenance `trust_level` at or below the principal's `trust_ceiling`. Above it, the request is rejected with 403 `TRUST_CEILING_EXCEEDED` — never silently downgraded, because a silent downgrade hides a misconfigured integration. |
| D3 | **Policy authority.** Caller-supplied `policy_context` overrides (`allowed_tools`, `consequential_tools`, `internal_email_domains`) are **ignored** unless the principal holds the scope `policy:context_override`. The default is the server-stored policy set named by `policy_set {id, version}`. |
| D4 | **Confirmation channel.** Grants are issued only by `POST /api/v1/confirmations` (scope `confirmation:grant`) and persisted as rows `(tenant_id, run_id, step_id, execution_digest, issued_by, issued_at, expires_at)`. At decision time a grant must exist in the store, match all four components and be unexpired. A syntactically perfect grant that was never issued is refused — this is what closes F2 rather than merely reformatting it. |
| D5 | **Legacy surface.** `/v1/decision` stays available only in an explicitly labelled development mode bound to loopback, and only when `AEGISGRAPH_LEGACY_UNAUTHENTICATED=true` is set. Production mode refuses to start with the legacy unauthenticated surface enabled. |
| D6 | **Retention.** Digests, verdicts, reason codes, policy identity and actor identity are retained indefinitely: they are the audit trail. Payload-adjacent metadata is digest-only or redacted by default, with a documented retention window (default 90 days) and a tested deletion procedure. |
| D7 | **Configuration safety.** No secret in Git. Configuration arrives through environment variables or mounted files. Startup fails closed when `AEGISGRAPH_AUTH_MODE=none` in production mode, when the legacy surface is enabled in production mode, or when a required secret is absent. |

