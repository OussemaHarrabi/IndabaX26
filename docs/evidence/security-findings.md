# Security findings register

Owner: orchestrator. Sources: two independent adversarial reviews. Statuses change only with evidence
attached below.

| Field | Review #1 (M0) | Review #2 (M1–M5) |
| --- | --- | --- |
| Reviewer | Agent H, read-only | Agent H2, read-only |
| Date | 2026-10-08 | 2026-10-08 |
| Reviewed revision | `770e88d` (defence code identical to `649f65a`) | `3353886` |
| Raw artifact | `docs/evidence/reviews/M0-adversarial-security-review.json` (31,179 B, blob SHA-256 `8d6c50522723e54c3bbafd24267dc56020519862ccc736cdfd8a3374effe6ecf`) | `docs/evidence/reviews/M1-M5-adversarial-security-review.json` (28,934 B, SHA-256 `539d604b5a1e3a6b93f333a5584d68993abf7cb690dd3e6f1d3bfe381c2e9e24`) |
| Finding vector | 4 high (F1–F4), 4 medium (F5, F6, F7, F9), 2 low (F8, F10) | 1 high (H2-01), 2 medium (H2-02, H2-03), 3 low (H2-04, H2-05, H2-06) |

An earlier commit message on this branch (`d86ac83`) summarised review #1 as "3 high, 5 medium, 2 low"; that was
wrong and is corrected here. The per-finding severities in the table below were always correct, and the review
artifacts are the authority.

**Hashing rule for evidence artifacts.** These artifacts are committed as *blobs* whose bytes must not be
transformed by a checkout. Hash the blob, not a Windows working copy: `git show <commit>:<path> | sha256sum`.
`.gitattributes` marks `*.json`/`*.jsonl` as `-text` so a checkout cannot rewrite line endings; existing legacy
blobs were deliberately **not** renormalised, because that would change their bytes and invalidate the frozen
digests.

Status vocabulary: `fixed` (a regression test exists and the fix was verified), `accepted` (documented residual
risk with an explicit decision), `open`.

| ID | Sev | Finding | Milestone | Status | Evidence |
| --- | --- | --- | --- | --- | --- |
| F1 | high | Unauthenticated decision boundary: every security-relevant input supplied by the caller | M2 | **fixed** | Live: anonymous `POST /api/v1/decisions` → `401`; auditor token → `403` with the missing scope named; `decision_client` → `200`. `docs/api/auth.md`, `tests/test_authentication.py` |
| F2 | high | Confirmation self-granted inside the same envelope | M2 | **fixed** | Live: a syntactically perfect grant that was never issued → `escalate / CONFIRMATION_REQUIRED`; the same grant issued through `POST /api/v1/confirmations` → `allow / CONFIRMATION_VERIFIED`; replayed in another run → `escalate`. `docs/api/receipts.md` §3, `tests/test_receipts_api.py` |
| F3 | high | Provenance labels and policy facts were attacker-declared | M2 | **fixed (caller-authority half)**; residual `accepted` | Live: a `system_policy` label from a `trusted_internal`-ceiling credential → `403 TRUST_CEILING_EXCEEDED`; caller `policy_context` ignored without `policy:context_override` (server policy applied, `policy_set` reported from the server). **Residual:** the *harness* still supplies labels; a deployment must treat the caller as the source of truth for its own evidence, bounded by the ceiling. Documented in `docs/api/auth.md` §5–6 |
| F4 | high | Quadratic scan in `_is_laundered_claim` (163 s for one 2 MiB request) | M1 | **fixed**, then **partially reopened as H2-01** | Live: 880,000 adversarial characters across 55 observations → 36 ms; linear 192 k/480 k/880 k → 9/17/36 ms. `tests/test_bounds.py` |
| H2-01 | high | Per-request CPU unbounded: the F4 fix bounded one scan, not the number of scans (`2 × sources × sentences`, each up to 64 KB) | M1 (follow-up) | **fixed** | Fixed by caching one source profile per distinct source per evaluation plus a per-pass sentence budget that fails closed. Orchestrator re-measurement over HTTP: 4 sources × 16 kB + 1000 sentences → **0.016 s** (reviewer's shape was 13.4 s; the fix's own heavier variant was 101 s in-process); 8 sources → 0.025 s; worst accepted shape (60 × 16 kB + 2000 sentences, ≈986 kB) → **0.256 s** against a 2 s bound; 4000/5300 sentences → `block / NARRATIVE_SCAN_BUDGET_EXCEEDED` in ~10–26 ms. Verdicts unchanged (`rewrite / UNTRUSTED_AUTHORITY_REDACTED`). Call-count regression `tests/test_bounds.py::test_source_profile_is_built_once_per_distinct_source` (4 calls for 4 distinct sources, set equality asserted; 8000 before) |
| F5 | medium | No upper bound on request body size | M1 | **fixed** | Live: 1.2 MB body → `413` in 5 ms with a clean JSON body; boundary case `200`. `tests/test_bounds.py` |
| F6 | medium | Confirmation matched a non-injective canonical digest; grants unbound and permanent | M1 (new surface) | **fixed** | Live: strict grant `run:step:execution_digest:expiry`; bare, expired and wrong-run grants escalate; the bound grant allows. Legacy surface keeps the canonical digest the pinned harness supplies — proved by the mock recheck being byte-identical (`8669aadb…`) |
| F7 | medium | No decision identity, receipt or audit record at the wire | M1 + M2 | **fixed** | Live: response carries `request_id`, `receipt_id`, `policy_set`, both digests, `decided_at`, `valid_until`; exactly one structured decision record per decision with a matching `receipt_id`; receipts are persisted in PostgreSQL, readable per tenant, and append-only |
| F8 | low | Lock pins versions without hashes | M4 | **accepted** | `requirements.lock` documents the refresh procedure, licence review and vulnerability review; hash pinning is deferred with the reason stated in the file header |
| F9 | medium | The environment that runs the suite differs from the shipped image | M3/M4 | **open** | CI is being changed to run the suite with a PostgreSQL service; running the suite **inside** the image remains the acceptance criterion |
| F10 | low | Application directory owned by the runtime user | M4 | **fixed** | Live: uid 10001, `/app` `dr-xr-xr-x root root`, `touch /app/breach` → "Read-only file system", no pip/compiler; read-only smoke passes |
| H2-01 | high | Per-request CPU unbounded: the F4 fix bounded one scan, not the number of scans (`2 × sources × sentences`, each up to 64 KB) | M1 (follow-up) | **fixed** | see the row above (this table keeps one row per finding; the F4 row carries the H2-01 status and measurements) |
| H2-02 | medium | Policy identity in the receipt/log/version was caller-asserted, making the SDK `POLICY_MISMATCH` check vacuous | M2 (follow-up) | **fixed** | The reported identity is now read from the stored policy row; a named version the server does not hold → `422 POLICY_SET_UNKNOWN` even for a `policy:context_override` holder, and a refused request writes no receipt. `tests/test_authorization_policy.py::test_the_receipt_identity_is_server_resolved_and_cannot_be_forged`; orchestrator re-verified live (server policy applied, caller override ignored without the scope) |
| H2-03 | medium | Strict confirmation was self-attested before M2's store check | M2 | **fixed** | Store existence + binding + expiry, with every drop classified and audited (`not_issued` / `not_bound` / `expired` / `malformed`). `tests/test_confirmation_channel.py` (14 tests); orchestrator verified live (never-issued grant → escalate; issued grant → allow; cross-run replay → escalate) |
| H2-04 | low | `parse_confirmation_grant` raises `ValueError` on superscript digits instead of returning `None` | M1 (follow-up) | **fixed** | ASCII-decimal validation (`re.fullmatch(r"[0-9]+", ...)`) for both numeric fields, covering superscript and Arabic-Indic digits; `tests/test_confirmation_strict.py::test_grant_fields_must_be_ascii_decimal`. The package audit for the same shape found only one other `isdigit` use, which gates redaction without converting |
| H2-05 | low | `request_id` echoed verbatim while documented as server-computed | M2 (follow-up) | **fixed (documented decision)** | Option (b): a caller `request_id` is preserved by design as the idempotency/correlation key (tenant-scoped, `409 REQUEST_ID_CONFLICT` on conflicting reuse), and `receipt_id` is the server-computed decision identity. Documented in `docs/api/receipts.md` §2 with two pinning tests |
| H2-06 | low | Holdout passphrase transcript exposure | M5 | **fixed** | The seal was rotated with a key that never entered a transcript; the same 20 scenarios were re-sealed (scenario-set hashes compared), the old key is void, and `docs/evidence/m5-seal-custody.md` records the history and the rotation procedure |

## Third review (M2 surface, Agent H3, at `989346c`)

Artifact: `docs/evidence/reviews/M2-surface-adversarial-security-review.json` (raw). Scope: authentication,
authorization, policy administration, the confirmation channel, receipts/audit and the new configuration
surface. Finding vector: 1 high, 3 medium, 5 low. Out of scope by instruction: M3 telemetry (in flight).

| ID | Sev | Finding | Status |
| --- | --- | --- | --- |
| H3-01 | high | The trust ceiling did not cover conversation-derived evidence: `access._declared_trust_levels` read only declared `provenance[]` and `least_trusted_seen`, while the adapter labels a `user`-role item with no provenance ids as `authenticated_user`, so any `decision:submit` caller could re-open the F3 relabelling move inside the ceiling | open — fix in flight (M2 owner) |
| H3-02 | medium | An idempotent replay returned a fresh decision under the stored `receipt_id`, so the response and the durable receipt could disagree | open — fix in flight |
| H3-03 | medium | `POST /api/v1/confirmations` returned the candidate grant rather than the stored row, so the response and the audit event could report an expiry the store does not hold | open — fix in flight |
| H3-04 | low (medium with the override scope) | `policy:context_override` let a receipt name a policy identity that was never stored — a partial reopening of H2-02 for override holders | open — fix in flight |
| H3-05 | low | `/readyz` reported `ready: true` for an `AUTH_MODE=none` process, contradicting the documented contract | open — fix in flight |
| H3-06 | low | The legacy-surface loopback refusal checks the configured bind variable rather than the actual bind | open — fix in flight |
| H3-07 | low | An unknown `kid` forced a full JWKS re-read per request, bypassing the TTL | open — fix in flight |
| H3-08 | low | The request body is read, bounded and parsed before the credential is checked | open — fix in flight |
| H3-09 | low | A non-finite float in a policy document escaped as an unhandled `ValueError` → 500 | open — fix in flight |

**H3-01 is the most consequential finding of the whole program so far**, because it invalidates the sentence I
wrote when closing F3: the ceiling was described as the bound on caller-declared trust, and it did not bound the
implicit role-based path. The register keeps that correction rather than hiding it. It also means the benchmark
reference run may need re-running after the fix, since the fix changes which requests are accepted.

## Verification log (orchestrator, live, with the artefacts in the tree)

- **Legacy compatibility after M1:** pinned mock suite byte-identical to the M0 recheck — 40/40 scenario labels,
  deterministic digest `8669aadb87e94652645ae8ed1f454f6f103c21bc8960cc65bf6e051de3043dfa`, decision mix
  150 allow / 57 block / 1 rewrite, score 0.953956.
- **M1 surface:** one decision record per decision with a matching `receipt_id`; build identity from
  `AEGISGRAPH_BUILD_COMMIT`/`_VERSION`; enforcement SDK executes the approved action and refuses the tampered
  one with `digest_mismatch`.
- **M2 with PostgreSQL 17:** `alembic upgrade head` from an empty database → `0001_initial`;
  `alembic check` → "No new upgrade operations detected"; `454 passed` with the database, `442 passed, 12 skipped`
  without; coverage **96.68 %** (2619/2709) with the database and 93.06 % without (which is why the CI quality
  job is being given a database service and the floor is moving to 95).
- **M2 live:** policy publish/activate → `201` with a checksum; receipts readable by the owning tenant and `404`
  for another tenant; idempotent `request_id` returns the same receipt; the same `request_id` with a different
  action → `409`; legacy surface → `404`; no credential or request content in the logs.
- **M4:** read-only container smoke; compose config with five services; kustomize renders 7 objects; both
  validators pass; pinned kubeconform installer verifies the vendor checksum; SBOM byte-identical across runs.
- **M4 compose stack, end to end (orchestrator, `docker compose up -d --build`):** five services healthy
  (api, postgres, grafana, prometheus, otel-collector); the one-shot `migrate` service applied
  `0001_initial`; `GET /healthz` → `{"status":"ok"}`; `GET /readyz` → `ready: true` with
  `receipt_store: {durable: true, reachable: true}` (M2's durable store wired through the stack); one
  decision on the legacy surface → `allow / BENIGN_ACTION`. Torn down afterwards; the port was overridden
  to 18088 so it could not collide with a sibling's service.
- **M5:** validator `PASS` (60 scenarios, 42/18, six per family across ten families, dataset
  `7e916a11981fa6444724dc78558e51561d32a3005b182862efb52b7c5f2cf735`); scoring deterministic (two runs
  byte-identical); duplicate run directory refused; seal `verify` `PASS` with `opened: false`; the custodian key
  opens it (20 scenarios) and lives outside the repository.

## Orchestrator decisions locked for M2 (implemented)

| # | Decision |
| --- | --- |
| D1 | Principal and tenant from the credential; receipts keyed by `(tenant_id, request_id)`; every query tenant-scoped |
| D2 | Trust ceiling per credential; a more-trusted assertion → `403 TRUST_CEILING_EXCEEDED`, never silently downgraded |
| D3 | Caller `policy_context` ignored unless the credential holds `policy:context_override`; the server-stored policy set is the authority; an unknown policy set → `422 POLICY_SET_UNKNOWN` |
| D4 | Grants exist only if issued by `POST /api/v1/confirmations` and persisted; a never-issued grant is refused |
| D5 | Legacy `/v1/decision` only in development, loopback-bound, with `AEGISGRAPH_LEGACY_UNAUTHENTICATED=true`; production refuses to start with it enabled |
| D6 | Digests, verdicts, reason codes, policy and actor identity retained indefinitely; payload-adjacent metadata digest-only by default with a documented retention window |
| D7 | Configuration from env or mounted files; startup fails closed on insecure production configuration |

## Effect on published results

None of the findings changes a legacy scorecard: those runs measure the engine under a trusted-simulator model
with a trusted caller, which remains a valid stated precondition. Two caveats must travel with the claims:

- F6 and H2-03 touch the confirmation matching rule, which is the mechanism behind the measured benign failure in
  `enterprise_security_digest`. The strict rule applies to the **new** surface only; the legacy surface keeps the
  canonical-digest behaviour, which is why the recheck is byte-identical. Any future change to legacy matching
  requires a new evaluation run recorded as a new artefact — the legacy scorecard is never overwritten.
- F9 means the "N passed" baseline is evidence about the local interpreter and, once CI has a database service,
  about a CI runner — not yet about the shipped image.

## Required regression criteria (short form)

- F1: anonymous `POST` → 401/403 and no decision; policy overrides and grants require a verified credential.
- F2: a correct-but-never-issued grant still escalates; a grant issued for one run is rejected in another.
- F3: a self-declared trusted label above the ceiling → 403; policy overrides require the scope and are otherwise
  ignored.
- F4/H2-01: a 2 MiB adversarial request completes or is rejected in under 1 s; per-character scan cost stays flat
  from 1 KB to 16 KB; the worst shape (4 × 16 kB sources, 1000 sentences) decides in under 2 s with a call count
  bounded by the number of distinct sources.
- F5: a body above the cap → 413 before JSON parsing, for Content-Length and chunked.
- F6: confirmation matches the exact execution digest and is bound to the run and step.
- F7: the response carries a server-computed identity and exactly one durable record per decision.
- F8: `pip install --require-hashes -r requirements.lock` succeeds, or the file states version-pinning only.
- F9: CI runs the suite inside the built image and records the image digest with the result.
- F10: read-only root filesystem or root-owned `/app`; smoke-tested.
