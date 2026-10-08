# ADR-0001 — Persistence: PostgreSQL + SQLAlchemy 2 + Alembic

- **Status:** proposed
- **Date:** 2026-10-08
- **Deciders:** architecture lead (proposal), orchestrator (approval), owner
- **Milestone:** M2 (auth + policy + audit store)

## Context

AegisGraph currently has no durable store. Decisions are returned over HTTP and
never persisted (`backend/aegisgraph/app.py:84`); the receipt model exists but is
not emitted or stored (`backend/aegisgraph/contracts.py:236`). The only durable
records are committed legacy files under `evaluation/**`. The platform needs an
auditable store for receipts: it must bind a decision to an exact action digest,
be append-only, support per-tenant and per-time queries, and survive a policy
change without losing historical meaning.

Local tooling has no host `psql` (see
[`../roadmap.md`](../roadmap.md) §4), so the development path must be a
container.

## Decision

Use **PostgreSQL** as the system of record, accessed through **SQLAlchemy 2** with
typed ORM models and **Alembic** migrations.

- One append-only `receipts` table keyed by `(tenant_id, request_id)`, storing the
  action digest, execution digest, decision, reason codes, policy version and a
  server-side timestamp.
- Rejected mutations (update/delete of an existing receipt) are prevented at the
  database layer, not only in application code.
- Migrations are the only way the schema changes; no runtime DDL.
- Tests run against a containerized PostgreSQL so the verified store matches the
  deployed store.

## Alternatives

1. **SQLite.** Zero-ops and test-friendly, but weak concurrency semantics and no
   row-level security; using it for tests would mean the verified store differs
   from the deployed one.
2. **Event log + object storage (append-only blobs).** Excellent for audit, poor
   for indexed queries by tenant/time/decision; would need a separate index.
3. **Document store (MongoDB).** Flexible schema, but weaker relational integrity
   for the tenant/policy joins we need and an extra operational dependency.
4. **No persistence (rely on the caller).** Rejected: the platform claims
   auditable receipts, and a caller-supplied log is not an audit trail.

## Consequences

- **Positive:** strong integrity, mature migrations, row-level security available
  for tenancy, one well-understood dependency.
- **Negative:** an operational database becomes a hard dependency; local
  development requires Docker; schema changes become reviewable artifacts.
- **Neutral:** the legacy file-based evidence stays exactly as it is; the new
  store is additive and never rewrites `evaluation/**`.
- **Blocked locally:** no host `psql`; verification is container-only until a
  host client is installed. This must be reported as a limitation, not hidden.
