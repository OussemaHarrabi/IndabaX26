# ADR-0002 — Authentication: OIDC/JWT for humans, scoped service tokens for machines

- **Status:** proposed
- **Date:** 2026-10-08
- **Deciders:** architecture lead (proposal), security reviewer, orchestrator
- **Milestone:** M2 (auth + policy + audit store)

## Context

The decision API has **no authentication** by default and must stay bound to
localhost (see [`../threat-model.md`](../threat-model.md) §3). The platform
personas — agent-platform engineer, security reviewer, audit reviewer — all need
caller identity, and the audit/compliance persona needs per-tenant isolation.
Trust and sensitivity labels must not be attacker-controllable, so they must be
derived from an authenticated principal, not from the request body.

There is no external identity provider available in this environment, so any
verification uses a local test issuer, clearly labelled as such.

## Decision

Two authentication mechanisms behind one authorization model:

1. **OIDC/JWT for interactive principals** — standard bearer tokens validated
   against an issuer's JWKS; used by human reviewers and operator tooling.
2. **Scoped service tokens for machine callers** — opaque, hashed-at-rest tokens
   with an explicit scope list (`decision:submit`, `receipt:read`,
   `policy:read`, `policy:write`) and a `tenant_id`.

Authorization is enforced at the boundary and again at the store. The principal
determines the tenant and the maximum trust label a request may assert; a payload
claiming a higher trust level is rejected, not honoured. Every request is
attributed to a principal in the receipt.

## Alternatives

1. **mTLS only.** Strong for machine-to-machine, awkward for browsers and human
   reviewers; would still need a principal→tenant mapping.
2. **API-key-only.** Simple, but no standard rotation, expiry or claims, and no
   clean path to human SSO.
3. **JWT for everything (including machines).** Uniform, but long-lived service
   JWTs are easy to leak and hard to scope; opaque, revocable tokens are safer
   for machine callers.
4. **Network-trust only (bind to a private network).** Rejected: it is the
   current limitation, not a solution; it gives no identity and no audit trail.

## Consequences

- **Positive:** least privilege, per-tenant isolation, auditable actor identity,
  and trust labels that the attacker cannot set.
- **Negative:** new key/secret lifecycle and rotation duties; a test issuer must
  be run and labelled; local development needs a way to bypass auth **only** in an
  explicitly labelled dev mode that never ships enabled.
- **Neutral:** the legacy unauthenticated localhost contract stays available as
  the preserved legacy adapter, on localhost only.
- **Blocked:** no production IdP; M2 is verified against a local test issuer and
  labelled accordingly.
