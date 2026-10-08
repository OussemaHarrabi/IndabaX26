# ADR-0006 — Enforcement binding: decisions are bound to exact action digests

- **Status:** proposed
- **Date:** 2026-10-08
- **Deciders:** architecture lead (proposal), security reviewer, orchestrator
- **Milestone:** M1 (contracts + enforcement)

## Context

The gateway evaluates an inert proposal and returns a decision, but it never
executes anything (`backend/aegisgraph/app.py:85`,
`backend/aegisgraph/contracts.py:112`). Execution is the integrator's job. That
creates a confused-deputy risk: an attacker (or a bug) could take an `allow`
decision made about action A and apply it to action B, or mutate the action
between the decision and the tool call.

The contract already computes a canonical digest (`action_digest`,
`backend/aegisgraph/contracts.py:249`) and an exact execution-semantic digest
(`exact_action_digest`, `contracts.py:265`), and `DecisionReceipt` binds both to
the decision (`contracts.py:236`). Escalation already resumes only when the
caller supplies a matching confirmation digest for the exact action
(`engine.py:514`).

## Decision

Make digest binding the enforcement contract:

1. Every decision response and stored receipt carries the **exact** action digest
   (`execution_digest`) in addition to the protocol identity digest.
2. An enforcement adapter must recompute the digest of the concrete action it is
   about to execute and **refuse** if it does not match the receipt.
3. Escalation resumes only on a matching confirmation digest; a rewrite must be
   re-validated by the same checks as a direct action before it may execute
   (`engine.py:397`–`engine.py:458`).
4. If binding cannot be verified, execution is refused — fail closed.
5. The wire response gains the receipt fields in M1; until then this is a
   contract commitment, not an implemented control.

## Alternatives

1. **Trust the caller to keep the action unchanged.** Rejected: that is exactly
   the confused deputy.
2. **Bind by content hash only (ignore execution semantics).** Rejected: two
   actions can share a protocol digest while differing in execution-semantic
   fields; the exact digest exists for this reason.
3. **Bind by a server-side pointer to the stored action.** Strong, but requires
   the server to retain every candidate action and the caller to reference it;
   heavier than a digest and not necessary for the integrity property.
4. **Re-decide immediately before execution.** Adds latency and doubles the
   policy surface; the digest check is cheaper and sufficient to detect
   substitution.

## Consequences

- **Positive:** decision substitution and post-decision mutation become
  detectable; receipts become sufficient to prove what was authorized; escalation
  and rewrite stay sound end-to-end.
- **Negative:** the integrator must implement the digest check correctly, and the
  exact digest is deliberately strict (spacing, numeric form and `final` all
  matter), so callers must pass the action through unchanged.
- **Neutral:** the legacy wire contract is unchanged; receipt fields are additive
  and versioned.
- **Blocked:** the enforcement adapter and SDK land in M1; until then the platform is
  decision-only and this ADR records the commitment, not a working guarantee.
