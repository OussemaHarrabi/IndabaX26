# ADR-0004 — Evaluation: native schema authoritative, legacy adapter preserved, Inspect AI optional

- **Status:** proposed
- **Date:** 2026-10-08
- **Deciders:** architecture lead (proposal), evaluation engineer, orchestrator
- **Milestone:** M5

## Context

Every measured result this project has today comes from the **pinned external
SENTINEL starter kit** (`benchmark.lock`,
`Skan22/Sentinel_Starter_Kit@dd2e5fe0979d0781a4bfe6d0849cd80cf69ef4a2`), scored
by its evaluator and gated by
`scripts/validate_attack_reachability.py`. Those artifacts are evidence of record
and must not be edited or re-derived. But the platform now needs to evaluate its
**own** surfaces — receipts, policy versions, enforcement binding — which the
starter kit knows nothing about.

The risk is drift: a native harness that quietly disagrees with the legacy
numbers, or a legacy adapter that silently rewrites them.

## Decision

Three layers, with a strict authority rule:

1. **Native evaluation schema is authoritative** for platform claims. It defines
   scenarios, runs, per-case reachability, component ablations and a
   deterministic score digest computed over the run's canonical fields.
2. **Legacy SENTINEL adapter is a versioned, read-only adapter.** It runs the
   pinned suite and reports the legacy metrics, but it may not modify legacy
   artifacts and must reproduce the preserved baseline byte-for-byte. Legacy
   results stay labelled `legacy`.
3. **Inspect AI is an optional, additive integration** for external benchmarks
   (for example AgentDojo), used to test generalization. It never overrides the
   native schema, and its absence must not block a release.

Cross-cutting rules: reachability is mandatory (an attack result is void unless
the same configuration reaches it — see
[`../../../REACHABILITY_GATE.md`](../../../REACHABILITY_GATE.md)); every run records
model/runtime identity and is labelled synthetic or real; digests are computed
with latency excluded where the evaluator defines it so.

## Alternatives

1. **Legacy suite as the only evaluator.** Would block evaluation of receipts,
   policy versions and enforcement, and would tie the platform's progress to an
   external, frozen kit.
2. **Native-only, drop the legacy harness.** Rejected: it would strand the
   historical evidence and make the preserved numbers unverifiable.
3. **Adopt Inspect AI as the primary framework.** Attractive ecosystem, but it is
   an external moving dependency and would make our platform claims depend on a
   third party's schema; kept optional.
4. **Custom scripts per experiment.** Fast to write, impossible to compare
   across time; rejected as the authoritative path.

## Consequences

- **Positive:** the platform can measure itself without touching legacy evidence;
  the legacy numbers stay reproducible and honestly labelled; external
  generalization stays possible without becoming a dependency.
- **Negative:** two schemas to maintain and a real risk of double-reporting the
  same metric under two names — mitigated by a naming rule (`legacy.*` vs
  `native.*`) and a ledger entry per claim.
- **Neutral:** the existing `evaluation/**` artifacts are untouched (add-only).
- **Blocked:** real-model reruns need `ollama` or an authorized API; synthetic
  runs are labelled and cannot substitute for real-model evidence.
