# Product

## Register

product

## What this is

AegisGraph is a **policy-enforcement, provenance, evaluation and observability
platform for agentic systems**. It sits on the path between an agent and the
tools that agent wants to use. For each proposed action it answers one question
with one of four verbs — `allow`, `block`, `escalate`, `rewrite` — and records an
auditable receipt that binds the decision to the exact action it was made about.

It does not execute tools and it does not call models. Enforcement is the
integrator's responsibility, and the receipt tells the integrator exactly which
action may execute.

The platform is the successor to the IndabaX/SENTINEL challenge defence. The
legacy implementation and its measured evidence are preserved as a versioned
benchmark adapter and historical evidence package (see
[`docs/legacy/sentinel-challenge.md`](docs/legacy/sentinel-challenge.md)).

## Users and personas

### Agent-platform engineer

Builds or operates agents that call tools with real side effects. Needs a
decision point they can drop into their execution loop, a stable API, latency
budgets they can reason about, and receipts they can store. Cares about
throughput, determinism, versioned policy and clear failure behaviour.

### Security reviewer

Owns the question "what is this agent actually allowed to do, and can we prove
it?". Needs the threat model, the reason codes behind every decision, the
trust/provenance of every input, and the ability to replay an incident from
receipts.

### ML/research engineer

Evaluates defences and needs reproducible, honest measurement. Needs a native
evaluation schema, adapters for external benchmarks, per-attack reachability
controls, component ablations, and results that separate synthetic from real
model runs.

### Audit / compliance reviewer

Reads the record after the fact. Needs an immutable, timestamped, tamper-evident
chain from proposal → policy version → decision → enforcement, with the exact
action digest and the retention story.

## Jobs to be done

- Intercept a proposed action and return a decision before anything executes.
- Explain the decision with reason codes and the evidence it used.
- Bind the decision to the exact action so a mismatched action cannot execute.
- Escalate to a human and resume the decision when the escalation resolves.
- Rewrite an unsafe action into a safe equivalent, then re-validate it.
- Store auditable receipts and expose them for review.
- Version policy and attribute every decision to the policy version used.
- Evaluate the defence reproducibly, including against legacy benchmarks.
- Observe decisions, latency and enforcement outcomes in production.

## Product purpose

Make the decision point between an agent and its tools **inspectable, auditable
and reproducible**. A reviewer should be able to follow the evidence chain —
proposed action → normalized facts and provenance → policy version → verdict and
reasons → bound action digest → enforcement outcome — instead of trusting an
aggregate score or an opaque security claim.

## Design principles

1. **Evidence before summary.** Show the observation, the decision and its
   reasons before any aggregate score.
2. **Keep the causal chain visible.** Proposal → decision → bound action →
   enforcement outcome, in order and with stable identifiers.
3. **Always label provenance and trust.** Never imply untrusted text became
   trusted, and never let a label decide a verdict.
4. **Fail closed and say so.** Incomplete, failed, truncated, escalated and
   synthetic-only cases are shown as such, not smoothed over.
5. **Honest status vocabulary.** Every capability is `implemented`, `partial` or
   `proposed`; every measurement is `verified`, `pending` or `blocked`.
6. **Boring, deterministic core.** No learned components in the decision path;
   the same input yields the same verdict, reasons and digests.
7. **Accessible to a focused reviewer.** WCAG 2.2 AA, keyboard-first, detail on
   demand, and no meaning carried by colour alone.

## Product surfaces

- **Decision API.** A versioned HTTP contract returning a bounded decision and
  receipt for one proposed action. *(implemented, legacy v1 boundary)*
- **Inspector UI.** A local, read-only surface to load traces and scorecards and
  follow the decision chain. *(implemented for legacy artifacts; native platform
  surfaces proposed)*
- **Receipt store.** Durable, queryable audit receipts. *(proposed)*
- **Authority service.** Authentication and scoped tokens for the API.
  *(proposed)*
- **Telemetry.** Traces, metrics and dashboards for decisions and enforcement.
  *(proposed)*
- **Evaluation harness.** Native schema plus the legacy SENTINEL adapter.
  *(legacy adapter implemented; native harness proposed)*

Per-component maturity, with code anchors, is in
[`docs/architecture/system-context.md`](docs/architecture/system-context.md).

## Anti-references

- Flashy "hacker" styling, neon-on-black clichés, or decorative threat
  animations.
- Opaque scores without the observations and decision reasons behind them.
- Presenting development `mock` results as real-model results.
- Describing a `proposed` capability as if it already exists.
- Colour as the only way to distinguish allow, block, escalate, error or attack
  outcome.
- A decision that depends on a scenario ID, filename, label or expected result.
- "Trust me" security claims without a replayable artifact and a command.
- Deleting or rewriting legacy evidence to make the new platform look cleaner.

## Accessibility and inclusion

Target **WCAG 2.2 AA**. Support keyboard navigation, visible focus, readable
text, reduced motion, and state labels/icons in addition to colour. Use
accessible names for interactive controls, announce async status changes, and
keep the decision timeline and receipt details understandable to screen readers.
Minimum 44px touch targets on narrow screens. No meaning is conveyed by colour
alone.
