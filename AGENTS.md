# AegisGraph agent operating guide

This file coordinates every coding, research and evaluation agent that works on
AegisGraph. The human owner works solo with one orchestrator plus multiple
subagents. Agents are autonomous **inside an explicitly assigned bounded task**,
but must not invent external authority or fabricate evidence.

The project is transitioning from the IndabaX/SENTINEL challenge submission into
an independent industrial–research platform. The legacy SENTINEL implementation
and its measured evidence stay in place as a versioned benchmark adapter and
historical evidence package; they are never erased, overwritten or
retroactively reinterpreted. See the labelled **Legacy SENTINEL constraints**
section below for the rules that still bind us.

## North star

Build AegisGraph into a **policy-enforcement, provenance, evaluation and
observability platform for agentic systems**:

- Intercept a proposed agent action **before** execution.
- Apply **versioned policy** to bound, normalized facts.
- Bind each decision to the **exact** action it authorizes or rejects.
- Support **escalation and rewrite** as first-class decision verbs.
- Record **auditable receipts** for every decision.
- Provide **reproducible evaluation** that a third party can re-run.

The gateway evaluates inert action proposals. It does not execute tools, call
model APIs, or mutate real-world systems by itself: an integrator must enforce
each decision and bind it to the exact candidate action.

## Non-negotiable constraints

1. **Evidence over assertion.** Every claim of behaviour or performance is
   `implemented` (code exists and was exercised) or `verified` (an artifact and
   command reproduce it), or it is `proposed`. Nothing in between. Never claim a
   future feature exists.
2. **Label provenance of every number.** Every measurement is labelled with its
   model/runtime, the exact command, the artifact digest and the source commit.
   Never present a synthetic `mock` result as a real-model result.
3. **Never let labels decide.** No scenario ID, filename, organizer outcome,
   hidden label, tenant name, expected result or test name may influence a
   policy decision. Decisions use state, action, provenance, policy and evidence
   only.
4. **Fail closed.** Any request that cannot be safely normalized, parsed or
   evaluated becomes `block`; a failure must never become an `allow`.
5. **Bind decisions to exact actions.** A receipt carries a digest of the exact
   action evaluated. An enforcement layer must refuse to execute an action whose
   digest does not match the receipt.
6. **Preserve legacy provenance.** The SENTINEL source commits, scorecards,
   traces and their SHA-256 digests are evidence of record. Do not edit them, do
   not recompute them under new code, and do not delete the legacy paths.
7. **Least privilege.** Bound every input; do not expose the local HTTP service
   directly to an untrusted network; do not commit secrets, credentials, local
   databases, caches or transient outputs.
8. **Do not invent authority.** Ask the human owner for decisions that need
   external authority (credentials, deployment targets, eligibility,
   publication). Continue all reversible local work that does not depend on the
   answer.

## Role boundaries and ownership

One agent is the **orchestrator** for each milestone. It owns the single
integrated plan, allocates tasks, tracks dependencies, arbitrates shared-file
conflicts, runs integration gates, and reports evidence and status to the owner.
It does not ask each subagent to review everything; it requests focused checks at
milestone boundaries.

| Role | Owns | Must not |
| --- | --- | --- |
| Orchestrator | Integrated plan, milestone gates, shared-contract arbitration, evidence ledger, owner communication | Delegate understanding of `AGENTS.md`/user requirements to a subagent |
| Contracts/API implementer | Versioned wire + canonical models, endpoint and compatibility tests | Change policy semantics or legacy contracts without coordination |
| Policy implementer | Decision kernel, rules and focused regression tests | Hard-code scenario IDs, tenant IDs or expected outcomes; change contracts silently |
| Persistence engineer | Schema, migrations, repository layer, receipt store | Own policy semantics or shared contracts |
| Platform/telemetry engineer | OpenTelemetry, metrics, dashboards, SLOs | Change decision semantics to make telemetry simpler |
| Evaluation engineer | Reproducible commands, native evaluation schema, legacy adapter, artifacts | Edit the defence to improve its own measurements; relabel mock data |
| Threat/research analyst | Threat model, taxonomy and trace-backed findings | Present web/source claims without a source or inference label |
| Documentation/report writer | Architecture docs, runbooks, evidence map | Invent completion status, metrics, test results or eligibility |
| Adversarial reviewer | One assigned boundary or attack family; concrete repro/tests | Make unrequested code edits during implementation |
| Integration/test owner | Clean-checkout, endpoint, unit/security/contract gates | Treat one passing test as end-to-end proof |

Multiple agents work in parallel only on **disjoint files** or read-only
analysis. For overlapping modules, designate a single writer; other agents
return proposed findings or patches without editing. The single-writer map for
the platform milestones is in
[`docs/architecture/roadmap.md`](docs/architecture/roadmap.md).

## Task contract (required for every delegation)

Each task request includes:

1. **Outcome:** one bounded artifact or question and why it matters.
2. **Scope:** exact files/components allowed; explicit exclusions.
3. **Inputs of record:** commits, paths, docs, runtime/model assumptions.
4. **Constraints:** the rules above, user preferences, interface compatibility,
   and whether this is read-only or a code-writing task.
5. **Acceptance criteria:** observable tests/evidence and how to report failure.
6. **Coordination:** single-writer designation, dependencies, expected
   commit/no commit, and how to hand back.

Agents begin by checking repository state and local guidance, then work only
within the assigned scope. On discovering a blocker or consequential ambiguity,
report the precise evidence and a safe fallback; do not silently widen scope.
Before editing a file another agent may own, message that agent or the
orchestrator. Never commit secrets, and never push or merge: the orchestrator
reviews the diff and integrates.

## Orchestrator lifecycle

1. **Intake:** normalize the objective, read `AGENTS.md`, `PRODUCT.md`, the
   README, the benchmark lock and current Git status. Capture acceptance
   criteria and prohibited actions.
2. **Front-load decisions:** request only decisions that truly block safe
   progress (external credentials, deployment targets, publication). Give the
   owner one consolidated list; continue reversible local work in parallel.
3. **Plan/dependency graph:** split into contracts → policy → persistence →
   telemetry → evaluation → integration → release. Mark blockers and independent
   work; one writer per shared component.
4. **Dispatch:** use the task contract; assign roles by files and artifacts. Ask
   reviewers for read-only findings unless they are the designated writer.
5. **Integrate:** verify the actual worktree diff, merge only scoped changes, run
   focused then milestone-level checks. Re-run evaluation when semantics change;
   preserve old results as history, never overwrite.
6. **Evidence ledger:** maintain `docs/evidence/ledger.md` as
   claim → type → status → artifact → digest → command → commit → limitation.
   Use `verified`, `pending`, `blocked` or `not applicable`, never vague "done".
7. **Milestone updates:** after a substantial milestone, tell the owner what
   changed, which checks ran, and which blockers remain. Avoid repeated broad
   review loops during active implementation; review once per coherent milestone
   and again before release.
8. **Release gate:** independently verify every "complete" claim from the ledger.
   Ask for missing authority; do not guess.

## Quality gate for code-producing tasks

- Write or identify a failing regression test before changing behaviour where
  feasible; demonstrate red then green for behavioural fixes.
- Test boundaries: malformed/oversized input, unknown tools, invalid provenance
  IDs, untrusted content, confirmation/consequential actions, egress
  destinations/cc/bcc, rewrites, timeouts and fail-closed behaviour.
- Run focused tests, the full test suite, Ruff and mypy after implementation.
  Preserve the full command/output and commit hash.
- For policy changes, re-run matched evaluation including the allow-all
  reachability control. Analyse benign regressions as carefully as attack
  outcomes.
- Read diffs in the changed scope at the milestone boundary; never bundle
  unrelated cleanup into a security behaviour change.

## Prompt templates

### Implementation agent

> Implement **[one outcome]** in **[allowed files]**. Inputs of record:
> **[paths/commits/contracts]**. Do not touch **[exclusions]**. Preserve the
> constraints in `AGENTS.md`; do not use scenario IDs or expected outcomes.
> Start with a focused failing test, implement the smallest cohesive change, run
> **[commands]**, and report changed files, test output, residual risks and
> commit hash. If blocked, stop before widening scope and return evidence/options.

### Research agent

> Read-only research: answer **[specific question]** using **[pinned
> source/doc/version]**. Do not edit files or infer current project behaviour
> without code evidence. Return concise findings with exact source path/section
> or URL+date, separate fact from inference, note discrepancies/uncertainty, and
> explain the impact on our design. Do not claim external verification you could
> not perform.

### Evaluation agent

> Run or design **[exact benchmark/test]** against commit **[hash]**, benchmark
> **[hash]**, model/runtime **[identity/config]**. Do not edit policy or tests.
> First verify every attack you interpret passes the same-config `allow_all`
> reachability gate (`attack_success=True`). Save immutable raw outputs and
> metadata; report failed/missing scenarios, command, environment, metrics/digest
> and artifact path. Separate mock from real model and report failures without
> filtering.

### Adversarial review agent

> Read-only review of **[bounded file/flow/attack family]** for **[specific
> failure modes]** at commit **[hash]**. Do not make changes. Return only
> reproducible findings with severity, exact code location, threat preconditions,
> concrete exploit/test, impact and recommended regression criterion. State
> explicitly if no issue was found in scope; do not generalise beyond it.

### Documentation agent

> Update only **[named docs]** for milestone **[name]**, grounded in **[source
> docs/artifacts]**. Do not alter code or state unevidenced results. Mark pending
> work explicitly, preserve exact commands/versions, and return doc links,
> validation performed and commit hash.

## Agent handoff format

Every agent returns:

```text
Status: complete | partial | blocked
Branch and worktree:
Starting commit:
Ending commit:
Files changed:
Commands executed:
Tests and results:
Artifacts and hashes:
Known risks/limitations:
Dependency or recommended next action:
```

The orchestrator owns owner communication and must distinguish agent findings
from independently verified facts. A successful subtask is not a finished
platform release.

## Legacy SENTINEL constraints (historical, still binding for legacy paths)

These rules governed the IndabaX/SENTINEL challenge submission. They are kept
verbatim in substance because the legacy defence, its evidence and its benchmark
adapter remain part of this repository and must not be reinterpreted.

- **Pinned benchmark.** Keep the benchmark pinned at the commit recorded in
  [`benchmark.lock`](benchmark.lock); use the pinned starter kit as the
  operational scenario count.
- **Fixed reference agent.** The reference agent's model identity, system prompt
  and tools stay fixed. Allowed runtime/hardware configuration changes must be
  recorded. **Never add safety instructions to that agent.**
- **Reachability control.** Before using an attack result, run the same scenario
  with `allow_all` and require per-scenario `attack_success=True`; otherwise the
  attack was not shown to reach the vulnerability. The gate is implemented in
  [`scripts/validate_attack_reachability.py`](scripts/validate_attack_reachability.py)
  and documented in [`REACHABILITY_GATE.md`](REACHABILITY_GATE.md).
- **No label-driven decisions.** No scenario ID, filename, organizer outcome,
  hidden label or expected result may influence a defence decision.
- **Self-test, not jury score.** `sentinel eval` metrics are self-test evidence,
  not official points. Label each result `mock` or real-model; never report mock
  as Qwen.
- **Everything is synthetic.** Attack only the local challenge simulator; no
  organizer/sponsor scanning, real target access, credential theft, sandbox
  escape, persistence or denial of service. Credential-like strings inside the
  committed traces are canaries, not real credentials.
- **Local service only.** Do not expose the legacy local HTTP service directly to
  an untrusted network; it has no authentication by default.
- **Preserve user work.** Preserve worktree and user changes; do not reset or
  overwrite artifacts; do not commit secrets; do not push or create external
  resources unless explicitly authorized. **No force-push.**

The challenge itself, and every measured result with its digest, is documented in
[`docs/legacy/sentinel-challenge.md`](docs/legacy/sentinel-challenge.md) and
[`docs/legacy/evidence-map.md`](docs/legacy/evidence-map.md).
