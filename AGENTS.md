# AegisGraph agent operating guide

This file coordinates future coding/research/evaluation agents working on AegisGraph. The human owner is working solo and may use multiple subagents plus an orchestrator; agents should be autonomous inside an explicitly assigned bounded task, but must not invent external authority or fabricate evidence.

## Project north star

Build a reproducible, honest SENTINEL v1 decision gateway that protects the fixed reference Qwen3-8B agent before simulated tool execution, preserves benign utility, and produces evidence a reviewer can inspect. The gateway evaluates inert proposed actions; it does not invoke tools, model APIs, or real-world systems. Scope is the synthetic SENTINEL environment, not universal cyber protection.

## Non-negotiable challenge constraints

- Keep benchmark pinned at the commit in `benchmark.lock`; use the pinned starter kit as operational count.
- The reference agent's model identity, system prompt, and tools stay fixed. Allowed runtime/hardware configuration changes must be recorded. Never add safety instructions to that agent.
- Before using an attack result, run the same scenario with `allow_all` and require per-scenario `attack_success=True`; otherwise the attack was not shown to reach the vulnerability.
- No scenario ID, filename, organizer outcome, hidden label, or expected result may influence a defense decision. Use state/action/provenance/policy/evidence only.
- `sentinel eval` metrics are self-test evidence, not official points. Clearly label each `mock` or Qwen result. Never report mock as Qwen.
- Attack only the local challenge simulator. No organizer/sponsor scanning, real target access, credential theft, sandbox escape, persistence, or denial of service.
- Do not expose the local HTTP service directly to an untrusted network; it has no authentication by default.
- Preserve worktree/user changes, do not reset or overwrite artifacts, do not commit secrets, and do not push/create external resources unless explicitly authorized.

## Role boundaries and ownership

One agent is the **orchestrator** for each milestone. It owns the single integrated plan, allocates tasks, tracks dependencies, arbitrates shared-file conflicts, runs integration gates, and reports evidence/status to the user. It should not ask each subagent to review everything; request focused checks at milestone boundaries.

Suggested independently bounded roles:

| Role | Owns | Must not |
| --- | --- | --- |
| Contracts/API implementer | Wire models, adapter, endpoint and compatibility tests | Change policy semantics or benchmark config without coordination |
| Policy implementer | Decision kernel, rules and focused regression tests | Hard-code scenario IDs/outcomes or change contracts silently |
| Evaluation engineer | Reproducible commands, scorecard parsing, artifacts and reachability checks | Edit the defense to improve its own measurements; relabel mock data |
| Threat/research analyst | Organizer docs, threat taxonomy and trace-backed findings | Present web/source claims without a source or inference label |
| Documentation/report writer | Architecture/runbooks/report and evidence mapping | Invent completion status, metrics, test results or team eligibility |
| Adversarial reviewer | One assigned boundary or attack family; returns concrete repro/tests | Make unrequested code edits or broad style reviews during implementation |
| Integration/test owner | Clean-checkout, endpoint, unit/security/contract gates | Treat one passing test as end-to-end proof |

Multiple agents may work in parallel only on disjoint files or read-only analysis. For overlapping modules, designate a single writer and have other agents return proposed findings/patches without editing. Never delegate reading project instructions (`AGENTS.md`, applicable skills or user-provided requirements); the orchestrator reads them and passes the necessary requirements to agents.

## Task contract (required for every delegation)

Each task request includes:

1. **Outcome:** one bounded artifact or question and why it matters.
2. **Scope:** exact files/components allowed; explicit exclusions.
3. **Inputs of record:** commits, paths, docs, runtime/model assumptions.
4. **Constraints:** challenge rules above, user preferences, interface compatibility, and whether this is read-only or a code-writing task.
5. **Acceptance criteria:** observable tests/evidence and how to report failure.
6. **Coordination:** single-writer designation, dependencies, expected commit/no commit, and how to hand back.

Agents should begin by checking repository state and local guidance, then work only within the assigned scope. On discovering a blocker or consequential ambiguity, report the precise evidence and a safe fallback; do not silently widen scope. Before editing shared files, announce ownership/coordination to the orchestrator.

## Orchestrator lifecycle

1. **Intake:** normalize the objective, read `AGENTS.md`, README, benchmark lock, relevant organizer material, and current Git status. Capture acceptance criteria and prohibited actions.
2. **Front-load decisions:** request only decisions that truly block safe progress (registered team eligibility, external credentials/runtime access, substantive threat-model tradeoff). Give the owner a single consolidated list. In parallel, continue reversible local work that does not depend on those answers.
3. **Plan/dependency graph:** split into architecture/contracts → policy → integration → evaluation → observability/demo/report. Mark blockers and independent work; use one writer per shared component.
4. **Dispatch:** use the task contract; assign roles based on files and artifacts. Ask evaluation/review agents for read-only findings unless they are the designated writer.
5. **Integrate:** verify actual shared-worktree diff, merge/commit only scoped changes, run focused then milestone-level checks. Re-run evaluation when semantics change; preserve old results as history, never overwrite.
6. **Evidence ledger:** track claim → source/artifact → commit/config → status. Use `verified`, `pending`, `blocked` or `not applicable`, not vague “done.”
7. **Milestone updates:** after a substantial milestone, tell the owner what changed, checks run and remaining blockers. Avoid repeated broad review loops during active implementation; review once per coherent milestone and again before release.
8. **Release gate:** use `SUBMISSION_CHECKLIST.md`; independently verify every “complete” claim. Ask for missing user authority/eligibility clarification; do not guess.

## Quality gate for code-producing tasks

- Write/identify a failing regression test before changing behavior where feasible; demonstrate red then green for behavioral fixes.
- Test boundaries: malformed/oversized input, unknown tools, invalid provenance IDs, untrusted content, confirmation/consequential actions, egress destinations/cc/bcc, rewrites, timeouts and fail-closed behavior.
- Run focused tests, full test suite, Ruff and mypy after implementation. Use contract tests against the pinned organizer interface. Preserve full command/output and commit hash.
- For policy changes, rerun matched public evaluation on the pinned suite, including allow-all reachability. Analyze benign regressions as carefully as attack outcomes.
- For release, validate the manifest and live HTTP contract with organizer validator; build the Docker image if an engine is available and record when unavailable. Do not expose secrets or run with privileged container settings.
- Read diffs in the changed scope at milestone boundary; no unrelated cleanup bundled into a security behavior change.

## Prompt templates

### Implementation agent

> Implement **[one outcome]** in **[allowed files]**. Inputs of record: **[paths/commits/contracts]**. Do not touch **[exclusions]**. Preserve SENTINEL compatibility and all constraints in `AGENTS.md`; do not use scenario IDs or expected outcomes. Start with a focused failing test, implement the smallest cohesive change, run **[commands]**, and report changed files, test output, residual risks, and commit hash. If blocked, stop before widening scope and return evidence/options.

### Research agent

> Read-only research: answer **[specific question]** using **[pinned source/doc/version]**. Do not edit files or infer current project behavior without code evidence. Return concise findings with exact source path/section or URL+date, separate fact from inference, note discrepancies/uncertainty, and explain impact on our design. Do not claim external verification if you could not access the source.

### Evaluation agent

> Run or design **[exact benchmark/test]** against commit **[hash]**, benchmark **[hash]**, model/runtime **[identity/config]**. Do not edit policy or tests. First verify every attack being interpreted passes the same-config `allow_all` reachability gate (`attack_success=True`). Save immutable raw outputs and metadata; report failed/missing scenarios, command, environment, metrics/digest, and any artifact path. Separate mock from real model and report failures without filtering.

### Adversarial review agent

> Read-only review of **[bounded file/flow/attack family]** for **[specific failure modes]** at commit **[hash]**. Do not make changes. Return only reproducible findings with severity, exact code location, threat preconditions, concrete exploit/test, impact, and recommended regression criterion. Explicitly say if no issue was found in scope; do not generalize beyond reviewed scope.

### Documentation agent

> Update only **[named docs]** for milestone **[name]**, grounded in **[source docs/artifacts]**. Do not alter code or state unevidenced results. Mark pending work explicitly, preserve exact commands/versions, and return doc links, validation performed, and commit hash.

## Agent handoff format

Every agent returns:

```text
Status: complete | partial | blocked
Scope/files:
Evidence/commands:
Results:
Commit (if requested):
Known risks or open questions:
Next dependency:
```

The orchestrator owns user communication and must distinguish agent findings from independently verified facts. A successful subtask is not a successful submission; final readiness is determined by the complete checklist, real artifacts, organizer rules and explicit user decisions.
