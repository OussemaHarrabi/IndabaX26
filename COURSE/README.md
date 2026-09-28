# AegisGraph, explained from zero

A course about the project in this repository: what it is, what it defends against, how it works, what it measured, and what still needs fixing.

Written for someone who knows machine learning and agents but has never worked in security. Every module starts from the concept, then shows the real implementation, then the pitfall.

---

## The project in ten minutes

**The challenge.** SENTINEL (IndabaX Tunisia) is an *agent-security* challenge. You get a tool-using agent — Qwen3-8B driving a simulated enterprise/SOC/finance environment — and a published library of 40 attack scenarios. Nothing is hidden: the attacks are known, and the challenge is to build a defense that stops them without destroying the agent's ability to do its job. Four verbs are allowed per candidate action: `allow`, `block`, `escalate`, `rewrite`. Judging is by a jury rubric (video & observability 40, technical report 25, creativity 15, engineering & responsible AI 20) — there is no automated score to game.

**The project.** AegisGraph is a deterministic decision gateway. It sits between the agent and the tools, and for each proposed action it decides `allow` / `block` / `escalate` / `rewrite` using provenance (where the text came from), the authenticated user's goal, the active policy, and the content itself. It never executes anything. Code: `backend/aegisgraph/`.

**What it achieved** (independently recomputed during this audit from the raw artifacts in `evaluation/`):

| Measure | Killed by do-nothing defense (allow-all) | With AegisGraph v5 |
| --- | --- | --- |
| Attacks that succeed, among the 22 a real model actually reaches | 22 / 22 | **0 / 22** |
| Attacks that succeed, full suite of 31 | 22 / 31 (0.7097) | 0 / 31 |
| Benign tasks completed | 5 / 9 | 4 / 9 |
| False block rate | 0 | **0.86%** |
| Decision latency p95 | — | **9.3 ms** |

Real Qwen3-8B, temperature 0, seed 0, one run. Everything is labelled: this is a self-test on a published suite, not a jury score, and the kit's own utility gate marks the run `eligible=false` because 4/9 benign utility is below its 0.5 threshold. Four of the five benign failures already occur with no defense installed; the fifth is an `email_send` confirmation mismatch.

**What is not done.** No video, no rendered report PDF, no live organizer-validator run, no verified Docker-engine run, no multi-seed rerun, no AgentDojo generalization, and one real residual weakness (a hostile tool-use prompt can still be paraphrased into a final answer).

**Where the code lives.** The project is on `main` (and on `feature/aegisgraph`, which is the same tree — `main` was fast-forwarded to it). This audit read the project through a read-only worktree while `main` still held only the specification PDF; that worktree is no longer needed, and you can drop it with `git worktree remove .audit-tmp/aegisgraph`.

---

## How to read this course

Two paths:

- **Understand the project (≈2 hours).** 1 → 2 → 3 → 4 → 6 → 7 → 8 → 9. The first four modules are the field and the arena; 6 and 7 are AegisGraph itself; 8 is the evidence; 9 is the audit and the repair list.
- **Learn by doing (≈half a day).** 1 → 2 → 3 → 6 → 7 → 10, then run the labs against the live service.

Read Module 9 last even if you are impatient: it tells you which of the project's claims you can safely repeat, and which parts of the code you should not trust.

| Module | Title | What it answers |
| --- | --- | --- |
| [1](01-agent-security-basics.md) | Agent security basics | What is actually being attacked when an agent is the target? Terms, trust, injection, the utility tradeoff. |
| [2](02-the-challenge.md) | The challenge | What SENTINEL asked for, the defense contract, the jury rubric, the metrics, the rules of engagement. |
| [3](03-the-arena.md) | The arena | Step-by-step mechanics of one scenario: who sees what, when the defense is called, what it may and may not see. |
| [4](04-the-attacks.md) | The attacks | All five attack families and the full 40-scenario table, with three detailed walkthroughs. |
| [5](05-baseline-defenses.md) | The defenses everyone writes first | allow-all, keyword, deny-sensitive, heuristic-risk, built-in provenance — and their measured failure modes. |
| [6](06-aegisgraph-architecture.md) | AegisGraph, part 1 | System shape, wire contract, adapter and provenance resolution, bounds, service surface. |
| [7](07-the-decision-kernel.md) | AegisGraph, part 2 | The decision pipeline gate by gate: rules, intent envelope, redaction, confirmation, reason codes. |
| [8](08-evidence-and-evolution.md) | The evidence | How the defense evolved v1→v5 and how to read the scorecards without fooling yourself. |
| [9](09-audit-findings.md) | Audit findings | 14 findings with severities, an ordered repair plan, and the experiments that would falsify the claims. |
| [10](10-labs.md) | Labs | Run it, attack it, add a rule, measure honestly. |
| — | [Glossary](GLOSSARY.md) | Every term, defined once, with the code anchor where you meet it. |

---

## How to check anything this course claims

| Kind of claim | How to verify it yourself |
| --- | --- |
| A number | Open the artifact in `evaluation/` (scorecards are JSON, one entry per scenario) and recompute. Everything in the course is labelled mock vs real-Qwen. |
| A code behaviour | The anchor after the claim, e.g. `backend/aegisgraph/engine.py:462`, is a real file and line in the project. |
| A harness behaviour | Anchors under `.sentinel_reference/src/sentinel/` — the pinned starter kit. |
| An audit finding | [Module 9](09-audit-findings.md) labels each as measured / code reading / `[INFERENCE]`. |

The dense research notes produced during the audit are kept at `COURSE/notes/01…10-*.md` if you want the raw evidence behind any module.

## One honest paragraph

AegisGraph is a competent, well-evidenced instance of one specific idea: check every action against provenance, policy and the user's actual goal before it executes. It is not a general solution to prompt injection, and its own documentation says so. What makes it worth studying is not that it wins — it is that it measures itself honestly enough that you can see exactly where it would break: paraphrased instructions, translated payloads, encoded payloads, longer multi-turn laundering, and any exfiltration channel that is not an external email recipient. Module 9 turns those into experiments.
