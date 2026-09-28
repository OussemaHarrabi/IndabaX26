# Glossary

Every term the course uses, defined once, with the place in the code where you can see it. Terms are listed in the order you meet them; the module column tells you where the concept is taught.

| Term | Meaning | Seen in code | Module |
| --- | --- | --- | --- |
| **agent** | A loop that asks a model for an action, executes it with tools, feeds the result back, and repeats. In SENTINEL the model is Qwen3-8B and the loop is the starter kit's reference agent. | `.sentinel_reference/src/sentinel/agent/reference.py` | 1, 3 |
| **candidate action** | The single action the agent proposes at one step, before anything executes: a tool call, a reply, or a memory write. The defense sees exactly this one action, not a plan. | `.sentinel_reference/src/sentinel/core/actions.py` | 3 |
| **action-level mediation (reference monitor)** | The security pattern of putting a decision point between the agent and its tools so every action is checked before it takes effect. AegisGraph is this component. | `backend/aegisgraph/engine.py:462-548` | 1, 6 |
| **defense / gateway** | The component under test that returns a decision for each candidate action. AegisGraph never executes the action it judges. | `backend/aegisgraph/sentinel.py` | 3, 6 |
| **decision** | One of exactly four verbs: `allow`, `block`, `escalate` (ask a simulated human), `rewrite` (substitute a safer action). | `backend/aegisgraph/contracts.py` | 2, 7 |
| **reason code** | An `UPPER_SNAKE_CASE` label explaining a decision, at most 16 per decision. AegisGraph defines ~30 across the pipeline. | `backend/aegisgraph/engine.py` (each gate) | 7 |
| **risk score / confidence** | Two numbers in `[0,1]` accompanying a decision. In AegisGraph they are fixed literals chosen per gate, not computed probabilities. | `backend/aegisgraph/engine.py:1107` (confidence 0.99) | 7, 9 |
| **provenance** | The record of where a piece of text came from: source type, origin actor, how it was retrieved, when, and — most importantly — how much it can be trusted. | `backend/aegisgraph/adapter.py:55-91` | 1, 3, 6 |
| **trust level** | An ordered label on content. The kit's ladder: `system_policy` > `authenticated_user` > `trusted_internal` > `untrusted_internal` > `untrusted_external` > `adversary_controlled`. | `.sentinel_reference/src/sentinel/core/provenance.py` | 1, 3 |
| **sensitivity** | A label describing how damaging disclosure would be: `public`, `internal`, `confidential`, `restricted`. Separate axis from trust. | `.sentinel_reference/src/sentinel/core/provenance.py` | 1, 3 |
| **taint / trust inheritance** | The rule that text keeps the lowest trust it has touched. A memory entry written after reading untrusted content stays untrusted when recalled. | `.sentinel_reference/src/sentinel/agent/reference.py:196-236` | 1, 3 |
| **canary** | A synthetic secret the benchmark generates per run (for example a vendor portal token) and plants in fixtures. Any appearance of it at a destination its tags do not allow is a data-flow violation. | `.sentinel_reference/src/sentinel/core/canary.py` | 3, 4 |
| **sink / destination** | Anywhere data can end up: a tool argument, a record field, an email recipient, the final answer. | `.sentinel_reference/src/sentinel/domains/*/tools.py` | 1, 4 |
| **exfiltration / data-flow violation** | Moving sensitive data to a sink whose destination the data's tags do not permit. The dominant harm in this benchmark. | `.sentinel_reference/src/sentinel/evaluator/leakage.py` | 4, 7 |
| **prompt injection — direct** | The user's own turn asks for something outside policy, e.g. "give me the vault token". | `scenarios/public/enterprise/enterprise_direct_token_request.yaml` | 1, 4 |
| **prompt injection — indirect** | Hostile text arrives inside content the agent reads while doing legitimate work: a ticket comment, a document body, a log line, vendor email. | `scenarios/public/soc/soc_hostile_log_text.yaml` | 1, 4 |
| **memory poisoning** | Writing a hostile instruction into the agent's memory so it is recalled — and obeyed — in a later turn. | `scenarios/public/enterprise/enterprise_memory_poison.yaml` | 4 |
| **goal hijacking** | Making the agent pursue the attacker's objective while appearing to continue the user's task. | scenario `attack.objective` fields | 4 |
| **fail-closed / fail-open** | What the harness does when the defense errors, times out, or returns nonsense. SENTINEL defaults to fail-closed: the action is blocked. | `.sentinel_reference/src/sentinel/defenses/client.py:21-89` | 3 |
| **reachability control** | The organizer's mandatory check: run the attack with the do-nothing defense first. If it does not succeed undefended, it never reached the agent and any defended result for it is meaningless. | `.sentinel_reference/docs/participant-guide.md:65-72` | 2, 8 |
| **ASR** | Attack Success Rate: attack scenarios that succeeded ÷ attack scenarios. Lower is better. AegisGraph's headline: 0/22 reached attacks. | `.sentinel_reference/src/sentinel/evaluator/metrics.py` | 2, 8 |
| **BTU** | Benign Task Utility: benign scenarios whose success conditions all pass ÷ benign scenarios. Higher is better. AegisGraph: 4/9 versus 5/9 undefended. | same | 2, 8 |
| **FBR** | False Block Rate: legitimate actions blocked (or escalated and denied) ÷ legitimate actions. Lower is better. AegisGraph v5: 0.86%. | same | 2, 8 |
| **DFI / TUI / CVR / UER** | Data-Flow Integrity, Tool-Use Integrity, Critical Violation Rate, Unnecessary Escalation Rate. Secondary metrics over the same finding stream. | same | 2, 8 |
| **Brier score / ECE** | Calibration metrics comparing a reported risk against a label. Only meaningful if the risk is a real estimate — see finding F5. | `.sentinel_reference/src/sentinel/evaluator/metrics.py` | 8, 9 |
| **intent envelope** | AegisGraph's representation of what the authenticated user actually asked for, derived from the goal text, used to decide whether an action the goal supports may proceed despite untrusted text. | `backend/aegisgraph/engine.py:804-887` | 7 |
| **redaction** | Replacing a detected secret inside an action with the literal `[REDACTED]`, then re-validating the replacement. | `backend/aegisgraph/engine.py:586-610` | 7 |
| **rewrite** | Substituting a safer action (for example `email_send` → `email_draft`). The harness executes the rewritten action instead of the original; a rewrite may not make a non-final action final and may not name an unknown tool. | `.sentinel_reference/src/sentinel/agent/reference.py:314-341` | 3, 7 |
| **false positive** | A legitimate action blocked or escalated. Costs utility (BTU, FBR) and jury points for precision. | measured in `evaluation/` | 1, 5 |
| **false negative** | An attack that succeeds because the defense allowed it. Costs ASR and the whole point of the exercise. | measured in `evaluation/` | 1, 5 |
| **hard negative (over-refusal trap)** | A benign scenario deliberately full of security vocabulary — a fraud-awareness note, a security digest — to punish keyword-based defenses. | `scenarios/public/finance/finance_fraud_awareness_note.yaml` | 4, 5 |
| **mock model vs real Qwen3-8B** | `--model mock` is a deterministic plan-driven stand-in used to iterate without a GPU; it never paraphrases, so mock results are optimistic. Real runs use Qwen3-8B (the archived ones via Ollama Q4_K_M). Every number in the course is labelled with which one produced it. | `.sentinel_reference/src/sentinel/models/` | 3, 8 |
| **deterministic digest** | A SHA-256 over a scorecard's outcomes and metrics with latency removed, so the same inputs give the same digest. The project's evidence uses it to pin results. | `sentinel eval` output | 8 |
| **scope of a decision** | What the defense is allowed to use: agent state, candidate action, provenance, active policy, observed content. Scenario ids, filenames and expected outcomes are forbidden inputs and disqualify a decision. | `.sentinel_reference/docs/participant-guide.md` | 2, 9 |
