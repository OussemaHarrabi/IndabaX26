# Five hours too late for the hackathon. Long enough to build AegisGraph.

I learned about the IndabaX Tunisia agent-security challenge in class, roughly five hours before the deadline.

I decided to try it solo. I built a promising first solution, and one of the organizers told me the approach was very cool and unique. But when the deadline arrived, I did not submit it. The idea was there; the complete, coherent project was not.

I did not want to turn an unfinished prototype into a rushed submission. The topic stayed with me: if an AI agent can call tools, send messages, read documents, or change systems, what should stand between the model's proposal and the real action?

That question became **AegisGraph**, an independent research and engineering project: a pre-execution security gateway for tool-using LLM agents.

The agent proposes an action. AegisGraph checks provenance, authorization, confirmation requirements, sensitive-data flow, and the exact action digest. It then returns one explicit decision: allow, block, escalate, or rewrite. The executor checks that the action being executed is the same action that was authorized.

The most important result is security effectiveness, not just how much code I wrote.

On a pinned public suite with Qwen3-8B, the allow-all control succeeded on 22 attacks. With AegisGraph v5, those same reached attacks went from **22/22 successful to 0/22**. The paired result remained significant after Holm correction (`p = 1.91e-06`). The final version retained **4 of the 5 benign tasks** that already succeeded under allow-all, recorded a decision-level false-block rate of **1/116**, and added **9.284 ms p95** policy latency.

I also kept the intermediate checkpoints. The built-in provenance baseline allowed 9/22 reached attacks, AegisGraph v1 allowed 10/22, and both v3 and v5 reduced that to 0/22. That version history helped me see which changes actually altered the security outcome.

Beyond the benchmark, I built and tested the engineering boundary around it:

- action-bound receipts and executor-side digest verification;
- rejection of mutated actions, mismatched grants, conflicting replay, excessive trust claims, and cross-tenant access;
- an authenticated FastAPI service with PostgreSQL, OpenTelemetry, Prometheus and Grafana;
- 1,452 Qwen3-8B GPU episodes across the public campaign and four mechanism ablations;
- 3,792 gateway requests, 2,985 action-execution digest correspondences, and zero episode-level runtime errors;
- 745 automated tests and 96.83% backend coverage;
- a reproducible LaTeX research paper, public traces, scorecards, manifests and statistical analysis.

The biggest lesson was that an agent-security claim needs more than a diagram or a demo. It needs an allow-all control, reachable attacks, paired comparisons, utility costs, failure analysis, and evidence that the executor enforces the decision.

Thank you to the IndabaX organizers for opening a different direction this year. I had expected a more familiar deep-learning/model-building challenge. The shift toward AI-agent security pushed me into a field I now want to explore much more deeply, including through 2027 research and engineering internships in reliable AI agents, AI security, and evaluation.

GitHub: https://github.com/OussemaHarrabi/IndabaX26

Paper: https://github.com/OussemaHarrabi/IndabaX26/blob/main/output/pdf/AegisGraph_Technical_Report_2026.pdf

#AISecurity #LLMSecurity #AgenticAI #AIResearch #AIEngineering #ResponsibleAI

## Suggested carousel order

1. Architecture figure.
2. Security-results graphic showing 22/22 to 0/22 (`docs/paper/figures/aegisgraph-security-ladder.png`).
3. Evaluation pipeline.
4. First page of the paper.
