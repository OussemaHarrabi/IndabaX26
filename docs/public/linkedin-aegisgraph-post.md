# From a missed hackathon deadline to AegisGraph

I learned about the IndabaX Tunisia agent-security challenge in class, roughly five hours before submissions closed. I decided to try it solo, but I did not submit: the idea was promising, yet the project was not complete enough.

After the deadline, one of the organizers told me the approach was very cool and unique. That feedback stayed with me. Instead of leaving the prototype behind, I used it to explore a question I wanted to understand properly: what should stand between an AI agent's proposal and a real tool action?

That became **AegisGraph**, a pre-execution security gateway for tool-using LLM agents. It checks provenance, authorization, confirmation requirements, sensitive-data flow and the exact action digest, then returns `allow`, `block`, `escalate` or `rewrite`. The executor verifies that the action being executed is the one that was authorized.

On a pinned public Qwen3-8B suite, the allow-all control succeeded on 22 attacks. AegisGraph v5 reduced those same reached attacks from **22/22 successful to 0/22**, while retaining **4/5** benign tasks that had succeeded under allow-all. The paired reduction remained significant after Holm correction (`p = 1.91 × 10⁻⁶`).

I also turned the idea into a reproducible research and engineering project: **1,452 GPU episodes**, **745 automated tests**, **96.83% backend coverage**, public evidence artifacts and a seven-page LaTeX technical paper.

The main lesson: security claims need controls, reachable attacks, utility measurements and enforcement evidence, not only a good demo.

Thank you to the IndabaX organizers for introducing me to this direction. I hope to continue working on reliable AI agents, AI security and evaluation through a 2027 research or engineering internship.

GitHub: https://github.com/OussemaHarrabi/IndabaX26

Paper: https://github.com/OussemaHarrabi/IndabaX26/blob/main/output/pdf/AegisGraph_Technical_Report_2026.pdf

#AISecurity #LLMSecurity #AgenticAI #AIResearch #AIEngineering

## Suggested images (not part of the caption)

1. Architecture figure.
2. Security-results graphic showing 22/22 to 0/22 (`docs/paper/figures/aegisgraph-security-ladder.png`).
3. First page of the paper.
