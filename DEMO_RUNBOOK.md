# Demo runbook (target: 7–8 minutes; organizer range: 5–10)

The organizer judges whether the attack genuinely reaches the defense, whether decisions are legible, whether a benign task still succeeds, and whether the defense avoids needless blocking. The present repository is not yet a finished demo: it has a decision API and mock-development evaluation artifacts, but this document does not claim a Qwen run, completed observability UI, or recorded video. Use a live, real-Qwen configuration for the final walkthrough if it passes the gate below; do not use mock in the final demo unless the team explicitly changes its stated no-mock preference and labels the substitution.

## Before recording (must-pass checklist)

1. Freeze AegisGraph commit, starter-kit commit (`dd2e5fe0979d0781a4bfe6d0849cd80cf69ef4a2`), model/runtime, scenario IDs, and outputs.
2. Run each intended attack scenario with `allow_all` under the same Qwen configuration. Confirm and save `attack_success=True` per scenario. If it fails, do not portray the defended run as evidence that the attack was stopped.
3. Run the chosen attack against AegisGraph, save the full trace, and verify the attack fails due to a defense decision, not model non-reachability, transport failure, or scenario termination.
4. Choose a benign scenario whose allow-all and defended task success are both recorded. A defense that blocks all actions is not a successful demo.
5. Start the defense on localhost, check `/healthz`, check one request end-to-end, and ensure its observed decision/reason/next event can be shown. The decision service has no built-in authentication; do not expose it to the public internet.
6. Have raw JSON, replay output, benchmark/model/config metadata, and backup terminal views ready. Hide credentials and private notebook data. Do not stage/edit traces.

## Suggested 7–8 minute narrative

| Time | Show | Narration/evidence |
| --- | --- | --- |
| 0:00–0:40 | Problem and boundary diagram | “AegisGraph sits between the agent's proposed action and tool execution. It evaluates an inert proposal; it never calls tools or the model.” State synthetic simulator scope. |
| 0:40–1:30 | Model + reproducibility metadata | Show exact Qwen model, GPU/runtime configuration, starter commit, AegisGraph commit. State that system prompt/tools are unchanged and no model safety prompt was added. |
| 1:30–3:30 | Attack reachability then defense | Show the chosen scenario run under `allow_all`, with `attack_success=True`. Then replay the defended run, showing candidate action, AegisGraph decision, reason code/evidence, and next tool/simulator outcome. Explain why this is a block/escalation/rewrite. |
| 3:30–5:00 | Benign success | Replay a benign scenario and show the task completes with the action allowed (or safe rewrite) and no unnecessary interruption. |
| 5:00–6:10 | Observability | Follow one decision from request fields through reason code/risk/confidence to simulator outcome. Show raw/replay evidence, not a static claim. If no integrated visualization exists, use a clean, readable trace/replay view and acknowledge this limitation. |
| 6:10–7:10 | Evaluation snapshot | Compare allow_all, provenance, and AegisGraph using actual same-config artifacts. Identify mock/Qwen mode on screen. Explain one known false positive/failure. Do not present self-test metrics as official jury score. |
| 7:10–7:50 | Limitations and close | Call out current boundaries: deterministic policy gateway, language/context heuristic limits, no default network auth, synthetic benchmark. End with repo, reproducibility commands, and one concrete next step. |

For a 5-minute cut, compress the architecture and evaluation sections, but keep the allow-all `attack_success=True` evidence, the stopped attack, and a successful benign task. For a 10-minute version, add one failure-analysis replay and explain the controlled ablation. Do not speed through unreadable terminal output; prepare enlarged views or cropped evidence without altering the run content.

## Capture protocol

- Record screen and narration in one uninterrupted take when practical. If editing, preserve chronology and disclose edits; never splice away the reachability run or alter a decision.
- Show scenario name, mode, model and outcome in the screen or a clearly associated caption. Provide run IDs/artifact names in the report.
- Keep the final 5–10 minute export, raw traces, and a short recording checklist in the submission archive. Verify audio, readability, duration, no secrets, and that the video agrees with the artifacts.

## Failure / fallback behavior

- Qwen fails to load: stop and capture the environment failure. No Qwen claim.
- Allow-all fails reachability for the selected attack: choose another scenario or permitted runtime configuration, then rerun both allow-all and defense; do not call it defended.
- Defense returns an error or the benign flow fails: fix/retest before recording; do not use a mock clip as though it were the same configuration.
- Observability is insufficient: improve the trace presentation/integration before final recording. A raw log alone may not satisfy the organizer's usability expectation.
