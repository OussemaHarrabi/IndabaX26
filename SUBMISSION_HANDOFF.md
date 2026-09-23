# SENTINEL submission handoff — 9ahwa mahrou9a

This is a human-juried submission, not an automated leaderboard. Do **not** submit until the PDF and video links open in a private window. The public repository default branch is [`feature/aegisgraph`](https://github.com/OussemaHarrabi/IndabaX26).

| Form field | Value / action |
| --- | --- |
| Team Name | `9ahwa mahrou9a` |
| Team members | **Blocked:** owner says they registered solo. The form demands full names of 3–5 registered humans. Do not invent names; ask the organizer whether solo registration is accepted and enter the actual name(s) only. |
| Technical Report | Upload `output/pdf/AegisGraph-SENTINEL-Technical-Report.pdf` after checking the rendered PDF and 100 MB limit. Source: `REPORT.tex`. |
| GitHub Repository Link | `https://github.com/OussemaHarrabi/IndabaX26` (public; default branch `feature/aegisgraph`). |
| Video Demo Google Drive Link | **Pending recording/upload.** 5–10 minutes; set the specific video file to “Anyone with the link — Viewer” and verify in a private window. |
| Anything we should know? | Suggested honest text below. |

Suggested “Anything we should know?” text:

> We ran the unmodified SENTINEL reference agent with Qwen3-8B Q4_K_M on a free Colab T4, via local Ollama rather than an external inference API. In one seeded run of all 40 public scenarios, allow-all reached 22 of 31 attacks; final AegisGraph v5 stopped those 22 but preserved only 4/9 benign task successes, below the kit's 0.5 self-test utility gate. Four benign failures also occurred under allow-all; the fifth is due to a consequential email confirmation mismatch. V5 still allows a tool-use prompt in one final answer from an allow-all-unreached memory-poisoning case. We disclose both limitations in the report and provide raw traces. We are registered solo and seek confirmation that this is eligible despite the form's 3–5-member wording.

## Submission gate

- [ ] Report PDF rendered and visually checked; exact v5 scorecard digest and source commit included.
- [ ] Public repo includes defense, observability UI, README install/run commands, v5 scorecard, raw traces, and PDF.
- [ ] The attack demonstrated has `attack_success=True` under **allow-all with Qwen**, then `attack_success=False` with v5; the defense decision appears before the blocked/redacted effect.
- [ ] A separate benign v5 trace has `task_success=True`; dashboard displays its reason codes and next events.
- [ ] Video is 5–10 minutes, readable, audible, and shows an uncut critical sequence. Name Qwen3-8B Q4_K_M on camera.
- [ ] Video link opens in a logged-out/private browser as viewer; report/repo/evidence links accessible to `skanderyacoubi2005@gmail.com`.
- [ ] Organizer resolves the solo-registration conflict; actual human name entered without inventing people.
- [ ] Owner submits the form and saves the receipt. A draft is not a submission.

## Evidence to put on screen

Import `evaluation/real-qwen/ent_portal_rotation_draft-v5.jsonl` and `evaluation/real-qwen/aegisgraph-v5-qwen3-8b.json` into the read-only dashboard. The same scenario's allow-all outcome is in the baseline archive and scorecard. For the benign control, import `evaluation/real-qwen/enterprise_project_status-v5.jsonl` with the same v5 scorecard. Do not load both v1 and v5 scorecards for the same run ID simultaneously; the dashboard correctly warns that their outcome association is ambiguous. Keep the full, unmodified JSONL trace available for inspection.
