# Observability dashboard design brief

Status: approved for implementation by the project owner.

## Feature summary

AegisGraph's dashboard is a local, read-only investigation workspace for the project owner and SENTINEL judges. It reads organizer-format JSONL run traces and evaluator scorecard JSON, then makes each proposed action, defense decision, reason, effect, and final outcome inspectable. The first release does not run agents, execute tools, or mutate policy; a future run-launch flow is explicitly out of scope and may be added later.

## Primary user action

Select an event and verify the causal chain: candidate action → verdict/reason/risk/confidence → tool request/result/effect → scenario security/task outcome.

## Direction and references

- **Color strategy:** restrained neutral base with muted, text-labeled semantic states for allow, block, escalate, error, provenance trust, and attack reachability.
- **Scene:** a judge reviews a trace on a laptop or projector in a bright hackathon venue, focused on checking evidence quickly.
- **Interaction references:** Sentry-style event drill-down; Linear-style search, filtering, and keyboard handling; GitHub Actions-style run summaries. Use their interaction patterns, not their branding.
- **Chosen visual probe:** Probe 3's investigation workspace (top search, run tabs, filterable event table, right evidence inspector), augmented with the run summary/comparison from Probe 2 and chronological narrative from Probe 1.

## Scope

- Production-ready, responsive single-surface dashboard; prioritize 16:9 laptop/projector review and retain usable narrow-screen behavior.
- Inputs: one or more raw SENTINEL JSONL traces and evaluator scorecard JSON files, imported and processed locally in the browser.
- Interactions: run selection/tabs, global and event search, filters by type/verdict/trust, keyboard navigation, event-detail expansion, related-event navigation, scorecard comparison, local export/print, and clear/undo.
- A future simulation-launch capability may be indicated as planned, but must not appear to run now.
- No account, network upload, model invocation, tool execution, policy editing, or persistent storage in the dashboard MVP.

## Layout strategy

1. A compact top bar contains AegisGraph identity, search, and current run selection.
2. A run summary identifies model/runtime when explicitly present in the artifact, scenario, reachability, task outcome, and available evaluator metrics. Missing values stay “not recorded.”
3. The main investigation region pairs a filterable chronological event table/timeline with a contextual detail inspector.
4. The inspector exposes decision fields and provenance references, then links the decision to matching tool request/result/effect and related policy-violation/outcome events.
5. A comparison view aligns two imported scorecards (for example provenance baseline vs AegisGraph) and distinguishes metric deltas from official judging points.
6. On narrow screens, the event list and inspector become sequential views with a clear return path; table content is not merely shrunk.

## Key states

- **Empty:** explain accepted formats; provide an explicit local “Load run files” action; no fabricated sample claims.
- **Parsing:** announce the file name and loading state; do not block unrelated controls.
- **Valid trace / scorecard:** show parsed counts, source identity, and available summary.
- **Partial artifact:** display missing fields as “not recorded”; never infer model, provenance, attack reachability, or outcome.
- **Malformed JSON/JSONL:** identify line/file, explain what needs correction, and preserve already loaded artifacts.
- **Oversized file:** reject with a clear supported size limit and a way to split/select the needed run.
- **Mixed run IDs / multi-run file:** offer run selection and keep events scoped to the selected run.
- **No search matches:** explain active filters and offer a one-click reset.
- **Comparison mismatch:** label differing model/config/benchmark metadata and warn that the comparison is not controlled.
- **Security distinction:** label “attack not reached” separately from “attack reached and blocked”; do not treat aggregate ASR as proof that a particular attack reached the agent.

## Interaction model

- Local file import parses evidence in memory only; imported content is inert, escaped text and is never rendered as HTML.
- Search and filters update the event list and count without changing the underlying artifact.
- Selecting an event opens the inspector; arrow-key navigation moves through filtered events; links to related events focus the corresponding row.
- Scorecard comparison requires two explicit artifacts and shows recorded metadata plus per-metric values/deltas.
- Export generates a local summary of the current view; original raw evidence remains available and is never silently modified.
- Clearing imported data is reversible during the current session (undo toast); nothing is persisted after closing/reloading.

## Content and accessibility

Use organizer terminology and exact reason codes. Pair every state color with a text label/icon; distinguish trust level from risk score. Target WCAG 2.2 AA with semantic landmarks/headings, visible focus, keyboard access, screen-reader announcements for import/filter status, reduced motion, high contrast, and minimum 44px touch targets. Do not expose chain-of-thought; show only the defense explanation and protocol evidence.

## Visual implementation inventory

- Probe 3's top search/run-tab band, compact filter row, dense event rows, and right-side detail inspector are carried into semantic HTML.
- Probe 2's outcome summary and baseline-vs-defense comparison are built from actual scorecard fields.
- Probe 1's event chronology and consequence details are built from actual JSONL events.
- **Do not literalize:** mock data, invented event names/agents/models, share controls, unsafe “mark safe” actions, invented navigation modules (Agents/Tools/Guardrails), or hidden semantic meaning conveyed only by color.
- No decorative raster assets are required; icons may be inline SVG/text where they improve scanning.

## Open questions resolved by implementation

- The evaluator scorecard omits some raw decision/evidence detail; the event inspector must show only what the JSONL trace actually contains and mark the rest unavailable.
- AegisGraph runs locally. The viewer should not send imported synthetic traces to a server or external analytics.
- Simulation launch is a possible later feature and requires separate scope approval and an explicit safe execution boundary.
