# 08 — HTTP service surface, dashboard, packaging, tests

Scope: `.audit-tmp/aegisgraph/backend/aegisgraph/app.py`, `backend/aegisgraph/static/{index.html,dashboard.js,dashboard.css}`,
`Dockerfile`, `requirements.lock`, `pyproject.toml`, `.dockerignore`, `OBSERVABILITY_DASHBOARD_BRIEF.md`,
`tests/{test_http_service.py,test_dashboard.py,test_project_metadata.py}`.
Nothing was executed (protocol: read-only). Everything below is CODE READING or MEASURED (from parsing artifact JSON), never a run.
`app.py` is 116 lines total — the whole HTTP surface is one file.

---

## 1. Service surface

`app = FastAPI(title="AegisGraph SENTINEL v1 defense API", docs_url=None, redoc_url=None, openapi_url=None)`
(`.audit-tmp/aegisgraph/backend/aegisgraph/app.py:30-35`).

| Route | Method | Semantics | Anchor |
|---|---|---|---|
| `/` | GET | `FileResponse(static/index.html, media_type="text/html")`, `include_in_schema=False` | `app.py:38-42` |
| `/assets` | mount | `StaticFiles(directory=_STATIC_DIRECTORY)` serving `index.html`, `dashboard.js`, `dashboard.css` | `app.py:45` |
| `/healthz` | GET | `{"status": "ok"}` — liveness only; does not touch the engine | `app.py:78-80` |
| `/v1/decision` | POST | body `SentinelRequest` → `SentinelResponse`; validates policy and returns one of `allow|block|escalate|rewrite`; never executes the proposed action | `app.py:83-105`, docstring `app.py:85` |

Everything else → 404 through `http_error_handler` (`app.py:70-75`). Wrong method → 405 (asserted `test_http_service.py:187-189`).
There is no `/dashboard/import`-style server endpoint; the dashboard is pure client-side (`test_dashboard.py:45-46` asserts `POST /dashboard/import` → 404).

### Request validation and size limits
- Envelope model `SentinelRequest` (`sentinel.py:159`) is `extra="ignore"` (`sentinel.py:51`, `_LenientFrozenModel`) — unknown envelope fields are silently dropped, deliberately, for forward compatibility (asserted `test_http_service.py:100`).
- `SentinelCandidateAction` (`sentinel.py:54`) and `SentinelResponse` (`sentinel.py:188`) are `extra="forbid"` (`sentinel.py:57`, `sentinel.py:191`) — unknown response/candidate fields are a hard error.
- Per-field bounds (CODE READING, `contracts.py`): `MAX_ARGUMENT_CHARS = 8_000` (`contracts.py:25`), `MAX_CONTENT_CHARS = 16_000` (`contracts.py:26`), `MAX_CONTEXT_BYTES = 16_384` (`contracts.py:27`), `MAX_METADATA_BYTES = 4_096` (`contracts.py:28`), `REASON_CODE_PATTERN = r"^[A-Z][A-Z0-9_]{1,63}$"` (`contracts.py:29`). Also: ≤32 arguments and identifier keys ≤64 chars, string arguments ≤8,000 chars, floats must be finite (`sentinel.py:68-81`); `tool` must match `^[a-z][a-z0-9_]{1,63}$` (`sentinel.py:60`); per-`type` shape rules (`sentinel.py:89-108`); `conversation`/`provenance`/`tool_calls` each `max_length=256`; `policy_context` ≤16,384 bytes of canonical JSON (`sentinel.py:176-181`); `reason_codes` `max_length=16` and must match `REASON_CODE_PATTERN` (`sentinel.py:196`, `:203-209`); `explanation` `max_length=500` (`sentinel.py:197`); `metadata` ≤4,096 bytes (`sentinel.py:211-217`).
- **No request-body size limit exists at the HTTP layer.** Nothing inspects `Content-Length`, and no middleware caps the body. Worst-case accepted body is roughly 256 conversation items × 16,000 chars + 256 provenance records + a 16,384-byte `policy_context` ≈ 4 MB+, buffered in full by Starlette before validation. [INFERENCE] a single large POST can pin memory; no test covers it.
- **Response** limit exists: `_MAX_RESPONSE_BYTES = 64_000` (`app.py:20`), checked after `model_dump_json()` (`app.py:91-92`). Same constant as the organizer client's own bound (`.sentinel_reference/src/sentinel/defenses/client.py:14,78`) — the two agree. The bound is reachable: `rewritten_action` can carry a `tool_call` with 32 arguments × 8,000 chars (`contracts.py:25,131`), far above 64 KB.

### Response headers (`app.py:48-62`, middleware, applied to every response)
`Cache-Control: no-store` (`:57`), `Pragma: no-cache` (`:58`), `X-Content-Type-Options: nosniff` (`:59`), and — only for `path == "/"` or `path.startswith("/assets/")` — `Content-Security-Policy` (`:60-61`) exactly:
`default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'none'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'` (`app.py:24-28`, asserted verbatim `test_dashboard.py:37-46`).
No `X-Frame-Options` header; framing is prevented by `frame-ancestors 'none'` on the HTML asset only.

### Error handling
- `RequestValidationError` → 422 `{"detail": "Invalid SENTINEL request"}` (`app.py:65-67`). Pydantic detail is never returned, so no field path or input fragment leaks (asserted `test_http_service.py:110`, which also checks the secret is absent from the body).
- `StarletteHTTPException` → status preserved, framework headers preserved, body replaced by `_GENERIC_INVALID` for 400/413/415/422 else `_GENERIC_FAILURE` (`app.py:70-75`).
- Unhandled exception in the middleware → 500 `{"detail": "Request could not be safely processed"}` + `_LOGGER.error` of the exception **type name only** (`app.py:54-56`).
- Inside the endpoint, **any** exception becomes a 200 fail-closed `block`: `risk_score=1.0, confidence=1.0, reason_codes=("INTERNAL_EVALUATION_FAILED",), explanation="The request could not be safely evaluated.", metadata={}` (`app.py:94-105`). The comment at `app.py:96` states the rule: "A valid request reaching policy must never become an allow on an error." The engine has its own identical fail-closed layer (`engine.py:345-368`, `_failure_decision`), so there are two independent catch-alls that produce the same reason code.

### Concurrency and state
- All three handlers are `async def` (`app.py:39,79,84`), but `decision_endpoint` calls the **synchronous, pure-CPU** `decide()` directly (`app.py:88`) with no `run_in_threadpool`/`anyio.to_thread`. [INFERENCE] a request blocks the single event loop for the duration of the decision.
- Measured cost is small: the real scorecards report `latency_median_ms` 4.555 / `latency_p95_ms` 9.284 (`evaluation/real-qwen/aegisgraph-v5-qwen3-8b.json`), 4.491/8.355 for v3. MEASURED FACT.
- **Zero server-side state**: `app.py` holds only frozen constants; `engine.py`/`policy.py`/`adapter.py` have no module-level mutable containers, no `lru_cache`, no `global` (grep). Each request is independent; there is no session, no run store, no cache, and nothing written to disk. Statelessness is therefore a structural fact, though no test asserts it.

---

## 2. Security posture of the service itself

- **Authentication: none.** No `Authorization`, `api_key`, `Depends`, `HTTPBasic`, CORS or `TrustedHost` middleware anywhere in `backend/aegisgraph/` (grep: none). Documented, not hidden: `README.md:134-135` "The service has no API key requirement for local simulation. Keep it bound to localhost unless it is placed behind your deployment's authentication and network controls." and `README.md:155-157` "These decisions are deterministic policy checks, not proof that every possible prompt injection or cyberattack is detected. The service has no authentication by default and must not be exposed directly to an untrusted network." → **documented local prototype, not a hidden vulnerability**, *provided* the binding advice is followed.
- **Binding.** Local run command binds loopback explicitly: `--host 127.0.0.1 --port 8080` (`README.md:125`). The container binds `0.0.0.0` (`Dockerfile:23`), which is normal inside a container namespace.
  **Contradiction (real, actionable):** the Docker guidance (`README.md:164-169`, `docker run` at `:166`) publishes with `-p 8080:8080` (`README.md:168`), which maps the port on **all host interfaces**, directly contradicting the "keep it bound to localhost" rule three paragraphs earlier (`README.md:134`). With an unauthenticated API this is the one concrete deployment footgun in the packaging. Fix = `-p 127.0.0.1:8080:8080`.
- **Docs exposure: closed.** `docs_url=None, redoc_url=None, openapi_url=None` (`app.py:30-35`); `/docs` and `/openapi.json` both 404 (asserted `test_http_service.py:40-46`). The local run command does not pass `--no-server-header`, so the `Server: uvicorn` header is present when run from `README.md:125`; the container CMD does pass `--no-server-header` (`Dockerfile:23`).
- **Injection surfaces.** [MEASURED, by exhaustive reading] No user-supplied string reaches a sink:
  - No HTML is generated server-side; the only HTML is a static file (`app.py:42`).
  - No string interpolation into `explanation` anywhere in `engine.py` (grep for `explanation=f` = none) — every explanation is a literal.
  - `reason_codes` are literals except `engine.py:615` `f"SENSITIVE_{surface.upper()}_REDACTED"`, where `surface` is a caller-supplied literal, not request text; and any accidental free text would be rejected by `REASON_CODE_PATTERN` validation (`sentinel.py:203-209`), which then becomes a fail-closed block rather than a leak.
  - `metadata` carries only enum values: `least_trust`, `max_sensitivity` and (for memory writes) `memory_trust` (`engine.py:1110-1115`) — enum-typed, ≤4,096 bytes (`sentinel.py:211-217`).
  - `rewritten_action` is reconstructed by the policy engine (redacted arguments / static `"Redacted"` content), not echoed verbatim.
  - The response is serialized with pydantic `model_dump_json()` (`app.py:90`) — JSON-escaped, and the shape is closed (`extra="forbid"`).
  - The only reflection risk that remains is *semantic*: a caller learns nothing about its own payload from error bodies (`_GENERIC_INVALID`/`_GENERIC_FAILURE` are constant strings, `app.py:21-22`), and the two tests that plant a secret in the request assert it does not come back (`test_http_service.py:72`, `:110`).
- **File/serve risks.** `/assets` is a `StaticFiles` mount (`app.py:45`) → directory listing is off by default in Starlette, path traversal is normalized by `StaticFiles`, and `index.html` is also reachable at `/assets/index.html` (CSP still applied because of the prefix test at `app.py:60`). Assets are read from the installed package directory `Path(__file__).parent / "static"` (`app.py:23`), so there is no user-controlled path component anywhere. `/` serves a fixed file name. No upload, no write, no file-read endpoint.
- **What the Dockerfile hardens** (`Dockerfile:1-23`): pinned non-floating install from `requirements.lock` (`:11-12`), `PYTHONDONTWRITEBYTECODE=1`, `PYTHONUNBUFFERED=1`, no pip cache (`:3-7`), only `backend/` copied — no tests, no artifacts (`:14`), dedicated non-root system user/group `10001` with `--home /nonexistent`, `chown -R` (`:16-19`), `USER 10001:10001` (`:20`), `--no-server-header` (`:23`). Missing: no `HEALTHCHECK`; the README's `docker run` flags (`--read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=64 --memory=512m`, `README.md:166-168`) are *documented but not enforced by the image itself*, and `README.md:175` admits "A live Docker-engine run has not yet been verified."
- `.dockerignore` (21 lines) excludes `.git*`, `.venv`, caches, `tests`, `frontend`, `artifacts`, `results`, `*.pdf`, `.env*`. [MEASURED] build context is still ~4.7 MB because `evaluation/` (2.4 MB of mock and real-Qwen artifacts) and `scripts/` are not excluded; harmless for the image (only `backend/` is `COPY`ed, `Dockerfile:14`) but wasteful and easy to fix.

---

## 3. Dashboard: capabilities and limits

Client-only, file-input driven, IIFE with `"use strict"` and no modules (`dashboard.js:1-2`).

**Can:** import one or more files (`<input type="file" multiple accept=".jsonl,.ndjson,.json,application/json,text/plain">`, `index.html:26`); parse JSONL traces; parse evaluator scorecard JSON; group a trace file into runs by `run_id` (`dashboard.js:353-363`); attach scorecard outcomes to runs (`addScorecard`, `dashboard.js:370-393`); search/filter by free text, event type, verdict, trust bucket (`filteredEvents`, `dashboard.js:155-166`); click/keyboard row selection (`dashboard.js:183,203-212`); inspector with decision fields, reason chips, candidate action, provenance refs, related events (same `step_id`, `matchingRelated` `dashboard.js:228-235`), and raw event JSON (`renderInspector`, `dashboard.js:237-270`); compare two scorecards metric-by-metric with deltas (`renderComparison`, `dashboard.js:279-319`); export the current filtered view as JSON (`exportView`, `dashboard.js:434-443`); print (CSS `@media print`, `dashboard.css:212-221`); clear with undo (`clearArtifacts` `dashboard.js:446-450`, undo `:464`); **redact chain-of-thought keys** on import via `REDACTED_KEY = /(?:reasoning|thought|chain.?of.?thought)/i` (`dashboard.js:6,16-23`).

**Matching traces to scorecards** (the important mechanic):
- `addScorecard` matches by `outcome.run_id` if present, else `outcome.scenario_id` (`dashboard.js:383-391`).
- `reconcileTraceScorecards` re-scans every scorecard against every trace run and sets `run.scorecardConflict = matches.length > 1` and `run.scorecard = matches.length === 1 ? matches[0] : null` (`dashboard.js:395-409`).
- Multi-match warning text (also used as the import banner): "Multiple scorecards match this trace run ID. Attack and task outcomes are intentionally unlinked; load only the matching scorecard to inspect this trace." (`dashboard.js:132,431`; `index.html:54` has the `role="status"` container).
- **MEASURED confirmation of the ambiguity is real, not hypothetical:** the v3 and v5 real scorecards both contain `run_id = "ent_portal_rotation_draft-http_defense-s0"` (`evaluation/real-qwen/aegisgraph-v3-qwen3-8b.json`, `.../aegisgraph-v5-qwen3-8b.json`), and the trace `evaluation/real-qwen/ent_portal_rotation_draft-v5.jsonl` has that exact `run_id` on all 10 events. Loading both cards + the trace ⇒ conflict ⇒ outcomes unlinked. This matches `DEMO_RUNBOOK.md:13`. The mock card `evaluation/aegisgraph-mock.json` shares the same `run_id` namespace too (`ent_backup_restore_draft-http_defense-s0`), so mixing mock and real cards triggers the same warning — which is exactly the anti-reference "presenting development mock results as Qwen results" (`PRODUCT.md`).

**Refuses to / cannot:**
- No network at all: `connect-src 'none'` (`app.py:26`), no `fetch`/XHR anywhere in `dashboard.js`; UI copy "Artifacts are parsed in your browser and are not uploaded" (`index.html:36`) is truthful.
- No tool execution, no policy editing, no persistence (footer `index.html:89`; session-only `state` `dashboard.js:7`; nothing in `localStorage`).
- No agent/model invocation; "Simulation launch · planned" is an inert `<span class="planned-tag">` with no handler (`index.html:64`).
- Cannot infer missing data: every missing field renders as "Not recorded" through `text(value, fallback = "Not recorded")` (`dashboard.js:10-15`).
- Hard limits: 25 MiB per file (`MAX_FILE_BYTES = 25 * 1024 * 1024`, `dashboard.js:4,417`) and 100,000 events (`MAX_EVENTS = 100000`, `dashboard.js:5,358`).
- **No virtualization**: `renderEvents` builds one DOM row per filtered event up to 100,000, and `filteredEvents` `JSON.stringify`s every event on each keystroke (`dashboard.js:164`) — [INFERENCE] a large trace will jank the UI; the cap is the only protection.

**UI statements the code does not fully support (concrete):**
1. **"Attack reachability" row can never populate from shipped evidence.** `deriveRun` reads `attack_reached` from trace events/outcome objects (`dashboard.js:109,119-120`), but `attack_reached` appears **only in `dashboard.js` and its test** — a repo-wide grep over `.audit-tmp/aegisgraph` and `.sentinel_reference` finds no other occurrence, and none of the 5 mock scorecards, 5 real scorecards, or 7 traces contains it (parsed JSON key sets; mock/real outcome keys are `attack_present, attack_success, task_success, run_id, scenario_id, domain, …`). So the row renders "Not recorded" for all real evidence, while the brief (`OBSERVABILITY_DASHBOARD_BRIEF.md`, "Security distinction") asks the dashboard to distinguish "attack not reached" from "attack reached and blocked". Real reachability lives in the allow-all scorecard's per-scenario `attack_success` plus `scripts/validate_attack_reachability.py` (`REACHABILITY_GATE.md:1-20`), which the dashboard does not cross-reference.
2. **The uncontrolled-comparison guard does not fire for the real v3-vs-v5 pair.** `metadataKeys` (`dashboard.js:302-308`) omits `deterministic_digest`, `defense`, and `score`; and neither card carries any of `model_id`/`runtime`/`config*` keys (MEASURED: both cards' top-level keys are exactly `attack_mode, benchmark_version, by_domain, defense, deterministic_digest, metrics, outcomes, run_seed, scenario_count, score, split`). v3 vs v5 differ only in `deterministic_digest` (`56ac2dba…` vs `57ad9925…`) and in `score.core` (0.814716 vs 0.814731) — `attack_mode="static"`, `split="public"`, `run_seed=0`, `benchmark_version="sentinel-bench/0.1.0"`, `defense="http_defense"` are all identical. Result: `differentMetadata` is empty and `recordedMetadata` is non-empty ⇒ **no warning is shown** (`dashboard.js:314-320`), even though the two cards are different defense revisions. The human can still tell them apart from the select labels (they show the raw file names, `dashboard.js:285`), and the ABOVE-the-table caveat "Aggregate metrics do not prove that a specific attack reached the agent." is static (`index.html:56`). Also note `defense` is `"http_defense"` in both mock and real cards, so the mock/real distinction is likewise invisible to the metadata check.
3. **"Search runs and events"** (`index.html:18`) is really "search the selected run's events" — `filteredEvents` only reads `currentEvents()` (`dashboard.js:155-166`), and `renderEvents` never touches run list; run selection is the tab strip only (`dashboard.js:78-91`).
4. Minor: `index.html:38` says "up to 25 MB per file" while the code is 25 MiB (26,214,400 bytes); `.json` scorecards that happen to contain the literal `\n{"type"` are routed to the trace parser because `||` binds looser than `&&` in `dashboard.js:420`; `exportView` calls `URL.revokeObjectURL(url)` synchronously right after `link.click()` (`dashboard.js:443`) — [INFERENCE] a known browser flakiness (download may be cancelled on some engines); the download anchor is never appended to the document (works in current Chromium/Firefox, not guaranteed by spec).

---

## 4. Accessibility and UX claims actually implemented

`PRODUCT.md` "Accessibility & Inclusion": "Target WCAG 2.2 AA. Support keyboard navigation, visible focus, readable text, reduced motion, and state labels/icons in addition to color. Use accessible names for interactive controls…". `OBSERVABILITY_DASHBOARD_BRIEF.md` adds "minimum 44px touch targets" and "screen-reader announcements for import/filter status".

Implemented (with anchors):
- **Color-independent states.** Every state pill carries text: `statePill(label, tone)` renders `label` as text with a decorative dot via `.state::before` (`dashboard.css:85`); the call sites pass literal strings "Attack reached"/"Attack not reached"/"Task succeeded"/"Task failed" (`dashboard.js:148-149`). Verdict rendering writes the verdict word and only then colors it (`.verdict-allow/.verdict-block/.verdict-escalate`, `dashboard.css:128-131`); `rewrite` deliberately has no color rule and falls back to neutral. This satisfies `PRODUCT.md` anti-reference #4.
- **Visible focus.** `:focus-visible { outline: 3px solid oklch(57% 0.16 245); outline-offset: 3px; }` (`dashboard.css:31`), plus `:focus-within` on the search wrappers (`dashboard.css:41`) and inner-input outline suppression to avoid double rings (`dashboard.css:42`).
- **Keyboard access.** Rows are focusable and operably by Enter/Space; ↑/↓ move between filtered rows (`dashboard.js:183,204-212`); `/` focuses global search and `Ctrl/Cmd+O` opens the picker, guarded against firing while typing in an input (`dashboard.js:466-468`); Escape clears global search (`dashboard.js:466`); `selectEvent` restores focus and scrolls the row into view (`dashboard.js:272-277`); the table caption documents the arrow keys (`index.html:75`); `Tab` reaches every control natively.
- **Accessible names.** `aria-label="Load SENTINEL artifacts"` on the hidden file input (`index.html:26`), `aria-label="Dismiss message"` on the toast close (`index.html:88`), `aria-label="AegisGraph investigation dashboard"` on the brand link (`index.html:13`), `sr-only` labels for the two search inputs and the three filter selects (`index.html:18,66-69`), `scope="col"` on all headers (`index.html:76`), `aria-labelledby`/`aria-label` on the main landmarks (`index.html:32,48,51,55,62,81`).
- **Live regions.** `role="status" aria-live="polite"` on import status (`index.html:31`), trace status (`index.html:72`), scorecard-conflict warning (`index.html:54`), toast (`index.html:88`); the inspector is `aria-live="polite"` (`index.html:81`).
- **Reduced motion.** `@media (prefers-reduced-motion: reduce)` zeroes transitions/animations (`dashboard.css:211`).
- **Touch targets.** `button, select, .load-button { min-height: 44px }` (`dashboard.css:28`), search wrappers 44px (`:39`), filter/compare selects 44px (`:98`), `.text-button`/`.related-button` 44px (`:115,151`), `.icon-button { width: 44px; height: 44px }` (`:156`).
- **Responsive/narrow behaviour** (`dashboard.css:159,169,206`) stacks list and inspector (`flex-direction: column`, no shrunken table: `.event-table { min-width: 580px }` with a scroll container) and print CSS (`:212`) hides chrome.

Gaps / not implemented:
- **No high-contrast support.** The brief (Visual implementation inventory / Content and accessibility) asks for "high contrast"; there is no `@media (forced-colors)` or `prefers-contrast` rule anywhere in `dashboard.css` (grep = none). [INFERENCE] Windows High Contrast mode will drop the oklch washes and rely on the text labels, which happens to degrade acceptably, but this is unimplemented, not verified.
- **Incomplete ARIA tabs pattern.** `role="tablist"` with `role="tab"` + `aria-selected` + `aria-controls="summary-grid"` (`dashboard.js:83-86`) but the controlled element `summary-grid` has no `role="tabpanel"` (`index.html:53`), tabs have no ←/→ key handling, and every tab stays in the tab order (no roving tabindex) — [INFERENCE] a screen-reader/user will not get the expected tab semantics or arrow-key switching.
- **Trust labels are collapsed, not preserved.** `getTrust` maps the six spec trust levels into three buckets: any of `untrusted, untrusted_internal, untrusted_external, adversary_controlled` ⇒ `"untrusted"`; any of `trusted, trusted_internal, authenticated_user, system_policy` ⇒ `"trusted"`; else `"unknown"` (`dashboard.js:45-57`). The inspector shows only the bucket (`dashboard.js:258`), so `system_policy` and `authenticated_user` are indistinguishable without reading the raw JSON block — a partial miss against `PRODUCT.md` principle 3 ("Preserve provenance and trust labels"). The filter options mirror those three buckets (`index.html:69`).
- **`aria-live="polite"` on the whole inspector** (`index.html:81`) means each selection re-announces the entire panel (decision, reasons, provenance, related events, full JSON) — [INFERENCE] verbose for AT users; a focused summary region would be better.
- Chain-of-thought suppression is key-name based only (`REDACTED_KEY`, `dashboard.js:6`); values containing reasoning text under other keys (e.g. `rationale`, `scratchpad`, `notes`) are displayed and exported verbatim. [INFERENCE] partial enforcement of the brief's "Do not expose chain-of-thought".
- `max-width`/`min-width: 320px` baseline (`dashboard.css:26`) and 16:9-first layout match the brief; no horizontal-overflow audit was performed.
- No automated accessibility verification exists (see §5) and `README.md:109-112` lists "exercise the dashboard with assistive technology" (`:111`) as still-to-do release work — an honest statement of status.

---

## 5. Test coverage map

### `tests/test_http_service.py` (189 lines, FastAPI `TestClient`)
Asserts: `/healthz` → 200 `{"status":"ok"}` and `/docs` + `/openapi.json` → 404 (`:40-46`); safe `respond` action → 200, `decision == "allow"`, `reason_codes == ["BENIGN_ACTION"]`, **exact key set** `{decision, risk_score, confidence, reason_codes, explanation, rewritten_action, metadata}`, `len(content) < 64_000`, `cache-control: no-store`, `x-content-type-options: nosniff` (`:49-70`); unauthorized `tool_call` → `block` + `UNAUTHORIZED_TOOL` and the secret argument is absent from the body (`:72-84`); consequential tool without confirmation → `escalate` + exactly `["CONFIRMATION_REQUIRED"]` (`:87`); unknown envelope field ignored → `allow` (`:100`); malformed body → 422 with the exact constant body and no echo of the secret (`:110`); `decide` raising → 200 `block` + `INTERNAL_EVALUATION_FAILED` with no exception text leaked (`:124`); `SentinelResponse` rejects unknown fields and `rewrite` without `rewritten_action` (unit, `:143`); `_to_wire_response` on a rewrite emits `decision: "rewrite"` and `rewritten_action.content` (`:168`); 405 on `GET /v1/decision` and `POST /healthz` (`:187-189`).
Strength/weakness: this file is the strongest in scope — it tests behaviour and specific security invariants (no echo, fail-closed, exact wire shape), not source text. It never inspects a 404/405 body, never exercises the response-size guard, and never exercises the 500 middleware catch-all.

### `tests/test_dashboard.py` (114 lines) — mostly source-text assertions
`/` → 200 `text/html`, `no-store`, contains the file-input `aria-label` and both asset paths (`:13-22`); assets → 200 + `no-store`, CSS contains `@media`, JS contains the substrings `defense_decision` and `textContent` (`:24-31`); exact CSP string on `/` and `POST /dashboard/import` → 404 (`:37-46`); the three static files exist as package resources via `importlib.resources` (`:49`); then `_section()`-sliced **substring** checks on `dashboard.js` for the attack success/present/reachability rows, `deriveRun` booleans, and the trust label lists (`:57`), for the `step_id` equality guard and import-progress strings and comparison metadata keys and `selectEvent` focus/scroll (`:81`), for `outcome.run_id`/`run.id === outcome.run_id`/`run.id === scenarioId` in `addScorecard` (`:100`), and for the conflict strings `run.scorecardConflict = matches.length > 1` / `Multiple scorecards match this trace run ID` (`:109`).
[INFERENCE] Most of this file pins implementation text rather than behaviour: renaming a variable, reordering the arrays, or changing the JS wording fails the suite without any user-visible change, while a real regression in matching logic can pass as long as the substrings survive. It also cannot detect a change in the actual rendered DOM.

### `tests/test_project_metadata.py` (13 lines)
Exactly one assertion: `"uvicorn>=0.30,<1" in pyproject["project"]["dependencies"]` (`:9-13`). That is the entire packaging test surface.

### Untested paths (verbatim list)
```
SERVICE (app.py / sentinel.py / contracts.py)
1.  _MAX_RESPONSE_BYTES breach (app.py:20,91-92) → 64 KB fallback block; reachable via a rewrite whose rewritten_action carries large arguments (contracts.py:25,131; sentinel.py:60-81)
2.  Middleware catch-all except Exception → 500 {"detail": "Request could not be safely processed"} (app.py:54-56)
3.  _GENERIC_FAILURE body for 404/405 (app.py:74) — only status codes are asserted, never the body
4.  413 and 415 branches of http_error_handler (app.py:74) — no oversized or wrong-Content-Type request is posted
5.  Header preservation on 405 (app.py:73, the Allow header) — never asserted
6.  CSP on /assets/* (app.py:60-61) — CSP is only asserted for "/" (test_dashboard.py:37-46)
7.  Pragma: no-cache (app.py:58) — asserted nowhere; /healthz headers never checked at all
8.  Asset Content-Type inference and /assets/../ traversal attempts (app.py:45)
9.  Missing-asset 404 body (app.py:45,70-75)
10. Routing shapes: /healthz/, /v1/decision/, HEAD, OPTIONS (app.py:38,78,83)
11. Concurrency and statelessness: two overlapping requests; blocking of the event loop by sync decide() inside async def (app.py:84-88); no rate limiting anywhere
12. Fallback response field values risk_score=1.0, confidence=1.0, metadata={} (app.py:97-104) — only decision and reason_codes are asserted
13. HTTP-level rewrite verdict — rewrite is tested only through _to_wire_response (test_http_service.py:168), never through POST /v1/decision
14. Request-side bounds: >16,000-char user_goal/content (contracts.py:26), 33-key arguments and argument keys that are not identifiers or exceed 64 chars, string arguments >8,000 chars, non-finite floats (sentinel.py:68-81), tool name failing ^[a-z][a-z0-9_]{1,63}$ (sentinel.py:60), extra="forbid" inside candidate_action (sentinel.py:57), action/type shape mismatches (sentinel.py:89-108), policy_context > MAX_CONTEXT_BYTES=16384 (sentinel.py:176-181), >256-item conversation/provenance/tool_calls, >16 reason_codes and invalid REASON_CODE_PATTERN (sentinel.py:196,203-209)
15. Unknown field inside candidate_action rejected vs ignored at envelope level (only the envelope case is tested, test_http_service.py:100)
16. No test asserts the service is unauthenticated or that a stray Authorization header is ignored (no auth exists, grep: none in backend/aegisgraph)
17. Wire-level explanation ≤500 chars and metadata ≤4,096 bytes (sentinel.py:197,211-217)
18. Cross-repo consistency with the organizer client bound MAX_RESPONSE_BYTES=64_000 (client.py:14,78) and its "expect 4xx for malformed" check (submission.py:202-206)

DASHBOARD (dashboard.js / dashboard.css / index.html)
19. 25 MiB rejection branch (dashboard.js:4,417)
20. 100,000-event cap branch (dashboard.js:5,358)
21. Malformed-JSONL-line error and "line N must contain a JSON object" (dashboard.js:355-356)
22. Empty trace "no JSONL event records found" (dashboard.js:360)
23. Scorecard shape rejection "expected evaluator JSON with metrics or outcomes" (dashboard.js:375)
24. File-type routing ambiguity: .json scorecard containing \n{"type", and .jsonl scorecard sent to addTrace (dashboard.js:420)
25. Run grouping fallback to file.name when run_id is absent (dashboard.js:353-363)
26. Multi-match conflict end-to-end: two matching scorecards ⇒ scorecardConflict, outcome unlinked, warning visible (only substrings are grepped, test_dashboard.py:109)
27. exportView Blob/download path and filename sanitization (dashboard.js:434-443)
28. clearArtifacts + undo restore (dashboard.js:446-450,464)
29. Keyboard shortcuts "/", Ctrl/Cmd+O, Escape (dashboard.js:466-468)
30. Run-tab click switching (dashboard.js:87)
31. Type/verdict/trust filter behaviour and getVerdict fallbacks (dashboard.js:41-43,155-166)
32. safeCopy chain-of-thought key redaction (dashboard.js:6,16-23)
33. formatMetric precision formatting (dashboard.js:321-324)
34. renderComparison delta row and metadata-diff/unavailable warning branches (dashboard.js:302-320)
35. Narrow-screen (760/480), print, and prefers-reduced-motion CSS behaviour (dashboard.css:169,206,211,212) — only the substring "@media" is asserted (test_dashboard.py:24-31)
36. No accessibility test of any kind (no axe/Lighthouse/pa11y, no keyboard or screen-reader run), although README.md:111 lists an assistive-technology check as pending

PACKAGING (test_project_metadata.py only asserts the uvicorn dependency string)
37. requirements.lock ↔ pyproject.toml version-range consistency (requirements.lock:1-14 vs pyproject.toml:11-14); nothing verifies the lock resolves or matches the declared floors/ceilings
38. Dockerfile COPY paths and that PYTHONPATH=/app/backend makes aegisgraph importable and static/* discoverable (Dockerfile:7,11,14; pyproject.toml:27,29-30)
39. .dockerignore coverage (evaluation/ and scripts/ are not ignored; .dockerignore:1-21)
40. sentinel-submission.yaml port 8080 vs Dockerfile EXPOSE 8080 (sentinel-submission.yaml:4, Dockerfile:21)
41. benchmark.lock counts (40 scenarios / 31 attacks / 9 benign) vs the shipped scorecards (scenario_count=40, attack_count=31, benign_count=9 — consistent today, unverified by any test)
```

---

## 6. Run-once facts for the course

**Start (documented; not executed during this audit)** — `README.md:119-126`, PowerShell on Windows:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m uvicorn aegisgraph.app:app --app-dir backend --host 127.0.0.1 --port 8080
```
Linux/macOS: same two install/run lines after `python3.12 -m venv .venv` + `source .venv/bin/activate` (`README.md:127-129`).
- Package/entry point: `aegisgraph.app:app`; import path needs `backend/` on `PYTHONPATH` (`pyproject.toml:27` `package-dir = {"" = "backend"}`, Dockerfile sets `PYTHONPATH=/app/backend`, `Dockerfile:7`).
- Requires Python `>=3.12,<3.13` (`pyproject.toml:10`); runtime deps fastapi/pydantic/uvicorn (`pyproject.toml:12-14`); the container pins exact versions from `requirements.lock`.
- **Port 8080** (`README.md:125`, `Dockerfile:21,23`, `sentinel-submission.yaml:4`). Loopback-only locally; the container also honours the harness's `--defense-url http://127.0.0.1:8080` (`README.md:190-191`).
- Dashboard URL: `http://127.0.0.1:8080/` (`README.md:16`).

**Health check** — `README.md:138-142`:
```powershell
curl.exe http://127.0.0.1:8080/healthz
```
Expected: HTTP 200, body exactly `{"status": "ok"}` (asserted `test_http_service.py:40-46`).

**Decision call** — `README.md:144-150`:
```powershell
curl.exe -X POST http://127.0.0.1:8080/v1/decision `
  -H "Content-Type: application/json" `
  --data-binary '{"run_id":"local-demo","step_id":1,"user_goal":"Summarize the request","candidate_action":{"type":"respond","content":"The request is ready for review."},"policy_context":{"allowed_tools":[]}}'
```
**Expected response shape** (closed object, exactly these 7 keys — asserted at `test_http_service.py:49-70`):
```json
{
  "decision": "allow",
  "risk_score": 0.05,
  "confidence": 0.99,
  "reason_codes": ["BENIGN_ACTION"],
  "explanation": "A response has no tool or memory side effect.",
  "rewritten_action": null,
  "metadata": {"least_trust": "authenticated_user", "max_sensitivity": "internal"}
}
```
Values derived by code reading, not by executing the service: `respond` ⇒ `_decision(ALLOW, 0.05, "BENIGN_ACTION", …)` (`engine.py:530-536`); `confidence=0.99` and `metadata = {least_trust, max_sensitivity}` are fixed by `_decision` (`engine.py:1110-1123`); with no observations the defaults are `TrustLevel.AUTHENTICATED_USER` and `Sensitivity.INTERNAL` (`adapter.py:107-117`); `allowed_tools` is the one required policy key (`policy.py:37`) and an empty list is valid, so the request does not hit `POLICY_CONTEXT_INVALID` (`engine.py:466`). HTTP 200, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, no CSP on JSON responses (`app.py:57-61`).

**Other invocation modes:** container `docker build -t aegisgraph:local .` + `docker run … -p 8080:8080 aegisgraph:local` (`README.md:165-169`; note the binding caveat in §2); harness `uv run sentinel eval public --defense-url http://127.0.0.1:8080 --model ollama:qwen3:8b --json --output aegisgraph-v5-recheck.json` (`README.md:190-191`), which calls `GET /healthz` and `POST /v1/decision` (`.sentinel_reference/src/sentinel/defenses/client.py:59,68`).

**Dashboard demo inputs that exist in-repo:** trace `evaluation/real-qwen/ent_portal_rotation_draft-v5.jsonl` (10 events, `run_id` `ent_portal_rotation_draft-http_defense-s0`) + scorecard `evaluation/real-qwen/aegisgraph-v5-qwen3-8b.json` (40 outcomes, `metrics.asr=0.0`, `metrics.dfi=1.0`). Loading the v3 card as well is the deliberate ambiguity demo. Baseline comparisons: `evaluation/real-qwen/allow-all-qwen3-8b.json` (`metrics.asr=0.7096…`) and `evaluation/real-qwen/provenance-qwen3-8b.json` (`metrics.asr=0.2903…`) — MEASURED from the files.

---

## 7. Course framing: what the dashboard is for, and what it deliberately cannot prove

**For:** turning one run's JSONL trace + the matching evaluator scorecard into an inspectable causal chain — candidate action → verdict/risk/confidence/reason codes → tool request/effect → task and security outcome (`OBSERVABILITY_DASHBOARD_BRIEF.md` "Primary user action"; UI mirrors it in `index.html:40-44`).

**Cannot prove (state these explicitly):**
1. It is a *viewer*: no agent is run, no tool is executed, no policy is changed, nothing is uploaded, nothing persists after reload (`index.html:36,89`; CSP `connect-src 'none'` `app.py:26`).
2. It shows **per-run** outcomes, never aggregate truth: "Aggregate metrics do not prove that a specific attack reached the agent" (`index.html:56`), and the comparison table is only as controlled as the metadata the cards happen to record — as §3.2 shows, v3-vs-v5 compares without any warning because `deterministic_digest` is not part of the check (`dashboard.js:302-320`).
3. Attack **reachability** per trace is not in the artifacts: the row stays "Not recorded" (`dashboard.js:119-120`), and reachability must be established separately from the allow-all card's `attack_success` via `scripts/validate_attack_reachability.py` (`REACHABILITY_GATE.md`). The brief's "label attack not reached separately from attack reached and blocked" is therefore only partially delivered.
4. An absent scorecard ⇒ unlinked outcomes, and two matching scorecards ⇒ deliberately unlinked outcomes with a visible warning rather than a silent guess (`dashboard.js:132,395-409`); mock and real cards share the `-http_defense-s0` run-id namespace, so the warning is also what stands between a reviewer and the "mock presented as Qwen" anti-reference.
5. Server-side, the service itself asserts nothing about detection completeness — `README.md:152-157`: "These decisions are deterministic policy checks, not proof that every possible prompt injection or cyberattack is detected. The service has no authentication by default and must not be exposed directly to an untrusted network." The reachability gate exists precisely because a defense scoring well on an attack nobody reached proves nothing.

## 8. Contradictions / gaps found (summary)

1. **`README.md:168` `-p 8080:8080` publishes the unauthenticated API on every host interface**, contradicting the "keep it bound to localhost" rule at `README.md:134`. Concrete fix: `-p 127.0.0.1:8080:8080`.
2. **Comparison-warning blind spot (measured):** v3 vs v5 real scorecards differ only in `deterministic_digest`/`score.core`, which the `metadataKeys` list omits (`dashboard.js:302-308`) ⇒ the "uncontrolled comparison" warning never fires for the one comparison this project actually ships.
3. **`attack_reached` has no producer:** present only in `dashboard.js` (+ its test); no artifact, and not the organizer evaluator (repo-wide grep). The UI row is a forward-compatible stub; the brief's reachability distinction is not satisfied by data.
4. **No HTTP request-body limit**, only per-field pydantic caps (largest accepted body ≈ 4 MB, buffered in memory).
5. **`tests/test_dashboard.py` validates source substrings, not behaviour** — it can pass while the rendered dashboard is broken, and fails on harmless renames.
6. **No high-contrast (`forced-colors`) CSS** though the brief asks for high contrast; ARIA tabs pattern incomplete (no `tabpanel`, no arrow-key switching); trust labels collapsed 6→3 buckets against `PRODUCT.md` principle 3.
7. **Two dependency sources of truth** (`pyproject.toml:12-14` ranges vs `requirements.lock:1-14` exact pins) with no test reconciling them; `test_project_metadata.py` checks only one string.
8. **`.dockerignore` misses `evaluation/` (2.4 MB) and `scripts/`**; build context ≈ 4.7 MB, never copied into the image but wasted.
