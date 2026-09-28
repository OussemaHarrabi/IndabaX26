# Module 6 — AegisGraph, part 1: shape of the system and its data contracts

> **What this module gives you:** the map of the whole defense — what each file does, how one HTTP request becomes one canonical action, and exactly where trust comes from for every piece of evidence the engine sees. You will also see the fail-closed boundaries and one honest finding about a trust rule the client gets to choose.

**Prerequisites:** [Module 5](05-baseline-defenses.md)

---

## 1. AegisGraph in one sentence

> AegisGraph is a small, deterministic HTTP service that reads a SENTINEL **decision request**, converts the loose wire fields into a strict internal **canonical action**, and returns one of four **decisions** — `allow`, `block`, `escalate`, `rewrite` — without ever executing the proposed action.

Read that second clause again, because it is the whole point. The service is a **reference monitor**: a checkpoint that inspects a proposed action and issues a verdict. It does not run tools, does not call a model, does not write memory. The docstring on the one endpoint says it plainly: "candidate actions are never executed" (`backend/aegisgraph/app.py:85`).

Two clarifications that prevent a lot of confusion later:

- **It is rules, not a model.** Every verdict comes from deterministic Python policy code. There is no LLM inside the defense. That is why the same request always yields the same answer (Section 7).
- **It is not a classifier you train.** The project never fits weights for the defense. The only model in the picture is the *agent* on the harness side, which proposes the candidate actions the defense judges.

## 2. The path of one request

Five stages, left to right. Each stage has exactly one job.

```text
POST /v1/decision
        |
        v
[ sentinel.py ]        parse the loose SENTINEL v1 wire request
        |              (forward-compatible: unknown envelope fields dropped)
        v
[ adapter.py ]         resolve provenance, bound the evidence, build the
        |              canonical action; mark incomplete/truncated evidence
        v
[ contracts.py ]       the strict canonical model the engine is allowed to see
        |              (frozen, bounded, shape-checked)
        v
[ engine.py / policy.py ]  apply deterministic rules -> a GuardDecision
        |                  (Module 7)
        v
[ app.py ]             serialize one bounded SENTINEL response, or fail closed
```

- **`sentinel.py`** is the *wire* model: the exact JSON shape the organizer harness sends and expects (`backend/aegisgraph/sentinel.py:159-224`). It is written to be tolerant of fields it does not know yet (`extra="ignore"`, `sentinel.py:50-52`).
- **`adapter.py`** is the only bridge between the two model families. The engine imports it and never touches wire types directly (`backend/aegisgraph/adapter.py:1`, imported at `engine.py:8`).
- **`contracts.py`** is the *canonical* model — the frozen, policy-neutral facts the rule engine reasons about (`backend/aegisgraph/contracts.py:97-99`).
- **`engine.py` / `policy.py`** are the rules. They are the subject of [Module 7](07-the-decision-kernel.md); this module stops at the engine's front door.
- **`app.py`** is the thin HTTP boundary (`backend/aegisgraph/app.py:30-108`).

The reason to split "wire" from "canonical" at all is the theme of the next two sections.

## 3. The canonical action model

The engine never reads JSON. It reads five small, frozen classes in `contracts.py`. Frozen means you cannot change one after it is built — trying raises an error, and a test asserts it (`tests/test_contracts.py:30`).

**Enums first.** An **enum** is a fixed set of allowed strings.

- **Trust level** — how much the system believes a piece of text. Ordered from most to least trusted: `system_policy`, `authenticated_user`, `trusted_internal`, `untrusted_internal`, `untrusted_external`, `adversary_controlled` (`contracts.py:67-74`). The ordering is real: the class defines `<` by declaration order (`contracts.py:59-64`), so the engine can ask "is this source less trusted than that sink?" with a plain comparison.
- **Sensitivity** — how damaging the data is if it moves somewhere it should not: `public`, `internal`, `confidential`, `restricted` (`contracts.py:76-81`).
- **Action kind** — `respond`, `tool_call`, `memory_write`, `request_confirmation` (`contracts.py:83-88`).
- **Verdict** — `allow`, `block`, `escalate`, `rewrite` (`contracts.py:90-95`).

**`Observation`** (`contracts.py:101-108`) is one bounded input plus its security labels:

| field | type | bound |
|---|---|---|
| `kind` | string | 1–64 chars, lowercase snake case (`^[a-z][a-z0-9_]*$`) |
| `content` | string | ≤ 16 000 chars (`MAX_CONTENT_CHARS`) |
| `source` | string | 1–256 chars |
| `trust_level` | enum | required |
| `sensitivity` | enum | defaults to `internal` |

**`CandidateAction`** (`contracts.py:111-170`) is the proposed action. Its fields: `type`; `tool` (optional, must match `^[a-z][a-z0-9_]{1,63}$`, so a tool name is 2–64 lowercase characters); `arguments` (a small map); `content` (≤ 16 000 chars); `final` (a boolean); and `confirmation_for` (an optional nested `CandidateAction`).

Argument values are deliberately flat — `str | int | float | bool | None` only, no nested objects or lists (`contracts.py:31`). Validators then enforce (`contracts.py:123-136`):

- at most **32** arguments;
- every key must be a valid Python identifier and ≤ 64 characters;
- every string value ≤ 8 000 characters (`MAX_ARGUMENT_CHARS`);
- every float must be finite (no `NaN`/`inf`).

A second validator, `_shape_matches_type` (`contracts.py:142-161`), enforces that the *shape* matches the *type*: a `tool_call` needs `tool` and must not carry `content`; `respond` and `memory_write` need `content` and must not carry `tool`/`arguments`; `request_confirmation` must wrap a `tool_call` in `confirmation_for`; and only `respond` may set `final=True`.

**`GuardRequest`** (`contracts.py:172-195`) is the complete engine input: a `request_id` (≤ 128 chars, `^[A-Za-z0-9][A-Za-z0-9._:-]*$`), a non-empty `user_goal` (≤ 16 000 chars), `observations` (at most **128**), the `candidate_action`, and a `policy_context` map bounded to 16 384 bytes of JSON (`MAX_CONTEXT_BYTES`).

**`GuardDecision`** (`contracts.py:198-233`) is the engine output: a `verdict`; `risk_score` and `confidence` in `[0,1]`; up to 16 `reason_codes`, each matching `^[A-Z][A-Z0-9_]{1,63}$`; an `explanation` ≤ 500 chars; an optional `rewritten_action`; and a `metadata` map ≤ 4 096 bytes. One consistency rule ties the verb to the payload: `rewrite` requires a `rewritten_action`, and any other verdict forbids one (`contracts.py:228-233`).

### Two fingerprints, on purpose

The model can produce two different hashes of the same action:

- **`action_digest`** (`contracts.py:249-262`) is the **confirmation digest** the protocol uses to match a human approval to a later execution. It *normalizes*: argument keys are sorted, whitespace inside strings is collapsed, an integral float like `12.0` becomes `12`, and `final` is ignored. The test pins this with an official golden vector: `{amount: 12.0, note: "a   b\n c"}` and `{amount: 12, note: "a b c"}` hash to `2ce0b8de5d0b516fd176a716` (`tests/test_contracts.py:52`, MEASURED).
- **`exact_action_digest`** (`contracts.py:265-285`) is the **execution fingerprint**. It keeps `final`, keeps raw argument text, and recurses into `confirmation_for`. A test shows a non-`final` and a `final` respond share an `action_digest` but differ under `execution_digest` (`tests/test_contracts.py:80`).

The normalization is lossy *by design* (it is what the protocol asked for), and the second digest exists to recover the lost precision for audit. **[INFERENCE]** The practical trap is that anything binding only `action_digest` inherits the loss — two genuinely different executions can share a confirmation signature. The project mitigates this with `exact_action_digest`, but the risk is real and the code comments it as intentional.

## 4. Why a second, stricter internal model

You might ask: `contracts.py` and `sentinel.py` describe nearly the same four action types. Why not reuse one model?

Because the two sides have **opposite jobs**. The wire model must be *forgiving*: the organizer can add a field to the envelope next season, and a defense that crashes on unknown fields fails closed on every request. So the envelope, provenance records, conversation items, observation view, and history digest all use `extra="ignore"` (`sentinel.py:50-52`). A test feeds in `future_envelope_field` and `future` keys and asserts they are dropped (`tests/test_sentinel_adapter.py:52-63`).

But in two places the wire model is **strict** (`extra="forbid"`):

- `SentinelCandidateAction` — an unknown key inside the action is a hard error, not ignored (`sentinel.py:54-57`, test at `tests/test_sentinel_adapter.py:65-80`).
- `SentinelResponse` — the response shape is closed (`sentinel.py:188-191`).

The canonical model is strict everywhere (`contracts.py:97-99`). The benefit: by the time the engine runs, every field it can read has been re-checked against canonical bounds. A value that passed the lenient wire parse is parsed *again* under the canonical rules, so a looser wire type can never smuggle a value the engine was not written to handle. The adapter is also the single place that knows both vocabularies, which keeps the engine free of wire coupling.

## 5. Provenance resolution: where trust comes from

**Provenance** is the audit trail that says *where* a piece of text came from and *how much* it should be trusted. On the wire it is a list of records the request can cite by id (`sentinel.py:123-125`). The adapter's central job is to turn each cited id into a trust label on an `Observation`, so the engine can compare "untrusted content" against "trusted sink" (Module 7).

The adapter builds an index of provenance records once (`adapter.py:43-47`) and then walks every conversation item, plus the single `observation`, through one function, `append_resolved` (`adapter.py:54-93`). Three cases matter.

### Case 1 — a cited id that resolves

The item has `provenance_ids: ["prov-1"]`, and `prov-1` exists in `provenance`. The adapter copies the trust level and sensitivity **verbatim from the wire record** and mints an observation whose `source` string is `<id>:<source_type>:<source_id>` (`adapter.py:83-93`).

Honesty note: nothing here verifies the declared label against the actual origin. **[INFERENCE]** The whole trust model rests on the harness honestly labeling its own sources. This is an assumption the design *chooses* to make, not a cryptographic guarantee.

### Case 2 — an id that is missing or duplicated

If the cited id is not in the index, `records.get(identifier)` returns `None`, and the adapter marks the whole request **incomplete** (`complete = False`) and emits an observation labeled `source="unresolved:<id>"`, `trust_level=adversary_controlled`, `sensitivity=restricted` (`adapter.py:75-80`, helper at `adapter.py:151-159`). The engine then returns a `block` with reason code `PROVENANCE_INCOMPLETE` (`engine.py:467-468`), regardless of what the candidate action was.

Duplicates take the same path. The index is built with `records[record.id] = None if record.id in records else record` (`adapter.py:47`), so a repeated id overwrites the real record with `None`, and any later citation of it is treated as unresolved. **[INFERENCE]** This is fail-closed, but the first record is silently discarded and no error names the duplicate — the id simply becomes indistinguishable from "never declared".

### Case 3 — no ids, and the implicit-trust rule (an audit finding)

This is the case worth slowing down for. If a conversation item carries **no** `provenance_ids`, the adapter does not mark it unresolved. Instead it looks at the item's `role` and mints a label (`adapter.py:56-67`):

| role, with no ids | resulting trust | source string |
|---|---|---|
| `user` | `authenticated_user` | `implicit:user` |
| `agent`, `safety`, `human` | `trusted_internal` | `implicit:<role>` |
| anything else (`tool`, `memory`, observation) | `untrusted_internal` | `unattributed:<role>` |

The contrast is the finding. An *explicit* id that fails to resolve becomes `adversary_controlled` and blocks the request. An item that simply *omits* its ids can be auto-promoted to `authenticated_user` — and the omission is **not** recorded as incomplete.

Why this is a finding, stated factually:

- The wire client chooses the `role` (`sentinel.py:129`) **and** chooses whether to include `provenance_ids`.
- So a client can present attacker-influenced text under `role="user"` with no ids and have it trusted as if a real authenticated user wrote it.
- Trust is therefore **self-asserted** by the client in this path, and the defense accepts it without a completeness flag (`adapter.py:55-68`).

The code's own docstring frames it as deliberate: evidence "supplied without provenance identifiers remains usable but is marked unattributed and untrusted rather than being confused with a broken integrity reference" (`adapter.py:40-43`). That is true for the `tool`/`memory` roles — but the `user`/`agent`/`safety`/`human` branch does the opposite of "untrusted": it *widens* trust. `[INFERENCE]` The likely rationale is that a legitimate harness always labels turn text as `user`; the cost is that the defense cannot distinguish a well-labelled turn from a self-labelled attack. This module presents it as a documented gap in the trust model, not as a feature.

### Everything else the adapter decides

Beyond the three cases, `adapt_request` also (`adapter.py:107-134`):

- computes `least_trust` and `max_sensitivity` across all observations (with defaults `authenticated_user` / `internal` when there are none, `adapter.py:107-116`) — these become the `metadata` on the response;
- derives a canonical `request_id` as `"request:" + sha256(run_id + "\x00" + step_id)[:32]` (`adapter.py:120`, helper at `adapter.py:178-181`);
- replaces an empty `user_goal` with the literal `"Unspecified user goal"` (`adapter.py:121`) — the wire model permits an empty goal but the canonical model requires a non-empty one (`sentinel.py:164` vs `contracts.py:180`), so the mismatch is smoothed over rather than rejected;
- normalizes `kind` to fit the canonical pattern with `_safe_kind` (`adapter.py:171-176`), which lowercases, replaces non-conforming characters with `_`, and truncates to 64. **[INFERENCE]** this is lossy: two distinct wire `kind` values could collapse to one canonical value with no collision check;
- compacts any `source` string longer than 256 characters into `source:<sha256>` (`adapter.py:183-187`).

## 6. Bounded, fail-closed I/O

"**Fail closed**" means: when something is wrong or unknown, the system chooses the *safe* outcome (`block`), never the permissive one (`allow`). AegisGraph applies this at several layers.

**Field caps.** Every string, map, and list the request can carry has a ceiling: content 16 000, one argument 8 000, at most 32 arguments, argument keys ≤ 64 and identifier-shaped, tool names 2–64, `policy_context` 16 384 bytes, and on the way out `reason_codes` ≤ 16, `explanation` ≤ 500, `metadata` ≤ 4 096 bytes (`contracts.py:25-29`; wire mirrors at `sentinel.py:54-108`, `sentinel.py:176-181`).

**The 128-observation truncation.** A request can carry many conversation items and each one may cite several provenance ids, so the number of observations can exceed the canonical cap of 128. The adapter does not reject; it *selects*. `_select_security_relevant_observations` (`adapter.py:190-206`) ranks observations by `(-trust_index, -sensitivity_index, original_index)` and keeps the 128 that are **least trusted and most sensitive**, then restores their original order. In other words, when it must drop evidence, it drops the *benign* evidence and keeps the *suspicious* evidence.

But "keeps the suspicious ones" is a heuristic, not a proof. `[INFERENCE]` a benign-but-relevant item can vanish, and the only trace left is the boolean flag `evidence_truncated = len(observations) > 128` (`adapter.py:133`). The engine consumes that flag as a block with reason code `EVIDENCE_TRUNCATED` (`engine.py:471-472`).

**Generic error bodies.** Malformed input never leaks field names or values. The app installs a handler that turns any request-validation error into the constant body `{"detail": "Invalid SENTINEL request"}` with status 422 (`app.py:65-67`), and routing errors into either that constant or `{"detail": "Request could not be safely processed"}` with the original status (`app.py:70-75`). A test plants a secret in a bad request and asserts it does not come back (`tests/test_http_service.py:110`).

**The 64 KB response cap with a block fallback.** After a decision is built, the app serializes it and checks the byte length against `_MAX_RESPONSE_BYTES = 64_000` (`app.py:20`, `app.py:91-92`). If the response is too large — reachable in principle because a `rewrite` can carry a `tool_call` with 32 arguments of 8 000 characters each — the endpoint does **not** send it. Instead, *any* exception while building or validating the response falls into one catch-all that returns HTTP 200 with a fixed `block` (`app.py:94-105`): `risk_score = 1.0`, `confidence = 1.0`, `reason_codes = ("INTERNAL_EVALUATION_FAILED",)`. The comment states the invariant directly: "A valid request reaching policy must never become an allow on an error" (`app.py:96`).

That same bound appears on the organizer side — the harness treats a body over 64 000 bytes as a defense failure (`.sentinel_reference/src/sentinel/defenses/client.py:14,78`), so the two ends agree.

## 7. The service surface

The entire HTTP surface is one 116-line file (`app.py`). Routes:

| route | method | meaning |
|---|---|---|
| `/` | GET | the local dashboard (a static HTML file) |
| `/assets/...` | static | dashboard JS/CSS |
| `/healthz` | GET | liveness only, returns `{"status": "ok"}`; does not touch the engine (`app.py:78-80`) |
| `/v1/decision` | POST | one decision (`app.py:83-108`) |

Design choices, each with a reason:

- **No authentication.** There is no API key, session, or auth middleware anywhere in the package. This is *documented*, not hidden: the README says the service "has no authentication by default and must not be exposed directly to an untrusted network" (`README.md:155-157`) and "keep it bound to localhost" (`README.md:134`). It is a local prototype by intent.
- **Local-only binding.** The documented run command binds loopback explicitly: `--host 127.0.0.1 --port 8080` (`README.md:125`).
- **Docs disabled.** `docs_url=None, redoc_url=None, openapi_url=None` (`app.py:30-35`), so `/docs` and `/openapi.json` return 404 — asserted in `tests/test_http_service.py:40-46`.
- **CSP and client-side-only dashboard.** Every response gets `Cache-Control: no-store`, `Pragma: no-cache`, and `X-Content-Type-Options: nosniff` (`app.py:57-59`); the HTML asset additionally gets a strict `Content-Security-Policy` including `connect-src 'none'` (`app.py:24-28`, `app.py:60-61`). The dashboard is pure client-side: it reads files you pick and never uploads them (`static/index.html:36`), has hard limits of 25 MiB per file and 100 000 events (`static/dashboard.js:4-5`), and persists nothing.

### Two places where docs and code disagree

Both are worth stating plainly, because "documented prototype" and "documented prototype with a footgun" are different things.

1. **The Docker port publish contradicts the localhost rule.** The README tells you to keep the unauthenticated service bound to localhost (`README.md:134`), then a few paragraphs later gives a `docker run ... -p 8080:8080` (`README.md:168`). `-p 8080:8080` publishes the port on **all** host interfaces, not just loopback. With no authentication, that is the one concrete deployment mistake in the packaging. The fix is to publish to loopback only: `-p 127.0.0.1:8080:8080`. `[INFERENCE]` This is a documentation defect, not a code defect — the app itself cannot control how the container is published.
2. **No HTTP-layer request-body cap.** Per-field pydantic bounds exist, but nothing inspects `Content-Length` and no middleware limits the body. A worst-case accepted body is roughly 256 conversation items × 16 000 characters plus provenance and context — on the order of a few megabytes, buffered in full before validation. `[INFERENCE]` a single large POST can pin memory; no test covers it.

Neither of these is a hidden vulnerability; both are places where the code is looser than the prose implies. Naming them is the honest move.

## 8. Why this design is auditable

The architecture is deliberately boring, and boring is exactly what you want from a security component you must defend to a jury:

- **Purity and determinism.** The decision path holds no server-side state: no session, no cache, no run store, nothing written to disk. Each request is evaluated independently. Combined with rule-based (not model-based) policy, this gives the property "same request in, same decision out." **[INFERENCE]** The statelessness is a structural fact of the code (no module-level mutable state in `engine.py`/`policy.py`/`adapter.py`), though no test asserts it.
- **Explicit reason codes.** Every verdict carries machine-readable `reason_codes` in a fixed UPPER_SNAKE vocabulary, so a reviewer can tell *why* without reading the explanation text. The code vocabulary is defined by a single pattern, so a stray free-text code becomes a validation failure rather than a leak.
- **Hashes that pin the revision.** The canonical request id is a content hash of `run_id` and `step_id` (`adapter.py:178-181`), and the two action digests bind the exact action semantics. Together with the evaluator's own deterministic digest, these let you prove which revision produced a given measured result — which is why [Module 8](08-evidence-and-evolution.md) can talk about "the v5 revision" and mean one specific artifact.

That is the through-line for the rest of the course: a small transparent pipeline (this module), a rules engine with explicit reason codes (Module 7), and evidence that pins exactly what was measured (Module 8).

## Check yourself

1. In one sentence, what does AegisGraph return for each candidate action, and what does it never do?
   - It returns exactly one of `allow`, `block`, `escalate`, `rewrite` for the proposed action; it never executes that action (`app.py:85`).

2. Why does the project keep a separate canonical model in `contracts.py` instead of trusting the wire types in `sentinel.py`?
   - The wire model must be forgiving (`extra="ignore"`) for forward compatibility, while the canonical model is strict and bounded everywhere (`contracts.py:97-99`). Re-validating into canonical types means the engine only ever reads fields that passed the strict bounds, and the engine stays free of wire coupling.

3. A request cites `provenance_ids: ["prov-x"]` and `prov-x` is not in `provenance`. What trust does the observation get, and what does the engine do?
   - The observation is labelled `unresolved:prov-x`, `adversary_controlled`, `restricted`, and the request is marked incomplete (`adapter.py:75-80`); the engine returns a `block` with `PROVENANCE_INCOMPLETE` (`engine.py:467-468`).

4. Now the same request cites no ids at all, with `role="user"`. What changes?
   - The observation is labelled `implicit:user` with trust `authenticated_user` and is *not* marked incomplete (`adapter.py:56-67`). This is the trust-widening finding: the client chose both the role and the omission, so the trust is self-asserted.

5. What does the 128-observation truncation keep, and what flag does it set?
   - It keeps the 128 least-trusted, most-sensitive observations, re-sorted to their original order (`adapter.py:190-206`), and sets `evidence_truncated = True` when observations exceeded 128 (`adapter.py:133`). The engine then blocks with `EVIDENCE_TRUNCATED` (`engine.py:471-472`).

6. A `rewrite` decision would produce a response larger than 64 KB. What is sent?
   - Not the oversized response: the size check raises (`app.py:91-92`) and the endpoint returns a fixed HTTP 200 `block` with `risk_score = 1.0`, `confidence = 1.0`, `INTERNAL_EVALUATION_FAILED` (`app.py:94-105`).

7. Why are `action_digest` and `exact_action_digest` different?
   - `action_digest` is the protocol's confirmation digest and normalizes whitespace, integral floats, and ignores `final` (`contracts.py:249-262`, `contracts.py:287-292`); `exact_action_digest` keeps those distinctions so a confirmation signature can never stand in for an exact execution fingerprint (`contracts.py:265-285`).

## Where this lives in the repo

- `backend/aegisgraph/sentinel.py:159-224` — the wire request/response envelope: lenient envelope, strict candidate action and response, provenance records, history digest.
- `backend/aegisgraph/contracts.py:67-95` — the four enums, including the trust ordering that makes trust comparisons meaningful.
- `backend/aegisgraph/contracts.py:101-170` — `Observation` and `CandidateAction`, with the argument and shape validators.
- `backend/aegisgraph/contracts.py:249-292` — the two digests and the canonicalization that makes `action_digest` lossy by design.
- `backend/aegisgraph/adapter.py:35-134` — `adapt_request`: provenance index, the three trust cases, aggregates, truncation, and the canonical build.
- `backend/aegisgraph/adapter.py:151-169` — the unresolved and unattributed observation labels.
- `backend/aegisgraph/adapter.py:190-206` — the truncation selector that keeps the least-trusted, most-sensitive evidence.
- `backend/aegisgraph/app.py:20-108` — the whole HTTP surface: routes, security headers, generic error bodies, and the fail-closed block fallback.
- `tests/test_contracts.py:52,80` — the golden digest vector and the `action_digest` vs `execution_digest` distinction (measured).
- `tests/test_sentinel_adapter.py:52-80` — forward-compatible envelope parsing and strict candidate-action parsing.
- `tests/test_http_service.py:40-110` — docs disabled, exact response key set, payload non-echo, and sanitized 422.
- `README.md:134-135,155-157,168` — the documented local-prototype caveat and the Docker publish contradiction.
