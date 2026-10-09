# Component ablations

AegisGraph's defence is a pipeline of separable mechanisms. To measure each
mechanism's contribution to security, false blocks and escalations, the
real-model campaign needs a configuration that disables **exactly one**
mechanism at a time. This document defines those configurations, their exact
code sites, what each disables, how a run records the ablation, and the rule
that an ablated run is never reported as the defence.

An ablation is a **research configuration, never product behaviour**:

* the default path (`AEGISGRAPH_ABLATION` unset) is byte-identical in behaviour
  to the unmodified service;
* an ablated run is impossible in production — the service refuses to start;
* every ablated decision is visibly marked in its metadata, its receipt and the
  service's version surface, so an ablated run is identifiable from its
  artifacts alone.

## 1. The switch

One enum, one environment variable, one field on the evaluation options.

| Item | Location |
| --- | --- |
| Enum `Ablation` (four members) | `backend/aegisgraph/engine.py` — `class Ablation` |
| Field on the options | `backend/aegisgraph/engine.py` — `EvaluationOptions.ablation` |
| Public entry points | `evaluate(..., ablation=...)`, `decide(..., ablation=...)`, `validate_rewrite(..., ablation=...)` |
| Environment variable | `AEGISGRAPH_ABLATION` (`settings.ABLATION_ENV`) |
| Parsing | `backend/aegisgraph/settings.py` — `_ablation` |
| Production refusal | `backend/aegisgraph/settings.py` — `validate_settings` |

The variable takes one of the four member values, case-insensitively. An unknown
value is a **configuration error** that fails closed (`validate_settings` raises
`ConfigurationError`): a misspelled mechanism must never run an unablated
configuration that its own labels would present as ablated.

`AEGISGRAPH_ENV=production` with any ablation set is refused at startup:

```
aegisgraph.settings.ConfigurationError: AEGISGRAPH_ABLATION=strict_confirmation
is refused in AEGISGRAPH_ENV=production: an ablation is a research configuration,
never a product path; unset it
```

## 2. The mechanisms

Each mechanism has exactly one switch site, carrying a comment that names the
mechanism, the reason code it suppresses, and the campaign consequence. There is
no `if <ablation>` scattered through the pipeline.

| Ablation value | Code site | What it disables | Reason code suppressed |
| --- | --- | --- | --- |
| `provenance_enforcement` | `engine.py` `_evaluate` (before the `PROVENANCE_INCOMPLETE` gate) | The engine stops consulting provenance labels: completeness and every observation's `trust_level` are neutralised for the evaluation. | `PROVENANCE_INCOMPLETE`, `UNTRUSTED_INSTRUCTION`, `UNTRUSTED_MEMORY_INHERITED`, `UNTRUSTED_AUTHORITY_*` |
| `trust_ceiling` | `access.py` `assert_trust_ceiling` | The bound that caps how far a caller's induced labels may be believed. | `TRUST_CEILING_EXCEEDED` (403) |
| `strict_confirmation` | `engine.py` `_evaluate` (the `requires_confirmation` arm) | The strict, store-backed grant channel: a consequential action with no bound grant is treated as policy-valid. | `CONFIRMATION_REQUIRED` |
| `rewrite_revalidation` | `engine.py` `_validate_rewrite` (after the structural traps) | The mandatory re-evaluation of the exact replacement action. | `UNSAFE_REWRITE` (and the replacement's effect-escalation check) |

### Provenance enforcement

The pipeline consults provenance in four places — the `PROVENANCE_INCOMPLETE`
gate, `_coupled_instruction` (`UNTRUSTED_INSTRUCTION`), `_has_untrusted_evidence`
(`UNTRUSTED_MEMORY_INHERITED`) and `_redact_untrusted_authority`. They all read
the same two signals: the request's completeness and each observation's
`trust_level`. The switch is therefore a single site that removes exactly those
signals (`_unlabelled_provenance`), not four conditionals. Sensitivity, the
action, `least_trust` metadata and every other gate are untouched, which is what
makes this one mechanism.

### Trust-ceiling enforcement

The bound lives in `access.py` (`assert_trust_ceiling`), the only place a request
is bound to a caller, and is called once from the generic decision surface
(`api_v1.py`). It is **not** inside the engine: the engine never sees the caller's
ceiling, so the ablation is a separate, separable mechanism. Disabling it lets a
caller assert any trust label; the engine then evaluates the labels it is given.

### Strict confirmation channel

The channel is the `requires_confirmation(...)` → `CONFIRMATION_REQUIRED`
escalation. `requires_confirmation` still decides *which* tools are
consequential — that is policy, not the channel — so only the escalation changes.
A genuinely confirmation-bound action still reports `CONFIRMATION_VERIFIED`
unchanged; only the no-grant case becomes `POLICY_CHECKS_PASSED`.

### Rewrite revalidation

`_validate_rewrite` first runs structural traps (finality escalation,
confirmation bypass, final-action change) and the original-action downgrade
check; those are separate mechanisms and still run under the ablation. The
ablation removes only the re-evaluation of the replacement
(`_evaluate(rewritten, ...)`), so a replacement that would fail policy is
accepted with `SAFE_REWRITE`.

### Separability

All four mechanisms are separable, with one structural caveat that the tests
pin:

* the trust ceiling is enforced in the access path, not in the engine, so it is
  not entangled with the provenance gate;
* the provenance gate's four checks share one input (provenance labels), so
  they are one mechanism, not four;
* the confirmation channel and rewrite revalidation are distinct switch sites
  with distinct reason codes, and each leaves the other's gate unchanged.

No mechanism was found inseparable; the separable subset is all four.

## 3. How a run records an ablation

An ablated decision is marked in three artifacts:

1. **Response metadata** — `metadata.ablation` names the mechanism
   (`engine._mark_ablation`). The default path adds no key, so the default
   response is byte-identical.
2. **Receipt / audit record** — the durable receipt body
   (`ReceiptRecord.decision_body`) carries the same metadata; the structured
   decision log line grows an `ablation` key **only** for an ablated run
   (`api_v1._log_decision`), so the default record shape is unchanged.
3. **Version surface** — `GET /api/v1/version` reports `ablation` only when one
   is active (`api_v1.version`, `response_model_exclude_none`), so an ablated
   service is identifiable before any request is sent:

```json
{"api_version": "aegisgraph/v1", "policy_set": {"id": "aegisgraph-default", "version": "1"},
 "build": {"service": "aegisgraph", "version": "0.1.0", "commit": "unknown"},
 "ablation": "rewrite_revalidation"}
```

**Rule.** An ablated run is never reported as the defence. The ablation name is
part of the decision, the receipt and the version, so a result produced with a
mechanism disabled cannot be mistaken for, or cited as, the defence's measured
behaviour.

## 4. Live evidence

Each ablation below was exercised against a running service
(`uvicorn aegisgraph.app:app`) started with the switch, and the full defence's
response is shown beside the ablated one. The two requests differ only in the
`AEGISGRAPH_ABLATION` the process was started with.

### Provenance enforcement

`POST /api/v1/decisions` with an observation whose provenance id is unknown.

Full defence (`HTTP 200`):

```json
{"decision": "block", "reason_codes": ["PROVENANCE_INCOMPLETE"], "risk_score": 0.97,
 "metadata": {"least_trust": "adversary_controlled", "max_sensitivity": "restricted"}}
```

Ablated (`AEGISGRAPH_ABLATION=provenance_enforcement`, `HTTP 200`):

```json
{"decision": "allow", "reason_codes": ["BENIGN_ACTION"], "risk_score": 0.05,
 "metadata": {"least_trust": "adversary_controlled", "max_sensitivity": "restricted",
              "ablation": "provenance_enforcement"}}
```

### Strict confirmation channel

`POST /api/v1/decisions` with a consequential `payment_execute` and no grant.

Full defence (`HTTP 200`):

```json
{"decision": "escalate", "reason_codes": ["CONFIRMATION_REQUIRED"], "risk_score": 0.72,
 "metadata": {"least_trust": "authenticated_user", "max_sensitivity": "internal"}}
```

Ablated (`AEGISGRAPH_ABLATION=strict_confirmation`, `HTTP 200`):

```json
{"decision": "allow", "reason_codes": ["POLICY_CHECKS_PASSED"], "risk_score": 0.16,
 "metadata": {"least_trust": "authenticated_user", "max_sensitivity": "internal",
              "ablation": "strict_confirmation"}}
```

### Trust ceiling

`POST /api/v1/decisions` with an opaque service token whose ceiling is
`trusted_internal`, asserting `system_policy`.

Full defence (`HTTP 403`):

```json
{"code": "TRUST_CEILING_EXCEEDED",
 "detail": "the request asserts trust_level 'system_policy' above the caller ceiling 'trusted_internal'"}
```

Ablated (`AEGISGRAPH_ABLATION=trust_ceiling`, `HTTP 200`):

```json
{"decision": "allow", "reason_codes": ["POLICY_CHECKS_PASSED"], "risk_score": 0.08,
 "metadata": {"least_trust": "authenticated_user", "max_sensitivity": "internal",
              "ablation": "trust_ceiling"}}
```

### Rewrite revalidation

There is **no HTTP route** that exercises `validate_rewrite`: it is a
library/SDK entry point (`backend/aegisgraph/enforcement.py` refuses a `rewrite`
receipt as `REWRITE_NOT_REVALIDATED` at execution time), and the generic
decision surface never accepts a replacement action. This ablation is therefore
demonstrated through the public entry point rather than over HTTP.

`validate_rewrite(request, shadow_export)`:

Full defence:

```json
{"verdict": "block", "reason_codes": ["UNSAFE_REWRITE", "UNAUTHORIZED_TOOL"],
 "risk_score": 1.0, "rewritten_action": null,
 "metadata": {"least_trust": "trusted_internal", "max_sensitivity": "internal"}}
```

Ablated (`ablation=REWRITE_REVALIDATION`):

```json
{"verdict": "rewrite", "reason_codes": ["SAFE_REWRITE"], "risk_score": 0.2,
 "rewritten_action": {"type": "tool_call", "tool": "shadow_export", "arguments": {}},
 "metadata": {"least_trust": "trusted_internal", "max_sensitivity": "internal",
              "ablation": "rewrite_revalidation"}}
```

## 5. Running an ablated configuration

```bash
AEGISGRAPH_ABLATION=strict_confirmation uvicorn aegisgraph.app:app --port 8000
```

The service reports the active ablation at `GET /api/v1/version`, and every
decision it returns carries `metadata.ablation`. Setting
`AEGISGRAPH_ENV=production` together with any ablation value is refused at
startup. `tests/test_ablations.py` pins all of the above: each ablation's paired
outcome, the unrelated gates that must not move, the production refusal, and the
byte-identical default path.
