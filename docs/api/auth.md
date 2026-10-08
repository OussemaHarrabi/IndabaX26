# Authentication and authorization

Status: Milestone 2. Closes finding **F1** (unauthenticated decision boundary) and
the caller-authority half of **F3**; implements decisions **D1**, **D2**, **D3**,
**D5** and **D7**.

The service has exactly one protected decision surface — `POST /api/v1/decisions` —
plus the read/administration surfaces in [receipts.md](receipts.md). Every
security-relevant input is now resolved from the *credential*, never from the body.

## 1. Configuration

| Variable | Values | Default | Notes |
| --- | --- | --- | --- |
| `AEGISGRAPH_ENV` | `development`, `production` | `development` | Only `production` applies the hard refusals below |
| `AEGISGRAPH_AUTH_MODE` | `none`, `required` | `none` | `none` is refused in production |
| `AEGISGRAPH_JWT_ISSUER` | string | — | required for JWT verification |
| `AEGISGRAPH_JWT_AUDIENCE` | string | — | required for JWT verification |
| `AEGISGRAPH_JWKS` | **file path** | — | mounted JWKS document; the runtime never fetches a URL |
| `AEGISGRAPH_JWKS_FILE` | file path | — | explicit override, wins over `AEGISGRAPH_JWKS` |
| `AEGISGRAPH_JWKS_URL` | URL | — | recorded for `scripts/jwks_refresh.py`; not read by the service |
| `AEGISGRAPH_JWKS_TTL_SECONDS` | integer ≥ 0 | `300` | how long a JWKS document is cached before a re-read |
| `AEGISGRAPH_JWT_ALGORITHMS` | comma list | `RS256,ES256` | asymmetric only; `HS*` is refused |
| `AEGISGRAPH_SERVICE_TOKENS` | JSON array | — | see below |
| `AEGISGRAPH_SERVICE_TOKEN_FILE` | file path | — | mounted equivalent of the above |
| `AEGISGRAPH_TRUST_CEILING_DEFAULT` | trust level | `trusted_internal` | ceiling for a credential that declares none |
| `AEGISGRAPH_LEGACY_UNAUTHENTICATED` | boolean | `true` in development, `false` otherwise | enables the frozen legacy wire |
| `AEGISGRAPH_BIND_ADDRESS` | host | `127.0.0.1` | must be loopback while the legacy surface is enabled |
| `DATABASE_URL` | SQLAlchemy URL | — | required in production |

### Startup refuses to serve an unsafe process

`python -m aegisgraph.settings` validates the environment, prints one actionable
line and exits `2` on refusal. `backend/aegisgraph/app.py` runs the same check at
import, so `uvicorn` exits before binding. Refused in `AEGISGRAPH_ENV=production`:

* `AEGISGRAPH_AUTH_MODE=none`;
* `AEGISGRAPH_LEGACY_UNAUTHENTICATED=true`;
* a missing `DATABASE_URL` (receipts must survive a restart);
* `AEGISGRAPH_AUTH_MODE=required` with neither a JWT verifier nor service tokens;
* a `AEGISGRAPH_JWKS` path that does not exist.

Also refused in any environment: a JWKS *URL* in `AEGISGRAPH_JWKS` (the decision
process holds no network capability), a non-loopback bind while the legacy surface
is enabled, an unknown trust level, and a symmetric JWT algorithm.

```console
$ AEGISGRAPH_ENV=production python -m aegisgraph.settings
aegisgraph: refusing to start: AEGISGRAPH_AUTH_MODE=none is refused in AEGISGRAPH_ENV=production; set AEGISGRAPH_AUTH_MODE=required
$ echo $?
2
```

## 2. Principals

Every authenticated request resolves to a `Principal` with four fields, all taken
from the credential:

| Field | Source | Purpose |
| --- | --- | --- |
| `principal_id` | JWT `sub` / service-token `id` | audit identity |
| `tenant_id` | JWT `tenant_id` \| `tid` \| `tenant` / service-token `tenant_id` | every query is scoped to it (D1) |
| `scopes` | JWT `scope` \| `scp` \| `scopes` plus role expansion | authorization |
| `trust_ceiling` | JWT `trust_ceiling` / service-token `trust_ceiling` / `AEGISGRAPH_TRUST_CEILING_DEFAULT` | provenance ceiling (D2) |

A credential without a tenant is rejected with `401 INVALID_TOKEN`: the tenant is
never inferred from the body or from a default.

## 3. Credentials

### Asymmetric JWT

Verified against the mounted JWKS with the algorithm pinned to
`AEGISGRAPH_JWT_ALGORITHMS`. The issuer, the audience, the expiry and `nbf` (when
present) are checked; `exp`, `iat` and `sub` are required. The `kid` selects the
key; an unknown `kid` triggers exactly one document re-read, and a document older
than `AEGISGRAPH_JWKS_TTL_SECONDS` is re-read on the next verification.

Because the runtime must not open a socket, a JWKS **URL** is materialised into the
mounted file out of band:

```console
$ python scripts/jwks_refresh.py --url "$AEGISGRAPH_JWKS_URL" --output /run/secrets/jwks.json
```

Run it from an init container, a sidecar or a cron job. `--check` reports the state
of the mounted file without fetching.

### Scoped opaque service token

The service stores only `sha256(token)`; the value itself is never configured,
logged or returned. Records are compared in constant time.

```json
[
  {
    "id": "reporter-a",
    "tenant_id": "tenant-a",
    "sha256": "<64 lowercase hex characters>",
    "scopes": ["decision:submit"],
    "trust_ceiling": "trusted_internal"
  }
]
```

Rotation and revocation are configuration changes: remove the old digest (and the
token stops working immediately), add the new one. Unknown fields in a record are
refused at startup, so a typo cannot silently widen a token.

## 4. Scopes

| Scope | Grants |
| --- | --- |
| `decision:submit` | `POST /api/v1/decisions` |
| `receipt:read` | `GET /api/v1/receipts`, `GET /api/v1/receipts/{id}`, `GET /api/v1/audit-events` |
| `policy:read` | `GET /api/v1/policies`, `GET /api/v1/audit-events` |
| `policy:write` | `POST /api/v1/policies`, `POST /api/v1/policies/{id}/activate` |
| `confirmation:grant` | `POST /api/v1/confirmations` |
| `policy:context_override` | honour caller-supplied `policy_context` (D3) |

Roles expand to scopes:

| Role | Scopes |
| --- | --- |
| `decision_client` | `decision:submit` |
| `auditor` | `receipt:read` |
| `policy_admin` | `policy:read`, `policy:write` |

`confirmation:grant` and `policy:context_override` are **not** implied by any role:
they must be granted explicitly, so a normal decision client cannot confirm its own
consequential action or replace policy facts.

Failures are explicit and carry no credential material:

| Status | Code | Meaning |
| --- | --- | --- |
| 401 | `AUTHENTICATION_REQUIRED` | no `Authorization: Bearer` header |
| 401 | `INVALID_TOKEN` | signature, issuer, audience, algorithm, `kid` or claim shape |
| 401 | `TOKEN_EXPIRED` | the token is past `exp` |
| 403 | `INSUFFICIENT_SCOPE` | the credential lacks a required scope (the missing names are listed) |
| 403 | `TRUST_CEILING_EXCEEDED` | see below |
| 503 | `AUTHENTICATION_UNAVAILABLE` | the process has no usable verifier |

## 5. Trust ceiling (D2)

`TrustLevel` is ordered most-trusted first: `system_policy`, `authenticated_user`,
`trusted_internal`, `untrusted_internal`, `untrusted_external`,
`adversary_controlled`. A request may assert any level **at or below** the caller's
ceiling; asserting a *more trusted* level is refused with
`403 TRUST_CEILING_EXCEEDED`. It is never silently downgraded: a downgrade would
hide a misconfigured integration and would leave the decision looking normal.

With the default ceiling `trusted_internal`, a `decision_client` may label evidence
as `trusted_internal` or lower, but cannot claim `system_policy` or
`authenticated_user` — which is precisely the relabelling move F3 described.
Claiming *less* trust is always allowed: it only makes the engine stricter.

## 6. Policy authority (D3) and policy identity (H2-02)

The **identity** a decision reports is always a server value, never a caller-asserted
string:

* The request may name `policy_set {id, version}`. The server looks that version up
  in its own store. If it is not stored for the caller's tenant, the request is
  refused with `422 POLICY_SET_UNKNOWN` — regardless of the caller's scopes, so an
  override holder cannot invent an identity either. A refused request writes no
  receipt, so no receipt can claim a policy version that did not decide.
* When the request names nothing, the server reports its own default identity
  (`{"id": "aegisgraph-default", "version": "1"}`) and, unless the caller holds the
  override scope, decides under that stored version.
* The response, the receipt, and the structured decision record all carry the
  resolved server identity. `enforcement.POLICY_MISMATCH` is therefore meaningful:
  the identity it compares against cannot be chosen by the caller it checks.
* `GET /api/v1/version` reports the same server default identity and accepts no
  caller input that could change it.

The **facts** are a separate question:

* A caller holding `policy:context_override` may supply `policy_context`
  (`allowed_tools`, `consequential_tools`, `internal_email_domains`, …) on top of the
  stored version it named. This is the frozen trusted-caller behaviour and the
  labelled development mode.
* Every other caller has its `policy_context` **ignored**: the stored document is
  used, so editing the request can never switch a control off.

Publish and activate the server-side policy through `POST /api/v1/policies`
(see [receipts.md](receipts.md)).

## 7. Legacy surface (D5)

`POST /v1/decision` is the frozen SENTINEL wire and is deliberately **not**
authenticated and **not** receipt-bearing: its measured behaviour is preserved.
It is available only while `AEGISGRAPH_LEGACY_UNAUTHENTICATED=true` — the
development default — and only on a loopback bind. Production refuses to start with
it enabled, and in development it answers `404` when the flag is off.

## 8. The development-only issuer

`scripts/dev_issuer.py` mints tokens against a local JWKS file. It is **not** a
production identity provider and every artefact it writes carries
`"aegisgraph_label": "development-only"`.

```console
$ python scripts/dev_issuer.py init
$ python scripts/dev_issuer.py mint --tenant tenant-a --role decision_client
$ export AEGISGRAPH_AUTH_MODE=required \
         AEGISGRAPH_JWT_ISSUER=https://dev-issuer.aegisgraph.local \
         AEGISGRAPH_JWT_AUDIENCE=aegisgraph \
         AEGISGRAPH_JWKS="$(python scripts/dev_issuer.py show | python -c 'import json,sys;print(json.load(sys.stdin)["jwks"])')"
```

The default output directory is a temporary directory **outside** the repository, so
a generated private key cannot be committed by accident. If you pass `--directory`
inside the repository, add it to `.gitignore` first.

## 9. Secret handling

* No secret is committed. `AEGISGRAPH_JWKS_FILE` and `AEGISGRAPH_SERVICE_TOKEN_FILE`
  exist so a deployment can mount secrets read-only instead of passing them in the
  environment.
* Service tokens are stored as digests; the plaintext value is never needed by the
  service.
* `safe_summary()` — printed by the startup check — reports only presence and
  shape: counts, booleans, the issuer and audience, and never a digest, a token, a
  key or the database URL.
* The structured decision record carries `caller` (the `principal_id`) and never a
  credential; `tests/test_authentication.py` asserts that neither the token nor its
  digest nor any request content appears in the logs.
