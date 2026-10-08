"""Request-level authorization: principals, scopes, trust ceiling and policy authority.

This module is the only place where a request is bound to a caller. It provides the
FastAPI dependencies used by the protected surfaces, plus the two request-level
authorization rules of M2:

* **D2 trust ceiling** — a request may assert a provenance ``trust_level`` at or
  below the principal's ceiling. Above it the request is rejected with 403
  ``TRUST_CEILING_EXCEEDED``; it is never silently downgraded, because a silent
  downgrade hides a misconfigured integration.
* **D3 policy authority** — caller-supplied ``policy_context`` is honoured only
  for a principal holding ``policy:context_override``. Otherwise the effective
  policy is the server-stored policy set named by ``policy_set {id, version}``,
  and an unknown policy set is refused rather than defaulted.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from contextlib import suppress
from typing import Annotated

from fastapi import Depends, Request

from aegisgraph.adapter import IMPLICIT_ROLE_TRUST, UNATTRIBUTED_TRUST
from aegisgraph.auth import (
    INSUFFICIENT_SCOPE,
    SCOPE_POLICY_CONTEXT_OVERRIDE,
    TRUST_CEILING_EXCEEDED,
    AuthError,
    Principal,
    resolve_principal,
)
from aegisgraph.contracts import PolicyIdentity, TrustLevel, thaw_json
from aegisgraph.sentinel import SentinelRequest
from aegisgraph.settings import Settings, load_settings
from aegisgraph.store import ReceiptStore, canonical_json, open_store

POLICY_SET_UNKNOWN = "POLICY_SET_UNKNOWN"
POLICY_CONTEXT_INVALID = "POLICY_CONTEXT_INVALID"
OVERRIDE_POLICY_ID = "caller-override"
"""Identity reported when a caller's own document decides under the override scope.

The version is the first 32 hex characters of the SHA-256 of the canonical JSON of
that document, so the identity is content-addressed: two different documents give
two different identities and no caller string ever appears verbatim (H3-04).
"""


class ProblemError(Exception):
    """A refused API request with an explicit status and machine-readable code."""

    def __init__(self, code: str, detail: str, *, status_code: int = 400) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.status_code = status_code


def settings_dependency() -> Settings:
    """Resolve the configuration for one request (no caching, so tests can vary it)."""

    return load_settings()


def store_dependency(settings: Annotated[Settings, Depends(settings_dependency)]) -> ReceiptStore:
    """Resolve the process store; durable when ``DATABASE_URL`` is configured."""

    return open_store(settings)


def principal_dependency(
    request: Request,
    settings: Annotated[Settings, Depends(settings_dependency)],
) -> Principal:
    """Resolve the caller identity from the credential, never from the body (D1)."""

    return resolve_principal(request.headers.get("authorization"), settings)


SettingsDep = Annotated[Settings, Depends(settings_dependency)]
StoreDep = Annotated[ReceiptStore, Depends(store_dependency)]
PrincipalDep = Annotated[Principal, Depends(principal_dependency)]


def require_scopes(*required: str) -> Callable[[Principal], Principal]:
    """Build a dependency that refuses a caller missing any of ``required``."""

    def dependency(principal: PrincipalDep) -> Principal:
        principal.assert_scopes(*required)
        return principal

    return dependency


def require_any_scope(*alternatives: str) -> Callable[[Principal], Principal]:
    """Build a dependency that accepts a caller holding at least one scope."""

    def dependency(principal: PrincipalDep) -> Principal:
        if not any(scope in principal.scopes for scope in alternatives):
            raise AuthError(
                INSUFFICIENT_SCOPE,
                "missing any of the required scope(s): " + ", ".join(sorted(alternatives)),
                status_code=403,
            )
        return principal

    return dependency


def assert_trust_ceiling(principal: Principal, request: SentinelRequest) -> None:
    """Refuse a request whose induced trust labels exceed the ceiling (D2, H3-01).

    ``TrustLevel`` is ordered most-trusted first, so a level whose rank is *lower*
    than the ceiling's rank claims more trust than the caller is allowed to assert.
    A caller may always claim *less* trust: that only makes the engine stricter.

    The check covers the labels the request can *induce*, not only the ones it
    declares: a conversation item with no provenance ids is labelled by the adapter
    from its role (``user`` becomes ``authenticated_user``, ``agent``/``safety``/
    ``human`` become ``trusted_internal``, anything else becomes
    ``untrusted_internal``). Reading only the declared labels let a caller place
    hostile text in a ``user``-role item and have it treated as authenticated user
    intent, which re-opened the F3 relabelling move.
    """

    declared = _induced_trust_levels(request)
    offending = [
        level for level in declared if _rank(level) < _rank(principal.trust_ceiling)
    ]
    if offending:
        highest = max(offending, key=_rank)
        raise AuthError(
            TRUST_CEILING_EXCEEDED,
            f"the request asserts trust_level {highest.value!r} above the caller ceiling "
            f"{principal.trust_ceiling.value!r}",
            status_code=403,
        )


def induced_trust_ceiling(request: SentinelRequest) -> TrustLevel | None:
    """Return the most trusted label this request can induce, if any."""

    levels = _induced_trust_levels(request)
    return max(levels, key=_rank) if levels else None


def _induced_trust_levels(request: SentinelRequest) -> list[TrustLevel]:
    """Every trust label the adapter would assign while evaluating this request."""

    levels: list[TrustLevel] = []
    for record in request.provenance:
        try:
            levels.append(TrustLevel(record.provenance.trust_level))
        except ValueError:  # pragma: no cover - the wire model constrains the values
            continue
    least = request.history_digest.least_trusted_seen
    if least is not None:
        with suppress(ValueError):
            levels.append(TrustLevel(least))
    for item in request.conversation:
        if not item.provenance_ids:
            levels.append(IMPLICIT_ROLE_TRUST.get(item.role, UNATTRIBUTED_TRUST))
    observation = request.observation
    if observation is not None and not observation.provenance_ids:
        levels.append(UNATTRIBUTED_TRUST)
    return levels


def _rank(level: TrustLevel) -> int:
    return list(TrustLevel).index(level)


def effective_policy(
    principal: Principal,
    *,
    policy_set: PolicyIdentity | None,
    policy_context: Mapping[str, object],
    store: ReceiptStore,
    default_policy_set: PolicyIdentity,
) -> tuple[PolicyIdentity, Mapping[str, object]]:
    """Return the policy identity and context the decision must be taken under (D3).

    The reported identity is always a **server** value: it is the stored policy row
    the request names, never a caller-asserted string. A caller may name a policy
    set only if that version exists for its tenant; anything else is refused with
    ``422 POLICY_SET_UNKNOWN`` rather than echoed, so a receipt can never claim a
    policy version that did not decide (H2-02). Without a name, the server default
    identity is reported.

    ``policy:context_override`` grants authority over the policy *facts*
    (``allowed_tools`` and friends), not over the policy *identity*: an override
    holder still has to name a stored version. A principal without the scope always
    gets the stored document, so a caller can never substitute policy facts by
    editing the request.
    """

    override = principal.has(SCOPE_POLICY_CONTEXT_OVERRIDE)
    if policy_set is None:
        stored_default = store.get_policy_set(
            principal.tenant_id, default_policy_set.id, default_policy_set.version
        )
        if stored_default is not None:
            identity = PolicyIdentity(id=stored_default.id, version=stored_default.version)
            return (identity, policy_context) if override else (identity, stored_default.document)
        if not override:
            raise ProblemError(
                POLICY_SET_UNKNOWN,
                f"policy set {default_policy_set.id!r} version "
                f"{default_policy_set.version!r} is not stored for this tenant",
                status_code=422,
            )
        return override_policy_identity(policy_context), policy_context
    stored = store.get_policy_set(principal.tenant_id, policy_set.id, policy_set.version)
    if stored is None:
        raise ProblemError(
            POLICY_SET_UNKNOWN,
            f"policy set {policy_set.id!r} version {policy_set.version!r} is not stored "
            "for this tenant",
            status_code=422,
        )
    identity = PolicyIdentity(id=stored.id, version=stored.version)
    return (identity, policy_context) if override else (identity, stored.document)


def override_policy_identity(document: Mapping[str, object]) -> PolicyIdentity:
    """Derive a content-addressed identity for a document used under the override scope.

    The caller's document decided, so the identity must describe *it*, not a name the
    caller chose. The version is the SHA-256 of the canonical JSON of the document,
    truncated to 32 hex characters, so the identity is deterministic and reproducible
    by the caller (it can compute the same value for ``enforce(expected_policy=...)``).
    """

    try:
        encoded = canonical_json(thaw_json(document)).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ProblemError(
            POLICY_CONTEXT_INVALID,
            "the policy context is not canonicalisable (non-finite number or unsupported value)",
            status_code=422,
        ) from error
    return PolicyIdentity(id=OVERRIDE_POLICY_ID, version=hashlib.sha256(encoded).hexdigest()[:32])


__all__ = [
    "OVERRIDE_POLICY_ID",
    "POLICY_CONTEXT_INVALID",
    "POLICY_SET_UNKNOWN",
    "PrincipalDep",
    "ProblemError",
    "SettingsDep",
    "StoreDep",
    "assert_trust_ceiling",
    "effective_policy",
    "induced_trust_ceiling",
    "override_policy_identity",
    "principal_dependency",
    "require_any_scope",
    "require_scopes",
    "settings_dependency",
    "store_dependency",
]
