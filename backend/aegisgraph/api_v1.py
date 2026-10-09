"""The versioned generic decision surface (``aegisgraph/v1``).

The legacy ``POST /v1/decision`` wire stays byte-compatible and is served by
:mod:`aegisgraph.app`. This module adds the industrial contract: a required API
version, a server-computed receipt identity, both action digests, a server-resolved
policy identity, a bounded validity window, strict confirmation binding, and one
structured decision record per request.

``request_id`` is the **caller's** correlation and idempotency key: it is preserved
verbatim (H2-05), because a client must be able to reuse it when it retries. The
server-computed decision identity is ``receipt_id``; it is what the audit trail and
the enforcement SDK key on, and it is never derived from caller input.

Nothing here executes a candidate action; it only decides.
"""

from __future__ import annotations

import json
import logging
import os
import time
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Annotated, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError

from aegisgraph import telemetry
from aegisgraph.access import (
    ProblemError,
    SettingsDep,
    StoreDep,
    assert_trust_ceiling,
    effective_policy,
    require_scopes,
)
from aegisgraph.adapter import canonical_action
from aegisgraph.auth import (
    AUTH_METHOD_DEVELOPMENT,
    SCOPE_DECISION_SUBMIT,
    Principal,
)
from aegisgraph.confirmation import authorize_confirmations, record_refusal
from aegisgraph.contracts import (
    ActionKind,
    CandidateAction,
    ConfirmationMode,
    PolicyIdentity,
    action_digest,
    exact_action_digest,
)
from aegisgraph.engine import EvaluatedDecision, evaluate
from aegisgraph.sentinel import MAX_RESPONSE_BYTES, SentinelRequest, SentinelResponse, wire_response
from aegisgraph.settings import Settings
from aegisgraph.store import (
    EVENT_RECEIPT_CONFLICT,
    AuditRecord,
    ReceiptConflictError,
    ReceiptRecord,
    ReceiptStore,
    digest_of,
)

ApiVersion = Literal["aegisgraph/v1"]

API_VERSION: ApiVersion = "aegisgraph/v1"
"""Wire version of the generic contract; the only accepted ``api_version``."""

DEFAULT_POLICY_SET = PolicyIdentity(id="aegisgraph-default", version="1")
"""Policy identity reported when the caller does not pin one."""

DECISION_ROUTE: str = "/api/v1/decisions"
"""The route template this surface is served at; the only telemetry route value here."""

RECEIPT_TTL_ENV = "AEGISGRAPH_RECEIPT_TTL_SECONDS"
DEFAULT_RECEIPT_TTL_SECONDS = 60

BUILD_COMMIT_ENV = "AEGISGRAPH_BUILD_COMMIT"
BUILD_VERSION_ENV = "AEGISGRAPH_BUILD_VERSION"

_LOGGER = logging.getLogger("aegisgraph.decision")
_RECEIPT_LOGGER = logging.getLogger("aegisgraph.receipts")
_DECISION_FAILED = "INTERNAL_EVALUATION_FAILED"
RECEIPT_NOT_RECONSTRUCTIBLE = "RECEIPT_NOT_RECONSTRUCTIBLE"


@dataclass(frozen=True)
class _ReceiptIdentity:
    """Server-computed decision identity carried by the generic response."""

    request_id: str
    receipt_id: str
    policy_set: PolicyIdentity
    decided_at: datetime
    valid_until: datetime



class GenericDecisionRequest(SentinelRequest):
    """Bounded generic decision request: the SENTINEL envelope plus identity.

    Unknown envelope keys stay ignored, exactly as on the legacy wire, so a newer
    client can add fields without breaking older servers.
    """

    model_config = ConfigDict(frozen=True, extra="ignore")

    api_version: Literal["aegisgraph/v1"]
    request_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
        description=(
            "Caller-supplied correlation and idempotency key, preserved verbatim. "
            "Receipts are keyed by (tenant_id, request_id); reusing it for the same "
            "action returns the stored receipt, reusing it for a different action is "
            "refused with 409. Omitted: the server generates one."
        ),
    )
    policy_set: PolicyIdentity | None = None


class GenericDecisionResponse(SentinelResponse):
    """Strict generic decision response: the seven legacy fields plus identity."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    api_version: Literal["aegisgraph/v1"]
    request_id: str = Field(min_length=1, max_length=128)
    receipt_id: str = Field(
        pattern=r"^[0-9a-f]{32}$",
        description="Server-computed decision identity; the audit trail keys on it.",
    )
    policy_set: PolicyIdentity
    action_digest: str = Field(pattern=r"^[0-9a-f]{24}$")
    execution_digest: str = Field(pattern=r"^[0-9a-f]{24}$")
    decided_at: datetime
    valid_until: datetime


class VersionResponse(BaseModel):
    """Build and policy identity for clients and the enforcement SDK."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    api_version: Literal["aegisgraph/v1"]
    policy_set: PolicyIdentity
    build: Mapping[str, JsonValue]
    ablation: str | None = None
    """The active research ablation, or absent when the defence is running."""


router = APIRouter()

DecisionSubmitter = Annotated[Principal, Depends(require_scopes(SCOPE_DECISION_SUBMIT))]


@router.get(
    "/api/v1/version", response_model=VersionResponse, response_model_exclude_none=True
)
async def version(settings: SettingsDep) -> VersionResponse:
    """Return the API version, the active policy identity and build metadata.

    ``ablation`` names the one mechanism a research run disabled. It is absent
    for the defence, so the default version shape is unchanged; when present it
    makes an ablated service identifiable before any request is sent.
    """

    return VersionResponse(
        api_version=API_VERSION,
        policy_set=DEFAULT_POLICY_SET,
        build={
            "service": "aegisgraph",
            "version": _package_version(),
            "commit": os.environ.get(BUILD_COMMIT_ENV, "unknown"),
        },
        ablation=settings.ablation.value if settings.ablation is not None else None,
    )


@router.post("/api/v1/decisions", response_model=GenericDecisionResponse)
async def create_decision(
    request: GenericDecisionRequest,
    principal: DecisionSubmitter,
    settings: SettingsDep,
    store: StoreDep,
) -> Response:
    """Return one bounded, receipt-bearing decision; candidate actions are inert.

    The authenticated caller decides the tenant and the authority (D1): a request
    asserting provenance above the caller's trust ceiling is refused (D2), the
    caller's ``policy_context`` is honoured only with ``policy:context_override``
    (D3), and a confirmation grant counts only if it was issued for this step
    (D4). The decision is then persisted as an idempotent receipt (F7).
    """

    started = time.perf_counter()
    decided_at = datetime.now(UTC)
    now_epoch = int(decided_at.timestamp())

    with telemetry.span(
        telemetry.SPAN_DECISION, **{telemetry.ATTR_ROUTE: DECISION_ROUTE}
    ) as decision_span:
        with telemetry.span(telemetry.SPAN_NORMALISE) as normalise_span:
            assert_trust_ceiling(principal, request, ablation=settings.ablation)
            policy_set, policy_context = effective_policy(
                principal,
                policy_set=request.policy_set,
                policy_context=request.policy_context,
                store=store,
                default_policy_set=DEFAULT_POLICY_SET,
            )
            request = _with_policy_context(request, policy_context)
            authorization = authorize_confirmations(
                request, tenant_id=principal.tenant_id, store=store, now=decided_at
            )
            request = authorization.request
            identity = _ReceiptIdentity(
                request_id=request.request_id or uuid4().hex,
                receipt_id=uuid4().hex,
                policy_set=policy_set,
                decided_at=decided_at,
                valid_until=decided_at + timedelta(seconds=receipt_ttl_seconds()),
            )
            normalise_span.set_attribute(telemetry.ATTR_POLICY_SET_ID, policy_set.id)
            normalise_span.set_attribute(
                telemetry.ATTR_POLICY_SET_VERSION, policy_set.version
            )
        with telemetry.span(telemetry.SPAN_EVALUATE) as evaluate_span:
            try:
                evaluated = evaluate(
                    request,
                    confirmation_mode=ConfirmationMode.STRICT,
                    now_epoch=now_epoch,
                    ablation=settings.ablation,
                )
                response = _to_generic_response(evaluated, identity)
            except Exception as error:
                _LOGGER.error("Generic decision failed (%s)", type(error).__name__)
                response = _fail_closed_response(request, identity)
            encoded = response.model_dump_json().encode("utf-8")
            if len(encoded) > MAX_RESPONSE_BYTES:
                response = _fail_closed_response(request, identity)
            evaluate_span.set_attribute(telemetry.ATTR_VERDICT, response.decision)
            evaluate_span.set_attribute(telemetry.ATTR_POLICY_SET_ID, response.policy_set.id)
            evaluate_span.set_attribute(
                telemetry.ATTR_POLICY_SET_VERSION, response.policy_set.version
            )
        with telemetry.span(telemetry.SPAN_PERSIST) as persist_span:
            receipt_outcome = telemetry.OUTCOME_UNAVAILABLE
            try:
                response, receipt_outcome = _persist_receipt(
                    request=request,
                    response=response,
                    identity=identity,
                    principal=principal,
                    settings=settings,
                    store=store,
                )
            except ProblemError as error:
                telemetry.record_receipt_failure(error.code)
                receipt_outcome = _receipt_outcome(error.code)
                raise
            finally:
                persist_span.set_attribute(
                    telemetry.ATTR_RECEIPT_STORE_OUTCOME, receipt_outcome
                )
        with telemetry.span(telemetry.SPAN_RESPOND) as respond_span:
            record_refusal(
                authorization,
                tenant_id=principal.tenant_id,
                principal_id=principal.principal_id,
                store=store,
                now=decided_at,
                request_id=response.request_id,
            )
            latency_ms = round((time.perf_counter() - started) * 1000.0, 3)
            _log_decision(
                response,
                latency_ms=latency_ms,
                caller=_caller_label(principal),
            )
            telemetry.record_decision(
                verdict=response.decision,
                policy_id=response.policy_set.id,
                latency_seconds=latency_ms / 1000.0,
            )
            respond_span.set_attribute(telemetry.ATTR_LATENCY_MS, latency_ms)
        decision_span.set_attribute(telemetry.ATTR_VERDICT, response.decision)
        decision_span.set_attribute(telemetry.ATTR_POLICY_SET_ID, response.policy_set.id)
        decision_span.set_attribute(
            telemetry.ATTR_POLICY_SET_VERSION, response.policy_set.version
        )
        decision_span.set_attribute(
            telemetry.ATTR_RECEIPT_STORE_OUTCOME, receipt_outcome
        )
        decision_span.set_attribute(telemetry.ATTR_LATENCY_MS, latency_ms)
    encoded = response.model_dump_json().encode("utf-8")
    return Response(content=encoded, media_type="application/json", status_code=200)


def _receipt_outcome(problem_code: str) -> str:
    """Map a receipt-store refusal onto the bounded telemetry outcome value."""

    if problem_code == "REQUEST_ID_CONFLICT":
        return telemetry.OUTCOME_CONFLICT
    return telemetry.OUTCOME_UNAVAILABLE


def _caller_label(principal: Principal) -> str | None:
    """Report the caller identity, or ``None`` in the development mode (D5)."""

    return None if principal.auth_method == AUTH_METHOD_DEVELOPMENT else principal.principal_id


def _with_policy_context(
    request: GenericDecisionRequest, policy_context: Mapping[str, object]
) -> GenericDecisionRequest:
    if policy_context is request.policy_context:
        return request
    payload = request.model_dump(mode="json")
    payload["policy_context"] = dict(policy_context)
    return GenericDecisionRequest.model_validate(payload)


def _persist_receipt(
    *,
    request: GenericDecisionRequest,
    response: GenericDecisionResponse,
    identity: _ReceiptIdentity,
    principal: Principal,
    settings: Settings,
    store: ReceiptStore,
) -> tuple[GenericDecisionResponse, str]:
    """Store the receipt idempotently and return it with the store outcome (F7, D1)."""

    record = ReceiptRecord(
        tenant_id=principal.tenant_id,
        request_id=response.request_id,
        receipt_id=response.receipt_id,
        surface="generic",
        principal_id=principal.principal_id,
        auth_method=principal.auth_method,
        policy_set_id=response.policy_set.id,
        policy_set_version=response.policy_set.version,
        verdict=response.decision,
        risk_score=response.risk_score,
        confidence=response.confidence,
        reason_codes=tuple(response.reason_codes),
        action_digest=response.action_digest,
        execution_digest=response.execution_digest,
        payload_digest=digest_of(
            {
                "request": request.model_dump(mode="json"),
                "response_metadata": dict(response.metadata),
            }
        ),
        decision_body=response.model_dump(mode="json"),
        decided_at=identity.decided_at,
        valid_until=identity.valid_until,
        created_at=identity.decided_at,
        run_id=request.run_id,
        step_id=request.step_id,
        metadata=dict(response.metadata) if settings.store_payload_metadata else None,
    )
    try:
        stored = store.store_receipt(record)
    except ReceiptConflictError as error:
        store.record_audit_event(
            AuditRecord(
                tenant_id=principal.tenant_id,
                event_type=EVENT_RECEIPT_CONFLICT,
                actor_id=principal.principal_id,
                subject=response.request_id,
                details={"action_digest": response.action_digest},
                created_at=datetime.now(UTC),
            )
        )
        raise ProblemError(
            "REQUEST_ID_CONFLICT",
            f"request_id {response.request_id!r} was already used for a different action",
            status_code=409,
        ) from error
    except Exception as error:
        _RECEIPT_LOGGER.error("Receipt persistence failed (%s)", type(error).__name__)
        raise ProblemError(
            "RECEIPT_STORE_UNAVAILABLE",
            "the durable receipt store is unavailable",
            status_code=503,
        ) from error
    if stored.decision_body == record.decision_body:
        return response, telemetry.OUTCOME_STORED
    # A replay returns the *stored* decision, so the response and the durable receipt
    # are the same object instead of two different evaluations of the same request
    # (H3-02). A row whose body cannot be reconstructed faithfully is refused rather
    # than answered with a freshly evaluated decision.
    try:
        replay = GenericDecisionResponse.model_validate(stored.decision_body)
    except ValidationError as error:
        _RECEIPT_LOGGER.error("Stored receipt body is not reconstructible")
        raise ProblemError(
            RECEIPT_NOT_RECONSTRUCTIBLE,
            "the stored receipt for this request_id cannot be reconstructed faithfully",
            status_code=409,
        ) from error
    return replay, telemetry.OUTCOME_DUPLICATE


def receipt_ttl_seconds() -> int:
    """Return the receipt validity window from the environment (default 60 s)."""

    raw = os.environ.get(RECEIPT_TTL_ENV)
    if raw is None:
        return DEFAULT_RECEIPT_TTL_SECONDS
    try:
        ttl = int(raw)
    except ValueError:
        return DEFAULT_RECEIPT_TTL_SECONDS
    return ttl if ttl > 0 else DEFAULT_RECEIPT_TTL_SECONDS


def _to_generic_response(
    evaluated: EvaluatedDecision, identity: _ReceiptIdentity
) -> GenericDecisionResponse:
    payload = wire_response(evaluated.decision).model_dump(mode="json")
    payload.update(
        api_version=API_VERSION,
        request_id=identity.request_id,
        receipt_id=identity.receipt_id,
        policy_set=identity.policy_set.model_dump(mode="json"),
        action_digest=evaluated.action_digest,
        execution_digest=evaluated.execution_digest,
        decided_at=identity.decided_at,
        valid_until=identity.valid_until,
    )
    return GenericDecisionResponse.model_validate(payload)


def _fail_closed_response(
    request: SentinelRequest, identity: _ReceiptIdentity
) -> GenericDecisionResponse:
    """Never turn a boundary failure into an allow or leak internal details."""

    action_digest_value, execution_digest_value = _action_identity(request)
    return GenericDecisionResponse(
        api_version=API_VERSION,
        request_id=identity.request_id,
        receipt_id=identity.receipt_id,
        policy_set=identity.policy_set,
        action_digest=action_digest_value,
        execution_digest=execution_digest_value,
        decided_at=identity.decided_at,
        valid_until=identity.valid_until,
        decision="block",
        risk_score=1.0,
        confidence=1.0,
        reason_codes=(_DECISION_FAILED,),
        explanation="The request could not be safely evaluated.",
        metadata={},
    )


def _action_identity(request: SentinelRequest) -> tuple[str, str]:
    try:
        canonical = canonical_action(request.candidate_action)
    except Exception:
        canonical = CandidateAction(type=ActionKind.RESPOND, content="")
    return action_digest(canonical), exact_action_digest(canonical)


def _log_decision(
    response: GenericDecisionResponse, *, latency_ms: float, caller: str | None
) -> None:
    """Emit exactly one structured decision record; never any request content."""

    record: dict[str, object] = {
        "event": "decision",
        "request_id": response.request_id,
        "receipt_id": response.receipt_id,
        "policy_set": {
            "id": response.policy_set.id,
            "version": response.policy_set.version,
        },
        "verdict": response.decision,
        "reason_codes": list(response.reason_codes),
        "action_digest": response.action_digest,
        "execution_digest": response.execution_digest,
        "latency_ms": latency_ms,
        "caller": caller,
    }
    # An ablated run must be identifiable from its artifacts: the decision record
    # carries the ablation name, and only an ablated run grows this key, so the
    # default record shape is unchanged (ablation visibility, docs/benchmark/ablations.md).
    ablation = response.metadata.get("ablation")
    if ablation is not None:
        record["ablation"] = ablation
    _LOGGER.info(
        json.dumps(record, separators=(",", ":"), sort_keys=True)
    )


def _package_version() -> str:
    """Report the build version: environment, distribution, source tree, or unknown.

    CI and Compose set ``AEGISGRAPH_BUILD_VERSION`` (and
    ``AEGISGRAPH_BUILD_COMMIT``) at image build time. When neither is present the
    installed distribution version, then the source ``pyproject.toml`` version, is
    reported, and ``"unknown"`` is the honest default.
    """

    declared = os.environ.get(BUILD_VERSION_ENV)
    if declared:
        return declared
    try:
        return importlib_metadata.version("aegisgraph")
    except importlib_metadata.PackageNotFoundError:
        pass
    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    try:
        project = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        version = project["project"]["version"]
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError):
        return "unknown"
    return version if isinstance(version, str) else "unknown"


__all__ = [
    "API_VERSION",
    "BUILD_COMMIT_ENV",
    "BUILD_VERSION_ENV",
    "DECISION_ROUTE",
    "DEFAULT_POLICY_SET",
    "DEFAULT_RECEIPT_TTL_SECONDS",
    "RECEIPT_TTL_ENV",
    "GenericDecisionRequest",
    "GenericDecisionResponse",
    "VersionResponse",
    "receipt_ttl_seconds",
    "router",
]
