"""The versioned generic decision surface (``aegisgraph/v1``).

The legacy ``POST /v1/decision`` wire stays byte-compatible and is served by
:mod:`aegisgraph.app`. This module adds the industrial contract: a required API
version, a server-computed request and receipt identity, both action digests, a
policy identity, a bounded validity window, strict confirmation binding, and one
structured decision record per request.

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
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, Response
from pydantic import BaseModel, ConfigDict, Field, JsonValue

from aegisgraph.adapter import canonical_action
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

ApiVersion = Literal["aegisgraph/v1"]

API_VERSION: ApiVersion = "aegisgraph/v1"
"""Wire version of the generic contract; the only accepted ``api_version``."""

DEFAULT_POLICY_SET = PolicyIdentity(id="aegisgraph-default", version="1")
"""Policy identity reported when the caller does not pin one."""

RECEIPT_TTL_ENV = "AEGISGRAPH_RECEIPT_TTL_SECONDS"
DEFAULT_RECEIPT_TTL_SECONDS = 60

_LOGGER = logging.getLogger("aegisgraph.decision")
_DECISION_FAILED = "INTERNAL_EVALUATION_FAILED"


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
    )
    policy_set: PolicyIdentity | None = None


class GenericDecisionResponse(SentinelResponse):
    """Strict generic decision response: the seven legacy fields plus identity."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    api_version: Literal["aegisgraph/v1"]
    request_id: str = Field(min_length=1, max_length=128)
    receipt_id: str = Field(pattern=r"^[0-9a-f]{32}$")
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


router = APIRouter()


@router.get("/api/v1/version", response_model=VersionResponse)
async def version() -> VersionResponse:
    """Return the API version, the active policy identity and build metadata."""

    return VersionResponse(
        api_version=API_VERSION,
        policy_set=DEFAULT_POLICY_SET,
        build={
            "service": "aegisgraph",
            "version": _package_version(),
            "commit": os.environ.get("AEGISGRAPH_BUILD_COMMIT", "unknown"),
        },
    )


@router.post("/api/v1/decisions", response_model=GenericDecisionResponse)
async def create_decision(request: GenericDecisionRequest) -> Response:
    """Return one bounded, receipt-bearing decision; candidate actions are inert."""

    started = time.perf_counter()
    decided_at = datetime.now(UTC)
    identity = _ReceiptIdentity(
        request_id=request.request_id or uuid4().hex,
        receipt_id=uuid4().hex,
        policy_set=request.policy_set or DEFAULT_POLICY_SET,
        decided_at=decided_at,
        valid_until=decided_at + timedelta(seconds=receipt_ttl_seconds()),
    )
    try:
        evaluated = evaluate(
            request,
            confirmation_mode=ConfirmationMode.STRICT,
            now_epoch=int(decided_at.timestamp()),
        )
        response = _to_generic_response(evaluated, identity)
    except Exception as error:
        _LOGGER.error("Generic decision failed (%s)", type(error).__name__)
        response = _fail_closed_response(request, identity)
    encoded = response.model_dump_json().encode("utf-8")
    if len(encoded) > MAX_RESPONSE_BYTES:
        response = _fail_closed_response(request, identity)
        encoded = response.model_dump_json().encode("utf-8")
    _log_decision(response, latency_ms=round((time.perf_counter() - started) * 1000.0, 3))
    return Response(content=encoded, media_type="application/json", status_code=200)


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


def _log_decision(response: GenericDecisionResponse, *, latency_ms: float) -> None:
    """Emit exactly one structured decision record; never any request content."""

    _LOGGER.info(
        json.dumps(
            {
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
                "caller": None,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def _package_version() -> str:
    """Report the version of the distribution, source tree, or ``unknown``."""

    try:
        return importlib_metadata.version("aegisgraph")
    except importlib_metadata.PackageNotFoundError:
        pass
    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    try:
        declared = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        version = declared["project"]["version"]
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError):
        return "unknown"
    return version if isinstance(version, str) else "unknown"


__all__ = [
    "API_VERSION",
    "DEFAULT_POLICY_SET",
    "DEFAULT_RECEIPT_TTL_SECONDS",
    "RECEIPT_TTL_ENV",
    "GenericDecisionRequest",
    "GenericDecisionResponse",
    "VersionResponse",
    "receipt_ttl_seconds",
    "router",
]
