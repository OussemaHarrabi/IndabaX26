"""Self-contained models for the official SENTINEL v1 defense API contract."""

from __future__ import annotations

import json
import re
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from aegisgraph.contracts import (
    MAX_ARGUMENT_CHARS,
    MAX_CONTENT_CHARS,
    MAX_CONTEXT_BYTES,
    MAX_METADATA_BYTES,
    REASON_CODE_PATTERN,
    ArgumentValue,
)

API_VERSION = "v1"


class _LenientFrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")


class SentinelCandidateAction(BaseModel):
    """Exact action shape carried by a SENTINEL request or rewrite response."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: Literal["respond", "tool_call", "memory_write", "request_confirmation"]
    tool: str | None = Field(default=None, max_length=64)
    arguments: dict[str, ArgumentValue] = Field(default_factory=dict)
    content: str | None = Field(default=None, max_length=MAX_CONTENT_CHARS)
    final: bool = False
    confirmation_for: SentinelCandidateAction | None = None

    @field_validator("arguments")
    @classmethod
    def _bounded_arguments(cls, value: dict[str, ArgumentValue]) -> dict[str, ArgumentValue]:
        if len(value) > 32:
            raise ValueError("at most 32 arguments are allowed")
        for key, item in value.items():
            if not key.isidentifier() or len(key) > 64:
                raise ValueError(f"invalid argument name: {key!r}")
            if isinstance(item, str) and len(item) > MAX_ARGUMENT_CHARS:
                raise ValueError(f"argument {key!r} exceeds {MAX_ARGUMENT_CHARS} characters")
        return value


class SentinelProvenance(_LenientFrozenModel):
    source_type: str = Field(min_length=1, max_length=128)
    source_id: str = Field(min_length=1, max_length=256)
    trust_level: Literal[
        "system_policy",
        "authenticated_user",
        "trusted_internal",
        "untrusted_internal",
        "untrusted_external",
        "adversary_controlled",
    ]
    origin_actor: str = Field(min_length=1, max_length=256)
    retrieved_via: str = Field(min_length=1, max_length=256)
    sensitivity: Literal["public", "internal", "confidential", "restricted"] = "internal"


class SentinelProvenanceRecord(_LenientFrozenModel):
    id: str = Field(min_length=1, max_length=256)
    provenance: SentinelProvenance


class SentinelConversationItem(_LenientFrozenModel):
    role: str = Field(min_length=1, max_length=64)
    kind: str = Field(min_length=1, max_length=64)
    content: str = Field(max_length=MAX_CONTENT_CHARS)
    provenance_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=128)


class SentinelObservationView(_LenientFrozenModel):
    kind: str = Field(min_length=1, max_length=64)
    content: str = Field(max_length=MAX_CONTENT_CHARS)
    provenance_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=128)


class SentinelHistoryDigest(_LenientFrozenModel):
    steps_taken: int = Field(default=0, ge=0)
    turn_index: int = Field(default=0, ge=0)
    tool_calls: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=256)
    confirmations_granted: tuple[str, ...] = Field(default_factory=tuple, max_length=256)
    blocked_count: int = Field(default=0, ge=0)
    escalated_count: int = Field(default=0, ge=0)
    least_trusted_seen: str | None = Field(default=None, max_length=64)
    most_sensitive_seen: str | None = Field(default=None, max_length=64)


class SentinelRequest(_LenientFrozenModel):
    """Forward-compatible SENTINEL v1 request envelope."""

    run_id: str = Field(min_length=1, max_length=256)
    step_id: int = Field(ge=0)
    user_goal: str = Field(max_length=MAX_CONTENT_CHARS)
    conversation: tuple[SentinelConversationItem, ...] = Field(
        default_factory=tuple, max_length=256
    )
    observation: SentinelObservationView | None = None
    candidate_action: SentinelCandidateAction
    policy_context: dict[str, JsonValue] = Field(default_factory=dict)
    provenance: tuple[SentinelProvenanceRecord, ...] = Field(default_factory=tuple, max_length=256)
    history_digest: SentinelHistoryDigest = Field(default_factory=SentinelHistoryDigest)

    @field_validator("policy_context")
    @classmethod
    def _bounded_policy_context(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        if len(json.dumps(value)) > MAX_CONTEXT_BYTES:
            raise ValueError(f"policy_context exceeds {MAX_CONTEXT_BYTES} bytes")
        return value


class SentinelResponse(BaseModel):
    """Strict SENTINEL v1 defense response."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision: Literal["allow", "block", "escalate", "rewrite"]
    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    reason_codes: tuple[str, ...] = Field(default_factory=tuple, max_length=16)
    explanation: str | None = Field(default=None, max_length=500)
    rewritten_action: SentinelCandidateAction | None = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("reason_codes")
    @classmethod
    def _valid_codes(cls, codes: tuple[str, ...]) -> tuple[str, ...]:
        for code in codes:
            if re.fullmatch(REASON_CODE_PATTERN, code) is None:
                raise ValueError(f"invalid reason code {code!r}; use UPPER_SNAKE_CASE")
        return codes

    @field_validator("metadata")
    @classmethod
    def _bounded_metadata(cls, metadata: dict[str, JsonValue]) -> dict[str, JsonValue]:
        size = len(json.dumps(metadata))
        if size > MAX_METADATA_BYTES:
            raise ValueError(f"metadata exceeds {MAX_METADATA_BYTES} bytes")
        return metadata

    @model_validator(mode="after")
    def _rewrite_needs_action(self) -> Self:
        if (self.decision == "rewrite") != (self.rewritten_action is not None):
            raise ValueError("rewritten_action is required for, and only for, decision 'rewrite'")
        return self


# Names used by the official starter kit, retained as stable adapter aliases.
CandidateAction = SentinelCandidateAction
DefenseRequest = SentinelRequest
DefenseDecision = SentinelResponse
SentinelDefenseRequest = SentinelRequest
SentinelDefenseResponse = SentinelResponse
