"""Self-contained models for the official SENTINEL v1 defense API contract."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Annotated, Literal, Self, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_serializer,
    field_validator,
    model_validator,
)

from aegisgraph.contracts import (
    MAX_ARGUMENT_CHARS,
    MAX_CONTENT_CHARS,
    MAX_CONTEXT_BYTES,
    MAX_METADATA_BYTES,
    REASON_CODE_PATTERN,
    ArgumentValue,
    FrozenDict,
    _freeze_json_mapping,
    _thaw_json,
)

API_VERSION = "v1"

TrustLevelLiteral = Literal[
    "system_policy",
    "authenticated_user",
    "trusted_internal",
    "untrusted_internal",
    "untrusted_external",
    "adversary_controlled",
]
SensitivityLiteral = Literal["public", "internal", "confidential", "restricted"]
VerdictLiteral = Literal["allow", "block", "escalate", "rewrite"]
BoundedIdentifier = Annotated[str, Field(min_length=1, max_length=256)]
BoundedTag = Annotated[str, Field(min_length=1, max_length=128)]


class _LenientFrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")


class SentinelCandidateAction(BaseModel):
    """Exact action shape carried by a SENTINEL request or rewrite response."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: Literal["respond", "tool_call", "memory_write", "request_confirmation"]
    tool: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{1,63}$")
    arguments: Mapping[str, ArgumentValue] = Field(default_factory=FrozenDict)
    content: str | None = Field(default=None, max_length=MAX_CONTENT_CHARS)
    final: bool = False
    confirmation_for: SentinelCandidateAction | None = None

    @field_validator("arguments")
    @classmethod
    def _bounded_arguments(
        cls, value: Mapping[str, ArgumentValue]
    ) -> Mapping[str, ArgumentValue]:
        if len(value) > 32:
            raise ValueError("at most 32 arguments are allowed")
        for key, item in value.items():
            if not key.isidentifier() or len(key) > 64:
                raise ValueError(f"invalid argument name: {key!r}")
            if isinstance(item, str) and len(item) > MAX_ARGUMENT_CHARS:
                raise ValueError(f"argument {key!r} exceeds {MAX_ARGUMENT_CHARS} characters")
            if isinstance(item, float) and not math.isfinite(item):
                raise ValueError(f"argument {key!r} must be finite")
        return FrozenDict(value)

    @field_serializer("arguments")
    def _serialize_arguments(
        self, value: Mapping[str, ArgumentValue]
    ) -> dict[str, ArgumentValue]:
        return dict(value)

    @model_validator(mode="after")
    def _shape_matches_type(self) -> Self:
        if self.type == "tool_call":
            if self.tool is None:
                raise ValueError("tool_call actions require 'tool'")
            if self.content is not None or self.confirmation_for is not None:
                raise ValueError("tool_call actions take 'arguments' only")
        elif self.type in ("respond", "memory_write"):
            if self.content is None:
                raise ValueError(f"{self.type} actions require 'content'")
            if self.tool is not None or self.arguments or self.confirmation_for is not None:
                raise ValueError(f"{self.type} actions take 'content' only")
        elif self.type == "request_confirmation":
            target = self.confirmation_for
            if target is None or target.type != "tool_call":
                raise ValueError("request_confirmation requires a tool_call in 'confirmation_for'")
            if self.tool is not None or self.arguments:
                raise ValueError("request_confirmation takes 'confirmation_for' and 'content' only")
        if self.final and self.type != "respond":
            raise ValueError("only respond actions can be final")
        return self


class SentinelProvenance(_LenientFrozenModel):
    source_type: str = Field(min_length=1, max_length=128)
    source_id: str = Field(min_length=1, max_length=256)
    trust_level: TrustLevelLiteral
    origin_actor: str = Field(min_length=1, max_length=256)
    retrieved_via: str = Field(min_length=1, max_length=256)
    sensitivity: SensitivityLiteral = "internal"
    timestamp: datetime
    parent_event_ids: tuple[BoundedIdentifier, ...] = Field(default_factory=tuple, max_length=128)
    tags: tuple[BoundedTag, ...] = Field(default_factory=tuple, max_length=128)


class SentinelProvenanceRecord(_LenientFrozenModel):
    id: str = Field(min_length=1, max_length=256)
    provenance: SentinelProvenance


class SentinelConversationItem(_LenientFrozenModel):
    role: Literal["user", "agent", "tool", "memory", "safety", "human"]
    kind: str = Field(min_length=1, max_length=64)
    content: str = Field(max_length=MAX_CONTENT_CHARS)
    provenance_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=128)


class SentinelObservationView(_LenientFrozenModel):
    kind: str = Field(min_length=1, max_length=64)
    content: str = Field(max_length=MAX_CONTENT_CHARS)
    provenance_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=128)


class SentinelToolCallSummary(_LenientFrozenModel):
    step_id: int = Field(ge=0)
    tool: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    decision: VerdictLiteral
    succeeded: bool | None = None


class SentinelHistoryDigest(_LenientFrozenModel):
    steps_taken: int = Field(default=0, ge=0)
    turn_index: int = Field(default=0, ge=0)
    tool_calls: tuple[SentinelToolCallSummary, ...] = Field(default_factory=tuple, max_length=256)
    confirmations_granted: tuple[str, ...] = Field(default_factory=tuple, max_length=256)
    blocked_count: int = Field(default=0, ge=0)
    escalated_count: int = Field(default=0, ge=0)
    least_trusted_seen: TrustLevelLiteral | None = None
    most_sensitive_seen: SensitivityLiteral | None = None


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
    policy_context: Mapping[str, JsonValue] = Field(default_factory=FrozenDict)
    provenance: tuple[SentinelProvenanceRecord, ...] = Field(default_factory=tuple, max_length=256)
    history_digest: SentinelHistoryDigest = Field(default_factory=SentinelHistoryDigest)

    @field_validator("policy_context")
    @classmethod
    def _bounded_policy_context(
        cls, value: Mapping[str, JsonValue]
    ) -> Mapping[str, JsonValue]:
        if len(json.dumps(value, allow_nan=False)) > MAX_CONTEXT_BYTES:
            raise ValueError(f"policy_context exceeds {MAX_CONTEXT_BYTES} bytes")
        return _freeze_json_mapping(value)

    @field_serializer("policy_context")
    def _serialize_policy_context(self, value: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
        return cast(dict[str, JsonValue], _thaw_json(value))


class SentinelResponse(BaseModel):
    """Strict SENTINEL v1 defense response."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision: VerdictLiteral
    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    reason_codes: tuple[str, ...] = Field(default_factory=tuple, max_length=16)
    explanation: str | None = Field(default=None, max_length=500)
    rewritten_action: SentinelCandidateAction | None = None
    metadata: Mapping[str, JsonValue] = Field(default_factory=FrozenDict)

    @field_validator("reason_codes")
    @classmethod
    def _valid_codes(cls, codes: tuple[str, ...]) -> tuple[str, ...]:
        for code in codes:
            if re.fullmatch(REASON_CODE_PATTERN, code) is None:
                raise ValueError(f"invalid reason code {code!r}; use UPPER_SNAKE_CASE")
        return codes

    @field_validator("metadata")
    @classmethod
    def _bounded_metadata(cls, metadata: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        size = len(json.dumps(metadata, allow_nan=False))
        if size > MAX_METADATA_BYTES:
            raise ValueError(f"metadata exceeds {MAX_METADATA_BYTES} bytes")
        return _freeze_json_mapping(metadata)

    @field_serializer("metadata")
    def _serialize_metadata(self, value: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
        return cast(dict[str, JsonValue], _thaw_json(value))

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
