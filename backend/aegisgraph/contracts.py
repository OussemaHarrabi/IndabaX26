"""Canonical, policy-neutral security-domain contracts."""

from __future__ import annotations

import hashlib
import json
import re
from enum import StrEnum
from functools import total_ordering
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

MAX_ARGUMENT_CHARS = 8_000
MAX_CONTENT_CHARS = 16_000
MAX_CONTEXT_BYTES = 16_384
MAX_METADATA_BYTES = 4_096
REASON_CODE_PATTERN = r"^[A-Z][A-Z0-9_]{1,63}$"

ArgumentValue = str | int | float | bool | None


@total_ordering
class _OrderedSecurityEnum(StrEnum):
    def __lt__(self, other: Any) -> bool:
        if self.__class__ is not other.__class__:
            return NotImplemented
        members = list(self.__class__)
        return members.index(self) < members.index(other)


class TrustLevel(_OrderedSecurityEnum):
    SYSTEM_POLICY = "system_policy"
    AUTHENTICATED_USER = "authenticated_user"
    TRUSTED_INTERNAL = "trusted_internal"
    UNTRUSTED_INTERNAL = "untrusted_internal"
    UNTRUSTED_EXTERNAL = "untrusted_external"
    ADVERSARY_CONTROLLED = "adversary_controlled"


class Sensitivity(_OrderedSecurityEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class ActionKind(StrEnum):
    RESPOND = "respond"
    TOOL_CALL = "tool_call"
    MEMORY_WRITE = "memory_write"
    REQUEST_CONFIRMATION = "request_confirmation"


class Verdict(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    ESCALATE = "escalate"
    REWRITE = "rewrite"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Observation(_FrozenModel):
    """A bounded input together with its security provenance."""

    kind: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    content: str = Field(max_length=MAX_CONTENT_CHARS)
    source: str = Field(min_length=1, max_length=256)
    trust_level: TrustLevel
    sensitivity: Sensitivity = Sensitivity.INTERNAL


class CandidateAction(_FrozenModel):
    """An inert action proposal. Constructing this model never executes the action."""

    type: ActionKind
    tool: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{1,63}$")
    arguments: dict[str, ArgumentValue] = Field(default_factory=dict)
    content: str | None = Field(default=None, max_length=MAX_CONTENT_CHARS)
    final: bool = False
    confirmation_for: CandidateAction | None = None

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

    @model_validator(mode="after")
    def _shape_matches_type(self) -> Self:
        if self.type is ActionKind.TOOL_CALL:
            if self.tool is None:
                raise ValueError("tool_call actions require 'tool'")
            if self.content is not None or self.confirmation_for is not None:
                raise ValueError("tool_call actions take 'arguments' only")
        elif self.type in (ActionKind.RESPOND, ActionKind.MEMORY_WRITE):
            if self.content is None:
                raise ValueError(f"{self.type} actions require 'content'")
            if self.tool is not None or self.arguments or self.confirmation_for is not None:
                raise ValueError(f"{self.type} actions take 'content' only")
        elif self.type is ActionKind.REQUEST_CONFIRMATION:
            target = self.confirmation_for
            if target is None or target.type is not ActionKind.TOOL_CALL:
                raise ValueError("request_confirmation requires a tool_call in 'confirmation_for'")
            if self.tool is not None or self.arguments:
                raise ValueError("request_confirmation takes 'confirmation_for' and 'content' only")
        if self.final and self.type is not ActionKind.RESPOND:
            raise ValueError("only respond actions can be final")
        return self

    def digest(self) -> str:
        return action_digest(self)


class GuardRequest(_FrozenModel):
    """All policy-neutral facts needed to evaluate an action proposal."""

    request_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    )
    user_goal: str = Field(min_length=1, max_length=MAX_CONTENT_CHARS)
    observations: tuple[Observation, ...] = Field(default_factory=tuple, max_length=128)
    candidate_action: CandidateAction
    policy_context: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("policy_context")
    @classmethod
    def _bounded_policy_context(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        _require_json_size(value, MAX_CONTEXT_BYTES, "policy_context")
        return value


class GuardDecision(_FrozenModel):
    """A policy engine's decision for one candidate action."""

    verdict: Verdict
    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    reason_codes: tuple[str, ...] = Field(default_factory=tuple, max_length=16)
    explanation: str | None = Field(default=None, max_length=500)
    rewritten_action: CandidateAction | None = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("reason_codes")
    @classmethod
    def _valid_reason_codes(cls, codes: tuple[str, ...]) -> tuple[str, ...]:
        for code in codes:
            if re.fullmatch(REASON_CODE_PATTERN, code) is None:
                raise ValueError(f"invalid reason code {code!r}; use UPPER_SNAKE_CASE")
        return codes

    @field_validator("metadata")
    @classmethod
    def _bounded_metadata(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        _require_json_size(value, MAX_METADATA_BYTES, "metadata")
        return value

    @model_validator(mode="after")
    def _rewrite_consistency(self) -> Self:
        if self.verdict is Verdict.REWRITE and self.rewritten_action is None:
            raise ValueError("rewrite decisions require 'rewritten_action'")
        if self.verdict is not Verdict.REWRITE and self.rewritten_action is not None:
            raise ValueError("'rewritten_action' is only valid with verdict 'rewrite'")
        return self


class DecisionReceipt(_FrozenModel):
    """Stable record binding a request, its exact action, and the resulting decision."""

    request_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    )
    action_digest: str = Field(pattern=r"^[0-9a-f]{24}$")
    decision: GuardDecision


def action_digest(action: CandidateAction) -> str:
    """Return the SENTINEL-compatible stable digest for an action proposal."""
    payload: dict[str, JsonValue] = {
        "type": action.type.value,
        "tool": action.tool,
        "arguments": {
            key: _canonical_argument(value) for key, value in sorted(action.arguments.items())
        },
        "content": action.content if action.type is not ActionKind.TOOL_CALL else None,
    }
    if action.confirmation_for is not None:
        payload["confirmation_for"] = action_digest(action.confirmation_for)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:24]


def _canonical_argument(value: ArgumentValue) -> ArgumentValue:
    if isinstance(value, str):
        return " ".join(value.split())
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def _require_json_size(value: object, limit: int, field_name: str) -> None:
    try:
        size = len(json.dumps(value))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be JSON-serializable") from exc
    if size > limit:
        raise ValueError(f"{field_name} exceeds {limit} bytes")
