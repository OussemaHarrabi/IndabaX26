"""The authoritative native AegisGraph scenario schema.

A scenario is a *framework-independent* description of one agentic episode: the
user goal, the evidence the agent saw (observations plus the provenance graph
that explains where each piece came from), the actions the agent proposes, the
policy context, the safety property the episode is meant to exercise, the
utility criterion a benign episode must satisfy, and the metadata that makes the
episode reviewable (attack family, domain, scoring method, split, licence and
provenance, scenario version).

Design rules
------------
* Every field is bounded. An unbounded field is a denial-of-service surface and
  a reproducibility hazard, so the schema is strict and the bounds are explicit.
* Enums mirror the vocabulary of the SENTINEL wire contract but are defined
  here: the native schema is authoritative and :mod:`benchmark.wire` translates
  it. The legacy adapter is a compatibility layer, not a second source of truth.
* **Labels never reach a request.** ``pair_id``, ``scenario_kind``,
  ``attack_family``, ``split``, ``scoring`` and ``dataset`` are benchmark
  metadata. :func:`benchmark.validators.check_label_leakage` proves that none of
  them is serialised into the decision request built by :mod:`benchmark.wire`.
* ``model_dump(mode="json")`` with :func:`canonical_json` is the canonical byte
  form used for every dataset hash. Two checkouts of the same scenario produce
  the same digest.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from benchmark import SCHEMA_VERSION

# --------------------------------------------------------------------------- #
# Bounds (native, deliberately tighter than the wire limits they must fit into)
# --------------------------------------------------------------------------- #

MAX_ID = 80
MAX_TITLE = 200
MAX_DESCRIPTION = 2000
MAX_GOAL = 4000
MAX_CONTENT = 4000
MAX_ARGUMENT_CHARS = 4000
MAX_ARGUMENTS = 32
MAX_PROVENANCE_NODES = 64
MAX_OBSERVATIONS = 32
MAX_ACTIONS = 16
MAX_POLICY_TOOLS = 64
MAX_TAGS = 16

Identifier = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{2,79}$")]
ShortIdentifier = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
ToolName = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")]
Tag = Annotated[str, Field(min_length=1, max_length=48)]
ActorName = Annotated[str, Field(min_length=1, max_length=256)]


# --------------------------------------------------------------------------- #
# Vocabulary
# --------------------------------------------------------------------------- #


class TrustLevel(StrEnum):
    """Ordered from most to least trusted; mirrors the wire vocabulary."""

    SYSTEM_POLICY = "system_policy"
    AUTHENTICATED_USER = "authenticated_user"
    TRUSTED_INTERNAL = "trusted_internal"
    UNTRUSTED_INTERNAL = "untrusted_internal"
    UNTRUSTED_EXTERNAL = "untrusted_external"
    ADVERSARY_CONTROLLED = "adversary_controlled"


class Sensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class SourceType(StrEnum):
    """Where an observation physically came from."""

    USER_MESSAGE = "user_message"
    AGENT_MESSAGE = "agent_message"
    EMAIL = "email"
    DOCUMENT = "document"
    TICKET = "ticket"
    WIKI = "wiki"
    LOG = "log"
    ALERT = "alert"
    INTEL = "intel"
    TOOL_OUTPUT = "tool_output"
    MEMORY = "memory"
    WEB = "web"
    POLICY = "policy"
    OTHER = "other"


class Domain(StrEnum):
    ENTERPRISE = "enterprise"
    FINANCE = "finance"
    SOC = "soc"


class AttackFamily(StrEnum):
    """The ten required families plus the matched-benign lane."""

    DIRECT_PROMPT_INJECTION = "direct_prompt_injection"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    PROVENANCE_LAUNDERING = "provenance_laundering"
    MEMORY_POISONING = "memory_poisoning"
    UNAUTHORIZED_TOOL_USE = "unauthorized_tool_use"
    SENSITIVE_DATA_EXFILTRATION = "sensitive_data_exfiltration"
    CONFIRMATION_BYPASS = "confirmation_bypass"
    REPLAY_TAMPERING = "replay_tampering"
    UNSAFE_REWRITE = "unsafe_rewrite"
    OUTPUT_INTEGRITY = "output_integrity"


class SafetyProperty(StrEnum):
    NO_UNAUTHORIZED_TOOL = "no_unauthorized_tool"
    CONSEQUENTIAL_REQUIRES_CONFIRMATION = "consequential_requires_confirmation"
    NO_SENSITIVE_DATA_TO_UNTRUSTED_SINK = "no_sensitive_data_to_untrusted_sink"
    NO_PERSISTED_UNTRUSTED_INSTRUCTION = "no_persisted_untrusted_instruction"
    PROVENANCE_INTEGRITY = "provenance_integrity"
    OUTPUT_INTEGRITY = "output_integrity"
    NO_REPLAY_AUTHORIZATION = "no_replay_authorization"
    REWRITE_PRESERVES_POLICY = "rewrite_preserves_policy"
    NO_FORBIDDEN_EFFECT = "no_forbidden_effect"


class Split(StrEnum):
    DEVELOPMENT = "development"
    VALIDATION = "validation"
    HOLDOUT = "holdout"


class ScenarioKind(StrEnum):
    ATTACK = "attack"
    BENIGN = "benign"


class ActionType(StrEnum):
    RESPOND = "respond"
    TOOL_CALL = "tool_call"
    MEMORY_WRITE = "memory_write"
    REQUEST_CONFIRMATION = "request_confirmation"


ArgumentValue = str | int | float | bool | None

#: How a benign episode's declared utility is judged against the gateway verdict.
Expectation = Literal["allowed", "escalated", "blocked", "not_allowed"]

#: How an attack's success is judged. ``action_authorization`` is the default;
#: ``action_authorization_with_leakage`` additionally counts a rewrite as a
#: failure when the effective (post-rewrite) action still carries the secret.
ScoringMethod = Literal["action_authorization", "action_authorization_with_leakage"]

#: How a declared confirmation grant is normalised for the request. The runner
#: never mints a grant: it cannot, because it talks HTTP only, and a benchmark
#: that could mint a valid grant through a side channel would be testing itself.
GrantKind = Literal["bare_digest", "foreign_bound", "malformed", "expired"]


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #


def _non_empty(value: str, field: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{field} must not be blank")
    if "TODO" in stripped.upper() or stripped.lower() in {"unknown", "tbd", "n/a"}:
        raise ValueError(f"{field} must be a real value, not a placeholder: {value!r}")
    return stripped


class ProvenanceNode(BaseModel):
    """One node of the provenance graph.

    ``origin_actor`` is who *actually* produced the content; ``retrieved_via``
    is the retrieval path used to reach it. A node whose ``origin_actor`` is
    untrusted but whose ``trust_level`` is trusted is exactly the laundering
    signal the provenance-laundering family exercises, so both fields are
    mandatory and separate.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: ShortIdentifier
    source_type: SourceType
    source_id: Annotated[str, Field(min_length=1, max_length=256)]
    trust_level: TrustLevel
    sensitivity: Sensitivity
    origin_actor: ActorName
    retrieved_via: ActorName
    observed_at: datetime
    parents: tuple[ShortIdentifier, ...] = Field(
        default_factory=tuple, max_length=MAX_PROVENANCE_NODES
    )
    labels: tuple[Tag, ...] = Field(default_factory=tuple, max_length=MAX_TAGS)

    @field_validator("observed_at")
    @classmethod
    def _timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        return value


class Observation(BaseModel):
    """Bounded content the agent saw, tied to exactly one provenance node."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: ShortIdentifier
    kind: ShortIdentifier
    content: Annotated[str, Field(min_length=1, max_length=MAX_CONTENT)]
    provenance_id: ShortIdentifier


class ActionSpec(BaseModel):
    """A proposed action, shape-compatible with the wire candidate action."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: ActionType
    tool: ToolName | None = None
    arguments: dict[Annotated[str, Field(min_length=1, max_length=64)], ArgumentValue] = Field(
        default_factory=dict
    )
    content: Annotated[str, Field(max_length=MAX_CONTENT)] | None = None
    final: bool = False
    confirmation_for: ActionSpec | None = None

    @field_validator("arguments")
    @classmethod
    def _bounded_arguments(cls, value: dict[str, ArgumentValue]) -> dict[str, ArgumentValue]:
        if len(value) > MAX_ARGUMENTS:
            raise ValueError(f"at most {MAX_ARGUMENTS} arguments are allowed")
        for key, item in value.items():
            if not key.isidentifier():
                raise ValueError(f"argument name must be an identifier: {key!r}")
            if isinstance(item, str) and len(item) > MAX_ARGUMENT_CHARS:
                raise ValueError(f"argument {key!r} exceeds {MAX_ARGUMENT_CHARS} characters")
            if isinstance(item, float) and item != item:  # NaN
                raise ValueError(f"argument {key!r} must be finite")
        return value

    @model_validator(mode="after")
    def _shape_matches_type(self) -> Self:
        if self.type is ActionType.TOOL_CALL:
            if self.tool is None:
                raise ValueError("tool_call actions require 'tool'")
            if self.content is not None or self.confirmation_for is not None:
                raise ValueError("tool_call actions take 'arguments' only")
        elif self.type in (ActionType.RESPOND, ActionType.MEMORY_WRITE):
            if self.content is None:
                raise ValueError(f"{self.type} actions require 'content'")
            if self.tool is not None or self.arguments or self.confirmation_for is not None:
                raise ValueError(f"{self.type} actions take 'content' only")
        else:
            target = self.confirmation_for
            if target is None or target.type is not ActionType.TOOL_CALL:
                raise ValueError("request_confirmation requires a tool_call in 'confirmation_for'")
            if self.tool is not None or self.arguments:
                raise ValueError("request_confirmation takes 'confirmation_for' and 'content' only")
        if self.final and self.type is not ActionType.RESPOND:
            raise ValueError("only respond actions can be final")
        return self


class ProposedAction(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    step_id: int = Field(ge=0, le=99)
    description: Annotated[str, Field(min_length=1, max_length=400)]
    action: ActionSpec


class PolicyContext(BaseModel):
    """Declarative policy facts handed to the gateway with the request."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    policy_id: Annotated[str, Field(min_length=1, max_length=64)]
    policy_version: Annotated[str, Field(min_length=1, max_length=64)]
    allowed_tools: tuple[ToolName, ...] = Field(min_length=1, max_length=MAX_POLICY_TOOLS)
    consequential_tools: tuple[ToolName, ...] = Field(
        default_factory=tuple, max_length=MAX_POLICY_TOOLS
    )
    confirmation_required_tools: tuple[ToolName, ...] = Field(
        default_factory=tuple, max_length=MAX_POLICY_TOOLS
    )
    internal_email_domains: tuple[str, ...] = Field(
        default_factory=tuple, max_length=MAX_POLICY_TOOLS
    )


class HistoryStep(BaseModel):
    """A prior tool call summarised into the request's history digest."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    step_id: int = Field(ge=0, le=99)
    tool: ToolName
    decision: Literal["allow", "block", "escalate", "rewrite"]
    succeeded: bool | None = None


class HistoryDigest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    steps_taken: int = Field(default=0, ge=0, le=200)
    tool_calls: tuple[HistoryStep, ...] = Field(default_factory=tuple, max_length=64)
    blocked_count: int = Field(default=0, ge=0, le=200)
    escalated_count: int = Field(default=0, ge=0, le=200)


class ConfirmationGrant(BaseModel):
    """A caller-supplied confirmation grant, declared symbolically.

    ``value`` is used verbatim. The kind is documentation plus a validator
    check: a ``bare_digest`` must look like a bare 24-hex digest, a
    ``foreign_bound`` must be four ``:``-separated components, an ``expired``
    must carry an expiry in the past, and a ``malformed`` need only be a string.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: GrantKind
    value: Annotated[str, Field(min_length=1, max_length=512)]


class ExpectedSafetyProperty(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    property: SafetyProperty
    statement: Annotated[str, Field(min_length=1, max_length=600)]


class UtilityCriterion(BaseModel):
    """What a *benign* episode must do for the system to be useful."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    statement: Annotated[str, Field(min_length=1, max_length=600)]
    step_id: int = Field(ge=0, le=99)
    expectation: Expectation


class LeakageSpec(BaseModel):
    """Post-condition for the unsafe-rewrite family.

    The attack succeeds when the effective action (the original proposal, or the
    gateway's rewrite of it) still carries ``secret_value`` after normalization.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    secret_value: Annotated[str, Field(min_length=8, max_length=512)]
    normalization: Literal["exact", "alnum_lower", "compact"]
    statement: Annotated[str, Field(min_length=1, max_length=600)]


class ScoringSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    method: ScoringMethod
    attack_step_id: int | None = Field(default=None, ge=0, le=99)
    leakage: LeakageSpec | None = None

    @model_validator(mode="after")
    def _method_matches_payload(self) -> Self:
        if self.method == "action_authorization_with_leakage" and self.leakage is None:
            raise ValueError("action_authorization_with_leakage requires a leakage spec")
        if self.method == "action_authorization" and self.leakage is not None:
            raise ValueError("a leakage spec requires the action_authorization_with_leakage method")
        return self


class DatasetProvenance(BaseModel):
    """Licence and provenance of the scenario file itself."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    license: Annotated[str, Field(min_length=1, max_length=200)]
    origin: Annotated[str, Field(min_length=1, max_length=300)]
    created: date
    synthetic: bool
    source_reference: Annotated[str, Field(max_length=300)] | None = None
    notes: Annotated[str, Field(max_length=1000)] = ""

    @field_validator("license", "origin")
    @classmethod
    def _real_value(cls, value: str, info: Any) -> str:
        return _non_empty(value, str(info.field_name))


class Scenario(BaseModel):
    """A native, self-contained agentic episode."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["aegisgraph-benchmark/v1"] = SCHEMA_VERSION  # type: ignore[assignment]
    scenario_version: int = Field(default=1, ge=1, le=1000)
    id: Identifier
    title: Annotated[str, Field(min_length=1, max_length=MAX_TITLE)]
    description: Annotated[str, Field(max_length=MAX_DESCRIPTION)] = ""
    domain: Domain
    scenario_kind: ScenarioKind
    attack_family: AttackFamily | None = None
    pair_id: ShortIdentifier
    paraphrase_family: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")]
    split: Split
    user_goal: Annotated[str, Field(min_length=1, max_length=MAX_GOAL)]
    provenance: tuple[ProvenanceNode, ...] = Field(min_length=1, max_length=MAX_PROVENANCE_NODES)
    observations: tuple[Observation, ...] = Field(min_length=1, max_length=MAX_OBSERVATIONS)
    proposed_actions: tuple[ProposedAction, ...] = Field(min_length=1, max_length=MAX_ACTIONS)
    policy_context: PolicyContext
    history: HistoryDigest = Field(default_factory=HistoryDigest)
    confirmations: tuple[ConfirmationGrant, ...] = Field(default_factory=tuple, max_length=8)
    expected_safety_property: ExpectedSafetyProperty
    utility_criterion: UtilityCriterion
    scoring: ScoringSpec
    dataset: DatasetProvenance
    tags: tuple[Tag, ...] = Field(default_factory=tuple, max_length=MAX_TAGS)

    @property
    def attack_present(self) -> bool:
        return self.scenario_kind is ScenarioKind.ATTACK

    @property
    def family_label(self) -> str:
        """The attack family for slicing; ``unlabelled`` when a control omits it."""

        return self.attack_family.value if self.attack_family is not None else "unlabelled"

    @model_validator(mode="after")
    def _internally_consistent(self) -> Self:
        node_ids = [node.id for node in self.provenance]
        if len(set(node_ids)) != len(node_ids):
            raise ValueError("provenance node ids must be unique")
        known = set(node_ids)
        for node in self.provenance:
            missing = [parent for parent in node.parents if parent not in known]
            if missing:
                raise ValueError(f"provenance node {node.id!r} has unknown parents: {missing}")
        for node in self.provenance:
            if node.id in node.parents:
                raise ValueError(f"provenance node {node.id!r} cannot be its own parent")

        observation_ids = [observation.id for observation in self.observations]
        if len(set(observation_ids)) != len(observation_ids):
            raise ValueError("observation ids must be unique")
        for observation in self.observations:
            if observation.provenance_id not in known:
                raise ValueError(
                    f"observation {observation.id!r} references unknown provenance "
                    f"{observation.provenance_id!r}"
                )

        step_ids = [proposed.step_id for proposed in self.proposed_actions]
        if len(set(step_ids)) != len(step_ids):
            raise ValueError("proposed action step ids must be unique")
        if (
            self.scoring.method == "action_authorization_with_leakage"
            and self.scoring.attack_step_id not in step_ids
        ):
            raise ValueError("scoring.attack_step_id must reference a proposed action")
        if self.scoring.attack_step_id is not None and self.scoring.attack_step_id not in step_ids:
            raise ValueError("scoring.attack_step_id must reference a proposed action")
        if self.utility_criterion.step_id not in step_ids:
            raise ValueError("utility_criterion.step_id must reference a proposed action")

        if self.scenario_kind is ScenarioKind.ATTACK:
            if self.attack_family is None:
                raise ValueError("an attack scenario must declare an attack_family")
            if self.scoring.attack_step_id is None:
                raise ValueError("an attack scenario must declare scoring.attack_step_id")
            if self.utility_criterion.expectation == "allowed":
                pass  # an attack may carry a legitimate step too
        else:
            if self.scoring.attack_step_id is not None:
                raise ValueError("a benign control must not declare scoring.attack_step_id")
            if self.utility_criterion.expectation not in {"allowed", "escalated"}:
                raise ValueError(
                    "a benign control's expectation must be 'allowed' or 'escalated'; "
                    "'blocked' and 'not_allowed' are not derivable from the episode, so "
                    "accepting them would let a relabelled control flip utility and FBR"
                )
        for grant in self.confirmations:
            if grant.kind == "bare_digest" and len(grant.value) != 24:
                raise ValueError("a bare_digest grant must be a 24-character digest")
            if grant.kind == "foreign_bound" and grant.value.count(":") < 3:
                raise ValueError("a foreign_bound grant must have four ':'-separated components")
        return self


# --------------------------------------------------------------------------- #
# Canonical serialisation and hashing
# --------------------------------------------------------------------------- #


def canonical_json(value: object) -> str:
    """Return the canonical JSON text used for every benchmark hash."""

    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, separators=(",", ": "))
        + "\n"
    )


def scenario_payload(scenario: Scenario) -> dict[str, Any]:
    return scenario.model_dump(mode="json")


def canonical_scenario_text(scenario: Scenario) -> str:
    return canonical_json(scenario_payload(scenario))


def scenario_hash(scenario: Scenario) -> str:
    """SHA-256 of the canonical scenario text."""

    return hashlib.sha256(canonical_scenario_text(scenario).encode("utf-8")).hexdigest()


def parse_scenario(data: object) -> Scenario:
    """Validate one decoded JSON value into a :class:`Scenario`."""

    return Scenario.model_validate(data)


def load_scenario_text(text: str) -> Scenario:
    return Scenario.model_validate(json.loads(text))


def scenario_json_schema() -> dict[str, Any]:
    """The exported JSON Schema, for reviewers who do not read Python."""

    return Scenario.model_json_schema()


ActionSpec.model_rebuild()
