"""Translate the wire contract into inert, provenance-aware evaluation facts."""

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import cast

from pydantic import JsonValue

from aegisgraph.contracts import (
    ActionKind,
    CandidateAction,
    GuardRequest,
    Observation,
    Sensitivity,
    TrustLevel,
)
from aegisgraph.sentinel import SentinelCandidateAction, SentinelProvenanceRecord, SentinelRequest


@dataclass(frozen=True)
class AdaptedRequest:
    request: GuardRequest
    confirmations_granted: frozenset[str]
    least_trust: TrustLevel
    max_sensitivity: Sensitivity
    provenance_complete: bool
    referenced_provenance: tuple[SentinelProvenanceRecord, ...]


def adapt_request(request: SentinelRequest) -> AdaptedRequest:
    """Resolve wire provenance into bounded canonical observations.

    Every referenced source becomes its own observation so a high-trust source can
    never hide a low-trust co-source. Missing or ambiguous references are represented
    explicitly with adversary-controlled/restricted labels and make the adapter
    incomplete, which the engine fails closed.
    """

    records: dict[str, SentinelProvenanceRecord | None] = {}
    for record in request.provenance:
        records[record.id] = None if record.id in records else record

    observations: list[Observation] = []
    referenced_records: list[SentinelProvenanceRecord] = []
    referenced_ids: set[str] = set()
    complete = True

    def append_resolved(kind: str, content: str, ids: Iterable[str], *, role: str) -> None:
        nonlocal complete
        identifiers = tuple(ids)
        if not identifiers:
            if role in {"user", "agent", "safety", "human"}:
                trust = (
                    TrustLevel.AUTHENTICATED_USER if role == "user" else TrustLevel.TRUSTED_INTERNAL
                )
                observations.append(
                    Observation(
                        kind=_safe_kind(kind),
                        content=content,
                        source=f"implicit:{role}",
                        trust_level=trust,
                        sensitivity=Sensitivity.INTERNAL,
                    )
                )
                return
            complete = False
            observations.append(_unknown_observation(kind, content, "missing"))
            return

        for identifier in identifiers:
            record = records.get(identifier)
            if record is None:
                complete = False
                observations.append(_unknown_observation(kind, content, identifier))
                continue
            provenance = record.provenance
            if identifier not in referenced_ids:
                referenced_ids.add(identifier)
                referenced_records.append(record)
            observations.append(
                Observation(
                    kind=_safe_kind(kind),
                    content=content,
                    source=(f"{identifier}:{provenance.source_type}:{provenance.source_id}"),
                    trust_level=TrustLevel(provenance.trust_level),
                    sensitivity=Sensitivity(provenance.sensitivity),
                )
            )

    for item in request.conversation:
        append_resolved(item.kind, item.content, item.provenance_ids, role=item.role)
    if request.observation is not None:
        append_resolved(
            request.observation.kind,
            request.observation.content,
            request.observation.provenance_ids,
            role="observation",
        )

    least_trust = max(
        (item.trust_level for item in observations),
        key=lambda item: list(TrustLevel).index(item),
        default=TrustLevel.AUTHENTICATED_USER,
    )
    max_sensitivity = max(
        (item.sensitivity for item in observations),
        key=lambda item: list(Sensitivity).index(item),
        default=Sensitivity.INTERNAL,
    )
    dumped_context = cast(dict[str, JsonValue], request.model_dump(mode="json")["policy_context"])
    canonical = GuardRequest(
        request_id=f"{request.run_id}:{request.step_id}",
        user_goal=request.user_goal or "Unspecified user goal",
        observations=tuple(observations),
        candidate_action=_canonical_action(request.candidate_action),
        policy_context=dumped_context,
    )
    return AdaptedRequest(
        request=canonical,
        confirmations_granted=frozenset(request.history_digest.confirmations_granted),
        least_trust=least_trust,
        max_sensitivity=max_sensitivity,
        provenance_complete=complete,
        referenced_provenance=tuple(referenced_records),
    )


def _canonical_action(action: SentinelCandidateAction) -> CandidateAction:
    target = (
        _canonical_action(action.confirmation_for) if action.confirmation_for is not None else None
    )
    return CandidateAction(
        type=ActionKind(action.type),
        tool=action.tool,
        arguments=action.arguments,
        content=action.content,
        final=action.final,
        confirmation_for=target,
    )


def _unknown_observation(kind: str, content: str, identifier: str) -> Observation:
    return Observation(
        kind=_safe_kind(kind),
        content=content,
        source=f"unresolved:{identifier}",
        trust_level=TrustLevel.ADVERSARY_CONTROLLED,
        sensitivity=Sensitivity.RESTRICTED,
    )


def _safe_kind(kind: str) -> str:
    normalized = re.sub(r"[^a-z0-9_]+", "_", kind.lower()).strip("_")
    if not normalized or not normalized[0].isalpha():
        normalized = f"event_{normalized}" if normalized else "event"
    return normalized[:64]
