"""Translate the wire contract into inert, provenance-aware evaluation facts."""

import hashlib
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

_MAX_CANONICAL_OBSERVATIONS = 128


@dataclass(frozen=True)
class AdaptedRequest:
    request: GuardRequest
    confirmations_granted: frozenset[str]
    least_trust: TrustLevel
    max_sensitivity: Sensitivity
    provenance_complete: bool
    referenced_provenance: tuple[SentinelProvenanceRecord, ...]
    evidence_truncated: bool


def adapt_request(request: SentinelRequest) -> AdaptedRequest:
    """Resolve wire provenance into bounded canonical observations.

    Every referenced source becomes its own observation so a high-trust source can
    never hide a low-trust co-source. Explicit missing or ambiguous references are
    represented with adversary-controlled/restricted labels and fail closed. Evidence
    supplied without provenance identifiers remains usable but is marked unattributed
    and untrusted rather than being confused with a broken integrity reference.
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
            observations.append(_unattributed_observation(kind, content, role))
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
                    source=_compact_source(
                        f"{identifier}:{provenance.source_type}:{provenance.source_id}"
                    ),
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
    bounded_observations = _select_security_relevant_observations(observations)
    dumped_context = cast(dict[str, JsonValue], request.model_dump(mode="json")["policy_context"])
    canonical = GuardRequest(
        request_id=_canonical_request_id(request),
        user_goal=request.user_goal or "Unspecified user goal",
        observations=bounded_observations,
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
        evidence_truncated=len(observations) > _MAX_CANONICAL_OBSERVATIONS,
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
        source=_compact_source(f"unresolved:{identifier}"),
        trust_level=TrustLevel.ADVERSARY_CONTROLLED,
        sensitivity=Sensitivity.RESTRICTED,
    )


def _unattributed_observation(kind: str, content: str, role: str) -> Observation:
    return Observation(
        kind=_safe_kind(kind),
        content=content,
        source=_compact_source(f"unattributed:{role}"),
        trust_level=TrustLevel.UNTRUSTED_INTERNAL,
        sensitivity=Sensitivity.INTERNAL,
    )


def _safe_kind(kind: str) -> str:
    normalized = re.sub(r"[^a-z0-9_]+", "_", kind.lower()).strip("_")
    if not normalized or not normalized[0].isalpha():
        normalized = f"event_{normalized}" if normalized else "event"
    return normalized[:64]


def _canonical_request_id(request: SentinelRequest) -> str:
    material = f"{request.run_id}\x00{request.step_id}".encode()
    return f"request:{hashlib.sha256(material).hexdigest()[:32]}"


def _compact_source(source: str) -> str:
    if len(source) <= 256:
        return source
    digest = hashlib.sha256(source.encode()).hexdigest()
    return f"source:{digest}"


def _select_security_relevant_observations(
    observations: list[Observation],
) -> tuple[Observation, ...]:
    """Bound expansion while keeping the least-trusted, most-sensitive evidence."""

    if len(observations) <= _MAX_CANONICAL_OBSERVATIONS:
        return tuple(observations)
    ranked = sorted(
        enumerate(observations),
        key=lambda pair: (
            -list(TrustLevel).index(pair[1].trust_level),
            -list(Sensitivity).index(pair[1].sensitivity),
            pair[0],
        ),
    )
    selected = sorted(index for index, _ in ranked[:_MAX_CANONICAL_OBSERVATIONS])
    return tuple(observations[index] for index in selected)
