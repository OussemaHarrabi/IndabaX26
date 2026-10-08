"""Bounded-input regression tests for the confirmed M1 findings F4 and F5."""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from importlib import import_module
from typing import Any

import aegisgraph.engine as engine
import pytest
from aegisgraph.app import DEFAULT_MAX_BODY_BYTES, MAX_BODY_BYTES_ENV, max_body_bytes
from aegisgraph.sentinel import SentinelRequest
from fastapi.testclient import TestClient

app_module = import_module("aegisgraph.app")
client = TestClient(app_module.app)

_SENTENCE = "Please review the attached summary."
_ADVERSARIAL_CHARACTERS = "a."
"""A long run of local-part characters: the pre-fix quadratic ``findall`` input."""

_ECHOED_ADDRESS = "ops@evil.test"
"""An address the source carries and the action text echoes (H2-01 worst shape)."""

_SOURCE_TEXT = f"sent {_ECHOED_ADDRESS}. "
"""Repeated address-bearing clauses: each pre-fix rescan of this source cost ~2.6 ms."""

_SHORT_SENTENCE = "S. "
"""A sentence that is its own unit and costs nothing per pair by itself."""


def _h201_request(
    sources: int,
    sentences: int,
    *,
    sentence: str = _SHORT_SENTENCE,
    source_chars: int = 16_000,
) -> SentinelRequest:
    """Build the reviewer's H2-01 shape.

    Every source is a distinct 16 kB body of repeated address-bearing clauses, and
    the action text is ``sentences`` repetitions of ``sentence`` (an uppercase
    start, so each repetition is its own sentence). Pre-fix, every
    ``(sentence, source)`` pair rescanned the whole source for claim patterns and
    addresses, twice per request.
    """

    provenance = [
        {
            "id": f"source-{index}",
            "provenance": {
                "source_type": "email",
                "source_id": f"mailbox-{index}",
                "trust_level": "untrusted_external",
                "origin_actor": "vendor",
                "retrieved_via": "email_read",
                "sensitivity": "internal",
                "timestamp": "2026-09-21T10:30:00Z",
            },
        }
        for index in range(sources)
    ]
    return SentinelRequest.model_validate(
        {
            "run_id": "bounds-h201",
            "step_id": 0,
            "user_goal": "Review the queue",
            "conversation": [
                {
                    "role": "tool",
                    "kind": "email",
                    "content": (
                        _SOURCE_TEXT * (source_chars // len(_SOURCE_TEXT))
                    )[: source_chars - 3]
                    + f" {index:02d}",
                    "provenance_ids": [f"source-{index}"],
                }
                for index in range(sources)
            ],
            "candidate_action": {"type": "respond", "content": (sentence * sentences)[:16_000]},
            "policy_context": {"allowed_tools": ["email_read"]},
            "provenance": provenance,
            "history_digest": {"confirmations_granted": []},
        }
    )


def _valid_request_bytes(**overrides: Any) -> bytes:
    payload: dict[str, Any] = {
        "run_id": "bounds-run",
        "step_id": 1,
        "user_goal": "Perform the requested safe task",
        "conversation": [],
        "candidate_action": {"type": "respond", "content": "Ok"},
        "policy_context": {"allowed_tools": ["document_search"]},
        "history_digest": {"confirmations_granted": []},
    }
    payload.update(overrides)
    return json.dumps(payload).encode("utf-8")


def _adversarial_request(sources: int, size: int) -> SentinelRequest:
    content = _ADVERSARIAL_CHARACTERS * (size // 2)
    provenance = [
        {
            "id": f"source-{index}",
            "provenance": {
                "source_type": "email",
                "source_id": f"mailbox-{index}",
                "trust_level": "untrusted_external",
                "origin_actor": "vendor",
                "retrieved_via": "email_read",
                "sensitivity": "internal",
                "timestamp": "2026-09-21T10:30:00Z",
            },
        }
        for index in range(sources)
    ]
    return SentinelRequest.model_validate(
        {
            "run_id": "bounds-adversarial",
            "step_id": 0,
            "user_goal": "Review the queue",
            "conversation": [
                {
                    "role": "tool",
                    "kind": "email",
                    "content": content,
                    "provenance_ids": [f"source-{index}"],
                }
                for index in range(sources)
            ],
            "candidate_action": {"type": "respond", "content": _SENTENCE},
            "policy_context": {"allowed_tools": ["email_read"]},
            "provenance": provenance,
            "history_digest": {"confirmations_granted": []},
        }
    )


def test_max_body_bytes_reads_the_environment_with_a_safe_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(MAX_BODY_BYTES_ENV, raising=False)
    assert max_body_bytes() == DEFAULT_MAX_BODY_BYTES
    assert DEFAULT_MAX_BODY_BYTES == 1_048_576
    monkeypatch.setenv(MAX_BODY_BYTES_ENV, "2048")
    assert max_body_bytes() == 2048
    monkeypatch.setenv(MAX_BODY_BYTES_ENV, "not-a-number")
    assert max_body_bytes() == DEFAULT_MAX_BODY_BYTES
    monkeypatch.setenv(MAX_BODY_BYTES_ENV, "0")
    assert max_body_bytes() == DEFAULT_MAX_BODY_BYTES


def test_body_above_the_bound_is_rejected_with_content_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(MAX_BODY_BYTES_ENV, "4096")

    response = client.post(
        "/v1/decision",
        content=b'{"padding":"' + b"x" * 10_000 + b'"}',
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json() == {"detail": "Request body exceeds the configured limit"}
    assert response.headers["cache-control"] == "no-store"


def test_body_above_the_bound_is_rejected_when_streamed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(MAX_BODY_BYTES_ENV, "4096")
    body = b'{"padding":"' + b"x" * 10_000 + b'"}'

    def chunks() -> Iterator[bytes]:
        yield body[:5_000]
        yield body[5_000:]

    response = client.post(
        "/v1/decision", content=chunks(), headers={"content-type": "application/json"}
    )

    assert response.status_code == 413
    assert response.json() == {"detail": "Request body exceeds the configured limit"}
    assert response.headers["cache-control"] == "no-store"


def test_oversized_body_is_rejected_before_json_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(MAX_BODY_BYTES_ENV, "2048")

    response = client.post(
        "/v1/decision",
        content=b"not json at all " + b"y" * 4096,
        headers={"content-type": "application/json"},
    )

    # A 413 (not 400/422) proves the rejection happens before parsing.
    assert response.status_code == 413


def test_body_exactly_at_the_bound_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    body = _valid_request_bytes()
    monkeypatch.setenv(MAX_BODY_BYTES_ENV, str(len(body)))

    at_bound = client.post(
        "/v1/decision", content=body, headers={"content-type": "application/json"}
    )
    monkeypatch.setenv(MAX_BODY_BYTES_ENV, str(len(body) - 1))
    over_bound = client.post(
        "/v1/decision", content=body, headers={"content-type": "application/json"}
    )

    assert at_bound.status_code == 200
    assert at_bound.json()["decision"] == "allow"
    assert over_bound.status_code == 413


def test_streamed_body_exactly_at_the_bound_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = _valid_request_bytes()
    monkeypatch.setenv(MAX_BODY_BYTES_ENV, str(len(body)))

    accepted = client.post(
        "/v1/decision",
        content=iter([body[:64], body[64:]]),
        headers={"content-type": "application/json"},
    )
    monkeypatch.setenv(MAX_BODY_BYTES_ENV, str(len(body) - 1))
    refused = client.post(
        "/v1/decision",
        content=iter([body[:64], body[64:]]),
        headers={"content-type": "application/json"},
    )

    assert accepted.status_code == 200
    assert refused.status_code == 413


def test_generic_surface_is_bounded_the_same_way(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(MAX_BODY_BYTES_ENV, "512")
    payload = json.dumps(
        {
            "api_version": "aegisgraph/v1",
            "run_id": "bounds",
            "step_id": 0,
            "user_goal": "Padding",
            "conversation": [],
            "candidate_action": {"type": "respond", "content": "x" * 2000},
            "policy_context": {"allowed_tools": []},
            "history_digest": {},
        }
    ).encode()

    response = client.post(
        "/api/v1/decisions", content=payload, headers={"content-type": "application/json"}
    )

    assert response.status_code == 413


def _per_character_seconds(source: str) -> float:
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        engine._build_source_profile(source, "goal")
        best = min(best, time.perf_counter() - started)
    return best / len(source)


def test_laundered_claim_scan_cost_stays_flat_as_input_grows() -> None:
    """F4 regression: per-character cost must not grow with the input length."""

    small = _per_character_seconds(_ADVERSARIAL_CHARACTERS * (1024 // 2))
    large = _per_character_seconds(_ADVERSARIAL_CHARACTERS * (16384 // 2))

    # Linear scanning has a flat per-character cost; the pre-fix quadratic scan
    # measured ~9 us/char at 1 KiB and ~80 us/char at 16 KiB (a 16x growth).
    assert large < small * 4, f"per-character cost grew from {small} to {large}"


def test_worst_case_adversarial_request_is_bounded() -> None:
    """F4 regression: the measured 2 MiB worst case must finish well under 1 s."""

    request = _adversarial_request(sources=128, size=16_000)

    started = time.perf_counter()
    decision = engine.decide(request)
    elapsed = time.perf_counter() - started

    assert decision.verdict in {"allow", "block", "escalate", "rewrite"}
    assert elapsed < 1.0, f"2 MiB adversarial request took {elapsed:.3f} s"


def test_worst_case_adversarial_http_request_is_rejected_before_storage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(MAX_BODY_BYTES_ENV, "1048576")
    padding = b"x" * (2 * 1024 * 1024)

    started = time.perf_counter()
    response = client.post(
        "/v1/decision",
        content=b'{"padding":"' + padding + b'"}',
        headers={"content-type": "application/json"},
    )
    elapsed = time.perf_counter() - started

    assert response.status_code == 413
    assert elapsed < 1.0, f"2 MiB HTTP request took {elapsed:.3f} s"


def test_email_extraction_matches_the_legacy_scan_on_realistic_text() -> None:
    """The bounded scan must not change results for ordinary text."""

    text = "Contact ops@company.test or SOC team <soc.team@company.test> today. Not an @ sign."

    assert engine._email_addresses(text) == {
        "ops@company.test",
        "soc.team@company.test",
    }
    assert engine._email_addresses("no address here") == set()


def test_source_profile_is_built_once_per_distinct_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H2-01: address extraction must run once per distinct source, not per pair."""

    calls: list[str] = []
    original = engine._email_addresses

    def counting(value: str) -> set[str]:
        calls.append(value)
        return original(value)

    monkeypatch.setattr(engine, "_email_addresses", counting)
    request = _h201_request(sources=4, sentences=1000)

    engine.decide(request)

    distinct_sources = {item.content for item in request.conversation}
    assert len(distinct_sources) == 4
    # Pre-fix this shape made 8000 calls (2 passes x 1000 sentences x 4 sources).
    assert len(calls) <= len(distinct_sources), (
        f"{len(calls)} calls for {len(distinct_sources)} sources"
    )
    assert set(calls) == distinct_sources


def test_source_classification_is_lazy_and_cached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H2-01: the per-source instruction classification runs at most once."""

    calls: list[str] = []
    original = engine._classify_instruction_text

    def counting(value: str) -> engine.ClauseDisposition:
        calls.append(value)
        return original(value)

    monkeypatch.setattr(engine, "_classify_instruction_text", counting)
    # The echo sentence reaches the address-echo branch, which needs the class.
    request = _h201_request(sources=4, sentences=200, sentence=f"Sent {_ECHOED_ADDRESS}. ")

    decision = engine.decide(request)

    assert decision.verdict == "rewrite"
    assert len(calls) <= 4, f"classified {len(calls)} times for 4 sources"


def test_reviewer_worst_shape_is_decided_quickly_over_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H2-01 acceptance: 4 sources x 16 kB plus 1000 sentences in under 2 s.

    The wall-clock bound is a smoke bound (this host, not the shipped image); the
    strict assertions are the call-count tests above.
    """

    monkeypatch.setenv("AEGISGRAPH_LEGACY_UNAUTHENTICATED", "true")
    body = _h201_request(sources=4, sentences=1000).model_dump_json().encode("utf-8")

    started = time.perf_counter()
    response = client.post(
        "/v1/decision", content=body, headers={"content-type": "application/json"}
    )
    elapsed = time.perf_counter() - started

    assert response.status_code == 200
    assert elapsed < 2.0, f"worst shape took {elapsed:.3f} s (acceptance bound)"
    assert elapsed < 5.0, f"worst shape took {elapsed:.3f} s (smoke bound)"


def test_narrative_sentence_budget_fails_closed() -> None:
    """H2-01: a narrative surface too large to verify blocks instead of scanning."""

    budget = engine._MAX_NARRATIVE_SENTENCES
    request = _h201_request(sources=2, sentences=budget + 100)

    decision = engine.decide(request)

    assert decision.verdict == "block"
    assert decision.reason_codes == ("NARRATIVE_SCAN_BUDGET_EXCEEDED",)


def test_narrative_sentence_budget_does_not_affect_small_narratives() -> None:
    """The budget must stay out of the way of ordinary requests."""

    decision = engine.decide(
        _h201_request(sources=2, sentences=200, sentence=f"Sent {_ECHOED_ADDRESS}. ")
    )

    assert decision.verdict == "rewrite"
    assert decision.reason_codes == ("UNTRUSTED_AUTHORITY_REDACTED",)


def test_sentence_budget_is_renewed_for_the_revalidation_pass() -> None:
    """A redaction at the edge of the budget must not block its own revalidation."""

    budget = engine._MAX_NARRATIVE_SENTENCES
    echo = f"Sent {_ECHOED_ADDRESS}. "
    request = _h201_request(
        sources=1, sentences=1, sentence=echo + _SHORT_SENTENCE * (budget - 1)
    )

    decision = engine.decide(request)

    assert decision.reason_codes != ("NARRATIVE_SCAN_BUDGET_EXCEEDED",)
