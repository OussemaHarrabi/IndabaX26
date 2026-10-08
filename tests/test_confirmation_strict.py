"""Confirmation binding tests: strict mode on the generic surface (F6)."""

from __future__ import annotations

import time
from typing import Any

import pytest
from aegisgraph.adapter import canonical_action
from aegisgraph.app import app
from aegisgraph.contracts import ConfirmationMode, parse_confirmation_grant
from aegisgraph.engine import decide
from aegisgraph.sentinel import SentinelRequest
from fastapi.testclient import TestClient

client = TestClient(app)

RUN_ID = "strict-run"
STEP_ID = 7
PAYMENT = {"type": "tool_call", "tool": "payment_execute", "arguments": {"amount": 25}}


def _request(
    *, confirmations: list[str], run_id: str = RUN_ID, step_id: int = STEP_ID
) -> SentinelRequest:
    return SentinelRequest.model_validate(
        {
            "run_id": run_id,
            "step_id": step_id,
            "user_goal": "Execute the approved payment",
            "conversation": [],
            "candidate_action": PAYMENT,
            "policy_context": {
                "allowed_tools": ["payment_execute"],
                "confirmation_required_tools": [],
                "consequential_tools": [],
            },
            "history_digest": {"confirmations_granted": confirmations},
        }
    )


def _execution_digest(request: SentinelRequest) -> str:
    return canonical_action(request.candidate_action).execution_digest()


def _bound_grant(
    request: SentinelRequest, *, expires_at: int | None = None, run_id: str | None = None
) -> str:
    expiry = int(time.time()) + 300 if expires_at is None else expires_at
    return ":".join(
        (
            run_id if run_id is not None else RUN_ID,
            str(request.step_id),
            _execution_digest(request),
            str(expiry),
        )
    )


def test_strict_mode_accepts_a_grant_bound_to_run_step_action_and_expiry() -> None:
    request = _request(confirmations=[])
    granted = _request(confirmations=[_bound_grant(request)])

    decision = decide(granted, confirmation_mode=ConfirmationMode.STRICT)

    assert decision.verdict == "allow"
    assert decision.reason_codes == ("CONFIRMATION_VERIFIED",)


def test_strict_mode_rejects_a_bare_canonical_digest() -> None:
    bare = canonical_action(_request(confirmations=[]).candidate_action).digest()
    request = _request(confirmations=[bare])

    strict = decide(request, confirmation_mode=ConfirmationMode.STRICT)
    legacy = decide(request, confirmation_mode=ConfirmationMode.LEGACY)

    assert strict.verdict == "escalate"
    assert strict.reason_codes == ("CONFIRMATION_REQUIRED",)
    # Legacy trusted-caller mode is unchanged: the pinned harness depends on it.
    assert legacy.verdict == "allow"
    assert legacy.reason_codes == ("CONFIRMATION_VERIFIED",)


@pytest.mark.parametrize(
    "grant",
    [
        "nonsense",
        "run:step:digest",
        f"{RUN_ID}:{STEP_ID}:not-a-digest:{int(time.time()) + 300}",
        f"{RUN_ID}:not-a-step:{'0' * 24}:{int(time.time()) + 300}",
        f"{RUN_ID}:{STEP_ID}:{'0' * 24}:not-an-expiry",
        "",
    ],
)
def test_strict_mode_rejects_malformed_grants(grant: str) -> None:
    decision = decide(_request(confirmations=[grant]), confirmation_mode=ConfirmationMode.STRICT)

    assert decision.verdict == "escalate"
    assert decision.reason_codes == ("CONFIRMATION_REQUIRED",)


def test_grant_fields_must_be_ascii_decimal() -> None:
    """H2-04: ``str.isdigit`` is true for superscripts that ``int`` rejects."""

    digest = "0" * 24
    superscript = "\u00b2"  # isdigit() is True, int() raises ValueError
    arabic_indic = "\u0663"  # isdigit() is True and int() silently returns 3

    assert superscript.isdigit() and arabic_indic.isdigit()
    assert parse_confirmation_grant(f"{RUN_ID}:{superscript}:{digest}:99") is None
    assert parse_confirmation_grant(f"{RUN_ID}:1:{digest}:{superscript}") is None
    assert parse_confirmation_grant(f"{RUN_ID}:{arabic_indic}:{digest}:99") is None
    assert parse_confirmation_grant(f"{RUN_ID}:1:{digest}:9{superscript}") is None
    assert parse_confirmation_grant(f"{RUN_ID}:1:{digest}:99") is not None

    # A grant with a non-decimal step or expiry is not granted, so the action
    # escalates instead of being allowed.
    for grant in (
        f"{RUN_ID}:{superscript}:{digest}:{int(time.time()) + 300}",
        f"{RUN_ID}:{STEP_ID}:{digest}:{superscript}",
    ):
        decision = decide(
            _request(confirmations=[grant]), confirmation_mode=ConfirmationMode.STRICT
        )
        assert decision.verdict == "escalate"
        assert decision.reason_codes == ("CONFIRMATION_REQUIRED",)


def test_strict_mode_rejects_an_expired_grant() -> None:
    request = _request(confirmations=[])
    expired = _bound_grant(request, expires_at=int(time.time()) - 1)

    decision = decide(
        _request(confirmations=[expired]), confirmation_mode=ConfirmationMode.STRICT
    )

    assert decision.verdict == "escalate"


def test_strict_mode_rejects_a_grant_issued_for_another_run_or_step() -> None:
    request = _request(confirmations=[])
    other_run = _bound_grant(request, run_id="another-run")
    other_step = ":".join(
        (RUN_ID, str(STEP_ID + 1), _execution_digest(request), str(int(time.time()) + 300))
    )

    for grant in (other_run, other_step):
        decision = decide(
            _request(confirmations=[grant]), confirmation_mode=ConfirmationMode.STRICT
        )
        assert decision.verdict == "escalate"


def test_strict_mode_rejects_a_grant_for_a_colliding_action_variant() -> None:
    """A variant that collides on the canonical digest is not covered (F6)."""

    approved = _request(confirmations=[])
    variant = SentinelRequest.model_validate(
        {
            **approved.model_dump(mode="json"),
            "candidate_action": {**PAYMENT, "arguments": {"amount": 25.0}},
        }
    )
    grant = _bound_grant(approved)

    assert (
        canonical_action(variant.candidate_action).digest()
        == canonical_action(approved.candidate_action).digest()
    )
    decision = decide(
        SentinelRequest.model_validate(
            {
                **variant.model_dump(mode="json"),
                "history_digest": {"confirmations_granted": [grant]},
            }
        ),
        confirmation_mode=ConfirmationMode.STRICT,
    )

    assert decision.verdict == "escalate"
    assert parse_confirmation_grant(grant) is not None


def test_generic_endpoint_uses_strict_confirmation_binding() -> None:
    """F2 regression: only a grant issued through the channel is honoured (D4)."""

    base = _request(confirmations=[])
    bare_grant = canonical_action(base.candidate_action).digest()
    payload: dict[str, Any] = {
        "api_version": "aegisgraph/v1",
        "run_id": RUN_ID,
        "step_id": STEP_ID,
        "user_goal": "Execute the approved payment",
        "conversation": [],
        "candidate_action": PAYMENT,
        "policy_context": {
            "allowed_tools": ["payment_execute"],
            "confirmation_required_tools": [],
        },
        "history_digest": {"confirmations_granted": [bare_grant]},
    }
    bare = client.post("/api/v1/decisions", json=payload)
    unissued = client.post(
        "/api/v1/decisions",
        json={
            **payload,
            "history_digest": {"confirmations_granted": [_bound_grant(base)]},
        },
    )

    assert bare.status_code == 200
    assert bare.json()["decision"] == "escalate"
    # A syntactically perfect but never-issued grant is refused, not honoured.
    assert unissued.status_code == 200
    assert unissued.json()["decision"] == "escalate"
    assert unissued.json()["reason_codes"] == ["CONFIRMATION_REQUIRED"]

    issued = client.post(
        "/api/v1/confirmations",
        json={
            "run_id": RUN_ID,
            "step_id": STEP_ID,
            "execution_digest": _execution_digest(base),
        },
    )
    assert issued.status_code == 201
    confirmed = client.post(
        "/api/v1/decisions",
        json={
            **payload,
            "history_digest": {"confirmations_granted": [issued.json()["grant"]]},
        },
    )

    assert confirmed.status_code == 200
    assert confirmed.json()["decision"] == "allow"
    assert confirmed.json()["reason_codes"] == ["CONFIRMATION_VERIFIED"]


def test_legacy_endpoint_still_accepts_a_bare_digest() -> None:
    bare = canonical_action(_request(confirmations=[]).candidate_action).digest()
    response = client.post(
        "/v1/decision",
        json={
            "run_id": RUN_ID,
            "step_id": STEP_ID,
            "user_goal": "Execute the approved payment",
            "conversation": [],
            "candidate_action": PAYMENT,
            "policy_context": {"allowed_tools": ["payment_execute"]},
            "history_digest": {"confirmations_granted": [bare]},
        },
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "allow"
    assert response.json()["reason_codes"] == ["CONFIRMATION_VERIFIED"]
