"""The confirmation channel: a grant is a record, not a string (finding F2, decision D4).

Regression coverage for H2-03: a *syntactically perfect* grant whose
``(run_id, step_id, execution_digest, expiry)`` all match must still escalate when
it was never issued through ``POST /api/v1/confirmations``, and every refusal must
appear in the audit trail. Replay cases (another tenant, another run, another step,
another action, expired, malformed) are covered individually.

The engine's strict binding check stays as a second line of defence; these tests
assert the *observable* outcome, not which layer produced it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from aegisgraph.app import app
from aegisgraph.auth import SCOPE_CONFIRMATION_GRANT
from aegisgraph.settings import load_settings
from aegisgraph.store import GrantRecord, open_store
from fastapi.testclient import TestClient
from m2_support import AuthHarness, decision_payload, seed_policy_set

client = TestClient(app)

TENANT = "tenant-a"
OTHER_TENANT = "tenant-b"
RUN_ID = "confirm-run"
STEP_ID = 9
CONSEQUENTIAL_POLICY = {
    "allowed_tools": ["payment_execute"],
    "confirmation_required_tools": [],
    "consequential_tools": ["payment_execute"],
}


def _payload(*, request_id: str, run_id: str = RUN_ID, step_id: int = STEP_ID,
             confirmations: tuple[str, ...] = (), amount: int = 25) -> dict[str, Any]:
    payload = decision_payload(
        request_id=request_id,
        run_id=run_id,
        step_id=step_id,
        tool="payment_execute",
        confirmations=confirmations,
    )
    payload["candidate_action"] = {
        "type": "tool_call",
        "tool": "payment_execute",
        "arguments": {"amount": amount},
    }
    return payload


def _submit(auth: AuthHarness, *, tenant: str = TENANT, **kwargs: Any) -> Any:
    return client.post(
        "/api/v1/decisions",
        json=_payload(**kwargs),
        headers=auth.header(role="decision_client", tenant=tenant),
    )


def _issue(auth: AuthHarness, *, tenant: str = TENANT, run_id: str = RUN_ID,
           step_id: int = STEP_ID, execution_digest: str, ttl_seconds: int = 300) -> Any:
    return client.post(
        "/api/v1/confirmations",
        json={
            "run_id": run_id,
            "step_id": step_id,
            "execution_digest": execution_digest,
            "ttl_seconds": ttl_seconds,
        },
        headers=auth.header(scopes=(SCOPE_CONFIRMATION_GRANT,), tenant=tenant),
    )


def _refusals(auth: AuthHarness, *, tenant: str = TENANT) -> list[dict[str, Any]]:
    events = client.get(
        "/api/v1/audit-events?limit=50", headers=auth.header(role="auditor", tenant=tenant)
    ).json()["items"]
    return [event for event in events if event["event_type"] == "confirmation_grant_refused"]


@pytest.fixture
def prepared(auth: AuthHarness) -> str:
    """Seed the server policy and return the exact execution digest to confirm."""

    seed_policy_set(TENANT, document=CONSEQUENTIAL_POLICY)
    first = _submit(auth, request_id="confirm-probe")
    assert first.status_code == 200
    assert first.json()["decision"] == "escalate"
    assert first.json()["reason_codes"] == ["CONFIRMATION_REQUIRED"]
    return str(first.json()["execution_digest"])


def test_a_syntactically_perfect_but_never_issued_grant_still_escalates(
    auth: AuthHarness, prepared: str
) -> None:
    """H2-03 regression: matching every field is not proof of confirmation."""

    expiry = int((datetime.now(UTC) + timedelta(minutes=5)).timestamp())
    never_issued = f"{RUN_ID}:{STEP_ID}:{prepared}:{expiry}"

    response = _submit(auth, request_id="never-issued", confirmations=(never_issued,))

    assert response.status_code == 200
    assert response.json()["decision"] == "escalate"
    assert response.json()["reason_codes"] == ["CONFIRMATION_REQUIRED"]
    refusals = _refusals(auth)
    assert [event["details"]["reasons"] for event in refusals] == [["not_issued"]]
    assert refusals[0]["details"] == {
        "presented": 1,
        "accepted": 0,
        "refused": 1,
        "reasons": ["not_issued"],
    }
    assert refusals[0]["subject"] == "never-issued"


def test_an_issued_grant_allows_exactly_the_action_it_was_issued_for(
    auth: AuthHarness, prepared: str
) -> None:
    issued = _issue(auth, execution_digest=prepared)

    assert issued.status_code == 201
    response = _submit(auth, request_id="issued", confirmations=(issued.json()["grant"],))

    assert response.status_code == 200
    assert response.json()["decision"] == "allow"
    assert response.json()["reason_codes"] == ["CONFIRMATION_VERIFIED"]
    assert _refusals(auth) == []


def test_a_grant_issued_for_another_run_is_refused_when_replayed(
    auth: AuthHarness, prepared: str
) -> None:
    issued = _issue(auth, execution_digest=prepared, run_id="original-run")

    response = _submit(
        auth, request_id="cross-run", run_id=RUN_ID, confirmations=(issued.json()["grant"],)
    )

    assert response.json()["decision"] == "escalate"
    assert _refusals(auth)[0]["details"]["reasons"] == ["not_bound"]


def test_a_grant_issued_for_another_step_is_refused_when_replayed(
    auth: AuthHarness, prepared: str
) -> None:
    issued = _issue(auth, execution_digest=prepared, step_id=STEP_ID + 1)

    response = _submit(auth, request_id="cross-step", confirmations=(issued.json()["grant"],))

    assert response.json()["decision"] == "escalate"
    assert _refusals(auth)[0]["details"]["reasons"] == ["not_bound"]


def test_a_grant_issued_for_another_action_is_refused(auth: AuthHarness, prepared: str) -> None:
    issued = _issue(auth, execution_digest=prepared)

    response = _submit(
        auth, request_id="cross-action", confirmations=(issued.json()["grant"],), amount=999
    )

    assert response.json()["decision"] == "escalate"
    assert _refusals(auth)[0]["details"]["reasons"] == ["not_bound"]


def test_a_grant_issued_to_another_tenant_is_refused(auth: AuthHarness, prepared: str) -> None:
    issued = _issue(auth, tenant=OTHER_TENANT, execution_digest=prepared)
    assert issued.status_code == 201

    response = _submit(auth, request_id="cross-tenant", confirmations=(issued.json()["grant"],))

    assert response.json()["decision"] == "escalate"
    assert _refusals(auth)[0]["details"]["reasons"] == ["not_issued"]


def test_an_expired_grant_is_refused_and_audited(auth: AuthHarness, prepared: str) -> None:
    store = open_store(load_settings())
    now = datetime.now(UTC)
    store.issue_grant(
        GrantRecord(
            tenant_id=TENANT,
            run_id=RUN_ID,
            step_id=STEP_ID,
            execution_digest=prepared,
            issued_by="reviewer-a",
            issued_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
        )
    )

    response = _submit(auth, request_id="expired", confirmations=(
        f"{RUN_ID}:{STEP_ID}:{prepared}:{int((now - timedelta(hours=1)).timestamp())}",
    ))

    assert response.json()["decision"] == "escalate"
    assert _refusals(auth)[0]["details"]["reasons"] == ["expired"]


@pytest.mark.parametrize(
    "grant",
    ["nonsense", "run:step:digest", "", f"{RUN_ID}:{STEP_ID}:not-a-digest:99999999999"],
)
def test_a_malformed_grant_is_refused_and_audited(
    auth: AuthHarness, prepared: str, grant: str
) -> None:
    response = _submit(auth, request_id="malformed", confirmations=(grant,))

    assert response.json()["decision"] == "escalate"
    assert _refusals(auth)[0]["details"]["reasons"] == ["malformed"]


def test_several_presented_grants_are_classified_individually(
    auth: AuthHarness, prepared: str
) -> None:
    issued = _issue(auth, execution_digest=prepared).json()["grant"]
    expiry = int((datetime.now(UTC) + timedelta(minutes=5)).timestamp())
    never_issued = f"{RUN_ID}:{STEP_ID}:{'0' * 24}:{expiry}"

    response = _submit(
        auth,
        request_id="mixed",
        confirmations=(issued, "nonsense", never_issued),
    )

    assert response.json()["decision"] == "allow"
    assert response.json()["reason_codes"] == ["CONFIRMATION_VERIFIED"]
    assert _refusals(auth)[0]["details"] == {
        "presented": 3,
        "accepted": 1,
        "refused": 2,
        "reasons": ["malformed", "not_issued"],
    }


def test_issuing_requires_the_grant_scope(auth: AuthHarness, prepared: str) -> None:
    response = client.post(
        "/api/v1/confirmations",
        json={"run_id": RUN_ID, "step_id": STEP_ID, "execution_digest": prepared},
        headers=auth.header(role="decision_client", tenant=TENANT),
    )

    assert response.status_code == 403
    assert response.json()["code"] == "INSUFFICIENT_SCOPE"


def test_the_confirmation_surface_refuses_unknown_fields(auth: AuthHarness) -> None:
    response = client.post(
        "/api/v1/confirmations",
        json={
            "run_id": RUN_ID,
            "step_id": STEP_ID,
            "execution_digest": "0" * 24,
            "note": "please approve",
        },
        headers=auth.header(scopes=(SCOPE_CONFIRMATION_GRANT,), tenant=TENANT),
    )

    assert response.status_code == 422
