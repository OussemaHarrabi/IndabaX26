"""Trust ceiling, policy authority and policy administration (findings F1/F3, decisions D2, D3).

The two rules under test are the ones that close F3:

* a request may not assert provenance above the caller's ceiling, and it is
  refused rather than silently downgraded (D2);
* caller-supplied ``policy_context`` is ignored unless the caller holds
  ``policy:context_override``, so relabelling evidence or editing the request can
  never switch off a server-side control (D3).
"""

from __future__ import annotations

from typing import Any

import pytest
from aegisgraph.app import app
from aegisgraph.auth import (
    SCOPE_CONFIRMATION_GRANT,
    SCOPE_POLICY_CONTEXT_OVERRIDE,
)
from fastapi.testclient import TestClient
from m2_support import (
    DECISION_CLIENT_SCOPES,
    POLICY_ADMIN_SCOPES,
    AuthHarness,
    decision_payload,
    seed_policy_set,
)

client = TestClient(app)

TENANT = "tenant-a"
OTHER_TENANT = "tenant-b"
SERVER_POLICY = {
    "allowed_tools": ["document_search"],
    "confirmation_required_tools": [],
    "consequential_tools": [],
    "internal_email_domains": ["example.com"],
}


def _client_token(auth: AuthHarness, *, tenant: str = TENANT, scopes: tuple[str, ...] = ()) -> str:
    return auth.token(role="decision_client", tenant=tenant, scopes=scopes)


def _submit(token: str, **overrides: Any) -> Any:
    return client.post(
        "/api/v1/decisions",
        json=decision_payload(**overrides),
        headers={"Authorization": f"Bearer {token}"},
    )


def test_a_request_above_the_trust_ceiling_is_refused_and_never_downgraded(
    auth: AuthHarness,
) -> None:
    """F1/F3 regression (D2): an over-claiming caller is refused, not softened."""

    seed_policy_set(TENANT, document=SERVER_POLICY)
    token = _client_token(auth)

    response = _submit(token, trust_level="system_policy")

    assert response.status_code == 403
    body = response.json()
    assert body["code"] == "TRUST_CEILING_EXCEEDED"
    assert "trusted_internal" in body["detail"]
    assert "decision" not in body


@pytest.mark.parametrize("level", ["trusted_internal", "untrusted_internal", "untrusted_external"])
def test_a_request_at_or_below_the_ceiling_is_evaluated(auth: AuthHarness, level: str) -> None:
    seed_policy_set(TENANT, document=SERVER_POLICY)

    response = _submit(_client_token(auth), trust_level=level)

    assert response.status_code == 200
    assert response.json()["decision"] in {"allow", "block", "escalate", "rewrite"}


def test_a_token_can_carry_a_lower_ceiling(auth: AuthHarness) -> None:
    seed_policy_set(TENANT, document=SERVER_POLICY)
    token = auth.token(role="decision_client", tenant=TENANT, trust_ceiling="untrusted_external")

    response = _submit(token, trust_level="trusted_internal")

    assert response.status_code == 403
    assert response.json()["code"] == "TRUST_CEILING_EXCEEDED"


def test_the_configured_default_ceiling_applies_when_the_token_declares_none(
    auth: AuthHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AEGISGRAPH_TRUST_CEILING_DEFAULT", "adversary_controlled")
    seed_policy_set(TENANT, document=SERVER_POLICY)

    response = _submit(_client_token(auth), trust_level="untrusted_internal")

    assert response.status_code == 403


def test_policy_context_is_ignored_without_the_override_scope(auth: AuthHarness) -> None:
    """F3 regression (D3): editing the request cannot relax the stored policy."""

    seed_policy_set(TENANT, document=SERVER_POLICY)
    token = _client_token(auth)

    response = _submit(
        token,
        tool="email_send",
        allowed_tools=("email_send",),
        policy_context_extra={"consequential_tools": [], "internal_email_domains": ["evil.test"]},
    )

    assert response.status_code == 200
    body = response.json()
    # The stored policy does not allow `email_send`, so the caller's own allow-list
    # must not have been used.
    assert body["decision"] == "block"
    assert "email_send" not in str(body.get("explanation", ""))


def test_policy_context_is_honoured_with_the_override_scope(auth: AuthHarness) -> None:
    seed_policy_set(TENANT, document=SERVER_POLICY)
    token = _client_token(auth, scopes=(SCOPE_POLICY_CONTEXT_OVERRIDE,))

    response = _submit(token, tool="document_search", allowed_tools=("document_search",))

    assert response.status_code == 200
    assert response.json()["decision"] == "allow"


def test_an_unknown_server_policy_set_is_refused_rather_than_defaulted(
    auth: AuthHarness,
) -> None:
    seed_policy_set(TENANT, document=SERVER_POLICY)
    token = _client_token(auth)

    response = _submit(token, policy_set={"id": "absent-policy", "version": "9"})

    assert response.status_code == 422
    assert response.json()["code"] == "POLICY_SET_UNKNOWN"


def test_the_stored_policy_identity_is_echoed_in_the_decision(auth: AuthHarness) -> None:
    seed_policy_set(TENANT, policy_id="stored-policy", version="4", document=SERVER_POLICY)
    token = _client_token(auth)

    response = _submit(token, policy_set={"id": "stored-policy", "version": "4"})

    assert response.status_code == 200
    assert response.json()["policy_set"] == {"id": "stored-policy", "version": "4"}


def test_policy_administration_requires_the_write_scope(auth: AuthHarness) -> None:
    body = {"id": "p-1", "version": "1", "document": SERVER_POLICY}

    assert client.post("/api/v1/policies", json=body).status_code == 401
    reader = auth.header(role="auditor", tenant=TENANT)
    assert client.post("/api/v1/policies", json=body, headers=reader).status_code == 403
    assert client.post("/api/v1/policies", json=body, headers=reader).json()["code"] == (
        "INSUFFICIENT_SCOPE"
    )


def test_a_policy_admin_publishes_versions_that_are_immutable_and_audited(
    auth: AuthHarness,
) -> None:
    headers = auth.header(role="policy_admin", tenant=TENANT)
    first = {"id": "p-1", "version": "1", "document": SERVER_POLICY}

    created = client.post("/api/v1/policies", json=first, headers=headers)
    assert created.status_code == 201
    assert created.json()["active"] is False
    assert created.json()["created_by"] == "client-a"

    # Re-publishing the identical document is idempotent.
    again = client.post("/api/v1/policies", json=first, headers=headers)
    assert again.status_code == 201
    assert again.json()["checksum"] == created.json()["checksum"]

    # A different document for the same version is refused: versions are immutable.
    conflicting = client.post(
        "/api/v1/policies",
        json={**first, "document": {**SERVER_POLICY, "allowed_tools": []}},
        headers=headers,
    )
    assert conflicting.status_code == 409
    assert conflicting.json()["code"] == "POLICY_SET_IMMUTABLE"

    activated = client.post("/api/v1/policies/p-1/activate", json={"version": "1"}, headers=headers)
    assert activated.status_code == 200
    assert activated.json()["active"] is True
    assert activated.json()["activated_at"] is not None

    listed = client.get("/api/v1/policies", headers=headers)
    assert listed.status_code == 200
    assert [item["version"] for item in listed.json()["items"]] == ["1"]
    assert listed.json()["items"][0]["active"] is True

    events = client.get("/api/v1/audit-events", headers=headers)
    assert events.status_code == 200
    kinds = [item["event_type"] for item in events.json()["items"]]
    assert kinds.count("policy_set_created") == 1
    assert kinds.count("policy_set_activated") == 1


def test_activating_an_unknown_version_is_refused(auth: AuthHarness) -> None:
    headers = auth.header(role="policy_admin", tenant=TENANT)

    response = client.post(
        "/api/v1/policies/absent/activate", json={"version": "1"}, headers=headers
    )

    assert response.status_code == 404
    assert response.json()["code"] == "POLICY_SET_UNKNOWN"


def test_activating_one_version_deactivates_the_previous_one(auth: AuthHarness) -> None:
    headers = auth.header(role="policy_admin", tenant=TENANT)
    for version in ("1", "2"):
        client.post(
            "/api/v1/policies",
            json={"id": "p-2", "version": version, "document": SERVER_POLICY},
            headers=headers,
        )
    client.post("/api/v1/policies/p-2/activate", json={"version": "1"}, headers=headers)

    client.post("/api/v1/policies/p-2/activate", json={"version": "2"}, headers=headers)

    listed = client.get("/api/v1/policies", headers=headers).json()["items"]
    states = {item["version"]: item["active"] for item in listed if item["id"] == "p-2"}
    assert states == {"1": False, "2": True}


def test_an_unusable_policy_document_is_refused(auth: AuthHarness) -> None:
    headers = auth.header(role="policy_admin", tenant=TENANT)

    response = client.post(
        "/api/v1/policies",
        json={"id": "p-3", "version": "1", "document": {"allowed_tools": "document_search"}},
        headers=headers,
    )

    assert response.status_code == 422
    assert response.json()["code"] == "POLICY_DOCUMENT_INVALID"


def test_a_policy_document_over_the_size_bound_is_refused(auth: AuthHarness) -> None:
    headers = auth.header(role="policy_admin", tenant=TENANT)
    oversized = {
        "allowed_tools": ["document_search"],
        "notes": "x" * 300_000,
    }

    response = client.post(
        "/api/v1/policies",
        json={"id": "p-4", "version": "1", "document": oversized},
        headers=headers,
    )

    assert response.status_code == 413
    assert response.json()["code"] == "POLICY_DOCUMENT_TOO_LARGE"


def test_policies_are_tenant_scoped(auth: AuthHarness) -> None:
    mine = auth.header(role="policy_admin", tenant=TENANT)
    theirs = auth.header(role="policy_admin", tenant=OTHER_TENANT)
    client.post(
        "/api/v1/policies",
        json={"id": "private", "version": "1", "document": SERVER_POLICY},
        headers=mine,
    )

    listed = client.get("/api/v1/policies", headers=theirs)

    assert listed.status_code == 200
    assert listed.json()["items"] == []
    assert client.get("/api/v1/audit-events", headers=theirs).json()["items"] == []


def test_publishing_with_the_activate_flag_activates_in_one_call(auth: AuthHarness) -> None:
    headers = auth.header(role="policy_admin", tenant=TENANT)

    response = client.post(
        "/api/v1/policies",
        json={"id": "p-5", "version": "1", "document": SERVER_POLICY, "activate": True},
        headers=headers,
    )

    assert response.status_code == 201
    assert response.json()["active"] is True


def test_unknown_fields_are_refused_on_the_administration_surfaces(auth: AuthHarness) -> None:
    headers = auth.header(role="policy_admin", tenant=TENANT)

    response = client.post(
        "/api/v1/policies",
        json={"id": "p-6", "version": "1", "document": SERVER_POLICY, "owner": "someone"},
        headers=headers,
    )

    assert response.status_code == 422


def test_the_development_mode_keeps_the_frozen_trusted_caller_behaviour(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The labelled development mode is the trusted-caller model, refused in production."""

    monkeypatch.setenv("AEGISGRAPH_AUTH_MODE", "none")
    monkeypatch.delenv("AEGISGRAPH_ENV", raising=False)

    response = client.post(
        "/api/v1/decisions",
        json=decision_payload(allowed_tools=("document_search",), trust_level="system_policy"),
    )

    assert response.status_code == 200
    assert response.json()["decision"] in {"allow", "escalate"}


def test_the_two_extra_scopes_are_separately_grantable(auth: AuthHarness) -> None:
    """Neither role implies the confirmation or the policy-override authority."""

    assert SCOPE_CONFIRMATION_GRANT not in DECISION_CLIENT_SCOPES
    assert SCOPE_CONFIRMATION_GRANT not in POLICY_ADMIN_SCOPES
    assert SCOPE_POLICY_CONTEXT_OVERRIDE not in DECISION_CLIENT_SCOPES
    headers = auth.header(scopes=(SCOPE_CONFIRMATION_GRANT,), tenant=TENANT)

    issued = client.post(
        "/api/v1/confirmations",
        json={"run_id": "r", "step_id": 1, "execution_digest": "0" * 24},
        headers=headers,
    )

    assert issued.status_code == 201
    assert issued.json()["grant"].startswith(f"r:1:{'0' * 24}:")
    assert client.get("/api/v1/receipts", headers=headers).status_code == 403


def test_the_audit_trail_accepts_either_read_scope_and_names_the_missing_ones(
    auth: AuthHarness,
) -> None:
    decision_only = auth.header(role="decision_client", tenant=TENANT)

    denied = client.get("/api/v1/audit-events", headers=decision_only)

    assert denied.status_code == 403
    assert denied.json()["code"] == "INSUFFICIENT_SCOPE"
    assert "any of the required scope(s)" in denied.json()["detail"]
    for role in ("auditor", "policy_admin"):
        trail = client.get(
            "/api/v1/audit-events", headers=auth.header(role=role, tenant=TENANT)
        )
        assert trail.status_code == 200


def test_the_receipt_identity_is_server_resolved_and_cannot_be_forged(
    auth: AuthHarness,
) -> None:
    """H2-02 regression: the caller cannot make a receipt claim another policy version."""

    seed_policy_set(TENANT, policy_id="stored-policy", version="1", document=SERVER_POLICY)
    # Even a caller holding the override scope cannot invent an identity.
    forger = auth.header(
        role="decision_client", tenant=TENANT, scopes=(SCOPE_POLICY_CONTEXT_OVERRIDE,)
    )
    forged = client.post(
        "/api/v1/decisions",
        json=decision_payload(
            request_id="forged-policy", policy_set={"id": "stored-policy", "version": "2"}
        ),
        headers=forger,
    )

    assert forged.status_code == 422
    assert forged.json()["code"] == "POLICY_SET_UNKNOWN"

    unknown = client.post(
        "/api/v1/decisions",
        json=decision_payload(
            request_id="forged-policy", policy_set={"id": "ghost", "version": "9"}
        ),
        headers=forger,
    )
    assert unknown.status_code == 422

    accepted = client.post(
        "/api/v1/decisions",
        json=decision_payload(
            request_id="named-policy", policy_set={"id": "stored-policy", "version": "1"}
        ),
        headers=forger,
    )
    assert accepted.status_code == 200
    assert accepted.json()["policy_set"] == {"id": "stored-policy", "version": "1"}

    # No refused request may leave a receipt behind, so no receipt can claim a
    # policy version that did not decide.
    auditor = auth.header(role="auditor", tenant=TENANT)
    items = client.get("/api/v1/receipts?limit=100", headers=auditor).json()["items"]
    assert [item["request_id"] for item in items] == ["named-policy"]
    assert items[0]["policy_set"] == {"id": "stored-policy", "version": "1"}


def test_the_version_endpoint_reports_the_servers_identity_regardless_of_caller_input(
    auth: AuthHarness,
) -> None:
    """H2-02: ``/api/v1/version`` has no caller-controlled identity channel."""

    headers = auth.header(role="decision_client", tenant=TENANT)

    plain = client.get("/api/v1/version", headers=headers)
    influenced = client.get(
        "/api/v1/version?policy_set=ghost&version=9",
        headers={**headers, "x-aegisgraph-policy-set": "ghost/9"},
    )

    assert plain.status_code == 200
    assert plain.json()["policy_set"] == {"id": "aegisgraph-default", "version": "1"}
    assert influenced.json()["policy_set"] == plain.json()["policy_set"]
