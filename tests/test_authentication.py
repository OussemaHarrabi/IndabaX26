"""Authentication, scope enforcement and credential hygiene (finding F1, decisions D1, D7).

Every test drives the real HTTP boundary through ``TestClient`` with
``AEGISGRAPH_AUTH_MODE=required`` against a locally generated keypair, so the
verification path exercised here is the one a deployment uses. No network, no
database and no committed key material is involved.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest
from aegisgraph.app import app
from aegisgraph.auth import (
    ALL_SCOPES,
    SCOPE_CONFIRMATION_GRANT,
    SCOPE_DECISION_SUBMIT,
    SCOPE_POLICY_CONTEXT_OVERRIDE,
    SCOPE_RECEIPT_READ,
    Principal,
    resolve_principal,
)
from aegisgraph.settings import AuthMode, load_settings
from fastapi.testclient import TestClient
from m2_support import (
    DECISION_CLIENT_SCOPES,
    ISSUER,
    AuthHarness,
    decision_payload,
    seed_policy_set,
    service_token_env,
    token_digest,
)

client = TestClient(app)

TENANT = "tenant-a"


def _submit(headers: dict[str, str], **overrides: Any) -> Any:
    return client.post(
        "/api/v1/decisions", json=decision_payload(**overrides), headers=headers
    )


def mint_for(private_pem: str, *, kid: str = "test-key-1") -> str:
    """Mint a decision-client token with an arbitrary signing key."""

    from m2_support import mint

    return mint(private_pem, role="decision_client", tenant=TENANT, kid=kid)


def _seeded_client(auth: AuthHarness) -> tuple[TestClient, dict[str, str]]:
    seed_policy_set(TENANT)
    return client, auth.header(role="decision_client", tenant=TENANT)


def test_anonymous_request_is_rejected_and_produces_no_decision(
    auth: AuthHarness, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="aegisgraph.decision"):
        response = client.post("/api/v1/decisions", json=decision_payload())

    assert response.status_code == 401
    assert response.json()["code"] == "AUTHENTICATION_REQUIRED"
    assert response.headers["www-authenticate"] == "Bearer"
    assert [record for record in caplog.records if record.name == "aegisgraph.decision"] == []


def test_a_valid_token_is_accepted_and_the_decision_is_persisted(auth: AuthHarness) -> None:
    _, headers = _seeded_client(auth)

    response = _submit(headers, request_id="auth-ok")

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "allow"
    receipts = client.get("/api/v1/receipts", headers=auth.header(role="auditor", tenant=TENANT))
    assert receipts.status_code == 200
    stored = [item for item in receipts.json()["items"] if item["request_id"] == "auth-ok"]
    assert len(stored) == 1
    assert stored[0]["receipt_id"] == body["receipt_id"]
    assert stored[0]["verdict"] == "allow"
    assert stored[0]["principal_id"] == "client-a"


@pytest.mark.parametrize(
    "overrides",
    [
        {"audience": "another-service"},
        {"issuer": "https://not-our-issuer.example"},
        {"ttl_seconds": -60},
        {"not_before_offset": 600},
        {"kid": "unknown-key"},
    ],
    ids=["wrong-audience", "wrong-issuer", "expired", "not-yet-valid", "unknown-key"],
)
def test_an_invalid_token_is_rejected(auth: AuthHarness, overrides: dict[str, Any]) -> None:
    seed_policy_set(TENANT)
    token = auth.token(role="decision_client", tenant=TENANT, **overrides)

    response = client.post(
        "/api/v1/decisions",
        json=decision_payload(),
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401
    assert response.json()["code"] in {"INVALID_TOKEN", "TOKEN_EXPIRED"}


def test_a_symmetric_algorithm_is_rejected(auth: AuthHarness) -> None:
    """An HS256 token signed with the public key material must never verify."""

    import jwt

    seed_policy_set(TENANT)
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": "aegisgraph",
            "sub": "client-a",
            "tenant_id": TENANT,
            "scope": SCOPE_DECISION_SUBMIT,
            "iat": 1_700_000_000,
            "nbf": 1_700_000_000,
            "exp": 4_100_000_000,
        },
        "a-symmetric-secret-of-at-least-32-bytes",
        algorithm="HS256",
        headers={"kid": "test-key-1"},
    )

    response = client.post(
        "/api/v1/decisions",
        json=decision_payload(),
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401
    assert response.json()["code"] == "INVALID_TOKEN"


def test_a_token_without_a_tenant_claim_is_rejected(auth: AuthHarness) -> None:
    import jwt

    seed_policy_set(TENANT)
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": "aegisgraph",
            "sub": "client-a",
            "scope": SCOPE_DECISION_SUBMIT,
            "iat": 1_700_000_000,
            "nbf": 1_700_000_000,
            "exp": 4_100_000_000,
        },
        auth.private_pem,
        algorithm="RS256",
        headers={"kid": "test-key-1"},
    )

    response = client.post(
        "/api/v1/decisions",
        json=decision_payload(),
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401
    assert response.json()["code"] == "INVALID_TOKEN"


def test_a_missing_scope_is_refused_with_403(auth: AuthHarness) -> None:
    seed_policy_set(TENANT)
    headers = auth.header(scopes=(SCOPE_RECEIPT_READ,), tenant=TENANT)

    response = _submit(headers)

    assert response.status_code == 403
    assert response.json()["code"] == "INSUFFICIENT_SCOPE"
    assert SCOPE_DECISION_SUBMIT in response.json()["detail"]


def test_a_read_only_token_cannot_submit_but_can_read_its_tenants_receipts(
    auth: AuthHarness,
) -> None:
    _, submitter = _seeded_client(auth)
    assert _submit(submitter, request_id="reader-scope").status_code == 200
    auditor = auth.header(role="auditor", tenant=TENANT)

    assert _submit(auditor).status_code == 403
    listed = client.get("/api/v1/receipts", headers=auditor)
    assert listed.status_code == 200
    assert any(item["request_id"] == "reader-scope" for item in listed.json()["items"])


def test_an_opaque_service_token_is_accepted_and_only_its_digest_is_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "opaque-service-token-value-1"
    service_token_env(
        monkeypatch,
        token=token,
        tenant=TENANT,
        scopes=(SCOPE_DECISION_SUBMIT,),
    )
    seed_policy_set(TENANT)

    response = _submit({"Authorization": f"Bearer {token}"}, request_id="service-token")

    assert response.status_code == 200
    settings = load_settings()
    assert settings.auth_mode is AuthMode.REQUIRED
    assert token not in json.dumps([record.sha256 for record in settings.service_tokens])
    assert settings.service_tokens[0].sha256 == token_digest(token)


def test_revoking_a_service_token_takes_effect_without_a_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "opaque-service-token-value-2"
    service_token_env(monkeypatch, token=token, tenant=TENANT, scopes=(SCOPE_DECISION_SUBMIT,))
    seed_policy_set(TENANT)
    headers = {"Authorization": f"Bearer {token}"}
    assert _submit(headers).status_code == 200

    monkeypatch.setenv("AEGISGRAPH_SERVICE_TOKENS", "[]")

    assert _submit(headers).status_code == 401


def test_rotating_a_service_token_invalidates_the_previous_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_token = "opaque-service-token-old"
    new_token = "opaque-service-token-new"
    service_token_env(monkeypatch, token=old_token, tenant=TENANT, scopes=(SCOPE_DECISION_SUBMIT,))
    seed_policy_set(TENANT)
    assert _submit({"Authorization": f"Bearer {old_token}"}).status_code == 200

    service_token_env(
        monkeypatch,
        token=new_token,
        tenant=TENANT,
        scopes=(SCOPE_DECISION_SUBMIT,),
        token_id="svc-b",
    )

    assert _submit({"Authorization": f"Bearer {old_token}"}).status_code == 401
    assert _submit({"Authorization": f"Bearer {new_token}"}).status_code == 200


def test_a_rotated_verification_key_is_picked_up_without_a_restart(
    auth: AuthHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rotation is honoured as soon as the mounted file changes and the TTL lapses."""

    from m2_support import generate_keypair, write_jwks

    seed_policy_set(TENANT)
    headers = auth.header(role="decision_client", tenant=TENANT)
    assert _submit(headers).status_code == 200

    replacement_pem, replacement_jwks = generate_keypair()
    write_jwks(auth.jwks_path.parent, replacement_jwks, name=auth.jwks_path.name)
    monkeypatch.setenv("AEGISGRAPH_JWKS_TTL_SECONDS", "0")

    assert _submit(headers).status_code == 401
    rotated = mint_for(replacement_pem)
    assert client.post(
        "/api/v1/decisions",
        json=decision_payload(),
        headers={"Authorization": f"Bearer {rotated}"},
    ).status_code == 200


def test_a_new_signing_key_is_found_when_the_cache_is_configured_to_re_read(
    auth: AuthHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unknown ``kid`` forces a refresh; ``JWKS_TTL_SECONDS=0`` re-reads always.

    The forced re-read is rate-bounded (H3-07), so a rollover that must be visible
    immediately is configured with a zero TTL; with the default TTL the next
    verification after the interval picks it up.
    """

    from m2_support import generate_keypair, write_jwks

    monkeypatch.setenv("AEGISGRAPH_JWKS_TTL_SECONDS", "0")
    seed_policy_set(TENANT)
    assert _submit(auth.header(role="decision_client", tenant=TENANT)).status_code == 200

    replacement_pem, replacement_jwks = generate_keypair()
    replacement_jwks["keys"][0]["kid"] = "rotated-key-2"
    write_jwks(auth.jwks_path.parent, replacement_jwks, name=auth.jwks_path.name)
    rotated = mint_for(replacement_pem, kid="rotated-key-2")

    response = client.post(
        "/api/v1/decisions",
        json=decision_payload(),
        headers={"Authorization": f"Bearer {rotated}"},
    )

    assert response.status_code == 200


def test_liveness_and_readiness_stay_unauthenticated(auth: AuthHarness) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}
    ready = client.get("/readyz")

    assert ready.status_code == 200
    body = ready.json()
    assert body["ready"] is True
    assert body["dependencies"]["authentication"]["mode"] == "required"
    assert body["dependencies"]["receipt_store"]["durable"] is False


def test_no_credential_or_request_content_reaches_the_logs(
    auth: AuthHarness, caplog: pytest.LogCaptureFixture
) -> None:
    canary = "canary-content-must-not-be-logged"
    seed_policy_set(TENANT)
    token = auth.token(role="decision_client", tenant=TENANT)
    digest = token_digest(token)

    with caplog.at_level(logging.DEBUG):
        response = client.post(
            "/api/v1/decisions",
            json=decision_payload(request_id="log-leak"),
            headers={"Authorization": f"Bearer {token}"},
        )
        payload = decision_payload(request_id="log-leak")
        payload["user_goal"] = canary
        client.post(
            "/api/v1/decisions",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )

    emitted = "\n".join(record.getMessage() for record in caplog.records)
    assert token not in emitted
    assert digest not in emitted
    assert canary not in emitted
    assert token not in response.text
    assert canary not in response.text


def test_roles_expand_to_scopes_and_explicit_scopes_are_additive(auth: AuthHarness) -> None:
    settings = load_settings()
    by_role = resolve_principal(
        f"Bearer {auth.token(role='policy_admin', tenant=TENANT)}", settings
    )
    by_scope = resolve_principal(
        f"Bearer {auth.token(role='auditor', scopes=(SCOPE_CONFIRMATION_GRANT,), tenant=TENANT)}",
        settings,
    )

    assert by_role.scopes == {"policy:read", "policy:write"}
    assert by_scope.scopes == {SCOPE_RECEIPT_READ, SCOPE_CONFIRMATION_GRANT}
    assert by_role.tenant_id == TENANT


def test_a_scope_list_claim_and_a_trust_ceiling_claim_are_honoured(auth: AuthHarness) -> None:
    import jwt

    settings = load_settings()
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": "aegisgraph",
            "sub": "list-client",
            "tenant_id": TENANT,
            "scp": [SCOPE_DECISION_SUBMIT, SCOPE_POLICY_CONTEXT_OVERRIDE],
            "trust_ceiling": "untrusted_external",
            "iat": 1_700_000_000,
            "nbf": 1_700_000_000,
            "exp": 4_100_000_000,
        },
        auth.private_pem,
        algorithm="RS256",
        headers={"kid": "test-key-1"},
    )

    principal = resolve_principal(f"Bearer {token}", settings)

    assert principal.scopes == {SCOPE_DECISION_SUBMIT, SCOPE_POLICY_CONTEXT_OVERRIDE}
    assert principal.trust_ceiling.value == "untrusted_external"


def test_the_development_principal_holds_every_scope_and_is_labelled() -> None:
    settings = load_settings({"AEGISGRAPH_AUTH_MODE": "none"})

    principal = resolve_principal(None, settings)

    assert principal.auth_method == "development"
    assert principal.scopes == ALL_SCOPES
    assert isinstance(principal, Principal)


def test_a_non_bearer_authorization_header_is_rejected(auth: AuthHarness) -> None:
    seed_policy_set(TENANT)

    response = client.post(
        "/api/v1/decisions",
        json=decision_payload(),
        headers={"Authorization": "Basic dXNlcjpwYXNz"},
    )

    assert response.status_code == 401
    assert response.json()["code"] == "INVALID_TOKEN"


def test_a_token_for_another_tenant_cannot_read_this_tenants_receipt(auth: AuthHarness) -> None:
    _, submitter = _seeded_client(auth)
    created = _submit(submitter, request_id="tenant-isolation")
    receipt_id = created.json()["receipt_id"]
    other_tenant = auth.header(role="auditor", tenant="tenant-b")

    response = client.get(f"/api/v1/receipts/{receipt_id}", headers=other_tenant)

    assert response.status_code == 404
    assert response.json()["code"] == "RECEIPT_NOT_FOUND"


def test_decision_client_scopes_are_exactly_the_documented_role() -> None:
    assert {SCOPE_DECISION_SUBMIT} == DECISION_CLIENT_SCOPES


def test_the_legacy_surface_is_refused_when_the_flag_is_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """D5: the frozen legacy wire exists only while it is explicitly enabled."""

    monkeypatch.setenv("AEGISGRAPH_LEGACY_UNAUTHENTICATED", "false")
    payload = {
        "run_id": "legacy-off",
        "step_id": 1,
        "user_goal": "Read the queue",
        "conversation": [],
        "candidate_action": {"type": "respond", "content": "Ok"},
        "policy_context": {"allowed_tools": ["document_search"]},
    }

    response = client.post("/v1/decision", json=payload)

    assert response.status_code == 404


def test_authentication_without_a_configured_verifier_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGISGRAPH_AUTH_MODE", "required")
    for name in ("AEGISGRAPH_JWKS", "AEGISGRAPH_JWT_ISSUER", "AEGISGRAPH_JWT_AUDIENCE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("AEGISGRAPH_SERVICE_TOKENS", raising=False)

    response = client.post(
        "/api/v1/decisions",
        json=decision_payload(),
        headers={"Authorization": "Bearer a.b.c"},
    )

    assert response.status_code == 503
    assert response.json()["code"] == "AUTHENTICATION_UNAVAILABLE"


def test_an_unreadable_jwks_document_fails_closed(auth: AuthHarness) -> None:
    auth.jwks_path.write_text("{not json", encoding="utf-8")
    token = auth.token(role="decision_client", tenant=TENANT)

    response = client.post(
        "/api/v1/decisions",
        json=decision_payload(),
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 503
    assert response.json()["code"] == "AUTHENTICATION_UNAVAILABLE"


def test_a_missing_jwks_document_fails_closed(auth: AuthHarness) -> None:
    token = auth.token(role="decision_client", tenant=TENANT)
    auth.jwks_path.unlink()

    response = client.post(
        "/api/v1/decisions",
        json=decision_payload(),
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 503
    assert response.json()["code"] == "AUTHENTICATION_UNAVAILABLE"


def test_a_token_without_a_key_id_is_refused_when_several_keys_are_published(
    auth: AuthHarness,
) -> None:
    import jwt
    from m2_support import generate_keypair, write_jwks

    _, second = generate_keypair()
    second["keys"][0]["kid"] = "second-key"
    _, extra = generate_keypair()
    extra["keys"][0]["kid"] = "third-key"
    write_jwks(
        auth.jwks_path.parent,
        {"keys": second["keys"] + extra["keys"]},
        name=auth.jwks_path.name,
    )
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": "aegisgraph",
            "sub": "client-a",
            "tenant_id": TENANT,
            "scope": SCOPE_DECISION_SUBMIT,
            "iat": 1_700_000_000,
            "nbf": 1_700_000_000,
            "exp": 4_100_000_000,
        },
        auth.private_pem,
        algorithm="RS256",
    )

    response = client.post(
        "/api/v1/decisions",
        json=decision_payload(),
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_a_token_without_a_subject_is_refused(auth: AuthHarness) -> None:
    import jwt

    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": "aegisgraph",
            "tenant_id": TENANT,
            "scope": SCOPE_DECISION_SUBMIT,
            "iat": 1_700_000_000,
            "nbf": 1_700_000_000,
            "exp": 4_100_000_000,
        },
        auth.private_pem,
        algorithm="RS256",
        headers={"kid": "test-key-1"},
    )

    response = client.post(
        "/api/v1/decisions",
        json=decision_payload(),
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401
    assert response.json()["code"] == "INVALID_TOKEN"


def test_an_unknown_trust_ceiling_claim_is_refused(auth: AuthHarness) -> None:
    token = auth.token(role="decision_client", tenant=TENANT, trust_ceiling="superuser")

    response = client.post(
        "/api/v1/decisions",
        json=decision_payload(),
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401
    assert response.json()["code"] == "INVALID_TOKEN"


def test_a_jwks_document_that_is_not_a_key_set_fails_closed(auth: AuthHarness) -> None:
    auth.jwks_path.write_text('{"keys": [{"kty": "RSA"}]}', encoding="utf-8")
    token = auth.token(role="decision_client", tenant=TENANT)

    response = client.post(
        "/api/v1/decisions",
        json=decision_payload(),
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code in {401, 503}
    assert response.json()["code"] in {"INVALID_TOKEN", "AUTHENTICATION_UNAVAILABLE"}


def test_a_token_without_a_key_id_verifies_against_a_single_key_document(
    auth: AuthHarness,
) -> None:
    """A single published key needs no ``kid``: the only candidate is the key."""

    seed_policy_set(TENANT, document={"allowed_tools": ["document_search"]})
    import jwt

    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": "aegisgraph",
            "sub": "client-a",
            "tenant_id": TENANT,
            "scope": SCOPE_DECISION_SUBMIT,
            "iat": 1_700_000_000,
            "nbf": 1_700_000_000,
            "exp": 4_100_000_000,
        },
        auth.private_pem,
        algorithm="RS256",
    )

    response = client.post(
        "/api/v1/decisions",
        json=decision_payload(),
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200


def test_readiness_is_honest_about_an_insecure_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H3-05: readiness reports whether the process is serving *safely*."""

    monkeypatch.setenv("AEGISGRAPH_AUTH_MODE", "none")
    monkeypatch.delenv("AEGISGRAPH_ENV", raising=False)

    body = client.get("/readyz").json()

    assert body["ready"] is True
    assert body["insecure"] is True
    assert "AUTH_MODE_NONE" in body["warnings"]
    assert body["dependencies"]["authentication"]["mode"] == "none"


def test_readiness_reports_a_secure_process_without_the_insecurity_warnings(
    auth: AuthHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AEGISGRAPH_ENV", "production")
    monkeypatch.setenv("AEGISGRAPH_LEGACY_UNAUTHENTICATED", "false")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://nobody:nothing@127.0.0.1:1/absent")

    body = client.get("/readyz").json()

    assert "AUTH_MODE_NONE" not in body["warnings"]
    assert "LEGACY_UNAUTHENTICATED" not in body["warnings"]
    assert "NOT_PRODUCTION" not in body["warnings"]


def test_an_unknown_key_id_cannot_force_a_file_read_per_request(auth: AuthHarness) -> None:
    """H3-07: a forced JWKS re-read is rate-bounded."""

    from aegisgraph.auth import _CACHES

    seed_policy_set(TENANT)
    assert _submit(auth.header(role="decision_client", tenant=TENANT)).status_code == 200
    cache = next(iter(_CACHES.values()))
    before = cache.reads
    bogus = auth.token(role="decision_client", tenant=TENANT, kid="not-a-published-key")

    for _ in range(5):
        response = client.post(
            "/api/v1/decisions",
            json=decision_payload(),
            headers={"Authorization": f"Bearer {bogus}"},
        )
        assert response.status_code == 401

    assert cache.reads - before <= 1
