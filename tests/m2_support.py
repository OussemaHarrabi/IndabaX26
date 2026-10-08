"""Shared fixtures and helpers for the M2 identity, authorization and audit tests.

Nothing here touches the network or the repository: keypairs are generated in a
temporary directory, service tokens are digests of random strings, and the
PostgreSQL-backed tests skip cleanly unless ``AEGISGRAPH_TEST_DATABASE_URL`` is
exported.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from aegisgraph.auth import ROLE_SCOPES

ISSUER = "https://dev-issuer.aegisgraph.local"
AUDIENCE = "aegisgraph"
KID = "test-key-1"
TEST_DATABASE_URL_ENV = "AEGISGRAPH_TEST_DATABASE_URL"

DECISION_CLIENT_SCOPES = ROLE_SCOPES["decision_client"]
AUDITOR_SCOPES = ROLE_SCOPES["auditor"]
POLICY_ADMIN_SCOPES = ROLE_SCOPES["policy_admin"]


def generate_keypair() -> tuple[str, dict[str, Any]]:
    """Return a PEM private key and the matching single-key JWKS document."""

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    numbers = key.public_key().public_numbers()

    def b64(value: int) -> str:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": KID,
                "n": b64(numbers.n),
                "e": b64(numbers.e),
            }
        ]
    }
    return private_pem, jwks


def write_jwks(directory: Path, jwks: dict[str, Any], *, name: str = "jwks.json") -> Path:
    path = directory / name
    path.write_text(json.dumps(jwks), encoding="utf-8")
    return path


def mint(
    private_pem: str,
    *,
    scopes: tuple[str, ...] = (),
    role: str | None = None,
    tenant: str = "tenant-a",
    subject: str = "client-a",
    audience: str = AUDIENCE,
    issuer: str = ISSUER,
    kid: str = KID,
    trust_ceiling: str | None = None,
    ttl_seconds: int = 3600,
    not_before_offset: int = -1,
    algorithm: str = "RS256",
) -> str:
    """Mint a signed token for the local test issuer."""

    import jwt

    resolved = list(scopes)
    if role is not None:
        resolved.extend(ROLE_SCOPES[role])
    now = int(__import__("time").time())
    claims: dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "tenant_id": tenant,
        "scope": " ".join(dict.fromkeys(resolved)),
        "iat": now,
        "nbf": now + not_before_offset,
        "exp": now + ttl_seconds,
        "jti": secrets.token_hex(8),
    }
    if trust_ceiling is not None:
        claims["trust_ceiling"] = trust_ceiling
    return jwt.encode(claims, private_pem, algorithm=algorithm, headers={"kid": kid})


class AuthHarness:
    """A JWT-verifying configuration plus a token minter for the local test issuer."""

    def __init__(self, private_pem: str, jwks_path: Path) -> None:
        self.private_pem = private_pem
        self.jwks_path = jwks_path

    def token(self, **kwargs: Any) -> str:
        return mint(self.private_pem, **kwargs)

    def header(self, **kwargs: Any) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token(**kwargs)}"}


def service_token_env(
    monkeypatch: pytest.MonkeyPatch,
    *,
    token: str,
    tenant: str = "tenant-a",
    scopes: tuple[str, ...] = ("decision:submit",),
    token_id: str = "svc-a",
    trust_ceiling: str | None = None,
) -> None:
    """Configure one opaque service token by its digest, never by its value."""

    record: dict[str, Any] = {
        "id": token_id,
        "tenant_id": tenant,
        "sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
        "scopes": list(scopes),
    }
    if trust_ceiling is not None:
        record["trust_ceiling"] = trust_ceiling
    monkeypatch.setenv("AEGISGRAPH_AUTH_MODE", "required")
    monkeypatch.setenv("AEGISGRAPH_SERVICE_TOKENS", json.dumps([record]))


def decision_payload(
    *,
    request_id: str | None = None,
    run_id: str = "m2-run",
    step_id: int = 1,
    tool: str = "document_search",
    allowed_tools: tuple[str, ...] = ("document_search",),
    policy_context_extra: dict[str, Any] | None = None,
    policy_set: dict[str, str] | None = None,
    trust_level: str | None = None,
    confirmations: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Build one generic decision request with bounded, explicit facts."""

    policy_context: dict[str, Any] = {
        "allowed_tools": list(allowed_tools),
        "confirmation_required_tools": [],
        "consequential_tools": [],
    }
    policy_context.update(policy_context_extra or {})
    payload: dict[str, Any] = {
        "api_version": "aegisgraph/v1",
        "run_id": run_id,
        "step_id": step_id,
        "user_goal": "Perform the requested safe task",
        "conversation": [],
        "candidate_action": {"type": "tool_call", "tool": tool, "arguments": {"query": "status"}},
        "policy_context": policy_context,
        "history_digest": {"confirmations_granted": list(confirmations)},
    }
    if request_id is not None:
        payload["request_id"] = request_id
    if policy_set is not None:
        payload["policy_set"] = policy_set
    if trust_level is not None:
        payload["provenance"] = [
            {
                "id": "source-1",
                "provenance": {
                    "source_type": "email",
                    "source_id": "mailbox-1",
                    "trust_level": trust_level,
                    "origin_actor": "vendor",
                    "retrieved_via": "email_read",
                    "sensitivity": "internal",
                    "timestamp": "2026-10-08T00:00:00Z",
                },
            }
        ]
    return payload


def seed_policy_set(
    tenant_id: str,
    *,
    policy_id: str = "aegisgraph-default",
    version: str = "1",
    document: dict[str, Any] | None = None,
    active: bool = True,
) -> dict[str, Any]:
    """Store one server-side policy set in the process store (D3).

    The decision path then takes its policy facts from this document rather than
    from the caller, which is exactly what a production deployment looks like.
    """

    from datetime import UTC, datetime

    from aegisgraph.settings import load_settings
    from aegisgraph.store import PolicyRecord, digest_of, open_store

    resolved = document or {
        "allowed_tools": ["document_search", "payment_execute"],
        "confirmation_required_tools": [],
        "consequential_tools": [],
        "internal_email_domains": ["example.com"],
    }
    store = open_store(load_settings())
    store.create_policy_set(
        PolicyRecord(
            tenant_id=tenant_id,
            id=policy_id,
            version=version,
            document=resolved,
            checksum=digest_of(resolved),
            active=active,
            created_by="test-harness",
            created_at=datetime.now(UTC),
        )
    )
    return resolved


def test_database_url() -> str | None:
    """Return the PostgreSQL URL for the ``db`` tests, if one is exported."""

    value = os.environ.get(TEST_DATABASE_URL_ENV, "").strip()
    return value or None


def require_database() -> str:
    """Skip the calling test unless a PostgreSQL test database is configured."""

    url = test_database_url()
    if url is None:
        pytest.skip(f"{TEST_DATABASE_URL_ENV} is not set")
    return url


def alembic(*args: str, database_url: str) -> subprocess.CompletedProcess[str]:
    """Run one Alembic command against the test database."""

    environment = dict(os.environ)
    environment["DATABASE_URL"] = database_url
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=str(Path(__file__).resolve().parents[1]),
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


__all__ = [
    "AUDIENCE",
    "AUDITOR_SCOPES",
    "DECISION_CLIENT_SCOPES",
    "ISSUER",
    "KID",
    "POLICY_ADMIN_SCOPES",
    "TEST_DATABASE_URL_ENV",
    "AuthHarness",
    "alembic",
    "decision_payload",
    "generate_keypair",
    "mint",
    "require_database",
    "seed_policy_set",
    "service_token_env",
    "test_database_url",
    "token_digest",
    "write_jwks",
]
