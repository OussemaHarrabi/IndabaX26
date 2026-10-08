"""Shared pytest configuration for the AegisGraph test suite.

Two things live here:

* the ``db`` marker registration for tests that need a PostgreSQL database. They
  skip cleanly unless ``AEGISGRAPH_TEST_DATABASE_URL`` is exported, so the rest of
  the suite runs with no database at all;
* the ``auth`` fixture, which enables ``AEGISGRAPH_AUTH_MODE=required`` against a
  keypair generated into a temporary directory. No key material is committed and
  no network is touched.

The autouse reset fixture keeps the in-process store and JWKS caches empty at the
start of every test, so a test never observes another test's receipts or keys.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from aegisgraph.auth import clear_jwks_cache
from aegisgraph.store import reset_store_cache
from m2_support import ISSUER, AuthHarness, generate_keypair, write_jwks

DB_MARKER = "db"
"""Tests that require ``AEGISGRAPH_TEST_DATABASE_URL`` (a PostgreSQL database)."""


def pytest_configure(config: pytest.Config) -> None:
    """Register the markers this suite uses."""

    config.addinivalue_line(
        "markers",
        f"{DB_MARKER}: requires AEGISGRAPH_TEST_DATABASE_URL (PostgreSQL); skipped when unset",
    )


@pytest.fixture(autouse=True)
def fresh_process_state() -> Iterator[None]:
    """Start every test with an empty store cache and no cached JWKS document."""

    reset_store_cache()
    clear_jwks_cache()
    yield
    reset_store_cache()
    clear_jwks_cache()


@pytest.fixture
def auth(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> AuthHarness:
    """Enable ``AEGISGRAPH_AUTH_MODE=required`` against a local JWKS file."""

    private_pem, jwks = generate_keypair()
    jwks_path = write_jwks(tmp_path, jwks)
    monkeypatch.setenv("AEGISGRAPH_AUTH_MODE", "required")
    monkeypatch.setenv("AEGISGRAPH_JWT_ISSUER", ISSUER)
    monkeypatch.setenv("AEGISGRAPH_JWT_AUDIENCE", "aegisgraph")
    monkeypatch.setenv("AEGISGRAPH_JWKS", str(jwks_path))
    monkeypatch.delenv("AEGISGRAPH_ENV", raising=False)
    monkeypatch.delenv("AEGISGRAPH_LEGACY_UNAUTHENTICATED", raising=False)
    monkeypatch.delenv("AEGISGRAPH_SERVICE_TOKENS", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    return AuthHarness(private_pem, jwks_path)
