"""Configuration safety and the fail-closed startup refusal (finding F1, decision D7).

These tests never touch the network and never need a database: they drive
:func:`aegisgraph.settings.load_settings` with an explicit environment mapping and
run the startup check as a subprocess, which is the same code path a deployment
takes before the server binds.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from aegisgraph.settings import (
    AuthMode,
    ConfigurationError,
    Environment,
    load_settings,
    main,
    safe_summary,
    validate_settings,
)
from m2_support import generate_keypair, token_digest, write_jwks

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BACKEND = REPOSITORY_ROOT / "backend"


def _complete_production(tmp_path: Path, **overrides: str) -> dict[str, str]:
    """Return a production configuration that must be accepted, plus overrides."""

    _, jwks = generate_keypair()
    environment = {
        "AEGISGRAPH_ENV": "production",
        "AEGISGRAPH_AUTH_MODE": "required",
        "AEGISGRAPH_JWT_ISSUER": "https://issuer.example",
        "AEGISGRAPH_JWT_AUDIENCE": "aegisgraph",
        "AEGISGRAPH_JWKS": str(write_jwks(tmp_path, jwks)),
        "DATABASE_URL": "postgresql+psycopg://user:secret@db:5432/aegisgraph",
        "AEGISGRAPH_LEGACY_UNAUTHENTICATED": "false",
    }
    environment.update(overrides)
    return environment


def test_defaults_are_the_labelled_development_mode() -> None:
    settings = load_settings({})

    assert settings.environment is Environment.DEVELOPMENT
    assert settings.auth_mode is AuthMode.NONE
    assert settings.legacy_unauthenticated is True
    assert settings.durable is False
    assert settings.retention_days == 90
    assert settings.trust_ceiling_default.value == "trusted_internal"
    assert settings.bind_address == "127.0.0.1"
    validate_settings(settings)


def test_production_refuses_the_unauthenticated_mode(tmp_path: Path) -> None:
    settings = load_settings(_complete_production(tmp_path, AEGISGRAPH_AUTH_MODE="none"))

    with pytest.raises(ConfigurationError) as error:
        validate_settings(settings)

    message = str(error.value)
    assert "AEGISGRAPH_AUTH_MODE=none is refused" in message
    assert "AEGISGRAPH_AUTH_MODE=required" in message


def test_production_refuses_the_legacy_unauthenticated_surface(tmp_path: Path) -> None:
    settings = load_settings(
        _complete_production(tmp_path, AEGISGRAPH_LEGACY_UNAUTHENTICATED="true")
    )

    with pytest.raises(ConfigurationError) as error:
        validate_settings(settings)

    assert "legacy surface is refused" in str(error.value)


def test_production_refuses_a_process_without_a_durable_receipt_store(tmp_path: Path) -> None:
    environment = _complete_production(tmp_path)
    del environment["DATABASE_URL"]

    with pytest.raises(ConfigurationError) as error:
        validate_settings(load_settings(environment))

    assert "DATABASE_URL is required" in str(error.value)


def test_production_refuses_authentication_without_a_verifier(tmp_path: Path) -> None:
    environment = _complete_production(tmp_path)
    for key in ("AEGISGRAPH_JWKS", "AEGISGRAPH_JWT_ISSUER", "AEGISGRAPH_JWT_AUDIENCE"):
        del environment[key]

    with pytest.raises(ConfigurationError) as error:
        validate_settings(load_settings(environment))

    assert "needs a verifier" in str(error.value)


def test_a_complete_production_configuration_is_accepted(tmp_path: Path) -> None:
    settings = load_settings(_complete_production(tmp_path))

    validate_settings(settings)

    assert settings.production is True
    assert settings.jwt_enabled is True
    assert settings.durable is True


def test_a_missing_jwks_file_is_refused_at_startup(tmp_path: Path) -> None:
    settings = load_settings(
        _complete_production(tmp_path, AEGISGRAPH_JWKS="/run/secrets/absent-jwks.json")
    )

    with pytest.raises(ConfigurationError) as error:
        validate_settings(settings)

    assert "file does not exist" in str(error.value)


def test_a_jwks_url_is_refused_in_the_runtime_and_names_the_refresher(tmp_path: Path) -> None:
    """The decision process holds no network capability, so a URL must be materialised."""

    settings = load_settings(
        _complete_production(tmp_path, AEGISGRAPH_JWKS="https://issuer.example/jwks")
    )

    assert settings.jwks_file is None
    assert settings.jwks_url == "https://issuer.example/jwks"
    with pytest.raises(ConfigurationError) as error:
        validate_settings(settings)
    assert "scripts/jwks_refresh.py" in str(error.value)


def test_a_non_loopback_bind_address_is_refused_while_the_legacy_surface_is_on() -> None:
    environment = {"AEGISGRAPH_BIND_ADDRESS": "0.0.0.0"}

    with pytest.raises(ConfigurationError) as error:
        validate_settings(load_settings(environment))

    assert "requires a loopback" in str(error.value)


@pytest.mark.parametrize(
    "value",
    ["system_policy", "authenticated_user", "trusted_internal", "untrusted_external"],
)
def test_known_trust_ceilings_are_accepted(value: str) -> None:
    settings = load_settings({"AEGISGRAPH_TRUST_CEILING_DEFAULT": value})

    validate_settings(settings)

    assert settings.trust_ceiling_default.value == value


def test_an_unknown_trust_ceiling_is_refused() -> None:
    settings = load_settings({"AEGISGRAPH_TRUST_CEILING_DEFAULT": "trusted"})

    with pytest.raises(ConfigurationError) as error:
        validate_settings(settings)

    assert "AEGISGRAPH_TRUST_CEILING_DEFAULT must be one of" in str(error.value)


def test_a_symmetric_jwt_algorithm_is_refused() -> None:
    settings = load_settings({"AEGISGRAPH_JWT_ALGORITHMS": "HS256"})

    with pytest.raises(ConfigurationError) as error:
        validate_settings(settings)

    assert "asymmetric algorithms" in str(error.value)


def test_service_token_records_are_validated() -> None:
    digest = token_digest("s3cret")
    good = {
        "id": "svc-a",
        "tenant_id": "tenant-a",
        "sha256": digest,
        "scopes": ["decision:submit"],
    }
    bad_digest = {**good, "sha256": "not-a-digest"}
    unknown_field = {**good, "secret": "must-not-be-accepted"}
    missing_tenant = {**good, "tenant_id": ""}
    not_a_list = {"id": "svc-a"}

    accepted = load_settings({"AEGISGRAPH_SERVICE_TOKENS": json.dumps([good])})
    assert accepted.service_tokens[0].sha256 == digest
    assert accepted.service_tokens[0].scopes == ("decision:submit",)

    for record in (bad_digest, unknown_field, missing_tenant, not_a_list):
        settings = load_settings({"AEGISGRAPH_SERVICE_TOKENS": json.dumps([record])})
        with pytest.raises(ConfigurationError):
            validate_settings(settings)


def test_service_tokens_can_arrive_through_a_mounted_file(tmp_path: Path) -> None:
    record = {
        "id": "svc-file",
        "tenant_id": "tenant-a",
        "sha256": token_digest("mounted"),
        "scopes": ["receipt:read"],
        "trust_ceiling": "untrusted_external",
    }
    path = tmp_path / "service-tokens.json"
    path.write_text(json.dumps([record]), encoding="utf-8")

    settings = load_settings({"AEGISGRAPH_SERVICE_TOKEN_FILE": str(path)})

    assert settings.service_tokens[0].id == "svc-file"
    assert settings.service_tokens[0].trust_ceiling.value == "untrusted_external"


def test_a_missing_service_token_file_is_refused() -> None:
    settings = load_settings({"AEGISGRAPH_SERVICE_TOKEN_FILE": "/run/secrets/absent.json"})

    with pytest.raises(ConfigurationError) as error:
        validate_settings(settings)

    assert "could not be read" in str(error.value)


def test_safe_summary_reports_shape_only_and_no_secret_material() -> None:
    secret = "super-secret-service-token-value"
    environment = {
        "AEGISGRAPH_SERVICE_TOKENS": json.dumps(
            [
                {
                    "id": "svc-a",
                    "tenant_id": "tenant-a",
                    "sha256": token_digest(secret),
                    "scopes": ["decision:submit"],
                }
            ]
        )
    }

    summary = json.dumps(safe_summary(load_settings(environment)))

    assert token_digest(secret) not in summary
    assert secret not in summary
    assert '"service_token_count": 1' in summary


def _subprocess_environment(extra: dict[str, str]) -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("AEGISGRAPH_") and key != "DATABASE_URL"
    }
    environment["PYTHONPATH"] = str(BACKEND)
    environment.update(extra)
    return environment


def test_the_startup_check_exits_non_zero_for_an_insecure_production_process() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "aegisgraph.settings"],
        env=_subprocess_environment({"AEGISGRAPH_ENV": "production"}),
        cwd=str(REPOSITORY_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode != 0
    assert "refusing to start" in completed.stderr
    assert "AEGISGRAPH_AUTH_MODE=none is refused" in completed.stderr


def test_the_startup_check_accepts_the_development_default() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "aegisgraph.settings"],
        env=_subprocess_environment({}),
        cwd=str(REPOSITORY_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "configuration accepted" in completed.stdout


def test_main_reports_the_refusal_and_returns_non_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("AEGISGRAPH_ENV", "production")

    assert main([]) == 2
    assert "refusing to start" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ("not json", "is not valid JSON"),
        ('{"id": "svc"}', "must be a JSON list"),
        ('["svc"]', "must be an object"),
        (
            '[{"id":"a","tenant_id":"t","sha256":"' + "0" * 64 + '","scopes":"read"}]',
            "scopes must be a list of strings",
        ),
        (
            '[{"id":"a","tenant_id":"t","sha256":"' + "0" * 64
            + '","scopes":[],"trust_ceiling":"superuser"}]',
            "not a known trust level",
        ),
        (
            '[{"id":"","tenant_id":"t","sha256":"' + "0" * 64 + '","scopes":[]}]',
            "id must be a non-empty string",
        ),
        (
            '[{"id":"a","tenant_id":"","sha256":"' + "0" * 64 + '","scopes":[]}]',
            "tenant_id must be a non-empty string",
        ),
    ],
)
def test_a_malformed_service_token_configuration_is_refused(payload: str, expected: str) -> None:
    settings = load_settings({"AEGISGRAPH_SERVICE_TOKENS": payload})

    assert settings.service_tokens == ()
    with pytest.raises(ConfigurationError) as error:
        validate_settings(settings)
    assert expected in str(error.value)


def test_an_unknown_environment_name_is_refused() -> None:
    settings = load_settings({"AEGISGRAPH_ENV": "staging"})

    assert settings.environment is Environment.DEVELOPMENT
    with pytest.raises(ConfigurationError) as error:
        validate_settings(settings)
    assert "AEGISGRAPH_ENV must be one of development, production" in str(error.value)


def test_an_unknown_auth_mode_is_refused() -> None:
    settings = load_settings({"AEGISGRAPH_AUTH_MODE": "mTLS"})

    assert settings.auth_mode is AuthMode.NONE
    with pytest.raises(ConfigurationError) as error:
        validate_settings(settings)
    assert "AEGISGRAPH_AUTH_MODE must be one of none, required" in str(error.value)


@pytest.mark.parametrize(
    ("environment", "expected"),
    [
        ({"AEGISGRAPH_RECEIPT_TTL_SECONDS": "soon"}, 60),
        ({"AEGISGRAPH_RECEIPT_TTL_SECONDS": "-1"}, 60),
        ({"AEGISGRAPH_RETENTION_DAYS": "forever"}, 90),
        ({"AEGISGRAPH_RETENTION_DAYS": "0"}, 90),
        ({"AEGISGRAPH_JWKS_TTL_SECONDS": "nope"}, 300),
        ({"AEGISGRAPH_JWKS_TTL_SECONDS": "-5"}, 300),
    ],
)
def test_invalid_numeric_configuration_falls_back_to_the_default(
    environment: dict[str, str], expected: int
) -> None:
    settings = load_settings(environment)

    assert expected in (
        settings.receipt_ttl_seconds,
        settings.retention_days,
        settings.jwks_ttl_seconds,
    )
    validate_settings(settings)


def test_a_valid_numeric_configuration_is_honoured() -> None:
    settings = load_settings(
        {
            "AEGISGRAPH_RECEIPT_TTL_SECONDS": "120",
            "AEGISGRAPH_RETENTION_DAYS": "30",
            "AEGISGRAPH_JWKS_TTL_SECONDS": "0",
            "AEGISGRAPH_STORE_PAYLOAD_METADATA": "true",
        }
    )

    assert settings.receipt_ttl_seconds == 120
    assert settings.retention_days == 30
    assert settings.jwks_ttl_seconds == 0
    assert settings.store_payload_metadata is True
