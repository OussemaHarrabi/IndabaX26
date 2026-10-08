"""Fail-closed configuration for the AegisGraph service (finding F1, decision D7).

Configuration arrives through environment variables or through mounted files; no
secret is ever read from, or written to, the repository. :func:`load_settings`
performs no I/O beyond reading the two optional mounted files, and
:func:`validate_settings` refuses a production configuration that would expose an
unauthenticated decision boundary.

The module is also the startup check: ``python -m aegisgraph.settings`` validates
the current environment, prints one actionable line, and exits non-zero when the
configuration is unsafe. ``backend/aegisgraph/app.py`` runs the same check at
import time, so a misconfigured production process dies instead of serving.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from aegisgraph.contracts import TrustLevel

ENVIRONMENT_ENV = "AEGISGRAPH_ENV"
AUTH_MODE_ENV = "AEGISGRAPH_AUTH_MODE"
JWT_ISSUER_ENV = "AEGISGRAPH_JWT_ISSUER"
JWT_AUDIENCE_ENV = "AEGISGRAPH_JWT_AUDIENCE"
JWKS_ENV = "AEGISGRAPH_JWKS"
JWKS_FILE_ENV = "AEGISGRAPH_JWKS_FILE"
JWKS_URL_ENV = "AEGISGRAPH_JWKS_URL"
JWKS_TTL_ENV = "AEGISGRAPH_JWKS_TTL_SECONDS"
JWT_ALGORITHMS_ENV = "AEGISGRAPH_JWT_ALGORITHMS"
SERVICE_TOKENS_ENV = "AEGISGRAPH_SERVICE_TOKENS"
SERVICE_TOKEN_FILE_ENV = "AEGISGRAPH_SERVICE_TOKEN_FILE"
DATABASE_URL_ENV = "DATABASE_URL"
RECEIPT_TTL_ENV = "AEGISGRAPH_RECEIPT_TTL_SECONDS"
RETENTION_DAYS_ENV = "AEGISGRAPH_RETENTION_DAYS"
LEGACY_ENV = "AEGISGRAPH_LEGACY_UNAUTHENTICATED"
TRUST_CEILING_ENV = "AEGISGRAPH_TRUST_CEILING_DEFAULT"
DEFAULT_TENANT_ENV = "AEGISGRAPH_DEFAULT_TENANT"
BIND_ADDRESS_ENV = "AEGISGRAPH_BIND_ADDRESS"
STORE_PAYLOAD_METADATA_ENV = "AEGISGRAPH_STORE_PAYLOAD_METADATA"

DEFAULT_ENVIRONMENT = "development"
DEFAULT_AUTH_MODE = "none"
DEFAULT_RECEIPT_TTL_SECONDS = 60
DEFAULT_RETENTION_DAYS = 90
DEFAULT_TRUST_CEILING = TrustLevel.TRUSTED_INTERNAL
DEFAULT_TENANT = "development"
DEFAULT_BIND_ADDRESS = "127.0.0.1"
DEFAULT_JWT_ALGORITHMS = ("RS256", "ES256")
DEFAULT_JWKS_TTL_SECONDS = 300
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_SERVICE_TOKEN_FIELDS = frozenset({"id", "tenant_id", "sha256", "scopes", "trust_ceiling"})


class Environment(StrEnum):
    """Deployment environment; only ``production`` applies the hard refusals."""

    DEVELOPMENT = "development"
    PRODUCTION = "production"


class AuthMode(StrEnum):
    """How the protected surfaces resolve a caller identity."""

    NONE = "none"
    """Development-only: every request is the implicit trusted caller (D5)."""

    REQUIRED = "required"
    """A verified credential (JWT or opaque service token) is mandatory."""


class ConfigurationError(RuntimeError):
    """Raised when the configuration would start an unsafe service."""


@dataclass(frozen=True)
class ServiceTokenRecord:
    """One scoped opaque service token, stored as a SHA-256 digest only."""

    id: str
    tenant_id: str
    sha256: str
    scopes: tuple[str, ...]
    trust_ceiling: TrustLevel


@dataclass(frozen=True)
class Settings:
    """Validated, immutable view of the process configuration."""

    environment: Environment
    auth_mode: AuthMode
    jwt_issuer: str | None
    jwt_audience: str | None
    jwks_file: str | None
    jwks_url: str | None
    jwks_ttl_seconds: int
    jwt_algorithms: tuple[str, ...]
    service_tokens: tuple[ServiceTokenRecord, ...]
    database_url: str | None
    receipt_ttl_seconds: int
    retention_days: int
    legacy_unauthenticated: bool
    trust_ceiling_default: TrustLevel
    default_tenant: str
    bind_address: str
    store_payload_metadata: bool = False
    problems: tuple[str, ...] = field(default=())

    @property
    def production(self) -> bool:
        return self.environment is Environment.PRODUCTION

    @property
    def jwt_enabled(self) -> bool:
        return bool(self.jwt_issuer and self.jwt_audience and self.jwks_file)

    @property
    def durable(self) -> bool:
        """Whether receipts survive a restart (F7's durable half)."""

        return self.database_url is not None


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    """Read and validate the configuration.

    The function is pure apart from reading the two optional mounted secret files,
    so a test can drive every branch by passing an ``environ`` mapping.
    """

    source = os.environ if environ is None else environ
    problems: list[str] = []

    environment = _environment(source, problems)
    auth_mode = _auth_mode(source, problems)
    legacy = _legacy(source, environment)
    trust_ceiling = _trust_ceiling(source, problems)
    algorithms = _algorithms(source, problems)
    jwks_file, jwks_url = _jwks_sources(source, problems)
    service_tokens = _service_tokens(source, problems)
    database_url = _clean(source.get(DATABASE_URL_ENV))

    settings = Settings(
        environment=environment,
        auth_mode=auth_mode,
        jwt_issuer=_clean(source.get(JWT_ISSUER_ENV)),
        jwt_audience=_clean(source.get(JWT_AUDIENCE_ENV)),
        jwks_file=jwks_file,
        jwks_url=jwks_url,
        jwks_ttl_seconds=_non_negative_int(
            source.get(JWKS_TTL_ENV), DEFAULT_JWKS_TTL_SECONDS
        ),
        jwt_algorithms=algorithms,
        service_tokens=service_tokens,
        database_url=database_url,
        receipt_ttl_seconds=_positive_int(
            source.get(RECEIPT_TTL_ENV), DEFAULT_RECEIPT_TTL_SECONDS
        ),
        retention_days=_positive_int(source.get(RETENTION_DAYS_ENV), DEFAULT_RETENTION_DAYS),
        legacy_unauthenticated=legacy,
        trust_ceiling_default=trust_ceiling,
        default_tenant=_clean(source.get(DEFAULT_TENANT_ENV)) or DEFAULT_TENANT,
        bind_address=_clean(source.get(BIND_ADDRESS_ENV)) or DEFAULT_BIND_ADDRESS,
        store_payload_metadata=_flag(source.get(STORE_PAYLOAD_METADATA_ENV)),
        problems=tuple(problems),
    )
    return settings


def validate_settings(settings: Settings) -> None:
    """Refuse an unsafe configuration with a message an operator can act on (D7)."""

    problems = list(settings.problems)
    if settings.production:
        if settings.auth_mode is AuthMode.NONE:
            problems.append(
                f"{AUTH_MODE_ENV}=none is refused in {ENVIRONMENT_ENV}=production; "
                f"set {AUTH_MODE_ENV}=required"
            )
        if settings.legacy_unauthenticated:
            problems.append(
                f"the unauthenticated legacy surface is refused in {ENVIRONMENT_ENV}=production; "
                f"unset {LEGACY_ENV}"
            )
        if not settings.database_url:
            problems.append(
                f"{DATABASE_URL_ENV} is required in {ENVIRONMENT_ENV}=production: receipts must "
                "survive a restart"
            )
        if (
            settings.auth_mode is AuthMode.REQUIRED
            and not settings.jwt_enabled
            and not settings.service_tokens
        ):
            problems.append(
                f"{AUTH_MODE_ENV}=required needs a verifier: set {JWT_ISSUER_ENV}, "
                f"{JWT_AUDIENCE_ENV} and {JWKS_ENV}, or configure {SERVICE_TOKENS_ENV}"
            )
    if settings.legacy_unauthenticated and not _is_loopback(settings.bind_address):
        problems.append(
            f"{LEGACY_ENV}=true requires a loopback {BIND_ADDRESS_ENV}; "
            f"got {settings.bind_address!r}"
        )
    if settings.jwks_file is not None and not Path(settings.jwks_file).is_file():
        problems.append(f"{JWKS_ENV} file does not exist: {settings.jwks_file}")
    if problems:
        raise ConfigurationError("; ".join(problems))


def safe_summary(settings: Settings) -> dict[str, object]:
    """Return a log-safe summary: presence and shape only, never secret material."""

    return {
        "environment": settings.environment.value,
        "auth_mode": settings.auth_mode.value,
        "jwt_issuer": settings.jwt_issuer,
        "jwt_audience": settings.jwt_audience,
        "jwks_file_configured": settings.jwks_file is not None,
        "jwks_url_configured": settings.jwks_url is not None,
        "jwks_ttl_seconds": settings.jwks_ttl_seconds,
        "jwt_algorithms": list(settings.jwt_algorithms),
        "service_token_count": len(settings.service_tokens),
        "durable_store": settings.durable,
        "receipt_ttl_seconds": settings.receipt_ttl_seconds,
        "retention_days": settings.retention_days,
        "legacy_unauthenticated": settings.legacy_unauthenticated,
        "trust_ceiling_default": settings.trust_ceiling_default.value,
        "bind_address": settings.bind_address,
        "store_payload_metadata": settings.store_payload_metadata,
    }


def main(argv: list[str] | None = None) -> int:
    """Validate the configuration and exit non-zero when it is unsafe (D7)."""

    del argv
    try:
        settings = load_settings()
        validate_settings(settings)
    except ConfigurationError as error:
        print(f"aegisgraph: refusing to start: {error}", file=sys.stderr)
        return 2
    print(f"aegisgraph: configuration accepted: {json.dumps(safe_summary(settings))}")
    return 0


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _environment(source: Mapping[str, str], problems: list[str]) -> Environment:
    raw = (_clean(source.get(ENVIRONMENT_ENV)) or DEFAULT_ENVIRONMENT).lower()
    try:
        return Environment(raw)
    except ValueError:
        problems.append(f"{ENVIRONMENT_ENV} must be one of development, production; got {raw!r}")
        return Environment.DEVELOPMENT


def _auth_mode(source: Mapping[str, str], problems: list[str]) -> AuthMode:
    raw = (_clean(source.get(AUTH_MODE_ENV)) or DEFAULT_AUTH_MODE).lower()
    try:
        return AuthMode(raw)
    except ValueError:
        problems.append(f"{AUTH_MODE_ENV} must be one of none, required; got {raw!r}")
        return AuthMode.NONE


def _legacy(source: Mapping[str, str], environment: Environment) -> bool:
    """The frozen legacy surface is on by default in development only (D5)."""

    raw = _clean(source.get(LEGACY_ENV))
    if raw is None:
        return environment is Environment.DEVELOPMENT
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _trust_ceiling(source: Mapping[str, str], problems: list[str]) -> TrustLevel:
    raw = _clean(source.get(TRUST_CEILING_ENV))
    if raw is None:
        return DEFAULT_TRUST_CEILING
    try:
        return TrustLevel(raw.strip().lower())
    except ValueError:
        allowed = ", ".join(level.value for level in TrustLevel)
        problems.append(f"{TRUST_CEILING_ENV} must be one of {allowed}; got {raw!r}")
        return DEFAULT_TRUST_CEILING


def _algorithms(source: Mapping[str, str], problems: list[str]) -> tuple[str, ...]:
    raw = _clean(source.get(JWT_ALGORITHMS_ENV))
    if raw is None:
        return DEFAULT_JWT_ALGORITHMS
    algorithms = tuple(item.strip() for item in raw.split(",") if item.strip())
    unsupported = [item for item in algorithms if item not in {"RS256", "ES256", "RS384", "ES384"}]
    if unsupported or not algorithms:
        problems.append(
            f"{JWT_ALGORITHMS_ENV} accepts only asymmetric algorithms "
            f"(RS256, RS384, ES256, ES384); got {raw!r}"
        )
        return DEFAULT_JWT_ALGORITHMS
    return algorithms


def _jwks_sources(source: Mapping[str, str], problems: list[str]) -> tuple[str | None, str | None]:
    """Resolve the mounted JWKS file and the optional issuer URL (D7).

    The decision process must not hold a network capability, so the runtime reads a
    **mounted file**. ``AEGISGRAPH_JWKS_URL`` records the issuer document the
    operator-side refresher (``scripts/jwks_refresh.py``) materialises into that
    file; it is never fetched by the service itself.
    """

    url = _clean(source.get(JWKS_URL_ENV))
    declared = _clean(source.get(JWKS_FILE_ENV)) or _clean(source.get(JWKS_ENV))
    if declared is not None and declared.startswith(("http://", "https://")):
        problems.append(
            f"{JWKS_ENV} must be a mounted file path; run scripts/jwks_refresh.py to materialise "
            f"{declared!r} into a file and point {JWKS_ENV} at it"
        )
        return None, url or declared
    return declared, url


def _service_tokens(
    source: Mapping[str, str], problems: list[str]
) -> tuple[ServiceTokenRecord, ...]:
    payload: object = None
    inline = _clean(source.get(SERVICE_TOKENS_ENV))
    if inline is not None:
        payload = _parse_json(inline, SERVICE_TOKENS_ENV, problems)
    else:
        path_text = _clean(source.get(SERVICE_TOKEN_FILE_ENV))
        if path_text is not None:
            path = Path(path_text)
            try:
                payload = _parse_json(
                    path.read_text(encoding="utf-8"), SERVICE_TOKEN_FILE_ENV, problems
                )
            except OSError:
                problems.append(f"{SERVICE_TOKEN_FILE_ENV} could not be read: {path_text}")
    if payload is None:
        return ()
    if not isinstance(payload, list):
        problems.append(f"{SERVICE_TOKENS_ENV} must be a JSON list of token records")
        return ()
    records: list[ServiceTokenRecord] = []
    for index, item in enumerate(payload):
        record = _service_token(item, index, problems)
        if record is not None:
            records.append(record)
    return tuple(records)


def _parse_json(text: str, name: str, problems: list[str]) -> object:
    try:
        return json.loads(text)
    except ValueError:
        problems.append(f"{name} is not valid JSON")
        return None


def _service_token(
    item: object, index: int, problems: list[str]
) -> ServiceTokenRecord | None:
    if not isinstance(item, dict):
        problems.append(f"{SERVICE_TOKENS_ENV}[{index}] must be an object")
        return None
    unknown = set(item) - _SERVICE_TOKEN_FIELDS
    if unknown:
        problems.append(f"{SERVICE_TOKENS_ENV}[{index}] has unknown fields: {sorted(unknown)}")
        return None
    identifier = item.get("id")
    tenant = item.get("tenant_id")
    digest = item.get("sha256")
    scopes = item.get("scopes")
    ceiling = item.get("trust_ceiling", DEFAULT_TRUST_CEILING.value)
    if not isinstance(identifier, str) or not identifier:
        problems.append(f"{SERVICE_TOKENS_ENV}[{index}].id must be a non-empty string")
        return None
    if not isinstance(tenant, str) or not tenant:
        problems.append(f"{SERVICE_TOKENS_ENV}[{index}].tenant_id must be a non-empty string")
        return None
    if not isinstance(digest, str) or _SHA256_HEX.fullmatch(digest.lower()) is None:
        problems.append(
            f"{SERVICE_TOKENS_ENV}[{index}].sha256 must be a lowercase SHA-256 hex digest"
        )
        return None
    if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
        problems.append(f"{SERVICE_TOKENS_ENV}[{index}].scopes must be a list of strings")
        return None
    try:
        ceiling_value = TrustLevel(str(ceiling))
    except ValueError:
        problems.append(f"{SERVICE_TOKENS_ENV}[{index}].trust_ceiling is not a known trust level")
        return None
    return ServiceTokenRecord(
        id=identifier,
        tenant_id=tenant,
        sha256=digest.lower(),
        scopes=tuple(str(scope) for scope in scopes),
        trust_ceiling=ceiling_value,
    )


def _flag(raw: str | None) -> bool:
    text = _clean(raw)
    return text is not None and text.lower() in {"1", "true", "yes", "on"}


def _non_negative_int(raw: str | None, default: int) -> int:
    text = _clean(raw)
    if text is None:
        return default
    try:
        value = int(text)
    except ValueError:
        return default
    return value if value >= 0 else default


def _positive_int(raw: str | None, default: int) -> int:
    text = _clean(raw)
    if text is None:
        return default
    try:
        value = int(text)
    except ValueError:
        return default
    return value if value > 0 else default


def _is_loopback(address: str) -> bool:
    return address in LOOPBACK_HOSTS


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    raise SystemExit(main())


__all__ = [
    "AUTH_MODE_ENV",
    "BIND_ADDRESS_ENV",
    "DATABASE_URL_ENV",
    "DEFAULT_TENANT",
    "DEFAULT_TRUST_CEILING",
    "JWKS_ENV",
    "JWKS_FILE_ENV",
    "JWKS_TTL_ENV",
    "JWKS_URL_ENV",
    "JWT_AUDIENCE_ENV",
    "JWT_ISSUER_ENV",
    "LEGACY_ENV",
    "RETENTION_DAYS_ENV",
    "SERVICE_TOKENS_ENV",
    "SERVICE_TOKEN_FILE_ENV",
    "STORE_PAYLOAD_METADATA_ENV",
    "TRUST_CEILING_ENV",
    "AuthMode",
    "ConfigurationError",
    "Environment",
    "ServiceTokenRecord",
    "Settings",
    "load_settings",
    "main",
    "safe_summary",
    "validate_settings",
]
