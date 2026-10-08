"""Credential verification, principals and scopes (findings F1, F3; decisions D1-D3).

Two credential shapes are accepted:

* an **asymmetric JWT** verified against a JWKS (issuer, audience, expiry and
  ``nbf`` are checked; the algorithm is pinned to the configured asymmetric set),
* an **opaque service token** whose SHA-256 digest is configured out of band, so
  the service never stores or logs the token itself.

Either way the credential — never the request body — decides ``principal_id``,
``tenant_id``, the scope list and the provenance trust ceiling (D1). A
development-only, unauthenticated principal exists so the frozen trusted-caller
behaviour can be exercised locally; it is refused in production (D5, D7).

Nothing in this module logs, raises with, or returns the credential material.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from aegisgraph.contracts import TrustLevel
from aegisgraph.settings import AuthMode, Settings

SCOPE_DECISION_SUBMIT: Final[str] = "decision:submit"
SCOPE_RECEIPT_READ: Final[str] = "receipt:read"
SCOPE_POLICY_READ: Final[str] = "policy:read"
SCOPE_POLICY_WRITE: Final[str] = "policy:write"
SCOPE_CONFIRMATION_GRANT: Final[str] = "confirmation:grant"
SCOPE_POLICY_CONTEXT_OVERRIDE: Final[str] = "policy:context_override"

ALL_SCOPES: Final[frozenset[str]] = frozenset(
    {
        SCOPE_DECISION_SUBMIT,
        SCOPE_RECEIPT_READ,
        SCOPE_POLICY_READ,
        SCOPE_POLICY_WRITE,
        SCOPE_CONFIRMATION_GRANT,
        SCOPE_POLICY_CONTEXT_OVERRIDE,
    }
)

ROLE_SCOPES: Final[Mapping[str, frozenset[str]]] = {
    "decision_client": frozenset({SCOPE_DECISION_SUBMIT}),
    "auditor": frozenset({SCOPE_RECEIPT_READ}),
    "policy_admin": frozenset({SCOPE_POLICY_READ, SCOPE_POLICY_WRITE}),
}

AUTH_METHOD_JWT: Final[str] = "jwt"
AUTH_METHOD_SERVICE_TOKEN: Final[str] = "service_token"
AUTH_METHOD_DEVELOPMENT: Final[str] = "development"

AUTHENTICATION_REQUIRED: Final[str] = "AUTHENTICATION_REQUIRED"
INVALID_TOKEN: Final[str] = "INVALID_TOKEN"
TOKEN_EXPIRED: Final[str] = "TOKEN_EXPIRED"
INSUFFICIENT_SCOPE: Final[str] = "INSUFFICIENT_SCOPE"
TRUST_CEILING_EXCEEDED: Final[str] = "TRUST_CEILING_EXCEEDED"
TENANT_MISMATCH: Final[str] = "TENANT_MISMATCH"
AUTHENTICATION_UNAVAILABLE: Final[str] = "AUTHENTICATION_UNAVAILABLE"

JWKS_REFRESH_MIN_INTERVAL_SECONDS: Final[float] = 1.0
"""Minimum spacing between two forced JWKS re-reads, so a stream of tokens with an
unknown ``kid`` cannot turn into one file read per request (H3-07)."""

JWT_TENANT_CLAIMS: Final[tuple[str, ...]] = ("tenant_id", "tid", "tenant")
JWT_SCOPE_CLAIMS: Final[tuple[str, ...]] = ("scope", "scp", "scopes")
JWT_ROLE_CLAIMS: Final[tuple[str, ...]] = ("role", "roles")
JWT_REQUIRED_CLAIMS: Final[tuple[str, ...]] = ("exp", "iat", "sub")



class AuthError(Exception):
    """A credential was absent, unverifiable, or insufficiently scoped."""

    def __init__(self, code: str, detail: str, *, status_code: int = 401) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.status_code = status_code


@dataclass(frozen=True)
class Principal:
    """The resolved caller identity: tenant and scopes come from the credential."""

    principal_id: str
    tenant_id: str
    scopes: frozenset[str]
    trust_ceiling: TrustLevel
    auth_method: str

    def has(self, *required: str) -> bool:
        return all(scope in self.scopes for scope in required)

    def assert_scopes(self, *required: str) -> None:
        """Raise a 403 carrying only the missing scope names (never the token)."""

        missing = sorted(scope for scope in required if scope not in self.scopes)
        if missing:
            raise AuthError(
                INSUFFICIENT_SCOPE,
                f"missing required scope(s): {', '.join(missing)}",
                status_code=403,
            )


def development_principal(settings: Settings) -> Principal:
    """Return the labelled development-only caller used when auth is ``none`` (D5).

    This principal holds every scope, because ``AEGISGRAPH_AUTH_MODE=none`` is the
    frozen trusted-caller model: the process is responsible for restricting who
    can reach it, and the configuration refuses that mode in production.
    """

    return Principal(
        principal_id="development",
        tenant_id=settings.default_tenant,
        scopes=ALL_SCOPES,
        trust_ceiling=TrustLevel.SYSTEM_POLICY,
        auth_method=AUTH_METHOD_DEVELOPMENT,
    )


def resolve_principal(authorization: str | None, settings: Settings) -> Principal:
    """Resolve the caller identity from the ``Authorization`` header (D1)."""

    if settings.auth_mode is AuthMode.NONE:
        return development_principal(settings)
    if authorization is None or not authorization.strip():
        raise AuthError(AUTHENTICATION_REQUIRED, "an Authorization header is required")
    scheme, _, credential = authorization.partition(" ")
    if scheme.lower() != "bearer" or not credential.strip():
        raise AuthError(INVALID_TOKEN, "the Authorization header must be 'Bearer <token>'")
    token = credential.strip()
    if token.count(".") == 2:
        return verify_jwt(token, settings)
    return verify_service_token(token, settings)


def verify_jwt(token: str, settings: Settings) -> Principal:
    """Verify a JWT against the configured JWKS and return its principal."""

    jwt = _import_jwt()
    if not settings.jwt_enabled or settings.jwks_file is None:
        raise AuthError(
            AUTHENTICATION_UNAVAILABLE,
            "no JWT verifier is configured for this process",
            status_code=503,
        )
    try:
        header = jwt.get_unverified_header(token)
    except Exception as error:
        raise AuthError(INVALID_TOKEN, "the token header could not be read") from error
    algorithm = header.get("alg")
    if not isinstance(algorithm, str) or algorithm not in settings.jwt_algorithms:
        raise AuthError(INVALID_TOKEN, "the token algorithm is not accepted")
    key = _jwks(settings).key_for(header.get("kid"), algorithm)
    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=list(settings.jwt_algorithms),
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={"require": list(JWT_REQUIRED_CLAIMS)},
        )
    except jwt.ExpiredSignatureError as error:
        raise AuthError(TOKEN_EXPIRED, "the token has expired") from error
    except Exception as error:
        raise AuthError(INVALID_TOKEN, "the token failed verification") from error
    return _principal_from_claims(claims, settings)


def verify_service_token(token: str, settings: Settings) -> Principal:
    """Match an opaque token against the configured SHA-256 digests."""

    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    for record in settings.service_tokens:
        if hmac.compare_digest(digest, record.sha256):
            return Principal(
                principal_id=record.id,
                tenant_id=record.tenant_id,
                scopes=frozenset(record.scopes),
                trust_ceiling=record.trust_ceiling,
                auth_method=AUTH_METHOD_SERVICE_TOKEN,
            )
    raise AuthError(INVALID_TOKEN, "the service token is not recognised")


def _principal_from_claims(claims: Mapping[str, Any], settings: Settings) -> Principal:
    principal_id = _first_string(claims, ("sub",))
    if principal_id is None:
        raise AuthError(INVALID_TOKEN, "the token carries no subject")
    tenant_id = _first_string(claims, JWT_TENANT_CLAIMS)
    if tenant_id is None:
        raise AuthError(INVALID_TOKEN, "the token carries no tenant")
    scopes = _claim_scopes(claims)
    for claim in JWT_ROLE_CLAIMS:
        for role in _as_strings(claims.get(claim)):
            scopes |= ROLE_SCOPES.get(role, frozenset())
    ceiling = settings.trust_ceiling_default
    declared = claims.get("trust_ceiling")
    if isinstance(declared, str):
        try:
            ceiling = TrustLevel(declared)
        except ValueError as error:
            raise AuthError(INVALID_TOKEN, "the token declares an unknown trust ceiling") from error
    return Principal(
        principal_id=principal_id,
        tenant_id=tenant_id,
        scopes=frozenset(scopes),
        trust_ceiling=ceiling,
        auth_method=AUTH_METHOD_JWT,
    )


def _claim_scopes(claims: Mapping[str, Any]) -> set[str]:
    scopes: set[str] = set()
    for claim in JWT_SCOPE_CLAIMS:
        value = claims.get(claim)
        if isinstance(value, str):
            scopes.update(part for part in value.replace(",", " ").split() if part)
        else:
            scopes.update(_as_strings(value))
    return scopes


def _as_strings(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence):
        return tuple(item for item in value if isinstance(item, str))
    return ()


def _first_string(claims: Mapping[str, Any], names: Iterable[str]) -> str | None:
    for name in names:
        value = claims.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _import_jwt() -> Any:
    """Import PyJWT lazily so the development mode needs no JWT dependency."""

    try:
        import jwt
    except ImportError as error:  # pragma: no cover - deployment defect
        raise AuthError(
            AUTHENTICATION_UNAVAILABLE,
            "the JWT verifier dependency is not installed",
            status_code=503,
        ) from error
    return jwt


@dataclass
class _JwksCache:
    """A small, refresh-on-miss cache over one mounted JWKS document.

    The document is read from a file, never fetched: the decision process holds no
    network capability. ``scripts/jwks_refresh.py`` materialises an issuer URL into
    that file out of band.
    """

    path: str
    ttl_seconds: float = 300.0
    refresh_interval: float = JWKS_REFRESH_MIN_INTERVAL_SECONDS
    reads: int = 0
    _document: dict[str, Any] | None = field(default=None, repr=False)
    _fetched_at: float = 0.0

    def key_for(self, kid: str | None, algorithm: str) -> Any:
        del algorithm  # the algorithm is already pinned by the decode call
        key = _select_key(self._keys(refresh=False), kid)
        if key is None:
            key = _select_key(self._keys(refresh=True), kid)
        if key is None:
            raise AuthError(INVALID_TOKEN, "the token key is not published by the issuer")
        return key

    def _keys(self, *, refresh: bool) -> tuple[Any, ...]:
        now = time.monotonic()
        age = now - self._fetched_at
        # A forced re-read (an unknown ``kid``) is rate-bounded, so a stream of
        # tokens with a bogus key id cannot turn into a file read per request.
        forced = refresh and age >= min(self.ttl_seconds, self.refresh_interval)
        if self._document is None or age > self.ttl_seconds or forced:
            document = self._load()
            if document is not None:
                self._document = document
                self._fetched_at = now
        if self._document is None:
            raise AuthError(
                AUTHENTICATION_UNAVAILABLE,
                "the JWKS document is unavailable",
                status_code=503,
            )
        jwt = _import_jwt()
        try:
            key_set = jwt.PyJWKSet.from_dict(self._document)
        except Exception as error:
            raise AuthError(
                AUTHENTICATION_UNAVAILABLE, "the JWKS document is malformed", status_code=503
            ) from error
        return tuple(key_set.keys)

    def _load(self) -> dict[str, Any] | None:
        self.reads += 1
        try:
            raw = Path(self.path).read_text(encoding="utf-8")
        except OSError:
            return None
        try:
            document = json.loads(raw)
        except ValueError:
            return None
        return document if isinstance(document, dict) else None


def _select_key(keys: tuple[Any, ...], kid: str | None) -> Any | None:
    if kid is not None:
        for key in keys:
            if getattr(key, "key_id", None) == kid:
                return key.key
        return None
    if len(keys) == 1:
        return keys[0].key
    return None


_CACHES: dict[str, _JwksCache] = {}


def _jwks(settings: Settings) -> _JwksCache:
    assert settings.jwks_file is not None
    ttl = float(settings.jwks_ttl_seconds)
    cache = _CACHES.get(settings.jwks_file)
    if cache is None:
        cache = _JwksCache(path=settings.jwks_file, ttl_seconds=ttl)
        _CACHES[settings.jwks_file] = cache
    elif cache.ttl_seconds != ttl:
        cache.ttl_seconds = ttl
    return cache


def clear_jwks_cache() -> None:
    """Drop cached JWKS documents (used by tests and after a key rotation)."""

    _CACHES.clear()


__all__ = [
    "ALL_SCOPES",
    "AUTHENTICATION_REQUIRED",
    "AUTHENTICATION_UNAVAILABLE",
    "AUTH_METHOD_DEVELOPMENT",
    "AUTH_METHOD_JWT",
    "AUTH_METHOD_SERVICE_TOKEN",
    "INSUFFICIENT_SCOPE",
    "INVALID_TOKEN",
    "ROLE_SCOPES",
    "SCOPE_CONFIRMATION_GRANT",
    "SCOPE_DECISION_SUBMIT",
    "SCOPE_POLICY_CONTEXT_OVERRIDE",
    "SCOPE_POLICY_READ",
    "SCOPE_POLICY_WRITE",
    "SCOPE_RECEIPT_READ",
    "TENANT_MISMATCH",
    "TOKEN_EXPIRED",
    "TRUST_CEILING_EXCEEDED",
    "AuthError",
    "Principal",
    "clear_jwks_cache",
    "development_principal",
    "resolve_principal",
    "verify_jwt",
    "verify_service_token",
]
