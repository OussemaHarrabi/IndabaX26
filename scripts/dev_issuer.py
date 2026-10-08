#!/usr/bin/env python3
"""Development-only local JWT issuer for AegisGraph (D7).

This is **not** a production identity provider. It exists so the local stack and
the test suite can mint short-lived asymmetric tokens against a local JWKS file.
It is labelled ``development`` in every artefact it writes, it refuses to write
into the repository by default, and it must never be deployed.

Usage::

    python scripts/dev_issuer.py init
    python scripts/dev_issuer.py mint --tenant acme --role decision_client
    python scripts/dev_issuer.py show

The default output directory is a temporary directory outside the repository, so
a generated private key cannot be committed by accident.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import tempfile
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

DEFAULT_ISSUER = "https://dev-issuer.aegisgraph.local"
DEFAULT_AUDIENCE = "aegisgraph"
DEFAULT_KID = "aegisgraph-dev-1"
DEFAULT_TTL_SECONDS = 3600
LABEL = "development-only"

ROLE_SCOPES = {
    "decision_client": ("decision:submit",),
    "auditor": ("receipt:read",),
    "policy_admin": ("policy:read", "policy:write"),
}


def default_directory() -> Path:
    """Return a location outside the repository for generated key material."""

    override = os.environ.get("AEGISGRAPH_DEV_ISSUER_DIR")
    if override:
        return Path(override)
    return Path(tempfile.gettempdir()) / "aegisgraph-dev-issuer"


def _require_crypto() -> tuple[Any, Any, Any]:
    try:
        import jwt
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError as error:  # pragma: no cover - deployment defect
        raise SystemExit(
            "dev_issuer: install pyjwt[crypto] first (pip install 'pyjwt[crypto]>=2.9,<3')"
        ) from error
    return jwt, serialization, rsa


def _b64url_uint(value: int) -> str:
    import base64

    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def init(directory: Path, *, kid: str, force: bool) -> dict[str, Any]:
    """Generate one RSA keypair and write the public JWKS document."""

    jwt, serialization, rsa = _require_crypto()
    del jwt
    directory.mkdir(parents=True, exist_ok=True)
    key_path = directory / "private.pem"
    jwks_path = directory / "jwks.json"
    if key_path.exists() and not force:
        raise SystemExit(f"dev_issuer: {key_path} already exists; pass --force to replace it")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(private_pem)
    with suppress(OSError):  # pragma: no cover - Windows without POSIX modes
        key_path.chmod(0o600)

    numbers = key.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": _b64url_uint(numbers.n),
                "e": _b64url_uint(numbers.e),
            }
        ],
        "aegisgraph_label": LABEL,
    }
    jwks_path.write_text(json.dumps(jwks, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "directory": str(directory),
        "private_key": str(key_path),
        "jwks": str(jwks_path),
        "kid": kid,
        "label": LABEL,
    }


def mint(
    directory: Path,
    *,
    issuer: str,
    audience: str,
    kid: str,
    tenant: str,
    subject: str,
    role: str | None,
    scopes: tuple[str, ...],
    trust_ceiling: str,
    ttl_seconds: int,
) -> str:
    """Mint one signed access token with the resolved scope set."""

    jwt, _, _ = _require_crypto()
    key_path = directory / "private.pem"
    if not key_path.is_file():
        raise SystemExit(f"dev_issuer: {key_path} is missing; run `init` first")
    resolved = list(scopes)
    if role is not None:
        if role not in ROLE_SCOPES:
            raise SystemExit(f"dev_issuer: unknown role {role!r}; known: {sorted(ROLE_SCOPES)}")
        resolved.extend(ROLE_SCOPES[role])
    if not resolved:
        raise SystemExit("dev_issuer: provide --role and/or --scope")

    now = datetime.now(UTC)
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "tenant_id": tenant,
        "scope": " ".join(dict.fromkeys(resolved)),
        "trust_ceiling": trust_ceiling,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
        "jti": secrets.token_hex(8),
        "aegisgraph_label": LABEL,
    }
    return jwt.encode(
        claims,
        key_path.read_text(encoding="utf-8"),
        algorithm="RS256",
        headers={"kid": kid},
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("command", choices=("init", "mint", "show"))
    parser.add_argument("--directory", type=Path, default=default_directory())
    parser.add_argument("--kid", default=DEFAULT_KID)
    parser.add_argument("--issuer", default=DEFAULT_ISSUER)
    parser.add_argument("--audience", default=DEFAULT_AUDIENCE)
    parser.add_argument("--tenant", default="development")
    parser.add_argument("--subject", default="dev-client")
    parser.add_argument("--role", default=None)
    parser.add_argument("--scope", action="append", default=[])
    parser.add_argument("--trust-ceiling", default="trusted_internal")
    parser.add_argument("--ttl", type=int, default=DEFAULT_TTL_SECONDS)
    parser.add_argument("--force", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run one command and print the result as JSON."""

    args = _parser().parse_args(argv)
    if args.command == "init":
        result: dict[str, Any] = init(args.directory, kid=args.kid, force=args.force)
    elif args.command == "mint":
        result = {
            "token": mint(
                args.directory,
                issuer=args.issuer,
                audience=args.audience,
                kid=args.kid,
                tenant=args.tenant,
                subject=args.subject,
                role=args.role,
                scopes=tuple(args.scope),
                trust_ceiling=args.trust_ceiling,
                ttl_seconds=args.ttl,
            ),
            "issuer": args.issuer,
            "audience": args.audience,
            "tenant_id": args.tenant,
            "role": args.role,
            "label": LABEL,
        }
    else:
        result = {
            "directory": str(args.directory),
            "jwks": str(args.directory / "jwks.json"),
            "exists": (args.directory / "jwks.json").is_file(),
            "label": LABEL,
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    sys.exit(main())
