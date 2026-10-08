"""The sealed holdout: a passphrase-encrypted scenario set plus its public seal.

The holdout must exist *now* (so it can be hashed and frozen with the rest of the
benchmark) but must be invisible to every agent that writes policy until the
orchestrator opens the seal after the policy freeze. A file in Git is visible, so
the plaintext is not in Git: the committed artifact is a single encrypted blob
and a manifest that records only hashes and KDF parameters.

Custodian rule
--------------
The passphrase is generated when the seal is created, printed exactly once, and
handed to the orchestrator. It is never written to the repository, never written
to a log, and never committed. Opening the seal is an orchestrator action, and
``docs/benchmark/holdout.md`` records the exact command.

Cryptography
------------
scrypt (``hashlib.scrypt``, n=2**15, r=8, p=1) derives a 32-byte key from the
passphrase; AES-256-GCM from the ``cryptography`` package performs authenticated
encryption. The salt and nonce live in the manifest; both hashes (plaintext and
ciphertext) live in the manifest so tampering is detectable *without* the
passphrase.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from benchmark.dataset import SEAL_FILE, SEALED_FILE
from benchmark.schema import Scenario, canonical_json

SEAL_SCHEMA_VERSION = "aegisgraph-benchmark-holdout/v1"
CIPHER = "AES-256-GCM"
KDF = "scrypt-n32768-r8-p1"
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1


class SealError(RuntimeError):
    """Raised for every seal failure: missing file, wrong passphrase, tampering."""


def _cryptography() -> Any:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as error:  # pragma: no cover - depends on the environment
        raise SealError(
            "the 'cryptography' package is required to seal or open the holdout; "
            "install it with: python -m pip install 'cryptography>=42'"
        ) from error
    return AESGCM


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    import hashlib

    if not passphrase:
        raise SealError("the holdout passphrase must not be empty")
    return hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=KEY_BYTES,
        # 128 * n * r bytes are needed; OpenSSL's default ceiling is 32 MiB, which
        # this work factor exceeds, so the limit is set explicitly.
        maxmem=128 * SCRYPT_N * SCRYPT_R * 2,
    )


@dataclass(frozen=True)
class SealManifest:
    schema_version: str
    created: str
    sealed_file: str
    cipher: str
    kdf: str
    salt_hex: str
    nonce_hex: str
    ciphertext_sha256: str
    plaintext_sha256: str
    scenario_count: int
    domains: tuple[str, ...]
    families: tuple[str, ...]
    note: str

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "created": self.created,
            "sealed_file": self.sealed_file,
            "cipher": self.cipher,
            "kdf": self.kdf,
            "salt_hex": self.salt_hex,
            "nonce_hex": self.nonce_hex,
            "ciphertext_sha256": self.ciphertext_sha256,
            "plaintext_sha256": self.plaintext_sha256,
            "scenario_count": self.scenario_count,
            "domains": list(self.domains),
            "families": list(self.families),
            "note": self.note,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> SealManifest:
        return cls(
            schema_version=str(data["schema_version"]),
            created=str(data["created"]),
            sealed_file=str(data.get("sealed_file", SEALED_FILE)),
            cipher=str(data["cipher"]),
            kdf=str(data["kdf"]),
            salt_hex=str(data["salt_hex"]),
            nonce_hex=str(data["nonce_hex"]),
            ciphertext_sha256=str(data["ciphertext_sha256"]),
            plaintext_sha256=str(data["plaintext_sha256"]),
            scenario_count=int(data["scenario_count"]),
            domains=tuple(data.get("domains") or ()),
            families=tuple(data.get("families") or ()),
            note=str(data.get("note", "")),
        )


def plaintext_bytes(scenarios: list[Scenario]) -> bytes:
    """The exact bytes that get encrypted, and whose hash the manifest records."""

    document = {
        "schema_version": SEAL_SCHEMA_VERSION,
        "scenarios": [
            scenario.model_dump(mode="json")
            for scenario in sorted(scenarios, key=lambda item: item.id)
        ],
    }
    return canonical_json(document).encode("utf-8")


def seal_holdout(
    scenarios: list[Scenario],
    passphrase: str,
    root: Path | str,
    *,
    created: str | None = None,
    note: str = "",
) -> SealManifest:
    """Encrypt ``scenarios`` into ``<root>/holdout`` and write the manifest."""

    import hashlib
    import os

    AESGCM = _cryptography()
    if not scenarios:
        raise SealError("refusing to seal an empty holdout")
    if any(scenario.split.value != "holdout" for scenario in scenarios):
        raise SealError("every sealed scenario must declare split='holdout'")

    base = Path(root)
    holdout_dir = base / "holdout"
    holdout_dir.mkdir(parents=True, exist_ok=True)
    sealed_path = base / SEALED_FILE
    if sealed_path.exists():
        raise SealError(f"refusing to overwrite an existing seal at {sealed_path}")

    payload = plaintext_bytes(scenarios)
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    key = _derive_key(passphrase, salt)
    ciphertext = AESGCM(key).encrypt(nonce, payload, None)
    sealed_path.write_bytes(ciphertext)
    manifest = SealManifest(
        schema_version=SEAL_SCHEMA_VERSION,
        created=created or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        sealed_file=SEALED_FILE,
        cipher=CIPHER,
        kdf=KDF,
        salt_hex=salt.hex(),
        nonce_hex=nonce.hex(),
        ciphertext_sha256=hashlib.sha256(ciphertext).hexdigest(),
        plaintext_sha256=hashlib.sha256(payload).hexdigest(),
        scenario_count=len(scenarios),
        domains=tuple(sorted({scenario.domain.value for scenario in scenarios})),
        families=tuple(sorted({scenario.family_label for scenario in scenarios})),
        note=note,
    )
    (base / SEAL_FILE).write_text(
        canonical_json(manifest.to_json()), encoding="utf-8", newline="\n"
    )
    return manifest


def read_manifest(root: Path | str) -> SealManifest:
    base = Path(root)
    seal_path = base / SEAL_FILE
    if not seal_path.is_file():
        raise SealError(f"no seal manifest at {seal_path}")
    return SealManifest.from_json(json.loads(seal_path.read_text(encoding="utf-8")))


def open_seal(passphrase: str, root: Path | str) -> list[Scenario]:
    """Decrypt and validate the sealed holdout. Nothing is written to disk."""

    import hashlib

    AESGCM = _cryptography()
    base = Path(root)
    manifest = read_manifest(base)
    sealed_path = base / manifest.sealed_file
    if not sealed_path.is_file():
        raise SealError(f"no sealed holdout at {sealed_path}")
    ciphertext = sealed_path.read_bytes()
    actual = hashlib.sha256(ciphertext).hexdigest()
    if actual != manifest.ciphertext_sha256:
        raise SealError(
            "the sealed holdout does not match its manifest "
            f"(expected {manifest.ciphertext_sha256}, found {actual})"
        )
    key = _derive_key(passphrase, bytes.fromhex(manifest.salt_hex))
    try:
        payload = AESGCM(key).decrypt(bytes.fromhex(manifest.nonce_hex), ciphertext, None)
    except Exception as error:  # cryptography raises InvalidTag, which is not ours
        raise SealError(
            "the passphrase is wrong or the sealed holdout was tampered with"
        ) from error
    if hashlib.sha256(payload).hexdigest() != manifest.plaintext_sha256:
        raise SealError("decrypted holdout does not match the recorded plaintext hash")
    document = json.loads(payload.decode("utf-8"))
    scenarios = [Scenario.model_validate(item) for item in document["scenarios"]]
    if plaintext_bytes(scenarios) != payload:
        raise SealError("the decrypted scenario set is not canonical")
    return scenarios


def verify_seal(root: Path | str, passphrase: str | None = None) -> dict[str, Any]:
    """Verify what is verifiable. Without a passphrase this is a hash check only."""

    import hashlib

    base = Path(root)
    manifest = read_manifest(base)
    sealed_path = base / manifest.sealed_file
    result: dict[str, Any] = {
        "sealed_file": manifest.sealed_file,
        "scenario_count": manifest.scenario_count,
        "plaintext_sha256": manifest.plaintext_sha256,
        "ciphertext_present": sealed_path.is_file(),
        "ciphertext_matches": False,
        "opened": False,
        "domains": list(manifest.domains),
        "families": list(manifest.families),
    }
    if sealed_path.is_file():
        result["ciphertext_matches"] = (
            hashlib.sha256(sealed_path.read_bytes()).hexdigest() == manifest.ciphertext_sha256
        )
    if passphrase is not None:
        scenarios = open_seal(passphrase, base)
        result["opened"] = True
        result["opened_scenario_count"] = len(scenarios)
        result["splits"] = sorted({scenario.split.value for scenario in scenarios})
    return result


__all__ = [
    "CIPHER",
    "KDF",
    "SealError",
    "SealManifest",
    "open_seal",
    "plaintext_bytes",
    "read_manifest",
    "seal_holdout",
    "verify_seal",
]
