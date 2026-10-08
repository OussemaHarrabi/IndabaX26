"""Produce a dependency inventory and provenance record for a built image.

``syft`` is not available in this environment, so this script emits an equivalent
**hash-bearing** manifest instead:

* the image identity from ``docker image inspect`` (id, repo digests, size);
* the exact source revision and the SHA-256 of ``requirements.lock``;
* every Python distribution installed *inside the image*, read with the standard
  library ``importlib.metadata`` (the hardened image has no ``pip`` by design, so
  ``pip freeze`` cannot run in it — this is the equivalent);
* for each distribution, the SHA-256 of its ``RECORD`` file, which is the wheel's
  own integrity manifest.

``--deterministic`` drops the generation timestamp so two runs against the same
image produce byte-identical output, which makes the committed manifest a stable
artifact whose digest can be recorded as evidence.

Usage:
    python scripts/generate_sbom.py --image aegisgraph:m4
    python scripts/generate_sbom.py --image aegisgraph:m4 --deterministic \
        --output deploy/sbom/aegisgraph-image-sbom.json
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

TOOL_VERSION = "1.0.0"
REPO_ROOT = Path(__file__).resolve().parents[1]

# Runs inside the image: no third-party imports, no writes, JSON on stdout.
_PROBE = (
    "import hashlib, importlib.metadata as md, json, sys\n"
    "packages = []\n"
    "for dist in md.distributions():\n"
    "    try:\n"
    "        name = dist.metadata['Name']\n"
    "    except Exception:\n"
    "        name = None\n"
    "    try:\n"
    "        record = dist.read_text('RECORD')\n"
    "    except Exception:\n"
    "        record = None\n"
    "    digest = hashlib.sha256(record.encode('utf-8')).hexdigest() if record else None\n"
    "    packages.append({'name': name or 'unknown', 'version': dist.version,\n"
    "                     'record_sha256': digest})\n"
    "packages.sort(key=lambda p: (p['name'].lower(), p['version'] or ''))\n"
    "json.dump({'python': sys.version.split()[0], 'packages': packages}, sys.stdout)\n"
)


def _run(command: list[str], *, cwd: Path | None = None) -> str:
    completed = subprocess.run(command, capture_output=True, text=True, cwd=cwd, check=False)
    if completed.returncode != 0:
        raise SystemExit(
            f"command failed ({completed.returncode}): {' '.join(command)}\n{completed.stderr}"
        )
    return completed.stdout


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(*args: str) -> str:
    try:
        return _run(["git", *args], cwd=REPO_ROOT).strip()
    except SystemExit:
        return "unknown"


def inspect_image(image: str) -> dict[str, Any]:
    raw = _run(["docker", "image", "inspect", image])
    metadata = json.loads(raw)[0]
    return {
        "reference": image,
        "id": metadata.get("Id"),
        "repo_digests": sorted(metadata.get("RepoDigests") or []),
        "created": metadata.get("Created"),
        "architecture": metadata.get("Architecture"),
        "os": metadata.get("Os"),
        "size_bytes": metadata.get("Size"),
        "entrypoint": metadata.get("Config", {}).get("Entrypoint"),
        "cmd": metadata.get("Config", {}).get("Cmd"),
        "user": metadata.get("Config", {}).get("User"),
    }


def probe_runtime(image: str) -> dict[str, Any]:
    raw = _run(
        [
            "docker",
            "run",
            "--rm",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--entrypoint",
            "python",
            image,
            "-c",
            _PROBE,
        ]
    )
    return json.loads(raw)


def build_manifest(image: str, *, deterministic: bool) -> dict[str, Any]:
    lock_path = REPO_ROOT / "requirements.lock"
    runtime = probe_runtime(image)
    manifest: dict[str, Any] = {
        "schema": "aegisgraph/sbom/v1",
        "generated_by": {
            "tool": "scripts/generate_sbom.py",
            "tool_version": TOOL_VERSION,
            "method": "docker image inspect + importlib.metadata inside the image",
            "note": "syft unavailable; hash-bearing equivalent manifest",
        },
        "source": {
            "commit": _git("rev-parse", "HEAD"),
            "dirty": bool(_git("status", "--porcelain")),
            "requirements_lock_sha256": _sha256_file(lock_path) if lock_path.is_file() else None,
        },
        "image": inspect_image(image),
        "runtime": {"python": runtime["python"]},
        "packages": runtime["packages"],
        "totals": {"packages": len(runtime["packages"])},
    }
    if not deterministic:
        manifest["generated_at"] = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
    return manifest


def _slug(image: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", image.replace(":", "_").replace("/", "_"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="aegisgraph:local", help="image reference to inventory")
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="manifest path (default: artifacts/sbom/<image>-sbom.json)",
    )
    parser.add_argument(
        "--deterministic",
        action="store_true",
        help="omit the generation timestamp for byte-reproducible output",
    )
    arguments = parser.parse_args()

    output = arguments.output or Path("artifacts") / "sbom" / f"{_slug(arguments.image)}-sbom.json"
    if not output.is_absolute():
        output = REPO_ROOT / output
    output.parent.mkdir(parents=True, exist_ok=True)

    manifest = build_manifest(arguments.image, deterministic=arguments.deterministic)
    payload = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    output.write_text(payload, encoding="utf-8", newline="\n")

    requirements_path = output.with_suffix(".requirements.txt")
    requirements_path.write_text(
        "".join(f"{package['name']}=={package['version']}\n" for package in manifest["packages"]),
        encoding="utf-8",
        newline="\n",
    )

    print(f"manifest:     {output.relative_to(REPO_ROOT)}")
    print(f"sha256:       {hashlib.sha256(payload.encode('utf-8')).hexdigest()}")
    print(f"inventory:    {requirements_path.relative_to(REPO_ROOT)}")
    print(f"sha256:       {_sha256_file(requirements_path)}")
    print(f"packages:     {manifest['totals']['packages']}")
    print(f"image id:     {manifest['image']['id']}")
    print(f"python:       {manifest['runtime']['python']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
