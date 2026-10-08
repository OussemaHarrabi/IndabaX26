"""Install a pinned ``kubeconform`` binary, verifying its SHA-256.

``kubeconform`` is an optional second schema validator: the primary validator is
the ``kubernetes-validate`` Python package (pip-installable, fully offline) used
by ``scripts/validate_k8s_manifests.py``. This installer exists so the second
validator is reproducible instead of "some binary that happened to be on PATH".

The version and every asset checksum are pinned. The checksums are the vendor's
own, published at
``https://github.com/yannh/kubeconform/releases/download/<version>/CHECKSUMS``
(that file's SHA-256 for v0.7.0 is
``3b8bfbac6e662823a51292368b0c25bc04001a32b006f04aafdf348c091d243f``). A download
whose SHA-256 does not match the pinned value is rejected and nothing is written.

Usage:
    python scripts/install_kubeconform.py                 # -> artifacts/tools/
    python scripts/install_kubeconform.py --dest /tmp/bin
    python scripts/install_kubeconform.py --print-path    # for scripting
"""

from __future__ import annotations

import argparse
import hashlib
import io
import platform
import stat
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

VERSION = "0.7.0"
BASE_URL = f"https://github.com/yannh/kubeconform/releases/download/v{VERSION}"
# Vendor CHECKSUMS for v0.7.0, keyed by "<os>-<arch><ext>"; the asset name is
# f"kubeconform-{key}". Source:
# https://github.com/yannh/kubeconform/releases/download/v0.7.0/CHECKSUMS
CHECKSUMS = {
    "darwin-amd64.tar.gz": "c6771cc894d82e1b12f35ee797dcda1f7da6a3787aa30902a15c264056dd40d4",
    "darwin-arm64.tar.gz": "b5d32b2cb77f9c781c976b20a85e2d0bc8f9184d5d1cfe665a2f31a19f99eeb9",
    "linux-386.tar.gz": "1b540677a77064aadae65099ac14030066d91a97b2f7bd381a955eedd636ac6b",
    "linux-amd64.tar.gz": "c31518ddd122663b3f3aa874cfe8178cb0988de944f29c74a0b9260920d115d3",
    "linux-arm64.tar.gz": "cc907ccf9e3c34523f0f32b69745265e0a6908ca85b92f41931d4537860eb83c",
    "linux-armv6.tar.gz": "c3a0fef861c774a5f5b2522db21ca7df9f5d4ed738cd849349d3e5545222f80e",
    "windows-386.zip": "3fc5f1fd4a8ac5d09cd75419727e0b02799687862c65e358fa62fb76fa287b85",
    "windows-amd64.zip": "9cb75551d81c909c2241ab383ced2be68363b5bfb15fd989badcc5a63bea5d7e",
    "windows-arm64.zip": "85c5b984950e2783cafac58cac432f35c5003d45ba1dee47d70f05e471960c55",
    "windows-armv6.zip": "fedcb2e911e1f796ef692d214ca4ce0bdb891b3c1ee2844ef552dd1b099bc5d2",
}

REPO_ROOT = Path(__file__).resolve().parents[1]


def asset_name() -> str:
    machine = platform.machine().lower()
    arch = {
        "amd64": "amd64",
        "x86_64": "amd64",
        "arm64": "arm64",
        "aarch64": "arm64",
        "x86": "386",
        "i386": "386",
        "i686": "386",
    }.get(machine, machine)
    if sys.platform == "win32":
        key = f"windows-{arch}.zip"
    elif sys.platform == "darwin":
        key = f"darwin-{arch}.tar.gz"
    else:
        key = f"linux-{arch}.tar.gz"
    return f"kubeconform-{key}"


def download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "aegisgraph-m4-installer"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def extract(payload: bytes, name: str, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    if name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            member = next(m for m in archive.namelist() if m.endswith("kubeconform.exe"))
            target = destination / "kubeconform.exe"
            target.write_bytes(archive.read(member))
    else:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            member = next(m for m in archive.getmembers() if m.name.endswith("kubeconform"))
            extracted = archive.extractfile(member)
            if extracted is None:
                raise SystemExit("archive member could not be read")
            target = destination / "kubeconform"
            target.write_bytes(extracted.read())
    target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dest",
        type=Path,
        default=REPO_ROOT / "artifacts" / "tools",
        help="directory the binary is written into (default: artifacts/tools)",
    )
    parser.add_argument(
        "--print-path",
        action="store_true",
        help="print only the installed binary path (for scripting)",
    )
    arguments = parser.parse_args()

    name = asset_name()
    key = name.removeprefix("kubeconform-")
    expected = CHECKSUMS.get(key)
    if expected is None:
        raise SystemExit(f"no pinned checksum for {name!r}; supported: {sorted(CHECKSUMS)}")

    url = f"{BASE_URL}/{name}"
    payload = download(url)
    actual = hashlib.sha256(payload).hexdigest()
    if actual != expected:
        raise SystemExit(
            f"checksum mismatch for {name}: expected {expected}, got {actual}. Nothing written."
        )

    destination = arguments.dest if arguments.dest.is_absolute() else REPO_ROOT / arguments.dest
    binary = extract(payload, name, destination)
    version = subprocess.run(
        [str(binary), "-v"], capture_output=True, text=True, check=False
    ).stdout.strip()

    if arguments.print_path:
        print(binary)
    else:
        print(f"asset:    {name}")
        print(f"url:      {url}")
        print(f"sha256:   {actual} (verified against the pinned vendor checksum)")
        print(f"binary:   {binary}")
        print(f"reported: {version or 'unknown'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
