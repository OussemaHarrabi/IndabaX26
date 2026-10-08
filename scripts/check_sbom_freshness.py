"""Fail loudly when the committed SBOM describes a different dependency lock.

The SBOM records `source.requirements_lock_sha256`, the **git blob** (LF) content
hash of `requirements.lock` at the revision the image was built from. When the
lock changes — a milestone adds dependencies, a pin moves — that recorded value
silently becomes a claim about a file that no longer exists. This check recomputes
the lock's content hash and the number of pinned entries and compares both with
the committed manifest.

Exit status:
    0  the SBOM matches the current lock
    1  it does not (with the exact expected/actual values printed)

The recorded `source.commit` is checked too, but *as an ancestry check*: the
manifest is necessarily committed one revision after the inputs it describes, so
a recorded commit that is an ancestor of HEAD is correct, and a recorded commit
that is not in HEAD's history at all is a hard failure.

Usage:
    python scripts/check_sbom_freshness.py
    python scripts/check_sbom_freshness.py --sbom deploy/sbom/other.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SBOM = REPO_ROOT / "deploy" / "sbom" / "aegisgraph-image-sbom.json"
LOCK_RELATIVE_PATH = "requirements.lock"


def _git(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, check=False)


def lock_content_sha256() -> str:
    """Hash the lock as committed (LF bytes), falling back to an LF-normalized read."""

    blob = _git("show", f"HEAD:{LOCK_RELATIVE_PATH}")
    if blob.returncode == 0:
        return hashlib.sha256(blob.stdout).hexdigest()
    text = (REPO_ROOT / LOCK_RELATIVE_PATH).read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(text).hexdigest()


def lock_entry_count() -> int:
    """Count pinned entries: non-empty lines that are neither blank nor comments."""

    blob = _git("show", f"HEAD:{LOCK_RELATIVE_PATH}")
    if blob.returncode != 0:
        return 0
    lines = blob.stdout.decode("utf-8").splitlines()
    return sum(1 for line in lines if line.strip() and not line.lstrip().startswith("#"))


def head_commit() -> str:
    result = _git("rev-parse", "HEAD")
    return result.stdout.decode().strip() if result.returncode == 0 else "unknown"


def is_ancestor(commit: str) -> bool | None:
    """True/False for a commit present locally; None when the object is absent.

    A shallow clone (`actions/checkout` defaults to depth 1) does not contain the
    manifest's recorded commit, so "unknown" must not be reported as a failure.
    """

    if _git("cat-file", "-e", f"{commit}^{{commit}}").returncode != 0:
        return None
    return _git("merge-base", "--is-ancestor", commit, "HEAD").returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom", type=Path, default=DEFAULT_SBOM)
    arguments = parser.parse_args()

    sbom_path = arguments.sbom if arguments.sbom.is_absolute() else REPO_ROOT / arguments.sbom
    if not sbom_path.is_file():
        print(f"FAIL: SBOM manifest not found: {sbom_path}", file=sys.stderr)
        return 1

    manifest = json.loads(sbom_path.read_text(encoding="utf-8"))
    source = manifest.get("source", {})
    recorded_lock = source.get("requirements_lock_sha256")
    recorded_commit = source.get("commit", "unknown")
    recorded_packages = manifest.get("totals", {}).get("packages")

    actual_lock = lock_content_sha256()
    actual_entries = lock_entry_count()
    current = head_commit()

    failures: list[str] = []
    if recorded_lock != actual_lock:
        failures.append(
            f"{LOCK_RELATIVE_PATH} content hash drifted: "
            f"SBOM records {recorded_lock}, HEAD is {actual_lock}"
        )
    if recorded_packages != actual_entries:
        failures.append(
            f"pinned entry count drifted: SBOM records {recorded_packages}, "
            f"HEAD has {actual_entries}"
        )
    if recorded_commit != "unknown":
        ancestry = is_ancestor(recorded_commit)
        if ancestry is None:
            print(
                f"[NOTE] recorded source.commit {recorded_commit[:12]} is not present "
                "locally (shallow clone?); ancestry not checked. The lock comparison "
                "above is unaffected."
            )
        elif not ancestry:
            failures.append(
                f"recorded source.commit {recorded_commit[:12]} is not an ancestor of HEAD "
                f"({current[:12]}); the manifest describes a revision this tree does not contain"
            )

    print(f"sbom:              {sbom_path.relative_to(REPO_ROOT)}")
    print(f"lock (HEAD):       {actual_lock}  ({actual_entries} pinned entries)")
    print(f"lock (in SBOM):    {recorded_lock}  ({recorded_packages} entries)")
    print(f"HEAD:              {current[:12]}")
    print(f"source.commit:     {recorded_commit[:12]}")

    if failures:
        print(
            "\nFAIL: the committed SBOM is stale; regenerate it at this revision:",
            file=sys.stderr,
        )
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        print(
            "\n  python scripts/generate_sbom.py --image <image> --deterministic \\\n"
            "      --output deploy/sbom/aegisgraph-image-sbom.json",
            file=sys.stderr,
        )
        return 1

    print("\nPASS: the SBOM matches the lock at HEAD.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
