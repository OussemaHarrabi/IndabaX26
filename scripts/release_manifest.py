#!/usr/bin/env python3
"""Deterministic release provenance manifest generator (milestone M8).

The manifest lists every release-critical artifact with its SHA-256 under two
conventions, because this repository learned the difference the hard way:

* ``sha256_raw`` -- the bytes exactly as they exist on disk in this checkout;
* ``sha256_lf``  -- the same bytes with CRLF normalised to LF (the repository's
  ``content-sha256-lf`` convention, see ``benchmark/runner.py``).

A file written through Python's text mode carries CRLF on Windows while the
committed blob may carry LF, so a sidecar computed under one convention can
disagree with the bytes the other convention reads.  The M3 load review recorded
exactly that (ledger rows P75/P76) and ``docs/evidence/m6-freeze.md`` section 8
labels every hash with its convention.  This script labels all of them and also
records the SHA-256 of the committed git blob, so a reviewer knows which value
``git show <commit>:<path> | sha256sum`` has to reproduce.

Determinism and hygiene: no network access; no timestamp is part of any digest
(the single generation timestamp lives in the ``generation`` block and nothing
hashes it); the container image digest and the frozen campaign identity are
*read* from committed artifacts, never recomputed by hand.  The one value the
script does recompute is the 60-file dataset aggregate, and it fails loudly if
that disagrees with the campaign's recorded ``dataset.sha256``.

Failure behaviour: the script exits non-zero and writes nothing if any declared
artifact is absent from the working tree or from the requested revision, so a
release cannot be tagged from an incomplete tree.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn

REPO_ROOT = Path(__file__).resolve().parents[1]
GENERATOR = "scripts/release_manifest.py"
GENERATOR_VERSION = "1.0.0"
MANIFEST_SCHEMA = "aegisgraph-release-manifest/v1"

CAMPAIGN_RUN = "benchmark/runs/20261008T203656Z-m6-campaign"
CAMPAIGN_MANIFEST = f"{CAMPAIGN_RUN}/manifest.json"
CAMPAIGN_SCORE = f"{CAMPAIGN_RUN}/score.json"
SBOM_PATH = "deploy/sbom/aegisgraph-image-sbom.json"
DATASET_DIR = "benchmark/data/scenarios"
DATASET_BASE = "benchmark/data"

CONVENTION_RAW = "sha256 of the bytes exactly as they exist on disk in this checkout"
CONVENTION_LF = "sha256 of the same bytes with CRLF normalised to LF (content-sha256-lf)"
CONVENTION_BLOB = "sha256 of the bytes git stores for that path at the release commit"
CONVENTION_DATASET = (
    "sha256 over path-sorted (relative_path NUL per-file-sha256 LF) pairs, "
    "as benchmark/dataset.py computes dataset.sha256"
)
DATASET_NOTE = (
    "the 60 native scenario files whose per-file hashes the campaign's dataset.sha256 aggregates"
)

#: Manifest generations that have been superseded by a later regeneration.  Kept
#: in the script rather than passed on the command line, so the documented
#: regeneration command stays a single line and the history stays visible to a
#: reader who saw the earlier commit instead of being silently overwritten.
SUPERSEDED_GENERATIONS: tuple[dict[str, Any], ...] = (
    {
        "commit": "e4a43164fb9ef14c781739d8d836137218440488",
        "mismatches": 8,
        "reason": (
            "first generation, at the integration tip before the review-closure, corrected-figure "
            "and release merges; four listed documents changed afterwards, so --verify reported 8 "
            "digest mismatches (4 paths x 2 conventions) against it"
        ),
    },
)

#: The declared release artifact list: ``(path, kind, note)``.  Order is the
#: published order; every path is checked for presence in the working tree *and*
#: in the requested revision.
ARTIFACTS: tuple[tuple[str, str, str], ...] = (
    (
        f"{CAMPAIGN_RUN}/manifest.json",
        "campaign-run",
        "frozen run identity: commit, dataset, policy, model, seed, per-file hashes",
    ),
    (
        f"{CAMPAIGN_RUN}/outcomes.jsonl",
        "campaign-run",
        "one decision record per scenario step of the C1 run, the scorecard's source",
    ),
    (
        f"{CAMPAIGN_RUN}/control.jsonl",
        "campaign-run",
        "the allow-all reachability control (C2) that licenses which attacks count",
    ),
    (
        f"{CAMPAIGN_RUN}/score.json",
        "campaign-run",
        "the C1 native scorecard carrying the deterministic digest b6951afb...",
    ),
    (
        f"{CAMPAIGN_RUN}/score.txt",
        "campaign-run",
        "rendered form of the same scorecard; written in text mode, so raw bytes are CRLF",
    ),
    (
        f"{CAMPAIGN_RUN}/README.md",
        "campaign-run",
        "the run directory's own account of how the C1/C2 artifacts were produced",
    ),
    (
        "evaluation/allow-all-mock.json",
        "legacy-scorecard",
        "legacy 40-scenario mock control (ASR 1.0) defining the reached-attack denominator",
    ),
    (
        "evaluation/provenance-mock.json",
        "legacy-scorecard",
        "legacy built-in provenance baseline row of the frozen mock ladder",
    ),
    (
        "evaluation/aegisgraph-mock.json",
        "legacy-scorecard",
        "final calibrated legacy mock scorecard (ASR 0, BTU 8/9, FBR 0.0683)",
    ),
    (
        "evaluation/real-qwen/allow-all-qwen3-8b.json",
        "legacy-scorecard",
        "Qwen3-8B allow-all control; its ASR 0.7097 over 31 attacks is the v5 22-attack basis",
    ),
    (
        "evaluation/real-qwen/aegisgraph-v3-qwen3-8b.json",
        "legacy-scorecard",
        "frozen v3 scorecard (ASR 0 of 31, BTU 4/9, FBR 0.0087, p95 8.355 ms), the ladder's step",
    ),
    (
        "evaluation/real-qwen/aegisgraph-v5-qwen3-8b.json",
        "legacy-scorecard",
        "frozen v5 scorecard (ASR 0 of 31, BTU 4/9, FBR 0.0086, p95 9.284 ms, eligible=false)",
    ),
    (
        "evaluation/m6-recheck/aegisgraph-mock-m6-818cf1f.json",
        "campaign-run",
        "campaign cell C3: legacy mock re-check at the freeze gateway commit, digest 8669aadb...",
    ),
    (
        "docs/evidence/performance/m3-load-20261008T210436Z.json",
        "load-report",
        "corrected M3 load baseline: warm-up excluded from the service-side block",
    ),
    (
        "docs/evidence/performance/m3-load-20261008T210436Z.sha256",
        "load-report",
        "the report's own sidecar, byte-exact under the corrected harness",
    ),
    (
        SBOM_PATH,
        "sbom",
        "image inventory (39 packages) plus the one committed container image digest",
    ),
    (
        "deploy/sbom/aegisgraph-image-sbom.requirements.txt",
        "sbom",
        "the pinned inventory the SBOM came from, drift-checked against requirements.lock",
    ),
    (
        "requirements.lock",
        "dependency-lock",
        "the 39-entry dependency lock pinned by digest in the campaign manifest and SBOM",
    ),
    (
        "benchmark/scoring.py",
        "campaign-identity-source",
        "scoring source pinned by the campaign identity; defines the digest and metrics",
    ),
    (
        "benchmark/schema.py",
        "schema",
        "the authoritative native evaluation schema the campaign artifacts validate against",
    ),
    (
        "benchmark/runner.py",
        "campaign-identity-source",
        "campaign runner pinned by the identity; carries the repository's hash conventions",
    ),
    (
        "docs/research/analysis.py",
        "campaign-identity-source",
        "preregistered paired re-analysis pinned by the campaign identity",
    ),
    (
        "backend/aegisgraph/policy.py",
        "campaign-identity-source",
        "policy source blob pinned by the campaign identity",
    ),
    (
        "backend/aegisgraph/engine.py",
        "campaign-identity-source",
        "decision-kernel source blob pinned by the campaign identity",
    ),
    (
        "backend/aegisgraph/adapter.py",
        "campaign-identity-source",
        "request-adapter source blob pinned by the campaign identity",
    ),
    (
        "backend/aegisgraph/contracts.py",
        "schema",
        "shared canonical contract, the roadmap's highest-blast-radius single-writer file",
    ),
    (
        "docs/api/decision.schema.json",
        "schema",
        "published JSON schema of the generic decision response",
    ),
    (
        "docs/architecture/roadmap.md",
        "doc",
        "authoritative M0-M8 milestone map and the blocked-by-tooling ledger",
    ),
    (
        "docs/evidence/ledger.md",
        "doc",
        "claim-to-evidence map: artifact, digest, command and commit per claim",
    ),
    (
        "docs/evidence/m6-freeze.md",
        "doc",
        "the freeze contract (section 7) and results (section 8), with hash conventions",
    ),
    (
        "docs/evidence/m6-campaign.md",
        "doc",
        "the campaign report: identity, C1-C4, the null delta and the blocked cells",
    ),
    (
        "docs/research/report.md",
        "doc",
        "the research report stating the headline numbers in the permitted claim register",
    ),
    (
        "docs/evidence/reviews/M0-adversarial-security-review.json",
        "review",
        "M0 independent adversarial review (F1-F10), the origin of the findings register",
    ),
    (
        "docs/evidence/reviews/M0-M5-research-reproducibility-audit.json",
        "review",
        "independent read-only research and reproducibility audit of the legacy chain",
    ),
    (
        "docs/evidence/reviews/M1-M5-adversarial-security-review.json",
        "review",
        "M1-M5 adversarial security review (the H2-xx findings)",
    ),
    (
        "docs/evidence/reviews/M2-surface-adversarial-security-review.json",
        "review",
        "M2-surface adversarial review (H3-01 to H3-09), which re-opened F3's relabelling move",
    ),
    (
        "docs/evidence/reviews/M3-telemetry-load-adversarial-review.json",
        "review",
        "M3 telemetry/load adversarial review (H4-01 to H4-10), source of the pending load rows",
    ),
    (
        "docs/evidence/reviews/M6-campaign-reproducibility-audit.json",
        "review",
        "independent M6 campaign audit (I3-01 to I3-06) that reproduced C1-C4",
    ),
    (DATASET_DIR, "dataset", DATASET_NOTE),
)


def fail(message: str) -> NoReturn:
    """Print an error and exit non-zero without writing anything."""

    print(f"release_manifest: FAIL: {message}", file=sys.stderr)
    raise SystemExit(2)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalise_lf(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")


def git(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, check=False)


def resolve_commit(ref: str) -> str:
    proc = git("rev-parse", "--verify", f"{ref}^{{commit}}")
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        fail(f"revision {ref!r} cannot be resolved to a commit: {stderr}")
    return proc.stdout.decode("utf-8").strip()


def commit_blob(commit: str, path: str) -> bytes | None:
    proc = git("show", f"{commit}:{path}")
    return None if proc.returncode != 0 else proc.stdout


def read_json(relative_path: str) -> Any:
    try:
        return json.loads((REPO_ROOT / relative_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read {relative_path}: {exc}")


def pick(source: Any, key_path: str, origin: str) -> Any:
    """Copy a value out of a committed artifact, failing loudly when it moved."""

    node = source
    for part in key_path.split("."):
        if not isinstance(node, dict) or part not in node:
            fail(f"{origin} no longer carries the key {key_path!r} (at {part!r})")
        node = node[part]
    return node


def aggregate_members(base: Path, members: list[Path], *, normalise: bool) -> str:
    """Reproduce ``benchmark/dataset.py``'s dataset digest over the member files."""

    digest = hashlib.sha256()
    for member in members:
        raw = member.read_bytes()
        payload = normalise_lf(raw) if normalise else raw
        digest.update(member.relative_to(base).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256_hex(payload).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def file_entry(
    commit: str, path: str, kind: str, note: str, problems: list[str]
) -> dict[str, Any] | None:
    target = REPO_ROOT / path
    if not target.is_file():
        problems.append(f"{path}: absent from the working tree")
        return None
    blob = commit_blob(commit, path)
    if blob is None:
        problems.append(f"{path}: absent from revision {commit[:12]}")
        return None
    raw = target.read_bytes()
    raw_hash = sha256_hex(raw)
    lf_hash = sha256_hex(normalise_lf(raw))
    blob_hash = sha256_hex(blob)
    if blob_hash == raw_hash:
        blob_matches = "raw"
    elif blob_hash == lf_hash:
        blob_matches = "lf"
    else:
        blob_matches = "neither"
    return {
        "path": path,
        "kind": kind,
        "note": note,
        "bytes": len(raw),
        "sha256_raw": raw_hash,
        "sha256_lf": lf_hash,
        "sha256_blob": blob_hash,
        "blob_matches": blob_matches,
    }


def dataset_entry(commit: str, problems: list[str]) -> dict[str, Any] | None:
    base = REPO_ROOT / DATASET_BASE
    members = sorted(base.glob("scenarios/**/*.json"))
    if not members:
        problems.append(f"{DATASET_DIR}: no scenario files found")
        return None
    ls_tree = git("ls-tree", "-r", "--name-only", commit, "--", DATASET_DIR)
    committed = [line for line in ls_tree.stdout.decode("utf-8").splitlines() if line.strip()]
    if ls_tree.returncode != 0 or len(committed) != len(members):
        problems.append(
            f"{DATASET_DIR}: {len(members)} files on disk but {len(committed)} in "
            f"revision {commit[:12]}"
        )
        return None
    aggregate_raw = aggregate_members(base, members, normalise=False)
    aggregate_lf = aggregate_members(base, members, normalise=True)
    recorded = pick(read_json(CAMPAIGN_MANIFEST), "dataset.sha256", CAMPAIGN_MANIFEST)
    if aggregate_raw != recorded:
        problems.append(
            f"{DATASET_DIR}: raw aggregate {aggregate_raw} does not match the campaign's "
            f"recorded dataset.sha256 {recorded}"
        )
        return None
    return {
        "path": DATASET_DIR,
        "kind": "dataset",
        "note": DATASET_NOTE,
        "members": len(members),
        "bytes": sum(member.stat().st_size for member in members),
        "sha256_raw": aggregate_raw,
        "sha256_lf": aggregate_lf,
        "aggregate_convention": CONVENTION_DATASET,
        "matches_campaign_dataset_sha256": True,
    }


def frozen_identity() -> dict[str, Any]:
    manifest = read_json(CAMPAIGN_MANIFEST)
    score = read_json(CAMPAIGN_SCORE)
    campaign = {
        "run_name": pick(manifest, "run.name", CAMPAIGN_MANIFEST),
        "run_created": pick(manifest, "run.created", CAMPAIGN_MANIFEST),
        "schema_version": pick(manifest, "schema_version", CAMPAIGN_MANIFEST),
        "code": pick(manifest, "code", CAMPAIGN_MANIFEST),
        "dataset_sha256": pick(manifest, "dataset.sha256", CAMPAIGN_MANIFEST),
        "dataset_scenario_count": pick(manifest, "dataset.scenario_count", CAMPAIGN_MANIFEST),
        "scenario_set_sha256": pick(manifest, "scenario_set.sha256", CAMPAIGN_MANIFEST),
        "splits": pick(manifest, "scenario_set.splits", CAMPAIGN_MANIFEST),
        "policy_set": pick(manifest, "policy_set", CAMPAIGN_MANIFEST),
        "policy_blob_sha256": pick(manifest, "policy.blob_sha256", CAMPAIGN_MANIFEST),
        "policy_set_count": pick(manifest, "policy.policy_set_count", CAMPAIGN_MANIFEST),
        "policy_source_blobs": pick(manifest, "policy.source_blobs.blobs", CAMPAIGN_MANIFEST),
        "model_kind": pick(manifest, "model.kind", CAMPAIGN_MANIFEST),
        "model_name": pick(manifest, "model.name", CAMPAIGN_MANIFEST),
        "seed": pick(manifest, "seed", CAMPAIGN_MANIFEST),
        "temperature": pick(manifest, "temperature", CAMPAIGN_MANIFEST),
        "max_tokens": pick(manifest, "max_tokens", CAMPAIGN_MANIFEST),
        "dependency_lock": pick(manifest, "dependency_lock", CAMPAIGN_MANIFEST),
        "artifact_hashes": pick(manifest, "artifacts", CAMPAIGN_MANIFEST),
        "limitations": pick(manifest, "limitations", CAMPAIGN_MANIFEST),
    }
    overall = pick(score, "overall", CAMPAIGN_SCORE)
    score_block = {
        "deterministic_digest": pick(score, "deterministic_digest", CAMPAIGN_SCORE),
        "outcome_count": pick(score, "outcome_count", CAMPAIGN_SCORE),
        "min_slice": pick(score, "min_slice", CAMPAIGN_SCORE),
        "overall": {
            key: overall[key]
            for key in (
                "scenario_count",
                "attack_count",
                "reached_attacks",
                "attack_successes",
                "asr",
                "asr_excluding_errors",
                "benign_count",
                "benign_successes",
                "benign_task_success",
                "false_block_rate",
                "false_block_rate_scenarios",
                "escalation_rate",
                "defense_errors",
                "errored_attacks",
                "control_licensed",
                "control_excluded",
                "effectiveness_claim",
                "decisions",
                "legitimate_actions",
                "legitimate_blocked",
                "rewrites",
            )
        },
    }
    return {
        "source_artifacts": [CAMPAIGN_MANIFEST, CAMPAIGN_SCORE],
        "source_note": "copied verbatim from the committed run artifacts, never recomputed here",
        "campaign": campaign,
        "score": score_block,
    }


def container_image() -> dict[str, Any]:
    sbom = read_json(SBOM_PATH)
    repo_digests = pick(sbom, "image.repo_digests", SBOM_PATH)
    return {
        "source_artifact": SBOM_PATH,
        "image_id": pick(sbom, "image.id", SBOM_PATH),
        "repository_digest": repo_digests[0] if repo_digests else None,
        "size_bytes": pick(sbom, "image.size_bytes", SBOM_PATH),
        "user": pick(sbom, "image.user", SBOM_PATH),
        "runtime_python": pick(sbom, "runtime.python", SBOM_PATH),
        "package_count": pick(sbom, "totals.packages", SBOM_PATH),
        "built_from_commit": pick(sbom, "source.commit", SBOM_PATH),
        "requirements_lock_sha256": pick(sbom, "source.requirements_lock_sha256", SBOM_PATH),
        "note": (
            "digest copied from the committed SBOM; the image was built at the SBOM's source "
            "commit, not rebuilt for this release"
        ),
    }


def checkout_context() -> dict[str, Any]:
    """Record the line-ending configuration that produced ``sha256_raw``."""

    autocrlf = git("config", "--get", "core.autocrlf").stdout.decode("utf-8").strip()
    git_version = git("--version").stdout.decode("utf-8").strip()
    return {
        "core_autocrlf": autocrlf or None,
        "git_version": git_version,
        "note": (
            "sha256_raw is taken from the bytes on disk in this checkout; with core.autocrlf=true "
            "that is the CRLF form for git-text files, while sha256_lf and sha256_blob keep the "
            "portable value (see each entry's blob_matches)"
        ),
    }


def build_manifest(commit_ref: str, tag: str, version: str) -> dict[str, Any]:
    commit = resolve_commit(commit_ref)
    problems: list[str] = []
    entries: list[dict[str, Any]] = []
    for path, kind, note in ARTIFACTS:
        entry = (
            dataset_entry(commit, problems)
            if kind == "dataset"
            else file_entry(commit, path, kind, note, problems)
        )
        if entry is not None:
            entries.append(entry)
    if problems:
        fail(
            f"{len(problems)} declared artifact(s) failed at {commit}:\n    "
            + "\n    ".join(problems)
        )
    branch = git("rev-parse", "--abbrev-ref", "HEAD").stdout.decode("utf-8").strip()
    return {
        "schema": MANIFEST_SCHEMA,
        "generator": GENERATOR,
        "generator_version": GENERATOR_VERSION,
        "generation": {
            "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "digest_bound": False,
            "note": "the generation time is not part of any digest and nothing here hashes it",
            "superseded": [dict(record) for record in SUPERSEDED_GENERATIONS],
        },
        "release": {
            "tag": tag,
            "version": version,
            "commit": commit,
            "commit_input": commit_ref,
            "branch": branch,
            "self_reference": (
                "the digests describe the tree of release.commit; this manifest is added in that "
                "commit's child, which the tag points at, and --verify re-hashes the listed "
                "artifacts only, because a manifest cannot hash itself"
            ),
        },
        "hash_conventions": {
            "sha256_raw": CONVENTION_RAW,
            "sha256_lf": CONVENTION_LF,
            "sha256_blob": CONVENTION_BLOB,
            "blob_matches": (
                "which of sha256_raw / sha256_lf the committed git blob equals; 'neither' means "
                "the working copy is dirty relative to the release commit"
            ),
            "dataset_aggregate": CONVENTION_DATASET,
        },
        "checkout": checkout_context(),
        "artifact_summary": {
            "total": len(entries),
            "kinds": {
                kind: sum(1 for entry in entries if entry["kind"] == kind)
                for kind in sorted({entry["kind"] for entry in entries})
            },
            "blob_matches_raw": sum(1 for e in entries if e.get("blob_matches") == "raw"),
            "blob_matches_lf": sum(1 for e in entries if e.get("blob_matches") == "lf"),
            "blob_matches_neither": sum(1 for e in entries if e.get("blob_matches") == "neither"),
        },
        "artifacts": entries,
        "frozen_identity": frozen_identity(),
        "container_image": container_image(),
        "verification": {
            "regenerate_manifest": (
                f"python {GENERATOR} --commit <commit> --tag <tag> "
                "--out docs/evidence/release-manifest.json"
            ),
            "rehash_every_entry": (
                f"python {GENERATOR} --verify docs/evidence/release-manifest.json"
            ),
            "single_file_raw": "sha256sum <path>   # must equal the entry's sha256_raw",
            "single_file_committed_blob": (
                "git show <commit>:<path> | sha256sum   # must equal sha256_blob "
                "(and sha256_raw whenever blob_matches is 'raw')"
            ),
            "single_file_lf": (
                "git show <commit>:<path> | tr -d '\\r' | sha256sum   # must equal sha256_lf"
            ),
            "note": (
                "every entry names the convention that produced each value; a Windows checkout "
                "with CRLF files must compare sha256_raw to the on-disk bytes and sha256_lf to "
                "the LF-normalised bytes, never the other way round"
            ),
        },
    }


def verify(manifest_path: Path) -> int:
    """Recompute every recorded digest from the working tree; non-zero on drift."""

    if not manifest_path.is_file():
        fail(f"manifest {manifest_path} does not exist")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    failures = 0
    checked = 0
    for entry in manifest["artifacts"]:
        path = entry["path"]
        if entry["kind"] == "dataset":
            base = REPO_ROOT / DATASET_BASE
            members = sorted(base.glob("scenarios/**/*.json"))
            raw_hash = aggregate_members(base, members, normalise=False)
            lf_hash = aggregate_members(base, members, normalise=True)
        else:
            target = REPO_ROOT / path
            if not target.is_file():
                print(f"FAIL {path}: missing from the working tree", file=sys.stderr)
                failures += 1
                continue
            raw = target.read_bytes()
            raw_hash = sha256_hex(raw)
            lf_hash = sha256_hex(normalise_lf(raw))
        checked += 1
        for field, recomputed in (("sha256_raw", raw_hash), ("sha256_lf", lf_hash)):
            if entry.get(field) != recomputed:
                print(
                    f"FAIL {path}: {field} {entry.get(field)} != {recomputed}",
                    file=sys.stderr,
                )
                failures += 1
    if failures:
        print(f"release_manifest: FAIL: {failures} digest mismatch(es)", file=sys.stderr)
        return 1
    print(f"release_manifest: OK: {checked} entries re-hashed, all digests match")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--commit", default="HEAD", help="revision to tag (default: HEAD)")
    parser.add_argument("--tag", help="release tag name, e.g. v0.1.0-industrial")
    parser.add_argument("--version", help="release version string (default: the tag)")
    parser.add_argument("--out", help="path of the JSON manifest to write")
    parser.add_argument(
        "--verify",
        metavar="MANIFEST",
        help="re-hash every entry of an existing manifest; exit non-zero on drift",
    )
    args = parser.parse_args(argv)

    if args.verify:
        return verify(Path(args.verify))
    if not args.tag or not args.out:
        parser.error("--tag and --out are required unless --verify is used")

    manifest = build_manifest(args.commit, args.tag, args.version or args.tag)
    destination = Path(args.out)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    destination.write_bytes(payload.encode("utf-8"))
    release = manifest["release"]
    print(
        f"release_manifest: wrote {destination} for {release['tag']} at "
        f"{release['commit'][:12]} ({len(manifest['artifacts'])} artifacts)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
