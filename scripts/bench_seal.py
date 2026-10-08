#!/usr/bin/env python3
"""Seal, verify or open the native benchmark holdout.

The holdout is sealed so that the agents writing policy cannot read it before the
policy freeze. ``open`` is the exact command that lifts the seal, and it needs the
custodian passphrase that the orchestrator holds.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from benchmark.dataset import SEALED_FILE, DatasetError, load_dataset  # noqa: E402
from benchmark.schema import canonical_json, load_scenario_text  # noqa: E402
from benchmark.seal import (  # noqa: E402
    SealError,
    open_seal,
    read_manifest,
    seal_holdout,
    verify_seal,
)
from benchmark.splits import holdout_leakage_findings, published_id_namespace  # noqa: E402

DEFAULT_ROOT = REPO_ROOT / "benchmark" / "data"
PASSPHRASE_ENV = "AEGISGRAPH_HOLDOUT_PASSPHRASE"


def _passphrase(args: argparse.Namespace) -> str:
    if args.passphrase_file:
        return Path(args.passphrase_file).read_text(encoding="utf-8").strip()
    value = os.environ.get(PASSPHRASE_ENV)
    if not value:
        raise SealError(
            f"no passphrase: set {PASSPHRASE_ENV} or pass --passphrase-file; the passphrase is "
            "held by the orchestrator and is never committed"
        )
    return value


def _cmd_status(args: argparse.Namespace) -> int:
    try:
        manifest = read_manifest(args.root)
    except SealError as error:
        print(f"seal status: {error}")
        return 1
    print(canonical_json(manifest.to_json()), end="")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    passphrase = None
    if args.with_passphrase:
        passphrase = _passphrase(args)
    result = verify_seal(args.root, passphrase)
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["ciphertext_present"] or not result["ciphertext_matches"]:
        print("RESULT: FAIL (the sealed holdout does not match its manifest)")
        return 1
    if args.with_passphrase and not result["opened"]:
        print("RESULT: FAIL (the passphrase did not open the seal)")
        return 1
    print("RESULT: PASS")
    return 0


def _cmd_open(args: argparse.Namespace) -> int:
    scenarios = open_seal(_passphrase(args), args.root)
    print(f"opened {len(scenarios)} sealed scenarios")
    print(f"splits: {sorted({scenario.split.value for scenario in scenarios})}")
    print(f"families: {sorted({scenario.family_label for scenario in scenarios})}")
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        for scenario in scenarios:
            (out / f"{scenario.id}.json").write_text(
                canonical_json(scenario.model_dump(mode="json")), encoding="utf-8", newline="\n"
            )
        print(f"wrote plaintext to {out}")
    else:
        print("no --out given: nothing was written to disk")
    return 0


def _cmd_seal(args: argparse.Namespace) -> int:
    source = Path(args.from_dir)
    files = sorted(source.glob("*.json"))
    if not files:
        print(f"no plaintext holdout scenarios under {source}", file=sys.stderr)
        return 1
    scenarios = [load_scenario_text(path.read_text(encoding="utf-8")) for path in files]

    # A holdout that overlaps the plaintext dataset measures memorisation, so the
    # seal is gated on the leakage check. There is no override. The check covers
    # three namespaces: the native plaintext dataset, the legacy SENTINEL ids
    # published elsewhere in the tracked tree, and the payload templates of both.
    dataset = load_dataset(args.root)
    published = published_id_namespace(REPO_ROOT)
    leaks = holdout_leakage_findings(scenarios, dataset, published_ids=published)
    if leaks:
        print("refusing to seal: the candidate holdout leaks into the plaintext dataset")
        for finding in leaks:
            print("  " + finding.render())
        return 1

    manifest = seal_holdout(scenarios, _passphrase(args), args.root, note=args.note)
    print(canonical_json(manifest.to_json()), end="")
    print(f"sealed {manifest.scenario_count} scenarios into {Path(args.root) / SEALED_FILE}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(DEFAULT_ROOT), help="benchmark data root")
    sub = parser.add_subparsers(dest="command", required=True)

    status = sub.add_parser("status", help="print the hash-only seal manifest")
    status.set_defaults(func=_cmd_status)

    verify = sub.add_parser("verify", help="check the sealed bytes against the manifest")
    verify.add_argument("--with-passphrase", action="store_true")
    verify.add_argument("--passphrase-file", default=None)
    verify.set_defaults(func=_cmd_verify)

    open_cmd = sub.add_parser("open", help="decrypt the holdout (orchestrator only)")
    open_cmd.add_argument("--out", default=None, help="directory to write plaintext into")
    open_cmd.add_argument("--passphrase-file", default=None)
    open_cmd.set_defaults(func=_cmd_open)

    seal = sub.add_parser("seal", help="create the seal from a staging directory")
    seal.add_argument("--from-dir", required=True, help="directory of plaintext holdout JSON")
    seal.add_argument("--note", default="")
    seal.add_argument("--passphrase-file", default=None)
    seal.set_defaults(func=_cmd_seal)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (SealError, DatasetError) as error:
        print(f"seal error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
