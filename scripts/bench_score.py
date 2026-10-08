#!/usr/bin/env python3
"""Score a written run (or a pair of outcome files) into the native metric table."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from benchmark.runner import RunError, load_run  # noqa: E402
from benchmark.scoring import (  # noqa: E402
    IDENTITY_KEYS,
    Outcome,
    format_score_report,
    score,
)


def _read_jsonl(path: Path) -> list[Outcome]:
    outcomes: list[Outcome] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            outcomes.append(Outcome.from_json(json.loads(line)))
    return outcomes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--run", help="a run directory written by benchmark.runner")
    group.add_argument("--outcomes", help="a raw outcomes JSONL file")
    parser.add_argument("--control", default=None, help="control JSONL (with --outcomes)")
    parser.add_argument("--min-slice", type=int, default=None)
    parser.add_argument(
        "--json", action="store_true", help="print the JSON view instead of a table"
    )
    parser.add_argument("--out", default=None, help="write the JSON view to this path")
    args = parser.parse_args(argv)

    configuration: dict[str, object] = {}
    if args.run:
        try:
            manifest, outcomes, control = load_run(Path(args.run))
        except RunError as error:
            print(f"scoring failed: {error}", file=sys.stderr)
            return 1
        # The identity keys are the ones the digest covers: a different commit,
        # dataset, policy blob, model configuration or seed must not be able to
        # share a digest with this run.
        configuration = {
            "run": manifest.get("run", {}).get("name"),
            "code_commit": manifest.get("code", {}).get("commit"),
            "dataset_sha256": manifest.get("dataset", {}).get("sha256"),
            "scenario_set_sha256": manifest.get("scenario_set", {}).get("sha256"),
            "policy_blob_sha256": (manifest.get("policy") or {}).get("blob_sha256"),
            "policy_set": manifest.get("policy_set"),
            "model": manifest.get("model", {}).get("kind"),
            "seed": manifest.get("seed"),
            "temperature": manifest.get("temperature"),
            "max_tokens": manifest.get("max_tokens"),
            "splits": (manifest.get("scenario_set") or {}).get("splits"),
        }
    else:
        outcomes = _read_jsonl(Path(args.outcomes))
        control = _read_jsonl(Path(args.control)) if args.control else []
        # An attack-evidence-free table must not look like a result. Without the
        # control configuration the reached set is unknown, so ASR is undefined
        # for every attack and the table would print a clean-looking "n/a".
        if any(outcome.attack_present for outcome in outcomes) and not control:
            print(
                "refusing to score: the input contains attack outcomes but no --control "
                "file, so the reached set cannot be established and ASR would be "
                "undefined. Supply --control, or score a run directory with --run.",
                file=sys.stderr,
            )
            return 1

    kwargs: dict[str, object] = {
        "configuration": {key: configuration.get(key) for key in IDENTITY_KEYS}
        | {"run": configuration.get("run")}
    }
    if args.min_slice is not None:
        kwargs["min_slice"] = args.min_slice
    report = score(outcomes, control_outcomes=control, **kwargs)

    payload = report.to_json()
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", "utf-8")
        print(f"wrote {args.out}")
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(format_score_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
