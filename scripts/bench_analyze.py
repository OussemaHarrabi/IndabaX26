#!/usr/bin/env python3
"""Analyse a completed native benchmark campaign into the published numbers.

Read-only over the run directories it is given: it verifies each run's hashes,
reproduces the committed ``score.json`` from the raw outcomes, and writes the
preregistered paired statistics (with honest uncertainty) into an output
directory as ``statistics.json``, Markdown/CSV tables and — when a plotting
library is importable — PNG plots.

The analysis rules are the ones fixed in ``docs/research/statistics.md`` and
``docs/research/research-plan.md``; a run that fails to reproduce is reported and
never silently dropped (and the command exits non-zero).

Examples
--------
    python scripts/bench_analyze.py \\
      --run benchmark/runs/20261008T203656Z-m6-campaign --out /tmp/analysis

    python scripts/bench_analyze.py \\
      --run benchmark/runs/<defence> --control benchmark/runs/<allow-all> \\
      --out /tmp/analysis --group-by domain,family
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from benchmark.analysis import (  # noqa: E402
    BOOTSTRAP_REPLICATES,
    BOOTSTRAP_SEED,
    AnalysisError,
    analyse_campaign,
    write_analysis_outputs,
)

_GROUPINGS = {"domain": "domain", "family": "attack_family", "attack_family": "attack_family"}


def _group_by(spec: str, parser: argparse.ArgumentParser) -> tuple[str, ...]:
    selected: list[str] = []
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if token not in _GROUPINGS:
            parser.error(f"unknown grouping {token!r}; choose from domain, family")
        field = _GROUPINGS[token]
        if field not in selected:
            selected.append(field)
    return tuple(selected or ("domain", "attack_family"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run",
        action="append",
        required=True,
        metavar="DIR",
        help="a defence run directory (repeatable)",
    )
    parser.add_argument(
        "--control",
        action="append",
        default=None,
        metavar="DIR",
        help="a control run directory (repeatable: one shared by every --run, or one per --run)",
    )
    parser.add_argument(
        "--baseline", default=None, metavar="DIR", help="the same-suite baseline run for H1.1b"
    )
    parser.add_argument("--out", required=True, metavar="DIR", help="output directory")
    parser.add_argument(
        "--force", action="store_true", help="overwrite an existing, non-empty output directory"
    )
    parser.add_argument(
        "--min-slice", type=int, default=None, help="override the reportability floor"
    )
    parser.add_argument(
        "--bootstrap", type=int, default=BOOTSTRAP_REPLICATES, help="paired bootstrap replicates"
    )
    parser.add_argument("--bootstrap-seed", type=int, default=BOOTSTRAP_SEED)
    parser.add_argument(
        "--group-by",
        default="domain,family",
        help="comma-separated slice groupings (domain, family)",
    )
    parser.add_argument(
        "--exploratory",
        action="store_true",
        help="RQ2 ablation invocation: Benjamini-Hochberg at q = 0.05, labelled exploratory",
    )
    parser.add_argument("--json", action="store_true", help="also print statistics.json to stdout")
    args = parser.parse_args(argv)

    try:
        result = analyse_campaign(
            [Path(item) for item in args.run],
            control_dirs=[Path(item) for item in (args.control or [])] or None,
            baseline=Path(args.baseline) if args.baseline else None,
            group_by=_group_by(args.group_by, parser),
            min_slice=args.min_slice,
            bootstrap_replicates=args.bootstrap,
            bootstrap_seed=args.bootstrap_seed,
            exploratory=args.exploratory,
        )
        written = write_analysis_outputs(result, args.out, force=args.force)
    except AnalysisError as error:
        print(f"analysis failed: {error}", file=sys.stderr)
        return 1

    for row in result["accounting"]["runs"]:
        if row["status"] == "analysed":
            print(
                f"verified + reproduced: {row['name']} (role {row['role']}, "
                f"hashes from {row['hash_source']}, {len(row['verified_files'])} file(s))"
            )
        else:
            print(f"FAILED: {row['name']} (role {row['role']}): {row['error']}", file=sys.stderr)

    for comparison in result["comparisons"]:
        test = comparison["test"]
        print(
            "{name}: reached {n} | control {cs}/{n} -> treatment {ts}/{n} | reduction {rd} | "
            "b/c {b}/{c} | exact p {p} | adj p {pa} (m={m})".format(
                name=comparison["treatment"],
                n=comparison["reached_n"],
                cs=comparison["paired"]["control_success"],
                ts=comparison["paired"]["treatment_success"],
                rd="n/a"
                if comparison["reduction_absolute"] is None
                else f"{comparison['reduction_absolute']:+.4f}",
                b=test["b_control_only_stopped"],
                c=test["c_treatment_only_new_success"],
                p="n/a" if test["exact_p"] is None else f"{test['exact_p']:.3g}",
                pa="n/a" if test["adjusted_p"] is None else f"{test['adjusted_p']:.3g}",
                m=test["m"] if test["m"] is not None else "n/a",
            )
        )

    print(f"statistics digest: {result['digest']}")
    print(f"wrote {len(written)} file(s) into {args.out}")
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["accounting"]["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
