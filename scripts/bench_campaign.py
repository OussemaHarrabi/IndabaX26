#!/usr/bin/env python3
"""Run the Qwen3-8B campaign: a stage, a condition and a seed, resumably.

This is the only campaign entry point a notebook calls. It imports the tested
modules — it reimplements no evaluation logic, and it never shells out to
``bench_run.py``. Publishing the policy sets the scenarios pin stays a separate,
auditable step (``scripts/bench_policies.py publish``), and scoring stays
``scripts/bench_score.py``.

Usage::

    # Stage A smoke, one seed, against a local gateway on loopback
    python scripts/bench_campaign.py --stage A --seed 1729 \\
      --defense-url http://127.0.0.1:8091 --runs-dir /content/runs \\
      --model qwen --adapter-json '{"revision": "<sha>", "quantization": "4bit"}'

    # See exactly what a command would run, touching nothing
    python scripts/bench_campaign.py --stage B --seed 1729 --seed 2741 --seed 3253 --dry-run

    # Resume an interrupted stage (skips verified checkpoints), then package it
    python scripts/bench_campaign.py --stage A --seed 1729 --resume --bundle ...

Exit codes: 0 completed with zero scenario errors or stopped early cleanly,
1 retained one or more model/scenario failures, 2 refused the plan, and 130 was
interrupted. The last line is always a ``RESULT:`` marker.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from benchmark.campaign import (  # noqa: E402
    ANCHOR_SEED,
    CampaignConfig,
    CampaignError,
    CampaignResult,
    bundle_sha256,
    dry_run_plan,
    run_campaign,
)
from benchmark.runner import (  # noqa: E402
    DEFAULT_RUNS_DIR,
    DEFAULT_TIMEOUT_SECONDS,
    AuthConfig,
    RunError,
    read_token,
)

REFUSED = 2
FAILED = 1
INTERRUPTED = 130


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--stage", required=True, choices=("A", "B", "C", "D"))
    parser.add_argument(
        "--condition",
        default="defence",
        help="defence (default), control, or ablation:<name>",
    )
    parser.add_argument(
        "--seed",
        action="append",
        type=int,
        default=None,
        help=(
            "a preregistered seed; repeat for each seed of the stage. One run directory is "
            "written per seed. Stage A defaults to the anchor seed 1729; B/C/D require it."
        ),
    )
    parser.add_argument("--model", default="qwen", help="qwen (default), scripted, or ollama")
    parser.add_argument(
        "--adapter-json",
        default=None,
        help=(
            "JSON object of QwenConfig fields (model_id, revision, quantization, dtype, seed, "
            "temperature, top_p, max_new_tokens, thinking, device, format_retries). The "
            "per-run --seed is authoritative over an embedded adapter seed."
        ),
    )
    parser.add_argument(
        "--tbd-json",
        default=None,
        help="JSON object of the freeze block's TBD-BEFORE-STAGE-B values, recorded verbatim",
    )
    parser.add_argument("--dataset", default=str(REPO_ROOT / "benchmark" / "data"))
    parser.add_argument("--holdout-dir", default=None, help="Stage D plaintext holdout directory")
    parser.add_argument(
        "--scenario-ids",
        default=None,
        help=(
            "comma-separated scenario ids to restrict the stage to (Stage A defaults to the "
            "freeze block's fixed six-scenario smoke set)"
        ),
    )
    parser.add_argument("--runs-dir", default=str(REPO_ROOT / DEFAULT_RUNS_DIR))
    parser.add_argument("--defense-url", default="http://127.0.0.1:8091")
    parser.add_argument("--control-url", default=None, help="external allow-all control origin")
    credential = parser.add_mutually_exclusive_group()
    credential.add_argument("--auth-token", default=None, help="bearer token (prefer a file)")
    credential.add_argument("--auth-token-file", default=None, help="file holding the token")
    parser.add_argument("--auth-header", default="Authorization")
    parser.add_argument("--auth-scheme", default="Bearer")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--hardware-note", default="unspecified host")
    parser.add_argument("--lock", default=str(REPO_ROOT / "requirements.lock"))
    parser.add_argument("--timestamp", default=None, help="override the run-dir timestamp")
    parser.add_argument(
        "--max-scenarios",
        type=int,
        default=None,
        help=(
            "process at most this many new scenarios per run this session, then stop cleanly "
            "and leave the run resumable (a Colab cell budget)"
        ),
    )
    parser.add_argument("--resume", action="store_true", help="continue the newest incomplete run")
    parser.add_argument("--bundle", action="store_true", help="zip the run directory after it runs")
    parser.add_argument(
        "--authorize-holdout",
        action="store_true",
        help="the explicit authorization Stage D requires before it will touch the holdout",
    )
    parser.add_argument("--dry-run", action="store_true", help="list what would run; call nothing")
    parser.add_argument("--json", action="store_true", help="print the machine-readable result")
    return parser


def _json_object(raw: str | None, flag: str) -> dict[str, object]:
    if raw is None:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise CampaignError(f"{flag} is not valid JSON: {error}") from error
    if not isinstance(value, dict):
        raise CampaignError(f"{flag} must be a JSON object, got {type(value).__name__}")
    return value


def _seeds(args: argparse.Namespace) -> tuple[int, ...]:
    if args.seed:
        return tuple(args.seed)
    if args.stage == "A":
        return (ANCHOR_SEED,)
    raise CampaignError(
        f"stage {args.stage} needs --seed: the seed list is preregistered before Stage A and is "
        "never chosen after seeing outcomes"
    )


def _auth(args: argparse.Namespace) -> AuthConfig | None:
    if args.auth_token is None and args.auth_token_file is None:
        return None
    return AuthConfig(
        token=read_token(args.auth_token, args.auth_token_file),
        header=args.auth_header,
        scheme=args.auth_scheme,
    )


def _config(args: argparse.Namespace, seeds: tuple[int, ...]) -> CampaignConfig:
    return CampaignConfig(
        stage=args.stage,
        dataset_root=Path(args.dataset),
        runs_dir=Path(args.runs_dir),
        seed=seeds[0],
        declared_seeds=seeds,
        condition=args.condition,
        model_name=args.model,
        adapter_config=_json_object(args.adapter_json, "--adapter-json"),
        gateway_url=args.defense_url,
        control_url=args.control_url,
        auth=_auth(args),
        timeout=args.timeout,
        hardware_note=args.hardware_note,
        lock_path=Path(args.lock),
        resume=args.resume,
        bundle=args.bundle,
        authorize_holdout=args.authorize_holdout,
        holdout_dir=None if args.holdout_dir is None else Path(args.holdout_dir),
        scenario_ids=(
            None
            if not args.scenario_ids
            else tuple(part.strip() for part in args.scenario_ids.split(",") if part.strip())
        ),
        timestamp=args.timestamp,
        max_scenarios=args.max_scenarios,
        tbd=_json_object(args.tbd_json, "--tbd-json"),
    )


def _print_result(result: CampaignResult) -> None:
    print(f"run directory: {result.run_dir}")
    print(f"stage:         {result.plan.stage}")
    print(f"condition:     {result.plan.condition.slug}")
    print(f"seed:          {result.plan.seed}")
    print(f"resumed:       {str(result.resumed).lower()}")
    print(
        f"scenarios:     {result.completed}/{len(result.plan.scenarios)} "
        f"(skipped {result.skipped}, errored {result.errored}, remaining {result.remaining})"
    )
    print(f"failures:      {result.failures}")
    if result.bundle is not None:
        print(f"zip:           {result.bundle}")
        print(f"zip sha256:    {bundle_sha256(result.bundle)}")


def _print_summary(results: list[CampaignResult]) -> bool:
    completed = [result for result in results if result.status == "complete"]
    errored = sum(result.errored for result in results)
    failures = sum(result.failures for result in results)
    if errored:
        print(f"errored scenarios: {errored}")
    if failures:
        print(f"retained failure records: {failures}")
    if errored:
        print("RESULT: CAMPAIGN COMPLETED WITH ERRORS")
    elif len(completed) == len(results):
        print("RESULT: CAMPAIGN COMPLETE")
    else:
        print("RESULT: CAMPAIGN INCOMPLETE")
    if results and all(result.bundle is not None for result in results):
        print("RESULT: BUNDLE OK")
    return not errored


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        seeds = _seeds(args)
        config = _config(args, seeds)
        if args.dry_run:
            plan = dry_run_plan(config, seeds)
            print(json.dumps(plan, indent=2, sort_keys=True))
            print("RESULT: DRY-RUN")
            return 0
        results: list[CampaignResult] = []
        for seed in seeds:
            results.append(run_campaign(replace(config, seed=seed)))
    except CampaignError as error:
        marker = "DRY-RUN FAILED" if args.dry_run else "REFUSED"
        print(f"RESULT: {marker}: {error}", file=sys.stderr)
        return REFUSED
    except RunError as error:
        print(f"run failed: {error}", file=sys.stderr)
        return FAILED
    except KeyboardInterrupt:
        print("RESULT: CAMPAIGN INTERRUPTED", file=sys.stderr)
        return INTERRUPTED

    for result in results:
        _print_result(result)
    if args.json:
        print(json.dumps([result.to_json() for result in results], indent=2, sort_keys=True))
    succeeded = _print_summary(results)
    return 0 if succeeded else FAILED


if __name__ == "__main__":
    raise SystemExit(main())
