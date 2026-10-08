#!/usr/bin/env python3
"""Run the native benchmark against a gateway and write an immutable run directory."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from benchmark.runner import (  # noqa: E402
    DEFAULT_RUNS_DIR,
    DEFAULT_TIMEOUT_SECONDS,
    AuthConfig,
    RunConfig,
    RunError,
    execute_run,
    model_adapter,
    read_token,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--defense-url", required=True, help="e.g. http://127.0.0.1:8080")
    parser.add_argument("--dataset", default=str(REPO_ROOT / "benchmark" / "data"))
    parser.add_argument("--runs-dir", default=str(REPO_ROOT / DEFAULT_RUNS_DIR))
    parser.add_argument("--model", default="scripted", help="scripted (default) or ollama")
    parser.add_argument(
        "--splits",
        default="development,validation",
        help="comma-separated splits to evaluate; the sealed holdout is never runnable here",
    )
    parser.add_argument("--config-slug", default=None, help="override the derived run slug")
    parser.add_argument(
        "--timestamp",
        default=None,
        help="override the run-directory timestamp (YYYYMMDDTHHMMSSZ)",
    )
    parser.add_argument("--control-url", default=None, help="external allow-all control origin")
    credential = parser.add_mutually_exclusive_group()
    credential.add_argument(
        "--auth-token",
        default=None,
        help="bearer token for the decision surface (prefer --auth-token-file)",
    )
    credential.add_argument(
        "--auth-token-file",
        default=None,
        help="file containing the bearer token; never appears in a shell history",
    )
    parser.add_argument(
        "--auth-header",
        default="Authorization",
        help="header name carrying the credential (default: Authorization)",
    )
    parser.add_argument(
        "--auth-scheme",
        default="Bearer",
        help="scheme prefixing the credential (default: Bearer; use '' for a raw token)",
    )
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--seed", type=int, default=1729)
    parser.add_argument("--temperature", type=float, default=None)
    parser.add_argument("--max-tokens", type=int, default=None)
    parser.add_argument("--hardware-note", default="unspecified host")
    parser.add_argument(
        "--lock",
        default=str(REPO_ROOT / "requirements.lock"),
        help="dependency lock file to hash into the manifest",
    )
    args = parser.parse_args(argv)

    splits = tuple(part.strip() for part in args.splits.split(",") if part.strip())
    if "holdout" in splits:
        print(
            "refusing to evaluate the sealed holdout: only the orchestrator may open the "
            "seal after the policy freeze (docs/benchmark/holdout.md)",
            file=sys.stderr,
        )
        return 2
    auth = None
    if args.auth_token is not None or args.auth_token_file is not None:
        try:
            auth = AuthConfig(
                token=read_token(args.auth_token, args.auth_token_file),
                header=args.auth_header,
                scheme=args.auth_scheme,
            )
        except RunError as error:
            print(f"run failed: {error}", file=sys.stderr)
            return 1

    try:
        config = RunConfig(
            defense_url=args.defense_url,
            dataset_root=Path(args.dataset),
            runs_dir=Path(args.runs_dir),
            model=model_adapter(args.model),
            control_url=args.control_url,
            splits=splits,
            config_slug=args.config_slug,
            timestamp=args.timestamp,
            timeout=args.timeout,
            seed=args.seed,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
            hardware_note=args.hardware_note,
            lock_path=Path(args.lock),
            auth=auth,
        )
        result = execute_run(config)
    except RunError as error:
        print(f"run failed: {error}", file=sys.stderr)
        return 1
    print(f"run directory: {result.run_dir}")
    print(f"scenarios:     {len(result.outcomes)}")
    print(f"manifest:      {result.run_dir / 'manifest.json'}")
    print(f"auth mode:     {result.manifest['auth']['mode']} "
          f"(header={result.manifest['auth']['header']}, "
          f"principal={result.manifest['auth']['principal']})")
    print(f"policy blob:   {result.manifest['policy']['blob_sha256']}")
    print(json.dumps(result.manifest["artifacts"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
