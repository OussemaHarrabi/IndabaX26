#!/usr/bin/env python3
"""Publish the policy sets the native benchmark pins, then verify they are active.

Since Milestone 2 the gateway resolves the policy *identity* server-side: a
request may name a policy set only if that version exists for its tenant, and
without a name the server's default set is used. The benchmark therefore derives
one policy set per distinct policy document in the dataset (id
``bench-<digest>``, version ``1``), publishes it here, and pins it in every
request. That is why a benchmark run needs no ``policy:context_override`` scope:
the policy facts it measures are stored, versioned and auditable rather than
asserted by the caller.

Usage::

    python scripts/bench_policies.py publish \
      --defense-url http://127.0.0.1:8080 --token-file /tmp/policy-admin.jwt

    python scripts/bench_policies.py publish --check-only ...   # verify only

The token must carry ``policy:read`` and ``policy:write`` (the ``policy_admin``
role of ``scripts/dev_issuer.py``). It is never printed, logged or hashed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from benchmark.policies import (  # noqa: E402
    MISSING,
    PRESENT_INACTIVE,
    collect_policy_sets,
    publish_plan,
)
from benchmark.runner import AuthConfig, HttpClient, RunError, read_token  # noqa: E402
from benchmark.wire import policy_document_digest  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        nargs="?",
        default="publish",
        choices=("publish",),
        help="the only operation: publish (and verify) the policy sets",
    )
    parser.add_argument("--defense-url", required=True)
    parser.add_argument("--dataset", default=str(REPO_ROOT / "benchmark" / "data"))
    parser.add_argument("--splits", default="development,validation")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--auth-token", default=None, help="bearer token (prefer --token-file)")
    group.add_argument("--token-file", default=None, help="file containing the bearer token")
    parser.add_argument("--auth-header", default="Authorization")
    parser.add_argument("--auth-scheme", default="Bearer")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--check-only", action="store_true", help="verify without publishing")
    args = parser.parse_args(argv)

    splits = tuple(part.strip() for part in args.splits.split(",") if part.strip())
    try:
        token = read_token(args.auth_token, args.token_file)
    except RunError as error:
        print(f"policy publication failed: {error}", file=sys.stderr)
        return 1
    auth = AuthConfig(token=token, header=args.auth_header, scheme=args.auth_scheme)
    client = HttpClient(args.defense_url, args.timeout, auth)

    try:
        plan = collect_policy_sets(Path(args.dataset), splits)
        results = publish_plan(client, plan, check_only=args.check_only)
    except RunError as error:
        print(f"policy publication failed: {error}", file=sys.stderr)
        return 1

    report = {
        "defense_url": args.defense_url,
        "splits": list(splits),
        "policy_set_count": len(plan.documents),
        "policy_blob_sha256": plan.blob_sha256,
        "results": results,
        "document_digests": {
            key: policy_document_digest(document)
            for key, document in sorted(plan.documents.items())
        },
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    failures = [key for key, value in results.items() if value in {MISSING, PRESENT_INACTIVE}]
    if failures:
        print(f"not active after publication: {failures}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
