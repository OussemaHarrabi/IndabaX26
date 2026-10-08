#!/usr/bin/env python3
"""Concurrent load harness for the generic decision surface (M3).

The harness speaks the M2 surface exactly as a client would: it authenticates with
an opaque service token read from ``--token-file``, checks ``GET /api/v1/version``,
**publishes or reuses** an activated policy set, then drives a weighted mix of
decision requests with a fixed concurrency for a bounded budget.

It reports throughput, p50/p95/p99, the error rate, the status and verdict
distributions, and the hardware/environment the numbers were observed on, then
writes an **immutable** JSON report (and its SHA-256) under
``docs/evidence/performance/``. An existing report is never overwritten.

Usage::

    python scripts/load_test.py --token-file /run/secrets/service-token \\
        --base-url http://127.0.0.1:8080 --duration 20 --concurrency 16

    python scripts/load_test.py --token-file token.txt --requests 500 --warmup 50

Exit codes: ``0`` when the measured error rate is within ``--max-error-rate``,
``1`` when it is not, ``2`` for a usage or environment problem.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
import statistics
import sys
import threading
import time
from collections import Counter
from collections.abc import Sequence
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIRECTORY = REPOSITORY_ROOT / "docs" / "evidence" / "performance"
DEFAULT_BASE_URL = "http://127.0.0.1:8080"
DEFAULT_POLICY_ID = "load-test-policy"
DEFAULT_POLICY_VERSION = "1"
POLICY_DOCUMENT: dict[str, Any] = {
    "allowed_tools": ["document_search", "payment_execute"],
    "confirmation_required_tools": ["payment_execute"],
    "consequential_tools": ["payment_execute"],
    "internal_email_domains": ["aegisgraph.local"],
}

# The request mix: (weight, name, candidate action). Weights are the reported mix;
# every shape is a valid request, so a non-2xx status is a real failure, not the mix.
REQUEST_MIX: tuple[tuple[int, str, dict[str, Any]], ...] = (
    (60, "answer", {"type": "respond", "content": "Summarise the incident report."}),
    (
        20,
        "read_tool",
        {"type": "tool_call", "tool": "document_search", "arguments": {"query": "runbook"}},
    ),
    (
        15,
        "blocked_tool",
        {"type": "tool_call", "tool": "email_send", "arguments": {"to": "external@example.test"}},
    ),
    (
        5,
        "confirmation_required",
        {"type": "tool_call", "tool": "payment_execute", "arguments": {"amount": 10}},
    ),
)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--token-file", required=True, help="file holding the service token")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="API base URL")
    parser.add_argument("--concurrency", type=int, default=16, help="concurrent workers")
    parser.add_argument("--duration", type=float, default=10.0, help="measured seconds")
    parser.add_argument(
        "--requests", type=int, default=0, help="measured request cap (0: duration only)"
    )
    parser.add_argument("--warm-up", type=int, default=40, help="requests before measuring")
    parser.add_argument("--timeout", type=float, default=10.0, help="per-request timeout (s)")
    parser.add_argument(
        "--max-error-rate", type=float, default=0.0, help="exit non-zero above this rate"
    )
    parser.add_argument("--policy-id", default=DEFAULT_POLICY_ID, help="policy set to activate")
    parser.add_argument("--policy-version", default=DEFAULT_POLICY_VERSION)
    parser.add_argument("--out-dir", default=str(DEFAULT_OUTPUT_DIRECTORY))
    parser.add_argument("--label", default="", help="free-text label recorded in the report")
    parser.add_argument(
        "--server-log",
        default="",
        help="path to the API stdout log, to also report service-side decision latency",
    )
    return parser.parse_args(argv)


def read_token(path: str) -> str:
    """Read the service token, refusing an empty or multi-line file."""

    text = Path(path).read_text(encoding="utf-8").strip()
    if not text:
        raise ValueError(f"{path} is empty")
    if "\n" in text:
        raise ValueError(f"{path} must hold exactly one token")
    return text


def percentile(sorted_samples: Sequence[float], fraction: float) -> float:
    """Return the linearly interpolated percentile of an already sorted sequence."""

    if not sorted_samples:
        return 0.0
    if len(sorted_samples) == 1:
        return sorted_samples[0]
    position = fraction * (len(sorted_samples) - 1)
    lower = int(position)
    upper = min(lower + 1, len(sorted_samples) - 1)
    weight = position - lower
    return sorted_samples[lower] * (1.0 - weight) + sorted_samples[upper] * weight


def decision_body(
    action: dict[str, Any], *, run_id: str, policy_set: dict[str, str]
) -> dict[str, Any]:
    return {
        "api_version": "aegisgraph/v1",
        "run_id": run_id,
        "step_id": 1,
        "user_goal": "Exercise the decision surface under load",
        "conversation": [],
        "candidate_action": action,
        "policy_set": policy_set,
        "history_digest": {"confirmations_granted": []},
    }


def ensure_policy_set(
    client: httpx.Client, *, policy_id: str, version: str
) -> tuple[dict[str, str], str]:
    """Publish and activate the policy set, or reuse an already activated one.

    Returns the ``policy_set`` value to send and a short description of how it was
    obtained. Requires ``policy:write`` on the token; a token without it may still
    reuse a version an operator activated earlier.
    """

    policy_set = {"id": policy_id, "version": version}
    payload = {"id": policy_id, "version": version, "document": POLICY_DOCUMENT, "activate": True}
    created = client.post("/api/v1/policies", json=payload)
    if created.status_code == 201:
        return policy_set, "published and activated by the harness"
    if created.status_code == 409:
        activated = client.post(f"/api/v1/policies/{policy_id}/activate", json={"version": version})
        if activated.status_code == 200:
            return policy_set, "an existing immutable version was re-activated"
    listed = client.get("/api/v1/policies")
    if listed.status_code == 200:
        for item in listed.json()["items"]:
            if item["id"] == policy_id and item["version"] == version and item["active"]:
                return policy_set, "reused: an operator had already activated this version"
    raise RuntimeError(
        "could not publish or reuse an activated policy set: "
        f"create={created.status_code} detail={created.text[:200]}"
    )


def environment_note(base_url: str, version: dict[str, Any]) -> dict[str, Any]:
    """Describe the machine and the server build the numbers were observed on."""

    uname = platform.uname()
    return {
        "observed_on": "local developer hardware, single API process, no tuning",
        "base_url": base_url,
        "platform": f"{uname.system} {uname.release}",
        "machine": uname.machine,
        "processor": uname.processor or "not reported by the platform",
        "cpu_count": os.cpu_count(),
        "python": platform.python_version(),
        "server_build": version.get("build"),
        "server_policy_set": version.get("policy_set"),
    }


def run_warm_up(
    client: httpx.Client, *, count: int, policy_set: dict[str, str], timeout: float
) -> int:
    """Send ``count`` requests so the first measured one is not a cold start."""

    for index in range(count):
        action = REQUEST_MIX[index % len(REQUEST_MIX)][2]
        client.post(
            "/api/v1/decisions",
            json=decision_body(action, run_id=f"warm-up-{index}", policy_set=policy_set),
            timeout=timeout,
        )
    return count


def measure(
    client: httpx.Client,
    *,
    concurrency: int,
    duration: float,
    request_cap: int,
    policy_set: dict[str, str],
    timeout: float,
) -> dict[str, Any]:
    """Drive the weighted mix and return the raw observations."""

    deadline = time.monotonic() + duration
    stop = threading.Event()
    lock = threading.Lock()
    latencies: list[float] = []
    statuses: list[int] = []
    verdicts: list[str] = []
    shapes: list[str] = []
    errors: list[str] = []
    issued = 0
    weights = [weight for weight, _name, _action in REQUEST_MIX]
    names = [name for _weight, name, _action in REQUEST_MIX]
    actions = [action for _weight, _name, action in REQUEST_MIX]

    def worker(seed: int) -> None:
        nonlocal issued
        rng = random.Random(seed)
        while not stop.is_set():
            with lock:
                if request_cap and issued >= request_cap:
                    stop.set()
                    return
                issued += 1
                slot = issued
            index = rng.choices(range(len(REQUEST_MIX)), weights=weights, k=1)[0]
            started = time.perf_counter()
            try:
                response = client.post(
                    "/api/v1/decisions",
                    json=decision_body(
                        actions[index],
                        run_id=f"load-{seed}-{slot}",
                        policy_set=policy_set,
                    ),
                    timeout=timeout,
                )
                elapsed = time.perf_counter() - started
                status = response.status_code
                verdict = response.json().get("decision", "") if status == 200 else ""
                failure = None if status == 200 else f"HTTP {status}"
            except Exception as error:  # transport failure, timeout, cancellation
                elapsed = time.perf_counter() - started
                status, verdict, failure = 0, "", type(error).__name__
            with lock:
                latencies.append(elapsed)
                statuses.append(status)
                verdicts.append(verdict)
                shapes.append(names[index])
                if failure is not None:
                    errors.append(failure)
            if time.monotonic() >= deadline:
                stop.set()

    workers = [
        threading.Thread(target=worker, args=(seed,), daemon=True) for seed in range(concurrency)
    ]
    started_at = time.monotonic()
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join()
    elapsed = time.monotonic() - started_at
    return {
        "elapsed_seconds": elapsed,
        "latencies": latencies,
        "statuses": statuses,
        "verdicts": verdicts,
        "shapes": shapes,
        "errors": errors,
    }


def summarise(
    measured: dict[str, Any],
    *,
    concurrency: int,
    duration: float,
    request_cap: int,
    warm_up: int,
    mix_description: list[dict[str, Any]],
) -> dict[str, Any]:
    """Turn the raw observations into the reported figures."""

    latencies = sorted(measured["latencies"])
    total = len(latencies)
    failures = sum(1 for status in measured["statuses"] if status != 200)
    server_errors = sum(1 for status in measured["statuses"] if status >= 500 or status == 0)
    elapsed = float(measured["elapsed_seconds"]) or 1e-9
    return {
        "measured_requests": total,
        "elapsed_seconds": round(elapsed, 6),
        "throughput_rps": round(total / elapsed, 3),
        "latency_seconds": {
            "min": round(latencies[0], 6) if latencies else 0.0,
            "p50": round(percentile(latencies, 0.50), 6),
            "p95": round(percentile(latencies, 0.95), 6),
            "p99": round(percentile(latencies, 0.99), 6),
            "max": round(latencies[-1], 6) if latencies else 0.0,
            "mean": round(statistics.fmean(latencies), 6) if latencies else 0.0,
        },
        "error_rate": round(failures / total, 6) if total else 1.0,
        "server_error_rate": round(server_errors / total, 6) if total else 1.0,
        "status_counts": {
            str(key): value for key, value in sorted(Counter(measured["statuses"]).items())
        },
        "verdict_counts": dict(sorted(Counter(measured["verdicts"]).items())),
        "shape_counts": dict(sorted(Counter(measured["shapes"]).items())),
        "error_samples": dict(sorted(Counter(measured["errors"]).items())),
        "parameters": {
            "concurrency": concurrency,
            "duration_seconds": duration,
            "request_cap": request_cap or None,
            "warm_up_requests": warm_up,
        },
        "request_mix": mix_description,
        "percentile_method": "linear interpolation on the sorted sample set",
        "latency_kind": (
            "client-observed end-to-end, including load-generator scheduling on the same host"
        ),
    }


def digest_of(payload: dict[str, Any]) -> str:
    """Return the SHA-256 of the canonical encoding of a payload."""

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def decision_record_latencies(path: Path, *, offset: int) -> dict[str, Any]:
    """Read service-side decision latencies from the structured decision log.

    The API emits exactly one JSON decision record per decision, carrying
    ``latency_ms`` measured inside the process. Reading only the bytes written after
    ``offset`` excludes the warm-up, so this is the server-side half of the same
    measurement window the client observed — free of load-generator scheduling.
    """

    text = path.read_text(encoding="utf-8", errors="replace")
    tail = text[offset:] if offset <= len(text) else text
    samples: list[float] = []
    for line in tail.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict) and record.get("event") == "decision":
            value = record.get("latency_ms")
            if isinstance(value, (int, float)):
                samples.append(float(value) / 1000.0)
    ordered = sorted(samples)
    return {
        "source": path.as_posix(),
        "decisions_observed": len(ordered),
        "latency_seconds": {
            "p50": round(percentile(ordered, 0.50), 6),
            "p95": round(percentile(ordered, 0.95), 6),
            "p99": round(percentile(ordered, 0.99), 6),
            "max": round(ordered[-1], 6) if ordered else 0.0,
            "mean": round(statistics.fmean(ordered), 6) if ordered else 0.0,
        },
    }


def write_report(report: dict[str, Any], out_dir: Path, *, stamp: datetime) -> tuple[Path, str]:
    """Write the report and its digest, refusing to overwrite an existing artifact."""

    out_dir.mkdir(parents=True, exist_ok=True)
    name = f"m3-load-{stamp.strftime('%Y%m%dT%H%M%SZ')}"
    path = out_dir / f"{name}.json"
    if path.exists():
        raise FileExistsError(f"{path} already exists; reports are immutable")
    body = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    path.write_text(body, encoding="utf-8")
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    (out_dir / f"{name}.sha256").write_text(f"{digest}  {name}.json\n", encoding="utf-8")
    with suppress(OSError):  # a filesystem that cannot mark the artifact read-only
        path.chmod(0o444)
    return path, digest


def markdown_summary(report: dict[str, Any], *, path: Path, digest: str) -> str:
    """Render the human-readable half of the report."""

    latency = report["results"]["latency_seconds"]
    lines = [
        f"# Load test report — {report['started_at']}",
        "",
        f"- artifact: `{path.as_posix()}`",
        f"- sha256: `{digest}`",
        f"- base URL: `{report['environment']['base_url']}`",
        f"- policy set: `{report['policy_set']['id']}:{report['policy_set']['version']}`"
        f" ({report['policy_set']['source']})",
        "",
        "| metric | value |",
        "| --- | --- |",
        f"| measured requests | {report['results']['measured_requests']} |",
        f"| throughput | {report['results']['throughput_rps']} req/s |",
        f"| p50 | {latency['p50'] * 1000:.3f} ms |",
        f"| p95 | {latency['p95'] * 1000:.3f} ms |",
        f"| p99 | {latency['p99'] * 1000:.3f} ms |",
        f"| max | {latency['max'] * 1000:.3f} ms |",
        f"| error rate | {report['results']['error_rate']:.4%} |",
        f"| status counts | {report['results']['status_counts']} |",
        f"| verdict counts | {report['results']['verdict_counts']} |",
        "",
    ]
    service_side = report.get("service_side")
    if isinstance(service_side, dict):
        service_latency = service_side["latency_seconds"]
        lines += [
            "Service-side decision latency, read from the structured decision record"
            f" ({service_side['decisions_observed']} decisions in the measured window):",
            "",
            "| metric | value |",
            "| --- | --- |",
            f"| p50 | {service_latency['p50'] * 1000:.3f} ms |",
            f"| p95 | {service_latency['p95'] * 1000:.3f} ms |",
            f"| p99 | {service_latency['p99'] * 1000:.3f} ms |",
            f"| max | {service_latency['max'] * 1000:.3f} ms |",
            "",
        ]
    lines += [
        f"Observed on {report['environment']['observed_on']}: "
        f"{report['environment']['platform']} / {report['environment']['machine']} / "
        f"{report['environment']['cpu_count']} CPUs / Python {report['environment']['python']}, "
        f"concurrency {report['results']['parameters']['concurrency']}.",
        "",
    ]
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        token = read_token(args.token_file)
    except (OSError, ValueError) as error:
        print(f"load-test: {error}", file=sys.stderr)
        return 2
    if args.concurrency < 1 or args.warm_up < 0 or args.duration <= 0 or args.requests < 0:
        print(
            "load-test: concurrency >= 1, duration > 0, warm-up >= 0, requests >= 0",
            file=sys.stderr,
        )
        return 2

    stamp = datetime.now(UTC)
    headers = {"Authorization": f"Bearer {token}"}
    try:
        with httpx.Client(
            base_url=args.base_url, headers=headers, timeout=args.timeout
        ) as client:
            version_response = client.get("/api/v1/version")
            if version_response.status_code != 200:
                print(
                    f"load-test: GET /api/v1/version returned {version_response.status_code}; "
                    "check the token and the base URL",
                    file=sys.stderr,
                )
                return 2
            version = version_response.json()
            policy_set, policy_source = ensure_policy_set(
                client, policy_id=args.policy_id, version=args.policy_version
            )
            log_path = Path(args.server_log) if args.server_log else None
            log_offset = log_path.stat().st_size if log_path and log_path.exists() else 0
            warm_up = run_warm_up(
                client, count=args.warm_up, policy_set=policy_set, timeout=args.timeout
            )
            measured = measure(
                client,
                concurrency=args.concurrency,
                duration=args.duration,
                request_cap=args.requests,
                policy_set=policy_set,
                timeout=args.timeout,
            )
            service_side = (
                decision_record_latencies(log_path, offset=log_offset)
                if log_path is not None
                else None
            )
    except (httpx.HTTPError, RuntimeError) as error:
        print(f"load-test: {type(error).__name__}: {error}", file=sys.stderr)
        return 2

    results = summarise(
        measured,
        concurrency=args.concurrency,
        duration=args.duration,
        request_cap=args.requests,
        warm_up=warm_up,
        mix_description=[
            {"name": name, "weight": weight} for weight, name, _action in REQUEST_MIX
        ],
    )
    report: dict[str, Any] = {
        "schema": "aegisgraph.load-test/1",
        "started_at": stamp.isoformat(),
        "label": args.label,
        "tool": {"name": "scripts/load_test.py", "version": "1"},
        "environment": environment_note(args.base_url, version),
        "api_version": version.get("api_version"),
        "policy_set": {**policy_set, "source": policy_source, "document": POLICY_DOCUMENT},
        "results": results,
    }
    if service_side is not None:
        report["service_side"] = service_side
    report["digest_semantics"] = (
        "report_digest_sha256 covers this report's canonical (sorted, compact) encoding "
        "without that field; the .sha256 sidecar covers the exact bytes written to disk"
    )
    report["report_digest_sha256"] = digest_of(report)
    try:
        path, digest = write_report(report, Path(args.out_dir), stamp=stamp)
    except OSError as error:
        print(f"load-test: {error}", file=sys.stderr)
        return 2
    print(markdown_summary(report, path=path, digest=digest))
    if results["error_rate"] > args.max_error_rate:
        print(
            f"load-test: error rate {results['error_rate']:.4%} exceeds "
            f"--max-error-rate {args.max_error_rate:.4%}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    sys.exit(main())
