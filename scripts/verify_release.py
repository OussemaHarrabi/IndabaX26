#!/usr/bin/env python3
"""Run the release verification battery and save an auditable transcript.

Every check is a subprocess whose exact command, exit code and output are recorded
under ``docs/evidence/verification/``. A check that cannot run in this environment
is recorded as ``unavailable`` with the reason — never as a pass — and skipped
tests are reported as skips rather than folded into a green result.

Usage::

    python scripts/verify_release.py                 # the full battery
    python scripts/verify_release.py --skip-container
    python scripts/verify_release.py --db-url postgresql+psycopg://user:pw@host:port/db
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = REPO_ROOT / "docs" / "evidence" / "verification"
DB_ENV = "AEGISGRAPH_TEST_DATABASE_URL"
DEFAULT_DB_URL = "postgresql+psycopg://aegisgraph:verify@127.0.0.1:15533/aegisgraph_verify"
CONTAINER_HOST_PORT = 18080


@dataclass
class Result:
    name: str
    command: str
    status: str  # passed | failed | unavailable
    exit_code: int | None = None
    output: str = ""
    note: str = ""

    def summary(self) -> str:
        tail = [line for line in self.output.strip().splitlines() if line.strip()][-1:]
        return tail[0][:160] if tail else ""


@dataclass
class Battery:
    results: list[Result] = field(default_factory=list)
    environment: dict[str, str] = field(default_factory=dict)

    def add(self, result: Result) -> Result:
        self.results.append(result)
        mark = {"passed": "PASS", "failed": "FAIL", "unavailable": "N/A "}[result.status]
        print(f"[{mark}] {result.name}: {result.summary() or result.note}", flush=True)
        return result


def _run(
    name: str,
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: int = 2400,
) -> Result:
    printable = " ".join(command)
    merged = {**os.environ, **(env or {})}
    try:
        completed = subprocess.run(
            command,
            cwd=REPO_ROOT,
            env=merged,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return Result(name, printable, "failed", None, f"timed out after {timeout}s")
    except FileNotFoundError as exc:
        return Result(name, printable, "unavailable", None, "", str(exc))
    output = (completed.stdout or "") + (completed.stderr or "")
    return Result(
        name,
        printable,
        "passed" if completed.returncode == 0 else "failed",
        completed.returncode,
        output,
    )


def _git(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8"
    )
    return completed.stdout.strip()


def collect_environment(db_url: str) -> dict[str, str]:
    environment = {
        "recorded_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "commit": _git("rev-parse", "HEAD"),
        "commit_short": _git("rev-parse", "--short", "HEAD"),
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "dirty": "yes" if _git("status", "--porcelain") else "no",
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "core_autocrlf": _git("config", "core.autocrlf") or "(unset)",
        "db_url": db_url,
    }
    for tool, args in (
        ("docker", ["--version"]),
        ("kubectl", ["version", "--client", "-o", "yaml"]),
    ):
        binary = shutil.which(tool)
        if binary is None:
            environment[tool] = "unavailable"
            continue
        completed = subprocess.run([binary, *args], capture_output=True, text=True)
        first = (completed.stdout or completed.stderr).strip().splitlines()
        environment[tool] = first[0] if first else "available"
    return environment


# --------------------------------------------------------------------------- #
# Database helpers (throwaway databases, dropped afterwards)
# --------------------------------------------------------------------------- #


def _admin_engine(db_url: str) -> Any:
    import sqlalchemy

    return sqlalchemy.create_engine(db_url, isolation_level="AUTOCOMMIT")


def _drop_database(db_url: str, name: str) -> None:
    with _admin_engine(db_url).connect() as connection:
        connection.exec_driver_sql(f'DROP DATABASE IF EXISTS "{name}"')


def _create_database(db_url: str, name: str) -> str:
    _drop_database(db_url, name)
    with _admin_engine(db_url).connect() as connection:
        connection.exec_driver_sql(f'CREATE DATABASE "{name}"')
    return db_url.rsplit("/", 1)[0] + f"/{name}"


def check_alembic(battery: Battery, db_url: str) -> None:
    try:
        from sqlalchemy.engine import make_url

        base = make_url(db_url)
    except Exception as exc:  # pragma: no cover - configuration error
        battery.add(Result("alembic", "n/a", "unavailable", None, "", str(exc)))
        return

    if base.get_backend_name().startswith("sqlite"):
        battery.add(
            Result(
                "alembic",
                "n/a",
                "unavailable",
                None,
                "",
                "a PostgreSQL URL is required for the migration checks",
            )
        )
        return

    try:
        empty_url = _create_database(db_url, "aegisgraph_battery_empty")
        incremental_url = _create_database(db_url, "aegisgraph_battery_incremental")
    except Exception as exc:
        battery.add(
            Result("alembic", "n/a", "unavailable", None, "", f"cannot create a database: {exc}")
        )
        return

    try:
        battery.add(
            _run(
                "alembic upgrade head from an empty database",
                ["python", "-m", "alembic", "upgrade", "head"],
                env={"DATABASE_URL": empty_url},
            )
        )
        battery.add(
            _run(
                "alembic check (no unapplied operations)",
                ["python", "-m", "alembic", "check"],
                env={"DATABASE_URL": empty_url},
            )
        )
        battery.add(
            _run(
                "alembic upgrade 0001_initial (incremental base)",
                ["python", "-m", "alembic", "upgrade", "0001_initial"],
                env={"DATABASE_URL": incremental_url},
            )
        )
        battery.add(
            _run(
                "alembic upgrade head (incremental from 0001)",
                ["python", "-m", "alembic", "upgrade", "head"],
                env={"DATABASE_URL": incremental_url},
            )
        )
    finally:
        for name in ("aegisgraph_battery_empty", "aegisgraph_battery_incremental"):
            with contextlib.suppress(Exception):
                _drop_database(db_url, name)


def check_container(battery: Battery, commit: str) -> None:
    if shutil.which("docker") is None:
        battery.add(
            Result(
                "container build + read-only smoke",
                "docker build",
                "unavailable",
                None,
                "",
                "docker is not installed",
            )
        )
        return

    tag = f"aegisgraph:verify-{commit[:12]}"
    name = f"aegisgraph-verify-{commit[:8]}"
    build = _run("container build", ["docker", "build", "-t", tag, "."], timeout=3600)
    battery.add(build)
    if build.status != "passed":
        return

    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    run = _run(
        "container run (read-only root, no capabilities)",
        [
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=64",
            "--memory=512m",
            "-p",
            f"{CONTAINER_HOST_PORT}:8080",
            tag,
        ],
    )
    if run.status != "passed":
        battery.add(run)
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        return

    healthy = Result("container smoke: /healthz", "curl 127.0.0.1", "failed", None, "")
    try:
        import urllib.error
        import urllib.request

        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{CONTAINER_HOST_PORT}/healthz", timeout=2
                ) as response:
                    body = response.read().decode()
                    healthy = Result(
                        "container smoke: /healthz",
                        f"curl http://127.0.0.1:{CONTAINER_HOST_PORT}/healthz",
                        "passed" if response.status == 200 else "failed",
                        response.status,
                        body,
                    )
                    break
            except (urllib.error.URLError, OSError) as exc:
                last = str(exc)
                time.sleep(1)
        else:
            healthy = Result(
                "container smoke: /healthz",
                f"curl http://127.0.0.1:{CONTAINER_HOST_PORT}/healthz",
                "failed",
                None,
                last,
            )
        battery.add(healthy)
        # Ask the running container for its readiness report from the host. The
        # earlier `docker exec … urlopen(127.0.0.1:8080)` form failed with
        # "connection refused" because the container's loopback is not the mapped
        # interface; the host port is what a reader would actually probe.
        ready_url = f"http://127.0.0.1:{CONTAINER_HOST_PORT}/readyz"
        try:
            with urllib.request.urlopen(ready_url, timeout=10) as response:
                report = json.loads(response.read().decode())
            battery.add(
                Result(
                    "container smoke: /readyz reports the development posture",
                    f"curl {ready_url}",
                    "passed" if report.get("ready") is True else "failed",
                    response.status,
                    json.dumps(report, indent=2),
                )
            )
        except Exception as exc:
            battery.add(
                Result(
                    "container smoke: /readyz reports the development posture",
                    f"curl {ready_url}",
                    "failed",
                    None,
                    str(exc),
                )
            )
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        subprocess.run(["docker", "rmi", tag], capture_output=True)


def run_battery(args: argparse.Namespace) -> Battery:
    battery = Battery()
    battery.environment = collect_environment(args.db_url)
    commit = battery.environment["commit_short"]
    db_env = {DB_ENV: args.db_url}

    battery.add(_run("tests without PostgreSQL", ["python", "-m", "pytest", "-q"]))
    battery.add(_run("tests with PostgreSQL 17", ["python", "-m", "pytest", "-q"], env=db_env))
    battery.add(
        _run(
            "PostgreSQL-marked tests only",
            ["python", "-m", "pytest", "-q", "-m", "db", "-p", "no:cacheprovider"],
            env=db_env,
        )
    )
    battery.add(
        _run(
            "coverage with PostgreSQL (floor 95)",
            [
                "python",
                "-m",
                "pytest",
                "-q",
                "--cov=aegisgraph",
                "--cov-report=term",
                "--cov-fail-under=95",
            ],
            env=db_env,
        )
    )
    battery.add(
        _run("ruff", ["python", "-m", "ruff", "check", "backend", "tests", "scripts", "benchmark"])
    )
    battery.add(_run("mypy (strict)", ["python", "-m", "mypy"]))
    battery.add(_run("native benchmark validation", ["python", "scripts/bench_validate.py"]))
    battery.add(_run("SBOM freshness", ["python", "scripts/check_sbom_freshness.py"]))
    battery.add(
        _run(
            "release manifest verification",
            [
                "python",
                "scripts/release_manifest.py",
                "--verify",
                "docs/evidence/release-manifest.json",
            ],
        )
    )
    battery.add(
        _run(
            "Kubernetes manifests (both validators)",
            ["python", "scripts/validate_k8s_manifests.py", "--validator", "both"],
        )
    )
    check_alembic(battery, args.db_url)
    if args.skip_container:
        battery.add(
            Result(
                "container build + read-only smoke",
                "docker build",
                "unavailable",
                None,
                "",
                "skipped by request",
            )
        )
    else:
        check_container(battery, commit)
    return battery


def write_transcript(battery: Battery) -> tuple[Path, Path]:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    json_path = OUTPUT_DIR / f"{stamp}-battery.json"
    text_path = OUTPUT_DIR / f"{stamp}-battery.txt"

    lines = [
        f"AegisGraph release verification battery — {battery.environment['recorded_at']}",
        "commit {commit} ({branch}, dirty={dirty})".format(
            commit=battery.environment["commit"],
            branch=battery.environment["branch"],
            dirty=battery.environment["dirty"],
        ),
        "",
        "environment:",
    ]
    for key, value in battery.environment.items():
        lines.append(f"  {key}: {value}")
    lines.append("")
    for result in battery.results:
        lines.append(f"$ {result.command}")
        lines.append(f"[{result.status}] exit={result.exit_code} {result.note}")
        if result.output.strip():
            lines.append(result.output.rstrip())
        lines.append("")
    text_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")

    payload = {
        "environment": battery.environment,
        "summary": {
            "passed": sum(1 for r in battery.results if r.status == "passed"),
            "failed": sum(1 for r in battery.results if r.status == "failed"),
            "unavailable": sum(1 for r in battery.results if r.status == "unavailable"),
        },
        "checks": [
            {
                "name": r.name,
                "command": r.command,
                "status": r.status,
                "exit_code": r.exit_code,
                "note": r.note,
                "last_line": r.summary(),
            }
            for r in battery.results
        ],
        "transcript": text_path.name,
    }
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")
    return json_path, text_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-url", default=os.environ.get(DB_ENV, DEFAULT_DB_URL))
    parser.add_argument(
        "--skip-container", action="store_true", help="skip the Docker build and smoke test"
    )
    args = parser.parse_args(argv)

    battery = run_battery(args)
    json_path, text_path = write_transcript(battery)
    failed = [r.name for r in battery.results if r.status == "failed"]
    print()
    print(f"transcript: {text_path.relative_to(REPO_ROOT)}")
    print(f"summary:    {json_path.relative_to(REPO_ROOT)}")
    print(f"failed:     {failed or 'none'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
