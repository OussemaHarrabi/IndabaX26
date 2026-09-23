"""Packaging metadata needed by documented server startup commands."""

from __future__ import annotations

import tomllib
from pathlib import Path


def test_runtime_metadata_declares_uvicorn_for_server_startup() -> None:
    project_root = Path(__file__).resolve().parents[1]
    pyproject = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))

    assert "uvicorn>=0.30,<1" in pyproject["project"]["dependencies"]
