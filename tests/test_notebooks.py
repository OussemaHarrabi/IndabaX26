"""CPU-only structural and honesty checks for the cloud notebooks.

The notebook toolchain (``nbformat``, ``nbclient``, ``matplotlib``, ``pandas``)
and ``torch`` are deliberately **not** installed here, so this module parses the
notebook JSON directly and, where it needs to execute a notebook, extracts the
code cells and runs them as a plain Python script in a subprocess.

What this test proves
---------------------
* every committed notebook is valid nbformat JSON with the expected cell shape;
* no cell source or saved output carries a secret-shaped string;
* every first-party module a cell imports resolves in this repository, every
  third-party module a cell imports is an expected cloud dependency (so a typo in
  an import name fails rather than hiding), and every ``scripts/*.py`` path a cell
  invokes exists;
* the campaign CLI's ``--dry-run`` works and refuses Stage D without
  ``--authorize-holdout``;
* notebook 03's code cells, extracted and executed as a script against the
  committed scripted run, produce the analysis artifacts (``statistics.json`` plus
  the Markdown/CSV tables) with every hash verified and the committed score
  reproduced.

What this test does **not** prove
---------------------------------
* that a real GPU/model campaign runs — there is no GPU and no model here, and no
  real-model result exists in the repository;
* that the notebooks' cloud-only branches (toolchain install, model load, real
  campaign) execute — only that they are well-formed interfaces;
* that a campaign bundle round-trips through ``scripts/bench_campaign.py`` — that
  driver is a separate deliverable, so this module only asserts the CLI surface.
"""

from __future__ import annotations

import ast
import importlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest

REPO = Path(__file__).resolve().parents[1]
NOTEBOOK_DIR = REPO / "notebooks"
COMMITTED_RUN = REPO / "benchmark" / "runs" / "20261008T203656Z-m6-campaign"

EXPECTED_NOTEBOOKS = [
    "00_environment_and_smoke.ipynb",
    "01_qwen3_8b_public_campaign.ipynb",
    "02_qwen3_8b_ablations.ipynb",
    "03_qwen_results_analysis.ipynb",
]

#: Third-party imports the cloud cells legitimately need but that are absent in a
#: CPU-only test environment. A module not listed here and not first-party is a
#: defect (most likely a typo), so the import test fails on it.
CLOUD_ALLOWLIST = {
    "accelerate",
    "bitsandbytes",
    "google",
    "huggingface_hub",
    "IPython",
    "matplotlib",
    "nbconvert",
    "numpy",
    "pandas",
    "PIL",
    "psutil",
    "requests",
    "seaborn",
    "torch",
    "transformers",
}

#: Secret-shaped strings a cell or a saved output must never contain.
SECRET_PATTERNS = (
    "hf_",
    "sk-",
    "AKIA",
    "ghp_",
    "Bearer ",
    "-----BEGIN ",
    "PRIVATE KEY",
)

_SCRIPT_PATH = re.compile(r"scripts/[A-Za-z0-9_]+\.py")

FIRST_PARTY_ROOTS = {"benchmark", "backend"}


def _load(name: str) -> dict[str, Any]:
    path = NOTEBOOK_DIR / name
    assert path.is_file(), f"missing notebook: {path}"
    payload: Any = json.loads(path.read_text(encoding="utf-8"))
    return cast("dict[str, Any]", payload)


def _source(cell: dict[str, Any]) -> str:
    source = cell.get("source", "")
    if isinstance(source, list):
        return "".join(cast("list[str]", source))
    return cast(str, source)


def _code_cells(notebook: dict[str, Any]) -> list[dict[str, Any]]:
    cells = cast("list[dict[str, Any]]", notebook["cells"])
    return [cell for cell in cells if cell["cell_type"] == "code"]


def _flatten_outputs(cell: dict[str, Any]) -> list[str]:
    texts: list[str] = []
    for output in cast("list[dict[str, Any]]", cell.get("outputs", [])):
        value = output.get("text")
        if isinstance(value, list):
            texts.extend(str(item) for item in value)
        elif isinstance(value, str):
            texts.append(value)
        data = output.get("data")
        if isinstance(data, dict):
            for entry in data.values():
                if isinstance(entry, list):
                    texts.extend(str(item) for item in entry)
                elif isinstance(entry, str):
                    texts.append(entry)
    return texts


def _imported_top_levels(source: str) -> set[str]:
    tree = ast.parse(source)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return names


@pytest.mark.parametrize("name", EXPECTED_NOTEBOOKS)
def test_notebook_is_valid_nbformat_with_expected_structure(name: str) -> None:
    notebook = _load(name)
    assert notebook.get("nbformat") == 4
    assert isinstance(notebook.get("cells"), list) and notebook["cells"]
    assert notebook["cells"][0]["cell_type"] == "markdown"
    for cell in notebook["cells"]:
        assert cell["cell_type"] in {"code", "markdown", "raw"}
        assert "source" in cell
        if cell["cell_type"] == "code":
            assert isinstance(cell.get("outputs"), list)
            assert "execution_count" in cell
    titles = [_source(cell) for cell in _code_cells(notebook)]
    assert any("# @title Parameters" in title for title in titles), (
        f"{name} has no parameters cell"
    )


@pytest.mark.parametrize("name", EXPECTED_NOTEBOOKS)
def test_no_secret_shaped_string_in_cells_or_outputs(name: str) -> None:
    notebook = _load(name)
    haystacks = [_source(cell) for cell in notebook["cells"]]
    for cell in _code_cells(notebook):
        haystacks.extend(_flatten_outputs(cell))
    for haystack in haystacks:
        for pattern in SECRET_PATTERNS:
            assert pattern not in haystack, f"{name}: found secret-shaped {pattern!r}"


@pytest.mark.parametrize("name", EXPECTED_NOTEBOOKS)
def test_imports_and_script_paths_resolve(name: str) -> None:
    notebook = _load(name)
    sources = [_source(cell) for cell in _code_cells(notebook)]
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    for source in sources:
        for module in sorted(_imported_top_levels(source)):
            if module in sys.stdlib_module_names:
                continue
            package = REPO / module
            is_first_party = (
                module in FIRST_PARTY_ROOTS
                or package.is_dir()
                or package.with_suffix(".py").is_file()
            )
            if is_first_party:
                importlib.import_module(module)  # raises if the first-party module is broken
                continue
            assert module in CLOUD_ALLOWLIST, (
                f"{name}: unexpected import {module!r}; add it to CLOUD_ALLOWLIST only "
                "if it is a required cloud dependency"
            )
        for script in sorted(set(_SCRIPT_PATH.findall(source))):
            assert (REPO / script).is_file(), f"{name}: missing script {script}"


def test_campaign_cli_dry_run_and_holdout_refusal() -> None:
    campaign = REPO / "scripts" / "bench_campaign.py"
    assert campaign.is_file(), "scripts/bench_campaign.py is missing"
    base = [sys.executable, str(campaign), "--model", "scripted"]

    plan_args = [
        *base,
        "--stage", "A", "--condition", "defence", "--seed", "1729",
        "--defense-url", "http://127.0.0.1:1", "--dry-run",
    ]
    plan = subprocess.run(plan_args, cwd=REPO, capture_output=True, text=True)
    assert plan.returncode == 0, plan.stderr
    assert "RESULT: DRY-RUN" in plan.stdout

    refused_args = [
        *base, "--stage", "D", "--condition", "defence", "--seed", "1729", "--dry-run",
    ]
    refused = subprocess.run(refused_args, cwd=REPO, capture_output=True, text=True)
    assert refused.returncode == 2
    assert "RESULT: DRY-RUN FAILED" in (refused.stdout + refused.stderr)


@pytest.mark.parametrize("name", EXPECTED_NOTEBOOKS[:3])
def test_gpu_notebooks_use_the_closed_runtime_contract(name: str) -> None:
    sources = "\n".join(_source(cell) for cell in _code_cells(_load(name)))

    assert "FORMAT_RETRIES = 1" in sources
    assert "MODEL_REVISION = resolved_identity" in sources
    assert "del adapter" in sources
    assert "torch.cuda.empty_cache()" in sources
    assert "minted = sh(" not in sources
    assert "adapter_json=ADAPTER_JSON" in sources


@pytest.mark.parametrize("name", EXPECTED_NOTEBOOKS[:3])
def test_gpu_notebooks_bootstrap_the_repository_in_a_fresh_cloud_runtime(name: str) -> None:
    sources = "\n".join(_source(cell) for cell in _code_cells(_load(name)))

    assert "https://github.com/OussemaHarrabi/IndabaX26.git" in sources
    assert '"git", "clone"' in sources
    assert "AEGISGRAPH_REF" in sources


@pytest.mark.parametrize(
    ("name", "seed_assignment"),
    [
        ("01_qwen3_8b_public_campaign.ipynb", "SEEDS_B = [1729, 2741, 3253, 4253, 5527]"),
        ("02_qwen3_8b_ablations.ipynb", "SEEDS = [1729, 2741, 3253, 4253, 5527]"),
    ],
)
def test_full_gpu_notebooks_carry_the_preregistered_seed_list(
    name: str, seed_assignment: str
) -> None:
    sources = "\n".join(_source(cell) for cell in _code_cells(_load(name)))

    assert seed_assignment in sources


def test_notebook_03_executes_against_the_committed_scripted_run(tmp_path: Path) -> None:
    assert COMMITTED_RUN.is_dir(), f"committed run missing: {COMMITTED_RUN}"
    notebook = _load("03_qwen_results_analysis.ipynb")
    sources = [_source(cell) for cell in _code_cells(notebook)]
    script = tmp_path / "notebook_03.py"
    script.write_text("\n\n".join(sources) + "\n", encoding="utf-8")

    out_dir = tmp_path / "analysis-out"
    env = dict(os.environ)
    env["AEGISGRAPH_REPO"] = str(REPO)
    env["AEGISGRAPH_ANALYSIS_OUT"] = str(out_dir)
    proc = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(REPO), capture_output=True, text=True, env=env, timeout=900,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr

    statistics = json.loads((out_dir / "statistics.json").read_text(encoding="utf-8"))
    assert statistics["accounting"]["failed"] == 0
    assert [row["status"] for row in statistics["accounting"]["runs"]] == ["analysed"]
    assert statistics["comparisons"], "no paired comparison was produced"
    assert statistics["comparisons"][0]["reached_n"] > 0

    tables = sorted((out_dir / "tables").glob("*.md"))
    assert tables, "no Markdown tables were written"
    assert (out_dir / "tables" / "paired.md").is_file()
