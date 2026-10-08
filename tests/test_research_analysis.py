"""Tests for the preregistered research analysis script.

Covers the multiplicity step (Holm-Bonferroni / Benjamini-Hochberg) with
hand-checked examples, the reportability floor applied to the decision-level
cells, the control-liveness check and its falsifiable failure mode, and the
correction-gated H3 verdict.
"""

from __future__ import annotations

import importlib.util
import json
import math
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "docs" / "research" / "analysis.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("research_analysis", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


analysis = _load_module()


# --------------------------------------------------------------------------
# multiplicity, hand-checked
# --------------------------------------------------------------------------
def test_holm_adjust_matches_hand_computation() -> None:
    # m = 3: sorted 0.001, 0.02, 0.03 -> 3*0.001 = 0.003; max(0.003, 2*0.02) = 0.04;
    # max(0.04, 1*0.03) = 0.04.
    assert analysis.holm_adjust([0.001, 0.02, 0.03]) == [0.003, 0.04, 0.04]


def test_holm_adjust_is_monotone_and_caps_at_one() -> None:
    adjusted = analysis.holm_adjust([0.9, 0.01, 0.6])
    # 3*0.01 = 0.03; max(0.03, 2*0.6) = 1.2 capped to 1.0; max(1.0, 0.9) = 1.0.
    assert adjusted == [1.0, 0.03, 1.0]


def test_holm_adjust_overturns_a_raw_verdict() -> None:
    # raw 0.03 < 0.05 would be called significant on its own; in a family of two
    # the adjusted value is max(2*0.03, 0.049) = 0.06 and the verdict is overturned.
    raw = [0.03, 0.049]
    adjusted = analysis.holm_adjust(raw)
    assert adjusted == [0.06, 0.06]
    assert raw[0] < analysis.ALPHA < adjusted[0]


def test_holm_adjust_empty_family() -> None:
    assert analysis.holm_adjust([]) == []


def test_bh_adjust_matches_hand_computation() -> None:
    # m = 3: rank 3 -> 0.03*3/3 = 0.03; rank 2 -> min(0.03, 0.02*3/2) = 0.03;
    # rank 1 -> min(0.03, 0.001*3) = 0.003.
    assert analysis.bh_adjust([0.001, 0.02, 0.03]) == [0.003, 0.03, 0.03]


# --------------------------------------------------------------------------
# exact estimators used by the corrected gate
# --------------------------------------------------------------------------
def test_mcnemar_exact_hand_values() -> None:
    assert analysis.mcnemar_exact(22, 0) == 2.0 / 2**22
    assert analysis.mcnemar_exact(0, 0) == 1.0
    assert analysis.mcnemar_exact(1, 0) == 1.0


def test_clopper_pearson_zero_of_22() -> None:
    lower, upper = analysis.clopper_pearson(0, 22)
    assert lower == 0.0
    assert math.isclose(upper, 1.0 - 0.025 ** (1.0 / 22.0), rel_tol=1e-9)


def test_nearest_rank_p95() -> None:
    # rank = max(1, min(20, ceil(0.95 * 20))) = 19 -> the 19th smallest value.
    assert analysis.nearest_rank_p95([float(i) for i in range(1, 21)]) == 19.0
    assert analysis.nearest_rank_p95([]) is None


# --------------------------------------------------------------------------
# scorecard fixtures
# --------------------------------------------------------------------------
def _outcome(
    scenario_id: str,
    *,
    attack_present: bool,
    attack_success: bool,
    task_success: bool = True,
    domain: str = "alpha",
    attack_family: str = "data_exfiltration",
    decisions: list[str] | None = None,
) -> dict[str, object]:
    return {
        "scenario_id": scenario_id,
        "attack_present": attack_present,
        "attack_success": attack_success,
        "task_success": task_success,
        "domain": domain,
        "attack_family": attack_family,
        "decisions": [
            {"decision": kind, "latency_ms": 1.0 + i}
            for i, kind in enumerate(decisions if decisions is not None else ["allow"] * 3)
        ],
    }


def _write(path: Path, outcomes: list[dict[str, object]]) -> Path:
    path.write_text(json.dumps({"outcomes": outcomes}), encoding="utf-8")
    return path


def _run(*args: str) -> str:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=True,
        cwd=PROJECT_ROOT,
    )
    return result.stdout


# --------------------------------------------------------------------------
# reportability floor on the decision-level cells
# --------------------------------------------------------------------------
def test_decision_cells_are_n_a_below_the_floor() -> None:
    one_decision = [_outcome("a", attack_present=True, attack_success=True, decisions=["allow"])]
    cells = analysis.decision_cells(one_decision)
    assert cells["reportable"] is False
    assert cells["escalation_rate"] is None
    assert cells["rewrite_rate"] is None
    assert cells["latency_p95_ms"] is None
    assert cells["n_a_reason"] == "decisions < 3"


def test_decision_cells_are_n_a_when_the_slice_is_not_reportable() -> None:
    rows = [_outcome("a", attack_present=True, attack_success=True) for _ in range(4)]
    cells = analysis.decision_cells(rows, slice_reportable=False)
    assert cells["reportable"] is False
    assert cells["n_a_reason"] == "slice below the reached-n floor"


def test_decision_cells_report_rates_and_p95_above_the_floor() -> None:
    rows = [
        _outcome("a", attack_present=True, attack_success=True, decisions=["allow", "escalate"]),
        _outcome("b", attack_present=True, attack_success=True, decisions=["rewrite"]),
    ]
    cells = analysis.decision_cells(rows)
    assert cells["reportable"] is True
    assert cells["escalation_rate"] == 1 / 3
    assert cells["rewrite_rate"] == 1 / 3
    # latencies 1.0, 2.0, 1.0 -> sorted [1.0, 1.0, 2.0]; rank = ceil(0.95*3) = 3.
    assert cells["latency_p95_ms"] == 2.0


# --------------------------------------------------------------------------
# control liveness
# --------------------------------------------------------------------------
def test_liveness_counts_the_scenarios_the_control_did_not_licence() -> None:
    control = {
        "a": {"attack_present": True, "attack_success": True},
        "b": {"attack_present": True, "attack_success": False},
        "c": {"attack_present": True, "attack_success": False},
        "d": {"attack_present": False, "attack_success": False},
    }
    live = analysis.liveness(control)
    assert live["attack_scenarios"] == 3
    assert live["reached_n"] == 1
    assert live["excluded_n"] == 2
    assert live["excluded_ids"] == ["b", "c"]
    assert live["effectiveness_claim_licensed"] is True
    assert live["failure_mode"] is None


def test_liveness_fails_when_the_control_licences_nothing() -> None:
    control = {
        "a": {"attack_present": True, "attack_success": False},
        "b": {"attack_present": True, "attack_success": False},
    }
    live = analysis.liveness(control)
    assert live["effectiveness_claim_licensed"] is False
    assert live["excluded_n"] == 2
    assert "no effectiveness claim is licensed" in live["failure_mode"]


def test_default_table_prints_the_exclusion_count(tmp_path: Path) -> None:
    control = _write(
        tmp_path / "control.json",
        [
            _outcome("a", attack_present=True, attack_success=True),
            _outcome("b", attack_present=True, attack_success=False),
            _outcome("c", attack_present=False, attack_success=False),
        ],
    )
    treatment = _write(
        tmp_path / "treatment.json",
        [
            _outcome("a", attack_present=True, attack_success=False),
            _outcome("b", attack_present=True, attack_success=False),
            _outcome("c", attack_present=False, attack_success=False),
        ],
    )
    out = _run("--control", str(control), "--treatment", str(treatment))
    assert "1 excluded from the effectiveness claim and counted: b" in out
    assert "| Holm adj p |" in out


# --------------------------------------------------------------------------
# the H3 verdict is gated on the corrected p and the floor
# --------------------------------------------------------------------------
def test_h3_verdict_is_overturned_when_the_correction_fails(tmp_path: Path) -> None:
    """Count rule holds (reduction > 0 everywhere) but no slice survives Holm."""
    control_rows = [
        _outcome(f"a{i}", attack_present=True, attack_success=True, domain="alpha")
        for i in range(6)
    ] + [
        _outcome(f"b{i}", attack_present=True, attack_success=True, domain="beta") for i in range(6)
    ]
    treatment_rows = [
        _outcome(f"a{i}", attack_present=True, attack_success=False, domain="alpha")
        for i in range(6)
    ] + [
        _outcome(f"b{i}", attack_present=True, attack_success=False, domain="beta")
        for i in range(6)
    ]
    control = _write(tmp_path / "control.json", control_rows)
    treatment = _write(tmp_path / "treatment.json", treatment_rows)
    # Each slice: b = 6, c = 0 -> raw p = 2/2^6 = 0.03125 (< 0.05). The family has
    # m = 2, so Holm gives 2 * 0.03125 = 0.0625 and both verdicts are overturned.
    out = _run("--control", str(control), "--treatment", str(treatment), "--by-domain")
    assert "0.0312" in out
    assert "0.0625" in out
    assert "NOT CONFIRMED" in out
    assert "overturned by the Holm-Bonferroni correction" in out
    assert "**does not hold**" not in out


def test_h3_verdict_confirmed_on_a_corrected_significant_family(tmp_path: Path) -> None:
    """Six reached attacks, all six stopped -> raw p = 2/2^6, adjusted stays tiny."""
    scenarios = [f"a{i}" for i in range(6)]
    control = _write(
        tmp_path / "control.json",
        [_outcome(s, attack_present=True, attack_success=True) for s in scenarios],
    )
    treatment = _write(
        tmp_path / "treatment.json",
        [_outcome(s, attack_present=True, attack_success=False) for s in scenarios],
    )
    out = _run("--control", str(control), "--treatment", str(treatment), "--by-domain")
    assert "**confirmed**" in out
    assert "NOT CONFIRMED" not in out


def test_h3_verdict_fails_on_the_count_rule_when_a_slice_is_untouched(tmp_path: Path) -> None:
    """Two domains, one with a stop and one untouched -> the count rule falsifies."""
    control = _write(
        tmp_path / "control.json",
        [
            _outcome("a1", attack_present=True, attack_success=True, domain="alpha"),
            _outcome("a2", attack_present=True, attack_success=True, domain="alpha"),
            _outcome("a3", attack_present=True, attack_success=True, domain="alpha"),
            _outcome("b1", attack_present=True, attack_success=True, domain="beta"),
            _outcome("b2", attack_present=True, attack_success=True, domain="beta"),
            _outcome("b3", attack_present=True, attack_success=True, domain="beta"),
        ],
    )
    treatment = _write(
        tmp_path / "treatment.json",
        [
            _outcome("a1", attack_present=True, attack_success=False, domain="alpha"),
            _outcome("a2", attack_present=True, attack_success=False, domain="alpha"),
            _outcome("a3", attack_present=True, attack_success=False, domain="alpha"),
            _outcome("b1", attack_present=True, attack_success=True, domain="beta"),
            _outcome("b2", attack_present=True, attack_success=True, domain="beta"),
            _outcome("b3", attack_present=True, attack_success=True, domain="beta"),
        ],
    )
    out = _run("--control", str(control), "--treatment", str(treatment), "--by-domain")
    assert "**does not hold**" in out
    assert "zero-or-negative reduction: beta" in out


# --------------------------------------------------------------------------
# the primary family is corrected across the treatments of one invocation
# --------------------------------------------------------------------------
def test_primary_family_adjusts_across_treatments(tmp_path: Path) -> None:
    scenarios = [f"a{i}" for i in range(6)]
    control = _write(
        tmp_path / "control.json",
        [_outcome(s, attack_present=True, attack_success=True) for s in scenarios],
    )
    treatment = _write(
        tmp_path / "treatment.json",
        [_outcome(s, attack_present=True, attack_success=False) for s in scenarios],
    )
    out = _run(
        "--control", str(control), "--treatment", str(treatment), "--treatment", str(treatment)
    )
    # Two identical treatments: raw 2/2^6, Holm doubles it.
    raw = 2.0 / 2**6
    assert f"{raw:.3g}" in out
    assert f"{min(1.0, 2 * raw):.3g}" in out
    assert "m = 2 treatment(s)" in out
