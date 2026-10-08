#!/usr/bin/env python3
"""Regenerate the RQ1/RQ2 paired tables from SENTINEL scorecards.

Stdlib only. Reads evaluator scorecard JSON (the pinned starter-kit payload:
top-level ``outcomes[]`` with ``scenario_id``, ``attack_present``,
``attack_success``, ``task_success``, plus a ``metrics`` block).

The unit of analysis is one scenario. Treatments are paired with the control by
``scenario_id``; the reached set is the control's ``attack_present and
attack_success`` scenarios, which is the only set on which an attack-effectiveness
claim is licensed (see docs/research/design.md).

Examples
--------
Compare the legacy configs on the real-Qwen public suite:

    python docs/research/analysis.py \
      --control evaluation/real-qwen/allow-all-qwen3-8b.json \
      --treatment evaluation/real-qwen/provenance-qwen3-8b.json \
      --treatment evaluation/real-qwen/aegisgraph-v3-qwen3-8b.json \
      --treatment evaluation/real-qwen/aegisgraph-v5-qwen3-8b.json

Emit machine-readable JSON instead of Markdown:

    python docs/research/analysis.py --control C.json --treatment T.json --json

Report the same paired comparison per domain (H3.3) or per attack family (H3.2):

    python docs/research/analysis.py \
      --control evaluation/real-qwen/allow-all-qwen3-8b.json \
      --treatment evaluation/real-qwen/provenance-qwen3-8b.json \
      --by-domain

`--by-domain` and `--by-family` are mutually exclusive and add a `slices` block.

Multiplicity (statistics.md §5). Every p-value this script prints is corrected
inside a declared family with Holm-Bonferroni at family-wise ``alpha = 0.05``:

* **F1 effectiveness** — one exact McNemar test per treatment, on the reached set,
  `attack_success`. Family = all treatments passed to one invocation.
* **F2 utility** — one exact McNemar test per treatment, on the benign scenarios,
  `task_success`. Family = all treatments passed to one invocation.
* **F3 RQ3 slices** — per treatment, the reportable slice tests of the chosen
  grouping. A slice that produced no p-value (below the reportability floor) is
  not a test and does not enter the family.

The tables print the raw and the Holm-adjusted p side by side; the H3 verdict is
gated on the adjusted p and on the preregistered reportability floor. The legacy
point estimates, counts and intervals are unchanged by the correction: the
historical default table keeps every cell it had and gains the corrected column.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

ALPHA = 0.05
# statistics.md §5: confirmatory families are corrected with Holm-Bonferroni at
# family-wise alpha; the exploratory ablation rows use Benjamini-Hochberg FDR.
CORRECTION = "holm-bonferroni"
CORRECTION_LABEL = "Holm-Bonferroni"
BH_Q = 0.05

# A subgroup is reportable only when its reached set has at least this many paired
# scenarios (H3.2/H3.3: ">= 3 reached attacks"). Below it the slice is printed as
# `n/a` rather than as a point estimate the data cannot support. The same floor
# governs the denominator of every derived slice cell — including the decision-level
# rates (escalation, rewrite) and the latency percentiles — so no derived cell is
# printed from fewer than this many observations (statistics.md §3).
MIN_SLICE_N = 3
# statistics.md §3: with fewer than this many discordant pairs the exact McNemar
# p-value carries no usable information, so the cell is `n/a`.
MIN_DISCORDANT_P = 5


# --------------------------------------------------------------------------
# exact / small-sample estimators (no SciPy)
# --------------------------------------------------------------------------
def _binomial_pmf(n: int, p: float) -> list[float]:
    return [math.comb(n, i) * p**i * (1.0 - p) ** (n - i) for i in range(n + 1)]


def clopper_pearson(k: int, n: int, alpha: float = ALPHA) -> tuple[float, float]:
    """Exact binomial interval (Clopper-Pearson) by bisection."""
    if n == 0:
        return (0.0, 1.0)
    if k == 0:
        return (0.0, 1.0 - (alpha / 2) ** (1.0 / n))
    if k == n:
        return ((alpha / 2) ** (1.0 / n), 1.0)

    def tail_ge(p: float) -> float:
        return sum(_binomial_pmf(n, p)[k:])

    def tail_le(p: float) -> float:
        return sum(_binomial_pmf(n, p)[: k + 1])

    def solve(f, increasing: bool, target: float) -> float:
        lo, hi = 0.0, 1.0
        for _ in range(200):
            mid = (lo + hi) / 2.0
            if (f(mid) > target) == increasing:
                hi = mid
            else:
                lo = mid
        return (lo + hi) / 2.0

    return (solve(tail_ge, True, alpha / 2), solve(tail_le, False, alpha / 2))


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value for discordant counts b and c."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = 2.0 * sum(math.comb(n, i) for i in range(k + 1)) / 2.0**n
    return min(1.0, p)


def discordant_rd_ci(b: int, c: int, n: int, alpha: float = ALPHA) -> tuple[float, float]:
    """95% CI for a paired risk difference from the discordant pairs only.

    RD = (b - c) / n. With q = b / (b + c) the exact Clopper-Pearson interval for
    q maps to RD = (2q - 1) * (b + c) / n. Degenerate when there are no discordant
    pairs (the data carry no paired information).
    """
    d = b + c
    if n == 0 or d == 0:
        return (0.0, 0.0)
    q_lo, q_hi = clopper_pearson(b, d, alpha)
    return ((2 * q_lo - 1) * d / n, (2 * q_hi - 1) * d / n)


def wilson(k: int, n: int, alpha: float = ALPHA) -> tuple[float, float]:
    """Wilson score interval for a single proportion."""
    if n == 0:
        return (0.0, 1.0)
    z = _z(alpha)
    p = k / n
    d = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def newcombe_mover(
    p1: float, lo1: float, hi1: float, p2: float, lo2: float, hi2: float
) -> tuple[float, float]:
    """Newcombe MOVER interval for a paired difference of proportions."""
    diff = p1 - p2
    lo = diff - math.sqrt((p1 - lo1) ** 2 + (hi2 - p2) ** 2)
    hi = diff + math.sqrt((hi1 - p1) ** 2 + (p2 - lo2) ** 2)
    return (max(-1.0, lo), min(1.0, hi))


def cohens_h(p1: float, p2: float) -> float:
    """Cohen's h on the arc-sine scale."""
    return 2.0 * math.asin(math.sqrt(p1)) - 2.0 * math.asin(math.sqrt(p2))


def _z(alpha: float) -> float:
    """Two-sided normal quantile via bisection on the error function."""
    target = 1.0 - alpha / 2.0
    lo, hi = 0.0, 10.0
    for _ in range(200):
        mid = (lo + hi) / 2.0
        if 0.5 * (1.0 + math.erf(mid / math.sqrt(2.0))) < target:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2.0


# --------------------------------------------------------------------------
# multiplicity: step-down / step-up adjusted p-values (statistics.md §5)
# --------------------------------------------------------------------------
def holm_adjust(pvalues: list[float]) -> list[float]:
    """Holm-Bonferroni adjusted p-values, in the input order.

    Step-down: with the p-values sorted ascending, the rank-``k`` adjusted value
    (0-based) is ``min(1, (m - k) * p_(k))`` made monotone non-decreasing. The
    adjusted value is the smallest family-wise error rate at which that test is
    still rejected, so ``p_adj < alpha`` is exactly Holm's reject rule.
    """
    m = len(pvalues)
    if m == 0:
        return []
    adjusted = [0.0] * m
    running = 0.0
    for rank, index in enumerate(sorted(range(m), key=lambda i: pvalues[i])):
        running = max(running, min(1.0, (m - rank) * pvalues[index]))
        adjusted[index] = running
    return adjusted


def bh_adjust(pvalues: list[float], q: float = BH_Q) -> list[float]:
    """Benjamini-Hochberg adjusted p-values (step-up), in the input order.

    Used for the exploratory RQ2 ablation family at FDR ``q = 0.05``; ``q`` is
    accepted so the caller can state the level it corrected at.
    """
    m = len(pvalues)
    if m == 0:
        return []
    order = sorted(range(m), key=lambda i: pvalues[i])
    adjusted = [0.0] * m
    running = 1.0
    for rank in range(m - 1, -1, -1):
        index = order[rank]
        running = min(running, min(1.0, pvalues[index] * m / (rank + 1)))
        adjusted[index] = running
    return adjusted


# --------------------------------------------------------------------------
# scorecard handling
# --------------------------------------------------------------------------
def load_outcomes(path: Path) -> dict[str, dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload["outcomes"]
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        sid = row["scenario_id"]
        if sid in by_id:
            raise ValueError(f"{path}: duplicate scenario_id {sid!r}")
        if not isinstance(row["attack_present"], bool) or not isinstance(
            row["attack_success"], bool
        ):
            raise ValueError(f"{path}: non-bool attack_present/attack_success for {sid!r}")
        if row["attack_success"] and not row["attack_present"]:
            raise ValueError(f"{path}: attack_success on a non-attack scenario {sid!r}")
        by_id[sid] = row
    return by_id


def reached_set(control: dict[str, dict[str, Any]]) -> list[str]:
    return sorted(
        sid for sid, row in control.items() if row["attack_present"] and row["attack_success"]
    )


def liveness(control: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """The control-liveness check: which attack scenarios the control licensed.

    Falsifiable form (design.md §3): an attack scenario whose control verdict does
    **not** authorise the attack action (`attack_present` true, `attack_success`
    false under allow-all) is excluded from the effectiveness claim and counted
    here. The check fails — and no effectiveness claim is licensed — when the
    excluded set is the whole attack set, because then the control authorised no
    attack action at all and the run measured nothing about the defense.
    """
    attacks = sorted(sid for sid, row in control.items() if row["attack_present"])
    unreached = sorted(sid for sid in attacks if not control[sid]["attack_success"])
    reached = [sid for sid in attacks if control[sid]["attack_success"]]
    return {
        "attack_scenarios": len(attacks),
        "reached_n": len(reached),
        "excluded_n": len(unreached),
        "excluded_ids": unreached,
        "effectiveness_claim_licensed": bool(reached),
        "failure_mode": (
            "the control authorised no attack action: every attack scenario is excluded "
            "and no effectiveness claim is licensed"
            if not reached
            else None
        ),
    }


def nearest_rank_p95(samples: list[float]) -> float | None:
    """Nearest-rank p95: `rank = max(1, min(n, ceil(0.95 * n)))` (statistics.md §6)."""
    n = len(samples)
    if n == 0:
        return None
    rank = max(1, min(n, math.ceil(0.95 * n)))
    return sorted(samples)[rank - 1]


def decision_cells(rows: list[dict[str, Any]], *, slice_reportable: bool = True) -> dict[str, Any]:
    """Decision-level cells for one arm on one slice, under the same floor.

    Counts the arm's own decisions inside the slice. Every derived cell is `n/a`
    unless the slice itself is reportable **and** the decision denominator reaches
    ``MIN_SLICE_N``: the reportability floor is not a property of the ASR cells
    alone (statistics.md §3), and a rate over decisions drawn from a single
    scenario would present pseudo-replicated decisions as independent
    (design.md §1).
    """
    decisions = [d for row in rows for d in row.get("decisions", [])]
    n = len(decisions)
    reportable = slice_reportable and n >= MIN_SLICE_N
    if not slice_reportable:
        reason = "slice below the reached-n floor"
    elif not reportable:
        reason = f"decisions < {MIN_SLICE_N}"
    else:
        reason = None
    escalations = sum(1 for d in decisions if d.get("decision") == "escalate")
    rewrites = sum(1 for d in decisions if d.get("decision") == "rewrite")
    latencies = [
        float(d["latency_ms"])
        for d in decisions
        if isinstance(d.get("latency_ms"), (int, float))
        and not isinstance(d.get("latency_ms"), bool)
    ]
    return {
        "decisions_n": n,
        "reportable": reportable,
        "n_a_reason": reason,
        "escalations": escalations,
        "escalation_rate": escalations / n if reportable else None,
        "rewrites": rewrites,
        "rewrite_rate": rewrites / n if reportable else None,
        "latency_n": len(latencies),
        "latency_p95_ms": nearest_rank_p95(latencies) if reportable else None,
    }


def paired_binary(control_rows, treatment_rows, ids, field: str) -> dict[str, int]:
    b = c = both = neither = 0
    missing = []
    for sid in ids:
        if sid not in control_rows or sid not in treatment_rows:
            missing.append(sid)
            continue
        a = bool(control_rows[sid][field])
        t = bool(treatment_rows[sid][field])
        if a and not t:
            b += 1
        elif t and not a:
            c += 1
        elif a and t:
            both += 1
        else:
            neither += 1
    return {
        "b_stopped": b,
        "c_new_success": c,
        "both_success": both,
        "neither": neither,
        "missing": missing,
    }


# --------------------------------------------------------------------------
# slice grouping (H3.2 attack family, H3.3 domain)
# --------------------------------------------------------------------------
def slice_labels(
    control: dict[str, dict[str, Any]], treatment: dict[str, dict[str, Any]], field: str
) -> list[str]:
    """Sorted union of the label values present in either scorecard."""
    labels = {row.get(field, "unknown") for row in control.values()}
    labels |= {row.get(field, "unknown") for row in treatment.values()}
    return sorted(str(label) for label in labels)


def analyse_slice(
    control: dict[str, dict[str, Any]],
    treatment: dict[str, dict[str, Any]],
    reached: list[str],
    field: str,
    value: str,
) -> dict[str, Any]:
    """Paired comparison restricted to one label of ``field`` on the reached set."""
    in_slice = [sid for sid in reached if str(control[sid].get(field, "unknown")) == value]
    scenarios = sum(1 for row in control.values() if str(row.get(field, "unknown")) == value)
    att = paired_binary(control, treatment, in_slice, "attack_success")
    n = att["b_stopped"] + att["c_new_success"] + att["both_success"] + att["neither"]
    ctrl_succ = att["b_stopped"] + att["both_success"]
    trt_succ = att["c_new_success"] + att["both_success"]

    b, c = att["b_stopped"], att["c_new_success"]
    reportable = n >= MIN_SLICE_N
    if not reportable:
        n_a_reason = f"reached n < {MIN_SLICE_N}"
    elif b + c < MIN_DISCORDANT_P:
        n_a_reason = f"discordant pairs < {MIN_DISCORDANT_P}"
    else:
        n_a_reason = None
    exact_p = mcnemar_exact(b, c) if reportable and b + c >= MIN_DISCORDANT_P else None
    decisions = decision_cells([treatment[sid] for sid in in_slice], slice_reportable=reportable)

    return {
        "slice": value,
        "slice_field": field,
        "slice_scenarios": scenarios,
        "reached_n": n,
        "reportable": reportable,
        "control_success": ctrl_succ,
        "treatment_success": trt_succ,
        "control_asr": ctrl_succ / n if reportable else None,
        "treatment_asr": trt_succ / n if reportable else None,
        "reduction": (ctrl_succ - trt_succ) / n if reportable else None,
        "mcnemar_b_stopped": b,
        "mcnemar_c_new_success": c,
        "mcnemar_exact_p": exact_p,
        "mcnemar_exact_p_adj": None,
        "family_size_slice": 0,
        "n_a_reason": n_a_reason,
        "missing_reached": att["missing"],
        "decisions": decisions,
    }


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------
def analyse(
    control_path: Path, treatment_path: Path, group_by: str | None = None
) -> dict[str, Any]:
    control = load_outcomes(control_path)
    treatment = load_outcomes(treatment_path)
    reached = reached_set(control)
    benign = sorted(sid for sid, row in control.items() if not row["attack_present"])

    att = paired_binary(control, treatment, reached, "attack_success")
    n = att["b_stopped"] + att["c_new_success"] + att["both_success"] + att["neither"]
    ctrl_succ = att["b_stopped"] + att["both_success"]
    trt_succ = att["c_new_success"] + att["both_success"]

    p_ctrl, p_trt = ctrl_succ / n, trt_succ / n
    lo1, hi1 = wilson(ctrl_succ, n)
    lo2, hi2 = wilson(trt_succ, n)
    mover = newcombe_mover(p_ctrl, lo1, hi1, p_trt, lo2, hi2)
    discordant = discordant_rd_ci(att["b_stopped"], att["c_new_success"], n)

    ben = paired_binary(control, treatment, benign, "task_success")
    ben_n = ben["b_stopped"] + ben["c_new_success"] + ben["both_success"] + ben["neither"]
    ben_ctrl = ben["b_stopped"] + ben["both_success"]
    ben_trt = ben["c_new_success"] + ben["both_success"]

    result = {
        "control": str(control_path),
        "treatment": str(treatment_path),
        "reached_n": n,
        "liveness": liveness(control),
        "reached_control_success": ctrl_succ,
        "reached_treatment_success": trt_succ,
        "reached_control_cp95": clopper_pearson(ctrl_succ, n),
        "reached_treatment_cp95": clopper_pearson(trt_succ, n),
        "attack_success_reduction": p_ctrl - p_trt,
        "reduction_discordant95": discordant,
        "reduction_mover95": mover,
        "cohens_h": cohens_h(p_ctrl, p_trt) if n else float("nan"),
        "mcnemar_b_stopped": att["b_stopped"],
        "mcnemar_c_new_success": att["c_new_success"],
        "mcnemar_exact_p": mcnemar_exact(att["b_stopped"], att["c_new_success"]),
        "mcnemar_exact_p_adj": None,
        "family_size_attack": 0,
        "correction": CORRECTION,
        "missing_reached": att["missing"],
        "benign_n": ben_n,
        "benign_control_success": ben_ctrl,
        "benign_treatment_success": ben_trt,
        "benign_mcnemar_exact_p": mcnemar_exact(ben["b_stopped"], ben["c_new_success"]),
        "benign_mcnemar_exact_p_adj": None,
        "family_size_benign": 0,
        "benign_lost": sorted(
            sid
            for sid in benign
            if control[sid]["task_success"]
            and not treatment.get(sid, {}).get("task_success", False)
        ),
    }
    if group_by is not None:
        result["group_by"] = group_by
        result["slices"] = [
            analyse_slice(control, treatment, reached, group_by, value)
            for value in slice_labels(control, treatment, group_by)
        ]
    return result


def apply_corrections(results: list[dict[str, Any]]) -> None:
    """Fill the declared families' Holm-adjusted p-values, in place (statistics.md §5).

    Families, one invocation of `analysis.py` = one family:

    * **F1 effectiveness** — the per-treatment reached-attack McNemar tests.
    * **F2 utility** — the per-treatment benign `task_success` McNemar tests.
    * **F3 slices** — per treatment, its reportable slice tests in the chosen
      grouping; a slice that produced no p-value is not a test and is excluded
      from the family, so the correction does not inflate `m` with `n/a` rows.
    """
    attack = [r["mcnemar_exact_p"] for r in results]
    for result, adjusted in zip(results, holm_adjust(attack), strict=True):
        result["mcnemar_exact_p_adj"] = adjusted
        result["family_size_attack"] = len(attack)
    benign = [r["benign_mcnemar_exact_p"] for r in results]
    for result, adjusted in zip(results, holm_adjust(benign), strict=True):
        result["benign_mcnemar_exact_p_adj"] = adjusted
        result["family_size_benign"] = len(benign)
    for result in results:
        slices = result.get("slices")
        if not slices:
            continue
        tested = [s for s in slices if s["mcnemar_exact_p"] is not None]
        adjustments = iter(holm_adjust([s["mcnemar_exact_p"] for s in tested]))
        for s in tested:
            s["mcnemar_exact_p_adj"] = next(adjustments)
            s["family_size_slice"] = len(tested)


def markdown(results: list[dict[str, Any]]) -> str:
    header = (
        "| Treatment | Reached n | Control ASR | Treatment ASR | Reduction "
        "| 95% CI (discordant) | 95% CI (MOVER) | Cohen h | b/c | exact p "
        "| Holm adj p | BTU ctrl | BTU trt |"
    )
    rule = (
        "| --- | ---: | ---: | ---: | ---: | --- | --- | ---: | --- | ---: | ---: | ---: | ---: |"
    )
    row = (
        "| {t} | {n} | {cs}/{n} | {ts}/{n} | {rd:+.4f} "
        "| [{lo:+.4f}, {hi:+.4f}] | [{mlo:+.4f}, {mhi:+.4f}] | {h:+.3f} "
        "| {b}/{c} | {p:.3g} | {pa:.3g} | {bc}/{bn} | {bt}/{bn} |"
    )
    lines = [header, rule]
    for r in results:
        dlo, dhi = r["reduction_discordant95"]
        mlo, mhi = r["reduction_mover95"]
        lines.append(
            row.format(
                t=Path(r["treatment"]).name,
                n=r["reached_n"],
                cs=r["reached_control_success"],
                ts=r["reached_treatment_success"],
                rd=r["attack_success_reduction"],
                lo=dlo,
                hi=dhi,
                mlo=mlo,
                mhi=mhi,
                h=r["cohens_h"],
                b=r["mcnemar_b_stopped"],
                c=r["mcnemar_c_new_success"],
                p=r["mcnemar_exact_p"],
                pa=r["mcnemar_exact_p_adj"],
                bc=r["benign_control_success"],
                bt=r["benign_treatment_success"],
                bn=r["benign_n"],
            )
        )
    lines.append("")
    lines.append(
        "Reduction = control ASR - treatment ASR on the reached set (positive is a "
        "security win). The discordant CI uses only the McNemar discordant pairs; "
        "MOVER (Newcombe) uses the marginal Wilson intervals and is more "
        "conservative. `b/c`: b = control success stopped by the treatment, "
        "c = treatment introduced a success where the control had none. Exact p is "
        "two-sided and conditional on the discordant pairs, not a population-level "
        "p-value (see statistics.md)."
    )
    if results:
        m = results[0]["family_size_attack"]
        lines.append(
            f"Multiplicity: {CORRECTION_LABEL} at family-wise alpha = {ALPHA} over the "
            f"effectiveness family (m = {m} treatment(s) in this invocation); the "
            "`Holm adj p` column is that family's corrected value and `exact p` is "
            "raw. The utility (BTU) tests form a separate family and are corrected "
            "in the `--json` output as `benign_mcnemar_exact_p_adj`."
        )
    seen: set[str] = set()
    for r in results:
        if r["control"] in seen:
            continue
        seen.add(r["control"])
        lines.append(liveness_note(r))
    return "\n".join(lines)


def liveness_note(result: dict[str, Any]) -> str:
    """The control-liveness check, with its falsifiable failure mode (design.md §3)."""
    live = result["liveness"]
    name = Path(result["control"]).name
    if not live["effectiveness_claim_licensed"]:
        return (
            f"Liveness FAILED for control {name}: {live['failure_mode']} "
            f"(excluded {live['excluded_n']}/{live['attack_scenarios']})."
        )
    note = (
        f"Liveness (control {name}): {live['attack_scenarios']} attack "
        f"scenarios, {live['reached_n']} licensed by the control, "
        f"{live['excluded_n']} excluded from the effectiveness claim and counted"
    )
    if live["excluded_ids"]:
        note += f": {', '.join(live['excluded_ids'])}"
    return note + "."


def _rate_cell(count: int, n: int, value: float | None) -> str:
    return "n/a" if value is None else f"{count}/{n} ({value:.4f})"


def _slice_row(s: dict[str, Any]) -> str:
    n = s["reached_n"]
    decisions = s["decisions"]
    d_cells = " | ".join(
        [
            _rate_cell(
                decisions["escalations"], decisions["decisions_n"], decisions["escalation_rate"]
            ),
            _rate_cell(decisions["rewrites"], decisions["decisions_n"], decisions["rewrite_rate"]),
            "n/a" if decisions["latency_p95_ms"] is None else f"{decisions['latency_p95_ms']:.3f}",
        ]
    )
    if not s["reportable"]:
        return (
            f"| {s['slice']} | {s['slice_scenarios']} | {n} | n/a | n/a | n/a | n/a "
            f"| n/a | n/a | {d_cells} |"
        )
    exact_p = s["mcnemar_exact_p"]
    adjusted_p = s["mcnemar_exact_p_adj"]
    p_cell = "n/a" if exact_p is None else f"{exact_p:.3g}"
    adj_cell = "n/a" if adjusted_p is None else f"{adjusted_p:.3g}"
    return (
        f"| {s['slice']} | {s['slice_scenarios']} | {n} "
        f"| {s['control_success']}/{n} | {s['treatment_success']}/{n} "
        f"| {s['reduction']:+.4f} | {s['mcnemar_b_stopped']}/{s['mcnemar_c_new_success']} "
        f"| {p_cell} | {adj_cell} | {d_cells} |"
    )


def _p_pair(s: dict[str, Any]) -> str:
    raw = "n/a" if s["mcnemar_exact_p"] is None else f"{s['mcnemar_exact_p']:.3g}"
    adj = "n/a" if s["mcnemar_exact_p_adj"] is None else f"{s['mcnemar_exact_p_adj']:.3g}"
    return f"{s['slice']} (raw p = {raw}, adjusted p = {adj})"


def _hypothesis_note(result: dict[str, Any], group_by: str) -> str:
    """The H3 verdict, gated on the corrected p-values and the reportability floor.

    A slice below the floor (reached `n < MIN_SLICE_N`, or no usable p because
    `b + c < MIN_DISCORDANT_P`) carries no confirmatory test, so it can neither
    support nor falsify the hypothesis. When the count rule holds but the
    corrected gate does not, the overturn is printed instead of a bare verdict.
    """
    rows = [s for s in result["slices"] if s["reportable"]]
    tested = [s for s in rows if s["mcnemar_exact_p_adj"] is not None]
    floored = [s for s in rows if s["mcnemar_exact_p_adj"] is None]
    m = tested[0]["family_size_slice"] if tested else 0

    if group_by == "domain":
        zero = [s["slice"] for s in rows if s["reduction"] is not None and s["reduction"] <= 0.0]
        count_holds = bool(rows) and not zero
        failed = [s for s in tested if s["mcnemar_exact_p_adj"] >= ALPHA or s["reduction"] <= 0.0]
        confirmed = count_holds and not failed and not floored
        if not rows:
            verdict = "not computable (no domain slice reaches the minimum)"
        elif confirmed:
            verdict = "confirmed"
        elif count_holds:
            causes = []
            if failed:
                causes.append(f"the {CORRECTION_LABEL} correction")
            if floored:
                causes.append("the reportability floor")
            verdict = (
                "holds on the count rule but is NOT CONFIRMED — overturned by "
                + " and ".join(causes)
            )
        else:
            verdict = "does not hold"
        detail = f"reportable domains: {len(rows)}; corrected family m = {m}"
        if zero:
            detail += f"; zero-or-negative reduction: {', '.join(zero)}"
        if failed:
            detail += "; failing the corrected gate: " + ", ".join(_p_pair(s) for s in failed)
        if floored:
            detail += "; no usable p (floor): " + ", ".join(
                f"{s['slice']} ({s['n_a_reason']})" for s in floored
            )
        return (
            "**H3.3** (every domain with >= 3 reached attacks shows reduction > 0, "
            f"adjusted p < {ALPHA}): **{verdict}** — {detail}."
        )

    stopped = [s for s in rows if s["mcnemar_b_stopped"] > 0]
    untouched = [s for s in rows if s["mcnemar_b_stopped"] == 0]
    count_holds = bool(rows) and len(stopped) >= 2 and not untouched
    confirmed_stopped = [s for s in tested if s["mcnemar_b_stopped"] > 0]
    floored_stopped = [s for s in floored if s["mcnemar_b_stopped"] > 0]
    confirmed = count_holds and len(confirmed_stopped) >= 2 and not floored_stopped
    if not rows:
        verdict = "not computable (no family slice reaches the minimum)"
    elif confirmed:
        verdict = "confirmed"
    elif count_holds:
        causes = []
        if len(confirmed_stopped) < 2:
            causes.append(f"the {CORRECTION_LABEL} correction")
        if floored_stopped:
            causes.append("the reportability floor")
        verdict = "holds on the count rule but is NOT CONFIRMED — overturned by " + " and ".join(
            causes
        )
    else:
        verdict = "does not hold"
    detail = (
        f"reportable families: {len(rows)}; families with a stop: {len(stopped)}; "
        f"families with no stop: {len(untouched)}; corrected-significant stops: "
        f"{len(confirmed_stopped)}; corrected family m = {m}"
    )
    if floored_stopped:
        detail += "; stopped families with no usable p (floor): " + ", ".join(
            f"{s['slice']} ({s['n_a_reason']})" for s in floored_stopped
        )
    return (
        "**H3.2** (at least two families contain a stopped attack and no family with "
        f">= 3 reached attacks is untouched, adjusted p < {ALPHA}): **{verdict}** — "
        f"{detail}."
    )


def markdown_slices(results: list[dict[str, Any]], group_by: str) -> str:
    label = "domain" if group_by == "domain" else "attack family"
    lines = [
        f"Grouped by {label}. A slice is reportable only at reached n >= {MIN_SLICE_N} "
        f"(H3.2/H3.3); the exact McNemar p is printed only when b + c >= "
        f"{MIN_DISCORDANT_P} (statistics.md §3). The same floor governs the decision "
        f"cells: escalation, rewrite and p95 latency are `n/a` below {MIN_SLICE_N} "
        "decisions in the slice. Every other cell is `n/a`: the slice carries no "
        "usable paired information and no estimate is manufactured for it.",
        "",
    ]
    header = (
        "| Slice | Scenarios | Reached n | Control ASR | Treatment ASR | Reduction "
        "| b/c | exact p | Holm adj p | Escal. | Rewr. | p95 ms |"
    )
    rule = "| --- | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | --- | --- | ---: |"
    seen: set[str] = set()
    for r in results:
        if r["control"] in seen:
            continue
        seen.add(r["control"])
        lines.append(liveness_note(r))
    lines.append("")
    for r in results:
        lines.append(f"## {Path(r['treatment']).name} — by {label}")
        lines.append("")
        lines += [header, rule]
        lines += [_slice_row(s) for s in r["slices"]]
        notes = [f"`{s['slice']}` ({s['n_a_reason']})" for s in r["slices"] if s["n_a_reason"]]
        tested = [s for s in r["slices"] if s["mcnemar_exact_p"] is not None]
        m = tested[0]["family_size_slice"] if tested else 0
        lines.append("")
        lines.append(f"H3 verdict: {_hypothesis_note(r, group_by)}")
        lines.append(
            f"Multiplicity: {CORRECTION_LABEL} at family-wise alpha = {ALPHA} over this "
            f"treatment's slice family (m = {m} test(s)); `exact p` is raw, "
            "`Holm adj p` is the family-corrected value."
        )
        if notes:
            lines.append(f"`n/a` because: {', '.join(notes)}.")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--treatment", type=Path, action="append", required=True)
    parser.add_argument("--json", action="store_true")
    grouping = parser.add_mutually_exclusive_group()
    grouping.add_argument(
        "--by-domain",
        action="store_true",
        help="report the paired comparison per scenario domain (H3.3)",
    )
    grouping.add_argument(
        "--by-family",
        action="store_true",
        help="report the paired comparison per attack_family label (H3.2)",
    )
    args = parser.parse_args()

    if args.by_domain:
        group_by = "domain"
    elif args.by_family:
        group_by = "attack_family"
    else:
        group_by = None
    results = [analyse(args.control, t, group_by) for t in args.treatment]
    apply_corrections(results)
    if args.json:
        print(json.dumps(results, indent=2))
    elif group_by is not None:
        print(markdown_slices(results, group_by))
    else:
        print(markdown(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
