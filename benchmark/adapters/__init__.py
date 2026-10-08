"""Compatibility adapters that read artifacts from other benchmark formats.

An adapter is a *read-only projection*: it reads an external artifact and
expresses it in the native representation. It never writes to the source, never
recomputes a legacy number under new code, and never lets the projection become a
second source of truth.
"""

from __future__ import annotations

from benchmark.adapters.sentinel import (
    ADAPTER_INFERENCES,
    LEGACY_REPO,
    AdapterError,
    LegacyProjection,
    LegacyScorecard,
    LegacyVerification,
    load_legacy_scenarios,
    load_legacy_scorecard,
    reproduce_digest,
    reproduce_metrics,
    verify_scorecard,
)

__all__ = [
    "ADAPTER_INFERENCES",
    "LEGACY_REPO",
    "AdapterError",
    "LegacyProjection",
    "LegacyScorecard",
    "LegacyVerification",
    "load_legacy_scenarios",
    "load_legacy_scorecard",
    "reproduce_digest",
    "reproduce_metrics",
    "verify_scorecard",
]
