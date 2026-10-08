"""Inert simulated tools for end-to-end enforcement demonstrations.

Nothing in this module performs I/O: no network, no filesystem, no subprocess and
no external system is touched. Every function only records what it was asked to
do and returns a synthetic result, so a receipt-bound execution can be
demonstrated without wiring a real destructive integration.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from aegisgraph.contracts import CandidateAction
from aegisgraph.enforcement import ToolResult


@dataclass
class InertToolbox:
    """Records actions it is asked to execute and performs no side effect."""

    calls: list[CandidateAction] = field(default_factory=list)

    def executor(self, action: CandidateAction) -> ToolResult:
        """Act as the caller-supplied executor for the enforcement SDK."""

        self.calls.append(action)
        return ToolResult(
            tool=action.tool or action.type.value,
            status="simulated",
            detail="Inert simulated execution; no external effect occurred.",
        )

    def audit(self) -> list[Mapping[str, Any]]:
        """Return a content-free record of the actions that were executed."""

        return [
            {"tool": action.tool or action.type.value, "digest": action.execution_digest()}
            for action in self.calls
        ]
