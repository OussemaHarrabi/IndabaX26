"""Run a decision response through the enforcement SDK.

Usage
-----

    # Offline: build a decision locally and enforce it against two actions.
    python examples/enforce_decision.py

    # Live: ask a running service for a decision, then enforce it.
    python examples/enforce_decision.py --url http://127.0.0.1:8080

The example never performs a real side effect. The executor it passes to
``execute_guarded`` is the inert simulated toolbox from
``aegisgraph.demo_tools``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from aegisgraph.api_v1 import DEFAULT_POLICY_SET
from aegisgraph.contracts import CandidateAction
from aegisgraph.demo_tools import InertToolbox
from aegisgraph.enforcement import execute_guarded

REQUEST: dict[str, Any] = {
    "api_version": "aegisgraph/v1",
    "request_id": "example-1",
    "run_id": "example-run",
    "step_id": 1,
    "user_goal": "Look up the status of the open ticket",
    "conversation": [],
    "candidate_action": {
        "type": "tool_call",
        "tool": "ticket_read",
        "arguments": {"ticket_id": "t-42"},
    },
    "policy_context": {"allowed_tools": ["ticket_read", "ticket_update"]},
    "history_digest": {"confirmations_granted": []},
}


def decision_from_service(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Ask a running service for a decision (stdlib HTTP client only)."""

    import urllib.request

    request = urllib.request.Request(
        f"{url.rstrip('/')}/api/v1/decisions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def decision_from_engine(payload: dict[str, Any]) -> dict[str, Any]:
    """Produce the same decision locally, without an HTTP round trip."""

    from aegisgraph.app import app
    from fastapi.testclient import TestClient

    response = TestClient(app).post("/api/v1/decisions", json=payload)
    return response.json()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", help="live service base URL, e.g. http://127.0.0.1:8080")
    arguments = parser.parse_args()

    receipt = (
        decision_from_service(arguments.url, REQUEST)
        if arguments.url
        else decision_from_engine(REQUEST)
    )
    print("decision response:")
    print(json.dumps(receipt, indent=2, sort_keys=True))

    approved = CandidateAction.model_validate(REQUEST["candidate_action"])
    tampered = CandidateAction(
        type="tool_call",
        tool="ticket_update",
        arguments={"ticket_id": "t-42", "status": "closed"},
    )
    toolbox = InertToolbox()

    for label, action in (("approved action", approved), ("tampered action", tampered)):
        guarded = execute_guarded(
            toolbox.executor,
            receipt,
            action,
            expected_policy=DEFAULT_POLICY_SET,
        )
        if guarded.executed:
            print(f"{label}: EXECUTED (inert) -> {guarded.result}")
        else:
            print(f"{label}: REFUSED [{guarded.outcome.reason}] {guarded.outcome.detail}")

    print(f"executed actions: {toolbox.audit()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
