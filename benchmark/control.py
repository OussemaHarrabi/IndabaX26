"""The allow-all control: a deliberately permissive decision surface.

The reachability control asks one question of every attack scenario: *would this
scenario's attack action be authorized if the defence did nothing?* If the answer
is no, the scenario proves nothing about the defence and its attack result is not
licensed.

This module answers that question with the simplest possible origin server: an
HTTP endpoint that returns ``allow`` for every well-formed request. It is part of
the harness, not part of the defence, and it deliberately lives in the benchmark
package so that no production code path can accidentally serve it.

Boundary
--------
The control targets scripted (non-model) agents. With a scripted agent the
control is a **harness-liveness** check: it proves the assembled request is
well-formed, is accepted by the wire contract, and proposes an action that a
decision surface is willing to authorize. It is *not* evidence that a real model
would fall for the payload. Real-model reachability requires a model and is
recorded as blocked in the manifest.
"""

from __future__ import annotations

import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

API_VERSION = "aegisgraph/v1"
CONTROL_REASON = "CONTROL_ALLOW_ALL"
MAX_BODY_BYTES = 1_048_576


def _digest(body: bytes, length: int) -> str:
    return hashlib.sha256(body).hexdigest()[:length]


def allow_response(body: bytes, *, generic: bool) -> dict[str, Any]:
    """The deterministic allow verdict for one request body."""

    response: dict[str, Any] = {
        "decision": "allow",
        "risk_score": 0.0,
        "confidence": 1.0,
        "reason_codes": [CONTROL_REASON],
        "explanation": None,
        "rewritten_action": None,
        "metadata": {"control": "allow_all"},
    }
    if generic:
        response.update(
            {
                "api_version": API_VERSION,
                "request_id": _digest(b"request:" + body, 32),
                "receipt_id": _digest(b"receipt:" + body, 32),
                "policy_set": {"id": "control-allow-all", "version": "1"},
                "action_digest": _digest(b"action:" + body, 24),
                "execution_digest": _digest(b"execution:" + body, 24),
                "decided_at": "1970-01-01T00:00:00Z",
                "valid_until": "1970-01-01T00:01:00Z",
            }
        )
    return response


class _ControlHandler(BaseHTTPRequestHandler):
    server_version = "aegisgraph-control/1"
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        """Silence the default stderr access log."""

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send(200, {"status": "ok"})
            return
        self._send(404, {"detail": "Not found"})

    def do_POST(self) -> None:
        counter = getattr(self.server, "request_count", None)
        if counter is not None:
            counter.append(1)
        generic = self.path.startswith("/api/v1/decisions")
        if not (generic or self.path.startswith("/v1/decision")):
            self._send(404, {"detail": "Not found"})
            return
        declared = self.headers.get("Content-Length")
        if declared is None or not declared.isdigit():
            self._send(411, {"detail": "Length required"})
            return
        length = int(declared)
        if length > MAX_BODY_BYTES:
            self._send(413, {"detail": "Request body exceeds the configured limit"})
            return
        body = self.rfile.read(length)
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send(422, {"detail": "Invalid SENTINEL request"})
            return
        if not isinstance(parsed, dict) or "candidate_action" not in parsed:
            self._send(422, {"detail": "Invalid SENTINEL request"})
            return
        if generic and parsed.get("api_version") != API_VERSION:
            self._send(422, {"detail": "Invalid SENTINEL request"})
            return
        self._send(200, allow_response(body, generic=generic))


class ControlServer:
    """A bound, running allow-all control origin server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._httpd = ThreadingHTTPServer((host, port), _ControlHandler)
        self._httpd.daemon_threads = True
        self.requests: list[int] = []
        self._httpd.request_count = self.requests  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def host(self) -> str:
        return str(self._httpd.server_address[0])

    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1])

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> ControlServer:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    def __enter__(self) -> ControlServer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()
