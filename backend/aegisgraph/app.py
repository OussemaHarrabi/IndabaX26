"""Local HTTP boundary for deterministic AegisGraph decisions."""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import RequestResponseEndpoint
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from aegisgraph.api_v1 import router as api_v1_router
from aegisgraph.contracts import GuardDecision
from aegisgraph.engine import decide
from aegisgraph.sentinel import (
    MAX_RESPONSE_BYTES,
    SentinelRequest,
    SentinelResponse,
    wire_response,
)

_LOGGER = logging.getLogger(__name__)
_GENERIC_INVALID = {"detail": "Invalid SENTINEL request"}
_GENERIC_FAILURE = {"detail": "Request could not be safely processed"}
_GENERIC_TOO_LARGE = {"detail": "Request body exceeds the configured limit"}
_STATIC_DIRECTORY = Path(__file__).parent / "static"
_DASHBOARD_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "connect-src 'none'; img-src 'self' data:; object-src 'none'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

MAX_BODY_BYTES_ENV = "AEGISGRAPH_MAX_BODY_BYTES"
DEFAULT_MAX_BODY_BYTES = 1_048_576
"""Upper bound for a request body, enforced before the body is parsed (F5)."""

LOG_LEVEL_ENV = "AEGISGRAPH_LOG_LEVEL"
DEFAULT_LOG_LEVEL = logging.INFO
_DECISION_HANDLER_NAME = "aegisgraph-decision-stdout"


def log_level() -> int:
    """Return the configured service log level (default ``INFO``)."""

    raw = os.environ.get(LOG_LEVEL_ENV)
    if raw is None:
        return DEFAULT_LOG_LEVEL
    resolved = logging.getLevelNamesMapping().get(raw.strip().upper())
    return resolved if isinstance(resolved, int) else DEFAULT_LOG_LEVEL


class _DecisionStreamHandler(logging.Handler):
    """Write decision records to the current stdout.

    The stream is resolved at emit time rather than captured at construction, so
    output redirection (containers, pipes, test capture) is honoured.
    """

    def emit(self, record: logging.LogRecord) -> None:
        try:
            stream = sys.stdout
            stream.write(f"{self.format(record)}\n")
            stream.flush()
        except Exception:  # pragma: no cover - logging must never break a decision
            self.handleError(record)


def configure_logging() -> None:
    """Route ``aegisgraph`` records to stdout for the running service.

    The decision record is a structured JSON line, so the handler emits the
    message verbatim. Only the application boundary configures logging: importing
    a library module such as ``aegisgraph.engine`` never touches global logging
    state. The call is idempotent, so a reloaded application does not stack
    handlers. Records still propagate, so a host that configures the root logger
    keeps receiving them.
    """

    level = log_level()
    logger = logging.getLogger("aegisgraph")
    logger.setLevel(level)
    for handler in logger.handlers:
        if handler.get_name() == _DECISION_HANDLER_NAME:
            handler.setLevel(level)
            return
    handler = _DecisionStreamHandler()
    handler.set_name(_DECISION_HANDLER_NAME)
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)


app = FastAPI(
    title="AegisGraph SENTINEL v1 defense API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


class BodySizeLimitMiddleware:
    """Reject oversized request bodies with 413 before any JSON parsing (F5).

    Both the declared ``Content-Length`` and the streamed body (chunked transfer
    encoding) are bounded: the declared size is rejected before the body is read,
    and a streamed body is buffered only until the bound is crossed. The request
    is then replayed downstream, so the bound is applied in front of parsing and
    memory never exceeds the configured size.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = max_body_bytes()
        headers = {key.lower(): value for key, value in scope["headers"]}
        declared = headers.get(b"content-length")
        if declared is not None and _declared_too_large(declared, limit):
            await _send_too_large(send)
            return

        chunks: list[bytes] = []
        received = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                return
            chunk = message.get("body", b"")
            received += len(chunk)
            if received > limit:
                await _send_too_large(send)
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if replayed:
                return {"type": "http.disconnect"}
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay, send)


app.add_middleware(BodySizeLimitMiddleware)


@app.get("/", include_in_schema=False)
async def dashboard() -> FileResponse:
    """Serve the local, read-only investigation surface."""

    return FileResponse(_STATIC_DIRECTORY / "index.html", media_type="text/html")


app.mount("/assets", StaticFiles(directory=_STATIC_DIRECTORY), name="dashboard-assets")


@app.middleware("http")
async def no_store_and_sanitize_errors(
    request: Request, call_next: RequestResponseEndpoint
) -> Response:
    try:
        response = await call_next(request)
    except Exception as error:
        _LOGGER.error("Unhandled HTTP boundary exception (%s)", type(error).__name__)
        response = JSONResponse(_GENERIC_FAILURE, status_code=500)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    if request.url.path == "/" or request.url.path.startswith("/assets/"):
        response.headers["Content-Security-Policy"] = _DASHBOARD_CSP
    return response


def max_body_bytes() -> int:
    """Return the configured request-body bound in bytes (default 1 MiB)."""

    raw = os.environ.get(MAX_BODY_BYTES_ENV)
    if raw is None:
        return DEFAULT_MAX_BODY_BYTES
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MAX_BODY_BYTES
    return value if value > 0 else DEFAULT_MAX_BODY_BYTES


def _declared_too_large(declared: bytes, limit: int) -> bool:
    try:
        return int(declared) > limit
    except ValueError:
        return True


async def _send_too_large(send: Send) -> None:
    body = json.dumps(_GENERIC_TOO_LARGE).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"cache-control", b"no-store"),
                (b"pragma", b"no-cache"),
                (b"x-content-type-options", b"nosniff"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


app.include_router(api_v1_router)


@app.exception_handler(RequestValidationError)
async def invalid_request_handler(_request: Request, _error: RequestValidationError) -> Response:
    return JSONResponse(_GENERIC_INVALID, status_code=422)


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(_request: Request, error: StarletteHTTPException) -> Response:
    # Keep routing status and method headers while dropping framework details.
    headers = {key: value for key, value in (error.headers or {}).items()}
    body = _GENERIC_INVALID if error.status_code in {400, 413, 415, 422} else _GENERIC_FAILURE
    return JSONResponse(body, status_code=error.status_code, headers=headers)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/decision", response_model=SentinelResponse)
async def decision_endpoint(request: SentinelRequest) -> Response:
    """Return one bounded policy decision; candidate actions are never executed."""

    try:
        result = decide(request)
        response = _to_wire_response(result)
        encoded = response.model_dump_json().encode("utf-8")
        if len(encoded) > MAX_RESPONSE_BYTES:
            raise ValueError("decision response exceeded protocol response bound")
        return Response(content=encoded, media_type="application/json", status_code=200)
    except Exception as error:
        _LOGGER.error("Decision response validation failed (%s)", type(error).__name__)
        # A valid request reaching policy must never become an allow on an error.
        fallback = SentinelResponse(
            decision="block",
            risk_score=1.0,
            confidence=1.0,
            reason_codes=("INTERNAL_EVALUATION_FAILED",),
            explanation="The request could not be safely evaluated.",
            metadata={},
        )
        return Response(
            content=fallback.model_dump_json(), media_type="application/json", status_code=200
        )


def _to_wire_response(decision: GuardDecision) -> SentinelResponse:
    """Translate canonical enums into the strict public response contract."""

    return wire_response(decision)


configure_logging()
